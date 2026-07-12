//! Low-level terminal primitives shared by the supervised secret-egress
//! commands (`hd-secret copy` and `hd-secret reveal`).
//!
//! Two families of command need the same terminal machinery:
//!
//! - a **raw-mode countdown loop** that animates a status line and polls
//!   stdin for a **keypress** without blocking ([`run_countdown`]), and
//! - the **alternate screen buffer** that `reveal` displays a secret on, a
//!   scrollback-free surface that vanishes on exit ([`enter_alt_screen`] /
//!   [`leave_alt_screen`]).
//!
//! Rust's std has no raw mode, so (as elsewhere in this tool) `stty` is the
//! portable, dependency-free way to get it.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// --------------
// TTY predicates
// --------------

/// Whether stdin is a terminal (needed to read a keypress from raw-mode stdin)
pub fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Whether stdout is a terminal
pub fn stdout_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// Whether stderr is a terminal
pub fn stderr_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

/// The controlling terminal's height in rows (`stty size` prints
/// `rows cols`), or `None` when there is no terminal or no `stty`. Used to
/// decide whether a tall block (the `reveal --setup` QR) fits on screen.
pub fn rows() -> Option<usize> {
    let size = stty(&["size"])?;
    size.split_whitespace().next()?.parse().ok()
}

/// Re-assert a sane **line-input** terminal mode: canonical, echoing, and
/// signal-generating (so `Ctrl-C` interrupts and `Ctrl-Z` suspends). A prior
/// no-echo password prompt, or a countdown that was interrupted before its
/// raw-mode guard could restore, can leave the terminal without these; this
/// repairs it. No-op if `stty` is unavailable. Call only on a TTY.
pub fn ensure_line_input() {
    let _ = stty(&["icanon", "echo", "isig"]);
}

// -----------------------------
// Raw-mode countdown loop (fun)
// -----------------------------

/// How a [`run_countdown`] loop finished
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The full `timeout` elapsed with no cancel
    TimedOut,
    /// The user pressed a key, **any** key, ending the window early
    Cancelled,
    /// The caller's per-frame closure asked to stop (see [`run_countdown_while`])
    Stopped,
}

/// One animation frame every 60 ms, smooth enough to look alive, cheap enough
/// to leave the terminal idle between ticks.
const FRAME: Duration = Duration::from_millis(60);

/// Drive a raw-mode countdown for `timeout`, calling `draw(elapsed, remaining)`
/// once per frame to render whatever the caller wants (a status line, a secret
/// view). The loop puts the terminal in raw, no-echo, non-blocking mode so a
/// single `read()` returns instantly whether or not a key is waiting. That
/// lets one loop both animate and poll for a keypress with no thread and no
/// `select`/`poll` (absent from std anyway).
///
/// **Any** keypress cancels, and that is a safety property, not a convenience.
/// [`RawMode`] also clears `isig`, so `Ctrl-C`, `Ctrl-Z` and `Ctrl-\` arrive
/// here as ordinary bytes rather than as `SIGINT`/`SIGTSTP`/`SIGQUIT`. Were they
/// signals, the default disposition would kill or stop the process *between*
/// frames: [`RawMode`]'s `Drop` would never run (leaving the terminal with no
/// echo and no line editing), the caller's alt-screen teardown would never run
/// (leaving the secret on screen, and the cursor hidden), and the secret's
/// `Zeroizing` buffer would never be scrubbed. Turning them into cancels means
/// every exit from this loop is the same, ordinary, cleaned-up one.
///
/// `remaining` is whole seconds left (ceiled), matching what a countdown wants
/// to print. Returns [`Ended::Cancelled`] on a keypress, else
/// [`Ended::TimedOut`]. The terminal is always restored before returning. If raw
/// mode cannot be entered (no `stty`), the loop still animates to completion but
/// cannot observe a keypress and `isig` is then untouched, so `Ctrl-C` retains
/// its usual meaning.
pub fn run_countdown(timeout: Duration, mut draw: impl FnMut(Duration, u64)) -> Ended {
    run_countdown_while(timeout, |elapsed, secs| {
        draw(elapsed, secs);
        true
    })
}

/// [`run_countdown`], but the per-frame closure decides whether to continue:
/// returning `false` ends the loop early with [`Ended::Stopped`]. The `copy`
/// countdown uses it to stop the moment the clipboard's paste budget is spent,
/// since there is then nothing left to zero and nothing left to wait for.
pub fn run_countdown_while(timeout: Duration, mut tick: impl FnMut(Duration, u64) -> bool) -> Ended {
    let raw = RawMode::enable();

    let start = Instant::now();
    let mut stdin = std::io::stdin();
    let mut byte = [0u8; 1];
    let mut ended = Ended::TimedOut;

    while start.elapsed() < timeout {
        let elapsed = start.elapsed();
        let remaining = timeout.saturating_sub(elapsed);
        let secs = remaining.as_secs_f64().ceil() as u64;
        if !tick(elapsed, secs) {
            ended = Ended::Stopped;
            break;
        }

        // Non-blocking read: Ok(1) is any key; Ok(0) is "nothing pressed"
        if raw.is_some() {
            if let Ok(1) = stdin.read(&mut byte) {
                ended = Ended::Cancelled;
                // A function or arrow key is one escape *sequence*, not one
                // byte. Swallow the rest while the terminal is still raw and
                // non-blocking, so a stray `[A` cannot land on the shell prompt
                // we are about to return to.
                while let Ok(1) = stdin.read(&mut byte) {}
                break;
            }
        }
        std::thread::sleep(FRAME);
    }

    drop(raw);
    ended
}

// -----------------------
// Alternate screen buffer
// -----------------------

/// Switch stdout to the **alternate screen buffer** (`ESC [?1049h`). The
/// scrollback-free surface `less`/`vim` use. Nothing drawn here reaches the
/// main screen or its scrollback, so a secret shown on it leaves no trace once
/// [`leave_alt_screen`] restores the main screen. The cursor is hidden while
/// the alt screen is up.
pub fn enter_alt_screen(w: &mut impl Write) -> std::io::Result<()> {
    // ?1049h: save cursor + switch to alt buffer. ?25l: hide the cursor
    write!(w, "\x1b[?1049h\x1b[?25l")?;
    w.flush()
}

/// Leave the alternate screen buffer (`ESC [?1049l`), restoring the main
/// screen exactly as it was and re-showing the cursor. Belt-and-braces: the
/// caller should [`wipe_region`] the rendered lines *before* calling this, so
/// even a terminal that mishandles the alt buffer holds no secret bytes.
///
/// The cursor is shown **after** the buffer switch, not before. Terminals
/// disagree on whether `DECTCEM` (the `?25` cursor-visibility mode) is global or
/// saved per screen buffer; showing it while still on the alt screen can leave
/// the restored main screen with an invisible cursor on the ones that scope it
/// per buffer. Issuing `?25h` last makes it unambiguously about the screen the
/// user is returning to.
pub fn leave_alt_screen(w: &mut impl Write) -> std::io::Result<()> {
    // ?1049l: restore main buffer. ?25h: show cursor, on *that* buffer
    write!(w, "\x1b[?1049l\x1b[?25h")?;
    w.flush()
}

/// Overwrite `lines` lines (each `width` columns) with spaces, starting from
/// the top-left of the current screen. This is the explicit **fixed-width block** the
/// egress plan calls for. Used to scrub the rendered secret from the alt buffer
/// before leaving it: defence in depth against a terminal that mishandles the
/// alt buffer or where a bare erase-display leaves stale cells.
pub fn wipe_region(w: &mut impl Write, lines: usize, width: usize) -> std::io::Result<()> {
    let blank = " ".repeat(width);
    // Home the cursor, then blank each line in turn
    write!(w, "\x1b[H")?;
    for _ in 0..lines {
        // Blank the whole line and drop to the next
        write!(w, "{blank}\x1b[K\r\n")?;
    }
    write!(w, "\x1b[H")?;
    w.flush()
}

/// Home the cursor and erase the entire screen (`ESC [2J`). Complements
/// [`wipe_region`]: the block-overwrite handles terminals that don't paint on
/// erase, and this handles content that wrapped beyond the rendered width.
pub fn clear_screen(w: &mut impl Write) -> std::io::Result<()> {
    write!(w, "\x1b[H\x1b[2J\x1b[H")?;
    w.flush()
}

// -----------------
// Raw mode via stty
// -----------------

/// A raw-mode guard: disables canonical mode and echo via `stty` on
/// construction and restores the saved settings on drop.
pub struct RawMode {
    saved: Option<String>,
}

impl RawMode {
    /// Enable raw, no-echo, no-signal mode; returns `None` if `stty` is
    /// unavailable (then a countdown still animates, just without key-to-cancel).
    pub fn enable() -> Option<Self> {
        let saved = stty(&["-g"])?;
        // No echo, no line-buffering (`-icanon`), and a non-blocking read
        // (`min 0 time 0`): `read()` returns at once with 0 or 1 byte. Output
        // post-processing is left on, so our `\r`/`\n` still behave.
        //
        // `-isig` is the load-bearing one: it stops `Ctrl-C`/`Ctrl-Z`/`Ctrl-\`
        // from raising a signal whose default disposition would kill or stop us
        // mid-frame, skipping this guard's `Drop` and every teardown the caller
        // has queued behind it. They become bytes, and the countdown cancels on
        // any byte. See [`run_countdown`].
        stty(&["-echo", "-icanon", "-isig", "min", "0", "time", "0"])?;
        Some(RawMode { saved: Some(saved) })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(s) = self.saved.take() {
            let _ = stty(&[s.as_str()]);
        }
    }
}

/// Run `stty` against the controlling terminal (inheriting our stdin),
/// returning trimmed stdout on success, or `None` on any failure.
fn stty(args: &[&str]) -> Option<String> {
    let out = Command::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_region_blanks_each_line_and_homes_cursor() {
        let mut buf: Vec<u8> = Vec::new();
        wipe_region(&mut buf, 2, 4).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Two blank runs of the requested width, cursor homed at start and end
        assert!(s.starts_with("\x1b[H"));
        assert!(s.ends_with("\x1b[H"));
        assert_eq!(s.matches("    ").count(), 2, "one 4-wide blank per line");
    }

    #[test]
    fn clear_screen_homes_and_erases() {
        let mut buf: Vec<u8> = Vec::new();
        clear_screen(&mut buf).unwrap();
        assert_eq!(buf, b"\x1b[H\x1b[2J\x1b[H");
    }

    #[test]
    fn alt_screen_sequences_are_paired() {
        let mut enter: Vec<u8> = Vec::new();
        enter_alt_screen(&mut enter).unwrap();
        assert_eq!(enter, b"\x1b[?1049h\x1b[?25l");
        let mut leave: Vec<u8> = Vec::new();
        leave_alt_screen(&mut leave).unwrap();
        // The cursor is shown *after* the buffer switch, so the main screen is
        // unambiguously the one it applies to.
        assert_eq!(leave, b"\x1b[?1049l\x1b[?25h");
    }

    #[test]
    fn countdown_zero_timeout_ends_immediately() {
        // A already-elapsed window draws nothing and reports TimedOut without
        // touching a terminal (raw mode is best-effort).
        let mut drew = false;
        let ended = run_countdown(Duration::from_secs(0), |_, _| drew = true);
        assert_eq!(ended, Ended::TimedOut);
        assert!(!drew);
    }
}
