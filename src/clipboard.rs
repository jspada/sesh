//! System-clipboard integration for `copy` commands.
//!
//! The secret is always piped to the clipboard tool's **stdin**. It never
//! appears on a command line (visible in `ps`) and is never echoed. The tool
//! is chosen by, in order:
//!
//! 1. `SESH_CLIPBOARD_CMD` run via `sh -c` (also the test seam);
//! 2. `pbcopy` on macOS;
//! 3. `wl-copy` if `WAYLAND_DISPLAY` is set, else `xclip -selection clipboard`.
//!
//! After a copy, an interactive terminal runs a **zeroing countdown**: a smooth
//! colour/shape animation ticks down (default 30s), then the clipboard is
//! overwritten (zeroed). Pressing **any key** zeros immediately. Both paths exit
//! cleanly. In a non-interactive context (piped stdin/stderr) the countdown is
//! skipped-— there is no terminal to animate or to read a keypress from.
//!
//! On Linux the countdown can also end **early, on paste**. X11 and Wayland
//! clipboards are request-served (the copying process stays alive and hands the
//! data to each pasting application), so the tool can count paste requests and
//! drop the selection after a budget of them. macOS's `NSPasteboard` never reports a read, so the
//! budget is a Linux-only affordance, and the timed zeroing is what everyone
//! gets. The budget is `linux_paste_count` in [`crate::config::Settings`].
//!
//! Everything the countdown writes goes through a [`Sink`], so the loop can be
//! unit-tested against a recording double instead of a real clipboard.

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::terminal::{self, Ended};

/// Resolve `(program, args)` for the clipboard tool (see module docs)
fn clipboard_tool() -> (String, Vec<String>) {
    match std::env::var("SESH_CLIPBOARD_CMD") {
        Ok(cmd) => ("sh".into(), vec!["-c".into(), cmd]),
        Err(_) => {
            if cfg!(target_os = "macos") {
                ("pbcopy".into(), vec![])
            } else if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                ("wl-copy".into(), vec![])
            } else {
                (
                    "xclip".into(),
                    vec!["-selection".into(), "clipboard".into()],
                )
            }
        }
    }
}

/// Copy `text` to the system clipboard (see the module docs for tool selection)
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let (program, args) = clipboard_tool();
    let mut child = Command::new(&program)
        .args(&args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "cannot run clipboard tool '{program}': {e} (install it, or set \
                 SESH_CLIPBOARD_CMD to a command that reads the secret from stdin)"
            )
        })?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(text.as_bytes())
        .map_err(|e| format!("cannot write to clipboard tool '{program}': {e}"))?;
    let status = child
        .wait()
        .map_err(|e| format!("clipboard tool '{program}' failed: {e}"))?;
    if !status.success() {
        return Err(format!("clipboard tool '{program}' exited with {status}"));
    }
    Ok(())
}

/// Overwrite the clipboard, removing any copied secret. Writes an empty payload
/// and, for robustness against tools that ignore an empty write, a single
/// scrubbing space first.
pub fn clear_clipboard() -> Result<(), String> {
    // A space then empty: some clipboard managers no-op on a zero-byte write
    let _ = copy_to_clipboard(" ");
    copy_to_clipboard("")
}

/// Whether a real interactive terminal is attached (stdin readable for a keypress,
/// stderr a TTY to animate on) for the `copy` countdown.
pub fn interactive() -> bool {
    terminal::stdin_is_tty() && terminal::stderr_is_tty()
}

// ----------------------------------
// The clipboard the countdown drives
// ----------------------------------

/// Where a `copy` countdown writes. The real one is [`System`]; tests use a
/// recording double, so the loop is exercised without a clipboard, a subprocess,
/// or a mutation of the process environment.
pub trait Sink {
    /// Put `text` on the clipboard, replacing whatever is there.
    fn copy(&mut self, text: &str) -> Result<(), String>;

    /// Whether the clipboard has already released the secret because its paste
    /// budget ran out. Always `false` where no budget applies.
    fn spent(&mut self) -> bool {
        false
    }

    /// Overwrite the clipboard, removing the copied secret.
    fn clear(&mut self) -> Result<(), String>;
}

/// The system clipboard, optionally with a **paste budget** (Linux only, see
/// the module docs): after `pastes` paste requests the tool exits and the
/// selection is gone, which the countdown notices and stops on.
pub struct System {
    pastes: Option<u32>,
    /// The live paste-counting tool, while it owns the selection
    child: Option<Child>,
}

impl System {
    /// A plain clipboard: copies land, and only the countdown clears them.
    pub fn new() -> Self {
        System {
            pastes: None,
            child: None,
        }
    }

    /// A clipboard that releases the secret after `pastes` pastes.
    ///
    /// Only meaningful on Linux and only with a real display server; the caller
    /// ([`paste_budget`]) decides, so this constructor simply obeys.
    pub fn with_paste_budget(pastes: u32) -> Self {
        System {
            pastes: Some(pastes),
            child: None,
        }
    }

    /// Kill the paste-counting tool, if one is running: it owns the selection,
    /// so it must go before anything else may own it.
    fn release(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Default for System {
    fn default() -> Self {
        System::new()
    }
}

impl Sink for System {
    fn copy(&mut self, text: &str) -> Result<(), String> {
        self.release();
        match self.pastes {
            None => copy_to_clipboard(text),
            Some(n) => {
                self.child = Some(spawn_paste_counting(text, n)?);
                Ok(())
            }
        }
    }

    fn spent(&mut self) -> bool {
        // The tool exits once it has served its budget; until then `try_wait`
        // reports it still running. An error (no such process) is treated as
        // spent, so a countdown can never wedge on a tool that vanished.
        match self.child.as_mut() {
            None => false,
            Some(child) => !matches!(child.try_wait(), Ok(None)),
        }
    }

    fn clear(&mut self) -> Result<(), String> {
        self.release();
        clear_clipboard()
    }
}

/// The clipboard tool spelled to serve exactly `pastes` paste requests and then
/// exit, releasing the selection.
///
/// Both tools must be kept in the **foreground** (`--foreground` / `-quiet`):
/// left to themselves they fork, our handle would exit at once, and every
/// countdown would think its budget was spent on the first frame.
fn paste_counting_tool(pastes: u32) -> Result<(String, Vec<String>), String> {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        if pastes != 1 {
            return Err(format!(
                "linux_paste_count = {pastes} is not supported on Wayland: wl-copy can serve \
                 at most one paste (`--paste-once`). Set it to 1, or remove it to keep only \
                 the timed clearing."
            ));
        }
        return Ok((
            "wl-copy".into(),
            vec!["--foreground".into(), "--paste-once".into()],
        ));
    }
    Ok((
        "xclip".into(),
        vec![
            "-selection".into(),
            "clipboard".into(),
            "-quiet".into(),
            "-loops".into(),
            pastes.to_string(),
        ],
    ))
}

/// Spawn the paste-counting tool, hand it the secret on stdin, and **leave it
/// running**: it owns the selection until it has served its budget.
fn spawn_paste_counting(text: &str, pastes: u32) -> Result<Child, String> {
    let (program, args) = paste_counting_tool(pastes)?;
    let mut child = Command::new(&program)
        .args(&args)
        .stdin(Stdio::piped())
        // `-quiet` chatters about each selection request; nothing there is ours
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            format!(
                "cannot run clipboard tool '{program}': {e} (install it, or remove \
                 linux_paste_count from settings.json to use the timed clearing only)"
            )
        })?;
    // Dropping the handle closes the pipe, which is what tells the tool the
    // payload is complete; it then stays alive to serve pastes.
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(text.as_bytes())
        .map_err(|e| format!("cannot write to clipboard tool '{program}': {e}"))?;
    Ok(child)
}

/// The paste budget in force for a `copy`, or `None` for the timed clearing
/// alone. `None` unless every condition holds: Linux, a real countdown to end
/// early (interactive), no `SESH_CLIPBOARD_CMD` override (that command *is* the
/// clipboard, and sesh cannot know how to make it count pastes), and a budget in
/// the user's config.
pub fn paste_budget(settings: &crate::config::Settings) -> Option<u32> {
    if !cfg!(target_os = "linux") || !interactive() {
        return None;
    }
    if std::env::var_os("SESH_CLIPBOARD_CMD").is_some() {
        return None;
    }
    settings.linux_paste_count
}

/// Re-assert a sane line-input terminal mode after a no-echo prompt or an
/// interrupted countdown. Thin re-export of [`terminal::ensure_line_input`].
pub fn ensure_line_input() {
    terminal::ensure_line_input();
}

// -----------------
// Zeroing countdown
// -----------------

/// Run the post-copy zeroing countdown, then clear the clipboard.
///
/// Shows a smooth colour/shape animation counting down `timeout` seconds; the
/// user has that window to switch apps and paste. **Any key** ends it early. Either
/// way the clipboard is overwritten and the function returns `Ok(())`, so the
/// process exits cleanly. Requires an interactive terminal ([`interactive`]).
/// The raw-mode keypress loop is shared with `reveal` via [`terminal::run_countdown`].
/// `Ctrl-C` and `Ctrl-Z` cancel it like any other key rather than killing or
/// suspending us with the clipboard still populated.
pub fn hold_then_clear(sink: &mut impl Sink, timeout: Duration) -> Result<(), String> {
    hold_then_clear_refreshing(sink, timeout, || None)
}

/// [`hold_then_clear`], but re-copying whenever `refresh` hands back a fresh
/// payload. `refresh` runs once per animation frame; `None` means "the
/// clipboard is still current" (the common case, and all a static secret ever
/// answers). The otp `copy` passes a closure that returns the new code exactly
/// when the 30-second TOTP window rolls over, so the clipboard never holds a
/// dead code mid-countdown.
///
/// The loop also ends the moment the sink's paste budget is spent (Linux; see
/// the module docs): the secret is already off the clipboard, so there is
/// nothing left to zero and nothing left to wait for.
///
/// A failed re-copy is deliberately swallowed: mid-animation there is no clean
/// place to report it, the clipboard then simply keeps the previous (now
/// stale) code, which is a liveness nit, not a leak, and the final zeroing write
/// below still runs and still reports its own failure.
pub fn hold_then_clear_refreshing(
    sink: &mut impl Sink,
    timeout: Duration,
    mut refresh: impl FnMut() -> Option<Zeroizing<String>>,
) -> Result<(), String> {
    let color = std::env::var_os("NO_COLOR").is_none();
    let mut err = std::io::stderr();

    let total = timeout.as_secs_f64();
    let ended: Ended = terminal::run_countdown_while(timeout, |elapsed, secs| {
        // Pastes spent: the tool has dropped the selection already
        if sink.spent() {
            return false;
        }
        if let Some(fresh) = refresh() {
            let _ = sink.copy(&fresh);
        }
        // The waterline: fraction of the window still left, 1.0 -> 0.0. It scales
        // the wave's height so the crests sink as time runs out and settle to a
        // flat baseline the instant the clock hits zero.
        let remaining = if total > 0.0 {
            (1.0 - elapsed.as_secs_f64() / total).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let line = render_frame(elapsed.as_secs_f64(), secs, remaining, color);
        let _ = write!(err, "\r{line}\x1b[K");
        let _ = err.flush();
        true
    });

    // Clear the status line, zero the clipboard, and confirm
    let _ = write!(err, "\r\x1b[K");
    let _ = err.flush();
    sink.clear()?;
    let done = if color { "\x1b[90m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let why = if ended == Ended::Stopped {
        "Secret pasted; cleared from clipboard."
    } else {
        "Secret zeroed from clipboard."
    };
    let _ = writeln!(err, "{done}{why}{reset}");
    Ok(())
}

/// Render just the undulating, hue-cycling wave with no surrounding labels. A
/// traveling sine wave sets each cell's height, scaled by `waterline ∈ [0,1]`:
/// at a full waterline the crests reach the top; as it drops they sink; at zero
/// every cell is the lowest bar, a flat line. :)  `t` is elapsed seconds (drives
/// the motion). Shared by the `copy` countdown and `reveal`'s footer. In colour
/// it ends with an active SGR colour; the caller appends its own reset.
pub(crate) fn render_wave(t: f64, waterline: f64, color: bool) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    const WIDTH: usize = 12;

    let waterline = waterline.clamp(0.0, 1.0);
    let mut wave = String::new();
    for i in 0..WIDTH {
        let phase = t * 6.5 - i as f64 * 0.55;
        let height = (phase.sin() * 0.5 + 0.5) * waterline;
        let level = height * (BARS.len() - 1) as f64;
        let ch = BARS[level.round() as usize];
        if color {
            // The colour drifts, blue-weighted, down through cyan and green to a
            // yellow-green and back, but never into red, pink, or purple. Crests
            // ride a touch brighter than troughs, for shimmer; as the waterline
            // sinks the whole band dims with it.
            let (r, g, b) = wave_color(t * 0.18 + i as f64 / WIDTH as f64, height);
            wave.push_str(&format!("\x1b[38;2;{r};{g};{b}m{ch}"));
        } else {
            wave.push(ch);
        }
    }
    wave
}

/// Build one animation frame: the "Secret copied..." label, the undulating wave,
/// and the countdown. `t` is elapsed seconds; `secs` is the whole seconds
/// remaining; `waterline ∈ [0,1]` is the fraction of the window still left.
fn render_frame(t: f64, secs: u64, waterline: f64, color: bool) -> String {
    let wave = render_wave(t, waterline, color);
    let (label_a, dim, reset) = if color {
        ("\x1b[97m", "\x1b[90m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    format!(
        "{label_a}Secret copied to clipboard: {reset}{wave}{reset} \
         {label_a}zeroing in {secs}s {dim}(any key to cancel){reset}"
    )
}

/// The wave colour as `phase` advances: a **blue-weighted** sweep that sits in
/// rich blue most of the time and dips, briefly, down through cyan and green to
/// a yellow-green, thereby deliberately staying out of red, pink, and purple. Darker
/// and more saturated than a pastel. `lift ∈ [0,1]` (the wave height) lightens
/// crests a touch for shimmer.
fn wave_color(phase: f64, lift: f64) -> (u8, u8, u8) {
    use std::f64::consts::TAU;
    // `u` eases 0↔1; the `^1.5` skew makes the sweep linger near the blue end
    // and only briefly reach the yellow-green end. Hue spans 0.64 (blue) ->
    // 0.20 (yellow-green): no red (<0.10), no purple/pink (>0.70).
    let u = 0.5 - 0.5 * (phase * TAU).cos();
    let hue = 0.64 - 0.44 * u.powf(1.5);
    let l = 0.50 + 0.08 * lift.clamp(0.0, 1.0);
    hsl_to_rgb(hue, 0.65, l)
}

/// HSL -> RGB for `h ∈ [0,1)`, `s,l ∈ [0,1]`
fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let hp = h.rem_euclid(1.0) * 6.0;
    let x = c * (1.0 - (hp.rem_euclid(2.0) - 1.0).abs());
    let (r1, g1, b1) = match hp as i64 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    (
        ((r1 + m) * 255.0).round() as u8,
        ((g1 + m) * 255.0).round() as u8,
        ((b1 + m) * 255.0).round() as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // A recording clipboard: what the countdown wrote, in order, and whether it
    // cleared. `spent_after` mimics a paste budget running out after that many
    // frames. Driving the loop through a double keeps it out of the process
    // environment, which `set_var` would otherwise mutate under the other test
    // threads.
    #[derive(Default)]
    struct Recorder {
        copies: Vec<String>,
        cleared: bool,
        frames: u32,
        spent_after: Option<u32>,
    }

    impl Sink for Recorder {
        fn copy(&mut self, text: &str) -> Result<(), String> {
            self.copies.push(text.to_string());
            Ok(())
        }
        fn spent(&mut self) -> bool {
            self.frames += 1;
            self.spent_after.is_some_and(|n| self.frames > n)
        }
        fn clear(&mut self) -> Result<(), String> {
            self.cleared = true;
            Ok(())
        }
    }

    // Every `Some` from the refresh closure lands on the clipboard, in order,
    // and the clipboard is cleared when the window ends. (What decides *when* a
    // refresh happens is `cli::otp_refresher`, tested there.)
    #[test]
    fn the_countdown_recopies_on_refresh_and_clears_at_the_end() {
        let mut sink = Recorder::default();
        // ~16 frames at 60ms: ample even on a loaded machine for the two the
        // closure hands out.
        let mut calls = 0;
        hold_then_clear_refreshing(&mut sink, Duration::from_secs(1), move || {
            calls += 1;
            match calls {
                1 => Some(Zeroizing::new("111111".into())),
                2 => Some(Zeroizing::new("222222".into())),
                _ => None,
            }
        })
        .unwrap();
        assert_eq!(sink.copies, ["111111", "222222"]);
        assert!(sink.cleared);
    }

    // No refresh (every non-otp `copy`): the countdown writes nothing and
    // clears once, at the end.
    #[test]
    fn a_plain_countdown_only_clears() {
        let mut sink = Recorder::default();
        hold_then_clear(&mut sink, Duration::from_millis(120)).unwrap();
        assert!(sink.copies.is_empty());
        assert!(sink.cleared);
    }

    // A spent paste budget ends the window early: the secret is already off the
    // clipboard, so there is nothing left to wait for. The clear still runs,
    // it costs nothing, and covers a tool that exited without releasing.
    #[test]
    fn a_spent_paste_budget_ends_the_countdown_early() {
        let mut sink = Recorder {
            spent_after: Some(2),
            ..Recorder::default()
        };
        let start = std::time::Instant::now();
        hold_then_clear(&mut sink, Duration::from_secs(30)).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "must stop on the spent budget, not run the 30s window out"
        );
        assert!(sink.cleared);
    }

    // Wayland's wl-copy serves at most one paste, so a larger budget is refused
    // rather than silently honoured as 1. X11's xclip takes any count.
    #[test]
    fn the_paste_counting_tool_is_spelled_per_display_server() {
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        let (program, args) = match paste_counting_tool(1) {
            Ok(t) => t,
            Err(e) => panic!("a single paste is always supported: {e}"),
        };
        if wayland {
            assert_eq!(program, "wl-copy");
            assert!(args.contains(&"--paste-once".to_string()));
            assert!(args.contains(&"--foreground".to_string()), "or it forks");
            assert!(paste_counting_tool(3).is_err(), "wl-copy cannot serve 3");
        } else {
            assert_eq!(program, "xclip");
            assert!(args.contains(&"-quiet".to_string()), "or it forks");
            let three = paste_counting_tool(3).unwrap().1;
            assert!(three.windows(2).any(|w| w == ["-loops", "3"]));
        }
    }

    #[test]
    fn wave_color_stays_blue_through_green_never_warm() {
        // Across the whole sweep the band spans yellow-green -> blue: green is
        // always at least as strong as red, which rules out red, orange, pink
        // and purple. It stays vivid (not grey) and dark-ish but never black.
        for k in 0..48 {
            let phase = k as f64 / 48.0;
            for &lift in &[0.0_f64, 0.5, 1.0] {
                let (r, g, b) = wave_color(phase, lift);
                assert!(
                    r <= g,
                    "no red/orange/pink/purple (green ≥ red): {r},{g},{b}"
                );
                let max = r.max(g).max(b);
                assert!(max > 150, "not too dark: {r},{g},{b}");
                assert!(r.min(g).min(b) > 20, "not near-black: {r},{g},{b}");
            }
        }
    }

    #[test]
    fn hsl_midtones_are_grey() {
        // Zero saturation -> grey at the given lightness, regardless of hue
        assert_eq!(hsl_to_rgb(0.3, 0.0, 0.5), (128, 128, 128));
    }

    #[test]
    fn frame_has_label_countdown_and_changes_over_time() {
        let a = render_frame(0.0, 30, 1.0, true);
        assert!(a.contains("Secret copied to clipboard:"));
        assert!(a.contains("zeroing in 30s"));
        assert!(a.contains("any key to cancel"));
        // The wave differs across time (shape and/or colour)
        let b = render_frame(0.5, 30, 1.0, true);
        assert_ne!(a, b);
    }

    #[test]
    fn frame_without_color_has_no_escape_sequences() {
        let plain = render_frame(0.2, 12, 1.0, false);
        assert!(!plain.contains('\x1b'));
        assert!(plain.contains("zeroing in 12s"));
    }

    #[test]
    fn waterline_at_zero_is_a_flat_line_of_the_lowest_bar() {
        // When no time is left the wave has fully drained: every cell is the
        // lowest bar char, regardless of the animation phase.
        for &t in &[0.0_f64, 0.3, 1.7, 5.0] {
            let plain = render_frame(t, 0, 0.0, false);
            let wave: String = plain.chars().filter(|c| "▁▂▃▄▅▆▇█".contains(*c)).collect();
            assert!(!wave.is_empty(), "frame should still draw the wave cells");
            assert!(
                wave.chars().all(|c| c == '▁'),
                "drained wave must be a flat baseline, got {wave:?}"
            );
        }
    }

    #[test]
    fn waterline_lowers_crests_as_time_runs_out() {
        // The tallest bar reached at a full waterline is never shorter than the
        // tallest bar at a partial one: the crests sink as the window drains.
        let tallest = |waterline: f64| -> usize {
            (0..200)
                .map(|k| {
                    let plain = render_frame(k as f64 * 0.05, 10, waterline, false);
                    plain
                        .chars()
                        .filter_map(|c| "▁▂▃▄▅▆▇█".find(c))
                        .max()
                        .unwrap_or(0)
                })
                .max()
                .unwrap_or(0)
        };
        assert!(
            tallest(1.0) > tallest(0.4),
            "crests should be lower part-way through"
        );
        assert!(tallest(0.4) > tallest(0.0), "and lower still as it drains");
    }
}
