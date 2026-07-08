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

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

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
pub fn hold_then_clear(timeout: Duration) -> Result<(), String> {
    let color = std::env::var_os("NO_COLOR").is_none();
    let mut err = std::io::stderr();

    let total = timeout.as_secs_f64();
    let _ended: Ended = terminal::run_countdown(timeout, |elapsed, secs| {
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
    });

    // Clear the status line, zero the clipboard, and confirm
    let _ = write!(err, "\r\x1b[K");
    let _ = err.flush();
    clear_clipboard()?;
    let done = if color { "\x1b[90m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let _ = writeln!(err, "{done}Secret zeroed from clipboard.{reset}");
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
