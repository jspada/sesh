//! Terminal QR rendering for the `reveal --setup` enrollment view.
//!
//! Built on `qrcodegen` (Nayuki's reference implementation: pure Rust, zero
//! transitive dependencies) at ECC **Low** (the spec minimum), plenty for a
//! bright close-range screen scan, and it keeps the code small (an ~80-char
//! otpauth URI lands at version 4-5, 33-37 modules).
//!
//! Two rendering rules matter for real phone scanners (ISO/IEC 18004 and
//! every scanner SDK's docs):
//!
//! 1. **Dark modules on a light background.** Inverted codes fail on many
//!    phones. A terminal-themed rendering (bright blocks on whatever the
//!    background happens to be) silently inverts on light themes, so when
//!    color is available the QR forces its own colors (black on bright-white)
//!    and is correct on *any* theme. Under `NO_COLOR` we can only draw with
//!    the terminal's own foreground, so light modules become the blocks:
//!    correct polarity on dark terminals (the common case), a documented
//!    limitation on light ones.
//!
//! 2. **A 4-module quiet zone** on all sides, the ISO minimum; it is part of
//!    what lets a scanner lock onto the finder patterns.

/// Render `text` as terminal lines, two QR modules per character cell via
/// half blocks (`▀`/`▄`/`█`/space), quiet zone included.
///
/// With `color`, each line is wrapped in SGR `30;107` (black foreground,
/// bright-white background) so the polarity is explicit and theme-proof;
/// without it, lines are bare half-blocks with **light modules as the drawn
/// blocks** (see the module docs for why). Pure: no I/O, unit-testable.
pub fn rows(text: &str, color: bool) -> Result<Vec<String>, String> {
    let qr = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Low)
        .map_err(|e| format!("QR encoding failed: {e}"))?;

    /// The ISO/IEC 18004 minimum quiet zone, in modules
    const QUIET: i32 = 4;
    let dim = qr.size() + 2 * QUIET;
    // Dark at grid coordinates including the quiet zone (qrcodegen returns
    // light for out-of-range coordinates, which is exactly the quiet zone).
    let dark = |x: i32, y: i32| qr.get_module(x - QUIET, y - QUIET);

    let mut out = Vec::with_capacity(((dim + 1) / 2) as usize);
    for y in (0..dim).step_by(2) {
        let mut row = String::with_capacity(dim as usize + 16);
        if color {
            row.push_str("\x1b[30;107m");
        }
        for x in 0..dim {
            // The row below the grid is quiet zone, i.e. light
            let (top, bottom) = (dark(x, y), y + 1 < dim && dark(x, y + 1));
            // In color the foreground (the block ink) is black = dark; bare
            // half-blocks draw with the terminal foreground = light, so the
            // mapping inverts.
            row.push(match (top == color, bottom == color) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        if color {
            row.push_str("\x1b[0m");
        }
        out.push(row);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/example.com:bob?secret=A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYH&issuer=example.com";

    // Strip the SGR wrapping from a colored row, leaving the module cells
    fn cells(row: &str) -> &str {
        row.strip_prefix("\x1b[30;107m")
            .and_then(|r| r.strip_suffix("\x1b[0m"))
            .unwrap_or(row)
    }

    #[test]
    fn geometry_matches_the_qr_plus_quiet_zone() {
        let plain = rows(URI, false).unwrap();
        // Every row has the same width, and the row count is ceil((size+8)/2)
        // for the (always odd) module count, i.e. rows*2-1 or rows*2 == width.
        let width = plain[0].chars().count();
        assert!(plain.iter().all(|r| r.chars().count() == width));
        let modules = width as i32; // one module per column, quiet zone included
        assert!(modules % 2 == 1, "QR size is odd, plus 8 quiet modules");
        let size = modules - 8;
        // An ~100-char URI at ECC Low is version 4-6 (33-41 modules)
        assert!((33..=41).contains(&size), "unexpected QR size {size}");
        assert_eq!(plain.len() as i32, (modules + 1) / 2);
        // And the colored rendering has identical cell geometry
        let colored = rows(URI, true).unwrap();
        assert_eq!(colored.len(), plain.len());
        assert!(colored
            .iter()
            .all(|r| cells(r).chars().count() == width));
    }

    #[test]
    fn quiet_zone_is_light_on_all_four_sides() {
        // In color, light = space: the top/bottom two text rows (4 module
        // rows) and the outer 4 columns must be entirely light.
        let colored = rows(URI, true).unwrap();
        for row in [&colored[0], &colored[1]] {
            assert!(cells(row).chars().all(|c| c == ' '), "top quiet zone");
        }
        for row in colored.iter().rev().take(2) {
            assert!(cells(row).chars().all(|c| c == ' '), "bottom quiet zone");
        }
        for row in &colored {
            let cs: Vec<char> = cells(row).chars().collect();
            assert!(cs[..4].iter().all(|c| *c == ' '), "left quiet zone");
            assert!(cs[cs.len() - 4..].iter().all(|c| *c == ' '), "right");
        }
        // Bare rendering: light is the block, so the quiet zone is solid ink
        let plain = rows(URI, false).unwrap();
        assert!(plain[0].chars().all(|c| c == '█'), "{}", plain[0]);
    }

    #[test]
    fn finder_patterns_land_where_the_spec_puts_them() {
        // The three 7x7 finder patterns sit at the corners of the module grid
        // (inside the quiet zone). Check their unmistakable signature on the
        // first module row: 7 dark, 1 light, then data, then 1 light, 7 dark.
        // Module row 4 is the top half of text row 2 in color mode ('▀' or '█'
        // means the top module is dark).
        let colored = rows(URI, true).unwrap();
        let row2: Vec<char> = cells(&colored[2]).chars().collect();
        let top_dark: Vec<bool> = row2.iter().map(|c| matches!(c, '█' | '▀')).collect();
        let width = top_dark.len();
        assert!(
            top_dark[4..11].iter().all(|&d| d),
            "top-left finder's 7-module bar"
        );
        assert!(!top_dark[11], "separator after the top-left finder");
        assert!(
            top_dark[width - 11..width - 4].iter().all(|&d| d),
            "top-right finder's 7-module bar"
        );
        assert!(!top_dark[width - 12], "separator before the top-right finder");
    }

    #[test]
    fn colored_rows_force_polarity_and_bare_rows_are_pure_halfblocks() {
        let colored = rows(URI, true).unwrap();
        for row in &colored {
            assert!(row.starts_with("\x1b[30;107m"), "explicit black-on-white");
            assert!(row.ends_with("\x1b[0m"), "reset at end of row");
            assert!(
                cells(row).chars().all(|c| " ▀▄█".contains(c)),
                "only half-block cells inside"
            );
        }
        let plain = rows(URI, false).unwrap();
        for row in &plain {
            assert!(!row.contains('\x1b'), "NO_COLOR carries no escapes");
            assert!(row.chars().all(|c| " ▀▄█".contains(c)));
        }
        // The two renderings are each other's inverse, cell for cell
        for (c, p) in colored.iter().zip(&plain) {
            let flip = |ch: char| match ch {
                '█' => ' ',
                '▀' => '▄',
                '▄' => '▀',
                _ => '█',
            };
            assert_eq!(cells(c).chars().map(flip).collect::<String>(), *p);
        }
    }

    #[test]
    fn undecodable_input_is_a_clean_error() {
        // qrcodegen refuses text beyond the version-40 capacity
        assert!(rows(&"x".repeat(8000), false).is_err());
    }
}
