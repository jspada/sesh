//! There are minimal monospace rendering helpers for the CLI: fixed-width tables for
//! `list` commands and aligned `Label: value` blocks for `show` commands.
//!
//! Pure string formatting with no I/O, no dependencies.

/// A simple monospace table: column widths grow to fit the widest cell (or the
/// header), cells are joined with `" | "`, and a `-` rule separates the header
/// from the rows.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// A new table with the given column headers
    pub fn new(headers: &[&str]) -> Self {
        Table {
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    /// Append one row. The row must have exactly one cell per header
    pub fn push(&mut self, row: Vec<String>) {
        assert_eq!(
            row.len(),
            self.headers.len(),
            "table row width must match the header count"
        );
        self.rows.push(row);
    }

    /// Whether the table has no rows
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Render the table (header, `-` rule, rows), one trailing newline per line
    pub fn render(&self) -> String {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();
        for row in &self.rows {
            for (w, cell) in widths.iter_mut().zip(row) {
                *w = (*w).max(cell.len());
            }
        }

        let render_row = |cells: &[String]| -> String {
            let mut line = String::new();
            for (i, (cell, w)) in cells.iter().zip(&widths).enumerate() {
                if i > 0 {
                    line.push_str(" | ");
                }
                line.push_str(cell);
                // Pad every column but the last so lines have no trailing spaces
                if i + 1 < cells.len() {
                    line.push_str(&" ".repeat(w - cell.len()));
                }
            }
            line.push('\n');
            line
        };

        let mut out = render_row(&self.headers);
        let rule_len = widths.iter().sum::<usize>() + 3 * (widths.len() - 1);
        out.push_str(&"-".repeat(rule_len));
        out.push('\n');
        for row in &self.rows {
            out.push_str(&render_row(row));
        }
        out
    }
}

/// Render an aligned `Label: value` block. Each label starts its line (so it
/// remains greppable as `Label:`), and values line up in one column.
pub fn render_kv(pairs: &[(&str, String)]) -> String {
    let width = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in pairs {
        out.push_str(k);
        out.push(':');
        out.push_str(&" ".repeat(width - k.len() + 1));
        out.push_str(v);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_widths_fit_headers_and_cells() {
        let mut t = Table::new(&["Name", "Fingerprint"]);
        t.push(vec!["a".into(), "2f9qLxHq3ce".into()]);
        t.push(vec!["longer-name".into(), "x".into()]);
        let out = t.render();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "Name        | Fingerprint");
        assert_eq!(lines[1], "-".repeat("Name        | Fingerprint".len()));
        assert_eq!(lines[2], "a           | 2f9qLxHq3ce");
        assert_eq!(lines[3], "longer-name | x");
    }

    #[test]
    fn table_last_column_has_no_trailing_padding() {
        let mut t = Table::new(&["A", "B"]);
        t.push(vec!["x".into(), "y".into()]);
        for line in t.render().lines() {
            assert_eq!(line, line.trim_end());
        }
    }

    #[test]
    fn table_is_empty_tracks_rows() {
        let mut t = Table::new(&["A"]);
        assert!(t.is_empty());
        t.push(vec!["x".into()]);
        assert!(!t.is_empty());
    }

    #[test]
    fn kv_labels_align_and_start_lines() {
        let out = render_kv(&[
            ("Name", "me".to_string()),
            ("Contact token", "abc".to_string()),
        ]);
        assert_eq!(out, "Name:          me\nContact token: abc\n");
    }
}
