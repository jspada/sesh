//! Human-facing encodings for secrets and public keys.
//!
//! These are presentation helpers only. No key material is derived here. A
//! byte string can be rendered as hex, base58, base10, a custom alphabetic
//! code, or a BIP-39 mnemonic, and a secret can be trimmed to a requested
//! length, mixed with a symbol vocabulary, and/or given a fixed suffix.
//!
//! Everything here returns `Result` so formatting parameters can arrive from
//! untrusted-ish places (stored registries, group share tokens), so a bad
//! `mode`/`length`/`suffix` must surface as a clean error, never a panic.

use num_bigint::BigUint;

/// Canonical width, in bytes, of a BLS12-381 scalar (the output-secret width)
pub const SCALAR_BYTES: usize = 32;

/// Escape control characters for terminal display, leaving everything else
/// (quotes, non-ASCII) untouched.
///
/// For echoing an untrusted string (a token-borne name, a member-authored id)
/// in an error or prompt without handing the terminal an escape sequence.
/// Narrower than `str::escape_debug`, which also escapes quotes and backslashes
/// and would mangle ordinary messages.
pub fn escape_control(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The supported output modes, in display order
pub const MODES: [&str; 5] = ["hex", "alpha", "b10", "b58", "bip39"];

/// Longest `alpha`-mode string we will emit
pub fn max_alpha_len() -> usize {
    78
}

/// Longest `b10`-mode string we will emit
pub fn max_b10_len() -> usize {
    78
}

/// Longest `hex`-mode string we will emit (`0x` + two chars per byte)
pub fn max_hex_len() -> usize {
    2 * SCALAR_BYTES + 2
}

/// Longest `b58`-mode string we will emit (32 bytes in base58)
pub fn max_b58_len() -> usize {
    (SCALAR_BYTES as f32 * 8.0 / 58f32.log2()).ceil() as usize
}

/// Longest `bip39`-mode string we will emit (`refrigerator` × 24 + 23 spaces)
pub fn max_bip39_len() -> usize {
    311
}

/// Longest string emittable in the given mode, or `None` for an unknown mode
pub fn max_len(mode: &str) -> Option<usize> {
    match mode {
        "alpha" => Some(max_alpha_len()),
        "b10" => Some(max_b10_len()),
        "hex" => Some(max_hex_len()),
        "b58" => Some(max_b58_len()),
        "bip39" => Some(max_bip39_len()),
        _ => None,
    }
}

/// The mode's "zero" character, used to left-pad a rendering that came out
/// shorter than a requested `--length` (b10/b58/alpha renderings have
/// data-dependent length; padding keeps every stored length reproducible).
fn pad_char(mode: &str) -> char {
    match mode {
        "b58" => '1',   // base58 digit zero
        "alpha" => 'A', // alpha digit zero (uppercase 'a' per the case rule)
        _ => '0',       // b10 / hex
    }
}

/// Map a base-10 string to the custom case-encoded alphabetic alphabet
fn b10_to_alpha(b10: String) -> String {
    b10.chars()
        .map(|c| {
            let digit = c.to_digit(10).unwrap();
            let c = char::from_digit(digit + 10, 20).unwrap();
            if digit % 2 == 1 {
                c
            } else {
                c.to_uppercase().collect::<Vec<char>>()[0]
            }
        })
        .collect()
}

/// The **default** set of characters `--symbols` mixes into the alphabet when
/// given no explicit set. Broad enough to add real entropy, curated to dodge
/// characters that commonly break shells, CSVs, URLs, or naive password
/// validators-— no quotes, backslash, backtick, space, slash, pipe, tilde, or
/// angle brackets.
///
/// That curation describes this default, not a global rule: a user who passes
/// `--symbols=<set>` has opted out of it, and [`validate_symbol_set`] admits any
/// printable-ASCII set that stays disjoint from the mode's base alphabet.
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:;,.?";

/// The ordered base alphabet for a **positional** mode, or `None` for modes
/// that aren't a clean positional base (`alpha`, `bip39`) and so can't carry
/// `--symbols`. The first character is the mode's "zero" (matches [`pad_char`]).
fn base_alphabet(mode: &str) -> Option<&'static str> {
    match mode {
        "hex" => Some("0123456789abcdef"),
        "b10" => Some("0123456789"),
        "b58" => Some("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
        _ => None,
    }
}

/// Whether `--symbols` is meaningful for `mode` (a clean positional base). The
/// wordlist (`bip39`) and the case-mapped `alpha` code are excluded.
pub fn supports_symbols(mode: &str) -> bool {
    base_alphabet(mode).is_some()
}

/// Whether `set` may extend `mode`'s base alphabet. **The one gate**, called by
/// `render_body` at the point of use, so it covers every source a set can
/// arrive from: a CLI flag, a hand-edited registry, or a peer's share token.
///
/// The checks, in this order:
/// 1. `mode` is a positional base (so it *has* a base alphabet to extend).
/// 2. The set is non-empty.
/// 3. Every byte is printable ASCII (`0x21..=0x7E`) with no whitespace, no
///    control characters, and nothing multi-byte.
/// 4. No character repeats within the set.
/// 5. No character already appears in the mode's base alphabet.
///
/// Checks 3–5 together are what make the rendering **injective**: a positional
/// encoding indexes `alphabet[digit]`, so a repeated or colliding character
/// would map two distinct digits onto one output character.
///
/// There is no length rule and none is needed. The largest set these checks
/// admit is `94 (i.e. |base_alphabet(mode)|`) 36 for `b58`, 78 for `hex`, 84 for
/// `b10`, so the `u8` length prefix in the share-token wire format is safe *by
/// construction*.
///
/// **The set may contain alphanumerics.** `--symbols=ABCDEF` is legal under
/// `hex` (whose base alphabet is lowercase) and `--symbols=0OIl` is legal under
/// `b58` (the four characters base58 omits). The flag is really
/// `--alphabet-extra`; it keeps its name because the default set is symbols.
pub fn validate_symbol_set(mode: &str, set: &str) -> Result<(), String> {
    let base = base_alphabet(mode)
        .ok_or_else(|| format!("--symbols works only with modes hex, b10, b58 (not '{mode}')"))?;
    if set.is_empty() {
        return Err("--symbols set must not be empty".into());
    }
    for (i, c) in set.char_indices() {
        if !matches!(c, '\x21'..='\x7e') {
            return Err(format!(
                "--symbols set must be printable ASCII (no whitespace or control \
                 characters); found {c:?}"
            ));
        }
        if set[..i].contains(c) {
            return Err(format!("--symbols set repeats {c:?}"));
        }
        if base.contains(c) {
            return Err(format!(
                "--symbols set contains {c:?}, which mode '{mode}' already uses"
            ));
        }
    }
    Ok(())
}

/// Encode `n` as a big-endian positional number in the given ASCII `alphabet`
/// (a base-`alphabet.len()` rendering). Deterministic: the sole source of the
/// "randomly distributed" symbols is the secret's own bits, so the same recipe
/// reproduces the same string every time.
fn encode_biguint(mut n: BigUint, alphabet: &[u8]) -> String {
    let base = BigUint::from(alphabet.len());
    let zero = BigUint::from(0u32);
    if n == zero {
        return String::from(alphabet[0] as char);
    }
    let mut out: Vec<u8> = Vec::new();
    while n > zero {
        let rem = &n % &base;
        // `rem < base`, so it fits in a single 32-bit digit (or is zero)
        let idx = rem.to_u32_digits().first().copied().unwrap_or(0) as usize;
        out.push(alphabet[idx]);
        n /= &base;
    }
    out.reverse();
    // Discharged by `render_body`'s `validate_symbol_set` call, which is the only
    // way a non-builtin alphabet reaches here and which admits printable ASCII
    // only. Note it could NOT be discharged by demoting this to a `map_err`:
    // `from_utf8` inspects the assembled output, not the alphabet, so a
    // multi-byte set would fail or succeed depending on the secret's own bits.
    String::from_utf8(out).expect("alphabet is ASCII")
}

/// Render `bytes` as the raw body of a secret: the plain mode encoding, or
/// (when `symbols` names a set) the same value re-encoded in the mode's base
/// alphabet *extended with that set*, so the extra characters fall out uniformly
/// and deterministically across the string rather than clumping at the end.
///
/// The set's **length and order are part of the recipe**: change either and every
/// derived password changes (the derived *secret* does not; params never enter
/// the derivation, only the rendering).
///
/// This is where [`validate_symbol_set`] is enforced, before the alphabet is
/// built, because this is the one point every caller passes through.
fn render_body(bytes: &[u8], mode: &str, symbols: Option<&str>) -> Result<String, String> {
    let Some(set) = symbols else {
        return format_bytes(bytes, mode);
    };
    validate_symbol_set(mode, set)?;
    let base = base_alphabet(mode).expect("validate_symbol_set accepted this mode");
    let mut alphabet: Vec<u8> = base.bytes().collect();
    alphabet.extend(set.bytes());
    Ok(encode_biguint(BigUint::from_bytes_le(bytes), &alphabet))
}

/// Render a byte string in the given output mode. Errors on an unknown mode
/// or a byte length unsuitable for `bip39`.
pub fn format_bytes(bytes: &[u8], mode: &str) -> Result<String, String> {
    match mode {
        "alpha" => Ok(format!(
            "I{}",
            b10_to_alpha(BigUint::from_bytes_le(bytes).to_string())
        )),
        "b10" => Ok(BigUint::from_bytes_le(bytes).to_string()),
        "b58" => Ok(bs58::encode(bytes).into_string()),
        "hex" => Ok(format!("0x{}", hex::encode(bytes))),
        "bip39" => bip39::Mnemonic::from_entropy(bytes)
            .map(|m| m.to_string())
            .map_err(|e| format!("bip39: {e}")),
        _ => Err(format!("Unknown mode '{mode}'")),
    }
}

/// Render a 32-byte secret, optionally with a `symbols` set mixed into the
/// alphabet, trimmed to a total `length` (including the optional `suffix`).
///
/// The `length` counts the whole output, suffix included. Because b10/b58/
/// alpha renderings have data-dependent length, a rendering shorter than the
/// requested length is left-padded with the mode's zero character, so a stored
/// `(mode, length, symbols, suffix)` recipe reproduces a string of the same
/// shape for every epoch. All invalid parameter combinations are reported as
/// errors.
///
/// `hex` **loses its `0x` prefix** when a symbol set is given: the extended
/// alphabet is re-encoded positionally rather than passed through
/// [`format_bytes`], which is where the prefix is prepended. [`max_hex_len`]
/// still budgets two characters for it, so no length becomes unsatisfiable.
pub fn format_secret(
    secret: &[u8; SCALAR_BYTES],
    mode: &str,
    length: Option<u64>,
    suffix: Option<&str>,
    symbols: Option<&str>,
) -> Result<String, String> {
    if mode == "bip39" && (length.is_some() || suffix.is_some()) {
        return Err("--length and --suffix are not compatible with bip39 output".into());
    }
    let mut secret_str = render_body(secret, mode, symbols)?;
    let suffix = suffix.unwrap_or("");
    if secret_str.len() < 4 * suffix.len() {
        return Err("Secret must be at least 4 times longer than the suffix".into());
    }
    let max = max_len(mode).expect("mode was validated by format_bytes");

    let total = match length {
        None => secret_str.len().saturating_sub(suffix.len()),
        Some(l) => l as usize,
    };
    if total > max {
        return Err(format!("Length can be at most {max} for mode '{mode}'"));
    }
    let need = match total.checked_sub(suffix.len()) {
        Some(n) if n > 0 || suffix.is_empty() => n,
        _ => return Err("Length must exceed the suffix length".into()),
    };

    // Data-dependent short rendering: left-pad so the recipe stays satisfiable
    while secret_str.len() < need {
        secret_str.insert(0, pad_char(mode));
    }

    Ok(secret_str[..need].to_string() + suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> [u8; SCALAR_BYTES] {
        [byte; SCALAR_BYTES]
    }

    // The default symbol set, as `--symbols` (bare) resolves it
    fn dflt() -> Option<&'static str> {
        Some(SYMBOLS)
    }

    // Control characters are neutralized; everything else (i.e. quotes, spaces,
    // non-ASCII) passes through untouched, so ordinary names and error
    // messages read exactly as before.
    #[test]
    fn escape_control_neutralizes_only_control_characters() {
        assert_eq!(escape_control("plain-name_1"), "plain-name_1");
        assert_eq!(
            escape_control("it's \"quoted\" - café"),
            "it's \"quoted\" - café"
        );
        let escaped = escape_control("a\x1b[2Jb\nc\0d");
        assert!(!escaped.contains('\x1b') && !escaped.contains('\n') && !escaped.contains('\0'));
        assert_eq!(escaped, "a\\u{1b}[2Jb\\nc\\0d");
    }

    #[test]
    fn unknown_mode_is_an_error_not_a_panic() {
        assert!(format_bytes(&secret(1), "mr_evil").is_err());
        assert!(format_secret(&secret(1), "mr_evil", None, None, None).is_err());
        assert!(max_len("mr_evil").is_none());
    }

    #[test]
    fn default_length_matches_plain_rendering() {
        for mode in ["hex", "b58", "b10", "alpha", "bip39"] {
            assert_eq!(
                format_secret(&secret(7), mode, None, None, None).unwrap(),
                format_bytes(&secret(7), mode).unwrap()
            );
        }
    }

    #[test]
    fn length_counts_suffix_and_is_applied() {
        let out = format_secret(&secret(3), "hex", Some(12), Some("^%"), None).unwrap();
        assert_eq!(out.len(), 12);
        assert!(out.ends_with("^%"));
        assert!(out.starts_with("0x"));
    }

    #[test]
    fn length_not_exceeding_suffix_is_an_error() {
        // Underflow case that used to panic: total 2 with a 4-byte suffix.
        assert!(format_secret(&secret(3), "b58", Some(2), Some("abc!"), None).is_err());
        // Equal is also rejected (zero secret characters).
        assert!(format_secret(&secret(3), "b58", Some(4), Some("abc!"), None).is_err());
    }

    #[test]
    fn length_beyond_mode_max_is_an_error() {
        assert!(format_secret(&secret(3), "b58", Some(100), None, None).is_err());
        assert!(format_secret(&secret(3), "hex", Some(67), None, None).is_err());
    }

    #[test]
    fn bip39_rejects_length_and_suffix() {
        assert!(format_secret(&secret(3), "bip39", Some(20), None, None).is_err());
        assert!(format_secret(&secret(3), "bip39", None, Some("!"), None).is_err());
        assert!(format_secret(&secret(3), "bip39", None, None, None).is_ok());
    }

    #[test]
    fn short_rendering_is_left_padded_to_the_requested_length() {
        // A tiny value renders short in b10 ("42")-- the recipe must still
        // produce the requested length, deterministically.
        let mut small = [0u8; SCALAR_BYTES];
        small[0] = 42; // little-endian value 42
        assert_eq!(
            format_secret(&small, "b10", Some(6), None, None).unwrap(),
            "000042"
        );
        // b58 reads the byte slice big-endian, so leading zero BYTES render
        // short ("1" per zero byte); padding tops it up with more '1's.
        let mut low = [0u8; SCALAR_BYTES];
        low[SCALAR_BYTES - 1] = 1; // 31 leading zero bytes for bs58
        let unpadded = format_bytes(&low, "b58").unwrap();
        assert!(unpadded.len() < 43, "fixture must render short");
        let out = format_secret(&low, "b58", Some(43), None, None).unwrap();
        assert_eq!(out.len(), 43);
        assert!(out.starts_with('1'));
        assert!(out.ends_with(&unpadded));
    }

    #[test]
    fn padding_never_alters_a_long_enough_rendering() {
        // A full-entropy secret renders ≥ 43 chars in b58; a 20-char trim is a
        // plain prefix of the untrimmed rendering.
        let full = format_bytes(&secret(9), "b58").unwrap();
        let trimmed = format_secret(&secret(9), "b58", Some(20), None, None).unwrap();
        assert_eq!(trimmed, full[..20]);
    }

    // Symbols

    #[test]
    fn symbols_only_for_positional_modes() {
        assert!(supports_symbols("hex"));
        assert!(supports_symbols("b10"));
        assert!(supports_symbols("b58"));
        assert!(!supports_symbols("alpha"));
        assert!(!supports_symbols("bip39"));
        // alpha/bip39 with --symbols is a clean error, not a panic
        assert!(format_secret(&secret(3), "alpha", None, None, dflt()).is_err());
        assert!(format_secret(&secret(3), "bip39", None, None, dflt()).is_err());
        assert!(validate_symbol_set("alpha", "!@").is_err());
        assert!(validate_symbol_set("bip39", "!@").is_err());
    }

    #[test]
    fn symbols_are_deterministic_and_reproducible() {
        // The whole point of the recipe model: same input -> same string, always
        let a = format_secret(&secret(5), "b58", None, None, dflt()).unwrap();
        let b = format_secret(&secret(5), "b58", None, None, dflt()).unwrap();
        assert_eq!(a, b);
        // Different secret -> different string (the symbols track the bits)
        let c = format_secret(&secret(6), "b58", None, None, dflt()).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn symbols_draw_from_the_vocabulary_and_spread_out() {
        // A full-entropy secret picks up several symbols, and they come only
        // from the given set and never a stray char outside it.
        let out = format_secret(&secret(0xAB), "b58", None, None, dflt()).unwrap();
        let syms: Vec<char> = out.chars().filter(|c| SYMBOLS.contains(*c)).collect();
        assert!(
            syms.len() >= 3,
            "expected several symbols, got {syms:?} in {out}"
        );
        // They are distributed through the body, not appended at the end: at
        // least one symbol sits before the final character.
        let last = out.chars().count() - 1;
        let first_sym = out.chars().position(|c| SYMBOLS.contains(c)).unwrap();
        assert!(
            first_sym < last,
            "symbols should be interior, not just a suffix"
        );
    }

    #[test]
    fn the_default_symbol_set_is_valid_for_every_mode_that_takes_one() {
        for mode in MODES {
            assert_eq!(
                validate_symbol_set(mode, SYMBOLS).is_ok(),
                supports_symbols(mode),
                "the built-in default must be usable exactly where symbols are"
            );
        }
    }

    #[test]
    fn symbols_respect_length_and_can_combine_with_suffix() {
        let out = format_secret(&secret(7), "b58", Some(20), Some("!!"), dflt()).unwrap();
        assert_eq!(out.chars().count(), 20);
        assert!(
            out.ends_with("!!"),
            "the fixed suffix still lands at the end"
        );
    }

    // Custom symbol sets

    #[test]
    fn a_custom_set_equal_to_the_default_renders_identically() {
        // Bare `--symbols` resolves to SYMBOLS, so the two spellings are one
        // recipe. This is what lets the stored form always name its alphabet.
        assert_eq!(
            format_secret(&secret(0x5A), "b58", None, None, dflt()).unwrap(),
            format_secret(&secret(0x5A), "b58", None, None, Some(SYMBOLS)).unwrap()
        );
    }

    #[test]
    fn set_order_is_load_bearing() {
        // The set's order is part of the recipe: it fixes which digit maps to
        // which character. Two orderings coincide for any secret whose digits
        // never land on the reordered indices, so this asserts against a fixed
        // fixture rather than as a law.
        let a = format_secret(&secret(0xC3), "b58", None, None, Some("!@")).unwrap();
        let b = format_secret(&secret(0xC3), "b58", None, None, Some("@!")).unwrap();
        assert_ne!(
            a, b,
            "swapping the last two alphabet slots must change this fixture"
        );
    }

    #[test]
    fn set_length_is_load_bearing() {
        // A longer set is a larger base, so the whole rendering changes
        let a = format_secret(&secret(0xC3), "b58", None, None, Some("!")).unwrap();
        let b = format_secret(&secret(0xC3), "b58", None, None, Some("!@")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_custom_set_draws_only_from_itself_and_the_base_alphabet() {
        let set = "!@#$";
        let out = format_secret(&secret(0xAB), "b58", None, None, Some(set)).unwrap();
        let base = base_alphabet("b58").unwrap();
        assert!(
            out.chars().all(|c| base.contains(c) || set.contains(c)),
            "{out} drew a character from outside b58 ∪ {set}"
        );
        assert!(
            out.chars().any(|c| set.contains(c)),
            "the set must actually appear"
        );
    }

    // Every rejected set must be rejected at **both** gates: the validator the
    // CLI calls up front, and `format_secret`, which is `pub`, reachable with a
    // hand-edited registry or a peer's share token, and must never panic.
    #[test]
    fn invalid_sets_are_rejected_at_both_gates() {
        let cases: [(&str, &str); 6] = [
            ("b58", ""),       // empty
            ("b58", "!!"),     // duplicate character
            ("b58", "1"),      // '1' is base58's zero digit
            ("hex", "a"),      // 'a' is a hex digit
            ("b10", "\u{a3}"), // non-ASCII (£, two UTF-8 bytes)
            ("b58", "a b"),    // whitespace is not printable ASCII
        ];
        for (mode, set) in cases {
            assert!(
                validate_symbol_set(mode, set).is_err(),
                "validate_symbol_set({mode}, {set:?}) must reject"
            );
            assert!(
                format_secret(&secret(3), mode, None, None, Some(set)).is_err(),
                "format_secret({mode}, {set:?}) must reject"
            );
        }
    }

    // A set may legally contain alphanumerics the mode's base alphabet omits.
    // Accepted deliberately: the rule is disjointness, not punctuation.
    #[test]
    fn a_set_may_contain_characters_the_base_alphabet_omits() {
        assert!(validate_symbol_set("hex", "ABCDEF").is_ok()); // hex's base is lowercase
        assert!(validate_symbol_set("b58", "0OIl").is_ok()); // the four b58 omits
        assert!(validate_symbol_set("b58", "'").is_ok()); // and a quote, too
        assert!(format_secret(&secret(3), "hex", None, None, Some("ABCDEF")).is_ok());
    }

    // The gate lives in `render_body`, not in `encode_biguint`'s `from_utf8`.
    //
    // Demoting that `expect` to a `map_err` would make the error **data-
    // dependent**: `from_utf8` inspects the assembled output, so a two-byte set
    // character errors only for the secrets whose digits happen to split it.
    // The recipe's central promise (same recipe, same string, every time)
    // would break, and where it *did* succeed the byte-indexed trim in
    // `format_secret` would panic mid-character instead.
    #[test]
    fn a_non_ascii_set_fails_for_every_fixture_not_merely_some() {
        for byte in 0..=u8::MAX {
            for length in [None, Some(10), Some(20)] {
                assert!(
                    format_secret(&secret(byte), "b58", length, None, Some("£")).is_err(),
                    "secret({byte}) with length {length:?} must be rejected, not rendered"
                );
            }
        }
    }

    #[test]
    fn hex_with_symbols_loses_its_0x_prefix() {
        // Documented consequence: the extended alphabet is re-encoded
        // positionally, bypassing `format_bytes` where "0x" is prepended.
        let plain = format_secret(&secret(7), "hex", None, None, None).unwrap();
        let with = format_secret(&secret(7), "hex", None, None, dflt()).unwrap();
        assert!(plain.starts_with("0x"));
        assert!(!with.starts_with("0x"));
    }

    // The checks structurally cap a set below the `u8` length prefix the share-
    // token wire format uses. No length rule is needed; this is why.
    #[test]
    fn the_largest_admissible_set_is_far_below_a_u8() {
        for mode in ["hex", "b10", "b58"] {
            let base = base_alphabet(mode).unwrap();
            let widest: String = (0x21u8..=0x7e)
                .map(char::from)
                .filter(|c| !base.contains(*c))
                .collect();
            assert!(validate_symbol_set(mode, &widest).is_ok());
            assert_eq!(widest.len(), 94 - base.len());
            assert!(widest.len() < u8::MAX as usize);
        }
    }
}
