//! TOTP (RFC 6238) semantics for `--mode otp` secrets.
//!
//! This module is the **single source of truth** for every OTP constant, so
//! the Base32 export ([`crate::format`]), the live code computation, and the
//! `otpauth://` URI can never disagree about key width, period, or digits.
//!
//! The choices are the RFC defaults on purpose (see the design notes on each
//! constant): they are what every authenticator app, password safe, and OATH
//! hardware key is tested against, and sesh generates its own secrets, so
//! there is nothing to be gained by configurability that could only create
//! ways to disagree with an export.
//!
//! **On SHA-1.** RFC 6238's default (and universally supported) HMAC is
//! HMAC-SHA-1, and that is what this module implements. SHA-1's collision
//! breaks do **not** apply here: HMAC's security rests on the compression
//! function behaving as a PRF, not on collision resistance, and HMAC-SHA-1
//! remains unbroken in that role. A future audit should not trip on the
//! `sha1` dependency-- it is RFC-mandated, used only inside HMAC, and only
//! for 6-digit codes with a 30-second lifetime.

use zeroize::Zeroize;

use crate::format::SCALAR_BYTES;

/// TOTP shared-secret width in bytes: 160 bits, per RFC 4226 §4 R6 (which
/// RECOMMENDs a 160-bit shared secret) and RFC 6238's recommendation that the
/// key match the hash output length (20 bytes for SHA-1).
///
/// 20 bytes also encode to **exactly 32 unpadded Base32 characters** (160 =
/// 32 × 5, no leftover bits), the industry-standard secret size every app's
/// manual-entry path is tested against. A padded or 52-character secret is
/// RFC-legal but breaks real imports (Google Authenticator rejects `=`).
pub const KEY_BYTES: usize = 20;

/// The TOTP time step in seconds (RFC 6238's default `X = 30`)
pub const PERIOD: u64 = 30;

/// Code length in decimal digits (RFC 4226's minimum and universal default)
pub const DIGITS: u32 = 6;

/// The TOTP key for a derived child secret: its first [`KEY_BYTES`] bytes.
///
/// This is **the one place** the 32 -> 20 byte truncation happens; the Base32
/// arm of [`crate::format::format_bytes`] and [`code`] both go through it, so
/// the exported secret and the computed code always agree. A fixed, documented
/// truncation of uniformly random bytes, like `--length` trims elsewhere in
/// sesh: the child scalar is full-entropy, so its 20-byte prefix carries the
/// full 160 bits the key width calls for.
pub fn key(secret: &[u8; SCALAR_BYTES]) -> &[u8] {
    &secret[..KEY_BYTES]
}

/// The 6-digit TOTP code for `key` at `unix_secs` (RFC 6238: HOTP over the
/// number of [`PERIOD`]-second steps since the Unix epoch), zero-padded so a
/// code below 100000 still prints 6 digits.
pub fn code(key: &[u8], unix_secs: u64) -> String {
    hotp(key, unix_secs / PERIOD)
}

/// Seconds until the current TOTP window rolls over (1..=[`PERIOD`]): the
/// remaining validity of [`code`] at the same instant. At an exact window
/// boundary a fresh window has just opened, so the answer is [`PERIOD`].
pub fn secs_left_in_window(unix_secs: u64) -> u64 {
    PERIOD - (unix_secs % PERIOD)
}

/// HOTP (RFC 4226): HMAC-SHA-1 over the big-endian 8-byte counter, dynamically
/// truncated per §5.3 (offset = low nibble of the last byte; take 31 bits from
/// there), reduced modulo 10^[`DIGITS`].
fn hotp(key: &[u8], counter: u64) -> String {
    use hmac::{Hmac, Mac};

    let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(key)
        .expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    // Copy the tag into a plain array so it can be scrubbed: the full tag
    // determines the code for this window, so it gets the same hygiene as the
    // code itself (best-effort-- the MAC's own internal buffers are handled by
    // the RustCrypto crates).
    let mut digest = [0u8; 20];
    digest.copy_from_slice(&mac.finalize().into_bytes());

    // Dynamic truncation (RFC 4226 §5.3): the low nibble of the final byte
    // picks a 4-byte window (offset ≤ 15, so offset+3 ≤ 18 < 20), whose top
    // bit is masked to sidestep signedness ambiguity.
    let offset = (digest[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    digest.zeroize();
    format!("{:0width$}", bin % 10u32.pow(DIGITS), width = DIGITS as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The RFC 4226/6238 test key: the 20-byte ASCII string "12345678901234567890"
    const RFC_KEY: &[u8; 20] = b"12345678901234567890";

    // RFC 4226 Appendix D: HOTP values for counters 0..=9 under the standard
    // test key, truncated to 6 digits.
    #[test]
    fn rfc4226_appendix_d_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(
                hotp(RFC_KEY, counter as u64),
                *want,
                "counter {counter}"
            );
        }
    }

    // RFC 6238 Appendix B, SHA-1 rows. The RFC prints 8-digit codes; the
    // 6-digit code is the same 31-bit value mod 10^6, i.e. the last 6 digits.
    #[test]
    fn rfc6238_appendix_b_sha1_vectors() {
        let expected: [(u64, &str); 6] = [
            (59, "287082"),            // 94287082
            (1111111109, "081804"),    // 07081804
            (1111111111, "050471"),    // 14050471
            (1234567890, "005924"),    // 89005924
            (2000000000, "279037"),    // 69279037
            (20000000000, "353130"),   // 65353130
        ];
        for (t, want) in expected {
            assert_eq!(code(RFC_KEY, t), want, "T = {t}");
        }
    }

    // A code below 100000 keeps its leading zeros: what you read must be the
    // 6 characters you type. (T = 1111111109 is such a vector: 081804.)
    #[test]
    fn codes_are_zero_padded_to_six_digits() {
        let c = code(RFC_KEY, 1111111109);
        assert_eq!(c.len(), DIGITS as usize);
        assert!(c.starts_with('0'));
        // And every code is exactly 6 ASCII digits, across a sweep of times
        for t in (0..90_000u64).step_by(1_000) {
            let c = code(RFC_KEY, t);
            assert_eq!(c.len(), 6, "T = {t}");
            assert!(c.bytes().all(|b| b.is_ascii_digit()), "T = {t}: {c}");
        }
    }

    // The code is constant within a window and changes across its boundary
    // (equality across a boundary is possible in principle for some key, but
    // not for this fixed one).
    #[test]
    fn code_tracks_the_thirty_second_window() {
        assert_eq!(code(RFC_KEY, 60), code(RFC_KEY, 89));
        assert_ne!(code(RFC_KEY, 59), code(RFC_KEY, 60));
    }

    #[test]
    fn secs_left_counts_down_to_the_window_boundary() {
        assert_eq!(secs_left_in_window(0), 30);
        assert_eq!(secs_left_in_window(1), 29);
        assert_eq!(secs_left_in_window(29), 1);
        assert_eq!(secs_left_in_window(30), 30);
        assert_eq!(secs_left_in_window(59), 1);
        // Always in 1..=PERIOD: never 0 (a fresh window opens at the boundary)
        for t in 0..120 {
            let left = secs_left_in_window(t);
            assert!((1..=PERIOD).contains(&left), "t = {t}: {left}");
        }
    }

    // The key is the child's 20-byte prefix, exactly: the one documented
    // truncation, shared by the Base32 export and the code computation.
    #[test]
    fn key_is_a_twenty_byte_prefix_of_the_child() {
        let child: [u8; SCALAR_BYTES] = std::array::from_fn(|i| i as u8);
        let k = key(&child);
        assert_eq!(k.len(), KEY_BYTES);
        assert_eq!(k, &child[..KEY_BYTES]);
    }
}
