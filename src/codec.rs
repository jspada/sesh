//! base58check framing for the human-pasted tokens: **contact tokens**,
//! **setup tokens**, and **share tokens**.
//!
//! Every token is a versioned, type-tagged payload with a trailing 4-byte
//! checksum, base58-encoded with the Bitcoin alphabet:
//!
//! ```text
//! payload = type(1) ‖ version(1) ‖ body
//! encoded = base58( payload ‖ checksum4 )
//! ```
//!
//! where `checksum4 = SHA3-256(payload)[..4]`.
//!
//! The `type`/`version` framing rejects cross-use (pasting a contact token where
//! a setup token is expected) and stale versions on **honest** input; the
//! checksum catches **accidental corruption**, such as a mistyped or truncated
//! paste, *before* any cryptography runs. It is emphatically **not** a tamper
//! defense: an attacker who substitutes a whole token simply recomputes the
//! checksum. Authentication rests on the secure channel over which contact
//! pubkeys are pinned and on the per-group signatures, never on this checksum.
//!
//! The version byte therefore sits in the clear, outside every ciphertext. The
//! sealed tokens ([`crate::protocol::SetupToken`], [`crate::protocol::ShareToken`])
//! bind it *again*, cryptographically, in their AEAD associated data and signed
//! message, so rewriting the byte and recomputing the checksum yields a token
//! that fails to open, not one a future build might accept.

use std::fmt;

use sha3::{Digest, Sha3_256};

/// Number of trailing checksum bytes appended before base58 encoding
pub const CHECKSUM_LEN: usize = 4;

/// Type tag for a **contact token** (`type=0x01`): a peer's long-term public
/// identity (and its name), shared once over a secure channel and pinned.
pub const TYPE_CONTACT: u8 = 0x01;
/// Current version of the contact-token body layout
pub const VERSION_CONTACT: u8 = 1;

/// Type tag for a **setup token** (`type=0x02`): a per-group signed child pubkey
/// exchanged when forming a shared secret.
pub const TYPE_TOKEN: u8 = 0x02;
/// Current version of the setup-token body layout: the body (name, child
/// pubkeys, signature) is encrypted under the members' long-term DH/Joux wrap
/// key, leaving only the party count in the clear.
pub const VERSION_TOKEN: u8 = 1;

/// Type tag for a **share token** (`type=0x03`): a signed, group-bound
/// hd-secret registry change (`NEW`/`UPDATE`/`REMOVE`).
pub const TYPE_SHARE: u8 = 0x03;
/// Current version of the share-token body layout: the body is encrypted under
/// the group secret `K`, leaving only the routing `group_ctx` in the clear.
pub const VERSION_SHARE: u8 = 1;

/// Errors from decoding a base58check token
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The string is not valid base58 (illegal characters)
    NotBase58,
    /// The decoded payload is too short to hold the frame + checksum
    TooShort,
    /// The trailing checksum does not match, the token looks mistyped or
    /// truncated. This is a friendly "check your paste" signal, not a security
    /// verdict
    BadChecksum,
    /// The token's type tag is not the one this call expected (e.g. a contact
    /// token pasted where a setup token belongs)
    WrongType {
        /// The type tag the caller required
        expected: u8,
        /// The type tag actually found in the token
        found: u8,
    },
    /// The token's version is not the one this build understands
    WrongVersion {
        /// The version the caller required
        expected: u8,
        /// The version actually found in the token
        found: u8,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::NotBase58 => write!(f, "Not valid base58 (illegal character)"),
            CodecError::TooShort => write!(f, "Pasted value is too short to be valid"),
            CodecError::BadChecksum => write!(
                f,
                "Checksum mismatch - the pasted value looks mistyped or truncated; \
                 make sure you copied the whole token (these can be long)"
            ),
            CodecError::WrongType { expected, found } => write!(
                f,
                "Wrong token type: expected 0x{expected:02x}, found 0x{found:02x}"
            ),
            CodecError::WrongVersion { expected, found } => write!(
                f,
                "Unsupported token version {found} (this build understands {expected})"
            ),
        }
    }
}

impl std::error::Error for CodecError {}

/// The 4-byte checksum over the (type ‖ version ‖ body) payload.
fn checksum4(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha3_256::digest(payload);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// Encode a framed body as a base58check string.
///
/// The returned string is `base58( type ‖ version ‖ body ‖ checksum4 )`.
pub fn encode(type_tag: u8, version: u8, body: &[u8]) -> String {
    let mut payload = Vec::with_capacity(2 + body.len() + CHECKSUM_LEN);
    payload.push(type_tag);
    payload.push(version);
    payload.extend_from_slice(body);
    let checksum = checksum4(&payload);
    payload.extend_from_slice(&checksum);
    bs58::encode(payload).into_string()
}

/// Decode and fully frame-check a base58check string, returning the `body`.
///
/// Checks are ordered cheapest-and-friendliest first: base58 validity, then the
/// integrity checksum (the "looks mistyped" signal), then the type and version
/// guards. **All** whitespace is stripped first (base58 never contains any) so
/// a long token that a terminal soft-wrapped or an email folded across lines
/// (introducing spaces or newlines) still decodes; only genuinely missing or
/// altered characters fail the checksum.
pub fn decode(s: &str, expected_type: u8, expected_version: u8) -> Result<Vec<u8>, CodecError> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = bs58::decode(&cleaned)
        .into_vec()
        .map_err(|_| CodecError::NotBase58)?;

    if raw.len() < 2 + CHECKSUM_LEN {
        return Err(CodecError::TooShort);
    }

    let (payload, checksum) = raw.split_at(raw.len() - CHECKSUM_LEN);
    if checksum4(payload).as_slice() != checksum {
        return Err(CodecError::BadChecksum);
    }

    let type_tag = payload[0];
    if type_tag != expected_type {
        return Err(CodecError::WrongType {
            expected: expected_type,
            found: type_tag,
        });
    }
    let version = payload[1];
    if version != expected_version {
        return Err(CodecError::WrongVersion {
            expected: expected_version,
            found: version,
        });
    }

    Ok(payload[2..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_body() {
        let body = b"the quick brown fox".to_vec();
        let encoded = encode(TYPE_CONTACT, VERSION_CONTACT, &body);
        let decoded = decode(&encoded, TYPE_CONTACT, VERSION_CONTACT).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn round_trip_empty_body() {
        let encoded = encode(TYPE_TOKEN, VERSION_TOKEN, &[]);
        assert_eq!(
            decode(&encoded, TYPE_TOKEN, VERSION_TOKEN).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let body = b"payload".to_vec();
        let encoded = encode(TYPE_TOKEN, VERSION_TOKEN, &body);
        let padded = format!("  {encoded}\n");
        assert_eq!(decode(&padded, TYPE_TOKEN, VERSION_TOKEN).unwrap(), body);
    }

    #[test]
    fn internal_whitespace_is_stripped() {
        // A long token that a terminal or email wrapped across lines (spaces,
        // newlines, tabs injected mid-token) must still decode, but base58 never
        // contains whitespace, so stripping it is always safe.
        let body = b"a reasonably long token body that might wrap on paste".to_vec();
        let encoded = encode(TYPE_TOKEN, VERSION_TOKEN, &body);
        let mid = encoded.len() / 2;
        let wrapped = format!(
            "{}\n  {} \t{}",
            &encoded[..mid],
            &encoded[mid..mid + 5],
            &encoded[mid + 5..]
        );
        assert_eq!(decode(&wrapped, TYPE_TOKEN, VERSION_TOKEN).unwrap(), body);
    }

    #[test]
    fn a_truncated_token_still_fails_checksum() {
        // Stripping whitespace must NOT mask genuine loss of characters
        let encoded = encode(TYPE_TOKEN, VERSION_TOKEN, b"important token body");
        let truncated = &encoded[..encoded.len() - 6];
        assert!(matches!(
            decode(truncated, TYPE_TOKEN, VERSION_TOKEN),
            Err(CodecError::BadChecksum) | Err(CodecError::TooShort)
        ));
    }

    #[test]
    fn flipped_character_fails_checksum() {
        let body = b"important token body".to_vec();
        let encoded = encode(TYPE_TOKEN, VERSION_TOKEN, &body);

        // Flip one character to a *different valid base58 character*, so the
        // failure is the checksum (not a base58 decode error).
        let mut chars: Vec<char> = encoded.chars().collect();
        let idx = chars.len() / 2;
        let replacement = if chars[idx] == 'A' { 'B' } else { 'A' };
        chars[idx] = replacement;
        let corrupted: String = chars.into_iter().collect();

        // If we happened to land on an unchanged char, the test is still valid
        // because a genuine corruption is what we assert against.
        assert_ne!(corrupted, encoded);
        assert_eq!(
            decode(&corrupted, TYPE_TOKEN, VERSION_TOKEN),
            Err(CodecError::BadChecksum)
        );
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let encoded = encode(TYPE_TOKEN, VERSION_TOKEN, b"body");
        let truncated = &encoded[..encoded.len() - 2];
        assert!(matches!(
            decode(truncated, TYPE_TOKEN, VERSION_TOKEN),
            Err(CodecError::BadChecksum) | Err(CodecError::TooShort)
        ));
    }

    #[test]
    fn type_mismatch_is_rejected() {
        let encoded = encode(TYPE_CONTACT, VERSION_CONTACT, b"identity");
        assert_eq!(
            decode(&encoded, TYPE_TOKEN, VERSION_TOKEN),
            Err(CodecError::WrongType {
                expected: TYPE_TOKEN,
                found: TYPE_CONTACT,
            })
        );
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let encoded = encode(TYPE_CONTACT, 2, b"identity");
        assert_eq!(
            decode(&encoded, TYPE_CONTACT, VERSION_CONTACT),
            Err(CodecError::WrongVersion {
                expected: VERSION_CONTACT,
                found: 2,
            })
        );
    }

    #[test]
    fn non_base58_input_is_rejected() {
        // '0', 'O', 'I', 'l' are not in the Bitcoin base58 alphabet
        assert_eq!(
            decode("0OIl not base58!", TYPE_CONTACT, VERSION_CONTACT),
            Err(CodecError::NotBase58)
        );
    }

    #[test]
    fn empty_input_is_too_short() {
        // The empty string base58-decodes to zero bytes
        assert_eq!(
            decode("", TYPE_CONTACT, VERSION_CONTACT),
            Err(CodecError::TooShort)
        );
    }

    #[test]
    fn checksum_covers_type_and_version() {
        // A blob whose type byte is edited (keeping everything else) must fail
        // the checksum, because the checksum is over type ‖ version ‖ body.
        let encoded = encode(TYPE_CONTACT, VERSION_CONTACT, b"x");
        let mut raw = bs58::decode(&encoded).into_vec().unwrap();
        raw[0] = TYPE_TOKEN; // flip type without fixing the checksum
        let reencoded = bs58::encode(raw).into_string();
        assert_eq!(
            decode(&reencoded, TYPE_TOKEN, VERSION_TOKEN),
            Err(CodecError::BadChecksum)
        );
    }
}
