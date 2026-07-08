//! Decentralized backup: the `shared-secret export` / `import` payload.
//!
//! A group's master `K` lives nowhere. It is re-derived on every command from
//! your seed plus the peers' setup tokens, and the `hd-secret` recipes it keys
//! live in a registry encrypted under that seed. Lose the machine and you lose
//! the tokens and the recipes, even though every surviving member already holds
//! a complete copy of both, because [`SharedSecretState::peers`][peers] records
//! *every* peer's setup token and [`derive_group_key`][dgk] needs only those plus
//! the importer's own child scalar.
//!
//! This module is the pure layer of the file that hands them back: build, seal,
//! open, verify. It knows nothing of the keystore beyond [`peek_version`], and
//! nothing of the CLI.
//!
//! # The wrap key is the membership
//!
//! The envelope is sealed under [`setup_wrap_key`][swk], the static
//! multiparty DH/Joux value over the members' *long-term* identity keys, with the
//! sorted 192-byte member identities hashed in. No other key in the system will
//! do:
//!
//! * It needs no `K`. The recovering member does not have `K`; reconstructing it
//!   is what the file is *for*. Sealing under
//!   [`share_wrap_key`][crate::crypto::share_wrap_key] would be circular.
//! * It needs no group state. Only your seed and your pinned contacts, both of
//!   which a recovering member re-establishes from a mnemonic and two
//!   out-of-band pins.
//! * It is membership-exact. A file sealed for `{alice, bob}` will not open for
//!   `{alice, carol}`: the wrong `--party` set is an AEAD authentication
//!   failure, not a subtly wrong result.
//!
//! There is **no forward secrecy**: the keys are static, so a member's seed
//! leaking later decrypts every export ever sent. That makes the file as
//! sensitive as the group's setup tokens, which have always been pasted over
//! whatever channel the user had. It carries no seed, no `K`, no child scalar
//! and no rendered password, so `K` cannot be derived from it: the first
//! argument of `derive_group_key(my_child_scalar(my_seed, ctx), peer_tokens)` is
//! not in the file and cannot be computed from it.
//!
//! # Four verification layers
//!
//! They are not the same thing and they fail separately.
//!
//! 1. **AEAD tag.** Corruption and tampering. Every member holds the wrap key,
//!    so this is integrity, never attribution.
//! 2. **BLS signature over the plaintext, sealed inside the ciphertext.**
//!    Attribution. [`verify_signer`] identifies the exporter by trying each
//!    pinned member's key, exactly as [`ShareToken::verify`][sv] identifies an
//!    editor. Sign-then-encrypt, so an eavesdropper cannot even attribute the
//!    file. An outsider cannot forge one and they cannot seal one.
//! 3. **The agreement checksum over `K`.** The end-to-end confirmation that both
//!    sides hold the same group master. This is the security-relevant answer,
//!    and the caller prints it.
//! 4. **Per-definition `hd_fingerprint`, recomputed and compared**
//!    ([`check_fingerprints`]). Redundant given 1–3, and this module should not
//!    pretend otherwise: if the AEAD opened, the signature verified over those
//!    exact param bytes, and the checksum confirms the same `K`, the
//!    fingerprints match by construction. It ships as a **snare** for the class
//!    of bugs that would otherwise be silent-- a params-encoding drift, an
//!    archive row filed under the wrong epoch. Layer 3 is the security property;
//!    layer 4 is a self-check.
//!
//! [peers]: crate::keystore::SharedSecretState::peers
//! [dgk]: crate::protocol::derive_group_key
//! [swk]: crate::protocol::setup_wrap_key
//! [sv]: crate::protocol::ShareToken::verify

use std::fmt;

use blstrs::Scalar;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{
    self, bls_verify, canonical_hd_context, derive_sig_scalar, hd_child, hd_fingerprint,
    CryptoError, PublicIdentity, BLS_SIG_BYTES, G1_COMPRESSED, G2_COMPRESSED, SEED_BYTES,
};
use crate::keystore::peek_version;
use crate::protocol::{Parties, ProtocolError, SetupToken};
use crate::registry::{Definition, Registry, REGISTRY_VERSION};

/// Schema version of the **file framing**: the JSON envelope, its cipher, and
/// the AAD that binds it. Bumped when the layout around the ciphertext changes.
///
/// Deliberately distinct from [`EXPORT_VERSION`], which versions the body the
/// ciphertext protects; the same split as `REGISTRY_AAD_VERSION` vs
/// [`REGISTRY_VERSION`]. [`open`] checks this one before decrypting and that one
/// after.
pub const EXPORT_ENVELOPE_VERSION: u32 = 1;

/// Schema version of the **body document** ([`ExportBody`]), as it exists once
/// decrypted. Bumped when a field's shape changes.
pub const EXPORT_VERSION: u32 = 1;

/// AEAD associated-data tag for the envelope. Names a domain only-— the version
/// is bound as a number beside it, by the private `aad` helper: the pattern
/// `backup.rs` and `protocol.rs` both use.
pub const EXPORT_AAD_TAG: &[u8] = b"sesh-export-aad";

/// Domain tag prefixing the message the exporter's BLS signature covers.
/// Distinct from [`EXPORT_AAD_TAG`]: one separates a signature domain, the other
/// an AES-GCM associated-data domain, and two cryptographic domains must never
/// share a tag by accident.
pub const EXPORT_MSG_TAG: &[u8] = b"sesh-export-msg";

/// The one cipher an envelope may name
const CIPHER_ALGORITHM: &str = "aes-256-gcm";

/// Errors from building, sealing, opening, or verifying an export payload
#[derive(Debug)]
pub enum ExportError {
    /// The envelope or body is structurally malformed
    BadFormat(String),
    /// (De)serialization error
    Serde(serde_json::Error),
    /// AEAD authentication failed: the file is not sealed for this exact
    /// membership, or it was tampered with. The two are indistinguishable by
    /// design (see [`CryptoError::TokenDecrypt`]).
    Decrypt,
    /// A version this build does not speak
    UnsupportedVersion {
        /// Which version field: `envelope`, `body`, or `registry schema`
        what: &'static str,
        /// The version found in the file
        found: u32,
    },
    /// No pinned member's signing key verifies the payload signature
    BadSignature,
    /// A point in a token failed decoding or subgroup validation
    Crypto(CryptoError),
    /// A token was structurally rejected by the protocol layer
    Protocol(ProtocolError),
    /// A definition's recomputed `hd_fingerprint` does not match the file's
    FingerprintMismatch {
        /// The `(id, user)` selector, already formatted
        key: String,
        /// The epoch whose fingerprint diverged
        epoch: u64,
    },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportError::BadFormat(m) => write!(f, "Malformed export: {m}"),
            ExportError::Serde(e) => write!(f, "Export serialization error: {e}"),
            ExportError::Decrypt => write!(
                f,
                "Export could not be decrypted (not sealed for this membership, or tampered)"
            ),
            ExportError::UnsupportedVersion { what, found } => {
                write!(f, "Unsupported export {what} version {found}")
            }
            ExportError::BadSignature => write!(
                f,
                "Export is not signed by any member of this group (signature verification failed)"
            ),
            ExportError::Crypto(e) => write!(f, "{e}"),
            ExportError::Protocol(e) => write!(f, "{e}"),
            ExportError::FingerprintMismatch { key, epoch } => write!(
                f,
                "Fingerprint mismatch for {key} at epoch {epoch}: the recipe in the file does \
                 not derive the secret it claims. Nothing was written."
            ),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<serde_json::Error> for ExportError {
    fn from(e: serde_json::Error) -> Self {
        ExportError::Serde(e)
    }
}
impl From<CryptoError> for ExportError {
    fn from(e: CryptoError) -> Self {
        ExportError::Crypto(e)
    }
}
impl From<ProtocolError> for ExportError {
    fn from(e: ProtocolError) -> Self {
        ExportError::Protocol(e)
    }
}

type Result<T> = std::result::Result<T, ExportError>;

/// One member's setup token, as the payload carries it: child pubkeys plus the
/// BLS signature binding them to the group context. All public values.
///
/// `child_g2` is present **iff** the group is 3-party, and [`decode_tokens`]
/// enforces it, the same structural rule `load_shared_secret` keeps on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    /// Hex of the compressed per-group child pubkey `g * G1` (48 bytes)
    pub child_g1: String,
    /// Hex of the compressed per-group child pubkey `g * G2` (96 bytes), 3-party only
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub child_g2: Option<String>,
    /// Hex of the compressed BLS signature (96 bytes)
    pub signature: String,
}

/// One definition's `hd_fingerprint`, positionally aligned with the registry
/// rows [`fingerprinted_rows`] yields.
///
/// The `(id, user, epoch)` fields are **not a key**; they cannot be, because a
/// live entry and an archived recipe may share all three after a
/// `create --recover`. They are carried so a mismatch can name the row it found,
/// and [`open`] checks them positionally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FprRecord {
    /// The definition's id
    pub id: String,
    /// The definition's sub-account (empty string = none)
    pub user: String,
    /// The definition's epoch
    pub epoch: u64,
    /// `<recipe>-<secret>`, as `hd-secret list` prints it
    pub fingerprint: String,
}

/// The decrypted export document: everything a fellow member needs to rebuild
/// the group and its registry from nothing but their own seed and their pins.
///
/// Everything in it is already known to every member. **Out:** no seed, no `K`,
/// no child scalar, no rendered password.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportBody {
    /// [`EXPORT_VERSION`]
    pub version: u32,
    /// The agreed group name, bound into `group_ctx`, and the storage key. It
    /// is *inside* the payload, so `import` takes no group argument and cannot
    /// be mistyped into a different group.
    pub group_name: String,
    /// 2 or 3, cross-checked against `tokens.len()`
    pub parties: u8,
    /// Every member's setup token, the exporter's included, in no meaningful
    /// order: the importer matches them to members by signature.
    pub tokens: Vec<TokenRecord>,
    /// The whole registry document: `entries` (live **and** tombstoned) plus
    /// the `archive` of superseded recipes, so `copy --recover <epoch>` works on
    /// the far side of an import.
    pub registry: Registry,
    /// One fingerprint per registry row, in [`fingerprinted_rows`] order
    pub fingerprints: Vec<FprRecord>,
}

/// The plaintext JSON envelope, `peek_version`-able before anything decrypts.
///
/// Deliberately **not** base58check. Every "pasteable" token in this codebase
/// is base58, but `bs58` encoding is O(n²) big-number base conversion, and a
/// registry of 500 definitions is tens of kilobytes. Hex is O(n), and a *file*
/// is the right precedent here (`backup.rs`) not a *paste*.
///
/// There is no cleartext routing field to bind, and no KDF record: the wrap key
/// is derived from identity keys, not a passphrase.
#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    cipher_algorithm: String,
    /// Hex of `nonce(12) ‖ AES-256-GCM(wrap_key, aad, plaintext)`
    sealed: String,
}

/// The associated data the envelope authenticates: a domain tag and a
/// numerically-bound version.
fn aad() -> Vec<u8> {
    let mut a = EXPORT_AAD_TAG.to_vec();
    a.extend_from_slice(&EXPORT_ENVELOPE_VERSION.to_le_bytes());
    a
}

/// The exact bytes the exporter's BLS signature covers:
/// `EXPORT_MSG_TAG ‖ u32_le(EXPORT_VERSION) ‖ inner`.
///
/// `inner` is the serialized [`ExportBody`] **verbatim**, so there is no
/// canonical-JSON problem to solve: [`open`] splits the fixed 96-byte signature
/// off the opened plaintext and hashes the remainder as it lies. Nothing
/// re-serializes for signing, and [`Params::canonical_bytes`][cb] is untouched.
///
/// The version is signed, not merely framed (i.e. the same discipline
/// [`ShareToken::signed_message`][sm] keeps) so a body whose `version` field
/// was rewritten cannot verify under a build that would read it differently.
///
/// [cb]: crate::registry::Params::canonical_bytes
/// [sm]: crate::protocol::ShareToken
fn signed_message(inner: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(EXPORT_MSG_TAG.len() + 4 + inner.len());
    m.extend_from_slice(EXPORT_MSG_TAG);
    m.extend_from_slice(&EXPORT_VERSION.to_le_bytes());
    m.extend_from_slice(inner);
    m
}

/// The registry rows an export fingerprints, in the order it fingerprints them:
/// every entry (live **and** tombstoned), then every archived recipe.
///
/// A tombstone is not a deletion ([`Registry::remove`] bumps the epoch, leaves
/// `params` intact, and keeps the row) so covering `entries` covers both
/// readings of "removed", and covering `archive` covers the recipes `rotate` and
/// `remove` superseded.
///
/// The order is the document's own, and the importer recomputes over the same
/// iteration, so the two lists align positionally. Nothing is keyed: a live entry
/// and an archived recipe can share an `(id, user, epoch)` after a
/// `create --recover`, and a map would silently collapse them.
pub fn fingerprinted_rows(reg: &Registry) -> impl Iterator<Item = &Definition> {
    reg.entries.iter().chain(reg.archive.iter())
}

/// Format an `(id, user)` selector for error messages.
///
/// Escaped, because these strings are member-authored and some of the errors
/// naming them ([`check_structure`]'s, notably) print before any content gate
/// has run.  A control character must not ride an error message to the
/// terminal.
fn key(id: &str, user: &str) -> String {
    let id = crate::format::escape_control(id);
    if user.is_empty() {
        format!("'{id}'")
    } else {
        format!("'{id}' (user '{}')", crate::format::escape_control(user))
    }
}

/// One row's `hd_fingerprint` under the group master `K`.
///
/// A fingerprint is two one-way digests of the **child scalar**, never of the
/// rendered password (see [`crypto::hd_fingerprint`]). `hd-secret list` already
/// prints these, so the payload discloses nothing new.
fn fingerprint_of(master: &Scalar, def: &Definition) -> String {
    let child = hd_child(master, &canonical_hd_context(&def.id, &def.user, def.epoch));
    hd_fingerprint(&def.params.canonical_bytes(), &child)
}

/// Build the payload for a group: its name, every member's setup token, the whole
/// registry document, and one fingerprint per row.
///
/// `tokens` is the full set (the exporter's own included), so a single export
/// from **any one member** is enough for any other member to reconstruct `K`.
/// Their order carries no meaning: [`decode_tokens`] hands the caller a list and
/// the caller matches each to a member by signature.
pub fn build_body(
    group_name: &str,
    parties: Parties,
    tokens: &[SetupToken],
    registry: &Registry,
    master: &Scalar,
) -> ExportBody {
    let token_records = tokens
        .iter()
        .map(|t| TokenRecord {
            child_g1: hex::encode(t.child_g1.to_compressed()),
            child_g2: t.child_g2.map(|g2| hex::encode(g2.to_compressed())),
            signature: hex::encode(t.signature),
        })
        .collect();
    let fingerprints = fingerprinted_rows(registry)
        .map(|d| FprRecord {
            id: d.id.clone(),
            user: d.user.clone(),
            epoch: d.epoch,
            fingerprint: fingerprint_of(master, d),
        })
        .collect();
    ExportBody {
        version: EXPORT_VERSION,
        group_name: group_name.to_string(),
        parties: parties.as_u8(),
        tokens: token_records,
        registry: registry.clone(),
        fingerprints,
    }
}

/// Sign `body` with the exporter's `s_sig`, then seal it under `wrap_key`,
/// returning the envelope JSON ready to write to a file.
///
/// `plaintext = signature(96) ‖ inner`, where `inner` is the serialized body.
/// **Sign-then-encrypt**, matching [`ShareToken::encode`][enc]'s stated
/// discipline: the signature is confined to the ciphertext, so an eavesdropper
/// holding the file cannot even attribute it.
///
/// [enc]: crate::protocol::ShareToken::encode
pub fn seal(seed: &[u8; SEED_BYTES], wrap_key: &[u8; 32], body: &ExportBody) -> Result<Vec<u8>> {
    let inner = Zeroizing::new(serde_json::to_vec(body)?);
    let signature = crypto::bls_sign(&derive_sig_scalar(seed), &signed_message(&inner));

    let mut plaintext = Zeroizing::new(Vec::with_capacity(BLS_SIG_BYTES + inner.len()));
    plaintext.extend_from_slice(&signature);
    plaintext.extend_from_slice(&inner);

    let sealed = crypto::seal_token(wrap_key, &aad(), &plaintext);
    let envelope = Envelope {
        version: EXPORT_ENVELOPE_VERSION,
        cipher_algorithm: CIPHER_ALGORITHM.into(),
        sealed: hex::encode(sealed),
    };
    Ok(serde_json::to_vec_pretty(&envelope)?)
}

/// An opened, structurally-validated export: the parsed body **and** the exact
/// `inner` bytes the exporter signed.
///
/// Both are needed. The signature covers `inner` verbatim, so
/// [`verify_signer`] hashes the bytes as they lie rather than re-serializing a
/// parsed body, which would make the payload's integrity hostage to serde's
/// field ordering.
pub struct Opened {
    signature: [u8; BLS_SIG_BYTES],
    inner: Zeroizing<Vec<u8>>,
    body: ExportBody,
}

impl Opened {
    /// The parsed body
    pub fn body(&self) -> &ExportBody {
        &self.body
    }
}

/// Redacted on purpose. The one quasi-sensitive field in a payload is
/// `params.suffix`.  This is a free-form string, often a literal fragment of the user's
/// password and it lives in both `inner` and `body`. A derived `Debug` would
/// put it in every `unwrap()` panic and every `{:?}` in a test.
impl fmt::Debug for Opened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opened")
            .field("group_name", &self.body.group_name)
            .field("parties", &self.body.parties)
            .field("entries", &self.body.registry.entries.len())
            .field("archived", &self.body.registry.archive.len())
            .finish_non_exhaustive()
    }
}

/// Fixed-width hex field
fn read_hex<const N: usize>(s: &str, field: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|e| ExportError::BadFormat(format!("{field}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| ExportError::BadFormat(format!("{field}: expected {N} bytes")))
}

/// Open an export envelope under `wrap_key`: authenticate the AEAD, gate both
/// versions, and validate the body's structure.
///
/// This does **no** signature check. The caller supplies the members, and the
/// match identifies the exporter ([`verify_signer`]).
///
/// Order matters. `peek_version` runs before `serde_json::from_slice`, never
/// after, on both the envelope and the body: it demands only a `version` field
/// and ignores everything else, so it parses any record shape: past, present, or
/// future! A version check that ran after the full parse could only reject a
/// record this build was already able to read, and the moment a bump adds a
/// required field the old build dies inside serde instead.
pub fn open(bytes: &[u8], wrap_key: &[u8; 32]) -> Result<Opened> {
    let envelope_version = peek_version(bytes)
        .map_err(|e| ExportError::BadFormat(format!("not a sesh export file: {e}")))?;
    if envelope_version != EXPORT_ENVELOPE_VERSION {
        return Err(ExportError::UnsupportedVersion {
            what: "envelope",
            found: envelope_version,
        });
    }
    let envelope: Envelope = serde_json::from_slice(bytes)?;
    if envelope.cipher_algorithm != CIPHER_ALGORITHM {
        return Err(ExportError::BadFormat(format!(
            "unsupported cipher algorithm '{}'",
            envelope.cipher_algorithm
        )));
    }
    let sealed = hex::decode(&envelope.sealed)
        .map_err(|e| ExportError::BadFormat(format!("sealed: {e}")))?;

    // Layer 1. Wrong wrap key and one flipped bit are indistinguishable here, by
    // design.  This is integrity, not attribution: every member holds the key.
    let plaintext = Zeroizing::new(
        crypto::open_token(wrap_key, &aad(), &sealed).map_err(|_| ExportError::Decrypt)?,
    );
    if plaintext.len() < BLS_SIG_BYTES {
        return Err(ExportError::BadFormat(
            "plaintext is shorter than a signature".into(),
        ));
    }
    let (sig, inner) = plaintext.split_at(BLS_SIG_BYTES);
    let signature: [u8; BLS_SIG_BYTES] = sig.try_into().expect("slice len checked");
    let inner = Zeroizing::new(inner.to_vec());

    let body_version =
        peek_version(&inner).map_err(|e| ExportError::BadFormat(format!("export body: {e}")))?;
    if body_version != EXPORT_VERSION {
        return Err(ExportError::UnsupportedVersion {
            what: "body",
            found: body_version,
        });
    }
    let body: ExportBody = serde_json::from_slice(&inner)?;
    check_structure(&body)?;

    Ok(Opened {
        signature,
        inner,
        body,
    })
}

/// Structural invariants of a body, all checked before anything is derived.
///
/// The registry's own invariants are re-established here rather than assumed.
/// `Registry` documents "exactly one entry per `(id, user)`" and an archive
/// "deduplicated by `(id, user, epoch)`", but serde enforces neither, and a
/// duplicate would send `classify` and `adopt` to different rows on the import
/// side. Member-signed is not member-*trusted*.
fn check_structure(body: &ExportBody) -> Result<()> {
    let parties = Parties::from_u8(body.parties)?;
    if body.tokens.len() != parties.as_u8() as usize {
        return Err(ExportError::BadFormat(format!(
            "a {}-party group needs {} setup tokens, found {}",
            body.parties,
            body.parties,
            body.tokens.len()
        )));
    }
    if body.registry.version != REGISTRY_VERSION {
        return Err(ExportError::UnsupportedVersion {
            what: "registry schema",
            found: body.registry.version,
        });
    }

    let mut seen: Vec<(&str, &str)> = Vec::with_capacity(body.registry.entries.len());
    for d in &body.registry.entries {
        if seen.contains(&(&d.id, &d.user)) {
            return Err(ExportError::BadFormat(format!(
                "registry holds two entries for {}",
                key(&d.id, &d.user)
            )));
        }
        seen.push((&d.id, &d.user));
    }
    let mut seen: Vec<(&str, &str, u64)> = Vec::with_capacity(body.registry.archive.len());
    for d in &body.registry.archive {
        if seen.contains(&(&d.id, &d.user, d.epoch)) {
            return Err(ExportError::BadFormat(format!(
                "archive holds two recipes for {} at epoch {}",
                key(&d.id, &d.user),
                d.epoch
            )));
        }
        seen.push((&d.id, &d.user, d.epoch));
    }

    // The fingerprint list is positional, so its alignment is structure
    let rows: Vec<&Definition> = fingerprinted_rows(&body.registry).collect();
    if rows.len() != body.fingerprints.len() {
        return Err(ExportError::BadFormat(format!(
            "{} registry rows but {} fingerprints",
            rows.len(),
            body.fingerprints.len()
        )));
    }
    for (row, fpr) in rows.iter().zip(body.fingerprints.iter()) {
        if row.id != fpr.id || row.user != fpr.user || row.epoch != fpr.epoch {
            return Err(ExportError::BadFormat(format!(
                "fingerprint {} at epoch {} is not aligned with registry row {} at epoch {}",
                key(&fpr.id, &fpr.user),
                fpr.epoch,
                key(&row.id, &row.user),
                row.epoch
            )));
        }
    }
    Ok(())
}

/// **Layer 2.** Identify the exporter: the index of the member whose pinned
/// signing key verifies the payload signature.
///
/// Mirrors [`ShareToken::verify`][sv]. A body signed by nobody in `members` is
/// [`ExportError::BadSignature`]; signed by yourself is legal (you are restoring
/// your own file) and lands at index 0 when `members[0]` is you.
///
/// An outsider cannot forge one and they cannot seal one. Another *member* could,
/// but members already author share tokens: no new surface.
///
/// [sv]: crate::protocol::ShareToken::verify
pub fn verify_signer(opened: &Opened, members: &[PublicIdentity]) -> Result<usize> {
    let msg = signed_message(&opened.inner);
    members
        .iter()
        .position(|m| bls_verify(&m.sig_g1, &msg, &opened.signature))
        .ok_or(ExportError::BadSignature)
}

/// Decode and subgroup-validate every setup token in the body.
///
/// `child_g2` must be present iff the group is 3-party, which is the same rule
/// `load_shared_secret` keeps on disk, restated here because a payload is not a
/// keystore file. The tokens' `group_name` is filled from the body; it is
/// advisory, exactly as it is in a decoded [`SetupToken`], and the caller
/// authenticates the name by recomputing `group_ctx` and verifying every peer's
/// signature against it.
pub fn decode_tokens(body: &ExportBody) -> Result<Vec<SetupToken>> {
    let parties = Parties::from_u8(body.parties)?;
    let mut out = Vec::with_capacity(body.tokens.len());
    for rec in &body.tokens {
        let g1 = read_hex::<G1_COMPRESSED>(&rec.child_g1, "child_g1")?;
        let child_g1 = crypto::read_g1(&g1)?;
        let child_g2 = match (parties, &rec.child_g2) {
            (Parties::Two, None) => None,
            (Parties::Three, Some(h)) => {
                let g2 = read_hex::<G2_COMPRESSED>(h, "child_g2")?;
                Some(crypto::read_g2(&g2)?)
            }
            _ => {
                return Err(ExportError::BadFormat(
                    "a setup token's child_g2 presence does not match the party count".into(),
                ))
            }
        };
        let signature = read_hex::<BLS_SIG_BYTES>(&rec.signature, "signature")?;
        out.push(SetupToken {
            parties,
            group_name: body.group_name.clone(),
            child_g1,
            child_g2,
            signature,
        });
    }
    Ok(out)
}

/// **Layer 4, the tripwire.** Recompute every row's `hd_fingerprint` from the
/// locally derived `master` and compare it against the file's.
///
/// This cannot fail unless there is a bug: layers 1–3 already establish that the
/// params are the exporter's and that `master` is the group's. It ships anyway,
/// because the bugs it catches (i.e. a params-encoding drift, an archive row filed
/// under the wrong epoch) are otherwise silent, and the cost of a silent one is
/// a password that no longer opens the account it was for.
///
/// A mismatch is a hard error, raised before anything is written.
pub fn check_fingerprints(body: &ExportBody, master: &Scalar) -> Result<()> {
    // `check_structure` already pinned the alignment, so zip is total
    for (row, fpr) in fingerprinted_rows(&body.registry).zip(body.fingerprints.iter()) {
        if fingerprint_of(master, row) != fpr.fingerprint {
            return Err(ExportError::FingerprintMismatch {
                key: key(&row.id, &row.user),
                epoch: row.epoch,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::public_identity_from_seed;
    use crate::protocol::{self, Purpose};
    use crate::registry::Params;

    fn seed(b: u8) -> [u8; SEED_BYTES] {
        [b; SEED_BYTES]
    }

    fn pubid(b: u8) -> PublicIdentity {
        public_identity_from_seed(&seed(b))
    }

    // The setup wrap key member `b` derives for `members`
    fn wrap(b: u8, members: &[PublicIdentity]) -> [u8; 32] {
        let me = public_identity_from_seed(&seed(b));
        let others: Vec<PublicIdentity> = members.iter().filter(|m| **m != me).cloned().collect();
        protocol::setup_wrap_key(&seed(b), &others, members).unwrap()
    }

    fn params(mode: &str) -> Params {
        Params {
            mode: mode.into(),
            length: None,
            symbols: None,
            suffix: None,
        }
    }

    // A registry with a live entry, a tombstone, and an archived recipe
    fn registry() -> Registry {
        let mut reg = Registry::empty();
        reg.create("a.com", "", params("b58")).unwrap();
        reg.create("b.com", "bob", params("hex")).unwrap();
        reg.rotate("a.com", "", Some(params("b10")), None).unwrap(); // archives epoch 1
        reg.remove("b.com", "bob").unwrap(); // tombstones, archives epoch 1
        reg
    }

    // A 2-party group `{1, 2}` named "grp": members, both tokens, and `K`.
    fn group_2p() -> (Vec<PublicIdentity>, Vec<SetupToken>, Scalar) {
        let members = vec![pubid(1), pubid(2)];
        let t1 = SetupToken::create(&seed(1), Purpose::Master, "grp", &members).unwrap();
        let t2 = SetupToken::create(&seed(2), Purpose::Master, "grp", &members).unwrap();
        let ctx = protocol::group_ctx(Purpose::Master, "grp", &members).unwrap();
        let k = protocol::derive_group_key(
            &SetupToken::my_child_scalar(&seed(1), &ctx),
            std::slice::from_ref(&t2),
        )
        .unwrap();
        (members, vec![t1, t2], k)
    }

    fn seal_2p() -> (Vec<u8>, Vec<PublicIdentity>, Scalar) {
        let (members, tokens, k) = group_2p();
        let body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        let bytes = seal(&seed(1), &wrap(1, &members), &body).unwrap();
        (bytes, members, k)
    }

    #[test]
    fn round_trip_yields_the_same_body() {
        let (members, tokens, k) = group_2p();
        let reg = registry();
        let body = build_body("grp", Parties::Two, &tokens, &reg, &k);
        let bytes = seal(&seed(1), &wrap(1, &members), &body).unwrap();

        // Every member's wrap key opens it-— that's the whole point!
        for who in [1u8, 2] {
            let opened = open(&bytes, &wrap(who, &members)).unwrap();
            let got = opened.body();
            assert_eq!(got.group_name, "grp");
            assert_eq!(got.parties, 2);
            assert_eq!(got.tokens.len(), 2);
            assert_eq!(got.registry.entries.len(), reg.entries.len());
            assert_eq!(got.registry.archive.len(), reg.archive.len());
            assert_eq!(got.fingerprints, body.fingerprints);
        }
        // The tokens decode back to exactly what went in
        let opened = open(&bytes, &wrap(2, &members)).unwrap();
        assert_eq!(decode_tokens(opened.body()).unwrap(), tokens);
    }

    // The payload fingerprints *every* row: live, tombstoned, and archived.
    // Tombstones come for free: `remove` keeps the row, so exporting the whole
    // document covers both readings of "removed".
    #[test]
    fn every_registry_row_is_fingerprinted_live_tombstoned_and_archived() {
        let reg = registry();
        let rows: Vec<&Definition> = fingerprinted_rows(&reg).collect();
        assert_eq!(rows.len(), reg.entries.len() + reg.archive.len());
        assert!(
            rows.iter().any(|d| d.tombstone),
            "a tombstone must be covered"
        );
        assert!(reg.archive.len() >= 2, "rotate and remove both archived");

        let (_, tokens, k) = group_2p();
        let body = build_body("grp", Parties::Two, &tokens, &reg, &k);
        assert_eq!(body.fingerprints.len(), rows.len());
        check_fingerprints(&body, &k).unwrap();
    }

    // Membership-exact: the wrong `--party` set is an AEAD failure, not a subtly
    // wrong result.
    #[test]
    fn a_file_sealed_for_ab_does_not_open_for_ac() {
        let (bytes, _, _) = seal_2p();
        let wrong = vec![pubid(1), pubid(3)];
        assert!(matches!(
            open(&bytes, &wrap(1, &wrong)),
            Err(ExportError::Decrypt)
        ));
    }

    // A non-member cannot open the file even holding every member's *public*
    // identity: the wrap key is the static DH/Joux value over the members'
    // long-term secrets, and an outsider holds none of them. Safe on an
    // unencrypted channel: email it, Slack it, slap it on a USB stick.
    #[test]
    fn a_non_member_cannot_open_it() {
        let (bytes, members, _) = seal_2p();
        // Seed 3 knows the whole membership and tries its own key against each
        // member in turn. Neither is the group's key.
        for peer in &members {
            let k = protocol::setup_wrap_key(&seed(3), std::slice::from_ref(peer), &members)
                .expect("one other member is the 2-party shape");
            assert!(matches!(open(&bytes, &k), Err(ExportError::Decrypt)));
        }
    }

    // A flipped ciphertext byte fails the AEAD, never serde
    #[test]
    fn a_flipped_byte_fails_the_aead_not_the_parser() {
        let (bytes, members, _) = seal_2p();
        let mut env: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let sealed = env["sealed"].as_str().unwrap().to_string();
        let mut raw = hex::decode(&sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        env["sealed"] = serde_json::Value::String(hex::encode(raw));
        let tampered = serde_json::to_vec(&env).unwrap();
        assert!(matches!(
            open(&tampered, &wrap(1, &members)),
            Err(ExportError::Decrypt)
        ));
    }

    // `peek_version` gates the envelope before `Envelope` parses, so a future
    // framing says "unsupported version" rather than dying inside serde. The
    // same discipline `backup.rs` pins for its manifest.
    #[test]
    fn a_future_envelope_version_is_rejected_before_the_envelope_parses() {
        let bytes = br#"{"version":99,"future_field":true}"#;
        match open(bytes, &[0u8; 32]) {
            Err(ExportError::UnsupportedVersion {
                what: "envelope",
                found: 99,
            }) => {}
            other => panic!("expected an unsupported envelope version, got {other:?}"),
        }
    }

    // ...and the body's own version gates before `ExportBody` parses. Sealing a
    // body this build cannot even deserialize is the only way to prove it.
    #[test]
    fn a_future_body_version_is_rejected_before_the_body_parses() {
        let members = vec![pubid(1), pubid(2)];
        let wk = wrap(1, &members);
        let inner = br#"{"version":99,"an_unknown_shape":[1,2,3]}"#;
        let mut plaintext = vec![0u8; BLS_SIG_BYTES]; // a signature we never reach
        plaintext.extend_from_slice(inner);
        let envelope = Envelope {
            version: EXPORT_ENVELOPE_VERSION,
            cipher_algorithm: CIPHER_ALGORITHM.into(),
            sealed: hex::encode(crypto::seal_token(&wk, &aad(), &plaintext)),
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        match open(&bytes, &wk) {
            Err(ExportError::UnsupportedVersion {
                what: "body",
                found: 99,
            }) => {}
            other => panic!("expected an unsupported body version, got {other:?}"),
        }
    }

    #[test]
    fn a_foreign_cipher_algorithm_is_rejected() {
        let (bytes, members, _) = seal_2p();
        let mut env: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        env["cipher_algorithm"] = serde_json::Value::String("rot13".into());
        let bytes = serde_json::to_vec(&env).unwrap();
        assert!(matches!(
            open(&bytes, &wrap(1, &members)),
            Err(ExportError::BadFormat(_))
        ));
    }

    #[test]
    fn verify_signer_returns_the_exporters_index() {
        let (members, tokens, k) = group_2p();
        // Member 2 exports; member 1 opens and attributes it
        let body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        let bytes = seal(&seed(2), &wrap(2, &members), &body).unwrap();
        let opened = open(&bytes, &wrap(1, &members)).unwrap();
        assert_eq!(verify_signer(&opened, &members).unwrap(), 1);

        // And from member 2's own view, self-signature lands at their own index
        let mine = vec![pubid(2), pubid(1)];
        let opened = open(&bytes, &wrap(2, &members)).unwrap();
        assert_eq!(verify_signer(&opened, &mine).unwrap(), 0);
    }

    // A member of the group seals the file (they must, to seal it at all) but
    // signs with a key nobody pinned. Attribution fails even though the AEAD
    // opened: layer 1 and layer 2 are different claims.
    #[test]
    fn a_body_signed_by_a_non_member_is_a_bad_signature() {
        let (members, tokens, k) = group_2p();
        let body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        // Seed 9 is not a member; it seals under member 1's wrap key
        let bytes = seal(&seed(9), &wrap(1, &members), &body).unwrap();
        let opened = open(&bytes, &wrap(2, &members)).unwrap();
        assert!(matches!(
            verify_signer(&opened, &members),
            Err(ExportError::BadSignature)
        ));
    }

    // The signature covers `inner` verbatim, so rewriting *any* field of the
    // body (group name included) invalidates it. This is what lets `open`
    // hash the remainder of the plaintext as it lies, with no canonical-JSON
    // problem to solve.
    #[test]
    fn a_tampered_group_name_is_a_bad_signature() {
        let (members, tokens, k) = group_2p();
        let mut body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        let inner = serde_json::to_vec(&body).unwrap();
        let signature = crypto::bls_sign(&derive_sig_scalar(&seed(1)), &signed_message(&inner));

        // Re-seal the *signed* bytes of "grp" beside a body that says "evil"
        body.group_name = "mr_evil".into();
        let mut plaintext = signature.to_vec();
        plaintext.extend_from_slice(&serde_json::to_vec(&body).unwrap());
        let envelope = Envelope {
            version: EXPORT_ENVELOPE_VERSION,
            cipher_algorithm: CIPHER_ALGORITHM.into(),
            sealed: hex::encode(crypto::seal_token(&wrap(1, &members), &aad(), &plaintext)),
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let opened = open(&bytes, &wrap(2, &members)).unwrap();
        assert_eq!(opened.body().group_name, "mr_evil"); // the AEAD does not care
        assert!(matches!(
            verify_signer(&opened, &members),
            Err(ExportError::BadSignature)
        ));
    }

    // Layer 4's tripwire: one edited digest, one hard error, naming the row
    #[test]
    fn a_tampered_fingerprint_row_is_a_hard_error() {
        let (_, tokens, k) = group_2p();
        let mut body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        check_fingerprints(&body, &k).unwrap();
        body.fingerprints[0].fingerprint = "aaaa-bbbbbbbbbbb".into();
        match check_fingerprints(&body, &k) {
            Err(ExportError::FingerprintMismatch { epoch, .. }) => {
                assert_eq!(epoch, body.fingerprints[0].epoch);
            }
            other => panic!("expected a fingerprint mismatch, got {other:?}"),
        }
    }

    // A different `K` moves every fingerprint, so the tripwire also fires on a
    // file whose tokens agree structurally but derive another group's master.
    #[test]
    fn fingerprints_are_bound_to_the_group_master() {
        let (_, tokens, k) = group_2p();
        let body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        let other = crypto::hash_to_scalar(b"test", b"not-K");
        assert!(matches!(
            check_fingerprints(&body, &other),
            Err(ExportError::FingerprintMismatch { .. })
        ));
    }

    // `Registry`'s "exactly one entry per (id, user)" is documented, not
    // enforced by serde. Member-signed is not member-trusted.
    #[test]
    fn a_duplicate_registry_entry_is_rejected() {
        let (members, tokens, k) = group_2p();
        let mut reg = registry();
        let dup = reg.entries[0].clone();
        reg.entries.push(dup);
        let mut body = build_body("grp", Parties::Two, &tokens, &reg, &k);
        // Rebuild fingerprints so the failure is the duplicate, not the alignment
        body.fingerprints = fingerprinted_rows(&reg)
            .map(|d| FprRecord {
                id: d.id.clone(),
                user: d.user.clone(),
                epoch: d.epoch,
                fingerprint: fingerprint_of(&k, d),
            })
            .collect();
        let bytes = seal(&seed(1), &wrap(1, &members), &body).unwrap();
        match open(&bytes, &wrap(2, &members)) {
            Err(ExportError::BadFormat(m)) => assert!(m.contains("two entries"), "{m}"),
            other => panic!("expected a duplicate-entry rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_archive_recipe_is_rejected() {
        let (members, tokens, k) = group_2p();
        let mut reg = registry();
        let dup = reg.archive[0].clone();
        reg.archive.push(dup);
        let mut body = build_body("grp", Parties::Two, &tokens, &reg, &k);
        body.fingerprints = fingerprinted_rows(&reg)
            .map(|d| FprRecord {
                id: d.id.clone(),
                user: d.user.clone(),
                epoch: d.epoch,
                fingerprint: fingerprint_of(&k, d),
            })
            .collect();
        let bytes = seal(&seed(1), &wrap(1, &members), &body).unwrap();
        match open(&bytes, &wrap(2, &members)) {
            Err(ExportError::BadFormat(m)) => assert!(m.contains("two recipes"), "{m}"),
            other => panic!("expected a duplicate-archive rejection, got {other:?}"),
        }
    }

    // A misaligned fingerprint list is structure, caught by `open`, not a
    // mismatch caught by `check_fingerprints`.
    #[test]
    fn a_misaligned_fingerprint_list_is_rejected_as_structure() {
        let (members, tokens, k) = group_2p();
        let mut body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        body.fingerprints.pop();
        let bytes = seal(&seed(1), &wrap(1, &members), &body).unwrap();
        match open(&bytes, &wrap(2, &members)) {
            Err(ExportError::BadFormat(m)) => assert!(m.contains("fingerprints"), "{m}"),
            other => panic!("expected an alignment rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_token_count_that_contradicts_the_party_count_is_rejected() {
        let (members, tokens, k) = group_2p();
        let mut body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        body.tokens.pop();
        let bytes = seal(&seed(1), &wrap(1, &members), &body).unwrap();
        match open(&bytes, &wrap(2, &members)) {
            Err(ExportError::BadFormat(m)) => assert!(m.contains("setup tokens"), "{m}"),
            other => panic!("expected a party/token mismatch, got {other:?}"),
        }
    }

    // `child_g2` is present iff 3-party.  This is the same rule `load_shared_secret`
    // keeps on disk, restated because a payload is not a keystore file.
    #[test]
    fn child_g2_presence_must_match_the_party_count() {
        let (_, tokens, k) = group_2p();
        let mut body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        assert!(decode_tokens(&body).is_ok());
        body.tokens[0].child_g2 = Some(hex::encode([0u8; G2_COMPRESSED]));
        assert!(matches!(
            decode_tokens(&body),
            Err(ExportError::BadFormat(_))
        ));

        // ...and a 3-party token missing its G2 half is rejected too
        let members3 = vec![pubid(1), pubid(2), pubid(3)];
        let tokens3: Vec<SetupToken> = [1u8, 2, 3]
            .iter()
            .map(|b| SetupToken::create(&seed(*b), Purpose::Master, "g3", &members3).unwrap())
            .collect();
        let mut body3 = build_body("g3", Parties::Three, &tokens3, &Registry::empty(), &k);
        assert!(decode_tokens(&body3).is_ok());
        body3.tokens[2].child_g2 = None;
        assert!(matches!(
            decode_tokens(&body3),
            Err(ExportError::BadFormat(_))
        ));
    }

    // A child pubkey outside the prime-order subgroup never reaches the
    // derivation: `decode_tokens` routes every point through `read_g1`/`read_g2`.
    #[test]
    fn a_token_point_is_subgroup_validated_on_the_way_in() {
        let (_, tokens, k) = group_2p();
        let mut body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        body.tokens[0].child_g1 = hex::encode([0xffu8; G1_COMPRESSED]);
        assert!(matches!(decode_tokens(&body), Err(ExportError::Crypto(_))));
        // A short field is a format error, not a curve error
        body.tokens[0].child_g1 = hex::encode([0u8; 4]);
        assert!(matches!(
            decode_tokens(&body),
            Err(ExportError::BadFormat(_))
        ));
    }

    // The envelope deliberately carries no cleartext group identifier. A
    // linkable, long-lived tag on a file that may sit in a mailbox for years
    // buys nothing: `import` gets its routing from `--party`.
    #[test]
    fn the_envelope_leaks_no_group_name() {
        let (bytes, _, _) = seal_2p();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("grp"));
        assert!(!text.contains("a.com"));
        let env: serde_json::Value = serde_json::from_str(&text).unwrap();
        let keys: Vec<&String> = env.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["cipher_algorithm", "sealed", "version"]);
    }

    // Two seals of one body differ (a fresh nonce per call) and both open.
    // Nobody should expect byte equality across runs.
    #[test]
    fn sealing_is_randomized_and_both_ciphertexts_open() {
        let (members, tokens, k) = group_2p();
        let body = build_body("grp", Parties::Two, &tokens, &registry(), &k);
        let a = seal(&seed(1), &wrap(1, &members), &body).unwrap();
        let b = seal(&seed(1), &wrap(1, &members), &body).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            open(&a, &wrap(2, &members)).unwrap().body().group_name,
            open(&b, &wrap(2, &members)).unwrap().body().group_name
        );
    }
}
