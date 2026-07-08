//! Protocol glue: publishing and verifying signed identities, and
//! reconstructing the shared secret from a local seed plus peers' public
//! identities.
//!
//! The trust model is two-tier: a one-time out-of-band **pin** of a peer's
//! whole-identity fingerprint (Tier 1), and a **BLS signature** over every
//! published value verified against that pin (Tier 2). This module enforces
//! both when admitting a peer; the wizard (elsewhere) is responsible for the
//! human-in-the-loop first-sight pinning.

use std::fmt;

use blstrs::{G1Affine, G2Affine, Scalar};
use sha3::{Digest, Sha3_256};

use crate::codec::{self, CodecError};
use crate::crypto::{
    self, bls_sign, bls_verify, compute_pubkey_g1, compute_pubkey_g2, derive_dh_scalar,
    derive_sig_scalar, group_child, group_secret_3, read_g1, read_g2, shared_secret_2, CryptoError,
    DhPublic, PublicIdentity, BLS_SIG_BYTES, G1_COMPRESSED, G2_COMPRESSED, SEED_BYTES,
};
use crate::registry::Params;

/// The number of parties to a shared secret: 2 (ECDH) or 3 (Joux). These are
/// the only supported values so the pairing is bilinear, so 3 is the ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parties {
    /// 2-party ECDH in `G1`
    Two,
    /// 3-party one-round Joux agreement
    Three,
}

/// What a shared secret is *for, bound into the group context as a
/// domain-separation tag. Only one purpose survives: every shared secret is a
/// stored group's master `K`. The enum is kept as a single-variant marker so
/// the `group_ctx` domain byte stays explicit and the wire format is pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A stored group's master `K`: keys the group's `hd-secret` layer and
    /// never leaves the keystore. Used by `shared-secret create`.
    Master,
}

impl Purpose {
    /// The byte mixed into `group_ctx`
    fn as_u8(self) -> u8 {
        match self {
            Purpose::Master => 1,
        }
    }
}

impl Parties {
    /// Parse from the CLI integer (2 or 3)
    pub fn from_u8(n: u8) -> Result<Self, ProtocolError> {
        match n {
            2 => Ok(Parties::Two),
            3 => Ok(Parties::Three),
            _ => Err(ProtocolError::WrongPartyCount(n as usize)),
        }
    }

    /// The integer form (2 or 3)
    pub fn as_u8(self) -> u8 {
        match self {
            Parties::Two => 2,
            Parties::Three => 3,
        }
    }

    /// How many *peers* (other parties) this configuration requires
    pub fn peer_count(self) -> usize {
        self.as_u8() as usize - 1
    }
}

/// Errors from the protocol layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// A peer's BLS signature did not verify against its pinned signing key
    BadSignature,
    /// The wrong number of peers was supplied for the party count
    WrongPartyCount(usize),
    /// A supplied point failed subgroup / consistency validation
    Crypto(CryptoError),
    /// A decoded body was structurally malformed (wrong length / bad UTF-8)
    BadEncoding,
    /// A base58check blob failed to decode / frame-check
    Codec(CodecError),
    /// A setup token's advertised party count did not match the local group
    PartyMismatch {
        /// The party count the verifier expected (`#--party + 1`)
        expected: u8,
        /// The party count advertised in the token
        found: u8,
    },
    /// A published child pubkey equals one of the group's long-term identity
    /// keys, a member is masquerading its static key as a per-group
    /// contribution, forfeiting the per-group-child invariant.
    ChildKeyReuse,
    /// The agreed group name is too long to length-prefix (`> u16::MAX` bytes)
    NameTooLong,
    /// A share-token field is too long for its length prefix
    FieldTooLong(&'static str),
    /// A share token's `group_ctx` does not match this group's
    WrongGroup,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::BadSignature => write!(f, "Peer signature verification failed"),
            ProtocolError::WrongPartyCount(n) => {
                write!(f, "Unexpected number of peers: {n}")
            }
            ProtocolError::Crypto(e) => write!(f, "{e}"),
            ProtocolError::BadEncoding => {
                write!(f, "Malformed value (wrong length or invalid encoding)")
            }
            ProtocolError::Codec(e) => write!(f, "{e}"),
            ProtocolError::PartyMismatch { expected, found } => write!(
                f,
                "Setup token is for a {found}-party group but this group has {expected} parties"
            ),
            ProtocolError::ChildKeyReuse => write!(
                f,
                "A setup token reuses a long-term identity key as its per-group \
                 contribution - rejected"
            ),
            ProtocolError::NameTooLong => write!(f, "Group name is too long"),
            ProtocolError::FieldTooLong(what) => write!(f, "{what} is too long"),
            ProtocolError::WrongGroup => {
                write!(
                    f,
                    "share token is not for this group (group context mismatch)"
                )
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<CryptoError> for ProtocolError {
    fn from(e: CryptoError) -> Self {
        ProtocolError::Crypto(e)
    }
}

impl From<CodecError> for ProtocolError {
    fn from(e: CodecError) -> Self {
        ProtocolError::Codec(e)
    }
}

/// Serialized width of a long-term public identity (`dh_g1 ‖ dh_g2 ‖ sig_g1`)
pub const IDENTITY_BYTES: usize = 2 * G1_COMPRESSED + G2_COMPRESSED;

/// Encode a peer's long-term public identity as a base58check **contact token**
/// (`type=0x01`, `version=1`).  The value is shared once over a secure channel and
/// pinned locally. The owner's chosen name travels inside the token, so the
/// recipient can pin it without retyping a name (or override it locally):
///
/// `body = u16_le(byte_len(name)) ‖ name ‖ identity_bytes(192)`.
pub fn encode_contact_token(name: &str, public: &PublicIdentity) -> Result<String, ProtocolError> {
    if name.len() > u16::MAX as usize {
        return Err(ProtocolError::NameTooLong);
    }
    let name_bytes = name.as_bytes();
    let mut body = Vec::with_capacity(2 + name_bytes.len() + IDENTITY_BYTES);
    body.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    body.extend_from_slice(name_bytes);
    body.extend_from_slice(&public.to_bytes());
    Ok(codec::encode(
        codec::TYPE_CONTACT,
        codec::VERSION_CONTACT,
        &body,
    ))
}

/// Decode and fully validate a base58check contact token into the embedded
/// name and public identity.
///
/// The frame checksum catches a mistyped paste first; then every point is
/// subgroup-validated and the DH pair consistency-checked on the way in (via
/// [`PublicIdentity::from_bytes`]).
pub fn decode_contact_token(s: &str) -> Result<(String, PublicIdentity), ProtocolError> {
    let body = codec::decode(s, codec::TYPE_CONTACT, codec::VERSION_CONTACT)?;
    let mut cur = Cursor::new(&body);

    let name_len = cur.u16()? as usize;
    let name =
        String::from_utf8(cur.take(name_len)?.to_vec()).map_err(|_| ProtocolError::BadEncoding)?;

    let g1: [u8; G1_COMPRESSED] = cur
        .take(G1_COMPRESSED)?
        .try_into()
        .expect("slice len checked");
    let g2: [u8; G2_COMPRESSED] = cur
        .take(G2_COMPRESSED)?
        .try_into()
        .expect("slice len checked");
    let sig: [u8; G1_COMPRESSED] = cur
        .take(G1_COMPRESSED)?
        .try_into()
        .expect("slice len checked");
    if !cur.is_empty() {
        return Err(ProtocolError::BadEncoding); // trailing garbage
    }

    Ok((name, PublicIdentity::from_bytes(&g1, &g2, &sig)?))
}

// -----------------------------------------------------
// Group context, per-group child keys, and setup tokens
// -----------------------------------------------------

/// Fixed **derivation** domain tag mixed into every group context. Frozen,
/// suffix and all: renaming it would re-derive every group's `K`.
const GROUP_CTX_TAG: &[u8] = b"sesh-group-v1";
/// Fixed **derivation** domain tag prefixing the message signed over a per-group
/// child pubkey. Frozen for the same reason.
const GROUP_KEY_MSG_TAG: &[u8] = b"sesh-group-key-v1";
/// AEAD associated-data tag for a sealed setup token. Names a domain only; the
/// token version is bound numerically beside it, in [`setup_token_aad`].
const SETUP_AAD_TAG: &[u8] = b"sesh-setup-aad";

/// The associated data authenticated (but not hidden) by a sealed setup token:
/// the domain tag, the token version, and the clear party count.
///
/// The version byte lives in the clear at `payload[1]` of the frame, covered
/// only by a checksum any attacker can recompute. Binding it here is what makes
/// "old tokens are rejected outright" true of an adversary and not merely of
/// [`codec::decode`] on honest input: rewrite the byte and the AEAD no longer
/// opens.
fn setup_token_aad(parties: Parties) -> Vec<u8> {
    let mut aad = SETUP_AAD_TAG.to_vec();
    aad.push(codec::VERSION_TOKEN);
    aad.push(parties.as_u8());
    aad
}

/// The **agreed group context**: a 32-byte digest binding the agreed name and
/// the exact membership.
///
/// ```text
/// group_ctx = SHA3-256(
///     "sesh-group-v1"
///   ‖ u16_le(byte_len(name)) ‖ name
///   ‖ concat( bytelex_sort( identity_bytes(m) : m ∈ M ) )   # each 192 bytes
/// )
/// ```
///
/// `members` is the **full** member set (every party, including yourself). The
/// fixed-width 192-byte identity encodings are byte-lexicographically sorted, so
/// the result is **identical for every member regardless of listing order** so
/// no extra coordination round is needed. Because the name is bound in, two
/// groups with the same members but different names yield different contexts
/// (and hence different `K`).
///
/// Errors with [`ProtocolError::NameTooLong`] if the name exceeds `u16::MAX`
/// bytes (the length-prefix width), enforced here, at the hash itself, so no
/// caller can ever feed a silently truncated length prefix.
pub fn group_ctx(
    purpose: Purpose,
    name: &str,
    members: &[PublicIdentity],
) -> Result<[u8; 32], ProtocolError> {
    if name.len() > u16::MAX as usize {
        return Err(ProtocolError::NameTooLong);
    }
    let mut h = Sha3_256::new();
    h.update(GROUP_CTX_TAG);
    h.update([purpose.as_u8()]);
    h.update((name.len() as u16).to_le_bytes());
    h.update(name.as_bytes());
    h.update(sorted_member_ids(members));
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

/// The members' 192-byte identity encodings, byte-lexicographically sorted and
/// concatenated. This is the order-independent membership commitment used by both
/// [`group_ctx`] and the setup-token wrap key.
fn sorted_member_ids(members: &[PublicIdentity]) -> Vec<u8> {
    let mut ids: Vec<Vec<u8>> = members.iter().map(|m| m.to_bytes()).collect();
    ids.sort(); // ascending byte-lexicographic over fixed-width 192-byte encodings
    ids.concat()
}

/// The setup-token wrap key for a member, from its identity seed, the **other**
/// members' pinned identities, and the full member set (bound in for
/// membership-exactness). See [`crypto::setup_wrap_key`]-- the key is the
/// static multiparty DH/Joux value, identical for every member and unknowable
/// to an eavesdropper, so a single sealed token decrypts for all peers.
pub fn setup_wrap_key(
    seed: &[u8; SEED_BYTES],
    others: &[PublicIdentity],
    members: &[PublicIdentity],
) -> Result<[u8; 32], ProtocolError> {
    let my_s_dh = derive_dh_scalar(seed);
    let others_dh: Vec<DhPublic> = others.iter().map(|m| m.dh.clone()).collect();
    crypto::setup_wrap_key(&my_s_dh, &others_dh, &sorted_member_ids(members)).map_err(Into::into)
}

/// The short fingerprint of a group, over its public [`group_ctx`], identical
/// for every member (the context already binds the name and the sorted
/// membership) and computable without any password. A recognition aid only.
pub fn group_fingerprint(ctx: &[u8; 32]) -> String {
    crypto::fingerprint(crypto::DST_FPR_GROUP, ctx)
}

/// The message signed to bind a per-group child pubkey to its group context.
/// `msg = "sesh-group-key-v1" ‖ group_ctx ‖ child_g1 [‖ child_g2]`.
fn group_key_message(ctx: &[u8; 32], child_g1: &G1Affine, child_g2: Option<&G2Affine>) -> Vec<u8> {
    let mut m = Vec::with_capacity(GROUP_KEY_MSG_TAG.len() + 32 + G1_COMPRESSED + G2_COMPRESSED);
    m.extend_from_slice(GROUP_KEY_MSG_TAG);
    m.extend_from_slice(ctx);
    m.extend_from_slice(&child_g1.to_compressed());
    if let Some(g2) = child_g2 {
        m.extend_from_slice(&g2.to_compressed());
    }
    m
}

/// A party's **setup token**: its per-group child pubkey(s) plus a signature by
/// its long-term signing key binding that pubkey to the group context.
///
/// The `parties` and `group_name` fields are **advisory** (used to parse `g2`
/// presence and give a friendly early name-mismatch check); the authoritative
/// name and membership are always the verifier's own, never values read from
/// the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupToken {
    /// Party count this token is built for (2 or 3)
    pub parties: Parties,
    /// The agreed group name embedded by the sender (advisory)
    pub group_name: String,
    /// Per-group child pubkey `g * G1` (48 bytes)
    pub child_g1: G1Affine,
    /// Per-group child pubkey `g * G2` (96 bytes), present iff 3-party
    pub child_g2: Option<G2Affine>,
    /// BLS signature over `group_key_message` by the sender's `s_sig`
    pub signature: [u8; BLS_SIG_BYTES],
}

impl SetupToken {
    /// Build and sign this party's setup token for the group
    ///
    /// `members` is the **full** member set (self + every contact). The party
    /// count is inferred from `members.len()` (2 or 3).
    pub fn create(
        seed: &[u8; SEED_BYTES],
        purpose: Purpose,
        group_name: &str,
        members: &[PublicIdentity],
    ) -> Result<Self, ProtocolError> {
        let parties = Parties::from_u8(members.len() as u8)?;
        let ctx = group_ctx(purpose, group_name, members)?; // rejects an over-long name!
        let s_dh = derive_dh_scalar(seed);
        let s_sig = derive_sig_scalar(seed);
        let g = group_child(&s_dh, &ctx);

        let child_g1 = compute_pubkey_g1(&g);
        let child_g2 = match parties {
            Parties::Two => None,
            Parties::Three => Some(compute_pubkey_g2(&g)),
        };
        let msg = group_key_message(&ctx, &child_g1, child_g2.as_ref());
        let signature = bls_sign(&s_sig, &msg);

        Ok(SetupToken {
            parties,
            group_name: group_name.to_string(),
            child_g1,
            child_g2,
            signature,
        })
    }

    /// My own per-group child **scalar** (private), needed to derive `K`
    pub fn my_child_scalar(seed: &[u8; SEED_BYTES], ctx: &[u8; 32]) -> Scalar {
        group_child(&derive_dh_scalar(seed), ctx)
    }

    /// Encode this token as a base58check string (`type=0x02`, `version=2`),
    /// **encrypting** everything but the party count under `wrap_key` (the
    /// members' long-term DH/Joux key, see [`setup_wrap_key`]).
    ///
    /// `body = parties(1, clear) ‖ nonce(12) ‖ AEAD(plaintext)`, where
    /// `plaintext = u16_le(byte_len(name)) ‖ name ‖ child_g1(48)
    ///  [‖ child_g2(96) if 3-party] ‖ sig(96)`.
    pub fn encode(&self, wrap_key: &[u8; 32]) -> String {
        let name = self.group_name.as_bytes();
        let mut pt =
            Vec::with_capacity(2 + name.len() + G1_COMPRESSED + G2_COMPRESSED + BLS_SIG_BYTES);
        pt.extend_from_slice(&(name.len() as u16).to_le_bytes());
        pt.extend_from_slice(name);
        pt.extend_from_slice(&self.child_g1.to_compressed());
        if let Some(g2) = &self.child_g2 {
            pt.extend_from_slice(&g2.to_compressed());
        }
        pt.extend_from_slice(&self.signature);

        let aad = setup_token_aad(self.parties);
        let sealed = crypto::seal_token(wrap_key, &aad, &pt);
        let mut body = Vec::with_capacity(1 + sealed.len());
        body.push(self.parties.as_u8());
        body.extend_from_slice(&sealed);
        codec::encode(codec::TYPE_TOKEN, codec::VERSION_TOKEN, &body)
    }

    /// Decode, decrypt, and structurally validate a base58check setup token.
    ///
    /// `expected_parties` is the verifier's own party count (`#--party + 1`); a
    /// token advertising a different count is rejected up front. `wrap_key` is
    /// the verifier's own [`setup_wrap_key`].  A token not sealed for this
    /// membership fails AEAD authentication ([`CryptoError::TokenDecrypt`]).
    /// Every point is subgroup-validated on the way in. This does **not** check
    /// the signature or membership. You must call [`SetupToken::verify`] for that.
    pub fn decode(
        s: &str,
        expected_parties: Parties,
        wrap_key: &[u8; 32],
    ) -> Result<Self, ProtocolError> {
        let body = codec::decode(s, codec::TYPE_TOKEN, codec::VERSION_TOKEN)?;
        if body.is_empty() {
            return Err(ProtocolError::BadEncoding);
        }
        let parties = Parties::from_u8(body[0])?;
        if parties != expected_parties {
            return Err(ProtocolError::PartyMismatch {
                expected: expected_parties.as_u8(),
                found: parties.as_u8(),
            });
        }

        let aad = setup_token_aad(parties);
        let pt = crypto::open_token(wrap_key, &aad, &body[1..])?;
        let mut cur = Cursor::new(&pt);

        let name_len = cur.u16()? as usize;
        let name_bytes = cur.take(name_len)?;
        let group_name =
            String::from_utf8(name_bytes.to_vec()).map_err(|_| ProtocolError::BadEncoding)?;

        let g1_bytes: [u8; G1_COMPRESSED] = cur
            .take(G1_COMPRESSED)?
            .try_into()
            .expect("slice len checked");
        let child_g1 = read_g1(&g1_bytes)?;

        let child_g2 = match parties {
            Parties::Two => None,
            Parties::Three => {
                let g2_bytes: [u8; G2_COMPRESSED] = cur
                    .take(G2_COMPRESSED)?
                    .try_into()
                    .expect("slice len checked");
                Some(read_g2(&g2_bytes)?)
            }
        };

        let sig_bytes: [u8; BLS_SIG_BYTES] = cur
            .take(BLS_SIG_BYTES)?
            .try_into()
            .expect("slice len checked");

        if !cur.is_empty() {
            return Err(ProtocolError::BadEncoding); // trailing garbage
        }

        Ok(SetupToken {
            parties,
            group_name,
            child_g1,
            child_g2,
            signature: sig_bytes,
        })
    }

    /// Verify this peer token against a **locally recomputed** group context and
    /// the peer's **pinned** signing key.
    ///
    /// Checks, in order: the BLS signature (binds the child pubkey to *this*
    /// group's context and to the pinned signer); for 3-party, the DH-pair
    /// consistency of `(child_g1, child_g2)`; and child-key **disjointness**,
    /// i.e., that the child pubkey must not equal any member's long-term identity key.
    ///
    /// A token signed for a different name or membership fails here because its
    /// signature was made over a different `group_ctx`.
    pub fn verify(
        &self,
        ctx: &[u8; 32],
        signer_sig_g1: &G1Affine,
        members: &[PublicIdentity],
    ) -> Result<(), ProtocolError> {
        let msg = group_key_message(ctx, &self.child_g1, self.child_g2.as_ref());
        if !bls_verify(signer_sig_g1, &msg, &self.signature) {
            return Err(ProtocolError::BadSignature);
        }
        if let Some(g2) = &self.child_g2 {
            DhPublic {
                g1: self.child_g1,
                g2: *g2,
            }
            .check_consistency()?;
        }
        for m in members {
            if self.child_g1 == m.dh.g1 || self.child_g1 == m.sig_g1 {
                return Err(ProtocolError::ChildKeyReuse);
            }
            if let Some(g2) = &self.child_g2 {
                if *g2 == m.dh.g2 {
                    return Err(ProtocolError::ChildKeyReuse);
                }
            }
        }
        Ok(())
    }

    /// The peer's per-group child DH public pair (3-party only)
    fn peer_dh(&self) -> Result<DhPublic, ProtocolError> {
        let g2 = self.child_g2.ok_or(ProtocolError::BadEncoding)?;
        Ok(DhPublic {
            g1: self.child_g1,
            g2,
        })
    }
}

/// Derive the per-group shared secret `K` from my own per-group child scalar and
/// the verified peer setup tokens (positionally the other parties).
///
/// - 1 peer  -> `K = shared_secret_2(g_A, child_B.g1)`  (`= H2S(g_A * g_B * G1)`).
/// - 2 peers -> `K = group_secret_3(g_A, child_B, child_C)` (Joux; symmetric).
pub fn derive_group_key(
    my_child: &Scalar,
    peer_tokens: &[SetupToken],
) -> Result<Scalar, ProtocolError> {
    match peer_tokens.len() {
        1 => Ok(shared_secret_2(my_child, &peer_tokens[0].child_g1)),
        2 => {
            let pa = peer_tokens[0].peer_dh()?;
            let pb = peer_tokens[1].peer_dh()?;
            Ok(group_secret_3(my_child, &pa, &pb))
        }
        n => Err(ProtocolError::WrongPartyCount(n)),
    }
}

/// Reconstruct the per-group secret `K` from local state.
///
/// Rebuilds the full member set (self + `contacts`), recomputes `group_ctx`,
/// **re-verifies every peer token** against its positionally-assigned contact's
/// pinned signing key (so tampered state, a changed name, or a swapped member is
/// caught), then derives `K` from the caller's own re-derived child scalar.
///
/// `contacts` and `peer_tokens` are aligned (peer `i` was signed by contact `i`).
pub fn reconstruct_group_key(
    my_seed: &[u8; SEED_BYTES],
    group_name: &str,
    self_public: &PublicIdentity,
    contacts: &[PublicIdentity],
    peer_tokens: &[SetupToken],
) -> Result<Scalar, ProtocolError> {
    if contacts.len() != peer_tokens.len() {
        return Err(ProtocolError::WrongPartyCount(peer_tokens.len()));
    }
    let mut members = Vec::with_capacity(contacts.len() + 1);
    members.push(self_public.clone());
    members.extend_from_slice(contacts);

    // Stored groups are always created with `create` (Master purpose)
    let ctx = group_ctx(Purpose::Master, group_name, &members)?;
    for (tok, contact) in peer_tokens.iter().zip(contacts.iter()) {
        tok.verify(&ctx, &contact.sig_g1, &members)?;
    }
    let my_child = SetupToken::my_child_scalar(my_seed, &ctx);
    derive_group_key(&my_child, peer_tokens)
}

// --------------------------------------------------------
// Registry share tokens (hd-secret sync, group scope only)
// --------------------------------------------------------

/// Fixed domain tag prefixing the message signed over a registry share token.
/// Names a domain only: the version is bound numerically beside it, in
/// [`ShareToken::signed_message`].
const SHARE_MSG_TAG: &[u8] = b"sesh-share-msg";
/// AEAD associated-data tag for a sealed share token. Distinct from
/// [`SHARE_MSG_TAG`]: one separates a BLS signature domain, the other an
/// AES-GCM associated-data domain, and two cryptographic domains must never
/// share a tag by accident.
const SHARE_AAD_TAG: &[u8] = b"sesh-share-aad";

/// The associated data authenticated (but not hidden) by a sealed share token:
/// the domain tag, the token version, and the clear routing `group_ctx`.
///
/// The version is bound for the same reason as in [`setup_token_aad`]: the frame
/// byte carrying it is outside every ciphertext, so it is bound again here.
///
/// The frame's **type** byte needs no such treatment. `TYPE_SHARE` and
/// `TYPE_TOKEN` seal under different AAD tags, so a retagged setup token already
/// fails AEAD.
fn share_token_aad(ctx: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SHARE_AAD_TAG.len() + 1 + 32);
    aad.extend_from_slice(SHARE_AAD_TAG);
    aad.push(codec::VERSION_SHARE);
    aad.extend_from_slice(ctx);
    aad
}

/// The kind of registry change a share token broadcasts
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareAction {
    /// A new definition was created (or an existing one re-shared)
    New,
    /// An existing definition was rotated to a new epoch / params
    Update,
    /// A definition was removed (an epoch-versioned tombstone)
    Remove,
}

impl ShareAction {
    fn as_u8(self) -> u8 {
        match self {
            ShareAction::New => 1,
            ShareAction::Update => 2,
            ShareAction::Remove => 3,
        }
    }

    fn from_u8(n: u8) -> Result<Self, ProtocolError> {
        match n {
            1 => Ok(ShareAction::New),
            2 => Ok(ShareAction::Update),
            3 => Ok(ShareAction::Remove),
            _ => Err(ProtocolError::BadEncoding),
        }
    }

    /// The display name (`NEW`/`UPDATE`/`REMOVE`)
    pub fn describe(self) -> &'static str {
        match self {
            ShareAction::New => "NEW",
            ShareAction::Update => "UPDATE",
            ShareAction::Remove => "REMOVE",
        }
    }
}

/// A signed, group-bound broadcast of one registry definition change
///
/// Carries `(group_ctx, action, id, user, epoch, params)` and a BLS signature by
/// the editor's long-term `s_sig`, **no private material** (it cannot derive
/// the secret without the group master). The token does not name its signer: on
/// apply the recipient recomputes its **local** `group_ctx`, rejects a token for
/// any other group, and identifies the editor by trying each member's pinned
/// signing key (see [`ShareToken::verify`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareToken {
    /// The 32-byte group context this change is bound to
    pub group_ctx: [u8; 32],
    /// What kind of change this is
    pub action: ShareAction,
    /// Definition id (e.g. `google.com`)
    pub id: String,
    /// Definition sub-account (empty string = none)
    pub user: String,
    /// The definition's (post-change) epoch
    pub epoch: u64,
    /// The definition's formatting params
    pub params: Params,
    /// BLS signature over the domain-tagged body by the editor's `s_sig`
    pub signature: [u8; BLS_SIG_BYTES],
}

impl ShareToken {
    /// The length-prefixed body (everything but the signature).
    ///
    /// `group_ctx(32) ‖ action(1) ‖ u16_le(|id|) ‖ id ‖ u16_le(|user|) ‖ user
    ///  ‖ u64_le(epoch) ‖ u8(|mode|) ‖ mode ‖ u8(has_len) [‖ u64_le(len)]
    ///  ‖ u8(|symbols|) [‖ symbols] ‖ u8(has_suffix) [‖ u16_le(|suffix|) ‖ suffix]`
    ///
    /// The symbol set is a bare length prefix, `0` meaning off. Not
    /// `u8(has) ‖ u8(len) ‖ set`: that spelling has an illegal state (`has=1,
    /// len=0`) for `open` to reject by hand, and two encodings of *off*, the
    /// same class of ambiguity the version binding above exists to close. A
    /// `u8` suffices where `suffix` needs a `u16` because
    /// [`crate::format::validate_symbol_set`] structurally caps a set at 84
    /// characters.
    fn body_prefix(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.id.len() > u16::MAX as usize {
            return Err(ProtocolError::FieldTooLong("definition id"));
        }
        if self.user.len() > u16::MAX as usize {
            return Err(ProtocolError::FieldTooLong("definition user"));
        }
        if self.params.mode.len() > u8::MAX as usize {
            return Err(ProtocolError::FieldTooLong("params mode"));
        }
        // `create` is `pub` and never calls `validate_params`, so the structural
        // cap is not enough on its own. Without this guard `set.len() as u8`
        // would truncate, not a forgery (`create` and `verify` both sign the
        // same truncated body) but an unparseable token, surfacing far away as a
        // trailing-garbage `BadEncoding`.
        if let Some(set) = &self.params.symbols {
            if set.len() > u8::MAX as usize {
                return Err(ProtocolError::FieldTooLong("params symbols"));
            }
        }
        if let Some(s) = &self.params.suffix {
            if s.len() > u16::MAX as usize {
                return Err(ProtocolError::FieldTooLong("params suffix"));
            }
        }
        let mut b = Vec::with_capacity(64 + self.id.len() + self.user.len());
        b.extend_from_slice(&self.group_ctx);
        b.push(self.action.as_u8());
        b.extend_from_slice(&(self.id.len() as u16).to_le_bytes());
        b.extend_from_slice(self.id.as_bytes());
        b.extend_from_slice(&(self.user.len() as u16).to_le_bytes());
        b.extend_from_slice(self.user.as_bytes());
        b.extend_from_slice(&self.epoch.to_le_bytes());
        b.push(self.params.mode.len() as u8);
        b.extend_from_slice(self.params.mode.as_bytes());
        match self.params.length {
            None => b.push(0),
            Some(l) => {
                b.push(1);
                b.extend_from_slice(&l.to_le_bytes());
            }
        }
        match &self.params.symbols {
            None => b.push(0),
            Some(set) => {
                b.push(set.len() as u8);
                b.extend_from_slice(set.as_bytes());
            }
        }
        match &self.params.suffix {
            None => b.push(0),
            Some(s) => {
                b.push(1);
                b.extend_from_slice(&(s.len() as u16).to_le_bytes());
                b.extend_from_slice(s.as_bytes());
            }
        }
        Ok(b)
    }

    /// The exact bytes a share token's BLS signature covers:
    /// `"sesh-share-msg" ‖ u8(VERSION_SHARE) ‖ body_prefix`.
    ///
    /// The version is signed, not merely framed. Two adjacent versions' bodies
    /// coincide byte-for-byte whenever a bump did not touch a field this
    /// particular token uses, the common case, so without this an attacker
    /// could rewrite the frame's clear version byte, recompute the checksum, and
    /// hand a newer build a token whose signature still verified.
    fn signed_message(&self) -> Result<Vec<u8>, ProtocolError> {
        let prefix = self.body_prefix()?;
        let mut msg = Vec::with_capacity(SHARE_MSG_TAG.len() + 1 + prefix.len());
        msg.extend_from_slice(SHARE_MSG_TAG);
        msg.push(codec::VERSION_SHARE);
        msg.extend_from_slice(&prefix);
        Ok(msg)
    }

    /// Build and sign a share token for one definition change
    pub fn create(
        seed: &[u8; SEED_BYTES],
        group_ctx: &[u8; 32],
        action: ShareAction,
        id: &str,
        user: &str,
        epoch: u64,
        params: Params,
    ) -> Result<Self, ProtocolError> {
        let mut token = ShareToken {
            group_ctx: *group_ctx,
            action,
            id: id.to_string(),
            user: user.to_string(),
            epoch,
            params,
            signature: [0u8; BLS_SIG_BYTES],
        };
        token.signature = bls_sign(&derive_sig_scalar(seed), &token.signed_message()?);
        Ok(token)
    }

    /// Encode as a base58check string (`type=0x03`, `version=2`), **encrypting**
    /// everything but the routing `group_ctx` under `wrap_key`
    /// ([`crypto::share_wrap_key`] of the group secret `K`).
    ///
    /// `body = group_ctx(32, clear) ‖ nonce(12) ‖ AEAD(inner)`, where
    /// `inner = body_prefix[32..] ‖ sig(96)` (the signed body sans its leading
    /// ctx, plus the signature). Sign-then-encrypt: the signature is confined
    /// to the ciphertext, so an eavesdropper cannot attribute the token.
    pub fn encode(&self, wrap_key: &[u8; 32]) -> Result<String, ProtocolError> {
        let prefix = self.body_prefix()?; // group_ctx is prefix[..32]
        let mut inner = Vec::with_capacity(prefix.len() - 32 + BLS_SIG_BYTES);
        inner.extend_from_slice(&prefix[32..]);
        inner.extend_from_slice(&self.signature);

        let aad = share_token_aad(&self.group_ctx);
        let sealed = crypto::seal_token(wrap_key, &aad, &inner);
        let mut body = Vec::with_capacity(32 + sealed.len());
        body.extend_from_slice(&self.group_ctx);
        body.extend_from_slice(&sealed);
        Ok(codec::encode(
            codec::TYPE_SHARE,
            codec::VERSION_SHARE,
            &body,
        ))
    }

    /// Read only the clear routing `group_ctx` of a share token-- no key
    /// needed. The recipient uses it to pick which local group's `K` to open
    /// the token with (see [`ShareToken::open`]).
    pub fn peek_group_ctx(s: &str) -> Result<[u8; 32], ProtocolError> {
        let body = codec::decode(s, codec::TYPE_SHARE, codec::VERSION_SHARE)?;
        let mut cur = Cursor::new(&body);
        let ctx: [u8; 32] = cur.take(32)?.try_into().expect("slice len checked");
        Ok(ctx)
    }

    /// Decrypt and parse a share token with the group's `wrap_key`
    /// ([`crypto::share_wrap_key`] of `K`). A token for another group fails AEAD
    /// authentication. Structure only; call [`ShareToken::verify`] to
    /// authenticate the editor's signature against the pinned members.
    pub fn open(s: &str, wrap_key: &[u8; 32]) -> Result<Self, ProtocolError> {
        let body = codec::decode(s, codec::TYPE_SHARE, codec::VERSION_SHARE)?;
        if body.len() < 32 {
            return Err(ProtocolError::BadEncoding);
        }
        let ctx: [u8; 32] = body[..32].try_into().expect("slice len checked");
        let aad = share_token_aad(&ctx);
        let pt = crypto::open_token(wrap_key, &aad, &body[32..])?;
        let mut cur = Cursor::new(&pt);

        let action = ShareAction::from_u8(cur.u8()?)?;
        let id_len = cur.u16()? as usize;
        let id = String::from_utf8(cur.take(id_len)?.to_vec())
            .map_err(|_| ProtocolError::BadEncoding)?;
        let user_len = cur.u16()? as usize;
        let user = String::from_utf8(cur.take(user_len)?.to_vec())
            .map_err(|_| ProtocolError::BadEncoding)?;
        let epoch = cur.u64()?;
        let mode_len = cur.u8()? as usize;
        let mode = String::from_utf8(cur.take(mode_len)?.to_vec())
            .map_err(|_| ProtocolError::BadEncoding)?;
        let length = match cur.u8()? {
            0 => None,
            1 => Some(cur.u64()?),
            _ => return Err(ProtocolError::BadEncoding),
        };
        // A bare length: no illegal states, no flag byte to range-check. The set
        // is read as UTF-8 but not validated here; `render_body`'s gate is the
        // safety net, and `validate_params` fires earlier on the `apply` path.
        let symbols = match cur.u8()? as usize {
            0 => None,
            n => Some(
                String::from_utf8(cur.take(n)?.to_vec()).map_err(|_| ProtocolError::BadEncoding)?,
            ),
        };
        let suffix = match cur.u8()? {
            0 => None,
            1 => {
                let n = cur.u16()? as usize;
                Some(
                    String::from_utf8(cur.take(n)?.to_vec())
                        .map_err(|_| ProtocolError::BadEncoding)?,
                )
            }
            _ => return Err(ProtocolError::BadEncoding),
        };
        let signature: [u8; BLS_SIG_BYTES] = cur
            .take(BLS_SIG_BYTES)?
            .try_into()
            .expect("slice len checked");
        if !cur.is_empty() {
            return Err(ProtocolError::BadEncoding); // trailing garbage
        }

        Ok(ShareToken {
            group_ctx: ctx,
            action,
            id,
            user,
            epoch,
            params: Params {
                mode,
                length,
                symbols,
                suffix,
            },
            signature,
        })
    }

    /// Verify this token against the **locally recomputed** group context and
    /// the group's pinned members, returning the index of the member whose
    /// signing key verifies (identifying the editor).
    ///
    /// A token bound to a different `group_ctx` is rejected up front
    /// ([`ProtocolError::WrongGroup`]m no cross-group replay); a token signed
    /// by no member is rejected ([`ProtocolError::BadSignature`]).
    pub fn verify(
        &self,
        local_ctx: &[u8; 32],
        members: &[PublicIdentity],
    ) -> Result<usize, ProtocolError> {
        if &self.group_ctx != local_ctx {
            return Err(ProtocolError::WrongGroup);
        }
        let msg = self.signed_message()?;
        members
            .iter()
            .position(|m| bls_verify(&m.sig_g1, &msg, &self.signature))
            .ok_or(ProtocolError::BadSignature)
    }
}

/// A minimal forward-only byte cursor for structural token parsing
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.pos.checked_add(n).ok_or(ProtocolError::BadEncoding)?;
        if end > self.buf.len() {
            return Err(ProtocolError::BadEncoding);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let b: [u8; 8] = self.take(8)?.try_into().expect("slice len checked");
        Ok(u64::from_le_bytes(b))
    }
    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// The agreement checksum for a derived secret (re-exported convenience)
pub fn checksum(secret: &Scalar) -> String {
    crypto::agreement_checksum(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::public_identity_from_seed;

    fn seed(b: u8) -> [u8; SEED_BYTES] {
        [b; SEED_BYTES]
    }

    // Test shorthand: `group_ctx` with a known-valid name
    fn gctx(name: &str, members: &[PublicIdentity]) -> [u8; 32] {
        group_ctx(Purpose::Master, name, members).unwrap()
    }

    // Test shorthand: the setup-token wrap key member `b` derives for `members`
    fn swk(b: u8, members: &[PublicIdentity]) -> [u8; 32] {
        let me = public_identity_from_seed(&seed(b));
        let others: Vec<PublicIdentity> = members.iter().filter(|m| **m != me).cloned().collect();
        setup_wrap_key(&seed(b), &others, members).unwrap()
    }

    #[test]
    fn setup_wrap_key_is_shared_by_all_members() {
        // Every member derives the SAME setup wrap key (2- and 3-party), the
        // property that lets one sealed token decrypt for all peers.
        let m2 = [pubid(1), pubid(2)];
        assert_eq!(swk(1, &m2), swk(2, &m2));
        let m3 = [pubid(1), pubid(2), pubid(3)];
        assert_eq!(swk(1, &m3), swk(2, &m3));
        assert_eq!(swk(2, &m3), swk(3, &m3));
        // A different membership yields a different key
        assert_ne!(swk(1, &m2), swk(1, &m3));
    }

    #[test]
    fn setup_token_wrong_membership_fails_to_open() {
        // A token sealed for {1,2} cannot be opened with the {1,3} wrap key
        let m12 = [pubid(1), pubid(2)];
        let tok = SetupToken::create(&seed(1), Purpose::Master, "g", &m12).unwrap();
        let enc = tok.encode(&swk(1, &m12));
        let m13 = [pubid(1), pubid(3)];
        assert!(matches!(
            SetupToken::decode(&enc, Parties::Two, &swk(1, &m13)),
            Err(ProtocolError::Crypto(CryptoError::TokenDecrypt))
        ));
    }

    #[test]
    fn group_ctx_rejects_over_long_name() {
        let members = [pubid(1), pubid(2)];
        let long = "x".repeat(u16::MAX as usize + 1);
        assert_eq!(
            group_ctx(Purpose::Master, &long, &members),
            Err(ProtocolError::NameTooLong)
        );
        assert!(matches!(
            SetupToken::create(&seed(1), Purpose::Master, &long, &members),
            Err(ProtocolError::NameTooLong)
        ));
        // The maximum valid length still works
        let max = "x".repeat(u16::MAX as usize);
        assert!(group_ctx(Purpose::Master, &max, &members).is_ok());
    }

    #[test]
    fn parties_parsing() {
        assert_eq!(Parties::from_u8(2).unwrap().peer_count(), 1);
        assert_eq!(Parties::from_u8(3).unwrap().peer_count(), 2);
        assert!(Parties::from_u8(4).is_err());
        assert!(Parties::from_u8(1).is_err());
    }

    #[test]
    fn contact_token_round_trips() {
        let public = public_identity_from_seed(&seed(1));
        let token = encode_contact_token("alice", &public).unwrap();
        let (name, decoded) = decode_contact_token(&token).unwrap();
        assert_eq!(name, "alice");
        assert_eq!(decoded, public);
        // The empty name round-trips too (recipient must supply one)
        let (name, _) = decode_contact_token(&encode_contact_token("", &public).unwrap()).unwrap();
        assert_eq!(name, "");
    }

    #[test]
    fn contact_token_rejects_corruption() {
        let public = public_identity_from_seed(&seed(1));
        let token = encode_contact_token("alice", &public).unwrap();
        // Flip a character in the middle -> checksum failure surfaces as Codec
        let mut chars: Vec<char> = token.chars().collect();
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let corrupt: String = chars.into_iter().collect();
        assert!(matches!(
            decode_contact_token(&corrupt),
            Err(ProtocolError::Codec(_))
        ));
    }

    #[test]
    fn contact_token_rejects_wrong_type() {
        // A setup-token-framed value (wrong type tag) must not decode as a contact
        let body = vec![0u8; 2 + IDENTITY_BYTES];
        let setup_framed = codec::encode(codec::TYPE_TOKEN, codec::VERSION_TOKEN, &body);
        assert!(matches!(
            decode_contact_token(&setup_framed),
            Err(ProtocolError::Codec(CodecError::WrongType { .. }))
        ));
    }

    // Group context

    fn pubid(b: u8) -> PublicIdentity {
        public_identity_from_seed(&seed(b))
    }

    #[test]
    fn group_ctx_is_permutation_invariant() {
        let (a, b, c) = (pubid(1), pubid(2), pubid(3));
        let ctx1 = gctx("grp", &[a.clone(), b.clone(), c.clone()]);
        let ctx2 = gctx("grp", &[c.clone(), a.clone(), b.clone()]);
        let ctx3 = gctx("grp", &[b, c, a]);
        assert_eq!(ctx1, ctx2);
        assert_eq!(ctx2, ctx3);
    }

    #[test]
    fn group_ctx_is_identical_from_every_members_view() {
        // Each member lists "self first, then the others" in their own order;
        // all must arrive at the same context.
        let (a, b, c) = (pubid(1), pubid(2), pubid(3));
        let a_view = gctx("g", &[a.clone(), b.clone(), c.clone()]);
        let b_view = gctx("g", &[b.clone(), a.clone(), c.clone()]);
        let c_view = gctx("g", &[c.clone(), a.clone(), b.clone()]);
        assert_eq!(a_view, b_view);
        assert_eq!(b_view, c_view);
    }

    #[test]
    fn group_ctx_binds_the_name_and_membership() {
        let (a, b, c) = (pubid(1), pubid(2), pubid(3));
        let base = gctx("grp", &[a.clone(), b.clone()]);
        assert_ne!(base, gctx("other", &[a.clone(), b.clone()]));
        // Different membership -> different context
        assert_ne!(base, gctx("grp", &[a, b, c]));
    }

    #[test]
    fn group_fingerprint_is_member_order_invariant_and_group_sensitive() {
        let (a, b, c) = (pubid(1), pubid(2), pubid(3));
        // Identical for every member's view of the same group...
        let f1 = group_fingerprint(&gctx("g", &[a.clone(), b.clone(), c.clone()]));
        let f2 = group_fingerprint(&gctx("g", &[c.clone(), b.clone(), a.clone()]));
        assert_eq!(f1, f2);
        // ... but different for a different name or membership
        assert_ne!(
            f1,
            group_fingerprint(&gctx("h", &[a.clone(), b.clone(), c]))
        );
        assert_ne!(f1, group_fingerprint(&gctx("g", &[a, b])));
    }

    // Setup tokens & per-group agreement

    #[test]
    fn token_round_trips_2p() {
        let members = [pubid(1), pubid(2)];
        let wk = swk(1, &members);
        let token = SetupToken::create(&seed(1), Purpose::Master, "grp", &members).unwrap();
        let decoded = SetupToken::decode(&token.encode(&wk), Parties::Two, &wk).unwrap();
        assert_eq!(decoded, token);
        assert!(decoded.child_g2.is_none());
    }

    #[test]
    fn token_round_trips_3p() {
        let members = [pubid(1), pubid(2), pubid(3)];
        let wk = swk(1, &members);
        let token = SetupToken::create(&seed(1), Purpose::Master, "grp", &members).unwrap();
        let decoded = SetupToken::decode(&token.encode(&wk), Parties::Three, &wk).unwrap();
        assert_eq!(decoded, token);
        assert!(decoded.child_g2.is_some());
    }

    #[test]
    fn two_party_per_group_agreement() {
        let (a, b) = (seed(10), seed(20));
        let members = [public_identity_from_seed(&a), public_identity_from_seed(&b)];
        let ctx = gctx("g", &members);

        let ta = SetupToken::create(&a, Purpose::Master, "g", &members).unwrap();
        let tb = SetupToken::create(&b, Purpose::Master, "g", &members).unwrap();

        // Each verifies the other's token against the pinned signer
        ta.verify(&ctx, &members[0].sig_g1, &members).unwrap();
        tb.verify(&ctx, &members[1].sig_g1, &members).unwrap();

        let ka = derive_group_key(&SetupToken::my_child_scalar(&a, &ctx), &[tb]).unwrap();
        let kb = derive_group_key(&SetupToken::my_child_scalar(&b, &ctx), &[ta]).unwrap();
        assert_eq!(ka, kb);
        assert_eq!(checksum(&ka), checksum(&kb));
    }

    #[test]
    fn three_party_per_group_agreement() {
        let (a, b, c) = (seed(11), seed(22), seed(33));
        let members = [
            public_identity_from_seed(&a),
            public_identity_from_seed(&b),
            public_identity_from_seed(&c),
        ];
        let ctx = gctx("g", &members);

        let ta = SetupToken::create(&a, Purpose::Master, "g", &members).unwrap();
        let tb = SetupToken::create(&b, Purpose::Master, "g", &members).unwrap();
        let tc = SetupToken::create(&c, Purpose::Master, "g", &members).unwrap();

        let ka = derive_group_key(
            &SetupToken::my_child_scalar(&a, &ctx),
            &[tb.clone(), tc.clone()],
        )
        .unwrap();
        let kb = derive_group_key(
            &SetupToken::my_child_scalar(&b, &ctx),
            &[ta.clone(), tc.clone()],
        )
        .unwrap();
        let kc = derive_group_key(
            &SetupToken::my_child_scalar(&c, &ctx),
            &[ta.clone(), tb.clone()],
        )
        .unwrap();
        assert_eq!(ka, kb);
        assert_eq!(kb, kc);

        // Permutation of the peer tokens does not matter (Joux symmetry)
        let ka2 = derive_group_key(&SetupToken::my_child_scalar(&a, &ctx), &[tc, tb]).unwrap();
        assert_eq!(ka, ka2);
    }

    #[test]
    fn same_members_different_name_diverges() {
        let (a, b) = (seed(1), seed(2));
        let members = [public_identity_from_seed(&a), public_identity_from_seed(&b)];
        let key = |name: &str| {
            let ctx = gctx(name, &members);
            let tb = SetupToken::create(&b, Purpose::Master, name, &members).unwrap();
            derive_group_key(&SetupToken::my_child_scalar(&a, &ctx), &[tb]).unwrap()
        };
        assert_eq!(key("grp"), key("grp")); // same name -> same K
        assert_ne!(key("grp"), key("other")); // different name -> different K
    }

    #[test]
    fn reconstruct_group_key_matches_direct_derivation_2p() {
        let (a, b) = (seed(10), seed(20));
        let (pa, pb) = (public_identity_from_seed(&a), public_identity_from_seed(&b));
        let members = [pa.clone(), pb.clone()];
        let ctx = gctx("g", &members);
        let tb = SetupToken::create(&b, Purpose::Master, "g", &members).unwrap();

        let reconstructed = reconstruct_group_key(
            &a,
            "g",
            &pa,
            std::slice::from_ref(&pb),
            std::slice::from_ref(&tb),
        )
        .unwrap();
        let direct = derive_group_key(&SetupToken::my_child_scalar(&a, &ctx), &[tb]).unwrap();
        assert_eq!(reconstructed, direct);
    }

    #[test]
    fn reconstruct_group_key_3p_all_agree() {
        let (a, b, c) = (seed(11), seed(22), seed(33));
        let (pa, pb, pc) = (
            public_identity_from_seed(&a),
            public_identity_from_seed(&b),
            public_identity_from_seed(&c),
        );
        let members = [pa.clone(), pb.clone(), pc.clone()];
        let ta = SetupToken::create(&a, Purpose::Master, "g", &members).unwrap();
        let tb = SetupToken::create(&b, Purpose::Master, "g", &members).unwrap();
        let tc = SetupToken::create(&c, Purpose::Master, "g", &members).unwrap();

        let ka = reconstruct_group_key(
            &a,
            "g",
            &pa,
            &[pb.clone(), pc.clone()],
            &[tb.clone(), tc.clone()],
        )
        .unwrap();
        let kb = reconstruct_group_key(&b, "g", &pb, &[pa.clone(), pc.clone()], &[ta.clone(), tc])
            .unwrap();
        let kc = reconstruct_group_key(&c, "g", &pc, &[pa, pb], &[ta, tb]).unwrap();
        assert_eq!(ka, kb);
        assert_eq!(kb, kc);
    }

    #[test]
    fn reconstruct_group_key_rejects_tampered_peer_token() {
        let (a, b) = (seed(10), seed(20));
        let (pa, pb) = (public_identity_from_seed(&a), public_identity_from_seed(&b));
        let members = [pa.clone(), pb.clone()];
        let mut tb = SetupToken::create(&b, Purpose::Master, "g", &members).unwrap();
        tb.signature[5] ^= 0xff; // corrupt the peer's signature! :-)
        assert_eq!(
            reconstruct_group_key(&a, "g", &pa, &[pb], &[tb]),
            Err(ProtocolError::BadSignature)
        );
    }

    #[test]
    fn token_verify_rejects_wrong_signer() {
        let members = [pubid(1), pubid(2), pubid(3)];
        let ctx = gctx("g", &members);
        let tb = SetupToken::create(&seed(2), Purpose::Master, "g", &members).unwrap();
        // Verify B's token against C's signing key
        assert_eq!(
            tb.verify(&ctx, &members[2].sig_g1, &members),
            Err(ProtocolError::BadSignature)
        );
    }

    #[test]
    fn token_verify_rejects_wrong_name() {
        let members = [pubid(1), pubid(2)];
        let tb = SetupToken::create(&seed(2), Purpose::Master, "grp", &members).unwrap();
        // Verifier recomputes ctx under a DIFFERENT name --> signature mismatch
        let wrong_ctx = gctx("other", &members);
        assert_eq!(
            tb.verify(&wrong_ctx, &members[1].sig_g1, &members),
            Err(ProtocolError::BadSignature)
        );
    }

    #[test]
    fn token_verify_rejects_tampered_child_pubkey() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let mut tb = SetupToken::create(&seed(2), Purpose::Master, "g", &members).unwrap();
        // Swap in a different valid G1 point; signature no longer matches
        tb.child_g1 = members[0].dh.g1;
        assert!(matches!(
            tb.verify(&ctx, &members[1].sig_g1, &members),
            Err(ProtocolError::BadSignature)
        ));
    }

    #[test]
    fn token_verify_rejects_child_reusing_identity_key() {
        // A cheater signs a token whose "child" is its own long-term DH key
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let s_dh = derive_dh_scalar(&seed(1));
        let s_sig = derive_sig_scalar(&seed(1));
        let child_g1 = compute_pubkey_g1(&s_dh); // == members[0].dh.g1
        assert_eq!(child_g1, members[0].dh.g1);
        let msg = group_key_message(&ctx, &child_g1, None);
        let signature = bls_sign(&s_sig, &msg);
        let cheat = SetupToken {
            parties: Parties::Two,
            group_name: "g".into(),
            child_g1,
            child_g2: None,
            signature,
        };
        // The signature is valid, but the disjointedness check catches the reuse
        assert_eq!(
            cheat.verify(&ctx, &members[0].sig_g1, &members),
            Err(ProtocolError::ChildKeyReuse)
        );
    }

    #[test]
    fn token_verify_rejects_inconsistent_3party_pair() {
        let members = [pubid(1), pubid(2), pubid(3)];
        let ctx = gctx("g", &members);
        let s_dh = derive_dh_scalar(&seed(2));
        let s_sig = derive_sig_scalar(&seed(2));
        let g = group_child(&s_dh, &ctx);
        let child_g1 = compute_pubkey_g1(&g);
        // g2 from a DIFFERENT scalar -> inconsistent pair
        let bad_g2 = compute_pubkey_g2(&group_child(&s_dh, &[9u8; 32]));
        let msg = group_key_message(&ctx, &child_g1, Some(&bad_g2));
        let signature = bls_sign(&s_sig, &msg);
        let token = SetupToken {
            parties: Parties::Three,
            group_name: "g".into(),
            child_g1,
            child_g2: Some(bad_g2),
            signature,
        };
        assert_eq!(
            token.verify(&ctx, &members[1].sig_g1, &members),
            Err(ProtocolError::Crypto(CryptoError::InconsistentDhPair))
        );
    }

    #[test]
    fn token_decode_rejects_party_mismatch() {
        // Party count is clear and checked before decryption, so the wrap key
        // is irrelevant here.
        let members = [pubid(1), pubid(2)];
        let token = SetupToken::create(&seed(1), Purpose::Master, "g", &members).unwrap();
        assert!(matches!(
            SetupToken::decode(&token.encode(&swk(1, &members)), Parties::Three, &[0u8; 32]),
            Err(ProtocolError::PartyMismatch {
                expected: 3,
                found: 2
            })
        ));
    }

    #[test]
    fn token_decode_rejects_corruption() {
        let members = [pubid(1), pubid(2)];
        let wk = swk(1, &members);
        let token = SetupToken::create(&seed(1), Purpose::Master, "g", &members).unwrap();
        let enc = token.encode(&wk);
        let mut chars: Vec<char> = enc.chars().collect();
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let corrupt: String = chars.into_iter().collect();
        assert!(matches!(
            SetupToken::decode(&corrupt, Parties::Two, &wk),
            Err(ProtocolError::Codec(_))
        ));
    }

    // Registry share tokens

    fn share_params(mode: &str, length: Option<u64>, suffix: Option<&str>) -> Params {
        Params {
            mode: mode.to_string(),
            length,
            symbols: None,
            suffix: suffix.map(|s| s.to_string()),
        }
    }

    #[test]
    fn share_token_round_trips_all_param_shapes() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        for params in [
            share_params("b58", None, None),
            share_params("alpha", Some(20), None),
            share_params("hex", None, Some("!X9")),
            share_params("b10", Some(6), Some("#")),
        ] {
            let tok = ShareToken::create(
                &seed(1),
                &ctx,
                ShareAction::Update,
                "google.com",
                "bob@google.com",
                7,
                params,
            )
            .unwrap();
            let wk = [7u8; 32];
            let decoded = ShareToken::open(&tok.encode(&wk).unwrap(), &wk).unwrap();
            assert_eq!(decoded, tok);
            // The routing ctx is readable without the key ...
            assert_eq!(
                ShareToken::peek_group_ctx(&tok.encode(&wk).unwrap()).unwrap(),
                ctx
            );
            // but the wrong key cannot open the body.
            assert!(matches!(
                ShareToken::open(&tok.encode(&wk).unwrap(), &[9u8; 32]),
                Err(ProtocolError::Crypto(CryptoError::TokenDecrypt))
            ));
        }
    }

    #[test]
    fn share_token_round_trips_a_custom_symbol_set_and_its_signature_verifies() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let wk = [7u8; 32];
        for set in [None, Some(crate::format::SYMBOLS), Some("!@#"), Some("'")] {
            let params = Params {
                mode: "b58".into(),
                length: None,
                symbols: set.map(str::to_string),
                suffix: None,
            };
            let tok =
                ShareToken::create(&seed(1), &ctx, ShareAction::New, "vpn", "", 1, params).unwrap();
            let decoded = ShareToken::open(&tok.encode(&wk).unwrap(), &wk).unwrap();
            assert_eq!(decoded, tok);
            assert_eq!(decoded.params.symbols.as_deref(), set);
            // The set is inside the signed body, so it is authenticated too
            assert_eq!(decoded.verify(&ctx, &members).unwrap(), 0);
        }
    }

    #[test]
    fn share_token_symbol_set_is_covered_by_the_signature() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let tok = ShareToken::create(
            &seed(1),
            &ctx,
            ShareAction::New,
            "vpn",
            "",
            1,
            Params {
                symbols: Some("!@".into()),
                ..share_params("b58", None, None)
            },
        )
        .unwrap();
        let mut tampered = tok.clone();
        tampered.params.symbols = Some("@!".into()); // same length, different order
        assert_eq!(
            tampered.verify(&ctx, &members),
            Err(ProtocolError::BadSignature)
        );
        let mut tampered = tok;
        tampered.params.symbols = None;
        assert_eq!(
            tampered.verify(&ctx, &members),
            Err(ProtocolError::BadSignature)
        );
    }

    // `create` is `pub` and never calls `validate_params`, so the `as u8`
    // truncation in `body_prefix` must be **unreachable**, not merely unreached.
    // No set this long can come from `validate_symbol_set`, which structurally
    // caps at 84 characters.
    #[test]
    fn share_token_refuses_a_symbol_set_too_long_for_its_length_prefix() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let huge = "!".repeat(300);
        assert_eq!(
            ShareToken::create(
                &seed(1),
                &ctx,
                ShareAction::New,
                "vpn",
                "",
                1,
                Params {
                    symbols: Some(huge),
                    ..share_params("b58", None, None)
                },
            ),
            Err(ProtocolError::FieldTooLong("params symbols"))
        );
        // The longest set that still fits is accepted.
        let max = "!".repeat(u8::MAX as usize);
        assert!(ShareToken::create(
            &seed(1),
            &ctx,
            ShareAction::New,
            "vpn",
            "",
            1,
            Params {
                symbols: Some(max),
                ..share_params("b58", None, None)
            },
        )
        .is_ok());
    }

    #[test]
    fn share_token_verify_identifies_the_editor() {
        let members = [pubid(1), pubid(2), pubid(3)];
        let ctx = gctx("g", &members);
        // Signed by member index 1 (seed 2)
        let tok = ShareToken::create(
            &seed(2),
            &ctx,
            ShareAction::New,
            "vpn",
            "",
            1,
            share_params("b58", None, None),
        )
        .unwrap();
        assert_eq!(tok.verify(&ctx, &members).unwrap(), 1);
    }

    #[test]
    fn share_token_rejects_non_member_signer() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        // Signed by an outsider (seed 9, not in members)
        let tok = ShareToken::create(
            &seed(9),
            &ctx,
            ShareAction::New,
            "vpn",
            "",
            1,
            share_params("b58", None, None),
        )
        .unwrap();
        assert_eq!(tok.verify(&ctx, &members), Err(ProtocolError::BadSignature));
    }

    #[test]
    fn share_token_rejects_cross_group_replay() {
        let members = [pubid(1), pubid(2)];
        let ctx_a = gctx("groupA", &members);
        let ctx_b = gctx("groupB", &members);
        let tok = ShareToken::create(
            &seed(1),
            &ctx_a,
            ShareAction::New,
            "vpn",
            "",
            1,
            share_params("b58", None, None),
        )
        .unwrap();
        // Applied against a different group's locally recomputed context
        assert_eq!(tok.verify(&ctx_b, &members), Err(ProtocolError::WrongGroup));
    }

    #[test]
    fn share_token_rejects_tampered_fields() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let tok = ShareToken::create(
            &seed(1),
            &ctx,
            ShareAction::Update,
            "vpn",
            "",
            3,
            share_params("b58", None, None),
        )
        .unwrap();
        // Any post-signing field change breaks the signature
        let mut t = tok.clone();
        t.epoch = 4;
        assert_eq!(t.verify(&ctx, &members), Err(ProtocolError::BadSignature));
        let mut t = tok.clone();
        t.id = "vpn2".into();
        assert_eq!(t.verify(&ctx, &members), Err(ProtocolError::BadSignature));
        let mut t = tok.clone();
        t.action = ShareAction::Remove;
        assert_eq!(t.verify(&ctx, &members), Err(ProtocolError::BadSignature));
        let mut t = tok;
        t.params.mode = "hex".into();
        assert_eq!(t.verify(&ctx, &members), Err(ProtocolError::BadSignature));
    }

    #[test]
    fn share_token_rejects_corruption_and_wrong_type() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let tok = ShareToken::create(
            &seed(1),
            &ctx,
            ShareAction::New,
            "vpn",
            "",
            1,
            share_params("b58", None, None),
        )
        .unwrap();
        let wk = [7u8; 32];
        let enc = tok.encode(&wk).unwrap();
        // Flip a character -> integrity checksum failure (before any decrypt)
        let mut chars: Vec<char> = enc.chars().collect();
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let corrupt: String = chars.into_iter().collect();
        assert!(matches!(
            ShareToken::open(&corrupt, &wk),
            Err(ProtocolError::Codec(_))
        ));
        // A setup token must not decode as a share token (wrong type tag,
        // rejected by the frame check before decryption).
        let setup = SetupToken::create(&seed(1), Purpose::Master, "g", &members)
            .unwrap()
            .encode(&swk(1, &members));
        assert!(matches!(
            ShareToken::peek_group_ctx(&setup),
            Err(ProtocolError::Codec(CodecError::WrongType { .. }))
        ));
    }

    // Token version binding.
    //
    // The frame's version byte sits in the clear, covered only by a checksum an
    // attacker recomputes at will. These fixtures keep the body byte-identical
    // across the two versions (the common case for a bump that did not touch a
    // field this token uses) so nothing but the binding itself can reject them.

    // Re-frame `encoded` at `version`, recomputing the checksum as an attacker
    // would. The body is untouched.
    fn reframe_version(encoded: &str, version: u8) -> String {
        let mut raw = bs58::decode(encoded).into_vec().unwrap();
        let end = raw.len() - codec::CHECKSUM_LEN;
        raw[1] = version;
        let digest = Sha3_256::digest(&raw[..end]);
        raw[end..].copy_from_slice(&digest[..codec::CHECKSUM_LEN]);
        bs58::encode(raw).into_string()
    }

    #[test]
    fn share_token_rejects_a_rewritten_frame_version() {
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let wk = [7u8; 32];
        let tok = ShareToken::create(
            &seed(1),
            &ctx,
            ShareAction::New,
            "vpn",
            "",
            1,
            share_params("b58", None, None),
        )
        .unwrap();
        let forged = reframe_version(&tok.encode(&wk).unwrap(), codec::VERSION_SHARE + 1);
        assert!(matches!(
            ShareToken::open(&forged, &wk),
            Err(ProtocolError::Codec(CodecError::WrongVersion { .. }))
        ));
    }

    #[test]
    fn setup_token_rejects_a_rewritten_frame_version() {
        let members = [pubid(1), pubid(2)];
        let wk = swk(1, &members);
        let tok = SetupToken::create(&seed(1), Purpose::Master, "g", &members).unwrap();
        let forged = reframe_version(&tok.encode(&wk), codec::VERSION_TOKEN + 1);
        assert!(matches!(
            SetupToken::decode(&forged, Parties::Two, &wk),
            Err(ProtocolError::Codec(CodecError::WrongVersion { .. }))
        ));
    }

    #[test]
    fn share_token_aad_and_signed_message_both_bind_the_version() {
        // The frame check above is a claim about honest input. These two are the
        // claims about an adversary: even a build that *accepted* the rewritten
        // version byte could neither decrypt nor verify the token.
        let members = [pubid(1), pubid(2)];
        let ctx = gctx("g", &members);
        let wk = [7u8; 32];
        let tok = ShareToken::create(
            &seed(1),
            &ctx,
            ShareAction::Update,
            "vpn",
            "",
            3,
            share_params("b58", None, None),
        )
        .unwrap();

        // AAD: a body sealed for the next version does not open under this one,
        // same wrap key and same routing ctx.
        let mut next_aad = SHARE_AAD_TAG.to_vec();
        next_aad.push(codec::VERSION_SHARE + 1);
        next_aad.extend_from_slice(&ctx);
        assert_ne!(next_aad, share_token_aad(&ctx));
        let sealed = crypto::seal_token(&wk, &next_aad, b"identical inner body");
        assert!(crypto::open_token(&wk, &share_token_aad(&ctx), &sealed).is_err());

        // Signed message: a signature over the body alone, without the version,
        // fails to verify, so the version is genuinely inside the signature.
        let mut unversioned = SHARE_MSG_TAG.to_vec();
        unversioned.extend_from_slice(&tok.body_prefix().unwrap());
        assert_ne!(unversioned, tok.signed_message().unwrap());
        let mut forged = tok.clone();
        forged.signature = bls_sign(&derive_sig_scalar(&seed(1)), &unversioned);
        assert_eq!(
            forged.verify(&ctx, &members),
            Err(ProtocolError::BadSignature)
        );
        assert_eq!(tok.verify(&ctx, &members).unwrap(), 0);
    }

    #[test]
    fn setup_token_aad_binds_the_version() {
        let mut next_aad = SETUP_AAD_TAG.to_vec();
        next_aad.push(codec::VERSION_TOKEN + 1);
        next_aad.push(Parties::Two.as_u8());
        assert_ne!(next_aad, setup_token_aad(Parties::Two));

        let wk = [5u8; 32];
        let sealed = crypto::seal_token(&wk, &next_aad, b"identical inner body");
        assert!(crypto::open_token(&wk, &setup_token_aad(Parties::Two), &sealed).is_err());
    }

    // The two share-token domain tags must never collide: one separates a BLS
    // signature domain, the other an AES-GCM associated-data domain.
    #[test]
    fn share_signature_and_aad_tags_are_distinct() {
        assert_ne!(SHARE_MSG_TAG, SHARE_AAD_TAG);
    }

    #[test]
    fn contact_token_rejects_wrong_subgroup_point() {
        // A correctly-framed token whose dh_g1 is the identity element (invalid
        // pubkey) must be rejected by the subgroup/identity validation.
        let public = public_identity_from_seed(&seed(1));
        let mut bytes = public.to_bytes();
        // Overwrite dh_g1 (first 48 bytes) with a compressed identity point
        use group::prime::PrimeCurveAffine;
        let ident = blstrs::G1Affine::identity().to_compressed();
        bytes[..G1_COMPRESSED].copy_from_slice(&ident);
        let mut body = vec![3, 0]; // u16_le("bob".len())
        body.extend_from_slice(b"bob");
        body.extend_from_slice(&bytes);
        let token = codec::encode(codec::TYPE_CONTACT, codec::VERSION_CONTACT, &body);
        assert!(matches!(
            decode_contact_token(&token),
            Err(ProtocolError::Crypto(_))
        ));
    }
}
