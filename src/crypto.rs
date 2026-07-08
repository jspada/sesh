//! Core cryptographic primitives over BLS12-381.
//!
//! Every derivation here is deterministic and side-effect free, so it can be
//! unit tested exhaustively; [`seal_token`] is the one exception, drawing a
//! fresh nonce from the OS. The module provides subkey derivation,
//! subgroup-checked point validation, an unbiased deterministic hash-to-scalar,
//! and the 2- and 3-party key agreements.
//!
//! An identity is a single 32-byte **seed**. From it two domain-separated
//! subkeys are derived with [`hash_to_scalar`]: the DH/Joux scalar `s_dh`
//! (public value `(s_dh * G1, s_dh * G2)`) and the BLS signing scalar `s_sig`.

use std::fmt;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use blst::min_pk::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};
use blst::BLST_ERROR;
use blstrs::{pairing, Compress, G1Affine, G2Affine, Gt, Scalar};
use ff::Field;
use group::prime::PrimeCurveAffine;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256};

/// Width, in bytes, of an identity seed
pub const SEED_BYTES: usize = 32;
/// Compressed size, in bytes, of a `G1` point
pub const G1_COMPRESSED: usize = 48;
/// Compressed size, in bytes, of a `G2` point
pub const G2_COMPRESSED: usize = 96;
/// Serialized size, in bytes, of a compressed `GT` element
pub const GT_COMPRESSED: usize = 288;

/// Domain-separation label for deriving the DH/Joux subkey `s_dh`
pub const DST_DH_SUBKEY: &[u8] = b"sesh-dh";
/// Domain-separation label for deriving the BLS signing subkey `s_sig`
pub const DST_SIG_SUBKEY: &[u8] = b"sesh-sig";
/// Domain-separation label turning a 2-party `G1` element into the output secret
pub const DST_SECRET_G1: &[u8] = b"sesh-secret-g1-v1";
/// Domain-separation label turning a 3-party `GT` element into the output secret
pub const DST_SECRET_GT: &[u8] = b"sesh-secret-gt-v1";

/// Errors from validating externally supplied points
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The point does not satisfy the curve equation
    NotOnCurve,
    /// The point is on the curve but outside the prime-order subgroup (has an
    /// `h`-torsion component)
    NotInSubgroup,
    /// The point is the identity element, which is never a valid public key
    Identity,
    /// The bytes are not a canonical compressed encoding of a curve point
    BadEncoding,
    /// A published DH pair `(P_g1, P_g2)` is inconsistent: it does not satisfy
    /// `e(P_g1, G2) == e(G1, P_g2)`
    InconsistentDhPair,
    /// A sealed token failed AEAD authentication: it is not for this recipient
    /// (wrong group / membership) or was tampered with in transit
    TokenDecrypt,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            CryptoError::NotOnCurve => "Point not on the curve",
            CryptoError::NotInSubgroup => "Point not in the prime-order subgroup",
            CryptoError::Identity => "Point is the identity element",
            CryptoError::BadEncoding => "Point is not a canonical compressed encoding",
            CryptoError::InconsistentDhPair => "DH public pair is inconsistent across G1/G2",
            CryptoError::TokenDecrypt => {
                "Token could not be decrypted (not for this group/membership, or tampered)"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CryptoError {}

/// Deterministic, unbiased hash-to-scalar ("H2S"), uniform over `[1, r)`.
///
/// SHA3-256 is applied to the length-prefixed `(dst, input, counter)` tuple; the
/// 32-byte digest is interpreted little-endian as a candidate scalar and
/// **rejected while `>= r` or `== 0`**, incrementing the counter each time. The
/// `>= r` arm (which fires for ~55% of digests, since `r ≈ 2^254.86`) removes
/// the modular bias of a naive `mod r` reduction, under which ~20% of residues
/// would take three preimages instead of two and so be 1.5x more likely.
///
/// The `== 0` arm never fires in practice (reaching it needs a zero SHA3-256
/// digest) but it makes non-zeroness a property of *this function* rather than
/// a 2^-256 bet, so no scalar derived through it can be an invalid BLS secret
/// key or yield an identity public key. That is a guarantee about the output of
/// `hash_to_scalar`, not about `Scalar` as a type: [`bls_sign`] still accepts a
/// bare scalar and would panic on zero. Both arms leave the function
/// deterministic, so all parties agree.
///
/// Used for the final secret and everywhere a hash or group element becomes a
/// scalar, including `s_dh` / `s_sig` derivation.
pub fn hash_to_scalar(dst: &[u8], input: &[u8]) -> Scalar {
    hash_to_scalar_counted(dst, input).0
}

/// As [`hash_to_scalar`], but also returns the number of rejections that
/// occurred before acceptance (exposed for testing the rejection branch).
fn hash_to_scalar_counted(dst: &[u8], input: &[u8]) -> (Scalar, u32) {
    let mut counter: u32 = 0;
    loop {
        let mut hasher = Sha3_256::new();
        hasher.update((dst.len() as u64).to_le_bytes());
        hasher.update(dst);
        hasher.update((input.len() as u64).to_le_bytes());
        hasher.update(input);
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);

        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_bytes_le(&bytes)) {
            if !bool::from(scalar.is_zero()) {
                return (scalar, counter);
            }
        }
        counter = counter
            .checked_add(1)
            .expect("hash_to_scalar exhausted its 2^32 counter space (statistically impossible)");
    }
}

/// A secret scalar that scrubs its owned value on drop.
///
/// `blstrs::Scalar` is `Copy` and defined in another crate, so it can neither
/// implement `Zeroize` directly (the orphan rule forbids it) nor have its many
/// transient copies tracked. This wrapper is **not** `Copy`; on drop it
/// volatile-overwrites the one value it owns, which narrows the window a
/// long-lived secret (an HD master, a group `K`) lingers in freed memory.
/// Zeroization here is therefore genuine but **best-effort**: copies the code
/// made in registers or on the stack are outside its reach.
///
/// `Deref<Target = Scalar>` lets it stand in for `&Scalar` at call sites.
pub struct SecretScalar(Scalar);

impl SecretScalar {
    /// Wrap a secret scalar so it is scrubbed on drop
    pub fn new(s: Scalar) -> Self {
        SecretScalar(s)
    }
    /// Borrow the inner scalar
    pub fn expose(&self) -> &Scalar {
        &self.0
    }
}

impl std::ops::Deref for SecretScalar {
    type Target = Scalar;
    fn deref(&self) -> &Scalar {
        &self.0
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        // A volatile write the optimizer may not elide, plus a fence so the
        // clobber is ordered before the memory is released.
        unsafe { std::ptr::write_volatile(&mut self.0, Scalar::from(0u64)) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Derive the DH/Joux subkey scalar `s_dh` from an identity seed
pub fn derive_dh_scalar(seed: &[u8; SEED_BYTES]) -> Scalar {
    hash_to_scalar(DST_DH_SUBKEY, seed)
}

/// Derive the BLS signing subkey scalar `s_sig` from an identity seed
pub fn derive_sig_scalar(seed: &[u8; SEED_BYTES]) -> Scalar {
    hash_to_scalar(DST_SIG_SUBKEY, seed)
}

/// Compute the `G1` public key `secret * G1`
pub fn compute_pubkey_g1(secret: &Scalar) -> G1Affine {
    G1Affine::from(G1Affine::generator() * secret)
}

/// Compute the `G2` public key `secret * G2`
pub fn compute_pubkey_g2(secret: &Scalar) -> G2Affine {
    G2Affine::from(G2Affine::generator() * secret)
}

/// Sample a uniformly random scalar in `[1, r)`.
///
/// Resamples on zero. As in [`hash_to_scalar`], that arm is unreachable in
/// practice (`~2^-255`); it is here so a generated secret is non-zero by
/// construction, never by probability.
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(&mut *rng);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Generate a raw `(secret, G1 public key)` DH keypair from the given RNG
pub fn create_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (Scalar, G1Affine) {
    let secret = random_scalar(rng);
    let pubkey = compute_pubkey_g1(&secret);
    (secret, pubkey)
}

/// Validate a `G1` public key: **on-curve AND in the prime-order subgroup AND
/// non-identity**. BLS12-381 `G1` has a cofactor != 1, so the subgroup
/// (torsion-free) check is mandatory.
pub fn validate_g1(p: &G1Affine) -> Result<(), CryptoError> {
    if !bool::from(p.is_on_curve()) {
        return Err(CryptoError::NotOnCurve);
    }
    if bool::from(p.is_identity()) {
        return Err(CryptoError::Identity);
    }
    if !bool::from(p.is_torsion_free()) {
        return Err(CryptoError::NotInSubgroup);
    }
    Ok(())
}

/// Validate a `G2` public key: **on-curve AND in the prime-order subgroup AND
/// non-identity**. BLS12-381 `G2` has a an even larger cofactor != 1 than G1,
/// so the subgroup (torsion-free) check is mandatory.
pub fn validate_g2(p: &G2Affine) -> Result<(), CryptoError> {
    if !bool::from(p.is_on_curve()) {
        return Err(CryptoError::NotOnCurve);
    }
    if bool::from(p.is_identity()) {
        return Err(CryptoError::Identity);
    }
    if !bool::from(p.is_torsion_free()) {
        return Err(CryptoError::NotInSubgroup);
    }
    Ok(())
}

/// Deserialize and fully validate a compressed `G1` public key.
///
/// Uses the unchecked decoder (canonical + on-curve only) and then routes the
/// point through [`validate_g1`], so the subgroup and non-identity checks are
/// always applied to every point read from the CLI or keystore.
pub fn read_g1(bytes: &[u8; G1_COMPRESSED]) -> Result<G1Affine, CryptoError> {
    let p = Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(bytes))
        .ok_or(CryptoError::BadEncoding)?;
    validate_g1(&p)?;
    Ok(p)
}

/// Deserialize and fully validate a compressed `G2` public key
pub fn read_g2(bytes: &[u8; G2_COMPRESSED]) -> Result<G2Affine, CryptoError> {
    let p = Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(bytes))
        .ok_or(CryptoError::BadEncoding)?;
    validate_g2(&p)?;
    Ok(p)
}

/// A party's published DH/Joux public value: the pair `(s_dh * G1, s_dh * G2)`.
///
/// The `G2` half is only needed for the 3-party (Joux) pairing; a 2-party ECDH
/// exchange uses `g1` alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhPublic {
    /// `s_dh * G1` (48 bytes compressed)
    pub g1: G1Affine,
    /// `s_dh * G2` (96 bytes compressed)
    pub g2: G2Affine,
}

impl DhPublic {
    /// Build the DH public pair from a DH scalar `s_dh`
    pub fn from_scalar(s_dh: &Scalar) -> Self {
        DhPublic {
            g1: compute_pubkey_g1(s_dh),
            g2: compute_pubkey_g2(s_dh),
        }
    }

    /// Compressed serialization: `(g1 ‖ 48B, g2 ‖ 96B)`
    pub fn to_bytes(&self) -> ([u8; G1_COMPRESSED], [u8; G2_COMPRESSED]) {
        (self.g1.to_compressed(), self.g2.to_compressed())
    }

    /// Deserialize and fully validate a DH public pair: each half on-curve, in
    /// the prime-order subgroup and non-identity, **and** the two halves sharing
    /// one discrete log (see [`check_consistency`][Self::check_consistency]).
    ///
    /// The pair check is what makes the symmetry [`group_element_3`] relies on
    /// hold, so it belongs at the trust boundary rather than at the call sites.
    ///
    /// It costs two pairings: ~1.7ms against ~170µs for the point decoding
    /// alone, a 10x increase on this call, paid once per identity imported *and*
    /// once per row of `contact list` / `keypair list`.
    ///
    /// Where it earns that: `decode_contact_token`, the wire boundary, where a
    /// peer chooses the bytes. Where it does not: reloading the local keystore,
    /// whose records are plaintext and unauthenticated anyway. Anyone able to
    /// write an inconsistent pair there could just as well write a *consistent*
    /// pair for a key they control. On that path this is a check against
    /// corruption, not against an adversary. Kept on both because the cost is
    /// bounded and one entry point is easier to reason about than two.
    pub fn from_bytes(
        g1: &[u8; G1_COMPRESSED],
        g2: &[u8; G2_COMPRESSED],
    ) -> Result<Self, CryptoError> {
        let dh = DhPublic {
            g1: read_g1(g1)?,
            g2: read_g2(g2)?,
        };
        dh.check_consistency()?;
        Ok(dh)
    }

    /// Check that both halves share the same discrete log:
    /// `e(g1, G2) == e(G1, g2)`.
    ///
    /// A pair with `g1 = x * G1` and `g2 = y * G2`, `x != y`, cannot force false
    /// agreement. Whoever published it knows both `x` and `y`, so it learns
    /// nothing an honest pair would not give it. What it *can* do is break the
    /// symmetry of [`group_element_3`], whose result is independent of which
    /// peer supplies which half only when every pair is consistent. Two honest
    /// members would then derive different secrets and fail to open each other's
    /// tokens.
    ///
    /// Called from [`from_bytes`][Self::from_bytes] and hence
    /// [`PublicIdentity::from_bytes`], so every identity parsed from bytes is
    /// checked. A peer's per-group child pair takes a different route-- it is
    /// built from points decoded individually, and checked in
    /// `SetupToken::verify`, not at decode. Every `derive_group_key` call site
    /// verifies before deriving, which is what closes that path.
    pub fn check_consistency(&self) -> Result<(), CryptoError> {
        // TODO: maybe could optimize with a cheaper batched formulation
        //       like multi-pairing of e(g1, G2) * e(-G1, g2) == 1
        let lhs = pairing(&self.g1, &G2Affine::generator());
        let rhs = pairing(&G1Affine::generator(), &self.g2);
        if lhs == rhs {
            Ok(())
        } else {
            Err(CryptoError::InconsistentDhPair)
        }
    }
}

/// The public half of an identity: the DH pair `(s_dh * G1, s_dh * G2)` plus the
/// BLS signing public key `s_sig * G1`. This whole object is what peers pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    /// DH/Joux public pair
    pub dh: DhPublic,
    /// BLS signing public key `s_sig * G1` (minimal-pubkey-size)
    pub sig_g1: G1Affine,
}

impl PublicIdentity {
    /// Deserialize and fully validate a public identity: the DH pair through
    /// [`DhPublic::from_bytes`] (both halves valid *and* mutually consistent)
    /// and the signing key through [`read_g1`].
    ///
    /// Every untrusted identity (e.g. a contact token off the wire, a record read
    /// back from the keystore) is expected to enter through here. That is a
    /// **convention, not an invariant**: the fields of `PublicIdentity` and
    /// [`DhPublic`] are public, so a caller can assemble one by struct literal
    /// and skip every check. [`SetupToken`][crate::protocol::SetupToken]
    /// legitimately does, then validates by hand. Making the checks unskippable
    /// needs a validated newtype with private fields; until then this is a
    /// convention `grep` enforces, not the type system.
    pub fn from_bytes(
        g1: &[u8; G1_COMPRESSED],
        g2: &[u8; G2_COMPRESSED],
        sig_g1: &[u8; G1_COMPRESSED],
    ) -> Result<Self, CryptoError> {
        Ok(PublicIdentity {
            dh: DhPublic::from_bytes(g1, g2)?,
            sig_g1: read_g1(sig_g1)?,
        })
    }

    /// Canonical serialization: `dh.g1 ‖ dh.g2 ‖ sig_g1` (48 + 96 + 48 bytes).
    /// This 192-byte encoding is what a contact pins and what feeds `group_ctx`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 * G1_COMPRESSED + G2_COMPRESSED);
        v.extend_from_slice(&self.dh.g1.to_compressed());
        v.extend_from_slice(&self.dh.g2.to_compressed());
        v.extend_from_slice(&self.sig_g1.to_compressed());
        v
    }
}

/// Derive the full public identity (DH pair + signing pubkey) from a seed
pub fn public_identity_from_seed(seed: &[u8; SEED_BYTES]) -> PublicIdentity {
    let s_dh = derive_dh_scalar(seed);
    let s_sig = derive_sig_scalar(seed);
    PublicIdentity {
        dh: DhPublic::from_scalar(&s_dh),
        sig_g1: compute_pubkey_g1(&s_sig),
    }
}

/// Raw 2-party ECDH group element in `G1`: `K = a * B = ab * G1`
pub fn dh_g1(a_secret: &Scalar, b_pubkey: &G1Affine) -> G1Affine {
    // Scalar multiplication is done in projective coordinates to avoid
    // a field inversion at every intermediate addition.
    G1Affine::from(b_pubkey * a_secret)
}

/// 2-party output secret: `H2S(ab * G1)`
pub fn shared_secret_2(a_secret: &Scalar, b_pub_g1: &G1Affine) -> Scalar {
    // k = a*B
    let k = dh_g1(a_secret, b_pub_g1);
    hash_to_scalar(DST_SECRET_G1, &k.to_compressed())
}

/// Raw 3-party Joux group element `e(G1,G2)^{abc} ∈ GT`.
///
/// From *my* DH scalar and the two other parties' DH public pairs. Uses one
/// peer's `G1` half and the other peer's `G2` half; because the result is the
/// fully symmetric `e(G1,G2)^{abc}`, the choice of which peer supplies which
/// half (and the order of the two peers) does not matter.
pub fn group_element_3(my_secret: &Scalar, peer_a: &DhPublic, peer_b: &DhPublic) -> Gt {
    // e(peer_a * g1, peer_b * g2)^a = e(b * G1, c * G2)^a = e(G1, G2)^{bca} = e(G1,G2)^{abc}
    // Assumes each published pair shares one discrete log (verified by check_consistency
    pairing(&peer_a.g1, &peer_b.g2) * *my_secret
}

/// 3-party Joux output secret: `H2S(e(G1,G2)^{abc})`
pub fn group_secret_3(my_secret: &Scalar, peer_a: &DhPublic, peer_b: &DhPublic) -> Scalar {
    let gt = group_element_3(my_secret, peer_a, peer_b);
    hash_to_scalar(DST_SECRET_GT, &gt_to_bytes(&gt))
}

/// Domain-separation label for hierarchical-deterministic child derivation
pub const DST_HD: &[u8] = b"sesh-hd-v1";

/// Domain-separation label for per-group child-key derivation.
///
/// **Distinct** from [`DST_HD`], so a per-group child (see [`group_child`]) can
/// never collide with an `hd-secret` child even under the same master.
pub const DST_GROUP_CHILD: &[u8] = b"sesh-group-child-v1";

/// Derive an independent HD child scalar from a master secret and a byte context.
///
/// The master is a fixed 32-byte scalar (an identity's `s_dh`, or a group `K`),
/// so `master.to_bytes_le() ‖ context` is unambiguous (the master is fixed
/// width). Callers pass an already-canonicalized context (e.g.
/// `canonical(id, user, epoch)`). Uses the same unbiased [`hash_to_scalar`];
/// never the legacy top-bit truncation.
pub fn hd_child(master: &Scalar, context: &[u8]) -> Scalar {
    let mut input = Vec::with_capacity(32 + context.len());
    input.extend_from_slice(&master.to_bytes_le());
    input.extend_from_slice(context);
    hash_to_scalar(DST_HD, &input)
}

/// Canonical byte context for an hd-secret child: `(id, user, epoch)`.
///
/// `id` and `user` are `u64_le` length-prefixed (so `("a","bc")` and `("ab","c")`
/// never collide) and `epoch` is appended as `u64_le`. This is what
/// [`hd_child`] consumes; formatting params never enter the derivation.
pub fn canonical_hd_context(id: &str, user: &str, epoch: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + id.len() + 8 + user.len() + 8);
    v.extend_from_slice(&(id.len() as u64).to_le_bytes());
    v.extend_from_slice(id.as_bytes());
    v.extend_from_slice(&(user.len() as u64).to_le_bytes());
    v.extend_from_slice(user.as_bytes());
    v.extend_from_slice(&epoch.to_le_bytes());
    v
}

/// Derive a per-group **child DH scalar** from a DH master `s_dh` and the
/// 32-byte group context.
///
/// `group_child(s_dh, group_ctx) = H2S("sesh-group-child-v1", s_dh ‖ group_ctx)`.
/// Deterministic, hence fully re-derivable from `seed + public state` (there is
/// no forward secrecy, intended). Because [`DST_GROUP_CHILD`] differs from
/// [`DST_HD`], the per-group child is key-separated from any `hd-secret` child.
pub fn group_child(s_dh: &Scalar, group_ctx: &[u8; 32]) -> Scalar {
    let mut input = Vec::with_capacity(32 + group_ctx.len());
    input.extend_from_slice(&s_dh.to_bytes_le());
    input.extend_from_slice(group_ctx);
    hash_to_scalar(DST_GROUP_CHILD, &input)
}

// --------------------------------------
// BLS signatures (Tier 2 authentication)
// --------------------------------------

/// Fixed IETF signature ciphersuite / domain separation tag (min-pubkey-size:
/// public keys in `G1`, signatures in `G2`).
///
/// `draft-irtf-cfrg-bls-signature-04` builds a ciphersuite ID as
/// `"BLS_SIG_" ‖ H2C_SUITE_ID ‖ SC_TAG ‖ "_"` and recommends using it verbatim
/// as the hash-to-curve DST. `SC_TAG` names the scheme: `NUL` for basic, `AUG`
/// for message-augmentation, `POP` for proof-of-possession. Ours is `NUL` and
/// [`bls_verify`] checks one signature against one signer, so neither the
/// rogue-key protection of `POP` nor the augmentation of `AUG` buys anything.
///
/// This literal is frozen. It is not a `sesh-*` tag, so `tests/domain_tags.rs`
/// does not cover it, but it obeys the same rule: it is baked into every
/// signature ever issued, including the peer setup tokens the keystore persists
/// and re-verifies on load. Editing it invalidates all of them, and the failure
/// surfaces as `BadSignature` that are indistinguishable from tampering. Change
/// it only behind a token/state version bump, and re-pin the vector in
/// `bls_signature_matches_its_pinned_vector`.
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Size, in bytes, of a compressed BLS signature (a `G2` point)
pub const BLS_SIG_BYTES: usize = 96;

/// BLS-sign `msg` under the signing subkey scalar `s_sig`
pub fn bls_sign(s_sig: &Scalar, msg: &[u8]) -> [u8; BLS_SIG_BYTES] {
    // blst rejects a zero secret key, so this would panic on `s_sig == 0`. Every
    // scalar in this crate reaches here from `hash_to_scalar`, which never
    // returns zero, but that is a property of the callers not of `&Scalar`, so
    // state it where a new caller will trip over it.
    debug_assert!(
        !bool::from(s_sig.is_zero()),
        "bls_sign was handed a zero scalar: not a valid BLS secret key"
    );
    let sk = BlsSecretKey::from_bytes(&s_sig.to_bytes_be())
        .expect("s_sig is a valid non-zero scalar < r");
    sk.sign(msg, BLS_DST, &[]).to_bytes()
}

/// Verify a BLS signature on `msg` against the signing public key `sig_g1`.
///
/// Verification is per-signer (no aggregation), so no proof-of-possession is
/// needed. Returns `false` on any decoding or verification failure.
pub fn bls_verify(sig_g1: &G1Affine, msg: &[u8], signature: &[u8; BLS_SIG_BYTES]) -> bool {
    let pk = match BlsPublicKey::from_bytes(&sig_g1.to_compressed()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match BlsSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig.verify(true, msg, BLS_DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
}

/// Number of bytes in the agreement checksum
pub const CHECKSUM_BYTES: usize = 16;

/// The 16-byte agreement checksum confirming that parties derived the same
/// secret. It is *agreement confirmation*, not authentication.
pub fn agreement_checksum(secret: &Scalar) -> String {
    let mut h = Sha3_256::new();
    h.update(b"sesh-agreement-checksum-v1");
    h.update(secret.to_bytes_le());
    bs58::encode(&h.finalize()[..CHECKSUM_BYTES]).into_string()
}

/// Number of digest bytes in a short fingerprint (≈ 11 base58 characters)
pub const FINGERPRINT_BYTES: usize = 8;

/// Domain-separation label for identity fingerprints
pub const DST_FPR_IDENTITY: &[u8] = b"sesh-fpr-identity-v1";

/// Domain-separation label for group fingerprints
pub const DST_FPR_GROUP: &[u8] = b"sesh-fpr-group-v1";

/// A short base58 fingerprint of `parts` under the given domain tag, truncated
/// to `bytes` of digest:
/// `b58(SHA3-256(u64_le(|dst|) ‖ dst ‖ (u64_le(|p|) ‖ p for p in parts))[..bytes])`.
///
/// Every part is length-prefixed, so the boundary between two of them cannot be
/// slid: `["ab"]`, `["a", "b"]` and `["ab", ""]` all hash differently.
///
/// The parts are hashed as they stream by rather than concatenated into a
/// buffer, so a secret part (an HD child scalar) never gets a second heap copy.
fn fingerprint_parts(dst: &[u8], parts: &[&[u8]], bytes: usize) -> String {
    let mut h = Sha3_256::new();
    h.update((dst.len() as u64).to_le_bytes());
    h.update(dst);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    bs58::encode(&h.finalize()[..bytes]).into_string()
}

/// A short base58 fingerprint of `input` under the given domain tag:
/// `b58(SHA3-256(u64_le(|dst|) ‖ dst ‖ u64_le(|input|) ‖ input)[..8])`.
///
/// This is a **recognition aid only**. 8 bytes is far too short to be a security
/// boundary (the pinned contact token remains the ground truth); it exists so
/// a human can spot at a glance that two listings refer to the same identity
/// or group. Computed on the fly; never stored.
pub fn fingerprint(dst: &[u8], input: &[u8]) -> String {
    fingerprint_parts(dst, &[input], FINGERPRINT_BYTES)
}

/// The short fingerprint of a public identity, over its canonical 192-byte
/// encoding, so your `keypair show` fingerprint equals what peers see in
/// `contact show` for you.
pub fn identity_fingerprint(public: &PublicIdentity) -> String {
    fingerprint(DST_FPR_IDENTITY, &public.to_bytes())
}

/// Domain-separation label for the secret half of an HD fingerprint
pub const DST_FPR_HD: &[u8] = b"sesh-fpr-hd-v1";

/// Domain-separation label for the recipe half of an HD fingerprint
pub const DST_FPR_HD_RECIPE: &[u8] = b"sesh-fpr-hd-recipe-v1";

/// Number of digest bytes in the recipe half of an HD fingerprint (5-6 base58
/// characters).
///
/// Shorter than [`FINGERPRINT_BYTES`] because the secret half already pins the
/// entry: the recipe half only has to separate the handful of recipes a group
/// could plausibly disagree about. It is **not** sized against a search. Whoever
/// authors a share token chooses `params`, where `suffix` is a free-form string, so
/// they can grind it for a 4-byte collision cheaply. That buys nothing: `apply`
/// prints a lossless [`describe`][crate::registry::Params::describe] diff of the
/// incoming params and prompts before adopting, and the recipe, not this digest,
/// is what a reader checks. The same caveat as every other fingerprint here-— a
/// recognition aid, never a gate.
pub const HD_RECIPE_FINGERPRINT_BYTES: usize = 4;

/// The short fingerprint of a derived HD child secret **as a given recipe
/// renders it**: `<recipe>-<secret>`, e.g. `8pKx-6mNX4zND3Qp`.
///
/// Two halves, because there are two things to agree on and they fail
/// separately:
///
/// * The **secret** half, `b58(H(child)[..8])`, covers the raw child scalar
///   alone. Params never enter the derivation, so every view (hex/b58/trimmed)
///   of the same `(master, id, user, epoch)` shares it.
/// * The **recipe** half, `b58(H(canonical(params) ‖ child)[..4])`, additionally
///   covers the formatting. It moves when the rendered password moves.
///
/// So a mismatch says *which* thing diverged: differing secret halves mean
/// different `(master, id, user, epoch)`; matching secret halves under differing
/// recipe halves mean one derived secret formatted two ways; the exact failure
/// a params-blind fingerprint used to wave through, where two members hold
/// different passwords and see the same digest.
///
/// The recipe half binds `child` as well as `params`, deliberately. A digest of
/// `params` alone would be a global constant; nearly every definition shares a
/// recipe, so the column would repeat, and one ground collision would serve
/// every entry in every group.
///
/// Neither half hashes the *rendered* password. That would be an unsalted,
/// unstretched password hash: against `--mode b10 --length 8` a printed digest
/// would put the secret inside a 10⁸ search. Both halves commit to the child
/// scalar instead, whose entropy is full regardless of how short the password
/// it renders to is, whilst still agreeing exactly when the rendered passwords
/// agree (since formatting is deterministic). Like the agreement checksum, this
/// identifies a secret without revealing it.
///
/// `params` is [`Params::canonical_bytes`][crate::registry::Params::canonical_bytes];
/// it is length-prefixed against `child` so the boundary cannot be slid.
/// Computed on the fly; never stored.
pub fn hd_fingerprint(params: &[u8], child: &Scalar) -> String {
    let child = child.to_bytes_le();
    let recipe = fingerprint_parts(
        DST_FPR_HD_RECIPE,
        &[params, &child],
        HD_RECIPE_FINGERPRINT_BYTES,
    );
    let secret = fingerprint_parts(DST_FPR_HD, &[&child], FINGERPRINT_BYTES);
    format!("{recipe}-{secret}")
}

/// Canonical, deterministic serialization of a `GT` element (288 bytes)
pub(crate) fn gt_to_bytes(gt: &Gt) -> [u8; GT_COMPRESSED] {
    let mut buf = [0u8; GT_COMPRESSED];
    (*gt)
        .write_compressed(buf.as_mut_slice())
        .expect("GT compression into a fixed-size buffer is infallible");
    buf
}

// -------------------------------------------------------------
// Token confidentiality: AEAD sealing + key-agreement wrap keys
// -------------------------------------------------------------

/// Nonce width for a sealed token (AES-256-GCM)
pub const TOKEN_NONCE_LEN: usize = 12;

/// Domain tag deriving the **share-token** wrap key from a group secret `K`
pub const DST_SHARE_WRAP: &[u8] = b"sesh-share-wrap-v1";
/// Domain tag deriving the **setup-token** wrap key from the long-term
/// multiparty DH/Joux value over the members' pinned identities.
pub const DST_SETUP_WRAP: &[u8] = b"sesh-setup-wrap-v1";

/// Seal a token body under a 32-byte symmetric key: returns
/// `nonce(12) ‖ AES-256-GCM(key, nonce, plaintext, aad)`. A fresh random nonce
/// is drawn per call, so identical plaintexts do not produce identical output.
pub fn seal_token(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key is valid");
    let mut nonce = [0u8; TOKEN_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM sealing is infallible for a valid key");
    let mut out = Vec::with_capacity(TOKEN_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a token body sealed by [`seal_token`]. Fails with
/// [`CryptoError::TokenDecrypt`] on any authentication failure (wrong key or
/// tamper). The caller cannot distinguish the two, by design.
pub fn open_token(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < TOKEN_NONCE_LEN {
        return Err(CryptoError::TokenDecrypt);
    }
    let (nonce, ct) = sealed.split_at(TOKEN_NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key is valid");
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::TokenDecrypt)
}

/// The **share-token** wrap key: `SHA3-256(DST_SHARE_WRAP ‖ K_le)`. Every group
/// member holds `K`, so every member (and no eavesdropper) can open the token.
pub fn share_wrap_key(k: &Scalar) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_SHARE_WRAP);
    h.update(k.to_bytes_le());
    let mut key = [0u8; 32];
    key.copy_from_slice(&h.finalize());
    key
}

/// The **setup-token** wrap key, from *my* long-term DH scalar and the other
/// members' long-term DH public pairs, the static multiparty DH/Joux value:
///
/// - 1 other  -> `s_dh_me * s_dh_other * G1` (a `G1` point);
/// - 2 others -> `e(G1,G2)^{s_dh_me * s_dh_a * s_dh_b}` (a `GT` element).
///
/// Because that value is symmetric, **every** member derives the same key from
/// the other members' pinned public keys plus their own long-term secret, while
/// an eavesdropper with no long-term secret cannot. `member_ids` (the sorted,
/// concatenated 192-byte identities) is bound in so the key is membership-exact.
pub fn setup_wrap_key(
    my_s_dh: &Scalar,
    others: &[DhPublic],
    member_ids: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let material: Vec<u8> = match others {
        [only] => dh_g1(my_s_dh, &only.g1).to_compressed().to_vec(),
        [a, b] => gt_to_bytes(&group_element_3(my_s_dh, a, b)).to_vec(),
        _ => return Err(CryptoError::BadEncoding),
    };
    let mut h = Sha3_256::new();
    h.update(DST_SETUP_WRAP); // fixed at compile time
    h.update((material.len() as u64).to_le_bytes());
    h.update(&material);
    h.update(member_ids); // final field (otherwise needs length prefix)
    let mut key = [0u8; 32];
    key.copy_from_slice(&h.finalize());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::G1Projective;
    use rand::rngs::OsRng;

    // A fixed, non-zero seed for deterministic derivations
    fn seed(byte: u8) -> [u8; SEED_BYTES] {
        [byte; SEED_BYTES]
    }

    // `derive_sig_scalar(seed(42))`, big-endian, the secret key blst signs
    // with in `bls_signature_matches_its_pinned_vector`.
    //
    // Recomputed from the written spec of [`hash_to_scalar`] (SHA3-256 over the
    // length-prefixed `(dst, input, counter)` tuple read little-endian,
    // rejecting on `>= r` or `== 0`) using nothing but `hashlib`. It accepts on
    // the first counter.
    const SIG_SCALAR_SEED42_BE: &str =
        "4a342891fd2f79546354aa662d9a544ee9c85628f9b244b13aae5ed942465ac3";

    // `bls_sign(derive_sig_scalar(seed(42)), b"sesh-bls-dst-test-vector")`
    // under [`BLS_DST`].
    //
    // A **cross-implementation conformance vector**, not merely a regression
    // pin: `scripts/verify_bls_vector.py` reproduces these exact bytes with
    // `py_ecc`'s `G2Basic` (an unrelated pure-Python BLS whose ciphersuite is
    // the same minimal-pubkey-size basic scheme) and confirms py_ecc verifies
    // the signature this crate produces. The script also runs the negative
    // control that matters: signing under the pre-`NUL` DST yields *different*
    // bytes, so this vector genuinely binds [`BLS_DST`] rather than passing
    // whatever the signer happens to do.
    //
    // Re-run that script if the vector ever changes. It is not part of `cargo
    // test` because it needs a Python venv and a network install.
    //
    // Together with `bls_dst_is_the_pinned_ciphersuite` (which checks
    // [`BLS_DST`] against the literal `draft-irtf-cfrg-bls-signature-04` names)
    // the two tests say: the DST is the one the spec names, and it is the one
    // the signer actually uses.
    const BLS_PINNED_SIG: &str = "b218215615e4af6bf4207deb95170edbf9a5284952e9a6f38396af84a262d7d0197d2560389ad8dbf47a24a338ff17f403caec1eb41f492ade88c6c302010dbfa4e45d0bd31dd905342abcf38ac9a0fc7e16dd203566f8a72365aa449fd6f245";

    // Construct an on-curve G1 point that is (almost surely) outside the
    // prime-order subgroup, i.e. has an h-torsion component. blstrs does not
    // expose its base field publicly, so we build the coordinates with the
    // low-level blst field API and go through the standard compressed encoding.
    fn torsion_g1() -> G1Affine {
        use blst::{
            blst_fp, blst_fp_add, blst_fp_from_uint64, blst_fp_mul, blst_fp_sqr, blst_fp_sqrt,
            blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_in_g1, blst_p1_affine_on_curve,
        };
        unsafe {
            let mut four = blst_fp::default();
            blst_fp_from_uint64(&mut four, [4, 0, 0, 0, 0, 0].as_ptr());
            let mut i: u64 = 1;
            loop {
                let mut x = blst_fp::default();
                blst_fp_from_uint64(&mut x, [i, 0, 0, 0, 0, 0].as_ptr());
                let (mut x2, mut x3, mut rhs, mut y) = Default::default();
                blst_fp_sqr(&mut x2, &x);
                blst_fp_mul(&mut x3, &x2, &x);
                blst_fp_add(&mut rhs, &x3, &four); // y^2 = x^3 + 4
                if blst_fp_sqrt(&mut y, &rhs) {
                    let p = blst_p1_affine { x, y };
                    if blst_p1_affine_on_curve(&p) && !blst_p1_affine_in_g1(&p) {
                        let mut out = [0u8; G1_COMPRESSED];
                        blst_p1_affine_compress(out.as_mut_ptr(), &p);
                        return Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&out))
                            .unwrap();
                    }
                }
                i += 1;
            }
        }
    }

    // Construct an on-curve G2 point outside the prime-order subgroup
    fn torsion_g2() -> G2Affine {
        use blst::{
            blst_fp, blst_fp2, blst_fp2_add, blst_fp2_mul, blst_fp2_sqr, blst_fp2_sqrt,
            blst_fp_from_uint64, blst_p2_affine, blst_p2_affine_compress, blst_p2_affine_in_g2,
            blst_p2_affine_on_curve,
        };
        unsafe {
            let mut fp4 = blst_fp::default();
            blst_fp_from_uint64(&mut fp4, [4, 0, 0, 0, 0, 0].as_ptr());
            let b2 = blst_fp2 { fp: [fp4, fp4] }; // 4 * (1 + u)
            let mut i: u64 = 1;
            loop {
                let mut xi = blst_fp::default();
                blst_fp_from_uint64(&mut xi, [i, 0, 0, 0, 0, 0].as_ptr());
                let x = blst_fp2 {
                    fp: [xi, blst_fp::default()],
                };
                let (mut x2, mut x3, mut rhs, mut y) = Default::default();
                blst_fp2_sqr(&mut x2, &x);
                blst_fp2_mul(&mut x3, &x2, &x);
                blst_fp2_add(&mut rhs, &x3, &b2);
                if blst_fp2_sqrt(&mut y, &rhs) {
                    let p = blst_p2_affine { x, y };
                    if blst_p2_affine_on_curve(&p) && !blst_p2_affine_in_g2(&p) {
                        let mut out = [0u8; G2_COMPRESSED];
                        blst_p2_affine_compress(out.as_mut_ptr(), &p);
                        return Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&out))
                            .unwrap();
                    }
                }
                i += 1;
            }
        }
    }

    #[test]
    fn secret_scalar_derefs_and_exposes_the_inner_value() {
        let s = derive_dh_scalar(&seed(5));
        let wrapped = SecretScalar::new(s);
        // Deref and expose both yield the original scalar (usable as &Scalar)
        assert_eq!(*wrapped.expose(), s);
        assert_eq!(compute_pubkey_g1(&wrapped), compute_pubkey_g1(&s));
        // Dropping runs the scrubbing Drop without panicking
        drop(wrapped);
    }

    #[test]
    fn h2s_is_deterministic_and_in_field() {
        // Same (dst, input) -> same scalar; different dst -> different scalar
        let a = hash_to_scalar(b"dst", b"hello");
        let b = hash_to_scalar(b"dst", b"hello");
        let c = hash_to_scalar(b"other", b"hello");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Re-encoding the result is canonical (i.e. it really is `< r`)
        assert!(bool::from(
            Scalar::from_bytes_le(&a.to_bytes_le()).is_some()
        ));
    }

    #[test]
    fn h2s_domain_separation_is_length_prefixed() {
        // Without length-prefixing, ("ab","c") and ("a","bc") would collide
        let x = hash_to_scalar(b"ab", b"c");
        let y = hash_to_scalar(b"a", b"bc");
        assert_ne!(x, y);
    }

    #[test]
    fn h2s_rejection_branch_is_exercised() {
        // ~55% of SHA3 outputs exceed r, so scanning a handful of inputs must
        // hit the reject-and-increment path at least once.
        let max_rejections = (0u8..64)
            .map(|i| hash_to_scalar_counted(b"reject", &[i]).1)
            .max()
            .unwrap();
        assert!(
            max_rejections >= 1,
            "expected at least one rejection across 64 inputs"
        );
    }

    #[test]
    fn subkey_derivation_is_separated_and_stable() {
        let s = seed(7);
        let dh = derive_dh_scalar(&s);
        let sig = derive_sig_scalar(&s);
        assert_ne!(dh, sig, "s_dh and s_sig must not collide");
        assert_eq!(dh, derive_dh_scalar(&s), "derivation must be deterministic");
    }

    #[test]
    fn validate_accepts_valid_keys() {
        let s = derive_dh_scalar(&seed(1));
        assert!(validate_g1(&compute_pubkey_g1(&s)).is_ok());
        assert!(validate_g2(&compute_pubkey_g2(&s)).is_ok());
    }

    #[test]
    fn validate_rejects_identity() {
        assert_eq!(
            validate_g1(&G1Affine::identity()),
            Err(CryptoError::Identity)
        );
        assert_eq!(
            validate_g2(&G2Affine::identity()),
            Err(CryptoError::Identity)
        );
    }

    #[test]
    fn validate_rejects_wrong_subgroup() {
        assert_eq!(validate_g1(&torsion_g1()), Err(CryptoError::NotInSubgroup));
        assert_eq!(validate_g2(&torsion_g2()), Err(CryptoError::NotInSubgroup));
    }

    // An inconsistent pair is rejected at the trust boundary, not merely
    // detectable by a caller who remembers to ask. Each half is individually
    // valid (on-curve, in-subgroup, non-identity) so only the pairing check
    // catches it.
    #[test]
    fn from_bytes_rejects_an_inconsistent_dh_pair() {
        let g1 = compute_pubkey_g1(&derive_dh_scalar(&seed(3))).to_compressed();
        let g2 = compute_pubkey_g2(&derive_dh_scalar(&seed(4))).to_compressed();
        assert!(read_g1(&g1).is_ok());
        assert!(read_g2(&g2).is_ok());
        assert_eq!(
            DhPublic::from_bytes(&g1, &g2),
            Err(CryptoError::InconsistentDhPair)
        );

        // ...and PublicIdentity::from_bytes inherits the check, so no untrusted
        // identity reaches a pairing with a mismatched pair.
        let sig = compute_pubkey_g1(&derive_sig_scalar(&seed(3))).to_compressed();
        assert_eq!(
            PublicIdentity::from_bytes(&g1, &g2, &sig),
            Err(CryptoError::InconsistentDhPair)
        );

        // A consistent pair still round-trips
        let good = DhPublic::from_scalar(&derive_dh_scalar(&seed(3)));
        let (g1, g2) = good.to_bytes();
        assert_eq!(DhPublic::from_bytes(&g1, &g2), Ok(good));
    }

    #[test]
    fn read_g1_rejects_torsion_point_roundtrip() {
        // A torsion point serializes fine but must be rejected on read
        let bytes = torsion_g1().to_compressed();
        assert_eq!(read_g1(&bytes), Err(CryptoError::NotInSubgroup));
    }

    // Derived scalars land in `[1, r)`.
    //
    // **This test cannot fail whether or not the zero arms exist**-- no real
    // input reaches them. It documents the property callers lean on; it does
    // not exercise the code that establishes it. `random_scalar_resamples_zero`
    // does that for the RNG path. The `hash_to_scalar` zero arm stays uncovered
    // on purpose: reaching it needs a SHA3-256 preimage of the zero digest, and
    // injecting a fake digest to fake it would test the injection, not the
    // function.
    #[test]
    fn derived_scalars_are_never_zero() {
        for i in 0u8..64 {
            assert!(!bool::from(hash_to_scalar(b"nonzero", &[i]).is_zero()));
            assert!(!bool::from(derive_dh_scalar(&seed(i)).is_zero()));
            assert!(!bool::from(derive_sig_scalar(&seed(i)).is_zero()));
        }
        let mut rng = OsRng;
        for _ in 0..64 {
            assert!(!bool::from(random_scalar(&mut rng).is_zero()));
        }
    }

    // An RNG whose first four `u64`s are zero, and which then defers to the OS.
    //
    // `blstrs`' `Scalar::random` draws four `u64`s and accepts the result when
    // it is a canonical field element. All-zero is canonical, so this drives
    // the first draw to `Scalar::ZERO` (the branch `random_scalar` must
    // resample past) and lets the second draw succeed normally rather than
    // spinning against a fixed value.
    struct ZeroThenOs {
        drawn: u32,
    }

    impl RngCore for ZeroThenOs {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.drawn += 1;
            if self.drawn <= 4 {
                0
            } else {
                OsRng.next_u64()
            }
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                *b = self.next_u64() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ZeroThenOs {}

    // The resample loop in `random_scalar` actually runs, and actually returns
    // a non-zero scalar when the RNG hands it a zero. Without the loop this
    // test returns `Scalar::ZERO` and fails.
    #[test]
    fn random_scalar_resamples_zero() {
        let mut rng = ZeroThenOs { drawn: 0 };

        // Sanity: the rigged RNG really does drive blstrs to zero on draw one,
        // so the assertion below is testing the loop and not a lucky sample.
        let mut probe = ZeroThenOs { drawn: 0 };
        assert!(bool::from(Scalar::random(&mut probe).is_zero()));

        let s = random_scalar(&mut rng);
        assert!(!bool::from(s.is_zero()));
        assert!(rng.drawn > 4, "expected a second draw after the zero");
    }

    // A zero scalar is not a valid BLS secret key, and `bls_sign` takes a bare
    // `&Scalar`, so the guard has to live inside it. This panics through
    // `debug_assert!` in debug builds and through blst's own rejection of a
    // zero secret key in release; the substring below matches both messages.
    // The type system prevents neither, which is exactly why the guard is there.
    #[test]
    #[should_panic(expected = "zero scalar")]
    fn bls_sign_rejects_a_zero_scalar() {
        bls_sign(&Scalar::from(0u64), b"msg");
    }

    // The ciphersuite ID from `draft-irtf-cfrg-bls-signature-04` for
    // minimal-pubkey-size, basic scheme (`SC_TAG = NUL`).
    //
    // Corroborated three ways: the draft's own construction
    // (`"BLS_SIG_" ‖ H2C_SUITE_ID ‖ SC_TAG ‖ "_"`); blst's `min_pk` example and
    // its `sig_variant_impl!("MinPk", ... blst_core_verify_pk_in_g1 ...)`, which is
    // what fixes signatures to `G2` and hence `H2C_SUITE_ID = BLS12381G2`; and
    // `py_ecc.bls.G2Basic.DST`, checked by `scripts/verify_bls_vector.py`.
    #[test]
    fn bls_dst_is_the_pinned_ciphersuite() {
        assert_eq!(BLS_DST, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");
    }

    // BLS signing is deterministic (hash the message to `G2`, multiply by the
    // secret), so a signature is a stable vector over `(BLS_DST, s_sig, msg)`.
    //
    // This pins `BLS_DST` the way `fingerprint_matches_its_pinned_vector` pins
    // the fingerprint domains. Editing the DST does not fail loudly on its own.
    // Instead it silently invalidates every signature already written to a
    // keystore, which then reports `BadSignature` as though a peer had tampered.
    // This test is what turns that into a compile-time-visible decision.
    //
    // The vector itself is cross-checked against `py_ecc`; see [`BLS_PINNED_SIG`]
    // and `scripts/verify_bls_vector.py`.
    #[test]
    fn bls_signature_matches_its_pinned_vector() {
        let s_sig = derive_sig_scalar(&seed(42));

        // The signing key is checked against an independently recomputed value,
        // so a drift in `hash_to_scalar` cannot hide inside a drift in the
        // signature.
        assert_eq!(hex::encode(s_sig.to_bytes_be()), SIG_SCALAR_SEED42_BE);

        let sig = bls_sign(&s_sig, b"sesh-bls-dst-test-vector");
        assert_eq!(hex::encode(sig), BLS_PINNED_SIG);
        assert!(bls_verify(
            &compute_pubkey_g1(&s_sig),
            b"sesh-bls-dst-test-vector",
            &sig
        ));
    }

    #[test]
    fn dh_pair_consistency_check() {
        let s = derive_dh_scalar(&seed(3));
        let good = DhPublic::from_scalar(&s);
        assert!(good.check_consistency().is_ok());

        // Mismatched halves (different discrete logs) must be caught
        let bad = DhPublic {
            g1: compute_pubkey_g1(&s),
            g2: compute_pubkey_g2(&derive_dh_scalar(&seed(4))),
        };
        assert_eq!(
            bad.check_consistency(),
            Err(CryptoError::InconsistentDhPair)
        );
    }

    #[test]
    fn two_party_secret_is_symmetric_via_h2s() {
        let a = derive_dh_scalar(&seed(10));
        let b = derive_dh_scalar(&seed(20));
        let a_pub = compute_pubkey_g1(&a);
        let b_pub = compute_pubkey_g1(&b);

        let a_secret = shared_secret_2(&a, &b_pub);
        let b_secret = shared_secret_2(&b, &a_pub);
        assert_eq!(a_secret, b_secret);

        // A different peer yields a different secret
        let c_pub = compute_pubkey_g1(&derive_dh_scalar(&seed(30)));
        assert_ne!(shared_secret_2(&a, &c_pub), a_secret);
    }

    #[test]
    fn three_party_all_agree() {
        let a = derive_dh_scalar(&seed(11));
        let b = derive_dh_scalar(&seed(22));
        let c = derive_dh_scalar(&seed(33));
        let pa = DhPublic::from_scalar(&a);
        let pb = DhPublic::from_scalar(&b);
        let pc = DhPublic::from_scalar(&c);

        let ka = group_secret_3(&a, &pb, &pc);
        let kb = group_secret_3(&b, &pa, &pc);
        let kc = group_secret_3(&c, &pa, &pb);

        assert_eq!(ka, kb);
        assert_eq!(kb, kc);
    }

    #[test]
    fn three_party_is_permutation_independent() {
        let a = derive_dh_scalar(&seed(11));
        let pb = DhPublic::from_scalar(&derive_dh_scalar(&seed(22)));
        let pc = DhPublic::from_scalar(&derive_dh_scalar(&seed(33)));
        // Swapping the two peers must not change the derived element
        assert_eq!(group_element_3(&a, &pb, &pc), group_element_3(&a, &pc, &pb));
    }

    #[test]
    fn three_party_equals_canonical_pairing() {
        let a = derive_dh_scalar(&seed(11));
        let b = derive_dh_scalar(&seed(22));
        let c = derive_dh_scalar(&seed(33));
        let pb = DhPublic::from_scalar(&b);
        let pc = DhPublic::from_scalar(&c);

        // e(G1,G2)^{abc} computed the canonical way
        let canonical = pairing(&G1Affine::generator(), &G2Affine::generator()) * a * b * c;
        assert_eq!(group_element_3(&a, &pb, &pc), canonical);
    }

    #[test]
    fn bls_pubkey_matches_g1_derivation() {
        // The identity's sig pubkey (computed with blstrs) must equal the key
        // blst uses to verify, i.e. both agree on the G1 generator + encoding.
        use blst::min_pk::SecretKey;
        let s_sig = derive_sig_scalar(&seed(5));
        let sk = SecretKey::from_bytes(&s_sig.to_bytes_be()).unwrap();
        assert_eq!(
            sk.sk_to_pk().compress(),
            compute_pubkey_g1(&s_sig).to_compressed()
        );
    }

    #[test]
    fn bls_sign_verify_roundtrip() {
        let s = seed(42);
        let s_sig = derive_sig_scalar(&s);
        let public = public_identity_from_seed(&s);
        let msg = b"sesh-group-key-v1 arbitrary bound message";

        let sig = bls_sign(&s_sig, msg);
        assert!(bls_verify(&public.sig_g1, msg, &sig));

        // Tampered message fails
        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 0x01;
        assert!(!bls_verify(&public.sig_g1, &bad_msg, &sig));

        // Wrong signer's pubkey fails
        let other = public_identity_from_seed(&seed(43));
        assert!(!bls_verify(&other.sig_g1, msg, &sig));

        // Tampered signature fails
        let mut bad_sig = sig;
        bad_sig[0] ^= 0x01;
        assert!(!bls_verify(&public.sig_g1, msg, &bad_sig));
    }

    #[test]
    fn checksum_agrees_iff_secret_agrees() {
        let a = shared_secret_2(
            &derive_dh_scalar(&seed(1)),
            &compute_pubkey_g1(&derive_dh_scalar(&seed(2))),
        );
        let b = shared_secret_2(
            &derive_dh_scalar(&seed(2)),
            &compute_pubkey_g1(&derive_dh_scalar(&seed(1))),
        );
        assert_eq!(agreement_checksum(&a), agreement_checksum(&b));
        let c = shared_secret_2(
            &derive_dh_scalar(&seed(1)),
            &compute_pubkey_g1(&derive_dh_scalar(&seed(9))),
        );
        assert_ne!(agreement_checksum(&a), agreement_checksum(&c));
    }

    #[test]
    fn hd_child_is_deterministic_and_separated() {
        let master = derive_dh_scalar(&seed(1));
        // Deterministic over an arbitrary byte context
        assert_eq!(hd_child(&master, b"acct-0"), hd_child(&master, b"acct-0"));
        assert_ne!(hd_child(&master, b"acct-0"), hd_child(&master, b"acct-1"));
        // Empty and binary contexts are handled and distinct
        assert_ne!(hd_child(&master, b""), hd_child(&master, b"acct-0"));
        assert_ne!(
            hd_child(&master, &[0x00, 0x01]),
            hd_child(&master, &[0x01, 0x00])
        );
        // Different master -> different child for the same context
        let other = derive_dh_scalar(&seed(2));
        assert_ne!(hd_child(&master, b"acct-0"), hd_child(&other, b"acct-0"));
    }

    #[test]
    fn canonical_hd_context_is_unambiguous() {
        // Deterministic; the length prefixes prevent field-boundary collisions
        assert_eq!(
            canonical_hd_context("google.com", "bob", 0),
            canonical_hd_context("google.com", "bob", 0)
        );
        assert_ne!(
            canonical_hd_context("a", "bc", 0),
            canonical_hd_context("ab", "c", 0)
        );
        // Epoch participates.
        assert_ne!(
            canonical_hd_context("x", "y", 0),
            canonical_hd_context("x", "y", 1)
        );
        // Empty user differs from a non-empty one
        assert_ne!(
            canonical_hd_context("x", "", 0),
            canonical_hd_context("x", "u", 0)
        );
    }

    #[test]
    fn group_child_is_deterministic_and_dst_separated() {
        let s = derive_dh_scalar(&seed(1));
        let ctx = [7u8; 32];
        let ctx2 = [8u8; 32];
        // Deterministic; different context -> different child
        assert_eq!(group_child(&s, &ctx), group_child(&s, &ctx));
        assert_ne!(group_child(&s, &ctx), group_child(&s, &ctx2));
        // Different master -> different child for the same context
        let other = derive_dh_scalar(&seed(2));
        assert_ne!(group_child(&s, &ctx), group_child(&other, &ctx));
        // DST separation: same master, same 32-byte context, yet a group child
        // and an hd child never coincide (distinct domain tags).
        assert_ne!(group_child(&s, &ctx), hd_child(&s, &ctx));
    }

    #[test]
    fn two_party_dh_is_symmetric() {
        let mut rng = OsRng;
        let (a_sec, a_pub) = create_keypair(&mut rng);
        let (b_sec, b_pub) = create_keypair(&mut rng);
        assert_eq!(dh_g1(&a_sec, &b_pub), dh_g1(&b_sec, &a_pub));
    }

    #[test]
    fn two_party_dh_wrong_peer_diverges() {
        let mut rng = OsRng;
        let (a_sec, a_pub) = create_keypair(&mut rng);
        let (b_sec, b_pub) = create_keypair(&mut rng);
        let tampered = G1Affine::from(G1Projective::from(&b_pub) + G1Projective::from(&a_pub));
        assert_ne!(dh_g1(&a_sec, &tampered), dh_g1(&b_sec, &a_pub));
    }

    #[test]
    fn fingerprint_is_deterministic_and_input_sensitive() {
        assert_eq!(
            fingerprint(DST_FPR_IDENTITY, b"input"),
            fingerprint(DST_FPR_IDENTITY, b"input")
        );
        assert_ne!(
            fingerprint(DST_FPR_IDENTITY, b"input"),
            fingerprint(DST_FPR_IDENTITY, b"other")
        );
    }

    // A pinned vector for `b58(SHA3-256(u64_le(|dst|) ‖ dst ‖ u64_le(|input|) ‖
    // input)[..8])`, computed independently of this implementation.
    //
    // `fingerprint` is the one fingerprint in this module whose output is
    // **stored**: `backup.rs` writes an `identity_fingerprint` into every bundle
    // and `restore` compares it against the identity a mnemonic re-derives. A
    // change here does not fail loudly. It makes every existing bundle refuse
    // to restore, blaming the user's mnemonic. So it is frozen, and refactors
    // that route it through new helpers must land on these exact strings.
    #[test]
    fn fingerprint_matches_its_pinned_vector() {
        let input = b"sesh-fingerprint-test-vector";
        assert_eq!(fingerprint(DST_FPR_IDENTITY, input), "TV1ep5iBDZZ");
        assert_eq!(fingerprint(DST_FPR_GROUP, input), "EnnoqhCzLQA");
    }

    #[test]
    fn fingerprint_dsts_are_separated() {
        // The same input under the two domain tags never collides, including
        // via length-prefix confusion.
        assert_ne!(
            fingerprint(DST_FPR_IDENTITY, b"same"),
            fingerprint(DST_FPR_GROUP, b"same")
        );
    }

    #[test]
    fn identity_fingerprint_covers_the_whole_identity() {
        let a = identity_fingerprint(&public_identity_from_seed(&seed(1)));
        let b = identity_fingerprint(&public_identity_from_seed(&seed(2)));
        assert_ne!(a, b);
        assert_eq!(
            a,
            identity_fingerprint(&public_identity_from_seed(&seed(1)))
        );
    }

    // Every part is length-prefixed, so the boundary between two of them cannot
    // be slid. This is what lets `hd_fingerprint` concatenate params and child.
    #[test]
    fn fingerprint_parts_cannot_have_its_boundaries_slid() {
        let n = FINGERPRINT_BYTES;
        let one = fingerprint_parts(DST_FPR_HD, &[b"ab"], n);
        assert_ne!(one, fingerprint_parts(DST_FPR_HD, &[b"a", b"b"], n));
        assert_ne!(one, fingerprint_parts(DST_FPR_HD, &[b"ab", b""], n));
        assert_ne!(one, fingerprint_parts(DST_FPR_HD, &[b"", b"ab"], n));
        // Truncation width is part of the identity of the digest, not of its
        // prefix: 4 bytes is not the first characters of 8.
        assert_ne!(
            one,
            fingerprint_parts(DST_FPR_HD, &[b"ab"], HD_RECIPE_FINGERPRINT_BYTES)
        );
    }

    // The `<recipe>-<secret>` split, as the CLI prints it.
    fn halves(fpr: &str) -> (String, String) {
        let mut it = fpr.split('-');
        let (r, s) = (it.next().unwrap(), it.next().unwrap());
        assert!(it.next().is_none(), "exactly one separator: {fpr}");
        // base58 excludes '-', so the separator is unambiguous and both halves
        // land in the expected width band.
        assert!((5..=6).contains(&r.len()), "recipe half width: {r}");
        assert!((10..=11).contains(&s.len()), "secret half width: {s}");
        (r.to_string(), s.to_string())
    }

    #[test]
    fn hd_fingerprint_tracks_the_child_scalar() {
        let master = hash_to_scalar(b"test-master", b"m");
        let c1 = hd_child(&master, &canonical_hd_context("a.com", "", 1));
        let c2 = hd_child(&master, &canonical_hd_context("a.com", "", 2));
        assert_eq!(hd_fingerprint(b"p", &c1), hd_fingerprint(b"p", &c1)); // deterministic
        assert_ne!(hd_fingerprint(b"p", &c1), hd_fingerprint(b"p", &c2)); // epoch-sensitive
                                                                          // A different epoch moves *both* halves: the child changed.
        let (r1, s1) = halves(&hd_fingerprint(b"p", &c1));
        let (r2, s2) = halves(&hd_fingerprint(b"p", &c2));
        assert_ne!(r1, r2);
        assert_ne!(s1, s2);
    }

    // The point of the split. Reformatting one secret moves the recipe half and
    // leaves the secret half alone so a reader can tell "different password"
    // from "different secret" at a glance.
    #[test]
    fn hd_fingerprint_separates_the_recipe_from_the_secret() {
        let master = hash_to_scalar(b"test-master", b"m");
        let child = hd_child(&master, &canonical_hd_context("a.com", "", 1));
        let (r1, s1) = halves(&hd_fingerprint(b"params-1", &child));
        let (r2, s2) = halves(&hd_fingerprint(b"params-2", &child));
        assert_ne!(r1, r2, "the recipe half must cover params");
        assert_eq!(s1, s2, "the secret half must not");
    }

    // The recipe half binds the child too, so one ground collision cannot be
    // replayed across entries: identical params under different children give
    // different recipe halves.
    #[test]
    fn hd_fingerprint_recipe_half_is_bound_to_the_child() {
        let master = hash_to_scalar(b"test-master", b"m");
        let c1 = hd_child(&master, &canonical_hd_context("a.com", "", 1));
        let c2 = hd_child(&master, &canonical_hd_context("b.com", "", 1));
        assert_ne!(
            halves(&hd_fingerprint(b"same", &c1)).0,
            halves(&hd_fingerprint(b"same", &c2)).0
        );
    }

    // The secret half is exactly the digest the params-blind `hd_fingerprint`
    // used to return, so a fingerprint written down before the split still
    // recognizes its secret by the tail.
    #[test]
    fn hd_fingerprint_secret_half_is_unchanged_by_the_split() {
        let master = hash_to_scalar(b"test-master", b"m");
        let child = hd_child(&master, &canonical_hd_context("a.com", "", 1));
        let legacy = fingerprint(DST_FPR_HD, &child.to_bytes_le());
        assert_eq!(halves(&hd_fingerprint(b"anything", &child)).1, legacy);
    }

    // The two halves use separate domain tags, so the recipe digest of some
    // input can never be a truncation of the secret digest of another.
    #[test]
    fn hd_fingerprint_halves_are_domain_separated() {
        assert_ne!(
            fingerprint_parts(DST_FPR_HD, &[b"x"], HD_RECIPE_FINGERPRINT_BYTES),
            fingerprint_parts(DST_FPR_HD_RECIPE, &[b"x"], HD_RECIPE_FINGERPRINT_BYTES)
        );
    }
}
