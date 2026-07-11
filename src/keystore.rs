//! Local encrypted keystore. Its location is resolved by [`crate::config`]
//! (`--keystore` > `$SESH_HOME` > a `config.toml` pointer > `~/.sesh`) and
//! created and stamped with an identity marker ([`KeystoreMarker`]) on first
//! write. A `config.toml` pointer target is the exception: it is never
//! auto-created, so an absent external mount can't become a silent write.
//!
//! Two namespaces live here: `keypairs/<name>/` holds personal identities and
//! `shared-secrets/<name>/` holds named groups that reference an identity. Only
//! the identity **seed** is ever encrypted (AES-256-GCM with an Argon2id key);
//! public values are stored in the clear, and the derived secret `K` is never
//! written anywhere-— it is always re-derived on demand!
//!
//! All files are created atomically at `0600` and directories at `0700`
//! (Unix). Encryption is the real protection; the permission bits are
//! defense-in-depth and do not map onto Windows ACLs.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, PublicIdentity, SEED_BYTES};
#[cfg(test)]
use crate::protocol::Purpose;
use crate::protocol::{self, Parties, ProtocolError, SetupToken};
use crate::registry::{Registry, REGISTRY_VERSION};

/// On-disk schema version for `keypairs/<name>/identity`: the public keys and
/// the password-protected seed. Contact trust comes from the secure channel and
/// per-group signatures are made fresh at exchange time, so no self-signature is
/// stored.
pub const IDENTITY_VERSION: u32 = 1;
/// On-disk schema version for `shared-secrets/<name>/state`: contact refs, the
/// group name, and the per-group setup tokens. Never `K`.
pub const STATE_VERSION: u32 = 1;
/// On-disk schema version for `contacts/<alias>/identity`
pub const CONTACT_VERSION: u32 = 1;

/// Argon2id memory cost in KiB (64 MiB)
pub const ARGON2_M_COST: u32 = 64 * 1024;
/// Argon2id iteration (time) cost
pub const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism (lanes)
pub const ARGON2_P_COST: u32 = 1;

/// Upper bounds accepted for *stored* Argon2 parameters on load. Decryption
/// honors the parameters recorded in the identity file (so old keystores keep
/// working if the defaults above ever change), but a tampered file must not be
/// able to demand absurd resources (memory/CPU DoS).
pub const ARGON2_MAX_M_COST: u32 = 2 * 1024 * 1024; // 2 GiB in KiB
/// Maximum accepted stored Argon2 iteration count
pub const ARGON2_MAX_T_COST: u32 = 64;
/// Maximum accepted stored Argon2 parallelism
pub const ARGON2_MAX_P_COST: u32 = 16;

/// The only KDF algorithm this build reads or writes
const KDF_ALGORITHM: &str = "argon2id";
/// The only AEAD algorithm this build reads or writes
const CIPHER_ALGORITHM: &str = "aes-256-gcm";

const KDF_SALT_LEN: usize = 16;
const AEAD_NONCE_LEN: usize = 12;
const AEAD_KEY_LEN: usize = 32;

/// Errors from keystore operations
#[derive(Debug)]
pub enum KeystoreError {
    /// Filesystem I/O error
    Io(std::io::Error),
    /// (De)serialization error
    Serde(serde_json::Error),
    /// A point failed validation on load
    Crypto(CryptoError),
    /// AEAD authentication failed, wrong password or tampered ciphertext/metadata
    Decrypt,
    /// Argon2 key derivation failed
    Kdf(String),
    /// The stored record is malformed or internally inconsistent
    BadFormat(String),
    /// The requested entry does not exist
    NotFound(String),
    /// An entry with that name already exists
    AlreadyExists(String),
    /// An entry name is not a safe single path component
    InvalidName(String),
    /// A protocol-level failure (bad signature, pin mismatch, party count)
    Protocol(ProtocolError),
    /// A contact alias is already pinned to a *different* long-term key,
    /// refusing to silently overwrite. Rotate = remove then re-add after
    /// out-of-band re-verification.
    PinConflict(String),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeystoreError::Io(e) => write!(f, "Keystore I/O error: {e}"),
            KeystoreError::Serde(e) => write!(f, "Keystore serialization error: {e}"),
            KeystoreError::Crypto(e) => write!(f, "Invalid key material in keystore: {e}"),
            KeystoreError::Decrypt => {
                write!(f, "Decryption failed: wrong password or tampered keystore")
            }
            KeystoreError::Kdf(e) => write!(f, "Key derivation failed: {e}"),
            KeystoreError::BadFormat(e) => write!(f, "Malformed keystore record: {e}"),
            KeystoreError::NotFound(n) => write!(f, "No such keystore entry: {n}"),
            KeystoreError::AlreadyExists(n) => write!(f, "Keystore entry already exists: {n}"),
            // Escaped, because this is the one error that echoes a name
            // rejected *for* containing control characters. Printing it raw
            // would hand the escape sequence to the terminal after all.
            KeystoreError::InvalidName(n) => {
                write!(
                    f,
                    "Invalid entry name: {}",
                    crate::format::escape_control(n)
                )
            }
            KeystoreError::Protocol(e) => write!(f, "{e}"),
            KeystoreError::PinConflict(a) => write!(
                f,
                "Contact '{a}' is already pinned to a different key, refusing to \
                 overwrite; `contact remove` then re-add after out-of-band re-verification"
            ),
        }
    }
}

impl std::error::Error for KeystoreError {}

impl From<std::io::Error> for KeystoreError {
    fn from(e: std::io::Error) -> Self {
        KeystoreError::Io(e)
    }
}
impl From<serde_json::Error> for KeystoreError {
    fn from(e: serde_json::Error) -> Self {
        KeystoreError::Serde(e)
    }
}
impl From<CryptoError> for KeystoreError {
    fn from(e: CryptoError) -> Self {
        KeystoreError::Crypto(e)
    }
}
impl From<ProtocolError> for KeystoreError {
    fn from(e: ProtocolError) -> Self {
        KeystoreError::Protocol(e)
    }
}

/// Convenience result type
pub type Result<T> = std::result::Result<T, KeystoreError>;

// ---------------
// On-disk records
// ---------------

/// Read the `version` field of a JSON record **without parsing the rest of it**.
///
/// Every versioned reader (here and in [`crate::backup`]) calls this *before*
/// `serde_json::from_slice`, never after. A version check that runs after the
/// full parse can only ever reject a record the current code was already able to
/// read; the moment a bump adds a required field or retires an enum variant,
/// which is what a bump is *for*. The old record dies inside serde with
/// `missing field ...` and the clean `unsupported version N` never runs.
///
/// The peek struct ignores unknown fields and demands only `version`, so it
/// parses any record shape: past, present, or future.
pub fn peek_version(bytes: &[u8]) -> serde_json::Result<u32> {
    #[derive(Deserialize)]
    struct VersionPeek {
        version: u32,
    }
    serde_json::from_slice::<VersionPeek>(bytes).map(|p| p.version)
}

#[derive(Serialize, Deserialize)]
struct PubkeysRecord {
    dh_g1: String,
    dh_g2: String,
    sig_g1: String,
}

#[derive(Serialize, Deserialize)]
struct KdfRecord {
    algorithm: String,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize, Deserialize)]
struct CipherRecord {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

/// How the seed is protected at rest. **Always** encrypted: a seed is a
/// signing-capable secret, and a record that says otherwise takes an
/// authentication-free path through [`Keystore::load_seed`].
///
/// One variant, but still an enum with its `protection` tag, so the on-disk
/// shape stays self-describing and a future second scheme is additive.
#[derive(Serialize, Deserialize)]
#[serde(tag = "protection")]
enum SeedRecord {
    /// Password-protected: Argon2id key + AES-256-GCM ciphertext
    #[serde(rename = "argon2id-aes256gcm")]
    Encrypted {
        kdf: KdfRecord,
        cipher: CipherRecord,
    },
}

/// Where an identity's seed came from.
///
/// Recorded because a **mnemonic** seed is recoverable from 24 words the owner
/// already holds, and a **random** one exists nowhere else. [`crate::backup`]
/// acts on that difference by omitting the former from a bundle.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SeedOrigin {
    /// Generated by the OS CSPRNG. Unrecoverable if lost, so it always travels
    /// with the backup.
    Random,
    /// Imported from a 24-word BIP39 mnemonic the owner holds elsewhere
    Mnemonic,
}

impl SeedOrigin {
    /// The byte bound into [`identity_aad`], so the origin is authenticated
    /// rather than merely recorded.
    fn as_u8(self) -> u8 {
        match self {
            SeedOrigin::Random => 0,
            SeedOrigin::Mnemonic => 1,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityRecord {
    version: u32,
    pubkeys: PubkeysRecord,
    /// Deliberately **not** `#[serde(default)]`. A defaulted `origin` would read
    /// a record predating the field as `Random`: silently right for a random
    /// seed and silently catastrophic for a mnemonic one. A required field is
    /// safe here only because [`peek_version`] rejects an old record before
    /// serde ever looks for this key.
    origin: SeedOrigin,
    #[serde(flatten)]
    seed: SeedRecord,
}

// --------
// Keystore
//---------

/// A handle to the on-disk keystore rooted at some directory
pub struct Keystore {
    root: PathBuf,
}

impl Keystore {
    /// Open a keystore handle rooted at `root`. This is a bare handle: it does
    /// not create the directory and does not resolve any location. Location
    /// resolution (the `--keystore` / `$SESH_HOME` / config-pointer / `~/.sesh`
    /// chain) and the availability/identity checks live in [`crate::config`]
    /// and the CLI, so every command opens through one vetted path.
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Keystore { root: root.into() }
    }

    /// The keystore root directory
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path to the in-keystore identity marker (`config.toml` at the root: the
    /// same filename as the pointer, in its marker role).
    pub fn marker_path(&self) -> PathBuf {
        self.root.join(crate::config::CONFIG_FILE)
    }

    /// Read the identity marker, or `None` if the keystore carries none (not
    /// yet written to, or a legacy store).
    ///
    /// A keystore's `config.toml` is a marker only: just `id`. The
    /// `default_keystore_path` redirect key is legal only in the `~/.config/sesh`
    /// pointer, so finding it *inside* a keystore is a hard error: it would be a
    /// second, ambiguous hop.
    pub fn read_marker(&self) -> Result<Option<KeystoreMarker>> {
        let path = self.marker_path();
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(KeystoreError::Io(e)),
        };
        let kv = crate::config::parse_kv(&contents)
            .map_err(|e| KeystoreError::BadFormat(format!("{}: {e}", path.display())))?;
        if kv.contains_key("default_keystore_path") {
            return Err(KeystoreError::BadFormat(format!(
                "{}: a keystore's config.toml must not contain a `default_keystore_path` redirect \
                 (that key belongs only in ~/.config/sesh/config.toml)",
                path.display()
            )));
        }
        let id = kv
            .get("id")
            .cloned()
            .ok_or_else(|| KeystoreError::BadFormat(format!("{}: missing `id`", path.display())))?;
        Ok(Some(KeystoreMarker { id }))
    }

    /// Whether the root exists and carries a valid identity marker
    pub fn is_initialized(&self) -> bool {
        matches!(self.read_marker(), Ok(Some(_)))
    }

    /// Ensure this keystore exists and carries an identity marker, creating the
    /// directory and stamping a fresh marker if absent. **Idempotent**, and
    /// called at the start of every write, so the first `keypair create` (or any
    /// first write) provisions the store automatically, no separate `init`
    /// step. Returns the keystore id.
    ///
    /// This auto-provisions a **local** keystore. It never runs for a
    /// config-pointer target without that target's marker already validated (the
    /// CLI checks availability first), so it can never silently create secrets at
    /// an un-inserted USB mount point.
    pub fn ensure_initialized(&self) -> Result<String> {
        if let Some(m) = self.read_marker()? {
            return Ok(m.id);
        }
        create_dir_secure(&self.root)?;
        let id = new_keystore_id();
        // Marker role of config.toml: just this keystore's id, and deliberately
        // no `default_keystore_path` redirect (a keystore never points elsewhere).
        let body = format!(
            "# sesh keystore identity, stamped on first use. Do not edit.\n\
             id = \"{id}\"\n"
        );
        write_atomic_secure(&self.marker_path(), body.as_bytes())?;
        Ok(id)
    }

    fn keypair_dir(&self, name: &str) -> PathBuf {
        self.root.join("keypairs").join(name)
    }

    fn identity_path(&self, name: &str) -> PathBuf {
        self.keypair_dir(name).join("identity")
    }

    /// Whether an identity with this name exists
    pub fn identity_exists(&self, name: &str) -> bool {
        validate_name(name).is_ok() && self.identity_path(name).is_file()
    }

    /// List all identity names, sorted
    pub fn list_identities(&self) -> Result<Vec<String>> {
        list_entries(&self.root.join("keypairs"))
    }

    /// Generate a fresh random identity `name` and store it, its seed encrypted
    /// under `password`. Returns the public identity to display and pin.
    ///
    /// Takes no `origin`: generating the seed here *is* [`SeedOrigin::Random`].
    pub fn create_identity(&self, name: &str, password: &str) -> Result<PublicIdentity> {
        let mut rng = OsRng;
        self.create_identity_from_rng(name, password, &mut rng)
    }

    /// Like [`create_identity`](Self::create_identity) but with an explicit
    /// RNG. The `CryptoRng` bound keeps non-cryptographic generators out of
    /// identity creation; deterministic tests use a seeded `StdRng` (which is
    /// cryptographic) or [`write_identity`](Self::write_identity) directly.
    pub fn create_identity_from_rng<R: RngCore + CryptoRng>(
        &self,
        name: &str,
        password: &str,
        rng: &mut R,
    ) -> Result<PublicIdentity> {
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        rng.fill_bytes(&mut seed[..]);
        self.write_identity(name, &seed, password, SeedOrigin::Random)
    }

    /// Store an identity from an explicit seed (the mnemonic-import path, and a
    /// deterministic test/KAT helper).
    ///
    /// `origin` is bound into the AEAD's associated data, so it can only be
    /// changed by someone who can also re-encrypt the seed.
    pub fn write_identity(
        &self,
        name: &str,
        seed: &[u8; SEED_BYTES],
        password: &str,
        origin: SeedOrigin,
    ) -> Result<PublicIdentity> {
        validate_new_name(name)?;
        // Provision the store on first write (creates + stamps if absent)
        self.ensure_initialized()?;
        let path = self.identity_path(name);
        if path.exists() {
            return Err(KeystoreError::AlreadyExists(name.to_string()));
        }
        // Keypair and group names share one namespace so `hd-secret <owner>`
        // can resolve a bare name unambiguously.
        if self.shared_secret_exists(name) {
            return Err(KeystoreError::AlreadyExists(format!(
                "{name} (a shared-secret group has this name; keypair and group names must differ)"
            )));
        }

        let (record, public) = encrypt_identity_record(
            seed,
            password,
            origin,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        )?;
        let json = serde_json::to_vec_pretty(&record)?;

        create_dir_secure(&self.keypair_dir(name))?;
        write_atomic_secure(&path, &json)?;
        Ok(public)
    }

    /// Re-encrypt identity `name`'s seed under `new_password`.
    ///
    /// `old_password` must decrypt the record, which authenticates the schema
    /// version, the [`SeedOrigin`], and the public keys via the AAD. The record
    /// is then rewritten in place (atomically) with a fresh salt and nonce and
    /// the origin the decryption just authenticated. Any failure leaves the
    /// file untouched.
    ///
    /// Each Argon2 cost is the **max** of the record's stored value and this
    /// build's default: a password change upgrades an old wrap to current
    /// defaults, but can never weaken one written with stronger parameters
    /// (say, by a newer build). The stored costs were bounds-checked against
    /// `ARGON2_MAX_*` during decryption.
    pub fn change_identity_password(
        &self,
        name: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        validate_name(name)?;
        let record = self.read_identity_record(name)?;
        let seed = decrypt_identity_record(&record, old_password)?;
        let SeedRecord::Encrypted { kdf, .. } = &record.seed;
        let (new_record, _) = encrypt_identity_record(
            &seed,
            new_password,
            record.origin,
            kdf.m_cost.max(ARGON2_M_COST),
            kdf.t_cost.max(ARGON2_T_COST),
            kdf.p_cost.max(ARGON2_P_COST),
        )?;
        let json = serde_json::to_vec_pretty(&new_record)?;
        write_atomic_secure(&self.identity_path(name), &json)
    }

    /// Load an identity's public keys without needing the password
    pub fn load_public_identity(&self, name: &str) -> Result<PublicIdentity> {
        validate_name(name)?;
        let record = self.read_identity_record(name)?;
        public_from_record(&record.pubkeys)
    }

    /// Read identity `name`'s [`SeedOrigin`]. **The value is unauthenticated.**
    ///
    /// This reads the record's plaintext JSON (no password, no AEAD) exactly
    /// as [`load_public_identity`](Self::load_public_identity) does. A caller
    /// about to take a **destructive** action on the answer (backup omitting an
    /// unrecoverable seed, say) must first confirm it via
    /// [`load_seed`](Self::load_seed), which authenticates the origin as part of
    /// its associated data. Anything less trusts a byte an attacker with write
    /// access can flip.
    pub fn identity_origin(&self, name: &str) -> Result<SeedOrigin> {
        validate_name(name)?;
        Ok(self.read_identity_record(name)?.origin)
    }

    /// Remove an identity and its directory
    pub fn remove_identity(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let dir = self.keypair_dir(name);
        if !dir.is_dir() {
            return Err(KeystoreError::NotFound(name.to_string()));
        }
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    /// Remove an identity **and every shared-secret group it owns** (a group is
    /// unusable without its seed-providing keypair; its registry lives inside
    /// its directory and goes with it). Returns the cascaded group names,
    /// sorted. Groups whose state file cannot be read are left in place.  A
    /// corrupt file must not block removing the identity itself.
    pub fn remove_identity_cascade(&self, name: &str) -> Result<Vec<String>> {
        if !self.identity_exists(name) {
            return Err(KeystoreError::NotFound(name.to_string()));
        }
        let cascaded = self.remove_groups_where(|state| state.keypair == name)?;
        self.remove_identity(name)?;
        Ok(cascaded)
    }

    /// Remove a contact **and every shared-secret group it is a member of**
    /// (without the pinned contact the group's `K` can no longer be
    /// reconstructed). Returns the cascaded group names, sorted. Groups whose
    /// state file cannot be read are left in place.
    pub fn remove_contact_cascade(&self, alias: &str) -> Result<Vec<String>> {
        if !self.contact_exists(alias) {
            return Err(KeystoreError::NotFound(alias.to_string()));
        }
        let cascaded =
            self.remove_groups_where(|state| state.members.iter().any(|m| m == alias))?;
        self.remove_contact(alias)?;
        Ok(cascaded)
    }

    /// Remove every shared-secret group whose (readable) state matches `pred`;
    /// return the removed names, sorted.
    fn remove_groups_where(
        &self,
        pred: impl Fn(&SharedSecretState) -> bool,
    ) -> Result<Vec<String>> {
        let mut removed = Vec::new();
        for group in self.list_shared_secrets()? {
            match self.load_shared_secret(&group) {
                Ok(state) if pred(&state) => {
                    self.remove_shared_secret(&group)?;
                    removed.push(group);
                }
                _ => {} // not a match, or unreadable state so leave it alone!
            }
        }
        Ok(removed)
    }

    /// Remove a shared-secret entry and its directory
    pub fn remove_shared_secret(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let dir = self.shared_secret_dir(name);
        if !dir.is_dir() {
            return Err(KeystoreError::NotFound(name.to_string()));
        }
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    /// Decrypt and return an identity's seed.
    ///
    /// Every seed is AEAD-protected, and decryption (`decrypt_identity_record`,
    /// where the invariant is documented) authenticates the schema version, the
    /// [`SeedOrigin`], and every public key. A successful return is therefore
    /// the only proof that the record's `origin` is the one its owner wrote.
    pub fn load_seed(&self, name: &str, password: &str) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
        validate_name(name)?;
        let record = self.read_identity_record(name)?;
        decrypt_identity_record(&record, password)
    }

    fn read_identity_record(&self, name: &str) -> Result<IdentityRecord> {
        let path = self.identity_path(name);
        let bytes = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KeystoreError::NotFound(name.to_string())
            } else {
                KeystoreError::Io(e)
            }
        })?;
        let version = peek_version(&bytes)?;
        if version != IDENTITY_VERSION {
            return Err(KeystoreError::BadFormat(format!(
                "unsupported identity version {version}"
            )));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}

// -------------------------------------------------------
// Contacts (pinned peer long-term identities, all public)
// -------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ContactRecord {
    version: u32,
    alias: String,
    pubkeys: PubkeysRecord,
}

/// Outcome of pinning a contact
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactOutcome {
    /// The alias was newly pinned to this key
    Pinned,
    /// The alias already held exactly this key (a no-op)
    AlreadyPinned,
}

impl Keystore {
    fn contact_dir(&self, alias: &str) -> PathBuf {
        self.root.join("contacts").join(alias)
    }

    fn contact_path(&self, alias: &str) -> PathBuf {
        self.contact_dir(alias).join("identity")
    }

    /// Whether a contact with this alias exists
    pub fn contact_exists(&self, alias: &str) -> bool {
        validate_name(alias).is_ok() && self.contact_path(alias).is_file()
    }

    /// List all contact aliases, sorted.
    pub fn list_contacts(&self) -> Result<Vec<String>> {
        list_entries(&self.root.join("contacts"))
    }

    /// Pin a peer's long-term public identity under `alias`.
    ///
    /// Every point is subgroup-validated. Re-importing the **same** key under an
    /// existing alias is a no-op ([`ContactOutcome::AlreadyPinned`]); importing a
    /// **different** key is a hard failure ([`KeystoreError::PinConflict`]), to
    /// rotate, remove then re-add after out-of-band re-verification.
    pub fn add_contact(&self, alias: &str, public: &PublicIdentity) -> Result<ContactOutcome> {
        validate_new_name(alias)?;
        self.ensure_initialized()?;
        // Defense-in-depth: re-validate every point even though a token-decoded
        // identity is already validated.
        crypto::validate_g1(&public.dh.g1)?;
        crypto::validate_g2(&public.dh.g2)?;
        crypto::validate_g1(&public.sig_g1)?;

        if self.contact_exists(alias) {
            let existing = self.load_contact(alias)?;
            if existing == *public {
                return Ok(ContactOutcome::AlreadyPinned);
            }
            return Err(KeystoreError::PinConflict(alias.to_string()));
        }

        let record = ContactRecord {
            version: CONTACT_VERSION,
            alias: alias.to_string(),
            pubkeys: pubkeys_record(public),
        };
        let json = serde_json::to_vec_pretty(&record)?;
        create_dir_secure(&self.contact_dir(alias))?;
        write_atomic_secure(&self.contact_path(alias), &json)?;
        Ok(ContactOutcome::Pinned)
    }

    /// Load a pinned contact's long-term public identity
    pub fn load_contact(&self, alias: &str) -> Result<PublicIdentity> {
        validate_name(alias)?;
        let bytes = fs::read(self.contact_path(alias)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KeystoreError::NotFound(alias.to_string())
            } else {
                KeystoreError::Io(e)
            }
        })?;
        let version = peek_version(&bytes)?;
        if version != CONTACT_VERSION {
            return Err(KeystoreError::BadFormat(format!(
                "unsupported contact version {version}"
            )));
        }
        let record: ContactRecord = serde_json::from_slice(&bytes)?;
        public_from_record(&record.pubkeys)
    }

    /// Remove a pinned contact and its directory
    pub fn remove_contact(&self, alias: &str) -> Result<()> {
        validate_name(alias)?;
        let dir = self.contact_dir(alias);
        if !dir.is_dir() {
            return Err(KeystoreError::NotFound(alias.to_string()));
        }
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}

// -------------------------------------------
// Shared-secret state (public, never holds K)
// -------------------------------------------

/// One stored peer setup token: the per-group child pubkey(s) and the signature.
#[derive(Serialize, Deserialize)]
struct PeerTokenRecord {
    child_g1: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    child_g2: Option<String>,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct StateRecord {
    version: u32,
    keypair: String,
    group_name: String,
    /// Peer contact aliases, in the order given (the party count is
    /// `members.len() + 1`).
    members: Vec<String>,
    /// Per-peer setup tokens, aligned to `members`
    peers: Vec<PeerTokenRecord>,
}

/// The public state of a named shared-secret group. Holds no secret and the
/// derived `K` is always reconstructed on demand from the seed + this state.
#[derive(Clone, Debug)]
pub struct SharedSecretState {
    /// Name of the local identity that provides the seed
    pub keypair: String,
    /// The agreed group name (also the storage key), bound into `group_ctx`
    pub group_name: String,
    /// The peers' contact aliases, in the order given
    pub members: Vec<String>,
    /// The peers' setup tokens, aligned to `members`
    pub peers: Vec<SetupToken>,
}

impl SharedSecretState {
    /// The party count (self + peers) implied by the membership
    pub fn parties(&self) -> Result<Parties> {
        Parties::from_u8((self.members.len() + 1) as u8).map_err(KeystoreError::Protocol)
    }
}

impl Keystore {
    fn shared_secret_dir(&self, name: &str) -> PathBuf {
        self.root.join("shared-secrets").join(name)
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.shared_secret_dir(name).join("state")
    }

    /// Whether a shared-secret with this name exists
    pub fn shared_secret_exists(&self, name: &str) -> bool {
        validate_name(name).is_ok() && self.state_path(name).is_file()
    }

    /// List all shared-secret names, sorted
    pub fn list_shared_secrets(&self) -> Result<Vec<String>> {
        list_entries(&self.root.join("shared-secrets"))
    }

    /// Persist a shared-secret group's public state (never the derived secret)
    pub fn store_shared_secret(&self, name: &str, state: &SharedSecretState) -> Result<()> {
        validate_new_name(name)?;
        self.ensure_initialized()?;
        // Keypair and group names share one namespace so `hd-secret <owner>`
        // can resolve a bare name unambiguously.
        if self.identity_exists(name) {
            return Err(KeystoreError::AlreadyExists(format!(
                "{name} (a keypair has this name; keypair and group names must differ)"
            )));
        }
        // Party-count sanity (2 or 3) and members/peers alignment
        state.parties()?;
        if state.members.len() != state.peers.len() {
            return Err(KeystoreError::BadFormat(format!(
                "state has {} members but {} peer tokens",
                state.members.len(),
                state.peers.len()
            )));
        }
        let path = self.state_path(name);
        if path.exists() {
            return Err(KeystoreError::AlreadyExists(name.to_string()));
        }

        let peers = state
            .peers
            .iter()
            .map(|t| PeerTokenRecord {
                child_g1: hex::encode(t.child_g1.to_compressed()),
                child_g2: t.child_g2.map(|g2| hex::encode(g2.to_compressed())),
                signature: hex::encode(t.signature),
            })
            .collect();

        let record = StateRecord {
            version: STATE_VERSION,
            keypair: state.keypair.clone(),
            group_name: state.group_name.clone(),
            members: state.members.clone(),
            peers,
        };
        let json = serde_json::to_vec_pretty(&record)?;

        create_dir_secure(&self.shared_secret_dir(name))?;
        write_atomic_secure(&path, &json)?;
        Ok(())
    }

    /// Load a shared-secret group's public state (parsing + subgroup-validating
    /// every stored point). Signatures are re-verified later, during
    /// reconstruction, against the resolved contacts.
    pub fn load_shared_secret(&self, name: &str) -> Result<SharedSecretState> {
        validate_name(name)?;
        let bytes = fs::read(self.state_path(name)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KeystoreError::NotFound(name.to_string())
            } else {
                KeystoreError::Io(e)
            }
        })?;
        let version = peek_version(&bytes)?;
        if version != STATE_VERSION {
            return Err(KeystoreError::BadFormat(format!(
                "Unsupported shared-secret version {version}"
            )));
        }
        let record: StateRecord = serde_json::from_slice(&bytes)?;
        if record.members.len() != record.peers.len() {
            return Err(KeystoreError::BadFormat(format!(
                "State lists {} members but {} peer tokens",
                record.members.len(),
                record.peers.len()
            )));
        }
        let parties =
            Parties::from_u8((record.members.len() + 1) as u8).map_err(KeystoreError::Protocol)?;

        let mut peers = Vec::with_capacity(record.peers.len());
        for pr in &record.peers {
            let g1 = decode_hex_array::<{ crypto::G1_COMPRESSED }>(&pr.child_g1, "child_g1")?;
            let child_g1 = crypto::read_g1(&g1)?;
            let child_g2 = match (parties, &pr.child_g2) {
                (Parties::Two, None) => None,
                (Parties::Three, Some(hexg2)) => {
                    let g2 = decode_hex_array::<{ crypto::G2_COMPRESSED }>(hexg2, "child_g2")?;
                    Some(crypto::read_g2(&g2)?)
                }
                _ => {
                    return Err(KeystoreError::BadFormat(
                        "Peer token child_g2 presence does not match party count".into(),
                    ));
                }
            };
            let signature =
                decode_hex_array::<{ crypto::BLS_SIG_BYTES }>(&pr.signature, "signature")?;
            peers.push(SetupToken {
                parties,
                group_name: record.group_name.clone(),
                child_g1,
                child_g2,
                signature,
            });
        }

        Ok(SharedSecretState {
            keypair: record.keypair,
            group_name: record.group_name,
            members: record.members,
            peers,
        })
    }

    /// Reconstruct the group secret `K` from stored state + the unlocked seed.
    ///
    /// Resolves each peer's pinned contact, rebuilds the full member set,
    /// recomputes `group_ctx`, re-verifies every peer token, then derives `K`.
    pub fn reconstruct_shared_secret(
        &self,
        state: &SharedSecretState,
        seed: &[u8; SEED_BYTES],
    ) -> Result<blstrs::Scalar> {
        let self_public = crypto::public_identity_from_seed(seed);
        let mut contacts = Vec::with_capacity(state.members.len());
        for alias in &state.members {
            contacts.push(self.load_contact(alias)?);
        }
        protocol::reconstruct_group_key(
            seed,
            &state.group_name,
            &self_public,
            &contacts,
            &state.peers,
        )
        .map_err(KeystoreError::Protocol)
    }
}

// ---------------------------------------------------------------
// HD-secret registry (encrypted at rest under the owning keypair)
// ---------------------------------------------------------------

/// Which scope owns a registry: a personal keypair or a shared-secret group
#[derive(Clone, Debug)]
pub enum RegistryScope {
    /// Personal registry under `keypairs/<name>/registry`
    Keypair(String),
    /// Group registry under `shared-secrets/<name>/registry`
    Group(String),
}

#[derive(Serialize, Deserialize)]
struct RegistryFile {
    version: u32,
    cipher: CipherRecord,
}

impl RegistryScope {
    fn tag(&self) -> &'static [u8] {
        match self {
            RegistryScope::Keypair(_) => b"keypair",
            RegistryScope::Group(_) => b"group",
        }
    }
    fn name(&self) -> &str {
        match self {
            RegistryScope::Keypair(n) | RegistryScope::Group(n) => n,
        }
    }
}

/// Schema version of the encrypted **envelope** that carries a registry on disk
/// (the `RegistryFile`: cipher algorithm, nonce, ciphertext) and of the AAD that
/// binds it.
///
/// Deliberately distinct from `registry::REGISTRY_VERSION`, which versions the
/// **inner** registry document the ciphertext protects. They are two versions of
/// two different things and move independently: a new AEAD or envelope layout
/// bumps this one, a new definition schema bumps that one. [`Keystore::load_registry`]
/// checks the envelope before decrypting and the document after.
const REGISTRY_AAD_VERSION: u32 = 1;

impl Keystore {
    fn registry_path(&self, scope: &RegistryScope) -> PathBuf {
        match scope {
            RegistryScope::Keypair(n) => self.keypair_dir(n).join("registry"),
            RegistryScope::Group(n) => self.shared_secret_dir(n).join("registry"),
        }
    }

    /// Load the (decrypted) registry for `scope`, or an empty one if none exists.
    ///
    /// `seed` is the owning keypair's seed; the registry encryption key is
    /// derived from it, so reading always requires unlocking that keypair
    /// (metadata privacy, a disk attacker without the password learns nothing).
    pub fn load_registry(
        &self,
        scope: &RegistryScope,
        seed: &[u8; SEED_BYTES],
    ) -> Result<Registry> {
        let path = self.registry_path(scope);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Registry::empty()),
            Err(e) => return Err(KeystoreError::Io(e)),
        };
        let envelope_version = peek_version(&bytes)?;
        if envelope_version != REGISTRY_AAD_VERSION {
            return Err(KeystoreError::BadFormat(format!(
                "unsupported registry envelope version {envelope_version}"
            )));
        }
        let file: RegistryFile = serde_json::from_slice(&bytes)?;
        if file.cipher.algorithm != CIPHER_ALGORITHM {
            return Err(KeystoreError::BadFormat(format!(
                "unsupported cipher algorithm '{}'",
                file.cipher.algorithm
            )));
        }
        let key = registry_key(seed);
        let nonce = decode_hex_array::<AEAD_NONCE_LEN>(&file.cipher.nonce, "nonce")?;
        let ct = hex::decode(&file.cipher.ciphertext)
            .map_err(|e| KeystoreError::BadFormat(format!("ciphertext: {e}")))?;
        let aad = registry_aad(scope);
        let pt = aead_decrypt(&*key, &nonce, &ct, &aad)?;
        // The envelope's version says nothing about the schema it carries, so
        // the decrypted document is version-checked in its own right.
        let schema_version = peek_version(&pt)?;
        if schema_version != REGISTRY_VERSION {
            return Err(KeystoreError::BadFormat(format!(
                "unsupported registry schema version {schema_version}"
            )));
        }
        Ok(serde_json::from_slice(&pt)?)
    }

    /// Encrypt and persist the registry for `scope` (atomic `0600`)
    pub fn save_registry(
        &self,
        scope: &RegistryScope,
        seed: &[u8; SEED_BYTES],
        registry: &Registry,
    ) -> Result<()> {
        self.ensure_initialized()?;
        let plaintext = serde_json::to_vec(registry)?;
        let key = registry_key(seed);
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = registry_aad(scope);
        let ciphertext = aead_encrypt(&*key, &nonce, &plaintext, &aad)?;

        let file = RegistryFile {
            version: REGISTRY_AAD_VERSION,
            cipher: CipherRecord {
                algorithm: CIPHER_ALGORITHM.into(),
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ciphertext),
            },
        };
        let json = serde_json::to_vec_pretty(&file)?;
        let path = self.registry_path(scope);
        if let Some(parent) = path.parent() {
            create_dir_secure(parent)?;
        }
        write_atomic_secure(&path, &json)?;
        Ok(())
    }
}

/// Derive the registry AES key from the owning keypair's seed. The seed is
/// high-entropy, so a domain-separated SHA3-256 suffices (no Argon2 needed).
///
/// The `-v1` in the domain tag is **frozen**, unlike the AAD tags above: it is a
/// KDF domain separator, and changing it would re-derive the key of every
/// registry ever written.
fn registry_key(seed: &[u8; SEED_BYTES]) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
    let mut h = Sha3_256::new();
    h.update(b"sesh-registry-key-v1");
    h.update(seed);
    let digest = h.finalize();
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    key.copy_from_slice(&digest);
    key
}

/// AAD binds the registry envelope version and the scope (tag + name), so a
/// registry file cannot be swapped between scopes or re-framed under a
/// different envelope version.
///
/// What it does **not** provide is freshness. The key and AAD are static per
/// scope, so an attacker with write access to the keystore can replace the
/// file with an *older* validly-encrypted registry for the same scope (say,
/// one from before a `rotate` or `remove`) and it decrypts cleanly. Replay
/// protection needs a counter held somewhere that attacker cannot write, which
/// a self-contained keystore does not have; the same limitation applies to
/// every file in it. Within the stated threat model (a disk attacker without
/// the password learns nothing and can forge nothing) this is a rollback, not
/// a compromise.
///
/// The tag names a domain and nothing else; the version is a number bound
/// alongside it, so the two can never drift apart. (Contrast [`registry_key`],
/// whose `-v1` suffix is frozen: renaming it would re-derive every key.)
fn registry_aad(scope: &RegistryScope) -> Vec<u8> {
    let name = scope.name().as_bytes();
    let mut aad = Vec::with_capacity(24 + name.len());
    aad.extend_from_slice(b"sesh-registry-aad");
    aad.extend_from_slice(&REGISTRY_AAD_VERSION.to_le_bytes());
    aad.extend_from_slice(scope.tag());
    aad.push(0);
    aad.extend_from_slice(name);
    aad
}

// -----------------------------
// Record <-> crypto conversions
// -----------------------------

fn pubkeys_record(public: &PublicIdentity) -> PubkeysRecord {
    let (g1, g2) = public.dh.to_bytes();
    PubkeysRecord {
        dh_g1: hex::encode(g1),
        dh_g2: hex::encode(g2),
        sig_g1: hex::encode(public.sig_g1.to_compressed()),
    }
}

fn public_from_record(rec: &PubkeysRecord) -> Result<PublicIdentity> {
    let g1 = decode_hex_array::<{ crypto::G1_COMPRESSED }>(&rec.dh_g1, "dh_g1")?;
    let g2 = decode_hex_array::<{ crypto::G2_COMPRESSED }>(&rec.dh_g2, "dh_g2")?;
    let sig = decode_hex_array::<{ crypto::G1_COMPRESSED }>(&rec.sig_g1, "sig_g1")?;
    Ok(crypto::PublicIdentity::from_bytes(&g1, &g2, &sig)?)
}

/// AAD binds the schema version, the seed's origin, and every public key, so
/// metadata rollback, pubkey substitution, or a flipped `origin` all fail
/// authentication.
///
/// Binding `origin` is what lets `backup` act on it: a `random` seed relabelled
/// `mnemonic` in the file (this would make the next backup silently omit an
/// unrecoverable seed fails to decrypt here instead.
fn identity_aad(version: u32, origin: SeedOrigin, public: &PublicIdentity) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + public.to_bytes().len());
    aad.extend_from_slice(b"sesh-identity-aad");
    aad.extend_from_slice(&version.to_le_bytes());
    aad.push(origin.as_u8());
    aad.extend_from_slice(&public.to_bytes());
    aad
}

/// Assemble a freshly encrypted [`IdentityRecord`] for `seed` under `password`:
/// new random salt and nonce, the given Argon2 parameters (recorded in the
/// [`KdfRecord`]), and an AAD binding [`IDENTITY_VERSION`], `origin`, and the
/// seed's public keys.
fn encrypt_identity_record(
    seed: &[u8; SEED_BYTES],
    password: &str,
    origin: SeedOrigin,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(IdentityRecord, PublicIdentity)> {
    let public = crypto::public_identity_from_seed(seed);
    let pubkeys = pubkeys_record(&public);
    let aad = identity_aad(IDENTITY_VERSION, origin, &public);

    let mut salt = [0u8; KDF_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key_with(password.as_bytes(), &salt, m_cost, t_cost, p_cost)?;
    let ciphertext = aead_encrypt(&*key, &nonce, seed.as_slice(), &aad)?;

    let seed_record = SeedRecord::Encrypted {
        kdf: KdfRecord {
            algorithm: KDF_ALGORITHM.into(),
            salt: hex::encode(salt),
            m_cost,
            t_cost,
            p_cost,
        },
        cipher: CipherRecord {
            algorithm: CIPHER_ALGORITHM.into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        },
    };

    let record = IdentityRecord {
        version: IDENTITY_VERSION,
        pubkeys,
        origin,
        seed: seed_record,
    };
    Ok((record, public))
}

/// Decrypt `record`'s seed with `password`. The AAD is rebuilt from the
/// record's own `version`, `origin`, and pubkeys, so all three are
/// authenticated on every path through this function.
fn decrypt_identity_record(
    record: &IdentityRecord,
    password: &str,
) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
    let public = public_from_record(&record.pubkeys)?;
    let aad = identity_aad(record.version, record.origin, &public);

    let seed = {
        let SeedRecord::Encrypted { kdf, cipher } = &record.seed;
        if kdf.algorithm != KDF_ALGORITHM {
            return Err(KeystoreError::BadFormat(format!(
                "unsupported KDF algorithm '{}'",
                kdf.algorithm
            )));
        }
        if cipher.algorithm != CIPHER_ALGORITHM {
            return Err(KeystoreError::BadFormat(format!(
                "unsupported cipher algorithm '{}'",
                cipher.algorithm
            )));
        }
        // Decrypt with the parameters the file was written with (so a
        // future change to the defaults cannot lock old stores out),
        // bounded so a tampered file cannot demand absurd resources.
        if kdf.m_cost > ARGON2_MAX_M_COST
            || kdf.t_cost > ARGON2_MAX_T_COST
            || kdf.p_cost > ARGON2_MAX_P_COST
        {
            return Err(KeystoreError::BadFormat(
                "stored Argon2 parameters exceed the accepted bounds".into(),
            ));
        }
        let salt = decode_hex_array::<KDF_SALT_LEN>(&kdf.salt, "salt")?;
        let nonce = decode_hex_array::<AEAD_NONCE_LEN>(&cipher.nonce, "nonce")?;
        let ct = hex::decode(&cipher.ciphertext)
            .map_err(|e| KeystoreError::BadFormat(format!("ciphertext: {e}")))?;
        let key = derive_key_with(
            password.as_bytes(),
            &salt,
            kdf.m_cost,
            kdf.t_cost,
            kdf.p_cost,
        )?;
        // Zeroizing: the Vec briefly holds the raw seed, and must not leave it
        // behind in freed heap memory (including on the length-error return).
        let pt = Zeroizing::new(aead_decrypt(&*key, &nonce, &ct, &aad)?);
        if pt.len() != SEED_BYTES {
            return Err(KeystoreError::BadFormat(
                "decrypted seed has wrong length".into(),
            ));
        }
        let mut bytes = [0u8; SEED_BYTES];
        bytes.copy_from_slice(&pt);
        Zeroizing::new(bytes)
    };

    // Defense-in-depth: the (plaintext) stored pubkeys must match what the
    // seed actually derives to, else the record has been tampered with.
    if crypto::public_identity_from_seed(&seed) != public {
        return Err(KeystoreError::BadFormat(
            "stored public keys do not match the seed".into(),
        ));
    }
    Ok(seed)
}

// --------------
// Crypto helpers
// --------------

/// Derive the AEAD key with explicit Argon2id parameters. Decryption honors
/// what the record was written with (bounds-checked by the caller); encryption
/// passes this build's defaults, or the max of those and the stored costs on a
/// password change.
fn derive_key_with(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(AEAD_KEY_LEN))
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    Ok(key)
}

fn aead_encrypt(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| KeystoreError::Decrypt)
}

fn aead_decrypt(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| KeystoreError::Decrypt)
}

// ------------------
// Filesystem helpers
// ------------------

/// Reject names that are not a safe, printable single path component.
///
/// `:` is rejected because Windows reads `C:foo` as a drive-prefixed path, and
/// `PathBuf::push` **replaces the whole path** when handed one, so a name
/// arriving in a malicious contact token or export file could otherwise escape
/// the keystore root. Control characters are rejected because names are echoed
/// in prompts and listings, where an embedded escape sequence could redraw the
/// very terminal the user is reading. Both rules run on read paths too (unlike
/// the [`validate_new_name`] extras) because the hazard is joining or printing
/// the name at all, not merely creating it.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains(':')
        && !name.chars().any(char::is_control)
        && !name.starts_with('.');
    if ok {
        Ok(())
    } else {
        Err(KeystoreError::InvalidName(name.to_string()))
    }
}

/// CLI subcommand words an entity may never be named, so a name in the
/// `hd-secret <owner>` position can never be mistaken for a subcommand.
pub const RESERVED_NAMES: [&str; 12] = [
    "create", "show", "copy", "list", "rotate", "remove", "reveal", "share", "apply", "new", "add",
    "help",
];

/// [`validate_name`] plus the rules enforced only at **creation** time: the
/// name must not be a [`RESERVED_NAMES`] word and must not start with `-`
/// (either would be unaddressable as a CLI positional). Read/remove paths use
/// plain [`validate_name`] so a legacy entry with such a name stays removable.
pub fn validate_new_name(name: &str) -> Result<()> {
    validate_name(name)?;
    if RESERVED_NAMES.contains(&name) || name.starts_with('-') {
        return Err(KeystoreError::InvalidName(format!(
            "{name} (reserved command word or leading '-')"
        )));
    }
    Ok(())
}

fn list_entries(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    match fs::read_dir(dir) {
        Ok(rd) => {
            for entry in rd {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(KeystoreError::Io(e)),
    }
    names.sort();
    Ok(names)
}

/// The keystore identity marker: the keystore's own `config.toml`, holding a
/// random UUID. Its presence distinguishes a real keystore from an empty mount
/// point; its id lets a config pointer detect a swapped device. (It shares the
/// filename `config.toml` with the pointer-- see [`crate::config::CONFIG_FILE`].)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeystoreMarker {
    /// The keystore's unique identity (UUID string)
    pub id: String,
}

/// A random keystore identity: 16 random bytes formatted as a v4-shaped UUID
/// string. No external `uuid` crate is pulled in.  Hence, the bytes only need to be
/// unique and opaque, which `OsRng` provides.
pub fn new_keystore_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1 (RFC 4122)
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Create a directory (and parents) at `0700` on Unix
pub fn create_dir_secure(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Write `contents` to `path` atomically, creating the file at `0600` on Unix.
///
/// A temporary sibling is created with `create_new` (closing the TOCTOU window
/// against a pre-existing symlink), written, fsync'd, renamed into place, and
/// finally the **containing directory is fsync'd** so the rename itself is
/// durable. On removable media (a USB key yanked mid-write) this is what keeps
/// a torn write from leaving a half-written registry or seed behind: readers
/// see either the old file or the whole new one, never a fragment.
pub fn write_atomic_secure(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| KeystoreError::BadFormat("path has no parent directory".into()))?;

    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let tmp = dir.join(format!(".tmp-{}", hex::encode(suffix)));

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let write_result = (|| -> Result<()> {
        let mut file = opts.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(KeystoreError::Io(e));
    }
    // Persist the directory entry (the rename) itself. Best-effort: a
    // filesystem that rejects a directory fsync must not fail the write.
    fsync_dir(dir);
    Ok(())
}

/// Best-effort fsync of a directory, so a rename into it survives power loss.
/// Errors are swallowed: some filesystems reject `fsync` on a directory, and a
/// non-durable rename is still a *complete* rename.  The atomicity guarantee is
/// unaffected, only the crash-durability window is.
fn fsync_dir(dir: &Path) {
    if let Ok(f) = fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

fn decode_hex_array<const N: usize>(s: &str, field: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|e| KeystoreError::BadFormat(format!("{field}: {e}")))?;
    if bytes.len() != N {
        return Err(KeystoreError::BadFormat(format!(
            "{field}: expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixed_seed() -> [u8; SEED_BYTES] {
        let mut s = [0u8; SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        s
    }

    #[test]
    fn password_roundtrip() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();

        let public = ks
            .write_identity("alice", &seed, "correct horse", SeedOrigin::Random)
            .unwrap();
        let loaded = ks.load_seed("alice", "correct horse").unwrap();
        assert_eq!(&seed, loaded.as_ref());
        // Public identity is recoverable without the password
        assert_eq!(ks.load_public_identity("alice").unwrap(), public);
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("bob", &fixed_seed(), "hunter2", SeedOrigin::Random)
            .unwrap();
        match ks.load_seed("bob", "wrong") {
            Err(KeystoreError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }

    #[test]
    fn change_password_reencrypts_the_same_seed() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("alice", &seed, "old", SeedOrigin::Random)
            .unwrap();
        let before: serde_json::Value =
            serde_json::from_slice(&fs::read(ks.identity_path("alice")).unwrap()).unwrap();

        ks.change_identity_password("alice", "old", "new").unwrap();

        // The old password no longer decrypts; the new one yields the same seed
        assert!(matches!(
            ks.load_seed("alice", "old"),
            Err(KeystoreError::Decrypt)
        ));
        assert_eq!(ks.load_seed("alice", "new").unwrap().as_ref(), &seed);

        // Fresh randomness on rewrap; public material and metadata unchanged
        let after: serde_json::Value =
            serde_json::from_slice(&fs::read(ks.identity_path("alice")).unwrap()).unwrap();
        assert_ne!(before["kdf"]["salt"], after["kdf"]["salt"]);
        assert_ne!(before["cipher"]["nonce"], after["cipher"]["nonce"]);
        assert_eq!(before["pubkeys"], after["pubkeys"]);
        assert_eq!(before["version"], after["version"]);
        assert_eq!(before["origin"], after["origin"]);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(ks.identity_path("alice"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn change_password_never_weakens_stored_kdf_params() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("dave", &seed, "old", SeedOrigin::Random)
            .unwrap();

        // Rewrap the record on disk with a t_cost above this build's default,
        // as a newer build with bumped defaults would have written it.
        let (rec, _) = encrypt_identity_record(
            &seed,
            "old",
            SeedOrigin::Random,
            ARGON2_M_COST,
            ARGON2_T_COST + 2,
            ARGON2_P_COST,
        )
        .unwrap();
        write_atomic_secure(
            &ks.identity_path("dave"),
            &serde_json::to_vec_pretty(&rec).unwrap(),
        )
        .unwrap();

        ks.change_identity_password("dave", "old", "new").unwrap();

        // The stronger stored cost survives the rewrap (max, not overwrite)
        let after: serde_json::Value =
            serde_json::from_slice(&fs::read(ks.identity_path("dave")).unwrap()).unwrap();
        assert_eq!(after["kdf"]["t_cost"], serde_json::json!(ARGON2_T_COST + 2));
        assert_eq!(after["kdf"]["m_cost"], serde_json::json!(ARGON2_M_COST));
        assert_eq!(ks.load_seed("dave", "new").unwrap().as_ref(), &seed);
    }

    #[test]
    fn change_password_preserves_a_mnemonic_origin() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("mnem", &seed, "old", SeedOrigin::Mnemonic)
            .unwrap();

        ks.change_identity_password("mnem", "old", "new").unwrap();

        // Origin survives the rewrap, and (since it is bound into the AAD) a
        // successful decrypt under the new password proves it was re-bound
        // correctly.
        assert_eq!(ks.identity_origin("mnem").unwrap(), SeedOrigin::Mnemonic);
        assert_eq!(ks.load_seed("mnem", "new").unwrap().as_ref(), &seed);
    }

    #[test]
    fn change_password_with_wrong_old_password_leaves_the_file_untouched() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("carol", &fixed_seed(), "right", SeedOrigin::Random)
            .unwrap();
        let before = fs::read(ks.identity_path("carol")).unwrap();

        assert!(matches!(
            ks.change_identity_password("carol", "wrong", "new"),
            Err(KeystoreError::Decrypt)
        ));

        assert_eq!(fs::read(ks.identity_path("carol")).unwrap(), before);
        ks.load_seed("carol", "right").unwrap();
    }

    #[test]
    fn change_password_for_a_missing_identity_is_not_found() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        assert!(matches!(
            ks.change_identity_password("ghost", "a", "b"),
            Err(KeystoreError::NotFound(_))
        ));
    }

    #[test]
    fn origin_round_trips_and_is_readable_without_a_password() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("rand", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();
        ks.write_identity("mnem", &[4u8; SEED_BYTES], "pw", SeedOrigin::Mnemonic)
            .unwrap();
        // `create_identity` is the random path by definition
        ks.create_identity("gen", "pw").unwrap();

        assert_eq!(ks.identity_origin("rand").unwrap(), SeedOrigin::Random);
        assert_eq!(ks.identity_origin("mnem").unwrap(), SeedOrigin::Mnemonic);
        assert_eq!(ks.identity_origin("gen").unwrap(), SeedOrigin::Random);
        // Both origins still decrypt under their own AAD
        assert_eq!(
            ks.load_seed("mnem", "pw").unwrap().as_ref(),
            &[4u8; SEED_BYTES]
        );
    }

    // The whole security argument of the seedless backup. `identity_origin` is
    // unauthenticated, so a `random` seed relabelled `mnemonic` would make the
    // next backup silently drop an unrecoverable seed. Binding `origin` into the
    // AAD means `load_seed` (which `backup` calls before it agrees to skip)
    // rejects the flip.
    #[test]
    fn a_flipped_origin_fails_authentication() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("victim", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();

        let path = ks.identity_path("victim");
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        rec["origin"] = serde_json::json!("mnemonic");
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

        // The unauthenticated read believes the lie...
        assert_eq!(ks.identity_origin("victim").unwrap(), SeedOrigin::Mnemonic);
        // ...and the authenticated one does not. AES-GCM cannot tell this from a
        // wrong password, and must not try to.
        assert!(matches!(
            ks.load_seed("victim", "pw"),
            Err(KeystoreError::Decrypt)
        ));
    }

    // `origin` has no serde default: a record predating the field must be
    // rejected outright, never read as `Random`. Silently right for a random
    // seed; silently catastrophic for a mnemonic one.
    #[test]
    fn an_identity_record_without_an_origin_is_rejected() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("old", &fixed_seed(), "pw", SeedOrigin::Mnemonic)
            .unwrap();

        let path = ks.identity_path("old");
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        rec.as_object_mut().unwrap().remove("origin");
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

        assert!(ks.identity_origin("old").is_err());
        assert!(ks.load_seed("old", "pw").is_err());
    }

    // Deleting the `--no-password` flag was not the fix; deleting the variant
    // was. While `SeedRecord::Plaintext` deserialized, a hand-written record
    // could still send `load_seed` down an AEAD-free path, leaving the AAD that
    // binds the version and the pubkeys entirely unchecked.
    #[test]
    fn a_plaintext_seed_record_is_rejected() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        let public = ks
            .write_identity("carol", &seed, "pw", SeedOrigin::Random)
            .unwrap();

        // A well-formed record at the *current* version, carrying every required
        // field, and differing from a real one only in the protection scheme it
        // claims, so the rejection can only be about the scheme.
        let record = serde_json::json!({
            "version": IDENTITY_VERSION,
            "pubkeys": {
                "dh_g1": hex::encode(public.dh.g1.to_compressed()),
                "dh_g2": hex::encode(public.dh.g2.to_compressed()),
                "sig_g1": hex::encode(public.sig_g1.to_compressed()),
            },
            "origin": "random",
            "protection": "plaintext",
            "seed": hex::encode(seed),
        });
        fs::write(
            ks.identity_path("carol"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();

        assert!(ks.load_seed("carol", "pw").is_err());
        assert!(ks.load_public_identity("carol").is_err());
    }

    // Assert `f` fails with a `BadFormat` naming an unsupported version
    fn assert_unsupported_version<T: std::fmt::Debug>(what: &str, r: Result<T>) {
        match r {
            Err(KeystoreError::BadFormat(msg)) => assert!(
                msg.contains("nsupported") && msg.contains("99"),
                "{what}: expected an unsupported-version error, got {msg:?}"
            ),
            other => panic!("{what}: expected BadFormat, got {other:?}"),
        }
    }

    // Every version check fires BEFORE its record deserializes. Each fixture
    // below bumps the version *and* mangles the body so the current code could
    // not parse it, exactly what a real bump looks like from an old build's
    // side. The version error, not a serde error, is what must surface.

    #[test]
    fn identity_version_is_checked_before_the_record_parses() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("v", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();

        let path = ks.identity_path("v");
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        rec["version"] = serde_json::json!(99);
        rec["protection"] = serde_json::json!("some-future-scheme"); // unknown variant
        rec.as_object_mut().unwrap().remove("pubkeys"); // missing required field
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

        assert_unsupported_version("identity", ks.load_public_identity("v"));
        assert_unsupported_version("identity", ks.load_seed("v", "pw"));
    }

    #[test]
    fn contact_version_is_checked_before_the_record_parses() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let public = crypto::public_identity_from_seed(&[3u8; SEED_BYTES]);
        ks.add_contact("bob", &public).unwrap();

        let path = ks.contact_path("bob");
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        rec["version"] = serde_json::json!(99);
        rec.as_object_mut().unwrap().remove("pubkeys");
        rec["future_field"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

        assert_unsupported_version("contact", ks.load_contact("bob"));
    }

    #[test]
    fn state_version_is_checked_before_the_record_parses() {
        let (_dirs, stores, _seeds) = build_group(2, "grp");
        let path = stores[0].state_path("grp");
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        rec["version"] = serde_json::json!(99);
        rec.as_object_mut().unwrap().remove("peers");
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

        assert_unsupported_version("state", stores[0].load_shared_secret("grp"));
    }

    #[test]
    fn registry_envelope_version_is_checked_before_the_record_parses() {
        use crate::registry::Registry;
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("me", &seed, "pw", SeedOrigin::Random)
            .unwrap();
        let scope = RegistryScope::Keypair("me".into());
        ks.save_registry(&scope, &seed, &Registry::empty()).unwrap();

        let path = ks.registry_path(&scope);
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        rec["version"] = serde_json::json!(99);
        rec.as_object_mut().unwrap().remove("cipher");
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

        assert_unsupported_version("registry envelope", ks.load_registry(&scope, &seed));
    }

    #[test]
    fn registry_schema_version_is_checked_after_the_decrypt() {
        // The envelope's version says nothing about the schema inside it. Seal a
        // well-formed envelope around a future-schema document and confirm the
        // inner check fires.
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("me", &seed, "pw", SeedOrigin::Random)
            .unwrap();
        let scope = RegistryScope::Keypair("me".into());

        let future = br#"{"version":99,"definitions":[]}"#;
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let key = registry_key(&seed);
        let ct = aead_encrypt(&*key, &nonce, future, &registry_aad(&scope)).unwrap();
        let file = RegistryFile {
            version: REGISTRY_AAD_VERSION,
            cipher: CipherRecord {
                algorithm: CIPHER_ALGORITHM.into(),
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ct),
            },
        };
        let path = ks.registry_path(&scope);
        create_dir_secure(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

        assert_unsupported_version("registry schema", ks.load_registry(&scope, &seed));
    }

    #[test]
    fn tampering_ciphertext_fails() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("dave", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();

        let path = ks.identity_path("dave");
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        // Flip the last hex nibble of the ciphertext
        let ct = record["cipher"]["ciphertext"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = ct.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        record["cipher"]["ciphertext"] = serde_json::Value::String(chars.into_iter().collect());
        fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

        match ks.load_seed("dave", "pw") {
            Err(KeystoreError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }

    #[test]
    fn tampering_aad_pubkey_fails() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        // A second identity gives us a valid substitute pubkey
        ks.write_identity("erin", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();
        let other = ks
            .write_identity("erin2", &[9u8; SEED_BYTES], "pw", SeedOrigin::Random)
            .unwrap();

        let path = ks.identity_path("erin");
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        // Swap in the other identity's DH pair *whole*. Both halves are valid
        // and mutually consistent, so the record parses and the substitution
        // must be caught by the AAD binding rather than by pair validation,
        // which is the property under test.
        record["pubkeys"]["dh_g1"] =
            serde_json::Value::String(hex::encode(other.dh.g1.to_compressed()));
        record["pubkeys"]["dh_g2"] =
            serde_json::Value::String(hex::encode(other.dh.g2.to_compressed()));
        fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

        match ks.load_seed("erin", "pw") {
            Err(KeystoreError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }

    // Substituting only *one* half of a stored DH pair never reaches the AEAD:
    // `public_from_record` consistency-checks the pair, so the record is
    // rejected while it is still being parsed.
    #[test]
    fn tampering_half_a_dh_pair_is_rejected_before_decrypt() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("frank", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();
        let other = ks
            .write_identity("frank2", &[9u8; SEED_BYTES], "pw", SeedOrigin::Random)
            .unwrap();

        let path = ks.identity_path("frank");
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record["pubkeys"]["dh_g1"] =
            serde_json::Value::String(hex::encode(other.dh.g1.to_compressed()));
        fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

        match ks.load_seed("frank", "pw") {
            Err(KeystoreError::Crypto(crypto::CryptoError::InconsistentDhPair)) => {}
            other => panic!("expected InconsistentDhPair, got {other:?}"),
        }
    }

    #[test]
    fn stored_kdf_params_are_honored_on_load() {
        // An identity written with non-default (weaker, but valid) Argon2
        // parameters must still decrypt: load reads the params from the file
        // instead of assuming this build's constants.
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("kdf", &seed, "pw", SeedOrigin::Random)
            .unwrap();

        let (m, t, p) = (8 * 1024, 1, 1); // valid but different from the defaults
        let public = ks.load_public_identity("kdf").unwrap();
        let aad = identity_aad(IDENTITY_VERSION, SeedOrigin::Random, &public);
        let mut salt = [0u8; KDF_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let key = derive_key_with(b"pw", &salt, m, t, p).unwrap();
        let ct = aead_encrypt(&*key, &nonce, &seed, &aad).unwrap();

        let path = ks.identity_path("kdf");
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        rec["kdf"] = serde_json::json!({
            "algorithm": KDF_ALGORITHM, "salt": hex::encode(salt),
            "m_cost": m, "t_cost": t, "p_cost": p,
        });
        rec["cipher"] = serde_json::json!({
            "algorithm": CIPHER_ALGORITHM, "nonce": hex::encode(nonce),
            "ciphertext": hex::encode(ct),
        });
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

        assert_eq!(&seed, ks.load_seed("kdf", "pw").unwrap().as_ref());
    }

    #[test]
    fn absurd_or_unknown_kdf_params_are_rejected() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("kdf", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();
        let path = ks.identity_path("kdf");
        let orig = fs::read(&path).unwrap();

        // Out-of-bounds memory cost -> BadFormat (a resource-DoS guard), never
        // an attempt to run the KDF with it.
        let mut rec: serde_json::Value = serde_json::from_slice(&orig).unwrap();
        rec["kdf"]["m_cost"] = serde_json::json!(ARGON2_MAX_M_COST + 1);
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();
        assert!(matches!(
            ks.load_seed("kdf", "pw"),
            Err(KeystoreError::BadFormat(_))
        ));

        // Unknown KDF algorithm name -> BadFormat
        let mut rec: serde_json::Value = serde_json::from_slice(&orig).unwrap();
        rec["kdf"]["algorithm"] = serde_json::json!("argon2i");
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();
        assert!(matches!(
            ks.load_seed("kdf", "pw"),
            Err(KeystoreError::BadFormat(_))
        ));

        // Unknown cipher algorithm name -> BadFormat
        let mut rec: serde_json::Value = serde_json::from_slice(&orig).unwrap();
        rec["cipher"]["algorithm"] = serde_json::json!("aes-128-gcm");
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();
        assert!(matches!(
            ks.load_seed("kdf", "pw"),
            Err(KeystoreError::BadFormat(_))
        ));
    }

    #[test]
    fn seed_never_stored_in_plaintext_when_encrypted() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("frank", &seed, "pw", SeedOrigin::Random)
            .unwrap();
        let raw = fs::read(ks.identity_path("frank")).unwrap();
        // Neither the raw seed bytes nor its hex encoding may appear on disk
        assert!(!raw.windows(SEED_BYTES).any(|w| w == seed));
        let seed_hex = hex::encode(seed);
        assert!(!String::from_utf8_lossy(&raw).contains(&seed_hex));
    }

    #[test]
    #[cfg(unix)]
    fn permissions_are_locked_down() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("grace", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();

        let file_mode = fs::metadata(ks.identity_path("grace"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "identity file must be 0600");

        let dir_mode = fs::metadata(ks.keypair_dir("grace"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "keypair dir must be 0700");
    }

    #[test]
    fn duplicate_name_is_rejected() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("heidi", &fixed_seed(), "pw", SeedOrigin::Random)
            .unwrap();
        match ks.write_identity("heidi", &fixed_seed(), "pw", SeedOrigin::Random) {
            Err(KeystoreError::AlreadyExists(_)) => {}
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn invalid_names_rejected() {
        assert!(validate_name("../evil").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name(".hidden").is_err());
        // Windows drive prefix: `PathBuf::push("C:evil")` REPLACES the path, so
        // a ':' anywhere would let a token-borne name escape the keystore root.
        assert!(validate_name("C:evil").is_err());
        assert!(validate_name("a:b").is_err());
        // Control characters: names are echoed in prompts and listings, where
        // an embedded escape sequence could redraw the terminal.
        assert!(validate_name("a\x1b[2Jb").is_err());
        assert!(validate_name("a\nb").is_err());
        assert!(validate_name("a\0b").is_err());
        assert!(validate_name("ok-name_1").is_ok());
    }

    #[test]
    fn listing_and_random_identity() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.create_identity("i1", "pw").unwrap();
        ks.create_identity("i2", "pw").unwrap();
        assert_eq!(ks.list_identities().unwrap(), vec!["i1", "i2"]);
        // A generated identity round-trips
        let pub2 = ks.load_public_identity("i2").unwrap();
        let seed2 = ks.load_seed("i2", "pw").unwrap();
        assert_eq!(crypto::public_identity_from_seed(&seed2), pub2);
    }

    #[test]
    fn contact_import_round_trip() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let public = crypto::public_identity_from_seed(&[3u8; SEED_BYTES]);
        assert_eq!(
            ks.add_contact("bob", &public).unwrap(),
            ContactOutcome::Pinned
        );
        assert_eq!(ks.load_contact("bob").unwrap(), public);
        assert!(ks.contact_exists("bob"));
        assert_eq!(ks.list_contacts().unwrap(), vec!["bob"]);
    }

    #[test]
    fn contact_same_key_is_idempotent() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let public = crypto::public_identity_from_seed(&[3u8; SEED_BYTES]);
        ks.add_contact("bob", &public).unwrap();
        assert_eq!(
            ks.add_contact("bob", &public).unwrap(),
            ContactOutcome::AlreadyPinned
        );
    }

    #[test]
    fn contact_different_key_is_pin_conflict() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let a = crypto::public_identity_from_seed(&[3u8; SEED_BYTES]);
        let b = crypto::public_identity_from_seed(&[4u8; SEED_BYTES]);
        ks.add_contact("bob", &a).unwrap();
        match ks.add_contact("bob", &b) {
            Err(KeystoreError::PinConflict(alias)) => assert_eq!(alias, "bob"),
            other => panic!("expected PinConflict, got {other:?}"),
        }
        // The original pin is untouched
        assert_eq!(ks.load_contact("bob").unwrap(), a);
    }

    #[test]
    fn contact_remove_and_reimport_allows_rotation() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let a = crypto::public_identity_from_seed(&[3u8; SEED_BYTES]);
        let b = crypto::public_identity_from_seed(&[4u8; SEED_BYTES]);
        ks.add_contact("bob", &a).unwrap();
        ks.remove_contact("bob").unwrap();
        assert!(!ks.contact_exists("bob"));
        // After removal a different key may be pinned (explicit rotation)
        assert_eq!(ks.add_contact("bob", &b).unwrap(), ContactOutcome::Pinned);
        assert_eq!(ks.load_contact("bob").unwrap(), b);
    }

    #[test]
    fn contact_remove_missing_is_not_found() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        assert!(matches!(
            ks.remove_contact("ghost"),
            Err(KeystoreError::NotFound(_))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn contact_permissions_are_locked_down() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let public = crypto::public_identity_from_seed(&[3u8; SEED_BYTES]);
        ks.add_contact("bob", &public).unwrap();
        let file_mode = fs::metadata(ks.contact_path("bob"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "contact file must be 0600");
        let dir_mode = fs::metadata(ks.contact_dir("bob"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "contact dir must be 0700");
    }

    // Build a group across N temp keystores. Each keystore holds identity "me"
    // and pins the others as contacts "p0".."pN-1". Returns the stores (with
    // their temp dirs kept alive) and the seeds.
    fn build_group(
        n: usize,
        group: &str,
    ) -> (Vec<tempfile::TempDir>, Vec<Keystore>, Vec<[u8; SEED_BYTES]>) {
        let dirs: Vec<tempfile::TempDir> = (0..n).map(|_| tempdir().unwrap()).collect();
        let stores: Vec<Keystore> = dirs.iter().map(|d| Keystore::open(d.path())).collect();
        let seeds: Vec<[u8; SEED_BYTES]> = (0..n).map(|i| [(i as u8) + 1; SEED_BYTES]).collect();
        let pubs: Vec<PublicIdentity> = seeds
            .iter()
            .map(crypto::public_identity_from_seed)
            .collect();

        for (i, ks) in stores.iter().enumerate() {
            ks.write_identity("me", &seeds[i], "pw", SeedOrigin::Random)
                .unwrap();
            // Pin the others as contacts, in ascending index order
            for j in (0..n).filter(|&j| j != i) {
                ks.add_contact(&format!("p{j}"), &pubs[j]).unwrap();
            }
        }

        // Each party stores its group state: aliases + the peers' setup tokens
        for (i, ks) in stores.iter().enumerate() {
            let members: Vec<PublicIdentity> = pubs.clone(); // full member set
            let aliases: Vec<String> = (0..n)
                .filter(|&j| j != i)
                .map(|j| format!("p{j}"))
                .collect();
            let peers: Vec<SetupToken> = (0..n)
                .filter(|&j| j != i)
                .map(|j| SetupToken::create(&seeds[j], Purpose::Master, group, &members).unwrap())
                .collect();
            ks.store_shared_secret(
                group,
                &SharedSecretState {
                    keypair: "me".into(),
                    group_name: group.into(),
                    members: aliases,
                    peers,
                },
            )
            .unwrap();
        }
        (dirs, stores, seeds)
    }

    #[test]
    fn one_identity_many_shared_secrets() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        ks.write_identity("me", &[1u8; SEED_BYTES], "pw", SeedOrigin::Random)
            .unwrap();
        let me = crypto::public_identity_from_seed(&[1u8; SEED_BYTES]);
        let bob_pub = crypto::public_identity_from_seed(&[2u8; SEED_BYTES]);
        ks.add_contact("bob", &bob_pub).unwrap();

        for name in ["g1", "g2"] {
            let members = [me.clone(), bob_pub.clone()];
            let token =
                SetupToken::create(&[2u8; SEED_BYTES], Purpose::Master, name, &members).unwrap();
            let state = SharedSecretState {
                keypair: "me".into(),
                group_name: name.into(),
                members: vec!["bob".into()],
                peers: vec![token],
            };
            ks.store_shared_secret(name, &state).unwrap();
        }
        assert_eq!(ks.list_shared_secrets().unwrap(), vec!["g1", "g2"]);
        assert_eq!(ks.load_shared_secret("g1").unwrap().keypair, "me");
        let g2 = ks.load_shared_secret("g2").unwrap();
        assert_eq!(g2.peers.len(), 1);
        assert_eq!(g2.parties().unwrap(), Parties::Two);
    }

    #[test]
    fn store_rejects_misaligned_members_and_peers() {
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let me = crypto::public_identity_from_seed(&[1u8; SEED_BYTES]);
        let bob = crypto::public_identity_from_seed(&[2u8; SEED_BYTES]);
        let token =
            SetupToken::create(&[2u8; SEED_BYTES], Purpose::Master, "g", &[me, bob]).unwrap();
        let state = SharedSecretState {
            keypair: "me".into(),
            group_name: "g".into(),
            members: vec!["bob".into(), "carol".into()], // 2 members
            peers: vec![token],                          // but 1 token
        };
        assert!(ks.store_shared_secret("bad", &state).is_err());
    }

    #[test]
    fn two_keystores_reconstruct_identical_secret() {
        let (_dirs, stores, _seeds) = build_group(2, "grp");
        let ka = {
            let st = stores[0].load_shared_secret("grp").unwrap();
            let seed = stores[0].load_seed("me", "pw").unwrap();
            stores[0].reconstruct_shared_secret(&st, &seed).unwrap()
        };
        let kb = {
            let st = stores[1].load_shared_secret("grp").unwrap();
            let seed = stores[1].load_seed("me", "pw").unwrap();
            stores[1].reconstruct_shared_secret(&st, &seed).unwrap()
        };
        assert_eq!(ka, kb);
    }

    #[test]
    fn three_keystores_reach_identical_secret_and_state_has_no_k() {
        use blstrs::Scalar;
        let (_dirs, stores, _seeds) = build_group(3, "team");

        let reconstruct = |ks: &Keystore| -> Scalar {
            let st = ks.load_shared_secret("team").unwrap();
            let seed = ks.load_seed("me", "pw").unwrap();
            ks.reconstruct_shared_secret(&st, &seed).unwrap()
        };
        let secrets: Vec<Scalar> = stores.iter().map(reconstruct).collect();
        assert_eq!(secrets[0], secrets[1]);
        assert_eq!(secrets[1], secrets[2]);

        // The derived K must never appear in the on-disk state
        let raw = fs::read(stores[0].state_path("team")).unwrap();
        let sbytes = secrets[0].to_bytes_le();
        assert!(!raw.windows(sbytes.len()).any(|w| w == sbytes));
        assert!(!String::from_utf8_lossy(&raw).contains(&hex::encode(sbytes)));
    }

    #[test]
    fn registry_round_trips_and_is_encrypted_at_rest() {
        use crate::registry::{Params, Registry};
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("me", &seed, "pw", SeedOrigin::Random)
            .unwrap();
        let scope = RegistryScope::Keypair("me".into());

        // Missing file -> empty registry
        assert!(ks.load_registry(&scope, &seed).unwrap().live().is_empty());

        let mut reg = Registry::empty();
        reg.create(
            "google.com",
            "bob",
            Params {
                mode: "b58".into(),
                length: None,
                symbols: None,
                suffix: None,
            },
        )
        .unwrap();
        ks.save_registry(&scope, &seed, &reg).unwrap();

        let loaded = ks.load_registry(&scope, &seed).unwrap();
        assert_eq!(loaded.get("google.com", "bob").unwrap().epoch, 1);

        // The id must NOT appear in the raw file (encrypted at rest)
        let raw = fs::read(ks.registry_path(&scope)).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("google.com"));
    }

    #[test]
    fn registry_wrong_seed_fails_to_decrypt() {
        use crate::registry::{Params, Registry};
        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        let seed = fixed_seed();
        ks.write_identity("me", &seed, "pw", SeedOrigin::Random)
            .unwrap();
        let scope = RegistryScope::Keypair("me".into());
        let mut reg = Registry::empty();
        reg.create(
            "x",
            "",
            Params {
                mode: "b58".into(),
                length: None,
                symbols: None,
                suffix: None,
            },
        )
        .unwrap();
        ks.save_registry(&scope, &seed, &reg).unwrap();

        let wrong = [0xAAu8; SEED_BYTES];
        assert!(matches!(
            ks.load_registry(&scope, &wrong),
            Err(KeystoreError::Decrypt)
        ));
    }

    #[test]
    fn reserved_and_dash_names_rejected_at_creation_only() {
        for bad in ["show", "list", "apply", "help", "-x"] {
            assert!(validate_new_name(bad).is_err(), "{bad} must be rejected");
        }
        assert!(validate_new_name("google.com").is_ok());
        // Plain validate_name (read/remove paths) still accepts them
        assert!(validate_name("show").is_ok());
        assert!(validate_name("-x").is_ok());

        let dir = tempdir().unwrap();
        let ks = Keystore::open(dir.path());
        assert!(matches!(
            ks.write_identity("show", &fixed_seed(), "pw", SeedOrigin::Random),
            Err(KeystoreError::InvalidName(_))
        ));
        let public = crypto::public_identity_from_seed(&[3u8; SEED_BYTES]);
        assert!(matches!(
            ks.add_contact("remove", &public),
            Err(KeystoreError::InvalidName(_))
        ));
    }

    #[test]
    fn keypair_and_group_names_are_disjoint() {
        let (_dirs, stores, _seeds) = build_group(2, "grp");
        // A keypair may not take an existing group's name
        match stores[0].write_identity("grp", &[7u8; SEED_BYTES], "pw", SeedOrigin::Random) {
            Err(KeystoreError::AlreadyExists(_)) => {}
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        // ... and a group may not take an existing keypair's name ...
        let st = stores[0].load_shared_secret("grp").unwrap();
        match stores[0].store_shared_secret("me", &st) {
            Err(KeystoreError::AlreadyExists(_)) => {}
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn remove_identity_cascade_takes_owned_groups_only() {
        let (_dirs, stores, _seeds) = build_group(2, "grp");
        let ks = &stores[0];
        // A second identity owning nothing
        ks.write_identity("other", &[9u8; SEED_BYTES], "pw", SeedOrigin::Random)
            .unwrap();

        // Removing the non-owner cascades nothing
        assert_eq!(
            ks.remove_identity_cascade("other").unwrap(),
            Vec::<String>::new()
        );
        assert!(ks.shared_secret_exists("grp"));

        // Removing the owner cascades its group (and reports it)
        assert_eq!(ks.remove_identity_cascade("me").unwrap(), vec!["grp"]);
        assert!(!ks.shared_secret_exists("grp"));
        assert!(!ks.identity_exists("me"));

        assert!(matches!(
            ks.remove_identity_cascade("ghost"),
            Err(KeystoreError::NotFound(_))
        ));
    }

    #[test]
    fn remove_contact_cascade_takes_member_groups_only() {
        let (_dirs, stores, _seeds) = build_group(2, "grp");
        let ks = &stores[0];
        // A contact that is in no group
        let stranger = crypto::public_identity_from_seed(&[9u8; SEED_BYTES]);
        ks.add_contact("stranger", &stranger).unwrap();

        assert_eq!(
            ks.remove_contact_cascade("stranger").unwrap(),
            Vec::<String>::new()
        );
        assert!(ks.shared_secret_exists("grp"));

        // "p1" is the sole member of "grp" on store 0 -> cascade removes it
        assert_eq!(ks.remove_contact_cascade("p1").unwrap(), vec!["grp"]);
        assert!(!ks.shared_secret_exists("grp"));
        assert!(!ks.contact_exists("p1"));

        assert!(matches!(
            ks.remove_contact_cascade("ghost"),
            Err(KeystoreError::NotFound(_))
        ));
    }

    #[test]
    fn cascade_skips_unreadable_group_state() {
        let (_dirs, stores, _seeds) = build_group(2, "grp");
        let ks = &stores[0];
        // Corrupt the state file: the cascade must still remove the identity
        fs::write(ks.state_path("grp"), b"not json").unwrap();
        assert_eq!(
            ks.remove_identity_cascade("me").unwrap(),
            Vec::<String>::new()
        );
        assert!(!ks.identity_exists("me"));
        // The (corrupt) group dir was left in place
        assert!(ks.shared_secret_dir("grp").is_dir());
    }

    #[test]
    fn tampered_peer_token_in_state_is_rejected_on_reconstruct() {
        let (_dirs, stores, _seeds) = build_group(2, "grp");
        // Corrupt peer 0's stored signature on store[0]
        let path = stores[0].state_path("grp");
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let sig = rec["peers"][0]["signature"].as_str().unwrap().to_string();
        let mut bytes = hex::decode(&sig).unwrap();
        bytes[10] ^= 0xff;
        rec["peers"][0]["signature"] = serde_json::Value::String(hex::encode(bytes));
        fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

        let st = stores[0].load_shared_secret("grp").unwrap();
        let seed = stores[0].load_seed("me", "pw").unwrap();
        assert!(stores[0].reconstruct_shared_secret(&st, &seed).is_err());
    }
}
