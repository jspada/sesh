//! Encrypted whole-keystore backup and restore.
//!
//! `sesh backup <file>` bundles the `SESH_HOME` tree into a single file,
//! encrypted with **AES-256-GCM** under an **Argon2id** key derived from a
//! backup passphrase that is independent of any keypair password. `sesh restore
//! <file>` reverses it.
//!
//! The bundle is self-describing: a plaintext JSON envelope carries the KDF
//! parameters and salt/nonce, and the ciphertext is the AEAD sealing of a JSON
//! manifest `{ relative_path -> file bytes }`. The manifest, and hence every
//! filename and the encrypted seeds within, is confidential, so only the envelope
//! metadata is in the clear. On restore, each path is validated as a safe
//! relative path before anything is written.
//!
//! This is **not** quite a dumb file-tree packer. The manifest also carries a
//! [`MnemonicIdentity`] list: the keypairs whose seed was deliberately left out,
//! because their owner can restore it from 24 words. `restore` prompts for those
//! mnemonics, and lets the user optionally skip them. Skipped keypairs and the
//! groups they own are then absent from the restored tree, though the bundle
//! still holds everything but their seeds, so re-running `restore` recovers them.
//!
//! Restore is not transactional: [`apply_manifest`] writes the tree, then the
//! caller writes the identities. What the ordering buys is that a *wrong*
//! mnemonic (the common, recoverable mistake) is caught before the target is
//! touched. The bundle remains the source of truth and `restore --force` is
//! idempotent, so a later failure is re-runnable.
//!
//! # The other kind of backup
//!
//! This is the **centralized** one: the whole keystore, in one bundle, under a
//! passphrase you choose. It protects against a dead disk. It does not protect
//! against a dead disk *and* a forgotten passphrase.
//!
//! [`crate::export`] is the **decentralized** one: a single group, plus its
//! hd-secret registry, encrypted to the group's *membership* rather than to a
//! passphrase. There is no new secret to lose, because the key is the static
//! DH/Joux value over identity keys the members already pinned in each other's
//! keystores.
//!
//! They fail differently, which is why both exist. A bundle is lost with its
//! passphrase; an export is lost only when the whole group is lost. A bundle
//! holds seeds (except the mnemonic-derived ones it deliberately omits); an
//! export holds no seed, no group master and no password at all.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::keystore::{
    create_dir_secure, peek_version, write_atomic_secure, ARGON2_MAX_M_COST, ARGON2_MAX_P_COST,
    ARGON2_MAX_T_COST, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST,
};

const BACKUP_VERSION: u32 = 1;
const KDF_SALT_LEN: usize = 16;
const AEAD_NONCE_LEN: usize = 12;
const AEAD_KEY_LEN: usize = 32;
const KDF_ALGORITHM: &str = "argon2id";
const CIPHER_ALGORITHM: &str = "aes-256-gcm";
/// AEAD associated-data tag. Names a domain only; [`aad`] binds the version
/// numerically beside it.
const AAD_TAG: &[u8] = b"sesh-backup-aad";

/// Errors from backup / restore
#[derive(Debug)]
pub enum BackupError {
    /// Filesystem I/O error
    Io(std::io::Error),
    /// (De)serialization error
    Serde(serde_json::Error),
    /// AEAD authentication failed, wrong passphrase or a tampered bundle
    Decrypt,
    /// Argon2 key derivation failed
    Kdf(String),
    /// The bundle is malformed or uses an unsupported algorithm/version
    BadFormat(String),
    /// A manifest entry has an unsafe path (absolute or containing `..`)
    UnsafePath(String),
    /// The restore target already exists and is non-empty (use `--force`)
    TargetNotEmpty(String),
    /// The keystore to back up does not exist or holds no files
    NothingToBackup(String),
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackupError::Io(e) => write!(f, "Backup I/O error: {e}"),
            BackupError::Serde(e) => write!(f, "Backup serialization error: {e}"),
            BackupError::Decrypt => {
                write!(f, "Restore failed: wrong passphrase or tampered backup")
            }
            BackupError::Kdf(e) => write!(f, "Key derivation failed: {e}"),
            BackupError::BadFormat(e) => write!(f, "Malformed backup: {e}"),
            BackupError::UnsafePath(p) => {
                write!(f, "Backup contains an unsafe path and was rejected: {p}")
            }
            BackupError::TargetNotEmpty(p) => write!(
                f,
                "Refusing to restore over a non-empty keystore at {p} (pass --force to overwrite)"
            ),
            BackupError::NothingToBackup(p) => write!(f, "Nothing to back up at {p}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<std::io::Error> for BackupError {
    fn from(e: std::io::Error) -> Self {
        BackupError::Io(e)
    }
}
impl From<serde_json::Error> for BackupError {
    fn from(e: serde_json::Error) -> Self {
        BackupError::Serde(e)
    }
}

type Result<T> = std::result::Result<T, BackupError>;

#[derive(Serialize, Deserialize)]
struct Entry {
    path: String,
    data: String, // hex
}

/// A keypair whose seed was **left out** of the bundle because it is
/// mnemonic-derived, and everything `restore` needs to put it back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnemonicIdentity {
    /// The keypair's name in the keystore
    pub name: String,
    /// `crypto::identity_fingerprint` of its public identity, so `restore` can
    /// tell a valid mnemonic *for the wrong keypair* from the right one before
    /// it writes anything
    pub fingerprint: String,
    /// The shared-secret groups this keypair owns. Recorded at backup time so
    /// `restore` need not parse `state` files out of the manifest to work out
    /// what a skip must cascade to.
    pub groups: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    entries: Vec<Entry>,
    mnemonic_identities: Vec<MnemonicIdentity>,
}

/// A decrypted, path-validated bundle, ready for [`apply_manifest`].
///
/// Opaque on purpose: making `Manifest` public would expose its `Entry` list as
/// API for no reason. The one thing a caller needs before writing anything is
/// [`Bundle::mnemonic_identities`], to prompt for the seeds the bundle omits.
///
/// The `Drop` impl scrubs the decoded file bytes. That is defence in depth, not
/// seed protection: a bundle holds no plaintext seed at all (every `identity`
/// and `registry` in it is AEAD ciphertext and `state` is public) and
/// `serde_json` has already allocated copies this can never reach. The
/// `Zeroizing` plaintext buffer in [`read_manifest`] is what actually matters.
pub struct Bundle {
    manifest: Manifest,
}

impl Bundle {
    /// The keypairs whose seed the bundle omits, each with the fingerprint and
    /// owned groups `restore` needs.
    pub fn mnemonic_identities(&self) -> &[MnemonicIdentity] {
        &self.manifest.mnemonic_identities
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        for entry in &mut self.manifest.entries {
            entry.data.zeroize();
            entry.path.zeroize();
        }
    }
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
struct BackupFile {
    version: u32,
    kdf: KdfRecord,
    cipher_algorithm: String,
    nonce: String,
    ciphertext: String,
}

/// Bundle the keystore rooted at `root` into an encrypted file at `out`,
/// omitting every path under `skip`. Returns the number of files backed up.
///
/// `skip` holds `/`-joined path **prefixes** (`keypairs/alice/identity`, say);
/// `mnemonic_identities` describes the keypairs whose seed those prefixes leave
/// out. All keystore knowledge lives in the caller: this module only packs what
/// it is handed.
pub fn create_backup(
    root: &Path,
    out: &Path,
    passphrase: &str,
    skip: &HashSet<String>,
    mnemonic_identities: Vec<MnemonicIdentity>,
) -> Result<usize> {
    let mut entries = Vec::new();
    collect_files(root, root, skip, &mut entries)?;
    if entries.is_empty() {
        return Err(BackupError::NothingToBackup(root.display().to_string()));
    }
    let count = entries.len();

    let manifest = Manifest {
        version: BACKUP_VERSION,
        entries,
        mnemonic_identities,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&manifest)?);

    let mut salt = [0u8; KDF_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase.as_bytes(), &salt)?;
    let aad = aad();
    let ciphertext = aead_encrypt(&*key, &nonce, &plaintext, &aad)?;

    let file = BackupFile {
        version: BACKUP_VERSION,
        kdf: KdfRecord {
            algorithm: KDF_ALGORITHM.into(),
            salt: hex::encode(salt),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        },
        cipher_algorithm: CIPHER_ALGORITHM.into(),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    };
    let json = serde_json::to_vec_pretty(&file)?;
    // Permission at 0600 since a backup holds the encrypted seeds;
    // the bundle is as sensitive as the keystore itself.
    write_atomic_secure(out, &json).map_err(|e| BackupError::BadFormat(e.to_string()))?;
    Ok(count)
}

/// Refuse a non-empty restore target unless `force`.
///
/// Exported so `restore` can run this guard **first**, before the passphrase
/// prompt and any 24-word mnemonic prompts. It must not drift behind them!
pub fn check_target_empty(root: &Path, force: bool) -> Result<()> {
    if !force && dir_has_files(root)? {
        return Err(BackupError::TargetNotEmpty(root.display().to_string()));
    }
    Ok(())
}

/// Decrypt and structurally validate the bundle at `input`, writing nothing.
///
/// Split from [`apply_manifest`] so a caller can inspect
/// [`Bundle::mnemonic_identities`] and prompt for what it needs while the target
/// is still untouched. Every path is validated here too, preserving the
/// "validate before writing anything" discipline.
pub fn read_manifest(input: &Path, passphrase: &str) -> Result<Bundle> {
    let bytes = fs::read(input)?;
    let envelope_version = peek_version(&bytes)?;
    if envelope_version != BACKUP_VERSION {
        return Err(BackupError::BadFormat(format!(
            "Unsupported backup version {envelope_version}"
        )));
    }
    let file: BackupFile = serde_json::from_slice(&bytes)?;
    if file.kdf.algorithm != KDF_ALGORITHM {
        return Err(BackupError::BadFormat(format!(
            "Unsupported KDF algorithm '{}'",
            file.kdf.algorithm
        )));
    }
    if file.cipher_algorithm != CIPHER_ALGORITHM {
        return Err(BackupError::BadFormat(format!(
            "Unsupported cipher algorithm '{}'",
            file.cipher_algorithm
        )));
    }
    // Decrypt with the parameters the bundle was written with (so a future
    // change to the defaults cannot lock old backups out), bounded so a
    // tampered file cannot demand absurd resources; the same discipline
    // `Keystore::load_seed` keeps for identity records.
    if file.kdf.m_cost > ARGON2_MAX_M_COST
        || file.kdf.t_cost > ARGON2_MAX_T_COST
        || file.kdf.p_cost > ARGON2_MAX_P_COST
    {
        return Err(BackupError::BadFormat(
            "stored Argon2 parameters exceed the accepted bounds".into(),
        ));
    }
    let salt = decode_hex(&file.kdf.salt, "salt")?;
    let nonce = decode_hex(&file.nonce, "nonce")?;
    let ct = decode_hex(&file.ciphertext, "ciphertext")?;
    let key = derive_key_with(
        passphrase.as_bytes(),
        &salt,
        file.kdf.m_cost,
        file.kdf.t_cost,
        file.kdf.p_cost,
    )?;
    let plaintext = Zeroizing::new(aead_decrypt(&*key, &nonce, &ct, &aad())?);
    let manifest_version = peek_version(&plaintext)?;
    if manifest_version != BACKUP_VERSION {
        return Err(BackupError::BadFormat(format!(
            "Unsupported manifest version {manifest_version}"
        )));
    }
    let manifest: Manifest = serde_json::from_slice(&plaintext)?;

    // Fail closed on traversal before the caller can act on anything
    for e in &manifest.entries {
        safe_relative(&e.path)?;
    }
    Ok(Bundle { manifest })
}

/// Write `bundle`'s files into the keystore rooted at `root`, omitting every
/// path under `skip`. Returns the number of files written.
///
/// Takes no `force`: emptying the target is `restore`'s decision, made before
/// this is called. `skip` is an argument, not a deletion instruction; it only
/// says what *not* to write.
pub fn apply_manifest(bundle: &Bundle, root: &Path, skip: &HashSet<String>) -> Result<usize> {
    // Validate every path BEFORE writing anything (fail closed on traversal).
    let mut planned: Vec<(PathBuf, Vec<u8>)> = Vec::with_capacity(bundle.manifest.entries.len());
    for e in &bundle.manifest.entries {
        if is_skipped(&e.path, skip) {
            continue;
        }
        let rel = safe_relative(&e.path)?;
        let data = decode_hex(&e.data, "file data")?;
        planned.push((root.join(rel), data));
    }
    for (path, data) in &planned {
        if let Some(parent) = path.parent() {
            create_dir_secure(parent).map_err(|e| BackupError::BadFormat(e.to_string()))?;
        }
        // A restore legitimately replaces existing files; write_atomic_secure
        // uses create_new for its temp sibling, then renames over the target.
        let _ = fs::remove_file(path);
        write_atomic_secure(path, data).map_err(|e| BackupError::BadFormat(e.to_string()))?;
    }
    Ok(planned.len())
}

/// Whether the `/`-joined `rel` path is covered by a `skip` **prefix**.
///
/// Matched on the joined string, not a `PathBuf`, so there is no separator
/// mismatch to get wrong. The trailing-`/` test is what keeps a skip of
/// `keypairs/n` from also catching `keypairs/n2`.
fn is_skipped(rel: &str, skip: &HashSet<String>) -> bool {
    skip.iter()
        .any(|s| rel == s || rel.starts_with(&format!("{s}/")))
}

/// Recursively gather every regular file under `dir`, keyed by its path
/// relative to `base`, using `/` separators. Paths under a `skip` prefix are
/// left out of the bundle entirely.
fn collect_files(
    base: &Path,
    dir: &Path,
    skip: &HashSet<String>,
    out: &mut Vec<Entry>,
) -> Result<()> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(BackupError::Io(e)),
    };
    for entry in rd {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            collect_files(base, &path, skip, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|_| BackupError::BadFormat("Path escaped the keystore root".into()))?;
            let rel_str = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if is_skipped(&rel_str, skip) {
                continue;
            }
            out.push(Entry {
                path: rel_str,
                data: hex::encode(fs::read(&path)?),
            });
        }
        // Symlinks and other special files are intentionally skipped. They are
        // not in the bundle, and `restore --force` destroys them.
    }
    Ok(())
}

/// Turn a stored `/`-separated relative path into a safe [`PathBuf`], rejecting
/// absolute paths and any `..` / root components.
fn safe_relative(p: &str) -> Result<PathBuf> {
    if p.is_empty() {
        return Err(BackupError::UnsafePath(p.to_string()));
    }
    let mut out = PathBuf::new();
    for part in p.split('/') {
        if part.is_empty() || part == "." {
            return Err(BackupError::UnsafePath(p.to_string()));
        }
        let candidate = Path::new(part);
        let mut comps = candidate.components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(c)), None) => out.push(c),
            _ => return Err(BackupError::UnsafePath(p.to_string())),
        }
    }
    Ok(out)
}

/// Whether `dir` exists and contains at least one entry
fn dir_has_files(dir: &Path) -> Result<bool> {
    match fs::read_dir(dir) {
        Ok(mut rd) => Ok(rd.next().is_some()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(BackupError::Io(e)),
    }
}

fn aad() -> Vec<u8> {
    let mut a = AAD_TAG.to_vec();
    a.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    a
}

/// Derive the AEAD key with this build's default Argon2id parameters (the
/// backup path. New bundles always use the current defaults).
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    derive_key_with(password, salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
}

/// Derive the AEAD key with explicit Argon2id parameters (the restore path —
/// honors what the bundle was written with; bounds-checked by the caller).
fn derive_key_with(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(AEAD_KEY_LEN))
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    Ok(key)
}

fn aead_encrypt(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| BackupError::Kdf(e.to_string()))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| BackupError::Decrypt)
}

fn aead_decrypt(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| BackupError::Kdf(e.to_string()))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| BackupError::Decrypt)
}

fn decode_hex(s: &str, field: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|e| BackupError::BadFormat(format!("{field}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(root: &Path, rel: &str, data: &[u8]) {
        let path = root.join(rel);
        create_dir_secure(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }

    // No skips, no omitted identities, the plain whole-tree backup
    fn backup_all(root: &Path, out: &Path, passphrase: &str) -> Result<usize> {
        create_backup(root, out, passphrase, &HashSet::new(), Vec::new())
    }

    // The old `restore_backup`, recomposed from the three exported pieces
    fn restore_all(input: &Path, root: &Path, passphrase: &str, force: bool) -> Result<usize> {
        check_target_empty(root, force)?;
        let bundle = read_manifest(input, passphrase)?;
        apply_manifest(&bundle, root, &HashSet::new())
    }

    fn skip_set(paths: &[&str]) -> HashSet<String> {
        paths.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn round_trips_the_whole_tree() {
        let src = tempdir().unwrap();
        write(src.path(), "keypairs/me/identity", b"secret-identity");
        write(src.path(), "contacts/bob/identity", b"bob-pubkey");
        write(src.path(), "shared-secrets/grp/state", b"group-state");

        let outdir = tempdir().unwrap();
        let out = outdir.path().join("backup.sesh");
        let n = backup_all(src.path(), &out, "pw").unwrap();
        assert_eq!(n, 3);

        // The bundle must not leak file contents in the clear
        let raw = fs::read_to_string(&out).unwrap();
        assert!(!raw.contains("secret-identity"));

        let dst = tempdir().unwrap();
        let restored = restore_all(&out, dst.path(), "pw", false).unwrap();
        assert_eq!(restored, 3);
        assert_eq!(
            fs::read(dst.path().join("keypairs/me/identity")).unwrap(),
            b"secret-identity"
        );
        assert_eq!(
            fs::read(dst.path().join("shared-secrets/grp/state")).unwrap(),
            b"group-state"
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let src = tempdir().unwrap();
        write(src.path(), "keypairs/me/identity", b"x");
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        backup_all(src.path(), &out, "right").unwrap();
        let dst = tempdir().unwrap();
        assert!(matches!(
            restore_all(&out, dst.path(), "wrong", false),
            Err(BackupError::Decrypt)
        ));
    }

    #[test]
    fn refuses_non_empty_target_without_force() {
        let src = tempdir().unwrap();
        write(src.path(), "keypairs/me/identity", b"x");
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        backup_all(src.path(), &out, "pw").unwrap();

        let dst = tempdir().unwrap();
        write(dst.path(), "keypairs/other/identity", b"pre-existing");
        assert!(matches!(
            check_target_empty(dst.path(), false),
            Err(BackupError::TargetNotEmpty(_))
        ));
        // The guard runs before the passphrase is even read
        assert!(check_target_empty(dst.path(), true).is_ok());
        assert!(restore_all(&out, dst.path(), "pw", true).is_ok());
    }

    // `skip` holds prefixes, matched on the `/`-joined relative path. A skip of
    // `keypairs/n` must never also catch `keypairs/n2`.
    #[test]
    fn skip_prefixes_match_whole_path_components_only() {
        let skip = skip_set(&["keypairs/n", "keypairs/alice/identity"]);
        assert!(is_skipped("keypairs/n", &skip));
        assert!(is_skipped("keypairs/n/registry", &skip));
        assert!(is_skipped("keypairs/alice/identity", &skip));
        assert!(!is_skipped("keypairs/n2", &skip));
        assert!(!is_skipped("keypairs/n2/registry", &skip));
        assert!(!is_skipped("keypairs/alice/registry", &skip));
        assert!(!is_skipped("keypairs/alice/identity2", &skip));
    }

    #[test]
    fn a_skipped_path_never_enters_the_bundle() {
        let src = tempdir().unwrap();
        write(src.path(), "keypairs/mn/identity", b"mnemonic-seed");
        write(src.path(), "keypairs/mn/registry", b"mn-registry");
        write(src.path(), "keypairs/mn2/identity", b"other-seed");
        write(src.path(), "config.toml", b"id = \"x\"");

        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        let n = create_backup(
            src.path(),
            &out,
            "pw",
            &skip_set(&["keypairs/mn/identity"]),
            vec![MnemonicIdentity {
                name: "mn".into(),
                fingerprint: "fpr".into(),
                groups: vec!["grp".into()],
            }],
        )
        .unwrap();
        assert_eq!(n, 3, "the skipped identity is not counted");

        let dst = tempdir().unwrap();
        let bundle = read_manifest(&out, "pw").unwrap();
        // The manifest records what it left out, and why
        assert_eq!(bundle.mnemonic_identities().len(), 1);
        assert_eq!(bundle.mnemonic_identities()[0].name, "mn");
        assert_eq!(bundle.mnemonic_identities()[0].groups, ["grp"]);

        apply_manifest(&bundle, dst.path(), &HashSet::new()).unwrap();
        assert!(
            !dst.path().join("keypairs/mn/identity").exists(),
            "seed omitted"
        );
        assert!(
            dst.path().join("keypairs/mn/registry").is_file(),
            "registry kept"
        );
        // The prefix must not have caught the sibling keypair
        assert!(dst.path().join("keypairs/mn2/identity").is_file());
    }

    // A restore-side skip prunes the tree without touching the bundle: the
    // keypair's whole directory, and the groups it owns, simply are not written.
    #[test]
    fn apply_manifest_honours_a_restore_side_skip() {
        let src = tempdir().unwrap();
        write(src.path(), "keypairs/mn/registry", b"mn-registry");
        write(src.path(), "keypairs/other/identity", b"other");
        write(src.path(), "shared-secrets/grp/state", b"state");
        write(src.path(), "shared-secrets/grp/registry", b"registry");
        write(src.path(), "shared-secrets/kept/state", b"kept");

        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        backup_all(src.path(), &out, "pw").unwrap();

        let dst = tempdir().unwrap();
        let bundle = read_manifest(&out, "pw").unwrap();
        let n = apply_manifest(
            &bundle,
            dst.path(),
            &skip_set(&["keypairs/mn", "shared-secrets/grp"]),
        )
        .unwrap();
        assert_eq!(n, 2);
        assert!(!dst.path().join("keypairs/mn").exists());
        assert!(!dst.path().join("shared-secrets/grp").exists());
        assert!(dst.path().join("keypairs/other/identity").is_file());
        assert!(dst.path().join("shared-secrets/kept/state").is_file());
    }

    #[test]
    fn rejects_unsafe_paths_in_a_manifest() {
        for bad in ["../evil", "/etc/passwd", "a/../../b", ""] {
            assert!(
                matches!(safe_relative(bad), Err(BackupError::UnsafePath(_))),
                "{bad:?} must be rejected"
            );
        }
        assert!(safe_relative("keypairs/me/identity").is_ok());
    }

    // Seal `plaintext` into a well-formed envelope at `out` under `passphrase`,
    // bypassing `create_backup` so the manifest can be anything at all.
    fn seal_envelope(out: &Path, passphrase: &str, plaintext: &[u8]) {
        seal_envelope_with_kdf(
            out,
            passphrase,
            plaintext,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        );
    }

    // As [`seal_envelope`], but with explicit Argon2 costs recorded (and used),
    // so a bundle written under *different* parameters can be fabricated.
    fn seal_envelope_with_kdf(
        out: &Path,
        passphrase: &str,
        plaintext: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) {
        let mut salt = [0u8; KDF_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let key = derive_key_with(passphrase.as_bytes(), &salt, m_cost, t_cost, p_cost).unwrap();
        let ct = aead_encrypt(&*key, &nonce, plaintext, &aad()).unwrap();
        let file = BackupFile {
            version: BACKUP_VERSION,
            kdf: KdfRecord {
                algorithm: KDF_ALGORITHM.into(),
                salt: hex::encode(salt),
                m_cost,
                t_cost,
                p_cost,
            },
            cipher_algorithm: CIPHER_ALGORITHM.into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ct),
        };
        fs::write(out, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    }

    // Restore derives the key from the bundle's **stored** KDF parameters, not
    // this build's defaults, so a bundle written under different (still sane)
    // costs keeps decrypting after the `ARGON2_*` constants are retuned. Before
    // this, the stored parameters were decorative, and any retune would have
    // turned every old backup into "wrong passphrase" at the worst possible
    // moment.
    #[test]
    fn restore_honours_the_stored_kdf_parameters() {
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        let manifest = br#"{"version":1,"entries":[],"mnemonic_identities":[]}"#;
        // Cheap but valid costs, deliberately unlike the build defaults
        assert_ne!((8 * 1024, 1), (ARGON2_M_COST, ARGON2_T_COST));
        seal_envelope_with_kdf(&out, "pw", manifest, 8 * 1024, 1, 1);
        assert!(read_manifest(&out, "pw").is_ok());
        // And the passphrase still gates it
        assert!(matches!(
            read_manifest(&out, "wrong"),
            Err(BackupError::Decrypt)
        ));
    }

    // Stored parameters are honored but **bounded**: a tampered envelope must
    // not be able to demand absurd resources before the passphrase is even
    // checked. Rejected up front, before any key derivation runs.
    #[test]
    fn restore_rejects_stored_kdf_parameters_beyond_the_bounds() {
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        let manifest = br#"{"version":1,"entries":[],"mnemonic_identities":[]}"#;
        seal_envelope_with_kdf(&out, "pw", manifest, 8 * 1024, 1, 1);
        // Rewrite the plaintext envelope's costs past the cap, as an attacker
        // would (no key needed, the KDF record is outside the ciphertext).
        let mut rec: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        rec["kdf"]["m_cost"] = serde_json::json!(ARGON2_MAX_M_COST + 1);
        fs::write(&out, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();
        // `Bundle` has no `Debug` (deliberately), so match the error side only
        match read_manifest(&out, "pw") {
            Err(BackupError::BadFormat(m)) => assert!(m.contains("Argon2"), "got {m:?}"),
            Err(other) => panic!("expected BadFormat, got {other:?}"),
            Ok(_) => panic!("expected BadFormat, got a decrypted bundle"),
        }
    }

    #[test]
    fn envelope_version_is_checked_before_the_record_parses() {
        // A future envelope bumps its version and reshapes its body. The old
        // build must say "unsupported version", not die inside serde.
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        fs::write(&out, br#"{"version":99,"future_field":true}"#).unwrap();
        let dst = tempdir().unwrap();
        match restore_all(&out, dst.path(), "pw", false) {
            Err(BackupError::BadFormat(m)) => assert!(m.contains("99"), "got {m:?}"),
            other => panic!("expected an unsupported-version error, got {other:?}"),
        }
    }

    #[test]
    fn manifest_version_is_checked_before_the_manifest_parses() {
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        seal_envelope(&out, "pw", br#"{"version":99,"files":[]}"#);
        let dst = tempdir().unwrap();
        match restore_all(&out, dst.path(), "pw", false) {
            Err(BackupError::BadFormat(m)) => assert!(m.contains("99"), "got {m:?}"),
            other => panic!("expected an unsupported-version error, got {other:?}"),
        }
        assert!(
            !dir_has_files(dst.path()).unwrap(),
            "nothing may be written"
        );
    }

    #[test]
    fn empty_keystore_is_nothing_to_back_up() {
        let src = tempdir().unwrap();
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("b.sesh");
        assert!(matches!(
            backup_all(src.path(), &out, "pw"),
            Err(BackupError::NothingToBackup(_))
        ));
    }
}
