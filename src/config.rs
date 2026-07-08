//! Keystore-location resolution and the on-disk config **pointer**.
//!
//! The machine holds a keystore *location*, never a keystore secret. Data lives
//! wherever the pointer says (a USB key at `/foo`, say); the pointer itself
//! lives in a strict-subset TOML file under `$XDG_CONFIG_HOME/sesh/config.toml`
//! (default `~/.config/sesh/config.toml`) and records a path plus the expected
//! keystore identity (UUID)-- never a secret.
//!
//! Resolution is a linear precedence chain (highest first):
//!
//! ```text
//! --keystore <dir>          # a data dir; never read for settings
//! > $SESH_HOME
//! > config.toml: keystore = "/abs/path"   # absolute path required
//! > ~/.sesh
//! ```
//!
//! Only the `config.toml` branch carries an expected id, so only it triggers
//! the open-time identity check (see [`Source`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The one config filename, used in two roles: the redirect *pointer* under
/// `~/.config/sesh/` (`default_keystore_path` [+ optional `default_keystore_id`])
/// and the identity *marker* inside a keystore (`id`). The `default_keystore_*`
/// keys are legal only in the pointer (see [`crate::keystore`]).
pub const CONFIG_FILE: &str = "config.toml";

/// Where a resolved keystore path came from. This drives both error wording
/// (an unavailable USB pointer reads differently from a missing default store)
/// and whether the identity (UUID) check applies-- only [`Source::Config`]
/// carries an expected id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `--keystore <dir>` on the command line
    Flag,
    /// The `$SESH_HOME` environment variable
    Env,
    /// The `keystore = ...` pointer in `config.toml`
    Config,
    /// The `~/.sesh` fallback
    Default,
}

/// A resolved keystore location: the path, where it came from, and (only for a
/// config pointer) the keystore identity the pointer expects to find there.
#[derive(Clone, Debug)]
pub struct Location {
    /// The keystore root directory
    pub path: PathBuf,
    /// Which precedence rung produced [`Location::path`]
    pub source: Source,
    /// The UUID the config pointer expects the keystore to carry (config only)
    pub expected_id: Option<String>,
}

/// Resolve the keystore location from the precedence chain. `flag` is the
/// value of a `--keystore` override, if any.
pub fn resolve(flag: Option<PathBuf>) -> Result<Location, String> {
    if let Some(path) = flag {
        return Ok(Location {
            path,
            source: Source::Flag,
            expected_id: None,
        });
    }
    if let Some(p) = std::env::var_os("SESH_HOME") {
        return Ok(Location {
            path: PathBuf::from(p),
            source: Source::Env,
            expected_id: None,
        });
    }
    if let Some((path, expected_id)) = read_config()? {
        return Ok(Location {
            path,
            source: Source::Config,
            expected_id,
        });
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| "HOME is not set and SESH_HOME is unset".to_string())?;
    Ok(Location {
        path: PathBuf::from(home).join(".sesh"),
        source: Source::Default,
        expected_id: None,
    })
}

/// The directory holding `config.toml`: `$XDG_CONFIG_HOME/sesh` if set to an
/// absolute path, else `~/.config/sesh`. `None` if neither is resolvable.
pub fn config_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(&xdg);
        if p.is_absolute() {
            return Some(p.join("sesh"));
        }
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config").join("sesh"))
}

/// The full path to the config pointer (`~/.config/sesh/config.toml`)
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join(CONFIG_FILE))
}

/// Read the config pointer, returning `(keystore_path, expected_id)` from
/// `default_keystore_path` and the optional `default_keystore_id`. `None` if
/// there is no config file, or one without a `default_keystore_path` (so
/// resolution falls through to `~/.sesh`).
///
/// The config is trusted input (whoever edits it redirects future secret
/// writes) so a config that is not owned by the user or is group/world-
/// writable is refused outright.
pub fn read_config() -> Result<Option<(PathBuf, Option<String>)>, String> {
    let path = match config_path() {
        Some(p) => p,
        None => return Ok(None),
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Cannot read {}: {e}", path.display())),
    };
    check_config_perms(&path)?;

    let kv = parse_kv(&contents).map_err(|e| format!("{}: {e}", path.display()))?;
    let keystore = match kv.get("default_keystore_path") {
        Some(v) => v,
        // No path key then not a pointer; fall through to the default location
        None => return Ok(None),
    };
    let ks_path = PathBuf::from(keystore);
    if !ks_path.is_absolute() {
        return Err(format!(
            "{}: default_keystore_path must be absolute, got \"{keystore}\"",
            path.display()
        ));
    }
    Ok(Some((ks_path, kv.get("default_keystore_id").cloned())))
}

/// Refuse a config file that is not owned by the current user or is group/
/// world-writable. Either would let another party redirect our secret writes.
/// No-op on non-Unix (no ownership/permission model to enforce).
fn check_config_perms(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta =
            std::fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        // SAFETY: geteuid is always safe-- it reads the caller's effective uid
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(format!(
                "{} is not owned by you (uid {}, file owned by {}) - refusing to trust it",
                path.display(),
                euid,
                meta.uid()
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is group/world-writable (mode {:o}) - refusing to trust it; run `chmod 600` on it",
                path.display(),
                meta.mode() & 0o7777
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Parse a deliberately strict subset of TOML: blank lines and `#` comments are
/// ignored; every other line must be `key = "value"` (a double-quoted string).
/// No sections, arrays, integers, or escapes... The file holds a path and an id,
/// so the grammar stays minimal on purpose. Shared by the hand-written config
/// pointer and the in-keystore identity marker.
pub(crate) fn parse_kv(contents: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for (i, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected `key = \"value\"`", i + 1))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return Err(format!("Line {}: empty key", i + 1));
        }
        let inner = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| format!("Line {}: value must be a double-quoted string", i + 1))?;
        if inner.contains('"') {
            return Err(format!("Line {}: unsupported quote in value", i + 1));
        }
        map.insert(key.to_string(), inner.to_string());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv_reads_strings_ignoring_comments() {
        let kv = parse_kv(
            "# a comment\n\ndefault_keystore_path = \"/mnt/usb/sesh\"\ndefault_keystore_id = \"abc-123\"\n",
        )
        .unwrap();
        assert_eq!(kv.get("default_keystore_path").unwrap(), "/mnt/usb/sesh");
        assert_eq!(kv.get("default_keystore_id").unwrap(), "abc-123");
    }

    #[test]
    fn parse_kv_rejects_malformed_lines() {
        assert!(parse_kv("default_keystore_path /no/equals").is_err());
        assert!(parse_kv("default_keystore_path = bareword").is_err());
        assert!(parse_kv("= \"value\"").is_err());
    }
}
