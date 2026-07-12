//! Keystore-location resolution, user settings, and the on-disk config
//! **pointer**.
//!
//! The machine holds a keystore *location*, never a keystore secret. Data lives
//! wherever the pointer says (a USB key at `/foo`, say); the pointer itself
//! lives in a strict-subset TOML file under `$XDG_CONFIG_HOME/sesh/config.toml`
//! (default `~/.config/sesh/config.toml`) and records a path plus the expected
//! keystore identity (UUID)-- never a secret.
//!
//! That same file carries the user's [`Settings`]. It is per-machine, which is
//! what a setting like `linux_paste_count` (a property of the desktop, not of
//! the secrets) wants to be: it does not belong to a keystore and does not
//! travel into a backup. Every key it may contain is in [`KNOWN_KEYS`], so a
//! typo is an error rather than a preference that silently never applies.
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

/// The one config filename, used in two roles: the user's config under
/// `~/.config/sesh/` (the keystore pointer plus [`Settings`]) and the identity
/// *marker* inside a keystore (`id`). The `default_keystore_*` keys are legal
/// only in the user config (see [`crate::keystore`]).
pub const CONFIG_FILE: &str = "config.toml";

/// Every key the user's `config.toml` may carry. Anything else is a typo, and
/// [`read_user_config`] says so rather than ignoring a line the user wrote
/// expecting it to take effect.
pub const KNOWN_KEYS: [&str; 3] = [
    "default_keystore_path",
    "default_keystore_id",
    "linux_paste_count",
];

/// The user's preferences, read from `~/.config/sesh/config.toml`. Every field
/// is optional, so an absent file behaves exactly like an empty one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// Clear the clipboard after this many pastes, on Linux (X11/Wayland).
    ///
    /// The clipboard there is *request-served*: the copying process stays alive
    /// and hands the secret to each application that pastes, so it can count
    /// the requests and drop the selection after `n` of them. `copy` still runs
    /// its zeroing countdown and still zeroes on timeout or a keypress; the
    /// budget only lets the clipboard clear **earlier**.
    ///
    /// macOS has no equivalent (`NSPasteboard` never reports a read), so this
    /// is ignored there. Wayland's `wl-copy` serves at most one paste, so only
    /// `1` is meaningful on it; X11's `xclip` takes any count.
    pub linux_paste_count: Option<u32>,
}

/// Read the user's [`Settings`]. An absent config file is the defaults; a
/// malformed one, an unknown key, or an unusable value is an error.
pub fn settings() -> Result<Settings, String> {
    let Some((path, kv)) = read_user_config()? else {
        return Ok(Settings::default());
    };
    let linux_paste_count = match kv.get("linux_paste_count") {
        None => None,
        Some(v) => {
            let n: u32 = v
                .parse()
                .map_err(|_| format!("{}: linux_paste_count must be a number", path.display()))?;
            if n == 0 {
                // "Clear before the first paste" is just a broken copy
                return Err(format!(
                    "{}: linux_paste_count must be at least 1",
                    path.display()
                ));
            }
            Some(n)
        }
    };
    Ok(Settings { linux_paste_count })
}

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

/// The full path to the user config (`~/.config/sesh/config.toml`)
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join(CONFIG_FILE))
}

/// The user's `config.toml`, parsed: where it is, and what it says.
type UserConfig = (PathBuf, BTreeMap<String, String>);

/// Read and parse the user's `config.toml` once, or `None` when there is no
/// such file. Both the keystore pointer ([`read_config`]) and the preferences
/// ([`settings`]) come from here, so the permission check and the unknown-key
/// check apply to every reader.
///
/// The config is trusted input (whoever edits it redirects future secret
/// writes), so one that is not owned by the user or is group/world-writable is
/// refused outright.
fn read_user_config() -> Result<Option<UserConfig>, String> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Cannot read {}: {e}", path.display())),
    };
    check_config_perms(&path)?;

    let kv = parse_kv(&contents).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(unknown) = kv.keys().find(|k| !KNOWN_KEYS.contains(&k.as_str())) {
        return Err(format!(
            "{}: unknown setting `{unknown}` (known: {})",
            path.display(),
            KNOWN_KEYS.join(", ")
        ));
    }
    Ok(Some((path, kv)))
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
    let Some((path, kv)) = read_user_config()? else {
        return Ok(None);
    };
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
/// ignored; every other line must be `key = "value"` (a double-quoted string)
/// or `key = 12` (a bare non-negative integer). No sections, arrays, floats, or
/// escapes: the file holds a path, an id, and a small count, so the grammar
/// stays minimal on purpose. An integer comes back as its digits, for the
/// caller to parse into whatever width it wants.
///
/// Shared by the user config and the in-keystore identity marker.
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
        let inner = match value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            Some(s) => {
                if s.contains('"') {
                    return Err(format!("Line {}: unsupported quote in value", i + 1));
                }
                s
            }
            // A bare integer, the one unquoted value the grammar admits
            None if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => value,
            None => {
                return Err(format!(
                    "Line {}: value must be a double-quoted string or a number",
                    i + 1
                ))
            }
        };
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

    // A bare non-negative integer is the one unquoted value the grammar takes,
    // so a count reads as a count (`linux_paste_count = 1`, not `= "1"`).
    #[test]
    fn parse_kv_reads_bare_integers() {
        let kv = parse_kv("linux_paste_count = 2\n").unwrap();
        assert_eq!(kv.get("linux_paste_count").unwrap(), "2");
        // Still no floats, signs, or barewords
        assert!(parse_kv("linux_paste_count = 1.5").is_err());
        assert!(parse_kv("linux_paste_count = -1").is_err());
        assert!(parse_kv("linux_paste_count = one").is_err());
    }

    // Every key the user config may carry is known; a typo is an error, not a
    // preference that silently never applies.
    #[test]
    fn the_known_keys_are_exactly_what_the_readers_look_for() {
        assert!(KNOWN_KEYS.contains(&"default_keystore_path"));
        assert!(KNOWN_KEYS.contains(&"default_keystore_id"));
        assert!(KNOWN_KEYS.contains(&"linux_paste_count"));
        assert_eq!(KNOWN_KEYS.len(), 3, "document any new key in config.toml.example");
    }
}
