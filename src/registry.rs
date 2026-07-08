//! The hd-secret **registry**: named, versioned, syncable derived-secret
//! *definitions* (recipes) forming a personal and group "password manager" layer.
//!
//! A definition is keyed by `(id, user)` and records an `epoch` (a
//! strictly-increasing version that is *also* the derivation index) plus the
//! formatting `params`. **No secret value and no `K` is ever stored**, but only the
//! recipe. The child secret is `hd_child(master, canonical(id, user, epoch))`
//! formatted by `params`; params never enter the derivation, so viewing an entry
//! in a different format needs no new version (`copy`/`reveal` take a
//! display-only `--mode` override).
//!
//! Because `params` never enter the derivation, a past epoch's *secret* is
//! always re-derivable but its *password* is not: the string depends on a recipe
//! that `rotate` overwrites in place and `create` overwrites on revival. The
//! [`Registry::archive`] keeps those superseded recipes so `copy --recover N`
//! and `reveal --recover N` can render the old password. Nothing about it is
//! secret-- it stores no key material, only formatting.
//!
//! This module is pure (no I/O): the encrypted at-rest storage lives in
//! [`crate::keystore`], and signed share-token sync lives in [`crate::protocol`].

use std::fmt;

use serde::{Deserialize, Serialize};

/// Current schema version of the registry **document**: its definitions and
/// their params, as they exist once decrypted.
///
/// Deliberately distinct from the version of the encrypted envelope that carries
/// the document on disk (`REGISTRY_AAD_VERSION` in [`crate::keystore`]). They are
/// two versions of two different things: this one bumps when a definition's
/// shape changes, that one when the file format around it does.
///
/// **Still `1` after the archive landed.** [`Registry::load`][crate::keystore]
/// compares this for *equality*, so a bump makes every existing registry
/// unreadable rather than migrating it. [`Registry::archive`] is therefore
/// additive: `#[serde(default)]` reads a v1 document into an empty archive, and
/// `skip_serializing_if` writes one back byte-identically. An older build
/// reading a newer document ignores the unknown field. It drops the archive on
/// the next save, which loses recovery history but corrupts nothing.
pub const REGISTRY_VERSION: u32 = 1;

/// Output-formatting parameters (never part of the derivation)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Output encoding (`hex`/`b58`/`b10`/`alpha`/`bip39`)
    pub mode: String,
    /// Optional trim length
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub length: Option<u64>,
    /// The characters to extend the mode's base alphabet with (positional modes
    /// only), so they are distributed uniformly through the output rather than
    /// appended. `None` = off.
    ///
    /// The **resolved set** is stored, never a bare "yes": bare `--symbols`
    /// records `format::SYMBOLS` itself. A later edit to that constant therefore
    /// cannot silently change the password of an existing definition.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub symbols: Option<String>,
    /// Optional fixed suffix, appended verbatim to the end
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub suffix: Option<String>,
}

impl Params {
    /// A human-readable one-line rendering of **every** param (for `show`,
    /// `create`, `rotate`, `list` and the `apply` summary).
    ///
    /// Every field is printed always, including the ones the user never typed
    /// and the ones that are off. Someone reading a definition wants to know
    /// exactly what the password looks like, and an omitted `--suffix` is
    /// indistinguishable from a suffix the renderer forgot to mention. So
    /// "absent" gets a spelling of its own: `--length none`, `--no-symbols`,
    /// `--suffix none`.
    ///
    /// The symbol set is always shown **verbatim**, never as a bare `--symbols`
    /// standing for "whatever this build's default is". The set's length and
    /// order are part of the recipe; a reader must be able to see them.
    ///
    /// This is display, not a shell command: the `none` spellings are not flags,
    /// and the quoting is for legibility rather than for `sh`.
    ///
    /// Equivalent to [`describe_with_rendered_length`](Self::describe_with_rendered_length)
    /// with no length to report: use that one wherever the secret is at hand.
    pub fn describe(&self) -> String {
        self.describe_with_rendered_length(None)
    }

    /// [`describe`](Self::describe), but annotating an untrimmed recipe with the
    /// character count `rendered` of the secret it currently produces.
    ///
    /// `--length none` says there is no trim; it does not say how long the
    /// password is. A reader wants both, so callers that hold the derived secret
    /// pass its length and get `--length none (79 chars)`.
    ///
    /// Deliberately *not* rendered as a bare `--length 79`. That would read as a
    /// value you could re-supply, and it is not one: `b10`, `b58` and `alpha`
    /// encode the secret as a big number, so the natural length drifts with the
    /// value and would differ at the next epoch. The count is an observation
    /// about this epoch, not a part of the recipe-- and the parenthesis says so.
    pub fn describe_with_rendered_length(&self, rendered: Option<usize>) -> String {
        let length = match (self.length, rendered) {
            (Some(l), _) => format!("--length {l}"),
            (None, Some(n)) => format!("--length none ({n} chars)"),
            (None, None) => "--length none".to_string(),
        };
        let symbols = match &self.symbols {
            Some(set) => format!("--symbols='{set}'"),
            None => "--no-symbols".to_string(),
        };
        let suffix = match &self.suffix {
            Some(s) => format!("--suffix '{s}'"),
            None => "--suffix none".to_string(),
        };
        format!("--mode {} {length} {symbols} {suffix}", self.mode)
    }

    /// An unambiguous byte encoding of every param, for the recipe half of
    /// [`crypto::hd_fingerprint`][crate::crypto::hd_fingerprint].
    ///
    /// Each string is length-prefixed and each `Option` carries a presence tag,
    /// so no two distinct `Params` can encode to the same bytes. Without the
    /// prefixes, `--symbols='a' --suffix 'b'` and `--symbols='ab'` (no suffix)
    /// would collide; without the tags, `--length none` and `--length 0` would.
    /// Two recipes that fingerprint alike must *be* alike-- that is the entire
    /// claim the fingerprint makes.
    ///
    /// This is a hash input, not a storage format: nothing parses it back, and
    /// no on-disk or on-wire record contains it. Adding a field to `Params`
    /// therefore changes every HD fingerprint and breaks nothing fingerprints
    /// are computed on the fly at display time and never persisted. It is the
    /// serde representation, not this one, that `REGISTRY_VERSION` governs.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let push_bytes = |b: &[u8], out: &mut Vec<u8>| {
            out.extend_from_slice(&(b.len() as u64).to_le_bytes());
            out.extend_from_slice(b);
        };
        push_bytes(self.mode.as_bytes(), &mut out);
        match self.length {
            Some(l) => {
                out.push(1);
                out.extend_from_slice(&l.to_le_bytes());
            }
            None => out.push(0),
        }
        for opt in [&self.symbols, &self.suffix] {
            match opt {
                Some(s) => {
                    out.push(1);
                    push_bytes(s.as_bytes(), &mut out);
                }
                None => out.push(0),
            }
        }
        out
    }
}

/// One registry definition. A tombstone marks a removed entry (kept, at an
/// advanced epoch, so a stale `create` cannot resurrect it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Definition {
    /// Service / label (e.g. `google.com`)
    pub id: String,
    /// Optional sub-account (e.g. `bob@google.com`); empty string = none
    pub user: String,
    /// Monotonic version and derivation index
    pub epoch: u64,
    /// Output-formatting params
    pub params: Params,
    /// Whether this entry has been removed
    #[serde(default)]
    pub tombstone: bool,
}

/// The in-memory registry: a set of `(id, user)`-keyed definitions, plus an
/// append-only archive of the recipes they used to have.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registry {
    /// Schema version
    pub version: u32,
    /// All definitions, live and tombstoned, **exactly one per `(id, user)`**
    ///
    /// `Registry::position` resolves a key to a single index, and `get`,
    /// `create`, `rotate`, `remove`, `classify` and `adopt` are all built on it.
    /// Archived recipes therefore live in [`Registry::archive`], never here: a
    /// second entry under one key would silently send `adopt` to the wrong row.
    pub entries: Vec<Definition>,
    /// Superseded recipes, so a password can be re-derived after the definition
    /// that formatted it is gone
    ///
    /// Every entry is a *live* recipe (`tombstone: false`) that was current at
    /// its `epoch` and is not any more, pushed by whichever of `rotate`,
    /// `remove`, `create` or `adopt` displaced it. Without this, `rotate`
    /// overwrites `params` in place and `create` overwrites the tombstone that
    /// held the last copy, so the recipe for every past epoch is unrecoverable
    /// and the password with it.
    ///
    /// Append-only and deduplicated by `(id, user, epoch)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archive: Vec<Definition>,
}

/// The recipe an entry *records*, as an archivable definition or `None` if it
/// records none.
///
/// A live entry at epoch `N` formats the secret at epoch `N`. A tombstone at
/// epoch `N` is a removal marker: no secret is derived at `N`, and the `params`
/// it still carries are the ones that were live at `N - 1`, because
/// [`Registry::remove`] bumps the epoch and leaves `params` untouched. Reading a
/// tombstone's own epoch as its recipe's epoch is an off-by-one that yields a
/// different password with no warning.  The fingerprint covers the epoch, so it
/// changes too, and there is nothing to compare it against.
///
/// `None` for a tombstone at epoch 0 or 1, which supersede nothing: `create`
/// starts at 1, so no secret was ever derived at 0.
fn recipe_of(def: &Definition) -> Option<Definition> {
    let epoch = if def.tombstone {
        def.epoch.checked_sub(1)?
    } else {
        def.epoch
    };
    if epoch == 0 {
        return None;
    }
    Some(Definition {
        epoch,
        tombstone: false,
        ..def.clone()
    })
}

/// How one incoming definition change relates to the local registry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The incoming change is newer (or the entry is unknown), adoptable
    Adopt,
    /// The incoming change is older than the local entry, ignore it
    Stale {
        /// The (newer) local epoch
        local_epoch: u64,
    },
    /// The local entry already has exactly this content at this epoch
    AlreadyApplied,
    /// Same epoch but different content, concurrent edits; the user decides
    Conflict,
}

/// Errors from registry operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// A live definition with this `(id, user)` already exists
    AlreadyExists(String),
    /// No live definition matched the given selector
    NotFound(String),
    /// The selector matched more than one live definition (need `--user`)
    Ambiguous(String),
    /// A supplied epoch did not strictly exceed the current one
    NonMonotonicEpoch {
        /// The current stored epoch
        current: u64,
        /// The rejected requested epoch
        requested: u64,
    },
    /// The epoch cannot advance past `u64::MAX` (a wrap would break the
    /// monotonicity that stale-change and tombstone protection rest on).
    EpochOverflow,
    /// No recipe (live or archived) was ever recorded for this epoch
    NoRecipeAt {
        /// The `(id, user)` selector, already formatted
        key: String,
        /// The epoch that has no recorded recipe
        epoch: u64,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::AlreadyExists(k) => {
                write!(
                    f,
                    "A definition for {k} already exists (use `rotate` to change it)"
                )
            }
            RegistryError::NotFound(k) => write!(f, "No stored definition for {k}"),
            RegistryError::Ambiguous(k) => {
                write!(f, "{k} matches multiple entries, specify --user")
            }
            RegistryError::NonMonotonicEpoch { current, requested } => write!(
                f,
                "Epoch must strictly increase: current is {current}, got {requested}"
            ),
            RegistryError::EpochOverflow => {
                write!(f, "Epoch is at its maximum and cannot advance")
            }
            RegistryError::NoRecipeAt { key, epoch } => write!(
                f,
                "No recorded recipe for {key} at epoch {epoch} - \
                 the password cannot be reproduced (see `list --archived`)"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Format an `(id, user)` selector for error messages
fn key(id: &str, user: &str) -> String {
    if user.is_empty() {
        format!("'{id}'")
    } else {
        format!("'{id}' (user '{user}')")
    }
}

impl Registry {
    /// An empty registry
    pub fn empty() -> Self {
        Registry {
            version: REGISTRY_VERSION,
            entries: Vec::new(),
            archive: Vec::new(),
        }
    }

    fn position(&self, id: &str, user: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|d| d.id == id && d.user == user)
    }

    /// Record `def` as a past recipe, unless `(id, user, epoch)` is already
    /// archived.
    ///
    /// First writer wins. The only way to reach a second, differing recipe for
    /// one epoch is a same-epoch params [`ApplyOutcome::Conflict`] (a state
    /// `classify` already declares unresolvable by the tool) so there is no
    /// principled reason to prefer the later record, and overwriting would let
    /// an adopted token quietly rewrite local recovery history.
    fn archive_push(&mut self, def: Definition) {
        let dup = self
            .archive
            .iter()
            .any(|a| a.id == def.id && a.user == def.user && a.epoch == def.epoch);
        if !dup {
            self.archive.push(def);
        }
    }

    /// Archive whatever recipe `entries[i]` currently records, before it is
    /// replaced. Call *after* any fallible step, so a failed mutation leaves the
    /// archive untouched.
    fn archive_superseded(&mut self, i: usize) {
        if let Some(recipe) = recipe_of(&self.entries[i]) {
            self.archive_push(recipe);
        }
    }

    /// The archived recipe for exactly `(id, user, epoch)`, if one was recorded
    ///
    /// Note this never returns the *current* entry: a recipe is archived only
    /// once it stops being current.
    pub fn archived(&self, id: &str, user: &str, epoch: u64) -> Option<&Definition> {
        self.archive
            .iter()
            .find(|d| d.id == id && d.user == user && d.epoch == epoch)
    }

    /// Every archived recipe, sorted by `(id, user, epoch)` with oldest epoch first
    pub fn archived_all(&self) -> Vec<&Definition> {
        let mut v: Vec<&Definition> = self.archive.iter().collect();
        v.sort_by(|a, b| {
            (a.id.as_str(), a.user.as_str(), a.epoch).cmp(&(
                b.id.as_str(),
                b.user.as_str(),
                b.epoch,
            ))
        });
        v
    }

    /// Every archived recipe for one `(id, user)`, oldest epoch first
    pub fn archived_for(&self, id: &str, user: &str) -> Vec<&Definition> {
        let mut v: Vec<&Definition> = self
            .archive
            .iter()
            .filter(|d| d.id == id && d.user == user)
            .collect();
        v.sort_by_key(|d| d.epoch);
        v
    }

    /// The live (non-tombstone) definition for exactly `(id, user)`, if any
    pub fn get(&self, id: &str, user: &str) -> Option<&Definition> {
        self.entries
            .iter()
            .find(|d| d.id == id && d.user == user && !d.tombstone)
    }

    /// All live definitions, sorted by `(id, user)`
    pub fn live(&self) -> Vec<&Definition> {
        let mut v: Vec<&Definition> = self.entries.iter().filter(|d| !d.tombstone).collect();
        v.sort_by(|a, b| (a.id.as_str(), a.user.as_str()).cmp(&(b.id.as_str(), b.user.as_str())));
        v
    }

    /// Resolve a single live entry by `id` and an optional `user`
    ///
    /// With `user = Some`, requires an exact match. With `user = None`, requires
    /// that exactly one live entry has this `id` (else ambiguous / not found).
    pub fn find_one(&self, id: &str, user: Option<&str>) -> Result<&Definition, RegistryError> {
        match user {
            Some(u) => self
                .get(id, u)
                .ok_or_else(|| RegistryError::NotFound(key(id, u))),
            None => {
                let matches: Vec<&Definition> = self
                    .entries
                    .iter()
                    .filter(|d| d.id == id && !d.tombstone)
                    .collect();
                match matches.len() {
                    0 => Err(RegistryError::NotFound(key(id, ""))),
                    1 => Ok(matches[0]),
                    _ => Err(RegistryError::Ambiguous(format!("'{id}'"))),
                }
            }
        }
    }

    /// Resolve the recipe that was current at `epoch`: the live entry if it
    /// still sits there, otherwise the archived one.
    ///
    /// This is what `copy --recover N` and `reveal --recover N` derive from. It
    /// **never falls back to the live entry's params for a different epoch**:
    /// those may not be the params that were in force at `epoch`, and a wrong
    /// recipe renders a wrong password. `hd_fingerprint`'s recipe half would
    /// register the substitution, but only for someone holding the right
    /// fingerprint to compare against, which is exactly what a recovery does
    /// not have. An absent recipe is an error, not a guess.
    ///
    /// A tombstone is never a candidate: it formats nothing (see `recipe_of`).
    /// `user = None` requires that exactly one user matches, as [`find_one`]
    /// does.
    ///
    /// [`find_one`]: Registry::find_one
    pub fn recipe_at(
        &self,
        id: &str,
        user: Option<&str>,
        epoch: u64,
    ) -> Result<&Definition, RegistryError> {
        let live = self
            .entries
            .iter()
            .filter(|d| d.id == id && !d.tombstone && d.epoch == epoch);
        let archived = self
            .archive
            .iter()
            .filter(|d| d.id == id && d.epoch == epoch);

        // Live first, so a recipe that is still current wins over any archived
        // record of the same epoch. One hit per user.
        let mut matches: Vec<&Definition> = Vec::new();
        for d in live.chain(archived) {
            if user.is_none_or(|u| d.user == u) && !matches.iter().any(|m| m.user == d.user) {
                matches.push(d);
            }
        }
        match matches.len() {
            0 => Err(RegistryError::NoRecipeAt {
                key: key(id, user.unwrap_or("")),
                epoch,
            }),
            1 => Ok(matches[0]),
            _ => Err(RegistryError::Ambiguous(format!("'{id}'"))),
        }
    }

    /// Create a new definition. Errors if a live one already exists. If a
    /// tombstone exists, the new entry revives at `tombstone.epoch + 1` (so it
    /// is monotonic); otherwise it starts at epoch 1.
    pub fn create(
        &mut self,
        id: &str,
        user: &str,
        params: Params,
    ) -> Result<&Definition, RegistryError> {
        match self.position(id, user) {
            Some(i) if !self.entries[i].tombstone => {
                Err(RegistryError::AlreadyExists(key(id, user)))
            }
            Some(i) => {
                let epoch = self.entries[i]
                    .epoch
                    .checked_add(1)
                    .ok_or(RegistryError::EpochOverflow)?;
                // The tombstone about to be overwritten is the last copy of the
                // pre-removal recipe. Archive it before it is gone.
                self.archive_superseded(i);
                self.entries[i] = Definition {
                    id: id.to_string(),
                    user: user.to_string(),
                    epoch,
                    params,
                    tombstone: false,
                };
                Ok(&self.entries[i])
            }
            None => {
                self.entries.push(Definition {
                    id: id.to_string(),
                    user: user.to_string(),
                    epoch: 1,
                    params,
                    tombstone: false,
                });
                Ok(self.entries.last().unwrap())
            }
        }
    }

    /// Advance a live entry to a new epoch (default `current + 1`), optionally
    /// replacing its params. An explicit `epoch` must strictly exceed the
    /// current one.
    pub fn rotate(
        &mut self,
        id: &str,
        user: &str,
        new_params: Option<Params>,
        epoch: Option<u64>,
    ) -> Result<&Definition, RegistryError> {
        let i = self
            .position(id, user)
            .filter(|&i| !self.entries[i].tombstone)
            .ok_or_else(|| RegistryError::NotFound(key(id, user)))?;
        let current = self.entries[i].epoch;
        let next = match epoch {
            None => current.checked_add(1).ok_or(RegistryError::EpochOverflow)?,
            Some(e) if e > current => e,
            Some(e) => {
                return Err(RegistryError::NonMonotonicEpoch {
                    current,
                    requested: e,
                })
            }
        };
        // `params` is replaced in place, so the outgoing recipe is archived here
        // or lost, even when only the epoch moves, since the old epoch's
        // password is no longer derivable from any live entry.
        self.archive_superseded(i);
        self.entries[i].epoch = next;
        if let Some(p) = new_params {
            self.entries[i].params = p;
        }
        Ok(&self.entries[i])
    }

    /// **Disaster recovery.** Overwrite `(id, user)` with `params` at exactly
    /// `epoch`, live, whatever the current epoch is and whether or not the entry
    /// is a tombstone. The one operation that breaks epoch monotonicity.
    ///
    /// There is no cryptographic consequence: the epoch is a public derivation
    /// index, and any holder of the master can already derive the child at any
    /// epoch. What it breaks is bookkeeping and it **cannot be synced**. A peer
    /// at a higher epoch classifies the resulting share token
    /// [`Stale`](ApplyOutcome::Stale) and ignores it silently, so every member
    /// must run the same command locally. The caller is responsible for saying
    /// so.
    ///
    /// The displaced definition is archived, so a recovery is itself recoverable.
    ///
    /// Rejects `u64::MAX`, which would leave every future `rotate` and `remove`
    /// failing on [`EpochOverflow`](RegistryError::EpochOverflow), and epoch 0,
    /// which never held a secret.
    pub fn recover_at(
        &mut self,
        id: &str,
        user: &str,
        epoch: u64,
        params: Params,
    ) -> Result<&Definition, RegistryError> {
        if epoch == 0 || epoch == u64::MAX {
            return Err(RegistryError::EpochOverflow);
        }
        let def = Definition {
            id: id.to_string(),
            user: user.to_string(),
            epoch,
            params,
            tombstone: false,
        };
        match self.position(id, user) {
            Some(i) => {
                // Same-epoch recovery *corrects* this epoch's recipe rather than
                // superseding it, exactly as a resolved conflict does.
                if self.entries[i].epoch != epoch {
                    self.archive_superseded(i);
                }
                self.entries[i] = def;
                Ok(&self.entries[i])
            }
            None => {
                self.entries.push(def);
                Ok(self.entries.last().unwrap())
            }
        }
    }

    /// Classify one incoming definition change against the local registry
    /// (pure inspection, see [`Registry::adopt`] to actually take it).
    ///
    /// Convergence is epoch-versioned: newer adopts, older is stale, and a
    /// same-epoch content difference is a conflict the **user** must resolve
    /// (the tool cannot know which version is "true"). Tombstones participate
    /// like any entry, so a stale `create` cannot resurrect a removed one.
    pub fn classify(
        &self,
        id: &str,
        user: &str,
        epoch: u64,
        params: &Params,
        tombstone: bool,
    ) -> ApplyOutcome {
        match self.position(id, user) {
            None => ApplyOutcome::Adopt,
            Some(i) => {
                let local = &self.entries[i];
                if epoch < local.epoch {
                    ApplyOutcome::Stale {
                        local_epoch: local.epoch,
                    }
                } else if epoch > local.epoch {
                    ApplyOutcome::Adopt
                } else if local.tombstone == tombstone && (tombstone || &local.params == params) {
                    // Same epoch, same content (params are irrelevant between
                    // two tombstones, the entry is gone either way).
                    ApplyOutcome::AlreadyApplied
                } else {
                    ApplyOutcome::Conflict
                }
            }
        }
    }

    /// Unconditionally set `(id, user)` to the given definition (used after the
    /// user approves an incoming change, including conflict resolution).
    pub fn adopt(&mut self, id: &str, user: &str, epoch: u64, params: Params, tombstone: bool) {
        let def = Definition {
            id: id.to_string(),
            user: user.to_string(),
            epoch,
            params,
            tombstone,
        };
        match self.position(id, user) {
            Some(i) => {
                // A same-epoch adopt is conflict resolution: the incoming recipe
                // *corrects* this epoch rather than superseding it, so archiving
                // the local one would file a losing recipe under an epoch the
                // winner now owns. Only a genuine epoch change supersedes.
                if self.entries[i].epoch != epoch {
                    self.archive_superseded(i);
                }
                self.entries[i] = def.clone();
            }
            None => self.entries.push(def.clone()),
        }
        // An incoming tombstone carries the pre-removal params (`remove` leaves
        // them intact and the share token ships them verbatim), so it asserts
        // the recipe that was live at `epoch - 1`. Record it even on a member
        // that never saw the `create`. This is what lets a peer who only ever
        // applied the removal recover the password.
        if tombstone {
            if let Some(recipe) = recipe_of(&def) {
                self.archive_push(recipe);
            }
        }
    }

    /// Absorb one archived recipe from elsewhere, first-writer-wins on
    /// `(id, user, epoch)`.
    ///
    /// The public face of `archive_push` for `shared-secret import`, which merges
    /// a peer's whole archive rather than one displaced recipe at a time. Share
    /// tokens ship no archive, so this is the only path by which a *foreign* recipe
    /// enters the local one and the dedup is why it cannot rewrite local recovery
    /// history: whatever the local `adopt` already filed under an epoch keeps it.
    pub fn absorb_archive(&mut self, def: Definition) {
        self.archive_push(def)
    }

    /// Tombstone a live entry at `current + 1` (an epoch-versioned removal),
    /// returning the tombstoned definition.
    pub fn remove(&mut self, id: &str, user: &str) -> Result<&Definition, RegistryError> {
        let i = self
            .position(id, user)
            .filter(|&i| !self.entries[i].tombstone)
            .ok_or_else(|| RegistryError::NotFound(key(id, user)))?;
        let next = self.entries[i]
            .epoch
            .checked_add(1)
            .ok_or(RegistryError::EpochOverflow)?;
        // After the fallible step, so an overflowing `remove` leaves no trace
        self.archive_superseded(i);
        self.entries[i].epoch = next;
        self.entries[i].tombstone = true;
        Ok(&self.entries[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(mode: &str) -> Params {
        Params {
            mode: mode.to_string(),
            length: None,
            symbols: None,
            suffix: None,
        }
    }

    /// `describe` is lossless: every field, every time. A reader inspecting a
    /// definition must be able to see exactly what the password looks like, and
    /// "not printed" must never be mistakable for "not set".
    #[test]
    fn describe_renders_every_param_including_the_absent_ones() {
        let p = |length, symbols: Option<&str>, suffix: Option<&str>| Params {
            mode: "b58".into(),
            length,
            symbols: symbols.map(str::to_string),
            suffix: suffix.map(str::to_string),
        };
        assert_eq!(
            p(None, None, None).describe(),
            "--mode b58 --length none --no-symbols --suffix none"
        );
        assert_eq!(
            p(Some(14), Some("!@#"), Some("Z9")).describe(),
            "--mode b58 --length 14 --symbols='!@#' --suffix 'Z9'"
        );
        // The set is shown verbatim, never as a bare `--symbols` standing for
        // whatever this build's default happens to be.
        assert_eq!(
            p(Some(14), Some(crate::format::SYMBOLS), None).describe(),
            format!(
                "--mode b58 --length 14 --symbols='{}' --suffix none",
                crate::format::SYMBOLS
            )
        );
    }

    /// An untrimmed recipe says nothing about how long the password *is*, so a
    /// caller holding the secret annotates it. An explicit trim already does.
    #[test]
    fn describe_annotates_an_untrimmed_recipe_with_its_rendered_length() {
        let untrimmed = Params {
            mode: "alpha".into(),
            length: None,
            symbols: None,
            suffix: None,
        };
        assert_eq!(
            untrimmed.describe_with_rendered_length(Some(79)),
            "--mode alpha --length none (79 chars) --no-symbols --suffix none"
        );
        // With no length to report, it degrades to the plain recipe.
        assert_eq!(
            untrimmed.describe_with_rendered_length(None),
            untrimmed.describe()
        );

        // An explicit trim is exact; a rendered count would be noise.
        let trimmed = Params {
            length: Some(14),
            ..untrimmed
        };
        assert_eq!(
            trimmed.describe_with_rendered_length(Some(14)),
            "--mode alpha --length 14 --no-symbols --suffix none"
        );
    }

    /// The encoding is injective: every field is length-prefixed and every
    /// `Option` tagged, so no two distinct recipes share an encoding. Each pair
    /// below collides under a naive concatenation.
    #[test]
    fn canonical_bytes_never_collides_between_distinct_params() {
        let p = |mode: &str, length, symbols: Option<&str>, suffix: Option<&str>| Params {
            mode: mode.to_string(),
            length,
            symbols: symbols.map(str::to_string),
            suffix: suffix.map(str::to_string),
        };
        // Distinct params, pairwise distinct encodings
        let all = [
            p("b58", None, None, None),
            // A present-but-empty string is not an absent one...
            p("b58", None, Some(""), None),
            p("b58", None, None, Some("")),
            // ...and `--length none` is not `--length 0`.
            p("b58", Some(0), None, None),
            p("b58", Some(1), None, None),
            // The symbols/suffix boundary cannot be slid
            p("b58", None, Some("a"), Some("b")),
            p("b58", None, Some("ab"), None),
            p("b58", None, None, Some("ab")),
            // The mode/length boundary cannot be slid either
            p("b5", None, None, None),
            p("b588", None, None, None),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(
                    a.canonical_bytes(),
                    b.canonical_bytes(),
                    "collision: {a:?} vs {b:?}"
                );
            }
        }
    }

    /// Deterministic, and equal exactly when the params are equal
    #[test]
    fn canonical_bytes_is_deterministic_and_tracks_equality() {
        let a = Params {
            symbols: Some("!@".into()),
            length: Some(14),
            ..params("b58")
        };
        let b = a.clone();
        assert_eq!(a.canonical_bytes(), a.canonical_bytes());
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        // Every field moves it.
        assert_ne!(
            a.canonical_bytes(),
            Params {
                mode: "hex".into(),
                ..a.clone()
            }
            .canonical_bytes()
        );
        assert_ne!(
            a.canonical_bytes(),
            Params {
                length: Some(15),
                ..a.clone()
            }
            .canonical_bytes()
        );
        assert_ne!(
            a.canonical_bytes(),
            Params {
                symbols: None,
                ..a.clone()
            }
            .canonical_bytes()
        );
        assert_ne!(
            a.canonical_bytes(),
            Params {
                suffix: Some("Z".into()),
                ..a
            }
            .canonical_bytes()
        );
    }

    /// `skip_serializing_if` omits `symbols` whenever it is off (the common
    /// case) so without `#[serde(default)]` every registry this code writes
    /// would fail to read back.
    #[test]
    fn params_with_symbols_off_round_trip_through_serde() {
        let off = params("b58");
        let json = serde_json::to_string(&off).unwrap();
        assert!(
            !json.contains("symbols"),
            "an off set must not be written: {json}"
        );
        assert_eq!(serde_json::from_str::<Params>(&json).unwrap(), off);

        let on = Params {
            symbols: Some("!@".into()),
            ..params("hex")
        };
        let json = serde_json::to_string(&on).unwrap();
        assert_eq!(serde_json::from_str::<Params>(&json).unwrap(), on);
    }

    #[test]
    fn create_then_get_and_list() {
        let mut r = Registry::empty();
        r.create("google.com", "", params("b58")).unwrap();
        r.create("aws.com", "root", params("hex")).unwrap();
        assert_eq!(r.get("google.com", "").unwrap().epoch, 1);
        let live = r.live();
        assert_eq!(live.len(), 2);
        // Sorted by (id, user)
        assert_eq!(live[0].id, "aws.com");
        assert_eq!(live[1].id, "google.com");
    }

    #[test]
    fn create_duplicate_errors() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap();
        assert!(matches!(
            r.create("x", "", params("b58")),
            Err(RegistryError::AlreadyExists(_))
        ));
    }

    #[test]
    fn find_one_by_id_and_ambiguity() {
        let mut r = Registry::empty();
        r.create("x", "a", params("b58")).unwrap();
        r.create("x", "b", params("b58")).unwrap();
        assert!(matches!(
            r.find_one("x", None),
            Err(RegistryError::Ambiguous(_))
        ));
        assert_eq!(r.find_one("x", Some("a")).unwrap().user, "a");
        assert!(matches!(
            r.find_one("y", None),
            Err(RegistryError::NotFound(_))
        ));
    }

    #[test]
    fn rotate_advances_epoch() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap();
        assert_eq!(r.rotate("x", "", None, None).unwrap().epoch, 2);
        // Explicit epoch must strictly increase
        assert!(matches!(
            r.rotate("x", "", None, Some(2)),
            Err(RegistryError::NonMonotonicEpoch { .. })
        ));
        assert_eq!(r.rotate("x", "", None, Some(5)).unwrap().epoch, 5);
        // New params replace the old
        let d = r.rotate("x", "", Some(params("hex")), None).unwrap();
        assert_eq!(d.epoch, 6);
        assert_eq!(d.params.mode, "hex");
    }

    #[test]
    fn remove_tombstones_and_blocks_stale_resurrection() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1
        r.rotate("x", "", None, None).unwrap(); // epoch 2
        r.remove("x", "").unwrap(); // tombstone epoch 3
        assert!(r.get("x", "").is_none());
        // A fresh create revives at a strictly higher epoch than the tombstone
        let revived = r.create("x", "", params("hex")).unwrap();
        assert_eq!(revived.epoch, 4);
        assert!(!revived.tombstone);
    }

    #[test]
    fn epoch_at_max_cannot_advance() {
        // An adopted (e.g. share-token) epoch of u64::MAX must not wrap. A wrap
        // to 0 would defeat stale-change and tombstone protection.
        let mut r = Registry::empty();
        r.adopt("x", "", u64::MAX, params("b58"), false);
        assert_eq!(
            r.rotate("x", "", None, None),
            Err(RegistryError::EpochOverflow)
        );
        assert_eq!(r.remove("x", ""), Err(RegistryError::EpochOverflow));
        // A tombstone at u64::MAX cannot be revived by create either
        r.adopt("x", "", u64::MAX, params("b58"), true);
        assert_eq!(
            r.create("x", "", params("b58")).err(),
            Some(RegistryError::EpochOverflow)
        );
    }

    #[test]
    fn remove_missing_errors() {
        let mut r = Registry::empty();
        assert!(matches!(r.remove("x", ""), Err(RegistryError::NotFound(_))));
    }

    // Convergence (classify / adopt)

    #[test]
    fn classify_unknown_entry_adopts() {
        let r = Registry::empty();
        assert_eq!(
            r.classify("x", "", 1, &params("b58"), false),
            ApplyOutcome::Adopt
        );
        // A removal of an unknown entry is also adoptable (records the tombstone)
        assert_eq!(
            r.classify("x", "", 2, &params("b58"), true),
            ApplyOutcome::Adopt
        );
    }

    #[test]
    fn classify_newer_adopts_older_is_stale() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1
        r.rotate("x", "", None, Some(5)).unwrap(); // epoch 5
        assert_eq!(
            r.classify("x", "", 6, &params("hex"), false),
            ApplyOutcome::Adopt
        );
        assert_eq!(
            r.classify("x", "", 4, &params("hex"), false),
            ApplyOutcome::Stale { local_epoch: 5 }
        );
    }

    #[test]
    fn classify_same_epoch_same_content_is_already_applied() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap();
        assert_eq!(
            r.classify("x", "", 1, &params("b58"), false),
            ApplyOutcome::AlreadyApplied
        );
    }

    #[test]
    fn classify_same_epoch_different_content_is_conflict() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap();
        // Different params at the same epoch
        assert_eq!(
            r.classify("x", "", 1, &params("hex"), false),
            ApplyOutcome::Conflict
        );
        // A removal against a live entry at the same epoch
        assert_eq!(
            r.classify("x", "", 1, &params("b58"), true),
            ApplyOutcome::Conflict
        );
    }

    #[test]
    fn classify_tombstone_blocks_stale_create() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1
        r.remove("x", "").unwrap(); // tombstone epoch 2
                                    // A stale create (epoch 1) cannot resurrect the removed entry
        assert_eq!(
            r.classify("x", "", 1, &params("b58"), false),
            ApplyOutcome::Stale { local_epoch: 2 }
        );
        // Two tombstones at the same epoch agree regardless of params
        assert_eq!(
            r.classify("x", "", 2, &params("hex"), true),
            ApplyOutcome::AlreadyApplied
        );
        // A genuinely newer create does revive it
        assert_eq!(
            r.classify("x", "", 3, &params("b58"), false),
            ApplyOutcome::Adopt
        );
    }

    #[test]
    fn adopt_sets_or_replaces_the_entry() {
        let mut r = Registry::empty();
        r.adopt("x", "", 3, params("hex"), false);
        assert_eq!(r.get("x", "").unwrap().epoch, 3);
        // Replaces in place (including into a tombstone)
        r.adopt("x", "", 4, params("hex"), true);
        assert!(r.get("x", "").is_none());
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].epoch, 4);
    }

    // The archive

    // The tombstone at `N+1` carries the params that were live at `N`, because
    // `remove` bumps the epoch and leaves `params` alone. Archiving it under
    // its own epoch would file the recipe one epoch too high and every recovery
    // would render a different password.
    #[test]
    fn remove_archives_the_recipe_at_the_epoch_it_actually_formats() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1
        r.rotate("x", "", None, None).unwrap(); // epoch 2
        r.remove("x", "").unwrap(); // tombstone at 3

        assert_eq!(
            r.entries[0].epoch, 3,
            "the tombstone sits one past the secret"
        );
        // The rotate archived epoch 1; the remove archived epoch 2, not 3
        let epochs: Vec<u64> = r.archived_for("x", "").iter().map(|d| d.epoch).collect();
        assert_eq!(epochs, vec![1, 2]);
        assert!(
            r.archived("x", "", 3).is_none(),
            "a tombstone formats nothing"
        );
        assert!(r.archived_for("x", "").iter().all(|d| !d.tombstone));
    }

    // `rotate` replaces `params` in place, so the outgoing recipe is archived
    // there or lost. This is the "I rotated and want the old password" case.
    #[test]
    fn rotate_archives_the_outgoing_recipe() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1, b58
        r.rotate("x", "", Some(params("hex")), None).unwrap(); // epoch 2, hex

        assert_eq!(r.get("x", "").unwrap().params.mode, "hex");
        assert_eq!(r.archived("x", "", 1).unwrap().params.mode, "b58");
        assert!(
            r.archived("x", "", 2).is_none(),
            "the current recipe is not archived"
        );
    }

    // The scenario that motivated the archive: create -> remove -> create again.
    // The second `create` overwrites the tombstone slot (`entries[i] = ...`),
    // destroying the last copy of the pre-removal recipe. The archive must
    // outlive it.
    #[test]
    fn create_over_a_tombstone_preserves_the_removed_recipe() {
        let mut r = Registry::empty();
        r.create("fu", "bar", params("b58")).unwrap(); // epoch 1
        r.rotate("fu", "bar", None, Some(5050)).unwrap(); // epoch 5050, b58
        r.remove("fu", "bar").unwrap(); // tombstone at 5051
        r.create("fu", "bar", params("hex")).unwrap(); // revived at 5052, hex

        // The live entry says nothing about epoch 5050 any more...
        let live = r.get("fu", "bar").unwrap();
        assert_eq!(live.epoch, 5052);
        assert_eq!(live.params.mode, "hex");
        assert_eq!(r.entries.len(), 1, "still exactly one entry per key");

        // ...but the archive does, and it is the only place that does.
        assert_eq!(r.archived("fu", "bar", 5050).unwrap().params.mode, "b58");
    }

    // A member who only ever applied the removal token (never the create)
    // still learns the pre-removal recipe, because the token ships `params`
    // verbatim. Without this, group recovery would need an out-of-band recipe.
    #[test]
    fn adopting_a_removal_archives_the_recipe_even_with_no_local_entry() {
        let mut r = Registry::empty();
        // Exactly what `apply` does with an incoming ShareAction::Remove token.
        r.adopt("x", "", 9, params("b58"), true);

        assert!(r.get("x", "").is_none(), "the entry is removed");
        assert_eq!(r.archived("x", "", 8).unwrap().params.mode, "b58");
        assert!(r.archived("x", "", 9).is_none());
    }

    // Adopting a *newer* definition supersedes the local recipe, which must be
    // archived. Adopting at the *same* epoch is conflict resolution. The
    // incoming recipe corrects that epoch rather than superseding it, so filing
    // the losing local recipe under the winner's epoch would poison recovery.
    #[test]
    fn adopt_archives_a_superseded_recipe_but_not_a_resolved_conflict() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1, b58
        r.adopt("x", "", 2, params("hex"), false); // newer: supersedes epoch 1
        assert_eq!(r.archived("x", "", 1).unwrap().params.mode, "b58");

        // Same-epoch conflict resolution: epoch 2 is corrected to alpha
        r.adopt("x", "", 2, params("alpha"), false);
        assert_eq!(r.get("x", "").unwrap().params.mode, "alpha");
        assert!(
            r.archived("x", "", 2).is_none(),
            "the conflicted epoch is not archived"
        );
    }

    // First writer wins: a later record for an epoch never rewrites an earlier
    // one, so an adopted token cannot quietly revise local recovery history.
    #[test]
    fn archive_is_deduplicated_by_id_user_epoch() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1, b58
        r.remove("x", "").unwrap(); // archives (1, b58), tombstone at 2
                                    // An incoming removal at the same epoch re-asserts epoch 1 with hex.
        r.adopt("x", "", 2, params("hex"), true);

        assert_eq!(r.archived_for("x", "").len(), 1);
        assert_eq!(r.archived("x", "", 1).unwrap().params.mode, "b58");
    }

    // `(id, user)` keys the archive as well: two users of one service keep
    // separate histories.
    #[test]
    fn archive_separates_users_of_the_same_id() {
        let mut r = Registry::empty();
        r.create("x", "a", params("b58")).unwrap();
        r.create("x", "b", params("hex")).unwrap();
        r.remove("x", "a").unwrap();
        r.remove("x", "b").unwrap();

        assert_eq!(r.archived("x", "a", 1).unwrap().params.mode, "b58");
        assert_eq!(r.archived("x", "b", 1).unwrap().params.mode, "hex");
        assert_eq!(r.archived_all().len(), 2);
    }

    // A tombstone at epoch 1 supersedes nothing: `create` starts at 1, so no
    // secret was ever derived at epoch 0.
    #[test]
    fn a_tombstone_at_the_first_epoch_archives_nothing() {
        let mut r = Registry::empty();
        r.adopt("x", "", 1, params("b58"), true);
        assert!(r.archive.is_empty());
        assert!(r.archived("x", "", 0).is_none());
    }

    // The archive is written only after every fallible step, so a mutation that
    // errors leaves no trace.
    #[test]
    fn a_failed_mutation_does_not_touch_the_archive() {
        let mut r = Registry::empty();
        r.adopt("x", "", u64::MAX, params("b58"), false);
        assert_eq!(
            r.rotate("x", "", None, None),
            Err(RegistryError::EpochOverflow)
        );
        assert_eq!(r.remove("x", ""), Err(RegistryError::EpochOverflow));
        assert!(
            r.archive.is_empty(),
            "an overflowing mutation archived something"
        );

        // A non-monotonic rotate is rejected before anything is archived.
        r.adopt("y", "", 5, params("b58"), false);
        assert!(r.rotate("y", "", None, Some(5)).is_err());
        assert!(r.archived("y", "", 5).is_none());
    }

    // `recipe_at` serves the live entry when the epoch is still current, the
    // archive when it is not, and refuses to guess when neither has it.
    #[test]
    fn recipe_at_resolves_live_then_archive_and_never_guesses() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1, b58
        r.rotate("x", "", Some(params("hex")), None).unwrap(); // epoch 2, hex

        // The current epoch resolves from the live entry.
        assert_eq!(r.recipe_at("x", None, 2).unwrap().params.mode, "hex");
        // A past epoch resolves from the archive, not from the live params.
        assert_eq!(r.recipe_at("x", None, 1).unwrap().params.mode, "b58");
        // An epoch nobody recorded is an error, never the live recipe.
        assert!(matches!(
            r.recipe_at("x", None, 3),
            Err(RegistryError::NoRecipeAt { epoch: 3, .. })
        ));
    }

    // A tombstone formats nothing, so its own epoch resolves to no recipe even
    // though an entry sits at exactly that epoch.
    #[test]
    fn recipe_at_never_resolves_to_a_tombstone() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1
        r.remove("x", "").unwrap(); // tombstone at 2

        assert_eq!(r.recipe_at("x", None, 1).unwrap().params.mode, "b58");
        assert!(matches!(
            r.recipe_at("x", None, 2),
            Err(RegistryError::NoRecipeAt { epoch: 2, .. })
        ));
    }

    // `user = None` demands exactly one match, exactly as `find_one` does,
    // including across archived entries whose live definitions are long gone.
    #[test]
    fn recipe_at_requires_an_unambiguous_user() {
        let mut r = Registry::empty();
        r.create("x", "a", params("b58")).unwrap();
        r.create("x", "b", params("hex")).unwrap();
        r.remove("x", "a").unwrap(); // archives (x, a, 1)
        r.remove("x", "b").unwrap(); // archives (x, b, 1)

        assert!(matches!(
            r.recipe_at("x", None, 1),
            Err(RegistryError::Ambiguous(_))
        ));
        assert_eq!(r.recipe_at("x", Some("a"), 1).unwrap().params.mode, "b58");
        assert_eq!(r.recipe_at("x", Some("b"), 1).unwrap().params.mode, "hex");
        assert!(matches!(
            r.recipe_at("x", Some("c"), 1),
            Err(RegistryError::NoRecipeAt { .. })
        ));
    }

    // End to end at the registry layer: the password recipe survives
    // create -> rotate -> remove -> create, which is the sequence that destroys
    // every other copy of it.
    #[test]
    fn recipe_at_survives_a_full_remove_and_revive_cycle() {
        let mut r = Registry::empty();
        let original = Params {
            length: Some(14),
            ..params("b58")
        };
        r.create("fu", "bar", original.clone()).unwrap(); // epoch 1
        r.rotate("fu", "bar", None, Some(5050)).unwrap(); // epoch 5050
        r.remove("fu", "bar").unwrap(); // tombstone 5051
        r.create("fu", "bar", params("alpha")).unwrap(); // revived 5052

        assert_eq!(r.recipe_at("fu", None, 5050).unwrap().params, original);
        assert_eq!(r.recipe_at("fu", None, 5052).unwrap().params.mode, "alpha");
    }

    // Disaster recovery (recover_at)

    // The scenario in full: a live entry at a far higher epoch is forced back
    // to a removed-and-overwritten one, and the password returns.
    #[test]
    fn recover_at_overrides_a_live_entry_at_a_lower_epoch() {
        let mut r = Registry::empty();
        let original = Params {
            length: Some(14),
            ..params("b58")
        };
        r.create("fu", "bar", original.clone()).unwrap(); // epoch 1
        r.rotate("fu", "bar", None, Some(5050)).unwrap(); // epoch 5050
        r.remove("fu", "bar").unwrap(); // tombstone 5051
        r.create("fu", "bar", params("alpha")).unwrap(); // live at 5052

        let recipe = r.recipe_at("fu", None, 5050).unwrap().params.clone();
        let def = r.recover_at("fu", "bar", 5050, recipe).unwrap().clone();
        assert_eq!(def.epoch, 5050);
        assert!(!def.tombstone);
        assert_eq!(def.params, original);
        assert_eq!(r.get("fu", "bar").unwrap().epoch, 5050);
        assert_eq!(r.entries.len(), 1, "still one entry per key");

        // The definition it displaced is archived, so the recovery is reversible
        assert_eq!(r.archived("fu", "bar", 5052).unwrap().params.mode, "alpha");
    }

    // A tombstone is overridden too, the entry comes back live
    #[test]
    fn recover_at_revives_a_tombstone() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1
        r.remove("x", "").unwrap(); // tombstone at 2
        assert!(r.get("x", "").is_none());

        r.recover_at("x", "", 1, params("b58")).unwrap();
        assert_eq!(r.get("x", "").unwrap().epoch, 1);
    }

    // `u64::MAX` would leave every future `rotate` and `remove` failing on
    // `EpochOverflow`; epoch 0 never held a secret. Neither may be recovered to,
    // and a rejected recovery changes nothing.
    #[test]
    fn recover_at_rejects_the_epochs_that_would_brick_the_entry() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap();
        for bad in [0, u64::MAX] {
            assert_eq!(
                r.recover_at("x", "", bad, params("b58")),
                Err(RegistryError::EpochOverflow)
            );
        }
        assert_eq!(
            r.get("x", "").unwrap().epoch,
            1,
            "a rejected recovery is a no-op"
        );
        assert!(r.archive.is_empty());
    }

    // Recovering onto the entry's own epoch corrects that epoch's recipe. It
    // must not file the outgoing recipe under the epoch the new one now owns.
    #[test]
    fn recover_at_the_same_epoch_corrects_rather_than_supersedes() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1, b58
        r.recover_at("x", "", 1, params("hex")).unwrap();

        assert_eq!(r.get("x", "").unwrap().params.mode, "hex");
        assert!(r.archived("x", "", 1).is_none());
    }

    // A recovery is itself recoverable: the displaced entry is archived, so the
    // epoch you forced away from can be forced back to.
    #[test]
    fn a_recovery_can_be_undone_from_the_archive() {
        let mut r = Registry::empty();
        r.create("x", "", params("b58")).unwrap(); // epoch 1, b58
        r.rotate("x", "", Some(params("hex")), None).unwrap(); // epoch 2, hex

        r.recover_at("x", "", 1, params("b58")).unwrap(); // back to 1
        assert_eq!(r.get("x", "").unwrap().epoch, 1);

        // Epoch 2's recipe survived the trip back
        let two = r.recipe_at("x", None, 2).unwrap().params.clone();
        assert_eq!(two.mode, "hex");
        r.recover_at("x", "", 2, two).unwrap();
        assert_eq!(r.get("x", "").unwrap().params.mode, "hex");
    }

    // `#[serde(default)]` reads a v1 document (no `archive` key) and
    // `skip_serializing_if` writes an empty archive back byte-identically, so
    // `REGISTRY_VERSION` can stay at 1, which `load_registry` compares for
    // equality.
    #[test]
    fn archive_round_trips_and_stays_compatible_with_a_v1_document() {
        let v1 = r#"{"version":1,"entries":[{"id":"x","user":"","epoch":1,
                     "params":{"mode":"b58"},"tombstone":false}]}"#;
        let mut r: Registry = serde_json::from_str(v1).unwrap();
        assert!(r.archive.is_empty());

        // An empty archive is not written: existing registries do not churn
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("archive"),
            "an empty archive must not be written: {json}"
        );

        // A populated one survives the round trip
        r.remove("x", "").unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("archive"));
        let back: Registry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.archived("x", "", 1).unwrap().params.mode, "b58");
        assert_eq!(back.version, REGISTRY_VERSION);
    }

    #[test]
    fn two_registries_converge_by_exchanging_changes() {
        // Simulate two members editing and syncing
        let (mut a, mut b) = (Registry::empty(), Registry::empty());
        // A creates; B applies
        let d = a.create("vpn", "", params("b58")).unwrap().clone();
        assert_eq!(
            b.classify(&d.id, &d.user, d.epoch, &d.params, false),
            ApplyOutcome::Adopt
        );
        b.adopt(&d.id, &d.user, d.epoch, d.params.clone(), false);
        // B rotates; A applies
        let d2 = b
            .rotate("vpn", "", Some(params("hex")), None)
            .unwrap()
            .clone();
        assert_eq!(
            a.classify(&d2.id, &d2.user, d2.epoch, &d2.params, false),
            ApplyOutcome::Adopt
        );
        a.adopt(&d2.id, &d2.user, d2.epoch, d2.params, false);
        assert_eq!(a.get("vpn", ""), b.get("vpn", ""));
        // Replaying A's original (stale) create at B changes nothing
        assert_eq!(
            b.classify(&d.id, &d.user, d.epoch, &d.params, false),
            ApplyOutcome::Stale { local_epoch: 2 }
        );
    }
}
