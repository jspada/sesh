//! Command-line surface for `sesh`.
//!
//! Every command resolves the keystore from `SESH_HOME` (default `~/.sesh`).
//! Secrets are never accepted as arguments, only public keys, base58check
//! contact tokens, and setup tokens. Passwords are read with no-echo from stdin.
//! This module hosts the non-interactive shared-secret path; the interactive
//! wizard lives in [`crate::wizard`].
//!
//! `show` prints labeled details and never a secret. Managed hd-secret leaf
//! secrets are retrieved only through two supervised commands: `hd-secret copy`
//! (system clipboard, zeroed) and `hd-secret reveal` (a supervised on-screen
//! viewing window, zeroed). No other command outputs raw secret material.

use blstrs::Scalar;
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_complete::{ArgValueCandidates, CompleteEnv, CompletionCandidate};
use zeroize::Zeroizing;

use crate::clipboard;
use crate::config;
use crate::crypto::{self, canonical_hd_context, derive_dh_scalar, PublicIdentity, SEED_BYTES};
use crate::export;
use crate::format;
use crate::keystore::{Keystore, SeedOrigin, SharedSecretState, IDENTITY_VERSION, STATE_VERSION};
use crate::protocol::{
    self, decode_contact_token, derive_group_key, encode_contact_token, group_ctx, Parties,
    Purpose, SetupToken, ShareAction, ShareToken,
};
use crate::table::{render_kv, Table};
use crate::terminal;
use crate::totp;
use crate::wizard::{self, GroupPlan, StdioTerminal};

const MAX_SUFFIX_LEN: usize = 8;

/// Longest `id` or `user` a definition may carry, in bytes. See
/// [`validate_hd_strings`]: room for any real site name or account, and still
/// inside what the `otpauth://` URI of an otp definition can encode as a QR.
const MAX_HD_STRING_LEN: usize = 256;

/// The output mode a new definition gets when `--mode` is not given
const DEFAULT_MODE: &str = "b58";

/// The trim length a new definition gets when `--length` is not given, **and**
/// its mode takes the default symbol set. See [`mode_defaults`].
const DEFAULT_LENGTH: u64 = 14;

/// The trim length a bare `--mode b10` definition gets: a PIN-style,
/// digits-only numeric code. See [`mode_defaults`].
const DEFAULT_B10_LENGTH: u64 = 6;

/// The `(length, symbols)` a bare `create` resolves for `mode` when neither
/// flag is given.
///
/// For `hex`/`b58` they are one package: a 14-character password drawn from an
/// alphabet extended with symbols. `b10` is the deliberate exception. A bare
/// `--mode b10` means a numeric code (a PIN), so it resolves `--length 6
/// --no-symbols` rather than mixing punctuation into digits. The modes that
/// take no symbol set (`alpha`, `bip39`, `otp`) get neither half, rather than
/// silently trimming a mnemonic, a case-code, or a TOTP secret export (`otp`
/// is a fixed 32-character shape that could not carry them anyway). Passing
/// `--length` or `--symbols` explicitly still wins wherever it is valid.
fn mode_defaults(mode: &str) -> (Option<u64>, Option<&'static str>) {
    match mode {
        "b10" => (Some(DEFAULT_B10_LENGTH), None),
        _ if format::supports_symbols(mode) => (Some(DEFAULT_LENGTH), Some(format::SYMBOLS)),
        _ => (None, None),
    }
}

/// Names for shell completion. Runs on every tab press, so it must never
/// prompt and never fail loudly: any resolution or listing error completes to
/// nothing. Only plaintext-on-disk names are offered; hd-secret ids live in an
/// encrypted registry and are deliberately not completable.
fn completion_names(
    list: fn(&Keystore) -> crate::keystore::Result<Vec<String>>,
) -> Vec<CompletionCandidate> {
    let Ok(loc) = config::resolve(None) else {
        return Vec::new();
    };
    list(&Keystore::open(loc.path))
        .map(|names| names.into_iter().map(CompletionCandidate::new).collect())
        .unwrap_or_default()
}

fn keypair_completer() -> ArgValueCandidates {
    ArgValueCandidates::new(|| completion_names(Keystore::list_identities))
}

fn contact_completer() -> ArgValueCandidates {
    ArgValueCandidates::new(|| completion_names(Keystore::list_contacts))
}

fn group_completer() -> ArgValueCandidates {
    ArgValueCandidates::new(|| completion_names(Keystore::list_shared_secrets))
}

fn owner_completer() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        let mut names = completion_names(Keystore::list_identities);
        names.extend(completion_names(Keystore::list_shared_secrets));
        names
    })
}

/// Build the top-level clap command tree
pub fn build_cli() -> Command {
    // `--mode` appears on the commands that **set** a definition's recipe:
    // `create` (with the default) and `rotate` (without one, so an absent flag
    // inherits the stored mode rather than re-applying the default).
    let mode_arg = || {
        Arg::new("mode")
            .short('m')
            .long("mode")
            .value_parser(format::MODES)
            .help("Output encoding")
    };
    let name_arg = |help: &'static str| Arg::new("name").required(true).help(help);
    let group_arg = || name_arg("Shared-secret group name").add(group_completer());

    Command::new("sesh")
        .version("0.1.0")
        .author("Joseph Spadavecchia <joseph@redtrie.com>")
        .about("Authenticated 2- and 3-party shared secrets over BLS12-381")
        .subcommand_required(true)
        .arg_required_else_help(true)
        // A global override for the keystore location. Takes precedence over
        // both $SESH_HOME and the ~/.sesh default; `global(true)` so it may
        // appear before or after any subcommand.
        .arg(
            Arg::new("keystore")
                .long("keystore")

                .global(true)
                .help("Keystore directory (overrides $SESH_HOME and ~/.sesh)"),
        )
        // keypair subcommand
        .subcommand(
            Command::new("keypair")
                .about("Manage local identities")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("create")
                        .about("Create a new identity (random seed, or --mnemonic to recover one)")
                        .long_about(
                            "Create a new identity.\n\n\
                             By default the seed is random. With --mnemonic, sesh prompts (no \
                             echo) for a 24-word BIP39 mnemonic and uses its 256 bits of entropy \
                             directly as the seed (the way to recover a keypair first created \
                             with --mnemonic). Mnemonics are import-only: bring your own from a \
                             hardware wallet, dice, or another tool.\n\n\
                             Recovering the mnemonic restores the keypair and its keypair-owned \
                             hd-secrets (re-`create`/`rotate` with the same id/user and formatting \
                             params). A shared-secret group needs one thing more, because its \
                             master is derived from the members' setup tokens and never stored: \
                             re-pin the peers' contact tokens, then `shared-secret import` a \
                             file any one of them wrote with `shared-secret export`. That brings \
                             back the group and every hd-secret recipe in it, live, rotated and \
                             removed. Re-running the exchange plus share/apply, or \
                             backup/restore, also work.",
                        )
                        .arg_required_else_help(true)
                        .arg(name_arg("Identity name"))
                        .arg(Arg::new("mnemonic").long("mnemonic").action(ArgAction::SetTrue)
                            .help("Prompt for a 24-word BIP39 mnemonic and use it as the seed \
                                   (import-only; takes no value, never put a phrase on the command line)")),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show an identity: fingerprint, contact token, private-key status")
                        .arg_required_else_help(true)
                        .arg(name_arg("Identity name").add(keypair_completer())),
                )
                .subcommand(Command::new("list").about("List identities"))
                .subcommand(
                    Command::new("remove")
                        .about("Remove an identity (cascades the shared-secrets it owns)")
                        .arg_required_else_help(true)
                        .arg(name_arg("Identity name").add(keypair_completer())),
                )
                .subcommand(
                    Command::new("password")
                        .about("Change the password of an identity")
                        .arg_required_else_help(true)
                        .arg(name_arg("Identity name").add(keypair_completer())),
                ),
        )
        // contact subcommand
        .subcommand(
            Command::new("contact")
                .about("Manage pinned peer identities (contacts)")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("add")
                        .about("Pin a peer's contact token under its embedded name (or --name)")
                        .arg(Arg::new("token")
                            .help("The peer's base58check contact token (prompts if omitted)"))
                        .arg(Arg::new("name").short('n').long("name")
                            .help("Pin under this local alias instead of the token's name")),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show a contact: fingerprint and pinned token")
                        .arg_required_else_help(true)
                        .arg(name_arg("Contact alias").add(contact_completer())),
                )
                .subcommand(Command::new("list").about("List contacts"))
                .subcommand(
                    Command::new("remove")
                        .about("Remove a contact (cascades the shared-secrets it belongs to)")
                        .arg_required_else_help(true)
                        .arg(name_arg("Contact alias").add(contact_completer())),
                ),
        )
        // shared-secret subcommand
        .subcommand({
            Command::new("shared-secret")
                .about("Form and manage 2- and 3-party shared secrets with pinned contacts")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("create")
                        .about("Create a shared secret with pinned contacts")
                        .arg_required_else_help(true)
                        .arg(Arg::new("name").required(true)
                            .help("Agreed group name (also the storage key)"))
                        .arg(Arg::new("keypair").long("keypair").required(true)
                            .add(keypair_completer())
                            .help("Local identity providing the seed"))
                        .arg(Arg::new("party").long("party")
                            .action(ArgAction::Append).required(true)
                            .add(contact_completer())
                            .help("A pinned contact alias (repeat for a 3rd party)"))
                        .arg(Arg::new("token").long("token")
                            .action(ArgAction::Append)
                            .help("Peer setup token(s), one per --party in matching order (non-interactive)"))
                        .arg(Arg::new("emit-token").long("emit-token").action(ArgAction::SetTrue)
                            .help("Print your own setup token and exit (phase 1)"))
                        .arg(Arg::new("wizard").long("wizard").action(ArgAction::SetTrue)
                            .help("Force the interactive wizard even when stdin is piped")),
                )
                .subcommand(
                    Command::new("list")
                        .about("List shared-secret groups")
                        .arg(Arg::new("keypair")
                            .add(keypair_completer())
                            .help("Only list groups owned by this keypair")),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show a shared secret's metadata (the secret K never leaves the keystore)")
                        .arg_required_else_help(true)
                        .arg(group_arg()),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove a shared-secret group")
                        .arg_required_else_help(true)
                        .arg(group_arg()),
                )
                // export subcommand
                //
                // Decentralized backup. Both hang off `shared-secret`, which is
                // `subcommand_required(true)` with no bare-owner positional (so
                // they need NO entry in `RESERVED_NAMES`) and a keystore holding
                // a group named `export` keeps working. Adding them to that list
                // would be a silent breaking change.
                .subcommand(
                    Command::new("export")
                        .about("Write an encrypted, member-only backup of a group and its registry (no secrets exported)")
                        .long_about(
                            "Write one encrypted file holding everything a fellow member needs \
                             to rebuild this group and its hd-secret registry from nothing but \
                             their own seed and their pins.\n\n\
                             This is the *decentralized* backup. `sesh backup` is the \
                             centralized one with your whole keystore under a passphrase you \
                             choose. There is no passphrase here, because there is no new \
                             secret: the file is encrypted to the group's membership, using \
                             the identity keys the members already pinned in each other's \
                             keystores. Only members can open it, so it is safe to send over \
                             an unencrypted channel.\n\n\
                             The file contains no seed, no group master, and no password. It \
                             cannot be used to derive anything without a member's own seed. It \
                             does carry every hd-secret recipe (live, rotated and removed) so \
                             `copy --recover <epoch>` works on the far side of an import.\n\n\
                             It has no forward secrecy: the keys are static, so treat the file \
                             as being exactly as sensitive as the group's setup tokens.",
                        )
                        .arg_required_else_help(true)
                        .arg(group_arg())
                        .arg(Arg::new("file").required(true)
                            .help("Output path for the encrypted export")),
                )
                // import subcommand
                .subcommand(
                    Command::new("import")
                        .about("Restore a group and merge its registry from a member's export")
                        .long_about(
                            "Verify a member's export end to end, derive the group master, and \
                             merge the registry it carries.\n\n\
                             Takes no group name: the name is inside the signed payload (it is \
                             bound into the group context, and it is the storage key), so it \
                             cannot be mistyped into a different group.\n\n\
                             The contacts must be pinned first, and this is not a convention \
                             you could skip: the file's decryption key is derived from the \
                             members' identity keys, so without the pins it does not decrypt \
                             at all. The export deliberately carries no identity keys-- if it \
                             did, and import pinned them, whoever handed you the file would \
                             choose your group's membership!\n\n\
                             Everything is verified before anything is written.
                             The registry merges as `hd-secret apply` does, epoch by epoch: a \
                             newer epoch is adopted, an older one is stale, and a same-epoch \
                             content difference is a conflict this command reports and skips \
                             rather than resolving. An export is a snapshot of one member's \
                             registry, not group-wide truth, so it merges rather than \
                             replaces, and importing two members' exports converges them.",
                        )
                        .arg_required_else_help(true)
                        .arg(Arg::new("file").required(true)
                            .help("Path to the export file (the group name is inside it)"))
                        .arg(Arg::new("keypair").long("keypair").required(true)
                            .add(keypair_completer())
                            .help("Local identity providing the seed"))
                        .arg(Arg::new("party").long("party")
                            .action(ArgAction::Append).required(true)
                            .add(contact_completer())
                            .help("A pinned contact alias (repeat for a 3rd party)"))
                        .arg(Arg::new("dry-run").long("dry-run").action(ArgAction::SetTrue)
                            .help("Verify and show the diff without writing anything")),
                )
        })
        // hd-secret subcommand
        .subcommand({
            let owner_arg = || Arg::new("owner").required(true)
                .add(owner_completer())
                .help("Owning keypair or shared-secret group");
            let id_arg = || Arg::new("id").required(true)
                .help("Child label, e.g. google.com");
            let user_arg = || Arg::new("user")
                .help("Optional sub-account, e.g. bob@google.com");
            let length_arg = || Arg::new("length").short('l').long("length")
                .help("Trim the secret to this length");
            let suffix_arg = || Arg::new("suffix").short('u').long("suffix")
                .help("Append this fixed suffix (max 8)");
            // `--symbols` alone resolves to the built-in default set;
            // `--symbols='!@#'` names one explicitly. `require_equals` keeps
            // `--symbols --length 20` from swallowing the next flag as the set,
            // and `num_args(0..=1)` caps how many values the flag may take.
            let symbols_arg = || Arg::new("symbols").long("symbols")
                .num_args(0..=1)
                .require_equals(true)
                .default_missing_value(format::SYMBOLS)
                .conflicts_with("no-symbols")
                .help("Extend the password alphabet with these characters (hex/b10/b58 only)");
            let no_symbols_arg = || Arg::new("no-symbols").long("no-symbols").action(ArgAction::SetTrue)
                .help("Turn off symbol mixing (e.g. on rotate)");
            let epoch_arg = || Arg::new("epoch").short('e').long("epoch");
            // Disaster recovery, read-only. One flag, not an `--epoch` /
            // `--force` pair: on a command that derives and prints there is no
            // safety rule to override, so there is no invalid combination to
            // guard against. The epoch *is* the whole request.
            let recover_arg = || Arg::new("recover").long("recover")
                .value_name("EPOCH")
                .help("Re-derive using the recipe that was current at this epoch");
            Command::new("hd-secret")
                .about("Manage and derive HD child secrets (password-manager layer)")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List stored definitions (never secrets)")
                        .arg_required_else_help(true)
                        .arg(owner_arg())
                        // `--removed` is the obvious name and stays as an alias,
                        // but the archive also holds recipes superseded by
                        // `rotate`, which were never removed. `--archived` is
                        // what the table actually contains.
                        .arg(Arg::new("archived").long("archived").action(ArgAction::SetTrue).visible_alias("removed")
                            .help("List superseded recipes (from `rotate` and `remove`) instead"))
                        .arg(Arg::new("verbose").short('v').long("verbose").action(ArgAction::SetTrue)
                            .help("Include the Params column")),
                )
                .subcommand(
                    Command::new("create")
                        .about("Register a new definition (details + fingerprint, never the secret)")
                        .long_about(
                            "Register a new hd-secret definition.\n\n\
                             Defaults, when the flags are not given: `--mode b58 --length 14 \
                             --symbols`. They are resolved once and stored in the definition's \
                             params, where `hd-secret list` and `show` print them back.\n\n\
                             The --length and --symbols defaults apply only to the modes that \
                             take a symbol set, and per mode: hex and b58 get `--length 14 \
                             --symbols`; b10 is a numeric code, so it gets `--length 6 \
                             --no-symbols` (a PIN). Under --mode alpha, bip39, or otp \
                             neither is filled in, so the full mnemonic, case-code, or TOTP \
                             secret is produced. Pass --no-symbols to opt out of the symbol \
                             set, or --length explicitly to override the trim.\n\n\
                             --mode otp makes the definition a standard TOTP authenticator \
                             secret (RFC 6238): `copy` and `reveal` egress the live 6-digit \
                             code, and their --setup flag gives the one-time enrollment view \
                             (Base32 secret, otpauth:// URI, QR code).\n\n\
                             `rotate --mode <m>` drops any stored param the new mode cannot \
                             render (a symbol set under alpha, a length or suffix under bip39 \
                             or otp), naming each one as it goes.\n\n\
                             --recover <EPOCH> is the disaster escape hatch: it overwrites the \
                             entry (either live or removed) at exactly that epoch, with the recipe \
                             recorded for it (see `list --archived`). The recipe is read, never \
                             typed, so --recover takes no formatting flags: every member who \
                             recovers an epoch lands on the same password. It is the one \
                             command that breaks epoch monotonicity, it asks before it writes, \
                             and it emits no share token, because a token below the other \
                             members' epoch is classified stale and silently ignored. Every \
                             member must run the identical command. If you only want the old \
                             password, and not the entry back, use `copy --recover <EPOCH>` \
                             instead: it writes nothing and needs no coordination.",
                        )
                        .arg_required_else_help(true)
                        .arg(owner_arg()).arg(id_arg()).arg(user_arg())
                        .arg(length_arg()).arg(symbols_arg()).arg(no_symbols_arg()).arg(suffix_arg())
                        .arg(mode_arg().default_value(DEFAULT_MODE))
                        .arg(Arg::new("recover").long("recover")
                            .value_name("EPOCH")
                            .help("Disaster recovery: overwrite at exactly this epoch, inheriting its recorded recipe")),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show one stored entry: params + secret fingerprint (never the secret)")
                        .arg_required_else_help(true)
                        .arg(owner_arg()).arg(id_arg()).arg(user_arg()).arg(recover_arg()),
                )
                .subcommand(
                    Command::new("copy")
                        .about("Derive one stored secret and copy it to the clipboard")
                        .long_about(
                            "Derive one stored secret and copy it to the clipboard.\n\n\
                             For an otp-mode definition the clipboard gets the current 6-digit \
                             TOTP code (re-copied automatically if the 30s window rolls over \
                             during the countdown); --setup copies the otpauth:// enrollment \
                             URI instead.\n\n\
                             --recover <EPOCH> re-derives a *past* password: the secret at that \
                             epoch, formatted by the recipe that was current then, read from the \
                             archive `rotate` and `remove` write to. Nothing is written and no \
                             epoch rule is bent, so it needs no coordination with the other group \
                             members, run it alone, at any time.\n\n\
                             The params are never guessed. An epoch with no recorded recipe is an \
                             error: a wrong recipe renders a wrong password, and the fingerprint \
                             that would betray it is only useful to someone holding the right one \
                             to compare against.",
                        )
                        .arg_required_else_help(true)
                        .arg(owner_arg()).arg(id_arg()).arg(user_arg()).arg(recover_arg())
                        .arg(Arg::new("setup").long("setup").action(ArgAction::SetTrue)
                            .help("Copy the otpauth:// enrollment URI instead of the current code (otp mode only)"))
                        .arg(Arg::new("timeout").short('t').long("timeout")
                            .default_value("30")
                            .help("Seconds before the clipboard is zeroed (any key zeros early)")),
                )
                .subcommand(
                    Command::new("rotate")
                        .about("Bump a definition's epoch (optionally new params) and show it")
                        .arg_required_else_help(true)
                        .arg(owner_arg()).arg(id_arg()).arg(user_arg())
                        .arg(epoch_arg().help("Explicit new epoch (must exceed the current one)"))
                        .arg(length_arg()).arg(symbols_arg()).arg(no_symbols_arg()).arg(suffix_arg()).arg(mode_arg())
                        .arg(Arg::new("dry-run").long("dry-run").action(ArgAction::SetTrue)
                            .help("Print the outcome (and share token) without updating the keystore")),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Tombstone a definition")
                        .arg_required_else_help(true)
                        .arg(owner_arg()).arg(id_arg()).arg(user_arg()),
                )
                .subcommand(
                    Command::new("reveal")
                        .about("Show a stored secret on screen in a supervised, timed window (TTY only)")
                        .long_about(
                            "Show a stored secret on screen in a supervised, timed window \
                             (TTY only).\n\n\
                             For an otp-mode definition the window shows the live rolling \
                             6-digit TOTP code, recomputed as each 30s window rolls over; \
                             --setup shows the one-time enrollment view instead: the Base32 \
                             secret, the otpauth:// URI, and a scannable QR code.",
                        )
                        .arg_required_else_help(true)
                        .arg(owner_arg()).arg(id_arg()).arg(user_arg()).arg(recover_arg())
                        .arg(Arg::new("setup").long("setup").action(ArgAction::SetTrue)
                            .help("Show the one-time enrollment view: Base32 secret, otpauth:// URI, QR code (otp mode only)"))
                        .arg(Arg::new("timeout").short('t').long("timeout")
                            .default_value("60")
                            .help("Seconds the secret stays on screen (any key clears early)")),
                )
                .subcommand(
                    Command::new("share")
                        .about("Print a stored entry's share token for the other group members")
                        .arg_required_else_help(true)
                        .arg(owner_arg()).arg(id_arg()).arg(user_arg()),
                )
                .subcommand(
                    Command::new("apply")
                        .about("Apply a group member's registry share token (shows a diff, asks Y/N)")
                        .arg(Arg::new("token")
                            .help("The base58check share token (prompts if omitted)")),
                )
        })
        // backup / restore subcommands
        .subcommand(
            Command::new("backup")
                .about("Write an encrypted single-file backup of the whole keystore")
                .long_about(
                    "Write an encrypted single-file backup of the keystore.\n\n\
                     A mnemonic-derived keypair's seed is never copied into the bundle: \
                     you already hold it as 24 words, and omitting it loses nothing the \
                     mnemonic cannot restore (registries and group state come back, and \
                     decrypt once the mnemonic does). Backup therefore prompts for the \
                     password of each mnemonic keypair, to authenticate that it really is \
                     mnemonic-derived before dropping its seed. That makes `backup` \
                     interactive, and so not scriptable, in proportion to how many \
                     mnemonic keypairs you hold.\n\n\
                     A random-seed keypair's seed exists nowhere else, so it is always \
                     included.",
                )
                .arg_required_else_help(true)
                .arg(Arg::new("file").required(true)
                    .help("Output path for the encrypted backup")),
        )
        .subcommand(
            Command::new("restore")
                .about("Restore the keystore from an encrypted backup file")
                .long_about(
                    "Restore the keystore from an encrypted backup file.\n\n\
                     For every mnemonic-derived keypair the bundle omitted, restore asks \
                     for its 24-word mnemonic, and checks the fingerprint before writing \
                     anything. You may skip one: the rest of the bundle still restores, \
                     and the skipped keypair (along with every group it owns) is left \
                     out entirely and named in the output. Re-running restore with the \
                     mnemonic recovers them.\n\n\
                     --force means the bundle replaces the target: the existing keystore \
                     directory is removed first. Symlinks and special files are never in \
                     a bundle, so --force destroys them without restoring them.",
                )
                .arg_required_else_help(true)
                .arg(Arg::new("file").required(true)
                    .help("Path to the encrypted backup"))
                .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)
                    .help("Remove the existing keystore first, the bundle replaces it")),
        )
}

/// Parse arguments and run, returning a process exit code
pub fn run() -> i32 {
    // Dynamic shell completion: `COMPLETE=<shell> sesh` prints the registration
    // script, and completion requests are answered here and exit before parsing.
    CompleteEnv::with_factory(build_cli).complete();
    let matches = build_cli().get_matches();
    // A `--keystore` anywhere on the line pins the keystore location for this
    // process, ahead of $SESH_HOME and the default.
    if let Some(path) = find_keystore_override(&matches) {
        let _ = KEYSTORE_OVERRIDE.set(std::path::PathBuf::from(path));
    }
    match dispatch(&matches) {
        Ok(()) => exitcode::OK,
        Err(e) => {
            eprintln!("error: {e}");
            exitcode::DATAERR
        }
    }
}

/// The process-wide keystore override set from `--keystore` (if any)
static KEYSTORE_OVERRIDE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Find `--keystore` wherever it appears because it is a global arg its value
/// surfaces on whichever subcommand level consumed it, so descend to find it.
fn find_keystore_override(m: &ArgMatches) -> Option<String> {
    if let Some(v) = m.get_one::<String>("keystore").map(String::as_str) {
        return Some(v.to_string());
    }
    match m.subcommand() {
        Some((_, sm)) => find_keystore_override(sm),
        None => None,
    }
}

fn dispatch(matches: &ArgMatches) -> Result<(), String> {
    match matches.subcommand() {
        Some(("keypair", m)) => cmd_keypair(m),
        Some(("contact", m)) => cmd_contact(m),
        Some(("shared-secret", m)) => cmd_shared_secret(m),
        Some(("hd-secret", m)) => cmd_hd_secret(m),
        Some(("backup", m)) => cmd_backup(m),
        Some(("restore", m)) => cmd_restore(m),
        _ => Err("no command given".into()),
    }
}

/// Survey the keystore's mnemonic-derived keypairs, **authenticating** each
/// one's `origin` before agreeing to leave its seed out of a backup.
///
/// `identity_origin` reads plaintext JSON and verifies nothing. Acting on it
/// directly would mean that flipping `"origin": "random"` to `"mnemonic"` in a
/// file makes the next backup silently omit an unrecoverable seed; the AEAD
/// failure would only arrive at the owner's next `load_seed`, whose one effect
/// is to send them to the poisoned bundle. So every identity we intend to skip
/// is unlocked here, and `load_seed`'s AAD, which binds `origin`, is what
/// makes the claim true.
///
/// The other direction needs no check: `mnemonic` mislabelled `random` merely
/// includes a seed that did not need including, which is today's behaviour and
/// loses nothing. The prompt count is therefore the number of *mnemonic*
/// keypairs, and it covers the only direction that can destroy data.
fn survey_mnemonic_identities(
    ks: &Keystore,
) -> Result<
    (
        std::collections::HashSet<String>,
        Vec<crate::backup::MnemonicIdentity>,
    ),
    String,
> {
    use crate::keystore::SeedOrigin;

    let groups_of = |owner: &str| -> Result<Vec<String>, String> {
        let mut owned = Vec::new();
        for g in ks.list_shared_secrets().map_err(se)? {
            if ks.load_shared_secret(&g).map_err(se)?.keypair == owner {
                owned.push(g);
            }
        }
        Ok(owned)
    };

    let mut skip = std::collections::HashSet::new();
    let mut omitted = Vec::new();
    for name in ks.list_identities().map_err(se)? {
        if ks.identity_origin(&name).map_err(se)? != SeedOrigin::Mnemonic {
            continue; // unauthenticated, but `random` is the safe direction
        }
        let password = unlock_password(&name)?;
        // AES-GCM cannot distinguish a flipped `origin` from a wrong password,
        // so this must not accuse the user of a typo. Either way we write nothing.
        ks.load_seed(&name, &password).map_err(|e| {
            format!(
                "could not unlock mnemonic keypair '{name}' ({e}). Backup aborted; \
                 nothing was written. If the password is right, the identity file's \
                 `origin` may have been tampered with."
            )
        })?;

        let public = ks.load_public_identity(&name).map_err(se)?;
        skip.insert(format!("keypairs/{name}/identity"));
        omitted.push(crate::backup::MnemonicIdentity {
            fingerprint: crypto::identity_fingerprint(&public),
            groups: groups_of(&name)?,
            name,
        });
    }
    Ok((skip, omitted))
}

fn cmd_backup(m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let out = std::path::PathBuf::from(m.get_one::<String>("file").map(String::as_str).unwrap());

    // Unlock first: a tampered `origin` must abort before the user is asked to
    // choose a backup passphrase, and long before anything is written.
    let (skip, omitted) = survey_mnemonic_identities(&ks)?;

    let p1 = read_password_noecho("Set backup passphrase: ").map_err(se)?;
    let p2 = read_password_noecho("Confirm passphrase: ").map_err(se)?;
    if p1 != p2 {
        return Err("passphrases do not match".into());
    }
    if p1.is_empty() {
        return Err("backup passphrase must not be empty".into());
    }
    let pass = Zeroizing::new(p1);
    let n =
        crate::backup::create_backup(ks.root(), &out, &pass, &skip, omitted.clone()).map_err(se)?;

    if omitted.is_empty() {
        println!("Backed up {n} file(s) to {} (encrypted).", out.display());
        println!("Keep this file AND its passphrase safe, together they are your whole identity.");
        return Ok(());
    }

    // A seed can now be absent, so "this file is your whole identity" would be
    // false, and dangerous. Name what is missing and what restores it.
    println!(
        "Backed up {n} file(s) to {} (encrypted); the seeds below are deliberately \
         not among them, so the count under-reports the tree.",
        out.display()
    );
    println!();
    println!("Omitted (mnemonic-derived, you already hold the seed as 24 words):");
    for id in &omitted {
        let groups = if id.groups.is_empty() {
            String::new()
        } else {
            format!("  (and its group(s): {})", id.groups.join(", "))
        };
        println!("    {}{groups}", id.name);
    }
    println!();
    println!(
        "To restore {}, you need this file, its passphrase, AND the 24-word \
         mnemonic for each keypair above.",
        if omitted.len() == 1 { "it" } else { "them" }
    );
    Ok(())
}

fn cmd_restore(m: &ArgMatches) -> Result<(), String> {
    use wizard::Terminal;

    // `restore` is the one command allowed to POPULATE a target, so it resolves
    // the location without the availability check (the target may legitimately
    // not exist yet).
    let root = resolve_location()?.path;
    let input = std::path::PathBuf::from(m.get_one::<String>("file").map(String::as_str).unwrap());
    let force = m.get_flag("force");

    // 0. Guard the target before any prompt, the passphrase and N mnemonics
    //    must not be typed only to discover the target was non-empty.
    crate::backup::check_target_empty(&root, force).map_err(se)?;

    // 1. Decrypt the bundle. Nothing is written yet
    let pass = Zeroizing::new(read_password_noecho("Backup passphrase: ").map_err(se)?);
    let bundle = crate::backup::read_manifest(&input, &pass).map_err(se)?;

    // 2-3. Prompt for each omitted mnemonic, fingerprint-checking it the moment
    //      it is entered, before moving on to the next identity's prompts.
    let mut recovered: Vec<(String, Zeroizing<[u8; SEED_BYTES]>, Zeroizing<String>)> = Vec::new();
    let mut skipped: Vec<&crate::backup::MnemonicIdentity> = Vec::new();
    let mut term = StdioTerminal::new();
    for id in bundle.mnemonic_identities() {
        // A skip is an explicit answer, never an empty line: `prompt_mnemonic_seed`
        // reads with no echo, and Enter is what people press when a silent prompt
        // looks hung. Overloading "" to mean "permanently abandon this keypair"
        // would be a trap.
        let cascade = if id.groups.is_empty() {
            String::new()
        } else {
            format!(" and its group(s) {}", id.groups.join(", "))
        };
        if term
            .confirm(&format!(
                "Skip mnemonic keypair '{}'{cascade}? [y/N] ",
                id.name
            ))
            .map_err(se)?
        {
            skipped.push(id);
            continue;
        }
        let seed = prompt_mnemonic_seed()?;
        // A typo almost always dies at the BIP39 checksum above. What this
        // catches is a *valid* mnemonic for the wrong keypair, which would
        // otherwise surface much later as an opaque AEAD failure when the
        // registry refused to decrypt. Nothing has been written, so we can fail
        // immediately and by name.
        let public = crypto::public_identity_from_seed(&seed);
        let fingerprint = crypto::identity_fingerprint(&public);
        if fingerprint != id.fingerprint {
            return Err(format!(
                "that mnemonic is valid but belongs to a different keypair: '{}' has \
                 fingerprint {}, the mnemonic derives {fingerprint}. Nothing was written.",
                id.name, id.fingerprint
            ));
        }
        let password = prompt_new_password("Set keypair password: ")?;
        recovered.push((id.name.clone(), seed, password));
    }

    // 4. `--force` means the bundle replaces the target. One rule; everything
    //    else follows. No stale identity can survive into step 7, so
    //    `write_identity`'s AlreadyExists guard cannot fire, and restore is
    //    idempotent. Note that symlinks and special files, which the bundle
    //    never contained, are destroyed here.
    if force && root.exists() {
        std::fs::remove_dir_all(&root).map_err(se)?;
    }

    // 5. A skipped keypair's whole directory stays out, and so do the groups it
    //    owns: a group restored without its seed-providing keypair is a state
    //    file pointing at nothing, beside ciphertext nobody can open.
    let mut skip = std::collections::HashSet::new();
    for id in &skipped {
        skip.insert(format!("keypairs/{}", id.name));
        for group in &id.groups {
            skip.insert(format!("shared-secrets/{group}"));
        }
    }

    // 6. Write the tree
    let n = crate::backup::apply_manifest(&bundle, &root, &skip).map_err(se)?;

    // 7. Write the recovered identities. `write_identity` calls
    //    `create_dir_secure` itself, which matters: a mnemonic keypair with no
    //    hd-secrets contributes zero files to the manifest, so step 6 made no
    //    directory for it.
    let ks = Keystore::open(&root);
    for (name, seed, password) in &recovered {
        ks.write_identity(name, seed, password, SeedOrigin::Mnemonic)
            .map_err(se)?;
    }

    // 8. Report
    println!("Restored {n} file(s) into {}.", root.display());
    for (name, _, _) in &recovered {
        println!("Recovered keypair '{name}' from its mnemonic.");
    }
    if !skipped.is_empty() {
        println!();
        println!("Not recovered (mnemonic skipped):");
        for id in &skipped {
            println!("    keypair '{}'", id.name);
            for group in &id.groups {
                println!("      shared-secret \"{group}\" (owned by '{}')", id.name);
            }
        }
        println!();
        println!("Re-running `restore` with the mnemonic recovers them, groups included.");
    }
    Ok(())
}

/// Resolve the keystore location from the precedence chain
/// (`--keystore` > `$SESH_HOME` > `config.toml` > `~/.sesh`), without touching
/// the filesystem.
fn resolve_location() -> Result<config::Location, String> {
    config::resolve(KEYSTORE_OVERRIDE.get().cloned())
}

/// Open the resolved keystore. **Local** keystores (`--keystore` / `$SESH_HOME`
/// / `~/.sesh`) are provisioned automatically on first write, so nothing is
/// checked or created here, a read on a missing store simply lists nothing. A
/// **config pointer** is the one case that is *never* auto-created (an
/// un-inserted USB mount point must not be silently written to), so its target
/// is verified present and identity-matched first.
fn keystore() -> Result<Keystore, String> {
    let loc = resolve_location()?;
    if loc.source == config::Source::Config {
        ensure_pointer_available(&loc)?;
    }
    Ok(Keystore::open(loc.path))
}

/// Verify a config-pointer target is present and is the keystore the pointer
/// names. Creates nothing (a pointer is never auto-provisioned). A missing path
/// exits `EX_UNAVAILABLE`; a present-but-empty target and an id mismatch each
/// get a distinct, path-agnostic message.
fn ensure_pointer_available(loc: &config::Location) -> Result<(), String> {
    let path = loc.path.display();
    if !loc.path.is_dir() {
        // Path-agnostic: the keystore may be on removable media, a network
        // share, or any mount. All we can say is the path is not there.
        eprintln!("error: keystore path {path} does not exist");
        std::process::exit(exitcode::UNAVAILABLE);
    }
    let marker = Keystore::open(&loc.path).read_marker().map_err(se)?;
    match (&loc.expected_id, &marker) {
        (Some(exp), Some(m)) if &m.id == exp => Ok(()),
        // A pointer without an id can only confirm a keystore is present
        (None, Some(_)) => Ok(()),
        (Some(_), Some(_)) => Err(format!(
            "this is not the keystore your config is linked to ({path})"
        )),
        // Path exists but holds no keystore. A pointer never auto-creates one,
        // so point --keystore at it once to provision it, then the pointer finds it.
        (_, None) => Err(format!(
            "no keystore at {path} - create it first by creating a keypair"
        )),
    }
}

/// Stringify any Display error
fn se<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// -----------------
// Passwords helpers
// -----------------

/// Read a password with no echo. On a real TTY the terminal echo is disabled;
/// when stdin is piped (scripts, tests) a line is read from stdin.
fn read_password_noecho(prompt: &str) -> std::io::Result<String> {
    use std::io::{IsTerminal, Write};
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)
    } else {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }
}

fn prompt_token(prompt: &str) -> Result<String, String> {
    use crate::wizard::Terminal as _;
    let line = StdioTerminal::new().prompt_line(prompt).map_err(se)?;
    if line.is_empty() {
        return Err("no token entered".into());
    }
    Ok(line)
}

/// Read the password needed to unlock keypair `name`. Every identity is
/// encrypted, so this always prompts-- there is nothing to inspect first.
fn unlock_password(name: &str) -> Result<Zeroizing<String>, String> {
    let pw = read_password_noecho(&format!("Unlock keypair '{name}': ")).map_err(se)?;
    Ok(Zeroizing::new(pw))
}

/// Prompt (twice, no echo) for a new password. Both reads are wrapped in
/// `Zeroizing` immediately, so the confirmation copy and the mismatch/empty
/// error paths leave no plaintext behind in freed heap memory.
fn prompt_new_password(prompt: &str) -> Result<Zeroizing<String>, String> {
    let p1 = Zeroizing::new(read_password_noecho(prompt).map_err(se)?);
    let p2 = Zeroizing::new(read_password_noecho("Confirm password: ").map_err(se)?);
    if p1 != p2 {
        return Err("passwords do not match".into());
    }
    if p1.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(p1)
}

/// Prompt (no echo, never on argv) for a 24-word BIP39 mnemonic and turn it
/// into a seed. The mnemonic's 256 bits of entropy are used **directly** as the
/// 32-byte seed-- the BIP39 checksum is validated, but the standard's PBKDF2
/// "seed" step (which yields 64 bytes) is skipped: it adds nothing here, since a
/// 24-word mnemonic already carries exactly `SEED_BYTES` of entropy. BIP32/44
/// derivation paths do not apply. The phrase is whitespace-normalised so pasted
/// input with newlines or double spaces still parses.
fn prompt_mnemonic_seed() -> Result<Zeroizing<[u8; SEED_BYTES]>, String> {
    let raw = Zeroizing::new(read_password_noecho("Enter 24-word BIP39 mnemonic: ").map_err(se)?);
    let phrase = Zeroizing::new(raw.split_whitespace().collect::<Vec<_>>().join(" "));
    let mnemonic = bip39::Mnemonic::parse(phrase.as_str())
        .map_err(|e| format!("invalid BIP39 mnemonic: {e}"))?;
    if mnemonic.word_count() != 24 {
        return Err(format!(
            "expected a 24-word mnemonic (256 bits of entropy), got {} words",
            mnemonic.word_count()
        ));
    }
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    // 24 words -> 256 bits -> exactly SEED_BYTES; enforce structurally
    if entropy.len() != SEED_BYTES {
        return Err(format!(
            "mnemonic entropy is {} bytes, expected {SEED_BYTES}",
            entropy.len()
        ));
    }
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    seed.copy_from_slice(&entropy);
    Ok(seed)
}

// ---------------
// Keypair helpers
// ---------------

/// The `Private key:` value for `keypair create` and `keypair show`. Every
/// identity's seed is encrypted, so there is no status to report, only the
/// schema version and the width.
fn private_key_summary() -> String {
    format!("v{IDENTITY_VERSION}, encrypted, {SEED_BYTES} bytes")
}

/// Vet a new keypair name before `keypair create` prompts for anything.
///
/// The whitespace rule exists for one reason. `--mnemonic` is a **flag**: it
/// takes no value, because a seed phrase must never reach argv, the process
/// list, or a shell history file. So `keypair create --mnemonic "<24 words>"`
/// does not pass the phrase to the flag, it slides into the `<name>`
/// positional, and `validate_name` is happy to accept it. The phrase would then
/// become a directory name on disk, in the clear, forever.
///
/// Neither branch below echoes `name`. When this fires, the name may *be* the
/// secret, and an error message is the last place it should appear.
fn check_new_keypair_name(name: &str, mnemonic: bool) -> Result<(), String> {
    if name.chars().any(char::is_whitespace) {
        if mnemonic {
            return Err(
                "`--mnemonic` takes no value: it prompts for the phrase, so the words never \
                 appear in your shell history or the process list. The words you passed were \
                 read as the keypair's NAME.\n\n  \
                 Usage: sesh keypair create <name> --mnemonic\n\n\
                 Treat that phrase as exposed (it is in your shell history) and clear it."
                    .into(),
            );
        }
        return Err("a keypair name may not contain whitespace".into());
    }
    // Reserved words and a leading '-' would be unaddressable as a CLI
    // positional. The keystore enforces this too; failing here just spares the
    // user two no-echo prompts first.
    crate::keystore::validate_new_name(name).map_err(se)
}

/// The `Seed origin:` value, spelling out what each origin means for backups.
fn seed_origin_summary(origin: SeedOrigin) -> String {
    match origin {
        SeedOrigin::Random => "random (not in any mnemonic, backups carry it)",
        SeedOrigin::Mnemonic => "mnemonic (24 words, backups omit the seed)",
    }
    .to_string()
}

fn cmd_keypair(m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    match m.subcommand() {
        Some(("create", sm)) => {
            let name = sm.get_one::<String>("name").map(String::as_str).unwrap();
            // Vet the name before any prompt: making the user type a mnemonic and
            // a password only to be told the name was reserved is needlessly cruel.
            // The keystore re-checks it; this is the friendly gate, not the real one.
            check_new_keypair_name(name, sm.get_flag("mnemonic"))?;
            // Read the mnemonic (if any) BEFORE prompting for a keystore
            // password, so both no-echo prompts happen in a predictable order.
            let mnemonic_seed = if sm.get_flag("mnemonic") {
                Some(prompt_mnemonic_seed()?)
            } else {
                None
            };
            let password = prompt_new_password("Set keypair password: ")?;
            let origin = match &mnemonic_seed {
                Some(_) => SeedOrigin::Mnemonic,
                None => SeedOrigin::Random,
            };
            let public = match &mnemonic_seed {
                // Import path: the seed is the mnemonic's entropy, stored and
                // encrypted like any other seed, but marked recoverable,  so
                // `backup` may leave it out.
                Some(seed) => ks
                    .write_identity(name, seed, &password, origin)
                    .map_err(se)?,
                // The random path is `Random` by definition, so `create_identity`
                // takes no origin at all.
                None => ks.create_identity(name, &password).map_err(se)?,
            };
            // Same labeled block as `keypair show`
            print!(
                "{}",
                render_kv(&[
                    ("Name", name.to_string()),
                    ("Fingerprint", crypto::identity_fingerprint(&public)),
                    (
                        "Contact token",
                        encode_contact_token(name, &public).map_err(se)?
                    ),
                    ("Private key", private_key_summary()),
                    ("Seed origin", seed_origin_summary(origin)),
                ])
            );
            Ok(())
        }
        Some(("show", sm)) => {
            let name = sm.get_one::<String>("name").map(String::as_str).unwrap();
            let public = ks.load_public_identity(name).map_err(se)?;
            // The origin is read without a password and so is unauthenticated;
            // it is shown as information, and never acted on here.
            let origin = ks.identity_origin(name).map_err(se)?;
            print!(
                "{}",
                render_kv(&[
                    ("Name", name.to_string()),
                    ("Fingerprint", crypto::identity_fingerprint(&public)),
                    (
                        "Contact token",
                        encode_contact_token(name, &public).map_err(se)?
                    ),
                    ("Private key", private_key_summary()),
                    ("Seed origin", seed_origin_summary(origin)),
                ])
            );
            Ok(())
        }
        Some(("list", _)) => {
            let mut table = Table::new(&["Name", "Fingerprint"]);
            for name in ks.list_identities().map_err(se)? {
                let fpr = ks
                    .load_public_identity(&name)
                    .map(|p| crypto::identity_fingerprint(&p))
                    .unwrap_or_else(|_| "(unavailable)".into());
                table.push(vec![name, fpr]);
            }
            if table.is_empty() {
                println!("(no identities)");
            } else {
                print!("{}", table.render());
            }
            Ok(())
        }
        Some(("remove", sm)) => {
            let name = sm.get_one::<String>("name").map(String::as_str).unwrap();
            let cascaded = ks.remove_identity_cascade(name).map_err(se)?;
            for group in &cascaded {
                println!("Removed shared-secret \"{group}\" (owned by '{name}').");
            }
            println!("Removed identity '{name}'.");
            Ok(())
        }
        Some(("password", sm)) => {
            let name = sm.get_one::<String>("name").map(String::as_str).unwrap();
            // Vet the name before any prompt: a missing identity should fail
            // before the user types two passwords, not after.
            ks.load_public_identity(name).map_err(se)?;
            let old = unlock_password(name)?;
            let new = prompt_new_password("Set new keypair password: ")?;
            ks.change_identity_password(name, &old, &new).map_err(se)?;
            println!("Password changed for identity '{name}'.");
            Ok(())
        }
        _ => Err("unknown keypair subcommand".into()),
    }
}

// ---------------
// Contact helpers
// ---------------

fn cmd_contact(m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    match m.subcommand() {
        Some(("add", sm)) => {
            let token = match sm.get_one::<String>("token") {
                Some(t) => t.clone(),
                None => prompt_token("Peer contact token: ")?,
            };
            let (embedded, public) = decode_contact_token(&token).map_err(se)?;
            // The token's embedded name is the default alias; --name overrides
            let alias = match sm.get_one::<String>("name").map(String::as_str) {
                Some(n) => n.to_string(),
                None => {
                    if embedded.is_empty() {
                        return Err(
                            "This contact token carries no name, pass --name <alias>".into()
                        );
                    }
                    embedded
                }
            };
            let outcome = ks.add_contact(&alias, &public).map_err(se)?;
            match outcome {
                crate::keystore::ContactOutcome::Pinned => {
                    println!("Pinned contact '{alias}'.");
                }
                crate::keystore::ContactOutcome::AlreadyPinned => {
                    println!("Contact '{alias}' already pinned to this key (no change).");
                }
            }
            print!(
                "{}",
                render_kv(&[
                    ("Fingerprint", crypto::identity_fingerprint(&public)),
                    (
                        "Pinned token",
                        encode_contact_token(&alias, &public).map_err(se)?
                    ),
                ])
            );
            Ok(())
        }
        Some(("show", sm)) => {
            let alias = sm.get_one::<String>("name").map(String::as_str).unwrap();
            let public = ks.load_contact(alias).map_err(se)?;
            print!(
                "{}",
                render_kv(&[
                    ("Name", alias.to_string()),
                    ("Fingerprint", crypto::identity_fingerprint(&public)),
                    (
                        "Contact token",
                        encode_contact_token(alias, &public).map_err(se)?
                    ),
                ])
            );
            Ok(())
        }
        Some(("list", _)) => {
            let mut table = Table::new(&["Name", "Fingerprint"]);
            for alias in ks.list_contacts().map_err(se)? {
                let fpr = ks
                    .load_contact(&alias)
                    .map(|p| crypto::identity_fingerprint(&p))
                    .unwrap_or_else(|_| "(unavailable)".into());
                table.push(vec![alias, fpr]);
            }
            if table.is_empty() {
                println!("(no contacts)");
            } else {
                print!("{}", table.render());
            }
            Ok(())
        }
        Some(("remove", sm)) => {
            let alias = sm.get_one::<String>("name").map(String::as_str).unwrap();
            let cascaded = ks.remove_contact_cascade(alias).map_err(se)?;
            for group in &cascaded {
                println!("Removed shared-secret \"{group}\" ('{alias}' was a member).");
            }
            println!("Removed contact '{alias}'.");
            Ok(())
        }
        _ => Err("unknown contact subcommand".into()),
    }
}

// ---------------------
// Shared-secret helpers
// ---------------------

/// A resolved membership: the local identity providing the seed, and the ordered
/// `--party` contacts.
struct Members {
    self_public: PublicIdentity,
    contacts: Vec<(String, PublicIdentity)>,
    parties: Parties,
}

impl Members {
    /// The full member set (**self first**) the shape `group_ctx`,
    /// `setup_wrap_key` and `SetupToken::create` all take. Order carries no
    /// meaning to any of them (the 192-byte identities are sorted internally),
    /// but index 0 being self is what lets a signer index name a member.
    fn all(&self) -> Vec<PublicIdentity> {
        let mut v = Vec::with_capacity(self.contacts.len() + 1);
        v.push(self.self_public.clone());
        v.extend(self.contacts.iter().map(|(_, p)| p.clone()));
        v
    }

    /// The **other** members' identities, as `setup_wrap_key` wants them
    fn others(&self) -> Vec<PublicIdentity> {
        self.contacts.iter().map(|(_, p)| p.clone()).collect()
    }
}

/// Resolve `--keypair` and each `--party` against the local keystore.
///
/// One gate for `shared-secret create` and `import` alike. Rejects a duplicate
/// alias, yourself as a party, and two aliases pinning one key. That last check
/// earns its keep twice over in `import`: two members sharing a signing key would
/// make [`match_peer_tokens`]'s token-to-member matching ambiguous.
fn resolve_members(ks: &Keystore, keypair: &str, aliases: &[String]) -> Result<Members, String> {
    if !ks.identity_exists(keypair) {
        return Err(format!("no such keypair '{keypair}'"));
    }
    let self_public = ks.load_public_identity(keypair).map_err(se)?;

    // Party count = peers + 1; enforce 2 or 3
    let parties = Parties::from_u8((aliases.len() + 1) as u8).map_err(|_| {
        format!(
            "a shared secret needs 1 or 2 --party contacts (got {})",
            aliases.len()
        )
    })?;

    let mut contacts: Vec<(String, PublicIdentity)> = Vec::with_capacity(aliases.len());
    for alias in aliases {
        // Duplicate alias?
        if contacts.iter().any(|(a, _)| a == alias) {
            return Err(format!("duplicate --party '{alias}'"));
        }
        if !ks.contact_exists(alias) {
            return Err(format!(
                "'{alias}' is not a pinned contact (add it with `contact add`)"
            ));
        }
        let public = ks.load_contact(alias).map_err(se)?;
        if public == self_public {
            return Err(format!("--party '{alias}' is your own identity"));
        }
        // Is this a duplicate contact (same key under two aliases)?
        if contacts.iter().any(|(_, p)| *p == public) {
            return Err(format!(
                "--party '{alias}' pins the same key as another party"
            ));
        }
        contacts.push((alias.clone(), public));
    }

    Ok(Members {
        self_public,
        contacts,
        parties,
    })
}

/// The `--party` aliases on a command line, in the order given
fn party_aliases(m: &ArgMatches) -> Vec<String> {
    m.get_many::<String>("party")
        .map(|v| v.map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// A resolved group: the self identity, agreed name, and ordered peers
struct ResolvedGroup {
    keypair: String,
    group_name: String,
    self_public: PublicIdentity,
    contacts: Vec<(String, PublicIdentity)>,
    parties: Parties,
}

fn resolve_group(ks: &Keystore, m: &ArgMatches) -> Result<ResolvedGroup, String> {
    let keypair = m
        .get_one::<String>("keypair")
        .map(String::as_str)
        .unwrap()
        .to_string();
    let group_name = m
        .get_one::<String>("name")
        .map(String::as_str)
        .unwrap()
        .to_string();
    let mem = resolve_members(ks, &keypair, &party_aliases(m))?;
    Ok(ResolvedGroup {
        keypair,
        group_name,
        self_public: mem.self_public,
        contacts: mem.contacts,
        parties: mem.parties,
    })
}

fn cmd_shared_secret(m: &ArgMatches) -> Result<(), String> {
    match m.subcommand() {
        Some(("create", sm)) => cmd_ss_exchange(sm),
        Some(("list", sm)) => cmd_ss_list(sm),
        Some(("show", sm)) => cmd_ss_show(sm),
        Some(("remove", sm)) => cmd_ss_remove(sm),
        Some(("export", sm)) => cmd_ss_export(sm),
        Some(("import", sm)) => cmd_ss_import(sm),
        _ => Err("unknown shared-secret subcommand".into()),
    }
}

/// The `shared-secret create` exchange: form the group master `K` and store it.
/// Phase 1 (`--emit-token`) prints this party's token and stores nothing; phase
/// 2 (one `--token` per peer, or the interactive wizard) derives `K` and writes
/// the group state.
fn cmd_ss_exchange(m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let group = resolve_group(&ks, m)?;

    let tokens: Vec<&str> = m
        .get_many::<String>("token")
        .map(|v| v.map(String::as_str).collect())
        .unwrap_or_default();
    let force_wizard = m.get_flag("wizard");
    let force_emit = m.get_flag("emit-token");
    let interactive = {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal()
    };
    let completing = !tokens.is_empty();
    let will_store = completing || force_wizard || (interactive && !force_emit);

    // Fail fast: if the target name is already taken, say so no (before the
    // token exchange or unlocking the seed) rather than after. Phase-1
    // `--emit-token` stores nothing, so it is never blocked (a peer can still
    // emit their token).
    if will_store {
        if ks.shared_secret_exists(&group.group_name) {
            return Err(format!(
                "a shared-secret named \"{}\" already exists, `shared-secret remove {}` first",
                group.group_name, group.group_name
            ));
        }
        if ks.identity_exists(&group.group_name) {
            return Err(format!(
                "the name \"{}\" already exists as a keypair (keypairs and groups \
                 share one namespace)",
                group.group_name
            ));
        }
    }

    if completing {
        return complete_with_tokens(&ks, &group, &tokens);
    }

    if force_wizard || (interactive && !force_emit) {
        run_wizard_flow(&ks, &group)
    } else {
        emit_own_token(&ks, &group)
    }
}

/// The fingerprint of a stored group, or `(unavailable)` if a member cannot be
/// resolved (fingerprints are an aid, not a gate: listing must not fail).
fn stored_group_fingerprint(ks: &Keystore, state: &SharedSecretState) -> String {
    group_member_identities(ks, state)
        .and_then(|members| group_ctx(Purpose::Master, &state.group_name, &members).map_err(se))
        .map(|ctx| protocol::group_fingerprint(&ctx))
        .unwrap_or_else(|_| "(unavailable)".into())
}

fn cmd_ss_list(m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let filter = m.get_one::<String>("keypair").map(String::as_str);
    if let Some(f) = filter {
        if !ks.identity_exists(f) {
            return Err(format!("no such keypair '{f}'"));
        }
    }
    let mut table = Table::new(&["Name", "Owner", "Fingerprint"]);
    for group in ks.list_shared_secrets().map_err(se)? {
        match ks.load_shared_secret(&group) {
            Ok(state) => {
                if filter.is_none_or(|f| f == state.keypair) {
                    let fpr = stored_group_fingerprint(&ks, &state);
                    table.push(vec![group, state.keypair, fpr]);
                }
            }
            // Unreadable state: the owner is unknown, so such rows only show
            // up in the unfiltered listing.
            Err(_) if filter.is_none() => {
                table.push(vec![group, "(unavailable)".into(), "(unavailable)".into()]);
            }
            Err(_) => {}
        }
    }
    if table.is_empty() {
        println!("(no shared secrets)");
    } else {
        print!("{}", table.render());
    }
    Ok(())
}

/// Load a group's state for a positional that must name a group; a keypair
/// name gets a pointed error instead of a generic not-found.
fn load_group_arg(ks: &Keystore, name: &str, verb: &str) -> Result<SharedSecretState, String> {
    if ks.identity_exists(name) && !ks.shared_secret_exists(name) {
        return Err(format!(
            "'{name}' is a keypair; `shared-secret {verb}` takes a group name \
             (for per-site secrets use `hd-secret <command> {name} ...`)"
        ));
    }
    ks.load_shared_secret(name).map_err(se)
}

/// The common `Name / Owner / Members / Fingerprint` block for one group.
/// The full membership includes the owning keypair, listed first.
fn group_details(
    ks: &Keystore,
    name: &str,
    state: &SharedSecretState,
) -> Vec<(&'static str, String)> {
    let mut members = vec![state.keypair.clone()];
    members.extend(state.members.iter().cloned());
    vec![
        ("Name", name.to_string()),
        ("Owner", state.keypair.clone()),
        ("Members", members.join(", ")),
        ("Fingerprint", stored_group_fingerprint(ks, state)),
    ]
}

fn cmd_ss_show(m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let name = m.get_one::<String>("name").map(String::as_str).unwrap();
    let state = load_group_arg(&ks, name, "show")?;
    // Deliberately metadata-only: K is the group master keying every group
    // `hd-secret` and never leaves the keystore. Its leaf secrets are reached
    // only through `hd-secret copy <group>` / `reveal`.
    let mut kv = group_details(&ks, name, &state);
    kv.push((
        "Secret",
        format!("v{STATE_VERSION}, 32 bytes, derived on demand"),
    ));
    print!("{}", render_kv(&kv));
    Ok(())
}

fn cmd_ss_remove(m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let name = m.get_one::<String>("name").map(String::as_str).unwrap();
    if ks.identity_exists(name) && !ks.shared_secret_exists(name) {
        return Err(format!(
            "'{name}' is a keypair; use `keypair remove {name}` to remove it"
        ));
    }
    ks.remove_shared_secret(name).map_err(se)?;
    println!("Removed shared-secret \"{name}\".");
    Ok(())
}

/// Full member set (self first, then peers) for `group_ctx`/token building
fn member_set(group: &ResolvedGroup) -> Vec<PublicIdentity> {
    let mut members = Vec::with_capacity(group.contacts.len() + 1);
    members.push(group.self_public.clone());
    for (_, pk) in &group.contacts {
        members.push(pk.clone());
    }
    members
}

/// Phase 1: print this party's setup token and exit (no derivation, no storage)
fn emit_own_token(ks: &Keystore, group: &ResolvedGroup) -> Result<(), String> {
    let password = unlock_password(&group.keypair)?;
    let seed = ks.load_seed(&group.keypair, &password).map_err(se)?;
    let members = member_set(group);
    let wrap_key = group_setup_wrap_key(&seed, group, &members)?;
    let token =
        SetupToken::create(&seed, Purpose::Master, &group.group_name, &members).map_err(se)?;
    println!("Your setup token: {}", token.encode(&wrap_key));
    println!(
        "(send this to your {} peer(s); then re-run with one --token each to derive)",
        group.contacts.len()
    );
    Ok(())
}

/// The setup-token wrap key for this exchange: my seed, the other members'
/// pinned identities, and the full member set
fn group_setup_wrap_key(
    seed: &[u8; SEED_BYTES],
    group: &ResolvedGroup,
    members: &[PublicIdentity],
) -> Result<[u8; 32], String> {
    let others: Vec<PublicIdentity> = group.contacts.iter().map(|(_, pk)| pk.clone()).collect();
    protocol::setup_wrap_key(seed, &others, members).map_err(se)
}

/// Phase 2: verify one token per party, derive `K`, and store the group state
fn complete_with_tokens(
    ks: &Keystore,
    group: &ResolvedGroup,
    tokens: &[&str],
) -> Result<(), String> {
    if tokens.len() != group.contacts.len() {
        return Err(format!(
            "expected {} --token (one per --party, in matching order), got {}",
            group.contacts.len(),
            tokens.len()
        ));
    }
    let members = member_set(group);
    let ctx = group_ctx(Purpose::Master, &group.group_name, &members).map_err(se)?;

    // The wrap key (and hence decoding an encrypted token) needs our seed, so
    // unlock first-- before verifying, deriving, or decoding any peer token.
    let password = unlock_password(&group.keypair)?;
    let seed = ks.load_seed(&group.keypair, &password).map_err(se)?;
    let wrap_key = group_setup_wrap_key(&seed, group, &members)?;

    let mut peer_tokens = Vec::with_capacity(tokens.len());
    for (tok_str, (alias, contact)) in tokens.iter().zip(group.contacts.iter()) {
        let token = SetupToken::decode(tok_str, group.parties, &wrap_key).map_err(se)?;
        if token.group_name != group.group_name {
            // The foreign name is peer-authored and unverified her-- escape it!
            return Err(format!(
                "Token for '{alias}' is for group \"{}\", not \"{}\"",
                format::escape_control(&token.group_name),
                group.group_name
            ));
        }
        token.verify(&ctx, &contact.sig_g1, &members).map_err(se)?;
        peer_tokens.push(token);
    }

    let my_child = SetupToken::my_child_scalar(&seed, &ctx);
    let secret = derive_group_key(&my_child, &peer_tokens).map_err(se)?;

    // The non-interactive path has no wizard step to confirm the agreement
    // checksum, so print it here and compare it across the group to confirm
    // everyone derived the same secret. It is distinct from the group
    // Fingerprint shown below (that is over the public group context, not K).
    println!(
        "Checksum: {}  (compare across the group to confirm the same secret)",
        protocol::checksum(&secret)
    );

    finalize_shared_secret(ks, group, &peer_tokens)
}

/// Interactive wizard flow
fn run_wizard_flow(ks: &Keystore, group: &ResolvedGroup) -> Result<(), String> {
    let password = unlock_password(&group.keypair)?;
    let seed = ks.load_seed(&group.keypair, &password).map_err(se)?;
    // The no-echo password prompt above can leave the terminal without signal
    // generation; re-assert cooked, signal-enabled input so Ctrl-C interrupts
    // while pasting setup tokens.
    if clipboard::interactive() {
        clipboard::ensure_line_input();
    }
    let plan = GroupPlan {
        keypair_name: &group.keypair,
        group_name: &group.group_name,
        self_public: &group.self_public,
        contacts: &group.contacts,
        seed: &seed,
    };
    let mut term = StdioTerminal::new();
    let outcome = wizard::run_wizard(&mut term, &plan).map_err(se)?;
    finalize_shared_secret(ks, group, &outcome.peer_tokens)
}

/// Finish the exchange: store the group and print the same metadata block as
/// `shared-secret show`, never the secret, which stays in the keystore and is
/// re-derived on demand.
fn finalize_shared_secret(
    ks: &Keystore,
    group: &ResolvedGroup,
    peer_tokens: &[SetupToken],
) -> Result<(), String> {
    // The duplicate-name guard ran up front (see `cmd_ss_exchange`), so the
    // name is free here.
    let state = SharedSecretState {
        keypair: group.keypair.clone(),
        group_name: group.group_name.clone(),
        members: group.contacts.iter().map(|(a, _)| a.clone()).collect(),
        peers: peer_tokens.to_vec(),
    };
    ks.store_shared_secret(&group.group_name, &state)
        .map_err(se)?;

    // The finished block mirrors `shared-secret show`: metadata only
    let mut kv = group_details(ks, &group.group_name, &state);
    kv.push((
        "Secret",
        format!("v{STATE_VERSION}, 32 bytes, derived on demand"),
    ));
    print!("{}", render_kv(&kv));
    Ok(())
}

// ---------------------------------------------------
// Decentralized backup: shared-secret export / import
// ---------------------------------------------------

/// A stored group's full member set (self first) and the setup wrap key every
/// member of it derives, the static multiparty DH/Joux value over their
/// long-term identity keys.
///
/// Symmetric by construction, so the exporter and the importer arrive at the same
/// key from opposite sides: the exporter from its own seed plus its pins, the
/// importer from its own seed plus its pins. Neither needs `K`, and neither needs
/// the other's group state.
fn stored_group_wrap_key(
    ks: &Keystore,
    state: &SharedSecretState,
    seed: &[u8; SEED_BYTES],
) -> Result<(Vec<PublicIdentity>, [u8; 32]), String> {
    let members = group_member_identities(ks, state)?;
    let wrap_key = protocol::setup_wrap_key(seed, &members[1..], &members).map_err(se)?;
    Ok((members, wrap_key))
}

fn cmd_ss_export(m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let name = m.get_one::<String>("name").map(String::as_str).unwrap();
    let out = std::path::PathBuf::from(m.get_one::<String>("file").map(String::as_str).unwrap());
    let state = load_group_arg(&ks, name, "export")?;

    let parties = state.parties().map_err(se)?;
    let password = unlock_password(&state.keypair)?;
    let seed = ks.load_seed(&state.keypair, &password).map_err(se)?;
    let (members, wrap_key) = stored_group_wrap_key(&ks, &state, &seed)?;

    // One file suffices from *any* member. `state.peers` records every peer's
    // token but never our own because we never needed it, since `derive_group_key`
    // takes our child *scalar*. It regenerates: `SetupToken::create` is a pure
    // function of `(seed, purpose, group_name, members)` and BLS signing is
    // deterministic. So alice's export holds {tok_A, tok_B, tok_C}; bob needs
    // tok_A and tok_C and ignores the copy of his own.
    let mine =
        SetupToken::create(&seed, Purpose::Master, &state.group_name, &members).map_err(se)?;
    let mut tokens = vec![mine];
    tokens.extend(state.peers.iter().cloned());

    // Re-verifies every peer token against its pinned contact on the way
    let k = crypto::SecretScalar::new(ks.reconstruct_shared_secret(&state, &seed).map_err(se)?);
    let scope = crate::keystore::RegistryScope::Group(name.to_string());
    let reg = ks.load_registry(&scope, &seed).map_err(se)?;

    let body = export::build_body(&state.group_name, parties, &tokens, &reg, &k);
    let bytes = export::seal(&seed, &wrap_key, &body).map_err(se)?;
    crate::keystore::write_atomic_secure(&out, &bytes).map_err(se)?;

    let live = reg.live().len();
    let removed = reg.entries.len() - live;
    println!("Wrote {} ({} bytes).", out.display(), bytes.len());
    println!(
        "Checksum: {}  (`import` prints the same one)",
        protocol::checksum(&k)
    );
    println!();
    println!(
        "Group \"{}\" · {}-party · {live} definition(s), {removed} removed, {} archived recipe(s).",
        state.group_name,
        parties.as_u8(),
        reg.archive.len()
    );
    println!(
        "Sealed to the membership: any member can open it, nobody else can. It holds no\n\
         seed, no group master and no password, so it is safe to send over an unencrypted\n\
         channel. A member restores it with:"
    );
    println!();
    println!(
        "    sesh shared-secret import {} --keypair <you> {}",
        out.display(),
        state
            .members
            .iter()
            .map(|_| "--party <alias>")
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!();
    // An export is one member's snapshot, and this command cannot know whether it
    // is behind: nothing in the keystore records what the other members hold. Say
    // so, rather than pretend to a group-wide truth the file does not carry.
    println!(
        "This is a snapshot of your registry as it stands. If you are holding share\n\
         tokens you have not applied, run `sesh hd-secret apply <token>` on them first."
    );
    Ok(())
}

/// Match every setup token in the payload to exactly one member, by signature,
/// and return the peers' tokens aligned to `contacts`.
///
/// A **bijection**, not a filter. The exporter ships all N tokens, yours
/// included, and yours is the one the derivation must never take from the file:
/// `derive_group_key` gets your child *scalar*, re-derived from your own seed.
/// Requiring each token to claim exactly one member drops yours as a matter of
/// arithmetic, and rejects a padded or duplicated list on the way.
///
/// [`SetupToken::verify`] does the real work: it re-checks the BLS signature
/// against the **locally recomputed** `ctx`, so a token signed for another name
/// or another membership fails here, which is what binds the payload's
/// `group_name`, since a member cannot forge their peers' signatures over a
/// context they never agreed to. It also runs the 3-party DH-pair consistency
/// check and child-key disjointness.
///
/// Only `BadSignature` means "not this member". Every other error is a genuine
/// rejection and propagates rather than being retried against the next member.
fn match_peer_tokens(
    tokens: &[SetupToken],
    ctx: &[u8; 32],
    members: &[PublicIdentity],
    contacts: &[(String, PublicIdentity)],
    keypair: &str,
    group_name: &str,
) -> Result<Vec<SetupToken>, String> {
    let mut taken = vec![false; tokens.len()];
    let mut matched: Vec<Option<SetupToken>> = vec![None; members.len()];

    for (i, member) in members.iter().enumerate() {
        for (j, tok) in tokens.iter().enumerate() {
            if taken[j] {
                continue;
            }
            match tok.verify(ctx, &member.sig_g1, members) {
                Ok(()) => {
                    taken[j] = true;
                    matched[i] = Some(tok.clone());
                    break;
                }
                Err(protocol::ProtocolError::BadSignature) => continue,
                Err(e) => return Err(se(e)),
            }
        }
        if matched[i].is_none() {
            let who = if i == 0 {
                format!("you ('{keypair}')")
            } else {
                format!("'{}'", contacts[i - 1].0)
            };
            return Err(format!(
                "The export carries no setup token signed by {who} for group \"{group_name}\" - \
                 it was built for a different membership, or one of its tokens was swapped"
            ));
        }
    }
    // `matched[0]` is our own token: verified, then discarded. We contribute the
    // child scalar, never the child pubkey.
    Ok(matched
        .into_iter()
        .skip(1)
        .map(|t| t.expect("every member matched"))
        .collect())
}

/// `open` fails at the AEAD when the file is not sealed for *this exact*
/// membership. Say that, and only that.
///
/// No signature has been checked at this point, and naming one would send a user
/// who mistyped a `--party` looking for a forged file. The AEAD cannot tell a
/// wrong wrap key from a flipped bit, by design, so neither can this message.
fn export_open_error(e: export::ExportError, keypair: &str, aliases: &[String]) -> String {
    match e {
        export::ExportError::Decrypt => format!(
            "could not open the export. It is sealed to an exact membership, and the one \
             given here is you ('{keypair}') plus {}. Every member of the group (and \
             nobody else) must be named with --party and pinned with `contact add`. \
             Otherwise the file is corrupt.",
            aliases
                .iter()
                .map(|a| format!("'{a}'"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => se(other),
    }
}

/// One registry row as the import diff prints it
fn row_selector(d: &crate::registry::Definition) -> String {
    if d.user.is_empty() {
        d.id.clone()
    } else {
        format!("{} (user '{}')", d.id, d.user)
    }
}

fn cmd_ss_import(m: &ArgMatches) -> Result<(), String> {
    cmd_ss_import_with(&mut StdioTerminal::new(), m)
}

/// Verify a member's export end to end, then merge it.
///
/// Everything verifies **before anything is written**, the discipline
/// `backup.rs` already keeps, where `read_manifest` validates every path before
/// `apply_manifest` touches disk. The order below is load-bearing:
///
/// 1. Read the file and resolve the membership, so a missing path or a typo'd
///    `--party` costs no password prompt.
/// 2. Unlock once; derive the setup wrap key.
/// 3. Open the AEAD. Failure means: not a member, wrong `--party` set, or a
///    corrupt file-- indistinguishable, and it must stay that way.
/// 4. Verify the signature; the match identifies the exporter.
/// 5. Recompute `group_ctx` from **our** pins, match every token to a member, and
///    derive `K` from our own child scalar. Print the agreement checksum.
/// 6. Re-gate the (member-signed, member-*untrusted*) params, then run layer 4's
///    fingerprint tripwire.
/// 7. Classify the merge, render the diff, prompt. Only then write.
///
/// The checksum is printed, never gated on. The wizard gates because its peer
/// tokens arrive over an unauthenticated paste; here they arrive AEAD-sealed to
/// the exact membership and BLS-signed.
fn cmd_ss_import_with<T: wizard::Terminal>(term: &mut T, m: &ArgMatches) -> Result<(), String> {
    use crate::keystore::RegistryScope;
    use crate::registry::ApplyOutcome;

    let ks = keystore()?;
    let path = std::path::PathBuf::from(m.get_one::<String>("file").map(String::as_str).unwrap());
    let dry_run = m.get_flag("dry-run");
    let keypair = m
        .get_one::<String>("keypair")
        .map(String::as_str)
        .unwrap()
        .to_string();
    let aliases = party_aliases(m);

    // 1. A missing file and a bad alias must both fail before the prompt
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mem = resolve_members(&ks, &keypair, &aliases)?;
    let members = mem.all();

    // 2. One password prompt
    let password = unlock_password(&keypair)?;
    let seed = ks.load_seed(&keypair, &password).map_err(se)?;
    let wrap_key = protocol::setup_wrap_key(&seed, &mem.others(), &members).map_err(se)?;

    // 3. Layer 1: the AEAD. Also gates both versions and the body's structure
    let opened =
        export::open(&bytes, &wrap_key).map_err(|e| export_open_error(e, &keypair, &aliases))?;

    // 4. Layer 2: attribution. Signed by yourself is legal (you are restoring
    //    your own file) and `members[0]` is you.
    let signer = export::verify_signer(&opened, &members).map_err(se)?;
    let signed_by = if signer == 0 {
        format!("{keypair} (you)")
    } else {
        mem.contacts[signer - 1].0.clone()
    };

    // `open` already checked `parties == tokens.len()`; this cross-checks it
    // against *us*. Belt and braces: a payload whose party count disagrees with
    // the `--party` list was sealed under a different wrap-key shape and a
    // different membership commitment, so step 3 rejected it already. Cheap to
    // keep, and it stops the two facts from silently drifting apart.
    let body = opened.body();
    if body.parties != mem.parties.as_u8() {
        return Err(format!(
            "the export is for a {}-party group, but {} --party contact(s) were given",
            body.parties,
            mem.contacts.len()
        ));
    }

    // A signed member could still name the group `../../etc`. Defense in depth:
    // the name is about to become a directory under `shared-secrets/`.
    let group_name = body.group_name.clone();
    crate::keystore::validate_new_name(&group_name).map_err(se)?;

    // If the group is already here it must be the *same* group, and its state is
    // never rewritten. A member set that disagrees is not a merge, it is a
    // different group wearing the same name.
    let existing = if ks.shared_secret_exists(&group_name) {
        Some(ks.load_shared_secret(&group_name).map_err(se)?)
    } else {
        if ks.identity_exists(&group_name) {
            return Err(format!(
                "the export names a group \"{group_name}\", but that is already a keypair \
                 here (keypairs and groups share one namespace)"
            ));
        }
        None
    };
    if let Some(st) = &existing {
        if st.keypair != keypair {
            return Err(format!(
                "\"{group_name}\" already exists here, owned by keypair '{}', not '{keypair}'. \
                 `shared-secret remove {group_name}` first if you mean to replace it.",
                st.keypair
            ));
        }
        let (mut have, mut want) = (st.members.clone(), aliases.clone());
        have.sort();
        want.sort();
        if have != want {
            return Err(format!(
                "\"{group_name}\" already exists here with members {}, not {}. \
                 `shared-secret remove {group_name}` first if you mean to replace it.",
                st.members.join(", "),
                aliases.join(", ")
            ));
        }
    }

    // 5. The context: the name from the payload (every peer token is signed over
    //    it, so a member cannot rename the group without their peers' seeds), the
    //    membership from our own pins, never values read from the file.
    let ctx = group_ctx(Purpose::Master, &group_name, &members).map_err(se)?;
    let tokens = export::decode_tokens(body).map_err(se)?;
    let peer_tokens = match_peer_tokens(
        &tokens,
        &ctx,
        &members,
        &mem.contacts,
        &keypair,
        &group_name,
    )?;

    let my_child = SetupToken::my_child_scalar(&seed, &ctx);
    let k = crypto::SecretScalar::new(derive_group_key(&my_child, &peer_tokens).map_err(se)?);

    // 6. Member-signed is not member-trusted, the doctrine `hd_apply` states
    for d in export::fingerprinted_rows(&body.registry) {
        // Gate the strings before the diff below prints them; the error's own
        // `{:?}` escaping (inside `validate_hd_strings`) keeps it safe to show.
        validate_hd_strings(&d.id, &d.user)
            .map_err(|e| format!("the export carries a malformed definition: {e}"))?;
        validate_params(&d.params).map_err(|e| {
            format!(
                "the export carries invalid params for {} at epoch {}: {e}",
                row_selector(d),
                d.epoch
            )
        })?;
    }
    // Layer 4's tripwire. Redundant given layers 1-3, and it fires only on a bug
    export::check_fingerprints(body, &k).map_err(se)?;

    // 7. Classify against the *local* registry. Every incoming entry has a
    //    distinct `(id, user)` (structure, checked by `open`), so adopting one
    //    cannot re-classify another, and a single pass is exact.
    let scope = RegistryScope::Group(group_name.clone());
    let local = ks.load_registry(&scope, &seed).map_err(se)?;
    let mut merged = local.clone();

    let mut adopted: Vec<crate::registry::Definition> = Vec::new();
    let mut rows: Vec<String> = Vec::new();
    let mut conflicts: Vec<String> = Vec::new();
    let mut up_to_date = 0usize;
    let mut stale = 0usize;

    for d in &body.registry.entries {
        match local.classify(&d.id, &d.user, d.epoch, &d.params, d.tombstone) {
            ApplyOutcome::Adopt => {
                let before = local
                    .entries
                    .iter()
                    .find(|e| e.id == d.id && e.user == d.user);
                let (verb, epochs) = match (before, d.tombstone) {
                    (None, false) => ("new", format!("epoch {}", d.epoch)),
                    (None, true) => ("remove", format!("epoch {} (removed)", d.epoch)),
                    (Some(b), false) => ("update", format!("epoch {} → {}", b.epoch, d.epoch)),
                    (Some(b), true) => (
                        "remove",
                        format!("epoch {} → {} (removed)", b.epoch, d.epoch),
                    ),
                };
                rows.push(format!("  {verb:<10}  {:<32}  {epochs}", row_selector(d)));
                adopted.push(d.clone());
            }
            ApplyOutcome::AlreadyApplied => up_to_date += 1,
            ApplyOutcome::Stale { local_epoch } => {
                stale += 1;
                rows.push(format!(
                    "  {:<10}  {:<32}  local epoch {local_epoch} > {} incoming (kept)",
                    "stale",
                    row_selector(d),
                    d.epoch
                ));
            }
            ApplyOutcome::Conflict => {
                conflicts.push(row_selector(d));
                rows.push(format!(
                    "  {:<10}  {:<32}  epoch {} - params differ (kept)",
                    "conflict",
                    row_selector(d),
                    d.epoch
                ));
            }
        }
    }

    for d in &adopted {
        merged.adopt(&d.id, &d.user, d.epoch, d.params.clone(), d.tombstone);
    }
    // Archived rows merge first-writer-wins, and **after** the adopts. `adopt`
    // files the superseded local recipe under its own epoch; absorbing first
    // would let an incoming row win that key and quietly rewrite local recovery
    // history, which is exactly what `archive_push`'s dedup exists to prevent.
    let mut absorbed = 0usize;
    for d in &body.registry.archive {
        if merged.archived(&d.id, &d.user, d.epoch).is_none() {
            absorbed += 1;
        }
        merged.absorb_archive(d.clone());
    }

    // Report. Layer 3: the checksum both sides compute from the `K` each derived
    println!("Importing \"{group_name}\"  ·  signed by '{signed_by}'");
    println!(
        "Checksum: {}  (matches '{signed_by}'s export)",
        protocol::checksum(&k)
    );
    if existing.is_none() {
        println!(
            "New group: {}-party, you ('{keypair}') plus {}",
            mem.parties.as_u8(),
            aliases.join(", ")
        );
    }
    println!();
    for r in &rows {
        println!("{r}");
    }
    if up_to_date > 0 {
        println!(
            "  {:<10}  {up_to_date} entr{}",
            "up to date",
            if up_to_date == 1 { "y" } else { "ies" }
        );
    }
    if absorbed > 0 {
        println!(
            "  {:<10}  {absorbed} superseded recipe(s) to absorb",
            "archive"
        );
    }
    if rows.is_empty() && up_to_date == 0 && absorbed == 0 {
        println!("  (the export carries an empty registry)");
    }
    println!();

    if !conflicts.is_empty() {
        // Punted deliberately. `classify` already declares a same-epoch content
        // difference a thing the *user* must resolve, and `hd-secret apply`'s
        // conflict branch is the existing UI for exactly one such decision.
        println!(
            "Conflicts are not resolved here. Ask '{signed_by}' to run\n    \
             sesh hd-secret share {group_name} {}\n\
             and apply the token with `sesh hd-secret apply <token>`: it shows both recipes\n\
             side by side and lets you pick.",
            conflicts[0]
        );
        println!();
    }

    let creating = existing.is_none();
    let changed = !adopted.is_empty() || absorbed > 0;
    if !creating && !changed {
        // "Already up to date" and "everything incoming lost" are different
        // answers, and the second one must not wear the first one's words.
        let skipped = stale + conflicts.len();
        if skipped == 0 {
            println!("Nothing to import: your registry already holds everything in this file.");
        } else {
            println!(
                "Nothing applied: all {skipped} incoming change(s) were stale or conflicting, \
                 and your versions were kept."
            );
        }
        return Ok(());
    }
    if dry_run {
        println!("--dry-run: nothing was written.");
        return Ok(());
    }

    let mut parts: Vec<String> = Vec::new();
    if creating {
        parts.push(format!("create group \"{group_name}\""));
    }
    if !adopted.is_empty() {
        parts.push(format!("apply {} change(s)", adopted.len()));
    }
    if absorbed > 0 {
        parts.push(format!("absorb {absorbed} archived recipe(s)"));
    }
    // Read as a sentence, whatever the combination: "Create group "team", apply
    // 4 change(s) and absorb 12 archived recipe(s) from 'bob'?"
    let mut action = match parts.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, head)) => format!("{} and {last}", head.join(", ")),
        None => unreachable!("`creating || changed` is checked above"),
    };
    action[..1].make_ascii_uppercase();
    if !term
        .confirm(&format!("{action} from '{signed_by}'? [y/N] "))
        .map_err(se)?
    {
        return Err("not imported".into());
    }

    // Write. `store_shared_secret` first, so `save_registry`'s group directory
    // exists and a failure leaves no registry orphaned under a missing state.
    if creating {
        let state = SharedSecretState {
            keypair: keypair.clone(),
            group_name: group_name.clone(),
            members: aliases.clone(),
            peers: peer_tokens,
        };
        ks.store_shared_secret(&group_name, &state).map_err(se)?;
        println!("Restored group \"{group_name}\".");
    }
    if changed {
        ks.save_registry(&scope, &seed, &merged).map_err(se)?;
    }
    println!(
        "Imported {} change(s) and {absorbed} archived recipe(s) from '{signed_by}'.",
        adopted.len()
    );
    Ok(())
}

// -----------------
// Hd-secret helpers
// -----------------

fn cmd_hd_secret(m: &ArgMatches) -> Result<(), String> {
    // Every subcommand except `apply` carries a required `owner` positional;
    // `apply` has none, because the token itself identifies the group.
    fn owner(sm: &ArgMatches) -> &str {
        sm.get_one::<String>("owner").expect("required").as_str()
    }
    match m.subcommand() {
        Some(("apply", sm)) => cmd_hd_apply(sm),
        Some(("list", sm)) => cmd_hd_list(owner(sm), sm),
        Some(("create", sm)) => cmd_hd_create(owner(sm), sm),
        Some(("show", sm)) => cmd_hd_show(owner(sm), sm),
        Some(("copy", sm)) => cmd_hd_copy(owner(sm), sm),
        Some(("rotate", sm)) => cmd_hd_rotate(owner(sm), sm),
        Some(("remove", sm)) => cmd_hd_remove(owner(sm), sm),
        Some(("reveal", sm)) => cmd_hd_reveal(owner(sm), sm),
        Some(("share", sm)) => cmd_hd_share(owner(sm), sm),
        _ => Err("unknown hd-secret subcommand".into()),
    }
}

/// A resolved registry scope: the storage scope plus the keypair whose seed
/// protects it (and, for a group, the loaded state used to reconstruct `K`).
struct RegScope {
    scope: crate::keystore::RegistryScope,
    owner_keypair: String,
    group_state: Option<SharedSecretState>,
}

/// Resolve a bare owner name: a keypair, else a shared-secret group. The two
/// namespaces are kept disjoint at creation, so a name can only be ambiguous
/// in a legacy store.
fn resolve_owner(ks: &Keystore, name: &str) -> Result<RegScope, String> {
    use crate::keystore::RegistryScope;
    match (ks.identity_exists(name), ks.shared_secret_exists(name)) {
        (true, true) => Err(format!(
            "'{name}' names both a keypair and a shared-secret group (legacy store), \
             remove or rename one of them"
        )),
        (true, false) => Ok(RegScope {
            scope: RegistryScope::Keypair(name.to_string()),
            owner_keypair: name.to_string(),
            group_state: None,
        }),
        (false, true) => {
            let state = ks.load_shared_secret(name).map_err(se)?;
            Ok(RegScope {
                scope: RegistryScope::Group(name.to_string()),
                owner_keypair: state.keypair.clone(),
                group_state: Some(state),
            })
        }
        (false, false) => Err(format!("no keypair or shared-secret named '{name}'")),
    }
}

/// Resolve `owner` and unlock its protecting keypair's seed
fn unlock_owner(
    ks: &Keystore,
    owner: &str,
) -> Result<(RegScope, Zeroizing<[u8; SEED_BYTES]>), String> {
    let rs = resolve_owner(ks, owner)?;
    let password = unlock_password(&rs.owner_keypair)?;
    let seed = ks.load_seed(&rs.owner_keypair, &password).map_err(se)?;
    Ok((rs, seed))
}

/// The HD master scalar for a scope: `s_dh` for a keypair, or `K` for a group.
/// Returned as a [`SecretScalar`] so this long-lived secret is scrubbed on drop
/// (`Deref` lets it stand in for `&Scalar` at every call site).
fn master_for(
    ks: &Keystore,
    rs: &RegScope,
    seed: &[u8; SEED_BYTES],
) -> Result<crypto::SecretScalar, String> {
    let scalar = match &rs.group_state {
        None => derive_dh_scalar(seed),
        Some(state) => ks.reconstruct_shared_secret(state, seed).map_err(se)?,
    };
    Ok(crypto::SecretScalar::new(scalar))
}

/// The derived child scalar for a stored definition
fn hd_child_of(master: &Scalar, def: &crate::registry::Definition) -> Scalar {
    crypto::hd_child(master, &canonical_hd_context(&def.id, &def.user, def.epoch))
}

/// The `<recipe>-<secret>` fingerprint of a stored definition: the secret half
/// over the child `(master, id, user, epoch)` derives, the recipe half over that
/// child *and* the params that format it.
///
/// Taken over the definition's **stored** params, which are also the params it
/// renders under, so the fingerprint attests exactly the string `copy`/`reveal`
/// will produce: two members whose fingerprints agree hold the same password,
/// character for character, and not merely the same underlying child.
fn hd_fingerprint_of(master: &Scalar, def: &crate::registry::Definition) -> String {
    crypto::hd_fingerprint(&def.params.canonical_bytes(), &hd_child_of(master, def))
}

/// The `Params:` value for a stored definition, with an untrimmed recipe
/// annotated by the character count it currently renders to.
///
/// The secret is derived to measure it and scrubbed on the spot; only its length
/// leaves this function. That length is not a secret (every mode's maximum is a
/// public constant) but the string it was measured from is.
///
/// A definition whose params no longer render (a hand-edited registry, say) is
/// simply left unannotated rather than allowed to break the display.
///
/// otp-mode definitions are also left unannotated: "(32 chars)" would describe
/// the Base32 export, not the 6-digit code the user actually sees, so it
/// misleads - and the mode name already says everything about the shape.
fn describe_params(master: &Scalar, def: &crate::registry::Definition) -> String {
    let rendered = match def.params.length {
        Some(_) => None, // an explicit trim already says the length exactly
        None if def.params.mode == "otp" => None,
        None => registry_secret(master, def)
            .ok()
            .map(|s| Zeroizing::new(s).chars().count()),
    };
    def.params.describe_with_rendered_length(rendered)
}

/// The common `Id / User / Epoch / Params / Fingerprint` block for one
/// definition (User omitted when empty), led by a `Group:` row for
/// group-owned entries. Callers append their own final rows.
fn def_details(
    master: &Scalar,
    def: &crate::registry::Definition,
    group: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut kv: Vec<(&'static str, String)> = Vec::new();
    if let Some(g) = group {
        kv.push(("Group", g.to_string()));
    }
    kv.push(("Id", def.id.clone()));
    if !def.user.is_empty() {
        kv.push(("User", def.user.clone()));
    }
    kv.push(("Epoch", def.epoch.to_string()));
    kv.push(("Params", describe_params(master, def)));
    kv.push(("Fingerprint", hd_fingerprint_of(master, def)));
    kv
}

/// Derive and format the secret for a stored definition, the one way its stored
/// params say.
///
/// **Egress is single-valued, and that is a security property.** Rendering one
/// child under a caller-chosen mode would hand back the entropy a lossy recipe
/// (a trimmed, symbol-mixed password) deliberately withholds: a password's
/// child rendered as `otp` would mint TOTP codes anyone holding that password
/// could compute. It is also what lets a fingerprint attest the exact string a
/// member will copy, not just the child behind it. Re-shaping is `rotate`,
/// which advances the epoch.
fn registry_secret(
    master: &Scalar,
    def: &crate::registry::Definition,
) -> Result<String, String> {
    let params = &def.params;
    let child = hd_child_of(master, def);
    format::format_secret(
        &child.to_bytes_le(),
        &params.mode,
        params.length,
        params.suffix.as_deref(),
        params.symbols.as_deref(),
    )
}

/// The full member set of a group scope (self first), as pinned identities
fn group_member_identities(
    ks: &Keystore,
    state: &SharedSecretState,
) -> Result<Vec<PublicIdentity>, String> {
    let mut ids = Vec::with_capacity(state.members.len() + 1);
    ids.push(ks.load_public_identity(&state.keypair).map_err(se)?);
    for alias in &state.members {
        ids.push(ks.load_contact(alias).map_err(se)?);
    }
    Ok(ids)
}

/// Sign and print the share token broadcasting a group-scope definition change.
/// Personal (keypair-owned) definitions are local-only, so callers pass a
/// group state only when there is one.
fn print_share_token(
    ks: &Keystore,
    state: &SharedSecretState,
    seed: &[u8; SEED_BYTES],
    action: ShareAction,
    def: &crate::registry::Definition,
) -> Result<(), String> {
    println!(
        "Share token: {}",
        group_share_token(ks, state, seed, action, def)?
    );
    Ok(())
}

/// Sign and encode the share token broadcasting a group-scope definition
fn group_share_token(
    ks: &Keystore,
    state: &SharedSecretState,
    seed: &[u8; SEED_BYTES],
    action: ShareAction,
    def: &crate::registry::Definition,
) -> Result<String, String> {
    let members = group_member_identities(ks, state)?;
    let ctx = group_ctx(Purpose::Master, &state.group_name, &members).map_err(se)?;
    let token = ShareToken::create(
        seed,
        &ctx,
        action,
        &def.id,
        &def.user,
        def.epoch,
        def.params.clone(),
    )
    .map_err(se)?;
    // Encrypt the token body under the group secret K, so only members can read
    // the recipe (id/user/epoch/params) it carries over the insecure channel.
    let k = ks.reconstruct_shared_secret(state, seed).map_err(se)?;
    token.encode(&crypto::share_wrap_key(&k)).map_err(se)
}

fn cmd_hd_list(owner: &str, m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let (rs, seed) = unlock_owner(&ks, owner)?;
    let reg = ks.load_registry(&rs.scope, &seed).map_err(se)?;
    let master = master_for(&ks, &rs, &seed)?;
    let archived = m.get_flag("archived");
    let verbose = m.get_flag("verbose");

    // Say which kind of owner this registry belongs to
    if rs.group_state.is_some() {
        println!("Group: {owner}");
    } else {
        println!("Personal: {owner}");
    }
    // The archive holds past recipes, not past secrets: every row is one epoch's
    // formatting, and `copy --recover <epoch>` is what turns a row back into a
    // password. Both listings are sorted by (id, user), the archive then by epoch.
    if archived {
        println!("(archived recipes, superseded by `rotate` or `remove`)");
    }
    println!();
    // The plain listing gets a Mode column - the bare mode name is what tells
    // an otp entry (a code generator) from a password at a glance. The verbose
    // listing already names the mode inside Params, so there it would only be
    // a duplicate.
    let mut table = if verbose {
        Table::new(&["Id", "User", "Epoch", "Params", "Fingerprint"])
    } else {
        Table::new(&["Id", "User", "Epoch", "Mode", "Fingerprint"])
    };
    let rows = if archived {
        reg.archived_all()
    } else {
        reg.live()
    };
    for d in rows {
        let mut row = vec![d.id.clone(), d.user.clone(), d.epoch.to_string()];
        if verbose {
            row.push(describe_params(&master, d));
        } else {
            row.push(d.params.mode.clone());
        }
        row.push(hd_fingerprint_of(&master, d));
        table.push(row);
    }
    if table.is_empty() {
        println!(
            "{}",
            if archived {
                "(no archived recipes)"
            } else {
                "(no definitions)"
            }
        );
    } else {
        print!("{}", table.render());
        if archived {
            println!();
            println!("Recover one with: hd-secret copy {owner} <id> [user] --recover <epoch>");
        }
    }
    Ok(())
}

/// Print the show-style summary of a definition: details + fingerprint,
/// never the secret. Group-owned entries lead with a `Group:` row.
fn print_def_summary(master: &Scalar, def: &crate::registry::Definition, group: Option<&str>) {
    let mut kv = def_details(master, def, group);
    // The derived secret has no schema version, only the registry that records
    // its recipe does, and that is not what this row describes.
    kv.push(("Secret", "32 bytes, derived on demand".to_string()));
    print!("{}", render_kv(&kv));
}

/// The group name of a group-owned scope (for the summary's `Group:` row)
fn scope_group_name(rs: &RegScope) -> Option<&str> {
    rs.group_state.as_ref().map(|s| s.group_name.as_str())
}

/// The fields that differ between a local definition and an incoming one, as
/// `(field, old, new)` display tuples (for `apply`'s change block).
fn def_changes(
    before: &crate::registry::Definition,
    after: &crate::registry::Definition,
) -> Vec<(&'static str, String, String)> {
    let opt_num = |v: Option<u64>| v.map_or("(none)".to_string(), |n| n.to_string());
    let opt_str = |v: &Option<String>| {
        v.as_ref()
            .map_or("(none)".to_string(), |s| format!("\"{s}\""))
    };
    let mut changes = Vec::new();
    if before.epoch != after.epoch {
        changes.push(("epoch", before.epoch.to_string(), after.epoch.to_string()));
    }
    if before.params.mode != after.params.mode {
        changes.push((
            "mode",
            before.params.mode.clone(),
            after.params.mode.clone(),
        ));
    }
    if before.params.length != after.params.length {
        changes.push((
            "length",
            opt_num(before.params.length),
            opt_num(after.params.length),
        ));
    }
    // Print the sets verbatim, never yes/no. This is the surface on which a
    // human disambiguates two symbol sets, and the reason `describe()` may
    // render the default one as a bare `--symbols` elsewhere.
    if before.params.symbols != after.params.symbols {
        changes.push((
            "symbols",
            opt_str(&before.params.symbols),
            opt_str(&after.params.symbols),
        ));
    }
    if before.params.suffix != after.params.suffix {
        changes.push((
            "suffix",
            opt_str(&before.params.suffix),
            opt_str(&after.params.suffix),
        ));
    }
    changes
}

fn cmd_hd_create(owner: &str, m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let id = m.get_one::<String>("id").map(String::as_str).unwrap();
    let user = m
        .get_one::<String>("user")
        .map(String::as_str)
        .unwrap_or("");
    // Before any prompt: an id that cannot be displayed safely is a usage error.
    validate_hd_strings(id, user)?;
    let recover = parse_recover(m)?;
    // An invalid recipe is a usage error and must not cost a password prompt, so
    // the ordinary path validates its flags before unlocking anything. A recovery
    // cannot: its params are merged over a recipe only the decrypted registry
    // holds, so `merge_params` validates them later, inside `recover_definition`.
    let params = match recover {
        None => Some(parse_params(m)?),
        Some(_) => None,
    };

    let (rs, seed) = unlock_owner(&ks, owner)?;
    let mut reg = ks.load_registry(&rs.scope, &seed).map_err(se)?;

    let def = match (recover, params) {
        (None, Some(p)) => reg.create(id, user, p).map_err(se)?.clone(),
        (Some(epoch), _) => {
            let mut term = StdioTerminal::new();
            recover_definition(&mut term, &mut reg, id, user, epoch, m, &rs)?
        }
        (None, None) => unreachable!("params are built whenever --recover is absent"),
    };
    ks.save_registry(&rs.scope, &seed, &reg).map_err(se)?;

    // Details only-- retrieve the secret via `copy`/`reveal`. A group-owned
    // create also emits the share token for the other members.
    let master = master_for(&ks, &rs, &seed)?;
    print_def_summary(&master, &def, scope_group_name(&rs));
    match (recover, &rs.group_state) {
        // A recovery below the peers' epoch is `Stale` at every peer, and `apply`
        // ignores it *silently*; printing a token here would look like a sync
        // and be none. Say what must actually happen instead.
        (Some(_), Some(_)) => {
            let sel = if user.is_empty() {
                id.to_string()
            } else {
                format!("{id} {user}")
            };
            println!();
            println!(
                "No share token: a recovery cannot be synced. Every other member must run\n    \
                 sesh hd-secret create {owner} {sel} --recover {}\n\
                 for the group to agree. The recipe above is inherited, so it need not be retyped.",
                def.epoch
            );
        }
        (None, Some(state)) => {
            println!();
            println!(
                "Share token: {}",
                group_share_token(&ks, state, &seed, ShareAction::New, &def)?
            );
        }
        _ => {}
    }
    Ok(())
}

/// Refuse a formatting flag typed alongside `--recover`.
///
/// A recovery reproduces a recorded recipe; a flag that changed it would make
/// the recovered password depend on what the user typed, so two members
/// recovering the same epoch could hold different passwords while agreeing on
/// everything the tool shows them. `rotate` is where a shape changes.
fn recovery_takes_no_formatting_flags(m: &ArgMatches) -> Result<(), String> {
    let typed = [
        ("--mode", explicit_mode(m).is_some()),
        ("--length", m.get_one::<String>("length").is_some()),
        ("--symbols", m.contains_id("symbols")),
        ("--no-symbols", m.get_flag("no-symbols")),
        ("--suffix", m.get_one::<String>("suffix").is_some()),
    ];
    let named: Vec<&str> = typed.iter().filter(|(_, on)| *on).map(|(f, _)| *f).collect();
    if named.is_empty() {
        return Ok(());
    }
    Err(format!(
        "--recover restores the recipe as recorded at that epoch, so it cannot be \
         combined with {}",
        named.join(", ")
    ))
}

/// `create --recover <EPOCH>`: overwrite the entry at exactly `epoch`, live,
/// **exactly as it was recorded**.
///
/// The recipe is read, never typed: `recipe_at` refuses an epoch it has no
/// record of, and [`recovery_takes_no_formatting_flags`] refuses to let the
/// command line change what it found. So every member who recovers the same
/// epoch lands on the same password, whatever they type, which is the whole
/// point of a recovery that cannot be shared (a token at a past epoch is
/// classified stale and ignored, so the members' registries can only converge
/// if the command is deterministic from the archive alone). To change a
/// definition's shape, `rotate` it: that advances the epoch, so it is a new
/// secret and it *does* travel as a share token.
///
/// Asks before it writes: this is destructive, and it is the one place the
/// epoch-monotonicity rule bends.
fn recover_definition<T: wizard::Terminal>(
    term: &mut T,
    reg: &mut crate::registry::Registry,
    id: &str,
    user: &str,
    epoch: u64,
    m: &ArgMatches,
    rs: &RegScope,
) -> Result<crate::registry::Definition, String> {
    recovery_takes_no_formatting_flags(m)?;
    let params = reg
        .recipe_at(id, Some(user), epoch)
        .map_err(se)?
        .params
        .clone();

    let sel = if user.is_empty() {
        format!("'{id}'")
    } else {
        format!("'{id}' (user '{user}')")
    };
    let current = reg.entries.iter().find(|d| d.id == id && d.user == user);
    println!("Recovering {sel} to epoch {epoch}.");
    match current {
        Some(d) if d.tombstone => println!("    now:    removed, at epoch {}", d.epoch),
        Some(d) => println!("    now:    epoch {}  {}", d.epoch, d.params.describe()),
        None => println!("    now:    (no entry)"),
    }
    println!("    after:  epoch {epoch}  {}", params.describe());
    if rs.group_state.is_some() {
        println!();
        println!(
            "This rewrites the definition and cannot be shared: peers at a higher epoch\n\
             classify the change stale and ignore it silently. Coordinate out of band."
        );
    }
    println!();
    if !term
        .confirm(&format!("Overwrite {sel} at epoch {epoch}? [y/N] "))
        .map_err(se)?
    {
        return Err("not recovered".into());
    }
    Ok(reg.recover_at(id, user, epoch, params).map_err(se)?.clone())
}

/// Parse `--recover <EPOCH>`, the read-only past-epoch selector. `None` when the
/// flag is absent, which is the ordinary "use the current definition" path.
fn parse_recover(m: &ArgMatches) -> Result<Option<u64>, String> {
    match m.get_one::<String>("recover").map(String::as_str) {
        None => Ok(None),
        Some(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("--recover takes an epoch (a non-negative integer), got '{s}'")),
    }
}

/// Load the registry and resolve one stored definition (show/copy/reveal),
/// reporting whether it is the current definition or a superseded recipe.
///
/// With `--recover N` this resolves the recipe that was current at epoch `N`
/// (the live entry if it still sits there, else the archived one) and errors if
/// no recipe for `N` was ever recorded. Read-only either way: the registry is
/// loaded, never saved, so a recovery leaves the file byte-identical.
///
/// The `bool` is `true` when the resolved definition is **not** the current live
/// entry. `--recover` at the current epoch is therefore an ordinary read, and
/// says so.
///
/// `recover` is passed in rather than read from `m`, because `share` also calls
/// this and defines no `--recover`: clap debug-asserts on reading an arg a
/// subcommand never declared. That is the right shape anyway-- a share token for
/// an archived epoch would be `Stale` at every peer and silently ignored, so
/// `share` must only ever carry the current definition.
fn find_stored_def(
    ks: &Keystore,
    rs: &RegScope,
    seed: &[u8; SEED_BYTES],
    m: &ArgMatches,
    recover: Option<u64>,
) -> Result<(crate::registry::Definition, bool), String> {
    let reg = ks.load_registry(&rs.scope, seed).map_err(se)?;
    let id = m.get_one::<String>("id").map(String::as_str).unwrap();
    let user = m.get_one::<String>("user").map(String::as_str);
    let def = match recover {
        Some(epoch) => reg.recipe_at(id, user, epoch).map_err(se)?,
        None => reg.find_one(id, user).map_err(se)?,
    }
    .clone();
    let superseded = reg.get(&def.id, &def.user).map(|d| d.epoch) != Some(def.epoch);
    Ok((def, superseded))
}

fn cmd_hd_show(owner: &str, m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let (rs, seed) = unlock_owner(&ks, owner)?;
    let (def, superseded) = find_stored_def(&ks, &rs, &seed, m, parse_recover(m)?)?;
    let master = master_for(&ks, &rs, &seed)?;

    // Metadata + fingerprint only / the secret itself comes via `copy`/`reveal`
    print_def_summary(&master, &def, scope_group_name(&rs));
    // An archived recipe renders identically to a current one, so say which it
    // is. Silence here would let a superseded entry read as the live definition.
    if superseded {
        println!();
        println!(
            "This is an archived recipe, superseded after epoch {} - not the current definition.",
            def.epoch
        );
    }
    Ok(())
}

/// Enforce `--setup`'s mode gate, returning whether the flag was given.
///
/// The enrollment view (Base32 secret, otpauth URI, QR) exists only for an
/// otp-mode definition; anything else has no TOTP secret to enroll. The error
/// sends the user to a *separate* otp definition rather than to this one's
/// child: a TOTP seed and the password guarding the same account must not be
/// the same key material, or the second factor is computable from the first.
fn check_setup_mode(def: &crate::registry::Definition, setup: bool) -> Result<bool, String> {
    if !setup {
        return Ok(false);
    }
    if def.params.mode == "otp" {
        return Ok(true);
    }
    Err(format!(
        "--setup shows the otp enrollment view, which needs an otp definition \
         (this one's mode is '{}'). Create a separate `--mode otp` definition to \
         enroll TOTP.",
        def.params.mode
    ))
}

/// The refresh closure an otp `copy` hands to the clipboard countdown: the
/// fresh code exactly when the TOTP window has rolled since `start` (the
/// instant of the initial copy) or since the last refresh, `None` otherwise,
/// so the clipboard is rewritten once per rollover, not once per frame.
///
/// `now_fn` is injected (the countdown passes the wall clock) so the rollover
/// logic is unit-testable against a scripted clock. A `None` from `now_fn`
/// (unset system clock) skips the refresh rather than copying a wrong-window
/// code.
fn otp_refresher<'a>(
    key: &'a Zeroizing<[u8; format::SCALAR_BYTES]>,
    start: u64,
    mut now_fn: impl FnMut() -> Option<u64> + 'a,
) -> impl FnMut() -> Option<Zeroizing<String>> + 'a {
    let mut window = start / totp::PERIOD;
    move || {
        let now = now_fn()?;
        let w = now / totp::PERIOD;
        if w == window {
            return None;
        }
        window = w;
        Some(Zeroizing::new(totp::code(totp::key(key), now)))
    }
}

/// Whole seconds since the Unix epoch, the TOTP time base. A pre-1970 system
/// clock is an error, not a silent code-of-the-wrong-window: any TOTP code we
/// produced then would simply be rejected by the verifier.
fn unix_now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "system clock is set before the Unix epoch; TOTP needs a correct clock".into())
}

fn cmd_hd_copy(owner: &str, m: &ArgMatches) -> Result<(), String> {
    use crate::clipboard::Sink;

    let ks = keystore()?;
    let (rs, seed) = unlock_owner(&ks, owner)?;
    let (def, superseded) = find_stored_def(&ks, &rs, &seed, m, parse_recover(m)?)?;
    let master = master_for(&ks, &rs, &seed)?;
    let timeout = std::time::Duration::from_secs(parse_timeout(m)?);

    // The clipboard this copy writes through. With a Linux paste budget it also
    // releases the secret once it has been pasted that many times, which ends
    // the countdown early.
    let settings = config::settings()?;
    let mut clip = match clipboard::paste_budget(&settings) {
        Some(n) => clipboard::System::with_paste_budget(n),
        None => clipboard::System::new(),
    };

    // otp mode: the default egress is the live 6-digit code (what a login
    // prompt wants), never the underlying secret; the Base32 secret and URI
    // move only through the explicit --setup enrollment view.
    let setup = check_setup_mode(&def, m.get_flag("setup"))?;
    if setup {
        // One-time enrollment egress: the full otpauth URI (it carries the
        // secret, so it gets the same zeroized handling and countdown).
        let b32 = Zeroizing::new(registry_secret(&master, &def)?);
        let uri = format::otpauth_uri(&def.id, &def.user, &b32);
        clip.copy(&uri)?;
        if superseded {
            print_recovery_note(&def);
        }
        if clipboard::interactive() {
            clipboard::hold_then_clear(&mut clip, timeout)?;
        } else {
            println!(
                "Copied the otpauth enrollment URI for '{}' (epoch {}) to the clipboard.",
                def.id, def.epoch
            );
        }
        return Ok(());
    }
    if def.params.mode == "otp" {
        let key = Zeroizing::new(hd_child_of(&master, &def).to_bytes_le());
        let now = unix_now()?;
        let code = Zeroizing::new(totp::code(totp::key(&key), now));
        clip.copy(&code)?;
        if superseded {
            print_recovery_note(&def);
        }
        if clipboard::interactive() {
            // The countdown re-copies the fresh code whenever the 30s window
            // rolls over, so the clipboard never holds a dead code mid-window
            clipboard::hold_then_clear_refreshing(
                &mut clip,
                timeout,
                otp_refresher(&key, now, || unix_now().ok()),
            )?;
        } else {
            // A script owns clipboard hygiene here; tell it how long the code
            // it just took is even worth pasting.
            println!(
                "Copied HD secret '{}' (epoch {}) to the clipboard \
                 (current code, expires in {}s).",
                def.id,
                def.epoch,
                totp::secs_left_in_window(now)
            );
        }
        return Ok(());
    }

    // Hold the secret in a zeroizing buffer: it is scrubbed the moment it drops
    let secret = Zeroizing::new(registry_secret(&master, &def)?);
    clip.copy(secret.as_str())?;

    // Name the recipe a recovery used, before the countdown takes the screen.
    // The recipe is what a reader checks the recovered password against: the
    // fingerprint's recipe half commits to these params, but `copy` prints no
    // fingerprint, and a lone digest confirms nothing anyway.
    if superseded {
        print_recovery_note(&def);
    }

    if clipboard::interactive() {
        // Live countdown on stderr; the clipboard is zeroed on timeout or any key
        clipboard::hold_then_clear(&mut clip, timeout)?;
    } else {
        // No terminal to animate or read a keypress from so copy and report only. A
        // script owns clipboard hygiene here.
        println!(
            "Copied HD secret '{}' (epoch {}) to the clipboard.",
            def.id, def.epoch
        );
    }
    Ok(())
}

/// Say which archived recipe a `--recover` derivation used, and that nothing was
/// written. Printed by `copy` and `reveal` before they hand over the secret.
fn print_recovery_note(def: &crate::registry::Definition) {
    println!(
        "Recovered '{}' at epoch {} from the archived recipe:",
        def.id, def.epoch
    );
    println!("    {}", def.params.describe());
    println!("The registry is unchanged; the other members need do nothing.");
    println!();
}

/// Parse `--timeout` seconds for `copy` (must be ≥ 1)
fn parse_timeout(m: &ArgMatches) -> Result<u64, String> {
    let secs: u64 = m
        .get_one::<String>("timeout")
        .map(String::as_str)
        .unwrap_or("30")
        .parse()
        .map_err(|_| "timeout must be a non-negative integer (seconds)".to_string())?;
    if secs == 0 {
        return Err("timeout must be at least 1 second".into());
    }
    Ok(secs)
}

fn cmd_hd_rotate(owner: &str, m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let id = m.get_one::<String>("id").map(String::as_str).unwrap();
    let user = m
        .get_one::<String>("user")
        .map(String::as_str)
        .unwrap_or("");
    let epoch_override: Option<u64> = match m.get_one::<String>("epoch").map(String::as_str) {
        None => None,
        Some(s) => Some(
            s.parse()
                .map_err(|_| "epoch must be a non-negative integer".to_string())?,
        ),
    };

    let (rs, seed) = unlock_owner(&ks, owner)?;
    let mut reg = ks.load_registry(&rs.scope, &seed).map_err(se)?;

    // Merge any provided formatting flags over the existing params
    let existing = reg
        .get(id, user)
        // Name the sub-account too: `rotate foo bar` selects (foo, bar), and an
        // error that mentions only `foo` sends the reader looking in the wrong place.
        .ok_or_else(|| {
            if user.is_empty() {
                format!("no stored definition for '{id}'")
            } else {
                format!("no stored definition for '{id}' (user '{user}')")
            }
        })?
        .params
        .clone();
    let (merged, notes) = merge_params(m, existing)?;
    // Announce anything the new mode forced us to drop, before the summary that
    // reflects it. A dropped param is never silent.
    for note in &notes {
        eprintln!("{note}");
    }

    // `reg.rotate` only mutates the in-memory registry; skipping the save is
    // all a dry run needs.
    let dry_run = m.get_flag("dry-run");
    let def = reg
        .rotate(id, user, Some(merged), epoch_override)
        .map_err(se)?
        .clone();
    if !dry_run {
        ks.save_registry(&rs.scope, &seed, &reg).map_err(se)?;
    }

    let master = master_for(&ks, &rs, &seed)?;
    print_def_summary(&master, &def, scope_group_name(&rs));
    println!();
    if dry_run {
        println!(
            "Would rotate to epoch {} (dry run, keystore unchanged).",
            def.epoch
        );
    } else {
        println!("Rotated to epoch {}.", def.epoch);
    }
    if let Some(state) = &rs.group_state {
        println!();
        println!(
            "Share token: {}",
            group_share_token(&ks, state, &seed, ShareAction::Update, &def)?
        );
    }
    Ok(())
}

fn cmd_hd_remove(owner: &str, m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let id = m.get_one::<String>("id").map(String::as_str).unwrap();
    let user = m
        .get_one::<String>("user")
        .map(String::as_str)
        .unwrap_or("");

    let (rs, seed) = unlock_owner(&ks, owner)?;
    let mut reg = ks.load_registry(&rs.scope, &seed).map_err(se)?;
    let def = reg.remove(id, user).map_err(se)?.clone();
    ks.save_registry(&rs.scope, &seed, &reg).map_err(se)?;
    println!("Removed definition '{id}'.");
    if let Some(state) = &rs.group_state {
        print_share_token(&ks, state, &seed, ShareAction::Remove, &def)?;
    }
    Ok(())
}

/// `reveal`: show a stored secret on screen in a supervised, timed window.
///
/// Unlike `export` (which it replaces), this never writes the secret to stdout.
/// It refuses outright unless **both** stdin and stdout are terminals-- piping
/// would bypass the countdown/wipe and silently recreate `export`, so the guard
/// is structural, not a warning. The secret is rendered on the alternate screen
/// buffer (no scrollback, vanishes on exit) with a countdown below it; the
/// window closes when `--timeout` seconds elapse or the user presses **any key**
/// (including `Ctrl-C` and `Ctrl-Z`, which cannot kill or suspend it mid-secret),
/// and the region is wiped before the main screen returns.
fn cmd_hd_reveal(owner: &str, m: &ArgMatches) -> Result<(), String> {
    // Structural TTY guard, enforced before any keystore work or password
    // prompt: the countdown reads keys from raw-mode stdin, and the alt-screen
    // display needs a real stdout. No TTY -> no reveal.
    if !(terminal::stdin_is_tty() && terminal::stdout_is_tty()) {
        return Err(
            "reveal needs an interactive terminal - both stdin and stdout must be a TTY. \
             For scripted or piped use, `copy` puts the secret on the clipboard instead."
                .into(),
        );
    }

    let ks = keystore()?;
    let (rs, seed) = unlock_owner(&ks, owner)?;
    let (def, superseded) = find_stored_def(&ks, &rs, &seed, m, parse_recover(m)?)?;
    let master = master_for(&ks, &rs, &seed)?;
    // The --setup mode gate fires before any rendering (the flag means the
    // otp enrollment view; the view itself is assembled below).
    let setup = check_setup_mode(&def, m.get_flag("setup"))?;
    let timeout = std::time::Duration::from_secs(parse_timeout(m)?);
    let group = scope_group_name(&rs);

    // On the main screen, before the alt screen takes over: the note carries no
    // secret, and the main screen (and this note with it) returns on exit.
    if superseded {
        print_recovery_note(&def);
    }

    // The no-echo unlock prompt can leave the terminal without cooked input;
    // re-assert it before switching to the alt screen so a clean state returns.
    terminal::ensure_line_input();

    // --setup: the one-time enrollment view (gate above guarantees otp mode).
    // The QR is rendered in both polarities up front; the frame closure picks
    // by its color flag, so the wipe sizing (which passes color = false) sizes
    // itself over the escape-free rendering.
    if setup {
        let b32 = Zeroizing::new(registry_secret(&master, &def)?);
        let uri = format::otpauth_uri(&def.id, &def.user, &b32);
        // The QR is a visual encoding of the URI (which carries the secret),
        // so its buffers get the same scrub-on-drop treatment.
        //
        // A URI too long to encode is not a reason to fail the whole view: the
        // paste and manual-entry paths still work, and `setup_lines` prints a
        // note in place of the block. `MAX_HD_STRING_LEN` bounds id/user well
        // inside a QR's capacity, so this is only reachable for a definition
        // stored before that bound existed.
        let qr_color = Zeroizing::new(crate::qr::rows(&uri, true).unwrap_or_default());
        let qr_plain = Zeroizing::new(crate::qr::rows(&uri, false).unwrap_or_default());
        // No measurable height (no stty): assume the classic 24-row terminal
        // rather than blindly overflow the alt screen
        let max_rows = terminal::rows().unwrap_or(24);
        return reveal_window(timeout, |secs, t, waterline, color| {
            let qr = if color { &qr_color } else { &qr_plain };
            setup_lines(
                &def, group, &b32, &uri, qr, max_rows, secs, t, waterline, color,
            )
        })
        .map_err(|e| format!("Reveal failed: {e}"));
    }

    // otp mode without --setup (which returned above): the live view. The code
    // is recomputed from the wall clock inside the frame closure, so a 30s
    // rollover shows the fresh code on the very next frame instead of a stale
    // print-and-exit snapshot.
    if def.params.mode == "otp" {
        let key = Zeroizing::new(hd_child_of(&master, &def).to_bytes_le());
        // Surface a broken clock as a clean error before the alt screen is up
        unix_now()?;
        return reveal_window(timeout, |secs, t, waterline, color| {
            otp_frame(
                &def,
                group,
                totp::key(&key),
                unix_now().unwrap_or(0),
                secs,
                t,
                waterline,
                color,
            )
        })
        .map_err(|e| format!("Reveal failed: {e}"));
    }

    // Hold the secret in a zeroizing buffer: scrubbed the moment it drops
    let secret = Zeroizing::new(registry_secret(&master, &def)?);
    reveal_window(timeout, |secs, t, waterline, color| {
        reveal_lines(&def, group, &secret, secs, t, waterline, color)
    })
    .map_err(|e| format!("Reveal failed: {e}"))
}

/// The lines shown in a `reveal` window: a dim header describing the entry, the
/// secret on its own line, and a countdown footer led by the same undulating
/// waterline wave the `copy` countdown uses. `secs` is the whole seconds
/// remaining; `t` is elapsed seconds and `waterline ∈ [0,1]` the fraction of the
/// window still left (drive the wave). Pure so it can be unit-tested; the caller
/// adds cursor control.
fn reveal_lines(
    def: &crate::registry::Definition,
    group: Option<&str>,
    secret: &str,
    secs: u64,
    t: f64,
    waterline: f64,
    color: bool,
) -> Vec<String> {
    let (bright, reset) = if color {
        ("\x1b[97m", "\x1b[0m")
    } else {
        ("", "")
    };
    reveal_frame(
        def,
        group,
        format!("{bright}{secret}{reset}"),
        secs,
        t,
        waterline,
        color,
    )
}

/// The reveal-window skeleton shared by every view: dim header, the given
/// (pre-styled) `body` line, and the wave/countdown footer. The body is the
/// only part that differs between a static secret and a live code.
fn reveal_frame(
    def: &crate::registry::Definition,
    group: Option<&str>,
    body: String,
    secs: u64,
    t: f64,
    waterline: f64,
    color: bool,
) -> Vec<String> {
    let (dim, reset) = if color { ("\x1b[90m", "\x1b[0m") } else { ("", "") };
    let head = reveal_headline(def, group);
    let wave = clipboard::render_wave(t, waterline, color);
    vec![
        format!("{dim}Revealing {head}{reset}"),
        String::new(),
        body,
        String::new(),
        format!("{wave}{reset}  {dim}Clearing in {secs}s  (press any key to clear now){reset}"),
    ]
}

/// `{group} · {id} · {user} (epoch N)`, the entry description every reveal
/// view leads with (group/user omitted when absent)
fn reveal_headline(def: &crate::registry::Definition, group: Option<&str>) -> String {
    let mut head = String::new();
    if let Some(g) = group {
        head.push_str(&format!("{g} · "));
    }
    head.push_str(&def.id);
    if !def.user.is_empty() {
        head.push_str(&format!(" · {}", def.user));
    }
    head.push_str(&format!(" (epoch {})", def.epoch));
    head
}

/// The `reveal --setup` frame: the one-time TOTP enrollment view, rendering
/// everything an importer can take - the Base32 secret (manual entry), the
/// otpauth URI (paste), and the QR block (phone scan) - over the shared
/// countdown footer.
///
/// The QR is included only when the whole layout fits `max_rows`: a 37-module
/// code plus header and footer runs ~30 rows, taller than a classic 24-row
/// terminal, and a per-frame `ESC[H` redraw that overflows the screen would
/// scroll-garbage the alt buffer. When it does not fit, one hint line stands
/// in and the URI/Base32 remain (every enrollment stays possible, just not by
/// scan). Pure, so the layout and the fallback are unit-testable.
#[allow(clippy::too_many_arguments)]
fn setup_lines(
    def: &crate::registry::Definition,
    group: Option<&str>,
    b32: &str,
    uri: &str,
    qr_rows: &[String],
    max_rows: usize,
    secs: u64,
    t: f64,
    waterline: f64,
    color: bool,
) -> Vec<String> {
    let (dim, bright, reset) = if color {
        ("\x1b[90m", "\x1b[97m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    let head = reveal_headline(def, group);
    let mut lines = vec![
        format!("{dim}Enrolling {head} - scan, or paste the URI or Base32 secret{reset}"),
        String::new(),
        format!("{dim}Secret (Base32):{reset}  {bright}{b32}{reset}"),
        format!("{dim}URI:{reset}  {bright}{uri}{reset}"),
        String::new(),
    ];
    // Rows the full layout needs: what we have, the QR, a blank, the footer
    let need = lines.len() + qr_rows.len() + 2;
    if qr_rows.is_empty() {
        // The URI would not encode (see the caller): the other two enrollment
        // paths, paste and manual entry, are unaffected, so say so and go on.
        lines.push(format!(
            "{dim}(the URI is too long to encode as a QR - paste it instead){reset}"
        ));
    } else if need <= max_rows {
        lines.extend(qr_rows.iter().cloned());
    } else {
        lines.push(format!(
            "{dim}(terminal too short for the QR: {need} rows needed - showing the URI only){reset}"
        ));
    }
    lines.push(String::new());
    let wave = clipboard::render_wave(t, waterline, color);
    lines.push(format!(
        "{wave}{reset}  {dim}Clearing in {secs}s  (press any key to clear now){reset}"
    ));
    lines
}

/// One frame of the **live otp view**: the code for `now`, with its own
/// rolls-in countdown beside it. The code carries no digit grouping (what you
/// read must equal what you type) and the seconds are padded to a fixed two
/// columns, so every frame of the body line has the same width - which is what
/// lets the wipe-sizing call cover it for any timestamp.
#[allow(clippy::too_many_arguments)]
fn otp_frame(
    def: &crate::registry::Definition,
    group: Option<&str>,
    key: &[u8],
    now: u64,
    secs: u64,
    t: f64,
    waterline: f64,
    color: bool,
) -> Vec<String> {
    let (dim, bright, reset) = if color {
        ("\x1b[90m", "\x1b[97m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    let code = Zeroizing::new(totp::code(key, now));
    let left = totp::secs_left_in_window(now);
    let body = format!("{bright}{}{reset}  {dim}·  rolls in {left:>2}s{reset}", &*code);
    reveal_frame(def, group, body, secs, t, waterline, color)
}

/// Drive a `reveal` alt-screen window to completion (timeout or keypress),
/// wiping the rendered region before restoring the main screen.
///
/// `frame_lines(secs, t, waterline, color)` renders one frame: `secs` is the
/// whole seconds left in the window, `t` the elapsed seconds, `waterline` the
/// fraction of the window remaining. The static-secret view closes over a
/// fixed rendering; the otp view recomputes the live code inside the closure,
/// so a window rollover shows up on the very next frame.
fn reveal_window(
    timeout: std::time::Duration,
    frame_lines: impl Fn(u64, f64, f64, bool) -> Vec<String>,
) -> std::io::Result<()> {
    use std::io::Write;
    let color = std::env::var_os("NO_COLOR").is_none();
    let mut out = std::io::stdout();

    let total = timeout.as_secs_f64();
    terminal::enter_alt_screen(&mut out)?;
    terminal::run_countdown(timeout, |elapsed, secs| {
        // Redraw from home each frame so the secret sits stably (no reflow);
        // only the countdown number and the footer wave change.
        let waterline = if total > 0.0 {
            (1.0 - elapsed.as_secs_f64() / total).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let mut buf = String::from("\x1b[H");
        for line in frame_lines(secs, elapsed.as_secs_f64(), waterline, color) {
            buf.push_str(&line);
            buf.push_str("\x1b[K\n");
        }
        let _ = write!(out, "{buf}");
        let _ = out.flush();
    });

    // Wipe the rendered region with a fixed-width block, clear the whole
    // screen, then leave the alt buffer, three layers so no secret byte
    // survives on any terminal.
    //
    // Every layer runs, unconditionally. An early `?` here would be the worst
    // possible failure mode: it would abandon the user on the alt screen, with
    // the secret still displayed and the cursor still hidden. Errors are
    // collected and reported only once the terminal is back.
    let plain = frame_lines(0, 0.0, 0.0, false);
    let width = plain.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let wiped = terminal::wipe_region(&mut out, plain.len(), width);
    let cleared = terminal::clear_screen(&mut out);
    let left = terminal::leave_alt_screen(&mut out);
    // The countdown's `RawMode` guard already restored the saved settings; this
    // repairs the terminal even on the path where it could not be created.
    terminal::ensure_line_input();
    wiped.and(cleared).and(left)
}

fn cmd_hd_share(owner: &str, m: &ArgMatches) -> Result<(), String> {
    let ks = keystore()?;
    let (rs, seed) = unlock_owner(&ks, owner)?;
    let state = rs.group_state.as_ref().ok_or_else(|| {
        "personal (keypair-owned) definitions are local-only, share tokens exist only \
         for shared-secret groups"
            .to_string()
    })?;
    // `None`: a share token always carries the current definition (see above)
    let (def, _) = find_stored_def(&ks, &rs, &seed, m, None)?;
    let master = master_for(&ks, &rs, &seed)?;

    // Fingerprint + share token only-- no secret (the token carries just the
    // recipe; the fingerprint lets the recipient confirm agreement, params and
    // all, since the recipe half covers the formatting the token ships).
    print!(
        "{}",
        render_kv(&[
            ("Fingerprint", hd_fingerprint_of(&master, &def)),
            (
                "Share token",
                group_share_token(&ks, state, &seed, ShareAction::New, &def)?,
            ),
        ])
    );
    Ok(())
}

fn cmd_hd_apply(m: &ArgMatches) -> Result<(), String> {
    let token = match m.get_one::<String>("token") {
        Some(t) => t.clone(),
        None => prompt_token("Share token: ")?,
    };
    hd_apply(&mut StdioTerminal::new(), &token)
}

/// Apply one incoming share token: identify its group by recomputing every
/// local group's context, authenticate the editor against the pinned members,
/// classify the change against the local registry, and (behind the [`Terminal`]
/// trait) show a diff and prompt before adopting. Same-epoch conflicts show
/// both versions (the params *and* derived secrets) and the user picks.
fn hd_apply<T: wizard::Terminal>(term: &mut T, token_str: &str) -> Result<(), String> {
    use crate::registry::ApplyOutcome;

    let ks = keystore()?;

    // Route by the CLEAR group_ctx: no key needed to learn which group a token
    // targets. A token matching no local group's context is rejected.
    let wanted_ctx = ShareToken::peek_group_ctx(token_str).map_err(se)?;
    let mut found: Option<(SharedSecretState, Vec<PublicIdentity>, [u8; 32])> = None;
    for gname in ks.list_shared_secrets().map_err(se)? {
        let state = ks.load_shared_secret(&gname).map_err(se)?;
        let members = group_member_identities(&ks, &state)?;
        let ctx = group_ctx(Purpose::Master, &state.group_name, &members).map_err(se)?;
        if ctx == wanted_ctx {
            found = Some((state, members, ctx));
            break;
        }
    }
    let (state, members, ctx) = found.ok_or_else(|| {
        "share token does not match any local group (wrong group, or its members \
         are not pinned here)"
            .to_string()
    })?;
    let group_name = state.group_name.clone();

    let rs = RegScope {
        scope: crate::keystore::RegistryScope::Group(group_name.clone()),
        owner_keypair: state.keypair.clone(),
        group_state: Some(state),
    };
    let password = unlock_password(&rs.owner_keypair)?;
    let seed = ks.load_seed(&rs.owner_keypair, &password).map_err(se)?;

    // Decrypt under this group's K, then authenticate the editor's signature
    // and re-gate the (member-signed but not member-trusted) params.
    let group_state = rs.group_state.as_ref().expect("group scope");
    let k = ks
        .reconstruct_shared_secret(group_state, &seed)
        .map_err(se)?;
    let token = ShareToken::open(token_str, &crypto::share_wrap_key(&k)).map_err(se)?;
    // Member-signed is not member-trusted: gate the strings the prompt and diff
    // below will print, before anything is displayed.
    validate_hd_strings(&token.id, &token.user)
        .map_err(|e| format!("share token rejected: {e}"))?;
    validate_params(&token.params)
        .map_err(|e| format!("share token carries invalid params: {e}"))?;
    let editor_idx = token.verify(&ctx, &members).map_err(se)?;
    let editor = if editor_idx == 0 {
        format!("{} (you)", rs.owner_keypair)
    } else {
        group_state.members[editor_idx - 1].clone()
    };

    let mut reg = ks.load_registry(&rs.scope, &seed).map_err(se)?;

    let incoming_tombstone = token.action == ShareAction::Remove;
    let sel = if token.user.is_empty() {
        format!("'{}'", token.id)
    } else {
        format!("'{}' (user '{}')", token.id, token.user)
    };
    // A tombstone has no params to describe. The entry is gone either way. Live
    // definitions go through `def_details`, which annotates their params.
    let describe_tombstone = |epoch: u64| format!("(removed, epoch {epoch})");

    match reg.classify(
        &token.id,
        &token.user,
        token.epoch,
        &token.params,
        incoming_tombstone,
    ) {
        ApplyOutcome::AlreadyApplied => {
            println!("Already up to date: {sel} is at epoch {}.", token.epoch);
            Ok(())
        }
        ApplyOutcome::Stale { local_epoch } => {
            println!(
                "Ignored stale change: {sel} is locally at epoch {local_epoch}, \
                 incoming is epoch {}.",
                token.epoch
            );
            Ok(())
        }
        ApplyOutcome::Adopt => {
            // Summary of the incoming definition, then a change block naming
            // only the fields that differ from the local entry (if any).
            let incoming = crate::registry::Definition {
                id: token.id.clone(),
                user: token.user.clone(),
                epoch: token.epoch,
                params: token.params.clone(),
                tombstone: incoming_tombstone,
            };
            // A tombstone derives nothing and formats nothing: the `params` it
            // carries are the ones that were live at `epoch - 1` (see
            // `recipe_of`), so summarizing it as a definition would advertise a
            // recipe, a fingerprint and a "derived on demand" secret for an
            // entry being deleted. Name it for what it is, as the conflict
            // branch below does and derive no master to do it.
            if incoming_tombstone {
                let mut kv: Vec<(&'static str, String)> =
                    vec![("Group", group_name.clone()), ("Id", token.id.clone())];
                if !token.user.is_empty() {
                    kv.push(("User", token.user.clone()));
                }
                kv.push(("Entry", describe_tombstone(token.epoch)));
                print!("{}", render_kv(&kv));
            } else {
                let master = master_for(&ks, &rs, &seed)?;
                print_def_summary(&master, &incoming, Some(&group_name));
            }

            let local = reg
                .entries
                .iter()
                .find(|d| d.id == token.id && d.user == token.user)
                .cloned();
            if let Some(before) = &local {
                let label = match token.action {
                    ShareAction::New => "Created",
                    ShareAction::Update => "Rotated",
                    ShareAction::Remove => "Removed",
                };
                println!();
                println!("{label}:");
                for (key, old, new) in def_changes(before, &incoming) {
                    println!("    {:<7} {old} → {new}", format!("{key}:"));
                }
            }
            println!();

            if !term
                .confirm(&format!("Apply this change from '{editor}'? [y/N] "))
                .map_err(se)?
            {
                return Err("not applied".into());
            }
            reg.adopt(
                &token.id,
                &token.user,
                token.epoch,
                token.params.clone(),
                incoming_tombstone,
            );
            ks.save_registry(&rs.scope, &seed, &reg).map_err(se)?;
            println!(
                "Applied {} for {sel} (now at epoch {}).",
                token.action.describe(),
                token.epoch
            );
            Ok(())
        }
        ApplyOutcome::Conflict => {
            // Same epoch, different content. Show each side exactly as `show`
            // does, the params and fingerprint, and never the rendered secret.
            // `apply` has none of `reveal`'s guards (TTY check, alt screen,
            // countdown, wipe), so printing a secret here would silently
            // recreate the `export` command `reveal` replaced. Nothing is lost:
            // the child scalar depends only on (id, user, epoch), which both
            // sides share by definition of a same-epoch conflict, so the two
            // fingerprints agree in their secret half and differ in their recipe
            // half: the block below *shows* that the sides differ in formatting
            // alone, rather than asking the reader to take it on faith.
            let master = master_for(&ks, &rs, &seed)?;
            let local = reg
                .entries
                .iter()
                .find(|d| d.id == token.id && d.user == token.user)
                .expect("conflict implies a local entry")
                .clone();
            let incoming = crate::registry::Definition {
                id: token.id.clone(),
                user: token.user.clone(),
                epoch: token.epoch,
                params: token.params.clone(),
                tombstone: incoming_tombstone,
            };
            let group = scope_group_name(&rs);
            // One side's indented `show` block. A tombstone has nothing to
            // describe; params that no longer validate (a legacy entry) are
            // annotated rather than allowed to block the comparison.
            let block = |def: &crate::registry::Definition| -> Vec<String> {
                if def.tombstone {
                    return vec![format!("  {}", describe_tombstone(def.epoch))];
                }
                let mut lines: Vec<String> = render_kv(&def_details(&master, def, group))
                    .lines()
                    .map(|l| format!("  {l}"))
                    .collect();
                if let Err(e) = validate_params(&def.params) {
                    lines.push(format!("  (invalid params: {e})"));
                }
                lines
            };
            term.write_line(&format!(
                "Conflict: {sel} has concurrent edits at epoch {} (incoming signed by '{editor}').",
                token.epoch
            ));
            term.write_line("yours:");
            for line in block(&local) {
                term.write_line(&line);
            }
            term.write_line("incoming:");
            for line in block(&incoming) {
                term.write_line(&line);
            }
            if !local.tombstone && !incoming_tombstone {
                term.write_line(
                    "Both sides share one child secret (the fingerprints agree after the dash) \
                     and differ only in how it is formatted; the secret is never printed here \
                     - use `copy` to test a candidate.",
                );
            }
            term.write_line(
                "Pick the one that works (test it, or check with the group); whoever \
                 holds the winner should then `rotate` it to lock it in for everyone.",
            );
            loop {
                let ans = term
                    .prompt_line("[k] keep mine · [u] use incoming · [a] abort: ")
                    .map_err(se)?;
                match ans.trim().to_ascii_lowercase().as_str() {
                    "k" => {
                        println!("Kept your version of {sel} (epoch {}).", token.epoch);
                        return Ok(());
                    }
                    "u" => {
                        reg.adopt(
                            &token.id,
                            &token.user,
                            token.epoch,
                            token.params.clone(),
                            incoming_tombstone,
                        );
                        ks.save_registry(&rs.scope, &seed, &reg).map_err(se)?;
                        println!(
                            "Adopted the incoming version of {sel} (epoch {}).",
                            token.epoch
                        );
                        return Ok(());
                    }
                    "a" => return Err("Aborted, registry unchanged".into()),
                    _ => term.write_line("Please answer k, u, or a."),
                }
            }
        }
    }
}

/// Validate a full set of formatting params. One gate for **every** source
/// with local flags (create/rotate) and incoming share tokens (`apply`), so
/// a definition that reaches the registry is always renderable:
/// known mode; bip39 excludes length/suffix; suffix within [`MAX_SUFFIX_LEN`];
/// length within the mode's maximum and strictly longer than the suffix.
/// Reject control characters in a definition's `id`/`user`.
///
/// These strings end up in prompts, diffs and listings, including the very
/// confirmation prompt `apply` and `import` gate a change on, and a share
/// token or export is member-signed, not member-*trusted*: an embedded escape
/// sequence could redraw the prompt the user is deciding on. Enforced at local
/// creation and re-gated on every ingress, exactly like [`validate_params`].
/// The `{:?}` in the message escapes what it names, so the error cannot itself
/// deliver the payload.
///
/// Both strings are also length-bounded by [`MAX_HD_STRING_LEN`]. They are
/// display strings (a table cell, a prompt) and, under `--mode otp`, the label
/// and issuer of the `otpauth://` URI the QR encodes. A QR tops out near 2,950
/// bytes; the worst URI this bound admits (every byte of both strings
/// percent-encoded to three, and the issuer appearing twice) is about 2,370, so
/// an id that renders is an id that scans. The error reports the length, never
/// the string.
fn validate_hd_strings(id: &str, user: &str) -> Result<(), String> {
    for (what, s) in [("id", id), ("user", user)] {
        if s.chars().any(char::is_control) {
            return Err(format!(
                "Definition {what} {s:?} contains control characters"
            ));
        }
        if s.len() > MAX_HD_STRING_LEN {
            return Err(format!(
                "Definition {what} is {} bytes; the maximum is {MAX_HD_STRING_LEN}",
                s.len()
            ));
        }
    }
    Ok(())
}

fn validate_params(p: &crate::registry::Params) -> Result<(), String> {
    let max = format::max_len(&p.mode).ok_or_else(|| format!("unknown mode '{}'", p.mode))?;
    if format::fixed_rendering(&p.mode) && (p.length.is_some() || p.suffix.is_some()) {
        return Err(format!(
            "--length and --suffix are not compatible with {} output",
            p.mode
        ));
    }
    if let Some(set) = &p.symbols {
        // The `supports_symbols` check fires first so the message names the
        // flag; `validate_symbol_set` would otherwise reject the same case in
        // less pointed terms.
        if !format::supports_symbols(&p.mode) {
            return Err(format!(
                "--symbols works only with modes hex, b10, b58 (not '{}')",
                p.mode
            ));
        }
        format::validate_symbol_set(&p.mode, set)?;
    }
    let suffix_len = p.suffix.as_deref().map_or(0, str::len);
    if suffix_len > MAX_SUFFIX_LEN {
        return Err(format!("suffix can be at most {MAX_SUFFIX_LEN} bytes"));
    }
    // A suffix is pasted into passwords and printed in `describe()` output: a
    // control character is hostile or a mistake in either role. The symbol set
    // already gets this from `validate_symbol_set`'s printable-ASCII rule.
    if p.suffix
        .as_deref()
        .is_some_and(|s| s.chars().any(char::is_control))
    {
        return Err("suffix must not contain control characters".into());
    }
    if let Some(l) = p.length {
        if l > max as u64 {
            return Err(format!("length can be at most {max} for mode '{}'", p.mode));
        }
        if l <= suffix_len as u64 {
            return Err("length must exceed the suffix length".into());
        }
    }
    Ok(())
}

/// Build `Params` from `create` flags, filling in the defaults.
///
/// The defaults are **resolved here and stored**, never re-derived at render
/// time: `describe()` prints them back, so the recipe always names the exact
/// mode, length and alphabet it used. A later change to `DEFAULT_LENGTH` or
/// `SYMBOLS` therefore cannot alter an existing password.
fn parse_params(m: &ArgMatches) -> Result<crate::registry::Params, String> {
    let mode = m
        .get_one::<String>("mode")
        .map(String::as_str)
        .unwrap_or(DEFAULT_MODE)
        .to_string();
    let (default_length, default_symbols) = mode_defaults(&mode);

    let symbols = if m.get_flag("no-symbols") {
        None
    } else if m.contains_id("symbols") {
        m.get_one::<String>("symbols")
            .map(String::as_str)
            .map(str::to_string)
    } else {
        // `alpha`/`bip39` take no symbol set (a bare `--mode alpha` must not
        // become an error about a flag the user never typed), and a bare
        // `b10` is a digits-only code. For all three the default is not set.
        default_symbols.map(str::to_string)
    };

    let length = match parse_length(m)? {
        Some(l) => Some(l),
        None => default_length,
    };

    let params = crate::registry::Params {
        mode,
        length,
        symbols,
        suffix: m
            .get_one::<String>("suffix")
            .map(String::as_str)
            .map(|s| s.to_string()),
    };
    validate_params(&params)?;
    Ok(params)
}

/// The `--mode` the user actually typed, as opposed to the one clap filled in.
///
/// `rotate`'s `--mode` has no default, so `value_of` alone would do; `create`'s
/// defaults to [`DEFAULT_MODE`], and there `get_one` is always `Some`. A merge
/// driven by `get_one` would therefore silently rewrite an inherited mode to
/// `b58` on every `create --recover`. `value_source` distinguishes a value
/// supplied on the command line from a filled-in default.
fn explicit_mode(m: &ArgMatches) -> Option<&str> {
    matches!(
        m.value_source("mode"),
        Some(clap::parser::ValueSource::CommandLine)
    )
    .then(|| m.get_one::<String>("mode").map(String::as_str))
    .flatten()
}

/// Merge provided formatting flags over `base` (for `rotate` and
/// `create --recover`), returning the merged params and any notes about params
/// the new mode forced us to drop.
///
/// **A param the new mode cannot express is dropped, not refused**, provided
/// the user did not ask for it on this same command line. `rotate x --mode alpha`
/// says "render this as alpha" and means it; a stored symbol set has no
/// positional alphabet to extend there, so it goes, and the note says so.
/// Requiring the user to restate the obvious as `--no-symbols` would be the tool
/// arguing with an unambiguous instruction.
///
/// Asking for both at once is a different thing (`--mode alpha --symbols` is a
/// contradiction, not an instruction) and stays an error.
///
/// Every drop is announced. The epoch is advancing regardless, so the password
/// changes either way; what must never happen is a *silent* change to the stored
/// recipe.
fn merge_params(
    m: &ArgMatches,
    base: crate::registry::Params,
) -> Result<(crate::registry::Params, Vec<String>), String> {
    let mode = explicit_mode(m).map(|s| s.to_string()).unwrap_or(base.mode);
    let mut notes: Vec<String> = Vec::new();

    // --symbols[=set] / --no-symbols switch it on/off (they conflict, so at most
    // one is present); absent both, the base set carries over.
    let symbols_asked_for = m.contains_id("symbols");
    let mut symbols = if m.get_flag("no-symbols") {
        None
    } else if symbols_asked_for {
        m.get_one::<String>("symbols")
            .map(String::as_str)
            .map(str::to_string)
    } else {
        base.symbols
    };
    if symbols.is_some() && !format::supports_symbols(&mode) {
        if symbols_asked_for {
            return Err(format!(
                "--symbols works only with modes hex, b10, b58 (not '{mode}')"
            ));
        }
        notes.push(format!(
            "Dropped --symbols: mode '{mode}' has no positional alphabet to extend."
        ));
        symbols = None;
    }

    let length_asked_for = m.get_one::<String>("length").map(String::as_str).is_some();
    let mut length = if length_asked_for {
        parse_length(m)?
    } else {
        base.length
    };
    let suffix_asked_for = m.get_one::<String>("suffix").map(String::as_str).is_some();
    let mut suffix = if suffix_asked_for {
        m.get_one::<String>("suffix")
            .map(String::as_str)
            .map(|s| s.to_string())
    } else {
        base.suffix
    };
    // bip39 (a 24-word mnemonic) and otp (a 32-character TOTP secret) are
    // fixed-shape renderings: they can carry neither a trim nor a suffix
    if format::fixed_rendering(&mode) {
        if length.is_some() {
            if length_asked_for {
                return Err(format!(
                    "--length and --suffix are not compatible with {mode} output"
                ));
            }
            notes.push(format!(
                "Dropped --length: {mode} output is a fixed shape that cannot be trimmed."
            ));
            length = None;
        }
        if suffix.is_some() {
            if suffix_asked_for {
                return Err(format!(
                    "--length and --suffix are not compatible with {mode} output"
                ));
            }
            notes.push(format!(
                "Dropped --suffix: {mode} output is a fixed shape that cannot carry one."
            ));
            suffix = None;
        }
    }

    let merged = crate::registry::Params {
        mode,
        length,
        symbols,
        suffix,
    };
    validate_params(&merged)?;
    Ok((merged, notes))
}

/// Parse `--length` as a number; the mode-aware bounds live in [`validate_params`].
fn parse_length(m: &ArgMatches) -> Result<Option<u64>, String> {
    match m.get_one::<String>("length").map(String::as_str) {
        None => Ok(None),
        Some(s) => Ok(Some(
            s.parse()
                .map_err(|_| "length must be a number".to_string())?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Definition, Params};

    fn def(id: &str, user: &str, epoch: u64) -> Definition {
        Definition {
            id: id.to_string(),
            user: user.to_string(),
            epoch,
            params: Params {
                mode: "b58".into(),
                length: None,
                symbols: None,
                suffix: None,
            },
            tombstone: false,
        }
    }

    // Parse an `hd-secret <sub> <owner> x` line, returning the subcommand's matches
    fn sub_matches(sub: &str, extra: &[&str]) -> Result<ArgMatches, clap::Error> {
        let mut argv = vec!["sesh", "hd-secret", sub, "me", "x"];
        argv.extend_from_slice(extra);
        let m = build_cli().try_get_matches_from(argv)?;
        let (_, hd) = m.subcommand().expect("hd-secret");
        let (_, sm) = hd.subcommand().expect("subcommand");
        Ok(sm.clone())
    }

    // An `hd-secret create <owner>` line. `--mode` carries a `default_value`
    // here and **not** on `rotate` which is exactly why `rotate` cannot
    // re-apply `create`'s defaults over a stored recipe.
    fn create_matches(extra: &[&str]) -> Result<ArgMatches, clap::Error> {
        sub_matches("create", extra)
    }

    // An `hd-secret rotate <owner>` line.
    fn rotate_matches(extra: &[&str]) -> Result<ArgMatches, clap::Error> {
        sub_matches("rotate", extra)
    }

    // A bare `create` gets a memorable, sensible recipe and **stores** it, so
    // the params `list`/`show` print back name the exact alphabet and length used.
    #[test]
    fn create_defaults_to_b58_length_14_with_the_default_symbol_set() {
        let p = parse_params(&create_matches(&[]).unwrap()).unwrap();
        assert_eq!(p.mode, "b58");
        assert_eq!(p.length, Some(14));
        assert_eq!(p.symbols.as_deref(), Some(format::SYMBOLS));
        assert_eq!(p.suffix, None);
        // Nothing is lost by leaving them off the command line: `describe` prints
        // every param back, absent ones included.
        assert_eq!(
            p.describe(),
            format!(
                "--mode b58 --length 14 --symbols='{}' --suffix none",
                format::SYMBOLS
            )
        );
    }

    // The `--length` and `--symbols` defaults are per-mode. `hex`/`b58` get the
    // 14-char symbol-mixed package; `b10` is a numeric code, so a bare create
    // resolves a 6-digit, digits-only PIN; `alpha` and `bip39` get neither. A
    // defaulted `--symbols` would make a bare `--mode bip39` fail on a flag the
    // user never typed, and a defaulted `--length 14` would truncate a mnemonic.
    #[test]
    fn the_defaults_apply_only_to_modes_that_take_a_symbol_set() {
        for mode in ["hex", "b58"] {
            let p = parse_params(&create_matches(&["--mode", mode]).unwrap()).unwrap();
            assert_eq!(p.length, Some(14), "{mode}");
            assert_eq!(p.symbols.as_deref(), Some(format::SYMBOLS), "{mode}");
        }
        // b10: PIN defaults, resolved and stored like any other.
        let p = parse_params(&create_matches(&["--mode", "b10"]).unwrap()).unwrap();
        assert_eq!(p.length, Some(6));
        assert_eq!(p.symbols, None);
        assert_eq!(
            p.describe(),
            "--mode b10 --length 6 --no-symbols --suffix none"
        );
        for mode in ["alpha", "bip39"] {
            let p = parse_params(&create_matches(&["--mode", mode]).unwrap()).unwrap();
            assert_eq!(p.length, None, "{mode}");
            assert_eq!(p.symbols, None, "{mode}");
            assert_eq!(
                p.describe(),
                format!("--mode {mode} --length none --no-symbols --suffix none"),
                "{mode}"
            );
        }
    }

    #[test]
    fn explicit_flags_override_the_defaults() {
        // An explicit length wins
        let p = parse_params(&create_matches(&["--length", "20"]).unwrap()).unwrap();
        assert_eq!(p.length, Some(20));

        // An explicit set wins, and the length default still applies beside it
        let p = parse_params(&create_matches(&["--symbols=!@"]).unwrap()).unwrap();
        assert_eq!(p.symbols.as_deref(), Some("!@"));
        assert_eq!(p.length, Some(14));

        // `--no-symbols` opts out of the set. The length default is keyed on the
        // mode, not on the set, so it stays.
        let p = parse_params(&create_matches(&["--no-symbols"]).unwrap()).unwrap();
        assert_eq!(p.symbols, None);
        assert_eq!(p.length, Some(14));
        assert_eq!(
            p.describe(),
            "--mode b58 --length 14 --no-symbols --suffix none"
        );

        // An explicit length under a mode that takes no default is still honoured
        let p =
            parse_params(&create_matches(&["--mode", "alpha", "--length", "30"]).unwrap()).unwrap();
        assert_eq!(p.length, Some(30));
        assert_eq!(p.symbols, None);

        // b10's PIN defaults yield to explicit flags too, each independently.
        let p =
            parse_params(&create_matches(&["--mode", "b10", "--length", "10"]).unwrap()).unwrap();
        assert_eq!(p.length, Some(10));
        assert_eq!(
            p.symbols, None,
            "an explicit length must not revive the symbol default"
        );
        let p = parse_params(&create_matches(&["--mode", "b10", "--symbols"]).unwrap()).unwrap();
        assert_eq!(p.symbols.as_deref(), Some(format::SYMBOLS));
        assert_eq!(
            p.length,
            Some(6),
            "an explicit set must not disturb the PIN length"
        );
    }

    // `--mode bip39` rejects `--length`/`--suffix`, so a defaulted length would
    // have made the plain command impossible.
    #[test]
    fn bare_bip39_create_is_not_broken_by_the_defaults() {
        assert!(parse_params(&create_matches(&["--mode", "bip39"]).unwrap()).is_ok());
        assert!(
            parse_params(&create_matches(&["--mode", "bip39", "--length", "14"]).unwrap()).is_err()
        );
        assert!(parse_params(&create_matches(&["--mode", "bip39", "--symbols"]).unwrap()).is_err());
    }

    // `otp` is a fixed shape like bip39: a bare create resolves neither a
    // length nor a set, and asking for either is a parse-time contradiction.
    #[test]
    fn bare_otp_create_resolves_no_length_and_no_symbols() {
        assert_eq!(mode_defaults("otp"), (None, None));
        let p = parse_params(&create_matches(&["--mode", "otp"]).unwrap()).unwrap();
        assert_eq!(p.mode, "otp");
        assert_eq!(p.length, None);
        assert_eq!(p.symbols, None);
        assert_eq!(p.suffix, None);
        assert_eq!(
            p.describe(),
            "--mode otp --length none --no-symbols --suffix none"
        );
    }

    #[test]
    fn otp_create_rejects_length_suffix_and_symbols() {
        for extra in [
            &["--length", "8"][..],
            &["--suffix", "x"][..],
            &["--symbols"][..],
        ] {
            let mut args = vec!["--mode", "otp"];
            args.extend_from_slice(extra);
            let e = parse_params(&create_matches(&args).unwrap()).unwrap_err();
            assert!(e.contains("otp"), "{extra:?}: the error names the mode: {e}");
        }
    }

    // `rotate --mode otp` over a defaulted b58 recipe: every param the fixed
    // shape cannot render is dropped, each with its own note (the bip39
    // behaviour, now shared through `format::fixed_rendering`).
    #[test]
    fn rotate_to_otp_drops_length_symbols_and_suffix_with_notes() {
        let defaulted = Params {
            mode: "b58".into(),
            length: Some(14),
            symbols: Some(format::SYMBOLS.into()),
            suffix: Some("!!".into()),
        };
        let (p, notes) =
            merge_params(&rotate_matches(&["--mode", "otp"]).unwrap(), defaulted).unwrap();
        assert_eq!(
            p,
            Params {
                mode: "otp".into(),
                length: None,
                symbols: None,
                suffix: None
            }
        );
        assert_eq!(notes.len(), 3, "every drop is announced: {notes:?}");

        // Asking for the contradiction on the same command line stays an error
        let base = || Params {
            mode: "b58".into(),
            length: None,
            symbols: None,
            suffix: None,
        };
        assert!(merge_params(
            &rotate_matches(&["--mode", "otp", "--length", "8"]).unwrap(),
            base()
        )
        .is_err());
        assert!(merge_params(
            &rotate_matches(&["--mode", "otp", "--suffix", "x"]).unwrap(),
            base()
        )
        .is_err());
        assert!(merge_params(
            &rotate_matches(&["--mode", "otp", "--symbols"]).unwrap(),
            base()
        )
        .is_err());
    }

    // `rotate` merges over the *stored* params and fills in nothing, so a
    // definition's recipe only ever changes when the user says so.
    #[test]
    fn rotate_never_applies_the_create_defaults() {
        let base = Params {
            mode: "alpha".into(),
            length: None,
            symbols: None,
            suffix: None,
        };
        let (merged, notes) = merge_params(&rotate_matches(&[]).unwrap(), base.clone()).unwrap();
        assert_eq!(
            merged, base,
            "an empty rotate must not invent a length or a set"
        );
        assert!(notes.is_empty());

        // Nor over a defaulted b58 recipe: the stored params carry through
        let stored = Params {
            mode: "b58".into(),
            length: Some(14),
            symbols: Some(format::SYMBOLS.into()),
            suffix: None,
        };
        let (merged, notes) = merge_params(&rotate_matches(&[]).unwrap(), stored.clone()).unwrap();
        assert_eq!(merged, stored);
        assert!(notes.is_empty());
    }

    // `rotate --mode alpha` says "render this as alpha" and means it. A symbol
    // set that was merely *carried over* has nothing to extend there, so it is
    // dropped with a note rather than refused. `--length`/`--suffix` go the
    // same way under `bip39`.
    #[test]
    fn rotate_drops_params_the_new_mode_cannot_render() {
        let defaulted = || Params {
            mode: "b58".into(),
            length: Some(14),
            symbols: Some(format::SYMBOLS.into()),
            suffix: Some("!!".into()),
        };

        let (p, notes) =
            merge_params(&rotate_matches(&["--mode", "alpha"]).unwrap(), defaulted()).unwrap();
        assert_eq!(p.mode, "alpha");
        assert_eq!(p.symbols, None, "alpha has no alphabet to extend");
        assert_eq!(p.length, Some(14), "but alpha can still be trimmed");
        assert_eq!(p.suffix.as_deref(), Some("!!"), "and still take a suffix");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("Dropped --symbols"), "{notes:?}");

        // bip39 is a fixed 24-word rendering: no set, no trim, no suffix.
        let (p, notes) =
            merge_params(&rotate_matches(&["--mode", "bip39"]).unwrap(), defaulted()).unwrap();
        assert_eq!(
            p,
            Params {
                mode: "bip39".into(),
                length: None,
                symbols: None,
                suffix: None
            }
        );
        assert_eq!(notes.len(), 3, "every drop is announced: {notes:?}");
    }

    // Dropping a *carried* param is obeying an instruction. Dropping one the
    // user just typed would be ignoring a contradiction, so that stays an error.
    #[test]
    fn rotate_refuses_a_mode_and_a_param_that_contradict_each_other() {
        let base = || Params {
            mode: "b58".into(),
            length: None,
            symbols: None,
            suffix: None,
        };
        assert!(merge_params(
            &rotate_matches(&["--mode", "alpha", "--symbols"]).unwrap(),
            base()
        )
        .is_err());
        assert!(merge_params(
            &rotate_matches(&["--mode", "alpha", "--symbols=!@"]).unwrap(),
            base()
        )
        .is_err());
        assert!(merge_params(
            &rotate_matches(&["--mode", "bip39", "--length", "14"]).unwrap(),
            base()
        )
        .is_err());
        assert!(merge_params(
            &rotate_matches(&["--mode", "bip39", "--suffix", "!"]).unwrap(),
            base()
        )
        .is_err());
        // ... and an explicit --no-symbols alongside the mode is simply redundant
        let (p, notes) = merge_params(
            &rotate_matches(&["--mode", "alpha", "--no-symbols"]).unwrap(),
            base(),
        )
        .unwrap();
        assert_eq!(p.symbols, None);
        assert!(
            notes.is_empty(),
            "nothing was dropped: there was nothing to drop"
        );
    }

    // `min_values(0)` is deprecated in clap 3.2 and implies `multiple_values`,
    // so each of these behaviours is a property of the exact builder chain in
    // `symbols_arg` not something to assume.
    #[test]
    fn bare_symbols_resolves_to_the_default_set() {
        let m = create_matches(&["--symbols"]).unwrap();
        assert!(m.contains_id("symbols"));
        assert_eq!(
            m.get_one::<String>("symbols").map(String::as_str),
            Some(format::SYMBOLS)
        );
        assert_eq!(
            parse_params(&m).unwrap().symbols.as_deref(),
            Some(format::SYMBOLS)
        );
    }

    #[test]
    fn symbols_takes_an_explicit_set_after_an_equals_sign() {
        let m = create_matches(&["--symbols=!@#"]).unwrap();
        assert_eq!(
            m.get_one::<String>("symbols").map(String::as_str),
            Some("!@#")
        );
        assert_eq!(parse_params(&m).unwrap().symbols.as_deref(), Some("!@#"));
    }

    #[test]
    fn symbols_may_be_given_at_most_once() {
        // clap 4 reports a repeated single-value arg as ArgumentConflict
        // ("cannot be used multiple times") rather than TooManyValues.
        assert_eq!(
            create_matches(&["--symbols=a", "--symbols=b"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    // `--symbols` (bare) and `--symbols=` (empty) are different: `default_missing_value` fires only for the former
    #[test]
    fn an_explicitly_empty_symbol_set_is_rejected() {
        let m = create_matches(&["--symbols="]).unwrap();
        assert_eq!(m.get_one::<String>("symbols").map(String::as_str), Some(""));
        assert!(parse_params(&m).is_err());
    }

    // `require_equals` is what stops `--symbols --length 20` from reading the next flag as the charset
    #[test]
    fn bare_symbols_does_not_swallow_the_following_flag() {
        let m = create_matches(&["--symbols", "--length", "20"]).unwrap();
        assert_eq!(
            m.get_one::<String>("symbols").map(String::as_str),
            Some(format::SYMBOLS)
        );
        assert_eq!(
            m.get_one::<String>("length").map(String::as_str),
            Some("20")
        );
    }

    #[test]
    fn symbols_and_no_symbols_conflict() {
        assert_eq!(
            create_matches(&["--symbols", "--no-symbols"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn a_colliding_or_unsupported_symbol_set_is_rejected_at_parse_time() {
        let b58_zero = create_matches(&["--symbols=1"]).unwrap();
        assert!(
            parse_params(&b58_zero).is_err(),
            "'1' is base58's zero digit"
        );
        let hex_upper = create_matches(&["--mode", "hex", "--symbols=ABC"]).unwrap();
        assert!(parse_params(&hex_upper).is_ok(), "hex's base is lowercase");
        let hex_lower = create_matches(&["--mode", "hex", "--symbols=abc"]).unwrap();
        assert!(parse_params(&hex_lower).is_err(), "'a' is a hex digit");
        let alpha = create_matches(&["--mode", "alpha", "--symbols"]).unwrap();
        assert!(
            parse_params(&alpha).is_err(),
            "alpha is not a positional base"
        );
    }

    // `id`/`user` land in the confirmation prompts of `apply` and `import`, and
    // a share token is member-signed, not member-trusted: an embedded escape
    // sequence could redraw the very prompt the user is deciding on. Rejected at
    // ingress and the error's own `{:?}` escaping keeps it safe to print.
    #[test]
    fn hd_strings_with_control_characters_are_rejected() {
        assert!(validate_hd_strings("google.com", "bob").is_ok());
        assert!(validate_hd_strings("", "").is_ok());
        for bad in ["a\x1b[2Jb", "a\nb", "a\0b", "\x07"] {
            let e = validate_hd_strings(bad, "").unwrap_err();
            assert!(
                !e.contains('\x1b') && !e.contains('\n') && !e.contains('\0'),
                "the error must escape what it names: {e:?}"
            );
            assert!(validate_hd_strings("ok", bad).is_err());
        }
    }

    // id/user are bounded so that the `otpauth://` URI an otp definition builds
    // stays far inside a QR code's capacity and so a table cell or a prompt
    // cannot be flooded. The error reports a length, never the string.
    #[test]
    fn hd_strings_are_length_bounded() {
        let at = "a".repeat(MAX_HD_STRING_LEN);
        let over = "a".repeat(MAX_HD_STRING_LEN + 1);
        assert!(validate_hd_strings(&at, &at).is_ok(), "the bound is inclusive");
        for (id, user) in [(over.as_str(), ""), ("ok", over.as_str())] {
            let e = validate_hd_strings(id, user).unwrap_err();
            assert!(e.contains(&format!("{}", MAX_HD_STRING_LEN + 1)), "{e}");
            assert!(!e.contains("aaaa"), "the error must not echo the string: {e}");
        }

        // The bound's purpose, asserted against the worst case it admits: every
        // byte of id and user percent-encoded to three, with the issuer
        // appearing twice. That URI must still fit in a QR (~2,950 bytes), or
        // an id that renders would be an id that cannot be scanned.
        let worst = "\u{7f}".repeat(MAX_HD_STRING_LEN); // 1 byte -> "%7F"
        let uri = format::otpauth_uri(&worst, &worst, &"A".repeat(32));
        assert_eq!(uri.len(), 64 + 3 * 3 * MAX_HD_STRING_LEN);
        assert!(
            crate::qr::rows(&uri, false).is_ok(),
            "the worst URI the bound admits ({} bytes) must still encode",
            uri.len()
        );
    }

    // A suffix is pasted into passwords and printed back by `describe()`; a
    // control character is hostile or a mistake in either role. Gated in
    // `validate_params`, which both `apply` and `import` re-run on ingress.
    #[test]
    fn a_suffix_with_control_characters_is_rejected() {
        let p = |suffix: &str| crate::registry::Params {
            mode: "b58".into(),
            length: None,
            symbols: None,
            suffix: Some(suffix.into()),
        };
        assert!(validate_params(&p("!x9")).is_ok());
        assert!(validate_params(&p("a\x1b[2J")).is_err());
        assert!(validate_params(&p("a\tb")).is_err());
    }

    // `--no-symbols` clears a set; `--symbols[=x]` replaces it; neither carries
    // the stored one through.
    #[test]
    fn merge_params_switches_the_symbol_set_on_and_off() {
        let base = || Params {
            mode: "b58".into(),
            length: None,
            symbols: Some("!@".into()),
            suffix: None,
        };

        let cleared = rotate_matches(&["--no-symbols"]).unwrap();
        assert_eq!(merge_params(&cleared, base()).unwrap().0.symbols, None);

        let replaced = rotate_matches(&["--symbols=#$"]).unwrap();
        assert_eq!(
            merge_params(&replaced, base())
                .unwrap()
                .0
                .symbols
                .as_deref(),
            Some("#$")
        );

        let defaulted = rotate_matches(&["--symbols"]).unwrap();
        assert_eq!(
            merge_params(&defaulted, base())
                .unwrap()
                .0
                .symbols
                .as_deref(),
            Some(format::SYMBOLS)
        );

        let untouched = rotate_matches(&[]).unwrap();
        assert_eq!(
            merge_params(&untouched, base())
                .unwrap()
                .0
                .symbols
                .as_deref(),
            Some("!@")
        );
    }

    // Egress is single-valued: only `create`/`rotate` choose a mode, and they
    // choose it for the definition. See [`registry_secret`] for why the reading
    // commands must not.
    #[test]
    fn copy_and_reveal_take_no_mode_override() {
        for sub in ["copy", "reveal"] {
            for extra in [&["--mode", "hex"][..], &["-m", "otp"][..]] {
                let err = sub_matches(sub, extra).unwrap_err();
                assert_eq!(
                    err.kind(),
                    clap::error::ErrorKind::UnknownArgument,
                    "{sub} must reject {extra:?}"
                );
            }
        }
        // `create` and `rotate` still take it: that is *setting* the recipe,
        // not casting an existing one (and `rotate` advances the epoch, so the
        // secret changes with the shape).
        assert!(create_matches(&["--mode", "hex"]).is_ok());
        assert!(rotate_matches(&["--mode", "otp"]).is_ok());
    }

    // One definition, one rendering: whatever the stored params say, including
    // the symbol set that was validated when it was stored.
    #[test]
    fn registry_secret_renders_the_stored_params_only() {
        use crate::crypto::hd_child;
        let master = hd_child(&Scalar::from(7u64), b"ctx");
        let with = |mode: &str, length: Option<u64>, symbols: Option<&str>| Definition {
            params: Params {
                mode: mode.into(),
                length,
                symbols: symbols.map(str::to_string),
                suffix: None,
            },
            ..def("site", "", 1)
        };

        // A stored otp def renders its 32-char Base32 secret, and that is the
        // same pipeline `format_bytes` drives (no separate otp code path).
        let otp = with("otp", None, None);
        let out = registry_secret(&master, &otp).unwrap();
        let child = hd_child_of(&master, &otp);
        assert_eq!(out, format::format_bytes(&child.to_bytes_le(), "otp").unwrap());
        assert_eq!(out.len(), 32);

        // A stored password def renders its password - a *different* string
        // from the otp export of the same id/user/epoch under a different def.
        let pw = with("b58", Some(14), Some("!@"));
        let rendered = registry_secret(&master, &pw).unwrap();
        assert_eq!(rendered.chars().count(), 14);
        assert_ne!(rendered, out);

        // A hand-edited registry whose params no longer render is an error, not
        // a panic: `format_secret` is still the gate (it always was).
        let broken = with("hex", None, Some("a")); // 'a' collides with hex
        assert!(registry_secret(&master, &broken).is_err());
        let impossible = with("bip39", Some(20), None); // fixed shape + a trim
        assert!(registry_secret(&master, &impossible).is_err());
    }

    // `--setup` is the otp enrollment view: allowed exactly for an otp
    // definition, and the error points at a separate one rather than at this
    // definition's own child (which would alias a password into a TOTP seed).
    #[test]
    fn setup_gate_requires_an_otp_definition() {
        let otp_def = Definition {
            params: Params {
                mode: "otp".into(),
                length: None,
                symbols: None,
                suffix: None,
            },
            ..def("vpn", "", 1)
        };
        let b58_def = def("site", "", 1);

        // No flag: no gate, whatever the mode
        assert!(!check_setup_mode(&otp_def, false).unwrap());
        assert!(!check_setup_mode(&b58_def, false).unwrap());

        // The flag passes for an otp definition
        assert!(check_setup_mode(&otp_def, true).unwrap());

        // ...and is refused for any other, naming its mode and pointing at a
        // separate definition rather than a cast
        let e = check_setup_mode(&b58_def, true).unwrap_err();
        assert!(e.contains("--setup") && e.contains("otp") && e.contains("b58"), "{e}");
        assert!(e.contains("separate"), "{e}");
    }

    #[test]
    fn def_changes_shows_symbol_sets_verbatim() {
        let with = |set: Option<&str>| Definition {
            params: Params {
                mode: "b58".into(),
                length: None,
                symbols: set.map(str::to_string),
                suffix: None,
            },
            ..def("site", "", 1)
        };
        let changes = def_changes(&with(None), &with(Some("!@")));
        assert_eq!(
            changes,
            vec![("symbols", "(none)".to_string(), "\"!@\"".to_string())]
        );
        // Two different sets are distinguishable: the reason `describe()` may
        // print the default one as a bare `--symbols`.
        let changes = def_changes(&with(Some("!@")), &with(Some("@!")));
        assert_eq!(
            changes,
            vec![("symbols", "\"!@\"".to_string(), "\"@!\"".to_string())]
        );
    }

    // `--mnemonic` is a flag. A phrase written beside it lands in `<name>`, and
    // `validate_name` would happily make it a directory. Catch it, and never
    // echo it, when this fires, the name *is* the secret.
    #[test]
    fn a_mnemonic_phrase_cannot_become_a_keypair_name() {
        let phrase = "abandon abandon abandon art";
        let err = check_new_keypair_name(phrase, true).unwrap_err();
        assert!(err.contains("takes no value"), "{err}");
        assert!(
            !err.contains("abandon"),
            "the error must never echo the phrase: {err}"
        );

        // Without --mnemonic it is still refused, and still not echoed
        let err = check_new_keypair_name(phrase, false).unwrap_err();
        assert!(err.contains("whitespace"), "{err}");
        assert!(!err.contains("abandon"), "{err}");
    }

    #[test]
    fn new_keypair_names_are_vetted_before_any_prompt() {
        // Reserved words and a leading '-' are unaddressable as CLI positionals.
        assert!(check_new_keypair_name("show", false).is_err());
        assert!(check_new_keypair_name("-x", false).is_err());
        assert!(check_new_keypair_name("../evil", false).is_err());
        // Ordinary names, with or without the flag, pass.
        assert!(check_new_keypair_name("Tom", true).is_ok());
        assert!(check_new_keypair_name("google.com", false).is_ok());
    }

    #[test]
    fn reveal_lines_render_secret_header_and_countdown() {
        let d = def("google.com", "bob", 3);
        let lines = reveal_lines(&d, Some("grp"), "hunter2", 42, 0.5, 0.7, false);
        let joined = lines.join("\n");
        // Header names the group, id, user, and epoch; secret and countdown show
        assert!(joined.contains("grp · google.com · bob (epoch 3)"));
        assert!(
            lines.iter().any(|l| l == "hunter2"),
            "secret on its own line"
        );
        assert!(joined.contains("Clearing in 42s"));
        assert!(joined.contains("press any key to clear now"));
        // No-colour rendering carries no escape sequences (wave bars aren't any)
        assert!(!joined.contains('\x1b'));
    }

    #[test]
    fn reveal_lines_omit_user_and_group_when_absent() {
        let d = def("site", "", 1);
        let joined = reveal_lines(&d, None, "s3cret", 5, 0.0, 1.0, false).join("\n");
        assert!(joined.contains("Revealing site (epoch 1)"));
        assert!(
            !joined.contains('·'),
            "no group/user separators when both absent"
        );
    }

    // The Params annotation: an untrimmed b58 recipe gets its rendered length;
    // an otp recipe does not so "(32 chars)" would describe the Base32 export,
    // not the 6-digit codes the user will see.
    #[test]
    fn describe_params_skips_the_rendered_length_for_otp() {
        use crate::crypto::hd_child;
        let master = hd_child(&Scalar::from(7u64), b"ctx");
        let with_mode = |mode: &str| Definition {
            params: Params {
                mode: mode.into(),
                length: None,
                symbols: None,
                suffix: None,
            },
            ..def("site", "", 1)
        };
        assert!(
            describe_params(&master, &with_mode("b58")).contains("chars"),
            "untrimmed b58 recipes stay annotated"
        );
        let described = describe_params(&master, &with_mode("otp"));
        assert!(!described.contains("chars"), "{described}");
        assert_eq!(described, "--mode otp --length none --no-symbols --suffix none");
    }

    // The copy countdown's refresh closure: silent within a window, one fresh
    // code per rollover, and silent again until the next one.
    #[test]
    fn otp_refresher_fires_exactly_once_per_window_rollover() {
        let key = Zeroizing::new([7u8; format::SCALAR_BYTES]);
        // A scripted clock: two ticks in the start window, two in the next,
        // one two windows later, and one unreadable instant.
        let script: Vec<Option<u64>> =
            vec![Some(70), Some(89), Some(90), Some(95), Some(150), None];
        let mut i = 0;
        let mut refresh = otp_refresher(&key, 70, move || {
            let t = script[i];
            i += 1;
            t
        });

        assert!(refresh().is_none(), "same window as the initial copy");
        assert!(refresh().is_none(), "still the same window");
        let rolled = refresh().expect("the window rolled at t=90");
        assert_eq!(*rolled, totp::code(totp::key(&key), 90));
        assert!(refresh().is_none(), "already refreshed for this window");
        let again = refresh().expect("a later window refreshes again");
        assert_eq!(*again, totp::code(totp::key(&key), 150));
        assert_ne!(*rolled, *again);
        assert!(refresh().is_none(), "an unreadable clock skips the refresh");
    }

    // The enrollment frame: Base32 + URI always; the QR exactly when it fits.
    #[test]
    fn setup_lines_include_the_qr_when_the_terminal_is_tall_enough() {
        let d = def("vpn", "bob", 1);
        let b32 = "A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYH";
        let uri = format!("otpauth://totp/vpn:bob?secret={b32}&issuer=vpn");
        let qr = crate::qr::rows(&uri, false).unwrap();

        let ample = setup_lines(&d, Some("grp"), b32, &uri, &qr, 200, 60, 0.0, 1.0, false);
        let joined = ample.join("\n");
        assert!(joined.contains(b32));
        assert!(joined.contains(&uri));
        assert!(joined.contains("Enrolling grp · vpn · bob (epoch 1)"));
        assert!(joined.contains("Clearing in 60s"));
        assert!(!joined.contains('\x1b'), "no-color frames carry no escapes");
        // Every QR row is present, verbatim
        for row in qr.iter() {
            assert!(ample.contains(row), "missing QR row");
        }
        // ... and the whole layout honours its own row accounting
        assert_eq!(ample.len(), 5 + qr.len() + 2);

        // The wipe width (max over these lines) covers the QR block
        let width = ample.iter().map(|l| l.chars().count()).max().unwrap();
        assert!(width >= qr[0].chars().count());
    }

    #[test]
    fn setup_lines_swap_the_qr_for_a_hint_on_a_short_terminal() {
        let d = def("vpn", "", 1);
        let b32 = "A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYH";
        let uri = format!("otpauth://totp/vpn?secret={b32}&issuer=vpn");
        let qr = crate::qr::rows(&uri, false).unwrap();

        // A classic 24-row terminal cannot hold header + ~21-row QR + footer.
        // Waterline 0.0 keeps the footer wave flat ('▁'), so a '█' can only be
        // a QR cell.
        let short = setup_lines(&d, None, b32, &uri, &qr, 24, 60, 0.0, 0.0, false);
        let joined = short.join("\n");
        assert!(joined.contains("terminal too short for the QR"), "{joined}");
        assert!(!joined.contains('█'), "no QR cells in the fallback");
        // The URI and Base32 survive: enrollment by paste still works
        assert!(joined.contains(&uri));
        assert!(joined.contains(b32));
        assert!(short.len() <= 24, "the fallback must itself fit");

        // The boundary is exact: the QR appears the moment it fits
        let exact = 5 + qr.len() + 2;
        assert!(setup_lines(&d, None, b32, &uri, &qr, exact, 60, 0.0, 0.0, false)
            .join("\n")
            .contains('█'));
        assert!(!setup_lines(&d, None, b32, &uri, &qr, exact - 1, 60, 0.0, 0.0, false)
            .join("\n")
            .contains('█'));
    }

    // A URI that will not encode as a QR costs the QR block, not the view: the
    // Base32 and the URI still enroll by typing and by pasting.
    #[test]
    fn setup_lines_survive_a_qr_that_cannot_be_encoded() {
        let d = def("vpn", "", 1);
        let b32 = "A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYH";
        let uri = format!("otpauth://totp/vpn?secret={b32}&issuer=vpn");
        let lines = setup_lines(&d, None, b32, &uri, &[], 200, 60, 0.0, 0.0, false);
        let joined = lines.join("\n");
        assert!(joined.contains("too long to encode"), "{joined}");
        assert!(joined.contains(b32) && joined.contains(&uri));
        assert!(!joined.contains('█'), "no QR block");
    }

    // The live otp frame: the RFC 6238 code for the given instant, beside its
    // own rolls-in countdown, over the shared header/footer skeleton.
    #[test]
    fn otp_frame_shows_the_live_code_and_rollover_countdown() {
        let d = def("vpn", "", 2);
        let key: &[u8] = b"12345678901234567890";
        // RFC 6238 Appendix B: T = 59 -> 287082, with 1s left in its window
        let lines = otp_frame(&d, None, key, 59, 42, 0.5, 0.7, false);
        let joined = lines.join("\n");
        assert!(joined.contains("287082"), "{joined}");
        assert!(joined.contains("rolls in  1s"), "{joined}");
        assert!(joined.contains("Revealing vpn (epoch 2)"));
        assert!(joined.contains("Clearing in 42s"));
        // No-colour frames carry no escape sequences
        assert!(!joined.contains('\x1b'));

        // One second later the window has rolled: new code, reset countdown
        let rolled = otp_frame(&d, None, key, 60, 42, 0.5, 0.7, false).join("\n");
        assert!(!rolled.contains("287082"), "{rolled}");
        assert!(rolled.contains("rolls in 30s"), "{rolled}");
    }

    // The wipe sizes itself from a single frame_lines call; the otp body pads
    // its rollover seconds to a fixed two columns so that call bounds the body
    // width for **every** timestamp a later frame might render.
    #[test]
    fn otp_frame_width_is_timestamp_independent_so_the_wipe_covers_it() {
        let d = def("vpn", "bob", 1);
        let key: &[u8] = b"12345678901234567890";
        let wipe = otp_frame(&d, Some("grp"), key, 0, 0, 0.0, 0.0, false);
        let wipe_width = wipe.iter().map(|l| l.chars().count()).max().unwrap();
        for now in (0..600).step_by(7) {
            let frame = otp_frame(&d, Some("grp"), key, now, 0, 0.0, 0.0, false);
            let width = frame.iter().map(|l| l.chars().count()).max().unwrap();
            assert!(width <= wipe_width, "frame at t={now} wider than the wipe");
            assert_eq!(
                frame[2].chars().count(),
                wipe[2].chars().count(),
                "body width must not depend on the timestamp"
            );
        }
    }
}
