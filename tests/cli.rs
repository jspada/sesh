//! End-to-end CLI integration tests driving the `sesh` binary against isolated
//! temporary `SESH_HOME` directories, exercising the contacts + setup-token
//! exchange surface.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tempfile::TempDir;

// The password every identity in these tests is created with. Seeds are always
// encrypted, so any command that touches one prompts for it.
const PW: &str = "pw";

// Password lines for a command that prompts at most twice: one unlock, or a
// `create`'s set-and-confirm pair. Surplus lines are simply never read.
fn pw_lines() -> String {
    format!("{PW}\n{PW}\n")
}

// A `sesh` invocation against `home` with **no stdin**.
//
// This is the default on purpose. Plenty of commands read only public state
// (`keypair show`/`list`/`remove`, all of `contact`, `shared-secret
// list`/`show`/`remove`) and must never prompt. Handing every command a
// password would hide the day one of them starts to: the test would pass on
// input it should not have needed. With no stdin, a stray prompt reads EOF,
// takes the empty password, and fails loudly.
//
// Commands that *do* unlock a seed use [`sesh_pw`] instead, so each such call
// site is a standing statement that this command prompts.
fn sesh(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("sesh").unwrap();
    cmd.env("SESH_HOME", home);
    cmd
}

// A `sesh` invocation with [`PW`] on stdin, for commands that unlock a seed. A
// test wanting different input (a mnemonic, a Y/N, a conflict choice) calls
// `write_stdin` again, which replaces this.
fn sesh_pw(home: &Path) -> Command {
    let mut cmd = sesh(home);
    cmd.write_stdin(pw_lines());
    cmd
}

// Run a **password-free** command, assert success, return stdout
fn run_ok(home: &Path, args: &[&str]) -> String {
    let out = sesh(home).args(args).assert().success();
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

// Run a command that **unlocks a seed**, assert success, return stdout
fn run_pw(home: &Path, args: &[&str]) -> String {
    let out = sesh_pw(home).args(args).assert().success();
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

// Extract the value after `label:` from the first matching line
fn field(stdout: &str, label: &str) -> String {
    let line = stdout
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no line starting with {label:?} in:\n{stdout}"));
    line.split_once(':').unwrap().1.trim().to_string()
}

// Extract the agreement checksum token from any line mentioning `Checksum:`
// (works for both the non-interactive `Checksum: ...` line on stdout and the
// wizard's `  > Checksum: ... (share...)` line on stderr).
fn checksum_after(s: &str) -> String {
    let line = s
        .lines()
        .find(|l| l.contains("Checksum:"))
        .unwrap_or_else(|| panic!("no Checksum: line in:\n{s}"));
    line.split_once("Checksum:")
        .unwrap()
        .1
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

// Extract column `col` from the table row whose **first** cell is `key`
// (annotations after the key, e.g. `me  (unencrypted)`, are tolerated).
fn table_cell(stdout: &str, key: &str, col: usize) -> String {
    let line = stdout
        .lines()
        .find(|l| {
            l.split('|').next().is_some_and(|c| {
                let c = c.trim();
                c == key || c.starts_with(&format!("{key} "))
            })
        })
        .unwrap_or_else(|| panic!("no table row keyed {key:?} in:\n{stdout}"));
    line.split('|')
        .nth(col)
        .unwrap_or_else(|| panic!("row has no column {col}:\n{line}"))
        .trim()
        .to_string()
}

// Create a random-seed identity in `home` under [`PW`]; return its contact token
fn make_identity(home: &Path, name: &str) -> String {
    let out = run_pw(home, &["keypair", "create", name]);
    field(&out, "Contact token")
}

// Emit a party's `create` setup token (phase 1) for group `g`. Phase 1 stores
// nothing but still unlocks the seed, to derive the child key it publishes.
fn emit_token(home: &Path, keypair: &str, group: &str, parties: &[&str]) -> String {
    let mut args = vec![
        "shared-secret",
        "create",
        group,
        "--keypair",
        keypair,
        "--emit-token",
    ];
    for p in parties {
        args.push("--party");
        args.push(p);
    }
    let out = run_pw(home, &args);
    field(&out, "Your setup token")
}

// keypair / contact basics

#[test]
fn keypair_create_output_matches_show() {
    let home = TempDir::new().unwrap();
    // `keypair create` prints the same labeled block as `keypair show`
    let created = run_pw(home.path(), &["keypair", "create", "me"]);
    assert_eq!(field(&created, "Name"), "me");
    assert!(!field(&created, "Fingerprint").is_empty());
    assert!(field(&created, "Private key").contains("encrypted"));
    let shown = run_ok(home.path(), &["keypair", "show", "me"]);
    assert_eq!(created, shown);
}

#[test]
fn keypair_new_show_list_remove() {
    let home = TempDir::new().unwrap();
    let created = make_identity(home.path(), "me");
    let shown = run_ok(home.path(), &["keypair", "show", "me"]);
    assert_eq!(created, field(&shown, "Contact token"));
    assert!(!field(&shown, "Fingerprint").is_empty());
    // Every seed is encrypted, so there is no status column to annotate
    assert!(field(&shown, "Private key").contains("encrypted"));

    let listed = run_ok(home.path(), &["keypair", "list"]);
    assert!(listed.contains("me"));
    assert_eq!(table_cell(&listed, "me", 1), field(&shown, "Fingerprint"));

    run_ok(home.path(), &["keypair", "remove", "me"]);
    sesh(home.path())
        .args(["keypair", "show", "me"])
        .assert()
        .failure();
}

#[test]
fn contact_add_show_list_remove() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    // A peer's token (make a throwaway identity in another home to get one)
    let peer_home = TempDir::new().unwrap();
    let token = make_identity(peer_home.path(), "bob");

    // No --name needed: the alias comes from the token's embedded name
    let added = run_ok(home.path(), &["contact", "add", &token]);
    assert!(added.contains("Pinned contact 'bob'"));
    // add now shows the fingerprint (so it can be compared out-of-band) and the
    // pinned token. The fingerprint must equal show's.
    let shown = run_ok(home.path(), &["contact", "show", "bob"]);
    assert_eq!(field(&added, "Fingerprint"), field(&shown, "Fingerprint"));
    assert!(!field(&added, "Fingerprint").is_empty());
    assert_eq!(token, field(&shown, "Contact token"));
    assert!(run_ok(home.path(), &["contact", "list"]).contains("bob"));
    run_ok(home.path(), &["contact", "remove", "bob"]);
    sesh(home.path())
        .args(["contact", "show", "bob"])
        .assert()
        .failure();
}

#[test]
fn contact_add_name_override() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    let peer_home = TempDir::new().unwrap();
    let token = make_identity(peer_home.path(), "bob");

    let added = run_ok(home.path(), &["contact", "add", &token, "--name", "robert"]);
    assert!(added.contains("Pinned contact 'robert'"));
    assert!(run_ok(home.path(), &["contact", "list"]).contains("robert"));
    sesh(home.path())
        .args(["contact", "show", "bob"])
        .assert()
        .failure();
}

#[test]
fn contact_add_same_key_idempotent_diff_key_conflict() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    let ph = TempDir::new().unwrap();
    let token = make_identity(ph.path(), "bob");
    run_ok(home.path(), &["contact", "add", &token]);
    // Same key again -> no-op success.
    let again = run_ok(home.path(), &["contact", "add", &token]);
    assert!(again.contains("already pinned"));
    // A different key under the same alias -> hard failure
    let ph2 = TempDir::new().unwrap();
    let other = make_identity(ph2.path(), "x");
    sesh(home.path())
        .args(["contact", "add", &other, "--name", "bob"])
        .assert()
        .failure();
}

#[test]
fn contact_add_rejects_corrupt_token() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    sesh(home.path())
        .args(["contact", "add", "not-a-real-token"])
        .assert()
        .failure();
}

// which commands prompt

// Reading **public** state must never cost a password. Every command here runs
// with no stdin at all: if one of them grew an `unlock_password` call it would
// read EOF, take the empty password, and fail.
//
// The complement of this list is the set of commands that hold a seed
// (`keypair create`, all of `shared-secret create`, every `hd-secret`
// subcommand, `backup` and `restore`) and those are exactly the call sites
// that use `sesh_pw` / `run_pw`.
#[test]
fn password_free_commands_never_prompt() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    let peer_token = run_ok(b, &["keypair", "show", "me"]);
    let peer_token = field(&peer_token, "Contact token");

    for args in [
        vec!["keypair", "show", "me"],
        vec!["keypair", "list"],
        vec!["contact", "show", "p1"],
        vec!["contact", "list"],
        vec!["contact", "add", peer_token.as_str(), "--name", "again"],
        vec!["shared-secret", "list"],
        vec!["shared-secret", "list", "me"],
        vec!["shared-secret", "show", "grp"],
    ] {
        sesh(a)
            .args(&args)
            .assert()
            .success()
            .stderr(contains("Unlock keypair").not());
    }

    // The removals come last: they mutate, and still need no password
    run_ok(a, &["contact", "remove", "again"]);
    run_ok(a, &["shared-secret", "remove", "grp"]);
    run_ok(a, &["keypair", "remove", "me"]);
}

// ...and the converse: a command that reads a seed really does prompt, so the
// `sesh_pw` call sites above are load-bearing rather than superstition. With no
// stdin the prompt reads EOF, takes the empty password, and fails to decrypt.
#[test]
fn seed_reading_commands_do_prompt() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "site"]);

    for args in [
        vec!["hd-secret", "me", "list"],
        vec!["hd-secret", "me", "show", "site"],
    ] {
        sesh(home.path())
            .args(&args)
            .assert()
            .failure()
            .stderr(contains("Decryption failed"));
    }
}

// --- fingerprints ---

#[test]
fn identity_fingerprint_agrees_between_keypair_and_contact_views() {
    let homes = wire_group(&["a", "b"]);
    // A's own view of its fingerprint...
    let a_fpr = field(
        &run_ok(homes[0].path(), &["keypair", "show", "me"]),
        "Fingerprint",
    );
    // ...equals B's view of A (pinned as contact "p0"), despite the alias
    let b_view = field(
        &run_ok(homes[1].path(), &["contact", "show", "p0"]),
        "Fingerprint",
    );
    assert_eq!(a_fpr, b_view);
    // And differs from B's own fingerprint
    let b_fpr = field(
        &run_ok(homes[1].path(), &["keypair", "show", "me"]),
        "Fingerprint",
    );
    assert_ne!(a_fpr, b_fpr);
}

#[test]
fn group_fingerprint_identical_for_all_members() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    let fa = field(&run_ok(a, &["shared-secret", "show", "grp"]), "Fingerprint");
    let fb = field(&run_ok(b, &["shared-secret", "show", "grp"]), "Fingerprint");
    assert_eq!(fa, fb);
    assert_ne!(fa, "(unavailable)");
    // The list shows the same fingerprint (last column)
    assert_eq!(
        table_cell(&run_ok(a, &["shared-secret", "list"]), "grp", 2),
        fa
    );
}

// name invariants

#[test]
fn reserved_names_rejected_at_creation() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    // The name is vetted before any prompt, so no password is needed and none
    // is asked for.
    sesh(home.path())
        .args(["keypair", "create", "show"])
        .assert()
        .failure()
        .stderr(contains("reserved"))
        .stderr(contains("Set keystore password").not());
    let ph = TempDir::new().unwrap();
    let token = make_identity(ph.path(), "bob");
    sesh(home.path())
        .args(["contact", "add", &token, "--name", "apply"])
        .assert()
        .failure()
        .stderr(contains("reserved"));
}

#[test]
fn keypair_and_group_names_must_differ() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    // A keypair may not take an existing group's name
    sesh_pw(a)
        .args(["keypair", "create", "grp"])
        .assert()
        .failure()
        .stderr(contains("already exists"));
    // A group may not take an existing keypair's name ("me"): completing the
    // exchange fails at store time.
    let b_tok = emit_token(b, "me", "me", &["p0"]);
    sesh(a)
        .args([
            "shared-secret",
            "create",
            "me",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--token",
            &b_tok,
        ])
        .assert()
        .failure()
        .stderr(contains("already exists"));
}

// cascading removal

#[test]
fn keypair_remove_cascades_owned_groups() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    let out = run_ok(a, &["keypair", "remove", "me"]);
    assert!(
        out.contains("Removed shared-secret \"grp\""),
        "cascade not reported:\n{out}"
    );
    assert!(out.contains("Removed identity 'me'"));
    assert!(run_ok(a, &["shared-secret", "list"]).contains("(no shared secrets)"));
    sesh(a)
        .args(["hd-secret", "grp", "list"])
        .assert()
        .failure();
    // B's copy of the group is untouched
    run_ok(b, &["shared-secret", "show", "grp"]);
}

#[test]
fn contact_remove_cascades_member_groups() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    let out = run_ok(a, &["contact", "remove", "p1"]);
    assert!(
        out.contains("Removed shared-secret \"grp\""),
        "cascade not reported:\n{out}"
    );
    assert!(out.contains("Removed contact 'p1'"));
    sesh(a)
        .args(["shared-secret", "show", "grp"])
        .assert()
        .failure();
    // The identity itself survives a contact cascade
    run_ok(a, &["keypair", "show", "me"]);
}

// auto-help

#[test]
fn bare_families_print_help() {
    let home = TempDir::new().unwrap();
    for family in ["keypair", "contact", "shared-secret", "hd-secret"] {
        let assert = sesh(home.path()).arg(family).assert().failure();
        let out = assert.get_output();
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            all.contains("USAGE"),
            "no help for bare `sesh {family}`:\n{all}"
        );
    }
}

// shared-secret: two-phase token exchange

// Wire up N parties in separate homes, pinning each other as contacts
// `p0..pN-1`. Returns the homes.
fn wire_group(names: &[&str]) -> Vec<TempDir> {
    let homes: Vec<TempDir> = names.iter().map(|_| TempDir::new().unwrap()).collect();
    let tokens: Vec<String> = homes
        .iter()
        .map(|h| make_identity(h.path(), "me"))
        .collect();
    for (i, h) in homes.iter().enumerate() {
        for (j, token) in tokens.iter().enumerate() {
            if i != j {
                // Every identity is named "me", so pin under a distinct alias
                run_ok(
                    h.path(),
                    &["contact", "add", token, "--name", &format!("p{j}")],
                );
            }
        }
    }
    homes
}

#[test]
fn two_party_token_exchange_agrees() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());

    // Phase 1: each emits its token (peer is the other's alias)
    let a_tok = emit_token(a, "me", "grp", &["p1"]);
    let b_tok = emit_token(b, "me", "grp", &["p0"]);

    // Phase 2: each completes with the peer's token
    let a_out = run_pw(
        a,
        &[
            "shared-secret",
            "create",
            "grp",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--token",
            &b_tok,
        ],
    );
    let b_out = run_pw(
        b,
        &[
            "shared-secret",
            "create",
            "grp",
            "--keypair",
            "me",
            "--party",
            "p0",
            "--token",
            &a_tok,
        ],
    );

    // Both parties agree on the checksum (proves the same derived K) and the
    // group fingerprint (same public group). The finished block is metadata
    // only and the secret itself is never printed.
    assert_eq!(checksum_after(&a_out), checksum_after(&b_out));
    assert_eq!(field(&a_out, "Fingerprint"), field(&b_out, "Fingerprint"));
    assert_eq!(field(&a_out, "Name"), "grp");
    assert_eq!(field(&a_out, "Owner"), "me");
    assert!(field(&a_out, "Secret").contains("derived on demand"));
    assert!(!a_out.contains("Shared secret"));
}

#[test]
fn three_party_token_exchange_agrees() {
    let homes = wire_group(&["a", "b", "c"]);
    let (a, b, c) = (homes[0].path(), homes[1].path(), homes[2].path());

    // Each party's peers are the other two, in ascending alias order
    let a_tok = emit_token(a, "me", "t", &["p1", "p2"]);
    let b_tok = emit_token(b, "me", "t", &["p0", "p2"]);
    let c_tok = emit_token(c, "me", "t", &["p0", "p1"]);

    let complete = |home: &Path, peers: [&str; 2], toks: [&str; 2]| {
        run_pw(
            home,
            &[
                "shared-secret",
                "create",
                "t",
                "--keypair",
                "me",
                "--party",
                peers[0],
                "--party",
                peers[1],
                "--token",
                toks[0],
                "--token",
                toks[1],
            ],
        )
    };
    let a_out = complete(a, ["p1", "p2"], [&b_tok, &c_tok]);
    let b_out = complete(b, ["p0", "p2"], [&a_tok, &c_tok]);
    let c_out = complete(c, ["p0", "p1"], [&a_tok, &b_tok]);

    // All three agree on the checksum (same derived K) and fingerprint
    let sum = checksum_after(&a_out);
    assert_eq!(sum, checksum_after(&b_out));
    assert_eq!(sum, checksum_after(&c_out));
    assert_eq!(field(&a_out, "Fingerprint"), field(&c_out, "Fingerprint"));
}

#[test]
fn different_group_name_diverges() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());

    let secret_for = |group: &str| -> String {
        let a_tok = emit_token(a, "me", group, &["p1"]);
        let b_tok = emit_token(b, "me", group, &["p0"]);
        let a_out = run_pw(
            a,
            &[
                "shared-secret",
                "create",
                group,
                "--keypair",
                "me",
                "--party",
                "p1",
                "--token",
                &b_tok,
            ],
        );
        // b must also derive (agreement), but we only compare a's here. The
        // checksum tracks the derived K, so a different name -> different sum.
        let _ = run_pw(
            b,
            &[
                "shared-secret",
                "create",
                group,
                "--keypair",
                "me",
                "--party",
                "p0",
                "--token",
                &a_tok,
            ],
        );
        checksum_after(&a_out)
    };
    assert_ne!(secret_for("groupone"), secret_for("grouptwo"));
}

// shared-secret: list / show / copy / dump / remove

#[test]
fn shared_secret_list_show_and_owner_filter() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    let listed = run_ok(a, &["shared-secret", "list"]);
    assert_eq!(table_cell(&listed, "grp", 1), "me");

    // Positional keypair filters by owner
    let filtered = run_ok(a, &["shared-secret", "list", "me"]);
    assert_eq!(table_cell(&filtered, "grp", 0), "grp");
    // An unknown filter keypair is an error
    sesh(a)
        .args(["shared-secret", "list", "ghost"])
        .assert()
        .failure();

    // show is metadata-only: owner, members, no secret material
    let shown = run_ok(a, &["shared-secret", "show", "grp"]);
    assert_eq!(field(&shown, "Owner"), "me");
    // The owning keypair is itself a member, listed first
    assert_eq!(field(&shown, "Members"), "me, p1");
    assert!(field(&shown, "Secret").contains("derived on demand"));
}

#[test]
fn shared_secret_master_never_leaves_the_keystore() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // The stored master K keys the group's hd-secrets and never leaves the
    // keystore: export/reveal/copy/dump do not exist in this family. Its leaf
    // secrets are reached only through `hd-secret <group> copy` / `reveal`.
    for sub in ["export", "reveal", "copy", "dump"] {
        sesh(a)
            .args(["shared-secret", sub, "grp"])
            .assert()
            .failure();
    }
    let _ = b; // symmetry: same holds on the other member
    let shown = run_ok(a, &["shared-secret", "show", "grp"]);
    assert!(field(&shown, "Secret").contains("derived on demand"));
}

#[test]
fn shared_secret_derive_subcommand_is_gone() {
    let homes = wire_group(&["a", "b"]);
    let a = homes[0].path();
    // `shared-secret derive` was removed: the one-off external secret is no
    // longer a spelling. Forming a group is `create` only.
    sesh(a)
        .args([
            "shared-secret",
            "derive",
            "adhoc",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--emit-token",
        ])
        .assert()
        .failure();
}

#[test]
fn shared_secret_remove() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    let out = run_ok(a, &["shared-secret", "remove", "grp"]);
    assert!(out.contains("Removed shared-secret \"grp\""));
    sesh(a)
        .args(["shared-secret", "show", "grp"])
        .assert()
        .failure();
    // A keypair name gets a pointed error, and the keypair survives
    sesh(a)
        .args(["shared-secret", "remove", "me"])
        .assert()
        .failure()
        .stderr(contains("is a keypair"));
    run_ok(a, &["keypair", "show", "me"]);
}

// keystore location override

#[test]
fn keystore_flag_overrides_location_and_env() {
    let ks_dir = TempDir::new().unwrap();
    let ks = ks_dir.path().to_str().unwrap();

    // Flag BEFORE the subcommand creates the identity in ks_dir
    Command::cargo_bin("sesh")
        .unwrap()
        .args(["--keystore", ks, "keypair", "create", "me"])
        .write_stdin(pw_lines())
        .assert()
        .success();

    // Flag AFTER the subcommand (global arg) finds the same store
    let out = Command::cargo_bin("sesh")
        .unwrap()
        .args(["keypair", "list", "--keystore", ks])
        .assert()
        .success();
    let listed = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(listed.contains("me"));

    // Precedence: --keystore beats $SESH_HOME. SESH_HOME points at an empty
    // (initialized) store, but the flag still resolves to ks_dir.
    let empty = TempDir::new().unwrap();
    let out = Command::cargo_bin("sesh")
        .unwrap()
        .env("SESH_HOME", empty.path())
        .args(["--keystore", ks, "keypair", "list"])
        .assert()
        .success();
    assert!(String::from_utf8(out.get_output().stdout.clone())
        .unwrap()
        .contains("me"));

    // Without the flag, $SESH_HOME (the empty dir) is used
    let out = Command::cargo_bin("sesh")
        .unwrap()
        .env("SESH_HOME", empty.path())
        .args(["keypair", "list"])
        .assert()
        .success();
    assert!(String::from_utf8(out.get_output().stdout.clone())
        .unwrap()
        .contains("(no identities)"));
}

// backup / restore

#[test]
fn backup_restore_round_trips_the_keystore() {
    let src = TempDir::new().unwrap();
    make_identity(src.path(), "me");
    run_pw(src.path(), &["hd-secret", "me", "create", "google.com"]);
    let secret_before = hd_secret_of(src.path(), "me", "google.com");

    // Back up (passphrase entered twice), producing a single encrypted file
    let backup_file = src.path().join("backup.sesh");
    let backup_arg = backup_file.to_str().unwrap();
    sesh(src.path())
        .args(["backup", backup_arg])
        .write_stdin("pw\npw\n")
        .assert()
        .success()
        .stdout(contains("Backed up"));

    // The bundle must not contain the identity name in the clear
    let raw = std::fs::read_to_string(&backup_file).unwrap();
    assert!(!raw.contains("google.com"));

    // Restore into a fresh, empty keystore and re-derive the same secret
    let dst = TempDir::new().unwrap();
    sesh(dst.path())
        .args(["restore", backup_arg])
        .write_stdin("pw\n")
        .assert()
        .success()
        .stdout(contains("Restored"));
    let secret_after = hd_secret_of(dst.path(), "me", "google.com");
    assert_eq!(secret_before, secret_after);

    // A wrong passphrase fails to restore
    let dst2 = TempDir::new().unwrap();
    sesh(dst2.path())
        .args(["restore", backup_arg])
        .write_stdin("wrong\n")
        .assert()
        .failure()
        .stderr(contains("wrong passphrase or tampered"));

    // Restoring over a non-empty keystore needs --force
    sesh(src.path())
        .args(["restore", backup_arg])
        .write_stdin("pw\n")
        .assert()
        .failure()
        .stderr(contains("--force"));
}

// backup: mnemonic keypairs travel without their seed

// stdin for `backup`: one unlock per mnemonic keypair (in `list_identities`
// order, i.e. sorted by name), then the bundle passphrase twice.
fn backup_stdin(mnemonic_keypairs: usize, passphrase: &str) -> String {
    let mut s = format!("{PW}\n").repeat(mnemonic_keypairs);
    s.push_str(&format!("{passphrase}\n{passphrase}\n"));
    s
}

// What to answer for one omitted mnemonic identity during `restore`
enum Answer<'a> {
    // Say `y` to the skip prompt: abandon this keypair and its groups
    Skip,
    // Decline the skip, type this mnemonic, then set a new keypair password
    Recover(&'a str),
}

// stdin for `restore`: the bundle passphrase, then one `answers` block per
// omitted mnemonic identity, in manifest order.
fn restore_stdin(passphrase: &str, answers: &[Answer]) -> String {
    let mut s = format!("{passphrase}\n");
    for a in answers {
        match a {
            Answer::Skip => s.push_str("y\n"),
            Answer::Recover(m) => s.push_str(&format!("n\n{m}\n{PW}\n{PW}\n")),
        }
    }
    s
}

// A pair of homes wired as each other's contact `peer`: `a` holds a
// mnemonic-derived keypair `me`, `b` a random-seed one.
fn wire_mnemonic_pair(mnemonic: &str) -> (TempDir, TempDir) {
    let (a, b) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let a_tok = field(&import_mnemonic(a.path(), "me", mnemonic), "Contact token");
    let b_tok = make_identity(b.path(), "me");
    run_ok(a.path(), &["contact", "add", &b_tok, "--name", "peer"]);
    run_ok(b.path(), &["contact", "add", &a_tok, "--name", "peer"]);
    (a, b)
}

// Form group `group` between two homes already wired as contacts `peer`
fn form_peer_group(a: &Path, b: &Path, group: &str) {
    let a_tok = emit_token(a, "me", group, &["peer"]);
    let b_tok = emit_token(b, "me", group, &["peer"]);
    run_pw(
        a,
        &[
            "shared-secret",
            "create",
            group,
            "--keypair",
            "me",
            "--party",
            "peer",
            "--token",
            &b_tok,
        ],
    );
    run_pw(
        b,
        &[
            "shared-secret",
            "create",
            group,
            "--keypair",
            "me",
            "--party",
            "peer",
            "--token",
            &a_tok,
        ],
    );
}

// The whole claim of the change, told as one story: a mnemonic keypair, an
// hd-secret and a group survive a seedless backup, restored from 24 words.
#[test]
fn mnemonic_keypair_round_trips_without_its_seed_in_the_bundle() {
    let (a, b) = wire_mnemonic_pair(ZERO_MNEMONIC);
    form_peer_group(a.path(), b.path(), "grp");
    run_pw(a.path(), &["hd-secret", "me", "create", "personal"]);
    run_pw(a.path(), &["hd-secret", "grp", "create", "shared"]);
    let personal_before = hd_secret_of(a.path(), "me", "personal");
    let shared_before = hd_secret_of(a.path(), "grp", "shared");

    let bundle = a.path().join("b.sesh");
    let arg = bundle.to_str().unwrap();
    let out = sesh(a.path())
        .args(["backup", arg])
        .write_stdin(backup_stdin(1, "bpass"))
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("Omitted"),
        "backup must name what it left out:\n{stdout}"
    );
    assert!(stdout.contains("me"));
    assert!(
        stdout.contains("grp"),
        "and the groups that depend on it:\n{stdout}"
    );

    // Restore into a fresh keystore, supplying the mnemonic
    let dst = TempDir::new().unwrap();
    sesh(dst.path())
        .args(["restore", arg])
        .write_stdin(restore_stdin("bpass", &[Answer::Recover(ZERO_MNEMONIC)]))
        .assert()
        .success()
        .stdout(contains("Recovered keypair 'me'"));

    // The seed came back from the words: the same hd-secret, and the group
    // still reconstructs (seed + state + pinned contacts were all present).
    assert_eq!(personal_before, hd_secret_of(dst.path(), "me", "personal"));
    assert_eq!(shared_before, hd_secret_of(dst.path(), "grp", "shared"));
}

#[test]
fn a_random_seed_keypair_is_included_and_restores_with_no_mnemonic_prompt() {
    let src = TempDir::new().unwrap();
    make_identity(src.path(), "me");
    run_pw(src.path(), &["hd-secret", "me", "create", "site"]);
    let before = hd_secret_of(src.path(), "me", "site");

    let bundle = src.path().join("b.sesh");
    let arg = bundle.to_str().unwrap();
    let out = sesh(src.path())
        .args(["backup", arg])
        .write_stdin(backup_stdin(0, "bpass"))
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains("Omitted"),
        "nothing was omitted:\n{stdout}"
    );
    assert!(
        stdout.contains("your whole identity"),
        "the old promise still holds"
    );

    // Only the passphrase is asked for; the seed rides along in the bundle
    let dst = TempDir::new().unwrap();
    sesh(dst.path())
        .args(["restore", arg])
        .write_stdin(restore_stdin("bpass", &[]))
        .assert()
        .success();
    assert!(dst.path().join("keypairs/me/identity").is_file());
    assert_eq!(before, hd_secret_of(dst.path(), "me", "site"));
}

#[test]
fn a_mixed_keystore_omits_only_the_mnemonic_seed() {
    let home = TempDir::new().unwrap();
    import_mnemonic(home.path(), "mnem", ZERO_MNEMONIC);
    make_identity(home.path(), "rand");

    let bundle = home.path().join("b.sesh");
    let arg = bundle.to_str().unwrap();
    sesh(home.path())
        .args(["backup", arg])
        .write_stdin(backup_stdin(1, "bpass")) // only 'mnem' is unlocked
        .assert()
        .success()
        .stdout(contains("mnem"));

    let dst = TempDir::new().unwrap();
    sesh(dst.path())
        .args(["restore", arg])
        .write_stdin(restore_stdin("bpass", &[Answer::Recover(ZERO_MNEMONIC)]))
        .assert()
        .success();
    // Both are back; the random one never needed a word typed
    assert!(dst.path().join("keypairs/rand/identity").is_file());
    assert!(dst.path().join("keypairs/mnem/identity").is_file());
    assert_eq!(
        field(
            &run_ok(home.path(), &["keypair", "show", "rand"]),
            "Fingerprint"
        ),
        field(
            &run_ok(dst.path(), &["keypair", "show", "rand"]),
            "Fingerprint"
        )
    );
}

// A mnemonic keypair with no hd-secrets contributes **zero** files to the
// manifest, so `write_identity`'s own `create_dir_secure` is what makes its
// directory. Do not "optimise" that mkdir away.
#[test]
fn a_mnemonic_keypair_with_no_hd_secrets_round_trips() {
    let src = TempDir::new().unwrap();
    let created = import_mnemonic(src.path(), "me", ZERO_MNEMONIC);

    let bundle = src.path().join("b.sesh");
    let arg = bundle.to_str().unwrap();
    sesh(src.path())
        .args(["backup", arg])
        .write_stdin(backup_stdin(1, "bpass"))
        .assert()
        .success();

    let dst = TempDir::new().unwrap();
    sesh(dst.path())
        .args(["restore", arg])
        .write_stdin(restore_stdin("bpass", &[Answer::Recover(ZERO_MNEMONIC)]))
        .assert()
        .success();
    assert!(dst.path().join("keypairs/me/identity").is_file());
    assert_eq!(
        field(&created, "Fingerprint"),
        field(
            &run_ok(dst.path(), &["keypair", "show", "me"]),
            "Fingerprint"
        )
    );
}

// A *valid* mnemonic for the wrong keypair. The BIP39 checksum cannot catch it
// (only the fingerprint can) and it must be caught before anything is written.
#[test]
fn a_wrong_mnemonic_fails_by_name_with_the_target_untouched() {
    let src = TempDir::new().unwrap();
    import_mnemonic(src.path(), "alpha", ZERO_MNEMONIC);
    import_mnemonic(src.path(), "beta", ONES_MNEMONIC);

    let bundle = src.path().join("b.sesh");
    let arg = bundle.to_str().unwrap();
    sesh(src.path())
        .args(["backup", arg])
        .write_stdin(backup_stdin(2, "bpass"))
        .assert()
        .success();

    // 'alpha' sorts first. Answer it with *beta's* mnemonic: valid words, wrong
    // keypair. It must fail there, before beta's prompts ever run.
    let dst = TempDir::new().unwrap();
    sesh(dst.path())
        .args(["restore", arg])
        .write_stdin(restore_stdin("bpass", &[Answer::Recover(ONES_MNEMONIC)]))
        .assert()
        .failure()
        .stderr(contains("'alpha'"))
        .stderr(contains("different keypair"));
    assert!(
        std::fs::read_dir(dst.path()).unwrap().next().is_none(),
        "a wrong mnemonic must leave the target untouched"
    );
}

// A backup must never become all-or-nothing. A user holding the bundle and its
// passphrase but missing one of two mnemonics still recovers their contacts,
// their random-seed keypairs, and every group owned by a keypair they restored.
#[test]
fn a_skipped_mnemonic_is_not_a_failure_and_cascades_to_its_groups() {
    // 'skipme' (mnemonic) owns "gone"; 'keepme' (mnemonic) owns "kept"
    let (a, b) = wire_mnemonic_pair(ZERO_MNEMONIC);
    let (a, b) = (a.path(), b.path());
    import_mnemonic(a, "keepme", ONES_MNEMONIC);
    make_identity(a, "randkp");
    form_peer_group(a, b, "gone"); // owned by 'me'
    run_pw(a, &["hd-secret", "gone", "create", "groupsecret"]);
    // 'me' needs a *personal* registry too, so `keypairs/me/registry` exists in
    // the bundle. Without it, skipping the directory and skipping only its
    // `identity` file would be indistinguishable and the latter is the wrong
    // implementation this test exists to reject.
    run_pw(a, &["hd-secret", "me", "create", "personal"]);

    let bundle_path = a.join("b.sesh");
    let arg = bundle_path.to_str().unwrap();
    // Three mnemonic keypairs sorted: keepme, me. ('randkp' is random.)
    let out = sesh(a)
        .args(["backup", arg])
        .write_stdin(backup_stdin(2, "bpass"))
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("gone"),
        "the owned group is named:\n{stdout}"
    );

    // Recover 'keepme', skip 'me' (which owns "gone")
    let dst = TempDir::new().unwrap();
    let out = sesh(dst.path())
        .args(["restore", arg])
        .write_stdin(restore_stdin(
            "bpass",
            &[Answer::Recover(ONES_MNEMONIC), Answer::Skip],
        ))
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("Not recovered"),
        "the skip is loud:\n{stdout}"
    );
    assert!(stdout.contains("keypair 'me'"), "named:\n{stdout}");
    assert!(
        stdout.contains("\"gone\""),
        "and so is its cascaded group:\n{stdout}"
    );

    // The skip is atomic: *nothing* of 'me' reached disk. Not the seed, not the
    // metadata, and above all not `registry`, ciphertext nobody could open,
    // sitting in a directory with no identity file, which `list_identities`
    // (which lists directories, and never opens `identity`) would happily report
    // as a healthy keypair.
    assert!(!dst.path().join("keypairs/me/registry").exists());
    assert!(!dst.path().join("keypairs/me").exists());
    // The cascade took its group with it, for the same reason: a group restored
    // without its seed-providing keypair is inert.
    assert!(!dst.path().join("shared-secrets/gone").exists());
    // Everything else came back.
    assert!(dst.path().join("keypairs/keepme/identity").is_file());
    assert!(dst.path().join("keypairs/randkp/identity").is_file());
    assert!(dst.path().join("contacts/peer/identity").is_file());
    run_ok(dst.path(), &["keypair", "show", "keepme"]);
    run_ok(dst.path(), &["keypair", "show", "randkp"]);

    // And atomicity is what lets the pruned keystore be backed up *again*:
    // `identity_origin` never meets an identity-less keypair directory.
    let again = dst.path().join("again.sesh");
    sesh(dst.path())
        .args(["backup", again.to_str().unwrap()])
        .write_stdin(backup_stdin(1, "bpass2")) // only 'keepme' remains mnemonic
        .assert()
        .success();
    assert!(again.is_file());
}

// A group owned by a *restored* keypair survives the skip of a different one,
// and still reconstructs.
#[test]
fn a_skip_spares_groups_owned_by_a_restored_keypair() {
    let (a, b) = wire_mnemonic_pair(ZERO_MNEMONIC);
    let (a, b) = (a.path(), b.path());
    form_peer_group(a, b, "kept"); // owned by 'me' (mnemonic)
    run_pw(a, &["hd-secret", "kept", "create", "s"]);
    let secret_before = hd_secret_of(a, "kept", "s");
    // A second mnemonic keypair that owns nothing, to be skipped
    import_mnemonic(a, "zzz", ONES_MNEMONIC);

    let bundle = a.join("b.sesh");
    let arg = bundle.to_str().unwrap();
    sesh(a)
        .args(["backup", arg])
        .write_stdin(backup_stdin(2, "bpass"))
        .assert()
        .success();

    // Sorted: 'me' then 'zzz'. Recover 'me', skip 'zzz'
    let dst = TempDir::new().unwrap();
    sesh(dst.path())
        .args(["restore", arg])
        .write_stdin(restore_stdin(
            "bpass",
            &[Answer::Recover(ZERO_MNEMONIC), Answer::Skip],
        ))
        .assert()
        .success();
    assert!(!dst.path().join("keypairs/zzz").exists());
    assert!(dst.path().join("shared-secrets/kept/state").is_file());
    assert_eq!(secret_before, hd_secret_of(dst.path(), "kept", "s"));
}

// `--force` means the bundle replaces the target. Everything else follows
#[test]
fn restore_force_replaces_the_target_entirely() {
    let src = TempDir::new().unwrap();
    import_mnemonic(src.path(), "me", ZERO_MNEMONIC);
    let expected = field(
        &run_ok(src.path(), &["keypair", "show", "me"]),
        "Fingerprint",
    );

    let bundle = src.path().join("b.sesh");
    let arg = bundle.to_str().unwrap();
    sesh(src.path())
        .args(["backup", arg])
        .write_stdin(backup_stdin(1, "bpass"))
        .assert()
        .success();

    // A populated target holding a *different* 'me', plus a file the bundle
    // never had.
    let dst = TempDir::new().unwrap();
    import_mnemonic(dst.path(), "me", ONES_MNEMONIC);
    let junk = dst.path().join("junk.txt");
    std::fs::write(&junk, b"not in the bundle").unwrap();
    assert_ne!(
        expected,
        field(
            &run_ok(dst.path(), &["keypair", "show", "me"]),
            "Fingerprint"
        )
    );

    sesh(dst.path())
        .args(["restore", arg, "--force"])
        .write_stdin(restore_stdin("bpass", &[Answer::Recover(ZERO_MNEMONIC)]))
        .assert()
        .success();

    // The restored identity is the mnemonic just entered, not the seed on disk
    assert_eq!(
        expected,
        field(
            &run_ok(dst.path(), &["keypair", "show", "me"]),
            "Fingerprint"
        )
    );
    assert!(
        !junk.exists(),
        "--force means the bundle replaces the target"
    );
}

// The regression this change's security argument rests on. Without
// unlock-before-skip, `backup` would trust a plaintext byte and write an
// unrecoverable bundle. Assert the abort and the absent file, **not** the
// error's flavour: AES-GCM cannot tell this from a wrong password.
#[test]
fn a_flipped_origin_aborts_the_backup_and_writes_nothing() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "victim"); // random seed: unrecoverable

    // Relabel it as mnemonic-derived, exactly as an attacker with write access
    // would, to make the next backup drop its seed.
    let path = home.path().join("keypairs/victim/identity");
    let mut rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(rec["origin"], "random");
    rec["origin"] = serde_json::json!("mnemonic");
    std::fs::write(&path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

    let bundle = home.path().join("b.sesh");
    let arg = bundle.to_str().unwrap();
    sesh(home.path())
        .args(["backup", arg])
        .write_stdin(backup_stdin(1, "bpass"))
        .assert()
        .failure()
        .stderr(contains("victim"));
    assert!(!bundle.exists(), "an aborted backup must write no bundle");
}

// The `TargetNotEmpty` guard must not drift behind the passphrase prompt and N
// 24-word mnemonic prompts. With no stdin at all, it still fires.
#[test]
fn restoring_over_a_non_empty_keystore_fails_before_any_prompt() {
    let src = TempDir::new().unwrap();
    import_mnemonic(src.path(), "me", ZERO_MNEMONIC);
    let bundle = src.path().join("b.sesh");
    let arg = bundle.to_str().unwrap();
    sesh(src.path())
        .args(["backup", arg])
        .write_stdin(backup_stdin(1, "bpass"))
        .assert()
        .success();

    sesh(src.path())
        .args(["restore", arg])
        .assert()
        .failure()
        .stderr(contains("--force"))
        .stderr(contains("Backup passphrase").not());
}

// shared-secret: wizard

#[test]
fn wizard_two_party_agrees_with_token_peer() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());

    // B emits a token that A will paste into the wizard
    let b_tok = emit_token(b, "me", "grp", &["p0"]);

    // A runs the forced wizard, piping: unlock, continue, press-enter, token,
    // confirm. The seed is unlocked before the wizard starts.
    let wiz = sesh(a)
        .args([
            "shared-secret",
            "create",
            "grp",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--wizard",
        ])
        .write_stdin(format!("{PW}\ny\n\n{b_tok}\ny\n"))
        .assert()
        .success();
    // The wizard shows the checksum on stderr (its interactive confirmation)
    let a_err = String::from_utf8(wiz.get_output().stderr.clone()).unwrap();

    // A's setup token is deterministic; emit it for B to complete with
    let a_tok = emit_token(a, "me", "grp", &["p1"]);
    let b_out = run_pw(
        b,
        &[
            "shared-secret",
            "create",
            "grp",
            "--keypair",
            "me",
            "--party",
            "p0",
            "--token",
            &a_tok,
        ],
    );
    // Wizard-A and token-B derived the same secret (equal agreement checksum)
    assert_eq!(checksum_after(&a_err), checksum_after(&b_out));
}

#[test]
fn wizard_aborts_on_declined_continue() {
    let homes = wire_group(&["a", "b"]);
    let a = homes[0].path();
    sesh(a)
        .args([
            "shared-secret",
            "create",
            "grp",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--wizard",
        ])
        .write_stdin(format!("{PW}\nn\n"))
        .assert()
        .failure();
}

// error cases

#[test]
fn unknown_party_rejected() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    sesh(home.path())
        .args([
            "shared-secret",
            "create",
            "g",
            "--keypair",
            "me",
            "--party",
            "ghost",
            "--emit-token",
        ])
        .assert()
        .failure();
}

#[test]
fn too_many_parties_rejected() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    // Pin three contacts
    for alias in ["x", "y", "z"] {
        let ph = TempDir::new().unwrap();
        let token = make_identity(ph.path(), alias);
        run_ok(home.path(), &["contact", "add", &token]);
    }
    sesh(home.path())
        .args([
            "shared-secret",
            "create",
            "g",
            "--keypair",
            "me",
            "--party",
            "x",
            "--party",
            "y",
            "--party",
            "z",
            "--emit-token",
        ])
        .assert()
        .failure();
}

#[test]
fn duplicate_party_rejected() {
    let homes = wire_group(&["a", "b"]);
    let a = homes[0].path();
    sesh(a)
        .args([
            "shared-secret",
            "create",
            "g",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--party",
            "p1",
            "--emit-token",
        ])
        .assert()
        .failure();
}

#[test]
fn wrong_token_count_rejected() {
    let homes = wire_group(&["a", "b", "c"]);
    let a = homes[0].path();
    let b_tok = emit_token(homes[1].path(), "me", "t", &["p0", "p2"]);
    // 3-party group but only one --token supplied
    sesh(a)
        .args([
            "shared-secret",
            "create",
            "t",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--party",
            "p2",
            "--token",
            &b_tok,
        ])
        .assert()
        .failure();
}

#[test]
fn tampered_token_rejected() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    let b_tok = emit_token(b, "me", "grp", &["p0"]);
    // Corrupt one character in the middle
    let mut chars: Vec<char> = b_tok.chars().collect();
    let i = chars.len() / 2;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    let bad: String = chars.into_iter().collect();
    // The wrap key needs our seed, so `create` unlocks before it decodes any
    // peer token: supply the password, or the failure would be the prompt's.
    sesh_pw(a)
        .args([
            "shared-secret",
            "create",
            "grp",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--token",
            &bad,
        ])
        .assert()
        .failure()
        .stderr(contains("Checksum mismatch"));
}

#[test]
fn name_mismatch_token_rejected() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    // B builds a token for a differently-named group
    let b_tok = emit_token(b, "me", "other", &["p0"]);
    sesh_pw(a)
        .args([
            "shared-secret",
            "create",
            "grp",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--token",
            &b_tok,
        ])
        .assert()
        .failure();
}

// hd-secret: owner resolution

#[test]
fn hd_unknown_owner_and_owner_with_apply_rejected() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    sesh(home.path())
        .args(["hd-secret", "ghost", "list"])
        .assert()
        .failure()
        .stderr(contains("no keypair or shared-secret named 'ghost'"));
    // apply identifies its group from the token; an owner is a usage error
    sesh(home.path())
        .args(["hd-secret", "me", "apply", "sometoken"])
        .assert()
        .failure()
        .stderr(contains("takes no owner"));
}

// hd-secret param validation & formatting

#[test]
fn hd_derive_subcommand_is_gone() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    // The ad-hoc `derive` password generator was removed: no fingerprint, no
    // rotation, no inventory. Managed secrets are created, not derived.
    sesh(home.path())
        .args(["hd-secret", "me", "derive", "google.com"])
        .assert()
        .failure();
}

#[test]
fn hd_length_and_suffix_applied() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    // Stored formatting params flow through to the rendered secret
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "x",
            "--mode",
            "hex",
            "--length",
            "12",
            "--suffix",
            "^%",
        ],
    );
    let secret = hd_secret_of(home.path(), "me", "x");
    assert_eq!(secret.len(), 12);
    assert!(secret.ends_with("^%"));
}

#[test]
fn hd_length_out_of_range_is_rejected_up_front() {
    // Regression (was a stored-then-panic): --length is validated against the
    // MODE's maximum at definition time, not bip39's, and never panics later.
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    sesh(home.path())
        .args([
            "hd-secret",
            "me",
            "create",
            "x",
            "--mode",
            "b58",
            "--length",
            "100",
        ])
        .assert()
        .failure()
        .stderr(contains("length can be at most"));
    // Nothing was stored by the failed create
    assert!(run_pw(home.path(), &["hd-secret", "me", "list"]).contains("(no definitions)"));
}

#[test]
fn hd_length_not_exceeding_suffix_is_rejected() {
    // Regression (was a usize-underflow panic in format_secret)
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    sesh(home.path())
        .args([
            "hd-secret",
            "me",
            "create",
            "x",
            "--length",
            "2",
            "--suffix",
            "abc!",
        ])
        .assert()
        .failure()
        .stderr(contains("length must exceed the suffix length"));
}

#[test]
fn hd_stored_max_length_survives_rotation() {
    // Regression (data-dependent panic): b10/b58 renderings vary in length by
    // epoch; a stored maximal --length must format for EVERY epoch (short
    // renderings are left-padded), so rotate can never brick copy/reveal.
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "x",
            "--mode",
            "b10",
            "--length",
            "78",
        ],
    );
    for _ in 0..12 {
        assert_eq!(hd_secret_of(home.path(), "me", "x").len(), 78);
        run_pw(home.path(), &["hd-secret", "me", "rotate", "x"]);
    }
}

// hd-secret: symbol sets

// The b58 base alphabet, for asserting what a rendering may draw from
const B58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// The built-in default symbol set (mirrors `format::SYMBOLS`)
const DEFAULT_SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:;,.?";

// `describe()` prints every param, absent ones included, so a reader can see
// exactly what a password looks like without knowing this build's defaults.
// This is that rendering for a definition created with no formatting flags.
fn default_params_row() -> String {
    format!("--mode b58 --length 14 --symbols='{DEFAULT_SYMBOLS}' --suffix none")
}

// A **deterministic** identity, imported from a fixed mnemonic.
//
// Symbol tests need this: a random seed makes "the set appears in the output" a
// coin toss (with a 2-character set over base58, a 43-character rendering omits
// it entirely about a fifth of the time). Against a fixed seed the rendering is
// a fixed string, so these assertions are facts rather than odds.
fn make_fixed_identity(home: &Path, name: &str) {
    import_mnemonic(home, name, ZERO_MNEMONIC);
}

// A bare `create` produces a memorable recipe (b58, 14 characters, symbols)
// and **stores** it, so nothing is lost by leaving the flags off.
#[test]
fn hd_create_defaults_are_sensible_and_recorded_in_the_params() {
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");
    let created = run_pw(home.path(), &["hd-secret", "me", "create", "google.com"]);
    assert_eq!(field(&created, "Params"), default_params_row());

    let secret = hd_secret_of(home.path(), "me", "google.com");
    assert_eq!(secret.chars().count(), 14);
    assert!(
        secret
            .chars()
            .all(|c| B58_ALPHABET.contains(c) || DEFAULT_SYMBOLS.contains(c)),
        "{secret} must draw from b58 ∪ the default symbol set"
    );

    // The recipe survives a round trip through the registry, so a later change
    // to the built-in defaults cannot alter this password.
    let listed = run_pw(home.path(), &["hd-secret", "me", "list"]);
    assert_eq!(table_cell(&listed, "google.com", 3), default_params_row());
    assert_eq!(hd_secret_of(home.path(), "me", "google.com"), secret);
}

// The `--length` and `--symbols` defaults are per-mode. `hex`/`b58` get the
// 14-char symbol-mixed package; `b10` resolves a 6-digit, digits-only PIN;
// `alpha` and `bip39` get neither.  A defaulted `--symbols` would make a bare
// `--mode bip39` fail on a flag nobody typed, and a defaulted `--length 14`
// would truncate a 24-word mnemonic to 14 characters.
#[test]
fn hd_create_defaults_are_withheld_from_modes_that_take_no_symbol_set() {
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");

    let alpha = run_pw(
        home.path(),
        &["hd-secret", "me", "create", "a", "--mode", "alpha"],
    );
    let bip39 = run_pw(
        home.path(),
        &["hd-secret", "me", "create", "b", "--mode", "bip39"],
    );

    // Full renderings, not 14-character stumps
    let a_len = hd_secret_of(home.path(), "me", "a").chars().count();
    let b_secret = hd_secret_of(home.path(), "me", "b");
    assert!(a_len > 14);
    assert_eq!(b_secret.split_whitespace().count(), 24);

    // `--length none` says there is no trim; the annotation says how long the
    // password actually is, so a reader learns both.
    assert_eq!(
        field(&alpha, "Params"),
        format!("--mode alpha --length none ({a_len} chars) --no-symbols --suffix none")
    );
    assert_eq!(
        field(&bip39, "Params"),
        format!(
            "--mode bip39 --length none ({} chars) --no-symbols --suffix none",
            b_secret.chars().count()
        )
    );

    // hex does get both halves of the symbol-mixed package
    let out = run_pw(
        home.path(),
        &["hd-secret", "me", "create", "h", "--mode", "hex"],
    );
    assert_eq!(
        field(&out, "Params"),
        format!("--mode hex --length 14 --symbols='{DEFAULT_SYMBOLS}' --suffix none")
    );
    assert_eq!(hd_secret_of(home.path(), "me", "h").chars().count(), 14);

    // b10 is the numeric exception: a bare create resolves a 6-digit,
    // digits-only PIN, stored resolved, like every other default.
    let out = run_pw(
        home.path(),
        &["hd-secret", "me", "create", "t", "--mode", "b10"],
    );
    assert_eq!(
        field(&out, "Params"),
        "--mode b10 --length 6 --no-symbols --suffix none"
    );
    let pin = hd_secret_of(home.path(), "me", "t");
    assert_eq!(pin.chars().count(), 6);
    assert!(
        pin.chars().all(|c| c.is_ascii_digit()),
        "not digits-only: {pin}"
    );
}

// `rotate --mode alpha` is an instruction, not a question. The stored symbol
// set has no positional alphabet to extend there, so it is dropped (announced,
// never silent) instead of the tool demanding the user restate the obvious.
#[test]
fn hd_rotate_drops_params_the_new_mode_cannot_render() {
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "x"]); // b58 + 14 + symbols

    let out = sesh_pw(home.path())
        .args(["hd-secret", "me", "rotate", "x", "--mode", "alpha"])
        .assert()
        .success()
        .stderr(contains("Dropped --symbols"));
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_eq!(
        field(&stdout, "Params"),
        "--mode alpha --length 14 --no-symbols --suffix none"
    );

    // bip39 can carry neither a trim nor a suffix; both go, and both are named
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "y", "--suffix", "!!"],
    );
    let out = sesh_pw(home.path())
        .args(["hd-secret", "me", "rotate", "y", "--mode", "bip39"])
        .assert()
        .success()
        .stderr(contains("Dropped --symbols"))
        .stderr(contains("Dropped --length"))
        .stderr(contains("Dropped --suffix"));
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let mnemonic = hd_secret_of(home.path(), "me", "y");
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    assert_eq!(
        field(&stdout, "Params"),
        format!(
            "--mode bip39 --length none ({} chars) --no-symbols --suffix none",
            mnemonic.chars().count()
        )
    );
}

// Asking for a mode and a param that contradict each other is a different
// thing from carrying one over, and stays an error.
#[test]
fn hd_rotate_refuses_a_mode_and_a_symbol_set_together() {
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "x"]);
    sesh_pw(home.path())
        .args([
            "hd-secret",
            "me",
            "rotate",
            "x",
            "--mode",
            "alpha",
            "--symbols",
        ])
        .assert()
        .failure()
        .stderr(contains("hex, b10, b58"));
}

#[test]
fn hd_bare_symbols_equals_spelling_the_default_set_out() {
    // The same seed, the same (id, user, epoch), and two spellings of one set:
    // bare `--symbols` resolves to the default, so the recipes coincide.
    let bare = TempDir::new().unwrap();
    make_fixed_identity(bare.path(), "me");
    run_pw(
        bare.path(),
        &["hd-secret", "me", "create", "x", "--symbols"],
    );

    let spelled = TempDir::new().unwrap();
    make_fixed_identity(spelled.path(), "me");
    run_pw(
        spelled.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "x",
            &format!("--symbols={DEFAULT_SYMBOLS}"),
        ],
    );

    assert_eq!(
        hd_secret_of(bare.path(), "me", "x"),
        hd_secret_of(spelled.path(), "me", "x")
    );

    // Both stored the resolved set, and `list` renders the default one bare
    for home in [bare.path(), spelled.path()] {
        let listed = run_pw(home, &["hd-secret", "me", "list"]);
        assert_eq!(table_cell(&listed, "x", 3), default_params_row());
    }
}

#[test]
fn hd_a_custom_symbol_set_draws_only_from_that_set() {
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "b", "--symbols=!@#$"],
    );
    let secret = hd_secret_of(home.path(), "me", "b");

    assert!(
        secret
            .chars()
            .all(|c| B58_ALPHABET.contains(c) || "!@#$".contains(c)),
        "{secret} drew a character from outside b58 ∪ {{!,@,#,$}}"
    );
    assert!(
        secret.chars().any(|c| "!@#$".contains(c)),
        "the set must appear: {secret}"
    );
    // The stored recipe names the exact alphabet it used
    let listed = run_pw(home.path(), &["hd-secret", "me", "list"]);
    assert_eq!(
        table_cell(&listed, "b", 3),
        "--mode b58 --length 14 --symbols='!@#$' --suffix none"
    );
}

#[test]
fn hd_symbol_set_order_is_load_bearing() {
    // Two sets differing only in order are two different recipes. They coincide
    // for any secret whose digits never land on the reordered slots; and the
    // default 14-character trim is short enough that this fixture's do not, so
    // the untrimmed rendering is what makes the difference observable.
    let render = |set: &str| {
        let home = TempDir::new().unwrap();
        make_fixed_identity(home.path(), "me");
        run_pw(
            home.path(),
            &["hd-secret", "me", "create", "x", set, "--length", "44"],
        );
        (hd_secret_of(home.path(), "me", "x"), home)
    };
    let (forward, _f) = render("--symbols=!@");
    let (reversed, _r) = render("--symbols=@!");
    assert_eq!(forward.len(), 44);
    assert_ne!(forward, reversed);
}

#[test]
fn hd_symbols_rejects_collisions_non_ascii_and_the_empty_set() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    // '1' is base58's zero digit, a collision would stop the rendering being
    // injective.
    sesh(home.path())
        .args(["hd-secret", "me", "create", "x", "--symbols=1"])
        .assert()
        .failure()
        .stderr(contains("already uses"));
    // Non-ASCII is refused cleanly, never a panic deep inside the encoder
    sesh(home.path())
        .args(["hd-secret", "me", "create", "x", "--symbols=£"])
        .assert()
        .failure()
        .stderr(contains("printable ASCII"));
    // `--symbols=` is not `--symbols`: it names the empty set
    sesh(home.path())
        .args(["hd-secret", "me", "create", "x", "--symbols="])
        .assert()
        .failure()
        .stderr(contains("must not be empty"));
    // A repeat inside the set is refused too
    sesh(home.path())
        .args(["hd-secret", "me", "create", "x", "--symbols=!!"])
        .assert()
        .failure()
        .stderr(contains("repeats"));
    // ...and `--symbols` on a non-positional mode still errors, as before
    sesh(home.path())
        .args([
            "hd-secret",
            "me",
            "create",
            "x",
            "--mode",
            "alpha",
            "--symbols",
        ])
        .assert()
        .failure()
        .stderr(contains("hex, b10, b58"));
    sesh(home.path())
        .args([
            "hd-secret",
            "me",
            "create",
            "x",
            "--mode",
            "bip39",
            "--symbols",
        ])
        .assert()
        .failure();
    assert!(run_pw(home.path(), &["hd-secret", "me", "list"]).contains("(no definitions)"));
}

#[test]
fn hd_symbols_may_hold_characters_the_mode_omits() {
    // Accepted deliberately: the rule is disjointness, not punctuation.
    // `--symbols` is really `--alphabet-extra`.
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");
    // The four characters base58 omits to avoid visual confusion
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "a", "--symbols=0OIl"],
    );
    // hex's base alphabet is lowercase, so the uppercase digits are free
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "b",
            "--mode",
            "hex",
            "--symbols=ABCDEF",
        ],
    );
    // ...and a quote is a legal password character; `describe()` gets no vote
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "c", "--symbols='"],
    );
    for id in ["a", "b", "c"] {
        assert!(!hd_secret_of(home.path(), "me", id).is_empty());
    }
}

#[test]
fn hd_symbols_with_hex_loses_the_0x_prefix() {
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");
    // `--symbols` is on by default under hex, so the plain rendering needs an
    // explicit opt-out to get its `0x` back.
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "plain",
            "--mode",
            "hex",
            "--no-symbols",
        ],
    );
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "mixed",
            "--mode",
            "hex",
            "--symbols",
        ],
    );
    assert!(hd_secret_of(home.path(), "me", "plain").starts_with("0x"));
    assert!(!hd_secret_of(home.path(), "me", "mixed").starts_with("0x"));
}

#[test]
fn hd_mode_override_rejects_a_set_that_collides_with_the_overridden_alphabet() {
    // `--mode` on copy/reveal is a display-only override that bypasses the
    // stored, already-validated params. 'a' is legal under b10, and a hex digit.
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "x",
            "--mode",
            "b10",
            "--symbols=a",
        ],
    );
    assert!(!hd_secret_of(home.path(), "me", "x").is_empty());

    let clip = home.path().join("clip.txt");
    sesh_pw(home.path())
        .env("SESH_CLIPBOARD_CMD", format!("cat > {}", clip.display()))
        .args(["hd-secret", "me", "copy", "x", "--mode", "hex"])
        .assert()
        .failure()
        .stderr(contains("drop the --mode override"));
}

#[test]
fn hd_rotate_switches_the_symbol_set_and_no_symbols_clears_it() {
    let home = TempDir::new().unwrap();
    make_fixed_identity(home.path(), "me");
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "x", "--symbols=!@"],
    );

    // A different set is a different alphabet, hence a different rendering
    let swapped = run_pw(
        home.path(),
        &["hd-secret", "me", "rotate", "x", "--symbols=#$"],
    );
    assert_eq!(
        field(&swapped, "Params"),
        "--mode b58 --length 14 --symbols='#$' --suffix none"
    );
    let after = hd_secret_of(home.path(), "me", "x");
    assert!(after
        .chars()
        .all(|c| B58_ALPHABET.contains(c) || "#$".contains(c)));

    // --no-symbols clears it entirely
    let cleared = run_pw(
        home.path(),
        &["hd-secret", "me", "rotate", "x", "--no-symbols"],
    );
    assert_eq!(
        field(&cleared, "Params"),
        "--mode b58 --length 14 --no-symbols --suffix none"
    );
    assert!(hd_secret_of(home.path(), "me", "x")
        .chars()
        .all(|c| B58_ALPHABET.contains(c)));
}

// hd-secret registry

// Complete a 2-party group named `group` between homes `a` and `b` (already
// wired as each other's contacts `p1`/`p0`).
fn form_group(a: &Path, b: &Path, group: &str) {
    let a_tok = emit_token(a, "me", group, &["p1"]);
    let b_tok = emit_token(b, "me", group, &["p0"]);
    run_pw(
        a,
        &[
            "shared-secret",
            "create",
            group,
            "--keypair",
            "me",
            "--party",
            "p1",
            "--token",
            &b_tok,
        ],
    );
    run_pw(
        b,
        &[
            "shared-secret",
            "create",
            group,
            "--keypair",
            "me",
            "--party",
            "p0",
            "--token",
            &a_tok,
        ],
    );
}

#[test]
fn registry_create_show_list_roundtrip() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");

    // create prints details + fingerprint, never the secret
    let created = run_pw(home.path(), &["hd-secret", "me", "create", "google.com"]);
    assert_eq!(field(&created, "Epoch"), "1");
    let fpr = field(&created, "Fingerprint");
    assert!(!fpr.is_empty());
    assert!(field(&created, "Secret").contains("derived on demand"));

    // show repeats the same details
    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "google.com"]);
    assert_eq!(created, shown);

    // copy/reveal re-derive the secret from the stored epoch + params; create
    // itself never prints it.
    let secret = hd_secret_of(home.path(), "me", "google.com");
    assert!(!secret.is_empty());
    assert!(!created.contains(&secret));

    // list says whose registry it is, then the table (fingerprint right of
    // params), never secrets.
    let listed = run_pw(home.path(), &["hd-secret", "me", "list"]);
    assert!(listed.starts_with("Personal: me\n"));
    assert_eq!(table_cell(&listed, "google.com", 2), "1");
    assert_eq!(table_cell(&listed, "google.com", 3), default_params_row());
    assert_eq!(table_cell(&listed, "google.com", 4), fpr);
    assert!(!listed.contains(&secret));

    // A duplicate create errors (use rotate to change it)
    sesh_pw(home.path())
        .args(["hd-secret", "me", "create", "google.com"])
        .assert()
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn registry_empty_list_placeholder() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    assert!(run_pw(home.path(), &["hd-secret", "me", "list"]).contains("(no definitions)"));
}

#[test]
fn hd_bare_owner_shows_help() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    // A bare owner is not a command, the family help is shown instead
    let assert = sesh(home.path())
        .args(["hd-secret", "me"])
        .assert()
        .failure();
    let out = assert.get_output();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(all.contains("USAGE"), "expected help output:\n{all}");
    assert!(
        all.contains("list"),
        "help should mention the list subcommand:\n{all}"
    );
}

#[test]
fn registry_encrypted_at_rest() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "supersecretlabel",
            "hiddenuser",
            "--suffix",
            "!Zq",
        ],
    );
    let raw = std::fs::read(home.path().join("keypairs/me/registry")).unwrap();
    let raw_str = String::from_utf8_lossy(&raw);
    // Neither the id, the user, nor the params appear in plaintext on disk
    assert!(!raw_str.contains("supersecretlabel"));
    assert!(!raw_str.contains("hiddenuser"));
    assert!(!raw_str.contains("!Zq"));
}

#[test]
fn registry_rotate_is_monotonic_and_changes_secret() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "x"]);
    let v1 = hd_secret_of(home.path(), "me", "x");

    // rotate prints the summary (no secret) and the confirmation
    let v2 = run_pw(home.path(), &["hd-secret", "me", "rotate", "x"]);
    assert!(v2.contains("Rotated to epoch 2"));
    assert_eq!(field(&v2, "Epoch"), "2");
    assert!(!v2.contains(&v1), "rotate must never print the secret");
    assert_ne!(v1, hd_secret_of(home.path(), "me", "x"));

    // An explicit epoch must strictly exceed the current one
    for epoch in ["2", "1"] {
        sesh_pw(home.path())
            .args(["hd-secret", "me", "rotate", "x", "--epoch", epoch])
            .assert()
            .failure()
            .stderr(contains("Epoch must strictly increase"));
    }
    let v10 = run_pw(
        home.path(),
        &["hd-secret", "me", "rotate", "x", "--epoch", "10"],
    );
    assert!(v10.contains("Rotated to epoch 10"));

    // show reflects the latest epoch
    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "x"]);
    assert_eq!(field(&shown, "Epoch"), "10");
    assert_eq!(field(&v10, "Fingerprint"), field(&shown, "Fingerprint"));
}

#[test]
fn hd_rotate_dry_run_changes_nothing() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "x"]); // epoch 1
    let secret = hd_secret_of(home.path(), "me", "x");

    // The dry run previews epoch 2 (and merged params) without storing
    let dry = run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "rotate",
            "x",
            "--dry-run",
            "--mode",
            "hex",
        ],
    );
    assert_eq!(field(&dry, "Epoch"), "2");
    assert_eq!(
        field(&dry, "Params"),
        format!("--mode hex --length 14 --symbols='{DEFAULT_SYMBOLS}' --suffix none")
    );
    assert!(dry.contains("dry run, keystore unchanged"));

    // The stored entry is untouched: still epoch 1, b58, same secret
    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "x"]);
    assert_eq!(field(&shown, "Epoch"), "1");
    assert_eq!(hd_secret_of(home.path(), "me", "x"), secret);
    let listed = run_pw(home.path(), &["hd-secret", "me", "list"]);
    assert_eq!(table_cell(&listed, "x", 3), default_params_row());

    // Group scope: the dry run also previews the share token, still unstored
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    run_pw(a, &["hd-secret", "grp", "create", "vpn"]);
    let dry = run_pw(a, &["hd-secret", "grp", "rotate", "vpn", "--dry-run"]);
    assert!(!field(&dry, "Share token").is_empty());
    assert_eq!(
        field(&run_pw(a, &["hd-secret", "grp", "show", "vpn"]), "Epoch"),
        "1"
    );
}

#[test]
fn registry_remove_tombstones_and_revive_advances_epoch() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "x"]); // epoch 1
    run_pw(home.path(), &["hd-secret", "me", "remove", "x"]); // tombstone epoch 2

    let listed = run_pw(home.path(), &["hd-secret", "me", "list"]);
    assert!(listed.contains("(no definitions)"));
    sesh_pw(home.path())
        .args(["hd-secret", "me", "show", "x"])
        .assert()
        .failure()
        .stderr(contains("No stored definition"));

    // Re-creating revives strictly above the tombstone epoch
    let revived = run_pw(home.path(), &["hd-secret", "me", "create", "x"]);
    assert_eq!(field(&revived, "Epoch"), "3");
}

// hd-secret: show / copy / reveal triad

#[test]
fn hd_show_hides_the_secret_and_dump_is_gone() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    let created = run_pw(home.path(), &["hd-secret", "me", "create", "site"]);
    let secret = hd_secret_of(home.path(), "me", "site");

    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "site"]);
    for out in [&created, &shown] {
        assert!(
            !out.contains(&secret),
            "create/show must never print the secret"
        );
        assert!(!field(out, "Fingerprint").is_empty());
        assert!(field(out, "Secret").contains("derived on demand"));
    }

    // dump no longer exists in this family
    sesh(home.path())
        .args(["hd-secret", "me", "dump", "site"])
        .assert()
        .failure();
}

#[test]
fn hd_reveal_is_tty_only_and_never_writes_to_stdout() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "site", "bob"]);
    let secret = hd_secret_of(home.path(), "me", "site");

    // reveal is structurally TTY-only: with piped stdin/stdout (as in tests) it
    // refuses outright, so it can never silently behave like the old `export`.
    // Nothing of the secret leaks to stdout on the refusal path.
    let assert = sesh(home.path())
        .args(["hd-secret", "me", "reveal", "site"])
        .assert()
        .failure()
        .stderr(contains("interactive terminal"));
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains(&secret),
        "reveal must never write the secret to stdout"
    );

    // The metadata is still reachable via `show` (never the secret)
    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "site"]);
    assert_eq!(field(&shown, "Id"), "site");
    assert_eq!(field(&shown, "User"), "bob");
    assert_eq!(field(&shown, "Epoch"), "1");
    assert!(!shown.contains(&secret));
}

#[test]
fn hd_copy_uses_clipboard_and_never_echoes() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "site"]);
    let secret = hd_secret_of(home.path(), "me", "site");

    let clip = home.path().join("clip.txt");
    let out = sesh_pw(home.path())
        .env("SESH_CLIPBOARD_CMD", format!("cat > {}", clip.display()))
        .args(["hd-secret", "me", "copy", "site"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Copied HD secret 'site' (epoch 1) to the clipboard."));
    assert!(!stdout.contains(&secret), "copy must never echo the secret");
    assert_eq!(std::fs::read_to_string(&clip).unwrap(), secret);
}

#[test]
fn hd_copy_fails_cleanly_when_clipboard_tool_fails() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "site"]);
    // The password is supplied, so the failure can only be the clipboard's
    sesh_pw(home.path())
        .env("SESH_CLIPBOARD_CMD", "exit 1")
        .args(["hd-secret", "me", "copy", "site"])
        .assert()
        .failure()
        .stderr(contains("clipboard"));
}

#[test]
fn hd_mode_override_is_display_only() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "site"]); // stored: b58
    let b58 = hd_secret_of(home.path(), "me", "site");
    let fpr = field(
        &run_pw(home.path(), &["hd-secret", "me", "show", "site"]),
        "Fingerprint",
    );

    // The override applies to copy (and reveal): hex differs from stored b58.
    // The stored symbol set rides along, so the hex rendering has no `0x`. The
    // override changes the base alphabet, not the recipe.
    let clip = home.path().join("clip.txt");
    sesh_pw(home.path())
        .env("SESH_CLIPBOARD_CMD", format!("cat > {}", clip.display()))
        .args(["hd-secret", "me", "copy", "site", "--mode", "hex"])
        .assert()
        .success();
    let hex = std::fs::read_to_string(&clip).unwrap();
    assert_ne!(hex, b58);
    assert_eq!(hex.chars().count(), 14, "the stored --length still applies");
    assert!(
        hex.chars()
            .all(|c| "0123456789abcdef".contains(c) || DEFAULT_SYMBOLS.contains(c)),
        "{hex} must draw from hex ∪ the stored symbol set"
    );

    // ...but is never persisted: stored params still say b58, the fingerprint
    // (over the raw child, not its encoding) is unchanged, and a plain copy
    // still yields b58.
    let listed = run_pw(home.path(), &["hd-secret", "me", "list"]);
    assert_eq!(table_cell(&listed, "site", 3), default_params_row());
    assert_eq!(table_cell(&listed, "site", 4), fpr);
    assert_eq!(hd_secret_of(home.path(), "me", "site"), b58);
}

// hd-secret: group scope

#[test]
fn registry_group_scope_members_agree() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // Both members create the same definition independently -> same secret
    // (same K, same (id, user, epoch)) and the same fingerprint, straight
    // from create's output, proving the derivation is member-independent.
    let a_created = run_pw(a, &["hd-secret", "grp", "create", "vpn"]);
    let b_created = run_pw(b, &["hd-secret", "grp", "create", "vpn"]);
    assert_eq!(
        field(&a_created, "Fingerprint"),
        field(&b_created, "Fingerprint")
    );
    // A group-owned create leads with the Group row and emits the share token
    assert_eq!(field(&a_created, "Group"), "grp");
    assert!(!field(&a_created, "Share token").is_empty());
    let a_secret = hd_secret_of(a, "grp", "vpn");
    let b_secret = hd_secret_of(b, "grp", "vpn");
    assert_eq!(a_secret, b_secret);

    // A personal entry with the same (id, epoch) derives under s_dh, not K
    let personal = run_pw(a, &["hd-secret", "me", "create", "vpn"]);
    assert_ne!(
        field(&personal, "Fingerprint"),
        field(&a_created, "Fingerprint")
    );

    // list headers name the owner kind, and show leads with the Group row for
    // group-owned entries (absent for personal ones).
    let group_list = run_pw(a, &["hd-secret", "grp", "list"]);
    assert!(group_list.starts_with("Group: grp\n"));
    assert_eq!(
        field(&run_pw(a, &["hd-secret", "grp", "show", "vpn"]), "Group"),
        "grp"
    );
    assert!(!run_pw(a, &["hd-secret", "me", "show", "vpn"]).contains("Group:"));
}

#[test]
fn registry_share_reshares_stored_entry() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    run_pw(a, &["hd-secret", "grp", "create", "wifi"]);
    let secret = hd_secret_of(a, "grp", "wifi");
    let shared = run_pw(a, &["hd-secret", "grp", "share", "wifi"]);
    // Fingerprint + share token only, never the secret
    assert_eq!(shared.lines().count(), 2);
    assert!(!field(&shared, "Share token").is_empty());
    assert!(!shared.contains(&secret));
    // The fingerprint matches show's, and the shared token round-trips
    let shown = run_pw(a, &["hd-secret", "grp", "show", "wifi"]);
    assert_eq!(field(&shared, "Fingerprint"), field(&shown, "Fingerprint"));
    let applied = apply_ok(b, &field(&shared, "Share token"), "y\n");
    assert!(applied.contains("Applied NEW"));

    // share errors if the entry is not stored
    sesh_pw(a)
        .args(["hd-secret", "grp", "share", "ghost"])
        .assert()
        .failure()
        .stderr(contains("No stored definition"));
    // share is group-only: personal definitions are local-only
    run_pw(a, &["hd-secret", "me", "create", "wifi"]);
    sesh_pw(a)
        .args(["hd-secret", "me", "share", "wifi"])
        .assert()
        .failure()
        .stderr(contains("local-only"));
}

#[test]
fn registry_user_disambiguates_and_is_required_when_ambiguous() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    let one = run_pw(home.path(), &["hd-secret", "me", "create", "x", "alice"]);
    let two = run_pw(home.path(), &["hd-secret", "me", "create", "x", "bob"]);
    assert_ne!(field(&one, "Fingerprint"), field(&two, "Fingerprint"));

    // Ambiguous without a user
    sesh_pw(home.path())
        .args(["hd-secret", "me", "show", "x"])
        .assert()
        .failure()
        .stderr(contains("matches multiple entries"));
    // Disambiguated by user: show matches create's fingerprint, and copy
    // (with the user) yields a non-empty secret.
    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "x", "alice"]);
    assert_eq!(field(&one, "Fingerprint"), field(&shown, "Fingerprint"));
    let clip = home.path().join("clip.txt");
    sesh_pw(home.path())
        .env("SESH_CLIPBOARD_CMD", format!("cat > {}", clip.display()))
        .args(["hd-secret", "me", "copy", "x", "alice"])
        .assert()
        .success();
    assert!(!std::fs::read_to_string(&clip).unwrap().is_empty());
}

// hd-secret registry sync (apply)

// Run `hd-secret apply` with piped stdin answers; assert success; return stdout.
// `apply` unlocks the group's keypair before it prompts, so the password comes
// first and `answers` supplies whatever the diff or conflict prompt asks for.
fn apply_ok(home: &Path, token: &str, answers: &str) -> String {
    let out = sesh(home)
        .args(["hd-secret", "apply", token])
        .write_stdin(format!("{PW}\n{answers}"))
        .assert()
        .success();
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

// The share token for a stored group definition (via `hd-secret ... share`)
fn share_token(home: &Path, group: &str, id: &str) -> String {
    field(
        &run_pw(home, &["hd-secret", group, "share", id]),
        "Share token",
    )
}

// The rendered secret of a stored definition, captured through the `copy`
// clipboard seam (`SESH_CLIPBOARD_CMD`). This is the stable, non-TTY way to
// observe secret content: `reveal` is TTY-only by design, and the clipboard
// tool receives exactly the secret bytes on stdin.
fn hd_secret_of(home: &Path, owner: &str, id: &str) -> String {
    let clip = home.join(format!(".clip-{owner}-{id}"));
    copy_secret(home, &clip, &["hd-secret", owner, "copy", id])
}

#[test]
fn apply_syncs_create_and_rotate_between_members() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // A creates and shares; B applies the token -> both derive the same secret.
    // A brand-new entry shows the summary but no change block.
    run_pw(a, &["hd-secret", "grp", "create", "vpn"]);
    let a_before = hd_secret_of(a, "grp", "vpn");
    let applied = apply_ok(b, &share_token(a, "grp", "vpn"), "y\n");
    assert!(applied.contains("Applied NEW"));
    assert_eq!(field(&applied, "Group"), "grp");
    assert!(!applied.contains("Rotated:"));
    assert_eq!(a_before, hd_secret_of(b, "grp", "vpn"));

    // B rotates (new params); A applies -> both converge. The apply shows the
    // change block with only the fields that differ.
    let rotated = run_pw(b, &["hd-secret", "grp", "rotate", "vpn", "--mode", "hex"]);
    assert_eq!(field(&rotated, "Group"), "grp");
    let tok2 = field(&rotated, "Share token");
    let applied = apply_ok(a, &tok2, "y\n");
    assert!(applied.contains("Applied UPDATE"));
    assert!(applied.contains("Rotated:"));
    assert!(
        applied.contains("epoch:  1 → 2"),
        "missing epoch diff:\n{applied}"
    );
    assert!(
        applied.contains("mode:   b58 → hex"),
        "missing mode diff:\n{applied}"
    );
    assert!(
        !applied.contains("suffix:"),
        "unchanged fields must not appear:\n{applied}"
    );
    let a_after = hd_secret_of(a, "grp", "vpn");
    assert_eq!(hd_secret_of(b, "grp", "vpn"), a_after);
    assert_ne!(a_before, a_after);
}

#[test]
fn apply_carries_a_custom_symbol_set_across_the_group() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // A signed share token carries the set verbatim; B renders the same string
    run_pw(a, &["hd-secret", "grp", "create", "vpn", "--symbols=!@#$"]);
    let a_secret = hd_secret_of(a, "grp", "vpn");
    let applied = apply_ok(b, &share_token(a, "grp", "vpn"), "y\n");
    assert!(applied.contains("Applied NEW"));
    assert_eq!(a_secret, hd_secret_of(b, "grp", "vpn"));
    assert_eq!(
        table_cell(&run_pw(b, &["hd-secret", "grp", "list"]), "vpn", 3),
        "--mode b58 --length 14 --symbols='!@#$' --suffix none"
    );

    // The `apply` diff prints the sets verbatim. It is the surface on which a
    // we tells two sets apart, so it must never collapse them to yes/no.
    let rotated = run_pw(a, &["hd-secret", "grp", "rotate", "vpn", "--symbols=%^"]);
    let diff = apply_ok(b, &field(&rotated, "Share token"), "y\n");
    assert!(
        diff.contains("symbols: \"!@#$\" → \"%^\""),
        "missing symbols diff:\n{diff}"
    );
    assert_eq!(hd_secret_of(a, "grp", "vpn"), hd_secret_of(b, "grp", "vpn"));
}

#[test]
fn apply_rejects_member_signed_token_with_invalid_params() {
    // Regression: a share token is member-signed, not member-trusted. A token
    // carrying params the CLI would never accept (unknown mode) must be
    // rejected cleanly at apply, not adopted, and never a panic.
    use sesh::crypto::share_wrap_key;
    use sesh::keystore::Keystore;
    use sesh::protocol::{group_ctx, Purpose, ShareAction, ShareToken};
    use sesh::registry::Params;

    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // Forge the token as member B, using B's real (unencrypted) seed. The token
    // is sealed under the group's real K (which B can reconstruct), so it opens
    // on A. The params gate, not decryption, is what must reject it.
    let ks_b = Keystore::open(b);
    let seed = ks_b.load_seed("me", PW).unwrap();
    let state = ks_b.load_shared_secret("grp").unwrap();
    let members = vec![
        ks_b.load_public_identity("me").unwrap(),
        ks_b.load_contact(&state.members[0]).unwrap(),
    ];
    let ctx = group_ctx(Purpose::Master, "grp", &members).unwrap();
    let k = ks_b.reconstruct_shared_secret(&state, &seed).unwrap();
    let evil = ShareToken::create(
        &seed,
        &ctx,
        ShareAction::New,
        "vpn",
        "",
        1,
        Params {
            mode: "evil".into(),
            length: None,
            symbols: None,
            suffix: None,
        },
    )
    .unwrap();

    sesh_pw(a)
        .args([
            "hd-secret",
            "apply",
            &evil.encode(&share_wrap_key(&k)).unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("share token carries invalid params"));
    // Nothing was adopted
    assert!(run_pw(a, &["hd-secret", "grp", "list"]).contains("(no definitions)"));
}

#[test]
fn create_with_existing_group_name_fails_fast() {
    // A create whose name is already taken must fail *immediately* (before any
    // token is even required) not after running the whole exchange.
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // No --token supplied at all: the duplicate is caught up front (the wizard
    // path, forced here) rather than reaching a token prompt.
    sesh(a)
        .args([
            "shared-secret",
            "create",
            "grp",
            "--keypair",
            "me",
            "--party",
            "p1",
            "--wizard",
        ])
        .assert()
        .failure()
        .stderr(contains("already exists"));

    // The stored group is untouched
    assert!(run_ok(a, &["shared-secret", "show", "grp"]).contains("grp"));
    let _ = b;
}

#[test]
fn apply_ignores_already_applied_and_stale() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    run_pw(a, &["hd-secret", "grp", "create", "x"]);
    let tok1 = share_token(a, "grp", "x");
    apply_ok(b, &tok1, "y\n");
    // Re-applying the same token is a no-op (no prompt needed)
    assert!(apply_ok(b, &tok1, "").contains("Already up to date"));

    // After adopting a rotation, the original token is stale
    let rotated = run_pw(a, &["hd-secret", "grp", "rotate", "x"]);
    apply_ok(b, &field(&rotated, "Share token"), "y\n");
    assert!(apply_ok(b, &tok1, "").contains("Ignored stale change"));
}

#[test]
fn apply_declined_leaves_registry_unchanged() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    run_pw(a, &["hd-secret", "grp", "create", "x"]);
    let tok = share_token(a, "grp", "x");
    // Declining the Y/N prompt fails and stores nothing
    sesh(b)
        .args(["hd-secret", "apply", &tok])
        .write_stdin(format!("{PW}\nn\n"))
        .assert()
        .failure();
    sesh_pw(b)
        .args(["hd-secret", "grp", "show", "x"])
        .assert()
        .failure()
        .stderr(contains("No stored definition"));
}

#[test]
fn apply_same_epoch_conflict_prompts_keep_or_use() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // Concurrent creates of the same (id, user) with different params -> both
    // at epoch 1 with different content (same raw child, different rendering).
    run_pw(a, &["hd-secret", "grp", "create", "x", "--mode", "b58"]);
    run_pw(b, &["hd-secret", "grp", "create", "x", "--mode", "hex"]);
    let a_secret = hd_secret_of(a, "grp", "x");
    let b_secret = hd_secret_of(b, "grp", "x");
    assert_ne!(a_secret, b_secret);
    let a_tok = share_token(a, "grp", "x");

    // [k] keeps B's own version
    let kept = apply_ok(b, &a_tok, "k\n");
    assert!(kept.contains("Kept your version"));
    assert_eq!(b_secret, hd_secret_of(b, "grp", "x"));

    // [u] adopts A's version
    let used = apply_ok(b, &a_tok, "u\n");
    assert!(used.contains("Adopted the incoming version"));
    assert_eq!(a_secret, hd_secret_of(b, "grp", "x"));

    // [a] aborts with a failure exit (B now agrees with A, so make a fresh
    // conflict by rotating both sides independently to the same next epoch).
    let a_rot = run_pw(a, &["hd-secret", "grp", "rotate", "x", "--mode", "b58"]);
    // Rotating into alpha drops the carried symbol set (announced on stderr)
    run_pw(b, &["hd-secret", "grp", "rotate", "x", "--mode", "alpha"]);
    sesh(b)
        .args(["hd-secret", "apply", &field(&a_rot, "Share token")])
        .write_stdin(format!("{PW}\na\n"))
        .assert()
        .failure();
}

// The same-epoch conflict branch must show only what `show` shows. `apply`
// has none of `reveal`'s guards (TTY check, alt screen, countdown, wipe), so a
// rendered secret here would leak into scrollback and CI logs. Nothing is lost
// by withholding it: both sides share one child scalar, so their fingerprints
// match and the params carry the entire difference.
#[test]
fn apply_conflict_shows_metadata_only_never_the_secret() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    run_pw(a, &["hd-secret", "grp", "create", "x", "--mode", "b58"]);
    run_pw(b, &["hd-secret", "grp", "create", "x", "--mode", "hex"]);
    let a_secret = hd_secret_of(a, "grp", "x");
    let b_secret = hd_secret_of(b, "grp", "x");
    assert_ne!(a_secret, b_secret);
    let a_tok = share_token(a, "grp", "x");

    // Abort, so the conflict block is printed but the registry is untouched
    let out = sesh(b)
        .args(["hd-secret", "apply", &a_tok])
        .write_stdin(format!("{PW}\na\n"))
        .assert()
        .failure();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();

    // Neither side's secret may appear on either stream
    for secret in [a_secret.trim(), b_secret.trim()] {
        assert!(
            !secret.is_empty(),
            "test needs a non-empty secret to search for"
        );
        assert!(
            !stderr.contains(secret),
            "conflict leaked a secret on stderr:\n{stderr}"
        );
        assert!(
            !stdout.contains(secret),
            "conflict leaked a secret on stdout:\n{stdout}"
        );
    }

    // ...but both `show` blocks are there, and the params (the whole of the
    // difference) distinguish them: local is hex, incoming is b58.
    assert!(stderr.contains("yours:"), "missing local block:\n{stderr}");
    assert!(
        stderr.contains("incoming:"),
        "missing incoming block:\n{stderr}"
    );
    assert!(
        stderr.contains("Fingerprint"),
        "missing fingerprint:\n{stderr}"
    );
    assert!(
        stderr.contains("--mode hex"),
        "missing local params:\n{stderr}"
    );
    assert!(
        stderr.contains("--mode b58"),
        "missing incoming params:\n{stderr}"
    );
}

#[test]
fn apply_remove_tombstone_blocks_stale_create() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    run_pw(a, &["hd-secret", "grp", "create", "x"]);
    let create_tok = share_token(a, "grp", "x");
    apply_ok(b, &create_tok, "y\n");

    // A removes; B applies the tombstone
    let removed = run_pw(a, &["hd-secret", "grp", "remove", "x"]);
    let applied = apply_ok(b, &field(&removed, "Share token"), "y\n");
    assert!(applied.contains("Applied REMOVE"));

    // A tombstone is not a definition. Its `params` are the ones that were live
    // one epoch back, so printing them (or a fingerprint over them, or a
    // "derived on demand" secret) would advertise a recipe for an entry that
    // is being deleted. It says what it is instead.
    assert!(applied.contains("Entry:"), "{applied}");
    assert!(applied.contains("(removed, epoch 2)"), "{applied}");
    for advertised in ["Params:", "Fingerprint:", "Secret:"] {
        assert!(
            !applied.contains(advertised),
            "a removal advertised {advertised}\n{applied}"
        );
    }
    sesh_pw(b)
        .args(["hd-secret", "grp", "show", "x"])
        .assert()
        .failure()
        .stderr(contains("No stored definition"));

    // Replaying the original (stale) create cannot resurrect the entry
    assert!(apply_ok(b, &create_tok, "").contains("Ignored stale change"));
    let listed = run_pw(b, &["hd-secret", "grp", "list"]);
    assert!(listed.contains("(no definitions)"));
}

#[test]
fn apply_rejects_token_for_unknown_group() {
    // a↔b form "grp"; a↔c form "other". A token for "grp" matches nothing on
    // C's keystore (its members/context are not pinned there as a group).
    let homes = wire_group(&["a", "b", "c"]);
    let (a, b, c) = (homes[0].path(), homes[1].path(), homes[2].path());
    form_group(a, b, "grp");
    let a_tok = emit_token(a, "me", "other", &["p2"]);
    let c_tok = emit_token(c, "me", "other", &["p0"]);
    run_pw(
        a,
        &[
            "shared-secret",
            "create",
            "other",
            "--keypair",
            "me",
            "--party",
            "p2",
            "--token",
            &c_tok,
        ],
    );
    run_pw(
        c,
        &[
            "shared-secret",
            "create",
            "other",
            "--keypair",
            "me",
            "--party",
            "p0",
            "--token",
            &a_tok,
        ],
    );

    run_pw(a, &["hd-secret", "grp", "create", "x"]);
    let tok = share_token(a, "grp", "x");
    sesh(c)
        .args(["hd-secret", "apply", &tok])
        .assert()
        .failure();
    // A corrupted token fails the integrity checksum outright
    let mut chars: Vec<char> = tok.chars().collect();
    let i = chars.len() / 2;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    let bad: String = chars.into_iter().collect();
    sesh(b)
        .args(["hd-secret", "apply", &bad])
        .assert()
        .failure();
}

// encrypted identity

#[test]
fn encrypted_identity_password_roundtrip() {
    let home = TempDir::new().unwrap();
    sesh(home.path())
        .args(["keypair", "create", "me"])
        .write_stdin("s3cret\ns3cret\n")
        .assert()
        .success();
    // show needs no password (and reports the seed as encrypted)
    let shown = run_ok(home.path(), &["keypair", "show", "me"]);
    assert!(field(&shown, "Private key").contains("encrypted"));
    // hd-secret create needs the password to unlock the seed (piped once)
    let good = sesh(home.path())
        .args(["hd-secret", "me", "create", "x"])
        .write_stdin("s3cret\n")
        .assert()
        .success();
    assert!(!String::from_utf8(good.get_output().stdout.clone())
        .unwrap()
        .is_empty());
    // Wrong password fails
    sesh(home.path())
        .args(["hd-secret", "me", "show", "x"])
        .write_stdin("wrong\n")
        .assert()
        .failure();
}

// `--mnemonic` takes no value, so `keypair create --mnemonic "<24 words>"`
// slides the phrase into the `<name>` positional, where it would become a
// directory name on disk, in the clear. No stdin here: the guard must fire
// before the mnemonic and password prompts, and must not echo the phrase.
#[test]
fn a_mnemonic_phrase_passed_as_an_argument_is_refused_and_never_echoed() {
    let home = TempDir::new().unwrap();
    let assert = sesh(home.path())
        .args(["keypair", "create", "--mnemonic", ZERO_MNEMONIC])
        .assert()
        .failure()
        .stderr(contains("takes no value"))
        .stderr(contains("abandon").not());
    // Not one prompt was reached
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.contains("BIP39 mnemonic:"),
        "prompted anyway:\n{stderr}"
    );
    assert!(
        !stderr.contains("Set keystore password"),
        "prompted anyway:\n{stderr}"
    );
    // And nothing whatsoever reached the disk
    assert!(!home.path().join("keypairs").exists());
    assert!(!home.path().join("config.toml").exists());

    // The correct spelling still works
    import_mnemonic(home.path(), "Tom", ZERO_MNEMONIC);
    assert!(home.path().join("keypairs/Tom/identity").is_file());
}

#[test]
fn a_whitespace_keypair_name_is_refused_without_echoing_it() {
    let home = TempDir::new().unwrap();
    sesh(home.path())
        .args(["keypair", "create", "two words"])
        .assert()
        .failure()
        .stderr(contains("whitespace"))
        .stderr(contains("two words").not());
    assert!(!home.path().join("keypairs").exists());
}

// keypair mnemonic recovery (BIP39)

// The canonical all-zeros-entropy 24-word BIP39 test vector (checksum "art")
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon art";

// The all-ones-entropy 24-word BIP39 test vector (checksum "vote")
const ONES_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
    zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

// Import identity `name` from `mnemonic` into `home` under [`PW`]; return the
// `keypair create` output block. The mnemonic is prompted for first, then the
// new keystore password twice.
fn import_mnemonic(home: &Path, name: &str, mnemonic: &str) -> String {
    let out = sesh(home)
        .args(["keypair", "create", name, "--mnemonic"])
        .write_stdin(format!("{mnemonic}\n{}", pw_lines()))
        .assert()
        .success();
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

#[test]
fn keypair_mnemonic_import_is_deterministic() {
    let h1 = TempDir::new().unwrap();
    let h2 = TempDir::new().unwrap();
    let h3 = TempDir::new().unwrap();
    let h4 = TempDir::new().unwrap();
    // The same mnemonic under the same name yields the same public identity
    // (fingerprint AND contact token) in two fresh keystores.
    let a = import_mnemonic(h1.path(), "me", ZERO_MNEMONIC);
    let b = import_mnemonic(h2.path(), "me", ZERO_MNEMONIC);
    assert_eq!(field(&a, "Fingerprint"), field(&b, "Fingerprint"));
    assert_eq!(field(&a, "Contact token"), field(&b, "Contact token"));

    // The fingerprint is name-independent: importing under a different local
    // name reproduces the same identity fingerprint.
    let named = import_mnemonic(h3.path(), "other", ZERO_MNEMONIC);
    assert_eq!(field(&a, "Fingerprint"), field(&named, "Fingerprint"));

    // A different mnemonic gives a different identity
    let c = import_mnemonic(h4.path(), "me", ONES_MNEMONIC);
    assert_ne!(field(&a, "Fingerprint"), field(&c, "Fingerprint"));
}

#[test]
fn keypair_mnemonic_recovers_keypair_owned_hd_secrets() {
    // The recovery story: mnemonic -> keypair -> the same keypair-owned
    // hd-secret, reproduced by recreating the definition with the same params.
    let h1 = TempDir::new().unwrap();
    import_mnemonic(h1.path(), "me", ZERO_MNEMONIC);
    run_pw(
        h1.path(),
        &["hd-secret", "me", "create", "google.com", "--length", "16"],
    );
    let s1 = hd_secret_of(h1.path(), "me", "google.com");

    let h2 = TempDir::new().unwrap();
    import_mnemonic(h2.path(), "me", ZERO_MNEMONIC);
    run_pw(
        h2.path(),
        &["hd-secret", "me", "create", "google.com", "--length", "16"],
    );
    let s2 = hd_secret_of(h2.path(), "me", "google.com");
    assert_eq!(s1, s2, "recovered keypair reproduces the same hd-secret");
}

#[test]
fn keypair_mnemonic_can_be_encrypted_and_unlocks() {
    let home = TempDir::new().unwrap();
    // Mnemonic line, then the new keystore password twice
    sesh(home.path())
        .args(["keypair", "create", "me", "--mnemonic"])
        .write_stdin(format!("{ZERO_MNEMONIC}\npw\npw\n"))
        .assert()
        .success();
    let shown = run_ok(home.path(), &["keypair", "show", "me"]);
    assert!(field(&shown, "Private key").contains("encrypted"));
    // The imported (encrypted) seed unlocks with that password
    sesh(home.path())
        .args(["hd-secret", "me", "create", "x"])
        .write_stdin("pw\n")
        .assert()
        .success();
}

#[test]
fn keypair_mnemonic_rejects_invalid_input() {
    let home = TempDir::new().unwrap();
    // 24 valid words but a wrong checksum word (all "abandon")
    let bad_checksum = "abandon ".repeat(24);
    sesh(home.path())
        .args(["keypair", "create", "x", "--mnemonic"])
        .write_stdin(format!("{}\n", bad_checksum.trim()))
        .assert()
        .failure()
        .stderr(contains("checksum"));
    // A 12-word mnemonic is refused: 24 words are required for 256-bit entropy
    sesh(home.path())
        .args(["keypair", "create", "y", "--mnemonic"])
        .write_stdin("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n")
        .assert()
        .failure()
        .stderr(contains("24-word"));
    // Neither failed attempt stored anything
    assert!(run_ok(home.path(), &["keypair", "list"]).contains("(no identities)"));
}

// relocatable keystore: init / status / config pointer

// A `sesh` invocation with **no** `$SESH_HOME` and an isolated
// `$XDG_CONFIG_HOME`, so the config-pointer branch of resolution is exercised
// without touching the real user config.
fn sesh_cfg(xdg: &Path) -> Command {
    let mut cmd = Command::cargo_bin("sesh").unwrap();
    cmd.env_remove("SESH_HOME").env("XDG_CONFIG_HOME", xdg);
    cmd
}

// Hand-write a config pointer at `$XDG_CONFIG_HOME/sesh/config.toml` (mode
// 0600, as sesh requires).
fn write_pointer(xdg: &Path, keystore: &Path, id: Option<&str>) {
    let dir = xdg.join("sesh");
    std::fs::create_dir_all(&dir).unwrap();
    let mut body = format!("default_keystore_path = \"{}\"\n", keystore.display());
    if let Some(id) = id {
        body.push_str(&format!("default_keystore_id = \"{id}\"\n"));
    }
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

// Read a keystore's own identity id from its marker (`<keystore>/config.toml`)
fn keystore_id(keystore: &Path) -> String {
    let s = std::fs::read_to_string(keystore.join("config.toml")).unwrap();
    s.lines()
        .find_map(|l| l.trim().strip_prefix("id ="))
        .expect("marker has an id")
        .trim()
        .trim_matches('"')
        .to_string()
}

// Provision a keystore at `path` by pointing `--keystore` at it once (a local
// source, which auto-creates on first write).
fn provision_at(path: &Path) {
    Command::cargo_bin("sesh")
        .unwrap()
        .args([
            "--keystore",
            path.to_str().unwrap(),
            "keypair",
            "create",
            "seed",
        ])
        .write_stdin(pw_lines())
        .assert()
        .success();
}

#[test]
fn keypair_create_auto_provisions_the_keystore() {
    // Fresh $SESH_HOME (never initialized): the first `keypair create` creates
    // and stamps the store automatically. There's no separate init step.
    let home = TempDir::new().unwrap();
    run_pw(home.path(), &["keypair", "create", "me"]);
    assert!(home.path().join("keypairs/me/identity").is_file());
    // A marker (config.toml, just an id, no redirect) was stamped
    let marker = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    assert!(marker.contains("id ="));
    assert!(!marker.contains("default_keystore_path"));

    // A read on a brand-new, never-written store just lists nothing (it is not
    // auto-created by a read).
    let fresh = TempDir::new().unwrap();
    assert!(run_ok(fresh.path(), &["keypair", "list"]).contains("(no identities)"));
    assert!(
        !fresh.path().join("config.toml").exists(),
        "a read created nothing"
    );
}

#[test]
fn keystore_config_pointer_resolves_and_round_trips() {
    let xdg = TempDir::new().unwrap();
    let media = TempDir::new().unwrap();
    let usb = media.path().join("sesh");

    // Provision the store, then hand-write a pointer (with its id) to it
    provision_at(&usb);
    write_pointer(xdg.path(), &usb, Some(&keystore_id(&usb)));

    // With no $SESH_HOME, resolution follows the pointer: a keypair created
    // here lands in the store the pointer names.
    sesh_cfg(xdg.path())
        .args(["keypair", "create", "me"])
        .write_stdin(pw_lines())
        .assert()
        .success();
    assert!(usb.join("keypairs/me/identity").is_file());
}

#[test]
fn keystore_config_pointer_missing_path_creates_nothing() {
    let xdg = TempDir::new().unwrap();
    let media = TempDir::new().unwrap();
    let usb = media.path().join("sesh"); // never created

    write_pointer(xdg.path(), &usb, None);

    // Following a pointer never auto-creates the target: a missing path fails
    // path-agnostically with EX_UNAVAILABLE (69) and creates nothing.
    sesh_cfg(xdg.path())
        .args(["keypair", "create", "x"])
        .assert()
        .failure()
        .code(69)
        .stderr(contains("does not exist"));
    assert!(!usb.exists(), "a pointer must never auto-create its target");
}

#[test]
fn keystore_config_pointer_present_but_empty_gives_bootstrap_hint() {
    let xdg = TempDir::new().unwrap();
    let media = TempDir::new().unwrap();
    let usb = media.path().join("sesh");
    std::fs::create_dir_all(&usb).unwrap(); // exists, but is not a keystore

    write_pointer(xdg.path(), &usb, None);

    // Present but not a keystore: refuse (never auto-provision via a pointer)
    // and hint how to bootstrap it.
    sesh_cfg(xdg.path())
        .args(["keypair", "create", "x"])
        .assert()
        .failure()
        .stderr(contains("create it first"));
    assert!(
        !usb.join("keypairs").exists(),
        "still nothing created via the pointer"
    );
}

#[test]
fn keystore_config_pointer_uuid_mismatch_rejected() {
    let xdg = TempDir::new().unwrap();
    let media = TempDir::new().unwrap();
    let usb = media.path().join("sesh");

    provision_at(&usb);
    // Pointer expects the original id...
    write_pointer(xdg.path(), &usb, Some(&keystore_id(&usb)));
    // ...but a different keystore is now mounted at that path
    std::fs::write(
        usb.join("config.toml"),
        "id = \"00000000-0000-4000-8000-000000000000\"\n",
    )
    .unwrap();

    sesh_cfg(xdg.path())
        .args(["keypair", "create", "x"])
        .assert()
        .failure()
        .stderr(contains("not the keystore your config is linked to"));
}

#[test]
fn keystore_marker_rejects_a_keystore_redirect_key() {
    // A `keystore` redirect key is legal only in the pointer, never inside a
    // keystore. Putting one in a keystore's config.toml is a hard error (it
    // would be a second, ambiguous hop).
    let home = TempDir::new().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "id = \"11111111-1111-4111-8111-111111111111\"\ndefault_keystore_path = \"/elsewhere\"\n",
    )
    .unwrap();
    // A write reads the marker (to provision if needed) and rejects the redirect
    sesh_pw(home.path())
        .args(["keypair", "create", "me"])
        .assert()
        .failure()
        .stderr(contains(
            "must not contain a `default_keystore_path` redirect",
        ));
}

#[test]
fn keystore_config_pointer_rejects_world_writable_config() {
    let xdg = TempDir::new().unwrap();
    let media = TempDir::new().unwrap();
    let usb = media.path().join("sesh");
    provision_at(&usb);
    write_pointer(xdg.path(), &usb, None);

    // A group/world-writable pointer could be edited by another party to
    // redirect secret writes, so it is refused outright.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let cfg = xdg.path().join("sesh/config.toml");
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o666)).unwrap();
        sesh_cfg(xdg.path())
            .args(["keypair", "list"])
            .assert()
            .failure()
            .stderr(contains("writable"));
    }
}

#[test]
fn keystore_legacy_store_without_marker_reads_and_restamps() {
    // A pre-marker (legacy) store (data intact, marker removed) still reads
    // fine (local sources need no marker to open) and gets re-stamped on the
    // next write, all without any explicit init/adopt step.
    let home = TempDir::new().unwrap();
    let created = run_pw(home.path(), &["keypair", "create", "me"]);
    let fpr = field(&created, "Fingerprint");
    std::fs::remove_file(home.path().join("config.toml")).unwrap();

    // Read works with no marker
    let shown = run_ok(home.path(), &["keypair", "show", "me"]);
    assert_eq!(field(&shown, "Fingerprint"), fpr);
    assert!(
        !home.path().join("config.toml").exists(),
        "a read did not re-stamp"
    );

    // The next write re-stamps the marker without disturbing existing data
    run_pw(home.path(), &["keypair", "create", "bob"]);
    assert!(
        home.path().join("config.toml").is_file(),
        "write re-stamped the marker"
    );
    assert_eq!(
        field(
            &run_ok(home.path(), &["keypair", "show", "me"]),
            "Fingerprint"
        ),
        fpr
    );
}

#[test]
fn restore_into_existing_empty_target_succeeds() {
    // Back up an initialized store, then restore into a freshly created (empty,
    // un-initialized) directory. Restore is allowed to populate a target.
    let src = TempDir::new().unwrap();
    make_identity(src.path(), "me");
    run_pw(src.path(), &["hd-secret", "me", "create", "site"]);
    let backup_file = src.path().join("b.sesh");
    let backup_arg = backup_file.to_str().unwrap();
    sesh(src.path())
        .args(["backup", backup_arg])
        .write_stdin("pw\npw\n")
        .assert()
        .success();

    let dst = TempDir::new().unwrap(); // exists, empty, never initialized
    sesh(dst.path())
        .args(["restore", backup_arg])
        .write_stdin("pw\n")
        .assert()
        .success()
        .stdout(contains("Restored"));
    // The restored store is usable straight away (its marker came in the bundle)
    let shown = run_pw(dst.path(), &["hd-secret", "me", "show", "site"]);
    assert_eq!(field(&shown, "Id"), "site");
}

// hd-secret: --recover (read-only disaster recovery)

// Run a seed-unlocking `copy` with the clipboard redirected into `sink`, and
// return exactly the bytes that reached the clipboard.
//
// `SESH_CLIPBOARD_CMD` is the documented test seam: the secret is piped to
// `sh -c <cmd>` on stdin, so `cat > file` captures the rendered password
// verbatim. The harness pipes stdin/stderr, so `copy` takes its non-interactive
// path: no countdown, and no clearing write to race with the read.
fn copy_secret(home: &Path, sink: &Path, args: &[&str]) -> String {
    sesh_pw(home)
        .env("SESH_CLIPBOARD_CMD", format!("cat > '{}'", sink.display()))
        .args(args)
        .assert()
        .success();
    std::fs::read_to_string(sink).unwrap()
}

// Every file under `root`, as `(relative path, bytes)` sorted by path, so a
// test can assert a command left the keystore untouched.
fn tree_snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap().map(Result::unwrap) {
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

// The headline recovery: `create` -> `remove` -> `create` destroys every stored
// copy of the original recipe (the second `create` overwrites the tombstone
// slot in place), yet `--recover 1` reproduces the original password **byte for
// byte** from the archive.
#[test]
fn recover_reproduces_a_removed_password_byte_for_byte() {
    let home = TempDir::new().unwrap();
    let sink = TempDir::new().unwrap();
    make_identity(home.path(), "me");

    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]); // epoch 1
    let original = copy_secret(
        home.path(),
        &sink.path().join("a"),
        &["hd-secret", "me", "copy", "bank"],
    );
    assert!(!original.is_empty());

    run_pw(home.path(), &["hd-secret", "me", "remove", "bank"]); // tombstone at 2
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]); // revived at 3

    // The revived entry is a different password: same recipe, new epoch
    let revived = copy_secret(
        home.path(),
        &sink.path().join("b"),
        &["hd-secret", "me", "copy", "bank"],
    );
    assert_ne!(
        original, revived,
        "reviving must not reproduce the old secret"
    );

    // The archive brings the original back, exactly
    let recovered = copy_secret(
        home.path(),
        &sink.path().join("c"),
        &["hd-secret", "me", "copy", "bank", "--recover", "1"],
    );
    assert_eq!(original, recovered);
}

// Recovery is read-only: the whole keystore is byte-identical afterwards, so no
// epoch rule bends and the other group members need do nothing.
#[test]
fn recover_leaves_the_keystore_byte_identical() {
    let home = TempDir::new().unwrap();
    let sink = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]);
    run_pw(home.path(), &["hd-secret", "me", "rotate", "bank"]); // epoch 2

    let before = tree_snapshot(home.path());
    copy_secret(
        home.path(),
        &sink.path().join("a"),
        &["hd-secret", "me", "copy", "bank", "--recover", "1"],
    );
    assert_eq!(before, tree_snapshot(home.path()));
}

// `rotate` replaces `params` in place. The old recipe must come back from the
// archive rather than being re-rendered under the *new* params, which would
// silently produce a different password.
#[test]
fn recover_uses_the_archived_recipe_not_the_current_params() {
    let home = TempDir::new().unwrap();
    let sink = TempDir::new().unwrap();
    make_identity(home.path(), "me");

    // Epoch 1: a "distinctive" recipe
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "bank",
            "--mode",
            "b58",
            "--length",
            "14",
            "--no-symbols",
        ],
    );
    let original = copy_secret(
        home.path(),
        &sink.path().join("a"),
        &["hd-secret", "me", "copy", "bank"],
    );
    assert_eq!(original.len(), 14);

    // Epoch 2: a completely different recipe
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "rotate",
            "bank",
            "--mode",
            "hex",
            "--length",
            "20",
            "--no-symbols",
        ],
    );

    let recovered = copy_secret(
        home.path(),
        &sink.path().join("b"),
        &["hd-secret", "me", "copy", "bank", "--recover", "1"],
    );
    assert_eq!(
        recovered, original,
        "recovery must use epoch 1's recipe, not epoch 2's"
    );
    assert_eq!(recovered.len(), 14);
    assert!(
        !recovered.starts_with("0x"),
        "hex is the current recipe, not the archived one"
    );
}

// An epoch with no recorded recipe is an error. It must never fall back to the
// live entry's params: the fingerprint covers only `(id, user, epoch)`, so a
// guessed recipe would render a wrong password under a right-looking
// fingerprint.
#[test]
fn recover_refuses_an_epoch_it_has_no_recipe_for() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]); // epoch 1 only

    for epoch in ["0", "2", "9999"] {
        sesh_pw(home.path())
            .args(["hd-secret", "me", "copy", "bank", "--recover", epoch])
            .assert()
            .failure()
            .stderr(contains("No recorded recipe").and(contains(epoch)));
    }
    // A non-numeric epoch is a usage error, not a panic
    sesh_pw(home.path())
        .args(["hd-secret", "me", "copy", "bank", "--recover", "none"])
        .assert()
        .failure()
        .stderr(contains("--recover takes an epoch"));
}

// A tombstone formats nothing: its own epoch has no password, even though an
// entry sits at exactly that epoch. Recovering "the epoch it was removed at" is
// the natural off-by-one, and it must fail loudly rather than derive a stranger.
#[test]
fn recover_rejects_the_tombstones_own_epoch() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]); // epoch 1
    run_pw(home.path(), &["hd-secret", "me", "remove", "bank"]); // tombstone at 2

    sesh_pw(home.path())
        .args(["hd-secret", "me", "copy", "bank", "--recover", "2"])
        .assert()
        .failure()
        .stderr(contains("No recorded recipe"));
    // Epoch 1 - the one the tombstone's params actually formatted (works)
    sesh_pw(home.path())
        .env("SESH_CLIPBOARD_CMD", "cat > /dev/null")
        .args(["hd-secret", "me", "copy", "bank", "--recover", "1"])
        .assert()
        .success();
}

// `--recover` at the current epoch is an ordinary read of the live entry, and
// says nothing about archives.
#[test]
fn recover_at_the_current_epoch_is_a_plain_read() {
    let home = TempDir::new().unwrap();
    let sink = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]); // epoch 1

    let plain = copy_secret(
        home.path(),
        &sink.path().join("a"),
        &["hd-secret", "me", "copy", "bank"],
    );
    let at_one = copy_secret(
        home.path(),
        &sink.path().join("b"),
        &["hd-secret", "me", "copy", "bank", "--recover", "1"],
    );
    assert_eq!(plain, at_one);

    let shown = run_pw(
        home.path(),
        &["hd-secret", "me", "show", "bank", "--recover", "1"],
    );
    assert!(
        !shown.contains("archived recipe"),
        "the live entry is not archived:\n{shown}"
    );
}

// `show --recover` on a superseded epoch renders exactly like a current entry,
// so it must say which it is.
#[test]
fn show_recover_marks_a_superseded_recipe() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--mode", "b58"],
    );
    run_pw(
        home.path(),
        &["hd-secret", "me", "rotate", "bank", "--mode", "hex"],
    );

    let shown = run_pw(
        home.path(),
        &["hd-secret", "me", "show", "bank", "--recover", "1"],
    );
    assert_eq!(field(&shown, "Epoch"), "1");
    assert!(
        shown.contains("b58"),
        "the archived recipe's params:\n{shown}"
    );
    assert!(
        shown.contains("archived recipe"),
        "must be marked as archived:\n{shown}"
    );

    // The current entry is epoch 2 and is not marked
    let current = run_pw(home.path(), &["hd-secret", "me", "show", "bank"]);
    assert_eq!(field(&current, "Epoch"), "2");
    assert!(!current.contains("archived recipe"));
}

// `list --archived` (and its `--removed` alias) show the superseded epochs and
// their full params; plain `list` shows neither.
#[test]
fn list_archived_shows_superseded_recipes_and_plain_list_does_not() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--mode", "b58"],
    );
    run_pw(home.path(), &["hd-secret", "me", "remove", "bank"]); // archives epoch 1

    // The removed entry is invisible to a plain list...
    let plain = run_pw(home.path(), &["hd-secret", "me", "list"]);
    assert!(plain.contains("(no definitions)"), "{plain}");

    // ...and its epoch and recipe are readable under --archived
    let archived = run_pw(home.path(), &["hd-secret", "me", "list", "--archived"]);
    assert_eq!(table_cell(&archived, "bank", 2), "1");
    assert!(archived.contains("--mode b58"), "full params:\n{archived}");
    assert!(
        archived.contains("--recover"),
        "must name the command that uses it:\n{archived}"
    );

    // `--removed` is the same flag under the name a user reaches for first
    let removed = run_pw(home.path(), &["hd-secret", "me", "list", "--removed"]);
    assert_eq!(removed, archived);
}

// An empty archive says so, rather than printing an empty table
#[test]
fn list_archived_is_empty_until_something_is_superseded() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]);

    let archived = run_pw(home.path(), &["hd-secret", "me", "list", "--archived"]);
    assert!(archived.contains("(no archived recipes)"), "{archived}");
}

// The documented hazard, pinned as a test: the fingerprint covers
// `(master, id, user, epoch)` and **not** `params`, so two recipes at one epoch
// agree on the fingerprint and render different passwords. The day someone adds
// a "fingerprints match, we're fine" check to a recovery path, this fails.
#[test]
fn the_fingerprint_does_not_cover_params() {
    let home = TempDir::new().unwrap();
    let sink = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--mode", "b58"],
    );

    // Two renderings of one epoch's secret, under different params
    let stored = copy_secret(
        home.path(),
        &sink.path().join("a"),
        &["hd-secret", "me", "copy", "bank"],
    );
    let other = copy_secret(
        home.path(),
        &sink.path().join("b"),
        &["hd-secret", "me", "copy", "bank", "--mode", "hex"],
    );
    assert_ne!(stored, other, "different params render different passwords");

    // Yet the fingerprint the user is invited to compare is identical, because
    // it is taken over the child scalar, which params never enter.
    let fpr = field(
        &run_pw(home.path(), &["hd-secret", "me", "show", "bank"]),
        "Fingerprint",
    );
    assert!(!fpr.is_empty());
    let fpr_again = field(
        &run_pw(
            home.path(),
            &["hd-secret", "me", "show", "bank", "--recover", "1"],
        ),
        "Fingerprint",
    );
    assert_eq!(fpr, fpr_again);
}

// `share` must never carry an archived epoch: a token below the peers' epoch is
// classified `Stale` and silently ignored, so it would look like a successful
// sync while changing nothing.
#[test]
fn share_has_no_recover_flag() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]);
    sesh_pw(home.path())
        .args(["hd-secret", "me", "share", "bank", "--recover", "1"])
        .assert()
        .failure();
}

// Group recovery needs no coordination and no out-of-band recipe. `remove`'s
// share token already carries the pre-removal params, so a member who *only*
// ever applied that token has the recipe archived locally and can re-derive the
// password alone. Both sides land on the same string.
#[test]
fn a_peer_recovers_a_removed_password_from_the_token_it_applied() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    run_pw(
        a,
        &[
            "hd-secret",
            "grp",
            "create",
            "bank",
            "--mode",
            "b58",
            "--length",
            "14",
            "--no-symbols",
        ],
    );
    apply_ok(b, &share_token(a, "grp", "bank"), "y\n");
    let original = hd_secret_of(a, "grp", "bank");
    assert_eq!(
        original,
        hd_secret_of(b, "grp", "bank"),
        "the group agrees before removal"
    );

    // A removes and hands B the removal token; B applies it
    let removed = run_pw(a, &["hd-secret", "grp", "remove", "bank"]);
    apply_ok(b, &field(&removed, "Share token"), "y\n");

    // The definition is gone on both sides...
    for h in [a, b] {
        sesh_pw(h)
            .args(["hd-secret", "grp", "show", "bank"])
            .assert()
            .failure()
            .stderr(contains("No stored definition"));
    }

    // ... yet both recover epoch 1 independently: A from its own `remove`, and B
    // (who never ran `remove`) from the params the token carried.
    let a_rec = copy_secret(
        a,
        &a.join(".rec"),
        &["hd-secret", "grp", "copy", "bank", "--recover", "1"],
    );
    let b_rec = copy_secret(
        b,
        &b.join(".rec"),
        &["hd-secret", "grp", "copy", "bank", "--recover", "1"],
    );
    assert_eq!(a_rec, original);
    assert_eq!(b_rec, original);
}

// The archive is per-keystore, not shared: a member who never saw the entry has
// nothing to recover from, and must be told so rather than shown a guess.
#[test]
fn a_peer_that_never_saw_the_entry_cannot_recover_it() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // A creates and removes without ever sharing either token
    run_pw(a, &["hd-secret", "grp", "create", "bank"]);
    run_pw(a, &["hd-secret", "grp", "remove", "bank"]);

    sesh_pw(b)
        .args(["hd-secret", "grp", "copy", "bank", "--recover", "1"])
        .assert()
        .failure()
        .stderr(contains("No recorded recipe"));
}

// hd-secret: create --recover (the mutating escape hatch)

// Run a `create --recover` that expects the confirmation prompt, answering
// `answer`, and return stdout.
fn recover_create(home: &Path, args: &[&str], answer: &str) -> Command {
    let mut cmd = sesh(home);
    cmd.args(args).write_stdin(format!("{PW}\n{answer}\n"));
    cmd
}

// The whole point: bring back the *entry* at a removed-and-overwritten epoch,
// inheriting its recipe. The password then matches what it was before removal,
// and the recipe was never typed.
#[test]
fn create_recover_restores_a_removed_entry_and_its_password() {
    let home = TempDir::new().unwrap();
    let sink = TempDir::new().unwrap();
    make_identity(home.path(), "me");

    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "fu",
            "bar",
            "--mode",
            "b58",
            "--length",
            "14",
        ],
    );
    let original = copy_secret(
        home.path(),
        &sink.path().join("a"),
        &["hd-secret", "me", "copy", "fu", "bar"],
    );

    run_pw(home.path(), &["hd-secret", "me", "remove", "fu", "bar"]); // tombstone at 2
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "fu", "bar", "--mode", "alpha"],
    ); // live at 3

    let out = recover_create(
        home.path(),
        &["hd-secret", "me", "create", "fu", "bar", "--recover", "1"],
        "y",
    )
    .assert()
    .success();
    let out = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("--mode b58"),
        "the inherited recipe is printed:\n{out}"
    );

    // The entry is live at epoch 1 again, with the original recipe...
    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "fu", "bar"]);
    assert_eq!(field(&shown, "Epoch"), "1");
    // ...and renders the original password
    let back = copy_secret(
        home.path(),
        &sink.path().join("b"),
        &["hd-secret", "me", "copy", "fu", "bar"],
    );
    assert_eq!(back, original);
}

// A recovery is destructive, so it asks. Declining writes nothing
#[test]
fn create_recover_asks_before_it_writes_and_declining_is_a_no_op() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]);
    run_pw(home.path(), &["hd-secret", "me", "rotate", "bank"]); // epoch 2

    let before = tree_snapshot(home.path());
    recover_create(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--recover", "1"],
        "n",
    )
    .assert()
    .failure();
    assert_eq!(
        before,
        tree_snapshot(home.path()),
        "a declined recovery must not write"
    );
    assert_eq!(
        field(
            &run_pw(home.path(), &["hd-secret", "me", "show", "bank"]),
            "Epoch"
        ),
        "2"
    );
}

// The recipe is read, never invented: an epoch with no recorded recipe is
// refused even when explicit formatting flags are supplied.
#[test]
fn create_recover_refuses_an_epoch_with_no_recorded_recipe() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]); // epoch 1 only

    for args in [
        vec!["hd-secret", "me", "create", "bank", "--recover", "7"],
        vec![
            "hd-secret",
            "me",
            "create",
            "bank",
            "--recover",
            "7",
            "--mode",
            "hex",
            "--length",
            "20",
        ],
    ] {
        recover_create(home.path(), &args, "y")
            .assert()
            .failure()
            .stderr(contains("No recorded recipe"));
    }
}

// `u64::MAX` would leave every future `rotate` and `remove` failing on epoch
// overflow; epoch 0 never held a secret. Both are refused.
#[test]
fn create_recover_rejects_the_bricking_epochs() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(home.path(), &["hd-secret", "me", "create", "bank"]);

    for bad in ["0", "18446744073709551615"] {
        recover_create(
            home.path(),
            &["hd-secret", "me", "create", "bank", "--recover", bad],
            "y",
        )
        .assert()
        .failure();
    }
    assert_eq!(
        field(
            &run_pw(home.path(), &["hd-secret", "me", "show", "bank"]),
            "Epoch"
        ),
        "1"
    );
}

// Explicit flags still override the inherited recipe. The override is
// called out, because that is exactly how two members agree on the epoch and
// disagree on the password.
#[test]
fn create_recover_lets_explicit_flags_override_but_warns() {
    let home = TempDir::new().unwrap();
    let sink = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "bank",
            "--mode",
            "b58",
            "--no-symbols",
        ],
    );
    let inherited = copy_secret(
        home.path(),
        &sink.path().join("a"),
        &["hd-secret", "me", "copy", "bank"],
    );
    run_pw(home.path(), &["hd-secret", "me", "rotate", "bank"]); // epoch 2

    let out = recover_create(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "bank",
            "--recover",
            "1",
            "--mode",
            "hex",
        ],
        "y",
    )
    .assert()
    .success();
    let out = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(out.contains("Warning: formatting flags override"), "{out}");
    assert!(out.contains("will hold a\ndifferent password"), "{out}");
    // The recipe half of the fingerprint is what catches this, so the warning
    // points at it rather than (as it once did) apologizing for its absence.
    assert!(
        out.contains("Compare fingerprints before the dash"),
        "{out}"
    );

    // The override took effect: a different password at the same epoch
    let overridden = copy_secret(
        home.path(),
        &sink.path().join("b"),
        &["hd-secret", "me", "copy", "bank"],
    );
    assert_eq!(
        field(
            &run_pw(home.path(), &["hd-secret", "me", "show", "bank"]),
            "Epoch"
        ),
        "1"
    );
    assert_ne!(overridden, inherited);
    assert!(overridden.starts_with("0x"));
}

// The `<recipe>-<secret>` split, end to end. Reformatting one epoch's secret
// moves the leading half and leaves the trailing half alone; re-deriving a new
// secret moves both. That is what lets two members tell "we formatted the same
// secret differently" from "we are not even holding the same secret"
#[test]
fn hd_fingerprint_recipe_half_tracks_params_and_secret_half_tracks_the_child() {
    let halves = |f: &str| {
        let (r, s) = f.split_once('-').expect("fingerprint is <recipe>-<secret>");
        assert!(!s.contains('-'), "exactly one separator: {f}");
        (r.to_string(), s.to_string())
    };
    let show = |home: &Path| {
        field(
            &run_pw(home, &["hd-secret", "me", "show", "bank"]),
            "Fingerprint",
        )
    };

    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "bank",
            "--mode",
            "b58",
            "--no-symbols",
        ],
    );
    let (r0, s0) = halves(&show(home.path()));

    // Same (id, user, epoch), so the same child formatted differently
    recover_create(
        home.path(),
        &[
            "hd-secret",
            "me",
            "create",
            "bank",
            "--recover",
            "1",
            "--mode",
            "hex",
        ],
        "y",
    )
    .assert()
    .success();
    let (r1, s1) = halves(&show(home.path()));
    assert_ne!(r0, r1, "reformatting must move the recipe half");
    assert_eq!(s0, s1, "reformatting must not move the secret half");

    // A rotate advances the epoch, so the child changes and both halves move
    run_pw(home.path(), &["hd-secret", "me", "rotate", "bank"]);
    let (r2, s2) = halves(&show(home.path()));
    assert_ne!(r1, r2);
    assert_ne!(s1, s2, "a new epoch must move the secret half");

    // `list` renders the same fingerprint `show` does, dash and all
    let listed = run_pw(home.path(), &["hd-secret", "me", "list"]);
    assert_eq!(table_cell(&listed, "bank", 4), format!("{r2}-{s2}"));
}

// Inheriting must not be quietly rewritten by clap's `create --mode` default.
// Without the `occurrences_of` guard this recovers epoch 1 as b58 regardless of
// what epoch 1 actually was.
#[test]
fn create_recover_inherits_the_mode_rather_than_the_clap_default() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    // Epoch 1 is alpha - *not* the DEFAULT_MODE that `create --mode` fills in
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--mode", "alpha"],
    );
    run_pw(
        home.path(),
        &["hd-secret", "me", "rotate", "bank", "--mode", "hex"],
    ); // epoch 2

    recover_create(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--recover", "1"],
        "y",
    )
    .assert()
    .success();
    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "bank"]);
    assert_eq!(field(&shown, "Epoch"), "1");
    assert!(
        shown.contains("--mode alpha"),
        "epoch 1 was alpha, not b58:\n{shown}"
    );
}

// A recovery displaces the current definition, which is archived, so the
// recovery itself can be undone.
#[test]
fn create_recover_is_itself_recoverable() {
    let home = TempDir::new().unwrap();
    make_identity(home.path(), "me");
    run_pw(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--mode", "b58"],
    );
    run_pw(
        home.path(),
        &["hd-secret", "me", "rotate", "bank", "--mode", "hex"],
    ); // epoch 2

    recover_create(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--recover", "1"],
        "y",
    )
    .assert()
    .success();
    assert_eq!(
        field(
            &run_pw(home.path(), &["hd-secret", "me", "show", "bank"]),
            "Epoch"
        ),
        "1"
    );

    // Epoch 2's recipe survived being displaced, so we can go back to it
    recover_create(
        home.path(),
        &["hd-secret", "me", "create", "bank", "--recover", "2"],
        "y",
    )
    .assert()
    .success();
    let shown = run_pw(home.path(), &["hd-secret", "me", "show", "bank"]);
    assert_eq!(field(&shown, "Epoch"), "2");
    assert!(shown.contains("--mode hex"), "{shown}");
}

// A group recovery emits **no** share token. A token below the peers' epoch is
// classified `Stale` and silently ignored, so printing one would look like a
// sync and be none. The command every member must run is printed instead.
#[test]
fn create_recover_emits_no_share_token_and_says_what_to_do_instead() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    run_pw(a, &["hd-secret", "grp", "create", "bank", "--mode", "b58"]);
    apply_ok(b, &share_token(a, "grp", "bank"), "y\n");
    let original = hd_secret_of(a, "grp", "bank");
    run_pw(a, &["hd-secret", "grp", "rotate", "bank"]); // both A and B move on
    apply_ok(b, &share_token(a, "grp", "bank"), "y\n");

    let out = recover_create(
        a,
        &["hd-secret", "grp", "create", "bank", "--recover", "1"],
        "y",
    )
    .assert()
    .success();
    let out = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        !out.contains("Share token"),
        "a recovery must not emit a token:\n{out}"
    );
    assert!(out.contains("cannot be synced"), "{out}");
    assert!(
        out.contains("create bank --recover 1"),
        "names the peer's command:\n{out}"
    );

    // B runs the identical command and lands on the same password. No recipe
    // was exchanged, because both inherited it from their own archives.
    recover_create(
        b,
        &["hd-secret", "grp", "create", "bank", "--recover", "1"],
        "y",
    )
    .assert()
    .success();
    assert_eq!(hd_secret_of(a, "grp", "bank"), original);
    assert_eq!(hd_secret_of(b, "grp", "bank"), original);
}

// decentralized backup: shared-secret export / import
//
// `backup`/`restore` is the centralized bundle: your whole keystore under a
// passphrase you choose. It does not protect against a dead disk *and* a
// forgotten passphrase. `shared-secret export`/`import` is the decentralized
// one: any member hands any other member a file sealed to the group's
// membership, so there is no passphrase, because there is no new secret.

// Run `import`, answering the password prompt and then the apply prompt
fn run_import(home: &Path, args: &[&str], answer: &str) -> String {
    let out = sesh(home)
        .args(args)
        .write_stdin(format!("{PW}\n{answer}\n"))
        .assert()
        .success();
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

// `export` writes the file and prints the same checksum `import` will
fn export_group(home: &Path, group: &str, file: &Path) -> String {
    run_pw(
        home,
        &["shared-secret", "export", group, file.to_str().unwrap()],
    )
}

// Three homes wired as mutual contacts (`p0`/`p1`/`p2`), with `a`'s identity
// derived from a mnemonic, the only way `a` can come back from bare metal.
fn wire_recoverable_trio() -> (TempDir, TempDir, TempDir) {
    let (a, b, c) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let at = field(
        &import_mnemonic(a.path(), "me", ZERO_MNEMONIC),
        "Contact token",
    );
    let bt = make_identity(b.path(), "me");
    let ct = make_identity(c.path(), "me");
    for (home, pins) in [
        (a.path(), [("p1", &bt), ("p2", &ct)]),
        (b.path(), [("p0", &at), ("p2", &ct)]),
        (c.path(), [("p0", &at), ("p1", &bt)]),
    ] {
        for (alias, token) in pins {
            run_ok(home, &["contact", "add", token, "--name", alias]);
        }
    }
    (a, b, c)
}

// Form the 3-party group `group` across three wired homes
fn form_group3(a: &Path, b: &Path, c: &Path, group: &str) {
    let at = emit_token(a, "me", group, &["p1", "p2"]);
    let bt = emit_token(b, "me", group, &["p0", "p2"]);
    let ct = emit_token(c, "me", group, &["p0", "p1"]);
    let complete = |home: &Path, parties: [&str; 2], toks: [&str; 2]| {
        run_pw(
            home,
            &[
                "shared-secret",
                "create",
                group,
                "--keypair",
                "me",
                "--party",
                parties[0],
                "--party",
                parties[1],
                "--token",
                toks[0],
                "--token",
                toks[1],
            ],
        );
    };
    complete(a, ["p1", "p2"], [&bt, &ct]);
    complete(b, ["p0", "p2"], [&at, &ct]);
    complete(c, ["p0", "p1"], [&at, &bt]);
}

// A stored secret at a past epoch, via the read-only `copy --recover` path
fn hd_secret_at(home: &Path, owner: &str, id: &str, epoch: &str) -> String {
    let clip = home.join(format!(".clip-{owner}-{id}-{epoch}"));
    copy_secret(
        home,
        &clip,
        &["hd-secret", owner, "copy", id, "--recover", epoch],
    )
}

// **The whole point, end to end.** A 3-party group with a rotated definition and
// a removed one. Alice exports; her machine is destroyed; she comes back from 24
// words plus two re-pinned contacts plus one file and every password, live and
// long-since-removed, is byte-identical.
#[test]
fn export_import_restores_a_group_and_its_registry_from_bare_metal() {
    let (a, b, c) = wire_recoverable_trio();
    let (ap, bp, cp) = (a.path(), b.path(), c.path());
    form_group3(ap, bp, cp, "team");

    run_pw(ap, &["hd-secret", "team", "create", "github.com"]);
    run_pw(ap, &["hd-secret", "team", "create", "aws.com", "root"]);
    run_pw(ap, &["hd-secret", "team", "create", "old.example.com"]);
    run_pw(ap, &["hd-secret", "team", "rotate", "github.com"]); // -> epoch 2, archives 1
    run_pw(ap, &["hd-secret", "team", "remove", "old.example.com"]); // tombstone at epoch 2

    let fingerprint = field(
        &run_ok(ap, &["shared-secret", "show", "team"]),
        "Fingerprint",
    );
    let github = hd_secret_of(ap, "team", "github.com");
    let github_e1 = hd_secret_at(ap, "team", "github.com", "1"); // pre-rotation
    let old_e1 = hd_secret_at(ap, "team", "old.example.com", "1"); // pre-removal

    let file = bp.join("team.export"); // lives outside the home we are about to wipe
    let exported = export_group(ap, "team", &file);

    // Bare metal. Everything alice had is gone
    std::fs::remove_dir_all(ap).unwrap();
    import_mnemonic(ap, "me", ZERO_MNEMONIC);
    for (alias, home) in [("p1", bp), ("p2", cp)] {
        let token = field(&run_ok(home, &["keypair", "show", "me"]), "Contact token");
        run_ok(ap, &["contact", "add", &token, "--name", alias]);
    }
    assert!(run_ok(ap, &["shared-secret", "list"]).contains("(no shared secrets)"));

    let imported = run_import(
        ap,
        &[
            "shared-secret",
            "import",
            file.to_str().unwrap(),
            "--keypair",
            "me",
            "--party",
            "p1",
            "--party",
            "p2",
        ],
        "y",
    );

    // Layer 3: both sides derived the same group master
    assert_eq!(checksum_after(&exported), checksum_after(&imported));
    assert!(imported.contains("signed by 'me (you)'"), "{imported}");
    // The public group is the same one
    assert_eq!(
        field(
            &run_ok(ap, &["shared-secret", "show", "team"]),
            "Fingerprint"
        ),
        fingerprint
    );
    // And every password comes back, byte for byte
    assert_eq!(hd_secret_of(ap, "team", "github.com"), github);
    assert_eq!(hd_secret_at(ap, "team", "github.com", "1"), github_e1);
    assert_eq!(hd_secret_at(ap, "team", "old.example.com", "1"), old_e1);
    // `aws.com` needs its user; it round-tripped too
    assert_eq!(
        table_cell(&run_pw(ap, &["hd-secret", "team", "list"]), "aws.com", 2),
        "1"
    );
    // The tombstone is still a tombstone: it does not list live
    assert!(!run_pw(ap, &["hd-secret", "team", "list"]).contains("old.example.com"));
}

// A peer's export restores *them* too. The file is symmetric, and one export
// from any one member carries every member's setup token.
#[test]
fn any_member_can_open_any_members_export() {
    let (a, b, c) = wire_recoverable_trio();
    let (ap, bp, cp) = (a.path(), b.path(), c.path());
    form_group3(ap, bp, cp, "team");
    run_pw(ap, &["hd-secret", "team", "create", "vpn"]);

    let file = ap.join("t.export");
    export_group(ap, "team", &file);

    // Carol already holds the group, so this is a pure registry merge; the
    // checksum still confirms both sides hold the same K.
    let out = run_import(
        cp,
        &[
            "shared-secret",
            "import",
            file.to_str().unwrap(),
            "--keypair",
            "me",
            "--party",
            "p0",
            "--party",
            "p1",
        ],
        "y",
    );
    assert!(
        out.contains("signed by 'p0'"),
        "attribution names the exporter:\n{out}"
    );
    assert_eq!(
        hd_secret_of(cp, "team", "vpn"),
        hd_secret_of(ap, "team", "vpn")
    );

    // Re-importing the same file is a no-op, not a rewrite
    let again = run_import(
        cp,
        &[
            "shared-secret",
            "import",
            file.to_str().unwrap(),
            "--keypair",
            "me",
            "--party",
            "p0",
            "--party",
            "p1",
        ],
        "y",
    );
    assert!(again.contains("Nothing to import"), "{again}");
}

// The wrong `--party` set is an AEAD authentication failure. It must say so
// without ever mentioning a signature: none has been checked, and a user who
// mistyped a `--party` must not go looking for a forged file.
#[test]
fn import_with_a_missing_party_fails_at_the_aead_and_never_mentions_signatures() {
    let (a, b, c) = wire_recoverable_trio();
    let (ap, bp, cp) = (a.path(), b.path(), c.path());
    form_group3(ap, bp, cp, "team");
    let file = ap.join("t.export");
    export_group(ap, "team", &file);

    let out = sesh_pw(bp)
        .args([
            "shared-secret",
            "import",
            file.to_str().unwrap(),
            "--keypair",
            "me",
            "--party",
            "p0",
        ]) // p2 omitted
        .assert()
        .failure();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(err.contains("sealed to an exact membership"), "{err}");
    assert!(
        !err.to_lowercase().contains("signature"),
        "must not mention signatures:\n{err}"
    );
    assert!(
        !err.to_lowercase().contains("signed"),
        "must not mention signing:\n{err}"
    );
}

// The full member set as `home` sees it: the local keypair first, then each
// pinned `--party` contact, the shape `setup_wrap_key` and `group_ctx` take.
fn members_of(
    ks: &sesh::keystore::Keystore,
    keypair: &str,
    parties: &[&str],
) -> Vec<sesh::crypto::PublicIdentity> {
    let mut v = vec![ks.load_public_identity(keypair).unwrap()];
    v.extend(parties.iter().map(|p| ks.load_contact(p).unwrap()));
    v
}

// Read an export's body using `home`'s keys
fn open_export(
    path: &Path,
    home: &Path,
    keypair: &str,
    parties: &[&str],
) -> sesh::export::ExportBody {
    let ks = sesh::keystore::Keystore::open(home);
    let seed = ks.load_seed(keypair, PW).unwrap();
    let members = members_of(&ks, keypair, parties);
    let wrap = sesh::protocol::setup_wrap_key(&seed, &members[1..], &members).unwrap();
    let bytes = std::fs::read(path).unwrap();
    sesh::export::open(&bytes, &wrap).unwrap().body().clone()
}

// Forge an export in place: open it as `keypair` in `home`, let `edit` mutate
// the body, then re-sign it with `sign_as = (home, keypair)`'s seed and re-seal
// it under the group's wrap key.
//
// Every forgery these tests build is one a **member** could build, because only
// a member holds the wrap key at all. That is precisely why `import` checks a
// signature *and* a checksum *and* every fingerprint: opening the AEAD proves
// the author was inside the group, and nothing more.
fn reseal_export(
    path: &Path,
    home: &Path,
    keypair: &str,
    parties: &[&str],
    sign_as: (&Path, &str),
    edit: impl FnOnce(&mut sesh::export::ExportBody),
) {
    let ks = sesh::keystore::Keystore::open(home);
    let seed = ks.load_seed(keypair, PW).unwrap();
    let members = members_of(&ks, keypair, parties);
    let wrap = sesh::protocol::setup_wrap_key(&seed, &members[1..], &members).unwrap();

    let mut body = sesh::export::open(&std::fs::read(path).unwrap(), &wrap)
        .unwrap()
        .body()
        .clone();
    edit(&mut body);

    let signer_ks = sesh::keystore::Keystore::open(sign_as.0);
    let signer_seed = signer_ks.load_seed(sign_as.1, PW).unwrap();
    std::fs::write(
        path,
        sesh::export::seal(&signer_seed, &wrap, &body).unwrap(),
    )
    .unwrap();
}

// Import args for a 2-party group, from `keypair` with one `--party`
fn import_args<'a>(file: &'a str, party: &'a str) -> [&'a str; 7] {
    [
        "shared-secret",
        "import",
        file,
        "--keypair",
        "me",
        "--party",
        party,
    ]
}

// A member cannot rename the group or swap in a foreign token: the payload's
// `group_name` is authenticated by every *peer's* setup-token signature, which
// is made over a `group_ctx` binding that name. A token lifted from another
// group fails `SetupToken::verify`, and the error names the alias it was
// expected from.
#[test]
fn import_rejects_a_setup_token_swapped_in_from_another_group() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    form_group(a, b, "other");
    run_pw(a, &["hd-secret", "grp", "create", "vpn"]);

    let file = a.join("grp.export");
    let other = a.join("other.export");
    export_group(a, "grp", &file);
    export_group(a, "other", &other);

    // Lift A's setup token for "other" (index 0: an export lists the exporter's
    // own token first) and splice it over A's token for "grp".
    let foreign = open_export(&other, a, "me", &["p1"]).tokens[0].clone();
    reseal_export(&file, a, "me", &["p1"], (a, "me"), |body| {
        body.tokens[0] = foreign;
    });

    // B opens it (A is a member, and signed it), but no token verifies as A
    let out = sesh_pw(b)
        .args(import_args(file.to_str().unwrap(), "p0"))
        .assert()
        .failure();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        err.contains("no setup token signed by 'p0'"),
        "names the alias:\n{err}"
    );
    assert!(err.contains("grp"), "names the group:\n{err}");
}

// Layer 1 proves the author held the wrap key; layer 2 proves *who* they were.
// A body sealed by a member but signed by an outsider opens and is rejected.
#[test]
fn import_rejects_a_body_signed_by_a_non_member() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    run_pw(a, &["hd-secret", "grp", "create", "vpn"]);

    let outsider = TempDir::new().unwrap();
    make_identity(outsider.path(), "dave");

    let file = a.join("grp.export");
    export_group(a, "grp", &file);
    reseal_export(&file, a, "me", &["p1"], (outsider.path(), "dave"), |_| {});

    let before = tree_snapshot(b);
    let out = sesh_pw(b)
        .args(import_args(file.to_str().unwrap(), "p0"))
        .assert()
        .failure();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(err.contains("not signed by any member"), "{err}");
    assert_eq!(
        before,
        tree_snapshot(b),
        "a rejected import must write nothing"
    );
}

// **Layer 4's tripwire, and the reason it exists.** Every other layer has
// already passed here: the AEAD opened, a member signed it, and the checksum
// confirms the same `K`. Only the per-definition fingerprint catches the edit.
//
// Written so that deleting the `check_fingerprints` call makes it fail: B holds
// no such definition, so without the check the import would succeed and write.
#[test]
fn a_tampered_fingerprint_row_is_a_hard_error_and_nothing_is_written() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    run_pw(a, &["hd-secret", "grp", "create", "vpn"]);

    let file = a.join("grp.export");
    export_group(a, "grp", &file);
    // A member re-signs their own file with one digest edited. Layers 1-3 pass
    reseal_export(&file, a, "me", &["p1"], (a, "me"), |body| {
        body.fingerprints[0].fingerprint = "aaaa-bbbbbbbbbbb".to_string();
    });

    let before = tree_snapshot(b);
    let out = sesh_pw(b)
        .args(import_args(file.to_str().unwrap(), "p0"))
        .assert()
        .failure();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(err.contains("Fingerprint mismatch"), "{err}");
    assert!(err.contains("vpn"), "names the row:\n{err}");
    assert_eq!(before, tree_snapshot(b), "nothing may be written");
}

// `--dry-run` verifies everything and stops before the prompt. The keystore
// must be byte-identical afterwards, group state and registry alike.
#[test]
fn import_dry_run_writes_nothing() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    run_pw(a, &["hd-secret", "grp", "create", "vpn"]);
    let file = a.join("grp.export");
    export_group(a, "grp", &file);

    let before = tree_snapshot(b);
    let mut args = import_args(file.to_str().unwrap(), "p0").to_vec();
    args.push("--dry-run");
    let out = run_pw(b, &args);
    assert!(out.contains("new"), "the diff is still rendered:\n{out}");
    assert!(out.contains("--dry-run: nothing was written"), "{out}");
    assert_eq!(before, tree_snapshot(b), "--dry-run must write nothing");
}

// An export is a snapshot of *one member's* registry, not group-wide truth. So
// it merges rather than replaces and because `classify` is epoch-versioned,
// importing both members' exports converges them, exactly as applying both
// members' share tokens would.
#[test]
fn two_exports_converge_the_registries() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // Each holds a definition the other has never seen (neither shared a token)
    run_pw(a, &["hd-secret", "grp", "create", "only-a"]);
    run_pw(b, &["hd-secret", "grp", "create", "only-b"]);

    // Snapshot both files before either import, so neither carries the other's
    let file_a = a.join("a.export");
    let file_b = b.join("b.export");
    export_group(a, "grp", &file_a);
    export_group(b, "grp", &file_b);

    run_import(b, &import_args(file_a.to_str().unwrap(), "p0"), "y");
    run_import(a, &import_args(file_b.to_str().unwrap(), "p1"), "y");

    for id in ["only-a", "only-b"] {
        assert_eq!(
            hd_secret_of(a, "grp", id),
            hd_secret_of(b, "grp", id),
            "{id} diverged"
        );
    }
}

// A locally-newer epoch is reported stale and never overwritten. Nothing is
// applied, and the message does not claim the registry was already complete.
#[test]
fn import_reports_a_stale_change_and_keeps_the_local_row() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    run_pw(a, &["hd-secret", "grp", "create", "site"]);
    apply_ok(b, &share_token(a, "grp", "site"), "y\n"); // both at epoch 1
    run_pw(a, &["hd-secret", "grp", "rotate", "site"]); // A moves to epoch 2
    let after_rotate = hd_secret_of(a, "grp", "site");

    let file = b.join("b.export"); // still at epoch 1
    export_group(b, "grp", &file);
    let out = run_pw(a, &import_args(file.to_str().unwrap(), "p1"));

    assert!(out.contains("stale"), "{out}");
    assert!(out.contains("local epoch 2 > 1 incoming"), "{out}");
    assert!(
        out.contains("stale or conflicting"),
        "must not claim it was up to date:\n{out}"
    );
    assert_eq!(
        hd_secret_of(a, "grp", "site"),
        after_rotate,
        "the local row must survive"
    );
}

// A same-epoch content difference is a conflict. `registry.rs` already declares
// it a thing the *user* must resolve, and `hd-secret apply` is the existing UI
// for exactly one such decision, so `import` reports it, skips it, and points
// there rather than growing a second, worse resolver.
#[test]
fn import_reports_a_conflict_skips_it_and_keeps_the_local_row() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // Concurrent creates: same (id, user), same epoch 1, different params
    run_pw(
        a,
        &[
            "hd-secret",
            "grp",
            "create",
            "dropbox.com",
            "--length",
            "14",
        ],
    );
    run_pw(
        b,
        &[
            "hd-secret",
            "grp",
            "create",
            "dropbox.com",
            "--length",
            "20",
        ],
    );
    let mine = hd_secret_of(a, "grp", "dropbox.com");
    assert_eq!(mine.chars().count(), 14);

    let file = b.join("b.export");
    export_group(b, "grp", &file);
    let out = run_pw(a, &import_args(file.to_str().unwrap(), "p1"));

    assert!(out.contains("conflict"), "{out}");
    assert!(out.contains("params differ"), "{out}");
    assert!(
        out.contains("hd-secret grp share dropbox.com"),
        "points at the resolver:\n{out}"
    );
    assert_eq!(
        hd_secret_of(a, "grp", "dropbox.com"),
        mine,
        "the local row must survive"
    );
}

// If the group is already here it must be the *same* group. A member set that
// disagrees is not a merge; it is a different group wearing the same name.
#[test]
fn import_refuses_a_local_group_whose_member_set_disagrees() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    let file = a.join("grp.export");
    export_group(a, "grp", &file);

    // B pins A a second time under another alias. The *identities* are unchanged,
    // so the wrap key still opens the file, only the stored aliases disagree.
    let a_token = field(&run_ok(a, &["keypair", "show", "me"]), "Contact token");
    run_ok(b, &["contact", "add", &a_token, "--name", "again"]);

    sesh_pw(b)
        .args(import_args(file.to_str().unwrap(), "again"))
        .assert()
        .failure()
        .stderr(contains("already exists here with members p0, not again"))
        .stderr(contains("shared-secret remove grp"));
}

// `RESERVED_NAMES` is untouched: the new verbs hang off `shared-secret`, which
// is `subcommand_required` with no bare-owner positional. A keystore holding a
// group named `export` keeps working, including `shared-secret export export`.
#[test]
fn a_group_named_export_still_lists_shows_exports_and_removes() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "export");

    assert!(run_ok(a, &["shared-secret", "list"]).contains("export"));
    assert_eq!(
        field(&run_ok(a, &["shared-secret", "show", "export"]), "Name"),
        "export"
    );

    let file = a.join("e.export");
    let out = export_group(a, "export", &file);
    assert!(out.contains("Group \"export\""), "{out}");
    assert!(file.is_file());

    run_ok(a, &["shared-secret", "remove", "export"]);
    assert!(run_ok(a, &["shared-secret", "list"]).contains("(no shared secrets)"));
}

// `export` and `import` both unlock a seed, so both prompt. With no stdin the
// prompt reads EOF, takes the empty password, and fails to decrypt, which is
// what makes the `run_pw` call sites above load-bearing rather than superstition.
//
// `shared-secret show` stays password-free; `password_free_commands_never_prompt`
// pins that, and neither new verb was allowed to drift into it.
#[test]
fn export_and_import_prompt_for_a_password() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");
    let file = a.join("grp.export");
    export_group(a, "grp", &file);
    let arg = file.to_str().unwrap();

    for (home, args) in [
        (a, vec!["shared-secret", "export", "grp", arg]),
        (b, import_args(arg, "p0").to_vec()),
    ] {
        sesh(home)
            .args(&args)
            .assert()
            .failure()
            .stderr(contains("Decryption failed"));
    }
}

// **Merge order is load-bearing.** `Registry::adopt` files the superseded local
// recipe under its own epoch; the incoming archive is absorbed *after*, so
// first-writer-wins keeps yours. Absorb first and the peer's recipe would win
// that epoch, silently rewriting the local recovery history `archive_push`'s
// dedup exists to protect.
//
// A wins epoch 2 with a 14-character recipe; B's export carries a 20-character
// recipe for the same epoch. After importing B's newer epoch 3, `copy --recover
// 2` must still render A's password.
#[test]
fn an_imported_archive_never_rewrites_local_recovery_history() {
    let homes = wire_group(&["a", "b"]);
    let (a, b) = (homes[0].path(), homes[1].path());
    form_group(a, b, "grp");

    // Concurrent creates, deliberately different recipes
    run_pw(a, &["hd-secret", "grp", "create", "site", "--length", "14"]);
    run_pw(b, &["hd-secret", "grp", "create", "site", "--length", "20"]);
    run_pw(a, &["hd-secret", "grp", "rotate", "site"]); // A: epoch 2, archives 1
    run_pw(b, &["hd-secret", "grp", "rotate", "site"]); // B: epoch 2, archives 1
    run_pw(b, &["hd-secret", "grp", "rotate", "site"]); // B: epoch 3, archives 2

    // A's own passwords at every epoch it has ever held
    let a_e1 = hd_secret_at(a, "grp", "site", "1");
    let a_e2 = hd_secret_at(a, "grp", "site", "2"); // the live entry, for now
    assert_eq!(a_e1.chars().count(), 14);
    assert_eq!(a_e2.chars().count(), 14);

    let file = b.join("b.export");
    export_group(b, "grp", &file);
    let out = run_import(a, &import_args(file.to_str().unwrap(), "p1"), "y");
    assert!(out.contains("update"), "epoch 3 > 2 is adopted:\n{out}");

    // A now runs B's recipe going forward...
    assert_eq!(hd_secret_of(a, "grp", "site").chars().count(), 20);
    // ...but every past epoch still renders exactly the password A had
    assert_eq!(
        hd_secret_at(a, "grp", "site", "1"),
        a_e1,
        "epoch 1 was rewritten"
    );
    assert_eq!(
        hd_secret_at(a, "grp", "site", "2"),
        a_e2,
        "epoch 2 was rewritten"
    );
}
