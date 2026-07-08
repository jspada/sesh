//! Interactive shared-secret exchange wizard.
//!
//! All terminal I/O goes through the [`Terminal`] trait so the state machine can
//! be driven by scripted input in tests with no real TTY. The wizard shows your
//! own setup token, then walks you through pasting each peer's token, verifying
//! its integrity checksum, advisory group name, per-group signature (against the
//! pinned contact), child-key disjointedness, and (3-party) DH-pair consistency.
//! Any failing check explains itself and re-prompts for that peer's token (a
//! rejected token is never used, so retrying is safe); once every check passes
//! the wizard moves on by itself. It ends by confirming the agreement checksum
//! before the secret is stored.
//!
//! Trust rests on the pinned contacts and the per-group signatures, never on the
//! integrity checksum (which only catches a mistyped paste).

use std::fmt;
use std::io::{self, Write};

use blstrs::Scalar;

use crate::crypto::{PublicIdentity, SEED_BYTES};
use crate::protocol::{
    self, derive_group_key, group_ctx, Parties, ProtocolError, Purpose, SetupToken,
};

/// SGR parameter string for "you" (white)
const C_YOU: &str = "97";
/// SGR parameter strings cycled per peer (24-bit truecolor): party 1 = pastel
/// orange, party 2 = pastel blue. The header colour-codes each party with the
/// same colour it carries in its step below.
const C_PARTY: [&str; 2] = ["38;2;245;190;130", "38;2;150;200;240"];
/// SGR parameter string for a passing check mark (green)
const C_OK: &str = "92";
/// SGR parameter string for a failing check mark (red)
const C_ERR: &str = "91";

/// Wrap `s` in an ANSI SGR sequence when enabled and a color is selected
fn paint(enabled: bool, sgr: Option<&str>, s: &str) -> String {
    match (enabled, sgr) {
        (true, Some(code)) => format!("\x1b[{code}m{s}\x1b[0m"),
        _ => s.to_string(),
    }
}

/// Terminal abstraction: colored line output, line prompts, yes/no, press-enter
pub trait Terminal {
    /// Set the active SGR color for subsequent output (`None` = default)
    fn set_color(&mut self, _sgr: Option<&'static str>) {}
    /// Emit an informational line
    fn write_line(&mut self, msg: &str);
    /// Render `s` so it stands out (i.e. with light blue) when colour is enabled; plain
    /// otherwise. Used inline within a line, restoring the line's base colour
    /// afterward so only `s` is recoloured.
    fn emphasize(&self, s: &str) -> String {
        s.to_string()
    }
    /// Emit one verification-check result line: a ✓/✗ mark plus explanation
    fn write_check(&mut self, ok: bool, msg: &str) {
        self.write_line(&format!("{} {msg}", if ok { "✓" } else { "✗" }));
    }
    /// Show `prompt` and read one line of input (trimmed)
    fn prompt_line(&mut self, prompt: &str) -> io::Result<String>;
    /// Show `prompt` and read a yes/no answer (default no)
    fn confirm(&mut self, prompt: &str) -> io::Result<bool> {
        let ans = self.prompt_line(prompt)?;
        let a = ans.trim().to_ascii_lowercase();
        Ok(a == "y" || a == "yes")
    }
    /// Show `prompt` and wait for the user to press enter.
    fn press_enter(&mut self, prompt: &str) -> io::Result<()> {
        self.prompt_line(prompt)?;
        Ok(())
    }
}

/// Real terminal: prompts/lines to stderr, reads from stdin. Colors are enabled
/// only when stderr is a TTY and `NO_COLOR` is unset
pub struct StdioTerminal {
    color_enabled: bool,
    current: Option<&'static str>,
}

impl StdioTerminal {
    /// Create a stdio-backed terminal
    pub fn new() -> Self {
        use std::io::IsTerminal;
        let color_enabled = io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        StdioTerminal {
            color_enabled,
            current: None,
        }
    }
}

impl Default for StdioTerminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminal for StdioTerminal {
    fn set_color(&mut self, sgr: Option<&'static str>) {
        self.current = sgr;
    }

    fn write_line(&mut self, msg: &str) {
        eprintln!("{}", paint(self.color_enabled, self.current, msg));
    }

    fn emphasize(&self, s: &str) -> String {
        // Bold, bright *light* blue (a luminous azure) for `s` (vivid and
        // light, but more saturated than party 2's pale pastel blue) then
        // restore the surrounding line colour.
        if self.color_enabled {
            let back = self.current.unwrap_or("0");
            format!("\x1b[1;38;2;80;195;255m{s}\x1b[22;{back}m")
        } else {
            s.to_string()
        }
    }

    fn write_check(&mut self, ok: bool, msg: &str) {
        // The mark carries the verdict color (green ✓ / red ✗); the
        // explanation stays white regardless of the active party color.
        let (mark, mark_color) = if ok { ("✓", C_OK) } else { ("✗", C_ERR) };
        eprintln!(
            "  {} {}",
            paint(self.color_enabled, Some(mark_color), mark),
            paint(self.color_enabled, Some(C_YOU), msg),
        );
    }

    fn prompt_line(&mut self, prompt: &str) -> io::Result<String> {
        // Keep the SGR color active while the line is read, so the input the
        // terminal echoes takes the same color as the prompt; reset only after.
        let colored = self.color_enabled && self.current.is_some();
        match (colored, self.current) {
            (true, Some(code)) => eprint!("\x1b[{code}m{prompt}"),
            _ => eprint!("{prompt}"),
        }
        io::stderr().flush()?;
        let mut line = String::new();
        let read = io::stdin().read_line(&mut line);
        if colored {
            eprint!("\x1b[0m");
            let _ = io::stderr().flush();
        }
        if read? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "end of input"));
        }
        Ok(line.trim().to_string())
    }
}

/// Errors from the wizard
#[derive(Debug)]
pub enum WizardError {
    /// The user declined a confirmation (continue or final checksum)
    Aborted,
    /// A protocol-level failure outside the per-peer retry loop
    Protocol(ProtocolError),
    /// An I/O failure reading input
    Io(io::Error),
}

impl fmt::Display for WizardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WizardError::Aborted => write!(f, "aborted"),
            WizardError::Protocol(e) => write!(f, "{e}"),
            WizardError::Io(e) => write!(f, "input error: {e}"),
        }
    }
}

impl std::error::Error for WizardError {}

impl From<ProtocolError> for WizardError {
    fn from(e: ProtocolError) -> Self {
        WizardError::Protocol(e)
    }
}
impl From<io::Error> for WizardError {
    fn from(e: io::Error) -> Self {
        WizardError::Io(e)
    }
}

/// Everything the wizard needs to drive one group exchange
pub struct GroupPlan<'a> {
    /// The local identity name (for display)
    pub keypair_name: &'a str,
    /// The agreed group name (bound into `group_ctx`)
    pub group_name: &'a str,
    /// My own long-term public identity
    pub self_public: &'a PublicIdentity,
    /// The peers, in party order: `(contact alias, pinned public identity)`
    pub contacts: &'a [(String, PublicIdentity)],
    /// My identity seed (never displayed)
    pub seed: &'a [u8; SEED_BYTES],
}

/// The result of a successful exchange: the derived secret and the verified
/// peer tokens (to persist as group state).
pub struct WizardOutcome {
    /// The derived per-group secret `K`
    pub secret: Scalar,
    /// The verified peer setup tokens, aligned to `plan.contacts`
    pub peer_tokens: Vec<SetupToken>,
    /// This party's own setup token (already shown; handy for the caller)
    pub my_token: String,
}

/// Drive the interactive exchange to completion, returning the derived secret.
///
/// Aborts (returning [`WizardError`]) only on a declined continue / final
/// confirmation or end of input. Every failing per-peer check, (e.g. mistyped
/// token, wrong group name, signature / disjointness / consistency failure)
/// explains itself and re-prompts for that peer's token: a rejected token is
/// never used, so retrying (e.g. after pasting the wrong member's token into
/// a slot) is safe.
pub fn run_wizard<T: Terminal>(
    term: &mut T,
    plan: &GroupPlan,
) -> Result<WizardOutcome, WizardError> {
    let n_peers = plan.contacts.len();
    let parties = Parties::from_u8((n_peers + 1) as u8)?;

    // Full member set (self + contacts) -> shared group context
    let mut members = Vec::with_capacity(n_peers + 1);
    members.push(plan.self_public.clone());
    for (_, pk) in plan.contacts {
        members.push(pk.clone());
    }
    // Every stored group's context uses the sole `Master` purpose
    let ctx = group_ctx(Purpose::Master, plan.group_name, &members)?;

    // The setup-token wrap key: shared by all members (derived from the
    // pinned long-term keys), so my sealed token opens for every peer and
    // theirs open for me, while an eavesdropper cannot open any of them.
    let others: Vec<PublicIdentity> = plan.contacts.iter().map(|(_, pk)| pk.clone()).collect();
    let wrap_key = protocol::setup_wrap_key(plan.seed, &others, &members)?;

    // My own token
    let my_token = SetupToken::create(plan.seed, Purpose::Master, plan.group_name, &members)?;
    let my_token_str = my_token.encode(&wrap_key);

    // Header
    term.set_color(Some(C_YOU));
    term.write_line(&format!(
        "\nForming \"{}\"  ·  {} parties (you + {})",
        plan.group_name,
        parties.as_u8(),
        n_peers
    ));
    term.write_line(&format!("  you     {}", plan.keypair_name));
    for (i, (alias, _)) in plan.contacts.iter().enumerate() {
        // Colour each party with the same colour it will carry in its step below
        term.set_color(Some(C_PARTY[i.min(C_PARTY.len() - 1)]));
        term.write_line(&format!("  party {} {}   (pinned contact)", i + 1, alias));
    }
    term.set_color(Some(C_YOU));
    if !term.confirm("\nContinue? [y/N] ")? {
        return Err(WizardError::Aborted);
    }

    // Step 1: your token
    let last_step = 2 + n_peers; // step 1 (you) + one per peer + final confirmation
    term.set_color(Some(C_YOU));
    term.write_line("\nStep 1: Share YOUR setup token with the group");
    term.write_line(&format!("  > Your setup token: {my_token_str}"));
    term.press_enter("\nPress enter to continue ")?;

    // Steps 2 ... (1 + n_peers): each peer
    let mut peer_tokens = Vec::with_capacity(n_peers);
    for (i, (alias, contact)) in plan.contacts.iter().enumerate() {
        let color = C_PARTY[i.min(C_PARTY.len() - 1)];
        term.set_color(Some(color));
        term.write_line(&format!("\nStep {}: Enter {}'s setup token", i + 2, alias));

        // Any failing check explains itself and re-prompts; a rejected token
        // is never used, so retrying is safe.
        let token = loop {
            let pasted = term.prompt_line("  > ")?;
            let token = match SetupToken::decode(&pasted, parties, &wrap_key) {
                Ok(t) => t,
                Err(e) => {
                    term.write_check(false, &format!("{e} - try pasting again"));
                    continue;
                }
            };
            term.write_check(true, "token intact and sealed for this group");

            // Advisory name-match (the authoritative name is always ours). The
            // foreign name is peer-authored and shown before any signature
            // check, so escape it. It must not be able to redraw this prompt.
            if token.group_name != plan.group_name {
                term.write_check(
                    false,
                    &format!(
                        "token is for group \"{}\", not \"{}\" - wrong token? try again",
                        crate::format::escape_control(&token.group_name),
                        plan.group_name
                    ),
                );
                continue;
            }
            term.write_check(true, &format!("group name matches \"{}\"", plan.group_name));

            // Signature + child-key disjointness + (3-party) DH-pair consistency
            if let Err(e) = token.verify(&ctx, &contact.sig_g1, &members) {
                term.write_check(
                    false,
                    &format!("{e} - is this really {alias}'s token for this group? try again"),
                );
                continue;
            }
            term.write_check(
                true,
                &format!("signature verifies against pinned contact '{alias}'"),
            );
            break token;
        };
        peer_tokens.push(token);
    }

    term.set_color(Some(C_YOU));
    term.write_line("\nAll members verified and approved.");

    // Derive K (all peers verified above)
    let my_child = SetupToken::my_child_scalar(plan.seed, &ctx);
    let secret = derive_group_key(&my_child, &peer_tokens)?;

    // Step final: agreement checksum
    term.set_color(Some(C_YOU));
    term.write_line(&format!(
        "\nStep {last_step}: Confirm the checksum is consistent across group members\n"
    ));
    // The whole line is white; only the checksum itself is emphasized (bright)
    term.set_color(Some(C_YOU));
    let checksum = term.emphasize(&protocol::checksum(&secret));
    term.write_line(&format!(
        "  > Checksum: {checksum} (share this with your group)\n"
    ));
    if !term.confirm("All confirmed? [y/N] ")? {
        return Err(WizardError::Aborted);
    }
    term.write_line("\n");

    Ok(WizardOutcome {
        secret,
        peer_tokens,
        my_token: my_token_str,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::public_identity_from_seed;
    use std::collections::VecDeque;

    // Scripted terminal: canned input lines, captured output
    struct Scripted {
        inputs: VecDeque<String>,
        output: Vec<String>,
    }

    impl Scripted {
        fn new(lines: &[&str]) -> Self {
            Scripted {
                inputs: lines.iter().map(|s| s.to_string()).collect(),
                output: Vec::new(),
            }
        }
        fn joined(&self) -> String {
            self.output.join("\n")
        }
    }

    impl Terminal for Scripted {
        fn write_line(&mut self, msg: &str) {
            self.output.push(msg.to_string());
        }
        fn prompt_line(&mut self, prompt: &str) -> io::Result<String> {
            self.output.push(prompt.to_string());
            self.inputs
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no more input"))
        }
    }

    fn seed(b: u8) -> [u8; SEED_BYTES] {
        [b; SEED_BYTES]
    }

    // Build a plan for `me` (seed `self_b`) with peers given as (alias, seed)
    fn plan_for<'a>(
        self_b: u8,
        peers: &'a [(String, PublicIdentity)],
        seed_store: &'a [u8; SEED_BYTES],
        self_pub: &'a PublicIdentity,
    ) -> GroupPlan<'a> {
        let _ = self_b;
        GroupPlan {
            keypair_name: "me",
            group_name: "grp",
            self_public: self_pub,
            contacts: peers,
            seed: seed_store,
        }
    }

    // The setup-token wrap key for `members`, computed from any member's seed
    // (identical for all-- that is the point).
    fn group_wrap_key(members: &[PublicIdentity], member_seed: &[u8; SEED_BYTES]) -> [u8; 32] {
        let me = public_identity_from_seed(member_seed);
        let others: Vec<PublicIdentity> = members.iter().filter(|m| **m != me).cloned().collect();
        protocol::setup_wrap_key(member_seed, &others, members).unwrap()
    }

    // A token by `signer_seed` over `members`, sealed under the group wrap key
    // (which the test computes via a real member `viewer_seed`).
    fn sealed_token(
        signer_seed: &[u8; SEED_BYTES],
        group: &str,
        members: &[PublicIdentity],
        viewer_seed: &[u8; SEED_BYTES],
    ) -> String {
        let wk = group_wrap_key(members, viewer_seed);
        SetupToken::create(signer_seed, Purpose::Master, group, members)
            .unwrap()
            .encode(&wk)
    }

    // A peer's token string, given the FULL member set and the peer's seed
    fn peer_token(peer_seed: &[u8; SEED_BYTES], members: &[PublicIdentity]) -> String {
        sealed_token(peer_seed, "grp", members, peer_seed)
    }

    #[test]
    fn paint_wraps_only_when_enabled() {
        assert_eq!(
            paint(true, Some("38;5;214"), "hi"),
            "\x1b[38;5;214mhi\x1b[0m"
        );
        assert_eq!(paint(false, Some("94"), "hi"), "hi");
        assert_eq!(paint(true, None, "hi"), "hi");
    }

    #[test]
    fn two_party_success() {
        let (a, b) = (seed(1), seed(2));
        let pa = public_identity_from_seed(&a);
        let pb = public_identity_from_seed(&b);
        let members = [pa.clone(), pb.clone()];
        let tok_b = peer_token(&b, &members);

        let contacts = vec![("bob".to_string(), pb)];
        let plan = plan_for(1, &contacts, &a, &pa);
        // continue, press-enter, token, final-confirm
        let mut term = Scripted::new(&["y", "", &tok_b, "y"]);
        let out = run_wizard(&mut term, &plan).unwrap();
        assert_eq!(out.peer_tokens.len(), 1);
        // Secret matches B's independent derivation
        let ctx = group_ctx(Purpose::Master, "grp", &members).unwrap();
        let kb = derive_group_key(
            &SetupToken::my_child_scalar(&b, &ctx),
            &[SetupToken::create(&a, Purpose::Master, "grp", &members).unwrap()],
        )
        .unwrap();
        assert_eq!(out.secret, kb);
    }

    #[test]
    fn three_party_success() {
        let (a, b, c) = (seed(1), seed(2), seed(3));
        let (pa, pb, pc) = (
            public_identity_from_seed(&a),
            public_identity_from_seed(&b),
            public_identity_from_seed(&c),
        );
        let members = [pa.clone(), pb.clone(), pc.clone()];
        let tok_b = peer_token(&b, &members);
        let tok_c = peer_token(&c, &members);

        let contacts = vec![("bob".to_string(), pb), ("carol".to_string(), pc)];
        let plan = plan_for(1, &contacts, &a, &pa);
        let mut term = Scripted::new(&["y", "", &tok_b, &tok_c, "y"]);
        let out = run_wizard(&mut term, &plan).unwrap();
        assert_eq!(out.peer_tokens.len(), 2);
    }

    #[test]
    fn mistyped_token_reprompts_same_peer() {
        let (a, b) = (seed(1), seed(2));
        let pa = public_identity_from_seed(&a);
        let pb = public_identity_from_seed(&b);
        let members = [pa.clone(), pb.clone()];
        let good = peer_token(&b, &members);
        // Corrupt one char to break the checksum
        let mut chars: Vec<char> = good.chars().collect();
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let bad: String = chars.into_iter().collect();

        let contacts = vec![("bob".to_string(), pb)];
        let plan = plan_for(1, &contacts, &a, &pa);
        // continue, enter, BAD token (re-prompt), GOOD token, final
        let mut term = Scripted::new(&["y", "", &bad, &good, "y"]);
        let out = run_wizard(&mut term, &plan).unwrap();
        assert_eq!(out.peer_tokens.len(), 1);
        assert!(term.joined().contains("try pasting again"));
    }

    #[test]
    fn declined_continue_aborts() {
        let (a, b) = (seed(1), seed(2));
        let pa = public_identity_from_seed(&a);
        let pb = public_identity_from_seed(&b);
        let contacts = vec![("bob".to_string(), pb)];
        let plan = plan_for(1, &contacts, &a, &pa);
        let mut term = Scripted::new(&["n"]);
        assert!(matches!(
            run_wizard(&mut term, &plan),
            Err(WizardError::Aborted)
        ));
    }

    #[test]
    fn final_confirmation_decline_aborts() {
        let (a, b) = (seed(1), seed(2));
        let pa = public_identity_from_seed(&a);
        let pb = public_identity_from_seed(&b);
        let members = [pa.clone(), pb.clone()];
        let tok_b = peer_token(&b, &members);
        let contacts = vec![("bob".to_string(), pb)];
        let plan = plan_for(1, &contacts, &a, &pa);
        let mut term = Scripted::new(&["y", "", &tok_b, "n"]);
        assert!(matches!(
            run_wizard(&mut term, &plan),
            Err(WizardError::Aborted)
        ));
    }

    #[test]
    fn wrong_member_token_in_slot_reprompts() {
        // 3-party: all members share the wrap key, so carol's token DECRYPTS in
        // bob's slot, but its signature verifies against carol, not the pinned
        // 'bob', so the signature check rejects it and the wizard re-prompts.
        let (a, b, c) = (seed(1), seed(2), seed(3));
        let (pa, pb, pc) = (
            public_identity_from_seed(&a),
            public_identity_from_seed(&b),
            public_identity_from_seed(&c),
        );
        let members = [pa.clone(), pb.clone(), pc.clone()];
        let tok_b = peer_token(&b, &members);
        let tok_c = peer_token(&c, &members);
        let contacts = vec![("bob".to_string(), pb), ("carol".to_string(), pc)];
        let plan = plan_for(1, &contacts, &a, &pa);
        // Step 2 (bob): carol's token -> sig fails -> reprompt with bob's;
        // Step 3 (carol): carol's token.
        let mut term = Scripted::new(&["y", "", &tok_c, &tok_b, &tok_c, "y"]);
        let out = run_wizard(&mut term, &plan).unwrap();
        assert_eq!(out.peer_tokens.len(), 2);
        assert!(term.joined().contains("is this really bob's token"));
    }

    #[test]
    fn outsider_token_fails_to_decrypt() {
        // An outsider cannot even produce a token that opens for the group.
        // It would fail AEAD authentication (a strictly stronger rejection than the
        // old signature-only check). The wizard re-prompts.
        let (a, b, outsider) = (seed(1), seed(2), seed(9));
        let (pa, pb) = (public_identity_from_seed(&a), public_identity_from_seed(&b));
        let members = [pa.clone(), pb.clone()];
        // Sealed under a DIFFERENT membership the group does not share
        let outsider_pub = public_identity_from_seed(&outsider);
        let foreign = [pa.clone(), outsider_pub.clone()];
        let tok_bad = sealed_token(&outsider, "grp", &foreign, &outsider);
        let tok_b = peer_token(&b, &members);
        let contacts = vec![("bob".to_string(), pb)];
        let plan = plan_for(1, &contacts, &a, &pa);
        let mut term = Scripted::new(&["y", "", &tok_bad, &tok_b, "y"]);
        let out = run_wizard(&mut term, &plan).unwrap();
        assert_eq!(out.peer_tokens.len(), 1);
        assert!(term.joined().contains("could not be decrypted"));
    }

    #[test]
    fn name_mismatch_reprompts_same_peer() {
        let (a, b) = (seed(1), seed(2));
        let pa = public_identity_from_seed(&a);
        let pb = public_identity_from_seed(&b);
        let members = [pa.clone(), pb.clone()];
        // B's token for a DIFFERENTLY-named group re-prompts; the right one
        // lands. (The wrap key binds membership, not the name, so this token
        // still decrypts and only the advisory name check rejects it.)
        let tok_b_other = sealed_token(&b, "other", &members, &b);
        let tok_b = peer_token(&b, &members);
        let contacts = vec![("bob".to_string(), pb)];
        let plan = plan_for(1, &contacts, &a, &pa);
        let mut term = Scripted::new(&["y", "", &tok_b_other, &tok_b, "y"]);
        let out = run_wizard(&mut term, &plan).unwrap();
        assert_eq!(out.peer_tokens.len(), 1);
        assert!(term.joined().contains("wrong token? try again"));
    }

    #[test]
    fn out_of_input_mid_retry_is_an_io_error() {
        // EOF while a peer's checks keep failing surfaces as Io, not a hang
        let (a, b, c) = (seed(1), seed(2), seed(3));
        let pa = public_identity_from_seed(&a);
        let pb = public_identity_from_seed(&b);
        let members = [pa.clone(), pb.clone()];
        // A token that decrypts (sealed under the group key) but whose signer
        // is not the pinned contact (i.e., a failing check) then EOF -> Io error.
        let tok_c = sealed_token(&c, "grp", &members, &a);
        let contacts = vec![("bob".to_string(), pb)];
        let plan = plan_for(1, &contacts, &a, &pa);
        let mut term = Scripted::new(&["y", "", &tok_c]);
        assert!(matches!(
            run_wizard(&mut term, &plan),
            Err(WizardError::Io(_))
        ));
    }
}
