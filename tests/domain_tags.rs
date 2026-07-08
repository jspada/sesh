//! Pins the domain-tag rule the whole tree depends on:
//!
//! - **AAD and signature-message tags** name a domain only. The version is a
//!   number bound alongside them, so the two can never drift out of step.
//! - **KDF and derivation domain tags** are frozen literals, version suffix and
//!   all: renaming one re-keys or re-derives everything it has ever touched.
//!
//! So a `sesh-...-vN` literal anywhere in `src/` is a claim to be in the second
//! group. This test enumerates the ones that are, and fails on any newcomer,
//! which is exactly what a version suffix creeping back onto an AAD tag looks
//! like.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

// Every `sesh-...-vN` literal that is legitimately frozen
const FROZEN_DERIVATION_TAGS: &[&str] = &[
    // keystore.rs - the registry encryption key's KDF domain
    "sesh-registry-key-v1",
    // protocol.rs - the group context and the per-group child signature domain
    "sesh-group-v1",
    "sesh-group-key-v1",
    // crypto.rs - every DST_*, the wrap-key KDFs, and the checksum's own domain
    "sesh-secret-g1-v1",
    "sesh-secret-gt-v1",
    "sesh-hd-v1",
    "sesh-group-child-v1",
    "sesh-fpr-identity-v1",
    "sesh-fpr-group-v1",
    "sesh-fpr-hd-v1",
    "sesh-fpr-hd-recipe-v1",
    "sesh-share-wrap-v1",
    "sesh-setup-wrap-v1",
    "sesh-agreement-checksum-v1",
];

// Every `sesh-...` string literal in `src`, whatever its shape
fn sesh_literals(src: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let bytes = text.as_bytes();
        for (i, _) in text.match_indices("\"sesh-") {
            let start = i + 1;
            if let Some(len) = bytes[start..].iter().position(|&b| b == b'"') {
                found.insert(text[start..start + len].to_string());
            }
        }
    }
    found
}

// A literal ends in a version suffix (`-v` followed by digits)
fn has_version_suffix(literal: &str) -> bool {
    match literal.rsplit_once("-v") {
        Some((_, tail)) => !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

#[test]
fn only_derivation_tags_carry_a_version_suffix() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let versioned: BTreeSet<String> = sesh_literals(&src)
        .into_iter()
        .filter(|l| has_version_suffix(l))
        .collect();
    let expected: BTreeSet<String> = FROZEN_DERIVATION_TAGS
        .iter()
        .map(|s| s.to_string())
        .collect();

    let unexpected: Vec<&String> = versioned.difference(&expected).collect();
    assert!(
        unexpected.is_empty(),
        "these tags carry a version suffix they do not control - an AAD or \
         signature-message tag must name a domain only, and bind its version as \
         a number beside it: {unexpected:?}"
    );
    let missing: Vec<&String> = expected.difference(&versioned).collect();
    assert!(
        missing.is_empty(),
        "a frozen derivation tag vanished - renaming one re-derives every key it \
         ever produced: {missing:?}"
    );
}
