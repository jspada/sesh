#![deny(missing_docs)]

//! `sesh` - "Secret Encrypted Shared Hierarchy".
//!
//! A small tool for establishing **2- and 3-party shared secrets** over
//! BLS12-381 with an encrypted local keystore:
//!
//! - **2-party** uses plain ECDH in `G1` (`ab * G1`)
//! - **3-party** uses the one-round, non-interactive [Joux] key agreement,
//!   yielding the symmetric pairing element `e(G1,G2)^{abc}`
//! - Both are turned into an output secret by a deterministic, unbiased
//!   hash-to-scalar ([`crypto::hash_to_scalar`])
//!
//! Identities are a single encrypted **seed** from which two domain-separated
//! subkeys are derived: a DH/Joux scalar and a BLS signing scalar. The keystore
//! location is resolved by [`config`] (`--keystore` > `$SESH_HOME` > a
//! `config.toml` pointer > `~/.sesh`); a local keystore is created and stamped
//! automatically on first write, while a `config.toml` pointer is never
//! auto-created.
//!
//! [Joux]: https://link.springer.com/chapter/10.1007/10722028_23

pub mod backup;
pub mod cli;
pub mod clipboard;
pub mod codec;
pub mod config;
pub mod crypto;
pub mod export;
pub mod format;
pub mod keystore;
pub mod protocol;
pub mod registry;
pub mod table;
pub mod terminal;
pub mod wizard;
