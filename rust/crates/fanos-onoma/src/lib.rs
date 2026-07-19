//! # fanos-onoma — the FANOS name system (ONOMA)
//!
//! ONOMA (Greek ὄνομα, "name") is the FANOS self-certifying naming layer — the equivalent of
//! `.onion` / `.i2p` / `.loki`, redesigned to be **post-quantum secure, unenumerable, leak-free,
//! and format-agile**. See `docs/design-names.md` for the full analysis.
//!
//! It is stratified so it escapes (rather than pretends to repeal) Zooko's Triangle:
//!
//! * **L-key** — [`Address`]: a self-certifying address that *commits* to a hybrid post-quantum
//!   key bundle (`BLAKE3-256`), encoded [`bech32m`](bech32) with a BCH checksum and a version byte
//!   so the whole recipe can change without a fork. This is the cryptographic ground truth.
//! * **L-pet** — [`zone`]: GNS/DNS-style **readable names & subdomains** via signed zones and
//!   delegation, needing no global consensus (names are relative to a trust root you choose).
//! * **L-global** — [`registry`]: an optional interface for **purchasable, globally-unique**
//!   readable names, with the settlement backend (the coherent chain, Phase 6) left pluggable.
//!
//! * [`derive`] — the per-epoch **lookup** and **encryption** derivations that make descriptors
//!   unenumerable and address-gated.
//! * [`mnemonic`] — a dictionary-free, pronounceable (proquint) rendering for human verification.
//!
//! `#![no_std]` with `alloc`; the only dependency chain is `fanos-primitives` (BLAKE3 + `MapToPoint`).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod address;
pub mod bech32;
pub mod derive;
pub mod error;
pub mod mnemonic;
pub mod name;
pub mod registry;
pub mod zone;

pub use address::{Address, COMMITMENT_LEN, DEFAULT_TLD, HRP};
pub use derive::{descriptor_key, lookup_key, lookup_point};
pub use error::OnomaError;
pub use fanos_primitives::Epoch;
pub use name::Name;
pub use registry::{Registration, Registry};
pub use zone::{Record, Target, Zone};
