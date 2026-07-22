//! # HERMES — the post-quantum threshold cross-chain
//!
//! *Greek Ἑρμῆς, the crosser of boundaries — god of travel, commerce, and messengers.* HERMES is the platform's
//! cross-chain tier (`spec/platform.md` §8): a **federation**, not a deeper recursive tier (ХОЛАРХ's depth
//! ceiling — beyond depth 2, federate). Its synthesis is two composable modes:
//!
//! 1. **PQ hash-locked atomic swaps** — trustless, no custody, for chains that support hashlocks. This module,
//!    [`htlc`], is that primitive: a hash time-locked contract whose lock is a **hash preimage** (post-quantum
//!    secure — a hash preimage has no quantum shortcut), so two parties swap value across chains with atomicity
//!    guaranteed by the shared hashlock and the timelock, and no trusted intermediary.
//! 2. **Threshold-attested custody** — for chains without hashlocks, a FANOS cell's BFT quorum jointly controls
//!    a foreign address (reusing the built DKG + threshold signing), and a cross-chain transfer becomes a
//!    TAXIS-attested event — an instance of cross-*cell* where the far cell is another chain. (Follows on top.)
//!
//! This first increment is the atomic-swap primitive, exact and unit-tested; the ledger settlement (a DROMOS
//! tag releasing escrow on a preimage reveal) and the threshold-custody mode compose on top.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod htlc;

pub use htlc::{Htlc, HtlcState, HtlcTerms, Resolution, hashlock};
