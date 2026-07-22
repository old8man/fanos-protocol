//! # fanos-taxis — the FANOS-native BFT blockchain (spec Part X.1, roadmap M7)
//!
//! **TAXIS** (τάξις, "order / arrangement") is FANOS's consensus-ordering and ledger layer. It does not
//! invent a new consensus — it *derives* one from the projective geometry load-bearing everywhere else in
//! FANOS, and composes primitives that already exist: the projective erasure code and data-availability
//! sampler ([`fanos_code`]), the threshold KEM-seal ([`fanos_aphantos::ThresholdSealed`]), the epoch beacon
//! and hashing ([`fanos_primitives`]), hybrid-PQ signatures ([`fanos_pqcrypto`]), and anonymous VOPRF
//! credits ([`fanos_incentives`]). The full derivation is `docs/design-taxis.md`.
//!
//! The pieces:
//! * [`params`] — the projective cell's PBFT quorum system `(n, f, Q)`, proved safe + live.
//! * [`committee`] — beacon leader election and line-committee selection (cartel-proof by construction).
//! * [`tx`] — transactions and the threshold-**sealed** transaction (the anti-MEV unit).
//! * [`mempool`] — the encrypted mempool: seal-on-submit, order-over-commitments, open-on-commit.
//! * [`block`] — the block, its hash-linking, and the DA (data-availability) commitment.
//! * [`vote`] — signed votes and the quorum certificate.
//! * [`state`] — the pluggable [`state::StateMachine`] and a reference account instantiation.
//! * [`chain`] — the finalized chain and its state root.
//! * [`consensus`] — the sans-I/O PBFT engine (propose → prepare → commit → reveal, with round advance).
//! * [`wire`] — the canonical wire messages (`Propose` / `Vote` / `Reveal`), `#[derive(Wire)]`.

#![forbid(unsafe_code)]

extern crate alloc;

pub mod block;
pub mod chain;
pub mod checkpoint;
pub mod committee;
pub mod consensus;
pub mod incentive;
pub mod params;
pub mod state;
pub mod tx;
pub mod vote;
pub mod wire;

pub use block::{Block, BlockHeader, GENESIS_PARENT};
pub use chain::Chain;
pub use checkpoint::{ExecCertificate, ExecVote};
pub use consensus::{ConsensusEngine, ConsensusMsg, Input, Output, RevealMsg};
pub use incentive::{RewardParams, SlashEvidence, best_response_is_honest, detect_equivocation};
pub use params::CellParams;
pub use state::{Accounts, ExecOutcome, StateMachine, Transfer};
pub use tx::{SealedTx, Transaction, TxCommit};
pub use vote::{Certificate, Phase, SignedVote, Vote};
