//! # OBOLOS — the FANOS private, untraceable, post-quantum currency
//!
//! *Greek ὀβολός, an ancient coin; its shielding machinery is **SKIA** (σκιά, "shadow").* OBOLOS is the value
//! tier of the FANOS platform (`spec/platform.md` §4): a **shielded-pool** cryptocurrency whose anonymity set
//! is the *whole pool* (strictly larger than Monero's fixed rings), instantiated **post-quantum** end to end,
//! and running as a state machine on the TAXIS blockchain — so a payment is hidden at two independent layers at
//! once: SKIA hides the *ledger* linkage (which note paid which), while APHANTOS + the anti-MEV encrypted
//! mempool hide the *network* linkage (who submitted, in what order) — the E∧L composition made spendable.
//!
//! A private currency must deliver three orthogonal properties, all **E** (interiority) facts enforced by **L**
//! (a zero-knowledge proof), in the ХОЛАРХ reading:
//!
//! | Property | hides | this crate's machinery |
//! |---|---|---|
//! | **Confidentiality** | the amount | a lattice additively-homomorphic **value commitment** (`commit`, forthcoming) |
//! | **Untraceability** | which note was spent | a whole-pool membership proof over the **commitment tree** ([`tree`]) + a **nullifier** ([`nullifier`]) |
//! | **Unlinkability** | the recipient | one-time note keys from a hybrid-KEM stealth address (`note`, forthcoming) |
//!
//! **Status discipline (`spec/platform.md` §9).** The *accounting* — the note-commitment tree, the nullifier
//! set, the balance homomorphism — is fully implementable and **verified here**. The single frontier component,
//! the post-quantum zero-knowledge shielded-transaction proof, is isolated behind a typed interface and tagged
//! **[P]/[H]** (it needs cryptanalysis); it is never claimed as done. **No new cryptographic hardness is
//! invented** — OBOLOS composes vetted post-quantum primitives (BLAKE3 for the tree/nullifiers, a Module-SIS
//! lattice commitment for value, ML-KEM for stealth keys) exactly as the rest of the platform does.
//!
//! Landed so far: the **untraceability accounting** — the append-only commitment tree ([`tree`]) a spend
//! proves membership in, and the nullifier set ([`nullifier`]) that makes a double-spend detectable while
//! keeping the spent note unlinkable — and the **confidentiality** primitive: the additively-homomorphic
//! lattice value [`commit`]ment that hides amounts while keeping the balance law checkable. All are exact,
//! deterministic, and unit-tested; the note / stealth-address model and the shielded transaction (with the
//! frontier zero-knowledge proof isolated behind a typed interface) compose on top in the following increments.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod build;
pub mod codec;
pub mod commit;
pub mod note;
pub mod note_cipher;
pub mod nullifier;
pub mod state;
pub mod tree;
pub mod tx;

pub use build::{SpendInput, build_transfer};
pub use codec::{decode_submission, encode_submission};
pub use commit::{Commitment, Params, Randomness, sum, sum_randomness, verify_balance};
pub use note::{Note, derive_owner_pk};
pub use note_cipher::{Address, NoteCipher, scan};
pub use nullifier::{Nullifier, NullifierSet};
pub use state::{ApplyError, ShieldedState};
pub use tree::{AuthPath, CommitmentTree, TREE_DEPTH};
pub use tx::{InputOpening, OutputNote, OutputOpening, ShieldedProof, ShieldedTx, TransparentProof};
