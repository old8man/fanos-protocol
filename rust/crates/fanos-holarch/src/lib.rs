//! # HOLARCH — the FANOS architecture viability gate
//!
//! This crate is the platform's *own definition of done*: a mechanical calculator that decides
//! whether the FANOS architecture sits inside the **viable window** of the HOLARCH meta-model
//! (`uhm-theory` corpus, `applied/research/holarch.md`; reference lab `architecture/holarch_lab.py`).
//! It is the executable form of `spec/platform.md` §1 — the release gate the platform must pass.
//!
//! ## The model in one paragraph
//!
//! A holon's internal wiring is a 7×7, trace-1, PSD **coherence matrix** `Γ` over the seven UHM
//! aspects — **A**rticulation, **S**tructure, **D**ynamics, **L**ogic, int**E**riority, gr**O**und,
//! **U**nity. `Γ` is not hand-drawn: each aspect declares how much it carries of the three
//! system-wide *flows* (control / data / supply — the T-262 trichotomy), a flow becomes a coherent
//! mode `|ψ_m⟩` ∝ its participation column, and
//!
//! ```text
//! Γ = (1−ε)·Σ_m λ_m |ψ_m⟩⟨ψ_m|  +  ε·I/7 .
//! ```
//!
//! Couplings are therefore *derived*, never asserted: two aspects cohere exactly as much as they are
//! co-loaded on shared flows (`γ_ij = (1−ε)Σ_m λ_m ψ_mi ψ_mj`), and `ε` is the unstructured background
//! (no real system is rank-3). See [`Gamma::from_modes`].
//!
//! ## The four release invariants (all [T])
//!
//! From `Γ` the calculator reads four scalars and checks each against a threshold. The thresholds are
//! the *same* coherence family the runtime [`fanos_diakrisis`] plane uses, imported from it so they
//! cannot drift:
//!
//! | # | name | measure | gate |
//! |---|------|---------|------|
//! | **V1** | Distinctness | `P = Tr(Γ²)` | `P > 2/7` (above the formless-mesh noise floor) |
//! | **V2** | Reflection | `R = 1/(7P)` | `R ≥ 1/3` ⇔ `P ≤ 3/7` (no aspect dominates) |
//! | **V3** | Integration | `Φ = Σ_{i≠j}γ_ij² / Σ_i γ_ii²` | `Φ ≥ 1` (the parts are actually coupled) |
//! | **V4** | Differentiation | `D = 1 + 6·Coh_E` | `D ≥ 2` (interiority is load-bearing) |
//!
//! A design is **viable** iff all four hold — a bounded window `P ∈ (2/7, 3/7]`, `Φ ≥ 1`, `D ≥ 2`.
//!
//! ## FANOS is the E∧L synthesis
//!
//! FANOS is the join of a mixnet holon (int**E**riority is the anonymity resource — the unobservable
//! pool/keys/delays) and a blockchain holon (**L**ogic-dominant — a consensus law-machine). Its
//! declared budget ([`fanos_platform`]) is therefore thick on *both* E and L, and lands inside the
//! window with margin. [`Panel::run`] recomputes the verdict, the [`Sigma`] stress panel, and the four
//! **Ω4 ablations** — each of which must break exactly the one invariant it targets, since a design you
//! cannot break on demand was never really constrained by that invariant.
//!
//! ## On floating point
//!
//! This is a **build/CI gate**, not a consensus path: `Γ` is evaluated once on the host to decide
//! whether to ship. `f64` here reproduces the reference lab bit-for-bit and carries no determinism or
//! DoS obligation — unlike the DIAKRISIS *runtime* diagnostics, which stay off `f64` on the hot path.
#![forbid(unsafe_code)]
// The whole crate is a 7×7 / 3-flow dense-matrix kernel: every index is an `Aspect`/`Flow` ordinal
// (`0..7` / `0..3`) against a compile-time-fixed array, so slicing is provably in bounds, and the
// triangular factorisations read most clearly as textbook `i/j/k` range loops. Both allowances match
// the convention the other numerical crates use for their kernels.
#![allow(clippy::indexing_slicing, clippy::needless_range_loop)]

pub mod aspect;
pub mod gamma;
pub mod instance;
pub mod panel;
pub mod verdict;

pub use aspect::{Aspect, FLOWS, Flow, N};
pub use gamma::{Budget, Gamma};
pub use instance::{Ablation, Instance, agent_platform, blockchain, fanos_platform, mixnet};
pub use panel::{Check, Class, Panel};
pub use verdict::{D_TH, Invariant, Margins, Sigma, Verdict};
