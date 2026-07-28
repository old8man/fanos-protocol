//! L3 Sybil admission: a pluggable gate a joining node must pass before its announcement is
//! trusted (spec §L3, §7.8 JOIN step 2). Structural centrality ([`crate::membership`]) is
//! necessary but not sufficient — every node touches exactly `q+1` lines regardless of how it
//! got there, so mass alone buys no *centrality*, but nothing stops the mass itself without a
//! per-admission cost: the threat-model derivation (`fanos-sim/tests/sybil_cost.rs`) shows
//! capturing even a cell *majority* by coordinate-grinding alone costs only `Θ(N·log N)`
//! hashes — polynomial, not prohibitive. This module is that missing per-admission cost.
//!
//! Three profiles are named in the spec: **(a) PoW** (memory-hard, open networks — implemented
//! here as [`PowAdmission`]), **(b) stake/bond** (the blockchain overlay), **(c) web-of-trust**
//! (federations). [`AdmissionPolicy`] is the shared shape all three implement; only (a) exists
//! today, but the trait is deliberately minimal (two byte slices in, a bool out) so a stake or
//! WoT profile is a new implementor, not a redesign.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use fanos_primitives::hash_labeled;

const POW_LABEL: &str = "FANOS-v1/admission-pow";

/// A pluggable Sybil admission check (spec §L3): whether `proof` admits a joiner under
/// `challenge`. `challenge` is the caller's own domain-separated binding material (e.g. a
/// joining node's coordinate and epoch, so a proof cannot be replayed at a different address or
/// after an epoch rolls) — this trait fixes only the pass/fail contract, not what a challenge
/// or proof contains, so it accommodates PoW (a nonce), stake (a signed bond attestation), or
/// web-of-trust (a vouch chain) alike. Object-safe, so a deployment can hold
/// `Box<dyn AdmissionPolicy>` and swap profiles without recompiling its caller.
///
/// `Send + Sync`: a policy is installed once on a long-lived node and consulted from whatever
/// context handles an announcement, which in a threaded deployment (e.g. `fanos-node`'s engine
/// factory) means the node itself — and everything it owns — must be `Send`. Any real policy
/// (PoW's plain difficulty counter; a stake ledger snapshot; a WoT graph) is trivially both, so
/// this costs implementors nothing.
pub trait AdmissionPolicy: Send + Sync {
    /// Whether `proof` admits a joiner under `challenge`.
    fn admits(&self, challenge: &[u8], proof: &[u8]) -> bool;

    /// The difficulty this policy currently demands, in proof-of-work bits, if it has one.
    ///
    /// Defaults to `None`, which is the honest answer for a profile where "difficulty" is not a number — a
    /// stake bond or a web-of-trust vouch is not something a joiner can grind harder at. A rejection then
    /// carries no guidance, which a joiner must read as "no guidance" and not as "zero".
    ///
    /// It exists because an *adaptive* price has to be communicable. A gate that raises its cost with the
    /// cell's stress and never says the new number turns every honest joiner whose proof was minted a moment
    /// earlier into a permanent refusal — the attacker's goal, reached through the defence.
    fn required_difficulty(&self) -> Option<u32> {
        None
    }
}

/// The number of leading zero bits of a 32-byte hash — the hashcash difficulty measure.
#[must_use]
fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Hashcash-style proof-of-work admission (spec §L3 profile (a)): a joiner presents a nonce
/// such that `hash(challenge ‖ nonce)` has at least `difficulty` leading zero bits. Expected
/// work to find one is `2^difficulty` hashes — a real, per-joiner cost, on top of (not instead
/// of) the structural centrality cap, closing exactly the gap the coordinate-grind alone leaves
/// open (module doc-comment).
///
/// This is a **sibling** of `fanos_calypso`'s introduction PoW (same hashcash shape, its own
/// domain-separation label below) rather than a shared dependency: the two are different costs
/// at a different layer of the stack (once per cell join here; once per rendezvous introduction
/// there, with its own adaptive-difficulty controller), and `fanos-core` — the dependency-light
/// computational core every other layer builds on — does not otherwise reach up into the
/// service layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PowAdmission {
    difficulty: u32,
}

impl PowAdmission {
    /// An admission gate requiring `difficulty` leading zero bits.
    #[must_use]
    pub fn new(difficulty: u32) -> Self {
        Self { difficulty }
    }

    /// The configured difficulty (leading zero bits required).
    #[must_use]
    pub fn difficulty(self) -> u32 {
        self.difficulty
    }

    /// The PoW hash of a challenge and nonce.
    #[must_use]
    fn hash(challenge: &[u8], nonce: u64) -> [u8; 32] {
        let mut data = Vec::with_capacity(challenge.len() + 8);
        data.extend_from_slice(challenge);
        data.extend_from_slice(&nonce.to_le_bytes());
        hash_labeled(POW_LABEL, &data)
    }

    /// Whether `nonce` solves `challenge` at `difficulty`.
    #[must_use]
    fn solves(challenge: &[u8], nonce: u64, difficulty: u32) -> bool {
        leading_zero_bits(&Self::hash(challenge, nonce)) >= difficulty
    }

    /// Find a nonce solving `challenge` at this policy's difficulty — the joiner's side.
    /// Expected work is `2^difficulty` hashes; keep `difficulty` modest for an interactive join.
    /// Returns the nonce as its canonical 8-byte little-endian encoding, ready to carry as a
    /// wire proof (e.g. the FANOS `Announce` admission-proof field).
    #[must_use]
    pub fn solve(self, challenge: &[u8]) -> Vec<u8> {
        let mut nonce = 0u64;
        while !Self::solves(challenge, nonce, self.difficulty) {
            nonce += 1;
        }
        nonce.to_le_bytes().to_vec()
    }
}

impl AdmissionPolicy for PowAdmission {
    fn required_difficulty(&self) -> Option<u32> {
        Some(self.difficulty)
    }

    fn admits(&self, challenge: &[u8], proof: &[u8]) -> bool {
        let Ok(nonce_bytes) = <[u8; 8]>::try_from(proof) else {
            return false; // malformed proof (wrong length) — reject, never panic
        };
        Self::solves(challenge, u64::from_le_bytes(nonce_bytes), self.difficulty)
    }
}

/// A **live** difficulty an admission gate reads and a controller writes.
///
/// The seam between the DDoS control law (`fanos_diakrisis::stability::AdmissionController`, which decides what
/// entry should cost right now) and the gate that charges it. Shared rather than passed because the two run on
/// different clocks: the controller updates once per observation window, the gate is consulted once per join,
/// and neither should wait on the other.
///
/// A plain atomic, deliberately. The value is a single `u32` that only ever needs the most recent write —
/// there is nothing to serialize, no invariant spanning two fields, and a lock here would put the join path
/// behind the observation loop for no gain.
#[derive(Clone, Debug)]
pub struct LiveDifficulty(Arc<AtomicU32>);

impl LiveDifficulty {
    /// A live difficulty starting at `bits`.
    #[must_use]
    pub fn new(bits: u32) -> Self {
        Self(Arc::new(AtomicU32::new(bits)))
    }

    /// The difficulty a joiner must currently meet.
    #[must_use]
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    /// Set the difficulty — the controller's side.
    pub fn set(&self, bits: u32) {
        self.0.store(bits, Ordering::Relaxed);
    }
}

/// Proof-of-work admission at a difficulty that **moves with the cell's stress**.
///
/// [`PowAdmission`] charges a fixed price, which is the right shape for a policy decision and the wrong one for
/// a defence: a flood does not arrive at the difficulty an operator guessed months earlier. This reads its
/// requirement from a [`LiveDifficulty`] the coherence controller drives, so the cost of joining a cell under
/// attack rises within one observation window, with no consensus to reach and no authority to ask.
///
/// **It never charges less than `floor`.** The controller can only raise the price above the operator's
/// configured baseline, never below it — so a bug, a stuck sensor or a compromised controller cannot *open* a
/// network that its operator chose to price.
///
/// The current requirement must reach an honest joiner, or an adaptive gate is a silent denial of service
/// against exactly the peers it exists to protect. That is why a rejection carries the required bits back
/// (`ProtocolError::SybilReject`'s reason field) rather than merely saying no.
#[derive(Clone, Debug)]
pub struct AdaptivePowAdmission {
    floor: u32,
    live: LiveDifficulty,
}

impl AdaptivePowAdmission {
    /// A gate that never charges below `floor` and otherwise follows `live`.
    #[must_use]
    pub fn new(floor: u32, live: LiveDifficulty) -> Self {
        Self { floor, live }
    }

    /// The difficulty a joiner must meet right now.
    #[must_use]
    pub fn required(&self) -> u32 {
        self.live.get().max(self.floor)
    }
}

impl AdmissionPolicy for AdaptivePowAdmission {
    fn required_difficulty(&self) -> Option<u32> {
        Some(self.required())
    }

    fn admits(&self, challenge: &[u8], proof: &[u8]) -> bool {
        let Ok(bytes) = <[u8; 8]>::try_from(proof) else { return false };
        PowAdmission::solves(challenge, u64::from_le_bytes(bytes), self.required())
    }

}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_solved_proof_admits_and_a_wrong_one_does_not() {
        let policy = PowAdmission::new(10);
        let challenge = b"node-coord \xE2\x80\x96 epoch";
        let proof = policy.solve(challenge);
        assert!(policy.admits(challenge, &proof));
        // A different challenge (a different joiner/epoch) rejects the same proof — the
        // binding is real, not decorative: a proof cannot be replayed elsewhere.
        assert!(!policy.admits(b"a different challenge", &proof));
        // A malformed (wrong-length) proof is rejected, not panicking.
        assert!(!policy.admits(challenge, b"short"));
        assert!(!policy.admits(challenge, &[]));
    }

    #[test]
    fn a_solution_for_high_difficulty_also_satisfies_lower_thresholds() {
        let hard = PowAdmission::new(14);
        let challenge = b"c";
        let proof = hard.solve(challenge);
        assert!(PowAdmission::new(8).admits(challenge, &proof));
        assert!(PowAdmission::new(14).admits(challenge, &proof));
    }

    #[test]
    fn zero_difficulty_admits_any_well_formed_proof() {
        // difficulty=0 is the degenerate "any 8-byte proof passes, no real work" case — a valid
        // deployment choice (bind-only, no cost), not a special case the type needs to forbid.
        let policy = PowAdmission::new(0);
        assert!(policy.admits(b"x", &0u64.to_le_bytes()));
    }

    #[test]
    fn solved_proofs_are_always_exactly_eight_bytes() {
        // The wire admission-proof field assumes an 8-byte nonce; guard the invariant directly.
        for difficulty in [0u32, 4, 9] {
            let proof = PowAdmission::new(difficulty).solve(b"ctx");
            assert_eq!(proof.len(), 8);
        }
    }
    #[test]
    fn the_adaptive_gate_charges_the_live_price_and_never_less_than_the_floor() {
        // The floor is the operator's decision and the controller may only raise it. A stuck sensor, a bug, or a
        // compromised controller must not be able to *open* a network its operator chose to price.
        let live = LiveDifficulty::new(0);
        let gate = AdaptivePowAdmission::new(6, live.clone());
        assert_eq!(gate.required(), 6, "a live value below the floor cannot lower the price");
        live.set(11);
        assert_eq!(gate.required(), 11, "above the floor, the controller governs");
        live.set(2);
        assert_eq!(gate.required(), 6, "and dropping back below the floor returns to it, not under it");
    }

    #[test]
    fn a_proof_minted_at_the_old_price_is_refused_once_the_price_rises() {
        // The whole point of the gate, and the reason a rejection must carry the new requirement: a joiner
        // holding a proof for yesterday's difficulty is turned away, and without being told the number it has no
        // way to succeed.
        let challenge = b"a joiner's challenge";
        let live = LiveDifficulty::new(4);
        let gate = AdaptivePowAdmission::new(0, live.clone());
        let cheap = PowAdmission::new(4).solve(challenge);
        assert!(gate.admits(challenge, &cheap), "it admits work done at the current price");
        live.set(18);
        assert!(!gate.admits(challenge, &cheap), "and refuses it once the price has risen");
    }

    #[test]
    fn the_adaptive_gate_agrees_with_the_fixed_one_at_the_same_difficulty() {
        // Two gates, one proof rule. A divergence here would mean a joiner that satisfies one node's arithmetic
        // and not another's — a split in who may join, from nothing but which type a node happened to install.
        let challenge = b"same challenge for both";
        for bits in [0u32, 3, 7] {
            let fixed = PowAdmission::new(bits);
            let adaptive = AdaptivePowAdmission::new(0, LiveDifficulty::new(bits));
            let nonce = fixed.solve(challenge);
            assert_eq!(
                fixed.admits(challenge, &nonce),
                adaptive.admits(challenge, &nonce),
                "the two gates disagree at {bits} bits"
            );
        }
    }

    #[test]
    fn a_malformed_proof_is_refused_rather_than_panicking() {
        let gate = AdaptivePowAdmission::new(1, LiveDifficulty::new(1));
        assert!(!gate.admits(b"c", b""), "an empty proof");
        assert!(!gate.admits(b"c", &[0u8; 7]), "a short proof");
        assert!(!gate.admits(b"c", &[0u8; 9]), "a long proof");
    }
}

