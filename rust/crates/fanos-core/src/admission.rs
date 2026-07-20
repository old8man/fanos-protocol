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

use alloc::vec::Vec;

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
    fn admits(&self, challenge: &[u8], proof: &[u8]) -> bool {
        let Ok(nonce_bytes) = <[u8; 8]>::try_from(proof) else {
            return false; // malformed proof (wrong length) — reject, never panic
        };
        Self::solves(challenge, u64::from_le_bytes(nonce_bytes), self.difficulty)
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
}
