//! **Proof-size accounting** — an exact count of the `R_q` elements each zero-knowledge proof consists of, so the
//! stack's cost is a measured number rather than an adjective.
//!
//! Every proof in this crate is ultimately a bag of ring elements: commitments ([`crate::ring_commit`]) are `K + 1`
//! of them, randomness openings are `ELL`, and revealed masked messages are one each. Counting them is therefore an
//! *encoding-independent* size metric — multiply by [`BYTES_PER_ELEMENT`] for the byte cost of the straightforward
//! encoding (one `u64` per coefficient, which is what a general element mod `q` needs).
//!
//! ## Why this exists
//!
//! The honest frontier of a lattice-ZK ledger is usually stated as proving *time*. For this stack **size** is the
//! harder half, and it was being described qualitatively. The counts here make the dominant term visible and give
//! any compaction work a before/after number instead of an impression. The shape they expose:
//!
//! - a [`crate::ring_linear`] proof over `n` messages costs `REPETITIONS · (n+1)(K+1) + n + (n+1)·ELL` elements —
//!   linear in the statement width and in the repetition count;
//! - a [`crate::ring_shortness`] proof costs one aggregated binarity proof plus one reconstruction, and the
//!   untraceability path needs one *per node limb* — so node shortness dominates everything else by orders of
//!   magnitude, and it is the term any compaction must attack first.
//!
//! The counts have already earned their keep twice: they showed that aggregating the bit-plane binarity checks was
//! worth 2× (built), and then that doing so **moves the bottleneck** to the reconstruction — which turns out to be
//! paying for a coefficient blow-up that cannot occur at its coefficient sizes. Neither was visible without numbers.
//!
//! > **STATUS — measurement, not calibration.** These are exact counts of what the current constructions emit, checked
//! > against the constructions in test. They are not a claim that the sizes are acceptable — see
//! > `docs/design-obolos-zk.md` §6 for the measured ladder and its ceiling.

use alloc::vec::Vec;

use crate::ring::D;

/// The bytes one `R_q` element costs in the straightforward encoding: `D` coefficients, each a `u64` (a general
/// element mod `q` needs the full width — short witnesses could pack tighter, which is itself a compaction).
pub const BYTES_PER_ELEMENT: usize = D * 8;

/// The number of `R_q` elements a proof (or proof component) consists of.
///
/// Implementations sum their parts, so a composed proof's count is exactly the sum of its sub-proofs' — which is what
/// makes the count auditable against the construction rather than a guess.
pub trait ProofSize {
    /// The count of `R_q` elements.
    #[must_use]
    fn ring_elements(&self) -> usize;

    /// The byte cost of the straightforward encoding — `ring_elements() · BYTES_PER_ELEMENT`.
    #[must_use]
    fn encoded_bytes(&self) -> usize {
        self.ring_elements() * BYTES_PER_ELEMENT
    }
}

impl<T: ProofSize> ProofSize for Vec<T> {
    fn ring_elements(&self) -> usize {
        self.iter().map(ProofSize::ring_elements).sum()
    }
}

impl<T: ProofSize> ProofSize for &[T] {
    fn ring_elements(&self) -> usize {
        self.iter().map(ProofSize::ring_elements).sum()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ring_commit::{ELL, K, RingCommitment, RingParams, RingRandomness};

    #[test]
    fn the_leaf_counts_match_the_constructions() {
        // A commitment is (t0 ∈ R_q^K, t1 ∈ R_q); a randomness is ELL elements. Everything else sums these.
        let params = RingParams::standard();
        let r = RingRandomness::from_seed(b"size-r");
        assert_eq!(r.ring_elements(), ELL, "a randomness is ELL elements");
        assert_eq!(RingCommitment::commit(&params, 1, &r).ring_elements(), K + 1, "a commitment is K+1");
        assert_eq!(r.encoded_bytes(), ELL * BYTES_PER_ELEMENT, "bytes follow from the count");
    }
}
