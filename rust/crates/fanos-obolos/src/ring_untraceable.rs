//! The **composed untraceability proof** for a shielded spend — the zero-knowledge half that hides *which note*
//! was spent. It binds together the two untraceability relations over a **single** note commitment `cm`:
//!
//! 1. **membership** ([`crate::ring_membership::prove_path_sound`]) — `cm` is a leaf under the public tree root
//!    (`anchor`), position hidden, every node proven short;
//! 2. **nullifier** ([`crate::ring_nullifier`]) — the public nullifier `nf = hash_nf(nsk, hash_slot(cm, pos))` is
//!    correctly derived from the spender's secret `nsk`, this same `cm`, and the leaf's tree position.
//!
//! Two shared-commitment bindings are what make this a *spend* rather than three unrelated proofs:
//!
//! - **the note** — the nullifier is verified against the **membership leaf commitment**
//!   ([`SoundPathProof::leaf_commitment`]), so the note proven a tree member is *exactly* the note whose nullifier is
//!   published; a spender cannot prove membership of one note while nullifying another;
//! - **the position** — a [`crate::ring_linear`] relation proves the nullifier's hidden position node recomposes to
//!   the path's **already-committed direction bits**, `Σ_d 2^{LOG_BASE·d}·pos_d = Σ_j 2ʲ·d_j`. The bits *are* the
//!   leaf index in binary, and each is already proven binary by its level's swap proof, so the slot the nullifier
//!   binds is exactly the slot the path proved — while the position itself stays hidden.
//!
//! Without that second tie the position node would be free, and position-binding would buy nothing: a prover could
//! nullify one slot while proving membership of another. With it, distinct leaves always nullify distinctly (every
//! tree slot is unique), so no note can ever lock another out — the ring form of [`crate::nullifier`]'s audit O-M1
//! property. Ownership — that `cm` embeds an owner derived from `nsk` — is proven by [`crate::ring_note`].
//!
//! > **STATUS — \[P\]/\[H\], correctness-first.** A composition of the sound membership path, the nullifier proof, and
//! > one linear relation; inherits their status and their `O(depth·ELL_H·LOG_BASE·REPETITIONS)` cost. Verified by an
//! > `#[ignore]`d test (`--ignored`) at real `bits = LOG_BASE`: a genuine spend proves, a nullifier of a different
//! > note is rejected, and a nullifier claiming a *different position* than the path proved is rejected.

use alloc::vec::Vec;

use crate::ring::Poly;
use crate::ring_commit::{RingCommitment, RingParams};
use crate::ring_hash::{HashNode, HashParams, LOG_BASE, digit_weights};
use crate::ring_linear::{LinearProof, prove_linear, verify_linear};
use crate::ring_membership::{
    NodeWitness, SoundPathProof, commit_node, dir_r, node_r, prove_path_sound, verify_path_sound,
};
use crate::ring_nullifier::{NullifierProof, prove_nullifier, verify_nullifier};

/// A zero-knowledge untraceability proof for a spend: membership of a note `cm` under the root, and the public
/// nullifier of that same `cm` at that same tree position.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UntraceableProof {
    membership: SoundPathProof,
    nullifier: NullifierProof,
    position_tie: LinearProof,     // Σ 2^{16d}·pos_d − Σ 2^j·d_j = 0 over shared commitments
    nsk_coms: Vec<RingCommitment>, // the committed (hidden) secret nullifier key
}

impl UntraceableProof {
    /// The commitment to the spent note `cm` (the membership leaf) — the per-input spend proof
    /// ([`crate::ring_input`]) binds the note-validity and value-tie proofs against it.
    #[must_use]
    pub fn cm_commitment(&self) -> &[RingCommitment] {
        self.membership.leaf_commitment()
    }

    /// The commitment to the hidden secret nullifier key `nsk` — bound against the note-validity proof's owner
    /// derivation.
    #[must_use]
    pub fn nsk_commitment(&self) -> &[RingCommitment] {
        &self.nsk_coms
    }
}

/// The leaf index the `directions` spell out — `Σ_j 2ʲ·d_j`, bit `j` being the direction at level `j`.
#[must_use]
pub fn position_of(directions: &[u64]) -> u64 {
    directions.iter().enumerate().fold(0u64, |acc, (j, &d)| acc | ((d & 1) << j))
}

/// The position-tie relation's public coefficients over `pos_node.limbs ‖ direction bits`:
/// `[2^{LOG_BASE·d} …, −2ʲ …]`, so the relation reads `Σ_d 2^{LOG_BASE·d}·pos_d − Σ_j 2ʲ·d_j = 0`.
fn position_tie_coeffs(depth: usize) -> Vec<Poly> {
    let mut coeffs = digit_weights();
    coeffs.extend((0..depth).map(|j| Poly::zero().sub(&Poly::constant(1u64 << j))));
    coeffs
}

/// Prove a spend's untraceability: `cm` is a member of the tree (`tree_hp`, hashing up through `siblings` with
/// hidden `directions`), and the public nullifier is derived from `nsk`, this same `cm`, **and this same position**.
/// The caller obtains `nf` as [`crate::ring_nullifier::nullifier_of`] over `position_of(directions)`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn prove_untraceable(
    params: &RingParams,
    tree_hp: &HashParams,
    slot_hp: &HashParams,
    nf_hp: &HashParams,
    cm: &HashNode,
    nsk: &HashNode,
    siblings: &[HashNode],
    directions: &[u64],
    seed: &[u8],
) -> Option<UntraceableProof> {
    // Membership: cm is the leaf. Its commitment uses node_r(seed, "/leaf", 0) internally.
    let membership = prove_path_sound(params, tree_hp, cm, siblings, directions, seed)?;

    // Nullifier over the SAME cm — bind by using the identical leaf randomness — at the path's own position.
    let cm_r = node_r(seed, "/leaf", 0);
    let nsk_r = node_r(seed, "/nsk", 0);
    let nsk_coms = commit_node(params, nsk, &nsk_r);
    let cm_w = NodeWitness { node: cm, randomness: &cm_r };
    let nsk_w = NodeWitness { node: nsk, randomness: &nsk_r };
    let mut nseed = seed.to_vec();
    nseed.extend_from_slice(b"/null");
    let position = position_of(directions);
    let nullifier = prove_nullifier(params, slot_hp, nf_hp, &nsk_w, &cm_w, position, LOG_BASE as usize, &nseed)?;

    // The position tie: the nullifier's hidden position node recomposes to the path's committed direction bits. The
    // `d_j` randomness is re-derived from the same seed prove_path used, so these are literally the path's own
    // commitments — a prover cannot nullify one slot while proving membership of another.
    let depth = directions.len();
    let pos_node = HashNode::from_u64_digits(position);
    let pos_r = crate::ring_nullifier::position_randomness(&nseed);
    let mut messages: Vec<Poly> = pos_node.limbs().to_vec();
    messages.extend(directions.iter().map(|&d| Poly::constant(d)));
    let mut commitments: Vec<RingCommitment> = nullifier.position_commitment().to_vec();
    commitments.extend(membership.direction_commitments());
    let mut randomness = pos_r;
    randomness.extend((0..depth).map(|j| dir_r(seed, j)));
    let mut tseed = seed.to_vec();
    tseed.extend_from_slice(b"/postie");
    let position_tie =
        prove_linear(params, &commitments, &position_tie_coeffs(depth), &messages, &randomness, &tseed)?;

    Some(UntraceableProof { membership, nullifier, position_tie, nsk_coms })
}

/// Verify a [`prove_untraceable`] proof against the public tree `root` and nullifier `nf`.
#[must_use]
pub fn verify_untraceable(
    params: &RingParams,
    tree_hp: &HashParams,
    slot_hp: &HashParams,
    nf_hp: &HashParams,
    root: &HashNode,
    nf: &HashNode,
    proof: &UntraceableProof,
) -> bool {
    // Membership under the public root.
    if !verify_path_sound(params, tree_hp, root, &proof.membership) {
        return false;
    }
    // Nullifier of the SAME note — verified against the membership leaf commitment, binding cm across both.
    if !verify_nullifier(
        params,
        slot_hp,
        nf_hp,
        nf,
        &proof.nsk_coms,
        proof.membership.leaf_commitment(),
        LOG_BASE as usize,
        &proof.nullifier,
    ) {
        return false;
    }
    // The position tie: the nullifier's position node recomposes to the path's committed direction bits, so the
    // nullified slot IS the slot proven a member.
    let dirs = proof.membership.direction_commitments();
    let mut commitments: Vec<RingCommitment> = proof.nullifier.position_commitment().to_vec();
    let depth = dirs.len();
    commitments.extend(dirs);
    verify_linear(params, &commitments, &position_tie_coeffs(depth), &proof.position_tie)
}

impl crate::ring_size::ProofSize for UntraceableProof {
    fn ring_elements(&self) -> usize {
        self.membership.ring_elements() + self.nullifier.ring_elements() + self.position_tie.ring_elements()
            + self.nsk_coms.ring_elements()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use crate::ring_nullifier::nullifier_of;

    #[test]
    fn the_position_is_the_direction_bits_in_binary() {
        // The relation the tie proves, in the clear: the path's direction bits ARE the leaf index.
        assert_eq!(position_of(&[0, 0, 0]), 0);
        assert_eq!(position_of(&[1, 0, 0]), 1, "level 0 is the low bit");
        assert_eq!(position_of(&[0, 1, 0]), 2);
        assert_eq!(position_of(&[1, 1, 1]), 7);
        assert_eq!(position_of(&[]), 0, "an empty path is the (only) root slot");
    }

    #[test]
    #[ignore = "sound membership + position-bound nullifier at bits=LOG_BASE=16 — minutes; run with --ignored"]
    fn a_spend_proves_membership_and_nullifier_over_one_note() {
        let params = RingParams::standard();
        let tree_hp = HashParams::standard();
        let slot_hp = HashParams::from_seed(b"FANOS-obolos-v1/note-slot");
        let nf_hp = HashParams::from_seed(b"FANOS-obolos-v1/nullifier");
        // The spent note cm (a genuine short SIS node), the sibling, and the secret key.
        let cm = HashNode::from_bytes(b"ut-note-cm");
        let sib0 = HashNode::from_bytes(b"ut-sib0");
        let nsk = HashNode::from_bytes(b"ut-nsk");
        let d0 = 1u64; // the leaf sits on the RIGHT at level 0 ⇒ position 1 (a non-trivial position to bind)
        // The tree root cm hashes up to, and the public nullifier.
        let root = {
            let (l, r) = if d0 == 1 { (sib0.clone(), cm.clone()) } else { (cm.clone(), sib0.clone()) };
            tree_hp.hash(&l, &r)
        };
        let sibs = [sib0.clone()];
        let dirs = [d0];
        let nf = nullifier_of(&slot_hp, &nf_hp, &nsk, &cm, position_of(&dirs));
        let proof =
            prove_untraceable(&params, &tree_hp, &slot_hp, &nf_hp, &cm, &nsk, &sibs, &dirs, b"seed").expect("spend");
        assert!(
            verify_untraceable(&params, &tree_hp, &slot_hp, &nf_hp, &root, &nf, &proof),
            "a genuine spend proves membership + position-bound nullifier over one note"
        );
        // The nullifier is bound to the membership leaf: a nullifier of a *different* note cannot ride on this
        // membership proof — the leaf-commitment tie in the hash step rejects it.
        let other_note = nullifier_of(&slot_hp, &nf_hp, &nsk, &sib0, position_of(&dirs));
        assert!(
            !verify_untraceable(&params, &tree_hp, &slot_hp, &nf_hp, &root, &other_note, &proof),
            "a nullifier of a different note is rejected"
        );
        // …and it is bound to the proven SLOT: the same note nullified for position 0 (while the path proves
        // position 1) is rejected — the property that makes colliding leaves independently spendable.
        let other_slot = nullifier_of(&slot_hp, &nf_hp, &nsk, &cm, 0);
        assert!(
            !verify_untraceable(&params, &tree_hp, &slot_hp, &nf_hp, &root, &other_slot, &proof),
            "a nullifier claiming a different position than the path proved is rejected"
        );
    }
}
