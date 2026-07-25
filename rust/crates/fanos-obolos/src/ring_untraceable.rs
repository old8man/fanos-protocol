//! The **composed untraceability proof** for a shielded spend — the zero-knowledge half that hides *which note*
//! was spent. It binds together the two untraceability relations over a **single** note commitment `cm`:
//!
//! 1. **membership** ([`crate::ring_membership::prove_path_sound`]) — `cm` is a leaf under the public tree root
//!    (`anchor`), position hidden, every node proven short;
//! 2. **nullifier** ([`crate::ring_nullifier`]) — the public nullifier `nf = hash(nsk, cm)` is correctly derived
//!    from the spender's secret `nsk` and this same `cm`.
//!
//! The soundness that makes it a *spend* rather than two unrelated proofs: the nullifier is verified against the
//! **membership leaf commitment** ([`SoundPathProof::leaf_commitment`]), so the note that is proven a tree member
//! is *exactly* the note whose nullifier is published — a spender cannot prove membership of one note while
//! nullifying another. `cm` is committed once (the shared leaf randomness) and used by both halves.
//!
//! Ownership — that `cm` actually embeds an owner derived from `nsk` — folds into the note redesign (the
//! integration step): once notes are SIS-based, `owner = hash(nsk, ·)` is another public-output hash step, and the
//! note commitment binds it.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the sound membership path and the nullifier proof;
//! > inherits their status and their `O(depth·ELL_H·LOG_BASE·REPETITIONS)` cost. Verified by an `#[ignore]`d test
//! > (`--ignored`) at real `bits = LOG_BASE`: a genuine spend (membership + matching nullifier over one `cm`)
//! > proves and verifies.

use alloc::vec::Vec;

use crate::ring_commit::{RingCommitment, RingParams};
use crate::ring_hash::{HashNode, HashParams, LOG_BASE};
use crate::ring_membership::{NodeWitness, SoundPathProof, commit_node, node_r, prove_path_sound, verify_path_sound};
use crate::ring_nullifier::{NullifierProof, prove_nullifier, verify_nullifier};

/// A zero-knowledge untraceability proof for a spend: membership of a note `cm` under the root, and the public
/// nullifier of that same `cm`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UntraceableProof {
    membership: SoundPathProof,
    nullifier: NullifierProof,
    nsk_coms: Vec<RingCommitment>, // the committed (hidden) secret nullifier key
}

/// Prove a spend's untraceability: `cm` is a member of the tree (`tree_hp`, hashing up through `siblings` with
/// hidden `directions`), and the public `nf = nf_hp.hash(nsk, cm)` is derived from `nsk` and this same `cm`. The
/// caller obtains `nf` as `nf_hp.hash(nsk, cm)`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn prove_untraceable(
    params: &RingParams,
    tree_hp: &HashParams,
    nf_hp: &HashParams,
    cm: &HashNode,
    nsk: &HashNode,
    siblings: &[HashNode],
    directions: &[u64],
    seed: &[u8],
) -> Option<UntraceableProof> {
    // Membership: cm is the leaf. Its commitment uses node_r(seed, "/leaf", 0) internally.
    let membership = prove_path_sound(params, tree_hp, cm, siblings, directions, seed)?;

    // Nullifier over the SAME cm — bind by using the identical leaf randomness.
    let cm_r = node_r(seed, "/leaf", 0);
    let nsk_r = node_r(seed, "/nsk", 0);
    let nsk_coms = commit_node(params, nsk, &nsk_r);
    let cm_w = NodeWitness { node: cm, randomness: &cm_r };
    let nsk_w = NodeWitness { node: nsk, randomness: &nsk_r };
    let mut nseed = seed.to_vec();
    nseed.extend_from_slice(b"/null");
    let nullifier = prove_nullifier(params, nf_hp, &nsk_w, &cm_w, LOG_BASE as usize, &nseed)?;

    Some(UntraceableProof { membership, nullifier, nsk_coms })
}

/// Verify a [`prove_untraceable`] proof against the public tree `root` and nullifier `nf`.
#[must_use]
pub fn verify_untraceable(
    params: &RingParams,
    tree_hp: &HashParams,
    nf_hp: &HashParams,
    root: &HashNode,
    nf: &HashNode,
    proof: &UntraceableProof,
) -> bool {
    // Membership under the public root.
    verify_path_sound(params, tree_hp, root, &proof.membership)
        // Nullifier of the SAME note — verified against the membership leaf commitment, binding cm across both.
        && verify_nullifier(
            params,
            nf_hp,
            nf,
            &proof.nsk_coms,
            proof.membership.leaf_commitment(),
            LOG_BASE as usize,
            &proof.nullifier,
        )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "sound membership + nullifier at bits=LOG_BASE=16 — a couple of minutes; run with --ignored"]
    fn a_spend_proves_membership_and_nullifier_over_one_note() {
        let params = RingParams::standard();
        let tree_hp = HashParams::standard();
        let nf_hp = HashParams::from_seed(b"FANOS-obolos-v1/nullifier");
        // The spent note cm (a genuine short SIS node), the sibling, and the secret key.
        let cm = HashNode::from_bytes(b"ut-note-cm");
        let sib0 = HashNode::from_bytes(b"ut-sib0");
        let nsk = HashNode::from_bytes(b"ut-nsk");
        let d0 = 0u64;
        // The tree root cm hashes up to, and the public nullifier.
        let root = {
            let (l, r) = if d0 == 1 { (sib0.clone(), cm.clone()) } else { (cm.clone(), sib0.clone()) };
            tree_hp.hash(&l, &r)
        };
        let nf = nf_hp.hash(&nsk, &cm);
        let sibs = [sib0.clone()];
        let dirs = [d0];
        let proof = prove_untraceable(&params, &tree_hp, &nf_hp, &cm, &nsk, &sibs, &dirs, b"seed").expect("spend");
        assert!(
            verify_untraceable(&params, &tree_hp, &nf_hp, &root, &nf, &proof),
            "a genuine spend proves membership + nullifier over one note"
        );
        // The nullifier is bound to the membership leaf: a nullifier of a *different* note (nf of a different cm)
        // cannot ride on this membership proof — the leaf-commitment tie in the hash step rejects it.
        let other_nf = nf_hp.hash(&nsk, &sib0);
        assert!(
            !verify_untraceable(&params, &tree_hp, &nf_hp, &root, &other_nf, &proof),
            "a nullifier of a different note is rejected"
        );
    }
}
