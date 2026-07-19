//! L0/L3 membership: node coordinates and the structural centrality cap (spec §L0, §L3, V3).
//!
//! A node's cell coordinate is a VRF of its identity and the epoch, so it reshuffles each
//! epoch and cannot be pre-aimed. Crucially, every node lies on **exactly `q + 1` of the `N`
//! lines** — a fixed fraction `(q+1)/N` — so *centrality cannot be bought*: a Sybil node gets
//! no more lines than anyone else, and to eclipse a node an adversary must control all `q+1`
//! of its lines at once.

use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point};

use fanos_primitives::{BeaconSeed, Epoch, NodeId};
use fanos_vrf::{VrfProof, VrfPublic, VrfSecret, prove_coordinate, verify_coordinate};

/// A cell member: its long-term identity and its epoch-bound coordinate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Member<F: Field> {
    /// The long-term node identifier (spec §L0).
    pub id: NodeId,
    /// The projective coordinate for the current epoch.
    pub coord: Point<F>,
    /// The epoch this coordinate was derived for.
    pub epoch: Epoch,
}

impl<F: Field> Member<F> {
    /// Assign **this** node's verifiable coordinate for (`epoch`, `beacon`) from its own VRF secret:
    /// `coord = MapToPoint(VRF(vrf_secret, id ‖ epoch ‖ beacon))` (spec §L0/§L3). The VRF binds the
    /// coordinate to the epoch's beacon, so it reshuffles unpredictably and cannot be pre-aimed onto a
    /// target's lines (§3.2 assumption 2); `vrf_secret` is the key committed in `id`'s identity bundle, so
    /// the placement is unforgeable. `beacon` is [`BeaconSeed::GENESIS`] before the first beacon round.
    #[must_use]
    pub fn assign(vrf_secret: &VrfSecret, id: NodeId, epoch: Epoch, beacon: &BeaconSeed) -> Self {
        let (coord, _proof) = prove_coordinate::<F>(vrf_secret, &id.0, epoch, beacon);
        Self { id, coord, epoch }
    }

    /// Admit a **peer's** claimed coordinate iff its proof-of-coordinate checks out — the `HELLO` /
    /// announcement admission (spec §7.3, error `BAD_COORD` on failure). Returns `Some(member)` only when
    /// `verify_coordinate(vrf_public, id ‖ epoch ‖ beacon) == coord`, so a `Member` admitted this way is
    /// provably at the coordinate its identity earns — a forged or misreported placement yields `None`.
    #[must_use]
    pub fn verified(
        id: NodeId,
        coord: Point<F>,
        epoch: Epoch,
        beacon: &BeaconSeed,
        vrf_public: &VrfPublic,
        proof: &VrfProof,
    ) -> Option<Self> {
        verify_coordinate::<F>(vrf_public, &id.0, epoch, beacon, &coord, proof)
            .then_some(Self { id, coord, epoch })
    }

    /// The `q + 1` lines this member belongs to (its quorums / buses).
    pub fn lines(&self) -> impl Iterator<Item = Line<F>> + Clone {
        Plane::<F>::lines_through(self.coord)
    }
}

/// The number of lines through every node: `q + 1` (spec §L3). This is the structural
/// centrality — identical for every node, Sybil or not.
#[must_use]
pub fn lines_per_node<F: Field>() -> u32 {
    Plane::<F>::LINE_SIZE
}

/// The centrality cap `(q+1)/N` — the fixed fraction of lines any node touches (spec §L3, V3).
/// For `q = 31` this is `3.22%`.
#[must_use]
pub fn centrality_fraction(q: u32) -> f64 {
    let n = q * q + q + 1;
    f64::from(q + 1) / f64::from(n)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F7, F31};
    use fanos_vrf::VrfSecret;

    fn secret(seed: u8) -> VrfSecret {
        VrfSecret::from_seed([seed; 32])
    }

    #[test]
    fn centrality_is_capped_and_uniform() {
        // V3: centrality (q+1)/N; q=31 → 3.22%.
        assert!((centrality_fraction(31) - 0.032_225).abs() < 1e-5);
        // Every node on the q=7 cell touches exactly q+1 = 8 lines — no exceptions.
        for p in Plane::<F7>::points() {
            assert_eq!(Plane::<F7>::lines_through(p).count() as u32, 8);
        }
    }

    #[test]
    fn member_coordinate_is_epoch_bound() {
        let id = NodeId([5u8; 32]);
        let sk = secret(5);
        let m0 = Member::<F31>::assign(&sk, id, Epoch::ZERO, &BeaconSeed::GENESIS);
        let m1 = Member::<F31>::assign(&sk, id, Epoch::new(1), &BeaconSeed::GENESIS);
        assert_eq!(m0.epoch, Epoch::ZERO);
        assert_ne!(m0.coord, m1.coord, "epoch reshuffle moves the coordinate");
        assert_eq!(m0.lines().count() as u32, lines_per_node::<F31>());
    }

    #[test]
    fn sybil_gains_no_extra_centrality() {
        // Many identities all land on exactly q+1 lines — mass does not buy centrality.
        for seed in 0u8..20 {
            let m = Member::<F31>::assign(
                &secret(seed),
                NodeId([seed; 32]),
                Epoch::ZERO,
                &BeaconSeed::GENESIS,
            );
            assert_eq!(m.lines().count() as u32, 32);
        }
    }

    #[test]
    fn a_peer_coordinate_is_admitted_only_with_a_valid_proof() {
        // The VRF makes placement unforgeable: a peer's claimed coordinate is admitted iff its proof
        // verifies under the VRF public committed in its identity — a forged coordinate, a proof from a
        // different key, or the wrong beacon is rejected (spec §L0/§7.3 BAD_COORD).
        let id = NodeId([9u8; 32]);
        let sk = secret(9);
        let epoch = Epoch::new(4);
        let (coord, proof) = prove_coordinate::<F31>(&sk, &id.0, epoch, &BeaconSeed::GENESIS);
        // The honest node's own placement equals what a verifier admits.
        assert_eq!(
            Member::<F31>::assign(&sk, id, epoch, &BeaconSeed::GENESIS).coord,
            coord
        );
        // A valid proof under the right key admits the peer at exactly that coordinate.
        assert_eq!(
            Member::<F31>::verified(id, coord, epoch, &BeaconSeed::GENESIS, &sk.public(), &proof)
                .map(|m| m.coord),
            Some(coord)
        );
        // A different key's public rejects the claim — no forgery.
        assert!(
            Member::<F31>::verified(
                id,
                coord,
                epoch,
                &BeaconSeed::GENESIS,
                &secret(10).public(),
                &proof
            )
            .is_none()
        );
        // A wrong beacon rejects (the coordinate is beacon-bound) — no cross-epoch replay.
        assert!(
            Member::<F31>::verified(
                id,
                coord,
                epoch,
                &BeaconSeed::new([7; 32]),
                &sk.public(),
                &proof
            )
            .is_none()
        );
    }
}
