//! **Coordinate-bound directory records** — the one check that makes a slot's address mean something (S1-M3).
//!
//! Every live directory in this crate ([`crate::mixdir`], [`crate::capdir`]) works the same way: a node publishes a record
//! at a store slot derived from its coordinate, and every other node reads the whole cell's roster back. The slot address
//! is derived from the coordinate — but that only says *where* the bytes were written, and any node that can write to the
//! store can write to every slot. Without a binding, one node can populate the entire plane and become the whole directory:
//! for `mixdir` that means a client's circuit runs through keys the adversary chose, and for `capdir` it means the cell's
//! role assignment runs over a roster the adversary wrote.
//!
//! Signing the record does not fix this, which is the trap `capdir` sat in: a signature proves *someone* holding that key
//! signed those bytes, not that the key is **entitled to that coordinate**. A forger publishing a self-consistent record
//! signed by their own fresh key at another node's slot passes every signature check.
//!
//! [`Entitlement`] is the missing half. The publisher carries the credential its coordinate is *derived from* — its identity
//! bytes, VRF public and VRF proof — and the reader recomputes the VRF output and checks that the slot's coordinate lies on
//! that publisher's own probe walk. A key that cannot prove entitlement to the coordinate is refused.
//!
//! ## What it costs an attacker, and what it does not
//!
//! Hitting *some* point of a chosen node's walk, rather than any point at all: the walk is `q + 1` of the plane's
//! `q² + q + 1` points, so on PG(2,7) a lifted record is refused at 49 of the other 56 points. Against **zero** for the
//! unsigned record it replaces — a cost, not an impossibility. It deliberately omits the exact probe *index*, which would
//! need the publisher's full witness chain (`CoordinateClaim`) and would raise the cost to the whole plane. That is the
//! stronger form and the natural follow-up.
//!
//! **A cross-reference to #249 stood here and was WRONG — corrected 2026-08-12, the same day it was written.** It
//! claimed `fanos_quic`'s unranked peer bindings suffered "the same omission", so the two were one wire change. They
//! are not the same, and #249 needed no wire change at all: the index is a *function of the peer's VRF output*
//! ([`probe_index_of`]'s own doc: a verifier learns it "without being told"), so over there it was derivable all along
//! and merely dropped at two internal boundaries. Fixed by carrying the peer's output and the plane type down to the
//! send path; the measured roster went `route [1,1,1,1,1,1,1]` → `[2,2,4,2,4,2,4]`.
//!
//! **What that leaves here is genuinely different, and it survives.** This module does not want to know *whether* the
//! coordinate is on the walk — it computes that already, on the line below. It wants to know that the publisher is at
//! the point it *settled* on, and settling is where a competitor displaced it: that fact is not a function of the
//! publisher's own output, which is exactly why it needs the witness chain and why the cost stays at 49-of-56. The two
//! problems shared a word ("probe index") and nothing else, and joining them cost a day.
//!
//! [`probe_index_of`]: fanos_vrf::probe_index_of
//!
//! ## It applies only where coordinates are VRF-derived
//!
//! A *pinned* coordinate has no relation to the node's VRF output, so no publisher in a pinned cell can produce a bound
//! record and no reader can verify one — the same VRF-versus-pinned split `OverlayNode::on_announce` makes for audit C3.
//! That is why every resolver here takes `Option<BeaconSeed>` rather than a `verify: bool`: having a beacon *is* the VRF
//! mode, and the absence of one is not a disabled check but an absent mechanism. [`crate::Node`] always runs VRF
//! coordinates; the `fanos-quic` cell harness always pins them.
//!
//! The mode cannot be inferred from below, and looked like it could: a claim book exists exactly when a node has a
//! self-certifying identity, which reads as the same predicate and is not one — a pinned harness gives its nodes identities
//! while seating none of them on a point it could prove. It is a deployment property of the cell, stated by whoever
//! configured it.

use fanos_diaulos::Coord;
use fanos_field::Field;
use fanos_geometry::{HierAddr, Point};
use fanos_primitives::BeaconSeed;
use fanos_rendezvous::Epoch;
use fanos_vrf::{VrfOutput, VrfProof, VrfPublic, coordinate_output, probe_index_of};

/// The fixed part of the wire form: `vrf_public(32) ‖ vrf_proof(80)`.
const CREDENTIAL_LEN: usize = 32 + 80;

/// A publisher's proof that its VRF key is entitled to the coordinate its record was found at.
///
/// Wire form `id_len(2) ‖ id ‖ vrf_public(32) ‖ vrf_proof(80)`, followed by the record's own payload. The identity bytes
/// are carried rather than derived from the payload because the coordinate VRF binds the publisher's **certificate DER**,
/// which no directory payload holds — and carrying a *second* copy of an identity the payload already names would create
/// two sources of truth for one fact, which is a cross-check waiting to be forgotten.
pub struct Entitlement {
    /// The identity the coordinate VRF is bound to — the publisher's certificate DER, as `CoordinateProver` yields it.
    pub id: Vec<u8>,
    /// The VRF public key the coordinate is derived from, and (in a signed directory) the key the payload is signed with.
    pub public: VrfPublic,
    /// The proof that ties `public` to `(id, epoch, beacon)`.
    pub proof: VrfProof,
}

impl Entitlement {
    /// Encode `self ‖ payload` as a bound record.
    #[must_use]
    pub fn encode(id: &[u8], public: &VrfPublic, proof: &VrfProof, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + id.len() + CREDENTIAL_LEN + payload.len());
        out.extend_from_slice(&u16::try_from(id.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(&public.to_bytes());
        out.extend_from_slice(&proof.to_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Split a bound record into its credential and the payload that follows, or `None` on malformed bytes.
    ///
    /// Length-checked throughout with `get`: these bytes arrive from the store, so any node may have written them, and a
    /// directory read that can panic is a directory read an adversary can use to stop a node.
    fn split(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let id_len = usize::from(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?));
        let id = bytes.get(2..2 + id_len)?.to_vec();
        let at = 2 + id_len;
        let public = VrfPublic::from_bytes(bytes.get(at..at + 32)?.try_into().ok()?)?;
        let proof = VrfProof::from_bytes(bytes.get(at + 32..at + CREDENTIAL_LEN)?.try_into().ok()?)?;
        let payload = bytes.get(at + CREDENTIAL_LEN..)?;
        Some((Self { id, public, proof }, payload))
    }

    /// Split a bound record **and verify** that its publisher is entitled to `coord` for `(epoch, beacon)`.
    ///
    /// `None` on malformed bytes, a proof that does not verify, or a coordinate the publisher's own probe walk never
    /// reaches. The verified [`Entitlement`] comes back with the payload so a signed directory can authenticate its payload
    /// against the very key that was just proven entitled — the two halves must be the same key or the chain does not
    /// close.
    #[must_use]
    pub fn open<'a, F: Field>(
        bytes: &'a [u8],
        coord: Coord,
        epoch: Epoch,
        beacon: &BeaconSeed,
    ) -> Option<(Self, &'a [u8])> {
        let (me, payload, _, _) = Self::open_with_claim::<F>(bytes, coord, epoch, beacon)?;
        Some((me, payload))
    }

    /// Split a bound record and verify its publisher is entitled to a **seat in the address trie** — the
    /// sub-cell counterpart of [`open`](Self::open), which can only speak about the base plane.
    ///
    /// The two halves of "entitled" are answered by two different things, and separating them is what makes
    /// a sub-cell record checkable at all:
    ///
    /// * **Key possession** — the same VRF proof [`open`](Self::open) checks. Only the holder of the secret
    ///   can produce it, so a record is not forgeable by anyone who merely knows the certificate.
    /// * **Seat membership** — a *recomputation*, not a proof. `coordinate_at_level(cert, level)` is a pure
    ///   function of the publisher's certificate, so the reader re-derives the address the identity descends
    ///   to and compares it, level by level, with the seat's own. If the identity derives this address, this
    ///   address **is** its seat; no signature can say more than the derivation already does.
    ///
    /// This is why a descended node keeping its transport coordinate is not the obstacle it looked like: the
    /// seat was never a claim about the transport point. What it deliberately does **not** establish is the
    /// *depth* — `hierarchical_coordinate` descends while its `occupied` predicate says a level is full, and
    /// that predicate is local knowledge. A node may therefore publish at a seat deeper than it occupies,
    /// which is a liveness claim about an absent node and is caught the way every other absence is: by the
    /// parent sampling the child.
    pub fn open_at_seat<'a, F: Field>(
        bytes: &'a [u8],
        seat: &HierAddr<F>,
        epoch: Epoch,
        beacon: &BeaconSeed,
    ) -> Option<(Self, &'a [u8])> {
        let (me, payload) = Self::split(bytes)?;
        // Key possession first: a mismatch below is a wrong seat, and a wrong seat by an unauthenticated
        // publisher is not worth distinguishing from noise.
        coordinate_output(&me.public, &me.id, epoch, beacon, &me.proof)?;
        let derives_this_seat = seat
            .points()
            .iter()
            .enumerate()
            .all(|(level, point)| fanos_quic::coordinate_at_level::<F>(&me.id, level) == *point);
        derives_this_seat.then_some((me, payload))
    }

    /// As [`open`](Self::open), and **hands back the claim it had to compute anyway**.
    ///
    /// Opening a bound record already derives the writer's `VrfOutput` and asks `probe_index_of` where the
    /// slot's point sits on that writer's walk — the two values `fanos_vrf::claim_beats` orders claims by,
    /// and the pair `fanos_quic`'s claim book is fed with. Both were computed, spent on one yes/no, dropped.
    ///
    /// **A reader that finds a record it did not write is holding a proof, not a puzzle.** Its own slot is
    /// keyed by its coordinate (`cap_slot`), so any node contending for that coordinate writes and reads the
    /// same place by construction — no routing luck, unlike dialling the point, which in a young cell
    /// resolves to nothing and, once the contest is live, to the reader itself. Handing the pair back is
    /// what lets the loser of a silent overwrite learn that it lost *and* prove the step it must take: an
    /// index `k` needs `k` witnesses, and the record at the slot is one.
    pub fn open_with_claim<'a, F: Field>(
        bytes: &'a [u8],
        coord: Coord,
        epoch: Epoch,
        beacon: &BeaconSeed,
    ) -> Option<(Self, &'a [u8], VrfOutput, u16)> {
        let (me, payload) = Self::split(bytes)?;
        let point = Point::<F>::new(coord)?;
        let output = coordinate_output(&me.public, &me.id, epoch, beacon, &me.proof)?;
        let index = probe_index_of::<F>(&output, &point)?;
        Some((me, payload, output, index))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    /// A sub-cell seat opens for the identity that **derives** it, and for no other seat on the path.
    ///
    /// Both halves are asserted because either alone is a hole. Acceptance alone would pass with a check that
    /// admits everything; refusal alone would pass with one that admits nothing — and "admits nothing" is
    /// exactly the state this replaced, so it is the failure mode most likely to come back.
    ///
    /// Falsified before it was trusted: replacing the level comparison in `open_at_seat` with `true` reddens
    /// the second assertion, and dropping the VRF check reddens the third.
    #[test]
    fn a_sub_cell_seat_opens_for_the_identity_that_derives_it() {
        use fanos_field::F4;
        use fanos_geometry::HierAddr;
        use fanos_vrf::{VrfSecret, prove_coordinate};

        let (epoch, beacon) = (Epoch::new(9), BeaconSeed::GENESIS);
        let sk = VrfSecret::from_seed([7u8; 32]);
        let id = b"a certificate, as far as the descent is concerned".to_vec();
        let (_, proof) = prove_coordinate::<F4>(&sk, &id, epoch, &beacon);
        let record = Entitlement::encode(&id, &sk.public(), &proof, b"payload");

        // The address this identity descends to, level by level — the same function the node itself walks.
        let mine = HierAddr::root(fanos_quic::coordinate_at_level::<F4>(&id, 0))
            .descended(fanos_quic::coordinate_at_level::<F4>(&id, 1))
            .expect("a depth-2 address exists below the root");
        assert_eq!(
            Entitlement::open_at_seat::<F4>(&record, &mine, epoch, &beacon).map(|(_, p)| p),
            Some(&b"payload"[..]),
            "a member could not open the sub-cell seat its own certificate derives, so no sub-cell can \
             publish at all"
        );

        // A neighbouring seat of the same cell: same prefix, a point this identity does not derive.
        let elsewhere = fanos_geometry::fano::cell_members_of::<F4>(0)
            .expect("PG(2,4) splits into cells")
            .coords()
            .iter()
            .filter_map(|&c| Point::<F4>::new(c))
            .find(|p| Some(p) != mine.points().get(1))
            .expect("a cell has more than one seat");
        let wrong = HierAddr::root(fanos_quic::coordinate_at_level::<F4>(&id, 0))
            .descended(elsewhere)
            .expect("the neighbour is an address too");
        assert!(
            Entitlement::open_at_seat::<F4>(&record, &wrong, epoch, &beacon).is_none(),
            "a seat accepted a record whose identity descends elsewhere: one member then fills every seat of \
             the cell, and everything folded from those seats is one identity's opinion seven times"
        );

        // Key possession is still required: the same identity bytes with somebody else's proof.
        let theirs = prove_coordinate::<F4>(&VrfSecret::from_seed([8u8; 32]), &id, epoch, &beacon).1;
        let forged = Entitlement::encode(&id, &sk.public(), &theirs, b"payload");
        assert!(
            Entitlement::open_at_seat::<F4>(&forged, &mine, epoch, &beacon).is_none(),
            "a seat opened for a record nobody proved a key for — the descent is public, so the VRF proof is \
             the whole of what separates the holder from anyone who has seen its certificate"
        );
    }

    #[test]
    fn a_malformed_record_is_refused_rather_than_panicking() {
        // These bytes come from the store, so every node can write them. Truncations at each field boundary, plus an
        // id_len that overruns the buffer — the shape an adversary reaches for first.
        let beacon = BeaconSeed::GENESIS;
        for len in 0..CREDENTIAL_LEN + 8 {
            let bytes = vec![0u8; len];
            assert!(
                Entitlement::open::<F2>(&bytes, [1, 0, 0], Epoch::ZERO, &beacon).is_none(),
                "a {len}-byte record is refused"
            );
        }
        let mut overrun = u16::MAX.to_be_bytes().to_vec();
        overrun.extend_from_slice(&[0u8; 200]);
        assert!(
            Entitlement::open::<F2>(&overrun, [1, 0, 0], Epoch::ZERO, &beacon).is_none(),
            "an id_len past the end of the buffer is refused, not read past"
        );
    }

    #[test]
    fn the_payload_survives_the_round_trip_byte_for_byte() {
        // `split` is the inverse of `encode` including a zero-length id and a zero-length payload — the two boundaries
        // where an off-by-one in the offset arithmetic hides.
        for id in [vec![], vec![7u8; 1], vec![9u8; 300]] {
            for payload in [vec![], b"a-payload".to_vec()] {
                // Any well-formed pair: `split` is pure offset arithmetic and never verifies, which is exactly the
                // separation being tested — a record that parses is not yet a record that is entitled.
                let secret = fanos_vrf::VrfSecret::from_seed([0x3B; 32]);
                let public = secret.public();
                let (proof, _) = secret.prove(b"any-alpha");
                let bytes = Entitlement::encode(&id, &public, &proof, &payload);
                let (me, rest) = Entitlement::split(&bytes).expect("a well-formed record splits");
                assert_eq!(me.id, id, "the identity round-trips");
                assert_eq!(rest, &payload[..], "and so does the payload, byte for byte");
            }
        }
    }
}
