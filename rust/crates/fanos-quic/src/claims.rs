//! The **claim book** — the peer coordinate-claims a node has verified this epoch.
//!
//! Coordinate resolution (`fanos_vrf::deferred_claim`) needs one thing a node can only get from the peers it has
//! actually met: their verified claim material, `(id, VRF public, proof, output)`. From that it computes the whole
//! assignment and reads its own seat and its own justification out of it. All of it comes from `HELLO` frames this node
//! already verified, so this is where it is kept.
//!
//! ## ⛔ What changed on 2026-08-21, and why the per-point index went with it
//!
//! This module used to maintain a `best` table — *the best claim any peer holds to each point* — built incrementally as
//! peers were recorded, and `settle_index` consumed it one point at a time. That table is exactly the **phantom yield**:
//! a peer's claim to `p` counted whether or not it ended up on `p`. Measured, that is the difference between **7.5 %**
//! and **97.5 %** of `PG(2,4)` draws at `1.5 N` clearing the line-viability floor
//! (`fanos-vrf/examples/line_confinement_coverage.rs`), so the table is gone and with it the foreign key from `best` to
//! `peers`, its eviction invariant, and `witness_for`.
//!
//! **The performance argument that built it still holds and is answered differently.** Computing a claim to `p` means
//! walking the peer's line, and doing that per query, at every step of every settle, measured a **77× slowdown** on the
//! simulator's `P = 993` fixture (209 s against 2.7 s). The deferred rule needs every walk anyway, so it builds each one
//! **once per assignment** (`fanos_vrf::probe_walk_of`) — the same "once, not once per query" shape, one layer up. What
//! it costs is one `O(n·q)` pass per settle instead of `q + 1` map lookups, on a path that runs when a peer is met or a
//! beacon advances, not per frame.
//!
//! **No per-point index remains at all, and the second one went the same way.** A replacement — `anyone_reaches`, "is
//! there any point in asking this peer for its claim" — survived the first pass and was removed on the same day it
//! landed, because it answers the phantom yield's question one layer up: under deferred acceptance a seat is decided by
//! who *holds* a point, so "someone I know reaches it" is not evidence about it and using that to skip an ask would
//! drop exactly the seated claim the assignment must have. The `Wake::Meet` probe now asks once per coordinate per
//! epoch (`fanos_quic::driver`), which is the same bound and no inference.
//!
//! ## Why the book is epoch-scoped
//!
//! A coordinate proof binds `(identity, epoch, beacon)`, so a claim verified for one epoch says nothing about the next —
//! and the epoch's beacon is exactly what makes placement unpredictable (spec §3.2 assumption 2). [`ClaimBook::adopt`]
//! therefore *clears* the book when the epoch moves. Carrying claims across an epoch would let a peer's retired placement
//! justify a displacement in the current one, which is the pre-settling attack the beacon exists to prevent.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::Notify;

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_primitives::collections::BoundedMap;
use fanos_primitives::hash::hash_labeled;
use fanos_primitives::Epoch;
use fanos_vrf::{Claimant, VrfOutput, VrfProof, VrfPublic};

/// How many peers' claim material one node retains.
///
/// A claim is only useful for a point on *this* node's line, of which there are `q + 1`, but a witness may be any peer
/// whose walk reaches a contested point earlier — so the useful set is not bounded by the line. This is bounded because
/// the book grows from the network: every accepted `HELLO` adds an entry, and an unbounded map fed by connection attempts
/// is a memory-exhaustion path even when every entry is authentic.
///
/// **This number carries no correctness argument, deliberately.** It used to: the doc said "the largest plane this code
/// represents holds 993 points, so this is comfortably past a full cell". That was wrong twice over. 993 is
/// `31² + 31 + 1`, the point count of `F31` — but `fanos_field` also defines `F127` (16257 points) and `F256`
/// (`Gf2m<8>`, 65793 points), so it was not the largest plane; and it was a statement about *points*, i.e. about the
/// per-point index, applied to `peers`, which is keyed by an identity hash over a 2^256 space and is bounded by nothing
/// geometric — as
/// the paragraph above says two sentences earlier. The shipped binary runs `F2` (7 points), so the arithmetic never
/// bit; it was a proof of the wrong proposition that happened to sit above true code.
///
/// ⛔ The paragraph that used to follow described an invariant tying `peers` to a per-point `best` index — *"it retains
/// every holder `best` names, since `Best::holder` is a foreign key into it"*. Both the index and the foreign key are
/// gone with the phantom yield (see the module doc), so `peers` is now the only store and this is free to be what it
/// always was: a flood bound, comfortably past a full cell, at a fixed cost.
pub(crate) const CAPACITY: usize = 1024;

/// One peer's verified coordinate claim material — exactly what `fanos_vrf::Claimant` needs, kept in the owned form a
/// book can hold.
///
/// ⛔ **The `output` is new and its absence used to be the point.** This struct's doc read *"note what is absent: where
/// the peer settled — a witness proves only its own claim to the contested point, which is what keeps
/// `verify_coordinate_claim` non-recursive"*. Where a peer settles is now a fact about the whole assignment rather than
/// a field, and computing that assignment needs every peer's output. It was already being kept, one struct over, in the
/// per-point index that has since been deleted.
#[derive(Clone)]
struct PeerClaim {
    /// The peer's identity bytes as fed to the coordinate VRF (its certificate DER).
    id: Vec<u8>,
    /// The peer's VRF public key.
    public: VrfPublic,
    /// The peer's coordinate proof for this epoch.
    proof: VrfProof,
    /// The output that proof yielded — the peer's rank, and the whole of what the assignment consumes.
    output: VrfOutput,
}

/// A shared, cloneable book of verified peer claims for the current epoch. Cheap to clone (shares one book).
#[derive(Clone)]
pub(crate) struct ClaimBook {
    inner: Arc<Mutex<Book>>,
    /// Signalled whenever a claim is recorded.
    ///
    /// The book is written by the `HELLO` verifier, which runs on a connection's own task, while settling runs on the
    /// placement loop. Nothing else connects them: the engine emits no notification for a peer merely *completing a
    /// handshake*, so without this the loop would only ever re-settle when a beacon advanced — and a node learns that a
    /// better claim holds its point precisely by meeting the peer that holds it. `notify_one` rather than
    /// `notify_waiters` so a record landing between two waits is remembered instead of lost — and signalled *after* the
    /// write completes, so a woken waiter cannot read the book as it was.
    changed: Arc<Notify>,
}

struct Book {
    epoch: Epoch,
    peers: BoundedMap<[u8; 32], PeerClaim>,
}

impl Default for ClaimBook {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaimBook {
    /// An empty book at the genesis epoch.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Book { epoch: Epoch::ZERO, peers: BoundedMap::new(CAPACITY) })),
            changed: Arc::new(Notify::new()),
        }
    }

    /// Move the book to `epoch`, **clearing** it if the epoch changed.
    ///
    /// Claims do not survive an epoch: each is a proof over `(identity, epoch, beacon)`, and the beacon is what makes the
    /// next epoch's placement unpredictable. Keeping a retired claim would let it justify a displacement it has no bearing
    /// on. Idempotent, so the caller may announce the same epoch repeatedly.
    pub(crate) fn adopt(&self, epoch: Epoch) {
        let mut book = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if book.epoch == epoch {
            return;
        }
        book.epoch = epoch;
        book.peers = BoundedMap::new(CAPACITY);
    }

    /// Record a peer's **verified** claim material, indexing its whole walk.
    ///
    /// **No longer generic over the plane.** It used to walk the peer's whole line to index it, which is where the `F`
    /// went; the assignment builds those walks itself now, once per settle rather than once per record, so recording a
    /// claim is a map insert and knows nothing about geometry.
    ///
    /// `output` must be the output the peer's `proof` actually yielded for `(id, epoch, beacon)` — this type does not
    /// re-verify, because its only caller is the `HELLO` verifier that just did. Recording an unverified claim would let a
    /// peer install a witness that fails at the far end, turning its own forgery into *this* node's rejected handshake.
    pub(crate) fn record(&self, id: &[u8], public: VrfPublic, proof: VrfProof, output: &VrfOutput) {
        let key = hash_labeled("FANOS-v1/claim-book-peer", id);
        let mut book = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        book.peers.insert(key, PeerClaim { id: id.to_vec(), public, proof, output: *output });
        // Signal AFTER the write, and after releasing the lock. Signalling first is a race that looks harmless and is not:
        // the waiter wakes, settles against the book as it was, finds nothing to do, and waits again — and if that record
        // was the only one coming (the common case, a two-node collision) nothing ever wakes it again. This ordering bug
        // was live between `474cda1` and here, and it is a candidate cause of the failed live-resolution measurement.
        drop(book);
        self.changed.notify_one();
    }

    /// This node's seat under the deferred assignment, or `None` if every point of its line is better held.
    ///
    /// The single query the placement loop asks. `me` is the caller's own claimant material; the book supplies every
    /// peer's. Both go into `fanos_vrf::deferred_assignment`, which is why this cannot be answered one point at a time.
    #[must_use]
    fn with_claimants<T>(&self, me: &Claimant<'_>, f: impl FnOnce(&[Claimant<'_>]) -> T) -> T {
        let book = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut claimants = Vec::with_capacity(book.peers.len() + 1);
        claimants.push(*me);
        claimants.extend(book.peers.iter().map(|(_, p)| Claimant {
            id: &p.id,
            public: p.public,
            proof: p.proof,
            output: p.output,
        }));
        f(&claimants)
    }

    /// The seat at probe step `index`, when the assignment gives that point to **someone else**.
    ///
    /// [`settle`] answers "where should I sit"; this answers the narrower question "is where I already sit still mine".
    /// The two differ only for a node that may not act on the answer — an established one, which the reshuffle loop
    /// forbids to move mid-epoch (see `spawn_self_certifying`). It cannot resolve the contest, so what it can do is
    /// *say* so, and that is why this exists apart from [`settle`] rather than inside it.
    ///
    /// Both read the same assignment from the same book, so a node reporting itself outranked here and a peer
    /// concluding it won there cannot disagree — the property the old pair maintained by sharing a table, now held by
    /// sharing the function that builds one.
    ///
    /// Takes the **output alone**, not a whole [`Claimant`]: an assignment is a function of the contending outputs, and
    /// the identity, key and proof are needed only to *build* a claim. The narrower argument is what lets a caller that
    /// holds only a directory binding — `Client::seat_outranked` — ask this at all.
    #[must_use]
    pub(crate) fn outranked_at<F: Field>(&self, mine: &VrfOutput, index: u16) -> Option<Triple> {
        let seat = fanos_vrf::probe_point::<F>(mine, index).coords();
        let book = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut outputs = Vec::with_capacity(book.peers.len() + 1);
        outputs.push(*mine);
        outputs.extend(book.peers.iter().map(|(_, p)| p.output));
        drop(book);
        // Position 0 is always the caller; anyone else on this node's seat is who took it.
        match fanos_vrf::deferred_assignment::<F>(&outputs).get(&seat) {
            Some(&(_, holder)) => (holder != 0).then_some(seat),
            None => None,
        }
    }

    /// Wait until a claim is recorded.
    ///
    /// The other half of the placement loop's wake-up: it selects on this and on the engine's notifications, so a peer
    /// arriving is as good a reason to re-settle as a beacon advancing.
    pub(crate) async fn changed(&self) {
        self.changed.notified().await;
    }

    /// The epoch this book holds claims for.
    ///
    /// A caller verifying a peer that proves a *past* epoch (the safe-stall window, audit R-C1) must not record it: that
    /// claim is evidence about the retired epoch's placement, and admitting it would let a stale placement justify a
    /// displacement now. Comparing against this is how the caller tells the two apart.
    #[must_use]
    pub(crate) fn epoch(&self) -> Epoch {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).epoch
    }

    /// The number of peers whose coordinate claims are recorded this epoch.
    ///
    /// Reported on the node's health surface, and not only as a diagnostic: it is the input coordinate resolution runs on,
    /// so a node that cannot advance off a contested point and has a *low* count is failing for a different reason than one
    /// with a high count. The simulator asserts on it for exactly that reason — a symptom that cannot be localised is a
    /// measurement, not a test.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).peers.len()
    }

}

/// This node's seat and the **provable claim** to it, given what it has verified.
///
/// Returns the settled index and a claim whose every skipped step is justified by the node that *holds* that point,
/// carrying that node's own claim, recursively. `None` if every point of this node's line is better held —
/// `deferred_claim` exhausted, the honest answer rather than a wrapped index.
///
/// **Settling and proving are one call now, and that is the repair rather than a tidy-up.** They used to be two —
/// `settle_index` over a per-point oracle, then `witness_for` per skipped step — kept consistent by both reading one
/// table, and the comment here said so. Two derivations of one rule is exactly what produced the unprovable-displacement
/// defect `fanos_vrf::displacement_is_forced` records; the table made them agree without making them one thing.
/// `fanos_vrf::deferred_claim` is one thing.
#[must_use]
pub(crate) fn settle<F: Field>(book: &ClaimBook, me: &Claimant<'_>) -> Option<(u16, fanos_vrf::CoordinateClaim)> {
    book.with_claimants(me, |claimants| fanos_vrf::deferred_claim::<F>(0, claimants))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::{F7, F31};
    use fanos_primitives::BeaconSeed;
    use fanos_vrf::{
        VrfSecret, claim_beats, probe_bound, probe_point, prove_coordinate_ranked, verify_coordinate_claim,
    };

    /// One identity's epoch claim material, as the HELLO verifier hands it over.
    type Material = (Vec<u8>, VrfPublic, VrfProof, VrfOutput);

    /// The claimant view of [`Material`] — what `settle` and `outranked_at` take.
    fn as_claimant(m: &Material) -> Claimant<'_> {
        Claimant { id: &m.0, public: m.1, proof: m.2, output: m.3 }
    }

    /// Whether two nodes take the identical walk — same line, same stride, so the same point at every index.
    fn walks_coincide(a: &VrfOutput, b: &VrfOutput) -> bool {
        (0..probe_bound::<F7>()).all(|k| probe_point::<F7>(a, k) == probe_point::<F7>(b, k))
    }

    /// As [`peer`], with a 16-bit seed — needed where the fixture must search a few hundred identities — and generic
    /// over the plane, because the flood fixture needs one large enough that a book at `CAPACITY` does not fill it.
    fn peer16<F: Field>(seed: u16, epoch: Epoch, beacon: &BeaconSeed) -> Material {
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&seed.to_le_bytes());
        let sk = VrfSecret::from_seed(bytes);
        let id = format!("peer16-{seed}").into_bytes();
        let (_, proof, output) = prove_coordinate_ranked::<F>(&sk, &id, epoch, beacon);
        (id, sk.public(), proof, output)
    }

    /// A peer identity with its epoch claim material, as the HELLO verifier would hand it over.
    fn peer(seed: u8, epoch: Epoch, beacon: &BeaconSeed) -> Material {
        let sk = VrfSecret::from_seed([seed; 32]);
        let id = format!("peer-{seed}").into_bytes();
        let (_, proof, output) = prove_coordinate_ranked::<F7>(&sk, &id, epoch, beacon);
        (id, sk.public(), proof, output)
    }

    /// Find two identities that collide on their preferred point but take **different** walks from it, ordered so the
    /// first is the one the rank rule moves. Sharing the whole walk is the separate case
    /// `a_node_beaten_at_every_step_is_not_seated_at_all` pins.
    fn colliding_pair(peers: &[Material]) -> Option<(&Material, &Material)> {
        peers.iter().enumerate().find_map(|(i, a)| {
            peers.iter().skip(i + 1).find_map(|b| {
                if probe_point::<F7>(&a.3, 0) != probe_point::<F7>(&b.3, 0) || walks_coincide(&a.3, &b.3) {
                    return None;
                }
                Some(if claim_beats((0, &b.3), (0, &a.3)) { (a, b) } else { (b, a) })
            })
        })
    }

    /// ⛔ **Replaces `a_peer_flood_never_leaves_a_best_claim_naming_a_forgotten_holder`.**
    ///
    /// That test guarded a foreign key: a per-point index named a holder in `peers`, the two were independently
    /// bounded, and an eviction could leave the book self-contradicting — reporting a point contested while being
    /// unable to name the witness. The index is gone with the phantom yield, and with it the whole failure mode: an
    /// assignment is computed over exactly the peers the book holds, so it cannot reference one it has forgotten.
    ///
    /// What survives is the property the invariant existed to protect, under the same load: **a book that has evicted
    /// half of everything it saw never settles anywhere it cannot prove.** Note the shape — `settle` is allowed to
    /// answer `None`, and at this load it usually must: 1024 peers on `PG(2,7)`'s 57 points is eighteen times
    /// oversubscribed, so almost nobody is seated. The property is the implication, not the seat.
    ///
    /// **And that is why this one runs on `F31` while every other test here uses `F7`.** Provoking an eviction needs
    /// more than `CAPACITY = 1024` peers; `PG(2,7)` has 57 points, so 1024 retained peers leave every point held by a
    /// very-well-ranked one and **no** candidate settles — the implication holds vacuously and the test asserts
    /// nothing. `PG(2,31)`'s 993 points make the retained book roughly one node per point, which is a load at which
    /// some candidates seat and some do not: exactly the mix the implication needs. The `checked > 0` guard is what
    /// caught the vacuous version.
    #[test]
    fn a_peer_flood_still_leaves_a_book_that_settles_only_where_it_can_prove() {
        let epoch = Epoch::new(4);
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        book.adopt(epoch);

        // Twice the capacity, so `peers` must evict about half of everything it ever saw.
        for s in 0..(CAPACITY as u16 * 2) {
            let m = peer16::<F31>(s, epoch, &beacon);
            book.record(&m.0, m.1, m.2, &m.3);
        }
        assert_eq!(book.len(), CAPACITY, "the book filled and evicted, so the property is under load");

        let mut checked = 0;
        for s in 60_000u16..60_040 {
            let me = peer16::<F31>(s, epoch, &beacon);
            let Some((index, claim)) = settle::<F31>(&book, &as_claimant(&me)) else { continue };
            checked += 1;
            assert!(
                verify_coordinate_claim::<F31>(
                    &me.1,
                    &me.0,
                    epoch,
                    &beacon,
                    &probe_point::<F31>(&me.3, index),
                    &claim
                ),
                "settled at index {index} against a flooded book, but the verifier rejects the claim"
            );
        }
        // Not an assertion about the seat: it is the guard against the implication being vacuous.
        assert!(checked > 0, "no candidate seated at all, so the verification above never ran");
    }

    #[test]
    fn a_settled_claim_is_one_the_verifier_accepts() {
        // The end-to-end property: whatever index the book settles on, the claim it assembles must verify against the
        // same predicate a remote peer applies. If these two ever disagree, a node announces a point it cannot prove.
        let epoch = Epoch::new(3);
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        book.adopt(epoch);

        let all: Vec<Material> = (0..24u8).map(|s| peer(s, epoch, &beacon)).collect();
        // Everyone except the last is a recorded peer; the last one settles against them.
        for m in &all[..all.len() - 1] {
            book.record(&m.0, m.1, m.2, &m.3);
        }
        let me = all.last().unwrap();

        let (index, claim) = settle::<F7>(&book, &as_claimant(me)).expect("a seat on its own line");
        assert_eq!(claim.witnesses.len(), usize::from(index), "one witness per skipped step");
        assert!(
            verify_coordinate_claim::<F7>(
                &me.1,
                &me.0,
                epoch,
                &beacon,
                &probe_point::<F7>(&me.3, index),
                &claim
            ),
            "settled at index {index} but the verifier rejects the claim"
        );
    }

    #[test]
    fn an_uncontested_node_settles_at_its_preference_with_no_witnesses() {
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        let me = peer(9, epoch, &beacon);
        let (index, claim) = settle::<F7>(&book, &as_claimant(&me)).expect("an empty book contests nothing");
        assert_eq!(index, 0, "nothing observed ⇒ the preference stands");
        assert!(claim.witnesses.is_empty(), "and a direct claim carries no witnesses");
        assert_eq!(claim, fanos_vrf::CoordinateClaim::direct(me.2), "it is exactly the pre-existing claim");
    }

    #[test]
    fn a_better_claim_displaces_and_supplies_its_own_witness() {
        // The displacement, constructed rather than hoped for: find two identities whose preferred point is the same and
        // whose claims therefore differ only by rank, record the better one, and settle the worse one against it.
        let epoch = Epoch::new(5);
        let beacon = BeaconSeed::GENESIS;
        let peers: Vec<Material> = (0..80u8).map(|s| peer(s, epoch, &beacon)).collect();
        let (loser, winner) =
            colliding_pair(&peers).expect("two of 80 identities collide on a point but not on a whole walk");

        let book = ClaimBook::new();
        book.adopt(epoch);
        book.record(&winner.0, winner.1, winner.2, &winner.3);

        let (index, claim) = settle::<F7>(&book, &as_claimant(loser)).expect("the loser has somewhere to go");
        assert!(index >= 1, "displaced from a point held by a better claim, so the index must advance (got {index})");
        assert_eq!(claim.witnesses.len(), usize::from(index), "and every step it took is witnessed");
        assert!(
            verify_coordinate_claim::<F7>(
                &loser.1,
                &loser.0,
                epoch,
                &beacon,
                &probe_point::<F7>(&loser.3, index),
                &claim
            ),
            "the displaced claim must verify at the far end"
        );
        // The winner keeps its preference: settling it against a book holding the loser does not move it.
        let other = ClaimBook::new();
        other.adopt(epoch);
        other.record(&loser.0, loser.1, loser.2, &loser.3);
        assert_eq!(
            settle::<F7>(&other, &as_claimant(winner)).map(|(k, _)| k),
            Some(0),
            "the better claim is the one that stays"
        );
    }

    /// The three answers `outranked_at` must give, on one constructed collision (#260).
    ///
    /// The reason it exists apart from `settle` is that its *caller* cannot act: an established node is forbidden to
    /// re-seat mid-epoch, so it needs the question "is my seat still mine?" answered on its own. The asymmetry is the
    /// property under test — the same pair must answer yes for the loser and no for the winner. A predicate that
    /// simply reported "somebody else claims this point" would pass the first assertion and fail the second, and it
    /// is the one an operator would have been shown.
    #[test]
    fn only_the_side_that_lost_the_arbitration_reports_its_seat_outranked() {
        let epoch = Epoch::new(5);
        let beacon = BeaconSeed::GENESIS;
        let peers: Vec<Material> = (0..80u8).map(|s| peer(s, epoch, &beacon)).collect();
        let (loser, winner) =
            colliding_pair(&peers).expect("two of 80 identities collide on a point but not on a whole walk");
        let contested = probe_point::<F7>(&loser.3, 0).coords();

        // An empty book contests nothing: the alarm must not fire merely because the node is seated somewhere.
        let empty = ClaimBook::new();
        empty.adopt(epoch);
        assert_eq!(empty.outranked_at::<F7>(&loser.3, 0), None, "no recorded peer ⇒ the seat is uncontested");

        let book = ClaimBook::new();
        book.adopt(epoch);
        book.record(&winner.0, winner.1, winner.2, &winner.3);
        assert_eq!(
            book.outranked_at::<F7>(&loser.3, 0),
            Some(contested),
            "the loser is seated on a point a recorded peer HOLDS, and must be able to say which"
        );

        // The other direction, on the same collision: the winner is contested too, and is not outranked.
        let mirror = ClaimBook::new();
        mirror.adopt(epoch);
        mirror.record(&loser.0, loser.1, loser.2, &loser.3);
        assert_eq!(
            mirror.outranked_at::<F7>(&winner.3, 0),
            None,
            "a peer merely *wanting* our point is not us losing it — and under the seated rule it is not even that: \
             the loser is assigned elsewhere, so it is not on this point at all"
        );
    }

    #[test]
    fn an_epoch_change_clears_the_book() {
        // A claim proves a placement for ONE epoch. Carrying it forward would let a retired placement justify a
        // displacement in the current epoch — the pre-settling attack the beacon exists to prevent.
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        book.adopt(Epoch::new(7));
        let m = peer(4, Epoch::new(7), &beacon);
        book.record(&m.0, m.1, m.2, &m.3);
        assert_eq!(book.len(), 1);
        let mine = peer(5, Epoch::new(7), &beacon);
        assert!(settle::<F7>(&book, &as_claimant(&mine)).is_some(), "a recorded peer is a claim the settle reads");

        book.adopt(Epoch::new(7)); // idempotent
        assert_eq!(book.len(), 1, "re-announcing the same epoch keeps the book");
        book.adopt(Epoch::new(8));
        assert_eq!(book.len(), 0, "a new epoch discards every claim");
        assert_eq!(
            settle::<F7>(&book, &as_claimant(&mine)).map(|(k, _)| k),
            Some(0),
            "with the book cleared the node is alone on the plane and settles at its own preferred point"
        );
    }

    /// ⛔ **Replaces `the_book_keeps_the_best_claim_per_point_not_the_last`.**
    ///
    /// That asserted arrival order over the deleted per-point index. The property it was really about — *insertion
    /// order must not decide anything* — belongs to the assignment now, so it is asserted where the assignment is
    /// read: every node settles at the same index whichever order the book learned its peers in.
    #[test]
    fn the_order_the_book_learned_its_peers_in_decides_nothing() {
        let epoch = Epoch::new(2);
        let beacon = BeaconSeed::GENESIS;
        let peers: Vec<Material> = (0..30u8).map(|s| peer(s, epoch, &beacon)).collect();

        let forward = ClaimBook::new();
        forward.adopt(epoch);
        for m in &peers {
            forward.record(&m.0, m.1, m.2, &m.3);
        }
        let backward = ClaimBook::new();
        backward.adopt(epoch);
        for m in peers.iter().rev() {
            backward.record(&m.0, m.1, m.2, &m.3);
        }
        let mut moved = 0;
        for m in &peers {
            let a = settle::<F7>(&forward, &as_claimant(m)).map(|(k, _)| k);
            let b = settle::<F7>(&backward, &as_claimant(m)).map(|(k, _)| k);
            assert_eq!(a, b, "a node's seat must not depend on the order its book learned the others in");
            if a.is_some_and(|k| k > 0) {
                moved += 1;
            }
        }
        assert!(moved > 0, "the fixture must actually displace somebody, or the assertion is about nothing");
    }

    /// ⛔ **Replaces `a_step_with_no_recorded_witness_is_not_taken`.**
    ///
    /// `witness_for` is gone: settling and proving are one call, so "settles where it cannot prove" is no longer a
    /// state the types admit. The property still worth pinning is the one that made it safe with partial information —
    /// an empty book moves nobody — plus the end-to-end check that a claim built from *any* book verifies, which the
    /// two tests above make against fuller ones.
    #[test]
    fn an_empty_book_moves_nobody() {
        let epoch = Epoch::new(6);
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        book.adopt(epoch);
        let me = peer(11, epoch, &beacon);
        assert_eq!(settle::<F7>(&book, &as_claimant(&me)).map(|(k, _)| k), Some(0));
        assert_eq!(book.outranked_at::<F7>(&me.3, 0), None);
    }

    /// ⛔ **`a_node_beaten_at_every_step_is_not_seated_at_all` asserted the opposite of this, and the phantom yield is
    /// why.**
    ///
    /// Two nodes whose outputs give the same preferred point AND the same line AND the same stride take the *identical*
    /// walk. Under the rule that shipped until 2026-08-21, the better-ranked one held the better *claim* at every index
    /// of that walk — whether or not it went there — so the other could be seated **nowhere**, and this file documented
    /// that as "the line restriction's residual failure mode", priced the attack that provokes it
    /// (`2·N·(q+1)·φ(q+1)` draws: 3 648 at `q = 7`, 1 016 832 at `q = 31`), and pinned it as a test.
    ///
    /// It was not the line restriction. It was the phantom yield. The winner is *seated* at one point of the shared
    /// walk, so under the seated rule it blocks exactly that one and the loser takes the next — which is what this now
    /// asserts, on the same constructed pair the old test used.
    ///
    /// **What remains, and it is a different attack.** `settle` can still answer `None`, and a caller must still read
    /// that as "announce nothing": a node is unseated when every one of the `q + 1` points of its line is *held* by a
    /// better claim. Starving a chosen victim therefore needs `q + 1` distinct better-ranked holders on that victim's
    /// line rather than one identity sharing its whole walk — the residual is not closed, it is `q + 1` times more
    /// expensive and no longer reachable by a single grind.
    #[test]
    fn two_nodes_sharing_a_whole_walk_are_both_seated_now() {
        let epoch = Epoch::new(5);
        let beacon = BeaconSeed::GENESIS;
        let peers: Vec<Material> = (0..400u16).map(|s| peer16::<F7>(s, epoch, &beacon)).collect();
        let pair = peers.iter().enumerate().find_map(|(i, a)| {
            peers.iter().skip(i + 1).find_map(|b| {
                walks_coincide(&a.3, &b.3).then(|| {
                    if claim_beats((0, &b.3), (0, &a.3)) { (a, b) } else { (b, a) }
                })
            })
        });
        let (loser, winner) = pair.expect("one of 400 identity pairs shares a whole walk (3.4% of colliding pairs)");

        let book = ClaimBook::new();
        book.adopt(epoch);
        book.record(&winner.0, winner.1, winner.2, &winner.3);
        let (index, claim) =
            settle::<F7>(&book, &as_claimant(loser)).expect("the winner holds ONE point of the shared walk, not all");
        assert_eq!(index, 1, "the winner is seated at index 0 of the walk they share, so the next point is free");
        assert!(
            verify_coordinate_claim::<F7>(
                &loser.1,
                &loser.0,
                epoch,
                &beacon,
                &probe_point::<F7>(&loser.3, index),
                &claim
            ),
            "and the seat it takes is one it can prove"
        );
        // The winner is unaffected: it holds its preference whichever way the pair is recorded.
        let other = ClaimBook::new();
        other.adopt(epoch);
        other.record(&loser.0, loser.1, loser.2, &loser.3);
        assert_eq!(settle::<F7>(&other, &as_claimant(winner)).map(|(k, _)| k), Some(0));
    }
}
