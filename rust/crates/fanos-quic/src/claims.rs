//! The **claim book** — the peer coordinate-claims a node has verified this epoch.
//!
//! Coordinate resolution (`fanos_vrf::settle_index`) needs two things a node can only get from the peers it has actually
//! met: the *best claim* held on each point of its own probe walk, and, for every step it advances, a *witness* proving it
//! was displaced. Both come from `HELLO` frames it has already verified, so this is where they are kept.
//!
//! ## Why the best claim is maintained per point, incrementally
//!
//! A claim to point `p` is `(probe_index_of(their_output, p), their_rank)`, and computing it means walking the peer's line
//! — `O(q² + q + 1)` with an allocation. Answering "who has the best claim to `p`?" by scanning the book per query costs
//! that for every peer, at every step of every settle. Measured on the simulator's `P = 993` fixture, doing it per query
//! rather than per peer was a **77× slowdown** (209 s against 2.7 s), so the walk happens **once per peer**, at insert,
//! and settling is then `q + 1` map lookups.
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
use fanos_geometry::{Point, Triple};
use fanos_primitives::collections::BoundedMap;
use fanos_primitives::hash::hash_labeled;
use fanos_primitives::Epoch;
use fanos_vrf::{DisplacementWitness, VrfOutput, VrfProof, VrfPublic, claim_beats, probe_bound, probe_point};

/// How many peers' claim material one node retains.
///
/// A claim is only useful for a point on *this* node's line, of which there are `q + 1`, but a witness may be any peer
/// whose walk reaches a contested point earlier — so the useful set is not bounded by the line. This is bounded because
/// the book grows from the network: every accepted `HELLO` adds an entry, and an unbounded map fed by connection attempts
/// is a memory-exhaustion path even when every entry is authentic. The largest plane this code represents holds 993
/// points, so this is comfortably past a full cell while staying a fixed cost.
pub(crate) const CAPACITY: usize = 1024;

/// One peer's verified coordinate claim material — everything a witness needs, and nothing more.
///
/// Note what is absent: where the peer *settled*. A witness proves only its own claim to the contested point, which is
/// what keeps `fanos_vrf::verify_coordinate_claim` non-recursive.
#[derive(Clone)]
struct PeerClaim {
    /// The peer's identity bytes as fed to the coordinate VRF (its certificate DER).
    id: Vec<u8>,
    /// The peer's VRF public key.
    public: VrfPublic,
    /// The peer's coordinate proof for this epoch.
    proof: VrfProof,
}

/// The best claim seen on one point, and who holds it.
#[derive(Clone, Copy)]
struct Best {
    index: u16,
    output: VrfOutput,
    /// Key into `peers`, so recovering the witness material is a lookup rather than a scan.
    holder: [u8; 32],
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
    best: BoundedMap<Triple, Best>,
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
            inner: Arc::new(Mutex::new(Book {
                epoch: Epoch::ZERO,
                peers: BoundedMap::new(CAPACITY),
                best: BoundedMap::new(CAPACITY),
            })),
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
        book.best = BoundedMap::new(CAPACITY);
    }

    /// Record a peer's **verified** claim material, indexing its whole walk.
    ///
    /// `output` must be the output the peer's `proof` actually yielded for `(id, epoch, beacon)` — this type does not
    /// re-verify, because its only caller is the `HELLO` verifier that just did. Recording an unverified claim would let a
    /// peer install a witness that fails at the far end, turning its own forgery into *this* node's rejected handshake.
    pub(crate) fn record<F: Field>(&self, id: &[u8], public: VrfPublic, proof: VrfProof, output: &VrfOutput) {
        let key = hash_labeled("FANOS-v1/claim-book-peer", id);
        let mut book = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        book.peers.insert(key, PeerClaim { id: id.to_vec(), public, proof });
        // Index the peer's entire walk once. This is the whole reason the book exists rather than a scan per query.
        for index in 0..probe_bound::<F>() {
            let point = probe_point::<F>(output, index).coords();
            let candidate = Best { index, output: *output, holder: key };
            let better = match book.best.get(&point) {
                None => true,
                Some(held) => claim_beats((candidate.index, &candidate.output), (held.index, &held.output)),
            };
            if better {
                book.best.insert(point, candidate);
            }
        }
        // Signal AFTER the write, and after releasing the lock. Signalling first is a race that looks harmless and is not:
        // the waiter wakes, settles against the book as it was, finds nothing to do, and waits again — and if that record
        // was the only one coming (the common case, a two-node collision) nothing ever wakes it again. This ordering bug
        // was live between `474cda1` and here, and it is a candidate cause of the failed live-resolution measurement.
        drop(book);
        self.changed.notify_one();
    }

    /// The best claim any recorded peer holds to `point` — the contender oracle `fanos_vrf::settle_index` consumes.
    #[must_use]
    pub(crate) fn contender<F: Field>(&self, point: &Point<F>) -> Option<(u16, VrfOutput)> {
        let book = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        book.best.get(&point.coords()).map(|b| (b.index, b.output))
    }

    /// The witness proving a node with `mine` was displaced from its `j`-th probe point, if one is recorded.
    ///
    /// Returns the *best* claimant on that point, which is the strongest witness available and the one whose claim most
    /// clearly beats the claimant's. `None` means this node cannot currently justify advancing past step `j` — in which
    /// case it must not, since `fanos_vrf::verify_coordinate_claim` would reject the claim at the far end.
    #[must_use]
    pub(crate) fn witness_for<F: Field>(&self, mine: &VrfOutput, j: u16) -> Option<DisplacementWitness> {
        let contested = probe_point::<F>(mine, j).coords();
        let book = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let best = *book.best.get(&contested)?;
        if !claim_beats((best.index, &best.output), (j, mine)) {
            return None;
        }
        let peer = book.peers.get(&best.holder)?;
        Some(DisplacementWitness { id: peer.id.clone(), public: peer.public, proof: peer.proof })
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

/// Assemble this node's own claim at the index its walk settles on, given what it has verified.
///
/// Returns the settled index and a claim carrying one witness per skipped step. `None` if every point of the node's line
/// is better claimed (`settle_index` exhausted — the honest answer, not a wrapped index), or if a witness the settle rule
/// relied on is missing.
///
/// The two halves cannot disagree by construction: [`ClaimBook::witness_for`] and the oracle passed to `settle_index` read
/// the same `best` table under the same `fanos_vrf::claim_beats` order. That is deliberate — deriving them independently
/// is exactly what produced the unprovable-displacement defect this machinery was rebuilt to remove.
#[must_use]
pub(crate) fn settle<F: Field>(
    book: &ClaimBook,
    mine: &VrfOutput,
    proof: VrfProof,
) -> Option<(u16, fanos_vrf::CoordinateClaim)> {
    let index = fanos_vrf::settle_index::<F>(mine, |p| book.contender::<F>(p))?;
    let mut witnesses = Vec::with_capacity(usize::from(index));
    for j in 0..index {
        witnesses.push(book.witness_for::<F>(mine, j)?);
    }
    Some((index, fanos_vrf::CoordinateClaim { proof, index, witnesses }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F7;
    use fanos_primitives::BeaconSeed;
    use fanos_vrf::{VrfSecret, prove_coordinate_ranked, verify_coordinate_claim};

    /// Whether two nodes take the identical walk — same line, same stride, so the same point at every index.
    fn walks_coincide(a: &VrfOutput, b: &VrfOutput) -> bool {
        (0..probe_bound::<F7>()).all(|k| probe_point::<F7>(a, k) == probe_point::<F7>(b, k))
    }

    /// As [`peer`], with a 16-bit seed — needed where the fixture must search a few hundred identities.
    fn peer16(seed: u16, epoch: Epoch, beacon: &BeaconSeed) -> (Vec<u8>, VrfPublic, VrfProof, VrfOutput) {
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&seed.to_le_bytes());
        let sk = VrfSecret::from_seed(bytes);
        let id = format!("peer16-{seed}").into_bytes();
        let (_, proof, output) = prove_coordinate_ranked::<F7>(&sk, &id, epoch, beacon);
        (id, sk.public(), proof, output)
    }

    /// A peer identity with its epoch claim material, as the HELLO verifier would hand it over.
    fn peer(seed: u8, epoch: Epoch, beacon: &BeaconSeed) -> (Vec<u8>, VrfPublic, VrfProof, VrfOutput) {
        let sk = VrfSecret::from_seed([seed; 32]);
        let id = format!("peer-{seed}").into_bytes();
        let (_, proof, output) = prove_coordinate_ranked::<F7>(&sk, &id, epoch, beacon);
        (id, sk.public(), proof, output)
    }

    #[test]
    fn a_settled_claim_is_one_the_verifier_accepts() {
        // The end-to-end property: whatever index the book settles on, the claim it assembles must verify against the
        // same predicate a remote peer applies. If these two ever disagree, a node announces a point it cannot prove.
        let epoch = Epoch::new(3);
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        book.adopt(epoch);

        let all: Vec<_> = (0..24u8).map(|s| peer(s, epoch, &beacon)).collect();
        // Everyone except the last is a recorded peer; the last one settles against them.
        for (id, public, proof, output) in &all[..all.len() - 1] {
            book.record::<F7>(id, *public, *proof, output);
        }
        let (id, public, proof, output) = all.last().unwrap();

        let (index, claim) = settle::<F7>(&book, output, *proof).expect("a seat on its own line");
        assert_eq!(claim.witnesses.len(), usize::from(index), "one witness per skipped step");
        assert!(
            verify_coordinate_claim::<F7>(public, id, epoch, &beacon, &probe_point::<F7>(output, index), &claim),
            "settled at index {index} but the verifier rejects the claim"
        );
    }

    #[test]
    fn an_uncontested_node_settles_at_its_preference_with_no_witnesses() {
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        let (_, _, proof, output) = peer(9, epoch, &beacon);
        let (index, claim) = settle::<F7>(&book, &output, proof).expect("an empty book contests nothing");
        assert_eq!(index, 0, "nothing observed ⇒ the preference stands");
        assert!(claim.witnesses.is_empty(), "and a direct claim carries no witnesses");
        assert_eq!(claim, fanos_vrf::CoordinateClaim::direct(proof), "it is exactly the pre-existing claim");
    }

    #[test]
    fn a_better_claim_displaces_and_supplies_its_own_witness() {
        // The displacement, constructed rather than hoped for: find two identities whose preferred point is the same and
        // whose claims therefore differ only by rank, record the better one, and settle the worse one against it.
        let epoch = Epoch::new(5);
        let beacon = BeaconSeed::GENESIS;
        let peers: Vec<_> = (0..80u8).map(|s| peer(s, epoch, &beacon)).collect();
        // The pair must share a preferred point AND take *different* walks from it. Sharing the whole walk — same line and
        // same stride, measured at 3.4% of colliding pairs on `PG(2,7)`, against the predicted `1/((q+1)·φ(q+1))` = 1/32 —
        // is the separate case pinned by `a_node_beaten_at_every_step_is_not_seated_at_all`.
        let pair = peers.iter().enumerate().find_map(|(i, a)| {
            peers.iter().skip(i + 1).find_map(|b| {
                if probe_point::<F7>(&a.3, 0) != probe_point::<F7>(&b.3, 0) || walks_coincide(&a.3, &b.3) {
                    return None;
                }
                // Order them so `loser` is the one the rank rule moves.
                Some(if claim_beats((0, &b.3), (0, &a.3)) { (a, b) } else { (b, a) })
            })
        });
        let (loser, winner) = pair.expect("two of 80 identities collide on a point but not on a whole walk");

        let book = ClaimBook::new();
        book.adopt(epoch);
        book.record::<F7>(&winner.0, winner.1, winner.2, &winner.3);

        let (index, claim) = settle::<F7>(&book, &loser.3, loser.2).expect("the loser has somewhere to go");
        assert!(index >= 1, "displaced from a point claimed better, so the index must advance (got {index})");
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
        other.record::<F7>(&loser.0, loser.1, loser.2, &loser.3);
        assert_eq!(
            settle::<F7>(&other, &winner.3, winner.2).map(|(k, _)| k),
            Some(0),
            "the better claim is the one that stays"
        );
    }

    #[test]
    fn an_epoch_change_clears_the_book() {
        // A claim proves a placement for ONE epoch. Carrying it forward would let a retired placement justify a
        // displacement in the current epoch — the pre-settling attack the beacon exists to prevent.
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        book.adopt(Epoch::new(7));
        let (id, public, proof, output) = peer(4, Epoch::new(7), &beacon);
        book.record::<F7>(&id, public, proof, &output);
        assert_eq!(book.len(), 1);
        assert!(book.contender::<F7>(&probe_point::<F7>(&output, 0)).is_some(), "the point is claimed");

        book.adopt(Epoch::new(7)); // idempotent
        assert_eq!(book.len(), 1, "re-announcing the same epoch keeps the book");
        book.adopt(Epoch::new(8));
        assert_eq!(book.len(), 0, "a new epoch discards every claim");
        assert!(book.contender::<F7>(&probe_point::<F7>(&output, 0)).is_none());
    }

    #[test]
    fn the_book_keeps_the_best_claim_per_point_not_the_last() {
        // Insertion order must not decide anything — that is the whole point of arbitrating on an unforgeable pair.
        let epoch = Epoch::new(2);
        let beacon = BeaconSeed::GENESIS;
        let peers: Vec<_> = (0..30u8).map(|s| peer(s, epoch, &beacon)).collect();

        let forward = ClaimBook::new();
        forward.adopt(epoch);
        for (id, pk, pr, out) in &peers {
            forward.record::<F7>(id, *pk, *pr, out);
        }
        let backward = ClaimBook::new();
        backward.adopt(epoch);
        for (id, pk, pr, out) in peers.iter().rev() {
            backward.record::<F7>(id, *pk, *pr, out);
        }
        for i in 0..fanos_geometry::Plane::<F7>::N as usize {
            let p = Point::<F7>::at(i);
            assert_eq!(
                forward.contender::<F7>(&p).map(|(k, o)| (k, o[0])),
                backward.contender::<F7>(&p).map(|(k, o)| (k, o[0])),
                "point {i}: the best claim must not depend on arrival order"
            );
        }
    }

    #[test]
    fn a_step_with_no_recorded_witness_is_not_taken() {
        // The safety property that makes this book usable with partial information: it can only settle where it can also
        // prove, so a node never announces a point whose justification it cannot present.
        let epoch = Epoch::new(6);
        let beacon = BeaconSeed::GENESIS;
        let book = ClaimBook::new();
        book.adopt(epoch);
        let (_, _, proof, output) = peer(11, epoch, &beacon);
        // Nothing recorded ⇒ nothing contested ⇒ index 0, and `witness_for` refuses every step.
        assert!(book.witness_for::<F7>(&output, 0).is_none());
        assert_eq!(settle::<F7>(&book, &output, proof).map(|(k, _)| k), Some(0));
    }

    #[test]
    fn a_node_beaten_at_every_step_is_not_seated_at_all() {
        // The line restriction's residual failure mode, stated as a test rather than left to be discovered. Two nodes whose
        // outputs give the same preferred point AND the same line AND the same stride take the *identical* walk, so the
        // better-ranked one holds the better claim at every index and the other can be seated nowhere. `settle` answers
        // `None`, which the caller must read as "announce nothing" rather than as an index to fall back on.
        //
        // Measured incidence among pairs that share a preferred point on `PG(2,7)`: 3.4% (predicted `1/((q+1)·φ(q+1))` =
        // 1/32 = 3.1%). Provoking it against a CHOSEN victim means matching that triple and outranking it, which costs
        // `2·N·(q+1)·φ(q+1)` draws — 3 648 at `q = 7`, **1 016 832 at `q = 31`**, 2.7e8 at `q = 127`. That is
        // `2(q+1)·φ(q+1)` times the `N` draws it took to make a victim unroutable *before* probing existed (a single
        // coordinate collision did it), so this residual is 64×/1024×/16384× HARDER than the baseline it replaced, not an
        // amplification of it. Falling back to a plane-wide walk would close it and reopen the steering primitive that
        // line restriction exists to remove, which is the worse trade.
        let epoch = Epoch::new(5);
        let beacon = BeaconSeed::GENESIS;
        let peers: Vec<_> = (0..400u16).map(|s| peer16(s, epoch, &beacon)).collect();
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
        book.record::<F7>(&winner.0, winner.1, winner.2, &winner.3);
        assert!(
            settle::<F7>(&book, &loser.3, loser.2).is_none(),
            "beaten at every index of its own line, the node must report no seat rather than an unprovable one"
        );
        // The winner is unaffected: its own claim is the best one everywhere on that walk.
        let other = ClaimBook::new();
        other.adopt(epoch);
        other.record::<F7>(&loser.0, loser.1, loser.2, &loser.3);
        assert_eq!(settle::<F7>(&other, &winner.3, winner.2).map(|(k, _)| k), Some(0));
    }
}

