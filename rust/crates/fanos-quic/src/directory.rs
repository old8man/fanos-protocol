//! The overlay address book: projective coordinate → network address.
//!
//! The engine routes on coordinates (`Triple`); the transport needs a `SocketAddr` to dial. In a
//! full deployment this mapping is served by the DHT (spec §L1) and is self-certifying (the
//! coordinate is `MapToPoint(H(pubkey))`, and the cert-bound key proves it). Here it is a shared,
//! cloneable table the harness fills once endpoints are bound — the single seam that a real
//! discovery layer slots into without touching the engine or the driver.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use fanos_geometry::Triple;
use fanos_primitives::BeaconSeed;
use fanos_vrf::{VrfOutput, claim_beats};

/// One coordinate's occupant: where to dial it, and — when a coordinate proof was verified — the **rank** that decides
/// who keeps the point if another node claims it.
#[derive(Clone, Copy)]
struct Binding {
    addr: SocketAddr,
    /// The occupant's coordinate-VRF output, or `None` for bindings made without a verified proof (bootstrap seeds,
    /// pinned fixtures). An unranked binding carries no evidence, so it can neither win an arbitration nor block one.
    rank: Option<VrfOutput>,
    /// The **probe index** of the occupant's verified claim to this point — how far along its own walk the point sits.
    ///
    /// Recorded rather than recomputed: it is part of what the peer proved, and recomputing it would need the plane's
    /// field, which this table is deliberately generic over. `0` is the uncontested claim, which is every claim until the
    /// `HELLO` frame carries a probe index.
    index: u16,
}

impl Binding {
    /// Whether `self` displaces `existing` at a contested point: the **better claim** wins
    /// ([`fanos_vrf::claim_beats`] — fewer probe steps first, then lowest rank), so a displaced node's own local walk
    /// ([`fanos_vrf::settle_index`]) reaches the same conclusion unprompted.
    ///
    /// Deciding on the pair rather than rank alone is what keeps this table consistent with settling. Rank alone would let
    /// a node that was *displaced onto* this point evict one whose own walk prefers it — and the preferrer, holding the
    /// cheaper claim, is the one that can prove it belongs here.
    ///
    /// The unranked cases are deliberately asymmetric. An unranked newcomer never displaces a *ranked* incumbent — it
    /// carries no evidence, and letting it win would restore the arrival-order eviction this rule removes. An unranked
    /// incumbent, by contrast, yields to anyone: it is a seed or fixture entry, not a proven claim.
    fn supersedes(&self, existing: &Self) -> bool {
        match (self.rank, existing.rank) {
            // Two proven claims: the unforgeable pair decides, never arrival order.
            (Some(mine), Some(theirs)) => claim_beats((self.index, &mine), (existing.index, &theirs)),
            // An unranked incumbent is a seed or fixture entry rather than a proven claim, so it yields to anyone.
            (_, None) => true,
            // An unranked newcomer carries no evidence: letting it displace a proven claim would restore exactly the
            // arrival-order eviction this rule exists to remove.
            (None, Some(_)) => false,
        }
    }
}

/// What a directory write actually did.
///
/// **Three-valued, because "the binding is unchanged" has two causes that call for opposite responses**, and
/// because until now it had none at all: every write returned `()`, so the arbitration rule above could
/// refuse one and the caller could not tell. That cost three harnesses during #240 — each was built on a
/// write that never landed, and a refused write is indistinguishable from a successful one when neither says
/// anything. It is also the shape #106 closed one layer up, at the publisher.
///
/// The rule for a caller is the one #244 derives: **does your next decision depend on the write having
/// landed?** If it does, branch here. If it does not, discard it with the reason at the call — an explicit
/// discard is a claim that can be checked, and silence is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a write the arbitration rule refused looks exactly like one that landed; branch on it, or \
              discard it with the reason at the call site"]
pub enum WriteOutcome {
    /// The binding is now this write's, and **the point was free**.
    ///
    /// It used to also cover "the incoming claim beat an incumbent", on the reasoning that from the writer's
    /// side those are the same outcome. They are — and the writer is not the only reader (#260). Taking an
    /// occupied point *evicts a live binding*: some other node is now unreachable there until it walks on,
    /// and that is a fact about the cell rather than about this write. Measured consequence of the
    /// conflation: `Directory::collisions` counts a clash on **both** branches while only the losing one
    /// reached a station, so a node that displaced two incumbents reported `collisions=2` on its health
    /// surface and an entirely empty stations plane.
    Bound,
    /// The binding is now this write's, and it **took the point from a live incumbent** whose claim it beat.
    ///
    /// The other half of what `Bound` used to mean. Distinct because the obligation is: `evicted` is an
    /// address that was reachable at this coordinate a moment ago and is not now, so a reader watching the
    /// cell — not this writer — needs it, and a run of them is the plane approaching its occupancy bound
    /// rather than one unlucky draw.
    Displaced {
        /// The address that held the point and no longer does.
        evicted: SocketAddr,
    },
    /// This exact address was already bound here. Not a collision (no second claimant) and not a refusal
    /// (nothing was rejected) — a re-publish of what the table already held. Kept distinct from [`Bound`]
    /// because a caller asking "did anything change" gets a different answer, and folding it into
    /// `Superseded` would report a healthy refresh as a lost arbitration.
    ///
    /// [`Bound`]: WriteOutcome::Bound
    Unchanged,
    /// An incumbent holds the better claim, so **the write did not land** and `keeping` is what the table
    /// still says. Not an error: seats are arbitrated by proof rather than arrival order, and losing is the
    /// rule working. What it obliges is a decision — a node whose own coordinate was refused must walk on
    /// (`fanos_vrf::settle_index`), while a node recording a *peer* usually should not care.
    Superseded {
        /// The address the table keeps — the incumbent's, not the rejected writer's.
        keeping: SocketAddr,
    },
}

/// A shared, cloneable coordinate → address table. Cheap to clone (shares one map).
#[derive(Clone, Default)]
pub struct Directory {
    inner: Arc<RwLock<HashMap<Triple, Binding>>>,
    /// Count of observed coordinate collisions — two distinct addresses claiming one point. Shared
    /// across clones, so a node's health surface can read it (see [`Directory::collisions`]).
    collisions: Arc<AtomicUsize>,
    /// Count of sends dropped because the destination coordinate had no address (unroutable). Shared
    /// across clones (see [`Directory::unresolved_drops`]).
    unresolved_drops: Arc<AtomicUsize>,
    /// The **genesis beacon seed of the network this directory belongs to** — what a node's epoch-0
    /// coordinate is drawn against, and what peers check an epoch-0 claim against.
    ///
    /// It lives here because a `Directory` *is* the network from a node's point of view, and because both
    /// sites that need the value already hold one: the node's own genesis seat (`driver.rs`) and the
    /// `BeaconWindow` peers' epoch-0 claims are verified against. They must agree or a node's seat and its
    /// peers' verification of that seat diverge, and threading one value to both is what makes that
    /// structural rather than a convention.
    ///
    /// **Why not `NodeCredentials`,** which is also threaded to both: it derives `Wire` and is persisted as
    /// the identity file, so a field there changes a stored format for every existing node — and it is the
    /// wrong home anyway, since credentials are per-*node* and should exist independently of any network.
    ///
    /// `None` is `BeaconSeed::GENESIS`, and that is correct rather than lax: a deployment with no beacon has
    /// no epoch clock and no reshuffle, so it has no placement defence at *any* epoch and nothing here can
    /// give it one (`docs/design-genesis.md` §7). Where a beacon IS configured, `Node::start` binds this.
    genesis: Option<BeaconSeed>,
}

impl Directory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind this directory to a network by its **genesis beacon seed** — the value every node of that network
    /// draws its epoch-0 coordinate against.
    ///
    /// Without it the seed is `BeaconSeed::GENESIS`, a compile-time constant shared by every FANOS deployment
    /// that has ever existed — so one grinding effort (roughly seven mints per point on a Fano cell) buys a
    /// chosen genesis placement on *every* network anyone founds, computed before any of them exists. Binding
    /// makes that work per-network and, since the seed is derived from the beacon commitment, unobtainable
    /// before first contact. `docs/design-genesis.md` has the derivation and what it does not buy.
    #[must_use]
    pub fn for_network(mut self, genesis: BeaconSeed) -> Self {
        self.genesis = Some(genesis);
        self
    }

    /// The genesis beacon seed of this network, or the shared constant when unbound.
    #[must_use]
    pub fn genesis(&self) -> BeaconSeed {
        self.genesis.unwrap_or(BeaconSeed::GENESIS)
    }

    /// Bind (or rebind) a coordinate to a network address, **without** a rank.
    ///
    /// Use this only where no verified coordinate proof is in hand — bootstrap seeds, statically-pinned test fixtures,
    /// directories keyed by something other than a node's epoch coordinate. Without a rank there is no basis on which to
    /// arbitrate a collision, so a later binding replaces an earlier one, exactly as before. Prefer
    /// [`insert_ranked`](Self::insert_ranked) wherever a `HELLO` proof has been verified.
    pub fn insert(&self, coord: Triple, addr: SocketAddr) -> WriteOutcome {
        self.bind(coord, Binding { addr, rank: None, index: 0 })
    }

    /// Bind a coordinate to an address **with the occupant's rank** — its coordinate-VRF output, as verified from a
    /// `HELLO` proof — so a collision is arbitrated rather than won by whoever arrives last.
    ///
    /// ## Why arrival order was the wrong rule
    ///
    /// Previously the later binding always replaced the earlier one, and the code documented the consequence: "the
    /// colliding node silently shadows another and one becomes unreachable". That is not only a fault to be tolerated, it
    /// is **exploitable** — a node whose coordinate lands on a victim's point could evict the victim by connecting after
    /// it. Arrival order is attacker-controlled; rank is not.
    ///
    /// Rank is the coordinate VRF's output: unforgeable without the node's secret and unpredictable before the epoch's
    /// beacon, so which of two colliding nodes keeps the point is decided by a value neither chose. **Lowest rank keeps
    /// the point**, matching [`fanos_vrf::settle_index`], so the displaced node's own local walk agrees with what every
    /// peer's directory concluded — with no message exchanged.
    ///
    /// A ranked binding is never displaced by a rank-*less* one: an unranked claim carries no evidence, and letting it
    /// win would reintroduce the eviction it exists to prevent.
    pub fn insert_ranked(&self, coord: Triple, addr: SocketAddr, rank: VrfOutput) -> WriteOutcome {
        self.insert_claimed(coord, addr, rank, 0)
    }

    /// As [`insert_ranked`](Self::insert_ranked), but for a claim at probe **index** `index` — a node seated somewhere
    /// other than its preferred point after being displaced.
    ///
    /// The index is the first component of the arbitration order ([`fanos_vrf::claim_beats`]), so it must be the one the
    /// peer *proved* (`fanos_vrf::verify_coordinate_claim`), never a local guess. `insert_ranked` is exactly this at index
    /// 0, which is what an uncontested node claims.
    pub fn insert_claimed(&self, coord: Triple, addr: SocketAddr, rank: VrfOutput, index: u16) -> WriteOutcome {
        self.bind(coord, Binding { addr, rank: Some(rank), index })
    }

    /// The shared binding path: apply the arbitration rule, count and log genuine collisions.
    fn bind(&self, coord: Triple, incoming: Binding) -> WriteOutcome {
        let Ok(mut map) = self.inner.write() else {
            // A poisoned lock is a local fault, not an arbitration result. Reported as `Superseded` against
            // this node's own address so a caller that branches on it does the conservative thing — treats
            // the binding as not-ours — rather than the optimistic one.
            return WriteOutcome::Superseded { keeping: incoming.addr };
        };
        {
            if let Some(existing) = map.get(&coord) {
                if existing.addr == incoming.addr {
                    // Not a collision and not a refusal: the same address is already bound here. Distinct from
                    // `Bound` because a caller asking "did my write change anything" gets a different answer,
                    // and distinct from `Superseded` because nothing was rejected and nothing is stale.
                    map.insert(coord, incoming);
                    return WriteOutcome::Unchanged;
                }
                self.collisions.fetch_add(1, Ordering::Relaxed);
                if !incoming.supersedes(existing) {
                    let keeping = existing.addr;
                    tracing::warn!(
                        ?coord,
                        keeping = %existing.addr,
                        rejected = %incoming.addr,
                        "overlay coordinate collision: the incumbent holds the better claim, so the newcomer must \
                         advance along its own probe walk (fanos_vrf::settle_index) — the binding is unchanged"
                    );
                    return WriteOutcome::Superseded { keeping };
                }
                tracing::warn!(
                    ?coord,
                    displaced = %existing.addr,
                    keeping = %incoming.addr,
                    "overlay coordinate collision: the newcomer holds the better claim and takes the point; the \
                     incumbent must advance along its own probe walk (fanos_vrf::settle_index)"
                );
                let evicted = existing.addr;
                map.insert(coord, incoming);
                return WriteOutcome::Displaced { evicted };
            }
            map.insert(coord, incoming);
            WriteOutcome::Bound
        }
    }

    /// The **claim** currently bound at `coord` — its probe index and rank — if it is bound *and* was recorded with one.
    ///
    /// This is the contender oracle [`fanos_vrf::settle_index`] consumes: a node walks its own probe sequence to the first
    /// point no *better* claim reaches. Returning the pair rather than the rank alone is what lets the walk and this table
    /// apply one order ([`fanos_vrf::claim_beats`]) instead of two that can disagree.
    ///
    /// `None` covers both "free" and "occupied but unranked" — for settling those are the same answer, since an unranked
    /// occupant provides no evidence that it may keep the point.
    #[must_use]
    pub fn claim_at(&self, coord: Triple) -> Option<(u16, VrfOutput)> {
        let binding = *self.inner.read().ok()?.get(&coord)?;
        Some((binding.index, binding.rank?))
    }

    /// Unbind a coordinate **only while it still names `addr`** — the vacating half of #241, and a
    /// compare-and-remove rather than a bare delete.
    ///
    /// Returns whether the entry was taken. `false` covers both "already gone" and "someone else's now",
    /// and the caller almost never needs to tell those apart: in both the point is not this node's to clear.
    ///
    /// **Why the comparison cannot live at the call site.** It used to, at one of the two: `get_or_connect`
    /// reads `resolve(to)`, compares, and then removes. That is a read followed by a write on a shared
    /// `RwLock<HashMap>`, so a rebinding that lands between them is deleted by a decision taken before it
    /// existed — and the repair #240 added would then undo a *fresher* correction than its own. Inside one
    /// write lock the pair is atomic and the race cannot be written by accident.
    ///
    /// **The other caller had no comparison at all.** `Reseater::apply` cleared its vacated point
    /// unconditionally, so a node walking off a point that a better claim had meanwhile taken deleted the
    /// rightful occupant's binding and made it unroutable in this node's table until it announced again.
    /// That is the #240 family for the third time: a write keyed on a coordinate, executed without asking
    /// whether the coordinate is still the one the caller was thinking of.
    ///
    /// There is deliberately **no unconditional `remove`** beside this: the point of the change is that the
    /// dangerous form cannot be written, which is the same reason `WriteOutcome` replaced `()` above rather
    /// than being offered alongside it (#105's shape, not repeated).
    pub fn remove_if(&self, coord: Triple, addr: SocketAddr) -> bool {
        let Ok(mut map) = self.inner.write() else {
            return false;
        };
        if map.get(&coord).is_some_and(|b| b.addr == addr) {
            map.remove(&coord);
            return true;
        }
        false
    }

    /// How many coordinate collisions this directory has observed (distinct addresses claiming one
    /// point). A nonzero value means the projective address space suffered a `MapToPoint` collision —
    /// surfaced here so a node can react (relocate) instead of silently shadowing a peer.
    #[must_use]
    pub fn collisions(&self) -> usize {
        self.collisions.load(Ordering::Relaxed)
    }

    /// Record that a send to `coord` was dropped for want of an address — so the transport's drop of an
    /// unroutable coordinate is *observable* (counted + logged) rather than silent.
    pub fn note_unresolved_drop(&self, coord: Triple) {
        self.unresolved_drops.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            ?coord,
            "dropped a send to an unresolved coordinate (no known address)"
        );
    }

    /// How many sends this directory has seen dropped for an unresolved destination coordinate.
    #[must_use]
    pub fn unresolved_drops(&self) -> usize {
        self.unresolved_drops.load(Ordering::Relaxed)
    }

    /// Resolve a coordinate to its address, if known.
    #[must_use]
    pub fn resolve(&self, coord: Triple) -> Option<SocketAddr> {
        self.inner.read().ok().and_then(|map| map.get(&coord).map(|b| b.addr))
    }

    /// The number of known peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().map_or(0, |map| map.len())
    }

    /// Whether the directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two ranks, ordered: `low` outranks `high`.
    fn ranks() -> (VrfOutput, VrfOutput) {
        let low = [0u8; 64];
        let mut high = [0u8; 64];
        high[0] = 1;
        (low, high)
    }

    #[test]
    fn a_write_reports_which_of_the_four_things_it_did() {
        // The PROPERTY: `Bound`, `Unchanged` and `Superseded` are each reachable, and no two of them are the same
        // observation. Before #241 all three returned `()`, so the arbitration rule above could refuse a write and the
        // caller could not tell — which cost three harnesses during #240, each built on a precondition that never
        // happened. The test that would have caught it is this one, and it is four lines.
        let (low, high) = ranks();
        let coord = [1, 2, 3];
        let dir = Directory::new();

        assert_eq!(dir.insert_ranked(coord, sa(1), low), WriteOutcome::Bound, "a free point takes the write");
        assert_eq!(
            dir.insert_ranked(coord, sa(1), low),
            WriteOutcome::Unchanged,
            "the same address re-published is not a collision and not a refusal — nothing changed and nothing was lost"
        );
        assert_eq!(
            dir.insert_ranked(coord, sa(2), high),
            WriteOutcome::Superseded { keeping: sa(1) },
            "a worse claim is refused, and the outcome names the address the table KEEPS — not the one it rejected, \
             because the caller\'s next move depends on where the point actually points"
        );
        assert_eq!(dir.resolve(coord), Some(sa(1)), "and the refusal is real: the table still holds the incumbent");

        // The displacing direction reports a FOURTH value, and this comment used to argue it should not (#260):
        // "from the writer's side the point was free and I beat the incumbent are the same outcome". True of the
        // writer, and the writer is not the only reader — `evicted` was reachable at this coordinate a moment ago
        // and is not now. Folding it into `Bound` is what left the winning half of every collision off the stations
        // plane while `Directory::collisions` counted it.
        //
        // The displacer must win on the INDEX, because `low` is already the minimum rank and an equal claim does not
        // beat an incumbent — which is what the first draft of this assertion got wrong, and what the run said.
        let dir = Directory::new();
        let _ = dir.insert_claimed(coord, sa(1), low, 2);
        assert_eq!(
            dir.insert_claimed(coord, sa(3), high, 0),
            WriteOutcome::Displaced { evicted: sa(1) },
            "fewer probe steps wins, and the outcome names WHO was evicted — the address that is now unreachable here"
        );

        // And the discriminator that keeps the split honest: binding a FREE point is still plain `Bound`. Without
        // this arm `Displaced` could be returned unconditionally and every assertion above would still pass.
        let dir = Directory::new();
        assert_eq!(dir.insert_claimed(coord, sa(7), high, 0), WriteOutcome::Bound, "a free point is not a displacement");
    }

    #[test]
    fn an_unranked_write_is_refused_by_a_proven_claim_and_says_so() {
        // The exact shape that made #240 cost three harnesses: a test pins a coordinate with `insert`, the rank rule
        // refuses it against a proven binding, and the precondition silently never holds. The refusal is unchanged —
        // it is the correct rule — but it is no longer silent.
        let (low, _) = ranks();
        let coord = [4, 5, 6];
        let dir = Directory::new();
        let _ = dir.insert_ranked(coord, sa(1), low);

        assert_eq!(
            dir.insert(coord, sa(9)),
            WriteOutcome::Superseded { keeping: sa(1) },
            "an unranked newcomer carries no evidence and must not displace a proven claim"
        );

        // ...and the converse, so the assertion above is a discriminator rather than a constant: over an UNRANKED
        // incumbent (a bootstrap seed, a pinned fixture) the same unranked write lands.
        let dir = Directory::new();
        let _ = dir.insert(coord, sa(1));
        assert_eq!(
            dir.insert(coord, sa(9)),
            WriteOutcome::Displaced { evicted: sa(1) },
            "an unranked incumbent yields to anyone — and yielding is a displacement, not a plain bind (#260)"
        );
    }

    #[test]
    fn a_ranked_collision_is_decided_by_rank_not_by_arrival_order() {
        // The security property. Before ranks the later binding always won, so a node whose coordinate landed on a
        // victim's point could **evict** the victim simply by connecting after it — and arrival order is
        // attacker-controlled. Rank is a VRF output: unforgeable without the node's secret and unpredictable before the
        // epoch's beacon, so neither party chooses who keeps the point.
        let (low, high) = ranks();
        let coord = [1, 2, 3];

        // Incumbent outranks the newcomer ⇒ the binding is unchanged, whichever order they arrive in.
        let dir = Directory::new();
        let _ = dir.insert_ranked(coord, sa(1), low);
        let _ = dir.insert_ranked(coord, sa(2), high);
        assert_eq!(dir.resolve(coord), Some(sa(1)), "the incumbent keeps the point it outranks for");
        assert_eq!(dir.claim_at(coord), Some((0, low)));

        // Newcomer outranks the incumbent ⇒ it takes the point, and the incumbent must advance its own probe walk.
        let dir = Directory::new();
        let _ = dir.insert_ranked(coord, sa(2), high);
        let _ = dir.insert_ranked(coord, sa(1), low);
        assert_eq!(dir.resolve(coord), Some(sa(1)), "the lower rank takes the point");
        assert_eq!(dir.claim_at(coord), Some((0, low)));

        // Either way the outcome is the SAME point holder regardless of order — which is what lets a displaced node's
        // local `settle_index` walk agree with every peer's directory without a message being exchanged.
        assert_eq!(dir.collisions(), 1, "and the collision is still surfaced, not hidden by being resolved");
    }

    #[test]
    fn an_unranked_claim_can_neither_evict_a_proven_one_nor_block_it() {
        let (low, _) = ranks();
        let coord = [0, 1, 1];

        // Unranked newcomer vs proven incumbent: rejected. Otherwise a caller with no proof could still evict.
        let dir = Directory::new();
        let _ = dir.insert_ranked(coord, sa(1), low);
        let _ = dir.insert(coord, sa(9));
        assert_eq!(dir.resolve(coord), Some(sa(1)), "no evidence, no eviction");

        // Unranked incumbent (a bootstrap seed or pinned fixture) yields to a proven claim, and to another seed.
        let dir = Directory::new();
        let _ = dir.insert(coord, sa(9));
        let _ = dir.insert_ranked(coord, sa(1), low);
        assert_eq!(dir.resolve(coord), Some(sa(1)), "a seed entry is not a proven claim");
        let dir = Directory::new();
        let _ = dir.insert(coord, sa(9));
        let _ = dir.insert(coord, sa(8));
        assert_eq!(dir.resolve(coord), Some(sa(8)), "two unranked bindings keep the pre-existing last-writer rule");
    }

    #[test]
    fn claim_at_is_the_contender_oracle_settling_consumes() {
        // `settle_index` asks exactly this question, and `None` must mean "free for me" in both the unbound and the
        // unranked case — an unranked occupant provides no evidence that it may keep the point.
        let (low, _) = ranks();
        let dir = Directory::new();
        assert_eq!(dir.claim_at([1, 0, 0]), None, "unbound");
        let _ = dir.insert([1, 0, 0], sa(3));
        assert_eq!(dir.claim_at([1, 0, 0]), None, "bound but unranked reads as free for settling");
        let _ = dir.insert_ranked([0, 0, 1], sa(4), low);
        assert_eq!(dir.claim_at([0, 0, 1]), Some((0, low)), "an unqualified ranked insert is a claim at index 0");
        let _ = dir.insert_claimed([0, 1, 0], sa(5), low, 3);
        assert_eq!(dir.claim_at([0, 1, 0]), Some((3, low)), "and a displaced claim reports the index it proved");
        assert!(dir.remove_if([0, 0, 1], sa(4)), "the occupant vacates its own point");
        assert_eq!(dir.claim_at([0, 0, 1]), None, "vacating clears the claim with the address");
        assert!(
            !dir.remove_if([0, 1, 0], sa(9)),
            "and a stranger's address does not vacate someone else's point — the compare is the guard (#241)"
        );
        assert_eq!(dir.claim_at([0, 1, 0]), Some((3, low)), "the rightful occupant is untouched");
    }

    #[test]
    fn a_cheaper_claim_takes_the_point_from_a_better_ranked_one() {
        // The arbitration order is (index, rank), not rank alone. A node DISPLACED onto a point must not evict one whose
        // own walk prefers it, however its rank compares: the preferrer holds the claim that needs no witnesses, and a
        // table that decided otherwise would contradict what every node's own `settle_index` concludes.
        let (low, high) = ranks();
        let coord = [1, 1, 0];

        let dir = Directory::new();
        let _ = dir.insert_claimed(coord, sa(1), low, 2); // better rank, but displaced here
        let _ = dir.insert_claimed(coord, sa(2), high, 0); // worse rank, but this is its preference
        assert_eq!(dir.resolve(coord), Some(sa(2)), "the cheaper claim wins the point");
        assert_eq!(dir.claim_at(coord), Some((0, high)));

        // Symmetric: the same two claims in the other arrival order reach the same holder.
        let dir = Directory::new();
        let _ = dir.insert_claimed(coord, sa(2), high, 0);
        let _ = dir.insert_claimed(coord, sa(1), low, 2);
        assert_eq!(dir.resolve(coord), Some(sa(2)), "and arrival order still decides nothing");

        // At EQUAL index the rank breaks the tie, exactly as before.
        let dir = Directory::new();
        let _ = dir.insert_claimed(coord, sa(2), high, 2);
        let _ = dir.insert_claimed(coord, sa(1), low, 2);
        assert_eq!(dir.resolve(coord), Some(sa(1)), "equal claims fall back to lowest rank");
    }

    fn sa(port: u16) -> SocketAddr {
        (std::net::Ipv4Addr::LOCALHOST, port).into()
    }

    #[test]
    fn collisions_are_observed_but_rebinding_the_same_address_is_not() {
        let dir = Directory::new();
        let _ = dir.insert([1, 2, 3], sa(1000));
        assert_eq!(dir.collisions(), 0);

        // Re-binding the identical address (a node reconnecting) is not a collision.
        let _ = dir.insert([1, 2, 3], sa(1000));
        assert_eq!(dir.collisions(), 0);

        // A different address on the same coordinate is a collision; last-writer-wins for routing.
        let _ = dir.insert([1, 2, 3], sa(2000));
        assert_eq!(dir.collisions(), 1);
        assert_eq!(dir.resolve([1, 2, 3]), Some(sa(2000)));

        // The counter is shared across clones (a node's health surface reads the same table).
        let clone = dir.clone();
        let _ = clone.insert([1, 2, 3], sa(3000));
        assert_eq!(
            dir.collisions(),
            2,
            "collision count is shared across clones"
        );

        // A distinct coordinate is unaffected.
        let _ = dir.insert([4, 5, 6], sa(4000));
        assert_eq!(dir.collisions(), 2);
    }

    #[test]
    fn unresolved_drops_are_observable() {
        let dir = Directory::new();
        assert_eq!(dir.unresolved_drops(), 0);
        // The transport records each send it drops for an unknown coordinate.
        dir.note_unresolved_drop([9, 9, 9]);
        dir.note_unresolved_drop([8, 8, 8]);
        assert_eq!(dir.unresolved_drops(), 2);
        // Shared across clones, like the collision counter.
        assert_eq!(dir.clone().unresolved_drops(), 2);
    }
}
