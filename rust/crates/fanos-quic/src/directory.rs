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
use fanos_vrf::{VrfOutput, outranks};

/// One coordinate's occupant: where to dial it, and — when a coordinate proof was verified — the **rank** that decides
/// who keeps the point if another node claims it.
#[derive(Clone, Copy)]
struct Binding {
    addr: SocketAddr,
    /// The occupant's coordinate-VRF output, or `None` for bindings made without a verified proof (bootstrap seeds,
    /// pinned fixtures). An unranked binding carries no evidence, so it can neither win an arbitration nor block one.
    rank: Option<VrfOutput>,
}

impl Binding {
    /// Whether `self` displaces `existing` at a contested point: **lowest rank wins**, matching
    /// [`fanos_vrf::settle_index`] so a displaced node's own local walk reaches the same conclusion unprompted.
    ///
    /// The unranked cases are deliberately asymmetric. An unranked newcomer never displaces a *ranked* incumbent — it
    /// carries no evidence, and letting it win would restore the arrival-order eviction this rule removes. An unranked
    /// incumbent, by contrast, yields to anyone: it is a seed or fixture entry, not a proven claim.
    fn supersedes(&self, existing: &Self) -> bool {
        match (self.rank, existing.rank) {
            // Two proven claims: the unforgeable value decides, never arrival order.
            (Some(mine), Some(theirs)) => outranks(&mine, &theirs),
            // An unranked incumbent is a seed or fixture entry rather than a proven claim, so it yields to anyone.
            (_, None) => true,
            // An unranked newcomer carries no evidence: letting it displace a proven claim would restore exactly the
            // arrival-order eviction this rule exists to remove.
            (None, Some(_)) => false,
        }
    }
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
}

impl Directory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind (or rebind) a coordinate to a network address, **without** a rank.
    ///
    /// Use this only where no verified coordinate proof is in hand — bootstrap seeds, statically-pinned test fixtures,
    /// directories keyed by something other than a node's epoch coordinate. Without a rank there is no basis on which to
    /// arbitrate a collision, so a later binding replaces an earlier one, exactly as before. Prefer
    /// [`insert_ranked`](Self::insert_ranked) wherever a `HELLO` proof has been verified.
    pub fn insert(&self, coord: Triple, addr: SocketAddr) {
        self.bind(coord, Binding { addr, rank: None });
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
    pub fn insert_ranked(&self, coord: Triple, addr: SocketAddr, rank: VrfOutput) {
        self.bind(coord, Binding { addr, rank: Some(rank) });
    }

    /// The shared binding path: apply the arbitration rule, count and log genuine collisions.
    fn bind(&self, coord: Triple, incoming: Binding) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(existing) = map.get(&coord)
                && existing.addr != incoming.addr
            {
                self.collisions.fetch_add(1, Ordering::Relaxed);
                if !incoming.supersedes(existing) {
                    tracing::warn!(
                        ?coord,
                        keeping = %existing.addr,
                        rejected = %incoming.addr,
                        "overlay coordinate collision: the incumbent outranks the newcomer, which must advance \
                         along its own probe walk (fanos_vrf::settle_index) — the binding is unchanged"
                    );
                    return;
                }
                tracing::warn!(
                    ?coord,
                    displaced = %existing.addr,
                    keeping = %incoming.addr,
                    "overlay coordinate collision: the newcomer outranks the incumbent and takes the point; the \
                     incumbent must advance along its own probe walk (fanos_vrf::settle_index)"
                );
            }
            map.insert(coord, incoming);
        }
    }

    /// The rank of the node currently bound at `coord`, if it is bound *and* was recorded with one.
    ///
    /// This is the occupancy oracle [`fanos_vrf::settle_index`] consumes: a node walks its own probe sequence to the
    /// first point no lower-ranked node holds. `None` covers both "free" and "occupied but unranked" — for settling those
    /// are the same answer, since an unranked occupant provides no evidence that it may keep the point.
    #[must_use]
    pub fn rank_at(&self, coord: Triple) -> Option<VrfOutput> {
        self.inner.read().ok()?.get(&coord)?.rank
    }

    /// Unbind a coordinate — a node vacating a point on a per-epoch reshuffle (§L3), so a stale
    /// coordinate → address binding does not linger and misroute after the occupant has moved. No-op if the
    /// coordinate is not bound. (In a full deployment the DHT ages these out; here the reshuffling node
    /// clears its own vacated point.)
    pub fn remove(&self, coord: Triple) {
        if let Ok(mut map) = self.inner.write() {
            map.remove(&coord);
        }
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
    fn a_ranked_collision_is_decided_by_rank_not_by_arrival_order() {
        // The security property. Before ranks the later binding always won, so a node whose coordinate landed on a
        // victim's point could **evict** the victim simply by connecting after it — and arrival order is
        // attacker-controlled. Rank is a VRF output: unforgeable without the node's secret and unpredictable before the
        // epoch's beacon, so neither party chooses who keeps the point.
        let (low, high) = ranks();
        let coord = [1, 2, 3];

        // Incumbent outranks the newcomer ⇒ the binding is unchanged, whichever order they arrive in.
        let dir = Directory::new();
        dir.insert_ranked(coord, sa(1), low);
        dir.insert_ranked(coord, sa(2), high);
        assert_eq!(dir.resolve(coord), Some(sa(1)), "the incumbent keeps the point it outranks for");
        assert_eq!(dir.rank_at(coord), Some(low));

        // Newcomer outranks the incumbent ⇒ it takes the point, and the incumbent must advance its own probe walk.
        let dir = Directory::new();
        dir.insert_ranked(coord, sa(2), high);
        dir.insert_ranked(coord, sa(1), low);
        assert_eq!(dir.resolve(coord), Some(sa(1)), "the lower rank takes the point");
        assert_eq!(dir.rank_at(coord), Some(low));

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
        dir.insert_ranked(coord, sa(1), low);
        dir.insert(coord, sa(9));
        assert_eq!(dir.resolve(coord), Some(sa(1)), "no evidence, no eviction");

        // Unranked incumbent (a bootstrap seed or pinned fixture) yields to a proven claim, and to another seed.
        let dir = Directory::new();
        dir.insert(coord, sa(9));
        dir.insert_ranked(coord, sa(1), low);
        assert_eq!(dir.resolve(coord), Some(sa(1)), "a seed entry is not a proven claim");
        let dir = Directory::new();
        dir.insert(coord, sa(9));
        dir.insert(coord, sa(8));
        assert_eq!(dir.resolve(coord), Some(sa(8)), "two unranked bindings keep the pre-existing last-writer rule");
    }

    #[test]
    fn rank_at_is_the_occupancy_oracle_settling_consumes() {
        // `settle_index` asks exactly this question, and `None` must mean "free for me" in both the unbound and the
        // unranked case — an unranked occupant provides no evidence that it may keep the point.
        let (low, _) = ranks();
        let dir = Directory::new();
        assert_eq!(dir.rank_at([1, 0, 0]), None, "unbound");
        dir.insert([1, 0, 0], sa(3));
        assert_eq!(dir.rank_at([1, 0, 0]), None, "bound but unranked reads as free for settling");
        dir.insert_ranked([0, 0, 1], sa(4), low);
        assert_eq!(dir.rank_at([0, 0, 1]), Some(low));
        dir.remove([0, 0, 1]);
        assert_eq!(dir.rank_at([0, 0, 1]), None, "vacating clears the rank with the address");
    }

    fn sa(port: u16) -> SocketAddr {
        (std::net::Ipv4Addr::LOCALHOST, port).into()
    }

    #[test]
    fn collisions_are_observed_but_rebinding_the_same_address_is_not() {
        let dir = Directory::new();
        dir.insert([1, 2, 3], sa(1000));
        assert_eq!(dir.collisions(), 0);

        // Re-binding the identical address (a node reconnecting) is not a collision.
        dir.insert([1, 2, 3], sa(1000));
        assert_eq!(dir.collisions(), 0);

        // A different address on the same coordinate is a collision; last-writer-wins for routing.
        dir.insert([1, 2, 3], sa(2000));
        assert_eq!(dir.collisions(), 1);
        assert_eq!(dir.resolve([1, 2, 3]), Some(sa(2000)));

        // The counter is shared across clones (a node's health surface reads the same table).
        let clone = dir.clone();
        clone.insert([1, 2, 3], sa(3000));
        assert_eq!(
            dir.collisions(),
            2,
            "collision count is shared across clones"
        );

        // A distinct coordinate is unaffected.
        dir.insert([4, 5, 6], sa(4000));
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
