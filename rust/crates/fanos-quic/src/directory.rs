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

/// A shared, cloneable coordinate → address table. Cheap to clone (shares one map).
#[derive(Clone, Default)]
pub struct Directory {
    inner: Arc<RwLock<HashMap<Triple, SocketAddr>>>,
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

    /// Bind (or rebind) a coordinate to a network address.
    ///
    /// A node's coordinate is `MapToPoint(H(pubkey))`, so two distinct identities collide on one point
    /// with probability `1/N` (§L0). When that happens the *earlier* binding is overwritten (so the
    /// colliding node silently shadows another and one becomes unreachable) — a real fault the network
    /// must resolve by relocation. Rebinding the *same* address (a node reconnecting) is not a
    /// collision. Every genuine collision is surfaced: it is counted ([`collisions`](Self::collisions))
    /// and logged, so the condition is observable instead of a silent routing break.
    pub fn insert(&self, coord: Triple, addr: SocketAddr) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(&existing) = map.get(&coord)
                && existing != addr
            {
                self.collisions.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    ?coord,
                    %existing,
                    new = %addr,
                    "overlay coordinate collision: two identities map to one point; the colliding \
                     node must relocate into a sub-cell (§L0) rather than shadow the existing binding"
                );
            }
            map.insert(coord, addr);
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
        tracing::debug!(?coord, "dropped a send to an unresolved coordinate (no known address)");
    }

    /// How many sends this directory has seen dropped for an unresolved destination coordinate.
    #[must_use]
    pub fn unresolved_drops(&self) -> usize {
        self.unresolved_drops.load(Ordering::Relaxed)
    }

    /// Resolve a coordinate to its address, if known.
    #[must_use]
    pub fn resolve(&self, coord: Triple) -> Option<SocketAddr> {
        self.inner
            .read()
            .ok()
            .and_then(|map| map.get(&coord).copied())
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
        assert_eq!(dir.collisions(), 2, "collision count is shared across clones");

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
