//! The overlay address book: projective coordinate → network address.
//!
//! The engine routes on coordinates (`Triple`); the transport needs a `SocketAddr` to dial. In a
//! full deployment this mapping is served by the DHT (spec §L1) and is self-certifying (the
//! coordinate is `MapToPoint(H(pubkey))`, and the cert-bound key proves it). Here it is a shared,
//! cloneable table the harness fills once endpoints are bound — the single seam that a real
//! discovery layer slots into without touching the engine or the driver.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use fanos_geometry::Triple;

/// A shared, cloneable coordinate → address table. Cheap to clone (shares one map).
#[derive(Clone, Default)]
pub struct Directory {
    inner: Arc<RwLock<HashMap<Triple, SocketAddr>>>,
}

impl Directory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind (or rebind) a coordinate to a network address.
    pub fn insert(&self, coord: Triple, addr: SocketAddr) {
        if let Ok(mut map) = self.inner.write() {
            map.insert(coord, addr);
        }
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
