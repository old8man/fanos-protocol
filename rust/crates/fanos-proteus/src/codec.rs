//! The **pluggable-transport SPI** (spec §13.3 `pluggable`, Pluggable-Transports-2.0-class) — the honest
//! extension point for morphs the core cannot ship itself.
//!
//! An embedder implements [`MorphCodec`] to carry the FANOS wire over a *custom* obfuscation or a **real**
//! cover-protocol tunnel — `tls-tunnel`, `masque-h3`, `fronted`, `webrtc` — and registers it on a
//! [`ProteusShaper`](crate::ProteusShaper) via
//! [`with_codec`](crate::ProteusShaper::with_codec). This is deliberate: per the "Parrot is Dead" principle
//! (§13.2, §13.8) those morphs must tunnel through a *real* handshake with real external stacks/infra —
//! never a faked byte-imitation the core could hard-code — so the core exposes the seam and leaves the real
//! implementation to the deployment that has the infrastructure. Both peers must run the same codec (as they
//! must share the community secret) to interoperate; a plugged codec fully replaces the built-in polymorph
//! transform.

use alloc::vec::Vec;

/// A pluggable morph codec: the wire encode/decode a `pluggable` morph substitutes for the built-in
/// polymorph transform. `Send + Sync` because the shaper carrying it is shared across a node's connections.
pub trait MorphCodec: Send + Sync {
    /// Wrap `frame` for the wire. `seq` is the shaper's monotonic per-packet counter — use it to diversify
    /// each packet (e.g. as a nonce) so identical frames do not produce identical wire bytes.
    fn encode(&self, frame: &[u8], seq: u64) -> Vec<u8>;

    /// Recover a frame from `wire`, or `None` if it was not produced by this codec (e.g. a probe, or a peer
    /// running a different codec).
    fn decode(&self, wire: &[u8]) -> Option<Vec<u8>>;
}
