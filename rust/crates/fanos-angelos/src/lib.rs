//! # ANGELOS — the anonymous post-quantum messenger
//!
//! *Greek ἄγγελος, a messenger.* ANGELOS is the platform's private messaging tier (`spec/platform.md` §6),
//! built to be **more advanced than Session** by *composing* the FANOS anonymity organs that each already beat
//! Session's — rather than reimplementing them:
//!
//! | Session (Oxen) | ANGELOS composes |
//! |---|---|
//! | Lokinet onion routing | **NYX** threshold-sheaf onion (`fanos-nyx`/`fanos-aphantos`) — mixnet-class, not just onion |
//! | a directory of swarms | **CALYPSO** computed rendezvous (`fanos-calypso`) — *no directory*, `O(1)`, unlinkable |
//! | Session ID (X25519) | **ONOMA** name → post-quantum identity (`fanos-onoma`, `fanos-dromos` naming) |
//! | online-ish delivery | **L4 store** mailboxes — store-and-forward, retrieved anonymously |
//! | Signal double-ratchet | this crate's **post-quantum forward-secret session** ([`session`]) |
//!
//! The one genuinely new piece — everything else being composition — is the **end-to-end session**: a
//! hybrid-ML-KEM handshake establishing a shared secret, then a BLAKE3 symmetric ratchet giving every message
//! its own key. That delivers **forward secrecy** post-quantum: a compromised key never decrypts *past*
//! messages, because the key chain is one-way. (Post-compromise security — healing after a compromise via a
//! fresh KEM ratchet step — composes on top, the double-ratchet's asymmetric half.)
//!
//! This first increment is that session core, exact and unit-tested; the transport (NYX/DIAULOS), the rendezvous
//! (CALYPSO), the ONOMA identity binding, and the offline mailbox protocol compose on top.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod group;
pub mod media;
pub mod session;

pub use group::GroupSession;
pub use media::{MediaKind, MediaSession};
pub use session::{Role, Session};

/// A per-message/frame AEAD nonce from a counter. Each key seals a monotonically-numbered stream, so a
/// counter-derived nonce is unique per (key, nonce) — the AEAD's safety requirement.
#[must_use]
pub(crate) fn nonce(n: u64) -> [u8; fanos_primitives::aead::NONCE_LEN] {
    let mut out = [0u8; fanos_primitives::aead::NONCE_LEN];
    let (head, _) = out.split_at_mut(8);
    head.copy_from_slice(&n.to_le_bytes());
    out
}
