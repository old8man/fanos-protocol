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
//! hybrid-ML-KEM handshake establishing a shared secret, then a BLAKE3 symmetric ratchet ([`session`]) giving
//! every message its own key. That delivers **forward secrecy** post-quantum: a compromised key never decrypts
//! *past* messages, because the key chain is one-way. On top of it, the [`ratchet`] module adds the asymmetric
//! half — a post-quantum **double ratchet** (a KEM in place of Signal's Diffie–Hellman) whose per-round-trip
//! healing step gives **post-compromise security**: the session recovers *future* secrecy after a compromise.
//!
//! ## The single face of the platform
//!
//! ANGELOS is not only a messenger — it is the platform's *one app*: chat, calls, communities, **and** the
//! wallet, in one surface (`spec/platform.md` §6). So the model here spans three planes and a bot layer:
//!
//! - the **content plane** — [`message`]'s canonical, language-agnostic [`Message`] envelope (text, control,
//!   presence, and in-chat **payments**: the wallet lives *in* the conversation);
//! - the **crypto planes** — a forward-secret 1:1 [`session`], a sender-key [`group`] session that makes a large
//!   channel `O(1)` per post, and a loss-tolerant real-time [`media`] session for voice/video;
//! - the **bot layer** — a pure, transport-agnostic [`bot`] contract every per-language SDK implements, so a bot
//!   written once runs anywhere the runtime carries it.
//!
//! Every wire format here is canonical and pinned by a known-answer test, so each language's SDK serializes it
//! byte-for-byte identically — the discipline the network's `conformance/vectors` follow. The transport
//! (NYX/DIAULOS), the rendezvous (CALYPSO), the ONOMA identity binding, and the offline mailbox protocol compose
//! underneath these planes.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod chain;

pub mod bot;
pub mod call;
pub mod group;
pub mod media;
pub mod message;
pub mod ratchet;
pub mod session;

pub use bot::{Bot, Event, Outgoing, dispatch};
pub use call::{CallId, CallSignal};
pub use group::GroupSession;
pub use media::{MediaKind, MediaSession};
pub use message::{Command, Message, MessageKind};
pub use ratchet::DoubleRatchet;
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
