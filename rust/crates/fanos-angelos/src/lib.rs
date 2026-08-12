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
//!
//! # What no binary reaches yet, and the DIFFERENT reason for each (#283)
//!
//! Six of the nine modules have zero production mentions outside this crate. That count is a fact about
//! wiring, not a verdict — but "five unreachable modules" is the shape of a shared justification held by
//! non-members, and each of these is blocked on something else. Measured 2026-08-12; two of the readings below
//! are corrections of my own scans, which is why they are stated as findings rather than assumptions.
//!
//! * [`call`] — **no consumer.** `MessageKind::CallSignal` has zero production handlers anywhere outside this
//!   crate. Signalling rides the message plane, which *is* wired, so what is absent is a node-side router that
//!   recognises the kind. Smallest missing piece of the five in mechanism, largest in reach.
//! * [`media`] — **the transport exists; the key agreement does not.** My first scan looked only in
//!   `fanos-quic/src` and read zero, which was wrong: the datagram path is in `fanos-proteus::datagram` and
//!   `fanos-node::{diaulos, rendezvous, node}`. What is missing is the per-call, per-direction epoch key agreed
//!   over the control plane, plus an exposure of that datagram path to this crate. Glue, not a subsystem.
//! * [`group`] — **the ceremony is genuinely absent.** The only `group_key` in the whole tree is
//!   `fanos-vrf/src/vss.rs`'s threshold commitment — a different quantity that shares a name. Nothing anywhere
//!   distributes a sender-key group key over 1:1 sessions, so this module is blocked on a mechanism that has
//!   not been written, not on wiring.
//! * [`bot`] — **the runtime is the missing half, by this module's own design.** It is a pure `Event → Outgoing`
//!   handler that deliberately does no I/O; the SDK runtime is supposed to encrypt, transport and decrypt around
//!   it, reached through the C ABI. `fanos-ffi` has no bot surface at all — my scan first reported two hits and
//!   both were the substring `bot` inside the English word "both" in comments.
//! * [`attachment`] — **its dependency is already there.** `fanos_quic::Client::put`/`get` exist, so the content
//!   store this module needs is live. What is missing is only the edge seal and the descriptor round-trip. The
//!   cheapest of the five to close.
//! * `chain` — private, and the same zero. It is the symmetric ratchet's chain, used by [`session`].
//!
//! [`message`], [`session`] and [`ratchet`] are wired; `ratchet` only became so when #282 found that the driver
//! held the *symmetric* half while its own doc claimed post-compromise security from the asymmetric one.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod chain;

pub mod attachment;
pub mod bot;
pub mod call;
pub mod group;
pub mod media;
pub mod message;
pub mod ratchet;
pub mod session;

pub use attachment::Attachment;
pub use bot::{Bot, Event, Outgoing, dispatch};
pub use call::{CallId, CallSignal};
pub use group::GroupSession;
pub use media::{MediaKind, MediaRole, MediaSession};
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
