//! # fanos-diaulos — the connection & stream layer (DIAULOS)
//!
//! **δίαυλος** — "the double conduit." A reliable, multiplexed, **end-to-end-encrypted** byte-stream
//! that runs *inside* the constant-size onion (its cells are onion `DELIVER` payloads) but keys
//! **end-to-end**, distinct from the onion's per-hop keys (`docs/design-platform.md` §3). It is the
//! transport a SOCKS5 client's TCP payload rides to a `.fanos` service and back.
//!
//! This crate is the sans-I/O protocol core, in three layers:
//!
//! * [`cell`] — the wire atom: a fixed-size, per-cell-explicit-nonce AEAD envelope. Every cell is
//!   `CELL_LEN` bytes, so a passive observer sees a constant stream; the explicit nonce means a lost
//!   or reordered cell never stalls decryption of the next (no crypto head-of-line blocking), and a
//!   tampered or wrong-key cell simply fails to open and is dropped.
//! * [`frame`] — what a cell carries: `DATA` (a reliability [`Segment`](fanos_stream::Segment)),
//!   `ACK` (a selective [`Ack`](fanos_stream::Ack) + receive credit), or `PADDING` (cover).
//!   The real content length is inside the encrypted frame, so the constant cell hides it end-to-end.
//! * [`endpoint`] — [`StreamEndpoint`]: a bidirectional reliable stream over
//!   cells, driving the shipped selective-repeat + SACK core of `fanos_stream` end-to-end.
//! * [`conn`] — [`Connection`]: many such streams multiplexed over one cell channel,
//!   each with independent reliability (no cross-stream head-of-line blocking), stream ids by role.
//! * [`handshake`] — the 1-RTT hybrid KEM key exchange ([`ClientHandshake`]
//!   / [`ServerHandshake`]) that establishes a [`Connection`]'s two
//!   direction keys: forward-secret, service-authenticated, client-anonymous.
//!
//! The threshold rendezvous-meeting reply path (carrying the `ClientHello` to a hidden service) and
//! the fanos-proxy wiring build on these (subsequent phases).

// `variant_count` proves `ALL` complete at COMPILE time. A test cannot: it can only visit the variants
// the list already holds, so the one case that matters — a variant added to the enum and forgotten in the
// list — is exactly the case a test never reaches. Nightly is pinned deliberately (`rust-toolchain.toml`);
// `fanos-wire` and `fanos-ports` use the same feature for the same reason.
#![feature(variant_count)]
#![forbid(unsafe_code)]

pub mod budget;
pub mod cell;
pub mod conn;
pub mod endpoint;
pub mod frame;
pub mod handshake;
pub mod overlay;
pub mod session;

pub use cell::{CELL_LEN, Key, open, seal};
pub use conn::Connection;
pub use endpoint::StreamEndpoint;
pub use frame::Frame;
pub use handshake::{
    ClientHandshake, ServerHandshake, SessionKeys, StaticKeypair, bundle_from_identity, bundle_from_kem_public,
    service_public_from_bundle,
};
pub use overlay::{ClientSession, Coord, Ingest, ServerSession};
pub use session::{Dialed, PendingDial, accept, dial, dial_bundle};
