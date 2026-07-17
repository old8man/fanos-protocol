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
//! * [`frame`] — what a cell carries: `DATA` (a reliability [`Segment`](fanos_runtime::stream::Segment)),
//!   `ACK` (a selective [`Ack`](fanos_runtime::stream::Ack) + receive credit), or `PADDING` (cover).
//!   The real content length is inside the encrypted frame, so the constant cell hides it end-to-end.
//! * [`endpoint`] — [`StreamEndpoint`](endpoint::StreamEndpoint): a bidirectional reliable stream over
//!   cells, driving the shipped selective-repeat + SACK core of `fanos_runtime::stream` end-to-end.
//!
//! Multiplexing many streams over one connection, the 1-RTT handshake, and the threshold
//! rendezvous-meeting reply path build on this atom (subsequent phases).

#![forbid(unsafe_code)]

pub mod cell;
pub mod conn;
pub mod endpoint;
pub mod frame;

pub use cell::{CELL_LEN, Key, open, seal};
pub use conn::Connection;
pub use endpoint::StreamEndpoint;
pub use frame::Frame;
