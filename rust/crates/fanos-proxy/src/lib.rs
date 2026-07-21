//! # fanos-proxy — the SOCKS5 front-end
//!
//! A correct, minimal **SOCKS5 CONNECT** server (roadmap Phase 2, `docs/design.md` §11) that hands
//! each accepted target to a pluggable [`Dialer`] and pipes bytes bidirectionally. The proxy itself
//! is transport-agnostic: the *how do I reach this target* policy — resolve a `.fanos` name over
//! the overlay, refuse the clear net until an exit is configured — lives entirely in the `Dialer`.
//!
//! **DNS never leaks**: a `.fanos` host is classified and handled in-network ([`Target::is_fanos`]),
//! never resolved through the system resolver; a clear-net host is passed to the dialer as a *name*,
//! so it is the dialer (an exit) that resolves it, not the local machine.
//!
//! * [`target`] — the SOCKS5 destination ([`Target`]).
//! * [`dialer`] — the [`Dialer`] / [`UdpDialer`] seams and their errors; [`dialer::EchoDialer`] for tests.
//! * [`socks5`] — the wire protocol: [`socks5::serve`] and [`socks5::handle`] (CONNECT + UDP ASSOCIATE).
//! * [`udp`] — the SOCKS5 UDP ASSOCIATE datagram relay (DNS-over-FANOS and any datagram flow).

#![forbid(unsafe_code)]

pub mod dialer;
pub mod http;
pub mod socks5;
pub mod target;
pub mod udp;

pub use dialer::{DialError, Dialer, UdpDialer, UdpTunnel};
pub use socks5::{handle, serve};
pub use target::Target;
