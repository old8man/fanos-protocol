//! # fanos-vpn — the VPN datapath (spec §11.4, "Surface C")
//!
//! Full-tunnel FANOS: capture traffic at a TUN device and route it through the overlay. The datapath follows
//! the same **sans-I/O engine / thin driver** split as the node: a pure, testable routing engine decides
//! what to do with each packet, and a thin driver owns the TUN device, the clock, and the exit tunnels.
//!
//! **Slice 1 (here): the UDP/DNS datapath.** `design.md` §11's "UDP mode" tunnels UDP (DNS, QUIC, …) with no
//! userspace TCP stack — exactly stateless per-packet header handling:
//! * [`packet`] — an IPv4/UDP codec (parse + build, with valid checksums).
//! * [`engine`] — [`classify`] an inbound TUN packet into a [`VpnAction`], and [`response_packet`] to rebuild
//!   an exit response into a packet for the TUN.
//! * [`mux`] — [`run_udp_datapath`], the driver's stateful core: relay flows over per-destination exit
//!   tunnels (the shared `UdpDialer` seam) and pump responses back, testable with a mock dialer.
//!
//! The TUN device driver (copying packets between `/dev/net/tun` / `utun` and the multiplexer's channels)
//! and the userspace-TCP full-tunnel mode are the thin/remaining layers on top.

#![forbid(unsafe_code)]

pub mod engine;
pub mod mux;
pub mod packet;

pub use engine::{DNS_PORT, FlowKey, VpnAction, classify, response_packet};
pub use mux::run_udp_datapath;
pub use packet::{IPPROTO_UDP, UdpDatagram, build_ipv4_udp, parse_ipv4_udp};
