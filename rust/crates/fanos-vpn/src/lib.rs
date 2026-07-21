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
//! * [`driver`] — [`run_vpn`] over a [`TunReader`]/[`TunWriter`] device seam: the full bridge, testable with
//!   an in-memory device; a real TUN device is a thin adapter implementing those two traits.
//!
//! Remaining: the real TUN device adapter (behind a safe `tun`-crate wrapper in the binary — the OS I/O
//! shell) and the userspace-TCP full-tunnel mode.

#![forbid(unsafe_code)]

pub mod driver;
pub mod engine;
pub mod mux;
pub mod packet;

pub use driver::{TunReader, TunWriter, run_vpn};
pub use engine::{DNS_PORT, FlowKey, VpnAction, classify, response_packet};
pub use mux::run_udp_datapath;
pub use packet::{
    IPPROTO_UDP, UdpDatagram, build_ipv4_udp, build_ipv6_udp, build_udp, parse_ipv4_udp,
    parse_ipv6_udp, parse_udp,
};
