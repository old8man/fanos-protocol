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
//!
//! The TUN device driver (wiring this to `/dev/net/tun` / `utun` and to [`dial_exit_udp`] tunnels) and the
//! userspace-TCP full-tunnel mode are layered on top in later slices.
//!
//! [`dial_exit_udp`]: https://docs.rs/fanos-node

#![forbid(unsafe_code)]

pub mod engine;
pub mod packet;

pub use engine::{DNS_PORT, FlowKey, VpnAction, classify, response_packet};
pub use packet::{IPPROTO_UDP, UdpDatagram, build_ipv4_udp, parse_ipv4_udp};
