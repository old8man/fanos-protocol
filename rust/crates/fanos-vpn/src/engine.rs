//! The sans-I/O VPN flow engine (spec §11.4): classify an inbound TUN packet into a tunnel action, and
//! rebuild a response datagram from the exit into a packet for the TUN.
//!
//! Stateless per packet — the 4-tuple carries the addressing — so the **driver** (which owns the clock, the
//! TUN device, and the flow→exit-tunnel map) stays the only stateful, I/O-bound layer, exactly as with the
//! node's sans-I/O engine/driver split. That makes the routing brain fully testable with synthetic packets,
//! no TUN required.

use std::net::IpAddr;

use crate::packet::{build_udp, parse_udp};

/// DNS's well-known port. A UDP datagram to it rides the DNS-over-FANOS path (still an exit UDP relay, but
/// flagged so a driver can route it to a configured resolver).
pub const DNS_PORT: u16 = 53;

/// The flow an exit UDP tunnel is keyed on: the client's 4-tuple as seen at the TUN (either address family).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    /// The client's `(address, port)` — where a response is delivered back to.
    pub client: (IpAddr, u16),
    /// The destination `(address, port)` the datagram is bound for.
    pub dst: (IpAddr, u16),
}

/// What the driver should do with an inbound TUN packet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VpnAction {
    /// Relay `payload` to the flow's destination over an exit UDP tunnel (open one keyed by `flow` if new).
    /// `is_dns` marks a datagram to [`DNS_PORT`] so a driver may special-case DNS-over-FANOS.
    RelayUdp {
        /// The flow (client + destination) the tunnel is keyed on.
        flow: FlowKey,
        /// The UDP payload to relay.
        payload: Vec<u8>,
        /// Whether the destination is the DNS port.
        is_dns: bool,
    },
    /// The packet is not handled by the UDP datapath (TCP — a later full-tunnel mode — IPv6, or malformed):
    /// drop it.
    Drop,
}

/// Classify an inbound IPv4 TUN packet: a UDP datagram becomes a [`VpnAction::RelayUdp`] whose flow is its
/// 4-tuple; anything else is [`VpnAction::Drop`].
#[must_use]
pub fn classify(packet: &[u8]) -> VpnAction {
    match parse_udp(packet) {
        Some(dg) => VpnAction::RelayUdp {
            flow: FlowKey { client: dg.src, dst: dg.dst },
            is_dns: dg.dst.1 == DNS_PORT,
            payload: dg.payload,
        },
        None => VpnAction::Drop,
    }
}

/// Build the TUN packet for a `response` the exit returned on `flow`: it appears to come **from** the flow's
/// destination back **to** the client (source/destination swapped), so the client's socket accepts it.
#[must_use]
pub fn response_packet(flow: FlowKey, response: &[u8]) -> Vec<u8> {
    build_udp(flow.dst, flow.client, response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::packet::{build_ipv4_udp, build_ipv6_udp, parse_udp};

    const CLIENT4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const RESOLVER4: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
    const HOST4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const CLIENT: IpAddr = IpAddr::V4(CLIENT4);
    const RESOLVER: IpAddr = IpAddr::V4(RESOLVER4);
    const CLIENT6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const RESOLVER6: Ipv6Addr = Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 9);

    #[test]
    fn classify_routes_udp_and_flags_dns() {
        let query = build_ipv4_udp((CLIENT4, 5555), (RESOLVER4, 53), b"a dns query");
        match classify(&query) {
            VpnAction::RelayUdp { flow, payload, is_dns } => {
                assert!(is_dns, "a datagram to :53 is flagged DNS");
                assert_eq!(flow.client, (CLIENT, 5555));
                assert_eq!(flow.dst, (RESOLVER, 53));
                assert_eq!(payload, b"a dns query");
            }
            VpnAction::Drop => panic!("a UDP datagram must be relayed"),
        }

        // A non-DNS UDP flow (e.g. QUIC) relays too, just not flagged DNS.
        let quic = build_ipv4_udp((CLIENT4, 6000), (HOST4, 443), b"quic");
        assert!(matches!(classify(&quic), VpnAction::RelayUdp { is_dns: false, .. }));
    }

    #[test]
    fn classify_routes_ipv6_udp() {
        // An IPv6 DNS query classifies and carries the v6 flow.
        let query = build_ipv6_udp((CLIENT6, 5555), (RESOLVER6, 53), b"ipv6 dns");
        match classify(&query) {
            VpnAction::RelayUdp { flow, is_dns, .. } => {
                assert!(is_dns);
                assert_eq!(flow.client, (IpAddr::V6(CLIENT6), 5555));
                assert_eq!(flow.dst, (IpAddr::V6(RESOLVER6), 53));
            }
            VpnAction::Drop => panic!("an IPv6 UDP datagram must be relayed"),
        }
    }

    #[test]
    fn classify_drops_non_udp() {
        let mut tcp = build_ipv4_udp((CLIENT4, 1), (HOST4, 2), b"x");
        tcp[9] = 6; // protocol → TCP
        assert_eq!(classify(&tcp), VpnAction::Drop, "TCP is not handled by the UDP datapath yet");
        assert_eq!(classify(&[]), VpnAction::Drop);
    }

    #[test]
    fn response_packet_swaps_endpoints_and_round_trips() {
        // IPv4.
        let flow = FlowKey { client: (CLIENT, 5555), dst: (RESOLVER, 53) };
        let dg = parse_udp(&response_packet(flow, b"a dns answer")).unwrap();
        assert_eq!(dg.src, (RESOLVER, 53), "the response appears to come from the resolver");
        assert_eq!(dg.dst, (CLIENT, 5555), "delivered back to the client's socket");
        assert_eq!(dg.payload, b"a dns answer");

        // IPv6 (same family in, same family out).
        let flow6 = FlowKey { client: (IpAddr::V6(CLIENT6), 5555), dst: (IpAddr::V6(RESOLVER6), 53) };
        let dg6 = parse_udp(&response_packet(flow6, b"v6 answer")).unwrap();
        assert_eq!(dg6.src, (IpAddr::V6(RESOLVER6), 53));
        assert_eq!(dg6.dst, (IpAddr::V6(CLIENT6), 5555));
        assert_eq!(dg6.payload, b"v6 answer");
    }
}
