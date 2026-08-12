//! The VPN flow multiplexer — the driver's stateful core (spec §11.4).
//!
//! Route classified UDP flows over per-destination exit tunnels and pump responses back to the TUN, reusing
//! the very same `UdpDialer` / `UdpTunnel` datagram seam the SOCKS5 UDP-ASSOCIATE relay uses (fanos-proxy) —
//! the VPN and the proxy share one exit-UDP-tunnel abstraction, and the production impl (a `FanosDialer`
//! with an exit) is the same. Given the TUN's two directions as channels, this is fully testable with a
//! mock dialer; the real TUN device is a thin adapter that copies packets between the fd and these channels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use fanos_proxy::{Target, UdpDialer};
use tokio::sync::mpsc;

use crate::engine::{FlowKey, VpnAction, classify, response_packet};

/// Cap on the distinct destination flows the datapath tunnels concurrently (audit A4: bound every per-flow
/// map). Traffic to many destinations (a scan, a peer-to-peer swarm) would otherwise grow the tunnel map —
/// and its exit dials — without limit; at the cap the least-recently-used flow is evicted (dropping its
/// sender tears the tunnel down). Matches the DIAULOS `MAX_SESSIONS` discipline.
pub const MAX_UDP_FLOWS: usize = 4096;

/// The MTU this build configures the userspace stack with, and therefore the largest IP packet it will ever
/// hand up.
///
/// **Set explicitly rather than inherited from `IpStackConfig::default()`, because [`UDP_BUF`] is derived
/// from it.** The default happens to be the same value today (ipstack's `MIN_MTU`), but a buffer sized from
/// a dependency's default is sized from something that can change in a patch release without this crate
/// noticing — and the failure would be a truncated datagram, not a build error. Stating it makes the
/// derivation below true by construction instead of true by reading someone else's source.
///
/// 1280 is the IPv6 minimum link MTU (RFC 8200 §5) and ipstack's own floor; a tunnel that stays at or below
/// it is deliverable over any path without path-MTU discovery, which is the property a VPN datapath wants.
///
/// **It moved here from `fulltunnel`, which is behind `feature = "device"` (#300).** This number is the
/// ceiling on every datagram *this* module queues, and this module is not gated — so the quantity that
/// bounds the mux's memory was only compiled when the device backend was. A bound that disappears with a
/// feature cannot be summed by anything that does not enable it.
pub const STACK_MTU: u16 = 1280;

/// The largest item this module can put in a tunnel queue: a UDP **payload**, not a link-sized packet.
///
/// **Derived, and the derivation is the correction.** `run_udp_datapath` queues `payload` — the bytes
/// `parse_udp_body` returns *after* the UDP header, from a packet that already lost its IP header. So the
/// ceiling is `STACK_MTU - IP header - UDP header`, and IPv4 is the worst case because its header is 20 B
/// against IPv6's 40, leaving MORE payload at the same MTU.
///
/// #300's first ratchet pinned `STACK_MTU` itself and was wrong by 2.2% — small in the number, total in the
/// meaning: a ratchet on the link MTU verifies a quantity this module never queues, and tells the next
/// reader to re-derive from the wrong factors. `fanos_primitives::budget`'s own header had it right at
/// `~1252` all along; the two numbers only disagreed out loud because both were written down.
pub const MAX_QUEUED_PAYLOAD: usize =
    STACK_MTU as usize - crate::packet::IPV4_HEADER_LEN - crate::packet::UDP_HEADER_LEN;

/// IPv4 is the worst case: at one MTU it leaves more payload than IPv6, so sizing on it covers both.
const _: () = assert!(
    STACK_MTU as usize - crate::packet::IPV6_HEADER_LEN - crate::packet::UDP_HEADER_LEN
        < MAX_QUEUED_PAYLOAD,
    "IPv6 was expected to leave less payload than IPv4 at one MTU; if that changed, the ceiling must be the \
     max of the two rather than the IPv4 figure"
);

/// An exit tunnel plus its last-use time, so the least-recently-used can be evicted at the cap.
struct Flow {
    outbound: mpsc::Sender<Vec<u8>>,
    last_used: Instant,
}

/// Evict the least-recently-used flow (called when the map is at [`MAX_UDP_FLOWS`]); dropping its sender
/// closes the exit tunnel and ends its reply pump.
fn evict_lru(tunnels: &mut HashMap<FlowKey, Flow>) {
    if let Some(victim) = tunnels.iter().min_by_key(|(_, f)| f.last_used).map(|(&k, _)| k) {
        tunnels.remove(&victim);
    }
}

/// Run the UDP datapath: read IP packets from `inbound` (the TUN), relay each UDP flow over an exit tunnel
/// obtained from `dialer`, and write response packets to `outbound` (the TUN). One tunnel per destination
/// flow (opened on first sight, re-opened if it closes); each response is rebuilt into a TUN packet with the
/// endpoints swapped so the client's socket accepts it. Non-UDP packets (TCP — a later mode — IPv6,
/// malformed) are dropped. Returns when `inbound` closes.
pub async fn run_udp_datapath<D: UdpDialer>(
    dialer: D,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
) {
    // One outbound tunnel per flow the client has active (bounded, LRU-evicted).
    let mut tunnels: HashMap<FlowKey, Flow> = HashMap::new();
    while let Some(packet) = inbound.recv().await {
        let VpnAction::RelayUdp { flow, payload, .. } = classify(&packet) else {
            continue; // Drop
        };
        // Open (or re-open) the exit tunnel for this destination flow on first sight, evicting the
        // least-recently-used flow first if the map is at its cap.
        if tunnels.get(&flow).is_none_or(|f| f.outbound.is_closed()) {
            let target = Target::Ip(SocketAddr::from((flow.dst.0, flow.dst.1)));
            let Ok(tunnel) = dialer.dial_udp(&target).await else {
                continue;
            };
            if tunnels.len() >= MAX_UDP_FLOWS {
                evict_lru(&mut tunnels);
            }
            spawn_response_pump(tunnel.inbound, flow, outbound.clone());
            tunnels.insert(flow, Flow { outbound: tunnel.outbound, last_used: Instant::now() });
        }
        if let Some(f) = tunnels.get_mut(&flow) {
            f.last_used = Instant::now();
            // UDP is lossy: drop if the tunnel is backed up rather than stall the whole datapath.
            let _ = f.outbound.try_send(payload);
        }
    }
}

/// Pump one flow's exit responses back to the TUN: each datagram becomes a TUN packet (from the flow's
/// destination back to the client) written to `outbound`. Ends when the tunnel or the TUN sink closes.
fn spawn_response_pump(
    mut inbound: mpsc::Receiver<Vec<u8>>,
    flow: FlowKey,
    outbound: mpsc::Sender<Vec<u8>>,
) {
    tokio::spawn(async move {
        while let Some(response) = inbound.recv().await {
            if outbound.send(response_packet(flow, &response)).await.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::net::Ipv4Addr;

    /// **The other member of #300's class, and it is a different number for a structural reason.**
    ///
    /// The tunnel queue is the same object as the proxy's — `UdpTunnel::pair(UDP_TUNNEL_BUFFER)`, one call
    /// site — so the depth is shared. What differs is the **ceiling on a queued item**, and that is set by
    /// the producer, not the channel: the proxy reads a UDP socket and can push 65535 bytes, this crate
    /// reads a TUN device and cannot exceed [`MAX_QUEUED_PAYLOAD`]. Hence `tunnel_queue_ceiling` takes the ceiling as
    /// an argument rather than assuming one — a single constant would have silently handed the VPN the
    /// proxy's 51x figure.
    ///
    /// **No share covers this, deliberately.** `fanos_primitives::budget` exempts the VPN because its cost
    /// is per-flow and a deployment chooses the flow count; the exemption names the per-flow costs, and the
    /// queue was not among them until #300. Pinned here so the omission is a number an operator can read
    /// rather than an absence.
    #[test]
    fn the_tunnel_queues_are_a_per_client_quantity_no_share_carries() {
        let ceiling = fanos_proxy::budget::tunnel_queue_ceiling(
            MAX_UDP_FLOWS,
            MAX_QUEUED_PAYLOAD,
        );
        println!("one client's tunnel queues: {ceiling} B ({} MiB)", ceiling >> 20);
        assert_eq!(
            ceiling, 656_408_576,
            "the per-client queue ceiling moved. MAX_UDP_FLOWS x 2 x UDP_TUNNEL_BUFFER x \
             MAX_QUEUED_PAYLOAD — \
             re-derive rather than re-pin, and check whether #300's byte debit makes this obsolete"
        );

        let proxy = fanos_proxy::budget::tunnel_queue_ceiling(
            fanos_proxy::udp::MAX_UDP_FLOWS,
            fanos_proxy::budget::MAX_UDP,
        );
        assert!(
            proxy > ceiling * 12,
            "the proxy's ceiling ({proxy} B) is supposed to dominate this one ({ceiling} B) because its \
             producer may push a full 65535-byte datagram. If they converged, one of the two producers \
             changed what it can emit, and that is the thing to look at"
        );
    }
    use std::time::Duration;

    use fanos_proxy::dialer::EchoDialer;
    use tokio::time::timeout;

    use std::net::IpAddr;

    use super::*;
    use crate::packet::{build_ipv4_udp, parse_udp};

    const CLIENT4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const RESOLVER4: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
    const HOST4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const CLIENT: IpAddr = IpAddr::V4(CLIENT4);
    const RESOLVER: IpAddr = IpAddr::V4(RESOLVER4);
    const HOST: IpAddr = IpAddr::V4(HOST4);

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_udp_flow_relays_out_and_the_response_returns_as_a_tun_packet() {
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(16);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(16);
        // The echo dialer stands in for the exit: whatever is relayed comes straight back.
        tokio::spawn(run_udp_datapath(EchoDialer, in_rx, out_tx));

        // A DNS query captured at the TUN.
        let query = build_ipv4_udp((CLIENT4, 5555), (RESOLVER4, 53), b"dns-query");
        in_tx.send(query).await.unwrap();

        // It round-trips: the response comes back as a TUN packet from the resolver to the client.
        let reply = timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("no timeout")
            .expect("a reply packet");
        let dg = parse_udp(&reply).unwrap();
        assert_eq!(dg.src, (RESOLVER, 53), "reply is from the resolver");
        assert_eq!(dg.dst, (CLIENT, 5555), "back to the client");
        assert_eq!(dg.payload, b"dns-query");

        // A second, different flow (QUIC to a web host) opens its own tunnel and also round-trips.
        let quic = build_ipv4_udp((CLIENT4, 6000), (HOST4, 443), b"quic-initial");
        in_tx.send(quic).await.unwrap();
        let reply2 = timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("no timeout")
            .expect("a reply packet");
        let dg2 = parse_udp(&reply2).unwrap();
        assert_eq!(dg2.src, (HOST, 443));
        assert_eq!(dg2.dst, (CLIENT, 6000));
        assert_eq!(dg2.payload, b"quic-initial");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_tcp_packet_is_dropped_not_relayed() {
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(16);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(16);
        tokio::spawn(run_udp_datapath(EchoDialer, in_rx, out_tx));

        let mut tcp = build_ipv4_udp((CLIENT4, 1), (HOST4, 80), b"x");
        tcp[9] = 6; // protocol → TCP
        in_tx.send(tcp).await.unwrap();
        // Nothing is relayed, so nothing comes back (a short wait times out).
        assert!(
            timeout(Duration::from_millis(300), out_rx.recv()).await.is_err(),
            "a TCP packet produces no UDP relay"
        );
    }

    #[test]
    fn evict_lru_drops_the_least_recently_used_flow() {
        let now = Instant::now();
        let mk = |secs_ago| Flow {
            outbound: mpsc::channel::<Vec<u8>>(1).0,
            last_used: now.checked_sub(Duration::from_secs(secs_ago)).unwrap(),
        };
        let key = |port| FlowKey { client: (CLIENT, port), dst: (RESOLVER, 53) };
        let mut tunnels: HashMap<FlowKey, Flow> = HashMap::new();
        tunnels.insert(key(1), mk(1)); // newest
        tunnels.insert(key(2), mk(30)); // oldest — the LRU victim
        tunnels.insert(key(3), mk(5));

        evict_lru(&mut tunnels);

        assert_eq!(tunnels.len(), 2, "exactly one flow is evicted");
        assert!(!tunnels.contains_key(&key(2)), "the least-recently-used flow is evicted");
        assert!(tunnels.contains_key(&key(1)) && tunnels.contains_key(&key(3)), "newer flows kept");
    }
}
