//! Minimal IPv4/IPv6 + UDP packet codec for the VPN datapath (spec §11.4, "UDP mode").
//!
//! Parses the header fields the flow engine routes on, and builds response packets to write back to the TUN.
//! This is **not** a full IP stack — TCP full-tunnel needs a userspace TCP/IP stack (a separate layer); this
//! is exactly the UDP/DNS datapath, which needs only stateless per-packet header handling. Internet
//! checksums (the IPv4 header checksum, and the UDP checksum over the IPv4/IPv6 pseudo-header) are computed
//! so the packets are valid on the wire. Both IP versions are handled; [`parse_udp`] / [`build_udp`]
//! dispatch on the version so the rest of the datapath is address-family-agnostic ([`std::net::IpAddr`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv4/IPv6 protocol / next-header number for UDP.
pub const IPPROTO_UDP: u8 = 17;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

/// A parsed UDP datagram: source and destination `(address, port)` and the UDP payload. The address family
/// (v4/v6) is carried in the [`IpAddr`], so the flow engine is version-agnostic.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UdpDatagram {
    /// The source `(address, port)`.
    pub src: (IpAddr, u16),
    /// The destination `(address, port)`.
    pub dst: (IpAddr, u16),
    /// The UDP payload.
    pub payload: Vec<u8>,
}

/// Read a big-endian `u16` at byte offset `at` of `s`, or `None` if it doesn't fit.
fn be16(s: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_be_bytes(s.get(at..end)?.try_into().ok()?))
}

/// Read the UDP header + payload from `udp` (the bytes after the IP header) into `(src_port, dst_port,
/// payload)`, honouring the UDP length field. `None` on truncation.
fn parse_udp_body(udp: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
    let src_port = be16(udp, 0)?;
    let dst_port = be16(udp, 2)?;
    let udp_len = usize::from(be16(udp, 4)?);
    if udp_len < UDP_HEADER_LEN {
        return None;
    }
    let payload = udp.get(UDP_HEADER_LEN..udp_len)?.to_vec();
    Some((src_port, dst_port, payload))
}

/// Parse an IP packet (v4 or v6), returning its UDP datagram if it is well-formed IPv4/UDP or IPv6/UDP —
/// else `None`. Dispatches on the IP version nibble.
#[must_use]
pub fn parse_udp(packet: &[u8]) -> Option<UdpDatagram> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_udp(packet),
        6 => parse_ipv6_udp(packet),
        _ => None,
    }
}

/// Build an IP/UDP packet (v4 or v6, chosen by the address family of `src`/`dst`) carrying `payload`, with
/// correct checksums. `src` and `dst` must be the same family (mixed families yield an empty packet).
#[must_use]
pub fn build_udp(src: (IpAddr, u16), dst: (IpAddr, u16), payload: &[u8]) -> Vec<u8> {
    match (src.0, dst.0) {
        (IpAddr::V4(s), IpAddr::V4(d)) => build_ipv4_udp((s, src.1), (d, dst.1), payload),
        (IpAddr::V6(s), IpAddr::V6(d)) => build_ipv6_udp((s, src.1), (d, dst.1), payload),
        _ => Vec::new(), // mixed families are never produced by the engine (a flow is one family)
    }
}

/// Parse an IPv4/UDP packet (see [`parse_udp`]). `None` for non-UDP, fragments, or truncation.
#[must_use]
pub fn parse_ipv4_udp(packet: &[u8]) -> Option<UdpDatagram> {
    let ver_ihl = *packet.first()?;
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(ver_ihl & 0x0f) * 4;
    if ihl < IPV4_HEADER_LEN {
        return None;
    }
    if *packet.get(9)? != IPPROTO_UDP {
        return None;
    }
    // Drop fragments (MF flag set, or a non-zero fragment offset) — we don't reassemble.
    if be16(packet, 6)? & 0x3fff != 0 {
        return None;
    }
    let octets4 = |at: usize| -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(at..at + 4)?).ok()?))
    };
    let src_addr = octets4(12)?;
    let dst_addr = octets4(16)?;
    let (src_port, dst_port, payload) = parse_udp_body(packet.get(ihl..)?)?;
    Some(UdpDatagram {
        src: (IpAddr::V4(src_addr), src_port),
        dst: (IpAddr::V4(dst_addr), dst_port),
        payload,
    })
}

/// Parse an IPv6/UDP packet (see [`parse_udp`]). `None` for a non-UDP next header (including any extension
/// header — we handle the common no-extension case) or truncation.
#[must_use]
pub fn parse_ipv6_udp(packet: &[u8]) -> Option<UdpDatagram> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    // Next Header must be UDP directly — extension headers (a rare case for UDP) are not walked.
    if *packet.get(6)? != IPPROTO_UDP {
        return None;
    }
    let addr16 = |at: usize| -> Option<Ipv6Addr> {
        Some(Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(at..at + 16)?).ok()?))
    };
    let src_addr = addr16(8)?;
    let dst_addr = addr16(24)?;
    let (src_port, dst_port, payload) = parse_udp_body(packet.get(IPV6_HEADER_LEN..)?)?;
    Some(UdpDatagram {
        src: (IpAddr::V6(src_addr), src_port),
        dst: (IpAddr::V6(dst_addr), dst_port),
        payload,
    })
}

/// Build a valid IPv4/UDP packet carrying `payload` from `src` to `dst`, with correct IPv4-header and UDP
/// checksums — suitable to write straight to a TUN device.
#[must_use]
pub fn build_ipv4_udp(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    let udp = udp_segment(src.1, dst.1, payload, |udp| {
        pseudo_ipv4(src.0, dst.0, udp)
    });
    let total_len = IPV4_HEADER_LEN + udp.len();

    let mut ip = Vec::with_capacity(IPV4_HEADER_LEN);
    ip.push(0x45); // version 4, IHL 5 (no options)
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&u16_be(total_len));
    ip.extend_from_slice(&[0, 0]); // identification
    ip.extend_from_slice(&[0x40, 0]); // flags: Don't-Fragment, fragment offset 0
    ip.push(64); // TTL
    ip.push(IPPROTO_UDP);
    ip.extend_from_slice(&[0, 0]); // header checksum placeholder
    ip.extend_from_slice(&src.0.octets());
    ip.extend_from_slice(&dst.0.octets());
    let ip_csum = checksum(&ip);
    let mut packet = splice_u16(&ip, 10, ip_csum);
    packet.extend_from_slice(&udp);
    packet
}

/// Build a valid IPv6/UDP packet carrying `payload` from `src` to `dst`, with the (mandatory) UDP checksum
/// over the IPv6 pseudo-header.
#[must_use]
pub fn build_ipv6_udp(src: (Ipv6Addr, u16), dst: (Ipv6Addr, u16), payload: &[u8]) -> Vec<u8> {
    let udp = udp_segment(src.1, dst.1, payload, |udp| {
        pseudo_ipv6(src.0, dst.0, udp)
    });

    let mut ip = Vec::with_capacity(IPV6_HEADER_LEN + udp.len());
    ip.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, traffic class 0, flow label 0
    ip.extend_from_slice(&u16_be(udp.len())); // payload length
    ip.push(IPPROTO_UDP); // next header
    ip.push(64); // hop limit
    ip.extend_from_slice(&src.0.octets());
    ip.extend_from_slice(&dst.0.octets());
    ip.extend_from_slice(&udp);
    ip
}

/// Build the UDP header + payload, then patch its checksum computed over `pseudo(udp_with_zero_checksum)`.
/// A computed `0` is transmitted as `0xFFFF` (UDP reserves `0` to mean "no checksum").
fn udp_segment(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    pseudo: impl Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&u16_be(udp_len));
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);
    let csum = match checksum(&pseudo(&udp)) {
        0 => 0xffff,
        c => c,
    };
    splice_u16(&udp, 6, csum)
}

/// The IPv4 UDP pseudo-header (`src ‖ dst ‖ 0 ‖ proto ‖ udp_len`) followed by the UDP segment.
fn pseudo_ipv4(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + udp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(IPPROTO_UDP);
    buf.extend_from_slice(&u16_be(udp.len()));
    buf.extend_from_slice(udp);
    buf
}

/// The IPv6 UDP pseudo-header (`src ‖ dst ‖ len(4) ‖ 0(3) ‖ next_header`) followed by the UDP segment.
fn pseudo_ipv6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40 + udp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&u32::try_from(udp.len()).unwrap_or(u32::MAX).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, IPPROTO_UDP]);
    buf.extend_from_slice(udp);
    buf
}

/// A length as big-endian `u16` bytes, saturating (a UDP datagram can't exceed a `u16` anyway).
fn u16_be(len: usize) -> [u8; 2] {
    u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes()
}

/// Return a copy of `bytes` with the big-endian `u16` `value` written at offset `at` (to patch a checksum
/// field after computing it over the zeroed header). Index-free.
fn splice_u16(bytes: &[u8], at: usize, value: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(bytes.get(..at).unwrap_or(bytes));
    out.extend_from_slice(&value.to_be_bytes());
    out.extend_from_slice(bytes.get(at + 2..).unwrap_or(&[]));
    out
}

/// The 16-bit one's-complement Internet checksum (RFC 1071) over `data`.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, remainder) = data.as_chunks::<2>();
    for &[a, b] in pairs {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([a, b])));
    }
    if let [last] = remainder {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const A4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const B4: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
    const A6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const B6: Ipv6Addr = Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 9);

    #[test]
    fn ipv4_build_then_parse_round_trips() {
        let pkt = build_ipv4_udp((A4, 40000), (B4, 53), b"a dns query");
        let dg = parse_udp(&pkt).expect("well-formed IPv4/UDP");
        assert_eq!(dg.src, (IpAddr::V4(A4), 40000));
        assert_eq!(dg.dst, (IpAddr::V4(B4), 53));
        assert_eq!(dg.payload, b"a dns query");
        assert_eq!(usize::from(u16::from_be_bytes([pkt[2], pkt[3]])), pkt.len());
    }

    #[test]
    fn ipv6_build_then_parse_round_trips() {
        let pkt = build_ipv6_udp((A6, 40000), (B6, 53), b"an ipv6 dns query");
        assert_eq!(pkt[0] >> 4, 6, "version 6");
        let dg = parse_udp(&pkt).expect("well-formed IPv6/UDP");
        assert_eq!(dg.src, (IpAddr::V6(A6), 40000));
        assert_eq!(dg.dst, (IpAddr::V6(B6), 53));
        assert_eq!(dg.payload, b"an ipv6 dns query");
        // Payload-length field matches the UDP segment length.
        assert_eq!(usize::from(u16::from_be_bytes([pkt[4], pkt[5]])), pkt.len() - IPV6_HEADER_LEN);
    }

    #[test]
    fn build_udp_dispatches_on_family() {
        let v4 = build_udp((IpAddr::V4(A4), 1), (IpAddr::V4(B4), 2), b"x");
        assert_eq!(v4[0] >> 4, 4);
        let v6 = build_udp((IpAddr::V6(A6), 1), (IpAddr::V6(B6), 2), b"x");
        assert_eq!(v6[0] >> 4, 6);
        // A mixed family is never produced by the engine; guard returns empty rather than a bad packet.
        assert!(build_udp((IpAddr::V4(A4), 1), (IpAddr::V6(B6), 2), b"x").is_empty());
    }

    #[test]
    fn checksums_are_valid_for_both_families() {
        // A receiver verifies the IPv4 header checksum by summing the header to 0.
        let v4 = build_ipv4_udp((A4, 1234), (B4, 5678), b"payload");
        assert_eq!(checksum(&v4[..IPV4_HEADER_LEN]), 0, "IPv4 header checksum verifies");
        // UDP (v4): recompute over the pseudo-header + UDP → 0.
        assert_eq!(checksum(&pseudo_ipv4(A4, B4, &v4[IPV4_HEADER_LEN..])), 0, "v4 UDP checksum verifies");
        // UDP (v6): recompute over the IPv6 pseudo-header + UDP → 0.
        let v6 = build_ipv6_udp((A6, 1234), (B6, 5678), b"payload");
        assert_eq!(checksum(&pseudo_ipv6(A6, B6, &v6[IPV6_HEADER_LEN..])), 0, "v6 UDP checksum verifies");
    }

    #[test]
    fn rejects_non_udp_fragments_and_truncation() {
        let mut tcp = build_ipv4_udp((A4, 1), (B4, 2), b"x");
        tcp[9] = 6;
        assert!(parse_udp(&tcp).is_none(), "non-UDP is not parsed");
        let mut frag = build_ipv4_udp((A4, 1), (B4, 2), b"x");
        frag[6] = 0x20; // set MF
        assert!(parse_udp(&frag).is_none(), "a fragment is dropped");
        // IPv6 with a non-UDP next header.
        let mut v6tcp = build_ipv6_udp((A6, 1), (B6, 2), b"x");
        v6tcp[6] = 6;
        assert!(parse_udp(&v6tcp).is_none(), "IPv6 non-UDP is not parsed");
        assert!(parse_udp(&[0x45, 0, 0, 0]).is_none(), "truncated");
        assert!(parse_udp(&[]).is_none());
    }

    #[test]
    fn empty_payload_is_valid() {
        for pkt in [build_ipv4_udp((A4, 1), (B4, 2), b""), build_ipv6_udp((A6, 1), (B6, 2), b"")] {
            let dg = parse_udp(&pkt).unwrap();
            assert!(dg.payload.is_empty());
        }
    }
}
