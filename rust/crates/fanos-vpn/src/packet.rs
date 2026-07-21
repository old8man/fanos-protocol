//! Minimal IPv4 + UDP packet codec for the VPN datapath (spec §11.4, "UDP mode").
//!
//! Parses the header fields the flow engine routes on, and builds response packets to write back to the TUN.
//! This is **not** a full IP stack — TCP full-tunnel needs a userspace TCP/IP stack (a separate layer); this
//! is exactly the UDP/DNS datapath, which needs only stateless per-packet header handling. Internet
//! checksums (IPv4 header + UDP with pseudo-header) are computed so the packets are valid on the wire.

use std::net::Ipv4Addr;

/// IPv4 protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;
/// The IPv4 header length without options.
const IPV4_HEADER_LEN: usize = 20;
/// The UDP header length.
const UDP_HEADER_LEN: usize = 8;

/// A parsed IPv4/UDP datagram: source and destination `(addr, port)` and the UDP payload.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UdpDatagram {
    /// The source `(address, port)`.
    pub src: (Ipv4Addr, u16),
    /// The destination `(address, port)`.
    pub dst: (Ipv4Addr, u16),
    /// The UDP payload.
    pub payload: Vec<u8>,
}

/// Read a big-endian `u16` at byte offset `at` of `s`, or `None` if it doesn't fit.
fn be16(s: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_be_bytes(s.get(at..end)?.try_into().ok()?))
}

/// Read a 4-byte IPv4 address at byte offset `at` of `s`, or `None` if it doesn't fit.
fn addr(s: &[u8], at: usize) -> Option<Ipv4Addr> {
    let end = at.checked_add(4)?;
    let octets: [u8; 4] = s.get(at..end)?.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// Parse an IPv4 packet, returning its UDP datagram if it is a well-formed IPv4/UDP packet — else `None`
/// (not IPv4, not UDP, a fragment we do not reassemble, or a truncated/malformed header).
#[must_use]
pub fn parse_ipv4_udp(packet: &[u8]) -> Option<UdpDatagram> {
    let ver_ihl = *packet.first()?;
    if ver_ihl >> 4 != 4 {
        return None; // IPv4 only (IPv6 is a later slice)
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
    let src_addr = addr(packet, 12)?;
    let dst_addr = addr(packet, 16)?;

    // The UDP header begins after the (possibly optioned) IPv4 header.
    let udp = packet.get(ihl..)?;
    let src_port = be16(udp, 0)?;
    let dst_port = be16(udp, 2)?;
    let udp_len = usize::from(be16(udp, 4)?);
    if udp_len < UDP_HEADER_LEN {
        return None;
    }
    let payload = udp.get(UDP_HEADER_LEN..udp_len)?.to_vec();
    Some(UdpDatagram {
        src: (src_addr, src_port),
        dst: (dst_addr, dst_port),
        payload,
    })
}

/// Build a valid IPv4/UDP packet carrying `payload` from `src` to `dst`, with correct IPv4-header and UDP
/// checksums — suitable to write straight to a TUN device.
#[must_use]
pub fn build_ipv4_udp(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;

    // --- UDP header + payload (checksum computed over a pseudo-header). ---
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src.1.to_be_bytes());
    udp.extend_from_slice(&dst.1.to_be_bytes());
    udp.extend_from_slice(&u16_be(udp_len));
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);
    let udp_csum = udp_checksum(src.0, dst.0, &udp);
    let udp = splice_u16(&udp, 6, udp_csum);

    // --- IPv4 header (checksum computed over the 20-byte header). ---
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
    let ip = splice_u16(&ip, 10, ip_csum);

    let mut packet = ip;
    packet.extend_from_slice(&udp);
    packet
}

/// A `usize` (a length that fits a packet) as big-endian `u16` bytes, saturating (a jumbo payload can't
/// exceed a `u16` in a single IPv4 datagram anyway).
fn u16_be(len: usize) -> [u8; 2] {
    u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes()
}

/// Return a copy of `bytes` with the big-endian `u16` `value` written at offset `at` (used to patch a
/// checksum field after computing it over the zeroed header). Index-free.
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

/// The UDP checksum: the Internet checksum over the IPv4 pseudo-header (`src ‖ dst ‖ 0 ‖ proto ‖ udp_len`)
/// followed by the UDP header and payload. A computed `0` is transmitted as `0xFFFF` (UDP reserves `0` to
/// mean "no checksum").
fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + udp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(IPPROTO_UDP);
    buf.extend_from_slice(&u16_be(udp.len()));
    buf.extend_from_slice(udp);
    match checksum(&buf) {
        0 => 0xffff,
        c => c,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const B: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

    #[test]
    fn build_then_parse_round_trips() {
        let pkt = build_ipv4_udp((A, 40000), (B, 53), b"a dns query");
        let dg = parse_ipv4_udp(&pkt).expect("well-formed IPv4/UDP");
        assert_eq!(dg.src, (A, 40000));
        assert_eq!(dg.dst, (B, 53));
        assert_eq!(dg.payload, b"a dns query");
        // Total length field matches the packet length.
        assert_eq!(usize::from(u16::from_be_bytes([pkt[2], pkt[3]])), pkt.len());
    }

    #[test]
    fn checksums_are_valid() {
        // A receiver verifies by summing the whole header (incl. checksum) to 0 (one's complement).
        let pkt = build_ipv4_udp((A, 1234), (B, 5678), b"payload");
        assert_eq!(checksum(&pkt[..IPV4_HEADER_LEN]), 0, "IPv4 header checksum verifies");
        // UDP: recompute over the pseudo-header + UDP with the checksum in place → 0.
        let udp = &pkt[IPV4_HEADER_LEN..];
        let mut v = Vec::new();
        v.extend_from_slice(&A.octets());
        v.extend_from_slice(&B.octets());
        v.extend_from_slice(&[0, IPPROTO_UDP]);
        v.extend_from_slice(&u16_be(udp.len()));
        v.extend_from_slice(udp);
        assert_eq!(checksum(&v), 0, "UDP checksum verifies over the pseudo-header");
    }

    #[test]
    fn rejects_non_udp_fragments_and_truncation() {
        // TCP (protocol 6), not UDP.
        let mut tcp = build_ipv4_udp((A, 1), (B, 2), b"x");
        tcp[9] = 6;
        assert!(parse_ipv4_udp(&tcp).is_none(), "non-UDP is not parsed");
        // A fragment (MF flag).
        let mut frag = build_ipv4_udp((A, 1), (B, 2), b"x");
        frag[6] = 0x20; // set MF
        assert!(parse_ipv4_udp(&frag).is_none(), "a fragment is dropped");
        assert!(parse_ipv4_udp(&[0x45, 0, 0, 0]).is_none(), "a truncated packet is rejected");
        assert!(parse_ipv4_udp(&[]).is_none());
        // IPv6 (version 6).
        assert!(parse_ipv4_udp(&[0x60, 0, 0, 0]).is_none(), "IPv6 is not handled here");
    }

    #[test]
    fn empty_payload_is_valid() {
        let pkt = build_ipv4_udp((A, 100), (B, 200), b"");
        let dg = parse_ipv4_udp(&pkt).unwrap();
        assert!(dg.payload.is_empty());
        assert_eq!(pkt.len(), IPV4_HEADER_LEN + UDP_HEADER_LEN);
    }
}
