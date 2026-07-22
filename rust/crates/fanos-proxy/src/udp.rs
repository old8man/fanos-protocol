//! SOCKS5 **UDP ASSOCIATE** (RFC 1928 §7) — the datagram relay path.
//!
//! Where CONNECT tunnels a byte stream, UDP ASSOCIATE tunnels datagrams. The client opens a TCP *control*
//! connection with `CMD = UDP ASSOCIATE`; the proxy binds a UDP *relay* socket and returns its address
//! (`BND`). The client then sends each datagram to that socket wrapped in a SOCKS5 UDP request header —
//!
//! ```text
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//! ```
//!
//! The proxy strips the header, opens (or reuses) a [`UdpTunnel`] to that destination through the
//! [`UdpDialer`], and forwards the payload; each reply is wrapped in the same header form (naming the
//! source) and sent back to the client's address. One association multiplexes many destinations — a tunnel
//! per distinct `DST` — and lives exactly as long as the control connection: when it closes, every tunnel
//! drops (RFC 1928 §7). **DNS-over-FANOS** falls out for free — a resolver query is just a datagram to
//! `host:53`.
//!
//! Robustness choices: fragmented datagrams (`FRAG != 0`) are dropped (we do not reassemble); the client's
//! UDP source address is *latched* on its first datagram, and datagrams from any other source are ignored
//! (a local proxy has exactly one client per association); a backed-up tunnel drops rather than stalls
//! (UDP's own delivery model).

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::dialer::UdpDialer;
use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, REP_SUCCESS, VER};
use crate::target::Target;

/// The largest datagram the relay socket reads — the SOCKS5 header plus payload. A UDP datagram carries at
/// most 65535 bytes total, so this bounds the whole wrapped frame.
const MAX_UDP: usize = 65535;

/// Cap on the distinct destinations one association relays to concurrently (audit A4: bound every per-flow
/// map). A client addressing many destinations (a UDP scanner, a DHT) would otherwise grow the tunnel map —
/// and its exit dials — without limit; at the cap the least-recently-used tunnel is evicted (dropping its
/// sender tears it down). Matches the DIAULOS `MAX_SESSIONS` discipline.
const MAX_UDP_FLOWS: usize = 1024;

/// An exit tunnel plus its last-use time, so the least-recently-used can be evicted at the cap.
struct Flow {
    outbound: mpsc::Sender<Vec<u8>>,
    last_used: Instant,
}

/// Evict the least-recently-used flow (called when the map is at [`MAX_UDP_FLOWS`]); dropping its sender
/// closes the exit tunnel and ends its reply pump.
fn evict_lru(tunnels: &mut HashMap<Target, Flow>) {
    if let Some(victim) = tunnels
        .iter()
        .min_by_key(|(_, f)| f.last_used)
        .map(|(t, _)| t.clone())
    {
        tunnels.remove(&victim);
    }
}

/// Run one SOCKS5 UDP association on its already-negotiated control connection, relaying datagrams through
/// `dialer` until the control connection closes.
///
/// # Errors
/// Propagates I/O errors from binding the relay socket or writing the reply; a per-datagram failure (bad
/// header, undialable destination) is dropped, never returned — matching UDP's own delivery model.
pub async fn associate<D: UdpDialer>(mut control: TcpStream, dialer: &D) -> io::Result<()> {
    // Bind the relay on the same local IP the control connection arrived on, so the address we hand back is
    // one the client can reach; an ephemeral port.
    let local_ip = control.local_addr()?.ip();
    let relay = Arc::new(UdpSocket::bind((local_ip, 0)).await?);
    write_associate_reply(&mut control, relay.local_addr()?).await?;

    // One outbound tunnel per distinct destination the client addresses (bounded, LRU-evicted).
    let mut tunnels: HashMap<Target, Flow> = HashMap::new();
    // The client's UDP source, latched on its first datagram (a local proxy serves one client per assoc).
    let mut client_addr: Option<SocketAddr> = None;
    let mut buf = vec![0u8; MAX_UDP];
    let mut ctrl = [0u8; 256];

    loop {
        tokio::select! {
            // The control connection closing (or erroring) ends the association (RFC 1928 §7). Any bytes
            // the client writes on it carry no SOCKS meaning here and are ignored.
            r = control.read(&mut ctrl) => {
                if matches!(r, Ok(0) | Err(_)) {
                    break;
                }
            }
            r = relay.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                match client_addr {
                    None => client_addr = Some(src),
                    Some(addr) if addr != src => continue, // ignore datagrams from any other source
                    Some(_) => {}
                }
                let Some(client) = client_addr else { continue };
                let Some((target, payload)) = parse_request(buf.get(..n).unwrap_or(&[])) else {
                    continue;
                };
                // Open a tunnel to this destination on first sight (and re-open if a prior one closed),
                // evicting the least-recently-used tunnel first if the map is at its cap.
                if tunnels.get(&target).is_none_or(|f| f.outbound.is_closed()) {
                    let Ok(tunnel) = dialer.dial_udp(&target).await else { continue };
                    if tunnels.len() >= MAX_UDP_FLOWS {
                        evict_lru(&mut tunnels);
                    }
                    spawn_reply_pump(Arc::clone(&relay), tunnel.inbound, target.clone(), client);
                    tunnels.insert(target.clone(), Flow { outbound: tunnel.outbound, last_used: Instant::now() });
                }
                if let Some(flow) = tunnels.get_mut(&target) {
                    flow.last_used = Instant::now();
                    // UDP is lossy: if the tunnel is backed up, drop rather than stall the association.
                    let _ = flow.outbound.try_send(payload);
                }
            }
        }
    }
    Ok(())
}

/// Pump one destination's replies back to the client: wrap each inbound datagram in a SOCKS5 UDP header
/// naming `source` and send it to the client's latched address. Ends when the tunnel closes.
fn spawn_reply_pump(
    relay: Arc<UdpSocket>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    source: Target,
    client: SocketAddr,
) {
    tokio::spawn(async move {
        while let Some(data) = inbound.recv().await {
            let Some(framed) = encode_reply(&source, &data) else { continue };
            if relay.send_to(&framed, client).await.is_err() {
                break;
            }
        }
    });
}

/// Send the SOCKS5 reply to a UDP ASSOCIATE request: success, with `BND` = the relay socket the client
/// sends its datagrams to.
async fn write_associate_reply(control: &mut TcpStream, bnd: SocketAddr) -> io::Result<()> {
    let mut reply = vec![VER, REP_SUCCESS, 0x00];
    push_addr(&mut reply, &Target::Ip(bnd)); // a socket address never overflows the header
    control.write_all(&reply).await
}

/// Parse a client UDP request datagram (`RSV FRAG ATYP DST.ADDR DST.PORT DATA`) into its destination and
/// payload. `None` if the header is malformed or fragmented (`FRAG != 0` — we do not reassemble).
fn parse_request(dg: &[u8]) -> Option<(Target, Vec<u8>)> {
    let mut c = Cursor::new(dg);
    let _rsv = c.take(2)?;
    if c.u8()? != 0 {
        return None; // only standalone datagrams; fragments are dropped
    }
    let target = match c.u8()? {
        ATYP_IPV4 => Target::Ip(SocketAddr::from((Ipv4Addr::from(c.array::<4>()?), c.u16()?))),
        ATYP_IPV6 => Target::Ip(SocketAddr::from((Ipv6Addr::from(c.array::<16>()?), c.u16()?))),
        ATYP_DOMAIN => {
            let len = usize::from(c.u8()?);
            let host = std::str::from_utf8(c.take(len)?).ok()?.to_owned();
            Target::Name(host, c.u16()?)
        }
        _ => return None,
    };
    Some((target, c.rest().to_vec()))
}

/// Wrap a datagram received from `source` in a SOCKS5 UDP reply header for the client. `None` only if a
/// domain source name exceeds the 255-byte header field (unreachable for a target parsed from a request).
fn encode_reply(source: &Target, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8, 0, 0]; // RSV(2) = 0, FRAG = 0
    push_addr(&mut out, source)?;
    out.extend_from_slice(data);
    Some(out)
}

/// Append `ATYP ‖ ADDR ‖ PORT` for `target` to `buf`. `None` only if a domain name exceeds 255 bytes.
fn push_addr(buf: &mut Vec<u8>, target: &Target) -> Option<()> {
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Name(host, port) => {
            let len = u8::try_from(host.len()).ok()?;
            buf.push(ATYP_DOMAIN);
            buf.push(len);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    Some(())
}

/// A minimal forward-only byte cursor for header parsing — every read is bounds-checked to `None`, so no
/// indexing can panic on a truncated datagram.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    fn u16(&mut self) -> Option<u16> {
        self.array::<2>().map(u16::from_be_bytes)
    }

    fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_ipv4_request() {
        // RSV=0 FRAG=0 ATYP=1 9.9.9.9 :53  DATA="qry"
        let dg = [0, 0, 0, 1, 9, 9, 9, 9, 0, 53, b'q', b'r', b'y'];
        let (target, payload) = parse_request(&dg).unwrap();
        assert_eq!(target, Target::Ip("9.9.9.9:53".parse().unwrap()));
        assert_eq!(payload, b"qry");
    }

    #[test]
    fn parses_a_domain_request() {
        let mut dg = vec![0, 0, 0, ATYP_DOMAIN, 9];
        dg.extend_from_slice(b"host.test");
        dg.extend_from_slice(&443u16.to_be_bytes());
        dg.extend_from_slice(b"payload");
        let (target, payload) = parse_request(&dg).unwrap();
        assert_eq!(target, Target::Name("host.test".into(), 443));
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn rejects_fragments_and_truncation() {
        assert!(parse_request(&[0, 0, 1, 1, 9, 9, 9, 9, 0, 53]).is_none(), "FRAG != 0 is dropped");
        assert!(parse_request(&[0, 0, 0, 1, 9, 9]).is_none(), "truncated address");
        assert!(parse_request(&[0, 0, 0, 9, 1, 2]).is_none(), "unknown ATYP");
        assert!(parse_request(&[]).is_none(), "empty datagram");
    }

    #[test]
    fn reply_header_round_trips_through_the_parser() {
        // A reply naming an IPv4 source parses back to the same target with the payload intact.
        let source = Target::Ip("1.2.3.4:80".parse().unwrap());
        let framed = encode_reply(&source, b"body").unwrap();
        let (target, payload) = parse_request(&framed).unwrap();
        assert_eq!(target, source);
        assert_eq!(payload, b"body");
    }

    #[test]
    fn reply_header_preserves_a_domain_source() {
        let source = Target::Name("resolver.test".into(), 53);
        let framed = encode_reply(&source, b"answer").unwrap();
        let (target, payload) = parse_request(&framed).unwrap();
        assert_eq!(target, source);
        assert_eq!(payload, b"answer");
    }

    #[test]
    fn evict_lru_drops_the_least_recently_used_flow() {
        use std::time::Duration;

        let now = Instant::now();
        let mk = |secs_ago| Flow {
            outbound: mpsc::channel::<Vec<u8>>(1).0,
            last_used: now.checked_sub(Duration::from_secs(secs_ago)).unwrap(),
        };
        let (a, b, c) = (
            Target::Ip("1.1.1.1:1".parse().unwrap()),
            Target::Ip("2.2.2.2:2".parse().unwrap()),
            Target::Ip("3.3.3.3:3".parse().unwrap()),
        );
        let mut tunnels: HashMap<Target, Flow> = HashMap::new();
        tunnels.insert(a.clone(), mk(1)); // newest
        tunnels.insert(b.clone(), mk(30)); // oldest — the LRU victim
        tunnels.insert(c.clone(), mk(5));

        evict_lru(&mut tunnels);

        assert_eq!(tunnels.len(), 2, "exactly one flow is evicted");
        assert!(!tunnels.contains_key(&b), "the least-recently-used flow is evicted");
        assert!(tunnels.contains_key(&a) && tunnels.contains_key(&c), "the newer flows are kept");
    }
}
