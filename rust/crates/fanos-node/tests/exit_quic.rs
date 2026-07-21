//! Clearnet **exit relay** end-to-end over the real QUIC driver: a client dials an exit node as a DIAULOS
//! service, names a clearnet `host:port`, and the exit opens a TCP connection there and splices bytes both
//! ways — so a plain TCP destination (here a loopback echo server standing in for "the internet") is
//! reached through the overlay. Proves the `exit` role's data path: `dial_exit` → `serve_exit` →
//! `TcpStream::connect` → `copy_bidirectional`, and that the [`ExitPolicy`] gates the destination.
//!
//! The relay is byte-transparent and fully interactive: the client here streams — writes then reads with
//! no half-close, as an HTTPS-CONNECT tunnel would — which the DIAULOS session now supports (the
//! flush-on-write fix in `fanos-session`/`fanos-diaulos`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::await_holding_lock)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;

use fanos_diaulos::StaticKeypair;
use fanos_field::F2;
use fanos_node::{
    Epoch, ExitParams, ExitPolicy, FanosDialer, Node, NodeConfig, Peer, RoleSet, StaticResolver,
    dial_exit, resolve_exit_key, serve_exit,
};
use fanos_pqcrypto::rng::SeedRng;
use fanos_proxy::{DialError, Dialer, Target, UdpDialer};
use fanos_runtime::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

type Coord = [u32; 3];

// Real-QUIC integration tests each bring up several loopback nodes; running them at once overloads the
// transport and stalls handshakes. Serialize them behind one blocking lock (see `diaulos_quic.rs`).
static SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

async fn start(bootstrap: Vec<Peer>) -> Node {
    Node::start::<F2>(NodeConfig {
        listen: LOOPBACK,
        bootstrap,
        ..NodeConfig::default()
    })
    .await
    .unwrap()
}

/// Start a node whose coordinate is distinct from every one in `taken` (fresh identities collide 1/7 on F2).
async fn start_distinct(bootstrap: Vec<Peer>, taken: &[Coord]) -> Node {
    loop {
        let node = start(bootstrap.clone()).await;
        if !taken.contains(&node.address()) {
            return node;
        }
        node.shutdown();
    }
}

/// Warm both QUIC directions so setup doesn't race the first handshake (the warmup byte is not a valid
/// frame — the peer ignores it).
fn warm(a: &Node, b: &Node) {
    a.command(Command::Send {
        to: b.address(),
        payload: vec![0xFF],
    });
    b.command(Command::Send {
        to: a.address(),
        payload: vec![0xFF],
    });
}

/// A loopback TCP echo server standing in for a clearnet destination; returns its bound address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind(LOOPBACK).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            if sock.write_all(buf.get(..n).unwrap_or(&[])).await.is_err() {
                                break;
                            }
                        }
                        // Clean EOF (`Ok(0)`) or any read error: the client is done, stop echoing.
                        _ => break,
                    }
                }
            });
        }
    });
    addr
}

/// A loopback UDP echo server standing in for a clearnet datagram destination (e.g. a DNS resolver);
/// returns its bound address.
async fn spawn_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind(LOOPBACK).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            if socket.send_to(buf.get(..n).unwrap_or(&[]), src).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// Bring up an exit node E and a client node C, cross-registered and warmed, plus a loopback echo server.
async fn exit_and_client() -> (Node, Node, StaticKeypair, SocketAddr) {
    let e = start(vec![]).await;
    let (e_addr, e_net) = (e.address(), e.local_addr());
    let c = start_distinct(
        vec![Peer {
            coord: e_addr,
            addr: e_net,
        }],
        &[e_addr],
    )
    .await;
    e.directory().insert(c.address(), c.local_addr());
    warm(&e, &c);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let keypair = StaticKeypair::generate(&mut SeedRng::from_seed(b"exit-quic-key"));
    let echo = spawn_echo().await;
    (e, c, keypair, echo)
}

#[tokio::test]
async fn a_client_reaches_a_clearnet_tcp_target_through_the_exit() {
    let _serial = serial();
    let (e, c, keypair, echo) = exit_and_client().await;
    let e_addr = e.address();
    let service_public = keypair.public().clone();
    serve_exit(
        e.client(),
        keypair,
        SeedRng::from_seed(b"exit-quic-svc"),
        ExitPolicy::default(),
    );

    // Dial the exit, ask it for the echo server, and round-trip a payload through it.
    let mut drng = SeedRng::from_seed(b"exit-quic-cli");
    let target = format!("127.0.0.1:{}", echo.port());
    let mut stream = dial_exit(c.client(), e_addr, &service_public, &target, &mut drng)
        .await
        .expect("dial the exit");

    // Interactive streaming: the client writes and reads with NO half-close (as an HTTPS-CONNECT tunnel
    // does), so this also exercises the DIAULOS flush-on-write fix — without it a sub-segment write is
    // never shipped until the stream closes and this would hang.
    let sent = b"through the exit to the clearnet";
    let echoed = tokio::time::timeout(Duration::from_secs(15), async {
        stream.write_all(sent).await.unwrap();
        let mut buf = vec![0u8; sent.len()];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    })
    .await
    .expect("the exit relayed the payload to the TCP target and back in time");
    assert_eq!(
        echoed, sent,
        "the payload round-tripped: client → exit → TCP echo → exit → client"
    );

    e.shutdown();
    c.shutdown();
}

#[tokio::test]
async fn the_exit_policy_refuses_a_disallowed_port() {
    let _serial = serial();
    // The exit serves a web-only policy (80/443); the echo server is on an ephemeral port, so the exit must
    // refuse to connect — the client's session closes with nothing relayed.
    let (e, c, keypair, echo) = exit_and_client().await;
    let e_addr = e.address();
    let service_public = keypair.public().clone();
    assert_ne!(echo.port(), 80, "ephemeral port is not the web port");
    serve_exit(
        e.client(),
        keypair,
        SeedRng::from_seed(b"exit-deny-svc"),
        ExitPolicy::web(),
    );

    let mut drng = SeedRng::from_seed(b"exit-deny-cli");
    let target = format!("127.0.0.1:{}", echo.port());
    let mut stream = dial_exit(c.client(), e_addr, &service_public, &target, &mut drng)
        .await
        .expect("dial the exit");

    // The exit denies the port before connecting anywhere, so it relays nothing and closes: the client
    // reads EOF (no echo). Also confirm the echo server itself never received a connection.
    let got = tokio::time::timeout(Duration::from_secs(10), async {
        stream.write_all(b"should not pass").await.ok();
        stream.shutdown().await.ok();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.ok();
        buf
    })
    .await
    .expect("the denied session closed in time");
    assert!(
        got.is_empty(),
        "a policy-denied target relays nothing (got {} bytes)",
        got.len()
    );
    // The forbidden destination was never dialed: connecting to it now still succeeds instantly (the echo
    // server has no pending/served connection from the exit to interfere with).
    assert!(
        TcpStream::connect(echo).await.is_ok(),
        "the echo server is still only reachable directly — the exit never dialed it"
    );

    e.shutdown();
    c.shutdown();
}

#[tokio::test]
async fn an_exit_advertises_itself_and_is_discovered() {
    let _serial = serial();
    // An exit node publishes its descriptor to the overlay store on startup; the live exit directory
    // discovers it — the auto-discovery half that lets a proxy find an exit with no hand-configured file.
    let seed = [0x7e; 32];
    let node = Node::start::<F2>(NodeConfig {
        listen: LOOPBACK,
        roles: RoleSet {
            exit: true,
            ..RoleSet::default()
        },
        exit: Some(ExitParams {
            seed,
            allowed_ports: Vec::new(),
        }),
        ..NodeConfig::default()
    })
    .await
    .unwrap();

    let expected = StaticKeypair::generate(&mut SeedRng::from_seed(&seed))
        .public()
        .clone();
    // The publish is async (through the store); resolve the exit's own slot (which `build_cell_exit_
    // directory` scans over the cell roster) until it appears. Resolving the node's own coordinate is a
    // fast local store hit — unlike an empty peer slot on this lone node, which has no live responder.
    let client = node.client();
    let coord = node.address();
    let found = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(public) = resolve_exit_key(&client, coord, Epoch::ZERO).await {
                return public;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the exit advertised its descriptor to the store");

    assert_eq!(
        found.encode(),
        expected.encode(),
        "the discovered key is the exit's seed-derived service public key"
    );
    node.shutdown();
}

#[tokio::test]
async fn the_proxy_dialer_reaches_clearnet_through_the_exit() {
    let _serial = serial();
    // The full proxy path: a `FanosDialer` configured with an exit dials a CLEARNET target (the echo
    // server) through it — the seam a SOCKS5/HTTP-CONNECT proxy uses for non-`.fanos` destinations.
    let (e, c, keypair, echo) = exit_and_client().await;
    let e_addr = e.address();
    let e_public = keypair.public().clone();
    serve_exit(
        e.client(),
        keypair,
        SeedRng::from_seed(b"exit-dialer-svc"),
        ExitPolicy::default(),
    );

    // A `.fanos`-resolving dialer (empty resolver — we only test clearnet) that routes clearnet via the exit.
    let dialer = FanosDialer::new(c.client(), StaticResolver::new()).with_exit(e_addr, e_public);
    let mut stream = dialer
        .dial(&Target::Ip(echo))
        .await
        .expect("the dialer reached the clearnet target through the exit");

    let sent = b"proxy dialer -> exit -> clearnet";
    let echoed = tokio::time::timeout(Duration::from_secs(15), async {
        stream.write_all(sent).await.unwrap();
        let mut buf = vec![0u8; sent.len()];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    })
    .await
    .expect("round-trip through the dialer's exit path");
    assert_eq!(echoed, sent, "clearnet round-trip via the proxy dialer's exit");

    // Without an exit configured, the same clearnet target is refused (a `.fanos`-only dialer).
    let no_exit = FanosDialer::new(c.client(), StaticResolver::new());
    assert!(
        matches!(no_exit.dial(&Target::Ip(echo)).await, Err(DialError::Unsupported(_))),
        "a dialer with no exit refuses a clearnet target"
    );

    e.shutdown();
    c.shutdown();
}

#[tokio::test]
async fn the_proxy_dialer_relays_udp_through_the_exit() {
    let _serial = serial();
    // The UDP counterpart of the clearnet path: a `FanosDialer` with an exit opens a datagram tunnel to a
    // clearnet UDP target (a loopback echo standing in for a DNS resolver) — the seam SOCKS5 UDP ASSOCIATE
    // and DNS-over-FANOS ride. Proves `dial_udp` → `dial_exit_udp` → `serve_exit`'s `relay_udp` → real UDP
    // socket and back.
    let (e, c, keypair, _tcp_echo) = exit_and_client().await;
    let e_addr = e.address();
    let e_public = keypair.public().clone();
    serve_exit(
        e.client(),
        keypair,
        SeedRng::from_seed(b"exit-udp-svc"),
        ExitPolicy::default(),
    );
    let udp_echo = spawn_udp_echo().await;

    let dialer = FanosDialer::new(c.client(), StaticResolver::new()).with_exit(e_addr, e_public);
    let mut tunnel = tokio::time::timeout(Duration::from_secs(15), dialer.dial_udp(&Target::Ip(udp_echo)))
        .await
        .expect("open the UDP tunnel in time")
        .expect("the dialer opened a UDP tunnel through the exit");

    // Two datagrams each round-trip: client → exit → UDP echo → exit → client.
    for payload in [b"a dns query".as_slice(), b"and a second datagram".as_slice()] {
        tunnel.outbound.send(payload.to_vec()).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(15), tunnel.inbound.recv())
            .await
            .expect("a datagram comes back in time")
            .expect("the tunnel is still open");
        assert_eq!(echoed, payload, "the datagram round-tripped through the exit's UDP relay");
    }

    // A `.fanos` name has no UDP form, and a dialer with no exit refuses clearnet UDP.
    assert!(
        matches!(
            dialer.dial_udp(&Target::Name("svc.fanos".into(), 53)).await,
            Err(DialError::Unsupported(_))
        ),
        ".fanos targets are byte-stream only — no UDP form"
    );
    let no_exit = FanosDialer::new(c.client(), StaticResolver::new());
    assert!(
        matches!(no_exit.dial_udp(&Target::Ip(udp_echo)).await, Err(DialError::Unsupported(_))),
        "a dialer with no exit refuses clearnet UDP"
    );

    e.shutdown();
    c.shutdown();
}
