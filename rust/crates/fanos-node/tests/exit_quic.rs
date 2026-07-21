//! Clearnet **exit relay** end-to-end over the real QUIC driver: a client dials an exit node as a DIAULOS
//! service, names a clearnet `host:port`, and the exit opens a TCP connection there and splices bytes both
//! ways — so a plain TCP destination (here a loopback echo server standing in for "the internet") is
//! reached through the overlay. Proves the `exit` role's data path: `dial_exit` → `serve_exit` →
//! `TcpStream::connect` → `copy_bidirectional`, and that the [`ExitPolicy`] gates the destination.
//!
//! The client sends its request and half-closes its send side, then reads the reply — the request →
//! response shape the DIAULOS session delivers today (see `exit.rs` "Session shape"); the relay itself is
//! byte-transparent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::await_holding_lock)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;

use fanos_diaulos::StaticKeypair;
use fanos_field::F2;
use fanos_node::{ExitPolicy, Node, NodeConfig, Peer, dial_exit, serve_exit};
use fanos_pqcrypto::rng::SeedRng;
use fanos_runtime::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

    let sent = b"through the exit to the clearnet";
    let echoed = tokio::time::timeout(Duration::from_secs(15), async {
        stream.write_all(sent).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
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
