//! DIAULOS end-to-end over the **real QUIC driver**: reliable, encrypted, hybrid-PQ request/response
//! sessions between live nodes on loopback sockets. Clients dial the service's coordinate
//! ([`dial_service`]) and the service answers over the multi-client accept loop ([`serve`]) — the
//! base overlay's `Command::Send`/`Notification::Delivered` carrying the DIAULOS handshake and cells
//! across actual UDP. This is the Direct-profile "SOCKS5→service pipe" on the production transport
//! (the sim covers the same path deterministically). Cell members are placed at *distinct*
//! coordinates: a node's point derives from its identity, so two fresh identities collide 1/7 of the
//! time (F2), which would make the coordinate→node mapping ambiguous and break routing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use fanos_diaulos::StaticKeypair;
use fanos_field::F2;
use fanos_node::{FanosDialer, Node, NodeConfig, Peer, StaticResolver, dial_service, serve};
use fanos_pqcrypto::rng::SeedRng;
use fanos_proxy::{DialError, Dialer, Target};
use fanos_runtime::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

type Coord = [u32; 3];

const LOOPBACK: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

async fn start(bootstrap: Vec<Peer>) -> Node {
    Node::start::<F2>(NodeConfig {
        listen: LOOPBACK,
        bootstrap,
        ..NodeConfig::default()
    })
    .await
    .unwrap()
}

/// Start a node whose coordinate is distinct from every one in `taken` (the cell invariant that
/// members occupy distinct points; fresh identities otherwise collide 1/7 of the time).
async fn start_distinct(bootstrap: Vec<Peer>, taken: &[Coord]) -> Node {
    loop {
        let node = start(bootstrap.clone()).await;
        if !taken.contains(&node.address()) {
            return node;
        }
        node.shutdown();
    }
}

/// Warm both QUIC connection directions so setup doesn't race the first handshake hellos (a warmup
/// payload is not a valid frame — the peer ignores it).
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

/// One request/response over a dialed stream: write `request`, signal end, read the whole response.
async fn exchange(stream: &mut DuplexStream, request: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(15), async {
        stream.write_all(request).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        buf
    })
    .await
    .expect("DIAULOS exchange over QUIC completed in time")
}

#[tokio::test]
async fn diaulos_request_response_over_quic() {
    let a = start(vec![]).await; // service
    let (a_addr, a_net) = (a.address(), a.local_addr());
    let b = start_distinct(
        vec![Peer {
            coord: a_addr,
            addr: a_net,
        }],
        &[a_addr],
    )
    .await; // client
    a.directory().insert(b.address(), b.local_addr());
    warm(&a, &b);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut krng = SeedRng::from_seed(b"quic-diaulos-key");
    let keypair = StaticKeypair::generate(&mut krng);
    let service_public = keypair.public.clone();
    serve(
        a.client(),
        keypair,
        SeedRng::from_seed(b"quic-diaulos-svc"),
        <[u8]>::to_ascii_uppercase,
    );

    let mut drng = SeedRng::from_seed(b"quic-diaulos-cli");
    let mut stream = dial_service(b.client(), a_addr, &service_public, &mut drng);
    let response = exchange(&mut stream, b"quic diaulos").await;
    assert_eq!(
        response, b"QUIC DIAULOS",
        "the encrypted response arrived end-to-end over the real QUIC transport"
    );

    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn diaulos_serves_two_clients_concurrently() {
    // One service, two distinct clients — proving the multi-client accept loop (a session per client
    // coordinate, one shared identity) delivers each client its own answer at the same time.
    let s = start(vec![]).await;
    let (s_addr, s_net) = (s.address(), s.local_addr());
    let boot = vec![Peer {
        coord: s_addr,
        addr: s_net,
    }];
    let c1 = start_distinct(boot.clone(), &[s_addr]).await;
    let c2 = start_distinct(boot.clone(), &[s_addr, c1.address()]).await;
    s.directory().insert(c1.address(), c1.local_addr());
    s.directory().insert(c2.address(), c2.local_addr());
    warm(&s, &c1);
    warm(&s, &c2);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut krng = SeedRng::from_seed(b"quic-multi-key");
    let keypair = StaticKeypair::generate(&mut krng);
    let service_public = keypair.public.clone();
    // Echo the request with an `echo:` prefix.
    serve(
        s.client(),
        keypair,
        SeedRng::from_seed(b"quic-multi-svc"),
        |req| {
            let mut v = b"echo:".to_vec();
            v.extend_from_slice(req);
            v
        },
    );

    let mut r1 = SeedRng::from_seed(b"quic-multi-c1");
    let mut r2 = SeedRng::from_seed(b"quic-multi-c2");
    let mut st1 = dial_service(c1.client(), s_addr, &service_public, &mut r1);
    let mut st2 = dial_service(c2.client(), s_addr, &service_public, &mut r2);

    let (resp1, resp2) = tokio::join!(exchange(&mut st1, b"one"), exchange(&mut st2, b"two"));
    assert_eq!(resp1, b"echo:one", "client 1 got its own answer");
    assert_eq!(resp2, b"echo:two", "client 2 got its own answer");

    s.shutdown();
    c1.shutdown();
    c2.shutdown();
}

#[tokio::test]
async fn fanos_dialer_reaches_a_service_by_name() {
    // The full SOCKS5→.fanos seam: a FanosDialer resolves a name to the service's coordinate + key
    // (here a StaticResolver) and returns a connected DIAULOS stream through the Dialer trait.
    let a = start(vec![]).await; // service
    let (a_addr, a_net) = (a.address(), a.local_addr());
    let b = start_distinct(
        vec![Peer {
            coord: a_addr,
            addr: a_net,
        }],
        &[a_addr],
    )
    .await; // client
    a.directory().insert(b.address(), b.local_addr());
    warm(&a, &b);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut krng = SeedRng::from_seed(b"fd-key");
    let keypair = StaticKeypair::generate(&mut krng);
    let service_public = keypair.public.clone();
    serve(
        a.client(),
        keypair,
        SeedRng::from_seed(b"fd-svc"),
        <[u8]>::to_ascii_uppercase,
    );

    let resolver = StaticResolver::new().with("svc.fanos", a_addr, service_public);
    let dialer = FanosDialer::new(b.client(), resolver);

    let mut stream = dialer
        .dial(&Target::Name("svc.fanos".to_owned(), 80))
        .await
        .expect("dial by name");
    let response = exchange(&mut stream, b"via dialer").await;
    assert_eq!(
        response, b"VIA DIALER",
        "reached the service through the SOCKS5 Dialer"
    );

    // A non-.fanos target is refused as unsupported.
    let clear = dialer
        .dial(&Target::Name("example.com".to_owned(), 443))
        .await;
    assert!(matches!(clear, Err(DialError::Unsupported(_))));

    a.shutdown();
    b.shutdown();
}
