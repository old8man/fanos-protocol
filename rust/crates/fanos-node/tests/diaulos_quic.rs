//! DIAULOS end-to-end over the **real QUIC driver**: a reliable, encrypted, hybrid-PQ request/
//! response session between two live nodes on loopback sockets. The client dials the service's
//! coordinate ([`dial_service`]) and the service answers over a single-client accept loop
//! ([`serve_one`]) — the base overlay's `Command::Send`/`Notification::Delivered` carrying the
//! DIAULOS handshake and cells across actual UDP. This is the Direct-profile "SOCKS5→service pipe"
//! working on the production transport (the sim covers the same path deterministically).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use fanos_diaulos::StaticKeypair;
use fanos_field::F2;
use fanos_node::{Node, NodeConfig, Peer, dial_service, serve_one};
use fanos_pqcrypto::rng::SeedRng;
use fanos_runtime::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// The Direct-profile DIAULOS path on the production QUIC driver: a full encrypted request/response
// over real sockets between two live nodes at *distinct* cell coordinates. (An earlier version was
// flaky until the root cause was found: two fresh identities collide on the same Fano point 1/7 of
// the time, making the coordinate→node mapping ambiguous and breaking routing — the node setup below
// now enforces distinct coordinates, the real cell invariant.)
#[tokio::test]
async fn diaulos_request_response_over_quic() {
    let loopback = SocketAddr::from(([127, 0, 0, 1], 0));

    // A = service, B = client (the two-node bootstrap pattern).
    let a = Node::start::<F2>(NodeConfig {
        listen: loopback,
        ..NodeConfig::default()
    })
    .await
    .unwrap();
    let a_addr = a.address();
    let a_net = a.local_addr();

    // A cell's members must occupy *distinct* projective points. A node's coordinate is derived from
    // its identity, so two fresh identities collide on the same Fano point with probability 1/7 —
    // start the client until it lands on a point different from the service's (modelling the
    // real invariant that cell slots are assigned distinctly; a collision otherwise makes the
    // coordinate→node mapping ambiguous and routing between them breaks).
    let mut b = Node::start::<F2>(NodeConfig {
        listen: loopback,
        bootstrap: vec![Peer {
            coord: a_addr,
            addr: a_net,
        }],
        ..NodeConfig::default()
    })
    .await
    .unwrap();
    while b.address() == a_addr {
        b.shutdown();
        b = Node::start::<F2>(NodeConfig {
            listen: loopback,
            bootstrap: vec![Peer {
                coord: a_addr,
                addr: a_net,
            }],
            ..NodeConfig::default()
        })
        .await
        .unwrap();
    }
    // A learns how to reach B (so it can send the DIAULOS reply path).
    a.directory().insert(b.address(), b.local_addr());

    // Warm both QUIC connection directions before the multi-round-trip handshake, so connection
    // setup doesn't race the first hellos (a warmup payload is not a valid frame — it is ignored).
    b.command(Command::Send {
        to: a_addr,
        payload: vec![0xFF],
    });
    a.command(Command::Send {
        to: b.address(),
        payload: vec![0xFF],
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The service's static identity + a single-client accept loop that answers uppercased.
    let mut krng = SeedRng::from_seed(b"quic-diaulos-key");
    let keypair = StaticKeypair::generate(&mut krng);
    let service_public = keypair.public.clone();
    serve_one(
        a.client(),
        keypair,
        SeedRng::from_seed(b"quic-diaulos-svc"),
        <[u8]>::to_ascii_uppercase,
    );

    // B dials A over DIAULOS and runs a request/response through the async stream.
    let mut drng = SeedRng::from_seed(b"quic-diaulos-cli");
    let mut stream = dial_service(b.client(), a_addr, &service_public, &mut drng);

    let response = tokio::time::timeout(Duration::from_secs(15), async {
        stream.write_all(b"quic diaulos").await.unwrap();
        stream.shutdown().await.unwrap(); // end of request
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        buf
    })
    .await
    .expect("DIAULOS request/response over QUIC completed in time");

    assert_eq!(
        response, b"QUIC DIAULOS",
        "the encrypted response arrived end-to-end over the real QUIC transport"
    );

    a.shutdown();
    b.shutdown();
}
