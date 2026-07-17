//! DIAULOS end-to-end over the **real** overlay: a reliable, encrypted, hybrid-PQ request/response
//! session runs between two nodes whose only transport is the production `OverlayNode` engine's
//! datagram surface (`Command::Send` → `Notification::Delivered`), driven under the simulator. This
//! is the flagship "DIAULOS becomes a working transport" milestone — the sans-I/O session logic and
//! the real node engine, composed, with nothing mocked but the wire.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_diaulos::{ClientSession, ServerSession, StaticKeypair};
use fanos_field::F2;
use fanos_pqcrypto::rng::SeedRng;
use fanos_runtime::{Command, Config, Duration, Notification};
use fanos_sim::{Sim, spawn_cell};

type Coord = [u32; 3];

/// Route every not-yet-seen overlay delivery to the client or service session it belongs to.
fn dispatch(
    sim: &Sim,
    seen: &mut usize,
    client_node: Coord,
    service_node: Coord,
    client: &mut ClientSession,
    server: &mut ServerSession,
    srng: &mut SeedRng,
) {
    let notes = &sim.report().notifications;
    for obs in &notes[*seen..] {
        if let Notification::Delivered { from, payload } = &obs.note {
            if obs.node == service_node {
                server.handle_delivery(*from, payload, srng);
            } else if obs.node == client_node {
                client.handle_delivery(*from, payload);
            }
        }
    }
    *seen = notes.len();
}

#[test]
fn diaulos_request_response_over_the_real_overlay() {
    let mut sim = Sim::new(42);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // establish liveness

    let client_node = cell[1];
    let service_node = cell[4];

    // The service's static identity (in production, published via ONOMA and resolved by the client).
    let mut krng = SeedRng::from_seed(b"e2e-key");
    let keypair = StaticKeypair::generate(&mut krng);
    let mut drng = SeedRng::from_seed(b"e2e-client");
    let mut client = ClientSession::dial(service_node, &keypair.public, &mut drng);
    let mut server = ServerSession::new(keypair);
    let mut srng = SeedRng::from_seed(b"e2e-server");

    let request = b"ping".to_vec();
    let (mut wrote, mut answered) = (false, false);
    let mut seen = 0usize;

    for _round in 0..30 {
        // client → overlay
        for cmd in client.poll_transmit() {
            sim.inject(client_node, cmd);
        }
        if client.is_live() && !wrote {
            client.write(&request);
            client.finish();
            wrote = true;
        }
        sim.run_for(Duration::from_millis(150));
        dispatch(
            &sim,
            &mut seen,
            client_node,
            service_node,
            &mut client,
            &mut server,
            &mut srng,
        );

        // service answers once the whole request has arrived.
        if let Some(sid) = server.primary()
            && !answered
            && server.receiver_finished(sid)
        {
            let req = server.read(sid);
            let mut resp = b"pong:".to_vec();
            resp.extend_from_slice(&req);
            server.write(sid, &resp);
            server.finish(sid);
            answered = true;
        }
        // service → overlay
        for cmd in server.poll_transmit() {
            sim.inject(service_node, cmd);
        }
        sim.run_for(Duration::from_millis(150));
        dispatch(
            &sim,
            &mut seen,
            client_node,
            service_node,
            &mut client,
            &mut server,
            &mut srng,
        );

        if client.is_done() {
            break;
        }
    }

    assert!(
        client.is_live(),
        "the 1-RTT handshake completed over the real overlay"
    );
    assert_eq!(
        client.read(),
        b"pong:ping",
        "the encrypted response arrived end-to-end over the datagram transport"
    );
}
