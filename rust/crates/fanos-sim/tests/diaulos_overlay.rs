//! DIAULOS end-to-end over the **real** overlay: a reliable, encrypted, hybrid-PQ request/response
//! session runs between two nodes whose only transport is the production `OverlayNode` engine's
//! datagram surface (`Command::Send` → `Notification::Delivered`), driven under the simulator. This
//! is the flagship "DIAULOS becomes a working transport" milestone — the sans-I/O session logic and
//! the real node engine, composed, with nothing mocked but the wire — and, as an **edge case**, it
//! must recover when the simulated network drops a quarter of every datagram (DIAULOS's selective
//! repeat retransmits until the whole request and response arrive).

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_diaulos::{ClientSession, ServerSession, StaticKeypair};
use fanos_field::F2;
use fanos_pqcrypto::rng::SeedRng;
use fanos_runtime::{Command, Config, Duration, Notification};
use fanos_sim::{NetworkModel, Sim, spawn_cell};

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

/// Establish a Fano cell on `sim`, then run one DIAULOS request/response (`ping` → `pong:ping`)
/// between two of its nodes over the real engine's datagram transport, allowing `rounds` pump
/// half-cycles. Returns `(handshake_completed, response_bytes)`.
fn run_request_response(mut sim: Sim, rounds: usize) -> (bool, Vec<u8>) {
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2500)); // establish liveness (generous, tolerates loss)

    let client_node = cell[1];
    let service_node = cell[4];

    let mut krng = SeedRng::from_seed(b"overlay-key");
    let keypair = StaticKeypair::generate(&mut krng);
    let service_public = keypair.public.clone();
    let mut drng = SeedRng::from_seed(b"overlay-client");
    let mut client = ClientSession::dial(service_node, &service_public, &mut drng);
    let mut server = ServerSession::new(keypair);
    let mut srng = SeedRng::from_seed(b"overlay-server");

    let request = b"ping".to_vec();
    let (mut wrote, mut answered) = (false, false);
    let mut seen = 0usize;

    for _ in 0..rounds {
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
    (client.is_live(), client.read())
}

#[test]
fn diaulos_request_response_over_the_real_overlay() {
    let (live, response) = run_request_response(Sim::new(42), 30);
    assert!(live, "the 1-RTT handshake completed over the real overlay");
    assert_eq!(
        response, b"pong:ping",
        "the encrypted response arrived end-to-end"
    );
}

#[test]
fn diaulos_recovers_under_heavy_packet_loss() {
    // A quarter of every datagram is dropped; DIAULOS's selective repeat must still deliver the
    // whole request and response (given enough retransmit rounds).
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), 0.25);
    let (live, response) = run_request_response(Sim::with_network(7, net), 120);
    assert!(live, "the handshake completed despite 25% loss");
    assert_eq!(
        response, b"pong:ping",
        "selective repeat recovered the full exchange under loss"
    );
}
