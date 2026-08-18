//! **The service role a deployment actually runs** — the outermost-but-one branch of `compose_engine`.
//!
//! `threshold_service_live.rs` stands up a line of bare `ThresholdService` engines, which is the right way to
//! test the threshold protocol and cannot test the composition: in isolation there is nothing underneath for a
//! frame to be dispatched *past*. `composition.rs:261` builds something different — a `ServiceNode` wrapping
//! the cell engine, so one coordinate both serves its line and stays a full cell member. Nothing stood that up
//! (#180): `service: Some(..)` appeared nowhere in this crate.
//!
//! The claim is a DISPATCH claim, and it has two sides. An intro must reach the service **while** the cell
//! engine underneath keeps running — a composite that swallowed everything would satisfy a one-sided test
//! perfectly. So both are asserted on the same run, and the control is the identical cell with `service: None`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use fanos_calypso::hosting::SealedIntro;
use fanos_field::F2;
use fanos_geometry::{Line, Plane, Point, Triple};
use fanos_node::composition::{CellComposition, compose_engine};
use fanos_node::intro_frame;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_runtime::{Command, Config, Duration};
use fanos_wire::{FrameType, encode_frame};
use fanos_sim::Sim;

/// The anonymous-source sentinel a surfaced request carries — the service never learns who delivered it.
const ANON: Triple = [0, 0, 0];

/// `t`-of-`(q+1)`: a Fano line holds three points and two must cooperate. Not 1: a 1-of-n line inverts the
/// claim hosting makes, and `ThresholdService` refuses it (audit #63).
const THRESHOLD: usize = 2;

/// The service member seed for the node at Fano point `i`.
///
/// Distinct per member for the same reason a relay's onion seeds are: one seed for the whole line would make
/// every share openable by the same secret, which is the property thresholding exists to remove.
fn service_seed(i: usize) -> [u8; 32] {
    let mut s = [0x5Eu8; 32];
    s[31] = i as u8;
    s
}

/// The public matching [`service_seed`], derived exactly as `compose_engine` derives the secret from it
/// (`composition.rs:265`). A client seals to these; if the two derivations ever part, the intro stops opening.
fn service_public(i: usize) -> HybridKemPublic {
    let (_secret, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&service_seed(i)));
    public
}

/// A whole Fano cell, with the three points of line 0 additionally composed as a service line.
///
/// Returns the line's coordinates in seal order. `hosting` switches the service role off for the control run
/// and changes nothing else — the same seven engines, the same seeds, the same seed for the `Sim`.
fn spawn_service_cell(sim: &mut Sim, hosting: bool) -> Vec<Triple> {
    let line: Vec<Triple> = Plane::<F2>::points_on(Line::<F2>::at(0)).map(|p| p.coords()).collect();
    assert_eq!(line.len(), 3, "a Fano line holds q+1 = 3 points");

    for point in Plane::<F2>::points() {
        let mut what = CellComposition::overlay_only(Config {
            heartbeat: Duration::from_millis(500),
            liveness_timeout: Duration::from_millis(1600),
            ..Config::default()
        });
        if hosting && let Some(seat) = line.iter().position(|&c| c == point.coords()) {
            // `None`: this scenario proves half (b) — the line reads no intro alone. Custody of the
            // signing identity (half (a)) is a separate deployment choice and has its own coverage.
            what.service = Some((service_seed(seat), line.clone(), THRESHOLD, None));
        }
        sim.add(compose_engine::<F2>(point, &what, None));
    }
    line
}

/// Seal a request to the whole line, as a client with only the published publics would.
fn sealed(request: &[u8], seed: &[u8]) -> SealedIntro {
    let pubs: Vec<HybridKemPublic> = (0..3).map(service_public).collect();
    let refs: Vec<&HybridKemPublic> = pubs.iter().collect();
    SealedIntro::seal(request, THRESHOLD as u8, &refs, seed).expect("sealed to the line")
}

/// A plain overlay `Route` frame: the cell engine surfaces its body as `Notification::Delivered`
/// (`overlay/mod.rs:785`). This is the traffic a `ServiceNode` must pass DOWN rather than answer.
fn route_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    encode_frame(FrameType::Route.code(), payload, &mut f);
    f
}

/// Both halves of the dispatch, on ONE coordinate, told apart by who the delivery says it came from: an
/// ordinary `Route` surfaces attributed to the sender, a served intro surfaces from [`ANON`] because the
/// service never learns who delivered it.
#[test]
fn a_composed_service_member_serves_its_line_and_still_carries_the_cells_traffic() {
    let request = b"served by a node that is also a cell member".to_vec();
    let ordinary = b"ordinary overlay traffic".to_vec();
    let client = Point::<F2>::at(6).coords();

    let mut sim = Sim::new(0x5E12);
    let line = spawn_service_cell(&mut sim, true);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));

    // SIDE ONE — a plain frame to the service-carrying coordinate reaches the CELL ENGINE underneath.
    //
    // This replaced an earlier `reporting == 7` assertion that could not fail: probing it by crashing a
    // service member left the count at seven, because `reporting` is sensitive to whether a node HAS a cell
    // roster, not to whether it is still processing traffic. A guard that does not fire when you break the
    // thing it watches is not evidence ([[a-silent-guard-is-not-evidence]]).
    sim.inject_frame(client, line[0], route_frame(&ordinary));
    sim.run_for(Duration::from_millis(500));
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == line[0] && from == client && bytes == ordinary.as_slice()),
        "the `ServiceNode` wrapper must pass a non-intro frame to the engine it wraps — a composite that \
         answered everything itself would swallow this one"
    );

    // SIDE TWO — the intro reaches the service half, and the line cooperates at threshold.
    sim.inject_frame(client, line[0], intro_frame(&sealed(&request, b"composed-intro")));
    sim.run_for(Duration::from_millis(2000));
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == line[0] && from == ANON && bytes == request.as_slice()),
        "the composed line gathered {THRESHOLD} partials and surfaced the request at its combiner"
    );

    // AND THEY WENT TO DIFFERENT HALVES. The intro's plaintext must never surface attributed to the client:
    // that would mean the overlay handled it as ordinary traffic and the dispatch is one-way after all.
    assert!(
        !sim.report()
            .deliveries()
            .any(|(_, from, bytes)| from == client && bytes == request.as_slice()),
        "a served request must surface anonymously; attributed to its sender means the service half never \
         saw it and the cell engine delivered the intro verbatim"
    );
}

/// The control, and the reason the test above is not vacuous.
///
/// The identical cell with `service: None` — same seven coordinates, same `Sim` seed, same client, same
/// sealed intro. The ordinary frame must still land (nothing about the cell changed) and the intro must NOT
/// be served (there is no service half to dispatch it to). Without this, the positive case would pass against
/// a composition that ignored `service` entirely, which is the state #180 found the simulator in.
#[test]
fn the_same_cell_without_the_service_role_carries_traffic_but_cannot_serve() {
    let request = b"served by a node that is also a cell member".to_vec();
    let ordinary = b"ordinary overlay traffic".to_vec();
    let client = Point::<F2>::at(6).coords();

    let mut sim = Sim::new(0x5E12);
    let line = spawn_service_cell(&mut sim, false);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));
    sim.inject_frame(client, line[0], route_frame(&ordinary));
    sim.inject_frame(client, line[0], intro_frame(&sealed(&request, b"composed-intro")));
    sim.run_for(Duration::from_millis(2000));

    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == line[0] && from == client && bytes == ordinary.as_slice()),
        "the control's cell engine carries ordinary traffic exactly as the hosting run's does — the two \
         differ in the service role ALONE"
    );
    assert!(
        !sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == line[0] && from == ANON && bytes == request.as_slice()),
        "a cell with no service role must not surface an intro — if it does, the anonymous delivery the \
         positive test watches comes from somewhere other than the composed `ThresholdService`"
    );
}
