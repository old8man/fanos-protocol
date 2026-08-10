//! **An established cell, then one arrival** — the scenario shape no harness had (#235).
//!
//! Every simulator scenario and every e2e brings the whole cell up simultaneously at epoch 0. Measured over
//! `fanos-sim/tests` + `fanos-node/tests`: of 653 test functions, exactly one creates a node after an epoch
//! advance, and reading it shows a *reshare* of an existing cell rather than an arrival. So the axis along
//! which a joining node differs from a founding one has never been exercised.
//!
//! What #235 claims by reading, and this file settles by running: a self-certifying node verifies a peer's
//! HELLO with `BeaconWindow::beacon_for(epoch)`, its window is seeded with the single pair
//! `(Epoch::ZERO, genesis_seed)`, and the only thing that ever adds to it is `reshuffle_loop` on a
//! `BeaconReady` that arrives *over the network*. A node that has just started therefore holds nothing but
//! genesis, so a live peer proving epoch N ≥ 1 is a claim it cannot judge at all.
//!
//! The fixture is `epoch_clock.rs`'s: a 1-of-1 beacon anchor assembles its own round, so one node advances
//! its epoch on the wall clock with no cell around it.
//!
//! Runtime: multi-threaded, because two live nodes plus a wall-clock driver cannot make progress on a
//! current-thread runtime (#84).

#![allow(clippy::expect_used)]

use std::time::Duration;

use fanos_field::F2;
use fanos_node::{BeaconParams, NetworkId, Node, NodeConfig, Peer};
use fanos_runtime::{Command, Notification};
use fanos_vrf::vss::{DeterministicRng, VssCommitment, deal};

/// The network both nodes are provisioned onto — the same one, so nothing here is a genesis mismatch (#141).
const NETWORK: &[u8] = b"late-join-network";

/// A 1-of-1 beacon anchor that advances its own epoch every `period`, plus the network's public commitment
/// — which is exactly what a joining node is provisioned with and nothing more.
async fn anchor(period: Duration) -> (Node, VssCommitment) {
    let (shares, commitment) =
        deal(&[0x5C; 32], 1, 1, &mut DeterministicRng::new(b"late-join")).expect("deal a 1-of-1 beacon");
    let share = shares.into_iter().next().expect("a 1-of-1 sharing yields one share");
    let node = Node::start::<F2>(NodeConfig {
        listen: "127.0.0.1:0".parse().expect("loopback addr"),
        beacon: Some(BeaconParams {
            network_id: NetworkId::from_seed(NETWORK),
            commitment: commitment.clone(),
            threshold: 1,
            share: Some(share),
            authority: None,
        }),
        epoch_period: period,
        start_heartbeat: false,
        ..NodeConfig::default()
    })
    .await
    .expect("the anchor starts");
    (node, commitment)
}

/// The arrival: same network, same public commitment, **no share** — a pure beacon consumer, which is what
/// a node joining someone else's cell actually is. `bootstrap` points it at `peer`, the one thing a joining
/// node is told out of band.
async fn arrival(commitment: VssCommitment, peer: Peer) -> Node {
    Node::start::<F2>(NodeConfig {
        listen: "127.0.0.1:0".parse().expect("loopback addr"),
        beacon: Some(BeaconParams {
            network_id: NetworkId::from_seed(NETWORK),
            commitment,
            threshold: 1,
            share: None,
            authority: None,
        }),
        bootstrap: vec![peer],
        // Long, so the arrival never advances its own clock: whatever epoch it ends up on came from the cell.
        epoch_period: Duration::from_secs(3600),
        start_heartbeat: false,
        ..NodeConfig::default()
    })
    .await
    .expect("the arriving node starts")
}

/// How many HELLOs this node refused because it holds no beacon for the epoch the peer proved.
///
/// **Read on BOTH nodes, and the first version of this file read only one** — which is why the run reported
/// "delivered nothing and refused nothing" and the non-vacuity assertion below caught it. The exchange is
/// symmetric: each side announces its own epoch and judges the other's, so an advanced cell and a cold
/// arrival refuse each other for two different reasons at two different counters.
fn epoch_unknown(node: &Node) -> u64 {
    node.client()
        .driver_stations()
        .iter()
        .filter(|o| o.station.name() == "hello.epoch_unknown")
        .map(|o| o.count)
        .sum()
}

/// Every station a node has raised, plus how many peers its transport holds.
///
/// Printed on BOTH outcomes, not only on failure. A stall reported as a bare `false` says nothing about
/// which of two very different worlds it is — "no peer was ever reached" and "a peer answered and then the
/// frame went nowhere" need different repairs, and the peer count is what separates them at a glance.
fn dump(tag: &str, n: &Node) {
    let mut v: Vec<String> = n
        .client()
        .driver_stations()
        .iter()
        // The line matters for the directory stations: `directory.point_taken` carries the CONTESTED
        // coordinate, and "which point was taken" is the question the count alone cannot answer (#260).
        .map(|o| match o.line {
            Some(line) => format!("{}@{:?}={}", o.station.name(), line, o.count),
            None => format!("{}={}", o.station.name(), o.count),
        })
        .collect();
    v.sort();
    let h = n.health();
    println!(
        "STATIONS {tag}: seat={:?} known_peers={} verified={} collisions={} send_drops={} unresolved={} | {}",
        h.address,
        h.known_peers,
        h.verified_claims.map_or(-1i64, |v| v as i64),
        h.collisions,
        h.send_drops,
        h.unresolved_drops,
        v.join(" ")
    );
}

/// Send from `from` to `to` and report whether it was delivered within `budget`.
async fn delivers(from: &Node, to: &mut Node, budget: Duration) -> bool {
    // **Both addresses are re-read every iteration, and that is not tidiness** (#260). A node that finds its
    // coordinate taken *moves*, and this harness is the one place where that happens often enough to matter:
    // two nodes drawing from 7 points collide about one time in seven. Bound once before the loop, `target`
    // is the seat the peer has just left and `source` is the name it no longer answers to — so the send goes
    // nowhere and the `f == source` comparison rejects the delivery that did arrive. The instrument would
    // then report a transport failure for an address it was holding wrong itself.
    //
    // Retry the send too: the first dial may lose the race with the peer's own startup, and a single shot
    // would make this measure a race rather than the property.
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let (target, source) = (to.address(), from.address());
        from.command(Command::Send { to: target, payload: b"late-join probe".to_vec() });
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        let step = left.min(Duration::from_millis(500));
        if let Ok(Some(Notification::Delivered { from: f, .. })) =
            tokio::time::timeout(step, to.next_notification()).await
            && f == source
        {
            return true;
        }
    }
}

/// **CONTROL: two nodes started together at epoch 0 exchange a frame.**
///
/// Without this arm the experiment below proves nothing — a harness that cannot deliver at all would report
/// the same silence for the wrong reason. The anchor's epoch period is an hour here, so the cell stays on
/// genesis for the whole test and the only difference from the experiment is *when* the second node starts.
/// **MEASURED 2026-08-10, and the number is why both tests here are measurements rather than assertions.**
///
/// This control is intermittent: 6 runs on the tree at `6ef3451` gave 1 failure, 6 runs on `cf7b309^` gave
/// 2 — so the flake predates #234 and is not caused by it (my first reading of a single red run said
/// otherwise, and only the A/B corrected it). It is bimodal in the way that matters: a pass takes 0.50 s, a
/// failure takes the full 20 s budget and delivers nothing. Same rate and same shape as #182's "emits
/// NOTHING for 48 s, ~1 run in 4" — and this harness is two nodes and 20 seconds where that one is a
/// composed hidden service, so if they are the same defect this is much the cheaper reproducer.
///
/// **SEPARATED, 8 runs, and the discriminator is exact: every failure has `collisions > 0` and every pass
/// has `collisions == 0`.** Two failures in eight, and in both the arriving node reported `collisions=2`;
/// the six passes reported zero. In one failure the two nodes ended on the *same* seat (`[0, 1, 1]` twice);
/// in the other their final seats differ, so the node did detect the clash and move — and delivery still
/// did not recover inside the 20 s budget. The anchor shows `verified=2` on both failures against 1 on
/// every pass, which is the same event from the other side: it authenticated the arrival twice, before and
/// after the move.
///
/// So this is not a harness flake. It is the **recovery path after a coordinate collision**, and the rate is
/// what the geometry predicts: two nodes drawing from the 7 points of `F2` collide with probability 1/7,
/// and 2-in-8 is that number within the noise of eight samples. Every scenario in this tree brings its whole
/// cell up at once and has never been read for this, because a collision there is absorbed by the other five
/// members; with exactly two nodes there is nobody to absorb it.
///
/// **The obvious explanation was mine, and this instrument refuted it.** `delivers` used to bind the peer's
/// address once, before its retry loop — so a node that re-seats leaves the sender addressing a seat it has
/// left, and the harness would report a transport failure for an address it was holding wrong itself. That
/// is a real defect in the instrument and it is fixed. It is **not** the cause: with both addresses re-read
/// every iteration the rate is unchanged at 2 in 10, and the discriminator still separates every run. Across
/// both batches `collisions` separates 18 of 18.
///
/// **Traced to the end, and the last reading is the one that names it.** Printing the station's *line* —
/// which coordinate was contested — gave the whole sequence on a failing run:
///
/// ```text
/// anchor   seat=[0,1,0]  known_peers=1  verified=2  collisions=0
/// second   seat=[0,1,0]  known_peers=1  verified=1  collisions=2  directory.point_taken@[0,1,0]=1
/// ```
///
/// Both nodes are on the SAME seat, and the anchor's `collisions=0` says it never saw the clash. The
/// arbitration happened only in the arrival's own directory: it decided locally that its claim beats the
/// incumbent, rebound `[0,1,0]` to itself — and in doing so **deleted the only address it had for the
/// anchor**, which is exactly `known_peers = 1`. The anchor was never told its point was taken, so it does
/// not walk on. Two nodes, one coordinate, and neither can address the other.
///
/// The resolution that does exist is the next epoch: each node re-derives its seat from a fresh rank on
/// `BeaconReady`. This fixture's period is an hour, so nothing re-derives inside the 20 s budget — which is
/// not the harness being unfair, it is the harness making visible how long the pair stays mutually
/// unreachable when the beacon is slow. The arbitration is one-sided and the loser has no notification path;
/// the epoch turn is the only thing that ends it.
///
/// The experiment below therefore **still cannot be read as evidence** — its silence has two causes and this
/// arm was meant to separate them — but the reason is now named rather than open. Neither ships as a gate.
/// They are `#[ignore]`d measurements, the class that prints for a person and never blocks, and they become
/// assertions the day a collision recovers inside the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement, not an assertion — the control is 1-in-4 intermittent; run with --ignored --nocapture"]
async fn probe_two_nodes_started_together_on_genesis_exchange_a_frame() {
    let (a, commitment) = anchor(Duration::from_secs(3600)).await;
    let mut b = arrival(commitment, Peer { coord: a.address(), addr: a.local_addr() }).await;

    let delivered = delivers(&a, &mut b, Duration::from_secs(20)).await;
    // Reported before the assertion, so a failing run leaves the same evidence a passing one does. Without
    // this the flake is a bare `false` and every explanation for it is equally consistent with the output.
    println!("CONTROL delivered={delivered}");
    dump("anchor", &a);
    dump("second", &b);
    assert!(
        delivered,
        "the control must deliver, or the experiment below measures the harness and not the property"
    );
    assert_eq!(
        (epoch_unknown(&a), epoch_unknown(&b)),
        (0, 0),
        "on genesis there is no epoch either side cannot judge, in either direction"
    );

    a.shutdown().await;
    b.shutdown().await;
}

/// **THE EXPERIMENT: a node that arrives after the cell has left genesis.**
///
/// The anchor ticks every 120 ms, so by the time the arrival starts the cell is several epochs past genesis
/// and the arrival holds only `(0, genesis_seed)`.
///
/// This test asserts what is TRUE TODAY, and it is written to fail the day it stops being true — the panic
/// message says so, because a joining node succeeding is the fix landing, not a regression.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement, not an assertion — its control above is intermittent, so a green here proves nothing yet"]
async fn probe_a_node_arriving_after_the_cell_leaves_genesis_cannot_be_verified() {
    // A subscriber, because `RUST_LOG` alone does nothing in a test binary — measured, and it is why the
    // first three attempts at this investigation produced no trace at all.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let (mut a, commitment) = anchor(Duration::from_millis(120)).await;

    // **Wait for the OBSERVABLE, not the clock.** A `sleep(2s)` is a proxy for "the cell has advanced", and
    // a proxy is what made this flake: one run in four the arrival still completed an exchange, because the
    // precondition the test needs — the cell's epoch is past the window that would still admit a genesis
    // claim — had not actually been reached when the arrival started.
    //
    // `BeaconWindow::DEPTH` is `1 + SHAPE_GRACE = 2` (it was 3 when this comment was written; #261 derived it
    // from the transport instead of choosing it), so a *rotated* epoch leaves the cell's window two epochs
    // on. Epoch 10 clears that by any reading, which is why this precondition survived the constant moving —
    // and why it is stated as a waited-for event rather than a number this file maintains.
    let reached = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(Notification::BeaconReady { epoch, .. }) = a.next_notification().await
                && epoch.get() >= 10
            {
                return epoch.get();
            }
        }
    })
    .await
    .expect("the anchor must climb past its own beacon window before the arrival starts");
    println!("PRECONDITION cell epoch = {reached} (well past BeaconWindow::DEPTH = 1 + SHAPE_GRACE = 2)");

    let mut b = arrival(commitment, Peer { coord: a.address(), addr: a.local_addr() }).await;

    // BOTH DIRECTIONS, because which side refuses depends on who dials and the two thresholds differ.
    // The dialer judges its peer's HELLO first and drops on refusal, so the acceptor never reaches its own
    // verification — the first refusal wins and the second never happens.
    //
    //   cell → arrival: the cell reads a genesis-epoch claim. **CLOSED** — the verifier now keeps a pinned
    //     genesis seed, matching the permanent genesis door PROTEUS already holds open (#235). Before the
    //     pin the claim aged out of the window and this was the FIRST refusal, which is what hid the other.
    //   arrival → cell: the arrival reads epoch N holding only genesis, so it cannot judge at all (N ≥ 1).
    //     **OPEN**, and now the only one — closing the cell's arm promoted this to the binding refusal.
    //
    // The second is the realistic join: `bootstrap` exists so the arrival dials the cell.
    // DISCRIMINATOR for step 1 of #235, using only shipped API: a node's coordinate is re-derived and
    // re-seated by `reshuffle_loop` on every adopted `BeaconReady`. So if the arrival's coordinate MOVES, it
    // adopted a round and a catch-up path exists; if it stays put and delivery still happens, the HELLO gate
    // was bypassed instead. Two different defects, and one address tells them apart.
    let arrival_seat_before = b.address();
    let cell_to_arrival = delivers(&a, &mut b, Duration::from_secs(15)).await;
    let arrival_to_cell = delivers(&b, &mut a, Duration::from_secs(15)).await;
    let delivered = cell_to_arrival || arrival_to_cell;
    let (on_cell, on_arrival) = (epoch_unknown(&a), epoch_unknown(&b));

    // EVERY station on BOTH nodes. One counter answers "did this gate fire"; the whole plane answers "which
    // gate fired", and that is the question left open — how a send can succeed when the exchange that
    // authorizes it was refused.
    println!(
        "OUTCOME delivered={delivered} cell->arrival={cell_to_arrival} arrival->cell={arrival_to_cell} \
         arrival_seat {arrival_seat_before:?} -> {:?}",
        b.address()
    );
    dump("cell", &a);
    dump("arrival", &b);
    assert!(
        !delivered,
        "a late-arriving node COMPLETED an exchange with an advanced cell (hello.epoch_unknown: cell \
         {on_cell}, arrival {on_arrival}). #235 is closed — replace this expectation with the property, \
         and record which mechanism made the beacon reachable without an already-verified peer."
    );
    assert!(
        on_cell + on_arrival > 0,
        "nothing was delivered AND neither side refused for an unknown epoch (cell {on_cell}, arrival \
         {on_arrival}), so this run never reached a HELLO exchange — it measures a dial that did not happen, \
         not the epoch window. Check the bootstrap address before reading anything into the silence."
    );
    // **THE ASYMMETRY HAS FLIPPED, and that is this instrument's clearest result** (#235).
    //
    // The first measurement refuted the prediction the test was written from. I expected the ARRIVAL to be
    // the binding refusal — its window holds only genesis, so a peer proving epoch N ≥ 1 is unjudgeable. The
    // run said the opposite: **cell 1, arrival 0**, in both dial directions. The dialer judges first and
    // drops on refusal, so whichever side refuses ends the exchange before the other reaches its own
    // verification, and the cell was refusing first.
    //
    // With the genesis pin the same run reads **cell 0, arrival 1**. Not a smaller number — a *moved* one:
    // the cell no longer refuses at all, and the refusal I originally predicted is now the one that fires.
    // That is a sharper result than a green would have been, because it says which of the two mechanisms the
    // pin touched, and it could not have been read off either counter alone.
    //
    // So the original finding — **the joining node cannot tell that it was refused** — has been repaired as
    // a side effect, and by the least expected route. Every instrument the arrival owned used to read clean:
    // no delivery failure it could attribute, no refusal counter, no dial error, because only the cell knew
    // and the cell is not the party that needs to act. Now the party that must act is the party that counts.
    // The assertions below therefore pin BOTH sides, where the old one pinned only the sum: the split is now
    // the property, not a race.
    assert_eq!(
        on_cell, 0,
        "the cell refused a genesis-epoch claim again (cell {on_cell}, arrival {on_arrival}) — the pinned \
         genesis seed in `BeaconWindow::beacon_for` is the verifier's half of PROTEUS's permanent genesis \
         door, and if this is non-zero the door leads to a wall again (#235)"
    );
    assert!(
        on_arrival > 0,
        "neither side refused for an unknown epoch (cell {on_cell}, arrival {on_arrival}). If the arrival \
         now joins, that is #235 closing — say by what mechanism it reached a beacon without an \
         already-verified peer, and turn this file into the property. If it merely stopped counting, the \
         joining node has gone silent again and THAT is the regression."
    );
    println!(
        "MEASURED delivered: cell->arrival {cell_to_arrival}, arrival->cell {arrival_to_cell}; \
         hello.epoch_unknown -> cell: {on_cell}, arrival: {on_arrival}; arrival seat {arrival_seat_before:?} \
         -> {:?} (moved: {})",
        b.address(),
        b.address() != arrival_seat_before,
    );

    a.shutdown().await;
    b.shutdown().await;
}
