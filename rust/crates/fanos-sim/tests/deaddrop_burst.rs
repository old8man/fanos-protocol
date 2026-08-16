//! **The NOSTOS dead-drop's `q+1` burst** (#134) — the timing half of the dead-drop's traffic signature,
//! measured against the ordinary forwarded onion in the same instrument.
//!
//! `cf55ead` closed the SIZE half: a drop cell is padded to the onion's bucket, so it is byte-identical in
//! width to a forwarded onion frame. What was left is *when* the cells leave. The mechanism as it stood, as a
//! sequence:
//!
//! 1. the last hop's gathering member peels the final layer (`ThresholdRouter::try_peel`);
//! 2. the payload carries `DEADDROP_TAG`, so the peel takes the `deaddrop_multicast` arm;
//! 3. `deaddrop_multicast` mapped `points_on(L)` to one `Effect::Send` each and returned them **all from one
//!    `step`** — so every cell left at one instant, and it never touched `forward_send`, the function that
//!    holds a forwarded hop for its Poisson mix delay or queues it for a constant-rate cover slot.
//!
//! So the observable is not "a `q+1`-wide burst exists" — every gather already fans `q` share-requests to the
//! same line, and that burst is *not* the finding. It is the **post-gather fan-out**: after its gather
//! completes, a node relaying an ordinary onion emits exactly **one** cell, and a node delivering a dead drop
//! emitted **`q`** at the same instant. One number, and its value was the plane order.
//!
//! Each cell now goes out through `forward_send`, one call each — a dead-drop delivery *is* `q` forwards — so
//! the fan-out is `1` under either defended schedule with no constant introduced. These tests are what measured
//! that, and what fails if it is undone.
//!
//! ## The instrument
//!
//! A global passive adversary's tape (`Sim::observe_frames`) gives `(t, from, to, len)`. Restrict to frames
//! leaving the peeling node whose length is the **cell width** `1 + 12 + THRESHOLD_ONION_LEN` — the class that
//! `cf55ead` merged, holding forwarded onions, cover cells and drop cells alike (a share-request is 20 bytes
//! wider and a share reply is tiny, so both fall out by length, which is how a GPA would separate them too).
//! Then take [`widest_instant`]: the most such frames sharing one timestamp. That is the burst.
//!
//! **The network model is fixed-latency and jitter-free on purpose.** The burst is a property of the emitter;
//! 10 ms of wire jitter would smear a synchronous burst across the tape and credit the network with a defence
//! it does not provide (it is symmetric per frame, and an adversary near the sender sees none of it). Every
//! arm runs the same wire, so nothing is being flattered.
//!
//! **The control arm is an ordinary forwarded onion peeled by the same node in the same position** — same
//! launch, same gather, same threshold, differing only in whether the peeled payload is dead-drop-enveloped.
//! Without it, `widest_instant = q` would say nothing: it is `q` for the *share-request* fan-out too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use fanos_aphantos::ThresholdRouter;
use fanos_aphantos::nostos::{ReplyKeys, seal_reply};
use fanos_aphantos::threshold::{HopLine, THRESHOLD_ONION_LEN, seal_onion};
use fanos_aphantos::threshold_router::{launch_frame, line_member_coords};
use fanos_field::{F2, F4, Field};
use fanos_geometry::{Line, Plane, Point, Triple};
use fanos_node::config::{DEFAULT_COVER_INTERVAL, DEFAULT_MIX_DELAY};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::Epoch;
use fanos_runtime::{Command, Duration};
use fanos_sim::{FrameObs, NetworkModel, Sim};

/// The on-wire width of one cell: a forwarded onion frame, a cover cell and a dead-drop cell are all exactly
/// this, which is what `cf55ead` bought. Computed from the constant rather than written down, so it tracks.
const CELL_LEN: usize = 1 + 12 + THRESHOLD_ONION_LEN;

/// The two things a peeling node can do with a peeled last layer — the arm and its control.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arm {
    /// The dead drop: the peeled payload is `DEADDROP_TAG`-enveloped, so the node multicasts to `points_on(L)`.
    Reply,
    /// **The control**: an ordinary onion with one more hop, so the same node peels and forwards **one** cell.
    Forward,
}

/// The emission schedule a router runs under. Named for what ships, not for what is convenient.
#[derive(Clone, Copy)]
struct Schedule {
    mix: Duration,
    cover: Duration,
}

impl Schedule {
    /// No mixing, no cover — the raw mechanism, where a burst is a burst.
    const BARE: Self = Self { mix: Duration(0), cover: Duration(0) };
}

/// `std::time::Duration` → the engine's nanosecond span (the conversion `Node::start` performs).
fn span(d: std::time::Duration) -> Duration {
    Duration(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Poisson mixing at the shipping mean, cover off — the schedule in which `forward_send`'s *delay* branch runs.
fn mixed() -> Schedule {
    Schedule { mix: span(DEFAULT_MIX_DELAY), cover: Duration(0) }
}

/// What a relay actually ships: mixing **and** constant-rate cover, read from the constants (#187).
fn shipping() -> Schedule {
    Schedule { mix: span(DEFAULT_MIX_DELAY), cover: span(DEFAULT_COVER_INTERVAL) }
}

/// A router at every point of `PG(2, q)`, returning the forward-secure onion publics to seal to.
///
/// `salt` varies the **identity KEM secret**, and that is the only knob that redraws a run: `mix_seed` — which
/// keys both the exponential mix delay and the whole cover schedule — is derived from it, while `Sim`'s own
/// seed drives a network model this harness has set to fixed-latency. A "seed sweep" that moved the simulator
/// seed alone would have run the same schedule every time and reported one draw as an average.
fn spawn<F: Field + 'static>(
    sim: &mut Sim,
    t: usize,
    sched: Schedule,
    salt: u8,
) -> BTreeMap<Triple, HybridKemPublic> {
    let mut pubs = BTreeMap::new();
    for i in 0..Plane::<F>::N as usize {
        let point = Point::<F>::at(i);
        let (secret, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xB1, salt, i as u8]));
        let mut onion_seed = [0xD3u8; 32];
        onion_seed[31] = i as u8;
        pubs.insert(point.coords(), OnionKeyRatchet::new(onion_seed, Epoch::ZERO).public().clone());
        let mut r = ThresholdRouter::<F>::new(point, &secret, t, onion_seed).with_mixing(sched.mix);
        if sched.cover.as_nanos() > 0 {
            r = r.with_cover(sched.cover);
        }
        sim.add(Box::new(r));
    }
    pubs
}

/// The member publics of `line`, in canonical seal order.
fn members_of<F: Field>(line: Triple, pubs: &BTreeMap<Triple, HybridKemPublic>) -> Vec<&HybridKemPublic> {
    line_member_coords::<F>(line).iter().map(|c| pubs.get(c).unwrap()).collect()
}

/// Run one arm and return the GPA's tape together with the peeling node's coordinate.
///
/// Both arms launch at **the same node** — member 0 of the drop line — and that node gathers and peels in
/// both. The only difference is what the peeled payload turns out to be, which is precisely the variable
/// under test.
fn run<F: Field + 'static>(arm: Arm, sched: Schedule, salt: u8) -> (Vec<FrameObs>, Triple) {
    // Fixed latency, no jitter, no loss: the burst is the emitter's, and jitter would credit the wire.
    let net = NetworkModel::new(Duration::from_millis(20), Duration(0), 0.0);
    let mut sim = Sim::with_network(u64::from(salt), net);
    let t = 2usize;
    let pubs = spawn::<F>(&mut sim, t, sched, salt);

    let drop_line = Line::<F>::at(1).coords();
    let peeler = line_member_coords::<F>(drop_line)[0];

    let drop_members = members_of::<F>(drop_line, &pubs);
    let onion = match arm {
        Arm::Reply => {
            // A real NOSTOS reply: end-to-end sealed to the receiver, wrapped in the dead-drop envelope,
            // then threshold-sealed with `drop_line` as its (only) hop.
            let (_keys, reply_pub) = ReplyKeys::generate(b"burst-reply-key");
            let hops = [HopLine { line: drop_line, members: &drop_members }];
            seal_reply(&reply_pub, &hops, t as u8, b"the homecoming", b"burst-onion-seed").unwrap()
        }
        Arm::Forward => {
            // THE CONTROL: the same node peels the same way, but there is a further hop, so it forwards one
            // cell instead of dead-dropping. A second line is chosen that does not pass through the peeler,
            // so the forward genuinely leaves the first line.
            let next = (0..Plane::<F>::N as usize)
                .map(|i| Line::<F>::at(i).coords())
                .find(|&l| l != drop_line && !line_member_coords::<F>(l).contains(&peeler))
                .expect("a plane has a line missing any given point");
            let next_members = members_of::<F>(next, &pubs);
            let hops = [
                HopLine { line: drop_line, members: &drop_members },
                HopLine { line: next, members: &next_members },
            ];
            seal_onion(&hops, t as u8, b"the homecoming", b"burst-onion-seed").unwrap()
        }
    };

    if sched.cover.as_nanos() > 0 {
        sim.inject_all(&Command::StartHeartbeat);
    }
    sim.observe_frames();
    // Launch from a point off the drop line, so the launcher's own emission is never attributed to the peeler.
    let source = (0..Plane::<F>::N as usize)
        .map(|i| Point::<F>::at(i).coords())
        .find(|c| !line_member_coords::<F>(drop_line).contains(c))
        .unwrap();
    sim.inject_frame(source, peeler, launch_frame(drop_line, &onion));
    sim.run_for(Duration::from_millis(6_000));
    (sim.observed_frames().to_vec(), peeler)
}

/// **The metric.** The most **cell-width** frames the node emits sharing a single timestamp — the width of its
/// widest synchronous fan-out, as a GPA reads it off `(t, from, len)`.
fn widest_instant(tape: &[FrameObs], node: Triple) -> usize {
    let mut per_instant: BTreeMap<u64, usize> = BTreeMap::new();
    for o in tape.iter().filter(|o| o.from == node && o.len == CELL_LEN) {
        *per_instant.entry(o.t_ms).or_default() += 1;
    }
    per_instant.values().copied().max().unwrap_or(0)
}

/// How many cell-width frames the node emits at all (meaningful only with cover off, where every such frame is
/// real traffic). With cover on this counts cover cells too, which is the point of cover.
fn cells_emitted(tape: &[FrameObs], node: Triple) -> usize {
    tape.iter().filter(|o| o.from == node && o.len == CELL_LEN).count()
}

/// The span between the node's first and last cell-width emission, in ms — zero when they all leave at once.
fn spread_ms(tape: &[FrameObs], node: Triple) -> u64 {
    let ts: Vec<u64> = tape.iter().filter(|o| o.from == node && o.len == CELL_LEN).map(|o| o.t_ms).collect();
    match (ts.iter().min(), ts.iter().max()) {
        (Some(lo), Some(hi)) => hi - lo,
        _ => 0,
    }
}

/// The line size `q + 1` of the plane under test — what a burst's width would disclose.
fn line_size<F: Field>() -> usize {
    Plane::<F>::LINE_SIZE as usize
}

/// **The neighbouring burst, and the volume hypothesis about it that this measurement refuted.**
///
/// Every gather fans `q` share-requests to the line, from `on_onion`, also as direct `Effect::Send`s that never
/// touch `forward_send`. That burst is *not* a dead-drop distinguisher — a transit hop and a delivery hop
/// produce it identically, which is why the burst metric above filters it out by length and why "a `q`-wide
/// burst exists" was never the finding. The obvious next suspicion is that it is a **volume** leak the cover
/// profile misses: `TAG_REQ` carries `req_id(8) ‖ combiner(12)` on top of the cell layout, so a share request is
/// 20 bytes wider than the cell width `cf55ead` unified, and cover cells are emitted at *cell* width — so the
/// gather class looks like a channel cover never fills, carrying volume proportional to real traffic.
///
/// **It is not, and the discriminator is in the counts below.** One real delivery through this node produced
/// **20** share requests, not the `q = 2` its own gather needs. The rest are the node gathering *cover* onions:
/// `emit_cover` sends a keystream cell to a pseudo-random line's gather member, which runs the identical
/// `on_onion` path and fans the identical `q` requests before the gather expires unpeelable. So the gather class
/// is filled by cover at the same rate as by cargo, and the displacement invariant one level up (a real forward
/// takes a cover slot rather than adding one) keeps the onion arrivals that trigger it constant.
///
/// What survives is a **width** observation, not a volume one: a GPA can still separate gather traffic from
/// cargo by length alone. That is a distinguisher between two *classes of FANOS traffic*, not between a relay
/// carrying a flow and one that is idle, so it is a different and much weaker thing than #134's burst — and it
/// is out of this ticket's scope either way. Pinned here so the refutation is not re-derived, and so a change
/// that stops cover from driving gathers fails at this assertion and gets read.
/// **The third class in this family was NOT filled, and closing it took `c98b2d5` (#354).** The reasoning
/// above follows the gather to its *request* and stops there. One step further, `member_share` ends in an
/// AEAD open, which fails on keystream — so a cover cell drew its `q` requests and then drew **no replies at
/// all**, while a cargo cell drew `q` of them. Measured on a composed relay cell, `TAG_REP` frames came to
/// `4 + 4·cells` while this class and the cell class stayed on the slot rate, and a reply is 42 bytes against
/// a cell's `THRESHOLD_ONION_LEN` — so it separates by size exactly as this one does. `on_request` now answers
/// an unpeelable request with a decoy share, and the same run reads `replies == requests` at every cargo level.
///
/// With that, the family is complete: **cells** unified in width by `cf55ead`, **requests** filled by cover as
/// argued here, **replies** filled by the decoy. The chain was worth walking one link past where it looked
/// finished, and the reason it looked finished is that each link is filled by a *different* mechanism.
#[test]
fn cover_onions_fill_the_share_request_class_so_its_volume_is_not_a_real_traffic_signal() {
    let (tape, peeler) = run::<F2>(Arm::Reply, shipping(), 0x0D);
    let mut by_len: BTreeMap<usize, usize> = BTreeMap::new();
    for o in tape.iter().filter(|o| o.from == peeler) {
        *by_len.entry(o.len).or_default() += 1;
    }
    println!("frame widths leaving the peeling node under the shipping profile: {by_len:?}");
    // `encode_req` = TAG(1) ‖ req_id(8) ‖ combiner(12) ‖ line(12) ‖ onion, against a cell's TAG(1) ‖ line(12) ‖ …
    let req_len = CELL_LEN + 8 + 12;
    assert_ne!(req_len, CELL_LEN, "a share request must not be the same width as a cell, or this test is vacuous");
    let requests = by_len.get(&req_len).copied().unwrap_or(0);
    assert!(
        requests > (line_size::<F2>() - 1) * 3,
        "the gather class must be filled by COVER, not only by the one real delivery: {requests} share requests \
         against the {} this node's own gather needs. If this has fallen to the real traffic's own fan-out, cover \
         no longer drives gathers and the class HAS become a volume channel — re-read #134's neighbour",
        line_size::<F2>() - 1,
    );
}

/// One printed row of the instrument, for a person reading the numbers.
fn row<F: Field + 'static>(name: &str, arm: Arm, sched: Schedule) -> usize {
    let (tape, peeler) = run::<F>(arm, sched, 0x0D);
    let w = widest_instant(&tape, peeler);
    println!(
        "  q={:<2} {name:<22} {arm:<9?} widest simultaneous fan-out {w:>2}   cells {:>3}   spread {:>5} ms",
        F::Q,
        cells_emitted(&tape, peeler),
        spread_ms(&tape, peeler),
    );
    w
}

/// **THE PROPERTY.** Under a schedule that defends at all, a dead-drop delivery must not fan out wider, at one
/// instant, than the ordinary forwarded onion the same node would have relayed — because that width is both a
/// "a reply landed here" flag and a readout of the plane order `q`.
///
/// Asserted on **two planes**, because a burst equal to `q` on one plane is a number and a burst equal to `q`
/// on two is the leak: `PG(2,2)` and `PG(2,4)` are the planes whose slot budget still admits the two-hop
/// circuit the control arm needs (`slots::depth_for` gives 3 and 2 respectively; `q = 7` gives 1, so its
/// control cannot be built and measuring only its dead-drop arm would be an arm without a control).
///
/// **`bare` is printed and not asserted, and that is the derivation showing through rather than a hole.** The
/// remedy is "a dead drop is `q` forwards, so emit each one the way a forward is emitted" — it adds no schedule
/// of its own. With `mean_delay = 0` and `cover_interval = 0` a forward leaves immediately, so `q` of them leave
/// immediately too, and asserting otherwise would be asserting a defence the operator switched off. Both ship
/// non-zero (`fanos_node::config`'s own defaults test pins that), and those are the rows with teeth.
///
/// The whole table is printed **before** any assertion, so a failure leaves the complete measurement behind
/// rather than the first row that broke — the reading is the point, and a half-printed table is how a
/// measurement becomes an anecdote.
#[test]
fn a_dead_drop_delivery_does_not_fan_out_wider_than_the_forward_it_replaces() {
    println!("post-gather fan-out at the peeling node (GPA tape, cell-width frames only):");
    let mut table = Vec::new();
    for (name, sched, defended) in [
        ("bare", Schedule::BARE, false),
        ("mixed", mixed(), true),
        ("SHIPPING", shipping(), true),
    ] {
        table.push((
            name,
            defended,
            row::<F2>(name, Arm::Reply, sched),
            row::<F2>(name, Arm::Forward, sched),
            row::<F4>(name, Arm::Reply, sched),
            row::<F4>(name, Arm::Forward, sched),
        ));
    }
    for (name, defended, f2_reply, f2_fwd, f4_reply, f4_fwd) in table {
        // The control must actually be a control: an ordinary forward is one cell, at every schedule — `bare`
        // included. If this ever reads more, the instrument is measuring something other than the peel's
        // fan-out, and every other number in the table is worthless. The one way it can: under cover, two
        // ticks whose exponential gap draws under the tape's 1 ms resolution would land in one instant with no
        // burst involved. That reads here first, naming the instrument, instead of being scored as a defect.
        assert_eq!(f2_fwd, 1, "{name}: the control arm must emit exactly one cell per peel (PG(2,2))");
        assert_eq!(f4_fwd, 1, "{name}: the control arm must emit exactly one cell per peel (PG(2,4))");
        if !defended {
            continue;
        }
        assert_eq!(
            f2_reply, f2_fwd,
            "{name}: a dead-drop delivery fans out {f2_reply} cells at one instant where a forwarded onion emits \
             {f2_fwd} — a burst nothing else on the wire produces, saying a reply landed here (PG(2,2))",
        );
        assert_eq!(
            f4_reply, f4_fwd,
            "{name}: a dead-drop delivery fans out {f4_reply} cells at one instant where a forwarded onion emits \
             {f4_fwd}, and {f4_reply} is the plane's line size − 1 — the burst's width IS the plane order (PG(2,4))",
        );
    }
}

/// The burst's width **was** `q`, and that is why it was worth removing: not merely a flag that a reply
/// happened, but a readout of which plane the cell runs. Pinned against the geometry rather than against
/// literals, so it cannot be satisfied by a coincidence on one plane — two planes are what discriminate "the
/// fan-out is `q`" from "the fan-out is some constant that happens to equal `q` here".
///
/// Measured on the **shipping** schedule, where the answer is structural rather than lucky: a queued cell
/// leaves only when a cover slot fires and `emit_cover` pops exactly one, so at most one cell can share an
/// instant however many are waiting.
#[test]
fn the_burst_width_no_longer_reads_off_the_plane_order() {
    let (f2, f4) = (
        widest_instant_of::<F2>(Arm::Reply, shipping()),
        widest_instant_of::<F4>(Arm::Reply, shipping()),
    );
    println!(
        "dead-drop fan-out on the shipping schedule — PG(2,2) {f2} (line size {}), PG(2,4) {f4} (line size {})",
        line_size::<F2>(),
        line_size::<F4>(),
    );
    // Undefended these read `q = line_size − 1` (2 and 4): the combiner keeps its own copy and sends to the rest.
    assert_ne!(f2, line_size::<F2>() - 1, "PG(2,2): the fan-out still equals q, so it still names the plane");
    assert_ne!(f4, line_size::<F4>() - 1, "PG(2,4): the fan-out still equals q, so it still names the plane");
    assert_eq!(f2, f4, "the fan-out must not vary with the plane at all — that variation IS the leak");
}

/// [`widest_instant`] for one arm, spawning and running it.
fn widest_instant_of<F: Field + 'static>(arm: Arm, sched: Schedule) -> usize {
    let (tape, peeler) = run::<F>(arm, sched, 0x0D);
    widest_instant(&tape, peeler)
}

/// **Does the reply still come home, and what does the stagger cost?** A stagger that lost cells would score
/// perfectly on the metric above and be a defence that works by eating the traffic — the
/// `a_zero_leak_slope_is_masking_and_not_starvation` failure mode, one file over. So: every member of the drop
/// line must still receive its cell, at every schedule.
///
/// The **cost** is printed beside it, because the remedy is only free in the sense of introducing no constant.
/// A cell held is a reply delayed, and only one of the `q` cells is the receiver's — so the receiver's expected
/// wait is the mean over the arrivals, which is what this reports. Removing a mechanism (or adding one) needs
/// its own measurement, and a burst removed at an unmeasured price is a trade nobody agreed to.
///
/// Averaged over [`RUNS`] independent schedules, because the holds are exponential draws: a single run's mean
/// over `q = 2` cells has a standard deviation of the same order as the mean it reports, so one draw would be an
/// anecdote wearing a decimal point.
#[test]
fn every_member_of_the_drop_line_still_receives_its_cell() {
    /// Independent schedules the arrival cost is averaged over (see the doc above).
    const RUNS: u8 = 16;

    println!("arrival of a drop cell, ms after launch, mean over {RUNS} independent schedules:");
    for (name, sched) in [("bare", Schedule::BARE), ("mixed", mixed()), ("SHIPPING", shipping())] {
        let mut arrivals = Vec::new();
        for salt in 0..RUNS {
            let (tape, peeler) = run::<F2>(Arm::Reply, sched, salt);
            let expected: Vec<Triple> = line_member_coords::<F2>(Line::<F2>::at(1).coords())
                .into_iter()
                .filter(|&m| m != peeler)
                .collect();
            for member in expected {
                let at = tape
                    .iter()
                    .find(|o| o.from == peeler && o.to == member && o.len == CELL_LEN)
                    .map(|o| o.t_ms);
                assert!(
                    at.is_some(),
                    "{name} (salt {salt}): member {member:?} of the drop line never received a cell — \
                     the stagger dropped it"
                );
                arrivals.extend(at);
            }
        }
        let mean = arrivals.iter().sum::<u64>() as f64 / arrivals.len() as f64;
        let (lo, hi) = (arrivals.iter().min().copied(), arrivals.iter().max().copied());
        println!(
            "  {name:<10} mean {mean:>7.1} ms over {} cells (min {} ms, max {} ms)",
            arrivals.len(),
            lo.unwrap_or(0),
            hi.unwrap_or(0),
        );
    }
}
