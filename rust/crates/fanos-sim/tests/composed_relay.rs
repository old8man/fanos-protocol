//! **The relay a deployment actually runs** — the composition branch nothing stood up.
//!
//! `CellComposition { relay: true }` appeared nowhere in this crate, `fabric.rs` never calls `compose_engine`,
//! and `composition.rs`'s own relay test deliberately takes the beacon-less branch so it builds no router.
//! `mixnet.rs` uses a bare `NyxNode` and `mix_relay.rs` hand-assembles a `MixRelay`. So the relay branch of
//! `compose_engine` — what a production `--relay` node is — was exercised by nothing, including the threshold
//! it seals onions at.
//!
//! That cost real verification: when `MIX_THRESHOLD` was generalized from a constant to `⌈2(q+1)/3⌉` (audit
//! E7), the change could only be checked arithmetically and by the fact that it is a no-op at `q = 2`.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::spawn_composed_relay_cell;
use fanos_field::{F2, F7};
use fanos_geometry::{Line, Point};
use fanos_pqcrypto::OnionKeyRatchet;
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, Epoch, MixDirectory, line_member_coords, meeting_line, seal_forward,
};
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::Sim;

/// The Fano onion threshold: `mix_threshold(LINE_SIZE) = ⌈2·3/3⌉ = 2`, the value `compose_engine` gives the
/// router it builds. Stated here rather than imported so a change to the derivation shows up as a failing
/// forward rather than as this test silently sealing to whatever the code now does.
const ONION_T: u8 = 2;

/// Mixing off — what every relay scenario in this crate ran at, invisibly, until #180.
///
/// Named rather than written as a bare zero at four call sites, because the value is the *point*: it is the
/// setting a stock deployment does NOT use (`NodeConfig::default` asserts `mix_mean_delay > 0`), and the two
/// cover tests below want it held at zero deliberately so that what they measure stays cover and not mixing.
const NO_MIX: Duration = Duration(0);

/// A composed relay cell emits cover traffic; the **identical cell without the relay role** does not.
///
/// Cover is the right observable because only a router produces it. An armed relay emits constant-rate cells
/// whether or not anyone is talking — that is the E1/E6 property, and `CellNode` starts the schedule on
/// `StartHeartbeat` precisely so the silence→cover transition does not coincide with, and thereby reveal, the
/// first real forward.
///
/// **The control has to be the same composition.** The first version of this test compared against a bare
/// `spawn_cell`, which differs in the *beacon* as well — and it stayed green when `relay` was switched off,
/// because the difference it measured was beacon traffic. Falsification caught it; nothing else would have.
#[test]
fn a_composed_relay_cell_arms_its_router_and_emits_cover() {
    let window = Duration::from_millis(4000);
    let cover = Duration::from_millis(200);

    let mut quiet = Sim::new(0xC0FE);
    let _no_relay = spawn_composed_relay_cell::<F2>(&mut quiet, Config::default(), cover, NO_MIX, false);
    quiet.inject_all(&Command::StartHeartbeat);
    quiet.run_for(window);
    let baseline = quiet.report().metrics.frames_sent;

    let mut relayed = Sim::new(0xC0FE);
    let _cell = spawn_composed_relay_cell::<F2>(&mut relayed, Config::default(), cover, NO_MIX, true);
    relayed.inject_all(&Command::StartHeartbeat);
    relayed.run_for(window);
    let with_cover = relayed.report().metrics.frames_sent;

    assert!(
        with_cover > baseline,
        "the relay role must add traffic the same cell without it does not send — the router is either not \
         built or not armed (relay {with_cover} vs same-cell-no-relay {baseline})"
    );
}

/// The same composition on a **wider plane**, where the hop threshold is no longer the Fano value.
///
/// `mix_threshold` is `⌈2(q+1)/3⌉`, so a `PG(2,7)` line of eight points seals at 6-of-8 rather than the 2-of-3
/// a Fano line uses. Nothing exercised that: the generalization was verified by arithmetic and by being a
/// no-op at `q = 2`. This stands the composition up at `q = 7` so the wider threshold is built and run rather
/// than only computed — 57 relays, each holding a beacon share and a router keyed to its own seeds.
#[test]
fn a_composed_relay_cell_composes_on_a_wider_plane() {
    let window = Duration::from_millis(4000);
    let cover = Duration::from_millis(200);

    let mut quiet = Sim::new(0xC0FE);
    let control = spawn_composed_relay_cell::<F7>(&mut quiet, Config::default(), cover, NO_MIX, false);
    assert_eq!(control.len(), 57, "PG(2,7) seats 57 points");
    quiet.inject_all(&Command::StartHeartbeat);
    quiet.run_for(window);
    let baseline = quiet.report().metrics.frames_sent;

    let mut relayed = Sim::new(0xC0FE);
    let cell = spawn_composed_relay_cell::<F7>(&mut relayed, Config::default(), cover, NO_MIX, true);
    assert_eq!(cell.len(), 57);
    relayed.inject_all(&Command::StartHeartbeat);
    relayed.run_for(window);

    // The same control as the Fano case, and for the same reason: `frames_sent > 0` alone would pass without
    // any router at all, which is what the first draft of the other test did.
    assert!(
        relayed.report().metrics.frames_sent > baseline,
        "a 57-point cell sealing at 6-of-8 must carry router traffic the same cell without the role does not"
    );
}

/// **What `mix_mean_delay` actually does, measured — and it is not what its own doc says.**
///
/// It was the last `CellComposition` field with no scenario at any value, so nothing had ever observed it.
/// Standing one up took three tries and each refuted the previous:
///
/// 1. Compare `frames_sent` from a quiet cell, mixing on vs off. **Identical** — mixing delays a *forwarded
///    hop*, and a cell nobody routes through forwards nothing.
/// 2. Drive a real onion and give it a 50 ms window. The **control** went red: stepping the unmixed run in
///    10 ms ticks shows the payload lands at exactly 200 ms, two hops of link latency. A window has to be
///    measured against what it times ([[measured-not-chosen-deadlines]]).
/// 3. With a 500 ms window the control passed and the mixed case delivered at 200 ms too. Sweeping the mean
///    over `[0, 1s, 5s, 60s, 600s]` gave **200 ms every time** — flat. A 600 s mean cannot produce 200 ms, so
///    this is not an unlucky exponential draw: the delay reaches nothing.
///
/// The cause is `forward_send`: when `cover_interval != 0` the frame is queued to the outbox and the function
/// **returns before** the `mean_delay` branch. That precedence is deliberate — `config.rs:35` says the cover
/// schedule sets the send *times* — so this test pins both halves rather than calling the early return a bug.
///
/// Cover is on in every shipped configuration (`DEFAULT_COVER_INTERVAL`), so the second case below is what a
/// deployment runs, and it is the reason `mix_mean_delay = 120 ms` is inert in production (#181).
#[test]
fn the_mix_delay_holds_a_hop_only_when_cover_is_off_which_is_never_in_production() {
    /// Measured, not chosen: the unmixed two-hop transit is exactly 200 ms, so this is that plus margin.
    const PROMPT: Duration = Duration::from_millis(500);
    /// Past the ~10 s expected total of two Exp(5 s) draws plus transit.
    const PATIENT: Duration = Duration::from_millis(60_000);
    const NO_COVER: Duration = Duration(0);
    let slow = Duration::from_millis(5000);
    let cover = Duration::from_millis(200);

    // The epoch-0 onion directory of the composed cell: `spawn_composed_relay_cell` seeds relay `i` with
    // `[i; 32]`, and the public key is a function of that seed alone.
    let mut dir = MixDirectory::new();
    for i in 0..7usize {
        let ratchet = OnionKeyRatchet::new([i as u8; 32], Epoch::ZERO);
        dir.insert(Point::<F2>::at(i).coords(), ratchet.public().clone());
    }
    let meeting = meeting_line::<F2>(b"mix-delay-svc", Epoch::ZERO, &BeaconSeed::GENESIS).coords();
    let hop = (0..7).map(|i| Line::<F2>::at(i).coords()).find(|&l| l != meeting).expect("a second line");
    let payload = b"held or not held";
    let members = line_member_coords::<F2>(meeting);
    let fwd = seal_forward::<F2>(&[hop, meeting], &dir, ONION_T, payload, b"mix-seed").expect("sealed");
    let delivered = |sim: &Sim| {
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| members.contains(&recv) && from == ANONYMOUS && bytes == payload)
    };
    let run = |cover_iv: Duration, mix: Duration, window: Duration| {
        let mut sim = Sim::new(0xB1B2_C3C4);
        spawn_composed_relay_cell::<F2>(&mut sim, Config::default(), cover_iv, mix, true);
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(500));
        sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame.clone());
        sim.run_for(window);
        sim
    };

    // Cover OFF, mixing OFF — the control. Without this the two below could both be measuring a dead circuit.
    assert!(
        delivered(&run(NO_COVER, NO_MIX, PROMPT)),
        "an unmixed two-hop onion must land inside {PROMPT:?}; if it does not, this test is timing a broken          circuit and every conclusion below is about the wrong thing"
    );

    // Cover OFF, mixing ON — the branch at `threshold_router.rs:407` is reachable and holds the hop...
    let held = run(NO_COVER, slow, PROMPT);
    assert!(
        !delivered(&held),
        "with cover off, a 5 s mean must hold the hop past {PROMPT:?} — arriving anyway means `mix_mean_delay`          reached no router at all"
    );
    // ...and HOLDS it, rather than losing it. A relay that dropped what it held would satisfy the line above.
    let mut held = held;
    held.run_for(PATIENT);
    assert!(delivered(&held), "mixing must delay the onion, not discard it");

    // Cover ON, mixing ON — `forward_send` returns at the cover branch before it reads `mean_delay`, so the
    // hop is NOT held. This is the shipped configuration. Pinned deliberately: it is the documented precedence
    // (`config.rs:35`), and pinning it is what makes a silent change to that precedence visible.
    assert!(
        delivered(&run(cover, slow, PROMPT)),
        "with cover on, the mix delay must be bypassed — if this ever holds the hop, `forward_send`'s          precedence changed and `config.rs:35` no longer describes the code"
    );
}
