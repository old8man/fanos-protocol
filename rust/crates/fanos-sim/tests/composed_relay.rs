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
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

mod common;

use common::spawn_composed_relay_cell;
use fanos_field::{F2, F7};
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::Sim;

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
    let _no_relay = spawn_composed_relay_cell::<F2>(&mut quiet, Config::default(), cover, false);
    quiet.inject_all(&Command::StartHeartbeat);
    quiet.run_for(window);
    let baseline = quiet.report().metrics.frames_sent;

    let mut relayed = Sim::new(0xC0FE);
    let _cell = spawn_composed_relay_cell::<F2>(&mut relayed, Config::default(), cover, true);
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
    let control = spawn_composed_relay_cell::<F7>(&mut quiet, Config::default(), cover, false);
    assert_eq!(control.len(), 57, "PG(2,7) seats 57 points");
    quiet.inject_all(&Command::StartHeartbeat);
    quiet.run_for(window);
    let baseline = quiet.report().metrics.frames_sent;

    let mut relayed = Sim::new(0xC0FE);
    let cell = spawn_composed_relay_cell::<F7>(&mut relayed, Config::default(), cover, true);
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
