//! **D5 — selective forwarding / data withholding.** A Byzantine storage node stays fully live —
//! heartbeats, gossip, self-diagnosis, and replication all pass — but **withholds** every stored value it
//! is asked for: it drops its own `Value` (Get-response) frames. This is the case that is *invisible to
//! first-order (liveness) monitoring* — the node is heartbeat-green, so no crash is ever diagnosed — yet
//! it silently refuses reads (spec §3.3 Byzantine row).
//!
//! FANOS's fundamental answer (§L4) is the **projective LRC erasure code** (#115): a value lives as `N=7`
//! point-shards, and a `Get` gathers a *recoverable* shard-set from across the cell and reconstructs. A live
//! withholder drops only the `Value` carrying *its own* shard — but a single missing shard is always
//! recoverable, so the reader reconstructs the value from the other survivors' shards. This validates the
//! threat-model D5 row on the real engine (not a formula): the read succeeds *despite* a heartbeat-green
//! withholder at the responsible coordinate, and the withholder is **not** mistaken for a crash — only the
//! read-side erasure redundancy, never liveness monitoring, defeats it.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fanos_diakrisis::Verdict;
use fanos_field::{F2, Field};
use fanos_geometry::Plane;
use fanos_primitives::{hash::label, map_to_point};
use fanos_runtime::{
    Command, Config, Duration, Effect, Engine, Input, Instant, OverlayNode, Triple,
};
use fanos_sim::Sim;
use fanos_wire::{FrameType, decode_frame};

/// A Byzantine storage node that is fully live but withholds every value it stores: it runs a **real**
/// `OverlayNode` and forwards every effect it produces EXCEPT its own `Value` (Get-response) frames,
/// which it drops (counting them in `withheld`, so a test can confirm the withholding actually happened).
/// Heartbeats (`Ping`/`Pong`), gossip, diagnosis, the `Put` ack, and replication (`Publish`) all pass — so
/// the node is heartbeat-green and undiagnosable as a crash — it simply never answers a read.
struct ByzantineWithholder<F: Field> {
    node: OverlayNode<F>,
    withheld: Arc<AtomicUsize>,
}

impl<F: Field> Engine for ByzantineWithholder<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let mut out = Vec::new();
        for effect in self.node.step(now, input) {
            if is_value_response(&effect) {
                self.withheld.fetch_add(1, Ordering::Relaxed); // drop it — the value is withheld
            } else {
                out.push(effect);
            }
        }
        out
    }

    fn address(&self) -> Triple {
        self.node.address()
    }
}

/// Whether an effect is an outbound `Value` (Get-response) frame — the one thing the withholder drops.
fn is_value_response(effect: &Effect) -> bool {
    matches!(
        effect,
        Effect::Send { frame, .. }
            if matches!(
                decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
                Some(FrameType::Value)
            )
    )
}

/// Spawn the full Fano cell with a [`ByzantineWithholder`] seated at `withhold_point` and honest
/// `OverlayNode`s at every other point — a real cell with one silent storage adversary. Returns the node
/// coordinates and the withholder's drop counter (how many `Value` responses it has suppressed).
fn spawn_cell_with_withholder(
    sim: &mut Sim,
    config: Config,
    withhold_point: Triple,
) -> (Vec<Triple>, Arc<AtomicUsize>) {
    let withheld = Arc::new(AtomicUsize::new(0));
    let mut coords = Vec::new();
    for point in Plane::<F2>::points() {
        let node: Box<dyn Engine> = if point.coords() == withhold_point {
            Box::new(ByzantineWithholder {
                node: OverlayNode::<F2>::new(point, config),
                withheld: withheld.clone(),
            })
        } else {
            Box::new(OverlayNode::<F2>::new(point, config))
        };
        coords.push(sim.add(node));
    }
    (coords, withheld)
}

#[test]
fn a_live_withholding_responsible_node_is_defeated_by_erasure_reconstruction() {
    let key = b"withheld-key".to_vec();
    // The responsible coordinate for the key — where the withholder is seated.
    let responsible = map_to_point::<F2>(label::STORAGE, &key).coords();

    let mut sim = Sim::new(9);
    let (cell, withheld) = spawn_cell_with_withholder(&mut sim, Config::default(), responsible);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // establish liveness

    // The querier is offline during the Put, so it never receives its own shard — its later Get must gather
    // shards from across the cell rather than reconstruct locally, exercising the read past the withholder.
    let putter = cell.iter().find(|&&c| c != responsible).copied().unwrap();
    let querier = cell
        .iter()
        .find(|&&c| c != responsible && c != putter)
        .copied()
        .unwrap();
    sim.crash(querier);

    // The put routes to the withholder (the responsible node): it erasure-codes the value and distributes the
    // shards (`Publish` passes) to the live members, then — being a withholder — refuses to serve reads of it.
    sim.inject(
        putter,
        Command::Put {
            key: key.clone(),
            value: b"served-anyway".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1500));

    // The querier rejoins and relearns the cell.
    sim.recover(querier);
    sim.inject(querier, Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(3000));

    // It reads the key. The responsible node is UP and heartbeat-green but silent on the read (it drops the
    // `Value` carrying its own shard); the Get gathers the *other* survivors' shards and reconstructs — a
    // single missing shard is always recoverable, so the withholder's silence cannot deny the read.
    sim.inject(querier, Command::Get { key: key.clone() });
    sim.run_for(Duration::from_millis(3000));

    let got = sim
        .report()
        .retrievals()
        .filter(|(who, _, _)| *who == querier)
        .last()
        .map(|(_, _, v)| v.map(<[u8]>::to_vec));
    assert_eq!(
        got,
        Some(Some(b"served-anyway".to_vec())),
        "the value is reconstructed from the surviving shards despite the responsible node withholding its own (erasure LRC, §L4)"
    );
    // Control — the withholding is genuine, not a vacuous pass: the withholder actually dropped ≥1 of its
    // own `Value` responses, so the successful read above reconstructed around it, not from it.
    assert!(
        withheld.load(Ordering::Relaxed) >= 1,
        "the withholder suppressed at least one Value response (else the test proves nothing)"
    );

    // The withholder is heartbeat-green throughout: a full diagnosis localizes no fault, so withholding is
    // invisible to first-order liveness monitoring — only the read-side redundancy above defeats it.
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    assert!(
        !sim.report()
            .verdicts()
            .any(|(_, v)| matches!(v, Verdict::Localized(_) | Verdict::Escalate(_))),
        "the live withholder is never diagnosed as a crash — D5 is invisible to liveness monitoring"
    );
}
