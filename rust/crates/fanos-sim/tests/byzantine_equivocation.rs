//! **Byzantine equivocation — the live §6.4 structural cross-attestation (audit #98).** A mediator
//! that stays fully live — heartbeats, pings, gossip, and diagnosis all pass — but forges its
//! `DiagAttest` polar-class report: it disagrees with itself about one of the 3 channel rates it
//! mediates. This is invisible to BOTH liveness monitoring (byzantine.rs, quorum-corroborated
//! liveness) and read-repair (withholding.rs, LRC availability) — the liar answers every ping
//! correctly and withholds nothing. Only the §6.2 polar sum-rule check, now fed live by the §6.4
//! cross-attestation this test exercises, catches it: spec §6.4, "an equivocating node produces
//! inconsistencies on all q+1 of its lines at once ... EXACTLY a nonzero syndrome (§6.3), and it
//! localizes the liar."

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fanos_diakrisis::Verdict;
use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{
    Command, Config, Duration, Effect, Engine, Input, Instant, Notification, OverlayNode, Triple,
};
use fanos_sim::{Sim, spawn_cell};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// A Byzantine mediator that is fully live — every heartbeat, ping, and gossip passes — but
/// forges its own outbound `DiagAttest` (spec §6.4): it perturbs one of the 3 channel rates it
/// attests for its polar class, so its own class becomes internally inconsistent, while
/// everything else about it (liveness, reads, replication) is honest. Mirrors
/// `ByzantineWithholder` (withholding.rs): a real `OverlayNode` with exactly one outbound frame
/// type intercepted and altered, not the node's own logic changed.
struct Equivocator {
    node: OverlayNode<F2>,
    forged: Arc<AtomicUsize>,
}

impl Engine for Equivocator {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let effects = self.node.step(now, input);
        let forged = &self.forged;
        effects.into_iter().map(|e| forge(e, forged)).collect()
    }

    fn address(&self) -> Triple {
        self.node.address()
    }
}

/// If `effect` is an outbound `DiagAttest`, corrupt its first attested channel rate (a gross
/// offset, far past `POLAR_TOLERANCE`) so the reporter's own 3 attested values no longer agree;
/// every other effect passes through unmodified. Counts each forgery in `forged` so the test can
/// confirm the attack genuinely happened, not merely that the wiring is a vacuous pass.
fn forge(effect: Effect, forged: &Arc<AtomicUsize>) -> Effect {
    let Effect::Send { to, frame } = &effect else {
        return effect;
    };
    let Ok((f, _)) = decode_frame(frame) else {
        return effect;
    };
    if f.frame_type() != Some(FrameType::DiagAttest) {
        return effect;
    }
    let mut body = f.body.to_vec();
    let Some(slot) = body.get_mut(0..8) else {
        return effect;
    };
    let Ok(raw) = <[u8; 8]>::try_from(&*slot) else {
        return effect;
    };
    slot.copy_from_slice(&(f64::from_le_bytes(raw) + 1000.0).to_le_bytes());
    forged.fetch_add(1, Ordering::Relaxed);
    let mut out = Vec::new();
    encode_frame(FrameType::DiagAttest.code(), &body, &mut out);
    Effect::Send {
        to: *to,
        frame: out,
    }
}

/// Spawn the full Fano cell with an [`Equivocator`] seated at Fano point `liar` and honest
/// `OverlayNode`s at every other point. Returns the coordinates indexed by point (matching
/// [`spawn_cell`]'s convention: `cell[i]` is the node at Fano point `i`) and the equivocator's
/// forge counter.
fn spawn_cell_with_equivocator(
    sim: &mut Sim,
    config: Config,
    liar: usize,
) -> (Vec<Triple>, Arc<AtomicUsize>) {
    let forged = Arc::new(AtomicUsize::new(0));
    let mut coords = Vec::with_capacity(7);
    for i in 0..7usize {
        let node: Box<dyn Engine> = if i == liar {
            Box::new(Equivocator {
                node: OverlayNode::<F2>::new(fano::point(i), config),
                forged: forged.clone(),
            })
        } else {
            Box::new(OverlayNode::<F2>::new(fano::point(i), config))
        };
        coords.push(sim.add(node));
    }
    (coords, forged)
}

#[test]
fn an_equivocating_mediator_is_localized_by_the_live_polar_check() {
    let liar = 3usize; // an arbitrary Fano point
    let mut sim = Sim::new(0xE9C1);
    let (cell, forged) = spawn_cell_with_equivocator(&mut sim, Config::default(), liar);
    sim.inject_all(&Command::StartHeartbeat);
    // Several heartbeats, so the liar's forged DiagAttest has propagated cell-wide (direct flood,
    // spec §6.4) before diagnosis.
    sim.run_for(Duration::from_millis(4000));

    sim.inject_all(&Command::Diagnose);
    sim.settle();

    let report = sim.report();
    let verdicts: Vec<_> = report.verdicts().map(|(who, v)| (who, v.clone())).collect();

    // Every HONEST observer localizes the liar's own polar class — not merely "some node".
    for (who, v) in &verdicts {
        if *who == cell[liar] {
            continue; // the liar's self-diagnosis is covered separately below
        }
        assert_eq!(
            *v,
            Verdict::Structural(vec![liar]),
            "node {who:?} must localize the equivocator to its polar point {liar}; all verdicts: {verdicts:?}"
        );
    }
    assert_eq!(
        verdicts.iter().filter(|(who, _)| *who != cell[liar]).count(),
        6,
        "all 6 honest observers reported a verdict"
    );

    // The actuation fires end-to-end (spec §6.4 + §6.3): the liar is quarantined AND escalated,
    // not merely diagnosed (`plan_healing`'s `Verdict::Structural` arm).
    assert!(
        report
            .notifications
            .iter()
            .any(|o| matches!(&o.note, Notification::Quarantined(c) if *c == cell[liar])),
        "the equivocator is locally quarantined: {verdicts:?}"
    );
    assert!(
        report
            .notifications
            .iter()
            .any(|o| matches!(&o.note, Notification::Escalated(mask) if mask & (1 << liar) != 0)),
        "the equivocator's residue is escalated to the parent for re-provisioning"
    );

    // Control — the forgery is genuine, not a vacuous pass: it actually corrupted ≥1 DiagAttest.
    assert!(
        forged.load(Ordering::Relaxed) >= 1,
        "the equivocator forged at least one DiagAttest (else the test proves nothing)"
    );
    // The liar is heartbeat-green throughout: this is invisible to liveness, unlike byzantine.rs —
    // only the structural check catches it.
    assert!(
        !report
            .notifications
            .iter()
            .any(|o| matches!(&o.note, Notification::PeerDown(c) if *c == cell[liar])),
        "the equivocator never goes heartbeat-down — this is not a liveness fault"
    );
}

#[test]
fn an_honest_cell_never_raises_a_structural_verdict() {
    // Control: the SAME live cross-attestation machinery, with no forgery, must never raise
    // Structural — so the positive test above is not passing vacuously from the wiring alone.
    let mut sim = Sim::new(0xE9C2);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(4000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    let report = sim.report();
    assert_eq!(cell.len(), 7);
    let verdicts: Vec<_> = report.verdicts().map(|(who, v)| (who, v.clone())).collect();
    assert!(
        !verdicts.iter().any(|(_, v)| matches!(v, Verdict::Structural(_))),
        "an honest cell never raises a structural (Byzantine) verdict: {verdicts:?}"
    );
    assert!(
        verdicts.iter().all(|(_, v)| *v == Verdict::Healthy),
        "an honest, fully-live cell diagnoses Healthy everywhere: {verdicts:?}"
    );
    assert_eq!(verdicts.len(), 7, "every node reported a verdict");
}
