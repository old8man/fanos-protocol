//! Live **TAXIS consensus over the real transport** — the side-car driver (task B, `docs/design-taxis.md` §7).
//!
//! The TAXIS [`ConsensusEngine`] is sans-I/O: `step(Input) -> Vec<Output>`, with its own `Input`/`Output` shape
//! that is *not* the overlay [`Engine`](fanos_runtime::Engine) trait. It therefore cannot compose into the
//! `Box<dyn Engine>` stack the node runs; instead this module drives it as a **side-car tokio task** bound to a
//! node's [`Client`], exactly as [`crate::role_loop`] drives the self-organization controller. The task bridges:
//!
//! * **receive** — subscribe to the client's notifications; a [`Notification::App`] body (the App-overlay `0x70`
//!   frame TAXIS rides, [`fanos_taxis::wire`]) is decoded to a [`ConsensusMsg`] and stepped into the engine;
//! * **broadcast** — an [`Output::Send`] means "to every validator". The transport is point-to-point, so the
//!   driver fans the App frame out to each cell coordinate ([`Command::Emit`]) **and** delivers it back to the
//!   local engine (the proposer prepares its own block like everyone else — `maybe_propose`'s contract);
//! * **drive** — a periodic `Tick` lets the elected leader propose; a slower `Timeout` advances a stuck round;
//! * **sinks** — `Committed`/`Slash`/`Reward` become observable [`TaxisEvent`]s; a snapshot query exposes the
//!   finalized ledger.
//!
//! **Scope.** This runs one cell at a fixed epoch — the beacon `seed`/`epoch` are pinned at construction (the
//! agreed genesis beacon). Per-epoch committee rotation (updating the leader schedule + keyper line mid-chain)
//! is a distinct dynamic-committee protocol question and is not attempted here; the beacon subscription is
//! wired so a rotation policy can slot in. DA is satisfied from the gossiped block (a full `Propose` carries
//! its payload, so every shard is present and `reconstruct_payload` verifies it against `da_commit`); dispersed
//! DA sampling is the erasure-store's concern, not the consensus datapath's.

use std::collections::VecDeque;

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_pqcrypto::kem::HybridKemSecret;
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier};
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_quic::Client;
use fanos_runtime::{Command, Notification};
use fanos_taxis::checkpoint::ExecCertificate;
use fanos_taxis::consensus::{ConsensusEngine, ConsensusMsg, Input, Output};
use fanos_taxis::state::StateMachine;
use fanos_taxis::wire::to_frame;
use fanos_taxis::{CellParams, SealedTx, SlashEvidence};
use fanos_vrf::pqvrf::MerkleVrfSecret;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval_at};

use crate::crosscell_dir::publish_checkpoint;

/// How often the driver ticks the engine — the leader proposes on a tick, so this bounds block time.
const TICK_PERIOD: Duration = Duration::from_millis(150);

/// The **base** round-timeout: how long the driver waits before injecting a `Timeout` (advancing a round whose
/// proposer never proposed) at a fresh height. Comfortably longer than a tick so the happy path finalizes well
/// before a round ever times out.
const ROUND_TIMEOUT_BASE: Duration = Duration::from_millis(1_500);

/// The **cap** on the adaptively-backed-off round timeout. A round that fails to finalize by its deadline
/// doubles the next round's timeout (see [`next_round_timeout`]) up to this ceiling — so a genuinely slow round
/// (a CPU-loaded host whose multi-round threshold gathers take longer than the base timeout) is given more
/// time rather than prematurely advanced, which under a fixed timeout **livelocks** the height (each premature
/// advance reshuffles the leader before the in-flight round can commit). Bounded so a truly failed leader is
/// still skipped in finite time. Reset to [`ROUND_TIMEOUT_BASE`] the moment the height advances (progress).
const ROUND_TIMEOUT_MAX: Duration = Duration::from_secs(24);

/// The next round timeout: reset to [`ROUND_TIMEOUT_BASE`] on progress (the height advanced — a fresh height
/// restarts at round 0), else double the current timeout up to [`ROUND_TIMEOUT_MAX`] (Tendermint-style
/// exponential backoff, so consensus adapts its pace to the host's actual round latency instead of livelocking).
#[must_use]
fn next_round_timeout(current: Duration, progressed: bool) -> Duration {
    if progressed {
        ROUND_TIMEOUT_BASE
    } else {
        (current * 2).min(ROUND_TIMEOUT_MAX)
    }
}

/// The identity + genesis a validator's engine is built from — the agreed cell configuration
/// ([`ConsensusEngine::new`]). Everything a node needs to join a live TAXIS cell, gathered into one struct.
pub struct TaxisParams<S> {
    /// The BFT quorum parameters of the cell (`CellParams::FANO` for the reference cell).
    pub cell: CellParams,
    /// This node's validator index (its Fano point index — it must be seated at `Point::at(me)`).
    pub me: u8,
    /// This node's consensus signing key.
    pub signer: HybridSigSecret,
    /// This node's anti-MEV decryption (KEM) secret.
    pub kem_secret: HybridKemSecret,
    /// Every validator's signature verifier, indexed by validator index.
    pub verifiers: Vec<HybridVerifier>,
    /// The agreed on-chain decryption-key commitment ([`fanos_taxis::keyper`]).
    pub keyper_commit: [u8; 32],
    /// The epoch beacon seed (fixes the leader schedule + keyper line).
    pub seed: BeaconSeed,
    /// The epoch this cell runs at.
    pub epoch: Epoch,
    /// The funded genesis ledger.
    pub genesis_state: S,
    /// The per-block reward pool distributed to commit-cert signers (`0` = no reward).
    pub reward_per_block: u64,
    /// **Secret-leader sortition** (SSLE) registration, or `None` to run the public deterministic leader.
    /// When present, round 0 becomes the min-ticket lottery over the elected line — the winner stays secret
    /// until it proposes, so an adversary cannot pre-aim a DoS/bribe at the single upcoming proposer.
    pub sortition: Option<SortitionParams>,
}

/// A node's **secret-leader sortition** registration (SSLE, spec §10.1) — its own post-quantum Merkle-VRF
/// secret plus every validator's pre-registered root, over a per-epoch bounded domain based at height `base`.
/// A node derives its `secret` deterministically from its identity and publishes its root; the collected
/// `roots` are agreed committee config, exactly like the signature `verifiers`. Re-issued each epoch to rotate
/// the bounded VRF domain (the anti-grinding registration fence — a key is fixed before the beacon it is used
/// with).
pub struct SortitionParams {
    /// This node's Merkle-VRF secret (proves its own round-0 ticket witness).
    pub secret: MerkleVrfSecret,
    /// Every validator's pre-registered Merkle-VRF root, indexed by validator index (like `verifiers`).
    pub roots: Vec<[u8; 32]>,
    /// The chain height at VRF index 0 — this registration's base, so the ticket index is `height − base`.
    pub base: u64,
}

/// An observable event from a running TAXIS cell — the driver's `Output` sinks, surfaced for callers/tests.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TaxisEvent {
    /// A block finalized: the ledger extended to `height` with `block_hash`.
    Committed {
        /// The finalized height.
        height: u64,
        /// The finalized block hash.
        block_hash: [u8; 32],
    },
    /// A validator was caught equivocating (the driver would apply the economic slash).
    Slashed {
        /// The equivocating validator's index.
        validator: u8,
    },
    /// A finalized block's reward split among its commit-certificate signers (`(validator, amount)`).
    Rewarded(Vec<(u8, u64)>),
    /// The cell's **execution checkpoint** advanced: a fresh `Q`-quorum [`ExecCertificate`] over the executed
    /// state at a new height — the artifact a parent cell attests for shared security ([`spawn_checkpoint_publisher`]).
    Checkpointed(ExecCertificate),
}

/// A handle to a running TAXIS driver: submit sealed transactions, observe [`TaxisEvent`]s, snapshot the ledger.
pub struct TaxisHandle<S> {
    /// The driver task; dropping it does not stop the task (it runs until the client's notification stream ends).
    pub task: JoinHandle<()>,
    submit: mpsc::Sender<SealedTx>,
    events: broadcast::Sender<TaxisEvent>,
    query: mpsc::Sender<oneshot::Sender<(u64, S)>>,
}

impl<S> TaxisHandle<S> {
    /// Submit a sealed transaction into this validator's mempool. `false` if the driver has stopped.
    pub async fn submit(&self, tx: SealedTx) -> bool {
        self.submit.send(tx).await.is_ok()
    }

    /// Subscribe to the cell's [`TaxisEvent`] stream (finalizations, slashes, rewards).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<TaxisEvent> {
        self.events.subscribe()
    }

    /// Snapshot the finalized ledger: `(next_height, state)`. `None` if the driver has stopped.
    pub async fn snapshot(&self) -> Option<(u64, S)> {
        let (tx, rx) = oneshot::channel();
        self.query.send(tx).await.ok()?;
        rx.await.ok()
    }
}

/// Spawn the live TAXIS driver for one validator on plane `F`, bound to `client`. Returns a [`TaxisHandle`].
/// Must run inside a tokio runtime. The node must be seated at `Point::at(params.me)` so its validator index
/// matches its overlay coordinate (the fan-out addresses peers by `Point::at(p).coords()`).
#[must_use]
pub fn spawn_taxis<F, S>(client: Client, params: TaxisParams<S>) -> TaxisHandle<S>
where
    F: Field,
    S: StateMachine + Clone + Send + 'static,
{
    let (submit_tx, mut submit_rx) = mpsc::channel::<SealedTx>(64);
    let (events_tx, _) = broadcast::channel::<TaxisEvent>(256);
    let (query_tx, mut query_rx) = mpsc::channel::<oneshot::Sender<(u64, S)>>(16);
    let events_for_task = events_tx.clone();
    // Validator index p ↔ overlay coordinate Point::at(p) — the whole cell's addresses, once.
    let coords: Vec<Triple> = (0..Plane::<F>::N as usize).map(|i| Point::<F>::at(i).coords()).collect();
    let me = params.me;

    // **Drainer task.** The client's `subscribe()` stream is a *lossy* broadcast: a subscriber that falls
    // behind has messages dropped (`RecvError::Lagged`). The engine task below does slow hybrid-PQ verification
    // inline, so draining the broadcast *from it* would lag under a burst and silently drop consensus messages
    // (which TAXIS never retransmits) — the cause of stalled finality. This task does no crypto: it drains the
    // broadcast at memory speed and forwards the two relevant notifications into an **unbounded** channel, so
    // the engine consumes them losslessly at its own pace. (QUIC delivery is already reliable; the only loss
    // was here.)
    let mut broadcast_rx = client.subscribe();
    let (note_tx, mut note_rx) = mpsc::unbounded_channel::<Notification>();
    let drainer = tokio::spawn(async move {
        loop {
            match broadcast_rx.recv().await {
                Ok(note @ (Notification::App { .. } | Notification::BeaconReady { .. })) => {
                    if note_tx.send(note).is_err() {
                        break; // the engine task ended
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let task = tokio::spawn(async move {
        let _drainer = drainer; // tie the drainer's lifetime to the engine task
        let mut engine = ConsensusEngine::new(
            params.cell,
            params.me,
            params.signer,
            params.kem_secret,
            params.verifiers,
            params.keyper_commit,
            params.seed,
            params.epoch,
            params.genesis_state,
        );
        engine.set_reward_per_block(params.reward_per_block);
        if let Some(s) = params.sortition {
            engine.enable_sortition(s.secret, s.roots, s.base);
        }

        // Delay the FIRST tick by a full period rather than firing it immediately (tokio's `interval` fires
        // tick 0 at once). The leader proposes on a tick, so an immediate first tick makes it propose height 1
        // before the other validators' drivers have finished spawning and subscribing to the consensus stream
        // — those late nodes miss the height-1 proposal, and since TAXIS drops off-height messages with no
        // catch-up, they wedge at genesis forever while the ready quorum advances without them (the dromos_quic
        // stall: 2 of 7 stuck at h0). One period's grace lets every driver subscribe first. The timeout is
        // likewise delayed so a spurious immediate round-advance cannot shuffle the height-1 leader pre-proposal.
        let start = Instant::now();
        let mut tick = interval_at(start + TICK_PERIOD, TICK_PERIOD);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The round timeout is ADAPTIVE (audit: the fixed timeout livelocked a CPU-loaded cell). It starts at
        // ROUND_TIMEOUT_BASE — delayed one period, like the first tick, so a spurious immediate advance cannot
        // shuffle the height-1 leader before it proposes — then backs off each round that fails to finalize and
        // resets on height progress (see next_round_timeout + the progress check after the select).
        let mut round_timeout = ROUND_TIMEOUT_BASE;
        let mut timeout_deadline = start + round_timeout;
        let mut last_height = engine.chain().next_height();
        // The height of the last execution checkpoint we surfaced, so each is emitted exactly once.
        let mut last_ckpt: Option<u64> = None;

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let outs = engine.step(Input::Tick);
                    drive(&mut engine, &client, &coords, me, outs, &events_for_task, &mut last_ckpt);
                }
                () = tokio::time::sleep_until(timeout_deadline) => {
                    let outs = engine.step(Input::Timeout);
                    drive(&mut engine, &client, &coords, me, outs, &events_for_task, &mut last_ckpt);
                    // This round did not finalize before its deadline: back off before injecting the next
                    // Timeout, so a slow (not failed) round is given more time rather than livelocked by a
                    // premature advance. A finalization anywhere resets it via the progress check below.
                    round_timeout = next_round_timeout(round_timeout, false);
                    timeout_deadline = Instant::now() + round_timeout;
                }
                Some(tx) = submit_rx.recv() => {
                    engine.submit(tx);
                }
                Some(reply) = query_rx.recv() => {
                    let _ = reply.send((engine.chain().next_height(), engine.chain().state().clone()));
                }
                note = note_rx.recv() => match note {
                    Some(Notification::App { body, from }) => {
                        // Map the sender's overlay coordinate to its validator index (a frame from an unknown
                        // coordinate is ignored); the index directs a state-sync reply back to the requester.
                        if let (Some(msg), Some(src)) = (
                            ConsensusMsg::from_bytes(&body),
                            coords.iter().position(|c| *c == from).and_then(|p| u8::try_from(p).ok()),
                        ) {
                            let outs = step_msg(&mut engine, &msg, src);
                            drive(&mut engine, &client, &coords, me, outs, &events_for_task, &mut last_ckpt);
                        }
                    }
                    // Fixed-epoch cell: the seed/epoch are pinned at construction. A future rotation policy
                    // would re-derive the leader schedule + keyper line here at a height boundary.
                    Some(_) => {}
                    None => break, // the drainer stopped (client shut down)
                },
            }
            // Progress check: whenever the height advances — a block finalized (via votes on the happy path, or
            // after a skipped round) — reset the adaptive round timeout to its base, since a fresh height starts
            // at round 0. This makes the backoff self-correcting: it grows only while a single height is stuck.
            let height = engine.chain().next_height();
            if height != last_height {
                last_height = height;
                round_timeout = ROUND_TIMEOUT_BASE;
                timeout_deadline = Instant::now() + round_timeout;
            }
        }
    });

    TaxisHandle { task, submit: submit_tx, events: events_tx, query: query_tx }
}

/// Map a received consensus message to the engine input and step it. A `Propose` carries the full block, so
/// every DA shard is present — the engine's `reconstruct_payload` still checks them against `da_commit`. `from`
/// is the sender's validator index; it matters only for a `SyncReq`, whose certified-state reply the engine
/// directs back to that requester (`Output::SendTo`).
fn step_msg<S: StateMachine>(engine: &mut ConsensusEngine<S>, msg: &ConsensusMsg, from: u8) -> Vec<Output> {
    let input = match msg {
        ConsensusMsg::Propose(b) => Input::Propose { block: b.clone(), shards: Box::new(b.da_shards().map(Some)) },
        ConsensusMsg::Vote(sv) => Input::Vote(sv.clone()),
        ConsensusMsg::Reveal(r) => Input::Reveal(r.clone()),
        ConsensusMsg::ExecVote(v) => Input::ExecVote(v.clone()),
        ConsensusMsg::SyncReq { have_height } => Input::SyncReq { from, have_height: *have_height },
        ConsensusMsg::SyncResp { cert, head, snapshot } => {
            Input::SyncResp { cert: cert.clone(), head: *head, snapshot: snapshot.clone() }
        }
    };
    engine.step(input)
}

/// Act on a batch of engine outputs: broadcast every `Send` to the cell (and deliver it back to the local
/// engine, cascading until quiescent), and surface `Committed`/`Slash`/`Reward` as [`TaxisEvent`]s. The local
/// self-delivery is what lets the proposer prepare its own proposal (`ConsensusEngine::maybe_propose`).
fn drive<S: StateMachine>(
    engine: &mut ConsensusEngine<S>,
    client: &Client,
    coords: &[Triple],
    me: u8,
    outs: Vec<Output>,
    events: &broadcast::Sender<TaxisEvent>,
    last_ckpt: &mut Option<u64>,
) {
    let mut queue: VecDeque<Output> = outs.into_iter().collect();
    while let Some(out) = queue.pop_front() {
        match out {
            Output::Send(msg) => {
                let frame = to_frame(&msg);
                // Broadcast to every *other* validator (point-to-point fan-out — no gossip primitive needed
                // for a small structured cell where every validator is directly addressable).
                for (p, &to) in coords.iter().enumerate() {
                    if u8::try_from(p).unwrap_or(u8::MAX) != me {
                        client.command(Command::Emit { to, frame: frame.clone() });
                    }
                }
                // Deliver back to ourselves, cascading any further outputs (prepare → commit → reveal …).
                for more in step_msg(engine, &msg, me) {
                    queue.push_back(more);
                }
            }
            Output::SendTo { to, msg } => {
                // A directed reply (a `SyncResp` serving a lagging peer's `SyncReq`): emit only to that peer.
                let frame = to_frame(&msg);
                if to == me {
                    for more in step_msg(engine, &msg, me) {
                        queue.push_back(more);
                    }
                } else if let Some(&coord) = coords.get(to as usize) {
                    client.command(Command::Emit { to: coord, frame });
                }
            }
            Output::Committed { height, block_hash } => {
                let _ = events.send(TaxisEvent::Committed { height, block_hash });
            }
            Output::Slash(ev) => {
                let _ = events.send(TaxisEvent::Slashed { validator: slash_validator(&ev) });
            }
            Output::Reward(split) => {
                let _ = events.send(TaxisEvent::Rewarded(split));
            }
        }
    }
    // A fresh execution checkpoint may have formed as ExecVotes reached a quorum during this batch; surface it
    // exactly once per height (the artifact `spawn_checkpoint_publisher` anchors for cross-cell shared security).
    if let Some(cert) = engine.latest_checkpoint()
        && last_ckpt.is_none_or(|h| cert.height > h)
    {
        *last_ckpt = Some(cert.height);
        let _ = events.send(TaxisEvent::Checkpointed(cert.clone()));
    }
}

/// Spawn a **cross-cell checkpoint publisher** for a running cell: subscribe to `handle`'s events and, for each
/// new [`TaxisEvent::Checkpointed`], publish the [`ExecCertificate`] to the cell's checkpoint slot in the
/// overlay store ([`crate::crosscell_dir::publish_checkpoint`]) under `cell_id` and `epoch` — where a parent
/// cell reads and attests it ([`crate::crosscell_dir::attest_children`]). This is the live producer side of
/// hierarchical shared security; a node that is not a cross-cell bridge simply does not spawn it. Must run in a
/// tokio runtime.
#[must_use]
pub fn spawn_checkpoint_publisher<S>(
    client: Client,
    cell_id: u32,
    epoch: Epoch,
    handle: &TaxisHandle<S>,
) -> JoinHandle<()> {
    let mut events = handle.subscribe();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(TaxisEvent::Checkpointed(cert)) => {
                    let _ = publish_checkpoint(&client, cell_id, epoch, &cert).await;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// The equivocating validator named by a slash proof.
fn slash_validator(ev: &SlashEvidence) -> u8 {
    ev.validator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_round_timeout_backs_off_exponentially_caps_and_resets_on_progress() {
        // A stuck height doubles the round timeout each failed round…
        let mut t = ROUND_TIMEOUT_BASE;
        t = next_round_timeout(t, false);
        assert_eq!(t, ROUND_TIMEOUT_BASE * 2, "one failed round doubles the timeout");
        t = next_round_timeout(t, false);
        assert_eq!(t, ROUND_TIMEOUT_BASE * 4);
        // …up to the cap, and never beyond it (a truly failed leader is still skipped in finite time).
        for _ in 0..20 {
            t = next_round_timeout(t, false);
        }
        assert_eq!(t, ROUND_TIMEOUT_MAX, "backoff is bounded by the cap");
        assert_eq!(next_round_timeout(t, false), ROUND_TIMEOUT_MAX, "it never grows past the cap");
        // Progress (the height advanced) snaps it straight back to the base — the backoff is self-correcting,
        // so it grows ONLY while a single height is stuck, never accumulating across a healthy chain.
        assert_eq!(next_round_timeout(t, true), ROUND_TIMEOUT_BASE, "a finalized height resets the timeout");
        assert_eq!(next_round_timeout(ROUND_TIMEOUT_BASE, true), ROUND_TIMEOUT_BASE);
        // The base is strictly below the cap (the backoff has room to grow), the invariant the fix relies on.
        assert!(ROUND_TIMEOUT_BASE < ROUND_TIMEOUT_MAX, "the base must leave headroom to back off");
    }
}
