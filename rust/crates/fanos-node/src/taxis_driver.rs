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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_pqcrypto::kem::HybridKemSecret;
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier};
use fanos_primitives::{BeaconSeed, BoundedMap, Epoch};
use fanos_quic::Client;
use fanos_runtime::{Command, Notification};
use fanos_taxis::checkpoint::ExecCertificate;
use fanos_taxis::consensus::{ConsensusEngine, ConsensusMsg, ConsensusProbe, Input, Output};
use fanos_taxis::da::Sampler;
use fanos_taxis::state::StateMachine;
use fanos_taxis::wire::{ShardMsg, TaxisApp, parse_app_body, shard_to_frame, to_frame, tx_to_frame};
use fanos_taxis::{Block, CellParams, SealedTx, SlashEvidence};
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
///
/// Public because it is the **longest quiet period consensus can legitimately produce**, which is exactly what an
/// integration harness needs to tell "still working" apart from "wedged": a driver merely between round attempts shows no
/// state change for just under this, so the harness's frozen threshold is derived as twice it
/// (`tests/common::FROZEN_SPAN`) rather than picked. Changing this changes that, which is the point.
pub const ROUND_TIMEOUT_MAX: Duration = Duration::from_secs(24);

/// Cap on the tx-gossip dedup set (commitments of transactions this node has already ingested + flooded). A
/// remote-chosen value (a sealed transaction's commitment) keys it, so it is bounded against a flood; a
/// well-behaved transaction whose commitment is evicted is simply re-gossiped once more (best-effort, like any
/// flood-dedup cache).
const SEEN_TX_CAP: usize = 8192;

/// Send a DA message to every other validator in the cell.
fn broadcast_shard(client: &Client, coords: &[Triple], me: u8, msg: &ShardMsg) {
    let frame = shard_to_frame(msg);
    for (p, &to) in coords.iter().enumerate() {
        if u8::try_from(p).unwrap_or(u8::MAX) != me {
            client.command(Command::Emit { to, frame: frame.clone() });
        }
    }
}

/// Emit a sampling request to every validator holding a shard this node still needs for `block`.
fn request_shards(client: &Client, coords: &[Triple], block: [u8; 32], missing: &[u8]) {
    for &index in missing {
        if let Some(&to) = coords.get(usize::from(index)) {
            client.command(Command::Emit { to, frame: shard_to_frame(&ShardMsg::Request { block, index }) });
        }
    }
}

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

/// The round timeout this host's **measured** round latency justifies, or [`ROUND_TIMEOUT_BASE`] before the first
/// sample.
///
/// `ROUND_TIMEOUT_BASE` was a chosen number whose own documentation justified it only as "comfortably longer than
/// a tick", and `ROUND_TIMEOUT_MAX` was bare. Together they cost a *240 s* stall: nine doublings before an
/// integration harness gave up, on a cell whose healthy heights finalize in well under a second.
///
/// So it is derived instead, and by the standard estimator rather than a new heuristic — a round timeout and a
/// retransmission timeout answer the identical question, "how long before I conclude the other side is not going
/// to answer?", and RFC 6298 answers it from measurement:
///
/// ```text
/// SRTT   <- (7*SRTT + R) / 8
/// RTTVAR <- (3*RTTVAR + |SRTT - R|) / 4
/// RTO     = SRTT + 4*RTTVAR
/// ```
///
/// The `4*RTTVAR` term is the whole point and is not a safety fudge: `k` deviations leave at most `1/k²` of the
/// mass beyond them (Chebyshev), so premature timeouts stay rare **without assuming a latency distribution** —
/// which matters here precisely because round latency under load has no distribution anyone has characterised.
///
/// Integer arithmetic, deliberately. RFC 6298 picks `1/8` and `1/4` *because they are shifts*; writing this in
/// floats would keep the constants and discard the reason they are those constants. It also matters beyond
/// taste — the output feeds a timer whose next value is computed from itself, and rounding drift in a
/// self-referential EWMA is a slow bias with no bound anyone has derived.
///
/// The **ceiling stays a constant** even though the operating point is now adaptive, because two other things
/// derive from it and both want the *longest legitimate quiet period*, not the typical one: `FROZEN_SPAN` in the
/// integration harness (`2 × ROUND_TIMEOUT_MAX`) and [`fanos_taxis::da::RESAMPLE_MAX_INTERVAL`]
/// (`ROUND_TIMEOUT_MAX / TICK_PERIOD`, machine-checked by `the_resample_cap_is_one_round_timeout_in_ticks`).
#[must_use]
fn estimated_round_timeout(rtt: Option<(Duration, Duration)>) -> Duration {
    match rtt {
        None => ROUND_TIMEOUT_BASE,
        Some((srtt, var)) => (srtt + var * 4).clamp(TICK_PERIOD, ROUND_TIMEOUT_MAX),
    }
}

/// Fold one **admissible** round-latency sample into the smoothed estimate — see [`estimated_round_timeout`].
///
/// Which samples are admissible is **Karn's algorithm**, and it is load-bearing rather than a refinement. The
/// driver can time a *height*, not a round: it holds the finalize edge, but the engine resets `round` on
/// finalization before the driver looks, so a height that needed three rounds is indistinguishable from one that
/// needed one. Folding those in would inflate the estimate exactly when the cell is struggling — the opposite of
/// what it is for. TCP has the identical ambiguity for retransmitted segments and resolves it the same way: do
/// not sample them, and let backoff cover them. The caller therefore passes only heights during which the round
/// timeout never fired.
#[must_use]
fn fold_round_latency(rtt: Option<(Duration, Duration)>, r: Duration) -> (Duration, Duration) {
    match rtt {
        // RFC 6298 §2.2, the first measurement.
        None => (r, r / 2),
        Some((srtt, var)) => {
            ((srtt * 7 + r) / 8, (var * 3 + srtt.abs_diff(r)) / 4)
        }
    }
}

/// A callback that turns a detected equivocation into a submittable **sealed slash transaction** — injected by
/// the node, which knows the concrete DROMOS state machine and holds the public keyper registry needed to seal.
/// The generic engine driver stays state-machine-agnostic; this closure carries the one DROMOS-specific step, so
/// a caught equivocation is automatically sealed and gossiped into the cell's mempool to be applied on-chain.
/// `None` for a driver that does not auto-submit slashes (a bare consensus test harness).
pub type SlashSealer = Arc<dyn Fn(&SlashEvidence) -> Option<SealedTx> + Send + Sync>;

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
    /// How to seal a detected equivocation into a submittable slash transaction, or `None` to only surface a
    /// [`TaxisEvent::Slashed`] without auto-submitting. Injected by the node (which holds the keyper registry).
    pub slash_sealer: Option<SlashSealer>,
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
    /// A validator was caught equivocating (the driver auto-submits the on-chain slash).
    Slashed {
        /// The equivocating validator's index.
        validator: u8,
    },
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
    probe: mpsc::Sender<oneshot::Sender<DriverProbe>>,
}

/// A validator's [`ConsensusProbe`] plus what only the **driver** can see: notifications lost before the engine
/// ever saw them.
///
/// The two belong together in a frozen cell's report. A validator stalled with `lagged > 0` was starved of input,
/// which is a transport question; one stalled with `lagged == 0` received everything the cell sent it, which makes
/// it a consensus question. Without the second number the first reading cannot be ruled out, and an unfalsifiable
/// explanation is worse than no explanation.
#[derive(Clone, Copy, Debug)]
pub struct DriverProbe {
    /// The engine's own position — see [`ConsensusProbe`].
    pub consensus: ConsensusProbe,
    /// Notifications dropped by the broadcast drainer (see the `lagged` counter in [`spawn_taxis`]). Cumulative.
    pub lagged: u64,
    /// Skeletons still being sampled (`Sampler::in_flight`). Read against `fanos_taxis::da::PENDING_CAP`: a validator
    /// stalled with this near the cap may be losing skeletons to eviction, and one stalled with it in single digits
    /// provably is not. That distinction was argued rather than measured once already.
    pub sampling: usize,
    /// The round timeout this driver is currently waiting out — the **measured** estimate, not the constant.
    ///
    /// Driver state, not engine state, which is why it is here: the engine has no clock. It is also the only way
    /// to check that [`estimated_round_timeout`] is *wired* rather than merely correct — unit tests prove the
    /// estimator follows its input, and only this says the driver is feeding it any. An estimate sitting exactly
    /// at `ROUND_TIMEOUT_BASE` on a cell that has been finalizing for minutes means no sample was ever admitted.
    pub round_timeout: Duration,
}

impl core::fmt::Display for DriverProbe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.consensus)?;
        if self.lagged > 0 {
            write!(f, " LAGGED={}", self.lagged)?;
        }
        if self.sampling > 0 {
            write!(f, " sampling={}/{}", self.sampling, fanos_taxis::da::PENDING_CAP)?;
        }
        // Always, unlike the two above: zero is not its uninteresting value. Reading `rto=1.5s` on a cell that has
        // been finalizing for minutes is the finding — it says the estimator was never fed — and a field that
        // hides at its default cannot report that.
        write!(f, " rto={:?}", self.round_timeout)?;
        Ok(())
    }
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

    /// Snapshot **why this validator sits where it does** — see [`ConsensusProbe`]. `None` if the driver has
    /// stopped. Distinct from [`snapshot`](Self::snapshot) because a frozen cell's ledger state is exactly what
    /// does *not* change: judging a stall needs the consensus position, and it exists only while the stall does.
    pub async fn probe(&self) -> Option<DriverProbe> {
        let (tx, rx) = oneshot::channel();
        self.probe.send(tx).await.ok()?;
        rx.await.ok()
    }
}

/// Spawn the live TAXIS driver for one validator on plane `F`, bound to `client`. Returns a [`TaxisHandle`].
/// Must run inside a tokio runtime. The node must be seated at `Point::at(params.me)` so its validator index
/// matches its overlay coordinate (the fan-out addresses peers by `Point::at(p).coords()`).
#[must_use]
#[allow(clippy::too_many_lines)] // the driver is one cohesive async orchestration loop (select over ticks,
// timeouts, submissions, and the DA/consensus/tx receive paths) — splitting it would only scatter shared state.
pub fn spawn_taxis<F, S>(client: Client, params: TaxisParams<S>) -> TaxisHandle<S>
where
    F: Field,
    S: StateMachine + Clone + Send + 'static,
{
    let (submit_tx, mut submit_rx) = mpsc::channel::<SealedTx>(64);
    let (events_tx, _) = broadcast::channel::<TaxisEvent>(256);
    let (query_tx, mut query_rx) = mpsc::channel::<oneshot::Sender<(u64, S)>>(16);
    let (probe_tx, mut probe_rx) = mpsc::channel::<oneshot::Sender<DriverProbe>>(16);
    let events_for_task = events_tx.clone();
    // Validator index p ↔ overlay coordinate Point::at(p) — the whole cell's addresses, once.
    // The validator index → overlay coordinate map. It starts at the canonical seating (validator `i` at
    // `Point::at(i)`) and is *maintained*, because the overlay reseats nodes: a coordinate collision or an
    // epoch reshuffle moves a peer, and `fanos-quic` proves the move on a live connection and reports it.
    //
    // A static map is not a simplification here, it is a silent eviction. Every consensus message this driver
    // sends is addressed by coordinate, and every one it receives is accepted only from a coordinate in this
    // list — so a peer that moved would have its votes dropped as "a frame from a stranger" while the votes
    // addressed to it went to the point it left. The cell would carry on without it, tolerating two such
    // losses and halting at the third, with no error anywhere: the moved validator is simply gone.
    let mut coords: Vec<Triple> = (0..Plane::<F>::N as usize).map(|i| Point::<F>::at(i).coords()).collect();
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
    // Consensus messages the drainer itself lost. The forwarding channel below is unbounded, but the *broadcast*
    // it drains is not: if this task is descheduled long enough for the client to overrun the ring, tokio reports
    // `Lagged(n)` and those `n` notifications are gone. TAXIS never retransmits a vote, so each one can be the
    // difference between a height finalizing and a validator wedging — and until now the loss was **silent**, which
    // is the one property that makes a defect unfalsifiable. Counting it does not prevent it; it makes the
    // hypothesis testable from a frozen cell's own failure message (see `DriverProbe`).
    let lagged = Arc::new(AtomicU64::new(0));
    let lagged_drainer = Arc::clone(&lagged);
    let drainer = tokio::spawn(async move {
        loop {
            match broadcast_rx.recv().await {
                Ok(
                    note @ (Notification::App { .. }
                    | Notification::BeaconReady { .. }
                    | Notification::PeerMoved { .. }),
                ) => {
                    if note_tx.send(note).is_err() {
                        break; // the engine task ended
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    lagged_drainer.fetch_add(n, Ordering::Relaxed);
                }
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
        // How to auto-submit a caught equivocation as an on-chain slash (moved out of `params` before it is
        // otherwise consumed above). `None` on a driver that only surfaces the slash as an event.
        let slash_sealer = params.slash_sealer;

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
        // The adaptive estimate and the two things Karn's rule needs to decide whether a height is samplable:
        // when it began, and whether its round timeout ever fired. `None` until the first admissible sample, so
        // behaviour before one is byte-identical to the fixed base.
        let mut rtt: Option<(Duration, Duration)> = None;
        let mut height_started = start;
        let mut timed_out_this_height = false;
        // The height of the last execution checkpoint we surfaced, so each is emitted exactly once.
        let mut last_ckpt: Option<u64> = None;
        // Tx-gossip dedup: a bounded set of transaction commitments this node has already ingested + gossiped,
        // so a received transaction floods the cell exactly once and a committed (pruned) one does not
        // re-circulate. Bounded ([`SEEN_TX_CAP`]) against a commitment flood.
        let mut seen_txs: BoundedMap<[u8; 32], ()> = BoundedMap::new(SEEN_TX_CAP);
        // Data-availability transport (spec §6): dispersed shards this node serves + skeletons it is sampling.
        let mut da = Sampler::new(me);

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    // Re-request the shards still missing from every block being sampled, BEFORE stepping the engine,
                    // so a reply can land within this tick's window.
                    //
                    // Sampling had no retry, and that was the deeper defect behind both TAXIS liveness failures. A
                    // replica requests a missing shard the instant a skeleton arrives, but the proposer emits
                    // skeleton-then-shard peer by peer, so the request routinely reaches peer `p` *before* `p` has been
                    // dispersed its own shard. `p` holds nothing, answers nothing, and with no retry the requester waits
                    // forever for a shard that its peer has held all along. One proposal in flight loses that race
                    // sometimes (measured: a 7-node cell executing on 6 of 7 validators, the seventh stranded at genesis
                    // permanently, and the same suite executing on 0 of 7 in the next run). Under SSLE all-propose there
                    // are N proposals racing at once and it loses reliably: no block ever finalized.
                    resample_pending(&client, &coords, me, &mut da);
                    // Ask for a body this validator is committed to but has never seen. Votes carry only a hash, so it
                    // can be locked on — or hold a commit certificate for — a block it never received, and then it will
                    // neither prepare it (it cannot execute what it does not have) nor accept any conflicting proposal.
                    // Measured live as four of seven validators frozen at genesis on `locked` refusals with an empty
                    // sampler. State sync does not cover it: that serves checkpoints, and a cell one block old has none.
                    // Protect the awaited skeleton from the sampler's insertion-order eviction before anything else
                    // touches it: under SSLE all-propose the cell produces one skeleton per validator per round, and
                    // the block being awaited is by definition an old one. See `Sampler::pin`.
                    da.pin(engine.awaited_body());
                    // Abandoned sampling is finished work: a skeleton for a height already decided can never be
                    // completed or needed, and it competes for a capped map with the block we are stuck on.
                    da.prune_below(engine.height());
                    if let Some(want) = engine.awaited_body()
                        && !da.is_sampling(&want)
                    {
                        broadcast_shard(&client, &coords, me, &ShardMsg::NeedSkeleton { block: want });
                    }
                    let outs = engine.step(Input::Tick);
                    drive(&mut engine, &client, &coords, me, outs, &events_for_task, &mut last_ckpt, slash_sealer.as_ref(), &mut seen_txs, &mut da);
                }
                () = tokio::time::sleep_until(timeout_deadline) => {
                    let outs = engine.step(Input::Timeout);
                    drive(&mut engine, &client, &coords, me, outs, &events_for_task, &mut last_ckpt, slash_sealer.as_ref(), &mut seen_txs, &mut da);
                    // This round did not finalize before its deadline: back off before injecting the next
                    // Timeout, so a slow (not failed) round is given more time rather than livelocked by a
                    // premature advance. A finalization anywhere resets it via the progress check below.
                    //
                    // It applies even when this validator holds a value to re-offer (a lock, or a polka observed
                    // via `Block::pol`). Suppressing it there is tempting — that retry is not the *identical*
                    // attempt backoff exists to space out, and a sub-quorum lock split heals through exactly those
                    // retries — and it measures **worse**: an interleaved A/B put the no-backoff variant at 0 of 4
                    // against 2 of 3 for this line as it stands. A round retried at base cadence preempts a round
                    // that would have completed, which is the livelock the backoff prevents, and no amount of "but
                    // the proposal differs" reasoning avoids it.
                    //
                    // It also makes this height inadmissible as a latency sample (Karn — see
                    // `fold_round_latency`): a height that needed more than one round says nothing about how long
                    // a *successful* round takes, and folding it in would raise the estimate precisely when the
                    // cell is already struggling.
                    timed_out_this_height = true;
                    round_timeout = next_round_timeout(round_timeout, false);
                    timeout_deadline = Instant::now() + round_timeout;
                }
                Some(tx) = submit_rx.recv() => {
                    // A locally-submitted transaction is ingested AND gossiped, so a single `handle.submit`
                    // (or a `fanos pay` client) seeds every validator's mempool, not just this one.
                    ingest_tx(&mut engine, &client, &coords, me, &mut seen_txs, &tx);
                }
                Some(reply) = query_rx.recv() => {
                    let _ = reply.send((engine.chain().next_height(), engine.chain().state().clone()));
                }
                Some(reply) = probe_rx.recv() => {
                    let _ = reply.send(DriverProbe {
                        consensus: engine.probe(),
                        lagged: lagged.load(Ordering::Relaxed),
                        sampling: da.in_flight(),
                        round_timeout,
                    });
                }
                note = note_rx.recv() => match note {
                    Some(Notification::App { body, from }) => match parse_app_body(&body) {
                        // A proposal arrives DA-dispersed: a payload-less skeleton (the full block rides as
                        // shards). Sample its shards from peers and admit it to the engine once reconstructed
                        // (spec §6). Only a known validator's skeleton is worth sampling.
                        Some(TaxisApp::Consensus(ConsensusMsg::Propose(skeleton))) => {
                            if coords.contains(&from) {
                                on_skeleton(&mut engine, &client, &coords, me, &mut da, &events_for_task, &mut last_ckpt, slash_sealer.as_ref(), &mut seen_txs, skeleton);
                            }
                        }
                        // Any other consensus message: accepted only from a known validator coordinate (its index
                        // also directs a state-sync reply back to the requester); a frame from a stranger is ignored.
                        Some(TaxisApp::Consensus(msg)) => {
                            if let Some(src) =
                                coords.iter().position(|c| *c == from).and_then(|p| u8::try_from(p).ok())
                            {
                                let outs = step_msg(&mut engine, &msg, src);
                                // A handed-over body ends the sampling for that block: it was obtained whole, so the
                                // pending entry is finished work competing for a capped map.
                                if let ConsensusMsg::Body(b) = &msg {
                                    da.forget(&b.hash());
                                }
                                drive(&mut engine, &client, &coords, me, outs, &events_for_task, &mut last_ckpt, slash_sealer.as_ref(), &mut seen_txs, &mut da);
                            }
                        }
                        // A submitted transaction: accepted from ANY sender — a client (the network ingress that
                        // makes the chain usable) or another validator's gossip — ingested into the mempool and
                        // flooded once to the rest of the cell.
                        Some(TaxisApp::Tx(tx)) => {
                            ingest_tx(&mut engine, &client, &coords, me, &mut seen_txs, &tx);
                        }
                        // A DA shard — a dispersed / sampled shard, or a peer's sampling request. Handled by the
                        // driver's DA layer; a reconstructed block enters the engine via `try_reconstruct`.
                        Some(TaxisApp::Shard(shard)) => {
                            on_shard(&mut engine, &client, &coords, me, &mut da, &events_for_task, &mut last_ckpt, slash_sealer.as_ref(), &mut seen_txs, shard, from);
                        }
                        None => {}
                    },
                    // Fixed-epoch cell: the seed/epoch are pinned at construction. A future rotation policy
                    // would re-derive the leader schedule + keyper line here at a height boundary.
                    // A peer proved it moved (§L1 reseating). Re-point its slot so the fan-out reaches it and its
                    // messages are still recognised as a validator's. Keyed by the coordinate it *held*, which is
                    // this map's own entry for it — a mover this driver never learned about would be
                    // indistinguishable from a stranger, which is exactly the state this arm exists to prevent.
                    Some(Notification::PeerMoved { old, new }) => {
                        if let Some(slot) = coords.iter_mut().find(|c| **c == old) {
                            *slot = new;
                        }
                    }
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
                let now = Instant::now();
                if !timed_out_this_height {
                    rtt = Some(fold_round_latency(rtt, now - height_started));
                }
                timed_out_this_height = false;
                height_started = now;
                round_timeout = estimated_round_timeout(rtt);
                timeout_deadline = now + round_timeout;
            }
        }
    });

    TaxisHandle { task, submit: submit_tx, events: events_tx, query: query_tx, probe: probe_tx }
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
        ConsensusMsg::CommitCert(cert) => Input::CommitCert(cert.clone()),
        // The body-recovery pair. `Body` deliberately does NOT go to `on_skeleton` like `Propose` does: it is a whole
        // block answering a decision this validator already holds, and the engine checks it against that decision.
        ConsensusMsg::NeedBody { block } => Input::NeedBody { from, block: *block },
        ConsensusMsg::Body(b) => Input::Body(b.clone()),
        ConsensusMsg::SyncResp { cert, snapshot } => {
            Input::SyncResp { cert: cert.clone(), snapshot: snapshot.clone() }
        }
    };
    engine.step(input)
}

/// Ingest a submitted transaction and gossip it to the cell **exactly once**. A transaction whose commitment
/// this node has already seen is dropped (so the flood terminates, and a committed/pruned transaction does not
/// re-circulate); otherwise it is submitted to the mempool, and **iff it was valid and newly added** it is
/// flooded to every other validator so the whole cell's mempool converges. Sealing to the keyper committee is
/// public, so admission here is intentionally permissive — a fee/stake mempool bound is the separate economic
/// layer (audit T-H5), not this transport concern.
fn ingest_tx<S: StateMachine>(
    engine: &mut ConsensusEngine<S>,
    client: &Client,
    coords: &[Triple],
    me: u8,
    seen: &mut BoundedMap<[u8; 32], ()>,
    tx: &SealedTx,
) {
    let commit = tx.commit();
    if seen.contains_key(&commit) {
        return;
    }
    if engine.submit(tx.clone()) {
        seen.insert(commit, ());
        let frame = tx_to_frame(tx);
        for (p, &to) in coords.iter().enumerate() {
            if u8::try_from(p).unwrap_or(u8::MAX) != me {
                client.command(Command::Emit { to, frame: frame.clone() });
            }
        }
    }
}

/// Act on a batch of engine outputs: broadcast every `Send` to the cell (and deliver it back to the local
/// engine, cascading until quiescent), and surface `Committed`/`Slash`/`Reward` as [`TaxisEvent`]s. The local
/// self-delivery is what lets the proposer prepare its own proposal (`ConsensusEngine::maybe_propose`).
#[allow(clippy::too_many_arguments)]
fn drive<S: StateMachine>(
    engine: &mut ConsensusEngine<S>,
    client: &Client,
    coords: &[Triple],
    me: u8,
    outs: Vec<Output>,
    events: &broadcast::Sender<TaxisEvent>,
    last_ckpt: &mut Option<u64>,
    slash_sealer: Option<&SlashSealer>,
    seen: &mut BoundedMap<[u8; 32], ()>,
    da: &mut Sampler,
) {
    let mut queue: VecDeque<Output> = outs.into_iter().collect();
    while let Some(out) = queue.pop_front() {
        match out {
            Output::Send(msg) => {
                if let ConsensusMsg::Propose(block) = &msg {
                    // DA dispersal (spec §6): rather than broadcasting the full block, broadcast the small
                    // *skeleton* and disperse ONE erasure shard to each validator. Availability is then
                    // established by real peer sampling — not the proposer's self-report — while every voter
                    // still agrees on the identical block (the skeleton shares the full block's header hash).
                    let hash = block.hash();
                    let shards = block.da_shards();
                    let skeleton_frame = to_frame(&ConsensusMsg::Propose(block.skeleton()));
                    for (p, &to) in coords.iter().enumerate() {
                        let Ok(idx) = u8::try_from(p) else { continue };
                        if idx != me {
                            client.command(Command::Emit { to, frame: skeleton_frame.clone() });
                            if let Some(shard) = shards.get(p) {
                                let deliver = ShardMsg::Deliver { block: hash, index: idx, data: shard.clone() };
                                client.command(Command::Emit { to, frame: shard_to_frame(&deliver) });
                                engine.note_shard_sent();
                            }
                        }
                    }
                    // Keep my own shard to serve samplers; deliver the FULL block (which I hold) to my own engine.
                    if let Some(mine) = shards.get(usize::from(me)) {
                        da.hold(hash, mine.clone());
                    }
                } else {
                    let frame = to_frame(&msg);
                    // Broadcast to every *other* validator (point-to-point fan-out — no gossip primitive needed
                    // for a small structured cell where every validator is directly addressable).
                    for (p, &to) in coords.iter().enumerate() {
                        if u8::try_from(p).unwrap_or(u8::MAX) != me {
                            client.command(Command::Emit { to, frame: frame.clone() });
                        }
                    }
                }
                // Deliver back to ourselves, cascading any further outputs (prepare → commit → reveal …). For a
                // Propose this is the FULL block: the proposer already holds its own payload.
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
                let _ = events.send(TaxisEvent::Slashed { validator: ev.validator });
                // Auto-submit the on-chain slash: seal the equivocation proof into a transaction and ingest +
                // gossip it exactly like a client tx, so the whole cell includes it and the equivocator's bonded
                // stake is debited in executed state. Idempotent — the DROMOS slash guard rejects a duplicate.
                if let Some(sealer) = slash_sealer
                    && let Some(sealed) = sealer(&ev)
                {
                    ingest_tx(engine, client, coords, me, seen, &sealed);
                }
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

/// Handle a received DA **skeleton** (a payload-less proposal): buffer it, request every shard it is missing
/// from that shard's holder, and — once enough shards are gathered — reconstruct the full block and admit it to
/// the engine. This is where "PREPARE gated on DA sampling" (spec §6) becomes real: a withholding proposer whose
/// shards no quorum will serve never reconstructs here, so this validator never admits the block, never PREPAREs.
#[allow(clippy::too_many_arguments)]
fn on_skeleton<S: StateMachine>(
    engine: &mut ConsensusEngine<S>,
    client: &Client,
    coords: &[Triple],
    me: u8,
    da: &mut Sampler,
    events: &broadcast::Sender<TaxisEvent>,
    last_ckpt: &mut Option<u64>,
    slash_sealer: Option<&SlashSealer>,
    seen: &mut BoundedMap<[u8; 32], ()>,
    skeleton: Block,
) {
    let hash = skeleton.hash();
    // Rank the skeleton into the SSLE round-0 lottery **before** sampling its body, because the lottery ranks the
    // *ticket* and the ticket rides in the skeleton. Admitting a proposal only after reconstruction is what deadlocked
    // an all-propose round: N proposals each needed a sampling round trip, the collection window is one tick, and so
    // every replica ranked a different subset and split its PREPARE. A no-op outside SSLE round 0.
    let ranked = engine.step(Input::Skeleton { block: skeleton.clone() });
    drive(engine, client, coords, me, ranked, events, last_ckpt, slash_sealer, seen, da);
    if !da.begin(skeleton) {
        return; // already sampling this block — do not discard the shards gathered so far
    }
    request_shards(client, coords, hash, &da.missing(&hash));
    admit_if_recovered(engine, client, coords, me, da, events, last_ckpt, slash_sealer, seen, hash);
}

/// Handle a received DA **shard** message: store a delivered shard (feeding any pending reconstruction, and
/// retaining my own dispersed shard to serve later requests), or answer a sampling request with my shard.
#[allow(clippy::too_many_arguments)]
fn on_shard<S: StateMachine>(
    engine: &mut ConsensusEngine<S>,
    client: &Client,
    coords: &[Triple],
    me: u8,
    da: &mut Sampler,
    events: &broadcast::Sender<TaxisEvent>,
    last_ckpt: &mut Option<u64>,
    slash_sealer: Option<&SlashSealer>,
    seen: &mut BoundedMap<[u8; 32], ()>,
    msg: ShardMsg,
    from: Triple,
) {
    match msg {
        ShardMsg::Deliver { block, index, data } => {
            engine.note_shard_taken();
            if let Some(full) = da.accept(block, index, data) {
                admit(engine, client, coords, me, da, events, last_ckpt, slash_sealer, seen, full);
            }
        }
        ShardMsg::Request { block, index } => {
            // Our own shard if we hold it, else re-derive the requested one from the whole block if we have it.
            // Without the fallback a shard has exactly one custodian, so a dispersal that never arrived is
            // unobtainable however many peers hold the block — including the proposer, which built it.
            let shard = da.serve(&block, index).or_else(|| engine.shard_of(&block, index));
            // Counted at the handling site rather than inside the engine: the answer comes from `da` first, which the
            // engine cannot see, so only here is `served` the truth about what went back on the wire.
            engine.note_shard_ask(shard.is_some());
            if let Some(shard) = shard {
                let deliver = ShardMsg::Deliver { block, index, data: shard.clone() };
                client.command(Command::Emit { to: from, frame: shard_to_frame(&deliver) });
            }
        }
        // A peer is committed to a block it never received. If we hold it, hand back the skeleton — the requester then
        // samples and admits it on the ordinary path, so this recovery needs no path of its own.
        ShardMsg::NeedSkeleton { block } => {
            let skeleton = engine.skeleton_of(&block);
            engine.note_skeleton_ask(skeleton.is_some());
            if let Some(skeleton) = skeleton {
                client.command(Command::Emit { to: from, frame: to_frame(&ConsensusMsg::Propose(skeleton)) });
            }
        }
    }
}

/// Re-request every shard still missing from each block being sampled.
///
/// Idempotent and cheap: a `Request` for a shard the peer holds is answered with one `Deliver`, and one for a shard it
/// does not hold is dropped — so retrying costs a message and converges the moment the peer has been dispersed its own.
/// Bounded by [`fanos_taxis::da::PENDING_CAP`] blocks × the cell size.
///
/// After [`RESAMPLE_ESCALATE`] fruitless rounds the request stops addressing each shard's custodian and goes to the
/// whole cell, because a custodian is only the right address while dispersal worked.
fn resample_pending(client: &Client, coords: &[Triple], me: u8, da: &mut Sampler) {
    for (block, missing) in da.due() {
        request_shards(client, coords, block, &missing);
        // …and the block's **proposer**, which is the one peer that cannot be empty. See `Sampler::proposer_of`.
        let Some(proposer) = da.proposer_of(&block).filter(|&p| p != me) else { continue };
        let Some(&to) = coords.get(usize::from(proposer)) else { continue };
        for &index in missing.iter().filter(|&&i| i != proposer) {
            client.command(Command::Emit { to, frame: shard_to_frame(&ShardMsg::Request { block, index }) });
        }
    }
}


/// Try to reconstruct a buffered skeleton from the shards gathered so far. On success, rebuild the full block and
/// admit it to the engine exactly like an ordinary proposal, driving the resulting outputs (its PREPARE, …).
#[allow(clippy::too_many_arguments)]
fn admit_if_recovered<S: StateMachine>(
    engine: &mut ConsensusEngine<S>,
    client: &Client,
    coords: &[Triple],
    me: u8,
    da: &mut Sampler,
    events: &broadcast::Sender<TaxisEvent>,
    last_ckpt: &mut Option<u64>,
    slash_sealer: Option<&SlashSealer>,
    seen: &mut BoundedMap<[u8; 32], ()>,
    hash: [u8; 32],
) {
    if let Some(full) = da.reconstruct(&hash) {
        admit(engine, client, coords, me, da, events, last_ckpt, slash_sealer, seen, full);
    }
}

/// Admit a **reconstructed** block to the engine exactly like an ordinary proposal, driving the outputs it produces.
#[allow(clippy::too_many_arguments)]
fn admit<S: StateMachine>(
    engine: &mut ConsensusEngine<S>,
    client: &Client,
    coords: &[Triple],
    me: u8,
    da: &mut Sampler,
    events: &broadcast::Sender<TaxisEvent>,
    last_ckpt: &mut Option<u64>,
    slash_sealer: Option<&SlashSealer>,
    seen: &mut BoundedMap<[u8; 32], ()>,
    full: Block,
) {
    // `from` is unused for a Propose; the reconstructed block carries its own proposer index.
    let outs = step_msg(engine, &ConsensusMsg::Propose(full), me);
    drive(engine, client, coords, me, outs, events, last_ckpt, slash_sealer, seen, da);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_estimator_follows_the_measured_latency_instead_of_the_chosen_base() {
        // The whole point: on a host whose rounds take 200 ms the timeout must land near 200 ms, not at the 1.5 s
        // someone once typed. Before any sample it *is* the base — genesis behaviour is unchanged.
        assert_eq!(estimated_round_timeout(None), ROUND_TIMEOUT_BASE, "no measurement yet ⇒ the documented base");

        let fast = Duration::from_millis(200);
        let mut rtt = None;
        for _ in 0..40 {
            rtt = Some(fold_round_latency(rtt, fast));
        }
        let settled = estimated_round_timeout(rtt);
        assert!(
            settled < ROUND_TIMEOUT_BASE,
            "a cell finalizing in {fast:?} must not keep waiting {ROUND_TIMEOUT_BASE:?} — settled at {settled:?}"
        );
        assert!(settled >= fast, "…and never below the latency it measured: {settled:?} < {fast:?}");

        // It tracks a step change rather than staying where it started.
        let slow = Duration::from_secs(3);
        for _ in 0..40 {
            rtt = Some(fold_round_latency(rtt, slow));
        }
        assert!(
            estimated_round_timeout(rtt) > settled * 4,
            "the estimate must follow latency upward, not stay at {settled:?}"
        );
    }

    #[test]
    fn the_deviation_term_is_what_absorbs_jitter() {
        // `SRTT + 4*RTTVAR`, not `SRTT`. Two hosts with the SAME mean and different jitter must get different
        // timeouts, or the estimator is just an average and a jittery host times out on half its good rounds.
        // Falsifying the `4*RTTVAR` term collapses these two to equal, which is exactly what this asserts against.
        let mean = Duration::from_millis(400);
        let (mut steady, mut jittery) = (None, None);
        for i in 0..40 {
            steady = Some(fold_round_latency(steady, mean));
            // Same mean, alternating ±300 ms. `saturating_sub` rather than `-`: the swing is smaller than the
            // mean by construction, and a checked form would put an unwrap in a test that is about arithmetic.
            let jitter = Duration::from_millis(300);
            let swing = if i % 2 == 0 { mean + jitter } else { mean.saturating_sub(jitter) };
            jittery = Some(fold_round_latency(jittery, swing));
        }
        assert!(
            estimated_round_timeout(jittery) > estimated_round_timeout(steady),
            "a jittery host must be given more headroom than a steady one at the same mean: {:?} vs {:?}",
            estimated_round_timeout(jittery),
            estimated_round_timeout(steady)
        );
    }

    #[test]
    fn the_estimate_stays_inside_the_bounds_the_rest_of_the_system_derives_from() {
        // Below a tick the driver would time out rounds it has not even ticked; above the ceiling it would break
        // two constants derived FROM that ceiling (`FROZEN_SPAN`, `RESAMPLE_MAX_INTERVAL`).
        let tiny = Duration::from_micros(1);
        let mut rtt = None;
        for _ in 0..40 {
            rtt = Some(fold_round_latency(rtt, tiny));
        }
        assert_eq!(estimated_round_timeout(rtt), TICK_PERIOD, "clamped up to one tick");

        let huge = ROUND_TIMEOUT_MAX * 10;
        let mut rtt = None;
        for _ in 0..40 {
            rtt = Some(fold_round_latency(rtt, huge));
        }
        assert_eq!(estimated_round_timeout(rtt), ROUND_TIMEOUT_MAX, "clamped down to the ceiling");
    }

    #[test]
    fn the_resample_cap_is_one_round_timeout_in_ticks() {
        // `Sampler::due` backs off geometrically and caps the gap at `RESAMPLE_MAX_INTERVAL`, whose whole justification
        // is that it equals the cell's own progress unit: a sampler that wakes at least once per round timeout can
        // never be the reason a round is lost. That claim spans two crates — the constant lives in `fanos-taxis`, which
        // cannot see this driver's clock — so it is asserted here, in the one crate that owns both.
        //
        // A derived constant with no link back to its derivation is a magic number with a nice comment: change
        // `TICK_PERIOD` or `ROUND_TIMEOUT_MAX` and nothing would have complained.
        let ticks_per_round_timeout = ROUND_TIMEOUT_MAX.as_millis() / TICK_PERIOD.as_millis();
        assert_eq!(
            u128::from(fanos_taxis::da::RESAMPLE_MAX_INTERVAL),
            ticks_per_round_timeout,
            "the resample cap must stay one round timeout ({ROUND_TIMEOUT_MAX:?}) at one tick per {TICK_PERIOD:?}"
        );
    }

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
