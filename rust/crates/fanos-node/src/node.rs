//! The running node: composes the sans-I/O engine behind the QUIC driver.
//!
//! Phase 1 runs the `OverlayNode` engine (membership, liveness, L4 storage, DIAKRISIS healing)
//! behind the production QUIC transport. Relay / service / exit engines compose in later phases; the
//! node advertises its role set via JOIN so the cell learns what it offers. The heavy lifting —
//! endpoint, connection pool, event loop — lives in the driver; this type is the supervisor that
//! wires identity, bootstrap, and the engine together and exposes control.

use core::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fanos_diaulos::StaticKeypair;
use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_onoma::{Address, Epoch, lookup_key};
use fanos_pqcrypto::SeedRng;
use fanos_quic::{
    Client, Directory, Fabric, NodeHandle, ProteusConfig, spawn_self_certifying_persistent_over,
};
use fanos_keygen::recovery::{RecoveryAction, StallDetector, recovery_decision};
use fanos_runtime::{Command, Config as OverlayConfig, Engine, Notification};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::{ExitPolicy, serve_exit, spawn_exit_publisher, spawn_mix_directory_feeder, spawn_mix_publisher};

use fanos_core::roles::{Capability, Demand, Role, RoleController, RoleSet as CoreRoleSet};
use fanos_primitives::NodeId;
use fanos_quic::NodeCredentials;

use fanos_primitives::BeaconSeed;

use crate::config::{IngressParams, NodeConfig, RoleSet};
use crate::role_loop::{
    Assignment, LoadSensor, SelfOrgConfig, SelfOrganization, role_capacity, spawn_load_sensor,
    spawn_self_organization,
};
use crate::error::NodeError;
use crate::identity;
use crate::resolve::{ResolvedService, verify_descriptor};

/// Validate the **POROS ingress** role's parameters (`docs/design-anonymity-substrate.md` §6), so bad
/// provisioning fails `start` here rather than producing a line that silently cannot serve.
///
/// The threshold is checked against the roster the same way the service role's is, and the floor is **2**, not
/// 1: a `1`-of-`n` sharing hands every member the descriptor whole, which is exactly the "seize `< t` reveals
/// nothing" property POROS is built on, and `emit_reshare` already refuses to propagate one. Rejecting it at
/// startup is better than rejecting it at the first rotation.
///
/// This node's own coordinate is **not** checked against the roster here, because a deployed node's coordinate
/// is drawn by its VRF at spawn and is not known yet at this point. A host that finds itself off the line
/// simply never holds a share position the line asks for.
fn ingress_params(config: &NodeConfig) -> Result<Option<IngressParams>, NodeError> {
    if !config.roles.ingress {
        return Ok(None);
    }
    let params = config.ingress.as_ref().ok_or_else(|| {
        NodeError::Config(
            "the ingress role hosts a member of a POROS ingress line and needs ingress parameters (the \
             community secret, this node's dealt descriptor share, the dealing's public binding, the line \
             roster and its threshold) — run `fanos ingress-deal` to produce them"
                .to_owned(),
        )
    })?;
    if params.threshold < 2 || params.threshold > params.line.len() {
        return Err(NodeError::Config(format!(
            "the ingress threshold {} must be in 2..={} (the line has {} members); a threshold of 1 would \
             hand every member the whole descriptor",
            params.threshold,
            params.line.len(),
            params.line.len(),
        )));
    }
    if params.community.is_empty() {
        return Err(NodeError::Config(
            "the ingress role needs a non-empty community secret — it is the enumeration-resistance input \
             of the §6 derivation, and an empty one makes the line computable by anyone holding the beacon"
                .to_owned(),
        ));
    }
    Ok(Some(params.clone()))
}

/// The mixnet's per-hop cooperation threshold: how many of a hop line's `q+1` members must combine to peel one
/// onion layer. A relay's `ThresholdRouter` gathers this many partials; an anonymous client's `--threshold`
/// MUST match, since it seals each layer for exactly this many members.
///
/// **Derived from the plane, not fixed.** This was `const MIX_THRESHOLD: usize = 2` — correct for a Fano line's
/// three points and silently wrong everywhere else, because a hop then falls to any *two* corrupt members
/// however wide the line is, while the Byzantine tolerance `f = ⌊(n−1)/3⌋` grows with the plane. Two points lie
/// on exactly one line, so each corrupt *pair* captures one hop; at `q = 2` the tolerance is `f = 2 = t`, so
/// exactly one of seven lines falls and one line cannot be both ends of a circuit — end-to-end deanonymization
/// is *impossible*. That is an accident of `f = t`. Above Fano the pairs outrun the lines: 45 % of hops
/// captured at `q = 4`, 80 % at `q = 7`, essentially all at `q = 31` (`docs/audit.md` E7).
///
/// The bound: under the platform's own tolerance the corrupt *density* is `f/n = ⌊(n−1)/3⌋/n → 1/3`, so a line
/// of `m` points carries about `m/3` corrupt in expectation, and the threshold preserving Fano's margin at any
/// `m` is
///
/// ```text
/// t = ⌈2m/3⌉
/// ```
///
/// At `m = 3` that is exactly `2` — **the previous constant, unchanged at the default plane.** The value was
/// right; it was never generalized. With it, hop capture *falls* as the plane grows (0.143 → 0.011 → 0.009 →
/// 0.00003) instead of rising to certainty, which is what makes `--plane-order 4|7|31` the sound advice
/// [`warn_if_plane_cannot_anonymize`](crate) already gives.
///
/// **Liveness is the cost.** A wider hop needs two thirds of its line reachable to peel — the same *ratio*
/// Fano already runs at, so the trade is the one BFT makes everywhere else, but it is a real one and the mixnet
/// liveness tests are what should confirm it.
#[must_use]
pub const fn mix_threshold(line_size: usize) -> usize {
    // The mixnet's name for the line law, which lives beside the plane because a hop is not the only thing
    // that needs it: a rendezvous line's occupancy floor and a threshold-hosted descriptor want the same
    // `⌈2m/3⌉` for the same reason, and three restatements of one formula is three chances to drift.
    fanos_geometry::line_threshold(line_size)
}

/// Whether a coalition **inside the tolerated fault budget** can capture the two distinct lines that name a
/// circuit's two endpoints — the predicate that decides whether drawing a fresh circuit per dial is safe.
///
/// `false` means first-and-last correlation is **structurally impossible**, not merely unlikely: naming both
/// ends costs `2t − 1` corrupted members (two distinct lines meet in exactly one point) and that exceeds
/// `f = ⌊(n−1)/3⌋`. `true` means it is possible, and then the *accumulation* matters.
///
/// ## Why this is the guard question, and why the answer is not a policy
///
/// FANOS draws a fresh circuit per dial (`RendezvousRoute::draw`), which is what makes successive dials
/// unlinkable. Tor abandoned that for entry **guards**, because with a fresh entry every circuit the chance of
/// *eventually* drawing a hostile one goes to 1. Whether that argument transfers here is decided by this
/// predicate and then by arithmetic, not by taste — and the answer is plane-dependent and **non-monotonic**,
/// because `t = ⌈2(q+1)/3⌉` crosses divisibility boundaries. Over 1000 dials, drawing both ends fresh:
///
/// | `q` | both capturable | `P(one line)` | `P(ever correlated)` | with a pinned entry |
/// |---|---|---|---|---|
/// | 2, 3, 4 | **no** | 0.14 / 0.05 / 0.01 | **0 %** | — |
/// | 5 | yes | 0.067 | **99.1 %** | 6.7 % |
/// | 7 | yes | 0.009 | 5.8 % | 0.9 % |
/// | 8 | yes | 0.030 | 64.2 % | 3.0 % |
/// | 11 | yes | 0.014 | 19.5 % | 1.4 % |
/// | 31 | yes | 3e-5 | ~0 % | ~0 % |
///
/// So **on every plane this platform recommends, fresh-per-dial is strictly right**: a guard would buy nothing
/// against an impossibility and would cost the unlinkability that fresh circuits exist for. The guard question
/// only opens where this returns `true` and the per-dial square is large enough to accumulate — `q = 5` and
/// `q = 8` are the sharp cases, and `q = 5` is the worst plane here exactly as it is on liveness spare.
///
/// A deployment that widens the plane therefore inherits a decision the base cell never had to make, and
/// nothing told it so until this existed.
#[must_use]
pub const fn correlation_within_budget(line_size: usize) -> bool {
    // `q + 1 = line_size`, so `n = q² + q + 1`. The budget itself is IMPORTED rather than re-derived.
    //
    // This comment used to assert the identity — "the same `f` every quorum in the platform is sized
    // against" — while restating the formula on the very next line, which is the worst of both: move the
    // canon and the copy keeps computing the old value while the comment keeps asserting the new one, and
    // nothing fails. `fault_budget`'s own doc names this outcome: "exactly the copy that drifts."
    //
    // The bodies were byte-identical (`n.saturating_sub(1) / 3` on both sides), so this changes no value
    // today — only who owns the formula. Both are `const fn`, so this stays a `const fn`.
    let q = line_size.saturating_sub(1);
    let n = q * q + q + 1;
    let f = fanos_runtime::fault_budget(n);
    f >= 2 * mix_threshold(line_size) - 1
}

/// The mix threshold on the default plane, `PG(2,2)`: a 3-point line, `2`-of-`3`.
///
/// Kept as a named value for the client CLI's default, which cannot see a plane before it parses one.
pub const DEFAULT_MIX_THRESHOLD: usize = mix_threshold(3);

/// 32 fresh bytes of OS entropy — the mix router's per-run key seeds (a relay node only).
fn os_entropy_32() -> Result<[u8; 32], NodeError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| NodeError::Config(format!("OS entropy failed: {e}")))?;
    Ok(bytes)
}

/// Spawn the wall-clock **epoch driver**: the root tick that periodically issues `Command::AdvanceEpoch`,
/// so the beacon anchors emit their partials, a threshold round assembles, `Notification::BeaconReady`
/// fires, and the reshuffle loop rotates the VRF coordinate, the PROTEUS wire shape, and the forward-secure
/// onion keys (§L3, §7.6). Without this nothing advances the epoch and the whole moving-target defence stays
/// pinned at genesis for the node's entire life. Only spawned when beacon params are configured (a bare
/// overlay has no clock to drive). The task ends when the engine stops (`command` returns `false`).
fn spawn_epoch_driver(client: Client, period: Duration) -> JoinHandle<()> {
    // Supervised: the sharpest case in the crate. Nothing else advances the epoch, so this actor's death
    // silently disarms the whole moving-target defence while every surface goes on reporting healthy (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        // If a tick is missed under load, fire once and carry on — never burst a backlog of epoch advances.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate tick so the node has a full period to connect and sync before its first advance.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if !client.command(Command::AdvanceEpoch) {
                break; // the engine actor has stopped
            }
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::EpochDriver, &supervised, task)
}

/// How many consecutive epoch-driver periods with no beacon advance confirm a stall. Set above the safe-stall
/// window depth (`BeaconWindow::DEPTH = 3`, `fanos-quic`) so a lagging-but-live cell — whose clock still
/// advances, only late — is never mistaken for a frozen one before the recovery trigger fires.
const RECOVERY_PATIENCE: usize = 4;

/// Actuate the recovery decision for the current live anchor set (audit §4). Both non-trivial regimes now
/// **escalate to the recovery authority** rather than self-issue: a reshare (Regime A) changes the sharing
/// threshold and a re-genesis (Regime B) mints a fresh key, so — per audit §2.1 — both must be AUTHORIZED by
/// the beacon's authority (a node holds no authority secret and cannot sign either). A node detects the
/// condition and escalates; the operator / parent then issues the authenticated `BeaconNode::reshare_trigger`
/// / `RecoveryAuthorization`. Returns `(generation, threshold)` unchanged — no state advances until the
/// authority actually acts.
fn actuate_recovery(live: &[u8], threshold: usize, generation: u64, epoch: Epoch) -> (u64, usize) {
    match recovery_decision(live, threshold) {
        RecoveryAction::ProactiveReshare { survivors, new_threshold } => {
            // A node cannot sign the authenticated reshare trigger (§2.1) — escalate for the authority to issue it.
            tracing::warn!(target: "fanos::recovery", new_threshold, survivors = survivors.len(),
                "beacon thinning — escalating for an authorized proactive reshare (audit §4 Regime A / §2.1)");
            (generation, threshold)
        }
        RecoveryAction::RequestRegenesis { survivors } => {
            tracing::warn!(target: "fanos::recovery", epoch = epoch.get(), survivors = survivors.len(),
                "beacon frozen below threshold — escalating for an authorized re-genesis (audit §4 R-C1)");
            (generation, threshold)
        }
        RecoveryAction::None => (generation, threshold),
    }
}

/// Spawn the **recovery auto-trigger** (audit §4 R-C1): the production caller that turns a beacon freeze into
/// action, closing the "`reshare_trigger` has zero production callers" gap. Beside the epoch driver it watches
/// this node's own `BeaconReady`/`PeerDown` notifications; when the clock has not advanced for
/// [`RECOVERY_PATIENCE`] periods it derives the live anchor set and applies [`recovery_decision`]:
/// - **Regime A** — a lower honest-majority threshold still buys headroom while `≥ t` anchors remain: escalate
///   for an authorized proactive reshare (a reshare changes the threshold, so — §2.1 — the authority must sign
///   the trigger; a node holds no authority secret and cannot self-issue one);
/// - **Regime B** — already below threshold, the key is gone: escalate for an authorized re-genesis (the
///   single-writer authority's decision, actuated by [`BeaconNode::rebootstrap`]).
///
/// To emit one trigger per generation rather than one per node, only the **deterministic coordinator** — the
/// lowest-index live anchor — fires; every node computes the same coordinator as their down-views converge.
/// `anchors` is the cell's candidate anchor coordinates in holder-index order (`anchors[i]` ↔ index `i + 1`).
/// The recovery watcher's mutable state (audit §4): the stall detector plus the tracked live-beacon epoch, the
/// down-anchor set, the current threshold, and the last-triggered generation. Separated from the spawn loop so
/// its state transitions and the coordinator election are unit-visible.
struct RecoveryWatcher {
    detector: StallDetector,
    last_epoch: Epoch,
    down: std::collections::BTreeSet<Triple>,
    threshold: usize,
    generation: u64,
    /// Consecutive stall confirmations since the last epoch advance — the **failover clock** for the
    /// coordinator election (see [`on_tick`](Self::on_tick)).
    confirmations: u32,
}

/// The transport-shaping config a node starts with, or `None` for plaintext QUIC (§13.4).
///
/// Extracted from `start_over` so the three decisions it makes are nameable rather than buried in an
/// argument list: whether shaping is on at all, which morph selects it, and which secrets are accepted
/// beside the one emitted under.
///
/// **`to_vec` and not a move, at both halves.** The config's copies are `Zeroizing` and stay that way, so
/// they are wiped when the config drops even though PROTEUS needs plain buffers to derive shapes from.
fn proteus_config(config: &NodeConfig) -> Option<ProteusConfig> {
    let secret = config.proteus_secret.as_ref()?;
    let mut proteus = match config.proteus_environment {
        Some(env) => ProteusConfig::auto(secret.to_vec(), env),
        None => ProteusConfig::with_morph(secret.to_vec(), config.proteus_morph),
    };
    // The rollover's receive-only half (#13): accepted, never emitted under, so phase 1 of a community-secret
    // rotation changes nothing on the wire.
    proteus.accept_secrets = config.proteus_accept_secrets.iter().map(|s| s.to_vec()).collect();
    Some(proteus)
}

impl RecoveryWatcher {
    fn new(threshold: usize) -> Self {
        Self {
            detector: StallDetector::new(RECOVERY_PATIENCE),
            last_epoch: Epoch::ZERO,
            down: std::collections::BTreeSet::new(),
            threshold,
            generation: 0,
            confirmations: 0,
        }
    }

    /// Fold one notification into the watched state: a `PeerDown` marks an anchor unreachable.
    ///
    /// **Progress is no longer read from here.** The epoch used to arrive as `BeaconReady` on the same lossy
    /// broadcast, so this watcher could sleep through the round that proves its anchors live; it comes from
    /// the router's latest-state watch in [`on_tick`](Self::on_tick) instead (#86). A dropped `PeerDown` is
    /// survivable in a way a dropped advance was not — see the failover in `on_tick`.
    fn on_note(&mut self, note: &Notification) {
        if let Notification::PeerDown(coord) = note {
            self.down.insert(*coord);
        }
    }

    /// The live anchor holder-index set (`i + 1` for each not-down candidate, in index order).
    fn live_anchors(&self, anchors: &[Triple]) -> Vec<u8> {
        anchors
            .iter()
            .enumerate()
            .filter(|(_, c)| !self.down.contains(*c))
            .map(|(i, _)| u8::try_from(i).unwrap_or(u8::MAX).saturating_add(1))
            .collect()
    }

    /// One epoch-driver tick: if a stall is confirmed and THIS node is the deterministic coordinator (the
    /// lowest-index live anchor), actuate the recovery decision, so the cell emits one action, not one per node.
    /// Returns whether this node **actuated** on this tick — the only observable the election has, and
    /// therefore the only thing a test of it can assert on.
    fn on_tick(&mut self, me: Triple, anchors: &[Triple], live_epoch: Epoch) -> bool {
        // Progress, taken from latest-state: an advancing round proves the anchors that produced it are live.
        if live_epoch > self.last_epoch {
            self.last_epoch = live_epoch;
            self.down.clear();
            self.confirmations = 0;
        }
        if !self.detector.observe(self.last_epoch) {
            return false;
        }
        self.confirmations = self.confirmations.saturating_add(1);

        // **Rank-delayed election, because "elect the lowest-index live anchor" had no way to fail.**
        // Every node fired only if it computed *itself* as the coordinator, which assumed every node's
        // down-view agreed. Views are built from `PeerDown` events on a lossy channel, and they diverge
        // exactly when it matters — the down set only accumulates while the beacon has already stalled,
        // which is when this node is busiest and most likely to be behind. One node wrongly believed live
        // was therefore elected by everybody, could not act, and **nobody else fired**: the cell stayed
        // frozen, in the one state this trigger exists to escape.
        //
        // A node now fires when its **rank** among the anchors it believes live is below the number of
        // stall confirmations. Rank 0 fires on the first, rank 1 one confirmation later, and so on — no
        // shared view is required, only that a live anchor eventually reaches its turn. Firing twice is
        // harmless (the trigger is generation-fenced and both regimes only escalate), so the design fails
        // toward *more* triggers, which is the safe direction for a mechanism that exists to unfreeze.
        let live = self.live_anchors(anchors);
        let Some(rank) = live
            .iter()
            .position(|&idx| anchors.get(usize::from(idx.saturating_sub(1))) == Some(&me))
        else {
            return false; // this node is not an anchor, or believes itself down
        };
        if u32::try_from(rank).unwrap_or(u32::MAX) >= self.confirmations {
            return false; // not yet this node's turn
        }
        (self.generation, self.threshold) =
            actuate_recovery(&live, self.threshold, self.generation, self.last_epoch);
        true
    }
}

/// Announce the node to its cell after start: kick off the heartbeat (cover traffic) if configured, and JOIN
/// with the offered role set so the cell learns what this node serves (spec §7.8 JOIN).
/// Also starts the move announcer, so a coordinate change is announced cell-wide too — see
/// [`spawn_move_announcer`]. Its handle is not returned: the announcer reports its own death by name
/// ([`NodeActor::MoveAnnouncer`](crate::supervise::NodeActor::MoveAnnouncer)), and holding a `JoinHandle`
/// does nothing at all, since dropping one **detaches** (#251).
fn announce_node(handle: &NodeHandle, config: &NodeConfig) {
    if config.start_heartbeat {
        handle.command(Command::StartHeartbeat);
    }
    if !config.roles.any() {
        return;
    }
    let info = vec![config.roles.encode()];
    handle.command(Command::Join { info: info.clone() });
    spawn_move_announcer(handle.client(), info);
}

/// Re-announce this node to the whole cell whenever its coordinate **moves**, so membership converges after a
/// collision is resolved.
///
/// A move already re-sends the HELLO on every **open connection** (`fanos_quic`'s move announcer) and republishes the
/// capability/load records at the new point. Neither reaches a peer this node is *not yet connected to*, and that peer is
/// exactly the one that needs telling: it holds no address for the mover, so it never dials, never connects, and never
/// learns — permanently.
///
/// An `Announce` is the path that does reach it, because `OverlayNode::on_announce` **re-floods on first sight**, so the
/// new coordinate propagates transitively through peers that *are* connected. The re-flood also terminates on its own: the
/// monotone guard drops a repeat for a coordinate already in `members`, so this costs one wave per genuine move.
///
/// Measured before this: with the draw forced to collide, `known_peers` stalled at 4–6 of 7 and the roster never agreed
/// (`[1,2,2,2,4,2,4]`), while an injective draw over the same code reached `[7; 7]` in 24 s. The roster is downstream —
/// a cell that has not finished connecting cannot assemble a directory over coordinates it cannot reach.
fn spawn_move_announcer(client: Client, info: Vec<u8>) -> JoinHandle<()> {
    // Supervised: dead, a peer this node is not connected to never learns where it moved, and holding no
    // address it never dials — the loss is permanent and nothing else reports it (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let mut events = client.subscribe();
        // **The coordinate is state, so a lost `Reseated` must not be permanent — and here it would have
        // been.** This flood is the *only* path that reaches a peer this node is not connected to (see
        // above): that peer holds no address for the mover, so it never dials and never learns. The
        // notification stream drops messages for a subscriber that falls behind, so one dropped move left
        // that peer without the new coordinate for good.
        //
        // The event stays, for promptness. Beside it, a tick compares the node's *current* coordinate — which
        // the driver keeps as shared state — against what was last announced, so a lost event costs one tick
        // rather than a peer. `ROSTER_REFRESH` is the cadence at which the cell already re-checks its own
        // composition, which is the same question asked from the other side.
        let mut last = client.address();
        let mut ticker = tokio::time::interval(crate::role_loop::ROSTER_REFRESH);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // the immediate tick would re-announce what `announce_node` just sent
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Ok(Notification::Reseated { .. }) => {
                        last = client.address();
                        client.command(Command::Join { info: info.clone() });
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = ticker.tick() => {
                    let now = client.address();
                    if now != last {
                        last = now;
                        client.command(Command::Join { info: info.clone() });
                    }
                }
            }
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::MoveAnnouncer, &supervised, task)
}

/// Spawn the recovery auto-trigger for a beacon-carrying node (`None` for a bare node), deriving the cell's
/// candidate anchor coordinates from the plane in holder-index order (audit §4).
fn spawn_recovery<F: Field + 'static>(
    client: Client,
    config: &NodeConfig,
    me: Triple,
    has_beacon: bool,
) -> Option<JoinHandle<()>> {
    has_beacon.then(|| {
        let anchors: Vec<Triple> = (0..Plane::<F>::N as usize).map(|i| Point::<F>::at(i).coords()).collect();
        let threshold = config.beacon.as_ref().map_or(0, |b| b.threshold);
        spawn_recovery_trigger(client, config.epoch_period, me, anchors, threshold)
    })
}

fn spawn_recovery_trigger(
    client: Client,
    period: Duration,
    me: Triple,
    anchors: Vec<Triple>,
    threshold: usize,
) -> JoinHandle<()> {
    // Supervised: this is the cell's only automatic path out of a frozen beacon (#88), so its death leaves
    // the stall permanent with nobody having decided not to act (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let mut events = client.subscribe();
        let beacons = client.beacons();
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // skip the immediate tick, matching the epoch driver's connect/sync grace period
        let mut watcher = RecoveryWatcher::new(threshold);
        loop {
            tokio::select! {
                ev = events.recv() => match ev {
                    Ok(note) => watcher.on_note(&note),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = ticker.tick() => {
                    let live_epoch = beacons.borrow().map_or(Epoch::ZERO, |(e, _)| e);
                    let _actuated = watcher.on_tick(me, &anchors, live_epoch);
                }
            }
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::RecoveryTrigger, &supervised, task)
}

/// Lowercase-hex encode `bytes` — for logging the exit's public-key descriptor a proxy configures with.
fn encode_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Spawn the clearnet exit relay for the `exit` role (a no-op when off): a stable, seed-derived DIAULOS
/// service identity on `handle`'s client that anonymous clients dial to reach the ordinary internet,
/// bounded by the port policy. Per-session handshake keys are fresh OS entropy (forward-secure); only the
/// identity is pinned to the seed so its published public stays stable across restarts. Logs the descriptor
/// a proxy needs (`--exit-via`) — the public is safe to publish, only the seed is secret.
fn spawn_exit_role(
    handle: &NodeHandle,
    address: Triple,
    exit: Option<([u8; 32], Vec<u16>)>,
    load: &Arc<LoadSensor>,
) -> Result<(), NodeError> {
    let Some((seed, allowed_ports)) = exit else {
        return Ok(());
    };
    let keypair = StaticKeypair::generate(&mut SeedRng::from_seed(&seed));
    let public = keypair.public().clone();
    let [x, y, z] = address;
    tracing::info!(
        coord = ?address,
        key = %encode_hex(&public.encode()),
        "exit descriptor — proxy `--exit-via` file: coord = {x}:{y}:{z}, key = <the `key=` value above>"
    );
    serve_exit(
        handle.client(),
        keypair,
        SeedRng::from_seed(&os_entropy_32()?),
        ExitPolicy::new(allowed_ports),
        // Metering the role is what closes the controller's loop for it: an exit's work happens in async
        // tasks, so no engine can count it, and without this the cell provisions exits by who volunteered.
        Some(load.gauge(Role::Exit)),
    );
    // Advertise the exit through the overlay store so a proxy discovers it automatically (each epoch, so a
    // departed exit falls out of the live directory) — no hand-configured descriptor needed. The task runs
    // until the node stops; its handle is not retained, because retaining one does nothing (#251).
    spawn_exit_publisher(handle.client(), public, handle.coordinate_prover());
    Ok(())
}

/// The **genesis beacon seed of this network**, derived from its beacon commitment.
///
/// `H("FANOS-v1/genesis-beacon" ‖ commitment)`. The commitment is the DKG-or-dealing output: random,
/// per-network, already in every provisioning file because no node can verify a beacon round without it, and
/// therefore requiring no new field, channel or operational step.
///
/// **What it replaces and why that mattered.** Epoch 0 has no reshuffle yet, and on `q = 2` the reshuffle is
/// the *entire* placement defence (`docs/design-coordinates.md`) — so the genesis coordinate is only as
/// unpredictable as its seed. `BeaconSeed::GENESIS` is a compile-time constant, which made it not
/// unpredictable at all: an adversary grinds identities offline until it holds one per point (roughly seven
/// mints per point on a Fano cell, which is why `fanos-quic::harness` can do it as a *test* facility) and
/// joins wherever it chose. Worse, being a constant, **one grinding effort worked against every FANOS
/// deployment that will ever exist** — computed before any of them was founded.
///
/// Proof-of-work does not substitute for this, and the reason is exact: `admission_challenge` binds
/// `(id, coord, epoch)`, all three of which the adversary knows offline at genesis, so a proof is
/// precomputable. In later epochs the same challenge bites because the adversary cannot know its own future
/// coordinate. Unpredictability is what prices placement; work only makes precomputation slower.
/// `docs/design-genesis.md` §2 has the derivation.
#[must_use]
pub fn genesis_seed(network: &NetworkId) -> BeaconSeed {
    BeaconSeed::new(fanos_primitives::hash_labeled("FANOS-v1/genesis-beacon", network.as_bytes()))
}

/// A network's **public name**: 32 bytes fixed once, at founding, and carried in every node's provisioning.
///
/// **Separate from the beacon commitment, and that separation is the point (#98).** The seed used to be
/// `H(label ‖ commitment)`, on the reasoning that the commitment is the only per-network random value every
/// participant necessarily holds before it can do anything. True, and it made the network's name a function
/// of the beacon's key material — a `VssCommitment` is a Feldman commitment `x·G` over ristretto255, so the
/// name was a discrete-log encryption of the beacon master secret, published in every configuration file and,
/// *because it was the name*, impossible to ever withdraw (`spec/protocol.md` §1265,
/// `docs/network-threat-model.md` E6).
///
/// **What this buys, stated exactly.** Not a bound on the retroactive exposure — an adversary who archived a
/// configuration file still holds that commitment, and one discrete-log solve still recomputes every epoch
/// that commitment served. What it buys is the **precondition for retiring one**: with the name independent,
/// a beacon can be replaced without re-seating the network, so the damage from a solve is confined to the
/// epochs its own commitment covered instead of all history. The bound arrives with rotation; this is what
/// rotation was blocked on.
///
/// It is **required**, never defaulted back to the commitment. A fallback would silently keep the coupling
/// for every configuration that omits the field, which is the shape that produced the last several findings:
/// an opt-in property is absent exactly where it matters.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NetworkId([u8; 32]);

impl NetworkId {
    /// Wrap 32 bytes chosen at founding.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive a name from any founding material — a chosen phrase, a ceremony transcript, a random draw.
    ///
    /// Domain-separated so a name can never coincide with a seed, a slot key or a challenge derived from the
    /// same bytes elsewhere.
    #[must_use]
    pub fn from_seed(material: &[u8]) -> Self {
        Self(fanos_primitives::hash_labeled("FANOS-v1/network-id", material))
    }

    /// The raw name.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NetworkId {
    /// Public material, so it prints in full — an operator comparing two nodes' networks needs the whole
    /// value, and a truncated one silently matches on a prefix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetworkId({})", encode_hex(&self.0))
    }
}

/// Validate the **beacon** parameters, so a provisioning file cannot hand a node a threshold the beacon it
/// names does not have.
///
/// This is the most consequential parameter in the system and it was the least checked: `bp.threshold` went
/// straight into `BeaconNode::new` with no floor and no comparison against the commitment.
/// `docs/design-governance.md` §2.1 states why that matters — "coordinates derive from the beacon; whoever
/// holds a reconstruction threshold of its shares influences where every joining node lands".
///
/// **The threshold must match the commitment.** A `VssCommitment` carries `t` coefficients, so it *knows*
/// the degree it was dealt at ([`VssCommitment::threshold`]). A config claiming a different `t` describes a
/// beacon that does not exist: rounds either never assemble (too high) or assemble from too few partials and
/// verify against a polynomial of the wrong degree (too low). Nothing compared the two, so a typo produced a
/// node that ran, flooded, and never adopted an epoch — with no diagnosis pointing at the file.
///
/// **There is deliberately no floor of `t ≥ 2` here, and that is a correction.** The obvious argument — at
/// `t = 1` one anchor reconstructs the epoch randomness alone, hence chooses every coordinate — is true and
/// still does not make `t = 1` refusable, because `fanos beacon-deal 1 1` is a *documented* configuration:
/// `docs/design-governance.md` §2.1 calls the dealt path "correct for a private or test cell, where the
/// dealer is the only operator". With one anchor, `t = 1` is the only threshold there is and distributes
/// nothing that was ever distributed.
///
/// The danger is `t = 1` with *several* anchors — a threshold that fails to spread trust across parties that
/// exist — and `BeaconParams` cannot express that: it carries the commitment and this node's share, never
/// the anchor count. So the check that can be made is made, and the one that cannot is named rather than
/// approximated by a floor that would refuse a legitimate deployment.
///
/// This differs from the service line's floor, which is right: a service *line* has `q+1` members by
/// construction, so `t = 1` there is one of several holding everything — the inversion the design warns
/// about. The beacon has no such structural guarantee, and reusing the argument across the two was an error.
fn beacon_params_checked(config: &NodeConfig) -> Result<(), NodeError> {
    let Some(bp) = config.beacon.as_ref() else {
        return Ok(());
    };
    let committed = bp.commitment.threshold();
    if bp.threshold != committed {
        return Err(NodeError::Config(format!(
            "the beacon threshold {} does not match the commitment, which was dealt at {committed} — the \
             file describes a beacon that does not exist, and rounds would never assemble",
            bp.threshold,
        )));
    }
    Ok(())
}

/// Validate the `service` role's parameters, returning the member-key seed, line roster, and threshold to
/// compose into a [`ServiceNode`] — or `None` when the role is off. The role requires its parameters (there
/// is no line to serve without them) and a threshold in `1..=line.len()` (zero would serve every intro from
/// a single host; above the line size can never be met). Validated here so bad provisioning fails
/// [`Node::start`] rather than the infallible engine builder.
#[allow(clippy::type_complexity)]
fn service_params(
    config: &NodeConfig,
) -> Result<Option<([u8; 32], Vec<Triple>, usize, Option<fanos_calypso::hosting::SealedShare>)>, NodeError> {
    if !config.roles.service {
        return Ok(None);
    }
    let params = config.service.as_ref().ok_or_else(|| {
        NodeError::Config(
            "the service role hosts a threshold CALYPSO line and needs service parameters (the line \
             roster, threshold, and this node's member key seed)"
                .to_owned(),
        )
    })?;
    // **The floor is 2, not 1, and the difference is the whole property.** Three places state that "no single
    // host holds the service identity in the clear" and that "seizing `< threshold` reveals nothing"
    // (`threshold_service`, `threshold_rendezvous`). At `t = 1` both are vacuous: `< 1` is zero members, so
    // the guarantee says seizing *nobody* learns nothing, while every member holds the identity whole.
    //
    // A threshold-hosted service provisioned 1-of-n is therefore not a weaker version of the design — it is
    // the design's claim inverted, and it starts and serves without complaint. The sibling ingress line got
    // this floor when the same shape was found in `emit_reshare`; this is the half that was left.
    if params.threshold < 2 || params.threshold > params.line.len() {
        return Err(NodeError::Config(format!(
            "the service threshold {} must be in 2..={} (the line has {} members); a threshold of 1 hands \
             every member the service identity whole, which is what threshold hosting exists to prevent",
            params.threshold,
            params.line.len(),
            params.line.len(),
        )));
    }
    // **An identity-custody slot must open under THIS member's own key, and that is checked here or never.**
    //
    // A `SealedShare` is addressed to one member: it opens under the KEM secret `seed` regenerates and under
    // no other. So the two fields are only correct as a pair, and the ways an operator gets them wrong are
    // ordinary — the wrong `service-<i>.conf` copied to a host, two members' files swapped, a file kept
    // across a re-deal that drew fresh seeds.
    //
    // Every one of those produces a line that starts, serves intros perfectly (half (b) uses `seed` and
    // never touches this slot), and is discovered to be unable to reconstruct its own identity only when it
    // is asked to — which by construction is during whatever emergency made the service need it. The
    // failure is silent, deferred, and lands at the worst possible moment: exactly the shape a startup check
    // exists to convert into a refusal an operator can still act on. `IngressParams` states the same rule
    // one field over ("the binding is not optional and is not separable from the share").
    if let Some(sealed) = &params.identity_share {
        let (secret, _public) = fanos_pqcrypto::HybridKemSecret::generate(&mut SeedRng::from_seed(&params.seed));
        if fanos_calypso::hosting::open_service_share(sealed, &secret).is_none() {
            return Err(NodeError::Config(
                "this service config's `identity_share` does not open under the key its own `seed` \
                 regenerates — the two are one member's pair, so the file carries another member's slot (a \
                 swapped `service-<i>.conf`, or one kept across a re-deal). The line would start, serve \
                 every intro, and fail only when the service had to authenticate."
                    .to_owned(),
            ));
        }
    }
    Ok(Some((params.seed, params.line.clone(), params.threshold, params.identity_share.clone())))
}

/// Validate the `exit` role's parameters, returning the service-key seed and allowed-port list to run
/// [`serve_exit`] — or `None` when the role is off. The role requires its parameters (there is no service
/// identity to run without them). Validated here so bad provisioning fails [`Node::start`].
#[allow(clippy::type_complexity)]
fn exit_params(config: &NodeConfig) -> Result<Option<([u8; 32], Vec<u16>)>, NodeError> {
    if !config.roles.exit {
        return Ok(None);
    }
    let params = config.exit.as_ref().ok_or_else(|| {
        NodeError::Config(
            "the exit role bridges to the clearnet and needs exit parameters (a service-key seed and \
             optional port policy)"
                .to_owned(),
        )
    })?;
    Ok(Some((params.seed, params.allowed_ports.clone())))
}

/// The capacity weight a node advertises for role assignment. Uniform for now: the controller's preference is then
/// driven by reputation and the beacon lottery rather than by a self-declared number no peer can check. A real
/// capacity class (bandwidth/uptime tier) belongs with the telemetry that would substantiate it.
const ROLE_CAPACITY_WEIGHT: u16 = 4;

/// The assignment controller's loop gain `κ = ROLE_GAIN_SEVENTH/7`. `7` is `κ = 1`: track the setpoint in one step.
///
/// **This doc has said "must stay 1" and "should be lowered" in turn, and both were true of their moment.**
/// It is kept as a history because the constant is exactly the kind that invites a change, and each reason
/// died for a different cause.
///
/// * *"Lower it so the Lyapunov descent smooths load jitter"* — written when the sensor was a placeholder and
///   the setpoint could not move. It died when the sensors went live and the advice became takeable.
/// * *"It must stay 1, because below 1 the demand is a function of how many times **this** node stepped, so
///   two members holding the same setpoint assign different roles"* — true of `RoleController::step`, which
///   folds the setpoint into a **carried** demand. It died when the assignment path stopped calling it.
///
/// **What is true now: cell agreement no longer rests on this constant's value.**
/// [`role_loop::LiveRoleController::step`] derives the demand with
/// [`RoleController::demand_from_setpoints`](fanos_core::roles::RoleController::demand_from_setpoints) —
/// the same law replayed from the shared `floor` rather than stepped from local history — so two nodes
/// reading one setpoint reach one demand **at any gain**. `RoleController::step` itself is now reached only
/// from `fanos-core`'s own tests. That doc records the change and its reason; this one must not contradict it.
///
/// So the gain is free, and `7` (κ = 1, `D' = setpoint`) is the *undamped* choice rather than a forced one.
/// Two things to weigh before lowering it:
///
/// 1. **Damping here costs a time constant of `1/κ` epochs.** At [`DEFAULT_EPOCH_PERIOD`] κ = 1/7 is about
///    seventy minutes of lag before the cell's role counts follow a real change in demand.
/// 2. **The noise it would damp is born in the estimator, not in the aggregation.** A gauged role publishes
///    [`role_loop::LoadGauge`]'s **instantaneous** in-flight count, sampled once per epoch by
///    [`crate::loaddir`]'s publisher on the epoch advance. Averaging that occupancy *within* the epoch, before
///    publication, attacks the same noise **locally and at no lag** — and, unlike smoothing the published
///    setpoint across epochs, it needs no closed directory to read (`LiveRoleController::step`: a window of
///    `W` closed setpoints is *"not a trade-off available here; it is unreadable"* at
///    [`DIRECTORY_SLOT_EPOCHS`](crate::DIRECTORY_SLOT_EPOCHS)` = 1`).
///
/// The magnitude of that noise is **unmeasured** — the structure above is read off the code, the size is not.
/// Measure before spending either cure.
const ROLE_GAIN_SEVENTH: u8 = 7;


/// The previous run's snapshot **and** whether this build can adopt it, derived together.
///
/// Two facts about one file, and the whole of #189 was them drifting apart: `compose_engine` applies the
/// bytes and discards `OverlayNode::restore`'s verdict, delegating the report to this host with the comment
/// *"the host reports whether it took"* — and the host held only the length, a **proxy**. "There was a file"
/// and "the file was adopted" agree on the happy path and nowhere else.
///
/// Computed in one function precisely so they cannot separate again: a caller that has the bytes has the
/// verdict, in the same expression. `snapshot_is_readable` asks the same `Store::restore` the adoption path
/// asks, so the report cannot disagree with what the engine then does.
///
/// Returns `(bytes for the engine builder, (len, adoptable) for the report)`; both `None` on a first boot or
/// an ephemeral node that configured no state directory.
fn read_restore(state_dir: Option<&Path>) -> (Option<Vec<u8>>, Option<Restored>) {
    let bytes = state_dir.and_then(crate::durable::read_snapshot);
    let report = bytes.as_ref().map(|b| Restored {
        len: b.len(),
        adoptable: fanos_runtime::snapshot_is_readable(b),
        // Counted from the same bytes the engine is about to adopt, so the sentence and the state agree.
        losses: fanos_runtime::snapshot_losses(b),
    });
    (bytes, report)
}

/// What a restart recovered, as three separate facts an operator needs apart (#189, #172).
#[derive(Clone, Copy, Debug)]
struct Restored {
    /// Bytes on disk.
    len: usize,
    /// Whether this build could decode them — a refusal is deliberate, not a fault.
    adoptable: bool,
    /// Permanent losses in the restored ledger, `None` when the bytes did not decode.
    ///
    /// Separate from `adoptable` because the two answer different questions: a refused snapshot has no
    /// ledger to report, while an adopted one with `Some(0)` is the healthy case and `Some(n)` is data this
    /// node is known to have lost for good. Their notifications were emitted in a previous process; without
    /// this line the fact survives the restart and the report does not.
    losses: Option<usize>,
}

/// Keep this node's durable store on disk, and say at startup whether the previous run's came back.
///
/// `None` when the config named no state directory — an ephemeral node (a test, a proxy-only client) has
/// nothing worth a file and should not make one.
///
/// The report is not decoration. Whether a restart recovered its shards or came up empty is the one fact
/// about this mechanism an operator cannot observe any other way, and a silent empty start is precisely the
/// failure #77 exists to remove; leaving it silent would reintroduce it one layer up.
fn spawn_store_role(
    handle: &NodeHandle,
    state_dir: Option<PathBuf>,
    restored: Option<Restored>,
) -> Option<crate::durable::StorePersister> {
    let Some(dir) = state_dir else {
        // Said once, rather than left to be discovered after a restart. A node with no state directory is a
        // legitimate configuration — a test, a proxy-only client — but "keeps nothing" must be a sentence the
        // operator read, not a behaviour they infer from missing shards.
        eprintln!("fanos: no state directory configured — this node keeps nothing across a restart");
        return None;
    };
    // Three states, not two. "A file was there" and "the file was adopted" are different facts, and the
    // second is the one this report claims; conflating them made an upgrade that changed the snapshot format
    // print `restored N bytes` at a node that had come up empty (#189). The refusal is not a fault — the
    // header carries `SNAPSHOT_VERSION` and a mismatch is *meant* to refuse, and `[7,3,4]` re-heals one
    // member's shards — but it must be a sentence the operator read, because by this function's own argument
    // there is no other way to observe it.
    match restored {
        // The loss count rides with the success line rather than in one of its own: a ledger is only
        // meaningful about a snapshot that was actually adopted, and an operator reading two sentences would
        // have to join them to know that.
        Some(Restored { len, adoptable: true, losses }) => eprintln!(
            "fanos: restored {len} bytes of store state from {} — {}",
            dir.join(crate::durable::STORE_FILE).display(),
            match losses {
                Some(0) => "no accounted losses in the ledger".to_string(),
                Some(n) => format!(
                    "WARNING: carrying {n} accounted permanent loss(es) (audit R-C3) from a previous run"
                ),
                None => "loss ledger unreadable".to_string(),
            }
        ),
        Some(Restored { len, adoptable: false, .. }) => eprintln!(
            "fanos: REFUSED the {len}-byte store snapshot in {} — it does not decode for this build \
             (format change, or a damaged file); starting empty, and the cell's erasure code re-heals \
             this node's shards",
            dir.display()
        ),
        None => eprintln!("fanos: no store snapshot in {} — starting empty", dir.display()),
    }
    Some(crate::durable::spawn_store_persister(
        handle.client(),
        dir,
        crate::durable::snapshot_interval(
            crate::durable::ASSUMED_RESTARTS_PER_DAY,
            crate::durable::DURABILITY_TARGET,
        ),
    ))
}

/// Spawn the **self-organizing role subsystem** (`crate::role_loop`): advertise what this node offers, report its
/// observed load, and run the cell's deterministic assignment each epoch.
///
/// Until this call existed the subsystem was a proven library a running node never started — so a deployed node's
/// roles were whatever its config file said and the cell had no say, the "libraries-ahead / wiring-behind" pattern
/// `docs/audit.md` tracks. The split it establishes is the intended one: **config declares the offer, the cell
/// decides the assignment.** A caller actuates [`Node::assigned_roles`], which changes as the cell rebalances.
/// Differentially-private telemetry export (audit C7), only when an ε is configured.
///
/// The mechanism and its sanctioned `CoherenceFrame::export` had existed with no caller since the audit named them, which
/// made the guarantee decorative: there was nothing to privatize. `None` publishes nothing, which is the default — a node's
/// coherence readings describe the cell it sits in, so emitting them is an operator's decision.
fn spawn_telemetry_export(handle: &NodeHandle, epsilon: Option<f64>) -> Option<JoinHandle<()>> {
    epsilon.map(|e| {
        // The prover binds each published frame to this node's coordinate (#262), so a census cannot be
        // told a Φ for a node that never said it. `None` where coordinates cannot be proven at all.
        crate::telemetry_dir::spawn_coherence_publisher(
            handle.client(),
            fanos_telemetry::dp::PrivacyBudget::new(e),
            handle.coordinate_prover(),
        )
    })
}

/// Keep this relay's onion key live in the mix directory as a **coordinate-bound** record (S1-M3).
///
/// Only for a relay — a node that does not relay has no onion key to advertise — and only with a self-certifying identity,
/// which is also the only case where a coordinate can be proven at all. The prover is the handle's own closure over its
/// credentials, so no signing key reaches this publisher.
/// **Not supervised, and no longer joined.** Both halves report their own deaths by name
/// ([`NodeActor::MixPublisher`](crate::supervise::NodeActor::MixPublisher) and `MixFeeder`), which is what a
/// third task here could never do — it could only say that *one of two* had stopped.
///
/// It used to `tokio::join!` the two into a single handle, stored in a `_`-prefixed field. That accomplished
/// nothing in either direction: a dropped `JoinHandle` **detaches**, so the field neither kept the actors
/// alive nor learned anything when they ended, and the join's own result was discarded with `let _`. One
/// spawned task whose entire purpose was to be dropped (#251).
fn spawn_mix_export(handle: &NodeHandle, relay: bool, onion_seed: [u8; 32]) {
    if !relay {
        return;
    }
    let Some(prover) = handle.coordinate_prover() else {
        return;
    };
    // Two halves of one role, spawned together because a relay is both: it PUBLISHES its own onion key so others
    // can seal to it, and it CONSUMES the cell's directory so it can seal a forward onion as a meeting combiner.
    // The second used to be unnecessary only because a host registration carried the hop keys itself, which does
    // not fit the fixed-width packet past the Fano plane.
    spawn_mix_directory_feeder::<fanos_field::F2>(handle.client(), true);
    spawn_mix_publisher(handle.client(), onion_seed, Some(prover));
}

fn spawn_roles<F: Field + 'static>(
    handle: &NodeHandle,
    credentials: &NodeCredentials,
    roles: RoleSet,
    directory: &Directory,
    load: Arc<LoadSensor>,
) -> SelfOrganization {
    let offered = roles.offered();
    let peers = directory.clone();
    spawn_self_organization::<F>(
        handle.client(),
        SelfOrgConfig {
            // The node's id for role assignment **is** its coordinate-VRF public key. That makes the capability
            // advertisement self-certifying: the descriptor is signed by the key its id names, so a node cannot
            // publish a capability under another's id without that node's secret — closing, for this directory, the
            // identity-binding step `capdir` records as outstanding.
            node_id: NodeId(credentials.vrf_secret().public().to_bytes()),
            vrf_secret: credentials.vrf_secret(),
            capability: Capability::new(offered, ROLE_CAPACITY_WEIGHT),
            capacity: role_capacity(),
            controller: RoleController::new(Demand::default(), Demand::default(), ROLE_GAIN_SEVENTH),
            // A `Node` runs VRF coordinates, so it publishes a coordinate-bound advertisement and verifies everyone
            // else's (`crate::bound`). `None` only in a pinned cell, where the proof cannot exist.
            prover: handle.coordinate_prover(),
        },
        // The measured load this node is carrying, in work units. The substitution for a role with **no**
        // sensor lives in `RoleReading::to_load`, so the fallback is stated once rather than inferred from a
        // magic zero here, and the `⌈load / capacity⌉` conversion happens once, cell-wide, in `cell_setpoint`.
        //
        // `load` is the sensor the caller also handed the role drivers, deliberately: it must be *the* one every
        // reporter writes to. Building a second here — which an earlier edit of this function did, and the
        // unused-parameter warning caught — leaves the exit gauge feeding a sensor nobody publishes from, so the
        // role reads unsensed forever while looking fully wired.
        move || load.load(offered, role_capacity()),
        // The transport's own peer table, as a lower bound on live membership that owes nothing to the overlay store.
        // The role loop uses it to tell "I am alone" from "I have found no one yet" — see `ROSTER_REFRESH`.
        move || peers.len(),
    )
}

/// A running FANOS node.
pub struct Node {
    handle: NodeHandle,
    directory: Directory,
    local_addr: SocketAddr,
    roles: RoleSet,
    /// Whether this node has a reflexive layer — see [`Health::reflexive`].
    reflexive: bool,
    /// Keeps this node's durable store on disk (#77) — present only when the config named a state directory.
    ///
    /// Held for the node's lifetime, and now **read on the way out**: [`Node::shutdown`] drains it so a clean
    /// stop persists what a crash-derived period would have lost (#178). It stopped being `_`-prefixed on the
    /// commit that gave it a reader.
    store_persister: Option<crate::durable::StorePersister>,
    /// The **self-organizing role subsystem** — the capability/load publishers and the per-epoch assignment loop.
    /// Held for the node's lifetime; [`assigned_roles`](Self::assigned_roles) reads the current assignment.
    self_org: SelfOrganization,
    /// The node's live `(epoch, beacon seed)`, updated by `_beacon_tracker`; `None` until the first round is
    /// adopted (or always, for a node with no beacon clock). Read by an anonymous proxy via [`live_beacon`](Self::live_beacon).
    live_beacon: fanos_quic::Beacons,
}

/// A point-in-time health snapshot of a node.
///
/// # Why there is no coherence number here, and why adding one would be a regression (#277/#278)
///
/// Every field below is something this node **knows first-hand**. Φ, purity and the correlation radius are
/// not: the only reading a node has of its own cell's coherence is its **ε-noised telemetry export**, and
/// #278 measured what happens when a node consults it — **100 invented alarms out of 3636 samples, 0
/// hidden ones**, every one of them `Healthy → Structure`. The noise is there so the export can leave the
/// node; reading it back locally pays the privacy cost twice and buys a worse answer than silence.
///
/// The absence is therefore a **decision with a measurement behind it**, not a gap someone forgot to fill —
/// stated here because the reason lives in a different crate, and an unexplained absence beside
/// [`reflexive`](Self::reflexive)'s carefully explained one reads as an oversight to the next person.
///
/// What would make coherence belong here is a reader of the **un-noised** frame, which is a different
/// object with a different owner (`fanos_telemetry::snapshot` — and its own doc records why the canonical
/// summary must sit at the frame layer rather than below it: readiness is a question about provenance as
/// much as about magnitudes, and provenance is a property of the frame).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Health {
    /// The node's overlay coordinate.
    pub address: Triple,
    /// The bound network address.
    pub local_addr: SocketAddr,
    /// The number of peers currently in the address book.
    pub known_peers: usize,
    /// Points this node holds a **ranked** binding for — what it can route to, as distinct from what it has
    /// heard of (#249).
    ///
    /// The pair with [`verified_claims`](Self::verified_claims) is the point, and they are counted in
    /// different structures on purpose: that is the *claim book* — peers whose coordinate proof this node
    /// checked — while this is the *dial table*. They diverge exactly where the roster investigation stalls.
    /// A claim verified but refused by the arbitration rule (`WriteOutcome::Superseded`) raises the first and
    /// not the second: the node knows the peer and cannot route to its point. `known_peers` sees neither
    /// case, because it counts seeded addresses too.
    pub routable_points: usize,
    /// Whether this node has a **reflexive layer** at all — a coherence self-model, a liveness diagnosis and
    /// the §6.7 self-healing actions (#145).
    ///
    /// `false` is not a degraded reading, it is an *absent instrument*: the DIAKRISIS unit is a seven-member
    /// cell, and only `PG(2,2)` forms one from the plane itself. On a larger plane a node discovers peers but
    /// nothing tells it which seven are its cell, so the whole reflex returns early — and every other field
    /// here still reads healthy, because the component that would say otherwise is the one that is missing.
    ///
    /// Derived from configuration rather than read from the engine, which is exact: the condition is
    /// `plane_order == 2` (or an explicit roster, which no deployment path sets today), and nothing at run
    /// time can change it.
    pub reflexive: bool,
    /// Whether this node is keeping durable state, and if not, which of the two reasons (#200).
    ///
    /// `NotConfigured` is a legitimate deployment and needs nothing; `Failing` is a node running on volatile
    /// state that will lose everything since its last successful write. They were equally invisible here
    /// before — the persister said so once per tick on stderr and nowhere else, so an operator who attached
    /// after the first failure, or who reads this at all, saw a node that looked healthy.
    pub durable: crate::durable::Durability,
    /// Frames this node did **not** make because a peer's send queue was full (#89).
    ///
    /// Zero on a healthy node, and one meaning when it is not: some peer stopped draining its connection, so
    /// this node stopped queueing for it instead of growing without limit. A peer that completes a handshake
    /// and never reads is enough to cause it, which makes this a health signal about the *cell*, not only
    /// about this node.
    pub send_drops: u64,
    /// Peers whose **coordinate claim** this node has verified this epoch, or `None` without a self-certifying identity.
    ///
    /// Distinct from `known_peers`, and the distinction is the point: the address book says who this node can *dial*, while
    /// this says whose claim to a point it has *checked* — the input coordinate resolution runs on. A node stuck on a
    /// contested point with a low count failed to hear of its rival; one with a high count heard and did not move. Same
    /// symptom, different defect, and without this they are indistinguishable from outside.
    pub verified_claims: Option<usize>,
    /// The **probe index** of this node's own coordinate claim, if it is bound with one.
    ///
    /// The third observable this investigation needed, and it closes the last gap: `0` means the node is at the point its
    /// own draw preferred, `> 0` means it advanced along its probe walk. A contested node still reading `0` decided not to
    /// move (`fanos_vrf::settle_index` did not advance — the book lacks the *specific* rival, or the rule says stay); one
    /// reading `> 0` while its coordinate looks wrong failed to *apply* the move. Two defects, one symptom, and without
    /// this they are indistinguishable — the same trap `verified_claims` was added for.
    pub probe_index: Option<u16>,
    /// **Coordinate collisions this node has observed** — two distinct addresses claiming one point.
    ///
    /// Nonzero means the projective address space suffered a `MapToPoint` collision, which is the exact
    /// condition coordinate resolution exists to settle: one of the two claimants must advance along its probe
    /// walk. Read beside `probe_index` and `verified_claims` on purpose — those two were added so that "did
    /// not hear of the rival" and "heard and did not move" could be told apart, and this is the third leg of
    /// the same question: *was there a rival at all*. The directory counted it from the start and nothing read
    /// it, so the counter's own doc promised a health surface that did not exist (#149).
    pub collisions: usize,
    /// **Frames dropped because the destination coordinate had no address.**
    ///
    /// Distinct from `send_drops`, and the distinction is why both are here: `send_drops` is a peer that
    /// stopped draining a connection this node *has*, while this is a peer this node cannot reach at all
    /// because its address book has no binding for the point. Same symptom from outside — traffic not moving —
    /// and opposite causes, so a node reporting only one of them is as ambiguous as one reporting neither.
    pub unresolved_drops: usize,
    /// The advertised roles.
    pub roles: RoleSet,
    /// Whether the cell's **assignment** is still being decided, or frozen at whatever the role controller
    /// last said before it died (#251).
    ///
    /// Reported beside `roles` because the two are easy to confuse and answer different questions: `roles` is
    /// the *offer* this node's config makes and cannot go stale, while the assignment is the cell's *decision*
    /// and is maintained by one task. `Stopped` means [`Node::assigned_roles`] is a fossil — the node still
    /// runs those behaviours, but nothing is checking whether the cell still wants them here, and the cell
    /// goes on counting them covered.
    pub organizing: crate::role_loop::RoleStanding,
}

/// Seed the address book from `config.bootstrap`, and say so when a coordinate is contested.
///
/// The **provenance** of that list decides what a repeated coordinate in it means (#186): an operator's
/// file must be refused, because a duplicate there silently shrinks the bootstrap set and `fanos keygen`
/// derives the network's name from the roster it was handed. A snapshot of *running* peers must not be —
/// two peers contesting one point is a live state `fanos_vrf::settle_index` resolves, and refusing over it
/// would stop THIS node for a collision that is neither its fault nor its to fix, at a total cost against
/// a transient one.
fn seed_bootstrap(config: &NodeConfig, directory: &Directory) -> Result<(), NodeError> {
    let contested =
        crate::config::seed_directory_from(&config.bootstrap, directory, config.bootstrap_source)?;
    if contested > 0 {
        tracing::warn!(
            contested,
            listed = config.bootstrap.len(),
            "bootstrap peers contest a coordinate: the point resolves to one of each pair, so this node \
             starts with fewer dialable seats than it was given — transient while the cell settles"
        );
    }
    Ok(())
}

impl Node {
    /// Start a node over the deployment field `F`, using `config` (identity, bootstrap, roles).
    ///
    /// # Errors
    /// [`NodeError`] if the identity cannot be loaded or the QUIC endpoint cannot be bound.
    pub async fn start<F: Field + 'static>(config: NodeConfig) -> Result<Self, NodeError> {
        let listen = config.listen;
        Self::start_over::<F>(config, Fabric::Udp(listen)).await
    }

    /// Start on the plane `config.plane_order` names, dispatching to the right [`Field`] at run time.
    ///
    /// The binary used to call `start::<F2>` directly, pinning every deployment to `PG(2,2)` — 7 points, the smallest
    /// plane there is — while `start` itself was always generic. For a mixnet that pin is the binding constraint: a flow
    /// hides in the set of relays available, and no amount of schedule tuning reaches past seven of them.
    ///
    /// # Errors
    /// [`NodeError::Config`] if `plane_order` is not a supported prime power. `PG(2,q)` exists only for prime powers, so
    /// an unsupported order is refused here rather than producing a cell whose geometry does not close.
    pub async fn start_on_plane(config: NodeConfig) -> Result<Self, NodeError> {
        // **A larger plane buys an anonymity set and costs the whole reflexive layer, and that trade was
        // silent.** The DIAKRISIS unit is a seven-member CELL, not a plane: `self_index` — the gate on the
        // coherence self-model, the liveness attestation, the verdict, the homeostat band, the shed and
        // every §6.7 healing action — is set either from an explicit roster or, on the base plane where the
        // plane IS the cell, from the node's own point. A deployed node is meant to discover its roster by
        // announcement, and announcement establishes *peers*, not a cell: on `PG(2,q>2)` nothing answers
        // "which seven of my peers are my cell", so `self_index` stays `None` and the reflex returns early
        // at every entry point.
        //
        // Said rather than refused, deliberately. The configuration is a real capability — `q = 2` is a test
        // fixture for a mixnet, as this function's own doc argues — and taking it away to fix a reporting
        // problem would be the wrong trade. What was dangerous was the SILENCE: a node with no reflex reported
        // healthy, because the component that would report otherwise is the missing one. Cell assignment on
        // a larger plane is an open design question (#145); until it is answered an operator must at least
        // be told which half of the trade they are getting.
        //
        // **That silence is now closed at both surfaces, and this line used to say otherwise.** It read "It
        // will report healthy regardless", which was true when it was written and is not any more:
        //   * `admin::render_health` prints `reflexive: NO` **first**, because it qualifies every line under
        //     it (#165) — it had been a `Health` field that nothing rendered;
        //   * and a non-reflexive node no longer passes its own liveness gate. `self_index` is `None`, so
        //     `sample_behavior` returns early, the behavioural window never fills, `measured_correlation`
        //     stays `None`, and `SnapshotFrame::ready` — which since #154 requires
        //     `correlation_is_measured()` — is therefore false. Before #154 it was *true*, on scalars the
        //     equicorrelated model produced from the configured `healthy_correlation = 0.45`.
        // The warning below is still the right thing to print at startup; it is no longer the only thing that
        // tells the operator.
        if config.plane_order > 2 {
            eprintln!(
                "fanos: WARNING — running on PG(2,{}) with no cell roster: this node has NO coherence \
                 self-model, NO liveness diagnosis and NO self-healing. `fanos status health` reports \
                 `reflexive: NO` and its coherence snapshot is not ready, because nothing measures. \
                 Only PG(2,2) forms a cell from the plane itself (#145).",
                config.plane_order
            );
        }
        // **What this node's subsystems have reserved, against what it is documented to run within (#213).**
        //
        // The three named shares — store, sessions, gathers — were each sized against "the 256 MiB node" by
        // authors who could not see one another, and their sum plus the measured resident set exceeds it. An
        // operator setting `MemoryMax=` (#207) needs that number, and needed it before the OOM killer
        // supplied it. Reported at start rather than counted at a station, because it is a property of the
        // build, not of the traffic: it cannot change while the node runs, and a reading that never moves is
        // a condition, not an event.
        //
        // Both directions are stated: a tree whose accounting closes says how much is still unclaimed, so
        // "no line" never has to be read as "nothing to say".
        {
            use fanos_primitives::budget;
            let mib = 1024 * 1024;
            if budget::overcommit() > 0 {
                tracing::warn!(
                    "fanos: memory accounting does not close — {} MiB of named subsystem budgets plus ~{} \
                     MiB resident exceed the {} MiB this node is documented to run within, by {} MiB, and \
                     the QUIC transport and VPN datapath are not in that sum at all. Size `MemoryMax=` \
                     against the real figure, not the recommendation (#213/#207).",
                    budget::allocated() / mib,
                    budget::PROCESS_RESIDENT / mib,
                    budget::NODE_MEMORY_BUDGET / mib,
                    budget::overcommit() / mib,
                );
            } else {
                tracing::info!(
                    unallocated_mib = budget::unallocated() / mib,
                    allocated_mib = budget::allocated() / mib,
                    "memory accounting closes"
                );
            }
        }

        match config.plane_order {
            2 => Self::start::<fanos_field::F2>(config).await,
            4 => Self::start::<fanos_field::F4>(config).await,
            7 => Self::start::<fanos_field::F7>(config).await,
            31 => Self::start::<fanos_field::F31>(config).await,
            q => Err(NodeError::Config(format!(
                "plane order {q} is not a supported prime power — PG(2,q) exists only for prime powers; use 2, 4, 7 or 31"
            ))),
        }
    }

    /// Start a node over an explicit transport [`Fabric`] — the **simulation entry point**.
    ///
    /// Identical to [`start`](Self::start) in every respect except where datagrams come from. Pass
    /// `Fabric::Abstract(socket)` (e.g. `fanos_sim::fabric::Fabric::bind`) to run this node — the *whole* node, every
    /// driver task it composes — over a modelled carrier. That is what makes the composition layer observable: it is
    /// where the wiring lives, and instantiating an engine directly cannot reach it
    /// (`docs/design-testing.md` §5.1/§5.2).
    ///
    /// `config.listen` is ignored when a fabric is supplied; a fabric endpoint has its own synthetic address.
    ///
    /// # Errors
    /// [`NodeError`] if the identity cannot be loaded or the endpoint cannot be created.
    // Nothing here awaits — endpoint creation is synchronous and every driver is `tokio::spawn`ed — but both entry
    // points stay `async` for API stability, matching `fanos_quic`'s spawn family.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn start_over<F: Field + 'static>(config: NodeConfig, fabric: Fabric) -> Result<Self, NodeError> {
        let credentials = identity::load_or_generate(config.identity_path.as_deref())?;

        // Seed the address book so a fresh node can dial into the network (design.md §9).
        //
        // Bound to THIS network's genesis seed at creation, not later: a directory bound after some uses
        // would leave those uses on the shared constant, and the whole point is that one value reaches every
        // site. Where no beacon is configured the constant stands, which is right — such a deployment has no
        // epoch clock and no reshuffle, so it has no placement defence at any epoch (`docs/design-genesis.md`).
        let directory = match config.beacon.as_ref() {
            Some(bp) => Directory::new().for_network(genesis_seed(&bp.network_id)),
            None => Directory::new(),
        };
        seed_bootstrap(&config, &directory)?;

        // Compose the engine per coordinate: a bare overlay by default, or — when beacon params are
        // configured — an `OverlayBeaconNode` that runs the live threshold-DVRF epoch clock (§7.6). A
        // pure consumer (`share = None`) only needs the group commitment + threshold to verify and adopt
        // the rounds anchors flood; an anchor also contributes partials.
        let beacon = config.beacon.clone();
        // Whether to run the live epoch clock (captured before `beacon` is moved into the engine builder).
        let has_beacon = beacon.is_some();
        // PoW Sybil-admission difficulty, if any — moved into the engine builder to price every join (§L3).
        let admission = config.admission_difficulty;
        // A relay node also runs the anonymity mixnet: its engine is a [`CellNode`] (overlay + beacon +
        // threshold-onion router), and it republishes its onion key each epoch so anonymous clients can
        // seal to it. The router's key material is fresh OS entropy per run — forward-secure, since a
        // restart cannot peel onions sealed to the old key. A relay needs the beacon to lock its onion-key
        // rotation to the cell epoch (E4∩E5), so require beacon parameters for the role.
        let relay = config.roles.relay;
        // Mixnet anonymity parameters, std→engine Duration, captured before the builder closure (audit S1-H1).
        let ns = |d: Duration| fanos_runtime::Duration(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        let (mix_mean_delay, cover_interval) = (ns(config.mix_mean_delay), ns(config.cover_interval));
        if relay && beacon.is_none() {
            return Err(NodeError::Config(
                "the relay role runs the anonymity mixnet and needs beacon parameters (configure the \
                 beacon commitment and threshold)"
                    .to_owned(),
            ));
        }
        let (onion_seed, kem_seed) = if relay {
            (os_entropy_32()?, os_entropy_32()?)
        } else {
            ([0u8; 32], [0u8; 32])
        };
        // The service role hosts one member of a threshold CALYPSO line. Validate its parameters up front so
        // bad provisioning fails `start` here rather than inside the infallible engine builder; the member
        // key seed is then carried into the builder (the secret is regenerated there, in memory).
        let service = service_params(&config)?;
        // Validate the exit role's parameters up front too (it spawns its relay after the node is up).
        let exit = exit_params(&config)?;
        // And the ingress role's, for the same reason.
        beacon_params_checked(&config)?;
        let ingress = ingress_params(&config)?;
        let rotation_params = ingress.as_ref().map(|p| (p.community.clone(), p.kem_seed));
        // The previous run's durable store, read before the engine exists — adopting one is only correct
        // before anything has been served (#77). Absent on a first boot, and absent for good on a node that
        // configured no state directory, which is what an ephemeral node means.
        let state_dir = config.state_path.clone();
        let (restore, restored) = read_restore(state_dir.as_deref());
        // Read before the engine closure captures `config`: the reflex's `cell_id` folds it, and the
        // closure is `move`, so taking it here is what keeps one network name serving both derivations.
        let genesis = config.genesis_seed();
        let handle = spawn_self_certifying_persistent_over::<F>(
            fabric,
            &credentials,
            move |coord| -> Box<dyn Engine + Send> {
                // A deployed node is seated by its VRF beacon coordinate (`spawn_self_certifying…` →
                // `verifiable_coordinate`), so its level-0 point is NOT the hash `address_point(id, 0)`.
                // Tell the overlay, so if a deployment turns on self-certified membership the check verifies
                // level 0 by the proof-of-coordinate HELLO + descriptor signature rather than the hash chain
                // (which would reject every legitimate VRF announcement, audit C3).
                let what = crate::composition::CellComposition {
                    // **This node's own epoch, not the runtime's default.** The band-keeping loop derives its
                    // control confidence and observation window from the epoch (`Config::behavior_window`),
                    // so a deployment that sets a different `epoch_period` must have that reach the reflex —
                    // otherwise the loop is tuned for an epoch this network does not have, and nothing says
                    // so because both halves still agree with themselves.
                    overlay: OverlayConfig {
                        vrf_coordinates: true,
                        epoch_period: fanos_runtime::Duration(
                            u64::try_from(config.epoch_period.as_nanos()).unwrap_or(u64::MAX),
                        ),
                        // And this node's *network*, for the same reason and by the same route: the reflex
                        // derives its `cell_id` from it, and a default seed would make two unrelated
                        // deployments report one cell (#210). Same derivation as the address space uses
                        // (`Directory::for_network`, node.rs:1128) — one network name, one seed, both places.
                        genesis,
                        // The three the operator can now express (#352). Without this line the keys would be
                        // decoration: `NodeConfig` would carry the wish and the overlay would keep its own
                        // default, which is a worse state than having no key at all — a setting that reports
                        // itself accepted and does nothing.
                        self_healing: config.overlay.self_healing,
                        require_self_certified_membership: config.overlay.require_self_certified_membership,
                        require_admission: config.overlay.require_admission,
                        ..OverlayConfig::default()
                    },
                    admission,
                    beacon: beacon.clone(),
                    relay,
                    onion_seed,
                    kem_seed,
                    mix_mean_delay,
                    cover_interval,
                    service: service.clone(),
                    ingress: ingress.clone(),
                    restore: restore.clone(),
                    // A deployed node sits at its cell root, discovers its roster by announcement and learns
                    // its hierarchical siblings the same way; all three are scenario parameters, and their
                    // absence here is what a deployment means.
                    hier_path: None,
                    cell_members: None,
                    hier_peers: Vec::new(),
                };
                crate::composition::compose_engine::<F>(coord, &what)
            },
            directory.clone(),
            // What this node ANNOUNCES is derived from what it wires, never written beside it (#284): these
            // are the same roles that decide whether the mixnet router and hidden-service path come up.
            config.roles.advertised_capabilities(config.plane_order),
            // PROTEUS (§13.4): when a community secret is configured, every frame is shaped and the shape
            // rotates each epoch (driven by the same beacon that reshuffles the coordinate). An environment
            // policy enables morph auto-fallback (§13.7); otherwise the fixed morph is used. No secret ⇒
            // plaintext QUIC.
            proteus_config(&config),
        )?;

        let address = handle.address();
        let local_addr = handle.local_addr();
        // Keep the relay's onion key live in the mix directory: publish genesis, then republish each epoch (E4∩E5).
        spawn_mix_export(&handle, relay, onion_seed);
        let _telemetry = spawn_telemetry_export(&handle, config.telemetry_epsilon);
        // The root epoch tick driving the live beacon clock (§L3, §7.6) — only when a beacon is configured.
        has_beacon.then(|| spawn_epoch_driver(handle.client(), config.epoch_period));

        // The live beacon (audit S1-M2) comes straight off the router's latest-state watch. It used to be a
        // second copy — its own task, subscribed to the *lossy* notification stream, maintaining an
        // `Arc<Mutex<Option<_>>>` that said the same thing. One task fewer, one lossy consumer fewer, and no
        // second answer to a question that has one.
        let live_beacon = handle.client().beacons();

        spawn_recovery::<F>(handle.client(), &config, address, has_beacon); // audit §4 R-C1

        // The measured per-role load, shared by every reporter: the engine's observations arrive on the
        // notification stream, and a driver task that performs work no engine can see opens a gauge on it.
        // Created before the roles that report into it.
        let load = spawn_load_sensor(&handle.client());

        // The exit role runs a clearnet relay on this node's client (see [`spawn_exit_role`]).
        spawn_exit_role(&handle, address, exit, &load)?;

        // The POROS ingress line's rotation. Spawned here rather than left to a caller for the reason this
        // whole subsystem keeps demonstrating: a driver nobody starts is a mechanism that does not exist,
        // and an ingress line that does not rotate forfeits the moving-target property §6 rests on — its
        // blocklist stops going stale. `None` for a node not hosting ingress, which is most of them.
        let _ingress_rotation = rotation_params.map(|(community, kem_seed)| {
            // The prover is what binds each published key to this node's coordinate (#262). `None` on a
            // deployment that cannot prove coordinates, which is the same condition every other bound
            // directory keys its envelope on.
            crate::ingressdir::spawn_ingress_rotation::<F>(
                handle.client(),
                community,
                kem_seed,
                handle.coordinate_prover(),
            )
        });

        // The self-organizing role subsystem (see [`spawn_roles`]).
        let self_org = spawn_roles::<F>(&handle, &credentials, config.roles, &directory, load);

        // Keep the durable store current (#77). Present only when the config named a state directory — an
        // ephemeral node (a test, a proxy-only client) has nothing worth a file and should not make one.
        // Reported at startup rather than inferred: whether the previous run's store came back is exactly the
        // fact an operator cannot see any other way, and a silent empty start is the failure this closes.
        let store_persister = spawn_store_role(&handle, state_dir, restored);

        announce_node(&handle, &config);

        Ok(Self {
            handle,
            directory,
            local_addr,
            roles: config.roles,
            // A cell is seven members; only the base plane is its own cell (#145).
            reflexive: config.plane_order == 2,
            store_persister,
            self_org,
            live_beacon,
        })
    }

    /// The roles the **cell has assigned** this node for the current epoch — the subset of what its config offers
    /// that the network decided it should actually serve.
    ///
    /// Distinct from [`Health::roles`], which reports the *offer*. A node actuates its behaviours from this: the
    /// assignment changes each epoch as the cell rebalances, so a role is started and stopped over the node's life
    /// rather than fixed at boot. Empty until the first beacon round is adopted (nothing to assign from before then).
    #[must_use]
    pub fn assigned_roles(&self) -> CoreRoleSet {
        self.assignment().roles
    }

    /// This node's full current [`Assignment`] — the roles **and the roster they were computed over**.
    ///
    /// Prefer this over [`assigned_roles`](Self::assigned_roles) wherever the *authority* of the assignment matters.
    /// A node whose peers are unreachable still computes a valid-looking assignment over a roster of one, because its
    /// own capability and load slots are local reads (`docs/design-testing.md` §5.3); only the roster distinguishes a
    /// cell-agreed assignment from a solitary guess, and [`Assignment::is_solitary`] names the unambiguous case.
    #[must_use]
    pub fn assignment(&self) -> Assignment {
        *self.self_org.assigned.borrow()
    }

    /// Whether the cell has currently assigned this node `role`.
    #[must_use]
    pub fn serves(&self, role: Role) -> bool {
        self.assigned_roles().has(role)
    }

    /// The node's live beacon — the `(epoch, seed)` it has most recently adopted from a threshold round
    /// (audit S1-M2). `None` until the first round is adopted (or always, for a node with no beacon clock). An
    /// anonymous proxy reads this so its mix directory + meeting lines track the epoch the relays have rotated
    /// to, rather than a stale static `--epoch`/`--beacon`.
    #[must_use]
    pub fn live_beacon(&self) -> Option<(Epoch, [u8; 32])> {
        *self.live_beacon.borrow()
    }

    /// The node's overlay coordinate, **as of now**.
    ///
    /// Read through the handle rather than from a field captured at spawn: a coordinate moves every epoch by the beacon
    /// reshuffle (spec §L3) and within an epoch when a better claim displaces this node from its point. A cached copy
    /// reported the genesis coordinate forever, from the first reshuffle onward, which made every position this surface
    /// showed wrong for the whole life of the node.
    #[must_use]
    pub fn address(&self) -> Triple {
        self.handle.address()
    }

    /// The bound network address (useful when the config requested an ephemeral port).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The shared address book (the discovery seam).
    #[must_use]
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// This node's transport handle — the seam a *plane-aware* caller needs.
    ///
    /// [`health`](Self::health) is not generic over the field, so a reading that needs `F` cannot go in
    /// [`Health`] without erasing it into a closure first. `NodeHandle::seat_contended::<F>` is exactly such a
    /// reading — whether a peer's claim to this node's own point is in its book — and the harness that asks it
    /// knows the plane. Exposing the handle is the smaller change and keeps `Health` field-free.
    #[must_use]
    pub const fn handle(&self) -> &NodeHandle {
        &self.handle
    }

    /// A current health snapshot.
    #[must_use]
    pub fn health(&self) -> Health {
        let address = self.address();
        Health {
            address,
            verified_claims: self.handle.verified_claims(),
            probe_index: self.directory.claim_at(address).map(|(index, _)| index),
            local_addr: self.local_addr,
            known_peers: self.directory.len(),
            routable_points: self.directory.routable_points(),
            reflexive: self.reflexive,
            // The absence of a persister IS the `NotConfigured` answer — there is no other way to be without
            // one — so the two sources cannot disagree about which of the three states this node is in.
            durable: self
                .store_persister
                .as_ref()
                .map_or(crate::durable::Durability::NotConfigured, crate::durable::StorePersister::state),
            send_drops: self.handle.send_drops(),
            collisions: self.directory.collisions(),
            unresolved_drops: self.directory.unresolved_drops(),
            roles: self.roles,
            organizing: self.self_org.standing(),
        }
    }

    /// Submit a command to the engine. Returns `false` if the node has shut down.
    pub fn command(&self, cmd: Command) -> bool {
        self.handle.command(cmd)
    }

    /// Await the next engine notification (`None` once the node has shut down).
    pub async fn next_notification(&mut self) -> Option<Notification> {
        self.handle.next_notification().await
    }

    /// Shut the node down cleanly: **persist the store, then** close the endpoint (the notification stream
    /// then ends).
    ///
    /// Async because it does I/O, and the ordering is the whole point (#178). The store persister runs on a
    /// derived period that bounds loss on a *crash*; a clean stop is the case where nothing need be lost, and
    /// before this it was charged the same bound — `shutdown` closed the endpoint, the persister's next
    /// `snapshot()` returned `None`, and it exited without writing. Everything stored since the last tick went
    /// with it, on the one path where the node knew it was stopping.
    ///
    /// **The order cannot be inverted.** `drain()` asks the engine for a snapshot, so it must run while the
    /// engine still answers — before `handle.shutdown()`, not after.
    ///
    /// This is the only door, deliberately. The alternative considered was a separate `persist_and_shutdown`
    /// leaving this one abrupt, which makes the safe path opt-in — the shape that is reliably missed by the
    /// next caller ([[opt-in-security-defaults-off]]). Making the single door async costs every caller an
    /// `.await`, and costs the C ABI one `block_on`, which is the idiom `fanos-ffi` already uses five times.
    ///
    /// A node with no state directory has no persister and returns as fast as the old synchronous call did.
    pub async fn shutdown(&self) {
        if let Some(persister) = &self.store_persister {
            persister.drain().await;
        }
        self.handle.shutdown();
    }

    /// A cloneable, concurrency-safe [`Client`] for this node — issue `get`/`put`/commands and await
    /// correlated replies from many tasks at once (the surface a proxy or resolver builds on).
    #[must_use]
    pub fn client(&self) -> Client {
        self.handle.client()
    }

    /// Resolve a `.fanos` `name` to its authenticated service descriptor at `epoch`, requiring at
    /// least `min_pow` proof-of-work on the published descriptor.
    ///
    /// Fetches the descriptor from the rotating epoch slot via a **correlated** `get` (so many
    /// resolves run concurrently without stealing each other's replies) and verifies it
    /// **client-side** (`H(bundle) == addr`), so a malicious store can never induce impersonation.
    ///
    /// # Errors
    /// [`NodeError::Resolve`] if the name is malformed, no descriptor is published, or the fetched
    /// descriptor fails verification.
    pub async fn resolve(
        &self,
        name: &str,
        epoch: Epoch,
        min_pow: u32,
    ) -> Result<ResolvedService, NodeError> {
        let address = Address::parse(name)
            .map_err(|e| NodeError::Resolve(format!("invalid .fanos name '{name}': {e}")))?;
        let slot = lookup_key(&address, epoch).to_vec();
        let value = self.client().get(slot).await.ok_or_else(|| {
            NodeError::Resolve(format!(
                "no descriptor published for '{name}' at epoch {epoch}"
            ))
        })?;
        verify_descriptor(&address, epoch, &value, min_pow)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    /// The planes this platform recommends cannot correlate a circuit's two ends within the fault budget, and
    /// the ones above them can — so fresh-per-dial is right here and the guard question is real there.
    ///
    /// Pinned as a table rather than a formula because the boundary is NON-MONOTONIC: `t = ⌈2(q+1)/3⌉` crosses
    /// divisibility boundaries, so "wider is safer" is false and an intuition check would pass the wrong code.
    #[test]
    fn correlation_is_impossible_exactly_on_the_recommended_planes() {
        for (q, expected) in [(2usize, false), (3, false), (4, false), (5, true), (7, true), (8, true), (31, true)] {
            assert_eq!(
                correlation_within_budget(q + 1),
                expected,
                "plane order {q}: 2t-1 = {} against f = {}",
                2 * mix_threshold(q + 1) - 1,
                (q * q + q + 1 - 1) / 3
            );
        }
        // The boundary is where it is because of the ARITHMETIC, not because 4 is special: at q = 4 the budget
        // is 6 and two lines cost 7, and one more corrupted node would flip it.
        assert_eq!(2 * mix_threshold(5) - 1, 7, "two lines cost 7 at q = 4");
        assert_eq!((4 * 4 + 4 + 1 - 1) / 3, 6, "and the budget there is 6");
    }
    use super::*;

    /// **The plane order should be chosen for its liveness SPARE, and the spare is `⌊(q+1)/3⌋`.**
    ///
    /// `t = ⌈2(q+1)/3⌉` comes from the BFT safety ratio, and safety is what it is for. But the same number
    /// fixes *liveness*: a gather completes when `t` of `q+1` members answer in time, so the members it can
    /// afford to lose is `(q+1) − t = ⌊(q+1)/3⌋`. The ceiling's **rounding** is therefore a liveness tax, and
    /// it is not paid evenly — `q = 3` and `q = 4` carry more members than Fano while tolerating the same
    /// single absence, which is strictly worse: more ways to lose, no more slack.
    ///
    /// The tax vanishes exactly when `3 | (q+1)`, i.e. **`q ≡ 2 (mod 3)`**, where the ceiling is exact. That
    /// family is `q = 2, 5, 8, 11, 14, …`, and the shipped Fano cell is its smallest member — so the base
    /// cell is defensible on liveness grounds and not only on tradition, while the sensible step *up* is
    /// `q = 5` or `q = 8`, never `q = 3` or `q = 4`.
    ///
    /// Asserted rather than argued, because the ordering is the surprising part: Fano beats the two orders
    /// above it, and a naive "bigger plane is more robust" reading of the geometry gets it backwards.
    #[test]
    fn a_planes_liveness_spare_is_floor_of_q_plus_one_over_three() {
        let spare = |q: usize| (q + 1) - mix_threshold(q + 1);
        for q in [2usize, 3, 4, 5, 7, 8, 9, 11, 13, 16, 31] {
            assert_eq!(spare(q), (q + 1) / 3, "q={q}: the spare must be ⌊(q+1)/3⌋");
        }
        // The rounding tax: three orders in a row tolerate exactly one absence, on lines of 3, 4 and 5.
        assert_eq!((spare(2), spare(3), spare(4)), (1, 1, 1), "q = 2, 3, 4 all tolerate one absence");
        // So more members buys nothing there — and a gather's failure probability is monotone in the member
        // count at fixed spare, which is what makes q = 3 and q = 4 strictly worse than Fano.
        assert!(spare(5) > spare(4), "q=5 is where the spare finally grows");

        // The tax is exactly the rounding, so it is zero iff 3 divides the line size.
        for q in [2usize, 5, 8, 11, 14] {
            assert_eq!(
                mix_threshold(q + 1) * 3,
                2 * (q + 1),
                "q={q} ≡ 2 (mod 3): the threshold is exact, so no capacity is lost to rounding"
            );
        }
        for q in [3usize, 4, 7, 9] {
            assert_ne!(mix_threshold(q + 1) * 3, 2 * (q + 1), "q={q}: the ceiling rounds up, and that costs");
        }
    }

    /// The default plane must be **bit-for-bit unchanged** by the generalization.
    ///
    /// `MIX_THRESHOLD` was `2`, correct for a Fano line's three points, and `mix_threshold(3)` must still be
    /// `2` — otherwise every existing `PG(2,2)` deployment silently changes its onion layout and stops
    /// interoperating. That is the whole reason this fix is safe to land: the constant's *value* was right.
    #[test]
    fn the_default_plane_keeps_the_threshold_it_shipped_with() {
        assert_eq!(mix_threshold(3), 2, "PG(2,2): a 3-point line stays 2-of-3");
        assert_eq!(DEFAULT_MIX_THRESHOLD, 2);
    }

    /// The threshold ratio must stay at or above `2/3` on every supported plane.
    ///
    /// That is the property, not the arithmetic. Under the platform's tolerance the corrupt *density* tends to
    /// `1/3`, so a line carries about `m/3` corrupt in expectation; a threshold below `2m/3` leaves no margin,
    /// and a threshold *fixed* at 2 — which is what shipped — collapses the ratio to `0.062` at `q = 31`,
    /// where any two corrupt members own a hop of thirty-two (`docs/audit.md` E7).
    #[test]
    fn the_threshold_ratio_never_falls_below_two_thirds() {
        for q in [2u32, 4, 7, 31] {
            let m = (q + 1) as usize;
            let t = mix_threshold(m);
            #[allow(clippy::cast_precision_loss)] // line sizes are tiny; f64 holds them exactly
            let ratio = t as f64 / m as f64;
            assert!(
                ratio >= 2.0 / 3.0 - 1e-12,
                "q={q}: t/m = {t}/{m} = {ratio} fell below 2/3 — a hop would have less margin than Fano's"
            );
            // And it is the *smallest* such threshold: one less would break the ratio, so this is not simply
            // "large enough" but the cheapest value that is.
            assert!(
                ((t - 1) as f64) / (m as f64) < 2.0 / 3.0,
                "q={q}: t={t} is larger than it needs to be"
            );
        }
    }

    /// A degenerate line still needs someone to peel it.
    #[test]
    fn a_degenerate_line_still_needs_one_peeler() {
        assert_eq!(mix_threshold(0), 1, "never zero — a hop nobody must open is not a hop");
        assert_eq!(mix_threshold(1), 1);
    }
    use crate::config::{BeaconParams, ExitParams, NodeConfig, ServiceParams};
    use fanos_field::F2;

    /// One anchor by index, without indexing — the lint that forbids `[i]` in this tree is right that a
    /// panicking subscript in a test is still a panicking subscript.
    fn anchor(anchors: &[Triple], i: usize) -> Triple {
        *anchors.get(i).expect("the base cell has seven anchors")
    }

    #[test]
    fn the_recovery_watcher_tracks_live_anchors_and_clears_them_on_a_round() {
        let anchors: Vec<Triple> = (0..Plane::<F2>::N as usize).map(|i| Point::<F2>::at(i).coords()).collect();
        let mut w = RecoveryWatcher::new(4);
        assert_eq!(w.live_anchors(&anchors), vec![1, 2, 3, 4, 5, 6, 7], "all anchors live initially");
        // PeerDown removes anchors from the live set (holder index = point index + 1).
        w.on_note(&Notification::PeerDown(Point::<F2>::at(0).coords()));
        w.on_note(&Notification::PeerDown(Point::<F2>::at(3).coords()));
        assert_eq!(w.live_anchors(&anchors), vec![2, 3, 5, 6, 7], "down anchors 1 and 4 are excluded");
        // A fresh (strictly-newer) epoch proves its producers live — the down set clears. Read from
        // latest-state on the tick, not from a `BeaconReady` event this watcher could have slept through.
        w.on_tick(anchor(&anchors, 6), &anchors, Epoch::new(1));
        assert_eq!(w.live_anchors(&anchors), vec![1, 2, 3, 4, 5, 6, 7], "an advancing epoch clears the down set");
        // A replayed, non-advancing epoch does NOT clear — progress is monotone.
        w.on_note(&Notification::PeerDown(Point::<F2>::at(2).coords()));
        w.on_tick(anchor(&anchors, 6), &anchors, Epoch::new(1));
        assert_eq!(w.live_anchors(&anchors), vec![1, 2, 4, 5, 6, 7], "a stale epoch keeps the down set");
    }

    /// **A dead coordinator must not freeze the cell, and it used to.**
    ///
    /// The election was "fire iff I am the lowest-index anchor I believe live", which is correct only while
    /// every node's down-view agrees. Those views are built from `PeerDown` events on a lossy channel and
    /// diverge exactly when it matters — the down set only accumulates while the beacon has *already*
    /// stalled. One anchor wrongly believed live was then elected by everybody, could not act, and nobody
    /// else fired.
    ///
    /// The property now: a node fires once its **rank** among the anchors it believes live falls below the
    /// number of stall confirmations. So rank 0 goes first, and if rank 0 never does, rank 1 follows.
    #[test]
    fn a_node_that_is_not_the_first_choice_still_takes_its_turn() {
        let anchors: Vec<Triple> = (0..Plane::<F2>::N as usize).map(|i| Point::<F2>::at(i).coords()).collect();
        // This node is anchor index 1 (rank 1), and believes every anchor live — so anchor 0 is the first
        // choice and this node must wait exactly one confirmation longer.
        let me = anchor(&anchors, 1);
        let mut w = RecoveryWatcher::new(4);

        // Confirmations arrive every `RECOVERY_PATIENCE` non-advancing ticks; drive them by ticking at a
        // frozen epoch and counting how many ticks it takes this node to fire.
        let mut fired_at = None;
        for tick in 1..=(RECOVERY_PATIENCE * 4) {
            if w.on_tick(me, &anchors, Epoch::ZERO) && fired_at.is_none() {
                fired_at = Some(tick);
            }
        }
        // `1 + (rank + 1) × patience`: the detector's first observation is a baseline rather than a stall,
        // then each confirmation costs a full patience window. Written as the formula, not the number, so a
        // change to `RECOVERY_PATIENCE` moves the expectation with it instead of breaking the test.
        assert_eq!(
            fired_at,
            Some(1 + 2 * RECOVERY_PATIENCE),
            "a rank-1 node takes its turn on the SECOND confirmation — one patience window after the first \
             choice had theirs, and without needing to know whether the first choice acted"
        );

        // A rank-0 node fires on the first confirmation, so the ordering is a delay and not a deadlock.
        let mut first = RecoveryWatcher::new(4);
        let mut first_fired_at = None;
        for tick in 1..=(RECOVERY_PATIENCE * 4) {
            if first.on_tick(anchor(&anchors, 0), &anchors, Epoch::ZERO) && first_fired_at.is_none() {
                first_fired_at = Some(tick);
            }
        }
        assert_eq!(
            first_fired_at,
            Some(1 + RECOVERY_PATIENCE),
            "the first choice acts on the first confirmation, so the ordering is a delay and not a deadlock"
        );
    }

    #[tokio::test]
    async fn resolve_rejects_a_malformed_name_without_touching_the_network() {
        // A name that is not a valid `.fanos` address fails at parse time, before any Get — so the
        // happy path (which needs a full cell) is covered by the resolve unit tests and the sim
        // `onoma_resolve` scenario, while this stays fast and deterministic.
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..NodeConfig::default()
        })
        .await
        .unwrap();
        // Concurrency-safe: two resolves run at once without stealing each other's replies (both
        // fail at parse here, before any network I/O — deterministic).
        let (a, b) = tokio::join!(
            node.resolve("definitely not a .fanos name", Epoch::new(0), 0),
            node.resolve("also-not-valid", Epoch::new(7), 0),
        );
        assert!(matches!(a, Err(NodeError::Resolve(_))));
        assert!(matches!(b, Err(NodeError::Resolve(_))));
        node.shutdown().await;
    }

    #[tokio::test]
    async fn the_plane_is_configurable_and_an_impossible_order_is_refused() {
        // The binary pinned `F2` at every call site, so every deployment ran PG(2,2) — 7 points, the smallest plane there
        // is — while `start` was always generic. For a mixnet that is the binding constraint: a flow hides in the set of
        // relays available, and no schedule tuning reaches past seven of them.
        for q in [2u32, 4, 7] {
            let node = Node::start_on_plane(NodeConfig { plane_order: q, ..NodeConfig::default() })
                .await
                .unwrap_or_else(|e| panic!("plane order {q} must start: {e}"));
            assert!(node.health().local_addr.port() > 0, "the node on PG(2,{q}) is live");
            // **And whether it has a reflex is reported, because "live" does not imply it** (#145). A cell
            // is seven members and only the base plane is its own cell, so a larger-plane node runs with no
            // coherence self-model, no diagnosis and no self-healing — while every other health field reads
            // fine, since the component that would say otherwise is the one that is absent. Asserted on both
            // sides so the flag cannot be a constant.
            assert_eq!(
                node.health().reflexive,
                q == 2,
                "PG(2,{q}) must report whether it forms a cell — silence here is the defect, not the plane"
            );
            node.shutdown().await;
        }

        // PG(2,q) exists only for prime powers, so a non-prime-power order is refused at the port rather than producing a
        // cell whose geometry does not close. 6 and 10 are the classical non-existence cases (Bruck–Ryser, and order 10
        // by exhaustive search).
        for q in [0u32, 1, 6, 10] {
            let err = Node::start_on_plane(NodeConfig { plane_order: q, ..NodeConfig::default() }).await;
            assert!(err.is_err(), "plane order {q} has no projective plane and must be refused");
        }
    }

    #[tokio::test]
    async fn a_node_starts_and_reports_health() {
        let node = Node::start::<F2>(NodeConfig::default()).await.unwrap();
        let health = node.health();
        assert_eq!(health.address, node.address());
        assert!(
            health.local_addr.port() > 0,
            "endpoint bound to a real port"
        );
        node.shutdown().await;
    }

    #[tokio::test]
    async fn a_node_starts_with_a_beacon_consumer_and_self_certifies_a_coordinate() {
        // A consumer-mode beacon (share = None) needs only the group commitment + threshold; the node
        // composes an OverlayBeaconNode, binds real QUIC, and self-certifies a coordinate. With no
        // anchors flooding rounds it simply sits at genesis — the epoch-advance behaviour is unit-tested
        // in overlay_beacon. This proves the Node::start wiring spawns the composite end-to-end (§7.6).
        use fanos_vrf::vss::{DeterministicRng, deal};
        let (_shares, commitment) =
            deal(&[0xB5; 32], 2, 3, &mut DeterministicRng::new(b"node-beacon")).unwrap();
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams {
                network_id: NetworkId::from_seed(b"test-network"),
                commitment,
                threshold: 2,
                share: None,
                authority: None,
            }),
            ..NodeConfig::default()
        })
        .await
        .unwrap();
        let health = node.health();
        assert_eq!(health.address, node.address());
        assert!(health.local_addr.port() > 0, "endpoint bound");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn a_relay_role_requires_beacon_parameters() {
        // A relay runs the anonymity mixnet, whose onion-key rotation locks to the beacon epoch — so the
        // role is refused without beacon parameters rather than silently running an un-rotating mixnet.
        let started = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            roles: RoleSet {
                relay: true,
                ..RoleSet::default()
            },
            ..NodeConfig::default()
        })
        .await;
        assert!(
            matches!(started, Err(NodeError::Config(_))),
            "the relay role without beacon parameters is refused"
        );
    }

    #[tokio::test]
    async fn a_service_role_requires_service_parameters() {
        // The service role hosts a threshold CALYPSO line; without the line roster + member key there is
        // nothing to serve, so the role is refused rather than silently running as a bare overlay.
        let started = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            roles: RoleSet {
                service: true,
                ..RoleSet::default()
            },
            ..NodeConfig::default()
        })
        .await;
        assert!(
            matches!(started, Err(NodeError::Config(_))),
            "the service role without service parameters is refused"
        );
    }

    #[tokio::test]
    async fn a_service_role_rejects_an_out_of_range_threshold() {
        // A threshold above the line size can never be met, and zero would serve every intro from a single
        // host — both defeat the hosting guarantee, so provisioning is rejected at start.
        for threshold in [0usize, 3] {
            let started = Node::start::<F2>(NodeConfig {
                listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                roles: RoleSet {
                    service: true,
                    ..RoleSet::default()
                },
                service: Some(ServiceParams {
                    seed: [0x5e; 32],
                    line: vec![[1, 0, 0], [0, 1, 0]],
                    threshold,
                    identity_share: None,
                }),
                ..NodeConfig::default()
            })
            .await;
            assert!(
                matches!(started, Err(NodeError::Config(_))),
                "threshold {threshold} (line size 2) is refused"
            );
        }
    }

    #[tokio::test]
    async fn a_service_node_starts_and_composes_the_hosting_engine() {
        // Valid service parameters compose a ServiceNode over the overlay and bind real QUIC — the wiring
        // path the intro-serving behaviour (unit-tested in `service_node`, sim-tested in
        // `threshold_service_live`) then runs on.
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            roles: RoleSet {
                service: true,
                ..RoleSet::default()
            },
            service: Some(ServiceParams {
                seed: [0x5e; 32],
                line: vec![[1, 0, 0], [0, 1, 0], [0, 0, 1]],
                threshold: 2,
                identity_share: None,
            }),
            ..NodeConfig::default()
        })
        .await
        .expect("a service node with valid parameters starts");
        assert!(node.health().local_addr.port() > 0, "endpoint bound");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn an_exit_role_requires_exit_parameters() {
        // The exit role bridges to the clearnet under a service identity; without its parameters there is
        // nothing to run, so the role is refused rather than silently doing nothing.
        let started = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            roles: RoleSet {
                exit: true,
                ..RoleSet::default()
            },
            ..NodeConfig::default()
        })
        .await;
        assert!(
            matches!(started, Err(NodeError::Config(_))),
            "the exit role without exit parameters is refused"
        );
    }

    #[tokio::test]
    async fn an_exit_node_starts_and_runs_the_relay() {
        // Valid exit parameters bring the node up and spawn its clearnet relay (the serve_exit/dial_exit
        // data path is exercised over real QUIC in `tests/exit_quic.rs`).
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            roles: RoleSet {
                exit: true,
                ..RoleSet::default()
            },
            exit: Some(ExitParams {
                seed: [0xe0; 32],
                allowed_ports: vec![80, 443],
            }),
            ..NodeConfig::default()
        })
        .await
        .expect("an exit node with valid parameters starts");
        assert!(node.health().local_addr.port() > 0, "endpoint bound");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn a_running_node_gets_its_roles_from_the_cell_not_its_config_file() {
        // The wiring this closes: the self-organizing role subsystem was a proven library that Node::start never
        // called, so a deployed node's roles were whatever its config said. Now config declares the OFFER and the
        // cell assigns from it — a distinction that only exists if the subsystem actually runs in a live node.
        use std::time::Duration;

        use fanos_vrf::vss::{DeterministicRng, deal};

        let (_shares, commitment) = deal(&[0xC1; 32], 2, 3, &mut DeterministicRng::new(b"role-wire")).unwrap();
        let offered = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams { network_id: NetworkId::from_seed(b"test-network"), commitment, threshold: 2, share: None, authority: None }),
            roles: offered,
            ..NodeConfig::default()
        })
        .await
        .expect("node starts");

        // The offer is what config said; the assignment is the cell's, and it converges on the offer for a cell of
        // one (nobody else can serve, so everything this node offers is wanted). Give the loop an epoch to run.
        assert_eq!(node.health().roles, offered, "health reports the OFFER");
        let mut assigned = node.assigned_roles();
        for _ in 0..200 {
            if assigned.any() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            assigned = node.assigned_roles();
        }
        assert!(
            assigned.has(Role::Relay) && assigned.has(Role::Rendezvous),
            "the cell assigned the roles this node offered (assigned = {assigned:?})"
        );
        assert!(node.serves(Role::Rendezvous), "…including the NOSTOS rendezvous role");
        // The wiring, on a live node: a running controller must say so, or the state added to close #251
        // would be reporting `Stopped` for every healthy node and mean nothing when it mattered.
        assert_eq!(
            node.health().organizing,
            crate::role_loop::RoleStanding::Deciding,
            "a node whose controller just assigned it roles must report that the controller is alive"
        );
        // A role the node never offered is never assigned — the offer is a ceiling, not a hint.
        assert!(!node.serves(Role::Exit), "an unoffered role is not assigned");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn a_relay_node_publishes_its_mix_key_to_the_directory() {
        // The Node::start relay wiring end-to-end: a relay composes a CellNode (overlay + beacon + mix
        // router) AND spawns the publisher that keeps its onion key live in the cell directory — so a
        // client's `build_cell_mix_directory` surfaces it, i.e. the anonymity mixnet is actually reachable.
        use std::time::Duration;

        use fanos_vrf::vss::{DeterministicRng, deal};

        use crate::build_cell_mix_directory;

        let (_shares, commitment) =
            deal(&[0xB6; 32], 2, 3, &mut DeterministicRng::new(b"relay-mix")).unwrap();
        let mut node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams {
                network_id: NetworkId::from_seed(b"test-network"),
                commitment,
                threshold: 2,
                share: None,
                authority: None,
            }),
            roles: RoleSet {
                relay: true,
                ..RoleSet::default()
            },
            start_heartbeat: true,
            ..NodeConfig::default()
        })
        .await
        .unwrap();

        // The publisher republishes asynchronously; poll the directory (draining notifications so the
        // engine makes progress) until the relay's own onion key appears.
        let client = node.client();
        // `Some(GENESIS)`: a `Node` always runs VRF coordinates, so its publisher writes bound records and this
        // reader must verify them (S1-M3). Passing `None` here read the bound record as a bare key and found nothing.
        //
        // This is the only live test of the *bound* path: every QUIC harness pins coordinates and so takes the unbound
        // branch. It exercises the bound one because `Node::start` sets `OverlayConfig::vrf_coordinates` and the publisher
        // therefore has a prover — assert the publisher below, since a `None` prover would silently emit bare keys that this
        // reader then would not find.
        // **This network's** genesis seed, asked of the node rather than assumed. The relay publishes its mix
        // key bound to the coordinate it actually occupies, and that coordinate is drawn against the seed
        // derived from the beacon this test provisions — not the constant. Naming the constant here was the
        // shape that hid the real defect: reader and writer agreed with each other and with nothing else.
        let genesis = client.genesis();
        let mut dir = build_cell_mix_directory::<F2>(&client, Epoch::ZERO, Some(genesis)).await.0;
        for _ in 0..30 {
            if !dir.is_empty() {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(100), node.next_notification()).await;
            dir = build_cell_mix_directory::<F2>(&client, Epoch::ZERO, Some(genesis)).await.0;
        }
        assert!(
            !dir.is_empty(),
            "the relay published its mix onion key to the cell directory"
        );
        node.shutdown().await;
    }

    #[tokio::test]
    async fn two_nodes_bootstrap_and_exchange_a_payload() {
        // Loopback so the bound address is directly dialable in-test (a public node would bind
        // 0.0.0.0 and advertise its reachable address — a Phase-2 concern).
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));

        // Bring up a first node; a second seeds its address book with the first and sends to it.
        let a = Node::start::<F2>(NodeConfig {
            listen: loopback,
            ..NodeConfig::default()
        })
        .await
        .unwrap();
        let a_addr = a.address();
        let a_net = a.local_addr();

        // A node's coordinate is derived from its (fresh, random) identity, so two nodes collide on
        // the same Fano point 1/7 of the time — which would make the coordinate→node mapping
        // ambiguous and break routing. Start B until it lands on a point distinct from A (the cell
        // invariant that members occupy distinct points).
        let make_b = || {
            Node::start::<F2>(NodeConfig {
                listen: loopback,
                bootstrap: vec![crate::config::Peer {
                    coord: a_addr,
                    addr: a_net,
                }],
                ..NodeConfig::default()
            })
        };
        let mut b = make_b().await.unwrap();
        while b.address() == a_addr {
            b.shutdown().await;
            b = make_b().await.unwrap();
        }

        b.command(Command::Send {
            to: a_addr,
            payload: b"hello over quic".to_vec(),
        });

        // a should observe the delivery. (No manual directory insert of b: b dialed in, and under
        // self-certification a's accept loop registered b's proven coordinate → source address itself.)
        let mut a = a;
        let delivered = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match a.next_notification().await {
                    Some(Notification::Delivered { payload, .. }) => break Some(payload),
                    Some(_) => {}
                    None => break None,
                }
            }
        })
        .await
        .expect("timed out waiting for delivery");
        assert_eq!(delivered.as_deref(), Some(b"hello over quic".as_slice()));

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn a_dialed_in_peer_is_routable_in_reverse_via_self_certifying_discovery() {
        // The reachability property (#119): a node that only ever *received* a connection can originate
        // traffic BACK to that peer, because under self-certification its accept loop registers the peer's
        // VRF-proven coordinate → source address (no shared directory, no manual insert). Without that
        // reverse discovery a real deployment forms a star — a dialled-in peer is unreachable in reverse.
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut a = Node::start::<F2>(NodeConfig { listen: loopback, ..NodeConfig::default() })
            .await
            .unwrap();
        let a_addr = a.address();
        let a_net = a.local_addr();

        // b bootstraps ONLY a; a is given nothing about b.
        let make_b = || {
            Node::start::<F2>(NodeConfig {
                listen: loopback,
                bootstrap: vec![crate::config::Peer { coord: a_addr, addr: a_net }],
                ..NodeConfig::default()
            })
        };
        let mut b = make_b().await.unwrap();
        while b.address() == a_addr {
            b.shutdown().await;
            b = make_b().await.unwrap();
        }
        let b_addr = b.address();

        // b dials in (its first Send establishes the connection a learns it on). Drain a's notification of
        // that inbound payload so we know the connection — and thus the reverse registration — is in place.
        b.command(Command::Send { to: a_addr, payload: b"knock".to_vec() });
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match a.next_notification().await {
                    Some(Notification::Delivered { .. }) | None => break,
                    Some(_) => {}
                }
            }
        })
        .await
        .expect("a received b's inbound knock");

        // Now the reverse direction: a originates to b. a never bootstrapped b — it can only route there
        // if it learned b's address from the inbound connection.
        a.command(Command::Send { to: b_addr, payload: b"reply over quic".to_vec() });
        let mut b = b;
        let got = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match b.next_notification().await {
                    Some(Notification::Delivered { payload, .. }) => break Some(payload),
                    Some(_) => {}
                    None => break None,
                }
            }
        })
        .await
        .expect("timed out waiting for the reverse delivery");
        assert_eq!(
            got.as_deref(),
            Some(b"reply over quic".as_slice()),
            "a routed back to a peer it only ever received a connection from (self-certifying reverse discovery)"
        );

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn a_node_hosting_ingress_publishes_the_key_its_line_needs_to_rotate_to_it() {
        // **The observable that says the rotation driver is actually running.** `emit_reshares` needs every
        // INCOMING member's KEM public, and until this driver existed nothing published one — so a dealt
        // ingress line served the epoch it was provisioned for and stayed there, which forfeits the whole
        // moving-target property §6 rests on. The driver is spawned by `Node::start`, not by a caller,
        // because a driver nobody starts is a mechanism that does not exist.
        //
        // Asserted through the STORE rather than by inspecting the task: what matters is that another node
        // could resolve this key, and that is exactly what a successful lookup proves.
        use std::time::Duration;

        use fanos_calypso::hosting::Share;
        use fanos_vrf::vss::{DeterministicRng, deal};

        use crate::config::IngressParams;
        use crate::poros::{IngressDescriptor, shard_descriptor};

        let (_shares, commitment) = deal(&[0xD2; 32], 2, 3, &mut DeterministicRng::new(b"ingress-wire")).unwrap();
        let desc = IngressDescriptor { peers: Vec::new() };
        let dealt = shard_descriptor(&desc, 2, 3, &vec![0x3Au8; 256]).expect("a valid dealing");
        let my_share = dealt.shares.first().expect("a dealing has shares").clone();
        let line: Vec<Triple> = (0..3).map(|i| Point::<F2>::at(i).coords()).collect();
        let kem_seed = [0x8Bu8; 32];

        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams { network_id: NetworkId::from_seed(b"test-network"), commitment, threshold: 2, share: None, authority: None }),
            roles: RoleSet { ingress: true, ..RoleSet::default() },
            ingress: Some(IngressParams {
                community: b"a-testnet-community".to_vec(),
                share: Share::new(1, my_share.y().to_vec()),
                binding: dealt.binding.clone(),
                line,
                threshold: 2,
                difficulty: 4,
                kem_seed,
            }),
            ..NodeConfig::default()
        })
        .await
        .expect("node starts");

        // The driver publishes at genesis before waiting on any beacon, so a line rotating out of epoch 0
        // can already resolve this member — otherwise the very first rotation would find nothing.
        let expected = crate::ingressdir::ingress_keypair(&kem_seed).1;
        let mut resolved = None;
        for _ in 0..200 {
            resolved =
                crate::ingressdir::resolve_ingress_key::<F2>(
                    &node.client(),
                    node.address(),
                    Epoch::new(0),
                    // Verified, not merely decoded: this test asserts the SHIPPED publisher binds its key
                    // (#262). Passing `None` here would let the envelope be deleted from
                    // `spawn_ingress_rotation` and leave this test green — the exact trap #80 recorded.
                    Some(node.client().genesis()),
                )
                .await;
            if resolved.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            resolved.map(|k| k.encode()),
            Some(expected.encode()),
            "an ingress-hosting node must publish the stable KEM public its line's outgoing members seal \
             reshare sub-shares to — without it the line cannot rotate, and a line that cannot rotate is a \
             line whose blocklist stops going stale",
        );
    }

    #[tokio::test]
    async fn a_one_of_n_service_line_is_refused_because_it_inverts_the_claim_it_makes() {
        // **The property, not the parameter.** `threshold_service` and `threshold_rendezvous` both state that
        // "no single host holds the service identity in the clear" and that "seizing `< threshold` reveals
        // nothing". At `t = 1` those are vacuous — `< 1` is zero members, so the guarantee says seizing
        // NOBODY learns nothing — while every member of the line holds the identity whole.
        //
        // So a 1-of-n service line is not a weaker configuration of the design; it is the design's own claim
        // inverted, and before this it started and served without a word. The sibling POROS ingress line got
        // this floor when the same shape was found in `emit_reshare`; the CALYPSO half was left behind.
        use fanos_vrf::vss::{DeterministicRng, deal};

        use crate::config::ServiceParams;

        let (_shares, commitment) = deal(&[0xE3; 32], 2, 3, &mut DeterministicRng::new(b"svc-floor")).unwrap();
        let line: Vec<Triple> = (0..3).map(|i| Point::<F2>::at(i).coords()).collect();
        let start = |threshold: usize| NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams {
                network_id: NetworkId::from_seed(b"test-network"),
                commitment: commitment.clone(),
                threshold: 2,
                share: None,
                authority: None,
            }),
            roles: RoleSet { service: true, ..RoleSet::default() },
            service: Some(ServiceParams {
                seed: [0x7A; 32],
                line: line.clone(),
                threshold,
                identity_share: None,
            }),
            ..NodeConfig::default()
        };

        assert!(
            Node::start::<F2>(start(1)).await.is_err(),
            "a 1-of-n service line must be refused at startup — it hands every member the identity whole \
             while three doc comments promise no single host holds it",
        );
        // And the floor is not over-eager: the smallest threshold that keeps the promise still starts.
        assert!(
            Node::start::<F2>(start(2)).await.is_ok(),
            "2-of-3 is the smallest line that means what the design says, and it must still run",
        );
    }

    /// **A member whose custody slot belongs to somebody else is refused at startup, not at the emergency.**
    ///
    /// §12.3 half (a) deals one `SealedShare` per member, openable under the KEM secret that member's `seed`
    /// regenerates and under no other. `seed` and `identity_share` are therefore one member's pair — and the
    /// ways an operator separates them are the ordinary ones: `service-2.conf` copied to the wrong host, two
    /// files swapped, one file kept across a re-deal that drew fresh seeds.
    ///
    /// Every one of those starts, serves every intro correctly (half (b) reads `seed` and never touches this
    /// slot), and is discovered only when the service must authenticate — which is, by construction, the
    /// moment it least can afford to find out. This is the check that converts a deferred silent failure
    /// into a refusal an operator can still act on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_custody_slot_sealed_to_another_member_is_refused_at_startup() {
        use fanos_calypso::hosting::deal_service_key;
        use fanos_pqcrypto::HybridKemSecret;
        use fanos_vrf::vss::{DeterministicRng, deal};

        use crate::config::ServiceParams;

        let (_shares, commitment) = deal(&[0xE3; 32], 2, 3, &mut DeterministicRng::new(b"svc-custody")).unwrap();
        let line: Vec<Triple> = (0..3).map(|i| Point::<F2>::at(i).coords()).collect();

        // Deal a real identity across three members whose seeds are the ones their files would carry.
        let seeds: [[u8; 32]; 3] = [[0xA1; 32], [0xB2; 32], [0xC3; 32]];
        let publics: Vec<_> = seeds
            .iter()
            .map(|s| HybridKemSecret::generate(&mut SeedRng::from_seed(s)).1)
            .collect();
        let refs: Vec<_> = publics.iter().collect();
        let sealed = deal_service_key(b"a service identity seed, 32 bytes", 2, &refs, &[9u8; 128], b"kem")
            .expect("the ceremony deals");

        let start = |seed_index: usize, slot_index: usize| NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams {
                network_id: NetworkId::from_seed(b"test-network"),
                commitment: commitment.clone(),
                threshold: 2,
                share: None,
                authority: None,
            }),
            roles: RoleSet { service: true, ..RoleSet::default() },
            service: Some(ServiceParams {
                seed: *seeds.get(seed_index).expect("a seed this test dealt"),
                line: line.clone(),
                threshold: 2,
                // `expect`, not `.cloned()`: an out-of-range index would silently become `None` — no
                // custody at all — and the mismatch assertion below would then pass for the opposite
                // reason to the one it claims.
                identity_share: Some(sealed.get(slot_index).expect("a slot this test dealt").clone()),
            }),
            ..NodeConfig::default()
        };

        // THE CONTROL FIRST, so a refusal that refuses everything cannot pass for this check: the pair the
        // ceremony actually wrote together must start.
        assert!(
            Node::start::<F2>(start(1, 1)).await.is_ok(),
            "the seed and the slot the ceremony wrote into ONE file must run — otherwise this guard is \
             refusing custody as such rather than refusing a mismatch",
        );

        // And the mismatch — member 1's seed beside member 2's slot — must not.
        assert!(
            Node::start::<F2>(start(1, 2)).await.is_err(),
            "a slot sealed to another member must be refused at startup: it opens for nobody here, so this \
             node would serve every intro and be unable to contribute to its own service's identity",
        );
    }

    #[tokio::test]
    async fn a_beacon_threshold_that_the_commitment_does_not_have_is_refused() {
        // **The most consequential parameter, and it was the least checked.** `bp.threshold` went straight
        // into `BeaconNode::new` with no floor and no comparison against the commitment — which knows the
        // degree it was dealt at, since it carries exactly `t` coefficients.
        //
        // A mismatch describes a beacon that does not exist. Rounds either never assemble (threshold above
        // the degree) or assemble from too few partials and verify against a polynomial of the wrong degree.
        // Either way the node runs, floods, and silently never adopts an epoch, with nothing pointing at the
        // file that caused it.
        use fanos_vrf::vss::{DeterministicRng, deal};

        let (_shares, commitment) = deal(&[0xB4; 32], 3, 5, &mut DeterministicRng::new(b"beacon-check")).unwrap();
        let start = |threshold: usize| NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams {
                network_id: NetworkId::from_seed(b"test-network"),
                commitment: commitment.clone(),
                threshold,
                share: None,
                authority: None,
            }),
            ..NodeConfig::default()
        };

        assert!(
            Node::start::<F2>(start(3)).await.is_ok(),
            "the threshold the commitment was dealt at is accepted",
        );
        assert!(
            Node::start::<F2>(start(2)).await.is_err(),
            "a threshold BELOW the commitment's degree must be refused — it would verify rounds against a \
             polynomial of the wrong degree",
        );
        assert!(
            Node::start::<F2>(start(4)).await.is_err(),
            "and one above it must be refused too — rounds would never assemble, silently",
        );
    }

    #[tokio::test]
    async fn a_single_operator_beacon_still_starts_because_it_is_a_documented_deployment() {
        // **The floor I nearly added, and why it was wrong.** At `t = 1` one anchor reconstructs the epoch
        // randomness alone and so chooses every node's coordinate — which sounds exactly like the inversion
        // the service line's `t ≥ 2` floor prevents, and I added the same floor here on that reasoning.
        //
        // It refused `fanos beacon-deal 1 1`, which `docs/design-governance.md` §2.1 documents as "correct
        // for a private or test cell, where the dealer is the only operator". With ONE anchor, `t = 1` is the
        // only threshold that exists and distributes nothing that was ever distributed. The service line is
        // different because a line has `q+1` members by construction — there, `t = 1` really is one of
        // several holding everything.
        //
        // `BeaconParams` cannot tell the two apart: it carries the commitment and this node's share, never
        // the anchor count. So the check that CAN be made is made, and this pins that the one that cannot is
        // not faked with a floor that refuses a real deployment.
        use fanos_vrf::vss::{DeterministicRng, deal};

        let (shares, commitment) = deal(&[0xB5; 32], 1, 1, &mut DeterministicRng::new(b"solo-beacon")).unwrap();
        let share = shares.into_iter().next();
        assert!(
            Node::start::<F2>(NodeConfig {
                listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                beacon: Some(BeaconParams { network_id: NetworkId::from_seed(b"test-network"), commitment, threshold: 1, share, authority: None }),
                ..NodeConfig::default()
            })
            .await
            .is_ok(),
            "a single-operator 1-of-1 beacon is a documented configuration and must still start",
        );
    }

    #[test]
    fn two_networks_seat_the_same_identity_at_different_genesis_points() {
        // **The property, not the plumbing.** Epoch 0 has no reshuffle, and on `q = 2` the reshuffle is the
        // entire placement defence — so the genesis coordinate is only as unpredictable as its seed. With
        // `BeaconSeed::GENESIS` a compile-time constant it was not unpredictable at all, and worse, it was
        // the SAME constant everywhere: one grinding effort bought a chosen genesis placement on every FANOS
        // deployment that will ever exist, computed before any of them was founded.
        //
        // So the observable is that an identity's genesis placement now depends on WHICH NETWORK it joins.
        // Asserted over the seeds rather than over a running node because that is where the property lives —
        // the transport reads `Directory::genesis()`, and a test that stood up two cells would be measuring
        // the same equality through more machinery.
        // Drawn from each network's NAME, not from its beacon commitment (#98). The commitment was the
        // obvious source — it is the one per-network random value everybody necessarily holds — and it made
        // the network's public name a Feldman `x·G` over its own master secret, published everywhere and,
        // being the name, unwithdrawable. The property below is the same either way, which is exactly why
        // nothing caught the coupling: it is invisible to any test that only asks "do two networks differ?".
        let net_a = NetworkId::from_seed(b"network-a");
        let net_b = NetworkId::from_seed(b"network-b");

        let (a, b) = (genesis_seed(&net_a), genesis_seed(&net_b));
        assert_ne!(
            a.as_bytes(),
            b.as_bytes(),
            "two networks must not share a genesis seed — sharing one is what let a single grinding effort \
             hold a chosen placement on every deployment at once",
        );
        assert_ne!(
            a.as_bytes(),
            BeaconSeed::GENESIS.as_bytes(),
            "and neither may be the shared constant",
        );
        assert_eq!(
            genesis_seed(&net_a).as_bytes(),
            a.as_bytes(),
            "deterministic in the name: every node of one network must derive the identical seed, or they \
             seat themselves in different coordinate spaces and cannot verify each other at epoch 0",
        );
    }

    /// **The network's name is independent of its beacon** (#98) — the property the old derivation could not
    /// have, and which no "do two networks differ?" test can see.
    ///
    /// `genesis_seed` used to hash the `VssCommitment`. That is a Feldman commitment `x·G` over ristretto255,
    /// so the network's public name was a discrete-log encryption of the beacon master secret — published in
    /// every provisioning file and, *because it was the name*, impossible to withdraw. What this buys is not
    /// a bound on that exposure (an archived file still holds the commitment) but the **precondition for
    /// retiring one**: re-deal the beacon, keep the name, and a later discrete-log solve reaches only the
    /// epochs its own commitment served instead of all history.
    ///
    /// Both halves are needed. That one name gives one seed across different beacons is the decoupling; that
    /// two names give different seeds is what stops the first from being satisfied by a constant.
    #[test]
    fn the_networks_name_is_independent_of_the_beacon_it_runs() {
        use fanos_vrf::vss::{DeterministicRng, deal};

        let name = NetworkId::from_seed(b"one-network");
        let (_x, first) = deal(&[0x44; 32], 2, 3, &mut DeterministicRng::new(b"beacon-one")).unwrap();
        let (_y, second) = deal(&[0x55; 32], 2, 3, &mut DeterministicRng::new(b"beacon-two")).unwrap();
        assert_ne!(first.to_bytes(), second.to_bytes(), "two genuinely different beacons, or this proves nothing");

        let before = BeaconParams { network_id: name, commitment: first, threshold: 2, share: None, authority: None };
        let after = BeaconParams { network_id: name, commitment: second, threshold: 2, share: None, authority: None };
        assert_eq!(
            before.genesis_seed().as_bytes(),
            after.genesis_seed().as_bytes(),
            "the beacon was replaced and the network kept its name — this is what a rotation needs, and what \
             hashing the commitment made impossible without re-seating every node",
        );

        // And the name still separates networks, or the decoupling above would be satisfied by a constant.
        let elsewhere = NetworkId::from_seed(b"another-network");
        assert_ne!(genesis_seed(&name).as_bytes(), genesis_seed(&elsewhere).as_bytes());
    }

    #[tokio::test]
    async fn a_node_with_a_beacon_binds_its_directory_to_that_network() {
        // The wiring the property needs: `Node::start` must bind at directory CREATION, because a directory
        // bound later leaves every earlier use on the shared constant — and the whole point is that one value
        // reaches both sites that must agree, the node's own seat and the window peers' claims are checked
        // against.
        use fanos_vrf::vss::{DeterministicRng, deal};

        let (_s, commitment) = deal(&[0x33; 32], 2, 3, &mut DeterministicRng::new(b"bound-net")).unwrap();
        let network_id = NetworkId::from_seed(b"bound-net");
        let expected = genesis_seed(&network_id);
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams { network_id, commitment, threshold: 2, share: None, authority: None }),
            ..NodeConfig::default()
        })
        .await
        .expect("node starts");

        assert_eq!(
            node.directory().genesis().as_bytes(),
            expected.as_bytes(),
            "a node provisioned with a beacon must run on that network's genesis seed, not the constant",
        );
    }
}
