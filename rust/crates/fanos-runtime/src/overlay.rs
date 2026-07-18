//! `OverlayNode` — the base FANOS node engine (spec L1/L3 + DIAKRISIS), sans-I/O.
//!
//! This is production node logic: it maintains liveness of its cell neighbours via periodic
//! heartbeats, resolves rendezvous by the algebraic line `u × v`, delivers application
//! payloads, and (on the base Fano cell) runs one DIAKRISIS round to localize a fault. It
//! reacts only to [`Input`]s and emits only [`Effect`]s — no clock, socket, or RNG — so the
//! same code runs under the simulator and a real transport.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use fanos_crypto::hash::label;
use fanos_crypto::{hash_labeled, map_to_point};
use fanos_diakrisis::coherence::phi_equicorrelated;
use fanos_diakrisis::monitor::BehaviorMonitor;
use fanos_diakrisis::{BandControl, HealingAction, Homeostat, Observation, diagnose, plan_healing};
use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_telemetry::{CellId, HistoryConfig, SelfObserver};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// Storage `Publish` sub-type: the responsible node fans out replicas; a replica just stores.
const PUBLISH_ORIGIN: u8 = 0;
/// Storage `Publish` sub-type: a replica copy — store it, do not re-fan-out.
const PUBLISH_REPLICA: u8 = 1;
/// The DHT key-digest / storage-address length (BLAKE3-256).
const DIGEST: usize = 32;

use crate::ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

/// The single heartbeat timer token.
const HEARTBEAT: TimerToken = TimerToken(0);

/// The behavioural-coherence observation window, in heartbeat samples: the cell's `Γ_net` is read from the
/// last this-many per-node relay-activity samples. Bounded, so the self-model memory is `7 × this`.
const BEHAVIOR_WINDOW: usize = 8;

/// How long a locally-distrusted (Byzantine) member stays quarantined before it is re-admitted for
/// re-evaluation. Quarantine is an *operational* safeguard, not a proven permanent exclusion (spec §6.2):
/// permanently exiling a member would strand one that only glitched transiently. After this window the
/// member is re-admitted; if it is still structurally inconsistent the next diagnosis re-quarantines it
/// (the polar sum-rules re-catch it), and the authoritative clear remains the parent's re-provisioning
/// (escalation). Bounded, so `quarantined` cannot grow without limit either (audit C5).
const QUARANTINE_TTL: Duration = Duration::from_millis(60_000);

/// Configuration of a node's liveness behaviour.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Config {
    /// Interval between heartbeat rounds.
    pub heartbeat: Duration,
    /// A peer unheard-from for longer than this is considered degraded.
    pub liveness_timeout: Duration,
    /// The healthy mean inter-node correlation `r` used to estimate the cell's integration `Φ`
    /// for the healing budget (`Φ_net = (N−1)·r²`, spec §2.7). The default `0.45` sits in the
    /// collective-subject band `(1/√6, 1/√3]` (spec §18.2), so a full cell reads `Φ ≈ 1.2 ≥ 1`.
    pub healthy_correlation: f64,
    /// Whether the node acts on its diagnosis (reroute / repair / escalate). On by default; the
    /// reflexive loop *senses and acts* (spec §6.9). Set `false` for a sense-only node.
    pub self_healing: bool,
    /// How many *distinct* witnesses must corroborate a peer's liveness before it is believed on
    /// gossip alone (own direct observation is always trusted). Tolerates up to `quorum − 1`
    /// Byzantine liars falsely vouching for a dead node (spec §6.4). Default `2`.
    pub corroboration_quorum: usize,
    /// How long a `Get` waits for a replica's `Value` answer before falling back to the next
    /// replica on the responsible point's line (spec §L4 read repair). Only bounds the latency of
    /// the *silent-replica* case — a `found=false` answer advances immediately. Default `1600 ms`.
    pub read_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_millis(500),
            liveness_timeout: Duration::from_millis(1600),
            healthy_correlation: 0.45,
            self_healing: true,
            corroboration_quorum: 2,
            read_timeout: Duration::from_millis(1600),
        }
    }
}

/// An in-flight `Get` awaiting a replica's answer: the replica candidates not yet tried (the
/// primary is queried first, these are the LRC fallbacks) and when the current query was issued
/// (for the silent-replica timeout). Read repair across the responsible line (spec §L4).
#[derive(Clone, Debug)]
struct PendingGet {
    issued: Instant,
    remaining: Vec<Triple>,
}

/// What we know about a cell neighbour.
#[derive(Clone, Copy, Debug)]
struct Peer {
    last_seen: Option<Instant>,
    reported_down: bool,
}

/// The base overlay node engine, generic over the cell's field `F`.
pub struct OverlayNode<F: Field> {
    coord: Point<F>,
    config: Config,
    started_at: Instant,
    peers: BTreeMap<Triple, Peer>,
    heartbeating: bool,
    /// This node's Fano point index (`Some` only on the base `N = 7` cell, where the reflexive
    /// loop's index-addressed geometry — syndrome, mediator, peeling — applies).
    self_index: Option<usize>,
    /// Self-healing routing state: to reach the (down) key coordinate, contact the value
    /// coordinate — the co-linear survivor from the projective LRC reroute (spec §L4).
    reroute: BTreeMap<Triple, Triple>,
    /// Nodes whose shard this cell has regenerated by peeling (spec §6.3), for observability.
    repaired: BTreeSet<Triple>,
    /// Members locally distrusted after a polar-rule violation (spec §6.2); their frames are
    /// dropped pending parental re-provisioning.
    quarantined: BTreeMap<Triple, Instant>,
    /// Witness-corroborated liveness (spec §6.4): for each peer, the freshest time *each distinct
    /// witness* directly observed it, learned from health-view gossip (`DiagGossip`). A lossy link
    /// cannot forge a false PeerDown (any honest witness rescues liveness), and a *Byzantine* liar
    /// cannot forge a false liveness either — a peer is believed alive on gossip only when a
    /// **quorum** of distinct witnesses vouch for it, so `quorum − 1` liars are outvoted.
    witnessed: BTreeMap<Triple, BTreeMap<Triple, Instant>>,
    /// This node's slice of the cell's distributed store (spec §L4): key digest → value. A value
    /// lives on its responsible point `MapToPoint(H(key))` and is replicated across the cell for
    /// LRC availability, so any survivor answers a lookup — and a lookup to a *down* primary
    /// reroutes to a replica through the same self-healing table (§6.7).
    store: BTreeMap<[u8; DIGEST], Vec<u8>>,
    /// In-flight `Get`s awaiting a `Value` answer, keyed by digest (spec §L4 read repair). A read
    /// consults the primary, then falls back through the replica line on a `found=false` or a
    /// silent-replica timeout, concluding "absent" only once the replicas are exhausted — so any
    /// surviving replica answers even when the primary recovered empty after churn.
    pending_gets: BTreeMap<[u8; DIGEST], PendingGet>,
    /// The membership view: cell coordinate → announced info (public keys, capabilities), learned
    /// by flooding JOIN announcements (spec §7.8). This is the key distribution onion routing reads.
    members: BTreeMap<Triple, Vec<u8>>,
    /// The current epoch, driven by the flooded beacon (adopt-max, spec §L3). Epoch-derived
    /// rendezvous/shapes rotate as it advances.
    epoch: u32,
    /// Mandatory per-node self-observation (`fanos_telemetry`): every diagnosis folds the cell's
    /// health into a `CoherenceFrame` and records it into bounded local history. Not optional — the
    /// reflexive loop cannot diagnose without observing (docs/design-telemetry.md).
    observer: SelfObserver,
    /// Per-peer **data-relay** activity (`Route` frames) accumulated since the last behavioural sample —
    /// the raw counts the coherence self-model is built from. Control chatter (pings, gossip) is excluded,
    /// so this reflects *load*, not liveness.
    activity: BTreeMap<Triple, u32>,
    /// This node's own relay activity (`Route` frames it originated) since the last sample — the self slot
    /// of the behavioural sample vector.
    self_activity: u32,
    /// The behavioural coherence monitor: a bounded window of per-node relay activity, read as the cell's
    /// real `Γ_net` so the [`Homeostat`] runs on *measured* correlation, not the liveness proxy (base cell).
    monitor: BehaviorMonitor,
    /// The coherence homeostat this node runs on its behavioural self-model — the sense→act seam, with the
    /// monitor sensing and `on_diagnose` actuating its band-keeping decision.
    homeostat: Homeostat,
}

/// A stable 16-byte identifier for a node's cell — a domain-separated hash of the canonical Fano
/// point coordinates, so every node in the cell derives the *same* id and their coherence frames
/// agree on which cell they describe.
fn cell_id<F: Field>() -> CellId {
    let mut input = Vec::with_capacity(7 * 12);
    for i in 0..7usize {
        for x in Point::<F>::at(i).coords() {
            input.extend_from_slice(&x.to_be_bytes());
        }
    }
    let digest = hash_labeled("FANOS-v1/cell-id", &input);
    let mut id = [0u8; 16];
    for (dst, src) in id.iter_mut().zip(digest) {
        *dst = src;
    }
    CellId(id)
}

impl<F: Field> OverlayNode<F> {
    /// Create a node at `coord`. Its cell neighbours are derived algebraically (the points on
    /// its `q+1` lines) — no discovery walk (spec §L1).
    #[must_use]
    pub fn new(coord: Point<F>, config: Config) -> Self {
        let mut peers = BTreeMap::new();
        for line in Plane::<F>::lines_through(coord) {
            for member in Plane::<F>::points_on(line) {
                if member != coord {
                    peers.entry(member.coords()).or_insert(Peer {
                        last_seen: None,
                        reported_down: false,
                    });
                }
            }
        }
        // On the base Fano cell, find this node's point index (its reflexive-loop address).
        let self_index = if Plane::<F>::N == 7 {
            (0..7).find(|&i| Point::<F>::at(i) == coord)
        } else {
            None
        };
        // The observation window is the heartbeat interval; local history stays compact and bounded.
        let observer = SelfObserver::new(
            cell_id::<F>(),
            config.heartbeat.as_nanos(),
            HistoryConfig::compact(),
        );
        Self {
            coord,
            config,
            started_at: Instant::default(),
            peers,
            heartbeating: false,
            self_index,
            reroute: BTreeMap::new(),
            repaired: BTreeSet::new(),
            quarantined: BTreeMap::new(),
            witnessed: BTreeMap::new(),
            store: BTreeMap::new(),
            pending_gets: BTreeMap::new(),
            members: BTreeMap::new(),
            epoch: 0,
            observer,
            activity: BTreeMap::new(),
            self_activity: 0,
            monitor: BehaviorMonitor::new(7, BEHAVIOR_WINDOW),
            homeostat: Homeostat::conservative(),
        }
    }

    /// The node's cell neighbour coordinates (its quorum members).
    pub fn neighbours(&self) -> impl Iterator<Item = Triple> + '_ {
        self.peers.keys().copied()
    }

    /// Whether `coord` is live, corroborated across its line-witnesses (spec §6.4). Our own direct
    /// observation is fully trusted; otherwise a **quorum** of distinct fresh witnesses is required,
    /// so a lossy link cannot forge a PeerDown *and* a lone Byzantine liar cannot forge liveness.
    fn coord_alive(&self, coord: Triple, now: Instant) -> bool {
        let timeout = self.config.liveness_timeout;
        // Trust our own eyes first.
        if let Some(seen) = self.peers.get(&coord).and_then(|p| p.last_seen)
            && now.since(seen) <= timeout
        {
            return true;
        }
        // Otherwise: a quorum of distinct witnesses must vouch for it within the window.
        let fresh = self.witnessed.get(&coord).map_or(0, |witnesses| {
            witnesses
                .values()
                .filter(|&&seen| now.since(seen) <= timeout)
                .count()
        });
        if fresh >= self.config.corroboration_quorum {
            return true;
        }
        // Startup grace: if nothing has been observed about this peer yet, assume alive briefly.
        let unobserved = self.peers.get(&coord).and_then(|p| p.last_seen).is_none()
            && self.witnessed.get(&coord).is_none_or(BTreeMap::is_empty);
        unobserved && now.since(self.started_at) <= timeout
    }

    fn on_heartbeat(&mut self, now: Instant) -> Vec<Effect> {
        let mut effects = Vec::new();
        let ping = encode(FrameType::Ping, &[]);
        // A health-view: how stale this node's *direct* observation of each cell point is, so
        // peers can corroborate liveness across the projective witness set (spec §6.4, §6.8).
        let gossip = self
            .self_index
            .map(|_| encode(FrameType::DiagGossip, &self.health_view(now)));
        // Detect newly-down peers (by the corroborated view), and (re-)ping + gossip everyone.
        let neighbours: Vec<Triple> = self.peers.keys().copied().collect();
        for coord in neighbours {
            let alive = self.coord_alive(coord, now);
            if let Some(peer) = self.peers.get_mut(&coord)
                && !alive
                && !peer.reported_down
            {
                peer.reported_down = true;
                effects.push(Effect::Notify(Notification::PeerDown(coord)));
            }
            effects.push(Effect::Send {
                to: coord,
                frame: ping.clone(),
            });
            if let Some(gossip) = &gossip {
                effects.push(Effect::Send {
                    to: coord,
                    frame: gossip.clone(),
                });
            }
        }
        // Read repair: advance any Get whose current replica has gone silent past the read timeout.
        self.sweep_pending_gets(now, &mut effects);
        // Fold this window's relay activity into the behavioural coherence self-model.
        self.sample_behavior();
        effects.push(Effect::ArmTimer {
            token: HEARTBEAT,
            after: self.config.heartbeat,
        });
        effects
    }

    /// Fold this window's per-node relay activity into the behavioural coherence [`monitor`](Self::monitor),
    /// then reset the accumulators. Base Fano cell only, where the 7-point index geometry applies; the
    /// sample's `i`-th slot is point `i`'s relay activity (this node's own for its index, else the peer's).
    fn sample_behavior(&mut self) {
        let Some(self_index) = self.self_index else {
            return;
        };
        let mut sample = [0.0f64; 7];
        for (i, slot) in sample.iter_mut().enumerate() {
            *slot = if i == self_index {
                f64::from(self.self_activity)
            } else {
                let coord = Point::<F>::at(i).coords();
                f64::from(self.activity.get(&coord).copied().unwrap_or(0))
            };
        }
        self.monitor.record(&sample);
        self.activity.clear();
        self.self_activity = 0;
    }

    /// Advance reads whose outstanding replica has not answered within `read_timeout`: try the next
    /// replica on the line, or conclude `Retrieved(None)` once they are exhausted (spec §L4). This
    /// is the backstop for a *crashed* replica (a live one answers `found=false` immediately).
    fn sweep_pending_gets(&mut self, now: Instant, effects: &mut Vec<Effect>) {
        let timeout = self.config.read_timeout;
        let stale: Vec<[u8; DIGEST]> = self
            .pending_gets
            .iter()
            .filter(|(_, p)| now.since(p.issued) > timeout)
            .map(|(digest, _)| *digest)
            .collect();
        for digest in stale {
            self.advance_pending_get(now, digest, effects);
        }
    }

    /// Encode this node's direct-observation ages over the Fano cell: `7 × u16` little-endian
    /// milliseconds since it last heard each point (`u16::MAX` = never / stale). Self reads `0`.
    fn health_view(&self, now: Instant) -> Vec<u8> {
        let mut body = Vec::with_capacity(14);
        for i in 0..7usize {
            let coord = Point::<F>::at(i).coords();
            let age = if coord == self.coord.coords() {
                0
            } else {
                match self.peers.get(&coord).and_then(|p| p.last_seen) {
                    Some(seen) => {
                        (now.since(seen).as_nanos() / 1_000_000).min(u64::from(u16::MAX)) as u16
                    }
                    None => u16::MAX,
                }
            };
            body.extend_from_slice(&age.to_le_bytes());
        }
        body
    }

    /// Fold witness `from`'s health-view into the corroborated `witnessed` map: for each cell point
    /// the gossip reports a fresh direct observation of, remember the freshest time *this witness*
    /// vouched for it. Keeping witnesses distinct is what makes the quorum Byzantine-robust — a lone
    /// liar is one entry, not a majority.
    fn apply_health_view(&mut self, now: Instant, from: Triple, body: &[u8]) {
        for i in 0..7usize {
            let (Some(&lo), Some(&hi)) = (body.get(i * 2), body.get(i * 2 + 1)) else {
                break;
            };
            let age_ms = u16::from_le_bytes([lo, hi]);
            if age_ms == u16::MAX {
                continue; // the gossiper had no fresh observation of point i
            }
            let observed = Instant(now.as_nanos().saturating_sub(u64::from(age_ms) * 1_000_000));
            let coord = Point::<F>::at(i).coords();
            let slot = self
                .witnessed
                .entry(coord)
                .or_default()
                .entry(from)
                .or_insert(observed);
            if observed > *slot {
                *slot = observed;
            }
        }
    }

    fn on_message(&mut self, now: Instant, from: Triple, frame: &[u8]) -> Vec<Effect> {
        // A locally-quarantined (Byzantine) member's frames are dropped (spec §6.2, §6.4) — but only for
        // the bounded quarantine window; once it elapses the member is re-admitted for re-evaluation, so a
        // transient fault is not a permanent exile (audit C5).
        if let Some(&since) = self.quarantined.get(&from) {
            if now.since(since) <= QUARANTINE_TTL {
                return Vec::new();
            }
            self.quarantined.remove(&from); // window elapsed — re-admit; re-diagnosis re-quarantines if bad
        }
        let Ok((frame, _)) = decode_frame(frame) else {
            return Vec::new(); // canonical decode failure — drop (spec §7.5)
        };
        match frame.frame_type() {
            Some(FrameType::Ping) => alloc::vec![Effect::Send {
                to: from,
                frame: encode(FrameType::Pong, &[]),
            }],
            Some(FrameType::Pong) => {
                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.last_seen = Some(now);
                    peer.reported_down = false;
                }
                // A recovered node no longer needs rerouting/repair (churn rejoin, spec §3.3).
                self.reroute.remove(&from);
                self.repaired.remove(&from);
                Vec::new()
            }
            Some(FrameType::Route) => {
                // Data relay is the behavioural load signal (control chatter is excluded); count it toward
                // this peer's activity, folded into the coherence self-model on the next heartbeat sample.
                let a = self.activity.entry(from).or_insert(0);
                *a = a.saturating_add(1);
                alloc::vec![Effect::Notify(Notification::Delivered {
                    from,
                    payload: frame.body.to_vec(),
                })]
            }
            Some(FrameType::DiagGossip) => {
                // Receiving the gossip is itself a direct observation of the sender; its body
                // corroborates the sender's view of the rest of the cell (spec §6.4).
                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.last_seen = Some(now);
                    peer.reported_down = false;
                }
                self.reroute.remove(&from);
                self.repaired.remove(&from);
                self.apply_health_view(now, from, frame.body);
                Vec::new()
            }
            Some(FrameType::Publish) => self.on_publish(from, frame.body),
            Some(FrameType::Lookup) => self.on_lookup(from, frame.body),
            Some(FrameType::Value) => self.on_value(now, frame.body),
            Some(FrameType::Ack) => Self::on_ack(frame.body),
            Some(FrameType::Announce) => self.on_announce(frame.body),
            Some(FrameType::Beacon) => self.on_beacon(frame.body),
            _ => Vec::new(),
        }
    }

    fn on_send(&mut self, to: Triple, payload: &[u8]) -> Vec<Effect> {
        // This node originating a relay is its own behavioural activity (the self slot of the sample).
        self.self_activity = self.self_activity.saturating_add(1);
        let mut effects = Vec::new();
        // Compute the rendezvous line u × v (O(1)); report it for observation, then deliver.
        if let Some(dst) = Point::<F>::new(to)
            && let Some(line) = self.coord.join(&dst)
        {
            effects.push(Effect::Notify(Notification::RendezvousLine(line.coords())));
        }
        // Self-healing reroute: if the destination is a down node whose data the LRC has placed
        // on a co-linear survivor, deliver there instead (spec §L4 availability, §6.7).
        effects.push(self.routed_send(to, encode(FrameType::Route, payload)));
        effects
    }

    /// Send `frame` to `to`, transparently rerouted to a co-linear survivor if `to` is a node the
    /// self-healing layer has marked down (spec §6.7). The single seam every store/route uses.
    fn routed_send(&self, to: Triple, frame: Vec<u8>) -> Effect {
        let actual = self.reroute.get(&to).copied().unwrap_or(to);
        Effect::Send { to: actual, frame }
    }

    /// The DHT storage address of `key`: the digest and the responsible point (spec §L4).
    fn address_of(key: &[u8]) -> ([u8; DIGEST], Triple) {
        let digest = hash_labeled(label::STORAGE, key);
        let primary = map_to_point::<F>(label::STORAGE, key).coords();
        (digest, primary)
    }

    /// `Command::Put` — store a value at its responsible point and replicate it across the cell.
    fn on_put(&mut self, key: &[u8], value: Vec<u8>) -> Vec<Effect> {
        let (digest, primary) = Self::address_of(key);
        if primary == self.coord.coords() {
            // We are the responsible node: store, replicate to the cell, ack ourselves.
            let mut effects = self.replicate(&digest, &value);
            effects.push(Effect::Notify(Notification::Stored(digest)));
            self.store.insert(digest, value);
            effects
        } else {
            alloc::vec![self.routed_send(primary, encode_publish(PUBLISH_ORIGIN, &digest, &value))]
        }
    }

    /// `Command::Get` — answer from the local replica if present, else read-repair across the
    /// responsible point's replica line (spec §L4).
    ///
    /// A `Put` replicates to every cell member, so any survivor holds the value. The read queries
    /// the responsible primary first (rerouted to a co-linear survivor if it is *down*, §6.7) and,
    /// on a `found=false` reply or a silent-replica timeout, falls back through the remaining
    /// replicas — concluding `Retrieved(None)` only once they are exhausted. This makes the LRC
    /// availability guarantee hold on *read* too: a value is found even when the primary recovered
    /// empty after churn while replicas still hold it. The in-flight query is tracked in
    /// [`pending_gets`](Self::pending_gets); [`on_value`](Self::on_value) and the heartbeat sweep drive it.
    fn on_get(&mut self, now: Instant, key: &[u8]) -> Vec<Effect> {
        let (digest, primary) = Self::address_of(key);
        if let Some(value) = self.store.get(&digest) {
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: Some(value.clone()),
            })];
        }
        // Fallback replicas: every other cell member could hold a replica; query the primary now
        // and keep the rest (live ones first) for read repair. A repeat Get simply refreshes them.
        let remaining: Vec<Triple> = self
            .peers
            .keys()
            .copied()
            .filter(|&c| c != primary)
            .collect();
        self.pending_gets.insert(
            digest,
            PendingGet {
                issued: now,
                remaining,
            },
        );
        alloc::vec![self.routed_send(primary, encode_lookup(&digest))]
    }

    /// Fan a value out to every cell member as a replica (LRC availability, spec §L4).
    fn replicate(&self, digest: &[u8; DIGEST], value: &[u8]) -> Vec<Effect> {
        self.peers
            .keys()
            .map(|&peer| Effect::Send {
                to: peer,
                frame: encode_publish(PUBLISH_REPLICA, digest, value),
            })
            .collect()
    }

    fn on_publish(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some(&flag) = body.first() else {
            return Vec::new();
        };
        let Some(digest) = parse_digest(body.get(1..1 + DIGEST)) else {
            return Vec::new();
        };
        let value = body.get(1 + DIGEST..).unwrap_or(&[]).to_vec();
        self.store.insert(digest, value.clone());
        if flag == PUBLISH_ORIGIN {
            // We are the responsible node: replicate across the cell and acknowledge the origin.
            let mut effects = self.replicate(&digest, &value);
            effects.push(Effect::Send {
                to: from,
                frame: encode(FrameType::Ack, &digest),
            });
            effects
        } else {
            Vec::new()
        }
    }

    fn on_lookup(&self, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some(digest) = parse_digest(body.get(..DIGEST)) else {
            return Vec::new();
        };
        let (found, value): (bool, &[u8]) = match self.store.get(&digest) {
            Some(v) => (true, v),
            None => (false, &[]),
        };
        alloc::vec![Effect::Send {
            to: from,
            frame: encode_value(&digest, found, value),
        }]
    }

    /// A `Value` reply to one of our lookups (spec §L4). `found=true` resolves the pending read
    /// with the value; `found=false` advances to the next replica on the line, or concludes
    /// `Retrieved(None)` once the replicas are exhausted (read repair).
    fn on_value(&mut self, now: Instant, body: &[u8]) -> Vec<Effect> {
        let Some(digest) = parse_digest(body.get(..DIGEST)) else {
            return Vec::new();
        };
        let found = body.get(DIGEST).copied().unwrap_or(0) != 0;
        if found {
            // A survivor has it. Deliver once and retire the pending read (later dup replies are
            // ignored because the entry is gone).
            self.pending_gets.remove(&digest);
            let value = Some(body.get(DIGEST + 1..).unwrap_or(&[]).to_vec());
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value
            })];
        }
        // A negative reply: advance the pending read to the next replica, or conclude it absent.
        // (No pending entry ⇒ already resolved / stale reply ⇒ nothing to do.)
        let mut effects = Vec::new();
        if self.pending_gets.contains_key(&digest) {
            self.advance_pending_get(now, digest, &mut effects);
        }
        effects
    }

    /// Advance one pending `Get` after its outstanding replica declined or went silent: query the
    /// next replica on the responsible line, or — once they are exhausted — conclude `Retrieved(None)`
    /// and retire the read. The single seam shared by the negative-reply and timeout-sweep paths.
    fn advance_pending_get(
        &mut self,
        now: Instant,
        digest: [u8; DIGEST],
        effects: &mut Vec<Effect>,
    ) {
        let Some(pending) = self.pending_gets.get_mut(&digest) else {
            return;
        };
        if let Some(next) = pending.remaining.pop() {
            pending.issued = now;
            effects.push(Effect::Send {
                to: next,
                frame: encode_lookup(&digest),
            });
        } else {
            self.pending_gets.remove(&digest);
            effects.push(Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
            }));
        }
    }

    fn on_ack(body: &[u8]) -> Vec<Effect> {
        match parse_digest(body.get(..DIGEST)) {
            Some(digest) => alloc::vec![Effect::Notify(Notification::Stored(digest))],
            None => Vec::new(),
        }
    }

    /// Flood `frame` to every cell neighbour (the substrate for JOIN and beacon propagation).
    fn flood(&self, frame: &[u8]) -> Vec<Effect> {
        self.peers
            .keys()
            .map(|&peer| Effect::Send {
                to: peer,
                frame: frame.to_vec(),
            })
            .collect()
    }

    /// `Command::Join` — record our own info and flood an announcement so every member learns it.
    fn on_join(&mut self, info: Vec<u8>) -> Vec<Effect> {
        let coord = self.coord.coords();
        let effects = self.flood(&encode(FrameType::Announce, &announce_body(coord, &info)));
        self.members.insert(coord, info);
        effects
    }

    /// A received announcement: on first sight of a member, record it, notify, and re-flood so the
    /// key propagates cell-wide; on a repeat, drop (the monotone guard terminates the flood).
    fn on_announce(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((coord, info)) = parse_announce(body) else {
            return Vec::new();
        };
        // Validate: a member coordinate must be a real, canonical projective point of this plane.
        // Rejecting the zero vector and out-of-range triples both prevents state poisoning and
        // bounds `members` by the plane size `N` — a peer cannot grow it without limit with forged
        // coordinates (spec §7.8 membership).
        let Some(coord) = Point::<F>::new(coord).map(|p| p.coords()) else {
            return Vec::new();
        };
        // First sight only. A repeat must NOT overwrite the stored key bundle — otherwise any peer
        // could silently replace a member's advertised keys in our local view (and suppress the
        // re-flood, diverging the cell). Ignore repeats entirely; the monotone guard ends the flood.
        if self.members.contains_key(&coord) {
            return Vec::new();
        }
        self.members.insert(coord, info.clone());
        let mut effects = self.flood(&encode(FrameType::Announce, &announce_body(coord, &info)));
        effects.push(Effect::Notify(Notification::MemberJoined { coord, info }));
        effects
    }

    /// `Command::AdvanceEpoch` — bump the epoch and flood the beacon so the cell adopts it.
    fn on_advance_epoch(&mut self) -> Vec<Effect> {
        self.epoch = self.epoch.saturating_add(1);
        let mut effects = self.flood(&encode(FrameType::Beacon, &self.epoch.to_be_bytes()));
        effects.push(Effect::Notify(Notification::EpochAdvanced(self.epoch)));
        effects
    }

    /// A received beacon: adopt it iff strictly newer (monotone), then re-flood and notify.
    fn on_beacon(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some(bytes) = body.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
            return Vec::new();
        };
        let epoch = u32::from_be_bytes(bytes);
        if epoch <= self.epoch {
            return Vec::new(); // not newer — drop (terminates the flood)
        }
        self.epoch = epoch;
        let mut effects = self.flood(&encode(FrameType::Beacon, &epoch.to_be_bytes()));
        effects.push(Effect::Notify(Notification::EpochAdvanced(epoch)));
        effects
    }

    /// The current membership view (coordinate → announced info), for onion routing / observation.
    pub fn members(&self) -> impl Iterator<Item = (Triple, &[u8])> + '_ {
        self.members.iter().map(|(&c, i)| (c, i.as_slice()))
    }

    /// The current beacon epoch.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// This node's cell-liveness view (base Fano cell only): `(self_index, degraded_mask,
    /// alive_count)`. Bit `i` of the mask is set when point `i` is not corroborated-alive. `None`
    /// off the base `N = 7` cell, where the index-addressed syndrome geometry does not apply.
    fn cell_liveness(&self, now: Instant) -> Option<(usize, u8, usize)> {
        let self_index = self.self_index?;
        let mut degraded = 0u8;
        let mut alive_count = 1usize; // self is alive
        for i in 0..7usize {
            let point = Point::<F>::at(i);
            if point == self.coord {
                continue;
            }
            if self.coord_alive(point.coords(), now) {
                alive_count += 1;
            } else {
                degraded |= 1 << i;
            }
        }
        Some((self_index, degraded, alive_count))
    }

    /// Fold this window's cell health into a `CoherenceFrame`, record it in local history, and return
    /// the effect that publishes its wire bytes. The exact 3-bit syndrome comes from `degraded`; the
    /// coherence scalars from the equicorrelated liveness model (docs/design-telemetry.md §2).
    fn emit_observation(&mut self, now: Instant, alive_count: usize, degraded: u8) -> Effect {
        let frame = self.observer.observe_liveness(
            now.as_nanos(),
            alive_count,
            self.config.healthy_correlation,
            degraded,
            0.0, // spectral gap Δ: not tracked from liveness alone; 0 = unknown this window
            -1,  // cascade forecast: none from liveness alone
        );
        Effect::Notify(Notification::Observed(frame.encode().to_vec()))
    }

    /// Sense-only self-observation (`Command::Observe`): emit the cell's coherence frame **without**
    /// running the verdict or any healing — the passive monitor read (docs/design-telemetry.md §4).
    fn on_observe(&mut self, now: Instant) -> Vec<Effect> {
        match self.cell_liveness(now) {
            Some((_, degraded, alive_count)) => {
                alloc::vec![self.emit_observation(now, alive_count, degraded)]
            }
            None => Vec::new(),
        }
    }

    fn on_diagnose(&mut self, now: Instant) -> Vec<Effect> {
        // DIAKRISIS runs at cell scale. On the base Fano cell (N=7) a node sees the whole cell
        // through its lines, so it can build the full degraded mask locally (spec §6.3).
        let Some((self_index, degraded, alive_count)) = self.cell_liveness(now) else {
            return Vec::new();
        };
        // The base node senses only liveness, so it feeds the degraded mask; partition and
        // cascade verdicts require the global coherence view (the simulator's observatory / a
        // real deployment's cross-attestation), not this local liveness alone (spec §6.5).
        let verdict = diagnose(&Observation {
            degraded,
            ..Default::default()
        });

        let mut effects = alloc::vec![Effect::Notify(Notification::Verdict(verdict.clone()))];
        if self.config.self_healing {
            // Estimate the cell's integration from its live membership on the equicorrelated
            // stratum: Φ_net = (alive−1)·r² (spec §2.7). This gates the reroute-depth budget.
            let phi = phi_equicorrelated(alive_count, self.config.healthy_correlation);
            let plan = plan_healing(&verdict, self_index, degraded, phi);
            if !plan.is_empty() {
                self.observer.note_healing();
            }
            effects.extend(self.apply_healing_plan(now, &plan));

            // Behavioural homeostasis: run the coherence homeostat on the *measured* Γ_net (the relay-
            // activity self-model), not the liveness proxy. A common-mode flood shows as behavioural
            // over-coupling; the homeostat's band-keeping decision is then to shed correlation. Low
            // behavioural correlation is the healthy diversified regime, so the other decisions
            // (Hold / Bind / Escalate) take no discrete action here — consistent with `diagnose`, whose
            // Systemic arm encodes the same over-coupling rule for the standalone diagnosis surface.
            if let Some(coherence) = self.monitor.coherence() {
                let m = coherence.measures();
                if let BandControl::Decouple { .. } =
                    self.homeostat
                        .control(m.purity, coherence.mean_correlation(), coherence.n())
                {
                    self.observer.note_healing();
                    effects.push(Effect::Notify(Notification::Decoupled));
                }
            }
        }
        // Mandatory self-observation: diagnosis cannot happen without observing.
        effects.push(self.emit_observation(now, alive_count, degraded));
        effects
    }

    /// Apply a [`HealingPlan`], mutating the reroute / repaired / quarantine state and emitting a
    /// notification for each *new* corrective action (idempotent across repeated rounds).
    fn apply_healing_plan(
        &mut self,
        now: Instant,
        plan: &fanos_diakrisis::HealingPlan,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();
        for action in &plan.actions {
            match *action {
                HealingAction::Reroute { around, via } => {
                    let around_c = Point::<F>::at(around).coords();
                    let via_c = Point::<F>::at(via).coords();
                    if self.reroute.insert(around_c, via_c) != Some(via_c) {
                        effects.push(Effect::Notify(Notification::Rerouted {
                            around: around_c,
                            via: via_c,
                        }));
                    }
                }
                HealingAction::Repair { node, .. } => {
                    let node_c = Point::<F>::at(node).coords();
                    if self.repaired.insert(node_c) {
                        effects.push(Effect::Notify(Notification::Repaired(node_c)));
                    }
                }
                HealingAction::Quarantine { node } => {
                    let node_c = Point::<F>::at(node).coords();
                    // Insert (or refresh the window on) the quarantine; notify only on a *new* distrust.
                    if self.quarantined.insert(node_c, now).is_none() {
                        effects.push(Effect::Notify(Notification::Quarantined(node_c)));
                    }
                }
                HealingAction::Decouple => {
                    effects.push(Effect::Notify(Notification::Decoupled));
                }
                HealingAction::Escalate { unrecoverable } => {
                    effects.push(Effect::Notify(Notification::Escalated(unrecoverable)));
                }
            }
        }
        effects
    }

    /// The current self-healing reroute table (down node → co-linear survivor), for observation.
    pub fn reroutes(&self) -> impl Iterator<Item = (Triple, Triple)> + '_ {
        self.reroute.iter().map(|(&k, &v)| (k, v))
    }
}

impl<F: Field> Engine for OverlayNode<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Command(Command::StartHeartbeat) => {
                self.started_at = now;
                self.heartbeating = true;
                alloc::vec![Effect::ArmTimer {
                    token: HEARTBEAT,
                    after: self.config.heartbeat,
                }]
            }
            Input::Command(Command::Send { to, payload }) => self.on_send(to, &payload),
            Input::Command(Command::Diagnose) => self.on_diagnose(now),
            Input::Command(Command::Observe) => self.on_observe(now),
            Input::Command(Command::Put { key, value }) => self.on_put(&key, value),
            Input::Command(Command::Get { key }) => self.on_get(now, &key),
            Input::Command(Command::Join { info }) => self.on_join(info),
            Input::Command(Command::AdvanceEpoch) => self.on_advance_epoch(),
            Input::Timer(HEARTBEAT) if self.heartbeating => self.on_heartbeat(now),
            Input::Timer(_) => Vec::new(),
            Input::Message { from, frame } => self.on_message(now, from, &frame),
        }
    }

    fn address(&self) -> Triple {
        self.coord.coords()
    }
}

/// Build a wire frame with the given type and body.
fn encode(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(ty.code(), body, &mut out);
    out
}

/// A `Publish` frame: `flag(1) ‖ key(32) ‖ value` (spec §L4).
fn encode_publish(flag: u8, digest: &[u8; DIGEST], value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + DIGEST + value.len());
    body.push(flag);
    body.extend_from_slice(digest);
    body.extend_from_slice(value);
    encode(FrameType::Publish, &body)
}

/// A `Lookup` frame: the bare 32-byte key digest (spec §L4).
fn encode_lookup(digest: &[u8; DIGEST]) -> Vec<u8> {
    encode(FrameType::Lookup, digest)
}

/// A `Value` reply: `key(32) ‖ found(1) ‖ value` (spec §L4).
fn encode_value(digest: &[u8; DIGEST], found: bool, value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(DIGEST + 1 + value.len());
    body.extend_from_slice(digest);
    body.push(u8::from(found));
    body.extend_from_slice(value);
    encode(FrameType::Value, &body)
}

/// Parse a 32-byte key digest from an optional slice.
fn parse_digest(slice: Option<&[u8]>) -> Option<[u8; DIGEST]> {
    <[u8; DIGEST]>::try_from(slice?).ok()
}

/// An `Announce` body: `coord(12) ‖ info` (spec §7.8 JOIN).
fn announce_body(coord: Triple, info: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(12 + info.len());
    for word in coord {
        body.extend_from_slice(&word.to_be_bytes());
    }
    body.extend_from_slice(info);
    body
}

/// Parse an `Announce` body into `(coord, info)`.
fn parse_announce(body: &[u8]) -> Option<(Triple, Vec<u8>)> {
    let x = u32::from_be_bytes(body.get(0..4)?.try_into().ok()?);
    let y = u32::from_be_bytes(body.get(4..8)?.try_into().ok()?);
    let z = u32::from_be_bytes(body.get(8..12)?.try_into().ok()?);
    Some(([x, y, z], body.get(12..)?.to_vec()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F2, F7};

    #[test]
    fn node_derives_all_cell_neighbours_algebraically() {
        // On the Fano cell a node sees all 6 others; on q=7 it sees all 56 others.
        let node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        assert_eq!(node.neighbours().count(), 6);
        let big = OverlayNode::<F7>::new(Point::at(0), Config::default());
        assert_eq!(big.neighbours().count(), 56);
    }

    #[test]
    fn heartbeat_pings_and_gossips_every_neighbour_and_rearms() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let start = node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        assert!(matches!(start.as_slice(), [Effect::ArmTimer { .. }]));
        let effects = node.step(Instant(500_000_000), Input::Timer(HEARTBEAT));
        let mut pings = 0;
        let mut gossips = 0;
        for e in &effects {
            if let Effect::Send { frame, .. } = e {
                match decode_frame(frame).unwrap().0.frame_type() {
                    Some(FrameType::Ping) => pings += 1,
                    Some(FrameType::DiagGossip) => gossips += 1,
                    other => panic!("unexpected heartbeat frame {other:?}"),
                }
            }
        }
        let arms = effects
            .iter()
            .filter(|e| matches!(e, Effect::ArmTimer { .. }))
            .count();
        assert_eq!(pings, 6, "pings all 6 neighbours");
        assert_eq!(gossips, 6, "gossips its health-view to all 6 neighbours");
        assert_eq!(arms, 1, "re-arms the heartbeat");
    }

    #[test]
    fn behavioural_over_coupling_drives_the_homeostat_to_decouple() {
        // The live homeostat runs on the MEASURED Γ_net (relay activity), not the liveness proxy. Feed a
        // common-mode flood: every peer relays the same lockstep-varying amount each window, so node 0's
        // observed per-peer slots move together — perfectly correlated (mean r ≈ 0.71 > 1/√3), i.e. the
        // over-coupled/groupthink regime. The homeostat's band-keeping response is to shed correlation.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));

        let mut t = 1u64;
        for w in 0..(BEHAVIOR_WINDOW + 2) {
            let bursts = (w % 3) + 1; // varying, but identical across all peers → correlated in lockstep
            for i in 1..7usize {
                let from = Point::<F2>::at(i).coords();
                for _ in 0..bursts {
                    node.step(
                        Instant(t),
                        Input::Message {
                            from,
                            frame: encode(FrameType::Route, b"x"),
                        },
                    );
                    t += 1;
                }
            }
            // Fire the heartbeat: it takes this window's behavioural sample into the coherence monitor.
            node.step(Instant(t), Input::Timer(HEARTBEAT));
            t += 1;
        }

        // Diagnose: the homeostat sees over-coupling in the measured Γ_net and sheds correlation.
        let effects = node.step(Instant(t), Input::Command(Command::Diagnose));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Decoupled))),
            "behavioural over-coupling drives the live homeostat to Decouple"
        );
    }

    #[test]
    fn a_quiet_cell_does_not_spuriously_decouple() {
        // With no relay traffic the behavioural signal is degenerate; the homeostat must NOT fire a
        // spurious Decouple (only genuine over-coupling acts — low/absent correlation is the healthy
        // diversified regime). Run many heartbeats with zero Route activity, then diagnose.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let mut t = 1u64;
        for _ in 0..(BEHAVIOR_WINDOW + 4) {
            node.step(Instant(t), Input::Timer(HEARTBEAT));
            t += 1;
        }
        let effects = node.step(Instant(t), Input::Command(Command::Diagnose));
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Decoupled))),
            "a quiet cell does not spuriously shed correlation"
        );
    }

    #[test]
    fn quarantine_is_bounded_and_re_admits_a_member_after_the_ttl() {
        // A distrusted member is not exiled forever: within the window its frames are dropped, but once the
        // quarantine TTL elapses it is re-admitted for re-evaluation (a transient fault is not permanent).
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let member = Point::<F2>::at(1).coords();
        node.quarantined.insert(member, Instant(0)); // as a Structural verdict would, at t=0

        // Within the window: frames are dropped and it stays quarantined.
        let within = node.step(
            Instant(1_000),
            Input::Message {
                from: member,
                frame: encode(FrameType::Route, b"x"),
            },
        );
        assert!(within.is_empty(), "a quarantined member's frames are dropped within the window");
        assert!(node.quarantined.contains_key(&member), "still quarantined within the window");

        // Past the TTL (70 s > 60 s): re-admitted, and its frames are processed again.
        let after = node.step(
            Instant(70_000_000_000),
            Input::Message {
                from: member,
                frame: encode(FrameType::Route, b"x"),
            },
        );
        assert!(!node.quarantined.contains_key(&member), "re-admitted once the window elapses");
        assert!(
            after
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Delivered { .. }))),
            "the re-admitted member's frames are processed again"
        );
    }

    #[test]
    fn ping_is_answered_with_pong() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let from = Point::<F2>::at(1).coords();
        let ping = encode(FrameType::Ping, &[]);
        let effects = node.step(Instant(1), Input::Message { from, frame: ping });
        match effects.as_slice() {
            [Effect::Send { to, frame }] => {
                assert_eq!(*to, from);
                let (f, _) = decode_frame(frame).unwrap();
                assert_eq!(f.frame_type(), Some(FrameType::Pong));
            }
            other => panic!("expected a single PONG, got {other:?}"),
        }
    }

    #[test]
    fn rendezvous_send_reports_the_line_and_delivers() {
        let mut node = OverlayNode::<F7>::new(Point::at(0), Config::default());
        let to = Point::<F7>::at(20).coords();
        let effects = node.step(
            Instant(1),
            Input::Command(Command::Send {
                to,
                payload: b"hi".to_vec(),
            }),
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::RendezvousLine(_))))
        );
        assert!(effects.iter().any(|e| matches!(e, Effect::Send { .. })));
    }

    #[test]
    fn announce_validates_coords_and_never_overwrites_a_member() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let peer = Point::<F2>::at(3).coords();
        let from = Point::<F2>::at(1).coords();
        let info_of = |c: Triple, n: &OverlayNode<F2>| {
            n.members().find(|(m, _)| *m == c).map(|(_, i)| i.to_vec())
        };

        // Honest first announce → recorded and MemberJoined notified.
        let honest = encode(FrameType::Announce, &announce_body(peer, b"HONEST"));
        let e1 = node.step(
            Instant(1),
            Input::Message {
                from,
                frame: honest,
            },
        );
        assert!(
            e1.iter()
                .any(|e| matches!(e, Effect::Notify(Notification::MemberJoined { .. })))
        );
        assert_eq!(info_of(peer, &node), Some(b"HONEST".to_vec()));

        // A repeat for the same coord with attacker keys must NOT overwrite or re-notify.
        let forged = encode(FrameType::Announce, &announce_body(peer, b"ATTACKER"));
        let e2 = node.step(
            Instant(2),
            Input::Message {
                from,
                frame: forged,
            },
        );
        assert!(
            !e2.iter()
                .any(|e| matches!(e, Effect::Notify(Notification::MemberJoined { .. })))
        );
        assert_eq!(
            info_of(peer, &node),
            Some(b"HONEST".to_vec()),
            "a repeat announce cannot silently replace a member's keys"
        );

        // The zero vector is not a projective point → rejected, never stored.
        let count_before = node.members().count();
        let zero = encode(FrameType::Announce, &announce_body([0, 0, 0], b"ZERO"));
        node.step(Instant(3), Input::Message { from, frame: zero });
        assert_eq!(
            node.members().count(),
            count_before,
            "an invalid coordinate is not accepted as a member"
        );
    }
}
