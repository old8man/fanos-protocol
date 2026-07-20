//! `OverlayNode` — the base FANOS node engine (spec L1/L3 + DIAKRISIS), sans-I/O.
//!
//! This is production node logic: it maintains liveness of its cell neighbours via periodic
//! heartbeats, resolves rendezvous by the algebraic line `u × v`, delivers application
//! payloads, and (on the base Fano cell) runs one DIAKRISIS round to localize a fault. It
//! reacts only to [`Input`]s and emits only [`Effect`]s — no clock, socket, or RNG — so the
//! same code runs under the simulator and a real transport.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use fanos_core::AdmissionPolicy;
use fanos_diakrisis::coherence::phi_equicorrelated;
use fanos_diakrisis::monitor::BehaviorMonitor;
use fanos_diakrisis::polar;
use fanos_diakrisis::regeneration::spectral_gap;
use fanos_diakrisis::{BandControl, HealingAction, Homeostat, Observation, diagnose, plan_healing};
use fanos_field::Field;
use fanos_geometry::{HierAddr, Plane, Point, Triple, fano, next_hop};
use fanos_primitives::{Epoch, hash_labeled, storage_digest, storage_point};
use fanos_telemetry::{CellId, HistoryConfig, SelfObserver};
use fanos_wire::{FrameType, ProtocolError, Wire, decode_frame, encode_frame};

/// Storage `Publish` sub-type: the responsible node fans out replicas; a replica just stores.
const PUBLISH_ORIGIN: u8 = 0;
/// Storage `Publish` sub-type: a replica copy — store it, do not re-fan-out.
const PUBLISH_REPLICA: u8 = 1;
/// The DHT key-digest / storage-address length (BLAKE3-256) — the one canonical digest width.
const DIGEST: usize = fanos_primitives::DIGEST_LEN;

use crate::ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

/// The single heartbeat timer token.
const HEARTBEAT: TimerToken = TimerToken(0);

/// The behavioural-coherence observation window, in heartbeat samples: the cell's `Γ_net` is read from the
/// last this-many per-node relay-activity samples. Bounded, so the self-model memory is `7 × this`.
const BEHAVIOR_WINDOW: usize = 8;

/// Homeostatic **decoupling** control (audit C6). `Decouple` must actually lower the cell's integration,
/// not merely notify: the node carries a mutable shed factor in `[0, DECOUPLE_MAX]` that scales its
/// effective correlation down, and that reduced correlation feeds `phi_equicorrelated` — so each
/// over-coupled round genuinely restores headroom, and the reflexive loop lowers `Φ` (spec §2.7/§6.5).
/// Over-coupling raises the factor by `DECOUPLE_STEP` per round (capped); once back in band it decays by
/// `DECOUPLE_DECAY` toward zero (re-integration).
const DECOUPLE_STEP: f64 = 0.25;
const DECOUPLE_MAX: f64 = 0.6;
const DECOUPLE_DECAY: f64 = 0.5;
/// Hysteresis dwell for the over-coupling shed (audit #122). The measured `Γ_net` must read over-coupled
/// for this many *consecutive* self-driven diagnoses before `Decouple` actuates. Diagnosis now runs every
/// heartbeat (not a one-shot injected command), so a single transient over-threshold reading — e.g. a
/// coincidental correlation inside an otherwise decorrelated burst flood — must not trigger a shed: the
/// DDoS response acts on *sustained* over-coupling (structure), never momentary load. Crash/Byzantine
/// healing is unaffected — this gates only the `Decouple` action.
const DECOUPLE_DWELL: u32 = 3;

/// DoS backstops on the DHT slice (audit A4). The distributed store and the in-flight-read table both
/// accept adversary-supplied keys, so without a cap a peer that floods `Publish`/`Get` with distinct
/// digests exhausts memory. These are *safety* ceilings far above any legitimate working set — a
/// reference node holding real application data never approaches them — chosen to bound worst-case
/// memory (`MAX_STORE_ENTRIES × MAX_VALUE_LEN` ≈ 256 MiB, `MAX_PENDING_GETS × PendingGet` ≈ a few MiB),
/// not to constrain honest use. When full, a *new* key is refused rather than an existing one evicted,
/// so an attacker cannot displace already-stored replicas (LRC availability is preserved); overwriting
/// an existing key is always allowed (it does not grow the map).
const MAX_STORE_ENTRIES: usize = 4096;
/// The largest value the store will hold, in bytes — bounds per-entry memory and rejects amplification.
const MAX_VALUE_LEN: usize = 65_536;
/// The most concurrent in-flight `Get`s tracked at once; further reads are refused until some resolve.
const MAX_PENDING_GETS: usize = 1024;

/// How long a locally-distrusted (Byzantine) member stays quarantined before it is re-admitted for
/// re-evaluation. Quarantine is an *operational* safeguard, not a proven permanent exclusion (spec §6.2):
/// permanently exiling a member would strand one that only glitched transiently. After this window the
/// member is re-admitted; if it is still structurally inconsistent the next diagnosis re-quarantines it
/// (the polar sum-rules re-catch it), and the authoritative clear remains the parent's re-provisioning
/// (escalation). Bounded, so `quarantined` cannot grow without limit either (audit C5).
const QUARANTINE_TTL: Duration = Duration::from_millis(60_000);

/// Configuration of a node's liveness behaviour.
// The several `bool`s here are independent, orthogonal deployment toggles (self-healing on/off, and the
// three opt-in membership guards), not a state machine — an enum would not model them (any combination is
// valid). This is exactly the config-flag case `struct_excessive_bools` over-fires on.
#[allow(clippy::struct_excessive_bools)]
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
    /// Whether to require **self-certified** membership: seed a peer's hierarchical address into the
    /// routing table only if it matches the descent chain of the identity carried in its announcement
    /// ([`fanos_primitives::address_matches_identity`]). Off by default (a peer's announced address is
    /// trusted, as the `members` view always is); on for a deployment that wants routing-table
    /// poisoning resistance — a peer then cannot announce an overlay address it did not earn, so
    /// attracting a target's `RouteHier` traffic costs `≈ N^k` identity grinding (threat §79/B1).
    pub require_self_certified_membership: bool,
    /// Whether to require **Sybil admission** (spec §L3): an announcing peer's proof must
    /// satisfy this node's admission policy (a builder-installed
    /// `Box<dyn `[`AdmissionPolicy`]`>`, e.g. [`fanos_core::PowAdmission`]) or the announcement
    /// is rejected — not admitted to `members`, and told why (`SYBIL_REJECT`, spec §7.5) —
    /// rather than merely trusted as today. Off by default, matching every other opt-in
    /// membership guard here (`require_self_certified_membership`); the structural centrality
    /// cap (spec §L3, V3) always applies regardless, since it needs no configuration to hold.
    /// On for a deployment that wants the missing per-admission cost the `sybil_cost.rs`
    /// threat-model derivation shows the geometry alone does not provide. **Fails closed**:
    /// turning this on with no policy installed rejects every peer, never silently admits.
    pub require_admission: bool,
    /// Whether this deployment seats **level-0 coordinates by the VRF beacon** (`MapToPoint(VRF(id, epoch,
    /// beacon))`, spec §L0/A7) rather than the hash `address_point(id, 0)` (§79). It only affects the
    /// [`require_self_certified_membership`](Self::require_self_certified_membership) check: with VRF
    /// coordinates the announced level-0 point is *not* the identity's hash-derived point, so the hash-chain
    /// check must skip level 0 (its authenticity comes from the proof-of-coordinate HELLO + the descriptor
    /// signature) — else every legitimate VRF announcement is rejected (audit C3). The sub-cell descent
    /// (levels `>= 1`) is hash-derived in both schemes and stays checked. Off by default (the §79 hash-chain
    /// scheme, full-chain check); a VRF deployment (the `A7` node model) sets it alongside its beacon.
    pub vrf_coordinates: bool,
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
            require_self_certified_membership: false,
            require_admission: false,
            vrf_coordinates: false,
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
    /// The per-request nonce this read is correlated on: a `Value` reply resolves it only if the reply
    /// echoes this exact nonce, so a stale/replayed reply from a prior get for the same key cannot drain
    /// it with an old value (audit C4).
    nonce: u64,
}

/// The DHT-storage concern factored out of [`OverlayNode`] (audit #125 decompose): this node's local
/// slice of the cell's distributed store plus its in-flight read-repair bookkeeping. The *orchestration*
/// of a Put/Get — resolving the responsible cell member, replicating across the cell — stays on
/// `OverlayNode`, which owns the membership view; this owns the local state and the read-repair walk.
#[derive(Default)]
struct Store {
    /// Key digest → value. A value lives on its responsible content point and is replicated across the
    /// cell for LRC availability, so any survivor answers a lookup (spec §L4).
    entries: BTreeMap<[u8; DIGEST], Vec<u8>>,
    /// In-flight `Get`s awaiting a `Value`, keyed by digest — the read-repair walk down the replica line.
    pending: BTreeMap<[u8; DIGEST], PendingGet>,
    /// Monotone per-request nonce source, so a stale/replayed `Value` cannot resolve a newer read (C4).
    seq: u64,
}

impl Store {
    /// Whether the local slice admits `(digest, value_len)` under the A4 DoS caps: within
    /// [`MAX_VALUE_LEN`], and either the key already exists (an overwrite — no growth) or the store is
    /// below [`MAX_STORE_ENTRIES`] — so a `Publish` flood cannot displace already-stored replicas, while
    /// updates to existing keys always pass.
    fn admits(&self, digest: &[u8; DIGEST], value_len: usize) -> bool {
        value_len <= MAX_VALUE_LEN
            && (self.entries.len() < MAX_STORE_ENTRIES || self.entries.contains_key(digest))
    }

    /// Advance an in-flight read to the next replica on its line, or conclude `Retrieved(None)` once the
    /// replicas are exhausted (spec §L4 read repair). The next replica comes from the read's own
    /// `remaining` list, so this needs no membership view.
    fn advance_pending_get(&mut self, now: Instant, digest: [u8; DIGEST], effects: &mut Vec<Effect>) {
        let Some(pending) = self.pending.get_mut(&digest) else {
            return;
        };
        if let Some(next) = pending.remaining.pop() {
            pending.issued = now;
            let nonce = pending.nonce;
            effects.push(Effect::Send {
                to: next,
                frame: encode_lookup(&digest, nonce),
            });
        } else {
            self.pending.remove(&digest);
            effects.push(Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
            }));
        }
    }
}

/// What we know about a cell neighbour.
#[derive(Clone, Copy, Debug)]
struct Peer {
    last_seen: Option<Instant>,
    reported_down: bool,
}

/// The forwarding decision for a `RouteHier` frame at a node (see [`Router::route`]).
enum HierRoute {
    /// This node is in the destination cell — deliver the payload locally.
    Deliver,
    /// Forward to this transport coordinate, one hop closer to the destination.
    Forward(Triple),
    /// Not the destination and no known peer is closer — drop (a routing hole).
    Drop,
}

/// The hierarchical-routing concern factored out of [`OverlayNode`] (audit #125 decompose): this node's
/// own overlay address plus its learned longest-prefix routing table, and the pure `RouteHier` forwarding
/// decision over them. Transport — the physical `coord` — stays on the facade: a flat transport underlays
/// this structured overlay and the two need not coincide past depth 1. This owns the addressing state and
/// the routing decision; the facade orchestrates the frame flow (an `Announce` carries the address out,
/// `on_announce` seeds a learned peer from one received).
struct Router<F: Field> {
    /// This node's hierarchical address (§L1). Defaults to the depth-1 `root(coord)` — the ordinary
    /// single-plane case — and is deepened only when the node descends into a sub-cell on a collision
    /// (§L0). It governs hierarchical (`RouteHier`) forwarding; single-plane routing is unchanged.
    address: HierAddr<F>,
    /// Learned hierarchical routing table: **transport coordinate → the overlay [`HierAddr`] reachable
    /// there**. Empty on a single-plane node (transport ≡ overlay); populated as the node learns sub-cell
    /// gateways and siblings (a deployment seed, or a JOIN/Announce). `RouteHier` forwarding is greedy
    /// longest-prefix over the addresses ([`next_hop`]), then resolved back to the transport coordinate to
    /// send on — this is what lets a node route *through* cells it is not a member of, and it decouples the
    /// node's transport coordinate (`coord`) from its overlay address (`address`), as a flat transport
    /// underlays a structured overlay. **Keyed by transport coordinate** (one overlay address per physical
    /// endpoint), so — exactly like [`OverlayNode::members`] — it is bounded by the plane size `N`: a peer
    /// cannot grow it without limit by announcing many forged addresses (audit C1/C2 DoS class). Like
    /// `members` it is an attacker-*writable* discovered view; safety does not rest on its integrity —
    /// delivery is decided by this node's own cert-bound `address`, so a poisoned entry can only misroute
    /// or blackhole (a bounded DoS), never impersonate a destination. Cert-verifying an announced address
    /// against its coordinate (poisoning resistance) is the QUIC-layer follow-up.
    peers: BTreeMap<Triple, HierAddr<F>>,
}

impl<F: Field> Router<F> {
    /// Seat this node at its default depth-1 overlay address `root(coord)`, with an empty routing table.
    /// A deployment that descends into a sub-cell or assigns overlay position independently of transport
    /// re-seats the address afterwards ([`OverlayNode::with_hier_address`]).
    fn new(coord: Point<F>) -> Self {
        Self {
            address: HierAddr::root(coord),
            peers: BTreeMap::new(),
        }
    }

    /// Register a hierarchical peer reachable in one hop — the transport coordinate that reaches it and the
    /// overlay [`HierAddr`] it serves — replacing any existing address for that coordinate. This *is* the
    /// hierarchical routing table: `RouteHier` frames are forwarded greedily over it. A single-plane node
    /// needs none (transport ≡ overlay); a deployment or the membership layer seeds it for depth > 1.
    fn learn_peer(&mut self, addr: HierAddr<F>, transport: Triple) {
        self.peers.insert(transport, addr);
    }

    /// Resolve the forwarding decision for hierarchical destination `dst` (§L1). If this node is already
    /// in `dst`'s cell it delivers. Otherwise, with **learned peers**, it routes greedily by longest
    /// shared prefix ([`next_hop`]) and resolves the chosen overlay address to its transport coordinate —
    /// the physical hop one level closer, so forwarding converges in `≤ dst.depth − commonPrefix` hops. A
    /// node with **no learned peers** (the bootstrap origin, or a single populated plane) targets `dst`'s
    /// own point at the divergence level directly. No closer peer and not the destination ⇒ drop (hole).
    fn route(&self, dst: &HierAddr<F>) -> HierRoute {
        if self.address.common_prefix(dst) == dst.depth() {
            return HierRoute::Deliver;
        }
        if !self.peers.is_empty() {
            let reachable: Vec<HierAddr<F>> = self.peers.values().cloned().collect();
            return match next_hop(&self.address, dst, &reachable) {
                Some(next) => self
                    .peers
                    .iter()
                    .find(|(_, a)| **a == next)
                    .map_or(HierRoute::Drop, |(t, _)| HierRoute::Forward(*t)),
                None => HierRoute::Drop,
            };
        }
        dst.point_at(self.address.common_prefix(dst))
            .map_or(HierRoute::Drop, |p| HierRoute::Forward(p.coords()))
    }
}

/// The membership concern factored out of [`OverlayNode`] (audit #125 decompose): this node's own
/// long-term **credentials** for joining a cell — its identity bundle, signed descriptor, and Sybil
/// admission proof — plus the [`AdmissionPolicy`] it checks *others* against, and the learned **key view**
/// of who else is in the cell. The facade orchestrates the JOIN/Announce frame flow (flood, self-cert,
/// re-flood); this owns the credential/view state and the invariant that must not be got wrong — the
/// fail-closed admission check ([`admits`](Membership::admits)).
#[derive(Default)]
struct Membership {
    /// This node's long-term identity bytes (spec §L0): its hybrid **signature public-key bundle**
    /// `Ed25519(32) ‖ ML-DSA-65(1952)`, which both derives its self-certifying address (`MapToPoint`) and
    /// verifies its descriptor signature. Carried in this node's `Announce`. Empty when self-certification
    /// is not in use (the address is trusted without proof).
    identity: Vec<u8>,
    /// The signature over this node's descriptor `coord ‖ hier ‖ id`, produced once by its hybrid signing
    /// key at deployment (the secret never enters the engine). Carried in the `Announce` and checked by
    /// peers under self-certified membership, so an attacker cannot announce a *different* transport
    /// coordinate for an identity's address without that identity's private key (§79/§80, the
    /// transport-hijack defence). Empty when unsigned.
    descriptor_sig: Vec<u8>,
    /// This node's own Sybil-admission proof (spec §L3), attached to its `Announce` when it joins. Empty
    /// when admission is not in use for this deployment — a peer that requires admission then rejects it
    /// (fail closed), exactly as an empty `identity`/`descriptor_sig` is rejected under
    /// `require_self_certified_membership`.
    admission_proof: Vec<u8>,
    /// This node's Sybil admission policy (spec §L3): checked against a peer's announced proof when
    /// `config.require_admission` is set. `None` even with the flag set means this node enforces the check
    /// but has no policy to check *against* — it then rejects every peer (fail closed, never fail open)
    /// rather than silently admitting for want of configuration.
    admission_policy: Option<Box<dyn AdmissionPolicy>>,
    /// The membership view: cell coordinate → announced info (public keys, capabilities), learned by
    /// flooding JOIN announcements (spec §7.8). This is the key distribution onion routing reads.
    members: BTreeMap<Triple, Vec<u8>>,
}

impl Membership {
    /// Whether an announced `proof` admits a joiner under this node's installed policy (spec §L3, §7.8).
    /// **Fails closed**: with no policy installed this returns `false`, so a node that *requires* admission
    /// but was handed no policy rejects every peer rather than silently admitting for want of
    /// configuration. The caller gates this on `config.require_admission`.
    fn admits(&self, challenge: &[u8], proof: &[u8]) -> bool {
        self.admission_policy
            .as_deref()
            .is_some_and(|policy| policy.admits(challenge, proof))
    }
}

/// The DIAKRISIS self-healing reflex factored out of [`OverlayNode`] (audit #125 decompose): the node's
/// **verified reflex layer** (see [[synarc-node-architecture]]) — behavioural coherence self-model, the
/// over-coupling homeostat, and the crash/Byzantine healing state (reroute / repair / quarantine) with the
/// live polar cross-attestation it diagnoses from. The facade owns the *liveness sensing* (the `peers`
/// substrate + `coord_alive`/`cell_liveness`/`health_view` + the `witnessed` corroboration cache) and
/// hands this a **sensed** cell snapshot (`self_index, degraded, alive_count`); this owns everything the
/// reflex then does with it. Not generic over `F`: its state is all concrete, and the few methods that
/// need the cell's index-addressed geometry take `<F>` per call.
struct Healer {
    /// Live polar cross-attestation (spec §6.4, §6.2): the freshest `DiagAttest` report gossiped by each
    /// OTHER cell member — its own honest reading of the 3 channel rates it mediates (`polar::polar_class`),
    /// and when it arrived. [`attested_pairwise_rates`](Healer::attested_pairwise_rates) assembles these
    /// (falling back to this node's own reading for any member it hasn't freshly heard from) into the
    /// `Observation.pairwise_rates` matrix `diagnose` feeds the 14 free polar sum-rule alarms. An honest
    /// report's 3 values always agree (`polar::mediator_attestation`); an equivocating member's disagree
    /// internally, and `polar::violated_classes` then localizes exactly it.
    attested: BTreeMap<Triple, ([f64; 3], Instant)>,
    /// Self-healing routing state: to reach the (down) key coordinate, contact the value coordinate — the
    /// co-linear survivor from the projective LRC reroute (spec §L4).
    reroute: BTreeMap<Triple, Triple>,
    /// Nodes whose shard this cell has regenerated by peeling (spec §6.3), for observability.
    repaired: BTreeSet<Triple>,
    /// Members locally distrusted after a polar-rule violation (spec §6.2); their frames are dropped
    /// pending parental re-provisioning.
    quarantined: BTreeMap<Triple, Instant>,
    /// Mandatory per-node self-observation (`fanos_telemetry`): every diagnosis folds the cell's health
    /// into a `CoherenceFrame` and records it into bounded local history. Not optional — the reflexive loop
    /// cannot diagnose without observing (docs/design-telemetry.md).
    observer: SelfObserver,
    /// The behavioural coherence monitor: a bounded window of per-node relay activity, read as the cell's
    /// real `Γ_net` so the [`Homeostat`] runs on *measured* correlation, not the liveness proxy (base cell).
    monitor: BehaviorMonitor,
    /// The coherence homeostat this node runs on its behavioural self-model — the sense→act seam, with the
    /// monitor sensing and `diagnose` actuating its band-keeping decision.
    homeostat: Homeostat,
    /// Per-peer **data-relay** activity (`Route` frames) accumulated since the last behavioural sample —
    /// the raw counts the coherence self-model is built from. Control chatter (pings, gossip) is excluded,
    /// so this reflects *load*, not liveness.
    activity: BTreeMap<Triple, u32>,
    /// This node's own relay activity (`Route` frames it originated) since the last sample — the self slot
    /// of the behavioural sample vector.
    self_activity: u32,
    /// The mutable **decoupling** shed factor `∈ [0, DECOUPLE_MAX]` (audit C6): scales this node's effective
    /// correlation down so a `Decouple` actually lowers `Φ`. `decoupled`/`escalated_coherence` dedup the
    /// homeostat notifications (which previously re-fired every diagnose).
    decoupling: f64,
    /// Dedup: currently in the shed (decoupled) regime — so `Decoupled` fires once on entry, not each round.
    decoupled: bool,
    /// Dedup: currently escalated on a coherence collapse — so `Escalated` fires once on entry.
    escalated_coherence: bool,
    /// Consecutive self-driven diagnoses that read over-coupled (`Verdict::Systemic`); resets to 0 on any
    /// non-over-coupled diagnosis. The `Decouple` shed only actuates once this reaches [`DECOUPLE_DWELL`] —
    /// the hysteresis that keeps the now-continuous reflex from shedding on a transient reading (#122).
    overcoupling_streak: u32,
}

impl Healer {
    /// Create the reflex with the given self-observer (built by the facade, which knows the cell id and
    /// window). Monitor/homeostat take their base-cell defaults; all healing state starts empty.
    fn new(observer: SelfObserver) -> Self {
        Self {
            attested: BTreeMap::new(),
            reroute: BTreeMap::new(),
            repaired: BTreeSet::new(),
            quarantined: BTreeMap::new(),
            observer,
            monitor: BehaviorMonitor::new(7, BEHAVIOR_WINDOW),
            homeostat: Homeostat::conservative(),
            activity: BTreeMap::new(),
            self_activity: 0,
            decoupling: 0.0,
            decoupled: false,
            escalated_coherence: false,
            overcoupling_streak: 0,
        }
    }

    /// Count a data-relay (`Route`) frame from `from` toward its behavioural activity — the load signal
    /// folded into the coherence self-model on the next heartbeat sample. Control chatter is excluded.
    fn record_relay(&mut self, from: Triple) {
        let a = self.activity.entry(from).or_insert(0);
        *a = a.saturating_add(1);
    }

    /// Count a relay this node *originated* toward its own activity (the self slot of the sample vector).
    fn record_origination(&mut self) {
        self.self_activity = self.self_activity.saturating_add(1);
    }

    /// The transport coordinate to actually send to when addressing `to`: the self-healing co-linear
    /// survivor if `to` is being rerouted around (spec §L4), else `to` itself.
    fn reroute_target(&self, to: Triple) -> Triple {
        self.reroute.get(&to).copied().unwrap_or(to)
    }

    /// A recovered node (churn rejoin, spec §3.3) no longer needs rerouting or repair — clear both.
    fn clear_healing(&mut self, coord: Triple) {
        self.reroute.remove(&coord);
        self.repaired.remove(&coord);
    }

    /// Whether `from`'s frames must be dropped this instant because it is locally quarantined (spec §6.2,
    /// §6.4) — true only within the bounded [`QUARANTINE_TTL`] window; once that elapses the member is
    /// re-admitted here (removed) for re-evaluation, so a transient fault is not a permanent exile (C5).
    fn is_quarantined(&mut self, from: Triple, now: Instant) -> bool {
        if let Some(&since) = self.quarantined.get(&from) {
            if now.since(since) <= QUARANTINE_TTL {
                return true;
            }
            self.quarantined.remove(&from); // window elapsed — re-admit; re-diagnosis re-quarantines if bad
        }
        false
    }

    /// The current self-healing reroute table (down node → co-linear survivor), for observation.
    fn reroutes(&self) -> impl Iterator<Item = (Triple, Triple)> + '_ {
        self.reroute.iter().map(|(&k, &v)| (k, v))
    }

    /// Fold witness `from`'s polar cross-attestation into the `attested` store (spec §6.4): its 3 reported
    /// channel rates (for the pairs it mediates, `polar::polar_class`) and when they arrived. A
    /// short/malformed body is dropped whole, not partially applied (matching the canonical-decode-failure
    /// convention elsewhere, spec §7.5). Freshness is enforced at *read* time by
    /// [`attested_pairwise_rates`](Healer::attested_pairwise_rates), not here.
    fn apply_diag_attest(&mut self, now: Instant, from: Triple, body: &[u8]) {
        let mut rates = [0.0f64; 3];
        for (i, slot) in rates.iter_mut().enumerate() {
            let Some(bytes) = body
                .get(i * 8..i * 8 + 8)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
            else {
                return; // short/malformed body — drop, do not partially apply
            };
            *slot = f64::from_le_bytes(bytes);
        }
        self.attested.insert(from, (rates, now));
    }

    /// Fold this window's per-node relay activity into the behavioural coherence [`monitor`](Self::monitor),
    /// then reset the accumulators. Base Fano cell only (`self_index` is `Some`), where the 7-point index
    /// geometry applies; the sample's `i`-th slot is point `i`'s relay activity (this node's own for its
    /// index, else the peer's).
    fn sample_behavior<F: Field>(&mut self, self_index: Option<usize>) {
        let Some(self_index) = self_index else {
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

    /// This node's **effective** equicorrelated correlation: the `healthy` baseline scaled down by the
    /// current `decoupling` shed factor (audit C6). Everything that computes `Φ`/`P` from a scalar
    /// correlation reads this, so a `Decouple` genuinely lowers the cell's integration.
    fn effective_correlation(&self, healthy: f64) -> f64 {
        healthy * (1.0 - self.decoupling)
    }

    /// Assemble the live `7×7` polar cross-attestation matrix (spec §6.4) for `diagnose`'s structural
    /// check: for each polar point `k`, the 3 rates in its class default to this node's own honest reading
    /// of `degraded` (`polar::mediator_attestation` — always internally consistent, for ANY liveness
    /// pattern), then are overridden by `k`'s own freshly-gossiped `DiagAttest`, if any (fresh within
    /// `timeout`) — the mediator is the authoritative witness of the channels it mediates. An honest
    /// override reproduces the same self-consistent triple; an equivocating one's disagrees internally by
    /// construction — and `polar::violated_classes` then localizes exactly that mediator, since each class
    /// here is filled atomically from ONE source (fallback or attestation), never a mix.
    fn attested_pairwise_rates<F: Field>(
        &self,
        now: Instant,
        degraded: u8,
        timeout: Duration,
    ) -> [[f64; 7]; 7] {
        let mut matrix = [[0.0f64; 7]; 7];
        for k in 0..7usize {
            let coord = Point::<F>::at(k).coords();
            let triple = match self.attested.get(&coord) {
                Some((rates, seen)) if now.since(*seen) <= timeout => *rates,
                _ => polar::mediator_attestation(k, degraded),
            };
            for ((a, b), rate) in polar::polar_class(k).into_iter().zip(triple) {
                // `a`, `b` are Fano point indices (< 7) by construction of `polar_class`; `.get_mut`
                // avoids raw bracket indexing rather than asserting that invariant with an allow.
                if let Some(cell) = matrix.get_mut(a).and_then(|row| row.get_mut(b)) {
                    *cell = rate;
                }
                if let Some(cell) = matrix.get_mut(b).and_then(|row| row.get_mut(a)) {
                    *cell = rate;
                }
            }
        }
        matrix
    }

    /// Fold this window's cell health into a `CoherenceFrame`, record it in local history, and return the
    /// effect that publishes its wire bytes. The exact 3-bit syndrome comes from `degraded`; the coherence
    /// scalars from the equicorrelated liveness model at the *effective* (post-shed) correlation
    /// (docs/design-telemetry.md §2). `epoch` is the cell's AGREED epoch, so cross-node roll-up buckets
    /// consistently (audit A3).
    fn emit_observation(
        &mut self,
        now: Instant,
        epoch: Epoch,
        alive_count: usize,
        degraded: u8,
        healthy_correlation: f64,
    ) -> Effect {
        let correlation = self.effective_correlation(healthy_correlation);
        let frame = self.observer.observe_liveness(
            now.as_nanos(),
            epoch.get(),
            alive_count,
            correlation,
            degraded,
            polar_gap_from_liveness(degraded), // spectral gap Δ (T-226(v)) from this window's health topology
            -1,                                // cascade forecast: none from liveness alone
        );
        Effect::Notify(Notification::Observed(frame.encode().to_vec()))
    }

    /// Diagnose the sensed cell snapshot (`self_index, degraded, alive_count`, produced by the facade's
    /// liveness sensing) and actuate any healing — the DIAKRISIS reflex proper. Feeds the *measured*
    /// behavioural `Γ_net` (the #74 unification) plus the live polar cross-attestation into `diagnose`,
    /// runs the verdict→plan→actuate path (over-coupling gated by the [`DECOUPLE_DWELL`] hysteresis, #122),
    /// then the homeostat's re-integration/escalation bands, and finally the mandatory self-observation.
    fn diagnose<F: Field>(
        &mut self,
        now: Instant,
        self_index: usize,
        degraded: u8,
        alive_count: usize,
        config: &Config,
        epoch: Epoch,
    ) -> Vec<Effect> {
        // The base node senses liveness, and — the #74 unification — the *measured* behavioural coherence
        // `Γ_net` (the relay-activity self-model). Feeding `Γ_net` into `diagnose` makes its Systemic
        // (over-coupling) verdict fire on the same signal the homeostat acts on, so there is one
        // over-coupling authority, not a dormant liveness-only arm beside a separate behavioural check.
        // (Partition/cascade still need the global cross-attestation view, not this local sense alone.)
        let measured = self.monitor.coherence();
        // The structural (Byzantine) check (spec §6.4 + §6.2): the live polar cross-attestation matrix,
        // assembled from gossiped `DiagAttest` reports (§98). `diagnose` runs the 14 free polar sum-rules
        // against it FIRST, ahead of the syndrome localizer — an equivocating mediator's own report is
        // internally inconsistent and is caught and localized here; an honest cell's is always consistent,
        // so this never pre-empts the ordinary crash/churn path below, however many members are down.
        let pairwise_rates = self.attested_pairwise_rates::<F>(now, degraded, config.liveness_timeout);
        let verdict = diagnose(&Observation {
            degraded,
            pairwise_rates: Some(pairwise_rates),
            coherence: measured.clone(),
            ..Default::default()
        });

        // Hysteresis for the over-coupling shed (audit #122): count consecutive over-coupled diagnoses,
        // resetting on any non-over-coupled one. `Decouple` actuates only once this reaches DECOUPLE_DWELL,
        // so the now-continuous reflex sheds on *sustained* over-coupling, not a single transient reading.
        self.overcoupling_streak = if matches!(verdict, fanos_diakrisis::Verdict::Systemic) {
            self.overcoupling_streak.saturating_add(1)
        } else {
            0
        };

        let mut effects = alloc::vec![Effect::Notify(Notification::Verdict(verdict.clone()))];
        if config.self_healing {
            // Φ from the cell's live membership on the equicorrelated stratum, at the *effective*
            // (post-shed) correlation — so a prior `Decouple` has genuinely lowered it (audit C6). Gates
            // the reroute-depth budget.
            let phi = phi_equicorrelated(alive_count, self.effective_correlation(config.healthy_correlation));
            let plan = plan_healing(&verdict, self_index, degraded, phi);
            if !plan.is_empty() {
                self.observer.note_healing();
            }
            // Over-coupling actuation (`Decouple`) flows through this verdict→plan path, gated by the dwell
            // hysteresis above; `apply_healing_plan` raises the mutable decoupling state and dedups the
            // notification (audit C6/#122). Crash/Byzantine actions in the plan are never gated.
            let decouple_ready = self.overcoupling_streak >= DECOUPLE_DWELL;
            effects.extend(self.apply_healing_plan::<F>(now, &plan, decouple_ready));

            // The homeostat covers the bands the Systemic verdict does not: **re-integration** once the
            // measured `Γ_net` is back in (or below) the band (Bind/Hold — decay the shed), and
            // **escalation** on a coherence *collapse* (`P ≤ 2/N`). Over-coupling is the verdict path's.
            if let Some(coherence) = measured {
                let m = coherence.measures();
                match self
                    .homeostat
                    .control(m.purity, coherence.mean_correlation(), coherence.n())
                {
                    BandControl::Escalate => {
                        if !self.escalated_coherence {
                            self.escalated_coherence = true;
                            self.observer.note_healing();
                            effects.push(Effect::Notify(Notification::Escalated(0)));
                        }
                    }
                    BandControl::Decouple { .. } => {
                        // Actuated via the verdict→plan path above; only clear the escalation latch.
                        self.escalated_coherence = false;
                    }
                    BandControl::Bind { .. } | BandControl::Hold => {
                        // In or below the band: let any prior shedding decay back toward the baseline
                        // coupling, and notify `Bound` once when fully re-integrated.
                        self.decoupling *= DECOUPLE_DECAY;
                        if self.decoupling < 1e-9 {
                            self.decoupling = 0.0;
                        }
                        self.escalated_coherence = false;
                        if self.decoupled && self.decoupling == 0.0 {
                            self.decoupled = false;
                            effects.push(Effect::Notify(Notification::Bound));
                        }
                    }
                }
            }
        }
        // Mandatory self-observation: diagnosis cannot happen without observing.
        effects.push(self.emit_observation(now, epoch, alive_count, degraded, config.healthy_correlation));
        effects
    }

    /// Apply a [`HealingPlan`], mutating the reroute / repaired / quarantine state and emitting a
    /// notification for each *new* corrective action (idempotent across repeated rounds).
    fn apply_healing_plan<F: Field>(
        &mut self,
        now: Instant,
        plan: &fanos_diakrisis::HealingPlan,
        decouple_ready: bool,
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
                    // Real correlation-shedding (audit C6), gated by the dwell hysteresis (#122): only once
                    // over-coupling has held for DECOUPLE_DWELL consecutive diagnoses do we raise the
                    // mutable decoupling factor (capped), lowering the effective correlation feeding `Φ`
                    // next round. Notify once on *entering* the shed regime (dedup), not each round.
                    if decouple_ready {
                        self.decoupling = (self.decoupling + DECOUPLE_STEP).min(DECOUPLE_MAX);
                        if !self.decoupled {
                            self.decoupled = true;
                            effects.push(Effect::Notify(Notification::Decoupled));
                        }
                    }
                }
                HealingAction::Escalate { unrecoverable } => {
                    effects.push(Effect::Notify(Notification::Escalated(unrecoverable)));
                }
            }
        }
        effects
    }
}

/// A projective point in the **content-address domain** (`MapToPoint(H(key))`, spec §L4): where a key
/// *ideally* lives, before the cell's actual occupancy is consulted. It is a distinct type from a node
/// coordinate on purpose (audit C4/#126): it carries no way to become a send target directly, so the
/// #123 send-to-nobody class — routing a `Put`/`Get` to a never-occupied content point — cannot happen by
/// construction. A content point is a routing target only once [`OverlayNode::responsible_point`] resolves
/// it to the nearest *occupied* node coordinate. It deliberately shares the plane's index ring with node
/// coordinates (that sharing is exactly what makes consistent hashing's "nearest occupied point"
/// meaningful), so the distinction is one of ROLE — enforced by requiring the explicit resolution step —
/// not of geometry.
#[derive(Clone, Copy)]
struct ContentPoint<F: Field>(Point<F>);

/// The base overlay node engine, generic over the cell's field `F`.
pub struct OverlayNode<F: Field> {
    coord: Point<F>,
    /// The hierarchical-routing concern — this node's overlay address + learned longest-prefix routing
    /// table (§L1). Factored into a [`Router`] collaborator (audit #125 decompose); the facade orchestrates
    /// the frame flow, the router owns the addressing state and the `RouteHier` forwarding decision.
    router: Router<F>,
    /// The membership concern — this node's own join credentials (identity bundle, signed descriptor,
    /// admission proof), the [`AdmissionPolicy`] it checks others against, and the learned key view of the
    /// cell. Factored into a [`Membership`] collaborator (audit #125 decompose); the facade orchestrates
    /// the JOIN/Announce frame flow.
    membership: Membership,
    config: Config,
    started_at: Instant,
    peers: BTreeMap<Triple, Peer>,
    heartbeating: bool,
    /// This node's Fano point index (`Some` only on the base `N = 7` cell, where the reflexive
    /// loop's index-addressed geometry — syndrome, mediator, peeling — applies).
    self_index: Option<usize>,
    /// The DIAKRISIS self-healing reflex — behavioural coherence self-model + over-coupling homeostat +
    /// crash/Byzantine healing state (reroute/repair/quarantine) + polar cross-attestation. Factored into a
    /// [`Healer`] collaborator (audit #125 decompose); the facade senses liveness (below) and hands it a
    /// sensed cell snapshot to diagnose and actuate on.
    healer: Healer,
    /// Witness-corroborated liveness (spec §6.4): for each peer, the freshest time *each distinct
    /// witness* directly observed it, learned from health-view gossip (`DiagGossip`). A lossy link
    /// cannot forge a false PeerDown (any honest witness rescues liveness), and a *Byzantine* liar
    /// cannot forge a false liveness either — a peer is believed alive on gossip only when a
    /// **quorum** of distinct witnesses vouch for it, so `quorum − 1` liars are outvoted.
    witnessed: BTreeMap<Triple, BTreeMap<Triple, Instant>>,
    /// The DHT-storage concern — this node's local store slice + read-repair bookkeeping (spec §L4). A
    /// value lives on its responsible content point and is cell-replicated for LRC availability, so any
    /// survivor answers a lookup (a lookup to a *down* primary reroutes through the self-healing table,
    /// §6.7). Factored into a [`Store`] collaborator (audit #125 decompose); the facade orchestrates.
    store: Store,
    /// The current epoch, driven by the flooded beacon (adopt-max, spec §L3). Epoch-derived
    /// rendezvous/shapes rotate as it advances.
    epoch: Epoch,
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

/// The cell's polar spectral gap `Δ` (T-226(v)) read from this window's **liveness topology** — the
/// recovery rate whose reciprocal `τ = 1/Δ` is the slowest polar mode's healing time constant.
///
/// Each Fano line's rate is the count of its three points that are corroborated-alive (`degraded` bit
/// clear), i.e. the coherence *flux* that axis can still carry; feeding these line rates to
/// [`spectral_gap`] yields `Δ = (G − maxₖ Tₖ)/6`. Deriving `Δ` from the same liveness signal that sets
/// the rest of the frame keeps the observation internally consistent — and, crucially, this is the
/// *polar* gap from the health topology, **not** the second-eigenvalue gap of the behavioural coherence
/// matrix `Γ_net`, which is a different quantity that must not be substituted here (audit #74). A fully
/// healthy cell has uniform line rates `γ̄ = 3`, giving the theorem's maximal `Δ = (2/3)·3 = 2`; each
/// degraded point lowers the incident axes' flux and so slows recovery, exactly as T-226(v) predicts.
fn polar_gap_from_liveness(degraded: u8) -> f64 {
    let mut line_rates = [0.0f64; fano::N];
    for (rate, points) in line_rates.iter_mut().zip(fano::LINE_POINTS.iter()) {
        let live = points
            .iter()
            .filter(|&&p| degraded & (1u8 << p) == 0)
            .count();
        *rate = live as f64;
    }
    spectral_gap(&line_rates)
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
            router: Router::new(coord),
            membership: Membership::default(),
            config,
            started_at: Instant::default(),
            peers,
            heartbeating: false,
            self_index,
            healer: Healer::new(observer),
            witnessed: BTreeMap::new(),
            store: Store::default(),
            epoch: Epoch::ZERO,
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
        // A health-view (how stale this node's direct observation of each cell point is) and a
        // polar cross-attestation (this node's honest per-channel rate report for the 3 channels
        // it mediates): both base-cell-only, and read from the SAME corroborated liveness snapshot
        // this window, so the two stay consistent with each other (spec §6.4, §6.8, §6.2).
        let gossip_attest = self.cell_liveness(now).map(|(self_index, degraded, _)| {
            (
                encode(FrameType::DiagGossip, &self.health_view(now)),
                encode(
                    FrameType::DiagAttest,
                    &encode_diag_attest(self_index, degraded),
                ),
            )
        });
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
            if let Some((gossip, attest)) = &gossip_attest {
                effects.push(Effect::Send {
                    to: coord,
                    frame: gossip.clone(),
                });
                effects.push(Effect::Send {
                    to: coord,
                    frame: attest.clone(),
                });
            }
        }
        // Read repair: advance any Get whose current replica has gone silent past the read timeout.
        self.sweep_pending_gets(now, &mut effects);
        // Fold this window's relay activity into the behavioural coherence self-model.
        self.healer.sample_behavior::<F>(self.self_index);
        // Close the reflex loop (audit #122): having sensed this window (liveness, behaviour, and the
        // peers' gossiped attestations accumulated since the last beat), run DIAKRISIS diagnosis and
        // actuate any healing — every heartbeat. This makes the self-healing layer self-driving off the
        // engine's own cadence under ANY driver; before this it depended on a `Command::Diagnose` no
        // production driver ever sends, so a deployed node's namesake reflex (reroute/repair/quarantine/
        // decouple/escalate) was inert. `Command::Diagnose` remains for an out-of-band forced diagnosis.
        effects.extend(self.on_diagnose(now));
        effects.push(Effect::ArmTimer {
            token: HEARTBEAT,
            after: self.config.heartbeat,
        });
        effects
    }

    /// Advance reads whose outstanding replica has not answered within `read_timeout`: try the next
    /// replica on the line, or conclude `Retrieved(None)` once they are exhausted (spec §L4). This
    /// is the backstop for a *crashed* replica (a live one answers `found=false` immediately).
    fn sweep_pending_gets(&mut self, now: Instant, effects: &mut Vec<Effect>) {
        let timeout = self.config.read_timeout;
        let stale: Vec<[u8; DIGEST]> = self
            .store
            .pending
            .iter()
            .filter(|(_, p)| now.since(p.issued) > timeout)
            .map(|(digest, _)| *digest)
            .collect();
        for digest in stale {
            self.store.advance_pending_get(now, digest, effects);
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
        // the bounded quarantine window; once it elapses the [`Healer`] re-admits the member for
        // re-evaluation, so a transient fault is not a permanent exile (audit C5).
        if self.healer.is_quarantined(from, now) {
            return Vec::new();
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
                self.healer.clear_healing(from);
                Vec::new()
            }
            Some(FrameType::Route) => {
                // Data relay is the behavioural load signal (control chatter is excluded); count it toward
                // this peer's activity, folded into the coherence self-model on the next heartbeat sample.
                self.healer.record_relay(from);
                alloc::vec![Effect::Notify(Notification::Delivered {
                    from,
                    payload: frame.body.to_vec(),
                })]
            }
            Some(FrameType::RouteHier) => self.on_route_hier(from, frame.body),
            Some(FrameType::DiagGossip) => {
                // Receiving the gossip is itself a direct observation of the sender; its body
                // corroborates the sender's view of the rest of the cell (spec §6.4).
                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.last_seen = Some(now);
                    peer.reported_down = false;
                }
                self.healer.clear_healing(from);
                self.apply_health_view(now, from, frame.body);
                Vec::new()
            }
            Some(FrameType::DiagAttest) => {
                // Likewise a direct observation of the sender (spec §6.4); folds its polar-class
                // report into the cross-attestation store `attested_pairwise_rates` assembles from.
                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.last_seen = Some(now);
                    peer.reported_down = false;
                }
                self.healer.clear_healing(from);
                self.healer.apply_diag_attest(now, from, frame.body);
                Vec::new()
            }
            Some(FrameType::Publish) => self.on_publish(from, frame.body),
            Some(FrameType::Lookup) => self.on_lookup(from, frame.body),
            Some(FrameType::Value) => self.on_value(now, frame.body),
            Some(FrameType::Ack) => Self::on_ack(frame.body),
            Some(FrameType::Announce) => self.on_announce(frame.body),
            Some(FrameType::EpochAgree) => self.on_epoch_agree(frame.body),
            _ => Vec::new(),
        }
    }

    /// Seat this node at an overlay hierarchical address (builder), decoupled from its transport `coord`.
    /// A depth-1 node keeps the default `root(coord)`; a node that descended into a sub-cell (§L0), or a
    /// deployment that assigns transport addresses independently of overlay position, seats a deeper or
    /// different address here. Only the (type-guaranteed non-empty) address is needed — routing reads
    /// `hier`, transport reads `coord`, and the two need not coincide past depth 1 (a flat transport
    /// underlaying a structured overlay).
    #[must_use]
    pub fn with_hier_address(mut self, hier: HierAddr<F>) -> Self {
        self.router.address = hier;
        self
    }

    /// This node's hierarchical address (§L1).
    #[must_use]
    pub fn hier_address(&self) -> &HierAddr<F> {
        &self.router.address
    }

    /// Seat this node's long-term identity (spec §L0): its hybrid signature public-key bundle, the
    /// pre-image its `hier` address is derived from (builder). Carried in the node's `Announce` so peers
    /// running self-certified membership can verify the address it claims. Only meaningful when `hier` is
    /// actually `id`'s descent chain ([`fanos_primitives::address_point`]); a deployment sets both together.
    #[must_use]
    pub fn with_identity(mut self, id: Vec<u8>) -> Self {
        self.membership.identity = id;
        self
    }

    /// Seat a fully **signed descriptor** (builder): the identity bundle `id` and a `sig` over
    /// [`descriptor_message(coord, hier, id)`](descriptor_message) produced by the identity's hybrid
    /// signing key. Under self-certified membership peers verify this signature, so the transport
    /// coordinate is bound to the identity — an attacker cannot re-announce another node's address at
    /// its own endpoint (§80). The signing secret is never handed to the engine; a deployment signs
    /// once and installs the result here.
    #[must_use]
    pub fn with_signed_descriptor(mut self, id: Vec<u8>, sig: Vec<u8>) -> Self {
        self.membership.identity = id;
        self.membership.descriptor_sig = sig;
        self
    }

    /// Seat this node's own **Sybil-admission proof** (builder), e.g. produced by
    /// [`fanos_core::PowAdmission::solve`] over [`admission_challenge`] for this node's
    /// coordinate and current epoch. Carried in this node's `Announce`; a peer with
    /// `config.require_admission` set checks it against its own installed policy. Only
    /// meaningful once `admission_challenge(self.coord.coords(), epoch)` is what a receiving
    /// peer will re-derive — i.e. the proof was solved for *this* coordinate and an epoch the
    /// peer still accepts.
    #[must_use]
    pub fn with_admission_proof(mut self, proof: Vec<u8>) -> Self {
        self.membership.admission_proof = proof;
        self
    }

    /// Install this node's Sybil admission policy (builder): what a peer's announced proof is
    /// checked against when `config.require_admission` is set (spec §L3). Not needed to
    /// *present* a proof when joining — only to *verify* one others present, so a pure joiner
    /// need not install a policy, only [`with_admission_proof`](Self::with_admission_proof).
    #[must_use]
    pub fn with_admission_policy(mut self, policy: Box<dyn AdmissionPolicy>) -> Self {
        self.membership.admission_policy = Some(policy);
        self
    }

    /// Register a hierarchical peer reachable in one hop — the transport coordinate that reaches it and
    /// the overlay [`HierAddr`] it serves — replacing any existing address for that coordinate. This *is*
    /// the hierarchical routing table: `RouteHier` frames are forwarded greedily over it. A single-plane
    /// node needs none (transport ≡ overlay); a deployment or the membership layer seeds it for depth > 1.
    pub fn learn_hier_peer(&mut self, addr: HierAddr<F>, transport: Triple) {
        self.router.learn_peer(addr, transport);
    }

    /// Builder form of [`learn_hier_peer`](Self::learn_hier_peer).
    #[must_use]
    pub fn with_hier_peer(mut self, addr: HierAddr<F>, transport: Triple) -> Self {
        self.learn_hier_peer(addr, transport);
        self
    }

    /// The next-hop transport coordinate toward `dst`, or `None` if this node delivers `dst` locally or
    /// has no route to it. A thin accessor over [`Router::route`] for drivers and tests.
    #[must_use]
    pub fn hier_next_hop(&self, dst: &HierAddr<F>) -> Option<Triple> {
        match self.router.route(dst) {
            HierRoute::Forward(next) => Some(next),
            HierRoute::Deliver | HierRoute::Drop => None,
        }
    }

    /// Originate a hierarchical send to `dst`: deliver locally if we are its cell, else emit a
    /// `RouteHier` frame (`HierAddr(dst) ‖ payload`) toward the next hop — the driver entry a client
    /// uses to reach a multi-level destination (the single-plane [`on_send`](Self::on_send) is unchanged).
    pub fn send_hier(&mut self, dst: &HierAddr<F>, payload: &[u8]) -> Vec<Effect> {
        self.healer.record_origination();
        match self.router.route(dst) {
            HierRoute::Deliver => alloc::vec![Effect::Notify(Notification::Delivered {
                from: self.coord.coords(),
                payload: payload.to_vec(),
            })],
            HierRoute::Forward(next) => {
                let mut body = dst.encode();
                body.extend_from_slice(payload);
                alloc::vec![self.routed_send(next, encode(FrameType::RouteHier, &body))]
            }
            HierRoute::Drop => Vec::new(),
        }
    }

    /// Handle an incoming `RouteHier` frame (`HierAddr(dst) ‖ payload`): deliver if we are in the
    /// destination cell, else forward one cell closer (see [`Router::route`]). The
    /// destination address travels unchanged, so every hop re-derives its own next step.
    fn on_route_hier(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some(&depth) = body.first() else {
            return Vec::new();
        };
        let addr_len = 1 + usize::from(depth) * 12;
        let Some(dst) = body.get(..addr_len).and_then(HierAddr::<F>::decode) else {
            return Vec::new();
        };
        let payload = body.get(addr_len..).unwrap_or(&[]);
        match self.router.route(&dst) {
            HierRoute::Deliver => {
                self.healer.record_relay(from);
                alloc::vec![Effect::Notify(Notification::Delivered {
                    from,
                    payload: payload.to_vec(),
                })]
            }
            HierRoute::Forward(next) => {
                alloc::vec![self.routed_send(next, encode(FrameType::RouteHier, body))]
            }
            HierRoute::Drop => Vec::new(),
        }
    }

    fn on_send(&mut self, to: Triple, payload: &[u8]) -> Vec<Effect> {
        // This node originating a relay is its own behavioural activity (the self slot of the sample).
        self.healer.record_origination();
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
        let actual = self.healer.reroute_target(to);
        Effect::Send { to: actual, frame }
    }

    /// The DHT storage address of `key`: the digest and the **ideal** responsible point (spec §L4). The
    /// point is a [`ContentPoint`], not a routing target — the *actual* responsible node is
    /// [`responsible_point`](Self::responsible_point) applied to this ideal (the nearest occupied point),
    /// since a real cell rarely occupies every point exactly.
    fn address_of(key: &[u8]) -> ([u8; DIGEST], ContentPoint<F>) {
        // The one storage-address rule (`fanos_primitives`): digest keys the store, point routes to it —
        // both on the STORAGE domain, so they can never drift to different hashes (audit C7).
        (storage_digest(key), ContentPoint(storage_point::<F>(key)))
    }

    /// The node responsible for an ideal storage point: the nearest **occupied** point at or after
    /// `ideal`'s canonical index, wrapping the ring — consistent hashing on projective coordinates
    /// (spec §L0 "the responsible node is the nearest occupied point"). This is the sole bridge from the
    /// content-address domain ([`ContentPoint`]) to a node coordinate: on a full cell it is `ideal` itself;
    /// on a sparse or churning cell — the *normal* condition, since independent VRF placement covers only a
    /// fraction of a plane's points — it routes the key to a live member instead of a never-occupied point
    /// where a `Put`/`Get` would be a silent send-to-nobody (audit #123). The occupied set is this node
    /// plus every announced member, so all nodes sharing a membership view resolve the same responsible
    /// node.
    fn responsible_point(&self, ideal: ContentPoint<F>) -> Triple {
        let ideal_idx = ideal.0.index();
        // Occupied points by canonical index: this node, every cell peer we have heard from (its
        // algebraic slot is actually filled by a live node — liveness populates this even before any
        // JOIN/Announce), and every announced member. A NEVER-occupied point is simply absent, so it
        // is skipped; a heard-then-crashed occupant is handled downstream by `routed_send`'s reroute.
        let mut occupied: BTreeSet<usize> = self
            .peers
            .iter()
            .filter(|(_, p)| p.last_seen.is_some())
            .filter_map(|(&c, _)| Point::<F>::new(c).map(|pt| pt.index()))
            .chain(
                self.membership
                    .members
                    .keys()
                    .filter_map(|&c| Point::<F>::new(c).map(|pt| pt.index())),
            )
            .collect();
        occupied.insert(self.coord.index());
        // Successor on the index ring: the smallest occupied index >= ideal, else wrap to the smallest.
        // The occupied set always contains this node, so the `.or_else` fallback never yields `None` and
        // the `map_or` default (the ideal point itself) is unreachable — kept only for totality.
        occupied
            .range(ideal_idx..)
            .next()
            .or_else(|| occupied.iter().next())
            .map_or(ideal.0.coords(), |&i| Point::<F>::at(i).coords())
    }

    /// `Command::Put` — store a value at its responsible point and replicate it across the cell.
    fn on_put(&mut self, key: &[u8], value: Vec<u8>) -> Vec<Effect> {
        let (digest, ideal) = Self::address_of(key);
        let primary = self.responsible_point(ideal);
        if primary == self.coord.coords() {
            // We are the responsible node. Refuse (over cap / over-size) without replicating or claiming
            // it stored; otherwise replicate to the cell, ack ourselves, and store (moving the value in).
            if !self.store.admits(&digest, value.len()) {
                return Vec::new();
            }
            let mut effects = self.replicate(&digest, &value);
            effects.push(Effect::Notify(Notification::Stored(digest)));
            self.store.entries.insert(digest, value);
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
    /// empty after churn while replicas still hold it. The in-flight query is tracked in the
    /// [`Store`]'s `pending` map; [`on_value`](Self::on_value) and the heartbeat sweep drive it.
    fn on_get(&mut self, now: Instant, key: &[u8]) -> Vec<Effect> {
        let (digest, ideal) = Self::address_of(key);
        let primary = self.responsible_point(ideal);
        if let Some(value) = self.store.entries.get(&digest) {
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: Some(value.clone()),
            })];
        }
        // Cap in-flight reads (A4 DoS backstop): once [`MAX_PENDING_GETS`] distinct reads are
        // outstanding, refuse a *new* one — concluding `Retrieved(None)` — rather than track it, so a
        // flood of distinct-key `Get`s cannot grow the pending map without bound. A repeat Get for an
        // already-pending digest is allowed through (it refreshes the existing entry, no growth).
        if self.store.pending.len() >= MAX_PENDING_GETS && !self.store.pending.contains_key(&digest) {
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
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
        // A fresh per-request nonce correlates this read's replies (audit C4); a repeat Get for the same
        // key supersedes the old one with a new nonce, so the old read's in-flight replies go stale.
        self.store.seq = self.store.seq.wrapping_add(1);
        let nonce = self.store.seq;
        self.store.pending.insert(
            digest,
            PendingGet {
                issued: now,
                remaining,
                nonce,
            },
        );
        alloc::vec![self.routed_send(primary, encode_lookup(&digest, nonce))]
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
        // Store under the A4 DoS caps. A refused publish (over cap / over-size) is dropped without an
        // Ack or replication — a relayed flood of distinct digests cannot exhaust this node's memory.
        if !self.store.admits(&digest, value.len()) {
            return Vec::new();
        }
        self.store.entries.insert(digest, value.clone());
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
        // Canonical derived codec (audit A1): rejects a short or trailing-byte Lookup.
        let Ok(LookupBody { key: digest, nonce }) = LookupBody::from_wire(body) else {
            return Vec::new();
        };
        let (found, value): (bool, &[u8]) = match self.store.entries.get(&digest) {
            Some(v) => (true, v),
            None => (false, &[]),
        };
        alloc::vec![Effect::Send {
            to: from,
            frame: encode_value(&digest, found, value, nonce),
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
        let Some(nonce) = parse_u64(body, DIGEST + 1) else {
            return Vec::new();
        };
        // Correlate on the per-request nonce, NOT merely the key: a reply resolves a read only if it
        // matches the read currently in flight for this key. A stale/replayed `Value` from a prior get
        // (old nonce), or one with no in-flight read at all, is ignored — so it emits no spurious
        // `Retrieved` and can never drain a later same-key get with an old value (read-your-writes,
        // audit C4). The value bytes follow the nonce.
        match self.store.pending.get(&digest) {
            Some(p) if p.nonce == nonce => {}
            _ => return Vec::new(),
        }
        if found {
            // A survivor has it. Deliver once and retire the pending read (later dup replies no longer
            // match — the entry is gone).
            self.store.pending.remove(&digest);
            let value = Some(body.get(DIGEST + 1 + 8..).unwrap_or(&[]).to_vec());
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value
            })];
        }
        // A negative reply for the in-flight read: advance to the next replica, or conclude it absent.
        let mut effects = Vec::new();
        self.store.advance_pending_get(now, digest, &mut effects);
        effects
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

    /// `Command::Join` — record our own info and flood an announcement (carrying our overlay address)
    /// so every member learns our keys and how to route to us hierarchically.
    fn on_join(&mut self, info: Vec<u8>) -> Vec<Effect> {
        let coord = self.coord.coords();
        let frame = encode(
            FrameType::Announce,
            &announce_body(
                coord,
                &self.router.address,
                &self.membership.identity,
                &self.membership.descriptor_sig,
                &self.membership.admission_proof,
                &info,
            ),
        );
        let effects = self.flood(&frame);
        self.membership.members.insert(coord, info);
        effects
    }

    /// A received announcement: on first sight of a member, record it, notify, and re-flood so the
    /// key propagates cell-wide; on a repeat, drop (the monotone guard terminates the flood).
    fn on_announce(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((coord, hier, id, sig, proof, info)) = parse_announce::<F>(body) else {
            return Vec::new();
        };
        // Validate: a member coordinate must be a real, canonical projective point of this plane.
        // Rejecting the zero vector and out-of-range triples both prevents state poisoning and
        // bounds `members` by the plane size `N` — a peer cannot grow it without limit with forged
        // coordinates (spec §7.8 membership). The hierarchical address was already validated by
        // `parse_announce` (canonical points, bounded depth), so a forged one is dropped before here.
        let Some(coord) = Point::<F>::new(coord).map(|p| p.coords()) else {
            return Vec::new();
        };
        // Sybil admission (opt-in, spec §L3, §7.8 JOIN step 2): the FIRST gate, ahead of
        // self-certification and membership — a per-admission cost is exactly what the
        // structural centrality cap alone does not provide (`sybil_cost.rs`). Fails **closed**:
        // requiring admission with no policy installed rejects every peer, never silently
        // admits. A rejection is not admitted to `members` and is told why (`SYBIL_REJECT`,
        // spec §7.5), sent to the *claimed* coordinate rather than the immediate relay hop —
        // `Announce` is flooded, so whoever forwarded it to us need not be the joiner itself.
        if self.config.require_admission {
            let challenge = admission_challenge(coord, self.epoch);
            if !self.membership.admits(&challenge, &proof) {
                return alloc::vec![Effect::Send {
                    to: coord,
                    frame: encode_error(ProtocolError::SybilReject),
                }];
            }
        }
        // Self-certified membership (opt-in) drops the whole announcement unless BOTH hold:
        //  1. the overlay address is the identity's own derived descent chain — else it is a
        //     routing-table poisoning attempt (a peer claiming an address it did not earn to attract a
        //     target's `RouteHier` traffic); forging a match costs `≈ N^k` grinding (threat §79/B1);
        //  2. the descriptor signature binds this exact transport `coord` to the identity — else it is a
        //     transport hijack (re-announcing another identity's address at the attacker's own endpoint),
        //     which without the identity's private key cannot be signed (threat §80).
        // Under VRF coordinates (`config.vrf_coordinates`, spec §A7) the level-0 point is the beacon-seated
        // VRF coordinate, NOT the hash `address_point(id, 0)`, so the chain check starts at level 1 — level
        // 0's authenticity is the proof-of-coordinate HELLO + the descriptor signature (check 2). Without
        // this skip a legitimate VRF announcement fails check 1 and is rejected (audit C3).
        // Neither `members` nor the router's peer table is written on failure.
        let min_level = usize::from(self.config.vrf_coordinates);
        if self.config.require_self_certified_membership
            && (!fanos_primitives::address_matches_identity_from::<F>(&id, &hier, min_level)
                || !descriptor_signature_ok::<F>(coord, &hier, &id, &sig))
        {
            return Vec::new();
        }
        // First sight only. A repeat must NOT overwrite the stored key bundle — otherwise any peer
        // could silently replace a member's advertised keys in our local view (and suppress the
        // re-flood, diverging the cell). Ignore repeats entirely; the monotone guard ends the flood.
        if self.membership.members.contains_key(&coord) {
            return Vec::new();
        }
        self.membership.members.insert(coord, info.clone());
        // Seed the hierarchical routing table: this overlay address is reachable via `coord`. A
        // descended sub-cell member thus becomes routable cell-wide from its announcement alone (§L1);
        // a depth-1 announcer adds its own direct entry, so `send_hier` also delivers within one plane.
        self.learn_hier_peer(hier.clone(), coord);
        let frame = encode(
            FrameType::Announce,
            &announce_body(coord, &hier, &id, &sig, &proof, &info),
        );
        let mut effects = self.flood(&frame);
        effects.push(Effect::Notify(Notification::MemberJoined { coord, info }));
        effects
    }

    /// `Command::AdvanceEpoch` — bump the epoch and flood the epoch-agreement gossip so the cell adopts
    /// it. This carries only the epoch ordinal ([`FrameType::EpochAgree`]), never randomness — under a
    /// live threshold-DVRF beacon the composite drives this from an authoritative `Beacon` round instead
    /// and suppresses the flood (audit #102).
    fn on_advance_epoch(&mut self) -> Vec<Effect> {
        self.epoch = self.epoch.next();
        let mut effects = self.flood(&encode(FrameType::EpochAgree, &self.epoch.low32_be_bytes()));
        effects.push(Effect::Notify(Notification::EpochAdvanced(self.epoch)));
        effects
    }

    /// A received epoch-agreement gossip: adopt it iff strictly newer (monotone), then re-flood and
    /// notify. The 4-byte body is the epoch ordinal — see [`FrameType::EpochAgree`].
    fn on_epoch_agree(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some(bytes) = body.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
            return Vec::new();
        };
        let epoch = Epoch::from_low32_be_bytes(bytes);
        if epoch <= self.epoch {
            return Vec::new(); // not newer — drop (terminates the flood)
        }
        self.epoch = epoch;
        let mut effects = self.flood(&encode(FrameType::EpochAgree, &epoch.low32_be_bytes()));
        effects.push(Effect::Notify(Notification::EpochAdvanced(epoch)));
        effects
    }

    /// `Command::Reseat` — re-seat this node at `new_coord` for the per-epoch reshuffle (spec §L3 "epoch
    /// reshuffle", §3.2). The driver supplies the new VRF-derived coordinate (the engine is crypto-free and
    /// cannot compute it); this re-derives the node's cell neighbours, Fano index, and hierarchical address
    /// for the new placement, re-announces so the cell relearns how to route to it, and emits
    /// [`Notification::Reseated`] (a driver rebuilds its HELLO proof-of-coordinate; the simulator re-keys
    /// the node). The unpredictable reshuffle is the load-bearing anti-eclipse / anti-path-prediction
    /// defence (§3.2 assumption 2), the one q=2 grinding does not provide.
    ///
    /// **STORAGE is deliberately preserved.** Content addressing is epoch-stable (`MapToPoint(H(k))`, §L4)
    /// and the store is full-cell-replicated, so a within-cell reshuffle is a *placement* move, not a data
    /// migration ("fixed points, flowing nodes"): the node still holds every value it held and keeps serving
    /// them across the transition — that preservation **is** the one-epoch grace window (audit C2), so no
    /// key is lost on rotation. A per-shard prune of values a node is no longer a replica for belongs to the
    /// erasure-coded store (#115), where a replica can compute its own line-membership; under full
    /// replication every cell member is a replica for every key, so within a cell there is nothing to prune.
    ///
    /// A no-op if `new_coord` is not a canonical projective point or already equals this coordinate.
    fn on_reseat(&mut self, new_coord: Triple) -> Vec<Effect> {
        let Some(new_pt) = Point::<F>::new(new_coord) else {
            return Vec::new(); // not a canonical projective point — ignore
        };
        if new_pt == self.coord {
            return Vec::new(); // already seated here
        }
        let old = self.coord.coords();
        // Re-derive the cell neighbour set for the new coordinate — with fresh liveness, exactly as a join
        // does: the node re-discovers which neighbours are live at its new position over the next heartbeat
        // round, so no stale "alive" carries over from the old placement into the responsibility set.
        let mut peers = BTreeMap::new();
        for line in Plane::<F>::lines_through(new_pt) {
            for member in Plane::<F>::points_on(line) {
                if member != new_pt {
                    peers.entry(member.coords()).or_insert(Peer {
                        last_seen: None,
                        reported_down: false,
                    });
                }
            }
        }
        self.peers = peers;
        self.self_index = if Plane::<F>::N == 7 {
            (0..7).find(|&i| Point::<F>::at(i) == new_pt)
        } else {
            None
        };
        self.coord = new_pt;
        self.router = Router::new(new_pt);
        // Drop our now-stale self-entry at the old coordinate and re-announce at the new one (spec §7.8), so
        // the cell relearns our placement; then signal the reshuffle for the driver (rebuild HELLO) and the
        // simulator (re-key routing). The store, membership view of others, witnessed liveness, and epoch
        // are all preserved.
        let info = self.membership.members.remove(&old).unwrap_or_default();
        let mut effects = self.on_join(info);
        // Re-establish the liveness heartbeat at the new coordinate. A driver's heartbeat is not
        // coordinate-keyed, so this merely resets its interval; but under a coordinate-addressed transport
        // (the simulator) the timer armed at the OLD coordinate is now orphaned, so the reflex would fall
        // silent after a reshuffle without this — the node must keep pinging from its new placement.
        if self.heartbeating {
            effects.push(Effect::ArmTimer {
                token: HEARTBEAT,
                after: self.config.heartbeat,
            });
        }
        effects.push(Effect::Notify(Notification::Reseated { old, new: new_coord }));
        effects
    }

    /// The current membership view (coordinate → announced info), for onion routing / observation.
    pub fn members(&self) -> impl Iterator<Item = (Triple, &[u8])> + '_ {
        self.membership.members.iter().map(|(&c, i)| (c, i.as_slice()))
    }

    /// The current beacon epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
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

    /// Sense-only self-observation (`Command::Observe`): emit the cell's coherence frame **without**
    /// running the verdict or any healing — the passive monitor read (docs/design-telemetry.md §4). The
    /// facade senses the cell's liveness; the [`Healer`] folds it into the observation frame.
    fn on_observe(&mut self, now: Instant) -> Vec<Effect> {
        match self.cell_liveness(now) {
            Some((_, degraded, alive_count)) => alloc::vec![self.healer.emit_observation(
                now,
                self.epoch,
                alive_count,
                degraded,
                self.config.healthy_correlation,
            )],
            None => Vec::new(),
        }
    }

    /// Run the DIAKRISIS reflex (`Command::Diagnose`, and every heartbeat since #122): the facade senses
    /// the cell's liveness locally — on the base Fano cell (N=7) a node sees the whole cell through its
    /// lines, so it builds the full degraded mask (spec §6.3) — then hands that sensed snapshot to the
    /// [`Healer`], which diagnoses the measured coherence + polar cross-attestation and actuates any
    /// healing. Off the base cell (`cell_liveness` is `None`) the index-addressed reflex does not apply.
    fn on_diagnose(&mut self, now: Instant) -> Vec<Effect> {
        let Some((self_index, degraded, alive_count)) = self.cell_liveness(now) else {
            return Vec::new();
        };
        self.healer
            .diagnose::<F>(now, self_index, degraded, alive_count, &self.config, self.epoch)
    }

    /// The current self-healing reroute table (down node → co-linear survivor), for observation.
    pub fn reroutes(&self) -> impl Iterator<Item = (Triple, Triple)> + '_ {
        self.healer.reroutes()
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
            Input::Command(Command::Reseat { coord }) => self.on_reseat(coord),
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

/// The `Lookup` frame body: `key(32) ‖ nonce(8)` (spec §L4). The nonce is the reader's per-request
/// correlator, echoed in the `Value` reply so a stale/replayed answer cannot resolve a different read
/// (audit C4). Its canonical codec is **derived** — one definition, one encoding (audit A1/G2).
#[derive(fanos_wire_derive::Wire)]
struct LookupBody {
    key: [u8; DIGEST],
    nonce: u64,
}

/// A `DiagAttest` frame body (spec §6.4): this node's honest polar-class report — the 3 rates
/// for the channels it mediates (`polar::polar_class(self_index)`), in that fixed order — as raw
/// `3 × f64` little-endian (24 bytes). Bit-exact, no quantization: an honest report's 3 values are
/// identical by construction (`polar::mediator_attestation`), and must round-trip identical
/// against the receiver's tight `POLAR_TOLERANCE` check.
fn encode_diag_attest(self_index: usize, degraded: u8) -> Vec<u8> {
    let rates = polar::mediator_attestation(self_index, degraded);
    let mut body = Vec::with_capacity(24);
    for r in rates {
        body.extend_from_slice(&r.to_le_bytes());
    }
    body
}

/// A `Lookup` frame (the derived body under the frame header).
fn encode_lookup(digest: &[u8; DIGEST], nonce: u64) -> Vec<u8> {
    encode(
        FrameType::Lookup,
        &LookupBody {
            key: *digest,
            nonce,
        }
        .to_wire(),
    )
}

/// A `Value` reply: `key(32) ‖ found(1) ‖ nonce(8) ‖ value` (spec §L4) — the nonce echoes the `Lookup`'s.
fn encode_value(digest: &[u8; DIGEST], found: bool, value: &[u8], nonce: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(DIGEST + 1 + 8 + value.len());
    body.extend_from_slice(digest);
    body.push(u8::from(found));
    body.extend_from_slice(&nonce.to_be_bytes());
    body.extend_from_slice(value);
    encode(FrameType::Value, &body)
}

/// Parse a big-endian `u64` at byte offset `off` from `body`, or `None` if it is too short.
fn parse_u64(body: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = body.get(off..off.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Parse a 32-byte key digest from an optional slice.
fn parse_digest(slice: Option<&[u8]>) -> Option<[u8; DIGEST]> {
    <[u8; DIGEST]>::try_from(slice?).ok()
}

/// The bytes a node's hybrid signing key signs to bind its **transport coordinate** to its identity's
/// **overlay address**: `coord(12) ‖ hier ‖ id` (spec §80). A deployment signs this once and installs
/// the signature via [`OverlayNode::with_signed_descriptor`]; a receiver reconstructs it from the parsed
/// announce and checks the signature — so an attacker cannot re-announce another identity's address at
/// its own coordinate (it would have to forge that identity's signature over a *different* `coord`).
#[must_use]
pub fn descriptor_message<F: Field>(coord: Triple, hier: &HierAddr<F>, id: &[u8]) -> Vec<u8> {
    let hier_bytes = hier.encode();
    let mut msg = Vec::with_capacity(12 + hier_bytes.len() + id.len());
    msg.extend_from_slice(&fanos_geometry::encode_triple(coord));
    msg.extend_from_slice(&hier_bytes);
    msg.extend_from_slice(id);
    msg
}

/// Whether `sig` is a valid hybrid signature over the descriptor `coord ‖ hier ‖ id`, under the
/// signature verifier packed at the front of the identity bundle `id` (`Ed25519(32) ‖ ML-DSA-65(1952)`
/// = [`HYBRID_VK_LEN`](fanos_pqcrypto::sig::HYBRID_VK_LEN) bytes). Binds the transport coordinate to the
/// identity, so a peer cannot re-announce another node's address at its own coordinate (§80). Any wrong
/// length or bad half returns `false` — never panics.
fn descriptor_signature_ok<F: Field>(
    coord: Triple,
    hier: &HierAddr<F>,
    id: &[u8],
    sig: &[u8],
) -> bool {
    let Some(verifier) = id
        .get(..fanos_pqcrypto::sig::HYBRID_VK_LEN)
        .and_then(fanos_pqcrypto::HybridVerifier::decode)
    else {
        return false;
    };
    let Some(signature) = fanos_pqcrypto::HybridSignature::from_bytes(sig) else {
        return false;
    };
    let msg = descriptor_message(coord, hier, id);
    verifier.verify(&msg, &signature)
}

/// An `Announce` body: `coord(12) ‖ hier(1+depth×12) ‖ id_len(2) ‖ id ‖ sig_len(2) ‖ sig ‖
/// proof_len(2) ‖ proof ‖ info` (spec §7.8 JOIN, §L1 address, §80 signed descriptor, §L3 Sybil
/// admission). `coord` is the transport point peers send to; `hier` is the announcer's overlay
/// address, so a receiver seeds its routing table (`hier → coord`). `id` is the announcer's
/// identity bundle (§L0) — the address derives from it — `sig` is the hybrid signature over
/// [`descriptor_message`] binding the coordinate to that identity, and `proof` is the
/// announcer's Sybil-admission proof, checked against [`admission_challenge`]`(coord, epoch)`
/// by a peer requiring admission. Every variable field is length- or self-delimited, so `info`
/// follows unambiguously.
fn announce_body<F: Field>(
    coord: Triple,
    hier: &HierAddr<F>,
    id: &[u8],
    sig: &[u8],
    proof: &[u8],
    info: &[u8],
) -> Vec<u8> {
    let hier_bytes = hier.encode();
    let id_len = u16::try_from(id.len()).unwrap_or(u16::MAX);
    let id = id.get(..usize::from(id_len)).unwrap_or(id);
    let sig_len = u16::try_from(sig.len()).unwrap_or(u16::MAX);
    let sig = sig.get(..usize::from(sig_len)).unwrap_or(sig);
    let proof_len = u16::try_from(proof.len()).unwrap_or(u16::MAX);
    let proof = proof.get(..usize::from(proof_len)).unwrap_or(proof);
    let mut body = Vec::with_capacity(
        12 + hier_bytes.len() + 2 + id.len() + 2 + sig.len() + 2 + proof.len() + info.len(),
    );
    body.extend_from_slice(&fanos_geometry::encode_triple(coord));
    body.extend_from_slice(&hier_bytes);
    body.extend_from_slice(&id_len.to_be_bytes());
    body.extend_from_slice(id);
    body.extend_from_slice(&sig_len.to_be_bytes());
    body.extend_from_slice(sig);
    body.extend_from_slice(&proof_len.to_be_bytes());
    body.extend_from_slice(proof);
    body.extend_from_slice(info);
    body
}

/// The parsed pieces of an `Announce` body: `(coord, hier, id, sig, proof, info)` (see
/// [`parse_announce`]).
type ParsedAnnounce<F> = (Triple, HierAddr<F>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Parse an `Announce` body into `(coord, hier, id, sig, proof, info)`. `None` on a short buffer
/// or a non-canonical hierarchical address (so a forged announce cannot inject a bogus
/// routing-table entry).
fn parse_announce<F: Field>(body: &[u8]) -> Option<ParsedAnnounce<F>> {
    let coord = fanos_geometry::decode_triple(body.get(..12)?)?;
    let rest = body.get(12..)?;
    let hier_len = 1 + usize::from(*rest.first()?) * 12;
    let hier = HierAddr::<F>::decode(rest.get(..hier_len)?)?;
    let after_hier = rest.get(hier_len..)?;
    let id_len = usize::from(u16::from_be_bytes(after_hier.get(0..2)?.try_into().ok()?));
    let id = after_hier.get(2..2 + id_len)?.to_vec();
    let after_id = after_hier.get(2 + id_len..)?;
    let sig_len = usize::from(u16::from_be_bytes(after_id.get(0..2)?.try_into().ok()?));
    let sig = after_id.get(2..2 + sig_len)?.to_vec();
    let after_sig = after_id.get(2 + sig_len..)?;
    let proof_len = usize::from(u16::from_be_bytes(after_sig.get(0..2)?.try_into().ok()?));
    let proof = after_sig.get(2..2 + proof_len)?.to_vec();
    let info = after_sig.get(2 + proof_len..)?.to_vec();
    Some((coord, hier, id, sig, proof, info))
}

/// The domain-separated Sybil-admission challenge for a joiner at `coord` in `epoch` (spec §L3):
/// what an [`AdmissionPolicy`] proof is checked against ([`OverlayNode::with_admission_policy`]).
/// Binding the coordinate and epoch means a proof cannot be replayed at a different address or
/// reused past an epoch roll. A live per-epoch beacon *seed* is not yet wired into
/// `OverlayNode` (§L3.2 / A7 Level B is tracked separately, not by this task); once it is,
/// folding it in here strengthens the binding as a drop-in change, not a redesign — `epoch`
/// already rotates unpredictably under the flooded epoch-agreement gossip (`on_epoch_agree`), so the
/// binding is real today, just not yet as strong as the full spec picture.
#[must_use]
pub fn admission_challenge(coord: Triple, epoch: Epoch) -> Vec<u8> {
    let mut challenge = Vec::with_capacity(12 + 4);
    challenge.extend_from_slice(&fanos_geometry::encode_triple(coord));
    challenge.extend_from_slice(&epoch.low32_be_bytes());
    challenge
}

/// An `Error` frame body: `code(8B BE) ‖ reason` — the numeric [`ProtocolError`] code and an
/// optional UTF-8 reason (empty here; a human-readable reason is left to the wire-handshake
/// follow-up, task #100). Canonical derived codec (audit A1) — one definition, one encoding,
/// the same `#[derive(Wire)]` pattern [`LookupBody`] uses above: a `u64` field's canonical
/// encoding is a fixed 8-byte big-endian integer (`fanos_wire::wire::impl_wire_int!`), not a
/// true LEB128 varint. Spec §7.5 describes the ERROR frame prose-level as "a varint code" —
/// this preliminary body is a real, working `SYBIL_REJECT` producer ahead of that, not the
/// formalization; reconciling the exact on-wire integer width against the spec text (or
/// widening the derive's integer convention itself) is task #100's, not this one's, to settle.
#[derive(fanos_wire_derive::Wire)]
struct ErrorBody {
    code: u64,
    reason: Vec<u8>,
}

/// An `Error` frame carrying `err`'s numeric code (spec §7.5), e.g. `SYBIL_REJECT` on a failed
/// admission check.
fn encode_error(err: ProtocolError) -> Vec<u8> {
    encode(
        FrameType::Error,
        &ErrorBody {
            code: err.code(),
            reason: Vec::new(),
        }
        .to_wire(),
    )
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
    fn hierarchical_route_delivers_at_the_destination_cell() {
        let dst = HierAddr::from_path(alloc::vec![Point::<F2>::at(2), Point::<F2>::at(5)]).unwrap();
        let mut node =
            OverlayNode::<F2>::new(Point::at(2), Config::default()).with_hier_address(dst.clone());
        assert_eq!(
            node.hier_next_hop(&dst),
            None,
            "the node is in the destination cell"
        );
        let mut body = dst.encode();
        body.extend_from_slice(b"hi");
        let frame = encode(FrameType::RouteHier, &body);
        let effects = node.step(
            Instant::default(),
            Input::Message {
                from: Point::<F2>::at(1).coords(),
                frame,
            },
        );
        assert!(
            effects.iter().any(|e| matches!(e,
                Effect::Notify(Notification::Delivered { payload, .. }) if payload == b"hi")),
            "the destination cell delivers the payload",
        );
    }

    #[test]
    fn hierarchical_route_forwards_toward_the_destination_cell() {
        // A depth-1 node at point 1 forwards a RouteHier for [2,5] to point 2 (the divergence level).
        let mut node = OverlayNode::<F2>::new(Point::at(1), Config::default());
        let dst = HierAddr::from_path(alloc::vec![Point::<F2>::at(2), Point::<F2>::at(5)]).unwrap();
        assert_eq!(
            node.hier_next_hop(&dst),
            Some(Point::<F2>::at(2).coords()),
            "forward toward the destination's top-cell point",
        );
        let effects = node.send_hier(&dst, b"p");
        assert!(
            effects.iter().any(
                |e| matches!(e, Effect::Send { to, .. } if *to == Point::<F2>::at(2).coords())
            ),
            "emits a RouteHier toward point 2",
        );
    }

    #[test]
    fn a_sub_cell_root_descends_toward_a_deeper_destination() {
        // A node at [2] forwarding to [2,5] descends into its sub-cell toward point 5 (dst.point_at(1)).
        let node = OverlayNode::<F2>::new(Point::at(2), Config::default());
        let dst = HierAddr::from_path(alloc::vec![Point::<F2>::at(2), Point::<F2>::at(5)]).unwrap();
        assert_eq!(
            node.hier_next_hop(&dst),
            Some(Point::<F2>::at(5).coords()),
            "an ancestor descends one level toward the destination",
        );
    }

    #[test]
    fn hierarchical_delivery_end_to_end_across_two_levels() {
        // A real two-engine hop: an origin in the top cell (address `[1]`) reaches a depth-2
        // destination (`[2,5]`). The origin forwards toward the destination's top point (2); the
        // destination engine decodes the `RouteHier`, sees every level match, and delivers. We drive
        // the emitted frames through a minimal routing loop — the same forward/deliver decision the
        // live mesh runs, exercised over real `OverlayNode` engines rather than in isolation.
        let mut origin = OverlayNode::<F2>::new(Point::at(1), Config::default());
        let dst = HierAddr::from_path(alloc::vec![Point::<F2>::at(2), Point::<F2>::at(5)]).unwrap();
        let mut dest =
            OverlayNode::<F2>::new(Point::at(2), Config::default()).with_hier_address(dst.clone());
        assert_eq!(
            dest.hier_address(),
            &dst,
            "the destination is seated at [2,5]"
        );

        // Engines reachable by their transport coordinate — the key the mesh forwards on.
        let now = Instant::default();
        let origin_coord = Point::<F2>::at(1).coords();
        let dest_coord = Point::<F2>::at(2).coords();
        let mut pending: Vec<(Triple, Triple, Vec<u8>)> = Vec::new(); // (from, to, frame)
        for e in origin.send_hier(&dst, b"unit-e2e") {
            if let Effect::Send { to, frame } = e {
                pending.push((origin_coord, to, frame));
            }
        }
        assert_eq!(
            pending.len(),
            1,
            "origin emits exactly one hop, not a local delivery"
        );

        let mut delivered = false;
        let mut hops = 0u32;
        while let Some((from, to, frame)) = pending.pop() {
            hops += 1;
            assert!(
                hops <= fanos_geometry::MAX_DEPTH as u32 + 1,
                "routing must converge, not loop"
            );
            // In this topology the only transport point that hosts an engine is the destination's.
            assert_eq!(to, dest_coord, "the hop targets the destination cell");
            for e in dest.step(now, Input::Message { from, frame }) {
                match e {
                    Effect::Notify(Notification::Delivered { payload, .. })
                        if payload == b"unit-e2e" =>
                    {
                        delivered = true;
                    }
                    Effect::Send { to: next, frame } => pending.push((dest_coord, next, frame)),
                    _ => {}
                }
            }
        }
        assert!(
            delivered,
            "the depth-2 destination delivered the payload end-to-end"
        );
    }

    #[test]
    fn heartbeat_pings_gossips_and_attests_to_every_neighbour_and_rearms() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let start = node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        assert!(matches!(start.as_slice(), [Effect::ArmTimer { .. }]));
        let effects = node.step(Instant(500_000_000), Input::Timer(HEARTBEAT));
        let mut pings = 0;
        let mut gossips = 0;
        let mut attests = 0;
        for e in &effects {
            if let Effect::Send { frame, .. } = e {
                match decode_frame(frame).unwrap().0.frame_type() {
                    Some(FrameType::Ping) => pings += 1,
                    Some(FrameType::DiagGossip) => gossips += 1,
                    Some(FrameType::DiagAttest) => attests += 1,
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
        assert_eq!(
            attests, 6,
            "attests its polar cross-attestation to all 6 neighbours"
        );
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
        let mut decoupled = false;
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
            // Fire the heartbeat: it folds this window's behavioural sample into the coherence monitor AND
            // runs the diagnosis reflex (audit #122) — after the dwell hysteresis confirms SUSTAINED
            // over-coupling in the measured Γ_net it sheds correlation right here, no explicit Diagnose.
            let hb = node.step(Instant(t), Input::Timer(HEARTBEAT));
            decoupled |= hb
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Decoupled)));
            t += 1;
        }
        assert!(
            decoupled,
            "sustained over-coupling drives the live homeostat to Decouple on its heartbeat reflex"
        );
    }

    #[test]
    fn decouple_genuinely_sheds_correlation_and_is_deduped() {
        // C6 + #74. A `Decouple` is no longer a no-op: it raises the mutable decoupling factor, which
        // lowers the *effective* correlation feeding Φ — so the reflexive loop actually restores headroom.
        // Detection is unified (#74): the verdict itself is `Systemic`, driven by the measured Γ_net.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let mut t = 1u64;
        let base = node.healer.effective_correlation(Config::default().healthy_correlation); // healthy_correlation, before any shed
        let mut decoupled_beats = 0usize;
        let mut systemic_seen = false;
        for w in 0..(BEHAVIOR_WINDOW + 2) {
            let bursts = (w % 3) + 1; // common-mode: every peer relays in lockstep
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
            // The heartbeat folds in this window's behaviour AND runs the diagnosis reflex (audit #122):
            // it emits a Systemic verdict on the measured over-coupling immediately, and once the dwell
            // hysteresis confirms it is SUSTAINED, sheds correlation — no explicit Diagnose needed.
            let hb = node.step(Instant(t), Input::Timer(HEARTBEAT));
            if hb.iter().any(|e| {
                matches!(
                    e,
                    Effect::Notify(Notification::Verdict(fanos_diakrisis::Verdict::Systemic))
                )
            }) {
                systemic_seen = true;
            }
            if hb
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Decoupled)))
            {
                decoupled_beats += 1;
            }
            t += 1;
        }
        // Unified detection (#74): the verdict is Systemic, from the measured Γ_net, not a dormant proxy.
        assert!(
            systemic_seen,
            "diagnosis's verdict is driven by the measured over-coupling (#74 unification)"
        );
        // Decoupled fires exactly ONCE — on crossing the dwell into the shed regime — then is deduped on
        // every later beat even though the reflex keeps running each heartbeat (audit C6 dedup / #122).
        assert_eq!(
            decoupled_beats, 1,
            "over-coupling decouples once on entering the shed regime, not on every beat"
        );
        assert!(
            node.healer.decoupling > 0.0,
            "the decoupling shed factor is raised (audit C6)"
        );
        assert!(
            node.healer.effective_correlation(Config::default().healthy_correlation) < base - 1e-9,
            "the effective correlation is genuinely lowered — Φ headroom restored, not a no-op"
        );
        // The mutable factor really is what scales the correlation (the feedback into Φ).
        assert!(
            (node.healer.effective_correlation(Config::default().healthy_correlation)
                - Config::default().healthy_correlation * (1.0 - node.healer.decoupling))
                .abs()
                < 1e-12
        );

        // Dedup holds under an explicit diagnose too: it keeps shedding but does NOT re-fire.
        let d2 = node.step(Instant(t), Input::Command(Command::Diagnose));
        assert!(
            !d2.iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Decoupled))),
            "Decoupled is emitted once on entering the shed regime, not every diagnose (audit C6 dedup)"
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
    fn the_polar_gap_tracks_the_liveness_topology() {
        // Δ is the T-226(v) polar recovery rate derived from the health topology. A fully healthy cell
        // has uniform line rates γ̄ = 3 ⇒ Δ = (2/3)·3 = 2 (the theorem's maximal gap); each degraded
        // point lowers the flux on its three incident axes and so slows the slowest polar mode.
        let healthy = polar_gap_from_liveness(0);
        assert!(
            (healthy - 2.0).abs() < 1e-12,
            "healthy cell has the maximal gap Δ = 2, got {healthy}"
        );

        // Degrading one point drops its 3 incident lines to rate 2: G = 18, max_k T_k = 8, Δ = 10/6.
        let one_down = polar_gap_from_liveness(1 << 0);
        assert!(
            (one_down - 10.0 / 6.0).abs() < 1e-12,
            "one degraded point gives Δ = 10/6 ≈ 1.667, got {one_down}"
        );
        assert!(one_down < healthy, "a fault slows recovery (smaller Δ)");

        // Monotone erosion: as more points fall, the gap never rises, and a dead cell has Δ = 0.
        let mut prev = healthy;
        let mut mask = 0u8;
        for p in 0..7u8 {
            mask |= 1 << p;
            let g = polar_gap_from_liveness(mask);
            assert!(
                g <= prev + 1e-12,
                "each additional fault does not raise the gap: {prev} → {g}"
            );
            assert!(g >= -1e-12, "the gap never goes negative");
            prev = g;
        }
        assert!(
            (prev - 0.0).abs() < 1e-12,
            "a fully degraded cell has zero recovery gap"
        );
    }

    // ---- A4: the DHT slice and in-flight-read table stay bounded under a flood (audit #62) ----

    /// A distinct 32-byte digest for flood index `i`, built without indexing (iterator zip).
    fn flood_digest(i: u32) -> [u8; DIGEST] {
        let mut d = [0u8; DIGEST];
        for (dst, src) in d.iter_mut().zip(i.to_be_bytes()) {
            *dst = src;
        }
        d
    }

    #[test]
    fn a_publish_flood_cannot_grow_the_store_without_bound() {
        // A relayed-Publish flood of distinct digests must not exhaust memory: the store is capped and a
        // new key is refused once full (existing replicas are never evicted).
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let from = Point::<F2>::at(1).coords();
        for i in 0..(MAX_STORE_ENTRIES as u32 + 500) {
            let frame = encode_publish(PUBLISH_REPLICA, &flood_digest(i), b"v");
            node.step(Instant(1), Input::Message { from, frame });
        }
        assert!(
            node.store.entries.len() <= MAX_STORE_ENTRIES,
            "the store is bounded under a publish flood, got {}",
            node.store.entries.len()
        );
    }

    #[test]
    fn an_oversize_published_value_is_refused() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let from = Point::<F2>::at(1).coords();
        let digest = [7u8; DIGEST];
        let too_big = alloc::vec![0u8; MAX_VALUE_LEN + 1];
        node.step(
            Instant(1),
            Input::Message {
                from,
                frame: encode_publish(PUBLISH_REPLICA, &digest, &too_big),
            },
        );
        assert!(
            !node.store.entries.contains_key(&digest),
            "an over-size value is refused"
        );
        // A value exactly at the limit is accepted.
        let at_limit = alloc::vec![0u8; MAX_VALUE_LEN];
        node.step(
            Instant(1),
            Input::Message {
                from,
                frame: encode_publish(PUBLISH_REPLICA, &digest, &at_limit),
            },
        );
        assert!(
            node.store.entries.contains_key(&digest),
            "a within-limit value is stored"
        );
    }

    #[test]
    fn an_existing_key_updates_even_when_the_store_is_full() {
        // Reject-when-full must never block overwriting an already-stored key (no growth) — otherwise a
        // flood that fills the store would freeze legitimate updates to existing replicas.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let from = Point::<F2>::at(1).coords();
        for i in 0..MAX_STORE_ENTRIES as u32 {
            let frame = encode_publish(PUBLISH_REPLICA, &flood_digest(i), b"a");
            node.step(Instant(1), Input::Message { from, frame });
        }
        assert_eq!(
            node.store.entries.len(),
            MAX_STORE_ENTRIES,
            "the store filled to the cap"
        );
        // Overwrite an existing key: allowed, no growth.
        let existing = flood_digest(0);
        node.step(
            Instant(1),
            Input::Message {
                from,
                frame: encode_publish(PUBLISH_REPLICA, &existing, b"updated"),
            },
        );
        assert_eq!(
            node.store.entries.get(&existing).map(Vec::as_slice),
            Some(&b"updated"[..]),
            "an existing key still updates when the store is full"
        );
        // A brand-new key is refused, and the cap is never exceeded.
        node.step(
            Instant(1),
            Input::Message {
                from,
                frame: encode_publish(PUBLISH_REPLICA, &[0xABu8; DIGEST], b"x"),
            },
        );
        assert!(
            !node.store.entries.contains_key(&[0xABu8; DIGEST]),
            "a new key is refused when full"
        );
        assert_eq!(
            node.store.entries.len(),
            MAX_STORE_ENTRIES,
            "the store never exceeds its cap"
        );
    }

    #[test]
    fn a_get_flood_cannot_grow_pending_reads_without_bound() {
        // A flood of distinct-key reads must not grow the in-flight table without bound; beyond the cap a
        // new read is settled `Retrieved(None)` immediately rather than tracked.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        for i in 0..(MAX_PENDING_GETS as u32 + 500) {
            node.step(
                Instant(1),
                Input::Command(Command::Get {
                    key: i.to_be_bytes().to_vec(),
                }),
            );
        }
        assert!(
            node.store.pending.len() <= MAX_PENDING_GETS,
            "pending reads are bounded under a get flood, got {}",
            node.store.pending.len()
        );
    }

    #[test]
    fn a_stale_value_reply_cannot_resolve_a_read_it_does_not_belong_to() {
        // C4. A `Value` correlates on the read's per-request nonce, not just the key. A reply with no
        // in-flight read, or a stale/replayed reply from a superseded prior get (old nonce), is ignored —
        // so it emits no spurious Retrieved and never drains a later same-key get with an old value.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let key = b"k";
        let (digest, _) = OverlayNode::<F2>::address_of(key);
        let peer = Point::<F2>::at(1).coords();
        let has_retrieved = |effects: &[Effect]| {
            effects
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Retrieved { .. })))
        };

        // A found=true Value with NO in-flight read is ignored (no spurious Retrieved).
        let stray = node.step(
            Instant(1),
            Input::Message {
                from: peer,
                frame: encode_value(&digest, true, b"ghost", 999),
            },
        );
        assert!(
            !has_retrieved(&stray),
            "a Value with no in-flight read emits no Retrieved"
        );

        // Issue read #1 (nonce 1), then supersede it with read #2 (nonce 2) for the same key.
        node.step(
            Instant(2),
            Input::Command(Command::Get { key: key.to_vec() }),
        );
        node.step(
            Instant(3),
            Input::Command(Command::Get { key: key.to_vec() }),
        );

        // A delayed reply from read #1 (old nonce 1) carrying a stale value must be ignored.
        let stale = node.step(
            Instant(4),
            Input::Message {
                from: peer,
                frame: encode_value(&digest, true, b"old", 1),
            },
        );
        assert!(
            !has_retrieved(&stale),
            "a stale reply (old nonce) does not resolve the newer read"
        );

        // The reply matching the in-flight nonce (2) resolves the read with the fresh value.
        let fresh = node.step(
            Instant(5),
            Input::Message {
                from: peer,
                frame: encode_value(&digest, true, b"new", 2),
            },
        );
        assert!(
            fresh.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Retrieved { key: k, value: Some(v) })
                    if *k == digest && v.as_slice() == b"new"
            )),
            "the reply matching the in-flight nonce resolves the read with the fresh value"
        );
    }

    #[test]
    fn quarantine_is_bounded_and_re_admits_a_member_after_the_ttl() {
        // A distrusted member is not exiled forever: within the window its frames are dropped, but once the
        // quarantine TTL elapses it is re-admitted for re-evaluation (a transient fault is not permanent).
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let member = Point::<F2>::at(1).coords();
        node.healer.quarantined.insert(member, Instant(0)); // as a Structural verdict would, at t=0

        // Within the window: frames are dropped and it stays quarantined.
        let within = node.step(
            Instant(1_000),
            Input::Message {
                from: member,
                frame: encode(FrameType::Route, b"x"),
            },
        );
        assert!(
            within.is_empty(),
            "a quarantined member's frames are dropped within the window"
        );
        assert!(
            node.healer.quarantined.contains_key(&member),
            "still quarantined within the window"
        );

        // Past the TTL (70 s > 60 s): re-admitted, and its frames are processed again.
        let after = node.step(
            Instant(70_000_000_000),
            Input::Message {
                from: member,
                frame: encode(FrameType::Route, b"x"),
            },
        );
        assert!(
            !node.healer.quarantined.contains_key(&member),
            "re-admitted once the window elapses"
        );
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
        let peer_addr = HierAddr::root(Point::<F2>::at(3));
        let honest = encode(
            FrameType::Announce,
            &announce_body(peer, &peer_addr, b"", b"", b"", b"HONEST"),
        );
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
        let forged = encode(
            FrameType::Announce,
            &announce_body(peer, &peer_addr, b"", b"", b"", b"ATTACKER"),
        );
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
        let zero = encode(
            FrameType::Announce,
            &announce_body([0, 0, 0], &peer_addr, b"", b"", b"", b"ZERO"),
        );
        node.step(Instant(3), Input::Message { from, frame: zero });
        assert_eq!(
            node.members().count(),
            count_before,
            "an invalid coordinate is not accepted as a member"
        );
    }
}
