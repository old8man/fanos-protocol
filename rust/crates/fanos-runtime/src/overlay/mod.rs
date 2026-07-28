//! `OverlayNode` — the base FANOS node engine (spec L1/L3 + DIAKRISIS), sans-I/O.
//!
//! This is production node logic: it maintains liveness of its cell neighbours via periodic
//! heartbeats, resolves rendezvous by the algebraic line `u × v`, delivers application
//! payloads, and (on the base Fano cell) runs one DIAKRISIS round to localize a fault. It
//! reacts only to [`Input`]s and emits only [`Effect`]s — no clock, socket, or RNG — so the
//! same code runs under the simulator and a real transport.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_code::erasure;
use fanos_core::{AdaptivePowAdmission, AdmissionPolicy, LiveDifficulty, ParentCell, PowAdmission};
use fanos_diakrisis::polar;
use fanos_diakrisis::regeneration::spectral_gap;
use fanos_field::Field;
use fanos_geometry::{HierAddr, Plane, Point, Triple, fano};
use fanos_primitives::{Epoch, hash_labeled, storage_digest, storage_point};
use fanos_telemetry::{CellId, HistoryConfig, SelfObserver};
use fanos_wire::{FrameType, decode_frame};


/// Hierarchical addressing, routing and escalation — see [`hier`].
mod hier;
/// Liveness sensing: heartbeat, aliveness view, loss/health snapshots — see [`liveness`].
mod liveness;
/// Joining, announcing, epoch advance and re-seat — see [`membership_ops`].
mod membership_ops;
/// Content storage and retrieval — see [`storage`].
mod storage;

/// Storage `Publish` sub-type: the **full value**, sent origin → responsible node, which then
/// erasure-codes it and distributes the shards. Carries no meaningful shard index (`0`).
pub(super) const PUBLISH_ORIGIN: u8 = 0;

/// The upward hop budget for a cell escalation (audit R-C2): a residue is handed up at most this many strata
/// before it is terminal (external help required), bounding the recursion at the HOLARCH depth ceiling so an
/// escalation storm cannot climb without end.
pub(super) const ESCALATE_TTL: u8 = 3;
/// Storage `Publish` sub-type: a single **erasure shard** for the point named by the frame's shard-index
/// byte — the receiver (its shard home) stores it under that index (spec §L4 projective LRC, #115). This is
/// what replaces full replication: a value is `erasure::encode`d into `N=7` shards, one per Fano point, each
/// placed at the point's [`nearest_occupied`](OverlayNode::nearest_occupied) home, so the cell holds the
/// value at `N/K ≈ 2.33×` redundancy (vs `N×` full replication) while any `≤3`-point loss still recovers it.
pub(super) const PUBLISH_SHARD: u8 = 2;
/// The DHT key-digest / storage-address length (BLAKE3-256) — the one canonical digest width.
pub(crate) const DIGEST: usize = fanos_primitives::DIGEST_LEN;

// Re-exported at this path, not merely imported: both are part of the crate's public surface and callers reach them as
// `overlay::…`. The codec moving to its own module is an internal split, and an internal split should not relocate a
// public name.
pub use crate::frames::{admission_challenge, descriptor_message};

use crate::frames::encode;
use crate::healer::Healer;
use crate::membership::Membership;
use crate::router::{Peer, Router};
use crate::store::Store;
use crate::ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

/// The single heartbeat timer token.
pub(super) const HEARTBEAT: TimerToken = TimerToken(0);

/// The behavioural-coherence observation window, in heartbeat samples: the cell's `Γ_net` is read from the
/// last this-many per-node relay-activity samples. Bounded, so the self-model memory is `7 × this`.
pub(crate) const BEHAVIOR_WINDOW: usize = 8;

/// Homeostatic **decoupling** control (audit C6). `Decouple` must actually lower the cell's integration,
/// not merely notify: the node carries a mutable shed factor in `[0, DECOUPLE_MAX]` that scales its
/// effective correlation down, and that reduced correlation feeds `phi_equicorrelated` — so each
/// over-coupled round genuinely restores headroom, and the reflexive loop lowers `Φ` (spec §2.7/§6.5).
/// Over-coupling raises the factor by `DECOUPLE_STEP` per round (capped); once back in band it decays by
/// `DECOUPLE_DECAY` toward zero (re-integration).
pub(crate) const DECOUPLE_STEP: f64 = 0.25;
pub(crate) const DECOUPLE_MAX: f64 = 0.6;
pub(crate) const DECOUPLE_DECAY: f64 = 0.5;
/// Hysteresis dwell for the over-coupling shed (audit #122). The measured `Γ_net` must read over-coupled
/// for this many *consecutive* self-driven diagnoses before `Decouple` actuates. Diagnosis now runs every
/// heartbeat (not a one-shot injected command), so a single transient over-threshold reading — e.g. a
/// coincidental correlation inside an otherwise decorrelated burst flood — must not trigger a shed: the
/// DDoS response acts on *sustained* over-coupling (structure), never momentary load. Crash/Byzantine
/// healing is unaffected — this gates only the `Decouple` action.
pub(crate) const DECOUPLE_DWELL: u32 = 3;

/// §6.4 endpoint cross-attestation window and firm-stale threshold, pinned by the simulator sweep
/// (`fanos-sim/tests/endpoint_attestation_research.rs`). The detector flags a witness only when it
/// *persistently* — across this many consecutive heartbeat rounds — vouches a node fresh that a firm
/// consensus reports stale. `ENDPOINT_WINDOW = 5` heartbeats (≈ 2.5 s > `liveness_timeout`) is longer than
/// a crash transient (all nodes stale on a dead peer within one heartbeat of each other), so churn cannot
/// persist across it; `ENDPOINT_MIN_STALE = ⌈(N−1)/2⌉ = 3` is a firm honest majority that still catches any
/// colluder minority (tolerates up to 3 vouch-fabricators, exceeding the plain `corroboration_quorum`).
pub(crate) const ENDPOINT_WINDOW: usize = 5;
pub(crate) const ENDPOINT_MIN_STALE: usize = 3;

/// §6.5 partition sensor (V14). A cell **line** counts as carrying live connectivity iff its worst pairwise
/// channel loss (measured, the #106 grey substrate) is below this — a fully-cut channel (`loss → 1`) or a
/// heavily-grey one drops the line, while honest jitter (`loss ≈ 0.05–0.15`) keeps it. Pinned by the sim
/// sweep (`coherence_live` / partition tests): it sits well above the jitter floor and below a cut/grey line.
const LINE_CUT_LOSS: f64 = 0.5;
/// §6.5 persistence: a partition candidate (the loss-weighted line graph disconnects, [`partition::is_connected`]
/// false) must hold this many consecutive diagnoses before `Verdict::Partition` is trusted. A recovery
/// transient — a just-healed node whose loss EWMA still lags, so its `q+1` lines read cut for a round or two
/// while it reads alive — does not persist, so it never false-fires; only a sustained lossy line-cover (a real
/// incipient split with nodes still alive) survives. `4` heartbeats > the EWMA recovery window.
pub(crate) const PARTITION_DWELL: u32 = 4;

/// §6.3 grey-detection loss EWMA smoothing factor. Each heartbeat folds one per-neighbour ping-answered
/// sample; `0.25` averages over ~4 rounds (~2 s at the default heartbeat), enough to distinguish a grey
/// node's sustained drop rate from a single lost `Pong` without lagging a real onset.
pub(super) const LOSS_EWMA_ALPHA: f64 = 0.25;
/// §6.3 grey-localization tolerance, pinned by the simulator sweep
/// (`fanos-sim/tests/endpoint_attestation_research.rs`): the minimum by which a grey node's WORST incident
/// channel loss must exceed the cell's baseline (median channel loss) for `polar::grey_endpoint` to localize
/// it. A grey node's minimum incident loss runs above baseline (every channel degraded); an honest node's runs
/// below it (its worst channel is a good honest link), so `0.10` sits in a wide separation.
const GREY_TOL: f64 = 0.10;

/// DoS backstops on the DHT slice (audit A4). The distributed store and the in-flight-read table both
/// accept adversary-supplied keys, so without a cap a peer that floods `Publish`/`Get` with distinct
/// digests exhausts memory. These are *safety* ceilings far above any legitimate working set — a
/// reference node holding real application data never approaches them — chosen to bound worst-case
/// memory (`MAX_STORE_ENTRIES × MAX_VALUE_LEN` ≈ 256 MiB, `MAX_PENDING_GETS × PendingGet` ≈ a few MiB),
/// not to constrain honest use. When full, a *new* key is refused rather than an existing one evicted,
/// so an attacker cannot displace already-stored replicas (LRC availability is preserved); overwriting
/// an existing key is always allowed (it does not grow the map).
pub(crate) const MAX_STORE_ENTRIES: usize = 4096;
/// The largest value the store will hold, in bytes — bounds per-entry memory and rejects amplification.
pub(crate) const MAX_VALUE_LEN: usize = 65_536;
/// The most concurrent in-flight `Get`s tracked at once; further reads are refused until some resolve.
pub(super) const MAX_PENDING_GETS: usize = 1024;
/// The most distinct shard-versions a single in-flight read accumulates before evicting the lowest (#115
/// Phase B). A read groups gathered shards by their write-version and reconstructs the highest recoverable
/// one (last-writer-wins); honestly there are only a handful in flight (the cell converges to one version),
/// so this bounds a Byzantine peer that sprays fabricated versions to grow the accumulator (A4 DoS).
pub(super) const MAX_READ_VERSIONS: usize = 8;
/// How many distinct Fano lines a [`Command::SampleAvailability`] probes (spec §L4.3). `3` gives an
/// independent-sampling false-available bound of `(1/7)³ ≈ 0.3%`, and — since `≥2` distinct passing samples
/// certify availability against any withholding adversary (`fanos_code::da`) — a comfortable margin.
pub(super) const DA_SAMPLES: usize = 3;

/// How long a locally-distrusted (Byzantine) member stays quarantined before it is re-admitted for
/// re-evaluation. Quarantine is an *operational* safeguard, not a proven permanent exclusion (spec §6.2):
/// permanently exiling a member would strand one that only glitched transiently. After this window the
/// member is re-admitted; if it is still structurally inconsistent the next diagnosis re-quarantines it
/// (the polar sum-rules re-catch it), and the authoritative clear remains the parent's re-provisioning
/// (escalation). Bounded, so `quarantined` cannot grow without limit either (audit C5).
pub const QUARANTINE_TTL: Duration = Duration::from_millis(60_000);

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

/// A key's held erasure shards at this node: Fano point index → (write-version, shard bytes) — §L4.
pub(crate) type HeldShards = BTreeMap<u8, (u64, Vec<u8>)>;
/// A [`erasure::reconstruct`]-shaped accumulator: one optional shard per Fano point.
type ShardAccumulator = [Option<Vec<u8>>; erasure::N];
/// Shards gathered during a read, grouped by their write-version (highest recoverable one wins).
pub(crate) type VersionedShards = BTreeMap<u64, ShardAccumulator>;





/// Reconstruct the **highest** write-version whose gathered shard-set is recoverable (spec §L4
/// last-writer-wins): iterate versions descending, returning the first that [`erasure::reconstruct`]s — so a
/// stale version that happens to complete first can never mask a fresher one, and mixed-version shards are
/// never combined into one (garbage) value. `None` until some version's set is recoverable.
pub(super) fn reconstruct_highest(by_version: &VersionedShards) -> Option<Vec<u8>> {
    by_version.values().rev().find_map(erasure::reconstruct)
}

















/// *ideally* lives, before the cell's actual occupancy is consulted. It is a distinct type from a node
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
pub(super) struct ContentPoint<F: Field>(Point<F>);

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
    /// The explicit 7-member cell this node self-diagnoses with, when it is **not** the base plane's
    /// points `0..6` — i.e. a 7-node Fano cell embedded in a larger transport plane (a unified
    /// hierarchy). `None` on the base cell, where cell position `i` is `Point::at(i)`; `Some(members)`
    /// remaps position `i` to `members[i]`, so the whole index-addressed reflex runs unchanged over a
    /// cell seated anywhere. See [`cell_coord`](Self::cell_coord) / [`with_cell_members`](Self::with_cell_members).
    cell_members: Option<[Triple; 7]>,
    /// The **parent-stratum reflex** (audit R-C2): when a child cell escalates its irrecoverable residue to
    /// this cell, its members fold the failure into a [`ParentCell`] — the same reflexive Fano decoder one
    /// tier up — and coarse-reroute around the failed child. `None` until this node first receives a child
    /// escalation; `Some(ParentCell::new(self_index))` thereafter, accumulating each child's summary.
    parent_cell: Option<ParentCell>,
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
    /// §6.3 grey detection: the freshest `DiagLoss` row each cell member gossiped — its measured per-neighbour
    /// loss vector (`[u8; 7]`, `loss × 255`) and when it arrived. Assembled with this node's own row into the
    /// symmetric channel-rate matrix `polar::grey_endpoint` localizes a grey node from (a lossy node lifts
    /// every channel incident to it). Bounded by the cell size.
    loss_reports: BTreeMap<Triple, ([u8; 7], Instant)>,
    /// Dedup for the grey diagnosis: the grey node currently reported, so `Notification::Grey` fires once on
    /// onset (and again only if a *different* node goes grey), cleared when the cell reads grey-free.
    grey_reported: Option<Triple>,
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
pub(super) fn cell_id<F: Field>() -> CellId {
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
pub(crate) fn polar_gap_from_liveness(degraded: u8) -> f64 {
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

/// The most admission work this engine will do **inline**, in proof-of-work bits.
///
/// Derived from the engine's own cadence rather than chosen: a solve blocks the step it happens in, so it must
/// finish well inside one observation window. At roughly `10^7` hashes a second a 500 ms window is about `2^22`;
/// 20 bits (~`10^6` hashes, ~0.1 s) leaves the margin that keeps a slow host from stalling its cell to pay an
/// entry fee.
///
/// Past this the refusal is reported and nothing is spent. That is the boundary between a defence and a remote
/// CPU-exhaustion primitive: without it, any peer could name a number and make honest nodes grind instead of run.
pub const MAX_INLINE_ADMISSION_BITS: u32 = 20;

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
                        loss: 0.0,
                        awaiting_pong: false,
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
            cell_members: None,
            parent_cell: None,
            healer: Healer::new(observer),
            witnessed: BTreeMap::new(),
            loss_reports: BTreeMap::new(),
            grey_reported: None,
            store: Store::default(),
            epoch: Epoch::ZERO,
        }
    }

    /// The node's cell neighbour coordinates (its quorum members).
    pub fn neighbours(&self) -> impl Iterator<Item = Triple> + '_ {
        self.peers.keys().copied()
    }

    /// The transport coordinate of cell position `i` (`0..7`): the explicit [`cell_members`](Self::with_cell_members)
    /// entry when this node is a cell embedded in a larger plane, else the base plane's `Point::at(i)`. This is
    /// the single indirection the index-addressed reflex routes through, so a cell runs identically wherever it
    /// is seated.
    fn cell_coord(&self, i: usize) -> Triple {
        self.cell_members
            .as_ref()
            .and_then(|members| members.get(i).copied())
            .unwrap_or_else(|| Point::<F>::at(i).coords())
    }

    /// The cell position (`0..7`) of transport coordinate `coord`, if it is a member of this cell — the
    /// inverse of [`cell_coord`](Self::cell_coord), used to fold gossiped rows back onto cell positions.
    fn cell_position(&self, coord: Triple) -> Option<usize> {
        match &self.cell_members {
            Some(members) => members.iter().position(|&m| m == coord),
            None => (0..7usize).find(|&i| Point::<F>::at(i).coords() == coord),
        }
    }

    /// Seat this node in an explicit 7-node Fano cell (`members`, in canonical position order) rather than the
    /// base plane's points `0..6` — for a cell embedded in a larger transport plane (a unified hierarchy). Sets
    /// the reflexive `self_index` to this node's position and rebuilds the cell peer set from the six other
    /// members, so liveness sensing, witnessing, and the whole reflex run over the real cell.
    #[must_use]
    pub fn with_cell_members(mut self, members: [Triple; 7]) -> Self {
        self.self_index = members.iter().position(|&m| m == self.coord.coords());
        self.peers.clear();
        for &m in &members {
            if m != self.coord.coords() {
                self.peers.entry(m).or_insert(Peer {
                    last_seen: None,
                    reported_down: false,
                    loss: 0.0,
                    awaiting_pong: false,
                });
            }
        }
        self.healer.cell_members = Some(members); // the reflex actuates on the real member coords too
        self.cell_members = Some(members);
        self
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
                    peer.awaiting_pong = false; // this round's ping was answered — a loss-sample "hit" (§6.3)
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
            Some(FrameType::App) => {
                // An App-overlay frame (0x70, spec §7.2): the receive seam for an application protocol driven
                // as a side-car on the overlay — today the TAXIS consensus engine (`fanos_taxis::wire`). Like a
                // Route delivery it is direct evidence of the sender's liveness and counts as behavioural load;
                // the raw body is surfaced as `Notification::App` for the app engine to decode and step. A frame
                // for an app this node does not run is inert — the driver simply has no consumer for it.
                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.last_seen = Some(now);
                    peer.reported_down = false;
                }
                self.healer.record_relay(from);
                alloc::vec![Effect::Notify(Notification::App {
                    from,
                    body: frame.body.to_vec(),
                })]
            }
            Some(FrameType::RouteHier) => self.on_route_hier(from, frame.body),
            Some(FrameType::CellEscalate) => self.on_cell_escalate(frame.body),
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
            Some(FrameType::DiagLoss) => {
                // The sender's measured per-neighbour loss row (spec §6.3 grey); stored for the grey-detection
                // matrix. Also a direct observation of the sender's liveness, like the other diagnostics.
                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.last_seen = Some(now);
                    peer.reported_down = false;
                }
                self.apply_diag_loss(now, from, frame.body);
                Vec::new()
            }
            Some(FrameType::Publish) => self.on_publish(now, from, frame.body),
            Some(FrameType::Lookup) => self.on_lookup(from, frame.body),
            Some(FrameType::Value) => self.on_value(now, frame.body),
            Some(FrameType::Ack) => Self::on_ack(frame.body),
            Some(FrameType::Announce) => self.on_announce(frame.body),
            Some(FrameType::EpochAgree) => self.on_epoch_agree(frame.body),
            Some(FrameType::RdvReply) => {
                // A rendezvous relay forwarded a peeled anonymous reply to us (audit #54, item 3): this
                // node is the registered client for the session cookie the reply carries. Surface it as an
                // anonymous delivery — identical to a reply we would have peeled ourselves had we been the
                // reply combiner — so the anonymous-session bridge consumes both paths uniformly. `from` is
                // the anonymous sentinel [0, 0, 0], never the relay, so no consumer learns which relay
                // carried it. The 16-byte cookie prefix stays on the payload; the session bridge strips it.
                // A forged RdvReply is inert: the inner bytes are an authenticated DIAULOS cell, so a wrong
                // or replayed one fails the session MAC and is dropped there.
                alloc::vec![Effect::Notify(Notification::Delivered {
                    from: [0, 0, 0],
                    payload: frame.body.to_vec(),
                })]
            }
            // A peer refused something we sent. Only admission refusals are actionable — the rest are
            // diagnostics for a log, and the engine has nowhere to write. Surfacing this one is what makes an
            // *adaptive* admission price safe to run at all: without it, a joiner priced out between minting its
            // proof and presenting it is refused forever with no way to learn the number that would work.
            Some(FrameType::Error) => self.on_error(frame.body),
            _ => Vec::new(),
        }
    }

    /// Decode an `Error` frame, act on the one kind a node can act on, and surface it either way.
    ///
    /// A refusal that names a price this node can afford is repaid **here**: the admission difficulty is raised
    /// and the proof re-minted, exactly as [`on_reseat`](Self::reseat) already does when the coordinate moves.
    /// Above [`MAX_INLINE_ADMISSION_BITS`] it is only reported, because the work would block the engine.
    fn on_error(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some(err) = crate::frames::parse_error(body) else { return Vec::new() };
        if err.code != fanos_wire::ProtocolError::SybilReject.code() {
            return Vec::new();
        }
        let required = crate::frames::decode_required_difficulty(&err.reason);
        if let Some(bits) = required {
            self.repay_admission(bits);
        }
        alloc::vec![Effect::Notify(Notification::AdmissionRefused { required })]
    }

    /// Re-mint this node's admission proof at `required`, if that is a price worth and safe to pay here.
    ///
    /// Three guards, and each answers a way this could be turned against the node that is trying to join:
    ///
    /// * **Never below what we already pay.** A peer claiming a *lower* difficulty cannot talk this node into
    ///   weakening a proof its own operator configured.
    /// * **Never above [`MAX_INLINE_ADMISSION_BITS`].** "Solve harder" on demand is otherwise a remote
    ///   CPU-exhaustion primitive aimed at honest joiners: a hostile peer names a huge number and the engine
    ///   grinds instead of running the cell. Past the bound the refusal is reported and nothing is spent.
    /// * **Monotone, so repetition is free.** A proof at difficulty `d` satisfies every requirement `≤ d`
    ///   (`admission::a_solution_for_high_difficulty_also_satisfies_lower_thresholds`), so one solve serves
    ///   every peer, and a crowd of peers all demanding the maximum costs exactly one solve rather than one
    ///   each.
    fn repay_admission(&mut self, required: u32) {
        let current = self.membership.admission_difficulty.unwrap_or(0);
        if required <= current || required > MAX_INLINE_ADMISSION_BITS {
            return;
        }
        let coord = self.coord.coords();
        self.membership.admission_difficulty = Some(required);
        self.membership.admission_proof = PowAdmission::new(required)
            .solve(&admission_challenge(&self.membership.identity, coord, self.epoch));
    }

    /// Demand `difficulty` of joiners **without** solving it ourselves — for tests only.
    ///
    /// `with_admission_pow` couples two separate things: the price this node demands of others, and the proof
    /// it mints for itself. A test that wants a strict gate should not have to pay for one, and paying turned a
    /// scenario test into a 48-second one.
    #[cfg(test)]
    pub(crate) fn demanding_for_test(mut self, difficulty: u32) -> Self {
        self.config.require_admission = true;
        self.membership.admission_policy = Some(Box::new(PowAdmission::new(difficulty)));
        self
    }

    /// This node's current admission proof — for tests that assert it was (or was not) re-minted.
    #[cfg(test)]
    pub(crate) fn admission_proof_for_test(&self) -> &[u8] {
        &self.membership.admission_proof
    }

    /// The difficulty this node currently pays — for tests that assert it did (or did not) move.
    #[cfg(test)]
    pub(crate) fn admission_difficulty_for_test(&self) -> Option<u32> {
        self.membership.admission_difficulty
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

    /// Enable **PoW Sybil admission** at `difficulty` in one call (spec §L3): install a [`PowAdmission`]
    /// policy to verify *others*, `require` admission of peers, solve this node's OWN genesis proof for
    /// `(coordinate, epoch 0)`, and remember the difficulty so the proof is **re-solved on every reshuffle**
    /// ([`on_reseat`](Self::on_reseat)) — keeping it valid for a peer's per-epoch check as the coordinate
    /// rotates, which is the "re-paid every epoch" cost that makes a grinded seat un-maintainable. This is
    /// the complete "join under a per-admission cost" setup; a deployment picks `difficulty` to price a join
    /// at ~`2^difficulty` hashes. Prefer this to wiring [`with_admission_policy`](Self::with_admission_policy)
    /// + [`with_admission_proof`](Self::with_admission_proof) by hand when the policy is PoW.
    #[must_use]
    pub fn with_admission_pow(mut self, difficulty: u32) -> Self {
        self.config.require_admission = true;
        self.membership.admission_difficulty = Some(difficulty);
        // **Adaptive, not fixed.** `difficulty` becomes the floor an operator guarantees, and the coherence
        // controller may raise the live price above it as the cell's measured stress rises — the only response
        // FANOS has that acts on the *magnitude* of a flood rather than on its aftermath (T-104: a cell
        // survives iff `‖h‖ < κ·r_stab`, and everything else moves `κ`). It can never go under the floor, so a
        // stuck sensor or a compromised controller cannot open a door the operator closed.
        //
        // At rest the live value equals the floor, so a node that is not under stress behaves exactly as the
        // fixed gate did.
        let live = LiveDifficulty::new(difficulty);
        self.membership.admission_policy =
            Some(Box::new(AdaptivePowAdmission::new(difficulty, live.clone())));
        self.healer.set_admission(difficulty, live);
        self.membership.admission_proof =
            PowAdmission::new(difficulty).solve(&admission_challenge(&self.membership.identity, self.coord.coords(), self.epoch));
        self
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







































    /// The current beacon epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The durable **loss ledger** (audit R-C3): the digests this node has accounted permanently lost — a
    /// held key whose live shard-homes can no longer reconstruct it — each with the epoch it was accounted.
    /// Empty in a healthy cell; a non-empty ledger is visible, auditable evidence of data that fell past the
    /// erasure tolerance, rather than the silent `Retrieved(None)` miss it used to be indistinguishable from.
    #[must_use]
    pub fn lost_keys(&self) -> Vec<([u8; DIGEST], Epoch)> {
        self.store.loss_ledger.iter().map(|(k, e)| (*k, *e)).collect()
    }

    /// This node's cell-liveness view (base Fano cell only): `(self_index, degraded_mask,
    /// alive_count)`. Bit `i` of the mask is set when point `i` is not corroborated-alive. `None`
    /// off the base `N = 7` cell, where the index-addressed syndrome geometry does not apply.
    fn cell_liveness(&self, now: Instant) -> Option<(usize, u8, usize)> {
        let self_index = self.self_index?;
        let own = self.coord.coords();
        let mut degraded = 0u8;
        let mut alive_count = 1usize; // self is alive
        for i in 0..7usize {
            let coord = self.cell_coord(i); // base cell: Point::at(i); embedded cell: members[i]
            if coord == own {
                continue;
            }
            if self.coord_alive(coord, now) {
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

    /// This node's OWN direct-observation liveness fresh-mask (bit `k` ⇔ it has heard Fano point `k` within
    /// `liveness_timeout`; self is always fresh) — byte-identical to what its [`health_view`](Self::health_view)
    /// gossip encodes. Used both as the (guaranteed-honest) judge's own witness row in the §6.4 endpoint
    /// cross-attestation and, complemented, as the set of subjects it may adjudicate (a node it directly sees
    /// alive is never cross-examined).
    fn own_fresh_mask(&self, now: Instant) -> u8 {
        let timeout = self.config.liveness_timeout;
        let self_c = self.coord.coords();
        let mut mask = 0u8;
        for k in 0..7usize {
            let coord = self.cell_coord(k);
            let fresh = coord == self_c
                || self
                    .peers
                    .get(&coord)
                    .and_then(|p| p.last_seen)
                    .is_some_and(|seen| now.since(seen) <= timeout);
            if fresh {
                mask |= 1u8 << k;
            }
        }
        mask
    }

    /// Reconstruct this round's per-witness liveness fresh-masks for the §6.4 endpoint cross-attestation
    /// (#106): entry `w` (a Fano point index) is `Some(mask)` with bit `k` set ⇔ witness `w` vouches a fresh
    /// (within `liveness_timeout`) observation of point `k`, or `None` if `w` has vouched nothing this window
    /// (absent — excluded from the consensus). Peer rows come from the corroborated `witnessed` gossip
    /// substrate (folded from each member's `DiagGossip`); this node's own row is its direct view
    /// ([`own_fresh_mask`](Self::own_fresh_mask)), so the honest judge itself counts toward the firm consensus,
    /// restoring the full 3-colluder tolerance.
    fn endpoint_round_mask(&self, now: Instant) -> [Option<u8>; 7] {
        let timeout = self.config.liveness_timeout;
        let self_c = self.coord.coords();
        core::array::from_fn(|w| {
            let witness_c = self.cell_coord(w);
            if witness_c == self_c {
                return Some(self.own_fresh_mask(now));
            }
            let mut mask = 0u8;
            let mut present = false;
            for k in 0..7usize {
                let subject_c = self.cell_coord(k);
                if let Some(seen) = self
                    .witnessed
                    .get(&subject_c)
                    .and_then(|m| m.get(&witness_c))
                    && now.since(*seen) <= timeout
                {
                    mask |= 1u8 << k;
                    present = true;
                }
            }
            present.then_some(mask)
        })
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
        // §6.5 partition sensor: the loss-derived healthy-line mask (independent of node liveness). `diagnose`
        // consults it only in the all-alive branch and behind a persistence dwell, so this is safe to pass
        // every round.
        let healthy_lines = self.partition_healthy_lines(now);
        let mut effects = self.healer.diagnose::<F>(
            now,
            self_index,
            degraded,
            alive_count,
            Some(healthy_lines),
            &self.config,
            self.epoch,
        );
        // R-C2: the Healer raises the `Escalated` NOTIFICATION but has no router — the facade (which owns the
        // hierarchical address) transports the residue up to the parent cell's sibling members, where it folds
        // into their `ParentCell` reflex. Origination lives here so a driver on any transport gets it.
        let escalations: Vec<u8> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Notify(Notification::Escalated(mask)) => Some(*mask),
                _ => None,
            })
            .collect();
        for mask in escalations {
            effects.extend(self.escalate_to_parent(mask));
        }
        // §6.4 endpoint cross-attestation (#106): fold this round's per-witness liveness fresh-masks —
        // reconstructed from the corroborated `witnessed` gossip substrate plus this node's own direct view —
        // into the Healer's window, and quarantine any colluding vouch-fabricator keeping a corroborated-dead
        // node believed-alive (the fault the plain corroboration quorum cannot see). The judge adjudicates
        // only subjects it cannot itself directly confirm alive (`!own_fresh_mask`) — a node it can see is
        // never adjudicated, so an honest lone-observer is never quarantined (the safeguard the sim pinned).
        let round = self.endpoint_round_mask(now);
        let subjects = !self.own_fresh_mask(now) & 0x7F;
        effects.extend(self.healer.attest_endpoints::<F>(now, round, subjects));
        // §6.3 grey detection (#106): localize a grey node — heartbeat-present but lossy on every channel —
        // from the assembled measured-loss matrix, and report it (observability only; grey is degradation, not
        // a lie, so it is never quarantined). Deduped to fire once per grey episode.
        effects.extend(self.detect_grey(now));
        effects
    }

    /// The §6.5 healthy-line mask: bit `l` set ⇔ Fano line `l` carries live connectivity, i.e. its **worst**
    /// pairwise channel loss (from the measured [`grey_rate_matrix`](Self::grey_rate_matrix)) is below
    /// [`LINE_CUT_LOSS`]. A line is only as good as its worst channel, so a line whose crossing channel is
    /// cut/grey reads unhealthy even if its other channels are fine — exactly the signal an incipient split
    /// (a lossy line-cover, nodes alive) presents. Feeds `partition::is_connected` inside `diagnose`.
    fn partition_healthy_lines(&self, now: Instant) -> u8 {
        let loss = self.grey_rate_matrix(now);
        let at = |a: usize, b: usize| loss.get(a).and_then(|r| r.get(b)).copied().unwrap_or(0.0);
        let mut healthy = 0u8;
        for l in 0..7usize {
            let Some(points) = fano::LINE_POINTS.get(l) else {
                continue;
            };
            let [a, b, c]: [usize; 3] =
                core::array::from_fn(|i| points.get(i).map_or(0, |&p| usize::from(p)));
            // The line's worst pairwise channel loss among its three points.
            let worst = at(a, b).max(at(a, c)).max(at(b, c));
            if worst < LINE_CUT_LOSS {
                healthy |= 1u8 << l;
            }
        }
        healthy
    }

    /// Assemble the symmetric measured-loss channel-rate matrix (§6.3): `rate[a][b] = max(a's loss toward b,
    /// b's loss toward a)` — a channel is only as good as its worst direction, so a grey node (lossy only
    /// *outbound*) still lifts every channel incident to it. Rows come from freshly-gossiped `DiagLoss`
    /// (`loss_reports`), plus this node's own directly-measured row (`peers[*].loss`).
    fn grey_rate_matrix(&self, now: Instant) -> [[f64; 7]; 7] {
        let timeout = self.config.liveness_timeout;
        let point_index = |c: &Triple| self.cell_position(*c);
        let mut directional = [[0.0f64; 7]; 7]; // directional[a][b] = a's loss toward b
        for (coord, (row, seen)) in &self.loss_reports {
            if now.since(*seen) <= timeout
                && let Some(a) = point_index(coord)
                && let Some(dst) = directional.get_mut(a)
            {
                for (cell, &byte) in dst.iter_mut().zip(row.iter()) {
                    *cell = f64::from(byte) / 255.0;
                }
            }
        }
        if let Some(me) = self.self_index
            && let Some(dst) = directional.get_mut(me)
        {
            for (b, cell) in dst.iter_mut().enumerate() {
                let coord = self.cell_coord(b);
                *cell = self.peers.get(&coord).map_or(0.0, |p| p.loss);
            }
        }
        let at = |a: usize, b: usize| {
            directional
                .get(a)
                .and_then(|r| r.get(b))
                .copied()
                .unwrap_or(0.0)
        };
        core::array::from_fn(|a| {
            core::array::from_fn(|b| if a == b { 0.0 } else { at(a, b).max(at(b, a)) })
        })
    }

    /// Localize a grey node from the measured-loss matrix ([`polar::grey_endpoint`]) and emit
    /// `Notification::Grey` on onset (deduped by [`grey_reported`](Self::grey_reported)); clears the latch when
    /// the cell reads grey-free. Base cell only — off it there is no index-addressed loss geometry.
    fn detect_grey(&mut self, now: Instant) -> Vec<Effect> {
        if self.self_index.is_none() {
            return Vec::new();
        }
        let matrix = self.grey_rate_matrix(now);
        let grey = polar::grey_endpoint(&matrix, GREY_TOL).map(|i| self.cell_coord(i));
        if grey == self.grey_reported {
            return Vec::new();
        }
        self.grey_reported = grey;
        grey.map(|g| alloc::vec![Effect::Notify(Notification::Grey(g))])
            .unwrap_or_default()
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
            // Raw-emit: put the frame on the wire verbatim (no `Route` wrapping) — an anonymous client
            // launching a threshold onion at a combiner or registering with a rendezvous relay (audit #54).
            Input::Command(Command::Emit { to, frame }) => alloc::vec![Effect::Send { to, frame }],
            Input::Command(Command::Diagnose) => self.on_diagnose(now),
            Input::Command(Command::Observe) => self.on_observe(now),
            Input::Command(Command::Put { key, value }) => self.on_put(now, &key, &value),
            Input::Command(Command::Get { key }) => self.on_get(now, &key),
            Input::Command(Command::SampleAvailability { key }) => self.on_sample(now, &key),
            Input::Command(Command::Join { info }) => self.on_join(info),
            // Audit R-M1: the driver re-applies distrust to the identity's *current* coordinate, and clears a tag whose
            // occupant has changed. The engine stays coordinate-keyed and crypto-free; the driver supplies the identity
            // binding it alone authenticated.
            Input::Command(Command::Quarantine { coord }) => {
                self.healer.quarantine(coord, now).into_iter().collect()
            }
            Input::Command(Command::Readmit { coord }) => {
                self.healer.readmit(coord);
                Vec::new()
            }
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

























/// The parsed pieces of an `Announce` body: `(coord, hier, id, sig, proof, info)` (see
/// [`parse_announce`]).
pub(crate) type ParsedAnnounce<F> = (Triple, HierAddr<F>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);









#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    // Codec helpers the tests build frames with; scoped here so the library build does not carry them.
    use crate::frames::{announce_body, encode_publish, encode_value};
    use super::*;
    use fanos_field::{F2, F7};

    #[test]
    fn a_refusal_that_names_an_affordable_price_is_repaid_on_the_spot() {
        // The point of carrying the price: a joiner one number away from admission repays it and re-announces,
        // instead of waiting for a human to notice.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default())
            .with_identity(alloc::vec![7u8; 8])
            .with_admission_pow(4);
        let before = node.admission_proof_for_test().to_vec();
        let refusal = crate::frames::encode_error_with(
            fanos_wire::ProtocolError::SybilReject,
            9u32.to_le_bytes().to_vec(),
        );
        node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: refusal });
        assert_ne!(node.admission_proof_for_test(), &before[..], "the proof was not re-minted at the new price");
        assert_eq!(node.admission_difficulty_for_test(), Some(9), "and the node now pays the price it was told");
    }

    #[test]
    fn a_peer_cannot_talk_a_node_into_paying_less() {
        // A hostile or broken peer naming a *lower* difficulty must not weaken a proof the operator configured.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default())
            .with_identity(alloc::vec![7u8; 8])
            .with_admission_pow(12);
        let refusal = crate::frames::encode_error_with(
            fanos_wire::ProtocolError::SybilReject,
            2u32.to_le_bytes().to_vec(),
        );
        node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: refusal });
        assert_eq!(node.admission_difficulty_for_test(), Some(12), "the node lowered its own admission cost");
    }

    #[test]
    fn an_extortionate_demand_is_reported_and_not_paid() {
        // The security boundary. "Solve harder" on demand, unbounded, is a remote CPU-exhaustion primitive
        // pointed at honest joiners: a peer names a huge number and the engine grinds instead of running its
        // cell. Past `MAX_INLINE_ADMISSION_BITS` the refusal is surfaced and nothing is spent.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default())
            .with_identity(alloc::vec![7u8; 8])
            .with_admission_pow(4);
        let refusal = crate::frames::encode_error_with(
            fanos_wire::ProtocolError::SybilReject,
            (MAX_INLINE_ADMISSION_BITS + 1).to_le_bytes().to_vec(),
        );
        let effects = node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: refusal });
        assert_eq!(node.admission_difficulty_for_test(), Some(4), "the engine paid an extortionate demand");
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::AdmissionRefused { .. }))),
            "and it must still be reported, so a driver or operator can decide"
        );
    }

    #[test]
    fn one_peer_pricing_a_joiner_out_does_not_exclude_it_from_the_cell() {
        // The answer to "what stops a node that mis-measures its stress from closing the network?" — and it is
        // a property of the shape rather than machinery added on top. Admission is decided by **each peer for
        // itself**: `members` is one node's own view, and `Announce` is flooded to all of them. So a peer whose
        // sensor is wrong, or that is simply hostile, shuts its own door and no one else's.
        //
        // That is why no cross-check between nodes was built for this. A quorum on the admission price would be
        // a new consensus to reach, a new thing to capture, and a new way for the cell to stall — to buy a
        // property the geometry already provides.
        /// The price the refusing peer demands — high enough that a cheap proof does not satisfy it by chance.
        const STRICT: u32 = 20;
        let identity = alloc::vec![3u8; 8];
        let joiner_coord = Point::<F2>::at(1).coords();
        let joiner = OverlayNode::<F2>::new(Point::at(1), Config::default())
            .with_identity(identity.clone())
            .with_admission_pow(4);
        let announce = encode(
            FrameType::Announce,
            &announce_body(
                joiner_coord,
                &joiner.router.address,
                &identity,
                &[],
                joiner.admission_proof_for_test(),
                &[1u8],
            ),
        );

        // One peer demands a price this joiner has not paid; the other demands exactly what it did.
        // Strict gate, cheap fixture: the refuser demands 20 bits without minting one itself. The premise is
        // asserted below rather than assumed — a 4-bit proof satisfies a 20-bit gate once in 2^16 draws, and a
        // test whose scenario silently evaporates is worse than one that fails loudly.
        let mut refuser = OverlayNode::<F2>::new(Point::at(2), Config::default())
            .with_identity(alloc::vec![9u8; 8])
            .with_admission_pow(4)
            .demanding_for_test(STRICT);
        let challenge = admission_challenge(&identity, joiner_coord, 0.into());
        assert!(
            !PowAdmission::new(STRICT).admits(&challenge, joiner.admission_proof_for_test()),
            "the cheap proof happened to satisfy the strict gate — re-run; there is nothing being tested here"
        );
        let mut admitter = OverlayNode::<F2>::new(Point::at(3), Config::default())
            .with_identity(alloc::vec![8u8; 8])
            .with_admission_pow(4);
        refuser.step(Instant(0), Input::Message { from: joiner_coord, frame: announce.clone() });
        admitter.step(Instant(0), Input::Message { from: joiner_coord, frame: announce });

        assert!(
            !refuser.members().any(|(c, _)| c == joiner_coord),
            "the refusing peer admitted a joiner that did not pay its price"
        );
        assert!(
            admitter.members().any(|(c, _)| c == joiner_coord),
            "one peer's refusal must not travel — the joiner paid this peer's price and belongs in its view"
        );
    }

    #[test]
    fn a_refused_join_surfaces_the_price_that_would_have_passed() {
        // The return path that makes an *adaptive* admission price safe to run. Without it a joiner priced out
        // between minting its proof and presenting it is refused permanently, with the number that would work
        // sitting unread in a frame nothing dispatched — the attacker's outcome, produced by the defence.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let refusal = crate::frames::encode_error_with(
            fanos_wire::ProtocolError::SybilReject,
            17u32.to_le_bytes().to_vec(),
        );
        let effects = node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: refusal });
        let told = effects.iter().find_map(|e| match e {
            Effect::Notify(Notification::AdmissionRefused { required }) => Some(*required),
            _ => None,
        });
        assert_eq!(told, Some(Some(17)), "the refusal must reach the node carrying its price: {effects:?}");
    }

    #[test]
    fn a_refusal_without_a_price_is_no_guidance_rather_than_zero() {
        // An older peer, or a policy where difficulty is not a number, says nothing. A driver that read that as
        // `0` would re-solve at zero against a gate demanding work — an infinite loop.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let refusal =
            crate::frames::encode_error_with(fanos_wire::ProtocolError::SybilReject, alloc::vec![]);
        let effects = node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: refusal });
        let told = effects.iter().find_map(|e| match e {
            Effect::Notify(Notification::AdmissionRefused { required }) => Some(*required),
            _ => None,
        });
        assert_eq!(told, Some(None), "a silent refusal must surface as `None`, never as a difficulty");
    }

    #[test]
    fn an_error_that_is_not_an_admission_refusal_is_not_surfaced() {
        // Only the actionable one. The rest are diagnostics, and this engine is sans-I/O — it has nowhere to
        // write a log and no business waking a driver for something it cannot act on.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let other =
            crate::frames::encode_error_with(fanos_wire::ProtocolError::Malformed, alloc::vec![]);
        let effects = node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: other });
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Notify(Notification::AdmissionRefused { .. }))),
            "an unrelated error must not read as an admission refusal"
        );
    }

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
    fn an_app_overlay_frame_surfaces_as_an_app_notification() {
        // The App-overlay (0x70) receive seam: an application frame (e.g. a TAXIS `ConsensusMsg`) delivered to
        // a node is surfaced verbatim as `Notification::App` for the app engine to decode — not dropped by the
        // catch-all, and distinct from a Route `Delivered`.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let from = Point::<F2>::at(1).coords();
        let frame = encode(FrameType::App, b"consensus-msg-bytes");
        let effects = node.step(Instant::default(), Input::Message { from, frame });
        assert!(
            effects.iter().any(|e| matches!(e,
                Effect::Notify(Notification::App { body, from: src })
                    if body == b"consensus-msg-bytes" && *src == from)),
            "an App frame is surfaced as Notification::App with its raw body and sender",
        );
        // It is NOT surfaced as a Route delivery (the two paths stay distinct).
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Delivered { .. }))),
            "an App frame is not a Route delivery",
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
    fn a_reshuffle_preserves_the_hierarchical_descent_chain() {
        // §L1/§95: an epoch reshuffle (`Command::Reseat`) moves only the level-0 VRF transport coordinate; the
        // deeper sub-cell levels are identity-hash-derived (epoch-stable), so a descended node keeps its
        // sub-cell placement. Before the fix, `on_reseat` reset the router to depth-1 `root(new_pt)`, silently
        // dropping the descent chain every epoch.
        let mut node = OverlayNode::<F2>::new(Point::at(3), Config::default())
            .with_hier_address(
                HierAddr::from_path(alloc::vec![Point::<F2>::at(3), Point::<F2>::at(5)]).unwrap(),
            );
        assert_eq!(node.hier_address().depth(), 2, "seated at a depth-2 address [3,5]");
        // Reshuffle the level-0 transport coordinate 3 → 1.
        node.step(
            Instant(0),
            Input::Command(Command::Reseat {
                coord: Point::<F2>::at(1).coords(),
            }),
        );
        assert_eq!(
            node.hier_address().points(),
            &[Point::<F2>::at(1), Point::<F2>::at(5)],
            "level 0 moved to the new coordinate; the deeper descent level 5 is preserved",
        );
        // The depth-1 case is unchanged: a plain node reseats to a plain `root(new)`.
        let mut plain = OverlayNode::<F2>::new(Point::at(0), Config::default());
        plain.step(
            Instant(0),
            Input::Command(Command::Reseat {
                coord: Point::<F2>::at(6).coords(),
            }),
        );
        assert_eq!(plain.hier_address().points(), &[Point::<F2>::at(6)]);
    }

    /// Decode a `CellEscalate` send into `(target, [child, residue, ttl])`, else `None`.
    fn cell_escalate(e: &Effect) -> Option<(Triple, [u8; 3])> {
        let Effect::Send { to, frame } = e else { return None };
        let (f, _) = decode_frame(frame).ok()?;
        if f.frame_type() != Some(FrameType::CellEscalate) {
            return None;
        }
        match f.body {
            [c, r, t] => Some((*to, [*c, *r, *t])),
            _ => None,
        }
    }

    #[test]
    fn a_sub_cell_escalation_is_transported_to_the_parent_cell_siblings() {
        // R-C2 origination: a node in a sub-cell (hier depth 2, at [3,5]) that exhausts its Φ-budget hands its
        // residue up — a CellEscalate to each of the parent (top) cell's OTHER points, tagged with the failed
        // child cell's root point (3). A depth-1 (top) cell has no parent, so its escalation is terminal.
        let mut sub = OverlayNode::<F2>::new(Point::at(3), Config::default()).with_hier_address(
            HierAddr::from_path(alloc::vec![Point::<F2>::at(3), Point::<F2>::at(5)]).unwrap(),
        );
        let effects = sub.escalate_to_parent(0b0110);
        let escalations: Vec<(Triple, [u8; 3])> = effects.iter().filter_map(cell_escalate).collect();
        // One escalation per parent-cell sibling (the six top points ≠ 3), each carrying child = 3 + the residue.
        assert_eq!(escalations.len(), 6, "one escalation per parent-cell sibling");
        for i in (0..7).filter(|&i| i != 3) {
            assert!(
                escalations.iter().any(|(to, _)| *to == Point::<F2>::at(i).coords()),
                "escalated to sibling point {i}"
            );
        }
        assert!(escalations.iter().all(|(_, body)| body[0] == 3 && body[1] == 0b0110), "child = 3, residue carried");

        // The top stratum has no parent — escalation is terminal (external help), nothing sent.
        let mut top = OverlayNode::<F2>::new(Point::at(0), Config::default());
        assert!(top.escalate_to_parent(0b0110).is_empty(), "a top-stratum cell escalates to no one");
    }

    #[test]
    fn a_parent_cell_member_absorbs_a_child_escalation_by_coarse_rerouting() {
        // R-C2 consumption: a top-cell node receiving a child escalation folds it into its ParentCell reflex
        // and, with a healthy coarse Φ-budget, reroutes around the failed child — the audit's "Escalated was
        // ACTED ON, not merely counted." (⌊log₉81⌋ = 2 affordable coarse hops.)
        let mut parent = OverlayNode::<F2>::new(Point::at(0), Config::default());
        parent.healer.last_phi = 81.0;
        let frame = encode(FrameType::CellEscalate, &[3u8, 0b0010, ESCALATE_TTL]);
        let effects = parent.step(Instant(0), Input::Message { from: [9, 9, 9], frame });
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Rerouted { around, .. }) if *around == Point::<F2>::at(3).coords())),
            "the parent tier reroutes around the failed child cell: {effects:?}"
        );
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Repaired(c)) if *c == Point::<F2>::at(3).coords())),
            "and marks the child repaired at the coarse tier"
        );
    }

    #[test]
    fn a_budgetless_top_parent_escalation_is_terminal() {
        // With no coarse budget (Φ = 1 ⇒ ⌊log₉1⌋ = 0) and no grandparent, a top-cell parent cannot absorb the
        // child escalation → it emits a terminal `Escalated` (external help), and does NOT reroute.
        let mut parent = OverlayNode::<F2>::new(Point::at(0), Config::default()); // last_phi defaults to 1.0
        let frame = encode(FrameType::CellEscalate, &[3u8, 0b0010, ESCALATE_TTL]);
        let effects = parent.step(Instant(0), Input::Message { from: [9, 9, 9], frame });
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Escalated(_)))),
            "a top parent with no budget escalates terminally: {effects:?}"
        );
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Rerouted { .. }))),
            "and does not reroute what it cannot afford"
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
        let mut losses = 0;
        for e in &effects {
            if let Effect::Send { frame, .. } = e {
                match decode_frame(frame).unwrap().0.frame_type() {
                    Some(FrameType::Ping) => pings += 1,
                    Some(FrameType::DiagGossip) => gossips += 1,
                    Some(FrameType::DiagAttest) => attests += 1,
                    Some(FrameType::DiagLoss) => losses += 1,
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
        assert_eq!(
            losses, 6,
            "gossips its measured loss vector to all 6 neighbours (§6.3)"
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
    fn a_node_senses_the_whole_cell_load_and_its_projective_balance_target_is_uniform() {
        // §6.7 grounding: because a node's q+1 lines COVER the plane (Aut(PG(2,q)) 2-transitivity), ONE node
        // observes every point's relay load. Inject a known hotspot (point 3 flooded, a differential-DDoS
        // target) in one window; after the heartbeat folds the behavioural sample, the node's sensed load
        // vector matches the injection exactly, and the DERIVED response `balance_exact(loads)` is the exact
        // uniform mean at every point — the hotspot dissolved into the whole cell with no local extremum.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let mut t = 1u64;
        for (i, count) in [(1, 1), (2, 1), (3, 20), (4, 1), (5, 1), (6, 1)] {
            let from = Point::<F2>::at(i).coords();
            for _ in 0..count {
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
        node.step(Instant(t), Input::Timer(HEARTBEAT)); // folds the window into `last_sample`

        let loads = node.healer.last_sample;
        assert!(
            (loads[3] - 20.0).abs() < 1e-9,
            "the flood on point 3 is sensed from one node"
        );
        assert!(
            (loads[1] - 1.0).abs() < 1e-9,
            "an idle peer's load is sensed too"
        );
        assert!(loads[0].abs() < 1e-9, "self (point 0) originated nothing");
        // The derived projective response: the exact global mean at every point (finite-time consensus).
        let mean = loads.iter().sum::<f64>() / 7.0;
        for (i, &x) in fanos_diakrisis::loadbalance::balance_exact(&loads)
            .iter()
            .enumerate()
        {
            assert!(
                (x - mean).abs() < 1e-9,
                "point {i}: the hotspot is balanced to the uniform mean {mean}, got {x}"
            );
        }
    }

    #[test]
    fn a_differential_flood_drives_the_under_coupled_band_and_emits_a_rebalance_prescription() {
        // §6.7 live wiring: a DIFFERENTIAL flood — each node relaying an INDEPENDENT amount, the opposite of
        // the common-mode lockstep that over-couples — decorrelates the measured Γ_net below r*, so the
        // homeostat enters the under-coupled `Aggregate`/`Bind` band. The engine then publishes the
        // projective load-balance prescription (`Notification::Rebalance`) once on entry: §6.7 made live.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let mut t = 1u64;
        let mut rebalanced = false;
        // Distinct per-node multipliers ⇒ mutually uncorrelated relay-activity series (decorrelated cell).
        let mult = [0u64, 2, 3, 5, 7, 11, 13];
        for w in 0..(BEHAVIOR_WINDOW + 6) {
            for (i, &m) in mult.iter().enumerate().skip(1) {
                let from = Point::<F2>::at(i).coords();
                let count = 1 + (w as u64 * m) % 9; // an independent sequence per node
                for _ in 0..count {
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
            let hb = node.step(Instant(t), Input::Timer(HEARTBEAT));
            if hb
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Rebalance { .. })))
            {
                rebalanced = true;
            }
            t += 1;
        }
        assert!(
            rebalanced,
            "a sustained differential flood decorrelates the cell into the under-coupled Bind band, so the \
             live homeostat emits the §6.7 projective load-balance prescription"
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
        let base = node
            .healer
            .effective_correlation(Config::default().healthy_correlation); // healthy_correlation, before any shed
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
            node.healer
                .effective_correlation(Config::default().healthy_correlation)
                < base - 1e-9,
            "the effective correlation is genuinely lowered — Φ headroom restored, not a no-op"
        );
        // The mutable factor really is what scales the correlation (the feedback into Φ).
        assert!(
            (node
                .healer
                .effective_correlation(Config::default().healthy_correlation)
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
            let frame = encode_publish(PUBLISH_SHARD, 0, 1, &flood_digest(i), b"v");
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
                frame: encode_publish(PUBLISH_SHARD, 0, 1, &digest, &too_big),
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
                frame: encode_publish(PUBLISH_SHARD, 0, 1, &digest, &at_limit),
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
            let frame = encode_publish(PUBLISH_SHARD, 0, 1, &flood_digest(i), b"a");
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
                frame: encode_publish(PUBLISH_SHARD, 0, 1, &existing, b"updated"),
            },
        );
        assert_eq!(
            node.store
                .entries
                .get(&existing)
                .and_then(|shards| shards.get(&0))
                .map(|(_version, shard)| shard.as_slice()),
            Some(&b"updated"[..]),
            "an existing key's shard still updates when the store is full"
        );
        // A brand-new key is refused, and the cap is never exceeded.
        node.step(
            Instant(1),
            Input::Message {
                from,
                frame: encode_publish(PUBLISH_SHARD, 0, 1, &[0xABu8; DIGEST], b"x"),
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
        // C4. A `Value` shard correlates on the read's per-request nonce, not just the key. A shard with no
        // in-flight read, or a stale/replayed one from a superseded prior get (old nonce), is ignored — so it
        // is never accumulated and can never resolve a later same-key get with an old value.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let key = b"k";
        let (digest, _) = OverlayNode::<F2>::address_of(key);
        let peer = Point::<F2>::at(1).coords();
        let has_retrieved = |effects: &[Effect]| {
            effects
                .iter()
                .any(|e| matches!(e, Effect::Notify(Notification::Retrieved { .. })))
        };
        // Real erasure shards of a known value — the only bytes that actually reconstruct. Feed the whole
        // set (all 7 point-shards) at a given nonce, collecting the effects.
        let shards = erasure::encode(b"the-fresh-value");
        let feed = |node: &mut OverlayNode<F2>, t: u64, nonce: u64| -> Vec<Effect> {
            let mut out = Vec::new();
            for (i, shard) in shards.iter().enumerate() {
                out.extend(node.step(
                    Instant(t),
                    Input::Message {
                        from: peer,
                        frame: encode_value(
                            &digest,
                            true,
                            u8::try_from(i).unwrap(),
                            1,
                            shard,
                            nonce,
                        ),
                    },
                ));
            }
            out
        };

        // A full shard-set with NO in-flight read is ignored (no spurious Retrieved).
        let stray = feed(&mut node, 1, 999);
        assert!(
            !has_retrieved(&stray),
            "shards with no in-flight read emit no Retrieved"
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

        // A delayed full shard-set from read #1 (old nonce 1) must be ignored — it never resolves read #2.
        let stale = feed(&mut node, 4, 1);
        assert!(
            !has_retrieved(&stale),
            "a stale shard-set (old nonce) does not resolve the newer read"
        );

        // The shard-set matching the in-flight nonce (2) reconstructs and resolves the read.
        let fresh = feed(&mut node, 5, 2);
        assert!(
            fresh.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Retrieved { key: k, value: Some(v) })
                    if *k == digest && v.as_slice() == b"the-fresh-value"
            )),
            "the shard-set matching the in-flight nonce reconstructs and resolves the read"
        );
    }

    #[test]
    fn an_admission_proof_is_bound_to_the_identity_that_solved_it() {
        // Found by probing the rank rule adversarially rather than by review. The challenge used to be `(coord, epoch)`
        // alone, so a solved proof was **replayable by any identity claiming that point** — an attacker could present the
        // incumbent's own proof and pay nothing. Combined with identity grinding (measured at ~20 draws to collide with a
        // chosen victim at a lower rank, `fanos-vrf/examples/grind_probe.rs`), that made eviction cost zero work.
        let coord = Point::<F2>::at(3).coords();
        let epoch = Epoch::new(4);
        let mine = admission_challenge(b"identity-A", coord, epoch);
        let theirs = admission_challenge(b"identity-B", coord, epoch);
        assert_ne!(mine, theirs, "same point, same epoch, different identity ⇒ different challenge");

        // A proof solved for one identity does not admit another.
        let policy = PowAdmission::new(8);
        let proof = policy.solve(&mine);
        assert!(policy.admits(&mine, &proof), "it admits the identity that solved it");
        assert!(!policy.admits(&theirs, &proof), "and is worthless to anyone else at the same point");

        // The pre-existing bindings still hold: a different point or epoch is still a different challenge.
        assert_ne!(mine, admission_challenge(b"identity-A", Point::<F2>::at(4).coords(), epoch));
        assert_ne!(mine, admission_challenge(b"identity-A", coord, Epoch::new(5)));
    }

    #[test]
    fn a_reshuffled_identity_neither_sheds_its_quarantine_nor_bequeaths_it() {
        // Audit R-M1, both directions. A quarantine tag belongs to an IDENTITY, but the engine can only drop by
        // coordinate — and a coordinate is a per-epoch VRF placement. So the driver, which alone authenticated the
        // identity↔coordinate binding, keeps distrust by identity and uses these two commands to keep the engine's
        // coordinate-keyed view honest across a move.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let old = Point::<F2>::at(1).coords();
        let new_coord = Point::<F2>::at(2).coords();
        let t0 = Instant(0);

        // The engine quarantines the peer at `old` (whatever the local verdict was).
        node.step(t0, Input::Command(Command::Quarantine { coord: old }));
        assert!(node.healer.is_quarantined(old, t0), "the tag lands");

        // DIRECTION 1 — the Byzantine identity reshuffles to a new coordinate. Without the driver re-applying, it
        // would arrive clean: the tag is on a point it no longer occupies. With it, distrust follows the identity.
        node.step(t0, Input::Command(Command::Quarantine { coord: new_coord }));
        assert!(node.healer.is_quarantined(new_coord, t0), "distrust follows the identity to its new point");

        // DIRECTION 2 — and the worse one. An *innocent* identity now lands on the vacated `old`. Left alone it would
        // inherit a verdict it never earned, which is a live denial-of-service against an honest node by nothing more
        // than the epoch turning. The driver clears the stale tag when the occupant changes.
        node.step(t0, Input::Command(Command::Readmit { coord: old }));
        assert!(!node.healer.is_quarantined(old, t0), "the arriving identity does not inherit its predecessor's tag");
        assert!(node.healer.is_quarantined(new_coord, t0), "and clearing one point does not clear the other");
    }

    #[test]
    fn re_admission_is_silent_because_it_is_the_absence_of_a_verdict() {
        // Quarantining announces a new distrust; re-admitting announces nothing. A `Notification::Quarantined` is a
        // claim about a peer, and its withdrawal is not a counter-claim — it is the tag ceasing to apply, which no
        // observer needs told.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let c = Point::<F2>::at(3).coords();
        let effects = node.step(Instant(0), Input::Command(Command::Quarantine { coord: c }));
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Quarantined(t)) if t == &c)),
            "a new distrust is announced"
        );
        // Idempotent: re-issuing the same tag is not a second verdict.
        let again = node.step(Instant(0), Input::Command(Command::Quarantine { coord: c }));
        assert!(!again.iter().any(|e| matches!(e, Effect::Notify(Notification::Quarantined(_)))));

        let cleared = node.step(Instant(0), Input::Command(Command::Readmit { coord: c }));
        assert!(cleared.is_empty(), "re-admission emits nothing");
        assert!(!node.healer.is_quarantined(c, Instant(0)));
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
