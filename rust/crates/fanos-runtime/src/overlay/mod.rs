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

use fanos_code::{da, erasure, lrc};
use fanos_core::{AdmissionPolicy, ParentCell, PowAdmission};
use fanos_diakrisis::polar;
use fanos_diakrisis::regeneration::spectral_gap;
use fanos_field::Field;
use fanos_geometry::{HierAddr, Plane, Point, Triple, fano};
use fanos_primitives::{Epoch, hash_labeled, storage_digest, storage_point};
use fanos_telemetry::{CellId, HistoryConfig, SelfObserver};
use fanos_wire::{FrameType, ProtocolError, Wire, decode_frame};


/// Hierarchical addressing, routing and escalation — see [`hier`].
mod hier;

/// Storage `Publish` sub-type: the **full value**, sent origin → responsible node, which then
/// erasure-codes it and distributes the shards. Carries no meaningful shard index (`0`).
const PUBLISH_ORIGIN: u8 = 0;

/// The upward hop budget for a cell escalation (audit R-C2): a residue is handed up at most this many strata
/// before it is terminal (external help required), bounding the recursion at the HOLARCH depth ceiling so an
/// escalation storm cannot climb without end.
pub(super) const ESCALATE_TTL: u8 = 3;
/// Storage `Publish` sub-type: a single **erasure shard** for the point named by the frame's shard-index
/// byte — the receiver (its shard home) stores it under that index (spec §L4 projective LRC, #115). This is
/// what replaces full replication: a value is `erasure::encode`d into `N=7` shards, one per Fano point, each
/// placed at the point's [`nearest_occupied`](OverlayNode::nearest_occupied) home, so the cell holds the
/// value at `N/K ≈ 2.33×` redundancy (vs `N×` full replication) while any `≤3`-point loss still recovers it.
const PUBLISH_SHARD: u8 = 2;
/// The DHT key-digest / storage-address length (BLAKE3-256) — the one canonical digest width.
pub(crate) const DIGEST: usize = fanos_primitives::DIGEST_LEN;

// Re-exported at this path, not merely imported: both are part of the crate's public surface and callers reach them as
// `overlay::…`. The codec moving to its own module is an internal split, and an internal split should not relocate a
// public name.
pub use crate::frames::{admission_challenge, descriptor_message};

use crate::frames::{
    LookupBody, announce_body, descriptor_signature_ok, encode, encode_diag_attest, encode_error,
    encode_lookup, encode_publish, encode_value, fold_seed, parse_announce, parse_digest, parse_u64,
};
use crate::healer::Healer;
use crate::membership::Membership;
use crate::router::{Peer, Router};
use crate::store::{PendingGet, PendingSample, Store};
use crate::ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

/// The single heartbeat timer token.
const HEARTBEAT: TimerToken = TimerToken(0);

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
const LOSS_EWMA_ALPHA: f64 = 0.25;
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
const MAX_PENDING_GETS: usize = 1024;
/// The most distinct shard-versions a single in-flight read accumulates before evicting the lowest (#115
/// Phase B). A read groups gathered shards by their write-version and reconstructs the highest recoverable
/// one (last-writer-wins); honestly there are only a handful in flight (the cell converges to one version),
/// so this bounds a Byzantine peer that sprays fabricated versions to grow the accumulator (A4 DoS).
const MAX_READ_VERSIONS: usize = 8;
/// How many distinct Fano lines a [`Command::SampleAvailability`] probes (spec §L4.3). `3` gives an
/// independent-sampling false-available bound of `(1/7)³ ≈ 0.3%`, and — since `≥2` distinct passing samples
/// certify availability against any withholding adversary (`fanos_code::da`) — a comfortable margin.
const DA_SAMPLES: usize = 3;

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
fn reconstruct_highest(by_version: &VersionedShards) -> Option<Vec<u8>> {
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
        let neighbours: Vec<Triple> = self.peers.keys().copied().collect();
        // §6.3 grey detection: fold last round's per-neighbour ping outcome into the loss EWMA, then mark this
        // round's ping outstanding (the loop below pings every neighbour). Done before building the gossip so
        // the `DiagLoss` row carries this round's fresh loss estimate.
        for coord in &neighbours {
            if let Some(peer) = self.peers.get_mut(coord) {
                let miss = f64::from(u8::from(peer.awaiting_pong));
                peer.loss = LOSS_EWMA_ALPHA * miss + (1.0 - LOSS_EWMA_ALPHA) * peer.loss;
                peer.awaiting_pong = true;
            }
        }
        // A health-view (how stale this node's direct observation of each cell point is), a polar
        // cross-attestation (its honest per-channel rate report for the 3 channels it mediates), and its
        // measured per-neighbour loss vector (§6.3 grey): all base-cell-only, read from the SAME snapshot this
        // window, so the three stay mutually consistent (spec §6.4, §6.8, §6.2, §6.3).
        let gossip_attest = self.cell_liveness(now).map(|(self_index, degraded, _)| {
            (
                encode(FrameType::DiagGossip, &self.health_view(now)),
                encode(
                    FrameType::DiagAttest,
                    &encode_diag_attest(self_index, degraded),
                ),
                encode(FrameType::DiagLoss, &self.loss_view()),
            )
        });
        // Detect newly-down peers (by the corroborated view), and (re-)ping + gossip everyone.
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
            if let Some((gossip, attest, loss)) = &gossip_attest {
                effects.push(Effect::Send {
                    to: coord,
                    frame: gossip.clone(),
                });
                effects.push(Effect::Send {
                    to: coord,
                    frame: attest.clone(),
                });
                effects.push(Effect::Send {
                    to: coord,
                    frame: loss.clone(),
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

    /// Account a permanent data loss (audit R-C3) for `digest` at a read's `Retrieved(None)` conclusion: if
    /// this node PROVABLY held a shard of it (so the value was stored) **and** the down shard-homes form a
    /// stopping set the `[7,3,4]` code cannot tolerate — so the corroborated-alive points can no longer
    /// reconstruct it — record it in the durable [`loss_ledger`] and emit [`Notification::DataLost`]. This
    /// turns silent permanent loss into accounted, visible loss.
    ///
    /// Timing-safe and R-H1-immune: it keys off the **corroborated-liveness** `degraded` mask (spec §6.4), not
    /// response latency or the append-only membership set — a slow peer never triggers a false loss, and a
    /// crashed peer that lingers in `members` is still counted down. Base `N = 7` cell only (where the code
    /// lives); off it the fine-grained placement is out of scope. Idempotent per key (the ledger is append-only).
    fn account_data_loss(&mut self, now: Instant, digest: [u8; DIGEST], effects: &mut Vec<Effect>) {
        if !self.store.entries.contains_key(&digest) || self.store.loss_ledger.contains_key(&digest) {
            return; // never held a shard (cannot attest the key was stored), or already accounted
        }
        // The shard-homes that are down (not corroborated-alive). If they form a stopping set the [7,3,4] code
        // cannot recover, the value is gone for good — no future read completes.
        let Some((_, degraded, _)) = self.cell_liveness(now) else {
            return; // off the base Fano cell — not this layer's placement domain
        };
        if !lrc::is_recoverable_fano(degraded) {
            let epoch = self.epoch();
            self.store.loss_ledger.insert(digest, epoch);
            effects.push(Effect::Notify(Notification::DataLost { key: digest, epoch }));
        }
    }

    /// Conclude reads that have not assembled a reconstructable shard-set within `read_timeout` as
    /// `Retrieved(None)` (spec §L4). Under erasure the read fans out to every shard home at once, so a
    /// timeout means too few shards came back to recover the value (enough nodes down / withholding, or the
    /// key was never stored) — there is no further replica to walk. A held key whose live shard-homes can no
    /// longer reconstruct is additionally accounted a permanent loss ([`account_data_loss`], R-C3).
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
            self.store.pending.remove(&digest);
            self.account_data_loss(now, digest, effects); // R-C3: a held-but-unrecoverable key is accounted lost
            effects.push(Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
            }));
        }
        // Conclude timed-out DA samples (§L4.3): a sample that never saw every sampled line present within the
        // timeout is inconclusive → `available = false` (a passing sample would have concluded early).
        let stale_samples: Vec<[u8; DIGEST]> = self
            .store
            .pending_samples
            .iter()
            .filter(|(_, s)| now.since(s.issued) > timeout)
            .map(|(digest, _)| *digest)
            .collect();
        for digest in stale_samples {
            if let Some(sample) = self.store.pending_samples.remove(&digest) {
                effects.push(Effect::Notify(Notification::Availability {
                    key: digest,
                    available: da::samples_pass(sample.present, &sample.lines),
                }));
            }
        }
    }

    /// Encode this node's direct-observation ages over the Fano cell: `7 × u16` little-endian
    /// milliseconds since it last heard each point (`u16::MAX` = never / stale). Self reads `0`.
    fn health_view(&self, now: Instant) -> Vec<u8> {
        let mut body = Vec::with_capacity(14);
        for i in 0..7usize {
            let coord = self.cell_coord(i);
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

    /// This node's measured **per-neighbour loss** row (§6.3 grey), one `u8` per Fano point (`loss × 255`,
    /// saturating). Self reads `0`; a point this node does not neighbour reads `0` (no measurement). The body
    /// of the `DiagLoss` frame flooded each heartbeat.
    fn loss_view(&self) -> Vec<u8> {
        let self_c = self.coord.coords();
        (0..7usize)
            .map(|i| {
                let coord = self.cell_coord(i);
                if coord == self_c {
                    0
                } else {
                    self.peers
                        .get(&coord)
                        .map_or(0, |p| (p.loss.clamp(0.0, 1.0) * 255.0) as u8)
                }
            })
            .collect()
    }

    /// Store witness `from`'s gossiped `DiagLoss` row — its measured loss toward each cell point — for the
    /// grey-detection matrix assembly ([`grey_rate_matrix`](Self::grey_rate_matrix)). Malformed (short) bodies
    /// are ignored.
    fn apply_diag_loss(&mut self, now: Instant, from: Triple, body: &[u8]) {
        if let Some(slice) = body.get(..7)
            && let Ok(row) = <[u8; 7]>::try_from(slice)
        {
            self.loss_reports.insert(from, (row, now));
        }
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
            let coord = self.cell_coord(i);
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
            _ => Vec::new(),
        }
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
        self.membership.admission_policy = Some(Box::new(PowAdmission::new(difficulty)));
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
        self.nearest_occupied(ideal.0.index())
    }

    /// The occupied points of this cell, by canonical index: this node, every cell peer we have heard from
    /// (its algebraic slot is filled by a live node — liveness populates this even before any JOIN/Announce),
    /// and every announced member. A never-occupied point is simply absent; a heard-then-crashed occupant is
    /// handled downstream by `routed_send`'s reroute. Always contains this node.
    fn occupied_points(&self) -> BTreeSet<usize> {
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
        occupied
    }

    /// The consistent-hashing home of the point at canonical index `ideal_idx`: the smallest occupied index
    /// `>= ideal_idx`, else wrap to the smallest occupied (successor on the index ring). This is the seam
    /// both content-routing ([`responsible_point`](Self::responsible_point)) and erasure shard-placement
    /// ([`distribute_shards`](Self::distribute_shards)) share — a shard for a point lands at that point when
    /// occupied, else its nearest-occupied successor. The occupied set always contains this node, so this is
    /// total (the `map_or` default is unreachable, kept only for totality).
    fn nearest_occupied(&self, ideal_idx: usize) -> Triple {
        let occupied = self.occupied_points();
        occupied
            .range(ideal_idx..)
            .next()
            .or_else(|| occupied.iter().next())
            .map_or_else(
                || Point::<F>::at(ideal_idx).coords(),
                |&i| Point::<F>::at(i).coords(),
            )
    }

    /// `Command::Put` — erasure-code the value and distribute its shards across the cell (spec §L4). The
    /// write is stamped with a version (the responsible node's `now`) so a later write supersedes it
    /// (last-writer-wins) and a reader never mixes two writes' shards.
    fn on_put(&mut self, now: Instant, key: &[u8], value: &[u8]) -> Vec<Effect> {
        let (digest, ideal) = Self::address_of(key);
        let primary = self.responsible_point(ideal);
        if primary == self.coord.coords() {
            // We are the responsible node: refuse an over-size value without distributing or claiming it
            // stored; otherwise erasure-code it into per-point shards, place each at its home, and ack.
            if value.len() > MAX_VALUE_LEN {
                return Vec::new();
            }
            let mut effects = self.distribute_shards(&digest, value, now.as_nanos());
            effects.push(Effect::Notify(Notification::Stored(digest)));
            effects
        } else {
            // Route the full value to the responsible node, which stamps the version and distributes shards.
            alloc::vec![self.routed_send(
                primary,
                encode_publish(PUBLISH_ORIGIN, 0, 0, &digest, value)
            )]
        }
    }

    /// `Command::Get` — gather a recoverable erasure shard-set from the cell and reconstruct (spec §L4).
    ///
    /// Under the projective LRC no single node holds the value: it lives as `N=7` shards, one per point.
    /// The read seeds any shards THIS node holds, and if they alone reconstruct (a small/degenerate cell)
    /// answers at once; otherwise it fans a `Lookup` out to *every* cell peer simultaneously and accumulates
    /// their shards ([`on_value`](Self::on_value)) until the present set is [`erasure::reconstruct`]-able —
    /// which tolerates any `≤3`-point loss, so the read succeeds even with several nodes down or withholding.
    /// The heartbeat sweep concludes `Retrieved(None)` if a recoverable set never assembles within the read
    /// timeout. The in-flight accumulator is tracked in the [`Store`]'s `pending` map.
    fn on_get(&mut self, now: Instant, key: &[u8]) -> Vec<Effect> {
        let (digest, _ideal) = Self::address_of(key);
        // Seed the accumulator with any shards this node already holds (grouped by write-version); short-
        // circuit if the highest recoverable version reconstructs from local shards alone.
        let mut by_version = BTreeMap::new();
        self.store.seed_versions(&digest, &mut by_version);
        if let Some(value) = reconstruct_highest(&by_version) {
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: Some(value),
            })];
        }
        // Cap in-flight reads (A4 DoS backstop): once [`MAX_PENDING_GETS`] distinct reads are outstanding,
        // refuse a *new* one — concluding `Retrieved(None)` — rather than track it, so a flood of
        // distinct-key `Get`s cannot grow the pending map without bound. A repeat Get for an already-pending
        // digest is allowed through (it refreshes the existing entry, no growth).
        if self.store.pending.len() >= MAX_PENDING_GETS && !self.store.pending.contains_key(&digest)
        {
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
            })];
        }
        // Fan a `Lookup` out to every cell peer at once — each is a potential shard home. Sent directly
        // (not rerouted): a down peer simply does not reply, and the erasure redundancy tolerates it.
        let peers: Vec<Triple> = self.peers.keys().copied().collect();
        if peers.is_empty() {
            // No peer to gather from and the local shards did not reconstruct — the value is unreachable.
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
            })];
        }
        // A fresh per-request nonce correlates this read's replies (audit C4); a repeat Get for the same
        // key supersedes the old one with a new nonce, so the old read's in-flight replies go stale.
        self.store.seq = self.store.seq.wrapping_add(1);
        let nonce = self.store.seq;
        self.store.pending.insert(
            digest,
            PendingGet {
                issued: now,
                by_version,
                nonce,
                queried: u16::try_from(peers.len()).unwrap_or(u16::MAX),
                negatives: 0,
            },
        );
        peers
            .into_iter()
            .map(|peer| Effect::Send {
                to: peer,
                frame: encode_lookup(&digest, nonce),
            })
            .collect()
    }

    /// `Command::SampleAvailability` — the light-client DA sample (spec §L4.3): probe a few unpredictable
    /// Fano lines to certify the value's shards are present, without downloading it. Seeds the `present` mask
    /// from local shards, picks `DA_SAMPLES` distinct lines ([`da::sample_lines`]) from an unpredictable seed
    /// (fold of the digest ⊕ a fresh nonce — so a withholding adversary cannot pre-position the lone external
    /// line), and probes only the sampled points' shard homes. Concludes `available` as soon as every sampled
    /// line is fully present ([`da::samples_pass`]); the sweep concludes it (unavailable) after the timeout.
    fn on_sample(&mut self, now: Instant, key: &[u8]) -> Vec<Effect> {
        let (digest, _ideal) = Self::address_of(key);
        self.store.seq = self.store.seq.wrapping_add(1);
        let nonce = self.store.seq;
        let lines = da::sample_lines(fold_seed(&digest) ^ nonce, DA_SAMPLES);
        // Seed the DA `present` mask from any shards this node itself holds.
        let mut present = 0u8;
        if let Some(held) = self.store.entries.get(&digest) {
            for &i in held.keys() {
                if usize::from(i) < erasure::N {
                    present |= 1 << i;
                }
            }
        }
        // Probe the distinct shard homes of the sampled lines' points (self is already seeded).
        let me = self.coord.coords();
        let mut targets: BTreeSet<Triple> = BTreeSet::new();
        for &l in &lines {
            let Some(points) = fano::LINE_POINTS.get(l) else {
                continue;
            };
            for &p in points {
                let home = self.nearest_occupied(usize::from(p));
                if home != me {
                    targets.insert(home);
                }
            }
        }
        // Already satisfied locally, or nobody else to probe — conclude now.
        if da::samples_pass(present, &lines) || targets.is_empty() {
            return alloc::vec![Effect::Notify(Notification::Availability {
                key: digest,
                available: da::samples_pass(present, &lines),
            })];
        }
        // A4 DoS cap (shared spirit with reads): bound the in-flight sample map.
        if self.store.pending_samples.len() >= MAX_PENDING_GETS
            && !self.store.pending_samples.contains_key(&digest)
        {
            return alloc::vec![Effect::Notify(Notification::Availability {
                key: digest,
                available: false,
            })];
        }
        self.store.pending_samples.insert(
            digest,
            PendingSample {
                issued: now,
                nonce,
                lines,
                present,
            },
        );
        targets
            .into_iter()
            .map(|t| Effect::Send {
                to: t,
                frame: encode_lookup(&digest, nonce),
            })
            .collect()
    }

    /// Erasure-code `value` into `N=7` point-shards and place each at its point's nearest-occupied home
    /// (spec §L4 projective LRC): shard `i` → [`nearest_occupied`](Self::nearest_occupied)`(i)`. Shards homed
    /// at this node are stored locally; the rest are sent as `PUBLISH_SHARD` frames carrying the point index.
    /// On a full Fano cell this is shard `i` → point `i` (one shard per node, `N/K ≈ 2.33×` redundancy vs
    /// `N×` full replication); on a sparse cell several shards may share a home (graceful degradation — the
    /// cell simply has fewer independent failure domains).
    fn distribute_shards(
        &mut self,
        digest: &[u8; DIGEST],
        value: &[u8],
        version: u64,
    ) -> Vec<Effect> {
        let me = self.coord.coords();
        let shards = erasure::encode(value);
        let mut effects = Vec::new();
        for (i, shard) in shards.into_iter().enumerate() {
            let home = self.nearest_occupied(i);
            #[allow(clippy::cast_possible_truncation)] // i < N = 7
            let index = i as u8;
            if home == me {
                self.store.insert_shard(*digest, index, version, shard);
            } else {
                effects.push(Effect::Send {
                    to: home,
                    frame: encode_publish(PUBLISH_SHARD, index, version, digest, &shard),
                });
            }
        }
        effects
    }

    fn on_publish(&mut self, now: Instant, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some(&flag) = body.first() else {
            return Vec::new();
        };
        let Some(&index) = body.get(1) else {
            return Vec::new();
        };
        let Some(version) = parse_u64(body, 2) else {
            return Vec::new();
        };
        let Some(digest) = parse_digest(body.get(10..10 + DIGEST)) else {
            return Vec::new();
        };
        let payload = body.get(10 + DIGEST..).unwrap_or(&[]);
        // A4 DoS caps: a refused publish (over-size, or a new key over the store cap) is dropped without an
        // Ack or distribution — a relayed flood of distinct digests cannot exhaust this node's memory.
        if !self.store.admits(&digest, payload.len()) {
            return Vec::new();
        }
        match flag {
            PUBLISH_ORIGIN => {
                // We are the responsible node: stamp this write's version (our distribution time),
                // erasure-distribute the full value across the cell, and acknowledge the origin.
                let mut effects = self.distribute_shards(&digest, payload, now.as_nanos());
                effects.push(Effect::Send {
                    to: from,
                    frame: encode(FrameType::Ack, &digest),
                });
                effects
            }
            PUBLISH_SHARD => {
                // A single versioned shard for Fano point `index` — store it, keeping the higher version.
                self.store
                    .insert_shard(digest, index, version, payload.to_vec());
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn on_lookup(&self, from: Triple, body: &[u8]) -> Vec<Effect> {
        // Canonical derived codec (audit A1): rejects a short or trailing-byte Lookup.
        let Ok(LookupBody { key: digest, nonce }) = LookupBody::from_wire(body) else {
            return Vec::new();
        };
        // Return EVERY shard this node holds for the key, one `Value` each carrying its write-version (the
        // reader groups by version, then point index). No shard → a single `found=false` "not here".
        match self.store.entries.get(&digest) {
            Some(held) if !held.is_empty() => held
                .iter()
                .map(|(&index, (version, shard))| Effect::Send {
                    to: from,
                    frame: encode_value(&digest, true, index, *version, shard, nonce),
                })
                .collect(),
            _ => alloc::vec![Effect::Send {
                to: from,
                frame: encode_value(&digest, false, 0, 0, &[], nonce),
            }],
        }
    }

    /// A `Value` reply carrying one versioned erasure shard (spec §L4). Accumulate it into the in-flight
    /// read's version-grouped shard-set and, once the **highest** recoverable version reconstructs, deliver
    /// that value (last-writer-wins) and retire the read. A `found=false` reply (the peer holds no shard) is
    /// not accumulated; once every queried peer has said so, or the read times out, the value is absent.
    fn on_value(&mut self, now: Instant, body: &[u8]) -> Vec<Effect> {
        let Some(digest) = parse_digest(body.get(..DIGEST)) else {
            return Vec::new();
        };
        let found = body.get(DIGEST).copied().unwrap_or(0) != 0;
        let index = body.get(DIGEST + 1).copied().unwrap_or(0);
        let Some(version) = parse_u64(body, DIGEST + 2) else {
            return Vec::new();
        };
        let Some(nonce) = parse_u64(body, DIGEST + 10) else {
            return Vec::new();
        };
        // A `Value` may answer an in-flight DA sample (§L4.3) rather than a read — the distinct per-request
        // nonce disambiguates. Route it there first: mark the point present and, once every sampled line is
        // present, conclude the value available.
        if let Some(sample) = self.store.pending_samples.get_mut(&digest)
            && sample.nonce == nonce
        {
            if found && usize::from(index) < erasure::N {
                sample.present |= 1u8 << index;
            }
            if da::samples_pass(sample.present, &sample.lines) {
                self.store.pending_samples.remove(&digest);
                return alloc::vec![Effect::Notify(Notification::Availability {
                    key: digest,
                    available: true,
                })];
            }
            return Vec::new();
        }
        // Otherwise correlate on the per-request nonce, NOT merely the key: a reply is accepted only for the
        // read currently in flight for this key. A stale/replayed `Value` from a prior get (old nonce), or one
        // with no in-flight read at all, is ignored — so it can never drain a later same-key get with an old
        // shard (read-your-writes, audit C4).
        let Some(pending) = self.store.pending.get_mut(&digest) else {
            return Vec::new();
        };
        if pending.nonce != nonce {
            return Vec::new();
        }
        if !found {
            // A peer holds no shard for this key. Once every queried peer has said so and no version's shards
            // reconstruct, conclude the value absent immediately (a fast miss, not a timeout wait).
            pending.negatives = pending.negatives.saturating_add(1);
            if pending.negatives >= pending.queried
                && reconstruct_highest(&pending.by_version).is_none()
            {
                self.store.pending.remove(&digest);
                let mut effects = alloc::vec![];
                self.account_data_loss(now, digest, &mut effects); // R-C3: all peers answered, none can supply it
                effects.push(Effect::Notify(Notification::Retrieved { key: digest, value: None }));
                return effects;
            }
            return Vec::new();
        }
        // shard bytes follow: digest(32) ‖ found(1) ‖ index(1) ‖ version(8) ‖ nonce(8) ‖ shard.
        let shard = body.get(DIGEST + 18..).unwrap_or(&[]).to_vec();
        if let Some(slot) = pending
            .by_version
            .entry(version)
            .or_default()
            .get_mut(index as usize)
        {
            *slot = Some(shard);
        }
        // Bound the version-grouped accumulator against a Byzantine peer spraying fabricated versions: keep
        // only the highest [`MAX_READ_VERSIONS`] (the freshest are what last-writer-wins wants anyway).
        while pending.by_version.len() > MAX_READ_VERSIONS {
            if let Some(&lowest) = pending.by_version.keys().next() {
                pending.by_version.remove(&lowest);
            }
        }
        // Deliver the highest write-version whose shard-set is now recoverable (a stale version completing
        // first can never mask a fresher one; mixed-version shards are never combined into a garbage value).
        if let Some(value) = reconstruct_highest(&pending.by_version) {
            self.store.pending.remove(&digest);
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: Some(value),
            })];
        }
        Vec::new()
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
            // The challenge binds the announcer's IDENTITY, not merely its coordinate. Without that a solved proof is
            // replayable by anyone claiming the same point: an attacker who wants a seat could present the *incumbent's
            // own* proof and pay nothing. Measured cost of the surrounding attack before this binding — grind ~20
            // identities until one collides with a chosen victim at a lower rank (`fanos-vrf/examples/grind_probe.rs`),
            // reuse the victim's proof, and the rank rule evicts the victim for zero proof-of-work.
            let challenge = admission_challenge(&id, coord, self.epoch);
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
    /// cannot compute it); this re-derives the node's cell neighbours and Fano index for the new placement,
    /// moves the level-0 of its hierarchical address to `new_coord` while **preserving the deeper descent
    /// levels** (identity-hash, epoch-stable — §L1), re-announces so the cell relearns how to route to it, and
    /// emits
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
                        loss: 0.0,
                        awaiting_pong: false,
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
        // Re-solve our Sybil-admission proof for the NEW `(coordinate, epoch)` (spec §L3), so a peer's
        // per-epoch admission check keeps passing as we reshuffle: seizing a coordinate costs a fresh PoW
        // *each epoch*, never a one-time grind (the "re-paid every epoch" cost of `anti_eclipse_reshuffle`).
        // `self.epoch` is already the new epoch here — the composite drives the overlay to the beacon epoch
        // before issuing this `Reseat`. Only when PoW admission is in use (`with_admission_pow`); cheap at a
        // modest difficulty, and deterministic (sans-I/O replay is preserved).
        if let Some(difficulty) = self.membership.admission_difficulty {
            self.membership.admission_proof =
                PowAdmission::new(difficulty).solve(&admission_challenge(&self.membership.identity, new_coord, self.epoch));
        }
        // Preserve the hierarchical DESCENT chain across the reshuffle (spec §L1): only the level-0 VRF
        // transport coordinate moves each epoch; the deeper sub-cell levels are identity-hash-derived
        // (`fanos_primitives::address_point`, epoch-INDEPENDENT), so a descended node keeps its sub-cell
        // placement. Resetting to a bare `root(new_pt)` here would silently drop a multi-level node's descent
        // chain every epoch (the depth-1 case is unchanged — its path is just `[new_pt]`). Learned peers ARE
        // cleared (via `Router::new`): every other node reshuffled too, so the transport-coord-keyed routing
        // table is stale and re-learns from the fresh `Announce`s below.
        let mut path: Vec<Point<F>> = self.router.address.points().to_vec();
        match path.first_mut() {
            Some(level0) => *level0 = new_pt,
            None => path.push(new_pt),
        }
        self.router = Router::new(new_pt);
        if let Some(addr) = HierAddr::from_path(path) {
            self.router.address = addr;
        }
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
        effects.push(Effect::Notify(Notification::Reseated {
            old,
            new: new_coord,
        }));
        effects
    }

    /// The current membership view (coordinate → announced info), for onion routing / observation.
    pub fn members(&self) -> impl Iterator<Item = (Triple, &[u8])> + '_ {
        self.membership
            .members
            .iter()
            .map(|(&c, i)| (c, i.as_slice()))
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
