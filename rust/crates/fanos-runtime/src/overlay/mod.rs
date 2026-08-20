//! `OverlayNode` — the base FANOS node engine (spec L1/L3 + DIAKRISIS), sans-I/O.
//!
//! This is production node logic: it maintains liveness of its cell neighbours via periodic
//! heartbeats, resolves rendezvous by the algebraic line `u × v`, delivers application
//! payloads, and (on the base Fano cell) runs one DIAKRISIS round to localize a fault. It
//! reacts only to [`Input`]s and emits only [`Effect`]s — no clock, socket, or RNG — so the
//! same code runs under the simulator and a real transport.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use Vec;

use fanos_code::erasure;
use crate::ports::stations::{GatherHealth, Station, Stations};
use fanos_core::roles::{self, Role, RoleReading};
use fanos_core::{AdaptivePowAdmission, AdmissionPolicy, LiveDifficulty, ParentCell, PowAdmission};
use fanos_diakrisis::polar;
use fanos_diakrisis::regeneration::spectral_gap;
use fanos_field::Field;
use fanos_geometry::{HierAddr, Plane, Point, Triple, fano};
use fanos_primitives::{BeaconSeed, Epoch, hash_labeled, storage_digest, storage_point};
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
pub use storage::{ReadRefusal, ReadStall};

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
use crate::ports::{
    AdmissionOutcome, Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken,
};

/// The single heartbeat timer token.
pub(super) const HEARTBEAT: TimerToken = TimerToken(0);

/// The base cell's point count, `q² + q + 1` at `q = 2` — the `n` every quorum and every band in this
/// module is stated for.
pub(crate) const CELL_POINTS: usize = 7;

/// The Byzantine fault budget of a cell of `n` nodes — **re-exported, no longer defined here** (#337).
///
/// Re-exported rather than moved-and-forgotten because this crate's own callers ([`corroboration_quorum`],
/// and `fanos-sim`'s flood-spread measurement from #288, which sizes `2f + 1` from it at *both* compared
/// plane orders) name it through this path, and a rename would be churn with no reader benefit.
///
/// **Why it left.** The doc that used to sit here warned that *"restating `(n − 1)/3` over there would work
/// and is exactly the copy that drifts"* — while two production sites did exactly that, in `fanos-rendezvous`
/// and `fanos-taxis`. Neither could import it: neither depends on `fanos-runtime`, and neither should, because
/// this is a higher layer. So the duplication was a *layering* fact, not carelessness, and the only fix that
/// removes it is a move to the one crate every consumer already reaches — see
/// [`fanos_geometry::tolerance`] for the enumeration that picked it and for the category tension it carries.
pub use fanos_geometry::fault_budget;

/// The **corroboration quorum** for a cell of `n` nodes — see [`Config::corroboration_quorum`] for the
/// two-sided derivation. `f + 1`, which at Fano is simultaneously the safety floor and the liveness ceiling.
///
/// Clamped to at least `1` so a degenerate cell still requires *someone* to vouch, and to at most the
/// witnesses that can exist (`n − 2`), so a plane too small to satisfy both constraints fails closed on the
/// liveness side rather than demanding a quorum no honest cell can reach.
pub const fn corroboration_quorum(n: usize) -> usize {
    let safety = fault_budget(n) + 1;
    let available = n.saturating_sub(2);
    if safety > available && available >= 1 { available } else if safety < 1 { 1 } else { safety }
}

/// The reflex's sampling period — one behavioural sample, one diagnosis, one control decision.
///
/// The default for [`Config::heartbeat`], and the loop's **quantum**: the observation window is a count of
/// these, the dwell is a count of these, and the epoch divided by this is what the control confidence is
/// derived against.
pub(crate) const HEARTBEAT_PERIOD: Duration = Duration::from_millis(500);

/// The default epoch, matching `fanos_node::config::DEFAULT_EPOCH_PERIOD`.
///
/// A default, not a constant the loop reads: the loop reads [`Config::epoch_period`], because an operator
/// who sets a different epoch must get a control loop derived for **their** epoch. See
/// [`Config::behavior_window`].
pub(crate) const EPOCH_PERIOD: Duration = Duration::from_millis(600_000);

/// Homeostatic **decoupling** control (audit C6). `Decouple` must actually lower the cell's integration,
/// not merely notify: the node carries a mutable shed factor that scales its effective correlation down,
/// and that reduced correlation feeds `phi_equicorrelated` — so each over-coupled round genuinely restores
/// headroom, and the reflexive loop lowers `Φ` (spec §2.7/§6.5).
///
/// # The shed is the homeostat's own law, and it used to be a constant
///
/// `Homeostat::control` computes `effort = κ(r − hi)/hi` — proportional to the over-excursion, and
/// documented as gradient descent on `V = ‖Γ − ρ*‖²`, which is what makes the closed loop inherit the T-104
/// contraction. That value had **exactly one production consumer and it discarded it**: actuation ran on a
/// different path (`plan_healing` → `HealingAction::Decouple`) and added a fixed `0.25`.
///
/// The constant was not merely unjustified, it was wrong by a factor of three for the shipped cell. The shed
/// scales the *configured baseline* `healthy_correlation = 0.45`, and the collective-subject band at `N = 7`
/// is `(1/√6, √(2/6)] = (0.4082, 0.5774]`, so the largest shed that keeps the cell a collective subject is
/// `1 − 0.4082/0.45 ≈ 0.093`. One step of `0.25` modelled the correlation at `0.3375` — **below the floor**,
/// classifying the cell as `Aggregate`, whose homeostatic answer is `Bind`: the opposite action, reachable in
/// a single round. The proportional law cannot do that, and says so at its own definition ("never negative,
/// so it cannot push `r` below the band").
///
/// So there is no step constant any more. `decouple_ceiling` is the cap, derived below.
pub(crate) const DECOUPLE_DECAY: f64 = decouple_decay();

/// The largest shed that still leaves the cell a **collective subject**, for a cell of `n` live nodes at
/// baseline correlation `healthy`.
///
/// The shed must not push the modelled correlation below `lo = 1/√(n−1)`, because that converts an
/// over-coupled cell into an *aggregate* (`Φ < 1`) — the opposite failure, and the one `Bind` exists to
/// answer. From `healthy·(1 − d) ≥ lo`:
///
/// ```text
/// d_max = 1 − lo/healthy = 1 − 1 / (healthy·√(n−1))
/// ```
///
/// **It depends on the plane, which is why it cannot be a constant.** At `n = 7` and `healthy = 0.45` the
/// budget is `0.093`; the retired `DECOUPLE_MAX = 0.6` was six and a half times that, and fixed on every
/// plane — the same shape as `MIX_THRESHOLD` pinned at 2 (E7).
///
/// **The safety setback is additive in correlation, not a fraction of the budget** (#92). `d_max` is a
/// *supremum*: `classify_collective` reads `r ≤ lo` as `Aggregate`, so spending the whole budget lands
/// exactly on the boundary and is classified as the failure it was avoiding. The band is a threshold on a
/// **measured** quantity, so the setback that keeps the controller off it must cover the *estimator's
/// error* — and that error does not depend on how much budget there happens to be.
///
/// The retired form multiplied the budget by a declared `0.5`, which made the setback shrink with the
/// headroom while the noise stayed put. The derived form moves the floor instead:
///
/// ```text
/// d_safe = 1 − (lo + z·SE(r̂)) / healthy
/// ```
///
/// with `z` = [`control_confidence()`] and `SE` the worst case over the band at the shipped window
/// ([`band_stderr`](fanos_diakrisis::window::band_stderr)). It collapses to the old `d_max` as `SE → 0`, so
/// the original derivation is intact underneath it — and it is the reason [`BEHAVIOR_WINDOW`] had to be
/// derived first: at the window this platform used to ship, `lo + z·SE` sat **above** `healthy` itself, so
/// no shed at all was statistically justified and the ceiling clamps to zero. That is not a regression, it
/// is the honest reading of an instrument that could not see the boundary.
///
/// Clamped to `[0, 1)`: a baseline already at or below the effective floor admits no shed, which is the
/// honest answer rather than a negative one.
pub(crate) fn decouple_ceiling(n: usize, healthy: f64, window: usize, z: f64) -> f64 {
    if n < 2 || healthy <= 0.0 {
        return 0.0;
    }
    // The floor and the estimator's error both come from DIAKRISIS rather than being re-derived here, so a
    // change to the band or to the window moves this ceiling with it instead of leaving copies to drift.
    let lo = fanos_diakrisis::coherence::systemic_correlation(n);
    let setback = z * fanos_diakrisis::window::band_stderr(n, window);
    (1.0 - (lo + setback) / healthy).clamp(0.0, 1.0)
}


/// The per-round re-integration factor: **half-life of one detection dwell**.
///
/// Derived rather than chosen. The loop must not un-shed faster than it can observe the effect of a shed, or
/// an intermittent cause produces a limit cycle — the standard anti-chatter condition. Detection takes
/// [`BAND_DWELL`] consecutive diagnoses, so the decay's half-life is set equal to it:
/// `DECAY = 2^(−1/DWELL)`. The retired `0.5` was a half-life of **one round**, three times faster than the
/// loop can decide anything.
const fn decouple_decay() -> f64 {
    // `2^(-1/3)`, written out because `powf` is not `const`. Checked against the formula in the tests.
    0.793_700_525_984_099_7
}
/// Hysteresis dwell for the over-coupling shed (audit #122). The measured `Γ_net` must read over-coupled
/// for this many *consecutive* self-driven diagnoses before `Decouple` actuates. Diagnosis now runs every
/// heartbeat (not a one-shot injected command), so a single transient over-threshold reading — e.g. a
/// coincidental correlation inside an otherwise decorrelated burst flood — must not trigger a shed: the
/// DDoS response acts on *sustained* over-coupling (structure), never momentary load. Crash/Byzantine
/// healing is unaffected — this gates only the `Decouple` action.
pub(crate) const BAND_DWELL: u32 = 3;

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
/// The most distinct keys one node's local store slice will hold.
///
/// **Public, because a caller cannot reason about its own key lifetime without it.** Six directories key
/// their slots by `(coordinate, epoch)` and re-publish every epoch, so a cell generates new keys on a wall
/// clock — and whether that is survivable is arithmetic over this number, the epoch period and the publisher
/// count. Keeping it crate-private meant no publisher could do that arithmetic, and none did
/// (`fanos-node/tests/store_lifetime.rs`).
pub const MAX_STORE_ENTRIES: usize = STORE_MEMORY_BUDGET / MAX_VALUE_LEN;

/// The product the share was never checked against, now checked by the compiler.
///
/// The division above stood alone. It is the fourth site found in one sweep with a share divided and nothing
/// multiplying the count back out — `MAX_PENDING`'s doc calls that shape *"the assertion whose absence was
/// the defect"*, and of the four, two were genuinely over their share (the threshold router's send queues by
/// `251_829 B`, and its attribution ring entirely outside the sum). This one is exact —
/// `2048 × 65_536 = 134_217_728 = 128 MiB` — which is the reason to add the guard now rather than the reason
/// to skip it: the cheap half of an assertion is the one that has never fired.
const _: () = assert!(
    MAX_STORE_ENTRIES * MAX_VALUE_LEN <= STORE_MEMORY_BUDGET,
    "the store slice's worst case exceeds STORE_SHARE — raise the share deliberately or lower a factor"
);

/// …and it is the **largest** count the share buys, so the number is derived rather than merely fitting.
///
/// Without this the assertion above is satisfied by any small number and neither says the count was derived —
/// which matters here more than elsewhere, because this constant's own doc records that it *was* `4096` with
/// no derivation at all before the budget existed.
const _: () = assert!(
    (MAX_STORE_ENTRIES + 1) * MAX_VALUE_LEN > STORE_MEMORY_BUDGET,
    "MAX_STORE_ENTRIES is below what the share buys, so it was chosen rather than derived"
);

/// The memory one node's store slice may occupy **at its ceiling** — the budget [`MAX_STORE_ENTRIES`]
/// divides, so the count and the bytes cannot drift apart.
///
/// **The value was 4096 entries and had no derivation** — its doc said what the cap did, never why it was
/// that number, which is the shape #45 exists to remove. Deriving it turned up a second thing:
/// `4096 × 64 KiB = 256 MiB` is *exactly* the RAM `docs/deployment-minima.md` recommends for the default
/// relay/storage role, so a node under a publish flood had its entire budget in one map with nothing left
/// for the transport, the engine or the process. (That guide also understated the ceiling threefold, having
/// divided by the erasure rate as though the cap applied to a reconstructed value; the cap is applied to the
/// `PUBLISH_SHARD` body, and `an_oversize_published_value_is_refused` stores a shard of exactly
/// `MAX_VALUE_LEN`.)
///
/// **Both bounds are derived; the point between them is a stated choice.**
///
/// *Ceiling.* Every cap saturating at once must still fit the recommendation — and **this paragraph used to
/// get that sum wrong, in the direction that made the store look affordable** (#213). It read: `HELD_CAP ×
/// MAX_VALUE_LEN` = 32 MiB, `PENDING_CAP × MAX_VALUE_LEN` = 4 MiB, in-flight reads < 1 MiB and 7.6 MB
/// measured resident, so `256 − 45 ≈ 203 MiB` was available. Three things were missing or wrong:
///
/// * **in-flight reads are not < 1 MiB.** The read path applied no length check to a `Value` shard, so one
///   read was measured holding **53.4 MiB** and the derived ceiling after the fix is
///   [`READ_MEMORY_CEILING`] = **2.6 GiB**, not 1 (#212).
/// * **the session layer is absent from the sum.** `fanos_diaulos::budget::SESSION_MEMORY_BUDGET` is 64 MiB
///   and was derived, in #205, against "what the store left" — which this paragraph is the statement of.
/// * **the mixnet router is absent too.** `fanos_aphantos`'s gather cap is a bare `64 * 1024 * 1024` in a
///   crate nothing here has ever mentioned.
///
/// So the honest reading is that the node's shares already exceed its own recommendation before this
/// constant is chosen, and #213 owns closing that. **128 MiB is kept unchanged rather than adjusted here**:
/// picking a new number against a sum that does not close would be a fifth budget fitted to the same 256 MiB
/// as the other four, which is precisely the defect.
///
/// *Floor.* Honest use must be nowhere near it. A fully-provisioned Fano cell writes 4 directory slots per
/// node per epoch and keeps one epoch of grace, so **56 slots are live at any moment**
/// (`fanos-node/tests/store_lifetime.rs`, which computes it from the shipped constants), and that test
/// additionally requires the directories to stay under a quarter of the cap — a floor of 224.
///
/// *The choice.* 128 MiB — half the relay recommendation, and the largest power of two that leaves a full
/// doubling of headroom below the 203 MiB ceiling. It gives **2048 entries**: 36× the live directory set and
/// 9× the floor that test enforces, so honest use is untouched, while a flooded node occupies half its
/// budget instead of all of it. The bounds are arithmetic; picking the round number inside them is
/// engineering judgement, and saying which is which is the point of writing it down.
pub(crate) const STORE_MEMORY_BUDGET: usize = fanos_primitives::budget::STORE_SHARE;
/// The largest value the store will hold, in bytes — bounds per-entry memory and rejects amplification.
pub const MAX_VALUE_LEN: usize = 65_536;
/// The most concurrent in-flight `Get`s tracked at once; further reads are refused until some resolve.
///
/// **Its product with [`READ_ACCUMULATOR_BYTES`] is stated below and does not fit the node's own memory
/// recommendation** (#213). That is recorded rather than silently repaired: the count cannot be lowered to
/// fit inside this crate, because it must clear the read concurrency a full cell's six epoch-keyed
/// directories generate, and picking a number for it here without the cross-crate apportionment would be a
/// fourth budget fitted to the same 256 MiB as the other three.
pub const MAX_PENDING_GETS: usize = 1024;

/// The most shards **one queried peer** may contribute to one in-flight read.
///
/// Not a policy number: a peer holds at most one shard per point index
/// (`HeldShards` is keyed by `u8`), so `on_lookup` sends at most this many `Value` replies and an honest
/// peer never reaches the quota. It is what replaced a count-bounded eviction keyed on the wire-supplied
/// `version` — see [`ReadRefusal::PeerQuota`].
pub const READ_PEER_SHARD_QUOTA: usize = erasure::N;

/// What one in-flight read may hold, in bytes — the quota above times the peers a read fans out to, times
/// the largest shard the store would ever have accepted.
///
/// **This is the term `STORE_MEMORY_BUDGET`'s accounting called "in-flight reads < 1 MiB".** It was not: the
/// read path applied no length check at all, so the true figure was bounded only by `MAX_FRAME`, and one read
/// was measured holding **53.4 MiB** (#212). With [`MAX_VALUE_LEN`] enforced on the reply and the per-peer
/// quota in place it becomes an honest number, and an honest number that is still large — which is the point
/// of writing it down rather than estimating it again.
///
/// The peer count is the base plane's `q² + q = 6`, the cell a deployment runs
/// (`docs/deployment-minima.md`); a wider plane fans out further and the per-read figure scales with it.
pub const READ_ACCUMULATOR_BYTES: usize = READ_PEER_SHARD_QUOTA * 6 * MAX_VALUE_LEN;

/// The product [`MAX_PENDING_GETS`] and [`READ_ACCUMULATOR_BYTES`] make, named so that it is a fact in the
/// code rather than a paragraph — **2.6 GiB**, against a 256 MiB node recommendation (#213).
///
/// Deliberately not a `const` assertion against the recommendation. That assertion belongs in the shared
/// apportionment #213 introduces, where all four subsystem budgets are visible at once; asserting it here
/// would fail the build of a crate that cannot fix it, and the tree's rule is that a guard names something
/// its owner can act on.
pub const READ_MEMORY_CEILING: usize = MAX_PENDING_GETS * READ_ACCUMULATOR_BYTES;
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
    /// This network's epoch — how often coordinates, rosters, directories and roles all turn over.
    ///
    /// The band-keeping loop is derived against it (see [`behavior_window`](Self::behavior_window)), so it
    /// must be the epoch the node's driver actually runs. `fanos-node` sets it from its own
    /// `epoch_period`; a simulation that runs a short epoch gets a correspondingly short window, which is
    /// the same derivation rather than a shortcut around it.
    pub epoch_period: Duration,
    /// This network's genesis seed — the value that tells one deployment from another (#98).
    ///
    /// Carried here for the same reason `epoch_period` is: it is a property of the *network* the reflex runs
    /// in, and the reflex derives something from it that must not silently agree across networks — the
    /// `CellId` its coherence frames are keyed by. `BeaconSeed::GENESIS` (the default) is the honest value
    /// for a deployment that has not
    /// named itself, and it reproduces the pre-#210 identifier exactly.
    pub genesis: BeaconSeed,
    /// A peer unheard-from for longer than this is considered degraded.
    ///
    /// **It is coupled to [`heartbeat`](Self::heartbeat) and the coupling is not expressed here.** The
    /// default is the literal `1600 ms` against a `500 ms` heartbeat; `fanos-observatory` builds the same
    /// quantity as `HEARTBEAT_MS * 3` (1500 ms), so the tree computes one thing two ways and the two
    /// disagree by 100 ms. Neither number is derived — `storage.rs`'s note ("at 1600 ms swept on the 500 ms
    /// heartbeat, a read settles at ~2 s — measured") takes 1600 as given and reports the consequence — and
    /// `ENDPOINT_WINDOW` (crate-internal, so named and not linked) is justified *against* this value
    /// — "≈ 2.5 s > `liveness_timeout`" — which holds at both 1500 and 1600.
    ///
    /// **Nothing can drift today**, because the heartbeat period is not operator-settable: the `heartbeat`
    /// config key sets `start_heartbeat`, a boolean. That is the whole reason this is a note and not a fix —
    /// deriving it would move a value that measurement is quoted against, for a gain that is hypothetical
    /// while the period is a constant. **Whoever makes the period tunable owes this line a second look**: the
    /// observatory's value will follow the heartbeat and this one will not.
    pub liveness_timeout: Duration,
    /// The healthy mean inter-node correlation `r` used to estimate the cell's integration `Φ`
    /// for the healing budget (`Φ_net = (N−1)·r²`, spec §2.7). The default `0.45` sits in the
    /// collective-subject band `(1/√6, 1/√3]` (spec §18.2), so a full cell reads `Φ ≈ 1.2 ≥ 1`.
    pub healthy_correlation: f64,
    /// Whether the node acts on its diagnosis (reroute / repair / escalate). On by default; the
    /// reflexive loop *senses and acts* (spec §6.9). Set `false` for a sense-only node.
    pub self_healing: bool,
    /// How many *distinct* **cell-member** witnesses must corroborate a peer's liveness before it is
    /// believed on gossip alone (own direct observation is always trusted).
    ///
    /// # It has exactly one admissible value, and the shipped default used to be below it
    ///
    /// This path is the fallback for a peer this node cannot see *directly*, so the witnesses available are
    /// the cell minus the subject and minus this node: `n − 2`. Two constraints bracket the quorum:
    ///
    /// * **safety** — forging liveness must cost more than the tolerated coalition: `Q ≥ f + 1`;
    /// * **liveness** — the honest witnesses alone must be able to supply it: `Q ≤ n − 2 − f`.
    ///
    /// At the Fano cell (`n = 7`, `f = 2`) both meet at **3**: one lower and a tolerated coalition forges,
    /// one higher and an honest cell cannot corroborate. It was `2`, which tolerates `Q − 1 = 1` liar
    /// against a budget of `f = 2` — the same defect as #50 in the sibling reflexive quorum, fixed there and
    /// left standing here. (Feasible in general iff `2f ≤ n − 3`; Fano is the equality case, as it is for
    /// the liveness spare in #47.)
    ///
    /// `spec/protocol.md` §6.4 calls this "a plain corroboration quorum that merely counts vouchers" and the
    /// VOUCH/DENY endpoint detector *"strictly stronger"* — which stays true at `Q = 3`, since the judge
    /// tolerates `⌈(N−1)/2⌉ = 3` fabricators against this quorum's `Q − 1 = 2`. But the judge adjudicates
    /// after the fact; **this** predicate is what `coord_alive` decides on, so it has to be sized correctly
    /// on its own.
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

impl Config {
    /// This deployment's epoch in the reflex's own heartbeats — the denominator of the control confidence.
    ///
    /// `1.0` (a single opportunity) when either period is degenerate, so a misconfiguration produces a
    /// refusing derivation rather than a plausible one.
    #[must_use]
    pub fn heartbeats_per_epoch(&self) -> f64 {
        if self.heartbeat.0 == 0 || self.epoch_period.0 == 0 {
            return 1.0;
        }
        self.epoch_period.0 as f64 / self.heartbeat.0 as f64
    }

    /// The band-keeping loop's **control confidence** `z`, in standard errors — derived, not chosen: the
    /// smallest `z` at which the loop actuates on its own measurement noise less than once per epoch
    /// ([`fanos_diakrisis::window::control_confidence`], distribution-free by Cantelli).
    ///
    /// One derived quantity now stands where three chosen ones did — this, the window, and the shed's safety
    /// margin in `decouple_ceiling` — and all three move with the plane, the dwell and this node's clock.
    #[must_use]
    pub fn control_confidence(&self) -> f64 {
        fanos_diakrisis::window::control_confidence(BAND_DWELL as usize, self.heartbeats_per_epoch())
    }

    /// The behavioural-coherence observation window, in heartbeat samples: the cell's `Γ_net` is read from
    /// the last this-many per-node relay-activity samples.
    ///
    /// # It is a resolution, not a memory bound
    ///
    /// It used to be a constant `8` — four seconds — justified by "the self-model memory is `7 × this`".
    /// That bound does not bind: `7 × 8` doubles is **448 bytes**. Meanwhile the estimator's standard error
    /// at `W = 8` is `≈ 0.168` against a collective-subject band `(0.4082, 0.5774]` that is `0.169` **wide**,
    /// and because `(1−r)(1+(n−1)r)` is nearly flat across the band that held at *every* operating point
    /// inside it. The homeostat was regulating against boundaries its instrument could not resolve.
    ///
    /// [`resolving_window`](fanos_diakrisis::window::resolving_window) inverts the requirement — `z` standard
    /// errors must fit inside the band's half-width — giving **178** at the shipped 600 s epoch and 500 ms
    /// heartbeat, about 89 s of history. That the answer is a minute and a half rather than four seconds is
    /// the finding, not a cost: the regulated quantity is structural, inside an epoch, and **a controller
    /// cannot respond faster than the precision it needs allows it to measure.**
    ///
    /// A node therefore has no coherence self-model for its first `W` heartbeats. That is the honest state,
    /// and strictly better than what it replaces — a two-sample correlation is `±1` by construction, and
    /// acting on one is acting on nothing (#102).
    ///
    /// Floored at `2`, below which a correlation is undefined.
    #[must_use]
    pub fn behavior_window(&self) -> usize {
        // The base cell's point count — the `n` the band and the estimator are both stated for.
        fanos_diakrisis::window::resolving_window(7, self.control_confidence()).max(2)
    }

    /// The shortest epoch under which a directory slot's **grace window still buys what it exists for**.
    ///
    /// A `(coordinate, epoch)`-keyed slot outlives its own epoch by one, so a reader that has not yet seen
    /// the new beacon still finds what it is looking for. Reaching that grace slot costs a *failed* read of
    /// the current one first: [`read_timeout`](Self::read_timeout) to give up, concluded on the next
    /// [`heartbeat`](Self::heartbeat) because the sweep that concludes absence is paced by the beat. If that
    /// whole cost does not fit inside the epoch the reader started in, the grace slot is reclaimed while the
    /// miss is still timing out and the retention buys **nothing**: the lookup fails, the rotation keeps its
    /// cost and loses its defence, and nothing anywhere says why.
    ///
    /// So the requirement is `read_timeout + heartbeat < epoch_period`, and this is its left side. It is
    /// **necessary and not sufficient** — the publisher's own write costs the descriptor proof-of-work plus a
    /// store round trip, and an operator sets that (`--descriptor-pow`), so no constant can bound it here.
    ///
    /// Here rather than at the comparison because both quantities it reads are fields of *this* struct, and a
    /// derivation kept away from its inputs is one that drifts from them. The comparison itself belongs where
    /// an operator names the number, which is `fanos_node`'s config parser (#348).
    ///
    /// **Not** `fanos_diakrisis::regeneration::min_epoch_period`, which is this knob's *other* floor: that one
    /// is measured from the cell's live stability, so it can only ever be reported after the fact (the
    /// `Notification::EpochFloor` an operator sees), where this one is static and can be refused before the
    /// node starts. Two floors, two answers, and only one of them could ever have been a refusal.
    #[must_use]
    pub fn minimum_epoch_period(&self) -> Duration {
        Duration(self.read_timeout.0.saturating_add(self.heartbeat.0))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            heartbeat: HEARTBEAT_PERIOD,
            epoch_period: EPOCH_PERIOD,
            genesis: BeaconSeed::GENESIS,
            liveness_timeout: Duration::from_millis(1600),
            healthy_correlation: 0.45,
            self_healing: true,
            corroboration_quorum: corroboration_quorum(CELL_POINTS),
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

// **The load report's width, proven equal to the role count.** `fanos_ports` cannot see `Role`, so
// `Notification::LoadReport`'s `[Option<u16>; 5]` is a literal there. This is a site that sees both, so this
// is where they are tied together: a sixth role that widened one and not the other would otherwise truncate
// every reading in silence. Anonymous, so it is checked without being an item anyone can leave unread.
const _: () = assert!(
    fanos_ports::ROLE_COUNT == Role::COUNT,
    "the load-report width and the role count must agree",
);


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
    /// Which line through this node's point the next heartbeat probes for discovery — see
    /// [`sweep_targets`](Self::sweep_targets). Wraps; the plane's `q + 1` lines through a point are the
    /// whole schedule, so this needs no bound of its own.
    sweep: usize,
    /// This node's Fano point index (`Some` only on the base `N = 7` cell, where the reflexive
    /// loop's index-addressed geometry — syndrome, mediator, peeling — applies).
    self_index: Option<usize>,
    /// The explicit 7-member cell this node self-diagnoses with, when it is **not** the base plane's
    /// points `0..6` — i.e. a 7-node Fano cell embedded in a larger transport plane (a unified
    /// hierarchy). `None` on the base cell, where cell position `i` is `Point::at(i)`; `Some(members)`
    /// remaps position `i` to `members[i]`, so the whole index-addressed reflex runs unchanged over a
    /// cell seated anywhere. See [`cell_coord`](Self::cell_coord) / [`with_cell_members`](Self::with_cell_members).
    cell_members: Option<[Triple; 7]>,
    /// Whether [`cell_members`](Self::cell_members) was **derived from the plane** rather than provisioned.
    ///
    /// The two want opposite behaviour at an epoch boundary, and one field decides which. A *provisioned*
    /// cell is a committee at fixed transport points, so a `Reseat` that would move a node out of it is a
    /// provisioning contradiction and is refused. A *derived* cell is a function of the plane
    /// (`fano::cell_of`), so the node's cell **follows its coordinate**: at every reshuffle it lands in
    /// whichever cell its new point belongs to, and the roster is re-derived rather than defended.
    ///
    /// Without this distinction a derived roster would meet the refusal rule and a node would reject its
    /// **own** epoch reshuffle — freezing at its founding coordinate while the rest of the cell moved on,
    /// with every effect still firing.
    cell_roster_derived: bool,
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
    /// Epoch ordinals gossiped by each cell member (`FrameType::EpochAgree`), keyed by the **claimant's**
    /// proven coordinate so each member overwrites only its own (#351).
    ///
    /// Deliberately the shape of [`witnessed`](Self::witnessed), because it answers the same question that
    /// map answers — *a quorum of distinct members must vouch* — asked about the epoch ordinal rather than
    /// about liveness. The spec's `adopt-max` (see [`epoch`](Self::epoch)) is sound for the object it was
    /// written about, a threshold-DVRF round that cannot be forged; this frame carries a bare four-byte
    /// ordinal with none of that authentication, and inherited the rule without its premise.
    ///
    /// **Pruned when the epoch advances, not on a timer.** A claim is worthless once the cell has reached it,
    /// and `on_epoch_changed` is exactly that moment — so the map needs no window and no chosen constant.
    /// Reusing `liveness_timeout` would have been wrong on the merits, not merely on de-duplication grounds:
    /// liveness gossip arrives every heartbeat and epoch gossip only on an epoch turn, so a window sized for
    /// the first expires the second long before its successor arrives and the quorum becomes unreachable.
    epoch_claims: BTreeMap<Triple, Epoch>,
    /// §6.3 grey detection: the freshest `DiagLoss` row each cell member gossiped — its measured per-neighbour
    /// loss vector (`[u8; 7]`, `loss × 255`) and when it arrived. Assembled with this node's own row into the
    /// symmetric channel-rate matrix `polar::grey_endpoint` localizes a grey node from (a lossy node lifts
    /// every channel incident to it). Bounded by the cell size.
    loss_reports: BTreeMap<Triple, ([u8; 7], Instant)>,
    /// Dedup for the grey diagnosis: the grey node currently reported, so `Notification::Grey` fires once on
    /// onset (and again only if a *different* node goes grey), cleared when the cell reads grey-free.
    grey_reported: Option<Triple>,
    /// Dedup for the version-skew escalation: the `(unknown critical type, sender)` pairs already reported,
    /// so `Escalation::UnsupportedCritical` fires **once per pair** rather than once per frame (#341).
    ///
    /// **Bounded by two finite vocabularies, neither of them attacker-chosen.** The escalation fires only
    /// when [`FrameType::group_is_critical`] holds — `code >> 4 == 0x1`, so codes `0x10`–`0x1F` and nothing
    /// else — minus every code this build can name. That count is
    /// [`FrameType::UNKNOWN_CRITICAL_CODES`], and the other axis is a plane point, so the set is bounded by
    /// `UNKNOWN_CRITICAL_CODES × (q² + q + 1)`. A peer cycling type codes buys itself no growth, which is why
    /// this needs no cap of its own (contrast `MAX_SKEW_TAG`, whose station IS tagged by any code and
    /// therefore does need one).
    ///
    /// **The number used to be written here by hand, and it went stale.** The sentence read *"this build
    /// names `0x11`–`0x1C`, leaving exactly four codes … `4 × (q² + q + 1)`: 28 entries on Fano"*, which was
    /// true until `DkgCommitReq = 0x1D` joined the registry. Nothing re-counted: the bound over-stated
    /// itself by one code — harmless, since it only sizes an argument — but the same stale range had also
    /// been copied into a test, where it picked `0x1D` as an example of a code this build cannot name. That
    /// assertion had quietly stopped being about anything.
    ///
    /// Derived, it has since absorbed a second variant without a word being edited here: `DkgConfirm = 0x10`
    /// took the group's last unnamed low code, and the count moved from three to two on its own.
    ///
    /// **Never cleared, and that is the design rather than an omission.** "Which release is this peer on"
    /// is a LEVEL, and the level already has its own always-current channel one line down —
    /// [`Station::FrameTypeUnknown`], which an operator polls. The event channel's job is to say it happened,
    /// once. (`BeaconShareMismatch` re-emits every epoch for the opposite reason: it has no station.)
    skew_reported: BTreeSet<(u64, Triple)>,
    /// The DHT-storage concern — this node's local store slice + read-repair bookkeeping (spec §L4). A
    /// value lives on its responsible content point and is cell-replicated for LRC availability, so any
    /// survivor answers a lookup (a lookup to a *down* primary reroutes through the self-healing table,
    /// §6.7). Factored into a [`Store`] collaborator (audit #125 decompose); the facade orchestrates.
    store: Store,
    /// The current epoch, driven by the flooded beacon (adopt-max, spec §L3). Epoch-derived
    /// rendezvous/shapes rotate as it advances.
    epoch: Epoch,
    /// The **data-path plane's** counters for this engine (`docs/design-observability.md`): where an
    /// announcement stopped, counted by structure.
    ///
    /// The threshold engines had these and an ordinary overlay node had none, so `fanos status stations` could
    /// only ever time out on the most common deployment there is — and two of the three refusals below returned
    /// a bare `Vec::new()`, which is the invisible discard this plane exists to end.
    stations: Stations,
    /// Per-role load readings pushed in from **outside this engine** — the sensors for roles the overlay itself
    /// cannot see (docs/design-observability.md §7).
    ///
    /// The overlay counts two of the five roles first-hand: storage (keys it holds) and relay (forwarding
    /// activity, counted in the healer). Service, exit and rendezvous are carried by *sibling* engines a
    /// composite owns — the service line, the clearnet exit, the rendezvous gatherer — and an engine that
    /// depended on any of them to read a number would have inverted the layering. So the composite pushes its
    /// readings in through [`observe_load`](Self::observe_load) and they leave on the next observation, in the
    /// one report the role controller already consumes.
    ///
    /// [`RoleReading::blind`] until something reports: a role no one measures stays `None`, and the driver's
    /// offer stands in for it. That is the *only* remaining fallback, and it now fires on absence rather than on
    /// a zero, so a measured idle role is believed.
    load_sensors: RoleReading,
}

/// A stable 16-byte identifier for a node's cell — a domain-separated hash of **this network's genesis seed**
/// and the canonical Fano point coordinates, so every node in the cell derives the *same* id and their
/// coherence frames agree on which cell they describe.
///
/// **The seed is what makes the id a cell's and not a plane's (#210).** Without it this is a pure function of
/// the plane order: every FANOS deployment ever founded on Fano emits the identical 16 bytes, so a `(cell_id,
/// epoch)` roll-up — the one thing the id exists for — silently merges frames from unrelated networks, and the
/// merge looks like agreement rather than an error. Folding the seed is the same move the platform already
/// makes for the address space (`fanos_quic::Directory::for_network`) and for rendezvous slots (`service_tag`),
/// and it costs nothing: the seed is public, `Copy`, and already in every node's config.
///
/// What it does **not** buy: two cells of the *same* deployment still collide, because the runtime has no
/// identity above the base cell to fold in. That is the open cell-identity question (#167), not this function's
/// to answer — and stating it here is deliberate, because a per-network id reads like a per-cell id.
pub(super) fn cell_id<F: Field>(genesis: BeaconSeed) -> CellId {
    let mut input = Vec::with_capacity(32 + 7 * 12);
    input.extend_from_slice(genesis.as_bytes());
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
        // Local history stays compact and bounded. The observer takes no window length: every fold is
        // stamped with the cell's AGREED epoch by its caller, never with local elapsed time (audit A3).
        let observer = SelfObserver::new(cell_id::<F>(config.genesis), HistoryConfig::compact());
        Self {
            coord,
            router: Router::new(coord),
            membership: Membership::default(),
            config,
            started_at: Instant::default(),
            peers,
            heartbeating: false,
            sweep: 0,
            self_index,
            cell_members: None,
            cell_roster_derived: false,
            parent_cell: None,
            healer: Healer::new(observer, config.behavior_window(), config.control_confidence()),
            witnessed: BTreeMap::new(),
            epoch_claims: BTreeMap::new(),
            loss_reports: BTreeMap::new(),
            skew_reported: BTreeSet::new(),
            grey_reported: None,
            store: Store::default(),
            epoch: Epoch::ZERO,
            stations: Stations::new(),
            load_sensors: RoleReading::blind(),
        }
    }

    /// Record what a **sibling engine** measured for `role`, to be reported on the next observation.
    ///
    /// The composite that owns the mix router, the rendezvous gatherer and the service line calls this; the
    /// overlay stores the latest reading and folds it into the load report the role controller reads. Latest
    /// wins, and a role never reported stays absent — see ``load_sensors``.
    ///
    /// This is the seam that keeps the layering right: the engine that *can* see a role's work reports it, and
    /// the engine that assembles the report needs to know about none of them.
    pub fn observe_load(&mut self, role: Role, load: u16) {
        self.load_sensors = self.load_sensors.measuring(role, load);
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
    ///
    /// **`None` for every coordinate when there is no cell to be a position in**, and that is the fourth
    /// place the same invariant is written. The reflex is index-addressed over a **Fano** cell: seven points,
    /// seven lines, no three collinear. Without an explicit roster the fallback is the base plane's
    /// `Point::at(0..6)` — which is that cell only when `N == 7`. Measured on `PG(2,7)`: `at(0..6)` are
    /// `[1,0,0]…[1,0,6]`, **all seven on the single line `[0,1,0]`**, and the pairs of that set span exactly
    /// **one** line where a Fano cell spans seven. Answering `Some(i)` there is answering confidently and
    /// wrongly, which is worse than declining ([[a-probe-must-admit-only-reachable-states]]).
    ///
    /// The emitting side is already closed and by a different mechanism: all three diagnostic frames are
    /// built inside one `cell_liveness(..)?`, whose first line is `self.self_index?`, and the constructor
    /// leaves `self_index = None` unless `N == 7`. So on a larger plane this node sends no diagnostics — but
    /// it would still have *accepted* them, folding a stranger's row onto a position of a set that is not a
    /// cell. Guarding both ends means the pair cannot drift apart silently (#242).
    fn cell_position(&self, coord: Triple) -> Option<usize> {
        match &self.cell_members {
            Some(members) => members.iter().position(|&m| m == coord),
            None if Plane::<F>::N == 7 => (0..7usize).find(|&i| Point::<F>::at(i).coords() == coord),
            None => None,
        }
    }

    /// Seat this node in an explicit 7-node Fano cell (`members`, in canonical position order) rather than the
    /// base plane's points `0..6` — for a cell embedded in a larger transport plane (a unified hierarchy). Sets
    /// the reflexive `self_index` to this node's position and rebuilds the cell peer set from the six other
    /// members, so liveness sensing, witnessing, and the whole reflex run over the real cell.
    ///
    /// **The argument is a [`CellMembers`](fano::CellMembers), not seven bare coordinates,
    /// and that is the fix rather than a style choice.** Everything downstream reads `fano::LINE_POINTS` on
    /// *indices* — `polar_class`, `theme_flags`, `cell_liveness`, `grey_rate_matrix` — so those tables are a
    /// claim about the coordinates, and nothing used to check it. Seven points in the wrong order left every
    /// polar identity, line gather and syndrome addressing triples that are **not collinear in the transport
    /// plane**: the alarms stay quiet and the diagnosis describes a cell that does not exist. Constructing
    /// the argument is now the check, so there is no call a caller can forget.
    #[must_use]
    pub fn with_cell_members(mut self, cell: fano::CellMembers<F>) -> Self {
        let members = cell.coords();
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

    /// Seat this node in the cell **the plane says it belongs to** — `fano::cell_of(coord)` — rather than
    /// in a provisioned roster. A no-op when the plane does not split (`7 ∤ N`), which is the honest
    /// outcome rather than a cell invented for it.
    ///
    /// This is #145's answer wired: *"which seven of my peers are my cell"* is `index mod (N/7)`, a pure
    /// function of the plane that every node computes identically, so no agreement round is needed. At
    /// `q = 2` it degenerates to exactly the base-plane behaviour — one cell whose roster is
    /// `Point::at(0..7)` — so it **unifies** the `N == 7` special case rather than adding a second one.
    ///
    /// Unlike [`with_cell_members`](Self::with_cell_members), the roster this installs is re-derived at
    /// every reshuffle: see [`cell_roster_derived`](Self::cell_roster_derived) for why the two must differ
    /// there and what happens if they do not.
    #[must_use]
    pub fn with_derived_cell(mut self) -> Self {
        let Some(index) = fano::cell_of(self.coord) else {
            return self; // the plane does not split — no cell to seat this node in
        };
        let Some(cell) = fano::cell_members_of::<F>(index) else {
            return self;
        };
        self = self.with_cell_members(cell);
        self.cell_roster_derived = true;
        self
    }

















    /// Record that a frame arrived from `from` — the single expression of "a node lives at that point".
    ///
    /// Read by `occupied_points`, which is the only input to shard placement and to the denominator a
    /// definite `Absent` must exhaust, so this mark decides where values are written and whether a read may
    /// claim the cell holds nothing. It is cleared at every seating change, never on a clock: see
    /// `occupied_points` for the measurement that settled which.
    ///
    /// The first frame from a coordinate in an epoch raises [`Station::OverlayFirstHeard`]. Bounded by
    /// construction — one per peer per epoch, since the boundary is what clears the mark — and it is the
    /// observable that separates "this node cannot address that peer" from "it can address it and no frame
    /// ever arrives", which are different faults with different repairs and were the same silence.
    fn note_heard(&mut self, now: Instant, from: Triple) {
        let Some(peer) = self.peers.get_mut(&from) else {
            return; // not an algebraic neighbour: nothing here is addressed by its coordinate
        };
        let first = peer.last_seen.is_none();
        peer.last_seen = Some(now);
        peer.reported_down = false;
        if first {
            self.stations.record(Station::OverlayFirstHeard, Some(from));
        }
    }

    fn on_message(&mut self, now: Instant, from: Triple, frame: &[u8]) -> Vec<Effect> {
        // A locally-quarantined (Byzantine) member's frames are dropped (spec §6.2, §6.4) — but only for
        // the bounded quarantine window; once it elapses the [`Healer`] re-admits the member for
        // re-evaluation, so a transient fault is not a permanent exile (audit C5).
        if self.healer.is_quarantined(from, now) {
            // Counted, because this drop is OURS. Every other silence is ambiguous between the peer, the path
            // and us; this one is a decision this node made, and it looked identical to the peer vanishing.
            self.stations.record(Station::QuarantineDropped, None);
            return Vec::new();
        }
        let Ok((frame, _)) = decode_frame(frame) else {
            // Unattributed: nothing parsed, so there is no type code and no claim to make about who sent it.
            self.stations.record(Station::FrameDecodeFailed, None);
            return Vec::new(); // canonical decode failure — drop (spec §7.5)
        };
        // **Here, once, for every frame that parses — and it used to be five copies and three omissions.**
        //
        // `from` is the coordinate the transport *proved* before delivering, so a frame arriving at all is
        // direct evidence that a node lives at that point. Five arms wrote `last_seen = Some(now)` by hand
        // (Pong and four diagnostics) and the rest did not, so `Ping`, `Route`, `RouteHier` and `App` — every
        // one of them a frame from a live peer — proved nothing about their sender.
        //
        // `Ping` is the sharp one. Under asymmetric loss, A's pings reach B while B's pongs are dropped: A
        // then holds B's pings in its own dispatch and still concludes B is absent, because only the *answer*
        // counted. The occupancy view that decides shard placement and a read's definite `Absent` is built
        // from exactly this mark, so an unread ping is a member the cell cannot place shards on or find
        // records at.
        self.note_heard(now, from);
        // Counted per frame, not per first contact: `overlay.first_heard` says contact happened at all, and
        // the question the fleet leaves open is one of *volume* — a node writing ~150 frames to a live
        // connection whose peer's engine is never stepped. The send side is counted on the driver plane; this
        // is the only place the receiving side can be.
        self.stations.record(Station::OverlayFrameIn, Some(from));
        match frame.frame_type() {
            Some(FrameType::Ping) => alloc::vec![Effect::Send {
                to: from,
                frame: encode(FrameType::Pong, &[]),
            }],
            Some(FrameType::Pong) => {
                if let Some(peer) = self.peers.get_mut(&from) {
                    // Pong-specific, and the only part of the old block that was: `note_heard` above records
                    // the evidence; this records that *our* ping was the thing answered (§6.3 loss sample).
                    peer.awaiting_pong = false;
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
                self.healer.clear_healing(from);
                self.apply_health_view(now, from, frame.body);
                Vec::new()
            }
            Some(FrameType::DiagAttest) => {
                // Likewise a direct observation of the sender (spec §6.4); folds its polar-class
                // report into the cross-attestation store `attested_pairwise_rates` assembles from.
                self.healer.clear_healing(from);
                // Member-only, like its two sibling diagnostics: `attested_pairwise_rates` reads this store
                // for the seven cell coordinates alone, so a non-member's row could never be read and would
                // never be evicted either.
                if self.cell_position(from).is_some() {
                    self.healer.apply_diag_attest(now, from, frame.body);
                }
                Vec::new()
            }
            Some(FrameType::DiagLoss) => {
                // The sender's measured per-neighbour loss row (spec §6.3 grey); stored for the grey-detection
                // matrix. Also a direct observation of the sender's liveness, like the other diagnostics.
                self.apply_diag_loss(now, from, frame.body);
                Vec::new()
            }
            Some(FrameType::Publish) => self.on_publish(now, from, frame.body),
            Some(FrameType::Lookup) => self.on_lookup(from, frame.body),
            Some(FrameType::Value) => self.on_value(now, from, frame.body),
            Some(FrameType::Ack) => Self::on_ack(frame.body),
            Some(FrameType::Announce) => self.on_announce(frame.body),
            Some(FrameType::EpochAgree) => self.on_epoch_agree(from, frame.body),
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
            Some(FrameType::Error) => self.on_error(from, frame.body),
            // **The reachable version-skew site.** A composite routes by frame type, so a type nobody claims
            // arrives here — this is where a peer on a different release actually lands in a deployed node,
            // not at a threshold engine whose composite filtered the frame away before it could see one.
            //
            // Counted with the type code *and* the sender, because `design-upgrade.md` §4's question is
            // "does any hop line hold fewer than `t` members that agree", and neither dimension answers it
            // alone: the code says which release, the sender says which line.
            _ => self.on_unclaimed_type(&frame, from),
        }
    }

    /// A frame this dispatch has no arm for — **two findings with opposite remedies**, told apart here.
    ///
    /// The seventeen arms above claim a type each; everything else lands in one place, and for a long time
    /// under one name. `frame_type()` resolving is the whole discriminator: `Some(_)` means the registry has
    /// a name for the code, so the sender is on *this* protocol and the frame simply reached a plane that
    /// does not serve it — a **dispatch** fact. `None` means this build cannot name the code at all, which is
    /// the **release** fact `design-upgrade.md` §4 asks about.
    ///
    /// Measured, and the size is the argument: a five-node cell of ONE binary — where skew cannot occur by
    /// construction — raised the skew station **130 times in 60 s**, every event the handshake's own tail
    /// (`HelloAck`, `0x01`) arriving here. The count was not noise around a signal, it was the entire count.
    fn on_unclaimed_type(&mut self, frame: &fanos_wire::Frame<'_>, from: Triple) -> Vec<Effect> {
        if frame.frame_type().is_some() {
            self.stations.record_tagged(
                Station::FrameTypeUnhandled,
                Some(from),
                Some(frame.type_code),
                1,
            );
            // **No `UnsupportedCritical` from here, deliberately.** That escalation says a *peer* is speaking
            // a code this build does not support; a code it does support, delivered to a plane that does not
            // serve it, is this node's own dispatch, and accusing the sender of it would put a second false
            // statement where the first one already was.
            return Vec::new();
        }
        {
                // The **raw** `type_code`, not `frame_type()`. The enum cannot represent a code this build
                // does not know — that is what makes it unknown — so resolving through it discards precisely
                // the evidence the station exists to carry, and records a skew observation with nothing in it.
                // Caught by the test, which asserted the code and got `None`.
                self.stations.record_tagged(Station::FrameTypeUnknown, Some(from), Some(frame.type_code), 1);
                // **Skippable or fatal, and the wire decides which** (spec §7.2). Skipping is right when
                // ignorance costs availability; it is wrong when it costs agreement, which is the membership
                // group and only it — a node that quietly drops a beacon round or a reshare keeps serving on
                // a retired epoch, indistinguishable from a healthy one. The rule was stated in three places
                // and implemented in none: `WireError::UnknownCriticalFrame` had no site that could build it.
                // ONCE PER (code, sender), not once per frame (#341). The station above counts every one;
                // this channel ends at `warn!` with no dedup on the path, so emitting per frame let a peer
                // mint an operator-visible line per frame it chose to send — measured at exactly 1:1 before
                // this guard existed, by `a_peer_mints_one_escalation_per_unknown_critical_frame_it_sends`.
                if FrameType::group_is_critical(frame.type_code)
                    && self.skew_reported.insert((frame.type_code, from))
                {
                    alloc::vec![Effect::Notify(Notification::Escalated(crate::ports::Escalation::UnsupportedCritical {
                        type_code: frame.type_code,
                        from,
                    }))]
            } else {
                Vec::new()
            }
        }
    }

    /// Decode an `Error` frame, act on the one kind a node can act on, and **count every kind**.
    ///
    /// A refusal that names a price this node can afford is repaid **here**: the admission difficulty is raised
    /// and the proof re-minted, exactly as [`on_reseat`](Self::reseat) already does when the coordinate moves.
    /// Above [`MAX_INLINE_ADMISSION_BITS`] it is only reported, because the work would block the engine.
    ///
    /// **Having nothing to do is not having nothing to say.** This used to `return Vec::new()` for every code
    /// but `SybilReject` — fourteen of the fifteen classes the protocol defines. A peer that refuses us states
    /// why on the wire, and `decode_error`'s own doc keeps the code *unresolved* precisely "so a caller can
    /// log/react to a future error class this build does not know"; the one caller resolved nothing and
    /// reacted to one code. During a version rollout that refusal is the entire diagnostic — the joining node
    /// otherwise reports only a peer that will not talk (#198).
    ///
    /// The `SybilReject` asymmetry stays, because it is the only class with an *action*. What changed is that
    /// the other fourteen now leave a trace, tagged by [`fanos_wire::ProtocolError::index`] so an operator can tell an
    /// `Unsupported` rollout wall from a `BadCoord` attack.
    fn on_error(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some((code, reason)) = crate::frames::parse_error(body) else {
            // Not a refusal we can name — a refusal we cannot read, which is likelier to be our own fault:
            // #75 found two incompatible ERROR encodings with only one in the conformance vector.
            self.stations.record(Station::PeerRefusalUnreadable, Some(from));
            return Vec::new();
        };
        // A code this build does not recognise is still counted, untagged — the honest reading, and the same
        // rule `FrameTypeUnknown` follows for a wire code outside its registry.
        self.stations.record_tagged(
            Station::PeerRefused,
            Some(from),
            fanos_wire::ProtocolError::from_code(code).map(fanos_wire::ProtocolError::index),
            1,
        );
        if code != fanos_wire::ProtocolError::SybilReject.code() {
            return Vec::new();
        }
        // The outcome is the engine's to determine and the driver's to act on: only this function knows
        // which of `repay_admission`'s three guards fired, and re-deriving it outside would mean a second
        // copy of the ceiling and of `paid_difficulty` (#199).
        let outcome = match crate::frames::decode_required_difficulty(reason) {
            Some(bits) => self.repay_admission(bits),
            None => AdmissionOutcome::NoGuidance,
        };
        alloc::vec![Effect::Notify(Notification::AdmissionRefused { outcome })]
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
    ///
    /// Returns which of the three guards decided, because "did this node spend anything, and will a retry
    /// help" is not recoverable from `required` alone — and it is the whole of what a driver and an operator
    /// need (#199). The two early returns are dead ends and used to be indistinguishable from the one that
    /// self-corrects.
    fn repay_admission(&mut self, required: u32) -> AdmissionOutcome {
        let current = self.membership.paid_difficulty.unwrap_or(0);
        if required <= current {
            return AdmissionOutcome::AlreadySufficient { paid: current, asked: required };
        }
        if required > MAX_INLINE_ADMISSION_BITS {
            return AdmissionOutcome::AboveCeiling {
                asked: required,
                ceiling: MAX_INLINE_ADMISSION_BITS,
            };
        }
        let coord = self.coord.coords();
        self.membership.paid_difficulty = Some(required);
        self.membership.admission_proof = PowAdmission::new(required)
            .solve(&admission_challenge(&self.membership.identity, coord, self.epoch));
        AdmissionOutcome::Repaid { bits: required }
    }

    /// Force the measured stress, so a test can exercise a law that normally waits on an observation.
    #[cfg(test)]
    pub(crate) fn stress_for_test(&mut self, stress: f64) {
        self.healer.set_stress_for_test(stress);
    }

    /// This node's current admission proof — for tests that assert it was (or was not) re-minted.
    #[cfg(test)]
    pub(crate) fn admission_proof_for_test(&self) -> &[u8] {
        &self.membership.admission_proof
    }

    /// The difficulty this node currently pays — for tests that assert it did (or did not) move.
    #[cfg(test)]
    pub(crate) fn paid_difficulty_for_test(&self) -> Option<u32> {
        self.membership.paid_difficulty
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
    /// its own endpoint (§80). The signing secret is never handed to the engine.
    ///
    /// **"Signs once" is wrong, and it is why this has no production caller.** The message includes the
    /// **transport** coordinate, which the per-epoch VRF reshuffle re-draws — so a signature made at
    /// provisioning is stale at the first boundary and every honest announce fails the binding check from
    /// then on. A working producer has to re-sign at **every reseat**, which is a runtime path this builder
    /// cannot be. [`Command::Descriptor`] is that path: the host signs for the coordinate it is **about to**
    /// reseat to and sends it first, so the announce that follows carries a signature over the coordinate it
    /// names. This builder remains the right way to seat the first one, before the node has moved at all.
    /// See `fanos_node::config::OverlayChoices::require_self_certified_membership` for the rest of that
    /// switch's state.
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
    /// (``on_reseat``) — keeping it valid for a peer's per-epoch check as the coordinate
    /// rotates, which is the "re-paid every epoch" cost that makes a grinded seat un-maintainable. This is
    /// the complete "join under a per-admission cost" setup; a deployment picks `difficulty` to price a join
    /// at ~`2^difficulty` hashes. Prefer this to wiring [`with_admission_policy`](Self::with_admission_policy)
    /// + [`with_admission_proof`](Self::with_admission_proof) by hand when the policy is PoW.
    #[must_use]
    pub fn with_admission_pow(self, difficulty: u32) -> Self {
        self.demanding(difficulty).paying(difficulty)
    }

    /// **Demand** `bits` of every joiner — install the admission gate at that floor.
    ///
    /// Adaptive above the floor: the coherence controller raises the live price as the cell's measured stress
    /// rises, which is the only response FANOS has that acts on the *magnitude* of a flood rather than on its
    /// aftermath (T-104: a cell survives iff `‖h‖ < κ·r_stab`, and everything else moves `κ`). It can never go
    /// under the floor, so a stuck sensor or a compromised controller cannot open a door the operator closed.
    /// At rest the live value equals the floor, so an unstressed node behaves exactly as a fixed gate did.
    #[must_use]
    pub fn demanding(mut self, bits: u32) -> Self {
        self.config.require_admission = true;
        let live = LiveDifficulty::new(bits);
        self.membership.admission_policy = Some(Box::new(AdaptivePowAdmission::new(bits, live.clone())));
        self.healer.set_admission(bits, live);
        self
    }

    /// **Pay** `bits` — mint this node's own admission proof at that difficulty, and re-mint it there whenever
    /// the coordinate moves.
    ///
    /// Separate from [`demanding`](Self::demanding), and the separation is the point: a node's own proof has to
    /// satisfy its *peers'* gates, and its own gate has nothing to do with it. While the two shared one number,
    /// raising the price a node charged forced it to pay that same price itself — a cost with no purpose, and
    /// one that made a scenario test spend 48 seconds minting a proof nobody was going to check.
    ///
    /// A peer that turns this node away raises it, bounded — see `repay_admission`.
    #[must_use]
    pub fn paying(mut self, bits: u32) -> Self {
        self.membership.paid_difficulty = Some(bits);
        self.membership.admission_proof = PowAdmission::new(bits)
            .solve(&admission_challenge(&self.membership.identity, self.coord.coords(), self.epoch));
        self
    }

















    fn on_send(&mut self, to: Triple, payload: &[u8]) -> Vec<Effect> {
        // This node putting a data frame on the wire is its own behavioural activity (the self slot of the
        // sample), recorded against the destination that will count it.
        self.healer.record_origination(to);
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

    /// This node's **durable state** as canonical bytes, for a host that can write a file.
    ///
    /// The store is the only thing in a node worth keeping across a restart that the network cannot hand
    /// back for free, and `fanos-runtime` is sans-I/O and `no_std` — it cannot open a file and should not
    /// learn how. So the split is: the engine says *what* is durable and in what bytes, and the host says
    /// *where* and *when* (`Store::snapshot` states what is in it and what is deliberately
    /// left out).
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        self.store.snapshot()
    }

    /// Adopt a [`snapshot`](Self::snapshot) taken by a previous run of this node, returning whether it was
    /// accepted. A rejected snapshot leaves the store untouched and **empty is the correct fallback** — the
    /// cell's `[7,3,4]` code re-heals one node's missing shards, which is precisely the case this whole
    /// mechanism exists to make rarer rather than impossible.
    ///
    /// Adopt it **before** the node starts serving. Restoring over a store that has already accepted writes
    /// would discard them, so this refuses once anything is held: the caller's mistake is then visible at
    /// startup rather than as data that quietly disappeared.
    pub fn restore(&mut self, bytes: &[u8]) -> bool {
        if !self.store.entries.is_empty() {
            return false;
        }
        match Store::restore(bytes) {
            Some(store) => {
                self.store = store;
                true
            }
            None => false,
        }
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
        // The data-path plane goes out **unconditionally**, unlike the coherence observation, which needs a
        // liveness view it may not have yet. A node too young or too alone to compute `Γ_net` is exactly the one
        // an operator asks where the work is stopping, and answering nothing there would make the verb useless
        // in the case it exists for.
        let mut out = alloc::vec![Effect::Notify(Notification::DataPath {
            stations: self.stations.observations(),
            // Stated, not implied: the overlay runs no threshold gather, which is different from having one
            // that has never completed, and only a variant can carry that.
            gather: GatherHealth::NoGatherPath,
        })];
        if let Some((_, degraded, alive_count)) = self.cell_liveness(now) {
            // The full footprint, beside the frame that carries only its syndrome. Computed here already and
            // discarded until now — an operator's node map cannot be reconstructed from a 3-bit code that
            // localizes one fault when there may be three.
            out.push(Effect::Notify(Notification::Liveness {
                epoch: self.epoch,
                degraded,
                responsive: self.responsive_mask(now),
                alive: u16::try_from(alive_count).unwrap_or(u16::MAX),
            }));
            out.push(self.healer.emit_observation(
                now,
                self.epoch,
                alive_count,
                degraded,
                self.config.healthy_correlation,
            ));
        }
        out
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
        let responsive = self.responsive_mask(now);
        // The same reading the sense-only `Observe` raises, raised here too — because `Observe` has one
        // production caller (the operator's `admin` read) while THIS runs every heartbeat, and the role loop
        // needs the pair every epoch to publish its diagnosis (`fanos_node::diagdir`). A notification only an
        // operator can provoke is not a sensor the cell can be driven by.
        let mut effects = alloc::vec![Effect::Notify(Notification::Liveness {
            epoch: self.epoch,
            degraded,
            responsive,
            alive: u16::try_from(alive_count).unwrap_or(u16::MAX),
        })];
        effects.extend(self.healer.diagnose::<F>(
            now,
            self_index,
            degraded,
            alive_count,
            Some(healthy_lines),
            Some(responsive),
            &self.config,
            self.epoch,
            &mut self.stations,
        ));
        // The load this node is carrying, reported every observation — it needs no coherence matrix, only the
        // counts the node already keeps, and the role controller's setpoint is its one real input.
        //
        // Assembled here rather than by the healer, and the move is what the sensor correction earned: the
        // healer used to *add* `Role::Relay` from its coherence self-slot, so the report had two authors. It
        // measured the wrong subject (frames this node **originated** — its work as a source, not the work it
        // carries for others) and it silently overwrote whatever a composite had reported for that role. With
        // that reading gone the healer contributed nothing, and a method that ignores its own `self` is a
        // justification held by a non-member. So the reading is complete where it is assembled: the overlay
        // adds the one sensor it owns, and every other role arrives through `observe_load`.
        //
        // The report's width is proven against `fanos_ports::ROLE_COUNT` by a const assertion at module scope.
        effects.push(Effect::Notify(Notification::LoadReport {
            per_role: self.load_sensors.counting(Role::Storage, self.store.entries.len()).into_array(),
        }));
        // R-C2: the Healer raises the `Escalated` NOTIFICATION but has no router — the facade (which owns the
        // hierarchical address) transports the residue up to the parent cell's sibling members, where it folds
        // into their `ParentCell` reflex. Origination lives here so a driver on any transport gets it.
        let escalations: Vec<u8> = effects
            .iter()
            .filter_map(|e| match e {
                // Only a node-set is forwardable: `escalate_to_parent` asks the parent to help with
                // *these members*, and a coherence collapse names none. It used to send an empty set.
                Effect::Notify(Notification::Escalated(crate::ports::Escalation::Faults(mask))) => Some(*mask),
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

    /// The points this node still hears from **at all**: bit `i` set ⇔ some fresh sighting of cell point `i`
    /// exists, direct or witnessed, with **no corroboration quorum required**.
    ///
    /// The weaker half of a deliberate pair. [`coord_alive`](Self::coord_alive) asks whether a point is
    /// reliable enough to route through, and sizes its witness count against the cell's Byzantine budget;
    /// this asks only whether the point is *there*. **One witness proves an endpoint exists, a quorum proves
    /// it is dependable** — and the difference between those two questions is exactly the difference between
    /// a lossy cut and a crash, which is what `diagnose` needs to tell a `Partition` from an `Escalate`.
    ///
    /// A count of sightings, never a loss rate, so no threshold appears here to be got wrong: a node behind a
    /// 92 %-loss cut still lands a probe within the window; a crashed one lands none, ever.
    ///
    /// Self always reads responsive — a node that could not hear itself would report its own coordinate as a
    /// crashed endpoint and turn every real cut into an escalation.
    fn responsive_mask(&self, now: Instant) -> u8 {
        let timeout = self.config.liveness_timeout;
        let mut mask = 0u8;
        for i in 0..7usize {
            let coord = self.cell_coord(i);
            let heard = coord == self.coord.coords()
                || self
                    .peers
                    .get(&coord)
                    .and_then(|p| p.last_seen)
                    .is_some_and(|seen| now.since(seen) <= timeout)
                || self.witnessed.get(&coord).is_some_and(|w| {
                    w.values().any(|&seen| now.since(seen) <= timeout)
                });
            if heard {
                mask |= 1u8 << i;
            }
        }
        mask
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

    /// The shortest epoch period this cell's own measurements say it can sustain, **in seconds**.
    ///
    /// `None` until an epoch advance has been observed — the cost of one is a difference *across* that
    /// boundary and cannot be read from a single window. Comparing it against the configured period compares a
    /// cadence against what the cell measures it can absorb; below the floor the cost is not churn but
    /// accumulation, since a cell reshuffled faster than it reintegrates never reaches a steady state. See
    /// `fanos_diakrisis::regeneration::min_epoch_period`.
    #[must_use]
    pub fn epoch_floor_seconds(&self) -> Option<f64> {
        self.healer.epoch_floor_seconds()
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
            Input::Command(Command::Broadcast { frame }) => alloc::vec![Effect::Flood { frame }],
            Input::Command(Command::Diagnose) => self.on_diagnose(now),
            Input::Command(Command::Observe) => self.on_observe(now),
            // Sense-only, like `Observe` beside it: the store is read, nothing is armed, nothing moves.
            Input::Command(Command::Snapshot) => {
                alloc::vec![Effect::Notify(Notification::Snapshot(self.store.snapshot()))]
            }
            Input::Command(Command::Put { key, value }) => self.on_put(now, &key, &value),
            Input::Command(Command::PutEphemeral { key, value, epochs }) => {
                // Record the lifetime BEFORE the write, so an entry can never be stored without one: a
                // slot that reached the store as content would be immortal, which is the whole defect.
                self.store.expires(storage_digest(&key), self.epoch.saturating_add(u64::from(epochs)));
                self.on_put(now, &key, &value)
            }
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
            // Installed silently: it replaces provisioning that was already this node's own, carries no
            // decision, and emits nothing. The announce that follows the `Reseat` is where it becomes
            // visible — which is exactly why the ordering rule is on the command's own doc.
            Input::Command(Command::Descriptor { id, sig }) => {
                self.membership.identity = id;
                self.membership.descriptor_sig = sig;
                Vec::new()
            }
            Input::Command(Command::PeerHandshaken { coord, identity }) => {
                self.on_peer_handshaken(now, coord, identity)
            }
            Input::Command(Command::Reseat { coord }) => self.on_reseat(coord),
            Input::Command(Command::ProposeAddress { contested }) => self.on_propose_address(contested),
            Input::Command(Command::Descend { path }) => self.on_descend(&path),
            Input::Timer(HEARTBEAT) if self.heartbeating => self.on_heartbeat(now),
            // An unarmed timer, and a sub-engine control message — inert here for the same reason: neither names
            // anything this engine owns. The overlay composes no sub-engine that takes a `Control`, and the
            // composite that does (`CellNode`, for the combiner's mix directory) intercepts it before this point.
            // A load reading from a sibling engine the composite could only reach by message (`dyn Engine`
            // erases the type that would let it call `observe_load` directly). Same seam, addressed by tag.
            Input::Command(Command::Control { tag, ref body })
                if tag == roles::CONTROL_LOAD_READING =>
            {
                if let Some((role, load)) = roles::decode_load_reading(body) {
                    self.observe_load(role, load);
                }
                Vec::new()
            }
            Input::Timer(_) | Input::Command(Command::Control { .. }) => Vec::new(),
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use crate::ports::ReadOutcome;

    /// Two deployments must not report one cell, and one deployment must report one cell (#210).
    ///
    /// Both halves, because either alone is passable by a wrong function: a constant id satisfies "every node
    /// agrees", and a per-*node* id satisfies "two networks differ". The pair is the property — and the second
    /// assertion is the one the pre-#210 code passed, which is why it looked correct for as long as it did.
    #[test]
    fn a_cell_id_names_the_network_and_not_merely_the_plane() {
        use fanos_field::{F2, F7};

        let alpha = BeaconSeed::new([0xA1; 32]);
        let beta = BeaconSeed::new([0xB2; 32]);
        assert_ne!(
            cell_id::<F2>(alpha),
            cell_id::<F2>(beta),
            "two networks on the same plane must not roll up as one cell"
        );
        assert_eq!(
            cell_id::<F2>(alpha),
            cell_id::<F2>(alpha),
            "and every node of one network must derive the same id, or the frames cannot be joined at all"
        );
        // The plane still separates: folding the seed adds an axis, it does not replace the one that was there.
        assert_ne!(cell_id::<F2>(alpha), cell_id::<F7>(alpha), "the plane axis survives");
        // The unnamed deployment keeps the pre-#210 identifier exactly, so an operator's dashboards do not
        // silently re-key on upgrade — the change costs a name, not a discontinuity.
        assert_eq!(
            cell_id::<F2>(BeaconSeed::GENESIS),
            cell_id::<F2>(BeaconSeed::default()),
            "GENESIS is the default, so an unconfigured network is one network and not many"
        );
    }

    /// Mark every algebraic neighbour **occupied**, as production does the moment a node hears from its cell.
    ///
    /// Six tests used to read from a node that had heard from nobody, and passed because a read fanned out to
    /// every algebraic point whether or not anyone was there — so the fixture was resting on the very defect
    /// #216 removes. In production `last_seen` is set by the first frame from a peer, long before any
    /// directory read; a bare node reading the cell is not a state a deployment passes through.
    /// **The seven erasure shards must land on distinct homes while distinct homes exist.**
    ///
    /// Placement used to walk each shard index to its *nearest-occupied successor* — the same rule content
    /// routing uses, and right there. It is wrong here, and only the base cell hid it: on `PG(2,2)` the seven
    /// shard indices **are** the seven plane indices, so the walk is the identity and `[7,3,4]`'s redundancy
    /// is intact. On a wider plane the indices `0..7` sit in one corner of the ring and all of them walk to
    /// the same successor.
    ///
    /// The fixture is that corner, chosen adversarially: **no occupied point between 1 and 7**. Under the old
    /// rule shard 0 stayed at this node and shards 1–6 all went to point 8 — one home holding six of seven,
    /// so a single home's loss left `1 < K = 3` and the value was gone. Sampled across placements the rule
    /// lost the value in `48.1 %` of five-node `PG(2,4)` cells and `73.9 %` of seven-node `PG(2,7)` cells,
    /// putting **all seven** on one node in `14.9 %` and `43.8 %` of them.
    ///
    /// Asserted as *distinct homes*, because that is the property and it is what a restored successor rule
    /// would break first — a count of shards would still read seven.
    #[test]
    fn shard_homes_spread_over_the_occupied_points_rather_than_piling_on_one_successor() {
        use fanos_field::F4;
        use std::collections::BTreeSet as Set;

        // This node is point 0; the other seats are all above the shard-index corner `1..=6`.
        const SEATS: [usize; 4] = [8, 12, 15, 18];
        let mut node = OverlayNode::<F4>::new(Point::at(0), Config::default());
        let wanted: Set<Triple> = SEATS.iter().map(|&i| Point::<F4>::at(i).coords()).collect();
        let known: Vec<Triple> = node.peers.keys().copied().collect();
        for c in known {
            if wanted.contains(&c)
                && let Some(p) = node.peers.get_mut(&c)
            {
                p.last_seen = Some(Instant(0));
            }
        }
        let occupied = node.occupied_points();
        assert_eq!(occupied.len(), SEATS.len() + 1, "the fixture seats exactly five points, this node included");
        assert!(
            (1..erasure::N).all(|i| !occupied.contains(&i)),
            "the corner must be empty, or the old rule would not have collapsed and this proves nothing"
        );

        let homes = node.shard_homes();
        let distinct: Set<Triple> = homes.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            occupied.len().min(erasure::N),
            "every occupied point must carry a shard while there are more shards than points; the successor \
             rule gave two homes here, and one of them held six of the seven"
        );

        // And the property those homes exist for: losing the worst single home must still leave `K` indices.
        let worst = distinct
            .iter()
            .map(|h| homes.iter().filter(|x| *x == h).count())
            .max()
            .unwrap_or(erasure::N);
        assert!(
            erasure::N - worst >= erasure::K,
            "one home's loss must leave at least K = {} distinct shards; the worst home holds {worst}",
            erasure::K
        );
    }


    /// **A cell with no transport at all: every send is delivered, instantly, to whoever is seated.**
    ///
    /// The store's own T1 rung, and the instrument the roster-partition investigation lacked. A live fleet
    /// mixes three planes — placement, membership evidence and QUIC — and a failed read cannot say which one
    /// lost the value. Here there is exactly one: an `Effect::Send` addressed to an occupied point is handed
    /// to that engine, one addressed to empty space is dropped, nothing reorders and nothing is lost. A read
    /// that fails in this mesh fails on the store's logic, and a read that succeeds acquits it.
    struct Mesh<F: Field> {
        engines: Vec<(Triple, OverlayNode<F>)>,
    }

    impl<F: Field> Mesh<F> {
        /// `seats` are canonical point indices; each gets an engine.
        fn new(seats: &[usize]) -> Self {
            Self {
                engines: seats
                    .iter()
                    .map(|&i| {
                        (
                            Point::<F>::at(i).coords(),
                            OverlayNode::<F>::new(Point::at(i), Config::default()),
                        )
                    })
                    .collect(),
            }
        }

        /// Give engine `who` the evidence that `heard` are occupied — the exact input `occupied_points`
        /// reads, set the way the mesh's own traffic would set it.
        fn heard(&mut self, who: usize, heard: &[usize], now: Instant) {
            let wanted: BTreeSet<Triple> =
                heard.iter().map(|&i| Point::<F>::at(i).coords()).collect();
            let Some((_, node)) = self.engines.get_mut(who) else {
                return;
            };
            let known: Vec<Triple> = node.peers.keys().copied().collect();
            for c in known {
                if wanted.contains(&c)
                    && let Some(p) = node.peers.get_mut(&c)
                {
                    p.last_seen = Some(now);
                }
            }
        }

        /// Run `cmd` at engine `origin` and pump every resulting frame to quiescence. Returns every
        /// notification any engine raised, tagged with the engine that raised it.
        fn run(&mut self, now: Instant, origin: usize, cmd: Command) -> Vec<(usize, Notification)> {
            let mut notes = Vec::new();
            let Some(&(from, _)) = self.engines.get(origin) else {
                return notes;
            };
            let mut queue: Vec<(Triple, Triple, Vec<u8>)> = Vec::new();
            let effects = {
                let Some((_, node)) = self.engines.get_mut(origin) else {
                    return notes;
                };
                node.step(now, Input::Command(cmd))
            };
            Self::drain(origin, effects, from, &mut queue, &mut notes);
            // Perfect delivery is not instant termination: bound the pump so a routing loop fails the test
            // rather than hanging it.
            let mut hops = 0u32;
            while let Some((src, dst, frame)) = queue.pop() {
                hops += 1;
                assert!(hops < 10_000, "the mesh must quiesce, not loop");
                let Some(at) = self.engines.iter().position(|&(c, _)| c == dst) else {
                    continue; // addressed to empty space — dropped, as the plane would
                };
                let effects = {
                    let Some((_, node)) = self.engines.get_mut(at) else {
                        continue;
                    };
                    node.step(now, Input::Message { from: src, frame })
                };
                Self::drain(at, effects, dst, &mut queue, &mut notes);
            }
            notes
        }

        fn drain(
            at: usize,
            effects: Vec<Effect>,
            from: Triple,
            queue: &mut Vec<(Triple, Triple, Vec<u8>)>,
            notes: &mut Vec<(usize, Notification)>,
        ) {
            for e in effects {
                match e {
                    Effect::Send { to, frame } => queue.push((from, to, frame)),
                    Effect::Notify(n) => notes.push((at, n)),
                    _ => {}
                }
            }
        }
    }

    /// **Every member must be able to read what any member wrote — over perfect delivery, this is the
    /// store's floor.**
    ///
    /// Five engines on `PG(2,4)`, each holding evidence of all the others, so every `occupied_points()` is
    /// the same set and placement cannot disagree. One writer, five readers, and the value must come back to
    /// all five. With the views equal this is the control: it isolates the *skewed-view* case below, which is
    /// what a real cell has at startup and what the fleet fixture reproduces.
    #[test]
    fn a_value_written_once_is_readable_by_every_member_when_the_views_agree() {
        use fanos_field::F4;
        const SEATS: [usize; 5] = [0, 8, 12, 15, 18];
        let now = Instant(1);
        let mut mesh = Mesh::<F4>::new(&SEATS);
        for (who, &seat) in SEATS.iter().enumerate() {
            let others: Vec<usize> = SEATS.iter().copied().filter(|&i| i != seat).collect();
            mesh.heard(who, &others, now);
        }
        let key = b"agreed-views".to_vec();
        let value = b"the value every member must see".to_vec();
        let stored = mesh.run(now, 0, Command::Put { key: key.clone(), value: value.clone() });
        assert!(
            stored.iter().any(|(_, n)| matches!(n, Notification::Stored(_))),
            "the write must be acknowledged before the reads mean anything: {stored:?}"
        );
        for reader in 0..SEATS.len() {
            let notes = mesh.run(now, reader, Command::Get { key: key.clone() });
            let found = notes.iter().any(|(who, n)| {
                *who == reader
                    && matches!(n, Notification::Retrieved { outcome: ReadOutcome::Found(v), .. } if *v == value)
            });
            assert!(found, "reader {reader} must reconstruct the value; it saw {notes:?}");
        }
    }


    /// **A fully skewed view costs the store nothing, and that refutes the obvious reading of its own
    /// note.**
    ///
    /// `occupied_points()` is *local* evidence, and `on_put` reads it twice — to pick the responsible node
    /// (`responsible_point`) and to place the shards (`shard_homes`). A node that has heard from nobody is
    /// its own successor and its own ring, so it keeps all seven shards and acknowledges `Stored`. The
    /// natural conclusion is that such a write is lost to everyone else, and the storage note's "a writer
    /// that knows few peers keeps every shard itself" invites exactly that reading.
    ///
    /// **It is wrong, and this is the experiment that says so.** `on_get` fans out to the *algebraic*
    /// neighbour set — every point of the plane, owing nothing to evidence — so the cell asks the isolated
    /// writer too, and it answers with all seven. Both directions work: the isolated node reads the cell,
    /// and the cell reads the isolated node.
    ///
    /// Which is why this test is worth its lines. It was written to reproduce a live-fleet partition
    /// (`fanos-sim`'s `the_whole_cell_resolves_every_member`, where three nodes resolve each other and two
    /// resolve only themselves) at unit level, and it **acquits the store**: over perfect delivery no view
    /// skew produces that split, so the partition is a delivery fact, not a placement one. A T1 rung that
    /// refutes a hypothesis is doing its job — see `falsify-every-new-test`.
    #[test]
    fn a_skewed_view_costs_the_store_nothing_because_the_read_is_algebraic() {
        use fanos_field::F4;
        const SEATS: [usize; 5] = [0, 8, 12, 15, 18];
        let now = Instant(1);
        let mut mesh = Mesh::<F4>::new(&SEATS);
        // Everyone but engine 0 has met the whole cell; engine 0 has met nobody — the startup state of the
        // first node up, which no later traffic corrects because nothing re-announces within an epoch.
        for (who, &seat) in SEATS.iter().enumerate().skip(1) {
            let others: Vec<usize> = SEATS.iter().copied().filter(|&i| i != seat).collect();
            mesh.heard(who, &others, now);
        }
        assert_eq!(
            mesh.engines.first().map(|(_, n)| n.occupied_points().len()),
            Some(1),
            "the fixture's whole point is that engine 0 believes it is alone; if this is not 1 the skew \
             never happened and the assertions below prove nothing"
        );

        // Direction 1 — the isolated node writes, and the *whole cell* can still read it.
        let key = b"written-while-alone".to_vec();
        let value = b"a write that never left its writer".to_vec();
        let stored = mesh.run(now, 0, Command::Put { key: key.clone(), value: value.clone() });
        assert!(
            stored.iter().any(|(who, n)| *who == 0 && matches!(n, Notification::Stored(_))),
            "the isolated writer is its own responsible node and acknowledges the write: {stored:?}"
        );
        let readers_that_found: Vec<usize> = (0..SEATS.len())
            .filter(|&reader| {
                mesh.run(now, reader, Command::Get { key: key.clone() })
                    .iter()
                    .any(|(who, n)| {
                        *who == reader
                            && matches!(n, Notification::Retrieved { outcome: ReadOutcome::Found(v), .. } if *v == value)
                    })
            })
            .collect();
        assert_eq!(
            readers_that_found,
            (0..SEATS.len()).collect::<Vec<_>>(),
            "every member reads a value written by a node that believed it was alone — the read asks the \
             whole plane, so it asks the writer"
        );

        // Direction 2 — the cell writes, the isolated node reads. Same reason, other way round.
        let key2 = b"written-by-the-cell".to_vec();
        let value2 = b"the cell's own value".to_vec();
        let stored2 = mesh.run(now, 1, Command::Put { key: key2.clone(), value: value2.clone() });
        assert!(
            stored2.iter().any(|(_, n)| matches!(n, Notification::Stored(_))),
            "the cell's write is acknowledged: {stored2:?}"
        );
        let notes = mesh.run(now, 0, Command::Get { key: key2.clone() });
        assert!(
            notes.iter().any(|(who, n)| *who == 0
                && matches!(n, Notification::Retrieved { outcome: ReadOutcome::Found(v), .. } if *v == value2)),
            "the isolated node reads the cell's value: its fan-out is algebraic, not evidential — {notes:?}"
        );
    }


    /// **A point heard from once is not a point occupied for ever, and the epoch boundary is where that
    /// stops being true.**
    ///
    /// `occupied_points` is placement's only input, and every coordinate on this plane is a *rotating* name:
    /// the beacon re-draws it each epoch, `on_reseat` moves an outranked node, the probe walk visits several
    /// points before settling. A mark that no path clears makes each of those leave a permanent claim on a
    /// point nobody occupies any more.
    ///
    /// Asserted on both sides of the boundary on one engine, because the property is the *transition*: a
    /// mark that never clears and one that is never set both pass a one-sided check. And on the engine's own
    /// coordinate too — the set must never empty, since this node is always in it.
    #[test]
    fn the_epoch_boundary_clears_every_liveness_mark_placement_reads() {
        use fanos_field::F4;
        let mut node = OverlayNode::<F4>::new(Point::at(0), Config::default());
        let seat = Point::<F4>::at(8).coords();
        if let Some(p) = node.peers.get_mut(&seat) {
            p.last_seen = Some(Instant(1));
        }
        assert!(
            node.occupied_points().contains(&8),
            "a peer we have heard from occupies its point"
        );
        assert!(
            node.shard_homes().contains(&seat),
            "and placement follows it — otherwise the assertion below proves nothing"
        );

        node.step(Instant(2), Input::Command(Command::AdvanceEpoch));
        assert!(
            !node.occupied_points().contains(&8),
            "past the boundary that point names somebody else, or nobody, and the evidence is gone"
        );
        assert!(
            node.occupied_points().contains(&0),
            "this node is always in its own occupied set — the set is never empty"
        );
        assert!(
            node.peers.contains_key(&seat),
            "the PEER stays: the algebraic neighbour set is a property of the plane, not of who is on it"
        );
    }

    /// **A mover leaves a vacancy, and the announcement it sends from the new point is the only retraction
    /// the cell ever gets.**
    ///
    /// Within one epoch, arbitration reseats an outranked node and the probe walk settles further along its
    /// own walk. Both leave the abandoned coordinate marked occupied in three position-keyed places, and no
    /// frame ever says "I am no longer there". `identities` maps coordinate → identity, so an identity
    /// appearing at a new point names the old one exactly.
    #[test]
    fn an_identity_announcing_from_a_new_point_vacates_the_one_it_left() {
        use fanos_field::F4;
        let cfg = Config { require_self_certified_membership: false, ..Config::default() };
        let mut node = OverlayNode::<F4>::new(Point::at(0), cfg);
        let old = Point::<F4>::at(8).coords();
        let new = Point::<F4>::at(12).coords();
        let id = alloc::vec![7u8; 32];
        let announce = |at: Triple| {
            let hier = HierAddr::from_path(alloc::vec![Point::<F4>::new(at).unwrap()]).unwrap();
            encode(FrameType::Announce, &announce_body(at, &hier, &id, &[], &[], b"info"))
        };
        node.step(Instant(1), Input::Message { from: old, frame: announce(old) });
        assert!(
            node.membership.members.contains_key(&old),
            "the first announcement seats it — otherwise the move below has nothing to vacate"
        );
        if let Some(p) = node.peers.get_mut(&old) {
            p.last_seen = Some(Instant(1));
        }

        node.step(Instant(2), Input::Message { from: new, frame: announce(new) });
        assert!(
            node.membership.members.contains_key(&new),
            "the mover is seated at the point it announced from"
        );
        assert!(
            !node.membership.members.contains_key(&old),
            "and the point it left is retracted, not held by a member who is elsewhere"
        );
        assert!(
            !node.occupied_points().contains(&8),
            "so placement stops addressing shards to it — the whole reason the retraction exists"
        );
    }

    /// **The consequence the live fleet paid, reproduced end to end: a ring of ghosts loses the value.**
    ///
    /// Five engines on `PG(2,4)` at seats `[0, 8, 12, 15, 18]`, each also holding a mark for indices
    /// `1..=6`, where no engine ever lived — the residue a few reshuffles and reseats leave behind, and
    /// every node accumulates its own. Those six sort below every real seat but the first, so an uncleared
    /// `occupied_points` hands `shard_homes` a ring whose seven entries are one live point and six
    /// vacancies: six shards in seven are addressed to nobody, `K = 3` never assembles, and no reader can
    /// find what no point holds.
    ///
    /// The epoch boundary is what clears it. After the advance the engines re-hear only each other, the
    /// ring is the five real seats, and the value comes back to all five.
    ///
    /// **The residue must be on every engine for this to bite, and finding that out corrected the claim.**
    /// With the ghosts on the writer alone the value still came back, because `on_put` routes to
    /// `responsible_point` and a *healthy* responsible node re-places the shards over its own clean ring.
    /// One sick node therefore loses only the keys it is itself responsible for — which is why the live
    /// fleet's failure was partial (three nodes resolving each other, two resolving only themselves) rather
    /// than total, and why a fixture with one sick node proves nothing.
    #[test]
    fn the_epoch_boundary_clears_a_ring_of_ghosts_that_would_swallow_every_write() {
        use fanos_field::F4;
        const SEATS: [usize; 5] = [0, 8, 12, 15, 18];
        const GHOSTS: [usize; 6] = [1, 2, 3, 4, 5, 6];
        let now = Instant(1);
        let mut mesh = Mesh::<F4>::new(&SEATS);
        for (who, &seat) in SEATS.iter().enumerate() {
            let others: Vec<usize> = SEATS.iter().copied().filter(|&i| i != seat).collect();
            mesh.heard(who, &others, now);
            mesh.heard(who, &GHOSTS, now);
        }
        assert_eq!(
            mesh.engines.first().map(|(_, n)| n.occupied_points().len()),
            Some(SEATS.len() + GHOSTS.len()),
            "the residue is there before the boundary — otherwise this fixture proves nothing"
        );

        // The advance every node takes, and the traffic that follows it: the seats are heard again, the
        // vacancies are not, because nothing lives there to be heard from.
        for (who, _) in SEATS.iter().enumerate() {
            if let Some((_, node)) = mesh.engines.get_mut(who) {
                node.step(now, Input::Command(Command::AdvanceEpoch));
            }
        }
        for (who, &seat) in SEATS.iter().enumerate() {
            let others: Vec<usize> = SEATS.iter().copied().filter(|&i| i != seat).collect();
            mesh.heard(who, &others, now);
        }
        assert_eq!(
            mesh.engines.first().map(|(_, n)| n.occupied_points().len()),
            Some(SEATS.len()),
            "past the boundary only the seats survive"
        );

        let key = b"written-over-a-graveyard".to_vec();
        let value = b"the value six ghosts would have swallowed".to_vec();
        let stored = mesh.run(now, 0, Command::Put { key: key.clone(), value: value.clone() });
        assert!(
            stored.iter().any(|(_, n)| matches!(n, Notification::Stored(_))),
            "the write is acknowledged: {stored:?}"
        );
        let readers_that_found: Vec<usize> = (0..SEATS.len())
            .filter(|&reader| {
                mesh.run(now, reader, Command::Get { key: key.clone() })
                    .iter()
                    .any(|(who, n)| {
                        *who == reader
                            && matches!(n, Notification::Retrieved { outcome: ReadOutcome::Found(v), .. } if *v == value)
                    })
            })
            .collect();
        assert_eq!(
            readers_that_found,
            (0..SEATS.len()).collect::<Vec<_>>(),
            "every member reads it, because every shard went to a point that answers"
        );
    }


    /// **Every point of the plane is an algebraic neighbour, and a frame from any of them is evidence.**
    ///
    /// Both halves measured on one engine, because the fleet made them a live question: five nodes on
    /// `PG(2,4)` recorded **four** `overlay.first_heard` events between them — one apiece for four of the
    /// five, none for the fifth — while the driver plane showed frames arriving from all four peers on every
    /// node. Either the neighbour set is not the whole plane, or the mark is not reached from the frame path;
    /// this pins both so the fleet's reading has something to be read against.
    #[test]
    fn a_frame_from_any_point_of_the_plane_marks_its_sender_heard() {
        use fanos_field::F4;
        let all: Vec<Triple> = Plane::<F4>::points().map(|p| p.coords()).collect();
        assert_eq!(all.len(), 21, "PG(2,4) has q²+q+1 = 21 points");
        // **Every seat, not one.** The fleet seats nodes wherever the VRF puts them, so a neighbour set that
        // is complete at `Point::at(0)` and short somewhere else would look exactly like the partition being
        // chased, and a single-seat check could not tell the difference.
        for seat in 0..all.len() {
            let at = OverlayNode::<F4>::new(Point::at(seat), Config::default());
            let missing: Vec<Triple> = all
                .iter()
                .copied()
                .filter(|c| *c != at.coord.coords() && !at.peers.contains_key(c))
                .collect();
            assert!(
                missing.is_empty(),
                "on a projective plane every other point shares a line with this one, so all 20 are \
                 neighbours of seat {seat}; these are absent: {missing:?}"
            );
        }
        let mut node = OverlayNode::<F4>::new(Point::at(0), Config::default());

        // A frame this dispatch has no arm for is still a frame that arrived — the weakest possible evidence,
        // and it must still count, because the handshake's own tail (`HelloAck`) is exactly that.
        let far = Point::<F4>::at(18).coords();
        assert!(!node.occupied_points().contains(&18), "not heard from yet");
        node.step(Instant(1), Input::Message { from: far, frame: encode(FrameType::HelloAck, &[]) });
        assert!(
            node.occupied_points().contains(&18),
            "an unclaimed-type frame from a proven coordinate still proves a node lives there"
        );
    }


    /// **A write that dies with its writer must say so, and `Stored` cannot.**
    ///
    /// `Notification::Stored` is raised the moment the placement effects are emitted — nothing has been
    /// acknowledged — so the publisher reports the same success whether the shards went to five homes or
    /// stayed on one. The erasure code supplies the only statement decidable at write time: the value
    /// survives losing this node iff at most `N − K` of its shards stayed here.
    ///
    /// Both sides asserted on one engine, because the property is the threshold: an alarm that always fires
    /// and one that never fires both pass a one-sided check.
    #[test]
    fn a_write_that_does_not_outlive_its_writer_raises_the_alarm_stored_cannot() {
        use fanos_field::F4;
        const SEATS: [usize; 5] = [0, 8, 12, 15, 18];
        let now = Instant(1);
        let count = |node: &OverlayNode<F4>| {
            node.stations.total(Station::StoreWriteNotDurable)
        };

        // Alone: every home is this node, all seven shards stay, and the alarm fires.
        let mut lone = OverlayNode::<F4>::new(Point::at(0), Config::default());
        assert_eq!(lone.occupied_points().len(), 1, "the fixture's whole point is a cell of one");
        lone.step(now, Input::Command(Command::Put { key: b"alone".to_vec(), value: b"v".to_vec() }));
        assert_eq!(count(&lone), 1, "a value written onto its own writer does not survive it");

        // With the cell heard from, the ring spreads and the alarm is silent.
        let mut seated = OverlayNode::<F4>::new(Point::at(0), Config::default());
        for &i in &SEATS[1..] {
            if let Some(p) = seated.peers.get_mut(&Point::<F4>::at(i).coords()) {
                p.last_seen = Some(now);
            }
        }
        assert_eq!(seated.occupied_points().len(), SEATS.len(), "all five seats are evidence now");
        // **A key this node is responsible for, found rather than assumed.** `on_put` routes a value whose
        // responsible point is elsewhere, so an arbitrary key leaves `distribute_shards` unreached and the
        // assertion below would pass for the wrong reason — it did, and a falsification that made the alarm
        // fire unconditionally still went green.
        let me = seated.coord.coords();
        let key = (0u32..1000)
            .map(|n| alloc::format!("spread-{n}").into_bytes())
            .find(|k| {
                let (_, ideal) = OverlayNode::<F4>::address_of(k);
                seated.responsible_point(ideal) == me
            })
            .expect("some key of a thousand lands on this node");
        let (digest, _) = OverlayNode::<F4>::address_of(&key);
        seated.step(now, Input::Command(Command::Put { key, value: b"v".to_vec() }));
        let mut held = BTreeMap::new();
        seated.store.seed_versions(&digest, &mut held);
        assert!(
            held.values().flatten().flatten().any(|s| !s.is_empty()),
            "the write must have been placed BY this node, or the silence below means nothing"
        );
        assert_eq!(
            count(&seated),
            0,
            "spread over five homes at most ⌈7/5⌉ = 2 shards stay here, well inside N − K = {}",
            erasure::N - erasure::K
        );
    }


    /// **A proved handshake is the strongest evidence there is, and the engine used to be told nothing.**
    ///
    /// The transport is the only layer that witnesses a coordinate being proved against a certificate. Until
    /// `Command::PeerHandshaken` the engine learned who was where from `Announce` frames alone, so a peer
    /// this node had dialled, verified and held a live connection to was absent from `occupied_points` —
    /// which decides shard placement, the denominator a definite `Absent` must exhaust, and the membership
    /// view. Measured on a five-node fleet: four transport connections per node against **one** heard peer.
    ///
    /// The retraction is asserted too, because a handshake is a *better* witness to a move than an
    /// announcement: it cannot be relayed, so it cannot be replayed by a third party.
    #[test]
    fn a_proved_handshake_seats_the_peer_and_vacates_the_point_it_left() {
        use fanos_field::F4;
        let mut node = OverlayNode::<F4>::new(Point::at(0), Config::default());
        let old = Point::<F4>::at(8).coords();
        let new = Point::<F4>::at(12).coords();
        let id = [7u8; 32];

        assert!(!node.occupied_points().contains(&8), "nothing is known about that point yet");
        let effects = node.step(Instant(1), Input::Command(Command::PeerHandshaken { coord: old, identity: id }));
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::PeerHandshaken { coord, .. }) if *coord == old
            )),
            "the host is told, which is what lets it hand a sub-engine the peer's verifier"
        );
        assert!(
            node.occupied_points().contains(&8),
            "and placement follows: a peer we have handshaken with occupies its point"
        );

        // The same identity proving a different point has left the first one.
        node.step(Instant(2), Input::Command(Command::PeerHandshaken { coord: new, identity: id }));
        assert!(node.occupied_points().contains(&12), "seated where it proved");
        assert!(
            !node.occupied_points().contains(&8),
            "and the point it left is retracted — no shard may be addressed to a vacancy"
        );

        // Our own dial arriving back is not a peer.
        let me = node.coord.coords();
        let self_effects =
            node.step(Instant(3), Input::Command(Command::PeerHandshaken { coord: me, identity: [9u8; 32] }));
        assert!(self_effects.is_empty(), "this node is not a peer of itself");
    }


    fn seat_every_neighbour<F: Field>(node: &mut OverlayNode<F>, now: Instant) {
        let coords: Vec<Triple> = node.peers.keys().copied().collect();
        for c in coords {
            if let Some(p) = node.peers.get_mut(&c) {
                p.last_seen = Some(now);
            }
        }
    }
    // Codec helpers the tests build frames with; scoped here so the library build does not carry them.
    use crate::frames::{announce_body, encode_publish, encode_value};
    use super::*;
    use fanos_field::{F2, F4, F7};

    /// **The Fano-only invariant is written in four places now, and this pins the fourth.**
    ///
    /// The reflex is index-addressed over a cell of seven points where no three are collinear. Without an
    /// explicit roster the fallback is `Point::at(0..6)` — which is that cell only on the base plane.
    /// Measured on `PG(2,7)`: those seven are `[1,0,0]…[1,0,6]`, **all on the one line `[0,1,0]`**, so the
    /// set spans one line where a Fano cell spans seven. `cell_position` used to answer `Some(i)` for them.
    ///
    /// Two worlds differing only in the plane order, because a test that checked F7 alone could pass with
    /// `cell_position` hardwired to `None` and would then be pinning nothing.
    #[test]
    fn a_larger_plane_has_no_implicit_cell_so_no_coordinate_holds_a_position_in_one() {
        // F2 — the base plane IS the cell: every one of the seven points has a position.
        let node = OverlayNode::<F2>::new(Point::<F2>::at(0), Config::default());
        for i in 0..7 {
            assert_eq!(
                node.cell_position(Point::<F2>::at(i).coords()),
                Some(i),
                "on the base Fano cell, point {i} is cell position {i}"
            );
        }

        // F7 — `at(0..6)` are collinear, so they are not a cell and no coordinate has a position in one.
        let big = OverlayNode::<F7>::new(Point::<F7>::at(0), Config::default());
        for i in 0..7 {
            assert_eq!(
                big.cell_position(Point::<F7>::at(i).coords()),
                None,
                "on PG(2,7) the fallback seven are collinear — answering a position would be confident and \
                 wrong (#242)"
            );
        }
    }

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
            &9u32.to_le_bytes(),
        );
        node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: refusal });
        assert_ne!(node.admission_proof_for_test(), &before[..], "the proof was not re-minted at the new price");
        assert_eq!(node.paid_difficulty_for_test(), Some(9), "and the node now pays the price it was told");
    }

    #[test]
    fn a_peer_cannot_talk_a_node_into_paying_less() {
        // A hostile or broken peer naming a *lower* difficulty must not weaken a proof the operator configured.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default())
            .with_identity(alloc::vec![7u8; 8])
            .with_admission_pow(12);
        let refusal = crate::frames::encode_error_with(
            fanos_wire::ProtocolError::SybilReject,
            &2u32.to_le_bytes(),
        );
        node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: refusal });
        assert_eq!(node.paid_difficulty_for_test(), Some(12), "the node lowered its own admission cost");
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
            &(MAX_INLINE_ADMISSION_BITS + 1).to_le_bytes(),
        );
        let effects = node.step(Instant(0), Input::Message { from: [1, 0, 0], frame: refusal });
        assert_eq!(node.paid_difficulty_for_test(), Some(4), "the engine paid an extortionate demand");
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::AdmissionRefused { .. }))),
            "and it must still be reported, so a driver or operator can decide"
        );
    }

    #[test]
    fn what_a_node_demands_and_what_it_pays_are_independent() {
        // The separation, asserted. A node's own proof has to satisfy its *peers'* gates; its own gate has
        // nothing to do with it. While one number served both, charging more forced a node to pay more for no
        // reason — a real cost, and the one that made a scenario test spend 48 seconds minting a proof nobody
        // was going to check.
        let strict_but_cheap = OverlayNode::<F2>::new(Point::at(0), Config::default())
            .with_identity(alloc::vec![1u8; 8])
            .paying(3)
            .demanding(19);
        assert_eq!(strict_but_cheap.paid_difficulty_for_test(), Some(3), "demanding must not raise what we pay");

        // …and the converse: paying a lot does not oblige a node to charge a lot.
        let generous_but_diligent = OverlayNode::<F2>::new(Point::at(0), Config::default())
            .with_identity(alloc::vec![2u8; 8])
            .demanding(1)
            .paying(9);
        assert_eq!(generous_but_diligent.paid_difficulty_for_test(), Some(9));
        // The gate is the demand, not the payment: a 1-bit proof satisfies a 1-bit door.
        let challenge = admission_challenge(&alloc::vec![2u8; 8], Point::<F2>::at(0).coords(), 0.into());
        let cheap = PowAdmission::new(1).solve(&challenge);
        assert!(
            generous_but_diligent.membership.admission_policy.as_ref().is_some_and(|p| p.admits(&challenge, &cheap)),
            "the gate charged what the node paid instead of what it demanded"
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
            .paying(4)
            .demanding(STRICT);
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
    fn no_allocated_frame_type_lies_above_the_skew_tag_ceiling() {
        // `MAX_SKEW_TAG` lives in fanos-ports, which cannot see the frame-type registry that justifies it — so
        // the derivation is checked here, where the registry is visible.
        //
        // The first version of this test asserted the ceiling was the single-byte *varint* space and failed:
        // these are QUIC varints, where one byte holds `0..=63`, which is below codes the registry already
        // allocates. The bound would have folded real evidence into the untagged bucket and the skew detector
        // would have gone quiet about genuine release differences. Tying the constant to the thing that
        // justifies it is what caught that.
        use crate::ports::stations::MAX_SKEW_TAG;
        // The property that makes the bound safe, checked exhaustively rather than by sampling the registry:
        // **no allocated code lies outside the tag space.** If one did, the clamp would fold real evidence
        // into the untagged bucket and the skew detector would go quiet about a genuine release difference.
        for code in (MAX_SKEW_TAG + 1)..=0xFFFF {
            assert!(
                FrameType::from_code(code).is_none(),
                "{code:#x} is an allocated frame type above the tag ceiling — the clamp would hide it"
            );
        }
    }

    /// **The descriptor a host signs for the coordinate it is about to hold is one this engine accepts.**
    ///
    /// This is the agreement the whole §80 binding rests on, and it has two ends in two crates: the *host*
    /// builds `descriptor_message(coord, hier, id)` and signs it (`fanos_quic`'s `Reseater`, at every
    /// reseat, because the message binds the transport coordinate and the reshuffle re-draws it); the
    /// *engine* rebuilds the identical bytes from the announce it emits and checks them. A signature over a
    /// message the engine does not rebuild verifies nowhere, and nothing in either type says so.
    ///
    /// What it pins is the part the host has to *predict*: after a reseat, this node's overlay address is
    /// `[new_coord]` — `HierAddr::root(new_coord)` — for the depth-1 case every production composition uses
    /// (`hier_path: None`). **The day a node descends, this fails**, which is the point: the host would then
    /// be signing over a path it does not know, and the deeper levels have to be handed to it.
    #[test]
    fn a_descriptor_signed_for_the_coordinate_about_to_be_held_verifies_on_the_announce_that_follows() {
        let moving_to = Point::<F2>::at(3);
        let (secret, verifier) =
            fanos_pqcrypto::HybridSigSecret::generate(&mut fanos_pqcrypto::SeedRng::from_seed(b"descriptor"));
        let id = verifier.encode();

        // The host's half: sign for the coordinate it is ABOUT to hold, and for the address it predicts the
        // engine will then have.
        let predicted = HierAddr::<F2>::root(moving_to);
        let sig = secret
            .sign(&descriptor_message::<F2>(moving_to.coords(), &predicted, &id))
            .to_bytes();

        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default())
            .with_signed_descriptor(id.clone(), sig.clone());
        // A peer to flood to, or the reseat emits no announce to inspect.
        node.peers.insert(
            Point::<F2>::at(1).coords(),
            Peer { last_seen: None, reported_down: false, loss: 0.0, awaiting_pong: false },
        );
        let effects = node.step(Instant(1), Input::Command(Command::Reseat { coord: moving_to.coords() }));

        let announce = effects
            .iter()
            .find_map(|e| {
                let Effect::Send { frame, .. } = e else { return None };
                let (f, _) = decode_frame(frame).ok()?;
                (f.frame_type() == Some(FrameType::Announce)).then(|| f.body.to_vec())
            })
            .expect("a reseat re-announces, or there is nothing for a peer to verify");
        let parsed = crate::frames::parse_announce::<F2>(&announce)
            .expect("this engine's own announce must parse");

        assert_eq!(parsed.0, moving_to.coords(), "the announce names the coordinate that was signed for");
        assert!(
            crate::frames::descriptor_signature_ok::<F2>(parsed.0, &parsed.1, &parsed.2, &parsed.3),
            "the engine must rebuild the very bytes the host signed — if this fails, the host's prediction \
             of this node's overlay address after a reseat is wrong, and every honest announce would be \
             refused by a peer running self-certified membership"
        );
    }

    /// **A DERIVED cell follows the coordinate, where a provisioned one is defended** (#145).
    ///
    /// The neighbouring test pins the provisioned case: a `Reseat` out of an explicit roster is refused,
    /// because that roster is a committee at fixed transport points. A roster obtained from the plane is
    /// the opposite — `fano::cell_of` is a function of the coordinate, so at every reshuffle the node
    /// belongs to whichever cell its new point is in. Applying the refusal rule there would make a node
    /// reject its **own** epoch reshuffle and freeze at its founding coordinate, with every effect still
    /// firing; one field decides which rule applies and this asserts that it decides correctly.
    ///
    /// On `F4`, where the plane splits into three cells and a move can change both the cell and the
    /// position inside it — at `q = 2` there is one cell, so neither could change and the test would pass
    /// on a build that had no rule at all.
    #[test]
    fn a_derived_cell_follows_the_coordinate_across_a_reshuffle() {
        let cells = fano::cells_in::<F4>().expect("PG(2,4) splits into three cells");
        assert_eq!(cells, 3, "21 points, seven to a cell");

        let start = Point::<F4>::at(0);
        let mut node = OverlayNode::<F4>::new(start, Config::default()).with_derived_cell();
        assert_eq!(fano::cell_of(start), Some(0), "point 0 is in cell 0");
        assert_eq!(node.self_index, Some(0), "and holds position 0 of it");

        // Point 4 is in cell 1 at position 1, so BOTH change — a build that re-read only the position, or
        // only the roster, fails here.
        let moved = Point::<F4>::at(4);
        assert_eq!(fano::cell_of(moved), Some(1), "the fixture really does cross a cell boundary");
        node.step(Instant(1), Input::Command(Command::Reseat { coord: moved.coords() }));

        assert_eq!(node.coord, moved, "the reshuffle was applied, not refused");
        assert_eq!(node.self_index, Some(1), "and the index is its position in the NEW cell");
        assert_eq!(
            node.cell_members,
            Some(fano::cell_members_of::<F4>(1).expect("cell 1").coords()),
            "the roster was re-derived, so the reflex attests against the seven it is actually among",
        );
        assert_eq!(
            node.healer.cell_members, node.cell_members,
            "and the healer actuates on the same roster — it has its own copy",
        );
    }

    /// **A node seated in an explicit cell does not reseat out of it** (#145).
    ///
    /// `with_cell_members` seats a node at a position in a provisioned 7-member roster, and the whole reflex
    /// is addressed off that index: `polar_class(self_index)` names the three channels this node mediates and
    /// `cell_coord(i)` maps every other index through the same roster. The per-epoch VRF reshuffle is a
    /// defence for a node's placement on the **base plane**, where the roster *is* the plane — a different
    /// mechanism, and applying it to a node holding the first used to recompute the index by the base-plane
    /// rule while leaving `cell_members` untouched. At `q = 2` the node then attested under its base-plane
    /// point rather than its cell position, filing its polar rates against the wrong three channels; above
    /// `q = 2` the rule yields `None` and the reflex switches off entirely. Neither is visible from outside:
    /// every effect still fires, addressed wrongly.
    ///
    /// Latent only because production never sets `cell_members`, which is precisely why it has to be right
    /// **before** it does. Asserted in both directions, because a refusal that also refused a legitimate move
    /// would be a different defect wearing the same shape.
    #[test]
    fn a_reseat_out_of_an_explicit_cell_is_refused_and_one_inside_it_re_reads_the_roster() {
        // **On `F7`, not `F2`, and that is a finding rather than a fixture choice.** A Fano roster has seven
        // members and the Fano plane has seven points, so an explicit roster *covers the whole plane* — the
        // out-of-cell case is unreachable at `q = 2`. It exists only on a larger transport plane, which is
        // exactly the setting #145 is about: a cell embedded in a plane bigger than itself. The first draft
        // of this test was written on `F2` and its own "the roster really does exclude this point" assertion
        // caught it.
        //
        // The seats are also NOT `Point::at(i)`: member `i` sits at point `i * 5 + 2`, so the base-plane rule
        // and the roster rule disagree about every index and the old code cannot pass by coincidence. They are
        // not a Fano *subplane* either, and they need not be: `PG(2,7)` has none — a subplane needs
        // `GF(2) ⊆ GF(q)` and 7 is an odd prime — while the cell's Fano structure is a labelling of the seven
        // members rather than a geometric claim about their coordinates (`fano::CellMembers`).
        let seat_of = |i: usize| Point::<F7>::at(i * 5 + 2).coords();
        let members: [Triple; 7] = core::array::from_fn(seat_of);
        let mut node = OverlayNode::<F7>::new(
            Point::<F7>::new(seat_of(0)).expect("a plane point"),
            Config::default(),
        )
        .with_cell_members(fano::CellMembers::<F7>::new(members).expect("seven distinct plane points"));
        assert_eq!(node.self_index, Some(0), "seated at roster position 0");

        // **Inside the roster**: a move to another member's seat re-reads the index FROM THE ROSTER. Position
        // 4 sits at base-plane point 0, so the two rules give different answers and only one is right.
        node.step(Instant(1), Input::Command(Command::Reseat { coord: seat_of(4) }));
        assert_eq!(node.coord.coords(), seat_of(4), "the move inside the cell was applied");
        assert_eq!(
            node.self_index,
            Some(4),
            "and the index came from the ROSTER — the base-plane rule yields {:?} on this plane",
            (0..7).find(|&i| Point::<F7>::at(i).coords() == seat_of(4)),
        );

        // **Outside the roster**: refused whole. Nothing is mutated — not the coordinate, not the index — and
        // the refusal is counted, because a silent one is indistinguishable from a `Reseat` that never came.
        let outside = Point::<F7>::at(0).coords();
        assert!(!members.contains(&outside), "the fixture's roster really does exclude this point");
        node.step(Instant(2), Input::Command(Command::Reseat { coord: outside }));
        assert_eq!(node.coord.coords(), seat_of(4), "the node did not move out of its cell");
        assert_eq!(node.self_index, Some(4), "and kept the index the reflex is addressed by");
        let obs = node
            .step(Instant(3), Input::Command(Command::Observe))
            .into_iter()
            .find_map(|e| match e {
                Effect::Notify(Notification::DataPath { stations, .. }) => Some(stations),
                _ => None,
            })
            .expect("the sense-only read answers with the data-path plane");
        assert_eq!(
            obs.iter()
                .filter(|o| o.station == Station::ReseatOutOfCell)
                .map(|o| o.count)
                .sum::<u64>(),
            1,
            "the refusal is on the operator's plane — nonzero means a deployment combined an explicit roster \
             with VRF coordinates, which is a provisioning contradiction rather than a runtime fault",
        );
    }

    #[test]
    fn version_skew_is_counted_by_tag_and_line_where_corruption_is_neither() {
        // `docs/design-upgrade.md` §4: the operational question is not "is anyone stale" — the network
        // tolerates that until the activation height — but **"does any hop line hold fewer than `t` members
        // that agree on the current derivation?"** A cell can be 90% upgraded and still have one line below
        // quorum, and that line's traffic is what silently stops.
        //
        // Answering it needs both dimensions, and only one of the two failure kinds carries them. A malformed
        // frame says nothing about who is on which release. A frame whose *type parsed* and names a handler
        // nobody claims says both: the code is the evidence, the sender localizes it to a line.
        //
        // Tested on the OVERLAY because that is where an unclaimed type actually lands in a deployed node —
        // a composite routes by frame type, so a threshold engine's own unknown-type arm never sees one. The
        // first draft of this test asserted against `ServiceNode` and failed for exactly that reason.
        let members: [Triple; 7] = core::array::from_fn(|i| Point::<F2>::at(i).coords());
        let mut node =
            OverlayNode::<F2>::new(Point::at(0), Config::default())
                .with_cell_members(fano::CellMembers::new(members).expect("a real subplane"));
        let peer = Point::<F2>::at(1).coords();

        node.step(Instant(0), Input::Message { from: peer, frame: alloc::vec![0xFF, 0xFF, 0xFF] });
        let mut unclaimed = Vec::new();
        // 0x7E is not a `FrameType` this build implements — exactly a peer on another release.
        fanos_wire::encode_frame(0x7E, &[1, 2, 3], &mut unclaimed);
        node.step(Instant(1), Input::Message { from: peer, frame: unclaimed });

        let obs = node
            .step(Instant(2), Input::Command(Command::Observe))
            .iter()
            .find_map(|e| match e {
                Effect::Notify(Notification::DataPath { stations, .. }) => Some(stations.clone()),
                _ => None,
            })
            .expect("a sense-only read exports the data-path plane");
        let at = |st: Station| -> Vec<crate::ports::stations::Observation> {
            obs.iter().filter(|o| o.station == st && o.count > 0).copied().collect()
        };

        let corrupt = at(Station::FrameDecodeFailed);
        assert_eq!(corrupt.len(), 1, "the malformed frame is counted once");
        assert_eq!(corrupt[0].line, None, "and stays unattributed — it names no line and no release");
        assert_eq!(corrupt[0].tag, None, "inventing a tag for it would be fabricated evidence");

        let skew = at(Station::FrameTypeUnknown);
        assert_eq!(skew.len(), 1, "the unclaimed type is counted once");
        assert_eq!(skew[0].line, Some(peer), "localized to the sender, so a LINE can be judged against `t`");
        assert_eq!(skew[0].tag, Some(0x7E), "carrying the code the peer used — the evidence of its release");

        // --- The third thing this arm receives, and for a long time the LOUDEST. -----------------------
        //
        // `HelloAck` is in the registry and is not one of the seventeen types this dispatch claims, so it
        // reaches the same catch-all as `0x7E` above and used to be counted beside it. The two are opposite
        // findings — "a peer is on another release" versus "our own dispatch sent a known frame to a plane
        // that does not serve it" — and a five-node cell of ONE binary, where skew cannot occur at all,
        // raised the skew station 130 times in 60 s on nothing but this.
        let mut known_here = Vec::new();
        fanos_wire::encode_frame(FrameType::HelloAck.code(), &[7], &mut known_here);
        node.step(Instant(3), Input::Message { from: peer, frame: known_here });
        let obs = node
            .step(Instant(4), Input::Command(Command::Observe))
            .iter()
            .find_map(|e| match e {
                Effect::Notify(Notification::DataPath { stations, .. }) => Some(stations.clone()),
                _ => None,
            })
            .expect("a sense-only read exports the data-path plane");
        let at = |st: Station| -> Vec<crate::ports::stations::Observation> {
            obs.iter().filter(|o| o.station == st && o.count > 0).copied().collect()
        };

        let unhandled = at(Station::FrameTypeUnhandled);
        assert_eq!(unhandled.len(), 1, "a known type this plane does not serve is counted");
        assert_eq!(unhandled[0].tag, Some(FrameType::HelloAck.code()));
        assert_eq!(unhandled[0].line, Some(peer), "and localized, because a dispatch fault has a direction");

        // The assertion the split exists for: the skew count did NOT move. Fold the two stations back
        // together and this is what reddens — `skew` becomes two observations, one of them a code the
        // registry can name, which is the one thing `FrameTypeUnknown` promises never to carry.
        let skew = at(Station::FrameTypeUnknown);
        assert_eq!(
            skew.len(),
            1,
            "a frame this build CAN name must not touch the release alarm: skew is what the registry has no \
             name for, and an alarm whose count is its own false-positive floor reports nothing"
        );
        assert_eq!(skew[0].tag, Some(0x7E), "and the one it does carry is still the unnameable code");
    }

    /// **A peer mints one version-skew report per (code, sender) pair — not one per frame** (#341).
    ///
    /// THE NUMBER THIS REPLACED WAS MEASURED, not argued. Before the dedup, ten frames from one peer produced
    /// **ten** escalations, and each is one `warn!` at the top of `fanos.rs`'s scale (it uses no `error!`),
    /// reached with no throttle anywhere on the path. So a peer set the rate of this node's loudest channel
    /// by choosing how many frames to send: an amplifier the node ran against itself.
    ///
    /// **This is also the first test to reach the branch at all.** Its neighbour above uses `0x7E`, which
    /// `group_is_critical` answers *no* to, so it exercises the station and walks past the escalation. The
    /// predicate has tests in `fanos-wire`; the escalation it gates had none.
    ///
    /// Three properties, and the third is what stops the fix from being a silencer:
    /// 1. repetition of the SAME (code, sender) reports once — the rate is no longer the peer's to set;
    /// 2. a DIFFERENT code from the same peer reports again — the dedup key is the pair, because "which
    ///    release" and "which line" are both the evidence `design-upgrade.md` §4 asks for, and collapsing to
    ///    the sender alone would answer only half;
    /// 3. the STATION still counts every frame. The aggregate is the level channel an operator polls, and it
    ///    is bounded against this same flood already (`MAX_SKEW_TAG`); if the fix had quieted it too, the
    ///    node would have gone from too loud to blind.
    #[test]
    fn a_peer_mints_one_escalation_per_pair_and_the_station_still_counts_every_frame() {
        const FRAMES: usize = 10;
        let members: [Triple; 7] = core::array::from_fn(|i| Point::<F2>::at(i).coords());
        let mut node =
            OverlayNode::<F2>::new(Point::at(0), Config::default())
                .with_cell_members(fano::CellMembers::new(members).expect("a real subplane"));
        let peer = Point::<F2>::at(1).coords();

        // `0x1F` and `0x1E`, and the second one used to be `0x1D` — **which this build knows**
        // (`DkgCommitReq`), so the assertion beneath it had stopped being about an unknown code at all. The
        // comment here carried the stale range that caused it (*"this build knows `0x11`–`0x1C`"*); the
        // count is now `FrameType::UNKNOWN_CRITICAL_CODES`, derived from the registry. Pinned below, so the
        // next variant to join the group is caught here rather than by a test that silently stops testing —
        // **and it did catch one**: `DkgConfirm = 0x10` took the third leaf, which is why this reads `2`
        // and not `3`. The two that remain are `0x1E` and `0x1F`, the pair used below, so a further variant
        // in this group must move this test deliberately rather than find a gap in it.
        assert_eq!(
            FrameType::UNKNOWN_CRITICAL_CODES,
            2,
            "the membership group holds 16 codes and this build names 14 of them; if this moved, the two \
             codes used below may no longer be unknown — check them before changing the number"
        );
        assert!(
            FrameType::from_code(0x1E).is_none() && FrameType::from_code(0x1F).is_none(),
            "both codes below must be ones this build cannot name, or the escalation under test cannot fire"
        );
        let escalations = |node: &mut OverlayNode<F2>, code: u64, frames: usize, t0: u64| {
            (0..frames)
                .map(|i| {
                    let mut frame = Vec::new();
                    fanos_wire::encode_frame(code, &[i as u8], &mut frame);
                    node.step(Instant(t0 + i as u64), Input::Message { from: peer, frame })
                        .iter()
                        .filter(|e| {
                            matches!(
                                e,
                                Effect::Notify(Notification::Escalated(
                                    crate::ports::Escalation::UnsupportedCritical { .. }
                                ))
                            )
                        })
                        .count()
                })
                .sum::<usize>()
        };

        assert_eq!(
            escalations(&mut node, 0x1F, FRAMES, 0),
            1,
            "{FRAMES} frames of ONE unknown critical code from one peer must report once, not {FRAMES} times              — the pre-#341 code produced {FRAMES}, measured"
        );
        assert_eq!(
            escalations(&mut node, 0x1E, FRAMES, 100),
            1,
            "a DIFFERENT unknown critical code is a different release claim and reports on its own"
        );

        let counted = node
            .step(Instant(200), Input::Command(Command::Observe))
            .iter()
            .find_map(|e| match e {
                Effect::Notify(Notification::DataPath { stations, .. }) => Some(stations.clone()),
                _ => None,
            })
            .expect("a sense-only read exports the data-path plane")
            .iter()
            .filter(|o| o.station == Station::FrameTypeUnknown)
            .map(|o| o.count)
            .sum::<u64>();
        assert_eq!(
            counted,
            (FRAMES * 2) as u64,
            "the aggregate must still see every frame: quieting the log is right, quieting the count would              trade too loud for blind"
        );
    }

    /// **Every reason a peer refuses us is counted, and by reason** (#198).
    ///
    /// The engine acted on `SybilReject` and returned `Vec::new()` for the other fourteen classes, so a peer
    /// that refused us for an unsupported version, a stale epoch or a failed coordinate proof said exactly
    /// that on the wire and nothing survived one function later. During a rollout that refusal is the entire
    /// diagnostic.
    ///
    /// Three properties, and the second is the one that makes the counter worth having:
    /// 1. a non-Sybil refusal is counted at all,
    /// 2. it is counted **under its own tag** — `Unsupported` and `EpochStale` must not share a bucket,
    /// 3. a code this build does not know is still counted, **untagged** rather than dropped or invented.
    ///
    /// The tag is `index()`, never `code()`: the wire codes reach 502 and `record_tagged` clamps at
    /// `MAX_SKEW_TAG = 255`, so a code-keyed tag would file 1xx/2xx under their names and fold 3xx–5xx into
    /// the untagged bucket — indistinguishable, here, from property 3 firing.
    #[test]
    fn a_peer_that_refuses_us_is_counted_by_the_reason_it_gave() {
        use fanos_wire::ProtocolError;
        use fanos_wire::error::encode_error;

        let members: [Triple; 7] = core::array::from_fn(|i| Point::<F2>::at(i).coords());
        let mut node =
            OverlayNode::<F2>::new(Point::at(0), Config::default())
                .with_cell_members(fano::CellMembers::new(members).expect("a real subplane"));
        let peer = Point::<F2>::at(1).coords();

        let refuse = |node: &mut OverlayNode<F2>, at: u64, body: Vec<u8>| {
            let mut frame = Vec::new();
            fanos_wire::encode_frame(FrameType::Error.code(), &body, &mut frame);
            node.step(Instant(at), Input::Message { from: peer, frame });
        };
        // Two different refusals, and one this build has no name for (`code 999`, a forward-compatible
        // peer's new class — `from_code` returns `None` by design).
        refuse(&mut node, 0, encode_error(ProtocolError::Unsupported, b"v3 required"));
        refuse(&mut node, 1, encode_error(ProtocolError::EpochStale, b""));
        let mut unknown = Vec::new();
        fanos_wire::varint::encode(999, &mut unknown);
        refuse(&mut node, 2, unknown);
        // And a body that is not an ERROR at all — the #75 shape, two incompatible encodings.
        refuse(&mut node, 3, alloc::vec![0xFF; 1]);

        let obs = node
            .step(Instant(4), Input::Command(Command::Observe))
            .iter()
            .find_map(|e| match e {
                Effect::Notify(Notification::DataPath { stations, .. }) => Some(stations.clone()),
                _ => None,
            })
            .expect("a sense-only read exports the data-path plane");
        let count = |st: Station, tag: Option<u64>| -> u64 {
            obs.iter().filter(|o| o.station == st && o.tag == tag).map(|o| o.count).sum()
        };

        assert_eq!(
            count(Station::PeerRefused, Some(ProtocolError::Unsupported.index())),
            1,
            "an unsupported-version refusal is the rollout's whole diagnostic and used to vanish here"
        );
        assert_eq!(
            count(Station::PeerRefused, Some(ProtocolError::EpochStale.index())),
            1,
            "and a stale-epoch refusal is a different operator action, so a different tag"
        );
        assert_eq!(
            count(Station::PeerRefused, None),
            1,
            "a code this build cannot name is counted untagged — not dropped, and not given an invented name"
        );
        assert_eq!(
            count(Station::PeerRefusalUnreadable, None),
            1,
            "and a body that will not parse is a different finding: we cannot read the message that explains \
             disagreements"
        );
        // The negative half. `SybilReject` keeps its ACTION — it is the only class with one — and that is
        // asserted elsewhere; what must not happen is the action arm skipping the count.
        refuse(&mut node, 5, encode_error(ProtocolError::SybilReject, b""));
        let after = node
            .step(Instant(6), Input::Command(Command::Observe))
            .iter()
            .find_map(|e| match e {
                Effect::Notify(Notification::DataPath { stations, .. }) => Some(stations.clone()),
                _ => None,
            })
            .expect("a second sense-only read");
        assert_eq!(
            after
                .iter()
                .filter(|o| o.station == Station::PeerRefused
                    && o.tag == Some(ProtocolError::SybilReject.index()))
                .map(|o| o.count)
                .sum::<u64>(),
            1,
            "the one class with an action is counted too — having something to do is not a reason to say nothing"
        );
    }

    #[test]
    fn a_node_reports_the_load_it_carries_rather_than_the_roles_it_offers() {
        // The gap this closes. The role controller has always taken the cell's *demand* — how many nodes each
        // role needs — and the number handed to it was one unit per role a node *offered*, which measures
        // supply and calls it need. So the assignment tracked who volunteered, not what the cell lacked.
        //
        // Two roles now have a real sensor, and the assertion is that they move with the work: a node holding
        // more keys reports more storage load, where the offer-based figure was constant at one whatever the
        // node was doing.
        let members: [Triple; 7] = core::array::from_fn(|i| Point::<F2>::at(i).coords());
        let mut node =
            OverlayNode::<F2>::new(Point::at(0), Config::default())
                .with_cell_members(fano::CellMembers::new(members).expect("a real subplane"));

        let load_of = |node: &mut OverlayNode<F2>, at: u64| -> RoleReading {
            node.step(Instant(at), Input::Command(Command::Diagnose))
                .iter()
                .find_map(|e| match e {
                    Effect::Notify(Notification::LoadReport { per_role }) => {
                        Some(RoleReading::from_array(*per_role))
                    }
                    _ => None,
                })
                .expect("an observation reports the load it measured")
        };

        let idle = load_of(&mut node, 0);

        // The property, first: **a measured zero and an unsensed role are different values.** They were the
        // same `0u16`, so the driver could only tell them apart by guessing, and guessed by value — every zero
        // became the node's offer, discarding the true reading of a role that had legitimately gone idle at
        // exactly the moment the controller should have shrunk it.
        assert_eq!(
            idle.of(Role::Storage),
            Some(0),
            "an empty node measured no keys, and that is a reading — not the absence of one"
        );
        for role in [Role::Service, Role::Exit, Role::Rendezvous] {
            assert_eq!(
                idle.of(role),
                None,
                "{role:?} has no sensor in a bare overlay; reporting 0 would be a fabricated measurement"
            );
        }

        // A sibling engine's reading reaches the report — the seam a composite fills the missing three through.
        node.observe_load(Role::Service, 3);
        assert_eq!(load_of(&mut node, 1).of(Role::Service), Some(3), "a pushed reading is reported");

        // **`Role::Relay` is now the composite's reading, and a bare overlay has none.** It used to be
        // `self_activity` — `Route` frames this node *originated* — which measured the node's traffic as a
        // source rather than the work it carries for others, and did it as a count over a window the
        // behavioural sample clears. Both are recorded at `Healer::load_report`.
        //
        // The property that has to hold now is the one this file states for the other three: **no sensor
        // means absent, not zero.** Traffic this node originates must not resurrect the old reading, so it is
        // driven here and the assertion is that it changes nothing.
        assert_eq!(
            idle.of(Role::Relay),
            None,
            "a bare overlay carries no mix router; a `0` here is a fabricated reading, which is what retires \
             a role that is busy"
        );
        for i in 0..3u8 {
            node.step(
                Instant(2),
                Input::Command(Command::Send { to: Point::<F2>::at(3).coords(), payload: alloc::vec![i] }),
            );
        }
        assert_eq!(
            load_of(&mut node, 2).of(Role::Relay),
            None,
            "originating traffic is this node's own work as a source — it is not relay load, and reporting it \
              as such let a node forwarding the whole cell's mix report zero"
        );

        // And the composite's own reading reaches the report by the same seam as the other three.
        node.observe_load(Role::Relay, 9);
        assert_eq!(
            load_of(&mut node, 3).of(Role::Relay),
            Some(9),
            "the engine that owns the mix router is the one that can see this role's work"
        );

        // And the mechanism: give it shards to hold, and the storage figure must follow.
        //
        // **Delivered as `PUBLISH_SHARD` from a cell member, not as a local `Put`.** A `Put` routes to the
        // key's responsible point and distributes the shards to their homes, so on a cell this node knows the
        // membership of, most keys leave rather than land — which is right, and which used to be invisible
        // because the node believed it was alone and was therefore every key's home (#216). What a storage
        // node actually experiences is shards arriving from its cell, so that is what this feeds it.
        let member = Point::<F2>::at(1).coords();
        for i in 0..4u8 {
            node.step(
                Instant(2),
                Input::Message {
                    from: member,
                    frame: encode_publish(PUBLISH_SHARD, 0, 1, &[i; DIGEST], &[7u8; 64]),
                },
            );
        }
        let busy = load_of(&mut node, 3);
        assert!(
            busy.of(Role::Storage) > idle.of(Role::Storage),
            "storage load must track the keys held: idle {:?} vs busy {:?}",
            idle.of(Role::Storage),
            busy.of(Role::Storage)
        );
    }

    #[test]
    fn a_read_narrows_under_stress_and_never_below_what_the_code_needs() {
        // The law wired into the read path. At rest a `Get` asks every peer — fastest-`K` wins, the right
        // default. Under stress the width follows the headroom, because asking everyone spends `N` messages to
        // recover `K` shards and that amplification lands on the links already struggling.
        //
        // The floor is the erasure code's, not policy's: below `K` a read cannot complete at all, so no stress
        // may produce one. That is the assertion worth having — a narrowing that goes too far does not slow a
        // read down, it makes it impossible.
        let members: [Triple; 7] = core::array::from_fn(|i| Point::<F2>::at(i).coords());
        let mut node =
            OverlayNode::<F2>::new(Point::at(0), Config::default())
                .with_cell_members(fano::CellMembers::new(members).expect("a real subplane"));
        // Pinning the roster says where the seats are; it does not say anyone is in them. Storage placement
        // follows CONTACT (`occupied_points`), so the fixture must state contact — which is what a deployed
        // node has by the time it reads anything (#216).
        seat_every_neighbour(&mut node, Instant(0));
        let lookups = |effects: &[Effect]| {
            effects
                .iter()
                .filter(|e| matches!(e, Effect::Send { frame, .. } if decode_frame(frame)
                    .is_ok_and(|(f, _)| f.frame_type() == Some(FrameType::Lookup))))
                .count()
        };

        let calm = node.step(Instant(0), Input::Command(Command::Get { key: b"k1".to_vec() }));
        assert_eq!(lookups(&calm), 6, "at rest a read asks every peer it knows");

        node.stress_for_test(1.0);
        let strained = node.step(Instant(1), Input::Command(Command::Get { key: b"k2".to_vec() }));
        let asked = lookups(&strained);
        assert!(asked < 6, "under full stress a read must narrow, asked {asked}");
        assert!(
            asked >= erasure::K,
            "asked {asked} peers for a value needing {} shards — that read cannot complete at all",
            erasure::K
        );
    }

    /// **A refusal reports what this node DID, and the four things it can do are four values (#199).**
    ///
    /// The return path is what makes an *adaptive* admission price safe to run: a joiner priced out between
    /// minting its proof and presenting it would otherwise be refused permanently, with the number that
    /// would work sitting unread in a frame nothing dispatched — the attacker's outcome, produced by the
    /// defence.
    ///
    /// But the price alone does not say whether anything happened. Two of the four outcomes are dead ends,
    /// and `AboveCeiling` — the one where this node deliberately spends nothing — used to print the most
    /// reassuring line of the four, because `required: Some(40)` reads like work in progress.
    ///
    /// All four worlds are built here and the outcomes must be **pairwise different**. Folding any two
    /// together fails on the `distinct` check rather than on a hand-written expectation, so the test cannot
    /// be satisfied by a payload that merely echoes its input.
    #[test]
    fn a_refusal_reports_which_of_the_four_things_this_node_did_about_it() {
        let refused = |node: &mut OverlayNode<F2>, body: &[u8]| {
            let frame = crate::frames::encode_error_with(fanos_wire::ProtocolError::SybilReject, body);
            let effects = node.step(Instant(0), Input::Message { from: [1, 0, 0], frame });
            effects
                .iter()
                .find_map(|e| match e {
                    Effect::Notify(Notification::AdmissionRefused { outcome }) => Some(*outcome),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("a SybilReject must surface as a refusal: {effects:?}"))
        };

        // (D) A payable price: solved, and a retry can now succeed. The only self-correcting outcome.
        let mut fresh = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let repaid = refused(&mut fresh, &17u32.to_le_bytes());
        assert_eq!(repaid, AdmissionOutcome::Repaid { bits: 17 }, "a payable price must be paid");
        assert_eq!(fresh.paid_difficulty_for_test(), Some(17), "and the proof must actually move");

        // (B) The same node asked for less than it now pays. A proof is monotone, so there is nothing to
        // buy — and the refusal is therefore about something the peer did not say.
        let sufficient = refused(&mut fresh, &5u32.to_le_bytes());
        assert_eq!(sufficient, AdmissionOutcome::AlreadySufficient { paid: 17, asked: 5 });
        assert_eq!(fresh.paid_difficulty_for_test(), Some(17), "and nothing was re-solved");

        // (C) Above the ceiling: nothing is spent, deliberately, because "solve harder" on demand is a
        // remote CPU-exhaustion primitive. The proof must be untouched — this assertion is the one that
        // separates a dead end from work in progress.
        let before = fresh.admission_proof_for_test().to_vec();
        let over = refused(&mut fresh, &(MAX_INLINE_ADMISSION_BITS + 1).to_le_bytes());
        assert_eq!(
            over,
            AdmissionOutcome::AboveCeiling {
                asked: MAX_INLINE_ADMISSION_BITS + 1,
                ceiling: MAX_INLINE_ADMISSION_BITS
            }
        );
        assert_eq!(fresh.admission_proof_for_test(), before.as_slice(), "not one hash was spent");

        // (A) No price at all — an older peer, or a policy where difficulty is not a number. Carried as its
        // own variant precisely so a driver cannot read it as zero and re-solve for ever against a gate
        // that wants work.
        let mut silent_peer = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let none = refused(&mut silent_peer, &[]);
        assert_eq!(none, AdmissionOutcome::NoGuidance);

        // And the property the four assertions above do not state on their own: no two of these worlds
        // report the same thing. This is what fails if a later change folds a dead end into a success.
        let all = [repaid, sufficient, over, none];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "two different outcomes report identically: {a:?}");
            }
        }
    }

    #[test]
    fn an_error_that_is_not_an_admission_refusal_is_not_surfaced() {
        // Only the actionable one. The rest are diagnostics, and this engine is sans-I/O — it has nowhere to
        // write a log and no business waking a driver for something it cannot act on.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let other =
            crate::frames::encode_error_with(fanos_wire::ProtocolError::Malformed, &[]);
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

    /// **A frame this node CARRIES is behavioural load on both ends of the hop, and the forward arm counted
    /// neither end.**
    ///
    /// `on_route_hier`'s deliver arm records the sender's activity; the forward arm recorded nothing. So a
    /// peer whose traffic through this node always transits read as **idle** in this node's coherence model,
    /// and the node's own carrying work was invisible to itself — the two ends of one omission.
    ///
    /// Driven through the real dispatch rather than through the healer's counters, because the counters are
    /// not the claim: removing both calls from the forward arm leaves a healer-level test green, which is
    /// how this one came to exist.
    #[test]
    #[allow(clippy::float_cmp)] // counts, exactly representable: 1.0 is the count, not a computed quantity
    fn a_carried_frame_is_behavioural_load_at_both_ends_of_the_hop() {
        // Depth-2 seating [3,5], with a learned peer one cell over so a foreign destination FORWARDS rather
        // than delivering or dropping.
        let mut node = OverlayNode::<F2>::new(Point::at(3), Config::default()).with_hier_address(
            HierAddr::from_path(alloc::vec![Point::<F2>::at(3), Point::<F2>::at(5)]).unwrap(),
        );
        let next_addr =
            HierAddr::from_path(alloc::vec![Point::<F2>::at(2), Point::<F2>::at(1)]).unwrap();
        let next_hop = Point::<F2>::at(2).coords();
        node.learn_hier_peer(next_addr.clone(), next_hop);

        let upstream = Point::<F2>::at(1).coords();
        let mut body = next_addr.encode();
        body.extend_from_slice(b"transit");
        let effects = node.step(
            Instant(0),
            Input::Message { from: upstream, frame: encode(FrameType::RouteHier, &body) },
        );
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Send { to, .. } if *to == next_hop)),
            "the fixture must FORWARD — a delivered or dropped frame would test the wrong arm: {effects:?}"
        );

        node.healer.sample_behavior::<F2>(node.self_index);
        let sample = node.healer.last_sample;
        let me = node.self_index.expect("seated on the base cell");
        assert_eq!(
            sample[Point::<F2>::new(upstream).unwrap().index()],
            1.0,
            "the upstream peer put a frame on the wire toward us; carrying it is not a reason to ignore that"
        );
        assert_eq!(sample[me], 1.0, "and we put one on the wire toward the next hop — that is our work");
    }

    /// **Only the identity already at a coordinate may move that coordinate's address.**
    ///
    /// `on_announce` is first-sight-only, and the descent needed one exception: a node that descends
    /// re-announces from the coordinate it already holds, so under the plain rule every peer drops it as a
    /// repeat and the sub-cell address is announced into silence. The exception is narrow because the guard's
    /// own reason is real — *"any peer could silently replace a member's advertised keys in our local
    /// view"* — and this pins the narrowness rather than the exception.
    ///
    /// Three announcements at one coordinate: the member's own (learned), a **stranger's** with a different
    /// address (refused), and the member's own again with a new address (learned). Without the identity
    /// check the middle one would be admitted and whoever announced last would own the route.
    #[test]
    fn a_strangers_announcement_cannot_move_a_members_overlay_address() {
        use crate::frames::announce_body;
        let mine = alloc::vec![9u8; 8];
        let stranger = alloc::vec![4u8; 8];
        let seat = Point::<F2>::at(1);
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());

        let announce = |id: &[u8], depth: usize| {
            let path: Vec<Point<F2>> =
                (0..depth).map(|l| if l == 0 { seat } else { Point::<F2>::at(3 + l) }).collect();
            let hier = HierAddr::from_path(path).unwrap();
            encode(FrameType::Announce, &announce_body(seat.coords(), &hier, id, &[], &[], &[7u8]))
        };
        // `PeerAddressed` means *moved*, so first sight is observed through `MemberJoined` instead — the
        // asymmetry is the notification's contract and asserting it here is what keeps the two apart.
        let moved = |effects: &[Effect]| {
            effects.iter().find_map(|e| match e {
                Effect::Notify(Notification::PeerAddressed { path, .. }) => Some(path.len()),
                _ => None,
            })
        };
        let joined = |effects: &[Effect]| {
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::MemberJoined { .. })))
        };

        let first = node.step(Instant(0), Input::Message { from: seat.coords(), frame: announce(&mine, 1) });
        assert!(joined(&first), "first sight of a member must be learned, or the guard refuses everyone");
        assert_eq!(
            moved(&first),
            None,
            "first sight is not a move — reporting one would put an extra notification on the broadcast for \
             every announce the cell has ever made"
        );
        assert_eq!(
            moved(&node.step(Instant(0), Input::Message { from: seat.coords(), frame: announce(&stranger, 3) })),
            None,
            "a different identity moved a member's address — then the route belongs to whoever announced last"
        );
        assert_eq!(
            moved(&node.step(Instant(0), Input::Message { from: seat.coords(), frame: announce(&mine, 2) })),
            Some(2),
            "the identity that holds the coordinate must be able to descend, which is the whole exception"
        );
        assert_eq!(
            moved(&node.step(Instant(0), Input::Message { from: seat.coords(), frame: announce(&mine, 2) })),
            None,
            "and re-flooding an address it already announced is not news — that is what ends the flood"
        );

        // **An unsigned deployment must not get the exception at all.** With no self-certifying identity
        // every announcer's `id` is empty, so "the same identity" would be true for anybody and the
        // exception would hand the route to whoever announced last — the opposite of what it is for. A
        // second coordinate, because the first one's identity is now recorded.
        let bare = Point::<F2>::at(2);
        let unsigned = |depth: usize| {
            let path: Vec<Point<F2>> =
                (0..depth).map(|l| if l == 0 { bare } else { Point::<F2>::at(3 + l) }).collect();
            let hier = HierAddr::from_path(path).unwrap();
            encode(FrameType::Announce, &announce_body(bare.coords(), &hier, &[], &[], &[], &[7u8]))
        };
        assert!(
            joined(&node.step(Instant(0), Input::Message { from: bare.coords(), frame: unsigned(1) })),
            "an unsigned deployment still learns its members at first sight"
        );
        assert_eq!(
            moved(&node.step(Instant(0), Input::Message { from: bare.coords(), frame: unsigned(3) })),
            None,
            "an empty identity matched itself and moved the address — under an unsigned deployment that is \
             every peer, so the exception would be unconditional"
        );
    }

    /// **The descent's two levels are decided by two different rules, and the engine may only apply one of
    /// them.**
    ///
    /// Level 0 is settled by the VRF claim order, which lives in the driver and is invisible here: a rival
    /// for this node's own point is not in `router.peers`, because that table is keyed by transport
    /// coordinate and this node *is* that coordinate. So `contested` is an argument. Levels ≥ 1 are
    /// `address_point(id, level)` arbitrated on identity bytes, and only this layer has the identities.
    ///
    /// Both answers are asserted, because an implementation that always descended would satisfy the second
    /// alone — and a node that descends while it holds its point makes itself unreachable for nothing.
    #[test]
    fn a_contested_node_is_told_a_sub_cell_under_the_point_it_lost_and_an_uncontested_one_its_flat_address() {
        let id = alloc::vec![7u8; 32];
        let mut node = OverlayNode::<F2>::new(Point::at(3), Config::default()).with_identity(id.clone());

        let proposed = |node: &mut OverlayNode<F2>, contested: bool| -> Option<Vec<Triple>> {
            node.step(Instant(0), Input::Command(Command::ProposeAddress { contested }))
                .into_iter()
                .find_map(|e| match e {
                    Effect::Notify(Notification::AddressProposed { path }) => Some(path),
                    _ => None,
                })
        };

        assert_eq!(
            proposed(&mut node, false),
            Some(alloc::vec![Point::<F2>::at(3).coords()]),
            "a node that holds its point is told the flat address — descending would cost it its own seat"
        );
        assert_eq!(
            proposed(&mut node, true),
            Some(alloc::vec![
                Point::<F2>::at(3).coords(),
                fanos_primitives::address_point::<F2>(&id, 1).coords(),
            ]),
            "a beaten node is told a sub-cell UNDER the point it wanted, derived from its own identity"
        );
    }

    /// **A smaller identity already in the sub-cell pushes this node one level deeper, and a peer nobody can
    /// name pushes nobody.**
    ///
    /// Priority is the strict total order on identity bytes, so of any identities contesting a position
    /// exactly one keeps it and the rest descend — conflict-free, with no negotiation, because every node
    /// runs the same pure function over the same view. The second half is the one an implementation gets
    /// wrong: a peer registered as a *route* carries no identity, cannot be compared, and must therefore not
    /// displace anyone. Yielding to it would be yielding to whoever announced last.
    #[test]
    fn only_a_smaller_identity_can_push_this_node_deeper_into_a_sub_cell() {
        let mine = alloc::vec![7u8; 32];
        let smaller = alloc::vec![1u8; 32];
        let sub = fanos_primitives::address_point::<F2>(&mine, 1);
        let taken = HierAddr::from_path(alloc::vec![Point::<F2>::at(3), sub]).unwrap();

        let deeper = |node: &mut OverlayNode<F2>| {
            node.step(Instant(0), Input::Command(Command::ProposeAddress { contested: true }))
                .into_iter()
                .find_map(|e| match e {
                    Effect::Notify(Notification::AddressProposed { path }) => Some(path.len()),
                    _ => None,
                })
        };

        // The rival holds exactly the path this node would take, and its identity sorts first.
        let mut yielded = OverlayNode::<F2>::new(Point::at(3), Config::default())
            .with_identity(mine.clone())
            .with_hier_peer_identity(smaller, taken.clone(), Point::<F2>::at(5).coords());
        assert_eq!(deeper(&mut yielded), Some(3), "the larger identity descends past the point it lost twice");

        // The same route with no identity behind it: nothing to compare, so nothing yields.
        let mut held = OverlayNode::<F2>::new(Point::at(3), Config::default())
            .with_identity(mine)
            .with_hier_peer(taken, Point::<F2>::at(5).coords());
        assert_eq!(
            deeper(&mut held),
            Some(2),
            "a route with no identity displaced this node — then whoever announces last wins the sub-cell"
        );
    }

    /// **`Descend` adopts an address and re-announces under it; depth 1 is how a node comes back up.**
    ///
    /// `on_reseat` preserves the deep levels across a reshuffle on purpose — they are identity-derived and
    /// epoch-independent — so without an explicit ascent a node that descended once would stay in a sub-cell
    /// for the life of the process even after it won its point back.
    ///
    /// The refusals are asserted beside it because each of them is a caller bug that would leave this node
    /// announcing an address nobody routes to it: a foreign level 0 is a different node's address, and a
    /// coordinate that is not a point of this plane is not an address at all.
    #[test]
    fn descend_adopts_re_announces_and_ascends_and_refuses_an_address_that_is_not_this_nodes() {
        let mut node = OverlayNode::<F2>::new(Point::at(3), Config::default());
        let deep = alloc::vec![Point::<F2>::at(3).coords(), Point::<F2>::at(5).coords()];

        let effects = node.step(Instant(0), Input::Command(Command::Descend { path: deep.clone() }));
        assert_eq!(node.hier_address().points(), &[Point::<F2>::at(3), Point::<F2>::at(5)], "the address is adopted");
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Send { .. })),
            "a descent that nobody hears leaves the descendant unroutable — `RouteHier` learns from the announce"
        );
        assert_eq!(node.coord.coords(), Point::<F2>::at(3).coords(), "the TRANSPORT coordinate does not move");

        // Idempotent: the same address again is not news, so it does not re-flood.
        assert!(
            node.step(Instant(0), Input::Command(Command::Descend { path: deep })).is_empty(),
            "re-adopting the address already held must not put an announce on the wire"
        );

        // Ascent.
        node.step(
            Instant(0),
            Input::Command(Command::Descend { path: alloc::vec![Point::<F2>::at(3).coords()] }),
        );
        assert_eq!(node.hier_address().depth(), 1, "depth 1 brings a node back out of its sub-cell");

        // Refusals, each leaving the address untouched.
        for bad in [
            alloc::vec![Point::<F2>::at(4).coords(), Point::<F2>::at(5).coords()], // a foreign level 0
            alloc::vec![[0, 0, 0]],                                                // not a point of the plane
            alloc::vec![],                                                         // no address at all
        ] {
            assert!(
                node.step(Instant(0), Input::Command(Command::Descend { path: bad })).is_empty(),
                "a path that is not this node's address must not be adopted or announced"
            );
            assert_eq!(node.hier_address().depth(), 1, "and must leave the address it had standing");
        }
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
    ///
    /// The child index is two bytes on the wire (#110): one aliased any index above 255 onto a different,
    /// *valid* child on a wide plane. Narrowed back to `u8` here only because every test in this module runs
    /// on the Fano base cell, where 7 points cannot reach that — and asserted, so a later test on a wider
    /// plane fails loudly here instead of comparing the wrong number.
    fn cell_escalate(e: &Effect) -> Option<(Triple, [u8; 3])> {
        let Effect::Send { to, frame } = e else { return None };
        let (f, _) = decode_frame(frame).ok()?;
        if f.frame_type() != Some(FrameType::CellEscalate) {
            return None;
        }
        match f.body {
            [hi, lo, r, t] => {
                let child = u16::from_be_bytes([*hi, *lo]);
                let child = u8::try_from(child).expect("this module's tests are base-cell only");
                Some((*to, [child, *r, *t]))
            }
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
        parent.healer.last_phi = Some(81.0);
        let frame = encode(FrameType::CellEscalate, &[0u8, 3, 0b0010, ESCALATE_TTL]);
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
        // With a MEASURED but exhausted coarse budget (Φ = 1 ⇒ ⌊log₉1⌋ = 0) and no grandparent, a top-cell
        // parent cannot absorb the child escalation → terminal `Escalated` (external help), and no reroute.
        //
        // The `Some(1.0)` is written out, and that is the point of this test after #259. It used to rely on
        // `last_phi` *defaulting* to 1.0 — so it pinned the fabricated value rather than a measured one, and
        // the moment the default became `None` it would have gone on passing while silently testing a
        // different branch. Its twin below covers the unmeasured case, and the pair is what separates them.
        let mut parent = OverlayNode::<F2>::new(Point::at(0), Config::default());
        parent.healer.last_phi = Some(1.0);
        let frame = encode(FrameType::CellEscalate, &[0u8, 3, 0b0010, ESCALATE_TTL]);
        let effects = parent.step(Instant(0), Input::Message { from: [9, 9, 9], frame });
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Escalated(_)))),
            "a top parent with no budget escalates terminally: {effects:?}"
        );
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Rerouted { .. }))),
            "and does not reroute what it cannot afford"
        );
        assert_eq!(
            parent.stations.total(Station::EscalationUnbudgeted),
            0,
            "a MEASURED refusal is not an unbudgeted one — the station must stay silent here"
        );
    }

    /// **A refusal with no measurement behind it is a different report** (#259).
    ///
    /// `last_phi` was `f64 = 1.0`, and `stratum`'s own test uses 1.0 to mean *the parent tier cannot afford
    /// this* — so a node that had never diagnosed itself answered a child's escalation with a confident
    /// refusal it had measured nothing to support. The action is unchanged (declining is right: absorbing
    /// means drawing a reroute plan against a budget nobody measured), so what this pins is the report.
    ///
    /// Falsified by deleting the `record` call in `on_cell_escalate`: the count goes to 0 and this fails,
    /// while its twin above keeps passing — which is what proves the two branches are actually separated.
    #[test]
    fn a_parent_that_never_diagnosed_declines_the_escalation_and_says_it_had_no_budget() {
        let mut parent = OverlayNode::<F2>::new(Point::at(0), Config::default());
        assert_eq!(parent.healer.last_phi(), None, "a fresh node has diagnosed nothing, so it holds no Φ");
        let frame = encode(FrameType::CellEscalate, &[0u8, 3, 0b0010, ESCALATE_TTL]);
        let effects = parent.step(Instant(0), Input::Message { from: [9, 9, 9], frame });
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Escalated(_)))),
            "it still hands the fault on rather than swallowing it: {effects:?}"
        );
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Rerouted { .. }))),
            "and installs no reroute, because it has no budget to draw one against"
        );
        assert_eq!(
            parent.stations.total(Station::EscalationUnbudgeted),
            1,
            "and the reason reaches an operator instead of looking like a measured refusal"
        );
    }

    /// **A seating change invalidates Φ like everything else derived from the coherence model** (#259).
    ///
    /// The omission that made this a wrong *action* rather than a wrong label: `on_seating_changed` clears
    /// `last_sample`, `measured_correlation`, `band_streak` and `last_band` — and used to leave `last_phi`
    /// alone. A healthy stale Φ therefore let the parent tier absorb a child's escalation and install coarse
    /// reroutes computed from the coherence reading of a seating that no longer exists.
    ///
    /// Falsified by removing `self.last_phi = None;` from `on_seating_changed`: the reroute reappears and
    /// both assertions below fail.
    #[test]
    fn a_seating_change_takes_the_coarse_budget_with_it() {
        let mut parent = OverlayNode::<F2>::new(Point::at(0), Config::default());
        parent.healer.last_phi = Some(81.0); // ⌊log₉81⌋ = 2 affordable coarse hops — enough to absorb
        parent.healer.on_seating_changed();
        assert_eq!(
            parent.healer.last_phi(),
            None,
            "Φ measured against the old seating is a reading of a different cell, not a stale one"
        );

        let frame = encode(FrameType::CellEscalate, &[0u8, 3, 0b0010, ESCALATE_TTL]);
        let effects = parent.step(Instant(0), Input::Message { from: [9, 9, 9], frame });
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Notify(Notification::Rerouted { .. }))),
            "and no reroute is drawn against it: {effects:?}"
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

    /// **A liveness quorum drawn from outside the cell is not a quorum** (#107).
    ///
    /// `coord_alive` falls back to counting distinct fresh witnesses for a peer it cannot see directly. The
    /// count is sized against *this cell's* fault budget, so the set it is drawn from has to be this cell —
    /// otherwise forging liveness costs `Q` admitted identities **anywhere**, needs no cell seat at all, and
    /// the vouch-fabricator judge that backs the quorum up cannot reach the forgers, because it quarantines
    /// members.
    ///
    /// Holding a dead node believed-alive is the availability attack this predicate exists to prevent: the
    /// cell does not reroute around it and does not regenerate its shards, so the erasure store loses
    /// redundancy while every node reports health.
    #[test]
    fn only_cell_members_can_witness_a_peers_liveness() {
        /// A `HealthView` body claiming a fresh direct observation of every cell point.
        fn vouch_for_all() -> Vec<u8> {
            let mut body = Vec::with_capacity(14);
            for _ in 0..7 {
                body.extend_from_slice(&1u16.to_le_bytes()); // observed 1 ms ago
            }
            body
        }

        // **Past the startup grace, and the vouches fresh inside it.** `coord_alive` assumes an entirely
        // unobserved peer is alive for one `liveness_timeout` after start — so a `now` inside that window
        // makes *every* branch return true and the test vacuous. Deliver at `SENT` and judge a nanosecond
        // later: the grace has expired (5 s > 1.6 s) while the vouches are 1 ms old.
        const SENT: Instant = Instant(5_000_000_000);

        let target = Point::<F2>::at(3).coords();
        let now = Instant(SENT.as_nanos() + 1);
        let quorum = Config::default().corroboration_quorum;

        // Outsiders: coordinates that are NOT points of this cell. `F2`'s plane has exactly 7, so anything
        // past them is a stranger — which on a hierarchical transport is an ordinary, reachable peer.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        for k in 0..(quorum + 2) {
            let outsider: Triple = [200 + k as u32, 1, 1];
            assert!(node.cell_position(outsider).is_none(), "the test's outsider must not be a cell member");
            node.step(
                SENT,
                Input::Message { from: outsider, frame: encode(FrameType::DiagGossip, &vouch_for_all()) },
            );
        }
        assert!(
            !node.coord_alive(target, now),
            "{} strangers vouching must not make a peer this node cannot see read as alive — the quorum is \
             sized against the CELL's fault budget, so drawing it from outside the cell voids the sizing",
            quorum + 2,
        );

        // The falsification: the identical vouches from genuine cell members DO corroborate. Without this
        // the assertion above would pass on a node that simply never believes anybody.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        for i in 1..=quorum {
            let member = Point::<F2>::at(i).coords();
            assert!(node.cell_position(member).is_some(), "a cell point must be a member");
            node.step(
                SENT,
                Input::Message { from: member, frame: encode(FrameType::DiagGossip, &vouch_for_all()) },
            );
        }
        assert!(node.coord_alive(target, now), "a quorum of genuine members does corroborate");

        // And one short of the quorum does not — so the count is load-bearing, not decorative.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        for i in 1..quorum {
            let member = Point::<F2>::at(i).coords();
            node.step(
                SENT,
                Input::Message { from: member, frame: encode(FrameType::DiagGossip, &vouch_for_all()) },
            );
        }
        assert!(!node.coord_alive(target, now), "one witness short of the quorum must not corroborate");
    }

    /// **The corroboration quorum has exactly one admissible value at Fano**, and it is derived from both
    /// sides rather than chosen (#107).
    #[test]
    fn the_corroboration_quorum_is_bracketed_from_both_sides() {
        let n = CELL_POINTS;
        let f = fault_budget(n);
        let q = corroboration_quorum(n);
        assert_eq!((n, f, q), (7, 2, 3), "the Fano cell: n = 7, f = 2, and the quorum is f + 1");
        assert_eq!(Config::default().corroboration_quorum, q, "the default is the derivation, not a literal");

        // Safety: forging must cost MORE than the tolerated coalition. A quorum of `f` would let exactly the
        // budget the cell already tolerates fabricate liveness — which was the shipped state at `Q = 2`.
        assert!(q > f, "a tolerated coalition of {f} must not be able to forge liveness");
        // Liveness: the honest witnesses alone must be able to supply it. Available witnesses are the cell
        // minus the subject and minus this node.
        assert!(q <= n - 2 - f, "an honest cell must be able to reach the quorum with {f} members faulty");
        // Together those two pin it: at Fano the bracket is empty for every other value.
        assert_eq!(f + 1, n - 2 - f, "at Fano the safety floor and the liveness ceiling coincide");

        // It moves with the plane rather than being a constant, and stays inside its own bracket there too.
        for n in [7usize, 13, 21, 57] {
            let (f, q) = (fault_budget(n), corroboration_quorum(n));
            assert!(q > f && q <= n - 2 - f, "n={n}: quorum {q} must sit inside [{}, {}]", f + 1, n - 2 - f);
        }
    }

    #[test]
    fn no_coherence_verdict_escapes_before_the_window_is_full() {
        // **A two-point correlation is `±1` exactly** — two samples always lie on a line — so a node that
        // read its self-model on the second heartbeat would see every `|C_ij| = 1`, i.e. `Φ = 6` and a mean
        // correlation of 1, and hand the homeostat a confident `Decouple` drawn from a matrix carrying no
        // information. Under the lockstep flood below that is exactly what happens: the dwell is satisfied by
        // heartbeats 2–4 and the shed actuates less than halfway to a full window.
        //
        // The property is therefore a *timing* one: the first coherence-driven notification must not appear
        // before the window has `Config::default().behavior_window()` samples. Asserted as the index it first fires at, not as a
        // boolean, so a run that never fires at all cannot pass by silence — the second assertion is what
        // makes the first one mean something.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));

        let mut t = 1u64;
        let mut first_verdict: Option<usize> = None;
        for w in 0..(Config::default().behavior_window() + 4) {
            let bursts = (w % 3) + 1; // identical across peers → perfectly correlated at every window length
            for i in 1..7usize {
                let from = Point::<F2>::at(i).coords();
                for _ in 0..bursts {
                    node.step(Instant(t), Input::Message { from, frame: encode(FrameType::Route, b"x") });
                    t += 1;
                }
            }
            let hb = node.step(Instant(t), Input::Timer(HEARTBEAT));
            // Only the homeostat's own outputs. `Escalated` is deliberately excluded: it is emitted both by
            // the band's `Escalate` arm and by the liveness healing plan, so it cannot tell a coherence
            // verdict from a peer going stale — which is a defect in its own right, not a signal this test
            // can use.
            let spoke = hb.iter().any(|e| {
                matches!(
                    e,
                    Effect::Notify(
                        Notification::Decoupled | Notification::Bound | Notification::Rebalance { .. }
                    )
                )
            });
            if spoke && first_verdict.is_none() {
                first_verdict = Some(w);
            }
            t += 1;
        }

        let at = first_verdict.expect(
            "the flood must eventually produce a coherence verdict — otherwise this test proves nothing \
             about *when* one appears",
        );
        assert!(
            at + 1 >= Config::default().behavior_window(),
            "a coherence verdict escaped at heartbeat {} with only {} samples: below a full window the \
             correlation matrix is degenerate, and acting on it is acting on nothing",
            at + 1,
            at + 1,
        );
    }

    /// **An epoch turn ends the observation it interrupts** (#153) — on *both* paths to a new epoch.
    ///
    /// The behavioural window's slot `i` is a cell POSITION, and an epoch re-draws every node's VRF
    /// coordinate, so the position keeps its name and changes its occupant. A window that spans the turn is a
    /// splice of two seatings, and on a cell whose members carry different loads that splice reads a
    /// perfectly coherent cell as *anti*-correlated — measured deterministically one crate down, in
    /// `monitor::tests::a_window_spanning_a_seat_permutation_reads_a_coherent_cell_as_anti_correlated`.
    ///
    /// Deliver `claimed` as an `EpochAgree` from `n` distinct cell members, starting at point 1.
    fn claim_epoch(node: &mut OverlayNode<F2>, claimed: Epoch, claimants: impl IntoIterator<Item = usize>) {
        for c in claimants {
            node.step(
                Instant(0),
                Input::Message {
                    from: Point::<F2>::at(c).coords(),
                    frame: encode(FrameType::EpochAgree, &claimed.low32_be_bytes()),
                },
            );
        }
    }

    /// **One member cannot set the cell's clock** (#351).
    ///
    /// `EpochAgree` carries a bare four-byte ordinal and inherited `adopt-max`, a rule whose safety came from
    /// the beacon round proving itself. Every other decision in FANOS tolerates `f` faulty members; this one
    /// tolerated zero. The stall is counted, and tagged with how many vouched, because a node that cannot
    /// corroborate must escalate rather than decide — and a stall nobody can see is not an escalation.
    #[test]
    fn a_single_witness_cannot_move_the_cells_epoch() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let start = node.epoch();
        claim_epoch(&mut node, start.saturating_add(2), 1..2);
        assert_eq!(node.epoch(), start, "one claimant is not a quorum, so the epoch must not move");
        let stalled: u64 = node
            .stations
            .observations()
            .iter()
            .filter(|o| o.station == Station::EpochAgreeBelowQuorum)
            .map(|o| o.count)
            .sum();
        assert_eq!(stalled, 1, "the refusal must be counted — a stall nobody can see is not an escalation");
    }

    /// **A quorum moves it, and in one round** (#351) — the other half, without which the fix is
    /// indistinguishable from a node that simply stopped agreeing epochs at all.
    #[test]
    fn a_quorum_of_witnesses_moves_the_epoch_in_one_round() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let start = node.epoch();
        let target = start.saturating_add(2);
        let quorum = Config::default().corroboration_quorum;
        claim_epoch(&mut node, target, 1..=quorum);
        assert_eq!(node.epoch(), target, "a quorum of distinct claimants must be adopted immediately");
    }

    /// **`f` liars cannot outvote an honest claim** (#351) — the ORDER-STATISTIC property, which a plain
    /// threshold test cannot see.
    ///
    /// A count of claimants says "enough members said something". What a quorum means is "enough members
    /// reached at least THIS", and only reading the `q`-th largest claim expresses it. With `f` liars shouting
    /// a far epoch and a quorum vouching a near one, the near one is what a quorum has actually reached.
    #[test]
    fn f_liars_cannot_outvote_an_honest_claim() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let start = node.epoch();
        let honest = start.saturating_add(1);
        let lie = start.saturating_add(9);
        let f = fault_budget(CELL_POINTS);
        let quorum = Config::default().corroboration_quorum;
        // The liars claim first and loudest; the honest majority claims a nearer epoch after them.
        claim_epoch(&mut node, lie, 1..=f);
        claim_epoch(&mut node, honest, (f + 1)..=(f + quorum));
        assert_eq!(
            node.epoch(),
            honest,
            "the adopted epoch must be the one a QUORUM has reached, not the largest any minority shouted",
        );
    }

    /// **One forged claim must not expire the directory** (#351) — the only test here about the DAMAGE, and
    /// every mechanism test above can pass while this one still fires.
    ///
    /// `DIRECTORY_SLOT_EPOCHS = 1`, so a slot written at `E` is reclaimed once `now ≥ E+2`. The attack is
    /// therefore `current + 2` and **not** `u32::MAX`: a two-epoch jump is indistinguishable from a node whose
    /// beacon ran two rounds while it was busy, which is exactly why no bound on the magnitude of a jump can
    /// work and only corroboration can.
    #[test]
    fn a_single_forged_claim_does_not_expire_the_directory() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        node.step(
            Instant(0),
            Input::Command(Command::PutEphemeral {
                key: b"a directory slot".to_vec(),
                value: b"a published record".to_vec(),
                epochs: 1,
            }),
        );
        let held = node.store.entries.len();
        assert_eq!(held, 1, "the setup must actually have stored something, or nothing below can fail");
        let forged = node.epoch().saturating_add(2);
        claim_epoch(&mut node, forged, 1..2);
        assert_eq!(
            node.store.entries.len(),
            held,
            "one member's unverified claim of `current + 2` reclaimed the directory slice — the epoch it \
             names is plausible, unlogged, and two epochs is all it takes",
        );
    }

    /// **A claim the cell has reached stops counting** (#351).
    ///
    /// The claims map needs no freshness window and no chosen constant, because a claim is worthless once the
    /// cell reaches it — and `on_epoch_changed` is exactly that moment. Without the prune the map would keep
    /// spent claims and a later quorum could be assembled out of votes that were already honoured.
    #[test]
    fn claims_the_cell_has_reached_stop_counting() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let quorum = Config::default().corroboration_quorum;
        let target = node.epoch().saturating_add(2);
        claim_epoch(&mut node, target, 1..=quorum);
        assert_eq!(node.epoch(), target, "the setup must have advanced, or the prune below is untested");
        assert!(
            node.epoch_claims.is_empty(),
            "claims at or below the epoch the cell reached must be dropped; {} survived",
            node.epoch_claims.len(),
        );
    }

    /// What *this* pins is the wiring, and specifically that both paths do it. A node reaches a new epoch
    /// either by its own `AdvanceEpoch` or by adopting a peer's `EpochAgree` gossip, and a fix applied to one
    /// of them would make whether a cell's self-model is spliced depend on which node happened to drive the
    /// advance — the identical hazard the store sweep already had to be duplicated for.
    #[test]
    fn a_new_epoch_ends_the_coherence_observation_it_interrupts_on_both_paths() {
        // Drive `windows` full observation rounds and return the first (if any) at which a coherence verdict
        // escaped. Two traffic shapes, because the homeostat's notifications are deduped per band: the
        // recovery assertion has to be able to fire, and a repeat of the pre-boundary verdict is silent by
        // design. `hotspot = false` is the lockstep flood (over-coupled → `Decoupled`); `true` is the k = 4
        // correlated block inside an otherwise independent cell (under-coupled → `Rebalance`), the same
        // construction `a_cell_wide_hotspot_drives_the_projective_load_balance` derives.
        fn run(node: &mut OverlayNode<F2>, t: &mut u64, windows: usize, hotspot: bool) -> Option<usize> {
            let mut first = None;
            for w in 0..windows {
                let bursts = (w % 3) + 1; // identical across peers → correlated at every window length
                let hot = (w % 5) + 1; // the hot block's shared load this round — this node is its fourth member
                for i in 1..7usize {
                    let from = Point::<F2>::at(i).coords();
                    let count = match (hotspot, i <= 3) {
                        (false, _) => bursts,
                        (true, true) => hot,
                        (true, false) => 1 + (w * (2 * i + 1)) % 7,
                    };
                    for _ in 0..count {
                        node.step(Instant(*t), Input::Message { from, frame: encode(FrameType::Route, b"x") });
                        *t += 1;
                    }
                }
                if hotspot {
                    // This node itself is the fourth member of the hot block.
                    for _ in 0..hot {
                        node.step(
                            Instant(*t),
                            Input::Command(Command::Send {
                                to: Point::<F2>::at(1).coords(),
                                payload: b"x".to_vec(),
                            }),
                        );
                        *t += 1;
                    }
                }
                let hb = node.step(Instant(*t), Input::Timer(HEARTBEAT));
                *t += 1;
                let spoke = hb.iter().any(|e| {
                    matches!(
                        e,
                        Effect::Notify(
                            Notification::Decoupled | Notification::Bound | Notification::Rebalance { .. }
                        )
                    )
                });
                if spoke && first.is_none() {
                    first = Some(w);
                }
            }
            first
        }

        let window = Config::default().behavior_window();
        for own_tick in [true, false] {
            let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
            node.step(Instant(0), Input::Command(Command::StartHeartbeat));
            let mut t = 1u64;

            // The mechanism must be live, or every assertion below passes by silence.
            assert!(
                run(&mut node, &mut t, window + 4, false).is_some(),
                "no coherence verdict at all before the boundary — this test would then prove nothing",
            );

            // The epoch turns. Either this node ticks it, or it adopts a peer's gossip; the engine must not
                // care which.
            if own_tick {
                node.step(Instant(t), Input::Command(Command::AdvanceEpoch));
            } else {
                let next = node.epoch().next();
                // **A quorum of distinct claimants, not one** (#351). The gossip path no longer adopts on a
                // single member's say-so: `EpochAgree` carries a bare ordinal that proves nothing, so the
                // epoch it names is adopted only once `corroboration_quorum` distinct members have reached
                // it. That is this test's setup requirement and not its subject — what it pins is still that
                // BOTH paths end the coherence observation, so the setup is brought up to the new rule rather
                // than the rule relaxed for the test.
                let quorum = Config::default().corroboration_quorum;
                for claimant in 1..=quorum {
                    node.step(
                        Instant(t),
                        Input::Message {
                            from: Point::<F2>::at(claimant).coords(),
                            frame: encode(FrameType::EpochAgree, &next.low32_be_bytes()),
                        },
                    );
                }
                assert_eq!(node.epoch(), next, "the gossip path must actually have advanced the epoch");
            }
            t += 1;

            // THE PROPERTY: for a whole window afterwards the node has no self-model and says nothing about
            // coherence — not one verdict drawn from a window that straddles the turn. Driven with the
            // *hotspot* shape, so the post-boundary rows genuinely disagree with the pre-boundary ones: a
            // spliced window has something new to say here, and must still say nothing.
            let escaped = run(&mut node, &mut t, window - 1, true);
            assert!(
                escaped.is_none(),
                "a coherence verdict escaped {} rounds after the epoch turn (own_tick = {own_tick}), from a \
                 window still holding samples addressed by the PREVIOUS seating",
                escaped.unwrap_or(0) + 1,
            );

            // And it recovers: once a full window of one consistent seating exists, the loop speaks again.
            assert!(
                run(&mut node, &mut t, window + 4, true).is_some(),
                "the reflex never recovered (own_tick = {own_tick}) — dropping the window must cost one \
                 window, not the self-model",
            );
        }
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
        for w in 0..(Config::default().behavior_window() + 2) {
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
    fn a_hotspot_drives_the_under_coupled_band_and_emits_a_rebalance_prescription() {
        // §6.7 live wiring — and **the scenario had to be re-derived**, because the one this test used to
        // drive does not reach the band it names. It flooded every node with an *independent* amount, which
        // drives the whole matrix toward zero: measured at the derived window, `purity = 0.2465 ≤ 2/7`, so
        // the homeostat returns `Escalate` (a coherence collapse), never `Bind`. It passed at the old
        // eight-sample window only because small-sample noise inflated the correlations enough to clear
        // `p_crit` — green for a reason that stopped existing the moment the estimator could see straight.
        //
        // `Bind` is `Φ > 1` **and** `mean r ≤ lo`, i.e. RMS above the floor while the mean is below it —
        // which by Cauchy–Schwarz is *dispersion among the pairs*, not weak coupling. That is the hotspot
        // signature the §6.7 response answers: part of the cell locked onto one target, the rest untouched.
        //
        // A block of `k` perfectly-correlated nodes in a cell of 7 gives `mean = C(k,2)/21` and
        // `Φ = 2·C(k,2)/7`, so the band needs `4 ≤ C(k,2) ≤ 8`, i.e. **exactly `k = 4`**: `mean = 0.286`
        // (below `lo = 0.408`) with `Φ = 1.71` (above 1). Three or fewer collapses; five or more is simply
        // an over-coupled cell.
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let mut t = 1u64;
        let mut rebalanced = false;
        for w in 0..(Config::default().behavior_window() + 6) {
            let hot = (w % 5) + 1; // the block's shared load, varying so a correlation is defined
            for i in 1..7usize {
                let from = Point::<F2>::at(i).coords();
                // Peers 1–3 plus this node itself are the hot block (k = 4); 4–6 carry an independent load.
                let count = if i <= 3 { hot } else { 1 + (w * (2 * i + 1)) % 7 };
                for _ in 0..count {
                    node.step(
                        Instant(t),
                        Input::Message { from, frame: encode(FrameType::Route, b"x") },
                    );
                    t += 1;
                }
            }
            // This node's own originated traffic is the fourth member of the hot block — `Command::Send` is
            // what `record_origination` counts into the self slot of the sample vector.
            for _ in 0..hot {
                node.step(
                    Instant(t),
                    Input::Command(Command::Send { to: Point::<F2>::at(1).coords(), payload: b"x".to_vec() }),
                );
                t += 1;
            }
            let hb = node.step(Instant(t), Input::Timer(HEARTBEAT));
            if hb.iter().any(|e| matches!(e, Effect::Notify(Notification::Rebalance { .. }))) {
                rebalanced = true;
            }
            t += 1;
        }
        assert!(
            rebalanced,
            "a sustained hotspot — a correlated block inside an otherwise independent cell — is the \
             under-coupled `Bind` band, so the live homeostat emits the §6.7 projective load-balance \
             prescription"
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
        for w in 0..(Config::default().behavior_window() + 2) {
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
        // **Lowered relative to what the cell MEASURED**, which is what the shed is answering — not relative
        // to the configured baseline it used to scale (#92). `base` is read before any window has filled, so
        // it is still the configured value and is kept only to show the two are different things.
        let measured = node.healer.baseline_correlation(Config::default().healthy_correlation);
        assert!(
            measured > base + 1e-9,
            "a lockstep flood must measure ABOVE the configured baseline ({measured:.4} vs {base:.4}) — \
             otherwise this test is not driving the regime it claims"
        );
        assert!(
            node.healer.effective_correlation(Config::default().healthy_correlation) < measured - 1e-9,
            "the effective correlation is genuinely lowered — Φ headroom restored, not a no-op"
        );
        // The mutable factor really is what scales the correlation (the feedback into Φ).
        assert!(
            (node.healer.effective_correlation(Config::default().healthy_correlation)
                - measured * (1.0 - node.healer.decoupling))
                .abs()
                < 1e-12
        );

        // **The shed must leave the cell a COLLECTIVE SUBJECT (#91).** This is the property the retired
        // constants got wrong: `DECOUPLE_STEP = 0.25` against a baseline of 0.45 modelled the correlation at
        // 0.3375, below the `1/√6 ≈ 0.4082` floor — so a single over-coupling response classified the cell
        // as `Aggregate`, whose homeostatic answer is `Bind`, the opposite action. Asserted against the band
        // rather than against a cap, because the band is what the value has to respect.
        let alive = node.healer.decoupling; // keep the shed visible in the failure message
        let eff = node
            .healer
            .effective_correlation(Config::default().healthy_correlation);
        let floor = fanos_diakrisis::coherence::systemic_correlation(7);
        assert!(
            eff > floor,
            "the shed dropped the modelled correlation to {eff:.4} against the collective-subject floor \
             {floor:.4} (shed factor {alive:.4}) — an over-coupling response must not turn the cell into an \
             aggregate, which is the failure `Bind` exists to answer"
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
        for _ in 0..(Config::default().behavior_window() + 4) {
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

    /// **A shard stamped in the future is refused, so no frame can pin a slot for ever.**
    ///
    /// `version` arrives off the wire and `insert_shard` keeps the higher one. A real distribution stamps
    /// the epoch it happened in; `u64::MAX` is an epoch no cell will reach, so before this an attacker sent
    /// one frame per (digest, index) and that shard could never be superseded — and since reads take the
    /// highest version group, filling every index owned the reconstruction, against every directory built on
    /// this store (#79).
    ///
    /// The bound is the beacon clock: agreed cell-wide and unforgeable *ahead*, because a future epoch's
    /// beacon cannot be known before its round assembles. One epoch of grace is allowed, the same one-epoch
    /// allowance the platform derives wherever a peer may be a turn ahead across an epoch boundary.
    #[test]
    fn a_shard_stamped_beyond_the_epoch_clock_is_refused() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        let from = Point::<F2>::at(1).coords();
        let digest = flood_digest(1);
        let epoch = node.epoch().get();

        // THE PROPERTY: a far-future stamp — the pin — is refused outright, and so is one two epochs ahead,
        // which is the first value past the grace.
        for ahead in [u64::MAX >> OverlayNode::<F2>::VERSION_EPOCH_SHIFT, epoch + 2] {
            let version = ahead << OverlayNode::<F2>::VERSION_EPOCH_SHIFT;
            node.step(
                Instant(1),
                Input::Message { from, frame: encode_publish(PUBLISH_SHARD, 0, version, &digest, b"pinned") },
            );
            assert!(
                !node.store.entries.contains_key(&digest),
                "a shard stamped at epoch {ahead} against a clock at {epoch} must be refused — accepting it \
                 lets one frame hold this slot against every later write"
            );
        }

        // **The PRODUCER is pinned too, and it has to be.** Removing the guard fails this test; removing
        // the epoch from `write_version` did NOT, because at `Instant(1)` raw nanos shift to 0 and the guard
        // waves them through. In production it is a liveness break rather than a no-op: raw nanos put
        // `uptime_seconds / 4.3` in the epoch field, so a node up ~9 s stamps epoch 2, and every peer at
        // epoch 0 refuses its shards. A second producer really was still doing that — `Command::Put`'s own
        // path — and this assertion is what stops it coming back.
        // Driven through `Command::Put` rather than by calling `write_version` beside it, because the
        // regression was at a CALL SITE: one of the two producers still passed raw `now.as_nanos()`. A test
        // that calls the helper directly cannot see that, and an earlier version of this assertion did not.
        // A one-node cell homes every shard on itself, so the stamp is read back out of the local store —
        // the same value a peer would have received.
        let late = Instant(60_000_000_000); // a minute of uptime — far past where nanos overflow 32 bits
        let key = alloc::vec![9u8];
        node.step(late, Input::Command(Command::Put { key: key.clone(), value: alloc::vec![7u8; 64] }));
        let (stored_digest, _) = OverlayNode::<F2>::address_of(&key);
        let stamped = node
            .store
            .entries
            .get(&stored_digest)
            .and_then(|held| held.values().next().map(|(version, _)| *version))
            .expect("a Put stores at least one shard");
        assert_eq!(
            stamped >> OverlayNode::<F2>::VERSION_EPOCH_SHIFT,
            node.epoch().get(),
            "uptime must never leak into the epoch half — a receiver reads it as a claim about the clock, so \
             raw nanos make a node refuse every shard from a peer that has been up a few seconds"
        );

        // THE MECHANISM, so the test cannot pass by refusing everything: this epoch is accepted, and so is
        // one epoch ahead, which is the grace a peer a turn ahead legitimately needs.
        for ok in [epoch, epoch + 1] {
            let d = flood_digest(u32::try_from(ok).unwrap_or(0) + 100);
            let version = ok << OverlayNode::<F2>::VERSION_EPOCH_SHIFT;
            node.step(
                Instant(1),
                Input::Message { from, frame: encode_publish(PUBLISH_SHARD, 0, version, &d, b"ok") },
            );
            assert!(node.store.entries.contains_key(&d), "a shard stamped at epoch {ok} must be stored");
        }
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
        seat_every_neighbour(&mut node, Instant(0));
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
                Effect::Notify(Notification::Retrieved { key: k, outcome: ReadOutcome::Found(v) })
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
        // **And the drop is audible.** This is the one discard that is unambiguously this node's own
        // decision — every other silence on the wire is ambiguous between the peer, the path and us — and it
        // used to look exactly like the member having gone away. An operator could not tell "that node is
        // down" from "we are refusing it", and a wrongly-quarantined healthy peer presented as a link that
        // simply does not work.
        assert_eq!(
            node.stations.total(Station::QuarantineDropped),
            1,
            "a quarantine drop must be counted, or refusing a peer is indistinguishable from losing one"
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

    #[test]
    fn an_expiring_directory_slot_is_reclaimed_and_content_beside_it_is_not() {
        // **The two kinds of write, and the store must tell them apart.** A directory slot is soft state
        // with a lifetime its publisher knows; content has none, and only the application knows when it
        // stops mattering. Before `PutEphemeral` the store could not distinguish them — a key arrives as an
        // opaque digest — so it kept both for ever, and since admission is fail-closed a cell filled up on a
        // wall clock and silently stopped publishing (`fanos-node/tests/store_lifetime.rs`).
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());

        let slot = b"FANOS-v1/mix-key/some-coord/epoch-0".to_vec();
        let content = b"an application value that must outlive every epoch".to_vec();
        node.step(Instant(0), Input::Command(Command::PutEphemeral {
            key: slot.clone(),
            value: alloc::vec![0x11; 48],
            epochs: 1,
        }));
        node.step(Instant(0), Input::Command(Command::Put {
            key: content.clone(),
            value: alloc::vec![0x22; 48],
        }));
        let (slot_digest, content_digest) = (storage_digest(&slot), storage_digest(&content));
        assert!(node.store.entries.contains_key(&slot_digest), "the slot was stored");
        assert!(node.store.entries.contains_key(&content_digest), "and so was the content");

        // One advance: still inside the grace window the onion ratchet's own `retain` defines, so a reader
        // one epoch behind can still use it.
        node.step(Instant(1), Input::Command(Command::AdvanceEpoch));
        assert!(
            node.store.entries.contains_key(&slot_digest),
            "a slot must survive its grace window — a client acting on the previous epoch's directory is \
             exactly the case the onion ratchet retains a past secret for",
        );

        // A second advance takes it past the window: now no honest reader can use it, and it goes.
        node.step(Instant(2), Input::Command(Command::AdvanceEpoch));
        assert!(
            !node.store.entries.contains_key(&slot_digest),
            "past its grace window a directory slot is dead to every honest reader and must be reclaimed",
        );
        assert!(
            node.store.entries.contains_key(&content_digest),
            "content is not swept — it never declared a lifetime, and saying nothing means saying content. \
             Reclaiming by AGE instead would have discarded this and kept the corpse beside it.",
        );
    }

    /// **The shed ceiling is a function of the plane, and this is what the retired constant got wrong.**
    ///
    /// `DECOUPLE_MAX = 0.6` was fixed on every plane while the budget it approximates moves with `n` through
    /// the collective-subject floor `1/√(n−1)`. On the shipped Fano cell it was six and a half times the
    /// whole budget.
    #[test]
    fn the_shed_ceiling_tracks_the_plane_and_leaves_the_cell_a_collective_subject() {
        let (w, z) = (Config::default().behavior_window(), Config::default().control_confidence());
        // **The argument is the MEASURED correlation the shed is reducing, not a configured baseline** (#92).
        // A shed only ever runs on an over-coupled reading, so the input is above `hi = √(2/(n−1))`; feeding
        // it `healthy_correlation = 0.45` — which is *inside* the band, where the answer is `Hold` — was the
        // confusion this task named, and it made every cap look arbitrary because the budget it measured was
        // the 0.042 between 0.45 and the floor rather than the room an over-coupled cell actually has.
        for n in [7usize, 21, 57, 993] {
            let (lo, hi) = fanos_diakrisis::window::collective_subject_window(n);
            let measured = hi * 1.2; // an over-coupled cell: the only state that sheds
            let d = decouple_ceiling(n, measured, Config::default().behavior_window(), Config::default().control_confidence());
            let modelled = measured * (1.0 - d);
            assert!(
                modelled > lo,
                "n={n}: a full shed models r={modelled:.4} against the floor {lo:.4} — an over-coupling \
                 response must never classify the cell as an aggregate"
            );
            assert!(d > 0.0, "n={n}: an over-coupled cell must have room to shed");
            // And it stops at the *derived* floor — `lo` plus the estimator's own error at the shipped
            // window — rather than at `lo` itself, because the band is a threshold on a measured quantity
            // and arriving exactly at it means arriving inside its error.
            let setback = Config::default().control_confidence() * fanos_diakrisis::window::band_stderr(n, Config::default().behavior_window());
            assert!(
                (modelled - (lo + setback)).abs() < 1e-9,
                "n={n}: a full shed must land on the derived floor lo+z·SE = {:.4}, not on {modelled:.4}",
                lo + setback,
            );
        }

        // It really does move with the plane: a larger cell has a lower floor and therefore more room. Taken
        // at one fixed correlation so the comparison is about the plane and not about the input.
        assert!(
            decouple_ceiling(993, 0.8, w, z) > decouple_ceiling(7, 0.8, w, z),
            "the budget grows as the floor 1/√(n−1) falls — which is why one constant cannot serve every plane"
        );

        // A correlation at or below the derived floor admits no shed, rather than a negative one — and that
        // now includes a cell sitting at the configured baseline, which is exactly right: an in-band cell is
        // `Hold`, and a controller with nothing to correct must spend nothing.
        assert!(
            decouple_ceiling(7, 0.40, w, z) <= f64::EPSILON,
            "a correlation below the floor has no budget to spend"
        );
        assert!(
            decouple_ceiling(1, 0.8, w, z) <= f64::EPSILON,
            "a degenerate cell has no correlation window"
        );
    }

    /// **Every constant in the band-keeping loop is recomputed here from the platform's own periods.**
    ///
    /// The chain is `(dwell, heartbeat, epoch) → z → window → shed ceiling`. Each link is a literal only
    /// because the derivation needs `exp`/`sqrt`, which are not `const`; this is what makes a literal that
    /// drifts from its derivation fail rather than merely continue to look plausible. Three chosen numbers
    /// (`Config::default().behavior_window() = 8`, `DECOUPLE_MARGIN = 0.5`, and a dwell on one branch of three) became one
    /// declared period and one derived confidence.
    #[test]
    fn the_control_loop_constants_are_derived() {
        use fanos_diakrisis::window::resolving_window;

        // The epoch figure is the platform's, in this loop's own clock — not a coincidence that happens to
        // read 1200. `fanos-cli/tests/skew_windows.rs` holds the other half, against `DEFAULT_EPOCH_PERIOD`.
        let heartbeat_nanos = Config::default().heartbeat.0 as f64;
        assert!(
            (Config::default().heartbeats_per_epoch() * heartbeat_nanos - 600.0 * 1e9).abs() < 1.0,
            "Config::default().heartbeats_per_epoch() × the heartbeat must be the 600 s epoch, not a free number",
        );

        let z = fanos_diakrisis::window::control_confidence(BAND_DWELL as usize, Config::default().heartbeats_per_epoch());
        assert!(
            (z - Config::default().control_confidence()).abs() < 1e-12,
            "the runtime's confidence must be exactly DIAKRISIS's derivation from the same inputs",
        );
        assert_eq!(
            resolving_window(7, Config::default().control_confidence()),
            Config::default().behavior_window(),
            "the window is the one that resolves the band at the derived confidence",
        );

        // Falsification: the window one sample shorter does NOT resolve the band, so the equality above is a
        // bound being met and not a number being asserted about itself.
        let (lo, hi) = fanos_diakrisis::window::collective_subject_window(7);
        let half = (hi - lo) / 2.0;
        assert!(Config::default().control_confidence() * fanos_diakrisis::window::band_stderr(7, Config::default().behavior_window()) <= half);
        assert!(
            Config::default().control_confidence() * fanos_diakrisis::window::band_stderr(7, Config::default().behavior_window() - 1) > half,
            "one sample short of the derived window must fail to resolve, or the window is slack",
        );

        // And the window the platform used to ship could not resolve the band at ANY confidence worth the
        // name: one standard error was the whole band.
        assert!(
            fanos_diakrisis::window::band_stderr(7, 8) > 2.0 * half * 0.95,
            "the retired window of 8 gave a standard error the width of the band it was regulating",
        );
    }

    /// The re-integration factor is the dwell's half-life, not a round's.
    #[test]
    fn the_decay_half_life_is_one_detection_dwell() {
        // After DWELL rounds of decay, exactly half the shed remains: the loop cannot un-shed faster than it
        // can decide to shed, which is the anti-chatter condition. The retired 0.5 halved every round.
        let after_dwell = DECOUPLE_DECAY.powi(i32::try_from(BAND_DWELL).expect("small dwell"));
        assert!(
            (after_dwell - 0.5).abs() < 1e-9,
            "DECAY^DWELL must be 1/2 (half-life = one dwell), got {after_dwell}"
        );
    }

    /// #211. One queried peer, answering first with eight fabricated high versions, used to delete every
    /// honest write on the step it arrived — because the accumulator evicted the LOWEST version and `version`
    /// comes off the wire. Measured before the fix: `retrieved = None` for a value that reconstructs from the
    /// very shards that were thrown away.
    ///
    /// The property is stated as the *outcome an operator cares about* — the value comes back — rather than
    /// as "the honest version is still in the map", because the second can hold while the first fails.
    #[test]
    fn a_peer_spraying_versions_cannot_delete_the_honest_write_from_a_read() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        seat_every_neighbour(&mut node, Instant(0));
        let key = b"k";
        let (digest, _) = OverlayNode::<F2>::address_of(key);
        node.step(Instant(1), Input::Command(Command::Get { key: key.to_vec() }));
        let nonce = node.store.pending.get(&digest).expect("the read fanned out").nonce;
        let mut peers = node.peers.keys().copied();
        let attacker = peers.next().expect("a cell has peers");
        let honest = peers.next().expect("and more than one");

        // The attacker answers first — it has nothing to look up, so it always wins that race — claiming
        // versions that outrank any honest write. One byte each: this was never a memory attack.
        //
        // **The versions are the highest the epoch bound ADMITS, not the highest expressible.** `u64::MAX - v`
        // is the natural thing to write and it makes this test prove nothing: those are refused by
        // `VersionAhead` before the accumulator sees them, so the eviction under test never runs and the test
        // passes with the defect restored. Falsified, and it did exactly that. The epoch field is `epoch + 1`
        // — a real value a peer one tick ahead could legitimately stamp — and the low 32 bits are free.
        let admissible_epoch = 1u64;
        for v in 0..12u64 {
            let version = (admissible_epoch << OverlayNode::<F2>::VERSION_EPOCH_SHIFT) | (0xFFFF_FFFF - v);
            node.step(Instant(2), Input::Message {
                from: attacker,
                frame: encode_value(&digest, true, 0, version, &[0u8], nonce),
            });
        }
        // Now the honest cell answers with the real shards of a real value, at a real write-version.
        let value = b"the-value-that-is-actually-stored";
        let shards = erasure::encode(value);
        let mut retrieved = None;
        for (i, shard) in shards.iter().enumerate() {
            for e in node.step(Instant(3), Input::Message {
                from: honest,
                frame: encode_value(&digest, true, u8::try_from(i).unwrap(), 3, shard, nonce),
            }) {
                if let Effect::Notify(Notification::Retrieved { outcome, .. }) = e {
                    retrieved = Some(outcome);
                }
            }
        }
        assert_eq!(
            retrieved,
            Some(ReadOutcome::Found(value.to_vec())),
            "the read must deliver the value the honest cell holds, whatever a member claims about versions"
        );
        // And the spray was recorded rather than absorbed: an operator can name the peer.
        let refused: u64 = node
            .stations
            .observations()
            .iter()
            .filter(|o| o.station == Station::ReadShardRefused)
            .map(|o| o.count)
            .sum();
        assert!(refused > 0, "the refused replies must reach the data-path plane, not vanish");
    }

    /// #212. The read path took `body[50..]` and stored it. The only ceiling was `MAX_FRAME`, so one read was
    /// measured holding **53.4 MiB** — against a store-budget comment claiming "in-flight reads < 1 MiB".
    ///
    /// The assertion is against [`READ_ACCUMULATOR_BYTES`], the *derived* ceiling, so that changing either
    /// factor of that derivation changes what this test permits rather than leaving a stale literal behind.
    #[test]
    fn a_read_accumulator_cannot_exceed_what_the_store_would_have_accepted() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        seat_every_neighbour(&mut node, Instant(0));
        let key = b"k";
        let (digest, _) = OverlayNode::<F2>::address_of(key);
        node.step(Instant(1), Input::Command(Command::Get { key: key.to_vec() }));
        let nonce = node.store.pending.get(&digest).expect("the read fanned out").nonce;
        let peers: Vec<_> = node.peers.keys().copied().collect();

        let held = |node: &OverlayNode<F2>| -> usize {
            node.store.pending.get(&digest).map_or(0, |p| {
                p.by_version.values().flatten().flatten().map(Vec::len).sum()
            })
        };
        // Phase 1 — every peer sprays every index at many versions with shards STRICTLY over the store's own
        // cap, at differing lengths so nothing could reconstruct and retire the read.
        for (p, &peer) in peers.iter().enumerate() {
            for v in 1..=12u64 {
                for i in 0..erasure::N {
                    let shard = alloc::vec![0xAAu8; MAX_VALUE_LEN + 1 + i + p];
                    node.step(Instant(2), Input::Message {
                        from: peer,
                        frame: encode_value(&digest, true, u8::try_from(i).unwrap(), v, &shard, nonce),
                    });
                }
            }
        }
        assert_eq!(held(&node), 0, "not one over-size shard is accepted, so the accumulator never opens");

        // Phase 2 — the same flood at EXACTLY the cap, which is admissible and is what the derived ceiling was
        // computed from. Each peer takes its OWN version, because that is the arrangement that actually
        // reaches the bound: peers sharing a version share `by_version[v][index]` slots and overwrite each
        // other, so a flood where everyone starts at version 1 fills only 7 slots and would let this test pass
        // while proving a sixth of what it claims. Phase 1 charged nothing, so a refusal must not consume
        // quota either — if it did, this phase would fall short and the ceiling would never be reached.
        // Each peer also spreads its replies over TWELVE versions rather than repeating one, so that without
        // the quota it would open `12 x 7` slots instead of 7. Falsified: with the quota deleted and every
        // peer repeating a single version, the total is unchanged and the test passes on a defect.
        for (p, &peer) in peers.iter().enumerate() {
            for v in 1..=12u64 {
                for i in 0..erasure::N {
                    let shard = alloc::vec![0xBBu8; MAX_VALUE_LEN];
                    node.step(Instant(3), Input::Message {
                        from: peer,
                        frame: encode_value(
                            &digest, true, u8::try_from(i).unwrap(), p as u64 * 20 + v, &shard, nonce,
                        ),
                    });
                }
            }
        }
        assert_eq!(
            held(&node),
            READ_ACCUMULATOR_BYTES,
            "the quota admits exactly the derived ceiling and not one shard more"
        );
    }

    /// The three rules, each driven on its own — because a test that only ever sees the *first* rule fire has
    /// not shown the other two are reachable, and [`ReadRefusal::of`] evaluates them in order.
    #[test]
    fn every_read_refusal_rule_is_reachable_and_admits_the_honest_reply() {
        let quota = READ_PEER_SHARD_QUOTA;
        assert_eq!(ReadRefusal::of(MAX_VALUE_LEN + 1, 0, 9, 0), Some(ReadRefusal::Oversize));
        assert_eq!(ReadRefusal::of(1, 10, 9, 0), Some(ReadRefusal::VersionAhead));
        assert_eq!(ReadRefusal::of(1, 0, 9, quota), Some(ReadRefusal::PeerQuota));
        // The honest reply: a full-size shard, this epoch's version, first contribution.
        assert_eq!(ReadRefusal::of(MAX_VALUE_LEN, 9, 9, quota - 1), None);
        // Distinct tags and distinct names, or the operator reads two rules as one.
        let tags: BTreeSet<u64> = ReadRefusal::ALL.iter().map(|r| r.tag()).collect();
        let names: BTreeSet<&str> = ReadRefusal::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(tags.len(), ReadRefusal::ALL.len(), "tags collide");
        assert_eq!(names.len(), ReadRefusal::ALL.len(), "names collide");
    }

    /// The product the read path's two bounds make, asserted as the number it is rather than left implicit
    /// (#213). This test exists to FAIL when the apportionment lands and the ceiling comes down — a stale
    /// 2.6 GiB left in the tree unremarked is the shape #212 was.
    #[test]
    fn the_read_paths_own_ceiling_is_stated_and_does_not_yet_fit_the_node() {
        assert_eq!(READ_PEER_SHARD_QUOTA, 7, "a peer holds at most one shard per point");
        assert_eq!(READ_ACCUMULATOR_BYTES, 2_752_512, "7 shards x 6 peers x 64 KiB");
        assert_eq!(READ_MEMORY_CEILING, 2_818_572_288, "x MAX_PENDING_GETS = 2.6 GiB");
        // A `const` block on clippy's advice, and it is the better shape: the day #213 lands and the ceiling
        // drops below the recommendation, this stops the BUILD rather than one test run — which is the moment
        // someone must replace this tripwire with the assertion it stands in for.
        const {
            assert!(
                READ_MEMORY_CEILING > 256 * 1024 * 1024,
                "#213 landed: replace this tripwire with the apportionment assertion it stands in for"
            );
        }
    }

    /// #215. A read nobody answers must say **"I did not find out"**, not "there is nothing here" — and it
    /// must say so at the engine's own timeout, which is where the lie used to be told.
    ///
    /// The assertion is on the OUTCOME rather than on a station count, because the station is the operator's
    /// copy and the outcome is what every caller decides on. Both are checked; only one is the property.
    #[test]
    fn a_read_that_nobody_answered_is_inconclusive_and_never_a_definite_absence() {
        let cfg = Config::default();
        let mut node = OverlayNode::<F2>::new(Point::at(0), cfg);
        seat_every_neighbour(&mut node, Instant(0));
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        node.step(Instant(1), Input::Command(Command::Get { key: b"k".to_vec() }));
        assert_eq!(node.store.pending.len(), 1, "the read fanned out to the algebraic cell");

        // Heartbeats pace the sweep, so the conclusion lands at the first beat past `read_timeout`.
        let mut concluded = None;
        let mut t = 0u64;
        while t < 6_000_000_000 && concluded.is_none() {
            t += cfg.heartbeat.0;
            for e in node.step(Instant(t), Input::Timer(HEARTBEAT)) {
                if let Effect::Notify(Notification::Retrieved { outcome, .. }) = e {
                    concluded = Some((t, outcome));
                }
            }
        }
        let (at, outcome) = concluded.expect("the engine must conclude a read it cannot complete");
        assert_eq!(
            outcome,
            ReadOutcome::Inconclusive,
            "a read that ran out of time established NOTHING; reporting Absent is what silently shrinks a \
             roster built from directory reads"
        );
        // The measurement that made this a defect rather than a preference: it lands well inside the 5 s
        // wrapper whose elapse used to be the caller's only way to learn a read had not concluded.
        assert!(
            at < 5_000_000_000,
            "the engine concludes at {at} ns, before the 5 s STORE_TIMEOUT — which is precisely why the \
             two-crate ordering invariant could not save the caller"
        );
        // And the operator gets the reason, which the caller deliberately does not.
        let stalls: u64 = node
            .stations
            .observations()
            .iter()
            .filter(|o| o.station == Station::ReadInconclusive && o.tag == Some(ReadStall::TimedOut.tag()))
            .map(|o| o.count)
            .sum();
        assert_eq!(stalls, 1, "the non-conclusion is counted, tagged with WHY");
    }

    /// The other side of the same coin: when the cell genuinely answers "nothing here", that is `Absent` and
    /// a caller may rely on it.
    ///
    /// Written because a three-state type is only worth having if BOTH negatives are reachable — a fix that
    /// turned every miss into `Inconclusive` would pass the test above and destroy the property it protects
    /// ([[discrimination-needs-differing-inputs]]).
    #[test]
    fn a_cell_that_answers_nothing_here_is_a_definite_absence() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        seat_every_neighbour(&mut node, Instant(0));
        let key = b"k";
        let (digest, _) = OverlayNode::<F2>::address_of(key);
        node.step(Instant(1), Input::Command(Command::Get { key: key.to_vec() }));
        let nonce = node.store.pending.get(&digest).expect("fanned out").nonce;
        let peers: Vec<_> = node.peers.keys().copied().collect();
        let mut outcome = None;
        for peer in peers {
            for e in node.step(Instant(2), Input::Message {
                from: peer,
                frame: encode_value(&digest, false, 0, 0, &[], nonce),
            }) {
                if let Effect::Notify(Notification::Retrieved { outcome: o, .. }) = e {
                    outcome = Some(o);
                }
            }
        }
        assert_eq!(
            outcome,
            Some(ReadOutcome::Absent),
            "every queried shard home answered and none holds a shard — that IS a definite negative"
        );
    }

    /// The invariant #214's optimisation rests on: **while a read is pending, no version reconstructs.**
    ///
    /// `on_value` now attempts only the version whose shard just arrived, instead of walking every group.
    /// That is exactly equivalent rather than approximate, and this is the claim it rests on — a version
    /// becomes reconstructable only when a shard arrives for it, and the read is retired the instant one
    /// does. Written as a test rather than left as an argument, because the argument is short enough to
    /// believe and the property is what last-writer-wins (#115) is built on.
    #[test]
    fn no_version_is_left_reconstructable_while_a_read_is_still_pending() {
        let mut node = OverlayNode::<F2>::new(Point::at(0), Config::default());
        seat_every_neighbour(&mut node, Instant(0));
        let key = b"k";
        let (digest, _) = OverlayNode::<F2>::address_of(key);
        node.step(Instant(1), Input::Command(Command::Get { key: key.to_vec() }));
        let nonce = node.store.pending.get(&digest).expect("fanned out").nonce;
        let peers: Vec<_> = node.peers.keys().copied().collect();

        // Two real values at two write-versions, fed shard by shard and interleaved so that neither
        // completes before the other has partial coverage — the arrangement that would expose a stale
        // "higher version was already whole" if one could exist.
        let low = erasure::encode(b"the-older-write");
        let high = erasure::encode(b"the-newer-write");
        let mut retired_at = None;
        for i in 0..erasure::N {
            for (version, shards) in [(3u64, &low), (9u64, &high)] {
                let from = peers[i % peers.len()];
                for e in node.step(Instant(2), Input::Message {
                    from,
                    frame: encode_value(
                        &digest, true, u8::try_from(i).unwrap(), version,
                        shards.get(i).map_or(&[][..], Vec::as_slice), nonce,
                    ),
                }) {
                    if let Effect::Notify(Notification::Retrieved { outcome, .. }) = e {
                        retired_at = Some(outcome);
                    }
                }
                // The property, checked after EVERY accepted shard: **if the entry is still in `pending`,
                // nothing in the accumulator reconstructs.**
                //
                // Keyed on the entry's presence and deliberately NOT on "have we seen a `Retrieved` yet".
                // That was the first version and it could not fail: `retired_at` goes `Some` on the very
                // notification that accompanies the violation, so the guard fell silent exactly when the
                // thing it watches for appears. Falsified — breaking retirement left it green.
                if let Some(p) = node.store.pending.get(&digest) {
                    assert!(
                        reconstruct_highest(&p.by_version).is_none(),
                        "a version reconstructs while the read is still pending — the equivalence #214 \
                         relies on does not hold, and `on_value` must go back to walking every version"
                    );
                }
            }
        }
        assert!(retired_at.is_some(), "the read must conclude once a full shard-set arrives");
    }
}
