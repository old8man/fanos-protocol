//! `ThresholdRouter` — the autonomous engine that routes a **threshold onion** where *a hop is a
//! line* (spec §5.2, §5.7). It completes [`crate::threshold`] on the network level: a client seals a
//! nested threshold onion over a circuit of hop *lines*; each hop is peeled only by a threshold `t`
//! of that line's `q + 1` members, cooperating through the overlay.
//!
//! The protocol per hop is a one-and-a-half round **combiner** exchange:
//!
//! 1. The previous hop routes the onion to this line's **combiner** — the canonical first member of
//!    the line (`points_on(line).next()`), so no coordination is needed to agree on who combines.
//! 2. The combiner asks the line's other members for their *partial decryption* of the layer
//!    ([`crate::threshold_onion::member_partial`]) and contributes its own.
//! 3. Once `≥ t` partials are in, the combiner reconstructs the layer key and peels: either it
//!    forwards the inner onion to the *next* line's combiner, or it delivers the payload.
//!
//! Below `t` cooperating members a hop cannot be peeled at all (the KEM-sealed shares are
//! zero-knowledge, [`crate::threshold`]), and no member ever learns more than its own share — so the
//! *line*, not any node, is the unit of trust. This is a sans-I/O [`Engine`]: it emits only
//! [`Effect`]s and reads only [`Input`]s, so the same code runs under the simulator and a real
//! transport. Member coordinates come from the projective geometry (`points_on`), so the router
//! needs no directory; only the client that *builds* an onion needs the hops' member public keys.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point, Triple};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, OnionKeyRatchet};
use fanos_primitives::Epoch;
use fanos_primitives::shamir::Share;
use fanos_ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

use crate::threshold_onion::{self as threshold, ThresholdPeel};

/// Internal frame tags (the onion travels as opaque overlay bytes; these are its sub-types). They live in
/// the **0xE0–0xEF range, deliberately outside the wire [`FrameType`](fanos_wire::FrameType) code space
/// (0x00–0x70)**: a node that composes the router with the overlay engine on one coordinate (the deployed
/// cell node) must tell an onion frame apart from an overlay wire frame by inspection alone, so an onion
/// tag must never alias a `FrameType` code (`Hello`/`HelloAck`/`Ping` used to sit at 0/1/2 and collided).
/// An onion frame therefore decodes to *no* `FrameType`, which is the composite's signal to route it here.
const TAG_ONION: u8 = 0xE0;
const TAG_REQ: u8 = 0xE1;
const TAG_REP: u8 = 0xE2;
/// A NOSTOS **dead-drop cell** the combiner multicasts to a delivery line's members: `TAG_DROP ‖
/// line(12) ‖ e2e_body`. A member hands the end-to-end body to its application; only the receiver's
/// reply key opens it (spec §5, NOSTOS).
const TAG_DROP: u8 = 0xE3;

/// The anonymous-source sentinel in a delivery notification (the endpoint learns no originator).
pub const ANONYMOUS: Triple = [0, 0, 0];

/// The deadline used **before the first gather completes**, when there is nothing measured to derive one
/// from — the bootstrap slot RFC 6298 fills with its 1 s initial RTO, for the same reason.
///
/// It is generous on purpose and it is *not* the operating value: one completed gather replaces it with a
/// measurement ([`GatherClock`]). Being wrong here costs at most the first hop of a cold node, which the
/// reliability layer retransmits; being wrong *permanently* is what the former 2000 ms constant did.
const INITIAL_GATHER_DEADLINE: Duration = Duration::from_millis(2000);

/// Floor on the derived deadline. Not a tuning knob: it stops a run of unusually fast gathers (an idle node
/// on a loopback) from collapsing the estimate so far that the first genuinely loaded gather is abandoned
/// before its partials can physically arrive. One millisecond is below any real `RTT + C_partial` — the
/// measured `C_partial` alone is 1.05 ms in release — so it can never bind in operation, only in pathology.
const MIN_GATHER_DEADLINE: Duration = Duration::from_millis(1);

/// Ceiling on the derived deadline, and the one place memory enters the timing. In-flight gathers are capped
/// by count ([`MAX_PENDING`]), so this does not bound memory; it bounds how long a *dead* hop is believed in,
/// which is what an adversary would stretch by answering slowly to pin gather slots. Ten seconds is far above
/// any honest `RTT + C_partial + Q` this cell has measured and far below a stall an operator would not notice.
const MAX_GATHER_DEADLINE: Duration = Duration::from_millis(10_000);

/// Cap on concurrently-pending gathers, so **memory is bounded by count rather than by the deadline**.
///
/// This is what makes the deadline free to be measured. Previously the only bound on `pending` was the
/// timeout — every gather sat in a `BTreeMap` until its deadline fired — which quietly made the timing
/// constant a *memory-safety* parameter, so lengthening it to fix liveness would have traded one defect for
/// another. Derived from a budget rather than picked: each entry holds one `THRESHOLD_ONION_LEN` onion plus
/// its shares, so `64 MiB / 20480 B ≈ 3276`. At the cap the oldest incomplete gather is dropped — correct
/// here, unlike the eviction hazard a keyed cache has, because the oldest gather is precisely the one most
/// likely already dead, and its client retransmits.
const MAX_PENDING: usize = (64 * 1024 * 1024) / fanos_threshold::THRESHOLD_ONION_LEN;

/// High bit marking a *mixing* timer token, distinguishing it from a gather-deadline token (which
/// carries a small request id). No real request id reaches `2^63`.
const MIX_FLAG: u64 = 1 << 63;

/// The dedicated **cover-traffic** tick token (bit 62) — distinct from mix tokens (bit 63 set) and
/// small gather-deadline request ids. A single recurring timer, matched exactly.
const COVER_TOKEN: u64 = 1 << 62;

/// Cap on distinct candidate shares a combiner will hold for one pending peel. A line has only `q + 1`
/// real members, so honest operation never approaches this; the cap bounds memory (and the peel search
/// below) against an attacker flooding forged `TAG_REP` replies.
const MAX_CANDIDATES: usize = 64;

/// Cap on the number of `t`-subsets tried while searching for a set of shares that peels. Honest
/// operation succeeds on the first (all-honest) subset; this bounds the CPU cost when up to `t − 1`
/// forged shares are mixed in and several subsets must be tried.
const MAX_PEEL_ATTEMPTS: usize = 256;

/// A combiner's in-flight peel: the layer being gathered, its member count (the valid share index
/// bound), and the candidate partials collected so far.
struct Pending {
    onion: Vec<u8>,
    shares: Vec<Share>,
    member_count: usize,
    /// The hop line this combiner is peeling for — the members to multicast a dead-drop delivery to.
    line: Triple,
    /// When the share requests went out. A gather that completes yields `now − armed_at` as one latency
    /// sample, which is what makes the deadline measured rather than chosen ([`GatherClock`]).
    armed_at: Instant,
}

/// The adaptive gather deadline: an EWMA of observed gather latency plus a margin from its variation,
/// in the shape RFC 6298 gives TCP's RTO (`SRTT`, `RTTVAR`, `RTO = SRTT + 4·RTTVAR`).
///
/// **Why measured and not chosen.** A gather's wall-clock is `RTT + C_partial + Q` — network, the ML-KEM
/// decap a member pays per share request, and the queue of requests already accepted. `tests/gather_cost.rs`
/// measures `C_partial` at **47 ms under `dev` and 1.05 ms under `release` on one machine**: a 45× spread
/// from a build flag alone, before any hardware or load variation. The former 2000 ms constant therefore
/// absorbed ~42 queued share requests per member in the profile the end-to-end tests run in and ~1900 in the
/// shipped one, and #55 measured what that costs — gathers expiring at 1 of `t = 2` in the hundreds, turning
/// a censorship-survival property into a run-to-run coin flip. No constant is right across that range.
///
/// **Why a completed gather is the right sample.** Its elapsed time contains all three terms *together*,
/// measured under the same load the next gather will meet — so `Q`, the term that actually dominates and the
/// one no formula can predict, needs no model. The engine stays sans-I/O: samples come from the `now` its
/// driver already passes to [`Engine::step`], never from a wall clock.
///
/// The `1/8` and `1/4` gains and the `4·var` margin are RFC 6298's, unchanged: they are the standard
/// smoothing for exactly this problem (a deadline over a latency whose variance is the signal), and inventing
/// different ones here would be a chosen constant wearing a derivation's clothes.
#[derive(Clone, Copy)]
struct GatherClock {
    /// Smoothed latency estimate; `None` until the first gather completes.
    srtt: Option<Duration>,
    /// Smoothed mean deviation of that estimate.
    var: Duration,
    /// Consecutive expiries since the last completed gather — the exponent of RFC 6298's backoff.
    ///
    /// **Smoothing without backoff is not RFC 6298, and the difference is a real defect that a test caught
    /// in this very engine.** An estimator fed only by *completions* converges to the mean of a quiet
    /// period and then holds no margin for a loud one: when load arrives, gathers expire, and — because an
    /// expiry produces no sample — the estimate never learns that it is now too tight. It expires at the
    /// same short deadline forever. Measured: `fanos-sim`'s role-convergence test passed 2/2 at baseline
    /// and failed 2/4 with a backoff-less adaptive deadline, because failing hops starved the capability
    /// directory the role controller reads.
    ///
    /// RFC 6298 §5.5 is exactly this repair — `RTO ← RTO × 2` on every timeout, reset on success. It is
    /// what makes the scheme *safe when the estimate is wrong*, which a pure smoother never is.
    backoff: u32,
}

/// Cap on the consecutive-expiry exponent. **It is sized so that it never binds before
/// [`MAX_GATHER_DEADLINE`] does**, which is a correctness requirement rather than a safety margin: the widest
/// span the backoff must be able to cross is `MIN → MAX`, a factor of `10⁴`, and `2¹⁶ = 65536 > 10⁴`. A
/// smaller exponent cap would silently strand the fastest cells — one whose gathers settle at 1 ms could
/// widen only to `2^k` ms and would keep expiring under a load spike no matter how many times it backed off,
/// which is precisely the failure this whole mechanism exists to end. So the CEILING is the bound that binds,
/// and this constant only keeps the shift total.
const MAX_GATHER_BACKOFF: u32 = 16;

impl GatherClock {
    const fn new() -> Self {
        Self { srtt: None, var: Duration(0), backoff: 0 }
    }

    /// A gather's deadline fired without reaching `t`: back off, per RFC 6298 §5.5.
    ///
    /// No latency *sample* is taken here — that is Karn's algorithm, and it matters: an expiry tells us the
    /// deadline was too short, not how long the gather would have taken, so folding a fabricated duration
    /// into `srtt` would corrupt the estimator with a number nobody measured.
    fn expired(&mut self) {
        self.backoff = (self.backoff + 1).min(MAX_GATHER_BACKOFF);
    }

    /// Fold in one completed gather's elapsed time, and clear the backoff — the estimate is trusted again.
    fn observe(&mut self, sample: Duration) {
        self.backoff = 0;
        match self.srtt {
            // RFC 6298 (2.2): the first measurement seeds both terms.
            None => {
                self.srtt = Some(sample);
                self.var = Duration(sample.as_nanos() / 2);
            }
            // RFC 6298 (2.3): var ← ¾·var + ¼·|srtt − sample|; srtt ← ⅞·srtt + ⅛·sample.
            Some(srtt) => {
                let (s, m) = (srtt.as_nanos(), sample.as_nanos());
                let delta = s.abs_diff(m);
                self.var = Duration((self.var.as_nanos() / 4).saturating_mul(3) + delta / 4);
                self.srtt = Some(Duration((s / 8).saturating_mul(7) + m / 8));
            }
        }
    }

    /// The deadline to arm the next gather with: `(SRTT + 4·RTTVAR) << backoff`, clamped.
    fn deadline(self) -> Duration {
        let Some(srtt) = self.srtt else {
            // Even the bootstrap backs off: a node whose very first gathers all expire must widen, or a
            // cold start into a loaded cell never completes a gather and so never gets a sample at all.
            return Duration(
                INITIAL_GATHER_DEADLINE
                    .as_nanos()
                    .saturating_mul(1u64 << self.backoff)
                    .min(MAX_GATHER_DEADLINE.as_nanos()),
            );
        };
        let raw = srtt
            .as_nanos()
            .saturating_add(self.var.as_nanos().saturating_mul(4))
            .saturating_mul(1u64 << self.backoff);
        Duration(raw.clamp(MIN_GATHER_DEADLINE.as_nanos(), MAX_GATHER_DEADLINE.as_nanos()))
    }
}

/// A node that routes threshold-onion hops — combiner for hops addressed to it, line member for
/// requests from other combiners.
pub struct ThresholdRouter<F: Field> {
    coord: Point<F>,
    /// The forward-secure per-epoch **onion** decap keypair (audit E4). Shares addressed to this node are
    /// peeled with the ratchet's live keys (`onion.secrets()` — the current epoch plus a bounded grace
    /// window of recent ones, so an onion in flight across a rotation still peels). On each epoch advance
    /// the ratchet rotates one-way, so a recorded onion becomes undecryptable once we ratchet more than
    /// the window past its epoch. Distinct from the long-term identity key.
    onion: OnionKeyRatchet,
    threshold: usize,
    /// The measured gather deadline (see [`GatherClock`]) — replaces a chosen constant with the engine's own
    /// observation of `RTT + C_partial + Q`.
    gather: GatherClock,
    /// An explicit override, for a driver that must pin the deadline (a deterministic scenario asserting a
    /// specific expiry). `None` — the default — uses the measured value.
    gather_override: Option<Duration>,
    pending: BTreeMap<u64, Pending>,
    seq: u64,
    /// Mean Poisson mixing delay before forwarding a peeled hop (0 ⇒ forward immediately). Holding
    /// each forward for an independent exponential delay reorders a batch, breaking the timing
    /// correlation an observer could otherwise use to link a hop's in- and out-flows (spec §L5/V7).
    mean_delay: Duration,
    /// Forwards held for their sampled mix delay, keyed by mix id (timer token = `MIX_FLAG | id`).
    mix_pending: BTreeMap<u64, (Triple, Vec<u8>)>,
    mix_seq: u64,
    /// A **secret** PRF key for the mixing-delay schedule, derived from the node's KEM secret. Keying the
    /// schedule on a secret (not the public coordinate) means a global passive adversary cannot recompute
    /// the delay sequence a priori and relink a hop's in/out flows (audit E2).
    mix_seed: [u8; 32],
    /// Mean interval between **cover cells** (0 ⇒ disabled). When on, the router emits a constant-size
    /// keystream cover onion on a Poisson schedule so its send pattern is uniform whether or not it is
    /// forwarding real traffic — a global passive adversary sees the same rate and size either way,
    /// closing the Full/threshold profile's cover-traffic gap (audit E1, spec §L5/V8).
    cover_interval: Duration,
    /// Whether the cover schedule is currently running.
    covering: bool,
    /// Counter driving the secret-keyed cover PRF (destination choice, cell keystream, inter-cell gaps).
    cover_seq: u64,
    /// Real forwards awaiting a constant-rate send slot when cover is on (audit E6). Each slot emits one
    /// cell — a queued real forward (which *displaces* a cover cell) if any, else cover — so the router's
    /// emitted volume is its slot count, independent of the real traffic it carries: a flow-correlation
    /// adversary counting cells on the Full profile sees no signal. Bounded by [`MAX_OUTBOX`]
    /// (drop-oldest) so a flood cannot grow it. Empty in the cover-off path, where forwards leave at once.
    outbox: VecDeque<(Triple, Vec<u8>)>,
    /// The intended circuit (`hop lines`, build `seed`) when this router **owns the endpoint** of a
    /// circuit it agreed on — a rendezvous loopback or a reply circuit it built. Set, it verifies the
    /// delivered path-authenticator (holonomy) and drops a payload that arrived over a different circuit
    /// (spec §5.4, S1-M1). `None` on a transit relay, which never knows the circuit and cannot verify.
    /// The build seed is a secret trapdoor: it is retained here **only** by the circuit's own owner, for
    /// its own loopback check — a deliberate, scoped exception to immediate seed zeroization.
    delivery_check: Option<(Vec<Triple>, Vec<u8>)>,
}

/// Bound on the constant-rate [`outbox`](ThresholdRouter::outbox): real forwards queued for a send slot.
/// Beyond this the oldest is dropped (the reliability layer retransmits) — bounded memory under flood.
const MAX_OUTBOX: usize = 2048;

impl<F: Field> ThresholdRouter<F> {
    /// A router at `coord`, peeling hops that need a threshold of `t`. `kem_secret` (the node's long-term
    /// identity KEM secret) is **borrowed only** to derive the secret mix-schedule key (audit E2) — it is
    /// neither consumed nor retained, since hops are peeled with the forward-secure onion ratchet below,
    /// so a driver may keep using its identity secret elsewhere.
    ///
    /// `onion_seed` is the **genesis** of the forward-secure onion ratchet (audit E4): fresh entropy in
    /// production (a driver CSPRNG draw), so a later compromise of the long-term `kem_secret` cannot
    /// recompute past epochs' onion keys; a fixed value under the deterministic simulator.
    #[must_use]
    pub fn new(
        coord: Point<F>,
        kem_secret: &HybridKemSecret,
        threshold: usize,
        onion_seed: [u8; 32],
    ) -> Self {
        // Derive the secret mixing-delay PRF key from the identity KEM secret up front (see `mix_seed`);
        // the identity key itself is not retained — the onion is peeled with the forward-secure `onion`
        // ratchet, so a later compromise of the long-term key cannot recover past hops (audit E4).
        let mix_seed = kem_secret.derive_subkey("FANOS-v1/threshold-mix-seed");
        Self {
            coord,
            onion: OnionKeyRatchet::new(onion_seed, Epoch::ZERO),
            threshold,
            gather: GatherClock::new(),
            gather_override: None,
            pending: BTreeMap::new(),
            seq: 0,
            mean_delay: Duration(0),
            mix_pending: BTreeMap::new(),
            mix_seq: 0,
            mix_seed,
            cover_interval: Duration(0),
            covering: false,
            cover_seq: 0,
            outbox: VecDeque::new(),
            delivery_check: None,
        }
    }

    /// This router's current-epoch **onion public key** — what a client seals hops to, and what the
    /// node's driver (re)publishes at the epoch-tagged mix-key slot each time the epoch advances (E4).
    #[must_use]
    pub fn onion_public(&self) -> &HybridKemPublic {
        self.onion.public()
    }

    /// The epoch this router's forward-secure onion key is currently at (advances on
    /// `Command::AdvanceEpoch`).
    #[must_use]
    pub fn onion_epoch(&self) -> Epoch {
        self.onion.epoch()
    }

    /// **Pin** the combiner's partial-gathering deadline, disabling the measured one ([`GatherClock`]).
    ///
    /// For a scenario that must assert a specific expiry — a starvation test proving a hop below `t` live
    /// members is abandoned rather than hanging. Production leaves it unset: a pinned deadline is the defect
    /// this type exists to remove, since the right value moved 45× between build profiles on one machine.
    #[must_use]
    pub fn with_gather_timeout(mut self, timeout: Duration) -> Self {
        self.gather_override = Some(timeout);
        self
    }

    /// The deadline the next gather will be armed with — the pin if one is set, else the measured value.
    fn gather_deadline(&self) -> Duration {
        self.gather_override.unwrap_or_else(|| self.gather.deadline())
    }

    /// Bind this router to the endpoint of a circuit it owns (a rendezvous loopback or a reply circuit
    /// it built): on delivery it recomputes the path-authenticator over `hop_lines` + `seed` and drops a
    /// payload whose holonomy does not match — the live wiring of [`threshold::verify_delivery`] onto the
    /// peel path (spec §5.4, S1-M1). A transit relay leaves this unset and delivers unverified, exactly as
    /// [`crate::sealed`]'s relay path does — only the circuit owner can (and does) verify.
    #[must_use]
    pub fn with_delivery_check(mut self, hop_lines: Vec<Triple>, seed: Vec<u8>) -> Self {
        self.delivery_check = Some((hop_lines, seed));
        self
    }

    /// Enable Poisson mixing: hold each forwarded hop for an exponential delay of mean `mean_delay`
    /// before sending, so a batch of onions leaves reordered (spec §L5, V7). Zero disables it.
    #[must_use]
    pub fn with_mixing(mut self, mean_delay: Duration) -> Self {
        self.mean_delay = mean_delay;
        self
    }

    /// Enable constant-rate **cover traffic** at mean interval `interval` (Poisson). The schedule begins
    /// on the first `Command::StartHeartbeat`; zero (the default) leaves cover off. Each tick emits a
    /// constant-size cover onion that is byte-indistinguishable from a real one, so the router's send
    /// rate and packet size reveal nothing about whether it is carrying real traffic (audit E1).
    #[must_use]
    pub fn with_cover(mut self, interval: Duration) -> Self {
        self.cover_interval = interval;
        self
    }

    /// A secret-keyed PRF unit in `[0, 1)` for the cover schedule (destination, gaps): keyed on the same
    /// secret `mix_seed` as the mix delay, so the whole cover pattern is unpredictable from public data.
    fn cover_prf_unit(&self, counter: u64) -> f64 {
        let mut data = self.mix_seed.to_vec();
        data.extend_from_slice(&counter.to_be_bytes());
        let digest = fanos_primitives::hash_labeled("FANOS-v1/threshold-cover-prf", &data);
        let bits = u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]));
        (bits as f64) / (u64::MAX as f64 + 1.0)
    }

    /// Arm the next cover tick after a fresh exponential gap (mean [`cover_interval`](Self::cover_interval)).
    fn arm_cover(&mut self) -> Effect {
        self.cover_seq = self.cover_seq.wrapping_add(1);
        let u = self.cover_prf_unit(self.cover_seq).max(1e-12);
        let gap = (-(self.cover_interval.as_nanos() as f64) * u.ln()) as u64;
        Effect::ArmTimer {
            token: TimerToken(COVER_TOKEN),
            after: Duration(gap.max(1)),
        }
    }

    /// Begin the cover schedule (arm the first tick) if cover is enabled and not already running.
    fn start_cover(&mut self) -> Vec<Effect> {
        if self.cover_interval.as_nanos() == 0 || self.covering {
            return Vec::new();
        }
        self.covering = true;
        alloc::vec![self.arm_cover()]
    }

    /// Emit one constant-size keystream **cover onion** to a pseudo-randomly chosen line's combiner, and
    /// re-arm the cover tick. The cell is a full [`THRESHOLD_ONION_LEN`] block of keystream that looks
    /// exactly like a padded threshold onion; the recipient tries to peel it, the KEM/AEAD fails on the
    /// random bytes, and it is dropped — the identical path a real onion routed to the wrong line takes,
    /// so cover and real traffic are unobservable to a network adversary (audit E1, spec §5.5/V8).
    fn emit_cover(&mut self) -> Vec<Effect> {
        let mut effects = Vec::new();
        if self.outbox.is_empty() {
            // A secret-keyed pseudo-random destination line (there are `N` lines in the plane).
            self.cover_seq = self.cover_seq.wrapping_add(1);
            let n_lines = Plane::<F>::N as usize;
            let idx = (self.cover_prf_unit(self.cover_seq) * n_lines as f64) as usize;
            let line = Line::<F>::at(idx.min(n_lines.saturating_sub(1))).coords();
            // A constant-size block of keystream, indistinguishable from a real padded threshold onion.
            self.cover_seq = self.cover_seq.wrapping_add(1);
            let mut material = self.mix_seed.to_vec();
            material.extend_from_slice(&self.cover_seq.to_be_bytes());
            let mut cell = alloc::vec![0u8; threshold::THRESHOLD_ONION_LEN];
            fanos_primitives::hash::hash_xof("FANOS-v1/threshold-cover-body", &material, &mut cell);
            // Salted like a real launch (#55): cover traffic must draw its gatherer the same way real
            // onions do, or the address pattern alone would tell cover and cargo apart.
            if let Some(combiner) = Self::combiner_of_salted(line, &cell) {
                effects.push(Effect::Send {
                    to: combiner,
                    frame: encode_onion(line, &cell),
                });
            }
        } else {
            // A queued real forward displaces this cover slot; the pseudo-random pick reorders the
            // batch (the mixing property) while the emission rate stays constant (audit E6).
            self.cover_seq = self.cover_seq.wrapping_add(1);
            let idx = (self.cover_prf_unit(self.cover_seq) * self.outbox.len() as f64) as usize;
            if let Some((to, frame)) = self.outbox.remove(idx.min(self.outbox.len() - 1)) {
                effects.push(Effect::Send { to, frame });
            }
        }
        if self.covering && self.cover_interval.as_nanos() > 0 {
            effects.push(self.arm_cover());
        }
        effects
    }

    /// Forward `frame` to `to`. With cover on (the Full profile) the cell is **queued for the next
    /// constant-rate send slot** (audit E6): it displaces a cover cell rather than adding to the send
    /// rate, so emitted volume never tracks real traffic. With cover off it leaves immediately, or — if
    /// a per-cell mixing delay is set — is held for a sampled exponential delay so a batch leaves
    /// reordered.
    fn forward_send(&mut self, to: Triple, frame: Vec<u8>) -> Vec<Effect> {
        if self.cover_interval.as_nanos() != 0 {
            if self.outbox.len() >= MAX_OUTBOX {
                self.outbox.pop_front();
            }
            self.outbox.push_back((to, frame));
            return if self.covering {
                Vec::new()
            } else {
                self.start_cover()
            };
        }
        if self.mean_delay.as_nanos() == 0 {
            return alloc::vec![Effect::Send { to, frame }];
        }
        self.mix_seq += 1;
        let id = self.mix_seq;
        let after = self.sample_delay(id);
        self.mix_pending.insert(id, (to, frame));
        alloc::vec![Effect::ArmTimer {
            token: TimerToken(MIX_FLAG | id),
            after,
        }]
    }

    /// Sample an exponential mixing delay with the configured mean (`−mean·ln u`), seeded from the node's
    /// **secret** `mix_seed` (not its public coordinate), so the delay sequence cannot be recomputed from
    /// public data — the timing correlation Poisson mixing exists to destroy (audit E2).
    fn sample_delay(&self, id: u64) -> Duration {
        let mut data = self.mix_seed.to_vec();
        data.extend_from_slice(&id.to_be_bytes());
        let digest = fanos_primitives::hash_labeled("FANOS-v1/threshold-mix", &data);
        let bits = u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]));
        let u = ((bits as f64) / (u64::MAX as f64 + 1.0)).max(1e-12);
        let ns = (-(self.mean_delay.as_nanos() as f64) * u.ln()) as u64;
        Duration(ns.max(1))
    }

    /// The canonical member coordinates of a hop line, in `points_on` order (the order a layer is
    /// sealed in, so a member's index in this list is its share index).
    fn line_members(line: Triple) -> Vec<Triple> {
        Line::<F>::new(line).map_or_else(Vec::new, |l| {
            Plane::<F>::points_on(l).map(|p| p.coords()).collect()
        })
    }

    /// This node's share index within `line`, if it is a member.
    fn my_index(&self, line: Triple) -> Option<usize> {
        let me = self.coord.coords();
        Self::line_members(line).iter().position(|&m| m == me)
    }

    /// The **canonical** combiner of a line — [`Self::combiner_of_salted`] with an empty salt. Use it where a
    /// pure function of the line alone is required: the `meeting_lines` distinct-combiner walk, a bare-proxy
    /// client's registration target, tests of the canonical map.
    ///
    /// **Not member zero, and the difference is a censorship bound.** Taking the first member made the combiner
    /// map concentrate: enumerating every line of the plane, only **4 of 7** points on `PG(2,2)` and **14 of 57**
    /// on `PG(2,7)` were ever a combiner — a fraction that *shrinks* as `q` grows. On `PG(2,7)` that let an
    /// adversary holding 14 specific points, **fewer than the `f = 18` the fault model already tolerates**,
    /// control every combiner in the plane and censor every hidden service in the cell. The points are a public
    /// function of the geometry, so choosing them needed no secret.
    ///
    /// Selecting by a digest of the line's own coordinates spreads the image to **5 of 7** and **40 of 57**
    /// respectively. The property that must hold is `|image| ≥ f + 1` — 5 ≥ 3 and 40 ≥ 19 — because that is what
    /// lets a service hold `f + 1` distinct meeting combiners and leaves at least one outside any admissible
    /// adversary set. `the_combiner_map_covers_more_of_the_plane_than_the_cell_tolerates_faults` asserts exactly
    /// that, on both planes.
    ///
    /// Full coverage is neither achieved nor required: ~70 % on `PG(2,7)` is what a uniform per-line choice gives
    /// (coupon-collector, `1 − 1/e`), and `|image| ≥ f + 1` is the whole requirement. This map is deliberately
    /// **fixed across epochs**, which used to be a stated residual — it no longer is, because nothing routes by
    /// it: launches draw a per-onion member ([`Self::combiner_of_salted`]), so the uniform member coverage a
    /// rotating map would have bought is supplied per packet instead of per epoch.
    fn combiner_of(line: Triple) -> Option<Triple> {
        Self::combiner_of_salted(line, &[])
    }

    /// The line member that gathers **this particular onion** — the canonical digest of the line, extended by
    /// a per-onion `salt`. Every member of a line can combine (nothing in [`Self::on_onion`] is
    /// combiner-specific), so *which* member an onion is addressed to is a free choice of the sender — and
    /// pinning it to one canonical member per line re-created, at every hop, the single point of failure the
    /// `f + 1` meeting-point spread exists to remove (#55): one silenced node killed a hop line outright even
    /// though `t` of its `q + 1` members were alive and its peel quorum was intact.
    ///
    /// Salting the pick with the onion bytes restores the line's own threshold as the hop's availability
    /// bound. Each sealed onion — and every DIAULOS retransmit is a **fresh** onion — draws an independent
    /// uniform member, so a hop with `d` dead members loses only `d/(q+1)` of attempts and a retransmitting
    /// session self-heals; silencing the hop **permanently** now requires killing `q + 2 − t` of its members,
    /// the same quorum the peel itself needs. The salt is a public function of the (public) onion ciphertext:
    /// deterministic — the simulator reproduces every pick, and a given onion has one target, so duplicates
    /// collapse — and it links nothing that the onion itself does not already link.
    ///
    /// The map stays fixed across epochs (empty-salt case above): rotation is supplied per onion by the salt,
    /// so the `(epoch, beacon)` threading the canonical map's doc once contemplated is no longer the missing
    /// piece — the per-onion draw already yields the uniform member coverage an epoch rotation would have.
    fn combiner_of_salted(line: Triple, salt: &[u8]) -> Option<Triple> {
        let members = Self::line_members(line);
        let [a, b, c] = line;
        let mut data = Vec::with_capacity(12 + salt.len());
        data.extend_from_slice(&a.to_be_bytes());
        data.extend_from_slice(&b.to_be_bytes());
        data.extend_from_slice(&c.to_be_bytes());
        data.extend_from_slice(salt);
        let digest = fanos_primitives::hash_labeled("FANOS-v1/threshold-combiner", &data);
        // **Eight digest bytes, not one, and the width is the uniformity claim.** Reducing a single byte
        // mod `q + 1` is only uniform when `q + 1` divides 256: the residues `0..(256 mod (q+1))` each get
        // one extra preimage, a bias of `(256 mod (q+1)) / 256` — 1.2 % on Fano, but **12.9 % at `q = 32`**,
        // and it grows with the plane. That matters here precisely because the availability bound in the
        // doc above is a uniformity statement: a member favoured by the reduction is a member an adversary
        // prefers to silence. Over `u64` the same bias is `≈ (q+1)·2⁻⁶⁴`, which is nothing on any plane.
        // Same shape as `nostos::select_drop_line`, which reduces a `q + 1` modulus the same way.
        let raw = u64::from_be_bytes(
            digest
                .get(..8)
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0u8; 8]),
        );
        let idx = (raw % members.len().max(1) as u64) as usize;
        members.get(idx).copied()
    }

    /// Handle an onion addressed to us as the combiner of `line`: seed a pending peel with our own
    /// partial and fan out share-requests to the rest of the line.
    fn on_onion(&mut self, now: Instant, line: Triple, onion: Vec<u8>) -> Vec<Effect> {
        let req_id = self.seq;
        self.seq += 1;

        let members = Self::line_members(line);
        let member_count = members.len();
        let mut shares = Vec::new();
        if let Some(i) = self.my_index(line)
            && let Some(share) = self
                .onion
                .secrets()
                .find_map(|sk| threshold::member_partial(&onion, i, sk))
        {
            shares.push(share);
        }

        let mut effects = Vec::new();
        let me = self.coord.coords();
        for member in &members {
            if *member != me {
                effects.push(Effect::Send {
                    to: *member,
                    frame: encode_req(req_id, me, line, &onion),
                });
            }
        }
        // Bounded by COUNT, not by the deadline (see `MAX_PENDING`): memory must not depend on a timing
        // value that is now measured and free to grow. The oldest incomplete gather goes — it is the one
        // most likely already dead, and its client retransmits.
        if self.pending.len() >= MAX_PENDING
            && let Some(&oldest) = self.pending.keys().next()
        {
            self.pending.remove(&oldest);
        }
        self.pending.insert(
            req_id,
            Pending {
                onion,
                shares,
                member_count,
                line,
                armed_at: now,
            },
        );
        // If we already have a threshold (e.g. t = 1), peel now; else await replies until deadline.
        if let Some(done) = self.try_peel(now, req_id) {
            effects.extend(done);
        } else {
            effects.push(Effect::ArmTimer {
                token: TimerToken(req_id),
                after: self.gather_deadline(),
            });
        }
        effects
    }

    /// Handle a share-request from a combiner: compute our partial for `line` and reply.
    fn on_request(&self, req_id: u64, combiner: Triple, line: Triple, onion: &[u8]) -> Vec<Effect> {
        let Some(i) = self.my_index(line) else {
            return Vec::new();
        };
        let Some(share) = self
            .onion
            .secrets()
            .find_map(|sk| threshold::member_partial(onion, i, sk))
        else {
            return Vec::new();
        };
        alloc::vec![Effect::Send {
            to: combiner,
            frame: encode_rep(req_id, &share),
        }]
    }

    /// Handle a partial-decryption reply: fold it in (if it is a plausible member share) and try to
    /// peel. A reply is only a *candidate* — it is not trusted until a subset of shares actually peels.
    fn on_reply(&mut self, now: Instant, req_id: u64, share: Share) -> Vec<Effect> {
        let Some(pending) = self.pending.get_mut(&req_id) else {
            return Vec::new(); // unknown / already-peeled request
        };
        // Reject any share whose index is not a real member of this line (valid Shamir x is
        // `1..=member_count`). This caps distinct pollution to the true membership and drops
        // garbage-index forgeries outright, so an attacker cannot balloon the candidate set with
        // arbitrary `x` values.
        if share.x() == 0 || usize::from(share.x()) > pending.member_count {
            return Vec::new();
        }
        // De-duplicate only *exact* (x, y) repeats. Crucially we do NOT drop a differing `y` at an
        // already-seen `x`: a forged share must not be able to evict or pre-empt the honest member's
        // real reply — both are kept as candidates and the peel search below picks the set that works.
        if pending
            .shares
            .iter()
            .any(|s| s.x() == share.x() && s.y() == share.y())
        {
            return Vec::new();
        }
        if pending.shares.len() >= MAX_CANDIDATES {
            return Vec::new(); // flood cap — a real line never needs this many candidates
        }
        pending.shares.push(share);
        self.try_peel(now, req_id).unwrap_or_default()
    }

    /// If a pending peel can be satisfied, peel it and act on the outcome. The pending state is removed
    /// **only** when a subset of shares actually peels (or when its gather deadline fires) — a single
    /// poisoned share can therefore neither reconstruct a wrong key that discards the peel nor destroy
    /// the in-flight state, so honest replies still complete the hop (liveness under up to `t − 1`
    /// malicious members).
    fn try_peel(&mut self, now: Instant, req_id: u64) -> Option<Vec<Effect>> {
        let pending = self.pending.get(&req_id)?;
        if pending.shares.len() < self.threshold {
            return None;
        }
        let line = pending.line;
        let armed_at = pending.armed_at;
        let peel = peel_best_subset(&pending.onion, &pending.shares, self.threshold)?;
        self.pending.remove(&req_id); // the hop is resolved — evict the in-flight state
        // One completed gather is one latency sample, and it contains `RTT + C_partial + Q` together —
        // measured under exactly the load the next gather will meet. This is what replaces the constant.
        self.gather
            .observe(Duration(now.0.saturating_sub(armed_at.0)));
        Some(match peel {
            ThresholdPeel::Deliver { payload, holonomy } => {
                // If we own this circuit's endpoint, verify the path-authenticator and drop a delivery
                // that traversed a different circuit than agreed (spec §5.4, S1-M1). A transit relay has
                // no `delivery_check` and delivers unverified — it cannot know the circuit.
                if let Some((lines, seed)) = &self.delivery_check
                    && threshold::verify_delivery(lines, seed, holonomy).is_err()
                {
                    return Some(Vec::new());
                }
                // NOSTOS geometric dead-drop: a delivery whose payload is dead-drop-enveloped is not
                // consumed here — the combiner multicasts the end-to-end body to this line's `q+1`
                // members, and the receiver, hidden among them, decrypts. A normal delivery is
                // notified locally as before. Reply integrity is the end-to-end AEAD, so the holonomy
                // (which the members do not receive) is not the reply's integrity guarantee here.
                match crate::nostos::parse_deaddrop(&payload) {
                    Some(e2e) => self.deaddrop_multicast(line, e2e),
                    None => alloc::vec![Effect::Notify(Notification::Delivered {
                        from: ANONYMOUS,
                        payload,
                    })],
                }
            }
            ThresholdPeel::Forward { next, onion } => {
                // Re-pad the inner onion to the constant bucket so the forwarded packet is the
                // same size as the one we received — no cross-hop size correlation. The next hop's
                // gatherer is then picked per onion (salted by the padded bytes, #55): any member
                // can combine, and varying the pick keeps one dead member from killing the hop.
                let padded = threshold::pad(&onion).unwrap_or(onion);
                match Self::combiner_of_salted(next, &padded) {
                    Some(c) => self.forward_send(c, encode_onion(next, &padded)),
                    None => Vec::new(),
                }
            }
        })
    }

    /// Deliver a NOSTOS dead-drop: multicast the end-to-end body `e2e` to every member of `line`. This
    /// combiner (itself a member) hands the body to its own application; every other member receives a
    /// dead-drop cell. Only the receiver's [`ReplyKeys`](crate::nostos::ReplyKeys) opens it, so no node —
    /// not the combiner, not any member — learns which of the `q+1` is the receiver (spec §5, NOSTOS).
    fn deaddrop_multicast(&self, line: Triple, e2e: &[u8]) -> Vec<Effect> {
        let me = self.coord.coords();
        Self::line_members(line)
            .into_iter()
            .map(|member| {
                if member == me {
                    Effect::Notify(Notification::Delivered {
                        from: ANONYMOUS,
                        payload: e2e.to_vec(),
                    })
                } else {
                    Effect::Send {
                        to: member,
                        frame: encode_drop(line, e2e),
                    }
                }
            })
            .collect()
    }

    /// Receive a dead-drop cell as a member of `line`: hand the end-to-end body to our application, which
    /// tries to open it with its reply key (only the intended receiver succeeds). Ignored if we are not a
    /// member of `line` — a misrouted or spoofed cell reaches no application.
    fn on_drop(&self, line: Triple, e2e: Vec<u8>) -> Vec<Effect> {
        if self.my_index(line).is_some() {
            alloc::vec![Effect::Notify(Notification::Delivered {
                from: ANONYMOUS,
                payload: e2e,
            })]
        } else {
            Vec::new()
        }
    }
}

/// Search for a set of `threshold` shares with distinct indices that peels `onion`, returning the
/// first successful outcome. Honest operation succeeds on the first (all-honest) subset; when up to
/// `t − 1` forged shares are interleaved, other subsets are tried, bounded by [`MAX_PEEL_ATTEMPTS`] so
/// the search can never be turned into a CPU-exhaustion vector.
fn peel_best_subset(onion: &[u8], shares: &[Share], threshold: usize) -> Option<ThresholdPeel> {
    if threshold == 0 || shares.len() < threshold {
        return None;
    }
    let mut chosen: Vec<usize> = Vec::with_capacity(threshold);
    let mut attempts = 0usize;
    peel_search(onion, shares, threshold, 0, &mut chosen, &mut attempts)
}

/// Recursive helper for [`peel_best_subset`]: extend `chosen` with distinct-`x` share indices until it
/// reaches `threshold`, trying a peel at each complete subset.
fn peel_search(
    onion: &[u8],
    shares: &[Share],
    threshold: usize,
    start: usize,
    chosen: &mut Vec<usize>,
    attempts: &mut usize,
) -> Option<ThresholdPeel> {
    if chosen.len() == threshold {
        *attempts += 1;
        let subset: Vec<Share> = chosen
            .iter()
            .filter_map(|&i| shares.get(i).cloned())
            .collect();
        return threshold::peel_onion_with_shares(onion, &subset).ok();
    }
    for i in start..shares.len() {
        if *attempts >= MAX_PEEL_ATTEMPTS {
            break;
        }
        // Keep share indices distinct: a valid Shamir reconstruction needs distinct x-coordinates.
        let Some(candidate) = shares.get(i) else {
            continue;
        };
        if chosen
            .iter()
            .any(|&j| shares.get(j).is_some_and(|s| s.x() == candidate.x()))
        {
            continue;
        }
        chosen.push(i);
        if let Some(peel) = peel_search(onion, shares, threshold, i + 1, chosen, attempts) {
            return Some(peel);
        }
        chosen.pop();
    }
    None
}

impl<F: Field> Engine for ThresholdRouter<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Message { frame, .. } => match frame.split_first() {
                Some((&TAG_ONION, body)) => match decode_onion(body) {
                    Some((line, onion)) => self.on_onion(now, line, onion),
                    None => Vec::new(),
                },
                Some((&TAG_REQ, body)) => match decode_req(body) {
                    Some((req_id, combiner, line, onion)) => {
                        self.on_request(req_id, combiner, line, onion)
                    }
                    None => Vec::new(),
                },
                Some((&TAG_REP, body)) => match decode_rep(body) {
                    Some((req_id, share)) => self.on_reply(now, req_id, share),
                    None => Vec::new(),
                },
                Some((&TAG_DROP, body)) => match decode_drop(body) {
                    Some((line, e2e)) => self.on_drop(line, e2e),
                    None => Vec::new(),
                },
                _ => Vec::new(),
            },
            Input::Timer(TimerToken(token)) => {
                if token == COVER_TOKEN {
                    // The cover tick fired: emit one indistinguishable cover onion and re-arm.
                    self.emit_cover()
                } else if token & MIX_FLAG != 0 {
                    // A held mix delay elapsed: release the forward now.
                    match self.mix_pending.remove(&(token & !MIX_FLAG)) {
                        Some((to, frame)) => alloc::vec![Effect::Send { to, frame }],
                        None => Vec::new(),
                    }
                } else {
                    // The gather deadline fired: drop an incomplete pending peel, and BACK OFF — the
                    // deadline was demonstrably too short for the load this node is under, and an expiry
                    // yields no sample, so nothing else would ever widen it (RFC 6298 §5.5 + Karn).
                    if self.pending.remove(&token).is_some() {
                        self.gather.expired();
                    }
                    Vec::new()
                }
            }
            // A node may also *originate* onions as a client: it launches an already-sealed frame to `to`
            // verbatim (the combiner of its first hop), so the same node that peels replies here can inject
            // its own launch frames. `Command::Emit` is the raw-emit primitive shared with the overlay
            // composite; `Command::Send` is accepted equivalently for a standalone router client. Other
            // commands do not apply to a router.
            Input::Command(Command::Emit { to, frame }) => alloc::vec![Effect::Send { to, frame }],
            Input::Command(Command::Send { to, payload }) => {
                alloc::vec![Effect::Send { to, frame: payload }]
            }
            // Begin the cover schedule (if `with_cover` enabled it), mirroring the other node engines.
            Input::Command(Command::StartHeartbeat) => self.start_cover(),
            // The epoch beacon advanced: rotate the forward-secure onion key one step (audit E4). The old
            // epoch's decap secret is dropped, so onions recorded under it can no longer be peeled here.
            Input::Command(Command::AdvanceEpoch) => {
                self.onion.advance_to(self.onion.epoch().next());
                Vec::new()
            }
            Input::Command(_) => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord.coords()
    }
}

/// Build the first-hop frame a client sends to launch a threshold onion: `TAG_ONION ‖ line ‖ onion`,
/// addressed to the first hop line's combiner ([`combiner_for`]).
#[must_use]
pub fn launch_frame(line: Triple, onion: &[u8]) -> Vec<u8> {
    encode_onion(line, onion)
}

/// The **canonical** combiner of a line, for a given field `F` — the empty-salt case of
/// [`combiner_for_salted`]. Derivations that need a pure function of the line alone (the
/// `meeting_lines` distinct-combiner walk, a bare-proxy registration target) use this; an actual
/// onion launch uses the salted pick.
#[must_use]
pub fn combiner_for<F: Field>(line: Triple) -> Option<Triple> {
    ThresholdRouter::<F>::combiner_of(line)
}

/// The line member a **particular onion** is launched at (`salt` = the sealed onion bytes), for a given
/// field `F`. Any member of a line can gather, so the sender's pick is free — and drawing it per onion is
/// what turns the hop's availability from "one canonical node" into "the line's own `t`-of-`q+1` quorum"
/// (#55). See `ThresholdRouter::combiner_of_salted` for the full derivation.
#[must_use]
pub fn combiner_for_salted<F: Field>(line: Triple, salt: &[u8]) -> Option<Triple> {
    ThresholdRouter::<F>::combiner_of_salted(line, salt)
}

/// The canonical member coordinates of `line` in seal order, for a client assembling a hop's keys.
#[must_use]
pub fn line_member_coords<F: Field>(line: Triple) -> Vec<Triple> {
    ThresholdRouter::<F>::line_members(line)
}

// --- internal framing ---
//
// Coordinates serialize via the canonical `fanos_geometry::{encode_triple, decode_triple}` (12-byte
// big-endian) — see the framing helpers below.

fn encode_onion(line: Triple, onion: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 12 + onion.len());
    v.push(TAG_ONION);
    v.extend_from_slice(&fanos_geometry::encode_triple(line));
    v.extend_from_slice(onion);
    v
}

fn decode_onion(body: &[u8]) -> Option<(Triple, Vec<u8>)> {
    let line = fanos_geometry::decode_triple(body.get(..12)?)?;
    Some((line, body.get(12..)?.to_vec()))
}

fn encode_drop(line: Triple, e2e: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 12 + e2e.len());
    v.push(TAG_DROP);
    v.extend_from_slice(&fanos_geometry::encode_triple(line));
    v.extend_from_slice(e2e);
    v
}

fn decode_drop(body: &[u8]) -> Option<(Triple, Vec<u8>)> {
    let line = fanos_geometry::decode_triple(body.get(..12)?)?;
    Some((line, body.get(12..)?.to_vec()))
}

fn encode_req(req_id: u64, combiner: Triple, line: Triple, onion: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 12 + 12 + onion.len());
    v.push(TAG_REQ);
    v.extend_from_slice(&req_id.to_be_bytes());
    v.extend_from_slice(&fanos_geometry::encode_triple(combiner));
    v.extend_from_slice(&fanos_geometry::encode_triple(line));
    v.extend_from_slice(onion);
    v
}

fn decode_req(body: &[u8]) -> Option<(u64, Triple, Triple, &[u8])> {
    let req_id = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let combiner = fanos_geometry::decode_triple(body.get(8..20)?)?;
    let line = fanos_geometry::decode_triple(body.get(20..32)?)?;
    Some((req_id, combiner, line, body.get(32..)?))
}

fn encode_rep(req_id: u64, share: &Share) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 1 + share.y().len());
    v.push(TAG_REP);
    v.extend_from_slice(&req_id.to_be_bytes());
    v.push(share.x());
    v.extend_from_slice(share.y());
    v
}

fn decode_rep(body: &[u8]) -> Option<(u64, Share)> {
    let req_id = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let x = *body.get(8)?;
    let y = body.get(9..)?.to_vec();
    Some((req_id, Share::new(x, y)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::threshold_onion::{HopLine, member_partial, seal_onion};
    use fanos_field::F2;

    /// **The censorship bound, asserted on two planes because it must follow from the geometry.**
    ///
    /// A hidden service is reachable only if some meeting combiner of its is honest, so it needs `f + 1` DISTINCT
    /// combiners — and that is impossible unless the combiner map's image is itself at least that large. Taking a
    /// line's first member (what this replaced) gave an image of 4 on `PG(2,2)` and **14 on `PG(2,7)`, below the
    /// `f = 18` the fault model already tolerates**: an adversary inside its budget held every combiner in the
    /// plane and could censor every hidden service in the cell.
    ///
    /// A Fano-only test would have stayed green — 4 ≥ 3 — which is exactly why this enumerates a second plane.
    #[test]
    fn the_combiner_map_covers_more_of_the_plane_than_the_cell_tolerates_faults() {
        use fanos_field::F7;
        use fanos_geometry::Plane;

        fn image<F: Field>() -> usize {
            Plane::<F>::lines()
                .filter_map(|l| ThresholdRouter::<F>::combiner_of(l.coords()))
                .collect::<alloc::collections::BTreeSet<_>>()
                .len()
        }
        for (q, image) in [(2usize, image::<F2>()), (7, image::<F7>())] {
            let n = q * q + q + 1;
            let f = (n - 1) / 3;
            assert!(
                image > f,
                "PG(2,{q}): only {image} of {n} points are ever a combiner, and the cell tolerates f = {f} faults \
                 — so an adversary within its budget can hold every combiner and censor the whole cell"
            );
        }
    }

    use fanos_pqcrypto::SeedRng;

    fn has_delivery(effects: &[Effect], payload: &[u8]) -> bool {
        effects.iter().any(|e| {
            matches!(e, Effect::Notify(Notification::Delivered { from, payload: p })
                if *from == ANONYMOUS && p == payload)
        })
    }

    #[test]
    fn the_mixing_delay_is_secret_keyed_not_a_public_function_of_the_coordinate() {
        // E2. Two routers at the SAME public coordinate but with DIFFERENT KEM secrets must produce
        // DIFFERENT delay schedules — otherwise a global passive adversary who knows a node's (public)
        // coordinate could recompute its whole `D(coord, 1), D(coord, 2), …` sequence a priori and relink
        // a hop's in/out flows by timing. Before the fix the schedule was a pure function of the
        // coordinate, so these would be byte-identical.
        let (s0, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"mix-secret-a"));
        let (s1, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"mix-secret-b"));
        let mean = Duration::from_millis(50);
        let a =
            ThresholdRouter::<F2>::new(Point::<F2>::at(0), &s0, 2, [0x11; 32]).with_mixing(mean);
        let b =
            ThresholdRouter::<F2>::new(Point::<F2>::at(0), &s1, 2, [0x11; 32]).with_mixing(mean);

        let seq_a: Vec<u64> = (1..=8).map(|i| a.sample_delay(i).as_nanos()).collect();
        let seq_b: Vec<u64> = (1..=8).map(|i| b.sample_delay(i).as_nanos()).collect();
        assert_ne!(
            seq_a, seq_b,
            "the delay schedule must depend on the node's secret, not just its public coordinate"
        );
        // Deterministic for a given secret — the sans-I/O replay property is preserved.
        let seq_a2: Vec<u64> = (1..=8).map(|i| a.sample_delay(i).as_nanos()).collect();
        assert_eq!(
            seq_a, seq_a2,
            "the schedule is deterministic for a given secret"
        );
    }

    #[test]
    fn cover_traffic_emits_indistinguishable_constant_size_cells_at_a_uniform_rate() {
        // E1. With cover enabled, StartHeartbeat arms the schedule; each tick emits ONE constant-size
        // cover onion — byte-indistinguishable from a real padded threshold onion — and re-arms, so the
        // router's send rate and packet size are uniform whether or not it is carrying real traffic.
        let (s, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"cover-on"));
        let mut r = ThresholdRouter::<F2>::new(Point::<F2>::at(0), &s, 2, [0x11; 32])
            .with_cover(Duration::from_millis(100));

        let armed = r.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let is_cover_timer = |e: &Effect| matches!(e, Effect::ArmTimer { token: TimerToken(t), .. } if *t == COVER_TOKEN);
        assert!(
            armed.iter().any(is_cover_timer),
            "StartHeartbeat arms the cover schedule"
        );

        let tick = r.step(Instant(1), Input::Timer(TimerToken(COVER_TOKEN)));
        let sends: Vec<&[u8]> = tick
            .iter()
            .filter_map(|e| match e {
                Effect::Send { frame, .. } => Some(frame.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 1, "exactly one cover cell per tick");
        // The cover cell is exactly the size of a real launched onion carrying a full padded packet.
        let real_len =
            launch_frame([0, 0, 0], &alloc::vec![0u8; threshold::THRESHOLD_ONION_LEN]).len();
        assert_eq!(
            sends[0].len(),
            real_len,
            "cover cell is the constant threshold-onion size"
        );
        assert!(
            tick.iter().any(is_cover_timer),
            "the schedule re-arms (constant rate)"
        );

        // Without `with_cover`, StartHeartbeat is inert (no cover on the mixing-only path).
        let (s2, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"cover-off"));
        let mut plain = ThresholdRouter::<F2>::new(Point::<F2>::at(0), &s2, 2, [0x11; 32]);
        assert!(
            plain
                .step(Instant(0), Input::Command(Command::StartHeartbeat))
                .is_empty(),
            "no cover configured ⇒ StartHeartbeat is a no-op"
        );
    }

    #[test]
    fn a_queued_real_forward_displaces_a_cover_slot_at_a_constant_rate() {
        // E6. On the Full profile a real forward must NOT add a send on top of the cover rate — it
        // DISPLACES the next cover slot, so the emission rate is constant whether or not real traffic
        // flows and a flow-correlation adversary counting cells learns nothing about the real load.
        let (s, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"e6-displace"));
        let mut r = ThresholdRouter::<F2>::new(Point::<F2>::at(0), &s, 2, [0x11; 32])
            .with_cover(Duration::from_millis(100));
        r.step(Instant(0), Input::Command(Command::StartHeartbeat));

        // A real forward (what the peel path calls) is queued, not sent immediately, while cover is on.
        let dest = Point::<F2>::at(3).coords();
        let real = alloc::vec![0xABu8; threshold::THRESHOLD_ONION_LEN];
        let queued = r.forward_send(dest, encode_onion(dest, &real));
        assert!(
            !queued.iter().any(|e| matches!(e, Effect::Send { .. })),
            "with cover on, a real forward is queued for the next slot, not sent at once"
        );

        // The next slot emits the QUEUED REAL cell (to its destination), displacing the cover cell —
        // one emission, so the rate is unchanged.
        let tick = r.step(Instant(1), Input::Timer(TimerToken(COVER_TOKEN)));
        let dests: Vec<Triple> = tick
            .iter()
            .filter_map(|e| match e {
                Effect::Send { to, .. } => Some(*to),
                _ => None,
            })
            .collect();
        assert_eq!(
            dests,
            alloc::vec![dest],
            "the slot emitted the queued real cell, not cover"
        );

        // With the queue empty again, the next slot falls back to a cover cell — still one emission.
        let tick2 = r.step(Instant(2), Input::Timer(TimerToken(COVER_TOKEN)));
        assert_eq!(
            tick2
                .iter()
                .filter(|e| matches!(e, Effect::Send { .. }))
                .count(),
            1,
            "an empty queue emits one cover cell — the rate stays constant"
        );
    }

    #[test]
    fn a_forged_reply_neither_blocks_nor_kills_a_hop() {
        // A Fano line (3 members), threshold 2. An attacker who knows the request id (a counter, and
        // in any case broadcast to the line) injects a forged partial at an honest member's index with
        // garbage `y`. Before the fix this poisoned the share set → wrong reconstruction → the pending
        // peel was destroyed → the hop died. It must now be inert: the honest member's real reply still
        // completes the hop.
        let line_coord = Line::<F2>::at(1).coords();
        let members = ThresholdRouter::<F2>::line_members(line_coord);
        assert_eq!(members.len(), 3);
        let t = 2usize;

        // Forward-secure ONION keypair per member, in points_on (seal) order (audit E4): the onion seals
        // each member's share to its epoch onion key, and the combiner router peels with its own onion
        // secret (its long-term identity key is separate and not used to peel).
        let onion_seed = |i: u8| {
            let mut s = [0x5Au8; 32];
            s[31] = i;
            s
        };
        let m0 = OnionKeyRatchet::new(onion_seed(0), Epoch::ZERO);
        let m1 = OnionKeyRatchet::new(onion_seed(1), Epoch::ZERO);
        let m2 = OnionKeyRatchet::new(onion_seed(2), Epoch::ZERO);
        let pubs = [m0.public(), m1.public(), m2.public()];
        let hop = HopLine {
            line: line_coord,
            members: &pubs,
        };
        let payload = b"anon-payload";
        let onion = seal_onion(&[hop], t as u8, payload, b"seed-router").unwrap();

        // The combiner is member 0; its onion genesis is onion_seed(0), so its onion_public == pubs[0].
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let (identity0, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"identity-0"));
        let mut router = ThresholdRouter::<F2>::new(combiner, &identity0, t, onion_seed(0));

        // Deliver the onion: the combiner seeds its own share and fans out requests — no peel yet.
        let onion_frame = launch_frame(line_coord, &onion);
        let e0 = router.step(
            Instant(0),
            Input::Message {
                from: [9, 9, 9],
                frame: onion_frame,
            },
        );
        assert!(
            !has_delivery(&e0, payload),
            "one share (t=2) cannot deliver"
        );

        // The honest member-1 reply (the real partial) and a forgery at the same index with mangled y.
        let honest1 = member_partial(&onion, 1, m1.secret()).unwrap();
        let forged = Share::new(honest1.x(), honest1.y().iter().map(|b| b ^ 0xFF).collect());
        assert_ne!(
            forged.y(),
            honest1.y(),
            "the forgery differs from the real share"
        );

        // Inject the forgery first: it reaches the threshold count but cannot peel, and must NOT be
        // allowed to force a (wrong) delivery or discard the pending peel.
        let e1 = router.step(
            Instant(1),
            Input::Message {
                from: [8, 8, 8],
                frame: encode_rep(0, &forged),
            },
        );
        assert!(
            !has_delivery(&e1, payload),
            "a forged share does not complete the hop"
        );

        // The honest reply now arrives: a valid subset (combiner + honest member 1) exists, so the hop
        // completes despite the forged candidate still sitting in the set.
        let e2 = router.step(
            Instant(2),
            Input::Message {
                from: members[1],
                frame: encode_rep(0, &honest1),
            },
        );
        assert!(
            has_delivery(&e2, payload),
            "the honest share completes the hop despite the forged one"
        );
    }

    #[test]
    fn a_circuit_owning_endpoint_drops_a_delivery_that_fails_the_holonomy_check() {
        // The live wiring of S1-M1: a router that owns a circuit's endpoint verifies the delivered
        // path-authenticator on the peel path and drops a payload that reached it over a different
        // circuit than agreed — while a transit relay (no `delivery_check`) delivers unverified.
        let line_coord = Line::<F2>::at(1).coords();
        let members = ThresholdRouter::<F2>::line_members(line_coord);
        let t = 2usize;
        let onion_seed = |i: u8| {
            let mut s = [0x5Au8; 32];
            s[31] = i;
            s
        };
        let m0 = OnionKeyRatchet::new(onion_seed(0), Epoch::ZERO);
        let m1 = OnionKeyRatchet::new(onion_seed(1), Epoch::ZERO);
        let m2 = OnionKeyRatchet::new(onion_seed(2), Epoch::ZERO);
        let pubs = [m0.public(), m1.public(), m2.public()];
        let hop = HopLine { line: line_coord, members: &pubs };
        let payload = b"anon-payload";
        let seed = b"seed-router";
        let onion = seal_onion(&[hop], t as u8, payload, seed).unwrap();
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let (identity0, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"identity-0"));

        // Drive a fresh router (optionally given a delivery check) to the delivery hop, and report
        // whether it emitted a Delivered. The combiner seeds its own share on the onion frame, then
        // member 1's honest partial reaches t = 2 and the hop peels.
        let deliver_with = |check: Option<(Vec<Triple>, Vec<u8>)>| -> bool {
            let mut router = ThresholdRouter::<F2>::new(combiner, &identity0, t, onion_seed(0));
            if let Some((lines, s)) = check {
                router = router.with_delivery_check(lines, s);
            }
            router.step(
                Instant(0),
                Input::Message { from: [9, 9, 9], frame: launch_frame(line_coord, &onion) },
            );
            let honest1 = member_partial(&onion, 1, m1.secret()).unwrap();
            let e = router.step(
                Instant(1),
                Input::Message { from: members[1], frame: encode_rep(0, &honest1) },
            );
            has_delivery(&e, payload)
        };

        assert!(deliver_with(None), "a transit relay delivers unverified (it cannot know the circuit)");
        assert!(
            deliver_with(Some((alloc::vec![line_coord], seed.to_vec()))),
            "the endpoint accepts a delivery over the true agreed circuit"
        );
        let wrong_line = Line::<F2>::at(2).coords();
        assert!(
            !deliver_with(Some((alloc::vec![wrong_line], seed.to_vec()))),
            "a delivery whose path does not match the agreed circuit is dropped (HolonomyFail)"
        );
        assert!(
            !deliver_with(Some((alloc::vec![line_coord], b"wrong-seed".to_vec()))),
            "a delivery under a different build seed is dropped — the holoseed is secret"
        );
    }

    #[test]
    fn a_command_send_launches_a_raw_frame() {
        // A router node can also originate onions as a client: Command::Send emits the frame verbatim.
        let (secret, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"launch"));
        let mut router = ThresholdRouter::<F2>::new(Point::<F2>::at(0), &secret, 2, [0x11; 32]);
        let effects = router.step(
            Instant(0),
            Input::Command(Command::Send {
                to: [1, 2, 3],
                payload: alloc::vec![9, 9, 9],
            }),
        );
        assert_eq!(
            effects,
            alloc::vec![Effect::Send {
                to: [1, 2, 3],
                frame: alloc::vec![9, 9, 9],
            }]
        );
    }

    #[test]
    fn the_combiner_set_is_a_strict_subset_of_the_points() {
        use fanos_geometry::Plane;
        // A line's combiner is its first `points_on` member, so many points are never any line's
        // combiner (Fano: 4 of 7; PG(2,7): 14 of 57). A rendezvous design must not assume a client is
        // reachable as the combiner of a line through its own coordinate — the service's replies have
        // to route to a *designated* rendezvous (combiner) point that relays them to the client.
        let n = Plane::<F2>::N as usize;
        let combiners: alloc::collections::BTreeSet<Triple> = (0..n)
            .filter_map(|l| combiner_for::<F2>(Line::<F2>::at(l).coords()))
            .collect();
        assert!(!combiners.is_empty());
        assert!(
            combiners.len() < n,
            "not every point is a combiner — replies need a designated rendezvous point"
        );
    }

    #[test]
    fn a_reply_with_an_out_of_range_index_is_rejected() {
        // A share whose x is not a real member index (here x = 200, far beyond the 3 members) must be
        // dropped outright — it can never join the candidate set, so it cannot flood or poison it.
        let line_coord = Line::<F2>::at(2).coords();
        let members = ThresholdRouter::<F2>::line_members(line_coord);
        let t = 2usize;
        // Member 0 (the combiner) is peeled with its forward-secure onion key, so its share seals to that
        // key (audit E4); members 1/2 never reply here, so their sealing keys are arbitrary.
        let onion_seed0 = {
            let mut s = [0x7Cu8; 32];
            s[31] = 0;
            s
        };
        let m0 = OnionKeyRatchet::new(onion_seed0, Epoch::ZERO);
        let (_s1, pub1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7C, 1]));
        let (_s2, pub2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7C, 2]));
        let pubs = [m0.public(), &pub1, &pub2];
        let onion = seal_onion(
            &[HopLine {
                line: line_coord,
                members: &pubs,
            }],
            t as u8,
            b"payload-2",
            b"seed-2",
        )
        .unwrap();
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let (identity0, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"identity-2"));
        let mut router = ThresholdRouter::<F2>::new(combiner, &identity0, t, onion_seed0);
        router.step(
            Instant(0),
            Input::Message {
                from: [1, 1, 1],
                frame: launch_frame(line_coord, &onion),
            },
        );
        // Two out-of-range forgeries (x = 0 and x = 200) and one that would exceed the member count.
        for bad_x in [0u8, 200, 4] {
            let e = router.step(
                Instant(1),
                Input::Message {
                    from: [2, 2, 2],
                    frame: encode_rep(0, &Share::new(bad_x, alloc::vec![0u8; 8])),
                },
            );
            assert!(
                e.is_empty(),
                "an out-of-range share index (x={bad_x}) is dropped"
            );
        }
    }

    #[test]
    fn a_recorded_onion_survives_one_rotation_then_becomes_unpeelable() {
        // E4 end-to-end forward secrecy WITH graceful rotation. An onion sealed to a relay's epoch-0
        // onion key delivers at epoch 0; after ONE rotation it still delivers (the relay's grace window
        // keeps the previous epoch decap-able, so onions in flight across a boundary are not dropped);
        // but once the relay is TWO rotations on, epoch 0 has fallen out of the retain=1 window and the
        // SAME recorded onion can no longer be peeled — a passive adversary that captured it and later
        // compromised the relay decrypts nothing. With t = 1 the combiner peels with its own share.
        let line_coord = Line::<F2>::at(3).coords();
        let members = ThresholdRouter::<F2>::line_members(line_coord);
        let t = 1usize;
        let onion_seed = [0xE4u8; 32];
        let m0 = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_i1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xE4, 1]));
        let (_i2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xE4, 2]));
        let pubs = [m0.public(), &p1, &p2];
        let payload = b"fs-payload";
        let onion = seal_onion(
            &[HopLine {
                line: line_coord,
                members: &pubs,
            }],
            t as u8,
            payload,
            b"fs-seed",
        )
        .unwrap();

        let combiner = Point::<F2>::new(members[0]).unwrap();
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"fs-identity"));
        let mut router = ThresholdRouter::<F2>::new(combiner, &identity, t, onion_seed);
        // Re-inject the SAME recorded onion at time `at` and report whether it was delivered.
        let replay = |router: &mut ThresholdRouter<F2>, at: u64| {
            has_delivery(
                &router.step(
                    Instant(at),
                    Input::Message {
                        from: [9, 9, 9],
                        frame: launch_frame(line_coord, &onion),
                    },
                ),
                payload,
            )
        };

        // Epoch 0: the current-epoch relay peels its own share (t = 1) and delivers.
        assert!(
            replay(&mut router, 0),
            "the current-epoch relay peels a current-epoch onion"
        );

        // One rotation: the epoch-0 key is now in the grace window, so an onion in flight still delivers.
        router.step(Instant(1), Input::Command(Command::AdvanceEpoch));
        assert_eq!(router.onion_epoch(), Epoch::new(1));
        assert!(
            replay(&mut router, 2),
            "an onion in flight across one rotation still peels (grace window)"
        );

        // A second rotation: epoch 0 falls out of the retain=1 window and its secret is gone.
        router.step(Instant(3), Input::Command(Command::AdvanceEpoch));
        assert_eq!(router.onion_epoch(), Epoch::new(2));
        assert!(
            !replay(&mut router, 4),
            "past the grace window the recorded onion is unpeelable (E4 forward secrecy)"
        );
    }

    #[test]
    fn a_nostos_dead_drop_is_multicast_to_the_delivery_lines_members() {
        use crate::nostos::{ReplyKeys, seal_reply};
        // The delivery line L (Fano: 3 members); the receiver R is one of its members, hidden 1-of-3.
        let l = Line::<F2>::at(1).coords();
        let members = ThresholdRouter::<F2>::line_members(l);
        assert_eq!(members.len(), 3);
        let t = 2usize;

        // Member forward-secure onion keys, in points_on (seal) order.
        let onion_seed = |i: u8| {
            let mut s = [0x60u8; 32];
            s[31] = i;
            s
        };
        let m0 = OnionKeyRatchet::new(onion_seed(0), Epoch::ZERO);
        let m1 = OnionKeyRatchet::new(onion_seed(1), Epoch::ZERO);
        let m2 = OnionKeyRatchet::new(onion_seed(2), Epoch::ZERO);
        let pubs = [m0.public(), m1.public(), m2.public()];

        // Seal a NOSTOS reply whose sole (delivery) hop is L.
        let (reply_keys, reply_pub) = ReplyKeys::generate(b"nostos-reply");
        let hops = [HopLine { line: l, members: &pubs }];
        let payload = b"the homecoming";
        let onion = seal_reply(&reply_pub, &hops, t as u8, payload, b"fresh-seed").unwrap();

        // Drive the combiner (member 0) to the dead-drop delivery: onion seeds its share, then member
        // 1's partial reaches t = 2 and it peels.
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"combiner-id"));
        let mut router = ThresholdRouter::<F2>::new(combiner, &identity, t, onion_seed(0));
        router.step(
            Instant(0),
            Input::Message { from: [9, 9, 9], frame: launch_frame(l, &onion) },
        );
        let honest1 = member_partial(&onion, 1, m1.secret()).unwrap();
        let effects = router.step(
            Instant(1),
            Input::Message { from: members[1], frame: encode_rep(0, &honest1) },
        );

        // The combiner did NOT consume the delivery: it handed the body to its own app once (a Notify)
        // and sent a dead-drop cell to each OTHER member — a multicast over all q+1 = 3.
        let notifies: Vec<&[u8]> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Notify(Notification::Delivered { payload, .. }) => Some(payload.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(notifies.len(), 1, "the combiner hands the body to its own app exactly once");
        assert_eq!(
            reply_keys.open(notifies[0]).as_deref(),
            Some(&payload[..]),
            "the end-to-end body the combiner sees opens only with the receiver's reply key",
        );

        let mut drop_dests = Vec::new();
        for e in &effects {
            if let Effect::Send { to, frame } = e {
                let (tag, body) = frame.split_first().unwrap();
                assert_eq!(*tag, TAG_DROP, "a multicast cell is a dead-drop frame");
                let (line, e2e_body) = decode_drop(body).unwrap();
                assert_eq!(line, l, "the cell names the delivery line");
                assert_eq!(
                    reply_keys.open(&e2e_body).as_deref(),
                    Some(&payload[..]),
                    "every member receives the same openable body",
                );
                drop_dests.push(*to);
            }
        }
        drop_dests.sort_unstable();
        let mut expected = alloc::vec![members[1], members[2]];
        expected.sort_unstable();
        assert_eq!(
            drop_dests, expected,
            "the dead-drop is multicast to every other member of L (the combiner keeps its own copy)",
        );
    }

    #[test]
    fn a_dead_drop_cell_delivers_to_a_line_member_and_a_non_member_ignores_it() {
        use crate::nostos::{ReplyKeys, seal_to_receiver};
        let l = Line::<F2>::at(1).coords();
        let line = Line::<F2>::new(l).unwrap();
        let members = ThresholdRouter::<F2>::line_members(l);

        // A dead-drop cell carrying an end-to-end body for the receiver.
        let (reply_keys, reply_pub) = ReplyKeys::generate(b"rk-drop");
        let payload = b"drop me home";
        let e2e = seal_to_receiver(&reply_pub, payload, b"e2e").unwrap();
        let cell = encode_drop(l, &e2e);

        // A router at a member coordinate of L hands the body to its application.
        let (id_r, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"id-r"));
        let mut member = ThresholdRouter::<F2>::new(Point::<F2>::new(members[1]).unwrap(), &id_r, 2, [0x1; 32]);
        let delivered = member.step(
            Instant(0),
            Input::Message { from: [0, 0, 0], frame: cell.clone() },
        );
        let body = match delivered.as_slice() {
            [Effect::Notify(Notification::Delivered { payload, .. })] => payload.clone(),
            _ => panic!("a member delivers the dead-drop body to its app"),
        };
        assert_eq!(
            reply_keys.open(&body).as_deref(),
            Some(&payload[..]),
            "the receiver opens its reply from the delivered body",
        );

        // A router NOT on L ignores the cell entirely.
        let off_line = (0..Plane::<F2>::N as usize)
            .map(Point::<F2>::at)
            .find(|p| !p.is_on(&line))
            .unwrap();
        let (id_x, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"id-x"));
        let mut outsider = ThresholdRouter::<F2>::new(off_line, &id_x, 2, [0x2; 32]);
        assert!(
            outsider
                .step(Instant(0), Input::Message { from: [0, 0, 0], frame: cell })
                .is_empty(),
            "a node not on the line ignores a dead-drop cell addressed to that line",
        );
    }

    #[test]
    fn the_salted_combiner_pick_spreads_over_the_lines_members_and_only_them() {
        // #55: the per-onion salted pick is what turns a hop's availability into the line's own
        // t-of-(q+1) quorum. Three properties carry that: every pick is a member of the line, the
        // picks are not constant across salts (a constant pick is the canonical-combiner SPOF again),
        // and the empty salt IS the canonical combiner (one derivation, not two).
        for idx in 0..Plane::<F2>::N as usize {
            let line = Line::<F2>::at(idx).coords();
            let members = ThresholdRouter::<F2>::line_members(line);
            let mut seen = Vec::new();
            for s in 0..64u8 {
                let pick = combiner_for_salted::<F2>(line, &[s, 0xA5]).unwrap();
                assert!(
                    members.contains(&pick),
                    "a salted pick is always a member of its line"
                );
                if !seen.contains(&pick) {
                    seen.push(pick);
                }
            }
            assert!(
                seen.len() >= 2,
                "64 salts must reach at least two distinct members of line {line:?} — a constant \
                 pick would re-create the per-hop single point of failure"
            );
            assert_eq!(
                combiner_for_salted::<F2>(line, &[]),
                combiner_for::<F2>(line),
                "the empty salt is exactly the canonical combiner — one derivation"
            );
        }
    }

    #[test]
    fn the_gather_deadline_tracks_measured_latency_instead_of_a_constant() {
        // The #14 property: the deadline is a function of what the node OBSERVES, so the same code adapts to
        // a machine where a share answer costs 1 ms and to one where it costs 47 ms — a 45x spread measured
        // between build profiles alone (`tests/gather_cost.rs`), which is why no constant can be correct.
        let mut clock = GatherClock::new();

        // Before any sample there is nothing to derive from, so the bootstrap stands.
        assert_eq!(
            clock.deadline(),
            INITIAL_GATHER_DEADLINE,
            "a cold node uses the bootstrap deadline, not a measurement it does not have"
        );

        // A fast cell: gathers complete in ~2 ms. The deadline must settle FAR below the old 2 s constant —
        // that constant's real cost was believing a dead hop for a thousand round trips.
        for _ in 0..40 {
            clock.observe(Duration::from_millis(2));
        }
        let fast = clock.deadline();
        assert!(
            fast < Duration::from_millis(50),
            "after 40 samples of 2 ms the deadline settles near the observation, not at 2000 ms: {fast:?}"
        );

        // The same code on a loaded/slow cell: gathers take ~800 ms. The deadline must rise ABOVE the old
        // constant's usable margin rather than abandoning honest hops — the failure #55 measured.
        let mut slow = GatherClock::new();
        for _ in 0..40 {
            slow.observe(Duration::from_millis(800));
        }
        let slow_deadline = slow.deadline();
        assert!(
            slow_deadline > Duration::from_millis(700),
            "a cell whose gathers take 800 ms must wait for them: {slow_deadline:?}"
        );
        assert!(
            slow_deadline > fast,
            "the deadline is a function of observed latency — slow cell {slow_deadline:?} must exceed fast              cell {fast:?}, which a constant could never do"
        );

        // Variance widens the margin: the same MEAN with jitter must yield a strictly larger deadline than
        // without, or a deadline would abandon the slow half of a bimodal cell.
        let mut steady = GatherClock::new();
        let mut jittery = GatherClock::new();
        for i in 0..40 {
            steady.observe(Duration::from_millis(100));
            jittery.observe(Duration::from_millis(if i % 2 == 0 { 20 } else { 180 }));
        }
        assert!(
            jittery.deadline() > steady.deadline(),
            "jitter must widen the margin: jittery {:?} vs steady {:?}",
            jittery.deadline(),
            steady.deadline()
        );

        // And it is bounded at both ends, so neither a pathological run of instant gathers nor an adversary
        // answering ever more slowly can drive it to zero or to forever.
        let mut instant = GatherClock::new();
        for _ in 0..40 {
            instant.observe(Duration(0));
        }
        assert_eq!(instant.deadline(), MIN_GATHER_DEADLINE, "floored");
        let mut forever = GatherClock::new();
        for _ in 0..40 {
            forever.observe(Duration::from_millis(600_000));
        }
        assert_eq!(forever.deadline(), MAX_GATHER_DEADLINE, "capped");
    }

    #[test]
    fn an_expiring_gather_backs_off_so_a_too_tight_estimate_can_recover() {
        // **The half of RFC 6298 that smoothing alone does not give**, and the one a real test caught
        // missing: an estimator fed only by COMPLETIONS converges to a quiet period's mean and then holds
        // no margin. When load arrives its gathers expire — and an expiry yields no sample, so nothing
        // ever tells it that it is now too tight. It expires at the same short deadline forever.
        //
        // Measured before this existed: fanos-sim's role-convergence test passed 2/2 at baseline and
        // failed 2/4 with a backoff-less adaptive deadline, because starved hops starved the capability
        // directory the role controller reads. That is the failure mode this asserts against.
        let mut clock = GatherClock::new();
        for _ in 0..40 {
            clock.observe(Duration::from_millis(2));
        }
        let settled = clock.deadline();

        // Each expiry must WIDEN the deadline — strictly, and monotonically.
        let mut prev = settled;
        for _ in 0..4 {
            clock.expired();
            let widened = clock.deadline();
            assert!(
                widened > prev,
                "every expiry must widen the deadline: {widened:?} did not exceed {prev:?}"
            );
            prev = widened;
        }
        assert!(
            prev.as_nanos() >= settled.as_nanos().saturating_mul(8),
            "four doublings must reach at least 8x the settled estimate: {prev:?} vs {settled:?}"
        );

        // A completed gather clears the backoff — the estimate is trusted again, so the deadline returns
        // to tracking observation rather than staying permanently inflated by one bad patch of load.
        clock.observe(Duration::from_millis(2));
        assert!(
            clock.deadline() < prev,
            "a completed gather must clear the backoff, not leave the deadline inflated forever"
        );

        // And the backoff is bounded, so a node under sustained failure cannot inflate without limit.
        let mut runaway = GatherClock::new();
        for _ in 0..40 {
            runaway.observe(Duration::from_millis(50));
        }
        for _ in 0..64 {
            runaway.expired();
        }
        assert_eq!(runaway.deadline(), MAX_GATHER_DEADLINE, "backoff is capped by the ceiling");
    }

    #[test]
    fn pending_gathers_are_bounded_by_count_so_memory_never_rides_on_the_deadline() {
        // Making the deadline measured (and therefore free to grow) is only safe because `pending` stopped
        // depending on it. Previously the timeout was the ONLY bound on the map — which quietly made a
        // timing value a memory-safety parameter, so fixing liveness by lengthening it would have traded one
        // defect for another.
        let line = Line::<F2>::at(0).coords();
        let members = ThresholdRouter::<F2>::line_members(line);
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"bounded-pending"));
        let mut router =
            ThresholdRouter::<F2>::new(Point::<F2>::new(members[0]).unwrap(), &identity, 2, [0x3B; 32]);

        // Flood distinct onions with NO timer ever firing — the deadline cannot be what saves us here.
        for i in 0..(MAX_PENDING + 128) {
            let mut onion = alloc::vec![0u8; threshold::THRESHOLD_ONION_LEN];
            onion[..8].copy_from_slice(&(i as u64).to_be_bytes());
            router.step(
                Instant(i as u64),
                Input::Message { from: [9, 9, 9], frame: launch_frame(line, &onion) },
            );
        }
        assert!(
            router.pending.len() <= MAX_PENDING,
            "in-flight gathers are capped at {MAX_PENDING}, got {} — with no timer fired",
            router.pending.len()
        );
    }

    #[test]
    fn the_salted_pick_reduces_wide_entropy_so_its_modulo_bias_is_negligible() {
        // The availability bound in `combiner_of_salted`'s doc is a UNIFORMITY statement, and uniformity
        // here is decided by ONE parameter: how many digest bits the modulus reduces. Reducing `k` bits by
        // `m = q + 1` biases the low residues by `(2^k mod m) / 2^k`. At `k = 8` that is 1.2 % on Fano and
        // **12.9 % at `q = 32`**, growing with the plane; at `k = 64` it is `≈ m·2⁻⁶⁴`. A member favoured by
        // the reduction is a member an adversary prefers to silence, so the width is a security parameter.
        //
        // **The test is exact rather than statistical, and that is the point.** The first version of this
        // test sampled 6000 draws and asserted a ±5 % band — and it PASSED against the single-byte
        // reduction it was written to catch, because Fano's 1.2 % bias is smaller than both the band and
        // the sampling noise (σ/µ ≈ 1.8 %). Detecting a 1.2 % bias by sampling needs ~10⁵ draws to clear
        // noise and is still marginal. So assert the cause, not the symptom: exhibit two salts whose
        // digests agree on byte 0 yet pick DIFFERENT members. Under `digest[0] % m` that is impossible by
        // construction; under a wide reduction it is ordinary. One counterexample settles it, with no
        // threshold to tune and nothing to go flaky.
        let line = Line::<F2>::at(0).coords();
        let salt_digest = |s: u64| {
            let [a, b, c] = line;
            let mut data = Vec::new();
            data.extend_from_slice(&a.to_be_bytes());
            data.extend_from_slice(&b.to_be_bytes());
            data.extend_from_slice(&c.to_be_bytes());
            data.extend_from_slice(&s.to_be_bytes());
            fanos_primitives::hash_labeled("FANOS-v1/threshold-combiner", &data)
        };
        let mut by_first_byte: BTreeMap<u8, (u64, Triple)> = BTreeMap::new();
        let mut witness = None;
        for s in 0..4_000u64 {
            let first = salt_digest(s)[0];
            let pick = combiner_for_salted::<F2>(line, &s.to_be_bytes()).unwrap();
            match by_first_byte.get(&first) {
                Some(&(prev_s, prev_pick)) if prev_pick != pick => {
                    witness = Some((prev_s, s, first));
                    break;
                }
                Some(_) => {}
                None => {
                    by_first_byte.insert(first, (s, pick));
                }
            }
        }
        assert!(
            witness.is_some(),
            "no two salts sharing digest byte 0 picked different members — the reduction consumes only \
             that byte, so its modulo bias is 2^8-wide (1.2 % on Fano, 12.9 % at q = 32) rather than \
             2^64-wide, and some member is systematically the one to silence"
        );

        // With the width established, a coarse spread check catches a gross skew the width test cannot
        // (e.g. a reduction that is wide but constant-folded): no member takes more than half the draws.
        let members = ThresholdRouter::<F2>::line_members(line);
        let mut counts = alloc::vec![0usize; members.len()];
        for s in 0..3_000u64 {
            let pick = combiner_for_salted::<F2>(line, &s.to_be_bytes()).unwrap();
            counts[members.iter().position(|&m| m == pick).unwrap()] += 1;
        }
        assert!(
            counts.iter().all(|&c| c * 2 < 3_000),
            "no member may take half the draws of a {}-member line: {counts:?}",
            members.len()
        );
    }

    #[test]
    fn an_onion_addressed_at_a_non_canonical_member_peels_there() {
        // #55: nothing in the gather is combiner-specific, so ANY member a salted launch lands on
        // must run it to completion. Drive a NON-canonical member of the delivery line through the
        // whole peel: it seeds its own share, folds one honest partial, and multicasts the dead-drop
        // — exactly what the canonical combiner would have done.
        use crate::nostos::{ReplyKeys, seal_reply};
        let l = Line::<F2>::at(1).coords();
        let members = ThresholdRouter::<F2>::line_members(l);
        let t = 2usize;
        let canonical = ThresholdRouter::<F2>::combiner_of(l).unwrap();
        let (alt_idx, alt) = members
            .iter()
            .enumerate()
            .find(|(_, m)| **m != canonical)
            .expect("a 3-member line has a non-canonical member");

        let onion_seed = |i: u8| {
            let mut s = [0x61u8; 32];
            s[31] = i;
            s
        };
        let ratchets: Vec<OnionKeyRatchet> =
            (0..3).map(|i| OnionKeyRatchet::new(onion_seed(i), Epoch::ZERO)).collect();
        let pubs = [ratchets[0].public(), ratchets[1].public(), ratchets[2].public()];

        let (reply_keys, reply_pub) = ReplyKeys::generate(b"nostos-alt-member");
        let payload = b"homecoming via any member";
        let onion =
            seal_reply(&reply_pub, &[HopLine { line: l, members: &pubs }], t as u8, payload, b"alt-seed")
                .unwrap();

        // The salted launch lands at `alt`, which gathers: its own share plus one honest partial.
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"alt-id"));
        let mut router = ThresholdRouter::<F2>::new(
            Point::<F2>::new(*alt).unwrap(),
            &identity,
            t,
            onion_seed(alt_idx as u8),
        );
        router.step(Instant(0), Input::Message { from: [9, 9, 9], frame: launch_frame(l, &onion) });
        let other_idx = (0..3).find(|&i| i != alt_idx).unwrap();
        let honest = member_partial(&onion, other_idx, ratchets[other_idx].secret()).unwrap();
        let effects = router.step(
            Instant(1),
            Input::Message { from: members[other_idx], frame: encode_rep(0, &honest) },
        );

        let delivered = effects.iter().any(|e| {
            matches!(e, Effect::Notify(Notification::Delivered { payload: p, .. })
                if reply_keys.open(p).as_deref() == Some(&payload[..]))
        });
        let multicast = effects
            .iter()
            .filter(|e| matches!(e, Effect::Send { frame, .. } if frame.first() == Some(&TAG_DROP)))
            .count();
        assert!(delivered, "the non-canonical member completes the peel and surfaces the body");
        assert_eq!(multicast, 2, "and multicasts the dead-drop to the other q members");
    }
}
