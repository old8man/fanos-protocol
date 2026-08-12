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
use fanos_ports::{
    Command, Duration, Effect, Engine, GatherClock, Input, Instant, Notification, TimerToken,
};
use fanos_ports::stations::{GatherHealth, Observation, Station, Stations};
use fanos_wire::activation::Derivation;

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

/// What the threshold router may hold in pending gathers, across every gather at once.
///
/// The value is unchanged from the bare literal it replaces. It is named here because a budget that is not
/// a constant cannot be summed with its neighbours, and #213 is about the fact that nobody had summed them:
/// this 64 MiB, `fanos_diaulos::budget::SESSION_MEMORY_BUDGET`'s 64 MiB and `fanos_runtime`'s
/// `STORE_MEMORY_BUDGET` of 128 MiB were each chosen as "a share of the 256 MiB node", by three authors who
/// could not see each other, and they sum to the whole recommendation before the process's own resident set.
const GATHER_MEMORY_BUDGET: usize = fanos_primitives::budget::GATHER_SHARE;

/// What **one** pending gather costs at its worst, in bytes the wire supplied.
///
/// Both terms are now enforced widths rather than assumed ones (#218):
/// * the onion is [`THRESHOLD_ONION_LEN`](threshold::THRESHOLD_ONION_LEN), checked by [`decode_onion`];
/// * the candidate shares are [`MAX_CANDIDATES`] × [`SHARE_LEN`](fanos_threshold::SHARE_LEN), checked by
///   [`decode_rep`].
///
/// **The second term is the one this constant exists to add.** `MAX_PENDING`'s previous doc said each entry
/// holds "one `THRESHOLD_ONION_LEN` onion **plus its shares**" and then divided by the onion alone — the
/// prose named the term and the arithmetic dropped it, which is [`GATHER_MEMORY_BUDGET`]'s own defect one
/// level in. With the shares unbounded the omission was not a rounding error: 64 frames were measured
/// leaving 62 MiB in a single gather.
const PENDING_ENTRY_BYTES: usize =
    threshold::THRESHOLD_ONION_LEN + MAX_CANDIDATES * fanos_threshold::SHARE_LEN;

/// Cap on concurrently-pending gathers, so **memory is bounded by count rather than by the deadline**.
///
/// This is what makes the deadline free to be measured. Previously the only bound on `pending` was the
/// timeout — every gather sat in a `BTreeMap` until its deadline fired — which quietly made the timing
/// constant a *memory-safety* parameter, so lengthening it to fix liveness would have traded one defect for
/// another. At the cap the oldest incomplete gather is dropped — correct here, unlike the eviction hazard a
/// keyed cache has, because the oldest gather is precisely the one most likely already dead, and its client
/// retransmits.
///
/// It is what the budget buys at the true per-entry cost, so it is not a round number and should not be
/// made one — the same discipline `fanos_diaulos::budget::MAX_SESSIONS` states.
const MAX_PENDING: usize = GATHER_MEMORY_BUDGET / PENDING_ENTRY_BYTES;

/// The product the budget was never checked against, now checked by the compiler.
///
/// The assertion whose absence *was* the defect: `MAX_PENDING` divided by one of the two terms it needed to
/// divide by, and nothing multiplied the result back out.
const _: () = assert!(
    MAX_PENDING * PENDING_ENTRY_BYTES <= GATHER_MEMORY_BUDGET,
    "the pending gathers' worst case exceeds GATHER_MEMORY_BUDGET — raise the budget deliberately or lower a factor"
);

/// [`MAX_PENDING`] is the **largest** count the budget buys, not merely a count that fits — without this the
/// assertion above is satisfied by any small number and neither says the count was derived.
const _: () = assert!(
    (MAX_PENDING + 1) * PENDING_ENTRY_BYTES > GATHER_MEMORY_BUDGET,
    "MAX_PENDING is below what the budget buys, so it was chosen rather than derived"
);

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

/// How many recently-resolved gathers are remembered, purely so a late share can be attributed.
///
/// A share that arrives for a gather no longer pending is one of three things — the gather **peeled** and
/// this is the expected remainder, it **expired** and the deadline was too tight, or it is foreign — and
/// those call for opposite responses. Without this ring they are one number, which is why the largest
/// counter on every node was arithmetic. `q + 1 − t` late shares follow each completion, so remembering a
/// few hundred outcomes covers the window in which they can still arrive; older ones fall out and are
/// attributed as unknown, which is the honest answer once the evidence is gone.
const MAX_RESOLVED: usize = 512;

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

/// How a gather ended, remembered just long enough to attribute the shares still in flight behind it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Resolved {
    /// A subset peeled and the hop went on — later shares are the expected `q + 1 − t` remainder.
    Peeled,
    /// The deadline fired first, at the instant the gather was armed — a later share is evidence the
    /// deadline was too tight, not that the line was silent, and `armed_at` is what turns that evidence
    /// into a measurement the estimator can use ([`GatherClock::observe_late`]).
    Expired { armed_at: Instant },
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
    /// The data-path plane's counters ([`Stations`], `docs/design-observability.md`). A threshold gather
    /// is where work most often stops, and #55 measured what that costs when it is invisible: gathers
    /// expiring at `1` of `t = 2` **by the hundreds per run** were found only by hand-inserted probes,
    /// after eleven other hypotheses had been eliminated one at a time. Local-only, keyed by structure.
    stations: Stations,
    /// An explicit override, for a driver that must pin the deadline (a deterministic scenario asserting a
    /// specific expiry). `None` — the default — uses the measured value.
    gather_override: Option<Duration>,
    pending: BTreeMap<u64, Pending>,
    /// Recently-resolved request ids and how they ended, oldest first ([`MAX_RESOLVED`]).
    resolved: VecDeque<(u64, Resolved)>,
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

/// What the router's **send-side queues** may hold — see [`THRESHOLD_ROUTER_SHARE`] for why one share
/// covers both of them.
///
/// [`THRESHOLD_ROUTER_SHARE`]: fanos_primitives::budget::THRESHOLD_ROUTER_SHARE
const ROUTER_QUEUE_MEMORY_BUDGET: usize = fanos_primitives::budget::THRESHOLD_ROUTER_SHARE;

/// What **one** queued forward costs, in the bytes the queue actually holds.
///
/// Not `THRESHOLD_ONION_LEN`. What is pushed is `encode_onion(next, &padded)` — a tag byte, an encoded
/// triple, then the padded onion — beside the destination `Triple` in the tuple. The previous bound divided
/// a budget nobody had written down by the onion alone, which is [`MAX_PENDING`]'s own defect (#218) one
/// queue over: **the prose named the frame and the arithmetic counted the payload.**
///
/// The correction moves the derived count from 2048 to 2045 — three cells stricter, which is the safe
/// direction and the reason it is worth stating rather than rounding away.
const QUEUED_CELL_BYTES: usize =
    1 + 12 + threshold::THRESHOLD_ONION_LEN + size_of::<Triple>();

/// Bound on the constant-rate [`outbox`](ThresholdRouter::outbox): real forwards queued for a send slot.
/// Beyond this the **oldest** is dropped — correct here because the reliability layer retransmits and this
/// queue is a rate smoother, not a mixer. The drop is counted ([`Station::RelayCargoDropped`]).
///
/// It is what the budget buys at the true per-entry cost, so it is not a round number and should not be
/// made one — the discipline [`MAX_PENDING`] and `fanos_diaulos::budget::MAX_SESSIONS` both state.
///
/// **The relay's throughput ceiling lives here, and had never been written down.** A real forward *displaces*
/// a cover slot rather than adding a send, and there is one slot stream per router, so the sustained rate a
/// Full-profile relay can carry is `1 / cover_interval` — ≈2 cells/s ≈ 40 KiB/s at the shipping 500 ms
/// default, for the **whole node**, not per circuit. Offered `λ`, this queue fills in `MAX_OUTBOX / (λ − 2)`
/// seconds and cargo is shed from then on. That figure is also what #135 left open for the `Relay` role: its
/// capacity is a derived protocol bound, not a measurement waiting to be taken.
const MAX_OUTBOX: usize = ROUTER_QUEUE_MEMORY_BUDGET / QUEUED_CELL_BYTES;

/// Bound on [`mix_pending`](ThresholdRouter::mix_pending) — the cover-**off** queue, which had none (#295).
///
/// Same share, same per-entry cost, therefore the same count: the two queues cannot fill together.
///
/// **The overflow rule is the opposite of its sibling's, and derived rather than copied.** The outbox evicts
/// the oldest; here the oldest entry is the one whose exponential delay is closest to firing, so evicting it
/// would throw away the wait already served *and* thin the batch a cell is being hidden in — the mix's whole
/// product. So a full queue refuses the **newest** arrival, protecting what is already in flight, and counts
/// the refusal ([`Station::RelayMixRefused`]).
///
/// Steady state is `λ × mean_delay` by Little's law, so at the shipping 120 ms mean this cap is reached at
/// roughly `λ = 17 000 /s` — far above any honest relay and reachable by a flood, which is what it is for.
/// Each entry also holds a live timer, so the bound caps two resources, not one.
const MAX_MIX_PENDING: usize = ROUTER_QUEUE_MEMORY_BUDGET / QUEUED_CELL_BYTES;

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
            stations: Stations::new(),
            resolved: VecDeque::new(),
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

    /// Record an unparseable frame and discard it — the one place a decode failure is counted, so the
    /// skew signal cannot be half-instrumented by a later arm being added without one.
    fn undecodable(&mut self) -> Vec<Effect> {
        self.stations.record(Station::FrameDecodeFailed, None);
        Vec::new()
    }


    /// This router's data-path counters for the current window — **local-only** (`stations` R4: nothing
    /// crosses a node boundary until per-family DP sensitivities are derived the way `Δr = 1/21` was).
    #[must_use]
    pub const fn stations(&self) -> &Stations {
        &self.stations
    }

    /// Take and clear this window's data-path observations — read-and-clear in one step, so a count is
    /// neither double-read nor lost between a read and a clear.
    pub fn take_stations(&mut self) -> Vec<Observation> {
        self.stations.take()
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
    ///
    /// **No shipped composition calls this, and the reason is architectural rather than an oversight.** The
    /// check needs a verifier that already holds the circuit, and in NOSTOS no such party is present at
    /// delivery: return hops are drawn freshly rather than derived from a shared secret (a predictable
    /// circuit is a targetable one), a service host never agreed the client's forward circuit, and a client's
    /// reply arrives as a geometric dead-drop opened by its end-to-end key — not through a router at all.
    /// Spec §5.4's "both endpoints, knowing the algebraic description of the path" is §5.6's derived-meeting
    /// model, which NOSTOS replaced. Delivery integrity on the shipped path is therefore the end-to-end AEAD,
    /// asserted directly in `nostos::a_reply_comes_home_and_only_the_receiver_opens_it`.
    ///
    /// Kept, not deleted: it is correct and proven, and an authenticated-rendezvous mode where both parties
    /// derive the circuit from a shared secret would have exactly the verifier it wants. Left unwired and
    /// **said so here**, because a security check that reads as enforced and is not is worse than none.
    #[must_use]
    pub fn with_delivery_check(mut self, hop_lines: Vec<Triple>, seed: Vec<u8>) -> Self {
        self.delivery_check = Some((hop_lines, seed));
        self
    }

    /// Enable Poisson mixing **for a router with cover off**: hold each forwarded hop for an exponential
    /// delay of mean `mean_delay` before sending, so a batch of onions leaves reordered (spec §L5, V7).
    /// Zero disables it.
    ///
    /// **With [`with_cover`](Self::with_cover) set, this value is not read at all** — `forward_send` queues
    /// the cell for the next constant-rate slot and returns before it reaches the delay, and the batch is
    /// reordered by the slot's PRF pick instead. The two are alternatives, not layers. Saying so here because
    /// `forward_send`'s doc said it and this one did not, and a builder is where a caller looks (#181).
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
            if let Some(combiner) = self.gather_member(line, &cell) {
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
                // Shedding real cargo, past the relay's `1 / cover_interval` ceiling. Counted, because an
                // operator whose relay is discarding traffic must not be the last to know (#294).
                self.outbox.pop_front();
                self.stations.record(Station::RelayCargoDropped, Some(to));
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
        if self.mix_pending.len() >= MAX_MIX_PENDING {
            // Refuse the newest rather than evict the oldest — see `MAX_MIX_PENDING`. No timer is armed, so
            // the cap bounds live timers as well as bytes (#295).
            self.stations.record(Station::RelayMixRefused, Some(to));
            return Vec::new();
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

    /// The member of `line` that gathers an onion whose body is `salt` — **through the activation registry**.
    ///
    /// This is the one place the gatherer is chosen, and it consults
    /// [`Derivation::OnionGatherMember`](fanos_wire::activation::Derivation::OnionGatherMember) rather than
    /// hard-coding the current form. At its registered height of `0` the answer is always the salted draw, so
    /// nothing changes today — and that is the point: the registry was built for the *next* derivation change
    /// and had no production caller, which is the shape that lets a mechanism rot until the release that needs
    /// it discovers it was never wired. A derivation switch that no code consults is a schedule nobody keeps.
    ///
    /// The epoch is the router's own onion epoch, which the beacon drives — so every member of a line reads the
    /// same height at the same time, which is what makes a scheduled switch a switch rather than a split.
    fn gather_member(&self, line: Triple, salt: &[u8]) -> Option<Triple> {
        if Derivation::OnionGatherMember.is_active_at(self.onion_epoch().get()) {
            Self::combiner_of_salted(line, salt)
        } else {
            // The pre-#55 canonical pick: one member per line. Unreachable at height 0 and kept because a
            // registry whose old form is deleted cannot serve a node that has not reached the height (§3.1).
            Self::combiner_of(line)
        }
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
        // Seed our own partial. Failing to is NOT nothing: a line's spare capacity is `q + 1 − t`, exactly 1
        // at `q = 2`, so a gather that starts one short has none left and needs every remaining member to
        // answer — a routine loss then becomes an expiry, and until this counter existed nothing said why.
        match self.my_index(line) {
            None => {} // not a member of this line: there is no own share to seed, and that is not a fault
            Some(i) => match self.onion.secrets().find_map(|sk| threshold::member_partial::<F>(&onion, i, sk)) {
                Some(share) => shares.push(share),
                None => self.stations.record(Station::GatherSelfShareMissing, Some(line)),
            },
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
            let evicted = self.pending.remove(&oldest);
            // Capacity pressure, NOT a slow line — a different world, so a different station.
            self.stations.record(Station::GatherEvicted, evicted.map(|p| p.line));
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
    fn on_request(&mut self, req_id: u64, combiner: Triple, line: Triple, onion: &[u8]) -> Vec<Effect> {
        let Some(i) = self.my_index(line) else {
            // A share request for a line this node is not on — the answer to "why does that gather
            // never reach quorum": its combiner is asking members that cannot serve it.
            self.stations.record(Station::ShareRequestNotAMember, Some(line));
            return Vec::new();
        };
        let Some(share) = self
            .onion
            .secrets()
            .find_map(|sk| threshold::member_partial::<F>(onion, i, sk))
        else {
            // A member of the line that cannot compute its own share: the layer was sealed to a key
            // this node no longer holds — **epoch/key skew between members**, otherwise invisible, and
            // exactly the per-line signal an upgrade needs (docs/design-upgrade.md §4).
            self.stations.record(Station::SharePartialFailed, Some(line));
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
            // Already peeled, past its deadline, or foreign — three worlds this used to sum into one, which
            // is how the largest counter on every node came to be arithmetic. `Peeled` is the expected
            // `q + 1 − t` remainder behind every completion; `Expired` says the line DID answer and the
            // deadline was too tight, which is the opposite reading of a gather expiry taken alone; unknown
            // is what is left once the ring has forgotten, and it is the only one that is evidence of
            // nothing in particular.
            let station = match self.resolved.iter().find(|(id, _)| *id == req_id).map(|(_, r)| *r) {
                Some(Resolved::Peeled) => Station::ShareLateAfterPeel,
                Some(Resolved::Expired { armed_at }) => {
                    // The sample the estimator could not otherwise see. `observe` is fed only by gathers
                    // that finished INSIDE the deadline, so its sample set is truncated at the very
                    // quantity it predicts and can never learn that the deadline is short. This one is a
                    // real, unambiguous measurement of a real round trip — it just arrived late.
                    self.gather.observe_late(now.since(armed_at));
                    Station::ShareAfterDeadline
                }
                None => Station::ShareForUnknownRequest,
            };
            self.stations.record(station, None);
            return Vec::new();
        };
        // Reject any share whose index is not a real member of this line (valid Shamir x is
        // `1..=member_count`). This caps distinct pollution to the true membership and drops
        // garbage-index forgeries outright, so an attacker cannot balloon the candidate set with
        // arbitrary `x` values.
        if share.x() == 0 || usize::from(share.x()) > pending.member_count {
            // A **forged** share: no honest member could produce this index. Distinguishable from
            // noise by construction, so this station is an attack indicator rather than an error rate.
            let line = pending.line;
            self.stations.record(Station::ShareIndexOutOfRange, Some(line));
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
            // Flood cap — a real line never needs this many candidates, so reaching it is an attack on
            // the gather's memory rather than a busy epoch.
            let line = pending.line;
            self.stations.record(Station::ShareFloodCapped, Some(line));
            return Vec::new();
        }
        pending.shares.push(share);
        self.try_peel(now, req_id).unwrap_or_default()
    }

    /// Remember how a gather ended, evicting the oldest past [`MAX_RESOLVED`].
    ///
    /// Bounded by COUNT and not by time, for the same reason `pending` is: memory must not depend on a
    /// deadline that is measured and free to grow.
    fn remember_resolved(&mut self, req_id: u64, how: Resolved) {
        if self.resolved.len() >= MAX_RESOLVED {
            self.resolved.pop_front();
        }
        self.resolved.push_back((req_id, how));
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
        let peel = peel_best_subset::<F>(&pending.onion, &pending.shares, self.threshold)?;
        self.pending.remove(&req_id); // the hop is resolved — evict the in-flight state
        self.remember_resolved(req_id, Resolved::Peeled);
        // One completed gather is one latency sample, and it contains `RTT + C_partial + Q` together —
        // measured under exactly the load the next gather will meet. This is what replaces the constant.
        self.gather.observe(now.since(armed_at));
        self.stations.record(Station::GatherCompleted, Some(line));
        Some(match peel {
            ThresholdPeel::Deliver { payload, holonomy } => {
                // If we own this circuit's endpoint, verify the path-authenticator and drop a delivery
                // that traversed a different circuit than agreed (spec §5.4, S1-M1). A transit relay has
                // no `delivery_check` and delivers unverified — it cannot know the circuit.
                if let Some((lines, seed)) = &self.delivery_check
                    && threshold::verify_delivery(lines, seed, holonomy).is_err()
                {
                    // S1-M1 firing: a delivery that traversed a different circuit than agreed. Silent
                    // by design on the wire (an attacker learns nothing), which is exactly why it must
                    // not also be silent to the operator.
                    self.stations.record(Station::HolonomyRejected, Some(line));
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
                // `pad` fails only on an onion already longer than the bucket, and a peeled inner onion is
                // strictly shorter than the received one — which arrived at exactly `THRESHOLD_ONION_LEN` or
                // `Packet::from_bytes` would have refused it. So this is unreachable, and the fallback is safe
                // for a second reason worth stating rather than trusting: an unpadded forward would be a frame
                // the NEXT hop drops, because `from_bytes` requires the exact bucket length. The property
                // degrades to a lost packet, never to a short one on the wire carrying the remaining depth.
                let padded = threshold::pad(&onion).unwrap_or(onion);
                match self.gather_member(next, &padded) {
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
            .filter_map(|member| {
                if member == me {
                    return Some(Effect::Notify(Notification::Delivered {
                        from: ANONYMOUS,
                        payload: e2e.to_vec(),
                    }));
                }
                // `encode_drop` refuses a body too wide for the bucket, and that cannot happen here:
                // `e2e` arrived inside an onion of exactly `THRESHOLD_ONION_LEN` (`Packet::from_bytes`
                // rejects any other width), so it is strictly shorter than the room a cell leaves. Stated
                // rather than trusted, and the fallback is a *skipped member* rather than a short frame —
                // a narrow cell on the wire would be precisely the distinguisher the padding removes, so
                // the property degrades to a lost delivery and never to a leaking one.
                encode_drop(line, e2e).map(|frame| Effect::Send { to: member, frame })
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
fn peel_best_subset<F: Field>(onion: &[u8], shares: &[Share], threshold: usize) -> Option<ThresholdPeel> {
    if threshold == 0 || shares.len() < threshold {
        return None;
    }
    let mut chosen: Vec<usize> = Vec::with_capacity(threshold);
    let mut attempts = 0usize;
    peel_search::<F>(onion, shares, threshold, 0, &mut chosen, &mut attempts)
}

/// Recursive helper for [`peel_best_subset`]: extend `chosen` with distinct-`x` share indices until it
/// reaches `threshold`, trying a peel at each complete subset.
fn peel_search<F: Field>(
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
        return threshold::peel_onion_with_shares::<F>(onion, &subset).ok();
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
        if let Some(peel) = peel_search::<F>(onion, shares, threshold, i + 1, chosen, attempts) {
            return Some(peel);
        }
        chosen.pop();
    }
    None
}

impl<F: Field> Engine for ThresholdRouter<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // Every `None` arm below is a frame this node could not parse. Counted, they are the
            // **derivation-skew detector** `docs/design-upgrade.md` §4 requires: a member running a
            // different wire or derivation version does not error loudly — it emits a well-formed frame
            // to a valid coordinate that simply never peels — so an upgrade is not a controlled
            // operation until this signal exists. An unparseable frame has no readable line, so these
            // are unattributed by construction (`None`), which the station type keeps distinct from a
            // line's own count.
            Input::Message { frame, .. } => match frame.split_first() {
                Some((&TAG_ONION, body)) => match decode_onion(body) {
                    Some((line, onion)) => self.on_onion(now, line, onion),
                    None => self.undecodable(),
                },
                Some((&TAG_REQ, body)) => match decode_req(body) {
                    Some((req_id, combiner, line, onion)) => {
                        self.on_request(req_id, combiner, line, onion)
                    }
                    None => self.undecodable(),
                },
                Some((&TAG_REP, body)) => match decode_rep(body) {
                    Some((req_id, share)) => self.on_reply(now, req_id, share),
                    None => self.undecodable(),
                },
                Some((&TAG_DROP, body)) => match decode_drop(body) {
                    Some((line, e2e)) => self.on_drop(line, e2e),
                    None => self.undecodable(),
                },
                // An unknown or absent tag: also skew, and also unattributable.
                _ => self.undecodable(),
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
                    if let Some(dead) = self.pending.remove(&token) {
                        self.gather.expired();
                        // THE station: the hop is discarded entire, and how many shares it had reached is
                        // the difference between "the line is slow" and "the line is dead". So record which
                        // — the previous single counter named that distinction in its own doc comment and
                        // then did not make it, leaving an absent member and a wrong answer summed together
                        // when they call for opposite responses.
                        //
                        // Below threshold: the line did not answer. At or above: it answered and no subset
                        // of its answers peeled, which on a line with one spare member (`q + 1 − t = 1` at
                        // `q = 2`) means the single candidate subset failed.
                        let station = if dead.shares.len() < self.threshold {
                            Station::GatherExpired
                        } else {
                            Station::GatherUnpeelable
                        };
                        self.stations.record(station, Some(dead.line));
                        self.remember_resolved(token, Resolved::Expired { armed_at: dead.armed_at });
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
            // The sense-only read: the engine that owns the counters and the clock answers for them, so any
            // composite that routes `Observe` here exports them without knowing what they are.
            Input::Command(Command::Observe) => alloc::vec![Effect::Notify(Notification::DataPath {
                stations: self.stations.observations(),
                gather: GatherHealth::of(&self.gather),
            })],
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

/// Decode a launch frame. **Fail-closed on width**, the same rule [`decode_drop`] states and for the same
/// two reasons (#218).
///
/// A threshold onion is [`THRESHOLD_ONION_LEN`](threshold::THRESHOLD_ONION_LEN) on **every** plane —
/// `slots::Packet` is a fixed-slot layout whose total is that constant by construction, which is what makes
/// the plane order "invisible from length alone" (`slots`, the module doc). This decoder read `body[12..]`,
/// everything, and handed the result to [`ThresholdRouter::on_onion`], which retains it in `Pending::onion`
/// for the gather's whole lifetime.
///
/// So the width the protocol guarantees was never checked at the one place it arrives from a stranger, and
/// [`MAX_PENDING`] — `budget / THRESHOLD_ONION_LEN` — was dividing by a length nothing enforced.
fn decode_onion(body: &[u8]) -> Option<(Triple, Vec<u8>)> {
    let line = fanos_geometry::decode_triple(body.get(..12)?)?;
    let onion = body.get(12..)?;
    if onion.len() != threshold::THRESHOLD_ONION_LEN {
        return None;
    }
    Some((line, onion.to_vec()))
}

/// A NOSTOS dead-drop cell: `TAG ‖ line(12) ‖ [len(4 BE) ‖ body ‖ filler]`, where the bracketed region is
/// **exactly [`THRESHOLD_ONION_LEN`]**.
///
/// ## The cell used to be the one payload-bearing frame on the anonymous path that was not constant-width
///
/// `ThresholdPeel::Forward` re-pads every onion it relays, with the reason stated at the site — *"so the
/// forwarded packet is the same size as the one we received — no cross-hop size correlation"*. The delivery
/// arm ten lines below it sent the raw end-to-end body. Since `e2e = seal_to_receiver(..)` is
/// `const(KEM) + len(payload) + const(tag)`, the cell's length **was** the reply's plaintext length — visible
/// to every member of the line, and the same length leaving one coordinate `q + 1` times at once, a pattern
/// nothing else on the network produces.
///
/// The transport shaper does not cover this and must not be relied on: `ShapingProfile::pad_to_target` only
/// pads *up* to a random target in `[size_floor, size_ceil]` and never buckets a larger frame down, and
/// `ProteusShaper::shape` returns immediately for `Morph::Plain`. It is a censorship-resistance device
/// (resemble the cover protocol's size distribution), not an anonymity-set one.
///
/// ## Why the bucket is the ONION's, not one sized to replies
///
/// A cheaper bucket sized to reply bodies would be a **separate anonymity set** — a frame in it says "this is
/// a dead-drop delivery" as loudly as its length said "this is a 900-byte reply". Reusing
/// `THRESHOLD_ONION_LEN` makes the cell byte-identical in size to a forwarded onion frame
/// (`1 + 12 + THRESHOLD_ONION_LEN` either way), so it joins the largest set the plane already has instead of
/// forming its own. The cost is `q + 1` × 20 KiB per delivery, which is what the forward direction already
/// pays per hop.
///
/// The body always fits: it arrived inside an onion of exactly this bucket, so it is strictly shorter.
/// `None` when it somehow is not — fail closed rather than emit a short cell that would be a distinguisher.
fn encode_drop(line: Triple, e2e: &[u8]) -> Option<Vec<u8>> {
    let room = threshold::THRESHOLD_ONION_LEN.checked_sub(4)?;
    if e2e.len() > room {
        return None;
    }
    let mut v = Vec::with_capacity(1 + 12 + threshold::THRESHOLD_ONION_LEN);
    v.push(TAG_DROP);
    v.extend_from_slice(&fanos_geometry::encode_triple(line));
    v.extend_from_slice(&u32::try_from(e2e.len()).ok()?.to_be_bytes());
    v.extend_from_slice(e2e);
    let mut filler = alloc::vec![0u8; room - e2e.len()];
    fanos_primitives::hash::hash_xof("FANOS-v1/nostos-drop-pad", e2e, &mut filler);
    v.extend_from_slice(&filler);
    Some(v)
}

/// Decode a dead-drop cell. **Fail-closed on width**: a cell whose padded region is not exactly
/// [`THRESHOLD_ONION_LEN`] is refused rather than accepted at its natural length, so the constant-width
/// property cannot silently degrade to "whatever arrived".
fn decode_drop(body: &[u8]) -> Option<(Triple, Vec<u8>)> {
    let line = fanos_geometry::decode_triple(body.get(..12)?)?;
    let region = body.get(12..)?;
    if region.len() != threshold::THRESHOLD_ONION_LEN {
        return None;
    }
    let len = u32::from_be_bytes(*region.first_chunk::<4>()?) as usize;
    Some((line, region.get(4..4 + len)?.to_vec()))
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

/// Decode a share request. Width-checked like [`decode_onion`] — it carries the same object, and a line
/// member that peels a partial from an off-width blob is doing work no honest combiner ever asks for. This
/// one borrows rather than copies, so it was never the memory defect; it is here because the rule is the
/// onion's, not the decoder's, and a rule enforced on one of two paths is the shape #218 is about.
fn decode_req(body: &[u8]) -> Option<(u64, Triple, Triple, &[u8])> {
    let req_id = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let combiner = fanos_geometry::decode_triple(body.get(8..20)?)?;
    let line = fanos_geometry::decode_triple(body.get(20..32)?)?;
    let onion = body.get(32..)?;
    if onion.len() != threshold::THRESHOLD_ONION_LEN {
        return None;
    }
    Some((req_id, combiner, line, onion))
}

fn encode_rep(req_id: u64, share: &Share) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 1 + share.y().len());
    v.push(TAG_REP);
    v.extend_from_slice(&req_id.to_be_bytes());
    v.push(share.x());
    v.extend_from_slice(share.y());
    v
}

/// Decode a share reply. **The share's on-wire length is fixed by the sealing side** (#218).
///
/// `ThresholdOnion::seal` Shamir-splits a `[u8; 32]` layer key, so a share's `y` is 32 bytes for every
/// legitimate share at every plane order and every threshold — and `fanos_threshold::share_to_bytes`, the
/// encoder used for the shares sealed *inside* the onion, already returns `None` for any other length.
/// This decoder is the **other** path a share crosses the wire on, and it read `body[9..]`: everything.
///
/// A longer share cannot even be useful to an attacker's own goal of forcing a wrong peel —
/// `shamir::reconstruct` refuses a subset whose `y` lengths differ — so what it bought was memory and
/// nothing else. Measured before this check: 64 frames left **62 MiB** in one gather, and
/// `MAX_PENDING × 62 MiB` is 201 GiB against a 64 MiB stated budget.
fn decode_rep(body: &[u8]) -> Option<(u64, Share)> {
    if body.len() != 8 + fanos_threshold::SHARE_LEN {
        return None;
    }
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
    /// The gather health this router reports on a sense-only read — the same path an operator's
    /// `fanos status stations` takes, rather than a test-only accessor beside it.
    fn reported_health<F: Field>(router: &mut ThresholdRouter<F>, at: u64) -> GatherHealth {
        router
            .step(Instant(at), Input::Command(Command::Observe))
            .iter()
            .find_map(|e| match e {
                Effect::Notify(Notification::DataPath { gather, .. }) => Some(*gather),
                _ => None,
            })
            .expect("a sense-only read exports the data-path plane")
    }

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
    fn the_mix_queue_stops_at_its_cap_and_refuses_the_newest(){
        // #295. The cover-OFF branch had no bound at all: `mix_pending` grew with the offered rate, one
        // live timer per entry, on a configuration `config.rs` presents as a supported trade.
        //
        // The bound is on a COUNT, so this drives it with tiny frames rather than real onions — the cap is
        // reached at the same length either way, and 2045 x 20 KiB of allocation would only make the test
        // slow enough to be skipped.
        let (s, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"mix-cap"));
        let mut r = ThresholdRouter::<F2>::new(Point::<F2>::at(0), &s, 2, [0x11; 32])
            .with_mixing(Duration::from_millis(120));
        let dest = Point::<F2>::at(3).coords();

        // Below the cap the queue grows, every arrival arms a timer, and nothing is refused. Without this
        // half the test would pass against a router that refuses everything.
        for _ in 0..8 {
            let out = r.forward_send(dest, alloc::vec![7u8; 4]);
            assert_eq!(out.len(), 1, "an accepted forward arms exactly one mix timer");
        }
        assert_eq!(r.mix_pending.len(), 8, "eight held, none refused");
        assert_eq!(r.stations().total(Station::RelayMixRefused), 0, "and the counter stays silent");

        // Past the cap the length STOPS and the refusals are counted.
        let first_id = *r.mix_pending.keys().next().expect("a held cell");
        for _ in 8..MAX_MIX_PENDING + 32 {
            let out = r.forward_send(dest, alloc::vec![7u8; 4]);
            assert!(out.len() <= 1, "a refusal arms no timer, so the cap bounds timers too");
        }
        assert_eq!(r.mix_pending.len(), MAX_MIX_PENDING, "the queue stops at its cap, not at the flood");
        assert_eq!(
            r.stations().total(Station::RelayMixRefused),
            32,
            "and every refusal past the cap is counted — a silent shed is what #295 was"
        );

        // The RULE, and the half that separates this from its sibling: the cells already in flight survive.
        // Drop-oldest would have evicted `first_id`, whose exponential delay is closest to firing — throwing
        // away the wait already served and thinning the batch the mix exists to hide a cell in.
        assert!(
            r.mix_pending.contains_key(&first_id),
            "a full mix queue refuses the NEWEST; evicting the oldest would discard the nearly-delivered"
        );
    }

    #[test]
    fn shedding_real_cargo_from_the_outbox_is_counted() {
        // #294. The cover-ON branch was bounded and silent: past `1 / cover_interval` the relay discards
        // real forwards, and an operator had no way to learn their node was doing it.
        let (s, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"outbox-shed"));
        let mut r = ThresholdRouter::<F2>::new(Point::<F2>::at(0), &s, 2, [0x11; 32])
            .with_cover(Duration::from_millis(500));
        let dest = Point::<F2>::at(3).coords();

        for _ in 0..MAX_OUTBOX {
            r.forward_send(dest, alloc::vec![9u8; 4]);
        }
        assert_eq!(r.outbox.len(), MAX_OUTBOX, "filled to the cap");
        assert_eq!(
            r.stations().total(Station::RelayCargoDropped),
            0,
            "nothing shed while the queue still had room — the control that makes the count below mean something"
        );

        for _ in 0..5 {
            r.forward_send(dest, alloc::vec![9u8; 4]);
        }
        assert_eq!(r.outbox.len(), MAX_OUTBOX, "still capped");
        assert_eq!(r.stations().total(Station::RelayCargoDropped), 5, "and each shed cell is named");
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
        let honest1 = member_partial::<F2>(&onion, 1, m1.secret()).unwrap();
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

    /// The budget's arithmetic, written out — so a reader can check it by eye and a change to any input
    /// shows up here as a diff rather than as a silently different bound (#213/#218).
    #[test]
    fn the_pending_cap_is_what_the_gather_budget_buys() {
        assert_eq!(threshold::THRESHOLD_ONION_LEN, 20480, "the constant bucket, on every plane");
        assert_eq!(fanos_threshold::SHARE_LEN, 33, "x(1) ‖ y(32), the Shamir split of a 32-byte layer key");
        assert_eq!(PENDING_ENTRY_BYTES, 22592, "20480 onion + 64 × 33 candidate shares");
        assert_eq!(MAX_PENDING, 2970, "64 MiB / 22592 B");
        // The two invariants are `const` assertions above, so they fail the BUILD rather than a run.
        // What is left here is what the old divisor bought and what it left out.
        let onion_only = GATHER_MEMORY_BUDGET / threshold::THRESHOLD_ONION_LEN;
        assert_eq!(onion_only, 3276, "what dividing by the onion alone bought");
        assert!(
            onion_only * PENDING_ENTRY_BYTES > GATHER_MEMORY_BUDGET,
            "the previous cap does not fit the true per-entry cost — the dropped term was not a rounding error"
        );
    }

    /// **A gather cannot be made to hold more than the budget says it holds** (#218).
    ///
    /// The two widths a stranger supplies — the onion and every candidate share — are fixed by the sealing
    /// side, and this asserts the router enforces both, by measuring what one gather retains under a flood
    /// that tries to exceed them. Measured before the checks: **62 MiB in one gather from 64 frames**, and
    /// `MAX_PENDING × 62 MiB = 201 GiB` against a stated 64 MiB budget.
    ///
    /// The assertion is against [`PENDING_ENTRY_BYTES`] rather than a literal, so a future change to either
    /// width moves the test with the constant instead of leaving it pinning a number nothing else believes.
    #[test]
    fn a_gather_cannot_be_flooded_past_the_width_the_sealing_side_produces() {
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
        let onion = seal_onion(&[hop], t as u8, b"anon-payload", b"seed-router").unwrap();
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let (identity0, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"identity-0"));
        let mut router = ThresholdRouter::<F2>::new(combiner, &identity0, t, onion_seed(0));
        router.step(Instant(0), Input::Message { from: [9, 9, 9], frame: launch_frame(line_coord, &onion) });

        // The wire ceiling on a frame body is `fanos_wire::MAX_FRAME`; a TAG_REP's `y` is everything
        // after `tag(1) ‖ req_id(8) ‖ x(1)`.
        // The sealing side's own width, asserted first: this is the number both checks are keyed on, and if
        // it ever stopped being constant the flood below would be measuring the wrong thing.
        assert_eq!(
            onion.len(),
            threshold::THRESHOLD_ONION_LEN,
            "a sealed onion is the constant bucket on every plane (`slots`), which is what makes the width \
             checkable at all"
        );
        assert_eq!(router.pending.len(), 1, "the launch frame armed a gather");

        // Flood: more candidates than the cap, each far wider than a share can legitimately be, each with a
        // distinct `y` so the exact-repeat dedup does not absorb them, at a valid member index so the
        // out-of-range gate does not either. The wire ceiling on a frame body is `fanos_wire::MAX_FRAME`.
        let oversize = (1usize << 20) - 10;
        for i in 0..MAX_CANDIDATES * 2 {
            let mut y = alloc::vec![0u8; oversize];
            y[0] = u8::try_from(i % 251).unwrap();
            router.step(
                Instant(1),
                Input::Message { from: [8, 8, 8], frame: encode_rep(0, &Share::new(1, y)) },
            );
        }
        let retained: usize = router
            .pending
            .values()
            .map(|p| p.onion.len() + p.shares.iter().map(|s| s.y().len()).sum::<usize>())
            .sum();
        assert!(
            retained <= PENDING_ENTRY_BYTES,
            "one gather retained {retained} B, above the {PENDING_ENTRY_BYTES} B the budget divides by — \
             MAX_PENDING is then a count of entries that do not cost what it assumed"
        );

        // The other half of the same rule, on the launch path: an off-width onion is refused outright
        // rather than retained at whatever width arrived.
        let before = router.pending.len();
        let mut wide = onion.clone(); // a real, peelable onion — one byte too wide is the only difference
        wide.push(0);
        router.step(Instant(2), Input::Message { from: [7, 7, 7], frame: launch_frame(line_coord, &wide) });
        assert_eq!(
            router.pending.len(),
            before,
            "an onion that is not the constant bucket armed a gather anyway"
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
            let honest1 = member_partial::<F2>(&onion, 1, m1.secret()).unwrap();
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
        let honest1 = member_partial::<F2>(&onion, 1, m1.secret()).unwrap();
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
        let cell = encode_drop(l, &e2e).expect("a body that came out of an onion fits a cell");

        // THE PROPERTY: the cell's width is a constant, so it carries no information about the reply. Asserted
        // against the ONION frame's width rather than a literal, because sharing the bucket is the point —
        // a cell in a bucket of its own would announce "dead-drop delivery" as loudly as its length used to
        // announce the reply's size.
        let onion_frame = 1 + 12 + threshold::THRESHOLD_ONION_LEN;
        assert_eq!(cell.len(), onion_frame, "a drop cell is the same width as a forwarded onion frame");
        let longer = seal_to_receiver(&reply_pub, &[7u8; 400], b"e2e2").unwrap();
        assert_ne!(longer.len(), e2e.len(), "the two replies really do differ in size");
        assert_eq!(
            encode_drop(l, &longer).expect("also fits").len(),
            cell.len(),
            "and a reply 400 bytes longer produces a cell of the identical width — the length of the plaintext \
             is what used to reach every member of the line"
        );
        // Fail closed on width: a short cell must be refused, not accepted at whatever arrived.
        assert!(decode_drop(&cell[1..cell.len() - 1]).is_none(), "a truncated cell is refused");

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
                .step(Instant(0), Input::Message { from: [0, 0, 0], frame: cell.clone() })
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
    fn the_router_arms_gathers_with_the_measured_deadline_not_a_constant() {
        // The WIRING of `fanos_ports::GatherClock` into this engine — the pure estimator is proven in
        // fanos-ports; what this engine owes is that (1) a completed peel feeds the clock a sample and
        // the next gather is armed with the measured deadline, and (2) an expiry feeds the backoff and
        // the next gather is armed wider. Disable either call and the matching assertion fails.
        let line = Line::<F2>::at(0).coords();
        let members = ThresholdRouter::<F2>::line_members(line);
        let t = 2usize;
        let onion_seed = |i: u8| {
            let mut s = [0x71u8; 32];
            s[31] = i;
            s
        };
        let ratchets: Vec<OnionKeyRatchet> =
            (0..3).map(|i| OnionKeyRatchet::new(onion_seed(i), Epoch::ZERO)).collect();
        let pubs = [ratchets[0].public(), ratchets[1].public(), ratchets[2].public()];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"measured-arm"));
        let me_idx = 0usize;
        let mut router = ThresholdRouter::<F2>::new(
            Point::<F2>::new(members[me_idx]).unwrap(),
            &identity,
            t,
            onion_seed(me_idx as u8),
        );
        let deadline_of = |effects: &[Effect]| {
            effects.iter().find_map(|e| match e {
                Effect::ArmTimer { token, after } if token.0 & (MIX_FLAG | COVER_TOKEN) == 0 => {
                    Some(*after)
                }
                _ => None,
            })
        };

        // Cold: the first gather is armed with the bootstrap deadline.
        let seal = |i: u8| {
            seal_onion(&[HopLine { line, members: &pubs }], t as u8, b"wired-clock", &[0x5A, i])
                .unwrap()
        };
        let effects =
            router.step(Instant(0), Input::Message { from: [9, 9, 9], frame: launch_frame(line, &seal(0)) });
        assert_eq!(
            deadline_of(&effects),
            Some(fanos_ports::gather::INITIAL_GATHER_DEADLINE),
            "a cold router arms the bootstrap deadline"
        );

        // Complete a run of 2 ms gathers: each peel feeds `now - armed_at` into the clock. If the
        // observe call were dropped, the deadline would stay at the 2 s bootstrap forever.
        let two_ms = Duration::from_millis(2).as_nanos();
        let mut now = 0u64;
        for i in 0..12u8 {
            let onion = seal(i);
            router.step(Instant(now), Input::Message { from: [9, 9, 9], frame: launch_frame(line, &onion) });
            let req_id = router.seq - 1;
            let other = 1 - me_idx; // any other line member's honest partial completes t = 2
            let honest = member_partial::<F2>(&onion, other, ratchets[other].secret()).unwrap();
            now += two_ms;
            router.step(
                Instant(now),
                Input::Message { from: members[other], frame: encode_rep(req_id, &honest) },
            );
        }
        let armed = router
            .step(Instant(now), Input::Message { from: [9, 9, 9], frame: launch_frame(line, &seal(200)) });
        let measured = deadline_of(&armed).unwrap();
        assert!(
            measured < Duration::from_millis(50),
            "after a dozen 2 ms completions the armed deadline tracks the measurement, got {measured:?}"
        );

        // Let that pending gather EXPIRE: the next arm must be strictly wider (the backoff wiring).
        let expired_id = router.seq - 1;
        router.step(Instant(now), Input::Timer(TimerToken(expired_id)));
        let rearmed = router
            .step(Instant(now), Input::Message { from: [9, 9, 9], frame: launch_frame(line, &seal(201)) });
        let widened = deadline_of(&rearmed).unwrap();
        assert!(
            widened > measured,
            "an expiry must widen the next armed deadline: {widened:?} vs {measured:?}"
        );
    }

    #[test]
    fn the_gather_path_health_is_none_until_measured_then_tracks_the_observation() {
        // §4.1's "export what is already computed": the deadline estimator's own SRTT is the gather path's
        // health, and a lengthening gather is what "this line is oversubscribed" looks like BEFORE any hop
        // fails. The property that makes it usable as a load signal is that it reports honestly when it
        // has nothing — a cold router must not present a fabricated latency as a measurement.
        let line = Line::<F2>::at(0).coords();
        let members = ThresholdRouter::<F2>::line_members(line);
        let t = 2usize;
        let onion_seed = |i: u8| {
            let mut sd = [0x9Cu8; 32];
            sd[31] = i;
            sd
        };
        let ratchets: Vec<OnionKeyRatchet> =
            (0..3).map(|i| OnionKeyRatchet::new(onion_seed(i), Epoch::ZERO)).collect();
        let pubs = [ratchets[0].public(), ratchets[1].public(), ratchets[2].public()];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"gather-health"));
        let mut router = ThresholdRouter::<F2>::new(
            Point::<F2>::new(members[0]).unwrap(),
            &identity,
            t,
            onion_seed(0),
        );

        assert_eq!(
            reported_health(&mut router, 0),
            GatherHealth::Unmeasured,
            "a router that has completed no gather reports NO measurement, not a plausible-looking zero"
        );

        // Complete gathers at a known latency; the estimate must land on it rather than merely be non-None.
        let step_ns = Duration::from_millis(5).as_nanos();
        let mut now = 0u64;
        for i in 0..12u8 {
            let onion =
                seal_onion(&[HopLine { line, members: &pubs }], t as u8, b"health", &[0x7C, i]).unwrap();
            router.step(
                Instant(now),
                Input::Message { from: [9, 9, 9], frame: launch_frame(line, &onion) },
            );
            let req_id = router.seq - 1;
            let honest = member_partial::<F2>(&onion, 1, ratchets[1].secret()).unwrap();
            now += step_ns;
            router.step(
                Instant(now),
                Input::Message { from: members[1], frame: encode_rep(req_id, &honest) },
            );
        }
        let GatherHealth::Measured { srtt, .. } = reported_health(&mut router, now) else {
            panic!("after twelve completed gathers there IS a measurement")
        };
        assert!(
            srtt > Duration::from_millis(1) && srtt < Duration::from_millis(20),
            "the estimate tracks the observed 5 ms rather than drifting: {srtt:?}"
        );
    }

    #[test]
    fn a_starved_hop_records_which_line_expired_instead_of_vanishing() {
        // **The question #55 could not answer.** With a node silenced, the coherence plane could say
        // "point 3 is faulted" — which the operator already knew, having stopped it — but not the two
        // facts that actually solved it. This is the second: gathers expiring below threshold, per line,
        // in the hundreds. It was found by hand-inserting probes and grepping; now the engine records it.
        let line = Line::<F2>::at(0).coords();
        let members = ThresholdRouter::<F2>::line_members(line);
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"starved-station"));
        let mut router =
            ThresholdRouter::<F2>::new(Point::<F2>::new(members[0]).unwrap(), &identity, 2, [0x7E; 32]);

        // Nothing is recorded before anything stops — a plane that reports activity it did not observe
        // is worse than none.
        assert!(router.stations().is_empty(), "a fresh router has observed nothing");

        // Launch a hop, then fire its deadline with no partial ever arriving: t = 2 was never reached.
        let mut onion = alloc::vec![0u8; threshold::THRESHOLD_ONION_LEN];
        onion[..8].copy_from_slice(&7u64.to_be_bytes());
        let armed = router.step(
            Instant(0),
            Input::Message { from: [9, 9, 9], frame: launch_frame(line, &onion) },
        );
        let token = armed
            .iter()
            .find_map(|e| match e {
                Effect::ArmTimer { token, .. } if token.0 & (MIX_FLAG | COVER_TOKEN) == 0 => Some(*token),
                _ => None,
            })
            .expect("the gather armed a deadline");
        router.step(Instant(1), Input::Timer(token));

        // The station names the LINE, which is the whole diagnostic value: "some gathers expired" is a
        // number, "this line's gathers expired" is a cause.
        assert_eq!(
            router.stations().get(Station::GatherExpired, Some(line)),
            1,
            "an expired gather is attributed to the line it was peeling for"
        );
        assert_eq!(
            router.stations().total(Station::GatherCompleted),
            0,
            "and a hop that never completed is not counted as one — a one-sided counter points at the \
             wrong half, so the denominator has to be honest too"
        );

        // A forged share index is an ATTACK indicator, not an error rate, so it gets its own station.
        let mut onion2 = alloc::vec![0u8; threshold::THRESHOLD_ONION_LEN];
        onion2[..8].copy_from_slice(&8u64.to_be_bytes());
        router.step(
            Instant(2),
            Input::Message { from: [9, 9, 9], frame: launch_frame(line, &onion2) },
        );
        let req_id = router.seq - 1;
        let forged = Share::new(200, alloc::vec![0u8; 32]); // no honest member has index 200
        router.step(
            Instant(3),
            Input::Message { from: members[1], frame: encode_rep(req_id, &forged) },
        );
        assert_eq!(
            router.stations().get(Station::ShareIndexOutOfRange, Some(line)),
            1,
            "a share index outside the line's real membership is distinguishable from noise"
        );
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
        let honest = member_partial::<F2>(&onion, other_idx, ratchets[other_idx].secret()).unwrap();
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
