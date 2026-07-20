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
//!    ([`crate::threshold::member_partial`]) and contributes its own.
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
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

use crate::threshold::{self, ThresholdPeel};

/// Internal frame tags (the onion travels as opaque overlay bytes; these are its sub-types).
const TAG_ONION: u8 = 0;
const TAG_REQ: u8 = 1;
const TAG_REP: u8 = 2;

/// The anonymous-source sentinel in a delivery notification (the endpoint learns no originator).
pub const ANONYMOUS: Triple = [0, 0, 0];

/// Default deadline for a combiner to gather `t` partials before abandoning a hop.
const DEFAULT_GATHER_TIMEOUT: Duration = Duration::from_millis(2000);

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
    gather_timeout: Duration,
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
            gather_timeout: DEFAULT_GATHER_TIMEOUT,
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

    /// Override the combiner's partial-gathering deadline (default 2 s).
    #[must_use]
    pub fn with_gather_timeout(mut self, timeout: Duration) -> Self {
        self.gather_timeout = timeout;
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
            if let Some(combiner) = Self::combiner_of(line) {
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

    /// The canonical combiner of a line — its first `points_on` member.
    fn combiner_of(line: Triple) -> Option<Triple> {
        Self::line_members(line).into_iter().next()
    }

    /// Handle an onion addressed to us as the combiner of `line`: seed a pending peel with our own
    /// partial and fan out share-requests to the rest of the line.
    fn on_onion(&mut self, line: Triple, onion: Vec<u8>) -> Vec<Effect> {
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
        self.pending.insert(
            req_id,
            Pending {
                onion,
                shares,
                member_count,
            },
        );
        // If we already have a threshold (e.g. t = 1), peel now; else await replies until deadline.
        if let Some(done) = self.try_peel(req_id) {
            effects.extend(done);
        } else {
            effects.push(Effect::ArmTimer {
                token: TimerToken(req_id),
                after: self.gather_timeout,
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
    fn on_reply(&mut self, req_id: u64, share: Share) -> Vec<Effect> {
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
        self.try_peel(req_id).unwrap_or_default()
    }

    /// If a pending peel can be satisfied, peel it and act on the outcome. The pending state is removed
    /// **only** when a subset of shares actually peels (or when its gather deadline fires) — a single
    /// poisoned share can therefore neither reconstruct a wrong key that discards the peel nor destroy
    /// the in-flight state, so honest replies still complete the hop (liveness under up to `t − 1`
    /// malicious members).
    fn try_peel(&mut self, req_id: u64) -> Option<Vec<Effect>> {
        let pending = self.pending.get(&req_id)?;
        if pending.shares.len() < self.threshold {
            return None;
        }
        let peel = peel_best_subset(&pending.onion, &pending.shares, self.threshold)?;
        self.pending.remove(&req_id); // the hop is resolved — evict the in-flight state
        Some(match peel {
            ThresholdPeel::Deliver { payload } => {
                alloc::vec![Effect::Notify(Notification::Delivered {
                    from: ANONYMOUS,
                    payload,
                })]
            }
            ThresholdPeel::Forward { next, onion } => match Self::combiner_of(next) {
                Some(c) => {
                    // Re-pad the inner onion to the constant bucket so the forwarded packet is the
                    // same size as the one we received — no cross-hop size correlation.
                    let padded = threshold::pad_onion(&onion).unwrap_or(onion);
                    self.forward_send(c, encode_onion(next, &padded))
                }
                None => Vec::new(),
            },
        })
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
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Message { frame, .. } => match frame.split_first() {
                Some((&TAG_ONION, body)) => match decode_onion(body) {
                    Some((line, onion)) => self.on_onion(line, onion),
                    None => Vec::new(),
                },
                Some((&TAG_REQ, body)) => match decode_req(body) {
                    Some((req_id, combiner, line, onion)) => {
                        self.on_request(req_id, combiner, line, onion)
                    }
                    None => Vec::new(),
                },
                Some((&TAG_REP, body)) => match decode_rep(body) {
                    Some((req_id, share)) => self.on_reply(req_id, share),
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
                    // The gather deadline fired: drop an incomplete pending peel.
                    self.pending.remove(&token);
                    Vec::new()
                }
            }
            // A node may also *originate* onions as a client: `Command::Send { to, payload }` launches
            // the already-sealed frame `payload` to `to` verbatim (the combiner of its first hop), so
            // the same node that peels replies here can inject its own launch frames. Other commands do
            // not apply to a router.
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

/// The combiner coordinate a client routes the first (or any) hop's onion to, for a given field `F`.
#[must_use]
pub fn combiner_for<F: Field>(line: Triple) -> Option<Triple> {
    ThresholdRouter::<F>::combiner_of(line)
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
    use crate::threshold::{HopLine, member_partial, seal_onion};
    use fanos_field::F2;
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
}
