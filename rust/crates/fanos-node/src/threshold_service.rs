//! `ThresholdService` — a **threshold-hosted CALYPSO service endpoint** as one sans-I/O engine
//! (spec §12.3, audit #99). A classic hidden service runs on one host; seize it and the service dies
//! (and may be deanonymized). A CALYPSO service is instead hosted across the members of a **service-line**:
//! each client `RDV_INTRO` is sealed to the whole line ([`fanos_calypso::hosting::SealedIntro`]), and
//! **no single host ever reads an intro alone** — a designated *combiner* gathers `≥ threshold`
//! members' PartialDecs over the overlay, Lagrange-combines them, and only then recovers the request.
//! Fewer than `threshold` seized/colluding hosts learn **nothing** (0-knowledge — the same guarantee NYX
//! §5.2 gives onion hops), the service *is the line* (nothing to raid), and any `threshold` of the
//! members serve — high availability for free.
//!
//! This lifts the worked `ServiceMember` template of `fanos-sim/tests/threshold_calypso.rs` into a real,
//! **multiplexed, DoS-bounded** engine on the production wire vocabulary
//! ([`FrameType::RdvIntro`]/[`SvcShareReq`](FrameType::SvcShareReq)/[`SvcPartial`](FrameType::SvcPartial)):
//! it tracks many concurrent intros keyed by intro id, caps the in-flight set, and drops an intro whose
//! gather does not complete before a deadline — none of which the single-intro template needed.
//!
//! ## Protocol (mirrors [`ThresholdRouter`](fanos_aphantos::ThresholdRouter)'s combiner exchange)
//! 1. A client (or the rendezvous transport) delivers a [`FrameType::RdvIntro`] carrying a `SealedIntro`
//!    to a line member — the **combiner** for that intro. The combiner seeds its *own* PartialDec and
//!    fans a [`SvcShareReq`](FrameType::SvcShareReq) (the intro) to every other member.
//! 2. Each member computes its own PartialDec ([`SealedIntro::member_partial`]) and returns it in a
//!    [`SvcPartial`](FrameType::SvcPartial) (`intro_id ‖ share`) to the combiner.
//! 3. Once the combiner holds `≥ threshold` distinct shares it [`open`](SealedIntro::open)s the intro and
//!    **surfaces the recovered request** as an anonymous [`Notification::Delivered`] for the service
//!    application to answer (the reply travels back over the client's reply circuit — the same path the
//!    single-host [`RendezvousService`](fanos_rendezvous::RendezvousService) already uses).
//!
//! The engine's job ends at *surfacing the decrypted request*: reply sealing is the application's, exactly
//! as it is for the non-threshold service — so a threshold service is this engine plus the existing
//! rendezvous reply path.

use std::collections::{BTreeMap, VecDeque};

use fanos_calypso::hosting::{SealedIntro, SealedShare, Share, open_service_share};
use fanos_geometry::Triple;
use fanos_pqcrypto::HybridKemSecret;
use fanos_primitives::hash_labeled;
use fanos_runtime::ports::GatherClock;
use fanos_runtime::ports::stations::{GatherHealth, Station, Stations};
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_wire::{FrameType, Wire, decode_frame, encode_frame};

/// A 32-byte intro id — `H("…/intro-id" ‖ SealedIntro bytes)` — correlates a combiner's pending gather
/// with the members' PartialDec replies. Both sides derive it from the same intro, so it never travels
/// except as an opaque tag in a [`SvcPartial`](FrameType::SvcPartial).
type IntroId = [u8; 32];

const INTRO_ID_LABEL: &str = "FANOS-v1/calypso-intro-id";

/// The anonymous-source sentinel a surfaced request carries (identical to the mixnet's), so the service
/// application never learns which relay delivered it.
const ANONYMOUS: Triple = [0, 0, 0];

/// Default cap on concurrently-gathering intros — a bound on combiner state against an intro flood
/// (spec §12.5 DoS). Beyond it, new intros are dropped until a slot frees (completed or timed out).
const DEFAULT_MAX_PENDING: usize = 256;

/// How many recently-served intro ids to remember, to suppress a replayed intro re-serving (bounded).
const SERVED_MEMORY: usize = 256;

/// A combiner's in-flight gather for one intro: the sealed intro, the shares collected so far (deduped by
/// share index so a member cannot inflate the count by replying twice), and the timer that bounds it.
struct PendingIntro {
    intro: SealedIntro,
    shares: BTreeMap<u8, Share>,
    timer: TimerToken,
    /// When the share requests went out — a completed gather yields `now − armed_at` as one latency
    /// sample for the measured deadline ([`GatherClock`]).
    armed_at: Instant,
}

/// One member of a threshold-hosted CALYPSO service-line (see the module docs). Constructed with this
/// host's KEM secret (its share slot), the full ordered member roster (index = share index, the order the
/// client sealed to), and the `threshold`.
pub struct ThresholdService {
    coord: Triple,
    secret: HybridKemSecret,
    line: Vec<Triple>,
    threshold: usize,
    my_index: Option<usize>,
    pending: BTreeMap<IntroId, PendingIntro>,
    served: VecDeque<IntroId>,
    seq: u64,
    max_pending: usize,
    /// The measured gather deadline (RFC 6298 over completed gathers — [`GatherClock`]); `pending` is
    /// bounded by `max_pending` COUNT, which is what leaves the deadline free to be measured.
    gather: GatherClock,
    /// An explicit pin for scenarios that must assert a specific expiry; `None` — the default — uses the
    /// measured value.
    gather_override: Option<Duration>,
    /// The data-path plane's counters (`docs/design-observability.md`). This engine measured a gather deadline
    /// nothing could read and counted nothing at all, so a hosted service that had stopped serving looked
    /// identical whether its line disagreed on the key, its intros were being flooded, or its shares were
    /// arriving tampered — the exact "eleven candidate causes, one clock" position #55 was diagnosed from.
    stations: Stations,
}

impl ThresholdService {
    /// A service-line member at `coord` holding `secret`, hosting the service `threshold`-of-`line.len()`.
    /// `line` is every member's coordinate in the exact order the client sealed their public keys — a
    /// member's position in it is its share index.
    #[must_use]
    pub fn new(coord: Triple, secret: HybridKemSecret, line: Vec<Triple>, threshold: usize) -> Self {
        let my_index = line.iter().position(|&c| c == coord);
        Self {
            coord,
            secret,
            line,
            threshold,
            my_index,
            pending: BTreeMap::new(),
            served: VecDeque::new(),
            seq: 0,
            max_pending: DEFAULT_MAX_PENDING,
            gather: GatherClock::new(),
            gather_override: None,
            stations: Stations::new(),
        }
    }

    /// **Pin** the combiner's gather deadline, disabling the measured one ([`GatherClock`]).
    ///
    /// For scenarios that must assert a specific expiry. Production leaves it unset: the pinned constant
    /// this used to set is the defect the measured deadline removed — the right value moved 45× between
    /// build profiles alone (`fanos-aphantos/tests/gather_cost.rs`).
    #[must_use]
    pub fn with_gather_timeout(mut self, timeout: Duration) -> Self {
        self.gather_override = Some(timeout);
        self
    }

    /// The deadline the next intro-gather is armed with — the pin if one is set, else the measured value.
    fn gather_deadline(&self) -> Duration {
        self.gather_override.unwrap_or_else(|| self.gather.deadline())
    }

    /// The number of intros currently gathering (combiner state) — for tests and observability.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Open this member's **identity-custody share** — a [`SealedShare`] of the service's threshold-hosted
    /// *identity* secret (§12.3–§12.6), distinct from the per-intro key shares. Uses this member's own KEM
    /// secret (kept encapsulated here); `None` if the share was not sealed to it. A combiner reconstructs the
    /// service identity from `threshold` such opened shares
    /// ([`recover_service_key`](fanos_calypso::hosting::recover_service_key)) only when the service must
    /// authenticate (e.g. re-signing an epoch cert, spec §12.6) — so **no single host holds the service
    /// identity in the clear**, the same seizure-resistance the per-intro sharing gives request confidentiality.
    #[must_use]
    pub fn open_identity_share(&self, sealed: &SealedShare) -> Option<Share> {
        open_service_share(sealed, &self.secret)
    }

    fn intro_id(intro: &SealedIntro) -> IntroId {
        hash_labeled(INTRO_ID_LABEL, &intro.to_wire())
    }

    /// Record a just-served (or replayed-and-suppressed) intro id in the bounded replay memory.
    fn remember_served(&mut self, id: IntroId) {
        if self.served.contains(&id) {
            return;
        }
        self.served.push_back(id);
        if self.served.len() > SERVED_MEMORY {
            self.served.pop_front();
        }
    }

    /// An intro was delivered to us as its combiner: seed our own PartialDec, fan share-requests to the
    /// rest of the line, and (if we already hold `threshold`, e.g. a degenerate 1-of-1 line) serve at once.
    fn on_intro(&mut self, now: Instant, intro: SealedIntro) -> Vec<Effect> {
        let id = Self::intro_id(&intro);
        // Suppress replays and duplicates: a recently-served id, or one already gathering, is ignored.
        if self.served.contains(&id) || self.pending.contains_key(&id) {
            return Vec::new();
        }
        if self.pending.len() >= self.max_pending {
            // Unattributed: the cap is on this member's own pending count, a property of *this* node under
            // load, not of any one line.
            self.stations.record(Station::ShareFloodCapped, None);
            return Vec::new(); // intro-flood bound (spec §12.5)
        }
        let mut shares: BTreeMap<u8, Share> = BTreeMap::new();
        if let Some(i) = self.my_index
            && let Some(share) = intro.member_partial(i, &self.secret)
        {
            shares.insert(share.x(), share);
        }
        let req = encode(FrameType::SvcShareReq, &intro.to_wire());
        let mut effects: Vec<Effect> = self
            .line
            .iter()
            .filter(|&&member| member != self.coord)
            .map(|&member| Effect::Send {
                to: member,
                frame: req.clone(),
            })
            .collect();

        let timer = TimerToken(self.seq);
        self.seq = self.seq.wrapping_add(1);
        effects.push(Effect::ArmTimer {
            token: timer,
            after: self.gather_deadline(),
        });
        self.pending.insert(id, PendingIntro { intro, shares, timer, armed_at: now });
        effects.extend(self.try_serve(now, id));
        effects
    }

    /// A combiner asked for our PartialDec of `intro`: compute and return it (if we are a line member).
    fn on_share_req(&mut self, combiner: Triple, intro: &SealedIntro) -> Vec<Effect> {
        let Some(i) = self.my_index else {
            // Asked for a share of a line this node is not on. Charged to the asker's coordinate, which is the
            // only thing here that identifies who is confused.
            self.stations.record(Station::ShareRequestNotAMember, Some(combiner));
            return Vec::new();
        };
        let Some(share) = intro.member_partial(i, &self.secret) else {
            // The sharper of the two skew signals (§6): a member on the line that cannot compute its own share
            // is key/epoch skew *inside* a line that is otherwise agreeing, and it presents as a hop that
            // simply never peels.
            self.stations.record(Station::SharePartialFailed, Some(self.coord));
            return Vec::new();
        };
        let id = Self::intro_id(intro);
        vec![Effect::Send {
            to: combiner,
            frame: encode(FrameType::SvcPartial, &encode_partial(&id, &share)),
        }]
    }

    /// A member's PartialDec arrived: fold it into the matching pending gather and retry.
    fn on_partial(&mut self, now: Instant, id: IntroId, share: Share) -> Vec<Effect> {
        let Some(pending) = self.pending.get_mut(&id) else {
            // A partial for a gather that is gone: served already, expired, or never started here. Common and
            // benign one at a time; a rate says the deadline is short against the line's real latency.
            self.stations.record(Station::ShareForUnknownRequest, None);
            return Vec::new(); // unknown/late intro id — nothing to gather it into
        };
        pending.shares.entry(share.x()).or_insert(share);
        self.try_serve(now, id)
    }

    /// If the gather for `id` has reached `threshold` distinct shares, open the intro and surface the
    /// recovered request; else leave it pending. A failed open (below threshold / tamper) leaves the
    /// gather in place to await more shares.
    fn try_serve(&mut self, now: Instant, id: IntroId) -> Vec<Effect> {
        let Some(pending) = self.pending.get(&id) else {
            return Vec::new();
        };
        if pending.shares.len() < self.threshold {
            return Vec::new();
        }
        let shares: Vec<Share> = pending.shares.values().cloned().collect();
        let Ok(request) = pending.intro.open(&shares) else {
            // Threshold met and the open still failed: the shares do not belong together. Not a member's own
            // share failing and not a timeout — both of which look identical from outside and are different
            // faults, which is why this has its own station.
            self.stations.record(Station::GatherOpenFailed, Some(self.coord));
            return Vec::new();
        };
        let armed_at = pending.armed_at;
        // Served: drop the gather and remember the id, then surface the request. The gather's deadline
        // timer may still fire later; `on_timer` finds no matching pending intro and harmlessly no-ops
        // (there is no CancelTimer effect — a stale tick is inert).
        self.pending.remove(&id);
        self.remember_served(id);
        // One completed gather is one latency sample — `RTT + C_partial + Q` together, under the load
        // the next gather will meet. This is what replaces the former 2 s constant.
        self.gather.observe(now.since(armed_at));
        vec![Effect::Notify(Notification::Delivered {
            from: ANONYMOUS,
            payload: request,
        })]
    }

    /// A gather deadline fired: drop the (still-incomplete) intro it bounds, freeing its slot — and back
    /// off ([`GatherClock::expired`]): the deadline was demonstrably too short for the load this node is
    /// under, and an expiry yields no sample, so nothing else would ever widen it (RFC 6298 §5.5 + Karn).
    /// Count a frame that stopped before it could be attributed, and discard it.
    ///
    /// One site for **every** decode-failure arm, including the unknown-type one, so the count cannot be
    /// half-instrumented by a later arm being added without a call. Deliberately unattributed: a frame that
    /// failed to parse has no readable line, and inventing one would put fabricated evidence against a line
    /// into the plane built to end diagnosis on thin evidence.
    fn undecodable(&mut self) -> Vec<Effect> {
        self.stations.record(Station::FrameDecodeFailed, None);
        Vec::new()
    }

    fn on_timer(&mut self, token: TimerToken) -> Vec<Effect> {
        if let Some(&id) = self
            .pending
            .iter()
            .find(|(_, p)| p.timer == token)
            .map(|(id, _)| id)
        {
            self.pending.remove(&id);
            self.stations.record(Station::GatherExpired, Some(self.coord));
            self.gather.expired();
        }
        Vec::new()
    }
}

impl Engine for ThresholdService {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Message { from, frame } => {
                let Ok((decoded, _)) = decode_frame(&frame) else {
                    return self.undecodable();
                };
                // Written as `match … { Ok(v) => …, Err(_) => self.undecodable() }` rather than `map_or_else`
                // with two closures, which cannot both hold `&mut self`.
                match decoded.frame_type() {
                    Some(FrameType::RdvIntro) => match SealedIntro::from_wire(decoded.body) {
                        Ok(intro) => self.on_intro(now, intro),
                        Err(_) => self.undecodable(),
                    },
                    Some(FrameType::SvcShareReq) => match SealedIntro::from_wire(decoded.body) {
                        Ok(intro) => self.on_share_req(from, &intro),
                        Err(_) => self.undecodable(),
                    },
                    Some(FrameType::SvcPartial) => match decode_partial(decoded.body) {
                        Some((id, share)) => self.on_partial(now, id, share),
                        None => self.undecodable(),
                    },
                    // Includes the unknown-type arm, deliberately: a frame this build does not recognise is
                    // the version-skew signal §6 is about, and leaving it uncounted is how a half-instrumented
                    // plane happens — a later arm added without one.
                    _ => self.undecodable(),
                }
            }
            Input::Timer(token) => self.on_timer(token),
            // The sense-only read: this engine owns both a gather clock and a counter map, so it answers for
            // them itself rather than a driver reaching in.
            Input::Command(Command::Observe) => vec![Effect::Notify(Notification::DataPath {
                stations: self.stations.observations(),
                gather: GatherHealth::of(&self.gather),
            })],
            // A threshold-service member takes no other application commands (it serves intros off the wire).
            Input::Command(_) => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord
    }
}

/// Build the `RdvIntro` frame a client sends to a service-line combiner to open a threshold-hosted
/// session: the `SealedIntro` (sealed to the line via [`SealedIntro::seal`]) as the frame body.
#[must_use]
pub fn intro_frame(intro: &SealedIntro) -> Vec<u8> {
    encode(FrameType::RdvIntro, &intro.to_wire())
}

/// Encode a wire frame with the given type and body.
fn encode(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(ty.code(), body, &mut out);
    out
}

/// A `SvcPartial` body: `intro_id(32) ‖ x(1) ‖ y`.
fn encode_partial(id: &IntroId, share: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 1 + share.y().len());
    out.extend_from_slice(id);
    out.push(share.x());
    out.extend_from_slice(share.y());
    out
}

fn decode_partial(body: &[u8]) -> Option<(IntroId, Share)> {
    let id: IntroId = body.get(..32)?.try_into().ok()?;
    let (&x, y) = body.get(32..)?.split_first()?;
    Some((id, Share::new(x, y.to_vec())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use fanos_geometry::Point;
    use fanos_pqcrypto::{HybridKemPublic, SeedRng};

    use super::*;
    use fanos_field::F2;

    /// A `t`-of-3 service line at Fano points 0..3, returning the coordinates, the members' secrets and
    /// their publics in seal order.
    fn line_of_three() -> (Vec<Triple>, Vec<HybridKemSecret>, Vec<HybridKemPublic>) {
        let mut coords = Vec::new();
        let mut secrets = Vec::new();
        let mut publics = Vec::new();
        for i in 0..3usize {
            let (secret, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xC1, i as u8]));
            coords.push(Point::<F2>::at(i).coords());
            secrets.push(secret);
            publics.push(public);
        }
        (coords, secrets, publics)
    }

    /// The gather-deadline this engine armed, if any (it arms exactly one timer per opened gather).
    fn armed_deadline(effects: &[Effect]) -> Option<Duration> {
        effects.iter().find_map(|e| match e {
            Effect::ArmTimer { after, .. } => Some(*after),
            _ => None,
        })
    }

    #[test]
    fn the_intro_gather_deadline_is_measured_not_a_constant() {
        // This engine held its own copy of the 2000 ms constant that #55 measured the cost of — a value
        // whose right setting moves 45x between build profiles alone
        // (`fanos-aphantos/tests/gather_cost.rs`). It now shares `fanos_ports::GatherClock`, and what
        // this test owes is the WIRING, since the estimator itself is proven in fanos-ports: a completed
        // gather must feed a sample (so the next deadline tracks observation) and an expiry must feed the
        // backoff (so a too-tight estimate can recover). Delete either call and one half fails.
        let (line, secrets, publics) = line_of_three();
        let t = 2usize;
        let refs: Vec<&HybridKemPublic> = publics.iter().collect();
        // A KEM secret is deliberately not `Clone` (secret hygiene), so take the two this test drives —
        // the combiner's and member 1's — by ownership, in seal order.
        let mut secrets = secrets.into_iter();
        let combiner_secret = secrets.next().unwrap();
        let member_1_secret = secrets.next().unwrap();
        let mut svc = ThresholdService::new(line[0], combiner_secret, line.clone(), t);

        // Cold: nothing measured yet, so the bootstrap deadline stands.
        let intro = SealedIntro::seal(b"first", t as u8, &refs, b"seed-0").unwrap();
        let effects = svc.step(Instant(0), Input::Message { from: line[2], frame: intro_frame(&intro) });
        assert_eq!(
            armed_deadline(&effects),
            Some(fanos_runtime::ports::gather::INITIAL_GATHER_DEADLINE),
            "a cold combiner arms the bootstrap deadline, not a measurement it does not have"
        );
        // Complete that gather in 3 ms — member 1's partial brings it to t = 2.
        let id = ThresholdService::intro_id(&intro);
        let share = intro.member_partial(1, &member_1_secret).unwrap();
        let served = svc.step(
            Instant(Duration::from_millis(3).as_nanos()),
            Input::Message { from: line[1], frame: encode(FrameType::SvcPartial, &encode_partial(&id, &share)) },
        );
        assert!(
            served.iter().any(|e| matches!(e, Effect::Notify(Notification::Delivered { .. }))),
            "the gather completed at threshold"
        );

        // A run of fast gathers: the armed deadline must collapse toward the observation, which the old
        // constant could never do.
        let mut now = Duration::from_millis(3).as_nanos();
        for i in 1..12u8 {
            let intro = SealedIntro::seal(b"payload", t as u8, &refs, &[0xA0, i]).unwrap();
            svc.step(Instant(now), Input::Message { from: line[2], frame: intro_frame(&intro) });
            let id = ThresholdService::intro_id(&intro);
            let share = intro.member_partial(1, &member_1_secret).unwrap();
            now += Duration::from_millis(3).as_nanos();
            svc.step(
                Instant(now),
                Input::Message { from: line[1], frame: encode(FrameType::SvcPartial, &encode_partial(&id, &share)) },
            );
        }
        let probe = SealedIntro::seal(b"probe", t as u8, &refs, b"seed-probe").unwrap();
        let armed = svc.step(Instant(now), Input::Message { from: line[2], frame: intro_frame(&probe) });
        let measured = armed_deadline(&armed).unwrap();
        assert!(
            measured < Duration::from_millis(60),
            "after a dozen 3 ms completions the armed deadline tracks the measurement, got {measured:?}"
        );

        // Now let that gather EXPIRE. Its deadline fired without reaching t, so the next one must be
        // strictly wider — the half of RFC 6298 a pure smoother never supplies (an expiry yields no
        // sample, so nothing else would ever widen a too-tight estimate).
        let timer = armed
            .iter()
            .find_map(|e| match e {
                Effect::ArmTimer { token, .. } => Some(*token),
                _ => None,
            })
            .unwrap();
        svc.step(Instant(now), Input::Timer(timer));
        let next = SealedIntro::seal(b"after-expiry", t as u8, &refs, b"seed-after").unwrap();
        let rearmed = svc.step(Instant(now), Input::Message { from: line[2], frame: intro_frame(&next) });
        let widened = armed_deadline(&rearmed).unwrap();
        assert!(
            widened > measured,
            "an expiry must widen the next armed deadline: {widened:?} vs {measured:?}"
        );
    }

    #[test]
    fn a_pinned_deadline_overrides_the_measurement() {
        // `with_gather_timeout` remains, but as an explicit PIN for a scenario that must assert a
        // specific expiry — not as the operating default it used to be.
        let (line, secrets, publics) = line_of_three();
        let refs: Vec<&HybridKemPublic> = publics.iter().collect();
        let pinned = Duration::from_millis(250);
        let combiner_secret = secrets.into_iter().next().unwrap();
        let mut svc = ThresholdService::new(line[0], combiner_secret, line.clone(), 2)
            .with_gather_timeout(pinned);
        let intro = SealedIntro::seal(b"pinned", 2, &refs, b"seed-pin").unwrap();
        let effects = svc.step(Instant(0), Input::Message { from: line[2], frame: intro_frame(&intro) });
        assert_eq!(armed_deadline(&effects), Some(pinned), "the pin wins over the measured value");
    }
}
