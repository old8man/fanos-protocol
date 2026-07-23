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
use fanos_runtime::{Duration, Effect, Engine, Input, Instant, Notification, TimerToken};
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

/// Default deadline for a combiner to gather `threshold` PartialDecs before abandoning an intro.
const DEFAULT_GATHER_TIMEOUT: Duration = Duration::from_millis(2000);

/// How many recently-served intro ids to remember, to suppress a replayed intro re-serving (bounded).
const SERVED_MEMORY: usize = 256;

/// A combiner's in-flight gather for one intro: the sealed intro, the shares collected so far (deduped by
/// share index so a member cannot inflate the count by replying twice), and the timer that bounds it.
struct PendingIntro {
    intro: SealedIntro,
    shares: BTreeMap<u8, Share>,
    timer: TimerToken,
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
    gather_timeout: Duration,
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
            gather_timeout: DEFAULT_GATHER_TIMEOUT,
        }
    }

    /// Override the combiner's gather deadline (default 2 s).
    #[must_use]
    pub fn with_gather_timeout(mut self, timeout: Duration) -> Self {
        self.gather_timeout = timeout;
        self
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
            after: self.gather_timeout,
        });
        self.pending.insert(id, PendingIntro { intro, shares, timer });
        effects.extend(self.try_serve(now, id));
        effects
    }

    /// A combiner asked for our PartialDec of `intro`: compute and return it (if we are a line member).
    fn on_share_req(&self, combiner: Triple, intro: &SealedIntro) -> Vec<Effect> {
        let Some(i) = self.my_index else {
            return Vec::new();
        };
        let Some(share) = intro.member_partial(i, &self.secret) else {
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
            return Vec::new(); // unknown/late intro id — nothing to gather it into
        };
        pending.shares.entry(share.x()).or_insert(share);
        self.try_serve(now, id)
    }

    /// If the gather for `id` has reached `threshold` distinct shares, open the intro and surface the
    /// recovered request; else leave it pending. A failed open (below threshold / tamper) leaves the
    /// gather in place to await more shares.
    fn try_serve(&mut self, _now: Instant, id: IntroId) -> Vec<Effect> {
        let Some(pending) = self.pending.get(&id) else {
            return Vec::new();
        };
        if pending.shares.len() < self.threshold {
            return Vec::new();
        }
        let shares: Vec<Share> = pending.shares.values().cloned().collect();
        let Ok(request) = pending.intro.open(&shares) else {
            return Vec::new();
        };
        // Served: drop the gather and remember the id, then surface the request. The gather's deadline
        // timer may still fire later; `on_timer` finds no matching pending intro and harmlessly no-ops
        // (there is no CancelTimer effect — a stale tick is inert).
        self.pending.remove(&id);
        self.remember_served(id);
        vec![Effect::Notify(Notification::Delivered {
            from: ANONYMOUS,
            payload: request,
        })]
    }

    /// A gather deadline fired: drop the (still-incomplete) intro it bounds, freeing its slot.
    fn on_timer(&mut self, token: TimerToken) -> Vec<Effect> {
        if let Some(&id) = self
            .pending
            .iter()
            .find(|(_, p)| p.timer == token)
            .map(|(id, _)| id)
        {
            self.pending.remove(&id);
        }
        Vec::new()
    }
}

impl Engine for ThresholdService {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Message { from, frame } => {
                let Ok((decoded, _)) = decode_frame(&frame) else {
                    return Vec::new();
                };
                match decoded.frame_type() {
                    Some(FrameType::RdvIntro) => SealedIntro::from_wire(decoded.body)
                        .map_or_else(|_| Vec::new(), |intro| self.on_intro(now, intro)),
                    Some(FrameType::SvcShareReq) => SealedIntro::from_wire(decoded.body)
                        .map_or_else(|_| Vec::new(), |intro| self.on_share_req(from, &intro)),
                    Some(FrameType::SvcPartial) => decode_partial(decoded.body)
                        .map_or_else(Vec::new, |(id, share)| self.on_partial(now, id, share)),
                    _ => Vec::new(),
                }
            }
            Input::Timer(token) => self.on_timer(token),
            // A threshold-service member takes no application commands (it serves intros off the wire).
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
