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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_crypto::shamir::Share;
use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point, Triple};
use fanos_pqcrypto::HybridKemSecret;
use fanos_runtime::{Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

use crate::threshold::{self, ThresholdPeel};

/// Internal frame tags (the onion travels as opaque overlay bytes; these are its sub-types).
const TAG_ONION: u8 = 0;
const TAG_REQ: u8 = 1;
const TAG_REP: u8 = 2;

/// The anonymous-source sentinel in a delivery notification (the endpoint learns no originator).
pub const ANONYMOUS: Triple = [0, 0, 0];

/// Default deadline for a combiner to gather `t` partials before abandoning a hop.
const DEFAULT_GATHER_TIMEOUT: Duration = Duration::from_millis(2000);

/// A combiner's in-flight peel: the layer being gathered, its line, and the partials collected.
struct Pending {
    line: Triple,
    onion: Vec<u8>,
    shares: Vec<Share>,
    contributors: Vec<usize>,
}

/// A node that routes threshold-onion hops — combiner for hops addressed to it, line member for
/// requests from other combiners.
pub struct ThresholdRouter<F: Field> {
    coord: Point<F>,
    kem_secret: HybridKemSecret,
    threshold: usize,
    gather_timeout: Duration,
    pending: BTreeMap<u64, Pending>,
    seq: u64,
}

impl<F: Field> ThresholdRouter<F> {
    /// A router at `coord` with its hybrid KEM secret, peeling hops that need a threshold of `t`.
    #[must_use]
    pub fn new(coord: Point<F>, kem_secret: HybridKemSecret, threshold: usize) -> Self {
        Self {
            coord,
            kem_secret,
            threshold,
            gather_timeout: DEFAULT_GATHER_TIMEOUT,
            pending: BTreeMap::new(),
            seq: 0,
        }
    }

    /// Override the combiner's partial-gathering deadline (default 2 s).
    #[must_use]
    pub fn with_gather_timeout(mut self, timeout: Duration) -> Self {
        self.gather_timeout = timeout;
        self
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

        let mut shares = Vec::new();
        let mut contributors = Vec::new();
        if let Some(i) = self.my_index(line)
            && let Some(share) = threshold::member_partial(&onion, i, &self.kem_secret)
        {
            contributors.push(usize::from(share.x)); // dedup by Shamir x-coordinate, as replies do
            shares.push(share);
        }

        let mut effects = Vec::new();
        let me = self.coord.coords();
        for member in Self::line_members(line) {
            if member != me {
                effects.push(Effect::Send {
                    to: member,
                    frame: encode_req(req_id, me, line, &onion),
                });
            }
        }
        self.pending.insert(
            req_id,
            Pending {
                line,
                onion,
                shares,
                contributors,
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
        let Some(share) = threshold::member_partial(onion, i, &self.kem_secret) else {
            return Vec::new();
        };
        alloc::vec![Effect::Send {
            to: combiner,
            frame: encode_rep(req_id, &share),
        }]
    }

    /// Handle a partial-decryption reply: fold it in and peel if we now have a threshold.
    fn on_reply(&mut self, req_id: u64, share: Share) -> Vec<Effect> {
        let Some(pending) = self.pending.get_mut(&req_id) else {
            return Vec::new(); // unknown / already-peeled request
        };
        // De-duplicate by share index so one member cannot be counted twice.
        if pending.contributors.contains(&usize::from(share.x)) {
            return Vec::new();
        }
        pending.contributors.push(usize::from(share.x));
        pending.shares.push(share);
        self.try_peel(req_id).unwrap_or_default()
    }

    /// If a pending peel has reached the threshold, peel it and act on the outcome.
    fn try_peel(&mut self, req_id: u64) -> Option<Vec<Effect>> {
        let pending = self.pending.get(&req_id)?;
        if pending.shares.len() < self.threshold {
            return None;
        }
        let outcome = threshold::peel_onion_with_shares(&pending.onion, &pending.shares);
        let pending = self.pending.remove(&req_id)?;
        let _ = pending.line;
        Some(match outcome {
            Ok(ThresholdPeel::Deliver { payload }) => {
                alloc::vec![Effect::Notify(Notification::Delivered {
                    from: ANONYMOUS,
                    payload,
                })]
            }
            Ok(ThresholdPeel::Forward { next, onion }) => Self::combiner_of(next)
                .map(|c| {
                    // Re-pad the inner onion to the constant bucket so the forwarded packet is the
                    // same size as the one we received — no cross-hop size correlation.
                    let padded = threshold::pad_onion(&onion).unwrap_or(onion);
                    alloc::vec![Effect::Send {
                        to: c,
                        frame: encode_onion(next, &padded),
                    }]
                })
                .unwrap_or_default(),
            Err(_) => Vec::new(), // malformed / below threshold → drop
        })
    }
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
            // The gather deadline fired: drop an incomplete pending peel.
            Input::Timer(TimerToken(req_id)) => {
                self.pending.remove(&req_id);
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

fn coord_bytes(c: Triple) -> [u8; 12] {
    let mut out = [0u8; 12];
    let (chunks, _) = out.as_chunks_mut::<4>();
    for (chunk, w) in chunks.iter_mut().zip(c) {
        *chunk = w.to_be_bytes();
    }
    out
}

fn coord_from(b: &[u8]) -> Option<Triple> {
    Some([
        u32::from_be_bytes(b.get(0..4)?.try_into().ok()?),
        u32::from_be_bytes(b.get(4..8)?.try_into().ok()?),
        u32::from_be_bytes(b.get(8..12)?.try_into().ok()?),
    ])
}

fn encode_onion(line: Triple, onion: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 12 + onion.len());
    v.push(TAG_ONION);
    v.extend_from_slice(&coord_bytes(line));
    v.extend_from_slice(onion);
    v
}

fn decode_onion(body: &[u8]) -> Option<(Triple, Vec<u8>)> {
    let line = coord_from(body.get(..12)?)?;
    Some((line, body.get(12..)?.to_vec()))
}

fn encode_req(req_id: u64, combiner: Triple, line: Triple, onion: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 12 + 12 + onion.len());
    v.push(TAG_REQ);
    v.extend_from_slice(&req_id.to_be_bytes());
    v.extend_from_slice(&coord_bytes(combiner));
    v.extend_from_slice(&coord_bytes(line));
    v.extend_from_slice(onion);
    v
}

fn decode_req(body: &[u8]) -> Option<(u64, Triple, Triple, &[u8])> {
    let req_id = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let combiner = coord_from(body.get(8..20)?)?;
    let line = coord_from(body.get(20..32)?)?;
    Some((req_id, combiner, line, body.get(32..)?))
}

fn encode_rep(req_id: u64, share: &Share) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 1 + share.y.len());
    v.push(TAG_REP);
    v.extend_from_slice(&req_id.to_be_bytes());
    v.push(share.x);
    v.extend_from_slice(&share.y);
    v
}

fn decode_rep(body: &[u8]) -> Option<(u64, Share)> {
    let req_id = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let x = *body.get(8)?;
    let y = body.get(9..)?.to_vec();
    Some((req_id, Share { x, y }))
}
