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

/// High bit marking a *mixing* timer token, distinguishing it from a gather-deadline token (which
/// carries a small request id). No real request id reaches `2^63`.
const MIX_FLAG: u64 = 1 << 63;

/// Cap on distinct candidate shares a combiner will hold for one pending peel. A line has only `q + 1`
/// real members, so honest operation never approaches this; the cap bounds memory (and the peel search
/// below) against an attacker flooding forged `TAG_REP` replies.
const MAX_CANDIDATES: usize = 64;

/// Cap on the number of `t`-subsets tried while searching for a set of shares that peels. Honest
/// operation succeeds on the first (all-honest) subset; this bounds the CPU cost when up to `t − 1`
/// forged shares are mixed in and several subsets must be tried.
const MAX_PEEL_ATTEMPTS: usize = 256;

/// A combiner's in-flight peel: the layer being gathered, its line, its member count (the valid share
/// index bound), and the candidate partials collected so far.
struct Pending {
    line: Triple,
    onion: Vec<u8>,
    shares: Vec<Share>,
    member_count: usize,
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
    /// Mean Poisson mixing delay before forwarding a peeled hop (0 ⇒ forward immediately). Holding
    /// each forward for an independent exponential delay reorders a batch, breaking the timing
    /// correlation an observer could otherwise use to link a hop's in- and out-flows (spec §L5/V7).
    mean_delay: Duration,
    /// Forwards held for their sampled mix delay, keyed by mix id (timer token = `MIX_FLAG | id`).
    mix_pending: BTreeMap<u64, (Triple, Vec<u8>)>,
    mix_seq: u64,
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
            mean_delay: Duration(0),
            mix_pending: BTreeMap::new(),
            mix_seq: 0,
        }
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

    /// Forward `frame` to `to` — immediately, or (when mixing is on) held for a sampled exponential
    /// mix delay so a batch of forwards leaves reordered.
    fn forward_send(&mut self, to: Triple, frame: Vec<u8>) -> Vec<Effect> {
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

    /// Sample an exponential mixing delay with the configured mean (`−mean·ln u`), seeded per node.
    fn sample_delay(&self, id: u64) -> Duration {
        let mut data = self
            .coord
            .coords()
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect::<Vec<u8>>();
        data.extend_from_slice(&id.to_be_bytes());
        let digest = fanos_crypto::hash_labeled("FANOS-v1/threshold-mix", &data);
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
            && let Some(share) = threshold::member_partial(&onion, i, &self.kem_secret)
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
                line,
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
        let Some(share) = threshold::member_partial(onion, i, &self.kem_secret) else {
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
        if share.x == 0 || usize::from(share.x) > pending.member_count {
            return Vec::new();
        }
        // De-duplicate only *exact* (x, y) repeats. Crucially we do NOT drop a differing `y` at an
        // already-seen `x`: a forged share must not be able to evict or pre-empt the honest member's
        // real reply — both are kept as candidates and the peel search below picks the set that works.
        if pending
            .shares
            .iter()
            .any(|s| s.x == share.x && s.y == share.y)
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
        let pending = self.pending.remove(&req_id)?;
        let _ = pending.line;
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
        let subset: Vec<Share> = chosen.iter().filter_map(|&i| shares.get(i).cloned()).collect();
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
            .any(|&j| shares.get(j).is_some_and(|s| s.x == candidate.x))
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
                if token & MIX_FLAG != 0 {
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

        // KEM keypair per member, in points_on (seal) order.
        let (sec0, pub0) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x5A, 0]));
        let (sec1, pub1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x5A, 1]));
        let (_sec2, pub2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x5A, 2]));
        let pubs = [&pub0, &pub1, &pub2];
        let hop = HopLine {
            line: line_coord,
            members: &pubs,
        };
        let payload = b"anon-payload";
        let onion = seal_onion(&[hop], t as u8, payload, b"seed-router").unwrap();

        // The combiner is member 0.
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let mut router = ThresholdRouter::<F2>::new(combiner, sec0, t);

        // Deliver the onion: the combiner seeds its own share and fans out requests — no peel yet.
        let onion_frame = launch_frame(line_coord, &onion);
        let e0 = router.step(
            Instant(0),
            Input::Message {
                from: [9, 9, 9],
                frame: onion_frame,
            },
        );
        assert!(!has_delivery(&e0, payload), "one share (t=2) cannot deliver");

        // The honest member-1 reply (the real partial) and a forgery at the same index with mangled y.
        let honest1 = member_partial(&onion, 1, &sec1).unwrap();
        let forged = Share {
            x: honest1.x,
            y: honest1.y.iter().map(|b| b ^ 0xFF).collect(),
        };
        assert_ne!(forged.y, honest1.y, "the forgery differs from the real share");

        // Inject the forgery first: it reaches the threshold count but cannot peel, and must NOT be
        // allowed to force a (wrong) delivery or discard the pending peel.
        let e1 = router.step(
            Instant(1),
            Input::Message {
                from: [8, 8, 8],
                frame: encode_rep(0, &forged),
            },
        );
        assert!(!has_delivery(&e1, payload), "a forged share does not complete the hop");

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
        let (sec0, pub0) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7C, 0]));
        let (_s1, pub1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7C, 1]));
        let (_s2, pub2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7C, 2]));
        let pubs = [&pub0, &pub1, &pub2];
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
        let mut router = ThresholdRouter::<F2>::new(combiner, sec0, t);
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
                    frame: encode_rep(0, &Share { x: bad_x, y: alloc::vec![0u8; 8] }),
                },
            );
            assert!(e.is_empty(), "an out-of-range share index (x={bad_x}) is dropped");
        }
    }
}
