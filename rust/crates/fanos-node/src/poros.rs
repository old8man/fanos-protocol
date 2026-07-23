//! # POROS (πόρος, "the way through") — derived-native censorship-resistant ingress.
//!
//! A censor's goal is *aporia* — no way through. POROS guarantees a way through **without fixed,
//! enumerable entry points**, derived from FANOS's own structure (the beacon-rotated line, the
//! threshold-hosted committee, the VRF-identity-bound coordinate) rather than ported from Tor's
//! fixed-bridge stack. It supersedes the earlier `bridge` module (whose framing leaned on Tor's
//! shared-random hashring). The design authority is `docs/design-anonymity-substrate.md` §6.
//!
//! The ingress is a function of **three inputs, each supplying one property** (the composite the
//! censorship-bootstrap audit found absent from the 2015–2026 literature):
//!
//! * the **unbiasable epoch beacon** → the ingress line rotates every epoch and is unpredictable in
//!   advance ([`ingress_line`]), so any blocklist goes stale each epoch and a censor cannot
//!   pre-position on a future line;
//! * a **community secret** → enumeration-resistance: a censor holding only the *public* beacon and a
//!   target cannot compute a community's ingress line without its shared secret;
//! * the requester's **VRF-identity coordinate** → Sybil/seed-extraction resistance: the admission
//!   proof is bound to the requester's identity-bound coordinate ([`IngressRequest`]), so it is
//!   **non-transferable** — a captured client's proof is useless to any other identity (unlike a DGA
//!   seed, which any captured client leaks whole).
//!
//! **Threshold-hosted, so seizing the entry reveals nothing.** The ingress descriptor (the reachable
//! entry peers) is not held by any single node: it is Shamir-**sharded across the ingress line's
//! `q+1` members** ([`shard_descriptor`]), reconstructable only by a threshold `t` of them
//! ([`recover_descriptor`]). Seizing `< t` members discloses neither the descriptor nor the ability
//! to serve it — the property no prior censorship-bootstrap system provides (the audit's flagged
//! novelty). This is the CALYPSO threshold-hosting primitive ([`fanos_calypso::hosting`]) applied to
//! a *rotating network entry-point* rather than a ledger secret.
//!
//! **The Sybil admission is honest about what it is.** The per-request proof of work
//! ([`solve_ingress_request`]) is a **rate-limiter, not a Sybil cap** (Boneh et al. CRYPTO'18: a
//! sequential-cost proof bounds identity-creation *rate*, never *total* identities). It keeps the
//! insider count `t` small — the Mahdian *FUN 2010* `Ω(t)` floor, not `n`, is what a censor must pay
//! to enumerate — but a true cap requires anchoring to a scarce resource: a fast-mixing trust graph
//! (SybilLimit `O(log n)`/edge) or proof-of-personhood. That anchor is the coherence/credential layer
//! ([[fanos-engineering-principles]]); POROS supplies the rate-limit and the threshold hosting, and
//! composes with it.
//!
//! **The irreducible residual, stated plainly** (the frontier does the same): a brand-new node with
//! no beacon and no peer still needs **one** out-of-band unblockable carrier to receive the first
//! beacon + community secret — minimized, not eliminated, by PROTEUS obfuscation
//! ([[proteus-morph-transforms]], the Parrot-is-Dead rule) and diverse high-collateral carriers.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fanos_calypso::hosting::{Share, recover_service_key, shard_service_key};
use fanos_calypso::pow;
use fanos_field::Field;
use fanos_geometry::{Line, TRIPLE_WIRE_LEN, Triple, decode_triple, encode_triple};
use fanos_primitives::codec::{Reader, put_seq, put_var_bytes};
use fanos_primitives::hash_labeled;
use fanos_rendezvous::{BeaconSeed, Epoch, combiner_for, meeting_line};
use fanos_runtime::{Duration, Effect, Engine, Input, Instant, TimerToken};
use fanos_wire::{FrameType, decode_frame, encode_frame};

use crate::config::Peer;

/// How many peer descriptors POROS hands out per request — a *few*, never the full set. One enumerator
/// learns at most `INGRESS_BUCKET` per (rotating) epoch, so it can never cheaply harvest `O(N)` (the
/// Lox/rdsys "no client learns `O(N)`" principle).
pub const INGRESS_BUCKET: usize = 3;

/// Domain separation for the POROS admission proof-of-work.
const POW_LABEL: &str = "FANOS-v1/poros-admission-pow";
/// Domain separation for the per-request bucket ranking.
const BUCKET_LABEL: &str = "FANOS-v1/poros-bucket";

/// The moving-target **ingress line** for a community sharing `community`, at `epoch` folded with the
/// beacon `SEED(epoch)`. Legitimate peers COMPUTE it; a censor cannot predict or pre-enumerate it, and
/// it rotates every epoch. Reuses the NYX meeting-line derivation (spec §5) — the ingress is a
/// first-class element of the routing geometry, not a published record.
#[must_use]
pub fn ingress_line<F: Field>(community: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Line<F> {
    meeting_line::<F>(community, epoch, beacon)
}

/// The **combiner** of the [`ingress_line`] — the canonical member a new node contacts, and where the
/// threshold hosts gather to serve. `None` only on a degenerate plane offering no combiner.
#[must_use]
pub fn ingress_combiner<F: Field>(
    community: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> Option<Triple> {
    combiner_for::<F>(ingress_line::<F>(community, epoch, beacon).coords())
}

/// The admission proof-of-work challenge — bound to `(community, epoch, beacon, requester)`. Folding
/// the requester's **VRF-identity coordinate** makes a solved proof **non-transferable**: it is valid
/// only for that requester, so a captured client's proof is useless to any other identity, and it
/// expires each epoch. This is the Sybil/seed-extraction-resistance input of the §6 derivation.
fn admission_challenge(
    community: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    requester: Triple,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(community.len() + 8 + 32 + TRIPLE_WIRE_LEN);
    buf.extend_from_slice(community);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(beacon.as_bytes());
    buf.extend_from_slice(&encode_triple(requester));
    hash_labeled(POW_LABEL, &buf)
}

/// A new node's request for ingress peers: its **identity-bound coordinate** plus a proof of work over
/// the epoch-and-identity-bound challenge. The coordinate is the requester's VRF-derived overlay
/// address (identity-bound by construction, [[coordinate-vrf-architecture]]); the network binds it to
/// the connection, and the proof binds to it — so the whole request is non-transferable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IngressRequest {
    /// The requester's VRF-identity coordinate (its overlay address).
    pub requester: Triple,
    /// The proof-of-work nonce solving the identity-and-epoch-bound challenge.
    pub nonce: u64,
}

impl IngressRequest {
    /// Canonical wire bytes: `requester(12) ‖ nonce(8)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRIPLE_WIRE_LEN + 8);
        out.extend_from_slice(&encode_triple(self.requester));
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let requester = decode_triple(r.bytes(TRIPLE_WIRE_LEN)?)?;
        let nonce = u64::from_be_bytes(r.array::<8>()?);
        r.finish()?;
        Some(Self { requester, nonce })
    }
}

/// Solve an ingress request (client side): find a PoW nonce over the identity-and-epoch-bound
/// challenge at `difficulty`. `requester` is this node's own VRF-identity coordinate.
#[must_use]
pub fn solve_ingress_request(
    requester: Triple,
    community: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    difficulty: u32,
) -> IngressRequest {
    let nonce = pow::solve(&admission_challenge(community, epoch, beacon, requester), difficulty);
    IngressRequest { requester, nonce }
}

/// Verify an ingress request's PoW (host side). The caller MUST additionally check that `req.requester`
/// matches the coordinate the request actually arrived from — the network binding that makes the
/// identity coordinate unforgeable — so a requester cannot claim another identity's coordinate.
#[must_use]
pub fn verify_ingress_request(
    req: &IngressRequest,
    community: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    difficulty: u32,
) -> bool {
    pow::verify(
        &admission_challenge(community, epoch, beacon, req.requester),
        req.nonce,
        difficulty,
    )
}

/// The **ingress descriptor** — the reachable entry peers a new node bootstraps from. It is never held
/// whole by any single node: it is threshold-sharded across the ingress line's members
/// ([`shard_descriptor`]) and reconstructed only by a threshold of them ([`recover_descriptor`]).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct IngressDescriptor {
    /// The reachable entry peers (a community's ingress set).
    pub peers: Vec<Peer>,
}

impl IngressDescriptor {
    /// Wire bytes for the whole descriptor (the plaintext that is Shamir-sharded across the line).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_seq(&mut out, self.peers.len(), &self.peers, |o, p| {
            put_var_bytes(o, &encode_peer(p));
        });
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        // Smallest element: a length-prefixed (4) minimal peer (coord 12 ‖ v4-tag 1 ‖ 4 ‖ port 2 = 19) = 23.
        let peers = r.seq(23, |r| decode_peer(r.var_bytes()?))?;
        r.finish()?;
        Some(Self { peers })
    }

    /// A per-request **bucket** of at most [`INGRESS_BUCKET`] peers, ranked by `H(requester ‖ nonce ‖
    /// peer)` so distinct requesters get distinct subsets and none learns the full set. Called by the
    /// combiner *after* a threshold of hosts have reconstructed the descriptor.
    #[must_use]
    pub fn bucket(&self, req: &IngressRequest) -> Vec<Peer> {
        let mut ranked: Vec<([u8; 32], Peer)> = self
            .peers
            .iter()
            .map(|p| (bucket_key(req, p), *p))
            .collect();
        ranked.sort_by_key(|(key, _)| *key);
        ranked.into_iter().take(INGRESS_BUCKET).map(|(_, p)| p).collect()
    }
}

/// **Threshold-shard** the ingress descriptor across a line of `line_size` members, so any `threshold`
/// of them can reconstruct it and no smaller set learns anything (spec §6, CALYPSO §12.3). Each share
/// is handed to one line member; seizing `< threshold` members reveals nothing about the entry peers.
/// `randomness` supplies the sharing polynomial (a CSPRNG draw in production).
///
/// # Errors
/// Returns `None` if the Shamir parameters are invalid (`threshold` zero or exceeding `line_size`).
#[must_use]
pub fn shard_descriptor(
    descriptor: &IngressDescriptor,
    threshold: u8,
    line_size: u8,
    randomness: &[u8],
) -> Option<Vec<Share>> {
    shard_service_key(&descriptor.to_bytes(), threshold, line_size, randomness).ok()
}

/// Reconstruct the ingress descriptor from `threshold` (or more) member shares — the combiner's step
/// once it has gathered a threshold of partials. `None` if fewer than the threshold are supplied, the
/// shares are inconsistent, or the reconstructed bytes are not a valid descriptor.
#[must_use]
pub fn recover_descriptor(shares: &[Share]) -> Option<IngressDescriptor> {
    let bytes = recover_service_key(shares).ok()?;
    IngressDescriptor::from_bytes(&bytes)
}

/// The bucket-ranking key for `peer` under a request — keyed on the requester coordinate *and* the
/// nonce, so the subset a requester learns is bound to its own (non-transferable) identity.
fn bucket_key(req: &IngressRequest, peer: &Peer) -> [u8; 32] {
    let mut buf = encode_triple(req.requester).to_vec();
    buf.extend_from_slice(&req.nonce.to_be_bytes());
    buf.extend_from_slice(&encode_peer(peer));
    hash_labeled(BUCKET_LABEL, &buf)
}

/// Wire-encode a peer: `coord(12) ‖ ip-tag(1) ‖ ip ‖ port(2)`.
fn encode_peer(peer: &Peer) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRIPLE_WIRE_LEN + 1 + 16 + 2);
    out.extend_from_slice(&encode_triple(peer.coord));
    match peer.addr.ip() {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&peer.addr.port().to_be_bytes());
    out
}

/// Decode a peer from [`encode_peer`].
fn decode_peer(bytes: &[u8]) -> Option<Peer> {
    let mut r = Reader::new(bytes);
    let coord = decode_triple(r.bytes(TRIPLE_WIRE_LEN)?)?;
    let ip = match r.u8()? {
        4 => IpAddr::V4(Ipv4Addr::from(r.array::<4>()?)),
        6 => IpAddr::V6(Ipv6Addr::from(r.array::<16>()?)),
        _ => return None,
    };
    let port = u16::from_be_bytes(r.array::<2>()?);
    r.finish()?;
    Some(Peer { coord, addr: SocketAddr::new(ip, port) })
}

/// A POROS combiner's **response** to a requester — the bounded bucket of entry peers it served (never
/// the full set). Encoded like an [`IngressDescriptor`]: a length-prefixed peer sequence.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct IngressResponse {
    /// At most [`INGRESS_BUCKET`] entry peers, varying per requester.
    pub peers: Vec<Peer>,
}

impl IngressResponse {
    /// Canonical wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_seq(&mut out, self.peers.len(), &self.peers, |o, p| {
            put_var_bytes(o, &encode_peer(p));
        });
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let peers = r.seq(23, |r| decode_peer(r.var_bytes()?))?;
        r.finish()?;
        Some(Self { peers })
    }
}

// --- The threshold-hosted ingress engine ---

/// Default deadline for a POROS combiner to gather a threshold of descriptor shares.
const DEFAULT_GATHER_TIMEOUT: Duration = Duration::from_millis(2000);
/// Default cap on concurrently-gathering requests — a bound on combiner state against a request flood.
const DEFAULT_MAX_PENDING: usize = 256;

/// A combiner's in-flight gather for one requester: the request, the descriptor shares collected so far
/// (deduped by share index so a member cannot inflate the count), and the timer that bounds it.
struct PendingServe {
    req: IngressRequest,
    shares: BTreeMap<u8, Share>,
    timer: TimerToken,
}

/// One member of a **threshold-hosted POROS ingress line**, as a sans-I/O engine. It holds only *one*
/// descriptor share (dealt via [`shard_descriptor`] for this epoch's line), so seizing it discloses
/// nothing; a threshold `t` of members collectively reconstruct the descriptor and serve. The combiner
/// exchange mirrors [`ThresholdService`](crate::ThresholdService) and the mixnet router:
///
/// 1. A requester sends a [`PorosRequest`](FrameType::PorosRequest) (its identity-bound
///    [`IngressRequest`]) to the [`ingress_combiner`]. The combiner verifies the PoW, seeds its own
///    share, and fans a [`PorosShareReq`](FrameType::PorosShareReq) (the requester tag) to the line.
/// 2. Each member replies with its descriptor share in a [`PorosShare`](FrameType::PorosShare).
/// 3. Once the combiner holds `≥ t` shares it reconstructs the descriptor ([`recover_descriptor`]),
///    buckets it for the requester, and sends the [`PorosResponse`](FrameType::PorosResponse). It then
///    discards the reconstructed descriptor — the at-rest "seize `< t` reveals nothing" property is
///    unchanged; only a transient serve-time reconstruction ever lives at the combiner.
pub struct PorosHost {
    coord: Triple,
    share: Share,
    line: Vec<Triple>,
    threshold: usize,
    community: Vec<u8>,
    epoch: Epoch,
    beacon: BeaconSeed,
    difficulty: u32,
    pending: BTreeMap<Triple, PendingServe>,
    seq: u64,
    max_pending: usize,
    gather_timeout: Duration,
}

impl PorosHost {
    /// A line member at `coord` holding its dealt descriptor `share`, hosting the ingress
    /// `threshold`-of-`line.len()` for `(community, epoch, beacon)` at PoW `difficulty`. `line` is every
    /// member's coordinate in the order [`shard_descriptor`] dealt shares (position = share index).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coord: Triple,
        share: Share,
        line: Vec<Triple>,
        threshold: usize,
        community: Vec<u8>,
        epoch: Epoch,
        beacon: BeaconSeed,
        difficulty: u32,
    ) -> Self {
        Self {
            coord,
            share,
            line,
            threshold,
            community,
            epoch,
            beacon,
            difficulty,
            pending: BTreeMap::new(),
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

    /// The number of requests currently gathering (combiner state), for tests/observability.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// A request arrived at us as the combiner: verify its PoW, seed our own share, fan share-requests to
    /// the rest of the line. A bad proof, wrong epoch/community, or a duplicate/flood is dropped.
    fn on_request(&mut self, now: Instant, req: IngressRequest) -> Vec<Effect> {
        if !verify_ingress_request(&req, &self.community, self.epoch, &self.beacon, self.difficulty) {
            return Vec::new();
        }
        if self.pending.contains_key(&req.requester) || self.pending.len() >= self.max_pending {
            return Vec::new();
        }
        let mut shares = BTreeMap::new();
        shares.insert(self.share.x(), self.share.clone());
        let sharereq = encode(FrameType::PorosShareReq, &encode_triple(req.requester));
        let mut effects: Vec<Effect> = self
            .line
            .iter()
            .filter(|&&m| m != self.coord)
            .map(|&m| Effect::Send { to: m, frame: sharereq.clone() })
            .collect();
        let timer = TimerToken(self.seq);
        self.seq = self.seq.wrapping_add(1);
        effects.push(Effect::ArmTimer { token: timer, after: self.gather_timeout });
        let requester = req.requester;
        self.pending.insert(requester, PendingServe { req, shares, timer });
        effects.extend(self.try_serve(now, requester));
        effects
    }

    /// A combiner asked for our descriptor share for `requester`: return our static share, tagged with the
    /// requester so the combiner correlates it to the right gather.
    fn on_share_req(&self, combiner: Triple, requester: Triple) -> Vec<Effect> {
        vec![Effect::Send {
            to: combiner,
            frame: encode(FrameType::PorosShare, &encode_share_reply(requester, &self.share)),
        }]
    }

    /// A member's descriptor share arrived: fold it into the matching gather and retry.
    fn on_share(&mut self, now: Instant, requester: Triple, share: Share) -> Vec<Effect> {
        let Some(pending) = self.pending.get_mut(&requester) else {
            return Vec::new();
        };
        pending.shares.entry(share.x()).or_insert(share);
        self.try_serve(now, requester)
    }

    /// If the gather for `requester` holds a threshold of shares, reconstruct the descriptor, bucket it,
    /// and send the response; else leave it pending. A failed reconstruction awaits more shares.
    fn try_serve(&mut self, _now: Instant, requester: Triple) -> Vec<Effect> {
        let Some(pending) = self.pending.get(&requester) else {
            return Vec::new();
        };
        if pending.shares.len() < self.threshold {
            return Vec::new();
        }
        let shares: Vec<Share> = pending.shares.values().cloned().collect();
        let Some(descriptor) = recover_descriptor(&shares) else {
            return Vec::new();
        };
        let response = IngressResponse { peers: descriptor.bucket(&pending.req) };
        self.pending.remove(&requester);
        vec![Effect::Send {
            to: requester,
            frame: encode(FrameType::PorosResponse, &response.to_bytes()),
        }]
    }

    /// A gather deadline fired: drop the still-incomplete request it bounds, freeing its slot.
    fn on_timer(&mut self, token: TimerToken) -> Vec<Effect> {
        if let Some(&requester) = self
            .pending
            .iter()
            .find(|(_, p)| p.timer == token)
            .map(|(r, _)| r)
        {
            self.pending.remove(&requester);
        }
        Vec::new()
    }
}

impl Engine for PorosHost {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Message { from, frame } => {
                let Ok((decoded, _)) = decode_frame(&frame) else {
                    return Vec::new();
                };
                match decoded.frame_type() {
                    Some(FrameType::PorosRequest) => IngressRequest::from_bytes(decoded.body)
                        .map_or_else(Vec::new, |req| self.on_request(now, req)),
                    Some(FrameType::PorosShareReq) => decoded
                        .body
                        .get(..TRIPLE_WIRE_LEN)
                        .and_then(decode_triple)
                        .map_or_else(Vec::new, |requester| self.on_share_req(from, requester)),
                    Some(FrameType::PorosShare) => decode_share_reply(decoded.body)
                        .map_or_else(Vec::new, |(requester, share)| self.on_share(now, requester, share)),
                    _ => Vec::new(),
                }
            }
            Input::Timer(token) => self.on_timer(token),
            // A POROS host takes no application commands — it serves requests off the wire.
            Input::Command(_) => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord
    }
}

/// Build the [`PorosRequest`](FrameType::PorosRequest) frame a new node sends to the ingress combiner.
#[must_use]
pub fn request_frame(req: &IngressRequest) -> Vec<u8> {
    encode(FrameType::PorosRequest, &req.to_bytes())
}

/// Encode a wire frame with the given type and body.
fn encode(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(ty.code(), body, &mut out);
    out
}

/// A `PorosShare` body: `requester(12) ‖ x(1) ‖ y`.
fn encode_share_reply(requester: Triple, share: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRIPLE_WIRE_LEN + 1 + share.y().len());
    out.extend_from_slice(&encode_triple(requester));
    out.push(share.x());
    out.extend_from_slice(share.y());
    out
}

fn decode_share_reply(body: &[u8]) -> Option<(Triple, Share)> {
    let requester = decode_triple(body.get(..TRIPLE_WIRE_LEN)?)?;
    let (&x, y) = body.get(TRIPLE_WIRE_LEN..)?.split_first()?;
    Some((requester, Share::new(x, y.to_vec())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F2;
    use fanos_geometry::Point;

    fn coord(i: usize) -> Triple {
        Point::<F2>::at(i % 7).coords()
    }

    fn descriptor(n: usize) -> IngressDescriptor {
        IngressDescriptor {
            peers: (0..n)
                .map(|i| Peer {
                    coord: coord(i),
                    addr: SocketAddr::from(([10, 0, 0, i as u8], 9000 + i as u16)),
                })
                .collect(),
        }
    }

    #[test]
    fn the_ingress_line_is_deterministic_and_rotates_with_the_epoch() {
        use std::collections::BTreeSet;
        let beacon = BeaconSeed::new([0x7b; 32]);
        let at = |c: &[u8], e: u64| ingress_line::<F2>(c, Epoch::new(e), &beacon).coords();
        assert_eq!(at(b"community", 1), at(b"community", 1), "deterministic: same inputs → same line");
        assert!(ingress_combiner::<F2>(b"community", Epoch::new(1), &beacon).is_some());
        // Across epochs the ingress line rotates — a blocklist goes stale each epoch.
        let lines: BTreeSet<_> = (1..=8).map(|e| at(b"community", e)).collect();
        assert!(lines.len() > 1, "the ingress line rotates across epochs");
        // A different community rendezvouses differently (the community-secret enumeration-resistance input).
        let other: BTreeSet<_> = (1..=8).map(|e| at(b"other-community", e)).collect();
        assert_ne!(lines, other, "distinct communities have distinct ingress rotations");
    }

    #[test]
    fn an_admission_proof_is_identity_bound_and_non_transferable() {
        let beacon = BeaconSeed::new([0x11; 32]);
        let (community, epoch, difficulty) = (b"comm".as_slice(), Epoch::new(3), 8);
        let alice = coord(1);
        let bob = coord(2);

        // Alice solves a proof bound to HER coordinate.
        let req = solve_ingress_request(alice, community, epoch, &beacon, difficulty);
        assert_eq!(req.requester, alice);
        assert!(verify_ingress_request(&req, community, epoch, &beacon, difficulty), "Alice's own proof verifies");

        // The SAME nonce presented for Bob's coordinate does not verify — the proof is non-transferable.
        let stolen = IngressRequest { requester: bob, nonce: req.nonce };
        assert!(
            !verify_ingress_request(&stolen, community, epoch, &beacon, difficulty),
            "a captured proof is useless to another identity (VRF-identity binding)",
        );
        // It also expires next epoch and is community-bound.
        assert!(!verify_ingress_request(&req, community, Epoch::new(4), &beacon, difficulty), "expires each epoch");
        assert!(!verify_ingress_request(&req, b"other", epoch, &beacon, difficulty), "community-bound");
        // Round-trips on the wire.
        assert_eq!(IngressRequest::from_bytes(&req.to_bytes()).unwrap(), req);
    }

    #[test]
    fn the_descriptor_is_threshold_hosted_seizing_below_t_reveals_nothing() {
        // The ingress descriptor is sharded 2-of-3 across a line's members; ANY 2 reconstruct it, and
        // ONE share alone reveals nothing (below-threshold zero-knowledge).
        let desc = descriptor(10);
        let (threshold, line_size) = (2u8, 3u8);
        // Byte-wise Shamir needs (threshold-1) random bytes per secret byte; size the polynomial
        // randomness to the descriptor length (a CSPRNG draw in production).
        let randomness = vec![0x5Au8; desc.to_bytes().len() * usize::from(threshold - 1) + 8];
        let shares = shard_descriptor(&desc, threshold, line_size, &randomness).expect("valid sharing");
        assert_eq!(shares.len(), usize::from(line_size), "one share per line member");

        // Any threshold of members reconstructs the exact descriptor.
        assert_eq!(recover_descriptor(&shares[0..2]), Some(desc.clone()), "members 0,1 reconstruct");
        assert_eq!(recover_descriptor(&shares[1..3]), Some(desc.clone()), "members 1,2 reconstruct");

        // A single seized share cannot reconstruct — recovery of a 1-subset does not yield the descriptor.
        // (Shamir needs `threshold` distinct shares; one is below threshold.)
        let one = recover_descriptor(&shares[0..1]);
        assert_ne!(one, Some(desc.clone()), "one seized share does not disclose the entry peers");
    }

    #[test]
    fn a_bucket_is_at_most_bucket_size_and_varies_by_requester() {
        let desc = descriptor(12);
        let beacon = BeaconSeed::GENESIS;
        let (community, epoch, difficulty) = (b"c".as_slice(), Epoch::new(1), 1);
        // Two distinct requesters get distinct, bounded buckets from the SAME reconstructed descriptor —
        // so an enumerator cannot harvest the full set from one identity's request.
        let a = solve_ingress_request(coord(1), community, epoch, &beacon, difficulty);
        let b = solve_ingress_request(coord(2), community, epoch, &beacon, difficulty);
        let bucket_a = desc.bucket(&a);
        let bucket_b = desc.bucket(&b);
        assert!(bucket_a.len() <= INGRESS_BUCKET && !bucket_a.is_empty());
        assert_ne!(bucket_a, bucket_b, "distinct requesters surface distinct buckets");
        // The descriptor round-trips on the wire.
        assert_eq!(IngressDescriptor::from_bytes(&desc.to_bytes()).unwrap(), desc);
    }

    #[test]
    fn a_threshold_of_hosts_reconstructs_and_serves_a_bucket() {
        use fanos_runtime::{Effect, Input, Instant};

        // Deal the descriptor 2-of-3 across a 3-member ingress line; build a PorosHost per member.
        let desc = descriptor(10);
        let threshold = 2usize;
        let community = b"comm".to_vec();
        let (epoch, difficulty) = (Epoch::new(2), 4);
        let beacon = BeaconSeed::new([0x33; 32]);
        let line: Vec<Triple> = (0..3).map(coord).collect();
        let randomness = vec![0x21u8; desc.to_bytes().len() * (threshold - 1) + 8];
        let shares = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let host = |i: usize| {
            PorosHost::new(
                line[i],
                shares[i].clone(),
                line.clone(),
                threshold,
                community.clone(),
                epoch,
                beacon,
                difficulty,
            )
        };
        let mut combiner = host(0); // the requester contacts line[0], the ingress combiner
        let mut member1 = host(1);

        // A requester solves an identity-bound PoW and sends the request to the combiner.
        let requester = coord(5);
        let req = solve_ingress_request(requester, &community, epoch, &beacon, difficulty);
        let fanned = combiner.step(
            Instant(0),
            Input::Message { from: requester, frame: request_frame(&req) },
        );
        assert_eq!(combiner.pending(), 1, "the combiner has its own share and is gathering the rest");

        // The combiner fanned a share-request to member 1; member 1 replies with its descriptor share.
        let share_req = fanned
            .iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if *to == line[1] => Some(frame.clone()),
                _ => None,
            })
            .expect("the combiner fanned a share-request to member 1");
        let reply = member1.step(Instant(1), Input::Message { from: line[0], frame: share_req });
        let share_frame = reply
            .iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if *to == line[0] => Some(frame.clone()),
                _ => None,
            })
            .expect("member 1 returned its descriptor share to the combiner");

        // The share reaches the combiner: it now holds t = 2 shares, reconstructs, and serves the bucket.
        let served = combiner.step(Instant(2), Input::Message { from: line[1], frame: share_frame });
        let response = served
            .iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if *to == requester => {
                    let (decoded, _) = decode_frame(frame).ok()?;
                    if decoded.frame_type() == Some(FrameType::PorosResponse) {
                        IngressResponse::from_bytes(decoded.body)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .expect("the combiner served a PorosResponse to the requester");

        assert!(
            !response.peers.is_empty() && response.peers.len() <= INGRESS_BUCKET,
            "a bounded, non-empty bucket is served",
        );
        assert_eq!(
            response.peers,
            desc.bucket(&req),
            "the served bucket equals the descriptor's bucket for this requester (correct reconstruction)",
        );
        assert_eq!(combiner.pending(), 0, "the gather completed and freed its slot");
    }

    #[test]
    fn a_request_with_a_bad_proof_of_work_is_dropped() {
        use fanos_runtime::{Input, Instant};
        let desc = descriptor(6);
        let threshold = 2usize;
        let community = b"c".to_vec();
        let (epoch, difficulty) = (Epoch::new(1), 8);
        let beacon = BeaconSeed::GENESIS;
        let line: Vec<Triple> = (0..3).map(coord).collect();
        let randomness = vec![0x9u8; desc.to_bytes().len() * (threshold - 1) + 8];
        let shares = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let mut combiner = PorosHost::new(
            line[0],
            shares[0].clone(),
            line.clone(),
            threshold,
            community.clone(),
            epoch,
            beacon,
            difficulty,
        );
        // A request whose nonce does not solve the challenge is refused: no gather is opened, no share
        // requests are fanned — the PoW gate holds before any threshold work is done.
        let bad = IngressRequest { requester: coord(4), nonce: 0 };
        let effects = combiner.step(
            Instant(0),
            Input::Message { from: coord(4), frame: request_frame(&bad) },
        );
        assert!(effects.is_empty(), "an unsolved request produces no effects");
        assert_eq!(combiner.pending(), 0, "and opens no gather");
    }
}
