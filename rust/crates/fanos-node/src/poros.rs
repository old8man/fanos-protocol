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
//! ([`crate::sybil`]). Both gates now compose in the host: [`PorosHost::with_admission`] takes the
//! trust layer's admitted coordinate set, and [`on_request`](PorosHost) serves a requester only if it
//! *both* clears the PoW (rate) *and* is in the admitted set (cap) — so a flood of freshly-minted
//! identities behind a sparse trust cut cannot buy ingress no matter how much work it burns. POROS
//! consumes the admitted *set*, not the graph, so it stays decoupled from the specific cap mechanism.
//!
//! **The irreducible residual, stated plainly** (the frontier does the same): a brand-new node with
//! no beacon and no peer still needs **one** out-of-band unblockable carrier to receive the first
//! beacon + community secret — minimized, not eliminated, by PROTEUS obfuscation
//! ([[proteus-morph-transforms]], the Parrot-is-Dead rule) and diverse high-collateral carriers.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fanos_calypso::hosting::{
    SealedShare, Share, combine_reshares, deal_service_key, open_service_share, recover_service_key,
    shard_service_key,
};
use fanos_calypso::pow;
use fanos_field::Field;
use fanos_geometry::{Line, TRIPLE_WIRE_LEN, Triple, decode_triple, encode_triple};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret};
use fanos_primitives::codec::{Reader, put_seq, put_var_bytes};
use fanos_primitives::hash_labeled;
use fanos_rendezvous::{BeaconSeed, Epoch, combiner_for, meeting_line};
use fanos_runtime::{Duration, Effect, Engine, Input, Instant, TimerToken};
use fanos_wire::{FrameType, Wire, decode_frame, encode_frame};

use crate::config::Peer;

/// How many peer descriptors POROS hands out per request — a *few*, never the full set. One enumerator
/// learns at most `INGRESS_BUCKET` per (rotating) epoch, so it can never cheaply harvest `O(N)` (the
/// Lox/rdsys "no client learns `O(N)`" principle).
pub const INGRESS_BUCKET: usize = 3;

/// Domain separation for the POROS admission proof-of-work.
const POW_LABEL: &str = "FANOS-v1/poros-admission-pow";
/// Domain separation for the per-request bucket ranking.
const BUCKET_LABEL: &str = "FANOS-v1/poros-bucket";
/// Domain separation for the **descriptor commitment** — the public binding a rotated line verifies its
/// reconstructed descriptor against, so a corrupted reshare can never serve a silently-wrong descriptor.
const DESCRIPTOR_COMMIT_LABEL: &str = "FANOS-v1/poros-descriptor-commit";

/// The public **commitment** to an ingress descriptor: `H(descriptor bytes)`. Preimage-resistant, so it
/// discloses nothing about the (semi-secret, per-requester-bucketed) descriptor, yet binds it — the old line
/// publishes it, and a rotated line checks its reconstruction against it (see
/// [`PorosHost::with_descriptor_commitment`]). Rotation preserves the descriptor, so the commitment is
/// epoch-invariant.
#[must_use]
pub fn descriptor_commitment(descriptor: &IngressDescriptor) -> [u8; 32] {
    hash_labeled(DESCRIPTOR_COMMIT_LABEL, &descriptor.to_bytes())
}

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

/// **One old line member's resharing contribution** when the ingress line rotates for a new epoch: a fresh
/// `threshold`-of-`new_line_size` sharing of its OWN descriptor `share` over the new line's positions. The
/// member computes this locally and sends sub-share `k` to new member `k + 1` — no member ever reconstructs
/// the descriptor. `None` on invalid Shamir parameters. See [`combine_descriptor_reshares`].
#[must_use]
pub fn reshare_descriptor_share(
    share: &Share,
    threshold: u8,
    new_line_size: u8,
    randomness: &[u8],
) -> Option<Vec<Share>> {
    shard_service_key(share.y(), threshold, new_line_size, randomness).ok()
}

/// **A new line member's rotated share**: combine the resharing contributions it received — `contributions[k]`
/// from the old member at old `x`-coordinate `old_xs[k]` — into its share of the SAME descriptor under the new
/// line, at position `new_x`. `old_xs` must be a threshold subset of the old line (`≥ t`). The descriptor is
/// never materialized; the new shares lie on a fresh polynomial, so the seize-`<t`-reveals-nothing property
/// holds afresh each epoch AND old shares cannot be mixed with new (proactive refresh). `None` on bad input.
#[must_use]
pub fn combine_descriptor_reshares(new_x: u8, contributions: &[Share], old_xs: &[u8]) -> Option<Share> {
    combine_reshares(new_x, contributions, old_xs).ok()
}

/// **Sealed** resharing contribution — the confidential form for the wire. An old member re-splits its OWN
/// descriptor `share` over the new line and **KEM-seals each sub-share to the corresponding new member**
/// (`new_member_keys` in new-line order), returning one [`SealedShare`] per new member. This is essential,
/// not optional: an *unsealed* sub-share travelling the network would let an observer collect a threshold of
/// them for one new member and reconstruct the descriptor — sealing keeps each sub-share readable only by its
/// intended new member. `None` on invalid Shamir/KEM parameters. Pairs with [`open_and_combine_reshares`].
#[must_use]
pub fn seal_reshare_contribution(
    share: &Share,
    new_threshold: u8,
    new_member_keys: &[&HybridKemPublic],
    key_randomness: &[u8],
    kem_seed: &[u8],
) -> Option<Vec<SealedShare>> {
    deal_service_key(share.y(), new_threshold, new_member_keys, key_randomness, kem_seed).ok()
}

/// The new member's side of sealed resharing: open the sealed sub-shares addressed to THIS member — one per
/// old member in a threshold subset, `contributions[k] = (old_x_k, sealed_k)` from the old member at old
/// `x`-coordinate `old_x_k` — with `member_secret`, then combine them into this member's rotated share at
/// `new_x`. `None` if any sealed share was not addressed to `member_secret` (wrong slot / tamper) or fewer
/// than the old threshold are supplied. The descriptor is never reconstructed, and a network observer without
/// `member_secret` learns nothing from the sealed contributions.
#[must_use]
pub fn open_and_combine_reshares(
    new_x: u8,
    contributions: &[(u8, SealedShare)],
    member_secret: &HybridKemSecret,
) -> Option<Share> {
    let mut old_xs = Vec::with_capacity(contributions.len());
    let mut sub_shares = Vec::with_capacity(contributions.len());
    for (old_x, sealed) in contributions {
        sub_shares.push(open_service_share(sealed, member_secret)?);
        old_xs.push(*old_x);
    }
    combine_reshares(new_x, &sub_shares, &old_xs).ok()
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
    // The Sybil **cap** layer (design authority §6): an optional allowlist of admitted requester coordinates,
    // supplied by the coherence/credential layer — canonically the fast-mixing trust graph ([`crate::sybil`]),
    // whose conductance bound caps admitted Sybils at `O(attack edges)` regardless of their count. `None` ⇒ the
    // PoW rate-limiter alone (the pre-cap default). POROS stays decoupled from the mechanism: it consumes the
    // admitted SET, not the graph, so proof-of-personhood or a credential system can supply it instead.
    admitted: Option<BTreeSet<Triple>>,
    // This host's KEM secret — needed only to OPEN sealed reshare sub-shares when rotating into a new epoch
    // line ([`with_kem_secret`](Self::with_kem_secret)). `None` ⇒ a serve-only host that cannot receive a
    // reshare (it can still emit contributions, which use only the new members' PUBLIC keys).
    kem_secret: Option<HybridKemSecret>,
    // The active rotation-into-a-new-line context, set by [`begin_rotation`](Self::begin_rotation): incoming
    // `PorosReshare` sub-shares are opened + gathered here, and a threshold of them combines into this host's
    // rotated share (then adopted). `None` outside a rotation.
    rotation: Option<RotationCtx>,
    // The public commitment `H(descriptor)` this host verifies every reconstruction against
    // ([`with_descriptor_commitment`](Self::with_descriptor_commitment)): a reconstructed descriptor that does
    // not match is NEVER served, so a corrupted reshare (or a tampered share set) fails safe. `None` ⇒ no
    // verification (the pre-commitment default, for a host whose descriptor is not yet committed).
    descriptor_commitment: Option<[u8; 32]>,
}

/// The receive-side state of a POROS line rotation: this host is a member of the incoming `new_line` for
/// `target_epoch` and gathers a threshold of reshare sub-shares to combine into its rotated descriptor share.
/// `old_line` is the roster of the OUTGOING line (index = share x-1) so each incoming sub-share can be
/// **authenticated to its genuine old member** — a sub-share whose transport source is not the old member it
/// claims to be from is rejected, closing the spoof/misattribution hole.
struct RotationCtx {
    target_epoch: Epoch,
    new_line: Vec<Triple>,
    old_line: Vec<Triple>,
    my_new_x: u8,
    gather: BTreeMap<u8, Share>,
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
            admitted: None,
            kem_secret: None,
            rotation: None,
            descriptor_commitment: None,
        }
    }

    /// Provide this host's KEM secret, enabling it to OPEN sealed reshare sub-shares and rotate into a new
    /// epoch line (see [`begin_rotation`](Self::begin_rotation)). Without it the host is serve-only.
    #[must_use]
    pub fn with_kem_secret(mut self, kem_secret: HybridKemSecret) -> Self {
        self.kem_secret = Some(kem_secret);
        self
    }

    /// Bind this host to the public **descriptor commitment** `H(descriptor)`
    /// ([`descriptor_commitment`]): every reconstruction it serves is checked against it, so a corrupted
    /// reshare (a Byzantine old member's poisoned sub-share) or a tampered share set can never yield a
    /// silently-wrong served descriptor — the serve fails safe instead. The commitment is epoch-invariant
    /// (rotation preserves the descriptor), so a rotated host carries the same one.
    #[must_use]
    pub fn with_descriptor_commitment(mut self, commitment: [u8; 32]) -> Self {
        self.descriptor_commitment = Some(commitment);
        self
    }

    /// Override the combiner's gather deadline (default 2 s).
    #[must_use]
    pub fn with_gather_timeout(mut self, timeout: Duration) -> Self {
        self.gather_timeout = timeout;
        self
    }

    /// Impose the **Sybil cap**: only requesters whose coordinate is in `admitted` are served (after they also
    /// clear the PoW rate-limiter). The set is the coherence layer's admission output — canonically the trust
    /// graph's [`admitted`](crate::sybil::TrustGraph::admitted) coordinates — and is refreshed as trust evolves
    /// (call again with a fresh set each epoch). Without this the host runs the rate-limiter alone.
    #[must_use]
    pub fn with_admission(mut self, admitted: BTreeSet<Triple>) -> Self {
        self.admitted = Some(admitted);
        self
    }

    /// Refresh the Sybil-cap allowlist in place (e.g. after the trust graph re-mixes for a new epoch). Passing
    /// an empty set admits no one; to remove the cap entirely, rebuild the host.
    pub fn set_admitted(&mut self, admitted: BTreeSet<Triple>) {
        self.admitted = Some(admitted);
    }

    /// Whether `requester` clears the Sybil cap: always `true` when no cap is configured, else membership in the
    /// admitted allowlist. (The PoW rate-limiter is a separate, additional gate — see [`on_request`](Self::on_request).)
    #[must_use]
    fn sybil_admits(&self, requester: &Triple) -> bool {
        self.admitted.as_ref().is_none_or(|set| set.contains(requester))
    }

    /// The number of requests currently gathering (combiner state), for tests/observability.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// The epoch this host currently serves (advances when it [`adopt`](Self::adopt)s a rotation).
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// This host's `x`-coordinate (1-based position) in `line`, or `None` if it is not a member.
    fn my_x_in(&self, line: &[Triple]) -> Option<u8> {
        line.iter().position(|c| *c == self.coord).and_then(|i| u8::try_from(i + 1).ok())
    }

    /// **Emit this old-line member's sealed reshare contributions** to the incoming `new_line` for
    /// `target_epoch` — one [`PorosReshare`](FrameType::PorosReshare) per new member, each sub-share KEM-sealed
    /// to that member (`new_keys` in `new_line` order, supplied by the driver from the directory). The driver
    /// calls this at an epoch boundary; the host need not be a member of `new_line`. Empty if this host is not
    /// an old-line member or the Shamir/KEM parameters are invalid.
    #[must_use]
    pub fn emit_reshare(
        &self,
        target_epoch: Epoch,
        new_line: &[Triple],
        new_keys: &[&HybridKemPublic],
        key_randomness: &[u8],
        kem_seed: &[u8],
    ) -> Vec<Effect> {
        let Some(my_old_x) = self.my_x_in(&self.line) else {
            return Vec::new(); // not an old-line member — nothing to reshare
        };
        let Ok(threshold) = u8::try_from(self.threshold) else {
            return Vec::new();
        };
        let Some(sealed) = seal_reshare_contribution(&self.share, threshold, new_keys, key_randomness, kem_seed)
        else {
            return Vec::new();
        };
        new_line
            .iter()
            .zip(&sealed)
            .map(|(&to, s)| Effect::Send { to, frame: reshare_frame(target_epoch, my_old_x, s) })
            .collect()
    }

    /// **Prepare to rotate INTO** `new_line` for `target_epoch`, receiving from the outgoing `old_line`: sets
    /// the receive context so incoming `PorosReshare` sub-shares are authenticated to their old member, opened,
    /// gathered, and combined into this host's rotated share (which it then [`adopt`](Self::adopt)s). A no-op if
    /// this host is not a member of `new_line`. The driver computes both rosters from
    /// `ingress_line(community, epoch, beacon)` (no I/O) — `new_line` at `target_epoch`, `old_line` at the
    /// current epoch — and calls this before the contributions arrive. `old_line` is the roster whose position
    /// `x-1` a sub-share claiming index `x` must have arrived FROM (sender authentication).
    pub fn begin_rotation(&mut self, target_epoch: Epoch, new_line: Vec<Triple>, old_line: Vec<Triple>) {
        if let Some(my_new_x) = self.my_x_in(&new_line) {
            self.rotation =
                Some(RotationCtx { target_epoch, new_line, old_line, my_new_x, gather: BTreeMap::new() });
        }
    }

    /// A reshare sub-share arrived from transport source `from`: authenticate it to its genuine old member
    /// (`from` must be `old_line[old_x-1]`), and if it belongs to the active rotation and opens under this
    /// host's KEM secret, gather it (first-writer-wins per old member). Once a threshold of distinct old
    /// members' sub-shares are in, combine them into the rotated share and [`adopt`](Self::adopt) the new
    /// epoch/line.
    ///
    /// Sender authentication closes the spoof hole: a `PorosReshare` from any coordinate other than the old
    /// member it claims (`old_x`) is dropped, so an outsider cannot inject a sub-share. A *genuine but
    /// Byzantine* old member's corrupt sub-share still combines here, but a rotated line NEVER serves a
    /// descriptor that fails its [`with_descriptor_commitment`](Self::with_descriptor_commitment) check — so
    /// corruption is fail-safe (detected at serve, never a wrong descriptor). Robust recovery from such a
    /// Byzantine contributor (attribute + retry a different old-member subset) is the VSS follow-on.
    fn on_reshare(&mut self, from: Triple, target_epoch: Epoch, old_x: u8, sealed: &SealedShare) -> Vec<Effect> {
        let threshold = self.threshold;
        let Some(secret) = self.kem_secret.as_ref() else {
            return Vec::new(); // serve-only host: cannot open sealed sub-shares
        };
        let Some(ctx) = self.rotation.as_mut() else {
            return Vec::new(); // no active rotation
        };
        if ctx.target_epoch != target_epoch {
            return Vec::new(); // a sub-share for a different rotation
        }
        // Sender authentication: the sub-share must have arrived FROM the old member it claims to be (index
        // `old_x` = position `old_x - 1` in the outgoing roster). Rejects a spoofed/misattributed contribution.
        if usize::from(old_x).checked_sub(1).and_then(|i| ctx.old_line.get(i)) != Some(&from) {
            return Vec::new();
        }
        let Some(sub) = open_service_share(sealed, secret) else {
            return Vec::new(); // not addressed to us, or tampered
        };
        ctx.gather.entry(old_x).or_insert(sub);
        if ctx.gather.len() < threshold {
            return Vec::new(); // still gathering
        }
        // A threshold of old members contributed: combine into this host's rotated share.
        let old_xs: Vec<u8> = ctx.gather.keys().copied().collect();
        let subs: Vec<Share> = ctx.gather.values().cloned().collect();
        let my_new_x = ctx.my_new_x;
        let new_line = ctx.new_line.clone();
        let Some(new_share) = combine_descriptor_reshares(my_new_x, &subs, &old_xs) else {
            return Vec::new();
        };
        self.adopt(target_epoch, new_line, new_share);
        Vec::new()
    }

    /// Adopt a completed rotation: advance to `epoch` with `line` and `share`, and clear per-epoch working
    /// state (the rotation context and any in-flight request gathers, which belonged to the old epoch).
    fn adopt(&mut self, epoch: Epoch, line: Vec<Triple>, share: Share) {
        self.epoch = epoch;
        self.line = line;
        self.share = share;
        self.rotation = None;
        self.pending.clear();
    }

    /// A request arrived at us as the combiner: verify its PoW, seed our own share, fan share-requests to
    /// the rest of the line. A bad proof, wrong epoch/community, or a duplicate/flood is dropped.
    fn on_request(&mut self, now: Instant, req: IngressRequest) -> Vec<Effect> {
        // Gate 1 — the PoW **rate-limiter** (bounds identity-creation rate, keeps the insider count small).
        if !verify_ingress_request(&req, &self.community, self.epoch, &self.beacon, self.difficulty) {
            return Vec::new();
        }
        // Gate 2 — the Sybil **cap** (the trust-graph conductance bound): a valid PoW is necessary but not
        // sufficient. A requester the coherence layer has not admitted is dropped no matter how much work it did,
        // so a flood of freshly-minted identities behind a sparse trust cut cannot buy ingress.
        if !self.sybil_admits(&req.requester) {
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
        // Fail-safe verification: if this host is bound to a descriptor commitment, a reconstruction that does
        // not match it (a corrupted reshare, or a tampered/inconsistent share set) is NEVER served — the serve
        // silently drops instead of handing back a wrong ingress set.
        if let Some(commit) = self.descriptor_commitment
            && descriptor_commitment(&descriptor) != commit
        {
            return Vec::new();
        }
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
                    Some(FrameType::PorosReshare) => decode_reshare(decoded.body)
                        .map_or_else(Vec::new, |(epoch, old_x, sealed)| self.on_reshare(from, epoch, old_x, &sealed)),
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

/// Build a [`PorosReshare`](FrameType::PorosReshare) frame: `target_epoch(8) ‖ old_x(1) ‖ SealedShare`.
#[must_use]
fn reshare_frame(target_epoch: Epoch, old_x: u8, sealed: &SealedShare) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&target_epoch.to_be_bytes());
    body.push(old_x);
    body.extend_from_slice(&sealed.to_wire());
    encode(FrameType::PorosReshare, &body)
}

/// Decode a [`PorosReshare`](FrameType::PorosReshare) body into `(target_epoch, old_x, sealed)`.
fn decode_reshare(body: &[u8]) -> Option<(Epoch, u8, SealedShare)> {
    let mut r = Reader::new(body);
    let target_epoch = Epoch::from_be_bytes(r.array::<8>()?);
    let old_x = r.u8()?;
    let sealed = SealedShare::from_wire(r.rest()).ok()?;
    Some((target_epoch, old_x, sealed))
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

    #[test]
    fn the_sybil_cap_composes_with_the_pow_rate_limiter() {
        use fanos_runtime::{Input, Instant};

        use crate::sybil::{NodeId, TrustGraph};

        let desc = descriptor(6);
        let threshold = 2usize;
        let community = b"cap".to_vec();
        let (epoch, difficulty) = (Epoch::new(1), 4);
        let beacon = BeaconSeed::new([0x44; 32]);
        let line: Vec<Triple> = (0..3).map(coord).collect();
        let randomness = vec![0x11u8; desc.to_bytes().len() * (threshold - 1) + 8];
        let shares = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();

        // A distinct identity coordinate per trust node (the Fano `coord` helper only has 7 points; a real
        // requester's VRF-identity coordinate lives in a large space — an opaque [u32;3] key for the gate).
        let id_coord = |i: NodeId| -> Triple { [i, 0, 1] };
        // The coherence layer's trust graph: a fast-mixing honest clique {0..15} plus a Sybil clique {100..140}
        // attached by 2 attack edges. The conductance bound (crate::sybil) admits the honest region and caps the
        // Sybils at O(attack edges) regardless of their count — the proven sybil.rs regime.
        let mut g = TrustGraph::new();
        let honest: Vec<NodeId> = (0..15).collect();
        let sybils: Vec<NodeId> = (100..140).collect();
        for &a in &honest {
            for &b in &honest {
                if a < b {
                    g.add_edge(a, b);
                }
            }
        }
        for &a in &sybils {
            for &b in &sybils {
                if a < b {
                    g.add_edge(a, b);
                }
            }
        }
        g.add_edge(0, 100); // the sparse attack cut: 2 edges
        g.add_edge(1, 101);
        // Admitted NodeIds → admitted coordinates (the layer maps identity handle i ↔ id_coord(i)); this SET is
        // all POROS consumes, keeping it decoupled from the trust-graph mechanism.
        let admitted_ids = g.admitted(0, honest.iter().chain(&sybils).copied(), 16, 0.3);
        let admitted: BTreeSet<Triple> = admitted_ids.iter().map(|&id| id_coord(id)).collect();
        assert!(honest.iter().all(|&h| admitted.contains(&id_coord(h))), "honest nodes clear the cap");

        let mut combiner = PorosHost::new(
            line[0],
            shares[0].clone(),
            line.clone(),
            threshold,
            community.clone(),
            epoch,
            beacon,
            difficulty,
        )
        .with_admission(admitted.clone());

        // An admitted honest requester with a valid PoW opens a gather (both gates pass).
        let good_coord = id_coord(3);
        let good = solve_ingress_request(good_coord, &community, epoch, &beacon, difficulty);
        let e_good = combiner.step(Instant(0), Input::Message { from: good_coord, frame: request_frame(&good) });
        assert!(!e_good.is_empty(), "an admitted requester with valid PoW is served");
        assert_eq!(combiner.pending(), 1, "and opens exactly one gather");

        // A Sybil requester with an EQUALLY valid PoW is dropped by the cap — burning work cannot buy ingress.
        let sybil = *sybils.iter().find(|&&s| !admitted.contains(&id_coord(s))).expect("a Sybil is capped out");
        let sybil_coord = id_coord(sybil);
        let bad = solve_ingress_request(sybil_coord, &community, epoch, &beacon, difficulty);
        assert!(verify_ingress_request(&bad, &community, epoch, &beacon, difficulty), "the Sybil's PoW is genuinely valid");
        let e_bad = combiner.step(Instant(1), Input::Message { from: sybil_coord, frame: request_frame(&bad) });
        assert!(e_bad.is_empty(), "the Sybil cap drops it despite valid PoW — no gather opened");
        assert_eq!(combiner.pending(), 1, "still only the admitted requester is gathering");
    }

    #[test]
    fn the_descriptor_reshares_to_a_new_epoch_line_without_reconstructing_it() {
        // The ingress line rotates each epoch: the descriptor must move to the NEW line's q+1 members without
        // any node ever holding it whole. An old threshold subset reshares; the new line recovers the SAME
        // descriptor — and no single node reconstructed it at any point (CHURP-style proactive resharing).
        let desc = descriptor(8);
        let (old_t, old_n) = (2u8, 3u8);
        let (new_t, new_n) = (2u8, 3u8);
        let secret_len = desc.to_bytes().len();
        let old_shares =
            shard_descriptor(&desc, old_t, old_n, &vec![0x5Au8; secret_len * usize::from(old_t - 1) + 8]).unwrap();

        // A threshold subset of the OLD line (members at x = 1, 2) each reshare their own share to the new line.
        let old_xs = [old_shares[0].x(), old_shares[1].x()];
        let contributions: Vec<Vec<Share>> = [&old_shares[0], &old_shares[1]]
            .iter()
            .enumerate()
            .map(|(k, s)| {
                // Distinct randomness per contributor ⇒ a genuinely fresh polynomial.
                let rnd: Vec<u8> = (0..secret_len).map(|i| ((i * 31 + k * 101 + 7) % 251) as u8).collect();
                reshare_descriptor_share(s, new_t, new_n, &rnd).expect("a valid resharing contribution")
            })
            .collect();

        // Each new member combines the sub-shares addressed to it into its rotated share.
        let new_shares: Vec<Share> = (0..usize::from(new_n))
            .map(|j| {
                let for_j: Vec<Share> = contributions.iter().map(|c| c[j].clone()).collect();
                combine_descriptor_reshares(u8::try_from(j + 1).unwrap(), &for_j, &old_xs)
                    .expect("a valid combined share")
            })
            .collect();

        // The NEW line recovers the SAME descriptor from any threshold of its rotated shares.
        assert_eq!(
            recover_descriptor(&[new_shares[0].clone(), new_shares[2].clone()]).as_ref(),
            Some(&desc),
            "the new epoch line reconstructs the identical descriptor after resharing",
        );
        // Seizing < t of the new line still reveals nothing (a real threshold committee), and a stale old
        // share is not a valid point of the fresh polynomial (proactive refresh).
        assert_ne!(recover_descriptor(&[new_shares[0].clone()]).as_ref(), Some(&desc), "one new share reveals nothing");
        assert_ne!(new_shares[0].y(), old_shares[0].y(), "the rotated share is on a fresh polynomial, not a copy");
    }

    #[test]
    fn sealed_resharing_keeps_sub_shares_confidential_end_to_end() {
        use fanos_pqcrypto::SeedRng;

        // The wire-safe form: each reshare sub-share is KEM-SEALED to its target new member, so a network
        // observer of the reshare traffic learns nothing. The new members open their sealed sub-shares and
        // combine — recovering the SAME descriptor — while a wrong secret cannot open another member's slot.
        let desc = descriptor(8);
        let (old_t, old_n) = (2u8, 3u8);
        let (new_t, new_n) = (2u8, 3usize);
        let secret_len = desc.to_bytes().len();
        let old_shares =
            shard_descriptor(&desc, old_t, old_n, &vec![0x5Au8; secret_len * usize::from(old_t - 1) + 8]).unwrap();

        // The new line's KEM keypairs (in new-line position order).
        let new_kp: Vec<(HybridKemSecret, HybridKemPublic)> = (0..new_n)
            .map(|j| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xE1, j as u8])))
            .collect();
        let new_keys: Vec<&HybridKemPublic> = new_kp.iter().map(|(_, p)| p).collect();

        // Each old member in the threshold subset seals a contribution to the new line's keys.
        let old_subset = [&old_shares[0], &old_shares[1]];
        let old_xs = [old_shares[0].x(), old_shares[1].x()];
        let sealed_contribs: Vec<Vec<SealedShare>> = old_subset
            .iter()
            .enumerate()
            .map(|(k, s)| {
                let key_rnd = vec![0x11u8 + k as u8; secret_len * usize::from(new_t - 1) + 8];
                seal_reshare_contribution(s, new_t, &new_keys, &key_rnd, &[0xA0, k as u8]).expect("sealed contribution")
            })
            .collect();

        // Each new member j opens the sealed sub-shares addressed to it (one from each old member) and combines.
        let new_shares: Vec<Share> = (0..new_n)
            .map(|j| {
                let for_j: Vec<(u8, SealedShare)> =
                    sealed_contribs.iter().enumerate().map(|(k, c)| (old_xs[k], c[j].clone())).collect();
                open_and_combine_reshares(u8::try_from(j + 1).unwrap(), &for_j, &new_kp[j].0)
                    .expect("new member opens and combines its sealed sub-shares")
            })
            .collect();

        // The new line recovers the identical descriptor from a threshold of its rotated shares.
        assert_eq!(
            recover_descriptor(&[new_shares[0].clone(), new_shares[1].clone()]).as_ref(),
            Some(&desc),
            "the new line recovers the descriptor from sealed, never-in-clear sub-shares",
        );
        // The seal is real: new member 0's sub-shares cannot be opened with new member 1's secret.
        let for_0: Vec<(u8, SealedShare)> =
            sealed_contribs.iter().enumerate().map(|(k, c)| (old_xs[k], c[0].clone())).collect();
        assert_eq!(
            open_and_combine_reshares(1, &for_0, &new_kp[1].0),
            None,
            "another member's secret cannot open a sub-share sealed to member 0 (confidentiality holds)",
        );
    }

    #[test]
    fn the_engine_rotates_a_host_into_a_new_epoch_line_via_reshare_frames() {
        use fanos_pqcrypto::SeedRng;
        use fanos_runtime::{Effect, Input, Instant};

        // The full engine path: OLD-line hosts emit sealed PorosReshare frames; NEW-line hosts (begin_rotation
        // set) receive them via step(), gather a threshold, combine, and ADOPT their rotated share — advancing
        // to the new epoch. The adopted shares then reconstruct the original descriptor.
        let desc = descriptor(6);
        let (t, n) = (2u8, 3u8);
        let secret_len = desc.to_bytes().len();
        let (old_epoch, new_epoch) = (Epoch::new(1), Epoch::new(2));
        let beacon = BeaconSeed::new([0x55; 32]);
        let old_line: Vec<Triple> = (0..3).map(coord).collect();
        let new_line: Vec<Triple> = (3..6).map(coord).collect();
        let shares = shard_descriptor(&desc, t, n, &vec![0x5Au8; secret_len * usize::from(t - 1) + 8]).unwrap();

        // Old-line hosts, each holding its real descriptor share.
        let old_host = |i: usize| {
            PorosHost::new(old_line[i], shares[i].clone(), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4)
        };
        // New-line hosts: a placeholder share (adopt replaces it), a KEM secret (to open sealed sub-shares), and
        // the rotation context set to the new line.
        let new_kp: Vec<(HybridKemSecret, HybridKemPublic)> =
            (0..3).map(|j| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF0, j as u8]))).collect();
        let new_keys: Vec<&HybridKemPublic> = new_kp.iter().map(|(_, p)| p).collect();
        let mut new_hosts: Vec<PorosHost> = (0..3)
            .map(|j| {
                let placeholder = Share::new(u8::try_from(j + 1).unwrap(), vec![0u8; secret_len]);
                let secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF0, j as u8])).0; // same seed ⇒ same secret
                let mut h = PorosHost::new(new_line[j], placeholder, new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4)
                    .with_kem_secret(secret);
                h.begin_rotation(new_epoch, new_line.clone(), old_line.clone());
                h
            })
            .collect();

        // A threshold subset of the old line (members 0, 1) each emit their sealed reshare contributions.
        for (i, &from) in old_line.iter().enumerate().take(usize::from(t)) {
            let key_rnd = vec![0x10u8 + i as u8; secret_len * usize::from(t - 1) + 8];
            let effects = old_host(i).emit_reshare(new_epoch, &new_line, &new_keys, &key_rnd, &[0xB0, i as u8]);
            assert_eq!(effects.len(), new_line.len(), "one reshare frame per new member");
            // Route each sealed sub-share to its target new host.
            for e in effects {
                if let Effect::Send { to, frame } = e {
                    let j = new_line.iter().position(|c| *c == to).unwrap();
                    new_hosts[j].step(Instant(0), Input::Message { from, frame });
                }
            }
        }

        // Every new host adopted: it advanced to the new epoch, its rotation context is cleared.
        for h in &new_hosts {
            assert_eq!(h.epoch(), new_epoch, "the new host rotated to the new epoch");
            assert!(h.rotation.is_none(), "the rotation completed and cleared its context");
        }
        // The adopted shares reconstruct the ORIGINAL descriptor — rotation preserved the hosted secret.
        assert_eq!(
            recover_descriptor(&[new_hosts[0].share.clone(), new_hosts[1].share.clone()]).as_ref(),
            Some(&desc),
            "the rotated new line hosts the identical descriptor",
        );
        // A stale sub-share for a DIFFERENT epoch is ignored (no spurious adoption / gather pollution).
        let fresh_secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF0, 0])).0; // new_host[0]'s secret
        let mut fresh = PorosHost::new(new_line[0], Share::new(1, vec![0u8; secret_len]), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4)
            .with_kem_secret(fresh_secret);
        fresh.begin_rotation(new_epoch, new_line.clone(), old_line.clone());
        let stale = old_host(0).emit_reshare(Epoch::new(99), &new_line, &new_keys, &vec![0x1u8; secret_len + 8], &[0xC0]);
        if let Some(Effect::Send { frame, .. }) = stale.into_iter().next() {
            fresh.step(Instant(0), Input::Message { from: old_line[0], frame });
        }
        assert_eq!(fresh.epoch(), old_epoch, "a reshare for a different target epoch does not rotate the host");
    }

    #[test]
    fn a_reshare_from_the_wrong_source_is_rejected_sender_authentication() {
        use fanos_pqcrypto::SeedRng;
        // A spoofer sends a genuine old member's reshare frame from a DIFFERENT coordinate: on_reshare
        // authenticates `from` against the old-line roster, so the misattributed sub-share is dropped and the
        // gather does not fill — the host never rotates on spoofed input.
        let desc = descriptor(6);
        let (t, n) = (2u8, 3u8);
        let secret_len = desc.to_bytes().len();
        let (old_epoch, new_epoch) = (Epoch::new(1), Epoch::new(2));
        let beacon = BeaconSeed::new([0x66; 32]);
        let old_line: Vec<Triple> = (0..3).map(coord).collect();
        let new_line: Vec<Triple> = (3..6).map(coord).collect();
        let shares = shard_descriptor(&desc, t, n, &vec![0x5Au8; secret_len * usize::from(t - 1) + 8]).unwrap();
        let old_host = |i: usize| {
            PorosHost::new(old_line[i], shares[i].clone(), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4)
        };
        let secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x77, 0])).0;
        let new_pubs: Vec<HybridKemPublic> =
            (0..3).map(|j| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x77, j as u8])).1).collect();
        let new_keys: Vec<&HybridKemPublic> = new_pubs.iter().collect();
        let mut victim = PorosHost::new(new_line[0], Share::new(1, vec![0u8; secret_len]), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4)
            .with_kem_secret(secret);
        victim.begin_rotation(new_epoch, new_line.clone(), old_line.clone());

        // Old member 0's genuine contribution to new member 0, but delivered from an IMPOSTOR coordinate.
        let frames = old_host(0).emit_reshare(new_epoch, &new_line, &new_keys, &vec![0x1u8; secret_len + 8], &[0xB0]);
        let to_victim = frames.into_iter().find_map(|e| match e {
            Effect::Send { to, frame } if to == new_line[0] => Some(frame),
            _ => None,
        }).unwrap();
        let impostor = coord(6); // not old_line[0]
        victim.step(Instant(0), Input::Message { from: impostor, frame: to_victim });
        assert_eq!(victim.epoch(), old_epoch, "a sub-share from the wrong source does not gather — no spoofed rotation");
    }

    #[test]
    fn a_corrupted_reshare_never_serves_a_wrong_descriptor_commitment_fail_safe() {
        use fanos_pqcrypto::SeedRng;
        // A Byzantine old member sends a CORRUPT sub-share (valid source, wrong value): it authenticates and
        // combines, so the new line's rotated shares are poisoned. But every new host is bound to the descriptor
        // commitment, so a serve that reconstructs a descriptor != H(commitment) returns NOTHING — the wrong
        // ingress set is never handed out (fail-safe over GF(256), where per-share Feldman verification cannot
        // apply).
        let desc = descriptor(6);
        let (t, n) = (2u8, 3u8);
        let secret_len = desc.to_bytes().len();
        let commit = descriptor_commitment(&desc);
        let (old_epoch, new_epoch) = (Epoch::new(1), Epoch::new(2));
        let beacon = BeaconSeed::new([0x88; 32]);
        let old_line: Vec<Triple> = (0..3).map(coord).collect();
        let new_line: Vec<Triple> = (3..6).map(coord).collect();
        let shares = shard_descriptor(&desc, t, n, &vec![0x5Au8; secret_len * usize::from(t - 1) + 8]).unwrap();

        // Old member 0 is honest; old member 1 is Byzantine — it holds a CORRUPTED share (flipped bytes), so its
        // reshare contribution poisons the combination.
        let honest0 = PorosHost::new(old_line[0], shares[0].clone(), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4);
        let mut bad_y = shares[1].y().to_vec();
        bad_y[0] ^= 0xFF;
        let byz1 = PorosHost::new(old_line[1], Share::new(shares[1].x(), bad_y), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4);

        let new_kp: Vec<(HybridKemSecret, HybridKemPublic)> =
            (0..3).map(|j| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x99, j as u8]))).collect();
        let new_keys: Vec<&HybridKemPublic> = new_kp.iter().map(|(_, p)| p).collect();
        // Every new host is COMMITTED to the true descriptor.
        let mut new_hosts: Vec<PorosHost> = (0..3)
            .map(|j| {
                let secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x99, j as u8])).0;
                let mut h = PorosHost::new(new_line[j], Share::new(u8::try_from(j + 1).unwrap(), vec![0u8; secret_len]), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4)
                    .with_kem_secret(secret)
                    .with_descriptor_commitment(commit);
                h.begin_rotation(new_epoch, new_line.clone(), old_line.clone());
                h
            })
            .collect();

        // Route both old members' contributions (honest 0 + Byzantine 1) to the new line.
        for (host, i) in [(&honest0, 0usize), (&byz1, 1usize)] {
            let frames = host.emit_reshare(new_epoch, &new_line, &new_keys, &vec![0x10u8 + i as u8; secret_len + 8], &[0xB0, i as u8]);
            for e in frames {
                if let Effect::Send { to, frame } = e {
                    let j = new_line.iter().position(|c| *c == to).unwrap();
                    new_hosts[j].step(Instant(0), Input::Message { from: old_line[i], frame });
                }
            }
        }
        // The new hosts adopted (poisoned) shares — rotation "completed" from their local view.
        assert!(new_hosts.iter().all(|h| h.epoch() == new_epoch), "the new hosts rotated on authenticated input");

        // Now a request: the new combiner gathers a threshold and reconstructs — but the descriptor fails the
        // commitment (poisoned), so it serves NOTHING rather than a wrong ingress set.
        assert!(
            !probe_serve(&mut new_hosts, &new_line, b"c", new_epoch, &beacon),
            "a corrupted rotation fails the commitment and serves nothing — never a wrong descriptor",
        );

        // Control: an UNcorrupted rotation of the same committed line DOES serve (the guard is not over-eager).
        let honest1 = PorosHost::new(old_line[1], shares[1].clone(), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4);
        let mut good_hosts: Vec<PorosHost> = (0..3)
            .map(|j| {
                let secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x99, j as u8])).0;
                let mut h = PorosHost::new(new_line[j], Share::new(u8::try_from(j + 1).unwrap(), vec![0u8; secret_len]), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4)
                    .with_kem_secret(secret)
                    .with_descriptor_commitment(commit);
                h.begin_rotation(new_epoch, new_line.clone(), old_line.clone());
                h
            })
            .collect();
        for (host, i) in [(&honest0, 0usize), (&honest1, 1usize)] {
            let frames = host.emit_reshare(new_epoch, &new_line, &new_keys, &vec![0x20u8 + i as u8; secret_len + 8], &[0xC0, i as u8]);
            for e in frames {
                if let Effect::Send { to, frame } = e {
                    let j = new_line.iter().position(|c| *c == to).unwrap();
                    good_hosts[j].step(Instant(0), Input::Message { from: old_line[i], frame });
                }
            }
        }
        assert!(
            probe_serve(&mut good_hosts, &new_line, b"c", new_epoch, &beacon),
            "an uncorrupted committed rotation still serves — the commitment guard is not over-eager",
        );
    }

    /// Drive one ingress request through a rotated line (combiner = `hosts[0]`) and report whether it served a
    /// `PorosResponse` — the observable that proves the descriptor reconstructed and passed its commitment.
    fn probe_serve(
        hosts: &mut [PorosHost],
        new_line: &[Triple],
        community: &[u8],
        epoch: Epoch,
        beacon: &BeaconSeed,
    ) -> bool {
        let req = solve_ingress_request(coord(6), community, epoch, beacon, 4);
        let fanned = hosts[0].step(Instant(1), Input::Message { from: coord(6), frame: request_frame(&req) });
        for e in fanned {
            if let Effect::Send { to, frame } = e
                && let Some(j) = new_line.iter().position(|c| *c == to)
            {
                for reply in hosts[j].step(Instant(2), Input::Message { from: new_line[0], frame }) {
                    if let Effect::Send { frame: share_frame, .. } = reply {
                        for out in hosts[0].step(Instant(3), Input::Message { from: new_line[j], frame: share_frame }) {
                            if let Effect::Send { frame: resp, .. } = out
                                && decode_frame(&resp).ok().and_then(|(f, _)| f.frame_type()) == Some(FrameType::PorosResponse)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}
