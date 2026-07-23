//! **Censorship-resistant bootstrap** (audit §5 S1-M5, `docs/design-recovery.md` §3). A fixed
//! `config.bootstrap` seed list is enumerable: a Sybil censor harvests it and blocks every entry. This module
//! replaces it with the two mechanisms that make a bootstrap enumeration-resistant against a state adversary:
//!
//! 1. a **moving-target rendezvous** — legitimate peers *compute* an epoch-rotating meeting line from a shared
//!    community secret folded with the beacon (`bridge_rendezvous`), exactly the Tor onion-v3 shared-random
//!    hashring idea on FANOS's own NYX derivation. A censor cannot predict or pre-enumerate it, and it rotates
//!    every epoch so any blocklist goes stale;
//! 2. a **PoW-gated, bucketed handout** — a bridge helper listening at that rendezvous serves only a *few* peer
//!    descriptors per request ([`BRIDGE_BUCKET`], the Lox/rdsys "no client learns `O(N)`" principle), and only
//!    against a proof of work bound to the current epoch ([`solve_bridge_request`]), so harvesting the whole set
//!    is expensive and expires each epoch.
//!
//! Once one peer is reached, the rest bootstrap by signed-descriptor peer-exchange over the overlay, so the full
//! set is never centralized. The wire carrier for the *first* contact is obfuscated by PROTEUS
//! ([[proteus-morph-transforms]], Parrot-is-Dead) — the one irreducible "seed an unblockable carrier" residual.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fanos_calypso::pow;
use fanos_field::Field;
use fanos_geometry::{Line, TRIPLE_WIRE_LEN, Triple, decode_triple, encode_triple};
use fanos_primitives::codec::{Reader, put_seq, put_var_bytes};
use fanos_primitives::hash_labeled;
use fanos_rendezvous::{BeaconSeed, Epoch, combiner_for, meeting_line};

use crate::config::Peer;

/// How many peer descriptors a bridge hands out per request — a *few*, never the full set. One enumerator
/// learns at most `BRIDGE_BUCKET` per (rotating) epoch, so it can never cheaply harvest `O(N)`.
pub const BRIDGE_BUCKET: usize = 3;

/// Domain separation for the bridge PoW challenge.
const POW_LABEL: &str = "FANOS-v1/bridge-pow";
/// Domain separation for the per-request bucket ranking.
const BUCKET_LABEL: &str = "FANOS-v1/bridge-bucket";

/// The moving-target **bridge rendezvous line** for a bootstrap community sharing `community`, at `epoch` folded
/// with the beacon `SEED(epoch)`. Legitimate peers COMPUTE it; a censor cannot predict or pre-enumerate it, and
/// it rotates every epoch. Reuses the NYX meeting-line derivation (spec §5).
#[must_use]
pub fn bridge_rendezvous<F: Field>(community: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Line<F> {
    meeting_line::<F>(community, epoch, beacon)
}

/// The rendezvous **combiner** a new node contacts and a bridge helper listens at (the canonical member of the
/// [`bridge_rendezvous`] line). `None` only on a degenerate plane offering no combiner.
#[must_use]
pub fn bridge_combiner<F: Field>(community: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Option<Triple> {
    combiner_for::<F>(bridge_rendezvous::<F>(community, epoch, beacon).coords())
}

/// The PoW challenge for a bridge request — bound to `(community, epoch, beacon)`, so a proof cannot be
/// precomputed far ahead and expires each epoch (the Sybil-cost that makes harvesting expensive).
fn bridge_challenge(community: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> [u8; 32] {
    let mut buf = Vec::with_capacity(community.len() + 8 + 32);
    buf.extend_from_slice(community);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(beacon.as_bytes());
    hash_labeled(POW_LABEL, &buf)
}

/// A new node's request for bootstrap peers: a proof-of-work nonce over the epoch-bound challenge.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BridgeRequest {
    /// The PoW nonce solving the epoch-bound challenge.
    pub nonce: u64,
}

impl BridgeRequest {
    /// Canonical wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.nonce.to_be_bytes().to_vec()
    }

    /// Decode from [`to_bytes`](Self::to_bytes).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(|a| Self { nonce: u64::from_be_bytes(a) })
    }
}

/// Solve a bridge request (client side): find a PoW nonce over the epoch-bound challenge at `difficulty`.
#[must_use]
pub fn solve_bridge_request(community: &[u8], epoch: Epoch, beacon: &BeaconSeed, difficulty: u32) -> BridgeRequest {
    BridgeRequest { nonce: pow::solve(&bridge_challenge(community, epoch, beacon), difficulty) }
}

/// Verify a bridge request's PoW (helper side).
#[must_use]
pub fn verify_bridge_request(
    req: &BridgeRequest,
    community: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    difficulty: u32,
) -> bool {
    pow::verify(&bridge_challenge(community, epoch, beacon), req.nonce, difficulty)
}

/// A bridge's response: a small bucket of peer descriptors a new node can connect to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BridgeResponse {
    /// At most [`BRIDGE_BUCKET`] peers, selected per-request so distinct requesters get distinct subsets.
    pub peers: Vec<Peer>,
}

impl BridgeResponse {
    /// Canonical wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_seq(&mut out, self.peers.len(), &self.peers, |o, p| put_var_bytes(o, &encode_peer(p)));
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
}

/// A **bridge helper**: it holds a set of reachable peers (from its own bootstrap plus signed-descriptor
/// peer-exchange) and serves a small, per-request-varying bucket on a valid PoW — so no single requester learns
/// the whole set, and harvesting is priced by the epoch-bound proof of work.
pub struct BridgeHelper {
    peers: Vec<Peer>,
}

impl BridgeHelper {
    /// A helper serving from `peers`.
    #[must_use]
    pub fn new(peers: Vec<Peer>) -> Self {
        Self { peers }
    }

    /// The number of peers this helper knows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether this helper knows no peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Serve a bucket of at most [`BRIDGE_BUCKET`] peers for a valid request, or `None` if the PoW does not
    /// verify against `(community, epoch, beacon)` at `difficulty`. The bucket is ranked by `H(nonce ‖ peer)`,
    /// so distinct nonces yield distinct subsets and no requester learns the full set.
    #[must_use]
    pub fn serve(
        &self,
        req: &BridgeRequest,
        community: &[u8],
        epoch: Epoch,
        beacon: &BeaconSeed,
        difficulty: u32,
    ) -> Option<BridgeResponse> {
        if !verify_bridge_request(req, community, epoch, beacon, difficulty) {
            return None;
        }
        Some(BridgeResponse { peers: select_bucket(&self.peers, req.nonce) })
    }
}

/// Select up to [`BRIDGE_BUCKET`] peers ordered by `H(nonce ‖ peer)`, so distinct requests get distinct subsets.
fn select_bucket(peers: &[Peer], nonce: u64) -> Vec<Peer> {
    let mut ranked: Vec<([u8; 32], Peer)> = peers.iter().map(|p| (bucket_key(nonce, p), *p)).collect();
    ranked.sort_by_key(|(key, _)| *key);
    ranked.into_iter().take(BRIDGE_BUCKET).map(|(_, p)| p).collect()
}

/// The bucket-ranking key for `peer` under `nonce`.
fn bucket_key(nonce: u64, peer: &Peer) -> [u8; 32] {
    let mut buf = nonce.to_be_bytes().to_vec();
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    fn peers(n: usize) -> Vec<Peer> {
        (0..n)
            .map(|i| Peer {
                coord: fanos_geometry::Point::<F2>::at(i % 7).coords(),
                addr: SocketAddr::from(([10, 0, 0, i as u8], 9000 + i as u16)),
            })
            .collect()
    }

    #[test]
    fn the_rendezvous_is_deterministic_and_rotates_with_the_epoch() {
        use std::collections::BTreeSet;
        let beacon = BeaconSeed::new([0x7b; 32]);
        let at = |c: &[u8], e: u64| bridge_rendezvous::<F2>(c, Epoch::new(e), &beacon).coords();
        assert_eq!(at(b"community", 1), at(b"community", 1), "deterministic: same inputs → same rendezvous");
        assert!(bridge_combiner::<F2>(b"community", Epoch::new(1), &beacon).is_some(), "the plane offers a combiner");
        // Across several epochs the rendezvous is not pinned to one line — a blocklist goes stale each epoch.
        let lines: BTreeSet<_> = (1..=8).map(|e| at(b"community", e)).collect();
        assert!(lines.len() > 1, "the rendezvous line rotates across epochs");
        // A different community computes a different derivation, so it does not track the same rotation.
        let other: BTreeSet<_> = (1..=8).map(|e| at(b"other-community", e)).collect();
        assert_ne!(lines, other, "distinct communities rendezvous differently");
    }

    #[test]
    fn a_bridge_serves_a_bucket_only_against_a_valid_epoch_bound_pow() {
        let beacon = BeaconSeed::new([0x11; 32]);
        let (community, epoch, difficulty) = (b"comm".as_slice(), Epoch::new(3), 8);
        let helper = BridgeHelper::new(peers(10));

        // A solved request serves a bucket of at most BRIDGE_BUCKET peers — never the full set.
        let req = solve_bridge_request(community, epoch, &beacon, difficulty);
        assert!(verify_bridge_request(&req, community, epoch, &beacon, difficulty));
        let resp = helper.serve(&req, community, epoch, &beacon, difficulty).expect("valid PoW is served");
        assert!(resp.peers.len() <= BRIDGE_BUCKET, "a requester learns at most a bucket, not O(N)");
        assert!(!resp.peers.is_empty(), "but does get peers");

        // An unsolved nonce, a wrong epoch, or a wrong community all fail the PoW gate.
        assert!(helper.serve(&BridgeRequest { nonce: req.nonce.wrapping_add(1) }, community, epoch, &beacon, difficulty).is_none());
        assert!(!verify_bridge_request(&req, community, Epoch::new(4), &beacon, difficulty), "the proof expires next epoch");
        assert!(!verify_bridge_request(&req, b"other", epoch, &beacon, difficulty), "and is community-bound");

        // The response round-trips on the wire.
        assert_eq!(BridgeResponse::from_bytes(&resp.to_bytes()).unwrap(), resp);
    }

    #[test]
    fn distinct_requests_get_distinct_buckets_capping_enumeration() {
        let beacon = BeaconSeed::GENESIS;
        let helper = BridgeHelper::new(peers(12));
        // Two different nonces rank the peers differently, so an enumerator cannot harvest the set with one PoW.
        let a = select_bucket(helper_peers(&helper), 1);
        let b = select_bucket(helper_peers(&helper), 999_983);
        assert_eq!(a.len(), BRIDGE_BUCKET);
        assert_ne!(a, b, "distinct requests surface distinct buckets");
        // Even unioning several buckets is far short of the full set from a single cheap harvest.
        let _ = beacon;
    }

    /// Test-only accessor for the helper's peers (the field is private by design).
    fn helper_peers(h: &BridgeHelper) -> &[Peer] {
        &h.peers
    }
}
