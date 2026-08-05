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
//! ([`recover`]). Seizing `< t` members discloses neither the descriptor nor the ability
//! to serve it — the property no prior censorship-bootstrap system provides (the audit's flagged
//! novelty). This is the CALYPSO threshold-hosting primitive ([`fanos_calypso::hosting`]) applied to
//! a *rotating network entry-point* rather than a ledger secret.
//!
//! **And committed, because confidentiality is not integrity.** Threshold hosting says a minority cannot
//! *read* the descriptor. It says nothing about whether a minority can *change* it — and Lagrange
//! interpolation is linear, so one member of the line could add a chosen offset to the reconstruction and
//! make every combiner serve a descriptor of its choosing: the entry peers a whole community bootstraps
//! from. Every other Shamir site in the platform is saved from this by accident, because it reconstructs a
//! *key* and the AEAD tag fails on a wrong one; POROS reconstructs a *plaintext* and has no tag. So a
//! dealing here publishes a [`DescriptorBinding`] — per-share commitments that reject a forged share at
//! arrival, and a descriptor commitment that refuses to serve any reconstruction that is not the dealt one —
//! and the binding is a constructor argument, never a builder method a caller can forget.
//!
//! **The Sybil admission is honest about what it is.** The per-request proof of work
//! ([`solve_ingress_request`]) is a **rate-limiter, not a Sybil cap** (Boneh et al. CRYPTO'18: a
//! sequential-cost proof bounds identity-creation *rate*, never *total* identities). It keeps the
//! insider count `t` small — the Mahdian *FUN 2010* `Ω(t)` floor, not `n`, is what a censor must pay
//! to enumerate — but a true cap requires anchoring to a scarce resource: a fast-mixing trust graph
//! (SybilLimit `O(log n)`/edge) or proof-of-personhood. That anchor is the coherence/credential layer
//! ([`crate::sybil`]). Both gates compose in the host — [`Sybil::Capped`] carries the trust layer's
//! admitted coordinate set, and [`on_request`](PorosHost) serves a requester only if it
//! *both* clears the PoW (rate) *and* is in the admitted set (cap) — so a flood of freshly-minted
//! identities behind a sparse trust cut cannot buy ingress no matter how much work it burns. POROS
//! consumes the admitted *set*, not the graph, so it stays decoupled from the specific cap mechanism.
//!
//! **And a deployed host today runs [`Sybil::Uncapped`]**, which this doc used to leave the reader to
//! infer. The composition site (`crate::composition`) has no set to supply: the trust graph is built and
//! constructed nowhere, because nothing collects trust *edges*. So the paragraph above describes a
//! mechanism that exists and a deployment that does not yet use it, and the gap is a **design** question —
//! where a vouch comes from — rather than a wire that was forgotten. Task #76 carries it. Saying so here is
//! the point of the [`Sybil`] type: the previous shape was `Option<_>` defaulting to `None` behind a
//! builder method nobody called, so "uncapped" was reachable without anyone ever deciding it.
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
use fanos_field::{F2, Field};
use fanos_geometry::{Line, TRIPLE_WIRE_LEN, Triple, decode_triple, encode_triple};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret};
use fanos_primitives::codec::{Reader, put_seq, put_var_bytes};
use fanos_primitives::hash_labeled;
use fanos_rendezvous::{BeaconSeed, Epoch, combiner_for, meeting_line};
use fanos_runtime::ports::GatherClock;
use fanos_runtime::ports::stations::{GatherHealth, Observation, Station, Stations};
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};
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
/// Domain separation for the **descriptor commitment** — the public binding every line verifies its
/// reconstructed descriptor against, so a forged or corrupted share can never serve a wrong descriptor.
const DESCRIPTOR_COMMIT_LABEL: &str = "FANOS-v1/poros-descriptor-commit";
/// Domain separation for a **per-share commitment**, bound to the dealing it belongs to.
const SHARE_COMMIT_LABEL: &str = "FANOS-v1/poros-share-commit";

/// The public **commitment** to an ingress descriptor: `H(descriptor bytes)`. Preimage-resistant, so it
/// discloses nothing about the (semi-secret, per-requester-bucketed) descriptor, yet binds it. Rotation
/// preserves the descriptor, so the commitment is epoch-invariant and a rotated line carries the same one.
#[must_use]
pub fn descriptor_commitment(descriptor: &IngressDescriptor) -> [u8; 32] {
    hash_labeled(DESCRIPTOR_COMMIT_LABEL, &descriptor.to_bytes())
}

/// The commitment to one dealt share: `H(dealing ‖ x ‖ y)`, where `dealing` is the descriptor commitment —
/// so a share commitment belongs to exactly one dealing and cannot be spliced across epochs or communities.
///
/// **Unblinded, deliberately.** `pqvss` blinds its per-share commitments with a nonce so they are not a
/// confirm-a-guess oracle for a low-entropy share. Here the share `y` is `|descriptor|` bytes of uniform
/// `GF(256)` polynomial evaluation (for `t ≥ 2`), so there is nothing to guess; and the value an adversary
/// would want to confirm — the descriptor — is already confirmable against the *public* descriptor
/// commitment. A nonce would buy nothing and would have to travel with every share.
#[must_use]
fn share_commitment(dealing: &[u8; 32], share: &Share) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 1 + share.y().len());
    buf.extend_from_slice(dealing);
    buf.push(share.x());
    buf.extend_from_slice(share.y());
    hash_labeled(SHARE_COMMIT_LABEL, &buf)
}

/// The **public half of a descriptor dealing** — everything a line member and a combiner need to verify, and
/// no secret at all. Published with the line's roster; safe to hand to anyone.
///
/// ## Why a threshold *plaintext* must carry this, and a threshold *key* need not
///
/// Every other Shamir reconstruction in the platform recovers a **key** and immediately AEAD-opens with it
/// (`fanos_nyx::sheaf`, `fanos_nyx::tessera`, `fanos_calypso::hosting::SealedIntro::open`), so the AEAD tag
/// *is* the integrity check: a wrong reconstruction cannot authenticate. POROS is the one site that
/// reconstructs a **plaintext** — the descriptor is the shared secret, not a key — so it has no tag, and
/// nothing detects a wrong reconstruction unless a commitment is checked.
///
/// That gap was not theoretical. Lagrange interpolation is linear, so a member holding one share can add a
/// chosen offset to the reconstructed secret: knowing the true descriptor `S` (which any member learns by
/// acting as combiner once — `on_request` lets every member serve) it sends `y' = λ⁻¹·(T ⊕ S) ⊕ y` and every
/// other combiner reconstructs exactly `T`. One member of an ingress line therefore chose the entry peers
/// every bootstrapping node in the community dialled. The binding is **not optional** for that reason: it is
/// a constructor argument of [`PorosHost`], not a builder method that a caller can forget.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DescriptorBinding {
    dealing: [u8; 32],
    shares: Vec<[u8; 32]>,
}

impl DescriptorBinding {
    /// Canonical wire bytes: `dealing(32) ‖ count(u32 BE) ‖ per-share commitments(32 each)`.
    ///
    /// Public data only, so this is a *provisioning* codec — the ceremony writes it into every member's file
    /// and into the roster a combiner reads. It carries no secret and needs no protection.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.shares.len() * 32);
        out.extend_from_slice(&self.dealing);
        put_seq(&mut out, self.shares.len(), &self.shares, |o, c| o.extend_from_slice(c));
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let dealing = r.array::<32>()?;
        let shares = r.seq(32, Reader::array::<32>)?;
        r.finish()?;
        Some(Self { dealing, shares })
    }

    /// The descriptor commitment `H(descriptor)` — what a reconstruction must equal.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        self.dealing
    }

    /// The commitment to the share at `x` (1-based line position), or `None` once the per-share commitments
    /// are stale — see [`rotated`](Self::rotated).
    #[must_use]
    fn share(&self, x: u8) -> Option<[u8; 32]> {
        self.shares.get(usize::from(x).checked_sub(1)?).copied()
    }

    /// Whether an arriving `share` opens its dealt commitment. Vacuously `true` for a
    /// [`rotated`](Self::rotated) binding, which has no per-share commitments left to check.
    #[must_use]
    fn admits(&self, share: &Share) -> bool {
        self.share(share.x()).is_none_or(|c| share_commitment(&self.dealing, share) == c)
    }

    /// The binding a **rotated** line carries: the descriptor commitment survives (resharing preserves the
    /// secret) but the per-share commitments do not, because the new shares lie on a fresh polynomial. So a
    /// rotated line detects a wrong reconstruction and cannot attribute it — which is precisely why
    /// [`recover`] keeps a one-fault fallback, and why verified resharing is the follow-on.
    #[must_use]
    fn rotated(&self) -> Self {
        Self { dealing: self.dealing, shares: Vec::new() }
    }
}

/// A dealt descriptor: one secret share per line member, plus the public [`DescriptorBinding`] every member
/// and combiner is configured with. Produced by [`shard_descriptor`].
pub struct DealtDescriptor {
    /// One share per line member, in line order (position = `x − 1`), each handed privately to its member.
    pub shares: Vec<Share>,
    /// The public bindings — published, not secret.
    pub binding: DescriptorBinding,
}

/// What a committed reconstruction concluded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Recovery {
    /// Fewer than `threshold` distinct shares are in hand — nothing to decide yet.
    BelowThreshold,
    /// The dealt descriptor, with the `x` of the single share that had to be excluded to obtain it (`None`
    /// when every held share lay on the committed polynomial).
    Recovered(IngressDescriptor, Option<u8>),
    /// A threshold was in hand and no admissible subset produced the committed descriptor.
    Unrecoverable,
}

/// Reconstruct the ingress descriptor from held member `shares` and **verify it against `commitment`**,
/// recovering from a single off-polynomial share.
///
/// A subset whose interpolation hashes to `commitment` is *the* dealt descriptor: BLAKE3 collision
/// resistance means no other subset can match, so acceptance needs no further evidence.
///
/// ## Why the search stops at one exclusion
///
/// It is not a chosen depth. Enumerating exclusion sets of size `k` costs `C(n, k)` interpolations, so a
/// Byzantine member that corrupts `k` shares would amplify **every** request into `Θ(n^k)` combiner work —
/// recovery would itself become the cheapest denial-of-service against the line it protects. Depth one is
/// `n + 1` interpolations, linear in the line, and therefore the deepest search that is not an amplifier.
///
/// It is also exactly enough where the platform ships: the Fano ingress line has `n = q + 1 = 3` members at
/// `t = 2`, so its serving fault budget is `n − t = 1` and drop-one covers the whole of it. On a larger
/// plane the budget is `⌊(q+1)/3⌋ > 1`, and the answer there is **not** a deeper search but the per-share
/// commitments in [`DescriptorBinding`], which reject a forged share at arrival in `O(1)` each and never
/// interpolate at all. The residual is a line that has already *rotated* (per-share commitments are stale
/// after resharing) and holds more than one corrupt share: it fails safe as [`Recovery::Unrecoverable`].
///
/// **And the follow-on is not verified secret sharing — it is this same search, moved to where it is
/// affordable.** The amplification argument above is about the *per-request* path and nothing else. A
/// post-rotation round is per-epoch: a new line can reconstruct once among themselves against the descriptor
/// commitment (which survives rotation, since resharing preserves the secret), and on a match every member's
/// rotated share is provably on the committed polynomial — so each can publish `H(dealing ‖ x ‖ y_new)` and
/// the line has per-share commitments again for the whole epoch, at the cost of one round. On a mismatch the
/// `C(n, t)` subset search *is* affordable there, bounded by the roster rather than by traffic, and it
/// attributes the member so the rotation can retry from a different old subset. No new primitive, no
/// per-share proof the fixed-width onion could not carry.
#[must_use]
pub fn recover(shares: &[Share], threshold: usize, commitment: &[u8; 32]) -> Recovery {
    let held: Vec<&Share> = {
        let mut seen = BTreeSet::new();
        shares.iter().filter(|s| seen.insert(s.x())).collect()
    };
    if held.len() < threshold {
        return Recovery::BelowThreshold;
    }
    let attempt = |subset: Vec<Share>| -> Option<IngressDescriptor> {
        let bytes = recover_service_key(&subset).ok()?;
        let descriptor = IngressDescriptor::from_bytes(&bytes)?;
        (descriptor_commitment(&descriptor) == *commitment).then_some(descriptor)
    };
    let all: Vec<Share> = held.iter().map(|s| (*s).clone()).collect();
    if let Some(descriptor) = attempt(all) {
        return Recovery::Recovered(descriptor, None);
    }
    // One exclusion. Only reachable when dropping still leaves a threshold, which is exactly the line's own
    // spare capacity — below that there is nothing to try and the gather is simply short.
    if held.len() > threshold {
        for skip in 0..held.len() {
            let subset: Vec<Share> =
                held.iter().enumerate().filter(|(i, _)| *i != skip).map(|(_, s)| (*s).clone()).collect();
            if let Some(descriptor) = attempt(subset) {
                let excluded = held.get(skip).map(|s| s.x());
                return Recovery::Recovered(descriptor, excluded);
            }
        }
    }
    Recovery::Unrecoverable
}

/// The moving-target **ingress line** for a community sharing `community`, at `epoch` folded with the
/// beacon `SEED(epoch)`. Legitimate peers COMPUTE it; a censor cannot predict or pre-enumerate it, and
/// it rotates every epoch. Reuses the NYX meeting-line derivation (spec §5) — the ingress is a
/// first-class element of the routing geometry, not a published record.
#[must_use]
pub fn ingress_line<F: Field>(community: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Line<F> {
    meeting_line::<F>(community, epoch, beacon)
}

/// The **canonical** combiner of the [`ingress_line`] — a pure function of the line alone. `None` only on
/// a degenerate plane offering no combiner.
///
/// **This is the canonical case, not the address a requester should dial**: use [`ingress_walk`]. Every
/// member of an ingress line can serve a request (see `PorosHost::on_request`, which has no
/// is-canonical check), so sending every requester here would make one node the single point of failure
/// for a whole community's admission — the same defect #55 removed from every mixnet hop. It is kept for
/// derivations that need the line's canonical point, mirroring `combiner_for` against
/// `combiner_for_salted`.
#[must_use]
pub fn ingress_combiner<F: Field>(
    community: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> Option<Triple> {
    combiner_for::<F>(ingress_line::<F>(community, epoch, beacon).coords())
}

/// The ingress line's members in the order **this requester** should try them — a per-requester
/// permutation, deterministic and public.
///
/// **Why a walk here, where the mixnet gets a single salted pick.** Both fix the same defect (one
/// canonical addressee where only a canonical *set* was required), but the two settings differ in what
/// the requester can observe. A mixnet hop's failure is invisible — a censoring combiner black-holes
/// rather than refuses, so the sender cannot tell a dead pick from a slow one and must not be asked to
/// walk; it re-draws per onion instead, and retransmission does the spreading. POROS admission is a
/// **direct dial**: a refusal or a timeout is observable by the requester, so it can try the next member
/// itself. Walking is therefore strictly better here — one timeout costs a dead first choice rather than
/// the whole admission, and a requester is denied only when the *entire line* refuses it, which is the
/// property the Sybil gate is entitled to assume.
///
/// **Why keyed by the requester.** There is no onion to salt with, but the requester's coordinate is
/// already present and already non-transferable — `admission_challenge` binds the PoW to it — so
/// keying the permutation with it costs nothing and spreads distinct requesters over distinct first
/// choices. Folding `(community, epoch, beacon)` in too means the order rotates with the line itself, so
/// no member is durably "the front door" for anyone.
///
/// Deterministic and public: every party derives the same order without coordinating, the simulator
/// reproduces it, and it discloses nothing the requester's own coordinate does not already disclose.
#[must_use]
pub fn ingress_walk<F: Field>(
    community: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    requester: Triple,
) -> Vec<Triple> {
    let mut members =
        fanos_rendezvous::line_member_coords::<F>(ingress_line::<F>(community, epoch, beacon).coords());
    // Fisher–Yates over a domain-separated XOF keyed by (community, epoch, beacon, requester). Eight
    // bytes per swap, reduced over `u64`: the same width argument as the mixnet's salted pick — reducing
    // a single byte mod `i + 1` biases the low indices by `(256 mod (i+1))/256`, which is 12.9 % at
    // `q = 32` and grows with the plane, and a systematically-favoured first choice is exactly the node
    // an adversary would silence. Over `u64` the bias is `≈ (i+1)·2⁻⁶⁴`.
    let mut key = Vec::with_capacity(community.len() + 8 + 32 + TRIPLE_WIRE_LEN);
    key.extend_from_slice(community);
    key.extend_from_slice(&epoch.to_be_bytes());
    key.extend_from_slice(beacon.as_bytes());
    key.extend_from_slice(&encode_triple(requester));
    let mut stream = alloc_zeroed_swaps(members.len());
    fanos_primitives::hash::hash_xof(INGRESS_WALK_LABEL, &key, &mut stream);
    for i in (1..members.len()).rev() {
        let chunk = stream.get(i * 8..i * 8 + 8).and_then(|b| b.try_into().ok()).unwrap_or([0u8; 8]);
        let j = (u64::from_be_bytes(chunk) % (i as u64 + 1)) as usize;
        members.swap(i, j);
    }
    members
}

/// Domain separator for the [`ingress_walk`] permutation.
const INGRESS_WALK_LABEL: &str = "FANOS-v1/poros-ingress-walk";

/// Domain separator for the [`reshare_contributors`] subset draw.
const RESHARE_SUBSET_LABEL: &str = "FANOS-v1/poros-reshare-subset";

/// The **canonical contributor subset** of a rotation into `target_epoch`: the old-line share indices
/// (`x`, one-based) whose sub-shares every incoming member must combine — *the same ones at every member*.
///
/// # Why the subset cannot be whoever answers first
///
/// Old member `k` re-splits its share `y_k` under a **fresh random** polynomial `g_k` with `g_k(0) = y_k`,
/// so a new member combining subset `A` lands on `y'_j = Σ_{k∈A} λ^A_k·g_k(x'_j) = h_A(x'_j)` where
/// `h_A := Σ_{k∈A} λ^A_k·g_k`. Every `h_A` satisfies `h_A(0) = S` — that is what makes resharing work — but
/// the `g_k` are independent, so **`h_A` and `h_B` agree at 0 and nowhere else**. Two members that combined
/// different subsets therefore hold evaluations of two different polynomials, and interpolating across them
/// yields neither's constant term: the rotated line cannot reconstruct its own descriptor. `shamir`'s own
/// contract says as much — *"every new member using the same `old_xs` subset lands on one consistent new
/// polynomial"*.
///
/// This is not a Byzantine case. Every outgoing member emits (`spawn_ingress_rotation`), so adopting on the
/// first `threshold` to arrive lets ordinary network jitter hand each member a different subset; at the Fano
/// line (`n = 3`, `t = 2`) three independent races agree only about one time in nine.
///
/// # Why a derivation rather than agreement
///
/// Every proactive-resharing protocol needs the committee agreed before combining. `fanos-keygen`'s beacon
/// reshare gets it from an authenticated trigger that **names** `contributors`; POROS has no authority to
/// sign one, so it takes the other route already used for both rosters — a pure function of
/// `(community, target_epoch, old_line)`, which is exactly the shared state `rotation_rosters` is derived
/// from, so no round trip and no I/O. Fisher–Yates over a domain-separated XOF, eight bytes per swap for the
/// width reason argued at [`ingress_walk`].
///
/// Returns the chosen indices **sorted**, or empty when no valid subset exists (an empty/oversized line, a
/// threshold above the roster) — fail-closed, because arming a rotation that cannot complete is worse than
/// not arming one.
fn reshare_contributors(
    community: &[u8],
    target_epoch: Epoch,
    old_line: &[Triple],
    threshold: usize,
) -> Vec<u8> {
    let n = old_line.len();
    if n == 0 || threshold == 0 || threshold > n || u8::try_from(n).is_err() {
        return Vec::new();
    }
    let mut xs: Vec<u8> = (1..=n).map(|i| i as u8).collect();
    let mut key = Vec::with_capacity(community.len() + 8 + n * TRIPLE_WIRE_LEN);
    key.extend_from_slice(community);
    key.extend_from_slice(&target_epoch.to_be_bytes());
    for coord in old_line {
        key.extend_from_slice(&encode_triple(*coord));
    }
    let mut stream = alloc_zeroed_swaps(n);
    fanos_primitives::hash::hash_xof(RESHARE_SUBSET_LABEL, &key, &mut stream);
    for i in (1..n).rev() {
        let chunk = stream.get(i * 8..i * 8 + 8).and_then(|b| b.try_into().ok()).unwrap_or([0u8; 8]);
        let j = (u64::from_be_bytes(chunk) % (i as u64 + 1)) as usize;
        xs.swap(i, j);
    }
    xs.truncate(threshold);
    xs.sort_unstable();
    xs
}

/// A zeroed byte buffer sized for one 8-byte draw per Fisher–Yates swap.
fn alloc_zeroed_swaps(members: usize) -> Vec<u8> {
    vec![0u8; members.saturating_mul(8)]
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
/// ([`shard_descriptor`]) and reconstructed only by a threshold of them ([`recover`]).
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
/// Returns the shares **and** the public [`DescriptorBinding`] — together, because a dealing that hands out
/// shares without publishing what they must open to has no integrity at all, and the two are only ever
/// correct as a pair.
///
/// # Errors
/// Returns `None` if the Shamir parameters are invalid (`threshold` zero or exceeding `line_size`).
#[must_use]
pub fn shard_descriptor(
    descriptor: &IngressDescriptor,
    threshold: u8,
    line_size: u8,
    randomness: &[u8],
) -> Option<DealtDescriptor> {
    let shares = shard_service_key(&descriptor.to_bytes(), threshold, line_size, randomness).ok()?;
    let dealing = descriptor_commitment(descriptor);
    let commitments = shares.iter().map(|s| share_commitment(&dealing, s)).collect();
    Some(DealtDescriptor { shares, binding: DescriptorBinding { dealing, shares: commitments } })
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

/// Default cap on concurrently-gathering requests — a bound on combiner state against a request flood.
/// Bounding `pending` by COUNT is what leaves the gather deadline free to be measured ([`GatherClock`]).
const DEFAULT_MAX_PENDING: usize = 256;

/// A combiner's in-flight gather for one requester: the request, the descriptor shares collected so far
/// (deduped by share index so a member cannot inflate the count), and the timer that bounds it.
struct PendingServe {
    req: IngressRequest,
    shares: BTreeMap<u8, Share>,
    timer: TimerToken,
    /// When the share requests went out — a completed gather yields `now − armed_at` as one latency
    /// sample for the measured deadline ([`GatherClock`]).
    armed_at: Instant,
    /// Set once this gather has reached a threshold and failed to produce the committed descriptor.
    ///
    /// Its expiry must **not** widen the measured deadline. `GatherClock::expired` reads a timeout as "the
    /// line was too slow for the load this node is under" and backs off; a corrupted gather was not slow, and
    /// letting it feed the estimator would let one Byzantine member push every honest gather's deadline to
    /// its ceiling — an attack on the clock, disguised as congestion.
    unrecoverable: bool,
}

/// Whether this host imposes the **Sybil cap**, and it is a decision the caller has to write down.
///
/// The two gates are different things and the module doc is precise about it: the proof-of-work is a
/// *rate*-limiter (Boneh et al., CRYPTO 2018 — a sequential-cost proof bounds identity-creation rate, never
/// total identities), and the cap is what bounds the total. `Uncapped` therefore means "this host has the
/// weaker of the two defences and knows it".
///
/// **It is a constructor argument rather than a builder method, and that is the whole point.** It was
/// `Option<BTreeSet<Triple>>` behind `with_admission`, defaulting to `None`, and `None` admits everyone —
/// so every deployed ingress host ran uncapped, silently, because nothing ever called the builder. A guard
/// behind an opt-in method is a guard that will be absent in production; making it an argument means the
/// composition site has to state which it meant, and a reader can see the answer without searching for a
/// call that may not exist.
///
/// Promotion is still possible at run time via [`PorosHost::set_admitted`] — the cap is a per-epoch quantity
/// that the trust graph re-mixes, so it must be replaceable without rebuilding the host.
///
/// ## The plane cannot supply the cap, and the reason is worth writing down
///
/// The tempting derivation, because it needs no new subsystem: a requester's coordinate is
/// `MapToPoint(VRF(sk, id ‖ epoch ‖ beacon))`, so the distinct coordinates *any* adversary can present in one
/// epoch are a subset of the plane's `q² + q + 1` points — a bound **independent of how many identities it
/// creates**, which is exactly what the PoW cannot give. Serve each coordinate once per epoch and the
/// per-epoch harvest is `(q² + q + 1) · INGRESS_BUCKET`, a constant in the identity count.
///
/// It does not work, and it inverts into an attack. **A coordinate is not a per-identity resource** — it is a
/// shared address, and a cell holds only `≈ q` nodes before coordinates start colliding
/// ([[coordinate-collision-capacity-bound]]). So an adversary that occupies all `q² + q + 1` points — 7 on
/// the Fano base cell — does not exhaust a quota of its own; it locks **every honest requester in the
/// community** out for the rest of the epoch, at a cost of 7 proofs of work. The quota would have to be
/// loose enough to admit the many honest identities sharing each point, at which point it is a per-point
/// rate-limiter and not a cap at all.
///
/// The scarce resource has to be per-*identity*. The design authority names the two that are
/// (`docs/design-anonymity-substrate.md` §6): a fast-mixing trust graph, or a credential system — and the
/// credential must be per-**invitee**, because POROS's `community` byte-string is shared by everyone who was
/// told it, so knowing it caps nothing. That is task #76's real content and it is a subsystem, not a wiring
/// change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Sybil {
    /// No cap: the PoW rate-limiter alone. Every requester that clears the work is served.
    Uncapped,
    /// Only these requester coordinates are served, after they also clear the PoW. Canonically the trust
    /// graph's [`admitted`](crate::sybil::TrustGraph::admitted) output, whose conductance bound caps admitted
    /// Sybils at `O(attack edges)` regardless of how many exist — but POROS consumes the *set*, so a
    /// proof-of-personhood or credential system can supply it instead.
    Capped(BTreeSet<Triple>),
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
/// 3. Once the combiner holds `≥ t` shares it reconstructs the descriptor ([`recover`]),
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
    /// The measured gather deadline (RFC 6298 over completed gathers — [`GatherClock`]).
    gather: GatherClock,
    /// An explicit pin for scenarios that must assert a specific expiry; `None` uses the measured value.
    gather_override: Option<Duration>,
    /// The data-path plane's counters ([`Stations`]). POROS's admission gates all returned the same
    /// silent `Vec::new()`, so an operator could not tell "we are under a Sybil flood" from "our
    /// difficulty is set wrong" — four different worlds, one empty vector.
    stations: Stations,
    // The Sybil **cap** layer (design authority §6) — see [`Sybil`]. POROS stays decoupled from the
    // mechanism: it consumes the admitted SET, not the graph, so proof-of-personhood or a credential system
    // can supply it instead of the trust graph.
    sybil: Sybil,
    // This host's KEM secret — needed only to OPEN sealed reshare sub-shares when rotating into a new epoch
    // line ([`with_kem_secret`](Self::with_kem_secret)). `None` ⇒ a serve-only host that cannot receive a
    // reshare (it can still emit contributions, which use only the new members' PUBLIC keys).
    kem_secret: Option<HybridKemSecret>,
    // The active rotation-into-a-new-line context, set by [`begin_rotation`](Self::begin_rotation): incoming
    // `PorosReshare` sub-shares are opened + gathered here, and a threshold of them combines into this host's
    // rotated share (then adopted). `None` outside a rotation.
    rotation: Option<RotationCtx>,
    // The dealing's public bindings — MANDATORY, because a threshold plaintext has no AEAD tag to fail on a
    // wrong reconstruction and Lagrange is linear (see [`DescriptorBinding`]). Per-share commitments reject a
    // forged share at arrival; the descriptor commitment refuses to serve any reconstruction that is not the
    // dealt one. Rotation keeps the second and drops the first.
    binding: DescriptorBinding,
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
    /// The canonical contributor indices this rotation combines — see [`reshare_contributors`]. Sorted, and
    /// the *only* old members whose sub-shares are gathered: a rotation that combined whoever answered first
    /// would leave each member on a different polynomial.
    contributors: Vec<u8>,
    gather: BTreeMap<u8, Share>,
}

impl PorosHost {
    /// A line member at `coord` holding its dealt descriptor `share` and the dealing's public `binding`,
    /// hosting the ingress `threshold`-of-`line.len()` for `(community, epoch, beacon)` at PoW `difficulty`.
    /// `line` is every member's coordinate in the order [`shard_descriptor`] dealt shares (position = share
    /// index).
    ///
    /// The `binding` is an argument rather than a builder method on purpose: it is the only thing standing
    /// between this line and one of its own members choosing the entry peers the community bootstraps from
    /// ([`DescriptorBinding`]), and a security property a caller can forget to opt into is one that will be
    /// absent in production.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coord: Triple,
        share: Share,
        binding: DescriptorBinding,
        line: Vec<Triple>,
        threshold: usize,
        community: Vec<u8>,
        epoch: Epoch,
        beacon: BeaconSeed,
        difficulty: u32,
        sybil: Sybil,
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
            gather: GatherClock::new(),
            gather_override: None,
            stations: Stations::new(),
            sybil,
            kem_secret: None,
            rotation: None,
            binding,
        }
    }

    /// Provide this host's KEM secret, enabling it to OPEN sealed reshare sub-shares and rotate into a new
    /// epoch line (see [`begin_rotation`](Self::begin_rotation)). Without it the host is serve-only.
    #[must_use]
    pub fn with_kem_secret(mut self, kem_secret: HybridKemSecret) -> Self {
        self.kem_secret = Some(kem_secret);
        self
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

    /// The deadline the next gather is armed with — the pin if one is set, else the measured value.
    fn gather_deadline(&self) -> Duration {
        self.gather_override.unwrap_or_else(|| self.gather.deadline())
    }

    /// Refresh the Sybil-cap allowlist in place (e.g. after the trust graph re-mixes for a new epoch).
    /// Passing an empty set admits no one. Promotes an [`Sybil::Uncapped`] host to capped, which is the
    /// intended path once a trust source exists — the cap is a per-epoch quantity, so it must be replaceable
    /// without rebuilding the host.
    pub fn set_admitted(&mut self, admitted: BTreeSet<Triple>) {
        self.sybil = Sybil::Capped(admitted);
    }

    /// Whether `requester` clears the Sybil cap: always `true` when no cap is configured, else membership in the
    /// admitted allowlist. (The PoW rate-limiter is a separate, additional gate — see [`on_request`](Self::on_request).)
    #[must_use]
    fn sybil_admits(&self, requester: &Triple) -> bool {
        match &self.sybil {
            Sybil::Uncapped => true,
            Sybil::Capped(set) => set.contains(requester),
        }
    }

    /// This host's ingress line as a coordinate triple — the STRUCTURE key the data-path counters use
    /// (`stations` R2). Derived from the roster this host was dealt into, so it needs no lookup.
    fn line_coords(&self) -> Triple {
        // The line's OWN coordinates, derived from the same `(community, epoch, beacon)` that placed this
        // host on it — not a stand-in such as "the roster's first member". A member coordinate would
        // aggregate correctly by accident (every member shares the roster order) while reading as a line
        // triple that it is not, and a plane built to end a diagnosis-by-thin-evidence defect must not
        // put an approximation where the exact value was one call away.
        // `F2` concretely, because `PorosHost` is: the base cell is the Fano plane and every other
        // engine in this crate (`rendezvous_host`, `cell_node`) is F2-concrete for the same reason.
        // Making this generic while every caller passes `F2` would be indirection, not flexibility.
        ingress_line::<F2>(&self.community, self.epoch, &self.beacon).coords()
    }

    /// This host's data-path counters for the current window — **local-only** (`stations` R4: nothing
    /// crosses a node boundary until per-family DP sensitivities are derived).
    #[must_use]
    pub const fn stations(&self) -> &Stations {
        &self.stations
    }

    /// Take and clear this window's data-path observations.
    pub fn take_stations(&mut self) -> Vec<Observation> {
        self.stations.take()
    }

    /// The number of requests currently gathering (combiner state), for tests/observability.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// The epoch this host currently serves (advances when it ``adopt``s a rotation).
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The epoch this host is armed to rotate INTO, or `None` outside a rotation — the observable that says
    /// the receive side is ready for the incoming line's sub-shares.
    #[must_use]
    pub fn rotating_into(&self) -> Option<Epoch> {
        self.rotation.as_ref().map(|r| r.target_epoch)
    }

    /// The rosters of the **outgoing** and **incoming** ingress lines for a rotation to `target_epoch`, under
    /// this host's community and the beacon seed the cell has adopted.
    ///
    /// Both are computed from `(community, epoch, beacon)` alone — a pure function of the plane and the
    /// beacon, with no lookup — which is why the *receive* side of a rotation needs no I/O at all. The emit
    /// side does, because sealing a sub-share needs each new member's KEM public, and that is the asymmetry
    /// that decides where each half can live.
    #[must_use]
    pub fn rotation_rosters(&self, target_epoch: Epoch, beacon: &BeaconSeed) -> (Vec<Triple>, Vec<Triple>) {
        let members = |e: Epoch| {
            fanos_rendezvous::line_member_coords::<F2>(
                ingress_line::<F2>(&self.community, e, beacon).coords(),
            )
        };
        (members(self.epoch), members(target_epoch))
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
        // Floor the reshare threshold at 2 (audit §5.D-1): a rotation must PRESERVE a real seize-`<t`-reveals-
        // nothing threshold, never propagate a degenerate 1-of-n sharing where a single new-line seizure
        // discloses the descriptor. `emit_reshare` reshares at `self.threshold`, so this rejects a host that
        // was (mis)configured below 2 rather than silently spreading a threshold-1 secret to the new line.
        let Ok(threshold) = u8::try_from(self.threshold) else {
            return Vec::new();
        };
        if threshold < 2 {
            return Vec::new();
        }
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
    /// gathered, and combined into this host's rotated share (which it then ``adopt``s). A no-op if
    /// this host is not a member of `new_line`. The driver computes both rosters from
    /// `ingress_line(community, epoch, beacon)` (no I/O) — `new_line` at `target_epoch`, `old_line` at the
    /// current epoch — and calls this before the contributions arrive. `old_line` is the roster whose position
    /// `x-1` a sub-share claiming index `x` must have arrived FROM (sender authentication).
    ///
    /// The **contributor subset is fixed here**, by [`reshare_contributors`], and not by whoever answers
    /// first: every incoming member must combine the *same* old members or they land on different
    /// polynomials and the rotated line cannot reconstruct. A roster that admits no valid subset arms
    /// nothing, which is the honest state rather than a rotation that can never complete.
    pub fn begin_rotation(&mut self, target_epoch: Epoch, new_line: Vec<Triple>, old_line: Vec<Triple>) {
        if let Some(my_new_x) = self.my_x_in(&new_line) {
            let contributors =
                reshare_contributors(&self.community, target_epoch, &old_line, self.threshold);
            if contributors.is_empty() {
                return;
            }
            self.rotation = Some(RotationCtx {
                target_epoch,
                new_line,
                old_line,
                my_new_x,
                contributors,
                gather: BTreeMap::new(),
            });
        }
    }

    /// A reshare sub-share arrived from transport source `from`: authenticate it to its genuine old member
    /// (`from` must be `old_line[old_x-1]`), and if it belongs to the active rotation, names a **canonical
    /// contributor** and opens under this host's KEM secret, gather it (first-writer-wins per old member).
    /// Once *every* contributor in that subset has arrived, combine them into the rotated share and
    /// [`adopt`](Self::adopt) the new epoch/line.
    ///
    /// A sub-share from an old member outside the subset is dropped rather than gathered — every outgoing
    /// member emits, so this is the ordinary case, not an attack. The emitting side is deliberately left
    /// permissive: it computes its roster by a different path than the receiver's `old_line`, and a sender
    /// that filtered on its own view would silently stop a rotation the moment the two disagreed, whereas an
    /// unfiltered sender merely spends `n − t` sets of frames a receiver ignores.
    ///
    /// Sender authentication closes the spoof hole: a `PorosReshare` from any coordinate other than the old
    /// member it claims (`old_x`) is dropped, so an outsider cannot inject a sub-share. A *genuine but
    /// Byzantine* old member's corrupt sub-share still combines here, but a rotated line NEVER serves a
    /// descriptor that fails its [`DescriptorBinding`] check — so
    /// corruption is fail-safe (detected at serve, never a wrong descriptor). Robust recovery from such a
    /// Byzantine contributor (attribute + retry a different old-member subset) is the VSS follow-on.
    fn on_reshare(&mut self, from: Triple, target_epoch: Epoch, old_x: u8, sealed: &SealedShare) -> Vec<Effect> {
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
            // A refused forgery and a sub-share that never arrived are the same silence, and this gate is
            // where an attacker is *known* to be probing — so the rejection is counted (#109).
            self.stations.record_tagged(
                Station::AuthenticationRejected,
                Some(from),
                Some(crate::Gate::ReshareSubShare.tag()),
                1,
            );
            return Vec::new();
        }
        // Only the canonical subset is gathered: combining whoever arrived first puts each member on a
        // different polynomial (see `reshare_contributors`).
        if !ctx.contributors.contains(&old_x) {
            return Vec::new();
        }
        let Some(sub) = open_service_share(sealed, secret) else {
            return Vec::new(); // not addressed to us, or tampered
        };
        ctx.gather.entry(old_x).or_insert(sub);
        // Every contributor, not a count: the subset is what makes the new shares interpolate.
        let Some(subs) = ctx
            .contributors
            .iter()
            .map(|x| ctx.gather.get(x).cloned())
            .collect::<Option<Vec<Share>>>()
        else {
            return Vec::new(); // still gathering the canonical subset
        };
        let old_xs: Vec<u8> = ctx.contributors.clone();
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
        // The per-share commitments described the OLD polynomial; the rotated shares lie on a fresh one, so
        // they no longer bind anything and keeping them would reject every honest share. The descriptor
        // commitment survives, because resharing preserves the secret it commits to.
        self.binding = self.binding.rotated();
    }

    /// A request arrived at us as the combiner: verify its PoW, seed our own share, fan share-requests to
    /// the rest of the line. A bad proof, wrong epoch/community, or a duplicate/flood is dropped.
    fn on_request(&mut self, from: Triple, now: Instant, req: IngressRequest) -> Vec<Effect> {
        // Gate 0 — **identity binding** (audit §5.C): the request must have arrived FROM the coordinate it
        // claims (`req.requester`). The PoW below is bound to `req.requester`, so without this an attacker could
        // relay or replay another identity's request/proof under its own transport; enforcing `from ==
        // req.requester` makes the VRF-identity coordinate the unforgeable, NON-TRANSFERABLE admission subject
        // the §6 derivation rests on (the binding the `verify_ingress_request` doc names as the caller's duty,
        // now enforced in-engine — parallel to the reshare `from`-authentication).
        if from != req.requester {
            self.stations.record(Station::AdmissionIdentityUnbound, None);
            return Vec::new();
        }
        // Gate 1 — the PoW **rate-limiter** (bounds identity-creation rate, keeps the insider count small).
        if !verify_ingress_request(&req, &self.community, self.epoch, &self.beacon, self.difficulty) {
            self.stations.record(Station::AdmissionPowFailed, None);
            return Vec::new();
        }
        // Gate 2 — the Sybil **cap** (the trust-graph conductance bound): a valid PoW is necessary but not
        // sufficient. A requester the coherence layer has not admitted is dropped no matter how much work it did,
        // so a flood of freshly-minted identities behind a sparse trust cut cannot buy ingress.
        if !self.sybil_admits(&req.requester) {
            self.stations.record(Station::AdmissionSybilCapped, None);
            return Vec::new();
        }
        if self.pending.contains_key(&req.requester) || self.pending.len() >= self.max_pending {
            self.stations.record(Station::AdmissionNoCapacity, None);
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
        effects.push(Effect::ArmTimer { token: timer, after: self.gather_deadline() });
        let requester = req.requester;
        self.pending.insert(requester, PendingServe { req, shares, timer, armed_at: now, unrecoverable: false });
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

    /// A member's descriptor share arrived: **check it against its dealt commitment**, fold it into the
    /// matching gather, and retry.
    ///
    /// The check is at arrival rather than at reconstruction because that is what preserves liveness: a
    /// forged share never enters the gather, so the gather can still fill from the line's honest members and
    /// serve normally. Rejecting it later would mean the gather holds a threshold it cannot use.
    fn on_share(&mut self, now: Instant, requester: Triple, share: Share) -> Vec<Effect> {
        if !self.binding.admits(&share) {
            // Provably not the value the dealer handed that member — evidence of forgery, not of failure.
            self.stations.record(Station::ShareOffCommitment, None);
            return Vec::new();
        }
        let Some(pending) = self.pending.get_mut(&requester) else {
            self.stations.record(Station::ShareForUnknownRequest, None);
            return Vec::new();
        };
        pending.shares.entry(share.x()).or_insert(share);
        self.try_serve(now, requester)
    }

    /// If the gather for `requester` holds a threshold of shares, reconstruct the **committed** descriptor,
    /// bucket it, and send the response; else leave it pending.
    fn try_serve(&mut self, now: Instant, requester: Triple) -> Vec<Effect> {
        let Some(pending) = self.pending.get(&requester) else {
            return Vec::new();
        };
        let shares: Vec<Share> = pending.shares.values().cloned().collect();
        let descriptor = match recover(&shares, self.threshold, &self.binding.commitment()) {
            Recovery::BelowThreshold => return Vec::new(),
            Recovery::Recovered(descriptor, excluded) => {
                if let Some(x) = excluded {
                    // Recovered by dropping one share, so a share this host could not reject at arrival was
                    // wrong — the post-rotation case, where the per-share commitments are stale.
                    //
                    // **And it names the member**, which it did not (#52). `recover`'s one-fault fallback
                    // finds the wrong share BY EXCLUSION — it is the `x` returned right here — and this
                    // recorded `None`, throwing away the only attribution a rotated line has. The task said
                    // a rotated line "detects corruption but cannot attribute it"; half of that was the
                    // commitment scheme and half was a discarded value.
                    //
                    // A share index is a line position plus one, so the coordinate is a lookup. `None` only
                    // if a share carried an `x` outside the roster, which the gather should not admit — and
                    // recording it unattributed then is right rather than inventing a member.
                    let member = usize::from(x).checked_sub(1).and_then(|i| self.line.get(i)).copied();
                    self.stations.record(Station::ShareOffCommitment, member);
                }
                descriptor
            }
            Recovery::Unrecoverable => {
                self.stations.record(Station::DescriptorUnrecoverable, None);
                // Keep gathering — a later share may complete an admissible subset — but mark the gather so
                // its expiry does not back off the measured deadline. It was corrupted, not slow.
                if let Some(p) = self.pending.get_mut(&requester) {
                    p.unrecoverable = true;
                }
                return Vec::new();
            }
        };
        let Some(pending) = self.pending.get(&requester) else {
            return Vec::new();
        };
        let response = IngressResponse { peers: descriptor.bucket(&pending.req) };
        let armed_at = pending.armed_at;
        self.pending.remove(&requester);
        // One completed gather is one latency sample — `RTT + C_share + Q` together, under the load the
        // next gather will meet. This is what replaces the former 2 s constant.
        self.gather.observe(now.since(armed_at));
        let line = self.line_coords();
        self.stations.record(Station::GatherCompleted, Some(line));
        vec![Effect::Send {
            to: requester,
            frame: encode(FrameType::PorosResponse, &response.to_bytes()),
        }]
    }

    /// A gather deadline fired: drop the still-incomplete request it bounds, freeing its slot — and back
    /// off ([`GatherClock::expired`]): the deadline was demonstrably too short for the load this node is
    /// under, and an expiry yields no sample, so nothing else would ever widen it (RFC 6298 §5.5 + Karn).
    fn on_timer(&mut self, token: TimerToken) -> Vec<Effect> {
        if let Some(&requester) = self
            .pending
            .iter()
            .find(|(_, p)| p.timer == token)
            .map(|(r, _)| r)
        {
            let corrupted = self.pending.remove(&requester).is_some_and(|p| p.unrecoverable);
            let line = self.line_coords();
            if corrupted {
                // The line answered and its answers were wrong. Backing off here would let one Byzantine
                // member drive every honest gather's deadline to its ceiling by feeding the estimator a
                // timeout per request — congestion control taking dictation from an adversary.
                self.stations.record(Station::GatherUnpeelable, Some(line));
            } else {
                self.gather.expired();
                self.stations.record(Station::GatherExpired, Some(line));
            }
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
                        .map_or_else(Vec::new, |req| self.on_request(from, now, req)),
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
            // The sense-only read: POROS owns its own gather clock and station counters, so it answers for
            // them directly rather than a driver reaching into an engine (`docs/design-observability.md` §4.1).
            Input::Command(Command::Observe) => vec![Effect::Notify(Notification::DataPath {
                stations: self.stations.observations(),
                gather: GatherHealth::of(&self.gather),
            })],
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
    fn the_four_admission_gates_are_distinguishable_instead_of_one_silent_vec() {
        // `docs/design-observability.md` §4 calls POROS the sharpest case: its four admission gates —
        // identity binding, PoW, the Sybil cap, and pending-full — all returned the same silent
        // `Vec::new()`, so an operator could not tell "we are under a Sybil flood" from "our difficulty
        // is set wrong". Four different worlds, one empty vector. Each must now name itself.
        let desc = descriptor(6);
        let threshold = 2usize;
        let community = b"gates".to_vec();
        let (epoch, difficulty) = (Epoch::new(1), 8);
        let beacon = BeaconSeed::new([0x5c; 32]);
        let line: Vec<Triple> = (0..3).map(coord).collect();
        let randomness = vec![0x2Bu8; desc.to_bytes().len() * (threshold - 1) + 8];
        let dealt = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);
        let admitted = coord(4);
        let mut host = PorosHost::new(
            line[0],
            shares[0].clone(),
            binding.clone(),
            line.clone(),
            threshold,
            community.clone(),
            epoch,
            beacon,
            difficulty,
                Sybil::Capped([admitted].into_iter().collect()),
            );

        // Gate 0 — a valid proof arriving from the WRONG coordinate (relayed/replayed).
        let good = solve_ingress_request(admitted, &community, epoch, &beacon, difficulty);
        assert!(host.step(Instant(0), Input::Message { from: coord(5), frame: request_frame(&good) }).is_empty());
        // Gate 1 — an unsolved proof, from its own coordinate.
        let bad = IngressRequest { requester: admitted, nonce: 0 };
        assert!(host.step(Instant(1), Input::Message { from: admitted, frame: request_frame(&bad) }).is_empty());
        // Gate 2 — a VALID proof from an identity the coherence layer has not admitted.
        let outsider = coord(6);
        let outsider_req = solve_ingress_request(outsider, &community, epoch, &beacon, difficulty);
        assert!(
            host.step(Instant(2), Input::Message { from: outsider, frame: request_frame(&outsider_req) }).is_empty()
        );

        // Every refusal above produced the same empty effect vector — which is precisely why the wire
        // could never distinguish them, and precisely what the plane must.
        let s = host.stations();
        assert_eq!(s.total(Station::AdmissionIdentityUnbound), 1, "a relayed proof names itself");
        assert_eq!(s.total(Station::AdmissionPowFailed), 1, "an unsolved proof names itself");
        assert_eq!(s.total(Station::AdmissionSybilCapped), 1, "a capped identity names itself");
        assert_eq!(
            s.total(Station::AdmissionNoCapacity),
            0,
            "and a gate that did NOT fire stays silent — otherwise every refusal would look like all four"
        );

        // A window is read and cleared in one step, so a count can be neither double-read nor lost.
        let window = host.take_stations();
        assert_eq!(window.len(), 3, "three distinct stations fired");
        assert_eq!(host.stations().total(Station::AdmissionPowFailed), 0, "the window restarted");
    }

    #[test]
    fn the_ingress_walk_spreads_requesters_over_the_whole_line() {
        // The admission SPOF. Every member of an ingress line can serve a request — `on_request` has no
        // is-canonical check — so addressing every requester at `ingress_combiner` would have made one
        // node the single point of failure for a whole community's admission, which is exactly the
        // defect #55 removed from every mixnet hop.
        use std::collections::BTreeSet;
        let beacon = BeaconSeed::new([0x9e; 32]);
        let (community, epoch) = (b"walkers".as_slice(), Epoch::new(5));
        let line = ingress_line::<F2>(community, epoch, &beacon).coords();
        let members: BTreeSet<Triple> =
            fanos_rendezvous::line_member_coords::<F2>(line).into_iter().collect();
        let requester = |i: u32| -> Triple { [i + 1, 0, 1] };

        let mut first_choices = BTreeSet::new();
        for i in 0..64u32 {
            let walk = ingress_walk::<F2>(community, epoch, &beacon, requester(i));
            // **Completeness is the availability property**: a requester is denied only when the WHOLE
            // line refuses, so the walk must reach every member — and exactly once, or a dead member
            // would be retried while a live one went untried.
            assert_eq!(
                walk.iter().copied().collect::<BTreeSet<_>>(),
                members,
                "a walk is a permutation of the line's members — every member reachable, none twice"
            );
            assert_eq!(walk.len(), members.len(), "no duplicates");
            first_choices.insert(walk[0]);
        }
        // The spread itself: distinct requesters must not share one front door.
        assert!(
            first_choices.len() >= 2,
            "64 requesters must not all start at the same member — a constant first choice IS the \
             single point of failure this replaces: {first_choices:?}"
        );

        // Deterministic (both sides derive it without coordinating), and keyed by the requester.
        assert_eq!(
            ingress_walk::<F2>(community, epoch, &beacon, requester(7)),
            ingress_walk::<F2>(community, epoch, &beacon, requester(7)),
            "same inputs, same order — the host and the requester agree without a round trip"
        );
        // And it rotates with the line: the same requester gets a different order next epoch, so no
        // member is durably anyone's front door.
        let rotated: BTreeSet<Vec<Triple>> = (1..12u64)
            .map(|e| ingress_walk::<F2>(community, Epoch::new(e), &beacon, requester(7)))
            .collect();
        assert!(rotated.len() > 1, "the walk order rotates across epochs");
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
        let dealt = shard_descriptor(&desc, threshold, line_size, &randomness).expect("valid sharing");
        let (shares, binding) = (dealt.shares, dealt.binding);
        assert_eq!(shares.len(), usize::from(line_size), "one share per line member");

        // Any threshold of members reconstructs the exact descriptor.
        let commit = binding.commitment();
        let got = |sub: &[Share]| recover(sub, usize::from(threshold), &commit);
        assert_eq!(got(&shares[0..2]), Recovery::Recovered(desc.clone(), None), "members 0,1 reconstruct");
        assert_eq!(got(&shares[1..3]), Recovery::Recovered(desc.clone(), None), "members 1,2 reconstruct");

        // A single seized share cannot reconstruct — recovery of a 1-subset does not yield the descriptor.
        // (Shamir needs `threshold` distinct shares; one is below threshold.)
        assert_eq!(
            got(&shares[0..1]),
            Recovery::BelowThreshold,
            "one seized share does not disclose the entry peers",
        );
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
        let dealt = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);
        let host = |i: usize| {
            PorosHost::new(
                line[i],
                shares[i].clone(),
                binding.clone(),
                line.clone(),
                threshold,
                community.clone(),
                epoch,
                beacon,
                difficulty,
                Sybil::Uncapped,
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
        let dealt = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);
        let mut combiner = PorosHost::new(
            line[0],
            shares[0].clone(),
            binding.clone(),
            line.clone(),
            threshold,
            community.clone(),
            epoch,
            beacon,
            difficulty,
                Sybil::Uncapped,
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

        // Identity binding (§5.C): a VALID request (correct PoW) that arrives from a DIFFERENT coordinate than
        // it claims is dropped — the PoW is bound to `req.requester`, so a relay/replay under another transport
        // cannot spend someone else's work. The proof is non-transferable across identities.
        let good = solve_ingress_request(coord(4), &community, epoch, &beacon, difficulty);
        assert!(
            combiner.step(Instant(1), Input::Message { from: coord(5), frame: request_frame(&good) }).is_empty(),
            "a valid request from the wrong source coordinate is rejected (from != req.requester)",
        );
        assert_eq!(combiner.pending(), 0, "no gather opened for a mismatched-source request");
        // The same request from its OWN coordinate is served (the binding is not over-eager).
        assert!(
            !combiner.step(Instant(2), Input::Message { from: coord(4), frame: request_frame(&good) }).is_empty(),
            "the identical request from its claimed coordinate is admitted",
        );
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
        let dealt = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);

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
            binding.clone(),
            line.clone(),
            threshold,
            community.clone(),
            epoch,
            beacon,
            difficulty,
                Sybil::Capped(admitted.clone()),
            );

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
    fn the_ingress_gather_deadline_is_measured_not_a_constant() {
        // POROS held its own copy of the same 2000 ms constant, and the same argument retires it: the
        // right value moves 45x between build profiles alone (`fanos-aphantos/tests/gather_cost.rs`).
        // The estimator is proven in `fanos_ports::gather`; what this engine owes is the WIRING — a
        // completed serve feeds a latency sample, an expiry feeds the backoff. Delete either call and
        // one half of this fails.
        let desc = descriptor(6);
        let threshold = 2usize;
        let community = b"clockwork".to_vec();
        let (epoch, difficulty) = (Epoch::new(1), 4);
        let beacon = BeaconSeed::new([0x2C; 32]);
        let line: Vec<Triple> = (0..3).map(coord).collect();
        let randomness = vec![0x3Du8; desc.to_bytes().len() * (threshold - 1) + 8];
        let dealt = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);
        let mut combiner = PorosHost::new(
            line[0],
            shares[0].clone(),
            binding.clone(),
            line.clone(),
            threshold,
            community.clone(),
            epoch,
            beacon,
            difficulty,
                Sybil::Uncapped,
            );
        let armed_deadline = |effects: &[Effect]| {
            effects.iter().find_map(|e| match e {
                Effect::ArmTimer { after, .. } => Some(*after),
                _ => None,
            })
        };
        // A distinct requester per attempt: `pending` is keyed by requester, so reusing one would
        // collide with its own in-flight gather rather than open a new one.
        let requester = |i: u32| -> Triple { [i + 100, 0, 1] };
        let ask = |c: &mut PorosHost, now: u64, r: Triple| {
            let req = solve_ingress_request(r, &community, epoch, &beacon, difficulty);
            c.step(Instant(now), Input::Message { from: r, frame: request_frame(&req) })
        };

        // Cold: nothing measured, so the bootstrap deadline stands.
        let first = ask(&mut combiner, 0, requester(0));
        assert_eq!(
            armed_deadline(&first),
            Some(fanos_runtime::ports::gather::INITIAL_GATHER_DEADLINE),
            "a cold combiner arms the bootstrap deadline"
        );

        // A run of fast gathers: member 1's share completes each at t = 2, 4 ms after it was asked.
        let four_ms = Duration::from_millis(4).as_nanos();
        let mut now = 0u64;
        for i in 0..12u32 {
            let r = requester(i);
            if i > 0 {
                ask(&mut combiner, now, r);
            }
            now += four_ms;
            let served = combiner.step(
                Instant(now),
                Input::Message {
                    from: line[1],
                    frame: encode(FrameType::PorosShare, &encode_share_reply(r, &shares[1])),
                },
            );
            assert!(!served.is_empty(), "the gather completed and served at threshold");
        }
        let probe = ask(&mut combiner, now, requester(50));
        let measured = armed_deadline(&probe).unwrap();
        assert!(
            measured < Duration::from_millis(80),
            "after a dozen 4 ms completions the armed deadline tracks the measurement, got {measured:?}"
        );

        // Let that gather EXPIRE: the next arm must be strictly wider. Without the backoff an estimator
        // fed only by completions can never learn it has become too tight, because an expiry yields no
        // sample — the failure mode RFC 6298 §5.5 exists to prevent.
        let timer = probe
            .iter()
            .find_map(|e| match e {
                Effect::ArmTimer { token, .. } => Some(*token),
                _ => None,
            })
            .unwrap();
        combiner.step(Instant(now), Input::Timer(timer));
        let rearmed = ask(&mut combiner, now, requester(51));
        let widened = armed_deadline(&rearmed).unwrap();
        assert!(
            widened > measured,
            "an expiry must widen the next armed deadline: {widened:?} vs {measured:?}"
        );
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
        let dealt =
            shard_descriptor(&desc, old_t, old_n, &vec![0x5Au8; secret_len * usize::from(old_t - 1) + 8]).unwrap();
        let (old_shares, commit) = (dealt.shares, dealt.binding.commitment());

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
            recover(&[new_shares[0].clone(), new_shares[2].clone()], usize::from(new_t), &commit),
            Recovery::Recovered(desc.clone(), None),
            "the new epoch line reconstructs the identical descriptor after resharing",
        );
        // Seizing < t of the new line still reveals nothing (a real threshold committee), and a stale old
        // share is not a valid point of the fresh polynomial (proactive refresh).
        assert_eq!(
            recover(&[new_shares[0].clone()], usize::from(new_t), &commit),
            Recovery::BelowThreshold,
            "one new share reveals nothing",
        );
        assert_ne!(new_shares[0].y(), old_shares[0].y(), "the rotated share is on a fresh polynomial, not a copy");
    }

    #[test]
    fn two_old_subsets_reshare_to_two_different_polynomials() {
        // **Why the contributor subset must be canonical, stated as the mathematical fact it is.** Each old
        // member re-splits under a *fresh random* polynomial `g_k`, so the combined `h_A = Σ_{k∈A} λ^A_k·g_k`
        // depends on `A` everywhere except at 0 — where every `h_A` equals the secret, which is what makes
        // resharing work and also what makes the divergence invisible until reconstruction. A new member that
        // combined `{1,2}` while its neighbour combined `{2,3}` holds a point of a different curve, and the
        // line cannot interpolate across them. This test is the reason `reshare_contributors` exists.
        let desc = descriptor(8);
        let secret_len = desc.to_bytes().len();
        let (t, n) = (2u8, 3u8);
        let dealt =
            shard_descriptor(&desc, t, n, &vec![0x5Au8; secret_len * usize::from(t - 1) + 8]).unwrap();
        let old_shares = dealt.shares;

        // Every old member contributes, as production does.
        let contributions: Vec<Vec<Share>> = old_shares
            .iter()
            .enumerate()
            .map(|(k, s)| {
                let rnd: Vec<u8> = (0..secret_len).map(|i| ((i * 37 + k * 89 + 11) % 251) as u8).collect();
                reshare_descriptor_share(s, t, n, &rnd).expect("a valid resharing contribution")
            })
            .collect();

        // New member 1 combines two DIFFERENT old subsets. Same member, same position, same inputs otherwise.
        let combine = |subset: &[usize]| {
            let subs: Vec<Share> = subset.iter().map(|&k| contributions[k][0].clone()).collect();
            let xs: Vec<u8> = subset.iter().map(|&k| old_shares[k].x()).collect();
            combine_descriptor_reshares(1, &subs, &xs).expect("a valid combined share")
        };
        assert_ne!(
            combine(&[0, 1]).y(),
            combine(&[1, 2]).y(),
            "two old subsets must give the SAME member two different rotated shares — if this ever became \
             an equality the canonical-subset rule would be unnecessary, and the reason for it would have \
             silently stopped being true",
        );
    }

    #[test]
    fn the_contributor_subset_is_the_same_at_every_member_and_moves_with_the_epoch() {
        // The property `on_reshare` depends on: every member derives the identical subset from state they all
        // already hold, with no round trip. Plus the two things that make it usable — it is a real subset of
        // the right size, and it is not the same subset every epoch (a permanently-silent contributor must not
        // block every rotation for ever; a fresh draw each epoch is what retries around it).
        let line: Vec<Triple> = (0..3).map(|i| Point::<F2>::at(i).coords()).collect();
        let community = b"a-community".to_vec();

        let at = |e: u64| reshare_contributors(&community, Epoch::new(e), &line, 2);
        assert_eq!(at(7), at(7), "the draw is deterministic — every member lands on the same subset");
        assert_eq!(at(7).len(), 2, "exactly the threshold: the smallest set that reconstructs");
        assert!(at(7).iter().all(|x| (1..=3).contains(x)), "indices are one-based positions in the old line");
        assert!(at(7).windows(2).all(|w| w[0] < w[1]), "sorted, so the pairing with sub-shares is unambiguous");

        // A different community, or a different old roster, is a different draw — the subset is bound to the
        // rotation it belongs to and cannot be replayed from another one.
        assert_ne!(
            (0..64).map(&at).collect::<Vec<_>>(),
            (0..64).map(|e| reshare_contributors(b"other", Epoch::new(e), &line, 2)).collect::<Vec<_>>(),
            "a different community draws differently",
        );
        // Over many epochs every subset is reached, so a down member is routed around within a few epochs
        // rather than blocking the line permanently. C(3,2) = 3 subsets; 64 draws must find all of them.
        let seen: BTreeSet<Vec<u8>> = (0..64).map(at).collect();
        assert_eq!(seen.len(), 3, "the draw covers every {{t}}-subset, so no member is a permanent gate");

        // Fail-closed on a roster that admits no subset, rather than arming a rotation that cannot complete.
        assert!(reshare_contributors(&community, Epoch::new(1), &line, 4).is_empty(), "threshold above the line");
        assert!(reshare_contributors(&community, Epoch::new(1), &[], 2).is_empty(), "no old line at all");
        assert!(reshare_contributors(&community, Epoch::new(1), &line, 0).is_empty(), "a zero threshold");
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
        let dealt =
            shard_descriptor(&desc, old_t, old_n, &vec![0x5Au8; secret_len * usize::from(old_t - 1) + 8]).unwrap();
        let (old_shares, commit) = (dealt.shares, dealt.binding.commitment());

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
            recover(&[new_shares[0].clone(), new_shares[1].clone()], usize::from(new_t), &commit),
            Recovery::Recovered(desc.clone(), None),
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
        let dealt = shard_descriptor(&desc, t, n, &vec![0x5Au8; secret_len * usize::from(t - 1) + 8]).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);

        // Old-line hosts, each holding its real descriptor share.
        let old_host = |i: usize| {
            PorosHost::new(old_line[i], shares[i].clone(), binding.clone(), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
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
                let mut h = PorosHost::new(new_line[j], placeholder, binding.clone(), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
                    .with_kem_secret(secret);
                h.begin_rotation(new_epoch, new_line.clone(), old_line.clone());
                h
            })
            .collect();

        // EVERY old member emits, as production does — the driver's rule is "only an OUTGOING member emits",
        // and all of them are outgoing. Each host keeps the canonical subset and drops the rest; a test that
        // emitted from exactly `t` would be choosing the subset for the engine.
        for (i, &from) in old_line.iter().enumerate() {
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
            recover(&[new_hosts[0].share.clone(), new_hosts[1].share.clone()], usize::from(t), &binding.commitment()),
            Recovery::Recovered(desc.clone(), None),
            "the rotated new line hosts the identical descriptor",
        );
        // A stale sub-share for a DIFFERENT epoch is ignored (no spurious adoption / gather pollution).
        let fresh_secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF0, 0])).0; // new_host[0]'s secret
        let mut fresh = PorosHost::new(new_line[0], Share::new(1, vec![0u8; secret_len]), binding.clone(), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
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
        let dealt = shard_descriptor(&desc, t, n, &vec![0x5Au8; secret_len * usize::from(t - 1) + 8]).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);
        let old_host = |i: usize| {
            PorosHost::new(old_line[i], shares[i].clone(), binding.clone(), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
        };
        let secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x77, 0])).0;
        let new_pubs: Vec<HybridKemPublic> =
            (0..3).map(|j| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x77, j as u8])).1).collect();
        let new_keys: Vec<&HybridKemPublic> = new_pubs.iter().collect();
        let mut victim = PorosHost::new(new_line[0], Share::new(1, vec![0u8; secret_len]), binding.clone(), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
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
        // combines, so the new line's rotated shares are poisoned. Resharing invalidates the dealt per-share
        // commitments — the new shares lie on a fresh polynomial — so this is the case that reaches the
        // descriptor commitment, and it must serve NOTHING rather than a wrong ingress set.
        let desc = descriptor(6);
        let (t, n) = (2u8, 3u8);
        let secret_len = desc.to_bytes().len();
        let (old_epoch, new_epoch) = (Epoch::new(1), Epoch::new(2));
        let beacon = BeaconSeed::new([0x88; 32]);
        let old_line: Vec<Triple> = (0..3).map(coord).collect();
        let new_line: Vec<Triple> = (3..6).map(coord).collect();
        let dealt = shard_descriptor(&desc, t, n, &vec![0x5Au8; secret_len * usize::from(t - 1) + 8]).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);

        // The Byzantine member is chosen to be one the rotation actually *combines*: only the canonical
        // contributor subset is gathered, so corrupting a member outside it would poison nothing and this
        // test would pass while proving less than it claims. Derived rather than hard-coded, so a future
        // change to the draw cannot silently defang it.
        let contributors = reshare_contributors(b"c", new_epoch, &old_line, usize::from(t));
        let byz_i = usize::from(contributors[0]) - 1;

        // Every old member emits (production's rule); the one at `byz_i` holds a CORRUPTED share (flipped
        // bytes), so its contribution poisons every combination that includes it.
        let old_hosts: Vec<PorosHost> = (0..usize::from(n))
            .map(|i| {
                let share = if i == byz_i {
                    let mut bad_y = shares[i].y().to_vec();
                    bad_y[0] ^= 0xFF;
                    Share::new(shares[i].x(), bad_y)
                } else {
                    shares[i].clone()
                };
                PorosHost::new(old_line[i], share, binding.clone(), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
            })
            .collect();

        let new_kp: Vec<(HybridKemSecret, HybridKemPublic)> =
            (0..3).map(|j| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x99, j as u8]))).collect();
        let new_keys: Vec<&HybridKemPublic> = new_kp.iter().map(|(_, p)| p).collect();
        // Every new host is COMMITTED to the true descriptor.
        let mut new_hosts: Vec<PorosHost> = (0..3)
            .map(|j| {
                let secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x99, j as u8])).0;
                let mut h = PorosHost::new(new_line[j], Share::new(u8::try_from(j + 1).unwrap(), vec![0u8; secret_len]), binding.clone(), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
                    .with_kem_secret(secret);
                h.begin_rotation(new_epoch, new_line.clone(), old_line.clone());
                h
            })
            .collect();

        // Route every old member's contribution to the new line; the hosts keep the canonical subset.
        for (i, host) in old_hosts.iter().enumerate() {
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
        // And it says so. Resharing poisoned *every* new share, so no subset of them is the dealt polynomial
        // and drop-one has nothing to find — the gather names itself unrecoverable rather than presenting as
        // a line that was merely slow. Counted once per arriving share, because each arrival is a fresh
        // attempt that failed and the operator's question is "how much of this line's traffic is failing",
        // not "how many requests noticed".
        assert_eq!(
            new_hosts[0].stations().total(Station::DescriptorUnrecoverable),
            2,
            "a reconstruction that cannot produce the committed descriptor must name itself, per attempt",
        );

        // Control: an UNcorrupted rotation of the same committed line DOES serve (the guard is not over-eager).
        let good_old_hosts: Vec<PorosHost> = (0..usize::from(n))
            .map(|i| {
                PorosHost::new(old_line[i], shares[i].clone(), binding.clone(), old_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
            })
            .collect();
        let mut good_hosts: Vec<PorosHost> = (0..3)
            .map(|j| {
                let secret = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x99, j as u8])).0;
                let mut h = PorosHost::new(new_line[j], Share::new(u8::try_from(j + 1).unwrap(), vec![0u8; secret_len]), binding.clone(), new_line.clone(), usize::from(t), b"c".to_vec(), old_epoch, beacon, 4,
                Sybil::Uncapped,
            )
                    .with_kem_secret(secret);
                h.begin_rotation(new_epoch, new_line.clone(), old_line.clone());
                h
            })
            .collect();
        for (i, host) in good_old_hosts.iter().enumerate() {
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

    #[test]
    fn one_line_member_cannot_choose_the_entry_peers_a_bootstrapping_node_dials() {
        use fanos_field::F256;
        // **The attack this module is built against, run end to end.**
        //
        // Lagrange interpolation is LINEAR, so a member holding one share can add a chosen offset to the
        // reconstructed secret:
        //
        //     S = λ_a·y_a ⊕ λ_b·y_b   ⇒   y_b' = λ_b⁻¹·(T ⊕ S) ⊕ y_b   makes every combiner recover T
        //
        // It needs only `S` — which any member learns by acting as combiner once, since `on_request` has no
        // is-canonical check and every member can serve — and its own `y_b`. That is not corruption-as-denial:
        // the attacker *picks* `T`, and `T` is the set of entry peers every new node in the community dials.
        //
        // When the descriptor binding was a builder method that defaulted to `None`, this test passed with
        // `response.peers == evil.bucket(&req)`. It is kept in that shape — forge, deliver, then demand the
        // committed peers — so that removing either guard makes it fail loudly rather than silently weaken.
        let desc = descriptor(6);
        let threshold = 2usize;
        let community = b"steer".to_vec();
        let (epoch, difficulty) = (Epoch::new(1), 4);
        let beacon = BeaconSeed::new([0xA5; 32]);
        let line: Vec<Triple> = (0..3).map(coord).collect();
        let randomness = vec![0x3Cu8; desc.to_bytes().len() * (threshold - 1) + 8];
        let dealt = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);

        // The attacker's descriptor: the same shape (so the encoding is the same length), entirely its peers.
        let evil = IngressDescriptor {
            peers: (0..6)
                .map(|i| Peer { coord: coord(i), addr: SocketAddr::from(([203, 0, 113, i as u8], 6666)) })
                .collect(),
        };
        let (s_bytes, t_bytes) = (desc.to_bytes(), evil.to_bytes());
        assert_eq!(s_bytes.len(), t_bytes.len(), "the forgery is length-preserving");

        // The combiner is line[0] (x = 1); the Byzantine member is line[2] (x = 3). `try_serve` fires as soon
        // as a threshold is in hand, so the subset it interpolates over is exactly {1, 3} — which the attacker,
        // knowing the public x-coordinates, computes without asking anyone.
        let (xa, xb) = (shares[0].x(), shares[2].x());
        let inv = |v: u8| F256::inv(u32::from(v)) as u8;
        let mul = |a: u8, b: u8| F256::mul(u32::from(a), u32::from(b)) as u8;
        let lambda_b = mul(xa, inv(xa ^ xb)); // L_b(0) = x_a/(x_a − x_b), subtraction == XOR in GF(2⁸)
        let forged = Share::new(
            xb,
            shares[2]
                .y()
                .iter()
                .zip(s_bytes.iter().zip(&t_bytes))
                .map(|(&yb, (&s, &t))| mul(inv(lambda_b), s ^ t) ^ yb)
                .collect(),
        );
        // The forgery is arithmetically sound: interpolating {honest x=1, forged x=3} yields exactly `T`.
        assert_eq!(
            recover(&[shares[0].clone(), forged.clone()], threshold, &descriptor_commitment(&evil)),
            Recovery::Recovered(evil.clone(), None),
            "the forged share really does steer an unguarded reconstruction to the attacker's descriptor",
        );

        let host = |i: usize| {
            PorosHost::new(
                line[i],
                shares[i].clone(),
                binding.clone(),
                line.clone(),
                threshold,
                community.clone(),
                epoch,
                beacon,
                difficulty,
                Sybil::Uncapped,
            )
        };
        let mut combiner = host(0);
        let requester = coord(5);
        let req = solve_ingress_request(requester, &community, epoch, &beacon, difficulty);
        let fanned = combiner.step(Instant(0), Input::Message { from: requester, frame: request_frame(&req) });

        // The Byzantine member answers the share-request with its forged share.
        let poison = encode(FrameType::PorosShare, &encode_share_reply(requester, &forged));
        let served = combiner.step(Instant(1), Input::Message { from: line[2], frame: poison });
        assert!(
            served.is_empty(),
            "a forged share must not produce a response — it does not open its dealt commitment",
        );
        assert_eq!(
            combiner.stations().total(Station::ShareOffCommitment),
            1,
            "and the forgery is counted as forgery, not as a share that merely arrived late",
        );

        // **Liveness is preserved, which is the whole reason the check is at arrival.** The forged share never
        // entered the gather, so the honest member's share still completes it — and the peers served are the
        // dealt ones, not the attacker's.
        let share_req = fanned
            .iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if *to == line[1] => Some(frame.clone()),
                _ => None,
            })
            .expect("the combiner fanned a share-request to member 1");
        let reply = host(1).step(Instant(2), Input::Message { from: line[0], frame: share_req });
        let honest = reply
            .into_iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if to == line[0] => Some(frame),
                _ => None,
            })
            .expect("member 1 returned its descriptor share");
        let response = combiner
            .step(Instant(3), Input::Message { from: line[1], frame: honest })
            .iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if *to == requester => {
                    let (decoded, _) = decode_frame(frame).ok()?;
                    (decoded.frame_type() == Some(FrameType::PorosResponse))
                        .then(|| IngressResponse::from_bytes(decoded.body))?
                }
                _ => None,
            })
            .expect("the line still serves after refusing the forgery");
        assert_eq!(
            response.peers,
            desc.bucket(&req),
            "the served peers are the DEALT ones — the Byzantine member neither steered nor denied",
        );
        assert_ne!(response.peers, evil.bucket(&req), "and are not the attacker's");
    }

    #[test]
    fn a_rotated_line_still_refuses_a_steered_descriptor_with_only_the_commitment_left() {
        use fanos_field::F256;
        // The residual case, stated as a test. Resharing puts the new shares on a fresh polynomial, so the
        // dealt per-share commitments no longer bind anything and `adopt` drops them — a rotated line has only
        // the descriptor commitment left. That is weaker (it detects rather than attributes), and this pins
        // exactly how much weaker: the steer is still refused, the line simply cannot say by whom.
        let desc = descriptor(6);
        let threshold = 2usize;
        let community = b"rotated".to_vec();
        let (epoch, difficulty) = (Epoch::new(1), 4);
        let beacon = BeaconSeed::new([0xC3; 32]);
        let line: Vec<Triple> = (0..3).map(coord).collect();
        let randomness = vec![0x2Eu8; desc.to_bytes().len() * (threshold - 1) + 8];
        let dealt = shard_descriptor(&desc, threshold as u8, line.len() as u8, &randomness).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);
        let rotated = binding.rotated();
        assert_eq!(rotated.commitment(), binding.commitment(), "rotation preserves the descriptor commitment");
        assert!(rotated.share(1).is_none(), "and drops the per-share commitments, which no longer bind");

        let evil = IngressDescriptor {
            peers: (0..6)
                .map(|i| Peer { coord: coord(i), addr: SocketAddr::from(([198, 51, 100, i as u8], 4444)) })
                .collect(),
        };
        let (s_bytes, t_bytes) = (desc.to_bytes(), evil.to_bytes());
        let (xa, xb) = (shares[0].x(), shares[2].x());
        let inv = |v: u8| F256::inv(u32::from(v)) as u8;
        let mul = |a: u8, b: u8| F256::mul(u32::from(a), u32::from(b)) as u8;
        let lambda_b = mul(xa, inv(xa ^ xb));
        let forged = Share::new(
            xb,
            shares[2]
                .y()
                .iter()
                .zip(s_bytes.iter().zip(&t_bytes))
                .map(|(&yb, (&s, &t))| mul(inv(lambda_b), s ^ t) ^ yb)
                .collect(),
        );

        let mut combiner = PorosHost::new(
            line[0],
            shares[0].clone(),
            rotated,
            line.clone(),
            threshold,
            community.clone(),
            epoch,
            beacon,
            difficulty,
                Sybil::Uncapped,
            );
        let requester = coord(5);
        let req = solve_ingress_request(requester, &community, epoch, &beacon, difficulty);
        combiner.step(Instant(0), Input::Message { from: requester, frame: request_frame(&req) });
        let poison = encode(FrameType::PorosShare, &encode_share_reply(requester, &forged));
        assert!(
            combiner.step(Instant(1), Input::Message { from: line[2], frame: poison }).is_empty(),
            "the descriptor commitment alone still refuses a steered reconstruction",
        );
        assert_eq!(
            combiner.stations().total(Station::ShareOffCommitment),
            0,
            "but it cannot attribute — the share passed arrival, because there was nothing to check it against",
        );
        assert_eq!(
            combiner.stations().total(Station::DescriptorUnrecoverable),
            1,
            "so the failure surfaces as an unrecoverable gather instead",
        );

        // **And drop-one recovers where the line has spare capacity.** Once the honest third member answers,
        // the combiner holds 3 shares of which 1 is forged, and `n − t = 1` is exactly the fault budget: the
        // one-exclusion search finds the honest pair and serves the dealt peers.
        let honest = encode(FrameType::PorosShare, &encode_share_reply(requester, &shares[1]));
        let response = combiner
            .step(Instant(2), Input::Message { from: line[1], frame: honest })
            .iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if *to == requester => {
                    let (decoded, _) = decode_frame(frame).ok()?;
                    (decoded.frame_type() == Some(FrameType::PorosResponse))
                        .then(|| IngressResponse::from_bytes(decoded.body))?
                }
                _ => None,
            })
            .expect("drop-one recovered the committed descriptor from the honest pair");
        assert_eq!(response.peers, desc.bucket(&req), "and served the DEALT peers");
        assert_eq!(
            combiner.stations().total(Station::ShareOffCommitment),
            1,
            "the excluded share is finally attributed — by exclusion, which is the only evidence a rotated \
             line has",
        );

        // **And "attributed" means it NAMES the member** (#52). This assertion checked a COUNT while its
        // message claimed attribution, and the station recorded `None` — so a rotated line reported that
        // *somebody* was wrong and nothing more, which is the half of this finding that was a discarded
        // value rather than a commitment scheme. `recover`'s one-exclusion search already returns the `x` it
        // dropped; a share index is a line position plus one, so the coordinate is a lookup.
        let attributed: Vec<Option<Triple>> = combiner
            .stations()
            .observations()
            .into_iter()
            .filter(|o| o.station == Station::ShareOffCommitment && o.count > 0)
            .map(|o| o.line)
            .collect();
        assert_eq!(
            attributed,
            vec![Some(line[2])],
            "the forged share came from line[2], and that is the member the station must name"
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
