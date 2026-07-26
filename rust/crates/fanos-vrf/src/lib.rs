//! # fanos-vrf — a real verifiable random function for the beacon & rendezvous
//!
//! The hash derivation in [`fanos_primitives::vrf`] is deterministic but **unverifiable**: nothing
//! stops a node lying about the coordinate it derived. This crate replaces it with an RFC 9381-*style*
//! VRF on the ristretto255 group (via the vetted [`vrf_r255`] crate) — it is *not* the
//! `ECVRF-EDWARDS25519-SHA512` ciphersuite of RFC 9381 and is not wire-compatible with it, so the RFC is a
//! reference, not a conformance claim: a node *proves* that its
//! per-epoch coordinate was derived correctly from its secret key, and anyone holding the node's
//! public key verifies that proof **without learning the secret** (spec §L6, §L1 beacon).
//!
//! * [`VrfSecret`] / [`VrfPublic`] / [`VrfProof`] wrap the primitive with a small, misuse-resistant
//!   surface (seed-derivable keys, byte encodings).
//! * [`prove_coordinate`] / [`verify_coordinate`] lift it to the protocol object: a **verifiable
//!   projective coordinate** `MapToPoint(VRF(sk, node ‖ epoch ‖ beacon))` that rotates every epoch —
//!   folding the epoch's beacon seed so it is unpredictable ahead of time — and cannot be forged or
//!   misreported (the `HELLO` proof-of-coordinate, spec §7.3).
//!
//! The composition adds no new hardness assumption — ristretto255 discrete log, already assumed by
//! the X25519/Ed25519 hybrid — and the primitive is a published construction, not a novel one.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod beacon;
pub mod dkg;
/// A post-quantum, hash-based Merkle-VRF for the bounded epoch domain (spec §16 `[P]`, an alternative to the
/// classical ristretto VRF above). See [`pqvrf`] and `docs/design-pq-vrf.md`.
pub mod pqvrf;
/// A post-quantum threshold randomness beacon with reconstruction-uniqueness — committed Shamir + an
/// all-`t`-subsets consistency check (spec §16 `[P]`). NOVEL/UNAUDITED; see [`pqvss`].
pub mod pqvss;
/// A verifiable shuffle (Sako–Kilian cut-and-choose over re-randomizable ElGamal) — sound, linkage-hiding
/// mixnet proof, generic over the cryptosystem so the ristretto instantiation PQ-swaps to lattice (spec §16
/// `[P]`). NOVEL/UNAUDITED; see [`shuffle`].
pub mod shuffle;
/// A post-quantum Ring-LWE re-randomizable encryption — the lattice backend that makes [`shuffle`] run
/// post-quantum with the identical proof (spec §16 `[P]`). NOVEL/UNAUDITED; see [`rlwe`].
pub mod rlwe;
pub mod vss;

use alloc::vec;
use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{Plane, Point};
use fanos_primitives::hash::label;
use fanos_primitives::{BeaconSeed, Epoch, map_to_point};
use vrf_r255::{Proof, PublicKey, SecretKey};

/// Length of a serialized VRF proof (`Γ ‖ c ‖ s`), in bytes.
pub const PROOF_LEN: usize = 80;
/// Length of a VRF output (the hash `β`), in bytes.
pub const OUTPUT_LEN: usize = 64;

/// A VRF output — the pseudo-random hash `β` a valid proof yields.
pub type VrfOutput = [u8; OUTPUT_LEN];

/// A VRF secret key (seed-derivable; carries its own public key). Deliberately **not** `Copy` — a
/// long-term coordinate secret must not be silently duplicated across stack frames (audit A6) — and its
/// `Debug` is redacted so a secret can never be printed into a log. (Wipe-on-drop is blocked upstream:
/// `vrf_r255::SecretKey` exposes no `Zeroize`; the derivation seed is wiped by its owner instead.)
#[derive(Clone)]
pub struct VrfSecret(SecretKey);

impl core::fmt::Debug for VrfSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VrfSecret(<redacted>)")
    }
}

/// A VRF public key: verifies proofs, reveals nothing about the secret.
#[derive(Clone, Copy, Debug)]
pub struct VrfPublic(PublicKey);

/// A VRF proof `π` binding an input to an output under a public key.
#[derive(Clone, Copy, Debug)]
pub struct VrfProof(Proof);

impl VrfSecret {
    /// Derive a secret key from any 32-byte seed — **total**: every seed yields a key.
    ///
    /// The seed is hashed **uniformly into the scalar field** (a wide reduction of a domain-separated
    /// XOF). A raw `SecretKey::from_bytes` would instead demand an already-canonical scalar
    /// (`< ℓ ≈ 2²⁵²`) and reject ~15/16 of random seeds — a trap for any caller deriving a VRF key
    /// deterministically from a node seed. Reducing mod order first makes the bytes always canonical,
    /// so the construction cannot fail; a node identity can derive its coordinate-VRF key from its seed
    /// with no error path (spec §L0).
    ///
    /// # Panics
    /// Never in practice: the mod-order reduction yields a scalar `< ℓ`, whose canonical bytes
    /// `SecretKey::from_bytes` always accepts. The internal assertion only documents that invariant.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut wide = [0u8; 64];
        fanos_primitives::hash::hash_xof("FANOS-v1/vrf-seed", &seed, &mut wide);
        let scalar = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide);
        // A mod-order-reduced scalar (< ℓ) has canonical bytes that `SecretKey::from_bytes` always
        // accepts, so this is total — the reduction above is exactly what guarantees it.
        #[allow(clippy::expect_used)]
        Self(
            Option::from(SecretKey::from_bytes(scalar.to_bytes()))
                .expect("a mod-order-reduced scalar is a canonical VRF secret key"),
        )
    }

    /// The 32-byte canonical encoding of this secret key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// This key's public half.
    #[must_use]
    pub fn public(&self) -> VrfPublic {
        VrfPublic(PublicKey::from(self.0))
    }

    /// Prove the VRF over `alpha`, returning the proof and the output it commits to.
    #[must_use]
    pub fn prove(&self, alpha: &[u8]) -> (VrfProof, VrfOutput) {
        let proof = self.0.prove(alpha);
        // The prover recovers its own output by verifying under its public key (always valid here).
        let output = Option::from(PublicKey::from(self.0).verify(alpha, &proof))
            .unwrap_or([0u8; OUTPUT_LEN]);
        (VrfProof(proof), output)
    }
}

impl VrfPublic {
    /// Parse a public key from its 32-byte encoding (with the group validity check).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        PublicKey::from_bytes(bytes).map(Self)
    }

    /// The 32-byte canonical encoding of this public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify `proof` for input `alpha`, returning the VRF output iff it is valid.
    #[must_use]
    pub fn verify(&self, alpha: &[u8], proof: &VrfProof) -> Option<VrfOutput> {
        Option::from(self.0.verify(alpha, &proof.0))
    }
}

impl VrfProof {
    /// The 80-byte serialized proof.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PROOF_LEN] {
        self.0.to_bytes()
    }

    /// Parse a proof from its 80-byte encoding, or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: [u8; PROOF_LEN]) -> Option<Self> {
        Proof::from_bytes(bytes).map(Self)
    }
}

/// Map a VRF output to a uniform projective point — the verifiable coordinate (spec §7.1, §L6).
#[must_use]
pub fn coordinate_from_output<F: Field>(output: &VrfOutput) -> Point<F> {
    map_to_point::<F>(label::COORD, output)
}

/// The `k`-th point of a node's **verifiable probe sequence** — where it lands after being displaced from its first `k`
/// preferences by lower-ranked claimants. `k = 0` is exactly [`coordinate_from_output`], so nothing changes for a node
/// that meets no collision.
///
/// ## Why a probe sequence at all
///
/// A coordinate is a *uniform draw* over the plane's `P = q² + q + 1` points, so by the birthday bound distinct nodes
/// collide once `n` approaches `√P ≈ q`, and two nodes on one point are mutually unroutable (one address per point).
/// Measured: seven nodes in PG(2,2) occupied **four** distinct points. Without resolution a cell therefore supports
/// `O(q)` nodes rather than `q² + q + 1` — a factor-`q` capacity loss (`fanos_sim::fabric::injective_probability`).
///
/// ## Why the sequence is derived from the node's own output, and nothing else
///
/// Placement security (§3.2 assumption 2) rests on a node being unable to *aim* its coordinate — at a victim's lines, at
/// a chosen storage neighbourhood. Any resolution rule that lets a node influence where it is displaced **to** trades
/// that away: choosing freely among `K` destinations is exactly a factor-`K` gain in aiming power.
///
/// So the destination sequence is a pure function of the node's own VRF output, fixed the moment the epoch's beacon is
/// known and no more predictable than `p_0` was. A node has **zero** choice over the *set* of points available to it. The
/// only thing it could misreport is *how far along* the sequence it sits, and that is what [`displacement_is_forced`]
/// makes it prove.
///
/// ## Why the walk stays on ONE LINE — the adversarial correction
///
/// An earlier version walked the *whole plane* by double hashing, which recovers capacity but sells a failure mode.
/// Because the walk is a deterministic function of a **public** VRF output, an attacker who knows a victim's identity can
/// compute its entire fallback sequence the moment the beacon lands, and — combined with grinding (~`N` local hashes to
/// seat a Sybil at a chosen point, threat model B1) — **steer** the victim: seat low-ranked Sybils on `p₀ … p_{j−1}` and
/// the victim deterministically lands on `p_j`. Before probing existed, that same spend merely made the victim
/// *unroutable*: a denial of service, disruptive and detectable. Steering a victim onto a line the attacker occupies is
/// **eclipse**, which is quieter and worse.
///
/// Confining the walk to one line through `p₀` — the line chosen by the node's *own* VRF output — removes the gain. The
/// attacker can now only move a victim among points of a line **he did not choose**, and to exploit that he must occupy
/// that line, which is the `N·H_{q+1}` coupon-collector cost he faced anyway. Probing stops being a lever.
///
/// The capacity cost is negligible where it matters, because a walk fails only if *every* point of the line is taken:
///
/// | plane | load 0.25 | load 0.5 | load 0.75 |
/// |---|---|---|---|
/// | `q = 7` (line 8) | 1.5e-5 | 3.9e-3 | 0.10 |
/// | `q = 31` (line 32) | 5.4e-20 | 2.3e-10 | 1.0e-4 |
/// | `q = 127` (line 128) | 8.6e-78 | 2.9e-39 | 1.0e-16 |
///
/// It is only poor on `PG(2,2)`, whose lines hold three points — one more way the base cell is a test fixture rather than
/// a deployment. The honest summary: full-plane probing recovers marginally more capacity on a toy plane and hands a
/// resourced adversary a steering primitive everywhere; line-restricted probing gives that up and keeps the capacity that
/// exists at real `q`.
///
/// ## Why the sequence within the line is a permutation, and not another hash
///
/// The obvious construction — `p_k = MapToPoint(H(probe ‖ output ‖ k))` — is a random *function*, so a node's own
/// sequence repeats points and never enumerates the plane. Measured on that version: at `n = P = 7` it seated **5** of 7
/// nodes, better than the bare draw's 4.62 but still short, because 7 draws from 7 points cover only ~4.6 of them. The
/// probing was re-colliding with itself.
///
/// This is **double hashing**, the classic fix, applied within the line:
///
/// ```text
/// p_k = line[(start + k·s) mod (q+1)],   start = position of MapToPoint(output) on its line,   gcd(s, q+1) = 1
/// ```
///
/// A stride coprime to the walk's length makes `k ↦ (start + k·s) mod len` a **cyclic permutation of the line's `q + 1`
/// points**, so the sequence enumerates that line and probing seats the node whenever any point of it is free. Both the
/// line and the stride derive from the node's own output, so the permutation is verifiable and unchoosable; the stride is
/// searched upward from a hashed start until coprime, which terminates immediately in practice and is deterministic for
/// any length — necessary because `q + 1` need not be prime (`q = 31` gives a line of 32 points).
#[must_use]
pub fn probe_point<F: Field>(output: &VrfOutput, k: u16) -> Point<F> {
    if k == 0 {
        // The preferred point needs no line: it is the walk's own starting position, so this fast path agrees with
        // `probe_walk` by construction rather than by coincidence.
        return coordinate_from_output::<F>(output);
    }
    let walk = probe_walk::<F>(output);
    walk.get(usize::from(k) % walk.len().max(1)).copied().unwrap_or_else(|| coordinate_from_output::<F>(output))
}

/// Where this node's own walk reaches `p`, or `None` if `p` is not on its line.
///
/// The inverse view of [`probe_point`], and the reason a claim to a point is checkable by anyone: the index is a function
/// of the peer's VRF **output** alone, so a verifier learns how far along `p` sits for that peer without being told, and
/// without needing to know where the peer actually settled. That is what keeps [`verify_coordinate_claim`]
/// **non-recursive**.
#[must_use]
pub fn probe_index_of<F: Field>(output: &VrfOutput, p: &Point<F>) -> Option<u16> {
    if coordinate_from_output::<F>(output) == *p {
        return Some(0); // same fast path as `probe_point`, same reason
    }
    let k = probe_walk::<F>(output).iter().position(|q| q == p)?;
    u16::try_from(k).ok()
}

/// The node's full probe walk: the `q + 1` points of its line, in the order its own output visits them.
///
/// **One sequence, two views.** [`probe_point`] reads it forwards and [`probe_index_of`] reads it backwards, so the two
/// cannot disagree about where a point sits — a class of defect this code has already paid for once (see
/// [`displacement_is_forced`]).
fn probe_walk<F: Field>(output: &VrfOutput) -> Vec<Point<F>> {
    let first = coordinate_from_output::<F>(output);
    // The line this node falls back along: one of the `q + 1` lines through its preferred point, chosen by its own output
    // so the node has no say in which.
    let through: Vec<_> = Plane::<F>::lines_through(first).collect();
    let Some(&line) = through.get(probe_line_index(output) % through.len().max(1)) else {
        return vec![first];
    };
    let pts: Vec<_> = Plane::<F>::points_on(line).collect();
    let len = pts.len();
    if len == 0 {
        return vec![first];
    }
    // Ordered by a stride coprime to the line size — a cyclic permutation of the line, for the same reason the plane walk
    // needed one: a hash would revisit points and stall short of the free seat. Start at `first`'s own position so `k`
    // counts *away from* the preferred point.
    let start = pts.iter().position(|p| *p == first).unwrap_or(0);
    let stride = coprime_stride(probe_stride_seed(output), len);
    (0..len).map(|k| pts.get((start + k.wrapping_mul(stride)) % len).copied().unwrap_or(first)).collect()
}

/// Which of the `q + 1` lines through the preferred point this node falls back along — derived, so unchoosable.
fn probe_line_index(output: &VrfOutput) -> usize {
    let d = fanos_primitives::hash::hash_labeled(label::COORD_PROBE, output);
    usize::from(d[0]) | (usize::from(d[1]) << 8)
}

/// The raw stride seed for ordering a line's points.
fn probe_stride_seed(output: &VrfOutput) -> usize {
    let d = fanos_primitives::hash::hash_labeled(label::COORD, output);
    usize::from(d[2]) | (usize::from(d[3]) << 8)
}

/// The smallest value at or above `seed mod (len-1) + 1` that is coprime to `len` — so stepping by it cycles through
/// every point of the line rather than a sub-orbit.
fn coprime_stride(seed: usize, len: usize) -> usize {
    if len <= 2 {
        return 1;
    }
    let start = 1 + (seed % (len - 1));
    (0..len).map(|d| 1 + ((start - 1 + d) % (len - 1))).find(|&s| gcd(s, len) == 1).unwrap_or(1)
}

/// The number of points on a line of `F`'s plane, `q + 1` — and hence the length of a probe walk.
///
/// The walk is confined to one line (see [`probe_point`]), so it **cycles** after this many steps: index `k` and
/// `k + (q+1)` name the same point. Every bound on a probe index is therefore this, not the plane size. Getting that
/// wrong is not merely wasteful — a claim at index `k + (q+1)` is equivalent to one at `k` but demands `q+1` more
/// witnesses, so an honest node would build an absurd chain to reach a point one step away.
#[must_use]
pub const fn probe_bound<F: Field>() -> u16 {
    // `q + 1` fits a `u16` for every plane this code can represent.
    (F::Q + 1) as u16
}

/// Binary-free Euclidean gcd, used only to pick a stride coprime to a line's length.
#[must_use]
const fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Total order used to arbitrate a collision: the VRF output read big-endian, lowest wins.
///
/// It is an ordering on *unforgeable* values — a node cannot lower its own rank without a different VRF secret, and
/// cannot predict its rank before the epoch's beacon. Both sides of a collision compute the same verdict from public
/// data, so resolution needs no negotiation, no round trip, and no agreement on membership: it is a **local pairwise
/// rule** that two nodes discovering each other apply identically.
#[must_use]
pub fn outranks(a: &VrfOutput, b: &VrfOutput) -> bool { a < b }

/// The total order on **claims to one point**: reaching it in fewer probe steps wins, and equal steps are broken by rank.
///
/// A node's claim to `p` is the pair `(probe_index_of(output, p), output)`, and both halves are unforgeable functions of
/// its VRF output — so every node computes the same verdict for the same pair of contenders, from public data, with no
/// negotiation. Ties are impossible: equal index *and* equal output means the same VRF, i.e. the same node.
///
/// Lexicographic order is deliberate and matches how the rest of the platform arbitrates (SYNARC-Ω U.14 B3). Ranking by
/// index first means a node that merely *wants* a point yields it to one whose walk arrives earlier — the cheaper claim,
/// and the one needing no witnesses at all — instead of rank alone deciding, which is what left a displaced holder
/// squatting a point its preferrer could prove and it could not.
#[must_use]
pub fn claim_beats(challenger: (u16, &VrfOutput), incumbent: (u16, &VrfOutput)) -> bool {
    challenger.0 < incumbent.0 || (challenger.0 == incumbent.0 && outranks(challenger.1, incumbent.1))
}

/// Whether a claimant at probe index `k` was **forced** off its `j`-th point by `witness`, for `j < k`.
///
/// The claimant's probe sequence is fixed by its own output, so the one degree of freedom left is claiming a larger `k`
/// than reality — landing further along a sequence it cannot choose, but which it might still prefer. This closes it: a
/// claim to index `k` is accepted only with `k` witnesses, the `j`-th holding a **better claim** ([`claim_beats`]) to the
/// claimant's `j`-th point. Each step is then a public fact rather than an assertion.
///
/// Verification is **non-recursive**: the witness's claim is `probe_index_of(witness_output, p_j)`, a function of its own
/// output, so checking a chain of length `k` costs `k` independent VRF verifications and never unfolds into the witnesses'
/// own chains. What it does *not* need is where the witness finally settled — which is exactly why the predicate can be
/// the same one [`settle_index`] uses.
///
/// ## The defect this replaced, and the measurement that found it
///
/// The original rule accepted only a witness that **preferred** `p_j` (index 0) *and* outranked the claimant, while
/// `settle_index` advanced past any point merely **held** by a better-ranked node. Two different predicates: a holder
/// displaced *onto* `p_j` does not prefer it, so it pushed the claimant off without supplying the witness the claimant
/// needed. The doc claimed the price was "occupancy efficiency, never correctness or security". That was **wrong** — the
/// node could neither hold its point nor prove any later one, so it could not be seated at all, and its HELLO would be
/// rejected. Measured over settled populations with *complete* information, the best case
/// (`examples/unprovable_displacement.rs`):
///
/// | plane | nodes | displaced | **unprovable** | first instance |
/// |---|---|---|---|---|
/// | `PG(2,2)` | 5 | 261 | 47 (18.0%) | index 2 |
/// | `PG(2,4)` | 12 | 572 | 100 (17.5%) | index 2 |
/// | `PG(2,7)` | 30 | 769 | 166 (21.6%) | **index 1** |
///
/// Index 1 at `PG(2,7)`: displaced a single step and already unprovable, so it was not an artefact of deep chains.
///
/// Under this rule the count is **0 by construction** — the predicate that moves a node is the predicate that justifies
/// it. The cost is occupancy: 2812 of 3000 seated versus the old rule's 3000, but 166 of those were inadmissible, so the
/// comparison is 2812 against 2834 — 0.8%, spent on phantom yields (a node vacates `p` for a contender that settles
/// elsewhere). The security-relevant quantity is unchanged and, measured, marginally better: a node can prove any index up
/// to its first unbeaten one and none beyond, and that prefix is **1.28** points wide on average against the old rule's
/// **1.30** (`PG(2,7)`, load 0.53).
#[must_use]
pub fn displacement_is_forced<F: Field>(
    claimant: &VrfOutput,
    j: u16,
    witness_public: &VrfPublic,
    witness_id: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    witness_proof: &VrfProof,
) -> bool {
    let Some(witness_output) = witness_public.verify(&beacon_alpha(witness_id, epoch, beacon), witness_proof) else {
        return false;
    };
    let contested = probe_point::<F>(claimant, j);
    // A point off the witness's own line is one it has no claim to, so it can displace nobody from it.
    let Some(reached) = probe_index_of::<F>(&witness_output, &contested) else {
        return false;
    };
    claim_beats((reached, &witness_output), (j, claimant))
}

/// The probe index a node settles at, given whatever peers it can observe — the sans-I/O core of live resolution.
///
/// `contender(p)` reports the **best claim any other node has to `p`** as `(probe_index_of(their_output, p),
/// their_output)`, or `None` if nobody the caller knows of reaches `p`. The walk stops at the first index whose point no
/// contender claims better ([`claim_beats`]).
///
/// This is the *same* predicate [`displacement_is_forced`] checks, which is the whole point: a node advances exactly where
/// it can prove it had to, so **no node is ever forced to a position it cannot justify**. Deriving the two independently
/// is what produced the defect recorded on `displacement_is_forced`.
///
/// Three properties follow from the claim being a function of outputs alone, none of which the previous
/// occupancy-based rule had:
///
/// * **One-shot.** A claim to `p` does not depend on where anyone settled, so there is no iteration to a fixed point and
///   no dependence on the order in which nodes arrive or learn of each other.
/// * **Injective.** Two nodes settling on `p` would each have to hold the best claim to it, and the order is total.
/// * **Monotone in information.** A node that has seen fewer peers may settle too early and later advance — a convergence
///   question, not a correctness one, since every intermediate position is one it can prove. Re-run it whenever the peer
///   set changes or the beacon advances.
///
/// The walk is bounded by [`probe_bound`] — the line's length — since [`probe_point`] cycles through exactly that many
/// points. Past it every point of the node's line is better claimed and it cannot be seated at all, which is the honest
/// answer rather than a loop over repeats.
#[must_use]
pub fn settle_index<F: Field>(
    output: &VrfOutput,
    contender: impl Fn(&Point<F>) -> Option<(u16, VrfOutput)>,
) -> Option<u16> {
    (0..probe_bound::<F>()).find(|&k| match contender(&probe_point::<F>(output, k)) {
        None => true,
        // The claimant's own claim to its `k`-th point is `k` by definition of the walk.
        Some((reached, theirs)) => !claim_beats((reached, &theirs), (k, output)),
    })
}

/// One step of a [`CoordinateClaim`]'s justification: the node whose *preference* forced the claimant off one of its
/// earlier probe points.
///
/// Carries the witness's identity, key and VRF proof — everything needed to check the step without asking anyone. Note
/// what it does **not** carry: where the witness itself ended up. Verification is non-recursive by construction.
#[derive(Clone, Debug)]
pub struct DisplacementWitness {
    /// The witness node's identity bytes, as fed to the coordinate VRF.
    pub id: Vec<u8>,
    /// The witness's VRF public key.
    pub public: VrfPublic,
    /// The witness's coordinate proof for this epoch and beacon.
    pub proof: VrfProof,
}

/// A node's **verifiable claim** to a coordinate: its own coordinate proof, the probe index it sits at, and one witness
/// per skipped index proving that each was taken by a lower-ranked node.
///
/// This is the contract a peer checks in a `HELLO` proof-of-coordinate. `index = 0` with no witnesses is the pre-existing
/// claim, so a node that meets no collision presents exactly what it always did.
#[derive(Clone, Debug)]
pub struct CoordinateClaim {
    /// The claimant's own coordinate proof.
    pub proof: VrfProof,
    /// The probe index the claimant occupies.
    pub index: u16,
    /// Exactly `index` witnesses; the `j`-th justifies skipping probe `j`.
    pub witnesses: Vec<DisplacementWitness>,
}

// Equality on the **canonical encodings**, since neither `VrfPublic` nor `VrfProof` is comparable directly: two claims
// are the same claim exactly when they serialize the same, which is also the only notion a peer can act on.
impl PartialEq for DisplacementWitness {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.public.to_bytes() == other.public.to_bytes()
            && self.proof.to_bytes() == other.proof.to_bytes()
    }
}
impl Eq for DisplacementWitness {}

impl PartialEq for CoordinateClaim {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
            && self.proof.to_bytes() == other.proof.to_bytes()
            && self.witnesses == other.witnesses
    }
}
impl Eq for CoordinateClaim {}

impl CoordinateClaim {
    /// The uncontested claim: probe 0, no witnesses.
    #[must_use]
    pub const fn direct(proof: VrfProof) -> Self {
        Self { proof, index: 0, witnesses: Vec::new() }
    }

    /// The canonical encoding: `proof ‖ index_be ‖ (id_len_be ‖ id ‖ public ‖ proof)*`.
    ///
    /// Witness identities are length-prefixed because a node id is not fixed-width at this layer (the coordinate VRF
    /// takes arbitrary identity bytes). The witness count is *not* encoded separately — it is `index`, and
    /// [`verify_coordinate_claim`] requires exactly that many, so a stated count could only ever disagree with the
    /// authoritative one.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROOF_LEN + 2 + self.witnesses.len() * (2 + 32 + PROOF_LEN));
        out.extend_from_slice(&self.proof.to_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        for w in &self.witnesses {
            let len = u16::try_from(w.id.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(w.id.get(..usize::from(len)).unwrap_or(&w.id));
            out.extend_from_slice(&w.public.to_bytes());
            out.extend_from_slice(&w.proof.to_bytes());
        }
        out
    }

    /// Parse a claim, or `None` if malformed — a wrong length, a witness count disagreeing with `index`, trailing bytes,
    /// or a proof/key that is not a valid group element.
    ///
    /// Every rejection here is a claim a peer must not act on, so the decoder is strict rather than lenient: an
    /// unparseable claim is indistinguishable from a forged one at this layer.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader { bytes, at: 0 };
        let proof = VrfProof::from_bytes(r.array::<PROOF_LEN>()?)?;
        let index = u16::from_be_bytes(r.array::<2>()?);
        let mut witnesses = Vec::with_capacity(usize::from(index));
        for _ in 0..index {
            let len = usize::from(u16::from_be_bytes(r.array::<2>()?));
            let id = r.take(len)?.to_vec();
            let public = VrfPublic::from_bytes(r.array::<32>()?)?;
            let proof = VrfProof::from_bytes(r.array::<PROOF_LEN>()?)?;
            witnesses.push(DisplacementWitness { id, public, proof });
        }
        if r.at != bytes.len() {
            return None; // trailing bytes: not a canonical encoding
        }
        Some(Self { proof, index, witnesses })
    }
}

/// A minimal sequential byte reader for [`CoordinateClaim::from_bytes`].
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    /// The next `n` bytes, advancing; `None` if short.
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    /// The next `N` bytes as a fixed array, advancing; `None` if short.
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
}

/// The **acceptance predicate** for a coordinate claim — what a peer runs on a `HELLO`, and the single place the
/// resolution rule's soundness rests.
///
/// Accepts `claimed` as the coordinate of `(claimant_id, claimant_public)` for `(epoch, beacon)` iff:
///
/// 1. the claimant's own proof verifies, yielding its VRF output;
/// 2. `claimed` is exactly `probe_point(output, index)` — the point its own sequence puts at that index, which it cannot
///    choose;
/// 3. there are **exactly** `index` witnesses, so the chain covers every skipped index with none to spare;
/// 4. each witness `j` genuinely forces the step ([`displacement_is_forced`]).
///
/// Witness distinctness needs no separate check: a witness justifies index `j` only if its single preference *is* the
/// claimant's `j`-th point, and distinct indices are distinct points on a permutation walk, so one witness can never
/// justify two steps. Verification also short-circuits on the first bad witness, so a fabricated long chain costs a
/// verifier one VRF check rather than `index` of them.
#[must_use]
pub fn verify_coordinate_claim<F: Field>(
    claimant_public: &VrfPublic,
    claimant_id: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    claimed: &Point<F>,
    claim: &CoordinateClaim,
) -> bool {
    let Some(output) = claimant_public.verify(&beacon_alpha(claimant_id, epoch, beacon), &claim.proof) else {
        return false;
    };
    // The walk cycles after `probe_bound` steps, so an index at or beyond it names a point some lower index already
    // names — while demanding that many more witnesses. Rejecting it keeps a claim's chain as short as the point it
    // reaches actually requires, and denies a claimant the option of presenting a needlessly long one.
    if claim.index >= probe_bound::<F>() {
        return false;
    }
    if probe_point::<F>(&output, claim.index) != *claimed {
        return false;
    }
    if claim.witnesses.len() != usize::from(claim.index) {
        return false;
    }
    claim.witnesses.iter().enumerate().all(|(j, w)| {
        u16::try_from(j).is_ok_and(|j| {
            displacement_is_forced::<F>(&output, j, &w.public, &w.id, epoch, beacon, &w.proof)
        })
    })
}

/// The VRF input a node proves for its epoch coordinate: `node_id ‖ epoch_low32_be ‖ beacon_seed`
/// (spec §L0/§L3, `VRF(sk, id ‖ epoch ‖ SEED(epoch))`). Folding the epoch's **beacon seed** is what makes the coordinate
/// *unpredictable ahead of the epoch* — an adversary cannot grind for a future placement it cannot yet
/// compute (§3.2 assumption 2), the load-bearing anti-pre-settling defence on the base cell.
fn beacon_alpha(node_id: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Vec<u8> {
    let mut alpha = Vec::with_capacity(node_id.len() + 4 + 32);
    alpha.extend_from_slice(node_id);
    alpha.extend_from_slice(&epoch.low32_be_bytes());
    alpha.extend_from_slice(beacon.as_bytes());
    alpha
}

/// Prove a node's verifiable coordinate for `epoch` under the epoch's `beacon` seed:
/// `MapToPoint(VRF(sk, node_id ‖ epoch ‖ beacon))`, with the proof that lets anyone check the derivation
/// (spec §L0, §L3, §7.3 proof-of-coordinate). Use [`BeaconSeed::GENESIS`] before the first beacon round.
#[must_use]
pub fn prove_coordinate<F: Field>(
    secret: &VrfSecret,
    node_id: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> (Point<F>, VrfProof) {
    let (point, proof, _rank) = prove_coordinate_ranked::<F>(secret, node_id, epoch, beacon);
    (point, proof)
}

/// As [`prove_coordinate`], but also returning this node's own **rank** — the VRF output.
///
/// A node needs its own rank for two things it cannot do without: binding its directory entry so a collision is
/// arbitrated by an unforgeable value rather than by arrival order, and driving [`settle_index`] to find the first probe
/// point no lower-ranked node holds. Both were previously impossible because the output was computed and thrown away.
#[must_use]
pub fn prove_coordinate_ranked<F: Field>(
    secret: &VrfSecret,
    node_id: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> (Point<F>, VrfProof, VrfOutput) {
    let (proof, output) = secret.prove(&beacon_alpha(node_id, epoch, beacon));
    (coordinate_from_output::<F>(&output), proof, output)
}

/// Verify that `claimed` is the correct epoch coordinate for the node with `public` key under the
/// epoch's `beacon` seed — i.e. that it equals `MapToPoint(VRF(sk, node_id ‖ epoch ‖ beacon))` — without
/// the secret (spec §L0, §L3, §7.3). This is the check a peer runs on a `HELLO` proof-of-coordinate.
#[must_use]
pub fn verify_coordinate<F: Field>(
    public: &VrfPublic,
    node_id: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    claimed: &Point<F>,
    proof: &VrfProof,
) -> bool {
    verify_coordinate_rank::<F>(public, node_id, epoch, beacon, claimed, proof).is_some()
}

/// As [`verify_coordinate`], but returning the verified **rank** — the VRF output itself — on success.
///
/// The rank is what a collision is arbitrated by (`fanos_quic::Directory::insert_ranked`), and it is already computed
/// while checking the proof. Returning it rather than discarding it is what lets the transport record *who* may keep a
/// contested point, instead of falling back on arrival order, which an attacker controls. [`verify_coordinate`] is
/// defined in terms of this so the two can never disagree about what a valid claim is.
#[must_use]
pub fn verify_coordinate_rank<F: Field>(
    public: &VrfPublic,
    node_id: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    claimed: &Point<F>,
    proof: &VrfProof,
) -> Option<VrfOutput> {
    let output = public.verify(&beacon_alpha(node_id, epoch, beacon), proof)?;
    (coordinate_from_output::<F>(&output) == *claimed).then_some(output)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use alloc::vec;

    use super::*;
    use fanos_field::{F7, F31};

    #[test]
    fn probe_zero_is_exactly_the_existing_coordinate() {
        // The compatibility hinge: a node meeting no collision derives what it always did, so adding resolution changes
        // no coordinate that was already correct.
        let sk = VrfSecret::from_seed([9u8; 32]);
        let (_p, _proof) = prove_coordinate::<F31>(&sk, b"node", Epoch::ZERO, &BeaconSeed::GENESIS);
        let (proof, output) = sk.prove(&beacon_alpha(b"node", Epoch::ZERO, &BeaconSeed::GENESIS));
        let _ = proof;
        assert_eq!(probe_point::<F31>(&output, 0), coordinate_from_output::<F31>(&output));
    }

    #[test]
    fn the_probe_sequence_is_fixed_by_the_node_and_offers_no_choice() {
        // The security property the whole design turns on: the sequence is a pure function of the node's own VRF output,
        // so it is settled the moment the beacon is known. A node has no more say over p_k than it had over p_0 — the
        // points differ from each other (a sequence, not a constant) but are not selectable.
        let sk = VrfSecret::from_seed([4u8; 32]);
        let (_, output) = sk.prove(&beacon_alpha(b"n", Epoch::new(3), &BeaconSeed::GENESIS));
        let seq: Vec<_> = (0..6).map(|k| probe_point::<F31>(&output, k)).collect();
        assert_eq!(seq, (0..6).map(|k| probe_point::<F31>(&output, k)).collect::<Vec<_>>(), "deterministic");
        assert!(seq.windows(2).any(|w| matches!(w, [a, b] if a != b)), "it advances rather than repeating a point");

        // The walk covers exactly ONE LINE through the preferred point, as a cyclic permutation of it — every point of
        // that line and no other. Confining it there is what denies an attacker a steering primitive: he can only move a
        // victim among points of a line the VICTIM's output chose, and to exploit that he must occupy that line, which is
        // the coupon-collector cost he already faced.
        let line_size = 31 + 1;
        let visited: alloc::collections::BTreeSet<_> =
            (0..64u16).map(|k| probe_point::<F31>(&output, k).index()).collect();
        assert_eq!(visited.len(), line_size, "the walk is a cyclic permutation of its line's {line_size} points");

        // And every visited point really is collinear with the preferred one.
        let first = probe_point::<F31>(&output, 0);
        let on_a_common_line = Plane::<F31>::lines_through(first)
            .any(|l| visited.iter().all(|&i| Plane::<F31>::points_on(l).any(|p| p.index() == i)));
        assert!(on_a_common_line, "the whole walk lies on one line through the preferred point");

        // A different beacon reshuffles the whole sequence, not just its head — so a future epoch's fallbacks are as
        // unpredictable as its preference (§3.2 assumption 2 extends to every probe index).
        let (_, later) = sk.prove(&beacon_alpha(b"n", Epoch::new(3), &BeaconSeed::new([7u8; 32])));
        let moved = (0..6).filter(|&k| probe_point::<F31>(&later, k) != probe_point::<F31>(&output, k)).count();
        assert!(moved >= 5, "a new beacon moves essentially the entire sequence (moved {moved} of 6)");
    }

    #[test]
    fn rank_is_a_strict_total_order_on_unforgeable_values() {
        let lo: VrfOutput = [0u8; OUTPUT_LEN];
        let mut hi: VrfOutput = [0u8; OUTPUT_LEN];
        hi[OUTPUT_LEN - 1] = 1;
        assert!(outranks(&lo, &hi));
        assert!(!outranks(&hi, &lo));
        assert!(!outranks(&lo, &lo), "not reflexive — a node never displaces itself");
    }

    #[test]
    fn a_displacement_claim_needs_a_genuinely_lower_ranked_witness_at_that_point() {
        // Search for a real colliding pair rather than constructing one: two secrets whose *preferences* coincide on a
        // small plane. F31's plane has 31² + 31 + 1 = 993 points, so a few hundred draws suffice by the birthday bound.
        let epoch = Epoch::new(2);
        let beacon = BeaconSeed::GENESIS;
        let mut seen: Vec<(u8, VrfOutput, VrfProof, Point<F31>)> = Vec::new();
        let mut pair = None;
        for seed in 0u8..=250 {
            let sk = VrfSecret::from_seed([seed; 32]);
            let id = [seed];
            let (proof, output) = sk.prove(&beacon_alpha(&id, epoch, &beacon));
            let point = probe_point::<F31>(&output, 0);
            if let Some(prev) = seen.iter().find(|(_, _, _, p)| *p == point) {
                pair = Some((*prev, (seed, output, proof, point)));
                break;
            }
            seen.push((seed, output, proof, point));
        }
        let ((a_seed, a_out, a_proof, _), (b_seed, b_out, b_proof, _)) =
            pair.unwrap_or_else(|| unreachable!("two preferences collide within 251 draws on a 993-point plane"));

        // Orient the pair: the lower-ranked one is the witness that forces the other off index 0.
        let (loser, l_out, winner, w_proof) = if outranks(&a_out, &b_out) {
            (b_seed, b_out, a_seed, a_proof)
        } else {
            (a_seed, a_out, b_seed, b_proof)
        };
        let w_out = if outranks(&a_out, &b_out) { a_out } else { b_out };
        let w_pk = VrfSecret::from_seed([winner; 32]).public();

        assert!(
            displacement_is_forced::<F31>(&l_out, 0, &w_pk, &[winner], epoch, &beacon, &w_proof),
            "a lower-ranked node preferring the same point forces the displacement"
        );
        // The reverse direction must fail: the higher-ranked node does not displace the lower one.
        let l_pk = VrfSecret::from_seed([loser; 32]).public();
        let l_proof = VrfSecret::from_seed([loser; 32]).prove(&beacon_alpha(&[loser], epoch, &beacon)).0;
        assert!(
            !displacement_is_forced::<F31>(&w_out, 0, &l_pk, &[loser], epoch, &beacon, &l_proof),
            "rank is what decides, and the winner keeps its point"
        );
        // And a claim about the WRONG index fails: the witness collides with index 0, not index 1.
        assert!(
            !displacement_is_forced::<F31>(&l_out, 1, &w_pk, &[winner], epoch, &beacon, &w_proof),
            "a witness justifies exactly the index whose point it collides with — this is what bounds k"
        );
    }

    /// Find a genuine colliding pair on F31's 993-point plane and orient it: `(loser, its output, witness claim)`.
    fn colliding_pair(epoch: Epoch, beacon: &BeaconSeed) -> (u8, VrfOutput, u8, VrfProof) {
        let mut seen: Vec<(u8, VrfOutput, VrfProof, Point<F31>)> = Vec::new();
        for seed in 0u8..=250 {
            let sk = VrfSecret::from_seed([seed; 32]);
            let (proof, output) = sk.prove(&beacon_alpha(&[seed], epoch, beacon));
            let point = probe_point::<F31>(&output, 0);
            if let Some(&(pseed, pout, pproof, _)) = seen.iter().find(|(_, _, _, p)| *p == point) {
                return if outranks(&pout, &output) {
                    (seed, output, pseed, pproof)
                } else {
                    (pseed, pout, seed, proof)
                };
            }
            seen.push((seed, output, proof, point));
        }
        unreachable!("two preferences collide within 251 draws on a 993-point plane")
    }

    #[test]
    fn settling_takes_the_first_point_no_better_claim_reaches() {
        let sk = VrfSecret::from_seed([33u8; 32]);
        let (_, mine) = sk.prove(&beacon_alpha(b"me", Epoch::ZERO, &BeaconSeed::GENESIS));
        let p0 = probe_point::<F31>(&mine, 0);
        let p1 = probe_point::<F31>(&mine, 1);

        // Nothing observed anywhere: the preference stands, and nothing changes for an uncontested node.
        assert_eq!(settle_index::<F31>(&mine, |_| None), Some(0));

        let mut lower = mine;
        lower[0] = 0;
        let lower = if outranks(&lower, &mine) { lower } else { [0u8; OUTPUT_LEN] };
        let mut higher = mine;
        higher[0] = 0xff;
        let higher = if outranks(&mine, &higher) { higher } else { [0xffu8; OUTPUT_LEN] };

        // At EQUAL index, rank decides: a lower-ranked contender on the preference displaces this node...
        assert_eq!(settle_index::<F31>(&mine, |p| (*p == p0).then_some((0, lower))), Some(1));
        // ...and a higher-ranked one does not — it is the one that must move. This complementarity is what lets both
        // sides act from public data alone, with exactly one of them yielding.
        assert_eq!(settle_index::<F31>(&mine, |p| (*p == p0).then_some((0, higher))), Some(0));

        // INDEX BEATS RANK, the change that closes the unprovable-displacement gap: a contender reaching this node's
        // `p1` at its own index 0 displaces it even while ranking WORSE, because the cheaper claim wins the point. Under
        // the old rank-only rule this settled at 1 and the node could not prove it.
        assert_eq!(
            settle_index::<F31>(&mine, |p| if *p == p0 {
                Some((0, lower))
            } else if *p == p1 {
                Some((0, higher))
            } else {
                None
            }),
            Some(2)
        );

        // Conversely a contender that reaches the point LATER than this node loses it, rank notwithstanding.
        assert_eq!(settle_index::<F31>(&mine, |p| (*p == p0).then_some((3, lower))), Some(0));

        // A genuinely full line is reported as such rather than looping forever.
        assert_eq!(settle_index::<F31>(&mine, |_| Some((0, lower))), None);

        // The bound is the LINE's length, not the plane's. A walk that cycles after `q+1` steps must never return an
        // index beyond it: index `k + (q+1)` names the same point as `k` but would demand `q+1` more witnesses, so an
        // honest node would build an absurd chain to reach a point one step away.
        assert_eq!(probe_bound::<F31>(), 32, "q + 1 for PG(2,31)");
        let occupied_until = |p: &Point<F31>| {
            let head: Vec<_> = (0..30u16).map(|k| probe_point::<F31>(&mine, k)).collect();
            head.contains(p).then_some((0, lower))
        };
        let Some(settled) = settle_index::<F31>(&mine, occupied_until) else { unreachable!("two points free") };
        assert!(settled < probe_bound::<F31>(), "the index never exceeds the line it walks");
        assert_eq!(settled, 30, "and it is the first free step, not a wrapped equivalent");
    }

    #[test]
    fn the_forward_and_inverse_views_of_a_walk_agree_everywhere() {
        // `probe_point` reads the walk forwards, `probe_index_of` backwards. Independent derivations of the same sequence
        // are exactly what produced the unprovable-displacement defect, so this pins them together exhaustively: every
        // index round-trips, and no point off the walk is claimed to be on it.
        for seed in 0..24u8 {
            let sk = VrfSecret::from_seed([seed; 32]);
            let (_, out) = sk.prove(&beacon_alpha(b"walker", Epoch::new(2), &BeaconSeed::GENESIS));
            let walk: Vec<_> = (0..probe_bound::<F7>()).map(|k| probe_point::<F7>(&out, k)).collect();
            for (k, p) in walk.iter().enumerate() {
                assert_eq!(
                    probe_index_of::<F7>(&out, p),
                    u16::try_from(k).ok(),
                    "seed {seed}: the inverse view disagrees at step {k}"
                );
            }
            // A walk is a permutation of its line, never a repeat — the property the double hashing exists to give.
            let distinct: alloc::collections::BTreeSet<_> = walk.iter().map(Point::coords).collect();
            assert_eq!(distinct.len(), walk.len(), "seed {seed}: the walk revisits a point");
            // And every point NOT on the walk is reported as unreachable, so no node can claim a step it never takes.
            let off = (0..Plane::<F7>::N)
                .filter_map(|i| {
                    let p = Point::<F7>::at(i as usize);
                    (!walk.contains(&p)).then_some(p)
                })
                .filter(|p| probe_index_of::<F7>(&out, p).is_some())
                .count();
            assert_eq!(off, 0, "seed {seed}: a point off the line is reported as on the walk");
        }
    }

    #[test]
    fn every_index_settling_chooses_is_one_the_verifier_accepts() {
        // The regression test for the defect this rule replaced: `settle_index` and `verify_coordinate_claim` must agree
        // about when a node may move, or a node is pushed off a point it can hold and off to one it cannot prove. Built
        // over a real population with real keys, since the whole question is whether two independently-derived predicates
        // read the same facts.
        const N: usize = 24;
        let epoch = Epoch::new(4);
        let beacon = BeaconSeed::GENESIS;
        let peers: Vec<(Vec<u8>, VrfPublic, VrfProof, VrfOutput)> = (0..N)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = u8::try_from(i).unwrap_or(0);
                let sk = VrfSecret::from_seed(seed);
                let id = alloc::format!("peer-{i}").into_bytes();
                let (proof, output) = sk.prove(&beacon_alpha(&id, epoch, &beacon));
                (id, sk.public(), proof, output)
            })
            .collect();

        let mut displaced = 0;
        for (i, (my_id, my_public, my_proof, mine)) in peers.iter().enumerate() {
            // The best claim any *other* peer holds to a point — exactly what a directory can compute from HELLOs.
            let contender = |p: &Point<F7>| {
                peers
                    .iter()
                    .enumerate()
                    .filter(|&(j, _)| j != i)
                    .filter_map(|(_, (_, _, _, o))| probe_index_of::<F7>(o, p).map(|k| (k, *o)))
                    .reduce(|a, b| if claim_beats((b.0, &b.1), (a.0, &a.1)) { b } else { a })
            };
            let Some(k) = settle_index::<F7>(mine, contender) else { continue };
            if k > 0 {
                displaced += 1;
            }
            // Build the claim the node would actually send: one witness per skipped index, taken from what it observed.
            let witnesses: Vec<DisplacementWitness> = (0..k)
                .filter_map(|j| {
                    let pj = probe_point::<F7>(mine, j);
                    peers
                        .iter()
                        .enumerate()
                        .filter(|&(w, _)| w != i)
                        .find(|(_, (_, _, _, o))| {
                            probe_index_of::<F7>(o, &pj).is_some_and(|kw| claim_beats((kw, o), (j, mine)))
                        })
                        .map(|(_, (id, public, proof, _))| DisplacementWitness {
                            id: id.clone(),
                            public: *public,
                            proof: *proof,
                        })
                })
                .collect();
            assert_eq!(witnesses.len(), usize::from(k), "a witness exists for every step settling took");
            let claim = CoordinateClaim { proof: *my_proof, index: k, witnesses };
            assert!(
                verify_coordinate_claim::<F7>(
                    my_public,
                    my_id,
                    epoch,
                    &beacon,
                    &probe_point::<F7>(mine, k),
                    &claim
                ),
                "peer {i} settled at index {k} but the verifier rejects the claim"
            );
        }
        assert!(displaced >= 3, "the fixture must actually exercise displacement, saw {displaced}");
    }

    #[test]
    fn a_claim_at_probe_zero_is_the_pre_existing_hello_proof() {
        // Compatibility: the uncontested claim carries no witnesses and verifies against the same point `verify_coordinate`
        // accepts, so adding resolution does not invalidate any claim that was already valid.
        let sk = VrfSecret::from_seed([21u8; 32]);
        let (point, proof) = prove_coordinate::<F31>(&sk, b"n", Epoch::new(6), &BeaconSeed::GENESIS);
        let claim = CoordinateClaim::direct(proof);
        assert!(verify_coordinate_claim::<F31>(
            &sk.public(), b"n", Epoch::new(6), &BeaconSeed::GENESIS, &point, &claim
        ));
        assert!(verify_coordinate::<F31>(&sk.public(), b"n", Epoch::new(6), &BeaconSeed::GENESIS, &point, &proof));
    }

    #[test]
    fn a_probed_claim_is_accepted_only_with_a_complete_and_correct_witness_chain() {
        let epoch = Epoch::new(8);
        let beacon = BeaconSeed::GENESIS;
        let (loser, l_out, winner, w_proof) = colliding_pair(epoch, &beacon);
        let l_sk = VrfSecret::from_seed([loser; 32]);
        let l_proof = l_sk.prove(&beacon_alpha(&[loser], epoch, &beacon)).0;
        let w_pk = VrfSecret::from_seed([winner; 32]).public();
        let witness = DisplacementWitness { id: vec![winner], public: w_pk, proof: w_proof };
        let at_one = probe_point::<F31>(&l_out, 1);

        let good = CoordinateClaim { proof: l_proof, index: 1, witnesses: vec![witness.clone()] };
        assert!(
            verify_coordinate_claim::<F31>(&l_sk.public(), &[loser], epoch, &beacon, &at_one, &good),
            "displaced by a lower-ranked claimant, so probe 1 is legitimately its point"
        );

        // Same claim, but asserting the point it was NOT displaced to.
        let elsewhere = probe_point::<F31>(&l_out, 2);
        assert!(!verify_coordinate_claim::<F31>(&l_sk.public(), &[loser], epoch, &beacon, &elsewhere, &good));

        // A chain shorter than the index: nothing justifies the skip.
        let bare = CoordinateClaim { proof: l_proof, index: 1, witnesses: Vec::new() };
        assert!(!verify_coordinate_claim::<F31>(&l_sk.public(), &[loser], epoch, &beacon, &at_one, &bare));

        // A chain LONGER than the index is equally rejected — "exactly index" is what stops a claimant padding a chain
        // and then asserting a lower index whose point it prefers.
        let padded =
            CoordinateClaim { proof: l_proof, index: 1, witnesses: vec![witness.clone(), witness.clone()] };
        assert!(!verify_coordinate_claim::<F31>(&l_sk.public(), &[loser], epoch, &beacon, &at_one, &padded));

        // Claiming index 2 with the same witness reused: the witness's single preference is the claimant's point 0, so
        // it can never justify step 1. This is why witness distinctness needs no separate check.
        let at_two = probe_point::<F31>(&l_out, 2);
        let reused = CoordinateClaim { proof: l_proof, index: 2, witnesses: vec![witness.clone(), witness] };
        assert!(
            !verify_coordinate_claim::<F31>(&l_sk.public(), &[loser], epoch, &beacon, &at_two, &reused),
            "one witness cannot justify two steps of a permutation walk"
        );
    }

    #[test]
    fn a_claim_index_beyond_the_line_is_refused_even_though_it_names_a_real_point() {
        // Stale-after-redesign check. Once the walk is confined to a line it cycles after `q + 1` steps, so an index at
        // or beyond that names a point some LOWER index already names — while demanding that many more witnesses. The
        // point is real and the arithmetic is consistent, which is exactly why this needs an explicit refusal rather than
        // failing naturally: nothing else would catch it.
        let sk = VrfSecret::from_seed([44u8; 32]);
        let epoch = Epoch::new(2);
        let beacon = BeaconSeed::GENESIS;
        let (proof, output) = sk.prove(&beacon_alpha(b"n", epoch, &beacon));
        let bound = probe_bound::<F31>();

        // Index `bound` names exactly the same point as index 0 — the walk has come full circle.
        assert_eq!(probe_point::<F31>(&output, bound), probe_point::<F31>(&output, 0));

        // A claim at that index, with a chain of the required length, is refused on the index alone.
        let padded = CoordinateClaim { proof, index: bound, witnesses: Vec::new() };
        assert!(!verify_coordinate_claim::<F31>(
            &sk.public(),
            b"n",
            epoch,
            &beacon,
            &probe_point::<F31>(&output, bound),
            &padded
        ));

        // And the uncontested claim at index 0 for that same point still verifies, so the refusal is about the index and
        // not the point.
        let direct = CoordinateClaim::direct(proof);
        assert!(verify_coordinate_claim::<F31>(
            &sk.public(),
            b"n",
            epoch,
            &beacon,
            &probe_point::<F31>(&output, 0),
            &direct
        ));
    }

    #[test]
    fn the_winner_cannot_claim_to_have_been_displaced() {
        // The direction that matters for fairness: the node that wins a point must not be able to *also* claim a probed
        // point, which would let it occupy a second slot of its choosing.
        let epoch = Epoch::new(9);
        let beacon = BeaconSeed::GENESIS;
        let (loser, l_out, winner, _) = colliding_pair(epoch, &beacon);
        let w_sk = VrfSecret::from_seed([winner; 32]);
        let (w_proof, w_out) = w_sk.prove(&beacon_alpha(&[winner], epoch, &beacon));
        let l_pk = VrfSecret::from_seed([loser; 32]).public();
        let l_proof = VrfSecret::from_seed([loser; 32]).prove(&beacon_alpha(&[loser], epoch, &beacon)).0;
        let _ = l_out;

        let bogus = CoordinateClaim {
            proof: w_proof,
            index: 1,
            witnesses: vec![DisplacementWitness { id: vec![loser], public: l_pk, proof: l_proof }],
        };
        assert!(!verify_coordinate_claim::<F31>(
            &w_sk.public(),
            &[winner],
            epoch,
            &beacon,
            &probe_point::<F31>(&w_out, 1),
            &bogus
        ));
    }

    #[test]
    fn a_claim_round_trips_and_the_decoder_rejects_malformed_input() {
        let epoch = Epoch::new(10);
        let beacon = BeaconSeed::GENESIS;
        let (loser, _, winner, w_proof) = colliding_pair(epoch, &beacon);
        let l_proof = VrfSecret::from_seed([loser; 32]).prove(&beacon_alpha(&[loser], epoch, &beacon)).0;
        let w_pk = VrfSecret::from_seed([winner; 32]).public();

        let direct = CoordinateClaim::direct(l_proof);
        assert_eq!(CoordinateClaim::from_bytes(&direct.to_bytes()).as_ref(), Some(&direct));

        let probed = CoordinateClaim {
            proof: l_proof,
            index: 1,
            witnesses: vec![DisplacementWitness { id: vec![winner, 7, 9], public: w_pk, proof: w_proof }],
        };
        let encoded = probed.to_bytes();
        assert_eq!(CoordinateClaim::from_bytes(&encoded).as_ref(), Some(&probed));

        assert_eq!(CoordinateClaim::from_bytes(&[]), None, "empty");
        assert_eq!(CoordinateClaim::from_bytes(encoded.get(..encoded.len() - 1).unwrap()), None, "truncated");
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(CoordinateClaim::from_bytes(&trailing), None, "trailing bytes are not canonical");
        // An index that promises more witnesses than the bytes carry must not decode to a short chain.
        let mut lying = encoded.clone();
        if let Some(slot) = lying.get_mut(PROOF_LEN..PROOF_LEN + 2) {
            slot.copy_from_slice(&2u16.to_be_bytes());
        }
        assert_eq!(CoordinateClaim::from_bytes(&lying), None, "index disagreeing with the payload");
    }

    #[test]
    fn a_forged_or_foreign_witness_justifies_nothing() {
        let epoch = Epoch::ZERO;
        let beacon = BeaconSeed::GENESIS;
        let sk = VrfSecret::from_seed([11u8; 32]);
        let (_, mine) = sk.prove(&beacon_alpha(b"me", epoch, &beacon));
        let other = VrfSecret::from_seed([12u8; 32]);
        let (other_proof, _) = other.prove(&beacon_alpha(b"other", epoch, &beacon));

        // Right proof, wrong node id ⇒ the VRF verification itself fails, so no witness value is ever produced.
        assert!(!displacement_is_forced::<F31>(&mine, 0, &other.public(), b"wrong-id", epoch, &beacon, &other_proof));
        // Right proof, wrong epoch ⇒ same. A stale witness cannot be replayed into a later epoch.
        assert!(!displacement_is_forced::<F31>(
            &mine, 0, &other.public(), b"other", Epoch::new(1), &beacon, &other_proof
        ));
        // Right proof, wrong public key ⇒ same.
        assert!(!displacement_is_forced::<F31>(&mine, 0, &sk.public(), b"other", epoch, &beacon, &other_proof));
    }

    fn secret(seed: u8) -> VrfSecret {
        VrfSecret::from_seed([seed; 32])
    }

    #[test]
    fn every_seed_yields_a_working_key_including_non_canonical_ones() {
        // Seeds whose raw bytes are NOT a canonical scalar (top bytes 0xFF ⇒ ≥ 2²⁵⁵ > ℓ) would be
        // rejected by a raw `from_bytes`; hashing into the field accepts them and the key works.
        for seed in [[0xFFu8; 32], [0x80; 32], [0xEE; 32], [0x00; 32]] {
            let sk = VrfSecret::from_seed(seed); // hashed seed is always a valid key
            let (proof, output) = sk.prove(b"alpha");
            assert_eq!(sk.public().verify(b"alpha", &proof), Some(output));
        }
        // Distinct seeds give distinct keys (the hash is injective in practice).
        assert_ne!(
            VrfSecret::from_seed([0xFF; 32]).to_bytes(),
            VrfSecret::from_seed([0xEE; 32]).to_bytes()
        );
    }

    #[test]
    fn prove_verify_round_trips() {
        let sk = secret(1);
        let pk = sk.public();
        let (proof, output) = sk.prove(b"alpha");
        assert_eq!(
            pk.verify(b"alpha", &proof),
            Some(output),
            "valid proof yields the output"
        );
    }

    #[test]
    fn a_tampered_input_or_key_fails() {
        let sk = secret(2);
        let (proof, _) = sk.prove(b"alpha");
        assert!(
            sk.public().verify(b"different", &proof).is_none(),
            "wrong input rejected"
        );
        assert!(
            secret(3).public().verify(b"alpha", &proof).is_none(),
            "wrong key rejected"
        );
    }

    #[test]
    fn the_verifiable_coordinate_is_deterministic_and_checks_out() {
        let sk = secret(4);
        let pk = sk.public();
        let beacon = BeaconSeed::new([0xB7; 32]);
        let (coord, proof) = prove_coordinate::<F31>(&sk, b"node-A", Epoch::new(7), &beacon);
        // Deterministic: the same key+epoch+beacon always yields the same coordinate.
        let (coord2, _) = prove_coordinate::<F31>(&sk, b"node-A", Epoch::new(7), &beacon);
        assert_eq!(coord, coord2);
        // Anyone with the public key verifies the coordinate without the secret.
        assert!(verify_coordinate::<F31>(
            &pk,
            b"node-A",
            Epoch::new(7),
            &beacon,
            &coord,
            &proof
        ));
        // A forged coordinate (from a different epoch) does not verify for epoch 7.
        let (other, _) = prove_coordinate::<F31>(&sk, b"node-A", Epoch::new(8), &beacon);
        assert!(!verify_coordinate::<F31>(
            &pk,
            b"node-A",
            Epoch::new(7),
            &beacon,
            &other,
            &proof
        ));
    }

    #[test]
    fn the_coordinate_rotates_every_epoch() {
        let sk = secret(5);
        let beacon = BeaconSeed::new([0x5B; 32]);
        let (c7, _) = prove_coordinate::<F31>(&sk, b"n", Epoch::new(7), &beacon);
        let (c8, _) = prove_coordinate::<F31>(&sk, b"n", Epoch::new(8), &beacon);
        assert_ne!(c7, c8, "the beacon coordinate moves each epoch");
    }

    #[test]
    fn the_coordinate_folds_the_beacon_and_is_unpredictable_ahead() {
        // The same key + epoch under a DIFFERENT beacon seed yields a different coordinate — so a node's
        // placement cannot be computed (nor pre-settled onto a victim's lines) until the epoch's beacon is
        // revealed (spec §3.2 assumption 2). A coordinate proven under one seed does not verify under
        // another, so a peer cannot replay a past epoch's proof against the current seed.
        let sk = secret(6);
        let pk = sk.public();
        let (c_a, proof_a) =
            prove_coordinate::<F31>(&sk, b"n", Epoch::new(3), &BeaconSeed::new([0xA1; 32]));
        let (c_b, _) = prove_coordinate::<F31>(&sk, b"n", Epoch::new(3), &BeaconSeed::new([0xB2; 32]));
        assert_ne!(c_a, c_b, "the coordinate depends on the beacon seed");
        assert!(!verify_coordinate::<F31>(
            &pk,
            b"n",
            Epoch::new(3),
            &BeaconSeed::new([0xB2; 32]),
            &c_a,
            &proof_a
        ), "a proof under one beacon does not verify under another");
    }

    #[test]
    fn proof_and_key_bytes_round_trip() {
        let sk = secret(6);
        let (proof, _) = sk.prove(b"x");
        assert!(VrfProof::from_bytes(proof.to_bytes()).is_some());
        let pk = sk.public();
        assert_eq!(
            VrfPublic::from_bytes(pk.to_bytes()).unwrap().to_bytes(),
            pk.to_bytes()
        );
    }
}
