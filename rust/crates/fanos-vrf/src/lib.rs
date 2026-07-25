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

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Point;
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
/// ## Why the sequence is a permutation, and not another hash
///
/// The obvious construction — `p_k = MapToPoint(H(probe ‖ output ‖ k))` — is a random *function*, so a node's own
/// sequence repeats points and never enumerates the plane. Measured on that version: at `n = P = 7` it seated **5** of 7
/// nodes, better than the bare draw's 4.62 but still short, because 7 draws from 7 points cover only ~4.6 of them. The
/// probing was re-colliding with itself.
///
/// This is **double hashing**, the classic fix: walk the canonical point index by a fixed stride,
///
/// ```text
/// p_k = Point::at((i₀ + k·s) mod P),   i₀ = index(MapToPoint(output)),   s coprime to P
/// ```
///
/// `gcd(s, P) = 1` makes `k ↦ (i₀ + k·s) mod P` a **cyclic permutation of all `P` points**, so the sequence enumerates
/// the whole plane and probing seats every node whenever `n ≤ P`. Both `i₀` and `s` derive from the node's own output, so
/// the permutation is verifiable and unchoosable; the stride is searched upward from a hashed start until coprime, which
/// terminates immediately in practice and is deterministic for any `P` — necessary because `P = q² + q + 1` need not be
/// prime (`P = 21 = 3·7` for `q = 4`).
#[must_use]
pub fn probe_point<F: Field>(output: &VrfOutput, k: u16) -> Point<F> {
    let first = coordinate_from_output::<F>(output);
    if k == 0 {
        return first;
    }
    let n = plane_points::<F>();
    let step = usize::from(k).wrapping_mul(probe_stride::<F>(output)) % n;
    Point::at((first.index() + step) % n)
}

/// The number of points in `F`'s projective plane, `q² + q + 1`.
#[must_use]
fn plane_points<F: Field>() -> usize {
    let q = F::Q as usize;
    q * q + q + 1
}

/// The node's probe **stride**: the smallest value at or above a hashed start that is coprime to the plane size, so the
/// probe walk is a cyclic permutation of every point rather than a sub-cycle.
///
/// Searching upward keeps the derivation deterministic and total for composite `P`, where a bare `H mod P` could land on
/// a divisor and confine the walk to a short orbit — the failure that a "random stride" would hit silently.
#[must_use]
fn probe_stride<F: Field>(output: &VrfOutput) -> usize {
    let n = plane_points::<F>();
    if n <= 2 {
        return 1;
    }
    let digest = fanos_primitives::hash::hash_labeled(label::COORD_PROBE, output);
    let start = 1 + (usize::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]) % (n - 1));
    (0..n).map(|d| 1 + ((start - 1 + d) % (n - 1))).find(|&s| gcd(s, n) == 1).unwrap_or(1)
}

/// Binary-free Euclidean gcd, used only to pick a stride coprime to the plane size.
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

/// Whether a claimant at probe index `k` was **forced** off its `j`-th preference by `witness`, for `j < k`.
///
/// The claimant's probe sequence is fixed by its own output, so the one degree of freedom left is claiming a larger `k`
/// than reality — landing further along a sequence it cannot choose, but which it might still prefer. This closes it: a
/// claim to index `k` is accepted only with `k` witnesses, the `j`-th showing that some **lower-ranked** node prefers the
/// claimant's `j`-th point. A lower-ranked node preferring `p` displaces the claimant from `p`, so each step is a public
/// fact rather than an assertion.
///
/// Verification is deliberately **non-recursive**: the witness proves only its own *preference* (`probe_point(·, 0)`), not
/// where it finally settled, so checking a chain of length `k` costs `k` independent VRF verifications and never unfolds
/// into the witnesses' own chains. The price is that a witness which was itself displaced from `p` still displaces the
/// claimant — a phantom collision that can leave a point empty. That costs *occupancy efficiency*, never correctness or
/// security, and it cannot be manufactured: the claimant does not choose which witnesses exist.
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
    // Strictly lower rank, and its *preference* is the point the claimant is being displaced from. Equality of outputs
    // would mean the same VRF, i.e. the same node — never a displacement.
    outranks(&witness_output, claimant)
        && probe_point::<F>(&witness_output, 0) == probe_point::<F>(claimant, j)
}

/// The probe index a node settles at, given whatever occupancy it can observe — the sans-I/O core of live resolution.
///
/// `occupant(p)` reports the VRF output of the node currently holding `p`, or `None` if the point looks free. The walk
/// stops at the first index whose point is **not held by a lower-ranked node**: an empty point is free, and so is one
/// held by a *higher*-ranked node, because that node is the one who must move. That asymmetry is what makes the rule
/// consistent without agreement — two nodes evaluating the same collision reach opposite, complementary conclusions
/// from the same public ranks, so exactly one of them moves.
///
/// It is monotone in information: a node that has observed fewer peers may settle too early and later discover it must
/// advance, which is a *convergence* question rather than a correctness one — every intermediate position is a claim it
/// can legitimately prove. Re-run it whenever occupancy changes or the beacon advances.
///
/// The walk is bounded by the plane size, since [`probe_point`] is a cyclic permutation of every point: past that bound
/// the plane is genuinely full and the node cannot be seated at all, which is the honest answer rather than a loop.
#[must_use]
pub fn settle_index<F: Field>(output: &VrfOutput, occupant: impl Fn(&Point<F>) -> Option<VrfOutput>) -> Option<u16> {
    let bound = u16::try_from(plane_points::<F>()).unwrap_or(u16::MAX);
    (0..bound).find(|&k| match occupant(&probe_point::<F>(output, k)) {
        None => true,
        Some(held) => !outranks(&held, output),
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
    let (proof, output) = secret.prove(&beacon_alpha(node_id, epoch, beacon));
    (coordinate_from_output::<F>(&output), proof)
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
    match public.verify(&beacon_alpha(node_id, epoch, beacon), proof) {
        Some(output) => &coordinate_from_output::<F>(&output) == claimed,
        None => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use alloc::vec;

    use super::*;
    use fanos_field::F31;

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

        // The property double hashing buys, and the reason the first construction was replaced: the sequence visits
        // EVERY point of the plane exactly once, so probing can always seat a node while any point is free.
        let plane = 31 * 31 + 31 + 1;
        let visited: alloc::collections::BTreeSet<_> = (0..u16::try_from(plane).unwrap_or(u16::MAX))
            .map(|k| probe_point::<F31>(&output, k).index())
            .collect();
        assert_eq!(visited.len(), plane, "the probe walk is a cyclic permutation of all {plane} points");

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
    fn settling_takes_the_first_point_no_lower_ranked_node_holds() {
        let sk = VrfSecret::from_seed([33u8; 32]);
        let (_, mine) = sk.prove(&beacon_alpha(b"me", Epoch::ZERO, &BeaconSeed::GENESIS));
        let p0 = probe_point::<F31>(&mine, 0);
        let p1 = probe_point::<F31>(&mine, 1);

        // Nothing observed anywhere: the preference stands, and nothing changes for an uncontested node.
        assert_eq!(settle_index::<F31>(&mine, |_| None), Some(0));

        // A LOWER-ranked node on the preference displaces this node to the next index.
        let mut lower = mine;
        lower[0] = 0;
        assert!(outranks(&lower, &mine) || lower == mine);
        let lower = if outranks(&lower, &mine) { lower } else { [0u8; OUTPUT_LEN] };
        assert_eq!(settle_index::<F31>(&mine, |p| (*p == p0).then_some(lower)), Some(1));

        // A HIGHER-ranked node on the preference does NOT: it is the one that must move. This complementarity is what
        // lets both sides act from public ranks alone, with exactly one of them yielding.
        let mut higher = mine;
        higher[0] = 0xff;
        let higher = if outranks(&mine, &higher) { higher } else { [0xffu8; OUTPUT_LEN] };
        assert_eq!(settle_index::<F31>(&mine, |p| (*p == p0).then_some(higher)), Some(0));

        // Two consecutive preferences held by lower-ranked nodes ⇒ index 2.
        assert_eq!(settle_index::<F31>(&mine, |p| (*p == p0 || *p == p1).then_some(lower)), Some(2));

        // A genuinely full plane is reported as such rather than looping forever.
        assert_eq!(settle_index::<F31>(&mine, |_| Some(lower)), None);
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
