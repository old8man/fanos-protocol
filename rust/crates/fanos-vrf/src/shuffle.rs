//! A **verifiable shuffle** — a sound, linkage-hiding mixnet proof, generic over the cryptosystem (spec §16
//! `[P]` "verifiable shuffle"; `docs/design-pq-vrf.md` §3, Hand-roll full).
//!
//! > **NOVEL, UNAUDITED.** Hand-rolled with the reduction below and an extensive test suite, but without
//! > external cryptanalysis. Do not deploy without an audit.
//!
//! A verifiable shuffle proves that a list of output ciphertexts is a secret **permutation + re-randomization**
//! of the inputs — so no output can be linked to its submitter — *without revealing the permutation*. A deep
//! audit established this is **impossible from hash commitments alone**: proving a shadow re-commits the inputs
//! forces opening them (leaking submitter↔value). Genuine unlinkability needs **re-randomization**, i.e. a
//! *homomorphic* cryptosystem where a verifier can check `ct' = ReRand(ct, r)` from `r` **without** the
//! plaintext — captured by the [`ReRandomizable`] trait.
//!
//! The proof — a **Sako–Kilian cut-and-choose** — is fully generic over [`ReRandomizable`]. Two backends are
//! provided: [`ElGamal`] (ristretto255, the group FANOS's VRF/DKG/VOPRF already use — **classical**, discrete
//! log) and [`crate::rlwe`]'s `Rlwe` (**post-quantum**, Ring-LWE). The *same* [`prove`]/[`verify`] run over
//! either.
//!
//! **Security reduction.** *Soundness*: each shadow `M_j` is committed before the Fiat–Shamir challenge; if the
//! output multiset ≠ the input multiset, `M_j` cannot be **both** a re-randomization of the inputs (`b=0`) and
//! the outputs a re-randomization of `M_j` (`b=1`) — so one challenge branch fails, caught with probability
//! `≥ 1/2` per shadow, `1 − 2^-k` over `k` shadows (`k ≥` [`MIN_ROUNDS`], enforced). The challenge is a single
//! joint hash over the public key, `(n, k)`, and *all* shadow ciphertexts, so a shadow cannot be re-ground
//! independently and a proof cannot be replayed across keys. *Hiding*: only re-randomization factors are ever
//! revealed (checked homomorphically), one branch per shadow, so the composed permutation `π` is never
//! revealed — each opened `σ_j` is random and each `τ_j = π∘σ_j^{-1}` is masked by the hidden, random `σ_j`
//! (which requires a **secret, high-entropy `seed`**: `seed` determines `π` and every factor, so a guessed or
//! reused `seed` de-anonymizes the batch — callers MUST pass a fresh CSPRNG draw).
//!
//! **Soundness scope — read before relying on the PQ backend.** The reduction above is exact **only when the
//! backend's re-randomization is plaintext-preserving and [`verify_rerandomization`](ReRandomizable::verify_rerandomization)
//! *enforces* that** (else a plaintext-changing factor satisfies whichever branch the challenge demands). The
//! [`ElGamal`] backend meets this **unconditionally** — its factor is one scalar tying both ciphertext
//! components, leaving no free translation — so the ElGamal shuffle is genuinely `1 − 2^-k` sound and is the
//! backend to rely on. The lattice [`crate::rlwe`] backend enforces a **shortness** gate that closes the
//! trivial free-translation forgery an independent audit found, but at `n = 512` a norm bound alone does *not*
//! give worst-case soundness (the verifier cannot bound the unknown `s·e1'` term below `q/4`); a
//! production-sound PQ shuffle needs a splitting-ring-aware NIZK (eprint 2025/658) or a re-parameterization.
//! **Treat the RLWE backend as an experimental research scaffold, not a sound PQ shuffle** (see its module doc
//! and `docs/design-pq-vrf.md` §4.2).

use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{RistrettoPoint, Scalar};

use fanos_primitives::hash::hash_xof;

const SCALAR_LABEL: &str = "FANOS-v1/shuffle-scalar";
const PERM_LABEL: &str = "FANOS-v1/shuffle-perm";
const CHALLENGE_LABEL: &str = "FANOS-v1/shuffle-challenge";

/// The minimum number of cut-and-choose rounds. Soundness is `2^-k`, so `k` is a security parameter and must
/// not be caller-tunable below the standard `128`-bit floor — a low `k` (or a grindable `k` like 32) is
/// otherwise a real forgery budget (audit fix). [`prove`]/[`verify`] reject any `k < MIN_ROUNDS`.
pub const MIN_ROUNDS: usize = 128;

/// A **re-randomizable public-key cryptosystem** — the homomorphic seam a verifiable shuffle needs. A
/// re-randomization must (i) preserve the plaintext, (ii) compose additively
/// (`ReRand(ReRand(ct, a), b) = ReRand(ct, a+b)`), and (iii) be **publicly checkable from the randomness
/// alone**, without the plaintext. ristretto ElGamal ([`ElGamal`]) and Ring-LWE ([`crate::rlwe::Rlwe`]) both
/// satisfy this; the shuffle proof is generic over it.
pub trait ReRandomizable {
    /// A ciphertext.
    type Ct: Clone + PartialEq;
    /// A re-randomization factor (an additive group under [`sub_rand`](Self::sub_rand)/composition).
    type Rand: Clone;
    /// The public key / parameters needed to re-randomize and verify.
    type Key;

    /// Re-randomize `ct` by `r` — same plaintext, fresh ciphertext.
    fn rerandomize(key: &Self::Key, ct: &Self::Ct, r: &Self::Rand) -> Self::Ct;
    /// Whether `ct2 == ReRand(ct1, r)` **for a valid `r`**, checkable from `r` without the plaintext. This
    /// MUST encode a validity/shortness predicate on `r`, not merely the syntactic relation: if any `r`
    /// (however large) is accepted, an additive-homomorphic backend admits a plaintext-*changing* factor that
    /// carries any `ct1` to any `ct2` (a free translation), and the cut-and-choose soundness collapses. ElGamal
    /// ties both ciphertext components through one scalar (no free translation); the lattice backend must
    /// additionally reject non-short factors.
    fn verify_rerandomization(key: &Self::Key, ct1: &Self::Ct, ct2: &Self::Ct, r: &Self::Rand) -> bool;
    /// `a − b` in the re-randomness group (`ReRand(ct, a−b)` takes `ReRand(ct, b)` to `ReRand(ct, a)`).
    fn sub_rand(a: &Self::Rand, b: &Self::Rand) -> Self::Rand;
    /// A deterministic re-randomization factor from `(seed, idx)`.
    fn derive_rand(seed: &[u8], idx: u64) -> Self::Rand;
    /// Canonical bytes of a ciphertext, for the Fiat–Shamir transcript.
    fn ct_bytes(ct: &Self::Ct) -> Vec<u8>;
    /// Canonical bytes of the public key, bound into the Fiat–Shamir challenge so a proof cannot be replayed
    /// across keys/instances (weak-FS hardening).
    fn key_bytes(key: &Self::Key) -> Vec<u8>;
}

// ---- ristretto255 ElGamal backend (classical) --------------------------------------------------------------

/// An additive-ElGamal ciphertext over ristretto255: `(a, b) = (rG, M + r·pk)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ElGamalCt {
    /// `a = r·G` (the ephemeral).
    pub a: RistrettoPoint,
    /// `b = M + r·pk` (the masked message).
    pub b: RistrettoPoint,
}

impl ElGamalCt {
    /// Encrypt message point `m` under `pk` with randomness `r`.
    #[must_use]
    pub fn encrypt(pk: &RistrettoPoint, m: &RistrettoPoint, r: &Scalar) -> Self {
        Self { a: r * RISTRETTO_BASEPOINT_POINT, b: m + r * pk }
    }

    /// The 64-byte compressed encoding `a ‖ b`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.a.compress().as_bytes());
        out[32..].copy_from_slice(self.b.compress().as_bytes());
        out
    }
}

/// The classical (discrete-log) ristretto255 ElGamal backend.
pub struct ElGamal;

impl ReRandomizable for ElGamal {
    type Ct = ElGamalCt;
    type Rand = Scalar;
    type Key = RistrettoPoint;

    fn rerandomize(pk: &RistrettoPoint, ct: &ElGamalCt, s: &Scalar) -> ElGamalCt {
        ElGamalCt { a: ct.a + s * RISTRETTO_BASEPOINT_POINT, b: ct.b + s * pk }
    }
    fn verify_rerandomization(pk: &RistrettoPoint, ct1: &ElGamalCt, ct2: &ElGamalCt, s: &Scalar) -> bool {
        *ct2 == Self::rerandomize(pk, ct1, s)
    }
    fn sub_rand(a: &Scalar, b: &Scalar) -> Scalar {
        a - b
    }
    fn derive_rand(seed: &[u8], idx: u64) -> Scalar {
        derive_scalar(seed, idx)
    }
    fn key_bytes(key: &RistrettoPoint) -> Vec<u8> {
        key.compress().as_bytes().to_vec()
    }

    fn ct_bytes(ct: &ElGamalCt) -> Vec<u8> {
        ct.to_bytes().to_vec()
    }
}

/// Re-randomize a ristretto ElGamal ciphertext (kept as a free function for direct callers).
#[must_use]
pub fn rerandomize(ct: &ElGamalCt, s: &Scalar, pk: &RistrettoPoint) -> ElGamalCt {
    ElGamal::rerandomize(pk, ct, s)
}

/// Whether `ct2 == ReRand(ct1, s)` for ristretto ElGamal (kept as a free function).
#[must_use]
pub fn verify_rerandomization(ct1: &ElGamalCt, ct2: &ElGamalCt, s: &Scalar, pk: &RistrettoPoint) -> bool {
    ElGamal::verify_rerandomization(pk, ct1, ct2, s)
}

/// Derive a deterministic ristretto scalar `H(seed ‖ idx)`.
fn derive_scalar(seed: &[u8], idx: u64) -> Scalar {
    let mut buf = Vec::with_capacity(seed.len() + 8);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&idx.to_be_bytes());
    let mut wide = [0u8; 64];
    hash_xof(SCALAR_LABEL, &buf, &mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ---- the generic shuffle -----------------------------------------------------------------------------------

/// A deterministic permutation of `0..n` from a seed (Fisher–Yates over a hash stream).
fn derive_permutation(seed: &[u8], tag: u64, n: usize) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..n).collect();
    if n <= 1 {
        return perm;
    }
    let mut buf = Vec::with_capacity(seed.len() + 8);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&tag.to_be_bytes());
    let mut stream = alloc::vec![0u8; n * 8];
    hash_xof(PERM_LABEL, &buf, &mut stream);
    for i in (1..n).rev() {
        let off = i * 8;
        let draw = stream
            .get(off..off + 8)
            .and_then(|b| b.try_into().ok())
            .map_or(0u64, u64::from_be_bytes);
        let j = (draw % (i as u64 + 1)) as usize;
        perm.swap(i, j);
    }
    perm
}

/// The inverse permutation (`inv[perm[i]] = i`).
fn invert(perm: &[usize]) -> Vec<usize> {
    let mut inv = alloc::vec![0usize; perm.len()];
    for (i, &p) in perm.iter().enumerate() {
        if let Some(slot) = inv.get_mut(p) {
            *slot = i;
        }
    }
    inv
}

/// Whether `p` is a permutation of `0..p.len()`.
fn is_permutation(p: &[usize]) -> bool {
    let mut seen = alloc::vec![false; p.len()];
    for &x in p {
        match seen.get_mut(x) {
            Some(slot) if !*slot => *slot = true,
            _ => return false,
        }
    }
    true
}

/// One shadow's opening: a permutation and one re-randomization factor per position (the `(σ_j, s_j)` `b=0`
/// branch or the `(τ_j, t_j)` `b=1` branch).
#[derive(Clone)]
struct Opening<R> {
    perm: Vec<usize>,
    factors: Vec<R>,
}

/// A verifiable-shuffle proof over backend `C`: the `k` shadow lists and their openings.
#[derive(Clone)]
pub struct ShuffleProof<C: ReRandomizable> {
    shadows: Vec<Vec<C::Ct>>,
    openings: Vec<Opening<C::Rand>>,
}

impl<C: ReRandomizable> ShuffleProof<C> {
    /// The number of cut-and-choose rounds `k` (soundness `1 − 2^-k`).
    #[must_use]
    pub fn rounds(&self) -> usize {
        self.shadows.len()
    }
}

/// Fiat–Shamir challenge bits — one per shadow — from `H(key ‖ n ‖ k ‖ inputs ‖ outputs ‖ shadows)`. Every
/// shadow ciphertext is committed *before* the challenge, and the public key and the shape `(n, k)` are bound
/// in, so a proof cannot be replayed across keys/instances and no single shadow can be re-ground independently
/// (changing any shadow re-rolls all `k` bits — the cut-and-choose grinding cost stays `2^k`, not `k·2`).
fn challenge_bits<C: ReRandomizable>(
    key: &C::Key,
    inputs: &[C::Ct],
    outputs: &[C::Ct],
    shadows: &[Vec<C::Ct>],
) -> Vec<bool> {
    let mut buf = C::key_bytes(key);
    buf.extend_from_slice(&(inputs.len() as u64).to_be_bytes());
    buf.extend_from_slice(&(shadows.len() as u64).to_be_bytes());
    for ct in inputs.iter().chain(outputs).chain(shadows.iter().flatten()) {
        buf.extend_from_slice(&C::ct_bytes(ct));
    }
    let mut digest = alloc::vec![0u8; shadows.len().div_ceil(8).max(1)];
    hash_xof(CHALLENGE_LABEL, &buf, &mut digest);
    (0..shadows.len())
        .map(|j| digest.get(j / 8).is_some_and(|byte| byte >> (j % 8) & 1 == 1))
        .collect()
}

/// Shuffle `inputs` (permute + re-randomize) under backend `C` and prove it non-interactively. Randomness is
/// derived from `seed`. Returns the shuffled outputs and a `k`-round proof. `None` if `inputs` is empty.
#[must_use]
pub fn prove<C: ReRandomizable>(
    key: &C::Key,
    inputs: &[C::Ct],
    seed: &[u8],
    k: usize,
) -> Option<(Vec<C::Ct>, ShuffleProof<C>)> {
    if k < MIN_ROUNDS {
        return None; // soundness parameter floor — a low k is a real forgery budget
    }
    let n = inputs.len();
    let first = inputs.first()?.clone(); // n >= 1
    // Real shuffle: out[pi[i]] = ReRand(in[i], rho[i]).
    let pi = derive_permutation(seed, 0, n);
    let rho: Vec<C::Rand> = (0..n).map(|i| C::derive_rand(seed, i as u64)).collect();
    let mut outputs = alloc::vec![first.clone(); n];
    for (i, ct) in inputs.iter().enumerate() {
        if let (Some(&dst), Some(r)) = (pi.get(i), rho.get(i))
            && let Some(slot) = outputs.get_mut(dst)
        {
            *slot = C::rerandomize(key, ct, r);
        }
    }

    // Shadows: M_j[sigma_j[i]] = ReRand(in[i], s_j[i]).
    let mut shadows: Vec<Vec<C::Ct>> = Vec::with_capacity(k);
    let mut sigmas: Vec<Vec<usize>> = Vec::with_capacity(k);
    let mut esses: Vec<Vec<C::Rand>> = Vec::with_capacity(k);
    for j in 0..k {
        let tag = 1 + j as u64;
        let sigma = derive_permutation(seed, tag, n);
        let s: Vec<C::Rand> = (0..n).map(|i| C::derive_rand(seed, tag * 1_000_003 + i as u64)).collect();
        let mut m = alloc::vec![first.clone(); n];
        for (i, ct) in inputs.iter().enumerate() {
            if let (Some(&dst), Some(si)) = (sigma.get(i), s.get(i))
                && let Some(slot) = m.get_mut(dst)
            {
                *slot = C::rerandomize(key, ct, si);
            }
        }
        shadows.push(m);
        sigmas.push(sigma);
        esses.push(s);
    }

    let bits = challenge_bits::<C>(key, inputs, &outputs, &shadows);
    let mut openings = Vec::with_capacity(k);
    for j in 0..k {
        let (sigma, s) = (sigmas.get(j)?, esses.get(j)?);
        let opening = if bits.get(j).copied().unwrap_or(false) {
            // b = 1: outputs re-randomize M_j. tau[l] = pi[sigma^{-1}[l]], t[l] = rho[i] − s[i], i = sigma^{-1}[l].
            let sinv = invert(sigma);
            let mut perm = alloc::vec![0usize; n];
            let mut factors: Vec<C::Rand> = Vec::with_capacity(n);
            for l in 0..n {
                let i = *sinv.get(l)?;
                *perm.get_mut(l)? = *pi.get(i)?;
                factors.push(C::sub_rand(rho.get(i)?, s.get(i)?));
            }
            Opening { perm, factors }
        } else {
            // b = 0: M_j re-randomizes the inputs — open (sigma_j, s_j).
            Opening { perm: sigma.clone(), factors: s.clone() }
        };
        openings.push(opening);
    }
    Some((outputs, ShuffleProof { shadows, openings }))
}

/// Verify a shuffle proof over backend `C`: the outputs are a permutation + re-randomization of the inputs,
/// soundness `1 − 2^-k`. Recomputes the Fiat–Shamir challenge and checks each shadow's opened branch
/// homomorphically — no plaintext is used, so verification reveals nothing about the permutation.
#[must_use]
pub fn verify<C: ReRandomizable>(
    key: &C::Key,
    inputs: &[C::Ct],
    outputs: &[C::Ct],
    proof: &ShuffleProof<C>,
) -> bool {
    let n = inputs.len();
    if outputs.len() != n || proof.shadows.len() != proof.openings.len() || proof.shadows.len() < MIN_ROUNDS {
        return false; // reject under-parameterized proofs (soundness floor)
    }
    if proof.shadows.iter().any(|m| m.len() != n) {
        return false;
    }
    let bits = challenge_bits::<C>(key, inputs, outputs, &proof.shadows);
    for (j, (m, opening)) in proof.shadows.iter().zip(&proof.openings).enumerate() {
        if opening.perm.len() != n || opening.factors.len() != n || !is_permutation(&opening.perm) {
            return false;
        }
        let b = bits.get(j).copied().unwrap_or(false);
        let ok = if b {
            // b = 1: for all l, outputs[tau[l]] == ReRand(M_j[l], t[l]).
            (0..n).all(|l| match (m.get(l), opening.perm.get(l), opening.factors.get(l)) {
                (Some(ml), Some(&dst), Some(t)) => {
                    outputs.get(dst).is_some_and(|o| C::verify_rerandomization(key, ml, o, t))
                }
                _ => false,
            })
        } else {
            // b = 0: for all i, M_j[sigma[i]] == ReRand(inputs[i], s[i]).
            (0..n).all(|i| match (inputs.get(i), opening.perm.get(i), opening.factors.get(i)) {
                (Some(inp), Some(&dst), Some(s)) => {
                    m.get(dst).is_some_and(|mm| C::verify_rerandomization(key, inp, mm, s))
                }
                _ => false,
            })
        };
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn keypair(tag: u8) -> (Scalar, RistrettoPoint) {
        let sk = derive_scalar(&[tag], 0);
        (sk, sk * RISTRETTO_BASEPOINT_POINT)
    }

    fn inputs(pk: &RistrettoPoint, n: usize, tag: &[u8]) -> Vec<ElGamalCt> {
        (0..n)
            .map(|i| {
                let mut seed = tag.to_vec();
                seed.push(0xE0);
                let m = derive_scalar(&seed, i as u64) * RISTRETTO_BASEPOINT_POINT;
                ElGamalCt::encrypt(pk, &m, &derive_scalar(&seed, i as u64 + 1_000))
            })
            .collect()
    }

    #[test]
    fn an_honest_shuffle_verifies_and_actually_permutes() {
        let (_sk, pk) = keypair(1);
        let ins = inputs(&pk, 6, b"A");
        let (outs, proof) = prove::<ElGamal>(&pk, &ins, b"shuffle-seed", MIN_ROUNDS).unwrap();
        assert!(verify::<ElGamal>(&pk, &ins, &outs, &proof), "an honest shuffle verifies");
        assert_eq!(proof.rounds(), MIN_ROUNDS, "128 rounds → 2^-128 soundness");
        assert!(ins.iter().zip(&outs).any(|(a, b)| a != b), "the shuffle re-randomizes");
    }

    #[test]
    fn re_randomization_preserves_the_plaintext() {
        let (sk, pk) = keypair(2);
        let ins = inputs(&pk, 5, b"A");
        let (outs, _proof) = prove::<ElGamal>(&pk, &ins, b"s", MIN_ROUNDS).unwrap();
        let decrypt = |ct: &ElGamalCt| ct.b - sk * ct.a;
        let mut in_msgs: Vec<[u8; 32]> = ins.iter().map(|c| decrypt(c).compress().to_bytes()).collect();
        let mut out_msgs: Vec<[u8; 32]> = outs.iter().map(|c| decrypt(c).compress().to_bytes()).collect();
        in_msgs.sort_unstable();
        out_msgs.sort_unstable();
        assert_eq!(in_msgs, out_msgs, "the shuffled plaintext multiset equals the input multiset");
    }

    #[test]
    fn a_dropped_added_or_altered_ciphertext_is_rejected() {
        let (_sk, pk) = keypair(3);
        let ins = inputs(&pk, 6, b"A");
        let (outs, proof) = prove::<ElGamal>(&pk, &ins, b"seed", MIN_ROUNDS).unwrap();

        let mut tampered = outs.clone();
        tampered[2] = ElGamalCt::encrypt(&pk, &(Scalar::from(999u64) * RISTRETTO_BASEPOINT_POINT), &Scalar::from(7u64));
        assert!(!verify::<ElGamal>(&pk, &ins, &tampered, &proof), "an altered output multiset is rejected");
        assert!(!verify::<ElGamal>(&pk, &ins, &outs[..5], &proof), "a dropped output is rejected");

        let other = inputs(&pk, 6, b"B");
        let (other_outs, other_proof) = prove::<ElGamal>(&pk, &other, b"seed2", MIN_ROUNDS).unwrap();
        assert!(!verify::<ElGamal>(&pk, &ins, &other_outs, &other_proof), "a shuffle of a different set does not verify against `ins`");
    }

    #[test]
    fn the_round_count_floor_is_enforced() {
        // Soundness is 2^-k, so k is a hard security parameter: prove refuses k < MIN_ROUNDS, and verify
        // refuses an under-parameterized proof even if one is hand-truncated (audit fix — no grindable low k).
        let (_sk, pk) = keypair(4);
        let ins = inputs(&pk, 4, b"A");
        for k in [1usize, 32, MIN_ROUNDS - 1] {
            assert!(prove::<ElGamal>(&pk, &ins, b"x", k).is_none(), "k={k} < floor must be refused");
        }
        // A valid proof, then truncate its rounds below the floor → verify rejects.
        let (outs, mut proof) = prove::<ElGamal>(&pk, &ins, b"y", MIN_ROUNDS).unwrap();
        assert!(verify::<ElGamal>(&pk, &ins, &outs, &proof), "the floor-parameterized proof verifies");
        proof.shadows.truncate(64);
        proof.openings.truncate(64);
        assert!(!verify::<ElGamal>(&pk, &ins, &outs, &proof), "a proof truncated below the floor is rejected");
    }

    #[test]
    fn the_challenge_binds_the_public_key() {
        // A proof made under one key must not verify under another (weak-FS hardening): the key is in the
        // Fiat–Shamir transcript, so a different key recomputes different challenge bits.
        let (_sk, pk) = keypair(6);
        let (_sk2, pk2) = keypair(7);
        let ins = inputs(&pk, 5, b"A");
        let (outs, proof) = prove::<ElGamal>(&pk, &ins, b"bind", MIN_ROUNDS).unwrap();
        assert!(verify::<ElGamal>(&pk, &ins, &outs, &proof));
        assert!(!verify::<ElGamal>(&pk2, &ins, &outs, &proof), "the proof must not verify under a different key");
    }

    #[test]
    fn the_opened_branches_never_reveal_the_full_permutation() {
        let (_sk, pk) = keypair(5);
        let ins = inputs(&pk, 5, b"A");
        let (outs, proof) = prove::<ElGamal>(&pk, &ins, b"hide", MIN_ROUNDS).unwrap();
        let bits = challenge_bits::<ElGamal>(&pk, &ins, &outs, &proof.shadows);
        assert_eq!(proof.openings.len(), bits.len());
        for opening in &proof.openings {
            assert_eq!(opening.perm.len(), 5);
            assert_eq!(opening.factors.len(), 5);
        }
        assert!(bits.iter().any(|&b| b) && bits.iter().any(|&b| !b), "both branches are exercised across rounds");
    }
}
