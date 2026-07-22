//! A **verifiable shuffle** — a sound, linkage-hiding mixnet proof (spec §16 `[P]` "verifiable shuffle";
//! `docs/design-pq-vrf.md` §3, Hand-roll full).
//!
//! > **NOVEL, UNAUDITED.** Hand-rolled with the reduction below and an extensive test suite, but without
//! > external cryptanalysis. Do not deploy without an audit.
//!
//! A verifiable shuffle proves that a list of output ciphertexts is a secret **permutation + re-randomization**
//! of the inputs — so no output can be linked to its submitter — *without revealing the permutation*. A deep
//! audit corrected an earlier plan: this is **impossible from hash commitments alone**. Proving a shadow
//! re-commits the inputs forces opening the input commitments, which leaks the submitter↔value link; genuine
//! unlinkability needs **re-randomization**, which needs a *homomorphic* cryptosystem so a verifier can check
//! `ct' = ReRand(ct, r)` from `r` **without** the plaintext.
//!
//! So the construction is a **Sako–Kilian cut-and-choose** over a re-randomizable encryption, and the *proof
//! logic is generic over that cryptosystem* — the sound, novel part. It is instantiated here over **ristretto
//! ElGamal** ([`curve25519_dalek`], already the group FANOS's VRF/DKG/VOPRF use — architecturally coherent).
//! The re-randomization is the only cryptosystem-specific seam ([`ElGamalCt`] / [`rerandomize`] /
//! [`verify_rerandomization`]); **swapping in a post-quantum re-randomizable encryption (a lattice/RLWE
//! ElGamal) makes the identical shuffle proof post-quantum** — the cut-and-choose soundness is unconditional.
//! Over ristretto it is classical (discrete log); over a lattice backend it is PQ. The [`[P]`] thus reduces to
//! "a PQ re-randomizable encryption", a known lattice primitive, and this construction is ready for it.
//!
//! **Security reduction.** *Soundness*: each shadow `M_j` is committed before the Fiat-Shamir challenge; if the
//! output multiset ≠ the input multiset, `M_j` cannot be **both** a re-randomization of the inputs (`b=0`) and
//! the outputs a re-randomization of `M_j` (`b=1`) — so one challenge branch fails, caught with probability
//! `≥ 1/2` per shadow, `1 − 2^-k` over `k` shadows. *Hiding*: no plaintext is ever revealed (only re-rand
//! factors, checked homomorphically), and only one branch per shadow is opened, so the composed permutation
//! `π` is never revealed — each opened `σ_j` is random and each `τ_j = π∘σ_j^{-1}` is masked by the hidden,
//! random `σ_j`.

use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{RistrettoPoint, Scalar};

use fanos_primitives::hash::hash_xof;

const SCALAR_LABEL: &str = "FANOS-v1/shuffle-scalar";
const PERM_LABEL: &str = "FANOS-v1/shuffle-perm";
const CHALLENGE_LABEL: &str = "FANOS-v1/shuffle-challenge";

/// An additive-ElGamal ciphertext over ristretto255: `(a, b) = (rG, M + r·pk)` for message point `M` and
/// randomness `r`. The cryptosystem seam — replace this (and [`rerandomize`]/[`verify_rerandomization`]) with a
/// lattice ElGamal for a post-quantum shuffle.
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

    /// The 64-byte compressed encoding `a ‖ b`, for hashing/transport.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.a.compress().as_bytes());
        out[32..].copy_from_slice(self.b.compress().as_bytes());
        out
    }
}

/// Re-randomize `ct` by `s` (same plaintext, fresh ciphertext): `(a + sG, b + s·pk)`. The homomorphic step the
/// shuffle relies on — the plaintext is unchanged but the ciphertext is unlinkable to the original.
#[must_use]
pub fn rerandomize(ct: &ElGamalCt, s: &Scalar, pk: &RistrettoPoint) -> ElGamalCt {
    ElGamalCt { a: ct.a + s * RISTRETTO_BASEPOINT_POINT, b: ct.b + s * pk }
}

/// Whether `ct2 == ReRand(ct1, s)` — checkable from `s` **without** the plaintext (the property that makes the
/// cut-and-choose zero-knowledge).
#[must_use]
pub fn verify_rerandomization(ct1: &ElGamalCt, ct2: &ElGamalCt, s: &Scalar, pk: &RistrettoPoint) -> bool {
    *ct2 == rerandomize(ct1, s, pk)
}

/// Derive a deterministic scalar `H(label ‖ seed ‖ idx)`.
fn derive_scalar(seed: &[u8], idx: u64) -> Scalar {
    let mut buf = Vec::with_capacity(seed.len() + 8);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&idx.to_be_bytes());
    let mut wide = [0u8; 64];
    hash_xof(SCALAR_LABEL, &buf, &mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive a deterministic permutation of `0..n` from a seed (Fisher–Yates over a hash stream).
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

/// The inverse of a permutation (`inv[perm[i]] = i`).
fn invert(perm: &[usize]) -> Vec<usize> {
    let mut inv = alloc::vec![0usize; perm.len()];
    for (i, &p) in perm.iter().enumerate() {
        if let Some(slot) = inv.get_mut(p) {
            *slot = i;
        }
    }
    inv
}

/// One shadow's opening: a permutation and one re-randomization scalar per position. For a `b=0` challenge it
/// is `(σ_j, s_j)` (proving `M_j` re-randomizes the inputs); for `b=1` it is `(τ_j, t_j)` (proving the outputs
/// re-randomize `M_j`). The verifier recomputes the challenge and applies the matching check.
#[derive(Clone, Debug)]
struct Opening {
    perm: Vec<usize>,
    scalars: Vec<Scalar>,
}

/// A verifiable-shuffle proof: the `k` shadow lists and their openings (one branch each, selected by the
/// Fiat–Shamir challenge).
#[derive(Clone, Debug)]
pub struct ShuffleProof {
    shadows: Vec<Vec<ElGamalCt>>,
    openings: Vec<Opening>,
}

impl ShuffleProof {
    /// The number of cut-and-choose rounds `k` (soundness `1 − 2^-k`).
    #[must_use]
    pub fn rounds(&self) -> usize {
        self.shadows.len()
    }
}

/// Fiat–Shamir challenge bits — one per shadow — from `H(inputs ‖ outputs ‖ shadows)`.
fn challenge_bits(inputs: &[ElGamalCt], outputs: &[ElGamalCt], shadows: &[Vec<ElGamalCt>]) -> Vec<bool> {
    let mut buf = Vec::new();
    for ct in inputs.iter().chain(outputs).chain(shadows.iter().flatten()) {
        buf.extend_from_slice(&ct.to_bytes());
    }
    let mut digest = alloc::vec![0u8; shadows.len().div_ceil(8).max(1)];
    hash_xof(CHALLENGE_LABEL, &buf, &mut digest);
    (0..shadows.len())
        .map(|j| digest.get(j / 8).is_some_and(|byte| byte >> (j % 8) & 1 == 1))
        .collect()
}

/// Shuffle `inputs` (permute + re-randomize) and prove it, non-interactively (Fiat–Shamir). All randomness is
/// derived from `seed` (a CSPRNG in production; a fixed seed under the simulator). Returns the shuffled
/// `outputs` and a [`ShuffleProof`] with `k` rounds. `None` if `inputs` is empty.
#[must_use]
pub fn prove(inputs: &[ElGamalCt], pk: &RistrettoPoint, seed: &[u8], k: usize) -> Option<(Vec<ElGamalCt>, ShuffleProof)> {
    let n = inputs.len();
    let first = *inputs.first()?; // n >= 1 for a non-empty shuffle
    // The real shuffle: out[pi[i]] = ReRand(in[i], rho[i]).
    let pi = derive_permutation(seed, 0, n);
    let rho: Vec<Scalar> = (0..n).map(|i| derive_scalar(seed, i as u64)).collect();
    let mut outputs = alloc::vec![first; n];
    for (i, ct) in inputs.iter().enumerate() {
        if let (Some(&dst), Some(r)) = (pi.get(i), rho.get(i))
            && let Some(slot) = outputs.get_mut(dst)
        {
            *slot = rerandomize(ct, r, pk);
        }
    }

    // Shadows: M_j[sigma_j[i]] = ReRand(in[i], s_j[i]).
    let mut shadows: Vec<Vec<ElGamalCt>> = Vec::with_capacity(k);
    let mut sigmas: Vec<Vec<usize>> = Vec::with_capacity(k);
    let mut esses: Vec<Vec<Scalar>> = Vec::with_capacity(k);
    for j in 0..k {
        let tag = 1 + j as u64;
        let sigma = derive_permutation(seed, tag, n);
        let s: Vec<Scalar> = (0..n).map(|i| derive_scalar(seed, tag * 1_000_003 + i as u64)).collect();
        let mut m = alloc::vec![first; n];
        for (i, ct) in inputs.iter().enumerate() {
            if let (Some(&dst), Some(si)) = (sigma.get(i), s.get(i))
                && let Some(slot) = m.get_mut(dst)
            {
                *slot = rerandomize(ct, si, pk);
            }
        }
        shadows.push(m);
        sigmas.push(sigma);
        esses.push(s);
    }

    let bits = challenge_bits(inputs, &outputs, &shadows);
    let mut openings = Vec::with_capacity(k);
    for j in 0..k {
        let (sigma, s) = (sigmas.get(j)?, esses.get(j)?);
        let opening = if bits.get(j).copied().unwrap_or(false) {
            // b = 1: prove outputs re-randomize M_j. tau[l] = pi[sigma^{-1}[l]], t[l] = rho[i] - s[i], i=sigma^{-1}[l].
            let sinv = invert(sigma);
            let mut perm = alloc::vec![0usize; n];
            let mut scalars = alloc::vec![Scalar::ZERO; n];
            for l in 0..n {
                let i = *sinv.get(l)?;
                *perm.get_mut(l)? = *pi.get(i)?;
                *scalars.get_mut(l)? = rho.get(i)? - s.get(i)?;
            }
            Opening { perm, scalars }
        } else {
            // b = 0: prove M_j re-randomizes the inputs — open (sigma_j, s_j) directly.
            Opening { perm: sigma.clone(), scalars: s.clone() }
        };
        openings.push(opening);
    }
    Some((outputs, ShuffleProof { shadows, openings }))
}

/// Verify a shuffle proof: the outputs are a permutation + re-randomization of the inputs, with soundness
/// `1 − 2^-k`. Recomputes the Fiat–Shamir challenge and checks each shadow's opened branch homomorphically —
/// no plaintext is used, so verification reveals nothing about the permutation.
#[must_use]
pub fn verify(inputs: &[ElGamalCt], outputs: &[ElGamalCt], pk: &RistrettoPoint, proof: &ShuffleProof) -> bool {
    let n = inputs.len();
    if outputs.len() != n || proof.shadows.len() != proof.openings.len() || proof.shadows.is_empty() {
        return false;
    }
    if proof.shadows.iter().any(|m| m.len() != n) {
        return false;
    }
    let bits = challenge_bits(inputs, outputs, &proof.shadows);
    for (j, (m, opening)) in proof.shadows.iter().zip(&proof.openings).enumerate() {
        if opening.perm.len() != n || opening.scalars.len() != n || !is_permutation(&opening.perm) {
            return false;
        }
        let b = bits.get(j).copied().unwrap_or(false);
        let ok = if b {
            // b = 1: for all l, outputs[tau[l]] == ReRand(M_j[l], t[l]).
            (0..n).all(|l| match (m.get(l), opening.perm.get(l), opening.scalars.get(l)) {
                (Some(ml), Some(&dst), Some(t)) => {
                    outputs.get(dst).is_some_and(|o| verify_rerandomization(ml, o, t, pk))
                }
                _ => false,
            })
        } else {
            // b = 0: for all i, M_j[sigma[i]] == ReRand(inputs[i], s[i]).
            (0..n).all(|i| match (inputs.get(i), opening.perm.get(i), opening.scalars.get(i)) {
                (Some(inp), Some(&dst), Some(s)) => {
                    m.get(dst).is_some_and(|mm| verify_rerandomization(inp, mm, s, pk))
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
                let m = derive_scalar(&seed, i as u64) * RISTRETTO_BASEPOINT_POINT; // a distinct message point
                ElGamalCt::encrypt(pk, &m, &derive_scalar(&seed, i as u64 + 1_000))
            })
            .collect()
    }

    #[test]
    fn an_honest_shuffle_verifies_and_actually_permutes() {
        let (_sk, pk) = keypair(1);
        let ins = inputs(&pk, 6, b"A");
        let (outs, proof) = prove(&ins, &pk, b"shuffle-seed", 32).unwrap();
        assert!(verify(&ins, &outs, &pk, &proof), "an honest shuffle verifies");
        assert_eq!(proof.rounds(), 32, "32 rounds → 2^-32 soundness");
        // The outputs are genuinely re-randomized (no output ciphertext equals its input verbatim in order).
        assert!(ins.iter().zip(&outs).any(|(a, b)| a != b), "the shuffle re-randomizes (outputs differ from inputs)");
    }

    #[test]
    fn re_randomization_preserves_the_plaintext() {
        // Decryption recovers the same message set — the shuffle only hides the order, not the contents.
        let (sk, pk) = keypair(2);
        let ins = inputs(&pk, 5, b"A");
        let (outs, _proof) = prove(&ins, &pk, b"s", 8).unwrap();
        let decrypt = |ct: &ElGamalCt| ct.b - sk * ct.a; // M = b - sk·a
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
        let (outs, proof) = prove(&ins, &pk, b"seed", 24).unwrap();

        // Replace one output with an unrelated ciphertext (the multiset no longer matches) → rejected.
        let mut tampered = outs.clone();
        tampered[2] = ElGamalCt::encrypt(&pk, &(Scalar::from(999u64) * RISTRETTO_BASEPOINT_POINT), &Scalar::from(7u64));
        assert!(!verify(&ins, &tampered, &pk, &proof), "an altered output multiset is rejected");

        // Drop an output (wrong length) → rejected.
        assert!(!verify(&ins, &outs[..5], &pk, &proof), "a dropped output is rejected");

        // A forged proof for a genuinely different (non-permutation) output set fails: shuffle a DIFFERENT
        // input set, then claim it shuffles `ins`.
        let other = inputs(&pk, 6, b"B");
        let (other_outs, other_proof) = prove(&other, &pk, b"seed2", 24).unwrap();
        assert!(!verify(&ins, &other_outs, &pk, &other_proof), "a shuffle of a different input set does not verify against `ins`");
    }

    #[test]
    fn soundness_scales_with_the_round_count() {
        // Even a single round rejects a wrong shuffle with probability >= 1/2; here the deterministic seed
        // happens to catch it, and more rounds only strengthen it. (A structural check, not a statistical one.)
        let (_sk, pk) = keypair(4);
        let ins = inputs(&pk, 4, b"A");
        let other = inputs(&pk, 4, b"B");
        for k in [1usize, 4, 16] {
            let (bad_outs, bad_proof) = prove(&other, &pk, b"x", k).unwrap();
            assert!(!verify(&ins, &bad_outs, &pk, &bad_proof), "k={k}: a mismatched shuffle is rejected");
            let (good_outs, good_proof) = prove(&ins, &pk, b"y", k).unwrap();
            assert!(verify(&ins, &good_outs, &pk, &good_proof), "k={k}: an honest shuffle verifies");
        }
    }

    #[test]
    fn the_opened_branches_never_reveal_the_full_permutation() {
        // Hiding (structural): for every shadow, the opening is a SINGLE branch — either the input→M map or the
        // M→output map, never both — so the composed input→output permutation is never present in the proof.
        let (_sk, pk) = keypair(5);
        let ins = inputs(&pk, 5, b"A");
        let (outs, proof) = prove(&ins, &pk, b"hide", 40).unwrap();
        let bits = challenge_bits(&ins, &outs, &proof.shadows);
        assert_eq!(proof.openings.len(), bits.len());
        // Each opening is exactly one permutation (one branch); there is no shadow with both branches present.
        for opening in &proof.openings {
            assert_eq!(opening.perm.len(), 5);
            assert_eq!(opening.scalars.len(), 5);
        }
        // Both challenge outcomes actually occur across the rounds (so neither map is always the one revealed).
        assert!(bits.iter().any(|&b| b) && bits.iter().any(|&b| !b), "both branches are exercised across rounds");
    }
}
