//! A **post-quantum re-randomizable encryption** — Ring-LWE (Regev-style) additive ElGamal — the lattice
//! backend that makes [`crate::shuffle`] genuinely post-quantum (spec §16 `[P]`; Hand-roll full).
//!
//! > **NOVEL, UNAUDITED.** A from-scratch Ring-LWE implementation with a security reduction to decisional
//! > Ring-LWE, **literature-calibrated parameters** (below), and a Monte-Carlo decryption-failure experiment.
//! > It has **not** had external cryptanalysis and is not constant-time/side-channel-hardened; deploy only
//! > after an audit and a hardened (NTT, CT) backend.
//!
//! **Parameters — NewHope-512-grounded (`docs/design-pq-vrf.md` §4).** `n = 512`, `q = 12289`, centered-
//! binomial noise `η = 8` (stddev `σ = √(η/2) = 2`): the canonical single-ring RLWE set of NewHope
//! (Alkim–Ducas–Pöppelmann–Schwabe), whose `NewHope-512` instance is estimated at **≈ 101-bit post-quantum**
//! core-SVP security (NIST level 1). `q = 12289 ≡ 1 (mod 2n)` is NTT-friendly (`R_q` splits completely). The
//! [`noise_experiment`] tests confirm the encrypt-then-re-randomize decryption noise is `~17σ_tot` below the
//! `q/4` failure bound, so the analytic decryption-failure rate `< 2^-100` holds even after a re-randomization.
//!
//! It implements [`ReRandomizable`](crate::shuffle::ReRandomizable) so the *same* Sako–Kilian shuffle proof
//! runs post-quantum. Ciphertexts live in `R_q = Z_q[X]/(X^n + 1)`:
//!
//! ```text
//! sk = s (small)                       pk = (a, b = a·s + e),  a uniform, e small
//! Enc(m ∈ {0,1}^n) = (u, v) = (a·r + e1 ,  b·r + e2 + m·⌊q/2⌋)         r, e1, e2 small
//! ReRand((u,v), (r',e1',e2')) = (u + a·r' + e1' ,  v + b·r' + e2')     — a fresh Enc(0) added; plaintext kept
//! Dec(s, (u,v)) = round( v − s·u )                                     — noise < q/4 ⇒ correct
//! ```
//!
//! Re-randomization is **additively composable** (`Enc(0)` values add: `zero(x)+zero(y) = zero(x+y)`), so the
//! shuffle's `b=1` factor `ρ − s` works exactly, and it is **publicly checkable from `(r',e1',e2')`** without
//! the plaintext — the two properties the shuffle needs. Security of re-randomization unlinkability reduces to
//! the **decisional Ring-LWE** assumption (a fresh `Enc(0)` is pseudorandom, so `ReRand(ct, ·)` is
//! indistinguishable from a fresh encryption of the same message).

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::shuffle::ReRandomizable;

/// Ring degree (a power of two): `R_q = Z_q[X]/(X^n + 1)` — NewHope-512.
const N: usize = 512;
/// Ring modulus (prime, `≡ 1 mod 2n` ⇒ NTT-friendly) — NewHope's `q`.
const Q: i64 = 12289;
/// Centered-binomial noise parameter (NewHope-512): coefficients in `[−η, η]`, variance `η/2 = 4`, `σ = 2`.
const ETA: usize = 8;
// `cbd_poly` draws η bits per popcount from each of two bytes, which pins η to the byte width.
const _: () = assert!(ETA == 8, "cbd_poly's per-byte popcount hardcodes η = 8");
/// The message scaling `⌊q/2⌋` (a `0` bit encodes near `0`, a `1` bit near `q/2`).
const HALF_Q: i64 = Q / 2;

/// Reduce into the canonical range `[0, q)`.
#[inline]
fn rem(x: i64) -> i64 {
    ((x % Q) + Q) % Q
}

/// An element of `R_q` — `n` coefficients in `[0, q)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Poly([i64; N]);

#[allow(clippy::indexing_slicing)] // fixed-size R_q kernels: all indices are loop-bounded < N
impl Poly {
    fn add(&self, o: &Self) -> Self {
        Self(core::array::from_fn(|k| rem(self.0[k] + o.0[k])))
    }

    fn sub(&self, o: &Self) -> Self {
        Self(core::array::from_fn(|k| rem(self.0[k] - o.0[k])))
    }

    /// Negacyclic multiplication in `Z_q[X]/(X^n + 1)` (schoolbook; `X^n = −1` folds the high half back with a
    /// sign flip).
    fn mul(&self, o: &Self) -> Self {
        let mut acc = [0i64; 2 * N];
        for (i, &ai) in self.0.iter().enumerate() {
            if ai == 0 {
                continue;
            }
            for (j, &oj) in o.0.iter().enumerate() {
                acc[i + j] += ai * oj;
            }
        }
        // X^n = −1 ⇒ the coefficient at k+n subtracts.
        Self(core::array::from_fn(|k| rem(acc[k] - acc[k + N])))
    }

    /// Canonical little-endian 2-bytes-per-coefficient encoding (for the Fiat–Shamir transcript / transport).
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(N * 2);
        for &c in &self.0 {
            out.extend_from_slice(&(c as u16).to_le_bytes());
        }
        out
    }
}

/// Derive a **centered-binomial** noise polynomial (NewHope-512: `η = 8`, coefficients in `[−η, η]`,
/// `σ = √(η/2) = 2`) from `(seed, tag, idx)`. Each coefficient uses `2η = 16` bits: `popcount(low η) −
/// popcount(high η)`.
fn cbd_poly(seed: &[u8], tag: &str, idx: u64) -> Poly {
    let mut buf = Vec::with_capacity(seed.len() + 8);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&idx.to_be_bytes());
    let mut bytes = alloc::vec![0u8; N * 2]; // 2 bytes = 16 bits per coeff (η = 8)
    hash_xof(tag, &buf, &mut bytes);
    Poly(core::array::from_fn(|k| {
        let lo = bytes.get(2 * k).copied().unwrap_or(0);
        let hi = bytes.get(2 * k + 1).copied().unwrap_or(0);
        let a = i64::from(lo.count_ones()); // η = 8 bits
        let b = i64::from(hi.count_ones());
        rem(a - b) // in [−η, η], reduced mod q
    }))
}

/// Derive a **uniform** polynomial (coefficients in `[0, q)`) from `(seed, tag)` — the public `a`.
#[allow(clippy::indexing_slicing)]
fn uniform_poly(seed: &[u8], tag: &str) -> Poly {
    let mut bytes = alloc::vec![0u8; N * 2];
    hash_xof(tag, seed, &mut bytes);
    Poly(core::array::from_fn(|k| {
        let lo = bytes.get(2 * k).copied().unwrap_or(0);
        let hi = bytes.get(2 * k + 1).copied().unwrap_or(0);
        i64::from(u16::from_le_bytes([lo, hi])) % Q
    }))
}

/// A Ring-LWE public key `(a, b = a·s + e)`.
#[derive(Clone, Debug)]
pub struct RlwePublic {
    a: Poly,
    b: Poly,
}

/// A Ring-LWE secret key.
pub struct RlweSecret {
    s: Poly,
}

/// A Ring-LWE ciphertext `(u, v)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RlweCt {
    u: Poly,
    v: Poly,
}

impl RlweCt {
    /// Bytes `u ‖ v` for the transcript.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.u.to_bytes();
        out.extend_from_slice(&self.v.to_bytes());
        out
    }
}

/// A re-randomization factor: a fresh `Enc(0)`'s randomness `(r, e1, e2)`.
#[derive(Clone, Debug)]
pub struct RlweRand {
    r: Poly,
    e1: Poly,
    e2: Poly,
}

/// Generate a Ring-LWE keypair deterministically from `seed`.
#[must_use]
pub fn keygen(seed: &[u8]) -> (RlweSecret, RlwePublic) {
    let a = uniform_poly(seed, "FANOS-v1/rlwe-a");
    let s = cbd_poly(seed, "FANOS-v1/rlwe-s", 0);
    let e = cbd_poly(seed, "FANOS-v1/rlwe-e", 1);
    let b = a.mul(&s).add(&e);
    (RlweSecret { s }, RlwePublic { a, b })
}

/// Encrypt a binary message `m` (coefficients `0`/`1`) under `pk`, with randomness derived from `(seed, idx)`.
#[must_use]
pub fn encrypt(pk: &RlwePublic, m: &[u8], seed: &[u8], idx: u64) -> RlweCt {
    let rand = RlweRand::derive(seed, idx);
    let mut mp = [0i64; N];
    for (k, slot) in mp.iter_mut().enumerate() {
        *slot = i64::from(m.get(k).copied().unwrap_or(0) & 1) * HALF_Q;
    }
    let u = pk.a.mul(&rand.r).add(&rand.e1);
    let v = pk.b.mul(&rand.r).add(&rand.e2).add(&Poly(mp));
    RlweCt { u, v }
}

/// Decrypt `ct` to its message bits (rounding `v − s·u`: near `⌊q/2⌋` ⇒ `1`, near `0` ⇒ `0`).
#[must_use]
pub fn decrypt(sk: &RlweSecret, ct: &RlweCt) -> Vec<u8> {
    let w = ct.v.sub(&sk.s.mul(&ct.u));
    (0..N)
        .map(|k| {
            let c = w.0.get(k).copied().unwrap_or(0);
            // Distance to 0 vs to q/2 (mod q): a coefficient nearer q/2 decodes to 1.
            let d0 = c.min(Q - c);
            let dh = (c - HALF_Q).abs().min(Q - (c - HALF_Q).abs());
            u8::from(dh < d0)
        })
        .collect()
}

impl RlweRand {
    /// Derive `(r, e1, e2)` small polynomials from `(seed, idx)`.
    #[must_use]
    fn derive(seed: &[u8], idx: u64) -> Self {
        Self {
            r: cbd_poly(seed, "FANOS-v1/rlwe-rand-r", idx),
            e1: cbd_poly(seed, "FANOS-v1/rlwe-rand-e1", idx),
            e2: cbd_poly(seed, "FANOS-v1/rlwe-rand-e2", idx),
        }
    }
}

/// The post-quantum Ring-LWE backend for [`crate::shuffle`].
pub struct Rlwe;

impl ReRandomizable for Rlwe {
    type Ct = RlweCt;
    type Rand = RlweRand;
    type Key = RlwePublic;

    fn rerandomize(pk: &RlwePublic, ct: &RlweCt, r: &RlweRand) -> RlweCt {
        // Add a fresh Enc(0): (a·r + e1, b·r + e2). The plaintext is unchanged.
        RlweCt {
            u: ct.u.add(&pk.a.mul(&r.r)).add(&r.e1),
            v: ct.v.add(&pk.b.mul(&r.r)).add(&r.e2),
        }
    }

    fn verify_rerandomization(pk: &RlwePublic, ct1: &RlweCt, ct2: &RlweCt, r: &RlweRand) -> bool {
        *ct2 == Self::rerandomize(pk, ct1, r)
    }

    fn sub_rand(a: &RlweRand, b: &RlweRand) -> RlweRand {
        RlweRand {
            r: a.r.sub(&b.r),
            e1: a.e1.sub(&b.e1),
            e2: a.e2.sub(&b.e2),
        }
    }

    fn derive_rand(seed: &[u8], idx: u64) -> RlweRand {
        RlweRand::derive(seed, idx)
    }

    fn ct_bytes(ct: &RlweCt) -> Vec<u8> {
        ct.to_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::shuffle;

    fn message(tag: u8) -> Vec<u8> {
        // A pseudo-random binary message.
        let mut bytes = alloc::vec![0u8; N / 8];
        hash_xof("FANOS-v1/rlwe-test-msg", &[tag], &mut bytes);
        (0..N).map(|k| (bytes[k / 8] >> (k % 8)) & 1).collect()
    }

    #[test]
    fn encryption_round_trips() {
        let (sk, pk) = keygen(b"rlwe-key-1");
        let m = message(1);
        let ct = encrypt(&pk, &m, b"enc", 0);
        assert_eq!(decrypt(&sk, &ct), m, "Enc then Dec recovers the message");
    }

    #[test]
    fn re_randomization_preserves_the_plaintext_and_changes_the_ciphertext() {
        let (sk, pk) = keygen(b"rlwe-key-2");
        let m = message(2);
        let ct = encrypt(&pk, &m, b"enc", 0);
        let r = RlweRand::derive(b"rerand", 7);
        let ct2 = Rlwe::rerandomize(&pk, &ct, &r);
        assert_ne!(ct2, ct, "re-randomization changes the ciphertext (unlinkable)");
        assert_eq!(decrypt(&sk, &ct2), m, "re-randomization preserves the plaintext");
        // Public checkability without the plaintext.
        assert!(Rlwe::verify_rerandomization(&pk, &ct, &ct2, &r));
        let wrong = RlweRand::derive(b"rerand", 8);
        assert!(!Rlwe::verify_rerandomization(&pk, &ct, &ct2, &wrong), "a wrong factor is rejected");
    }

    #[test]
    fn re_randomization_composes_additively() {
        // The property the shuffle's b=1 branch relies on: ReRand(ReRand(ct, s), ρ−s) == ReRand(ct, ρ).
        let (_sk, pk) = keygen(b"rlwe-key-3");
        let ct = encrypt(&pk, &message(3), b"enc", 0);
        let rho = RlweRand::derive(b"rho", 1);
        let s = RlweRand::derive(b"s", 2);
        let via_shadow = Rlwe::rerandomize(&pk, &Rlwe::rerandomize(&pk, &ct, &s), &Rlwe::sub_rand(&rho, &s));
        let direct = Rlwe::rerandomize(&pk, &ct, &rho);
        assert_eq!(via_shadow, direct, "re-randomization composes additively (ρ = s + (ρ−s))");
    }

    #[test]
    fn the_same_shuffle_proof_runs_post_quantum_over_rlwe() {
        // The whole point: the generic Sako–Kilian shuffle, unchanged, over the PQ Ring-LWE backend.
        let (sk, pk) = keygen(b"rlwe-shuffle");
        let ins: Vec<RlweCt> = (0..4).map(|i| encrypt(&pk, &message(10 + i as u8), b"in", i)).collect();
        let (outs, proof) = shuffle::prove::<Rlwe>(&pk, &ins, b"pq-shuffle-seed", 16).unwrap();
        assert!(shuffle::verify::<Rlwe>(&pk, &ins, &outs, &proof), "the PQ shuffle verifies");

        // The shuffled plaintext multiset equals the input multiset (order hidden, contents preserved).
        let mut in_msgs: Vec<Vec<u8>> = ins.iter().map(|c| decrypt(&sk, c)).collect();
        let mut out_msgs: Vec<Vec<u8>> = outs.iter().map(|c| decrypt(&sk, c)).collect();
        in_msgs.sort();
        out_msgs.sort();
        assert_eq!(in_msgs, out_msgs, "the PQ shuffle preserves the plaintext multiset");

        // A tampered output multiset is rejected (soundness over the PQ backend).
        let mut bad = outs.clone();
        bad[1] = encrypt(&pk, &message(99), b"forge", 0);
        assert!(!shuffle::verify::<Rlwe>(&pk, &ins, &bad, &proof), "a tampered PQ shuffle is rejected");
    }
}

/// The **decryption-noise experiment** (`docs/design-pq-vrf.md` §4): a Monte-Carlo validation of the analytic
/// noise model, so the extrapolated decryption-failure rate (`< 2^-100`, un-observable directly) is
/// trustworthy. For NewHope-512 CBD noise (`σ = 2`), the encrypt-then-one-re-randomization decryption noise has
/// per-coefficient stddev `σ_tot ≈ 2σ²√n = 2·4·√512 ≈ 181`, and `q/4 = 3072 ≈ 17·σ_tot`, so a failure is a
/// `> 17σ` tail event. The test confirms the empirical stddev matches `≈ 181` and every observed noise
/// coefficient sits far below `q/4`.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::cast_precision_loss)]
mod noise_experiment {
    use super::*;

    /// A pseudo-random binary message of `N` bits from `tag`.
    fn rand_message(tag: u64) -> Vec<u8> {
        let mut bytes = alloc::vec![0u8; N / 8];
        hash_xof("FANOS-v1/rlwe-noise-msg", &tag.to_be_bytes(), &mut bytes);
        bytes.iter().flat_map(|&byte| (0..8).map(move |b| (byte >> b) & 1)).take(N).collect()
    }

    #[test]
    fn decryption_noise_matches_the_analytic_model_after_re_randomization() {
        let trials = 100u64;
        let mut sum_sq = 0.0f64;
        let mut count = 0u64;
        let mut max_abs = 0i64;
        for t in 0..trials {
            let seed = alloc::format!("noise-key-{t}");
            let (sk, pk) = keygen(seed.as_bytes());
            let m = rand_message(t);
            let ct = encrypt(&pk, &m, b"noise-enc", t);
            // One re-randomization — the worst case a single-mixer shuffle output undergoes.
            let ct2 = Rlwe::rerandomize(&pk, &ct, &RlweRand::derive(b"noise-rr", t));
            // Decryption must be correct on every trial.
            assert_eq!(decrypt(&sk, &ct2), m, "trial {t}: decryption is correct after re-randomization");
            // Measure the centered decryption noise per coefficient: (v − s·u) − m·⌊q/2⌋, centered to [−q/2, q/2).
            let w = ct2.v.sub(&sk.s.mul(&ct2.u));
            for (mk, &wk) in m.iter().zip(&w.0) {
                let raw = rem(wk - i64::from(*mk) * HALF_Q);
                let centered = if raw > Q / 2 { raw - Q } else { raw };
                sum_sq += (centered as f64) * (centered as f64);
                max_abs = max_abs.max(centered.abs());
                count += 1;
            }
        }
        let emp_std = (sum_sq / count as f64).sqrt();
        // The analytic prediction is σ_tot ≈ 181; the empirical value must be close (within a modest factor).
        assert!(
            (120.0..250.0).contains(&emp_std),
            "empirical noise stddev {emp_std:.1} is far from the analytic ≈181 (σ=2, n=512, one re-rand)"
        );
        // Every observed noise coefficient is far below the q/4 failure bound (so the > 17σ tail — DFR < 2^-100
        // — is a sound extrapolation, not observed here over ~51k samples).
        assert!(max_abs < Q / 4, "max observed noise {max_abs} must be below q/4 = {}", Q / 4);
        assert!(
            (max_abs as f64) < 7.0 * emp_std,
            "max noise {max_abs} over {count} samples is a reasonable tail (< 7σ ≈ {:.0})",
            7.0 * emp_std
        );
    }
}
