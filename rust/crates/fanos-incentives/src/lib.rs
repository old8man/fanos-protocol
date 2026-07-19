//! # fanos-incentives — L7 anonymous relay credits (VOPRF blind tokens)
//!
//! Staking binds identity to capital, so paying for relay service would deanonymise. FANOS uses
//! **anonymous credits** instead (spec §L7): a Privacy-Pass-class **verifiable oblivious PRF**
//! (a VOPRF on ristretto255 — Privacy-Pass *in spirit*, but with a BLAKE3-XOF hash-to-curve and a bespoke
//! Chaum–Pedersen DLEQ, so **not** wire-compatible with RFC 9497/9578; the RFCs are a reference, not a
//! conformance claim). A client blinds a random input, the issuer evaluates the
//! PRF on the *blinded* point (learning nothing about the input) with a **DLEQ proof** that it used
//! its real key, and the client unblinds to a credit `N = k·H(x)`. Issuance sees only the blinded
//! point; redemption sees `x`; the two are **unlinkable** because the blind is uniformly random —
//! so a relay is paid without anyone learning *who* paid.
//!
//! * [`CreditIssuer`] — holds the PRF key `k`, issues (with a DLEQ proof), and redeems (with
//!   double-spend detection).
//! * [`request`] / [`finalize`] — the client side: blind, then verify the proof and unblind.
//! * [`Credit`] — a redeemable, transferable token `(x, N)`.
//!
//! The DLEQ (Chaum–Pedersen) proof makes the OPRF **verifiable**: a client is guaranteed the issuer
//! used the key its public value commits to, so it cannot be fed junk tokens. No new hardness
//! assumption — ristretto255 discrete log, already assumed across FANOS.

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

use fanos_primitives::hash::hash_xof;

/// The input length of a credit (a random nonce chosen by the client).
pub const INPUT_LEN: usize = 32;

const H2C_LABEL: &str = "FANOS-v1/credit-h2c";
const DLEQ_LABEL: &str = "FANOS-v1/credit-dleq";
const DLEQ_NONCE_LABEL: &str = "FANOS-v1/credit-dleq-nonce";

/// Hash an input to a ristretto255 point (`H(x)`), the PRF's domain map.
fn hash_to_curve(input: &[u8]) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    hash_xof(H2C_LABEL, input, &mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// The Fiat–Shamir challenge over a DLEQ transcript.
fn dleq_challenge(points: &[&RistrettoPoint]) -> Scalar {
    let mut data = Vec::with_capacity(points.len() * 32);
    for p in points {
        data.extend_from_slice(p.compress().as_bytes());
    }
    let mut wide = [0u8; 64];
    hash_xof(DLEQ_LABEL, &data, &mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A Chaum–Pedersen proof that `Z = k·B` under the same `k` as `K = k·G`.
#[derive(Clone, Copy, Debug)]
pub struct Dleq {
    c: Scalar,
    z: Scalar,
}

/// The **synthetic** (deterministic) DLEQ nonce `s = H(k ‖ K ‖ B ‖ Z)` — derived from the issuer secret
/// `k` and the full transcript, RFC-6979 style. It is unique per statement and never repeats across
/// different statements, and it does not depend on caller entropy — so a weak or reused RNG can no longer
/// leak `k` (two proofs sharing a nonce would give `k = (z₁−z₂)/(c₁−c₂)`; audit B4). Including the secret
/// makes `s` unpredictable to anyone without `k`; the hash is one-way, so it does not reveal `k`.
fn synthetic_dleq_nonce(
    k: &Scalar,
    pk: &RistrettoPoint,
    b: &RistrettoPoint,
    z_point: &RistrettoPoint,
) -> Scalar {
    let mut data = Vec::with_capacity(4 * 32);
    data.extend_from_slice(k.as_bytes());
    data.extend_from_slice(pk.compress().as_bytes());
    data.extend_from_slice(b.compress().as_bytes());
    data.extend_from_slice(z_point.compress().as_bytes());
    let mut wide = [0u8; 64];
    hash_xof(DLEQ_NONCE_LABEL, &data, &mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn prove_dleq(k: Scalar, pk: &RistrettoPoint, b: &RistrettoPoint, z_point: &RistrettoPoint) -> Dleq {
    let g = RISTRETTO_BASEPOINT_POINT;
    let s = synthetic_dleq_nonce(&k, pk, b, z_point);
    let a1 = s * g;
    let a2 = s * b;
    let c = dleq_challenge(&[&g, pk, b, z_point, &a1, &a2]);
    Dleq { c, z: s + c * k }
}

fn verify_dleq(
    pk: &RistrettoPoint,
    b: &RistrettoPoint,
    z_point: &RistrettoPoint,
    proof: &Dleq,
) -> bool {
    let g = RISTRETTO_BASEPOINT_POINT;
    let a1 = proof.z * g - proof.c * pk;
    let a2 = proof.z * b - proof.c * z_point;
    dleq_challenge(&[&g, pk, b, z_point, &a1, &a2]) == proof.c
}

/// The issuer's public key `K = k·G`, used by clients to verify the DLEQ proof.
#[derive(Clone, Copy, Debug)]
pub struct IssuerPublic(RistrettoPoint);

impl IssuerPublic {
    /// The 32-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

/// The client's private state for one token (kept until unblinding).
#[derive(Clone, Copy, Debug)]
pub struct TokenRequest {
    input: [u8; INPUT_LEN],
    blind: Scalar,
}

/// The blinded point `B = blind·H(x)` sent to the issuer (reveals nothing about `x`).
#[derive(Clone, Copy, Debug)]
pub struct BlindedToken(RistrettoPoint);

impl BlindedToken {
    /// The 32-byte compressed encoding (for transport).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Decode a blinded token, or `None` if not a valid group element.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        CompressedRistretto::from_slice(bytes)
            .ok()?
            .decompress()
            .map(Self)
    }
}

/// The issuer's response: the evaluated point `Z = k·B` and the DLEQ proof of correctness.
#[derive(Clone, Copy, Debug)]
pub struct SignedToken {
    evaluated: RistrettoPoint,
    proof: Dleq,
}

/// A redeemable, transferable credit `(x, N = k·H(x))`.
#[derive(Clone, Copy, Debug)]
pub struct Credit {
    input: [u8; INPUT_LEN],
    output: RistrettoPoint,
}

impl Credit {
    /// The credit's `input ‖ output` encoding (64 bytes) for transport.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..INPUT_LEN].copy_from_slice(&self.input);
        out[INPUT_LEN..].copy_from_slice(&self.output.compress().to_bytes());
        out
    }

    /// Decode a credit, or `None` if the output is not a valid group element.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let mut input = [0u8; INPUT_LEN];
        input.copy_from_slice(bytes.get(..INPUT_LEN)?);
        let point = CompressedRistretto::from_slice(bytes.get(INPUT_LEN..)?)
            .ok()?
            .decompress()?;
        Some(Self {
            input,
            output: point,
        })
    }
}

/// The result of presenting a credit for redemption.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Redemption {
    /// A valid, first-time credit — accept.
    Accepted,
    /// A valid credit already redeemed — reject (double-spend).
    DoubleSpent,
    /// The credit does not verify under the issuer's key — reject (forged).
    Invalid,
}

/// A credit issuer: holds the PRF key, issues blind-signed tokens, and redeems them once.
pub struct CreditIssuer {
    k: Scalar,
    public: RistrettoPoint,
    spent: alloc::collections::BTreeSet<[u8; INPUT_LEN]>,
}

impl CreditIssuer {
    /// Derive an issuer from a seed (its long-term PRF key).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut wide = [0u8; 64];
        hash_xof("FANOS-v1/credit-issuer", seed, &mut wide);
        let k = Scalar::from_bytes_mod_order_wide(&wide);
        Self {
            k,
            public: k * RISTRETTO_BASEPOINT_POINT,
            spent: alloc::collections::BTreeSet::new(),
        }
    }

    /// The issuer's public key (clients verify DLEQ proofs against it).
    #[must_use]
    pub fn public(&self) -> IssuerPublic {
        IssuerPublic(self.public)
    }

    /// Blind-evaluate a client's token: `Z = k·B`, with a DLEQ proof of correct evaluation. The
    /// issuer learns nothing about the underlying input. Needs no entropy — the DLEQ nonce is synthetic
    /// (deterministic from the secret + transcript), so issuance cannot be weakened by a bad RNG (B4).
    #[must_use]
    pub fn issue(&self, blinded: &BlindedToken) -> SignedToken {
        let evaluated = self.k * blinded.0;
        let proof = prove_dleq(self.k, &self.public, &blinded.0, &evaluated);
        SignedToken { evaluated, proof }
    }

    /// Whether a credit verifies under this issuer's key (`N == k·H(x)`).
    #[must_use]
    pub fn verify(&self, credit: &Credit) -> bool {
        self.k * hash_to_curve(&credit.input) == credit.output
    }

    /// Redeem a credit once: verify it, then reject a replay (double-spend).
    pub fn redeem(&mut self, credit: &Credit) -> Redemption {
        if !self.verify(credit) {
            return Redemption::Invalid;
        }
        if self.spent.insert(credit.input) {
            Redemption::Accepted
        } else {
            Redemption::DoubleSpent
        }
    }
}

/// Client step 1 — blind a fresh random input into a token the issuer will sign.
#[must_use]
pub fn request<R: RngCore + CryptoRng>(rng: &mut R) -> (TokenRequest, BlindedToken) {
    let mut input = [0u8; INPUT_LEN];
    rng.fill_bytes(&mut input);
    let blind = Scalar::random(rng);
    let blinded = blind * hash_to_curve(&input);
    (TokenRequest { input, blind }, BlindedToken(blinded))
}

/// Client step 2 — verify the issuer's DLEQ proof and unblind to a usable [`Credit`]. Returns
/// `None` if the proof does not check out (the issuer used the wrong key or cheated).
#[must_use]
pub fn finalize(
    request: TokenRequest,
    blinded: &BlindedToken,
    signed: &SignedToken,
    issuer: &IssuerPublic,
) -> Option<Credit> {
    if !verify_dleq(&issuer.0, &blinded.0, &signed.evaluated, &signed.proof) {
        return None;
    }
    // Unblind: N = blind⁻¹ · Z = blind⁻¹ · k · (blind · H(x)) = k · H(x).
    let output = signed.evaluated * request.blind.invert();
    Some(Credit {
        input: request.input,
        output,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A tiny deterministic rand_core 0.6 RNG for reproducible tests.
    struct TestRng([u8; 32], u64);
    impl TestRng {
        fn new(tag: &str) -> Self {
            let mut s = [0u8; 32];
            hash_xof("test-rng", tag.as_bytes(), &mut s);
            Self(s, 0)
        }
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut input = self.0.to_vec();
            input.extend_from_slice(&self.1.to_le_bytes());
            self.1 += 1;
            hash_xof("test-rng-block", &input, dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    #[test]
    fn a_credit_issues_finalizes_and_redeems() {
        let mut rng = TestRng::new("a");
        let mut issuer = CreditIssuer::from_seed(b"relay-issuer");
        let (req, blinded) = request(&mut rng);
        let signed = issuer.issue(&blinded);
        let credit = finalize(req, &blinded, &signed, &issuer.public()).unwrap();
        assert!(issuer.verify(&credit));
        assert_eq!(issuer.redeem(&credit), Redemption::Accepted);
    }

    #[test]
    fn a_double_spend_is_rejected() {
        let mut rng = TestRng::new("b");
        let mut issuer = CreditIssuer::from_seed(b"issuer");
        let (req, blinded) = request(&mut rng);
        let signed = issuer.issue(&blinded);
        let credit = finalize(req, &blinded, &signed, &issuer.public()).unwrap();
        assert_eq!(issuer.redeem(&credit), Redemption::Accepted);
        assert_eq!(issuer.redeem(&credit), Redemption::DoubleSpent);
    }

    #[test]
    fn a_forged_credit_is_invalid() {
        let mut issuer = CreditIssuer::from_seed(b"issuer");
        // A credit with a random output the issuer never signed.
        let forged = Credit {
            input: [7u8; INPUT_LEN],
            output: RISTRETTO_BASEPOINT_POINT,
        };
        assert_eq!(issuer.redeem(&forged), Redemption::Invalid);
    }

    #[test]
    fn the_dleq_proof_is_deterministic_so_a_bad_rng_cannot_leak_the_key() {
        // The synthetic nonce makes the DLEQ proof deterministic: the same statement always yields the
        // identical proof, so there is no caller RNG to weaken (B4). Two proofs of the same transcript are
        // byte-equal, and a different transcript uses a different nonce — no reuse across statements.
        let k = Scalar::from(12_345u64);
        let g = RISTRETTO_BASEPOINT_POINT;
        let pk = k * g;
        let b = hash_to_curve(b"a-blinded-input");
        let z = k * b;
        let p1 = prove_dleq(k, &pk, &b, &z);
        let p2 = prove_dleq(k, &pk, &b, &z);
        assert_eq!(p1.c.as_bytes(), p2.c.as_bytes(), "same statement → same challenge");
        assert_eq!(p1.z.as_bytes(), p2.z.as_bytes(), "same statement → same response");
        assert!(verify_dleq(&pk, &b, &z, &p1), "and the deterministic proof still verifies");

        let b2 = hash_to_curve(b"a-different-input");
        let z2 = k * b2;
        let p3 = prove_dleq(k, &pk, &b2, &z2);
        assert_ne!(p1.z.as_bytes(), p3.z.as_bytes(), "a different statement uses a different nonce");
    }

    #[test]
    fn a_wrong_key_issuance_is_caught_by_the_dleq_proof() {
        let mut rng = TestRng::new("c");
        let honest = CreditIssuer::from_seed(b"honest");
        let cheat = CreditIssuer::from_seed(b"cheat");
        let (req, blinded) = request(&mut rng);
        // The cheat evaluates with its own key but we verify against the honest public key.
        let signed = cheat.issue(&blinded);
        assert!(finalize(req, &blinded, &signed, &honest.public()).is_none());
    }

    #[test]
    fn the_output_is_deterministic_per_input_but_issuance_is_blinded() {
        // Same input ⇒ same credit output (a PRF), yet two blinds give different blinded points, so
        // the issuer cannot correlate issuance to redemption.
        let mut rng = TestRng::new("d");
        let issuer = CreditIssuer::from_seed(b"issuer");
        let input = [3u8; INPUT_LEN];
        let mk = |blind: Scalar| {
            let req = TokenRequest { input, blind };
            let blinded = BlindedToken(blind * hash_to_curve(&input));
            let signed = issuer.issue(&blinded);
            (
                blinded,
                finalize(req, &blinded, &signed, &issuer.public()).unwrap(),
            )
        };
        let (b1, c1) = mk(Scalar::random(&mut rng));
        let (b2, c2) = mk(Scalar::random(&mut rng));
        assert_ne!(
            b1.to_bytes(),
            b2.to_bytes(),
            "blinded points differ (unlinkable)"
        );
        assert_eq!(
            c1.output, c2.output,
            "PRF output is deterministic per input"
        );
    }

    #[test]
    fn credits_round_trip_through_bytes() {
        let mut rng = TestRng::new("f");
        let mut issuer = CreditIssuer::from_seed(b"issuer");
        let (req, blinded) = request(&mut rng);
        let signed = issuer.issue(&blinded);
        let credit = finalize(req, &blinded, &signed, &issuer.public()).unwrap();
        let wire = credit.to_bytes();
        let recovered = Credit::from_bytes(&wire).unwrap();
        assert_eq!(issuer.redeem(&recovered), Redemption::Accepted);
        assert!(BlindedToken::from_bytes(&blinded.to_bytes()).is_some());
    }
}
