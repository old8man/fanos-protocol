//! # fanos-incentives — L7 anonymous relay credits (VOPRF blind tokens)
//!
//! Staking binds identity to capital, so paying for relay service would deanonymise. FANOS uses
//! **anonymous credits** instead (spec §L7): a Privacy-Pass-class **verifiable oblivious PRF**
//! (VOPRF, RFC 9497/9578) on ristretto255. A client blinds a random input, the issuer evaluates the
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

use fanos_crypto::hash::hash_xof;

/// The input length of a credit (a random nonce chosen by the client).
pub const INPUT_LEN: usize = 32;

const H2C_LABEL: &str = "FANOS-v1/credit-h2c";
const DLEQ_LABEL: &str = "FANOS-v1/credit-dleq";

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

fn prove_dleq<R: RngCore + CryptoRng>(
    k: Scalar,
    pk: &RistrettoPoint,
    b: &RistrettoPoint,
    z_point: &RistrettoPoint,
    rng: &mut R,
) -> Dleq {
    let g = RISTRETTO_BASEPOINT_POINT;
    let s = Scalar::random(rng);
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
    /// issuer learns nothing about the underlying input.
    pub fn issue<R: RngCore + CryptoRng>(
        &self,
        blinded: &BlindedToken,
        rng: &mut R,
    ) -> SignedToken {
        let evaluated = self.k * blinded.0;
        let proof = prove_dleq(self.k, &self.public, &blinded.0, &evaluated, rng);
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
        let signed = issuer.issue(&blinded, &mut rng);
        let credit = finalize(req, &blinded, &signed, &issuer.public()).unwrap();
        assert!(issuer.verify(&credit));
        assert_eq!(issuer.redeem(&credit), Redemption::Accepted);
    }

    #[test]
    fn a_double_spend_is_rejected() {
        let mut rng = TestRng::new("b");
        let mut issuer = CreditIssuer::from_seed(b"issuer");
        let (req, blinded) = request(&mut rng);
        let signed = issuer.issue(&blinded, &mut rng);
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
    fn a_wrong_key_issuance_is_caught_by_the_dleq_proof() {
        let mut rng = TestRng::new("c");
        let honest = CreditIssuer::from_seed(b"honest");
        let cheat = CreditIssuer::from_seed(b"cheat");
        let (req, blinded) = request(&mut rng);
        // The cheat evaluates with its own key but we verify against the honest public key.
        let signed = cheat.issue(&blinded, &mut rng);
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
            let signed = issuer.issue(&blinded, &mut TestRng::new("e"));
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
        let signed = issuer.issue(&blinded, &mut rng);
        let credit = finalize(req, &blinded, &signed, &issuer.public()).unwrap();
        let wire = credit.to_bytes();
        let recovered = Credit::from_bytes(&wire).unwrap();
        assert_eq!(issuer.redeem(&recovered), Redemption::Accepted);
        assert!(BlindedToken::from_bytes(&blinded.to_bytes()).is_some());
    }
}
