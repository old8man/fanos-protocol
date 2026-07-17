//! Interactive multi-dealer distributed key generation (DKG) over Feldman VSS (spec §L6).
//!
//! Threshold hosting needs a key **no single party ever holds**. This is the `n`-party DKG that
//! composes the verified single-dealer VSS in [`crate::vss`]: every participant deals a random
//! secret, each participant verifies the shares it receives against the dealers' public
//! commitments, a dealer whose share fails is **disqualified**, and the survivors are aggregated —
//!
//! * each participant's **final share** is the sum of the shares it accepted, a point on the
//!   aggregate polynomial `f(x) = Σ_i f_i(x)`;
//! * the **joint public key** is `Y = Σ_i C_{i,0} = (Σ_i secret_i)·G`;
//! * the **joint secret** `x = Σ_i secret_i` is never assembled, yet any `t` final shares
//!   reconstruct it (Lagrange), and `x·G = Y`.
//!
//! No party learns `x`; a minority of cheaters is caught and excluded. Interactivity (the round of
//! exchanging dealings and complaints) is modelled here as passing [`Dealing`]s between
//! [`Participant`]s — the same logic a transport would carry.

use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::vss::{self, VssCommitment, VssShare};

/// One dealer's contribution: its public commitment and the private share for each participant.
#[derive(Clone, Debug)]
pub struct Dealing {
    commitment: VssCommitment,
    shares: Vec<VssShare>,
}

impl Dealing {
    /// The dealer's public commitment (used to verify each received share).
    #[must_use]
    pub fn commitment(&self) -> &VssCommitment {
        &self.commitment
    }

    /// The share addressed to participant `index`.
    #[must_use]
    pub fn share_for(&self, index: u8) -> Option<&VssShare> {
        self.shares.iter().find(|s| s.index() == index)
    }

    #[cfg(test)]
    fn corrupt_share_for(&mut self, index: u8) {
        if let Some(share) = self.shares.iter_mut().find(|s| s.index() == index) {
            share.corrupt();
        }
    }
}

/// Deal one participant's contribution — a Feldman VSS of a fresh secret to `participants` holders.
#[must_use]
pub fn deal<R: RngCore + CryptoRng>(
    secret: &[u8; 32],
    threshold: usize,
    participants: usize,
    rng: &mut R,
) -> Option<Dealing> {
    let (shares, commitment) = vss::deal(secret, threshold, participants, rng)?;
    Some(Dealing { commitment, shares })
}

/// A participant aggregating the verified shares it receives into its final key share.
#[derive(Clone, Copy, Debug)]
pub struct Participant {
    index: u8,
    accumulator: Scalar,
    accepted: usize,
}

impl Participant {
    /// A participant with holder index `index` (`1..=n`).
    #[must_use]
    pub fn new(index: u8) -> Self {
        Self {
            index,
            accumulator: Scalar::ZERO,
            accepted: 0,
        }
    }

    /// Ingest a dealer's [`Dealing`]: verify this participant's share against the commitment; if
    /// valid, fold it into the running final share and return `true`. A cheating dealer — one whose
    /// share is inconsistent with its public commitment — is rejected (`false`) and contributes
    /// nothing (disqualification).
    pub fn ingest(&mut self, dealing: &Dealing) -> bool {
        let Some(share) = dealing.share_for(self.index) else {
            return false;
        };
        if !vss::verify_share(share, dealing.commitment()) {
            return false;
        }
        self.accumulator += share.value();
        self.accepted += 1;
        true
    }

    /// How many dealings this participant accepted.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.accepted
    }

    /// This participant's final share of the joint secret (a point on the aggregate polynomial).
    #[must_use]
    pub fn final_share(&self) -> VssShare {
        VssShare::from_parts(self.index, self.accumulator)
    }
}

/// The joint public key `Y = Σ C_0` over the qualified dealings.
#[must_use]
pub fn joint_public_key(qualified: &[&Dealing]) -> [u8; 32] {
    let mut y = RistrettoPoint::identity();
    for dealing in qualified {
        y += dealing.commitment().commitment_point();
    }
    y.compress().to_bytes()
}

/// The public key `secret·G` of a scalar secret — used to check that a reconstructed joint secret
/// matches the joint public key.
#[must_use]
pub fn public_of_secret(secret: &[u8; 32]) -> [u8; 32] {
    (Scalar::from_bytes_mod_order(*secret) * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes()
}

/// Reconstruct the joint secret from any `t` participants' final shares (Lagrange at `x = 0`).
#[must_use]
pub fn reconstruct_joint_secret(final_shares: &[VssShare]) -> Option<[u8; 32]> {
    vss::reconstruct(final_shares)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::vss::DeterministicRng;
    use fanos_crypto::hash::hash_xof;

    fn secret(tag: &str) -> [u8; 32] {
        let mut s = [0u8; 32];
        hash_xof("dkg-secret", tag.as_bytes(), &mut s);
        s
    }

    fn sum_of(secrets: &[[u8; 32]]) -> [u8; 32] {
        secrets
            .iter()
            .fold(Scalar::ZERO, |acc, s| {
                acc + Scalar::from_bytes_mod_order(*s)
            })
            .to_bytes()
    }

    #[test]
    fn a_three_party_dkg_agrees_on_a_joint_key_no_party_holds() {
        let (t, n) = (2usize, 3usize);
        let secrets = [secret("a"), secret("b"), secret("c")];
        let dealings: Vec<Dealing> = (0..n)
            .map(|i| deal(&secrets[i], t, n, &mut DeterministicRng::new(&[i as u8])).unwrap())
            .collect();

        // Every participant verifies and accepts every honest dealing.
        let mut participants: Vec<Participant> = (1..=n as u8).map(Participant::new).collect();
        for p in &mut participants {
            for d in &dealings {
                assert!(p.ingest(d));
            }
            assert_eq!(p.accepted(), n);
        }

        // The joint key, and the joint secret reconstructed from only t final shares, agree — and
        // the secret is exactly Σ secret_i, which no single party ever assembled.
        let refs: Vec<&Dealing> = dealings.iter().collect();
        let joint_pub = joint_public_key(&refs);
        let finals: Vec<VssShare> = participants
            .iter()
            .take(t)
            .map(Participant::final_share)
            .collect();
        let joint_secret = reconstruct_joint_secret(&finals).unwrap();
        assert_eq!(public_of_secret(&joint_secret), joint_pub);
        assert_eq!(joint_secret, sum_of(&secrets));
    }

    #[test]
    fn any_t_of_n_final_shares_reconstruct_the_same_joint_secret() {
        let (t, n) = (3usize, 5usize);
        let secrets: Vec<[u8; 32]> = (0..n).map(|i| secret(&i.to_string())).collect();
        let dealings: Vec<Dealing> = (0..n)
            .map(|i| deal(&secrets[i], t, n, &mut DeterministicRng::new(&[9, i as u8])).unwrap())
            .collect();
        let mut participants: Vec<Participant> = (1..=n as u8).map(Participant::new).collect();
        for p in &mut participants {
            for d in &dealings {
                p.ingest(d);
            }
        }
        let expected = sum_of(&secrets);
        for subset in [[0, 1, 2], [1, 2, 4], [0, 3, 4]] {
            let finals: Vec<VssShare> = subset
                .iter()
                .map(|&j| participants[j].final_share())
                .collect();
            assert_eq!(reconstruct_joint_secret(&finals), Some(expected));
        }
    }

    #[test]
    fn a_cheating_dealer_is_disqualified_and_the_survivors_still_agree() {
        let (t, n) = (2usize, 3usize);
        let secrets = [secret("x"), secret("y"), secret("z")];
        let mut dealings: Vec<Dealing> = (0..n)
            .map(|i| deal(&secrets[i], t, n, &mut DeterministicRng::new(&[7, i as u8])).unwrap())
            .collect();
        // Dealer 0 sends participant 2 a share inconsistent with its published commitment.
        dealings[0].corrupt_share_for(2);

        // Participant 2 rejects dealer 0 but accepts the two honest dealers.
        let mut p2 = Participant::new(2);
        assert!(!p2.ingest(&dealings[0]), "the cheat is caught");
        assert!(p2.ingest(&dealings[1]));
        assert!(p2.ingest(&dealings[2]));
        assert_eq!(p2.accepted(), 2, "only the honest dealers qualified");

        // The qualified set (dealers 1,2) defines the joint key everyone agrees on.
        let qualified = [&dealings[1], &dealings[2]];
        let mut p1 = Participant::new(1);
        let mut p3 = Participant::new(3);
        for d in qualified {
            p1.ingest(d);
            p3.ingest(d);
        }
        let joint_pub = joint_public_key(&qualified);
        let finals = [p1.final_share(), p2.final_share()];
        let joint_secret = reconstruct_joint_secret(&finals).unwrap();
        assert_eq!(public_of_secret(&joint_secret), joint_pub);
        assert_eq!(joint_secret, sum_of(&[secrets[1], secrets[2]]));
    }
}
