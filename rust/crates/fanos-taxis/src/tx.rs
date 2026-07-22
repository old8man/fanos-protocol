//! Transactions and the threshold-**sealed** transaction — the anti-MEV unit (spec §10.1,
//! `docs/design-taxis.md` §5).
//!
//! A [`Transaction`] is opaque application bytes; TAXIS orders them but never interprets them (the ABCI-style
//! separation — execution lives in [`crate::state`]). Its anti-MEV form is a [`SealedTx`]: the transaction is
//! **threshold-KEM-sealed** to a beacon-chosen line committee via the very [`ThresholdSealed`] primitive every
//! NYX onion layer uses — `t`-of-`(q+1)` Shamir shares, each sealed under a fresh per-member hybrid KEM
//! (`X25519 ‖ ML-KEM-768`). The mempool holds only the ciphertext and its [`TxCommit`]; a proposer orders by
//! commitment, provably **blind** to contents, so it cannot front-run or sandwich. Only after the block that
//! fixes the order is finalized do `t` committee members release their share openings, and anyone
//! reconstructs the plaintext. No new crypto — this is the audited threshold seal, pointed at the mempool.

use alloc::vec::Vec;

use fanos_aphantos::{ThresholdError, ThresholdSealed};
use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};
use fanos_primitives::shamir::Share;
use fanos_primitives::{Epoch, hash::hash_xof, hash_labeled};

/// The 32-byte commitment a proposer orders by — a binding hash of the sealed ciphertext, bound to its
/// sealing epoch and committee line so it cannot be replayed into another. Computable by anyone holding the
/// [`SealedTx`] **without** opening it (the blind-ordering property).
pub type TxCommit = [u8; 32];

const KEY_LABEL: &str = "FANOS-v1/taxis-tx-key";
const NONCE_LABEL: &str = "FANOS-v1/taxis-tx-nonce";
const RND_LABEL: &str = "FANOS-v1/taxis-tx-sharing";
const KEM_LABEL: &str = "FANOS-v1/taxis-tx-kem";
const COMMIT_LABEL: &str = "FANOS-v1/taxis-tx-commit";

/// A cleartext transaction — opaque application bytes the consensus layer orders but does not interpret.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    /// The application payload (an account transfer, a contract call, …) — meaning is the state machine's.
    pub payload: Vec<u8>,
}

impl Transaction {
    /// A transaction from raw application bytes.
    #[must_use]
    pub fn new(payload: impl Into<Vec<u8>>) -> Self {
        Self { payload: payload.into() }
    }
}

/// A threshold-sealed transaction: the [`ThresholdSealed`] ciphertext plus the epoch and line it is sealed
/// to. Lives in the mempool and the block payload; its contents are recoverable only by `t`-of-`(q+1)`
/// committee members, and only they choose to release their shares (post-finality).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedTx {
    /// The epoch this transaction was sealed in (binds its committee and its commitment).
    pub epoch: Epoch,
    /// The Fano line index `0..7` of the sealing committee (`crate::committee::sealing_line`).
    pub line: u8,
    /// The threshold-sealed ciphertext of the transaction payload.
    sealed: ThresholdSealed,
}

impl SealedTx {
    /// Seal `tx` to the `member_keys` of committee `line` in `epoch`, openable by any `threshold` of them.
    /// All AEAD/sharing/KEM randomness is derived deterministically from `seed` (a real CSPRNG draw in
    /// production; a fixed seed under the deterministic simulator), exactly as `fanos_aphantos::seal_onion`
    /// does — so sealing needs no ambient entropy and is reproducible in tests.
    ///
    /// # Errors
    /// [`ThresholdError`] if the sharing parameters are invalid (e.g. `threshold > member_keys.len()`), a
    /// member key is non-contributory, or AEAD fails.
    pub fn seal(
        tx: &Transaction,
        epoch: Epoch,
        line: u8,
        member_keys: &[&HybridKemPublic],
        threshold: u8,
        seed: &[u8],
    ) -> Result<Self, ThresholdError> {
        let key = hash_labeled(KEY_LABEL, seed);
        let nonce_full = hash_labeled(NONCE_LABEL, seed);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_full.get(..12).ok_or(ThresholdError::Malformed)?);
        // (threshold − 1) · 32 bytes of sharing-polynomial randomness.
        let mut key_rnd = alloc::vec![0u8; usize::from(threshold.saturating_sub(1)) * 32];
        hash_xof(RND_LABEL, seed, &mut key_rnd);
        let kem_seed = hash_labeled(KEM_LABEL, seed);
        let sealed = ThresholdSealed::seal(
            &tx.payload,
            &key,
            &nonce,
            threshold,
            member_keys,
            &key_rnd,
            &kem_seed,
        )?;
        Ok(Self { epoch, line, sealed })
    }

    /// The transaction commitment a proposer orders by: `H(sealed_ciphertext ‖ epoch ‖ line)`. Binding to
    /// the ciphertext (so ordering fixes *which* transaction) and to `(epoch, line)` (so a ciphertext cannot
    /// be replayed under a different committee). Computable without opening — the blind-ordering guarantee.
    #[must_use]
    pub fn commit(&self) -> TxCommit {
        let mut buf = self.sealed.to_bytes();
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.push(self.line);
        hash_labeled(COMMIT_LABEL, &buf)
    }

    /// Committee member `i`'s Shamir share of the sealing key, recovered from its KEM-sealed slot with its
    /// own secret — the opening a member releases *after* the block that orders this transaction finalizes.
    /// `None` if `i` is out of range or the slot is not this member's (no other member's share is exposed).
    #[must_use]
    pub fn member_share(&self, i: usize, member_secret: &HybridKemSecret) -> Option<Share> {
        self.sealed.member_share(i, member_secret)
    }

    /// Reconstruct the cleartext [`Transaction`] from `threshold` (or more) member share openings. With
    /// fewer than `threshold` the reconstructed key is wrong and AEAD authentication fails — the transaction
    /// stays hidden (the zero-knowledge-below-threshold guarantee).
    ///
    /// # Errors
    /// [`ThresholdError::Aead`] below threshold or on tamper; [`ThresholdError::Sharing`] on bad shares.
    pub fn open(&self, shares: &[Share]) -> Result<Transaction, ThresholdError> {
        let payload = self.sealed.open(shares)?;
        Ok(Transaction { payload })
    }

    /// The number of committee members this transaction is sealed to (`q + 1`).
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.sealed.member_count()
    }

    /// Canonical bytes: `epoch(8) ‖ line(1) ‖ sealed`. The `sealed` tail is self-delimiting
    /// ([`ThresholdSealed::from_bytes`]), so no length prefix is needed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.push(self.line);
        out.extend_from_slice(&self.sealed.to_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let epoch = Epoch::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let line = *bytes.get(8)?;
        let sealed = ThresholdSealed::from_bytes(bytes.get(9..)?)?;
        Some(Self { epoch, line, sealed })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;

    /// A committee of `n` members' hybrid KEM keypairs (secret, public), from a deterministic seed.
    fn committee(n: usize, tag: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n).map(|i| {
            let mut rng = SeedRng::from_seed(&[tag, i as u8]);
            HybridKemSecret::generate(&mut rng)
        }).collect()
    }

    #[test]
    fn a_threshold_of_members_opens_the_tx_but_fewer_cannot() {
        // The anti-MEV core: seal to a 3-member line at threshold 2; any 2 open, 1 cannot.
        let kps = committee(3, 1);
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let tx = Transaction::new(b"transfer 10 to bob".to_vec());
        let sealed = SealedTx::seal(&tx, Epoch::new(4), 5, &pubs, 2, b"tx-seed-1").unwrap();
        assert_eq!(sealed.member_count(), 3);

        // Members 0 and 2 release their openings after finality.
        let s0 = sealed.member_share(0, &kps[0].0).unwrap();
        let s2 = sealed.member_share(2, &kps[2].0).unwrap();
        assert_eq!(sealed.open(&[s0.clone(), s2.clone()]).unwrap(), tx, "2-of-3 reconstructs the tx");

        // A single opening cannot: below threshold, AEAD auth fails — the tx stays hidden.
        assert!(sealed.open(&[s0]).is_err(), "1-of-3 must not reveal the transaction");
    }

    #[test]
    fn the_commitment_is_blind_and_binding() {
        // The proposer can compute the commitment (to order by) WITHOUT any member secret — blind ordering.
        let kps = committee(3, 2);
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let tx = Transaction::new(b"a".to_vec());
        let sealed = SealedTx::seal(&tx, Epoch::new(1), 0, &pubs, 2, b"seed-a").unwrap();
        // Deterministic + binding to the ciphertext.
        assert_eq!(sealed.commit(), sealed.commit());
        // A different transaction (different seed → different ciphertext) commits differently.
        let other = SealedTx::seal(&Transaction::new(b"b".to_vec()), Epoch::new(1), 0, &pubs, 2, b"seed-b").unwrap();
        assert_ne!(sealed.commit(), other.commit());
        // The SAME ciphertext under a different epoch commits differently (no cross-epoch replay).
        let same_ct_other_epoch = SealedTx { epoch: Epoch::new(2), ..sealed.clone() };
        assert_ne!(sealed.commit(), same_ct_other_epoch.commit());
    }

    #[test]
    fn a_wrong_member_secret_yields_no_share() {
        let kps = committee(3, 3);
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let sealed = SealedTx::seal(&Transaction::new(b"x".to_vec()), Epoch::new(0), 1, &pubs, 2, b"s").unwrap();
        // Member 0's slot cannot be opened with member 1's secret.
        assert!(sealed.member_share(0, &kps[1].0).is_none());
    }

    #[test]
    fn sealed_tx_round_trips_through_bytes() {
        let kps = committee(3, 4);
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let sealed = SealedTx::seal(&Transaction::new(b"round-trip".to_vec()), Epoch::new(9), 6, &pubs, 2, b"rt").unwrap();
        let decoded = SealedTx::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(decoded, sealed);
        assert_eq!(decoded.commit(), sealed.commit(), "the commitment survives serialization");
    }
}
