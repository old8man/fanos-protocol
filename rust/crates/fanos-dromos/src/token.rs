//! An **authenticated token ledger** — the transparent value tier of the platform: public balances that move
//! only under a valid post-quantum signature from the account owner. This is the payment substrate the
//! reference `fanos_taxis::Accounts` deliberately omits (it checks nonce and balance but not authorisation, a
//! simplification fine for a consensus demo but not for real value or for *paying* for things like names). It
//! is what a currency-bought name registration debits, what staking bonds, and — with the shield/unshield
//! bridge — what a shielded balance settles into to pay a public fee.
//!
//! An account id is the hash of its owner's hybrid verifying key ([`account_id`]), so funds are bound to a key:
//! only a signature under that key moves them. A [`SignedTransfer`] carries the transfer, the owner's public
//! key, and the signature; [`TokenLedger::apply`] verifies all three (key-binds-account, signature-valid,
//! nonce-fresh, funds-sufficient) before moving anything.

use std::collections::BTreeMap;

use fanos_pqcrypto::sig::{HYBRID_SIG_LEN, HYBRID_VK_LEN};
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};
use fanos_primitives::hash_labeled;

/// Domain-separation label for deriving an account id from a verifying key.
const ACCOUNT_LABEL: &str = "FANOS-dromos-v1/account-id";
/// Domain-separation label for the signed content of a transfer.
const TRANSFER_LABEL: &str = "FANOS-dromos-v1/transfer";
/// Domain-separation label for the token-ledger state root.
const ROOT_LABEL: &str = "FANOS-dromos-v1/token-root";

/// The account id owned by `verifier`: `H("account-id", verifier)`. Binds funds to a public key — only a
/// signature under it can spend them.
#[must_use]
pub fn account_id(verifier: &HybridVerifier) -> [u8; 32] {
    hash_labeled(ACCOUNT_LABEL, &verifier.encode())
}

/// A transparent value transfer: move `amount` from `from` to `to`, replay-protected by the sender's `nonce`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transfer {
    /// The sender's account id (must equal `account_id(signer's key)`).
    pub from: [u8; 32],
    /// The recipient's account id.
    pub to: [u8; 32],
    /// The amount to move.
    pub amount: u64,
    /// The sender's expected current nonce (replay protection).
    pub nonce: u64,
}

impl Transfer {
    /// The signed content: `label ‖ from ‖ to ‖ amount ‖ nonce`.
    #[must_use]
    fn signable(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRANSFER_LABEL.len() + 80);
        out.extend_from_slice(TRANSFER_LABEL.as_bytes());
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }
}

/// A transfer authorised by its sender's hybrid-PQ signature. `Clone` only (mirroring [`HybridVerifier`]'s
/// key-handling convention); compare or anchor through [`to_bytes`](Self::to_bytes).
#[derive(Clone)]
pub struct SignedTransfer {
    /// The transfer.
    pub transfer: Transfer,
    /// The sender's public verifying key (hashes to `transfer.from`).
    pub from_key: HybridVerifier,
    /// The signature over [`Transfer::signable`], `HYBRID_SIG_LEN` bytes.
    sig: Vec<u8>,
}

impl SignedTransfer {
    /// The fixed serialized length: `from(32) ‖ to(32) ‖ amount(8) ‖ nonce(8) ‖ key(VK) ‖ sig(SIG)`.
    pub const WIRE_LEN: usize = 80 + HYBRID_VK_LEN + HYBRID_SIG_LEN;

    /// Sign `transfer` under `signer`, whose public key `from_key` must hash to `transfer.from` (the caller's
    /// responsibility; a mismatch produces a transfer that will fail [`verify`](Self::verify)).
    #[must_use]
    pub fn sign(transfer: Transfer, signer: &HybridSigSecret, from_key: HybridVerifier) -> Self {
        let sig = signer.sign(&transfer.signable()).to_bytes();
        Self { transfer, from_key, sig }
    }

    /// Whether this transfer is authorised: the public key binds to the `from` account **and** the signature
    /// verifies under it.
    #[must_use]
    pub fn verify(&self) -> bool {
        if account_id(&self.from_key) != self.transfer.from {
            return false;
        }
        let Some(sig) = HybridSignature::from_bytes(&self.sig) else {
            return false;
        };
        self.from_key.verify(&self.transfer.signable(), &sig)
    }

    /// Canonical bytes: `from(32) ‖ to(32) ‖ amount(8) ‖ nonce(8) ‖ from_key(VK) ‖ sig(SIG)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80 + HYBRID_VK_LEN + HYBRID_SIG_LEN);
        out.extend_from_slice(&self.transfer.from);
        out.extend_from_slice(&self.transfer.to);
        out.extend_from_slice(&self.transfer.amount.to_le_bytes());
        out.extend_from_slice(&self.transfer.nonce.to_le_bytes());
        out.extend_from_slice(&self.from_key.encode());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 80 + HYBRID_VK_LEN + HYBRID_SIG_LEN {
            return None;
        }
        let from = bytes.get(..32)?.try_into().ok()?;
        let to = bytes.get(32..64)?.try_into().ok()?;
        let amount = u64::from_le_bytes(bytes.get(64..72)?.try_into().ok()?);
        let nonce = u64::from_le_bytes(bytes.get(72..80)?.try_into().ok()?);
        let from_key = HybridVerifier::decode(bytes.get(80..80 + HYBRID_VK_LEN)?)?;
        let sig = bytes.get(80 + HYBRID_VK_LEN..)?.to_vec();
        Some(Self { transfer: Transfer { from, to, amount, nonce }, from_key, sig })
    }
}

/// Why a transfer was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenError {
    /// The key does not bind to the `from` account, or the signature is invalid.
    Unauthorized,
    /// The nonce does not match the sender's current one (replay or out-of-order).
    BadNonce,
    /// The sender's balance is below the amount.
    InsufficientFunds,
}

/// The authenticated transparent balance ledger.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct TokenLedger {
    balances: BTreeMap<[u8; 32], u64>,
    nonces: BTreeMap<[u8; 32], u64>,
}

impl TokenLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Credit `amount` to `account` with no authorisation — issuance (a genesis allocation or a block reward),
    /// gated by the consensus/monetary policy, not by a signature.
    pub fn credit(&mut self, account: [u8; 32], amount: u64) {
        let bal = self.balances.entry(account).or_insert(0);
        *bal = bal.saturating_add(amount);
    }

    /// The balance of `account`.
    #[must_use]
    pub fn balance(&self, account: &[u8; 32]) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    /// The current nonce of `account`.
    #[must_use]
    pub fn nonce(&self, account: &[u8; 32]) -> u64 {
        self.nonces.get(account).copied().unwrap_or(0)
    }

    /// Apply an authorised transfer, or reject it with the reason. Atomic: on any error nothing changes.
    pub fn apply(&mut self, st: &SignedTransfer) -> Result<(), TokenError> {
        if !st.verify() {
            return Err(TokenError::Unauthorized);
        }
        let t = &st.transfer;
        if self.nonce(&t.from) != t.nonce {
            return Err(TokenError::BadNonce);
        }
        if self.balance(&t.from) < t.amount {
            return Err(TokenError::InsufficientFunds);
        }
        // Debit (cannot underflow — checked), credit (saturates), bump the nonce.
        if let Some(bal) = self.balances.get_mut(&t.from) {
            *bal -= t.amount;
        }
        self.credit(t.to, t.amount);
        *self.nonces.entry(t.from).or_insert(0) += 1;
        Ok(())
    }

    /// A binding commitment to the whole ledger — the sorted `(account, balance, nonce)` triples, hashed.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut accounts: Vec<[u8; 32]> = self.balances.keys().copied().collect();
        for k in self.nonces.keys() {
            if !accounts.contains(k) {
                accounts.push(*k);
            }
        }
        accounts.sort_unstable();
        let mut buf = Vec::with_capacity(accounts.len() * 48);
        for a in &accounts {
            buf.extend_from_slice(a);
            buf.extend_from_slice(&self.balance(a).to_le_bytes());
            buf.extend_from_slice(&self.nonce(a).to_le_bytes());
        }
        hash_labeled(ROOT_LABEL, &buf)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;

    /// A funded account: its signing key, verifying key, id, and a ledger crediting it `funds`.
    fn account(tag: u8) -> (HybridSigSecret, HybridVerifier, [u8; 32]) {
        let mut rng = SeedRng::from_seed(&[0xA0, tag]);
        let (signer, verifier) = HybridSigSecret::generate(&mut rng);
        let id = account_id(&verifier);
        (signer, verifier, id)
    }

    #[test]
    fn an_authorized_transfer_moves_funds_and_bumps_the_nonce() {
        let (alice_sk, alice_vk, alice) = account(1);
        let (_bob_sk, _bob_vk, bob) = account(2);
        let mut ledger = TokenLedger::new();
        ledger.credit(alice, 1000);

        let t = Transfer { from: alice, to: bob, amount: 300, nonce: 0 };
        let st = SignedTransfer::sign(t, &alice_sk, alice_vk);
        assert_eq!(ledger.apply(&st), Ok(()));
        assert_eq!(ledger.balance(&alice), 700);
        assert_eq!(ledger.balance(&bob), 300);
        assert_eq!(ledger.nonce(&alice), 1);
    }

    #[test]
    fn a_transfer_you_did_not_sign_is_unauthorized() {
        let (_alice_sk, _alice_vk, alice) = account(1);
        let (mallory_sk, mallory_vk, _mallory) = account(9);
        let (_bob_sk, _bob_vk, bob) = account(2);
        let mut ledger = TokenLedger::new();
        ledger.credit(alice, 1000);

        // Mallory tries to move Alice's funds, signing with her own key (which does not bind to `alice`).
        let t = Transfer { from: alice, to: bob, amount: 300, nonce: 0 };
        let forged = SignedTransfer::sign(t, &mallory_sk, mallory_vk);
        assert_eq!(ledger.apply(&forged), Err(TokenError::Unauthorized), "you cannot spend an account you don't own");
        assert_eq!(ledger.balance(&alice), 1000, "Alice's funds are untouched");
    }

    #[test]
    fn nonce_and_balance_are_enforced() {
        let (alice_sk, alice_vk, alice) = account(1);
        let (_b, _bv, bob) = account(2);
        let mut ledger = TokenLedger::new();
        ledger.credit(alice, 100);
        // Wrong nonce.
        let bad_nonce = SignedTransfer::sign(Transfer { from: alice, to: bob, amount: 10, nonce: 5 }, &alice_sk, alice_vk.clone());
        assert_eq!(ledger.apply(&bad_nonce), Err(TokenError::BadNonce));
        // Overspend.
        let overspend = SignedTransfer::sign(Transfer { from: alice, to: bob, amount: 1000, nonce: 0 }, &alice_sk, alice_vk.clone());
        assert_eq!(ledger.apply(&overspend), Err(TokenError::InsufficientFunds));
        // A replay of a good transfer is caught by the nonce.
        let good = SignedTransfer::sign(Transfer { from: alice, to: bob, amount: 10, nonce: 0 }, &alice_sk, alice_vk);
        assert_eq!(ledger.apply(&good), Ok(()));
        assert_eq!(ledger.apply(&good), Err(TokenError::BadNonce), "a replay is rejected");
    }

    #[test]
    fn a_signed_transfer_round_trips_and_a_tamper_is_rejected() {
        let (alice_sk, alice_vk, alice) = account(1);
        let (_b, _bv, bob) = account(2);
        let st = SignedTransfer::sign(Transfer { from: alice, to: bob, amount: 42, nonce: 0 }, &alice_sk, alice_vk);
        let bytes = st.to_bytes();
        let decoded = SignedTransfer::from_bytes(&bytes).expect("round-trips");
        assert_eq!(decoded.to_bytes(), bytes, "the decoded transfer re-encodes identically");
        assert!(decoded.verify(), "the decoded transfer still verifies");
        // Flip a byte of the amount → the signature no longer covers it.
        let mut tampered = bytes.clone();
        tampered[64] ^= 0xFF;
        assert!(!SignedTransfer::from_bytes(&tampered).unwrap().verify(), "a tampered transfer fails verification");
    }

    #[test]
    fn the_state_root_is_deterministic_and_binds_balances_and_nonces() {
        let (alice_sk, alice_vk, alice) = account(1);
        let (_b, _bv, bob) = account(2);
        let mut a = TokenLedger::new();
        a.credit(alice, 1000);
        let b = a.clone();
        assert_eq!(a.state_root(), b.state_root(), "identical ledgers share a root");
        let st = SignedTransfer::sign(Transfer { from: alice, to: bob, amount: 100, nonce: 0 }, &alice_sk, alice_vk);
        a.apply(&st).unwrap();
        assert_ne!(a.state_root(), b.state_root(), "a transfer changes the root");
    }
}
