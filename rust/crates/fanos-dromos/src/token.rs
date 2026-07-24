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

use std::collections::{BTreeMap, BTreeSet};

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

/// The domain label for a proof-of-retrievability authorisation.
const PROVER_AUTH_LABEL: &str = "FANOS-v1/dromos-prover-auth";

/// A **fresh per-audit** authorisation proving the designated provider — and only it — produced *this* audit
/// response (audit §3.6 / AT-H1). Where a static [`SignedTransfer`] auth is byte-identical every epoch (so it
/// can be captured off the public ledger and replayed forever, letting a confederate holding a replica of the
/// public leaves collect for data the provider deleted), this is the provider's hybrid-PQ signature over
/// `deal_id ‖ H(response)` — bound to the exact response, which `por::verify` in turn binds to the block's
/// audit beacon. So a captured auth cannot be replayed at a later epoch (the new beacon needs a new response,
/// which the old auth does not cover) and a third party cannot forge the provider's signature over a fresh one.
#[derive(Clone)]
pub struct ProverAuth {
    /// The provider's verifying key (hashes to the deal's `provider` account).
    pub provider_key: HybridVerifier,
    /// The signature over the [`challenge`](Self::challenge), `HYBRID_SIG_LEN` bytes.
    sig: Vec<u8>,
}

impl ProverAuth {
    /// The fixed serialized length: `provider_key(VK) ‖ sig(SIG)`.
    pub const WIRE_LEN: usize = HYBRID_VK_LEN + HYBRID_SIG_LEN;

    /// The signed challenge binding the authorisation to this exact deal + response.
    fn challenge(deal_id: &[u8; 32], response: &[u8]) -> Vec<u8> {
        let response_hash = hash_labeled(PROVER_AUTH_LABEL, response);
        let mut msg = Vec::with_capacity(PROVER_AUTH_LABEL.len() + 64);
        msg.extend_from_slice(PROVER_AUTH_LABEL.as_bytes());
        msg.extend_from_slice(deal_id);
        msg.extend_from_slice(&response_hash);
        msg
    }

    /// Sign an authorisation for `deal_id` over `response` under the provider's key.
    #[must_use]
    pub fn sign(deal_id: &[u8; 32], response: &[u8], signer: &HybridSigSecret, provider_key: HybridVerifier) -> Self {
        let sig = signer.sign(&Self::challenge(deal_id, response)).to_bytes();
        Self { provider_key, sig }
    }

    /// Whether this authorises `response` for `deal_id` as the deal's `provider`: the key binds to the provider
    /// account **and** the signature verifies over the fresh challenge.
    #[must_use]
    pub fn verify(&self, deal_id: &[u8; 32], response: &[u8], provider: &[u8; 32]) -> bool {
        if &account_id(&self.provider_key) != provider {
            return false;
        }
        let Some(sig) = HybridSignature::from_bytes(&self.sig) else {
            return false;
        };
        self.provider_key.verify(&Self::challenge(deal_id, response), &sig)
    }

    /// Canonical bytes: `provider_key(VK) ‖ sig(SIG)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&self.provider_key.encode());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        let provider_key = HybridVerifier::decode(bytes.get(..HYBRID_VK_LEN)?)?;
        let sig = bytes.get(HYBRID_VK_LEN..)?.to_vec();
        Some(Self { provider_key, sig })
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
        // Single-transaction path: verify the signature inline, then settle. Block execution verifies every
        // transfer's signature in parallel up front and settles via [`apply_with_verdict`](Self::apply_with_verdict).
        self.apply_with_verdict(st, st.verify())
    }

    /// Settle a signed transfer whose signature was **already verified** (the `sig_ok` verdict). The signature
    /// check is the transfer's one stateless, expensive step (a hybrid post-quantum verification); factoring it
    /// out lets a block verify every transfer's signature in parallel *before* this serial settle. The result is
    /// identical to [`apply`](Self::apply): the settle reads only ledger state (nonce, balance), never the
    /// signature, so verifying the signature earlier and off-thread cannot change the outcome.
    pub fn apply_with_verdict(&mut self, st: &SignedTransfer, sig_ok: bool) -> Result<(), TokenError> {
        if !sig_ok {
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

    /// A **system** move — no signature, no nonce — from `from` to `to`, authorised by the caller rather than a
    /// key (e.g. an unshield's credit, authorised by a shielded proof; the keyless pool sink can only move this
    /// way). `false` (and unchanged) if `from` lacks `amount`. Not exposed outside the crate: only the bridge
    /// may mint transparent value against a verified shielded spend.
    pub(crate) fn move_system(&mut self, from: &[u8; 32], to: [u8; 32], amount: u64) -> bool {
        if self.balance(from) < amount {
            return false;
        }
        if let Some(bal) = self.balances.get_mut(from) {
            *bal -= amount;
        }
        self.credit(to, amount);
        true
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

    /// The canonical wire form of the **entire** token state — every account (sorted) with its balance and
    /// nonce — for a state-sync snapshot (the `StateMachine::snapshot` path). Deterministic: the same state
    /// always encodes identically, and [`from_bytes`](Self::from_bytes) reconstructs a state with the identical
    /// [`state_root`](Self::state_root) (a 0 balance/nonce is inert, so the reconstruction is normalized-but-equivalent).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut accounts: BTreeSet<[u8; 32]> = self.balances.keys().copied().collect();
        accounts.extend(self.nonces.keys().copied());
        let mut out = Vec::with_capacity(4 + accounts.len() * 48);
        out.extend_from_slice(&(accounts.len() as u32).to_le_bytes());
        for a in &accounts {
            out.extend_from_slice(a);
            out.extend_from_slice(&self.balance(a).to_le_bytes());
            out.extend_from_slice(&self.nonce(a).to_le_bytes());
        }
        out
    }

    /// Reconstruct a token ledger from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated /
    /// over-long. Only non-zero balances/nonces are stored (a zero is the map default), so the result is
    /// canonical and reproduces the source `state_root`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let count = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        // Each account record is 48 bytes; reject a count the buffer cannot hold (bounds the allocation).
        if count > bytes.len().saturating_sub(4) / 48 {
            return None;
        }
        let mut ledger = Self::new();
        let mut off = 4usize;
        for _ in 0..count {
            let account: [u8; 32] = bytes.get(off..off + 32)?.try_into().ok()?;
            let balance = u64::from_le_bytes(bytes.get(off + 32..off + 40)?.try_into().ok()?);
            let nonce = u64::from_le_bytes(bytes.get(off + 40..off + 48)?.try_into().ok()?);
            if balance > 0 {
                ledger.balances.insert(account, balance);
            }
            if nonce > 0 {
                ledger.nonces.insert(account, nonce);
            }
            off += 48;
        }
        (off == bytes.len()).then_some(ledger) // reject trailing garbage
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

    #[test]
    fn a_prover_auth_binds_to_its_exact_deal_response_and_provider() {
        // Audit §3.6: the authorisation is bound to `deal_id ‖ H(response)` under the provider's key, so it
        // authorises exactly one (deal, response) as exactly one provider — a captured auth cannot be replayed
        // over a different (later-epoch) response, a different deal, or on behalf of a different provider.
        let (sk, vk, provider) = account(2);
        let (_other_sk, _other_vk, other) = account(3);
        let deal_id = [7u8; 32];
        let auth = ProverAuth::sign(&deal_id, b"response-0", &sk, vk);
        assert!(auth.verify(&deal_id, b"response-0", &provider), "authorises its own deal + response + provider");
        assert!(!auth.verify(&deal_id, b"response-1", &provider), "does not authorise a different (fresh) response");
        assert!(!auth.verify(&[8u8; 32], b"response-0", &provider), "does not authorise a different deal");
        assert!(!auth.verify(&deal_id, b"response-0", &other), "does not authorise a different provider");
        // The wire form round-trips, and a truncated one is refused.
        let bytes = auth.to_bytes();
        assert_eq!(bytes.len(), ProverAuth::WIRE_LEN);
        assert!(ProverAuth::from_bytes(&bytes).unwrap().verify(&deal_id, b"response-0", &provider));
        assert!(ProverAuth::from_bytes(&bytes[..bytes.len() - 1]).is_none());
    }
}
