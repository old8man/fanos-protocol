//! **Currency-bought naming** — the on-chain name registry (`spec/platform.md` §5, ONOMA-domains). Human-
//! memorable names are *owned* on the ledger, bought and renewed with the platform's currency, and resolve to a
//! target descriptor (a payment address, a CALYPSO service, an ANGELOS messaging id). Registration is a
//! **signed, fee-paying** operation, so the same post-quantum key that owns the funds owns the name — and the
//! fee flowing to a treasury, plus expiry, is the anti-squatting pressure (the ХОЛАРХ **DL — Regulation**
//! channel: a demand-priced scarce resource).
//!
//! Every operation carries a [`SignedTransfer`] paying the fee to the [`TREASURY`]; its signature *is* the
//! authorisation (its `from` is the acting account), so ownership and payment are one act. Applying a name
//! operation first settles the payment on the [`TokenLedger`] (which verifies the signature, nonce, and funds)
//! and then mutates the registry — atomically: if the payment is refused, the name state is untouched.

use std::collections::BTreeMap;

use fanos_pqcrypto::sig::{HYBRID_SIG_LEN, HYBRID_VK_LEN};
use fanos_primitives::hash_labeled;

use crate::token::{SignedTransfer, TokenError, TokenLedger};

/// The fixed serialized length of a [`SignedTransfer`] (`from ‖ to ‖ amount ‖ nonce ‖ key ‖ sig`).
const SIGNED_TRANSFER_LEN: usize = 80 + HYBRID_VK_LEN + HYBRID_SIG_LEN;

/// The treasury account that registration/renewal fees flow to (a fixed, keyless sink — its balance is the
/// accrued naming revenue, spendable only by a future governance rule, never by a signature).
pub const TREASURY: [u8; 32] = *b"FANOS-onoma-treasury-v1-account!";

/// The shortest allowed name (bytes) — empty names are rejected.
pub const MIN_NAME_LEN: usize = 1;
/// The longest allowed name (bytes).
pub const MAX_NAME_LEN: usize = 64;

/// Domain-separation label for the registry state root.
const ROOT_LABEL: &str = "FANOS-dromos-v1/name-root";

/// The **price** of registering or renewing `name` for `duration` periods — length-tiered so short, premium
/// names cost more (anti-squatting). A deterministic function of the name and duration; the exact constants are
/// a monetary-policy knob.
#[must_use]
pub fn price(name: &[u8], duration: u64) -> u64 {
    // Base per-period price, multiplied by a length tier: ≤4 bytes are premium, tapering to a flat rate.
    let base: u64 = 100;
    let tier: u64 = match name.len() {
        0..=2 => 1000,
        3..=4 => 100,
        5..=8 => 10,
        _ => 1,
    };
    base.saturating_mul(tier).saturating_mul(duration.max(1))
}

/// A registered name's on-chain record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NameRecord {
    /// The owning account id (a [`crate::token::account_id`]).
    pub owner: [u8; 32],
    /// The target descriptor the name resolves to (a payment address, service, or messaging id — opaque here).
    pub target: Vec<u8>,
    /// The height/epoch after which the name expires unless renewed.
    pub expiry: u64,
}

/// A name-registry operation. Each is authorised and paid for by an accompanying [`SignedTransfer`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NameOp {
    /// Claim a free or expired `name`, pointing it at `target`, for `duration` periods.
    Register {
        /// The name to claim.
        name: Vec<u8>,
        /// The descriptor it resolves to.
        target: Vec<u8>,
        /// How many periods to register for.
        duration: u64,
    },
    /// Extend the owner's `name` by `duration` periods.
    Renew {
        /// The name to renew.
        name: Vec<u8>,
        /// Extra periods.
        duration: u64,
    },
    /// Repoint the owner's `name` at a new `target`.
    Update {
        /// The name to update.
        name: Vec<u8>,
        /// The new descriptor.
        target: Vec<u8>,
    },
    /// Transfer the owner's `name` to `new_owner`.
    Transfer {
        /// The name to transfer.
        name: Vec<u8>,
        /// The new owning account id.
        new_owner: [u8; 32],
    },
}

impl NameOp {
    /// The name this operation acts on.
    #[must_use]
    fn name(&self) -> &[u8] {
        match self {
            NameOp::Register { name, .. }
            | NameOp::Renew { name, .. }
            | NameOp::Update { name, .. }
            | NameOp::Transfer { name, .. } => name,
        }
    }
}

/// A name operation together with the signed transfer that pays its fee and authorises it (the transfer's
/// `from` is the acting account).
#[derive(Clone)]
pub struct NameTx {
    /// The operation.
    pub op: NameOp,
    /// The fee payment (to [`TREASURY`]), whose signature authorises the acting account.
    pub payment: SignedTransfer,
}

/// Why a name operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameError {
    /// The name is empty or too long.
    BadName,
    /// The fee payment is not addressed to the treasury.
    WrongPayee,
    /// The fee is below the price for this name and duration.
    InsufficientFee,
    /// A `Register` for a name that is currently registered (and unexpired).
    NameTaken,
    /// An operation on a name that is not registered.
    NotRegistered,
    /// The acting account (the payment's `from`) is not the name's owner.
    NotOwner,
    /// The fee payment itself was refused by the token ledger (bad signature, nonce, or funds).
    Payment(TokenError),
}

/// The on-chain name registry.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct NameRegistry {
    records: BTreeMap<Vec<u8>, NameRecord>,
}

impl NameRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve `name` as of `now` — its record if registered and unexpired, else `None`.
    #[must_use]
    pub fn resolve(&self, name: &[u8], now: u64) -> Option<&NameRecord> {
        self.records.get(name).filter(|r| now <= r.expiry)
    }

    /// The number of names on record (including expired-but-not-reclaimed ones).
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the registry holds no names.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Apply a name operation as of height `now`, settling its fee on `tokens`. Atomic: the fee is settled and
    /// the registry mutated only if every check passes; on any [`NameError`] both are left unchanged.
    pub fn apply(&mut self, tx: &NameTx, tokens: &mut TokenLedger, now: u64) -> Result<(), NameError> {
        let name = tx.op.name();
        if !(MIN_NAME_LEN..=MAX_NAME_LEN).contains(&name.len()) {
            return Err(NameError::BadName);
        }
        if tx.payment.transfer.to != TREASURY {
            return Err(NameError::WrongPayee);
        }
        let actor = tx.payment.transfer.from;

        // Validate the registry precondition and compute the mutation BEFORE settling the payment, so a rejected
        // op never touches the token ledger.
        let mutation = self.plan(&tx.op, name, actor, now, tx.payment.transfer.amount)?;
        // Settle the fee (this verifies the signature, nonce, and funds).
        tokens.apply(&tx.payment).map_err(NameError::Payment)?;
        // Commit the registry mutation.
        mutation.commit(&mut self.records);
        Ok(())
    }

    /// Check an operation's registry precondition and return the mutation to commit after payment.
    fn plan(&self, op: &NameOp, name: &[u8], actor: [u8; 32], now: u64, fee: u64) -> Result<Mutation, NameError> {
        match op {
            NameOp::Register { target, duration, .. } => {
                if self.resolve(name, now).is_some() {
                    return Err(NameError::NameTaken);
                }
                if fee < price(name, *duration) {
                    return Err(NameError::InsufficientFee);
                }
                Ok(Mutation::Set(name.to_vec(), NameRecord { owner: actor, target: target.clone(), expiry: now.saturating_add(*duration) }))
            }
            NameOp::Renew { duration, .. } => {
                let rec = self.owned(name, actor, now)?;
                if fee < price(name, *duration) {
                    return Err(NameError::InsufficientFee);
                }
                let expiry = rec.expiry.max(now).saturating_add(*duration);
                Ok(Mutation::Set(name.to_vec(), NameRecord { expiry, ..rec.clone() }))
            }
            NameOp::Update { target, .. } => {
                let rec = self.owned(name, actor, now)?;
                Ok(Mutation::Set(name.to_vec(), NameRecord { target: target.clone(), ..rec.clone() }))
            }
            NameOp::Transfer { new_owner, .. } => {
                let rec = self.owned(name, actor, now)?;
                Ok(Mutation::Set(name.to_vec(), NameRecord { owner: *new_owner, ..rec.clone() }))
            }
        }
    }

    /// The record of `name` if it is registered, unexpired, and owned by `actor`.
    fn owned(&self, name: &[u8], actor: [u8; 32], now: u64) -> Result<&NameRecord, NameError> {
        let rec = self.resolve(name, now).ok_or(NameError::NotRegistered)?;
        if rec.owner != actor {
            return Err(NameError::NotOwner);
        }
        Ok(rec)
    }

    /// A binding commitment to the registry — sorted `(name, owner, expiry, target)`, hashed.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for (name, rec) in &self.records {
            buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
            buf.extend_from_slice(name);
            buf.extend_from_slice(&rec.owner);
            buf.extend_from_slice(&rec.expiry.to_le_bytes());
            buf.extend_from_slice(&(rec.target.len() as u32).to_le_bytes());
            buf.extend_from_slice(&rec.target);
        }
        hash_labeled(ROOT_LABEL, &buf)
    }
}

impl NameOp {
    /// Canonical bytes: a 1-byte variant tag then the variant's length-prefixed fields.
    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let put = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        };
        match self {
            NameOp::Register { name, target, duration } => {
                out.push(0);
                put(&mut out, name);
                put(&mut out, target);
                out.extend_from_slice(&duration.to_le_bytes());
            }
            NameOp::Renew { name, duration } => {
                out.push(1);
                put(&mut out, name);
                out.extend_from_slice(&duration.to_le_bytes());
            }
            NameOp::Update { name, target } => {
                out.push(2);
                put(&mut out, name);
                put(&mut out, target);
            }
            NameOp::Transfer { name, new_owner } => {
                out.push(3);
                put(&mut out, name);
                out.extend_from_slice(new_owner);
            }
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes).
    #[must_use]
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&tag, mut rest) = bytes.split_first()?;
        let mut take_bytes = || -> Option<Vec<u8>> {
            let len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let b = rest.get(4..4 + len)?.to_vec();
            rest = rest.get(4 + len..)?;
            Some(b)
        };
        let op = match tag {
            0 => {
                let name = take_bytes()?;
                let target = take_bytes()?;
                let duration = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
                NameOp::Register { name, target, duration }
            }
            1 => {
                let name = take_bytes()?;
                let duration = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
                NameOp::Renew { name, duration }
            }
            2 => {
                let name = take_bytes()?;
                let target = take_bytes()?;
                NameOp::Update { name, target }
            }
            3 => {
                let name = take_bytes()?;
                let new_owner = rest.get(..32)?.try_into().ok()?;
                NameOp::Transfer { name, new_owner }
            }
            _ => return None,
        };
        Some(op)
    }
}

impl NameTx {
    /// Canonical bytes: the operation, then the fixed-width payment (so decoding splits it off the end).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.op.to_bytes();
        out.extend_from_slice(&self.payment.to_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let split = bytes.len().checked_sub(SIGNED_TRANSFER_LEN)?;
        let op = NameOp::from_bytes(bytes.get(..split)?)?;
        let payment = SignedTransfer::from_bytes(bytes.get(split..)?)?;
        Some(Self { op, payment })
    }
}

/// A planned registry mutation, committed only after the fee settles.
enum Mutation {
    Set(Vec<u8>, NameRecord),
}

impl Mutation {
    fn commit(self, records: &mut BTreeMap<Vec<u8>, NameRecord>) {
        match self {
            Mutation::Set(name, rec) => {
                records.insert(name, rec);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::token::{Transfer, account_id};
    use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};

    /// A funded account (signer, verifier, id) and its next nonce tracker.
    fn account(tag: u8) -> (HybridSigSecret, HybridVerifier, [u8; 32]) {
        let mut rng = SeedRng::from_seed(&[0xB0, tag]);
        let (signer, verifier) = HybridSigSecret::generate(&mut rng);
        let id = account_id(&verifier);
        (signer, verifier, id)
    }

    /// A fee payment of `amount` to the treasury, from `account`, at `nonce`.
    fn pay(signer: &HybridSigSecret, vk: &HybridVerifier, from: [u8; 32], amount: u64, nonce: u64) -> SignedTransfer {
        SignedTransfer::sign(Transfer { from, to: TREASURY, amount, nonce }, signer, vk.clone())
    }

    fn fund(tokens: &mut TokenLedger, id: [u8; 32], amount: u64) {
        tokens.credit(id, amount);
    }

    #[test]
    fn registering_a_name_pays_the_fee_and_binds_it_to_the_owner() {
        let (sk, vk, alice) = account(1);
        let mut tokens = TokenLedger::new();
        fund(&mut tokens, alice, 100_000);
        let mut reg = NameRegistry::new();

        let name = b"alice.fanos".to_vec();
        let fee = price(&name, 10);
        let tx = NameTx {
            op: NameOp::Register { name: name.clone(), target: b"payaddr".to_vec(), duration: 10 },
            payment: pay(&sk, &vk, alice, fee, 0),
        };
        assert_eq!(reg.apply(&tx, &mut tokens, 0), Ok(()));
        let rec = reg.resolve(&name, 5).expect("resolves before expiry");
        assert_eq!(rec.owner, alice);
        assert_eq!(rec.target, b"payaddr");
        assert_eq!(rec.expiry, 10);
        assert_eq!(tokens.balance(&TREASURY), fee, "the fee flowed to the treasury");
        assert_eq!(tokens.balance(&alice), 100_000 - fee);
    }

    #[test]
    fn a_taken_name_cannot_be_re_registered_until_it_expires() {
        let (sk, vk, alice) = account(1);
        let (sk2, vk2, bob) = account(2);
        let mut tokens = TokenLedger::new();
        fund(&mut tokens, alice, 100_000);
        fund(&mut tokens, bob, 100_000);
        let mut reg = NameRegistry::new();
        let name = b"popular".to_vec();
        let fee = price(&name, 10);
        reg.apply(&NameTx { op: NameOp::Register { name: name.clone(), target: vec![1], duration: 10 }, payment: pay(&sk, &vk, alice, fee, 0) }, &mut tokens, 0).unwrap();

        // Bob cannot take it while it is live.
        let bob_try = NameTx { op: NameOp::Register { name: name.clone(), target: vec![2], duration: 10 }, payment: pay(&sk2, &vk2, bob, fee, 0) };
        assert_eq!(reg.apply(&bob_try, &mut tokens, 5), Err(NameError::NameTaken));
        assert_eq!(reg.resolve(&name, 5).unwrap().owner, alice, "still Alice's");
        // After expiry it resolves to nothing, and Bob can claim it.
        assert!(reg.resolve(&name, 11).is_none(), "expired names do not resolve");
        let bob_claim = NameTx { op: NameOp::Register { name: name.clone(), target: vec![2], duration: 10 }, payment: pay(&sk2, &vk2, bob, fee, 0) };
        assert_eq!(reg.apply(&bob_claim, &mut tokens, 11), Ok(()));
        assert_eq!(reg.resolve(&name, 11).unwrap().owner, bob, "Bob claims the expired name");
    }

    #[test]
    fn only_the_owner_can_renew_update_or_transfer() {
        let (sk, vk, alice) = account(1);
        let (sk2, vk2, bob) = account(2);
        let mut tokens = TokenLedger::new();
        fund(&mut tokens, alice, 100_000);
        fund(&mut tokens, bob, 100_000);
        let mut reg = NameRegistry::new();
        let name = b"alice.fanos".to_vec();
        let fee = price(&name, 10);
        reg.apply(&NameTx { op: NameOp::Register { name: name.clone(), target: vec![1], duration: 10 }, payment: pay(&sk, &vk, alice, fee, 0) }, &mut tokens, 0).unwrap();

        // Bob (not the owner) cannot update it.
        let bob_update = NameTx { op: NameOp::Update { name: name.clone(), target: vec![9] }, payment: pay(&sk2, &vk2, bob, 0, 0) };
        assert_eq!(reg.apply(&bob_update, &mut tokens, 1), Err(NameError::NotOwner));

        // Alice updates the target, renews, then transfers to Bob (nonces 1, 2, 3).
        reg.apply(&NameTx { op: NameOp::Update { name: name.clone(), target: vec![7] }, payment: pay(&sk, &vk, alice, 0, 1) }, &mut tokens, 1).unwrap();
        assert_eq!(reg.resolve(&name, 1).unwrap().target, vec![7]);
        reg.apply(&NameTx { op: NameOp::Renew { name: name.clone(), duration: 5 }, payment: pay(&sk, &vk, alice, fee, 2) }, &mut tokens, 1).unwrap();
        assert_eq!(reg.resolve(&name, 1).unwrap().expiry, 15, "renew extends expiry");
        reg.apply(&NameTx { op: NameOp::Transfer { name: name.clone(), new_owner: bob }, payment: pay(&sk, &vk, alice, 0, 3) }, &mut tokens, 1).unwrap();
        assert_eq!(reg.resolve(&name, 1).unwrap().owner, bob, "ownership transferred");
    }

    #[test]
    fn an_underpaid_or_misaddressed_or_unaffordable_registration_is_rejected_atomically() {
        let (sk, vk, alice) = account(1);
        let mut tokens = TokenLedger::new();
        fund(&mut tokens, alice, 50);
        let mut reg = NameRegistry::new();
        let name = b"alice".to_vec(); // 5 bytes → tier 10 → price(·,10) = 100*10*10 = 10000
        let full = price(&name, 10);

        // Underpaid.
        let underpaid = NameTx { op: NameOp::Register { name: name.clone(), target: vec![1], duration: 10 }, payment: pay(&sk, &vk, alice, full - 1, 0) };
        assert_eq!(reg.apply(&underpaid, &mut tokens, 0), Err(NameError::InsufficientFee));
        // Misaddressed fee (not to the treasury).
        let misaddressed = NameTx {
            op: NameOp::Register { name: name.clone(), target: vec![1], duration: 10 },
            payment: SignedTransfer::sign(Transfer { from: alice, to: [0u8; 32], amount: full, nonce: 0 }, &sk, vk.clone()),
        };
        assert_eq!(reg.apply(&misaddressed, &mut tokens, 0), Err(NameError::WrongPayee));
        // Can't afford it (fee ok, but balance too low → payment refused, registry untouched).
        let unaffordable = NameTx { op: NameOp::Register { name: name.clone(), target: vec![1], duration: 10 }, payment: pay(&sk, &vk, alice, full, 0) };
        assert_eq!(reg.apply(&unaffordable, &mut tokens, 0), Err(NameError::Payment(TokenError::InsufficientFunds)));
        assert!(reg.resolve(&name, 0).is_none(), "no name was registered by any rejected attempt");
        assert_eq!(tokens.balance(&alice), 50, "no funds moved on any rejection");
    }
}
