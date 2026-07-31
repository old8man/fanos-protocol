//! **Currency-bought naming** — the on-chain name registry (`spec/platform.md` §5, ONOMA-domains). Human-
//! memorable names are *owned* on the ledger, bought and renewed with the platform's currency, and resolve to a
//! target descriptor (a payment address, a CALYPSO service, an ANGELOS messaging id). Registration is a
//! **signed, fee-paying** operation, so the same post-quantum key that owns the funds owns the name — and the
//! fee flowing to a treasury, plus expiry, is the anti-squatting pressure (the HOLARCH **DL — Regulation**
//! channel: a demand-priced scarce resource).
//!
//! Every operation carries a [`SignedTransfer`] paying the fee to the [`TREASURY`]; its signature *is* the
//! authorisation (its `from` is the acting account), so ownership and payment are one act. Applying a name
//! operation first settles the payment on the [`TokenLedger`] (which verifies the signature, nonce, and funds)
//! and then mutates the registry — atomically: if the payment is refused, the name state is untouched.

use std::collections::BTreeMap;

use fanos_primitives::codec::{Reader, put_map, put_u64, put_var_bytes, read_map};
use fanos_primitives::hash_labeled;

use crate::token::{SignedTransfer, TokenError, TokenLedger};

/// The fixed serialized length of a [`SignedTransfer`].
const SIGNED_TRANSFER_LEN: usize = SignedTransfer::WIRE_LEN;

/// The treasury account that registration/renewal fees flow to (a fixed, keyless sink — its balance is the
/// accrued naming revenue, spendable only by a future governance rule, never by a signature).
pub const TREASURY: [u8; 32] = *b"FANOS-onoma-treasury-v1-account!";

/// The shortest allowed name (bytes) — empty names are rejected.
pub const MIN_NAME_LEN: usize = 1;
/// The longest allowed name (bytes).
pub const MAX_NAME_LEN: usize = 64;

/// Domain-separation label for the registry state root.
const ROOT_LABEL: &str = "FANOS-dromos-v1/name-root";

/// The label under which a name is digested to its registry key.
///
/// Lives here rather than in `hybrid`, because the registry itself is keyed by this digest now: the access list, the
/// ERGON footprint and the storage must name the same thing, and one of the three owning the definition is how they
/// stay that way.
pub const NAME_KEY_LABEL: &str = "FANOS-dromos-v1/name-key";

/// A name's registry key: the digest the access list, the ERGON footprint and the storage all agree on.
#[must_use]
pub fn name_digest(name: &[u8]) -> [u8; 32] { hash_labeled(NAME_KEY_LABEL, name) }

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

/// The kind of endpoint a name resolves to (`spec/platform.md` §5) — one human-memorable name, several private
/// endpoints.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DescriptorKind {
    /// An OBOLOS payment address (`data` is a serialized receiving address).
    Payment,
    /// A CALYPSO anonymous hidden service (`data` is a service address).
    Service,
    /// An ANGELOS messaging identity (`data` is a messaging id).
    Messenger,
    /// A THESAUROS stored object (`data` is a content id — a chunk or manifest CID; the storehouse resolves and
    /// serves it). Names point at immutable content, mutably.
    Storage,
    /// An opaque / application-defined target.
    Raw,
}

impl DescriptorKind {
    #[must_use]
    fn tag(self) -> u8 {
        match self {
            DescriptorKind::Payment => 0,
            DescriptorKind::Service => 1,
            DescriptorKind::Messenger => 2,
            DescriptorKind::Raw => 3,
            DescriptorKind::Storage => 4,
        }
    }

    #[must_use]
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(DescriptorKind::Payment),
            1 => Some(DescriptorKind::Service),
            2 => Some(DescriptorKind::Messenger),
            3 => Some(DescriptorKind::Raw),
            4 => Some(DescriptorKind::Storage),
            _ => None,
        }
    }
}

/// A **typed pointer** a name resolves to: a kind and its payload. A [`NameRecord`]'s `target` is a
/// `Descriptor`'s bytes, so resolving `alice.fanos` yields, say, her OBOLOS payment address or her ANGELOS id.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Descriptor {
    /// What kind of endpoint this points at.
    pub kind: DescriptorKind,
    /// The endpoint payload (interpreted per `kind`).
    pub data: Vec<u8>,
}

impl Descriptor {
    /// A descriptor from its parts.
    #[must_use]
    pub fn new(kind: DescriptorKind, data: Vec<u8>) -> Self {
        Self { kind, data }
    }

    /// Canonical bytes: `kind(1) ‖ data` — exactly what a name registration stores as its `target`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.data.len());
        out.push(self.kind.tag());
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode a descriptor from a name's `target` bytes, or `None` if the kind tag is unknown.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&tag, data) = bytes.split_first()?;
        Some(Self { kind: DescriptorKind::from_tag(tag)?, data: data.to_vec() })
    }
}

/// A registered name's on-chain record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NameRecord {
    /// The name itself — the preimage of the key this record is stored under.
    ///
    /// Carried in the value because the registry is keyed by digest and a digest has no preimage: a read addressed the
    /// way the scheduler addresses it must still be able to say *which* name it found. Exactly one place holds it, so
    /// there is no second source to disagree with.
    pub name: Vec<u8>,
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
    pub fn name(&self) -> &[u8] {
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
    records: BTreeMap<[u8; 32], NameRecord>,
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
        self.records.get(&name_digest(name)).filter(|r| now <= r.expiry)
    }

    /// Resolve `name` to its typed [`Descriptor`] as of `now` — the endpoint (payment address, service,
    /// messaging id) it points at. `None` if unregistered, expired, or the target is not a valid descriptor.
    #[must_use]
    pub fn resolve_descriptor(&self, name: &[u8], now: u64) -> Option<Descriptor> {
        self.resolve(name, now).and_then(|r| Descriptor::from_bytes(&r.target))
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
                Ok(Mutation::Set(name.to_vec(), NameRecord { name: name.to_vec(), owner: actor, target: target.clone(), expiry: now.saturating_add(*duration) }))
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

    #[must_use]
    /// The record stored under `key`, whatever its expiry — the digest-addressed read the ERGON state adapter needs.
    ///
    /// Unlike [`resolve`](Self::resolve) this does **not** filter expired records, because the two answer different
    /// questions: resolution asks "what does this name point at now", and a term reading state asks "what is stored
    /// here". Folding expiry into the read would make a term's view of state depend on the clock rather than on the
    /// state, and a footprint would then name a key whose contents change without a write.
    pub fn record_at(&self, key: &[u8; 32]) -> Option<&NameRecord> { self.records.get(key) }

    /// Store `rec` under its own name's digest, replacing any record there.
    ///
    /// The key is derived from the record rather than supplied, so a caller cannot place a record at an address that
    /// does not resolve to it — the same invariant the snapshot decoder enforces, kept in the one other place a
    /// record can enter the map.
    pub fn put(&mut self, rec: NameRecord) { self.records.insert(name_digest(&rec.name), rec); }

    /// A binding commitment to the registry — `(key, name, owner, expiry, target)` in **digest order**, hashed.
    ///
    /// Digest order rather than name order, because the map is keyed by digest so all five sub-ledgers are addressed
    /// the same way (see [`name_digest`]). Equally canonical — a `BTreeMap` over `[u8; 32]` has exactly one order —
    /// but **not the same root** as the name-ordered fold it replaces. Deliberate and stated: preserving a root
    /// computed over the wrong addressing would be preserving the defect.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for (key, rec) in &self.records {
            buf.extend_from_slice(key);
            buf.extend_from_slice(&(rec.name.len() as u32).to_le_bytes());
            buf.extend_from_slice(&rec.name);
            buf.extend_from_slice(&rec.owner);
            buf.extend_from_slice(&rec.expiry.to_le_bytes());
            buf.extend_from_slice(&(rec.target.len() as u32).to_le_bytes());
            buf.extend_from_slice(&rec.target);
        }
        hash_labeled(ROOT_LABEL, &buf)
    }

    /// Canonical bytes for a state-sync snapshot ([`fanos_primitives::codec`]): the registry records in sorted
    /// name order (`name ‖ owner ‖ expiry ‖ target` each), so a restore reproduces the registry `state_root`.
    /// The clock is not state — it is supplied per block — so it is not serialized.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_map(&mut out, &self.records, |o, key, rec| {
            o.extend_from_slice(key);
            put_var_bytes(o, &rec.name);
            o.extend_from_slice(&rec.owner);
            put_u64(o, rec.expiry);
            put_var_bytes(o, &rec.target);
        });
        out
    }

    /// Reconstruct a registry from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated / over-long.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        // Smallest record: key (32) ‖ empty name (4) ‖ owner (32) ‖ expiry (8) ‖ empty target (4) = 80 bytes.
        let records = read_map(&mut r, 80, |r| {
            let key = r.array::<32>()?;
            let name = r.var_bytes()?.to_vec();
            let owner = r.array::<32>()?;
            let expiry = r.u64()?;
            let target = r.var_bytes()?.to_vec();
            // The key must be the name's digest, or a snapshot could place a record under an address that does not
            // resolve to it — a restore that silently disagrees with the chain it restored from.
            (key == name_digest(&name)).then_some((key, NameRecord { name, owner, target, expiry }))
        })?;
        r.finish()?;
        Some(Self { records })
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
    fn commit(self, records: &mut BTreeMap<[u8; 32], NameRecord>) {
        match self {
            Mutation::Set(name, rec) => {
                records.insert(name_digest(&name), rec);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    /// The registry is keyed by the digest the access list and the ERGON footprint already use — so all three name the
    /// same thing. This asserts the identity rather than trusting it: a lookup by name must find what a lookup by that
    /// name's digest stored.
    #[test]
    fn a_name_and_its_digest_address_the_same_record() {
        let key = name_digest(b"alice");
        let mut reg = NameRegistry::default();
        reg.records.insert(key, NameRecord { name: b"alice".to_vec(), owner: [1u8; 32], target: vec![7], expiry: 100 });
        assert!(reg.resolve(b"alice", 50).is_some(), "resolving by name must find the digest-keyed record");
        assert_eq!(reg.resolve(b"alice", 50).map(|r| r.name.clone()), Some(b"alice".to_vec()), "and know its own name");
        assert!(reg.resolve(b"bob", 50).is_none(), "a different name must not collide");
    }

    /// A snapshot that placed a record under an address the record does not resolve to would restore a registry that
    /// silently disagrees with the chain it came from — every later lookup by name would miss it. Refused on decode.
    #[test]
    fn a_snapshot_cannot_store_a_record_under_the_wrong_address() {
        let mut reg = NameRegistry::default();
        reg.records.insert(
            name_digest(b"alice"),
            NameRecord { name: b"alice".to_vec(), owner: [1u8; 32], target: vec![7], expiry: 100 },
        );
        let good = reg.to_bytes();
        assert_eq!(NameRegistry::from_bytes(&good).as_ref(), Some(&reg), "a well-formed snapshot restores");

        // The same records under a key belonging to a different name.
        let mut wrong = NameRegistry::default();
        wrong.records.insert(
            name_digest(b"mallory"),
            NameRecord { name: b"alice".to_vec(), owner: [1u8; 32], target: vec![7], expiry: 100 },
        );
        assert!(NameRegistry::from_bytes(&wrong.to_bytes()).is_none(), "a mis-addressed record must not decode");
    }

    /// Digest order is a different order from name order, so the root necessarily changed — the point is that it is
    /// still *an* order, one and only one, which is what makes a root a commitment at all.
    #[test]
    fn the_root_is_canonical_under_the_new_key() {
        let make = |names: &[&[u8]]| {
            let mut reg = NameRegistry::default();
            for n in names {
                reg.records.insert(
                    name_digest(n),
                    NameRecord { name: (*n).to_vec(), owner: [2u8; 32], target: vec![], expiry: 9 },
                );
            }
            reg
        };
        let forward: &[&[u8]] = &[b"a", b"b", b"c"];
        let reverse: &[&[u8]] = &[b"c", b"b", b"a"];
        assert_eq!(make(forward).state_root(), make(reverse).state_root(), "insertion order must not reach the root");
    }
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
    fn a_name_resolves_to_its_typed_endpoint() {
        let (sk, vk, alice) = account(1);
        let mut tokens = TokenLedger::new();
        fund(&mut tokens, alice, 100_000);
        let mut reg = NameRegistry::new();
        // Register alice.fanos pointing at an OBOLOS payment endpoint.
        let name = b"alice.fanos".to_vec();
        let descriptor = Descriptor::new(DescriptorKind::Payment, b"her-payment-address".to_vec());
        let fee = price(&name, 10);
        let tx = NameTx {
            op: NameOp::Register { name: name.clone(), target: descriptor.to_bytes(), duration: 10 },
            payment: pay(&sk, &vk, alice, fee, 0),
        };
        assert_eq!(reg.apply(&tx, &mut tokens, 0), Ok(()));
        let resolved = reg.resolve_descriptor(&name, 5).expect("resolves to a descriptor");
        assert_eq!(resolved, descriptor, "the name resolves to exactly the registered endpoint");
        assert_eq!(resolved.kind, DescriptorKind::Payment);
        // An unregistered name resolves to nothing.
        assert!(reg.resolve_descriptor(b"nobody.fanos", 5).is_none());
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
