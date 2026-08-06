//! The on-chain **decryption-key commitment** — the anti-MEV keyper registry (`docs/design-taxis.md` §5).
//!
//! The anti-MEV mempool seals every transaction to the epoch keyper line's hybrid-KEM public keys — the
//! *decryption authority*. Those keys must be **canonical and agreed**: a client cannot seal to a line whose
//! keys it does not know, and a substituted key would silently make its transaction undecryptable. Shutter and
//! Ferveo solve this by registering the decryption key **on-chain**; this module is the FANOS post-quantum
//! analogue.
//!
//! Each validator **self-certifies** its decryption key: [`KeyperKeyCert::register`] signs `idx ‖ kem_public`
//! under the validator's *consensus signing key*, so the decryption key binds to the already-committed
//! consensus identity `verifiers[idx]` — adding **no new trust root**. The [`KeyperRegistry`] is the full,
//! ordered set of these certs.
//!
//! * [`KeyperRegistry::verify`] checks every cert against the committed consensus keys, binding the whole
//!   decryption authority to the validator identities — run once at cell formation.
//! * [`KeyperRegistry::commit`] is the **on-chain decryption-key commitment**: a binding hash of the key set,
//!   an agreed genesis constant (alongside `verifiers` and the beacon `seed`) that a light client checks.
//! * [`KeyperRegistry::line_keys`] / [`seal_to_keyper_committee`] are the **only** correct way for a client to
//!   seal: the keys come from the committed registry, so the transaction is bound to the on-chain authority.
//!
//! What this does **not** claim: a hybrid-KEM ciphertext is not publicly verifiable *before opening* to target
//! a given key (unlike Ferveo's pairing check — no PQ-native equivalent is production-ready). A transaction
//! sealed to non-committed keys therefore still *decodes*; it simply yields no honest share and is dropped
//! after the reveal window (`crate::consensus`) — a bounded liveness cost, never a safety break. The
//! commitment closes the *authority* gap (which keys decrypt, agreed and discoverable), which is the on-chain
//! guarantee Shutter/Ferveo provide.

use alloc::vec::Vec;

use fanos_threshold::ThresholdError;
use fanos_pqcrypto::kem::{HybridKemPublic, PUBLIC_LEN};
use fanos_pqcrypto::sig::HYBRID_SIG_LEN;
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};
use fanos_primitives::{Epoch, hash_labeled};

use crate::params::CellParams;
use crate::tx::{SealedTx, Transaction};

const KEY_CERT_LABEL: &str = "FANOS-v1/taxis-keyper-key";
const COMMIT_LABEL: &str = "FANOS-v1/taxis-keyper-commit";

/// One validator's **self-certified** anti-MEV decryption key: its hybrid-KEM public key plus a signature over
/// it under the validator's consensus signing key, binding the decryption key to the committed consensus
/// identity `verifiers[idx]`.
///
/// `Clone` only, mirroring [`HybridKemPublic`]'s own key-handling convention (keys are not casually compared or
/// printed); compare/anchor certs through [`to_bytes`](Self::to_bytes) or the registry
/// [`commit`](KeyperRegistry::commit).
#[derive(Clone)]
pub struct KeyperKeyCert {
    /// The validator's hybrid-KEM public (decryption) key — what transactions to it are sealed to.
    pub kem_public: HybridKemPublic,
    /// The validator's signature over [`signable`](Self::signable), `HYBRID_SIG_LEN` bytes.
    sig: Vec<u8>,
}

impl KeyperKeyCert {
    /// The signed content binding a decryption key to its owner: the domain-separation label `‖ idx(1) ‖
    /// kem_public(PUBLIC_LEN)`. A signature under validator `idx`'s key attests "validator `idx`'s anti-MEV
    /// decryption key is exactly this key"; the label stops the signature being reused as any other TAXIS message.
    #[must_use]
    fn signable(idx: u8, kem_public: &HybridKemPublic) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEY_CERT_LABEL.len() + 1 + PUBLIC_LEN);
        out.extend_from_slice(KEY_CERT_LABEL.as_bytes());
        out.push(idx);
        out.extend_from_slice(&kem_public.encode());
        out
    }

    /// Validator `idx` self-certifies `kem_public` under its consensus signing key.
    #[must_use]
    pub fn register(idx: u8, kem_public: HybridKemPublic, signer: &HybridSigSecret) -> Self {
        let sig = signer.sign(&Self::signable(idx, &kem_public)).to_bytes();
        Self { kem_public, sig }
    }

    /// Whether this cert verifies under `verifier` — validator `idx`'s consensus signing key — i.e. the
    /// decryption key genuinely belongs to that consensus identity.
    #[must_use]
    pub fn verify(&self, idx: u8, verifier: &HybridVerifier) -> bool {
        let Some(sig) = HybridSignature::from_bytes(&self.sig) else {
            return false;
        };
        verifier.verify(&Self::signable(idx, &self.kem_public), &sig)
    }

    /// Canonical bytes: `kem_public(PUBLIC_LEN) ‖ sig(HYBRID_SIG_LEN)`, both fixed width.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_LEN + HYBRID_SIG_LEN);
        out.extend_from_slice(&self.kem_public.encode());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed / wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PUBLIC_LEN + HYBRID_SIG_LEN {
            return None;
        }
        let kem_public = HybridKemPublic::decode(bytes.get(..PUBLIC_LEN)?)?;
        let sig = bytes.get(PUBLIC_LEN..)?.to_vec();
        Some(Self { kem_public, sig })
    }
}

/// The **on-chain decryption-key commitment**: the ordered set of every validator's self-certified anti-MEV
/// decryption key. Assembled once at cell formation (each validator contributes its signed cert), verified
/// against the consensus keys, and [`commit`](Self::commit)ted — the agreed decryption authority for the cell.
#[derive(Clone)]
pub struct KeyperRegistry {
    certs: Vec<KeyperKeyCert>,
}

impl KeyperRegistry {
    /// A registry from validators' self-certified keys, in validator-index order (`certs[i]` is validator `i`).
    #[must_use]
    pub fn new(certs: Vec<KeyperKeyCert>) -> Self {
        Self { certs }
    }

    /// The number of registered validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Canonical bytes: `n(4) ‖ cert₀ ‖ … ‖ cert_{n−1}`, each a fixed-width [`KeyperKeyCert::to_bytes`]. The
    /// public form a client needs to seal a transaction to the committee — published in `fanos taxis-deal`'s
    /// chain-info file so `fanos pay` can reconstruct the sealing authority.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.certs.len() * (PUBLIC_LEN + HYBRID_SIG_LEN));
        out.extend_from_slice(&u32::try_from(self.certs.len()).unwrap_or(u32::MAX).to_be_bytes());
        for c in &self.certs {
            out.extend_from_slice(&c.to_bytes());
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes); `None` on truncation, a malformed cert, or trailing bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let n = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        let cert_len = PUBLIC_LEN + HYBRID_SIG_LEN;
        let mut certs = Vec::with_capacity(n.min(4096));
        let mut off: usize = 4;
        for _ in 0..n {
            let end = off.checked_add(cert_len)?;
            certs.push(KeyperKeyCert::from_bytes(bytes.get(off..end)?)?);
            off = end;
        }
        if off != bytes.len() {
            return None; // trailing bytes ⇒ non-canonical
        }
        Some(Self { certs })
    }

    /// Validator `i`'s committed decryption (KEM public) key, or `None` if out of range.
    #[must_use]
    pub fn key(&self, i: usize) -> Option<&HybridKemPublic> {
        self.certs.get(i).map(|c| &c.kem_public)
    }

    /// Whether **every** cert verifies under the corresponding consensus signing key `verifiers[i]` — binding
    /// the whole decryption authority to the committed consensus identities. Requires `verifiers.len()` to
    /// match the registry size (a partial registry is not a valid authority). Run once at cell formation.
    #[must_use]
    pub fn verify(&self, verifiers: &[HybridVerifier]) -> bool {
        self.certs.len() == verifiers.len()
            && self
                .certs
                .iter()
                .zip(verifiers)
                .enumerate()
                .all(|(i, (c, v))| c.verify(u8::try_from(i).unwrap_or(u8::MAX), v))
    }

    /// The on-chain decryption-key commitment: `H_label(n(4) ‖ kem_public₀ ‖ … ‖ kem_public_{n−1})`. Bound to
    /// the *keys only* (not the recomputable signatures), so it names exactly the decryption authority. This
    /// is the agreed genesis constant a light client checks a served registry against.
    #[must_use]
    pub fn commit(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(4 + self.certs.len() * PUBLIC_LEN);
        buf.extend_from_slice(&u32::try_from(self.certs.len()).unwrap_or(u32::MAX).to_be_bytes());
        for c in &self.certs {
            buf.extend_from_slice(&c.kem_public.encode());
        }
        hash_labeled(COMMIT_LABEL, &buf)
    }

    /// The committed KEM keys of the keyper committee — **the whole cell**, in validator-index order, and
    /// the exact key set a client seals a transaction to (`docs/design-taxis.md` §5).
    ///
    /// It was the epoch's elected LINE, which could not be made sound: a coalition inside the cell's own
    /// fault budget owns a line outright and decrypts everything sealed to it
    /// ([`CellParams::seal_committee_size`], #136). The committee no longer depends on the epoch or the
    /// beacon, so there is nothing left to elect.
    ///
    /// `None` if the registry does not hold the whole cell — a partially-registered decryption authority
    /// cannot be sealed to, and guessing which subset to use would reintroduce exactly the question this
    /// removes.
    #[must_use]
    pub fn committee_keys(&self, params: CellParams) -> Option<Vec<&HybridKemPublic>> {
        (self.len() >= params.seal_committee_size())
            .then(|| (0..params.seal_committee_size()).map(|m| self.key(m)).collect())
            .flatten()
    }
}

/// Seal `tx` to the epoch's **committed** keyper line — the canonical client-side anti-MEV seal. Resolves the
/// keyper line and its committed decryption keys from `registry`, then threshold-seals to them, openable by
/// `t = params.seal_threshold()` of them. This is the only seal path that binds a transaction to the on-chain
/// decryption authority; `rng_seed` supplies the (production: fresh CSPRNG; test: fixed) sealing randomness.
///
/// # Errors
/// [`ThresholdError::Malformed`] if the registry cannot supply the elected line's keys (out-of-range member);
/// otherwise any [`ThresholdError`] from [`SealedTx::seal`] (bad sharing parameters, non-contributory key, …).
pub fn seal_to_keyper_committee(
    registry: &KeyperRegistry,
    tx: &Transaction,
    epoch: Epoch,
    params: CellParams,
    rng_seed: &[u8],
) -> Result<SealedTx, ThresholdError> {
    // Fail closed on unsound parameters rather than sealing to a committee that cannot keep the secret.
    // The predicate is cheap and the alternative is a transaction that looks sealed and is not (#136).
    // Both bounds, because they fail independently: `seal_is_sound` asks whether the committee keeps the
    // secret, `seal_fits_a_block` whether the resulting ciphertext can be carried at all (#136, #143).
    if !params.seal_is_sound() || !crate::block::seal_fits_a_block(params) {
        return Err(ThresholdError::Malformed);
    }
    let keys = registry.committee_keys(params).ok_or(ThresholdError::Malformed)?;
    SealedTx::seal(tx, epoch, &keys, params.seal_threshold(), rng_seed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;
    use fanos_pqcrypto::kem::HybridKemSecret;


    /// A cell of `n` validators, each with a consensus signing key + a hybrid-KEM decryption key.
    fn cell(n: usize) -> (Vec<HybridSigSecret>, Vec<HybridVerifier>, Vec<HybridKemSecret>, KeyperRegistry) {
        let mut signers = Vec::new();
        let mut verifiers = Vec::new();
        let mut kem_secrets = Vec::new();
        let mut certs = Vec::new();
        for i in 0..n {
            let mut rng = SeedRng::from_seed(&[0xA0, i as u8]);
            let (signer, verifier) = HybridSigSecret::generate(&mut rng);
            let mut krng = SeedRng::from_seed(&[0xB0, i as u8]);
            let (kem_secret, kem_public) = HybridKemSecret::generate(&mut krng);
            certs.push(KeyperKeyCert::register(i as u8, kem_public, &signer));
            signers.push(signer);
            verifiers.push(verifier);
            kem_secrets.push(kem_secret);
        }
        (signers, verifiers, kem_secrets, KeyperRegistry::new(certs))
    }

    #[test]
    fn a_registry_of_self_certified_keys_verifies_against_the_consensus_identities() {
        let (_s, verifiers, _k, registry) = cell(7);
        assert_eq!(registry.len(), 7);
        assert!(registry.verify(&verifiers), "every keyper key must certify under its consensus key");
    }

    #[test]
    fn a_key_substituted_under_the_wrong_identity_is_rejected() {
        let (_s, mut verifiers, _k, registry) = cell(7);
        // Swap two validators' consensus keys: the certs no longer match their positions.
        verifiers.swap(0, 1);
        assert!(!registry.verify(&verifiers), "a decryption key bound to the wrong consensus identity is refused");
    }

    #[test]
    fn a_size_mismatch_between_registry_and_identities_is_not_a_valid_authority() {
        let (_s, verifiers, _k, registry) = cell(7);
        assert!(!registry.verify(&verifiers[..6]), "a registry that does not cover every validator is not the authority");
    }

    #[test]
    fn the_commitment_is_deterministic_binds_the_keys_and_ignores_signatures() {
        let (_s, _v, _k, registry) = cell(7);
        let c = registry.commit();
        assert_eq!(c, registry.commit(), "the commitment is a deterministic function of the key set");
        // A different key set (a different cell) commits differently.
        let (_s2, _v2, _k2, other) = cell(6);
        assert_ne!(c, other.commit(), "distinct decryption authorities have distinct commitments");
    }

    #[test]
    fn the_keyper_line_keys_are_the_committed_keys_of_the_elected_members() {
        let (_s, _v, _k, registry) = cell(7);
        let params = CellParams::FANO;
        let keys = registry.committee_keys(params).expect("a fully-registered cell");
        assert_eq!(keys.len(), params.seal_committee_size(), "the committee is the whole cell (#136)");
        for (m, k) in keys.iter().enumerate() {
            assert_eq!(k.encode(), registry.key(m).unwrap().encode(), "committee key {m} matches the registry");
        }
    }

    #[test]
    fn a_cert_round_trips_through_bytes() {
        let (_s, _v, _k, registry) = cell(3);
        let cert = &registry.certs[0];
        let bytes = cert.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_LEN + HYBRID_SIG_LEN);
        let decoded = KeyperKeyCert::from_bytes(&bytes).expect("a full cert decodes");
        assert_eq!(decoded.to_bytes(), bytes, "the cert round-trips through its canonical bytes");
        assert!(KeyperKeyCert::from_bytes(&bytes[..bytes.len() - 1]).is_none(), "a truncated cert is rejected");
    }

    #[test]
    fn sealing_to_the_committed_line_produces_a_transaction_the_elected_members_open() {
        let (_s, _v, kem_secrets, registry) = cell(7);
        let epoch = Epoch::new(2);
        let params = CellParams::FANO;
        let tx = Transaction::new(b"anti-mev-payload".to_vec());
        let sealed = seal_to_keyper_committee(&registry, &tx, epoch, params, b"seal-seed").unwrap();
        // The seal is bound to the epoch; the committee is the cell, so there is no line left to bind.
        assert_eq!(sealed.epoch, epoch);
        assert_eq!(sealed.member_count(), params.seal_committee_size());
        // A threshold of the committee recovers the plaintext.
        let t = usize::from(params.seal_threshold());
        let shares: Vec<_> = (0..t)
            .map(|m| sealed.member_share(m, &kem_secrets[m]).expect("member opens its slot"))
            .collect();
        assert_eq!(sealed.open(&shares).unwrap(), tx, "the committed keyper committee decrypts its own seal");
    }

    /// **The anti-MEV property, measured against the fault budget the cell actually tolerates** (#136).
    ///
    /// `seal_threshold`'s doc derives `t` from "the per-line Byzantine bound `⌊(q+1)/3⌋`" — at Fano, one
    /// faulty member per line. Nothing in the protocol enforces that. The cell tolerates `f = 2` faults
    /// placed anywhere, a line has `q + 1 = 3` members, and in `PG(2,q)` two points lie on **exactly one**
    /// common line — so a coalition of two owns one of the seven lines outright, and `epoch_seal_line`
    /// hands it every transaction for a whole epoch once in seven.
    ///
    /// This asserts what the requirement is, not what the code does: a coalition inside the tolerated budget
    /// must not be able to open a sealed transaction. It fails today, and that failure is the finding.
    #[test]
    fn a_coalition_inside_the_fault_budget_must_not_open_a_sealed_transaction() {
        let (_s, _v, kem_secrets, registry) = cell(7);
        let epoch = Epoch::new(2);
        let params = CellParams::FANO;
        let tx = Transaction::new(b"a-transaction-the-cell-must-keep-sealed".to_vec());
        let sealed = seal_to_keyper_committee(&registry, &tx, epoch, params, b"seal-seed").unwrap();

        // The adversary corrupts `f` nodes of its choosing, all of them on the committee — which with the
        // committee being the whole cell is the strongest placement available to it.
        let coalition: Vec<_> = (0..params.f())
            .map(|m| sealed.member_share(m, &kem_secrets[m]).expect("a member opens its own slot"))
            .collect();
        assert_eq!(coalition.len(), params.f(), "the coalition is exactly the tolerated fault budget");

        // The cost of the only fix that exists, measured before it is built: the committee must be at least
        // `2f + 1` (safety needs `t > f`, liveness needs `t <= m - f`), which at Fano is 5 of the 7 and rules
        // a 3-member line out at every plane order. The seal encapsulates to each member, so the ciphertext
        // grows linearly in the committee — this prints what one transaction costs per member.
        let bytes = sealed.to_bytes().len();
        std::eprintln!(
            "SEAL COST: {bytes} B for m = {} members ({} B/member)",
            sealed.member_count(),
            bytes / sealed.member_count()
        );

        assert!(
            sealed.open(&coalition).is_err(),
            "a coalition of f = {} — inside the budget the cell already tolerates — opened a sealed \
             transaction before its order was fixed. The seal threshold is derived from a per-line fault \
             bound the protocol never enforces, so the whole anti-MEV property is void for an adversary \
             that simply chooses which nodes to corrupt.",
            params.f()
        );
    }
}
