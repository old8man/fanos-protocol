//! The OBOLOS **key hierarchy** and its delegatable **viewing keys** (`spec/platform.md` §4, audit O-M3).
//!
//! A wallet is one 32-byte **spending seed** `w` — the single secret to back up. From it, three capabilities
//! are derived by domain separation, and the *lesser* ones can be handed out without conferring the greater:
//!
//! ```text
//!                                    w  (SpendingKey — detect · decrypt · SPEND)
//!            ┌───────────────────────┼───────────────────────┐
//!    nsk = H("…/nsk", w)     ask = derive_spend_auth(         kem = HybridKem(H("…/kem", w))
//!    (nullifier key)          H("…/ask", w))  (spend-auth)    (note-delivery decryption)
//!            │                        │                        │
//!            ▼                        ▼                        ▼
//!   owner = H("owner-pk", nsk)  auth = H("…", ak)        kem_public  ──►  Address(owner, auth, kem_public)
//! ```
//!
//! * [`SpendingKey`] holds `w` and grants **full authority**: scan + decrypt incoming notes, detect when they
//!   are spent, and *authorize spends* (it can produce the `nsk`, `ak`, and — for signing — `ask`).
//! * [`FullViewingKey`] holds `(kem_seed, nsk, auth)` — it can **scan, decrypt, and detect spends** (it can
//!   compute a note's nullifier), but it carries **no `ask`**, so it can never *sign* a spend. Give it to an
//!   accountant who must reconcile both incoming *and* outgoing flows.
//! * [`IncomingViewingKey`] holds `(kem_seed, owner, auth)` — it can **scan and decrypt incoming** notes and
//!   nothing else (no `nsk` ⇒ it cannot even compute a nullifier). Give it to a watch-only wallet or a
//!   payment-notification service.
//!
//! **Why this is safe to delegate.** A spend requires *both* the nullifier key `nsk` (to nullify) and the
//! spend-auth secret `ask` (to sign — audit §5.D-2). The `kem` material is derived from `w` under a **separate
//! domain** from `nsk`/`ask`, so `kem_seed` reveals neither; and `owner = H(nsk)`, `auth = H(ak)` are one-way,
//! so they reveal neither. Thus the incoming-viewing key discloses *only* the ability to see incoming payments,
//! and the full-viewing key adds *only* the ability to see them spent — never the ability to spend. This is the
//! Zcash Sapling/Orchard viewing-key discipline, carried onto OBOLOS's post-§5.D-2 split spend keys.
//!
//! The `kem_secret` is **reconstructed from `kem_seed` on use** rather than stored, so a viewing key serializes
//! to plain bytes (`kem_seed ‖ …`) without a [`HybridKemSecret`] byte-spill — matching that type's deliberate
//! non-serializability (its own docs forbid an un-zeroized owned copy). Reconstruction is one ML-KEM keygen per
//! scan batch, which is negligible.

use alloc::vec::Vec;

use fanos_pqcrypto::rng::SeedRng;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, HybridSigSecret, HybridVerifier};
use fanos_primitives::hash_labeled;
use rand_core::CryptoRng;

use crate::commit::Params;
use crate::note::{Note, derive_owner_pk, derive_spend_auth, spend_auth_commit};
use crate::note_cipher::{Address, NoteCipher, scan};
use crate::nullifier::Nullifier;

/// Domain-separation labels deriving each capability from the spending seed `w`. Distinct labels guarantee the
/// nullifier key, the spend-auth seed, and the KEM seed are computationally independent one-way images of `w`.
const NSK_LABEL: &str = "FANOS-obolos-v1/wallet-nsk";
const ASK_LABEL: &str = "FANOS-obolos-v1/wallet-ask";
const KEM_LABEL: &str = "FANOS-obolos-v1/wallet-kem";

/// The serialized length of a viewing key: three 32-byte fields.
const VIEWING_KEY_LEN: usize = 96;

/// Reconstruct the note-delivery KEM keypair from a wallet's `kem_seed` (deterministic; the secret half is
/// never stored, only re-derived on use — see the module docs).
fn kem_keypair(kem_seed: &[u8; 32]) -> (HybridKemSecret, HybridKemPublic) {
    HybridKemSecret::generate(&mut SeedRng::from_seed(kem_seed))
}

/// Split three concatenated 32-byte fields out of a `VIEWING_KEY_LEN` buffer.
fn split_96(bytes: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
    if bytes.len() != VIEWING_KEY_LEN {
        return None;
    }
    let a = bytes.get(..32)?.try_into().ok()?;
    let b = bytes.get(32..64)?.try_into().ok()?;
    let c = bytes.get(64..)?.try_into().ok()?;
    Some((a, b, c))
}

/// The master **spending key** — a wallet's single 32-byte root secret. It derives, on demand, every key the
/// wallet needs to receive, recognize, and spend notes; and it hands out the lesser [`FullViewingKey`] /
/// [`IncomingViewingKey`] capabilities. Back up exactly this.
#[derive(Clone)]
pub struct SpendingKey {
    seed: [u8; 32],
}

impl SpendingKey {
    /// A wallet from a 32-byte spending seed (the operator's backed-up secret).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// A fresh wallet from a cryptographic RNG (OS entropy in production).
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self { seed }
    }

    /// The secret **nullifier key** `nsk` (recognize + nullify notes). Feed it, with a note's tree position, to
    /// [`Note::nullifier`] when building a spend. `nsk` alone is **not** spend authority (audit §5.D-2).
    #[must_use]
    pub fn nsk(&self) -> [u8; 32] {
        hash_labeled(NSK_LABEL, &self.seed)
    }

    /// The **spend-authorization keypair** `(ask, ak)` — the secret `ask` signs a spend's sighash, and never
    /// leaves the wallet; the verifier `ak` is committed into the note's `auth` and revealed at spend time.
    #[must_use]
    pub fn spend_auth(&self) -> (HybridSigSecret, HybridVerifier) {
        derive_spend_auth(&hash_labeled(ASK_LABEL, &self.seed))
    }

    /// The wallet's note-delivery **KEM keypair** (the secret decrypts [`NoteCipher`]s; the public receives).
    #[must_use]
    pub fn kem_keypair(&self) -> (HybridKemSecret, HybridKemPublic) {
        kem_keypair(&hash_labeled(KEM_LABEL, &self.seed))
    }

    /// The wallet's public **receiving address** `(owner, auth, kem_public)` — publish it to be paid.
    #[must_use]
    pub fn address(&self) -> Address {
        let (_ask, ak) = self.spend_auth();
        Address::new(derive_owner_pk(&self.nsk()), spend_auth_commit(&ak), self.kem_keypair().1)
    }

    /// Delegate a **full-viewing** capability (scan + decrypt incoming, and detect spends — no signing).
    #[must_use]
    pub fn full_viewing_key(&self) -> FullViewingKey {
        let (_ask, ak) = self.spend_auth();
        FullViewingKey {
            kem_seed: hash_labeled(KEM_LABEL, &self.seed),
            nsk: self.nsk(),
            auth: spend_auth_commit(&ak),
        }
    }

    /// Delegate an **incoming-viewing** capability (scan + decrypt incoming payments only).
    #[must_use]
    pub fn incoming_viewing_key(&self) -> IncomingViewingKey {
        self.full_viewing_key().to_incoming()
    }

    /// The seed bytes — back this up (the whole wallet). Anyone holding it holds full spend authority.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }
}

/// A **full-viewing key**: scan + decrypt a wallet's incoming notes *and* detect when its notes are spent (it
/// can compute their nullifiers via `nsk`), but with **no spend-auth secret**, so it can never sign a spend.
/// Serializes to [`VIEWING_KEY_LEN`] bytes (`kem_seed ‖ nsk ‖ auth`). Downgrades to an [`IncomingViewingKey`].
#[derive(Clone)]
pub struct FullViewingKey {
    kem_seed: [u8; 32],
    nsk: [u8; 32],
    auth: [u8; 32],
}

impl FullViewingKey {
    /// The `owner` tag this key sees (`= derive_owner_pk(nsk)`).
    #[must_use]
    pub fn owner(&self) -> [u8; 32] {
        derive_owner_pk(&self.nsk)
    }

    /// The receiving [`Address`] this key views.
    #[must_use]
    pub fn address(&self) -> Address {
        Address::new(self.owner(), self.auth, kem_keypair(&self.kem_seed).1)
    }

    /// Scan `outputs` for the wallet's incoming notes (verified against their commitments) — see [`scan`].
    #[must_use]
    pub fn scan(&self, params: &Params, outputs: &[(&[u8; 32], &NoteCipher)]) -> Vec<Note> {
        scan(&kem_keypair(&self.kem_seed).0, self.owner(), self.auth, params, outputs)
    }

    /// Try to open one delivered cipher (detect + decrypt a single output).
    #[must_use]
    pub fn open(&self, cipher: &NoteCipher) -> Option<Note> {
        cipher.open(&kem_keypair(&self.kem_seed).0, self.owner(), self.auth)
    }

    /// The nullifier a note (at tree `position`) reveals when spent — so a full-viewing holder can **watch the
    /// ledger for its own notes being spent** without any spend authority (audit O-M3 spend-detection).
    #[must_use]
    pub fn nullifier(&self, note: &Note, position: u64, params: &Params) -> Nullifier {
        note.nullifier(&self.nsk, position, params)
    }

    /// Downgrade to the strictly-lesser [`IncomingViewingKey`] (drop the nullifier key: keep detect+decrypt of
    /// incoming, lose spend-detection).
    #[must_use]
    pub fn to_incoming(&self) -> IncomingViewingKey {
        IncomingViewingKey { kem_seed: self.kem_seed, owner: self.owner(), auth: self.auth }
    }

    /// Canonical bytes `kem_seed(32) ‖ nsk(32) ‖ auth(32)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VIEWING_KEY_LEN);
        out.extend_from_slice(&self.kem_seed);
        out.extend_from_slice(&self.nsk);
        out.extend_from_slice(&self.auth);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes); `None` on the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (kem_seed, nsk, auth) = split_96(bytes)?;
        Some(Self { kem_seed, nsk, auth })
    }
}

/// An **incoming-viewing key**: the minimal delegatable capability — scan + decrypt the notes a wallet is
/// *paid*, and nothing more (no `nsk`, so it cannot even compute a nullifier; no `ask`, so it cannot spend).
/// Serializes to [`VIEWING_KEY_LEN`] bytes (`kem_seed ‖ owner ‖ auth`). Hand it to a watch-only wallet.
#[derive(Clone)]
pub struct IncomingViewingKey {
    kem_seed: [u8; 32],
    owner: [u8; 32],
    auth: [u8; 32],
}

impl IncomingViewingKey {
    /// The receiving [`Address`] this key views.
    #[must_use]
    pub fn address(&self) -> Address {
        Address::new(self.owner, self.auth, kem_keypair(&self.kem_seed).1)
    }

    /// Scan `outputs` for the wallet's incoming notes (verified against their commitments) — see [`scan`].
    #[must_use]
    pub fn scan(&self, params: &Params, outputs: &[(&[u8; 32], &NoteCipher)]) -> Vec<Note> {
        scan(&kem_keypair(&self.kem_seed).0, self.owner, self.auth, params, outputs)
    }

    /// Try to open one delivered cipher (detect + decrypt a single output).
    #[must_use]
    pub fn open(&self, cipher: &NoteCipher) -> Option<Note> {
        cipher.open(&kem_keypair(&self.kem_seed).0, self.owner, self.auth)
    }

    /// Canonical bytes `kem_seed(32) ‖ owner(32) ‖ auth(32)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VIEWING_KEY_LEN);
        out.extend_from_slice(&self.kem_seed);
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.auth);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes); `None` on the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (kem_seed, owner, auth) = split_96(bytes)?;
        Some(Self { kem_seed, owner, auth })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::commit::Randomness;
    use fanos_pqcrypto::SeedRng;

    /// A note paid to `address`, plus its on-chain commitment and delivery cipher.
    fn paid(address: &Address, value: u64, tag: &[u8]) -> (Note, [u8; 32], NoteCipher) {
        let p = Params::standard();
        let rho = hash_labeled("test/rho", tag);
        let note = Note::new(value, address.owner, address.auth, Randomness::from_seed(tag), rho);
        let cm = note.commitment(&p);
        let cipher = NoteCipher::seal(address, value, &note.value_r, &rho, &mut SeedRng::from_seed(tag)).unwrap();
        (note, cm, cipher)
    }

    #[test]
    fn the_hierarchy_derives_a_consistent_address_and_the_viewing_keys_see_it() {
        let sk = SpendingKey::from_seed([7u8; 32]);
        let addr = sk.address();
        // Every capability agrees on the same receiving address.
        assert_eq!(addr.owner, sk.full_viewing_key().address().owner);
        assert_eq!(addr.auth, sk.incoming_viewing_key().address().auth);
        assert_eq!(addr.kem_public.encode(), sk.full_viewing_key().address().kem_public.encode());

        // A payment to the address is found by BOTH viewing keys, with the exact note recovered.
        let (note, cm, cipher) = paid(&addr, 4242, b"a");
        let outputs = [(&cm, &cipher)];
        let ivk = sk.incoming_viewing_key();
        let fvk = sk.full_viewing_key();
        assert_eq!(ivk.scan(&Params::standard(), &outputs), alloc::vec![note.clone()]);
        assert_eq!(fvk.scan(&Params::standard(), &outputs), alloc::vec![note.clone()]);
        assert_eq!(ivk.open(&cipher), Some(note.clone()));
    }

    #[test]
    fn a_viewing_key_grants_no_spend_authority() {
        // The incoming-viewing key's bytes are exactly (kem_seed, owner, auth) — one-way images or a
        // domain-separated seed — and contain NEITHER the nullifier key nor anything the spend-auth secret can
        // be recovered from. Concretely: the ivk bytes never expose `nsk` or the `ask`-seed.
        let sk = SpendingKey::from_seed([9u8; 32]);
        let ivk = sk.incoming_viewing_key();
        let ivk_bytes = ivk.to_bytes();
        let nsk = sk.nsk();
        assert!(
            !ivk_bytes.windows(32).any(|w| w == nsk),
            "the incoming-viewing key never carries the nullifier key",
        );
        let ask_seed = hash_labeled(ASK_LABEL, &[9u8; 32]);
        assert!(
            !ivk_bytes.windows(32).any(|w| w == ask_seed),
            "nor anything the spend-auth secret derives from",
        );
        // The full-viewing key carries `nsk` (to detect spends) but STILL no spend-auth material — it can
        // compute a note's nullifier yet holds nothing that signs.
        let fvk = sk.full_viewing_key();
        assert!(!fvk.to_bytes().windows(32).any(|w| w == ask_seed), "fvk carries no spend-auth seed either");
    }

    #[test]
    fn the_full_viewing_key_detects_a_spend_matching_the_wallets_own_nullifier() {
        // The spend-detection guarantee: the nullifier a full-viewing key computes for a note is exactly the
        // one the SPENDING key reveals when it actually spends that note (same nsk, same position). So a
        // watch-only accountant recognizes the wallet's outgoing flow on the ledger.
        let sk = SpendingKey::from_seed([3u8; 32]);
        let (note, _cm, _c) = paid(&sk.address(), 100, b"n");
        let p = Params::standard();
        let position = 17u64;
        assert_eq!(
            sk.full_viewing_key().nullifier(&note, position, &p),
            note.nullifier(&sk.nsk(), position, &p),
            "the fvk-computed nullifier matches the spending key's — spend-detection is exact",
        );
    }

    #[test]
    fn viewing_keys_round_trip_through_bytes_and_downgrade() {
        let sk = SpendingKey::from_seed([5u8; 32]);
        let fvk = sk.full_viewing_key();
        let ivk = sk.incoming_viewing_key();
        assert_eq!(fvk.to_bytes().len(), VIEWING_KEY_LEN);
        assert_eq!(ivk.to_bytes().len(), VIEWING_KEY_LEN);
        // Round-trips reconstruct the same capability (same address).
        let fvk2 = FullViewingKey::from_bytes(&fvk.to_bytes()).unwrap();
        assert_eq!(fvk2.address().owner, fvk.address().owner);
        let ivk2 = IncomingViewingKey::from_bytes(&ivk.to_bytes()).unwrap();
        assert_eq!(ivk2.address().auth, ivk.address().auth);
        // The fvk downgrades to exactly the ivk the spending key hands out.
        assert_eq!(fvk.to_incoming().to_bytes(), ivk.to_bytes());
        // A wrong length is rejected.
        assert!(IncomingViewingKey::from_bytes(&ivk.to_bytes()[..VIEWING_KEY_LEN - 1]).is_none());
    }

    #[test]
    fn distinct_seeds_yield_independent_wallets_that_cannot_see_each_other() {
        let a = SpendingKey::from_seed([1u8; 32]);
        let b = SpendingKey::from_seed([2u8; 32]);
        assert_ne!(a.address().owner, b.address().owner);
        // A payment to A is not found by B's viewing key (AEAD auth under the wrong KEM key fails).
        let (_n, cm, cipher) = paid(&a.address(), 50, b"x");
        assert!(
            b.incoming_viewing_key().scan(&Params::standard(), &[(&cm, &cipher)]).is_empty(),
            "B cannot see A's incoming payment",
        );
    }
}
