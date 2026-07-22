//! **Unlinkable note delivery** — how a sender hands a recipient the secret opening of a note they were paid,
//! so the recipient can find it on the ledger and later spend it, *without any observer being able to link the
//! payment to the recipient* (`spec/platform.md` §4.1, the unlinkability property).
//!
//! On-chain a note is only its opaque commitment `H(value_commitment ‖ owner ‖ rho)` — the `owner` is hashed
//! inside, so the ledger never reveals who a note is for (this is the Zcash-Sapling hidden-commitment model,
//! *not* a public address, which is why no lattice key-blinding is needed for unlinkability). The sender
//! attaches a [`NoteCipher`]: the note's opening, sealed to the recipient's hybrid-KEM key. Because each cipher
//! is a **fresh ML-KEM encapsulation**, two payments to the same recipient are unlinkable, and only the
//! recipient — by trial-decrypting each output (the AEAD tag is the "is this mine?" oracle) — detects and
//! recovers their notes. The sender cannot spend what it sent: the spend key `nsk` behind `owner` never leaves
//! the recipient.

use alloc::vec::Vec;

use fanos_pqcrypto::kem::{CIPHERTEXT_LEN, HybridCiphertext, HybridKemPublic, HybridKemSecret};
use fanos_primitives::{aead, hash_labeled};
use rand_core::CryptoRng;

use crate::commit::Randomness;
use crate::note::Note;

/// Domain-separation labels for deriving the note-cipher AEAD key and nonce from the KEM session secret.
const KEY_LABEL: &str = "FANOS-obolos-v1/note-cipher-key";
const NONCE_LABEL: &str = "FANOS-obolos-v1/note-cipher-nonce";

/// The fixed serialized length of a note opening: `value(8) ‖ value_r(WIRE_LEN) ‖ rho(32)`.
const OPENING_LEN: usize = 8 + Randomness::WIRE_LEN + 32;

/// A recipient's public **receiving address**: the note-ownership tag (`owner = derive_owner_pk(nsk)`) a sender
/// stamps on notes for them, and the hybrid-KEM public key those notes are delivered to. Publishing it reveals
/// nothing — `owner` is a one-way hash of the secret spend key, and it is hidden inside note commitments on the
/// ledger. `Clone` only (mirroring the KEM key's convention).
#[derive(Clone)]
pub struct Address {
    /// The note-ownership tag.
    pub owner: [u8; 32],
    /// The hybrid-KEM public key notes are sealed to.
    pub kem_public: HybridKemPublic,
}

impl Address {
    /// A receiving address from its parts.
    #[must_use]
    pub fn new(owner: [u8; 32], kem_public: HybridKemPublic) -> Self {
        Self { owner, kem_public }
    }
}

/// A note's opening sealed to a recipient — the unlinkable on-chain delivery of a payment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoteCipher {
    /// The hybrid-KEM ciphertext (a fresh encapsulation), serialized (`CIPHERTEXT_LEN` bytes).
    kem_ct: Vec<u8>,
    /// The AEAD-sealed note opening under the KEM session key.
    aead_ct: Vec<u8>,
}

/// Derive the AEAD key and nonce from a KEM session secret (domain-separated).
fn derive_key_nonce(session: &[u8; 32]) -> ([u8; aead::KEY_LEN], [u8; aead::NONCE_LEN]) {
    let key = hash_labeled(KEY_LABEL, session);
    let full_nonce = hash_labeled(NONCE_LABEL, session);
    let mut nonce = [0u8; aead::NONCE_LEN];
    let (head, _) = full_nonce.split_at(aead::NONCE_LEN);
    nonce.copy_from_slice(head);
    (key, nonce)
}

/// Serialize a note opening (`value ‖ value_r ‖ rho`) for sealing.
fn encode_opening(value: u64, value_r: &Randomness, rho: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(OPENING_LEN);
    out.extend_from_slice(&value.to_le_bytes());
    out.extend_from_slice(&value_r.to_bytes());
    out.extend_from_slice(rho);
    out
}

/// Parse a decrypted note opening.
fn decode_opening(bytes: &[u8]) -> Option<(u64, Randomness, [u8; 32])> {
    if bytes.len() != OPENING_LEN {
        return None;
    }
    let value = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    let value_r = Randomness::from_bytes(bytes.get(8..8 + Randomness::WIRE_LEN)?)?;
    let rho = bytes.get(8 + Randomness::WIRE_LEN..)?.try_into().ok()?;
    Some((value, value_r, rho))
}

impl NoteCipher {
    /// Seal the opening of a note (`value`, `value_r`, `rho`) to `address`, drawing the KEM encapsulation
    /// randomness from `rng`. Taking a live [`CryptoRng`] (rather than a fixed seed) is the fix for audit O-H2:
    /// the AEAD key **and** nonce are both derived from the KEM session secret, so reusing the encapsulation
    /// randomness would reuse the `(key, nonce)` pair (a ChaCha20-Poly1305 two-time pad + Poly1305 forgery) and
    /// produce an identical, linkable KEM ciphertext. A CSPRNG advances on every draw, so two seals never share
    /// randomness — production passes an OS CSPRNG; a test passes a seeded RNG *by `&mut`* so it advances across
    /// seals. `None` only if the KEM key is non-contributory or AEAD fails.
    #[must_use]
    pub fn seal<R: CryptoRng>(address: &Address, value: u64, value_r: &Randomness, rho: &[u8; 32], rng: &mut R) -> Option<Self> {
        let (kem_ct, session) = address.kem_public.encapsulate(rng)?;
        let (key, nonce) = derive_key_nonce(&session);
        let aead_ct = aead::seal(&key, &nonce, &encode_opening(value, value_r, rho))?;
        Some(Self { kem_ct: kem_ct.to_bytes(), aead_ct })
    }

    /// Try to open this cipher with `kem_secret`, reconstructing the note for the given `owner` (the recipient's
    /// own ownership tag). Returns `None` if the cipher was **not** sealed to this key — the AEAD authentication
    /// under the (implicitly-rejected, wrong) session key fails — which is exactly how a recipient *detects*
    /// which outputs are theirs.
    #[must_use]
    pub fn open(&self, kem_secret: &HybridKemSecret, owner: [u8; 32]) -> Option<Note> {
        let kem_ct = HybridCiphertext::from_bytes(&self.kem_ct)?;
        let session = kem_secret.decapsulate(&kem_ct)?;
        let (key, nonce) = derive_key_nonce(&session);
        let opening = aead::open(&key, &nonce, &self.aead_ct)?;
        let (value, value_r, rho) = decode_opening(&opening)?;
        Some(Note::new(value, owner, value_r, rho))
    }

    /// Canonical bytes: `kem_ct(CIPHERTEXT_LEN) ‖ aead_ct`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.kem_ct.len() + self.aead_ct.len());
        out.extend_from_slice(&self.kem_ct);
        out.extend_from_slice(&self.aead_ct);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if too short.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let kem_ct = bytes.get(..CIPHERTEXT_LEN)?.to_vec();
        let aead_ct = bytes.get(CIPHERTEXT_LEN..)?.to_vec();
        Some(Self { kem_ct, aead_ct })
    }
}

/// Scan `outputs` (each an on-chain note commitment paired with its delivery cipher) for notes owned by the
/// holder of `kem_secret` / `owner`, verifying each recovered note against its on-chain commitment. This is the
/// recipient's wallet operation: find the notes you were paid without the ledger revealing which are yours.
#[must_use]
pub fn scan(
    kem_secret: &HybridKemSecret,
    owner: [u8; 32],
    params: &crate::commit::Params,
    outputs: &[(&[u8; 32], &NoteCipher)],
) -> Vec<Note> {
    outputs
        .iter()
        .filter_map(|(commitment, cipher)| {
            let note = cipher.open(kem_secret, owner)?;
            (note.commitment(params) == **commitment).then_some(note)
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;
    use crate::commit::Params;
    use crate::note::derive_owner_pk;

    /// A receiving address + the KEM secret behind it, from a seed.
    fn recipient(nsk: &[u8; 32], kem_tag: u8) -> (Address, HybridKemSecret) {
        let mut rng = SeedRng::from_seed(&[0xE0, kem_tag]);
        let (kem_secret, kem_public) = HybridKemSecret::generate(&mut rng);
        (Address::new(derive_owner_pk(nsk), kem_public), kem_secret)
    }

    #[test]
    fn the_recipient_recovers_the_sealed_note_and_others_cannot() {
        let nsk = [1u8; 32];
        let (addr, kem_secret) = recipient(&nsk, 1);
        let value_r = Randomness::from_seed(b"vr");
        let rho = [5u8; 32];
        let cipher = NoteCipher::seal(&addr, 4242, &value_r, &rho, &mut SeedRng::from_seed(b"enc-seed")).expect("seal");

        // The recipient opens it and recovers exactly the note.
        let note = cipher.open(&kem_secret, addr.owner).expect("the recipient recovers the note");
        assert_eq!(note.value, 4242);
        assert_eq!(note.rho, rho);
        assert_eq!(note, Note::new(4242, addr.owner, value_r, rho));

        // A different recipient's key cannot open it (AEAD auth under the wrong session key fails).
        let (_other_addr, other_secret) = recipient(&[9u8; 32], 2);
        assert!(cipher.open(&other_secret, derive_owner_pk(&[9u8; 32])).is_none(), "a non-recipient cannot open it");
    }

    #[test]
    fn two_seals_of_one_note_never_reuse_key_nonce_and_are_unlinkable() {
        // Audit O-H2: the AEAD key and nonce both come from the KEM session, so a reused encapsulation would
        // reuse the (key, nonce) pair and the KEM ciphertext. Drawing from an advancing CryptoRng makes every
        // seal fresh — even the same note to the same recipient seals to distinct, unlinkable ciphers.
        let nsk = [1u8; 32];
        let (addr, kem_secret) = recipient(&nsk, 1);
        let value_r = Randomness::from_seed(b"vr");
        let rho = [7u8; 32];
        let mut rng = SeedRng::from_seed(b"fresh");
        let c1 = NoteCipher::seal(&addr, 100, &value_r, &rho, &mut rng).unwrap();
        let c2 = NoteCipher::seal(&addr, 100, &value_r, &rho, &mut rng).unwrap();
        assert_ne!(c1, c2, "two seals of the same note produce distinct, unlinkable ciphertexts");
        // Both still open to the same note.
        assert_eq!(c1.open(&kem_secret, addr.owner).unwrap().value, 100);
        assert_eq!(c2.open(&kem_secret, addr.owner).unwrap().value, 100);
    }

    #[test]
    fn a_note_cipher_round_trips_through_bytes() {
        let (addr, _sk) = recipient(&[1u8; 32], 1);
        let cipher = NoteCipher::seal(&addr, 1, &Randomness::from_seed(b"r"), &[0u8; 32], &mut SeedRng::from_seed(b"s")).unwrap();
        let bytes = cipher.to_bytes();
        assert_eq!(NoteCipher::from_bytes(&bytes), Some(cipher));
        assert_eq!(NoteCipher::from_bytes(&bytes[..CIPHERTEXT_LEN - 1]), None, "a truncated cipher is rejected");
    }

    #[test]
    fn scanning_finds_only_the_recipients_notes_among_a_mix() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let (addr, kem_secret) = recipient(&nsk, 1);
        // Two notes for Alice, one for someone else.
        let (other_addr, _other_secret) = recipient(&[9u8; 32], 2);
        let n_a = Note::new(100, addr.owner, Randomness::from_seed(b"a"), [1u8; 32]);
        let n_b = Note::new(200, addr.owner, Randomness::from_seed(b"b"), [2u8; 32]);
        let n_other = Note::new(300, other_addr.owner, Randomness::from_seed(b"c"), [3u8; 32]);
        let c_a = NoteCipher::seal(&addr, n_a.value, &n_a.value_r, &n_a.rho, &mut SeedRng::from_seed(b"sa")).unwrap();
        let c_b = NoteCipher::seal(&addr, n_b.value, &n_b.value_r, &n_b.rho, &mut SeedRng::from_seed(b"sb")).unwrap();
        let c_other = NoteCipher::seal(&other_addr, n_other.value, &n_other.value_r, &n_other.rho, &mut SeedRng::from_seed(b"sc")).unwrap();
        let (cm_a, cm_b, cm_other) = (n_a.commitment(&p), n_b.commitment(&p), n_other.commitment(&p));
        let outputs = [(&cm_a, &c_a), (&cm_other, &c_other), (&cm_b, &c_b)];

        let mine = scan(&kem_secret, addr.owner, &p, &outputs);
        assert_eq!(mine.len(), 2, "Alice finds her two notes and not the third");
        assert!(mine.contains(&n_a) && mine.contains(&n_b), "the recovered notes are exactly Alice's");
    }
}
