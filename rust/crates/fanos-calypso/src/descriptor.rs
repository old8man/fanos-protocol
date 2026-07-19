//! ONOMA descriptors — the **unenumerable, address-gated, PoW-stamped** record a service publishes
//! so clients can resolve and *authenticate* it (`docs/design-names.md` §5–§6).
//!
//! A descriptor carries the hybrid public-key **bundle** (which opens the address commitment), the
//! service **metadata**, and an offline-root→epoch **signing cert + signature**. It is:
//!
//! 1. **encrypted** under `K = descriptor_key(addr, epoch)` — only holders of the address can
//!    decrypt it, so a storage node sees an opaque blob (content unenumerability);
//! 2. **stamped** with adaptive [`pow`](crate::pow) over the ciphertext — publishing at a lookup
//!    slot costs work, bounding squat/DoS floods;
//! 3. **indexed** at the rotating coordinate [`publish_point`] `= MapToPoint(H(addr ‖ epoch))` —
//!    without the address the slot is unguessable (service unenumerability).
//!
//! Resolution is **client-is-the-authority**: [`open`] verifies the PoW, decrypts, and requires
//! `H(bundle) == addr` (the post-quantum self-certification) before returning anything, so a
//! storage node — which cannot even check authorization — can never induce impersonation.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Point;
use fanos_onoma::Address;
use fanos_onoma::derive::{descriptor_key, lookup_point};
use fanos_primitives::Epoch;
use fanos_primitives::hash::hash_labeled;
use fanos_wire::Wire;
use fanos_wire::element::encode_bytes;

use crate::pow;

const NONCE_LABEL: &str = "FANOS-v1/onoma-desc-nonce";
const NONCE_SALT_LABEL: &str = "FANOS-v1/onoma-desc-nonce-salt";
const SIGN_LABEL: &str = "FANOS-v1/onoma-desc-sign";
const NONCE_LEN: usize = 12;
/// The per-publish nonce salt length, carried in the wire form.
const SALT_LEN: usize = 16;

/// An error sealing or opening a descriptor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DescriptorError {
    /// The bytes were malformed (bad length or trailing data).
    Malformed,
    /// AEAD authentication failed — wrong key (not an address-holder) or tampered ciphertext.
    Aead,
    /// The attached proof-of-work did not meet the required difficulty.
    BadPow,
    /// `H(bundle) != addr` — the descriptor does not certify this address (impersonation attempt).
    NotCertified,
    /// The descriptor's epoch did not match the requested epoch.
    EpochMismatch,
}

impl core::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed descriptor bytes",
            Self::Aead => "AEAD authentication failed (not an address-holder or tampered)",
            Self::BadPow => "proof-of-work below the required difficulty",
            Self::NotCertified => "descriptor does not certify this address (impersonation)",
            Self::EpochMismatch => "descriptor epoch does not match the requested epoch",
        })
    }
}

impl core::error::Error for DescriptorError {}

/// A service descriptor (plaintext form).
///
/// The canonical byte layout **is** the field order — `#[derive(Wire)]` emits
/// `epoch(8B BE) ‖ bundle ‖ metadata ‖ cert ‖ sig` (each `Vec<u8>` varint-length-prefixed, spec §7.1),
/// so this plaintext has one canonical encoding and no hand-rolled decoder to drift (audit A1).
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct Descriptor {
    /// The epoch this descriptor is valid for.
    pub epoch: Epoch,
    /// The canonical hybrid public-key bundle — opens the address commitment.
    pub bundle: Vec<u8>,
    /// Opaque service metadata (supported profiles, intro policy, …).
    pub metadata: Vec<u8>,
    /// The offline-root→epoch signing certificate (scheme-agnostic bytes).
    pub cert: Vec<u8>,
    /// The epoch key's signature over [`Descriptor::signing_bytes`] (scheme-agnostic).
    pub sig: Vec<u8>,
}

impl Descriptor {
    /// The canonical bytes an owner signs (everything except the signature itself): the domain label,
    /// then the epoch and the three opaque fields in the same canonical §7.1 form the [`Wire`] codec
    /// uses (`epoch` big-endian, each field varint-length-prefixed via [`encode_bytes`]). It stays a
    /// hand-written transcript — not the derived struct codec — because it is domain-separated and omits
    /// `sig`, but it shares the one canonical field encoding so signer and verifier cannot diverge.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(SIGN_LABEL.as_bytes());
        b.push(0x1f);
        b.extend_from_slice(&self.epoch.to_be_bytes());
        encode_bytes(&self.bundle, &mut b);
        encode_bytes(&self.metadata, &mut b);
        encode_bytes(&self.cert, &mut b);
        b
    }

    /// Verify the descriptor signature with a scheme-agnostic verifier `verify(msg, sig)` (the
    /// caller binds the epoch key via the cert chain).
    #[must_use]
    pub fn verify_signature<V>(&self, verify: V) -> bool
    where
        V: Fn(&[u8], &[u8]) -> bool,
    {
        verify(&self.signing_bytes(), &self.sig)
    }
}

/// A sealed (encrypted + PoW-stamped) descriptor, ready to publish at [`publish_point`].
///
/// `#[derive(Wire)]` emits the canonical `pow_nonce(8B BE) ‖ nonce_salt(16) ‖ ciphertext` — the
/// ciphertext varint-length-prefixed (spec §7.1), so this composes and has one canonical decoder.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct SealedDescriptor {
    /// The proof-of-work nonce over the ciphertext.
    pub pow_nonce: u64,
    /// The per-publish AEAD nonce salt (bound to the plaintext), carried so the reader re-derives the
    /// AEAD nonce and a mid-epoch republish of a changed body never reuses one (audit E3).
    pub nonce_salt: [u8; SALT_LEN],
    /// `AEAD(descriptor_key(addr, epoch), nonce(addr, epoch, nonce_salt), encode(descriptor))`.
    pub ciphertext: Vec<u8>,
}

impl SealedDescriptor {
    /// The canonical wire bytes (the derived [`Wire`] codec).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.to_wire()
    }

    /// Parse the canonical wire form.
    ///
    /// # Errors
    /// [`DescriptorError::Malformed`] on any malformed or non-canonical input (including trailing bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self, DescriptorError> {
        Self::from_wire(bytes).map_err(|_| DescriptorError::Malformed)
    }
}

/// The 12-byte AEAD nonce for `(addr, epoch, salt)`. Folding in a per-publish `salt` is what makes a
/// mid-epoch republish safe: the deterministic `(addr, epoch)` nonce would reuse the same keystream and MAC
/// tag if the descriptor body changed within an epoch (a new rendezvous set), catastrophically leaking the
/// XOR of the two bodies. With the salt bound to the body (see [`nonce_salt`]) a changed body yields a
/// fresh nonce (audit E3).
fn nonce_bytes(addr: &Address, epoch: Epoch, salt: &[u8; SALT_LEN]) -> [u8; NONCE_LEN] {
    let mut input = Vec::with_capacity(33 + 8 + SALT_LEN);
    input.extend_from_slice(&addr.payload());
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(salt);
    let digest = hash_labeled(NONCE_LABEL, &input);
    let mut n = [0u8; NONCE_LEN];
    if let Some(prefix) = digest.get(..NONCE_LEN) {
        n.copy_from_slice(prefix);
    }
    n
}

/// The per-publish nonce salt, derived from the descriptor **plaintext** — a synthetic (SIV-style) nonce:
/// a *different* body always yields a *fresh* salt (hence a fresh AEAD nonce, so no keystream/MAC reuse on a
/// mid-epoch republish, E3), while an *identical* body yields an identical salt, which is safe (the same
/// message under the same nonce). It is carried in the wire form so the reader re-derives the nonce, and the
/// AEAD tag authenticates it — a swapped salt simply fails to decrypt. No entropy is required.
fn nonce_salt(plaintext: &[u8]) -> [u8; SALT_LEN] {
    let digest = hash_labeled(NONCE_SALT_LABEL, plaintext);
    let mut s = [0u8; SALT_LEN];
    if let Some(prefix) = digest.get(..SALT_LEN) {
        s.copy_from_slice(prefix);
    }
    s
}

/// The PoW challenge binding the address, epoch, and ciphertext.
fn pow_challenge(addr: &Address, epoch: Epoch, ciphertext: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(33 + 8 + ciphertext.len());
    c.extend_from_slice(&addr.payload());
    c.extend_from_slice(&epoch.to_le_bytes());
    c.extend_from_slice(ciphertext);
    c
}

/// The rotating coordinate a descriptor is published at (directory-free, unenumerable).
#[must_use]
pub fn publish_point<F: Field>(addr: &Address, epoch: Epoch) -> Point<F> {
    lookup_point::<F>(addr, epoch)
}

/// Seal `desc` for `addr` at `epoch`, encrypting under the address-gated key and stamping PoW at
/// `difficulty`.
///
/// # Errors
/// [`DescriptorError::Aead`] if encryption fails (only on absurd input sizes).
pub fn seal(
    addr: &Address,
    epoch: Epoch,
    desc: &Descriptor,
    difficulty: u32,
) -> Result<SealedDescriptor, DescriptorError> {
    let plaintext = desc.to_wire();
    let salt = nonce_salt(&plaintext);
    let nonce = nonce_bytes(addr, epoch, &salt);
    let ciphertext = fanos_primitives::aead::seal(&descriptor_key(addr, epoch), &nonce, &plaintext)
        .ok_or(DescriptorError::Aead)?;
    let pow_nonce = pow::solve(&pow_challenge(addr, epoch, &ciphertext), difficulty);
    Ok(SealedDescriptor {
        pow_nonce,
        nonce_salt: salt,
        ciphertext,
    })
}

/// Open a sealed descriptor for `addr` at `epoch`, requiring at least `difficulty` PoW.
///
/// Verifies (in order) the PoW, the AEAD (address-gated decryption), the epoch, and finally the
/// **self-certification** `H(bundle) == addr`.
///
/// # Errors
/// [`DescriptorError`] on any failed check — a storage node's junk blob simply fails here and the
/// caller moves on to the next candidate.
pub fn open(
    addr: &Address,
    epoch: Epoch,
    sealed: &SealedDescriptor,
    difficulty: u32,
) -> Result<Descriptor, DescriptorError> {
    if !pow::verify(
        &pow_challenge(addr, epoch, &sealed.ciphertext),
        sealed.pow_nonce,
        difficulty,
    ) {
        return Err(DescriptorError::BadPow);
    }
    let nonce = nonce_bytes(addr, epoch, &sealed.nonce_salt);
    let plaintext =
        fanos_primitives::aead::open(&descriptor_key(addr, epoch), &nonce, &sealed.ciphertext)
            .ok_or(DescriptorError::Aead)?;
    let desc = Descriptor::from_wire(&plaintext).map_err(|_| DescriptorError::Malformed)?;
    if desc.epoch != epoch {
        return Err(DescriptorError::EpochMismatch);
    }
    if !addr.verifies(&desc.bundle) {
        return Err(DescriptorError::NotCertified);
    }
    Ok(desc)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec;
    use fanos_field::F7;

    fn service() -> (Address, Vec<u8>) {
        let bundle = vec![0x5Au8; 128]; // stand-in hybrid bundle
        (Address::from_bundle(&bundle), bundle)
    }

    fn descriptor(epoch: Epoch, bundle: Vec<u8>) -> Descriptor {
        Descriptor {
            epoch,
            bundle,
            metadata: vec![1, 2, 3],
            cert: vec![9, 9],
            sig: vec![7; 8],
        }
    }

    #[test]
    fn seal_open_round_trips() {
        let (addr, bundle) = service();
        let desc = descriptor(Epoch::new(42), bundle);
        let sealed = seal(&addr, Epoch::new(42), &desc, 4).unwrap();
        let opened = open(&addr, Epoch::new(42), &sealed, 4).unwrap();
        assert_eq!(opened, desc);
    }

    #[test]
    fn a_mid_epoch_republish_of_a_changed_body_uses_a_fresh_nonce() {
        // E3: within one epoch, re-sealing a *different* descriptor body must NOT reuse the AEAD nonce
        // (which would leak the XOR of the two bodies). The salt is bound to the body, so a changed body
        // yields a fresh salt → a fresh nonce.
        let (addr, bundle) = service();
        let epoch = Epoch::new(5);
        let d1 = descriptor(epoch, bundle.clone());
        let mut d2 = descriptor(epoch, bundle);
        d2.metadata = vec![0xAB; 40]; // a changed rendezvous set — same addr, same epoch

        let s1 = seal(&addr, epoch, &d1, 0).unwrap();
        let s2 = seal(&addr, epoch, &d2, 0).unwrap();
        assert_ne!(
            s1.nonce_salt, s2.nonce_salt,
            "a changed body yields a fresh nonce salt"
        );
        assert_ne!(
            nonce_bytes(&addr, epoch, &s1.nonce_salt),
            nonce_bytes(&addr, epoch, &s2.nonce_salt),
            "hence a fresh AEAD nonce — no keystream/MAC reuse on the republish"
        );

        // Both still open correctly (the salt round-trips through the wire form and is authenticated).
        assert_eq!(open(&addr, epoch, &s1, 0).unwrap(), d1);
        assert_eq!(open(&addr, epoch, &s2, 0).unwrap(), d2);
        assert_eq!(
            SealedDescriptor::decode(&s2.encode()).unwrap(),
            s2,
            "wire form carries the salt"
        );

        // An identical body re-seals to the identical salt — deterministic and safe (same message).
        assert_eq!(
            seal(&addr, epoch, &d1, 0).unwrap().nonce_salt,
            s1.nonce_salt
        );
    }

    #[test]
    fn wrong_address_cannot_decrypt() {
        let (addr, bundle) = service();
        // Difficulty 0 isolates the AEAD gate (PoW is address-bound, so a non-zero difficulty
        // would make a wrong address fail at the PoW stage first — also a rejection).
        let sealed = seal(
            &addr,
            Epoch::new(42),
            &descriptor(Epoch::new(42), bundle),
            0,
        )
        .unwrap();
        let other = Address::from_bundle(b"a-different-service");
        // The other address derives a different key → AEAD fails.
        assert_eq!(
            open(&other, Epoch::new(42), &sealed, 0),
            Err(DescriptorError::Aead)
        );
    }

    #[test]
    fn impersonation_is_rejected() {
        // A descriptor whose bundle does not match the address must not certify it.
        let (addr, _) = service();
        let forged = descriptor(Epoch::new(42), vec![0xFFu8; 64]); // bundle != addr's bundle
        let sealed = seal(&addr, Epoch::new(42), &forged, 4).unwrap();
        assert_eq!(
            open(&addr, Epoch::new(42), &sealed, 4),
            Err(DescriptorError::NotCertified)
        );
    }

    #[test]
    fn insufficient_pow_is_rejected() {
        let (addr, bundle) = service();
        let sealed = seal(
            &addr,
            Epoch::new(42),
            &descriptor(Epoch::new(42), bundle),
            1,
        )
        .unwrap();
        // Require far more work than was stamped.
        assert!(matches!(
            open(&addr, Epoch::new(42), &sealed, 40),
            Err(DescriptorError::BadPow)
        ));
    }

    #[test]
    fn a_tampered_stored_descriptor_is_rejected() {
        // DHT poisoning: a sealed descriptor sits in a MUTABLE DHT slot, so a storage node — or anyone
        // who can overwrite the slot — may flip its bytes. Every such tamper fails the address-gated
        // AEAD on open, so the resolver rejects the poisoned blob and falls through to the next replica.
        // Difficulty 0 isolates the AEAD gate (a non-zero PoW would reject a changed ciphertext earlier).
        let (addr, bundle) = service();

        let mut ct_tampered = seal(
            &addr,
            Epoch::new(7),
            &descriptor(Epoch::new(7), bundle.clone()),
            0,
        )
        .unwrap();
        if let Some(b) = ct_tampered.ciphertext.first_mut() {
            *b ^= 0x01;
        }
        assert_eq!(
            open(&addr, Epoch::new(7), &ct_tampered, 0),
            Err(DescriptorError::Aead),
            "a flipped ciphertext byte fails the AEAD tag"
        );

        let mut salt_tampered =
            seal(&addr, Epoch::new(7), &descriptor(Epoch::new(7), bundle), 0).unwrap();
        if let Some(b) = salt_tampered.nonce_salt.first_mut() {
            *b ^= 0x01;
        }
        assert_eq!(
            open(&addr, Epoch::new(7), &salt_tampered, 0),
            Err(DescriptorError::Aead),
            "a flipped nonce salt yields the wrong nonce → AEAD failure"
        );
    }

    #[test]
    fn a_descriptor_replayed_into_another_epoch_is_rejected() {
        // Cross-epoch replay: a valid descriptor captured at one epoch cannot be re-served at the next —
        // the slot, the address-gated key, and the nonce are all epoch-bound.
        let (addr, bundle) = service();
        let sealed = seal(&addr, Epoch::new(7), &descriptor(Epoch::new(7), bundle), 0).unwrap();
        assert_eq!(
            open(&addr, Epoch::new(8), &sealed, 0),
            Err(DescriptorError::Aead),
            "an epoch-7 descriptor does not open under epoch 8's address-gated key"
        );
        assert_ne!(
            publish_point::<F7>(&addr, Epoch::new(7)),
            publish_point::<F7>(&addr, Epoch::new(8)),
            "and the DHT slot rotates per epoch, so a stale descriptor is not even found there"
        );
    }

    #[test]
    fn epoch_mismatch_is_rejected() {
        let (addr, bundle) = service();
        let sealed = seal(
            &addr,
            Epoch::new(42),
            &descriptor(Epoch::new(42), bundle),
            4,
        )
        .unwrap();
        // Same slot key only if epoch matches; here we open at a different epoch → AEAD/epoch fail.
        assert!(open(&addr, Epoch::new(7), &sealed, 4).is_err());
    }

    #[test]
    fn publish_point_rotates_per_epoch() {
        let (addr, _) = service();
        assert_ne!(
            publish_point::<F7>(&addr, Epoch::new(1)),
            publish_point::<F7>(&addr, Epoch::new(2))
        );
    }

    #[test]
    fn signature_binding_is_verifiable() {
        let (addr, bundle) = service();
        let desc = descriptor(Epoch::new(5), bundle);
        let _ = addr;
        let expected = desc.signing_bytes();
        assert!(desc.verify_signature(|msg, sig| msg == expected.as_slice() && sig == [7u8; 8]));
        assert!(!desc.verify_signature(|_, _| false));
    }
}
