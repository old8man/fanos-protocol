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

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use fanos_crypto::hash::hash_labeled;
use fanos_field::Field;
use fanos_geometry::Point;
use fanos_onoma::Address;
use fanos_onoma::derive::{descriptor_key, lookup_point};

use crate::pow;

const NONCE_LABEL: &str = "FANOS-v1/onoma-desc-nonce";
const SIGN_LABEL: &str = "FANOS-v1/onoma-desc-sign";
const NONCE_LEN: usize = 12;

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

/// A service descriptor (plaintext form).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Descriptor {
    /// The epoch this descriptor is valid for.
    pub epoch: u64,
    /// The canonical hybrid public-key bundle — opens the address commitment.
    pub bundle: Vec<u8>,
    /// Opaque service metadata (supported profiles, intro policy, …).
    pub metadata: Vec<u8>,
    /// The offline-root→epoch signing certificate (scheme-agnostic bytes).
    pub cert: Vec<u8>,
    /// The epoch key's signature over [`Descriptor::signing_bytes`] (scheme-agnostic).
    pub sig: Vec<u8>,
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn read_u64(cur: &mut &[u8]) -> Option<u64> {
    let (head, tail) = cur.split_at_checked(8)?;
    *cur = tail;
    let mut a = [0u8; 8];
    a.copy_from_slice(head);
    Some(u64::from_le_bytes(a))
}

fn read_field(cur: &mut &[u8]) -> Option<Vec<u8>> {
    let (head, tail) = cur.split_at_checked(4)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(head);
    let n = u32::from_le_bytes(a) as usize;
    let (body, rest) = tail.split_at_checked(n)?;
    *cur = rest;
    Some(body.to_vec())
}

impl Descriptor {
    /// The canonical bytes an owner signs (everything except the signature itself).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(SIGN_LABEL.as_bytes());
        b.push(0x1f);
        b.extend_from_slice(&self.epoch.to_le_bytes());
        push_field(&mut b, &self.bundle);
        push_field(&mut b, &self.metadata);
        push_field(&mut b, &self.cert);
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

    /// Canonical serialization (the plaintext that gets encrypted).
    #[must_use]
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.epoch.to_le_bytes());
        push_field(&mut b, &self.bundle);
        push_field(&mut b, &self.metadata);
        push_field(&mut b, &self.cert);
        push_field(&mut b, &self.sig);
        b
    }

    fn decode(bytes: &[u8]) -> Result<Self, DescriptorError> {
        let mut cur = bytes;
        let epoch = read_u64(&mut cur).ok_or(DescriptorError::Malformed)?;
        let bundle = read_field(&mut cur).ok_or(DescriptorError::Malformed)?;
        let metadata = read_field(&mut cur).ok_or(DescriptorError::Malformed)?;
        let cert = read_field(&mut cur).ok_or(DescriptorError::Malformed)?;
        let sig = read_field(&mut cur).ok_or(DescriptorError::Malformed)?;
        if !cur.is_empty() {
            return Err(DescriptorError::Malformed); // canonical: no trailing bytes
        }
        Ok(Self {
            epoch,
            bundle,
            metadata,
            cert,
            sig,
        })
    }
}

/// A sealed (encrypted + PoW-stamped) descriptor, ready to publish at [`publish_point`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedDescriptor {
    /// The proof-of-work nonce over the ciphertext.
    pub pow_nonce: u64,
    /// `AEAD(descriptor_key(addr, epoch), nonce, encode(descriptor))`.
    pub ciphertext: Vec<u8>,
}

impl SealedDescriptor {
    /// Wire form: `pow_nonce(8 LE) ‖ ciphertext`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + self.ciphertext.len());
        b.extend_from_slice(&self.pow_nonce.to_le_bytes());
        b.extend_from_slice(&self.ciphertext);
        b
    }

    /// Parse the wire form.
    ///
    /// # Errors
    /// [`DescriptorError::Malformed`] if shorter than the 8-byte nonce prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, DescriptorError> {
        let (head, tail) = bytes
            .split_at_checked(8)
            .ok_or(DescriptorError::Malformed)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(head);
        Ok(Self {
            pow_nonce: u64::from_le_bytes(a),
            ciphertext: tail.to_vec(),
        })
    }
}

/// The deterministic 12-byte AEAD nonce for `(addr, epoch)` — safe because `K` is single-use per
/// address per epoch.
fn nonce_bytes(addr: &Address, epoch: u64) -> [u8; NONCE_LEN] {
    let mut input = Vec::with_capacity(33 + 8);
    input.extend_from_slice(&addr.payload());
    input.extend_from_slice(&epoch.to_le_bytes());
    let digest = hash_labeled(NONCE_LABEL, &input);
    let mut n = [0u8; NONCE_LEN];
    if let Some(prefix) = digest.get(..NONCE_LEN) {
        n.copy_from_slice(prefix);
    }
    n
}

/// The PoW challenge binding the address, epoch, and ciphertext.
fn pow_challenge(addr: &Address, epoch: u64, ciphertext: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(33 + 8 + ciphertext.len());
    c.extend_from_slice(&addr.payload());
    c.extend_from_slice(&epoch.to_le_bytes());
    c.extend_from_slice(ciphertext);
    c
}

/// The rotating coordinate a descriptor is published at (directory-free, unenumerable).
#[must_use]
pub fn publish_point<F: Field>(addr: &Address, epoch: u64) -> Point<F> {
    lookup_point::<F>(addr, epoch)
}

/// Seal `desc` for `addr` at `epoch`, encrypting under the address-gated key and stamping PoW at
/// `difficulty`.
///
/// # Errors
/// [`DescriptorError::Aead`] if encryption fails (only on absurd input sizes).
pub fn seal(
    addr: &Address,
    epoch: u64,
    desc: &Descriptor,
    difficulty: u32,
) -> Result<SealedDescriptor, DescriptorError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&descriptor_key(addr, epoch))
        .map_err(|_| DescriptorError::Aead)?;
    let nonce = nonce_bytes(addr, epoch);
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), desc.encode().as_ref())
        .map_err(|_| DescriptorError::Aead)?;
    let pow_nonce = pow::solve(&pow_challenge(addr, epoch, &ciphertext), difficulty);
    Ok(SealedDescriptor {
        pow_nonce,
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
    epoch: u64,
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
    let cipher = ChaCha20Poly1305::new_from_slice(&descriptor_key(addr, epoch))
        .map_err(|_| DescriptorError::Aead)?;
    let nonce = nonce_bytes(addr, epoch);
    let plaintext = cipher
        .decrypt(&Nonce::from(nonce), sealed.ciphertext.as_ref())
        .map_err(|_| DescriptorError::Aead)?;
    let desc = Descriptor::decode(&plaintext)?;
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

    fn descriptor(epoch: u64, bundle: Vec<u8>) -> Descriptor {
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
        let desc = descriptor(42, bundle);
        let sealed = seal(&addr, 42, &desc, 4).unwrap();
        let opened = open(&addr, 42, &sealed, 4).unwrap();
        assert_eq!(opened, desc);
    }

    #[test]
    fn wrong_address_cannot_decrypt() {
        let (addr, bundle) = service();
        // Difficulty 0 isolates the AEAD gate (PoW is address-bound, so a non-zero difficulty
        // would make a wrong address fail at the PoW stage first — also a rejection).
        let sealed = seal(&addr, 42, &descriptor(42, bundle), 0).unwrap();
        let other = Address::from_bundle(b"a-different-service");
        // The other address derives a different key → AEAD fails.
        assert_eq!(open(&other, 42, &sealed, 0), Err(DescriptorError::Aead));
    }

    #[test]
    fn impersonation_is_rejected() {
        // A descriptor whose bundle does not match the address must not certify it.
        let (addr, _) = service();
        let forged = descriptor(42, vec![0xFFu8; 64]); // bundle != addr's bundle
        let sealed = seal(&addr, 42, &forged, 4).unwrap();
        assert_eq!(
            open(&addr, 42, &sealed, 4),
            Err(DescriptorError::NotCertified)
        );
    }

    #[test]
    fn insufficient_pow_is_rejected() {
        let (addr, bundle) = service();
        let sealed = seal(&addr, 42, &descriptor(42, bundle), 1).unwrap();
        // Require far more work than was stamped.
        assert!(matches!(
            open(&addr, 42, &sealed, 40),
            Err(DescriptorError::BadPow)
        ));
    }

    #[test]
    fn epoch_mismatch_is_rejected() {
        let (addr, bundle) = service();
        let sealed = seal(&addr, 42, &descriptor(42, bundle), 4).unwrap();
        // Same slot key only if epoch matches; here we open at a different epoch → AEAD/epoch fail.
        assert!(open(&addr, 7, &sealed, 4).is_err());
    }

    #[test]
    fn publish_point_rotates_per_epoch() {
        let (addr, _) = service();
        assert_ne!(publish_point::<F7>(&addr, 1), publish_point::<F7>(&addr, 2));
    }

    #[test]
    fn signature_binding_is_verifiable() {
        let (addr, bundle) = service();
        let desc = descriptor(5, bundle);
        let _ = addr;
        let expected = desc.signing_bytes();
        assert!(desc.verify_signature(|msg, sig| msg == expected.as_slice() && sig == [7u8; 8]));
        assert!(!desc.verify_signature(|_, _| false));
    }
}
