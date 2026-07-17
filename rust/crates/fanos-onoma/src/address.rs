//! The L-key **self-certifying address**: a post-quantum commitment to a key bundle.
//!
//! `addr = version ‖ BLAKE3-256(bundle)`, encoded as bech32m under the stable HRP `onoma` and
//! displayed as `<label>.<tld>` (default `.fanos`). The address is a 256-bit commitment to the
//! *whole* hybrid PQ bundle, so a quantum adversary still needs a `2^128` second-preimage to forge
//! a different key with the same name. Verification is client-side: fetch the descriptor, recompute
//! `BLAKE3-256(bundle)`, and require it to equal the commitment.

use alloc::string::String;

use fanos_crypto::hash::{hash_labeled, label};

use crate::bech32;
use crate::error::OnomaError;
use crate::mnemonic;

/// The stable bech32m human-readable part (the checksum context). Independent of the display TLD.
pub const HRP: &str = "onoma";

/// The default display TLD. It is **display-only and swappable** — the address is stored and routed
/// by its payload commitment, never by this suffix, so changing it is a configuration change, not a
/// protocol fork (see `docs/design-names.md` §8).
pub const DEFAULT_TLD: &str = "fanos";

/// The commitment (address hash) length, in bytes.
pub const COMMITMENT_LEN: usize = 32;

/// The wire payload length: `version(1) ‖ commitment(32)`.
const PAYLOAD_LEN: usize = 1 + COMMITMENT_LEN;

/// A self-certifying ONOMA address (L-key).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Address {
    version: u8,
    commitment: [u8; COMMITMENT_LEN],
}

impl Address {
    /// The current address version (crypto recipe: BLAKE3-256 over the hybrid PQ bundle).
    pub const CURRENT_VERSION: u8 = 1;

    /// Derive the address that certifies `bundle` (the canonical-encoded hybrid public keys).
    #[must_use]
    pub fn from_bundle(bundle: &[u8]) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            commitment: hash_labeled(label::ONOMA_ADDR, bundle),
        }
    }

    /// Assemble from an explicit version and commitment.
    ///
    /// # Errors
    /// [`OnomaError::Unsupported`] if the version is not understood by this implementation.
    pub fn from_parts(version: u8, commitment: [u8; COMMITMENT_LEN]) -> Result<Self, OnomaError> {
        if version != Self::CURRENT_VERSION {
            return Err(OnomaError::Unsupported(version));
        }
        Ok(Self {
            version,
            commitment,
        })
    }

    /// The address version byte.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// The 32-byte commitment.
    #[must_use]
    pub const fn commitment(&self) -> &[u8; COMMITMENT_LEN] {
        &self.commitment
    }

    /// Whether this address certifies `bundle` — the client-side security check.
    #[must_use]
    pub fn verifies(&self, bundle: &[u8]) -> bool {
        self.version == Self::CURRENT_VERSION
            && hash_labeled(label::ONOMA_ADDR, bundle) == self.commitment
    }

    /// The canonical wire payload `version ‖ commitment`.
    #[must_use]
    pub fn payload(&self) -> [u8; PAYLOAD_LEN] {
        let mut p = [0u8; PAYLOAD_LEN];
        if let Some((first, rest)) = p.split_first_mut() {
            *first = self.version;
            rest.copy_from_slice(&self.commitment);
        }
        p
    }

    fn from_payload(p: &[u8]) -> Result<Self, OnomaError> {
        let (version, rest) = p.split_first().ok_or(OnomaError::BadLength)?;
        if rest.len() != COMMITMENT_LEN {
            return Err(OnomaError::BadLength);
        }
        let mut commitment = [0u8; COMMITMENT_LEN];
        commitment.copy_from_slice(rest);
        Self::from_parts(*version, commitment)
    }

    /// The full bech32m string, `onoma1<label>` (rarely shown; prefer [`Self::to_name`]).
    #[must_use]
    pub fn to_bech32(&self) -> String {
        bech32::encode(HRP, &self.payload())
    }

    /// The canonical display name, `<label>.fanos`.
    #[must_use]
    pub fn to_name(&self) -> String {
        self.to_name_with_tld(DEFAULT_TLD)
    }

    /// The display name under an explicit (swappable) TLD.
    #[must_use]
    pub fn to_name_with_tld(&self, tld: &str) -> String {
        let full = self.to_bech32();
        let label = match full.strip_prefix("onoma1") {
            Some(l) => l,
            None => full.as_str(),
        };
        let mut s = String::with_capacity(label.len() + 1 + tld.len());
        s.push_str(label);
        s.push('.');
        s.push_str(tld);
        s
    }

    /// A dictionary-free, pronounceable rendering for human verification (`v1-lusab-…`).
    #[must_use]
    pub fn mnemonic(&self) -> String {
        mnemonic::encode_commitment(self.version, &self.commitment)
    }

    /// Parse a canonical `<label>.fanos` name (or a raw `onoma1…` bech32m string).
    ///
    /// # Errors
    /// [`OnomaError`] on a wrong TLD, checksum failure, or unsupported version.
    pub fn parse(name: &str) -> Result<Self, OnomaError> {
        Self::parse_in_tld(name, DEFAULT_TLD)
    }

    /// Parse a name whose display TLD is `tld` (for a future/alternate TLD).
    ///
    /// # Errors
    /// [`OnomaError`] on a wrong TLD, checksum failure, or unsupported version.
    pub fn parse_in_tld(name: &str, tld: &str) -> Result<Self, OnomaError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(OnomaError::Empty);
        }
        let mut dotted = String::with_capacity(tld.len() + 1);
        dotted.push('.');
        dotted.push_str(tld);
        let bech = if let Some(lbl) = name.strip_suffix(dotted.as_str()) {
            if lbl.starts_with("onoma1") {
                String::from(lbl)
            } else {
                let mut b = String::with_capacity(6 + lbl.len());
                b.push_str("onoma1");
                b.push_str(lbl);
                b
            }
        } else if name.starts_with("onoma1") {
            String::from(name)
        } else {
            return Err(OnomaError::WrongTld);
        };
        let (hrp, payload) = bech32::decode(&bech)?;
        if hrp != HRP {
            return Err(OnomaError::WrongTld);
        }
        Self::from_payload(&payload)
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_name())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn bundle(fill: u8) -> Vec<u8> {
        vec![fill; 3200] // 32 + 1952 + 32 + 1184 = hybrid bundle length
    }

    #[test]
    fn address_round_trips_through_name() {
        let a = Address::from_bundle(&bundle(7));
        let name = a.to_name();
        assert!(name.strip_suffix(".fanos").is_some());
        let b = Address::parse(&name).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn self_certification_holds_and_rejects_wrong_bundle() {
        let a = Address::from_bundle(&bundle(7));
        assert!(a.verifies(&bundle(7)));
        assert!(!a.verifies(&bundle(8)));
    }

    #[test]
    fn one_flipped_character_is_rejected() {
        let a = Address::from_bundle(&bundle(1));
        let mut name = a.to_name().into_bytes();
        // Flip the first label char (not the '.fanos' suffix).
        if let Some(first) = name.first_mut() {
            *first = if *first == b'q' { b'p' } else { b'q' };
        }
        let corrupted = String::from_utf8(name).unwrap();
        assert!(matches!(
            Address::parse(&corrupted),
            Err(OnomaError::BadChecksum)
        ));
    }

    #[test]
    fn label_fits_in_a_dns_label() {
        let a = Address::from_bundle(&bundle(3));
        let name = a.to_name();
        let lbl = name.strip_suffix(".fanos").unwrap();
        assert!(
            lbl.len() <= 63,
            "label {} chars exceeds DNS limit",
            lbl.len()
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        assert_eq!(
            Address::from_parts(2, [0u8; 32]),
            Err(OnomaError::Unsupported(2))
        );
    }

    #[test]
    fn wrong_tld_is_rejected() {
        let a = Address::from_bundle(&bundle(4));
        let name = a.to_name();
        let lbl = name.strip_suffix(".fanos").unwrap();
        // Same label under a different display TLD parses only with the matching tld.
        let other = alloc::format!("{lbl}.example");
        assert_eq!(Address::parse(&other), Err(OnomaError::WrongTld));
        assert_eq!(Address::parse_in_tld(&other, "example").unwrap(), a);
    }
}
