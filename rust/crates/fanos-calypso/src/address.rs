//! Self-certifying `.fanos` service addresses (spec §12.1).
//!
//! A CALYPSO address is `base32(BLAKE3(service_pubkey)).fanos` — the address *is* the key
//! hash, so there is no CA and no naming authority, and anyone can check that an address
//! belongs to a public key. It is the post-quantum analogue of a Tor v3 `.onion`.

use alloc::string::String;

use fanos_crypto::hash_labeled;

/// The base32 alphabet (RFC 4648, lower-case, no padding).
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const ADDRESS_LABEL: &str = "FANOS-v1/calypso-addr";
const TLD: &str = ".fanos";

/// Encode bytes as lower-case base32 (no padding).
// `idx` is masked to 5 bits (`& 0x1f`), always `< 32 == ALPHABET.len()`, so the lookups are
// safe by construction.
#[allow(clippy::indexing_slicing)]
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(char::from(ALPHABET[idx]));
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(ALPHABET[idx]));
    }
    out
}

/// A self-certifying CALYPSO service address (the base32 label, without the `.fanos` suffix).
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct ServiceAddress {
    label: String,
}

impl ServiceAddress {
    /// Derive the address from a service's public-key bytes (spec §12.1).
    #[must_use]
    pub fn from_pubkey(service_pubkey: &[u8]) -> Self {
        let hash = hash_labeled(ADDRESS_LABEL, service_pubkey);
        Self {
            label: base32_encode(&hash),
        }
    }

    /// The base32 label (without the TLD).
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Whether this address self-certifies the given public key (the defining property).
    #[must_use]
    pub fn certifies(&self, service_pubkey: &[u8]) -> bool {
        Self::from_pubkey(service_pubkey) == *self
    }
}

impl core::fmt::Display for ServiceAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{TLD}", self.label)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::case_sensitive_file_extension_comparisons
)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn address_is_self_certifying() {
        let pubkey = b"service-public-key-bytes";
        let address = ServiceAddress::from_pubkey(pubkey);
        // The address certifies its own key, and no other.
        assert!(address.certifies(pubkey));
        assert!(!address.certifies(b"a-different-key"));
    }

    #[test]
    fn address_is_deterministic_and_suffixed() {
        let pubkey = b"svc";
        let a = ServiceAddress::from_pubkey(pubkey);
        let b = ServiceAddress::from_pubkey(pubkey);
        assert_eq!(a, b);
        assert!(a.to_string().ends_with(".fanos"));
        // A 32-byte hash → 52 base32 characters.
        assert_eq!(a.label().len(), 52);
    }

    #[test]
    fn distinct_keys_give_distinct_addresses() {
        assert_ne!(
            ServiceAddress::from_pubkey(b"key-a"),
            ServiceAddress::from_pubkey(b"key-b")
        );
    }

    #[test]
    fn base32_is_rfc4648_lowercase() {
        // Known vector: five zero bytes → "aaaaaaaa".
        assert_eq!(base32_encode(&[0, 0, 0, 0, 0]), "aaaaaaaa");
        // 0xFF byte → first char is the top 5 bits (11111 = '7').
        assert_eq!(base32_encode(&[0xFF]).chars().next().unwrap(), '7');
    }
}
