//! Threshold-hosted services — no single host to raid (spec §12.3).
//!
//! A classic hidden service runs on one host; seize it and the service dies. A CALYPSO service
//! is hosted **across the `q+1` members of a service-line**: the service secret is Shamir-
//! shared, so any `t` members serve a request and **fewer than `t` seized hosts learn nothing**
//! (0-knowledge — the same threshold guarantee as NYX §5.2). The service *is the line*, not a
//! machine — there is nothing to raid, and a corrupt host is caught by DIAKRISIS and repaired.

use alloc::vec::Vec;

use fanos_primitives::shamir::{self, ShamirError};

pub use fanos_primitives::shamir::Share;

/// Shard a service secret across the `line_size` members of a service-line, so any `threshold`
/// of them can reconstruct it (spec §12.3). `randomness` supplies the sharing polynomial.
pub fn shard_service_key(
    service_secret: &[u8],
    threshold: u8,
    line_size: u8,
    randomness: &[u8],
) -> Result<Vec<Share>, ShamirError> {
    shamir::split(service_secret, threshold, line_size, randomness)
}

/// Recover the service secret from `threshold` (or more) member shares.
pub fn recover_service_key(host_shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    shamir::reconstruct(host_shares)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn fixture_randomness(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 149 + 5) % 251) as u8).collect()
    }

    #[test]
    fn any_threshold_of_hosts_serves_the_request() {
        // A service hosted 5-of-8 across its line.
        let secret = b"service private key material";
        let rnd = fixture_randomness(4 * secret.len());
        let shares = shard_service_key(secret, 5, 8, &rnd).unwrap();
        assert_eq!(shares.len(), 8);
        // Any 5 members reconstruct.
        assert_eq!(recover_service_key(&shares[1..6]).unwrap(), secret);
        assert_eq!(recover_service_key(&shares[3..8]).unwrap(), secret);
    }

    #[test]
    fn below_threshold_seizure_learns_nothing() {
        let secret = b"seizure-proof key";
        let rnd = fixture_randomness(4 * secret.len());
        let shares = shard_service_key(secret, 5, 8, &rnd).unwrap();
        // Four seized hosts (t-1) cannot recover the key.
        assert_ne!(recover_service_key(&shares[0..4]).unwrap(), secret);
    }
}
