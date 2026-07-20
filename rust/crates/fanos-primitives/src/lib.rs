//! # fanos-primitives — the cryptographic surface
//!
//! FANOS's novelty is the *architectural composition* of vetted post-quantum primitives, not
//! new hardness (spec §L6). This crate provides the composition points the rest of the stack
//! needs, with the vetted primitives left pluggable:
//!
//! * [`hash`] — domain-separated BLAKE3 and the FANOS label registry (§7.1).
//! * [`maptopoint`] — `MapToPoint` / `MapToLine`, uniform hashing into `PG(2, q)` (§7.1, L0).
//! * [`address`] — self-certifying hierarchical addresses: the identity→address chain and its
//!   verifier, the single source of truth for the `MapToPoint` descent (§L0, §L1).
//! * [`shamir`] — Shamir secret sharing over `GF(256)`: the threshold substrate (§L6, §5.2).
//! * [`keys`] — hybrid PQ key bundles and the node identifier (§L0).
//! * [`vrf`] — the VRF surface for epoch-bound coordinate/rendezvous derivation (§L0, §5.6).
//!
//! `#![no_std]` with `alloc`; BLAKE3 is the only external dependency.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod address;
#[cfg(feature = "aead")]
pub mod aead;
pub mod beacon;
pub mod epoch;
pub mod hash;
pub mod keys;
pub mod maptopoint;
pub mod shamir;
pub mod vrf;

pub use address::{address_matches_identity, address_matches_identity_from, address_point};
pub use beacon::BeaconSeed;
pub use epoch::Epoch;
pub use hash::{DIGEST_LEN, hash_labeled, label, subkey};
pub use keys::{HybridPublicKey, NodeId};
pub use maptopoint::{map_to_line, map_to_point, storage_digest, storage_point};
pub use shamir::{Share, reconstruct, split};
pub use vrf::{coordinate_for, coordinate_from_vrf, rendezvous_line};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    //! End-to-end: identity → coordinate → threshold-shared secret on a line.
    use super::*;
    use fanos_field::F31;
    use fanos_geometry::Point;

    #[test]
    fn identity_to_coordinate_pipeline() {
        // A node's bundle hashes to an ID, which (with an epoch) derives a cell coordinate.
        let node = NodeId([42u8; 32]);
        let coord = coordinate_for::<F31>(&node, Epoch::new(7));
        assert_eq!(Point::<F31>::at(coord.index()), coord);
    }

    #[test]
    fn threshold_secret_survives_below_quorum_loss() {
        // A line's secret split 5-of-8: any 5 members reconstruct, matching NYX's t-of-(q+1).
        let secret = b"line private key";
        let rnd: Vec<u8> = (0..4 * secret.len())
            .map(|i| (i as u8).wrapping_mul(31))
            .collect();
        let shares = split(secret, 5, 8, &rnd).unwrap();
        let subset = &shares[2..7]; // any 5
        assert_eq!(reconstruct(subset).unwrap(), secret);
    }
}
