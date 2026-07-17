//! `.fanos` name resolution — the ONOMA resolver wired to the node's L4 store.
//!
//! The node fetches the service descriptor from its rotating, unenumerable epoch slot
//! `L = H(addr ‖ epoch)`, then **verifies it client-side** before returning anything: the
//! post-quantum self-certification `H(bundle) == addr` is checked here, so a malicious store can
//! never induce impersonation (`docs/design-names.md` §5–§6). See [`crate::node::Node::resolve`]
//! for the network plumbing; [`verify_descriptor`] is the pure, security-critical core.

use fanos_calypso::descriptor::{SealedDescriptor, open};
use fanos_onoma::Address;

use crate::error::NodeError;

/// A resolved `.fanos` service: its self-certifying address plus the authenticated descriptor
/// contents for the queried epoch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedService {
    /// The self-certifying address the name resolved to.
    pub address: Address,
    /// The epoch the descriptor was published for.
    pub epoch: u64,
    /// The hybrid public-key bundle, verified to satisfy `H(bundle) == address`.
    pub bundle: Vec<u8>,
    /// Opaque service metadata (supported profiles, intro policy, …).
    pub metadata: Vec<u8>,
}

/// Decode and **authenticate** a fetched descriptor `blob` for `address` at `epoch`, requiring at
/// least `min_pow` proof-of-work. This is the client-side authority: the returned service is only
/// produced if the descriptor decrypts under the address-gated key and satisfies `H(bundle) == addr`.
///
/// # Errors
/// [`NodeError::Resolve`] if the blob is not a descriptor or fails verification (bad PoW, wrong
/// key, epoch mismatch, or a bundle that does not certify the address).
pub fn verify_descriptor(
    address: &Address,
    epoch: u64,
    blob: &[u8],
    min_pow: u32,
) -> Result<ResolvedService, NodeError> {
    let sealed = SealedDescriptor::decode(blob)
        .map_err(|_| NodeError::Resolve("stored blob is not a descriptor".to_string()))?;
    let desc = open(address, epoch, &sealed, min_pow)
        .map_err(|e| NodeError::Resolve(format!("descriptor failed verification: {e:?}")))?;
    Ok(ResolvedService {
        address: *address,
        epoch,
        bundle: desc.bundle,
        metadata: desc.metadata,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_calypso::descriptor::{Descriptor, seal};

    fn published(epoch: u64) -> (Address, Vec<u8>, Vec<u8>) {
        let bundle = b"resolver-unit-test-service".to_vec();
        let address = Address::from_bundle(&bundle);
        let desc = Descriptor {
            epoch,
            bundle: bundle.clone(),
            metadata: b"profiles=full".to_vec(),
            cert: Vec::new(),
            sig: Vec::new(),
        };
        let blob = seal(&address, epoch, &desc, 4).unwrap().encode();
        (address, bundle, blob)
    }

    #[test]
    fn authenticates_a_valid_descriptor() {
        let (address, bundle, blob) = published(3);
        let resolved = verify_descriptor(&address, 3, &blob, 0).unwrap();
        assert_eq!(resolved.address, address);
        assert_eq!(resolved.bundle, bundle);
        assert_eq!(resolved.metadata, b"profiles=full");
    }

    #[test]
    fn rejects_junk_and_wrong_epoch_and_wrong_address() {
        let (address, _, blob) = published(3);
        assert!(verify_descriptor(&address, 3, b"not-a-descriptor", 0).is_err());
        assert!(verify_descriptor(&address, 4, &blob, 0).is_err()); // epoch mismatch
        let other = Address::from_bundle(b"someone-else");
        assert!(verify_descriptor(&other, 3, &blob, 0).is_err()); // address-gated
    }

    #[test]
    fn enforces_a_minimum_pow() {
        let (address, _, blob) = published(3);
        // The descriptor was stamped at difficulty 4; requiring 40 bits rejects it.
        assert!(verify_descriptor(&address, 3, &blob, 40).is_err());
    }
}
