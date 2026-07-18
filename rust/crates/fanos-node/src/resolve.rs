//! `.fanos` name resolution — the ONOMA resolver wired to the node's L4 store.
//!
//! The node fetches the service descriptor from its rotating, unenumerable epoch slot
//! `L = H(addr ‖ epoch)`, then **verifies it client-side** before returning anything: the
//! post-quantum self-certification `H(bundle) == addr` is checked here, so a malicious store can
//! never induce impersonation (`docs/design-names.md` §5–§6). See [`crate::node::Node::resolve`]
//! for the network plumbing; [`verify_descriptor`] is the pure, security-critical core.

use std::future::Future;
use std::time::Duration;

use fanos_calypso::descriptor::{Descriptor, SealedDescriptor, open, seal};
use fanos_diaulos::{Coord, service_public_from_bundle};
use fanos_onoma::{Address, lookup_key};
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;

use crate::diaulos::ServiceResolver;
use crate::error::NodeError;

/// The service's overlay coordinate occupies the first 12 bytes of a descriptor's metadata (three
/// big-endian `u32`s), before any opaque profile bytes. A Direct-profile client dials this coordinate;
/// it need not be authenticated on its own — the DIAULOS handshake binds the session to the service's
/// KEM key from the bundle, so a wrong coordinate only fails the dial, it cannot impersonate.
const COORD_META_LEN: usize = 12;

fn encode_coord(coord: Coord) -> [u8; COORD_META_LEN] {
    let mut out = [0u8; COORD_META_LEN];
    let (chunks, _) = out.as_chunks_mut::<4>();
    for (chunk, w) in chunks.iter_mut().zip(coord) {
        *chunk = w.to_be_bytes();
    }
    out
}

fn decode_coord(metadata: &[u8]) -> Option<Coord> {
    let head = metadata.get(..COORD_META_LEN)?;
    let (chunks, _) = head.as_chunks::<4>();
    let mut coord = [0u32; 3];
    for (slot, chunk) in coord.iter_mut().zip(chunks) {
        *slot = u32::from_be_bytes(*chunk);
    }
    Some(coord)
}

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

/// Publish a **Direct-profile** service descriptor over the overlay store: seal the service's hybrid
/// key `bundle` and overlay `coord` (with any `extra` metadata) into the address's rotating epoch slot
/// `L = H(addr ‖ epoch)`, gated by a `difficulty`-bit proof of work. Clients then [`resolve`] the name
/// to `(coord, key)` with no directory. `bundle` must be the canonical bundle the `.fanos` address
/// certifies (`H(bundle) == address`).
///
/// # Errors
/// [`NodeError::Resolve`] if sealing fails or the store rejects the write.
pub async fn publish_service(
    client: &Client,
    bundle: &[u8],
    coord: Coord,
    epoch: u64,
    difficulty: u32,
    extra: &[u8],
) -> Result<(), NodeError> {
    let address = Address::from_bundle(bundle);
    let mut metadata = encode_coord(coord).to_vec();
    metadata.extend_from_slice(extra);
    let descriptor = Descriptor {
        epoch,
        bundle: bundle.to_vec(),
        metadata,
        cert: Vec::new(),
        sig: Vec::new(),
    };
    let sealed = seal(&address, epoch, &descriptor, difficulty)
        .map_err(|e| NodeError::Resolve(format!("sealing the descriptor failed: {e:?}")))?;
    let slot = lookup_key(&address, epoch).to_vec();
    if client.put(slot, sealed.encode()).await {
        Ok(())
    } else {
        Err(NodeError::Resolve("the store rejected the descriptor".to_string()))
    }
}

/// A [`ServiceResolver`] backed by the live overlay: it resolves a `.fanos` name to the service's
/// `(coordinate, KEM key)` by fetching and authenticating the published descriptor (the real ONOMA
/// path, as opposed to a fixed [`StaticResolver`](crate::diaulos::StaticResolver)). This is what a
/// [`FanosDialer`](crate::diaulos::FanosDialer) uses in production.
/// How long a store lookup (a descriptor or a mix key) waits before giving up, so a Get that never
/// resolves fails the resolution instead of hanging the caller forever.
pub(crate) const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct NodeResolver {
    client: Client,
    epoch: u64,
    min_pow: u32,
}

impl NodeResolver {
    /// Resolve descriptors from `client`'s store for `epoch`, requiring at least `min_pow` PoW bits.
    #[must_use]
    pub fn new(client: Client, epoch: u64, min_pow: u32) -> Self {
        Self {
            client,
            epoch,
            min_pow,
        }
    }
}

impl ServiceResolver for NodeResolver {
    fn resolve(
        &self,
        host: &str,
    ) -> impl Future<Output = Option<(Coord, HybridKemPublic)>> + Send {
        let client = self.client.clone();
        let epoch = self.epoch;
        let min_pow = self.min_pow;
        let host = host.to_owned();
        async move {
            let address = Address::parse(&host).ok()?;
            let slot = lookup_key(&address, epoch).to_vec();
            // Bound the store lookup: a Get that never resolves (unknown key, unreachable responsible
            // node) must fail the resolution rather than hang the dial forever.
            let blob = tokio::time::timeout(RESOLVE_TIMEOUT, client.get(slot))
                .await
                .ok()??;
            let resolved = verify_descriptor(&address, epoch, &blob, min_pow).ok()?;
            let coord = decode_coord(&resolved.metadata)?;
            let public = service_public_from_bundle(&resolved.bundle)?;
            Some((coord, public))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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

    #[test]
    fn coord_round_trips_through_metadata() {
        let coord = [7u32, 13, 31];
        assert_eq!(decode_coord(&encode_coord(coord)), Some(coord));
        // Trailing profile bytes after the 12-byte coordinate are ignored by the decoder.
        let mut m = encode_coord(coord).to_vec();
        m.extend_from_slice(b"profiles=direct");
        assert_eq!(decode_coord(&m), Some(coord));
        // Metadata too short to hold a coordinate → None.
        assert_eq!(decode_coord(&[0u8; COORD_META_LEN - 1]), None);
    }

    #[test]
    fn a_published_descriptor_yields_its_coordinate_and_key() {
        use fanos_diaulos::{bundle_from_kem_public, service_public_from_bundle};
        use fanos_pqcrypto::{HybridKemSecret, SeedRng};

        // The KEM identity a service would publish, wrapped in a self-certifying bundle.
        let mut rng = SeedRng::from_seed(b"resolve-extract");
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        let bundle = bundle_from_kem_public(&public);
        let address = Address::from_bundle(&bundle);
        let coord = [3u32, 5, 7];

        // Exactly the sealed blob `publish_service` writes to the store.
        let mut metadata = encode_coord(coord).to_vec();
        metadata.extend_from_slice(b"profiles=direct");
        let desc = Descriptor {
            epoch: 9,
            bundle: bundle.clone(),
            metadata,
            cert: Vec::new(),
            sig: Vec::new(),
        };
        let blob = seal(&address, 9, &desc, 4).unwrap().encode();

        // What NodeResolver::resolve does once it has fetched the blob: authenticate, then recover the
        // coordinate and the KEM key.
        let resolved = verify_descriptor(&address, 9, &blob, 0).unwrap();
        assert_eq!(decode_coord(&resolved.metadata), Some(coord));
        let extracted = service_public_from_bundle(&resolved.bundle).unwrap();
        let (ct, k) = extracted.encapsulate(&mut rng);
        assert_eq!(secret.decapsulate(&ct), k, "resolved the service's real KEM key");
    }
}
