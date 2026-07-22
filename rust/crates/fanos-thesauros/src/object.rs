//! **Edge encryption** — sealing an object into stored, content-addressed ciphertext (`docs/design-storage.md`
//! §4, §8). Content is sealed *at the edge*, before it enters the store, so a provider only ever holds opaque
//! bytes: the E/privacy budget. Each plaintext chunk is AEAD-sealed under the object's fresh key with a
//! per-chunk nonce, the **ciphertext** is what gets addressed (its [`Cid`] is the Merkle root a provider is
//! audited against), and the [`Manifest`] lists the sealed chunks. Retrieval fetches each sealed chunk by CID,
//! checks it against that CID (integrity), and opens it — so tampering or a wrong key is caught.
//!
//! The key travels out of band (inside an end-to-end-encrypted ANGELOS message), never to the store. Because
//! the key is fresh per object, a plain counter nonce is unique per `(key, nonce)` — the AEAD's requirement.

use alloc::vec::Vec;

use fanos_primitives::aead;

use crate::content::{CHUNK, ChunkRef, Manifest, chunk_cid};

/// A sealed object ready to store: the [`Manifest`] (the handle, once its own bytes are stored) and the sealed
/// chunks, each addressed by its [`ChunkRef`] cid.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedObject {
    /// The manifest addressing the sealed chunks in order.
    pub manifest: Manifest,
    /// The sealed chunk ciphertexts, aligned with `manifest.chunks`.
    pub chunks: Vec<Vec<u8>>,
}

/// A per-chunk AEAD nonce from the chunk index (unique because the object key is fresh).
#[must_use]
fn nonce(index: usize) -> [u8; aead::NONCE_LEN] {
    let mut out = [0u8; aead::NONCE_LEN];
    if let Some(head) = out.get_mut(..8) {
        head.copy_from_slice(&(index as u64).to_le_bytes());
    }
    out
}

/// Seal `object` under `key`: split the plaintext into [`CHUNK`]-sized pieces, AEAD-seal each, address the
/// ciphertext, and build the manifest. The returned [`SealedObject`] is what a client stores (each chunk under
/// its cid, then the manifest under its own cid). An empty object seals to an empty manifest.
#[must_use]
pub fn seal_object(object: &[u8], key: &[u8; aead::KEY_LEN]) -> SealedObject {
    let mut chunks = Vec::new();
    let mut refs = Vec::new();
    for (i, plain) in object.chunks(CHUNK).enumerate() {
        let sealed = aead::seal(key, &nonce(i), plain).unwrap_or_default();
        refs.push(ChunkRef { cid: chunk_cid(&sealed), len: u32::try_from(sealed.len()).unwrap_or(u32::MAX) });
        chunks.push(sealed);
    }
    SealedObject { manifest: Manifest { chunks: refs }, chunks }
}

/// Open a sealed object: for each manifest entry, check the supplied sealed chunk addresses to the committed cid
/// (integrity), then AEAD-open it under `key`, concatenating the plaintext. `None` if a chunk is missing, does
/// not match its cid, or fails authentication (tamper or wrong key). `sealed_chunks` must align with the
/// manifest order.
#[must_use]
pub fn open_object(manifest: &Manifest, sealed_chunks: &[Vec<u8>], key: &[u8; aead::KEY_LEN]) -> Option<Vec<u8>> {
    if sealed_chunks.len() != manifest.chunks.len() {
        return None;
    }
    let mut out = Vec::new();
    for (i, (entry, sealed)) in manifest.chunks.iter().zip(sealed_chunks).enumerate() {
        if chunk_cid(sealed) != entry.cid {
            return None; // the stored bytes are not what the manifest committed to
        }
        let plain = aead::open(key, &nonce(i), sealed)?;
        out.extend_from_slice(&plain);
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x2Bu8; 32];

    #[test]
    fn an_object_seals_and_opens_round_trip() {
        // A multi-chunk object.
        let object: Vec<u8> = (0..CHUNK * 2 + 777).map(|i| (i * 5 + 1) as u8).collect();
        let sealed = seal_object(&object, &KEY);
        assert_eq!(sealed.chunks.len(), 3, "two full chunks + a partial one");
        assert_eq!(sealed.manifest.chunks.len(), 3);
        // The store holds ciphertext, not plaintext.
        assert_ne!(sealed.chunks[0].as_slice(), &object[..CHUNK], "the stored chunk is sealed, not plaintext");
        // Retrieval verifies + decrypts back to the original.
        assert_eq!(open_object(&sealed.manifest, &sealed.chunks, &KEY).as_deref(), Some(object.as_slice()));
    }

    #[test]
    fn the_wrong_key_or_a_tampered_chunk_cannot_open() {
        let object: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        let sealed = seal_object(&object, &KEY);
        // The wrong key fails authentication.
        assert!(open_object(&sealed.manifest, &sealed.chunks, &[0x99; 32]).is_none(), "wrong key refused");
        // A tampered chunk no longer matches its cid.
        let mut tampered = sealed.chunks.clone();
        let last = tampered[0].len() - 1;
        tampered[0][last] ^= 0xFF;
        assert!(open_object(&sealed.manifest, &tampered, &KEY).is_none(), "a tampered chunk is refused");
        // A missing chunk (count mismatch) is refused.
        let short = &sealed.chunks[..sealed.chunks.len() - 1];
        assert!(open_object(&sealed.manifest, short, &KEY).is_none(), "a missing chunk is refused");
    }

    #[test]
    fn an_empty_object_seals_to_an_empty_manifest() {
        let sealed = seal_object(&[], &KEY);
        assert!(sealed.chunks.is_empty());
        assert!(sealed.manifest.chunks.is_empty());
        assert_eq!(open_object(&sealed.manifest, &sealed.chunks, &KEY), Some(Vec::new()));
    }

    #[test]
    fn distinct_objects_seal_to_distinct_content_ids() {
        let a = seal_object(b"the first object", &KEY);
        let b = seal_object(b"a different object", &KEY);
        assert_ne!(a.manifest.cid(), b.manifest.cid(), "different content addresses differently");
    }
}
