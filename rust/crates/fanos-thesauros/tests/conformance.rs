//! THESAUROS conformance: pins the content-addressing wire from `conformance/vectors/thesauros.json`
//! (design: docs/design-storage.md). Any implementation must reproduce these CIDs and proof-of-retrievability
//! responses byte-for-byte to interoperate; drift in the leaf/node labels, the position-binding, the Merkle
//! fold, or the manifest layout breaks these.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::fmt::Write as _;

use fanos_thesauros::content::{CHUNK, Cid, LEAF, Manifest, chunk_cid, prove_leaf, verify_leaf};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn single_leaf_cid_matches_thesauros_json() {
    let input = unhex("544845534155524f532d763120636f6e666f726d616e6365");
    assert_eq!(std::str::from_utf8(&input).unwrap(), "THESAUROS-v1 conformance");
    assert_eq!(hex(chunk_cid(&input).as_bytes()), "08d188caddc77d94f74ffad43faf9dbfe30f580c7d0b7c6904fde7a9a1757352");
}

#[test]
fn two_leaf_cid_and_retrievability_proof_match_thesauros_json() {
    let mut data = vec![0xABu8; LEAF];
    data.extend_from_slice(&[0xCD; 100]);
    let cid = chunk_cid(&data);
    assert_eq!(hex(cid.as_bytes()), "ef5852c9ae5a18e782390d8a0390fcaeb24870b512f3f0a6cbf49a77ec5e4dab");

    // The PoR response for leaf index 1: 100 bytes + a 1-step path whose sibling (leaf 0's hash) is on the left.
    let (bytes, proof) = prove_leaf(&data, 1).expect("a leaf");
    assert_eq!(bytes.len(), 100);
    assert_eq!(proof.len(), 1);
    assert_eq!(hex(&proof[0].sibling), "42c328b17f0d442090c2fa24124d373b9d933bd561adfd3fc778ddc4faf65e62");
    assert!(!proof[0].sibling_on_right, "leaf 1's sibling (leaf 0) is on the left");
    assert!(verify_leaf(&cid, 1, &bytes, &proof), "the response verifies against the CID");
    // Position-binding: the same bytes and path do not verify as leaf 0.
    assert!(!verify_leaf(&cid, 0, &bytes, &proof), "the response does not verify at the wrong index");
}

#[test]
fn manifest_addressing_matches_thesauros_json() {
    let object: Vec<u8> = (0..CHUNK * 2 + 500).map(|i| (i * 7) as u8).collect();
    assert_eq!(object.len(), 524_788);
    let m = Manifest::of(&object);
    assert_eq!(m.chunks.len(), 3);
    assert_eq!(hex(m.chunks[0].cid.as_bytes()), "acb392e6be89ba2603c51ff71585906947575f47c92329c0858499eafda29f08");
    assert_eq!(hex(m.cid().as_bytes()), "77bee73e33cd5dea7db2e1d4ecf960ff03389d29b3ffb09269e8b1df14647858");
    // The manifest decodes back to itself (through the canonical encoding).
    assert_eq!(Manifest::decode(&m.encode()), Some(m.clone()));
    // Spot-check a manifest entry addresses its real chunk.
    let chunk0 = object.chunks(CHUNK).next().unwrap();
    assert_eq!(m.chunks[0].cid, chunk_cid(chunk0));
    let _ = Cid::new([0u8; 32]); // Cid is constructible from raw bytes for decoders.
}
