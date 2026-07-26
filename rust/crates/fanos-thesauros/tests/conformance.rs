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
    assert_eq!(hex(chunk_cid(&input).as_bytes()), "9310d25f3c05124ad5f1fbf8a851b200b25650c4c36060ad01baf74253bcdd49");
}

#[test]
fn two_leaf_cid_and_retrievability_proof_match_thesauros_json() {
    let mut data = vec![0xABu8; LEAF];
    data.extend_from_slice(&[0xCD; 100]);
    let cid = chunk_cid(&data);
    assert_eq!(hex(cid.as_bytes()), "5bc90dcc4bc71c80480c718d4c6eb5a953ae0e40b9ab4f9089c29fa108b1f006");

    // The PoR response for leaf index 1: 100 bytes + a 1-step path whose sibling (leaf 0's hash) is on the left.
    let (bytes, proof) = prove_leaf(&data, 1).expect("a leaf");
    assert_eq!(bytes.len(), 100);
    assert_eq!(proof.len(), 1);
    assert_eq!(hex(&proof[0]), "42c328b17f0d442090c2fa24124d373b9d933bd561adfd3fc778ddc4faf65e62");
    // The side is derived from the index (leaf 1 is odd ⇒ its sibling is the left child), not carried in the proof.
    assert!(verify_leaf(&cid, 1, &bytes, &proof, 2), "the response verifies against the CID");
    // Position-binding: the same bytes and path do not verify as leaf 0.
    assert!(!verify_leaf(&cid, 0, &bytes, &proof, 2), "the response does not verify at the wrong index");
}

#[test]
fn manifest_addressing_matches_thesauros_json() {
    let object: Vec<u8> = (0..CHUNK * 2 + 500).map(|i| (i * 7) as u8).collect();
    assert_eq!(object.len(), 524_788);
    let m = Manifest::of(&object);
    assert_eq!(m.chunks.len(), 3);
    assert_eq!(hex(m.chunks[0].cid.as_bytes()), "ff7464d155857d8dfb6648c505b8aa28dfd39ebe20003e8de9d5b67e20219c16");
    assert_eq!(hex(m.cid().as_bytes()), "6225c46db36386c4c0e8e9c5e1a657f66f2bf24bdce2311faa3b1eb42960c0d9");
    // The manifest decodes back to itself (through the canonical encoding).
    assert_eq!(Manifest::decode(&m.encode()), Some(m.clone()));
    // Spot-check a manifest entry addresses its real chunk.
    let chunk0 = object.chunks(CHUNK).next().unwrap();
    assert_eq!(m.chunks[0].cid, chunk_cid(chunk0));
    let _ = Cid::new([0u8; 32]); // Cid is constructible from raw bytes for decoders.
}

#[test]
fn por_challenge_matches_thesauros_json() {
    use fanos_thesauros::content::LEAF;
    use fanos_thesauros::{challenge, prove, verify};
    // A 16-leaf chunk (leaf i = byte i+1 repeated).
    let data: Vec<u8> = (0..16 * LEAF).map(|i| (i / LEAF + 1) as u8).collect();
    let cid = chunk_cid(&data);
    assert_eq!(hex(cid.as_bytes()), "31f091aa2d630bf9fd65ec1b930d14fe2593b36d5f4d541f93d2980fe83d4785");
    // The audit at beacon "epoch-42-beacon", k=5 of 16 leaves, challenges these indices.
    let indices = challenge(&cid, b"epoch-42-beacon", 5, 16);
    assert_eq!(indices, vec![4, 10, 13, 14, 15]);
    // An honest provider's response verifies; the challenge is recomputed by the verifier.
    let response = prove(&data, &indices).expect("honest response");
    assert!(verify(&cid, b"epoch-42-beacon", 5, 16, &response));
}
