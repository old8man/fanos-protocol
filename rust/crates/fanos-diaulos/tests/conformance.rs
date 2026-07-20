//! DIAULOS conformance — known-answer tests pinning the connection layer's wire formats so they
//! never change silently and a second implementation can reproduce them byte-for-byte.
//!
//! Small formats (frames) are pinned as full hex; large ones (constant-size cells, the 1-RTT
//! handshake messages, and the derived session keys) are pinned as a labeled 32-byte digest, which
//! locks the exact bytes just as tightly while staying readable. The handshake KAT is deterministic
//! via a seeded RNG, so it also pins the whole hybrid-KEM + KDF derivation (and thus the exact
//! pinned versions of the underlying ML-KEM / X25519 primitives). Mirrored in
//! `conformance/vectors/diaulos.json`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use fanos_diaulos::frame::Frame;
use fanos_diaulos::{CELL_LEN, ClientHandshake, ServerHandshake, StaticKeypair, seal};
use fanos_pqcrypto::rng::SeedRng;
use fanos_primitives::hash::hash_labeled;
use fanos_runtime::stream::{Ack, Segment};

const KAT_LABEL: &str = "FANOS-v1/diaulos-kat";

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A labeled 32-byte digest of `bytes` — pins the exact content compactly.
fn digest_hex(bytes: &[u8]) -> String {
    hex(&hash_labeled(KAT_LABEL, bytes))
}

#[test]
fn frame_encodings_are_pinned() {
    // DATA: ftype(01) ‖ stream_id(5) ‖ seq(9) ‖ fin(01) ‖ len(7) ‖ "payload".
    let data = Frame::Data(Segment {
        stream_id: 5,
        seq: 9,
        fin: true,
        data: b"payload".to_vec(),
    });
    assert_eq!(
        hex(&data.encode()),
        "0100000005000000090100077061796c6f6164"
    );

    // ACK: ftype(02) ‖ stream_id(4) ‖ cumulative(12) ‖ sack(0b1010) ‖ rwnd(30).
    let ack = Frame::Ack {
        stream_id: 4,
        ack: Ack {
            cumulative: 12,
            sack: 0b1010,
            rwnd: 30,
        },
    };
    assert_eq!(
        hex(&ack.encode()),
        "02000000040000000c000000000000000a0000001e"
    );

    // PADDING: ftype only.
    assert_eq!(hex(&Frame::Padding.encode()), "00");
}

#[test]
fn cell_seal_is_pinned() {
    // ChaCha20-Poly1305 is deterministic given key, nonce, and plaintext; the cell is constant-size.
    let cell = seal(&[7u8; 32], 42, &Frame::Padding.encode()).unwrap();
    assert_eq!(cell.len(), CELL_LEN);
    assert_eq!(
        digest_hex(&cell),
        "ec6633641bdd52afc8edf11cdf2c37df78831cb01275752657277cfbbf6bdfbf"
    );
}

#[test]
fn handshake_derivation_is_pinned() {
    let mut srng = SeedRng::from_seed(b"diaulos-kat-service");
    let service = StaticKeypair::generate(&mut srng);
    let mut crng = SeedRng::from_seed(b"diaulos-kat-client");
    let (client, client_hello) = ClientHandshake::start(service.public(), &mut crng);
    let mut rrng = SeedRng::from_seed(b"diaulos-kat-respond");
    let (server_keys, server_hello) =
        ServerHandshake::respond(&service, &client_hello, &mut rrng).expect("valid hello");
    let client_keys = client.finish(&server_hello).expect("valid server hello");
    assert_eq!(
        client_keys, server_keys,
        "both sides agree on the session keys"
    );

    let mut keymat = client_keys.key_c2s.to_vec();
    keymat.extend_from_slice(&client_keys.key_s2c);
    assert_eq!(
        digest_hex(&client_hello),
        "d60be806263bd220429d9b2571f72a13c3cee6c5e7c58ad33e0dc2c338d94f59",
        "ClientHello (ephemeral_pk ‖ ct→static)"
    );
    assert_eq!(
        digest_hex(&server_hello),
        "54c0b5dc34de55a6134d8a2e4bb932c8265a51c91cfff86cb69ae6b9fb0037cb",
        "ServerHello (ct→ephemeral)"
    );
    assert_eq!(
        digest_hex(&keymat),
        "a5966ca00aea8449529efdb18da525df1a220c270d7d396f12a64d266f0682e8",
        "derived key_c2s ‖ key_s2c (the whole hybrid-KEM + KDF pipeline; transcript-bound combiner, B5)"
    );
}
