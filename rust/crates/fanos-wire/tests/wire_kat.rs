//! §7.9 wire known-answer tests: `conformance/vectors/wire.json` is the language-agnostic interop
//! contract (spec §11.1) — enough byte-level detail that a clean-room re-implementation reproduces
//! FANOS's canonical encodings without sharing code. Rather than hard-code the expected bytes, this
//! test *parses the vector file* and re-derives every entry from the actual codec, so the published
//! contract and the implementation cannot silently drift apart (mirrors
//! `crates/fanos-cli/tests/conformance_vectors.rs`'s harness for `algebra.json`/`diakrisis.json`).
//!
//! The codec is the source of truth: if `wire.json` and the code ever disagree, `wire.json` is
//! regenerated from the code, never the other way around (see the `hello_handshake` vectors' own
//! comment for how the negotiated-HELLO transcript was derived).

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::{F2, F7, F127, F256, Gf2m};
use fanos_geometry::Point;
use fanos_wire::capability::{Capabilities, MIN_SUPPORTED_VERSION, PROTOCOL_VERSION, negotiate_version};
use fanos_wire::error::{decode_error, encode_error};
use fanos_wire::tessera;
use fanos_wire::{FrameType, ProtocolError, WireError, decode_frame, element, encode_frame, varint};
use serde_json::Value;

/// Load and parse `wire.json` relative to the repository root.
fn load() -> Value {
    let path = format!(
        "{}/../../../conformance/vectors/wire.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read conformance {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    let clean: String = h.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn varint_vectors_reproduced() {
    let v = load();
    for case in v["varint"]["encode"].as_array().unwrap() {
        let value = case["value"].as_u64().unwrap();
        let expected = hex_to_bytes(case["hex"].as_str().unwrap());
        let mut buf = Vec::new();
        varint::encode(value, &mut buf);
        assert_eq!(buf, expected, "varint encode({value})");
        let (decoded, n) = varint::decode(&buf).unwrap();
        assert_eq!(decoded, value, "varint decode round-trip({value})");
        assert_eq!(n, buf.len());
    }
}

#[test]
fn field_element_widths_reproduced() {
    let v = load();
    for w in v["field_element_width"]["widths"].as_array().unwrap() {
        let q = w["q"].as_u64().unwrap();
        let bytes = w["bytes"].as_u64().unwrap() as usize;
        // Encode the element `1` (always in-range for q ≥ 2) and check the emitted width.
        let mut buf = Vec::new();
        match q {
            2 => element::encode_element::<F2>(1, &mut buf),
            7 => element::encode_element::<F7>(1, &mut buf),
            127 => element::encode_element::<F127>(1, &mut buf),
            256 => element::encode_element::<F256>(1, &mut buf),
            65536 => element::encode_element::<Gf2m<16>>(1, &mut buf),
            other => panic!("wire.json field_element_width lists an untested q={other}"),
        }
        assert_eq!(buf.len(), bytes, "encoded width for q={q}");
    }
}

#[test]
fn point_encoding_vectors_reproduced() {
    let v = load();
    let pe = &v["point_encoding"];
    assert_eq!(pe["field"].as_u64().unwrap(), 7);
    for p in pe["points"].as_array().unwrap() {
        let coords = p["coords"].as_array().unwrap();
        let xyz = [
            coords[0].as_u64().unwrap() as u32,
            coords[1].as_u64().unwrap() as u32,
            coords[2].as_u64().unwrap() as u32,
        ];
        let expected = hex_to_bytes(p["hex"].as_str().unwrap());
        let point = Point::<F7>::new(xyz).unwrap();
        let mut buf = Vec::new();
        element::encode_point(&point, &mut buf);
        assert_eq!(buf, expected, "point {xyz:?}");
        let (decoded, n) = element::decode_point::<F7>(&buf).unwrap();
        assert_eq!(decoded, point);
        assert_eq!(n, buf.len());
    }
}

#[test]
fn byte_string_vectors_reproduced() {
    let v = load();
    for ex in v["byte_string"]["examples"].as_array().unwrap() {
        let s = ex["utf8"].as_str().unwrap();
        let expected = hex_to_bytes(ex["hex"].as_str().unwrap());
        // The canonical byte-string form (varint length ‖ bytes) is `Vec<u8>`'s `Wire` impl.
        let bytes = s.as_bytes().to_vec();
        assert_eq!(fanos_wire::Wire::to_wire(&bytes), expected, "byte_string {s:?}");
    }
}

#[test]
fn frame_type_registry_reproduced() {
    let v = load();
    for entry in v["frame"]["type_registry"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let code_str = entry["code"].as_str().unwrap();
        let code = u64::from_str_radix(code_str.trim_start_matches("0x"), 16).unwrap();
        let group = entry["group"].as_u64().unwrap() as u8;
        let ty = FrameType::from_code(code)
            .unwrap_or_else(|| panic!("{name} ({code_str}) is not in the FrameType registry"));
        assert_eq!(ty.code(), code, "{name} code round-trips");
        assert_eq!(ty.group(), group, "{name} group");
    }
}

#[test]
fn frame_examples_reproduced() {
    let v = load();
    for ex in v["frame"]["examples"].as_array().unwrap() {
        let code_str = ex["type"].as_str().unwrap();
        let code = u64::from_str_radix(code_str.trim_start_matches("0x"), 16).unwrap();
        let body = ex["body_utf8"].as_str().unwrap().as_bytes();
        let expected = hex_to_bytes(ex["hex"].as_str().unwrap());
        let mut buf = Vec::new();
        encode_frame(code, body, &mut buf);
        assert_eq!(buf, expected, "frame example {code_str}");
        let (frame, n) = decode_frame(&buf).unwrap();
        assert_eq!(frame.body, body);
        assert_eq!(n, buf.len());
    }
}

#[test]
fn non_canonical_inputs_are_rejected() {
    let v = load();
    for case in v["reject"]["cases"].as_array().unwrap() {
        let kind = case["kind"].as_str().unwrap();
        let bytes = hex_to_bytes(case["hex"].as_str().unwrap());
        match kind {
            "varint" => assert!(varint::decode(&bytes).is_err(), "{case}"),
            "field_element" => {
                let field = case["field"].as_u64().unwrap();
                let rejected = match field {
                    7 => element::decode_element::<F7>(&bytes).is_err(),
                    other => panic!("untested reject field q={other}"),
                };
                assert!(rejected, "{case}");
            }
            "point" => {
                let field = case["field"].as_u64().unwrap();
                let rejected = match field {
                    7 => element::decode_point::<F7>(&bytes).is_err(),
                    other => panic!("untested reject field q={other}"),
                };
                assert!(rejected, "{case}");
            }
            other => panic!("untested reject kind {other}"),
        }
    }
}

#[test]
fn error_taxonomy_reproduced() {
    let v = load();
    for entry in v["error_taxonomy"]["codes"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let code = entry["code"].as_u64().unwrap();
        let class = entry["class"].as_u64().unwrap() as u8;
        let err = ProtocolError::from_code(code)
            .unwrap_or_else(|| panic!("{name} ({code}) is not in the ProtocolError taxonomy"));
        assert_eq!(err.code(), code, "{name} code round-trips");
        assert_eq!(err.class(), class, "{name} class");
    }
}

#[test]
fn tessera_layout_reproduced() {
    let v = load();
    let t = &v["tessera_layout"];
    assert_eq!(t["version"].as_u64().unwrap(), u64::from(tessera::VERSION));
    let header = t["cleartext_header"].as_array().unwrap();
    let widths: Vec<usize> = header.iter().map(|f| f["bytes"].as_u64().unwrap() as usize).collect();
    assert_eq!(
        widths,
        [
            tessera::VERSION_LEN,
            tessera::KEM_CT_LEN,
            tessera::NONCE_LEN,
            tessera::LEN_CT_LEN
        ],
        "cleartext header field widths, in order"
    );
    assert_eq!(t["header_bytes"].as_u64().unwrap() as usize, tessera::HEADER_LEN);
    assert_eq!(t["total_bytes"].as_u64().unwrap() as usize, tessera::TOTAL_LEN);
}

#[test]
fn capability_negotiation_reproduced() {
    let v = load();
    let c = &v["capability_negotiation"];
    assert_eq!(c["protocol_version"].as_u64().unwrap(), u64::from(PROTOCOL_VERSION));
    assert_eq!(
        c["min_supported_version"].as_u64().unwrap(),
        u64::from(MIN_SUPPORTED_VERSION)
    );

    // Named flags map to their documented bit positions.
    let flag = |name: &str| -> Capabilities {
        match name {
            "CORE" => Capabilities::CORE,
            "APHANTOS_LITE" => Capabilities::APHANTOS_LITE,
            "APHANTOS_FULL" => Capabilities::APHANTOS_FULL,
            "CALYPSO" => Capabilities::CALYPSO,
            "PQ_ONLY" => Capabilities::PQ_ONLY,
            "GF_2M" => Capabilities::GF_2M,
            "BLOCKCHAIN" => Capabilities::BLOCKCHAIN,
            other => panic!("unknown capability flag {other} in wire.json"),
        }
    };
    for (name, bit) in c["capability_flags"].as_object().unwrap() {
        let bit = bit.as_u64().unwrap() as u32;
        assert_eq!(flag(name).bits(), 1 << bit, "{name} bit position");
    }

    for ex in c["version_negotiation_examples"].as_array().unwrap() {
        let mine = ex["mine"].as_u64().unwrap() as u16;
        let theirs = ex["theirs"].as_u64().unwrap() as u16;
        let expected = ex["negotiated"].as_u64().map(|n| n as u16);
        assert_eq!(
            negotiate_version(mine, theirs),
            expected,
            "negotiate_version({mine}, {theirs})"
        );
    }

    for ex in c["capability_intersection_examples"].as_array().unwrap() {
        let a: Capabilities = ex["a"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| flag(n.as_str().unwrap()))
            .fold(Capabilities::empty(), |acc, f| acc | f);
        let b: Capabilities = ex["b"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| flag(n.as_str().unwrap()))
            .fold(Capabilities::empty(), |acc, f| acc | f);
        assert_eq!(a.bits(), ex["a_bits"].as_u64().unwrap() as u32, "a_bits");
        assert_eq!(b.bits(), ex["b_bits"].as_u64().unwrap() as u32, "b_bits");
        let intersection = a.intersect(b);
        assert_eq!(
            intersection.bits(),
            ex["intersection_bits"].as_u64().unwrap() as u32,
            "intersection_bits"
        );
        let expected_names: Vec<&str> = ex["intersection_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        for name in &expected_names {
            assert!(intersection.contains(flag(name)), "{name} in intersection");
        }
        assert_eq!(
            expected_names.is_empty(),
            intersection.is_empty(),
            "is_empty matches the expected name list"
        );
    }
}

#[test]
fn hello_handshake_transcript_reproduced() {
    let v = load();
    let h = &v["hello_handshake"];

    // HELLO: version(2) ‖ capabilities(4) ‖ field_q(4) ‖ epoch(8) ‖ coord(12) ‖ proof(80), framed.
    // fanos-wire has no VRF machinery (that lives in fanos-quic/fanos-vrf), so this vector's `proof`
    // is an opaque placeholder — it pins the FIELD LAYOUT, not cryptographic validity. A real
    // `identity::hello_bytes()` output's non-proof fields are cross-checked against this same layout
    // in `crates/fanos-quic/tests/handshake_negotiation.rs`.
    let hello = &h["hello"];
    let mut body = Vec::new();
    body.extend_from_slice(&(hello["version"].as_u64().unwrap() as u16).to_be_bytes());
    body.extend_from_slice(&(hello["capabilities"].as_u64().unwrap() as u32).to_be_bytes());
    body.extend_from_slice(&(hello["field_q"].as_u64().unwrap() as u32).to_be_bytes());
    body.extend_from_slice(&hello["epoch"].as_u64().unwrap().to_be_bytes());
    for c in hello["coord"].as_array().unwrap() {
        body.extend_from_slice(&(c.as_u64().unwrap() as u32).to_be_bytes());
    }
    body.extend_from_slice(&hex_to_bytes(hello["proof_placeholder_hex"].as_str().unwrap()));
    assert_eq!(body, hex_to_bytes(hello["body_hex"].as_str().unwrap()), "hello body");
    let mut frame = Vec::new();
    encode_frame(FrameType::Hello.code(), &body, &mut frame);
    assert_eq!(frame, hex_to_bytes(hello["frame_hex"].as_str().unwrap()), "hello frame");
    let (decoded, n) = decode_frame(&frame).unwrap();
    assert_eq!(decoded.frame_type(), Some(FrameType::Hello));
    assert_eq!(decoded.body, body.as_slice());
    assert_eq!(n, frame.len());

    // HELLO_ACK: version(2) ‖ capabilities(4), framed.
    let ack = &h["hello_ack"];
    let mut ack_body = Vec::new();
    ack_body.extend_from_slice(&(ack["version"].as_u64().unwrap() as u16).to_be_bytes());
    ack_body.extend_from_slice(&(ack["capabilities"].as_u64().unwrap() as u32).to_be_bytes());
    assert_eq!(ack_body, hex_to_bytes(ack["body_hex"].as_str().unwrap()), "hello_ack body");
    let mut ack_frame = Vec::new();
    encode_frame(FrameType::HelloAck.code(), &ack_body, &mut ack_frame);
    assert_eq!(
        ack_frame,
        hex_to_bytes(ack["frame_hex"].as_str().unwrap()),
        "hello_ack frame"
    );

    // ERROR (no reason) and ERROR (with reason): code:varint ‖ reason:bytes, framed. Round-tripped
    // through the actual `encode_error`/`decode_error` codec fanos-quic's driver uses.
    for key in ["error_no_reason", "error_with_reason"] {
        let e = &h[key];
        let code = e["code"].as_u64().unwrap();
        let err = ProtocolError::from_code(code).unwrap();
        let reason = e["reason_utf8"].as_str().unwrap().as_bytes();
        let body = encode_error(err, reason);
        assert_eq!(body, hex_to_bytes(e["body_hex"].as_str().unwrap()), "{key} body");
        let mut frame = Vec::new();
        encode_frame(FrameType::Error.code(), &body, &mut frame);
        assert_eq!(frame, hex_to_bytes(e["frame_hex"].as_str().unwrap()), "{key} frame");
        let (decoded_code, decoded_reason) = decode_error(&body).unwrap();
        assert_eq!(decoded_code, code, "{key} code round-trips");
        assert_eq!(decoded_reason, reason, "{key} reason round-trips");
    }
}

#[test]
fn an_absurdly_short_hello_ack_or_error_is_rejected_by_decode_error() {
    // Defensive: decode_error on an empty body (a truncated ERROR frame) fails closed, not by panic.
    assert_eq!(decode_error(&[]), Err(WireError::UnexpectedEnd));
}
