//! End-to-end check of `#[derive(Wire)]`: a derived struct round-trips and enforces canonicity
//! (rejects trailing bytes), and its layout is exactly the field order.

#![allow(clippy::unwrap_used)]

use fanos_wire::{Wire, WireError};
use fanos_wire_derive::Wire;

#[derive(Wire, PartialEq, Eq, Debug, Clone)]
struct Header {
    version: u8,
    stream_id: u32,
    seq: u64,
    fin: bool,
    tag: [u8; 4],
}

#[derive(Wire, PartialEq, Eq, Debug, Clone)]
struct WithBody {
    id: u32,
    body: Vec<u8>, // length-prefixed
}

#[test]
fn a_derived_struct_round_trips_and_lays_out_fields_in_order() {
    let h = Header {
        version: 1,
        stream_id: 0x1122_3344,
        seq: 0x0102_0304_0506_0708,
        fin: true,
        tag: [0xAA, 0xBB, 0xCC, 0xDD],
    };
    let bytes = h.to_wire();
    // version(1) ‖ stream_id(4) ‖ seq(8) ‖ fin(1) ‖ tag(4) = 18 bytes, in declaration order.
    assert_eq!(bytes.len(), 1 + 4 + 8 + 1 + 4);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..5], &0x1122_3344u32.to_be_bytes());
    assert_eq!(Header::from_wire(&bytes).unwrap(), h);
}

#[test]
fn a_derived_struct_rejects_trailing_bytes() {
    let h = Header {
        version: 2,
        stream_id: 7,
        seq: 9,
        fin: false,
        tag: [0; 4],
    };
    let mut bytes = h.to_wire();
    bytes.push(0x00);
    assert_eq!(Header::from_wire(&bytes), Err(WireError::TrailingBytes));
    // Truncation is rejected too.
    assert_eq!(Header::from_wire(&bytes[..5]), Err(WireError::UnexpectedEnd));
}

#[test]
fn a_length_prefixed_body_field_round_trips() {
    let w = WithBody {
        id: 42,
        body: vec![1, 2, 3, 4, 5, 6, 7],
    };
    assert_eq!(WithBody::from_wire(&w.to_wire()).unwrap(), w);
    // The body length prefix means a struct with a different body decodes distinctly.
    let empty = WithBody { id: 42, body: vec![] };
    assert_ne!(w.to_wire(), empty.to_wire());
    assert_eq!(WithBody::from_wire(&empty.to_wire()).unwrap(), empty);
}
