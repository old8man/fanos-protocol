//! # fanos-wire — the canonical wire encoding
//!
//! This crate is the **language-agnostic contract** (spec Part VII): enough byte-level detail
//! that FANOS can be re-implemented in any language and two independent implementations
//! interoperate. The one rule is *canonical encoding* — exactly one valid byte sequence for
//! every object — so hashes, signatures, and MACs agree across implementations. A conformant
//! decoder **rejects** every non-canonical input.
//!
//! * [`varint`] — QUIC variable-length integers, minimal-length (§7.1).
//! * [`element`] — field elements, projective points/lines, byte strings (§7.1).
//! * [`frame`] — the frame layout and the message-type registry (§7.2).
//! * [`tessera`] — the fixed-size Tessera packet layout (§7.7).
//! * [`error`] — decode errors and the protocol error taxonomy (§7.5).
//!
//! The `#[cfg]` gates keep it `#![no_std]` (with `alloc`).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod element;
pub mod error;
pub mod frame;
pub mod tessera;
pub mod varint;
pub mod wire;

pub use error::{ProtocolError, WireError};
pub use frame::{Frame, FrameType, SessionFrameType, decode_frame, encode_frame};
pub use wire::Wire;

/// Re-exports the `#[derive(Wire)]` macro expansion refers to, so generated code resolves the same
/// types regardless of the consuming crate's imports or `std`/`alloc` setup. Not a stable public API.
#[doc(hidden)]
pub mod __private {
    pub use crate::error::WireError;
    pub use crate::wire::Wire;
    pub use alloc::vec::Vec;
    pub use core::result::Result;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod conformance {
    //! §7.9 known-answer vectors: canonical encodings pinned as `(input, expected-bytes)`,
    //! plus the non-canonical inputs a conformant decoder must reject.
    use super::*;
    use alloc::vec::Vec;
    use fanos_field::F7;
    use fanos_geometry::Point;

    #[test]
    fn point_kat_pg27() {
        // [1:2:3] in GF(7) encodes to three one-byte elements.
        let p = Point::<F7>::new([1, 2, 3]).unwrap();
        let mut buf = Vec::new();
        element::encode_point(&p, &mut buf);
        assert_eq!(buf, [1, 2, 3]);
        let (back, _) = element::decode_point::<F7>(&buf).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn frame_carrying_a_point_round_trips() {
        // A LOOKUP frame whose body is an encoded target point.
        let p = Point::<F7>::new([1, 0, 5]).unwrap();
        let mut body = Vec::new();
        element::encode_point(&p, &mut body);
        let mut wire = Vec::new();
        encode_frame(FrameType::Lookup.code(), &body, &mut wire);

        let (frame, n) = decode_frame(&wire).unwrap();
        assert_eq!(n, wire.len());
        assert_eq!(frame.frame_type(), Some(FrameType::Lookup));
        let (decoded, _) = element::decode_point::<F7>(frame.body).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn every_non_canonical_input_is_rejected() {
        // Non-minimal varint.
        assert!(varint::decode(&[0x40, 0x00]).is_err());
        // Out-of-range field element (GF(7)).
        assert!(element::decode_element::<F7>(&[9]).is_err());
        // Non-canonical projective coordinate ([2:0:0]).
        assert!(element::decode_point::<F7>(&[2, 0, 0]).is_err());
    }

    #[test]
    fn protocol_error_classes() {
        assert_eq!(ProtocolError::Unsupported.class(), 1);
        assert_eq!(ProtocolError::NoRoute.class(), 3);
        assert_eq!(ProtocolError::RdvExpired.code(), 501);
    }
}
