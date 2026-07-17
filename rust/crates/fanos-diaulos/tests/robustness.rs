//! Robustness: the DIAULOS decoders must never panic on arbitrary input. Every cell that arrives is
//! attacker-controlled — a tampered, truncated, or wrong-key blob — so the parsers must *reject* it
//! (return `None` / drop the cell) and leave the connection usable, never crash the node.

#![allow(clippy::unwrap_used)]

use fanos_diaulos::frame::Frame;
use fanos_diaulos::{Connection, open};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Decoding arbitrary bytes as a frame returns (some `None`, some `Some`) but never panics.
    #[test]
    fn frame_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Frame::decode(&bytes);
    }

    /// Opening an arbitrary blob under an arbitrary key never panics (AEAD rejects → `None`).
    #[test]
    fn cell_open_never_panics(
        key in proptest::array::uniform32(any::<u8>()),
        bytes in proptest::collection::vec(any::<u8>(), 0..1200),
    ) {
        let _ = open(&key, &bytes);
    }

    /// Feeding an arbitrary inbound cell to a live connection safely drops it, and the connection
    /// keeps working afterward (a hostile peer cannot wedge or crash the stream layer).
    #[test]
    fn connection_survives_arbitrary_cells(
        blobs in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..1200),
            0..8,
        ),
    ) {
        let mut conn = Connection::new([1u8; 32], [2u8; 32], false);
        for blob in &blobs {
            conn.on_cell(blob); // must never panic
        }
        // The connection is still usable: open a stream, write, and produce outbound cells.
        let sid = conn.open_stream();
        conn.write(sid, b"still alive");
        conn.finish(sid);
        let cells = conn.outbound();
        prop_assert!(cells.iter().all(|c| c.len() == fanos_diaulos::CELL_LEN));
    }
}
