//! Robustness: the telemetry decoders must never panic on arbitrary input. A `CoherenceFrame`
//! arrives over gossip/DHT from other (possibly hostile) nodes, and a history snapshot is read from
//! disk that may be truncated or corrupt — both parsers must reject bad bytes, never crash.

#![allow(clippy::indexing_slicing)]

use fanos_telemetry::{CoherenceFrame, MetricStore};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Decoding arbitrary bytes as a coherence frame never panics; a valid re-encode round-trips.
    #[test]
    fn frame_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        if let Some(frame) = CoherenceFrame::decode(&bytes) {
            // Anything that decodes must re-encode to a prefix of the input (canonical, fixed-size).
            let re = frame.encode();
            prop_assert_eq!(&bytes[..re.len()], &re[..]);
        }
    }

    /// Restoring an arbitrary blob as a metric-store snapshot never panics (bad magic/truncation →
    /// `None`).
    #[test]
    fn snapshot_restore_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = MetricStore::restore(&bytes);
    }
}
