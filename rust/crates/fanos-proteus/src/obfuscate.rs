//! The `polymorph` transform — "look like nothing" (spec §13.2).
//!
//! Given the epoch shape `θ`, wrap a payload with `θ`-derived junk and padding so the wire has
//! no static signature and looks different every epoch. Two peers sharing the community secret
//! derive the same `θ` and so can strip it. The payload is already encrypted by the transport;
//! this layer only removes the *shape* signature.

use alloc::vec;
use alloc::vec::Vec;

use fanos_crypto::hash::hash_xof;

use crate::shape::ShapeParams;

const JUNK_LABEL: &str = "FANOS-v1/proteus-junk";
const PAD_LABEL: &str = "FANOS-v1/proteus-pad";
const LENGTH_FIELD: usize = 4;

/// Wrap `payload` under the epoch shape: `junk ‖ len ‖ payload ‖ padding` (spec §13.2). The
/// junk length and content, and the padding granularity, all come from `θ`, so the wire has no
/// fixed signature and rotates every epoch.
#[must_use]
pub fn obfuscate(shape: &ShapeParams, payload: &[u8]) -> Vec<u8> {
    let junk_len = shape.junk_len();
    let mut out = vec![0u8; junk_len];
    hash_xof(JUNK_LABEL, &shape.scramble_seed, &mut out);

    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);

    let multiple = usize::from(shape.padding_multiple).max(1);
    let pad_len = (multiple - (out.len() % multiple)) % multiple;
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        hash_xof(PAD_LABEL, &shape.scramble_seed, &mut pad);
        out.extend_from_slice(&pad);
    }
    out
}

/// Strip the epoch shape, recovering the payload. Returns `None` if the wire is too short or
/// inconsistent with `θ`.
#[must_use]
pub fn deobfuscate(shape: &ShapeParams, wire: &[u8]) -> Option<Vec<u8>> {
    let after_junk = wire.get(shape.junk_len()..)?;
    let len_bytes: [u8; LENGTH_FIELD] = after_junk.get(..LENGTH_FIELD)?.try_into().ok()?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let payload = after_junk.get(LENGTH_FIELD..LENGTH_FIELD + len)?;
    Some(payload.to_vec())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::shape::epoch_shape;

    #[test]
    fn obfuscation_round_trips() {
        let shape = epoch_shape(b"secret", 5);
        let payload = b"the real encrypted transport bytes";
        let wire = obfuscate(&shape, payload);
        assert_eq!(deobfuscate(&shape, &wire).unwrap(), payload);
    }

    #[test]
    fn the_wire_looks_different_every_epoch() {
        // The same payload obfuscated under different epochs has different bytes and lengths —
        // no shared signature to train on (spec §13.4).
        let payload = b"same payload";
        let w0 = obfuscate(&epoch_shape(b"s", 0), payload);
        let w1 = obfuscate(&epoch_shape(b"s", 1), payload);
        assert_ne!(w0, w1);
    }

    #[test]
    fn output_is_padded_to_the_epoch_granularity() {
        let shape = epoch_shape(b"s", 9);
        let wire = obfuscate(&shape, b"abc");
        assert_eq!(wire.len() % usize::from(shape.padding_multiple), 0);
    }

    #[test]
    fn a_wrong_shape_does_not_recover() {
        let wire = obfuscate(&epoch_shape(b"s", 1), b"payload");
        // A different epoch's shape strips the wrong junk length → garbage or None.
        let recovered = deobfuscate(&epoch_shape(b"s", 2), &wire);
        assert_ne!(recovered.as_deref(), Some(&b"payload"[..]));
    }
}
