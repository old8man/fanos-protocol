//! The `polymorph` transform — "look like nothing" (spec §13.2).
//!
//! Wrap a payload with junk and padding so the wire has no static signature. The junk/padding
//! keystream is derived from the epoch shape `θ` **diversified by a per-packet nonce**, so the wire
//! rotates both *per epoch* (a classifier trained on one epoch is stale the next) and *per packet*
//! (even two sends of the identical frame shape to different bytes — no fixed intra-epoch prefix,
//! and equal frames are not linkable, cf. AmneziaWG per-packet junk, spec §13.3–§13.4). Two peers
//! sharing the community secret derive the same `θ`; the nonce travels in cleartext at the front so
//! the peer can strip the shape without deriving anything from it. The payload is already encrypted
//! by the transport; this layer only removes the *shape* signature.

use alloc::vec;
use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::shape::{MAX_JUNK_LEN, MAX_PADDING_MULTIPLE, ShapeParams};

const JUNK_LABEL: &str = "FANOS-v1/proteus-junk";
const PAD_LABEL: &str = "FANOS-v1/proteus-pad";
/// The obfuscated length prefix's width in bytes — a `u32`, so it can describe any packet the transport
/// will carry. Definitional (the field *is* a `u32`), and read by the peer, so it is wire-fixed.
const LENGTH_FIELD: usize = 4;

/// The per-packet nonce carried in cleartext at the front of the wire. It looks random (the shaper
/// PRFs a sequence counter into it), and the junk/padding keystream is derived from `θ ‖ nonce`, so
/// **every packet — even one carrying the identical frame — shapes to different bytes**. This closes
/// the intra-epoch fixed-prefix signature and the equal-frames-are-linkable weakness of a purely
/// `θ`-derived junk (cf. AmneziaWG per-packet junk, spec §13.3–§13.4).
pub const NONCE_LEN: usize = 8;

/// The most bytes shaping can add to a payload, over **every** shape [`epoch_shape`] can produce.
///
/// `obfuscate` is strictly growing — `nonce ‖ junk ‖ len ‖ payload ‖ padding` — so a frame sized against
/// a frame-layer ceiling arrives at the wire *larger than that ceiling*. A receiver that bounds its read
/// by the frame ceiling therefore drops full-size frames silently, and the sender sees a successful
/// write. This constant is what lets a reader bound the **wire** instead: it is the gap between the two
/// ceilings, derived from the parameter ranges rather than chosen, so widening a range without revisiting
/// the bound is a compile-time coupling instead of a silent hole.
///
/// Padding is `(multiple − out.len() % multiple) % multiple`, hence at most `multiple − 1`, and the
/// coarsest multiple is [`MAX_PADDING_MULTIPLE`].
///
/// [`epoch_shape`]: crate::shape::epoch_shape
/// [`MAX_PADDING_MULTIPLE`]: crate::shape::MAX_PADDING_MULTIPLE
pub const MAX_WIRE_OVERHEAD: usize =
    NONCE_LEN + MAX_JUNK_LEN + LENGTH_FIELD + (MAX_PADDING_MULTIPLE as usize - 1);

/// Wrap `payload` under the epoch shape with a per-packet `nonce`:
/// `nonce ‖ junk ‖ len ‖ payload ‖ padding` (spec §13.2). The junk and padding are keyed by
/// `θ ‖ nonce`, so their bytes rotate per packet as well as per epoch.
#[must_use]
pub fn obfuscate(shape: &ShapeParams, payload: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    // Per-packet keystream material: the epoch scramble seed diversified by the nonce.
    let mut material = shape.scramble_seed.to_vec();
    material.extend_from_slice(nonce);

    let junk_len = shape.junk_len();
    let mut out = Vec::with_capacity(NONCE_LEN + junk_len + LENGTH_FIELD + payload.len());
    out.extend_from_slice(nonce);
    let mut junk = vec![0u8; junk_len];
    hash_xof(JUNK_LABEL, &material, &mut junk);
    out.extend_from_slice(&junk);

    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);

    let multiple = usize::from(shape.padding_multiple).max(1);
    let pad_len = (multiple - (out.len() % multiple)) % multiple;
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        hash_xof(PAD_LABEL, &material, &mut pad);
        out.extend_from_slice(&pad);
    }
    out
}

/// Strip the epoch shape, recovering the payload. Returns `None` if the wire is too short or
/// inconsistent with `θ`. Unwrapping needs only the fixed field widths (skip `nonce`, skip `junk`,
/// read `len`), so the per-packet nonce value is never re-derived here.
#[must_use]
pub fn deobfuscate(shape: &ShapeParams, wire: &[u8]) -> Option<Vec<u8>> {
    let after_nonce = wire.get(NONCE_LEN..)?;
    let after_junk = after_nonce.get(shape.junk_len()..)?;
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
    use fanos_primitives::Epoch;

    const N0: [u8; NONCE_LEN] = [0; NONCE_LEN];

    #[test]
    fn obfuscation_round_trips() {
        let shape = epoch_shape(b"secret", Epoch::new(5));
        let payload = b"the real encrypted transport bytes";
        let wire = obfuscate(&shape, payload, &N0);
        assert_eq!(deobfuscate(&shape, &wire).unwrap(), payload);
    }

    #[test]
    fn the_wire_looks_different_every_epoch() {
        // The same payload obfuscated under different epochs has different bytes and lengths —
        // no shared signature to train on (spec §13.4).
        let payload = b"same payload";
        let w0 = obfuscate(&epoch_shape(b"s", Epoch::ZERO), payload, &N0);
        let w1 = obfuscate(&epoch_shape(b"s", Epoch::new(1)), payload, &N0);
        assert_ne!(w0, w1);
    }

    #[test]
    fn the_junk_rotates_per_packet_but_still_round_trips() {
        // The per-packet nonce diversifies junk/padding: the same frame under the same epoch shapes
        // to different bytes for different nonces, yet both strip back to the original payload.
        let shape = epoch_shape(b"s", Epoch::new(3));
        let payload = b"identical frame";
        let a = obfuscate(&shape, payload, &[1; NONCE_LEN]);
        let b = obfuscate(&shape, payload, &[2; NONCE_LEN]);
        assert_ne!(
            a, b,
            "different nonces → different wire bytes for the same frame"
        );
        assert_eq!(deobfuscate(&shape, &a).unwrap(), payload);
        assert_eq!(deobfuscate(&shape, &b).unwrap(), payload);
    }

    #[test]
    fn output_is_padded_to_the_epoch_granularity() {
        let shape = epoch_shape(b"s", Epoch::new(9));
        let wire = obfuscate(&shape, b"abc", &N0);
        assert_eq!(wire.len() % usize::from(shape.padding_multiple), 0);
    }

    #[test]
    fn no_shape_can_grow_a_payload_past_the_declared_overhead() {
        // MAX_WIRE_OVERHEAD is what a receiver adds to its frame ceiling to get a wire ceiling, so the
        // bound has to hold for *every* shape and every payload length — not just the ones arithmetic
        // says are worst. Sweep real shapes and measure the growth. The payload lengths straddle a
        // padding boundary in both directions, since padding is the term that depends on total length.
        let mut widest = 0usize;
        for e in 0u64..512 {
            let shape = epoch_shape(b"community", Epoch::new(e));
            for len in [0usize, 1, 63, 64, 65, 191, 192, 1000, 65_536] {
                let payload = vec![0xA5; len];
                let grown = obfuscate(&shape, &payload, &N0).len() - len;
                assert!(
                    grown <= MAX_WIRE_OVERHEAD,
                    "epoch {e}, payload {len}: shaping added {grown} bytes, over the declared \
                     {MAX_WIRE_OVERHEAD} — a receiver sizing its read on this bound would drop the frame"
                );
                widest = widest.max(grown);
            }
        }
        // The bound must also be reachable enough to be honest: a wildly loose bound would pass the
        // assertion above while wasting the receiver's ceiling. This is a floor on tightness, not equality
        // — the true maximum needs the largest junk AND a worst-case padding remainder in one shape.
        assert!(
            widest * 2 > MAX_WIRE_OVERHEAD,
            "observed worst growth {widest} is less than half the declared {MAX_WIRE_OVERHEAD}: the \
             bound has drifted away from what shaping actually does"
        );
    }

    #[test]
    fn a_wrong_shape_does_not_recover() {
        let wire = obfuscate(&epoch_shape(b"s", Epoch::new(1)), b"payload", &N0);
        // A different epoch's shape strips the wrong junk length → garbage or None.
        let recovered = deobfuscate(&epoch_shape(b"s", Epoch::new(2)), &wire);
        assert_ne!(recovered.as_deref(), Some(&b"payload"[..]));
    }
}
