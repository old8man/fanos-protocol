//! The **datagram envelope** — the layer `obfuscate` is not (spec §13.3, §13.5).
//!
//! [`obfuscate`](crate::obfuscate::obfuscate) wraps a *frame*, and a frame only exists once a QUIC connection is up.
//! That leaves the connection's own first packet — the Initial, carrying the ALPN, the SNI and the version
//! list in plaintext (a QUIC Initial is protected with keys derived from a well-known salt, RFC 9001 §5.2)
//! — outside every morph. Measured before this module existed: an unauthenticated prober got a Version
//! Negotiation packet back from the flagship `polymorph` morph, and the identical bytes from `plain`
//! (`fanos-quic/tests/probe_resistance.rs`). This module is what the spec's two claims actually need:
//!
//! * §13.3 — "carry the FANOS wire over a raw polymorphic UDP transport with **no QUIC/TLS handshake to
//!   fingerprint**": every datagram, handshake included, travels under the envelope.
//! * §13.5 — "without the correct `community_secret` the endpoint returns nothing decodable … **a prober
//!   sees an unresponsive UDP port**": a datagram whose tag does not verify is dropped before QUIC sees it.
//!
//! ## Why this is not [`obfuscate`](crate::obfuscate::obfuscate) with a different caller
//!
//! `obfuscate` **grows** its input: `MAX_WIRE_OVERHEAD` is 1466 bytes, larger than a path MTU. Applied per
//! datagram it could not fit, ever. The datagram layer needs the *other* property — a key, not a shape:
//!
//! ```text
//! wire = nonce(8) ‖ payload ⊕ keystream(θ ‖ nonce) ‖ tag(4)
//! ```
//!
//! [`DATAGRAM_OVERHEAD`] is therefore **12 bytes and length-preserving**, which is what makes the layering
//! possible at all. The budget: the IPv6 minimum MTU is 1280 (RFC 8200), less 40 + 8 of IPv6/UDP header
//! leaves 1232, and QUIC's own floor for an Initial is 1200 — so 32 bytes are available on the *guaranteed*
//! path and this envelope spends 12 of them. Above that floor quinn's own PMTU discovery does the rest,
//! correctly, because its probes travel sealed and therefore measure the sealed size.
//!
//! The size-and-timing half of a morph is unchanged and still lives at the frame layer, where it belongs:
//! this envelope deliberately does not pad, because padding here would fight PMTU discovery for the same
//! bytes.
//!
//! ## What this is not
//!
//! Not authenticated encryption. QUIC's own TLS provides confidentiality and integrity for the contents;
//! the keystream removes the *plaintext handshake fields* an observer would otherwise read, and the tag's
//! only job is to let a receiver drop strangers. A 4-byte tag gives a stranger one chance in 2³² of being
//! forwarded to quinn — which then rejects the packet anyway — and costs 4 bytes of a 32-byte budget.
//!
//! The tag comparison is **constant-time on purpose**. It is the one place where a timing oracle would
//! hand back exactly the property §13.5 buys: a censor who could learn "the first tag byte was right" by
//! measuring a reply delay could confirm a FANOS endpoint byte by byte, which is the confirmation the
//! whole envelope exists to deny.

use alloc::vec;
use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::obfuscate::NONCE_LEN;
use crate::shape::ShapeParams;

const KEYSTREAM_LABEL: &str = "FANOS-v1/proteus-datagram";
const TAG_LABEL: &str = "FANOS-v1/proteus-datagram-tag";

/// The keyed tag that lets a receiver drop a stranger's datagram without parsing it.
///
/// Four bytes: a stranger's chance of being forwarded to quinn is 2⁻³², and quinn then rejects it. Wider
/// would spend the MTU budget derived in this module's header on an outcome the layer above already
/// covers.
pub const TAG_LEN: usize = 4;

/// What the envelope costs on the wire, in bytes — and it is **length-preserving beyond this constant**,
/// which is the property that lets it sit under QUIC at all. See this module's header for the derivation
/// against the IPv6 minimum MTU.
pub const DATAGRAM_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Per-datagram keystream/tag material: the epoch's scramble seed diversified by this datagram's nonce.
fn material(shape: &ShapeParams, nonce: [u8; NONCE_LEN]) -> Vec<u8> {
    let mut material = shape.scramble_seed.to_vec();
    material.extend_from_slice(&nonce);
    material
}

/// The tag over `ciphertext`, keyed by `θ` and this datagram's nonce.
fn tag_of(shape: &ShapeParams, nonce: [u8; NONCE_LEN], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let mut data = material(shape, nonce);
    data.extend_from_slice(ciphertext);
    let mut tag = [0u8; TAG_LEN];
    hash_xof(TAG_LABEL, &data, &mut tag);
    tag
}

/// Equality that does not leak *where* two tags differ — see this module's header for why the timing
/// matters here specifically.
fn tags_equal(a: [u8; TAG_LEN], b: &[u8]) -> bool {
    if b.len() != TAG_LEN {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Wrap one datagram: `nonce ‖ payload ⊕ keystream ‖ tag`.
///
/// `nonce` must not repeat for a given `shape`. The caller owns that, because the caller is the only one
/// who knows how many sockets share this community secret — see `fanos_quic`'s `ProteusSocket`, which
/// draws it from the OS CSPRNG per datagram rather than from a counter two peers would both start at zero.
#[must_use]
pub fn seal(shape: &ShapeParams, payload: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut keystream = vec![0u8; payload.len()];
    hash_xof(KEYSTREAM_LABEL, &material(shape, *nonce), &mut keystream);

    let mut out = Vec::with_capacity(DATAGRAM_OVERHEAD + payload.len());
    out.extend_from_slice(nonce);
    out.extend(payload.iter().zip(&keystream).map(|(p, k)| p ^ k));

    let tag = tag_of(shape, *nonce, out.get(NONCE_LEN..).unwrap_or_default());
    out.extend_from_slice(&tag);
    out
}

/// Unwrap one datagram **in place**, returning the plaintext length; the plaintext ends up at `buf[..n]`.
///
/// `None` means "not ours": too short, or the tag does not verify. The receive path drops those without a
/// reply, which is the whole of §13.5.
///
/// In place because this is the per-datagram hot path on every connection, and quinn already owns a buffer
/// of the right size — allocating a second one per packet would be a throughput cost paid for nothing.
#[must_use]
pub fn open_in_place(shape: &ShapeParams, buf: &mut [u8]) -> Option<usize> {
    let payload_len = buf.len().checked_sub(DATAGRAM_OVERHEAD)?;
    let nonce: [u8; NONCE_LEN] = buf.get(..NONCE_LEN)?.try_into().ok()?;

    let (body, tag) = buf.split_at_mut(NONCE_LEN + payload_len);
    let ciphertext = body.get(NONCE_LEN..)?;
    if !tags_equal(tag_of(shape, nonce, ciphertext), tag) {
        return None;
    }

    let mut keystream = vec![0u8; payload_len];
    hash_xof(KEYSTREAM_LABEL, &material(shape, nonce), &mut keystream);
    for (b, k) in body.get_mut(NONCE_LEN..)?.iter_mut().zip(&keystream) {
        *b ^= k;
    }
    buf.copy_within(NONCE_LEN..NONCE_LEN + payload_len, 0);
    Some(payload_len)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::shape::epoch_shape;
    use fanos_primitives::Epoch;

    const N: [u8; NONCE_LEN] = [7; NONCE_LEN];

    /// A QUIC Initial's opening bytes: long header, version 1, then connection IDs. This is exactly what a
    /// censor keys on, so it is what the tests seal.
    fn quic_initial() -> Vec<u8> {
        let mut pkt = alloc::vec![0xC0u8, 0x00, 0x00, 0x00, 0x01];
        pkt.extend_from_slice(&[8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]);
        pkt.resize(1200, 0);
        pkt
    }

    #[test]
    fn a_sealed_datagram_round_trips() {
        let shape = epoch_shape(b"community", Epoch::new(4));
        let payload = quic_initial();
        let mut wire = seal(&shape, &payload, &N);
        let n = open_in_place(&shape, &mut wire).unwrap();
        assert_eq!(&wire[..n], &payload[..]);
    }

    /// The property the whole module exists for: the plaintext QUIC header is **not** on the wire.
    ///
    /// Falsification matters here — an envelope that XORed with an all-zero keystream would round-trip
    /// perfectly and pass the test above while changing nothing an observer sees.
    #[test]
    fn the_quic_header_is_not_recoverable_from_the_wire() {
        let shape = epoch_shape(b"community", Epoch::new(4));
        let payload = quic_initial();
        let wire = seal(&shape, &payload, &N);
        assert_eq!(wire.len(), payload.len() + DATAGRAM_OVERHEAD, "length-preserving but for the envelope");
        assert_ne!(
            &wire[NONCE_LEN..NONCE_LEN + 13],
            &payload[..13],
            "the long header, version and DCID must not survive to the wire",
        );
        // And the nonce is the only thing a stranger can read, by construction.
        assert_eq!(&wire[..NONCE_LEN], &N[..]);
    }

    /// §13.5, at this layer: a peer without the community secret cannot produce a datagram we accept.
    #[test]
    fn a_datagram_from_another_community_does_not_open() {
        let mine = epoch_shape(b"community-A", Epoch::new(4));
        let theirs = epoch_shape(b"community-B", Epoch::new(4));
        let mut wire = seal(&theirs, &quic_initial(), &N);
        assert!(open_in_place(&mine, &mut wire).is_none());
    }

    /// …and neither can an unshaped one: a bare QUIC packet arriving at a sealed endpoint is refused.
    #[test]
    fn a_bare_quic_packet_does_not_open() {
        let shape = epoch_shape(b"community", Epoch::new(4));
        let mut raw = quic_initial();
        assert!(open_in_place(&shape, &mut raw).is_none());
    }

    /// A flipped byte anywhere in the ciphertext fails the tag — swept over the whole packet rather than
    /// spot-checked, because a tag computed over only a prefix would pass a spot check.
    #[test]
    fn any_single_flipped_byte_is_refused() {
        let shape = epoch_shape(b"community", Epoch::new(4));
        let sealed = seal(&shape, &quic_initial(), &N);
        for i in 0..sealed.len() {
            let mut w = sealed.clone();
            w[i] ^= 0x01;
            assert!(open_in_place(&shape, &mut w).is_none(), "byte {i} was not covered");
        }
    }

    /// Anything shorter than the envelope is refused rather than panicking — the receive path takes
    /// arbitrary bytes off a public socket.
    #[test]
    fn a_runt_is_refused_and_does_not_panic() {
        let shape = epoch_shape(b"community", Epoch::new(4));
        for len in 0..=DATAGRAM_OVERHEAD {
            let mut buf = alloc::vec![0u8; len];
            assert!(open_in_place(&shape, &mut buf).is_none(), "len {len}");
        }
        // The boundary from the other side: exactly one payload byte does open.
        let mut one = seal(&shape, &[0xAB], &N);
        assert_eq!(open_in_place(&shape, &mut one), Some(1));
    }

    /// The envelope rotates with the epoch, like everything else in §13.4 — the same datagram under two
    /// epochs is two different wires, and neither opens under the other.
    #[test]
    fn the_envelope_rotates_every_epoch() {
        let e0 = epoch_shape(b"community", Epoch::new(4));
        let e1 = epoch_shape(b"community", Epoch::new(5));
        let payload = quic_initial();
        let w0 = seal(&e0, &payload, &N);
        let w1 = seal(&e1, &payload, &N);
        assert_ne!(w0, w1);
        let mut w0_under_e1 = w0;
        assert!(open_in_place(&e1, &mut w0_under_e1).is_none());
    }
}
