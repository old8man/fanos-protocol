//! The nested threshold onion over a circuit of hop **lines** — the "hop is a line" construction (spec §5.2, §5.4).
//!
//! Split from the seal itself, which now lives in [`fanos_threshold`]: sealing a share to a member's public key needs only
//! the KEM, while *routing* needs the plane's geometry and NYX's holonomy ratchet. Keeping them together forced every
//! consumer of the seal to depend on the onion router — `fanos-taxis` needs `ThresholdSealed` and nothing else, and that
//! was the one bad edge in an otherwise clean layer DAG.

use alloc::vec::Vec;

use fanos_primitives::shamir::Share;
use fanos_primitives::hash_labeled;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret};
use fanos_threshold::{NONCE_LEN, ThresholdError, ThresholdSealed};

use crate::slots;

/// The seal's own surface, re-exported so a caller working at the onion level reaches both halves through one path.
pub use fanos_threshold::THRESHOLD_ONION_LEN;
pub use fanos_threshold::pad_onion as pad;

const CMD_DELIVER: u8 = 0;
const CMD_NEXT: u8 = 1;

/// The length of the path-authenticator (holonomy) tag carried in a delivery (spec §5.4).
pub const HOLONOMY_LEN: usize = 32;

/// The domain label deriving the holonomy seed from the onion build seed. The holoseed is a *secret*
/// (a one-way image of the build seed), so only the sender can seal a tag that verifies against the
/// agreed circuit — an adversary who lacks the seed cannot forge a matching delivery.
const HOLOSEED_LABEL: &str = "FANOS-v1/threshold-holoseed";

/// The **holonomy** of a threshold circuit — a length-bound keyed MAC over its ordered hop *lines*.
///
/// Where [`crate::sealed`] authenticates a circuit of point-relays, the threshold onion's unit is a
/// *line*, so the authenticator ratchets over the ordered hop-line coordinates (`fanos_nyx::Ratchet`,
/// the same one-way cascade + length-binding finalization) and any inserted, substituted, reordered, or
/// truncated hop moves the cascade and breaks the tag. The holoseed is the ratchet's secret prefix, so
/// this is a keyed authenticator, not a public checksum — see [`HOLOSEED_LABEL`] (spec §5.4).
#[must_use]
pub fn circuit_line_holonomy(hop_lines: &[fanos_geometry::Triple], holoseed: &[u8; HOLONOMY_LEN]) -> [u8; HOLONOMY_LEN] {
    let mut ratchet = fanos_nyx::ratchet::Ratchet::new(holoseed);
    for line in hop_lines {
        ratchet.advance(&fanos_geometry::encode_triple(*line));
    }
    // Length-binding finalization folds in the hop count, so a truncated/extended path is caught even if
    // the surviving prefix matches (mirrors `fanos_nyx::circuit_holonomy`).
    ratchet.finalize(u32::try_from(hop_lines.len()).unwrap_or(u32::MAX))
}

/// Verify a delivered `claimed` holonomy against the circuit + build `seed` the verifier legitimately
/// knows (it built the onion, or agreed the circuit end-to-end in a rendezvous). Returns
/// [`ThresholdError::HolonomyFail`] if the payload was delivered over a different circuit than agreed.
///
/// Like [`crate::sealed::verify_delivery`], this is meaningful **only** for a verifier that already
/// holds the intended circuit + seed: a transit relay never does (and cannot verify), so it is the
/// circuit-owning endpoint — e.g. a [`ThresholdRouter`](crate::ThresholdRouter) built with
/// `with_delivery_check` — that performs the check (spec §5.4, S1-M1).
///
/// # Errors
/// [`ThresholdError::HolonomyFail`] if the recomputed holonomy does not match `claimed`.
pub fn verify_delivery(
    hop_lines: &[fanos_geometry::Triple],
    seed: &[u8],
    claimed: [u8; HOLONOMY_LEN],
) -> Result<(), ThresholdError> {
    let holoseed = hash_labeled(HOLOSEED_LABEL, seed);
    if circuit_line_holonomy(hop_lines, &holoseed) == claimed {
        Ok(())
    } else {
        Err(ThresholdError::HolonomyFail)
    }
}

/// One hop of a threshold circuit: the hop line's coordinate (where the packet is routed) and the
/// KEM public keys of its `q+1` members, in member order.
pub struct HopLine<'a> {
    /// The hop line's coordinate (the next-hop address a peeling hop learns).
    pub line: fanos_geometry::Triple,
    /// The line members' hybrid KEM public keys, in order.
    pub members: &'a [&'a HybridKemPublic],
}

/// The outcome of peeling one threshold hop.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ThresholdPeel {
    /// Forward the inner onion to the next hop line at `next`.
    Forward {
        /// The next hop line's coordinate.
        next: fanos_geometry::Triple,
        /// The inner onion bytes.
        onion: Vec<u8>,
    },
    /// The payload reached its destination.
    Deliver {
        /// The delivered payload.
        payload: Vec<u8>,
        /// The path-authenticator (holonomy) the sender sealed over the intended circuit. A verifier
        /// that shares the agreed circuit + build seed confirms it via [`verify_delivery`]; a payload
        /// delivered over a different circuit carries a different tag (spec §5.4, S1-M1).
        holonomy: [u8; HOLONOMY_LEN],
    },
}

/// Build a **nested threshold onion** over `hops`: each layer is a [`ThresholdSealed`] to that hop
/// line's members, so a hop is peeled only by a threshold `t` of its `q+1` members — the "a hop is a
/// line" property (spec §5.2). A peeling hop learns only the *next* hop line, never the whole path.
/// All per-hop keys, nonces, sharing randomness, and KEM randomness derive from `seed` (a real
/// CSPRNG in production; a fixed seed under the deterministic simulator).
pub fn seal_onion(
    hops: &[HopLine<'_>],
    threshold: u8,
    payload: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    if hops.is_empty() {
        return Err(ThresholdError::Malformed);
    }
    // The path-authenticator over the intended hop-line circuit, sealed into the innermost delivery layer
    // so the endpoint can confirm the payload traversed exactly the agreed circuit (spec §5.4, S1-M1).
    let hop_lines: Vec<fanos_geometry::Triple> = hops.iter().map(|h| h.line).collect();
    let holoseed = hash_labeled(HOLOSEED_LABEL, seed);
    let holonomy = circuit_line_holonomy(&hop_lines, &holoseed);
    let line_size = hops.first().map_or(0, |h| h.members.len());
    if line_size == 0 || hops.iter().any(|h| h.members.len() != line_size) {
        // Every hop line of a projective plane holds the same q+1 points, so a ragged circuit is a caller error — and a
        // header cannot have a fixed slot width without it.
        return Err(ThresholdError::Malformed);
    }
    if hops.len() > slots::depth_for(line_size) {
        // The depth ceiling the fixed-slot layout makes explicit; the nested layout accepted any depth and leaked it.
        return Err(ThresholdError::TooLong);
    }
    let last = hops.len() - 1;
    let tag = |k: usize, label: &str| {
        let mut s = seed.to_vec();
        s.extend_from_slice(label.as_bytes());
        s.extend_from_slice(&(k as u32).to_be_bytes());
        s
    };
    let payload_keys: Vec<[u8; 32]> =
        (0..hops.len()).map(|k| hash_labeled("FANOS-v1/threshold-onion-pkey", &tag(k, "p"))).collect();

    // The payload block, layered in REVERSE hop order: hop 0 peels first, so its layer is outermost.
    let mut block = slots::pack_payload(payload, line_size, &tag(0, "block"))?;
    for key in payload_keys.iter().rev() {
        slots::xor_payload(&mut block, key);
    }

    let mut header = Vec::with_capacity(slots::header_len(line_size));
    for (k, hop) in hops.iter().enumerate() {
        let mut cmd = Vec::with_capacity(slots::CMD_LEN);
        let operand: Vec<u8> = if k == last {
            cmd.push(CMD_DELIVER);
            holonomy.to_vec()
        } else {
            cmd.push(CMD_NEXT);
            fanos_geometry::encode_triple(hops.get(k + 1).ok_or(ThresholdError::Malformed)?.line).to_vec()
        };
        cmd.extend_from_slice(&operand);
        cmd.resize(slots::CMD_KEY_AT, 0); // one width for both commands, so the final hop is not distinguishable
        cmd.extend_from_slice(payload_keys.get(k).ok_or(ThresholdError::Malformed)?);

        let key = hash_labeled("FANOS-v1/threshold-onion-key", &tag(k, "k"));
        let nonce_full = hash_labeled("FANOS-v1/threshold-onion-nonce", &tag(k, "n"));
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_full.get(..NONCE_LEN).ok_or(ThresholdError::Malformed)?);
        let sealed = ThresholdSealed::seal(
            &cmd,
            &key,
            &nonce,
            threshold,
            hop.members,
            &sharing_randomness(&tag(k, "r"), threshold),
            &tag(k, "kem"),
        )?;
        let bytes = sealed.to_bytes();
        if bytes.len() != slots::slot_len(line_size) {
            return Err(ThresholdError::Malformed);
        }
        header.extend_from_slice(&bytes);
    }
    for k in hops.len()..slots::depth_for(line_size) {
        header.extend_from_slice(&slots::filler_slot(
            &hash_labeled("FANOS-v1/threshold-onion-pad-slot", &tag(k, "f")),
            line_size,
        ));
    }
    Ok(slots::Packet::new(slots::slot_len(line_size), header, block).to_bytes())
}

/// `(threshold − 1) · 32` bytes of deterministic sharing randomness from a seed.
fn sharing_randomness(seed: &[u8], threshold: u8) -> Vec<u8> {
    let n = usize::from(threshold.saturating_sub(1)) * 32;
    let mut out = alloc::vec![0u8; n];
    fanos_primitives::hash::hash_xof("FANOS-v1/threshold-onion-sharing", seed, &mut out);
    out
}

/// Peel one threshold hop: given `members` — at least `threshold` `(index, secret)` pairs of the
/// current hop line — reconstruct the layer key and reveal the routing command. Returns whether to
/// forward the inner onion to the next line or deliver the payload. Fewer than `threshold` members
/// (or wrong secrets) fail with [`ThresholdError::Aead`].
pub fn peel_onion(
    onion: &[u8],
    members: &[(usize, &HybridKemSecret)],
) -> Result<ThresholdPeel, ThresholdError> {
    let packet = slots::Packet::from_bytes(onion).ok_or(ThresholdError::Malformed)?;
    let sealed = ThresholdSealed::from_bytes(packet.slot(0).ok_or(ThresholdError::Malformed)?)
        .ok_or(ThresholdError::Malformed)?;
    let shares: Vec<Share> = members
        .iter()
        .filter_map(|(i, sk)| sealed.member_share(*i, sk))
        .collect();
    peel_packet(packet, &sealed, &shares)
}

/// Peel one threshold hop from **already-gathered member shares** (the form an autonomous combiner
/// uses: it collects `≥ threshold` `PartialDec` replies, then peels). Fewer than `threshold` shares
/// fail with [`ThresholdError::Aead`].
pub fn peel_onion_with_shares(
    onion: &[u8],
    shares: &[Share],
) -> Result<ThresholdPeel, ThresholdError> {
    let packet = slots::Packet::from_bytes(onion).ok_or(ThresholdError::Malformed)?;
    let sealed = ThresholdSealed::from_bytes(packet.slot(0).ok_or(ThresholdError::Malformed)?)
        .ok_or(ThresholdError::Malformed)?;
    peel_packet(packet, &sealed, shares)
}

/// Process one hop of a fixed-slot packet: open slot 0, strip one payload layer, and hand on a packet of **identical**
/// width — the header shifted one slot left with a fresh, correctly-framed filler slot appended.
fn peel_packet(
    mut packet: slots::Packet,
    sealed: &ThresholdSealed,
    shares: &[Share],
) -> Result<ThresholdPeel, ThresholdError> {
    let cmd = sealed.open(shares)?;
    if cmd.len() != slots::CMD_LEN {
        return Err(ThresholdError::Malformed);
    }
    let tag = *cmd.first().ok_or(ThresholdError::Malformed)?;
    let operand = cmd.get(1..1 + HOLONOMY_LEN).ok_or(ThresholdError::Malformed)?;
    let pkey = cmd
        .get(slots::CMD_KEY_AT..slots::CMD_KEY_AT + 32)
        .ok_or(ThresholdError::Malformed)?
        .to_vec();
    slots::xor_payload(&mut packet.payload, &pkey);
    match tag {
        CMD_DELIVER => {
            let mut holonomy = [0u8; HOLONOMY_LEN];
            holonomy.copy_from_slice(operand);
            let payload = slots::unpack_payload(&packet.payload).ok_or(ThresholdError::Malformed)?;
            Ok(ThresholdPeel::Deliver { payload, holonomy })
        }
        CMD_NEXT => {
            let next = fanos_geometry::decode_triple(operand.get(..12).ok_or(ThresholdError::Malformed)?)
                .ok_or(ThresholdError::Malformed)?;
            // Framed like a real slot, or a relay counts the parseable slots and reads off the remaining depth.
            let line_size = slots::line_size_of(packet.slot_len).ok_or(ThresholdError::Malformed)?;
            packet.shift_in(&slots::filler_slot(&pkey, line_size));
            Ok(ThresholdPeel::Forward { next, onion: packet.to_bytes() })
        }
        _ => Err(ThresholdError::Malformed),
    }
}

/// Compute a single member's Shamir share of a threshold onion layer — the `PartialDec` a line
/// member returns to the combiner (spec §5.2). `member_index` is the member's position in the line's
/// canonical `points_on` ordering (the order the layer was sealed in). Returns `None` if the slot is
/// not this member's or is tampered.
#[must_use]
pub fn member_partial(
    onion: &[u8],
    member_index: usize,
    secret: &HybridKemSecret,
) -> Option<Share> {
    // Slot 0 is always this hop's — every hop shifts the header, so a member never searches for its slot.
    let packet = slots::Packet::from_bytes(onion)?;
    ThresholdSealed::from_bytes(packet.slot(0)?)?.member_share(member_index, secret)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;
    use fanos_threshold::{THRESHOLD_ONION_LEN, pad_onion};

    fn line(n: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[seed, i as u8]);
                HybridKemSecret::generate(&mut rng)
            })
            .collect()
    }

    fn randomness(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 131 + 7) % 251) as u8).collect()
    }

    /// Build a `hops`-deep circuit over lines of `line_size` members and return the onion plus the per-hop secrets.
    fn circuit(hops: usize, line_size: usize) -> (Vec<u8>, Vec<Vec<(HybridKemSecret, HybridKemPublic)>>) {
        use fanos_geometry::Point;
        let lines: Vec<Vec<(HybridKemSecret, HybridKemPublic)>> =
            (0..hops).map(|h| line(line_size, u8::try_from(h).unwrap_or(0) + 90)).collect();
        let pubs: Vec<Vec<&HybridKemPublic>> =
            lines.iter().map(|l| l.iter().map(|(_, p)| p).collect()).collect();
        let hop_lines: Vec<HopLine<'_>> = (0..hops)
            .map(|h| HopLine {
                line: Point::<fanos_field::F2>::at(h % 7).coords(),
                members: pubs.get(h).map_or(&[][..], Vec::as_slice),
            })
            .collect();
        let onion = seal_onion(&hop_lines, 2, b"payload", b"depth-seed").unwrap();
        (onion, lines)
    }

    #[test]
    fn no_hop_can_infer_its_position_from_the_packet_it_is_handed_s1_m6() {
        // S1-M6: every hop, at every depth, is handed a packet of identical size, so the bytes say nothing about how far
        // along the circuit a relay sits. This test replaces its own opposite — the nested layout it succeeds measured
        // `[20480, 10689, 7135, 3581]` on this very circuit, where only the outermost onion was padded and
        // `round(size / 3554)` gave a relay its position.
        let (onion, lines) = circuit(3, 3);
        let mut sizes = alloc::vec![onion.len()];
        let mut current = onion;
        for hop in lines.iter().take(2) {
            let partials: Vec<Share> = [0usize, 1]
                .iter()
                .filter_map(|&i| hop.get(i).and_then(|(sk, _)| member_partial(&current, i, sk)))
                .collect();
            match peel_onion_with_shares(&current, &partials).unwrap() {
                ThresholdPeel::Forward { onion: inner, .. } => {
                    sizes.push(inner.len());
                    current = inner;
                }
                ThresholdPeel::Deliver { .. } => panic!("a 3-hop circuit forwards twice"),
            }
        }
        let first = sizes[0];
        for (k, &size) in sizes.iter().enumerate() {
            assert_eq!(size, first, "hop {k} is handed the same {first} bytes as every other: {sizes:?}");
        }
        assert_eq!(
            first,
            slots::PREAMBLE_LEN + slots::header_len(3) + slots::payload_len(3).unwrap(),
            "and the width is the plane's, not an accident of this payload"
        );
        assert_eq!(first, THRESHOLD_ONION_LEN, "which is the bucket the previous layout already paid for");
    }

    #[test]
    fn the_combiner_path_gathers_partials_and_peels() {
        use fanos_geometry::Point;
        // The autonomous-combiner form: each line member computes its `member_partial`, a combiner
        // collects >= t of them and peels via `peel_onion_with_shares`.
        let t = 3u8;
        let kps = line(5, 55);
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let hop = HopLine {
            line: Point::<fanos_field::F2>::at(1).coords(),
            members: &pubs,
        };
        let onion = seal_onion(&[hop], t, b"deliver me", b"seed").unwrap();

        // Members 0,2,4 each independently produce their partial share.
        let partials: Vec<Share> = [0usize, 2, 4]
            .iter()
            .map(|&i| member_partial(&onion, i, &kps[i].0).unwrap())
            .collect();
        // A combiner with those t partials peels the hop.
        match peel_onion_with_shares(&onion, &partials).unwrap() {
            ThresholdPeel::Deliver { payload, .. } => assert_eq!(payload, b"deliver me"),
            ThresholdPeel::Forward { .. } => panic!("single hop should deliver"),
        }
        // A member decapsulating the wrong slot gets nothing (index 0 with member 2's secret).
        assert!(member_partial(&onion, 0, &kps[2].0).is_none());
    }

    #[test]
    fn any_threshold_of_members_peels_but_fewer_cannot() {
        // A line of 8 members, threshold 6.
        let members = line(8, 1);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let key = [3u8; 32];
        let nonce = [7u8; 12];
        let cmd = b"next line = L_42; delay = 120ms";
        let layer = ThresholdSealed::seal(cmd, &key, &nonce, 6, &pubs, &randomness(5 * 32), b"kem")
            .unwrap();
        assert_eq!(layer.member_count(), 8);

        // Each member decapsulates ITS OWN share (and only its own).
        let shares: Vec<Share> = members
            .iter()
            .enumerate()
            .map(|(i, (sk, _))| layer.member_share(i, sk).unwrap())
            .collect();

        // Any 6 reconstruct and peel.
        assert_eq!(layer.open(&shares[1..7]).unwrap(), cmd);
        assert_eq!(layer.open(&shares[2..8]).unwrap(), cmd);
        // Fewer than 6 → wrong key → AEAD auth fails.
        assert_eq!(layer.open(&shares[0..5]), Err(ThresholdError::Aead));
    }

    #[test]
    fn a_wrong_member_secret_cannot_open_a_slot() {
        let members = line(5, 2);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let layer = ThresholdSealed::seal(
            b"x",
            &[9u8; 32],
            &[0u8; 12],
            3,
            &pubs,
            &randomness(2 * 32),
            b"s",
        )
        .unwrap();
        // Member 0's slot cannot be opened with member 1's secret.
        assert!(layer.member_share(0, &members[1].0).is_none());
    }

    #[test]
    fn a_threshold_circuit_routes_hop_by_hop_and_delivers() {
        use fanos_geometry::Point;
        // A 3-hop circuit; each hop is a line of 5 members with threshold 3.
        let t = 3u8;
        let lines: Vec<Vec<(HybridKemSecret, HybridKemPublic)>> =
            (0..3).map(|h| line(5, 20 + h as u8)).collect();
        // Borrow the public keys per hop (outlives the HopLine slice below).
        let pubs: Vec<Vec<&HybridKemPublic>> = lines
            .iter()
            .map(|kps| kps.iter().map(|(_, p)| p).collect())
            .collect();
        let hops: Vec<HopLine<'_>> = pubs
            .iter()
            .enumerate()
            .map(|(h, members)| HopLine {
                line: Point::<fanos_field::F2>::at(h).coords(),
                members,
            })
            .collect();

        let payload = b"threshold-routed anonymous hello";
        let mut onion = seal_onion(&hops, t, payload, b"circuit-seed").unwrap();
        assert_eq!(
            onion.len(),
            THRESHOLD_ONION_LEN,
            "the built onion is the fixed bucket size"
        );

        // Route through each hop: a threshold subset of the line's members cooperate to peel.
        for kps in &lines {
            let members: Vec<(usize, &HybridKemSecret)> = kps
                .iter()
                .take(usize::from(t))
                .enumerate()
                .map(|(i, (sk, _))| (i, sk))
                .collect();
            match peel_onion(&onion, &members).unwrap() {
                ThresholdPeel::Forward { onion: inner, .. } => {
                    // Re-pad the inner onion as the router does: every hop's packet is the same size.
                    onion = inner;
                    assert_eq!(
                        onion.len(),
                        THRESHOLD_ONION_LEN,
                        "each hop stays constant-size"
                    );
                }
                ThresholdPeel::Deliver { payload: got, .. } => {
                    assert_eq!(got, payload, "the payload arrives intact");
                    return;
                }
            }
        }
        panic!("onion never delivered");
    }

    /// Assemble a 3-hop threshold circuit's hop lines + member keypairs from a seed base.
    fn holo_circuit(base: u8) -> (Vec<Vec<(HybridKemSecret, HybridKemPublic)>>, Vec<fanos_geometry::Triple>) {
        use fanos_geometry::Point;
        let lines: Vec<Vec<(HybridKemSecret, HybridKemPublic)>> =
            (0..3).map(|h| line(5, base + h as u8)).collect();
        let hop_lines: Vec<fanos_geometry::Triple> =
            (0..3).map(|h| Point::<fanos_field::F2>::at(h).coords()).collect();
        (lines, hop_lines)
    }

    #[test]
    fn the_delivered_holonomy_authenticates_the_intended_circuit() {
        let t = 3u8;
        let (lines, hop_lines) = holo_circuit(70);
        let pubs: Vec<Vec<&HybridKemPublic>> =
            lines.iter().map(|kps| kps.iter().map(|(_, p)| p).collect()).collect();
        let hops: Vec<HopLine<'_>> = pubs
            .iter()
            .enumerate()
            .map(|(h, members)| HopLine { line: hop_lines[h], members })
            .collect();

        let seed = b"circuit-seed-holo";
        let mut onion = seal_onion(&hops, t, b"payload", seed).unwrap();

        // Route to the delivery hop and capture the holonomy the endpoint learns.
        let mut delivered = None;
        for kps in &lines {
            let members: Vec<(usize, &HybridKemSecret)> = kps
                .iter()
                .take(usize::from(t))
                .enumerate()
                .map(|(i, (sk, _))| (i, sk))
                .collect();
            match peel_onion(&onion, &members).unwrap() {
                ThresholdPeel::Forward { onion: inner, .. } => onion = inner,
                ThresholdPeel::Deliver { holonomy, .. } => {
                    delivered = Some(holonomy);
                    break;
                }
            }
        }
        let holonomy = delivered.unwrap();

        // The endpoint that agreed the circuit + seed accepts it.
        assert!(verify_delivery(&hop_lines, seed, holonomy).is_ok());
        // A substituted hop line is rejected — the authenticator caught the tamper (S1-M1).
        let mut substituted = hop_lines.clone();
        substituted[1] = fanos_geometry::Point::<fanos_field::F2>::at(4).coords();
        assert_eq!(verify_delivery(&substituted, seed, holonomy), Err(ThresholdError::HolonomyFail));
        // A reordered path is rejected (the ratchet is order-sensitive).
        let reordered = alloc::vec![hop_lines[1], hop_lines[0], hop_lines[2]];
        assert_eq!(verify_delivery(&reordered, seed, holonomy), Err(ThresholdError::HolonomyFail));
        // A truncated path is rejected (length-binding finalization).
        assert_eq!(verify_delivery(&hop_lines[..2], seed, holonomy), Err(ThresholdError::HolonomyFail));
        // The wrong build seed is rejected — the holoseed is secret, so a forger cannot match it.
        assert_eq!(verify_delivery(&hop_lines, b"wrong-seed", holonomy), Err(ThresholdError::HolonomyFail));
    }

    #[test]
    fn the_holonomy_is_sealed_until_delivery_not_a_cleartext_correlator() {
        let t = 3u8;
        let (lines, hop_lines) = holo_circuit(80);
        let pubs: Vec<Vec<&HybridKemPublic>> =
            lines.iter().map(|kps| kps.iter().map(|(_, p)| p).collect()).collect();
        let hops: Vec<HopLine<'_>> = pubs
            .iter()
            .enumerate()
            .map(|(h, members)| HopLine { line: hop_lines[h], members })
            .collect();

        let seed = b"seed";
        let tag = circuit_line_holonomy(&hop_lines, &hash_labeled(HOLOSEED_LABEL, seed));
        let mut onion = seal_onion(&hops, t, b"payload", seed).unwrap();

        // At every hop the *wire* onion is fully sealed: the holonomy tag never appears in the clear in a
        // forwarded packet — it rides encrypted in the innermost layer, revealed only when the last hop
        // peels. A passive on-path relay therefore cannot use it as a cross-hop correlator.
        for (hop, kps) in lines.iter().enumerate() {
            assert!(
                !onion.windows(HOLONOMY_LEN).any(|w| w == tag),
                "holonomy tag leaked in cleartext at hop {hop}"
            );
            let members: Vec<(usize, &HybridKemSecret)> = kps
                .iter()
                .take(usize::from(t))
                .enumerate()
                .map(|(i, (sk, _))| (i, sk))
                .collect();
            match peel_onion(&onion, &members).unwrap() {
                ThresholdPeel::Forward { onion: inner, .. } => onion = inner,
                ThresholdPeel::Deliver { holonomy, .. } => {
                    assert_eq!(holonomy, tag, "the delivered tag is the sealed authenticator");
                    return;
                }
            }
        }
        panic!("onion never delivered");
    }

    #[test]
    fn below_threshold_members_cannot_peel_a_hop() {
        use fanos_geometry::Point;
        let t = 4u8;
        let kps = line(6, 30);
        let members_pub: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let hop = HopLine {
            line: Point::<fanos_field::F2>::at(0).coords(),
            members: &members_pub,
        };
        let onion = seal_onion(&[hop], t, b"secret", b"s").unwrap();
        // Only t-1 members try — the reconstructed key is wrong and AEAD auth fails.
        let too_few: Vec<(usize, &HybridKemSecret)> = kps
            .iter()
            .take(usize::from(t) - 1)
            .enumerate()
            .map(|(i, (sk, _))| (i, sk))
            .collect();
        assert_eq!(peel_onion(&onion, &too_few), Err(ThresholdError::Aead));
    }

    #[test]
    fn a_threshold_layer_round_trips_through_bytes() {
        let members = line(5, 40);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let layer = ThresholdSealed::seal(
            b"cmd",
            &[1u8; 32],
            &[2u8; 12],
            3,
            &pubs,
            &randomness(2 * 32),
            b"s",
        )
        .unwrap();
        let decoded = ThresholdSealed::from_bytes(&layer.to_bytes()).unwrap();
        assert_eq!(decoded, layer);
    }

    #[test]
    fn seal_onion_rejects_bad_parameters() {
        use fanos_geometry::Point;
        let kps = line(3, 0x9E);
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let line_coord = Point::<fanos_field::F2>::at(1).coords();

        // An empty circuit has no hop to seal.
        assert!(matches!(
            seal_onion(&[], 2, b"x", b"s"),
            Err(ThresholdError::Malformed)
        ));
        // A threshold larger than the member count is unsatisfiable.
        assert!(
            seal_onion(
                &[HopLine {
                    line: line_coord,
                    members: &pubs,
                }],
                4,
                b"x",
                b"s",
            )
            .is_err(),
            "threshold > members is rejected"
        );
        // A zero threshold is degenerate.
        assert!(
            seal_onion(
                &[HopLine {
                    line: line_coord,
                    members: &pubs,
                }],
                0,
                b"x",
                b"s",
            )
            .is_err(),
            "threshold 0 is rejected"
        );
    }

    #[test]
    fn pad_onion_boundary() {
        // A short onion pads up to the constant bucket.
        assert_eq!(pad_onion(b"short").unwrap().len(), THRESHOLD_ONION_LEN);
        // Exactly the bucket size is a no-op pad (0 filler), still Ok.
        let exact = alloc::vec![0u8; THRESHOLD_ONION_LEN];
        assert_eq!(pad_onion(&exact).unwrap().len(), THRESHOLD_ONION_LEN);
        // One byte over the bucket cannot be padded down.
        let over = alloc::vec![0u8; THRESHOLD_ONION_LEN + 1];
        assert!(matches!(pad_onion(&over), Err(ThresholdError::TooLong)));
    }
}
