//! The **fixed-slot onion layout** — a constant-width packet that leaks no hop position (S1-M6).
//!
//! ## What it replaces, and why padding could not fix it
//!
//! The nested layout wrapped each hop's routing command around the *entire* inner onion, so a layer's plaintext shrank
//! with depth. Measured on a 4-hop circuit over 3-member lines: `[20480, 10689, 7135, 3581]` bytes. Only the outermost was
//! padded, so exactly one hop was protected; from hop 1 on the size fell by a constant 3554 bytes and a relay recovered its
//! position exactly as `round(size / 3554)`.
//!
//! Padding each nested layer to a constant does not fix it — a layer would then carry a full-width inner onion, so the
//! *total* would grow with depth instead. **Constant per-layer size and constant total size are incompatible under
//! nesting**, which is why this is a layout change and not a padding change.
//!
//! ## The layout
//!
//! ```text
//! onion = slots(2) ‖ slot_len(4) ‖ slot[0] ‖ … ‖ slot[D-1] ‖ payload_block
//! ```
//!
//! Every hop reads **slot 0**, shifts the array one slot left, and appends a pseudorandom slot — so the header is always
//! `D` slots wide and the packet is byte-identical in size at every hop. Slot `k` as built is hop `k`'s, and after `k`
//! shifts it has arrived at position 0.
//!
//! The two cleartext preamble fields are network parameters, not circuit facts: `slots` is the *maximum* depth `D`, the
//! same for every packet, and `slot_len` follows from the plane's line size. Neither reveals the actual depth `h`, which is
//! what the leak was.
//!
//! ## Why this is simpler than textbook Sphinx
//!
//! Sphinx needs precomputed ρ-filler because its header is a single stream encrypted under each hop's key in turn, so the
//! bytes a hop appends must be exactly what the *sender* accounted for or the MAC fails. Here each slot is **independently**
//! threshold-sealed to its own hop line, so nothing links one slot to another: an unused slot is indistinguishable random
//! bytes to anyone who cannot decapsulate it, and no honest path ever opens one. Filler therefore needs no consistency at
//! all, and a hop can append whatever it likes.
//!
//! The appended filler is derived from that hop's own layer key rather than drawn from an RNG, which keeps the whole
//! transform deterministic in the build seed — the simulator depends on that, and it costs nothing here because the filler
//! only has to be unpredictable to *other* parties.
//!
//! ## The payload
//!
//! A constant-width block, XOR-encrypted once per hop under a keystream derived from that hop's layer key. Size-preserving,
//! so the block is the same width at every hop; the sender applies the hops in reverse so each hop's peel removes exactly
//! one layer. The real payload is length-prefixed inside the block, so the endpoint trims it after the final peel.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;
use fanos_threshold::{NONCE_LEN, SEALED_SHARE_LEN, THRESHOLD_ONION_LEN, ThresholdError};

/// The circuit depth the layout targets, when the plane's budget allows it.
///
/// A **policy**, not a budget maximum, and the distinction is load-bearing. Filling the cell with slots leaves almost
/// nothing for the payload — and worse, it makes the payload *shrink* as the cell grows, since a wider cell buys more slots
/// rather than more room. Measured: doubling `THRESHOLD_ONION_LEN` to 40 960 took the payload from 2 444 B to **1 288 B**.
/// An experiment that widened the cell to test for a payload shortage therefore tested nothing, and wrongly cleared it.
///
/// Three hops is the depth that actually buys anonymity (it is what Tor uses), and capping there leaves ~9.6 KiB of payload
/// at `q = 2` instead of 2.4.
pub const TARGET_DEPTH: usize = 3;

/// The number of slots in every header on a plane whose lines hold `line_size` points — and so the ceiling on circuit
/// depth there: [`TARGET_DEPTH`], or fewer if the plane's slots are too wide to fit that many.
///
/// Derived per plane rather than fixed globally, because the invariant the layout needs is that *every packet on a given
/// network looks alike*, and the line size is already a network-wide parameter (`q + 1`). A single global constant cannot
/// serve both ends of the range: the budget is fixed, so a wide plane's slots are large and few, and forcing a Fano
/// deployment down to a wide plane's depth would throw away anonymity it has paid for.
///
/// It is also the ceiling the nested layout left **implicit** — there, a sender could build any depth and simply leak more.
/// Here exceeding it is an error.
///
/// **The payload floor is one slot's worth, and it is derived rather than chosen.** The largest thing this protocol nests
/// *inside* an onion payload is a threshold seal to a hop line — `line_size × SEALED_SHARE_LEN` plus a small header — which is
/// what a slot costs. So reserving one slot of payload reserves exactly one nested seal, and the arithmetic is
/// `(D + 1) × slot_len ≤ budget`.
///
/// Without that floor, [`TARGET_DEPTH`] alone is correct on narrow planes and silently breaks wide ones: at `q = 4` it gave
/// **2 642 B** of payload against **5 944 B** for one nested seal, and at `q = 7` **1 572** against **9 451**. That is the same
/// failure that broke every full anonymous session at `q = 2` under budget-filling — sessions fail while a single forward onion
/// still delivers — so it would have shipped the identical defect to anyone running `--plane-order 4`.
///
/// Resulting depths: **3 hops at `q = 2` and `q = 3`, 2 at `q = 4`, 1 at `q = 7`.** The last is honest rather than acceptable:
/// at that width `THRESHOLD_ONION_LEN` cannot carry a multi-hop circuit *and* a usable payload, and the answer is a wider cell
/// for wide planes (the budget is a per-deployment parameter) — not a thinner payload.
#[must_use]
pub const fn depth_for(line_size: usize) -> usize {
    // `n` slots fit in the bucket; one is reserved for the payload, so `n - 1` may carry hops.
    match (THRESHOLD_ONION_LEN - PREAMBLE_LEN).checked_div(slot_len(line_size)) {
        Some(0) | None => 0,
        Some(n) if n - 1 < TARGET_DEPTH => n - 1,
        Some(_) => TARGET_DEPTH,
    }
}

/// The largest structure this protocol nests inside an onion payload: a threshold seal to one hop line.
///
/// Exists so the payload floor in [`depth_for`] is a *derived* quantity a test can assert against, rather than a constant
/// someone has to trust.
#[must_use]
pub const fn nested_seal_len(line_size: usize) -> usize {
    NONCE_LEN + 2 + 4 + AEAD_TAG_LEN + line_size * SEALED_SHARE_LEN
}

/// The fixed-width command inside a slot: `tag(1) ‖ operand(32) ‖ payload_key(32)`.
///
/// One width for both commands, so the *kind* of command is not readable from its size either: `CMD_NEXT` carries a
/// 12-byte line coordinate and `CMD_DELIVER` a 32-byte holonomy tag, and the shorter one is padded. Without this the final
/// hop would be distinguishable from every intermediate hop — the same leak one step smaller.
///
/// The hop's **payload key** rides here rather than being derived from the threshold layer key, so the seal needs no new API
/// to hand its reconstructed key back. Deriving it from the *command* instead would be a trap: two hops forwarding to the
/// same next line would then share a keystream.
pub const CMD_LEN: usize = 1 + 32 + 32;

/// Offset of the payload key within a command.
pub const CMD_KEY_AT: usize = 1 + 32;

/// Bytes a single slot occupies: the sealed command plus one KEM-sealed share per line member.
///
/// `ThresholdSealed::to_bytes` is `nonce(12) ‖ members(2) ‖ ct_len(4) ‖ ciphertext ‖ share*`, and the ciphertext is
/// `CMD_LEN` plus the AEAD tag — all fixed once `line_size` is.
#[must_use]
pub const fn slot_len(line_size: usize) -> usize {
    NONCE_LEN + 2 + 4 + CMD_LEN + AEAD_TAG_LEN + line_size * SEALED_SHARE_LEN
}

/// The AEAD tag appended by the seal's ciphertext.
const AEAD_TAG_LEN: usize = 16;

/// The header's total width for a plane whose lines hold `line_size` points.
#[must_use]
pub const fn header_len(line_size: usize) -> usize {
    depth_for(line_size) * slot_len(line_size)
}

/// The payload block's width — whatever the header leaves of the constant bucket.
///
/// `None` when the line is so wide that a header leaves no usable payload, which is the honest answer rather than a
/// silently truncated packet.
#[must_use]
pub const fn payload_len(line_size: usize) -> Option<usize> {
    match THRESHOLD_ONION_LEN.checked_sub(header_len(line_size) + PREAMBLE_LEN) {
        Some(n) if n > 4 => Some(n),
        _ => None,
    }
}

/// `slots(2) ‖ slot_len(4)`.
pub const PREAMBLE_LEN: usize = 6;

/// The line size a slot of `slot_len` bytes implies — the inverse of [`slot_len`].
///
/// A hop needs it to frame the filler it appends, and it must come from the packet rather than from configuration: the
/// packet's declared width is what its peers will parse against.
#[must_use]
pub const fn line_size_of(slot_len: usize) -> Option<usize> {
    match slot_len.checked_sub(NONCE_LEN + 2 + 4 + CMD_LEN + AEAD_TAG_LEN) {
        Some(rest) if rest % SEALED_SHARE_LEN == 0 => Some(rest / SEALED_SHARE_LEN),
        _ => None,
    }
}

/// A parsed packet: the slot array and the payload block, both at their fixed widths.
pub struct Packet {
    /// Number of slots in the header — always [`depth_for`] the plane's line size in a well-formed packet.
    pub slots: usize,
    /// Bytes per slot, fixed by the plane's line size.
    pub slot_len: usize,
    /// The `slots × slot_len` header.
    pub header: Vec<u8>,
    /// The constant-width payload block.
    pub payload: Vec<u8>,
}

impl Packet {
    /// Assemble a packet from its header and payload block.
    #[must_use]
    pub fn new(slot_len: usize, header: Vec<u8>, payload: Vec<u8>) -> Self {
        Self { slots: header.len().checked_div(slot_len).unwrap_or(0), slot_len, header, payload }
    }

    /// Serialize to the wire form.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREAMBLE_LEN + self.header.len() + self.payload.len());
        out.extend_from_slice(&u16::try_from(self.slots).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&u32::try_from(self.slot_len).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse the wire form, or `None` if the preamble disagrees with the bytes present.
    ///
    /// Checked rather than trusted: these bytes arrive from the network, and a packet whose declared shape does not match
    /// its length is exactly the shape an attacker submits to make a peel read out of bounds.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let slots = usize::from(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?));
        let slot_len = usize::try_from(u32::from_be_bytes(bytes.get(2..PREAMBLE_LEN)?.try_into().ok()?)).ok()?;
        let header_bytes = slots.checked_mul(slot_len)?;
        let header = bytes.get(PREAMBLE_LEN..PREAMBLE_LEN.checked_add(header_bytes)?)?.to_vec();
        let payload = bytes.get(PREAMBLE_LEN + header_bytes..)?.to_vec();
        Some(Self { slots, slot_len, header, payload })
    }

    /// Slot `i`, or `None` if out of range.
    #[must_use]
    pub fn slot(&self, i: usize) -> Option<&[u8]> {
        let start = i.checked_mul(self.slot_len)?;
        self.header.get(start..start.checked_add(self.slot_len)?)
    }

    /// Shift the header one slot left and append `filler`, keeping the width exactly constant.
    ///
    /// This is what makes the packet unreadable as a depth counter: the hop that just consumed slot 0 hands on a header of
    /// the same `slots × slot_len` bytes it received.
    pub fn shift_in(&mut self, filler: &[u8]) {
        if self.slot_len == 0 || self.header.len() < self.slot_len {
            return;
        }
        self.header.drain(..self.slot_len);
        self.header.extend_from_slice(filler);
        self.header.truncate(self.slots * self.slot_len);
    }
}

/// Derive `n` bytes of keystream for a hop from its layer `key` under `label`.
#[must_use]
pub fn keystream(label: &str, key: &[u8], n: usize) -> Vec<u8> {
    let mut out = alloc::vec![0u8; n];
    hash_xof(label, key, &mut out);
    out
}

/// XOR `block` in place with keystream derived from `key` — the size-preserving payload layer.
///
/// Its own inverse, so one call encrypts at the sender and one decrypts at the hop.
pub fn xor_payload(block: &mut [u8], key: &[u8]) {
    let ks = keystream("FANOS-v1/threshold-onion-payload", key, block.len());
    for (b, k) in block.iter_mut().zip(ks) {
        *b ^= k;
    }
}

/// The filler slot a hop appends after consuming slot 0 — pseudorandom, but **framed exactly like a real slot**.
///
/// Pure keystream is not enough, and this is the leak that survives a naive constant-width fix. A relay holds the entire
/// header, so it can try to *parse* each slot: `ThresholdSealed::to_bytes` is
/// `nonce(12) ‖ members(2) ‖ ct_len(4) ‖ ciphertext ‖ share*`, and `members`/`ct_len` are fixed constants for a given plane.
/// Random bytes get them wrong with overwhelming probability, so a relay counts the slots that parse and recovers the
/// remaining depth exactly — the original leak restored through the back door. Measured on a 2-hop circuit over a plane
/// carrying 5: **2 of 5 slots parsed**, which is precisely the number of real hops.
///
/// So filler reproduces the framing and randomizes only what is genuinely opaque — the ciphertext and the sealed shares,
/// neither of which a relay can verify without the line's secrets.
#[must_use]
pub fn filler_slot(key: &[u8], line_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(slot_len(line_size));
    out.extend_from_slice(&keystream("FANOS-v1/threshold-onion-filler-nonce", key, NONCE_LEN));
    out.extend_from_slice(&u16::try_from(line_size).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&u32::try_from(CMD_LEN + AEAD_TAG_LEN).unwrap_or(u32::MAX).to_be_bytes());
    let opaque = CMD_LEN + AEAD_TAG_LEN + line_size * SEALED_SHARE_LEN;
    out.extend_from_slice(&keystream("FANOS-v1/threshold-onion-filler", key, opaque));
    out
}

/// Pack `payload` into a constant-width block: `len(4) ‖ payload ‖ pad`.
///
/// The pad is keystream from `seed`, not zeros, so a block is not distinguishable from ciphertext before its layers are
/// applied. `TooLong` if the payload does not fit the block a header of `MAX_DEPTH` slots leaves.
pub fn pack_payload(payload: &[u8], line_size: usize, seed: &[u8]) -> Result<Vec<u8>, ThresholdError> {
    let width = payload_len(line_size).ok_or(ThresholdError::TooLong)?;
    if payload.len() + 4 > width {
        return Err(ThresholdError::TooLong);
    }
    let mut block = Vec::with_capacity(width);
    block.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(u32::MAX).to_be_bytes());
    block.extend_from_slice(payload);
    block.extend_from_slice(&keystream("FANOS-v1/threshold-onion-block-pad", seed, width - block.len()));
    Ok(block)
}

/// Recover the payload from a fully-peeled block, or `None` if its length prefix does not fit.
#[must_use]
pub fn unpack_payload(block: &[u8]) -> Option<Vec<u8>> {
    let len = usize::try_from(u32::from_be_bytes(block.get(..4)?.try_into().ok()?)).ok()?;
    Some(block.get(4..4usize.checked_add(len)?)?.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A NOSTOS reply circuit: one intermediate mix line, then the delivery line.
    const REPLY_HOPS: usize = 2;

    #[test]
    fn the_budget_fits_and_states_its_own_depth_ceiling() {
        // The layout is only free if it fits the width the previous one already spent. At the Fano line size it does, with
        // room left for a payload — and the ceiling it makes explicit is the point: depth and plane order trade against a
        // fixed budget, where the nested layout let a sender exceed both and leak instead.
        // Every plane's header fits its own budget, and the depth it can carry is the legible trade the layout makes.
        for line_size in [3usize, 4, 5, 6, 8] {
            assert!(header_len(line_size) + PREAMBLE_LEN <= THRESHOLD_ONION_LEN, "line {line_size}: header fits");
            assert!(payload_len(line_size).is_some(), "line {line_size}: a payload block remains");
        }
        // The target depth where the plane affords it, less where it does not.
        // Every supported plane must leave room for one nested threshold seal, which is the largest thing the protocol puts
        // inside an onion payload. Without this the depth policy is right on narrow planes and silently breaks wide ones.
        for line_size in [3usize, 4, 5, 6, 8] {
            let payload = payload_len(line_size).unwrap_or(0);
            assert!(
                payload >= nested_seal_len(line_size),
                "line {line_size}: payload {payload} must hold one nested seal of {}",
                nested_seal_len(line_size)
            );
        }
        // A NOSTOS reply is two hops (one mix line, then the delivery line), so a plane can host the anonymity substrate
        // only if it affords at least two. This is the constraint the plane-order decision turns on.
        for (q, line_size) in [(2usize, 3usize), (3, 4), (4, 5)] {
            assert!(depth_for(line_size) >= REPLY_HOPS, "q = {q} must afford a {REPLY_HOPS}-hop reply circuit");
        }
        assert!(depth_for(8) < REPLY_HOPS, "q = 7 cannot, inside this bucket — a wider cell is required there");
        assert_eq!(depth_for(3), TARGET_DEPTH, "q = 2 affords the target depth");
        assert_eq!(depth_for(4), TARGET_DEPTH, "q = 3 affords it too");
        assert_eq!(depth_for(5), 2, "q = 4 affords only two hops once the payload floor is honoured");
        assert_eq!(depth_for(8), 1, "q = 7 affords only one — the bucket is too narrow for a circuit there");
        // And the payload is what the policy is for: budget-filling left 2.4 KiB, which is smaller than structures this
        // protocol nests *inside* an onion payload (sealing to a 3-member line alone is ~3.5 KiB).
        // **Against the packet's own width, not a copy of it.** `8192` here was `fanos_wire::tessera::TOTAL_LEN`
        // spelled out by hand — this crate imports that module, so the literal bought nothing and would have
        // gone quietly wrong the moment the packet resized: the assertion would still pass while testing a
        // ratio the layout no longer has. A payload worth more than the whole packet is the meaningful claim,
        // and it is only meaningful if the two numbers cannot drift apart.
        assert!(
            payload_len(3).unwrap() > fanos_wire::tessera::TOTAL_LEN,
            "capping depth leaves a real payload — more than a whole packet's worth: {:?}",
            payload_len(3),
        );
    }

    #[test]
    fn a_shift_keeps_the_header_exactly_as_wide() {
        // The property the whole layout exists for. Whatever a hop consumes, it hands on the same number of bytes.
        let sl = 8usize;
        let mut p = Packet::new(sl, alloc::vec![7u8; 4 * sl], alloc::vec![1u8; 100]);
        let before = (p.header.len(), p.payload.len());
        for _ in 0..6 {
            p.shift_in(&alloc::vec![9u8; sl]);
            assert_eq!((p.header.len(), p.payload.len()), before, "width is invariant under shifting");
        }
    }

    #[test]
    fn a_packet_round_trips_and_a_lying_preamble_is_refused() {
        let sl = 16usize;
        let p = Packet::new(sl, alloc::vec![3u8; 4 * sl], alloc::vec![4u8; 64]);
        let bytes = p.to_bytes();
        let back = Packet::from_bytes(&bytes).expect("round trip");
        assert_eq!((back.slots, back.slot_len), (4, sl));
        assert_eq!(back.header, p.header);
        assert_eq!(back.payload, p.payload);
        // A preamble claiming more header than the packet holds must not read past the end.
        let mut lying = bytes.clone();
        lying[0..2].copy_from_slice(&u16::to_be_bytes(9999));
        assert!(Packet::from_bytes(&lying).is_none(), "a header wider than the packet is refused");
        // And one that overflows the multiply.
        let mut overflow = bytes;
        overflow[2..6].copy_from_slice(&u32::to_be_bytes(u32::MAX));
        assert!(Packet::from_bytes(&overflow).is_none(), "an overflowing slot width is refused");
    }

    #[test]
    fn a_filler_slot_parses_as_a_sealed_layer_so_it_cannot_be_counted() {
        // The second-order leak, and the one a constant-*width* test cannot see. A relay holds the whole header, so if an
        // unused slot fails to parse as a sealed layer while a real one succeeds, the relay counts the parseable slots and
        // recovers the remaining depth — the original leak restored through the back door. Measured with pure-keystream
        // filler on a 2-hop circuit over a plane carrying 5: **2 of 5 slots parsed**, exactly the real hop count.
        //
        // So filler must reproduce the seal's framing (`members`, `ct_len`) and randomize only what is genuinely opaque.
        for line_size in [3usize, 5, 8] {
            let filler = filler_slot(b"a-layer-key", line_size);
            assert_eq!(filler.len(), slot_len(line_size), "line {line_size}: filler is exactly one slot wide");
            let parsed = fanos_threshold::ThresholdSealed::from_bytes(&filler)
                .unwrap_or_else(|| panic!("line {line_size}: filler must parse as a sealed layer"));
            assert_eq!(parsed.member_count(), line_size, "line {line_size}: and declare the plane's member count");
        }
        // Two fillers under different keys differ, so a slot is not a constant an observer can recognise either.
        assert_ne!(filler_slot(b"k1", 3), filler_slot(b"k2", 3), "filler is keyed, not a fixed pattern");
    }

    #[test]
    fn a_payload_block_round_trips_at_constant_width_and_refuses_an_oversize_one() {
        let width = payload_len(3).unwrap();
        let block = pack_payload(b"hello", 3, b"s").unwrap();
        assert_eq!(block.len(), width, "the block is the same width whatever it carries");
        assert_eq!(unpack_payload(&block).unwrap(), b"hello");
        let empty = pack_payload(b"", 3, b"s").unwrap();
        assert_eq!(empty.len(), width, "including empty");
        assert!(pack_payload(&alloc::vec![0u8; width], 3, b"s").is_err(), "an oversize payload errors, never truncates");
    }

    #[test]
    fn a_payload_layer_is_its_own_inverse_and_preserves_width() {
        let mut block = pack_payload(b"round trip me", 3, b"s").unwrap();
        let original = block.clone();
        for key in [&b"k1"[..], &b"k2"[..], &b"k3"[..]] {
            xor_payload(&mut block, key);
        }
        assert_ne!(block, original, "layered");
        assert_eq!(block.len(), original.len(), "and size-preserving");
        for key in [&b"k3"[..], &b"k2"[..], &b"k1"[..]] {
            xor_payload(&mut block, key);
        }
        assert_eq!(block, original, "peeling in reverse recovers it");
    }
}
