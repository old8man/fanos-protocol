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
//! onion = slot[0] ‖ … ‖ slot[D-1] ‖ payload_block
//! ```
//!
//! Every hop reads **slot 0**, shifts the array one slot left, and appends a pseudorandom slot — so the header is always
//! `D` slots wide and the packet is byte-identical in size at every hop. Slot `k` as built is hop `k`'s, and after `k`
//! shifts it has arrived at position 0.
//!
//! **Nothing describes the packet but the packet.** `D` and the slot width are functions of the plane's line size, and a
//! relay must already know that to hold a threshold share of a hop line at all — so the layout carries no preamble. It
//! used to open with `slots(2) ‖ slot_len(4)`, defended as "network parameters, not circuit facts". True of the depth
//! *ceiling*, and beside the point: the fields were also a cleartext declaration of the sender's cell order at a fixed
//! offset, which sorts traffic into per-plane anonymity sets for free and cannot be seen in the length, since the total
//! is the same bucket on every plane. Derived at the reader instead, and cross-checked against the seal's own declared
//! member count, a foreign-plane packet fails to parse — which costs nothing, because each slot is threshold-sealed to a
//! line of the *sender's* size, so such a relay could never have been a hop on that circuit.
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

/// The fewest **intermediate** hops a forward circuit needs before its destination line — derived, and the
/// derivation is what [`TARGET_DEPTH`] rests on.
///
/// Write the forward circuit as `[H_1, …, H_d, M]`, where `M` is the service's meeting line. Two of those
/// lines can *name* an endpoint, and which two follows from the protocol rather than from policy:
///
/// * **`H_1` names the client.** The client transmits the onion to `H_1`'s members itself, so `H_1` sees its
///   address. Nothing else on the path does.
/// * **`H_d` names the service.** Peeling the last intermediate slot reveals the next hop, which is `M` — and
///   `M` is a deterministic function of the service's public key (the client derives it with no lookup), so
///   knowing `M` *is* knowing the service.
///
/// Deanonymization is one adversary holding both names. Each line costs `t = ⌈2(q+1)/3⌉` corrupted members to
/// capture, and two **distinct** lines meet in exactly one point, so two of them cost `2t − 1`. On every plane
/// this platform recommends that exceeds the tolerated budget `f = ⌊(n−1)/3⌋` — at `q = 2`, `2t − 1 = 3 > 2 = f`
/// — which is the whole anonymity claim, and it holds **only while the two lines are two**.
///
/// So `H_1 ≠ H_d`, hence `d ≥ 2`. At `d = 1` the single intermediate hop is both: it is dialled by the client
/// *and* it learns `M`, so `t` corrupted members — exactly `f` at Fano — deanonymize the session outright. At
/// `d = 0` the client dials the service's own meeting line. Neither is a weaker anonymity setting; both are
/// none, and the circuit still looks like a circuit.
pub const MIN_FORWARD_DEPTH: usize = 2;

/// The fewest **intermediate** hops a reply circuit needs before the client's drop line.
///
/// The same argument on the return leg. The reply circuit is `[R_1, …, R_e, D]`: `R_1` is dialled by whoever
/// launches the reply, so it names the service side, and `D` is the client's own drop line, so it names the
/// client to within its `q + 1` members. `R_1 ≠ D` gives `e ≥ 1`.
///
/// One rather than two because the reply's client-side name is weaker: `D` narrows the client to a line's
/// worth of points, where `H_1` gives an address.
pub const MIN_REPLY_DEPTH: usize = 1;

/// The circuit depth the layout targets, when the plane's budget allows it — **intermediate hops plus the
/// destination**, so [`MIN_FORWARD_DEPTH`] `+ 1`.
///
/// A **policy**, not a budget maximum, and the distinction is load-bearing. Filling the cell with slots leaves almost
/// nothing for the payload — and worse, it makes the payload *shrink* as the cell grows, since a wider cell buys more slots
/// rather than more room. Measured: doubling `THRESHOLD_ONION_LEN` to 40 960 took the payload from 2 444 B to **1 288 B**.
/// An experiment that widened the cell to test for a payload shortage therefore tested nothing, and wrongly cleared it.
///
/// It used to say "three hops is what Tor uses". That is true and it is not a derivation — worse, Tor's hop is a
/// *node* that knows both its neighbours, while a hop here is a **line** that must be captured `t`-of-`q+1`, so
/// the two systems are not counting the same thing and one's number cannot justify the other's. The number is
/// the same and the reason is now the platform's own: `MIN_FORWARD_DEPTH + 1`.
///
/// Capping here also leaves ~9.6 KiB of payload at `q = 2` instead of 2.4.
pub const TARGET_DEPTH: usize = MIN_FORWARD_DEPTH + 1;

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
    match THRESHOLD_ONION_LEN.checked_div(slot_len(line_size)) {
        Some(0) | None => 0,
        Some(n) if n - 1 < TARGET_DEPTH => n - 1,
        Some(_) => TARGET_DEPTH,
    }
}

/// Whether a plane whose lines hold `line_size` points can carry a **sound** anonymous circuit — that is,
/// whether its slot budget reaches [`TARGET_DEPTH`].
///
/// The two halves were never joined. [`depth_for`] is a *budget*: how many hops the fixed-slot header can
/// afford once one slot is reserved for the payload. [`MIN_FORWARD_DEPTH`] is a *requirement*: how many the
/// anonymity argument needs. A plane can satisfy the budget and miss the requirement, and until this predicate
/// existed nothing compared them — the platform picked the depth that fit rather than the depth that was
/// needed, and a circuit one hop short still looks exactly like a circuit.
///
/// At the shipped `THRESHOLD_ONION_LEN` this is true at `q = 2` and `q = 3` and **false at `q = 4` and above**.
/// That is a real limit and it has a real answer — the onion budget is a per-deployment parameter, so a wide
/// plane wants a wider onion — but it must be *reported*, not discovered as dials that carry no anonymity.
#[must_use]
pub const fn plane_can_anonymize(line_size: usize) -> bool {
    depth_for(line_size) >= TARGET_DEPTH
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
    match THRESHOLD_ONION_LEN.checked_sub(header_len(line_size)) {
        Some(n) if n > 4 => Some(n),
        _ => None,
    }
}

/// A parsed packet: the slot array and the payload block, both at their fixed widths.
///
/// **The plane is not on the wire.** Both widths are functions of the line size, and the line size is a property of the
/// *reader's own plane* — a relay must already know it to hold a threshold share of a hop line at all. Declaring them
/// in a cleartext preamble was therefore never necessary, and cost two things:
///
/// * a relay on plane `A` would happily parse a packet built for plane `B`, instead of rejecting bytes it could not
///   possibly be a hop for;
/// * the sender's cell order sat in the clear at a fixed offset, so a passive observer could sort traffic by it. In a
///   deployment running more than one order that is an anonymity-set partition along a line no user chose — and it is
///   invisible from length alone, since the total is [`THRESHOLD_ONION_LEN`] on *every* plane.
///
/// Derived locally instead, a foreign-plane packet fails to parse. That is the correct outcome rather than a
/// regression: each slot is threshold-sealed to a line of the **sender's** size, so a relay on another plane could
/// never have been a hop on that circuit. The six bytes go back to the payload.
pub struct Packet {
    /// Points per line on **this node's plane** (`q + 1`) — the one parameter both widths derive from.
    pub line_size: usize,
    /// The `slots × slot_len` header.
    pub header: Vec<u8>,
    /// The constant-width payload block.
    pub payload: Vec<u8>,
}

impl Packet {
    /// Assemble a packet from its header and payload block.
    #[must_use]
    pub fn new(line_size: usize, header: Vec<u8>, payload: Vec<u8>) -> Self {
        Self { line_size, header, payload }
    }

    /// Bytes per slot on this packet's plane.
    #[must_use]
    pub const fn slot_len(&self) -> usize {
        slot_len(self.line_size)
    }

    /// Number of slots the header holds — [`depth_for`] this plane in a well-formed packet.
    #[must_use]
    pub fn slots(&self) -> usize {
        self.header.len().checked_div(self.slot_len()).unwrap_or(0)
    }

    /// Serialize to the wire form: `header ‖ payload`, and nothing else.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header.len() + self.payload.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Split the wire form at the header width **this plane** implies, or `None` if the bytes are not a packet of this
    /// plane's shape.
    ///
    /// Still checked rather than trusted — but the width now comes from the reader, so the check finally means
    /// something: previously the packet supplied both the claim and the evidence for it, which is no check at all. The
    /// exact-length test is what a constant-width layout is *for*, and it makes a truncated packet fail here rather
    /// than inside a peel.
    #[must_use]
    pub fn from_bytes(bytes: &[u8], line_size: usize) -> Option<Self> {
        if bytes.len() != THRESHOLD_ONION_LEN {
            return None;
        }
        let header = bytes.get(..header_len(line_size))?.to_vec();
        let payload = bytes.get(header_len(line_size)..)?.to_vec();
        Some(Self { line_size, header, payload })
    }

    /// Slot `i`, or `None` if out of range.
    #[must_use]
    pub fn slot(&self, i: usize) -> Option<&[u8]> {
        let start = i.checked_mul(self.slot_len())?;
        self.header.get(start..start.checked_add(self.slot_len())?)
    }

    /// Shift the header one slot left and append `filler`, keeping the width exactly constant.
    ///
    /// This is what makes the packet unreadable as a depth counter: the hop that just consumed slot 0 hands on a header of
    /// the same `slots × slot_len` bytes it received.
    pub fn shift_in(&mut self, filler: &[u8]) {
        let width = self.slot_len();
        let slots = self.slots();
        if width == 0 || self.header.len() < width {
            return;
        }
        self.header.drain(..width);
        self.header.extend_from_slice(filler);
        self.header.truncate(slots * width);
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
            assert!(header_len(line_size) <= THRESHOLD_ONION_LEN, "line {line_size}: header fits");
            assert!(payload_len(line_size).is_some(), "line {line_size}: a payload block remains");
            // Header and payload partition the budget *exactly* — there is nothing else on the wire, on any plane.
            assert_eq!(
                header_len(line_size) + payload_len(line_size).unwrap(),
                THRESHOLD_ONION_LEN,
                "line {line_size}: the two blocks are the whole packet"
            );
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
        let sl = slot_len(3);
        let mut p = Packet::new(3, alloc::vec![7u8; 4 * sl], alloc::vec![1u8; 100]);
        let before = (p.header.len(), p.payload.len());
        for _ in 0..6 {
            p.shift_in(&alloc::vec![9u8; sl]);
            assert_eq!((p.header.len(), p.payload.len()), before, "width is invariant under shifting");
        }
    }

    #[test]
    fn a_packet_round_trips_and_the_wire_names_no_plane() {
        let line_size = 3usize;
        let header = alloc::vec![3u8; header_len(line_size)];
        let payload = alloc::vec![4u8; payload_len(line_size).unwrap()];
        let p = Packet::new(line_size, header.clone(), payload.clone());
        let bytes = p.to_bytes();

        let back = Packet::from_bytes(&bytes, line_size).expect("round trip");
        assert_eq!((back.slots(), back.slot_len()), (depth_for(line_size), slot_len(line_size)));
        assert_eq!(back.header, header);
        assert_eq!(back.payload, payload);

        // **Nothing on the wire says which plane this is.** The layout used to open with `slots(2) ‖ slot_len(4)`, so
        // the sender's cell order sat in the clear at a fixed offset and a passive observer could sort traffic by it —
        // a partition of the anonymity set along a line no user chose, invisible from length alone because the total is
        // the same bucket on every plane. The packet is now the two blocks and nothing else.
        assert_eq!(bytes.len(), header.len() + payload.len(), "the wire is header ‖ payload, and nothing else");
        assert_eq!(&bytes[..header.len()], &header[..], "no preamble precedes the header");
        assert_eq!(bytes.len(), THRESHOLD_ONION_LEN, "and it is exactly the budget, on every plane");

        // A reader on another plane splits the same bytes elsewhere. That is precisely why the split must be the
        // *reader's* and then be checked against the seal (`open_slot0`): the packet can no longer dictate it, so a
        // foreign-plane circuit fails loudly instead of being mis-parsed into a peel.
        let foreign = Packet::from_bytes(&bytes, 5).expect("same total width, different plane");
        assert_ne!(foreign.header.len(), back.header.len(), "the split is the reader's, not the packet's");

        // Constant width is the layout's premise, so anything else is refused here rather than inside a peel.
        assert!(Packet::from_bytes(&bytes[..bytes.len() - 1], line_size).is_none(), "a truncated packet is refused");
        let mut over = bytes;
        over.push(0);
        assert!(Packet::from_bytes(&over, line_size).is_none(), "an over-long packet is refused");
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
