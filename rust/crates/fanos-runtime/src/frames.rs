//! The overlay's **frame codec** — every `encode_*`/`parse_*` for the wire bodies `OverlayNode` speaks, split out of
//! `overlay.rs` (task 7a).
//!
//! Pure serialization and its inverse, plus the two signature/challenge derivations that are *about* a frame's contents
//! (`descriptor_signature_ok`, `admission_challenge`). Nothing here touches node state, which is exactly why it separates
//! cleanly: a codec that needed the node would not be a codec.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{HierAddr, Triple};
use fanos_diakrisis::polar;
use fanos_primitives::Epoch;
use fanos_wire::error::ProtocolError;
use fanos_wire::{FrameType, Wire, encode_frame};

use crate::overlay::{DIGEST, ParsedAnnounce};

/// Build a wire frame with the given type and body.
pub(crate) fn encode(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(ty.code(), body, &mut out);
    out
}

/// A `Publish` frame: `flag(1) ‖ shard_index(1) ‖ version(8) ‖ key(32) ‖ payload` (spec §L4). For a
/// `PUBLISH_SHARD` the payload is one erasure shard for `shard_index` at write-`version`; for a
/// `PUBLISH_ORIGIN` it is the full value and index/version are `0` (the responsible node assigns the version).
pub(crate) fn encode_publish(
    flag: u8,
    index: u8,
    version: u64,
    digest: &[u8; DIGEST],
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + 8 + DIGEST + payload.len());
    body.push(flag);
    body.push(index);
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(digest);
    body.extend_from_slice(payload);
    encode(FrameType::Publish, &body)
}

/// The `Lookup` frame body: `key(32) ‖ nonce(8)` (spec §L4). The nonce is the reader's per-request
/// correlator, echoed in the `Value` reply so a stale/replayed answer cannot resolve a different read
/// (audit C4). Its canonical codec is **derived** — one definition, one encoding (audit A1/G2).
#[derive(fanos_wire_derive::Wire)]
pub(crate) struct LookupBody {
    pub(crate) key: [u8; DIGEST],
    pub(crate) nonce: u64,
}

/// A `DiagAttest` frame body (spec §6.4): this node's honest polar-class report — the 3 rates
/// for the channels it mediates (`polar::polar_class(self_index)`), in that fixed order — as raw
/// `3 × f64` little-endian (24 bytes). Bit-exact, no quantization: an honest report's 3 values are
/// identical by construction (`polar::mediator_attestation`), and must round-trip identical
/// against the receiver's tight `POLAR_TOLERANCE` check.
pub(crate) fn encode_diag_attest(self_index: usize, degraded: u8) -> Vec<u8> {
    let rates = polar::mediator_attestation(self_index, degraded);
    let mut body = Vec::with_capacity(24);
    for r in rates {
        body.extend_from_slice(&r.to_le_bytes());
    }
    body
}

/// A `Lookup` frame (the derived body under the frame header).
pub(crate) fn encode_lookup(digest: &[u8; DIGEST], nonce: u64) -> Vec<u8> {
    encode(
        FrameType::Lookup,
        &LookupBody {
            key: *digest,
            nonce,
        }
        .to_wire(),
    )
}

/// A `Value` reply: `key(32) ‖ found(1) ‖ shard_index(1) ‖ version(8) ‖ nonce(8) ‖ shard` (spec §L4) — the
/// nonce echoes the `Lookup`'s; `shard_index` names which Fano point's erasure shard this carries and
/// `version` its write-version, so the reader groups shards by version and reconstructs the highest recoverable
/// one (#115). A `found=false` reply carries index/version `0` and an empty shard.
pub(crate) fn encode_value(
    digest: &[u8; DIGEST],
    found: bool,
    index: u8,
    version: u64,
    shard: &[u8],
    nonce: u64,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(DIGEST + 2 + 16 + shard.len());
    body.extend_from_slice(digest);
    body.push(u8::from(found));
    body.push(index);
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&nonce.to_be_bytes());
    body.extend_from_slice(shard);
    encode(FrameType::Value, &body)
}

/// Fold a key digest into a `u64` seed for DA line-sampling (§L4.3): the first 8 digest bytes. The digest is a
/// hash, so this is unpredictable to anyone who does not know the key — which is what denies a withholding
/// adversary the chance to pre-position the lone external line.
pub(crate) fn fold_seed(digest: &[u8; DIGEST]) -> u64 {
    let mut head = [0u8; 8];
    for (h, &b) in head.iter_mut().zip(digest.iter()) {
        *h = b;
    }
    u64::from_le_bytes(head)
}

/// Parse a big-endian `u64` at byte offset `off` from `body`, or `None` if it is too short.
pub(crate) fn parse_u64(body: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = body.get(off..off.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Parse a 32-byte key digest from an optional slice.
pub(crate) fn parse_digest(slice: Option<&[u8]>) -> Option<[u8; DIGEST]> {
    <[u8; DIGEST]>::try_from(slice?).ok()
}

/// The bytes a node's hybrid signing key signs to bind its **transport coordinate** to its identity's
/// **overlay address**: `coord(12) ‖ hier ‖ id` (spec §80). A deployment signs this once and installs
/// the signature via [`OverlayNode::with_signed_descriptor`](crate::OverlayNode::with_signed_descriptor); a receiver reconstructs it from the parsed
/// announce and checks the signature — so an attacker cannot re-announce another identity's address at
/// its own coordinate (it would have to forge that identity's signature over a *different* `coord`).
#[must_use]
pub fn descriptor_message<F: Field>(coord: Triple, hier: &HierAddr<F>, id: &[u8]) -> Vec<u8> {
    let hier_bytes = hier.encode();
    let mut msg = Vec::with_capacity(12 + hier_bytes.len() + id.len());
    msg.extend_from_slice(&fanos_geometry::encode_triple(coord));
    msg.extend_from_slice(&hier_bytes);
    msg.extend_from_slice(id);
    msg
}

/// Whether `sig` is a valid hybrid signature over the descriptor `coord ‖ hier ‖ id`, under the
/// signature verifier packed at the front of the identity bundle `id` (`Ed25519(32) ‖ ML-DSA-65(1952)`
/// = [`HYBRID_VK_LEN`](fanos_pqcrypto::sig::HYBRID_VK_LEN) bytes). Binds the transport coordinate to the
/// identity, so a peer cannot re-announce another node's address at its own coordinate (§80). Any wrong
/// length or bad half returns `false` — never panics.
pub(crate) fn descriptor_signature_ok<F: Field>(
    coord: Triple,
    hier: &HierAddr<F>,
    id: &[u8],
    sig: &[u8],
) -> bool {
    let Some(verifier) = id
        .get(..fanos_pqcrypto::sig::HYBRID_VK_LEN)
        .and_then(fanos_pqcrypto::HybridVerifier::decode)
    else {
        return false;
    };
    let Some(signature) = fanos_pqcrypto::HybridSignature::from_bytes(sig) else {
        return false;
    };
    let msg = descriptor_message(coord, hier, id);
    verifier.verify(&msg, &signature)
}

/// An `Announce` body: `coord(12) ‖ hier(1+depth×12) ‖ id_len(2) ‖ id ‖ sig_len(2) ‖ sig ‖
/// proof_len(2) ‖ proof ‖ info` (spec §7.8 JOIN, §L1 address, §80 signed descriptor, §L3 Sybil
/// admission). `coord` is the transport point peers send to; `hier` is the announcer's overlay
/// address, so a receiver seeds its routing table (`hier → coord`). `id` is the announcer's
/// identity bundle (§L0) — the address derives from it — `sig` is the hybrid signature over
/// [`descriptor_message`] binding the coordinate to that identity, and `proof` is the
/// announcer's Sybil-admission proof, checked against [`admission_challenge`]`(coord, epoch)`
/// by a peer requiring admission. Every variable field is length- or self-delimited, so `info`
/// follows unambiguously.
pub(crate) fn announce_body<F: Field>(
    coord: Triple,
    hier: &HierAddr<F>,
    id: &[u8],
    sig: &[u8],
    proof: &[u8],
    info: &[u8],
) -> Vec<u8> {
    let hier_bytes = hier.encode();
    let id_len = u16::try_from(id.len()).unwrap_or(u16::MAX);
    let id = id.get(..usize::from(id_len)).unwrap_or(id);
    let sig_len = u16::try_from(sig.len()).unwrap_or(u16::MAX);
    let sig = sig.get(..usize::from(sig_len)).unwrap_or(sig);
    let proof_len = u16::try_from(proof.len()).unwrap_or(u16::MAX);
    let proof = proof.get(..usize::from(proof_len)).unwrap_or(proof);
    let mut body = Vec::with_capacity(
        12 + hier_bytes.len() + 2 + id.len() + 2 + sig.len() + 2 + proof.len() + info.len(),
    );
    body.extend_from_slice(&fanos_geometry::encode_triple(coord));
    body.extend_from_slice(&hier_bytes);
    body.extend_from_slice(&id_len.to_be_bytes());
    body.extend_from_slice(id);
    body.extend_from_slice(&sig_len.to_be_bytes());
    body.extend_from_slice(sig);
    body.extend_from_slice(&proof_len.to_be_bytes());
    body.extend_from_slice(proof);
    body.extend_from_slice(info);
    body
}

/// Parse an `Announce` body into `(coord, hier, id, sig, proof, info)`. `None` on a short buffer
/// or a non-canonical hierarchical address (so a forged announce cannot inject a bogus
/// routing-table entry).
pub(crate) fn parse_announce<F: Field>(body: &[u8]) -> Option<ParsedAnnounce<F>> {
    let coord = fanos_geometry::decode_triple(body.get(..12)?)?;
    let rest = body.get(12..)?;
    let hier_len = 1 + usize::from(*rest.first()?) * 12;
    let hier = HierAddr::<F>::decode(rest.get(..hier_len)?)?;
    let after_hier = rest.get(hier_len..)?;
    let id_len = usize::from(u16::from_be_bytes(after_hier.get(0..2)?.try_into().ok()?));
    let id = after_hier.get(2..2 + id_len)?.to_vec();
    let after_id = after_hier.get(2 + id_len..)?;
    let sig_len = usize::from(u16::from_be_bytes(after_id.get(0..2)?.try_into().ok()?));
    let sig = after_id.get(2..2 + sig_len)?.to_vec();
    let after_sig = after_id.get(2 + sig_len..)?;
    let proof_len = usize::from(u16::from_be_bytes(after_sig.get(0..2)?.try_into().ok()?));
    let proof = after_sig.get(2..2 + proof_len)?.to_vec();
    let info = after_sig.get(2 + proof_len..)?.to_vec();
    Some((coord, hier, id, sig, proof, info))
}

/// The domain-separated Sybil-admission challenge for a joiner at `coord` in `epoch` (spec §L3):
/// what an [`AdmissionPolicy`](fanos_core::AdmissionPolicy) proof is checked against ([`OverlayNode::with_admission_policy`](crate::OverlayNode::with_admission_policy)).
/// Binding the coordinate and epoch means a proof cannot be replayed at a different address or
/// reused past an epoch roll. A live per-epoch beacon *seed* is not yet wired into
/// `OverlayNode` (§L3.2 / A7 Level B is tracked separately, not by this task); once it is,
/// folding it in here strengthens the binding as a drop-in change, not a redesign — `epoch`
/// already rotates unpredictably under the flooded epoch-agreement gossip (`on_epoch_agree`), so the
/// binding is real today, just not yet as strong as the full spec picture.
#[must_use]
/// The Sybil-admission challenge a joiner solves and a receiver re-derives — bound to **identity, coordinate and epoch**.
///
/// The identity component is what stops a solved proof being **replayed by another node claiming the same point**.
/// Without it an attacker could present the incumbent's own proof and pay nothing, which — combined with identity
/// grinding, measured at ~20 draws to collide with a chosen victim at a lower rank
/// (`fanos-vrf/examples/grind_probe.rs`) — made evicting a chosen node cost *zero* work.
///
/// **Honest limitation:** a node that carries no identity (self-certification not in use) contributes an empty component,
/// and the challenge degenerates to the old `(coord, epoch)` form, replayable among all such nodes. The defence therefore
/// requires the self-certifying membership path, and is one more reason to run it.
///
/// **What this does *not* fix, stated plainly:** identity grinding itself stays cheap, because evaluating a VRF for a
/// candidate identity is local and offline — no admission gate can price it. Rank arbitration between an honest node and
/// a Sybil-capable adversary therefore rests on identities being *scarce* (stake- or reputation-bound), not on the rank
/// rule alone. See `docs/design-coordinates.md`.
pub fn admission_challenge(id: &[u8], coord: Triple, epoch: Epoch) -> Vec<u8> {
    let mut challenge = Vec::with_capacity(id.len() + 12 + 4);
    challenge.extend_from_slice(id);
    challenge.extend_from_slice(&fanos_geometry::encode_triple(coord));
    challenge.extend_from_slice(&epoch.low32_be_bytes());
    challenge
}

/// An `Error` frame body: `code(8B BE) ‖ reason` — the numeric [`ProtocolError`] code and an
/// optional UTF-8 reason (empty here; a human-readable reason is left to the wire-handshake
/// follow-up, task #100). Canonical derived codec (audit A1) — one definition, one encoding,
/// the same `#[derive(Wire)]` pattern [`LookupBody`] uses above: a `u64` field's canonical
/// encoding is a fixed 8-byte big-endian integer (`fanos_wire::wire::impl_wire_int!`), not a
/// true LEB128 varint. Spec §7.5 describes the ERROR frame prose-level as "a varint code" —
/// this preliminary body is a real, working `SYBIL_REJECT` producer ahead of that, not the
/// formalization; reconciling the exact on-wire integer width against the spec text (or
/// widening the derive's integer convention itself) is task #100's, not this one's, to settle.
#[derive(fanos_wire_derive::Wire)]
pub(crate) struct ErrorBody {
    pub(crate) code: u64,
    pub(crate) reason: Vec<u8>,
}

/// An `Error` frame carrying `err`'s numeric code **and a machine-readable reason**.
///
/// Used for `SYBIL_REJECT` to carry the difficulty the joiner must actually meet. An adaptive admission price
/// that is not communicated is a silent denial of service against exactly the honest peers the gate exists to
/// protect: their proof was minted at yesterday's price, it is refused, and nothing tells them the number that
/// would work. The reason field already existed and was always empty; this is what it is for.
///
/// Backward compatible in both directions — a peer that does not read the reason sees the same rejection it
/// always did, and a peer that does gets a retry it can actually satisfy.
pub(crate) fn encode_error_with(err: ProtocolError, reason: Vec<u8>) -> Vec<u8> {
    encode(FrameType::Error, &ErrorBody { code: err.code(), reason }.to_wire())
}

/// Parse an `Error` frame body.
pub(crate) fn parse_error(body: &[u8]) -> Option<ErrorBody> {
    ErrorBody::from_wire(body).ok()
}

/// The required admission difficulty carried by a `SYBIL_REJECT`, if it carries one.
///
/// `None` for a rejection from a peer that does not send it (an older build, or a refusal for some other
/// reason), which a joiner must treat as "no guidance" rather than as "zero" — retrying at zero would be an
/// infinite loop against a gate that is asking for work.
#[must_use]
pub(crate) fn decode_required_difficulty(reason: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(reason).ok().map(u32::from_le_bytes)
}
