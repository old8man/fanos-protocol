//! The FANOS frame and its message-type registry (spec §7.2).
//!
//! All control traffic is a sequence of frames `type:varint ‖ length:varint ‖ body[length]`.
//! Types are grouped by high nibble so a router can dispatch on the group without a full
//! table; unknown non-critical types are skipped by `length` (forward-compatible).

use alloc::vec::Vec;

use crate::error::WireError;
use crate::varint;

/// **The transport's frame ceiling — one authority for the whole workspace.**
///
/// A receiver reads at most this many bytes per stream; anything larger is discarded. That makes it a
/// *protocol* bound rather than a transport detail: every producer of a frame — a consensus message, a
/// data-availability shard, an ANGELOS envelope — is bounded by it, so it belongs to the wire authority
/// that already numbers frame types, not to whichever driver happens to enforce it.
///
/// **It used to live in two places, and the consequence was measured rather than theorised.** It was a
/// private `const` in `fanos-quic`'s driver and a second `pub const` in `fanos-node`'s ANGELOS driver —
/// two copies free to drift, and invisible to everyone else. `fanos-taxis` in particular could not see it
/// at all, so the block producer had *no* size bound: a block whose payload exceeded the ceiling was
/// assembled, accepted by `verify_structure`, and then **silently dropped by the receiver** — the mempool
/// could not drain, because the block carrying it was undeliverable (defect #46).
///
/// Measured against a live QUIC driver: a 1 048 576-byte frame is delivered; 1 048 577 vanishes, the
/// sender's send call still reports success, no error is logged, and the connection survives. That
/// silence is why the bound has to be enforced by the *producer* — nothing downstream will complain.
pub const MAX_FRAME: usize = 1 << 20;

/// The message-type registry (spec §7.2). Discriminants encode the group in the high nibble.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u64)]
#[allow(missing_docs)] // the registry names are documented by the specification's §7.2 table
pub enum FrameType {
    // 0x0* Session
    Hello = 0x00,
    HelloAck = 0x01,
    Ping = 0x02,
    Pong = 0x03,
    Error = 0x05,
    /// A peer reports the source address it **observes** this node's connection arriving from — the
    /// reflexive/public address for NAT traversal (#119). Body: the observed `SocketAddr` encoded as
    /// `family(1B: 4|6) ‖ ip(4|16) ‖ port(2B BE)`. A node aggregates these across peers
    /// (`fanos_quic::ReflexiveAddr`) to learn the address it should advertise / be reached at.
    ObservedAddr = 0x06,
    /// A client asks a **common hub** to coordinate a hole-punch to a peer it cannot reach directly
    /// (NAT traversal #119): body is the target's coordinate (12B). The hub — which observed both
    /// parties' public addresses when they dialed in — replies to *both* with a [`PunchTo`](Self::PunchTo).
    ConnectReq = 0x07,
    /// A hub tells a node to dial a peer at its observed public address, for a coordinated simultaneous
    /// open (NAT traversal #119): body is `peer_coord(12B) ‖ family(1B) ‖ ip(4|16) ‖ port(2B BE)`. Both
    /// endpoints dial at once, so each NAT sees an outbound packet first and admits the inbound reply.
    PunchTo = 0x08,
    /// A node asks a **common hub** to forward an inner frame to a `target` it cannot reach directly — the
    /// symmetric-NAT relay fallback (NAT traversal #119): body is `target_coord(12B) ‖ inner frame`. The
    /// hub, reachable from both ends (each dialed in), writes the inner frame on to the target. Used only
    /// when a direct connection / hole-punch cannot be made, so any pair behind NAT can still communicate.
    Relay = 0x09,
    // 0x1* Membership
    Announce = 0x11,
    BeaconReq = 0x12,
    Beacon = 0x13,
    DkgDeal = 0x14,
    DkgJustify = 0x15,
    DkgCommit = 0x16,
    DkgComplaint = 0x17,
    /// A request to a dealer for its own commitment, sent by a participant that reached the sharing
    /// deadline without one (#DKG-QUAL). Contentless: it is addressed to the dealer, and the only
    /// commitment that dealer may answer with is its own.
    DkgCommitReq = 0x1D,
    /// A relayed frame that **carries its own origin proof** — the symmetric-NAT fallback's authenticated
    /// form (#119). Unlike [`Relay`](Self::Relay), whose `origin` field is a claim the receiver must take on
    /// trust, this one binds the inner frame to a coordinate the receiver derives for itself.
    RelayAttested = 0x0A,
    /// One anchor's distributed-VRF **beacon partial** for an epoch (audit E5): flooded among the
    /// beacon group; a threshold of them assemble the epoch's [`Beacon`](Self::Beacon) round.
    BeaconPartial = 0x18,
    /// A cell's **epoch-number agreement** gossip — a bare 4-byte `epoch_low32_be`, flooded adopt-max so
    /// the cell converges on the current epoch counter (spec §L3). This is deliberately **not** the
    /// [`Beacon`](Self::Beacon): the beacon carries a full threshold-DVRF *randomness* round, whereas this
    /// carries only the epoch ordinal. A node with no beacon configured uses this to advance its epoch;
    /// under a live beacon the DVRF round is authoritative and the composite suppresses this flood (audit
    /// #102 — previously the overlay overloaded the `Beacon` code with this 4-byte payload, colliding with
    /// a real round on the wire).
    EpochAgree = 0x19,
    /// A **beacon-resharing trigger** (audit R-C1): a coordinator (a parent cell, an operator rollover, or
    /// the lowest live anchor over a committed membership snapshot) starts resharing generation `g`, moving
    /// the beacon key to a fresh anchor set at a new threshold. Body: `gen(8B BE) ‖ new_threshold(1B) ‖
    /// count(1B) ‖ new_index(count × 1B)`. Every anchor that adopts a strictly-newer generation deals its
    /// verifiable contribution to that set — so a depleted anchor set is reconstituted from ≥ t survivors
    /// **before** it drops below threshold, without ever assembling the secret or changing the group key.
    BeaconReshareTrigger = 0x1A,
    /// One anchor's **public resharing commitment** `Dᵢ` for a generation (audit R-C1): flooded so every
    /// node derives the identical new group commitment `C' = Σ λᵢ(0)·Dᵢ` from public data alone. Body:
    /// `gen(8B BE) ‖ old_index(1B) ‖ new_threshold(1B) ‖ VssCommitment(Dᵢ)`.
    BeaconReshareCommit = 0x1B,
    /// One anchor's **private resharing sub-share** `gᵢ(j)` for a specific new holder `j` (audit R-C1): sent
    /// only to `j`, who checks it against the flooded `Dᵢ` and combines it into its new share. Body:
    /// `gen(8B BE) ‖ old_index(1B) ‖ VssShare(gᵢ(j), 33B)`.
    BeaconReshareShare = 0x1C,
    // 0x2* Overlay / storage
    Lookup = 0x20,
    Value = 0x21,
    Publish = 0x22,
    Ack = 0x23,
    // 0x3* Direct route
    Route = 0x30,
    /// Hierarchical route: `HierAddr(dst) ‖ payload` — forwarded cell-to-cell toward a multi-level
    /// destination (§L1 recursion). Degenerates to `Route` for a depth-1 (single-plane) address.
    RouteHier = 0x34,
    // 0x4* APHANTOS / NYX
    Tessera = 0x40,
    // 0x5* Rendezvous / CALYPSO
    RdvIntro = 0x50,
    RdvReply = 0x51,
    /// A client registers its coordinate with a [rendezvous relay] so the relay forwards anonymous
    /// replies delivered at its combiner to the client (audit #54; the sender is the client).
    RdvRegister = 0x53,
    /// A threshold-hosted service's combiner asks a co-line member for its PartialDec of an intro
    /// (spec §12.3, audit #99): body is the `SealedIntro` bytes (from `fanos_calypso::hosting`); the
    /// member replies with a [`SvcPartial`](Self::SvcPartial). No single host reads an intro alone.
    SvcShareReq = 0x54,
    /// A service-line member's PartialDec reply to its combiner (spec §12.3, audit #99): body is the
    /// 32-byte intro id ‖ the member's Shamir share (`x(1B) ‖ y`). The combiner Lagrange-combines `t`.
    SvcPartial = 0x55,
    /// A new node's **POROS ingress request** to the ingress-line combiner (spec §6, censorship
    /// bootstrap): body is the identity-bound `IngressRequest` bytes. The combiner gathers a threshold of
    /// descriptor shares and replies with a [`PorosResponse`](Self::PorosResponse).
    PorosRequest = 0x56,
    /// A POROS combiner asks a co-line member for its threshold-hosted **descriptor share** (spec §6):
    /// the member replies with a [`PorosShare`](Self::PorosShare). No single host holds the entry set.
    PorosShareReq = 0x57,
    /// A POROS line member's descriptor-share reply to its combiner: body is `x(1B) ‖ y`. The combiner
    /// reconstructs the ingress descriptor from a threshold of these, then serves a bucket.
    PorosShare = 0x58,
    /// A POROS combiner's response to a requester: a bounded bucket of entry peers (never the full set).
    PorosResponse = 0x59,
    /// A POROS **descriptor-reshare** sub-share when the ingress line rotates for a new epoch (spec §6):
    /// body is `target_epoch(8) ‖ old_x(1) ‖ SealedShare` — one old-line member's contribution, KEM-sealed to
    /// the *new* member it is sent to, so the sub-share is confidential in transit. A new member gathers a
    /// threshold of these (one per old member) and combines them into its rotated share without the descriptor
    /// ever being reconstructed (CHURP-style proactive resharing).
    PorosReshare = 0x5A,
    // 0x6* DIAKRISIS
    DiagGossip = 0x60,
    /// A node's live polar-class cross-attestation (audit #98, spec §6.4): the rates it honestly
    /// reports for the 3 channels it mediates (`fanos_diakrisis::polar::polar_class`), flooded on
    /// the heartbeat like [`DiagGossip`](Self::DiagGossip). Feeds the 14 free polar sum-rule
    /// alarms (§6.2) live — an equivocating mediator's own report disagrees with itself and is
    /// localized by `fanos_diakrisis::polar::violated_classes`.
    DiagAttest = 0x63,
    /// A node's measured **per-neighbour loss vector** (spec §6.3 grey detection, #106): the fraction of its
    /// pings to each Fano point that went unanswered, one `u8` per point (`loss × 255`), flooded on the
    /// heartbeat like [`DiagGossip`](Self::DiagGossip). Assembled cell-wide into a channel-rate matrix whose
    /// polar minimum-incident reading (`fanos_diakrisis::polar::grey_endpoint`) localizes a grey node — one
    /// heartbeat-present but lossy on every channel, which the liveness and equivocation checks cannot see.
    DiagLoss = 0x64,
    /// A **cell escalation** to the parent stratum (audit R-C2): a child cell that exhausted its own
    /// `Φ`-budget hands its irrecoverable residue up. Body: `child_index(1) ‖ residue(1) ‖ ttl(1)` — the
    /// child cell's point in the parent, its unrecoverable node-mask (a stopping set, or `0` on a coherence
    /// collapse), and a hop budget that bounds the recursion. A parent-cell member folds it into its
    /// ``ParentCell`` reflex — the same reflexive Fano decoder one tier up — and coarse-reroutes
    /// around the failed child, or re-escalates the aggregate to the grandparent until absorbed or terminal.
    CellEscalate = 0x65,
    // 0x7* Application overlays (Kernel/Protocol split, design-platform.md §Kernel): a system Protocol
    // runs on port 0 and application overlays multiplex under one length-skippable outer type.
    App = 0x70,
}

impl FrameType {
    /// Whether an **unknown** type in this dispatch group must abort rather than be skipped (spec §7.2).
    ///
    /// The spec, this module's header and `activation.rs` all state the rule — "unknown types are skipped by
    /// `length`, unknown **critical** types abort with `UNSUPPORTED`" — and none of them said which types are
    /// critical. Nothing implemented it, and [`WireError::UnknownCriticalFrame`] existed with no site that
    /// could construct it: the concept was asserted in three places and was a `Display` arm.
    ///
    /// **The derivation.** Skipping is right when ignorance costs *availability*: an unread `LOOKUP` is a
    /// missed read, an unread `TESSERA` a dropped circuit, an unread `APP` an application's problem. It is
    /// wrong when ignorance costs *agreement* — when a quorum acts on a frame and a node that ignored it
    /// carries on as though nothing happened. That is the membership group `0x1*` and only it: `BEACON`
    /// rounds fix the epoch every coordinate, meeting point and roster derives from, and
    /// `BEACON_RESHARE_*` retires the key material underneath them. A node that skips those does not fail —
    /// it keeps serving, on a retired epoch, indistinguishably from a healthy one, which is the silent
    /// divergence `activation.rs` documents as the failure shape this platform most needs to avoid.
    ///
    /// Aborting does not make an old node obey a frame it cannot parse; it makes it **stop participating**
    /// instead of participating wrongly. That is the fail-closed half, and the reason criticality is not
    /// merely redundant with capability negotiation: capabilities govern what a well-behaved peer *sends*,
    /// this governs what an old node does when one arrives anyway.
    ///
    /// Judged on the **raw code's** group, because the whole case is a type this build cannot name.
    #[must_use]
    pub const fn group_is_critical(code: u64) -> bool {
        // `0x1*` — Membership: BEACON, BEACON_PARTIAL, EPOCH_AGREE, BEACON_RESHARE_*, ANNOUNCE, DKG_*.
        code >> 4 == 0x1
    }

    /// The dispatch group (high nibble) of the type (spec §7.2).
    #[must_use]
    pub fn group(self) -> u8 {
        (self as u64 >> 4) as u8
    }

    /// The registry entry for a numeric type code, or `None` if unknown to this build.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        // Exhaustive match keeps the registry and this decoder in lock-step.
        Some(match code {
            0x00 => Self::Hello,
            0x01 => Self::HelloAck,
            0x02 => Self::Ping,
            0x03 => Self::Pong,
            0x05 => Self::Error,
            0x06 => Self::ObservedAddr,
            0x07 => Self::ConnectReq,
            0x08 => Self::PunchTo,
            0x09 => Self::Relay,
            0x11 => Self::Announce,
            0x12 => Self::BeaconReq,
            0x13 => Self::Beacon,
            0x14 => Self::DkgDeal,
            0x15 => Self::DkgJustify,
            0x16 => Self::DkgCommit,
            0x17 => Self::DkgComplaint,
            0x1D => Self::DkgCommitReq,
            0x0A => Self::RelayAttested,
            0x18 => Self::BeaconPartial,
            0x19 => Self::EpochAgree,
            0x1A => Self::BeaconReshareTrigger,
            0x1B => Self::BeaconReshareCommit,
            0x1C => Self::BeaconReshareShare,
            0x20 => Self::Lookup,
            0x21 => Self::Value,
            0x22 => Self::Publish,
            0x23 => Self::Ack,
            0x30 => Self::Route,
            0x34 => Self::RouteHier,
            0x40 => Self::Tessera,
            0x50 => Self::RdvIntro,
            0x51 => Self::RdvReply,
            0x53 => Self::RdvRegister,
            0x54 => Self::SvcShareReq,
            0x55 => Self::SvcPartial,
            0x56 => Self::PorosRequest,
            0x57 => Self::PorosShareReq,
            0x58 => Self::PorosShare,
            0x59 => Self::PorosResponse,
            0x5A => Self::PorosReshare,
            0x60 => Self::DiagGossip,
            0x63 => Self::DiagAttest,
            0x64 => Self::DiagLoss,
            0x65 => Self::CellEscalate,
            0x70 => Self::App,
            _ => return None,
        })
    }

    /// The numeric type code.
    #[must_use]
    pub const fn code(self) -> u64 {
        self as u64
    }

    /// How many codes in the **membership-critical group** this build cannot name — the size of the only
    /// vocabulary an unsupported-critical report can draw from.
    ///
    /// **Derived, because the hand-count went stale the moment a variant was added.** The consumer
    /// (`fanos_runtime::overlay`'s `skew_reported`) bounded itself with the sentence *"this build names
    /// `0x11`–`0x1C`, leaving exactly four codes"*, written when that range was the truth. `DkgCommitReq =
    /// 0x1D` joined the registry afterwards and no one re-counted, so the bound claimed a fourth code that
    /// no longer exists and a test picked `0x1D` as its example of an *unknown* code — an assertion about
    /// this build's ignorance that the build had stopped satisfying.
    ///
    /// The list is compile-time-complete ([`ALL`](Self::ALL) is length-checked against the variant count),
    /// so this counts rather than guesses and cannot go stale again.
    pub const UNKNOWN_CRITICAL_CODES: usize = {
        let (mut count, mut code) = (0usize, 0x10u64);
        while code <= 0x1F {
            // Through the registry's **own** resolver rather than a second sweep of `ALL`. A parallel scan
            // would be a second answer to "does this build name that code", and two answers to one question
            // is how the hand-count this replaces went stale in the first place.
            if Self::from_code(code).is_none() {
                count += 1;
            }
            code += 1;
        }
        count
    };

    /// Every frame type, for a reader that **enumerates rather than guesses** — the resolver that turns a
    /// station's tag into a name, a dashboard, a conformance sweep over the registry.
    ///
    /// Completeness is a compile-time fact, not a test: the assertion below compares this list's length to
    /// the variant count, so adding a type without listing it here fails the build. A test could only visit
    /// the variants the list already holds, which is exactly the one it would need to notice.
    pub const ALL: [Self; 45] = [
        Self::Hello,
        Self::HelloAck,
        Self::Ping,
        Self::Pong,
        Self::Error,
        Self::ObservedAddr,
        Self::ConnectReq,
        Self::PunchTo,
        Self::Relay,
        Self::Announce,
        Self::BeaconReq,
        Self::Beacon,
        Self::DkgDeal,
        Self::DkgJustify,
        Self::DkgCommit,
        Self::DkgComplaint,
        Self::DkgCommitReq,
        Self::RelayAttested,
        Self::BeaconPartial,
        Self::EpochAgree,
        Self::BeaconReshareTrigger,
        Self::BeaconReshareCommit,
        Self::BeaconReshareShare,
        Self::Lookup,
        Self::Value,
        Self::Publish,
        Self::Ack,
        Self::Route,
        Self::RouteHier,
        Self::Tessera,
        Self::RdvIntro,
        Self::RdvReply,
        Self::RdvRegister,
        Self::SvcShareReq,
        Self::SvcPartial,
        Self::PorosRequest,
        Self::PorosShareReq,
        Self::PorosShare,
        Self::PorosResponse,
        Self::PorosReshare,
        Self::DiagGossip,
        Self::DiagAttest,
        Self::DiagLoss,
        Self::CellEscalate,
        Self::App,
    ];

    /// The registry name, in the snake_case every other resolved vocabulary in this tree uses.
    ///
    /// **Why the wire registry needed one (#268).** `Observation::tag` reserves its field for frame stations
    /// to carry a wire type code, and `Station::tag_kind` will only call a tag a *vocabulary* if something
    /// can resolve it. Without `ALL` + `name()` there was nothing to resolve against, so every frame station
    /// had to declare its tag a bare `Quantity` and print `#17` at an operator — or, as
    /// `RestrictedFrameDropped` did until #267 needed it, throw the code away entirely.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::HelloAck => "hello_ack",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Error => "error",
            Self::ObservedAddr => "observed_addr",
            Self::ConnectReq => "connect_req",
            Self::PunchTo => "punch_to",
            Self::Relay => "relay",
            Self::Announce => "announce",
            Self::BeaconReq => "beacon_req",
            Self::Beacon => "beacon",
            Self::DkgDeal => "dkg_deal",
            Self::DkgJustify => "dkg_justify",
            Self::DkgCommit => "dkg_commit",
            Self::DkgComplaint => "dkg_complaint",
            Self::DkgCommitReq => "dkg_commit_req",
            Self::RelayAttested => "relay_attested",
            Self::BeaconPartial => "beacon_partial",
            Self::EpochAgree => "epoch_agree",
            Self::BeaconReshareTrigger => "beacon_reshare_trigger",
            Self::BeaconReshareCommit => "beacon_reshare_commit",
            Self::BeaconReshareShare => "beacon_reshare_share",
            Self::Lookup => "lookup",
            Self::Value => "value",
            Self::Publish => "publish",
            Self::Ack => "ack",
            Self::Route => "route",
            Self::RouteHier => "route_hier",
            Self::Tessera => "tessera",
            Self::RdvIntro => "rdv_intro",
            Self::RdvReply => "rdv_reply",
            Self::RdvRegister => "rdv_register",
            Self::SvcShareReq => "svc_share_req",
            Self::SvcPartial => "svc_partial",
            Self::PorosRequest => "poros_request",
            Self::PorosShareReq => "poros_share_req",
            Self::PorosShare => "poros_share",
            Self::PorosResponse => "poros_response",
            Self::PorosReshare => "poros_reshare",
            Self::DiagGossip => "diag_gossip",
            Self::DiagAttest => "diag_attest",
            Self::DiagLoss => "diag_loss",
            Self::CellEscalate => "cell_escalate",
            Self::App => "app",
        }
    }
}

/// **`ALL` is complete, proven by the compiler.** A registry entry missing from the list is invisible to
/// every reader that enumerates — the tag resolver, a dashboard, a conformance sweep — and invisible
/// *exactly* where a new frame type was just added. `variant_count` answers that at compile time; a test
/// could not, because it can only visit what the list already contains.
const _: () = assert!(
    FrameType::ALL.len() == core::mem::variant_count::<FrameType>(),
    "a FrameType variant is missing from FrameType::ALL, so every reader that enumerates is blind to it"
);

/// The **inner-session** frame registry — the frame types carried *inside* one AEAD-encrypted DIAULOS
/// cell (spec §L2), a deliberately distinct layer from the outer overlay-transport [`FrameType`]. Like
/// QUIC frames inside a packet, these reuse the small `0x0*` range with no collision because they live
/// **behind the cell's encryption**, never on the cleartext wire. Keeping both registries in this one
/// crate makes `fanos-wire` the single frame-code numbering authority (audit A1): `fanos_diaulos::frame`
/// derives its `ftype` bytes from this enum rather than from private constants.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum SessionFrameType {
    /// A pure cover cell — no payload (byte-indistinguishable from [`Data`](Self::Data) once sealed).
    Padding = 0x00,
    /// A reliability segment (stream data).
    Data = 0x01,
    /// A selective acknowledgement with receive credit.
    Ack = 0x02,
    /// Abort a stream in both directions, reclaiming its slot immediately.
    Reset = 0x03,
}

impl SessionFrameType {
    /// The numeric `ftype` byte this frame is tagged with inside the cell.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }

    /// The registry entry for an inner-session `ftype` byte, or `None` if unknown to this build.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x00 => Self::Padding,
            0x01 => Self::Data,
            0x02 => Self::Ack,
            0x03 => Self::Reset,
            _ => return None,
        })
    }
}

/// A decoded frame: its numeric type code (which may be unknown to this build) and its body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Frame<'a> {
    /// The numeric type code; resolve with [`FrameType::from_code`].
    pub type_code: u64,
    /// The frame body.
    pub body: &'a [u8],
}

impl Frame<'_> {
    /// The registry entry for this frame's type, if known.
    #[must_use]
    pub fn frame_type(&self) -> Option<FrameType> {
        FrameType::from_code(self.type_code)
    }
}

/// Encode a frame `type:varint ‖ length:varint ‖ body`.
pub fn encode_frame(type_code: u64, body: &[u8], out: &mut Vec<u8>) {
    varint::encode(type_code, out);
    varint::encode(body.len() as u64, out);
    out.extend_from_slice(body);
}

/// Decode one frame from the front of `buf`, returning the frame and bytes consumed. Unknown
/// type codes are returned intact so a caller can skip them by `length` (spec §7.2).
pub fn decode_frame(buf: &[u8]) -> Result<(Frame<'_>, usize), WireError> {
    let (type_code, n0) = varint::decode(buf)?;
    let rest = buf.get(n0..).ok_or(WireError::UnexpectedEnd)?;
    let (len, n1) = varint::decode(rest)?;
    // Convert through `usize::try_from` (not `as usize`): on a 32-bit target (wasm32 is a declared
    // build target) a 64-bit length would silently truncate, so a 64-bit and a 32-bit node would
    // disagree on the same bytes — a canonical-encoding violation. Reject instead.
    let len = usize::try_from(len).map_err(|_| WireError::FrameLengthOverflow)?;
    let body_start = n0 + n1;
    let end = body_start
        .checked_add(len)
        .ok_or(WireError::FrameLengthOverflow)?;
    let body = buf
        .get(body_start..end)
        .ok_or(WireError::FrameLengthOverflow)?;
    Ok((Frame { type_code, body }, end))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// **The criticality rule was asserted in three places and implemented in none.**
    ///
    /// The spec (§7.2), this module's header and `activation.rs` all say unknown types are skipped while
    /// unknown *critical* types abort — and none of them said which are critical, nothing computed it, and
    /// `WireError::UnknownCriticalFrame` existed with no site able to construct it. Every unknown frame was
    /// therefore treated as skippable, including a future beacon round.
    ///
    /// Two halves, and the second is what stops the rule from being vacuous in the other direction: the
    /// membership group must be critical, and **every other group must not be**. A predicate that called
    /// everything critical would abort on an `APP` type from a newer application overlay, which is exactly
    /// the forward compatibility `0x7*` exists to provide.
    #[test]
    fn only_the_membership_group_makes_an_unknown_type_fatal() {
        // Codes this build does not name, one per group, chosen high in each range so no future allocation
        // is presumed: the predicate reads the group, never the type.
        for code in [0x0Fu64, 0x2F, 0x3F, 0x4F, 0x5F, 0x6F, 0x7F] {
            assert!(
                !FrameType::group_is_critical(code),
                "{code:#04x}: skipping this costs availability, not agreement — aborting would break the \
                 forward compatibility the length prefix exists to give"
            );
        }
        for code in [0x10u64, 0x1F] {
            assert!(
                FrameType::group_is_critical(code),
                "{code:#04x}: membership fixes the epoch every coordinate and roster derives from, so a node \
                 that skips it keeps serving on a retired one, indistinguishable from a healthy node"
            );
        }
        // And the rule is about the GROUP, not about whether this build happens to know the code: every
        // membership type it *does* know is critical too, so a future sibling inherits the same answer.
        for known in [FrameType::Beacon, FrameType::BeaconReshareCommit, FrameType::Announce] {
            assert!(FrameType::group_is_critical(known.code()), "{known:?}");
        }
    }

    #[test]
    fn groups_match_high_nibble() {
        assert_eq!(FrameType::Hello.group(), 0x0);
        assert_eq!(FrameType::Announce.group(), 0x1);
        assert_eq!(FrameType::Tessera.group(), 0x4);
        assert_eq!(FrameType::DiagGossip.group(), 0x6);
    }

    #[test]
    fn registry_round_trips() {
        for code in [0x00u64, 0x05, 0x13, 0x1A, 0x1B, 0x1C, 0x40, 0x63] {
            let ft = FrameType::from_code(code).unwrap();
            assert_eq!(ft.code(), code);
        }
        assert_eq!(FrameType::from_code(0xFF), None);
    }

    #[test]
    fn an_absurd_length_is_rejected_not_wrapped() {
        // A length that overflows the address space (or a 32-bit `usize`) must be rejected, never
        // truncated or wrapped into a valid-looking slice (canonical-encoding safety on wasm32).
        let mut buf = Vec::new();
        varint::encode(FrameType::Publish.code(), &mut buf);
        varint::encode(1u64 << 40, &mut buf); // ~1 TB body length — exceeds a 32-bit usize
        buf.extend_from_slice(b"short");
        assert!(matches!(
            decode_frame(&buf),
            Err(WireError::FrameLengthOverflow)
        ));
    }

    #[test]
    fn frame_round_trips() {
        let mut buf = Vec::new();
        encode_frame(FrameType::Publish.code(), b"payload", &mut buf);
        let (frame, n) = decode_frame(&buf).unwrap();
        assert_eq!(frame.frame_type(), Some(FrameType::Publish));
        assert_eq!(frame.body, b"payload");
        assert_eq!(n, buf.len());
    }

    #[test]
    fn unknown_type_is_skippable_not_fatal() {
        // A frame of unknown type still decodes with its body, so a router can skip it.
        let mut buf = Vec::new();
        encode_frame(0xAB, b"future", &mut buf);
        let (frame, n) = decode_frame(&buf).unwrap();
        assert_eq!(frame.frame_type(), None);
        assert_eq!(frame.type_code, 0xAB);
        assert_eq!(frame.body, b"future");
        assert_eq!(n, buf.len());
    }

    #[test]
    fn rejects_body_length_overflow() {
        // type=0x02, length=100, but no body.
        let mut buf = Vec::new();
        varint::encode(0x02, &mut buf);
        varint::encode(100, &mut buf);
        assert_eq!(decode_frame(&buf), Err(WireError::FrameLengthOverflow));
    }
}
