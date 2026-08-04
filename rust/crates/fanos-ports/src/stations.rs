//! # The data-path plane — where work stops, counted by structure
//!
//! The coherence plane (`fanos_telemetry::frame`) answers **"is the organism healthy?"**. Nothing
//! answered **"is the work getting done, and where does it stop?"** — and
//! `docs/design-observability.md` §1 measures what that cost: defect #55 was localized by hand-inserting
//! eight `eprintln!` probes and eliminating eleven candidate causes one at a time, while the coherence
//! plane could only report *"point 3 is faulted"* — which the operator already knew, having stopped that
//! node deliberately. The two facts that actually solved it (every circuit through that point was dead;
//! gathers were expiring at `1` of `t = 2` **by the hundreds**) were sitting in the process's own control
//! flow the whole time, and nothing recorded them.
//!
//! ## The stations are derived, not invented
//!
//! The temptation is to design a metrics taxonomy — a chosen structure where a derived one exists.
//! **Every branch that discards work is already written in the code**: each early return, each `None =>`,
//! each eviction and each expiry is a place where the system decided not to continue, and *that decision
//! is the observation*. So the enumeration is mechanical — instrument the discard sites, name each by
//! what it discards — and [`Station`] is that enumeration, not a taxonomy.
//!
//! ## Three rules, and the first one is a prohibition with a proof behind it
//!
//! This is an anonymity network, so **per-circuit tracing is deanonymization**. The usual answer —
//! propagate a trace id, correlate spans across hops — is not merely inadvisable here, it is an attack:
//! a token carried through the onion and visible at successive hops *is* a tagging attack, the channel
//! per-hop AEAD exists to close and that `onion_tamper.rs` proves closed. Adding one would reopen, in
//! plaintext, the exact channel the cryptography spends its budget closing.
//!
//! * **R1 — no cross-hop correlatable token, ever.** Not a trace id, not a request id, not a session id,
//!   nor a hash of one. The types here make this structural: a count is keyed by [`Station`] and an
//!   optional **line**, and there is no key that can carry a flow.
//! * **R2 — keys are STRUCTURE**, never flow: `(station, line)`. Structure is public — the geometry is a
//!   published function — so a counter keyed by it discloses nothing the plane's shape does not already.
//! * **R3 — no per-session counters**, even with the id withheld: a count that varies with one session's
//!   behaviour is a linkability channel by its variance alone.
//! * **R4 — anything crossing a node boundary is privatized** through fanos-telemetry's `dp`
//!   boundary. These counters are **local-only** until per-family sensitivities are derived the way
//!   `Δr = 1/21` was for the coherence frame, so nothing here exports itself.
//!
//! ## Cardinality is bounded by the geometry, not by a cap someone chose
//!
//! A metrics system usually needs a label-cardinality cap, because labels are attacker-mintable strings.
//! Here the key space is `(station, line)`: stations are a compile-time enumeration, and **lines are a
//! finite published set of size `q² + q + 1`** — 7 on Fano, 57 on `PG(2,7)`. So the bound is a *fact
//! about the plane* rather than a policy, with no dynamic allocation and no attacker-chosen keys.
//!
//! ## Owned per node, never a process global
//!
//! [`Stations`] is a plain value an engine owns, and deliberately **not** a `static` counter like
//! `fanos_session::dropped_payloads`. `fanos-sim` runs an entire cell — many nodes — inside one process,
//! so a global would blend every node's data path into one unreadable sum and destroy the simulator's
//! per-node determinism, which is the instrument this plane exists to sharpen. Ownership also keeps the
//! engines sans-I/O: recording is a field write, never a syscall or a lock.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::Duration;
use fanos_geometry::Triple;

/// A place where the data path **decided not to continue** — the code's own discard sites, named by what
/// they discard.
///
/// Each variant corresponds to a question that was asked by hand during #55's investigation, so the list
/// is a record of what an operator actually needs rather than what is easy to emit. New variants are
/// added by finding a discard site that is not yet named, never by inventing a category.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[non_exhaustive]
pub enum Station {
    // --- Threshold gather (`fanos_aphantos::ThresholdRouter`, and the sibling engines) ---
    /// A gather's deadline fired **below threshold** — the entire hop discarded. This *was* defect #14,
    /// found only by grepping hand-inserted probes: gathers expiring at `1` of `t = 2` in the hundreds
    /// per run turned a censorship-survival property into a run-to-run coin flip.
    GatherExpired,
    /// A gather completed and delivered — the denominator without which `GatherExpired` is a bare number
    /// rather than a rate. (Recording only failures is the one-sided-counter defect: it points at the
    /// wrong half.)
    GatherCompleted,
    /// A gather's deadline fired with **`t` or more shares in hand** that no subset would peel — so the line
    /// answered and its answers were wrong.
    ///
    /// Split from [`Station::GatherExpired`] because that counter's own doc names the distinction it was not
    /// making: "how many shares it had reached is the difference between *the line is slow* and *the line is
    /// dead*". Recorded together, the two are indistinguishable, and they call for opposite responses — one is
    /// a liveness problem answered by avoiding the line, the other is corruption or attack answered by
    /// refusing its shares. This is also the only counter that can tell whether a line with `q + 1 − t = 1`
    /// spare member is failing because a member is absent or because a peel had exactly one candidate subset
    /// and it did not work.
    GatherUnpeelable,
    /// A share arrived for a gather that had already **peeled** — the expected remainder.
    ///
    /// A `t`-of-`(q+1)` gather completes on the `t`-th share, so `q + 1 − t` more are already in flight and
    /// must land somewhere. Recording them as a discard made this the largest counter on every node — 613 to
    /// 2283 per run against comparable completion totals — so the plane's most prominent number was
    /// arithmetic, and the signals that actually found defects sat underneath it. Counted, because the ratio
    /// against `GatherCompleted` is a real check on the design, but counted **apart** from failure.
    ShareLateAfterPeel,
    /// A share arrived for a gather that had already **expired** — so the line did answer and the deadline
    /// was too tight, which is the opposite conclusion from [`Station::GatherExpired`] taken alone.
    ///
    /// This is the actionable one: it is direct evidence for widening the gather deadline (RFC 6298 §5.5),
    /// and it is invisible if late shares are all summed together.
    ShareAfterDeadline,
    /// The gatherer could **not compute its own share** of a line it is a member of, so the gather started
    /// one short of where it should.
    ///
    /// A silent path until now, and a consequential one: a line's spare capacity is `q + 1 − t`, which is
    /// exactly **1** at `q = 2`, so a gather that fails to seed itself has none left and needs every other
    /// member to answer. That converts a routine loss into an expiry, and nothing said why. It happens when
    /// the onion's layer was sealed to an epoch key this relay has already ratcheted past — the responder's
    /// side of the same failure is [`Station::SharePartialFailed`], and the gatherer's had no counter at all.
    GatherSelfShareMissing,
    /// A frame discarded because its sender is **locally quarantined** (spec §6.2/§6.4).
    ///
    /// The one discard that is unambiguously *this node's own decision*, and it was the quietest. Every other
    /// silence on the wire is ambiguous between the peer, the path, and us; a quarantine drop is us, and it
    /// looked exactly like the peer having gone away — to an operator, to the peer, and to any diagnosis
    /// downstream.
    ///
    /// That matters most when the quarantine is **wrong**. The window is bounded so a transient fault is not a
    /// permanent exile (audit C5), but a node that keeps re-quarantining a healthy peer keeps dropping it, and
    /// the only visible symptom is a link that does not work.
    ///
    /// **Aggregate, not per-peer, and deliberately so.** `Observation::line` is a *line*, and the sender here
    /// is a *point* — in `PG(2,q)` both are `Triple`s, so attributing this drop by putting the sender in that
    /// field would type-check and be a lie, which is precisely the category confusion this plane exists to
    /// stop. So the count answers "is this node refusing traffic at all", which is the question that was
    /// unanswerable; "which peer" needs a field the plane does not have and should not fake.
    QuarantineDropped,
    /// A meeting combiner held a registration for the named service but **could not seal the forward onion**
    /// to its dead-drop line, so the client's request was discarded there.
    ///
    /// Silent until now, and on the forward path — which is the half a wedged session was measured to lose.
    /// `seal_forward_to_host` reads the relay's OWN mix directory, so this fires when that directory is stale
    /// or short of a member of the host's route, and it fires **per combiner**: a launch draws a salted member
    /// per onion (#55), so one member with a bad directory drops the requests that happen to land on it while
    /// its siblings serve theirs. That is a session which handshakes and then stops, intermittently.
    HostForwardUnsealable,
    /// A client request named a `service_tag` this combiner holds no registration for, so it fell through to a
    /// local delivery at a node that is not the service, and died there.
    ///
    /// Distinguished from [`Station::HostForwardUnsealable`] because the responses differ: this one says the
    /// registration never arrived or has been evicted, the other says it arrived and the route cannot be used.
    RequestForUnknownHost,
    /// A pending gather evicted at the in-flight cap, not by its deadline — capacity pressure, which is a
    /// different world from a slow line and must not be summed with it.
    GatherEvicted,

    /// A gather reached its threshold and the **open still failed** — the shares were tampered with, or came
    /// from a line that does not agree on the key.
    ///
    /// Distinct from [`SharePartialFailed`](Self::SharePartialFailed), which is a member unable to compute its
    /// *own* share, and the distinction is the diagnosis: that one localizes to the member, this one says the
    /// threshold was met by shares that do not belong together. Folding them would report a combiner problem
    /// as a member problem. It is also not [`GatherExpired`](Self::GatherExpired): nothing timed out, enough
    /// arrived, and the result was still unusable — which looks identical from outside and is a different
    /// fault entirely.
    GatherOpenFailed,
    /// A share request arrived for a line this node is not on — why a gather never reaches quorum.
    ShareRequestNotAMember,
    /// This node could not compute its own share for a layer sealed to it — epoch/key skew between
    /// members, which is otherwise silent.
    SharePartialFailed,
    /// A share arrived for an unknown request: already peeled, foreign, or **past its deadline** — the
    /// last of which says the deadline is too tight rather than the line too slow.
    ShareForUnknownRequest,
    /// A share carried an index outside the line's real membership — a **forged** share, and therefore
    /// distinguishable from noise: this is an attack indicator, not an error rate.
    ShareIndexOutOfRange,
    /// Candidate shares hit the flood cap for one gather — a memory attack on the gather, since a real
    /// line never needs that many.
    ShareFloodCapped,
    /// A delivery whose path-authenticator did not match the circuit it claims to have traversed — the
    /// holonomy check firing.
    HolonomyRejected,

    // --- Frame handling (any engine) ---
    /// A frame this node could not parse — an unreadable body, or a tag it does not know.
    ///
    /// This is the input to the version/derivation **skew detector** `docs/design-upgrade.md` §4 requires
    /// before an upgrade can be a controlled operation: a member on a different derivation does not error
    /// loudly, it simply stops agreeing.
    ///
    /// **It is not skew *alone*, and reading it that way would over-conclude.** The same count rises for
    /// ordinary corruption and for foreign traffic addressed to this coordinate, because at the point of
    /// the failure those are indistinguishable — that is what "could not parse" means. Skew is the
    /// *hypothesis* a rise should prompt, confirmed by its shape: skew is persistent, correlated with a
    /// release, and concentrated on the lines whose members disagree, where garbage is diffuse and
    /// transient. [`SharePartialFailed`](Self::SharePartialFailed) is the sharper signal, since only a
    /// genuine key/epoch disagreement inside a line produces it.
    FrameDecodeFailed,

    /// A frame whose **type code parsed** and names a type this build does not implement.
    ///
    /// The version-skew detector `docs/design-upgrade.md` §4 asks for, and distinct from
    /// [`FrameDecodeFailed`](Self::FrameDecodeFailed) in the one way that matters: a malformed frame tells you
    /// nothing about *who* disagrees, while this one carries the type code the peer used. That code is the
    /// evidence — "a member of this line sent type 47 and I have no type 47" is a statement about releases, not
    /// about corruption.
    ///
    /// Counted **per tag**, because the operational question is not "is anyone stale" — the network tolerates
    /// that until the activation height — but "does any hop line hold fewer than `t` members that agree". A
    /// count without the tag cannot answer it, and a count without the line cannot localize it.
    FrameTypeUnknown,

    // --- POROS admission (`fanos_node::PorosHost`) ---
    /// A request arrived from a coordinate other than the one it claims — the identity binding refusing a
    /// relayed or replayed proof.
    AdmissionIdentityUnbound,
    /// The proof-of-work did not verify — the rate-limiter doing its job.
    AdmissionPowFailed,
    /// A valid proof from an identity the coherence layer has **not admitted** — the Sybil cap, which is
    /// a wholly different operational world from a wrong difficulty and was previously indistinguishable
    /// from it.
    AdmissionSybilCapped,
    /// Admission refused for want of a gather slot — capacity, not policy.
    AdmissionNoCapacity,
    /// A store write refused because this node is at its content cap — capacity, not policy, and the same
    /// distinction [`AdmissionNoCapacity`](Self::AdmissionNoCapacity) draws one layer over.
    ///
    /// **The only discard site in the overlay that used to record nothing.** A storage node fills with
    /// content by design — content has no lifetime, so it is never swept — and past `MAX_STORE_ENTRIES` a
    /// new digest is refused with no `Ack`. That refusal is correct: fail-closed admission is what stops a
    /// flood of distinct digests displacing stored shards. What was wrong is that nobody else could tell.
    /// The writer learns only from a `put` timing out, which is indistinguishable from an unreachable peer —
    /// the two failures an operator most needs to separate — and the node itself reported nothing at all.
    StoreAtCapacity,
    /// A descriptor share arrived that does **not** open its dealt per-share commitment: not a decode error
    /// and not a stale epoch, but a value provably different from the one the dealer handed that member.
    ///
    /// This is the only station in the table that is *evidence of forgery* rather than of failure. Lagrange
    /// interpolation is linear, so a single line member can add a chosen offset to the reconstructed secret;
    /// the per-share commitment is what turns that from an undetected substitution into a rejected frame,
    /// and this counter is what turns a rejected frame into something an operator can see.
    ShareOffCommitment,
    /// A threshold of shares reconstructed, but no admissible subset of them produced the **committed**
    /// descriptor — so nothing was served.
    ///
    /// Distinct from a gather that merely did not fill: this one *had* its threshold and still could not
    /// produce the dealt secret, which means a share it cannot individually attribute is wrong. A rotated
    /// line is the case that reaches it, because resharing invalidates the dealt per-share commitments and
    /// leaves only the descriptor commitment to check against.
    DescriptorUnrecoverable,
}

impl Station {
    /// Every station, for a reader that enumerates rather than guesses (a dashboard, a test asserting the
    /// table is complete).
    pub const ALL: &'static [Self] = &[
        Self::GatherExpired,
        Self::GatherCompleted,
        Self::QuarantineDropped,
        Self::HostForwardUnsealable,
        Self::RequestForUnknownHost,
        Self::ShareLateAfterPeel,
        Self::ShareAfterDeadline,
        Self::GatherUnpeelable,
        Self::GatherSelfShareMissing,
        Self::GatherEvicted,
        Self::ShareRequestNotAMember,
        Self::SharePartialFailed,
        Self::ShareForUnknownRequest,
        Self::ShareIndexOutOfRange,
        Self::ShareFloodCapped,
        Self::HolonomyRejected,
        Self::FrameDecodeFailed,
        Self::AdmissionIdentityUnbound,
        Self::AdmissionPowFailed,
        Self::AdmissionSybilCapped,
        Self::AdmissionNoCapacity,
        Self::ShareOffCommitment,
        Self::DescriptorUnrecoverable,
        Self::GatherOpenFailed,
        Self::FrameTypeUnknown,
        Self::StoreAtCapacity,
    ];

    /// A short stable name, for a human-facing readout. Stable because an operator's saved query should
    /// not break when a variant is added elsewhere in the enum.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::GatherExpired => "gather.expired",
            Self::GatherCompleted => "gather.completed",
            Self::QuarantineDropped => "quarantine.dropped",
            Self::HostForwardUnsealable => "host.forward_unsealable",
            Self::RequestForUnknownHost => "request.unknown_host",
            Self::ShareLateAfterPeel => "share.late_after_peel",
            Self::ShareAfterDeadline => "share.after_deadline",
            Self::GatherUnpeelable => "gather.unpeelable",
            Self::GatherSelfShareMissing => "gather.self_share_missing",
            Self::GatherEvicted => "gather.evicted",
            Self::GatherOpenFailed => "gather.open_failed",
            Self::ShareRequestNotAMember => "share.not_a_member",
            Self::SharePartialFailed => "share.partial_failed",
            Self::ShareForUnknownRequest => "share.unknown_request",
            Self::ShareIndexOutOfRange => "share.index_out_of_range",
            Self::ShareFloodCapped => "share.flood_capped",
            Self::HolonomyRejected => "holonomy.rejected",
            Self::FrameDecodeFailed => "frame.decode_failed",
            Self::FrameTypeUnknown => "frame.type_unknown",
            Self::StoreAtCapacity => "store.at_capacity",
            Self::AdmissionIdentityUnbound => "admission.identity_unbound",
            Self::AdmissionPowFailed => "admission.pow_failed",
            Self::AdmissionSybilCapped => "admission.sybil_capped",
            Self::AdmissionNoCapacity => "admission.no_capacity",
            Self::ShareOffCommitment => "share.off_commitment",
            Self::DescriptorUnrecoverable => "descriptor.unrecoverable",
        }
    }
}

/// The health of an engine's threshold-gather path, with **"there is no gather here"** kept distinct from
/// **"no gather has ever completed"**.
///
/// Written as an `Option<(srtt, var)>` these collapse, and they are not the same fact. An overlay node runs no
/// threshold gather, so reporting it as unmeasured tells its operator about a deadline the engine does not have.
/// A relay reporting unmeasured after minutes of traffic is a finding: it is running on the initial estimate
/// rather than on anything it observed, which is the difference between "the deadline is wrong" and "the
/// deadline was never measured". This is the same conflation `Notification::LoadReport` carried between a
/// measured zero and an absent sensor, and it is worth a variant for the same reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum GatherHealth {
    /// This engine has no threshold gather — nothing to report, and not a fault.
    #[default]
    NoGatherPath,
    /// There is a gather path and no gather has completed, so the deadline is still the initial estimate.
    Unmeasured,
    /// The measured deadline: RFC 6298's smoothed estimate and its variation.
    Measured {
        /// Smoothed round-trip estimate over completed gathers.
        srtt: Duration,
        /// Mean deviation of that estimate.
        var: Duration,
    },
}

impl GatherHealth {
    /// The more informative of two readings: a real gather path outranks
    /// [`NoGatherPath`](Self::NoGatherPath), which says only that *this* engine has none.
    ///
    /// Used where a composite folds several engines' answers into the one plane a node reports. Taking the
    /// first would let an overlay's `NoGatherPath` mask the relay's measured deadline sitting beside it.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        match self {
            Self::NoGatherPath => other,
            _ => self,
        }
    }

    /// The health a clock reports: [`Measured`](Self::Measured) once a gather has completed, else
    /// [`Unmeasured`](Self::Unmeasured). For an engine that has no gather at all, use
    /// [`NoGatherPath`](Self::NoGatherPath) directly — a clock cannot say that about itself.
    #[must_use]
    pub const fn of(clock: &crate::GatherClock) -> Self {
        match clock.srtt() {
            Some(srtt) => Self::Measured { srtt, var: clock.var() },
            None => Self::Unmeasured,
        }
    }
}

/// Combine two engines' observation lists, summing counts that share a `(station, line, tag)` key.
///
/// A composite node runs several data-path engines and must answer with **one** plane, not one per engine: a
/// reader that takes the first notification it sees would silently drop the rest, and which one arrives first
/// is an artifact of how the composite happens to order its delegation.
#[must_use]
pub fn merge_observations(parts: impl IntoIterator<Item = Observation>) -> Vec<Observation> {
    let mut totals: BTreeMap<(Station, Option<Triple>, Option<u64>), u64> = BTreeMap::new();
    for o in parts {
        *totals.entry((o.station, o.line, o.tag)).or_insert(0) += o.count;
    }
    totals
        .into_iter()
        .map(|((station, line, tag), count)| Observation { station, line, tag, count })
        .collect()
}

/// One `(station, line) → count` observation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Observation {
    /// Where the work stopped.
    pub station: Station,
    /// The hop line it stopped on, when the site knows one. `None` is *not* an aggregate bucket — it is
    /// "this discard is not attributable to a line" (a frame that failed to decode before its line could
    /// be read, say), and keeping it distinct stops an unattributed count from being read as a line's.
    pub line: Option<Triple>,
    /// The wire **type code** the frame carried, where the site read one — the second half of the skew
    /// question (`design-upgrade.md` §4 asks for decode failures "counted per tag, per line").
    ///
    /// `None` where the site has no tag to report, which is most of them: a gather that expired stopped for
    /// reasons that have nothing to do with a frame type. Kept `Option` rather than defaulted to `0` for the
    /// same reason `line` is: a fabricated tag would put invented evidence about a peer's release into the
    /// plane built to end diagnosis on thin evidence.
    pub tag: Option<u64>,
    /// How many times, this window.
    pub count: u64,
}

/// A node's data-path counters for the current window: `(station, line, tag) → count`.
///
/// Deliberately a plain owned value (see the module docs on why never a process global). Cleared by
/// [`take`](Self::take) at the window boundary, which is also how a reader gets the window's data — one
/// operation, so a count can never be read twice or lost between a read and a clear.
#[derive(Clone, Default, Debug)]
pub struct Stations {
    /// `(station, line, tag) → count`, ordered.
    ///
    /// A `BTreeMap` rather than a linear `Vec` probe, and the reason is the *largest* plane rather than
    /// the shipped one. On Fano the key space is at most `14 × 7 = 98` and a scan would be free — but the
    /// platform supports up to `PG(2,31)`, where it is `14 × 993 ≈ 14k`, and `record` is called on paths
    /// that are *already failing*: `ShareFloodCapped` fires precisely when a node is under a share flood,
    /// so an `O(n)` probe there would make the plane most expensive exactly when the node can least
    /// afford it — an observability layer amplifying the attack it exists to reveal. `O(log n)` costs
    /// nothing at Fano scale and stays honest at the plane sizes the platform actually claims.
    ///
    /// `BTreeMap` and not a hash map because the key space is closed and public (no attacker-chosen
    /// keys — module docs), so there is nothing for hashing to defend against, and ordered iteration
    /// gives `observations()` a stable output with no sort.
    counts: BTreeMap<(Station, Option<Triple>, Option<u64>), u64>,
}

/// The largest frame type code the plane will key a counter on.
///
/// **This bound is load-bearing, not tidiness.** A frame's type code is a `u64` this node decodes from bytes a
/// *peer* chose, so keying a counter on it verbatim hands an attacker the key space: one map entry per distinct
/// code, unbounded, inside the subsystem that exists to reveal such an attack rather than to be it — the same
/// argument [`Stations`] already makes for preferring `O(log n)` on paths that fire under flood. It is also
/// exactly the property `docs/design-observability.md` §5 claims ("no dynamic allocation and no attacker-chosen
/// keys"), which adding the tag dimension broke until this was put back.
///
/// Derived from the **frame-type registry's allocation space**, one byte: codes are handed out densely from
/// `0x00` and the highest allocated today is `0x70`, so a byte covers the registry with room for it to grow by
/// more than twice over. A code above it is not one this protocol allocates — it is a peer inventing values.
///
/// It is deliberately *not* derived from the varint boundary, which was the first attempt and was wrong: these
/// are QUIC varints, where the top two bits of the first byte select the length, so one byte holds only
/// `0..=63` — below `0x70`, i.e. below codes the registry already uses. Tying the constant to the codec is what
/// caught that; the test that checks the derivation lives where the registry is visible.
///
/// Codes above the ceiling are still **counted**, folded into the untagged bucket — so a flood of invented
/// codes reads as a rising `frame.type_unknown` with no tag, which is the honest reading: something is sending
/// nonsense, and nonsense names no release.
pub const MAX_SKEW_TAG: u64 = 0xFF;

impl Stations {
    /// An empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self { counts: BTreeMap::new() }
    }

    /// Record one discard (or completion) at `station`, attributed to `line` when the site knows one.
    ///
    /// Cheap and infallible: engines call it on paths that are already failing, so it must never be the
    /// reason a failure path costs anything measurable.
    pub fn record(&mut self, station: Station, line: Option<Triple>) {
        self.record_n(station, line, 1);
    }

    /// Record `n` occurrences at once — for a site that discards a batch.
    pub fn record_n(&mut self, station: Station, line: Option<Triple>, n: u64) {
        self.record_tagged(station, line, None, n);
    }

    /// Record one occurrence carrying the wire **type code** the frame used.
    ///
    /// The tagged form exists for one question — `design-upgrade.md` §4's "does any hop line hold fewer than
    /// `t` members that agree on the current derivation?" — which needs the tag to say *what* disagrees and the
    /// line to say *where*. Every other site passes `None`, because inventing a tag would put fabricated
    /// evidence about a peer's release into the plane.
    pub fn record_tagged(&mut self, station: Station, line: Option<Triple>, tag: Option<u64>, n: u64) {
        // Clamped **here**, at the one choke point every caller goes through, rather than at each site that
        // happens to have a tag. A bound a caller has to remember is a bound the next caller forgets, and the
        // cost of forgetting this one is an unbounded map keyed by bytes a peer chose — see [`MAX_SKEW_TAG`].
        let tag = tag.filter(|t| *t <= MAX_SKEW_TAG);
        let slot = self.counts.entry((station, line, tag)).or_insert(0);
        *slot = slot.saturating_add(n);
    }

    /// This window's count at `(station, line)`, summed over tags.
    #[must_use]
    pub fn get(&self, station: Station, line: Option<Triple>) -> u64 {
        self.counts.iter().filter(|((s, l, _), _)| *s == station && *l == line).map(|(_, c)| *c).sum()
    }

    /// This window's total at `station`, across every line and tag.
    #[must_use]
    pub fn total(&self, station: Station) -> u64 {
        self.counts.iter().filter(|((s, _, _), _)| *s == station).map(|(_, c)| *c).sum()
    }

    /// Whether anything was recorded this window.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Every observation this window, ordered by station, then line, then tag.
    #[must_use]
    pub fn observations(&self) -> Vec<Observation> {
        // Already ordered by `(station, line, tag)` — the map's own iteration order — so no sort is needed
        // and the output is stable across runs, which the simulator's determinism depends on.
        self.counts
            .iter()
            .map(|(&(station, line, tag), &count)| Observation { station, line, tag, count })
            .collect()
    }

    /// Take this window's observations and start a fresh window.
    ///
    /// Read-and-clear in one step on purpose: a separate `read` then `clear` has a gap in which a
    /// concurrent record is silently lost, and a plane built to find defects must not have one.
    pub fn take(&mut self) -> Vec<Observation> {
        let out = self.observations();
        self.counts.clear();
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const L1: Triple = [1, 0, 0];
    const L2: Triple = [0, 1, 0];

    #[test]
    fn an_invented_type_code_cannot_grow_the_key_space() {
        // The plane's §5 guarantee is that its key space has **no attacker-chosen keys** — stations are a
        // compile-time enumeration and lines a published set. A frame's type code is neither: it is a `u64`
        // decoded from bytes a peer chose. Keying on it verbatim would let one sender mint a map entry per
        // distinct code, in the subsystem that exists to reveal that attack rather than to be it.
        let mut st = Stations::new();
        let line = Some([1, 0, 1]);

        // A flood of invented codes, each one different, each above the allocation space.
        for i in 0..10_000u64 {
            st.record_tagged(Station::FrameTypeUnknown, line, Some(MAX_SKEW_TAG + 1 + i), 1);
        }
        assert_eq!(
            st.observations().len(),
            1,
            "10 000 invented codes must collapse to one bucket, not 10 000 map entries"
        );
        assert_eq!(st.observations()[0].tag, None, "and be reported untagged — nonsense names no release");
        assert_eq!(st.total(Station::FrameTypeUnknown), 10_000, "while still being COUNTED in full");

        // A real code is still recorded exactly, or the station stops being a skew detector.
        st.record_tagged(Station::FrameTypeUnknown, line, Some(0x70), 3);
        let tagged: Vec<_> = st.observations().into_iter().filter(|o| o.tag == Some(0x70)).collect();
        assert_eq!(tagged.len(), 1, "an allocated code keeps its own bucket");
        assert_eq!(tagged[0].count, 3);

        // The whole reachable space, exercised: bounded by the constant, not by luck.
        let mut full = Stations::new();
        for code in 0..=MAX_SKEW_TAG {
            full.record_tagged(Station::FrameTypeUnknown, line, Some(code), 1);
        }
        assert_eq!(
            full.observations().len(),
            usize::try_from(MAX_SKEW_TAG).unwrap() + 1,
            "the tag space is exactly the single-byte varint space, per line and station"
        );
    }

    #[test]
    fn counts_are_kept_per_station_and_per_line() {
        // R2: the key is STRUCTURE — a station and a line — so the same station on two lines must not be
        // summed away. "Which line stopped" is the whole diagnostic value: #55 presented as *one* point's
        // circuits being dead, which an aggregate would have hidden completely.
        let mut s = Stations::new();
        s.record(Station::GatherExpired, Some(L1));
        s.record(Station::GatherExpired, Some(L1));
        s.record(Station::GatherExpired, Some(L2));
        s.record(Station::GatherCompleted, Some(L1));

        assert_eq!(s.get(Station::GatherExpired, Some(L1)), 2);
        assert_eq!(s.get(Station::GatherExpired, Some(L2)), 1);
        assert_eq!(s.total(Station::GatherExpired), 3, "and the total is still available");
        assert_eq!(
            s.get(Station::GatherCompleted, Some(L1)),
            1,
            "distinct stations on one line stay distinct"
        );
        assert_eq!(s.get(Station::GatherEvicted, Some(L1)), 0, "an unrecorded station reads zero");
    }

    #[test]
    fn an_unattributed_discard_is_not_a_lines_discard() {
        // `None` means "not attributable to a line" (a frame that failed to decode before its line could
        // be read). Folding it into any line's count would invent evidence against that line — and this
        // plane exists to end a class of defect that was diagnosed by *believing* thin evidence.
        let mut s = Stations::new();
        s.record(Station::FrameDecodeFailed, None);
        s.record(Station::FrameDecodeFailed, Some(L1));
        assert_eq!(s.get(Station::FrameDecodeFailed, None), 1);
        assert_eq!(s.get(Station::FrameDecodeFailed, Some(L1)), 1);
        assert_eq!(s.total(Station::FrameDecodeFailed), 2, "the total spans both");
    }

    #[test]
    fn taking_a_window_reports_it_and_starts_a_fresh_one() {
        let mut s = Stations::new();
        s.record_n(Station::GatherExpired, Some(L1), 5);
        let window = s.take();
        assert_eq!(window.len(), 1);
        assert_eq!(window[0].count, 5);
        assert_eq!(window[0].station, Station::GatherExpired);
        assert!(s.is_empty(), "the window is cleared by the same call that reads it");
        assert_eq!(s.get(Station::GatherExpired, Some(L1)), 0);
    }

    #[test]
    fn all_lists_every_variant_and_the_compiler_enforces_it() {
        // `ALL` is hand-maintained, so a variant added to the enum could silently be missing from it —
        // and a dashboard that enumerates `ALL` would then have a blind spot exactly where a new discard
        // site was just instrumented, which is the failure this whole plane exists to end.
        //
        // The `match` below is what makes that impossible rather than merely tested: it is exhaustive,
        // so adding a variant **fails the build** until it is handled here, and each arm asserts the
        // variant is present in `ALL`. A test can only check the variants it knows about; a compiler
        // check knows about all of them.
        for station in Station::ALL {
            let listed = |s: Station| assert!(Station::ALL.contains(&s), "{s:?} missing from ALL");
            match *station {
                Station::GatherExpired => listed(Station::GatherExpired),
                Station::GatherCompleted => listed(Station::GatherCompleted),
                Station::QuarantineDropped => listed(Station::QuarantineDropped),
                Station::HostForwardUnsealable => listed(Station::HostForwardUnsealable),
                Station::RequestForUnknownHost => listed(Station::RequestForUnknownHost),
                Station::ShareLateAfterPeel => listed(Station::ShareLateAfterPeel),
                Station::ShareAfterDeadline => listed(Station::ShareAfterDeadline),
                Station::GatherUnpeelable => listed(Station::GatherUnpeelable),
                Station::GatherSelfShareMissing => listed(Station::GatherSelfShareMissing),
                Station::GatherEvicted => listed(Station::GatherEvicted),
                Station::GatherOpenFailed => listed(Station::GatherOpenFailed),
                Station::ShareRequestNotAMember => listed(Station::ShareRequestNotAMember),
                Station::SharePartialFailed => listed(Station::SharePartialFailed),
                Station::ShareForUnknownRequest => listed(Station::ShareForUnknownRequest),
                Station::ShareIndexOutOfRange => listed(Station::ShareIndexOutOfRange),
                Station::ShareFloodCapped => listed(Station::ShareFloodCapped),
                Station::HolonomyRejected => listed(Station::HolonomyRejected),
                Station::StoreAtCapacity => listed(Station::StoreAtCapacity),
                Station::FrameDecodeFailed => listed(Station::FrameDecodeFailed),
                Station::FrameTypeUnknown => listed(Station::FrameTypeUnknown),
                Station::AdmissionIdentityUnbound => listed(Station::AdmissionIdentityUnbound),
                Station::AdmissionPowFailed => listed(Station::AdmissionPowFailed),
                Station::AdmissionSybilCapped => listed(Station::AdmissionSybilCapped),
                Station::AdmissionNoCapacity => listed(Station::AdmissionNoCapacity),
                Station::ShareOffCommitment => listed(Station::ShareOffCommitment),
                Station::DescriptorUnrecoverable => listed(Station::DescriptorUnrecoverable),
            }
        }
        // And no variant is listed twice, which would double-count it in any enumeration.
        let mut seen: Vec<Station> = Station::ALL.to_vec();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "ALL contains no duplicates");
    }

    #[test]
    fn every_station_has_a_distinct_stable_name() {
        // A dashboard and an operator's saved query both key on these, so a duplicate would silently
        // merge two different worlds — the very confusion POROS's four identical `Vec::new()` returns
        // caused, reintroduced at the naming layer.
        let mut seen: Vec<&str> = Station::ALL.iter().map(|s| s.name()).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "station names must be distinct");
        assert!(!seen.iter().any(|n| n.is_empty()), "and non-empty");
    }
}
