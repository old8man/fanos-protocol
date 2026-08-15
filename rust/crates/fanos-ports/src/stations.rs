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
    /// A live cell member did not attest within `liveness_timeout`, so the structural (Byzantine) check
    /// was **not run** this window (#230).
    ///
    /// Not an error rate and not a fault: it is the localizer declining to conclude. A class filled by
    /// `polar::mediator_attestation` — the fallback used when no fresh report arrived — is internally
    /// consistent for ANY liveness pattern, so it can never violate. Measured over all 256 `degraded`
    /// masks, a matrix assembled entirely from the fallback fired **zero** times, against one for the same
    /// matrix with a single forged pair. "No Byzantine member" was therefore being reported with the same
    /// confidence whether seven members had attested or none had.
    ///
    /// A member attests every heartbeat unconditionally, so silence from a LIVE one is a refusal to be
    /// checked rather than absent data — which is why this counts members, not windows.
    StructuralCheckUnattested,

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
    /// A real forward was discarded because the constant-rate `outbox` was full (#294).
    ///
    /// The relay's sustained capacity is one cell per cover slot — `1 / cover_interval`, ≈2 cells/s at the
    /// shipping default, for the whole node rather than per circuit. Above it the queue fills and cargo is
    /// dropped. That was silent, and silence here reads as "the E6 volume claim holds" when what actually
    /// holds is that the emission rate is *capped*: past the slot rate the observable moves from the
    /// emission to the drop, and the drop surfaces as retransmissions at the edges.
    RelayCargoDropped,
    /// A forward was refused because the per-cell mixing queue was full (#295).
    ///
    /// Distinct from [`Self::RelayCargoDropped`] in both branch and rule. That one evicts the *oldest*
    /// queued cell, which is right there because the reliability layer retransmits and the queue is a rate
    /// smoother. This one refuses the *newest*: `mix_pending` is a mixer, its oldest entry is the one whose
    /// exponential delay is closest to firing, and evicting it would discard the wait already served and
    /// thin the batch the mix exists to hide a cell in. Under flood the right thing is to protect the cells
    /// already in flight.
    RelayMixRefused,
    /// An onion this router had already accepted arrived again and was dropped (§L5, #296).
    ///
    /// Non-zero is an attack signal, not congestion: no honest path re-sends identical bytes, because every
    /// emission re-seals. A recorded cell re-injected at a relay peels identically and forwards to the same
    /// next hop, so accepting it would answer "is this relay on that circuit?" for whoever injected it.
    ReplayDropped,

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

    // --- Transport (`fanos_quic::driver`) ---
    //
    // The first stations below the engine. Every other name in this enum is raised by an engine, which sees
    // only what the transport already accepted — so the layer every byte crosses first, and the only one an
    // adversary reaches without speaking the protocol, had no name for anything that happened to it (#191).

    /// Wire bytes exceeding `MAX_FRAME + MAX_WIRE_OVERHEAD` — the read refused them before allocating.
    ///
    /// Distinct from [`WireUnshaped`](Self::WireUnshaped) because the peer is *speaking our shape* and
    /// producing something this build will not read: a version disagreement about the ceiling, or a
    /// deliberate oversize. Before #190 this fired on every full TAXIS block from an honest peer and nobody
    /// could see it, which is exactly why it is a counter and not a log line.
    WireOverBound,

    /// Bytes that did not un-shape under this node's community secret and epoch.
    ///
    /// Two very different causes share this name today and must be split once the rotation window exists
    /// (#196): a peer one epoch behind is transient and self-healing, while bytes matching no known shape are
    /// a stranger — or an **active censor probing a PROTEUS bridge**. Until then a *rise* is the signal; a
    /// steady low rate at an epoch boundary is the benign half.
    ///
    /// **Scope narrowed by the datagram envelope (#232).** With sealing on, a stranger no longer reaches the
    /// frame layer at all — it is refused a layer earlier and counted as
    /// [`WireForeignDatagram`](Self::WireForeignDatagram). What still lands here is the `plain` morph and the
    /// pluggable-codec path, where there is no envelope below to catch it first.
    WireUnshaped,

    /// A datagram that did not open under this node's community secret and epoch — refused **before quinn
    /// parses it**, which is what makes the port unresponsive to an unauthenticated prober (spec §13.5).
    ///
    /// This is now the outermost gate on the receive path, so it is the first place an active censor's probe
    /// becomes visible — and the only place, since by design nothing downstream ever hears about it. A node
    /// under enumeration looks idle on every other counter.
    ///
    /// Distinct from [`WireUnshaped`](Self::WireUnshaped) by *layer*, not by cause: same question (is this
    /// ours?), asked of a datagram rather than a frame, and answered before any QUIC state exists to attach a
    /// coordinate to — which is why this one is never keyed by line.
    WireForeignDatagram,

    /// A dial whose QUIC handshake **completed** and whose shaped HELLO round trip then did not (#231).
    ///
    /// This is the data-phase censor's signature, and it had no name: the connection is established, so
    /// nothing reports a dial failure, and no frame ever arrives, so nothing reports a delivery failure. The
    /// morph auto-fallback reads the same event, but a breaker only tells an operator *that* it rotated —
    /// this says how often the shaped path is being cut while the handshake is let through, which is the
    /// number that distinguishes "the network is lossy" from "someone is filtering us".
    ///
    /// Keyed by the peer's coordinate: a rise against one line is a peer problem, a rise across the cell is
    /// the censor.
    TransportRoundTripLost,

    /// A connection whose peer authenticated with **this node's own certificate** — we reached ourselves (#350).
    ///
    /// Not a contrivance and not a test artefact: a self-certifying node's coordinate is `MapToPoint(H(cert))`,
    /// drawn independently of every other node's, so on a plane of `q² + q + 1` points two nodes share a point
    /// about once in that many draws. The directory serves the point as one address — the incumbent's — and the
    /// incumbent addressing the *other* claimant therefore dials itself. Measured on forced collisions before
    /// this station existed: 20 of 20 frames were delivered to the sender and 0 to the addressee, silently.
    ///
    /// **The operator needs this separate from a dial failure**, because the two call for opposite readings: a
    /// dial failure says the network did not carry the frame, this says the frame was carried perfectly and the
    /// *addressing* was ambiguous. A rise here is the placement layer failing to converge, not a transport fault.
    ///
    /// Keyed by the coordinate that was dialed — which is this node's own — because that is the point whose
    /// occupancy is contested, and it is what an operator correlates against the reseat that follows.
    ///
    /// Counted on the DIAL side only. The accept side sees the same event from the other end and refuses it too,
    /// but counting both would double every occurrence; the same asymmetry, for the same reason, that already
    /// keeps `resolve_peer_hello` from feeding the morph breaker.
    TransportSelfConnection,

    /// An `EpochAgree` claim arrived and the cell has **not** corroborated it: fewer distinct members vouch
    /// for that epoch than the corroboration quorum, so it was not adopted (#351).
    ///
    /// **A refusal nobody can see is not a refusal, and the cell freezing is the thing to see.** FANOS's rule
    /// for a node that cannot corroborate is to escalate, not to decide — but "do not decide alone" without
    /// "say that you could not" is a different rule, and it produces a stall indistinguishable from healthy
    /// operation. A beaconless cell whose members cannot agree an epoch is stuck, and stuck must have a voice.
    ///
    /// Tagged with **how many distinct members vouched**, because the two states an operator must separate
    /// are "nobody is claiming" and "two of the three needed are claiming". The first is a quiet cell; the
    /// second is a cell one member short of moving, and only the tag tells them apart.
    ///
    /// Not an attack signal on its own. Under a live beacon this station should never move, because the
    /// composite drops the fallback on receive; a cell that shows both a live beacon and this rising is
    /// reporting that its authoritative source and its fallback disagree about who is driving.
    EpochAgreeBelowQuorum,

    /// A peer's HELLO decoded and its coordinate proof did **not** verify against a beacon this node holds
    /// — a forgery or an impostor (#236). Actionable as an attack.
    ///
    /// Not keyed by line: the claim is unverified, so the coordinate it names is not a fact about anyone.
    /// Keying it would let a stranger choose which of this node's lines its own counters accuse.
    HelloProofRejected,

    /// A peer proved an epoch this node has **no beacon for**, so it could not judge the claim at all.
    ///
    /// This is *our* staleness, not the peer's dishonesty, and merging the two into one counter is the
    /// defect #109 named for POROS's gates. It is also the first thing an operator sees when a node cannot
    /// join a running cell (#235): a freshly-started node holds only the genesis beacon, so every live
    /// peer's claim lands here and nothing else moves at all.
    HelloEpochUnknown,

    /// A connection whose peer could not be judged is being **held open anyway**, in the restricted state
    /// (#235) — the count of joins currently in progress.
    ///
    /// The companion to [`HelloEpochUnknown`](Self::HelloEpochUnknown), and the two answer different
    /// questions: that one says a claim was refused, this one says the connection carrying it survived.
    /// Before this the two were the same event, so an operator could not tell "we turned a joining node
    /// away" from "we are waiting for the beacon that will let it in". On a healthy node it is small and
    /// transient; a value that stays high means beacons are not reaching new arrivals.
    ///
    /// Not keyed by line, for the same reason as its companion: the coordinate is a stranger's claim.
    PeerUnjudged,

    /// A beacon round **crossed** a restricted connection and was handed to the engine (#235).
    ///
    /// **The success half of the pair, and the pair is the point.** Its companion
    /// [`RestrictedFrameDropped`](Self::RestrictedFrameDropped) counts only refusals, and a refusal counter
    /// alone cannot answer the question the restricted state exists for — "did the beacon get through?" —
    /// because a round that *does* get through is admitted, so it never appears there. Six measured runs
    /// showed hundreds of drops and left "no round ever arrived" and "a round arrived and the engine
    /// rejected it" as the same reading. They are different defects, in different crates, and this counter
    /// is the discriminator: zero here means the cell is not flooding to this peer at all; non-zero with no
    /// adoption sends the question to the beacon engine's own reject counters (#161).
    ///
    /// Not keyed by line, like the rest of this group: the sender's coordinate is an unproven claim.
    RestrictedFrameAdmitted,

    /// A peer in the restricted state sent something other than a beacon round, and it was dropped (#235).
    ///
    /// The restricted set admits exactly the frames whose handler does **not** read `from`, because an
    /// unjudged peer's coordinate is a claim rather than a fact. Anything else is either a version skew or
    /// a peer probing what an unauthenticated connection will carry — and neither leaves a trace anywhere
    /// else, since a connection in this state is in no table and so has no per-peer counter.
    RestrictedFrameDropped,

    /// A DIAULOS session **discarded** an inbound payload, tagged by which of `Ingest`'s classes it fell in
    /// (#244).
    ///
    /// The session layer had no counter at all: four anonymous `return`s answered an unparseable frame, a
    /// frame in the wrong state, a refused handshake, and a delivery from the wrong coordinate alike, so
    /// "the service never answered" and "the service answered and I threw it all away" were the same
    /// reading. On the accepting side the path is fed by *any* peer, which makes this the only trace a
    /// probe leaves.
    ///
    /// Keyed by line where the caller knows it — the accepting side binds a client coordinate on the first
    /// accepted hello, so a `WrongSender` drop names the *bound* peer, not the one that sent it.
    SessionIngestDropped,

    /// A dialed coordinate was **vacant at the address the directory named**, and the peer that answered
    /// proved a *different* one — the peer moved and our entry is stale (#240).
    ///
    /// Not a refusal of a liar: the HELLO verified perfectly. Recording it apart from
    /// [`HelloProofRejected`](Self::HelloProofRejected) is the whole point, because the two call for
    /// opposite responses — this one is repaired by updating the directory, that one by dropping the peer.
    ///
    /// **A rise here means the epoch period is shorter than directory propagation**, which is a deployment
    /// fact no other counter states: seats rotate every epoch by §L3, so every stale entry is one dial
    /// wasted, and a cell that rotates faster than it republishes wastes all of them.
    ///
    /// Keyed by the coordinate we *dialed* — our own resolution, not a value a stranger chose.
    DirectoryStaleCoordinate,

    /// A peer that proved a **different** coordinate had its connection KEPT, filed at the point it proved
    /// (#264) — the companion to [`DirectoryStaleCoordinate`](Self::DirectoryStaleCoordinate), which counts
    /// the diagnosis while this counts what was salvaged from it.
    ///
    /// **Two counters because the outcomes differ and only one is good.** Every mismatch raises the stale
    /// counter; this one rises only when the connection became a usable route. It stays flat when a live
    /// connection already held that point — our new one was redundant and correctly discarded — so
    /// `stale_coordinate` minus this is the number of moves that cost a connection setup and bought nothing.
    ///
    /// Before #264 this was zero by construction: the connection was always dropped, which also closed the
    /// route the *answering* peer had just filed for us. Keyed by the coordinate the peer PROVED, which is
    /// the one fact the handshake established.
    DirectoryMovedPeerRetained,

    /// An inbound connection arrived while a live one to that peer was **already held** (#265).
    ///
    /// **Same event as the counter it replaces, opposite consequence — and that is why it was renamed.**
    /// Shipped one commit earlier as `conns.route_replaced`, it counted this arrival *evicting* the live
    /// route, because the map held one connection per peer: measured at 5 on the run whose reverse send
    /// timed out. The map now holds a list, so the arrival is retained beside the incumbent and costs
    /// nothing. Keeping the old name would have made a harmless number read as a defect.
    ///
    /// **Still worth counting, and it is not expected to be zero.** It is the rate at which peers open a
    /// second connection while the first works — surplus to the dialer, which discards it, and formerly
    /// fatal to the acceptor. A rise says placement churn or a dialer deduping by the wrong key; it no
    /// longer says anything was lost.
    ///
    /// Keyed by the peer's coordinate. The value it reports is how many live connections were held *before*
    /// this one, which is zero on every ordinary accept.
    ConnSurplusHeld,

    /// A send **read a peer's connection list while it held more than one**, and this is how many entries
    /// it found already closed (#267).
    ///
    /// **The discriminator between two very different worlds.** The peer at the other end may be closing
    /// connections this node still holds — in the late-join scenario it closes six of seven — and
    /// `Connection::close_reason` reports only a closure this side has *observed*, which costs a round trip.
    /// Either the closes arrive and get pruned, in which case sending into a corpse is a bounded transient,
    /// or they never do and the list is a graveyard whose head is permanently dead. The repair differs
    /// completely between those, so the counter has to separate them.
    ///
    /// **Fired on every surplus read, including the ones that prune nothing — and the first version was not.**
    /// Recording only when something was pruned makes a zero mean two incompatible things: "read the list,
    /// found nothing dead" and "never read the list at all". The measurement it was built for produced
    /// exactly that ambiguity and could not be concluded from. Tagging every read with its prune count —
    /// `#0` included — is what makes absence mean *the send path never consulted this peer*.
    ///
    /// Bounded by design: a single-entry list is the steady state and does not report, so this fires only
    /// where two connections to one coordinate actually coexist.
    ///
    /// Keyed by the peer's coordinate, tagged with how many entries that read removed.
    ConnSurplusRead,

    /// A peer announced a verified move, and this is how many of its connections travelled with it (#271).
    ///
    /// **The number is the point.** Re-keying used to carry exactly the connection the announcement arrived
    /// on, which was complete while the map held one connection per coordinate and stopped being complete
    /// the moment #265 made the value a list. Measured then: six left behind against one moved, each kept
    /// alive by `keep_alive_interval` and unreachable for pruning because #241's directory retraction means
    /// nothing addresses the vacated point again.
    ///
    /// So a `1` here on a peer that held several is the defect returning, and a `0` is a different world
    /// again — the old point held nothing. Keyed by the peer's NEW coordinate, tagged with the count moved.
    ConnMovedWithPeer,

    /// A second **unjudged** connection from a coordinate this node already holds one for was refused a
    /// reader and dropped, which closes it (#267).
    ///
    /// **The deliberate asymmetry with [`ConnSurplusHeld`](Self::ConnSurplusHeld), and the reason both are
    /// counted.** That station says a surplus was *kept*; this one says a surplus was *closed*. The two sit
    /// one layer apart on purpose: a judged peer's second connection costs a list entry, while an unjudged
    /// peer's would cost a spawned reader on a connection nothing has authenticated, and the bound there is
    /// one per coordinate. But the consequence lands on the peer, not here — it dialed, got answered, and
    /// had the answer closed under it.
    ///
    /// It was silent, and silence is what made a measurement unreadable: a late-joining node's restricted
    /// channel carried exactly two frames on every failing run, and nothing said that the same node had
    /// closed six other connections to the same peer in the same second. Keyed by the coordinate refused.
    RestrictedSurplusDropped,

    /// An unroutable coordinate made this node dial a **configured entry address** (#263) — the send
    /// ladder's last rung, below the relay hub.
    ///
    /// **Counts the attempt, not a delivery.** The rung is recovery rather than routing: the frame that
    /// triggered it is dropped (`unresolved_drops` rises with it) and the dial runs detached, so the drop
    /// path stays fast — awaiting it put a full `DIAL_TIMEOUT` on the one path that must not wait, which is
    /// #129's stall. What it buys is the *next* frame, once the handshake has filed whoever answered at the
    /// coordinate it proved.
    ///
    /// Zero on a healthy node: reached only when a coordinate has no address, no cached connection and no
    /// hub. A non-zero value says the address book lost a peer and the operator's bootstrap list is what the
    /// node fell back to — useful precisely because that loss is silent in the map, which simply no longer
    /// holds the entry.
    DirectoryEntryFallback,

    /// A POROS line rotation **did not arm**: the outgoing roster admits no valid contributor subset at the
    /// line's threshold, so this node prepared nothing and will keep serving on the share it already holds
    /// until that share's epoch expires (#243).
    ///
    /// Not an error and not an attack — a roster that cannot supply `t` contributors arms nothing, which is
    /// the honest state rather than a rotation that can never complete. What makes it worth a counter is that
    /// it is **this node's own stop**, and `poros.rs` counts eleven ways a *peer* can lie while counting no
    /// way for the node to fall silent by itself. A rise here means the community has drifted below the
    /// threshold its line was dealt at, which no other reading states and which an operator must answer by
    /// re-dealing rather than by waiting.
    ///
    /// Deliberately distinct from "this node is not on the new line", which is the ordinary case for most
    /// members every epoch and carries no information.
    PorosRotationUnarmed,

    /// This node tried to bind **its own coordinate** in its local address book and the arbitration rule
    /// refused: an incumbent holds the better claim, so the node is not resolvable at the point it believes
    /// it occupies (#241).
    ///
    /// Not an error — losing an arbitration is the rule working, and the answer is to walk on
    /// (`fanos_vrf::settle_index`). What makes it worth a counter is that the walk and the table are **two
    /// stores of one fact**: the walk settles against the claim book, the refusal comes from the directory,
    /// and each can hold a claim the other has never seen. A rise here is that disagreement, and it is
    /// invisible in every other reading — the node reports a coordinate, announces it in its HELLO, and
    /// peers resolve someone else.
    ///
    /// Keyed by the point this node was trying to take: its own derived seat, never a value a peer supplied.
    DirectorySeatSuperseded,

    /// A route to a **peer** that this node *proved* — it completed a mutual-TLS handshake and verified the
    /// coordinate at that address — was refused by the arbitration rule, so the table keeps another
    /// occupant's address for that point (#241).
    ///
    /// Split from [`DirectorySeatSuperseded`](Self::DirectorySeatSuperseded) because the response is the
    /// opposite one. There the node must move; here the node keeps working and simply does not get the route
    /// it earned — the hole it punched goes unused and the next frame falls back to the relay, or the send
    /// that discovered the move fails again. Both are quiet by construction: the write returns and nothing
    /// downstream changes.
    ///
    /// Nonzero without a matching [`DirectoryStaleCoordinate`](Self::DirectoryStaleCoordinate) rise means a
    /// *ranked* binding is squatting the point — a peer's verified claim that is better than our unranked
    /// observation, which is the arbitration behaving correctly, and also exactly what a node that has
    /// legitimately moved leaves behind for an epoch.
    ///
    /// Keyed by the coordinate the peer **proved**, so the key is evidence rather than an assertion.
    DirectoryRouteSuperseded,

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
    /// A **long-lived driver actor stopped** — the node lost a piece of itself and kept running (#251).
    ///
    /// The transport driver spawns six loops that are meant to outlive every request: the accept loop, the
    /// transport loop, the engine loop, the router, the announce watcher and the epoch reshuffle. Nothing
    /// joined them, and a task nobody joins cannot report its own death — so a panic inside one removed a
    /// whole capability (no new connections; or no frames sent; or no epoch reseat) while every other
    /// surface, `health` included, went on saying the node was fine. That is the worst shape an outage can
    /// take: degraded and confident.
    ///
    /// [`Observation::tag`] carries `fanos_quic::DriverActor`, because which one died decides what stopped
    /// working, and one aggregate count would say only "something".
    ///
    /// **Panic and cancellation are the same station and must NOT be**: they are separated by the log line
    /// beside the counter, since a cancelled actor is an orderly shutdown and a panicked one is a defect.
    /// The counter is the alarm; the line says which of the two rang it.
    ActorDied,
    /// A snapshot write to the state directory **failed**, so this node is running without durable state.
    ///
    /// The counterpart of [`StoreAtCapacity`](Self::StoreAtCapacity) one layer down: that one is a node
    /// refusing content it cannot hold, this one is a node holding content it cannot keep. Neither is fatal
    /// and both are invisible from outside — a node with a full disk serves every read and answers every
    /// probe exactly as a healthy one does, right up to the restart where #77's whole subject (the store, the
    /// ledger, the loss record) turns out to be the state of some earlier hour.
    ///
    /// **Why a counter beside the `Health` level rather than instead of it.** `fanos_node::Durability` is a
    /// *level* — an operator asking "is this node durable right now" gets a straight answer, which is what
    /// they need during an incident. A level cannot answer "has this disk been flapping all week", because a
    /// run of failures that ended leaves no trace in it by design. Both questions are real and one field
    /// cannot hold both, which is the same split [`ReadInconclusive`](Self::ReadInconclusive) draws between
    /// the caller's three-state answer and the operator's diagnosis (#200).
    ///
    /// [`Observation::tag`] carries `fanos_node::PersistFailure` — whether another tick will retry, or the
    /// process was already on its way out. The second is not a worse instance of the first: on the stopping
    /// path there is no retry, so everything since the last successful write is *gone*, and #178 exists
    /// because that path is the one where nothing needed to be lost.
    SnapshotWriteFailed,
    /// A `Value` shard reply refused on the **read** path, tagged by which rule refused it
    /// (`fanos_runtime::ReadRefusal` — named there because that is where the rules are, and this crate sits
    /// below it).
    ///
    /// **The mirror of [`StoreAtCapacity`](Self::StoreAtCapacity), which is the whole point.** The write path
    /// checked a shard's size and its write-version and counted the refusal; the read path checked neither and
    /// counted nothing, so the one an attacker reaches without being anyone's shard home was the unguarded one
    /// (#211, #212). Every reply refused here is evidence of a **cell member misbehaving** — an honest peer
    /// answers a `Lookup` with the shards it holds, which pass all three rules by construction — so unlike a
    /// full store this is never a symptom of honest load.
    ReadShardRefused,
    /// A `Get` settled as [`ReadOutcome::Inconclusive`](crate::ReadOutcome), tagged by why
    /// (`fanos_runtime::ReadStall`).
    ///
    /// **The reason lives here and not in the notification, deliberately.** A caller only ever needs the three
    /// states — it either has the bytes, knows there are none, or knows nothing. An operator needs to know
    /// *which* non-conclusion, because a slow cell, a saturated read table and an unseated node call for three
    /// different actions. Splitting them that way keeps the type the width of the decision and still puts the
    /// diagnosis somewhere a human can read it (#215).
    ReadInconclusive,
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

    /// The cell **wants more nodes in a role than any member offered** — a real provisioning shortfall
    /// (`AssignReport::deficit`), which for a threshold-line role means the guarantee that role exists to
    /// provide is not currently being met.
    ///
    /// Silent until now, and harmlessly so only by accident: while `ROLE_CAPACITY_PER_NODE` was the
    /// placeholder `1` the demand exceeded eligible supply on *every* active cell, so the deficit was a
    /// fabrication and reporting it would have been noise on every epoch. With the capacities derived from
    /// each role's own admission bound the number means what it says, and a shortfall that nothing reads is
    /// the worse of the two failure modes the tripwire in `role_loop` warned about.
    ///
    /// [`Observation::tag`] carries the role index. This is the *local* signal; escalating a shortfall to the
    /// parent cell (`docs/design-roles.md`) needs the hierarchy path and is not this station.
    RoleUnderProvisioned,

    /// This node's claim **took an occupied point from its holder** — arbitration went our way and a live
    /// binding was evicted (#260).
    ///
    /// The counterpart of [`Self::DirectorySeatSuperseded`], and the half that was silent. `WriteOutcome`
    /// used to fold "bound a free point" and "displaced an incumbent" into one value on the reasoning that
    /// the writer cannot tell them apart — which is true and beside the point, because the *cell* can: the
    /// evicted address was reachable at that coordinate a moment ago and is not now, until it walks on.
    ///
    /// [`Observation::line`] carries the contested coordinate. A run of these is the plane approaching its
    /// occupancy bound rather than one unlucky draw, and that is the reading an operator needs: a cell holds
    /// about `q` nodes before collisions become routine, not `q² + q + 1`.
    DirectoryPointTaken,

    /// A peer proved a **better claim to the point this node is seated on**, and this node may not move (#260).
    ///
    /// Not a third spelling of the two above. Those are outcomes of a *write this node made*; this is a standing
    /// condition it discovered and cannot act on. The coordinate rule (`fanos_vrf::claim_beats`) can decide that the
    /// seated node lost, while the placement rule forbids an established node to re-seat mid-epoch — because the cell
    /// has already derived committee membership, shard placement and routing from where it sits. Each rule is right
    /// alone; together they leave two nodes on one point until the next beacon re-derives placement.
    ///
    /// The frozen node is **not** uninformed: the winning claim is in its own claim book, which is what raised this.
    /// It is forbidden to act, so no message would help — the missing thing was that the state was invisible. Measured
    /// on the two-node join probe, the frozen side reported zero collisions and looked healthy while the cell was
    /// split, because a collision is counted where a *binding* is refused and this node never attempted one.
    ///
    /// [`Observation::line`] carries the contested coordinate. A nonzero count that does not clear at the next epoch
    /// is the settling window (`docs/design-coordinates.md`) being needed rather than one unlucky draw.
    DirectorySeatOutranked,

    /// This node passed its **first epoch boundary** and may no longer re-seat on a peer claim (#260).
    ///
    /// The two states the coordinate-resolution argument turns on are "still joining" and "committed":
    /// `spawn_self_certifying`'s reshuffle loop moves the first on a recorded peer claim and refuses to move
    /// the second, because the cell has by then derived committee membership, shard placement and routing from
    /// where this node sits. Both are load-bearing and neither was observable — so a contested coordinate could
    /// not be diagnosed without first guessing which side was even permitted to walk on.
    ///
    /// Fires **once per node lifetime**, on the transition. A second one is a node that restarted, which is a
    /// different reading from a node that never committed at all — and telling those apart is the point.
    /// [`Observation::line`] is deliberately absent: the boundary re-derives the placement a few statements
    /// later and may leave it unchanged, so any coordinate recorded here would be the one held *entering* the
    /// boundary, close enough to the settled answer to be misread as it.
    SeatCommitted,

    /// An anonymous **RPC request exceeded the bound its host was constructed with**, and was refused (#194).
    ///
    /// The `_rpc` conveniences in `fanos_node::rendezvous_host` buffer a whole request before the handler
    /// sees a byte, and the client sending it is unauthenticated *by construction* — anonymity is the point,
    /// so there is nobody to hold responsible for a request that never ends. The read used to have no
    /// ceiling at all; now the caller states one, and this is what a client hitting it looks like.
    ///
    /// A rise separates the two readings an operator must act on differently: a service whose legitimate
    /// clients have outgrown the bound it was given (raise it, and re-do the `bound × MAX_SESSIONS` sum),
    /// against a service being leaned on by someone who costs nothing to be (the bound is working). Neither
    /// is visible from a dropped session, which is why the refusal is counted rather than merely taken.
    HostRequestOverBound,

    /// A datagram opened under the **genesis** shape: the sender does not know the cell's live epoch, which
    /// is what a node joining for the first time necessarily looks like (#234).
    ///
    /// The one observable for "somebody is trying to join". Before it, the whole exchange — accepted or not
    /// — was indistinguishable from silence on every surface this node has: an unshaped datagram is counted
    /// as [`Self::WireForeignDatagram`], but a *correctly* genesis-shaped one is simply handled, and joining
    /// is the case an operator most wants to see succeed or fail.
    ///
    /// Also the rate an operator should watch for the second cost this path carries: the genesis shape is
    /// static for the network's whole life, so an observer holding the community secret sees a fixed
    /// signature. Bounded by admission — `MAX_INBOUND_CONNECTIONS` rows, each expiring after one
    /// `DIAL_TIMEOUT` — but bounded is not zero, and this counter is where a flood of it would show.
    WireGenesisShaped,

    /// A child cell's escalation was decided **without a coherence budget**: this node holds no `Φ` for the
    /// stratum it was asked to absorb the fault into, so it declined and handed the aggregate up.
    ///
    /// Declining is the right action — absorbing means installing coarse reroutes, and a reroute plan drawn
    /// against a budget nobody measured is a repair this node cannot justify. What was missing is that the
    /// outcome was indistinguishable from a measured refusal. The three ways to have no `Φ` all reached the
    /// same silent path: before this node's first self-healing diagnosis, for the whole life of a node
    /// deployed with `self_healing` off, and across a seating change, which invalidates every other
    /// coherence-derived value the healer holds.
    EscalationUnbudgeted,

    /// The role loop's **demand did not move**, because the cell-wide load scan it rests on did not conclude
    /// — tagged by what was used instead (`fanos_node::SetpointHold`).
    ///
    /// The silent half of a pair whose loud half is [`Self::AssignmentWithheld`]. Withholding is a decision not
    /// to *publish*; this is a decision not to *advance*, and it is the one an operator cannot infer from
    /// anything else: the node keeps publishing, the roster keeps moving, and the assignment it produces is
    /// simply computed from a demand that is one epoch — or, at genesis, infinitely — stale.
    ///
    /// Measured before it existed: five nodes on a 20 ms link, every load scan timing out, every node holding
    /// a demand of zero, and every node therefore assigning `RoleSet::EMPTY` for a full minute with the whole
    /// stations plane empty (#250). A cell serving nothing looked exactly like a cell serving everything.
    SetpointHeld,

    /// The role loop **declined to publish an assignment** because the view it derived one from was behind
    /// what this node can already see — its own capability record missing from the roster, or the roster
    /// smaller than the transport's own peer table.
    ///
    /// A deliberate non-action, and therefore one that has to be counted. Holding the previous assignment is
    /// right — a capability record lives at `cap_slot(coord, epoch)`, so at an epoch turn every slot is empty
    /// until each node republishes, and an assignment derived from that view is one no other node computes
    /// (#146, measured at a roster of 0 with 2 peers known). But a loop that silently keeps returning the
    /// same answer is indistinguishable from a converged one, which is exactly the ambiguity the
    /// `complete`/`repeated` split in `next_stable` exists to remove one level up.
    ///
    /// Zero after a cell settles. A **rising** count means this node's directory view is persistently behind
    /// its transport view — a store that is not answering, or a peer that is in the address book and never
    /// publishes a capability. [`Observation::tag`] carries the roster size the scan produced, so the two are
    /// distinguishable without a second station.
    AssignmentWithheld,

    /// A `Command::Reseat` would have moved this node **out of the explicit cell it was seated in**, and was
    /// refused.
    ///
    /// The two are different mechanisms that must not meet. `with_cell_members` seats a node at a position in
    /// a provisioned 7-member roster, and the whole DIAKRISIS reflex is addressed off that index —
    /// `polar_class(self_index)` names the three channels this node mediates. The per-epoch VRF reshuffle is a
    /// defence for a node's placement on the **base plane**, where the roster *is* the plane. Applying the
    /// second to a node holding the first used to recompute the index by the base-plane rule and leave the
    /// roster untouched: at `q = 2` the node then attested under the wrong three channels, and above it the
    /// reflex switched off — neither visible, because every effect still fired, addressed wrongly (#145).
    ///
    /// Nonzero means a deployment has combined an explicit cell roster with VRF coordinates. That is a
    /// provisioning contradiction, not a runtime fault: nothing is retried and nothing degrades, but the node
    /// is not doing what the operator's configuration says it is.
    ReseatOutOfCell,

    /// A `(coordinate, epoch)` directory publish did not land — the node is **absent from that roster for
    /// that epoch**, and until this station existed it was the last to know.
    ///
    /// Not a soft failure with a retry behind it. `DIRECTORY_SLOT_EPOCHS = 1`, derived from the one-epoch
    /// grace a reader running behind needs, so a slot outlives its own epoch and no further: the previous
    /// publish is already dead to anyone reading the current epoch's key. **One dropped write and the node is
    /// simply not in that directory** — unroutable through the mixdir, unassignable from the capability
    /// roster, unselectable as an exit, invisible to load balancing — while it keeps running and believing
    /// otherwise. There is no window in which a failure is harmless, so every one is recorded.
    ///
    /// [`Observation::tag`] carries which directory, since the consequence differs by directory and an
    /// aggregate count cannot say whether a node lost its onion key or its load report.
    DirectoryPublishFailed,

    /// A message was **rejected by an authentication gate** — a signature that did not verify, a sender that
    /// was not who it claimed, an epoch that was not this one.
    ///
    /// A refused forgery and a message that never arrived produce the identical observable: nothing happens.
    /// So a cell under a sustained forgery attempt looks exactly like a quiet cell, and the one moment an
    /// operator most needs evidence is the one where the code silently returns. Every gate is a place an
    /// attacker is *known* to be probing — that is what the gate is for — so a rejection is the most
    /// informative event the node ever discards.
    ///
    /// [`Observation::tag`] carries which gate, since "someone is forging host registrations" and "someone is
    /// forging capability advertisements" are different attacks with different responses.
    AuthenticationRejected,

    // --- Clearnet exit (`fanos_node::exit`) ---
    //
    // The exit is the one role whose refusals an operator is *accountable* for: the traffic leaves from their
    // address, and the requester is unidentifiable by construction. It shipped with exactly one loud refusal
    // (the #170 destination rule, a `warn!` and no counter) beside four silent ones, so the operator could
    // neither prove their policy was working nor see it being probed (#208).

    /// The exit **declined a client's request** before dialling anything.
    ///
    /// [`Observation::tag`] carries why — see `fanos_node::ExitRefusal`. The three reasons are one station
    /// because the operator's question is a single "what is my exit turning away, and how often"; they are
    /// *tagged* because the answers demand different actions. A malformed target is someone speaking the
    /// wrong protocol at the service. A refused port is the operator's own allow-list working, and its rate
    /// is how they learn whether the list is too narrow — or that someone is hunting for an open mail relay.
    /// A refused destination is the #170 alarm: an anonymous client naming a link-local or RFC 1918 address
    /// is probing for the cloud metadata endpoint from inside the anonymity set, and there is no benign
    /// reading of it.
    ///
    /// The tag is a bounded enumeration and deliberately **not** the destination port, which an anonymous
    /// client chooses: [`Stations::record_tagged`] folds anything above [`MAX_SKEW_TAG`] into the untagged
    /// bucket, so a port histogram would show `25` and silently swallow `443`, and R2 forbids attacker-minted
    /// keys outright. The specific target belongs in the log line beside the counter, and is logged there.
    ExitRefused,

    /// The exit accepted a target, dialled it, and the destination did not answer.
    ///
    /// Not a refusal — this node agreed to relay and the internet did not cooperate — which is why it is a
    /// separate station rather than a fourth [`ExitRefused`](Self::ExitRefused) tag. Individually this is the
    /// most ordinary event an exit has (targets go down, connections time out) and it is worth counting for
    /// exactly one reason: if it is the *only* thing this station shows, the operator's upstream connectivity
    /// is gone and the node is still reporting itself healthy and serving nobody.
    ExitDialFailed,

    /// The exit could not obtain a **local socket** for a session — it never reached the destination at all.
    ///
    /// A different failure from every other name here: nothing about the request was wrong and nothing about
    /// the network failed. This node is out of file descriptors or ephemeral ports. It is the concrete form
    /// of the abstract worry in `docs/design-hidden-service-hardening.md` about an unbounded unit, and it is
    /// the one exit failure that is *this operator's to fix* — so conflating it with a dial failure would
    /// point them at their upstream while the fault is `LimitNOFILE`.
    ExitSocketUnavailable,

    // --- Peer refusals (`fanos_runtime::OverlayNode::on_error`) ---

    /// A peer sent an `ERROR` frame refusing something this node did, and **said why**.
    ///
    /// The protocol defines fifteen error classes and the engine acted on one, returning `Vec::new()` for the
    /// other fourteen — so a peer that refuses us for an unsupported version, a stale epoch or a failed
    /// coordinate proof told us exactly that and the reason stopped one function short of the operator.
    /// During a rollout that refusal *is* the whole diagnostic: the joining node otherwise reports nothing
    /// but a peer that will not talk.
    ///
    /// [`Observation::tag`] carries `ProtocolError::index()` — a **dense** index, not the wire code, because
    /// the codes run to 502 and [`MAX_SKEW_TAG`] would silently fold nine of the fifteen into the untagged
    /// bucket. A code this build does not recognise is still counted, untagged, on the same reasoning as
    /// [`FrameTypeUnknown`](Self::FrameTypeUnknown): a rising count with no tag is the honest reading of
    /// "something is refusing us for a reason we have no name for".
    PeerRefused,

    /// An `ERROR` frame whose body would not parse at all — not a refusal we can name, a refusal we cannot
    /// read.
    ///
    /// Distinct from [`PeerRefused`](Self::PeerRefused) because the remedy is different and the cause is
    /// probably ours: #75 found the `ERROR` frame had two incompatible encodings and only one in the
    /// conformance vector, so a peer speaking the other one lands precisely here. A rise means the two ends
    /// disagree about the format of the message that explains disagreements.
    PeerRefusalUnreadable,
    /// The **beacon engine refused a frame** — tagged with which of its twelve refusal classes
    /// ([`fanos_keygen::BeaconRefusal`]).
    ///
    /// Every one of those twelve was already counted, and read by **nothing in production**: `.rejects()` had
    /// zero non-test callers, so a cell being flooded with forged reshare triggers and a cell running
    /// perfectly looked identical on every instrument an operator has (#327).
    ///
    /// It is an aggregate on purpose, not an `Escalation` per refusal. Most of these are driven by frames a
    /// peer chooses to send — `reshare_forged` rises *exactly* when a signature fails to verify — so a
    /// per-event report would let a remote party set the rate of the node's loudest channel, which is the
    /// defect #341 measured at 1:1 and removed one layer up.
    BeaconRefused,
}

/// What a station's [`Observation::tag`] *means* — declared where the station is, so a reader outside this
/// crate can tell a decodable discriminant from a raw number without guessing.
///
/// **This exists because no scan can answer the question.** The join that turns a tag into a name
/// (`fanos_node::admin::tag_name`) lives in a downstream crate, where [`Station`] is `#[non_exhaustive]` and
/// a `match` therefore needs a wildcard arm — so the compiler cannot notice a tagged station with no arm,
/// and the operator gets a bare integer. Five separate scans were tried for the missing list and each was
/// wrong in a different way: doc phrasing varies ("tag carries" / "tagged by why"), one site builds its tag
/// with `.map()` rather than `Some(...)`, two stations have *both* tagged and untagged call sites, the two
/// recording wrappers (`record_tagged` and the driver's `record_station`) split the sites between them, and
/// three stations reach `record_n` through a `match` that names the variant on another line.
///
/// The knowledge is the author's, at the moment they add the variant. So it is asked for there: the `match`
/// in [`Station::tag_kind`] is inside the defining crate, where `#[non_exhaustive]` does not apply and the
/// compiler makes it exhaustive. A new station does not build until its tag kind is declared, and a
/// downstream guard can then enumerate the ones that owe a vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TagKind {
    /// Every observation of this station carries `tag: None`.
    Untagged,
    /// The tag is a **number that means itself** — a roster size, a wire code outside any registry. There is
    /// nothing to decode, and inventing a name for it would put a fabricated vocabulary in front of an
    /// operator.
    Quantity,
    /// The tag is a **discriminant of a small enumeration**, so a reader that does not decode it is
    /// discarding the distinction the station was tagged for.
    Vocabulary,
}

/// **`ALL` is complete, proven by the compiler.**
///
/// `ALL` is what a reader enumerates, so a variant missing from it is invisible *exactly* where a new
/// discard site was just instrumented — the failure this whole plane exists to end. That cannot be closed
/// by a test: a test can only visit the variants the list already contains, so the omission it is looking
/// for is the one case it never reaches. (The previous guard here iterated `ALL` and asserted each element
/// was in `ALL`; every assertion was true by construction, and its exhaustive `match` forced a new variant
/// to be *named*, not *listed*.)
///
/// `variant_count` answers the question directly and at compile time. Add a variant without adding it to
/// `ALL` and the crate does not build.
const _: () = assert!(
    Station::ALL.len() == core::mem::variant_count::<Station>(),
    "a Station variant is missing from Station::ALL, so every reader that enumerates is blind to it"
);

impl Station {
    /// Every station, for a reader that enumerates rather than guesses (a dashboard, a test asserting the
    /// table is complete). Completeness is enforced above, by the compiler, not by a test.
    pub const ALL: &'static [Self] = &[
        Self::GatherExpired,
        Self::GatherCompleted,
        Self::StructuralCheckUnattested,
        Self::QuarantineDropped,
        Self::HostForwardUnsealable,
        Self::RequestForUnknownHost,
        Self::ShareLateAfterPeel,
        Self::ShareAfterDeadline,
        Self::GatherUnpeelable,
        Self::GatherSelfShareMissing,
        Self::GatherEvicted,
        Self::RelayCargoDropped,
        Self::RelayMixRefused,
        Self::ReplayDropped,
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
        Self::DirectoryPublishFailed,
        Self::RoleUnderProvisioned,
        Self::AssignmentWithheld,
        Self::SetpointHeld,
        Self::WireGenesisShaped,
        Self::DirectoryPointTaken,
        Self::DirectorySeatOutranked,
        Self::SeatCommitted,
        Self::HostRequestOverBound,
        Self::EscalationUnbudgeted,
        Self::ReseatOutOfCell,
        Self::AuthenticationRejected,
        Self::GatherOpenFailed,
        Self::FrameTypeUnknown,
        Self::WireOverBound,
        Self::WireUnshaped,
        Self::WireForeignDatagram,
        Self::TransportRoundTripLost,
        Self::TransportSelfConnection,
        Self::EpochAgreeBelowQuorum,
        Self::HelloProofRejected,
        Self::HelloEpochUnknown,
        Self::PeerUnjudged,
        Self::RestrictedFrameAdmitted,
        Self::RestrictedFrameDropped,
        Self::SessionIngestDropped,
        Self::DirectoryStaleCoordinate,
        Self::DirectoryMovedPeerRetained,
        Self::ConnSurplusHeld,
        Self::RestrictedSurplusDropped,
        Self::ConnSurplusRead,
        Self::ConnMovedWithPeer,
        Self::DirectoryEntryFallback,
        Self::PorosRotationUnarmed,
        Self::DirectorySeatSuperseded,
        Self::DirectoryRouteSuperseded,
        Self::StoreAtCapacity,
        Self::ActorDied,
        Self::SnapshotWriteFailed,
        Self::ReadShardRefused,
        Self::ReadInconclusive,
        Self::ExitRefused,
        Self::ExitDialFailed,
        Self::ExitSocketUnavailable,
        Self::PeerRefused,
        Self::PeerRefusalUnreadable,
        Self::BeaconRefused,
    ];

    /// A short stable name, for a human-facing readout. Stable because an operator's saved query should
    /// not break when a variant is added elsewhere in the enum.
    //
    // (The completeness of `ALL` is proven below the impl, at compile time — not here, and not by a test.)
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::GatherExpired => "gather.expired",
            Self::GatherCompleted => "gather.completed",
            Self::StructuralCheckUnattested => "structural.unattested",
            Self::QuarantineDropped => "quarantine.dropped",
            Self::HostForwardUnsealable => "host.forward_unsealable",
            Self::RequestForUnknownHost => "request.unknown_host",
            Self::ShareLateAfterPeel => "share.late_after_peel",
            Self::ShareAfterDeadline => "share.after_deadline",
            Self::GatherUnpeelable => "gather.unpeelable",
            Self::GatherSelfShareMissing => "gather.self_share_missing",
            Self::GatherEvicted => "gather.evicted",
            Self::RelayCargoDropped => "relay.cargo_dropped",
            Self::RelayMixRefused => "relay.mix_refused",
            Self::ReplayDropped => "relay.replay_dropped",
            Self::GatherOpenFailed => "gather.open_failed",
            Self::ShareRequestNotAMember => "share.not_a_member",
            Self::SharePartialFailed => "share.partial_failed",
            Self::ShareForUnknownRequest => "share.unknown_request",
            Self::ShareIndexOutOfRange => "share.index_out_of_range",
            Self::ShareFloodCapped => "share.flood_capped",
            Self::HolonomyRejected => "holonomy.rejected",
            Self::FrameDecodeFailed => "frame.decode_failed",
            Self::FrameTypeUnknown => "frame.type_unknown",
            Self::WireOverBound => "wire.over_bound",
            Self::WireUnshaped => "wire.unshaped",
            Self::WireForeignDatagram => "wire.foreign_datagram",
            Self::TransportRoundTripLost => "transport.round_trip_lost",
            Self::TransportSelfConnection => "transport.self_connection",
            Self::EpochAgreeBelowQuorum => "epoch.agree_below_quorum",
            Self::HelloProofRejected => "hello.proof_rejected",
            Self::HelloEpochUnknown => "hello.epoch_unknown",
            Self::PeerUnjudged => "hello.peer_unjudged",
            Self::RestrictedFrameAdmitted => "hello.restricted_frame_admitted",
            Self::RestrictedFrameDropped => "hello.restricted_frame_dropped",
            Self::SessionIngestDropped => "session.ingest_dropped",
            Self::DirectoryStaleCoordinate => "directory.stale_coordinate",
            Self::DirectoryMovedPeerRetained => "directory.moved_peer_retained",
            Self::ConnSurplusHeld => "conns.surplus_held",
            Self::RestrictedSurplusDropped => "hello.restricted_surplus_dropped",
            Self::ConnSurplusRead => "conns.surplus_read",
            Self::ConnMovedWithPeer => "conns.moved_with_peer",
            Self::DirectoryEntryFallback => "directory.entry_fallback",
            Self::PorosRotationUnarmed => "poros.rotation_unarmed",
            Self::DirectorySeatSuperseded => "directory.seat_superseded",
            Self::DirectoryRouteSuperseded => "directory.route_superseded",
            Self::StoreAtCapacity => "store.at_capacity",
            Self::ActorDied => "driver.actor_died",
            Self::SnapshotWriteFailed => "store.snapshot_write_failed",
            Self::ReadShardRefused => "read.shard_refused",
            Self::ReadInconclusive => "read.inconclusive",
            Self::AdmissionIdentityUnbound => "admission.identity_unbound",
            Self::AdmissionPowFailed => "admission.pow_failed",
            Self::AdmissionSybilCapped => "admission.sybil_capped",
            Self::AdmissionNoCapacity => "admission.no_capacity",
            Self::ShareOffCommitment => "share.off_commitment",
            Self::DescriptorUnrecoverable => "descriptor.unrecoverable",
            Self::DirectoryPublishFailed => "directory.publish_failed",
            Self::RoleUnderProvisioned => "role.under_provisioned",
            Self::AssignmentWithheld => "assignment.withheld",
            Self::SetpointHeld => "setpoint.held",
            Self::WireGenesisShaped => "wire.genesis_shaped",
            Self::DirectoryPointTaken => "directory.point_taken",
            Self::DirectorySeatOutranked => "directory.seat_outranked",
            Self::SeatCommitted => "seat.committed",
            Self::HostRequestOverBound => "host.request_over_bound",
            Self::EscalationUnbudgeted => "escalation.unbudgeted",
            Self::ReseatOutOfCell => "reseat.out_of_cell",
            Self::AuthenticationRejected => "auth.rejected",
            Self::ExitRefused => "exit.refused",
            Self::ExitDialFailed => "exit.dial_failed",
            Self::ExitSocketUnavailable => "exit.socket_unavailable",
            Self::PeerRefused => "peer.refused",
            Self::PeerRefusalUnreadable => "peer.refusal_unreadable",
            Self::BeaconRefused => "beacon.refused",
        }
    }

    /// What this station's tag means — see [`TagKind`] for why the question is asked here rather than
    /// answered by a scan downstream.
    ///
    /// **Exhaustive on purpose, with no wildcard.** `Station` is `#[non_exhaustive]`, but that attribute
    /// binds other crates, not this one: inside the defining crate the `match` below must cover every
    /// variant, so adding a station without saying what its tag means is a build error rather than a bare
    /// number on an operator's console.
    #[must_use]
    pub const fn tag_kind(self) -> TagKind {
        match self {
            // --- The tag is a discriminant somebody can name. ---
            //
            // Each of these is written out in its own enum's `tag()`/`index()` precisely so an operator's
            // saved counters survive a variant being added, and each has a resolving arm in
            // `fanos_node::admin::tag_name`. That correspondence is what the guard checks.
            Self::AuthenticationRejected      // fanos_node::Gate
            | Self::DirectoryPublishFailed    // fanos_node::Directory
            | Self::ExitRefused               // fanos_node::ExitRefusal
            | Self::PeerRefused               // fanos_wire::ProtocolError (dense index)
            | Self::ReadInconclusive          // fanos_runtime::ReadStall
            | Self::ReadShardRefused          // fanos_runtime::ReadRefusal
            | Self::RoleUnderProvisioned      // fanos_core::roles::Role
            | Self::SetpointHeld              // fanos_node::SetpointHold
            | Self::SnapshotWriteFailed       // fanos_node::PersistFailure
            | Self::ActorDied                 // fanos_quic::DriverActor
            | Self::RestrictedFrameDropped    // fanos_wire::FrameType
            | Self::SessionIngestDropped      // fanos_diaulos::Ingest (dense index)
            | Self::BeaconRefused             // fanos_keygen::BeaconRefusal (dense index)
            => TagKind::Vocabulary,

            // --- The tag is a number that means itself. ---
            //
            // `AssignmentWithheld` carries the roster size it withheld against; `FrameTypeUnknown` carries a
            // wire code that by definition is **not** in the registry — an enumeration cannot contain it, and
            // that is the whole reason the station exists.
            //
            // Note the pair with `RestrictedFrameDropped` above, which tags with a wire code too and IS a
            // vocabulary. The two are not a contradiction and must not be merged: one carries a code the
            // registry has a name for, the other carries the codes it does not. Folding them would hand the
            // resolver an unresolvable tag and force it to invent a name or return a hole (#268).
            //
            // `EpochAgreeBelowQuorum` carries the number of DISTINCT members that vouched — a count with no
            // vocabulary behind it, and the one fact separating a quiet cell from a cell one member short of
            // agreeing. A bare occurrence count cannot tell those apart, which is why it is tagged at all.
            Self::AssignmentWithheld
            | Self::FrameTypeUnknown
            | Self::ConnSurplusRead
            | Self::ConnMovedWithPeer
            | Self::EpochAgreeBelowQuorum => {
                TagKind::Quantity
            }

            // --- No tag. ---
            //
            // Not a default: each of these records `None`, and a station that starts carrying a tag must
            // move out of this arm, which is a change to this list rather than a silent widening.
            Self::EscalationUnbudgeted
            | Self::WireGenesisShaped
            | Self::DirectoryPointTaken
            | Self::DirectorySeatOutranked
            | Self::SeatCommitted
            | Self::HostRequestOverBound
            | Self::GatherExpired
            | Self::GatherCompleted
            | Self::GatherUnpeelable
            | Self::ShareLateAfterPeel
            | Self::ShareAfterDeadline
            | Self::GatherSelfShareMissing
            | Self::StructuralCheckUnattested
            | Self::QuarantineDropped
            | Self::HostForwardUnsealable
            | Self::RequestForUnknownHost
            | Self::GatherEvicted
            | Self::RelayCargoDropped
            | Self::RelayMixRefused
            | Self::ReplayDropped
            | Self::GatherOpenFailed
            | Self::ShareRequestNotAMember
            | Self::SharePartialFailed
            | Self::ShareForUnknownRequest
            | Self::ShareIndexOutOfRange
            | Self::ShareFloodCapped
            | Self::HolonomyRejected
            | Self::FrameDecodeFailed
            | Self::WireOverBound
            | Self::WireUnshaped
            | Self::WireForeignDatagram
            | Self::TransportRoundTripLost
            | Self::TransportSelfConnection
            | Self::HelloProofRejected
            | Self::HelloEpochUnknown
            | Self::PeerUnjudged
            | Self::RestrictedFrameAdmitted
            | Self::DirectoryStaleCoordinate
            | Self::DirectoryMovedPeerRetained
            | Self::ConnSurplusHeld
            | Self::RestrictedSurplusDropped
            | Self::DirectoryEntryFallback
            | Self::PorosRotationUnarmed
            | Self::DirectorySeatSuperseded
            | Self::DirectoryRouteSuperseded
            | Self::AdmissionIdentityUnbound
            | Self::AdmissionPowFailed
            | Self::AdmissionSybilCapped
            | Self::AdmissionNoCapacity
            | Self::StoreAtCapacity
            | Self::ShareOffCommitment
            | Self::DescriptorUnrecoverable
            | Self::ReseatOutOfCell
            | Self::ExitDialFailed
            | Self::ExitSocketUnavailable
            | Self::PeerRefusalUnreadable => TagKind::Untagged,
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
    /// A small **site-defined discriminant**: which sub-kind of this station fired. Its meaning belongs to
    /// the station, not to this field — the frame stations put the wire **type code** here (the second half
    /// of the skew question, which `design-upgrade.md` §4 asks be "counted per tag, per line"), and
    /// [`Station::DirectoryPublishFailed`] puts which directory failed to publish.
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
    fn all_contains_no_duplicates() {
        // Completeness is proven at compile time by the `const _` assertion above `impl Station`, so it
        // is deliberately NOT re-checked here. What a test can still add is the property the compiler
        // cannot see: that the list contains each variant *once*. A duplicate would double-count a
        // station on any dashboard that sums by enumerating.
        //
        // What stood here before was a loop over `ALL` asserting each element was in `ALL` — true by
        // construction, for every arm. It was removed rather than repaired: a guard that cannot fail is
        // worse than none, because it reads as coverage.
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
