//! Reliable, ordered, multiplexed, **incremental** byte streams over the overlay (spec §7.2
//! `Stream*`).
//!
//! The overlay delivers single, possibly-dropped datagrams; an application often wants a reliable
//! ordered byte-stream — a socket. This module is the sans-I/O protocol logic for one: bytes are
//! appended to a [`StreamSender`] as they are produced ([`push`](StreamSender::push)), cut into
//! [`Segment`]s (`STREAM_DATA`), and the [`StreamReceiver`] buffers out-of-order arrivals and
//! releases the in-order prefix incrementally ([`take`](StreamReceiver::take)). It is a socket, not a
//! one-shot message: you do not need the whole payload up front, and the reader gets bytes as they
//! arrive rather than only at FIN.
//!
//! * **Selective repeat (SACK).** The receiver returns the cumulative next-needed sequence *and* a
//!   bitmap of the out-of-order segments it already holds, so the sender retransmits only the
//!   genuinely missing segments (not the whole tail past a gap, as Go-Back-N would).
//! * **Two-level flow control.** A sender-side sliding **window** bounds lookahead; the receiver
//!   **advertises its remaining credit** (`rwnd`) in every ack, and the sender never sends beyond it —
//!   so a slow reader throttles a fast writer (backpressure) and the receiver's buffer is bounded.
//! * **Incremental both ways.** [`StreamSender::push`]/[`finish`](StreamSender::finish) append and
//!   close; [`StreamReceiver::take`] drains the contiguous delivered prefix, freeing buffer and
//!   credit. The one-shot [`StreamSender::new`] and [`StreamReceiver::deliver`] remain for
//!   whole-message use.
//!
//! It is a pure state machine — a driver performs the sends and the retransmit timer — so it composes
//! with either transport. Multiplexing is by `stream_id`: many independent streams share one peer
//! link, each with its own sender/receiver state, so a loss on one stream never stalls another.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

/// Maximum payload bytes per segment (keeps a segment within a typical datagram / onion cell).
pub const MAX_SEGMENT: usize = 1024;

/// The SACK bitmap width: the receiver reports out-of-order receipt of the 64 sequences immediately
/// following the cumulative ack. The send window is capped to this so every in-flight segment's
/// state is representable in one ack.
pub const SACK_WIDTH: u32 = 64;

/// The default sliding-window size (max in-flight / lookahead segments). Bounded by [`SACK_WIDTH`].
pub const DEFAULT_WINDOW: u32 = 32;

/// Retransmit-timer bounds, in **logical ticks** — one tick per [`StreamSender::outbound`] sweep. A
/// driver calls `outbound` at a fixed cadence (once per sim step; once per pacing timer under real
/// QUIC), so the sweep count is a monotone clock proportional to wall time, and RTT estimated in this
/// unit (RFC 6298) needs no wall-clock threaded through the whole stack — the sender stays sans-I/O
/// while still adapting to the driver's real cadence. `INIT` is the pre-measurement timeout (RFC 6298
/// §2.1); `MIN`/`MAX` clamp it. Historically TCP itself measured RTT in coarse timer ticks (RFC 793),
/// so a tick-clocked estimator is a derived, well-precedented construction, not an approximation of
/// convenience.
const RTO_INIT_TICKS: u32 = 3;
const RTO_MIN_TICKS: u32 = 1;
/// An absolute safety ceiling on the RTO, only ever reached before any RTT measurement exists (the
/// real ceiling is relative — see [`RTO_BACKOFF_MULT`]).
const RTO_MAX_TICKS: u32 = 240;

/// The exponential back-off ceiling, **relative to the measured base RTO** (`SRTT + 4·RTTVAR`). RFC
/// 6298's large absolute cap (≈60 s) exists to spare a *congested* path from retransmit storms — but
/// FANOS sends at a **constant cell rate** (a resend merely displaces a padding cell; see
/// [`Connection::outbound_padded`]), so a retransmit never adds network load and there is nothing to
/// back off *for*. Backing off far past the RTT would then only stall recovery under heavy loss with no
/// congestion benefit. Capping at a small multiple of the base RTO keeps spike protection (the base
/// already carries a 4·RTTVAR margin) while bounding recovery latency — and, being expressed in the
/// estimator's own RTT units, it adapts to whatever real cadence the driver sweeps at rather than
/// hard-coding a tick count that is only meaningful for one transport.
const RTO_BACKOFF_MULT: u32 = 4;

/// Duplicate acknowledgements that trigger a **fast retransmit** (RFC 5681 §3.2): three acks that repeat
/// the cumulative point while reporting fresh out-of-order data mean the gap segment was lost, so resend
/// it well before the RTO would expire.
const DUP_ACK_THRESHOLD: u32 = 3;

/// The span (in ticks) of the golden-ratio jitter applied when fast retransmit reschedules a lost gap.
/// Fast retransmit must be *prompt* but not fire in lock-step with the ack-clock that triggers it — else
/// the resend phase-locks with a periodic loss pattern exactly as a bare RTO would. A short jittered
/// delay in `[0, SPAN)` keeps it fast while walking the resend across loss phases (see [`jitter_ticks`]).
const FAST_RETX_JITTER_SPAN: u32 = 5;

/// An RFC 6298 smoothed-RTT / retransmit-timeout estimator in logical ticks, kept in the classic
/// Jacobson–Karels scaled-integer form (`srtt` ×8, `rttvar` ×4). This is a **local timing** value — it
/// gates only when the sender resends, never a security or consensus quantity — so exact integer ticks
/// (no `f64`) keep it deterministic and panic-free across platforms.
#[derive(Clone, Debug)]
struct RttEstimator {
    /// Smoothed round-trip time, scaled ×8. `0` means no measurement has been taken yet.
    srtt_x8: u32,
    /// Round-trip-time variation, scaled ×4.
    rttvar_x4: u32,
    /// The current retransmit timeout, in ticks (already clamped) — includes any exponential back-off.
    rto: u32,
    /// The measured base RTO `SRTT + max(1, 4·RTTVAR)` **before** back-off. Back-off is capped at
    /// [`RTO_BACKOFF_MULT`]·`base_rto`, so the ceiling tracks the real RTT rather than a fixed tick count.
    base_rto: u32,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            srtt_x8: 0,
            rttvar_x4: 0,
            rto: RTO_INIT_TICKS,
            base_rto: RTO_INIT_TICKS,
        }
    }

    /// Fold in one round-trip measurement `m` (ticks), updating `SRTT`, `RTTVAR` and the `RTO`
    /// (RFC 6298 §2, K = 4, clock granularity G = 1 tick). A measurement is floored at one tick: an ack
    /// seen in the same sweep as the send is still a full (minimal) round. A fresh measurement also
    /// clears any accumulated back-off (the new RTO is the base).
    fn sample(&mut self, m: u32) {
        let m = m.max(1);
        if self.srtt_x8 == 0 {
            self.srtt_x8 = m << 3; // SRTT   = m       (×8)
            self.rttvar_x4 = m << 1; // RTTVAR = m / 2   (×4)
        } else {
            let srtt = self.srtt_x8 >> 3;
            let delta = srtt.abs_diff(m); // |SRTT − m|
            // RTTVAR ← 3/4·RTTVAR + 1/4·|SRTT − m|, all ×4 (so +delta, not +delta/4).
            self.rttvar_x4 = self.rttvar_x4 - (self.rttvar_x4 >> 2) + delta;
            // SRTT   ← 7/8·SRTT + 1/8·m, all ×8 (so +m, not +m/8).
            self.srtt_x8 = self.srtt_x8 - (self.srtt_x8 >> 3) + m;
        }
        // RTO = SRTT + max(G, K·RTTVAR); K·RTTVAR is exactly `rttvar_x4`, G = 1 tick.
        self.base_rto =
            ((self.srtt_x8 >> 3) + self.rttvar_x4.max(1)).clamp(RTO_MIN_TICKS, RTO_MAX_TICKS);
        self.rto = self.base_rto;
    }

    /// Exponential back-off on a retransmit timeout (RFC 6298 §5.5): double the RTO, but cap it at a
    /// small multiple of the measured base RTO rather than a large absolute value — under constant-rate
    /// cover traffic a resend adds no load, so backing off far past the RTT only delays recovery (see
    /// [`RTO_BACKOFF_MULT`]). A later unambiguous [`sample`](Self::sample) resets to the base.
    fn back_off(&mut self) {
        let ceiling = self
            .base_rto
            .saturating_mul(RTO_BACKOFF_MULT)
            .min(RTO_MAX_TICKS);
        self.rto = self.rto.saturating_mul(2).min(ceiling).max(RTO_MIN_TICKS);
    }
}

/// `frac(φ) · 2³²` for the golden ratio `φ = (√5 − 1)/2` — Knuth's Fibonacci-hashing multiplier. The
/// golden ratio is, by Hurwitz's theorem, the real number *worst* approximable by rationals.
const GOLDEN_Q32: u32 = 0x9E37_79B9;
/// `frac(√2) · 2³²` — a second irrational step, incommensurable with the golden ratio, to spread the
/// jitter across sequence numbers as well as across attempts (a 2-D Kronecker sequence). Also the
/// SHA-2 `h₀` constant, a standard nothing-up-my-sleeve value.
const SILVER_Q32: u32 = 0x6A09_E667;

/// A deterministic, **provably non-resonant** retransmit jitter in `[0, rto)` ticks.
///
/// A pure exponential-backoff RTO is periodic, so against a *periodic* loss pattern a stuck segment's
/// retransmits can phase-lock onto the dropped phase and never get through — a mode-locking livelock.
/// Real stacks break this with random jitter; a sans-I/O engine has no randomness, so instead we use a
/// **golden-ratio Weyl (Kronecker) sequence**: `frac(seq·√2 + attempt·φ)` scaled into `[0, rto)`. By
/// Weyl's theorem this is equidistributed, and because `φ` is the most irrational number the sequence
/// is maximally resistant to phase-locking with any rational-period loss — the same anti-synchronisation
/// principle as phyllotaxis's golden angle, derived rather than analogised. Because it is a pure
/// function of `(seq, attempt, rto)` the engine stays fully deterministic and replayable.
fn jitter_ticks(seq: u32, attempt: u32, rto: u32) -> u32 {
    let phase = seq
        .wrapping_mul(SILVER_Q32)
        .wrapping_add(attempt.wrapping_mul(GOLDEN_Q32));
    // floor(frac(phase) · rto): scale the Q0.32 phase by `rto` and keep the integer part. The product
    // is < rto·2³² ≤ 240·2³², so the shifted result is < rto and the `try_from` never falls back.
    let scaled = (u64::from(phase) * u64::from(rto.max(1))) >> 32;
    u32::try_from(scaled).unwrap_or(0)
}

/// A selective acknowledgement plus a receive-window credit. `cumulative` is the next sequence the
/// receiver still needs (all below it are in order); `sack` is a bitmap where bit `i` set means
/// sequence `cumulative + i` has already been received out of order (bit `0` is always clear —
/// `cumulative` is the gap); `rwnd` is the number of further segments the receiver will buffer beyond
/// `cumulative` right now (its free credit — flow control).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ack {
    /// The next in-order sequence the receiver needs (cumulative ack).
    pub cumulative: u32,
    /// Bitmap of out-of-order sequences held beyond `cumulative` (bit `i` ⇒ `cumulative + i`).
    pub sack: u64,
    /// The receiver's remaining buffer credit, in segments (flow control / backpressure).
    pub rwnd: u32,
}

/// One stream segment: `stream_id ‖ seq ‖ fin ‖ data` (spec §7.2 `STREAM_DATA`/`STREAM_FIN`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Segment {
    /// The stream this segment belongs to.
    pub stream_id: u32,
    /// The segment's sequence number (`0`-based).
    pub seq: u32,
    /// Whether this is the final segment of the stream.
    pub fin: bool,
    /// The segment's payload bytes.
    pub data: Vec<u8>,
}

impl Segment {
    /// Encode the segment to bytes: `stream_id(4) ‖ seq(4) ‖ fin(1) ‖ data`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.data.len());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(u8::from(self.fin));
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode a segment, or `None` if the buffer is too short.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let stream_id = u32::from_be_bytes(bytes.get(0..4)?.try_into().ok()?);
        let seq = u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?);
        let fin = *bytes.get(8)? != 0;
        let data = bytes.get(9..)?.to_vec();
        Some(Self {
            stream_id,
            seq,
            fin,
            data,
        })
    }
}

/// The sender half: an append-only byte buffer, segmented lazily, that **selectively repeats** only
/// the missing segments within `min(window, peer_rwnd)`, until the stream drains.
#[derive(Clone, Debug)]
pub struct StreamSender {
    stream_id: u32,
    /// Sealed (immutable, sendable) segments still in flight, `segments[i]` bearing sequence
    /// `base + i`. Fully-acked segments are reclaimed off the front (they are never retransmitted), so
    /// this holds only the unacknowledged window — a transfer far larger than RAM streams in bounded
    /// memory (audit F3).
    segments: VecDeque<Vec<u8>>,
    /// Sequence number of `segments.front()` — the count of segments already reclaimed.
    base: u32,
    /// The unsealed tail — bytes pushed but not yet formed into a full segment.
    pending: Vec<u8>,
    /// Set once [`finish`](Self::finish) has sealed the final (FIN-bearing) segment.
    finished: bool,
    /// Cumulative ack: every sequence below this is acknowledged.
    acked: u32,
    /// Individually acknowledged sequences at or above `acked` (from SACK bitmaps) — NOT retransmitted.
    sacked: BTreeSet<u32>,
    /// Local lookahead cap (flow control).
    window: u32,
    /// The receiver's last-advertised credit (flow control); the effective window is `min` of the two.
    peer_rwnd: u32,
    /// Logical retransmit clock — advanced one tick per [`outbound`](Self::outbound) sweep. All send
    /// times and the RTO live in this unit (see [`RTO_INIT_TICKS`]).
    clock: u32,
    /// The tick each in-flight seq was last (re)sent — the RTT-sample timebase. Bounded by the window
    /// and pruned as segments are reclaimed, so it never grows with the transfer.
    last_sent: BTreeMap<u32, u32>,
    /// The earliest tick at which each in-flight seq may next be (re)sent — the **jittered retransmit
    /// schedule**. Absent ⇒ never sent ⇒ due immediately. Both the RTO timer and fast retransmit act by
    /// writing this one schedule, so every resend passes through the same anti-resonance jitter.
    due_at: BTreeMap<u32, u32>,
    /// Seqs retransmitted at least once, mapped to their **retransmit count**. Presence excludes the seq
    /// from RTT sampling (Karn's algorithm — an ack for a resent segment is unattributable); the count
    /// drives the per-attempt retransmit jitter (see [`jitter_ticks`]). Pruned on reclaim.
    retransmitted: BTreeMap<u32, u32>,
    /// The RFC 6298 RTT/RTO estimator, in ticks.
    rtt: RttEstimator,
    /// The last cumulative-ack point seen, and how many times it has repeated while reporting fresh
    /// out-of-order data — the RFC 5681 fast-retransmit counter.
    last_cumulative: u32,
    /// Count of duplicate acks accumulated at `last_cumulative` (reset on progress or on firing).
    dup_acks: u32,
}

impl StreamSender {
    /// Open an empty, incremental stream. Append with [`push`](Self::push), close with
    /// [`finish`](Self::finish).
    #[must_use]
    pub fn open(stream_id: u32) -> Self {
        Self {
            stream_id,
            segments: VecDeque::new(),
            base: 0,
            pending: Vec::new(),
            finished: false,
            acked: 0,
            sacked: BTreeSet::new(),
            window: DEFAULT_WINDOW,
            peer_rwnd: SACK_WIDTH,
            clock: 0,
            last_sent: BTreeMap::new(),
            due_at: BTreeMap::new(),
            retransmitted: BTreeMap::new(),
            rtt: RttEstimator::new(),
            last_cumulative: 0,
            dup_acks: 0,
        }
    }

    /// The total number of segments ever sealed (reclaimed + in-flight) — the sequence space, used as
    /// the send-window upper bound and the FIN-bearing last sequence.
    fn total(&self) -> u32 {
        self.base + self.segments.len() as u32
    }

    /// Open a stream carrying a complete `payload` (one-shot / whole-message convenience): equivalent
    /// to [`open`](Self::open) + [`push`](Self::push) + [`finish`](Self::finish).
    #[must_use]
    pub fn new(stream_id: u32, payload: &[u8]) -> Self {
        let mut s = Self::open(stream_id);
        s.push(payload);
        s.finish();
        s
    }

    /// Set the sliding-window size (clamped to `1..=SACK_WIDTH`).
    #[must_use]
    pub fn with_window(mut self, window: u32) -> Self {
        self.window = window.clamp(1, SACK_WIDTH);
        self
    }

    fn seal_full(&mut self) {
        while self.pending.len() >= MAX_SEGMENT {
            let rest = self.pending.split_off(MAX_SEGMENT);
            let seg = core::mem::replace(&mut self.pending, rest);
            self.segments.push_back(seg);
        }
    }

    /// Append `more` bytes to the send stream, sealing full segments as they form. A no-op once the
    /// stream is [`finish`](Self::finish)ed.
    pub fn push(&mut self, more: &[u8]) {
        if self.finished {
            return;
        }
        self.pending.extend_from_slice(more);
        self.seal_full();
    }

    /// Seal the current partial tail into a (non-final) segment so it is sent promptly, without
    /// closing the stream — the explicit-flush counterpart to a batching write. No-op if the tail is
    /// empty or the stream is finished.
    pub fn flush(&mut self) {
        if self.finished || self.pending.is_empty() {
            return;
        }
        let seg = core::mem::take(&mut self.pending);
        self.segments.push_back(seg);
    }

    /// Close the send side: seal the remaining tail as the final **FIN-bearing** segment (an empty one
    /// if the tail is empty, so the FIN always rides a freshly-sealed segment the peer will receive)
    /// and mark the stream finished. Idempotent.
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        let seg = core::mem::take(&mut self.pending);
        self.segments.push_back(seg);
        self.finished = true;
    }

    /// The segments to (re)send now — call on open/push and on each retransmit tick (one tick per call).
    /// Only segments within the effective window `[acked, acked + min(window, peer_rwnd))` that are
    /// **actually due** are emitted; every call advances the logical [`clock`](Self::clock) one tick.
    ///
    /// A segment is due iff it is (a) being sent for the **first time** (never transmitted), (b) flagged
    /// by **fast retransmit** (RFC 5681 — three dup-acks confirmed the gap lost), or (c) past its **RTO**
    /// (RFC 6298 — the estimated round trip has elapsed since its last send). Selectively-acked sequences
    /// are skipped (selective repeat). This replaces the old "resend the whole window every tick" policy,
    /// which spuriously retransmitted in-flight data and, under a constant-rate shaper, crowded genuine
    /// cover traffic out of the cell budget (audit F4-RTO); the freed budget is now filled by padding.
    /// The final segment carries `fin` once the stream is finished.
    #[must_use]
    pub fn outbound(&mut self) -> Vec<Segment> {
        self.clock = self.clock.saturating_add(1);
        let total = self.total();
        let last = total.saturating_sub(1);
        let win = self.window.min(self.peer_rwnd.max(1)); // at least 1: a zero-window probe
        let end = (self.acked + win).min(total);
        // A timeout backs the RTO off once per sweep (not once per timed-out segment).
        let mut backed_off = false;
        let mut out = Vec::new();
        for seq in self.acked..end {
            if self.sacked.contains(&seq) {
                continue;
            }
            // `seq >= acked >= base`, so the index into the in-flight deque is non-negative and in range.
            let Some(idx) = seq.checked_sub(self.base) else {
                continue;
            };
            // A segment is due iff it has never been scheduled (first send) or its scheduled (jittered)
            // retransmit tick has arrived. Fast retransmit and the RTO both act only by writing `due_at`,
            // so every resend — whichever triggered it — is spaced by the same anti-resonance jitter.
            let scheduled = self.due_at.get(&seq).copied();
            let due = match scheduled {
                None => true,
                Some(at) => self.clock >= at,
            };
            if !due {
                continue;
            }
            if scheduled.is_some() {
                // A retransmission: bump the attempt count (also Karn-excludes the seq from RTT sampling)
                // and back the RTO off once per sweep.
                *self.retransmitted.entry(seq).or_insert(0) += 1;
                if !backed_off {
                    self.rtt.back_off();
                    backed_off = true;
                }
            }
            // Schedule the next eligible resend: RTO + a golden-ratio jitter over the retransmit count,
            // so a stuck segment's resends cannot phase-lock with a periodic loss pattern.
            let attempt = self.retransmitted.get(&seq).copied().unwrap_or(0);
            let interval = self
                .rtt
                .rto
                .saturating_add(jitter_ticks(seq, attempt, self.rtt.rto));
            self.last_sent.insert(seq, self.clock);
            self.due_at.insert(seq, self.clock.saturating_add(interval));
            if let Some(data) = self.segments.get(idx as usize) {
                out.push(Segment {
                    stream_id: self.stream_id,
                    seq,
                    fin: self.finished && seq == last,
                    data: data.clone(),
                });
            }
        }
        out
    }

    /// Apply a selective ack: adopt the receiver's advertised credit, advance the cumulative point,
    /// record the individually-acked sequences from the SACK bitmap (not retransmitted), update the RTT
    /// estimate off an unambiguous newly-acked segment, and count duplicate acks for fast retransmit.
    pub fn on_ack(&mut self, ack: Ack) {
        self.peer_rwnd = ack.rwnd;
        let total = self.total();
        let prev_acked = self.acked;

        // Fast-retransmit trigger (RFC 5681 §3.2): an ack that repeats the cumulative point while
        // reporting fresh out-of-order data (`sack != 0`) is a duplicate. `DUP_ACK_THRESHOLD` of them
        // mean the gap segment — the one *at* the cumulative point — was lost. Reschedule it to resend
        // within a short golden-ratio-jittered delay: prompt, but deliberately *not* in lock-step with
        // this ack's arrival tick, which would re-create the mode-lock on the fast path. An ack that
        // advances the cumulative point instead resets the counter.
        if ack.cumulative == self.last_cumulative && ack.sack != 0 && ack.cumulative < total {
            self.dup_acks = self.dup_acks.saturating_add(1);
            if self.dup_acks >= DUP_ACK_THRESHOLD {
                let seq = ack.cumulative;
                let attempt = self.retransmitted.get(&seq).copied().unwrap_or(0);
                let target = self
                    .clock
                    .saturating_add(jitter_ticks(seq, attempt, FAST_RETX_JITTER_SPAN));
                // Only ever pull the resend *earlier* — never push it later. A segment that has not yet
                // fired keeps `attempt == 0`, so its jitter is a fixed value; without the `min`, each new
                // dup-ack burst would reset the schedule to `clock + that_fixed_delay` before `clock`
                // could ever reach it, starving the resend forever.
                self.due_at
                    .entry(seq)
                    .and_modify(|d| *d = (*d).min(target))
                    .or_insert(target);
                self.dup_acks = 0;
            }
        } else if ack.cumulative > self.last_cumulative {
            self.last_cumulative = ack.cumulative;
            self.dup_acks = 0;
        }

        self.acked = self.acked.max(ack.cumulative).min(total);
        for i in 1..SACK_WIDTH {
            if ack.sack & (1u64 << i) != 0 {
                let seq = ack.cumulative.saturating_add(i);
                // Only record a selective ack for a sequence that actually exists; a crafted ack with a
                // far-future `cumulative` must not seed the `sacked` set with unbounded phantom
                // sequences (audit F4).
                if seq < total {
                    self.sacked.insert(seq);
                }
            }
        }
        // A gap may now be filled by contiguous sacked sequences — advance the cumulative point.
        while self.sacked.remove(&self.acked) {
            self.acked = self.acked.saturating_add(1);
        }
        // Drop stale selective acks below the cumulative point.
        self.sacked = self.sacked.split_off(&self.acked);

        // RTT sample (RFC 6298 §4 / Karn's algorithm): among the sequences this ack newly acknowledged
        // — `[prev_acked, acked)` — take the highest that was sent exactly once (not retransmitted), so
        // the round trip is unambiguously attributable. Ranging over the `sent_at` map (not the seq
        // interval) bounds the scan by the in-flight window, so even a hostile far-future cumulative
        // cannot turn this into a long loop.
        if self.acked > prev_acked {
            let sample = self
                .last_sent
                .range(prev_acked..self.acked)
                .rev()
                .find(|&(seq, _)| !self.retransmitted.contains_key(seq))
                .map(|(_, &sent)| self.clock.wrapping_sub(sent));
            if let Some(m) = sample {
                self.rtt.sample(m);
            }
        }

        // Reclaim every segment now fully acknowledged (below the cumulative point): it is never
        // retransmitted, so it need not be held — the in-flight buffer stays bounded by the window,
        // independent of the total transfer size (audit F3).
        while self.base < self.acked && self.segments.pop_front().is_some() {
            self.base = self.base.saturating_add(1);
        }
        // Prune the timing state below the cumulative point in lock-step, so it stays bounded by the
        // window rather than growing with the transfer.
        self.last_sent = self.last_sent.split_off(&self.acked);
        self.due_at = self.due_at.split_off(&self.acked);
        self.retransmitted = self.retransmitted.split_off(&self.acked);
    }

    /// Whether the stream is finished and every segment has been acknowledged.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.finished && self.acked >= self.total()
    }
}

/// The receiver half: buffers in-window out-of-order segments, releases the in-order prefix on
/// [`take`](Self::take), and advertises its remaining credit for backpressure.
#[derive(Clone, Debug)]
pub struct StreamReceiver {
    stream_id: u32,
    /// Segments held but not yet taken (both the contiguous run awaiting `take` and out-of-order holds).
    received: BTreeMap<u32, Vec<u8>>,
    /// The next in-order sequence needed (the contiguous frontier).
    next: u32,
    /// The next sequence not yet handed to the application via `take` (`delivered ≤ next`).
    delivered: u32,
    fin_seq: Option<u32>,
    /// Max segments buffered beyond `next` (bounds memory; advertised as `rwnd` credit).
    recv_window: u32,
}

impl StreamReceiver {
    /// A receiver for `stream_id`.
    #[must_use]
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            received: BTreeMap::new(),
            next: 0,
            delivered: 0,
            fin_seq: None,
            recv_window: DEFAULT_WINDOW,
        }
    }

    /// Set the receive-window size (clamped to `1..=SACK_WIDTH`) — the buffer/credit bound.
    #[must_use]
    pub fn with_recv_window(mut self, window: u32) -> Self {
        self.recv_window = window.clamp(1, SACK_WIDTH);
        self
    }

    /// Ingest a segment (ignoring foreign stream ids and out-of-window/already-taken sequences).
    /// Returns the **selective** ack to send back: the next in-order sequence needed, a bitmap of the
    /// out-of-order segments already held, and the remaining buffer credit.
    pub fn on_segment(&mut self, segment: &Segment) -> Ack {
        if segment.stream_id != self.stream_id {
            return self.ack();
        }
        // Admit only sequences in `[delivered, delivered + recv_window)` — anchored on the *delivered*
        // frontier (what the application has drained), NOT on `next` (what has merely arrived). This is
        // the load-bearing bound: the buffer then holds at most `recv_window` segments no matter how
        // the sequences arrive, so a peer that floods past its advertised credit has the excess
        // *dropped*, not buffered — flow control is enforced, not merely advisory, and the receiver
        // cannot be driven out of memory (audit C3/F1). A slow reader (delivered lagging) shrinks the
        // admissible window, throttling the sender.
        let in_window = segment.seq >= self.delivered
            && segment.seq < self.delivered.saturating_add(self.recv_window);
        if in_window {
            // A FIN declares its `seq` the *final* segment of the stream. Reject anything that would
            // contradict a declared end, so a peer cannot truncate the stream (which would make
            // `deliver()` stop early while `take()` keeps draining — the two disagreeing on the payload):
            //   (a) a segment strictly beyond an already-established FIN is past the end — drop it;
            //   (b) a FIN whose seq sits below a segment we already hold contradicts accepted data —
            //       drop it (its own data included; a compliant sender never sets FIN before its tail).
            // A well-behaved sender — FIN only on its true last segment, nothing after — always passes.
            let beyond_declared_end = self.fin_seq.is_some_and(|fin| segment.seq > fin);
            let fin_contradicts_held = segment.fin
                && self
                    .received
                    .keys()
                    .next_back()
                    .is_some_and(|&hi| hi > segment.seq);
            if beyond_declared_end || fin_contradicts_held {
                return self.ack();
            }
            if segment.fin {
                self.fin_seq = Some(segment.seq);
            }
            self.received
                .entry(segment.seq)
                .or_insert_with(|| segment.data.clone());
            while self.received.contains_key(&self.next) {
                self.next = self.next.saturating_add(1);
            }
        }
        self.ack()
    }

    /// The current selective ack: cumulative next-needed sequence, out-of-order bitmap, and remaining
    /// credit `rwnd = recv_window − held`.
    #[must_use]
    pub fn ack(&self) -> Ack {
        let mut sack = 0u64;
        for i in 1..SACK_WIDTH {
            // saturating: near u32::MAX (a ~4 TB stream) the add must not wrap/panic; such a key can
            // never be present anyway, so saturating to u32::MAX simply reads as "not held".
            if self.received.contains_key(&self.next.saturating_add(i)) {
                sack |= 1u64 << i;
            }
        }
        let held = self.received.len() as u32;
        Ack {
            cumulative: self.next,
            sack,
            rwnd: self.recv_window.saturating_sub(held),
        }
    }

    /// Release the contiguous in-order bytes delivered since the last call, draining them from the
    /// buffer (freeing credit). Returns an empty vector if nothing new is in order. This is the
    /// socket read; use [`deliver`](Self::deliver) instead for whole-message reassembly (do not mix).
    pub fn take(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while self.delivered < self.next {
            if let Some(seg) = self.received.remove(&self.delivered) {
                out.extend_from_slice(&seg);
            }
            self.delivered = self.delivered.saturating_add(1);
        }
        out
    }

    /// The whole reassembled payload, once the FIN segment and every segment before it have arrived.
    /// For whole-message use; do not mix with [`take`](Self::take) (which drains the buffer).
    #[must_use]
    pub fn deliver(&self) -> Option<Vec<u8>> {
        let fin = self.fin_seq?;
        if self.next <= fin {
            return None; // still missing a segment
        }
        let mut payload = Vec::new();
        for seq in 0..=fin {
            payload.extend_from_slice(self.received.get(&seq)?);
        }
        Some(payload)
    }

    /// Whether the stream is fully received (FIN and every prior segment in order).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.fin_seq.is_some_and(|fin| self.next > fin)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // ---- RTT/RTO estimator + retransmit scheduling (audit F4-RTO) ----

    #[test]
    fn an_in_flight_segment_is_not_resent_before_its_rto() {
        // The core efficiency property: once a segment is sent, repeated `outbound` sweeps do NOT resend
        // it until its RTO elapses — the old "resend the whole window every tick" behaviour is gone.
        let payload: Vec<u8> = (0..4 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut tx = StreamSender::new(0, &payload).with_window(8);
        let first = tx.outbound();
        assert!(!first.is_empty(), "first sweep sends the window");
        let sent_seqs: BTreeSet<u32> = first.iter().map(|s| s.seq).collect();
        // Immediately-following sweeps, with no ack, send nothing until the RTO (init = 3 ticks) passes:
        // the earliest possible resend is clock(1) + RTO(3) + jitter(≥0) = tick 4, so ticks 2 and 3 are
        // silent. This is the efficiency property — no blind whole-window resend every tick.
        assert!(tx.outbound().is_empty(), "tick 2: nothing due yet");
        assert!(tx.outbound().is_empty(), "tick 3: nothing due yet");
        // Across the following sweeps every unacked segment is retransmitted exactly once — but NOT all
        // in the same sweep: the golden-ratio jitter deliberately de-synchronises them across ticks so a
        // loss burst cannot align with the whole window at once (anti-resonance). Collect the set.
        let mut resent = BTreeSet::new();
        for _ in 0..RTO_MAX_TICKS {
            for seg in tx.outbound() {
                resent.insert(seg.seq);
            }
            if resent == sent_seqs {
                break;
            }
        }
        assert_eq!(
            resent, sent_seqs,
            "after the RTO the whole unacked window is eventually retransmitted (jitter-spread, not before tick 4)"
        );
    }

    #[test]
    fn the_rtt_estimator_converges_to_a_stable_rto() {
        // Feed a constant 10-tick round trip; SRTT → 10, and RTTVAR decays to the integer granularity
        // floor (RTTVAR ≈ 0.75, i.e. rttvar_x4 = 3, since 3 >> 2 = 0 — the standard scaled-integer RFC
        // 6298 artifact), so RTO → SRTT + 3 = 13. The point: it converges just above the true RTT — never
        // to zero, never runaway.
        let mut est = RttEstimator::new();
        for _ in 0..50 {
            est.sample(10);
        }
        assert!(
            (11..=14).contains(&est.rto),
            "RTO converges just above the true RTT, got {}",
            est.rto
        );
        // A single large spike widens RTTVAR and thus the RTO (the 4·RTTVAR safety margin), then decays.
        est.sample(40);
        assert!(est.rto > 14, "a latency spike widens the RTO, got {}", est.rto);
    }

    #[test]
    fn back_off_is_bounded_by_a_multiple_of_the_base_rto() {
        let mut est = RttEstimator::new();
        for _ in 0..20 {
            est.sample(10); // base RTO ≈ 10
        }
        let base = est.rto;
        for _ in 0..20 {
            est.back_off(); // repeated timeouts
        }
        assert!(
            est.rto <= base * RTO_BACKOFF_MULT + 1,
            "back-off is capped at MULT·base ({}·{}), got {}",
            RTO_BACKOFF_MULT,
            base,
            est.rto
        );
        // A fresh measurement clears the back-off back to the base.
        est.sample(10);
        assert!(est.rto <= base + 1, "a new sample resets the back-off");
    }

    #[test]
    fn fast_retransmit_resends_the_gap_without_waiting_for_the_rto() {
        // Three dup-acks (same cumulative, fresh SACK data) resend the gap segment within the short
        // fast-retransmit window — well before the RTO would fire.
        let payload: Vec<u8> = (0..6 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut tx = StreamSender::new(7, &payload).with_window(8);
        let _ = tx.outbound(); // send the window; seq 0 is the "lost" gap
        // Three acks that keep cumulative = 0 but SACK seqs 1,2,3 (bits 1..=3) — classic dup-acks.
        for _ in 0..3 {
            tx.on_ack(Ack {
                cumulative: 0,
                sack: 0b1110,
                rwnd: 64,
            });
        }
        // Within FAST_RETX_JITTER_SPAN sweeps the gap (seq 0) is resent, ahead of the RTO.
        let mut gap_resent = false;
        for _ in 0..=FAST_RETX_JITTER_SPAN {
            if tx.outbound().iter().any(|s| s.seq == 0) {
                gap_resent = true;
                break;
            }
        }
        assert!(gap_resent, "fast retransmit resends the SACKed gap promptly");
    }

    #[test]
    fn the_golden_ratio_jitter_is_equidistributed_and_in_range() {
        // Weyl-sequence property: frac(seq·√2 + attempt·φ), scaled into [0, span), spreads roughly
        // uniformly across the range as `attempt` advances — this is what defeats phase-locking. Check
        // both the bound and that every bucket of a modest range is hit (no clustering).
        let span = 16u32;
        let mut buckets = [0u32; 16];
        for attempt in 0..2000u32 {
            let j = jitter_ticks(12345, attempt, span);
            assert!(j < span, "jitter {j} out of range for span {span}");
            buckets[j as usize] += 1;
        }
        assert!(
            buckets.iter().all(|&c| c > 0),
            "every jitter bucket is visited (equidistribution), got {buckets:?}"
        );
        // A zero span never divides by zero and yields zero delay.
        assert_eq!(jitter_ticks(1, 1, 0), 0);
    }

    #[test]
    fn timing_state_stays_bounded_by_the_window_over_a_long_transfer() {
        // Reliability-under-loss over a large transfer must not let the per-seq timing maps grow with the
        // stream: they are pruned below the cumulative ack in lock-step with segment reclaim (audit F3).
        let payload: Vec<u8> = (0..200 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut tx = StreamSender::new(0, &payload).with_window(16);
        let mut rx = StreamReceiver::new(0).with_recv_window(16);
        let mut ack = rx.ack();
        let mut guard = 0;
        while !tx.is_complete() {
            tx.on_ack(ack);
            for seg in tx.outbound() {
                ack = rx.on_segment(&seg);
            }
            let _ = rx.take();
            assert!(
                tx.last_sent.len() <= SACK_WIDTH as usize
                    && tx.due_at.len() <= SACK_WIDTH as usize
                    && tx.retransmitted.len() <= SACK_WIDTH as usize,
                "timing maps stay window-bounded, not transfer-bounded"
            );
            guard += 1;
            assert!(guard < 10_000, "should converge");
        }
    }

    #[test]
    fn segment_bytes_round_trip() {
        let seg = Segment {
            stream_id: 7,
            seq: 3,
            fin: true,
            data: b"hello".to_vec(),
        };
        assert_eq!(Segment::decode(&seg.encode()), Some(seg));
    }

    #[test]
    fn a_small_payload_is_one_fin_segment_and_reassembles() {
        let mut sender = StreamSender::new(1, b"short");
        let mut receiver = StreamReceiver::new(1);
        // Capture the one sweep's segments; `outbound` is now stateful (it ticks the retransmit clock and
        // will not re-emit an in-flight segment until its RTO), so a second call would return nothing.
        let segs = sender.outbound();
        for seg in &segs {
            receiver.on_segment(seg);
        }
        assert_eq!(receiver.deliver().as_deref(), Some(&b"short"[..]));
        sender.on_ack(receiver.on_segment(&segs[0]));
        assert!(sender.is_complete());
    }

    #[test]
    fn selective_repeat_resends_only_the_lost_segment() {
        let payload: Vec<u8> = (0..10 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut sender = StreamSender::new(3, &payload).with_window(64);
        let mut receiver = StreamReceiver::new(3).with_recv_window(64);

        let mut last_ack = receiver.ack();
        for seg in sender.outbound() {
            if seg.seq == 2 {
                continue; // drop seq 2
            }
            last_ack = receiver.on_segment(&seg);
        }
        sender.on_ack(last_ack);

        assert_eq!(last_ack.cumulative, 2);
        // With only a single ack there is no dup-ack burst, so recovery is by RTO: after the timeout the
        // lost gap resends — and when it does, ONLY the gap (seq 2) goes out (3.. are selectively acked,
        // everything else is still in flight and not yet timed out). This is the point of the change:
        // the whole window is no longer blindly re-emitted each tick.
        let mut resend = Vec::new();
        for _ in 0..RTO_MAX_TICKS {
            resend = sender.outbound();
            if !resend.is_empty() {
                break;
            }
        }
        assert_eq!(resend.len(), 1, "only the lost segment is retransmitted");
        assert_eq!(resend[0].seq, 2);

        sender.on_ack(receiver.on_segment(&resend[0]));
        assert!(sender.is_complete());
        assert_eq!(receiver.deliver(), Some(payload));
    }

    #[test]
    fn the_send_window_bounds_in_flight_segments() {
        let payload: Vec<u8> = (0..100 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut sender = StreamSender::new(4, &payload).with_window(8);
        assert_eq!(
            sender.outbound().len(),
            8,
            "no more than `window` segments are in flight at once"
        );
    }

    #[test]
    fn a_large_payload_reassembles_in_order() {
        let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let mut sender = StreamSender::new(9, &payload);
        // One stateful sweep; assert its size and reuse it (a second sweep would re-emit nothing yet).
        let mut segs = sender.outbound();
        assert!(segs.len() >= 5, "5000 bytes spans several segments");
        let mut receiver = StreamReceiver::new(9);
        segs.reverse();
        for seg in &segs {
            receiver.on_segment(seg);
        }
        assert_eq!(receiver.deliver(), Some(payload));
    }

    #[test]
    fn reliable_under_loss_via_retransmission() {
        let payload: Vec<u8> = (0..8000u32).map(|i| (i * 7) as u8).collect();
        let mut sender = StreamSender::new(2, &payload);
        let mut receiver = StreamReceiver::new(2);

        let mut pass = 0u32;
        while !sender.is_complete() {
            let mut ack = receiver.ack();
            for (k, seg) in sender.outbound().iter().enumerate() {
                if pass == 0 && k % 3 == 1 {
                    continue;
                }
                ack = receiver.on_segment(seg);
            }
            sender.on_ack(ack);
            pass += 1;
            assert!(pass < 10, "should converge quickly");
        }
        assert_eq!(receiver.deliver(), Some(payload));
    }

    // ---- incremental socket behaviour ----

    #[test]
    fn incremental_push_and_take_streams_bytes() {
        // A socket: push bytes as produced, close, and read the in-order prefix incrementally.
        let mut sender = StreamSender::open(5);
        sender.push(b"hello ");
        sender.flush(); // seal "hello " as a (non-fin) segment so it goes out now
        sender.push(b"world");
        sender.finish(); // seals "world" as the fin segment

        let mut receiver = StreamReceiver::new(5);
        let mut got = Vec::new();
        // deliver out of order to exercise reassembly, then take the contiguous prefix.
        let mut segs = sender.outbound();
        segs.reverse();
        for seg in &segs {
            receiver.on_segment(seg);
            got.extend_from_slice(&receiver.take());
        }
        got.extend_from_slice(&receiver.take());
        assert_eq!(got, b"hello world");
        assert!(receiver.is_finished());
    }

    #[test]
    fn a_finish_without_data_still_delivers_a_fin() {
        // finish() on an empty stream produces one empty FIN segment.
        let mut sender = StreamSender::new(6, b"");
        let mut receiver = StreamReceiver::new(6);
        for seg in sender.outbound() {
            receiver.on_segment(&seg);
        }
        assert!(receiver.is_finished());
        assert_eq!(receiver.deliver(), Some(Vec::new()));
    }

    #[test]
    fn receiver_advertises_shrinking_then_recovering_credit() {
        // With a small window, out-of-order holds consume credit; taking the in-order prefix frees it.
        let payload: Vec<u8> = (0..3 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut sender = StreamSender::new(7, &payload); // 4 segments (3 data + empty fin)
        let mut receiver = StreamReceiver::new(7).with_recv_window(4);

        // Deliver seq 1,2 (out of order) — held, credit drops; seq 0 still missing.
        let segs = sender.outbound();
        receiver.on_segment(&segs[1]);
        let a = receiver.on_segment(&segs[2]);
        assert_eq!(a.cumulative, 0, "still waiting on seq 0");
        assert_eq!(
            a.rwnd, 2,
            "two of four credits consumed by out-of-order holds"
        );

        // Fill the gap: everything becomes in order; take() drains and frees credit.
        receiver.on_segment(&segs[0]);
        let drained = receiver.take();
        assert!(!drained.is_empty());
        assert_eq!(receiver.ack().rwnd, 4, "credit fully recovered after take");
    }

    #[test]
    fn out_of_window_segments_are_dropped() {
        // A segment beyond the advertised window is not buffered (memory-exhaustion guard).
        let mut receiver = StreamReceiver::new(8).with_recv_window(4);
        let far = Segment {
            stream_id: 8,
            seq: 100,
            fin: false,
            data: b"x".to_vec(),
        };
        let a = receiver.on_segment(&far);
        assert_eq!(a.cumulative, 0);
        assert_eq!(a.rwnd, 4, "far-future segment was dropped, not buffered");
    }

    #[test]
    fn backpressure_caps_the_effective_window() {
        // The sender never sends beyond the receiver's advertised credit.
        let payload: Vec<u8> = (0..50 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut sender = StreamSender::new(9, &payload).with_window(64);
        // Receiver advertises only 3 credits.
        sender.on_ack(Ack {
            cumulative: 0,
            sack: 0,
            rwnd: 3,
        });
        assert_eq!(
            sender.outbound().len(),
            3,
            "effective window = min(window, peer_rwnd)"
        );
    }

    #[test]
    fn the_receive_buffer_is_bounded_by_recv_window_under_a_flood() {
        // A peer that ignores its advertised credit and floods far past the window has the excess
        // *dropped*, not buffered: the buffer holds at most recv_window segments (audit C3/F1).
        let mut rx = StreamReceiver::new(0).with_recv_window(4);
        for seq in 0..20u32 {
            rx.on_segment(&Segment {
                stream_id: 0,
                seq,
                fin: false,
                data: alloc::vec![seq as u8],
            });
        }
        assert!(
            rx.received.len() <= 4,
            "the receive buffer never exceeds recv_window, whatever the sender floods"
        );
        // The admitted in-order prefix delivers; everything past the window was dropped.
        assert_eq!(rx.take(), alloc::vec![0, 1, 2, 3]);
        // Draining slides the window forward — the next block is now admissible.
        for seq in 4..8u32 {
            rx.on_segment(&Segment {
                stream_id: 0,
                seq,
                fin: false,
                data: alloc::vec![seq as u8],
            });
        }
        assert_eq!(rx.take(), alloc::vec![4, 5, 6, 7]);
    }

    #[test]
    fn a_peer_cannot_truncate_the_stream_with_an_early_fin() {
        // Deliver 0..4 without FIN, then a malicious early FIN on seq 2 (below the held frontier) must
        // NOT finish/truncate the stream — otherwise deliver() would stop at 2 while take() drains more.
        let mut rx = StreamReceiver::new(0);
        for seq in 0..4u32 {
            rx.on_segment(&Segment {
                stream_id: 0,
                seq,
                fin: false,
                data: alloc::vec![seq as u8],
            });
        }
        rx.on_segment(&Segment {
            stream_id: 0,
            seq: 2,
            fin: true,
            data: alloc::vec![2],
        });
        assert!(!rx.is_finished(), "an early FIN under held data cannot finish the stream");

        // The legitimate final segment (4, with FIN) finishes it.
        rx.on_segment(&Segment {
            stream_id: 0,
            seq: 4,
            fin: true,
            data: alloc::vec![4],
        });
        assert!(rx.is_finished(), "the true tail FIN finishes the stream");

        // A straggler past the declared end is refused, so it cannot be injected after the FIN.
        rx.on_segment(&Segment {
            stream_id: 0,
            seq: 5,
            fin: false,
            data: alloc::vec![5],
        });
        assert_eq!(
            rx.take(),
            alloc::vec![0, 1, 2, 3, 4],
            "the full payload with no truncation and no past-end injection"
        );
        // deliver() (whole-message mode) agrees with take() on the same payload boundary.
        let mut rx2 = StreamReceiver::new(0);
        for seq in 0..4u32 {
            rx2.on_segment(&Segment {
                stream_id: 0,
                seq,
                fin: false,
                data: alloc::vec![seq as u8],
            });
        }
        rx2.on_segment(&Segment {
            stream_id: 0,
            seq: 2,
            fin: true,
            data: alloc::vec![2],
        });
        rx2.on_segment(&Segment {
            stream_id: 0,
            seq: 4,
            fin: true,
            data: alloc::vec![4],
        });
        assert_eq!(
            rx2.deliver(),
            Some(alloc::vec![0, 1, 2, 3, 4]),
            "deliver() sees the same untruncated payload as take()"
        );
    }

    #[test]
    fn the_receive_window_edge_is_exact() {
        let mut rx = StreamReceiver::new(0).with_recv_window(4);
        let seg = |seq| Segment {
            stream_id: 0,
            seq,
            fin: false,
            data: alloc::vec![seq as u8],
        };
        // next = 0, window = 4 ⇒ acceptable seqs are [0, 4). seq == next + recv_window (4) is dropped.
        rx.on_segment(&seg(4));
        assert_eq!(rx.ack().sack, 0, "a seq exactly at next+recv_window is dropped");
        // seq == next + recv_window - 1 (3) is the last accepted slot.
        rx.on_segment(&seg(3));
        assert_ne!(rx.ack().sack & (1u64 << 3), 0, "next+recv_window-1 is accepted");
    }

    #[test]
    fn the_sack_bitmap_marks_the_top_window_slot() {
        let mut rx = StreamReceiver::new(0).with_recv_window(SACK_WIDTH);
        // The highest representable out-of-order slot is next + (SACK_WIDTH - 1) = 63.
        rx.on_segment(&Segment {
            stream_id: 0,
            seq: SACK_WIDTH - 1,
            fin: false,
            data: alloc::vec![9],
        });
        assert_ne!(
            rx.ack().sack & (1u64 << (SACK_WIDTH - 1)),
            0,
            "the top SACK slot is representable without overflow"
        );
    }

    #[test]
    fn a_zero_receive_window_still_sends_a_one_segment_probe() {
        let payload: Vec<u8> = (0..3 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut tx = StreamSender::new(0, &payload); // several segments
        tx.on_ack(Ack {
            cumulative: 0,
            sack: 0,
            rwnd: 0,
        });
        // A zero window would otherwise deadlock the stream; the max(1) floor keeps one probe in flight.
        assert_eq!(
            tx.outbound().len(),
            1,
            "zero credit still emits exactly one probe segment"
        );
    }

    #[test]
    fn the_sender_reclaims_acked_segments() {
        // A 50-segment transfer: once a prefix is cumulatively acked, those segments are dropped from
        // the in-flight buffer, so memory tracks the window, not the whole transfer (audit F3).
        let payload = alloc::vec![0u8; 50 * MAX_SEGMENT];
        let mut tx = StreamSender::new(0, &payload); // 50 data + 1 FIN
        let total = tx.total();
        assert_eq!(tx.segments.len() as u32, total, "all segments buffered before any ack");

        tx.on_ack(Ack {
            cumulative: 40,
            sack: 0,
            rwnd: 64,
        });
        assert_eq!(tx.base, 40, "reclaimed the 40 acked segments");
        assert_eq!(tx.segments.len() as u32, total - 40, "the in-flight buffer shrank");
        // Retransmission still addresses the right sequences after reclaim.
        assert!(
            tx.outbound().iter().all(|s| s.seq >= 40),
            "outbound resumes from the cumulative point over the reclaimed deque"
        );

        // Fully ack: complete, and every segment reclaimed.
        tx.on_ack(Ack {
            cumulative: total,
            sack: 0,
            rwnd: 64,
        });
        assert!(tx.is_complete());
        assert!(tx.segments.is_empty(), "no segment is retained once fully acknowledged");
        assert!(tx.outbound().is_empty());
    }

    #[test]
    fn on_ack_is_robust_to_stale_and_hostile_cumulative() {
        let payload = alloc::vec![7u8; 2 * MAX_SEGMENT]; // segments 0,1 (+ empty FIN 2) ⇒ len 3
        let mut tx = StreamSender::new(0, &payload);
        tx.on_ack(Ack {
            cumulative: 1,
            sack: 0,
            rwnd: 64,
        });
        // A stale, lower cumulative must not rewind the acknowledged frontier.
        tx.on_ack(Ack {
            cumulative: 0,
            sack: 0,
            rwnd: 64,
        });
        assert!(
            tx.outbound().iter().all(|s| s.seq >= 1),
            "a stale lower cumulative does not resurrect already-acked segments"
        );
        // A cumulative past the end clamps to len — no overflow, no acked beyond the segment count.
        tx.on_ack(Ack {
            cumulative: u32::MAX,
            sack: 0,
            rwnd: 64,
        });
        assert!(tx.is_complete(), "an over-large cumulative clamps to len and completes");
        assert!(tx.outbound().is_empty(), "nothing remains to send once complete");
    }

    #[test]
    fn a_replay_cannot_alter_already_delivered_or_buffered_bytes() {
        let mut rx = StreamReceiver::new(0);
        let seg = |seq, byte| Segment {
            stream_id: 0,
            seq,
            fin: false,
            data: alloc::vec![byte],
        };
        rx.on_segment(&seg(0, b'A'));
        assert_eq!(rx.take(), b"A"); // delivered advances past 0
        // A replay of an already-taken sequence is out of window ⇒ dropped, surfacing nothing.
        rx.on_segment(&seg(0, b'Z'));
        assert!(rx.take().is_empty(), "a replay below the delivered frontier yields nothing");
        // The first bytes seen at a held seq win; a replay with altered payload cannot overwrite them.
        rx.on_segment(&seg(2, b'C'));
        rx.on_segment(&seg(2, b'X')); // replay, mangled
        rx.on_segment(&seg(1, b'B')); // fills the gap
        assert_eq!(rx.take(), b"BC", "a replay cannot corrupt buffered out-of-order bytes");
    }

    #[test]
    fn segment_decode_length_boundary() {
        // One byte short of the 9-byte header ⇒ rejected.
        assert!(Segment::decode(&[0u8; 8]).is_none());
        // Exactly the 9-byte header ⇒ a segment with empty data (the len-0 / FIN-only case).
        assert_eq!(
            Segment::decode(&[0, 0, 0, 1, 0, 0, 0, 2, 1]),
            Some(Segment {
                stream_id: 1,
                seq: 2,
                fin: true,
                data: alloc::vec![],
            })
        );
    }
}
