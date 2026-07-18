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

    /// The segments to (re)send now — call on open/push and on each retransmit tick. Only the
    /// **missing** segments within the effective window `[acked, acked + min(window, peer_rwnd))` are
    /// emitted: any sequence already selectively acked is skipped (selective repeat), and the final
    /// segment carries `fin` once the stream is finished.
    #[must_use]
    pub fn outbound(&self) -> Vec<Segment> {
        let total = self.total();
        let last = total.saturating_sub(1);
        let win = self.window.min(self.peer_rwnd.max(1)); // at least 1: a zero-window probe
        let end = (self.acked + win).min(total);
        (self.acked..end)
            .filter(|seq| !self.sacked.contains(seq))
            .filter_map(|seq| {
                // `seq >= acked >= base`, so the index into the in-flight deque is non-negative.
                let idx = seq.checked_sub(self.base)? as usize;
                self.segments.get(idx).map(|data| Segment {
                    stream_id: self.stream_id,
                    seq,
                    fin: self.finished && seq == last,
                    data: data.clone(),
                })
            })
            .collect()
    }

    /// Apply a selective ack: adopt the receiver's advertised credit, advance the cumulative point,
    /// and record the individually-acked sequences from the SACK bitmap so they are not retransmitted.
    pub fn on_ack(&mut self, ack: Ack) {
        self.peer_rwnd = ack.rwnd;
        let total = self.total();
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
            self.acked += 1;
        }
        // Drop stale selective acks below the cumulative point.
        self.sacked = self.sacked.split_off(&self.acked);
        // Reclaim every segment now fully acknowledged (below the cumulative point): it is never
        // retransmitted, so it need not be held — the in-flight buffer stays bounded by the window,
        // independent of the total transfer size (audit F3).
        while self.base < self.acked && self.segments.pop_front().is_some() {
            self.base += 1;
        }
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
                self.next += 1;
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
            self.delivered += 1;
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
        for seg in sender.outbound() {
            receiver.on_segment(&seg);
        }
        assert_eq!(receiver.deliver().as_deref(), Some(&b"short"[..]));
        sender.on_ack(receiver.on_segment(&sender.outbound()[0]));
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
        let resend = sender.outbound();
        assert_eq!(resend.len(), 1, "only the lost segment is retransmitted");
        assert_eq!(resend[0].seq, 2);

        sender.on_ack(receiver.on_segment(&resend[0]));
        assert!(sender.is_complete());
        assert_eq!(receiver.deliver(), Some(payload));
    }

    #[test]
    fn the_send_window_bounds_in_flight_segments() {
        let payload: Vec<u8> = (0..100 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let sender = StreamSender::new(4, &payload).with_window(8);
        assert_eq!(
            sender.outbound().len(),
            8,
            "no more than `window` segments are in flight at once"
        );
    }

    #[test]
    fn a_large_payload_reassembles_in_order() {
        let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let sender = StreamSender::new(9, &payload);
        assert!(
            sender.outbound().len() >= 5,
            "5000 bytes spans several segments"
        );
        let mut receiver = StreamReceiver::new(9);
        let mut segs = sender.outbound();
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
        let sender = StreamSender::new(6, b"");
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
        let sender = StreamSender::new(7, &payload); // 4 segments (3 data + empty fin)
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
