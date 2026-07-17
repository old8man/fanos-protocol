//! Reliable, ordered, multiplexed streams over the overlay (spec §7.2 `Stream*`).
//!
//! The overlay delivers single, possibly-dropped datagrams; an application often wants a reliable
//! ordered byte-stream. This module is the sans-I/O protocol logic for one: a payload is cut into
//! [`Segment`]s (`STREAM_DATA`), the receiver buffers out-of-order arrivals and delivers them in
//! order. Acknowledgement is **selective (SACK)**: the receiver returns the cumulative next-needed
//! sequence *and* a bitmap of the out-of-order segments it already holds, so the sender does
//! **selective repeat** — it retransmits only the genuinely missing segments, never the ones already
//! received past a gap (unlike Go-Back-N, which re-sends everything past the cumulative ack). Sends
//! are bounded by a **sliding window** for flow control. It is a pure state machine — a driver
//! performs the sends and the retransmit timer — so it composes with either transport (over QUIC,
//! native streams subsume it; over the lossy simulator or UDP, this provides the reliability).
//!
//! Multiplexing is by `stream_id`: many independent streams share one peer link, each with its own
//! sender/receiver state.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// Maximum payload bytes per segment (keeps a segment within a typical datagram).
pub const MAX_SEGMENT: usize = 1024;

/// The SACK bitmap width: the receiver reports out-of-order receipt of the 64 sequences immediately
/// following the cumulative ack. The send window is capped to this so every in-flight segment's
/// state is representable in one ack.
pub const SACK_WIDTH: u32 = 64;

/// The default sliding-window size (max in-flight / lookahead segments). Bounded by [`SACK_WIDTH`].
pub const DEFAULT_WINDOW: u32 = 32;

/// A selective acknowledgement: `cumulative` is the next sequence the receiver still needs (all
/// below it are in order), and `sack` is a bitmap where bit `i` set means sequence `cumulative + i`
/// has already been received out of order (bit `0` is always clear — `cumulative` is the gap).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ack {
    /// The next in-order sequence the receiver needs (cumulative ack).
    pub cumulative: u32,
    /// Bitmap of out-of-order sequences held beyond `cumulative` (bit `i` ⇒ `cumulative + i`).
    pub sack: u64,
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

/// The sender half: segments a payload and **selectively repeats** only the missing segments within
/// a sliding window, until the stream drains.
#[derive(Clone, Debug)]
pub struct StreamSender {
    stream_id: u32,
    segments: Vec<Vec<u8>>,
    /// Cumulative ack: every sequence below this is acknowledged.
    acked: u32,
    /// Individually acknowledged sequences at or above `acked` (from SACK bitmaps) — these are NOT
    /// retransmitted (the selective-repeat property).
    sacked: BTreeSet<u32>,
    /// Max in-flight / lookahead segments (flow control).
    window: u32,
}

impl StreamSender {
    /// Open a stream carrying `payload`, cut into `MAX_SEGMENT`-sized segments.
    #[must_use]
    pub fn new(stream_id: u32, payload: &[u8]) -> Self {
        let segments: Vec<Vec<u8>> = if payload.is_empty() {
            alloc::vec![Vec::new()] // an empty stream is still one (FIN) segment
        } else {
            payload.chunks(MAX_SEGMENT).map(<[u8]>::to_vec).collect()
        };
        Self {
            stream_id,
            segments,
            acked: 0,
            sacked: BTreeSet::new(),
            window: DEFAULT_WINDOW,
        }
    }

    /// Set the sliding-window size (clamped to `1..=SACK_WIDTH`).
    #[must_use]
    pub fn with_window(mut self, window: u32) -> Self {
        self.window = window.clamp(1, SACK_WIDTH);
        self
    }

    /// The segments to (re)send now — call on open and on each retransmit tick. Only the **missing**
    /// segments within the window `[acked, acked + window)` are emitted: any sequence already
    /// selectively acked is skipped, so a single loss costs a single retransmit (selective repeat),
    /// not a re-send of the whole tail. The stream's last segment carries `fin`.
    #[must_use]
    pub fn outbound(&self) -> Vec<Segment> {
        let last = self.segments.len().saturating_sub(1) as u32;
        let end = (self.acked + self.window).min(self.segments.len() as u32);
        (self.acked..end)
            .filter(|seq| !self.sacked.contains(seq))
            .filter_map(|seq| {
                self.segments.get(seq as usize).map(|data| Segment {
                    stream_id: self.stream_id,
                    seq,
                    fin: seq == last,
                    data: data.clone(),
                })
            })
            .collect()
    }

    /// Apply a selective ack: advance the cumulative point and record the individually-acked
    /// sequences from the SACK bitmap, so they are not retransmitted.
    pub fn on_ack(&mut self, ack: Ack) {
        let len = self.segments.len() as u32;
        self.acked = self.acked.max(ack.cumulative).min(len);
        for i in 1..SACK_WIDTH {
            if ack.sack & (1u64 << i) != 0 {
                self.sacked.insert(ack.cumulative.saturating_add(i));
            }
        }
        // A gap may now be filled by contiguous sacked sequences — advance the cumulative point.
        while self.sacked.remove(&self.acked) {
            self.acked += 1;
        }
        // Drop stale selective acks below the cumulative point.
        self.sacked = self.sacked.split_off(&self.acked);
    }

    /// Whether every segment has been acknowledged.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.acked as usize >= self.segments.len()
    }
}

/// The receiver half: buffers out-of-order segments, delivers in order, acks the contiguous run.
#[derive(Clone, Debug)]
pub struct StreamReceiver {
    stream_id: u32,
    received: BTreeMap<u32, Vec<u8>>,
    next: u32,
    fin_seq: Option<u32>,
}

impl StreamReceiver {
    /// A receiver for `stream_id`.
    #[must_use]
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            received: BTreeMap::new(),
            next: 0,
            fin_seq: None,
        }
    }

    /// Ingest a segment (ignoring foreign stream ids). Returns the **selective** ack to send back:
    /// the next in-order sequence needed plus a bitmap of the out-of-order segments already held, so
    /// the sender retransmits only the true gaps.
    pub fn on_segment(&mut self, segment: &Segment) -> Ack {
        if segment.stream_id != self.stream_id {
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
        self.ack()
    }

    /// The current selective ack: cumulative next-needed sequence + a bitmap of out-of-order holds.
    #[must_use]
    pub fn ack(&self) -> Ack {
        let mut sack = 0u64;
        for i in 1..SACK_WIDTH {
            if self.received.contains_key(&(self.next + i)) {
                sack |= 1u64 << i;
            }
        }
        Ack {
            cumulative: self.next,
            sack,
        }
    }

    /// The reassembled payload, once the FIN segment and every segment before it have arrived.
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
        // The sender learns it is drained once it applies the ack.
        sender.on_ack(receiver.on_segment(&sender.outbound()[0]));
        assert!(sender.is_complete());
    }

    #[test]
    fn selective_repeat_resends_only_the_lost_segment() {
        // Ten segments; the third (seq 2) is lost on the first pass. Under selective repeat the
        // sender must resend ONLY seq 2 next tick — not the whole tail (that would be Go-Back-N).
        let payload: Vec<u8> = (0..10 * MAX_SEGMENT as u32).map(|i| i as u8).collect();
        let mut sender = StreamSender::new(3, &payload).with_window(64);
        let mut receiver = StreamReceiver::new(3);

        let mut last_ack = receiver.ack();
        for seg in sender.outbound() {
            if seg.seq == 2 {
                continue; // drop seq 2
            }
            last_ack = receiver.on_segment(&seg);
        }
        sender.on_ack(last_ack);

        // The cumulative ack is stuck at 2 (the gap), but every later segment was SACKed.
        assert_eq!(last_ack.cumulative, 2);
        let resend = sender.outbound();
        assert_eq!(resend.len(), 1, "only the lost segment is retransmitted");
        assert_eq!(resend[0].seq, 2);

        // Deliver it and the stream completes.
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
        // Deliver segments out of order.
        let mut segs = sender.outbound();
        segs.reverse();
        for seg in &segs {
            receiver.on_segment(seg);
        }
        assert_eq!(receiver.deliver(), Some(payload));
    }

    #[test]
    fn reliable_under_loss_via_retransmission() {
        // A lossy channel drops every third segment on the first pass; the sender retransmits past
        // the cumulative ack until the receiver has the whole stream.
        let payload: Vec<u8> = (0..8000u32).map(|i| (i * 7) as u8).collect();
        let mut sender = StreamSender::new(2, &payload);
        let mut receiver = StreamReceiver::new(2);

        let mut pass = 0u32;
        while !sender.is_complete() {
            let mut ack = receiver.ack();
            for (k, seg) in sender.outbound().iter().enumerate() {
                // Drop one in three on the first pass only — later passes are clean.
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
}
