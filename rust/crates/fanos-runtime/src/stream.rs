//! Reliable, ordered, multiplexed streams over the overlay (spec §7.2 `Stream*`).
//!
//! The overlay delivers single, possibly-dropped datagrams; an application often wants a reliable
//! ordered byte-stream. This module is the sans-I/O protocol logic for one: a payload is cut into
//! [`Segment`]s (`STREAM_DATA`), the receiver buffers out-of-order arrivals and delivers them in
//! order, and acknowledges the highest contiguous sequence; the sender retransmits everything past
//! the cumulative ack until the stream drains. It is a pure state machine — a driver performs the
//! sends and the retransmit timer — so it composes with either transport (over QUIC, native streams
//! subsume it; over the lossy simulator or UDP, this provides the reliability).
//!
//! Multiplexing is by `stream_id`: many independent streams share one peer link, each with its own
//! sender/receiver state.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Maximum payload bytes per segment (keeps a segment within a typical datagram).
pub const MAX_SEGMENT: usize = 1024;

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

/// The sender half: segments a payload and retransmits past the cumulative ack until drained.
#[derive(Clone, Debug)]
pub struct StreamSender {
    stream_id: u32,
    segments: Vec<Vec<u8>>,
    acked: u32,
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
        }
    }

    /// The segments still awaiting acknowledgement — call on open and on each retransmit tick. The
    /// last segment of the stream carries `fin`.
    #[must_use]
    pub fn outbound(&self) -> Vec<Segment> {
        let last = self.segments.len().saturating_sub(1);
        (self.acked as usize..self.segments.len())
            .filter_map(|i| {
                self.segments.get(i).map(|data| Segment {
                    stream_id: self.stream_id,
                    seq: i as u32,
                    fin: i == last,
                    data: data.clone(),
                })
            })
            .collect()
    }

    /// Apply a cumulative ack (the receiver's next-expected sequence): everything below it is done.
    pub fn on_ack(&mut self, cumulative: u32) {
        self.acked = self.acked.max(cumulative).min(self.segments.len() as u32);
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

    /// Ingest a segment (ignoring foreign stream ids). Returns the cumulative ack to send back —
    /// the next sequence number the receiver still needs.
    pub fn on_segment(&mut self, segment: &Segment) -> u32 {
        if segment.stream_id != self.stream_id {
            return self.next;
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
        self.next
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
            let mut ack = receiver.next;
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
