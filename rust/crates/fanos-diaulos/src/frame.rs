//! DIAULOS frames — what a [`cell`](crate::cell) carries.
//!
//! A frame is `ftype(1) ‖ body`. The three steady-state frames reuse the reliability vocabulary of
//! `fanos_runtime::stream` verbatim, so the SACK core is driven end-to-end:
//!
//! * `DATA` — a [`Segment`] with an explicit `len` (the real byte count; the cell's remaining bytes
//!   are pad, so the constant cell hides the length end-to-end).
//! * `ACK` — a selective [`Ack`] (cumulative + SACK bitmap + receive credit `rwnd`).
//! * `PADDING` — a pure cover cell, byte-indistinguishable from `DATA` once sealed.

use fanos_runtime::stream::{Ack, MAX_SEGMENT, Segment};

const FT_PADDING: u8 = 0x00;
const FT_DATA: u8 = 0x01;
const FT_ACK: u8 = 0x02;
const FT_RESET: u8 = 0x03;

/// A DIAULOS frame carried inside one cell.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Frame {
    /// A reliability segment (stream data). The `stream_id` inside routes it in a multiplexed
    /// connection.
    Data(Segment),
    /// A selective acknowledgement with receive credit, tagged with the stream it acknowledges (so
    /// acks route independently over one connection).
    Ack {
        /// The stream this ack is for.
        stream_id: u32,
        /// The selective ack + receive credit.
        ack: Ack,
    },
    /// A cover cell — no payload.
    Padding,
    /// Abort a stream in both directions: the sender drops its state and the receiver drops its side,
    /// reclaiming the slot immediately (the teardown a plain FIN cannot give — a peer that opens a stream
    /// and never FINs would otherwise pin it). Carries only the `stream_id` to reset.
    Reset {
        /// The stream being aborted.
        stream_id: u32,
    },
}

fn read_u16(cur: &mut &[u8]) -> Option<u16> {
    let (head, tail) = cur.split_at_checked(2)?;
    *cur = tail;
    let mut a = [0u8; 2];
    a.copy_from_slice(head);
    Some(u16::from_be_bytes(a))
}
fn read_u32(cur: &mut &[u8]) -> Option<u32> {
    let (head, tail) = cur.split_at_checked(4)?;
    *cur = tail;
    let mut a = [0u8; 4];
    a.copy_from_slice(head);
    Some(u32::from_be_bytes(a))
}
fn read_u64(cur: &mut &[u8]) -> Option<u64> {
    let (head, tail) = cur.split_at_checked(8)?;
    *cur = tail;
    let mut a = [0u8; 8];
    a.copy_from_slice(head);
    Some(u64::from_be_bytes(a))
}

impl Frame {
    /// Encode the frame to bytes (placed at the front of a cell's plaintext; the cell zero-pads the
    /// rest, and the length fields let [`decode`](Self::decode) ignore that padding).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Data(s) => {
                let len = s.data.len().min(MAX_SEGMENT);
                let mut out = Vec::with_capacity(12 + len);
                out.push(FT_DATA);
                out.extend_from_slice(&s.stream_id.to_be_bytes());
                out.extend_from_slice(&s.seq.to_be_bytes());
                out.push(u8::from(s.fin));
                out.extend_from_slice(&(len as u16).to_be_bytes());
                out.extend_from_slice(s.data.get(..len).unwrap_or(&[]));
                out
            }
            Self::Ack { stream_id, ack } => {
                let mut out = Vec::with_capacity(21);
                out.push(FT_ACK);
                out.extend_from_slice(&stream_id.to_be_bytes());
                out.extend_from_slice(&ack.cumulative.to_be_bytes());
                out.extend_from_slice(&ack.sack.to_be_bytes());
                out.extend_from_slice(&ack.rwnd.to_be_bytes());
                out
            }
            Self::Padding => vec![FT_PADDING],
            Self::Reset { stream_id } => {
                let mut out = Vec::with_capacity(5);
                out.push(FT_RESET);
                out.extend_from_slice(&stream_id.to_be_bytes());
                out
            }
        }
    }

    /// Decode a frame from a cell's plaintext (trailing zero padding is ignored via the length
    /// fields). `None` on a malformed frame.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&ftype, rest) = bytes.split_first()?;
        let mut cur = rest;
        match ftype {
            FT_PADDING => Some(Self::Padding),
            FT_RESET => {
                let stream_id = read_u32(&mut cur)?;
                Some(Self::Reset { stream_id })
            }
            FT_DATA => {
                let stream_id = read_u32(&mut cur)?;
                let seq = read_u32(&mut cur)?;
                let (&fin, r) = cur.split_first()?;
                cur = r;
                let len = read_u16(&mut cur)? as usize;
                // Enforce the segment-size invariant on the parse side too: `encode` clamps to
                // `MAX_SEGMENT`, so a frame claiming more is malformed. Without this, a crafted DATA
                // frame could set `len` past `MAX_SEGMENT` and pull the cell's trailing zero-pad in as
                // payload — injecting bytes the sender never wrote.
                if len > MAX_SEGMENT {
                    return None;
                }
                let data = cur.get(..len)?.to_vec();
                Some(Self::Data(Segment {
                    stream_id,
                    seq,
                    fin: fin != 0,
                    data,
                }))
            }
            FT_ACK => {
                let stream_id = read_u32(&mut cur)?;
                let cumulative = read_u32(&mut cur)?;
                let sack = read_u64(&mut cur)?;
                let rwnd = read_u32(&mut cur)?;
                Some(Self::Ack {
                    stream_id,
                    ack: Ack {
                        cumulative,
                        sack,
                        rwnd,
                    },
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn data_frame_round_trips_ignoring_pad() {
        let f = Frame::Data(Segment {
            stream_id: 5,
            seq: 9,
            fin: true,
            data: b"payload bytes".to_vec(),
        });
        let mut wire = f.encode();
        wire.extend_from_slice(&[0u8; 200]); // simulate cell zero-padding after the frame
        assert_eq!(Frame::decode(&wire), Some(f));
    }

    #[test]
    fn ack_frame_round_trips() {
        let f = Frame::Ack {
            stream_id: 4,
            ack: Ack {
                cumulative: 12,
                sack: 0b1010,
                rwnd: 30,
            },
        };
        let mut wire = f.encode();
        wire.extend_from_slice(&[0u8; 64]);
        assert_eq!(Frame::decode(&wire), Some(f));
    }

    #[test]
    fn padding_frame_round_trips() {
        assert_eq!(
            Frame::decode(&Frame::Padding.encode()),
            Some(Frame::Padding)
        );
    }

    #[test]
    fn reset_frame_round_trips_ignoring_pad() {
        let f = Frame::Reset {
            stream_id: 0x1234_5678,
        };
        let mut wire = f.encode();
        wire.extend_from_slice(&[0u8; 128]); // cell zero-padding after the frame
        assert_eq!(Frame::decode(&wire), Some(f));
        // A RESET cut mid-field is rejected (stream_id needs 4 bytes).
        assert_eq!(Frame::decode(&[FT_RESET, 0, 0]), None);
    }

    #[test]
    fn empty_or_unknown_is_rejected() {
        assert_eq!(Frame::decode(&[]), None);
        assert_eq!(Frame::decode(&[0xFF]), None);
    }

    fn data_header(stream_id: u32, seq: u32, fin: bool, len: u16) -> Vec<u8> {
        let mut v = vec![FT_DATA];
        v.extend_from_slice(&stream_id.to_be_bytes());
        v.extend_from_slice(&seq.to_be_bytes());
        v.push(u8::from(fin));
        v.extend_from_slice(&len.to_be_bytes());
        v
    }

    #[test]
    fn a_data_frame_claiming_more_than_max_segment_is_rejected() {
        // len = MAX_SEGMENT + 1 with that many bytes present — inside the cell but past the invariant.
        let mut over = data_header(7, 0, false, (MAX_SEGMENT + 1) as u16);
        over.extend_from_slice(&vec![0u8; MAX_SEGMENT + 1]);
        assert_eq!(
            Frame::decode(&over),
            None,
            "len past MAX_SEGMENT is rejected"
        );

        // Exactly MAX_SEGMENT is accepted (the boundary).
        let mut ok = data_header(7, 0, false, MAX_SEGMENT as u16);
        ok.extend_from_slice(&vec![0xAB; MAX_SEGMENT]);
        match Frame::decode(&ok) {
            Some(Frame::Data(seg)) => assert_eq!(seg.data.len(), MAX_SEGMENT),
            other => panic!("expected a MAX_SEGMENT data frame, got {other:?}"),
        }
    }

    #[test]
    fn truncated_and_boundary_frames() {
        // A DATA header cut mid-field (stream_id needs 4 bytes).
        assert_eq!(Frame::decode(&[FT_DATA, 0, 0, 0]), None);
        // A DATA len exceeding the bytes actually present.
        let mut short = data_header(0, 0, false, 10);
        short.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            Frame::decode(&short),
            None,
            "len exceeding available bytes is rejected"
        );
        // An ACK cut mid-field.
        assert_eq!(Frame::decode(&[FT_ACK, 0, 0, 0]), None);
        // A DATA frame with exactly the header and len 0 → an empty-data segment (the FIN-only case).
        assert_eq!(
            Frame::decode(&data_header(1, 2, true, 0)),
            Some(Frame::Data(Segment {
                stream_id: 1,
                seq: 2,
                fin: true,
                data: vec![],
            }))
        );
    }
}
