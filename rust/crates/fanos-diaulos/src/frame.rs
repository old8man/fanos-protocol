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

/// A DIAULOS frame carried inside one cell.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Frame {
    /// A reliability segment (stream data).
    Data(Segment),
    /// A selective acknowledgement with receive credit.
    Ack(Ack),
    /// A cover cell — no payload.
    Padding,
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
            Self::Ack(a) => {
                let mut out = Vec::with_capacity(17);
                out.push(FT_ACK);
                out.extend_from_slice(&a.cumulative.to_be_bytes());
                out.extend_from_slice(&a.sack.to_be_bytes());
                out.extend_from_slice(&a.rwnd.to_be_bytes());
                out
            }
            Self::Padding => vec![FT_PADDING],
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
            FT_DATA => {
                let stream_id = read_u32(&mut cur)?;
                let seq = read_u32(&mut cur)?;
                let (&fin, r) = cur.split_first()?;
                cur = r;
                let len = read_u16(&mut cur)? as usize;
                let data = cur.get(..len)?.to_vec();
                Some(Self::Data(Segment {
                    stream_id,
                    seq,
                    fin: fin != 0,
                    data,
                }))
            }
            FT_ACK => {
                let cumulative = read_u32(&mut cur)?;
                let sack = read_u64(&mut cur)?;
                let rwnd = read_u32(&mut cur)?;
                Some(Self::Ack(Ack {
                    cumulative,
                    sack,
                    rwnd,
                }))
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
        let f = Frame::Ack(Ack {
            cumulative: 12,
            sack: 0b1010,
            rwnd: 30,
        });
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
    fn empty_or_unknown_is_rejected() {
        assert_eq!(Frame::decode(&[]), None);
        assert_eq!(Frame::decode(&[0xFF]), None);
    }
}
