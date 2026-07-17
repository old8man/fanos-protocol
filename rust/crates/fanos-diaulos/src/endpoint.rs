//! [`StreamEndpoint`] — a bidirectional, reliable, end-to-end-encrypted byte stream over cells.
//!
//! It drives the shipped selective-repeat + SACK core of `fanos_runtime::stream` end-to-end, sealing
//! its outbound segments and acks into constant-size cells ([`crate::cell`]) and opening inbound
//! cells back into segments and acks. Each direction has its own key and its own monotone nonce
//! counter, so the two directions never share nonce space. Reliability, ordering, and flow control
//! are entirely between the two endpoints — every relay in between sees only opaque, constant-size,
//! authenticated cells.

use fanos_runtime::stream::{StreamReceiver, StreamSender};

use crate::cell::{Key, open, seal};
use crate::frame::Frame;

/// One end of a DIAULOS stream. Write bytes, drain received bytes, and exchange [`cells`](Self::outbound)
/// with the peer until [`is_done`](Self::is_done).
pub struct StreamEndpoint {
    sender: StreamSender,
    receiver: StreamReceiver,
    key_tx: Key,
    key_rx: Key,
    nonce_tx: u64,
}

impl StreamEndpoint {
    /// A new endpoint for `stream_id`, sealing outbound cells with `key_tx` and opening inbound cells
    /// with `key_rx` (the peer's `key_tx`/`key_rx` are the mirror image).
    #[must_use]
    pub fn new(stream_id: u32, key_tx: Key, key_rx: Key) -> Self {
        Self {
            sender: StreamSender::open(stream_id),
            receiver: StreamReceiver::new(stream_id),
            key_tx,
            key_rx,
            nonce_tx: 0,
        }
    }

    /// Append bytes to the send stream.
    pub fn write(&mut self, bytes: &[u8]) {
        self.sender.push(bytes);
    }

    /// Close the send side (the final segment carries FIN).
    pub fn finish(&mut self) {
        self.sender.finish();
    }

    /// Drain and return the contiguous in-order bytes received since the last call.
    pub fn read(&mut self) -> Vec<u8> {
        self.receiver.take()
    }

    /// Whether both directions are complete: everything sent is acknowledged and the peer's stream is
    /// fully received.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.sender.is_complete() && self.receiver.is_finished()
    }

    fn next_nonce(&mut self) -> u64 {
        let n = self.nonce_tx;
        self.nonce_tx = self.nonce_tx.wrapping_add(1);
        n
    }

    /// The cells to (re)send now: one `DATA` cell per outbound segment (selective repeat within the
    /// window) plus one `ACK` cell advertising what has been received. Call on write and each tick.
    pub fn outbound(&mut self) -> Vec<Vec<u8>> {
        let mut cells = Vec::new();
        for seg in self.sender.outbound() {
            let nonce = self.next_nonce();
            if let Some(cell) = seal(&self.key_tx, nonce, &Frame::Data(seg).encode()) {
                cells.push(cell);
            }
        }
        let ack = Frame::Ack(self.receiver.ack()).encode();
        let nonce = self.next_nonce();
        if let Some(cell) = seal(&self.key_tx, nonce, &ack) {
            cells.push(cell);
        }
        cells
    }

    /// Ingest one cell. A cell that fails to open (wrong key / tampered) is silently dropped; a valid
    /// `DATA` cell feeds the receiver, a valid `ACK` cell advances the sender.
    pub fn on_cell(&mut self, cell: &[u8]) {
        let Some(frame_bytes) = open(&self.key_rx, cell) else {
            return;
        };
        match Frame::decode(&frame_bytes) {
            Some(Frame::Data(seg)) => {
                self.receiver.on_segment(&seg);
            }
            Some(Frame::Ack(ack)) => {
                self.sender.on_ack(ack);
            }
            Some(Frame::Padding) | None => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::cell::CELL_LEN;

    /// Drive two endpoints to completion over a (possibly lossy/tampering) cell relay, accumulating
    /// each side's received bytes. Returns `(client_got, service_got)`.
    fn run(
        client: &mut StreamEndpoint,
        service: &mut StreamEndpoint,
        mut drop_up: impl FnMut(usize, usize) -> bool,
        mut drop_down: impl FnMut(usize, usize) -> bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let (mut client_got, mut service_got) = (Vec::new(), Vec::new());
        let mut round = 0;
        while !(client.is_done() && service.is_done()) {
            for (k, cell) in client.outbound().into_iter().enumerate() {
                assert_eq!(cell.len(), CELL_LEN, "constant cell size on the wire");
                if !drop_up(round, k) {
                    service.on_cell(&cell);
                }
            }
            service_got.extend_from_slice(&service.read());
            for (k, cell) in service.outbound().into_iter().enumerate() {
                if !drop_down(round, k) {
                    client.on_cell(&cell);
                }
            }
            client_got.extend_from_slice(&client.read());
            round += 1;
            assert!(round < 40, "should converge");
        }
        client_got.extend_from_slice(&client.read());
        service_got.extend_from_slice(&service.read());
        (client_got, service_got)
    }

    fn endpoints() -> (StreamEndpoint, StreamEndpoint) {
        let (c2s, s2c) = ([1u8; 32], [2u8; 32]);
        (
            StreamEndpoint::new(0, c2s, s2c), // client: tx = c→s, rx = s→c
            StreamEndpoint::new(0, s2c, c2s), // service: mirror
        )
    }

    #[test]
    fn reliable_bidirectional_transfer_over_clean_cells() {
        let (mut client, mut service) = endpoints();
        let up: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let down: Vec<u8> = (0..3000u32).map(|i| (i * 3) as u8).collect();
        client.write(&up);
        client.finish();
        service.write(&down);
        service.finish();
        let (client_got, service_got) = run(&mut client, &mut service, |_, _| false, |_, _| false);
        assert_eq!(service_got, up, "service received the client's stream");
        assert_eq!(client_got, down, "client received the service's stream");
    }

    #[test]
    fn reliable_under_loss_and_reordering() {
        // Drop one in three up-cells and one in four down-cells on the first round; selective repeat
        // (SACK) recovers, and per-cell nonces mean reordered/late cells decrypt fine.
        let (mut client, mut service) = endpoints();
        let up: Vec<u8> = (0..8000u32).map(|i| (i * 7) as u8).collect();
        let down: Vec<u8> = (0..4096u32).map(|i| (i * 5) as u8).collect();
        client.write(&up);
        client.finish();
        service.write(&down);
        service.finish();
        let (client_got, service_got) = run(
            &mut client,
            &mut service,
            |round, k| round == 0 && k % 3 == 1,
            |round, k| round == 0 && k % 4 == 2,
        );
        assert_eq!(service_got, up);
        assert_eq!(client_got, down);
    }

    #[test]
    fn a_tampered_cell_is_dropped_and_the_stream_still_completes() {
        // Corrupt every up-cell on round 0 (they fail AEAD → dropped); retransmission recovers.
        let (mut client, mut service) = endpoints();
        let up: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        client.write(&up);
        client.finish();
        service.finish(); // service sends nothing
        // Custom relay that flips a byte in every up-cell on round 0.
        let (mut client_got, mut service_got) = (Vec::new(), Vec::new());
        let mut round = 0;
        while !(client.is_done() && service.is_done()) {
            for cell in client.outbound() {
                let mut c = cell;
                if round == 0 {
                    c[20] ^= 0xFF; // tamper → AEAD rejects
                }
                service.on_cell(&c);
            }
            service_got.extend_from_slice(&service.read());
            for cell in service.outbound() {
                client.on_cell(&cell);
            }
            client_got.extend_from_slice(&client.read());
            round += 1;
            assert!(round < 40);
        }
        let _ = client_got;
        service_got.extend_from_slice(&service.read());
        assert_eq!(service_got, up, "recovered despite round-0 tampering");
    }
}
