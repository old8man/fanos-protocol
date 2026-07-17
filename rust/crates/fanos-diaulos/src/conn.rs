//! A multiplexed DIAULOS connection — many independent reliable streams over one cell channel.
//!
//! All streams share the connection's two direction keys and one monotone nonce counter, but each
//! keeps its **own** selective-repeat + SACK state, so a loss or stall on one stream never blocks
//! another (no cross-stream head-of-line blocking — the QUIC property, which the datagram substrate
//! grants for free). Streams are identified by `stream_id` with parity by role — the initiator opens
//! **even** ids, the responder **odd** — so both ends may open streams concurrently without
//! negotiation. A `DATA` frame for an unknown id **implicitly opens** an inbound stream, queued for
//! [`accept`](Connection::accept).

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};

use fanos_runtime::stream::{StreamReceiver, StreamSender};

use crate::cell::{Key, open, seal};
use crate::frame::Frame;

/// One multiplexed stream's reliability state (the keys and nonce live on the [`Connection`]).
struct Stream {
    sender: StreamSender,
    receiver: StreamReceiver,
}

impl Stream {
    fn new(stream_id: u32) -> Self {
        Self {
            sender: StreamSender::open(stream_id),
            receiver: StreamReceiver::new(stream_id),
        }
    }
}

/// A multiplexed, bidirectional, end-to-end-encrypted DIAULOS connection.
pub struct Connection {
    key_tx: Key,
    key_rx: Key,
    nonce_tx: u64,
    next_local_id: u32,
    streams: BTreeMap<u32, Stream>,
    accept_queue: VecDeque<u32>,
}

impl Connection {
    /// A connection sealing outbound cells with `key_tx` and opening inbound with `key_rx`. The
    /// `initiator` opens even stream ids; a responder opens odd — so ids never collide.
    #[must_use]
    pub fn new(key_tx: Key, key_rx: Key, initiator: bool) -> Self {
        Self {
            key_tx,
            key_rx,
            nonce_tx: 0,
            next_local_id: u32::from(!initiator),
            streams: BTreeMap::new(),
            accept_queue: VecDeque::new(),
        }
    }

    /// Open a new locally-initiated stream; returns its id.
    pub fn open_stream(&mut self) -> u32 {
        let id = self.next_local_id;
        self.next_local_id = self.next_local_id.wrapping_add(2);
        self.streams.insert(id, Stream::new(id));
        id
    }

    /// The next inbound stream the peer opened (implicit OPEN), if any — the service-side accept.
    pub fn accept(&mut self) -> Option<u32> {
        self.accept_queue.pop_front()
    }

    /// Append bytes to `stream_id`'s send buffer (no-op for an unknown stream).
    pub fn write(&mut self, stream_id: u32, bytes: &[u8]) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.sender.push(bytes);
        }
    }

    /// Close the send side of `stream_id`.
    pub fn finish(&mut self, stream_id: u32) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.sender.finish();
        }
    }

    /// Drain and return the contiguous in-order bytes received on `stream_id` since the last call.
    pub fn read(&mut self, stream_id: u32) -> Vec<u8> {
        self.streams
            .get_mut(&stream_id)
            .map_or_else(Vec::new, |s| s.receiver.take())
    }

    /// Whether `stream_id`'s send side is fully acknowledged.
    #[must_use]
    pub fn sender_complete(&self, stream_id: u32) -> bool {
        self.streams
            .get(&stream_id)
            .is_some_and(|s| s.sender.is_complete())
    }

    /// Whether `stream_id`'s receive side has the whole peer stream (FIN and all prior segments).
    #[must_use]
    pub fn receiver_finished(&self, stream_id: u32) -> bool {
        self.streams
            .get(&stream_id)
            .is_some_and(|s| s.receiver.is_finished())
    }

    /// Whether `stream_id` is complete in both directions.
    #[must_use]
    pub fn is_stream_done(&self, stream_id: u32) -> bool {
        self.sender_complete(stream_id) && self.receiver_finished(stream_id)
    }

    fn next_nonce(&mut self) -> u64 {
        let n = self.nonce_tx;
        self.nonce_tx = self.nonce_tx.wrapping_add(1);
        n
    }

    /// All cells to (re)send now, across every stream: `DATA` cells for each stream's outbound
    /// segments (selective repeat within its window) plus one `ACK` cell per stream.
    pub fn outbound(&mut self) -> Vec<Vec<u8>> {
        let mut frames: Vec<Frame> = Vec::new();
        for (&id, s) in &self.streams {
            for seg in s.sender.outbound() {
                frames.push(Frame::Data(seg));
            }
            frames.push(Frame::Ack {
                stream_id: id,
                ack: s.receiver.ack(),
            });
        }
        frames
            .into_iter()
            .filter_map(|f| {
                let nonce = self.next_nonce();
                seal(&self.key_tx, nonce, &f.encode())
            })
            .collect()
    }

    /// Ingest one cell: route the frame to its stream. A `DATA` for an unknown id implicitly opens an
    /// inbound stream (queued for [`accept`](Self::accept)). Cells that fail to open are dropped.
    pub fn on_cell(&mut self, cell: &[u8]) {
        let Some(frame_bytes) = open(&self.key_rx, cell) else {
            return;
        };
        match Frame::decode(&frame_bytes) {
            Some(Frame::Data(seg)) => {
                let id = seg.stream_id;
                // A DATA for an id we never opened ⇒ the peer opened it (implicit OPEN).
                let fresh = match self.streams.entry(id) {
                    Entry::Occupied(mut e) => {
                        e.get_mut().receiver.on_segment(&seg);
                        false
                    }
                    Entry::Vacant(e) => {
                        e.insert(Stream::new(id)).receiver.on_segment(&seg);
                        true
                    }
                };
                if fresh {
                    self.accept_queue.push_back(id);
                }
            }
            Some(Frame::Ack { stream_id, ack }) => {
                if let Some(s) = self.streams.get_mut(&stream_id) {
                    s.sender.on_ack(ack);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::cell::CELL_LEN;

    #[test]
    fn two_streams_multiplex_bidirectionally_under_loss() {
        let (c2s, s2c) = ([9u8; 32], [8u8; 32]);
        let mut client = Connection::new(c2s, s2c, true); // initiator → even ids
        let mut service = Connection::new(s2c, c2s, false); // responder

        let a = client.open_stream(); // id 0
        let b = client.open_stream(); // id 2
        let da: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        let db: Vec<u8> = (0..2000u32).map(|i| (i * 5) as u8).collect();
        client.write(a, &da);
        client.finish(a);
        client.write(b, &db);
        client.finish(b);

        let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
        let (mut cli_got_a, mut cli_got_b) = (Vec::new(), Vec::new());
        let mut round = 0;
        loop {
            // client → service (drop one in three cells on round 0)
            for (k, cell) in client.outbound().into_iter().enumerate() {
                assert_eq!(cell.len(), CELL_LEN);
                if !(round == 0 && k % 3 == 1) {
                    service.on_cell(&cell);
                }
            }
            // service accepts new streams and echoes a response on each, then reads.
            while let Some(id) = service.accept() {
                service.write(id, &[id as u8; 300]);
                service.finish(id);
            }
            got_a.extend_from_slice(&service.read(a));
            got_b.extend_from_slice(&service.read(b));
            // service → client (drop one in four on round 0)
            for (k, cell) in service.outbound().into_iter().enumerate() {
                if !(round == 0 && k % 4 == 2) {
                    client.on_cell(&cell);
                }
            }
            cli_got_a.extend_from_slice(&client.read(a));
            cli_got_b.extend_from_slice(&client.read(b));

            if client.is_stream_done(a)
                && client.is_stream_done(b)
                && service.is_stream_done(a)
                && service.is_stream_done(b)
            {
                break;
            }
            round += 1;
            assert!(round < 40, "should converge");
        }
        // Drain any tail.
        got_a.extend_from_slice(&service.read(a));
        got_b.extend_from_slice(&service.read(b));
        cli_got_a.extend_from_slice(&client.read(a));
        cli_got_b.extend_from_slice(&client.read(b));

        assert_eq!(got_a, da, "service received stream a in full");
        assert_eq!(got_b, db, "service received stream b in full");
        assert_eq!(cli_got_a, vec![0u8; 300], "client got a's response");
        assert_eq!(cli_got_b, vec![2u8; 300], "client got b's response");
    }

    #[test]
    fn initiator_and_responder_ids_never_collide() {
        let mut client = Connection::new([1u8; 32], [2u8; 32], true);
        let mut service = Connection::new([2u8; 32], [1u8; 32], false);
        assert_eq!(client.open_stream(), 0);
        assert_eq!(client.open_stream(), 2); // initiator: even
        assert_eq!(service.open_stream(), 1);
        assert_eq!(service.open_stream(), 3); // responder: odd
    }

    /// A small deterministic LCG so a proptest seed reproduces the exact loss pattern.
    fn lcg_next(state: &mut u64) -> u32 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (*state >> 33) as u32
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

        /// Many streams multiplexed over one connection, each with a distinct payload, all arrive
        /// intact and correctly separated (no cross-stream contamination) despite early loss in both
        /// directions and arbitrary payload sizes. This is the multiplex-correctness property: the
        /// stream_id inside each frame — not cell order — decides routing.
        #[test]
        fn multiplexed_streams_arrive_intact_and_separated(
            payloads in proptest::collection::vec(
                proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2500usize),
                1..=4usize,
            ),
            loss_seed in proptest::prelude::any::<u64>(),
        ) {
            let (c2s, s2c) = ([11u8; 32], [22u8; 32]);
            let mut client = Connection::new(c2s, s2c, true);
            let mut service = Connection::new(s2c, c2s, false);

            let n = payloads.len();
            let mut ids = Vec::with_capacity(n);
            for p in &payloads {
                let id = client.open_stream();
                client.write(id, p);
                client.finish(id);
                ids.push(id);
            }

            let mut state = loss_seed | 1;
            let mut got: Vec<Vec<u8>> = vec![Vec::new(); n];
            let mut round = 0;
            loop {
                // client → service: drop ~40% of cells for the first few rounds, then a clean channel
                // guarantees convergence.
                for cell in client.outbound() {
                    if round >= 4 || lcg_next(&mut state) % 100 >= 40 {
                        service.on_cell(&cell);
                    }
                }
                while service.accept().is_some() {}
                for (i, &id) in ids.iter().enumerate() {
                    got[i].extend_from_slice(&service.read(id));
                }
                // service → client: only ACKs flow back; drop ~30% early.
                for cell in service.outbound() {
                    if round >= 4 || lcg_next(&mut state) % 100 >= 30 {
                        client.on_cell(&cell);
                    }
                }
                if ids
                    .iter()
                    .all(|&id| client.sender_complete(id) && service.receiver_finished(id))
                {
                    break;
                }
                round += 1;
                proptest::prop_assert!(round < 300, "must converge");
            }
            for (i, &id) in ids.iter().enumerate() {
                got[i].extend_from_slice(&service.read(id));
            }
            for i in 0..n {
                proptest::prop_assert_eq!(&got[i], &payloads[i]);
            }
        }
    }
}
