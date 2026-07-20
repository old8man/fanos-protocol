//! A multiplexed DIAULOS connection — many independent reliable streams over one cell channel.
//!
//! All streams share the connection's two direction keys and one monotone nonce counter, but each
//! keeps its **own** selective-repeat + SACK state, so a loss or stall on one stream never blocks
//! another (no cross-stream head-of-line blocking — the QUIC property, which the datagram substrate
//! grants for free). Streams are identified by `stream_id` with parity by role — the initiator opens
//! **even** ids, the responder **odd** — so both ends may open streams concurrently without
//! negotiation. A `DATA` frame for an unknown id **implicitly opens** an inbound stream, queued for
//! [`accept`](Connection::accept).

use std::collections::{BTreeMap, VecDeque};

use fanos_stream::{StreamReceiver, StreamSender};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// The hard ceiling on streams held concurrently on one connection. Once reached, a peer's *implicit*
/// opens (a `DATA` for an id we never saw) are refused, so a peer that floods `DATA` frames bearing an
/// ever-growing `stream_id` cannot force unbounded stream-state allocation (audit F2). The connection's
/// stream memory is then capped at `MAX_CONCURRENT_STREAMS ×` per-stream reliability state, whatever the
/// peer sends — and per-stream state is itself window-bounded (C3/F1). Because [`retire_stream`] frees a
/// completed stream's slot, the bound limits *concurrency*, not lifetime stream throughput. `256` mirrors
/// the concurrency a well-behaved QUIC endpoint grants by default; it is a resource bound, not a tuning
/// knob, so it is fixed rather than negotiated.
///
/// [`retire_stream`]: Connection::retire_stream
pub const MAX_CONCURRENT_STREAMS: usize = 256;

/// A multiplexed, bidirectional, end-to-end-encrypted DIAULOS connection.
pub struct Connection {
    key_tx: Key,
    key_rx: Key,
    nonce_tx: u64,
    next_local_id: u32,
    /// The low-bit parity an id must have for the *peer* to have opened it: the initiator (local even)
    /// accepts implicit opens only on odd ids, the responder only on even. Guards our own id space.
    peer_id_parity: u32,
    /// Retirement frontier: a peer-parity id `< peer_closed_below` has already been retired, so a late
    /// duplicate `DATA` for it is a straggler to drop, not a fresh stream to open. Peer ids are handed out
    /// strictly monotonically (`open_stream` steps by 2), so an unknown id below a retired one cannot be a
    /// legitimate new open — this is the QUIC closed-stream rule, and it prevents a retired stream from
    /// being resurrected as a phantom. Only advances on peer-id retirement; local ids need no frontier
    /// (a straggler for a retired local id is dropped by the parity guard or the unknown-ack no-op).
    peer_closed_below: u32,
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
            peer_id_parity: u32::from(initiator),
            peer_closed_below: 0,
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

    /// The number of streams currently held — local plus peer-opened. Bounded by
    /// [`MAX_CONCURRENT_STREAMS`]; exposed so a driver can watch pressure on the slot budget.
    #[must_use]
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Retire a completed stream, freeing its reliability state and its slot against the concurrency cap
    /// ([`MAX_CONCURRENT_STREAMS`]). Returns `true` only if the stream existed and was done in **both**
    /// directions — so no unacknowledged send data and no unreceived segment is ever discarded; an
    /// unfinished or unknown id is left untouched and returns `false`. Retiring a **peer**-opened stream
    /// advances the retirement frontier, so a straggler `DATA` for that id is dropped rather than
    /// re-opening a phantom stream (the ids are monotone, so nothing legitimate lives below a retired one).
    ///
    /// The application calls this once it has read a done stream to completion; long-lived connections then
    /// stay within the cap without ever refusing a fresh stream. By contract the caller has consumed what
    /// it needs via [`read`](Self::read) — retirement reclaims the buffer, it does not deliver it.
    pub fn retire_stream(&mut self, stream_id: u32) -> bool {
        if !self.is_stream_done(stream_id) || self.streams.remove(&stream_id).is_none() {
            return false;
        }
        if stream_id & 1 == self.peer_id_parity {
            // Close the peer id space through this id: ids step by 2, so `id + 1` (the other parity, never
            // a peer id) marks every peer id ≤ this one as retired.
            self.peer_closed_below = self.peer_closed_below.max(stream_id.saturating_add(1));
        }
        true
    }

    /// Abort `stream_id` in both directions: drop its local reliability state immediately (whether or not
    /// it is complete), close the id against re-opening, and return a sealed `RESET` cell to send so the
    /// peer drops its side too. Returns `None` only if sealing fails, or the stream was unknown (nothing to
    /// abort). Unlike [`retire_stream`](Self::retire_stream) — which requires completion — reset reclaims a
    /// stream at *any* point, so a driver can shed a stalled or half-open stream (e.g. a peer that opened it
    /// and never sent `FIN`) rather than pinning a slot until the connection closes.
    pub fn reset_stream(&mut self, stream_id: u32) -> Option<Vec<u8>> {
        // Nothing to abort if the stream is already gone (unknown/retired) — the dropped `Stream` is unused.
        self.streams.remove(&stream_id)?;
        self.accept_queue.retain(|&id| id != stream_id);
        if stream_id & 1 == self.peer_id_parity {
            self.peer_closed_below = self.peer_closed_below.max(stream_id.saturating_add(1));
        }
        let nonce = self.next_nonce()?;
        seal(&self.key_tx, nonce, &Frame::Reset { stream_id }.encode())
    }

    /// The next per-cell AEAD nonce, or `None` once the 2⁶⁴ nonce space is exhausted. Nonce reuse is
    /// catastrophic for the AEAD — it breaks both confidentiality and integrity — so at the limit the
    /// connection refuses to mint any further cell rather than wrap: a hard kill. (2⁶⁴ constant-size cells
    /// is ~18 ZB per connection, astronomically unreachable, so this only ever guards the invariant.)
    fn next_nonce(&mut self) -> Option<u64> {
        let n = self.nonce_tx;
        self.nonce_tx = self.nonce_tx.checked_add(1)?;
        Some(n)
    }

    /// All cells to (re)send now, across every stream: `DATA` cells for each stream's outbound
    /// segments (selective repeat within its window) plus one `ACK` cell per stream. Ticks every
    /// stream's retransmit clock (RFC 6298) one logical step — a driver must call this at a **fixed
    /// cadence** (its own retransmit timer), never reactively; see [`outbound_new`](Self::outbound_new)
    /// for the reactive counterpart.
    pub fn outbound(&mut self) -> Vec<Vec<u8>> {
        let mut frames: Vec<Frame> = Vec::new();
        for (&id, s) in &mut self.streams {
            for seg in s.sender.outbound() {
                frames.push(Frame::Data(seg));
            }
            frames.push(Frame::Ack {
                stream_id: id,
                ack: s.receiver.ack(),
            });
        }
        self.seal_frames(frames)
    }

    /// Cells to send **reactively** right now — e.g. once per inbound delivery, so a peer's new data or
    /// progress is acked promptly — without disturbing any stream's retransmit clock: each stream's
    /// never-before-sent segments (if any; see [`StreamSender::poll_new`]) plus a fresh `ACK`. Unlike
    /// [`outbound`](Self::outbound), safe to call any number of times between ticks — it never advances
    /// a stream's RTO clock, so a burst of reactive calls (inbound traffic over a high-latency transport
    /// includes the peer's own retransmissions) cannot race that clock ahead of real time and starve
    /// backoff of the chance to converge (the mechanism behind the anonymous-session retransmit-storm
    /// livelock this exists to prevent). Only [`outbound`](Self::outbound), driven by the fixed
    /// retransmit tick, may resend already-in-flight data.
    pub fn outbound_new(&mut self) -> Vec<Vec<u8>> {
        let mut frames: Vec<Frame> = Vec::new();
        for (&id, s) in &mut self.streams {
            for seg in s.sender.poll_new() {
                frames.push(Frame::Data(seg));
            }
            frames.push(Frame::Ack {
                stream_id: id,
                ack: s.receiver.ack(),
            });
        }
        self.seal_frames(frames)
    }

    /// Seal each frame with the next nonce, dropping any that cannot be sealed (nonce exhaustion).
    fn seal_frames(&mut self, frames: Vec<Frame>) -> Vec<Vec<u8>> {
        frames
            .into_iter()
            .filter_map(|f| {
                let nonce = self.next_nonce()?;
                seal(&self.key_tx, nonce, &f.encode())
            })
            .collect()
    }

    /// Like [`outbound`](Self::outbound) but tops the batch up to at least `min_cells` by minting
    /// indistinguishable `PADDING` cover cells (same key, same size, same monotone nonce space). This
    /// is the mechanism a constant-rate traffic shaper needs: only the connection may mint valid
    /// cells — it alone owns the send key and nonce counter — so padding cannot be added from outside.
    /// The peer's [`on_cell`](Self::on_cell) silently ignores padding.
    pub fn outbound_padded(&mut self, min_cells: usize) -> Vec<Vec<u8>> {
        let mut cells = self.outbound();
        while cells.len() < min_cells {
            let Some(nonce) = self.next_nonce() else {
                break; // nonce space exhausted — mint no more cover cells
            };
            match seal(&self.key_tx, nonce, &Frame::Padding.encode()) {
                Some(cell) => cells.push(cell),
                None => break,
            }
        }
        cells
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
                // A DATA for an id we never opened ⇒ the peer opened it (implicit OPEN). Admit such an
                // open only in the peer's own parity space (a DATA for an unopened id of *our* parity is a
                // hostile/buggy attempt to seize an id `open_stream` will later hand out — it would clobber
                // the local stream), only above the retirement frontier (else a straggler resurrects a
                // retired stream as a phantom), and only below the concurrency cap (else a flood of
                // ever-new ids exhausts memory — F2). Each condition drops the frame rather than allocate.
                if !self.streams.contains_key(&id) {
                    let admissible = id & 1 == self.peer_id_parity
                        && id >= self.peer_closed_below
                        && self.streams.len() < MAX_CONCURRENT_STREAMS;
                    if admissible {
                        self.streams.insert(id, Stream::new(id));
                        self.accept_queue.push_back(id);
                    }
                }
                // Deliver to the stream if it now exists (pre-existing or just opened); otherwise dropped.
                if let Some(s) = self.streams.get_mut(&id) {
                    s.receiver.on_segment(&seg);
                }
            }
            Some(Frame::Ack { stream_id, ack }) => {
                if let Some(s) = self.streams.get_mut(&stream_id) {
                    s.sender.on_ack(ack);
                }
            }
            Some(Frame::Reset { stream_id }) => {
                // The peer aborts this stream: drop our state, unqueue any pending accept, and (for a
                // peer-opened id) advance the retirement frontier so a straggler cannot re-open it.
                self.streams.remove(&stream_id);
                self.accept_queue.retain(|&id| id != stream_id);
                if stream_id & 1 == self.peer_id_parity {
                    self.peer_closed_below =
                        self.peer_closed_below.max(stream_id.saturating_add(1));
                }
            }
            _ => {}
        }
    }
}

impl Drop for Connection {
    /// Wipe both direction keys from memory on drop; the reliability state holds no key material.
    fn drop(&mut self) {
        self.key_tx.zeroize();
        self.key_rx.zeroize();
    }
}

impl ZeroizeOnDrop for Connection {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
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

    #[test]
    fn a_wrong_parity_implicit_open_cannot_seize_a_local_id() {
        use fanos_stream::Segment;
        let (c2s, s2c) = ([3u8; 32], [4u8; 32]);
        // The initiator's local ids are even; only odd (peer) ids may be implicitly opened.
        let mut initiator = Connection::new(c2s, s2c, true);

        // A hostile DATA for an EVEN id — the initiator's own id space — must be dropped, not accepted.
        let even = Frame::Data(Segment {
            stream_id: 0,
            seq: 0,
            fin: false,
            data: vec![9, 9, 9],
        })
        .encode();
        initiator.on_cell(&seal(&s2c, 0, &even).unwrap());
        assert!(
            initiator.accept().is_none(),
            "a wrong-parity (even) implicit open is refused"
        );
        assert!(
            initiator.read(0).is_empty(),
            "no stream state was injected at id 0"
        );

        // open_stream still hands out id 0 as a fresh local stream, uncorrupted by the injection.
        assert_eq!(initiator.open_stream(), 0);

        // A DATA for an ODD id — the peer's space — is a legitimate implicit open and is accepted.
        let odd = Frame::Data(Segment {
            stream_id: 1,
            seq: 0,
            fin: false,
            data: vec![7],
        })
        .encode();
        initiator.on_cell(&seal(&s2c, 1, &odd).unwrap());
        assert_eq!(
            initiator.accept(),
            Some(1),
            "a correct-parity implicit open is accepted"
        );
    }

    #[test]
    fn padding_holds_a_constant_cell_rate_without_disturbing_streams() {
        let (c2s, s2c) = ([5u8; 32], [6u8; 32]);
        let mut client = Connection::new(c2s, s2c, true);
        let mut service = Connection::new(s2c, c2s, false);
        let id = client.open_stream();
        client.write(id, b"hello");
        client.finish(id);

        // Ask for at least 8 cells this tick; the real DATA+ACK are topped up with cover.
        let cells = client.outbound_padded(8);
        assert!(cells.len() >= 8, "topped up to the target rate");
        for cell in &cells {
            assert_eq!(
                cell.len(),
                CELL_LEN,
                "cover is byte-indistinguishable from data"
            );
        }
        for cell in &cells {
            service.on_cell(cell);
        }
        let sid = service.accept().expect("the real stream still opened");
        assert_eq!(
            service.read(sid),
            b"hello",
            "padding did not disturb the stream"
        );

        // An idle connection with no streams can still emit pure cover to hold the rate.
        let mut idle = Connection::new(c2s, s2c, true);
        let cover = idle.outbound_padded(5);
        assert_eq!(cover.len(), 5);
        for cell in &cover {
            assert_eq!(cell.len(), CELL_LEN);
        }
    }

    #[test]
    fn implicit_opens_are_capped_to_bound_stream_memory() {
        use fanos_stream::Segment;
        let (c2s, s2c) = ([7u8; 32], [1u8; 32]);
        // A responder: its peer (the initiator) opens EVEN ids (parity 0). Flood far more distinct even
        // ids than the cap — each is a fresh implicit open a malicious peer could use to exhaust memory.
        let mut service = Connection::new(s2c, c2s, false);
        let flood = MAX_CONCURRENT_STREAMS + 50;
        for i in 0..flood {
            let id = (i as u32) * 2; // 0, 2, 4, … all in the peer's parity space
            let cell = seal(
                &c2s,
                i as u64,
                &Frame::Data(Segment {
                    stream_id: id,
                    seq: 0,
                    fin: false,
                    data: vec![1],
                })
                .encode(),
            )
            .unwrap();
            service.on_cell(&cell);
        }
        assert_eq!(
            service.stream_count(),
            MAX_CONCURRENT_STREAMS,
            "a flood of fresh stream ids is capped — it cannot exhaust memory (F2)"
        );
        let mut accepted = 0;
        while service.accept().is_some() {
            accepted += 1;
        }
        assert_eq!(
            accepted, MAX_CONCURRENT_STREAMS,
            "exactly the cap were opened; the rest dropped"
        );
    }

    #[test]
    fn retiring_a_done_stream_frees_its_slot_and_blocks_a_phantom_reopen() {
        use fanos_stream::Segment;
        let (c2s, s2c) = ([2u8; 32], [3u8; 32]);
        let mut client = Connection::new(c2s, s2c, true); // opens even ids
        let mut service = Connection::new(s2c, c2s, false); // peer parity 0 (even)

        let id = client.open_stream(); // 0
        client.write(id, b"ping");
        client.finish(id);

        // Drive both directions to completion (service echoes and finishes so its send side completes too).
        let mut round = 0;
        loop {
            for cell in client.outbound() {
                service.on_cell(&cell);
            }
            while let Some(sid) = service.accept() {
                service.write(sid, b"pong");
                service.finish(sid);
            }
            let _ = service.read(id);
            for cell in service.outbound() {
                client.on_cell(&cell);
            }
            let _ = client.read(id);
            if client.is_stream_done(id) && service.is_stream_done(id) {
                break;
            }
            round += 1;
            assert!(round < 40, "should converge");
        }

        // Retire the completed peer-opened stream: its slot is freed and the frontier advances.
        assert!(service.is_stream_done(id));
        assert!(service.retire_stream(id), "a done stream retires");
        assert_eq!(service.stream_count(), 0, "the slot is reclaimed");
        assert!(
            !service.retire_stream(id),
            "retiring an already-gone id is a no-op"
        );

        // A straggler DATA for the retired id must not resurrect it as a phantom stream.
        let straggler = seal(
            &c2s,
            9_999,
            &Frame::Data(Segment {
                stream_id: id,
                seq: 0,
                fin: false,
                data: vec![9],
            })
            .encode(),
        )
        .unwrap();
        service.on_cell(&straggler);
        assert_eq!(
            service.stream_count(),
            0,
            "a straggler cannot resurrect a retired stream"
        );
        assert!(
            service.accept().is_none(),
            "no phantom stream is queued for accept"
        );

        // Forward progress is unaffected: a genuinely new, higher peer id still opens.
        let fresh = seal(
            &c2s,
            10_000,
            &Frame::Data(Segment {
                stream_id: 2,
                seq: 0,
                fin: false,
                data: vec![5],
            })
            .encode(),
        )
        .unwrap();
        service.on_cell(&fresh);
        assert_eq!(
            service.accept(),
            Some(2),
            "a fresh higher id still opens after retirement"
        );
    }

    #[test]
    fn reset_aborts_a_stream_both_ways_and_blocks_reopen() {
        use fanos_stream::Segment;
        let (c2s, s2c) = ([1u8; 32], [2u8; 32]);
        let mut client = Connection::new(c2s, s2c, true); // opens even ids
        let mut service = Connection::new(s2c, c2s, false); // peer parity 0 (even)

        let id = client.open_stream(); // 0
        client.write(id, b"hello");
        client.finish(id);
        // Deliver so the service implicitly opens the stream.
        for cell in client.outbound() {
            service.on_cell(&cell);
        }
        assert_eq!(service.accept(), Some(id));
        assert_eq!(service.stream_count(), 1);

        // The service aborts the (peer-opened, never-to-complete) stream, reclaiming the slot at once.
        let reset = service.reset_stream(id).expect("a known stream resets");
        assert_eq!(
            service.stream_count(),
            0,
            "reset frees the slot immediately"
        );
        assert!(
            service.reset_stream(id).is_none(),
            "resetting an unknown stream is a no-op"
        );

        // The peer's reset drops the client's side too.
        client.on_cell(&reset);
        assert_eq!(client.stream_count(), 0, "the peer's reset aborts our side");

        // A straggler DATA for the reset id cannot resurrect it as a phantom on the service side.
        let straggler = seal(
            &c2s,
            9_999,
            &Frame::Data(Segment {
                stream_id: id,
                seq: 0,
                fin: false,
                data: vec![9],
            })
            .encode(),
        )
        .unwrap();
        service.on_cell(&straggler);
        assert_eq!(
            service.stream_count(),
            0,
            "a straggler cannot re-open a reset stream"
        );
        assert!(service.accept().is_none());
    }

    #[test]
    fn the_connection_hard_kills_at_nonce_exhaustion_rather_than_reusing_a_nonce() {
        // Nonce reuse would be catastrophic for the AEAD, so at the top of the 2⁶⁴ nonce space the
        // connection refuses to mint any further cell rather than wrap.
        let mut c = Connection::new([1u8; 32], [2u8; 32], true);
        c.nonce_tx = u64::MAX - 2; // two nonces from the top
        // Exactly the two remaining nonces are usable; then the space is spent.
        assert_eq!(
            c.outbound_padded(10).len(),
            2,
            "only the two remaining nonces are minted"
        );
        // Exhausted: NO further cell is minted, through any path (no wrap, no reuse).
        assert!(
            c.outbound_padded(10).is_empty(),
            "no cover cell after exhaustion"
        );
        assert!(c.outbound().is_empty(), "no data/ack cell after exhaustion");
        let id = c.open_stream();
        c.write(id, b"x");
        assert!(
            c.reset_stream(id).is_none(),
            "cannot even mint a RESET cell after exhaustion"
        );
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
