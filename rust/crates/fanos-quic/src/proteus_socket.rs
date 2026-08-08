//! The PROTEUS envelope **under** QUIC — an [`AsyncUdpSocket`] decorator (spec §13.3, §13.5).
//!
//! Every datagram this node sends is sealed with
//! [`fanos_proteus::datagram`](fanos_proteus::datagram); every datagram it receives must open, or it is
//! dropped before quinn ever parses it. The handshake travels inside the envelope like everything else, so
//! there is no plaintext ALPN, SNI or version list on the wire and an unauthenticated prober gets silence
//! instead of a Version Negotiation packet.
//!
//! ## Why a decorator, and not a change inside the driver
//!
//! The seam already existed for the simulator: [`Fabric::Abstract`](crate::Fabric) hands quinn any
//! `AsyncUdpSocket`. Putting the envelope there means the *same* code path carries it in production, in the
//! simulator and in the tests — the simulator-fidelity rule (differ in the transport, and only there) is
//! kept rather than spent.
//!
//! ## The envelope is configuration, not a dial — and that is derived, not preference
//!
//! A morph rotation (§13.7 auto-fallback) is explicitly a **local** decision: every codec-using morph
//! shares one wire codec, so a node walks the chain without renegotiating. Sealing is not like that. It is
//! a property both ends must agree on before the first packet, so it cannot be flipped by a local breaker
//! mid-flight without cutting every live connection. It is therefore decided **once**, at socket
//! construction, from the configured morph, and a later rotation does not move it.
//!
//! [`Morph::Plain`] is the one morph that does not seal: it exists to be indistinguishable from ordinary
//! QUIC on an uncensored network at zero overhead, and an envelope would be exactly the overhead it
//! declines.
//!
//! ## Batching
//!
//! GSO/GRO are off ([`max_transmit_segments`] and [`max_receive_segments`] pinned to 1). A segmented
//! `Transmit` is *N* datagrams in one buffer that the kernel splits on a fixed stride; sealing changes each
//! one's length, so the stride no longer describes them. Stated here rather than left to the trait default,
//! because the default silently being 1 is not the same as the value being load-bearing.
//!
//! [`max_transmit_segments`]: AsyncUdpSocket::max_transmit_segments
//! [`max_receive_segments`]: AsyncUdpSocket::max_receive_segments

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use fanos_runtime::ports::stations::{Station, Stations};
use fanos_proteus::obfuscate::NONCE_LEN;
use fanos_proteus::{Morph, ProteusShaper};

/// A socket that seals every outbound datagram and opens every inbound one, dropping what does not open.
#[derive(Debug)]
pub(crate) struct ProteusSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    /// The same shaper the frame layer uses, so the datagram envelope rotates on the same epoch turn and
    /// accepts the same grace window — one shape authority, not two that can disagree at a boundary.
    shaper: Arc<RwLock<ProteusShaper>>,
    /// The driver's station plane. A drop here is *invisible by design* — no reply, no error, nothing
    /// downstream — so if it is not counted at this exact spot, a node under active probing reads as idle on
    /// every surface it has. This is the outermost gate; there is no later one to catch it.
    stations: Arc<Mutex<Stations>>,
}

impl ProteusSocket {
    /// Wrap `inner` iff `shaper`'s morph seals. Returns the bare socket for [`Morph::Plain`], so the
    /// zero-overhead open-network path stays byte-for-byte native QUIC.
    ///
    /// Reading the morph here — once — is what makes the envelope configuration rather than a dial; see
    /// this module's header.
    pub(crate) fn wrap(
        inner: Arc<dyn AsyncUdpSocket>,
        shaper: &Arc<RwLock<ProteusShaper>>,
        stations: &Arc<Mutex<Stations>>,
    ) -> Arc<dyn AsyncUdpSocket> {
        let seals = shaper
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .morph()
            != Morph::Plain;
        if !seals {
            return inner;
        }
        Arc::new(Self {
            inner,
            shaper: Arc::clone(shaper),
            stations: Arc::clone(stations),
        })
    }

    /// A fresh per-datagram nonce from the OS CSPRNG.
    ///
    /// **Not a counter, and the reason is that two peers share `θ`.** Both ends of a community derive the
    /// same epoch shape, so two nodes whose counters both start at zero would produce the same keystream
    /// for their first datagram — and a QUIC Initial is *structured*, so the XOR of two of them leaks the
    /// header. Drawing at random makes a repeat a birthday event over 2⁶⁴, re-based every epoch.
    fn nonce() -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        // A failure here would mean the OS entropy source is gone. Falling back to a counter would silently
        // reintroduce exactly the collision above, so the datagram is dropped instead: loud, and recovered
        // by QUIC's own retransmission if entropy returns.
        if getrandom::fill(&mut n).is_err() {
            return [0u8; NONCE_LEN];
        }
        n
    }
}

impl AsyncUdpSocket for ProteusSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let nonce = Self::nonce();
        if nonce == [0u8; NONCE_LEN] {
            return Err(io::Error::other("no OS entropy for a PROTEUS datagram nonce"));
        }
        let sealed = self
            .shaper
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .seal_datagram(transmit.contents, &nonce);
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &sealed,
            // Pinned to `None` by `max_transmit_segments` above; restated so a future quinn that stops
            // asking cannot turn this into a silent stride mismatch.
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let n = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
            let shaper = self.shaper.read().unwrap_or_else(PoisonError::into_inner);

            // Compact in place: datagram `i` that opens moves to slot `kept`. A stranger's datagram is
            // simply not carried forward — no reply, no error, no trace on the wire, which is §13.5.
            let mut kept = 0usize;
            let mut refused = 0u64;
            for i in 0..n {
                let (Some(buf), Some(m)) = (bufs.get_mut(i), meta.get(i).copied()) else {
                    continue;
                };
                let Some(len) = shaper.open_datagram(buf.get_mut(..m.len).unwrap_or(&mut [])) else {
                    refused += 1;
                    continue;
                };
                if kept != i {
                    let (left, right) = bufs.split_at_mut(i);
                    let (Some(dst), Some(src)) = (left.get_mut(kept), right.first()) else {
                        continue;
                    };
                    let Some(dst) = dst.get_mut(..len) else { continue };
                    let Some(src) = src.get(..len) else { continue };
                    dst.copy_from_slice(src);
                }
                if let Some(slot) = meta.get_mut(kept) {
                    *slot = RecvMeta { len, stride: len, ..m };
                }
                kept += 1;
            }
            if refused > 0 {
                self.stations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .record_n(Station::WireForeignDatagram, None, refused);
            }
            // Every datagram in this batch was a stranger's. Returning `Ok(0)` would tell quinn a readiness
            // event produced nothing and risks a spin; go back to the socket instead, which either yields
            // more datagrams or registers the waker and parks.
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// See the module header: sealing changes each datagram's length, so a segmented `Transmit`'s fixed
    /// stride would no longer describe the wire.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    /// The receive side of the same argument: a GRO batch arrives as one buffer with a fixed stride, and
    /// the sealed datagrams in it do not share one.
    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
