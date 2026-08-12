//! The full-tunnel datapath, exercised end to end without a TUN device or root.
//!
//! `docs/open-tasks.md` recorded `fanos-vpn` as linked-but-unexercised: `fanos vpn` reaches `run_fulltunnel`, CI compiles
//! `--features vpn`, and `fulltunnel.rs` carried **zero tests** — so the platform's full-tunnel claim rested on code no
//! test had ever run. The linkage ratchet in `fanos-cli/tests/architecture.rs` structurally cannot see this: linkage is
//! computable from manifests, "is this code ever run" is not.
//!
//! It is testable because `run_fulltunnel` is generic over both of its edges — the device is any
//! `AsyncRead + AsyncWrite`, and the exit is any `Dialer + UdpDialer`. So a `tokio::io::duplex` stands in for the TUN and
//! a recording dialer stands in for the exit, and what is exercised is the real path: bytes → `ipstack` → flow accept →
//! per-flow bridge → dial to the flow's original destination.

#![cfg(feature = "device")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use fanos_proxy::Target;
use fanos_proxy::dialer::{DialError, Dialer, UdpDialer, UdpTunnel};
use fanos_vpn::fulltunnel::run_fulltunnel;
use fanos_vpn::packet::build_ipv4_udp;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// A dialer that records what it was asked to reach and echoes datagrams back.
struct Recorder {
    /// Every `dial_udp` target, in order. A std mutex, held only to push — no await inside it.
    udp_targets: StdMutex<Vec<Target>>,
    /// Datagrams the datapath pushed toward the destination.
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Set when a TCP dial arrives, so a UDP-only test can assert the paths are not confused.
    tcp_seen: AtomicBool,
}

impl Recorder {
    fn new() -> Self {
        Self {
            udp_targets: StdMutex::new(Vec::new()),
            sent: Arc::new(Mutex::new(Vec::new())),
            tcp_seen: AtomicBool::new(false),
        }
    }
}

impl Dialer for Recorder {
    type Stream = tokio::io::DuplexStream;

    fn dial(&self, _target: &Target) -> impl Future<Output = Result<Self::Stream, DialError>> + Send {
        self.tcp_seen.store(true, Ordering::SeqCst);
        async { Err(DialError::Refused) }
    }
}

impl UdpDialer for Recorder {
    fn dial_udp(&self, target: &Target) -> impl Future<Output = Result<UdpTunnel, DialError>> + Send {
        // Recorded here, synchronously, rather than inside the future: the target is what this test asserts on, and
        // deferring it into the async block would make the assertion depend on the task having been polled.
        if let Ok(mut targets) = self.udp_targets.lock() {
            targets.push(target.clone());
        }
        let sent = Arc::clone(&self.sent);
        async move {
            let (tunnel, inbound_tx, mut outbound_rx) = UdpTunnel::pair(fanos_proxy::budget::UDP_TUNNEL_BUFFER);
            tokio::spawn(async move {
                while let Some(datagram) = outbound_rx.recv().await {
                    // Record the bytes, then forward the datagram itself: a `Datagram` is deliberately not
                    // `Clone`, because cloning one would duplicate the bytes while the pool had been charged
                    // for a single copy (#300).
                    sent.lock().await.push(datagram.to_vec());
                    // Echo, so the return leg is exercised too rather than only the outbound one.
                    if inbound_tx.forward(datagram).await.is_err() {
                        break;
                    }
                }
            });
            Ok(tunnel)
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_udp_datagram_written_to_the_device_is_dialed_to_its_original_destination() {
    // The datapath's whole promise in one assertion: a packet the kernel would route to the TUN leaves through the exit
    // addressed to where the application sent it — not to the tunnel endpoint, and not dropped.
    let (mut app, device) = tokio::io::duplex(64 * 1024);
    let dialer = Arc::new(Recorder::new());
    let watch = Arc::clone(&dialer);
    tokio::spawn(run_fulltunnel(device, dialer));

    let dst = (Ipv4Addr::new(203, 0, 113, 9), 5353);
    let packet = build_ipv4_udp((Ipv4Addr::new(10, 0, 0, 2), 40404), dst, b"fanos-datapath");
    app.write_all(&packet).await.expect("the device accepts the packet");
    app.flush().await.expect("flushed");

    // Poll rather than sleep: the stack and the per-flow task are concurrent, and a fixed sleep is either flaky or slow.
    let mut seen = Vec::new();
    for _ in 0..200 {
        seen = watch.sent.lock().await.clone();
        if !seen.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    assert_eq!(seen, vec![b"fanos-datapath".to_vec()], "the payload reached the exit unchanged");
    assert!(!watch.tcp_seen.load(Ordering::SeqCst), "a UDP flow must not be bridged as TCP");

    // And it was dialed to the ORIGINAL destination, which is the property that distinguishes a tunnel from a proxy: the
    // exit must reach 203.0.113.9:5353, not the tunnel endpoint.
    let targets = watch.udp_targets.lock().expect("not poisoned").clone();
    assert_eq!(
        targets,
        vec![Target::Ip(std::net::SocketAddr::from((dst.0, dst.1)))],
        "one dial, to the packet's own destination"
    );
}
