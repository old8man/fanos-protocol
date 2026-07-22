//! Full-tunnel mode (spec §11.4) — the complete TCP + UDP datapath (feature `device`).
//!
//! A userspace TCP/IP stack ([`ipstack`]) terminates the client's TCP and UDP at the TUN, and each accepted
//! flow is bridged to a FANOS **exit**: a TCP connection over [`Dialer::dial`] (a byte-stream exit, spliced
//! with `copy_bidirectional`), a UDP flow over [`UdpDialer::dial_udp`] (the exit UDP tunnel). It reuses the
//! exact `Dialer` / `UdpDialer` seams the SOCKS5 proxy uses, so the VPN and the proxy share one exit
//! abstraction and the same production `FanosDialer`-with-exit. ipstack does the TCP state machine; this is
//! the thin exit bridge on top. (The lightweight [`crate::mux`] UDP datapath is the device-/stack-free
//! alternative for embedders that don't want the ipstack dependency.)

use std::sync::Arc;

use fanos_proxy::{Dialer, Target, UdpDialer};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};

/// The read buffer for a UDP flow (the IP maximum — a datagram is one read from the stack's UDP stream).
const UDP_BUF: usize = 65535;

/// Run full-tunnel mode over `device` (a TUN presented as an async byte device): accept each TCP/UDP flow
/// the kernel routes to the TUN and bridge it to the exit via `dialer`. Returns when the device closes.
///
/// `dialer` must reach clearnet targets — a `FanosDialer` with an exit configured; every flow leaves through
/// it. TCP and UDP each spawn a per-flow bridge task, so many flows run concurrently.
pub async fn run_fulltunnel<Dev, D>(device: Dev, dialer: Arc<D>)
where
    Dev: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    D: Dialer + UdpDialer + Send + Sync + 'static,
{
    let mut stack = IpStack::new(IpStackConfig::default(), device);
    while let Ok(stream) = stack.accept().await {
        match stream {
            IpStackStream::Tcp(tcp) => {
                tokio::spawn(bridge_tcp(tcp, Arc::clone(&dialer)));
            }
            IpStackStream::Udp(udp) => {
                tokio::spawn(bridge_udp(udp, Arc::clone(&dialer)));
            }
            // ICMP / unparsable network packets are not tunnelled.
            IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {}
        }
    }
}

/// Bridge one TCP connection: dial the exit to the flow's original destination and splice the two streams.
async fn bridge_tcp<D: Dialer>(mut tcp: IpStackTcpStream, dialer: Arc<D>) {
    let dst = tcp.peer_addr();
    if let Ok(mut exit) = dialer.dial(&Target::Ip(dst)).await {
        let _ = copy_bidirectional(&mut tcp, &mut exit).await;
    }
}

/// Bridge one UDP flow: open an exit UDP tunnel to the destination and shuttle datagrams both ways (each
/// read from the stack's UDP stream is one datagram; the tunnel carries them to the exit and back).
async fn bridge_udp<D: UdpDialer>(mut udp: IpStackUdpStream, dialer: Arc<D>) {
    let dst = udp.peer_addr();
    let Ok(mut tunnel) = dialer.dial_udp(&Target::Ip(dst)).await else {
        return;
    };
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        tokio::select! {
            read = udp.read(&mut buf) => {
                let Ok(n) = read else { break };
                if n == 0 {
                    break;
                }
                if tunnel.outbound.send(buf.get(..n).unwrap_or(&[]).to_vec()).await.is_err() {
                    break;
                }
            }
            reply = tunnel.inbound.recv() => {
                let Some(datagram) = reply else { break };
                if udp.write_all(&datagram).await.is_err() {
                    break;
                }
            }
        }
    }
}
