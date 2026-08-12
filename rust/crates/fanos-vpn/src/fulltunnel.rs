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

use crate::mux::STACK_MTU;

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
    let mut config = IpStackConfig::default();
    // Request `STACK_MTU`, then **read back what the config actually holds** and size every flow buffer from
    // that (#247). The setter is fallible — it refuses anything below ipstack's own minimum — and the two
    // ways of coping with a refusal are both wrong: panicking turns a dependency bump into a node that will
    // not start, and ignoring it leaves the stack at an MTU larger than the buffer, which truncates
    // datagrams and looks like packet loss on the tunnel. Reading the value back removes the question: the
    // buffer is whatever the stack is going to use, by construction, so there is nothing left to keep in
    // sync.
    let _ = config.mtu(STACK_MTU);
    let flow_buf = config.mtu as usize;
    let mut stack = IpStack::new(config, device);
    while let Ok(stream) = stack.accept().await {
        match stream {
            IpStackStream::Tcp(tcp) => {
                tokio::spawn(bridge_tcp(tcp, Arc::clone(&dialer)));
            }
            IpStackStream::Udp(udp) => {
                tokio::spawn(bridge_udp(udp, Arc::clone(&dialer), flow_buf));
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
/// `buf_len` is the stack's own MTU, handed down rather than re-derived: a read from the UDP stream yields at
/// most `mtu − (ip_header_len + udp_header_len)` (`ipstack::stream::udp`), so one MTU is a strict upper bound
/// with the header slack as margin, and the IPv4/IPv6 header difference stays inside the dependency where it
/// belongs.
async fn bridge_udp<D: UdpDialer>(mut udp: IpStackUdpStream, dialer: Arc<D>, buf_len: usize) {
    let dst = udp.peer_addr();
    let Ok(mut tunnel) = dialer.dial_udp(&Target::Ip(dst)).await else {
        return;
    };
    let mut buf = vec![0u8; buf_len];
    loop {
        tokio::select! {
            read = udp.read(&mut buf) => {
                let Ok(n) = read else { break };
                if n == 0 {
                    break;
                }
                // Non-blocking, UDP-lossy (matching the mux): a blocking `send().await` here would stall the
                // whole select — and so the reply direction — whenever the exit tunnel is backed up. Drop on
                // a full tunnel; stop only when it has closed.
                match tunnel.outbound.try_send(buf.get(..n).unwrap_or(&[]).to_vec()) {
                    Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The theoretical IP datagram maximum — what the per-flow buffer used to be. Only the ratchet needs it,
    /// so it lives here: a production constant nothing reads is the next thing someone reaches for.
    const IP_MAXIMUM: usize = 65535;

    /// **Every flow buffer is the MTU the stack is actually running at, not a number someone liked (#247).**
    ///
    /// The buffer is no longer a constant at all — `run_fulltunnel` reads `config.mtu` back after asking for
    /// [`STACK_MTU`] and hands that down — so the two cannot drift and there is no equality left to restate.
    /// What this checks is the pair of facts that make the arrangement worth anything:
    ///
    /// 1. The config really carries `STACK_MTU` after production's own sequence. If the setter had refused
    ///    or clamped, flows would be sized from a different number than this test reasons about, and the
    ///    ratchet below would be guarding the wrong quantity.
    /// 2. That number is nowhere near the IP maximum. This is the ratchet: the buffer was
    ///    `IP_MAXIMUM` **per flow**, and `crate::mux::MAX_UDP_FLOWS` of those is 268 MB of resident memory
    ///    against a documented 256 MiB node — for packets that could never exceed ~1252 bytes, so 1.9 % of
    ///    each buffer was reachable. An edit that "restores the safe ceiling" fails here.
    #[test]
    fn a_flow_buffer_is_one_mtu_of_the_stack_this_build_configures() {
        let mut config = IpStackConfig::default();
        let _ = config.mtu(STACK_MTU);
        assert_eq!(
            config.mtu, STACK_MTU,
            "the stack refused or clamped the requested MTU, so flows are sized from something this test \
             does not know about"
        );

        let flow_buf = config.mtu as usize;
        assert!(
            flow_buf * 8 < IP_MAXIMUM,
            "a flow buffer of {flow_buf} is within a factor of 8 of the IP maximum — it is allocated PER \
             FLOW, and MAX_UDP_FLOWS of them is what made this 268 MB of resident buffer (#247)"
        );
    }
}
