//! The VPN device driver (spec §11.4): bridge a TUN device to the UDP datapath multiplexer.
//!
//! The device is abstracted behind [`TunReader`] / [`TunWriter`] so the whole bridge — device → multiplexer
//! → exit tunnels → device — is testable with an in-memory device and a mock dialer; a real TUN device
//! (`/dev/net/tun` / `utun`) is a thin adapter implementing these two traits (the only part that touches the
//! OS and so the only part not exercisable in CI). This keeps the crate `forbid(unsafe_code)` — the raw
//! device syscalls live behind a safe `tun`-crate wrapper in the binary, not here.

use std::future::Future;

use fanos_proxy::UdpDialer;
use tokio::sync::mpsc;

use crate::mux::run_udp_datapath;

/// Channel depth between the device and the multiplexer — a burst of packets buffers here before backpressure.
const DEVICE_QUEUE: usize = 256;

/// The inbound half of a TUN device: yields the next IP packet the OS wrote to the device, or `None` when
/// the device closes. A real implementation reads the TUN file descriptor; a test supplies packets in memory.
pub trait TunReader: Send + 'static {
    /// Read the next packet from the device (`None` = the device closed).
    fn recv_packet(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// The outbound half of a TUN device: writes an IP packet back to the OS through the device.
pub trait TunWriter: Send + 'static {
    /// Write `packet` to the device.
    fn send_packet(&self, packet: &[u8]) -> impl Future<Output = std::io::Result<()>> + Send;
}

/// Run the VPN UDP datapath over a TUN device: pump inbound packets from `reader` into the multiplexer,
/// relay each UDP flow over `dialer`'s exit tunnels, and write the response packets back through `writer`.
/// Returns when the device's `reader` closes.
pub async fn run_vpn<R, W, D>(mut reader: R, writer: W, dialer: D)
where
    R: TunReader,
    W: TunWriter,
    D: UdpDialer + Send + 'static,
{
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(DEVICE_QUEUE);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(DEVICE_QUEUE);

    // Device → multiplexer: dropping `in_tx` when the device closes ends the multiplexer.
    let ingest = tokio::spawn(async move {
        while let Some(packet) = reader.recv_packet().await {
            if in_tx.send(packet).await.is_err() {
                break;
            }
        }
    });
    // Multiplexer → device: ends when `out_tx` (held by the multiplexer) drops.
    let egest = tokio::spawn(async move {
        while let Some(packet) = out_rx.recv().await {
            if writer.send_packet(&packet).await.is_err() {
                break;
            }
        }
    });

    run_udp_datapath(dialer, in_rx, out_tx).await;
    ingest.abort();
    egest.abort();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use fanos_proxy::dialer::EchoDialer;
    use tokio::time::timeout;

    use super::*;
    use crate::packet::{build_ipv4_udp, parse_udp};

    const CLIENT4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const RESOLVER4: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
    const CLIENT: IpAddr = IpAddr::V4(CLIENT4);
    const RESOLVER: IpAddr = IpAddr::V4(RESOLVER4);

    /// An in-memory TUN device: `recv_packet` drains a channel the test feeds; `send_packet` forwards to a
    /// channel the test reads. Standing in for the real `/dev/net/tun` fd.
    struct ChannelReader(mpsc::Receiver<Vec<u8>>);
    impl TunReader for ChannelReader {
        async fn recv_packet(&mut self) -> Option<Vec<u8>> {
            self.0.recv().await
        }
    }
    struct ChannelWriter(mpsc::Sender<Vec<u8>>);
    impl TunWriter for ChannelWriter {
        async fn send_packet(&self, packet: &[u8]) -> std::io::Result<()> {
            self.0.send(packet.to_vec()).await.ok();
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_vpn_bridges_a_tun_device_through_the_datapath() {
        let (feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(8);
        let (sent_tx, mut sent_rx) = mpsc::channel::<Vec<u8>>(8);
        tokio::spawn(run_vpn(
            ChannelReader(feed_rx),
            ChannelWriter(sent_tx),
            EchoDialer,
        ));

        // A DNS query "arrives" at the TUN; it must come back out of the TUN as a reply packet from the
        // resolver to the client (the echo dialer stands in for the exit).
        let query = build_ipv4_udp((CLIENT4, 5555), (RESOLVER4, 53), b"dns-query");
        feed_tx.send(query).await.unwrap();
        let out = timeout(Duration::from_secs(2), sent_rx.recv())
            .await
            .expect("no timeout")
            .expect("a packet is written back to the device");
        let dg = parse_udp(&out).unwrap();
        assert_eq!(dg.src, (RESOLVER, 53));
        assert_eq!(dg.dst, (CLIENT, 5555));
        assert_eq!(dg.payload, b"dns-query");
    }
}
