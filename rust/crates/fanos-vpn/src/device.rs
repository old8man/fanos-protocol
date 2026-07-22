//! The real OS TUN device adapter (feature `device`).
//!
//! Implements the [`TunReader`] / [`TunWriter`] seam over the platform `tun` crate, so [`run_vpn`] drives an
//! actual `/dev/net/tun` (Linux) / `utun` (macOS) device. **This is the OS I/O shell** — its device syscalls
//! need root and a TUN device, so it is runtime-verified only (on a real host); the datapath core (codec →
//! engine → multiplexer → driver) is verified without this module. `tun`'s own `unsafe` ioctls stay inside
//! that crate — this module is safe, keeping `fanos-vpn` `forbid(unsafe_code)`.
//!
//! [`run_vpn`]: crate::run_vpn

use std::io;
use std::sync::Arc;

use tun::AsyncDevice;

use crate::driver::{TunReader, TunWriter};

/// The read buffer size — the IP maximum, so no packet is ever truncated (the interface MTU is normally far
/// smaller, but a jumbo frame must still round-trip intact).
const MAX_PACKET: usize = 65536;

/// The read half of an opened TUN device.
pub struct TunDeviceReader {
    device: Arc<AsyncDevice>,
    buf: Vec<u8>,
}

/// The write half of an opened TUN device.
pub struct TunDeviceWriter {
    device: Arc<AsyncDevice>,
}

/// Open the TUN device `name` (or an OS-assigned name when empty), bring it up, and split it into a reader
/// and writer that share the device. The caller assigns the interface an address and route (via the OS or a
/// config) so the kernel steers traffic to it; pass the pair to [`run_vpn`](crate::run_vpn).
///
/// # Errors
/// Propagates the device-creation error — most often insufficient privilege (needs root / `CAP_NET_ADMIN`),
/// or the requested name is unavailable.
pub fn open(name: &str) -> io::Result<(TunDeviceReader, TunDeviceWriter)> {
    let device = Arc::new(open_tun(name)?);
    Ok((
        TunDeviceReader { device: Arc::clone(&device), buf: vec![0u8; MAX_PACKET] },
        TunDeviceWriter { device },
    ))
}

/// Open the raw async TUN device `name` (or OS-assigned when empty), brought up. The returned
/// [`AsyncDevice`] is `AsyncRead + AsyncWrite`, ready to hand to the full-tunnel stack
/// ([`run_fulltunnel`](crate::run_fulltunnel)). The caller assigns its address/route.
///
/// # Errors
/// Propagates the device-creation error (typically insufficient privilege).
pub fn open_tun(name: &str) -> io::Result<AsyncDevice> {
    let mut config = tun::Configuration::default();
    if !name.is_empty() {
        config.tun_name(name);
    }
    config.up();
    tun::create_as_async(&config).map_err(io::Error::other)
}

impl TunReader for TunDeviceReader {
    async fn recv_packet(&mut self) -> Option<Vec<u8>> {
        // A device error (including EOF on close) ends the datapath.
        let n = self.device.recv(&mut self.buf).await.ok()?;
        Some(self.buf.get(..n)?.to_vec())
    }
}

impl TunWriter for TunDeviceWriter {
    async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.device.send(packet).await.map(|_| ())
    }
}
