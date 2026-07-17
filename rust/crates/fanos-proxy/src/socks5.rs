//! The SOCKS5 wire protocol (RFC 1928) — CONNECT only.
//!
//! [`serve`] accepts connections on a listener and drives each through [`handle`]: negotiate
//! (no-auth), read the CONNECT request into a [`Target`], ask the [`Dialer`], reply, then splice the
//! two byte streams. UDP ASSOCIATE and BIND are intentionally unsupported (rejected cleanly) until
//! the overlay UDP path lands.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

use crate::dialer::Dialer;
use crate::target::Target;

const VER: u8 = 5;
const CMD_CONNECT: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;
const REP_SUCCESS: u8 = 0x00;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;
const METHOD_NO_AUTH: u8 = 0x00;

/// The outcome of reading a request: a target to connect, or a reply code to reject with.
enum Request {
    Connect(Target),
    Reject(u8),
}

/// Negotiate the method: we require the client to offer "no authentication".
async fn negotiate(client: &mut TcpStream) -> std::io::Result<bool> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    let [ver, nmethods] = head;
    if ver != VER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not SOCKS5",
        ));
    }
    let mut methods = vec![0u8; usize::from(nmethods)];
    client.read_exact(&mut methods).await?;
    let ok = methods.contains(&METHOD_NO_AUTH);
    // 0xFF = "no acceptable methods" if the client won't do no-auth.
    let reply = if ok { METHOD_NO_AUTH } else { 0xFF };
    client.write_all(&[VER, reply]).await?;
    Ok(ok)
}

async fn read_port(client: &mut TcpStream) -> std::io::Result<u16> {
    let mut p = [0u8; 2];
    client.read_exact(&mut p).await?;
    Ok(u16::from_be_bytes(p))
}

/// Read a CONNECT request into a [`Target`], or a rejection reply code.
async fn read_request(client: &mut TcpStream) -> std::io::Result<Request> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let [ver, cmd, _rsv, atyp] = head;
    if ver != VER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not SOCKS5",
        ));
    }
    if cmd != CMD_CONNECT {
        return Ok(Request::Reject(REP_CMD_NOT_SUPPORTED));
    }
    let target = match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            client.read_exact(&mut b).await?;
            let port = read_port(client).await?;
            Target::Ip(SocketAddr::from((Ipv4Addr::from(b), port)))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            client.read_exact(&mut b).await?;
            let port = read_port(client).await?;
            Target::Ip(SocketAddr::from((Ipv6Addr::from(b), port)))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let [len] = len;
            let mut name = vec![0u8; usize::from(len)];
            client.read_exact(&mut name).await?;
            let port = read_port(client).await?;
            let host = String::from_utf8(name).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF8 host")
            })?;
            Target::Name(host, port)
        }
        _ => return Ok(Request::Reject(REP_ATYP_NOT_SUPPORTED)),
    };
    Ok(Request::Connect(target))
}

/// Write a SOCKS5 reply with `code` and a null bound address (`0.0.0.0:0`).
async fn write_reply(client: &mut TcpStream, code: u8) -> std::io::Result<()> {
    client
        .write_all(&[VER, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

/// Handle one accepted SOCKS5 client end to end.
///
/// # Errors
/// Propagates I/O errors from the handshake; a failed *dial* is reported to the client as a SOCKS5
/// reply, not an error return.
pub async fn handle<D: Dialer>(mut client: TcpStream, dialer: &D) -> std::io::Result<()> {
    if !negotiate(&mut client).await? {
        return Ok(()); // method rejected; connection closes
    }
    let target = match read_request(&mut client).await? {
        Request::Connect(t) => t,
        Request::Reject(code) => {
            write_reply(&mut client, code).await?;
            return Ok(());
        }
    };

    match dialer.dial(&target).await {
        Ok(mut upstream) => {
            write_reply(&mut client, REP_SUCCESS).await?;
            // Splice the two streams until either side closes.
            let _ = copy_bidirectional(&mut client, &mut upstream).await;
            Ok(())
        }
        Err(e) => {
            tracing::debug!(%target, error = %e, "dial failed");
            write_reply(&mut client, e.socks5_reply_code()).await
        }
    }
}

/// Accept and serve SOCKS5 clients on `listener`, dialing each target through `dialer`.
///
/// # Errors
/// Returns an I/O error only if `accept` itself fails; per-connection errors are logged and dropped.
pub async fn serve<D>(listener: TcpListener, dialer: D) -> std::io::Result<()>
where
    D: Dialer + Clone + Send + Sync + 'static,
{
    loop {
        let (client, peer) = listener.accept().await?;
        let dialer = dialer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(client, &dialer).await {
                tracing::debug!(%peer, error = %e, "socks5 connection ended");
            }
        });
    }
}
