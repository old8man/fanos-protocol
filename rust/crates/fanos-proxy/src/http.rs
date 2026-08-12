//! The HTTP `CONNECT` proxy method (RFC 9110 §9.3.6) — the second client-facing surface beside
//! SOCKS5 (spec §11.3).
//!
//! Read a `CONNECT host:port HTTP/1.1` request head, ask the [`Dialer`] to reach that authority,
//! reply `200 Connection Established`, then splice the tunnelled bytes until either side closes.
//! Only the `CONNECT` method is served — a forward TCP tunnel, exactly what a browser's HTTPS proxy
//! setting speaks. FANOS carries opaque byte streams, so plain-HTTP request proxying is deliberately
//! out of scope (it would require parsing/forwarding request bodies the tunnel model never sees).
//!
//! Reachability policy is entirely the `Dialer`'s: a `.fanos` authority routes over the overlay, and
//! a clear-net authority is refused until an exit is configured — the identical seam SOCKS5 uses, so
//! the two surfaces share one policy and one dialer.

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional_with_sizes};
use tokio::net::{TcpListener, TcpStream};

use crate::dialer::{DialError, Dialer};
use crate::target::Target;

/// The largest request head (the lines before the terminating blank line) we buffer before rejecting
/// — a bound so a client cannot make us allocate without end before it even names a target.
const MAX_HEAD: usize = 8 * 1024;

/// Parse the `host:port` authority of a `CONNECT` request line into a [`Target`]. Handles a bracketed
/// IPv6 literal (`[::1]:443`). An IP literal becomes [`Target::Ip`]; anything else a [`Target::Name`]
/// (a `.fanos` service or a clear-net host — the dialer decides which it will serve).
fn parse_authority(authority: &str) -> Option<Target> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?; // `[v6]:port`
        (h, p)
    } else {
        authority.rsplit_once(':')? // `host:port` (rsplit so a bare host without ':' is rejected)
    };
    let port: u16 = port.parse().ok()?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Some(Target::Ip(std::net::SocketAddr::new(ip, port)))
    } else {
        Some(Target::Name(host.to_owned(), port))
    }
}

/// Read the request head up to the terminating `CRLFCRLF` and extract the `CONNECT` authority.
/// `Ok(None)` for anything malformed, oversized, a non-`CONNECT` method, or a premature close — the
/// caller answers those with a `400`, never an error return.
async fn read_connect(client: &mut TcpStream) -> std::io::Result<Option<Target>> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Ok(None);
        }
        if client.read(&mut byte).await? == 0 {
            return Ok(None); // closed before a complete head
        }
        head.push(byte[0]);
    }
    // The request line is the first CRLF-terminated line: `CONNECT <authority> HTTP/1.1`.
    let Some(line) = head.split(|&b| b == b'\r').next() else {
        return Ok(None);
    };
    let Ok(line) = core::str::from_utf8(line) else {
        return Ok(None);
    };
    let mut parts = line.split_whitespace();
    if parts.next() != Some("CONNECT") {
        return Ok(None); // only the tunnel method is served
    }
    let Some(authority) = parts.next() else {
        return Ok(None);
    };
    Ok(parse_authority(authority))
}

/// The HTTP status line for a failed dial, chosen to mirror the SOCKS5 reply-code semantics.
fn failure_status(err: &DialError) -> &'static [u8] {
    match err {
        DialError::Refused => b"HTTP/1.1 403 Forbidden\r\n\r\n",
        DialError::Unsupported(_) => b"HTTP/1.1 501 Not Implemented\r\n\r\n",
        DialError::Unreachable | DialError::Io(_) => b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
    }
}

/// Handle one accepted HTTP `CONNECT` client end to end.
///
/// # Errors
/// Propagates I/O errors from reading the head or writing the reply; a failed *dial* is reported to
/// the client as an HTTP status, not an error return (matching [`socks5::handle`](crate::socks5::handle)).
pub async fn handle<D: Dialer>(mut client: TcpStream, dialer: &D) -> std::io::Result<()> {
    let Some(target) = read_connect(&mut client).await? else {
        client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        return Ok(());
    };
    match dialer.dial(&target).await {
        Ok(mut upstream) => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let _ = copy_bidirectional_with_sizes(
                &mut client,
                &mut upstream,
                crate::budget::RELAY_BUF,
                crate::budget::RELAY_BUF,
            )
            .await;
            Ok(())
        }
        Err(e) => {
            tracing::debug!(%target, error = %e, "http connect dial failed");
            client.write_all(failure_status(&e)).await
        }
    }
}

/// Accept and serve HTTP `CONNECT` clients on `listener`, dialing each authority through `dialer`.
///
/// Every accepted connection first takes [`CONNECTION_COST`](crate::budget::CONNECTION_COST) bytes from the
/// proxy's memory share; without room it is refused before a task exists (#207).
///
/// # Errors
/// Returns an I/O error only if `accept` itself fails; per-connection errors are logged and dropped.
pub async fn serve<D>(listener: TcpListener, dialer: D) -> std::io::Result<()>
where
    D: Dialer + Clone + Send + Sync + 'static,
{
    loop {
        // Room BEFORE the accept: back-pressure belongs in the kernel's accept queue (see
        // `crate::budget::reserve` for the two refusal designs that were tried and why both were wrong).
        let permit = if let Some(p) = crate::budget::try_reserve(crate::budget::CONNECTION_COST) {
            p
        } else {
            tracing::warn!(
                cap = crate::budget::MAX_CONNECTIONS,
                "the proxy memory share has no room for another HTTP CONNECT relay: not accepting until a \
                 connection ends"
            );
            let Some(p) = crate::budget::reserve(crate::budget::CONNECTION_COST).await else {
                continue;
            };
            p
        };
        let (client, peer) = listener.accept().await?;
        let dialer = dialer.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(client, &dialer).await {
                tracing::debug!(%peer, error = %e, "http connect connection ended");
            }
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::dialer::{EchoDialer, RefuseDialer};

    // Read whatever the server has written so far (one flush) as a UTF-8 string.
    async fn read_available(client: &mut TcpStream) -> String {
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn parses_authorities_including_ipv6_and_rejects_bare_hosts() {
        assert!(matches!(parse_authority("example.fanos:80"), Some(Target::Name(h, 80)) if h == "example.fanos"));
        assert!(matches!(parse_authority("127.0.0.1:443"), Some(Target::Ip(_))));
        assert!(matches!(parse_authority("[::1]:8443"), Some(Target::Ip(_))));
        assert!(parse_authority("no-port").is_none());
        assert!(parse_authority("host:not-a-port").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connect_opens_a_tunnel_and_splices_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _serial = crate::budget::POOL.lock().await;
        tokio::spawn(serve(listener, EchoDialer));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"CONNECT chat.fanos:80 HTTP/1.1\r\nHost: chat.fanos:80\r\n\r\n")
            .await
            .unwrap();
        // The 200 comes back before the tunnel carries any payload.
        assert!(read_available(&mut client).await.starts_with("HTTP/1.1 200"));
        // Now the tunnel is open end-to-end — the echo dialer returns what we send.
        client.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refused_target_is_answered_403_not_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _serial = crate::budget::POOL.lock().await;
        tokio::spawn(serve(listener, RefuseDialer));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"CONNECT clearnet.example:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert!(read_available(&mut client).await.starts_with("HTTP/1.1 403"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_non_connect_method_gets_400() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _serial = crate::budget::POOL.lock().await;
        tokio::spawn(serve(listener, EchoDialer));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(read_available(&mut client).await.starts_with("HTTP/1.1 400"));
    }

    /// **The accept loop stops accepting when the proxy's memory share is spent** (#207).
    ///
    /// Before this, all three accept loops — this one, `socks5::serve` and `fanos_node::proxy::serve_proxy`
    /// — spawned a task per accepted connection with no counter. What an operator can observe is not "the
    /// task was not spawned" but "the connection is not served while there is no room, and is served once
    /// there is", so that is what this asserts, in both directions.
    ///
    /// The control comes first: the identical request on an untouched pool must be answered. Without it, a
    /// silent socket proves only that the fixture is broken.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_connection_is_not_accepted_while_the_share_is_spent() {
        use std::time::Duration;

        let _serial = crate::budget::POOL.lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, EchoDialer));

        // CONTROL: with room, this exact exchange is answered.
        let mut ok = TcpStream::connect(addr).await.unwrap();
        ok.write_all(b"CONNECT echo.fanos:80 HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(
            read_available(&mut ok).await.starts_with("HTTP/1.1 200"),
            "an idle pool must serve this request, or the silence below proves nothing about capacity"
        );

        // Spend what is left. `try_acquire_many` on the AVAILABLE count, never `acquire_many` on the whole
        // budget: the control connection above is still relaying and still holds its own permit, so
        // demanding the full share waits for bytes that only come back when this test ends — a deadlock I
        // wrote, and the first run found.
        let left = u32::try_from(crate::budget::PROXY_MEMORY.available_permits()).unwrap();
        let held = crate::budget::PROXY_MEMORY.try_acquire_many(left).unwrap();
        assert!(
            crate::budget::PROXY_MEMORY.available_permits() < crate::budget::CONNECTION_COST,
            "the drain must leave less than one connection's worth, or the silence is not about capacity"
        );

        // **The loop holds one permit in advance**, so at capacity exactly one more connection is admitted
        // and the one after it waits. That is the design, not slack: the permit is taken before `accept`
        // precisely so the accepted socket always has room, and the test model that missed it failed here
        // on its first run.
        let mut prepaid = TcpStream::connect(addr).await.unwrap();
        prepaid.write_all(b"CONNECT echo.fanos:80 HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(
            read_available(&mut prepaid).await.starts_with("HTTP/1.1 200"),
            "the permit the loop took before the drain must still be honoured"
        );

        // The kernel completes the handshake from the listen backlog, so `connect` succeeds — what must not
        // happen is the request being *served*.
        let mut waiting = TcpStream::connect(addr).await.unwrap();
        waiting.write_all(b"CONNECT echo.fanos:80 HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), waiting.read(&mut buf)).await.is_err(),
            "a connection arriving with the share spent must wait in the accept queue, not be served"
        );

        // And the other direction, which is what makes this a bound rather than a wedge: freeing the share
        // lets the waiting connection through without it having to reconnect.
        drop(held);
        drop(ok);
        drop(prepaid);
        let answer = tokio::time::timeout(Duration::from_secs(5), read_available(&mut waiting))
            .await
            .unwrap_or_else(|_| panic!("the freed share must let the queued connection be accepted"));
        assert!(answer.starts_with("HTTP/1.1 200"), "served once there is room: {answer:?}");
    }
}
