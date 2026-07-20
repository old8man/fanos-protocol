//! `serve_proxy` accept-loop tests (task #111, §11.3): a real SOCKS5 / HTTP-CONNECT client drives the proxy
//! loop through to an in-process echo [`Dialer`]. This exercises the loop the `fanos proxy` binary runs —
//! dispatching both protocols off one shared dialer and shutting down cleanly — deterministically, without a
//! QUIC node (the end-to-end FANOS session is covered by `diaulos_quic.rs`; the SOCKS/HTTP protocol itself by
//! `fanos-proxy`'s own tests). Here the seam between them — `serve_proxy` — is what is under test.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;

use fanos_node::serve_proxy;
use fanos_proxy::dialer::EchoDialer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Offer no-auth and assert the server selects it (RFC 1928 greeting).
async fn socks_greet(client: &mut TcpStream) {
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0], "server selects no-auth");
}

#[tokio::test]
async fn serve_proxy_tunnels_a_socks5_connect_through_one_shared_dialer() {
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socks.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(serve_proxy(socks, None, Arc::new(EchoDialer), async move {
        let _ = stop_rx.await;
    }));

    // Two sequential SOCKS5 clients through the same loop / shared dialer.
    for msg in [b"through the loop".as_slice(), b"and again".as_slice()] {
        let mut client = TcpStream::connect(addr).await.unwrap();
        socks_greet(&mut client).await;
        let host = b"svc.fanos";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 5, "SOCKS5 reply version");
        assert_eq!(reply[1], 0x00, "CONNECT succeeded");
        client.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            buf, msg,
            "the echo dialer mirrored the bytes back through the loop"
        );
    }

    // The shutdown future firing ends the loop cleanly.
    stop_tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn serve_proxy_tunnels_an_http_connect_on_the_second_listener() {
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(serve_proxy(
        socks,
        Some(http),
        Arc::new(EchoDialer),
        async move {
            let _ = stop_rx.await;
        },
    ));

    let mut client = TcpStream::connect(http_addr).await.unwrap();
    client
        .write_all(b"CONNECT svc.fanos:80 HTTP/1.1\r\nHost: svc.fanos:80\r\n\r\n")
        .await
        .unwrap();
    let mut status = [0u8; 39]; // "HTTP/1.1 200 Connection Established\r\n\r\n"
    client.read_exact(&mut status).await.unwrap();
    assert_eq!(&status[..12], b"HTTP/1.1 200", "HTTP CONNECT established");
    assert_eq!(
        &status[status.len() - 4..],
        b"\r\n\r\n",
        "response head terminates"
    );
    client.write_all(b"tunnelled").await.unwrap();
    let mut buf = [0u8; 9];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"tunnelled");

    stop_tx.send(()).unwrap();
    server.await.unwrap();
}
