//! End-to-end SOCKS5: a real client speaks the protocol to the proxy, which splices to the
//! in-process echo dialer. Proves the handshake, the CONNECT reply, and the byte pipe.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use fanos_proxy::dialer::EchoDialer;
use fanos_proxy::serve;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

async fn spawn_proxy() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, EchoDialer).await;
    });
    addr
}

/// Perform the greeting (offer no-auth) and assert the server selects it.
async fn greet(client: &mut TcpStream) {
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0], "server selects no-auth");
}

#[tokio::test]
async fn socks5_connect_and_echo_through_the_proxy() {
    let proxy = spawn_proxy().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    greet(&mut client).await;

    // CONNECT blog.alice.fanos:80 (domain ATYP=3) — a name the proxy never resolves via DNS.
    let host = b"blog.alice.fanos";
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 5, "SOCKS5 reply version");
    assert_eq!(reply[1], 0x00, "CONNECT succeeded");

    // The echo dialer mirrors bytes back through the spliced pipe.
    client.write_all(b"hello onion").await.unwrap();
    let mut buf = [0u8; 11];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello onion");
}

#[tokio::test]
async fn ipv4_connect_is_supported() {
    let proxy = spawn_proxy().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    greet(&mut client).await;

    // CONNECT 10.0.0.1:443 (IPv4 ATYP=1).
    let mut req = vec![5, 1, 0, 1, 10, 0, 0, 1];
    req.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00);
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn udp_associate_relays_a_datagram_and_back() {
    let proxy = spawn_proxy().await;
    // The control connection must stay open for the association to live (RFC 1928 §7).
    let mut control = TcpStream::connect(proxy).await.unwrap();
    greet(&mut control).await;

    // UDP ASSOCIATE, advertising an unknown source (0.0.0.0:0).
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "UDP ASSOCIATE succeeds");
    assert_eq!(reply[3], 1, "BND is an IPv4 address");
    let bnd = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    // Send a datagram wrapped in a SOCKS5 UDP header (destined for 9.9.9.9:53) to the relay socket.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut dg = vec![0, 0, 0, 1, 9, 9, 9, 9, 0, 53];
    dg.extend_from_slice(b"a dns query");
    client.send_to(&dg, bnd).await.unwrap();

    // The echo dialer returns the payload; the relay re-wraps it with the same header and sends it back.
    let mut buf = [0u8; 256];
    let (n, _from) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("no timeout")
        .unwrap();
    assert_eq!(&buf[..10], &[0, 0, 0, 1, 9, 9, 9, 9, 0, 53], "reply header names the source");
    assert_eq!(&buf[10..n], b"a dns query", "the payload round-trips through the relay");

    // A second datagram to a *different* destination opens its own tunnel and also round-trips.
    let mut dg2 = vec![0, 0, 0, 1, 1, 1, 1, 1, 1, 187];
    dg2.extend_from_slice(b"second");
    client.send_to(&dg2, bnd).await.unwrap();
    let (n2, _from) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("no timeout")
        .unwrap();
    assert_eq!(&buf[..10], &[0, 0, 0, 1, 1, 1, 1, 1, 1, 187]);
    assert_eq!(&buf[10..n2], b"second");
}

#[tokio::test]
async fn udp_associate_ignores_a_fragmented_datagram() {
    let proxy = spawn_proxy().await;
    let mut control = TcpStream::connect(proxy).await.unwrap();
    greet(&mut control).await;
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    let bnd = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // FRAG = 1: a fragment we do not reassemble — it must be dropped, no reply.
    let mut frag = vec![0, 0, 1, 1, 9, 9, 9, 9, 0, 53];
    frag.extend_from_slice(b"dropped");
    client.send_to(&frag, bnd).await.unwrap();
    let mut buf = [0u8; 64];
    assert!(
        timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await.is_err(),
        "a fragmented datagram gets no reply"
    );
}

#[tokio::test]
async fn a_refusing_dialer_yields_a_socks_error() {
    use fanos_proxy::dialer::RefuseDialer;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, RefuseDialer).await;
    });

    let mut client = TcpStream::connect(proxy).await.unwrap();
    greet(&mut client).await;
    let host = b"example.com";
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x02, "connection refused by policy");
}
