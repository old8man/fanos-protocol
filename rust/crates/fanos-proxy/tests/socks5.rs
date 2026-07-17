//! End-to-end SOCKS5: a real client speaks the protocol to the proxy, which splices to the
//! in-process echo dialer. Proves the handshake, the CONNECT reply, and the byte pipe.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_proxy::dialer::EchoDialer;
use fanos_proxy::serve;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_proxy() -> std::net::SocketAddr {
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
async fn udp_associate_is_rejected() {
    let proxy = spawn_proxy().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    greet(&mut client).await;

    // cmd = 3 (UDP ASSOCIATE) — unsupported.
    let req = vec![5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
    client.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x07, "command not supported");
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
