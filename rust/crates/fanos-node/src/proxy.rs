//! The local SOCKS5 / HTTP-CONNECT proxy accept loop (spec §11.3), factored out of the `fanos proxy` binary
//! so its dispatch is unit-testable with a fake [`Dialer`] and reusable by any embedder wiring a dialer to
//! local listeners. The SOCKS5 / HTTP protocol itself and the FANOS session dial live below this — in
//! [`fanos_proxy`] and [`crate::FanosDialer`]; this is only the accept-and-fan-out loop over them.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use fanos_proxy::{Dialer, UdpDialer};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

/// Which local proxy protocol a listener speaks.
#[derive(Clone, Copy)]
enum Proxy {
    Socks5,
    Http,
}

/// Serve SOCKS5 on `socks` (and, if present, HTTP-CONNECT on `http`), tunnelling every accepted `CONNECT`
/// through `dialer`, until `shutdown` resolves. Each connection is handled in its own task, so a slow dial
/// never blocks the accept loop; a single connection's error is logged and dropped, never sinking a listener.
/// `dialer` is shared behind an [`Arc`] because each per-connection handler needs only `&D` — so the dialer
/// need not be [`Clone`] (the production [`FanosDialer`](crate::FanosDialer) is not).
pub async fn serve_proxy<D>(
    socks: TcpListener,
    http: Option<TcpListener>,
    dialer: Arc<D>,
    shutdown: impl Future<Output = ()> + Send,
) where
    D: Dialer + UdpDialer + Send + Sync + 'static,
{
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = socks.accept() => spawn_proxy_conn(accepted, &dialer, Proxy::Socks5),
            accepted = accept_opt(http.as_ref()) => spawn_proxy_conn(accepted, &dialer, Proxy::Http),
        }
    }
}

/// Accept on an optional listener, or stay pending forever when it is absent — so a `select!` arm over an
/// unused HTTP listener simply never fires instead of needing a separate code path.
async fn accept_opt(listener: Option<&TcpListener>) -> std::io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

/// Spawn a per-connection handler for one accepted (or failed) TCP accept, tunnelling it through `dialer`.
fn spawn_proxy_conn<D>(
    accepted: std::io::Result<(TcpStream, SocketAddr)>,
    dialer: &Arc<D>,
    proxy: Proxy,
) where
    D: Dialer + UdpDialer + Send + Sync + 'static,
{
    let (sock, _peer) = match accepted {
        Ok(pair) => pair,
        Err(e) => {
            warn!(error = %e, "proxy accept failed");
            return;
        }
    };
    let dialer = dialer.clone();
    tokio::spawn(async move {
        // `FanosDialer` is `Sync`, so holding `&*dialer` across the copy_bidirectional await is sound.
        let result = match proxy {
            Proxy::Socks5 => fanos_proxy::socks5::handle(sock, &*dialer).await,
            Proxy::Http => fanos_proxy::http::handle(sock, &*dialer).await,
        };
        if let Err(e) = result {
            warn!(error = %e, "proxy connection ended with error");
        }
    });
}
