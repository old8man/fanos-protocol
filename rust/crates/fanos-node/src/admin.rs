//! The node's **local control socket** — how an operator asks a *running* node anything.
//!
//! Before this, a live node was opaque from outside its own log. `fanos status` could report what the host was
//! *configured* to be and whether something held the port, which is the difference between reading a plan and
//! reading a system; and the observatory, whose whole purpose is watching a cell, could only watch a simulated
//! one. Both had the same missing piece: no way to ask the process.
//!
//! ## Why a Unix socket, and why no authentication
//!
//! The socket is created inside the node's own state directory at mode `0600`, so the filesystem *is* the
//! authorization — the same mechanism that already protects the identity key sitting beside it. That is not a
//! shortcut around auth; it is the correct auth for this boundary, and it is strictly stronger than the
//! alternatives. A TCP port would need a credential to be safe, and a credential needs provisioning, rotation and
//! a place to live — every one of which is a new way for an operator to lock themselves out of their own node, in
//! exchange for guarding a boundary the kernel already guards.
//!
//! It also means the control plane cannot be reached from the network at all, which is the property that matters:
//! a node whose whole job is accepting traffic from strangers must not have an administrative surface those
//! strangers can address.
//!
//! ## The protocol
//!
//! One request word per connection, one response, close. Line-oriented text, because the thing on the other end is
//! as often a person with `socat` as it is this binary, and a format a human can read without a tool is a format
//! that gets used when something is wrong.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use crate::node::Health;

/// The socket's name inside the node's state directory.
pub const SOCKET_FILE: &str = "admin.sock";

/// The longest `sun_path` a Unix socket address can hold, minus slack for the terminator.
///
/// A hard kernel limit, not a convention: `sockaddr_un.sun_path` is 104 bytes on macOS and BSD, 108 on Linux.
/// Bind past it and the call fails with a message about `SUN_LEN` that says nothing about which path was too
/// long. 100 is the smaller platform's limit with room to spare, so the same node has the same socket everywhere.
const MAX_SOCKET_PATH: usize = 100;

/// The control socket's path for a node whose state lives in `data`.
///
/// Beside the state, where it belongs and where an operator will look for it — **unless** that path would exceed
/// what a socket address can hold, in which case it moves to a short name in the temporary directory, derived
/// from the data directory so both the node and `fanos status` compute the same one with no pointer file between
/// them to go stale.
///
/// The fallback is not hypothetical. It fires for a container mount a few levels deep, a long user name under an
/// XDG home, or any of the paths a packaging system picks — and found here by running a node from a scratch
/// directory, where it failed with nothing but `path must be shorter than SUN_LEN`.
#[must_use]
pub fn socket_path(data: &Path) -> PathBuf {
    let natural = data.join(SOCKET_FILE);
    if natural.as_os_str().len() <= MAX_SOCKET_PATH {
        return natural;
    }
    let digest = fanos_primitives::hash_labeled("FANOS-v1/admin-socket", data.as_os_str().as_encoded_bytes());
    let mut name = String::from("fanos-");
    for byte in digest.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".sock");
    std::env::temp_dir().join(name)
}

/// What an operator can ask a running node.
///
/// Deliberately small. Every verb here is either a question or a shutdown, and that is the whole surface a control
/// socket needs to justify existing: an administrative channel that can *reconfigure* a node is a channel that can
/// misconfigure it, and the configuration file is already the place where such changes are reviewable and survive
/// a restart.
#[derive(Debug)]
pub enum Request {
    /// Liveness only — the cheapest possible "is it there".
    Ping,
    /// The node's current [`Health`].
    Health,
    /// The roles the **cell** has assigned this node, which is not always what its config offered.
    Roles,
    /// A **census** of the cells this node can see — the answer to "is this my cell, or the network?".
    ///
    /// Reads every cell coordinate's published ε-private coherence frame for the current epoch and reports the
    /// distribution: healthy, alarmed, silent, unreachable. Slower than the other verbs by design — it goes to
    /// the overlay store rather than to local state — and issued serially, since a monitor that fans out over a
    /// federation at once is a load spike on a network it may be asking about because it is under load.
    Census,
    /// Ask the node to shut down cleanly.
    Shutdown,
}

impl Request {
    /// Parse a request word, case-insensitively.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word.trim().to_ascii_lowercase().as_str() {
            "ping" => Some(Self::Ping),
            "health" => Some(Self::Health),
            "roles" => Some(Self::Roles),
            "census" => Some(Self::Census),
            "shutdown" => Some(Self::Shutdown),
            _ => None,
        }
    }

    /// Every verb, for the error message a wrong one gets.
    #[must_use]
    pub const fn all() -> &'static str {
        "ping | health | roles | census | shutdown"
    }
}

/// A request paired with the channel its answer goes back on.
pub type Envelope = (Request, oneshot::Sender<String>);

/// Render a [`Health`] as the socket's response body.
///
/// `key: value` lines, aligned, one fact per line — parseable with `cut` and readable without anything. The
/// `verified_claims` and `probe_index` fields are carried through rather than summarized, because their whole
/// reason for existing is telling apart two failures that look identical from outside.
#[must_use]
pub fn render_health(health: &Health) -> String {
    use std::fmt::Write as _;
    let [x, y, z] = health.address;
    let mut s = String::new();
    let _ = writeln!(s, "coordinate: {x}:{y}:{z}");
    let _ = writeln!(s, "listen: {}", health.local_addr);
    let _ = writeln!(s, "known_peers: {}", health.known_peers);
    match health.verified_claims {
        Some(n) => {
            let _ = writeln!(s, "verified_claims: {n}");
        }
        None => {
            let _ = writeln!(s, "verified_claims: none (no self-certifying identity)");
        }
    }
    match health.probe_index {
        Some(i) => {
            let _ = writeln!(s, "probe_index: {i}");
        }
        None => {
            let _ = writeln!(s, "probe_index: unclaimed");
        }
    }
    let _ = writeln!(s, "roles_offered: {:?}", health.roles);
    s
}

/// Serve one connection: read a verb, forward it, write the answer.
async fn serve_one(stream: UnixStream, tx: &mpsc::Sender<Envelope>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let body = match Request::parse(&line) {
        Some(req) => {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send((req, reply_tx)).await.is_err() {
                // The node is gone; say so rather than hanging a client that is waiting on a corpse.
                "error: node is shutting down\n".to_owned()
            } else {
                reply_rx.await.unwrap_or_else(|_| "error: no answer\n".to_owned())
            }
        }
        None => format!("error: unknown request (expected {})\n", Request::all()),
    };
    let mut stream = reader.into_inner();
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Bind the control socket at `path` and serve it until the node stops.
///
/// A stale socket file from a previous run is removed first: a node that crashed left the path behind, and
/// `bind` fails on an existing path — so without this a hard restart silently loses its control plane, which is
/// exactly when an operator most wants it.
///
/// # Errors
/// Propagates the bind failure, which is the operator's to see: a node running without the socket it was asked
/// for should say so rather than pretend.
pub fn serve(path: &Path, tx: mpsc::Sender<Envelope>) -> std::io::Result<tokio::task::JoinHandle<()>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Only if it is actually a socket. Removing whatever happens to sit at the path would let a mistyped data
    // directory delete a real file.
    if path.exists() {
        use std::os::unix::fs::FileTypeExt as _;
        if std::fs::metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
            std::fs::remove_file(path)?;
        }
    }
    let listener = UnixListener::bind(path)?;
    restrict(path)?;
    let owned = path.to_path_buf();
    Ok(tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let tx = tx.clone();
            tokio::spawn(async move { serve_one(stream, &tx).await });
        }
        // The listener is dropped here; take the path with it so the next start binds cleanly.
        let _ = std::fs::remove_file(&owned);
    }))
}

/// Restrict the socket to its owner.
///
/// Applied immediately after `bind`, and it is the whole of this channel's access control — see the module note.
/// A socket left at the umask is an administrative channel open to every account on the host.
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Ask a running node one question over its control socket.
///
/// `Ok(None)` means *no node is listening* — a distinct answer from an error, and the distinction is the point:
/// "nothing is running here" is the normal state of a host that has been set up and not started, while a failure
/// to talk to a socket that does exist is a fault.
///
/// # Errors
/// I/O failures against a socket that exists.
pub async fn ask(path: &Path, request: &str) -> std::io::Result<Option<String>> {
    let stream = match UnixStream::connect(path).await {
        Ok(s) => s,
        // Both mean "not running": no socket file at all, or a stale one nobody is accepting on.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let mut stream = stream;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    let mut body = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_to_string(&mut body).await?;
    Ok(Some(body))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_verb_parses_and_nothing_else_does() {
        for word in ["ping", "health", "roles", "census", "shutdown"] {
            assert!(Request::parse(word).is_some(), "`{word}` is documented but does not parse");
            assert!(Request::all().contains(word), "`{word}` parses but is not in the help string");
        }
        assert!(Request::parse("PING").is_some(), "verbs are case-insensitive");
        assert!(Request::parse(" health \n").is_some(), "a line from a socket carries its newline");
        assert!(Request::parse("reconfigure").is_none(), "an unknown verb must not be silently accepted");
        assert!(Request::parse("").is_none());
    }

    #[test]
    fn a_long_data_directory_still_gets_a_bindable_socket_path() {
        // `sockaddr_un.sun_path` is 104 bytes on macOS. A node whose state sits a few levels deep — a container
        // mount, a long user name, a packaging layout — cannot put its socket beside its state, and the failure
        // is a bind error naming `SUN_LEN` and not the path. Found by running one.
        let deep = PathBuf::from(format!("/tmp/{}", "verylongsegment/".repeat(12)));
        assert!(deep.join(SOCKET_FILE).as_os_str().len() > MAX_SOCKET_PATH, "the fixture must be too long");
        let path = socket_path(&deep);
        assert!(
            path.as_os_str().len() <= MAX_SOCKET_PATH,
            "the fallback is still unbindable at {} bytes: {}",
            path.as_os_str().len(),
            path.display()
        );
        // Deterministic: the node and `fanos status` derive it independently, so it must not depend on anything
        // but the data directory — otherwise they would disagree and the socket would be unreachable.
        assert_eq!(path, socket_path(&deep), "the derivation must be stable across calls");
        let other = PathBuf::from(format!("/tmp/{}x", "verylongsegment/".repeat(12)));
        assert_ne!(socket_path(&other), path, "two nodes must not be handed the same socket");
    }

    #[test]
    fn a_short_data_directory_keeps_the_socket_beside_the_state() {
        // The fallback must stay a fallback: on a normal install the socket belongs where an operator looks.
        let path = socket_path(Path::new("/var/lib/fanos"));
        assert_eq!(path, Path::new("/var/lib/fanos").join(SOCKET_FILE));
    }

    #[tokio::test]
    async fn asking_a_path_with_no_socket_is_not_running_rather_than_an_error() {
        // The distinction the operator's first question depends on: "set up but not started" is normal, a broken
        // socket is a fault, and collapsing them makes `fanos status` unable to tell them apart.
        let missing = std::env::temp_dir().join(format!("fanos-absent-{}.sock", std::process::id()));
        let answer = ask(&missing, "ping").await.expect("an absent socket is not an error");
        assert!(answer.is_none(), "a path with no socket must read as `not running`");
    }

    #[tokio::test]
    async fn a_request_reaches_the_node_and_its_answer_comes_back() {
        let dir = std::env::temp_dir().join(format!("fanos-admin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = socket_path(&dir);
        let (tx, mut rx) = mpsc::channel::<Envelope>(4);
        let _server = serve(&path, tx).expect("bind the control socket");

        // Stand in for the node's main loop.
        tokio::spawn(async move {
            while let Some((req, reply)) = rx.recv().await {
                let body = match req {
                    Request::Ping => "pong\n".to_owned(),
                    Request::Roles => "relay,storage\n".to_owned(),
                    _ => "…\n".to_owned(),
                };
                let _ = reply.send(body);
            }
        });

        assert_eq!(ask(&path, "ping").await.unwrap().as_deref(), Some("pong\n"));
        assert_eq!(ask(&path, "roles").await.unwrap().as_deref(), Some("relay,storage\n"));
        let unknown = ask(&path, "reconfigure").await.unwrap().unwrap_or_default();
        assert!(unknown.starts_with("error: unknown request"), "got {unknown:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_socket_is_readable_only_by_its_owner() {
        // This permission *is* the channel's authentication. At the umask it would be an administrative surface
        // open to every account on the host.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("fanos-admin-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = socket_path(&dir);
        let (tx, _rx) = mpsc::channel::<Envelope>(1);
        let _server = serve(&path, tx).expect("bind");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the control socket must not be reachable by other accounts");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_stale_socket_from_a_crashed_node_does_not_block_the_next_start() {
        // `bind` fails on an existing path, so without clearing it a hard restart comes up with no control plane
        // — precisely when an operator most needs to ask the node anything.
        let dir = std::env::temp_dir().join(format!("fanos-admin-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = socket_path(&dir);
        {
            let (tx, _rx) = mpsc::channel::<Envelope>(1);
            let first = serve(&path, tx).expect("first bind");
            first.abort();
        }
        assert!(path.exists(), "the aborted server left its socket behind, as a crash would");
        let (tx, _rx) = mpsc::channel::<Envelope>(1);
        assert!(serve(&path, tx).is_ok(), "a stale socket must not prevent the node from restarting");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_non_socket_at_the_path_is_never_deleted() {
        // The guard against a mistyped data directory: clearing "whatever is in the way" would make a typo
        // destroy a real file.
        let dir = std::env::temp_dir().join(format!("fanos-admin-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = socket_path(&dir);
        std::fs::write(&path, b"precious").unwrap();
        let (tx, _rx) = mpsc::channel::<Envelope>(1);
        assert!(serve(&path, tx).is_err(), "binding over a regular file must fail rather than remove it");
        assert_eq!(std::fs::read(&path).unwrap(), b"precious", "the file was destroyed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
