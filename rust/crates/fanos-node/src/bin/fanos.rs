//! `fanos` — the unified FANOS node binary (roadmap Phase 1).
//!
//! Subcommands:
//!   * `fanos node`  — run a node (overlay membership, storage, healing) over QUIC.
//!   * `fanos id`    — print (and optionally persist) a node's self-certifying coordinate.
//!   * `fanos help`  — usage.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use fanos_field::F2;
use fanos_node::{Epoch, Node, NodeConfig, NodeError, Peer, RoleSet, identity};
use fanos_runtime::Notification;
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fanos: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> Result<(), NodeError> {
    match args.get(1).map(String::as_str) {
        Some("node") => cmd_node(args.get(2..).unwrap_or(&[])).await,
        Some("id") => cmd_id(args.get(2..).unwrap_or(&[])),
        Some("resolve") => cmd_resolve(args.get(2..).unwrap_or(&[])).await,
        Some("help" | "--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(NodeError::Config(format!(
            "unknown command '{other}' (try `fanos help`)"
        ))),
    }
}

/// Run a node until Ctrl-C.
async fn cmd_node(args: &[String]) -> Result<(), NodeError> {
    init_tracing();

    let listen = match flag(args, "--listen") {
        Some(s) => s
            .parse::<SocketAddr>()
            .map_err(|_| NodeError::Config(format!("bad --listen '{s}'")))?,
        None => SocketAddr::from(([0, 0, 0, 0], 0)),
    };
    let identity_path = flag(args, "--identity").map(PathBuf::from);
    let mut bootstrap = Vec::new();
    for value in flag_all(args, "--bootstrap") {
        for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            bootstrap.push(Peer::parse(part)?);
        }
    }
    let roles = match flag(args, "--role") {
        Some(s) => RoleSet::parse(s)?,
        None => RoleSet::default(),
    };
    let start_heartbeat = !has_flag(args, "--no-heartbeat");

    let config = NodeConfig {
        listen,
        identity_path,
        bootstrap,
        roles,
        start_heartbeat,
    };

    let mut node = Node::start::<F2>(config).await?;
    let health = node.health();
    let [x, y, z] = health.address;
    info!(coord = ?health.address, local_addr = %health.local_addr, peers = health.known_peers, "fanos node up");
    eprintln!(
        "fanos node up — coordinate {x}:{y}:{z} on {} ({} bootstrap peers)",
        health.local_addr, health.known_peers
    );

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            biased;
            _ = &mut ctrl_c => {
                info!("shutdown signal received");
                break;
            }
            note = node.next_notification() => match note {
                Some(n) => log_notification(&n),
                None => break,
            },
        }
    }
    node.shutdown();
    eprintln!("fanos node down");
    Ok(())
}

/// Print (and optionally persist) a node's self-certifying coordinate.
fn cmd_id(args: &[String]) -> Result<(), NodeError> {
    let path = flag(args, "--identity").map(PathBuf::from);
    let credentials = identity::load_or_generate(path.as_deref())?;
    let [x, y, z] = identity::coordinate::<F2>(&credentials);
    println!("coordinate: {x}:{y}:{z}");
    match &path {
        Some(p) => println!("identity file: {}", p.display()),
        None => println!("(ephemeral — pass --identity <path> to persist this coordinate)"),
    }
    println!("bootstrap seed (add host:port): {x}:{y}:{z}@HOST:PORT");
    Ok(())
}

/// Resolve a `.fanos` name against the network and print the authenticated result.
async fn cmd_resolve(args: &[String]) -> Result<(), NodeError> {
    init_tracing();

    let name = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or_else(|| NodeError::Config("`fanos resolve` needs a .fanos name".to_string()))?;
    let epoch = match flag(args, "--epoch") {
        Some(s) => Epoch::new(
            s.parse::<u64>()
                .map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?,
        ),
        None => Epoch::ZERO,
    };
    let min_pow = match flag(args, "--min-pow") {
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| NodeError::Config(format!("bad --min-pow '{s}'")))?,
        None => 0,
    };
    let mut bootstrap = Vec::new();
    for value in flag_all(args, "--bootstrap") {
        for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            bootstrap.push(Peer::parse(part)?);
        }
    }

    let config = NodeConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        bootstrap,
        ..NodeConfig::default()
    };
    let node = Node::start::<F2>(config).await?;
    let resolved = node.resolve(name, epoch, min_pow).await?;
    println!("resolved {name}");
    println!("  address:  {}", resolved.address);
    println!("  epoch:    {}", resolved.epoch);
    println!(
        "  bundle:   {} bytes (self-certified: H(bundle) == address)",
        resolved.bundle.len()
    );
    if !resolved.metadata.is_empty() {
        println!("  metadata: {} bytes", resolved.metadata.len());
    }
    node.shutdown();
    Ok(())
}

fn log_notification(note: &Notification) {
    match note {
        Notification::Delivered { from, payload } => {
            info!(?from, bytes = payload.len(), "payload delivered");
        }
        Notification::PeerDown(p) => info!(peer = ?p, "peer down"),
        Notification::MemberJoined { coord, .. } => info!(?coord, "member joined"),
        Notification::EpochAdvanced(e) => info!(epoch = e.get(), "epoch advanced"),
        Notification::Rerouted { around, via } => info!(?around, ?via, "rerouted (self-heal)"),
        Notification::Repaired(p) => info!(node = ?p, "shard repaired"),
        Notification::Quarantined(p) => info!(node = ?p, "member quarantined"),
        Notification::Escalated(n) => info!(count = n, "escalated to parent cell"),
        Notification::Decoupled => info!("cascade pre-empted (decoupled)"),
        other => info!(event = ?other, "engine event"),
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// The value following the first occurrence of `name`.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The values following every occurrence of `name` (repeatable flags).
fn flag_all<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == name
            && let Some(v) = args.get(i + 1)
        {
            out.push(v.as_str());
        }
    }
    out
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn print_help() {
    eprintln!(
        "fanos — the FANOS node\n\
         \n\
         USAGE:\n\
         \x20 fanos node [--listen ADDR] [--identity PATH] [--bootstrap x:y:z@host:port,...] \\\n\
         \x20            [--role relay,storage,service,exit] [--no-heartbeat]\n\
         \x20 fanos id   [--identity PATH]\n\
         \x20 fanos resolve NAME.fanos [--epoch N] [--min-pow BITS] [--bootstrap ...]\n\
         \x20 fanos help\n\
         \n\
         EXAMPLES:\n\
         \x20 fanos id --identity ~/.fanos/id.bin      # show this node's coordinate\n\
         \x20 fanos node --listen 0.0.0.0:9000 --identity ~/.fanos/id.bin \\\n\
         \x20            --bootstrap 1:0:0@seed.example:9000 --role relay,storage\n\
         \n\
         Set RUST_LOG=debug for verbose logs."
    );
}
