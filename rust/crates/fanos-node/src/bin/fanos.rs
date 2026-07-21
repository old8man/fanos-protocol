//! `fanos` — the unified FANOS node binary (roadmap Phase 1).
//!
//! Subcommands:
//!   * `fanos node`  — run a node (overlay membership, storage, healing) over QUIC.
//!   * `fanos proxy` — run local SOCKS5 / HTTP-CONNECT listeners tunnelling to `.fanos` services (§11.3).
//!   * `fanos id`    — print (and optionally persist) a node's self-certifying coordinate.
//!   * `fanos help`  — usage.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use fanos_field::F2;
use fanos_node::{
    AnonRouteParams, BeaconSeed, Epoch, FanosDialer, Node, NodeConfig, NodeError, NodeResolver,
    Peer, RoleSet, build_cell_mix_directory, identity, serve_proxy,
};
use fanos_runtime::Notification;
use tokio::net::TcpListener;
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
        Some("proxy") => cmd_proxy(args.get(2..).unwrap_or(&[])).await,
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

/// Build a [`NodeConfig`] from a `--config <file>` base (if any) with individual CLI flags overriding it,
/// so an operator can keep a config file and tweak one setting on the command line. Shared by `fanos node`
/// and `fanos proxy` — both run a full node, they differ only in what they do with its `Client`.
fn node_config_from_args(args: &[String]) -> Result<NodeConfig, NodeError> {
    let mut config = match flag(args, "--config") {
        Some(path) => NodeConfig::from_config_str(&std::fs::read_to_string(path)?)?,
        None => NodeConfig::default(),
    };
    if let Some(s) = flag(args, "--listen") {
        config.listen = s
            .parse::<SocketAddr>()
            .map_err(|_| NodeError::Config(format!("bad --listen '{s}'")))?;
    }
    if let Some(p) = flag(args, "--identity") {
        config.identity_path = Some(PathBuf::from(p));
    }
    for value in flag_all(args, "--bootstrap") {
        for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            config.bootstrap.push(Peer::parse(part)?);
        }
    }
    if let Some(s) = flag(args, "--role") {
        config.roles = RoleSet::parse(s)?;
    }
    if has_flag(args, "--no-heartbeat") {
        config.start_heartbeat = false;
    }
    if let Some(s) = flag(args, "--proteus-secret") {
        // Enable PROTEUS: shape every frame with this shared community secret, rotating per epoch (§13.4).
        config.proteus_secret = Some(s.as_bytes().to_vec());
    }
    Ok(config)
}

/// Run a node until Ctrl-C.
async fn cmd_node(args: &[String]) -> Result<(), NodeError> {
    init_tracing();
    let config = node_config_from_args(args)?;
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

/// Run local SOCKS5 (and optional HTTP-CONNECT) proxy listeners that tunnel `CONNECT <name>.fanos:port`
/// through this node's FANOS sessions (spec §11.3). This process joins the overlay exactly like `fanos node`,
/// then its `Client` backs a [`FanosDialer`]: each accepted CONNECT resolves the `.fanos` name to a service
/// coordinate (via the overlay descriptor store, [`NodeResolver`]) and opens an encrypted hybrid-PQ DIAULOS
/// byte-stream to it. The local SOCKS/HTTP hop answers `.fanos` addressing itself, so names never reach the
/// system resolver. Clearnet targets are refused today (a `.fanos`-only surface — no exit dialer yet), as are
/// UDP ASSOCIATE / BIND.
///
/// Two routing profiles (`--profile`): **direct** (default) opens the DIAULOS stream straight to the service
/// coordinate — fast, but an observer sees which coordinate the client talks to. **anonymous** draws a
/// *fresh, unlinkable* threshold-onion rendezvous route for every dial from the cell's live mix directory
/// (`build_cell_mix_directory` — the relays that published an onion key this epoch), so neither party's
/// location is revealed and an observer cannot link one client's successive connections by their path. It
/// refuses to start unless at least `threshold + 1` relays are live, and takes the epoch's public `--beacon`
/// so its drawn meeting line matches the service's.
async fn cmd_proxy(args: &[String]) -> Result<(), NodeError> {
    init_tracing();

    let socks_listen: SocketAddr = match flag(args, "--socks-listen") {
        Some(s) => s
            .parse()
            .map_err(|_| NodeError::Config(format!("bad --socks-listen '{s}'")))?,
        None => SocketAddr::from(([127, 0, 0, 1], 1080)),
    };
    let http_listen: Option<SocketAddr> = match flag(args, "--http-listen") {
        Some(s) => Some(
            s.parse()
                .map_err(|_| NodeError::Config(format!("bad --http-listen '{s}'")))?,
        ),
        None => None,
    };
    let epoch = match flag(args, "--epoch") {
        Some(s) => Epoch::new(
            s.parse()
                .map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?,
        ),
        None => Epoch::ZERO,
    };
    let min_pow = match flag(args, "--min-pow") {
        Some(s) => s
            .parse()
            .map_err(|_| NodeError::Config(format!("bad --min-pow '{s}'")))?,
        None => 0,
    };
    // Routing profile: `direct` (default) reaches services by coordinate; `anonymous` draws a fresh,
    // unlinkable threshold-onion rendezvous route per dial from the live cell mix directory (spec §L5,
    // #54). Parse its knobs up front so bad arguments fail before we join the overlay.
    let anon = match flag(args, "--profile").unwrap_or("direct") {
        "direct" => None,
        "anonymous" => Some(parse_anon_config(args)?),
        other => {
            return Err(NodeError::Config(format!(
                "unknown --profile '{other}' (expected 'direct' or 'anonymous')"
            )));
        }
    };

    let config = node_config_from_args(args)?;
    let mut node = Node::start::<F2>(config).await?;
    let health = node.health();
    let resolver = NodeResolver::new(node.client(), epoch, min_pow);
    // `FanosDialer` is not `Clone`, so `serve_proxy` shares it behind an `Arc` (per-connection handlers need
    // only `&D`). The dialer holds its own `Client`; the node stays owned here for notification draining + a
    // clean shutdown.
    let dialer = match build_proxy_dialer(&node, resolver, epoch, anon.as_ref()).await {
        Ok(dialer) => Arc::new(dialer),
        Err(e) => {
            node.shutdown();
            return Err(e);
        }
    };

    let socks = TcpListener::bind(socks_listen).await?;
    let http = match http_listen {
        Some(addr) => Some(TcpListener::bind(addr).await?),
        None => None,
    };
    let [x, y, z] = health.address;
    let http_line = http_listen.map_or_else(String::new, |a| {
        format!("\n  HTTP:    http://{a} (CONNECT)")
    });
    let profile_line = match &anon {
        None => "\n  Profile: direct (by-coordinate)".to_owned(),
        Some(cfg) => format!(
            "\n  Profile: anonymous (fresh per-dial routes, threshold {}, depths {}/{})",
            cfg.threshold, cfg.fwd_depth, cfg.reply_depth
        ),
    };
    eprintln!(
        "fanos proxy up — coordinate {x}:{y}:{z} on {}\n  SOCKS5:  socks5://{socks_listen}{http_line}{profile_line}",
        health.local_addr,
    );
    info!(coord = ?health.address, %socks_listen, ?http_listen, "fanos proxy up");

    // Serve the proxy until Ctrl-C, while concurrently draining the node's notifications so the overlay keeps
    // making progress and operator-visible events are logged.
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown signal received");
    };
    tokio::select! {
        () = serve_proxy(socks, http, dialer, shutdown) => {}
        () = async { while let Some(n) = node.next_notification().await { log_notification(&n); } } => {}
    }
    node.shutdown();
    eprintln!("fanos proxy down");
    Ok(())
}

/// Build the proxy's [`FanosDialer`] for the chosen routing profile. `direct` (when `anon` is `None`)
/// reaches services by coordinate; `anonymous` reads the cell's live mix directory for `epoch` (every
/// relay that published an onion key) and draws a *fresh, unlinkable* route per dial over it. Fails —
/// leaving the node for the caller to shut down — if too few relays are live to draw a threshold circuit,
/// since silently degrading anonymity would be worse than a clear refusal.
async fn build_proxy_dialer(
    node: &Node,
    resolver: NodeResolver,
    epoch: Epoch,
    anon: Option<&AnonConfig>,
) -> Result<FanosDialer<NodeResolver>, NodeError> {
    let Some(cfg) = anon else {
        return Ok(FanosDialer::new(node.client(), resolver));
    };
    let directory = build_cell_mix_directory::<F2>(&node.client(), epoch).await;
    let need = usize::from(cfg.threshold) + 1;
    if directory.len() < need {
        return Err(NodeError::Config(format!(
            "anonymous profile needs at least threshold+1={need} live mix relays for epoch {}, found \
             {} — start relays that publish mix keys or lower --threshold",
            epoch.get(),
            directory.len(),
        )));
    }
    info!(
        relays = directory.len(),
        threshold = cfg.threshold,
        fwd_depth = cfg.fwd_depth,
        reply_depth = cfg.reply_depth,
        "anonymous profile: fresh per-dial rendezvous routes over the live mix directory"
    );
    let params = AnonRouteParams {
        directory,
        threshold: cfg.threshold,
        epoch,
        beacon: cfg.beacon,
        depths: (cfg.fwd_depth, cfg.reply_depth),
    };
    Ok(FanosDialer::anonymous_fresh(node.client(), resolver, params))
}

/// The parsed knobs of the `--profile anonymous` proxy: how many relays per hop must cooperate to peel an
/// onion (`threshold`), the forward/reply intermediate-hop depths, and the epoch's public beacon seed.
struct AnonConfig {
    threshold: u8,
    fwd_depth: usize,
    reply_depth: usize,
    beacon: BeaconSeed,
}

/// Parse the `--profile anonymous` knobs from the proxy arguments, with defaults tuned for the base Fano
/// cell: `--threshold 2` (2-of-line onion peeling), `--fwd-depth 2` / `--reply-depth 2` intermediate hops,
/// and `--beacon` the epoch's public randomness (defaults to genesis).
fn parse_anon_config(args: &[String]) -> Result<AnonConfig, NodeError> {
    let usize_flag = |name: &str, default: usize| -> Result<usize, NodeError> {
        match flag(args, name) {
            Some(s) => s
                .parse()
                .map_err(|_| NodeError::Config(format!("bad {name} '{s}'"))),
            None => Ok(default),
        }
    };
    let threshold: u8 = match flag(args, "--threshold") {
        Some(s) => s
            .parse()
            .map_err(|_| NodeError::Config(format!("bad --threshold '{s}'")))?,
        None => 2,
    };
    if threshold == 0 {
        return Err(NodeError::Config("--threshold must be at least 1".to_owned()));
    }
    Ok(AnonConfig {
        threshold,
        fwd_depth: usize_flag("--fwd-depth", 2)?,
        reply_depth: usize_flag("--reply-depth", 2)?,
        beacon: match flag(args, "--beacon") {
            Some(s) => parse_beacon_hex(s)?,
            None => BeaconSeed::GENESIS,
        },
    })
}

/// Parse a 64-hex-char (32-byte) epoch beacon seed. The beacon is *public* per-epoch randomness (the
/// rendezvous DVRF output) shared by every party on the epoch — a client obtains it out-of-band or from
/// the overlay and passes it so its drawn meeting line matches the service's. Accepts an optional `0x`
/// prefix; avoids slice indexing (a hard-denied lint here) by consuming nibbles through an iterator.
fn parse_beacon_hex(s: &str) -> Result<BeaconSeed, NodeError> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let err = || NodeError::Config("bad --beacon: expected 64 hex chars (32 bytes)".to_owned());
    if hex.len() != 64 {
        return Err(err());
    }
    let mut nibbles = hex.chars().map(|c| c.to_digit(16));
    let mut bytes = [0u8; 32];
    for byte in &mut bytes {
        let hi = nibbles.next().flatten().ok_or_else(err)?;
        let lo = nibbles.next().flatten().ok_or_else(err)?;
        *byte = (hi * 16 + lo) as u8;
    }
    Ok(BeaconSeed::new(bytes))
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
         \x20 fanos node  [--listen ADDR] [--identity PATH] [--bootstrap x:y:z@host:port,...] \\\n\
         \x20             [--role relay,storage,service,exit] [--no-heartbeat] [--proteus-secret SECRET]\n\
         \x20 fanos proxy [--socks-listen ADDR] [--http-listen ADDR] [--epoch N] [--min-pow BITS] \\\n\
         \x20             [--profile direct|anonymous] [--threshold T] [--fwd-depth D] [--reply-depth D] \\\n\
         \x20             [--beacon HEX64] [--config FILE] [--identity PATH] [--bootstrap ...] [--listen ADDR]\n\
         \x20 fanos id    [--identity PATH]\n\
         \x20 fanos resolve NAME.fanos [--epoch N] [--min-pow BITS] [--bootstrap ...]\n\
         \x20 fanos help\n\
         \n\
         PROXY PROFILES:\n\
         \x20 direct     reach services by coordinate — fast, but reveals where each party is (default)\n\
         \x20 anonymous  draw a FRESH threshold-onion rendezvous route per dial from the live mix\n\
         \x20            directory, so successive connections are unlinkable (needs live relays; the\n\
         \x20            --beacon is the epoch's public randomness, shared by the service)\n\
         \n\
         EXAMPLES:\n\
         \x20 fanos id --identity ~/.fanos/id.bin      # show this node's coordinate\n\
         \x20 fanos node --listen 0.0.0.0:9000 --identity ~/.fanos/id.bin \\\n\
         \x20            --bootstrap 1:0:0@seed.example:9000 --role relay,storage\n\
         \x20 fanos proxy --socks-listen 127.0.0.1:1080 --bootstrap 1:0:0@seed.example:9000\n\
         \x20            # then: curl --socks5-hostname 127.0.0.1:1080 http://<pubkey>.fanos/\n\
         \x20 fanos proxy --profile anonymous --threshold 2 --bootstrap 1:0:0@seed.example:9000\n\
         \x20            # unlinkable per-dial routes over the cell mixnet\n\
         \n\
         Set RUST_LOG=debug for verbose logs."
    );
}
