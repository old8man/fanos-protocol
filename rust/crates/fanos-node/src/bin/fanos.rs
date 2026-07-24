//! `fanos` — the unified FANOS node binary (roadmap Phase 1).
//!
//! Subcommands:
//!   * `fanos node`  — run a node (overlay membership, storage, healing) over QUIC.
//!   * `fanos proxy` — run local SOCKS5 / HTTP-CONNECT listeners tunnelling to `.fanos` services (§11.3).
//!   * `fanos host`  — host a hidden service on the anonymous rendezvous, forwarding to a local port (§3b).
//!   * `fanos id`    — print (and optionally persist) a node's self-certifying coordinate.
//!   * `fanos help`  — usage.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use fanos_diaulos::{StaticKeypair, bundle_from_kem_public};
use fanos_field::F2;
use fanos_onoma::Address;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_pqcrypto::rng::SeedRng;
use fanos_node::{
    AnonRouteParams, BeaconParams, BeaconSeed, Environment, Epoch, ExitParams, FanosDialer, Morph, Node,
    NodeConfig,
    NodeError, NodeResolver, Peer, RoleSet, ServiceParams, build_cell_exit_directory,
    build_cell_mix_directory, identity, publish_service, serve_proxy, spawn_rendezvous_host,
};
// Only the (feature-gated) `fanos vpn` command dials clearnet by IP with an empty resolver.
#[cfg(feature = "vpn")]
use fanos_node::StaticResolver;
use fanos_runtime::Notification;
use fanos_vrf::vss::{DeterministicRng, deal};
use tokio::io::{DuplexStream, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
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
        Some("host") => cmd_host(args.get(2..).unwrap_or(&[])).await,
        Some("vpn") => cmd_vpn(args.get(2..).unwrap_or(&[])).await,
        Some("id") => cmd_id(args.get(2..).unwrap_or(&[])),
        Some("beacon-deal") => cmd_beacon_deal(args.get(2..).unwrap_or(&[])),
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
    if let Some(path) = flag(args, "--service") {
        // Provision the threshold-hosting line (seed, roster, threshold) from an out-of-band file, and
        // imply the `service` role — providing service parameters is the operator asking to host it.
        config.service = Some(ServiceParams::from_config_str(&std::fs::read_to_string(path)?)?);
        config.roles.service = true;
    }
    if let Some(path) = flag(args, "--exit") {
        // Provision the clearnet exit (service-key seed + optional port policy) and imply the `exit` role.
        config.exit = Some(ExitParams::from_config_str(&std::fs::read_to_string(path)?)?);
        config.roles.exit = true;
    }
    if has_flag(args, "--no-heartbeat") {
        config.start_heartbeat = false;
    }
    if let Some(s) = flag(args, "--proteus-secret") {
        // Enable PROTEUS: shape every frame with this shared community secret, rotating per epoch (§13.4).
        config.proteus_secret = Some(s.as_bytes().to_vec());
    }
    if let Some(m) = flag(args, "--proteus-morph") {
        // The morph selecting the codec + traffic-shaper (§13.3): plain, polymorph (default), tls-tunnel,
        // masque-h3, fronted, webrtc, pluggable. Only takes effect with a --proteus-secret.
        config.proteus_morph = Morph::from_name(m).ok_or_else(|| {
            NodeError::Config(format!(
                "unknown --proteus-morph '{m}' (expected: plain, polymorph, tls-tunnel, masque-h3, \
                 fronted, webrtc, pluggable)"
            ))
        })?;
    }
    if let Some(e) = flag(args, "--proteus-environment") {
        // Enable morph auto-fallback (§13.7) under this environment policy: open, dpi-corporate,
        // sni-filter, deep-censorship. Overrides --proteus-morph (the environment picks the morph).
        config.proteus_environment = Some(Environment::from_name(e).ok_or_else(|| {
            NodeError::Config(format!(
                "unknown --proteus-environment '{e}' (expected: open, dpi-corporate, sni-filter, \
                 deep-censorship)"
            ))
        })?);
    }
    if let Some(s) = flag(args, "--mix-delay-ms") {
        // A relay's mean Poisson mixing delay in ms (spec §L5/V7, audit S1-H1); 0 disables mixing.
        let ms = s.parse().map_err(|_| NodeError::Config(format!("bad --mix-delay-ms '{s}'")))?;
        config.mix_mean_delay = std::time::Duration::from_millis(ms);
    }
    if let Some(s) = flag(args, "--cover-interval-ms") {
        // A relay's mean cover-cell interval in ms (spec §L5/V8, audit S1-H1/E1); 0 disables cover traffic.
        let ms = s.parse().map_err(|_| NodeError::Config(format!("bad --cover-interval-ms '{s}'")))?;
        config.cover_interval = std::time::Duration::from_millis(ms);
    }
    if let Some(path) = flag(args, "--beacon-params") {
        // Provision the threshold-DVRF beacon so this node runs the live epoch clock (§7.6, audit S1-H2):
        // its DKG output — group commitment, threshold, and (if an anchor) its share. Generate with
        // `fanos beacon-deal`.
        config.beacon = Some(BeaconParams::from_config_str(&std::fs::read_to_string(path)?)?);
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
/// system resolver. **Clearnet** targets ride a configured or auto-discovered **exit** (`--exit-via`), which
/// resolves and connects on the client's behalf — so DNS still never leaks. **SOCKS5 UDP ASSOCIATE** is
/// served too: datagrams are relayed through the exit's UDP tunnel (DNS-over-FANOS and any single-destination
/// UDP flow); only BIND remains unsupported.
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
    // A hand-configured clearnet exit (`--exit-via`) overrides auto-discovery; parsed up front so a bad
    // file fails before we join the overlay.
    let exit_via = parse_exit_via(args)?;

    let config = node_config_from_args(args)?;
    let mut node = Node::start::<F2>(config).await?;
    let health = node.health();
    // The clearnet exit to route non-`.fanos` targets through: the `--exit-via` override, else an exit
    // discovered from the live cell directory (none ⇒ clearnet targets are refused).
    let exit = match exit_via {
        Some(e) => Some(e),
        None => discover_exit(&node, epoch).await,
    };
    let exit_coord = exit.as_ref().map(|(coord, _)| *coord);
    let resolver = NodeResolver::new(node.client(), epoch, min_pow);
    // `FanosDialer` is not `Clone`, so `serve_proxy` shares it behind an `Arc` (per-connection handlers need
    // only `&D`). The dialer holds its own `Client`; the node stays owned here for notification draining + a
    // clean shutdown.
    let dialer = match build_proxy_dialer(&node, resolver, epoch, anon.as_ref(), exit).await {
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
    let exit_line = exit_coord.map_or_else(
        || "\n  Clearnet: refused (no exit discovered — start an exit node, or pass --exit-via)".to_owned(),
        |[a, b, c]| {
            // The clearnet path now rides the *same* profile as a .fanos dial: anonymous → onion-routed to the
            // exit's service key (the exit learns only the target); direct → by-coordinate (the exit learns
            // your coordinate). State which, so the guarantee is never overclaimed (audit S1-C1).
            let how = if anon.is_some() { "anonymous (onion-routed to the exit)" } else { "direct — the exit learns your coordinate" };
            format!("\n  Clearnet: via exit {a}:{b}:{c} — {how}")
        },
    );
    eprintln!(
        "fanos proxy up — coordinate {x}:{y}:{z} on {}\n  SOCKS5:  socks5://{socks_listen}{http_line}{profile_line}{exit_line}",
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

/// Host a **hidden service** on the anonymous rendezvous (§3b, `design-anonymity-substrate.md`): run a node,
/// publish the service's descriptor so clients resolve its `.fanos` name, and forward every incoming
/// anonymous session to a local `--forward host:port` (the onion-service model). The service is reachable at
/// its rotating meeting line though this node is never that line's combiner, and no party — not even the
/// combiner — learns this node's coordinate. `--host-key <file>` is the service's secret seed, its **stable
/// `.fanos` identity** (keep it secret; generate one with `head -c 32 /dev/urandom > svc.key`). The dial
/// side is `fanos proxy --profile anonymous` with a matching `--epoch`/`--beacon`/`--threshold`.
async fn cmd_host(args: &[String]) -> Result<(), NodeError> {
    init_tracing();
    let forward: SocketAddr = flag(args, "--forward")
        .ok_or_else(|| NodeError::Config("fanos host requires --forward <host:port>".to_owned()))?
        .parse()
        .map_err(|_| NodeError::Config("bad --forward (expected host:port)".to_owned()))?;
    let host_secret = match flag(args, "--host-key") {
        Some(p) => std::fs::read(p)?,
        None => {
            return Err(NodeError::Config(
                "fanos host requires --host-key <file> — the service's secret seed and stable .fanos \
                 identity (generate one with `head -c 32 /dev/urandom > svc.key`)"
                    .to_owned(),
            ));
        }
    };
    let epoch = match flag(args, "--epoch") {
        Some(s) => {
            Epoch::new(s.parse().map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?)
        }
        None => Epoch::ZERO,
    };
    let beacon = match flag(args, "--beacon") {
        Some(s) => parse_beacon_hex(s)?,
        None => BeaconSeed::GENESIS,
    };
    let threshold: u8 = match flag(args, "--threshold") {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --threshold '{s}'")))?,
        None => 2,
    };
    if threshold == 0 {
        return Err(NodeError::Config("--threshold must be at least 1".to_owned()));
    }
    let descriptor_pow: u32 = match flag(args, "--descriptor-pow") {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --descriptor-pow '{s}'")))?,
        None => 0,
    };

    // Derive the service identity + its `.fanos` address from the secret seed.
    let service = StaticKeypair::generate(&mut SeedRng::from_seed(&host_secret));
    let bundle = bundle_from_kem_public(service.public());
    let address = Address::from_bundle(&bundle);

    let config = node_config_from_args(args)?;
    let mut node = Node::start::<F2>(config).await?;
    let health = node.health();

    // Publish the descriptor so clients resolve `<name>.fanos` → the service key. The coordinate is a
    // PLACEHOLDER (all-zero): an anonymous dial derives the meeting line from the KEY and ignores it, and
    // publishing this node's real coordinate would deanonymize the service (§3b).
    if let Err(e) =
        publish_service(&node.client(), &bundle, [0, 0, 0], epoch, descriptor_pow, b"profile=anonymous")
            .await
    {
        node.shutdown();
        return Err(e);
    }

    // Forward each accepted anonymous session to the local target (the onion-service model).
    let handler = move |mut stream: DuplexStream| async move {
        match TcpStream::connect(forward).await {
            Ok(mut tcp) => {
                let _ = copy_bidirectional(&mut stream, &mut tcp).await;
            }
            Err(e) => info!(%forward, error = %e, "hidden-service forward dial failed"),
        }
    };
    let _driver = spawn_rendezvous_host(
        node.client(),
        node.address(),
        service,
        host_secret,
        threshold,
        (epoch, *beacon.as_bytes()),
        handler,
    );

    let [x, y, z] = health.address;
    eprintln!(
        "fanos host up — coordinate {x}:{y}:{z} on {}\n  address: {}\n  forward: {forward}\n  \
         profile: anonymous (threshold {threshold}, epoch {}) — clients dial `--profile anonymous`",
        health.local_addr,
        address.to_name(),
        epoch.get(),
    );
    info!(coord = ?health.address, name = %address.to_name(), %forward, "fanos host up");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown signal received");
    };
    tokio::select! {
        () = shutdown => {}
        () = async { while let Some(n) = node.next_notification().await { log_notification(&n); } } => {}
    }
    node.shutdown();
    eprintln!("fanos host down");
    Ok(())
}

/// Run a full-tunnel VPN (spec §11.4): capture traffic at a TUN device and tunnel every TCP and UDP flow
/// through a FANOS exit, so system-wide traffic (DNS, QUIC, HTTPS, …) rides the overlay without per-app proxy
/// config. A userspace TCP/IP stack terminates each flow at the TUN; TCP bridges to a byte-stream exit, UDP
/// to the exit's UDP tunnel. Requires an exit (`--exit-via FILE`, or a discoverable one) since every flow
/// leaves through it, and root / `CAP_NET_ADMIN` for the TUN device. The device is brought up; the operator
/// assigns its address and route so the kernel steers traffic to it.
#[cfg(feature = "vpn")]
async fn cmd_vpn(args: &[String]) -> Result<(), NodeError> {
    init_tracing();

    let tun_name = flag(args, "--tun").unwrap_or("").to_owned();
    let epoch = match flag(args, "--epoch") {
        Some(s) => Epoch::new(
            s.parse()
                .map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?,
        ),
        None => Epoch::ZERO,
    };
    let exit_via = parse_exit_via(args)?;

    let config = node_config_from_args(args)?;
    let mut node = Node::start::<F2>(config).await?;
    // Every UDP flow leaves via the exit; without one the datapath could relay nothing.
    let exit = match exit_via {
        Some(e) => Some(e),
        None => discover_exit(&node, epoch).await,
    };
    let Some((exit_coord, exit_public)) = exit else {
        node.shutdown();
        return Err(NodeError::Config(
            "fanos vpn needs a clearnet exit (--exit-via FILE, or a discoverable exit) — every UDP flow \
             leaves through it"
                .to_owned(),
        ));
    };
    // The datapath dials clearnet destinations by IP through the exit (TCP byte-streams and UDP tunnels); it
    // never resolves `.fanos` names, so an empty resolver suffices. Shared behind an `Arc` — the full-tunnel
    // stack spawns a per-flow bridge task, each needing `&D`.
    let dialer = Arc::new(
        FanosDialer::new(node.client(), StaticResolver::new()).with_exit(exit_coord, exit_public),
    );

    let device = fanos_vpn::device::open_tun(&tun_name).map_err(|e| {
        NodeError::Config(format!(
            "opening the TUN device failed ({e}) — root / CAP_NET_ADMIN is required"
        ))
    })?;

    let [x, y, z] = node.address();
    let [ex, ey, ez] = exit_coord;
    let tun_shown = if tun_name.is_empty() { "<auto>" } else { &tun_name };
    eprintln!(
        "fanos vpn up — coordinate {x}:{y}:{z}, TUN '{tun_shown}', TCP+UDP full-tunnel via exit \
         {ex}:{ey}:{ez}\n  (assign the TUN an address + route so the kernel steers traffic to it)"
    );
    info!(coord = ?node.address(), tun = %tun_name, "fanos vpn up");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown signal received");
    };
    tokio::select! {
        () = fanos_vpn::run_fulltunnel(device, dialer) => {}
        () = shutdown => {}
        () = async { while let Some(n) = node.next_notification().await { log_notification(&n); } } => {}
    }
    node.shutdown();
    eprintln!("fanos vpn down");
    Ok(())
}

/// Without the `vpn` feature the binary has no TUN device support; report it rather than silently missing.
#[cfg(not(feature = "vpn"))]
#[allow(clippy::unused_async)] // async to match the command dispatch (`cmd_vpn(..).await`)
async fn cmd_vpn(_args: &[String]) -> Result<(), NodeError> {
    Err(NodeError::Config(
        "this build has no VPN support — rebuild with `cargo build -p fanos-node --features vpn`".to_owned(),
    ))
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
    exit: Option<([u32; 3], HybridKemPublic)>,
) -> Result<FanosDialer<NodeResolver>, NodeError> {
    let base = if let Some(cfg) = anon {
        // Prefer the node's LIVE beacon (audit S1-M2) so the mix directory + meeting lines track the epoch the
        // relays have actually rotated to; fall back to the static --epoch/--beacon before the first round is
        // adopted. Without this the proxy stays pinned at epoch 0 and its dials break after the first turn.
        let (epoch, beacon) = node
            .live_beacon()
            .map_or((epoch, cfg.beacon), |(e, s)| (e, BeaconSeed::new(s)));
        let directory = build_cell_mix_directory::<F2>(&node.client(), epoch).await;
        let need = usize::from(cfg.threshold) + 1;
        if directory.len() < need {
            return Err(NodeError::Config(format!(
                "anonymous profile needs at least threshold+1={need} live mix relays for epoch {}, \
                 found {} — start relays that publish mix keys or lower --threshold",
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
            beacon,
            depths: (cfg.fwd_depth, cfg.reply_depth),
        };
        FanosDialer::anonymous_fresh(node.client(), resolver, params)
    } else {
        FanosDialer::new(node.client(), resolver)
    };
    // With an exit configured, clearnet (non-`.fanos`) targets ride it; without one they are refused.
    Ok(match exit {
        Some((coord, public)) => base.with_exit(coord, public),
        None => base,
    })
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

/// `fanos beacon-deal <n> <t> [--out DIR]`: deal a `t`-of-`n` threshold-DVRF beacon key from OS entropy and
/// write each anchor's provisioning file (`anchor-<i>.beacon`, `i = 1..=n`) plus a share-less
/// `consumer.beacon` into `DIR` (default `.`). Provision a node with `fanos node --beacon-params
/// anchor-<i>.beacon` so it runs the live epoch clock (audit S1-H2). A single-operator convenience — a
/// trust-minimized deployment runs the networked DKG instead, so no one party ever holds the whole key.
fn cmd_beacon_deal(args: &[String]) -> Result<(), NodeError> {
    let usage = || NodeError::Config("usage: fanos beacon-deal <n> <t> [--out DIR]".to_owned());
    let n: usize = args.first().and_then(|s| s.parse().ok()).ok_or_else(usage)?;
    let t: usize = args.get(1).and_then(|s| s.parse().ok()).ok_or_else(usage)?;
    let out = flag(args, "--out").unwrap_or(".");

    // The beacon secret and the polynomial RNG are both drawn from OS entropy — this tool holds the whole key
    // for the moment of dealing (unlike the DKG), so it exists only to bootstrap a single-operator network.
    let mut secret = [0u8; 32];
    let mut rng_seed = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    getrandom::fill(&mut rng_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let (shares, commitment) = deal(&secret, t, n, &mut DeterministicRng::new(&rng_seed))
        .ok_or_else(|| NodeError::Config(format!("cannot deal {t}-of-{n}: need 1 <= t <= n <= 255")))?;

    for (i, share) in shares.iter().enumerate() {
        let params =
            BeaconParams { commitment: commitment.clone(), threshold: t, share: Some(share.clone()) };
        let path = format!("{out}/anchor-{}.beacon", i + 1);
        std::fs::write(&path, params.to_config_string())?;
        println!("wrote {path}");
    }
    let consumer = BeaconParams { commitment, threshold: t, share: None };
    let cpath = format!("{out}/consumer.beacon");
    std::fs::write(&cpath, consumer.to_config_string())?;
    println!("wrote {cpath}");
    println!("dealt a {t}-of-{n} beacon; run each anchor with `fanos node --beacon-params anchor-<i>.beacon`");
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

/// Discover a clearnet exit from the live cell exit directory for `epoch` — the best-effort roster the
/// cell advertises through the overlay store (each exit republishes per epoch). Picks one at random, so a
/// proxy restart spreads load across the available exits. `None` if none is currently published (clearnet
/// targets are then refused).
async fn discover_exit(node: &Node, epoch: Epoch) -> Option<([u32; 3], HybridKemPublic)> {
    let mut exits = build_cell_exit_directory::<F2>(&node.client(), epoch).await;
    let n = exits.len();
    if n == 0 {
        return None;
    }
    let mut buf = [0u8; 1];
    getrandom::fill(&mut buf).ok()?;
    let [byte] = buf;
    let picked = exits.swap_remove(usize::from(byte) % n);
    info!(exit = ?picked.0, available = n, "discovered a clearnet exit from the live directory");
    Some(picked)
}

/// Parse the exit descriptor for the proxy's clearnet path from `--exit-via <file>`: a `key = value` file
/// with `coord = x:y:z` (the exit's overlay coordinate) and `key = <hex>` (its DIAULOS service public key,
/// the hex of `HybridKemPublic::encode` — an exit logs this line at startup). `None` if the flag is absent,
/// in which case the proxy stays `.fanos`-only.
fn parse_exit_via(args: &[String]) -> Result<Option<([u32; 3], HybridKemPublic)>, NodeError> {
    let Some(path) = flag(args, "--exit-via") else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(path)?;
    let mut coord: Option<[u32; 3]> = None;
    let mut key: Option<HybridKemPublic> = None;
    for (n, raw) in text.lines().enumerate() {
        let l = raw.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let (k, v) = l.split_once('=').ok_or_else(|| {
            NodeError::Config(format!("exit-via line {}: expected `key = value`", n + 1))
        })?;
        match k.trim() {
            "coord" => coord = Some(parse_coord_str(v.trim())?),
            "key" => {
                let bytes = decode_hex(v.trim())
                    .ok_or_else(|| NodeError::Config("exit-via `key` is not valid hex".to_owned()))?;
                key = Some(HybridKemPublic::decode(&bytes).ok_or_else(|| {
                    NodeError::Config("exit-via `key` is not a valid hybrid public key".to_owned())
                })?);
            }
            other => return Err(NodeError::Config(format!("unknown exit-via key '{other}'"))),
        }
    }
    let coord = coord.ok_or_else(|| NodeError::Config("exit-via missing `coord`".to_owned()))?;
    let key = key.ok_or_else(|| NodeError::Config("exit-via missing `key`".to_owned()))?;
    Ok(Some((coord, key)))
}

/// Parse a `x:y:z` overlay coordinate.
fn parse_coord_str(s: &str) -> Result<[u32; 3], NodeError> {
    let mut it = s.split(':');
    let mut next = || {
        it.next()
            .and_then(|p| p.trim().parse::<u32>().ok())
            .ok_or_else(|| NodeError::Config(format!("bad coordinate '{s}' (expected x:y:z)")))
    };
    let c = [next()?, next()?, next()?];
    if it.next().is_some() {
        return Err(NodeError::Config(format!("coordinate '{s}' must be x:y:z")));
    }
    Ok(c)
}

/// Decode a hex string into bytes (`None` on an odd length or a non-hex character).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        match pair {
            [h, l] => out.push((nib(*h)? << 4) | nib(*l)?),
            _ => return None, // odd length
        }
    }
    Some(out)
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
         \x20 fanos node  [--config FILE] [--listen ADDR] [--identity PATH] [--bootstrap x:y:z@host:port,...] \\\n\
         \x20             [--role relay,storage,service,exit] [--service FILE] [--exit FILE] \\\n\
         \x20             [--no-heartbeat] [--proteus-secret SECRET] [--proteus-morph MORPH] \\\n\
         \x20             [--proteus-environment ENV] [--mix-delay-ms N] [--cover-interval-ms N] \\\n\
         \x20             [--beacon-params FILE]\n\
         \x20 fanos proxy [--socks-listen ADDR] [--http-listen ADDR] [--epoch N] [--min-pow BITS] \\\n\
         \x20             [--profile direct|anonymous] [--threshold T] [--fwd-depth D] [--reply-depth D] \\\n\
         \x20             [--beacon HEX64] [--exit-via FILE] [--config FILE] [--identity PATH] \\\n\
         \x20             [--bootstrap ...] [--listen ADDR]\n\
         \x20 fanos host  --forward HOST:PORT --host-key FILE [--epoch N] [--beacon HEX64] [--threshold T] \\\n\
         \x20             [--descriptor-pow BITS] [--config FILE] [--bootstrap ...] [--listen ADDR]\n\
         \x20             (host a hidden service on the anonymous rendezvous §3b: forward each incoming\n\
         \x20             anonymous session to a local port; --host-key is your stable .fanos identity)\n\
         \x20 fanos vpn   [--tun NAME] [--exit-via FILE] [--epoch N] [--config FILE] [--bootstrap ...]\n\
         \x20             (full-tunnel: routes all TCP+UDP through an exit; needs --features vpn + root)\n\
         \x20 fanos id    [--identity PATH]\n\
         \x20 fanos resolve NAME.fanos [--epoch N] [--min-pow BITS] [--bootstrap ...]\n\
         \x20 fanos beacon-deal N T [--out DIR]  (deal a T-of-N epoch-clock beacon; writes *.beacon files)\n\
         \x20 fanos help\n\
         \n\
         PROXY PROFILES:\n\
         \x20 direct     reach services by coordinate — fast, but reveals where each party is (default)\n\
         \x20 anonymous  draw a FRESH threshold-onion rendezvous route per dial from the live mix\n\
         \x20            directory, so successive connections are unlinkable (needs live relays; the\n\
         \x20            --beacon is the epoch's public randomness, shared by the service)\n\
         \n\
         SERVICE FILE (--service, threshold-hosted CALYPSO §12.3): a `key = value` file with\n\
         \x20 seed = <64 hex>            this member's key seed (secret; the operator hands it out)\n\
         \x20 line = x:y:z,x:y:z,...     the line's member coordinates, in seal order\n\
         \x20 threshold = T             members that must cooperate to serve an intro\n\
         \x20 (providing it implies the `service` role)\n\
         \n\
         EXIT FILE (--exit, clearnet exit relay): a `key = value` file with\n\
         \x20 seed = <64 hex>            the exit's service-identity seed (secret; clients dial this key)\n\
         \x20 ports = 80,443            destination ports to allow (omit = ANY port — an open relay)\n\
         \x20 (providing it implies the `exit` role; the node logs its `coord`/`key` descriptor at startup)\n\
         \n\
         CLEARNET (proxy): by default `fanos proxy` DISCOVERS an exit from the live cell directory (exits\n\
         \x20 advertise themselves each epoch) and routes clearnet (non-.fanos) targets through it. Pin a\n\
         \x20 specific exit with --exit-via FILE, a `key = value` file with\n\
         \x20 coord = x:y:z              the exit node's coordinate (from its startup log)\n\
         \x20 key   = <hex>              the exit's service public key (from its startup log)\n\
         \x20 If no exit is discovered and none is pinned, clearnet targets are refused (.fanos-only).\n\
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn service_flag_provisions_the_service_role() {
        // `--service <file>` reads the threshold-hosting parameters and implies the `service` role.
        let path =
            std::env::temp_dir().join(format!("fanos-svc-{}.conf", std::process::id()));
        std::fs::write(
            &path,
            format!("seed = {}\nline = 1:0:0, 0:1:0\nthreshold = 1\n", "ab".repeat(32)),
        )
        .unwrap();

        let args = vec!["--service".to_owned(), path.to_string_lossy().into_owned()];
        let config = node_config_from_args(&args).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(config.roles.service, "--service implies the service role");
        let sp = config.service.expect("service parameters were read");
        assert_eq!(sp.line, vec![[1, 0, 0], [0, 1, 0]]);
        assert_eq!(sp.threshold, 1);
    }

    #[test]
    fn exit_flag_provisions_the_exit_role() {
        // `--exit <file>` reads the exit parameters and implies the `exit` role.
        let path = std::env::temp_dir().join(format!("fanos-exit-{}.conf", std::process::id()));
        std::fs::write(&path, format!("seed = {}\nports = 80, 443\n", "ab".repeat(32))).unwrap();

        let args = vec!["--exit".to_owned(), path.to_string_lossy().into_owned()];
        let config = node_config_from_args(&args).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(config.roles.exit, "--exit implies the exit role");
        let ep = config.exit.expect("exit parameters were read");
        assert_eq!(ep.allowed_ports, vec![80, 443]);
    }

    #[test]
    fn exit_via_parses_an_exit_descriptor() {
        use core::fmt::Write as _;

        use fanos_pqcrypto::{HybridKemSecret, SeedRng};
        // Build a descriptor from a real public key (as an exit logs it) and parse it back.
        let (_sk, pk) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xE1; 32]));
        let mut key_hex = String::new();
        for b in pk.encode() {
            let _ = write!(key_hex, "{b:02x}");
        }
        let path = std::env::temp_dir().join(format!("fanos-exitvia-{}.conf", std::process::id()));
        std::fs::write(&path, format!("coord = 1:2:3\nkey = {key_hex}\n")).unwrap();

        let args = vec!["--exit-via".to_owned(), path.to_string_lossy().into_owned()];
        let parsed = parse_exit_via(&args).unwrap().expect("descriptor present");
        std::fs::remove_file(&path).ok();

        assert_eq!(parsed.0, [1, 2, 3], "coordinate parsed");
        assert_eq!(parsed.1.encode(), pk.encode(), "the public key round-trips");
        // No flag = no exit.
        assert!(parse_exit_via(&[]).unwrap().is_none());
    }

    #[test]
    fn decode_hex_round_trips() {
        assert_eq!(decode_hex("00ff10ab").unwrap(), vec![0x00, 0xff, 0x10, 0xab]);
        assert_eq!(decode_hex(""), Some(Vec::new()));
        assert!(decode_hex("abc").is_none(), "odd length rejected");
        assert!(decode_hex("zz").is_none(), "non-hex rejected");
    }
}
