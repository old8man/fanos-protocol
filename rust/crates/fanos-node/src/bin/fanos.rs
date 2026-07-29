//! `fanos` — the unified FANOS node binary (roadmap Phase 1).
//!
//! Subcommands:
//!   * `fanos node`  — run a node (overlay membership, storage, healing) over QUIC.
//!   * `fanos proxy` — run local SOCKS5 / HTTP-CONNECT listeners tunnelling to `.fanos` services (§11.3).
//!   * `fanos host`  — host a hidden service on the anonymous rendezvous, forwarding to a local port (§3b).
//!   * `fanos validator` / `taxis-deal` — deal + run a TAXIS blockchain cell over the DROMOS ledger.
//!   * `fanos id`    — print (and optionally persist) a node's self-certifying coordinate.
//!   * `fanos help`  — usage.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
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
    HostedService, build_cell_mix_directory, identity, publish_service, serve_proxy, spawn_rendezvous_host,
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
        Some("message") => cmd_message(args.get(2..).unwrap_or(&[])).await,
        Some("validator") => cmd_validator(args.get(2..).unwrap_or(&[])).await,
        Some("pay") => cmd_pay(args.get(2..).unwrap_or(&[])).await,
        Some("vpn") => cmd_vpn(args.get(2..).unwrap_or(&[])).await,
        Some("init") => cmd_init(args.get(2..).unwrap_or(&[])),
        Some(v @ ("start" | "stop" | "restart")) => cmd_service_lifecycle(v),
        Some("uninstall") => cmd_uninstall(args.get(2..).unwrap_or(&[])),
        Some("status") => cmd_status(args.get(2..).unwrap_or(&[])).await,
        Some("id") => cmd_id(args.get(2..).unwrap_or(&[])),
        Some("beacon-deal") => cmd_beacon_deal(args.get(2..).unwrap_or(&[])),
        Some("taxis-deal") => cmd_taxis_deal(args.get(2..).unwrap_or(&[])),
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
/// Warn when anonymity is requested on a plane that cannot provide it.
///
/// An adversary's flow-matching floor in a linkability measurement is `1/K` for `K` concurrent circuits, and `K` comes
/// from the **plane**, not the mix schedule: `PG(2,2)` has only 4 lines with *distinct* combiners, so it supports 2
/// circuits and the best any schedule achieves is a coin flip (`fanos_node::config::plane_order`).
///
/// Under-delivering an anonymity request in silence is the worse failure. An operator who is told can raise the order or
/// accept the limit knowingly; one who is not told believes the profile's name.
/// The mixnet hop threshold for this invocation: `--threshold` if given, else derived from `--plane-order`.
///
/// One helper rather than three copies, because the client and the relay must agree exactly — a client seals
/// each onion layer for precisely this many members — and three `None => 2` defaults are three chances to
/// diverge. The derivation is [`fanos_node::node::mix_threshold`]: a hop is a line of `q+1` points, and a
/// threshold fixed at the Fano value lets any two corrupt members own a hop however wide the line is
/// (`docs/audit.md` E7).
fn mix_threshold_arg(args: &[String]) -> Result<u8, NodeError> {
    if let Some(s) = flag(args, "--threshold") {
        return s.parse().map_err(|_| NodeError::Config(format!("bad --threshold '{s}'")));
    }
    let plane_order: u32 = match flag(args, "--plane-order") {
        Some(s) => s
            .parse()
            .map_err(|_| NodeError::Config(format!("bad --plane-order '{s}' (expected 2, 4, 7 or 31)")))?,
        None => 2,
    };
    u8::try_from(fanos_node::node::mix_threshold((plane_order + 1) as usize))
        .map_err(|_| NodeError::Config("plane order too large for a u8 threshold".to_owned()))
}

fn warn_if_plane_cannot_anonymize(config: &NodeConfig) {
    if config.plane_order > 2 {
        return;
    }
    eprintln!(
        "warning: anonymity requested on plane order {q} — PG(2,{q}) supports only 2 concurrent circuits, so a passive \
         adversary's flow-matching floor is a COIN FLIP (0.50) regardless of the mix schedule. Pass \
         `--plane-order 4|7|31` for the anonymity the profile implies (every node of a cell must agree on it); see \
         fanos_node::config::plane_order.",
        q = config.plane_order
    );
}

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
    // The cell's projective plane order. Exposed because it is the parameter that BOUNDS anonymity — an adversary's
    // flow-matching floor is `1/K` for `K` concurrent circuits, and `K` comes from the plane, not the mix schedule
    // (`fanos_node::config::plane_order`). Every node of a cell must agree on it, so it belongs in the same
    // out-of-band configuration as the bootstrap set rather than being negotiated.
    if let Some(s) = flag(args, "--plane-order") {
        config.plane_order = s
            .parse::<u32>()
            .map_err(|_| NodeError::Config(format!("bad --plane-order '{s}' (expected 2, 4, 7 or 31)")))?;
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
        config.mix_mean_delay = Duration::from_millis(ms);
    }
    if let Some(s) = flag(args, "--cover-interval-ms") {
        // A relay's mean cover-cell interval in ms (spec §L5/V8, audit S1-H1/E1); 0 disables cover traffic.
        let ms = s.parse().map_err(|_| NodeError::Config(format!("bad --cover-interval-ms '{s}'")))?;
        config.cover_interval = Duration::from_millis(ms);
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
    // Kept before the config moves into `start`: the epoch floor a cell measures is only a verdict next to
    // the cadence this node was actually configured with.
    let epoch_period = config.epoch_period;
    let mut node = Node::start_on_plane(config).await?;
    let health = node.health();
    let [x, y, z] = health.address;
    info!(coord = ?health.address, local_addr = %health.local_addr, peers = health.known_peers, "fanos node up");
    eprintln!(
        "fanos node up — coordinate {x}:{y}:{z} on {} ({} bootstrap peers)",
        health.local_addr, health.known_peers
    );

    // The control socket, so an operator can ask this process anything while it runs. Its absence is not fatal:
    // a node that cannot bind its admin socket is still a working node, and refusing to run over a control
    // channel would be the tool getting in the way of the thing it exists to serve.
    let (admin_tx, mut admin_rx) = tokio::sync::mpsc::channel::<fanos_node::admin::Envelope>(16);
    let admin_socket = fanos_node::admin::socket_path(&data_dir_for(args));
    match fanos_node::admin::serve(&admin_socket, admin_tx) {
        Ok(_task) => eprintln!("control socket: {}", admin_socket.display()),
        Err(e) => eprintln!("control socket unavailable ({e}) — `fanos status` will fall back to the config"),
    }

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            biased;
            _ = &mut ctrl_c => {
                info!("shutdown signal received");
                break;
            }
            Some((req, reply)) = admin_rx.recv() => {
                use fanos_node::admin::Request;
                let stop = matches!(req, Request::Shutdown);
                let body = match req {
                    Request::Ping => "pong\n".to_owned(),
                    Request::Health => fanos_node::admin::render_health(&node.health()),
                    Request::Roles => format!("{:?}\n", node.assigned_roles()),
                    Request::Shutdown => "shutting down\n".to_owned(),
                    Request::Census => {
                        // Answered off the loop. A census reads every cell coordinate out of the overlay store,
                        // so serving it inline would stop this node driving its own engine for the duration —
                        // an operator's question is not worth pausing the node it is about.
                        let client = node.client();
                        let epoch = node.live_beacon().map_or(Epoch::ZERO, |(e, _)| e);
                        tokio::spawn(async move {
                            let coords = fanos_node::telemetry_dir::cell_telemetry_coords::<F2>();
                            let census =
                                fanos_node::telemetry_dir::take_census(&client, &coords, epoch).await;
                            let _ = reply.send(census.to_string());
                        });
                        continue;
                    }
                };
                let _ = reply.send(body);
                if stop {
                    info!("shutdown requested over the control socket");
                    break;
                }
            }
            note = node.next_notification() => match note {
                Some(n) => log_notification_against(&n, Some(epoch_period)),
                None => break,
            },
        }
    }
    node.shutdown();
    // Take the control socket with us. The serving task clears it when its accept loop ends, but a clean exit
    // leaves the process before that task is polled again — so without this a normal shutdown leaves the path
    // behind. Not fatal (`serve` clears a stale socket, and `ask` reads a refused connection as "not running"),
    // but a state directory that is tidy after a clean stop is one an operator can trust at a glance.
    let _ = std::fs::remove_file(&admin_socket);
    eprintln!("fanos node down");
    Ok(())
}

/// Where this invocation's state lives — the directory the control socket goes in.
///
/// `--data` if given, else the platform layout this host was set up with, so `fanos status` finds the socket of a
/// node started by the service unit without being told where to look.
fn data_dir_for(args: &[String]) -> PathBuf {
    flag(args, "--data")
        .map_or_else(|| fanos_node::setup::Paths::detect().data, PathBuf::from)
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
    if anon.is_some() {
        warn_if_plane_cannot_anonymize(&config);
    }
    let mut node = Node::start_on_plane(config).await?;
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
    let threshold = mix_threshold_arg(args)?;
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
    let mut node = Node::start_on_plane(config).await?;
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
        // A `Node` always runs VRF coordinates, so each mix-key record must prove the slot it sits at (S1-M3).
        HostedService { service, host_secret, threshold, vrf_coordinates: true },
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
    let mut node = Node::start_on_plane(config).await?;
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
        // `Some(beacon)` — the live beacon resolved just above. A forged mix key at another relay's slot is
        // refused rather than sealed to (S1-M3).
        let directory = build_cell_mix_directory::<F2>(&node.client(), epoch, Some(beacon)).await;
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
    let threshold = mix_threshold_arg(args)?;
    if threshold == 0 {
        return Err(NodeError::Config("--threshold must be at least 1".to_owned()));
    }
    // A circuit is `depth` intermediate hops plus its destination line, so it costs `depth + 1` slots of the fixed-slot
    // onion header. Checked here because the failure is otherwise **silent**: `create_forward` swallows the over-depth error
    // with `.ok()?`, so an operator who raises this past the ceiling gets dials that quietly never connect rather than a
    // message saying why. The default of 2 sits exactly at the ceiling for the Fano plane.
    let line_size = fanos_geometry::fano::LINE_SIZE;
    let max_depth = fanos_aphantos::slots::depth_for(line_size).saturating_sub(1);
    let (fwd_depth, reply_depth) = (usize_flag("--fwd-depth", 2)?, usize_flag("--reply-depth", 2)?);
    for (name, depth) in [("--fwd-depth", fwd_depth), ("--reply-depth", reply_depth)] {
        if depth > max_depth {
            return Err(NodeError::Config(format!(
                "{name} is {depth}, but the onion header carries at most {} hops on this plane, so {max_depth} \
                 intermediate hops. A deeper circuit needs payload fragmentation, not a wider cell — widening the cell buys \
                 more slots and so a SMALLER payload.",
                max_depth + 1
            )));
        }
    }
    Ok(AnonConfig {
        threshold,
        fwd_depth,
        reply_depth,
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

// ============================== first-run setup ==============================

/// Ask a yes/no question, defaulting to `yes_default` when the operator just presses return.
///
/// Non-interactive input (a pipe, a provisioning script) takes the default rather than blocking forever: a setup
/// tool that hangs waiting for a terminal that will never appear is worse than one that makes the documented
/// choice and says which.
fn ask_yes_no(question: &str, yes_default: bool) -> bool {
    let hint = if yes_default { "[Y/n]" } else { "[y/N]" };
    eprint!("  {question} {hint} ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut line = String::new();
    if std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line).unwrap_or(0) == 0 {
        eprintln!("{}", if yes_default { "yes (no terminal)" } else { "no (no terminal)" });
        return yes_default;
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => yes_default,
    }
}

/// Ask a free-text question, returning `default` on an empty answer or a closed stdin.
fn ask_line(question: &str, default: &str) -> String {
    if default.is_empty() {
        eprint!("  {question}: ");
    } else {
        eprint!("  {question} [{default}]: ");
    }
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut line = String::new();
    if std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line).unwrap_or(0) == 0 {
        eprintln!("{default} (no terminal)");
        return default.to_owned();
    }
    let answered = line.trim();
    if answered.is_empty() { default.to_owned() } else { answered.to_owned() }
}

/// Write `contents` to `path`, creating parents, and restrict it to its owner when `secret`.
///
/// The permission is set **before** the bytes land, not after: a key written world-readable and chmod-ed a
/// microsecond later was world-readable, and on a shared host that is the whole of the exposure.
fn write_file(path: &Path, contents: &str, secret: bool) -> Result<(), NodeError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if secret {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        std::io::Write::write_all(&mut f, contents.as_bytes())?;
    } else {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

/// The address to listen on: the operator's if given, otherwise the first port in a window from the default that
/// this host can actually bind.
///
/// Probed rather than assumed, because a taken default port is the commonest reason a freshly-installed daemon
/// never comes up — and it fails after the operator has walked away. Exhausting the window is reported as an
/// error rather than answered with a port we know does not bind.
fn choose_listen(args: &[String]) -> Result<SocketAddr, NodeError> {
    /// How many consecutive ports to try before giving up and asking the operator.
    const WINDOW: u16 = 64;
    if let Some(s) = flag(args, "--listen") {
        return s.parse().map_err(|_| NodeError::Config(format!("bad --listen '{s}'")));
    }
    let default_port = fanos_node::setup::DEFAULT_PORT;
    let port = fanos_node::setup::free_udp_port(default_port, WINDOW).ok_or_else(|| {
        NodeError::Config(format!(
            "no free UDP port in {default_port}..{} — pass --listen ADDR explicitly",
            default_port.saturating_add(WINDOW)
        ))
    })?;
    if port != default_port {
        eprintln!("\n  note: UDP {default_port} is taken; using {port} instead.");
    }
    Ok(SocketAddr::from(([0, 0, 0, 0], port)))
}

/// `fanos init [--yes] [--force] [--no-service] [--role …] [--listen ADDR] [--bootstrap …] [--telemetry ε]`
///
/// Turn a freshly-installed binary into a running node. Everything determinable is determined — where files
/// belong on this OS and under this user, which port actually binds, whether there is an init system we may write
/// to — and the operator answers only what cannot be derived: what this node offers, and whose cell it joins.
///
/// `--yes` takes every default without asking, which is what a provisioning script wants; the same path is taken
/// automatically when stdin is not a terminal, so the tool never hangs waiting for a human who is not there.
fn cmd_init(args: &[String]) -> Result<(), NodeError> {
    let assume_yes = has_flag(args, "--yes");
    let force = has_flag(args, "--force");
    let paths = fanos_node::setup::Paths::detect();

    eprintln!("fanos init — setting this host up as a FANOS node\n");
    eprintln!("  configuration : {}", paths.config.display());
    eprintln!("  identity      : {}", paths.identity.display());
    eprintln!("  state         : {}", paths.data.display());

    // Refuse to overwrite a live deployment. An `init` that silently replaced a running node's identity would
    // change its coordinate, and the cell would see the old one simply vanish.
    if paths.config.exists() && !force {
        return Err(NodeError::Config(format!(
            "{} already exists — this host is already set up.\n  Re-run with --force to replace it (this \
             regenerates nothing: an existing identity file is kept).",
            paths.config.display()
        )));
    }

    // --- what cannot be derived ---
    let mut config = NodeConfig {
        roles: fanos_node::setup::default_roles(),
        ..NodeConfig::default()
    };
    if let Some(r) = flag(args, "--role") {
        config.roles = RoleSet::parse(r)?;
    } else if !assume_yes {
        eprintln!("\nWhat should this node offer the network?");
        eprintln!("  relay      — carry other nodes' traffic (the network's substance)");
        eprintln!("  storage    — hold shards of the distributed store");
        eprintln!("  service    — host addressable services");
        eprintln!("  rendezvous — help clients and hidden services meet");
        eprintln!("  exit       — carry traffic to the clear internet UNDER THIS HOST'S ADDRESS");
        let answer = ask_line("roles (comma-separated)", &config.roles.to_string());
        config.roles = RoleSet::parse(&answer)?;
    }
    if config.roles.exit {
        eprintln!(
            "\n  ! This node will act as an exit. Traffic other people send leaves to the clear internet from\n    \
             this host's IP address, and complaints arrive here. Make sure that is what you intend."
        );
    }

    config.listen = choose_listen(args)?;

    // --- joining, or starting a new cell ---
    for value in flag_all(args, "--bootstrap") {
        for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            config.bootstrap.push(Peer::parse(part)?);
        }
    }
    if config.bootstrap.is_empty() && !assume_yes {
        eprintln!("\nJoin an existing cell, or start a new one?");
        eprintln!("  Paste seed peers as `x:y:z@host:port` (comma-separated), or leave empty to start fresh.");
        let answer = ask_line("bootstrap peers", "");
        for part in answer.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            config.bootstrap.push(Peer::parse(part)?);
        }
    }

    // --- health telemetry: opt-in, and it stays opt-in ---
    match flag(args, "--telemetry") {
        Some(s) => {
            let eps: f64 =
                s.parse().map_err(|_| NodeError::Config(format!("bad --telemetry '{s}'")))?;
            config.telemetry_epsilon = Some(eps);
        }
        None => {
            if !assume_yes {
                eprintln!("\nPublish this node's health readings (differentially private, ε-noised)?");
                eprintln!("  They describe the cell you sit in, so this is your call, and the default is no.");
                if ask_yes_no("publish health readings?", false) {
                    config.telemetry_epsilon = Some(1.0);
                }
            }
        }
    }

    // --- identity: generated once, kept forever ---
    // The directories first. `load_or_generate` writes the key where it is told and does not invent a home for
    // it, so on a host that has never run FANOS the very first write fails with a bare ENOENT — which is what
    // this wizard exists to prevent an operator from ever meeting. Found by running it, not by reading it.
    if let Some(parent) = paths.identity.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(&paths.data)?;
    let credentials = identity::load_or_generate(Some(&paths.identity))?;
    let [x, y, z] = identity::coordinate::<F2>(&credentials);
    config.identity_path = Some(paths.identity.clone());

    ensure_beacon(&mut config, &paths, assume_yes, has_flag(args, "--private-cell"))?;

    // --- write ---
    let rendered = fanos_node::setup::render_config(&config, &paths.identity);
    write_file(&paths.config, &rendered, false)?;
    eprintln!("\n  wrote {}", paths.config.display());
    eprintln!("  coordinate {x}:{y}:{z}");

    // --- the daemon ---
    if has_flag(args, "--no-service") {
        eprintln!("\nSkipping service installation (--no-service). Run it in the foreground with:");
        eprintln!("  fanos node --config {}", paths.config.display());
        return Ok(());
    }
    install_service(&paths, assume_yes)?;

    eprintln!("\nDone. This node's seed address, for others joining your cell:");
    eprintln!("  {x}:{y}:{z}@<this-host>:{}", config.listen.port());
    eprintln!("Check on it with:  fanos status");
    Ok(())
}

/// Make sure a relaying node has the epoch beacon it needs, or stop being a relay.
///
/// `Node::start` refuses to relay without beacon parameters, and that check is right — which made a
/// wizard-written config unstartable, the exact failure this command exists to prevent. Which way out is correct
/// depends on something the operator has already told us:
///
///   * **starting a new cell** (no bootstrap peers) — there is no one to receive a beacon from, so this host *is*
///     the authority for it. Deal it here, 1-of-1, which is what `fanos beacon-deal 1 1` would produce.
///   * **joining an existing cell** — the beacon is that cell's genesis material and cannot be invented; a
///     locally-dealt one would put this node on a different epoch clock from every peer. So it is asked for, and
///     if it is not to hand the relay role is dropped **with the reason**, rather than writing a configuration
///     that fails at first start.
fn ensure_beacon(
    config: &mut NodeConfig,
    paths: &fanos_node::setup::Paths,
    assume_yes: bool,
    private_cell: bool,
) -> Result<(), NodeError> {
    let beacon_path = paths.config.with_file_name(fanos_node::setup::BEACON_FILE);
    if !config.roles.relay || beacon_path.exists() {
        return Ok(());
    }
    if config.bootstrap.is_empty() {
        // A cell with no one to join is a cell this host is *starting*, and someone has to hold its epoch clock
        // at the first instant. Dealing it here is right for a private cell and **wrong for a public network**,
        // so the difference is stated rather than assumed: coordinates derive from the beacon, so whoever holds
        // its shares influences where every joining node lands. A founder who deals 1-of-1 and then invites the
        // public holds that power over everyone who arrives, whether or not they ever use it.
        //
        // The alternative is not theoretical — `fanos-keygen` runs a real Byzantine-robust DKG (Feldman/Pedersen
        // with a GJKR complaint round) in which no party ever sees the whole key. It needs a set of founding
        // nodes to run *between*, which is why it cannot be what a single `fanos init` does, and exactly why
        // this path must not be walked into by default for a network meant to be public.
        // `--yes` must **not** reach past this. Every other question in this wizard has a defensible default;
        // this one does not, because taking it silently makes whoever ran the provisioning script the permanent
        // holder of an open network's epoch clock. A convenience that hands over a governance position without
        // saying so is worse than an inconvenience — so a non-interactive run must state its intent in the flag.
        if assume_yes && !private_cell {
            config.roles.relay = false;
            eprintln!("\n  ! starting a new cell non-interactively, and no beacon was dealt.");
            eprintln!("    Holding a cell's epoch beacon decides where every joining node lands, so it is not a");
            eprintln!("    thing `--yes` may assume. Choose explicitly:");
            eprintln!("      --private-cell   this is yours alone; deal the beacon here (1-of-1)");
            eprintln!("      (public network) run the distributed key generation across the founding nodes, then");
            eprintln!("                       set `beacon_params = <file>` and re-enable `relay`");
            eprintln!("    Relay role dropped for now; this node will still store and serve.");
            return Ok(());
        }
        if !assume_yes {
            eprintln!("\nThis host is starting a new cell, so it must hold the cell's epoch beacon.");
            eprintln!("  Coordinates derive from that beacon, so its holder influences where joining nodes land.");
            eprintln!("  For a private or test cell that is fine — you are the only operator.");
            eprintln!("  For a network you intend to open to others, deal it across the founding nodes with the");
            eprintln!("  distributed key generation instead, so no single party ever holds it.");
            if !ask_yes_no("this is a private/test cell — deal the beacon here?", true) {
                config.roles.relay = false;
                eprintln!("  relay role dropped. Run the DKG across your founding nodes, then set");
                eprintln!("  `beacon_params = <file>` and re-enable `relay`.");
                return Ok(());
            }
        }
        deal_own_beacon(&beacon_path)?;
        eprintln!("\n  dealt this cell's epoch beacon → {}", beacon_path.display());
        eprintln!("  give {} to every other node joining this cell.", fanos_node::setup::BEACON_FILE);
        eprintln!("  ! you now hold this cell's epoch clock. That is a governance position, not just a file.");
        return Ok(());
    }
    let given = if assume_yes {
        String::new()
    } else {
        eprintln!("\nThis cell's epoch beacon is genesis material held by whoever started it.");
        eprintln!("  Ask them for the `.beacon` file; without it this node cannot relay.");
        ask_line("path to the beacon file (empty to skip relaying)", "")
    };
    if given.is_empty() {
        config.roles.relay = false;
        eprintln!("  no beacon — dropping the relay role. This node will still store and serve.");
        eprintln!("  Add `beacon_params = <file>` to the config and re-enable `relay` when you have it.");
    } else {
        std::fs::copy(&given, &beacon_path)?;
        eprintln!("  installed the beacon → {}", beacon_path.display());
    }
    Ok(())
}

/// Deal this host its own 1-of-1 epoch beacon and write it where the config will point.
///
/// Only ever for a cell this host is *starting*. A single-operator bootstrap holds the whole key for the moment
/// of dealing, which is exactly what `fanos beacon-deal` documents about itself; a trust-minimized cell runs the
/// networked DKG instead so no one party ever sees it.
fn deal_own_beacon(path: &Path) -> Result<(), NodeError> {
    let mut secret = [0u8; 32];
    let mut rng_seed = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    getrandom::fill(&mut rng_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let (shares, commitment) = deal(&secret, 1, 1, &mut DeterministicRng::new(&rng_seed))
        .ok_or_else(|| NodeError::Config("could not deal a 1-of-1 beacon".to_owned()))?;
    let share = shares.first().cloned();
    let params = BeaconParams { commitment, threshold: 1, share };
    // Secret: it carries this cell's beacon share.
    write_file(path, &params.to_config_string(), true)
}

/// Install and (with consent) start the platform's service unit.
///
/// The unit is *written* here; activation is the operator's, because enabling a boot service is a change to the
/// machine and a setup tool should say what it is about to do. With `--yes` it proceeds, which is what a
/// provisioning run means by the flag.
fn install_service(paths: &fanos_node::setup::Paths, assume_yes: bool) -> Result<(), NodeError> {
    use fanos_node::setup::ServiceManager;
    let manager = ServiceManager::detect();
    if manager == ServiceManager::None {
        eprintln!("\nNo supervisor found (no systemd, no launchd). Run the node yourself with:");
        eprintln!("  fanos node --config {}", paths.config.display());
        return Ok(());
    }
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    let Some(unit_path) = manager.unit_path(&home) else { return Ok(()) };
    let exe = std::env::current_exe()?;

    let unit = match manager {
        ServiceManager::Launchd => fanos_node::setup::render_launchd_plist(
            &exe,
            &paths.config,
            &paths.data,
            &paths.data.join("fanos.log"),
        ),
        ServiceManager::SystemdSystem => {
            fanos_node::setup::render_systemd_unit(&exe, &paths.config, &paths.data, false)
        }
        ServiceManager::SystemdUser => {
            fanos_node::setup::render_systemd_unit(&exe, &paths.config, &paths.data, true)
        }
        ServiceManager::None => return Ok(()),
    };

    eprintln!("\nInstall a service so the node starts at boot and restarts on failure?");
    eprintln!("  unit: {}", unit_path.display());
    if !assume_yes && !ask_yes_no("write it?", true) {
        eprintln!("  skipped. Run in the foreground: fanos node --config {}", paths.config.display());
        return Ok(());
    }
    write_file(&unit_path, &unit, false)?;
    eprintln!("  wrote {}", unit_path.display());
    run_steps("activating", &manager.activation(&unit_path));
    Ok(())
}

/// Run a sequence of argv commands, reporting each.
///
/// Executed, not printed. An operator who asked for a node installed wants a running node, and a list of commands
/// to paste is the same work handed back to them. Run directly rather than through a shell: every one of these
/// carries a filesystem path, and a shell would make each of those an injection surface.
///
/// A failing step is reported and the sequence continues, because these are independent facts about the system —
/// `loginctl enable-linger` failing on a host without logind must not prevent the unit from having been enabled.
fn run_steps(what: &str, steps: &[Vec<String>]) {
    if steps.is_empty() {
        return;
    }
    eprintln!("\n{what}:");
    for step in steps {
        let Some((program, rest)) = step.split_first() else { continue };
        let shown = step.join(" ");
        match std::process::Command::new(program).args(rest).status() {
            Ok(status) if status.success() => eprintln!("  ✓ {shown}"),
            Ok(status) => eprintln!("  ! {shown} — exited {status}"),
            Err(e) => eprintln!("  ! {shown} — could not run: {e}"),
        }
    }
}

/// `fanos start` / `fanos stop` / `fanos restart`: drive the installed service.
fn cmd_service_lifecycle(verb: &str) -> Result<(), NodeError> {
    use fanos_node::setup::ServiceManager;
    let manager = ServiceManager::detect();
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    let Some(unit) = manager.unit_path(&home) else {
        return Err(NodeError::Config(
            "no service manager on this host — run the node in the foreground with `fanos node --config …`"
                .to_owned(),
        ));
    };
    if !unit.exists() {
        return Err(NodeError::Config(format!(
            "no service installed at {} — run `fanos init` first",
            unit.display()
        )));
    }
    match verb {
        "start" => run_steps("starting", &manager.start(&unit)),
        "stop" => run_steps("stopping", &manager.stop(&unit)),
        _ => {
            run_steps("stopping", &manager.stop(&unit));
            run_steps("starting", &manager.start(&unit));
        }
    }
    Ok(())
}

/// `fanos uninstall [--purge] [--yes]`: take FANOS off this machine.
///
/// Two levels, and the distinction is the node's **identity**. Removing the service leaves the configuration and
/// the identity key in place, so reinstalling returns the *same* node to the network at the same coordinate — the
/// operator's peers keep their seed addresses. `--purge` deletes those too, which is not an undo: the coordinate
/// is derived from the key, so a purged node comes back as a stranger.
#[allow(clippy::unnecessary_wraps)] // uniform with every other `cmd_*`, which the dispatch table requires
fn cmd_uninstall(args: &[String]) -> Result<(), NodeError> {
    use fanos_node::setup::ServiceManager;
    let assume_yes = has_flag(args, "--yes");
    let purge = has_flag(args, "--purge");
    let paths = fanos_node::setup::Paths::detect();
    let manager = ServiceManager::detect();
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);

    eprintln!("fanos uninstall — removing FANOS from this host\n");
    if let Some(unit) = manager.unit_path(&home).filter(|u| u.exists()) {
        eprintln!("  service : {}", unit.display());
        if assume_yes || ask_yes_no("stop, disable and remove the service?", true) {
            run_steps("removing the service", &manager.deactivation(&unit));
            match std::fs::remove_file(&unit) {
                Ok(()) => eprintln!("  ✓ removed {}", unit.display()),
                Err(e) => eprintln!("  ! could not remove {}: {e}", unit.display()),
            }
            // The unit file is gone; systemd still holds it in memory until told.
            run_steps("reloading", &[[manager_reload(manager)].concat()]);
        }
    } else {
        eprintln!("  service : none installed");
    }

    if !purge {
        eprintln!("\nKept (so a reinstall returns the *same* node at the same coordinate):");
        eprintln!("  {}", paths.config.display());
        eprintln!("  {}", paths.identity.display());
        eprintln!("  {}", paths.data.display());
        eprintln!("\nTo remove those as well: fanos uninstall --purge");
        return Ok(());
    }

    eprintln!("\n  ! --purge deletes this node's identity key. Its coordinate is derived from that key, so");
    eprintln!("    reinstalling afterwards joins the network as a different node. Peers holding your seed");
    eprintln!("    address will not find you again. This cannot be undone.");
    if !assume_yes && !ask_yes_no("delete configuration, identity and state?", false) {
        eprintln!("  kept.");
        return Ok(());
    }
    for target in [&paths.config, &paths.identity] {
        match std::fs::remove_file(target) {
            Ok(()) => eprintln!("  ✓ removed {}", target.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("  ! {}: {e}", target.display()),
        }
    }
    match std::fs::remove_dir_all(&paths.data) {
        Ok(()) => eprintln!("  ✓ removed {}", paths.data.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("  ! {}: {e}", paths.data.display()),
    }
    eprintln!("\nFANOS is off this host.");
    Ok(())
}

/// The manager's "re-read your unit files" command, as an argv list.
fn manager_reload(manager: fanos_node::setup::ServiceManager) -> Vec<String> {
    use fanos_node::setup::ServiceManager;
    match manager {
        ServiceManager::SystemdSystem => vec!["systemctl".to_owned(), "daemon-reload".to_owned()],
        ServiceManager::SystemdUser => {
            vec!["systemctl".to_owned(), "--user".to_owned(), "daemon-reload".to_owned()]
        }
        ServiceManager::Launchd | ServiceManager::None => Vec::new(),
    }
}

/// `fanos status [--config FILE]`: report what this host is set up to be, and whether it is running.
///
/// Deliberately answerable **without** contacting the node: the first question an operator has is "did my setup
/// take", and a status command that can only answer by connecting cannot distinguish "not configured" from
/// "configured and down" — which are opposite problems.
async fn cmd_status(args: &[String]) -> Result<(), NodeError> {
    let paths = fanos_node::setup::Paths::detect();
    let config_path = flag(args, "--config").map_or(paths.config.clone(), PathBuf::from);

    if !config_path.exists() {
        println!("not set up — no configuration at {}", config_path.display());
        println!("run: fanos init");
        return Ok(());
    }
    let config = NodeConfig::from_config_str(&std::fs::read_to_string(&config_path)?)?;
    println!("configuration : {}", config_path.display());
    println!("listen        : {}", config.listen);
    println!("roles         : {}", config.roles);
    println!("plane order   : q = {}", config.plane_order);
    println!(
        "bootstrap     : {}",
        if config.bootstrap.is_empty() {
            "none (this node starts its own cell)".to_owned()
        } else {
            config.bootstrap.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
        }
    );
    match &config.identity_path {
        Some(p) if p.exists() => {
            let credentials = identity::load_or_generate(Some(p))?;
            let [x, y, z] = identity::coordinate::<F2>(&credentials);
            println!("coordinate    : {x}:{y}:{z}");
            println!("seed address  : {x}:{y}:{z}@<this-host>:{}", config.listen.port());
        }
        Some(p) => println!("identity      : {} (missing — it will be generated at first start)", p.display()),
        None => println!("identity      : ephemeral (no path configured)"),
    }
    println!(
        "telemetry     : {}",
        config.telemetry_epsilon.map_or_else(|| "not published".to_owned(), |e| format!("published, ε = {e}"))
    );

    // Ask the node itself if it is there. A held port says *something* is running; only the node can say what it
    // sees — how many peers it has, whose claims it verified, which point it actually sits on. Falling back to
    // the port is deliberate rather than lazy: a node built before this socket existed, or one that could not
    // bind it, must still report as running rather than as missing.
    let socket = fanos_node::admin::socket_path(&paths.data);
    let live = fanos_node::admin::ask(&socket, "health").await.unwrap_or(None);
    if let Some(body) = live {
        println!("daemon        : running");
        println!("\n--- as the node itself reports ---");
        print!("{body}");
    } else {
        let bindable = std::net::UdpSocket::bind(config.listen).is_ok();
        println!(
            "daemon        : {}",
            if bindable {
                "NOT running (its port is free)"
            } else {
                "running, but not answering its control socket (an older build, or it could not bind one)"
            }
        );
    }
    Ok(())
}

/// Run one accepted ANGELOS conversation to its end, printing what arrives.
///
/// A refused handshake and a broken conversation are both logged rather than propagated: this is one caller of
/// many, and a messenger that stops serving because one peer sent garbage has been denied service by that peer.
async fn converse(stream: DuplexStream, secret: &fanos_pqcrypto::kem::HybridKemSecret) {
    let mut talk = match fanos_node::angelos_driver::Conversation::respond(stream, secret).await {
        Ok(c) => c,
        Err(e) => {
            info!(error = %e, "angelos handshake refused");
            return;
        }
    };
    loop {
        match talk.recv().await {
            Ok(Some(message)) => {
                if let Some(text) = message.as_text() {
                    println!("[{}] {text}", message.seq);
                } else {
                    info!(seq = message.seq, "non-text message");
                }
            }
            Ok(None) => break,
            Err(e) => {
                info!(error = %e, "conversation ended");
                break;
            }
        }
    }
}

/// `fanos message serve --host-key FILE` — host an ANGELOS messenger on the anonymous rendezvous.
///
/// The composition, and it is only a composition: `fanos host` already stands up an anonymous service and hands
/// each accepted session to a handler. This makes the handler the messenger instead of a TCP forward, so every
/// anonymity property of the hidden-service path — computed rendezvous, no directory, neither coordinate on the
/// wire — carries over unchanged, and ANGELOS adds end-to-end secrecy on top of the transport's.
///
/// Until this verb existed `fanos-angelos` was a complete messenger no shipped binary could reach: the
/// capability was finished and the door was missing.
async fn cmd_message(args: &[String]) -> Result<(), NodeError> {
    init_tracing();
    let Some(mode) = args.first().map(String::as_str) else {
        return Err(NodeError::Config(
            "usage: fanos message serve --host-key FILE [--config FILE] [--bootstrap …]".to_owned(),
        ));
    };
    if mode != "serve" {
        return Err(NodeError::Config(format!(
            "unknown `fanos message {mode}` (expected: serve)"
        )));
    }
    let rest = args.get(1..).unwrap_or(&[]);
    let host_secret = match flag(rest, "--host-key") {
        Some(p) => std::fs::read(p)?,
        None => {
            return Err(NodeError::Config(
                "fanos message serve requires --host-key <file> — the messenger's secret seed and stable \
                 .fanos identity (generate one with `head -c 32 /dev/urandom > msg.key`)"
                    .to_owned(),
            ));
        }
    };
    let epoch = match flag(rest, "--epoch") {
        Some(s) => Epoch::new(s.parse().map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?),
        None => Epoch::ZERO,
    };
    let beacon = match flag(rest, "--beacon") {
        Some(s) => parse_beacon_hex(s)?,
        None => BeaconSeed::GENESIS,
    };
    let threshold = mix_threshold_arg(rest)?;

    let service = StaticKeypair::generate(&mut SeedRng::from_seed(&host_secret));
    let bundle = bundle_from_kem_public(service.public());
    let address = Address::from_bundle(&bundle);
    // The messenger's own long-term KEM identity, derived from the same seed under its own label so the
    // transport identity and the end-to-end identity are not the same key doing two jobs.
    let (kem_secret, kem_public) = fanos_pqcrypto::kem::HybridKemSecret::generate(
        &mut SeedRng::from_seed(&fanos_primitives::hash_labeled("FANOS-v1/angelos-identity", &host_secret)),
    );

    let config = node_config_from_args(rest)?;
    let mut node = Node::start_on_plane(config).await?;
    if let Err(e) =
        publish_service(&node.client(), &bundle, [0, 0, 0], epoch, 0, b"profile=anonymous").await
    {
        node.shutdown();
        return Err(e);
    }

    let secret = Arc::new(kem_secret);
    let handler = move |stream: DuplexStream| {
        let secret = Arc::clone(&secret);
        async move { converse(stream, &secret).await }
    };
    let _driver = spawn_rendezvous_host(
        node.client(),
        node.address(),
        HostedService { service, host_secret, threshold, vrf_coordinates: true },
        (epoch, *beacon.as_bytes()),
        handler,
    );

    // `Address` renders its own `.fanos` suffix — appending another produced `…​.fanos.fanos` on the first run
    // of this verb, which is not cosmetic: an address a correspondent copies has to be the address that resolves.
    eprintln!("fanos messenger up — {address}");
    eprintln!("  end-to-end identity (share this with correspondents):");
    let mut identity_hex = String::new();
    for byte in kem_public.encode() {
        use std::fmt::Write as _;
        let _ = write!(identity_hex, "{byte:02x}");
    }
    eprintln!("  {identity_hex}");
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            biased;
            _ = &mut ctrl_c => break,
            note = node.next_notification() => match note {
                Some(n) => log_notification(&n),
                None => break,
            },
        }
    }
    node.shutdown();
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

/// `fanos taxis-deal [--out DIR] [--epoch N] [--beacon HEX64]`: deal a fresh 7-validator TAXIS cell (the base
/// Fano cell) from OS entropy and write each validator's provisioning file (`validator-<i>.taxis`, `i = 0..6`)
/// into `DIR` (default `.`). Run each with `fanos validator --config validator-<i>.taxis`. A single-operator
/// convenience for a permissioned cell — every validator file carries the whole public config (verifier set,
/// keyper commitment) plus that validator's one secret seed.
#[cfg(feature = "validator")]
fn cmd_taxis_deal(args: &[String]) -> Result<(), NodeError> {
    use fanos_dromos::token::account_id;
    use fanos_node::{ChainInfo, ValidatorConfig, deal_validators};
    use fanos_pqcrypto::HybridSigSecret;
    use fanos_pqcrypto::rng::SeedRng;
    use fanos_taxis::params::CellParams;

    let out = flag(args, "--out").unwrap_or(".");
    let epoch = match flag(args, "--epoch") {
        Some(s) => Epoch::new(s.parse().map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?),
        None => Epoch::ZERO,
    };
    let beacon = match flag(args, "--beacon") {
        Some(s) => parse_beacon_hex(s)?,
        None => BeaconSeed::GENESIS,
    };
    let supply: u64 = match flag(args, "--supply") {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --supply '{s}'")))?,
        None => 1_000_000_000,
    };
    let cell = CellParams::FANO;

    // The genesis FOUNDER: a fresh token keypair credited the whole initial supply (minting is genesis-only,
    // so this is the entire supply). Its 32-byte secret seed is written to `founder.key` so the operator can
    // later spend the genesis funds — a client reconstructs the signing key from the seed.
    let mut founder_seed = [0u8; 32];
    getrandom::fill(&mut founder_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let (_founder_sig, founder_vk) = HybridSigSecret::generate(&mut SeedRng::from_seed(&founder_seed));
    let founder = account_id(&founder_vk);
    let genesis_alloc = vec![(founder, supply)];

    // The validator seeds are drawn from OS entropy — this tool holds the whole cell's key material for the
    // moment of dealing (a single-operator bootstrap; a trust-minimized deployment provisions each validator
    // independently and exchanges only the public verifiers/keyper commitment/genesis allocation).
    let mut rng_seed = [0u8; 32];
    getrandom::fill(&mut rng_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let (configs, registry) =
        deal_validators(cell, epoch, beacon, &genesis_alloc, &mut SeedRng::from_seed(&rng_seed));

    for c in &configs {
        let path = format!("{out}/validator-{}.taxis", c.me);
        std::fs::write(&path, ValidatorConfig::to_bytes(c))?;
        println!("wrote {path}");
    }
    // The public chain info a client needs to build, seal, and submit a transaction (`fanos pay`).
    let info = ChainInfo { cell, epoch, beacon, keyper: registry };
    let ipath = format!("{out}/chain-info.taxis");
    std::fs::write(&ipath, info.to_bytes())?;
    println!("wrote {ipath} (public chain info for `fanos pay`)");
    let fpath = format!("{out}/founder.key");
    std::fs::write(&fpath, founder_seed)?;
    println!("wrote {fpath} (the genesis founder's secret seed — keep it safe)");
    println!(
        "dealt a {}-validator TAXIS cell (epoch {}); genesis-funded a founder with {supply} (key in founder.key)\n\
         run each validator with `fanos validator --config validator-<i>.taxis`",
        cell.n,
        epoch.get(),
    );
    Ok(())
}

/// Without the `validator` feature the binary carries no ledger, so `fanos taxis-deal` cannot deal a cell.
#[cfg(not(feature = "validator"))]
fn cmd_taxis_deal(_args: &[String]) -> Result<(), NodeError> {
    Err(NodeError::Config(
        "this build lacks validator support — rebuild with `cargo build -p fanos-node --features validator`"
            .to_owned(),
    ))
}

/// `fanos pay --chain-info chain-info.taxis --key founder.key --to <hex account> --amount N [--nonce M]
/// --bootstrap <coord>@host:port,…`: the **client half of the network transaction ingress**. Build a
/// transparent value transfer, seal it to the cell's anti-MEV keyper line (so no validator sees its contents
/// before the order is fixed), join the overlay, and submit it to a validator — which ingests it into its
/// mempool and gossips it across the cell. Provision the cell with `fanos taxis-deal` (which writes the
/// `chain-info.taxis` this reads and the `founder.key` that funds the genesis account).
#[cfg(feature = "validator")]
async fn cmd_pay(args: &[String]) -> Result<(), NodeError> {
    use fanos_dromos::HybridLedger;
    use fanos_dromos::token::{SignedTransfer, Transfer, account_id};
    use fanos_geometry::Point;
    use fanos_node::ChainInfo;
    use fanos_pqcrypto::HybridSigSecret;
    use fanos_pqcrypto::rng::SeedRng;
    use fanos_runtime::Command;
    use fanos_taxis::Transaction;
    use fanos_taxis::keyper::seal_to_keyper_line;
    use fanos_taxis::wire::tx_to_frame;

    init_tracing();

    // The public chain info (keyper registry + epoch + beacon + cell) — everything a client needs but a key.
    let info_path = flag(args, "--chain-info")
        .ok_or_else(|| NodeError::Config("fanos pay requires --chain-info chain-info.taxis".to_owned()))?;
    let info = ChainInfo::from_bytes(&std::fs::read(info_path)?)
        .ok_or_else(|| NodeError::Config("malformed chain-info file".to_owned()))?;

    // The sender's 32-byte key seed (e.g. `founder.key`) → its signing keypair + account id.
    let key_path = flag(args, "--key")
        .ok_or_else(|| NodeError::Config("fanos pay requires --key <32-byte seed file> (e.g. founder.key)".to_owned()))?;
    let seed: [u8; 32] = std::fs::read(key_path)?
        .as_slice()
        .try_into()
        .map_err(|_| NodeError::Config("the --key file must be a 32-byte seed".to_owned()))?;
    let (signer, from_key) = HybridSigSecret::generate(&mut SeedRng::from_seed(&seed));
    let from = account_id(&from_key);

    let to_hex = flag(args, "--to")
        .ok_or_else(|| NodeError::Config("fanos pay requires --to <32-byte hex account id>".to_owned()))?;
    let to: [u8; 32] = decode_hex(to_hex)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| NodeError::Config("--to must be a 32-byte (64 hex char) account id".to_owned()))?;
    let amount: u64 = flag(args, "--amount")
        .ok_or_else(|| NodeError::Config("fanos pay requires --amount N".to_owned()))?
        .parse()
        .map_err(|_| NodeError::Config("bad --amount".to_owned()))?;
    let nonce: u64 = match flag(args, "--nonce") {
        Some(s) => s.parse().map_err(|_| NodeError::Config("bad --nonce".to_owned()))?,
        None => 0,
    };

    // Build + sign the transparent transfer, wrap it as a DROMOS transaction, and seal it to the epoch keyper
    // line with fresh OS entropy (the anti-MEV property: the order is fixed on the sealed ciphertext).
    let signed = SignedTransfer::sign(Transfer { from, to, amount, nonce }, &signer, from_key);
    let tx = Transaction::new(HybridLedger::transparent_payload(&signed));
    let mut rng_seed = [0u8; 32];
    getrandom::fill(&mut rng_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let sealed = seal_to_keyper_line(&info.keyper, &tx, info.epoch, &info.beacon, info.cell, &rng_seed)
        .map_err(|e| NodeError::Config(format!("could not seal the transaction: {e:?}")))?;

    // Join the overlay (bootstrap to the validators via --bootstrap) and submit to validator 0, which ingests
    // the sealed transaction and gossips it to the whole cell's mempool.
    let config = node_config_from_args(args)?;
    let node = Node::start::<F2>(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // let bootstrap connections establish
    let submitted = node.command(Command::Emit { to: Point::<F2>::at(0).coords(), frame: tx_to_frame(&sealed) });
    tokio::time::sleep(Duration::from_secs(2)).await; // let the frame flush + propagate
    node.shutdown();
    if submitted {
        println!(
            "submitted: transfer {amount} → {to_hex} (nonce {nonce}), sealed to the epoch {} keyper line",
            info.epoch.get()
        );
        Ok(())
    } else {
        Err(NodeError::Config("could not emit the transaction (is the client connected to a validator?)".to_owned()))
    }
}

/// Without the `validator` feature the binary carries no ledger, so `fanos pay` cannot build a transaction.
#[cfg(not(feature = "validator"))]
#[allow(clippy::unused_async)]
async fn cmd_pay(_args: &[String]) -> Result<(), NodeError> {
    Err(NodeError::Config(
        "this build lacks validator support — rebuild with `cargo build -p fanos-node --features validator`"
            .to_owned(),
    ))
}

/// `fanos validator --config validator-<i>.taxis --listen ADDR --bootstrap <coord>@host:port,…`: run a TAXIS
/// blockchain validator — the caller that closes the "`spawn_taxis` has no prod caller" production gap. It
/// seats a node at its consensus point `Point::at(me)` (a production fixed-coordinate node — `spawn_pinned`'s
/// grind, so the coordinate is *chosen*, not VRF-accepted, which the Fano-cell BFT structure requires), wires
/// the other validators' coordinates→sockets from `--bootstrap`, and runs the sans-I/O consensus engine over
/// the DROMOS hybrid ledger (`spawn_taxis`). Provision a cell with `fanos taxis-deal`.
#[cfg(feature = "validator")]
async fn cmd_validator(args: &[String]) -> Result<(), NodeError> {
    use fanos_dromos::HybridLedger;
    use fanos_geometry::Point;
    use fanos_node::{ValidatorConfig, spawn_taxis};
    use fanos_quic::{Directory, credentials_for_point, spawn_self_certifying_persistent_on};
    use fanos_runtime::{Config as OverlayConfig, OverlayNode};

    init_tracing();
    let config_path = flag(args, "--config")
        .ok_or_else(|| NodeError::Config("fanos validator requires --config validator-<i>.taxis".to_owned()))?;
    let config = ValidatorConfig::from_bytes(&std::fs::read(config_path)?)
        .ok_or_else(|| NodeError::Config("malformed validator config file".to_owned()))?;
    let me = config.me;
    let listen: SocketAddr = match flag(args, "--listen") {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --listen '{s}'")))?,
        None => SocketAddr::from(([0, 0, 0, 0], 0)),
    };

    // The other validators' coordinates → sockets (this node reaches its peers by coordinate). Same
    // `<coord>@host:port` form as `fanos node --bootstrap`, but here every peer is a fixed cell seat.
    let directory = Directory::new();
    for value in flag_all(args, "--bootstrap") {
        for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let peer = Peer::parse(part)?;
            directory.insert(peer.coord, peer.addr);
        }
    }

    // Seat the node at Point::at(me) (grind an identity that hits it) and bind the consensus listen socket.
    let target = Point::<F2>::at(usize::from(me));
    let creds = credentials_for_point::<F2>(target, fanos_quic::DEFAULT_GRIND_LIMIT)
        .ok_or_else(|| NodeError::Config(format!("could not seat a node at validator point {me}")))?;
    let mut node = spawn_self_certifying_persistent_on::<F2>(
        listen,
        &creds,
        |coord| Box::new(OverlayNode::<F2>::new(coord, OverlayConfig::default())),
        directory,
        None,
    )
    .await
    .map_err(|e| NodeError::Config(format!("could not start the validator node: {e:?}")))?;

    // Run the consensus engine over the DROMOS hybrid ledger. The handle owns the driver tasks; keep it alive.
    let params = config
        .to_taxis_params()
        .ok_or_else(|| NodeError::Config("the validator config carries a malformed verifier".to_owned()))?;
    let handle = spawn_taxis::<F2, HybridLedger>(node.client(), params);
    let mut events = handle.subscribe();

    let [x, y, z] = node.address();
    eprintln!(
        "fanos validator {me} up — seat {x}:{y}:{z}, listening on {listen}\n  running TAXIS consensus over \
         the DROMOS hybrid ledger (epoch {})",
        config.epoch.get(),
    );
    info!(validator = me, coord = ?node.address(), %listen, "fanos validator up");

    // Serve until Ctrl-C, logging consensus progress and draining the node's notifications.
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown signal received");
    };
    tokio::select! {
        () = shutdown => {}
        () = async { while let Ok(ev) = events.recv().await { info!(?ev, "taxis event"); } } => {}
        () = async { while let Some(n) = node.next_notification().await { log_notification(&n); } } => {}
    }
    node.shutdown();
    eprintln!("fanos validator {me} down");
    Ok(())
}

/// Without the `validator` feature the binary carries no ledger, so it cannot run a `fanos validator`.
/// `async` only to share the dispatcher's `.await` with the real command; it awaits nothing.
#[cfg(not(feature = "validator"))]
#[allow(clippy::unused_async)]
async fn cmd_validator(_args: &[String]) -> Result<(), NodeError> {
    Err(NodeError::Config(
        "this build lacks validator support — rebuild with `cargo build -p fanos-node --features validator`"
            .to_owned(),
    ))
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
    log_notification_against(note, None);
}

/// Log a notification, judging the epoch floor against `configured` when the caller knows it.
///
/// The comparison is the whole point of the floor. A cell measures the shortest epoch period it can absorb;
/// on its own that is a number, and next to the configured period it is a verdict — and below the floor the
/// cost is not churn but accumulation, since a cell reshuffled faster than it reintegrates never reaches a
/// steady state at all.
fn log_notification_against(note: &Notification, configured: Option<Duration>) {
    if let Notification::EpochFloor { millis } = note {
        match (millis, configured) {
            (None, _) => {
                tracing::warn!(
                    "this cell can sustain no epoch cadence at all — one advance already spends its whole \
                     stability headroom. It is too unhealthy to reshuffle until it recovers."
                );
            }
            (Some(ms), Some(period)) if Duration::from_millis(*ms) > period => {
                tracing::warn!(
                    floor_ms = ms,
                    configured_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX),
                    "the configured epoch period is SHORTER than this cell can absorb — excursions accumulate \
                     across epochs rather than decaying, and the cell never reaches a steady state"
                );
            }
            (Some(ms), _) => info!(floor_ms = ms, "measured the shortest epoch period this cell can sustain"),
        }
        return;
    }
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
         \n\
           GETTING STARTED (one command on a fresh host)\n\
           fanos init  [--yes] [--force] [--no-service] [--role relay,storage,…] [--listen ADDR] \\\n\
                       [--bootstrap x:y:z@host:port,…] [--telemetry EPSILON]\n\
                       (detect this OS, pick a free port, generate an identity, write the config,\n\
                        install a service and start it — `--yes` takes every default, for provisioning)\n\
           fanos status                     — what this host is set up as, and whether it is running\n\
           fanos start | stop | restart     — drive the installed service\n\
           fanos uninstall [--purge] [--yes]\n\
                       (remove the service; --purge also deletes config, identity and state — the\n\
                        coordinate is derived from the identity, so a purged node returns as a stranger)\n\
         \n\
         ADVANCED:\n\
         \x20 fanos node  [--config FILE] [--listen ADDR] [--identity PATH] [--bootstrap x:y:z@host:port,...] \\\n\
         \x20             [--role relay,storage,service,exit] [--service FILE] [--exit FILE] \\\n\
         \x20             [--no-heartbeat] [--proteus-secret SECRET] [--proteus-morph MORPH] \\\n\
         \x20             [--proteus-environment ENV] [--mix-delay-ms N] [--cover-interval-ms N] \\\n\
         \x20             [--plane-order 2|4|7|31] [--beacon-params FILE]\n\
         \x20 fanos proxy [--socks-listen ADDR] [--http-listen ADDR] [--epoch N] [--min-pow BITS] \\\n\
         \x20             [--profile direct|anonymous] [--threshold T] [--fwd-depth D] [--reply-depth D] \\\n\
         \x20             [--beacon HEX64] [--exit-via FILE] [--config FILE] [--identity PATH] \\\n\
         \x20             [--bootstrap ...] [--listen ADDR] [--plane-order 2|4|7|31]\n\
         \x20 fanos host  --forward HOST:PORT --host-key FILE [--epoch N] [--beacon HEX64] [--threshold T] \\\n\
         \x20             [--descriptor-pow BITS] [--config FILE] [--bootstrap ...] [--listen ADDR]\n\
         \x20             (host a hidden service on the anonymous rendezvous §3b: forward each incoming\n\
         \x20             anonymous session to a local port; --host-key is your stable .fanos identity)\n\
         \x20 fanos vpn   [--tun NAME] [--exit-via FILE] [--epoch N] [--config FILE] [--bootstrap ...]\n\
         \x20             (full-tunnel: routes all TCP+UDP through an exit; needs --features vpn + root)\n\
         \x20 fanos id    [--identity PATH]\n\
         \x20 fanos resolve NAME.fanos [--epoch N] [--min-pow BITS] [--bootstrap ...]\n\
         \x20 fanos beacon-deal N T [--out DIR]  (deal a T-of-N epoch-clock beacon; writes *.beacon files)\n\
         \x20 fanos taxis-deal [--out DIR] [--epoch N] [--beacon HEX64] [--supply N]\n\
         \x20             (deal a 7-validator TAXIS blockchain cell + a genesis-funded founder; writes\n\
         \x20             validator-<i>.taxis + founder.key; --features validator)\n\
         \x20 fanos validator --config validator-<i>.taxis [--listen ADDR] [--bootstrap <coord>@host:port,…]\n\
         \x20             (run a TAXIS blockchain validator over the DROMOS ledger; --features validator)\n\
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
