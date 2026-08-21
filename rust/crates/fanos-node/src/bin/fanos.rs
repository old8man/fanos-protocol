//! `fanos` — the unified FANOS node binary (roadmap Phase 1).
//!
//! Subcommands:
//!   * `fanos node`  — run a node (overlay membership, storage, healing) over QUIC.
//!   * `fanos proxy` — run local SOCKS5 / HTTP-CONNECT listeners tunnelling to `.fanos` services (§11.3).
//!   * `fanos host`  — host a hidden service on the anonymous rendezvous, forwarding to a local port (§3b).
//!   * `fanos validator` / `taxis-deal` — deal + run a TAXIS blockchain cell over the DROMOS ledger.
//!   * `fanos term`  — compose an atomic ERGON term (multi-leg pays, name registrations, gates) and submit it.
//!   * `fanos id`    — print (and optionally persist) a node's self-certifying coordinate.
//!   * `fanos help`  — usage.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use std::sync::Arc;

use fanos_diaulos::{StaticKeypair, bundle_from_identity, bundle_from_kem_public};
use fanos_field::F2;
use fanos_onoma::Address;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_pqcrypto::rng::SeedRng;
use fanos_pqcrypto::sig::{HybridSigSecret, HybridVerifier};
use fanos_node::{
    AnonRouteParams, BeaconParams, BeaconSeed, Coverage, Environment, Epoch, ExitParams, FanosDialer, Morph, Node,
    NodeConfig,
    NodeError, NodeResolver, Peer, RoleSet, ServiceParams, build_plane_exit_directory,
    HostedService, build_plane_mix_directory, identity, publish_service, serve_proxy, spawn_rendezvous_host,
};
// Only the (feature-gated) `fanos vpn` command dials clearnet by IP with an empty resolver.
#[cfg(feature = "vpn")]
use fanos_node::StaticResolver;
use fanos_runtime::{AdmissionOutcome, Escalation, Notification};
use fanos_vrf::vss::{DeterministicRng, deal};
use tokio::io::{DuplexStream, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

/// The process entry point: run one verb and turn its `Result` into an exit code.
///
/// The only place a `NodeError` becomes a message and a status, so a verb that printed its own error
/// would be a second decision about the exit code and the two would drift.
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

/// Dispatch one invocation to its verb.
///
/// Separate from `main` so every path returns a `Result` the caller renders once: a verb that printed its
/// own error would be a second place for the exit code to be decided, and the two would drift.
async fn run(args: &[String]) -> Result<(), NodeError> {
    // **`--help` anywhere means help, and this guard is why.** The dispatch below matches `--help` only in
    // verb position, so `fanos node --help` fell through to `cmd_node`, which ignores flags it does not know
    // — and *launched a real node*, binding a port and joining a cell. An operator asking what a command does
    // got a running daemon instead of an answer, which is the one response a help request must never produce.
    //
    // Checked here rather than in each verb: uniform by construction, and a new verb inherits it instead of
    // having to remember. It runs before any argument is parsed, so a malformed command still explains itself
    // rather than failing on the first bad flag.
    if args.iter().skip(1).any(|a| a == "--help" || a == "-h") {
        // A named verb gets **its own** usage rather than the full listing — the block is projected out of the
        // one help text, so there is no second copy to drift (see `print_verb_help`).
        match args.get(1).map(String::as_str) {
            Some(v) if !v.starts_with('-') => print_verb_help(v),
            _ => print_help(),
        }
        return Ok(());
    }
    match args.get(1).map(String::as_str) {
        Some("node") => cmd_node(args.get(2..).unwrap_or(&[])).await,
        Some("proxy") => cmd_proxy(args.get(2..).unwrap_or(&[])).await,
        Some("host") => cmd_host(args.get(2..).unwrap_or(&[])).await,
        Some("message") => cmd_message(args.get(2..).unwrap_or(&[])).await,
        Some("validator") => cmd_validator(args.get(2..).unwrap_or(&[])).await,
        Some("pay") => cmd_pay(args.get(2..).unwrap_or(&[])).await,
        Some("term") => cmd_term(args.get(2..).unwrap_or(&[])).await,
        Some("vpn") => cmd_vpn(args.get(2..).unwrap_or(&[])).await,
        Some("init") => cmd_init(args.get(2..).unwrap_or(&[])),
        Some(v @ ("start" | "stop" | "restart")) => cmd_service_lifecycle(v),
        Some("uninstall") => cmd_uninstall(args.get(2..).unwrap_or(&[])),
        Some("status") => cmd_status(args.get(2..).unwrap_or(&[])).await,
        Some("id") => cmd_id(args.get(2..).unwrap_or(&[])),
        Some("beacon-deal") => cmd_beacon_deal(args.get(2..).unwrap_or(&[])),
        Some("keygen") => cmd_keygen(args.get(2..).unwrap_or(&[])).await,
        Some("authority-key") => cmd_authority_key(args.get(2..).unwrap_or(&[])),
        Some("beacon-reshare") => cmd_beacon_reshare(args.get(2..).unwrap_or(&[])).await,
        Some("ingress-deal") => cmd_ingress_deal(args.get(2..).unwrap_or(&[])),
        Some("service-deal") => cmd_service_deal(args.get(2..).unwrap_or(&[])),
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

/// Turn a provisioning file's **frame** into an operator-facing reason (#308).
///
/// `Current` means the frame is ours and the *body* failed — a genuinely corrupt or truncated file. The
/// other two are different mistakes with different fixes, and collapsing all three into "malformed" is
/// what left an operator unable to tell an old file from a broken one. FANOS versions its wire
/// (`PROTOCOL_VERSION`), its C ABI (`FANOS_ABI_VERSION`) and its telemetry snapshot (`FTS1`); the files
/// carrying every constant a cell agrees on were the outlier.
#[cfg(feature = "validator")]
fn provision_error(kind: &str, fmt: fanos_node::ProvisionFormat) -> NodeError {
    NodeError::Config(match fmt {
        fanos_node::ProvisionFormat::Current => {
            format!("{kind} file is corrupt or truncated — its frame is this build's, its body did not decode")
        }
        fanos_node::ProvisionFormat::OtherVersion(v) => format!(
            "{kind} file was written at provisioning format version {v}; this build reads {}. Re-run the \
             dealing ceremony with this build rather than reusing the old file.",
            fanos_node::PROVISION_FORMAT_VERSION
        ),
        fanos_node::ProvisionFormat::Unframed => format!(
            "that is not a {kind} file at all — it carries no frame this build recognises. Check the path; \
             a file of the right kind always begins with its own four-byte magic."
        ),
    })
}

/// The mixnet hop threshold for this invocation: `--threshold` if given, else derived from `--plane-order`.
///
/// One helper rather than three copies, because the client and the relay must agree exactly — a client seals
/// each onion layer for precisely this many members — and three `None => 2` defaults are three chances to
/// diverge. The derivation is [`fanos_node::node::mix_threshold`]: a hop is a line of `q+1` points, and a
/// threshold fixed at the Fano value lets any two corrupt members own a hop however wide the line is
/// (`docs/audit.md` E7).
fn mix_threshold_arg(args: &[String]) -> Result<u8, NodeError> {
    if let Some(s) = flag(args, "--threshold")? {
        return s.parse().map_err(|_| NodeError::Config(format!("bad --threshold '{s}'")));
    }
    u8::try_from(fanos_node::node::mix_threshold(line_size_arg(args)?))
        .map_err(|_| NodeError::Config("plane order too large for a u8 threshold".to_owned()))
}

/// The configured plane's line size, `q + 1` — the ONE place `--plane-order` becomes a geometry parameter.
///
/// It was read in two places that then disagreed: the mix threshold used the configured order while the
/// circuit-depth ceiling used `fano::LINE_SIZE`, a constant. So on `--plane-order 7` the ceiling was computed
/// for a plane the node was not running, and admitted a depth the onion header there cannot carry — the exact
/// silent failure the check exists to prevent, and its comment says so.
fn line_size_arg(args: &[String]) -> Result<usize, NodeError> {
    let plane_order: usize = match flag(args, "--plane-order")? {
        Some(s) => s
            .parse()
            .map_err(|_| NodeError::Config(format!("bad --plane-order '{s}' (expected 2, 4, 7 or 31)")))?,
        None => 2,
    };
    Ok(plane_order + 1)
}

/// Report the plane's anonymity limits — **both** of them, because they pull in opposite directions and this
/// used to state only one.
///
/// It advised "pass `--plane-order 4|7|31`", which is sound advice about the anonymity *set* and was, at the
/// same time, advice to use the planes where [`slots::plane_can_anonymize`](fanos_aphantos::slots::plane_can_anonymize) is false: the fixed-slot header
/// there carries fewer hops than [`slots::TARGET_DEPTH`](fanos_aphantos::slots::TARGET_DEPTH), so those deployments cannot build a circuit that
/// hides either endpoint. Two subsystems, opposite counsel, neither aware of the other — so the operator was
/// being sent from a real weakness to a worse one.
///
/// The reconciliation is not a compromise between the two numbers. Cell width and onion width are *independent*
/// deployment parameters, and the configuration the warning should point at raises both.
///
/// **Why the plane is the term that matters**, from this function's older doc and kept because the live one
/// never restated it: an adversary's flow-matching floor in a linkability measurement is `1/K` for `K`
/// concurrent circuits, and `K` comes from the **plane**, not the mix schedule. `PG(2,2)` has **6** lines
/// with *distinct* combiners (measured and pinned by
/// `fanos_aphantos::threshold_router`'s `the_combiner_map_covers_more_of_the_plane_than_the_cell_tolerates_faults`),
/// so it supports **3** circuits and the best any schedule achieves is **one in three**
/// (`fanos_node::config::plane_order`). This paragraph said *4 lines, 2 circuits, a coin flip* until the
/// image was pinned: that was the member-zero map replaced by the digest map, and the inequality the test
/// asserted could not tell the two apart. Under-delivering an anonymity request in silence is the worse
/// failure: an operator who is told can raise the order or accept the limit knowingly; one who is not told
/// believes the profile's name.
fn warn_if_plane_cannot_anonymize(config: &NodeConfig) {
    let line_size = config.plane_order as usize + 1;
    if !fanos_aphantos::slots::plane_can_anonymize(line_size) {
        eprintln!(
            "warning: plane order {q} cannot carry an anonymous circuit at the shipped onion budget — its header holds \
             {have} hops where {want} are needed. Raise the onion budget for a plane this wide; a shallower circuit is \
             not a weaker one, it is none.",
            q = config.plane_order,
            have = fanos_aphantos::slots::depth_for(line_size),
            want = fanos_aphantos::slots::TARGET_DEPTH,
        );
        return;
    }
    // A wider plane inherits a decision the base cell never had to make. Said here because nothing else says
    // it: on a plane where a tolerated coalition CAN hold both of a circuit's naming lines, drawing a fresh
    // circuit per dial accumulates — the chance of ever being correlated rises with the dial count, which is
    // exactly the argument that gave Tor its entry guards. On the recommended planes it cannot, so fresh is
    // strictly right and a guard would only cost unlinkability.
    if fanos_node::node::correlation_within_budget(line_size) {
        eprintln!(
            "warning: on plane order {q} a coalition inside the fault budget CAN hold both lines that name a \
             circuit's endpoints, so drawing a fresh circuit per dial accumulates risk with the dial count \
             (measured over 1000 dials: 99.1% at q=5, 64.2% at q=8, 5.8% at q=7 — the boundary is \
             non-monotonic). This deployment wants a pinned entry; the base cell does not, because there the \
             correlation is structurally impossible.",
            q = config.plane_order
        );
    }
    if config.plane_order > 2 {
        return;
    }
    eprintln!(
        "warning: anonymity requested on plane order {q} — PG(2,{q}) supports only 3 concurrent circuits, so a passive \
         adversary's flow-matching floor is ONE IN THREE (0.33) regardless of the mix schedule. A wider cell raises that \
         floor, but only together with a wider onion budget: at the shipped budget every plane above order 3 fails the \
         depth check above, so `--plane-order 4` alone would trade a small anonymity set for none at all. See \
         fanos_node::config::plane_order.",
        q = config.plane_order
    );
}

/// Build a [`NodeConfig`] from a `--config <file>` base (if any) with individual CLI flags overriding it,
/// so an operator can keep a config file and tweak one setting on the command line. Shared by `fanos node`
/// and `fanos proxy` — both run a full node, they differ only in what they do with its `Client`.
fn node_config_from_args(args: &[String]) -> Result<NodeConfig, NodeError> {
    let mut config = match flag(args, "--config")? {
        Some(path) => {
            let config = NodeConfig::from_config_str(&std::fs::read_to_string(path)?)?;
            // **The config file is the other door the same secret comes through** (#13). Refusing
            // `--proteus-secret` on the command line and then accepting `proteus_secret = …` out of a
            // world-readable file would be a guarded path beside an unguarded twin: the exposure is the
            // secret's, not the flag's, so the guard has to be on every channel that carries it. Checked
            // only when the parsed config actually holds one — a config without a secret is public
            // material (listen address, roles, bootstrap set) and there is nothing to protect.
            if config.proteus_secret.is_some() {
                require_private_file(path, "a shared PROTEUS community secret")?;
            }
            config
        }
        None => NodeConfig::default(),
    };
    if let Some(s) = flag(args, "--listen")? {
        config.listen = s
            .parse::<SocketAddr>()
            .map_err(|_| NodeError::Config(format!("bad --listen '{s}'")))?;
    }
    if let Some(p) = flag(args, "--identity")? {
        config.identity_path = Some(PathBuf::from(p));
    }
    // `--data DIR` names where this node's state lives, so it names where the **store** lives too (#77).
    // Without this the flag moved only the control socket and the store silently kept nothing — the operator
    // would have said exactly the thing that asks for persistence and not got it.
    if let Some(p) = flag(args, "--data")? {
        config.state_path = Some(PathBuf::from(p));
    }
    // The cell's projective plane order. Exposed because it is the parameter that BOUNDS anonymity — an adversary's
    // flow-matching floor is `1/K` for `K` concurrent circuits, and `K` comes from the plane, not the mix schedule
    // (`fanos_node::config::plane_order`). Every node of a cell must agree on it, so it belongs in the same
    // out-of-band configuration as the bootstrap set rather than being negotiated.
    if let Some(s) = flag(args, "--plane-order")? {
        config.plane_order = s
            .parse::<u32>()
            .map_err(|_| NodeError::Config(format!("bad --plane-order '{s}' (expected 2, 4, 7 or 31)")))?;
    }
    for value in flag_all(args, "--bootstrap")? {
        for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            config.bootstrap.push(Peer::parse(part)?);
        }
    }
    if let Some(s) = flag(args, "--role")? {
        config.roles = RoleSet::parse(s)?;
    }
    if let Some(path) = flag(args, "--service")? {
        // Provision the threshold-hosting line (seed, roster, threshold) from an out-of-band file, and
        // imply the `service` role — providing service parameters is the operator asking to host it.
        config.service = Some(ServiceParams::from_config_str(&std::fs::read_to_string(path)?)?);
        config.service_path = Some(PathBuf::from(path));
        config.roles.service = true;
    }
    if let Some(path) = flag(args, "--exit")? {
        // Provision the clearnet exit (service-key seed + optional port policy) and imply the `exit` role.
        config.exit = Some(ExitParams::from_config_str(&std::fs::read_to_string(path)?)?);
        config.exit_path = Some(PathBuf::from(path));
        config.roles.exit = true;
    }
    if has_flag(args, "--no-heartbeat") {
        config.start_heartbeat = false;
    }
    // **`--proteus-secret VALUE` is refused, not warned about** (#13).
    //
    // The failure sequence it used to allow: an operator runs `fanos node --proteus-secret hunter2`; the
    // kernel keeps that command line for the life of the process; every other account on the host reads it
    // with `ps -ef` or `cat /proc/<pid>/cmdline`, at any moment, without touching a single file. Holding the
    // community secret is holding the shaping key of every peer in that community (§13.4), so one `ps` by
    // one local user deanonymises the transport for everybody sharing it. The `Zeroizing` field this used to
    // fill wipes the process's copy and cannot reach the kernel's, so no amount of care *inside* the binary
    // closes it — only not putting the value in argv does.
    //
    // A warning was the previous answer and it is the "opt-in security default off" shape: the insecure path
    // still worked, so it stayed in the scripts. Deleting the branch outright would be worse still — `flag`
    // ignores arguments it does not recognise, so `--proteus-secret hunter2` would parse as nothing at all
    // and the node would start UNSHAPED while the operator believed they had turned PROTEUS on. Hence an
    // explicit refusal that names its replacement and prints the command that makes the file.
    //
    // Matched with `has_flag`, not `flag`, and it still is after #313 closed the general hole this used to
    // work around. `flag` no longer lets a valueless flag slip past — it refuses — but the refusal it
    // produces would be "`--proteus-secret` needs a value", which is the wrong sentence for an argument whose
    // whole problem is that giving it a value is the exposure. The refusal here is about the flag's
    // PRESENCE, so presence is what it matches on.
    if has_flag(args, "--proteus-secret") {
        return Err(NodeError::Config(
            "--proteus-secret is refused: its value becomes this process's command line, which every \
             other account on this host can read from `ps` for as long as the node runs — and no wipe \
             inside the process reaches the kernel's copy. Put the secret in a file only you can read \
             and pass --proteus-secret-file instead:\n\
             \x20   (umask 077; printf %s 'YOUR-COMMUNITY-SECRET' > ~/.config/fanos/proteus.secret)\n\
             \x20   fanos node --proteus-secret-file ~/.config/fanos/proteus.secret\n\
             or set `proteus_secret = …` in a config file that is itself mode 0600."
                .to_owned(),
        ));
    }
    if let Some(path) = flag(args, "--proteus-secret-file")? {
        // Enable PROTEUS: shape every frame with this shared community secret, rotating per epoch (§13.4).
        // The secret arrives by the one channel that can be made unreadable to other accounts, and
        // `read_secret_file` checks that it actually was — see its doc for why the mode is verified rather
        // than assumed.
        config.proteus_secret = Some(read_secret_file(path, "a shared PROTEUS community secret")?);
    }
    if let Some(m) = flag(args, "--proteus-morph")? {
        // The morph selecting the codec + traffic-shaper (§13.3): plain, polymorph (default), tls-tunnel,
        // masque-h3, fronted, webrtc, pluggable. Only takes effect with a --proteus-secret-file.
        config.proteus_morph = Morph::from_name(m).ok_or_else(|| {
            NodeError::Config(format!(
                "unknown --proteus-morph '{m}' (expected: plain, polymorph, tls-tunnel, masque-h3, \
                 fronted, webrtc, pluggable)"
            ))
        })?;
    }
    if let Some(e) = flag(args, "--proteus-environment")? {
        // Enable morph auto-fallback (§13.7) under this environment policy: open, dpi-corporate,
        // sni-filter, deep-censorship. Overrides --proteus-morph (the environment picks the morph).
        config.proteus_environment = Some(Environment::from_name(e).ok_or_else(|| {
            NodeError::Config(format!(
                "unknown --proteus-environment '{e}' (expected: open, dpi-corporate, sni-filter, \
                 deep-censorship)"
            ))
        })?);
    }
    if let Some(s) = flag(args, "--mix-delay-ms")? {
        // A relay's mean Poisson mixing delay in ms (spec §L5/V7, audit S1-H1); 0 disables mixing.
        let ms = s.parse().map_err(|_| NodeError::Config(format!("bad --mix-delay-ms '{s}'")))?;
        config.mix_mean_delay = Duration::from_millis(ms);
    }
    if let Some(s) = flag(args, "--cover-interval-ms")? {
        // A relay's mean cover-cell interval in ms (spec §L5/V8, audit S1-H1/E1); 0 disables cover traffic.
        let ms = s.parse().map_err(|_| NodeError::Config(format!("bad --cover-interval-ms '{s}'")))?;
        config.cover_interval = Duration::from_millis(ms);
    }
    if let Some(path) = flag(args, "--beacon-params")? {
        // Provision the threshold-DVRF beacon so this node runs the live epoch clock (§7.6, audit S1-H2):
        // its DKG output — group commitment, threshold, and (if an anchor) its share. Generate with
        // `fanos beacon-deal`.
        config.beacon = Some(BeaconParams::from_config_str(&std::fs::read_to_string(path)?)?);
    }
    if let Some(path) = flag(args, "--ingress-params")? {
        // Provision this node as one member of a community's POROS ingress line (§6): its dealt descriptor
        // share, the dealing's public binding, the line roster and the community secret. Generate the whole
        // set with `fanos ingress-deal`, and hand each member exactly one file.
        config.ingress =
            Some(fanos_node::config::IngressParams::from_config_str(&std::fs::read_to_string(path)?)?);
        config.ingress_path = Some(PathBuf::from(path));
        // **And imply the role, as `--service` and `--exit` do.** Without this the flag was accepted, the
        // file parsed, and the node then composed no ingress host — a silent no-op unless the operator also
        // passed `--role ingress`. Handing a node a community's dealt descriptor share IS the operator
        // asking it to serve that community; there is no other reason to provision one, and a flag whose
        // effect depends on a second flag being remembered is a flag that will be absent in production.
        config.roles.ingress = true;
    }
    Ok(config)
}

/// Whether this node was given bootstrap peers and has verified **none** of them (#179).
///
/// A pure function because it is the whole decision, and a decision buried in a `select!` arm cannot be
/// tested. Three states, not two:
///
/// * `configured == 0` — this node is founding a cell. Never isolated, however few peers it has verified;
///   warning here would fire at every genesis, which is how a warning stops being read.
/// * `verified == None` — no claims book at all (no self-certifying identity, a legitimate configuration).
///   That is **cannot tell**, not **verified nobody**. Writing `verified.is_none_or(|n| n == 0)` would warn
///   on every identity-less node, which is the shape that has bitten this codebase before.
/// * `verified == Some(0)` with peers configured — reached nobody. This is the one that warns.
const fn is_isolated(verified: Option<usize>, configured: usize) -> bool {
    configured > 0 && matches!(verified, Some(0))
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
    // "configured", not a bare count: bootstrap peers are INSERTED into the directory at startup without a
    // dial (`node.rs`), so `known_peers` here is the number the operator typed and nothing has answered yet.
    // Reporting it as though it were a connection count is what made a mistyped list look like a healthy
    // start (#179).
    eprintln!(
        "fanos node up — coordinate {x}:{y}:{z} on {} ({} bootstrap peers configured)",
        health.local_addr, health.known_peers
    );

    let (admin_socket, mut admin_rx) = control_socket(args);

    // One-shot isolation check, one epoch after start (#179).
    //
    // A mistyped or stale bootstrap list produces a node that starts cleanly, forms a cell of ONE, and looks
    // healthy — and an empty list is the legitimate genesis configuration, so "alone on purpose" and "alone
    // by accident" were the same observable. One epoch is the settling time the protocol itself defines: the
    // coordinate proof is epoch-scoped, so a peer that has not been verified within one has not been reached.
    //
    // **Three states, and that is the whole predicate.** `verified_claims` is `Option<usize>` and `None`
    // means this node has no claims book at all — no self-certifying identity, a legitimate configuration —
    // which is "cannot tell", not "verified nobody". `is_none_or(|n| n == 0)` would warn on every
    // identity-less node; the match on `Some(0)` is deliberate.
    let configured = health.known_peers;
    let isolation_check = tokio::time::sleep(epoch_period);
    tokio::pin!(isolation_check);
    let mut isolation_checked = configured == 0; // a node founding a cell must stay silent, or this cries wolf at every genesis

    let stop = fanos_node::shutdown::stop_requested();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            biased;
            () = &mut stop => {
                info!("shutdown signal received");
                break;
            }
            () = &mut isolation_check, if !isolation_checked => {
                isolation_checked = true;
                if is_isolated(node.health().verified_claims, configured) {
                    warn!(
                        configured,
                        "reached none of the configured bootstrap peers — this node is alone and is now its \
                         own cell; check the addresses are right and that those peers are running"
                    );
                    eprintln!(
                        "fanos: reached none of the {configured} configured bootstrap peers — this node is alone"
                    );
                }
            }
            Some((req, reply)) = admin_rx.recv() => {
                // `fanos node` runs no chain, so `consensus` is answered by saying so rather than by inventing a
                // reading — the honest answer to "what is your height" from a process that has no ledger.
                if answer_control(&req, reply, &node, NO_CHAIN) == Control::Stop {
                    break;
                }
            }
            note = node.next_notification() => match note {
                Some(n) => log_notification_against(&n, Some(epoch_period)),
                None => break,
            },
        }
    }
    node.shutdown().await;
    // Take the control socket with us. The serving task clears it when its accept loop ends, but a clean exit
    // leaves the process before that task is polled again — so without this a normal shutdown leaves the path
    // behind. Not fatal (`serve` clears a stale socket, and `ask` reads a refused connection as "not running"),
    // but a state directory that is tidy after a clean stop is one an operator can trust at a glance.
    remove_control_socket(admin_socket.as_ref());
    eprintln!("fanos node down");
    Ok(())
}

/// Whether the control loop should keep running after a request.
#[derive(PartialEq, Eq)]
enum Control {
    /// Answered; carry on.
    Go,
    /// The operator asked this node to stop.
    Stop,
}

/// What a role with no ledger answers `consensus` with.
///
/// A named constant rather than a literal at four call sites, because the point is that these roles answer
/// *honestly* — "I run no chain" is a real answer, and a role inventing a height it does not have would be worse
/// than the missing verb this replaces.
const NO_CHAIN: &str = "this role runs no chain — start `fanos validator` to run consensus\n";

/// How long the `consensus` verb waits for the driver before answering that it did not.
///
/// Short on purpose: the probe is a local channel round trip, so anything approaching this bound *is* the finding.
///
/// It used to be gated to `validator`, its only use, with the note that an ungated constant is dead code the
/// moment this crate is linted ALONE. `stations` is a second use and is not feature-gated — every role has a
/// control socket — so the gate came off with the reason for it.
///
/// One bound for both because they are the same shape of question: a round trip to something that may be the
/// very thing that is stuck. Awaiting either unbounded would hang the control loop on the wedge the operator is
/// asking about, taking `shutdown` down with it. The timeout is what turns "not answering" into an answer.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Bind this invocation's control socket, so an operator can ask a **running** role anything.
///
/// One function because the socket was one *command's*, not the node's: of the five commands that run until
/// Ctrl-C, only `fanos node` bound it, so the anonymous proxy, the hidden-service host, the VPN datapath and the
/// consensus validator — every role anyone actually deploys — had no control channel at all, not even
/// `shutdown`. Each command rolling its own run-until-shutdown loop is *why*, so the fix is a shared seam rather
/// than a fifth copy.
///
/// Failing to bind is deliberately not fatal: a node that cannot open a control channel is still a working node,
/// and refusing to run over one would be the tool getting in the way of the thing it exists to serve.
///
/// **Not knowing where the socket belongs is the same kind of failure, and is treated the same way** (#312).
/// An environment with no `HOME` and no `--data` cannot name the directory — but the node's own state comes
/// from its configuration file, so the only thing actually lost is the control channel. The returned path is
/// therefore an `Option`: `None` means there is no socket file, which is now the *one* answer covering both a
/// failed bind and an unknown directory. The previous signature handed back a path in both cases, so the
/// caller's cleanup deleted a file this process had never created.
fn control_socket(
    args: &[String],
) -> (Option<PathBuf>, tokio::sync::mpsc::Receiver<fanos_node::admin::Envelope>) {
    let (tx, rx) = tokio::sync::mpsc::channel::<fanos_node::admin::Envelope>(16);
    let path = match data_dir_for(args) {
        Ok(dir) => fanos_node::admin::socket_path(&dir),
        Err(e) => {
            eprintln!("control socket unavailable ({e}) — `fanos status` will fall back to the config");
            return (None, rx);
        }
    };
    match fanos_node::admin::serve(&path, tx) {
        Ok(_task) => {
            eprintln!("control socket: {}", path.display());
            (Some(path), rx)
        }
        Err(e) => {
            eprintln!("control socket unavailable ({e}) — `fanos status` will fall back to the config");
            (None, rx)
        }
    }
}

/// Take this process's control socket off the filesystem on the way out, if it put one there.
///
/// One function rather than five copies of the `if let`, and it is why [`control_socket`] can return `None`
/// without that spreading to every run loop.
fn remove_control_socket(path: Option<&PathBuf>) {
    if let Some(p) = path {
        let _ = std::fs::remove_file(p);
    }
}

/// What the control socket needs from whatever kind of node a role happens to be running.
///
/// Two kinds exist. Most roles hold a `fanos_node::Node`, which knows its health and the roles the cell assigned
/// it; `fanos validator` holds the lower-level `fanos_quic::NodeHandle`, which knows its coordinate and its peers
/// and nothing about role assignment. The trait exists so there is **one** answerer rather than one per node kind,
/// and so a role that cannot answer a verb says so instead of the verb silently disappearing from that role.
trait Controllable {
    /// This node's health, as the socket renders it.
    fn health_line(&self) -> String;
    /// The roles the cell assigned, or why this node cannot say.
    fn roles_line(&self) -> String;
    /// A client, epoch **and the beacon those records are bound against** to take a census with.
    ///
    /// The beacon travels with the epoch because a coherence record is bound to `(coord, epoch)` and checked
    /// against that epoch's seed (#262). Returning the epoch alone is what let this verb read frames it could
    /// not attribute. `None` means this role cannot prove coordinates at all, and then the records it reads
    /// are unbound too — the same `vrf.then_some(beacon)` condition the role loop applies to the load
    /// directory, on both sides at once so the reader and the publisher cannot disagree.
    fn census_source(&self) -> (fanos_quic::Client, Epoch, Option<BeaconSeed>);
    /// The next overlay notification, so [`serve_control`] can drain it alongside the socket.
    async fn next_note(&mut self) -> Option<Notification>;
}

impl Controllable for Node {
    fn health_line(&self) -> String {
        fanos_node::admin::render_health(&self.health())
    }
    fn roles_line(&self) -> String {
        // The verb that prints the assignment is the one that must say when nothing is maintaining it: an
        // operator reading `roles` is asking what the cell wants here *now*, and a frozen answer looks
        // identical to a settled one (#251).
        match self.health().organizing {
            fanos_node::role_loop::RoleStanding::Deciding => format!("{:?}\n", self.assigned_roles()),
            fanos_node::role_loop::RoleStanding::Stopped => {
                format!("{:?} (FROZEN — the role controller is gone; no epoch will change this)\n", self.assigned_roles())
            }
        }
    }
    fn census_source(&self) -> (fanos_quic::Client, Epoch, Option<BeaconSeed>) {
        // A `Node` always proves coordinates (`Node::start` sets `vrf_coordinates`), so the beacon is always
        // asked for. Before the first round the epoch is 0 and the seed is this NETWORK's genesis — the value
        // every epoch-0 publisher binds against, not the shared constant.
        let client = self.client();
        let (epoch, seed) = self
            .live_beacon()
            .map_or_else(|| (Epoch::ZERO, client.genesis()), |(e, s)| (e, BeaconSeed::new(s)));
        (client, epoch, Some(seed))
    }
    async fn next_note(&mut self) -> Option<Notification> {
        self.next_notification().await
    }
}

impl Controllable for fanos_quic::NodeHandle {
    /// Coordinate, listener and verified peer claims — what this layer genuinely knows. Deliberately not the same
    /// shape as `Node`'s: reporting a health record this node cannot actually compute would be worse than a
    /// shorter honest one.
    fn health_line(&self) -> String {
        let [x, y, z] = self.address();
        let claims = self.verified_claims().map_or_else(|| "n/a (directory trust)".to_owned(), |n| n.to_string());
        format!("coordinate: {x}:{y}:{z}\nlisten: {}\nverified claims: {claims}\n", self.local_addr())
    }
    fn roles_line(&self) -> String {
        "roles: not tracked by this role — it runs a fixed function, not a cell-assigned one\n".to_owned()
    }
    fn census_source(&self) -> (fanos_quic::Client, Epoch, Option<BeaconSeed>) {
        // No beacon of its own: a validator takes its epoch from the config it was dealt, and the census only
        // needs *an* epoch to address frames with. `ZERO` reads every cell's genesis frame, which is the honest
        // answer for a node that is not tracking the live beacon rather than a silently wrong one — and the
        // seed epoch-0 records are bound against is this network's genesis. Asked for only when this role can
        // prove coordinates, because a deployment that cannot also publishes unbound (#262).
        let client = self.client();
        let genesis = self.coordinate_prover().map(|_| client.genesis());
        (client, Epoch::ZERO, genesis)
    }
    async fn next_note(&mut self) -> Option<Notification> {
        self.next_notification().await
    }
}

/// Serve a role's control socket and drain its notifications until the socket says stop or the stream ends.
///
/// One function because it was three identical copies the moment the socket reached more than one command —
/// which is the same duplication that left four roles without a socket at all, arriving a second time. A role
/// whose own work future differs (the validator, which also drains consensus events and answers `consensus` from
/// a live probe) drives its loop directly instead; that difference is real, and hiding it behind a callback would
/// buy nothing.
async fn serve_control<N: Controllable>(
    node: &mut N,
    admin_rx: &mut tokio::sync::mpsc::Receiver<fanos_node::admin::Envelope>,
    consensus: &str,
) {
    loop {
        tokio::select! {
            Some((req, reply)) = admin_rx.recv() => {
                if answer_control(&req, reply, node, consensus) == Control::Stop {
                    break;
                }
            }
            note = node.next_note() => match note {
                Some(n) => log_notification(&n),
                None => break,
            },
        }
    }
}

/// Await the data-path plane's answer to an `Observe` this caller just issued, or say why there is none.
///
/// Drains until a [`Notification::DataPath`] arrives, because `Observe` also raises the coherence observation
/// and the two share the stream. `Lagged` is retried rather than treated as failure: the drop is of *other*
/// notifications, and the one being waited for may still be ahead.
async fn read_data_path(
    notes: &mut tokio::sync::broadcast::Receiver<Notification>,
    driver: Vec<fanos_runtime::ports::stations::Observation>,
    epoch: u64,
) -> String {
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    loop {
        match tokio::time::timeout_at(deadline, notes.recv()).await {
            Ok(Ok(Notification::DataPath { stations, gather })) => {
                // **Two planes, one answer.** The engine counts what stops inside it; the driver counts what
                // stops on its own side of the seam — a directory publish whose ack never came, which the
                // engine cannot see (#106). Reporting only the engine's would tell an operator "nothing has
                // been discarded" while this node was quietly absent from every roster. Same fold the
                // contract already asks of any composite that forwards `Observe` to more than one place.
                let merged =
                    fanos_runtime::ports::stations::merge_observations(stations.into_iter().chain(driver));
                return fanos_node::admin::render_data_path(&merged, gather, epoch);
            }
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return "the node is shutting down\n".to_owned();
            }
            Err(_) => {
                // Two different worlds, and the operator needs to tell them apart: an engine that never stepped
                // the command, and a node composed with no data-path engine at all (no relay, no POROS host),
                // which has no counters to report and is not faulty for it.
                return "no answer within the probe timeout: either this node runs no data-path engine \
                        (no relay, no POROS host) or its engine is not stepping\n"
                    .to_owned();
            }
        }
    }
}

/// Await this node's own **exact** coherence frame after an `Observe`, with the liveness footprint if it
/// survived the same broadcast — or the reason there is none, already worded for an operator.
///
/// Drains until a `Notification::Observed` arrives, because `Observe` raises the data-path plane on the same
/// stream. A node too young or too alone to have a liveness view raises no observation at all — the overlay
/// emits the coherence half only when `cell_liveness` resolves — so the timeout is a real answer here and not
/// merely a guard: "this node cannot yet see its cell" is what an operator needs to be told.
///
/// The footprint is returned as an `Option` **beside** the frame rather than being required with it, because
/// its two readers need different things: `status coherence` prints the mask and cannot report a frame
/// without it, while `status census` only needs the alarm. Requiring it for both would let a dropped
/// notification cost the census its own-cell reading — a precondition stricter than that reader has any
/// use for.
async fn observe_own_frame(
    notes: &mut tokio::sync::broadcast::Receiver<Notification>,
) -> Result<(fanos_telemetry::CoherenceFrame, Option<(u8, u16)>), String> {
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    // The footprint arrives in its own notification, immediately before the frame. Held rather than awaited
    // separately: one `Observe` raises both, so a second round trip would double the cost of the verb and
    // could straddle two observation windows — reporting a mask from one and a frame from the next.
    let mut seen: Option<(u8, u16)> = None;
    loop {
        match tokio::time::timeout_at(deadline, notes.recv()).await {
            Ok(Ok(Notification::Liveness { degraded, alive, .. })) => seen = Some((degraded, alive)),
            Ok(Ok(Notification::Observed(bytes))) => {
                return fanos_telemetry::CoherenceFrame::decode(&bytes).map_or_else(
                    || Err("the node emitted a frame this build cannot decode\n".to_owned()),
                    |f| Ok((f, seen)),
                );
            }
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return Err("the node is shutting down\n".to_owned());
            }
            Err(_) => {
                return Err("no coherence observation within the probe timeout: this node cannot yet see \
                            its cell (too few peers, or no heartbeats have completed a window)\n"
                    .to_owned());
            }
        }
    }
}

/// `status coherence`: this node's own frame rendered with its liveness footprint.
async fn read_coherence(notes: &mut tokio::sync::broadcast::Receiver<Notification>) -> String {
    match observe_own_frame(notes).await {
        Err(why) => why,
        // **`(0, 0)` would read as "nothing degraded, nobody alive", which is a claim rather than an
        // absence.** The footprint arrives on the same lossy broadcast as the frame, immediately before it,
        // so a `Lagged` between the two used to make `fanos status coherence` print a confident report of a
        // cell it had not seen. Reported as unknown instead (#88).
        Ok((_, None)) => "the coherence frame arrived without its liveness footprint (the notification \
                          stream dropped it under load) — re-run `fanos status coherence`\n"
            .to_owned(),
        Ok((frame, Some((degraded, alive)))) => {
            fanos_node::admin::render_coherence(&frame, degraded, alive)
        }
    }
}

/// Answer one control request. `consensus` is the only verb a role answers differently, so it arrives already
/// rendered — a role with a ledger passes its probe, a role without passes [`NO_CHAIN`].
fn answer_control<N: Controllable>(
    req: &fanos_node::admin::Request,
    reply: tokio::sync::oneshot::Sender<String>,
    node: &N,
    consensus: &str,
) -> Control {
    use fanos_node::admin::Request;
    let stop = matches!(req, Request::Shutdown);
    let body = match *req {
        Request::Ping => "pong\n".to_owned(),
        Request::Health => node.health_line(),
        Request::Roles => node.roles_line(),
        Request::Consensus => consensus.to_owned(),
        Request::Shutdown => "shutting down\n".to_owned(),
        // **The frame goes to the cell, not to a peer.** Its audience is every anchor and its authority
        // travels with it — the signature is checked by each recipient — so `Broadcast` is the shape, and
        // resolving q²+q+1 coordinates to deliver it would fail exactly when the cell is unwell enough to
        // need it. This node's own beacon is reached the same way every peer's is: by the re-flood, which is
        // why the operator may point this at any member rather than having to find an anchor.
        Request::Reshare(ref frame) => {
            let (client, _, _) = node.census_source();
            let bytes = frame.len();
            if client.command(fanos_runtime::Command::Broadcast { frame: frame.clone() }) {
                format!("reshare trigger broadcast ({bytes} bytes)\n")
            } else {
                "the engine has stopped; nothing was sent\n".to_owned()
            }
        }
        Request::Coherence => {
            // Answered off the loop and bounded, for the same reasons as `stations` — it is the same
            // `Observe` round trip, and the node an operator asks this of may be the one that is stuck.
            let (client, _, _) = node.census_source();
            tokio::spawn(async move {
                let mut notes = client.subscribe();
                let asked = client.command(fanos_node::Command::Observe);
                let body = if asked {
                    read_coherence(&mut notes).await
                } else {
                    "the engine is not accepting commands\n".to_owned()
                };
                let _ = reply.send(body);
            });
            return Control::Go;
        }
        Request::Stations => {
            // Answered off the loop, for the same reason as `census` and by the same shape: it round-trips a
            // command through the engine, and serving it inline would stop this node driving that engine while
            // it waits for its own answer.
            //
            // The wait is **bounded**, like the consensus probe. A node whose engine is not stepping is exactly
            // the node an operator asks this of, and an unbounded await would hang on it — turning the verb
            // that should report the wedge into another casualty of it. The timeout makes "the engine is not
            // answering" an answer.
            // The node's own epoch, so the schedule is reported against the clock the heights are measured
            // in. Reading it from the live beacon rather than a wall clock is the whole point of an
            // epoch-aligned activation: an operator comparing two nodes must see the same ordinal.
            // Only the epoch here: this verb reports a schedule, and reads no bound record whose binding
            // would need checking. Named `_beacon` rather than dropped so the next reader sees the source
            // does carry one (#262).
            let (client, epoch, _beacon) = node.census_source();
            tokio::spawn(async move {
                let mut notes = client.subscribe();
                // Subscribe *before* issuing, or the answer can land in the gap between the two.
                let asked = client.command(fanos_node::Command::Observe);
                let body = if asked {
                    read_data_path(&mut notes, client.driver_stations(), epoch.get()).await
                } else {
                    "the engine is not accepting commands\n".to_owned()
                };
                let _ = reply.send(body);
            });
            return Control::Go;
        }
        Request::Census => {
            // Answered off the loop. A census reads every cell coordinate out of the overlay store, so serving it
            // inline would stop this node driving its own engine for the duration — an operator's question is not
            // worth pausing the node it is about.
            let (client, epoch, beacon) = node.census_source();
            tokio::spawn(async move {
                // This node's own cell is answered from its own engine, never from its own ε-private export
                // read back out of the directory: the published frames are rebuilds of an equicorrelated
                // cell, measured to invent a `Structure` alarm on a healthy cell in 2.8% of the swept
                // parameter space, and the exact frame is one `Observe` away (#278).
                //
                // Subscribed *before* the command is issued, or the answer can land in the gap between the
                // two. A node that cannot answer — no observation window yet, engine not accepting commands —
                // gets `None`, and the census says so on its own line rather than silently falling back to
                // the export.
                let mut notes = client.subscribe();
                let own = if client.command(fanos_node::Command::Observe) {
                    observe_own_frame(&mut notes).await.ok().map(|(frame, _)| frame)
                } else {
                    None
                };
                let coords = fanos_node::telemetry_dir::plane_telemetry_coords::<F2>();
                let census = fanos_node::telemetry_dir::take_census::<F2>(
                    &client,
                    &coords,
                    epoch,
                    beacon,
                    own.as_ref(),
                )
                .await;
                let _ = reply.send(census.to_string());
            });
            return Control::Go;
        }
    };
    let _ = reply.send(body);
    if stop {
        info!("shutdown requested over the control socket");
        return Control::Stop;
    }
    Control::Go
}

/// Where this invocation's state lives — the directory the control socket goes in.
///
/// `--data` if given, else the platform layout this host was set up with, so `fanos status` finds the socket of a
/// node started by the service unit without being told where to look.
///
/// `--data` is checked **first**, and that ordering is the escape hatch: an operator who names the directory
/// never reaches the layout, so a process with no `HOME` is still fully usable — it just has to say where its
/// files are instead of being guessed at (#312).
///
/// # Errors
///
/// [`NodeError::Config`] when `--data` is absent and the layout cannot be determined.
fn data_dir_for(args: &[String]) -> Result<PathBuf, NodeError> {
    match flag(args, "--data")? {
        Some(d) => Ok(PathBuf::from(d)),
        None => Ok(fanos_node::setup::Paths::detect()?.data),
    }
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
/// (`build_plane_mix_directory` — the relays that published an onion key this epoch), so neither party's
/// location is revealed and an observer cannot link one client's successive connections by their path. It
/// refuses to start unless at least `threshold + 1` relays are live, and takes the epoch's public `--beacon`
/// so its drawn meeting line matches the service's.
async fn cmd_proxy(args: &[String]) -> Result<(), NodeError> {
    init_tracing();

    let socks_listen: SocketAddr = match flag(args, "--socks-listen")? {
        Some(s) => s
            .parse()
            .map_err(|_| NodeError::Config(format!("bad --socks-listen '{s}'")))?,
        None => SocketAddr::from(([127, 0, 0, 1], 1080)),
    };
    let http_listen: Option<SocketAddr> = match flag(args, "--http-listen")? {
        Some(s) => Some(
            s.parse()
                .map_err(|_| NodeError::Config(format!("bad --http-listen '{s}'")))?,
        ),
        None => None,
    };
    // **Absent means FOLLOW THE BEACON, not epoch zero** (#344). A descriptor now rotates, so a dialer that
    // silently pinned genesis would look at a slot the service left behind. `--epoch` stays as the operator's
    // override for reading a known past epoch; it is a deliberate act, not the default.
    let pinned_epoch = match flag(args, "--epoch")? {
        Some(s) => Some(Epoch::new(
            s.parse()
                .map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?,
        )),
        None => None,
    };
    let epoch = pinned_epoch.unwrap_or(Epoch::ZERO);
    let min_pow = match flag(args, "--min-pow")? {
        Some(s) => s
            .parse()
            .map_err(|_| NodeError::Config(format!("bad --min-pow '{s}'")))?,
        None => 0,
    };
    // Routing profile: `direct` (default) reaches services by coordinate; `anonymous` draws a fresh,
    // unlinkable threshold-onion rendezvous route per dial from the live cell mix directory (spec §L5,
    // #54). Parse its knobs up front so bad arguments fail before we join the overlay.
    let anon = match flag(args, "--profile")?.unwrap_or("direct") {
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
    let resolver = NodeResolver::new(node.client(), pinned_epoch, min_pow);
    // `FanosDialer` is not `Clone`, so `serve_proxy` shares it behind an `Arc` (per-connection handlers need
    // only `&D`). The dialer holds its own `Client`; the node stays owned here for notification draining + a
    // clean shutdown.
    let dialer = match build_proxy_dialer(&node, resolver, epoch, anon.as_ref(), exit).await {
        Ok(dialer) => Arc::new(dialer),
        Err(e) => {
            node.shutdown().await;
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
        fanos_node::shutdown::stop_requested().await;
        info!("shutdown signal received");
    };
    let (admin_socket, mut admin_rx) = control_socket(args);
    tokio::select! {
        () = serve_proxy(socks, http, dialer, shutdown) => {}
        () = serve_control(&mut node, &mut admin_rx, NO_CHAIN) => {}
    }
    node.shutdown().await;
    remove_control_socket(admin_socket.as_ref());
    eprintln!("fanos proxy down");
    Ok(())
}

/// Derive a hidden service's full published identity from its secret seed.
///
/// Both halves come from the one seed so a restart re-derives the same `.fanos` address, and they are
/// domain-separated so the KEM and signing keys are independent draws rather than two views of one.
///
/// Hosting **needs** the signing half, which is why this exists beside `bundle_from_kem_public` rather than
/// replacing a call to it: a combiner authenticates a route registration by recomputing the service tag from the
/// presented bundle and verifying a signature under its signing prefix, and a KEM-only bundle's prefix is zero —
/// reconstructible by anyone holding the (public) KEM key, so it would authenticate nothing while appearing to.
fn hidden_service_identity(host_secret: &[u8]) -> (StaticKeypair, HybridSigSecret, Vec<u8>) {
    let service = StaticKeypair::generate(&mut SeedRng::from_seed(host_secret));
    let mut sign_seed = host_secret.to_vec();
    sign_seed.extend_from_slice(b"/fanos-host-sign");
    let (signer, verifier) = HybridSigSecret::generate(&mut SeedRng::from_seed(&sign_seed));
    let bundle = bundle_from_identity(&verifier, service.public());
    (service, signer, bundle)
}

/// Host a **hidden service** on the anonymous rendezvous (§3b, `design-anonymity-substrate.md`): run a node,
/// publish the service's descriptor so clients resolve its `.fanos` name, and forward every incoming
/// anonymous session to a local `--forward host:port` (the onion-service model). The service is reachable at
/// its rotating meeting line though this node is never that line's combiner, and no party — not even the
/// combiner — learns this node's coordinate. `--host-key <file>` is the service's secret seed, its **stable
/// `.fanos` identity** (keep it secret; generate one with `(umask 077; head -c 32 /dev/urandom > svc.key)` —
/// the umask is part of the recipe, and #310 made the tool check it rather than only advise it). The dial
/// side is `fanos proxy --profile anonymous` with a matching `--epoch`/`--beacon`/`--threshold`.
async fn cmd_host(args: &[String]) -> Result<(), NodeError> {
    init_tracing();
    let forward: SocketAddr = flag(args, "--forward")?
        .ok_or_else(|| NodeError::Config("fanos host requires --forward <host:port>".to_owned()))?
        .parse()
        .map_err(|_| NodeError::Config("bad --forward (expected host:port)".to_owned()))?;
    let host_secret = match flag(args, "--host-key")? {
        Some(p) => read_seed_file(p, "a hidden service's secret seed")?,
        None => {
            return Err(NodeError::Config(
                "fanos host requires --host-key <file> — the service's secret seed and stable .fanos \
                 identity (generate one with `(umask 077; head -c 32 /dev/urandom > svc.key)`; the \
                 umask is part of the recipe — the default one writes the seed world-readable)"
                    .to_owned(),
            ));
        }
    };
    let epoch = match flag(args, "--epoch")? {
        Some(s) => {
            Epoch::new(s.parse().map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?)
        }
        None => Epoch::ZERO,
    };
    let beacon = beacon_arg(args)?;
    let threshold = mix_threshold_arg(args)?;
    if threshold == 0 {
        return Err(NodeError::Config("--threshold must be at least 1".to_owned()));
    }
    let descriptor_pow: u32 = match flag(args, "--descriptor-pow")? {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --descriptor-pow '{s}'")))?,
        None => 0,
    };

    // Derive the service identity + its `.fanos` address from the secret seed.
    let (service, signer, bundle) = hidden_service_identity(&host_secret);
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
        node.shutdown().await;
        return Err(e);
    }
    // **And keep it there** (#344). The first publish above stays because a startup failure must be an exit
    // code rather than a supervised actor's counter — an operator running `serve-anonymous` needs to know
    // immediately that the store refused. The loop then owns every later epoch: the slot the descriptor lives
    // at is a function of the epoch, so without this the service is resolvable only until its current slot
    // expires and then vanishes with the host still up and still serving.
    let _descriptors = fanos_node::spawn_descriptor_publisher(
        node.client(),
        bundle.clone(),
        [0, 0, 0],
        descriptor_pow,
        b"profile=anonymous".to_vec(),
    );

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
        HostedService { service, identity: bundle.clone(), signer, host_secret, threshold, vrf_coordinates: true },
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
        fanos_node::shutdown::stop_requested().await;
        info!("shutdown signal received");
    };
    let (admin_socket, mut admin_rx) = control_socket(args);
    tokio::select! {
        () = shutdown => {}
        () = serve_control(&mut node, &mut admin_rx, NO_CHAIN) => {}
    }
    node.shutdown().await;
    remove_control_socket(admin_socket.as_ref());
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

    let tun_name = flag(args, "--tun")?.unwrap_or("").to_owned();
    let epoch = match flag(args, "--epoch")? {
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
        node.shutdown().await;
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
        FanosDialer::new(node.client(), StaticResolver::new())
            .with_exit(exit_coord, bundle_from_kem_public(&exit_public)),
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
        fanos_node::shutdown::stop_requested().await;
        info!("shutdown signal received");
    };
    let (admin_socket, mut admin_rx) = control_socket(args);
    tokio::select! {
        () = fanos_vpn::run_fulltunnel(device, dialer) => {}
        () = shutdown => {}
        () = serve_control(&mut node, &mut admin_rx, NO_CHAIN) => {}
    }
    node.shutdown().await;
    remove_control_socket(admin_socket.as_ref());
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

/// Why the anonymous profile is refusing, in the operator's terms — **and the remediation differs by cause**.
///
/// This existed as one `format!` giving one piece of advice: *"start relays that publish mix keys or lower
/// `--threshold`"*. That advice is right for exactly one of the two ways `resolved < need` happens, and the
/// call site could not tell them apart because it dropped the scan's completeness with `.0`.
///
/// * **The relays are genuinely absent.** Fewer than `need` members published a mix key. Start relays, or
///   lower the threshold — the original message, now stated only when it is true.
/// * **The reads did not conclude.** Every relay may be up and publishing while this node's store reads time
///   out, which is congestion — or the read-stalling attack `mixdir`'s own module doc names, where slowing a
///   chosen subset of slots is far cheaper than compromising a node. Here "start more relays" is advice for a
///   problem the operator does not have, and "lower `--threshold`" is worse than useless: it edits their own
///   anonymity parameter downward, permanently, in response to a transient failure. The honest instruction is
///   to retry.
///
/// A pure function rather than an inline `format!` because a binary's inner `async fn` is not reachable from a
/// test, and the message **is** the claim being made — an untestable report is a report that can quietly go
/// back to giving one answer to two questions.
#[must_use]
fn too_few_relays(need: usize, epoch: u64, resolved: usize, view: Coverage) -> String {
    let head =
        format!("anonymous profile needs at least threshold+1={need} live mix relays for epoch {epoch}, found {resolved}");
    if view.complete() {
        format!("{head} — start relays that publish mix keys or lower --threshold")
    } else {
        format!(
            "{head}, and {} more slot(s) did not answer in time — the cell may be fully staffed and merely \
             slow to read. Retry before changing anything; do NOT lower --threshold, which would weaken this \
             node's anonymity for what may be a transient read failure",
            view.unresolved
        )
    }
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
        let (directory, view) =
            build_plane_mix_directory::<F2>(&node.client(), epoch, Some(beacon)).await;
        let need = usize::from(cfg.threshold) + 1;
        if directory.len() < need {
            return Err(NodeError::Config(too_few_relays(
                need,
                epoch.get(),
                directory.len(),
                view,
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
        // The exit directory publishes a KEM key, not a full identity bundle, so it is wrapped as a KEM-only one.
        // That is correct **for an exit** and would not be for a hidden service: an exit is located by coordinate
        // and answers at its own meeting combiner, so no `HostRegister` binds it and the tag a dial computes
        // matches nothing — the delivery then surfaces locally at the combiner, which is exactly the
        // service-is-its-own-combiner path. An exit hosted OFF its combiner would need a real bundle, and giving
        // the exit directory one is the follow-up rather than a silent gap.
        Some((coord, public)) => base.with_exit(coord, bundle_from_kem_public(&public)),
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
        match flag(args, name)? {
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
    // onion header. Both ends are checked because both failures are otherwise **silent**, in opposite ways.
    //
    // Too DEEP: `create_forward` swallows the over-depth error with `.ok()?`, so an operator past the ceiling gets dials
    // that quietly never connect rather than a message saying why.
    //
    // Too SHALLOW is the worse one, and it had no check at all: the dials connect. They just carry no anonymity, while the
    // profile still calls itself anonymous. `slots::MIN_FORWARD_DEPTH` derives why — below it the hop the client dials and
    // the hop that learns the meeting line are ONE line, so `t` corrupted members name both ends, and `t` is the tolerated
    // budget at Fano. At `--fwd-depth 0` the client dials the service's meeting line itself.
    //
    // On the Fano plane the two bounds MEET at 2, so the depth is forced rather than chosen — which is the honest reading of
    // a default that was picked to sit "exactly at the ceiling" without anyone checking there was a floor beneath it.
    let line_size = line_size_arg(args)?;
    let max_depth = fanos_aphantos::slots::depth_for(line_size).saturating_sub(1);
    let (fwd_depth, reply_depth) = (usize_flag("--fwd-depth", 2)?, usize_flag("--reply-depth", 2)?);
    let floors = [
        ("--fwd-depth", fwd_depth, fanos_aphantos::slots::MIN_FORWARD_DEPTH),
        ("--reply-depth", reply_depth, fanos_aphantos::slots::MIN_REPLY_DEPTH),
    ];
    for (name, depth, floor) in floors {
        if depth > max_depth {
            return Err(NodeError::Config(format!(
                "{name} is {depth}, but the onion header carries at most {} hops on a plane of order {}, so {max_depth} \
                 intermediate hops. A deeper circuit needs payload fragmentation, not a wider cell — widening the cell buys \
                 more slots and so a SMALLER payload.",
                max_depth + 1,
                line_size - 1
            )));
        }
        if depth < floor {
            return Err(NodeError::Config(format!(
                "{name} is {depth}, below the {floor} intermediate hops anonymity needs. This is not a weaker setting, it \
                 is none: a circuit that short has one line holding both endpoints' names, so capturing it alone — `t` \
                 members, which IS the tolerated fault budget on this plane — deanonymizes every session it carries. Use \
                 `--profile direct` if that is what you want, and it will say so."
            )));
        }
    }
    if !fanos_aphantos::slots::plane_can_anonymize(line_size) {
        return Err(NodeError::Config(format!(
            "plane order {} cannot carry an anonymous circuit at the shipped onion budget: its header holds {} hops where \
             {} are needed ({} intermediate plus the destination). The onion budget is a per-deployment parameter, so the \
             answer for a wide plane is a wider onion — not a shallower circuit, which would be no circuit.",
            line_size - 1,
            fanos_aphantos::slots::depth_for(line_size),
            fanos_aphantos::slots::TARGET_DEPTH,
            fanos_aphantos::slots::MIN_FORWARD_DEPTH,
        )));
    }
    Ok(AnonConfig {
        threshold,
        fwd_depth,
        reply_depth,
        beacon: beacon_arg(args)?,
    })
}

/// Put a sealed transaction on the wire, **anonymously by default**.
///
/// The submission used to be `Emit { to: Point::at(0) }` — this node's own coordinate, on a connection the
/// transport authenticates, straight at a constant validator. The keyper seal hid *what* was being sent and
/// the emission published *who* was sending it, to one named node, for every user of this binary. For a
/// platform whose currency is a shielded pool that is the wrong half hidden, and the fixed destination made
/// it worse: one node saw every submission, which is a surveillance point and a censorship chokepoint at once.
///
/// So the frame now rides a threshold onion to a **randomly drawn destination line**, launched at its first
/// hop, and surfaces there as an anonymous delivery the TAXIS driver ingests (`Tx` authenticates itself, so
/// accepting it from a sender with no name widens nothing). Two things change together: no validator learns
/// the submitter, and no validator sees more than its share.
///
/// `--direct` restores the old path for a user who wants it — and says what it costs, because an exposure
/// nobody names is one nobody weighs.
#[cfg(feature = "validator")]
async fn submit_tx_frame(
    node: &Node,
    args: &[String],
    epoch: Epoch,
    beacon: &BeaconSeed,
    frame: &[u8],
) -> Result<bool, NodeError> {
    use fanos_geometry::{Line, Plane, Point};
    use fanos_runtime::Command;

    // OS entropy, freshly per submission: the destination line and the circuit must not be predictable from
    // anything an observer holds, or a watcher waits at the line this binary was going to pick anyway.
    let mut entropy = [0u8; 33];
    getrandom::fill(&mut entropy).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let (seed, pick) = entropy.split_at(32);

    if has_flag(args, "--direct") {
        eprintln!(
            "warning: --direct submits straight to a validator from this node's own coordinate, so that \
             validator learns you submitted this transaction and can link it to you when it is revealed."
        );
        return Ok(node.command(Command::Emit { to: Point::<F2>::at(0).coords(), frame: frame.to_vec() }));
    }
    let client = node.client();
    let (directory, view) = build_plane_mix_directory::<F2>(&client, epoch, Some(*beacon)).await;
    if !view.complete() {
        // Not a refusal: unlike the proxy above, this path fails CLOSED — `emit_anonymously` returning
        // `None` produces an error that offers `--direct` with its cost stated. What it does not do is
        // say anything when it SUCCEEDS over a partial view, and that is the case worth a line: the
        // circuit was then drawn from whichever lines answered rather than from the cell, which is
        // exactly the placement an adversary stalling a chosen subset of store reads would shape.
        warn!(
            resolved = directory.len(),
            unresolved = view.unresolved,
            "submitting over a partially resolved mix directory: this circuit is drawn from the lines \
             that answered, not from the whole cell"
        );
    }
    let params = AnonRouteParams {
        directory,
        threshold: mix_threshold_arg(args)?,
        epoch,
        beacon: *beacon,
        depths: (fanos_aphantos::slots::MIN_FORWARD_DEPTH, fanos_aphantos::slots::MIN_REPLY_DEPTH),
    };
    let mut rng = SeedRng::from_seed(seed);
    // A fresh destination line per submission, so no node accumulates a view of who transacts. The line is
    // where the delivery surfaces; its salted member ingests and gossips to the rest of the cell.
    let n = Plane::<F2>::N as usize;
    let destination = Line::<F2>::at(usize::from(pick.first().copied().unwrap_or(0)) % n.max(1)).coords();
    if fanos_node::rendezvous::emit_anonymously::<F2, _>(&client, &params, destination, frame, &mut rng)
        .is_some()
    {
        return Ok(true);
    }
    Err(NodeError::Config(
        "could not submit anonymously: this cell offers no sealable circuit of the required depth right now. \
         Retry, or pass `--direct` to submit in the clear — which tells one validator that you sent this."
            .to_owned(),
    ))
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

/// The beacon seed a verb computes against: `--beacon HEX` when the operator names one, otherwise **epoch 0
/// of the network this invocation is configured for**.
///
/// The default used to be `BeaconSeed::GENESIS` in four separate verbs, which was correct only while that
/// constant *was* every network's epoch-0 seed. It is now derived per network
/// (`docs/design-genesis.md` §4), so the constant would draw meeting lines, hidden-service dead-drops, mix
/// routes and validator placements for a network nobody is on — each verb failing silently, by finding
/// nothing, which is the hardest failure for an operator to attribute.
///
/// The value comes from the very configuration the same command line already names (`--config`,
/// `--beacon-params`); with neither, there is no beacon and the constant is the honest answer.
fn beacon_arg(args: &[String]) -> Result<BeaconSeed, NodeError> {
    match flag(args, "--beacon")? {
        Some(s) => parse_beacon_hex(s),
        None => Ok(node_config_from_args(args)?.genesis_seed()),
    }
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
///
/// Bytes, not text, because the material that most needs the guard is not text: a founder's seed and a
/// validator's config are raw. The guard existed and the ceremonies that deal shares went around it (#82),
/// which is the reason this takes whatever the caller has rather than what the first caller happened to have.
fn write_file(path: &Path, contents: impl AsRef<[u8]>, secret: bool) -> Result<(), NodeError> {
    if let Some(parent) = path.parent() {
        // 0700, not the umask — the same lesson as the mode below, one level up, and the level #166 found
        // this helper had still missed: a seed written 0600 into a 0755 directory keeps its BYTES private
        // and publishes the fact that it exists, under its name, to every account on the host. Enumerating
        // a ceremony's output is most of knowing what to attack.
        //
        // Unconditional rather than `if secret`, because a ceremony writes secrets and non-secrets into one
        // directory and whichever happened to be written first would otherwise decide the mode for both.
        // An ordering-dependent permission is the defect, not a weaker default.
        fanos_node::durable::create_private_dir(parent)?;
    }
    if secret {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        std::io::Write::write_all(&mut f, contents.as_ref())?;
    } else {
        std::fs::write(path, contents.as_ref())?;
    }
    Ok(())
}

/// Write a dealt file and say so, in the one shape every ceremony in this tool uses.
///
/// `secret` is the caller's declaration that the bytes are key material — it selects 0600 AND the marking in
/// the operator's transcript, so a file cannot be quietly protected without being announced, or announced
/// without being protected.
fn write_dealt(path: &str, contents: impl AsRef<[u8]>, secret: bool) -> Result<(), NodeError> {
    write_file(Path::new(path), contents, secret)?;
    if secret {
        println!("wrote {path}  (SECRET — mode 0600; keep it off any node that does not need it)");
    } else {
        println!("wrote {path}");
    }
    Ok(())
}

/// Refuse `path` if any account other than its owner can reach its bytes — the read-side counterpart to
/// [`write_file`]'s `secret` arm.
///
/// A file is *able* to carry `0600`; that is not the same as carrying it, and the difference is the whole
/// value of moving a secret out of argv (#13). `echo hunter2 > secret` under the usual `umask 022` produces a
/// world-readable file, and a node that read it without looking would have swapped one universally readable
/// channel for another while reporting success. So the mode is verified, not assumed, at the moment the
/// secret is taken in.
///
/// The mask is `0o077` — *no* bit set for group or other — matching
/// [`fanos_node::durable`]'s guard rather than demanding an exact `0o600`, so an operator who narrowed the
/// mode further still passes. The message names the fix (`chmod 600 <path>`) because a refusal an operator
/// cannot act on is a refusal they will work around.
///
/// ## Reading is only half the authority (#314)
///
/// A `0600` key inside a directory another account can write cannot be *read* by them and can be
/// **replaced**: renaming and unlinking need write permission on the DIRECTORY, never on the file. A
/// substituted host key is a service identity the attacker now owns, so disclosure and substitution are
/// different attacks with the same outcome — and the mode check answers only the first. Every directory the
/// kernel will traverse on the way to the file is therefore checked as well, by
/// [`require_unsubstitutable_path`].
///
/// It does **not** claim more than it checks: an ACL, a shared home on a network filesystem, or a mount
/// point replaced underneath can still expose it, and the modes are a snapshot taken just before the read
/// rather than a lock. Ownership is deliberately not asked about, and does not need to be for what this
/// guard is for: a non-root process that passes the `0o077` test on a file it does **not** own cannot read
/// that file at all, so the read fails by itself — and a root operator naming another account's file is an
/// explicit act rather than an accident.
///
/// **And it does not cover every secret file this binary reads.** `--key`, `--service`, `--exit`,
/// `--beacon-params`, `--ingress-params` and `fanos validator --config` all take key material by path and
/// read it at whatever mode it has. Those are a different defect — an operator's permission choice, on files
/// this tool's own ceremonies already write `0600` through [`write_dealt`] — where the PROTEUS secret's was
/// the tool *forcing* the exposure with no private channel offered at all. **Six, not the seven this
/// paragraph used to list**: `--host-key` was the one file of the seven the tool never produces, so its
/// recipe was handed to the operator as prose (`umask 077; head -c 32 /dev/urandom`) and the justification
/// above did not cover it. It now goes through [`read_seed_file`], which comes through here. Named so a
/// reader does not take this guard for a property of the whole binary.
fn require_private_file(path: &str, what: &str) -> Result<(), NodeError> {
    use std::os::unix::fs::PermissionsExt as _;

    let meta = std::fs::metadata(path)
        .map_err(|e| NodeError::Config(format!("cannot open '{path}' ({what}): {e}")))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(NodeError::Config(format!(
            "'{path}' holds {what} and is reachable by other accounts on this host (mode {mode:o}) — run \
             `chmod 600 {path}` and start again"
        )));
    }
    require_unsubstitutable_path(path, what)
}

/// Whether a directory at `mode` lets an account other than an entry's owner put a *different* file there.
///
/// **Both halves are POSIX semantics, so there is no chosen number here.** Write permission on a directory
/// is the authority to create, rename and unlink entries within it — which is substitution. The sticky bit
/// (`0o1000`) withdraws exactly that for entries somebody else owns, and it is what makes `1777` `/tmp`
/// usable at all. A guard that ignored it would lie in both directions: refusing a perfectly safe secret in
/// `/tmp`, and — read the other way round — implying that "not world-writable" was the whole question.
const fn substitutable_by_others(mode: u32) -> bool {
    mode & 0o022 != 0 && mode & 0o1000 == 0
}

/// Refuse if any directory the kernel will traverse on the way to `path` can be written by another account.
///
/// Two things the obvious one-line version (`stat` the parent) would miss, and both are reachable:
///
/// * **Symlinks are resolved at every step, not once at the end.** A link inside a writable directory can be
///   re-pointed at another file, so the directory that *holds* each component matters as much as the one the
///   path finally names. Canonicalising only the whole path would check the target's chain and never the
///   link's.
/// * **Each resolved directory's ancestors are checked too.** A writable *grand*parent can rename the
///   directory itself and put its own in place, which substitutes everything beneath it.
///
/// The chains overlap heavily, so answered directories are remembered: the walk is one `stat` per distinct
/// directory rather than one per (component, ancestor) pair.
///
/// # Errors
///
/// [`NodeError::Config`] naming the first directory that fails, or the component that could not be resolved.
/// A directory that cannot be inspected is an error rather than a skip: `canonicalize` having succeeded
/// means every ancestor exists and is traversable, so a `stat` that fails anyway is a fact about the path
/// this guard must not swallow.
fn require_unsubstitutable_path(path: &str, what: &str) -> Result<(), NodeError> {
    use std::os::unix::fs::PermissionsExt as _;

    let given = Path::new(path);
    // Relative paths are resolved against the working directory, because that is what the kernel will do:
    // a guard that reasoned about `secret.key` without knowing where it sits would answer a question
    // nobody asked.
    let absolute =
        if given.is_absolute() { given.to_path_buf() } else { std::env::current_dir()?.join(given) };
    let components: Vec<_> = absolute.components().collect();
    let mut answered: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    let mut prefix = PathBuf::new();
    for (i, component) in components.iter().enumerate() {
        prefix.push(component);
        // The last component is the file itself; its own mode is `require_private_file`'s question.
        if i + 1 == components.len() {
            break;
        }
        let real = prefix.canonicalize().map_err(|e| {
            NodeError::Config(format!(
                "cannot resolve '{}' on the way to '{path}' ({what}): {e}",
                prefix.display()
            ))
        })?;
        for dir in real.ancestors() {
            if !answered.insert(dir.to_path_buf()) {
                continue;
            }
            let meta = std::fs::metadata(dir).map_err(|e| {
                NodeError::Config(format!(
                    "cannot inspect '{}', which holds the path to '{path}' ({what}): {e}",
                    dir.display()
                ))
            })?;
            let mode = meta.permissions().mode() & 0o7777;
            if substitutable_by_others(mode) {
                return Err(NodeError::Config(format!(
                    "'{path}' holds {what} inside '{}', which other accounts on this host can write (mode \
                     {mode:o}) — they cannot read the file, and they can REPLACE it, which for key material \
                     is the same authority. Move it under a directory only you can write (`mkdir -m 700 \
                     ~/.fanos` and keep it there). A shared directory carrying the sticky bit, such as \
                     /tmp, is accepted: there only a file's own owner may replace it.",
                    dir.display()
                )));
            }
        }
        prefix = real;
    }
    Ok(())
}

/// Read a **raw seed** out of an owner-only file — the `--host-key` form of key material (#310).
///
/// Guarded exactly like [`read_secret_file`] and, deliberately, parsed unlike it: **nothing is stripped**.
/// Folding the two into one function would be [`one constant, two quantities`](read_secret_file) in reader's
/// clothing. `read_secret_file` takes a *shared, human-transcribed* PROTEUS secret, where one member's `echo`
/// and another's `printf` must end up with identical bytes, so a trailing newline cannot be part of it. A
/// host key is 32 bytes from `/dev/urandom`, where **every byte is the secret**: about one seed in 256 ends
/// in `0x0a`, and stripping it would silently derive a different `.fanos` address for those — a service
/// unreachable at the name its operator wrote down, with nothing saying why.
///
/// An empty file is refused for a sharper reason than the shared secret's: `SeedRng::from_seed(&[])` is a
/// *fixed* seed, so a truncated copy or a failed `scp` would give every such service the **same** identity,
/// publicly derivable by anyone who tries the empty seed.
///
/// Returns a plain `Vec<u8>` rather than a [`Zeroizing`](zeroize::Zeroizing) one, and that is not an
/// oversight. The value is moved into `HostedService`, which holds it for the life of the process because
/// every epoch's dead-drop line and reply key are derived from it; wrapping the local would wipe one copy
/// while the long-lived one stayed — the appearance of the property without the property.
fn read_seed_file(path: &str, what: &str) -> Result<Vec<u8>, NodeError> {
    require_private_file(path, what)?;
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        return Err(NodeError::Config(format!(
            "'{path}' is empty, so it holds no {what} — an empty seed is a FIXED seed, and every service \
             started from one lands on the same publicly derivable identity. Generate one with \
             `(umask 077; head -c 32 /dev/urandom > {path})`"
        )));
    }
    Ok(bytes)
}

/// Read key material out of an owner-only file.
///
/// Wiped on drop ([`Zeroizing`](zeroize::Zeroizing)), matching the config field it fills.
///
/// **One trailing newline is stripped**, and that is a correctness requirement rather than a convenience: a
/// PROTEUS secret is *shared*, so two members who write it two ways must end up with the same bytes.
/// `echo s > f` appends a newline and `printf %s s > f` does not; without the strip those two members shape
/// their frames with different keys, and PROTEUS's failure mode for a key mismatch is silence — the
/// handshake simply does not complete, with nothing anywhere saying why. The price is that a secret whose
/// last byte is a newline cannot be expressed; stated because it is a real restriction and not an oversight.
/// `\r\n` is stripped too, for a file that has been through a Windows editor on its way between hosts.
///
/// An empty file is refused rather than accepted as an empty secret: it is what a truncated copy, a failed
/// `scp`, or a mistyped redirection leaves behind, and an empty shared secret shapes every frame identically
/// for everyone — the exact opposite of what enabling PROTEUS asks for.
fn read_secret_file(path: &str, what: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, NodeError> {
    require_private_file(path, what)?;
    let raw = zeroize::Zeroizing::new(std::fs::read(path)?);
    let bytes: &[u8] = &raw;
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.is_empty() {
        return Err(NodeError::Config(format!(
            "'{path}' is empty, so it holds no {what} — write the secret into it, e.g. \
             `(umask 077; printf %s 'YOUR-COMMUNITY-SECRET' > {path})`"
        )));
    }
    Ok(zeroize::Zeroizing::new(bytes.to_vec()))
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
    if let Some(s) = flag(args, "--listen")? {
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
    let paths = fanos_node::setup::Paths::detect()?;

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
    if let Some(r) = flag(args, "--role")? {
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
    for value in flag_all(args, "--bootstrap")? {
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
    match flag(args, "--telemetry")? {
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
    // Owner-only (`0o700`), both of them. These two directories hold `identity.key`, `beacon.params`,
    // `store.snapshot`, `taxis.snapshot` and `admin.sock`; created at the umask they are world-traversable,
    // which is also what leaves the admin socket reachable during its bind→chmod window. The files were
    // already `0o600` (#82's lesson); the directories were not, and one place now decides for all three
    // callers — see `fanos_node::durable::create_private_dir`.
    if let Some(parent) = paths.identity.parent() {
        fanos_node::durable::create_private_dir(parent)?;
    }
    fanos_node::durable::create_private_dir(&paths.data)?;
    let credentials = identity::load_or_generate(Some(&paths.identity))?;
    config.identity_path = Some(paths.identity.clone());
    // An installed node keeps its store (#77). Not asked about: a node that forgets every shard the cell gave
    // it on each restart is spending the erasure code's repair budget on ordinary reboots, and no operator
    // benefits from being offered that.
    config.state_path = Some(paths.data.clone());

    ensure_beacon(&mut config, &paths, assume_yes, has_flag(args, "--private-cell"))?;

    // **After the beacon, not before.** The seat is drawn against the network's genesis seed, and until
    // `ensure_beacon` has run there is no network to draw against — computing it a few lines earlier printed,
    // and then advertised at the end of this wizard, an address on a network this node was not about to join.
    let [x, y, z] = identity::coordinate::<F2>(&credentials, &config.genesis_seed());

    // --- write ---
    let rendered = fanos_node::setup::render_config(&config, &paths.identity);
    write_file(&paths.config, &rendered, false)?;
    eprintln!("\n  wrote {}", paths.config.display());
    eprintln!("  coordinate {x}:{y}:{z}");
    if config.beacon.is_some() {
        eprintln!("  network    {}", config.network_fingerprint());
    }

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
    // The network's name is minted here, from its own entropy — **not** derived from the commitment, and not
    // from `secret` or `rng_seed` either. A name that is any function of the beacon's key material is the
    // coupling #98 removes, and deriving it from the same draw would reintroduce it one step further away.
    let mut name = [0u8; 32];
    getrandom::fill(&mut name).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let params = BeaconParams {
        network_id: fanos_node::NetworkId::new(name),
        commitment,
        threshold: 1,
        share,
        authority: None,
    };
    // Secret: it carries this cell's beacon share.
    write_file(path, params.to_config_string(), true)
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
    let Some(unit_path) = manager.unit_path_here()? else { return Ok(()) };
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
    let Some(unit) = manager.unit_path_here()? else {
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
fn cmd_uninstall(args: &[String]) -> Result<(), NodeError> {
    use fanos_node::setup::ServiceManager;
    let assume_yes = has_flag(args, "--yes");
    let purge = has_flag(args, "--purge");
    let paths = fanos_node::setup::Paths::detect()?;
    let manager = ServiceManager::detect();

    eprintln!("fanos uninstall — removing FANOS from this host\n");
    if let Some(unit) = manager.unit_path_here()?.filter(|u| u.exists()) {
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

/// `fanos status [VERB] [--config FILE] [--data DIR]`: report what this host is set up to be, and whether it is
/// running.
///
/// `VERB` is any control-socket verb (`Request::all()`), defaulting to `health`. It is what makes the rest of
/// that surface reachable: the socket has served `census`, `consensus` and `stations` with no way to ask them
/// short of `socat`.
///
/// Deliberately answerable **without** contacting the node: the first question an operator has is "did my setup
/// take", and a status command that can only answer by connecting cannot distinguish "not configured" from
/// "configured and down" — which are opposite problems.
async fn cmd_status(args: &[String]) -> Result<(), NodeError> {
    // `--config` first, so an operator who names the file is never refused for want of a layout (#312).
    let config_path = match flag(args, "--config")? {
        Some(p) => PathBuf::from(p),
        None => fanos_node::setup::Paths::detect()?.config,
    };

    // Which question to ask the running node. `health` by default — the one an operator asks first — but the
    // control socket serves six verbs and the shipped CLI could reach exactly one of them, so `census`,
    // `consensus` and `stations` were features that required `socat` to invoke. A verb that ships behind a tool
    // nobody has is a verb that does not ship.
    //
    // Validated here rather than round-tripped, so a typo gets the whole list back instead of an unhelpful
    // answer from a node that is working fine.
    let verb = positional(args).unwrap_or("health");
    if fanos_node::admin::Request::parse(verb).is_none() {
        println!("unknown verb `{verb}` — try one of: {}", fanos_node::admin::Request::all());
        return Ok(());
    }

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
    // The first question when two hosts disagree is whether they are even on the same network, and nothing
    // else printed here answers it: coordinates differ between identities *and* between networks.
    println!(
        "network       : {}",
        if config.beacon.is_some() {
            config.network_fingerprint()
        } else {
            "none (no beacon — no epoch clock, no coordinate reshuffle)".to_owned()
        }
    );
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
            // On *this* network: the seat is a function of the identity and the genesis seed both.
            let [x, y, z] = identity::coordinate::<F2>(&credentials, &config.genesis_seed());
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
    // **Whether this node keeps what the cell gave it, and how much (#77).** The size is the fact an operator
    // needs and cannot get anywhere else: "persistence is configured" and "persistence is working" are
    // different claims, and a `store.snapshot` that exists but is 45 bytes says the second one is false.
    println!("store         : {}", store_status(config.state_path.as_deref()));

    // Ask the node itself if it is there. A held port says *something* is running; only the node can say what it
    // sees — how many peers it has, whose claims it verified, which point it actually sits on. Falling back to
    // the port is deliberate rather than lazy: a node built before this socket existed, or one that could not
    // bind it, must still report as running rather than as missing.
    // `data_dir_for`, not `paths.data`: the helper honours `--data` and its own doc says it exists "so
    // `fanos status` finds the socket of a node started by the service unit" — and `fanos status` was the one
    // caller that did not use it. So `fanos node --data X` bound its socket under X while `fanos status
    // --data X` looked under the platform default, and the answer was "running, but not answering its control
    // socket (an older build)" — a sentence that blames the node for the asker's arithmetic. Found by running
    // one against a node whose state was somewhere else.
    let socket = fanos_node::admin::socket_path(&data_dir_for(args)?);
    let live = fanos_node::admin::ask(&socket, verb).await.unwrap_or(None);
    if let Some(body) = live {
        println!("daemon        : running");
        println!("\n--- as the node itself reports ({verb}) ---");
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
///
/// Takes the identity **material** rather than the key pair: `DoubleRatchet::respond` owns the KEM secret as
/// its initial ratchet key and replaces it with a fresh one on the first reply (#282), so each conversation
/// needs its own. The pair is a pure function of the host secret, so re-deriving it per conversation is the
/// same key every time and costs a keygen, not a design.
async fn converse(stream: DuplexStream, identity: &[u8; 32]) {
    let (secret, public) = fanos_pqcrypto::kem::HybridKemSecret::generate(&mut SeedRng::from_seed(identity));
    let mut talk = match fanos_node::angelos_driver::Conversation::respond(stream, secret, &public).await {
        Ok(c) => c,
        Err(e) => {
            info!(error = %e, "angelos handshake refused");
            return;
        }
    };
    loop {
        match talk.recv().await {
            Ok(Some(message)) => {
                // **Dispatch on the declared kind, not on the shape of the bytes.** `as_text` is only a UTF-8
                // attempt, so the previous form printed a reaction, a join or an in-chat payment as if it were
                // a human message whenever its content happened to decode — and dropped everything else as
                // "non-text" without naming it. `as_attachment` was already kind-checked and already exported;
                // nothing here reached for it.
                match message.kind {
                    fanos_angelos::message::MessageKind::Text => {
                        if let Some(text) = message.as_text() {
                            println!("[{}] {text}", message.seq);
                        } else {
                            // Declared text that is not UTF-8 is a peer bug or a probe, and saying so is more
                            // use than printing nothing.
                            info!(seq = message.seq, "text message with invalid UTF-8");
                        }
                    }
                    fanos_angelos::message::MessageKind::Attachment => {
                        if let Some(a) = message.as_attachment() {
                            println!(
                                "[{}] attachment: {} bytes, {} — the object key travels in this message",
                                message.seq, a.size, a.media_type
                            );
                        } else {
                            info!(seq = message.seq, "attachment descriptor did not decode");
                        }
                    }
                    kind => info!(seq = message.seq, ?kind, "message kind this door does not handle yet"),
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
    let host_secret = match flag(rest, "--host-key")? {
        Some(p) => read_seed_file(p, "the messenger's secret seed")?,
        None => {
            return Err(NodeError::Config(
                "fanos message serve requires --host-key <file> — the messenger's secret seed and stable \
                 .fanos identity (generate one with `(umask 077; head -c 32 /dev/urandom > msg.key)`; \
                 the umask is part of the recipe — the default one writes the seed world-readable)"
                    .to_owned(),
            ));
        }
    };
    let epoch = match flag(rest, "--epoch")? {
        Some(s) => Epoch::new(s.parse().map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?),
        None => Epoch::ZERO,
    };
    let beacon = beacon_arg(rest)?;
    let threshold = mix_threshold_arg(rest)?;

    let (service, signer, bundle) = hidden_service_identity(&host_secret);
    let address = Address::from_bundle(&bundle);
    // The messenger's own long-term KEM identity, derived from the same seed under its own label so the
    // transport identity and the end-to-end identity are not the same key doing two jobs.
    let angelos_identity = fanos_primitives::hash_labeled("FANOS-v1/angelos-identity", &host_secret);
    let (_kem_secret, kem_public) =
        fanos_pqcrypto::kem::HybridKemSecret::generate(&mut SeedRng::from_seed(&angelos_identity));

    let config = node_config_from_args(rest)?;
    let mut node = Node::start_on_plane(config).await?;
    if let Err(e) =
        publish_service(&node.client(), &bundle, [0, 0, 0], epoch, 0, b"profile=anonymous").await
    {
        node.shutdown().await;
        return Err(e);
    }

    let handler = move |stream: DuplexStream| async move { converse(stream, &angelos_identity).await };
    let _driver = spawn_rendezvous_host(
        node.client(),
        node.address(),
        HostedService { service, identity: bundle.clone(), signer, host_secret, threshold, vrf_coordinates: true },
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
    let stop = fanos_node::shutdown::stop_requested();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            biased;
            () = &mut stop => break,
            note = node.next_notification() => match note {
                Some(n) => log_notification(&n),
                None => break,
            },
        }
    }
    node.shutdown().await;
    Ok(())
}

/// Print (and optionally persist) a node's self-certifying coordinate.
fn cmd_id(args: &[String]) -> Result<(), NodeError> {
    let path = flag(args, "--identity")?.map(PathBuf::from);
    let credentials = identity::load_or_generate(path.as_deref())?;

    // **Which network?** A coordinate is a function of the identity *and* the network's genesis seed
    // (`docs/design-genesis.md`), so printing one without the network is printing a placement the node will
    // not have — and this command's last line is a bootstrap address, which is coordinate-*pinned*. Read the
    // same configuration the daemon reads, from the same default location, so the two cannot disagree.
    let config_path = match flag(args, "--config")? {
        Some(p) => PathBuf::from(p),
        None => fanos_node::setup::Paths::detect()?.config,
    };
    let config = config_path
        .exists()
        .then(|| std::fs::read_to_string(&config_path).map_err(NodeError::from))
        .transpose()?
        .map(|text| NodeConfig::from_config_str(&text))
        .transpose()?;
    let genesis = config.as_ref().map_or(BeaconSeed::GENESIS, NodeConfig::genesis_seed);

    let [x, y, z] = identity::coordinate::<F2>(&credentials, &genesis);
    println!("coordinate: {x}:{y}:{z}");
    match &path {
        Some(p) => println!("identity file: {}", p.display()),
        None => println!("(ephemeral — pass --identity <path> to persist this coordinate)"),
    }
    match config.as_ref().filter(|c| c.beacon.is_some()) {
        Some(c) => println!("network: {} (from {})", c.network_fingerprint(), config_path.display()),
        None => println!(
            "network: none configured — this is the coordinate on a beacon-less cell only. \
             A network with a beacon seats this identity elsewhere; pass --config <file> \
             (or run `fanos init`) before publishing the address below."
        ),
    }
    println!("bootstrap seed (add host:port): {x}:{y}:{z}@HOST:PORT");
    Ok(())
}

/// `fanos ingress-deal <community> <peer>... [--out DIR] [--threshold T] [--difficulty D] [--line C:C:C,...]`:
/// the **POROS provisioning ceremony** (`docs/design-anonymity-substrate.md` §6).
///
/// Threshold-shards a community's ingress descriptor — the entry peers a censored newcomer bootstraps from —
/// across the `q+1` members of its ingress line, and writes one provisioning file per member. Run it once per
/// community; hand each member its own file and nothing else.
///
/// **Why this exists as a ceremony at all.** Every part of POROS was built and tested and none of it could be
/// reached, because the descriptor has to come from somewhere and nothing produced one: `shard_descriptor` had
/// no caller outside its own tests. A line with no dealing is a line that admits nobody.
///
/// **The binding travels with every share.** A POROS line reconstructs a *plaintext*, so unlike every other
/// threshold secret in the platform it has no AEAD tag to fail on a wrong reconstruction, and Lagrange is
/// linear — one member could otherwise choose the entry peers the whole community bootstraps from. Each file
/// therefore carries the dealing's public binding alongside the secret share, and a host refuses to start
/// without it.
///
/// The community secret is the enumeration-resistance input: a censor holding only the public beacon cannot
/// compute a community's ingress line without it. Pass it as a passphrase; it is hashed into the file.
fn cmd_ingress_deal(args: &[String]) -> Result<(), NodeError> {
    use fanos_field::F2;
    use fanos_geometry::{Point, Triple};
    use fanos_node::config::IngressParams;
    use fanos_node::node::mix_threshold;
    use fanos_node::{IngressDescriptor, shard_descriptor};

    let usage = || {
        NodeError::Config(
            "usage: fanos ingress-deal <community> <coord@host:port>... \
             [--out DIR] [--threshold T] [--difficulty D] [--line C:C:C,...]"
                .to_owned(),
        )
    };
    let community = args.first().filter(|s| !s.starts_with("--")).ok_or_else(usage)?.clone();
    let peers: Vec<Peer> = args
        .iter()
        .skip(1)
        .take_while(|a| !a.starts_with("--"))
        .map(|a| Peer::parse(a))
        .collect::<Result<_, _>>()?;
    if peers.is_empty() {
        return Err(usage());
    }
    let out = flag(args, "--out")?.unwrap_or(".");
    let difficulty: u32 = match flag(args, "--difficulty")? {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --difficulty '{s}'")))?,
        None => DEFAULT_INGRESS_DIFFICULTY,
    };
    // The line: either an explicit roster, or the Fano cell's points 0..q — the same default the rest of the
    // single-operator tooling uses, so a first deployment needs one flag fewer.
    let line: Vec<Triple> = match flag(args, "--line")? {
        Some(s) => s
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(parse_line_coord)
            .collect::<Result<_, _>>()?,
        None => (0..3).map(|i| Point::<F2>::at(i).coords()).collect(),
    };
    // The threshold defaults to the plane's own mix threshold ⌈2(q+1)/3⌉ rather than a chosen number: an
    // ingress line is a line, and the reason a hop's threshold is that value — two corrupt members must not
    // own it however wide the line grows — applies here unchanged.
    let threshold: usize = match flag(args, "--threshold")? {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --threshold '{s}'")))?,
        None => mix_threshold(line.len()),
    };
    if threshold < 2 || threshold > line.len() {
        return Err(NodeError::Config(format!(
            "the ingress threshold {threshold} must be in 2..={} (the line has {} members); a threshold of \
             1 would hand every member the whole descriptor",
            line.len(),
            line.len(),
        )));
    }

    let descriptor = IngressDescriptor { peers };
    // The sharing polynomial is OS entropy: this tool holds the whole descriptor for the moment of dealing,
    // exactly as `beacon-deal` holds the beacon secret, and exists to bootstrap a single-operator community.
    let mut randomness = vec![0u8; descriptor.to_bytes().len() * threshold + 32];
    getrandom::fill(&mut randomness).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let line_size = u8::try_from(line.len())
        .map_err(|_| NodeError::Config("an ingress line cannot exceed 255 members".to_owned()))?;
    let dealt = shard_descriptor(
        &descriptor,
        u8::try_from(threshold).unwrap_or(u8::MAX),
        line_size,
        &randomness,
    )
    .ok_or_else(|| NodeError::Config(format!("cannot deal {threshold}-of-{line_size}")))?;

    let community_bytes = fanos_primitives::hash_labeled("FANOS-v1/poros-community", community.as_bytes());
    for (i, share) in dealt.shares.iter().enumerate() {
        // One KEM seed per member, from OS entropy: it regenerates the secret that OPENS sealed reshare
        // sub-shares when the line rotates, so it must be that member's alone.
        let mut kem_seed = [0u8; 32];
        getrandom::fill(&mut kem_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
        let params = IngressParams {
            community: community_bytes.to_vec(),
            share: share.clone(),
            binding: dealt.binding.clone(),
            line: line.clone(),
            threshold,
            difficulty,
            kem_seed,
        };
        let path = format!("{out}/ingress-{}.poros", i + 1);
        write_dealt(&path, params.to_config_string(), true)?;
    }
    println!(
        "dealt a {threshold}-of-{line_size} POROS ingress line for community '{community}' over {} entry \
         peers; run each member with `fanos node --role ingress --ingress-params ingress-<i>.poros`",
        descriptor.peers.len(),
    );
    println!(
        "each file holds that member's SECRET share and the community secret — hand out one file per member, \
         and no more"
    );
    Ok(())
}

/// Parse a `x:y:z` coordinate from a `--line` roster entry.
fn parse_line_coord(s: &str) -> Result<fanos_geometry::Triple, NodeError> {
    let mut it = s.split(':').map(str::trim);
    let mut next = || -> Result<u32, NodeError> {
        it.next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| NodeError::Config(format!("bad line coordinate '{s}' (want x:y:z)")))
    };
    let (x, y, z) = (next()?, next()?, next()?);
    if it.next().is_some() {
        return Err(NodeError::Config(format!("bad line coordinate '{s}' (want x:y:z)")));
    }
    Ok([x, y, z])
}

/// The admission proof-of-work difficulty a freshly-dealt ingress line demands, in leading zero bits.
///
/// A **policy** constant (`docs/design-constants.md` §2): it prices one admission attempt, and the right price
/// is a deployment's trade between join latency and the rate a censor can enumerate at — no derivation fixes
/// it, because it depends on the hardware the community's newcomers actually have. Matched to the platform's
/// other join price (`--admission-difficulty`) so a first deployment has one number to reason about, and
/// overridable with `--difficulty`.
const DEFAULT_INGRESS_DIFFICULTY: u32 = 12;

/// `fanos beacon-deal <n> <t> [--out DIR]`: deal a `t`-of-`n` threshold-DVRF beacon key from OS entropy and
/// write each anchor's provisioning file (`anchor-<i>.beacon`, `i = 1..=n`) plus a share-less
/// `consumer.beacon` into `DIR` (default `.`). Provision a node with `fanos node --beacon-params
/// anchor-<i>.beacon` so it runs the live epoch clock (audit S1-H2). A single-operator convenience — a
/// trust-minimized deployment runs the networked DKG instead, so no one party ever holds the whole key.
fn cmd_beacon_deal(args: &[String]) -> Result<(), NodeError> {
    let usage = || NodeError::Config("usage: fanos beacon-deal <n> <t> [--out DIR]".to_owned());
    let n: usize = args.first().and_then(|s| s.parse().ok()).ok_or_else(usage)?;
    let t: usize = args.get(1).and_then(|s| s.parse().ok()).ok_or_else(usage)?;
    let out = flag(args, "--out")?.unwrap_or(".");

    // The beacon secret and the polynomial RNG are both drawn from OS entropy — this tool holds the whole key
    // for the moment of dealing (unlike the DKG), so it exists only to bootstrap a single-operator network.
    let mut secret = [0u8; 32];
    let mut rng_seed = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    getrandom::fill(&mut rng_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let (shares, commitment) = deal(&secret, t, n, &mut DeterministicRng::new(&rng_seed))
        .ok_or_else(|| NodeError::Config(format!("cannot deal {t}-of-{n}: need 1 <= t <= n <= 255")))?;

    // The **recovery authority**, without which the dealt beacon can never be reshaped. A beacon with no
    // configured trust root refuses every reshare trigger and every re-genesis, so losing `n − t + 1` anchors
    // freezes its epoch clock permanently — the R-C1 cliff. Every provisioning file therefore carries the
    // authority's VERIFIERS, and each member's secret is written separately for that operator to keep
    // offline: a node holds no authority key and cannot self-issue a threshold change.
    //
    // **One authority key per founder, not one for the ceremony.** The beacon is `t`-of-`n` so that no single
    // party holds it; an authority that can order that key REPLACED must not be weaker, and a single key was.
    let (authority_seeds, authority) = resolve_authority(args, n)?;

    // One name for the whole ceremony, minted from its own entropy: every file this loop writes must carry
    // the SAME name, or the anchors and the consumer would sit on different networks and never agree on a
    // single genesis coordinate. Drawn separately from `secret`/`rng_seed` so the name is not a function of
    // the beacon's key material — that coupling is what #98 removes.
    let mut name = [0u8; 32];
    getrandom::fill(&mut name).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let network_id = fanos_node::NetworkId::new(name);

    for (i, share) in shares.iter().enumerate() {
        let params = BeaconParams {
            network_id,
            commitment: commitment.clone(),
            threshold: t,
            share: Some(share.clone()),
            authority: Some(authority.clone()),
        };
        let path = format!("{out}/anchor-{}.beacon", i + 1);
        write_dealt(&path, params.to_config_string(), true)?;
    }
    let consumer =
        BeaconParams { network_id, commitment, threshold: t, share: None, authority: Some(authority.clone()) };
    let cpath = format!("{out}/consumer.beacon");
    write_dealt(&cpath, consumer.to_config_string(), false)?;
    // The SEEDS, not the derived secrets: `HybridSigSecret::generate` is deterministic in one, so a member
    // regenerates the same authority key whenever one is needed — the convention the rest of the tree uses
    // for secret material (a service member's KEM key is carried the same way). Member `i` signs at INDEX
    // `i - 1`, which is the position its verifier occupies in every `.beacon` file; the order is genesis
    // material and reordering it invalidates every signature.
    for (i, seed) in authority_seeds.iter().enumerate() {
        let apath = format!("{out}/recovery-authority-{}.key", i + 1);
        write_file(Path::new(&apath), fanos_node::config::hex_encode(seed), true)?;
        println!("wrote {apath}  (SECRET SEED for authority member index {i} — mode 0600, keep offline)");
    }
    println!("dealt a {t}-of-{n} beacon; run each anchor with `fanos node --beacon-params anchor-<i>.beacon`");
    if authority_seeds.is_empty() {
        println!(
            "recovery authority: {}-of-{n}, from verifiers you supplied — this dealer never saw an authority \
             secret. Each founder keeps the seed `fanos authority-key` wrote on their own machine.",
            authority.quorum()
        );
    } else {
        println!(
            "recovery authority: {}-of-{n} — hand recovery-authority-<i>.key to founder <i> and keep it OFF \
             the node. No single holder can order a reshare or a re-genesis.",
            authority.quorum()
        );
        println!(
            "  ! this machine generated every authority secret, so for the moment of dealing it held the \
             whole committee. Correct for a private cell; for a public one have each founder run \
             `fanos authority-key` and pass the collected verifiers with --authority-verifiers."
        );
    }
    Ok(())
}

/// The recovery committee this ceremony deals against, and the seeds it had to generate to get it.
///
/// Two paths, and which one an operator takes is the difference between a founding that needs a trusted
/// dealer and one that does not.
///
/// **`--authority-verifiers FILE` is the trust-minimized path, and it is the one a public network takes.**
/// Generating the members here means this machine holds every authority secret for the instant of dealing —
/// the same concentration the beacon shares have, and the residual #74 recorded when the committee landed.
/// With the flag, each founder runs `fanos authority-key` on their OWN machine, keeps the seed, and sends
/// back only the verifier; the dealer assembles the list and never sees a secret. It needs no cryptography
/// that does not already exist — only a ceremony step and this flag. The returned seed vector is then empty,
/// which is the caller's signal that there is nothing to write and nothing to hand over.
///
/// Without it the dealer generates them, which stays correct for a private or test cell and is what the
/// single-operator wizard needs. The difference is stated at the end of the run rather than left for an
/// operator to infer.
fn resolve_authority(
    args: &[String],
    n: usize,
) -> Result<(Vec<[u8; 32]>, fanos_keygen::recovery::RecoveryAuthoritySet), NodeError> {
    let members = if let Some(path) = flag(args, "--authority-verifiers")? {
        let text = std::fs::read_to_string(path)?;
        let members = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                HybridVerifier::decode(&fanos_node::config::hex_decode(l)?)
                    .ok_or_else(|| NodeError::Config(format!("{path}: '{l}' is not a HybridVerifier")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The order is genesis material: a signature names its member by index into this list, so a list one
        // short does not deal a smaller committee — it renames every member after the gap, and every
        // signature they produce would verify against the wrong key.
        if members.len() != n {
            return Err(NodeError::Config(format!(
                "{path} lists {} verifiers but this ceremony deals {n} anchors — the recovery committee is \
                 one key per founder, and its order is genesis material",
                members.len()
            )));
        }
        return Ok((Vec::new(), set_of(members)?));
    } else {
        let mut seeds = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        for _ in 0..n {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
            let (_secret, verifier) = HybridSigSecret::generate(&mut SeedRng::from_seed(&seed));
            seeds.push(seed);
            members.push(verifier);
        }
        (seeds, members)
    };
    Ok((members.0, set_of(members.1)?))
}

/// A committee from its members, refusing the empty one — a 0-member authority has a quorum of 1 and would
/// accept an authorization signed by nobody.
fn set_of(
    members: Vec<HybridVerifier>,
) -> Result<fanos_keygen::recovery::RecoveryAuthoritySet, NodeError> {
    fanos_keygen::recovery::RecoveryAuthoritySet::new(members)
        .ok_or_else(|| NodeError::Config("cannot deal a beacon for n = 0".to_owned()))
}

/// `fanos authority-key [--out FILE]`: generate **one recovery-authority member's** keypair on this
/// operator's own machine, keep the secret seed here, and print the verifier to hand to the dealer.
///
/// The trust-minimized half of the founding ceremony (#74). `fanos beacon-deal` can generate the whole
/// committee itself, and then this machine holds every authority secret for the instant of dealing — the
/// same concentration the beacon shares have, and the reason a public network should not do it that way.
/// With this verb each founder generates locally and sends back only the public half; the dealer assembles
/// them with `--authority-verifiers` and never sees a secret.
///
/// The seed, not the derived key: `HybridSigSecret::generate` is deterministic in it, so the holder
/// regenerates the same authority key whenever one is needed — the convention the rest of the tree uses for
/// `fanos keygen` — run the founding **distributed key generation** with the other founders and write this
/// operator's beacon provisioning file.
///
/// The verb that removes the last trusted dealer. `beacon-deal` is correct for a cell one operator starts —
/// it says so about itself — but for a public network it means one machine briefly holds the whole beacon
/// secret, which is the governance gap `docs/testnet.md` §7 names. Here each founder draws its own secret
/// locally, never transmits it whole, and the group commitment assembles from public data.
///
/// The roster is the `x:y:z@host:port` seed form every other verb already speaks, one per line, INCLUDING
/// this node — a ceremony is defined by its whole participant set and a file that omits its own author
/// describes a different one.
///
/// **The network's name comes from the roster, not from the DKG's output.** Every founder derives it from
/// the same agreed list, so there is nothing to distribute and no founder to trust with it; and it is not a
/// function of the beacon's key material, which is the coupling #98 removed — a name derived from the
/// commitment would make that beacon unretirable.
///
/// The recovery authority is a **separate** step and stays one: a DKG that produces the beacon share does
/// not produce the authority keys. Run `fanos authority-key` per founder and collect the verifiers.
/// Wait for the ceremony to publish a key, or say **which** way it failed.
///
/// Bounded: a ceremony that cannot converge must say so rather than hang an operator's terminal. The ceiling
/// is **derived** from the phases rather than chosen — three of them, doubled, so the handshakes between
/// them have as much room again as the phases themselves. A number picked here would go stale the next time
/// a phase was added, which is exactly what happened when the confirm round joined and the old literal still
/// said it "covers both phase deadlines".
///
/// Three outcomes, and they are deliberately not one: a published key, a ceremony that **assembled and
/// disagreed**, and a ceremony that never assembled. The middle one is the reason this is not a bare
/// timeout — every founder was reachable and what differs is what they ran with, which is a different
/// remedy from "check that everyone is running".
async fn await_ceremony(
    mut notes: tokio::sync::broadcast::Receiver<Notification>,
    threshold: usize,
) -> Result<(), NodeError> {
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(KEYGEN_PHASE_MS * u64::from(KEYGEN_PHASES) * 2);
    loop {
        match tokio::time::timeout_at(deadline, notes.recv()).await {
            Ok(Ok(Notification::DkgComplete(_))) => return Ok(()),
            Ok(Ok(Notification::DkgDiverged { agreed, heard })) => {
                return Err(NodeError::Config(format!(
                    "the ceremony finished WITHOUT agreement: {agreed} of the {threshold} participants \
                     needed hold this node's joint key ({heard} peers answered at all). No file was \
                     written, and that is the point — a share over a key the cell does not hold produces \
                     beacon partials that never combine, so the cell's epoch clock would never turn and \
                     the cause would be this ceremony. Check that every founder passed the IDENTICAL \
                     --roster file and --threshold, then re-run; if they did, a frame was lost and \
                     re-running is the whole remedy."
                )));
            }
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return Err(NodeError::Config("the node shut down mid-ceremony".to_owned()));
            }
            Err(_) => {
                return Err(NodeError::Config(
                    "the ceremony did not complete: check that every founder in the roster is running \
                     `fanos keygen` with the identical file, and that their addresses are reachable"
                        .to_owned(),
                ));
            }
        }
    }
}

/// The roster of a ceremony, in **file order** — which is also the order its network name is derived from,
/// so every founder must hold the identical file. Blank lines and `#` comments are allowed; anything else
/// must parse, and the line number travels with the error because a roster is hand-assembled by several
/// people.
///
/// Its own function because "what counts as a roster line" is a rule about the *file* rather than about the
/// ceremony — and because `cmd_keygen` has a line budget that the confirm round pushed it over.
fn parse_ceremony_roster(text: &str) -> Result<Vec<Peer>, NodeError> {
    let mut roster: Vec<Peer> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        roster.push(Peer::parse(line).map_err(|e| NodeError::Config(format!("roster line {}: {e}", n + 1)))?);
    }
    Ok(roster)
}

/// One DKG phase, in milliseconds — sharing, complaint and confirm each take this long.
///
/// **Wall-clock, not the simulator's 1.5 s**, and the reason is a safety one rather than politeness: these
/// phases run over real TLS handshakes between machines an operator does not control, `DkgNode` advances on
/// its timers rather than on completeness, and `QUAL` is whatever each participant has qualified when its
/// own deadline fires. A phase that closes before an honest share arrives is indistinguishable from a
/// Byzantine dealer — and the disagreement it causes is now *reported* (the confirm round) rather than
/// written to disk, but a deadline generous enough not to cause it is still the cheaper answer.
///
/// It is a chosen number, and `docs/testnet.md` §7 says so: the phase must outlast the slowest honest
/// founder's connect-and-deliver, which is a property of the operators' network rather than of this code.
const KEYGEN_PHASE_MS: u64 = 30_000;

/// How many deadline-bounded phases a ceremony runs — sharing, complaint, confirm.
///
/// Named so the overall ceiling below is arithmetic over the phases rather than a second number that has to
/// be remembered when one is added. It was: the ceiling read 180 s "covering both phase deadlines" while
/// there were three.
const KEYGEN_PHASES: u32 = 3;

/// [`KEYGEN_PHASE_MS`] as the engine's span type.
const KEYGEN_PHASE: fanos_runtime::Duration = fanos_runtime::Duration::from_millis(KEYGEN_PHASE_MS);

/// `fanos keygen --roster FILE --threshold T --out FILE` — run the founding DKG ceremony and write this
/// founder's beacon parameters.
///
/// Every founder runs this against the **same** roster file and threshold, and each ends holding its own
/// share of one group key: the beacon the whole network's epochs are drawn from. The roster is read as a
/// *set* — the canonical name is computed from its lines sorted — so two founders whose files differ only in
/// order are provisioning the same network rather than two that will never agree.
///
/// The identity is this founder's long-term one (`--identity`, or generated), which is the same identity
/// `fanos node` runs on: the coordinate the ceremony seats it at is the coordinate it holds afterwards.
///
/// **This doc is here because its absence is indistinguishable from an orphaned one.** Inserting a function
/// between a doc and its owner re-points that doc at the newcomer silently and leaves the owner bare, which
/// is what `every_function_in_the_node_binary_is_documented` watches for (#318) — and this function was one
/// of the sites it had been reporting.
async fn cmd_keygen(args: &[String]) -> Result<(), NodeError> {
    use fanos_keygen::DkgNode;
    use fanos_node::keygen::DkgCeremony;

    let roster_path = flag(args, "--roster")?
        .ok_or_else(|| NodeError::Config("usage: fanos keygen --roster FILE --threshold T --out FILE".to_owned()))?;
    let out = flag(args, "--out")?
        .ok_or_else(|| NodeError::Config("fanos keygen needs --out FILE (where to write this founder's beacon params)".to_owned()))?;
    let threshold: usize = flag(args, "--threshold")?
        .ok_or_else(|| NodeError::Config("fanos keygen needs --threshold T".to_owned()))?
        .parse()
        .map_err(|_| NodeError::Config("bad --threshold".to_owned()))?;

    let roster = parse_ceremony_roster(&std::fs::read_to_string(roster_path)?)?;
    if roster.len() < threshold || threshold == 0 {
        return Err(NodeError::Config(format!(
            "a {threshold}-of-{} ceremony is not expressible: need 1 <= t <= participants",
            roster.len()
        )));
    }

    // This founder's own long-term identity — the same one `fanos node` runs on, so the coordinate the DKG
    // seats it at is the coordinate it will hold afterwards.
    let identity_path = flag(args, "--identity")?.map(PathBuf::from);
    let creds = identity::load_or_generate(identity_path.as_deref())?;

    // The name every founder computes identically from the agreed roster. Sorted, so a file whose lines were
    // reordered is still the same network — the ceremony is a set, not a sequence.
    let mut canonical: Vec<String> = roster.iter().map(ToString::to_string).collect();
    canonical.sort();
    let network_id = fanos_node::NetworkId::from_seed(canonical.join("\n").as_bytes());

    // Fresh per-instance entropy: the participant's own secret (never transmitted whole) and the session
    // nonce that binds its frames to THIS ceremony, so nothing from a previous run replays into it.
    let mut secret = [0u8; 32];
    let mut session = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    getrandom::fill(&mut session).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;

    let directory = fanos_quic::Directory::new();
    fanos_node::config::seed_directory(&roster, &directory)?;
    let listen: SocketAddr = match flag(args, "--listen")? {
        Some(a) => a.parse().map_err(|_| NodeError::Config(format!("bad --listen '{a}'")))?,
        None => "0.0.0.0:0".parse().map_err(|_| NodeError::Identity)?,
    };

    let outcome = DkgCeremony::<F2>::slot();
    let slot = outcome.clone();
    let handle = fanos_quic::spawn_self_certifying_persistent_over::<F2>(
        listen.into(),
        &creds,
        move |coord| {
            // Wall-clock deadlines, not the simulator's logical ones: these phases run over real TLS
            // handshakes on machines an operator does not control, and a complaint round that closes before
            // an honest share arrives is indistinguishable from a Byzantine dealer.
            let node = DkgNode::<F2>::new(coord, threshold, secret, session)
                .with_deadlines(KEYGEN_PHASE, KEYGEN_PHASE)
                // Bind the ceremony to the network the roster names, so two founders holding rosters that
                // differ disagree **here**, by name, rather than founding two networks that each look
                // complete. The engine cannot see a roster file; this is the one fact it needs from it.
                .with_context(*network_id.as_bytes());
            Box::new(DkgCeremony::new(node, slot))
        },
        directory,
        // A keygen ceremony node runs the DKG engine and nothing else — no overlay, no mixnet router, no
        // hidden-service path — so `CORE` is not a conservative placeholder here, it is the whole truth
        // (#284). Written out rather than derived from a `RoleSet` this node does not have.
        fanos_wire::capability::Capabilities::CORE | fanos_wire::capability::Capabilities::PQ_ONLY,
        None,
    )
    .map_err(|_| NodeError::Identity)?;

    println!("ceremony: {}-of-{} at coordinate {:?}", threshold, roster.len(), handle.address());
    println!("network:  {}", fanos_node::config::hex_encode(network_id.as_bytes()));
    if !handle.command(fanos_node::Command::StartHeartbeat) {
        return Err(NodeError::Config("the engine is not accepting commands".to_owned()));
    }

    await_ceremony(handle.client().subscribe(), threshold).await?;

    let Some(result) = outcome.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone() else {
        return Err(NodeError::Config("the ceremony completed without an outcome".to_owned()));
    };
    let params = BeaconParams {
        network_id,
        commitment: result.commitment,
        threshold,
        share: Some(result.share),
        // Separate step, deliberately: a DKG that produces the beacon share does not produce the recovery
        // authority's keys, and a file that silently carried none would look provisioned while leaving the
        // cell unable to ever reshape its beacon.
        authority: None,
    };
    write_file(Path::new(&out), params.to_config_string(), true)?;
    let (agreed, heard) = result.agreement;
    println!("joint key agreed by {agreed} participants ({heard} answered); wrote {out}");
    println!(
        "next: run `fanos authority-key` on each founder and re-issue these files with \
         `--authority-verifiers`, or the cell can never reshape its beacon"
    );
    Ok(())
}

/// secret material.
/// `fanos beacon-reshare` — mint an **authenticated proactive-reshare trigger** and put it on the cell.
///
/// **The affordance a stalled beacon had none of.** When anchors fall below threshold the epoch clock stops,
/// and with it the coordinate reshuffle, the onion ratchet and every per-epoch key rotation. A node *detects*
/// that (`RECOVERY_PATIENCE` periods with no advance) and then escalates to a `tracing::warn!`, because the
/// authority secret is deliberately not held by any node — audit §2.1, and correctly so. What was missing is
/// the other half: a way for whoever *does* hold it to act. `BeaconNode::reshare_trigger` built the frame and
/// had three callers, every one of them in a test file (audit R-C1).
///
/// **The authority key is read, never transmitted.** The frame is signed here and only the signature travels;
/// the socket carries a frame every recipient verifies for itself, so reaching the verb grants nothing the
/// frame does not already carry.
///
/// **Sent to any member, not to an anchor.** It goes out as `Command::Broadcast`, so the cell floods it —
/// which is also why an operator does not have to know which nodes are anchors to repair one.
async fn cmd_beacon_reshare(args: &[String]) -> Result<(), NodeError> {
    let usage = || {
        NodeError::Config(
            "usage: fanos beacon-reshare --authority KEYFILE --generation N --threshold T \
             --contributors 1,2,.. --holders 1,2,.. [--data DIR]"
                .to_owned(),
        )
    };
    let key_path = flag(args, "--authority")?.ok_or_else(usage)?;
    let generation: u64 = flag(args, "--generation")?.and_then(|s| s.parse().ok()).ok_or_else(usage)?;
    let new_threshold: usize = flag(args, "--threshold")?.and_then(|s| s.parse().ok()).ok_or_else(usage)?;
    let indices = |name: &str| -> Result<Vec<u8>, NodeError> {
        let raw = flag(args, name)?.ok_or_else(usage)?;
        raw.split(',').map(|p| p.trim().parse::<u8>().map_err(|_| usage())).collect()
    };
    let contributors = indices("--contributors")?;
    let holders = indices("--holders")?;

    let seed_hex = std::fs::read_to_string(key_path)
        .map_err(|e| NodeError::Config(format!("authority key '{key_path}': {e}")))?;
    let seed = fanos_node::config::hex_decode(seed_hex.trim())?;
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| NodeError::Config("authority key must be 32 bytes of hex".to_owned()))?;
    let secret = HybridSigSecret::generate(&mut SeedRng::from_seed(&seed)).0;

    let frame = fanos_keygen::BeaconNode::<F2>::reshare_trigger(
        &[(0, &secret)],
        generation,
        new_threshold,
        &contributors,
        &holders,
    );
    let socket = fanos_node::admin::socket_path(&data_dir_for(args)?);
    let line = format!("reshare {}", fanos_node::config::hex_encode(&frame));
    if let Ok(Some(answer)) = fanos_node::admin::ask(&socket, &line).await {
        print!("{answer}");
    } else {
        // The frame is minted and the node is not there to take it. Printed rather than discarded, because a
        // trigger an operator can re-send by hand is worth more than a clean error.
        println!("no running node at {} — the signed trigger, to send by hand:", socket.display());
        println!("{line}");
    }
    Ok(())
}

/// `fanos authority-key` — mint a **recovery-authority** signing key for one founder.
///
/// The secret this writes is what `fanos beacon-reshare` signs a trigger with, and the verifier printed
/// beside it is what every node is configured with. Split that way on purpose: a cell that cannot name its
/// authority can never reshape its beacon, and a cell whose nodes hold the *secret* has an authority in name
/// only. One file stays on the founder's machine; the other is public and goes into every node's beacon
/// parameters.
fn cmd_authority_key(args: &[String]) -> Result<(), NodeError> {
    let out = flag(args, "--out")?.unwrap_or("recovery-authority.key");
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let (_secret, verifier) = HybridSigSecret::generate(&mut SeedRng::from_seed(&seed));
    // Secret: mode 0600 at creation, like the identity key — a key created world-readable and chmod-ed a
    // microsecond later WAS world-readable, and on a shared host that window is the whole exposure.
    write_file(Path::new(out), fanos_node::config::hex_encode(&seed), true)?;
    println!("wrote {out}  (SECRET SEED — keep it offline and never on a node)");
    println!();
    println!("Send this line to whoever runs `fanos beacon-deal`; it is public:");
    println!("{}", fanos_node::config::hex_encode(&verifier.encode()));
    println!();
    println!(
        "They collect one line per founder, in an agreed ORDER, into a file and pass it as \
         `--authority-verifiers`. The order is genesis material: a signature names its member by index."
    );
    Ok(())
}

/// One line describing this node's durable store, for `fanos status`.
///
/// Three states an operator has to be able to tell apart: not configured (keeps nothing, by choice), configured
/// but never written (a first boot, or a persister that is failing), and holding N bytes as of a moment. Only
/// the third is the working system, and the first two used to be indistinguishable from it.
fn store_status(state_dir: Option<&Path>) -> String {
    let Some(dir) = state_dir else {
        return "not kept (no `state` directory configured — this node forgets its shards on restart)"
            .to_owned();
    };
    let path = dir.join(fanos_node::durable::STORE_FILE);
    match std::fs::metadata(&path) {
        Ok(m) => {
            let age = m
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map_or_else(String::new, |d| format!(", written {}s ago", d.as_secs()));
            format!("{} ({} bytes{age})", path.display(), m.len())
        }
        Err(_) => format!("{} (not yet written — a first boot, or the persister is failing)", path.display()),
    }
}

/// `fanos service-deal <coord>... [--out DIR] [--threshold T]`: assemble a **threshold-hosted service line**
/// and write one provisioning file per member.
///
/// **Every other role had a dealer and this one had instructions**, which is why it is here. A service line's
/// members hold *independent* keys rather than shares of one split secret, so assembling one is simpler than
/// the beacon or ingress ceremony — and it was therefore left entirely manual: each of the `M` operators ran
/// `openssl rand -hex 32`, reported a coordinate, and hand-copied the same roster and threshold into their own
/// file.
///
/// The failure mode that makes this worth a tool is not the seeds, it is the **roster**. A line whose members
/// disagree by one coordinate cannot reconstruct, and it says nothing when it fails to: a client's intro is
/// sealed to a set of members, and a member that thinks the line is different simply contributes a share for
/// the wrong position. Dealing all `M` files from one list makes the disagreement impossible by construction,
/// which is the whole of what a ceremony buys — and the same reason `beacon-deal` writes every anchor file
/// rather than telling seven operators to agree on a commitment.
///
/// The seeds are still independent, one per member and never shared, so this holds no secret after it exits:
/// unlike the beacon, there is no split secret for a dealer to know. Each file is written mode 0600 (#82).
fn cmd_service_deal(args: &[String]) -> Result<(), NodeError> {
    let usage = || {
        NodeError::Config(
            "usage: fanos service-deal <x:y:z>... [--out DIR] [--threshold T]".to_owned(),
        )
    };
    let line: Vec<fanos_geometry::Triple> = args
        .iter()
        .take_while(|a| !a.starts_with("--"))
        .map(|a| parse_line_coord(a))
        .collect::<Result<_, _>>()?;
    if line.is_empty() {
        return Err(usage());
    }
    let out = flag(args, "--out")?.unwrap_or(".");
    // The default is the plane's own mix threshold ⌈2(q+1)/3⌉ rather than a chosen number, for the reason
    // that value exists: two corrupt members must not own a line however wide it grows. A `q+1`-member line
    // therefore gets the same threshold every other line on this plane gets.
    let threshold: usize = match flag(args, "--threshold")? {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --threshold '{s}'")))?,
        None => fanos_node::node::mix_threshold(line.len()),
    };
    if threshold < 2 || threshold > line.len() {
        return Err(NodeError::Config(format!(
            "the service threshold {threshold} must be in 2..={} (the line has {} members); a threshold of \
             1 would let any single member serve the whole service alone, which is the property a threshold \
             line exists to remove",
            line.len(),
            line.len(),
        )));
    }

    // **Every member's seed is drawn first, because the identity is dealt to their PUBLIC keys.** The
    // per-member seed regenerates that member's hybrid-KEM keypair (`composition.rs` does exactly this at
    // startup), so this tool can derive each public and seal that member its own slot — the same direction
    // `ingress-deal` uses. Drawing them inside the write loop, as this did, made the publics unavailable
    // while the shares were being sealed.
    let mut seeds: Vec<[u8; 32]> = Vec::with_capacity(line.len());
    let mut member_publics: Vec<HybridKemPublic> = Vec::with_capacity(line.len());
    for _ in &line {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
        let (_secret, public) = fanos_pqcrypto::HybridKemSecret::generate(&mut SeedRng::from_seed(&seed));
        seeds.push(seed);
        member_publics.push(public);
    }

    // **The service's signing identity, minted here and dealt away — §12.3 half (a).**
    //
    // What is sharded is the 32-byte SEED, not the key: `HybridSigSecret` has no `to_bytes`, deliberately,
    // because this tree carries secrets as seeds and regenerates them in memory (audit #124). A threshold of
    // members reconstructs the seed and re-derives the identical keypair — which is also why
    // `recover_service_key` returns bytes rather than a key type.
    //
    // The whole seed exists only inside this function: it is `Zeroizing`, it is never written to any file,
    // and after the shares are sealed nothing anywhere holds it. That is the property the ceremony buys —
    // a hidden service whose signing identity was, until now, derivable from one file on one host.
    let identity_seed = {
        let mut s = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(s.as_mut()).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
        s
    };
    let (_signer, verifier) = HybridSigSecret::generate(&mut SeedRng::from_seed(identity_seed.as_ref()));

    // The sharing polynomial and the per-member KEM encapsulation randomness, both from OS entropy. Sized
    // as `ingress-deal` sizes its own: `len × threshold + 32` covers `threshold − 1` coefficients of the
    // secret's width with slack, and `shard_service_key` refuses if it is short rather than silently
    // reusing bytes.
    let mut key_randomness = vec![0u8; identity_seed.len() * threshold + 32];
    getrandom::fill(&mut key_randomness).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let mut kem_seed = [0u8; 32];
    getrandom::fill(&mut kem_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let public_refs: Vec<&HybridKemPublic> = member_publics.iter().collect();
    let sealed = fanos_calypso::hosting::deal_service_key(
        identity_seed.as_ref(),
        u8::try_from(threshold).unwrap_or(u8::MAX),
        &public_refs,
        &key_randomness,
        &kem_seed,
    )
    .map_err(|e| NodeError::Config(format!("cannot deal the service identity: {e}")))?;
    drop(identity_seed); // Zeroized here; from this point the identity exists only as `threshold`-of-n slots.

    // **The count is checked before the loop, not assumed inside it.** Zipping three vectors silently
    // writes `min(len)` files, and indexing with `.cloned()` silently writes a file with no custody — both
    // turn "the dealer produced fewer slots than there are members" into a line that starts and cannot
    // reconstruct. It cannot happen (`deal_service_key` returns one slot per key it was handed), and that
    // is precisely why it must be stated: an invariant nothing checks is the one that changes quietly.
    if sealed.len() != line.len() || seeds.len() != line.len() {
        return Err(NodeError::Config(format!(
            "the ceremony produced {} slots and {} seeds for a {}-member line — refusing to write files \
             whose members would hold no identity",
            sealed.len(),
            seeds.len(),
            line.len(),
        )));
    }
    for (i, ((coord, seed), slot)) in line.iter().zip(&seeds).zip(&sealed).enumerate() {
        let params = ServiceParams {
            seed: *seed,
            line: line.clone(),
            threshold,
            identity_share: Some(slot.clone()),
        };
        let [x, y, z] = *coord;
        let path = format!("{out}/service-{}.conf", i + 1);
        write_dealt(&path, params.to_config_string(), true)?;
        println!("  ↳ for the member at {x}:{y}:{z}");
    }

    // The verifier is PUBLIC and is what a client checks a registration against — the only half of the
    // identity that survives this process. Written to its own file precisely because it is not secret: an
    // operator who cannot tell which of these files may be copied will copy the wrong one.
    let pub_path = format!("{out}/service-identity.pub");
    write_dealt(&pub_path, format!("verifier = {}\n", fanos_node::config::hex_encode(&verifier.encode())), false)?;

    println!(
        "dealt a {threshold}-of-{} service line; run each member with `fanos node --service service-<i>.conf` \
         (the flag implies the role, and `service = PATH` is a config key)",
        line.len()
    );
    println!(
        "every file carries the SAME roster and threshold — which is the point: a line whose members \
         disagree by one coordinate cannot reconstruct, and says nothing when it fails to."
    );
    println!(
        "the service's SIGNING IDENTITY was minted here and is gone: it exists only as the {threshold}-of-{} \
         `identity_share` slots in those files, and no copy was written anywhere (§12.3 half (a)). \
         Fewer than {threshold} seized members cannot reconstruct it — which is the guarantee, and it is \
         void if you keep these files together.",
        line.len()
    );
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
    use fanos_pqcrypto::rng::SeedRng;
    use fanos_taxis::params::CellParams;

    let out = flag(args, "--out")?.unwrap_or(".");
    let epoch = match flag(args, "--epoch")? {
        Some(s) => Epoch::new(s.parse().map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?),
        None => Epoch::ZERO,
    };
    let beacon = beacon_arg(args)?;
    let supply: u64 = match flag(args, "--supply")? {
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
        deal_validators(cell, epoch, beacon, &genesis_alloc, fanos_taxis::Economics::Unincentivised, &mut SeedRng::from_seed(&rng_seed));

    for c in &configs {
        let path = format!("{out}/validator-{}.taxis", c.me);
        write_dealt(&path, ValidatorConfig::to_bytes(c), true)?;
    }
    // The public chain info a client needs to build, seal, and submit a transaction (`fanos pay`).
    let info = ChainInfo { cell, epoch, beacon, keyper: registry };
    let ipath = format!("{out}/chain-info.taxis");
    write_file(Path::new(&ipath), info.to_bytes(), false)?;
    println!("wrote {ipath} (public chain info for `fanos pay`)");
    let fpath = format!("{out}/founder.key");
    write_file(Path::new(&fpath), founder_seed, true)?;
    println!("wrote {fpath}  (the genesis founder's SECRET seed — mode 0600, keep it safe)");
    println!(
        "dealt a {}-validator TAXIS cell (epoch {}); genesis-funded a founder with {supply} (key in founder.key)\n\
         run each validator with `fanos validator --config validator-<i>.taxis`",
        cell.n(),
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
    use fanos_node::ChainInfo;
    use fanos_pqcrypto::HybridSigSecret;
    use fanos_pqcrypto::rng::SeedRng;
    use fanos_taxis::Transaction;
    use fanos_taxis::keyper::seal_to_keyper_committee;
    use fanos_taxis::wire::tx_to_frame;

    init_tracing();

    // The public chain info (keyper registry + epoch + beacon + cell) — everything a client needs but a key.
    let info_path = flag(args, "--chain-info")?
        .ok_or_else(|| NodeError::Config("fanos pay requires --chain-info chain-info.taxis".to_owned()))?;
    let info_bytes = std::fs::read(info_path)?;
    let info = ChainInfo::from_bytes(&info_bytes)
        .ok_or_else(|| provision_error("chain-info", ChainInfo::format_of(&info_bytes)))?;

    // The sender's 32-byte key seed (e.g. `founder.key`) → its signing keypair + account id.
    let key_path = flag(args, "--key")?
        .ok_or_else(|| NodeError::Config("fanos pay requires --key <32-byte seed file> (e.g. founder.key)".to_owned()))?;
    let seed: [u8; 32] = std::fs::read(key_path)?
        .as_slice()
        .try_into()
        .map_err(|_| NodeError::Config("the --key file must be a 32-byte seed".to_owned()))?;
    let (signer, from_key) = HybridSigSecret::generate(&mut SeedRng::from_seed(&seed));
    let from = account_id(&from_key);

    let to_hex = flag(args, "--to")?
        .ok_or_else(|| NodeError::Config("fanos pay requires --to <32-byte hex account id>".to_owned()))?;
    let to: [u8; 32] = decode_hex(to_hex)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| NodeError::Config("--to must be a 32-byte (64 hex char) account id".to_owned()))?;
    let amount: u64 = flag(args, "--amount")?
        .ok_or_else(|| NodeError::Config("fanos pay requires --amount N".to_owned()))?
        .parse()
        .map_err(|_| NodeError::Config("bad --amount".to_owned()))?;
    let nonce: u64 = match flag(args, "--nonce")? {
        Some(s) => s.parse().map_err(|_| NodeError::Config("bad --nonce".to_owned()))?,
        None => 0,
    };

    // Build + sign the transparent transfer, wrap it as a DROMOS transaction, and seal it to the epoch keyper
    // line with fresh OS entropy (the anti-MEV property: the order is fixed on the sealed ciphertext).
    let signed = SignedTransfer::sign(Transfer { from, to, amount, nonce }, &signer, from_key);
    let tx = Transaction::new(HybridLedger::transparent_payload(&signed));
    let mut rng_seed = [0u8; 32];
    getrandom::fill(&mut rng_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let sealed = seal_to_keyper_committee(&info.keyper, &tx, info.epoch, info.cell, &rng_seed)
        .map_err(|e| NodeError::Config(format!("could not seal the transaction: {e:?}")))?;

    // Join the overlay (bootstrap to the validators via --bootstrap) and submit to validator 0, which ingests
    // the sealed transaction and gossips it to the whole cell's mempool.
    let config = node_config_from_args(args)?;
    let node = Node::start::<F2>(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // let bootstrap connections establish
    let submitted = submit_tx_frame(&node, args, info.epoch, &info.beacon, &tx_to_frame(&sealed)).await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // let the frame flush + propagate
    node.shutdown().await;
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

/// `fanos term`: compose an **ERGON term** — one atomic, optionally gated, optionally computed transaction over
/// the ledger's primitive effects — and submit it exactly the way `fanos pay` submits a transfer. **The door**
/// `docs/design-ergon.md` §11 names as the residual after step 3 wired `TAG_ERGON` into the ledger's own dispatch
/// (`HybridLedger::apply_with_verdict`'s `apply_term`, and `access_of`): before this verb, an ERGON term was
/// built, signed, and executed only inside this workspace's own tests — nothing running as a node ever produced
/// one. This does.
///
/// ```text
/// fanos term --chain-info chain-info.taxis --key founder.key [--nonce M] [--dry-run]
///            [--to <hex>[,<hex>...] --amount AMT[,AMT...]]      AMT = N | N% | all
///            [--register-name NAME:TARGETHEX:DURATION[:FEE]]...
///            [--require-name NAME=OWNERHEX]...
///            [--require-min ACCTHEX:N]...
///            [--bootstrap <coord>@host:port,…]
/// ```
///
/// The term is `Gate(guards, Seq[registrations…, payments…])`, degenerating to the bare effect when only one leg
/// and no guard is given. What each piece buys, and why no fixed tag can express it:
///
/// * **Atomic legs.** Every `--register-name` and every `--to`/`--amount` pair is one leg of a `Seq`: all apply
///   or none do. Registrations run first so a later `all` payment sweeps what the fees LEFT — "register a name
///   and forward the whole remainder" is one term, not a race between two transactions.
/// * **Computed amounts** (`N%`, `all`). The amount is an expression evaluated at execution against the state as
///   the previous legs left it — `all` is `Load(balance(sender))`, `N%` is `balance·N/100` — so a sweep cannot
///   miss or overdraw by racing a concurrent debit. The expression's reads join the derived footprint, so DROMOS
///   schedules on exactly what the amount reads.
/// * **Guards.** `--require-name` gates the whole term on *live on-chain ownership* of a name
///   (`PRED_NAME_OWNED`, the TOCTOU close for paying a name's off-chain resolution), `--require-min` on a
///   balance floor. Several guards conjoin. A declined guard is the identity: the transaction applies, nothing
///   moves, the nonce advances.
///
/// Everything downstream of building the payload is identical to `fanos pay`: the same chain-info/key parsing,
/// the same anti-MEV seal to the epoch keyper line (no validator sees the term before its order is fixed), the
/// same join-the-overlay-and-emit-to-a-validator submission. The chain re-derives everything it relies on —
/// canonical decode, `well_typed`, the footprint, confinement — so this builder is a convenience, never an
/// authority; `--dry-run` prints the same admission-facing numbers (depth, size, cost, footprint width, effect
/// kinds) the chain will compute, and stops.
#[cfg(feature = "validator")]
#[allow(clippy::too_many_lines)] // one verb, one linear pipeline: parse → build → check → seal → submit
async fn cmd_term(args: &[String]) -> Result<(), NodeError> {
    use fanos_dromos::HybridLedger;
    use fanos_dromos::ergon::exec::compare;
    use fanos_dromos::ergon::{Checked, Cmp, Expr, Limits, Predicate, Term, cost};
    use fanos_dromos::ergon_host::{
        PRED_NAME_OWNED, SignedTerm, balance_key, name_key, name_register_term, payment_term, transfer_term_with,
    };
    use fanos_dromos::naming::name_digest;
    use fanos_dromos::token::account_id;
    use fanos_dromos::price;
    use fanos_node::ChainInfo;
    use fanos_pqcrypto::HybridSigSecret;
    use fanos_pqcrypto::rng::SeedRng;
    use fanos_taxis::Transaction;
    use fanos_taxis::keyper::seal_to_keyper_committee;
    use fanos_taxis::wire::tx_to_frame;

    init_tracing();

    let key_path = flag(args, "--key")?.ok_or_else(|| {
        NodeError::Config("fanos term requires --key <32-byte seed file> (e.g. founder.key)".to_owned())
    })?;
    let seed: [u8; 32] = std::fs::read(key_path)?
        .as_slice()
        .try_into()
        .map_err(|_| NodeError::Config("the --key file must be a 32-byte seed".to_owned()))?;
    let (signer, from_key) = HybridSigSecret::generate(&mut SeedRng::from_seed(&seed));
    let from = account_id(&from_key);

    let account32 = |what: &str, s: &str| -> Result<[u8; 32], NodeError> {
        decode_hex(s)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| NodeError::Config(format!("{what} '{s}' is not a 32-byte (64 hex char) account id")))
    };

    // Registration legs, first in the `Seq` (see the doc comment): NAME:TARGETHEX:DURATION[:FEE], with the fee
    // defaulting to the registry's own floor `price(name, duration)` — computed here as a convenience, checked by
    // the chain as the rule.
    let mut registrations: Vec<Term> = Vec::new();
    let mut register_display: Vec<String> = Vec::new();
    for spec in flag_all(args, "--register-name")? {
        let parts: Vec<&str> = spec.split(':').collect();
        let (name, target_hex, duration_s, fee_s) = match parts.as_slice() {
            [n, t, d] => (*n, *t, *d, None),
            [n, t, d, f] => (*n, *t, *d, Some(*f)),
            _ => {
                return Err(NodeError::Config(format!(
                    "bad --register-name '{spec}' (expected NAME:TARGETHEX:DURATION[:FEE])"
                )));
            }
        };
        let target = decode_hex(target_hex)
            .ok_or_else(|| NodeError::Config(format!("--register-name target '{target_hex}' is not hex")))?;
        let duration: u64 =
            duration_s.parse().map_err(|_| NodeError::Config(format!("bad duration in --register-name '{spec}'")))?;
        let fee: u64 = match fee_s {
            Some(f) => f.parse().map_err(|_| NodeError::Config(format!("bad fee in --register-name '{spec}'")))?,
            None => price(name.as_bytes(), duration),
        };
        registrations.push(name_register_term(name.as_bytes(), &target, duration, fee, from));
        register_display.push(format!("register '{name}' for {duration} blocks (fee {fee})"));
    }

    // Payment legs: `--to`/`--amount` are parallel comma lists — the `ports = 80,443` convention — zipped into
    // pairs immediately so a length mismatch is a usage error here, not a silently truncated payment. An amount is
    // a constant, `N%` of the sender's balance, or `all` of it — the computed forms are expressions evaluated at
    // execution, against the state as the previous legs left it.
    let to_arg = flag(args, "--to")?;
    let amount_arg = flag(args, "--amount")?;
    if to_arg.is_some() != amount_arg.is_some() {
        return Err(NodeError::Config("--to and --amount must be given together".to_owned()));
    }
    let mut fixed_legs: Vec<([u8; 32], u64)> = Vec::new(); // the all-constant case, for `payment_term`
    let mut pay_terms: Vec<Term> = Vec::new();
    let mut pay_display: Vec<String> = Vec::new();
    let mut all_fixed = true;
    if let (Some(to_arg), Some(amount_arg)) = (to_arg, amount_arg) {
        let to_list: Vec<&str> = to_arg.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        let amount_list: Vec<&str> = amount_arg.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        if to_list.len() != amount_list.len() {
            return Err(NodeError::Config(format!(
                "--to has {} recipient(s) but --amount has {} — they must pair up",
                to_list.len(),
                amount_list.len()
            )));
        }
        for (&t, &a) in to_list.iter().zip(amount_list.iter()) {
            let to = account32("--to entry", t)?;
            let amount: Expr = if a == "all" {
                all_fixed = false;
                Expr::Load(balance_key(from))
            } else if let Some(pct) = a.strip_suffix('%') {
                let pct: u64 = pct.parse().map_err(|_| NodeError::Config(format!("bad --amount entry '{a}'")))?;
                all_fixed = false;
                Expr::bin(
                    fanos_dromos::ergon::BinOp::Div,
                    Expr::bin(
                        fanos_dromos::ergon::BinOp::Mul,
                        Expr::Load(balance_key(from)),
                        Expr::int(u128::from(pct)),
                    ),
                    Expr::int(100),
                )
            } else {
                let n: u64 = a.parse().map_err(|_| NodeError::Config(format!("bad --amount entry '{a}'")))?;
                fixed_legs.push((to, n));
                Expr::int(u128::from(n))
            };
            pay_terms.push(transfer_term_with(from, to, amount));
            pay_display.push(format!("pay {a} -> {t}"));
        }
    }

    // The body: registrations, then payments, one atomic `Seq` — or the bare leg when there is only one. The
    // all-constant pure-payment case goes through `payment_term`, the canonical builder for it; the general case
    // composes the same legs by hand.
    let body: Term = if registrations.is_empty() && all_fixed && !fixed_legs.is_empty() {
        payment_term(from, &fixed_legs)
            .unwrap_or_else(|| unreachable!("fixed_legs is non-empty, so payment_term returns Some"))
    } else {
        let mut legs = registrations;
        legs.append(&mut pay_terms);
        match legs.len() {
            0 => {
                return Err(NodeError::Config(
                    "fanos term needs at least one leg: --to/--amount and/or --register-name".to_owned(),
                ));
            }
            1 => legs.remove(0),
            _ => Term::Seq(legs),
        }
    };

    // Guards, conjoined: live name ownership (the TOCTOU close for paying a name's off-chain resolution) and
    // balance floors. The author imposes them on their own term — a declined guard is the identity, not a fault.
    let mut guards: Vec<Predicate> = Vec::new();
    let mut guard_display: Vec<String> = Vec::new();
    for spec in flag_all(args, "--require-name")? {
        let (name, owner_hex) = spec.split_once('=').ok_or_else(|| {
            NodeError::Config(format!("bad --require-name '{spec}' (expected NAME=OWNERHEX)"))
        })?;
        let owner = account32("--require-name owner", owner_hex)?;
        guards.push(Predicate::host_with(
            PRED_NAME_OWNED,
            vec![name_key(name_digest(name.as_bytes()))],
            vec![Expr::bytes32(owner)],
        ));
        guard_display.push(format!("require name '{name}' owned by {owner_hex}"));
    }
    for spec in flag_all(args, "--require-min")? {
        let (acct_hex, min_s) = spec.split_once(':').ok_or_else(|| {
            NodeError::Config(format!("bad --require-min '{spec}' (expected ACCTHEX:N)"))
        })?;
        let acct = account32("--require-min account", acct_hex)?;
        let min: u64 = min_s.parse().map_err(|_| NodeError::Config(format!("bad --require-min '{spec}'")))?;
        guards.push(compare(Cmp::Ge, Expr::Load(balance_key(acct)), Expr::int(u128::from(min))));
        guard_display.push(format!("require balance({acct_hex}) >= {min}"));
    }
    let term: Term = match guards.len() {
        0 => body,
        1 => Term::Gate(guards.remove(0), Box::new(body)),
        _ => Term::Gate(Predicate::And(guards), Box::new(body)),
    };

    // The client-side admission preview: the SAME check and the SAME price the chain computes at its port
    // (`well_typed` + `cost`, `docs/design-ergon.md` §4/§6), run before anything is signed — a term the chain
    // would refuse should be refused here, for free.
    let checked = Checked::new(term, &Limits::unbounded())
        .map_err(|e| NodeError::Config(format!("the term is not well-typed: {e:?}")))?;
    let fp = checked.term().footprint();
    println!(
        "term: depth {}, {} node(s), cost {} unit(s), footprint {} key(s) ({} read, {} written), effects {:?}",
        checked.term().depth(),
        checked.term().size(),
        cost(checked.term()),
        fp.width(),
        fp.reads().len(),
        fp.writes().len(),
        checked.term().effect_kinds(),
    );
    for line in register_display.iter().chain(&pay_display).chain(&guard_display) {
        println!("  {line}");
    }
    if has_flag(args, "--dry-run") {
        return Ok(());
    }

    // Sign, seal, submit — byte-for-byte the `fanos pay` path from here on; the seal operates on the
    // transaction's bytes and does not care which tag is inside them.
    let info_path = flag(args, "--chain-info")?
        .ok_or_else(|| NodeError::Config("fanos term requires --chain-info chain-info.taxis".to_owned()))?;
    let info_bytes = std::fs::read(info_path)?;
    let info = ChainInfo::from_bytes(&info_bytes)
        .ok_or_else(|| provision_error("chain-info", ChainInfo::format_of(&info_bytes)))?;
    let nonce: u64 = match flag(args, "--nonce")? {
        Some(s) => s.parse().map_err(|_| NodeError::Config("bad --nonce".to_owned()))?,
        None => 0,
    };
    let envelope = SignedTerm::sign(checked.encode(), nonce, &signer, from_key);
    let tx = Transaction::new(HybridLedger::term_payload(&envelope));
    let mut rng_seed = [0u8; 32];
    getrandom::fill(&mut rng_seed).map_err(|e| NodeError::Config(format!("OS entropy: {e}")))?;
    let sealed = seal_to_keyper_committee(&info.keyper, &tx, info.epoch, info.cell, &rng_seed)
        .map_err(|e| NodeError::Config(format!("could not seal the transaction: {e:?}")))?;

    let config = node_config_from_args(args)?;
    let node = Node::start::<F2>(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // let bootstrap connections establish
    let submitted = submit_tx_frame(&node, args, info.epoch, &info.beacon, &tx_to_frame(&sealed)).await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // let the frame flush + propagate
    node.shutdown().await;
    if submitted {
        println!("submitted: ERGON term (nonce {nonce}), sealed to the epoch {} keyper line", info.epoch.get());
        Ok(())
    } else {
        Err(NodeError::Config("could not emit the transaction (is the client connected to a validator?)".to_owned()))
    }
}

/// Without the `validator` feature the binary carries no ledger, so `fanos term` cannot build a term.
#[cfg(not(feature = "validator"))]
#[allow(clippy::unused_async)]
async fn cmd_term(_args: &[String]) -> Result<(), NodeError> {
    Err(NodeError::Config(
        "this build lacks validator support — rebuild with `cargo build -p fanos-node --features validator`"
            .to_owned(),
    ))
}

/// `fanos validator --config validator-<i>.taxis --listen ADDR --bootstrap <coord>@host:port,…`: run a TAXIS
/// blockchain validator — the caller that closes the "`spawn_taxis` has no prod caller" production gap. It
/// seats a node at its consensus point `Point::at(me)` (a production fixed-coordinate node — `spawn_pinned`'s
/// grind, so the coordinate is *chosen*, not VRF-accepted, which the Fano-cell BFT structure requires), wires
/// Publish this validator's verifying key at its seat in the cell committee directory (#167).
///
/// **The consumer is a parent cell, not this one.** A validator's own committee arrives by configuration, so
/// nothing here is discovering what this node already knows; what has no configuration is a *child's*
/// committee, and `ChildRegistry::attest_available` resolves one before it verifies anything and refuses an
/// unregistered child outright. Without this a parent can address its children, authenticate their health and
/// sample their data, and still not check one signature on their certificates.
///
/// Taken from `params.verifiers[me]` rather than re-derived from the seed: that is this node's own entry in
/// the committee it was configured with, so the key it publishes and the key its peers check its votes
/// against cannot drift. A validator whose index names no entry publishes nothing, which is the same refusal
/// `consensus.seat_index_mismatch` records one layer down.
/// ⛔ **Gated, because its only caller is.** `cmd_validator` is `#[cfg(feature = "validator")]` and this was not, so a
/// default-feature build compiled a function nothing calls — `dead_code`, which CI promotes to an error with
/// `-D warnings`. It reddened `clippy · test · verify` **and** `reproducible release build` for every push between
/// `44ae999` and here, while a local `cargo test` printed it as a warning and moved on. That gap between "warning
/// locally, error in CI" is the whole reason `gate.sh` exists, and this is the shape of what slips through it.
#[cfg(feature = "validator")]
fn publish_this_seats_key<S>(node: &fanos_quic::NodeHandle, params: &fanos_node::TaxisParams<S>) {
    if let Some(mine) = params.verifiers.get(usize::from(params.me)).cloned() {
        // The handle is deliberately dropped: this publisher lives as long as the process, exactly like the
        // capability and load publishers the role loop spawns, and there is nothing to await it for.
        drop(fanos_node::crosscell_dir::spawn_seat_key_publisher::<F2>(
            node.client(),
            mine,
            node.coordinate_prover(),
        ));
    }
}

/// the other validators' coordinates→sockets from `--bootstrap`, and runs the sans-I/O consensus engine over
/// the DROMOS hybrid ledger (`spawn_taxis`). Provision a cell with `fanos taxis-deal`.
#[cfg(feature = "validator")]
async fn cmd_validator(args: &[String]) -> Result<(), NodeError> {
    use fanos_dromos::HybridLedger;
    use fanos_geometry::Point;
    use fanos_node::{ValidatorConfig, spawn_taxis};
    use fanos_quic::{Directory, credentials_for_point, spawn_self_certifying_persistent_on};
    use fanos_runtime::Config as OverlayConfig;

    init_tracing();
    let config_path = flag(args, "--config")?
        .ok_or_else(|| NodeError::Config("fanos validator requires --config validator-<i>.taxis".to_owned()))?;
    let config_bytes = std::fs::read(config_path)?;
    let config = ValidatorConfig::from_bytes(&config_bytes)
        .ok_or_else(|| provision_error("validator config", ValidatorConfig::format_of(&config_bytes)))?;
    let me = config.me;
    let listen: SocketAddr = match flag(args, "--listen")? {
        Some(s) => s.parse().map_err(|_| NodeError::Config(format!("bad --listen '{s}'")))?,
        None => SocketAddr::from(([0, 0, 0, 0], 0)),
    };

    // The other validators' coordinates → sockets (this node reaches its peers by coordinate). Same
    // `<coord>@host:port` form as `fanos node --bootstrap`, but here every peer is a fixed cell seat —
    // which is why the duplicate-seat refusal matters more here than anywhere: a repeated coordinate does
    // not lose a bootstrap hint, it loses a **cell member**, and the validator then runs against a quorum
    // one seat smaller than the one its own config describes.
    //
    // Collected first, then seeded, because the check is on the whole list: two `--bootstrap` flags may each
    // be well-formed and contradict each other, and a per-flag check could not see that (#241).
    let mut peers: Vec<Peer> = Vec::new();
    for value in flag_all(args, "--bootstrap")? {
        for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            peers.push(Peer::parse(part)?);
        }
    }
    let directory = Directory::new();
    fanos_node::config::seed_directory(&peers, &directory)?;

    // Seat the node at Point::at(me) (grind an identity that hits it) and bind the consensus listen socket.
    let target = Point::<F2>::at(usize::from(me));
    let creds = credentials_for_point::<F2>(target, fanos_quic::DEFAULT_GRIND_LIMIT)
        .ok_or_else(|| NodeError::Config(format!("could not seat a node at validator point {me}")))?;
    let what = fanos_node::composition::CellComposition::bare(OverlayConfig::default());
    let desc_identity = creds.descriptor_identity();
    let mut node = spawn_self_certifying_persistent_on::<F2>(
        listen,
        &creds,
        // Through `compose_engine`, the one assembly function — not a bare `OverlayNode::new`. A validator
        // runs no cell role today, but "no roles" must be SAID rather than achieved by skipping the composer:
        // a layer added to `compose_engine` has to reach this binary on the same commit, which is the whole
        // invariant `composition.rs` exists to hold and which this call site silently broke (#168).
        move |coord| {
            // The §80 descriptor too: a validator announces its membership like any node, and a cell that
            // verifies descriptors must be able to verify this one. Signed here for the point it is being
            // seated at, which for a validator is fixed rather than VRF-drawn.
            let desc = fanos_node::composition::sign_descriptor::<F2>(&desc_identity, coord);
            fanos_node::composition::compose_engine::<F2>(coord, &what, Some(desc))
        },
        directory,
        None,
    )
    .await
    .map_err(|e| NodeError::Config(format!("could not start the validator node: {e:?}")))?;

    // Run the consensus engine over the DROMOS hybrid ledger. The handle owns the driver tasks; keep it alive.
    // The validator keeps its certified executed state here, so a whole-cell restart can re-seed from any
    // single survivor's disk (#57). `--data` names it, exactly as it names the store's.
    let params = config
        .to_taxis_params(Some(data_dir_for(args)?))
        .ok_or_else(|| NodeError::Config("the validator config carries a malformed verifier".to_owned()))?;
    // **This validator's verifying key, in its cell's committee directory** (#167). Its own committee comes
    // from configuration, so this publishes nothing this cell needs — it publishes what a *parent* cell
    // cannot configure: `ChildRegistry::attest_available` resolves a child's committee before it verifies
    // anything and refuses an unregistered child outright, so without this a parent can address its children,
    // authenticate their health and sample their data, and still not check one signature.
    //
    // Taken from `params` rather than re-derived: `verifiers[me]` is this node's own entry in the committee it
    // was configured with, so the key it publishes and the key its peers check its votes against cannot drift.
    publish_this_seats_key(&node, &params);
    let handle = spawn_taxis::<F2, HybridLedger>(node.client(), params);
    let mut events = handle.subscribe();

    let [x, y, z] = node.address();
    eprintln!(
        "fanos validator {me} up — seat {x}:{y}:{z}, listening on {listen}\n  running TAXIS consensus over \
         the DROMOS hybrid ledger (epoch {})",
        config.epoch.get(),
    );
    info!(validator = me, coord = ?node.address(), %listen, "fanos validator up");

    // Serve until Ctrl-C, logging consensus progress, draining the node's notifications, and — the point of the
    // `consensus` verb — answering an operator who wants to know why this validator sits where it does.
    let (admin_socket, mut admin_rx) = control_socket(args);
    let stop = fanos_node::shutdown::stop_requested();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            biased;
            () = &mut stop => {
                info!("shutdown signal received");
                break;
            }
            Some((req, reply)) = admin_rx.recv() => {
                if matches!(req, fanos_node::admin::Request::Consensus) {
                    // **Bounded, not spawned.** A probe is one round trip to the driver task, so `census`'s
                    // spawn-and-continue would be overkill — but awaiting it unbounded would hang this loop on
                    // precisely the wedged driver an operator is asking about, taking `shutdown` down with it.
                    // A timeout turns "the engine is not answering" into an answer, which is the one this verb
                    // exists to give.
                    let body = match tokio::time::timeout(PROBE_TIMEOUT, handle.probe()).await {
                        // The WHOLE `DriverProbe`, not just its `consensus` field: `LAGGED` and `sampling` are
                        // what make an operator's reading falsifiable. Stalled with `lagged > 0` is a transport
                        // question; stalled with `lagged == 0` received everything the cell sent and is a
                        // consensus one. Dropping them — as the first draft of this verb did — leaves exactly the
                        // unfalsifiable explanation the type's own doc warns against.
                        Ok(Some(p)) => format!("{p}\n"),
                        Ok(None) => "consensus: the driver task has ended\n".to_owned(),
                        Err(_) => format!("consensus: the driver did not answer within {PROBE_TIMEOUT:?}\n"),
                    };
                    let _ = reply.send(body);
                    continue;
                }
                if answer_control(&req, reply, &node, NO_CHAIN) == Control::Stop {
                    break;
                }
            }
            ev = events.recv() => match ev {
                Ok(e) => info!(?e, "taxis event"),
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => info!(missed = n, "taxis events lagged"),
            },
            note = node.next_notification() => match note {
                Some(n) => log_notification(&n),
                None => break,
            },
        }
    }
    node.shutdown();
    remove_control_socket(admin_socket.as_ref());
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
    let epoch = match flag(args, "--epoch")? {
        Some(s) => Epoch::new(
            s.parse::<u64>()
                .map_err(|_| NodeError::Config(format!("bad --epoch '{s}'")))?,
        ),
        None => Epoch::ZERO,
    };
    let min_pow = match flag(args, "--min-pow")? {
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| NodeError::Config(format!("bad --min-pow '{s}'")))?,
        None => 0,
    };
    let mut bootstrap = Vec::new();
    for value in flag_all(args, "--bootstrap")? {
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
    node.shutdown().await;
    Ok(())
}

/// Log one engine notification at the level its cause deserves.
///
/// The thin wrapper; [`log_notification_against`] holds the decision so it can be tested against a stated
/// configuration rather than against whatever the process happens to hold.
fn log_notification(note: &Notification) {
    log_notification_against(note, None);
}

/// Log an [`Escalation`] — the four ways a cell says it needs something only a human can supply.
///
/// Split out of [`log_notification_against`] because it is a **different vocabulary**, not a longer list:
/// `Notification` says what happened, `Escalation` says why the cell cannot fix it by itself, and the two
/// grow for unrelated reasons. The mechanical trigger was clippy's 105/100 when the fourth arm landed, but
/// the seam was already visible — the three original arms sat in *two separate places* in that match, split
/// by the history of #204's catch-all removal rather than by anything a reader could see.
fn log_escalation(esc: &Escalation) {
    match esc {
        Escalation::Faults(mask) => {
            info!(nodes = format!("{mask:#09b}"), "escalated unrecoverable nodes to the parent cell");
        }
        Escalation::CoherenceCollapse => {
            warn!("behavioural coherence collapsed (Phi <= 1) — the cell needs re-provisioning, not a reroute");
        }

        // Version skew, and the one escalation that names WHO sent WHAT — the actionable content of a
        // rollout. It read as "engine event" before, which is the least useful possible rendering of it.
        Escalation::UnsupportedCritical { type_code, from } => warn!(
            type_code,
            ?from,
            "a peer sent a critical frame type this build does not implement — the cell is running mixed \
             versions and this peer is ahead"
        ),

        // The other half of "this node cannot take part in fixing the epoch", and the only one an operator
        // can fix alone. `warn` is the top of this file's scale (it uses no `error!` anywhere) and is where
        // `CoherenceCollapse` sits for the same reason: nothing recovers it without a human.
        //
        // It repeats every epoch on purpose. The mismatch is a **level**, not an event — it was true when
        // the files were written and stays true until one is replaced — and re-emitting is how a level stays
        // visible on an event channel. An operator who joins mid-run must not have to have been watching.
        Escalation::BeaconShareMismatch => warn!(
            "this node's beacon share does not verify against its group commitment, so it is contributing \
             NOTHING to the cell's epoch clock — the two files are from different dealings; re-provision \
             the share from the DKG that produced this commitment"
        ),
    }
}

/// Log a notification, judging the epoch floor against `configured` when the caller knows it.
///
/// The comparison is the whole point of the floor. A cell measures the shortest epoch period it can absorb;
/// on its own that is a number, and next to the configured period it is a verdict — and below the floor the
/// cost is not churn but accumulation, since a cell reshuffled faster than it reintegrates never reaches a
/// steady state at all.
fn log_notification_against(note: &Notification, configured: Option<Duration>) {
    match note {
        // Folded into the one match rather than an early `if let … return`. That shape left a dead
        // `EpochFloor` arm below whose empty body clippy could not distinguish from the deliberately-quiet
        // ones — and the distinction between "handled elsewhere" and "chosen not to surface" is precisely
        // what this function now exists to record.
        Notification::EpochFloor { millis } => match (millis, configured) {
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
        },
        Notification::Delivered { from, payload } => {
            info!(?from, bytes = payload.len(), "payload delivered");
        }
        Notification::PeerDown(p) => info!(peer = ?p, "peer down"),
        Notification::MemberJoined { coord, .. } => info!(?coord, "member joined"),
        Notification::EpochAdvanced(e) => info!(epoch = e.get(), "epoch advanced"),
        Notification::Rerouted { around, via } => info!(?around, ?via, "rerouted (self-heal)"),
        Notification::Repaired(p) => info!(node = ?p, "shard repaired"),
        Notification::Quarantined(p) => info!(node = ?p, "member quarantined"),
        Notification::Escalated(esc) => log_escalation(esc),
        Notification::Decoupled => info!("cascade pre-empted (decoupled)"),

        // --- Everything below replaced one `other => info!(event = ?other, "engine event")` arm. ---
        //
        // That arm was not silence — every variant was logged — but it flattened all of them to one level,
        // one message and a `Debug` dump: `DataLost` (permanent loss of stored content) came out at `info`,
        // in the same shape as `Stored`, which is per-operation routine. An operator filtering at `warn`
        // never saw it, and one reading `info` saw it buried. Structured fields were lost too, so nothing a
        // log aggregator can index or alert on survived.
        //
        // The catch-all is also why it accumulated: a new variant compiled, logged *something*, and looked
        // handled. Being exhaustive makes "at what level, and with which fields?" a question the compiler
        // asks when a variant is added. Several arms below are deliberately quiet — the point is not to
        // print more, it is that staying quiet is now a decision on the record.

        // Permanent loss. `warn`, not `info`: the shard is gone and no repair will bring it back.
        Notification::DataLost { key, epoch } => warn!(
            key = %fanos_node::config::hex_encode(key),
            epoch = epoch.get(),
            "stored content is permanently lost — below the erasure threshold with no surviving replica"
        ),

        // This node's coordinate changed. Every address an operator recorded for it is now stale, which is
        // an action, not a status line.
        Notification::Reseated { old, new } => {
            warn!(?old, ?new, "this node moved coordinate — recorded addresses for it are stale");
        }

        // Being refused entry — and the four outcomes are split by whether anything will change on its own
        // (#199). Two are dead ends and get `warn!` because they need a person; the two that resolve
        // themselves get `info!`, because an operator woken for a node that is already fixing itself learns
        // to ignore the channel.
        Notification::AdmissionRefused { outcome } => match outcome {
            AdmissionOutcome::Repaid { bits } => {
                info!(bits, "a peer refused this node's admission; re-minted the proof at its price");
            }
            AdmissionOutcome::AlreadySufficient { paid, asked } => info!(
                paid,
                asked,
                "a peer refused this node's admission while it already pays at least the price asked — the \
                 refusal is for some other reason, or that peer misreports its price"
            ),
            AdmissionOutcome::AboveCeiling { asked, ceiling } => warn!(
                asked,
                ceiling,
                "a peer demands more admission work than this node will ever solve inline; NOTHING was \
                 spent and this node will not join through it until the ceiling is raised or the price drops"
            ),
            AdmissionOutcome::NoGuidance => warn!(
                "a peer refused this node's admission and named no price, so there is nothing to solve for \
                 — an older peer, or one whose policy is not a difficulty"
            ),
        },

        // The positive confirmation an operator starting a hidden service is waiting for. Without it,
        // success and silent failure look identical at the console.
        Notification::HostRegistered { service_tag } => info!(
            service_tag = %fanos_node::config::hex_encode(service_tag),
            "hidden service registered at its meeting points"
        ),

        Notification::PeerMoved { old, new } => info!(?old, ?new, "a peer moved coordinate"),
        // The coordinate is what did NOT change — that is why this is not `PeerMoved`: a descendant keeps its
        // point and is reached through an ancestor. A rising depth means the plane is oversubscribed and the
        // overflow is nesting rather than doubling up on points, which is the design working. `AddressProposed`
        // is one step of a three-message exchange, so it goes to debug and the adoption is what an operator sees.
        Notification::PeerAddressed { coord, path } => info!(?coord, depth = path.len(), "a peer took a sub-cell address"),
        // Debug rather than info: one per handshake, so on a large cell at churn this is the highest-rate
        // structural event there is. What an operator acts on is its *absence* beside a live connection,
        // which the `overlay.first_heard` station answers without a log line per peer.
        Notification::PeerHandshaken { coord, .. } => {
            tracing::debug!(?coord, "a peer proved its coordinate and the engine was told");
        }
        Notification::AddressProposed { path } => tracing::debug!(depth = path.len(), "an overlay address was named for this node"),
        Notification::Grey(p) => info!(node = ?p, "peer greylisted"),
        Notification::Bound => info!("cell bound (homeostat)"),
        Notification::Verdict(v) => info!(verdict = ?v, "coherence verdict"),
        Notification::Liveness { epoch, degraded, responsive, alive } => {
            info!(epoch = epoch.get(), degraded, responsive, alive, "cell liveness");
        }
        Notification::Rebalance { loads } => info!(?loads, "role rebalance"),
        Notification::BeaconReady { epoch, .. } => info!(epoch = epoch.get(), "beacon ready"),
        Notification::DkgComplete(commitment) => info!(
            commitment = %fanos_node::config::hex_encode(commitment),
            "distributed key generation complete"
        ),

        // **A ceremony that finished and did not agree**, which is a person's problem and not a status
        // line: the key this node holds is real, verifiable and useless, because fewer than a threshold of
        // participants hold the same one. `warn!` rather than `info!` for the reason the admission arm one
        // screen down splits on — nothing will change on its own, and the remedy (identical roster and
        // threshold on every founder, then re-run) is an action.
        Notification::DkgDiverged { agreed, heard } => warn!(
            agreed,
            heard,
            "distributed key generation finished WITHOUT agreement — no key was published; check that every \
             founder passed the identical --roster file and --threshold, then re-run"
        ),
        Notification::RendezvousLine(l) => info!(line = ?l, "rendezvous line selected"),
        Notification::Availability { key, available } => info!(
            key = %fanos_node::config::hex_encode(key),
            available,
            "availability sample"
        ),

        // Deliberately not surfaced: per-operation, and at a rate that would drown everything above.
        // `Snapshot`, `Observed` and `DataPath` are answers to a request the caller is already awaiting
        // (`await_data_path`, `await_observation`), so logging them here would duplicate that path.
        Notification::App { .. }
        | Notification::Stored(_)
        | Notification::Retrieved { .. }
        | Notification::LoadReport { .. }
        | Notification::Snapshot(_)
        | Notification::Observed(_)
        | Notification::DataPath { .. } => {}
    }
}

/// Discover a clearnet exit from the live cell exit directory for `epoch` — the best-effort roster the
/// cell advertises through the overlay store (each exit republishes per epoch). Picks one at random, so a
/// proxy restart spreads load across the available exits. `None` if none is currently published (clearnet
/// targets are then refused).
async fn discover_exit(node: &Node, epoch: Epoch) -> Option<([u32; 3], HybridKemPublic)> {
    // The seed the directory's records are bound against: the live beacon once one is adopted, else this
    // network's genesis seed. A deployed node always proves coordinates, so a record that is not bound to
    // the point it sits at is not an exit — it is someone else writing at that point.
    let beacon = node
        .live_beacon()
        .map_or_else(|| node.client().genesis(), |(_, seed)| BeaconSeed::new(seed));
    let mut exits = build_plane_exit_directory::<F2>(&node.client(), epoch, Some(beacon)).await;
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
    let Some(path) = flag(args, "--exit-via")? else {
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

/// Install the `tracing` subscriber, once per process.
///
/// `try_init` rather than `init`: every verb calls this, and a second call must not abort a running node
/// over its logging. The default filter is `info` when `RUST_LOG` says nothing — the one environment
/// variable this binary consults indirectly, and deliberately, because it configures observability and
/// nothing else (#311).
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// The value following the first occurrence of `name`, or a refusal naming what went wrong (#313).
///
/// **A missing value used to become a value.** `args.get(i + 1)` takes whatever is there, so
/// `fanos host --host-key --forward 127.0.0.1:80` bound the *string* `--forward` as the path to the
/// service's secret seed. What the operator then saw was a complaint about a file called `--forward`, three
/// steps away from the typo — and `--forward` itself still parsed, because `flag` searches by name rather
/// than by position. The refusal arrived late and about the wrong thing.
///
/// **The rule is read off this tool's own grammar, not chosen.** Every flag here is spelled `--name`, so a
/// leading `--` is the binary's own marker for "this is a flag, not a value"; an argument carrying it is not
/// a value. Nothing this CLI takes can legitimately begin that way — the placeholders are addresses, paths,
/// counts, hex digests, role lists and profile names — and a path that does can still be written `./--name`.
///
/// **And the vocabulary of "which flags take a value" needs no list**, which is the part worth keeping: it is
/// the set of names passed to *this function*. Booleans go through [`has_flag`] and are unaffected. A
/// hand-kept table of valued flags — derivable from the help text, tempting for exactly that reason — would
/// be a second place to forget one; the call graph cannot drift from itself.
///
/// # Errors
///
/// [`NodeError::Config`] when `name` is present but the next argument is another flag, or there is no next
/// argument at all. Absent is not an error: it is `Ok(None)`, and the caller decides whether it had to be
/// there.
fn flag<'a>(args: &'a [String], name: &str) -> Result<Option<&'a str>, NodeError> {
    let Some(i) = args.iter().position(|a| a == name) else { return Ok(None) };
    value_after(args, name, i).map(Some)
}

/// The argument after position `i`, refused if it is missing or is itself a flag.
///
/// Shared by [`flag`] and [`flag_all`] so the two cannot disagree about what a value is — the repeatable
/// form had the identical defect, and fixing one of them would have left the class half closed.
fn value_after<'a>(args: &'a [String], name: &str, i: usize) -> Result<&'a str, NodeError> {
    let Some(next) = args.get(i + 1) else {
        return Err(NodeError::Config(format!(
            "`{name}` needs a value and is the last argument — nothing followed it"
        )));
    };
    if next.starts_with("--") {
        return Err(NodeError::Config(format!(
            "`{name}` needs a value, and the next argument is `{next}`, which is a flag name. Taking it as \
             the value is how a missing value used to become one, with the refusal arriving later and about \
             something else. If the value really does begin with two dashes, write it as a path that does \
             not — `./{next}`"
        )));
    }
    Ok(next.as_str())
}

/// The first **positional** argument: one that neither starts with `-` nor is a flag's value.
///
/// The second half is what a bare `!a.starts_with('-')` scan misses, and it does not fail loudly — [`flag`]
/// takes the *next* argument as its value, so `status --config /etc/fanos.conf` offers that path as a
/// positional and a command reading one gets a file path where it expected a verb. Written the naive way and
/// caught by running it.
fn positional(args: &[String]) -> Option<&str> {
    args.iter()
        .enumerate()
        .find(|&(i, a)| {
            !a.starts_with('-')
                && !i.checked_sub(1).and_then(|p| args.get(p)).is_some_and(|p| p.starts_with('-'))
        })
        .map(|(_, a)| a.as_str())
}

/// The values following every occurrence of `name` (repeatable flags).
///
/// # Errors
///
/// As [`flag`], for the first occurrence that is missing its value — and per occurrence rather than for the
/// set, because `--bootstrap A --bootstrap --listen …` must name *which* one was left empty.
fn flag_all<'a>(args: &'a [String], name: &str) -> Result<Vec<&'a str>, NodeError> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == name {
            out.push(value_after(args, name, i)?);
        }
    }
    Ok(out)
}

/// Whether `name` appears at all — the boolean flags, which take no value.
///
/// The counterpart to [`flag`], and the reason that one needs no list of which flags are valued: the two
/// call graphs partition the vocabulary between them (#313).
fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// The whole `fanos help` listing — the first half, which is the verbs an operator meets on day one.
fn help_text() -> String {
    let mut s = String::from(
        "fanos — the FANOS node\n\
         \n\
         USAGE:\n\
         \n\
           GETTING STARTED (one command on a fresh host)\n\
           fanos init  [--yes] [--force] [--no-service] [--role relay,storage,…] [--listen ADDR] \\\n\
                       [--bootstrap x:y:z@host:port,…] [--telemetry EPSILON]\n\
                       (detect this OS, pick a free port, generate an identity, write the config,\n\
                        install a service and start it — `--yes` takes every default, for provisioning)\n\
           fanos status [VERB]              — what this host is set up as, and whether it is running\n\
           \x20                                 VERB asks a running node directly: health (default), roles,\n\
           \x20                                 coherence (is the cell healthy), stations (where work is\n\
           \x20                                 stopping), census, consensus\n\
           fanos start                      — start the installed service\n\
           fanos stop                       — stop it\n\
           fanos restart                    — stop and start it (after editing the config)\n\
           fanos uninstall [--purge] [--yes]\n\
                       (remove the service; --purge also deletes config, identity and state — the\n\
                        coordinate is derived from the identity, so a purged node returns as a stranger)\n\
         ",
    );
    s.push_str(&help_advanced());
    s
}

/// The rest of the help: the verbs an operator reaches for after the first day.
///
/// Split from [`print_help`] because it is one string and it grew past what one function may hold — the
/// boundary is where the text itself already put one. Split again into [`help_reference`] for the same
/// reason, at the same kind of boundary: this half is the *verb listing* (what to type), and everything
/// after `fanos help` is *reference* (what the files and profiles mean).
fn help_advanced() -> String {
    let mut s = String::from(
        "ADVANCED:\n\
         \x20 fanos node  [--config FILE] [--listen ADDR] [--identity PATH] [--data DIR] \\\n\
         \x20             [--bootstrap x:y:z@host:port,...] \\\n\
         \x20             [--role relay,storage,service,exit] [--service FILE] [--exit FILE] \\\n\
         \x20             [--no-heartbeat] [--proteus-secret-file FILE] [--proteus-morph MORPH] \\\n\
         \x20             [--proteus-environment ENV] [--mix-delay-ms N] [--cover-interval-ms N] \\\n\
         \x20             [--plane-order 2|4|7|31] [--beacon-params FILE] [--ingress-params FILE]\n\
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
         \x20 fanos id    [--identity PATH] [--config FILE]\n\
         \x20             (the coordinate depends on the NETWORK too: the config names the beacon it is\n\
         \x20              drawn against. Without one it prints the beacon-less coordinate and says so)\n\
         \x20 fanos resolve NAME.fanos [--epoch N] [--min-pow BITS] [--bootstrap ...]\n\
         \x20 fanos beacon-deal N T [--out DIR] [--authority-verifiers FILE]\n\
         \x20             (deal a T-of-N epoch-clock beacon; writes *.beacon files. Without the flag this\n\
         \x20              machine also generates the recovery committee, holding every authority secret for\n\
         \x20              the moment of dealing — fine for a private cell. For a public one, each founder\n\
         \x20              runs `fanos authority-key` and you pass their collected verifiers here)\n\
         \x20 fanos beacon-reshare --authority KEYFILE --generation N --threshold T \\\n\
         \x20                      --contributors 1,2,.. --holders 1,2,.. [--data DIR]\n\
         \x20             (repair a beacon whose anchors fell below threshold: signs a proactive-reshare\n\
         \x20              trigger with the recovery-authority key and hands it to the local node, which\n\
         \x20              floods it to the cell. Send it to ANY member — anchors learn it from the flood.\n\
         \x20              With no node running it prints the signed line instead, to send by hand)\n\
         \x20 fanos keygen --roster FILE --threshold T --out FILE [--identity PATH] [--listen ADDR]\n\
         \x20             (run the founding DKG with the other founders — each draws its own secret and no\n\
         \x20              party ever holds the whole beacon key, unlike `beacon-deal`. The roster is the\n\
         \x20              `x:y:z@host:port` seed form, one per line, INCLUDING this node; every founder must\n\
         \x20              hold the identical file, since the network's name is derived from it. The recovery\n\
         \x20              authority stays a separate step — see `fanos authority-key`)\n\
         \x20 fanos authority-key [--out FILE]\n\
         \x20             (generate THIS founder's recovery-authority key locally: the seed stays here, the\n\
         \x20              printed verifier goes to whoever deals the beacon)\n\
         \x20 fanos message serve --host-key FILE [--config FILE] [--bootstrap x:y:z@host:port,...]\n\
         \x20             (host an ANGELOS messenger on the anonymous rendezvous: clients reach it by\n\
         \x20              service tag, and neither side learns the other's coordinate)\n\
         \x20 fanos service-deal x:y:z... [--out DIR] [--threshold T]\n\
         \x20             (assemble a threshold-hosted service line: one file per member, all carrying the\n\
         \x20              SAME roster — a line whose members disagree by one coordinate cannot reconstruct)\n\
         \x20 fanos ingress-deal COMMUNITY PEER... [--out DIR] [--threshold T] [--difficulty D] [--line C:C:C,...]\n\
         \x20                                     (deal a community's POROS ingress line; writes *.poros files)\n\
         \x20 fanos taxis-deal [--out DIR] [--epoch N] [--beacon HEX64] [--supply N]\n\
         \x20             (deal a 7-validator TAXIS blockchain cell + a genesis-funded founder; writes\n\
         \x20             validator-<i>.taxis + founder.key; --features validator)\n\
         \x20 fanos validator --config validator-<i>.taxis [--listen ADDR] [--bootstrap <coord>@host:port,…]\n\
         \x20             (run a TAXIS blockchain validator over the DROMOS ledger; --features validator)\n\
         \x20 fanos pay --chain-info chain-info.taxis --key founder.key --to HEX --amount N [--nonce M] \\\n\
         \x20             [--bootstrap ...]  (submit a transparent transfer; --features validator)\n\
         \x20 fanos term --chain-info chain-info.taxis --key founder.key [--nonce M] [--dry-run] \\\n\
         \x20             [--to HEX[,HEX...] --amount AMT[,AMT...]] (AMT = N | N% | all) \\\n\
         \x20             [--register-name NAME:TARGETHEX:DUR[:FEE]] [--require-name NAME=OWNERHEX] \\\n\
         \x20             [--require-min ACCTHEX:N] [--bootstrap ...]\n\
         \x20             (compose ONE atomic ERGON term: multi-leg payments — amounts constant, N% of the\n\
         \x20             live balance, or `all` of it — plus name registrations, gated on live name\n\
         \x20             ownership or balance floors; all legs apply or none do, which no single tag\n\
         \x20             expresses; --dry-run prints depth/cost/footprint and stops; --features validator)\n\
         \x20 fanos help\n\
         ",
    );
    s.push_str(&help_reference());
    s
}

/// The reference half of the help: what each provisioning file holds, what a proxy profile means, and the
/// worked examples. Read after the verb listing has said what to type.
fn help_reference() -> String {
    String::from(
        "\n\
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
         \x20 (the port list is the only thing you choose: the exit ALWAYS refuses non-globally-routable\n\
         \x20  destinations — loopback, RFC1918, CGNAT, link-local — so `ports = 80,443` cannot be turned\n\
         \x20  into a proxy into your own network or your cloud metadata endpoint)\n\
         \x20 (providing it implies the `exit` role; the node logs its `coord`/`key` descriptor at startup)\n\
         \n\
         PROTEUS SECRET FILE (--proteus-secret-file, censorship-resistant shaping §13.4): a file holding\n\
         \x20 the raw shared community secret — the same bytes on every peer that must interoperate. It is\n\
         \x20 a bridge/community password, not a per-node key, and the node REFUSES to read it unless it is\n\
         \x20 unreadable to other accounts:\n\
         \x20   (umask 077; printf %s 'YOUR-COMMUNITY-SECRET' > ~/.config/fanos/proteus.secret)\n\
         \x20   fanos node --proteus-secret-file ~/.config/fanos/proteus.secret\n\
         \x20 One trailing newline is ignored, so `echo` and `printf` give the same secret. There is no\n\
         \x20 --proteus-secret VALUE flag: an argv value is readable by every local account via `ps` for as\n\
         \x20 long as the node runs. `proteus_secret = …` in a mode-0600 config file does the same job.\n\
         \x20 Without a secret, --proteus-morph and --proteus-environment do nothing (unshaped QUIC).\n\
         \n\
         CLEARNET (proxy): by default `fanos proxy` DISCOVERS an exit from the live cell directory (exits\n\
         \x20 advertise themselves each epoch) and routes clearnet (non-.fanos) targets through it. Pin a\n\
         \x20 specific exit with --exit-via FILE, a `key = value` file with\n\
         \x20 coord = x:y:z              the exit node's coordinate (from its startup log)\n\
         \x20 key   = <hex>              the exit's service public key (from its startup log)\n\
         \x20 If no exit is discovered and none is pinned, clearnet targets are refused (.fanos-only).\n\
         \n\
         EXAMPLES:\n\
         \x20 fanos id --identity ~/.fanos/id.bin --config /etc/fanos/node.conf  # coordinate on THIS network\n\
         \x20 fanos node --listen 0.0.0.0:9000 --identity ~/.fanos/id.bin \\\n\
         \x20            --bootstrap 1:0:0@seed.example:9000 --role relay,storage\n\
         \x20 fanos proxy --socks-listen 127.0.0.1:1080 --bootstrap 1:0:0@seed.example:9000\n\
         \x20            # then: curl --socks5-hostname 127.0.0.1:1080 http://<pubkey>.fanos/\n\
         \x20 fanos proxy --profile anonymous --threshold 2 --bootstrap 1:0:0@seed.example:9000\n\
         \x20            # unlinkable per-dial routes over the cell mixnet\n\
         \n\
         Set RUST_LOG=debug for verbose logs.",
    )
}

/// Print the whole help.
fn print_help() {
    eprint!("{}", help_text());
}

/// Print the usage block for **one verb**, projected out of the single help text — or the whole thing when the
/// verb has no block.
///
/// **A projection rather than a second set of strings, and that is the point.** `fanos <verb> --help` used to
/// print the top-level listing, and the obvious fix — a usage string per verb — is twenty copies of text that
/// already exists, which drift the first time a flag is added to one and not the other. Here there is one
/// source and the per-verb view is derived from it, so a flag documented once is documented everywhere.
///
/// A block is the line beginning `fanos <verb>` plus every following line indented under it, which is exactly
/// how the listing is already written. `every_verb_has_a_help_block` asserts the projection finds one for each
/// verb the dispatcher accepts, so a new verb cannot ship undocumented.
fn print_verb_help(verb: &str) {
    let text = help_text();
    let Some(block) = verb_block(&text, verb) else {
        eprint!("{text}");
        return;
    };
    eprintln!("usage:\n{block}");
    eprintln!("(`fanos help` lists every verb.)");
}

/// The lines of `text` documenting `verb`: the `fanos <verb>` line and the indented lines under it.
fn verb_block(text: &str, verb: &str) -> Option<String> {
    let head = format!("fanos {verb} ");
    let exact = format!("fanos {verb}");
    let mut lines = text.lines().skip_while(|l| {
        let t = l.trim_start();
        !(t.starts_with(&head) || t == exact)
    });
    let first = lines.next()?;
    // The continuation is every following line indented *past* the verb line's own indent — the shape the
    // listing already uses for a verb's flags and its parenthetical description.
    let indent = first.len() - first.trim_start().len();
    let mut out = vec![first.trim_end().to_owned()];
    for l in lines {
        let t = l.trim_start();
        if t.is_empty() || l.len() - t.len() <= indent {
            break;
        }
        out.push(l.trim_end().to_owned());
    }
    Some(out.join("\n"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Coverage, too_few_relays};

    /// The anonymous profile's refusal must give **different** remediation for its two causes (#291).
    ///
    /// Both worlds hold `resolved` and `need` fixed — 3 relays where 4 are wanted — so the only thing that
    /// differs between them is the scan's completeness. That is the discriminator being tested; a version
    /// that ignores it produces byte-identical output for both and fails here twice.
    ///
    /// The negative assertions are the load-bearing half. `lower --threshold` is sound advice for a cell that
    /// is genuinely short of relays and is *harmful* for one whose reads timed out: it edits the operator's
    /// own anonymity parameter down, permanently, over a transient failure. A message that merely *added*
    /// "some reads timed out" while keeping the old advice would satisfy a laxer test and still be wrong.
    #[test]
    fn the_refusal_advises_differently_when_relays_are_absent_than_when_reads_stalled() {
        let absent = too_few_relays(4, 12, 3, Coverage { unresolved: 0 });
        assert!(
            absent.contains("start relays that publish mix keys or lower --threshold"),
            "a cell genuinely short of relays gets the actionable advice: {absent}"
        );
        assert!(
            !absent.contains("did not answer"),
            "and is not told about reads that all concluded: {absent}"
        );

        let stalled = too_few_relays(4, 12, 3, Coverage { unresolved: 4 });
        assert!(
            stalled.contains("4 more slot(s) did not answer"),
            "a stalled read names its shortfall, so one slow slot reads differently from six: {stalled}"
        );
        assert!(
            stalled.contains("Retry"),
            "and the operator is pointed at the only thing that can help: {stalled}"
        );
        assert!(
            !stalled.contains("start relays that publish mix keys or lower --threshold"),
            "and NOT at lowering their own anonymity parameter over a transient failure: {stalled}"
        );

        // Same shortfall, same epoch, same need — different text. If these ever agree, the flag has been
        // dropped again somewhere between the scan and the report, which is the defect #291 was.
        assert_ne!(absent, stalled, "the cause must reach the operator, not just the count");
    }

    /// The three worlds the isolation warning must tell apart (#179).
    ///
    /// A test driving only the failing world passes against a build that always warns, so all three are here
    /// and the two silent ones carry the reason they must stay silent.
    #[test]
    fn isolation_is_reached_nobody_and_not_merely_alone() {
        // Reached nobody with peers configured — the one case that warns.
        assert!(is_isolated(Some(0), 3), "3 configured, 0 verified: this node is alone by accident");

        // Founding a cell: no peers configured, so "verified nobody" is the expected state, not a fault.
        assert!(!is_isolated(Some(0), 0), "genesis must not warn, or the warning fires on every new network");

        // No claims book — no self-certifying identity. Cannot tell, so must not claim.
        assert!(!is_isolated(None, 3), "`None` is 'cannot tell', not 'verified nobody'");
        assert!(!is_isolated(None, 0), "…and certainly not at genesis");

        // Reached somebody: healthy, whatever the configured count.
        assert!(!is_isolated(Some(1), 3), "one verified peer is not isolation");
        assert!(!is_isolated(Some(3), 3), "nor is all of them");
    }

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

    #[test]
    fn ingress_params_provisions_the_ingress_role_like_every_sibling_flag() {
        // **A flag whose effect depended on a second flag being remembered.** `--service` and `--exit` both
        // imply their own role; `--ingress-params` did not, so it parsed the file, stored the parameters, and
        // then composed no ingress host at all unless the operator also wrote `--role ingress`. A silent
        // no-op: no error, no warning, a node that looks provisioned for a community and admits nobody.
        //
        // Handing a node a community's dealt descriptor share IS asking it to serve that community — there is
        // no other reason to provision one — so the implication is not a convenience, it is what the flag
        // means.
        let path = std::env::temp_dir().join(format!("fanos-ing-{}.poros", std::process::id()));
        std::fs::write(
            &path,
            format!(
                "threshold = 2\ndifficulty = 4\ncommunity = {}\nshare = {}\nbinding = {}\n\
                 kem_seed = {}\nmember = 1:0:0\nmember = 0:1:0\nmember = 0:0:1\n",
                "cd".repeat(16),
                // x = 1, then a short y — the codec takes the first byte as the index.
                "01".to_owned() + &"ef".repeat(8),
                // A binding with the dealing commitment and no per-share commitments (the rotated form).
                "ab".repeat(32) + "00000000",
                "12".repeat(32),
            ),
        )
        .unwrap();

        let args = vec!["--ingress-params".to_owned(), path.to_string_lossy().into_owned()];
        let config = node_config_from_args(&args).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(config.ingress.is_some(), "the file was read");
        assert!(
            config.roles.ingress,
            "and the role it implies is set — otherwise the node stores the parameters and hosts nothing, \
             which is exactly what `--service` and `--exit` avoid by implying theirs",
        );
    }

    /// **A secret passed as an argv value is readable by every account on the host** (#13), so the flag that
    /// took one must refuse rather than warn.
    ///
    /// The failure this pins: `fanos node --proteus-secret hunter2` put the shared community secret into
    /// `/proc/<pid>/cmdline` for the life of the daemon, where `ps -ef` prints it to any local user. Holding
    /// that secret is holding the shaping key of every peer in the community (§13.4). The old code logged a
    /// warning and used it anyway — the insecure path still worked, so it stayed in the scripts.
    ///
    /// Three things are asserted, because a refusal that fails any one of them is not a fix:
    /// * it is an `Err`, not a warning — the run stops;
    /// * the message names the replacement flag, so the operator is not left guessing;
    /// * a *valueless* trailing `--proteus-secret` is refused too. That is the `has_flag`-versus-`flag`
    ///   distinction: `flag` needs a following argument, so a check built on it would have let the very
    ///   invocation whose secret is already in argv through, silently unshaped.
    #[test]
    fn proteus_secret_in_argv_is_refused_and_names_the_file_flag() {
        let args = vec!["--proteus-secret".to_owned(), "hunter2".to_owned()];
        let err = node_config_from_args(&args).expect_err("an argv secret must stop the run, not warn");
        let msg = err.to_string();
        assert!(
            msg.contains("--proteus-secret-file"),
            "the refusal must name what to do instead, not only what is wrong: {msg}"
        );
        assert!(msg.contains("ps"), "and say why argv is not a private channel: {msg}");

        // The flag with no value at all: `flag()` would return `None` here and wave it through.
        let trailing = vec!["--proteus-secret".to_owned()];
        assert!(
            node_config_from_args(&trailing).is_err(),
            "a valueless --proteus-secret is the same exposure and must be refused the same way"
        );
    }

    /// The replacement channel has to be one that other accounts cannot read — **verified, not assumed**.
    ///
    /// Moving a secret from argv into a file buys nothing on its own: `echo hunter2 > secret` under the
    /// default `umask 022` writes mode 0644, and a node that read it without looking would have swapped one
    /// world-readable channel for another while reporting success. So the file's mode is checked at the
    /// moment the secret is taken in.
    ///
    /// Also pins the newline strip, which is a *shared*-secret correctness property rather than a nicety:
    /// `echo s > f` and `printf %s s > f` must give two members of one community the same bytes, because
    /// PROTEUS's failure mode for mismatched shaping keys is silence — nothing connects and nothing says why.
    #[test]
    fn a_proteus_secret_file_must_be_unreadable_to_other_accounts() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = std::env::temp_dir().join(format!("fanos-proteus-{}.secret", std::process::id()));
        // `echo`'s trailing newline on purpose — the form an operator actually types.
        std::fs::write(&path, b"a-shared-bridge-secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let args = vec!["--proteus-secret-file".to_owned(), path.to_string_lossy().into_owned()];

        let config = node_config_from_args(&args).unwrap();
        assert_eq!(
            config.proteus_secret.as_deref().map(Vec::as_slice),
            Some(&b"a-shared-bridge-secret"[..]),
            "the secret is read from the file, and the trailing newline is not part of it — one member \
             using `echo` and another `printf` must end up with identical shaping keys"
        );

        // The same file, group- and world-readable: the exposure the file form exists to remove.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = node_config_from_args(&args)
            .expect_err("a world-readable secret file is the argv exposure with extra steps");
        let msg = err.to_string();
        assert!(
            msg.contains("chmod 600"),
            "the refusal must say how to fix it, or an operator works around it instead: {msg}"
        );

        // A truncated copy or a mistyped redirection: empty is not a secret.
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            node_config_from_args(&args).is_err(),
            "an empty file must not be accepted as an empty shared secret — it shapes every frame \
             identically for everyone, which is the opposite of turning PROTEUS on"
        );

        std::fs::remove_file(&path).ok();
    }

    /// **A secret in a directory other accounts can write is substitutable, and the guard now says so**
    /// (#314).
    ///
    /// `require_private_file` asked one of the two questions. Renaming and unlinking need write permission
    /// on the DIRECTORY, never on the file, so a `0600` key in a world-writable directory cannot be read by
    /// another account and can be replaced by one — and a replaced host key is a service identity they own.
    ///
    /// **The sticky bit is the half that makes this a rule rather than a nuisance**, and it is asserted here
    /// in both directions: `1777` is `/tmp`, where the kernel already forbids replacing somebody else's
    /// entry, and refusing that would have made the guard something operators route around. Same mode bits,
    /// opposite verdicts, one bit apart — which is what proves the check reads the sticky bit rather than
    /// just `0o022`.
    ///
    /// Falsified by dropping the `&& mode & 0o1000 == 0` term (the sticky case starts failing) and again by
    /// returning `Ok(())` from `require_unsubstitutable_path` (the world-writable case starts failing).
    /// Neither falsification touches the other assertion, so the two halves are independently load-bearing.
    #[test]
    fn a_secret_in_a_directory_others_can_write_is_refused_unless_the_sticky_bit_forbids_replacing_it() {
        use std::os::unix::fs::PermissionsExt as _;

        // The predicate directly, on the three modes that decide it. Cheap, exhaustive over the axis, and
        // it does not depend on what this host's /tmp happens to be.
        assert!(substitutable_by_others(0o777), "a world-writable directory lets anyone swap the file in");
        assert!(substitutable_by_others(0o770), "group-writable is the same authority, one audience smaller");
        assert!(
            !substitutable_by_others(0o1777),
            "1777 is /tmp: writable by all, and only an entry's own owner may replace it — refusing this \
             would make the guard a nuisance, and a nuisance is what gets removed"
        );
        assert!(!substitutable_by_others(0o755), "the ordinary case must pass, or every line above is vacuous");
        assert!(!substitutable_by_others(0o700), "and the recommended one");

        // And end to end, through the real walk, so the predicate is proved to be *reached*.
        let root = std::env::temp_dir().join(format!("fanos-substitutable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        for (mode, must_refuse) in [(0o777, true), (0o1777, false), (0o700, false)] {
            let dir = root.join(format!("d{mode:o}"));
            std::fs::create_dir_all(&dir).unwrap();
            let secret = dir.join("svc.key");
            std::fs::write(&secret, b"0123456789abcdef0123456789abcdef").unwrap();
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();

            let path = secret.to_string_lossy().into_owned();
            let verdict = read_seed_file(&path, "a hidden service's secret seed");
            assert_eq!(
                verdict.is_err(),
                must_refuse,
                "a 0600 seed inside a mode-{mode:o} directory: expected refuse = {must_refuse}, got {verdict:?}"
            );
            if must_refuse {
                let msg = verdict.unwrap_err().to_string();
                assert!(
                    msg.contains("REPLACE") && msg.contains(&dir.display().to_string()),
                    "the refusal must name the directory and what can be done to the file, or an operator \
                     cannot act on it: {msg}"
                );
            }
            // 0700 again before the recursive removal, or a later run inherits an odd mode.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A flag left without a value does not silently take the next flag's name** (#313).
    ///
    /// The invocation that produced this: `fanos host --host-key --forward 127.0.0.1:80`. `flag` took
    /// `args.get(i + 1)` unconditionally, so the *string* `--forward` became the path to the service's
    /// secret seed — and because `flag` searches by name rather than by position, `--forward` still parsed
    /// too. The operator's typo surfaced as a complaint about a file called `--forward`, three steps away
    /// from where it happened.
    ///
    /// Three cases, and the third is the one that keeps the rule honest: a path may legitimately begin with
    /// dashes if it is written relative (`./--forward`), and refusing that would be a guard wider than its
    /// defect. It must get past the argument parser and fail on the FILESYSTEM instead.
    ///
    /// Falsified by deleting the `starts_with("--")` arm: the first assertion goes red with `cannot open
    /// '--forward'`, which is precisely the misdirected refusal this closes.
    #[test]
    fn a_flag_with_no_value_is_refused_and_does_not_swallow_the_next_flag() {
        let swallowed =
            vec!["--host-key".to_owned(), "--forward".to_owned(), "127.0.0.1:80".to_owned()];
        let err = flag(&swallowed, "--host-key").expect_err("a flag name is not a value").to_string();
        assert!(
            err.contains("--host-key") && err.contains("--forward"),
            "the refusal must name BOTH the flag left empty and what was about to be bound as its value, \
             because the operator's mistake is the relationship between them: {err}"
        );

        let trailing = vec!["--forward".to_owned(), "1.2.3.4:9".to_owned(), "--host-key".to_owned()];
        let err = flag(&trailing, "--host-key").expect_err("a trailing flag has no value either").to_string();
        assert!(err.contains("last argument"), "and a trailing flag says so specifically: {err}");

        // CONTROL, and the reason the rule is `--` rather than `-`: a relative path is still a value, so the
        // parser must hand it on. A guard that refused this would be wider than the defect it removes.
        let awkward = vec!["--host-key".to_owned(), "./--forward".to_owned()];
        assert_eq!(
            flag(&awkward, "--host-key").expect("a relative path is a value, whatever it is named"),
            Some("./--forward"),
        );

        // And the repeatable form, which had the identical defect one function over.
        let repeated =
            vec!["--bootstrap".to_owned(), "1:2:3@h:1".to_owned(), "--bootstrap".to_owned(), "--listen".to_owned()];
        assert!(
            flag_all(&repeated, "--bootstrap").is_err(),
            "`flag_all` must refuse the same way — a class closed in one of two functions is half closed"
        );
    }

    /// **A raw seed is read raw, and its file must be private** (#310).
    ///
    /// Two properties that pull in opposite directions, which is why they are asserted together. The seed is
    /// guarded exactly like the PROTEUS secret — `--host-key` was the one of seven secret-taking flags the
    /// tool never produces a file for, so its whole recipe was prose in an error message two lines from a
    /// guard that did not run. And it is parsed **unlike** it: `head -c 32 /dev/urandom` ends in `0x0a` for
    /// about one seed in 256, and stripping that byte would derive a different `.fanos` address.
    #[test]
    fn a_host_key_seed_is_guarded_like_a_secret_and_read_byte_for_byte() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("fanos-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("svc.key");
        let shown = path.to_string_lossy().into_owned();

        // A seed whose last byte IS a newline — the case a strip would corrupt.
        let seed: Vec<u8> = (0u8..31).chain(std::iter::once(b'\n')).collect();
        std::fs::write(&path, &seed).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_seed_file(&shown, "a seed").unwrap(),
            seed,
            "every byte of a random seed is the secret — a trailing 0x0a is part of it, and dropping it \
             would move the service's .fanos address for one seed in 256"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let msg = read_seed_file(&shown, "a seed")
            .expect_err("a world-readable service seed is the identity itself, published")
            .to_string();
        assert!(msg.contains("chmod 600"), "the refusal must say how to fix it: {msg}");

        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            read_seed_file(&shown, "a seed").is_err(),
            "an empty seed file is a FIXED seed: every service started from one lands on the same \
             publicly derivable identity"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Both `--host-key` verbs go through the guard** — asserted at the verb, not at the helper.
    ///
    /// A guarded reader nobody calls is the defect this task was about, one layer up: `require_private_file`
    /// existed, was documented, and `--host-key` read the file with a bare `std::fs::read`. So this drives
    /// the two real entry points, `cmd_host` and `cmd_message`, against a world-readable seed and requires
    /// the permission refusal to come back.
    ///
    /// Both refuse **before** any network work: the seed is read, and the error returns — no socket, no
    /// node. That is also the ordering an operator wants, since a mode mistake should not cost a
    /// half-started service.
    ///
    /// **A deliberately malformed `--epoch` rides along, and it is what makes this falsifiable.** It fails
    /// on the very next line after the seed is read, so the two states are two *messages* rather than a
    /// message and a hang: with the guard wired the verb answers `chmod 600`, and with the call site put
    /// back to a bare `std::fs::read` it answers `bad --epoch` and this test fails in milliseconds. Without
    /// it, removing the mechanism would let the verb run on and start a real node, and a falsification that
    /// hangs demonstrates nothing.
    ///
    /// That same argument, run backwards, is the control: at `0600` each verb must reach `bad --epoch`,
    /// which proves the seed was **accepted** and execution moved past it — a guard that refused a correctly
    /// protected file is the other way to be wrong, and it would be invisible to a test that only checked
    /// for some error.
    #[tokio::test]
    async fn both_host_key_verbs_refuse_a_world_readable_seed() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("fanos-hostkey-wiring-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("svc.key");
        std::fs::write(&path, b"0123456789abcdef0123456789abcdef").unwrap();
        let shown = path.to_string_lossy().into_owned();

        let host = vec![
            "--forward".to_owned(),
            "127.0.0.1:1".to_owned(),
            "--host-key".to_owned(),
            shown.clone(),
            "--epoch".to_owned(),
            "not-a-number".to_owned(),
        ];
        let message = vec![
            "serve".to_owned(),
            "--host-key".to_owned(),
            shown.clone(),
            "--epoch".to_owned(),
            "not-a-number".to_owned(),
        ];

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let msg = cmd_host(&host).await.expect_err("fanos host must refuse an exposed seed").to_string();
        assert!(
            msg.contains("chmod 600"),
            "fanos host must fail on the seed's mode, not on the malformed epoch two lines later — a \
             `bad --epoch` here means the read went round the guard: {msg}"
        );
        let msg =
            cmd_message(&message).await.expect_err("fanos message serve must refuse it too").to_string();
        assert!(
            msg.contains("chmod 600"),
            "fanos message serve must fail on the seed's mode for the same reason: {msg}"
        );

        // CONTROL, at the verb rather than at the helper: a 0600 seed must be ACCEPTED, and the proof is
        // that each verb now fails on the next thing instead.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let msg = cmd_host(&host).await.expect_err("the malformed epoch still stops it").to_string();
        assert!(
            msg.contains("--epoch"),
            "a correctly protected seed must be accepted and execution must move past it: {msg}"
        );
        let msg = cmd_message(&message).await.expect_err("same, on the messenger").to_string();
        assert!(msg.contains("--epoch"), "and the messenger must accept it too: {msg}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The config file is the same secret's other door** (#13).
    ///
    /// `proteus_secret = …` is a documented config key, so refusing the argv flag and then reading the same
    /// secret out of a mode-0644 file would leave a guarded path beside an unguarded twin. And the guard must
    /// be conditional: a config *without* a secret is public material — listen address, roles, bootstrap set
    /// — that operators keep in `/etc` at 0644 on purpose, and refusing those would make this check
    /// something people turn off.
    #[test]
    fn a_config_file_carrying_the_secret_must_be_private_but_a_public_one_need_not_be() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir();
        let secretive = dir.join(format!("fanos-cfg-secret-{}.conf", std::process::id()));
        std::fs::write(&secretive, "proteus_secret = a-shared-bridge-secret\n").unwrap();
        std::fs::set_permissions(&secretive, std::fs::Permissions::from_mode(0o644)).unwrap();
        let args = vec!["--config".to_owned(), secretive.to_string_lossy().into_owned()];
        let err = node_config_from_args(&args).expect_err("a world-readable config holding a secret");
        assert!(err.to_string().contains("chmod 600"), "and it says how to fix it: {err}");

        std::fs::set_permissions(&secretive, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = node_config_from_args(&args).unwrap();
        assert!(config.proteus_secret.is_some(), "the same file at 0600 is accepted");

        // The other half: a config with no secret in it is not key material and must stay readable.
        let public = dir.join(format!("fanos-cfg-public-{}.conf", std::process::id()));
        std::fs::write(&public, "plane_order = 2\n").unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        let public_args = vec!["--config".to_owned(), public.to_string_lossy().into_owned()];
        assert!(
            node_config_from_args(&public_args).is_ok(),
            "a config carrying no secret must not be refused for its mode — that would make the check a \
             nuisance rather than a guard, and a nuisance gets removed"
        );

        std::fs::remove_file(&secretive).ok();
        std::fs::remove_file(&public).ok();
    }

    /// **The shipped example config must parse**, and nothing checked that it did.
    ///
    /// `deploy/node.conf.example` is what an operator installs to `/etc/fanos/node.conf`, and
    /// `NodeConfig::from_config_str` treats an unrecognised key as a **hard error** — deliberately, so a typo
    /// fails at start rather than leaving a setting silently at its default. Put together, one stale key in
    /// that file is a node that will not boot, discovered by the operator and by nobody here: no test, no
    /// build step and no lint reads it. It is the provisioning surface again — wire decoders get audited,
    /// the files that configure them do not.
    ///
    /// Found while documenting `proteus_secret` in it (#13), which is exactly the edit that would have
    /// introduced such a key.
    #[test]
    fn the_shipped_example_config_still_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../deploy/node.conf.example");
        let args = vec!["--config".to_owned(), path.to_string_lossy().into_owned()];
        let config = node_config_from_args(&args).unwrap_or_else(|e| {
            panic!("deploy/node.conf.example does not parse, so `fanos node --config` on a fresh install \
                    fails at start: {e}")
        });
        assert_eq!(config.listen.port(), 9000, "and the values in it are the ones it shows");
        assert!(
            config.proteus_secret.is_none(),
            "the example must not ship an ACTIVE proteus_secret — a shared community secret in a file \
             that gets copied between hosts, installed 0644 by the unit's own install line"
        );
    }

    /// **Every verb the dispatcher accepts must have a help block**, and this is the check that makes the
    /// projection honest.
    ///
    /// Per-verb help is derived from the one listing rather than written twice (`print_verb_help`), which
    /// removes drift — but it introduces a different failure: a verb with no block silently falls back to the
    /// whole listing, which is exactly the behaviour the change was made to remove. So the verb list is stated
    /// here and asserted against the text, and a new verb fails this test on the commit that adds it.
    #[test]
    fn every_verb_has_a_help_block() {
        // The dispatcher's own arms, in order. Kept by hand because the alternative — parsing the match — is
        // a worse test than a list someone has to update when they add an arm.
        const VERBS: &[&str] = &[
            "node", "proxy", "host", "message", "validator", "pay", "term", "vpn", "init", "start",
            "stop", "restart", "uninstall", "status", "id", "beacon-deal", "authority-key",
            "ingress-deal", "service-deal", "taxis-deal", "resolve", "keygen",
        ];
        let text = help_text();
        let missing: Vec<&str> = VERBS.iter().copied().filter(|v| verb_block(&text, v).is_none()).collect();
        assert!(
            missing.is_empty(),
            "these verbs are dispatched but documented nowhere, so `fanos <verb> --help` falls back to the \
             whole listing — which is the behaviour per-verb help exists to remove: {missing:?}"
        );
    }

    /// The projection must return **that verb's** block, not the first thing that happens to match.
    #[test]
    fn a_verb_block_is_the_verb_and_its_own_continuation() {
        let text = help_text();
        let block = verb_block(&text, "beacon-deal").expect("beacon-deal is documented");
        assert!(block.contains("beacon-deal"), "the block names its verb");
        assert!(block.contains("--authority-verifiers"), "and carries its own flags");
        assert!(
            !block.contains("fanos ingress-deal"),
            "and stops before the next verb — a block that ran on would make every projection the listing"
        );

        assert!(verb_block(&text, "not-a-verb").is_none(), "an unknown verb has no block");
    }
}
