//! # fanos-node — the FANOS node
//!
//! The unified node that the `fanos` binary runs (roadmap Phase 1). FANOS is **sans-I/O**: the
//! protocol logic is a pure engine (`fanos-runtime`) driven by a swappable driver. This crate is
//! the **supervisor** that binds a persistent, self-certifying identity, a bootstrap address book,
//! and the engine composition to the production QUIC driver (`fanos-quic`) — the same engine the
//! simulator exercises, now over a real socket.
//!
//! * [`config`] — [`NodeConfig`]: listen address, identity path, bootstrap peers, roles.
//! * [`identity`] — the durable, self-certifying identity (coordinate = `MapToPoint(H(cert))`).
//! * [`node`] — [`Node`]: start, control, health, shutdown.
//!
//! Phase 1 runs the overlay engine (membership, liveness, L4 storage, DIAKRISIS healing). Relay,
//! service, and exit engines — and the SOCKS5/DNS proxy and VPN surfaces — compose on top in later
//! phases (`docs/design.md` §5).

// See `fanos_ports::stations` for the reasoning: `variant_count` makes "every variant is listed in
// `ALL`" a compile-time fact rather than a hand-maintained one. `ALL` is what a reader enumerates, so a
// variant missing from it is invisible precisely where something new was just made observable — and a
// test cannot catch that, because it can only visit the variants the list already holds.
#![feature(variant_count)]
#![forbid(unsafe_code)]

/// How many further epoch advances a published directory slot outlives before the store reclaims it.
///
/// **Derived from the grace window it has to cover, not chosen.** A slot keyed `(coordinate, epoch)` is dead
/// to any honest reader the moment that epoch passes — a client derives the key from its own live epoch and
/// will never compute the old one again. What is *not* dead is a reader that is one epoch behind: the onion
/// ratchet retains `DEFAULT_RETAIN = 1` past epoch's secret precisely so an onion in flight across a rotation
/// still peels (`fanos-pqcrypto::onion_ratchet`), and a client acting on the previous epoch's directory is the
/// same situation on the lookup side. So the slot must outlive its epoch by exactly that window and no more:
/// one.
///
/// Larger buys nothing — no honest party can use a slot older than the ratchet can peel — and costs linearly,
/// since the live slot count is `publishers × (1 + this)`. Smaller reintroduces the failure the grace window
/// exists to prevent. This is the same reasoning that fixes the ratchet's own `retain`, applied on the other
/// side of the same rotation.
pub(crate) const DIRECTORY_SLOT_EPOCHS: u32 = 1;

/// How many further epoch advances a published **coherence diagnosis** outlives before the store reclaims it.
///
/// **Its own constant, because it answers a different question from [`DIRECTORY_SLOT_EPOCHS`]** (#44). That
/// one is derived from the onion ratchet's grace window: a reader acting on the *current* epoch can be one
/// behind, and nothing honest can use a slot older than the ratchet can peel. Sound — for a reader acting on
/// now. A diagnosis reader deliberately wants history: `Reputation::from_published` recomputes a score from
/// the last [`REP_WINDOW`](fanos_core::roles::REP_WINDOW) **closed** epochs, and at the routing retention of
/// one it could read exactly one. The law was tuned for a memory the store did not keep — one retention
/// serving two requirements with different needs.
///
/// Equal to `REP_WINDOW`, not merely at least it. Shorter and the score is not a function of agreed data at
/// all: a node reading a longer history than the store holds sees a different record set depending on *when*
/// it reads, so two nodes disagree permanently — the carried-score defect one layer down. Longer and the
/// extra epochs are retained for a law that cannot reach them, at a cost of `publishers × 1` slots each.
pub(crate) const DIAGNOSIS_SLOT_EPOCHS: u32 = fanos_core::roles::REP_WINDOW as u32;

/// Which `(coordinate, epoch)` directory a publish belongs to — the sub-kind
/// [`Station::DirectoryPublishFailed`](fanos_runtime::ports::stations::Station::DirectoryPublishFailed) is counted under.
///
/// Named rather than aggregated because the consequence differs: losing the mix key makes this node
/// unroutable for the epoch, losing the capability record makes it unassignable, losing the load report makes
/// its work invisible to the balancer. One number cannot say which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Directory {
    /// Per-epoch onion public (`mixdir`) — a relay missing here cannot be a circuit hop.
    MixKey,
    /// Capability advertisement (`capdir`) — the roster the role controller assigns from.
    Capability,
    /// Per-role load report (`loaddir`) — the balancer's input.
    Load,
    /// Exit service key (`exit`) — a clearnet exit missing here cannot be selected.
    ExitKey,
    /// POROS ingress KEM public (`ingressdir`).
    IngressKey,
    /// Coherence telemetry frame (`telemetry_dir`).
    Coherence,
    /// Per-epoch cell diagnosis (`diagdir`) — the evidence the reputation is recomputed from.
    Diagnosis,
    /// Cross-cell execution certificate (`crosscell_dir`) — what a parent anchors finality on.
    Checkpoint,
    /// Cross-cell health report (`crosscell_dir`).
    Health,
    /// Hidden-service descriptor (`resolve`) — the `.fanos` name's per-epoch lookup slot. A service
    /// missing here cannot be resolved at all, which is the loudest failure in this list: the other
    /// eight degrade a node, this one takes a whole service off the network.
    ServiceDescriptor,
}

/// `Directory::ALL` is complete, proven by the compiler — not by the `ALL.len() == 9` assertion in
/// `tests/directory_publish_reporting.rs`, which forces deliberation when the list *grows* but passes
/// unchanged when a variant is added to the enum and omitted from the list.
const _: () = assert!(
    Directory::ALL.len() == core::mem::variant_count::<Directory>(),
    "a Directory variant is missing from Directory::ALL, so it is invisible to every reader that enumerates"
);

impl Directory {
    /// Every directory, for a reader that enumerates rather than guesses.
    pub const ALL: &'static [Self] = &[
        Self::MixKey,
        Self::Capability,
        Self::Load,
        Self::ExitKey,
        Self::IngressKey,
        Self::Coherence,
        Self::Diagnosis,
        Self::Checkpoint,
        Self::Health,
        Self::ServiceDescriptor,
    ];

    /// The discriminant carried in [`Observation::tag`](fanos_runtime::ports::stations::Observation::tag).
    ///
    /// Written out rather than an `as` cast on the discriminant, so the wire-visible numbering is a decision
    /// in the source instead of a consequence of variant order — reordering the enum must not renumber an
    /// operator's counters.
    #[must_use]
    pub const fn tag(self) -> u64 {
        match self {
            Self::MixKey => 0,
            Self::Capability => 1,
            Self::Load => 2,
            Self::ExitKey => 3,
            Self::IngressKey => 4,
            Self::Coherence => 5,
            Self::Checkpoint => 6,
            Self::Health => 7,
            Self::Diagnosis => 8,
            Self::ServiceDescriptor => 9,
        }
    }

    /// The operator-facing name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MixKey => "mix_key",
            Self::Capability => "capability",
            Self::Load => "load",
            Self::ExitKey => "exit_key",
            Self::IngressKey => "ingress_key",
            Self::Coherence => "coherence",
            Self::Diagnosis => "diagnosis",
            Self::Checkpoint => "checkpoint",
            Self::Health => "health",
            Self::ServiceDescriptor => "service_descriptor",
        }
    }
}

/// What the role loop did when the load scan its demand rests on **did not conclude** — the sub-kind
/// [`Station::SetpointHeld`](fanos_runtime::ports::stations::Station::SetpointHeld) is counted under.
///
/// The two arms are the same non-conclusion with opposite consequences, which is why one counter cannot carry
/// both. `Held` keeps a value the cell agreed on, so the assignment merely fails to *improve*; `Floored` says
/// the cell has agreed on nothing yet, and the demand it uses instead is the geometry's own minimum rather
/// than an inherited one. An operator seeing a run of `Floored` is watching a cell that has never completed a
/// cell-wide load read — a bootstrap that is not finishing — and that is a different call-out from a settled
/// cell riding out a slow epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetpointHold {
    /// A previously **agreed** setpoint was kept, exactly as [`setpoint_to_track`](crate::role_loop) intends.
    Held,
    /// Nothing had ever been agreed, so the viability floor was applied to the understated read instead.
    ///
    /// There is no held value at this point — only [`Demand::default`](fanos_core::roles::Demand::default),
    /// which is the *absence* of a setpoint spelled as a number. Holding it froze the cell at zero for as long
    /// as the reads kept timing out (#250).
    Floored,
}

/// `SetpointHold::ALL` is complete, proven by the compiler, for the same reason [`Directory::ALL`] is.
const _: () = assert!(
    SetpointHold::ALL.len() == core::mem::variant_count::<SetpointHold>(),
    "a SetpointHold variant is missing from ALL, so it is invisible to every reader that enumerates"
);

impl SetpointHold {
    /// Both arms, for a reader that enumerates rather than guesses.
    pub const ALL: &'static [Self] = &[Self::Held, Self::Floored];

    /// The discriminant carried in [`Observation::tag`](fanos_runtime::ports::stations::Observation::tag),
    /// written out for the reason [`Directory::tag`] is.
    #[must_use]
    pub const fn tag(self) -> u64 {
        match self {
            Self::Held => 0,
            Self::Floored => 1,
        }
    }

    /// The operator-facing name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Floored => "floored",
        }
    }
}

/// Which authentication gate refused a message — the sub-kind
/// [`Station::AuthenticationRejected`](fanos_runtime::ports::stations::Station::AuthenticationRejected) is
/// counted under.
///
/// Named rather than aggregated because the attacks differ and so do the responses: forged host registrations
/// are someone trying to hijack a hidden service's meeting point, forged capability advertisements are someone
/// trying to be assigned a role they have no entitlement to, and a misattributed reshare sub-share is a line
/// member trying to steer a rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// A POROS reshare sub-share that did not come from the outgoing member whose index it claimed.
    ReshareSubShare,
    /// A POROS **descriptor share** that arrived from a coordinate outside the ingress line.
    ///
    /// A combiner asks its own line for shares and they answer it directly, so a share from anywhere else was
    /// never requested and cannot be an answer. The handler used to discard the sender entirely — unlike the
    /// reshare and share-request paths, which both take it — and a share is not a harmless message to accept
    /// from a stranger: it enters the gather, and `recover` tolerates only one corrupt member (#152).
    IngressShare,
    /// A rendezvous host registration whose signature or epoch did not verify.
    HostRegistration,
    /// A capability advertisement that failed its signature or epoch check.
    CapabilityAdvertisement,
    /// A **coordinate-bound** capability advertisement that failed entitlement, identity or signature.
    BoundCapabilityAdvertisement,
}

/// `Gate::ALL` is complete, proven by the compiler. Same reasoning as [`Directory`].
const _: () = assert!(
    Gate::ALL.len() == core::mem::variant_count::<Gate>(),
    "a Gate variant is missing from Gate::ALL, so it is invisible to every reader that enumerates"
);

impl Gate {
    /// Every gate, for a reader that enumerates rather than guesses.
    pub const ALL: &'static [Self] = &[
        Self::ReshareSubShare,
        Self::IngressShare,
        Self::HostRegistration,
        Self::CapabilityAdvertisement,
        Self::BoundCapabilityAdvertisement,
    ];

    /// The discriminant carried in `Observation::tag`, written out for the same reason
    /// [`Directory::tag`] is: variant order must not renumber an operator's counters.
    #[must_use]
    pub const fn tag(self) -> u64 {
        match self {
            Self::ReshareSubShare => 0,
            Self::HostRegistration => 1,
            Self::CapabilityAdvertisement => 2,
            Self::BoundCapabilityAdvertisement => 3,
            Self::IngressShare => 4,
        }
    }

    /// The operator-facing name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReshareSubShare => "reshare_sub_share",
            Self::IngressShare => "ingress_share",
            Self::HostRegistration => "host_registration",
            Self::CapabilityAdvertisement => "capability_advertisement",
            Self::BoundCapabilityAdvertisement => "bound_capability_advertisement",
        }
    }
}

/// Pass a directory publish's outcome through, recording the failures where an operator will see them.
///
/// **Called inside each `publish_*`, not at their callers, and that is the point.** All ten returned their
/// `bool` faithfully and every per-epoch republish loop dropped it, so a node falling out of every roster was
/// the last to know (#106). Putting the record at the ten callers would fix the ten that exist and leave the
/// eleventh to remember — the same reasoning that clamps `record_tagged`'s tag at its one choke point.
///
/// There is **no retry and no tolerance to spend**, and that is derived: [`DIRECTORY_SLOT_EPOCHS`] is 1, so a
/// slot outlives its own epoch by exactly the one-epoch grace a lagging reader needs and no more. A reader on
/// the current epoch derives the current key and finds nothing. One dropped write and the node is simply not
/// in that directory — there is no window in which a failure is harmless, so every one is recorded.
pub(crate) fn note_publish(
    client: &fanos_quic::Client,
    directory: Directory,
    epoch: Epoch,
    landed: bool,
) -> bool {
    if !landed {
        let coord = client.address();
        client.record_station(
            fanos_runtime::ports::stations::Station::DirectoryPublishFailed,
            Some(coord),
            Some(directory.tag()),
        );
        tracing::warn!(
            directory = directory.name(),
            epoch = ?epoch,
            coord = ?coord,
            "directory publish did not land — this node is absent from that roster for this epoch"
        );
    }
    landed
}

pub mod bound;
pub mod keygen;
pub mod cell_node;
pub mod config;
pub mod diaulos;
pub mod durable;
pub mod epoch_driver;
pub mod error;
pub mod exit;
pub mod capdir;
pub mod crosscell_dir;
pub mod diagdir;
pub mod loaddir;
pub mod role_loop;
/// **Supervision for the node's long-lived actors** — a task nobody joins cannot report its own death (#251).
pub mod supervise;
pub mod taxis_driver;
/// Validator provisioning for running the TAXIS blockchain from the binary (`fanos taxis-deal` / `validator`).
#[cfg(feature = "validator")]
pub mod taxis_config;
pub mod identity;
pub mod ingress_node;
pub mod ingressdir;
pub mod mix_relay;
pub mod mixdir;
pub mod node;
pub mod overlay_beacon;
pub mod poros;
pub mod proxy;
pub mod rendezvous;
pub mod rendezvous_host;
pub mod rendezvous_relay;
pub mod admin;
pub mod composition;
pub mod angelos_driver;
pub mod setup;
/// Which signals mean "stop cleanly" — the half of the drain that lives above the drain itself.
pub mod shutdown;
pub mod resolve;
/// Differentially-private telemetry export over the overlay store (audit C7) — see [`telemetry_dir`].
pub mod telemetry_dir;
pub mod service_node;
pub mod sybil;
pub mod threshold_rendezvous;
pub mod threshold_service;

pub use cell_node::CellNode;
pub use config::{BeaconParams, ExitParams, NodeConfig, Peer, RoleSet, ServiceParams};
pub use diaulos::{
    AnonRouteParams, FanosDialer, NodeTransport, ServiceResolver, StaticResolver, dial_service,
    serve, serve_rpc,
};
pub use epoch_driver::{EpochDriver, next_epoch};
pub use error::NodeError;
pub use exit::{
    ExitPolicy, ExitRefusal, build_cell_exit_directory, dial_exit, publish_exit_key, resolve_exit_key,
    serve_exit, spawn_exit_publisher,
};
pub use fanos_onoma::Epoch;
pub use fanos_quic::{Environment, Morph, MorphCodec};
pub use fanos_rendezvous::{BeaconSeed, MixDirectory};
pub use mix_relay::MixRelay;
pub use rendezvous_host::{
    HostedService, HostEpoch, RpcService, serve_anonymous, serve_anonymous_rpc, spawn_rendezvous_host, spawn_rendezvous_host_rpc,
};
pub use mixdir::{
    build_cell_mix_directory, build_mix_directory, cell_mix_coords, publish_mix_key,
    resolve_mix_key, spawn_mix_directory_feeder, spawn_mix_publisher,
};
pub use ingress_node::IngressNode;
pub use ingressdir::{ingress_keypair, publish_ingress_key, resolve_ingress_key, resolve_ingress_line};
pub use node::{Health, NetworkId, Node, genesis_seed};
pub use poros::{
    DealtDescriptor, DescriptorBinding, IngressDescriptor, IngressRequest, IngressResponse, PorosHost,
    Recovery, descriptor_commitment, recover, request_frame, shard_descriptor, solve_ingress_request,
};
pub use taxis_driver::{
    SortitionParams, TaxisEvent, TaxisHandle, TaxisParams, spawn_checkpoint_publisher, spawn_taxis,
};
#[cfg(feature = "validator")]
pub use taxis_config::{
    ChainInfo, PROVISION_FORMAT_VERSION, ProvisionFormat, ValidatorConfig, build_genesis, deal_validators,
    keys_from_seed,
};
pub use overlay_beacon::OverlayBeaconNode;
pub use proxy::serve_proxy;
pub use rendezvous::{RendezvousRoute, anonymous_dial, dial_anonymous};
pub use rendezvous_relay::{RendezvousRelay, register_frame, register_targets};
pub use service_node::ServiceNode;
pub use threshold_rendezvous::{
    ThresholdRendezvous, seal_request_intro, seal_request_to_line, split_delivery,
};
pub use threshold_service::{ThresholdService, intro_frame};
pub use fanos_session::dropped_payloads;
// `Node::command` takes a `Command` and `Node::next_notification` yields a `Notification`, both defined in
// `fanos-runtime` — so without these re-exports a downstream crate cannot call either public method without
// depending on `fanos-runtime` directly. Re-exported rather than duplicated: they are the same types.
pub use fanos_runtime::{Command, Notification};
pub use resolve::{
    Coverage, NodeResolver, Read, ResolvedService, STORE_TIMEOUT, Scan, publish_service,
    spawn_descriptor_publisher, verify_descriptor,
};
