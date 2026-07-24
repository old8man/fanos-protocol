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

#![forbid(unsafe_code)]

pub mod cell_node;
pub mod config;
pub mod diaulos;
pub mod epoch_driver;
pub mod error;
pub mod exit;
pub mod capdir;
pub mod crosscell_dir;
pub mod loaddir;
pub mod role_loop;
pub mod taxis_driver;
/// Validator provisioning for running the TAXIS blockchain from the binary (`fanos taxis-deal` / `validator`).
#[cfg(feature = "validator")]
pub mod taxis_config;
pub mod identity;
pub mod ingress_node;
pub mod mix_relay;
pub mod mixdir;
pub mod node;
pub mod overlay_beacon;
pub mod poros;
pub mod proxy;
pub mod rendezvous;
pub mod rendezvous_host;
pub mod rendezvous_relay;
pub mod resolve;
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
pub use epoch_driver::EpochDriver;
pub use error::NodeError;
pub use exit::{
    ExitPolicy, build_cell_exit_directory, dial_exit, publish_exit_key, resolve_exit_key, serve_exit,
    spawn_exit_publisher,
};
pub use fanos_onoma::Epoch;
pub use fanos_quic::{Environment, Morph, MorphCodec};
pub use fanos_rendezvous::{BeaconSeed, MixDirectory};
pub use mix_relay::MixRelay;
pub use rendezvous_host::{
    HostEpoch, serve_anonymous, serve_anonymous_rpc, spawn_rendezvous_host, spawn_rendezvous_host_rpc,
};
pub use mixdir::{
    build_cell_mix_directory, build_mix_directory, cell_mix_coords, publish_mix_key,
    resolve_mix_key, spawn_mix_publisher,
};
pub use ingress_node::IngressNode;
pub use node::{Health, Node};
pub use poros::{
    IngressDescriptor, IngressRequest, IngressResponse, PorosHost, request_frame, shard_descriptor,
    solve_ingress_request,
};
pub use taxis_driver::{
    SortitionParams, TaxisEvent, TaxisHandle, TaxisParams, spawn_checkpoint_publisher, spawn_taxis,
};
#[cfg(feature = "validator")]
pub use taxis_config::{ChainInfo, ValidatorConfig, build_genesis, deal_validators, keys_from_seed};
pub use overlay_beacon::OverlayBeaconNode;
pub use proxy::serve_proxy;
pub use rendezvous::{RendezvousRoute, anonymous_dial, dial_anonymous};
pub use rendezvous_relay::{RendezvousRelay, register_frame};
pub use service_node::ServiceNode;
pub use threshold_rendezvous::{
    ThresholdRendezvous, seal_request_intro, seal_request_to_line, split_delivery,
};
pub use threshold_service::{ThresholdService, intro_frame};
pub use resolve::{NodeResolver, ResolvedService, publish_service, verify_descriptor};
