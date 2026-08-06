//! `RendezvousRelay` — a designated rendezvous point that relays clients' replies (audit #54, item 3).
//!
//! A client's reply circuit ends at a rendezvous **line**, one of whose members peels the reply onion and
//! delivers it. An external `.fanos` client (running only an overlay node, never a router) can never peel an
//! onion at all, so it cannot be its own reply rendezvous.
//! It instead **engages a relay**: it registers its session cookie with a node on that line (an
//! [`RdvRegister`](fanos_wire::FrameType::RdvRegister) frame carrying the 16-byte cookie), names that
//! relay's line as its reply circuit's last hop, and the relay forwards each anonymous reply it peels —
//! tagged by that cookie — to the client's real coordinate as an [`RdvReply`](fanos_wire::FrameType::RdvReply).
//!
//! **A bare-proxy client registers with every member of its reply line, not one node** ([`register_targets`],
//! #55): a reply's final gather happens at a per-onion salted member, so the member that peels it is not
//! predictable from the line alone, and only a member holding the cookie can forward. That is the same spread
//! a §3b host registration makes, for the same reason — and it is the cost of this fallback, which NOSTOS
//! avoids entirely by making the client a line member that needs no forwarding at all.
//! This is Tor's rendezvous-point model, and it is the **bare-proxy fallback**: the relay learns the
//! client's coordinate (which the client chose) but never the service. The stronger, primary path — where
//! the client's coordinate never leaves its node at all — is **NOSTOS** ([`fanos_aphantos::nostos`]): a
//! full cell-node client receives its replies as a member of its own beacon-blinded dead-drop line, needing
//! no relay and exposing no coordinate. This relay serves only the residual case of a client that cannot be
//! a line member. (It supersedes the earlier single-relay SURB, now retired.)
//!
//! **Shared by cookie.** One combiner relays for *many* clients at once: each reply carries the
//! [`RendezvousService`](fanos_rendezvous::RendezvousService)'s 16-byte session-cookie prefix
//! ([`seal_reply`](fanos_rendezvous::RendezvousService::seal_reply)), so the relay demultiplexes replies
//! to the right registered client with no per-client relay instance. A reply whose cookie matches no
//! registration passes through as a local anonymous delivery — which is exactly the *service's* own
//! meeting-line combiner (no client registers there), so a forward request still surfaces locally.
//!
//! [`RendezvousRelay`] composes a [`ThresholdRouter`] (which peels the reply hops) with the forwarding
//! rule, as one sans-I/O engine — so a relay is one spawnable engine, exactly like [`crate::MixRelay`]
//! (which composes this to make every cell relay a rendezvous point). It is *additive*: a client that
//! already sits at a combiner keeps listening there directly; nothing in the sealing path changes.

use fanos_aphantos::ThresholdRouter;
use fanos_aphantos::threshold_router::ANONYMOUS;
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_primitives::BoundedMap;
use fanos_primitives::hash::{hash_labeled, label};
use fanos_rendezvous::{Epoch, HostRegister, MixDirectory, Request, SessionId, parse_host_register};
use fanos_runtime::ports::stations::{Station, Stations, merge_observations};
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// A rendezvous relay: a [`ThresholdRouter`] plus a table of the clients whose anonymous replies it
/// forwards, keyed by each client's session cookie. Construct one at **every member** of a line that serves as
/// a rendezvous — any member may be the one a given reply's salted pick sends the final gather to (#55), and
/// only a member holding the cookie can forward. `MixRelay` composes this at every cell node, which satisfies
/// that by construction.
pub struct RendezvousRelay<F: Field> {
    router: ThresholdRouter<F>,
    /// `cookie → client coordinate`: a peeled reply prefixed with `cookie` is forwarded straight to the
    /// registered coordinate as an [`RdvReply`](fanos_wire::FrameType::RdvReply). The relay learns that
    /// coordinate — the **bare-proxy fallback**; a full cell-node client uses NOSTOS instead and never
    /// registers here (its coordinate never leaves its node).
    /// `cookie → client coordinate`: the **bare-proxy fallback** — a peeled reply prefixed with `cookie` is
    /// forwarded straight to the registered coordinate as an [`RdvReply`](fanos_wire::FrameType::RdvReply). The
    /// relay learns that coordinate; a full cell-node client uses NOSTOS instead and never registers here. A
    /// [`BoundedMap`] so an attacker-chosen 16-byte-cookie flood cannot grow it (audit robustness B2): at
    /// [`MAX_REGISTRATIONS`] the oldest is evicted (an evicted client re-registers; the fallback is best-effort).
    ///
    /// **Carries its epoch, and is retired on the turn** ([`retire_stale_registrations`](Self::retire_stale_registrations)).
    /// Capacity alone is the wrong bound for this: it makes retention a function of TRAFFIC, so a busy relay
    /// forgets quickly while a quiet one keeps every binding indefinitely — exactly backwards. And what is kept
    /// is a table of *which coordinate ran which anonymous session*, which is the one thing a seized relay must
    /// not be able to hand over. The neighbouring `hosts` field already retires by epoch for the same reason
    /// (#58); a registration's usefulness ends with the epoch, because the client's route rotates with the
    /// beacon and a reply for a stale cookie can reach nothing.
    registrations: BoundedMap<SessionId, (Epoch, Triple)>,
    /// `service_tag → registration`: an anonymously-registered hidden service hosted **off** this combiner
    /// (`design-anonymity-substrate.md` §3b). A matching client request peeled here is re-sealed as a NOSTOS
    /// onion to the service's registered dead-drop line — reachable without any node learning its coordinate.
    /// A [`BoundedMap`], bounded like `registrations` at [`MAX_HOSTS`] against a registration flood.
    hosts: BoundedMap<[u8; 32], (Epoch, HostRegister)>,
    /// The **current epoch's beacon seed**, the second half of a host registration's tag (#132).
    ///
    /// `service_tag` used to commit to the epoch NUMBER alone, which is known arbitrarily far ahead — and a
    /// hidden service's identity is public by construction, since clients must hold it to dial. So anyone
    /// who knew a service could compute its rendezvous slot for every future epoch and pre-position against
    /// it, while `meeting_line` — the other half of the same rotation — had resisted exactly that since E5
    /// by folding in the beacon. Both halves resist anticipation now.
    ///
    /// Set at construction from the composite's own beacon and pushed forward by it
    /// ([`CellNode::step_obn`](crate::cell_node::CellNode)) at the moment the beacon adopts a round — not read
    /// from a directory, because the relay has no clock of its own and the composite is where the beacon and the
    /// router already meet. It begins at the composite's genesis seed, which is `H("FANOS-v1/genesis-beacon" ‖
    /// commitment)` for *this* network and is what every party derives an epoch-0 tag from, so a cell that has not
    /// yet produced a beacon round agrees with itself rather than failing.
    beacon: [u8; 32],
    /// This relay's **own** data-path readings, merged into the router's on `Command::Observe`.
    ///
    /// The relay had none, so its two forward-path discards — a host whose route it cannot seal to, and a
    /// request naming a service it does not hold — were invisible while the router's plane reported in
    /// detail beside them. A wedged session was measured to lose the FORWARD half, which is exactly the half
    /// these two cover.
    stations: Stations,
    /// The mix directory the forward seal reads its hop keys from, refreshed each epoch by the composite that
    /// owns this relay (the same place that drives the router's rotation).
    ///
    /// **The registration used to carry these keys itself** — `q + 1` per hop — on the argument that a combiner is
    /// any node the beacon happened to place there and holds no global directory. Measured, that argument bought a
    /// payload growing linearly with the plane: ~3.7 KB at `q = 2` and ~39 KB at `q = 31`, against a fixed 7041-byte
    /// onion body. The registration therefore did not fit on any plane past Fano, *before* authentication added a
    /// bundle and a signature. A combiner is a cell node and can be handed a directory; that is what this is.
    directory: MixDirectory,
    /// Per-node seed for the fresh onion/e2e seeds each host-forward draws; deterministic (derived from this
    /// relay's coordinate) so a sim reproduces exactly, distinct per node so two combiners never collide.
    forward_seed: [u8; 32],
    /// Monotonic counter domain-separating each forward's seed pair, so no two forwards reuse key material.
    forward_counter: u64,
}

/// The cap on concurrently-registered bare-proxy client sessions (audit robustness B2). Beyond it, the
/// oldest registration is evicted FIFO, so an attacker streaming distinct cookies cannot grow the map without
/// bound. Generous enough for any real relay's concurrent fallback clients.
pub(crate) const MAX_REGISTRATIONS: usize = 4096;

/// How many further epoch advances a hidden-service registration outlives before the relay retires it.
///
/// **Derived from the skew the rest of the system already tolerates, not chosen — and getting it wrong once
/// is why it is written down.** Retiring at the epoch boundary (`minted >= now`) looks obviously right and is
/// not: client and host derive the meeting line from `(epoch, beacon)` INDEPENDENTLY, so they turn at
/// different moments, and a client that has not yet adopted the new beacon computes last epoch's tag while
/// being an entirely honest client.
///
/// Every other component already grants that client its window. The host's accept loop keeps
/// `MAX_REPLY_KEYS = 3` epochs of dead-drop keys precisely because "a request forwarded just before a
/// rotation is sealed to the *previous* epoch's key". The onion ratchet retains one past epoch's secret so an
/// in-flight onion still peels. A relay retiring at the boundary would be the one component with no grace at
/// all — and the symptom is not a clean failure but a hidden service that goes unreachable once per
/// `epoch_period`, reported as "randomly down".
///
/// One, matching the ratchet rather than the key ring, because the ratchet is the binding constraint: past
/// its retain window the onion carrying the request cannot be peeled at all, so a longer host grace would
/// keep a route nothing can reach. Larger also re-widens the leak that retirement exists to close — a
/// recorded tag buys an adversary exactly this window, and it should buy no more than every other component
/// already concedes.
pub(crate) const HOST_GRACE_EPOCHS: u64 = 1;

/// The cap on concurrently-registered hidden-service hosts (§3b). A `HostRegister` peels out as an
/// anonymous delivery, so — like the client registrations — an unbounded map would be a remote OOM; beyond
/// the cap the oldest host is evicted FIFO (it re-registers each epoch anyway). Generous for any real cell.
pub(crate) const MAX_HOSTS: usize = 4096;

impl<F: Field> RendezvousRelay<F> {
    /// A relay wrapping `router`, holding `beacon` as the current epoch's seed. No client or host is registered
    /// until one sends an [`RdvRegister`](fanos_wire::FrameType::RdvRegister) / a §3b host registration; until
    /// then it just routes.
    ///
    /// `beacon` is a constructor ARGUMENT rather than a default the caller may override, because it decides which
    /// network's registrations this relay accepts: a host's `service_tag` commits to it (#132), so a relay holding
    /// the wrong seed rejects every genuine registration and — worse — would accept ones minted against whatever
    /// seed it does hold. There is no safe value to guess. The first draft defaulted it to `BeaconSeed::GENESIS`
    /// and was caught by `nothing_in_a_running_node_picks_its_network_by_naming_the_constant`: the genesis seed is
    /// `H("FANOS-v1/genesis-beacon" ‖ commitment)`, a per-network value, not the constant. Both composites have a
    /// beacon in hand where they build this, so neither has to invent one.
    #[must_use]
    pub fn new(router: ThresholdRouter<F>, beacon: [u8; 32]) -> Self {
        // Derive the host-forward seed from this relay's coordinate: deterministic (sim-reproducible) and
        // per-node distinct, with no new constructor parameter to thread through every caller.
        let forward_seed = hash_labeled(label::KDF, &encode_coord(router.address()));
        Self {
            router,
            registrations: BoundedMap::new(MAX_REGISTRATIONS),
            hosts: BoundedMap::new(MAX_HOSTS),
            beacon,
            stations: Stations::new(),
            directory: MixDirectory::new(),
            forward_seed,
            forward_counter: 0,
        }
    }

    /// Adopt `beacon` as the current epoch's seed — the second half of a registration's [`service_tag`].
    ///
    /// Driven by the composite the moment the beacon adopts a round, alongside the router's own onion-key
    /// rotation, so the relay's tag arithmetic and its epoch never disagree.
    pub fn set_beacon(&mut self, beacon: [u8; 32]) {
        self.beacon = beacon;
    }

    /// The number of hidden-service hosts currently registered here.
    #[must_use]
    pub fn hosts(&self) -> usize {
        self.hosts.len()
    }

    /// Record a hidden service's anonymous host registration (§3b): bind its `service_tag` to the route the
    /// relay forwards matching client requests through. Only **primary** (coordinate-hiding) registrations
    /// are accepted — a non-empty `forward_circuit` with self-provisioned keys; a bare-host registration
    /// (direct-coordinate fallback) is ignored here (its forwarding is a separate, weaker path). Bounded FIFO.
    /// Returns the effect announcing the binding, or nothing when the registration was refused — so a caller
    /// that must know the route exists has an observable instead of a duration to guess.
    fn register_host(&mut self, reg: HostRegister) -> Vec<Effect> {
        if reg.forward_circuit.is_empty() {
            return Vec::new();
        }
        // **The binding is checked, not believed.** `service_tag` is a one-way image of the service's published
        // identity and its epoch, so anyone holding the (public) address can compute it — and `BoundedMap::insert`
        // on a known key overwrites. Without this line one unsigned message per epoch seized a hidden service's
        // route: every client request peeled here would go to the sender's dead-drop instead of the service's, and
        // the sender would additionally read each request's `reply_circuit`, whose last hop is one of the CLIENT's
        // own lines. `HostRegister::verify` recomputes the tag from the carried identity, refuses a KEM-only
        // identity that could authenticate nothing, and checks the signature over the whole registration.
        //
        // The epoch comes from the router rather than a field of this type, because the router's is the same
        // beacon-led clock (`CellNode` documents the invariant: the beacon leads, the router follows). A
        // registration minted for another epoch carries another tag and would be filed under a key no client of
        // *this* epoch looks up, so refusing it costs nothing that was ever reachable.
        let epoch = self.router.onion_epoch();
        // And the epoch's BEACON, given at construction and pushed forward by the composite the moment the
        // beacon adopts a new round (`CellNode::step_obn`), because the tag is only unanticipatable if it
        // commits to a value that did not exist before the epoch opened (#132). Before the first round that
        // value is the network's genesis seed, which is what every party derives its epoch-0 tag from, so a
        // cell agrees with itself from the start.
        if !reg.verify(epoch, &self.beacon) {
            // Counted, or a relay under a sustained registration-forgery attempt is indistinguishable from a
            // relay nobody is using (#109). Unattributed: a registration that fails to verify has no
            // authenticated origin, and inventing one would put fabricated evidence against a coordinate into
            // the plane built to end exactly that.
            self.stations.record_tagged(
                Station::AuthenticationRejected,
                None,
                Some(crate::Gate::HostRegistration.tag()),
                1,
            );
            return Vec::new();
        }
        let service_tag = reg.service_tag;
        // The `BoundedMap` bounds this against a registration flood (a re-registration refreshes the route).
        // The epoch is stored WITH the registration, because a tag is a function of the epoch and therefore a
        // service takes a fresh slot every epoch — see `retire_stale_hosts`, which is what frees the old one.
        self.hosts.insert(service_tag, (epoch, reg));
        vec![Effect::Notify(Notification::HostRegistered { service_tag })]
    }

    /// The next `(e2e_seed, onion_seed)` pair for a host-forward — two independent fresh draws (the NOSTOS
    /// end-to-end nonce and the onion key material must not share entropy), advancing the counter.
    fn next_forward_seeds(&mut self) -> ([u8; 32], [u8; 32]) {
        let n = self.forward_counter;
        self.forward_counter += 1;
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(&self.forward_seed);
        data[32..].copy_from_slice(&n.to_be_bytes());
        let e2e = hash_labeled(label::KDF, &data);
        // A distinct second draw: flip the domain by appending a marker byte.
        let mut data2 = [0u8; 41];
        data2[..40].copy_from_slice(&data);
        data2[40] = 0x01;
        let onion = hash_labeled(label::KDF, &data2);
        (e2e, onion)
    }

    /// The coordinate registered for `cookie` (the bare-proxy fallback), if any.
    #[must_use]
    pub fn client_for(&self, cookie: &SessionId) -> Option<Triple> {
        self.registrations.get(cookie).map(|(_, coord)| *coord)
    }

    /// The number of client sessions currently registered.
    #[must_use]
    pub fn registrations(&self) -> usize {
        self.registrations.len()
    }

    /// A shared reference to the wrapped router (for a composite engine to read its onion-key state).
    #[must_use]
    pub fn router(&self) -> &ThresholdRouter<F> {
        &self.router
    }

    /// Install the epoch's mix directory — the hop keys [`HostRegister::seal_forward_to_host`] seals with.
    ///
    /// Mirrors `RendezvousService::set_directory` on the host side, and is driven from the same place: a combiner
    /// cannot look anything up itself (it is a sans-I/O `Engine`), so the composite that already rebuilds the cell
    /// directory each epoch hands it over. A relay with no directory simply cannot forward — registrations still
    /// bind, and the next epoch's install makes them usable.
    pub fn set_directory(&mut self, directory: MixDirectory) {
        self.directory = directory;
        self.retire_stale_hosts();
        self.retire_stale_registrations();
    }

    /// Drop every hidden-service registration minted for an epoch this relay has passed.
    ///
    /// **A retention rule that follows from the key, not from a policy.** `service_tag` is
    /// `H(signing identity ‖ epoch)`, so a service occupies a *different* slot every epoch and the previous
    /// one is never overwritten. Nothing removed it: the map's only eviction was FIFO under capacity
    /// pressure, and its comment justified that with "it re-registers each epoch anyway" — which is precisely
    /// what leaves the old entry behind.
    ///
    /// A past-epoch entry is unreachable by any honest client, because a client derives the tag from its own
    /// live epoch and will never compute that one again. So retaining it can serve exactly one party: an
    /// adversary that recorded the tag while it was current. It can then re-present that tag at any later
    /// epoch and this relay will still re-seal its request to the service's old dead-drop line — which is to
    /// say **rotation did not retire the path it rotated away from**, and the moving-target property the
    /// design claims ("rotation caps a single enumeration's value to one epoch") held only for honest
    /// lookups.
    ///
    /// Driven from `set_directory` because that is already the per-epoch hand-off: a combiner is a sans-I/O
    /// engine and cannot notice a clock on its own, and the composite that rebuilds the directory each epoch
    /// is the one party that knows the epoch turned.
    fn retire_stale_hosts(&mut self) {
        let now = self.router.onion_epoch().get();
        self.hosts.retain(|_, (minted, _)| minted.get().saturating_add(HOST_GRACE_EPOCHS) >= now);
    }

    /// Retire client registrations from past epochs — the same argument as [`retire_stale_hosts`], applied to
    /// the other table, which had only a capacity bound.
    ///
    /// A registration exists so this relay can forward one session's replies to the coordinate that asked. That
    /// coordinate is the single most sensitive thing a relay can hold, and its usefulness is bounded by the
    /// epoch: the client's route rotates with the beacon, so a reply against a stale cookie reaches nothing an
    /// honest client is still listening for. Keeping it therefore serves no session and exactly one adversary —
    /// whoever later takes the relay and reads the table.
    ///
    /// Same grace window as hosts, and for the same reason: a session live across the boundary must not be cut.
    fn retire_stale_registrations(&mut self) {
        let now = self.router.onion_epoch().get();
        self.registrations.retain(|_, (seen, _)| seen.get().saturating_add(HOST_GRACE_EPOCHS) >= now);
    }

    /// A mutable reference to the wrapped router (for a composite engine to drive its epoch rotation).
    pub fn router_mut(&mut self) -> &mut ThresholdRouter<F> {
        &mut self.router
    }

    /// Rewrite the router's effects, resolving each peeled anonymous delivery in priority order:
    /// 1. a **registered client's** cookie-tagged reply → an [`RdvReply`](fanos_wire::FrameType::RdvReply)
    ///    `Send` to that client (the bare-proxy fallback — the relay knows the *client*, never the service);
    /// 2. a **§3b host registration** → bind the hidden service's forward route (no effect emitted);
    /// 3. a **client request naming a registered host** → re-seal it as a NOSTOS onion to that host's
    ///    dead-drop line and `Send` it on — so the service is reachable though it is *not* this combiner and
    ///    this relay learns neither endpoint's coordinate;
    /// 4. anything else → pass through as a local anonymous delivery (the service *is* its own combiner, or an
    ///    unrelated onion). The rule is additive: with no clients and no hosts registered, every delivery
    ///    falls straight through and the relay is a plain router.
    fn process_deliveries(&mut self, effects: Vec<Effect>) -> Vec<Effect> {
        // Every anonymous delivery is inspected — no empty-map fast path: the *first* host registration
        // arrives while `hosts` is still empty, so skipping classification then would never bind it.
        let mut out = Vec::with_capacity(effects.len());
        for e in effects {
            match e {
                Effect::Notify(Notification::Delivered { from, payload }) if from == ANONYMOUS => {
                    out.extend(self.classify_anonymous(payload));
                }
                other => out.push(other),
            }
        }
        out
    }

    /// Resolve one peeled anonymous delivery to its effect(s) (see [`Self::process_deliveries`]).
    fn classify_anonymous(&mut self, payload: Vec<u8>) -> Vec<Effect> {
        // 1. A registered client's cookie-tagged reply → forward to that client.
        if let Some(client) = payload
            .get(..size_of::<SessionId>())
            .and_then(|c| <SessionId>::try_from(c).ok())
            .and_then(|cookie| self.registrations.get(&cookie).map(|(_, coord)| coord))
        {
            return vec![Effect::Send { to: *client, frame: framed(FrameType::RdvReply, &payload) }];
        }
        // 2. A host registration → bind it (primary, coordinate-hiding registrations only).
        if let Some(reg) = parse_host_register(&payload) {
            return self.register_host(reg);
        }
        // 3. A client request naming a registered host → re-seal to that host's dead-drop and forward.
        if let Some(req) = Request::decode(&payload)
            && req.service_tag != [0u8; 32]
            && let Some((_minted, reg)) = self.hosts.get(&req.service_tag).cloned()
        {
            let (e2e, onion) = self.next_forward_seeds();
            // A registered host whose route we cannot seal to: drop, don't surface locally (this node is not
            // the service — a local delivery would be answered by the wrong party). Dropping is right;
            // dropping SILENTLY was not, since this is the forward path and it fires per combiner.
            let Some(fwd) = reg.seal_forward_to_host::<F>(&self.directory, &payload, &e2e, &onion) else {
                self.stations.record(Station::HostForwardUnsealable, None);
                return Vec::new();
            };
            return vec![Effect::Send { to: fwd.combiner, frame: fwd.frame }];
        }
        // 4. Otherwise a local anonymous delivery (the service is its own combiner, or an unrelated onion).
        //
        // A request that names a service tag and reaches here named one this relay does not hold, so it is
        // about to be answered by the wrong party or by nobody. Surfacing it locally stays the right
        // behaviour — this node may BE the service — but the case is now counted, because a client whose
        // requests land on a member that never bound the registration sees exactly a forward-path wedge.
        if let Some(req) = Request::decode(&payload)
            && req.service_tag != [0u8; 32]
        {
            self.stations.record(Station::RequestForUnknownHost, None);
        }
        vec![Effect::Notify(Notification::Delivered { from: ANONYMOUS, payload })]
    }

    /// Record a client's registration: a 16-byte cookie binds this session to the sender's coordinate, so
    /// the relay forwards that session's replies there (the bare-proxy fallback). A body that is not exactly
    /// a 16-byte cookie (wrong length or trailing bytes) is ignored.
    fn register(&mut self, body: &[u8], from: Triple) {
        let Ok(cookie) = <SessionId>::try_from(body) else {
            return;
        };
        // The `BoundedMap` bounds this against a cookie flood: a re-registration refreshes the coordinate; a
        // new cookie takes a slot, evicting the oldest at capacity (audit B2) — a bounded map, not a leak.
        self.registrations.insert(cookie, (self.router.onion_epoch(), from));
    }
}

/// Encode `body` as a `frame_type` wire frame.
fn framed(frame_type: FrameType, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    encode_frame(frame_type.code(), body, &mut frame);
    frame
}

/// A coordinate's canonical bytes (three big-endian `u32`s), for deriving this relay's forward seed. Built
/// once at construction, so the small allocation is immaterial.
fn encode_coord(coord: Triple) -> Vec<u8> {
    coord.iter().flat_map(|c| c.to_be_bytes()).collect()
}

impl<F: Field> Engine for RendezvousRelay<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        // The sense-only read: answer with the router's plane AND this relay's own, merged. Without this the
        // relay's forward-path discards are invisible next to a router plane that reports in detail — and the
        // forward half is where a wedged session was measured to lose its request.
        if matches!(input, Input::Command(Command::Observe)) {
            let mut out = self.router.step(now, input);
            for effect in &mut out {
                if let Effect::Notify(Notification::DataPath { stations, .. }) = effect {
                    *stations = merge_observations(
                        stations.iter().copied().chain(self.stations.observations()),
                    );
                }
            }
            return out;
        }
        if let Input::Message { from, frame } = &input
            && let Ok((decoded, _)) = decode_frame(frame)
        {
            // A client registers a session cookie: the relay forwards that session's replies to the
            // sender's coordinate (the bare-proxy fallback).
            if decoded.frame_type() == Some(FrameType::RdvRegister) {
                self.register(decoded.body, *from);
                return Vec::new();
            }
        }
        // Everything else is onion traffic: route it, then resolve each peeled anonymous delivery (client
        // reply / host registration / request-for-a-registered-host / local).
        let effects = self.router.step(now, input);
        self.process_deliveries(effects)
    }

    fn address(&self) -> Triple {
        self.router.address()
    }
}

/// The frame a client sends to register with a rendezvous relay
/// ([`RdvRegister`](fanos_wire::FrameType::RdvRegister)): a 16-byte `cookie` binds the session so the relay
/// forwards its replies to the sender's coordinate — the **bare-proxy fallback**, for a client that cannot
/// be a line member. A full cell-node client uses NOSTOS and never registers here.
///
/// **Send it to every member of the reply line — use [`register_targets`], not this alone.** The frame is the
/// primitive; the *set of nodes it must reach* is the thing that is easy to get wrong.
#[must_use]
pub fn register_frame(cookie: SessionId) -> Vec<u8> {
    framed(FrameType::RdvRegister, &cookie)
}

/// Every `(coordinate, frame)` a bare-proxy client must send to register `cookie` for replies arriving on
/// `reply_line` — one per member of that line.
///
/// **The whole line, not its canonical combiner, and that is correctness rather than redundancy** (#55). A
/// reply's final gather happens at a per-onion salted member ([`fanos_rendezvous::combiner_for_salted`]), so
/// which member peels a given reply is not predictable from the line; a member without the cookie finds no
/// registration, and `classify_anonymous` then passes the reply through as a local delivery — silently losing
/// it at a node that is not the client. Registering with one node made the fallback work only for the
/// `1/(q+1)` of replies that happened to land there.
///
/// This costs the fallback `q + 1` small frames per session and tells every member of one line that *some*
/// client is at the sender's coordinate — which is the posture this fallback already has (it exists precisely
/// for a client that cannot hide as a line member), now spread over the line instead of concentrated in one
/// node. A client that can run a router should use NOSTOS instead and register nothing.
#[must_use]
pub fn register_targets<F: Field>(cookie: SessionId, reply_line: Triple) -> Vec<(Triple, Vec<u8>)> {
    let frame = register_frame(cookie);
    fanos_rendezvous::line_member_coords::<F>(reply_line)
        .into_iter()
        .map(|member| (member, frame.clone()))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    /// A fixed beacon for the tag arithmetic under test: the tag is `H(identity ‖ epoch ‖ beacon)` and these
    /// tests vary the first two, so the third is held constant to isolate what they are about (#132). The
    /// beacon's own contribution is asserted separately, by the test that shows a future epoch's tag is not
    /// computable under the current one.
    const TAG_BEACON: [u8; 32] = [0x7B; 32];

    /// A relay for these tests, holding [`TAG_BEACON`] as its epoch seed — the composite's job in production
    /// ([`CellNode::new`](crate::cell_node::CellNode::new) / [`MixRelay::new`](crate::mix_relay::MixRelay::new)),
    /// where the value comes from the node's own beacon rather than a literal.
    fn test_relay(router: ThresholdRouter<F2>) -> RendezvousRelay<F2> {
        RendezvousRelay::new(router, TAG_BEACON)
    }

    use super::*;
    use fanos_aphantos::threshold::{HopLine, seal_onion};
    use fanos_aphantos::threshold_router::{launch_frame, line_member_coords};
    use fanos_field::F2;
    use fanos_geometry::{Line, Point};
    use fanos_pqcrypto::{HybridKemSecret, OnionKeyRatchet, SeedRng};
    use fanos_runtime::Epoch;

    /// A client's coordinate is not kept past the epoch it was useful in.
    ///
    /// Capacity alone was the whole bound, which makes retention a function of TRAFFIC: a busy relay forgets
    /// quickly and a quiet one keeps every binding indefinitely. That is backwards, and what it keeps is the
    /// worst thing a relay can hold — a table of which coordinate ran which anonymous session, waiting for
    /// whoever takes the machine. The neighbouring `hosts` map already retired by epoch (#58) and this one
    /// did not, one field over, for the same reason and against a more sensitive value.
    #[test]
    fn a_client_registration_does_not_outlive_the_epoch_that_could_use_it() {
        let line = Line::<F2>::at(0).coords();
        let combiner = Point::<F2>::new(line_member_coords::<F2>(line)[0]).unwrap();
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"expiry-id"));
        let mut relay =
            test_relay(ThresholdRouter::<F2>::new(combiner, &identity, 1, [0x71; 32]));

        let cookie = [0xC0u8; 16];
        relay.step(Instant(0), Input::Message { from: [1, 2, 3], frame: register_frame(cookie) });
        assert_eq!(relay.client_for(&cookie), Some([1, 2, 3]), "the registration binds in its own epoch");

        // One turn: still inside the grace window, so a session live across the boundary is not cut.
        relay.step(Instant(1), Input::Command(Command::AdvanceEpoch));
        relay.set_directory(MixDirectory::new());
        assert_eq!(
            relay.client_for(&cookie),
            Some([1, 2, 3]),
            "one epoch of grace, so a session in flight across the rotation still gets its replies"
        );

        // A second turn puts it out of reach of any honest client — the client's route rotated with the
        // beacon two epochs ago — so keeping the coordinate can serve nobody but a seizure.
        relay.step(Instant(2), Input::Command(Command::AdvanceEpoch));
        relay.set_directory(MixDirectory::new());
        assert_eq!(
            relay.client_for(&cookie),
            None,
            "the coordinate is gone once no honest client could still be listening against this cookie"
        );
        assert_eq!(relay.registrations(), 0, "and the slot is released, not merely unreadable");
    }

    #[test]
    fn the_registration_map_is_bounded_against_a_cookie_flood() {
        // Audit B2: an RdvRegister carries an attacker-chosen 16-byte cookie, so an unbounded map is a
        // single-peer remote OOM. Streaming MAX_REGISTRATIONS + K distinct cookies must leave the map capped
        // at MAX_REGISTRATIONS (the oldest evicted FIFO), and a re-registration must not grow it.
        let line = Line::<F2>::at(0).coords();
        let combiner = Point::<F2>::new(line_member_coords::<F2>(line)[0]).unwrap();
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"flood-id"));
        let mut relay =
            test_relay(ThresholdRouter::<F2>::new(combiner, &identity, 1, [0x5D; 32]));

        let cookie_of = |i: u32| -> SessionId {
            let mut c = [0u8; 16];
            c[..4].copy_from_slice(&i.to_be_bytes());
            c
        };
        let overflow = 50u32;
        for i in 0..(MAX_REGISTRATIONS as u32 + overflow) {
            relay.step(Instant(0), Input::Message { from: [1, 2, 3], frame: register_frame(cookie_of(i)) });
        }
        assert_eq!(relay.registrations(), MAX_REGISTRATIONS, "the map is capped, not unbounded");
        // The oldest `overflow` cookies were evicted FIFO; the most recent are retained.
        assert!(relay.client_for(&cookie_of(0)).is_none(), "the oldest registration was evicted");
        assert_eq!(
            relay.client_for(&cookie_of(MAX_REGISTRATIONS as u32 + overflow - 1)),
            Some([1, 2, 3]),
            "the newest registration is retained",
        );
        // A re-registration of a still-present cookie refreshes its coordinate without growing the map.
        let recent = cookie_of(MAX_REGISTRATIONS as u32 + overflow - 1);
        relay.step(Instant(0), Input::Message { from: [7, 7, 7], frame: register_frame(recent) });
        assert_eq!(relay.registrations(), MAX_REGISTRATIONS, "a re-registration does not grow the bounded map");
        assert_eq!(relay.client_for(&recent), Some([7, 7, 7]), "but it does refresh the coordinate");
    }

    #[test]
    fn a_relay_forwards_anonymous_replies_to_the_registered_client() {
        // The relay sits at a Fano line's combiner and peels the reply hop (t = 1). A non-combiner client
        // registers, then a reply onion sealed to that line arrives: the relay forwards the peeled reply
        // to the client's coordinate instead of surfacing a local anonymous delivery.
        let line = Line::<F2>::at(0).coords();
        let members = line_member_coords::<F2>(line);
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let onion_seed = [0x3D; 32];

        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"relay-id"));
        let mut relay = test_relay(ThresholdRouter::<F2>::new(
            combiner, &identity, 1, onion_seed,
        ));

        // A client at a non-combiner coordinate registers its session cookie with the relay.
        let client: Triple = [0x0C, 0x0C, 0x0C];
        let cookie: SessionId = *b"relay-cookie-001";
        relay.step(
            Instant(0),
            Input::Message {
                from: client,
                frame: register_frame(cookie),
            },
        );
        assert_eq!(
            relay.client_for(&cookie),
            Some(client),
            "the client is registered for its cookie"
        );

        // Seal a single-hop reply onion to the relay's line, sealed to the relay's forward-secure onion
        // public (the combiner is member 0; the other members never reply at t = 1). The service tags the
        // reply with the session cookie so the relay can demultiplex it.
        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x3D, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x3D, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        let mut payload = cookie.to_vec();
        payload.extend_from_slice(b"anonymous reply for the client");
        let onion = seal_onion(
            &[HopLine {
                line,
                members: &pubs,
            }],
            1,
            &payload,
            b"relay-seed",
        )
        .unwrap();

        // The reply arrives: the relay peels it (t = 1), matches the cookie, and forwards the full
        // cookie-tagged reply to the registered client wrapped in an RdvReply (the client strips the cookie).
        let effects = relay.step(
            Instant(1),
            Input::Message {
                from: [9, 9, 9],
                frame: launch_frame(line, &onion),
            },
        );
        let forwarded = effects
            .iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if *to == client => Some(frame.clone()),
                _ => None,
            })
            .expect("the relay forwards the peeled reply to the registered client");
        let (decoded, _) = decode_frame(&forwarded).unwrap();
        assert_eq!(decoded.frame_type(), Some(FrameType::RdvReply));
        assert_eq!(
            decoded.body,
            payload.as_slice(),
            "the full cookie-tagged reply is forwarded for the client to strip"
        );
        assert!(
            !effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, .. }) if *from == ANONYMOUS
            )),
            "the reply left for the client, not surfaced as a local anonymous delivery"
        );
    }

    #[test]
    fn a_bare_proxy_registration_must_reach_every_member_of_its_reply_line() {
        // #55: which member peels a given reply is the per-onion salted pick, so a cookie registered at ONE
        // node serves only the `1/(q+1)` of replies that happen to land there — the rest fall through as
        // local deliveries at a node that is not the client, and are silently lost. `register_targets`
        // exists so a caller cannot express the broken form by accident.
        let line = Line::<F2>::at(0).coords();
        let members = line_member_coords::<F2>(line);
        let cookie: SessionId = *b"bare-proxy-cook0";
        let targets = register_targets::<F2>(cookie, line);

        // Every member is a target, exactly once, and each carries the same registration frame.
        let mut coords: Vec<Triple> = targets.iter().map(|(c, _)| *c).collect();
        let mut expected = members.clone();
        coords.sort_unstable();
        expected.sort_unstable();
        assert_eq!(coords, expected, "the whole line is addressed, not one canonical combiner");
        assert!(
            targets.iter().all(|(_, f)| *f == register_frame(cookie)),
            "each member receives the same RdvRegister frame"
        );

        // And the requirement is real, not cosmetic: a relay that never saw the registration does NOT
        // forward — it passes the reply through as a local anonymous delivery, which is the silent loss.
        let unregistered = Point::<F2>::new(members[1]).unwrap();
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"unregistered-member"));
        let mut relay =
            test_relay(ThresholdRouter::<F2>::new(unregistered, &identity, 1, [0x4Cu8; 32]));
        let mut tagged = cookie.to_vec();
        tagged.extend_from_slice(b"a reply this member cannot route");
        let effects = relay.classify_anonymous(tagged);
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
            "a member without the cookie forwards nothing — hence every member must be registered"
        );
    }

    #[test]
    fn one_shared_relay_demultiplexes_two_clients_by_cookie() {
        // The property a shared cell relay needs: two clients register distinct cookies at the SAME
        // combiner; each service reply, tagged by cookie, is forwarded to the correct client — no
        // per-client relay instance.
        let line = Line::<F2>::at(0).coords();
        let members = line_member_coords::<F2>(line);
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let onion_seed = [0x7Eu8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"shared-relay"));
        let mut relay =
            test_relay(ThresholdRouter::<F2>::new(combiner, &identity, 1, onion_seed));

        let alice: Triple = [0x0A, 0x0A, 0x0A];
        let bob: Triple = [0x0B, 0x0B, 0x0B];
        let cookie_a: SessionId = *b"alice-cookie-000";
        let cookie_b: SessionId = *b"bob-cookie-00000";
        for (who, ck) in [(alice, cookie_a), (bob, cookie_b)] {
            relay.step(
                Instant(0),
                Input::Message {
                    from: who,
                    frame: register_frame(ck),
                },
            );
        }
        assert_eq!(relay.registrations(), 2, "both clients are registered");

        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7E, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7E, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        // Bob's reply, tagged with Bob's cookie, must reach Bob and not Alice.
        let mut payload = cookie_b.to_vec();
        payload.extend_from_slice(b"for bob only");
        let onion = seal_onion(
            &[HopLine {
                line,
                members: &pubs,
            }],
            1,
            &payload,
            b"shared-seed",
        )
        .unwrap();
        let effects = relay.step(
            Instant(1),
            Input::Message {
                from: [9, 9, 9],
                frame: launch_frame(line, &onion),
            },
        );
        let dests: Vec<Triple> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Send { to, .. } => Some(*to),
                _ => None,
            })
            .collect();
        assert!(dests.contains(&bob), "the cookie-tagged reply reached Bob");
        assert!(
            !dests.contains(&alice),
            "it did not leak to the other registered client"
        );
    }

    #[test]
    fn without_a_registered_client_the_relay_is_a_plain_router() {
        // Before any registration, an anonymous delivery passes through unchanged — the relay is inert.
        let line = Line::<F2>::at(1).coords();
        let members = line_member_coords::<F2>(line);
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let onion_seed = [0x4Du8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"relay-id-2"));
        let mut relay = test_relay(ThresholdRouter::<F2>::new(
            combiner, &identity, 1, onion_seed,
        ));
        assert_eq!(relay.registrations(), 0);

        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x4D, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x4D, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        let payload = b"unrelayed reply";
        let onion = seal_onion(
            &[HopLine {
                line,
                members: &pubs,
            }],
            1,
            payload,
            b"relay-seed-2",
        )
        .unwrap();
        let effects = relay.step(
            Instant(1),
            Input::Message {
                from: [9, 9, 9],
                frame: launch_frame(line, &onion),
            },
        );
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, payload: p })
                    if *from == ANONYMOUS && p.as_slice() == payload.as_slice()
            )),
            "with no client, the anonymous delivery passes through unchanged"
        );
    }

    /// §3b: a hidden service registers **anonymously** at its meeting combiner, then a matching client
    /// request peeled there is re-sealed to the service's dead-drop line and forwarded on — not surfaced
    /// locally. The relay learns neither the service's coordinate (it registered by onion, naming only a
    /// line) nor the client's (the request names only its own dead-drop line).
    #[test]
    fn a_relay_forwards_a_request_to_an_anonymously_registered_host() {
        use fanos_pqcrypto::HybridKemSecret;
        use fanos_rendezvous::{HOST_REGISTER_TAG, MixDirectory, line_member_coords, service_tag};

        // A KEM key at every Fano point, so any line's members can be sealed to (the host's forward route).
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let (_s, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xD0, i]));
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }

        // The relay sits at line L's combiner (t = 1: the combiner is member 0).
        let l = Line::<F2>::at(0).coords();
        let combiner = Point::<F2>::new(line_member_coords::<F2>(l)[0]).unwrap();
        let onion_seed = [0xA5u8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"host-relay-id"));
        let mut relay =
            test_relay(ThresholdRouter::<F2>::new(combiner, &identity, 1, onion_seed));
        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xA5, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xA5, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        // Seal a single-hop onion to L carrying `body`, peelable by the relay (member 0, t = 1).
        let seal_to_relay = |body: &[u8], seed: &[u8]| {
            let onion = seal_onion(&[HopLine { line: l, members: &pubs }], 1, body, seed).unwrap();
            launch_frame(l, &onion)
        };

        // The service's identity and its dead-drop line L_O (a different line). It registers by onion.
        let epoch = relay.router().onion_epoch();
        let mut srng = SeedRng::from_seed(b"a-hidden-service-key");
        let (signer, verifier) = fanos_pqcrypto::HybridSigSecret::generate(&mut srng);
        let (_kem, kem_pub) = HybridKemSecret::generate(&mut srng);
        let bundle = fanos_diaulos::bundle_from_identity(&verifier, &kem_pub);
        let tag = service_tag(&bundle, epoch, &TAG_BEACON);
        let drop_line = Line::<F2>::at(3).coords();
        let (_svc_keys, svc_reply_pub) =
            fanos_aphantos::nostos::ReplyKeys::generate(b"svc-deaddrop");
        relay.set_directory(dir.clone());
        let reg = HostRegister::onion(&bundle, &signer, epoch, &TAG_BEACON, svc_reply_pub.encode(), vec![drop_line], 1)
            .expect("the dead-drop line's members are in the directory");

        // **A route seizure is refused before the genuine registration is even made.** The tag is a public
        // function of the address, so anyone can compute it; what an attacker cannot do is present an identity
        // that hashes to it. Asserted FIRST, so the count below cannot be satisfied by the attacker's entry.
        let (a_signer, a_verifier) = fanos_pqcrypto::HybridSigSecret::generate(&mut srng);
        let a_bundle = fanos_diaulos::bundle_from_identity(&a_verifier, &kem_pub);
        let mut seizure = HostRegister { identity: a_bundle, sig: Vec::new(), ..reg.clone() };
        seizure.sig = a_signer.sign(&seizure.encode()).to_bytes();
        let mut bad_body = HOST_REGISTER_TAG.to_vec();
        bad_body.extend_from_slice(&seizure.encode());
        relay.step(Instant(0), Input::Message { from: [6, 6, 6], frame: seal_to_relay(&bad_body, b"bad") });
        assert_eq!(relay.hosts(), 0, "a registration claiming a tag its identity does not hash to is refused");

        let mut reg_body = HOST_REGISTER_TAG.to_vec();
        reg_body.extend_from_slice(&reg.encode());
        relay.step(Instant(0), Input::Message { from: [9, 9, 9], frame: seal_to_relay(&reg_body, b"reg") });
        assert_eq!(relay.hosts(), 1, "the anonymous host registration was bound by its tag");

        // A client request naming that service_tag, peeled at the relay, is forwarded to the dead-drop.
        let request = Request {
            cookie: *b"client-cookie-01",
            service_tag: tag,
            reply_circuit: vec![Line::<F2>::at(5).coords()],
            payload: b"a DIAULOS ClientHello".to_vec(),
            reply_pub: b"client-reply-key".to_vec(),
        }
        .encode();
        let effects =
            relay.step(Instant(1), Input::Message { from: [8, 8, 8], frame: seal_to_relay(&request, b"req") });
        // A member of the drop line, not its canonical combiner: the forward's launch target is the
        // per-onion salted pick (#55).
        let drop_members = line_member_coords::<F2>(drop_line);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Send { to, .. } if drop_members.contains(to))),
            "the request is re-sealed and forwarded to a member of the service's dead-drop line",
        );
        assert!(
            !effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, .. }) if *from == ANONYMOUS
            )),
            "the request left for the host, not surfaced locally (this node is not the service)",
        );

        // A request for an UNregistered tag falls through to a local anonymous delivery (unchanged behaviour).
        let other = Request {
            cookie: *b"client-cookie-02",
            service_tag: service_tag(b"some-other-service", Epoch::new(0), &TAG_BEACON),
            reply_circuit: vec![],
            payload: b"unrelated".to_vec(),
            reply_pub: vec![],
        }
        .encode();
        let effects =
            relay.step(Instant(2), Input::Message { from: [7, 7, 7], frame: seal_to_relay(&other, b"oth") });
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, .. }) if *from == ANONYMOUS
            )),
            "a request for no registered host surfaces locally, as before",
        );
    }

    /// The tag binding stated as the thing an adversary is denied (#132).
    ///
    /// A hidden service's identity is PUBLIC — a client must hold it to dial — and the epoch number is a
    /// counter. So while `service_tag` folded those two alone, every future epoch's tag was computable today
    /// against any known service. A meeting-line member matches inbound requests against that tag, so
    /// precomputing it is precomputing which requests to drop: a censor could pick and pre-position against
    /// its targets an unbounded number of epochs ahead of the traffic, while `meeting_line` — the other half
    /// of the same rotation — had folded the beacon in since E5 for exactly this reason.
    ///
    /// This test is the falsification of the fix. It registers a genuine service under one beacon and shows
    /// the SAME identity at the SAME epoch under a different beacon does not reach the registered entry:
    /// tags derived under a beacon this relay does not hold are not the tags it serves. Remove `beacon` from
    /// `service_tag`'s input and both halves collapse to one value, the second registration overwrites the
    /// first at the same key, and the final assertion fails.
    #[test]
    fn a_tag_computed_under_another_beacon_does_not_name_this_epochs_service() {
        use fanos_pqcrypto::HybridKemSecret;
        use fanos_rendezvous::{HOST_REGISTER_TAG, MixDirectory, line_member_coords, service_tag};

        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let (_s, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF1, i]));
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }
        let l = Line::<F2>::at(0).coords();
        let combiner = Point::<F2>::new(line_member_coords::<F2>(l)[0]).unwrap();
        let onion_seed = [0xF1u8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"beacon-bind-relay"));
        let mut relay =
            test_relay(ThresholdRouter::<F2>::new(combiner, &identity, 1, onion_seed));
        relay.set_directory(dir.clone());
        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF1, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF1, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        let seal_to_relay = |body: &[u8], seed: &[u8]| {
            launch_frame(l, &seal_onion(&[HopLine { line: l, members: &pubs }], 1, body, seed).unwrap())
        };

        let epoch = relay.router().onion_epoch();
        let mut srng = SeedRng::from_seed(b"a-service-under-two-beacons");
        let (signer, verifier) = fanos_pqcrypto::HybridSigSecret::generate(&mut srng);
        let (_kem, kem_pub) = HybridKemSecret::generate(&mut srng);
        let bundle = fanos_diaulos::bundle_from_identity(&verifier, &kem_pub);
        let drop_line = Line::<F2>::at(3).coords();
        let (_svc, svc_reply_pub) = fanos_aphantos::nostos::ReplyKeys::generate(b"two-beacon-deaddrop");

        // The genuine registration, under the beacon this relay holds.
        let reg = HostRegister::onion(&bundle, &signer, epoch, &TAG_BEACON, svc_reply_pub.encode(), vec![drop_line], 1)
            .expect("the dead-drop line's members are in the directory");
        let mut body = HOST_REGISTER_TAG.to_vec();
        body.extend_from_slice(&reg.encode());
        relay.step(Instant(0), Input::Message { from: [9, 9, 9], frame: seal_to_relay(&body, b"reg") });
        assert_eq!(relay.hosts(), 1, "the service registered under the epoch's beacon");

        // Everything an adversary who has NOT yet learned this beacon can build: the same public identity, the
        // same epoch, a validly-signed registration — under the wrong beacon. It is not a forgery, which is the
        // point: the signature checks out and the tag simply is not the one this epoch serves.
        let other_beacon = [0x3Cu8; 32];
        assert_ne!(service_tag(&bundle, epoch, &TAG_BEACON), service_tag(&bundle, epoch, &other_beacon));
        let stale = HostRegister::onion(&bundle, &signer, epoch, &other_beacon, svc_reply_pub.encode(), vec![drop_line], 1)
            .expect("the dead-drop line's members are in the directory");
        let mut stale_body = HOST_REGISTER_TAG.to_vec();
        stale_body.extend_from_slice(&stale.encode());
        relay.step(Instant(1), Input::Message { from: [9, 9, 9], frame: seal_to_relay(&stale_body, b"stale") });
        assert_eq!(
            relay.hosts(),
            1,
            "a registration whose tag was derived under a beacon this relay does not hold is refused — with \
             the epoch alone it would have hashed to the SAME key and silently replaced the genuine entry",
        );
        // Stated as behaviour rather than as map contents, because what matters is which requests the relay
        // FORWARDS. A tag it hosts is re-sealed onward and never surfaces here; an unknown tag falls through to
        // a local anonymous delivery.
        let request = |tag: [u8; 32]| {
            Request {
                cookie: *b"two-beacon-cli01",
                service_tag: tag,
                reply_circuit: vec![Line::<F2>::at(5).coords()],
                payload: b"a request naming a tag".to_vec(),
                reply_pub: b"client-reply-key".to_vec(),
            }
            .encode()
        };
        let fell_through = |effects: &[Effect]| {
            effects.iter().any(|e| {
                matches!(e, Effect::Notify(Notification::Delivered { from, .. }) if *from == ANONYMOUS)
            })
        };
        let good = relay.step(Instant(2), Input::Message {
            from: [8, 8, 8],
            frame: seal_to_relay(&request(service_tag(&bundle, epoch, &TAG_BEACON)), b"good"),
        });
        assert!(!fell_through(&good), "the tag bound to this epoch's beacon still reaches the service");
        let wrong = relay.step(Instant(3), Input::Message {
            from: [8, 8, 8],
            frame: seal_to_relay(&request(service_tag(&bundle, epoch, &other_beacon)), b"wrong"),
        });
        assert!(
            fell_through(&wrong),
            "a tag computed under any other beacon names no service here — which is the whole guarantee: an \
             adversary holding the public identity and an epoch number cannot name a future epoch's slot",
        );
    }

    #[test]
    fn a_rotated_epoch_retires_the_path_it_rotated_away_from() {
        use fanos_pqcrypto::HybridKemSecret;
        use fanos_rendezvous::{HOST_REGISTER_TAG, MixDirectory, line_member_coords, service_tag};

        // **What rotation was supposed to buy, and did not.** `service_tag = H(identity ‖ epoch)`, so a
        // service takes a DIFFERENT slot in `hosts` every epoch and the previous one was never overwritten —
        // nothing removed it. The map's only eviction was FIFO under capacity pressure, justified in its own
        // comment with "it re-registers each epoch anyway", which is exactly what leaves the old entry behind.
        //
        // An honest client never notices: it derives the tag from its own live epoch and will never compute
        // the old one again. The party that does notice is one that RECORDED the tag while it was current —
        // it can re-present it at any later epoch and this relay would still re-seal the request to the
        // service's old dead-drop line. So the design's "rotation caps a single enumeration's value to one
        // epoch" held for honest lookups and not for the adversary it was written about.
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let (_s, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xE0, i]));
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }
        let l = Line::<F2>::at(0).coords();
        let combiner = Point::<F2>::new(line_member_coords::<F2>(l)[0]).unwrap();
        let onion_seed = [0xB7u8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"retire-relay-id"));
        let mut relay =
            test_relay(ThresholdRouter::<F2>::new(combiner, &identity, 1, onion_seed));
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xB7, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xB7, 2]));
        let seal_to_relay = |body: &[u8], seed: &[u8], epoch: Epoch| {
            let ratchet = OnionKeyRatchet::new(onion_seed, epoch);
            let pubs = [ratchet.public(), &p1, &p2];
            let onion = seal_onion(&[HopLine { line: l, members: &pubs }], 1, body, seed).unwrap();
            launch_frame(l, &onion)
        };

        let epoch0 = relay.router().onion_epoch();
        let mut srng = SeedRng::from_seed(b"a-rotating-hidden-service");
        let (signer, verifier) = fanos_pqcrypto::HybridSigSecret::generate(&mut srng);
        let (_kem, kem_pub) = HybridKemSecret::generate(&mut srng);
        let bundle = fanos_diaulos::bundle_from_identity(&verifier, &kem_pub);
        let stale_tag = service_tag(&bundle, epoch0, &TAG_BEACON);
        let drop_line = Line::<F2>::at(3).coords();
        let (_svc_keys, svc_reply_pub) = fanos_aphantos::nostos::ReplyKeys::generate(b"retire-deaddrop");
        relay.set_directory(dir.clone());
        let reg =
            HostRegister::onion(&bundle, &signer, epoch0, &TAG_BEACON, svc_reply_pub.encode(), vec![drop_line], 1)
                .expect("the dead-drop line's members are in the directory");
        let mut reg_body = HOST_REGISTER_TAG.to_vec();
        reg_body.extend_from_slice(&reg.encode());
        relay.step(
            Instant(0),
            Input::Message { from: [9, 9, 9], frame: seal_to_relay(&reg_body, b"reg", epoch0) },
        );
        assert_eq!(relay.hosts(), 1, "the registration bound at the epoch it was minted for");

        // The adversary records the tag while it is current — a public value, so this costs it nothing. Kept
        // as an assertion rather than a binding: what it can do with the record is measured in the grace
        // test, for the reason given below.
        assert_eq!(stale_tag, service_tag(&bundle, epoch0, &TAG_BEACON), "the tag is public and recordable");

        // The cell's clock turns. The composite hands the relay the new epoch's directory, which is the one
        // moment a sans-I/O combiner can learn that its epoch moved at all.
        // Two advances, not one: the registration outlives its epoch by `HOST_GRACE_EPOCHS`, because a
        // client that has not yet adopted the new beacon is an honest client computing last epoch's tag —
        // see `a_client_one_epoch_behind_still_reaches_a_host_across_the_turn`, which is the test that found
        // the boundary rule this one originally asserted made every service unreachable once per epoch.
        relay.step(Instant(1), Input::Command(Command::AdvanceEpoch));
        relay.set_directory(dir.clone());
        relay.step(Instant(2), Input::Command(Command::AdvanceEpoch));
        let epoch1 = relay.router().onion_epoch();
        assert!(epoch1 > epoch0, "the router's onion epoch advanced");
        relay.set_directory(dir.clone());
        assert_eq!(
            relay.hosts(),
            0,
            "a registration minted for an epoch the relay has passed must be gone — it is unreachable by \
             every honest client, so keeping it can serve only whoever recorded its tag",
        );

        // **The request-level check lives in the grace test, not here, and the reason is a real limit rather
        // than convenience.** Past two turns the relay's onion ratchet no longer holds the key an onion
        // sealed at the registration epoch was built with (`retain = 1`), so a request from that far back
        // cannot be *peeled* at all — there is no reachable state in which a two-epoch-old tag is presented
        // and answered, which is exactly the property, and it makes the effect unobservable at this layer.
        //
        // What is observable is the map, and it is asserted above: the registration is gone. The reachable
        // half — a tag one epoch old, whose onion still peels — is measured in
        // `a_client_one_epoch_behind_still_reaches_a_host_across_the_turn`, which is where the grace window
        // and its bound both belong.
    }

    #[test]
    fn a_client_one_epoch_behind_still_reaches_a_host_across_the_turn() {
        use fanos_pqcrypto::HybridKemSecret;
        use fanos_rendezvous::{HOST_REGISTER_TAG, MixDirectory, line_member_coords, service_tag};

        // **The window my own retirement fix opened, measured.** `a_rotated_epoch_retires_the_path_it_rotated
        // _away_from` closes a real leak — a recorded tag reached a service's retired dead-drop for ever —
        // and it retired at `minted >= now`: strictly the current epoch, nothing older.
        //
        // But client and host derive the meeting line from `(epoch, beacon)` INDEPENDENTLY, so they turn at
        // different moments. A client that has not yet seen the new `BeaconReady` computes last epoch's tag
        // and is, for that window, an ordinary honest client — which is precisely why the host's accept loop
        // keeps `MAX_REPLY_KEYS = 3` epochs of dead-drop keys, and why the onion ratchet retains one past
        // epoch's secret so an in-flight onion still peels. Retiring at the boundary made the relay the one
        // component with no grace at all: every hidden service would go unreachable once per `epoch_period`,
        // and it would be reported as "the service is randomly down".
        //
        // So the retention window is derived, not chosen — the same derivation as `DIRECTORY_SLOT_EPOCHS`:
        // outlive the epoch by exactly the grace the rest of the system already extends, and no more.
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let (_s, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF1, i]));
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }
        let l = Line::<F2>::at(0).coords();
        let combiner = Point::<F2>::new(line_member_coords::<F2>(l)[0]).unwrap();
        let onion_seed = [0xD3u8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"grace-relay-id"));
        let mut relay =
            test_relay(ThresholdRouter::<F2>::new(combiner, &identity, 1, onion_seed));
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xD3, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xD3, 2]));
        let seal = |body: &[u8], seed: &[u8], epoch: Epoch| {
            let ratchet = OnionKeyRatchet::new(onion_seed, epoch);
            let pubs = [ratchet.public(), &p1, &p2];
            launch_frame(l, &seal_onion(&[HopLine { line: l, members: &pubs }], 1, body, seed).unwrap())
        };

        let epoch0 = relay.router().onion_epoch();
        let mut srng = SeedRng::from_seed(b"a-service-across-a-turn");
        let (signer, verifier) = fanos_pqcrypto::HybridSigSecret::generate(&mut srng);
        let (_kem, kem_pub) = HybridKemSecret::generate(&mut srng);
        let bundle = fanos_diaulos::bundle_from_identity(&verifier, &kem_pub);
        let lagging_tag = service_tag(&bundle, epoch0, &TAG_BEACON);
        let drop_line = Line::<F2>::at(3).coords();
        let (_svc, svc_reply_pub) = fanos_aphantos::nostos::ReplyKeys::generate(b"grace-deaddrop");
        relay.set_directory(dir.clone());
        let reg = HostRegister::onion(&bundle, &signer, epoch0, &TAG_BEACON, svc_reply_pub.encode(), vec![drop_line], 1)
            .expect("the dead-drop line's members are in the directory");
        let mut body = HOST_REGISTER_TAG.to_vec();
        body.extend_from_slice(&reg.encode());
        relay.step(Instant(0), Input::Message { from: [9, 9, 9], frame: seal(&body, b"reg", epoch0) });
        assert_eq!(relay.hosts(), 1, "the service registered for its epoch");

        // The cell's clock turns. The host will re-register at the new epoch, but a client that has not yet
        // adopted the new beacon is still computing `lagging_tag`.
        relay.step(Instant(1), Input::Command(Command::AdvanceEpoch));
        relay.set_directory(dir.clone());
        assert_eq!(
            relay.hosts(),
            1,
            "one epoch of grace: a client that has not yet seen the new beacon is an honest client, and the \
             host's own accept loop keeps three epochs of keys for exactly this skew",
        );

        let request = |tag: [u8; 32]| {
            Request {
                cookie: *b"lagging-client01",
                service_tag: tag,
                reply_circuit: vec![Line::<F2>::at(5).coords()],
                payload: b"a request from one epoch behind".to_vec(),
                reply_pub: b"client-reply-key".to_vec(),
            }
            .encode()
        };
        let epoch1 = relay.router().onion_epoch();
        let effects =
            relay.step(Instant(2), Input::Message { from: [8, 8, 8], frame: seal(&request(lagging_tag), b"lag", epoch1) });
        assert!(
            !effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, .. }) if *from == ANONYMOUS
            )),
            "the lagging client's request must still be FORWARDED to the service, not fall through as an \
             unknown tag — falling through is what makes a service look randomly down once per epoch",
        );

        // And the grace is exactly one epoch, not indefinite: a second turn retires it, so the leak the
        // previous test closes stays closed. A recorded tag buys an adversary one epoch, which is the same
        // window every other component already grants.
        relay.step(Instant(3), Input::Command(Command::AdvanceEpoch));
        relay.set_directory(dir.clone());
        assert_eq!(
            relay.hosts(),
            0,
            "past the grace window the registration is gone — the retirement property still holds, it is \
             just measured against the skew the rest of the system already tolerates",
        );
    }
}
