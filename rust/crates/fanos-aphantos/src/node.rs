//! `NyxNode` — a sans-I/O anonymity-routing engine (spec §L5).
//!
//! A `NyxNode` originates anonymous circuits (on an application `Send`), and relays onions it
//! receives by peeling its own hop and forwarding the inner onion — using only the runtime's
//! `Input`/`Effect` ports, so the same engine runs under the simulator and a real transport.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{Point, Triple};
use fanos_nyx::{Circuit, build_circuit, build_circuit_via_guard};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret};
use fanos_primitives::hash::hash_xof;
use fanos_primitives::hash_labeled;
use fanos_primitives::map_to_point;
use fanos_ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_wire::{FrameType, ProtocolError, decode_frame, encode_frame};

use crate::sealed::{self, PeelOutcome};

/// The anonymous-source sentinel used in delivery notifications — the whole point of NYX is
/// that the receiver does not learn the originator's coordinate.
pub const ANONYMOUS: Triple = [0, 0, 0];

/// The cover-traffic timer token (distinct from the per-hop mix-delay tokens, which are `1 + id`).
const COVER_TIMER: TimerToken = TimerToken(0);

/// A membership directory mapping node coordinates to their hybrid KEM public keys. In
/// production this is learned via authenticated line announcements (spec §7.8 JOIN); here it
/// is provided explicitly so the routing logic is testable.
#[derive(Clone, Default)]
pub struct Directory {
    entries: BTreeMap<Triple, HybridKemPublic>,
}

impl Directory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a node's KEM public key.
    pub fn insert(&mut self, coord: Triple, public: HybridKemPublic) {
        self.entries.insert(coord, public);
    }

    /// Look up a node's KEM public key.
    #[must_use]
    pub fn get(&self, coord: &Triple) -> Option<&HybridKemPublic> {
        self.entries.get(coord)
    }
}

/// A NYX anonymity-routing node.
pub struct NyxNode<F: Field> {
    coord: Point<F>,
    kem_secret: HybridKemSecret,
    directory: Directory,
    seed: [u8; 32],
    path_len: usize,
    circuit_counter: u64,
    /// Mean per-hop mixing delay (Poisson mixing, spec §L5/V7). Zero ⇒ forward immediately.
    mean_delay: Duration,
    /// Mean cover-traffic interval (spec §L5/V8). Zero ⇒ no cover.
    cover_interval: Duration,
    /// Whether cover traffic is currently running.
    covering: bool,
    /// Forwards held for their sampled mix delay, keyed by delay id (timer token = `1 + id`).
    pending: BTreeMap<u64, (Triple, Vec<u8>)>,
    /// Monotonic counter for delay ids and delay-sample domain separation.
    delay_seq: u64,
    /// Replay cache: the [`sealed::replay_tag`]s of recently-forwarded cells. A cell whose tag is
    /// already here is a replay and is dropped (path-confirmation defense). Bounded by
    /// [`MAX_REPLAY_CACHE`] with FIFO eviction so a flood of distinct cells cannot grow it without
    /// bound (a memory-DoS); [`replay_order`](Self::replay_order) tracks insertion order for eviction.
    replay_seen: BTreeSet<[u8; sealed::REPLAY_TAG_LEN]>,
    /// Insertion order for [`replay_seen`](Self::replay_seen)'s bounded FIFO eviction.
    replay_order: VecDeque<[u8; sealed::REPLAY_TAG_LEN]>,
    /// Real forwards awaiting a constant-rate send slot when cover is on (audit E6). Each slot emits
    /// exactly one cell — a queued real cell (which *displaces* a cover cell) if any, else cover — so
    /// the node's emitted volume is the slot count, independent of how much real traffic it carries: a
    /// flow-correlation adversary counting cells sees no signal. Bounded by [`MAX_OUTBOX`] (drop-oldest
    /// under overload) so a flood cannot grow it without bound. Empty (and unused) in the cover-off
    /// direct profile, where forwards leave immediately.
    outbox: VecDeque<(Triple, Vec<u8>)>,
}

/// Bound on the constant-rate [`outbox`](NyxNode::outbox): real forwards queued for a send slot. Beyond
/// this the oldest is dropped (the reliability layer retransmits) — bounded memory under a flood.
const MAX_OUTBOX: usize = 2048;

/// Bound on the replay cache (§L5): the count of recently-seen cell tags a relay retains. A replay
/// within this window is dropped; beyond it, key rotation (E4) is the second line of defence. Bounding
/// it keeps a flood of distinct cells from exhausting memory (audit A4 discipline).
const MAX_REPLAY_CACHE: usize = 8192;

impl<F: Field> NyxNode<F> {
    /// Create a node at `coord` with its KEM secret, a membership directory, an entropy seed,
    /// and a default circuit length.
    #[must_use]
    pub fn new(
        coord: Point<F>,
        kem_secret: HybridKemSecret,
        directory: Directory,
        seed: [u8; 32],
        boot_nonce: [u8; 32],
        path_len: usize,
    ) -> Self {
        // Mix fresh per-boot entropy into the node seed, so every PRF derived from it — the circuit
        // seeds (hence per-hop onion KEM ephemerals, layer keys, and AEAD nonces), the cover-cell
        // material, and the mix delays — does NOT repeat across restarts. `circuit_counter` resets to 0
        // on reboot, so with a bare persistent `seed` the first circuits after a restart would re-derive
        // identical per-hop keys and nonces: catastrophic AEAD `(key, nonce)` reuse (keystream + tag
        // reuse). `boot_nonce` MUST be fresh each boot (a CSPRNG draw in production); a fixed value keeps
        // a test deterministic (audit: onion nonce-counter reset-on-boot, the E3 latent instance).
        let mut material = seed.to_vec();
        material.extend_from_slice(&boot_nonce);
        let seed = hash_labeled("FANOS-v1/nyx-boot-seed", &material);
        Self {
            coord,
            kem_secret,
            directory,
            seed,
            path_len,
            circuit_counter: 0,
            mean_delay: Duration(0),
            cover_interval: Duration(0),
            covering: false,
            pending: BTreeMap::new(),
            delay_seq: 0,
            replay_seen: BTreeSet::new(),
            replay_order: VecDeque::new(),
            outbox: VecDeque::new(),
        }
    }

    /// Record a forwarded cell's replay `tag`, evicting the oldest once the cache is full (bounded FIFO).
    fn note_replay(&mut self, tag: [u8; sealed::REPLAY_TAG_LEN]) {
        if self.replay_seen.insert(tag) {
            self.replay_order.push_back(tag);
            if self.replay_order.len() > MAX_REPLAY_CACHE
                && let Some(old) = self.replay_order.pop_front()
            {
                self.replay_seen.remove(&old);
            }
        }
    }

    /// Enable Poisson mixing and cover traffic (spec §L5, V7/V8): each relayed onion is held for
    /// an exponential delay of mean `mean_delay` before forwarding (so a batch of onions is
    /// reordered — the anonymity set), and, once cover is started, the node emits an
    /// indistinguishable cover cell every `cover_interval` on average (so its send pattern is
    /// uniform regardless of real traffic). A zero interval leaves that behaviour off.
    #[must_use]
    pub fn with_mixing(mut self, mean_delay: Duration, cover_interval: Duration) -> Self {
        self.mean_delay = mean_delay;
        self.cover_interval = cover_interval;
        self
    }

    fn nyx_frame(onion: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_frame(FrameType::Tessera.code(), onion, &mut out);
        out
    }

    /// Per-cover-cell keystream material: the node seed diversified by the mix counter, so every
    /// cover cell is a fresh random-looking block (no two identical, and unlinkable to the seed).
    fn cover_material(&self) -> Vec<u8> {
        let mut data = self.seed.to_vec();
        data.extend_from_slice(&self.delay_seq.to_be_bytes());
        data
    }

    /// A uniform sample in `[0, 1)` from the node seed and a domain-separating counter.
    fn prf_unit(&self, tag: &str, counter: u64) -> f64 {
        let mut data = self.seed.to_vec();
        data.extend_from_slice(&counter.to_be_bytes());
        let digest = hash_labeled(tag, &data);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(digest.get(..8).unwrap_or(&[0u8; 8]));
        u64::from_be_bytes(bytes) as f64 / (u64::MAX as f64 + 1.0)
    }

    /// Sample an exponential mixing delay with the configured mean (inverse-CDF `−mean·ln u`).
    fn sample_delay(&mut self) -> Duration {
        self.delay_seq = self.delay_seq.wrapping_add(1);
        let mean_ns = self.mean_delay.as_nanos() as f64;
        let u = self.prf_unit("FANOS-v1/nyx-mix", self.delay_seq).max(1e-12);
        let ns = (-mean_ns * u.ln()) as u64;
        Duration(ns.max(1))
    }

    /// Forward an onion. With cover on (the Full/anonymity profile) the cell is **queued for the next
    /// constant-rate send slot** (audit E6): it will displace a cover cell rather than add to the send
    /// rate, so the node's emitted volume never tracks its real traffic. With cover off (the direct
    /// profile) it leaves immediately, or — if a per-cell mixing delay is set — is held for a sampled
    /// exponential delay so a batch leaves reordered (spec §L5, V7).
    fn forward(&mut self, next: Triple, onion: &[u8]) -> Vec<Effect> {
        let frame = Self::nyx_frame(onion);
        if self.cover_interval.as_nanos() != 0 {
            // Constant-rate: enqueue (bounded, drop-oldest under overload) and let the slot loop drain
            // it. Start the slot loop if it is not already running, so queued cells are guaranteed to
            // leave even before a `StartHeartbeat`.
            if self.outbox.len() >= MAX_OUTBOX {
                self.outbox.pop_front();
            }
            self.outbox.push_back((next, frame));
            return if self.covering {
                Vec::new()
            } else {
                self.start_cover()
            };
        }
        if self.mean_delay.as_nanos() == 0 {
            return alloc::vec![Effect::Send { to: next, frame }];
        }
        let delay = self.sample_delay();
        let id = self.delay_seq;
        self.pending.insert(id, (next, frame));
        alloc::vec![Effect::ArmTimer {
            token: TimerToken(1 + id),
            after: delay,
        }]
    }

    /// Emit one **send slot** and re-arm the next (spec §L5, V8; audit E6). Every slot emits exactly one
    /// cell, so the node's send rate is constant whether or not it carries real traffic. If a real
    /// forward is queued it is sent — *displacing* a cover cell, not adding to the rate — picked
    /// pseudo-randomly from the [`outbox`](Self::outbox) so a batch leaves reordered (the mixing/V7
    /// property). Otherwise a cover cell is emitted: a byte-indistinguishable constant-size
    /// ([`sealed::ONION_LEN`]) block of keystream that looks exactly like ciphertext, which the
    /// recipient fails to peel and drops — the same path a real onion at the wrong relay takes, so cover
    /// and real are unobservable.
    fn emit_cover(&mut self) -> Vec<Effect> {
        let mut effects = Vec::new();
        if self.outbox.is_empty() {
            // No queued real cell: emit a cover cell to a pseudo-random known peer.
            let peers: Vec<Triple> = self.directory.entries.keys().copied().collect();
            if !peers.is_empty() {
                self.delay_seq = self.delay_seq.wrapping_add(1);
                let idx = (self.prf_unit("FANOS-v1/nyx-cover-dst", self.delay_seq)
                    * peers.len() as f64) as usize;
                if let Some(&dst) = peers.get(idx.min(peers.len() - 1)) {
                    let mut cell = alloc::vec![0u8; sealed::ONION_LEN];
                    hash_xof("FANOS-v1/nyx-cover-body", &self.cover_material(), &mut cell);
                    effects.push(Effect::Send {
                        to: dst,
                        frame: Self::nyx_frame(&cell),
                    });
                }
            }
        } else {
            // A queued real cell displaces this cover slot; the random pick reorders the batch (V7).
            self.delay_seq = self.delay_seq.wrapping_add(1);
            let idx = (self.prf_unit("FANOS-v1/nyx-slot-pick", self.delay_seq)
                * self.outbox.len() as f64) as usize;
            if let Some((to, frame)) = self.outbox.remove(idx.min(self.outbox.len() - 1)) {
                effects.push(Effect::Send { to, frame });
            }
        }
        if self.covering && self.cover_interval.as_nanos() > 0 {
            self.delay_seq = self.delay_seq.wrapping_add(1);
            let u = self
                .prf_unit("FANOS-v1/nyx-cover-gap", self.delay_seq)
                .max(1e-12);
            let gap = (-(self.cover_interval.as_nanos() as f64) * u.ln()) as u64;
            effects.push(Effect::ArmTimer {
                token: COVER_TIMER,
                after: Duration(gap.max(1)),
            });
        }
        effects
    }

    /// The node's stable **guard**: a fixed first-hop relay derived from the node seed alone — not the
    /// destination, not the circuit counter — so the client always enters through the same relay. A
    /// fixed entry bounds the predecessor attack (Wright et al., NDSS'02): with a rotating first hop an
    /// adversary holding a fraction `f` of relays is the initiator's direct successor on ~`f` of every
    /// circuit and identifies it after ~`1/f` rounds; with a guard it sees the initiator only if it
    /// controls that one guard (probability ~`f`, once), independent of the round count. Derived by
    /// rejection so it never coincides with the node itself (a self-loop is no guard).
    fn guard(&self) -> Point<F> {
        for i in 0..8u8 {
            let mut data = self.seed.to_vec();
            data.push(i);
            let g = map_to_point::<F>("FANOS-v1/nyx-guard", &data);
            if g != self.coord {
                return g;
            }
        }
        self.coord // astronomically unlikely; `build_circuit_via_guard` then falls back to guardless
    }

    /// A fresh, monotonically-distinct per-circuit seed derived from this node's own entropy.
    /// Shared by every circuit-building path ([`next_circuit`](Self::next_circuit) and
    /// [`build_verifiable_circuit`](Self::build_verifiable_circuit)), so `circuit_counter` is
    /// consumed exactly once per circuit however it is built.
    fn next_seed(&mut self) -> Vec<u8> {
        self.circuit_counter += 1;
        let mut circuit_seed = self.seed.to_vec();
        circuit_seed.extend_from_slice(&self.circuit_counter.to_be_bytes());
        circuit_seed
    }

    /// Build a fresh **outbound** circuit `self.coord → … → dest` — guard-anchored
    /// (predecessor-attack bound), falling back to a fully derived circuit only for a 1-hop path or
    /// the rare guard/source/dest collision. Used by [`originate`](Self::originate); `None` on a
    /// degenerate request (see [`build_circuit`]).
    fn next_circuit(&mut self, dest: Point<F>) -> Option<(Circuit<F>, Vec<u8>)> {
        let circuit_seed = self.next_seed();
        let guard = self.guard();
        let circuit = build_circuit_via_guard(self.coord, guard, dest, self.path_len, &circuit_seed)
            .or_else(|| build_circuit(self.coord, dest, self.path_len, &circuit_seed))?;
        Some((circuit, circuit_seed))
    }

    /// Originate an anonymous circuit to `dest` carrying `payload`.
    fn originate(&mut self, dest: Triple, payload: &[u8]) -> Vec<Effect> {
        let Some(destination) = Point::<F>::new(dest) else {
            return Vec::new();
        };
        let Some((circuit, circuit_seed)) = self.next_circuit(destination) else {
            return Vec::new();
        };
        let relays = circuit.relays();
        // Peeling relays are r_1 … r_L; gather each one's public key from the directory.
        let mut relay_keys: Vec<&HybridKemPublic> = Vec::with_capacity(circuit.hop_count());
        for relay in relays.iter().skip(1) {
            match self.directory.get(&relay.coords()) {
                Some(public) => relay_keys.push(public),
                None => return Vec::new(), // a relay is unknown — cannot route
            }
        }

        let Ok(onion) = sealed::build(&circuit, &relay_keys, payload, &circuit_seed) else {
            return Vec::new();
        };
        let Some(first_relay) = relays.get(1) else {
            return Vec::new();
        };
        alloc::vec![Effect::Send {
            to: first_relay.coords(),
            frame: Self::nyx_frame(&onion),
        }]
    }

    /// Build a fresh **reply** circuit `launch → … → self.coord` — the mirror image of
    /// [`next_circuit`](Self::next_circuit): it ends AT this node rather than starting from it, so
    /// this node's own KEM secret is the one that peels the final `Deliver` layer. `launch` is a
    /// nominal entry label (folded into the holonomy chain like any other hop
    /// — see [`fanos_nyx::ratchet::circuit_holonomy`] — but never a real routing step *this* node
    /// takes: whoever seals a reply onto this circuit launches it at `circuit.relays()[1]`'s
    /// combiner directly, the same way [`originate`](Self::originate) does for a forward circuit).
    /// Retained (never sent) so the caller can hold `(circuit, seed)` and later verify a delivery's
    /// holonomy against it via [`verified_deliver`](Self::verified_deliver) (spec §5.4).
    ///
    /// This is the "reply circuit" half of NYX path-integrity verification. Recomputing a
    /// delivery's expected holonomy needs the *exact* circuit and seed it was built under; no relay
    /// or third party is ever given enough to do that (the tag rides encrypted end-to-end — see
    /// [`crate::sealed`]'s module doc), and a destination cannot honestly reconstruct an
    /// *originator's* outbound circuit either — that would require learning who built it, breaking
    /// the "receiver never learns the originator" property this engine exists to uphold
    /// ([`ANONYMOUS`]). The one party who can soundly verify is whoever built the circuit in the
    /// first place: a caller retains `(circuit, seed)` from this call, hands the routing info
    /// (circuit + relay keys) to a peer end-to-end encrypted (inside a request payload — an
    /// application-layer concern above this engine) so the peer can address a reply through it, and
    /// checks the reply it eventually receives with [`verified_deliver`](Self::verified_deliver).
    #[must_use]
    pub fn build_verifiable_circuit(&mut self, launch: Triple) -> Option<(Circuit<F>, Vec<u8>)> {
        let launch_point = Point::<F>::new(launch)?;
        let circuit_seed = self.next_seed();
        let circuit = build_circuit(launch_point, self.coord, self.path_len, &circuit_seed)?;
        Some((circuit, circuit_seed))
    }

    /// Peel `frame`, expecting it to be the **final delivery** of a circuit this node itself built
    /// (see [`build_verifiable_circuit`](Self::build_verifiable_circuit)) — the same peel
    /// [`step`](Engine::step) drives, but additionally verifying the accumulated holonomy against
    /// `circuit`/`seed` before accepting the payload (spec §5.4). `Ok(payload)` only for a
    /// genuinely verified, in-order delivery; every other outcome is rejected, never handed to the
    /// caller:
    /// * a malformed frame or wrong frame type — [`ProtocolError::Malformed`];
    /// * `Forward` (not yet at the destination — `circuit` does not match what actually
    ///   happened) — [`ProtocolError::PathBroken`];
    /// * a peel failure (wrong relay layer / tampered / replay) — [`ProtocolError::Malformed`];
    /// * a holonomy mismatch (an inserted or substituted hop) — [`ProtocolError::HolonomyFail`].
    pub fn verified_deliver(
        &mut self,
        frame: &[u8],
        circuit: &Circuit<F>,
        seed: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let Ok((decoded, _)) = decode_frame(frame) else {
            return Err(ProtocolError::Malformed);
        };
        if decoded.frame_type() != Some(FrameType::Tessera) {
            return Err(ProtocolError::Malformed);
        }
        // The same replay defense `on_frame` applies: a cell whose tag we have already accepted
        // (forwarded or delivered) here is a replay, dropped before it can be re-verified.
        let tag = sealed::replay_tag(decoded.body);
        if let Some(tag) = tag
            && self.replay_seen.contains(&tag)
        {
            return Err(ProtocolError::Malformed);
        }
        match sealed::peel(decoded.body, &self.kem_secret) {
            Ok(PeelOutcome::Deliver { payload, holonomy }) => {
                // Record the tag on any successful peel — same rule as `on_frame` — before acting
                // on the outcome, so a holonomy failure still marks this exact cell seen.
                if let Some(tag) = tag {
                    self.note_replay(tag);
                }
                sealed::verify_delivery(circuit, seed, holonomy)?;
                Ok(payload)
            }
            Ok(PeelOutcome::Forward { .. }) => {
                if let Some(tag) = tag {
                    self.note_replay(tag);
                }
                Err(ProtocolError::PathBroken)
            }
            Err(_) => Err(ProtocolError::Malformed),
        }
    }

    /// Handle an incoming frame: peel our hop and forward (with mixing) or deliver.
    fn on_frame(&mut self, frame: &[u8]) -> Vec<Effect> {
        let Ok((frame, _)) = decode_frame(frame) else {
            return Vec::new();
        };
        if frame.frame_type() != Some(FrameType::Tessera) {
            return Vec::new(); // cover cells and foreign frames are dropped here
        }
        // Replay defense (before the expensive decapsulation): a cell whose tag we have already
        // forwarded is a replay — drop it, so an adversary cannot re-inject a captured cell to make us
        // re-forward it and confirm we are on its path.
        let tag = sealed::replay_tag(frame.body);
        if let Some(tag) = tag
            && self.replay_seen.contains(&tag)
        {
            return Vec::new();
        }
        match sealed::peel(frame.body, &self.kem_secret) {
            Ok(PeelOutcome::Forward { next, onion }) => {
                // Record the tag only on a *successful* peel: a cell that fails to peel (not our layer,
                // tampered) never enters the cache, so a flood of junk cannot evict genuine tags.
                if let Some(tag) = tag {
                    self.note_replay(tag);
                }
                self.forward(next, &onion)
            }
            Ok(PeelOutcome::Deliver { payload, .. }) => {
                if let Some(tag) = tag {
                    self.note_replay(tag);
                }
                alloc::vec![Effect::Notify(Notification::Delivered {
                    from: ANONYMOUS,
                    payload,
                })]
            }
            Err(_) => Vec::new(), // not our layer / tampered — drop
        }
    }

    /// A fired timer: release a delayed forward, or emit the next cover cell.
    fn on_timer(&mut self, token: TimerToken) -> Vec<Effect> {
        if token == COVER_TIMER {
            return if self.covering {
                self.emit_cover()
            } else {
                Vec::new()
            };
        }
        match self.pending.remove(&(token.0 - 1)) {
            Some((to, frame)) => alloc::vec![Effect::Send { to, frame }],
            None => Vec::new(),
        }
    }

    /// Begin emitting cover traffic (if a cover interval is configured).
    fn start_cover(&mut self) -> Vec<Effect> {
        if self.cover_interval.as_nanos() == 0 {
            return Vec::new();
        }
        self.covering = true;
        alloc::vec![Effect::ArmTimer {
            token: COVER_TIMER,
            after: self.cover_interval,
        }]
    }
}

impl<F: Field> Engine for NyxNode<F> {
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // Reused as "begin cover traffic": a NYX node has no heartbeat, but the same lifecycle
            // signal starts its steady cover emission (spec §L5, V8).
            Input::Command(Command::StartHeartbeat) => self.start_cover(),
            Input::Command(Command::Send { to, payload }) => self.originate(to, &payload),
            Input::Timer(token) => self.on_timer(token),
            Input::Message { frame, .. } => self.on_frame(&frame),
            // A NYX node ignores the overlay's diagnose/observe/storage/membership commands.
            Input::Command(
                Command::Diagnose
                | Command::Observe
                | Command::Put { .. }
                | Command::Get { .. }
                | Command::SampleAvailability { .. }
                | Command::Join { .. }
                | Command::AdvanceEpoch
                | Command::Reseat { .. },
            ) => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord.coords()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use fanos_field::F31;
    use fanos_pqcrypto::SeedRng;

    use super::*;

    #[test]
    fn a_fresh_boot_nonce_freshens_the_seed_so_reboots_dont_reuse_onion_nonces() {
        // Audit (onion nonce-counter reset-on-boot): every circuit/cover/delay PRF derives from the node
        // seed, and `circuit_counter` resets to 0 on restart — so the seed itself must be freshened per
        // boot, or a reboot re-derives identical per-hop onion keys and AEAD nonces (catastrophic reuse).
        // Same `seed` + different `boot_nonce` ⇒ DIFFERENT derived seed; same (seed, boot_nonce) is
        // deterministic (replayable).
        let derived = |boot: [u8; 32]| {
            let (secret, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"boot-seed"));
            NyxNode::<F31>::new(Point::at(0), secret, Directory::new(), [9u8; 32], boot, 2).seed
        };
        assert_ne!(
            derived([1u8; 32]),
            derived([2u8; 32]),
            "a fresh boot nonce freshens the seed"
        );
        assert_eq!(
            derived([5u8; 32]),
            derived([5u8; 32]),
            "same seed+boot is deterministic"
        );
    }

    /// A cover cell must be byte-indistinguishable from a real onion: the same `Tessera` frame type,
    /// the same constant [`sealed::ONION_LEN`] size, and it must simply fail to peel (the drop path a
    /// wrong-relay real onion takes) — never a give-away short `Cover`-typed frame (spec §5.5/V8).
    #[test]
    fn a_cover_cell_is_indistinguishable_from_a_real_onion() {
        // A node with one directory peer and cover enabled.
        let mut rng = SeedRng::from_seed(b"nyx-cover-node");
        let (secret, _public) = HybridKemSecret::generate(&mut rng);
        let (peer_secret, peer_public) = HybridKemSecret::generate(&mut rng);
        let mut directory = Directory::new();
        let peer_coord = Point::<F31>::at(9).coords();
        directory.insert(peer_coord, peer_public);

        let mut node = NyxNode::new(
            Point::<F31>::at(0),
            secret,
            directory,
            [7u8; 32],
            [0u8; 32],
            2,
        )
        .with_mixing(Duration(0), Duration::from_millis(200));

        // Start cover, then fire the cover timer to emit one cell.
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let effects = node.step(Instant(1), Input::Timer(COVER_TIMER));

        let frame = effects
            .iter()
            .find_map(|e| match e {
                Effect::Send { frame, .. } => Some(frame.clone()),
                _ => None,
            })
            .unwrap(); // a cover cell was emitted

        // Same frame type and same constant size as a real onion.
        let (decoded, _) = decode_frame(&frame).unwrap();
        assert_eq!(
            decoded.frame_type(),
            Some(FrameType::Tessera),
            "cover rides the real onion frame type, not a distinguishable Cover type"
        );
        assert_eq!(
            decoded.body.len(),
            sealed::ONION_LEN,
            "cover cell is the constant onion size"
        );
        // And it behaves like a wrong-relay onion: peeling fails and it is dropped.
        assert!(
            sealed::peel(decoded.body, &peer_secret).is_err(),
            "a cover cell does not peel — the same drop path a real onion takes"
        );
    }
}
