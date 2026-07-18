//! `NyxNode` — a sans-I/O anonymity-routing engine (spec §L5).
//!
//! A `NyxNode` originates anonymous circuits (on an application `Send`), and relays onions it
//! receives by peeling its own hop and forwarding the inner onion — using only the runtime's
//! `Input`/`Effect` ports, so the same engine runs under the simulator and a real transport.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_crypto::hash::hash_xof;
use fanos_crypto::hash_labeled;
use fanos_field::Field;
use fanos_geometry::{Point, Triple};
use fanos_nyx::build_circuit;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret};
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_wire::{FrameType, decode_frame, encode_frame};

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
}

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

    /// Forward an onion — immediately, or (when mixing is on) held for a sampled delay so a batch
    /// of onions leaves reordered (spec §L5, V7).
    fn forward(&mut self, next: Triple, onion: &[u8]) -> Vec<Effect> {
        let frame = Self::nyx_frame(onion);
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

    /// Emit one cover cell to a pseudo-randomly chosen known node and re-arm the cover timer, so
    /// the node's send pattern stays uniform whether or not it has real traffic (spec §L5, V8).
    fn emit_cover(&mut self) -> Vec<Effect> {
        let mut effects = Vec::new();
        let peers: Vec<Triple> = self.directory.entries.keys().copied().collect();
        if !peers.is_empty() {
            self.delay_seq = self.delay_seq.wrapping_add(1);
            let idx = (self.prf_unit("FANOS-v1/nyx-cover-dst", self.delay_seq) * peers.len() as f64)
                as usize;
            if let Some(&dst) = peers.get(idx.min(peers.len() - 1)) {
                // A cover cell is byte-indistinguishable from a real onion: the *same* Tessera frame
                // type carrying a full constant-size ([`sealed::ONION_LEN`]) block of keystream that
                // looks exactly like ciphertext (spec §5.5/V8). The recipient tries to peel it, the
                // KEM/AEAD fails on the random bytes, and it is dropped — the identical code path a
                // real onion addressed to the wrong relay takes, so cover and real are unobservable.
                let mut cell = alloc::vec![0u8; sealed::ONION_LEN];
                hash_xof("FANOS-v1/nyx-cover-body", &self.cover_material(), &mut cell);
                effects.push(Effect::Send {
                    to: dst,
                    frame: Self::nyx_frame(&cell),
                });
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

    /// Originate an anonymous circuit to `dest` carrying `payload`.
    fn originate(&mut self, dest: Triple, payload: &[u8]) -> Vec<Effect> {
        let Some(destination) = Point::<F>::new(dest) else {
            return Vec::new();
        };
        self.circuit_counter += 1;
        let mut circuit_seed = self.seed.to_vec();
        circuit_seed.extend_from_slice(&self.circuit_counter.to_be_bytes());

        let Some(circuit) = build_circuit(self.coord, destination, self.path_len, &circuit_seed)
        else {
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

    /// Handle an incoming frame: peel our hop and forward (with mixing) or deliver.
    fn on_frame(&mut self, frame: &[u8]) -> Vec<Effect> {
        let Ok((frame, _)) = decode_frame(frame) else {
            return Vec::new();
        };
        if frame.frame_type() != Some(FrameType::Tessera) {
            return Vec::new(); // cover cells and foreign frames are dropped here
        }
        match sealed::peel(frame.body, &self.kem_secret) {
            Ok(PeelOutcome::Forward { next, onion }) => self.forward(next, &onion),
            Ok(PeelOutcome::Deliver { payload, .. }) => {
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
                | Command::Join { .. }
                | Command::AdvanceEpoch,
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
        assert_ne!(derived([1u8; 32]), derived([2u8; 32]), "a fresh boot nonce freshens the seed");
        assert_eq!(derived([5u8; 32]), derived([5u8; 32]), "same seed+boot is deterministic");
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

        let mut node = NyxNode::new(Point::<F31>::at(0), secret, directory, [7u8; 32], [0u8; 32], 2)
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
