//! The distributed randomness **beacon** as a running node engine (spec §L3, audit E5) — the live
//! epoch clock that makes E5 (unpredictable rendezvous) and E4 (relay-key rotation) operational.
//!
//! [`fanos_vrf::beacon`] verifies the *cryptography* (pairing-free distributed VRF over the DKG);
//! [`BeaconNode`] makes it a **networked protocol**, exactly as [`crate::DkgNode`] does for the DKG.
//! Each node holds the group commitment (a DKG output, agreed by all honest nodes) and — if it is an
//! **anchor** — its beacon share. Per epoch:
//!
//! 1. On `Command::AdvanceEpoch` an anchor computes its partial `σ_i = s_i·M(next_epoch)` and floods a
//!    `BeaconPartial` to the cell.
//! 2. Any node verifies each partial's DLEQ against the group commitment and buffers it; once a
//!    threshold of distinct partials is in, it assembles a [`BeaconRound`], re-checks it, and **adopts**
//!    the epoch's public seed.
//! 3. It floods the assembled round (`Beacon` frame) so pure consumers (no share) adopt too, and emits
//!    [`Notification::BeaconReady`] carrying `(epoch, seed)` for the node driver to fold into the
//!    rendezvous meeting line and to rotate the E4 onion keys.
//!
//! Because the combined `σ = x·M` is subset-independent, every node adopts the **same** seed regardless
//! of which partials it happened to assemble; adoption is monotone (forward-only), so re-floods
//! terminate. Trust is in the algebra (every partial's DLEQ is checked against the public commitment),
//! never in the peer that relayed it — a forged partial or round is dropped, not adopted.

use std::collections::BTreeMap;

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_runtime::{Command, Effect, Engine, Epoch, Input, Instant, Notification};
use fanos_vrf::beacon::{BeaconPartial, BeaconRound, PARTIAL_LEN, partial_eval, verify_partial};
use fanos_vrf::vss::{VssCommitment, VssShare};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// Cap on partials buffered per in-progress epoch. A cell has at most `N` anchors, so honest operation
/// never approaches this; the cap bounds memory against a peer flooding forged `BeaconPartial`s (each
/// still fails its DLEQ, so none is ever adopted — this only bounds the buffer).
const MAX_PARTIALS: usize = 256;

/// A node running the distributed randomness beacon over its cell.
pub struct BeaconNode<F: Field> {
    coord: Point<F>,
    n: usize,
    threshold: usize,
    /// This node's beacon share — `Some` for an **anchor** that contributes partials, `None` for a pure
    /// consumer (which still verifies and adopts flooded rounds).
    share: Option<VssShare>,
    /// The group commitment every node verifies partials and rounds against (a DKG output; identical
    /// across all honest nodes, which fold the same qualified set).
    commitment: VssCommitment,
    /// The current adopted beacon epoch and its public seed (genesis all-zero until the first round).
    epoch: Epoch,
    seed: [u8; 32],
    /// Verified partials collected for each not-yet-adopted future epoch, until a round assembles.
    pending: BTreeMap<Epoch, Vec<BeaconPartial>>,
    /// The current epoch's assembled round, cached so this node can answer a `BeaconReq` pull-sync from a
    /// joining node (spec §7.8 bootstrap) — `None` until the first round is adopted.
    current_round: Option<BeaconRound>,
}

impl<F: Field> BeaconNode<F> {
    /// A beacon node at `coord`, verifying against the group `commitment` at `threshold`. `share` is
    /// this node's DKG beacon share if it is an anchor (it then contributes partials), else `None`.
    /// Starts at [`Epoch::ZERO`] with the genesis (all-zero) seed until the first round is adopted.
    #[must_use]
    pub fn new(
        coord: Point<F>,
        share: Option<VssShare>,
        commitment: VssCommitment,
        threshold: usize,
    ) -> Self {
        Self {
            coord,
            n: Plane::<F>::N as usize,
            threshold,
            share,
            commitment,
            epoch: Epoch::ZERO,
            seed: [0u8; 32],
            pending: BTreeMap::new(),
            current_round: None,
        }
    }

    /// The current beacon epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The current public beacon seed (all-zero genesis until the first round is adopted).
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Broadcast `frame` to every *other* cell member.
    fn broadcast(&self, frame: &[u8]) -> Vec<Effect> {
        let me = self.coord.coords();
        (0..self.n)
            .map(|i| Point::<F>::at(i).coords())
            .filter(|&c| c != me)
            .map(|to| Effect::Send {
                to,
                frame: frame.to_vec(),
            })
            .collect()
    }

    /// Begin producing the next epoch's beacon: an anchor floods its partial and folds it in. A pure
    /// consumer (no share) is inert here — it only adopts rounds others assemble.
    fn advance(&mut self) -> Vec<Effect> {
        let target = self.epoch.next();
        let partial = match &self.share {
            Some(share) => partial_eval(share, target),
            None => return Vec::new(),
        };
        let mut effects = self.broadcast(&partial_frame(target, &partial));
        self.buffer(target, partial);
        effects.extend(self.try_assemble(target));
        effects
    }

    /// Fold a verified partial into the pending set for a future `epoch` (deduped by index, bounded).
    fn buffer(&mut self, epoch: Epoch, partial: BeaconPartial) {
        if epoch <= self.epoch {
            return; // a seed for this or a later epoch is already adopted
        }
        let bucket = self.pending.entry(epoch).or_default();
        if bucket.len() >= MAX_PARTIALS || bucket.iter().any(|p| p.index() == partial.index()) {
            return;
        }
        bucket.push(partial);
    }

    /// If `epoch`'s pending partials reach the threshold, assemble + verify the round, adopt its seed,
    /// flood the round to the cell, and announce it.
    fn try_assemble(&mut self, epoch: Epoch) -> Vec<Effect> {
        if epoch <= self.epoch {
            return Vec::new();
        }
        let round = match self.pending.get(&epoch) {
            Some(bucket) => BeaconRound::assemble(epoch, bucket, self.threshold),
            None => None,
        };
        let Some(round) = round else {
            return Vec::new();
        };
        let Some(seed) = round.verify_and_seed(&self.commitment, self.threshold) else {
            return Vec::new();
        };
        self.adopt_and_announce(epoch, seed, round)
    }

    /// A received round: verify it against the group commitment and, if strictly newer, adopt + re-flood.
    fn on_round(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some(round) = BeaconRound::from_bytes(body) else {
            return Vec::new();
        };
        let epoch = round.epoch();
        if epoch <= self.epoch {
            return Vec::new(); // not newer — drop (terminates the flood)
        }
        let Some(seed) = round.verify_and_seed(&self.commitment, self.threshold) else {
            return Vec::new();
        };
        self.adopt_and_announce(epoch, seed, round)
    }

    /// A received partial: verify its DLEQ against the group commitment, buffer it, and try to assemble.
    fn on_partial(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((epoch, partial)) = parse_partial(body) else {
            return Vec::new();
        };
        if epoch <= self.epoch || !verify_partial(&partial, epoch, &self.commitment) {
            return Vec::new();
        }
        self.buffer(epoch, partial);
        self.try_assemble(epoch)
    }

    /// Adopt a new epoch + seed (monotone), dropping now-stale pending partials.
    fn adopt(&mut self, epoch: Epoch, seed: [u8; 32]) {
        self.epoch = epoch;
        self.seed = seed;
        self.pending.retain(|&e, _| e > epoch);
    }

    /// Adopt `round`'s epoch + seed, cache the round so this node can answer a later `BeaconReq`, and
    /// announce it (flood to the cell + notify the driver).
    fn adopt_and_announce(
        &mut self,
        epoch: Epoch,
        seed: [u8; 32],
        round: BeaconRound,
    ) -> Vec<Effect> {
        self.adopt(epoch, seed);
        let effects = self.announce(epoch, seed, &round);
        self.current_round = Some(round);
        effects
    }

    /// Flood `round` to the cell and emit the `BeaconReady` notification for the driver.
    fn announce(&self, epoch: Epoch, seed: [u8; 32], round: &BeaconRound) -> Vec<Effect> {
        let mut effects = self.broadcast(&round_frame(round));
        effects.push(Effect::Notify(Notification::BeaconReady { epoch, seed }));
        effects
    }

    /// Answer a joining node's `BeaconReq` pull-sync: send it the current epoch's round (which it verifies
    /// against the group commitment and adopts). Silent until this node has itself adopted a round.
    fn on_beacon_req(&self, from: Triple) -> Vec<Effect> {
        match &self.current_round {
            Some(round) => std::vec![Effect::Send {
                to: from,
                frame: round_frame(round),
            }],
            None => Vec::new(),
        }
    }

    /// Request the current beacon from the cell on join (spec §7.8 bootstrap): broadcast a `BeaconReq`, to
    /// which any synced peer replies with its round — so a node that missed live rounds still adopts the
    /// current epoch's verified seed rather than assuming one.
    fn request_sync(&self) -> Vec<Effect> {
        self.broadcast(&encode(FrameType::BeaconReq, &[]))
    }
}

impl<F: Field> Engine for BeaconNode<F> {
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // The epoch-advance trigger (a timer/driver tick): an anchor proposes the next epoch's beacon.
            Input::Command(Command::AdvanceEpoch) => self.advance(),
            // On join, pull the current beacon from the cell (spec §7.8 bootstrap).
            Input::Command(Command::StartHeartbeat) => self.request_sync(),
            Input::Message { from, frame } => match decode_frame(&frame) {
                Ok((f, _)) => match f.frame_type() {
                    Some(FrameType::BeaconPartial) => self.on_partial(f.body),
                    Some(FrameType::Beacon) => self.on_round(f.body),
                    Some(FrameType::BeaconReq) => self.on_beacon_req(from),
                    _ => Vec::new(),
                },
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord.coords()
    }
}

/// `BeaconPartial` frame body: `epoch(8B BE) ‖ partial`. The epoch travels alongside because a partial
/// is verified against it (its DLEQ binds the epoch), so a replay under a different epoch is rejected.
fn partial_frame(epoch: Epoch, partial: &BeaconPartial) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + PARTIAL_LEN);
    body.extend_from_slice(&epoch.to_be_bytes());
    body.extend_from_slice(&partial.to_bytes());
    encode(FrameType::BeaconPartial, &body)
}

/// `Beacon` frame body: the round's own byte encoding (which already carries the epoch).
fn round_frame(round: &BeaconRound) -> Vec<u8> {
    encode(FrameType::Beacon, &round.to_bytes())
}

fn encode(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(ty.code(), body, &mut out);
    out
}

fn parse_partial(body: &[u8]) -> Option<(Epoch, BeaconPartial)> {
    let epoch = Epoch::from_be_bytes(body.get(0..8)?.try_into().ok()?);
    let partial = BeaconPartial::from_bytes(body.get(8..)?)?;
    Some((epoch, partial))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;
    use fanos_vrf::vss::{DeterministicRng, deal};

    const N: usize = 7;

    /// The Fano-point index whose node address is `to`.
    fn node_at(to: Triple) -> Option<usize> {
        (0..N).find(|&k| Point::<F2>::at(k).coords() == to)
    }

    /// Step `Command::AdvanceEpoch` on every node, returning the `(target, frame)` bus of partials they
    /// flood — the start of one epoch's beacon round.
    fn kickoff(nodes: &mut [BeaconNode<F2>]) -> Vec<(usize, Vec<u8>)> {
        let mut bus = Vec::new();
        for node in nodes.iter_mut() {
            for e in node.step(Instant(0), Input::Command(Command::AdvanceEpoch)) {
                if let Effect::Send { to, frame } = e
                    && let Some(k) = node_at(to)
                {
                    bus.push((k, frame));
                }
            }
        }
        bus
    }

    /// Deliver the bus between `nodes` until quiescent, recording every `BeaconReady { epoch, seed }` a
    /// node emitted. Returns those adopted `(coord, epoch, seed)`.
    fn run(
        nodes: &mut [BeaconNode<F2>],
        mut bus: Vec<(usize, Vec<u8>)>,
    ) -> Vec<(Triple, Epoch, [u8; 32])> {
        let mut ready = Vec::new();
        let mut clock = 0u64;
        while !bus.is_empty() {
            let (target, frame) = bus.remove(0);
            clock += 1;
            let coord = nodes[target].address();
            for e in nodes[target].step(
                Instant(clock),
                Input::Message {
                    from: [0, 0, 0],
                    frame,
                },
            ) {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(k) = node_at(to) {
                            bus.push((k, frame));
                        }
                    }
                    Effect::Notify(Notification::BeaconReady { epoch, seed }) => {
                        ready.push((coord, epoch, seed));
                    }
                    _ => {}
                }
            }
        }
        ready
    }

    #[test]
    fn a_cell_of_beacon_nodes_converges_on_one_epoch_seed() {
        // A t-of-n sharing (stands for a completed DKG). Every node is an anchor; on AdvanceEpoch they
        // flood partials, assemble the round, and ALL adopt the SAME epoch-1 seed — the distributed
        // beacon, no node holding the secret.
        let t = 4usize;
        let (shares, commitment) = deal(
            &[0xBE; 32],
            t,
            N,
            &mut DeterministicRng::new(b"beacon-node-cell"),
        )
        .unwrap();
        let mut nodes: Vec<BeaconNode<F2>> = (0..N)
            .map(|i| BeaconNode::new(Point::at(i), Some(shares[i].clone()), commitment.clone(), t))
            .collect();

        // Trigger the next epoch on every anchor, then route their partials + assembled rounds.
        let bus = kickoff(&mut nodes);
        let ready = run(&mut nodes, bus);

        // Every node adopted epoch 1 and the SAME seed, which is the canonical beacon value.
        assert_eq!(ready.len(), N, "every node adopted the beacon");
        let seed0 = ready[0].2;
        assert!(
            ready
                .iter()
                .all(|&(_, e, s)| e == Epoch::new(1) && s == seed0),
            "all nodes adopt epoch 1 with one shared seed"
        );
        assert_ne!(
            seed0, [0u8; 32],
            "the seed is a real beacon value, not genesis"
        );
        for node in &nodes {
            assert_eq!(node.epoch(), Epoch::new(1));
            assert_eq!(node.seed(), seed0);
        }
    }

    #[test]
    fn a_pure_consumer_adopts_the_flooded_round() {
        // A node with no share never produces a partial, but adopts the round the anchors flood — so a
        // client/relay that is not a beacon anchor still learns each epoch's verified seed.
        let t = 4usize;
        let (shares, commitment) = deal(
            &[0xC0; 32],
            t,
            N,
            &mut DeterministicRng::new(b"beacon-consumer"),
        )
        .unwrap();
        // Node 6 is a pure consumer (no share); nodes 0..6 are anchors.
        let mut nodes: Vec<BeaconNode<F2>> = (0..N)
            .map(|i| {
                BeaconNode::new(
                    Point::at(i),
                    (i < 6).then_some(shares[i].clone()),
                    commitment.clone(),
                    t,
                )
            })
            .collect();
        let bus = kickoff(&mut nodes);
        run(&mut nodes, bus);
        // The consumer (node 6) adopted the same seed as an anchor (node 0).
        assert_eq!(nodes[6].epoch(), Epoch::new(1));
        assert_eq!(nodes[6].seed(), nodes[0].seed());
        assert_ne!(nodes[6].seed(), [0u8; 32]);
    }

    #[test]
    fn a_forged_partial_is_not_adopted() {
        // With t = 1 a single valid partial would form the beacon; a forged one (failing its DLEQ) must
        // not — so a Byzantine anchor cannot inject a bogus contribution.
        let (shares, commitment) = deal(
            &[0xF0; 32],
            1,
            N,
            &mut DeterministicRng::new(b"beacon-forge"),
        )
        .unwrap();
        let mut node = BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment, 1);

        // A valid partial from anchor 2 (index 3), with a flipped response byte.
        let honest = partial_eval(&shares[2], Epoch::new(1));
        let mut bytes = honest.to_bytes();
        bytes[65] ^= 0x01;
        // A non-canonical corruption is rejected at decode (also a rejection); a canonical one fails DLEQ.
        if let Some(forged) = BeaconPartial::from_bytes(&bytes) {
            let frame = partial_frame(Epoch::new(1), &forged);
            let effects = node.step(
                Instant(1),
                Input::Message {
                    from: [9, 9, 9],
                    frame,
                },
            );
            assert!(
                effects.is_empty(),
                "a forged partial (t=1) yields no beacon"
            );
        }
        assert_eq!(node.epoch(), Epoch::ZERO, "the node stays at genesis");
    }

    #[test]
    fn a_joining_node_pull_syncs_the_current_beacon() {
        // A node that missed the live round adopts the current epoch by asking a synced peer (BeaconReq),
        // rather than assuming an epoch — the bootstrap path (spec §7.8).
        let t = 4usize;
        let (shares, commitment) = deal(
            &[0x5C; 32],
            t,
            N,
            &mut DeterministicRng::new(b"beacon-sync"),
        )
        .unwrap();

        // A synced anchor: it proposes epoch 1 (its own partial) and receives the rest, so it adopts and
        // caches the round.
        let mut synced =
            BeaconNode::<F2>::new(Point::at(0), Some(shares[0].clone()), commitment.clone(), t);
        synced.step(Instant(0), Input::Command(Command::AdvanceEpoch));
        for share in &shares[1..t] {
            let p = partial_eval(share, Epoch::new(1));
            synced.step(
                Instant(0),
                Input::Message {
                    from: [0, 0, 0],
                    frame: partial_frame(Epoch::new(1), &p),
                },
            );
        }
        assert_eq!(synced.epoch(), Epoch::new(1), "the anchor adopted epoch 1");

        // A fresh consumer that saw none of it.
        let mut fresh = BeaconNode::<F2>::new(Point::at(1), None, commitment, t);
        assert_eq!(fresh.epoch(), Epoch::ZERO);

        // On join it broadcasts a BeaconReq; the synced peer answers with its round; the fresh node
        // verifies and adopts — reaching epoch 1 with the identical seed, no trust in the peer.
        let req_frame = fresh
            .step(Instant(1), Input::Command(Command::StartHeartbeat))
            .into_iter()
            .find_map(|e| match e {
                Effect::Send { frame, .. } => Some(frame),
                _ => None,
            })
            .expect("join broadcasts a BeaconReq");
        let round_frame = synced
            .step(
                Instant(2),
                Input::Message {
                    from: Point::<F2>::at(1).coords(),
                    frame: req_frame,
                },
            )
            .into_iter()
            .find_map(|e| match e {
                Effect::Send { frame, .. } => Some(frame),
                _ => None,
            })
            .expect("a synced peer answers the BeaconReq with its round");
        fresh.step(
            Instant(3),
            Input::Message {
                from: Point::<F2>::at(0).coords(),
                frame: round_frame,
            },
        );
        assert_eq!(
            fresh.epoch(),
            Epoch::new(1),
            "the joining node synced to epoch 1"
        );
        assert_eq!(
            fresh.seed(),
            synced.seed(),
            "and adopted the identical verified seed"
        );
    }
}
