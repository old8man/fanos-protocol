//! # fanos-keygen — distributed key generation as a running node engine
//!
//! [`fanos_vrf::dkg`] verifies the *logic* of multi-dealer DKG; this crate makes it a **running
//! protocol**. [`DkgNode`] is a sans-I/O [`Engine`] that, on start, deals a Feldman VSS of its own
//! secret and sends each cell member its private share plus the public commitment (a `DkgDeal`
//! frame). As the dealings arrive, each node verifies its share, folds it into its final key share,
//! and computes the **joint public key** `Y = Σ_{d ∈ QUAL} C_{d,0}` over its *qualified set* (the
//! dealers whose share it verified), emitting [`Notification::DkgComplete`]. Completion is **live**
//! (spec §6.4): a node finalizes as soon as every member has qualified (fast path), or — once a
//! collection **deadline** elapses — on whatever qualified subset reached the `threshold`, so an
//! offline or share-disqualified dealer cannot stall the honest majority. No node ever learns the
//! joint secret; a dealer whose Feldman share fails verification contributes nothing. The same
//! engine runs under the simulator and a real transport, exactly like the overlay node.
//!
//! Remaining gap (documented): the qualified set is agreed by the cell's reliable broadcast plus
//! the deadline, which is robust to *crash/offline* dealers. A *Byzantine equivocating* dealer (a
//! valid dealing to some members, none/invalid to others) could still split the set; excluding it
//! needs the classic complaint round (Gennaro et al.), a further round this engine does not drive.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_vrf::dkg::{self, Participant};
use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// The DKG collection-deadline timer token (a keygen node has no other timer).
const DKG_DEADLINE: TimerToken = TimerToken(0);

/// Default collection deadline: how long to wait for every member's dealing before finalizing on
/// the qualified subset received so far (spec §6.4 DKG liveness).
const DEFAULT_DEADLINE: Duration = Duration::from_millis(2000);

/// A node participating in a `t`-of-`n` distributed key generation across its cell.
pub struct DkgNode<F: Field> {
    coord: Point<F>,
    index: u8,
    n: usize,
    threshold: usize,
    secret: [u8; 32],
    participant: Participant,
    /// Dealer index → its commitment. A dealer is in this map iff **its share was verified and
    /// ingested** by us — so the map keys are exactly this node's *qualified set*, kept in lockstep
    /// with the accumulated final share (every ingest → one insert).
    commitments: BTreeMap<u8, VssCommitment>,
    /// The collection deadline: after this span from `start`, finalize on the qualified subset
    /// rather than waiting for every dealer (an offline dealer must not stall the honest majority).
    deadline: Duration,
    started_at: Instant,
    started: bool,
    done: bool,
}

impl<F: Field> DkgNode<F> {
    /// A DKG participant at `coord` contributing `secret`, targeting threshold `threshold`.
    #[must_use]
    pub fn new(coord: Point<F>, threshold: usize, secret: [u8; 32]) -> Self {
        let n = Plane::<F>::N as usize;
        let index = (0..n)
            .find(|&i| Point::<F>::at(i) == coord)
            .map_or(1, |i| i as u8 + 1);
        Self {
            coord,
            index,
            n,
            threshold,
            secret,
            participant: Participant::new(index),
            commitments: BTreeMap::new(),
            deadline: DEFAULT_DEADLINE,
            started_at: Instant::default(),
            started: false,
            done: false,
        }
    }

    /// Set the collection deadline (default 2 s): the span after `start` before the node finalizes
    /// on whatever qualified subset (`≥ threshold` dealers) it has, instead of waiting for all `n`.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// The coordinate of participant `index` (`1..=n`) — its Fano point.
    fn coord_of(index: u8) -> Triple {
        Point::<F>::at((index.saturating_sub(1)) as usize).coords()
    }

    /// Begin: deal a Feldman VSS, send each member its share + the public commitment, and arm the
    /// collection deadline so an offline dealer cannot stall completion.
    fn start(&mut self, now: Instant) -> Vec<Effect> {
        if self.started {
            return Vec::new();
        }
        self.started = true;
        self.started_at = now;
        let mut rng = DeterministicRng::new(&self.secret);
        let Some(dealing) = dkg::deal(&self.secret, self.threshold, self.n, &mut rng) else {
            return Vec::new();
        };
        let commitment = dealing.commitment().clone();
        if let Some(mine) = dealing.share_for(self.index) {
            self.participant.ingest_share(mine, &commitment);
        }
        self.commitments.insert(self.index, commitment.clone());

        let mut effects = Vec::new();
        for j in 1..=self.n as u8 {
            if j == self.index {
                continue;
            }
            if let Some(share) = dealing.share_for(j) {
                effects.push(Effect::Send {
                    to: Self::coord_of(j),
                    frame: deal_frame(share, &commitment),
                });
            }
        }
        // Arm the collection deadline: if not every dealing has arrived by then, we finalize on the
        // qualified subset (spec §6.4). A full house still completes early via `check_done`.
        effects.push(Effect::ArmTimer {
            token: DKG_DEADLINE,
            after: self.deadline,
        });
        self.check_done(&mut effects);
        effects
    }

    /// Handle a received dealing: verify our share, fold it in, and finish when all have arrived.
    fn on_deal(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some((share, commitment)) = parse_deal(body) else {
            return Vec::new();
        };
        let Some(dealer) = (1..=self.n as u8).find(|&j| Self::coord_of(j) == from) else {
            return Vec::new();
        };
        if self.commitments.contains_key(&dealer) {
            return Vec::new(); // duplicate dealing
        }
        if !self.participant.ingest_share(&share, &commitment) {
            return Vec::new(); // cheating dealer — disqualified, contributes nothing
        }
        self.commitments.insert(dealer, commitment);
        let mut effects = Vec::new();
        self.check_done(&mut effects);
        effects
    }

    /// Fast path: as soon as a valid dealing has been accepted from **every** member, publish the
    /// joint key immediately (no need to wait out the deadline).
    fn check_done(&mut self, effects: &mut Vec<Effect>) {
        if !self.done && self.commitments.len() == self.n {
            self.finalize(effects);
        }
    }

    /// Deadline path: finalize on the **qualified subset** received so far, provided it reaches the
    /// threshold. An offline or share-disqualified dealer therefore cannot stall the honest majority
    /// (spec §6.4 DKG liveness) — completion no longer requires all `n`.
    ///
    /// Agreement: the qualified set is `commitments.keys()` — exactly the dealers whose *share* this
    /// node verified and ingested, so the published `Y = Σ C₀` and this node's final share are over
    /// the identical set. Under the cell's reliable broadcast every honest node ingests every honest
    /// (and every non-equivocating faulty) dealer's dealing, so all honest nodes converge on the
    /// same qualified set and the same key. A dealer that *equivocates* — a valid dealing to some,
    /// none/invalid to others — can still split the set; excluding it needs the complaint round
    /// (documented as the remaining gap), which robustifies Byzantine equivocation, not crash/offline.
    fn finalize_on_deadline(&mut self, effects: &mut Vec<Effect>) {
        if !self.done && self.commitments.len() >= self.threshold {
            self.finalize(effects);
        }
        // Below threshold: too few dealers qualified to form a key — stay pending (a genuine failure
        // of participation, not something a longer wait fixes).
    }

    /// Compute `Y = Σ_{d ∈ QUAL} C_{d,0}` over the qualified commitments and emit `DkgComplete`.
    /// BTreeMap iterates dealer indices in sorted order, so the sum is order-deterministic.
    fn finalize(&mut self, effects: &mut Vec<Effect>) {
        self.done = true;
        let refs: Vec<&VssCommitment> = self.commitments.values().collect();
        let joint = dkg::joint_public_from_commitments(&refs);
        effects.push(Effect::Notify(Notification::DkgComplete(joint)));
    }

    /// This node's final key share bytes (a point on the aggregate polynomial), once complete.
    #[must_use]
    pub fn final_share_bytes(&self) -> [u8; 32] {
        self.participant.final_share().value_bytes()
    }
}

impl<F: Field> Engine for DkgNode<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // Reused as "begin DKG" (a keygen node has no heartbeat).
            Input::Command(Command::StartHeartbeat) => self.start(now),
            Input::Message { from, frame } => match decode_frame(&frame) {
                Ok((f, _)) if f.frame_type() == Some(FrameType::DkgDeal) => {
                    self.on_deal(from, f.body)
                }
                _ => Vec::new(),
            },
            // The collection deadline fired: finalize on the qualified subset (liveness).
            Input::Timer(DKG_DEADLINE) => {
                let mut effects = Vec::new();
                self.finalize_on_deadline(&mut effects);
                effects
            }
            _ => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord.coords()
    }
}

/// Encode a `DkgDeal`: `share(33) ‖ commitment` (spec §7.2).
fn deal_frame(share: &VssShare, commitment: &VssCommitment) -> Vec<u8> {
    let mut body = Vec::with_capacity(33 + commitment.threshold() * 32 + 1);
    body.extend_from_slice(&share.to_bytes());
    body.extend_from_slice(&commitment.to_bytes());
    let mut out = Vec::new();
    encode_frame(FrameType::DkgDeal.code(), &body, &mut out);
    out
}

/// Parse a `DkgDeal` body into `(share, commitment)`.
fn parse_deal(body: &[u8]) -> Option<(VssShare, VssCommitment)> {
    let share = VssShare::from_bytes(body.get(..33)?)?;
    let commitment = VssCommitment::from_bytes(body.get(33..)?)?;
    Some((share, commitment))
}
