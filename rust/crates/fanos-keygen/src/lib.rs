//! # fanos-keygen — distributed key generation as a running node engine
//!
//! [`fanos_vrf::dkg`] verifies the *logic* of multi-dealer DKG; this crate makes it a **running
//! protocol**. [`DkgNode`] is a sans-I/O [`Engine`] that, on start, deals a Feldman VSS of its own
//! secret and sends each cell member its private share plus the public commitment (a `DkgDeal`
//! frame). As the dealings arrive, each node verifies its share, folds it into its final key share,
//! and — once it holds a dealing from every member — computes the **joint public key** `Y = Σ C₀`
//! and emits [`Notification::DkgComplete`]. No node ever learns the joint secret; a dealer whose
//! share fails the Feldman check contributes nothing. The same engine runs under the simulator and
//! a real transport, exactly like the overlay node.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification};
use fanos_vrf::dkg::{self, Participant};
use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// A node participating in a `t`-of-`n` distributed key generation across its cell.
pub struct DkgNode<F: Field> {
    coord: Point<F>,
    index: u8,
    n: usize,
    threshold: usize,
    secret: [u8; 32],
    participant: Participant,
    /// Dealer index → its commitment (accumulated as dealings arrive).
    commitments: BTreeMap<u8, VssCommitment>,
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
            started: false,
            done: false,
        }
    }

    /// The coordinate of participant `index` (`1..=n`) — its Fano point.
    fn coord_of(index: u8) -> Triple {
        Point::<F>::at((index.saturating_sub(1)) as usize).coords()
    }

    /// Begin: deal a Feldman VSS and send each member its share + the public commitment.
    fn start(&mut self) -> Vec<Effect> {
        if self.started {
            return Vec::new();
        }
        self.started = true;
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

    /// When a dealing has been accepted from every member, publish the joint public key.
    ///
    /// Known limitation (liveness, tracked): completion requires a valid dealing from **all** `n`
    /// members (`== self.n`). A single offline dealer, or one whose Feldman share is disqualified,
    /// means the count never reaches `n` and `DkgComplete` never fires — the honest majority stalls.
    /// A production DKG completes on an agreed **qualified set** of size `≥ threshold` after a
    /// collection deadline (Gennaro et al.), which needs a timeout + an agreement round this
    /// sans-I/O engine does not yet drive. Safety is unaffected (every node that completes uses the
    /// identical full set and agrees on the key); only liveness under a faulty dealer is.
    fn check_done(&mut self, effects: &mut Vec<Effect>) {
        if !self.done && self.commitments.len() == self.n {
            self.done = true;
            let refs: Vec<&VssCommitment> = self.commitments.values().collect();
            let joint = dkg::joint_public_from_commitments(&refs);
            effects.push(Effect::Notify(Notification::DkgComplete(joint)));
        }
    }

    /// This node's final key share bytes (a point on the aggregate polynomial), once complete.
    #[must_use]
    pub fn final_share_bytes(&self) -> [u8; 32] {
        self.participant.final_share().value_bytes()
    }
}

impl<F: Field> Engine for DkgNode<F> {
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // Reused as "begin DKG" (a keygen node has no heartbeat).
            Input::Command(Command::StartHeartbeat) => self.start(),
            Input::Message { from, frame } => match decode_frame(&frame) {
                Ok((f, _)) if f.frame_type() == Some(FrameType::DkgDeal) => {
                    self.on_deal(from, f.body)
                }
                _ => Vec::new(),
            },
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
