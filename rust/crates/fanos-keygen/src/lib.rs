//! # fanos-keygen — distributed key generation as a running node engine
//!
//! [`fanos_vrf::dkg`] verifies the *logic* of multi-dealer DKG; this crate makes it a **running,
//! Byzantine-robust protocol**. [`DkgNode`] is a sans-I/O [`Engine`] that runs the classic
//! Feldman/Pedersen DKG with a **complaint round** (Gennaro–Jarecki–Krawczyk–Rabin) across its cell:
//!
//! 1. **Sharing.** Each node deals a Feldman VSS of its secret: it sends every member a private
//!    share (`DkgDeal`) and broadcasts its public commitment (`DkgCommit`, echoed for reliable
//!    broadcast). A share is accepted only if it verifies against the commitment.
//! 2. **Complaint.** At the sharing deadline, a node that is missing or holds an *invalid* share
//!    from some dealer broadcasts a `DkgComplaint` against it.
//! 3. **Justification.** A dealer answers each complaint by broadcasting the complainer's correct
//!    share (`DkgJustify`), which everyone verifies against the (public) commitment. A dealer with
//!    an **unanswered** complaint is **disqualified**.
//! 4. **Finalize.** At the complaint deadline, the **qualified set** `QUAL` = dealers with a known
//!    commitment and no unanswered complaint. If `|QUAL| ≥ threshold`, the node publishes the joint
//!    public key `Y = Σ_{d∈QUAL} C_{d,0}` ([`Notification::DkgComplete`]) and folds exactly the
//!    `QUAL` shares into its final key share — so `Y` and the share are over the identical set.
//!
//! Because commitments, complaints, and justifications are reliably broadcast (each is echoed on
//! first receipt), every honest node observes the same evidence and computes the **same** `QUAL` —
//! even against a *Byzantine equivocating* dealer that deals validly to some members and
//! invalidly/not-at-all to others. No node ever learns the joint secret. The same engine runs under
//! the simulator and a real transport, exactly like the overlay node.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_vrf::dkg::{self, Dealing, Participant};
use fanos_vrf::vss::{self, DeterministicRng, VssCommitment, VssShare};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// The sharing-phase deadline timer: after this, a node complains about missing/invalid shares.
const DKG_SHARE_DEADLINE: TimerToken = TimerToken(0);
/// The complaint-phase deadline timer: after this, a node finalizes on the qualified set.
const DKG_COMPLAINT_DEADLINE: TimerToken = TimerToken(1);

/// Default sharing-phase length (collect dealings before opening complaints).
const DEFAULT_SHARE_DEADLINE: Duration = Duration::from_millis(1500);
/// Default complaint-phase length (collect complaints + justifications before finalizing).
const DEFAULT_COMPLAINT_DEADLINE: Duration = Duration::from_millis(1500);

/// Serialized [`VssShare`] length (`index ‖ scalar`).
const SHARE_LEN: usize = 33;

/// The protocol phase a node is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Not yet started.
    Idle,
    /// Dealing sent; collecting shares/commitments until the sharing deadline.
    Sharing,
    /// Complaints opened; collecting complaints/justifications until the complaint deadline.
    Complaint,
    /// Key published (or abandoned below threshold).
    Done,
}

/// A node participating in a `t`-of-`n` distributed key generation across its cell.
pub struct DkgNode<F: Field> {
    coord: Point<F>,
    index: u8,
    n: usize,
    threshold: usize,
    secret: [u8; 32],
    /// Accumulates exactly the qualified dealers' shares — folded at finalize, not during sharing,
    /// so the final share is over `QUAL` (never over a dealer that others later disqualified).
    participant: Participant,
    /// This node's own dealing, retained so it can justify complaints raised against it.
    dealing: Option<Dealing>,
    /// Every commitment seen (from any dealer that dealt to us, or via echo) — the candidate dealers.
    commitments: BTreeMap<u8, VssCommitment>,
    /// This node's verified share from each dealer (direct or revealed by a justification).
    my_shares: BTreeMap<u8, VssShare>,
    /// Dealers this node holds a verified share from (`⊆ commitments`).
    qualified: BTreeSet<u8>,
    /// Dealer → the set of members that complained against it (reliably broadcast).
    complaints: BTreeMap<u8, BTreeSet<u8>>,
    /// Dealer → the set of complainers it answered with a *valid* revealed share.
    justified: BTreeMap<u8, BTreeSet<u8>>,
    phase: Phase,
    started_at: Instant,
    share_deadline: Duration,
    complaint_deadline: Duration,
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
            dealing: None,
            commitments: BTreeMap::new(),
            my_shares: BTreeMap::new(),
            qualified: BTreeSet::new(),
            complaints: BTreeMap::new(),
            justified: BTreeMap::new(),
            phase: Phase::Idle,
            started_at: Instant::default(),
            share_deadline: DEFAULT_SHARE_DEADLINE,
            complaint_deadline: DEFAULT_COMPLAINT_DEADLINE,
            done: false,
        }
    }

    /// Override the phase deadlines (sharing, then complaint). Defaults are 1.5 s each.
    #[must_use]
    pub fn with_deadlines(mut self, sharing: Duration, complaint: Duration) -> Self {
        self.share_deadline = sharing;
        self.complaint_deadline = complaint;
        self
    }

    /// The coordinate of participant `index` (`1..=n`) — its Fano point.
    fn coord_of(index: u8) -> Triple {
        Point::<F>::at((index.saturating_sub(1)) as usize).coords()
    }

    /// The dealer index that owns `from`, if `from` is a cell member.
    fn dealer_of(&self, from: Triple) -> Option<u8> {
        (1..=self.n as u8).find(|&j| Self::coord_of(j) == from)
    }

    /// Begin the sharing phase: deal a Feldman VSS, privately send each member its share, broadcast
    /// our commitment, and arm the sharing deadline.
    fn start(&mut self, now: Instant) -> Vec<Effect> {
        if self.phase != Phase::Idle {
            return Vec::new();
        }
        self.phase = Phase::Sharing;
        self.started_at = now;
        let mut rng = DeterministicRng::new(&self.secret);
        let Some(dealing) = dkg::deal(&self.secret, self.threshold, self.n, &mut rng) else {
            return Vec::new();
        };
        let commitment = dealing.commitment().clone();

        // Record our own commitment and our own share (self-dealt, trivially valid).
        self.commitments.insert(self.index, commitment.clone());
        if let Some(mine) = dealing.share_for(self.index) {
            self.my_shares.insert(self.index, *mine);
            self.qualified.insert(self.index);
        }

        let mut effects = Vec::new();
        // Broadcast our commitment (reliable-broadcast substrate) to every member.
        for j in 1..=self.n as u8 {
            if j != self.index {
                effects.push(Effect::Send {
                    to: Self::coord_of(j),
                    frame: commit_frame(self.index, &commitment),
                });
            }
        }
        // Send each member its private share.
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
        self.dealing = Some(dealing);
        effects.push(Effect::ArmTimer {
            token: DKG_SHARE_DEADLINE,
            after: self.share_deadline,
        });
        effects
    }

    /// Record a newly-seen commitment for dealer `d`; returns `true` if it was new (echo it).
    fn note_commitment(&mut self, d: u8, commitment: VssCommitment) -> bool {
        if self.commitments.contains_key(&d) {
            return false;
        }
        self.commitments.insert(d, commitment);
        self.try_verify(d);
        true
    }

    /// If we now hold both dealer `d`'s commitment and our share from it, verify and qualify.
    fn try_verify(&mut self, d: u8) {
        if self.qualified.contains(&d) {
            return;
        }
        if let (Some(commitment), Some(share)) = (self.commitments.get(&d), self.my_shares.get(&d))
            && vss::verify_share(share, commitment)
        {
            self.qualified.insert(d);
        }
    }

    /// A private `DkgDeal` (our share from dealer `from`): store and try to verify it.
    fn on_deal(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some(dealer) = self.dealer_of(from) else {
            return Vec::new();
        };
        let Some((share, commitment)) = parse_deal(body) else {
            return Vec::new();
        };
        if share.index() != self.index {
            return Vec::new(); // not our share
        }
        self.my_shares.entry(dealer).or_insert(share);
        // The deal carries the commitment too; adopt it (and echo it for reliable broadcast) if new.
        if self.note_commitment(dealer, commitment.clone()) {
            self.broadcast_to_peers(&commit_frame(dealer, &commitment))
        } else {
            self.try_verify(dealer);
            Vec::new()
        }
    }

    /// A broadcast `DkgCommit` echo for dealer `d`.
    fn on_commit(&mut self, body: &[u8]) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some((d, commitment)) = parse_commit(body) else {
            return Vec::new();
        };
        if self.note_commitment(d, commitment.clone()) {
            // Echo once for reliable broadcast.
            return self.broadcast_to_peers(&commit_frame(d, &commitment));
        }
        Vec::new()
    }

    /// A broadcast `DkgComplaint` (complainer `c` against dealer `d`).
    fn on_complaint(&mut self, body: &[u8]) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some((c, d)) = parse_complaint(body) else {
            return Vec::new();
        };
        let mut effects = Vec::new();
        if self.complaints.entry(d).or_default().insert(c) {
            // New complaint — echo it, and if we are the accused dealer, justify.
            effects.extend(self.broadcast_to_peers(&complaint_frame(c, d)));
            if d == self.index
                && c != self.index
                && let Some(dealing) = &self.dealing
                && let Some(share) = dealing.share_for(c)
            {
                let commitment = dealing.commitment().clone();
                let share = *share;
                self.justified.entry(d).or_default().insert(c);
                effects.extend(self.broadcast_to_peers(&justify_frame(d, &share, &commitment)));
            }
        }
        effects
    }

    /// A broadcast `DkgJustify` (dealer `d` reveals the share for complainer `share.index()`).
    fn on_justify(&mut self, body: &[u8]) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some((d, share, commitment)) = parse_justify(body) else {
            return Vec::new();
        };
        // The revealed share must verify against the dealer's public commitment.
        if !vss::verify_share(&share, &commitment) {
            return Vec::new();
        }
        self.note_commitment(d, commitment.clone());
        let complainer = share.index();
        let mut effects = Vec::new();
        if self.justified.entry(d).or_default().insert(complainer) {
            // If this reveals *our* share from d, adopt it (we can now qualify d).
            if complainer == self.index {
                self.my_shares.entry(d).or_insert(share);
                self.try_verify(d);
            }
            effects.extend(self.broadcast_to_peers(&justify_frame(d, &share, &commitment)));
        }
        effects
    }

    /// Sharing deadline: open the complaint phase — complain about every candidate dealer we do not
    /// hold a valid share from — and arm the complaint deadline.
    fn open_complaints(&mut self) -> Vec<Effect> {
        if self.phase != Phase::Sharing {
            return Vec::new();
        }
        self.phase = Phase::Complaint;
        let mut effects = Vec::new();
        let candidates: Vec<u8> = self.commitments.keys().copied().collect();
        for d in candidates {
            if !self.qualified.contains(&d) {
                // We are missing/invalid a share from d → complain (recorded locally + broadcast).
                self.complaints.entry(d).or_default().insert(self.index);
                effects.extend(self.broadcast_to_peers(&complaint_frame(self.index, d)));
            }
        }
        effects.push(Effect::ArmTimer {
            token: DKG_COMPLAINT_DEADLINE,
            after: self.complaint_deadline,
        });
        effects
    }

    /// Complaint deadline: compute `QUAL` and finalize the joint key (or abandon below threshold).
    fn finalize(&mut self) -> Vec<Effect> {
        if self.done || self.phase != Phase::Complaint {
            return Vec::new();
        }
        // QUAL = dealers with a commitment and no *unanswered* complaint.
        let qual: Vec<u8> = self
            .commitments
            .keys()
            .copied()
            .filter(|d| {
                let complained = self.complaints.get(d);
                let answered = self.justified.get(d);
                match complained {
                    None => true, // no complaints
                    Some(cs) => cs.iter().all(|c| answered.is_some_and(|a| a.contains(c))),
                }
            })
            .collect();

        self.phase = Phase::Done;
        if qual.len() < self.threshold {
            // Too few dealers survived — no key can be formed (genuine under-participation).
            self.done = true;
            return Vec::new();
        }
        self.done = true;

        // Fold exactly the QUAL shares into the final share, and sum their C₀ for the joint key —
        // the two are therefore over the identical set (agreement + share consistency).
        let mut refs: Vec<&VssCommitment> = Vec::with_capacity(qual.len());
        for &d in &qual {
            if let (Some(commitment), Some(share)) =
                (self.commitments.get(&d), self.my_shares.get(&d))
            {
                self.participant.ingest_share(share, commitment);
                refs.push(commitment);
            }
        }
        let joint = dkg::joint_public_from_commitments(&refs);
        alloc_vec_notify(joint)
    }

    /// Broadcast `frame` to every *other* cell member (the reliable-broadcast primitive).
    fn broadcast_to_peers(&self, frame: &[u8]) -> Vec<Effect> {
        (1..=self.n as u8)
            .filter(|&j| j != self.index)
            .map(|j| Effect::Send {
                to: Self::coord_of(j),
                frame: frame.to_vec(),
            })
            .collect()
    }

    /// This node's final key share bytes (a point on the aggregate polynomial), once complete.
    #[must_use]
    pub fn final_share_bytes(&self) -> [u8; 32] {
        self.participant.final_share().value_bytes()
    }
}

/// A one-element effect vector emitting `DkgComplete(joint)`.
fn alloc_vec_notify(joint: [u8; 32]) -> Vec<Effect> {
    std::vec![Effect::Notify(Notification::DkgComplete(joint))]
}

impl<F: Field> Engine for DkgNode<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // Reused as "begin DKG" (a keygen node has no heartbeat).
            Input::Command(Command::StartHeartbeat) => self.start(now),
            Input::Message { from, frame } => match decode_frame(&frame) {
                Ok((f, _)) => match f.frame_type() {
                    Some(FrameType::DkgDeal) => self.on_deal(from, f.body),
                    Some(FrameType::DkgCommit) => self.on_commit(f.body),
                    Some(FrameType::DkgComplaint) => self.on_complaint(f.body),
                    Some(FrameType::DkgJustify) => self.on_justify(f.body),
                    _ => Vec::new(),
                },
                Err(_) => Vec::new(),
            },
            Input::Timer(DKG_SHARE_DEADLINE) => self.open_complaints(),
            Input::Timer(DKG_COMPLAINT_DEADLINE) => self.finalize(),
            _ => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord.coords()
    }
}

/// Encode a private `DkgDeal`: `share(33) ‖ commitment`.
fn deal_frame(share: &VssShare, commitment: &VssCommitment) -> Vec<u8> {
    let mut body = Vec::with_capacity(SHARE_LEN + commitment.threshold() * 32);
    body.extend_from_slice(&share.to_bytes());
    body.extend_from_slice(&commitment.to_bytes());
    frame(FrameType::DkgDeal, &body)
}

/// Encode a broadcast `DkgCommit`: `dealer(1) ‖ commitment`.
fn commit_frame(dealer: u8, commitment: &VssCommitment) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + commitment.threshold() * 32);
    body.push(dealer);
    body.extend_from_slice(&commitment.to_bytes());
    frame(FrameType::DkgCommit, &body)
}

/// Encode a broadcast `DkgComplaint`: `complainer(1) ‖ dealer(1)`.
fn complaint_frame(complainer: u8, dealer: u8) -> Vec<u8> {
    frame(FrameType::DkgComplaint, &[complainer, dealer])
}

/// Encode a broadcast `DkgJustify`: `dealer(1) ‖ share(33) ‖ commitment`.
fn justify_frame(dealer: u8, share: &VssShare, commitment: &VssCommitment) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + SHARE_LEN + commitment.threshold() * 32);
    body.push(dealer);
    body.extend_from_slice(&share.to_bytes());
    body.extend_from_slice(&commitment.to_bytes());
    frame(FrameType::DkgJustify, &body)
}

fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(ty.code(), body, &mut out);
    out
}

fn parse_deal(body: &[u8]) -> Option<(VssShare, VssCommitment)> {
    let share = VssShare::from_bytes(body.get(..SHARE_LEN)?)?;
    let commitment = VssCommitment::from_bytes(body.get(SHARE_LEN..)?)?;
    Some((share, commitment))
}

fn parse_commit(body: &[u8]) -> Option<(u8, VssCommitment)> {
    let d = *body.first()?;
    let commitment = VssCommitment::from_bytes(body.get(1..)?)?;
    Some((d, commitment))
}

fn parse_complaint(body: &[u8]) -> Option<(u8, u8)> {
    Some((*body.first()?, *body.get(1)?))
}

fn parse_justify(body: &[u8]) -> Option<(u8, VssShare, VssCommitment)> {
    let d = *body.first()?;
    let share = VssShare::from_bytes(body.get(1..1 + SHARE_LEN)?)?;
    let commitment = VssCommitment::from_bytes(body.get(1 + SHARE_LEN..)?)?;
    Some((d, share, commitment))
}
