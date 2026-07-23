//! # fanos-keygen — distributed key generation as a running node engine
//!
//! [`fanos_vrf::dkg`] verifies the *logic* of multi-dealer DKG; this crate makes it a **running,
//! Byzantine-robust protocol**. [`DkgNode`] is a sans-I/O [`Engine`] that runs the classic
//! Feldman/Pedersen DKG with a **complaint round** (Gennaro–Jarecki–Krawczyk–Rabin) across its cell:
//!
//! 1. **Sharing.** Each node deals a Feldman VSS of its secret: it sends every member a private
//!    share (`DkgDeal`) and broadcasts its public commitment (`DkgCommit`) directly to every member. A
//!    share is accepted only if it verifies against the commitment.
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
//! **Authentication (Byzantine robustness).** Every control frame is bound to its origin so a malicious
//! member cannot speak for an honest one:
//! * a **commitment** is accepted only *direct from its own dealer* (the transport authenticates the
//!   sender), so no one can pre-register a bogus commitment for a silent dealer;
//! * a **complaint** is accepted only *direct from its own complainer*, so no one can forge a complaint
//!   against an honest dealer to evict it (the attack that would otherwise void GJKR robustness);
//! * a **justification** is *self-authenticating* — the revealed share is checked against the commitment
//!   everyone qualified on — so it can be, and is, reliably echoed; an equivocating dealer that reveals to
//!   only some members is still overruled.
//!
//! In the base cell every member reaches every other directly, so an honest complainer's complaint reaches
//! the accused dealer (to be justified) without an echo relay. Every honest node therefore observes the
//! same evidence and computes the **same** `QUAL` — even against a *Byzantine equivocating* dealer that
//! deals validly to some members and invalidly/not-at-all to others. No node ever learns the joint secret.
//! The same engine runs under the simulator and a real transport, exactly like the overlay node.

#![forbid(unsafe_code)]

pub mod beacon;
pub mod recovery;
pub use beacon::BeaconNode;
pub use recovery::RecoveryAuthorization;

use std::collections::{BTreeMap, BTreeSet};

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_vrf::dkg::{self, Dealing, Participant};
use fanos_vrf::vss::{self, DeterministicRng, VssCommitment, VssShare};
use fanos_wire::{FrameType, decode_frame, encode_frame};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    /// Fresh per-DKG-instance entropy, mixed into the sharing polynomial's randomness so that the
    /// coefficients (and hence every member's share) do **not** repeat across runs that reuse the same
    /// long-term `secret` (audit B6). It is a caller input to keep the engine sans-I/O deterministic.
    session_nonce: [u8; 32],
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
    /// The aggregate commitment over the folded (QUAL) dealers, set at finalize. Its `public_share(i)`
    /// is holder `i`'s public key `Y_i`, so a randomness-beacon partial from a node's final share
    /// verifies against it (spec §L6 DKG → beacon). `None` until the DKG completes.
    aggregate: Option<VssCommitment>,
}

impl<F: Field> DkgNode<F> {
    /// A DKG participant at `coord` contributing `secret`, targeting threshold `threshold`.
    ///
    /// `session_nonce` is **fresh per-DKG-instance** entropy folded into the sharing polynomial (audit
    /// B6): supply a distinct value each run — from a CSPRNG in production — so the dealt shares never
    /// repeat even if `secret` is a long-term key reused across runs. It is an explicit input rather than
    /// drawn internally so the engine stays sans-I/O and replayable.
    #[must_use]
    pub fn new(
        coord: Point<F>,
        threshold: usize,
        secret: [u8; 32],
        session_nonce: [u8; 32],
    ) -> Self {
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
            session_nonce,
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
            aggregate: None,
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
        // Seed the polynomial randomness with `secret ‖ session_nonce`, so the non-constant coefficients
        // (and thus every share) are fresh per run even when `secret` is reused (audit B6). `secret`
        // remains the a₀ contribution; only the RNG that draws a₁… is nonce-dependent.
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.secret);
        seed.extend_from_slice(&self.session_nonce);
        let mut rng = DeterministicRng::new(&seed);
        seed.zeroize();
        let Some(dealing) = dkg::deal(&self.secret, self.threshold, self.n, &mut rng) else {
            return Vec::new();
        };
        let commitment = dealing.commitment().clone();

        // Record our own commitment and our own share (self-dealt, trivially valid).
        self.commitments.insert(self.index, commitment.clone());
        if let Some(mine) = dealing.share_for(self.index) {
            self.my_shares.insert(self.index, mine.clone());
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
        // The deal carries the dealer's commitment too; adopt it. No echo: the dealer broadcasts its
        // commitment directly to the whole (complete-graph) cell, and a commitment is only accepted from
        // its own dealer now (see `on_commit`), so a relayed copy would be rejected anyway.
        self.note_commitment(dealer, commitment);
        self.try_verify(dealer); // in case the commitment was already known, qualify now we hold the share
        Vec::new()
    }

    /// A `DkgCommit` from dealer `d`. **Authenticated**: a commitment for dealer `d` is accepted only
    /// direct from `d` (the transport authenticates `from`). Without this, a Byzantine node pre-registers
    /// a bogus commitment for a silent dealer (first-writer-wins) — commitment poisoning (audit B1). The
    /// dealer broadcasts its commitment directly to every member, so no echo (which would fail this check)
    /// is needed.
    fn on_commit(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some((d, commitment)) = parse_commit(body) else {
            return Vec::new();
        };
        if self.dealer_of(from) != Some(d) {
            return Vec::new(); // a commitment may only come from its own dealer
        }
        self.note_commitment(d, commitment);
        Vec::new()
    }

    /// A `DkgComplaint` (complainer `c` against dealer `d`). **Authenticated**: a complaint is accepted
    /// only direct from its complainer `c`. Without this, a Byzantine node forges
    /// `DkgComplaint{complainer = d, dealer = d}` against any honest dealer `d` — which `d` cannot answer
    /// (the self-justify guard `c != self.index`) — so `d` is dropped from `QUAL` at finalize, evicting
    /// every honest dealer (audit B1, CRITICAL). An honest complainer broadcasts directly to the whole
    /// complete-graph cell (including the accused), so the complaint reaches the dealer to be justified
    /// without an echo relay (which would fail the `from` check).
    fn on_complaint(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some((c, d)) = parse_complaint(body) else {
            return Vec::new();
        };
        if self.dealer_of(from) != Some(c) {
            return Vec::new(); // a complaint may only come from its own complainer
        }
        let mut effects = Vec::new();
        if self.complaints.entry(d).or_default().insert(c) {
            // If we are the accused dealer, justify by revealing `c`'s correct share (the one consistent
            // with our published commitment), broadcast directly to the whole cell.
            if d == self.index
                && c != self.index
                && let Some(dealing) = &self.dealing
                && let Some(share) = dealing.share_for(c)
            {
                let commitment = dealing.commitment().clone();
                let share = share.clone();
                self.justified.entry(d).or_default().insert(c);
                effects.extend(self.broadcast_to_peers(&justify_frame(d, &share, &commitment)));
            }
        }
        effects
    }

    /// A `DkgJustify` (dealer `d` reveals the share for complainer `share.index()`). A justification is
    /// **self-authenticating** — the revealed share is checked against the commitment everyone *qualified*
    /// on ([`commitments`](Self::commitments)`[d]`), not one carried in the frame (audit B3): an
    /// equivocating dealer must not clear a complaint with a share consistent with a *different*,
    /// unqualified commitment. Because a valid justification cannot be forged (the VSS check), it is
    /// reliably echoed (self-authenticating reliable broadcast), so an equivocating dealer that reveals to
    /// only some members is still overruled — every honest node converges on the same `QUAL`.
    fn on_justify(&mut self, _from: Triple, body: &[u8]) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some((d, share, _frame_commitment)) = parse_justify(body) else {
            return Vec::new();
        };
        // B3: verify against the qualified commitment, ignoring any commitment carried in the frame.
        let Some(commitment) = self.commitments.get(&d).cloned() else {
            return Vec::new(); // we have no qualified commitment for d yet — cannot verify the reveal
        };
        if !vss::verify_share(&share, &commitment) {
            return Vec::new();
        }
        let complainer = share.index();
        let mut effects = Vec::new();
        if self.justified.entry(d).or_default().insert(complainer) {
            // If this reveals *our* share from d, adopt it (we can now qualify d).
            if complainer == self.index {
                self.my_shares.entry(d).or_insert(share.clone());
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
        // The complaint phase is over — this node's own dealing (which held every other participant's
        // plaintext share from our deal) is no longer needed. Drop it now rather than retain it for the
        // object's whole life (audit #124 retention-scope).
        self.dealing = None;
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
                // Add d to the joint key `Y` ONLY if its share actually folds into our final share
                // (the Feldman check passes). Pushing the commitment unconditionally could put a dealer's
                // C₀ into `Y` while its share is *not* in our secret share, so `x·G ≠ Y` (audit B2).
                if self.participant.ingest_share(share, commitment) {
                    refs.push(commitment);
                }
            }
        }
        let joint = dkg::joint_public_from_commitments(&refs);
        // The aggregate of exactly the folded commitments is the joint polynomial's commitment: its
        // `public_share(i)` is holder i's public key `Y_i`, so a beacon partial from a node's final
        // share verifies against it. Every honest node folds the same QUAL, so all agree on this.
        self.aggregate = VssCommitment::aggregate(&refs);
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

    /// This node's final key share as a verifiable [`VssShare`] (index + scalar) — the input a member
    /// feeds to a [beacon partial](fanos_vrf::beacon::partial_eval) once the DKG is complete.
    #[must_use]
    pub fn final_share(&self) -> VssShare {
        self.participant.final_share()
    }

    /// The aggregate commitment of the qualified dealers once the DKG has completed (`None` before).
    /// A [beacon partial](fanos_vrf::beacon) from any member's [`final_share`](Self::final_share)
    /// verifies against this: it is the group's public verification material, and because every honest
    /// node folds the same `QUAL`, all agree on it.
    #[must_use]
    pub fn aggregate_commitment(&self) -> Option<VssCommitment> {
        self.aggregate.clone()
    }
}

impl<F: Field> Drop for DkgNode<F> {
    /// Wipe this node's DKG secret contribution from memory on drop. (The derived shares in
    /// `participant`/`my_shares` are `Copy` ristretto scalars from `fanos-vrf` and cannot be wiped
    /// here without dropping their `Copy` — see that crate.)
    fn drop(&mut self) {
        self.secret.zeroize();
        self.session_nonce.zeroize();
    }
}

impl<F: Field> ZeroizeOnDrop for DkgNode<F> {}

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
                    Some(FrameType::DkgCommit) => self.on_commit(from, f.body),
                    Some(FrameType::DkgComplaint) => self.on_complaint(from, f.body),
                    Some(FrameType::DkgJustify) => self.on_justify(from, f.body),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    //! Byzantine-robustness tests for the DKG control frames — the cluster the audit flagged CRITICAL
    //! (B1–B3) and previously untested. Each drives one participant with crafted adversarial frames.
    use super::*;
    use fanos_field::F2;

    fn coord(i: u8) -> Triple {
        DkgNode::<F2>::coord_of(i)
    }

    /// Dealer `d`'s (commit-frame, deal-to-`j`-frame) from a fixed per-dealer secret, so a test can feed a
    /// participant a *valid* dealing without spinning a whole second node.
    fn dealer_frames(d: u8, j: u8, threshold: usize, n: usize) -> (Vec<u8>, Vec<u8>) {
        let secret = [d; 32];
        let mut rng = DeterministicRng::new(&secret);
        let dealing = dkg::deal(&secret, threshold, n, &mut rng).unwrap();
        let commitment = dealing.commitment().clone();
        let share = dealing.share_for(j).unwrap();
        (commit_frame(d, &commitment), deal_frame(share, &commitment))
    }

    fn completed(effects: &[Effect]) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Notify(Notification::DkgComplete(_))))
    }

    #[test]
    fn a_forged_complaint_cannot_evict_an_honest_dealer() {
        // B1 (CRITICAL). O is participant 1; dealer 2 deals to it validly, so O qualifies dealer 2. A
        // Byzantine node 3 then forges DkgComplaint{complainer = 2, dealer = 2} — the self-complaint an
        // accused dealer cannot answer. With origin authentication O rejects it (from = 3 ≠ complainer 2),
        // so dealer 2 survives and O finalizes with QUAL = {1, 2} ≥ threshold 2, emitting DkgComplete.
        // WITHOUT the fix the forged complaint evicts dealer 2 and O never completes.
        let (n, threshold) = (7, 2);
        let mut o = DkgNode::<F2>::new(Point::at(0), threshold, [1u8; 32], [9u8; 32])
            .with_deadlines(Duration::from_millis(10), Duration::from_millis(10));
        o.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let (commit2, deal2) = dealer_frames(2, 1, threshold, n);
        o.step(
            Instant(1),
            Input::Message {
                from: coord(2),
                frame: commit2,
            },
        );
        o.step(
            Instant(1),
            Input::Message {
                from: coord(2),
                frame: deal2,
            },
        );

        // The forged self-complaint against dealer 2, sent by attacker node 3.
        o.step(
            Instant(2),
            Input::Message {
                from: coord(3),
                frame: complaint_frame(2, 2),
            },
        );

        o.step(Instant(20), Input::Timer(DKG_SHARE_DEADLINE));
        let fin = o.step(Instant(40), Input::Timer(DKG_COMPLAINT_DEADLINE));
        assert!(
            completed(&fin),
            "an honest dealer survives a forged complaint and the DKG completes"
        );
    }

    #[test]
    fn a_commitment_is_only_accepted_from_its_own_dealer() {
        // B1 (CRITICAL). A commitment for dealer 2 relayed by an impostor (node 3) is rejected — no bogus
        // commitment can be pre-registered for a silent dealer (first-writer-wins poisoning). The real
        // dealer 2's direct commit is accepted.
        let mut o = DkgNode::<F2>::new(Point::at(0), 2, [1u8; 32], [9u8; 32]);
        o.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let (commit2, _deal2) = dealer_frames(2, 1, 2, 7);
        o.step(
            Instant(1),
            Input::Message {
                from: coord(3),
                frame: commit2,
            },
        );
        assert!(
            !o.commitments.contains_key(&2),
            "a commitment relayed by an impostor is rejected"
        );
        let (commit2b, _) = dealer_frames(2, 1, 2, 7);
        o.step(
            Instant(1),
            Input::Message {
                from: coord(2),
                frame: commit2b,
            },
        );
        assert!(
            o.commitments.contains_key(&2),
            "the real dealer's own commitment is accepted"
        );
    }

    #[test]
    fn a_justification_is_checked_against_the_qualified_commitment() {
        // B3 (CRITICAL). O qualifies dealer 2 on commitment C2. An equivocating dealer 2 answers a
        // complaint with a justify carrying a DIFFERENT commitment C2' and a share consistent with C2' —
        // which would clear the complaint if verified against the frame's own commitment. Verifying
        // against the qualified C2 (stored) instead, the share does not match, so the justify is rejected
        // and the complaint stays unanswered.
        let (n, threshold) = (7, 2);
        let mut o = DkgNode::<F2>::new(Point::at(0), threshold, [1u8; 32], [9u8; 32]);
        o.step(Instant(0), Input::Command(Command::StartHeartbeat));
        // O adopts dealer 2's real commitment C2 (direct from dealer 2).
        let (commit2, _) = dealer_frames(2, 1, threshold, n);
        o.step(
            Instant(1),
            Input::Message {
                from: coord(2),
                frame: commit2,
            },
        );
        assert!(o.commitments.contains_key(&2));

        // A complaint by node 3 against dealer 2 (authentic: from = complainer 3).
        o.step(
            Instant(2),
            Input::Message {
                from: coord(3),
                frame: complaint_frame(3, 2),
            },
        );

        // Dealer 2 tries to clear it with a share/commitment from a DIFFERENT polynomial (secret 22).
        let bogus_secret = [22u8; 32];
        let mut rng = DeterministicRng::new(&bogus_secret);
        let bogus = dkg::deal(&bogus_secret, threshold, n, &mut rng).unwrap();
        let bogus_commitment = bogus.commitment().clone();
        let bogus_share = bogus.share_for(3).unwrap().clone();
        o.step(
            Instant(3),
            Input::Message {
                from: coord(2),
                frame: justify_frame(2, &bogus_share, &bogus_commitment),
            },
        );
        assert!(
            !o.justified.get(&2).is_some_and(|s| s.contains(&3)),
            "a justify against a non-qualified commitment does not clear the complaint"
        );
    }

    #[test]
    fn a_fresh_session_nonce_makes_the_dealing_fresh() {
        // B6. The same long-term secret with DIFFERENT session nonces must produce DIFFERENT dealt
        // frames, so a node re-keying with a reused secret does not repeat its shares — while the same
        // (secret, nonce) stays deterministic (the sans-I/O replay property).
        let secret = [7u8; 32];
        let deals = |nonce: [u8; 32]| -> Vec<Vec<u8>> {
            DkgNode::<F2>::new(Point::at(0), 2, secret, nonce)
                .step(Instant(0), Input::Command(Command::StartHeartbeat))
                .into_iter()
                .filter_map(|e| match e {
                    Effect::Send { frame, .. } => Some(frame),
                    _ => None,
                })
                .collect()
        };
        let a = deals([1u8; 32]);
        assert!(!a.is_empty(), "dealing emits frames");
        assert_ne!(
            a,
            deals([2u8; 32]),
            "different session nonces yield different dealings (fresh shares)"
        );
        assert_eq!(
            a,
            deals([1u8; 32]),
            "same secret+nonce is deterministic (replayable)"
        );
    }

    /// The Fano-point index whose node address is `to` (the inverse of `Point::at`), for routing frames.
    fn node_at_f2(to: Triple) -> Option<usize> {
        (0..Plane::<F2>::N as usize).find(|&k| Point::<F2>::at(k).coords() == to)
    }

    /// Deliver every queued `(from, target, frame)` — routing each node's resulting sends back onto the
    /// bus — until the bus is quiescent. `clock` advances monotonically so stepped inputs stay ordered.
    fn drain(nodes: &mut [DkgNode<F2>], bus: &mut Vec<(Triple, usize, Vec<u8>)>, clock: &mut u64) {
        while !bus.is_empty() {
            let (from, target, frame) = bus.remove(0);
            *clock += 1;
            for e in nodes[target].step(Instant(*clock), Input::Message { from, frame }) {
                if let Effect::Send { to, frame } = e
                    && let Some(k) = node_at_f2(to)
                {
                    bus.push((Point::<F2>::at(target).coords(), k, frame));
                }
            }
        }
    }

    #[test]
    fn a_completed_dkg_exposes_consistent_beacon_material() {
        // Drive an all-honest t-of-n DKG to completion by hand (so the test keeps ownership of the nodes),
        // then check the material a randomness beacon consumes (fanos_vrf::beacon): every node exposes the
        // SAME aggregate commitment, and each node's final share verifies against it — so a beacon partial
        // from that share verifies and the group can produce its per-epoch seed.
        let (n, t) = (7usize, 4usize);
        let mut nodes: Vec<DkgNode<F2>> = (0..n)
            .map(|i| {
                DkgNode::<F2>::new(Point::at(i), t, [i as u8 + 1; 32], [(i as u8) ^ 0x5A; 32])
                    .with_deadlines(Duration::from_millis(10), Duration::from_millis(10))
            })
            .collect();

        let mut clock = 0u64;
        let mut bus: Vec<(Triple, usize, Vec<u8>)> = Vec::new();
        // Kick off: every node deals its sharing and broadcasts its commitment.
        for (k, node) in nodes.iter_mut().enumerate() {
            for e in node.step(Instant(0), Input::Command(Command::StartHeartbeat)) {
                if let Effect::Send { to, frame } = e
                    && let Some(j) = node_at_f2(to)
                {
                    bus.push((Point::<F2>::at(k).coords(), j, frame));
                }
            }
        }
        drain(&mut nodes, &mut bus, &mut clock);
        // Sharing deadline (no complaints — all honest), then complaint deadline ⇒ finalize.
        for node in &mut nodes {
            let _ = node.step(Instant(100), Input::Timer(DKG_SHARE_DEADLINE));
        }
        drain(&mut nodes, &mut bus, &mut clock);
        let done = (0..n)
            .filter(|&k| {
                completed(&nodes[k].step(Instant(200), Input::Timer(DKG_COMPLAINT_DEADLINE)))
            })
            .count();
        drain(&mut nodes, &mut bus, &mut clock);
        assert_eq!(done, n, "all honest nodes complete the DKG");

        let agg0 = nodes[0]
            .aggregate_commitment()
            .expect("a completed DKG exposes its aggregate commitment");
        for (k, node) in nodes.iter().enumerate() {
            let agg = node.aggregate_commitment().expect("aggregate commitment");
            assert_eq!(
                agg.to_bytes(),
                agg0.to_bytes(),
                "every node agrees on the aggregate commitment"
            );
            assert!(
                vss::verify_share(&node.final_share(), &agg0),
                "node {k}'s final share verifies against the group aggregate — beacon-ready"
            );
        }
    }
}
