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
//!    commitment and no unanswered complaint. If `|QUAL| ≥ threshold`, the node computes the joint
//!    public key `Y = Σ_{d∈QUAL} C_{d,0}` and folds exactly the `QUAL` shares into its final key share —
//!    so `Y` and the share are over the identical set.
//! 5. **Confirm.** The node broadcasts a digest of *everything its provisioning file depends on*
//!    (`DkgConfirm`) and publishes [`Notification::DkgComplete`] only once a **threshold** of participants
//!    have answered with the same one; otherwise it says [`Notification::DkgDiverged`] and publishes no
//!    key. The threshold is not a choice: a beacon round needs `t` partials and partials combine only if
//!    they are shares of one secret, so `t` agreeing participants is exactly the condition under which
//!    this node's file is usable.
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
//! the accused dealer (to be justified) without an echo relay. Against a *Byzantine equivocating* dealer
//! that deals validly to some members and not to others, the justification round overrules it and every
//! honest node computes the **same** `QUAL`. No node ever learns the joint secret. The same engine runs
//! under the simulator and a real transport, exactly like the overlay node.
//!
//! ## What that argument assumes, and what happens when the assumption fails
//!
//! It assumes **delivery**. `QUAL` is computed from each participant's own inbox, and the broadcast under
//! it is `n − 1` point-addressed sends with no acknowledgement (see [`DkgNode::broadcast_to_peers`], which
//! states the repair this crate still owes). One dropped directed link is enough to fork it —
//! `one_censored_link_gives_the_dkg_two_different_qualified_sets` asserts exactly that, with no faulty
//! participant and no forged frame — and a fork means aggregate commitments that differ and final shares
//! that never combine.
//!
//! **Step 5 does not repair that fork; it ends the silence around it.** Before it, a forked ceremony
//! reported `DkgComplete` exactly like an agreeing one, so a founder wrote a beacon share to disk and
//! learned months later that its cell's epoch clock would not turn. A ceremony that cannot agree now says
//! so, names how many peers answered, and publishes nothing.

#![forbid(unsafe_code)]

pub mod beacon;
pub mod recovery;
pub use beacon::BeaconNode;
pub use beacon::BeaconRefusal;
pub use recovery::{RecoveryAuthorization, RgcFormat};

use std::collections::btree_map::Entry;
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
/// The confirm-phase deadline timer: after this, a node either publishes the joint key or reports that its
/// peers did not agree on it.
const DKG_CONFIRM_DEADLINE: TimerToken = TimerToken(2);

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
    /// `QUAL` closed and the key computed; collecting peers' agreement digests before publishing it.
    ///
    /// The DKG proper is over here — no share, complaint or justification can change the outcome any more.
    /// What is still open is whether the outcome is the **same** one this node's peers reached, which is a
    /// different question and the only one this phase asks.
    Confirm,
    /// Key published, or withheld because the cell did not agree on it, or abandoned below threshold.
    Done,
}

/// Why the DKG refused a frame — the counters that made audit B1–B3 observable.
///
/// Those three were CRITICAL: unauthenticated complaint/commit/justify frames (one node could evict any
/// honest dealer), a discarded `ingest_share` result (the joint key could include a dealer whose Feldman
/// check had failed), and a justification verified against the frame's own commitment rather than the
/// qualified one. All are fixed. **None left a trace.**
///
/// A DKG that refuses forged complaints and a DKG nobody is talking to are the same silence, and this
/// ceremony produces the beacon key every epoch-aligned mechanism depends on — so a ceremony that fails to
/// terminate has to be able to say why.
///
/// Counters, not logs: `no_std`, sans-I/O, nowhere to write.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct DkgRejects {
    /// A complaint that did not come from the complainer it names — **B1**. A Byzantine node forging
    /// complaints in another's name can evict every honest dealer, and this is the only trace it leaves.
    pub complaint_impersonated: u64,
    /// A commitment that did not come from the dealer it names — B1's sibling on the commit path.
    pub commit_impersonated: u64,
    /// A justification that did not verify against the **qualified** commitment — **B3**. The frame's own
    /// commitment is deliberately ignored, so a dealer cannot justify itself with a commitment it just made
    /// up; this counts the attempts.
    pub justify_mismatch: u64,
    /// A dealt share that failed its Feldman check — **B2**. Discarding the result silently is what let a
    /// rejected dealer into the joint key.
    pub deal_rejected: u64,
    /// A frame this build could not parse or does not handle.
    pub frame_unusable: u64,
    /// A confirmation that did not come from the participant it names — B1's sibling on the agreement path.
    /// It cannot evict a dealer, but it can make a node believe its key is agreed when it is not, which is
    /// the one failure this phase exists to prevent.
    pub confirm_impersonated: u64,
    /// A participant that confirmed **two different** outcomes. The first is kept — a later one cannot
    /// retract a digest already counted — and this counts the attempts, since equivocating here is a
    /// deliberate act with no honest cause.
    pub confirm_equivocated: u64,
}


/// A node participating in a `t`-of-`n` distributed key generation across its cell.
pub struct DkgNode<F: Field> {
    /// Why this ceremony refused frames — see [`DkgRejects`].
    rejects: DkgRejects,
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
    /// The joint public key computed at finalize, held until the confirm phase decides whether to publish
    /// it. `None` before finalize and on the below-threshold abandon.
    joint: Option<[u8; 32]>,
    /// Opaque per-ceremony context folded into the agreement digest, so participants that ran under
    /// *different provisioning inputs* disagree even when their key material happens to match.
    ///
    /// The host supplies whatever names this ceremony to it. `fanos keygen` passes the network id it
    /// derived from the roster file, which is what catches the operator error the key material cannot: two
    /// founders holding rosters that differ produce two networks, and nothing else in this engine would
    /// ever notice.
    context: [u8; 32],
    /// Participant index → the agreement digest it broadcast. Bounded by the participant set, since the
    /// key is authenticated against the sender's own coordinate.
    confirmations: BTreeMap<u8, [u8; 32]>,
    /// `(agreed, heard)` once the confirm phase has closed — see [`DkgNode::agreement`].
    agreement: Option<(usize, usize)>,
}

impl<F: Field> DkgNode<F> {
    /// Why this ceremony has refused frames — the operator's read on whether a DKG that has not terminated
    /// is starved of peers or under attack.
    ///
    /// Those look identical without it: audit B1 was a Byzantine node forging complaints in other members'
    /// names to evict every honest dealer, and its only symptom is a ceremony that does not finish.
    #[must_use]
    pub const fn rejects(&self) -> DkgRejects {
        self.rejects
    }

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
            rejects: DkgRejects::default(),
            aggregate: None,
            joint: None,
            context: [0u8; 32],
            confirmations: BTreeMap::new(),
            agreement: None,
        }
    }

    /// Bind this ceremony to a caller-chosen **context**, folded into the agreement digest of step 5.
    ///
    /// Two participants agree only if they agree on this too, so it is where a host puts whatever it knows
    /// that the engine does not: `fanos keygen` passes the network id derived from the roster file, which
    /// makes a mismatched roster a *named* disagreement rather than two networks founded by accident.
    ///
    /// Defaults to zero, which is the honest default rather than a weak one — an engine given no context
    /// agrees on the key material alone, exactly as it did before this existed.
    #[must_use]
    pub const fn with_context(mut self, context: [u8; 32]) -> Self {
        self.context = context;
        self
    }

    /// Override the phase deadlines (sharing, then complaint). Defaults are 1.5 s each.
    ///
    /// **The confirm phase is not a third parameter, and deriving it is the point.** What it waits for is
    /// one broadcast to reach the cell and come back — the same thing the complaint phase waits for — so it
    /// takes `complaint`'s value. A separate knob would be a third number to size against the same network
    /// property, and the only way for the two to be right is for them to be one.
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
            self.rejects.frame_unusable = self.rejects.frame_unusable.saturating_add(1);
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
            self.rejects.commit_impersonated = self.rejects.commit_impersonated.saturating_add(1);
            return Vec::new(); // a commitment may only come from its own dealer
        }
        self.note_commitment(d, commitment);
        // **A commitment that arrives during the complaint phase still needs its complaint**, and this is
        // the half the pull was useless without. `open_complaints` draws its candidates from the
        // commitments held *at the deadline*, so a dealer answering a `DkgCommitReq` afterwards would be
        // registered and then never complained about — leaving this node holding the commitment, holding no
        // share, and dropping the dealer from `QUAL` exactly as if the frame had never arrived. Raising it
        // here puts the late dealer back on the ordinary path: complain, be justified, qualify.
        //
        // The guard is the same one `open_complaints` uses, so a dealer that *is* qualifiable (its deal
        // arrived, only the commitment was lost) is not accused of anything.
        if self.phase == Phase::Complaint && d != self.index && !self.qualified.contains(&d) {
            self.complaints.entry(d).or_default().insert(self.index);
            return Self::broadcast_to_peers(&complaint_frame(self.index, d));
        }
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
            // **B1, counted.** Forging complaints in another member's name evicts every honest dealer, and a
            // ceremony that never terminates is its only other symptom.
            self.rejects.complaint_impersonated = self.rejects.complaint_impersonated.saturating_add(1);
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
                effects.extend(Self::broadcast_to_peers(&justify_frame(d, &share, &commitment)));
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
            self.rejects.justify_mismatch = self.rejects.justify_mismatch.saturating_add(1);
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
            effects.extend(Self::broadcast_to_peers(&justify_frame(d, &share, &commitment)));
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
        // **Ask the dealers we never heard from, before deciding anything about them.** A dealer whose
        // commitment was lost in transit is not complained about below — `candidates` is drawn from
        // `commitments`, so an absent one is silently absent from `QUAL` here and present in it everywhere
        // the frame did arrive. That is the whole of the fork
        // `one_censored_link_gives_the_dkg_two_different_qualified_sets` measures: one dropped frame, two
        // different qualified sets, and a final share that verifies against neither the other's aggregate.
        //
        // **A pull to the dealer, not a relay through a peer**, and the difference is forced rather than
        // chosen: every frame in this class is authenticated by the transport's `from` (`on_commit` refuses
        // unless `dealer_of(from) == Some(d)`), so a commitment handed over by anyone else is refused by the
        // rule that stops a bogus one being pre-registered for a silent dealer. The only participant that can
        // answer for `d` is `d`, so the request goes there and the answer arrives with the authentication it
        // needs. It is the same shape `BeaconNode::request_sync` uses and it needs no new trust: the request
        // is contentless, and the answer is a commitment the dealer was already broadcasting to everyone.
        //
        // **Bounded by the participant set**, one request per missing dealer per ceremony, sent at the one
        // instant the missing ones are known — so there is no retry timer to size and nothing to keep in
        // step with the phase deadlines.
        for d in 1..=self.n as u8 {
            if d != self.index && !self.commitments.contains_key(&d) {
                effects.push(Effect::Send {
                    to: Self::coord_of(d),
                    frame: frame(FrameType::DkgCommitReq, &[]),
                });
            }
        }
        let candidates: Vec<u8> = self.commitments.keys().copied().collect();
        for d in candidates {
            if !self.qualified.contains(&d) {
                // We are missing/invalid a share from d → complain (recorded locally + broadcast).
                self.complaints.entry(d).or_default().insert(self.index);
                effects.extend(Self::broadcast_to_peers(&complaint_frame(self.index, d)));
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

        if qual.len() < self.threshold {
            // Too few dealers survived — no key can be formed (genuine under-participation).
            self.phase = Phase::Done;
            self.done = true;
            return Vec::new();
        }
        // The DKG proper is over: nothing arriving now can change `QUAL`, the aggregate or the share, and
        // every handler guards on this. What is *not* over is whether the cell reached the same answer,
        // which the confirm phase below asks and `Phase::Confirm` — not this flag — gates.
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
        // share verifies against it. Every honest node that folded the same QUAL agrees on this — and
        // whether it did is precisely what the round below establishes rather than assumes.
        self.aggregate = VssCommitment::aggregate(&refs);
        self.joint = Some(joint);

        // **Step 5.** `QUAL` is a decision that must agree cell-wide and is computed from a live local
        // read, which `fanos_runtime::healer` names as a defect class and `broadcast_to_peers` records as
        // this crate's eighth instance. The repair that class prescribes — publish, don't sense-and-act —
        // has no medium here (during a ceremony the engine *is* the node: no overlay, no store). What is
        // available is the cheaper half of it: publish the **outcome**, and refuse to act on a local read
        // that the cell did not confirm.
        self.phase = Phase::Confirm;
        let Some(digest) = self.agreement_digest() else {
            return Vec::new(); // unreachable: `aggregate` was just set — but a `?` here beats an unwrap
        };
        let mut effects = Self::broadcast_to_peers(&confirm_frame(self.index, &digest));
        effects.push(Effect::ArmTimer {
            token: DKG_CONFIRM_DEADLINE,
            after: self.complaint_deadline,
        });
        effects
    }

    /// The digest every participant must match: **everything this node's provisioning file depends on.**
    ///
    /// Not the joint key alone, and the difference is the operator errors it catches. A file carries the
    /// aggregate commitment, the threshold, and the network the ceremony was for; two founders can arrive
    /// at the same key material from different `--threshold` values or different roster files, and a beacon
    /// provisioned from mismatched files fails exactly as a forked `QUAL` does. Hashing them together makes
    /// one comparison answer for all of them.
    ///
    /// `None` before finalize, since there is no outcome to commit to.
    fn agreement_digest(&self) -> Option<[u8; 32]> {
        let aggregate = self.aggregate.as_ref()?;
        let aggregate = aggregate.to_bytes();
        let mut buf = Vec::with_capacity(32 + 16 + aggregate.len());
        buf.extend_from_slice(&self.context);
        // Width-explicit rather than `as u8`: `n` is the plane's point count, which is 65 793 on the widest
        // field this tree defines, and a truncating cast is how two different ceremonies come to agree.
        buf.extend_from_slice(&(self.n as u64).to_le_bytes());
        buf.extend_from_slice(&(self.threshold as u64).to_le_bytes());
        buf.extend_from_slice(&aggregate);
        Some(fanos_primitives::hash::hash_labeled(
            fanos_primitives::hash::label::DKG_CONFIRM,
            &buf,
        ))
    }

    /// A peer's agreement digest. **Authenticated** exactly as a commitment is — only from the participant
    /// it names — because a forged confirmation is the one frame that could tell a node its key is agreed
    /// when it is not, which is the failure this whole phase exists to prevent.
    ///
    /// Recorded in **any** phase, deliberately. Deadlines fire on each node's own clock, so a fast peer's
    /// confirmation routinely arrives before this node has finalized; dropping it would make the tally a
    /// measurement of clock skew. It is data, and it is counted when the phase closes.
    fn on_confirm(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some((j, digest)) = parse_confirm(body) else {
            self.rejects.frame_unusable = self.rejects.frame_unusable.saturating_add(1);
            return Vec::new();
        };
        if self.dealer_of(from) != Some(j) {
            self.rejects.confirm_impersonated = self.rejects.confirm_impersonated.saturating_add(1);
            return Vec::new();
        }
        if j == self.index {
            return Vec::new(); // our own broadcast, arriving back
        }
        match self.confirmations.entry(j) {
            Entry::Vacant(slot) => {
                slot.insert(digest);
            }
            // First wins: a later, different digest cannot retract one already counted, and an honest
            // participant emits exactly one.
            Entry::Occupied(held) if *held.get() != digest => {
                self.rejects.confirm_equivocated = self.rejects.confirm_equivocated.saturating_add(1);
            }
            Entry::Occupied(_) => {}
        }
        Vec::new()
    }

    /// Confirm deadline: publish the joint key **iff a threshold of participants confirmed this one**.
    ///
    /// The rule is derived, not chosen. A beacon round needs `t` partials, and partials combine only if
    /// they are evaluations of one polynomial — so `t` participants holding this node's aggregate is
    /// exactly the condition under which the file this node is about to write can ever produce a round.
    /// Below it the node holds a key that is real, verifiable and useless, and says so.
    ///
    /// **A dropped confirmation costs a false refusal, never a false accept**, which is the direction that
    /// matters: refusing a good ceremony costs a re-run, and accepting a forked one founds a cell whose
    /// epoch clock never turns.
    fn close_confirm(&mut self) -> Vec<Effect> {
        if self.phase != Phase::Confirm {
            return Vec::new();
        }
        self.phase = Phase::Done;
        let Some(mine) = self.agreement_digest() else {
            return Vec::new();
        };
        let heard = self.confirmations.len();
        let agreed = 1 + self.confirmations.values().filter(|&&d| d == mine).count();
        self.agreement = Some((agreed, heard));
        if agreed >= self.threshold {
            return self.joint.map_or_else(Vec::new, alloc_vec_notify);
        }
        std::vec![Effect::Notify(Notification::DkgDiverged {
            agreed: u8::try_from(agreed).unwrap_or(u8::MAX),
            heard: u8::try_from(heard).unwrap_or(u8::MAX),
        })]
    }

    /// `(agreed, heard)` once the confirm phase has closed — how many participants (this node included)
    /// hold the same outcome, and how many answered at all.
    ///
    /// The two are reported separately because they call for opposite actions: `heard` low is a ceremony
    /// that did not assemble (check that every founder is running), while `heard` high with `agreed` low is
    /// a ceremony that assembled and **disagreed** (check that every founder holds the identical roster and
    /// threshold, then re-run).
    #[must_use]
    pub const fn agreement(&self) -> Option<(usize, usize)> {
        self.agreement
    }

    /// Answer a participant that reached the sharing deadline without this node's commitment.
    ///
    /// Silent unless this node has dealt — there is nothing to hand over before `start`, exactly as
    /// `BeaconNode::on_beacon_req` is silent before its first round. The reply carries **only this node's
    /// own** commitment, which is what makes the pull sound: the requester's `on_commit` will refuse
    /// anything else, and this node cannot speak for another dealer even if asked to.
    ///
    /// The request is not authenticated beyond the transport, and does not need to be: it names nothing,
    /// and the answer is a frame this node broadcast to the whole cell moments earlier. The cost of a
    /// forged request is one re-send of public data to a peer that could have read it from the broadcast.
    fn on_commit_req(&mut self, from: Triple) -> Vec<Effect> {
        if self.done {
            return Vec::new();
        }
        let Some(dealing) = self.dealing.as_ref() else {
            return Vec::new();
        };
        std::vec![Effect::Send {
            to: from,
            frame: commit_frame(self.index, dealing.commitment()),
        }]
    }

    /// Broadcast `frame` to every *other* cell member (the reliable-broadcast primitive).
    ///
    /// # It is not reliable, and QUAL agreement is what pays for that
    ///
    /// This is `n − 1` point-addressed sends with no acknowledgement and no retransmission. Every rung of
    /// the transport's resolution ladder can drop one — and measured 2026-08-16, the two rungs share a
    /// failure mode: the directory and the connection cache are both keyed by coordinate, so a reseat
    /// invalidates both at the same instant (`conns.cache_miss` against occupied points read `[2,2,2]` on a
    /// three-node fleet, i.e. every node missing both rungs for both real peers).
    ///
    /// What rides it is complaints and justifications, and `QUAL` is computed from **what this node
    /// received**: `qualified.insert(d)` fires when we hold dealer `d`'s commitment *and* our share from it,
    /// and an unanswered complaint disqualifies. So a single dropped frame does not merely delay a node — it
    /// gives it a **different qualified set**, hence a different aggregate commitment, hence a final share
    /// that does not interoperate with its peers'. Agreement here is a correctness property, not a
    /// convergence one.
    ///
    /// **And this is exactly why it must NOT simply become [`Effect::Flood`].** Flooding fixes *reach under
    /// coordinate churn*, which is what the beacon round needed; it does not make a broadcast reliable, so
    /// it would swap one silent partial-delivery mode for another.
    ///
    /// # Which repair — and the first answer was wrong for a reason worth keeping
    ///
    /// `fanos_runtime::healer` states the governing rule and counts instances: *"a decision which must agree
    /// cell-wide is computed from closed published epochs, never from a live local read"*, naming its own
    /// case the **seventh**. `QUAL` is precisely that shape and is therefore the eighth — and the most
    /// severe, because the others decide provisioning or quality while a divergent `QUAL` yields key shares
    /// that do not interoperate at all.
    ///
    /// That rule prescribes *"publish, don't sense-and-act"*, and the obvious reading — publish each
    /// broadcast frame to a directory slot and read the set at the deadline — **cannot be built here.** The
    /// ceremony **is** the engine: `spawn_cell` and the `fanos` binary both run `DkgCeremony` as the node's
    /// whole engine, so during a ceremony there is no overlay, no store, and nothing to publish *to*. A law
    /// about closed published epochs has no medium on this path. (It also holds no `Client`, so the host
    /// could not read one either.)
    ///
    /// **The second answer was wrong too, and an existing test proved it — which is the useful part.** The
    /// obvious remaining repair is to make the flood *epidemic*: relay each broadcast frame once on first
    /// receipt, deduplicated, exactly as `BeaconNode::on_round` re-floods rounds. Built, it broke
    /// `a_commitment_is_only_accepted_from_its_own_dealer` immediately, and the reason is structural rather
    /// than a slip:
    ///
    /// > **Every frame in this class is authenticated by the transport's `from`.** `on_commit` refuses
    /// > unless `dealer_of(from) == Some(d)` — "a commitment may only come from its own dealer", which is
    /// > what stops a bogus commitment being pre-registered for a silent one — and `on_complaint` is
    /// > accepted "only direct from its complainer `c`", without which a Byzantine node forges complaints in
    /// > another's name.
    ///
    /// A relayed frame arrives from the **relayer**, so it is refused by exactly the rule that makes the
    /// ceremony safe. **Epidemic delivery is therefore not available to this class at all**, and the
    /// difference from the beacon round is now precise: a round carries its own proof against the group
    /// commitment, so any relayer can hand it over; these frames carry none, so the only thing vouching for
    /// them is the connection they arrived on.
    ///
    /// **What that leaves, stated so the next attempt does not re-derive it.** Reliable delivery here needs
    /// the frames to authenticate themselves — a dealer/complainant signature over the body, after which
    /// relaying is sound and the epidemic works — or an acknowledgement-and-retransmit layer under the
    /// direct sends. The first is the tree's own pattern (self-authenticating frames are relayable,
    /// transport-authenticated ones are not) and is the recommendation.
    ///
    /// **The signature route has a blocker of its own, priced 2026-08-19 so the third attempt does not pay
    /// for it again.** A signature is only checkable against a *verifier the receiver associates with the
    /// claimed dealer index*, and there are three places that could come from, two of which are closed:
    ///
    /// * **the roster** — `fanos keygen --roster` speaks `x:y:z@host:port` and carries no keys, so this is
    ///   an operator-facing format change, not a code one;
    /// * **inline in the frame** — self-defeating: a bundle carried by the frame is only as good as the
    ///   binding between it and the index, which is the thing being established;
    /// * **the transport** — sound, and the one that fits. Every participant authenticates by mutual TLS on
    ///   a direct connection, and `NodeCredentials::descriptor_identity` makes a node's verifier a function
    ///   of that certificate. So a receiver that has handshaken with participant `j` **can** know `j`'s
    ///   verifier, and `Command::Control` is the designed path for a host to hand key material to a
    ///   sub-engine (*"a sub-engine that installs key material from one is not thereby accepting key
    ///   material from the network"*).
    ///
    /// What blocks the third is small and nameable: **the driver emits no notification when a peer completes
    /// a handshake**, so the host never learns the moment at which it would hand one over. That is the
    /// enabling change, and it is smaller than either alternative.
    ///
    /// The bootstrap also works out, which is worth stating because it looks circular: a ceremony's roster
    /// names everyone and every participant dials every other at the start, so the verifiers are established
    /// while all links are healthy. The relay is then needed only when a link fails *later* — which is
    /// exactly the failure `one_censored_link_gives_the_dkg_two_different_qualified_sets` models.
    ///
    /// The flood below **is** kept: it costs nothing, it preserves `from` (this node is the dealer of what
    /// it broadcasts), and it removes the dependence on resolving `q² + q + 1` coordinates that a churning
    /// cell cannot satisfy. It does not close the `QUAL` fork, and
    /// `one_censored_link_gives_the_dkg_two_different_qualified_sets` still asserts that fork today — what
    /// is no longer true is that the fork is *silent*: the confirm round refuses to publish a key the cell
    /// did not confirm.
    ///
    fn broadcast_to_peers(frame: &[u8]) -> Vec<Effect> {
        std::vec![Effect::Flood { frame: frame.to_vec() }]
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
                    Some(FrameType::DkgCommitReq) => self.on_commit_req(from),
                    Some(FrameType::DkgConfirm) => self.on_confirm(from, f.body),
                    _ => Vec::new(),
                },
                Err(_) => Vec::new(),
            },
            Input::Timer(DKG_SHARE_DEADLINE) => self.open_complaints(),
            Input::Timer(DKG_COMPLAINT_DEADLINE) => self.finalize(),
            Input::Timer(DKG_CONFIRM_DEADLINE) => self.close_confirm(),
            _ => Vec::new(),
        }
    }

    fn address(&self) -> Triple {
        self.coord.coords()
    }
}

/// Encode a `DkgConfirm`: `index(1) ‖ digest(32)`.
///
/// The index is carried even though the transport already names the sender, for the same reason
/// `commit_frame` carries the dealer: the receiver checks the two against each other, so a frame that
/// travelled a path its author did not is refused rather than attributed to whoever handed it over.
fn confirm_frame(index: u8, digest: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 32);
    body.push(index);
    body.extend_from_slice(digest);
    frame(FrameType::DkgConfirm, &body)
}

/// Parse a `DkgConfirm` body into `(index, digest)`. Exact length: a 32-byte digest and nothing else.
fn parse_confirm(body: &[u8]) -> Option<(u8, [u8; 32])> {
    let (&index, rest) = body.split_first()?;
    Some((index, <[u8; 32]>::try_from(rest).ok()?))
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
        // **The observable is the qualified set, not the notification, and that is a correction rather than
        // a convenience.** This test drives ONE node; since the confirm round landed, a node that has heard
        // from nobody publishes no key however healthy its own ceremony was — correctly, because it cannot
        // know the cell reached the same answer. What this test is about is whether dealer 2 survived a
        // forged complaint, and the aggregate commitment says so exactly: it exists only when
        // `|QUAL| ≥ threshold`, and with `threshold = 2` that needs dealer 2 in it beside O itself.
        assert!(
            !completed(&fin),
            "a lone node must not publish a joint key: no peer confirmed it (this is the confirm round, not \
             a failure of the dealer under test — the assertion below is the one about the dealer)"
        );
        assert!(
            o.aggregate_commitment().is_some(),
            "an honest dealer survives a forged complaint: QUAL reached the threshold and the key was formed"
        );

        // **Surviving the attack is half of it.** B1's whole effect was a ceremony that would not terminate,
        // and a ceremony starved of peers does not terminate either — so without this counter the two are the
        // same observation and an operator has nothing to act on. Node 3 forged a complaint naming node 2 as
        // complainer; that is the only trace it leaves.
        assert_eq!(
            o.rejects().complaint_impersonated,
            1,
            "the forged complaint is refused AND recorded, or an attack on the ceremony is indistinguishable \
             from the ceremony being quiet"
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
        // The commit path's half of B1, counted for the same reason as the complaint path: pre-registering a
        // bogus commitment for a silent dealer is first-writer-wins poisoning, and its only other symptom is
        // a dealer that mysteriously fails to qualify.
        assert_eq!(o.rejects().commit_impersonated, 1, "the impostor's commitment is refused AND recorded");
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
        drain_over(nodes, bus, clock, None);
    }

    /// [`drain`] with one directed link dark — see [`fire_over`].
    fn drain_over(
        nodes: &mut [DkgNode<F2>],
        bus: &mut Vec<(Triple, usize, Vec<u8>)>,
        clock: &mut u64,
        dark: Option<(Triple, usize)>,
    ) {
        while !bus.is_empty() {
            let (from, target, frame) = bus.remove(0);
            *clock += 1;
            let origin = Point::<F2>::at(target).coords();
            for e in nodes[target].step(Instant(*clock), Input::Message { from, frame }) {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(k) = node_at_f2(to)
                            && dark != Some((origin, k))
                        {
                            bus.push((origin, k, frame));
                        }
                    }
                    // A flood reaches every other node of this cell — the bus is the connection graph here,
                    // and it is complete, which is what the driver's `flood_connections` approximates.
                    Effect::Flood { frame } => {
                        for k in 0..nodes.len() {
                            if k != target && dark != Some((origin, k)) {
                                bus.push((origin, k, frame.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Fire `token` on every node, putting what each emits onto the bus, then drain the bus.
    ///
    /// Returns each node's own effects, in node order, so a caller can still ask what a *particular* node
    /// said. Written once because the ceremony has three deadline-driven phases and a test that fires two of
    /// them measures a ceremony that has not finished: before this existed the complaint deadline's effects
    /// were consumed by `completed(..)` and dropped, so the confirm round's broadcasts never reached anyone
    /// and every node would have reported a cell that did not agree.
    fn fire(
        nodes: &mut [DkgNode<F2>],
        bus: &mut Vec<(Triple, usize, Vec<u8>)>,
        clock: &mut u64,
        token: TimerToken,
    ) -> Vec<Vec<Effect>> {
        fire_over(nodes, bus, clock, token, None)
    }

    /// [`fire`] with one directed link **dark** — `Some((from, to))` drops everything the node at `from`
    /// emits toward node `to`, in both the addressed and the flooded direction.
    ///
    /// One helper rather than two, because the censored copy this replaces had already drifted: it matched
    /// only `Effect::Send` while `broadcast_to_peers` returns `Effect::Flood`, so it censored the whole
    /// broadcast substrate rather than one link, and the claim it was demonstrating ("one dropped link is
    /// enough to fork QUAL") was demonstrated by nothing.
    fn fire_over(
        nodes: &mut [DkgNode<F2>],
        bus: &mut Vec<(Triple, usize, Vec<u8>)>,
        clock: &mut u64,
        token: TimerToken,
        dark: Option<(Triple, usize)>,
    ) -> Vec<Vec<Effect>> {
        let mut per_node = Vec::with_capacity(nodes.len());
        for k in 0..nodes.len() {
            *clock += 1;
            let origin = Point::<F2>::at(k).coords();
            let effects = nodes[k].step(Instant(*clock), Input::Timer(token));
            for e in &effects {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(j) = node_at_f2(*to)
                            && dark != Some((origin, j))
                        {
                            bus.push((origin, j, frame.clone()));
                        }
                    }
                    Effect::Flood { frame } => {
                        for j in 0..nodes.len() {
                            if j != k && dark != Some((origin, j)) {
                                bus.push((origin, j, frame.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }
            per_node.push(effects);
        }
        drain_over(nodes, bus, clock, dark);
        per_node
    }

    /// The companion to the tripwire above, and the acceptance test for the commitment pull: when the loss
    /// is **transient** rather than a permanently dark link, `QUAL` no longer forks.
    ///
    /// Dealer 0's frames to node 1 are dropped for the whole sharing phase and the link then opens — one
    /// outage, which is what a real transport produces and what the tripwire deliberately does not model.
    /// At the sharing deadline node 1 notices it holds no commitment from dealer 0 and **asks dealer 0 for
    /// it**; the answer arrives with the authentication `on_commit` requires, because the only participant
    /// that can answer for a dealer is that dealer. Node 1 then lacks only its *share*, complains through
    /// the ordinary path, is justified, and finalizes on the same qualified set as everyone else.
    ///
    /// Both endpoints asserted: the aggregate commitments agree **and** the recovered node's final share
    /// verifies against the group's, since agreeing on a commitment while holding an unusable share would be
    /// the same defect wearing a different face.
    #[test]
    fn a_transient_outage_no_longer_forks_qual_because_the_dealer_is_asked_directly() {
        let (n, t) = (7usize, 4usize);
        let mut nodes: Vec<DkgNode<F2>> = (0..n)
            .map(|i| {
                DkgNode::<F2>::new(Point::at(i), t, [i as u8 + 1; 32], [(i as u8) ^ 0x5A; 32])
                    .with_deadlines(Duration::from_millis(10), Duration::from_millis(10))
            })
            .collect();
        let dark_from = Point::<F2>::at(0).coords();
        let dark_to = 1usize;

        let mut clock = 0u64;
        let mut bus: Vec<(Triple, usize, Vec<u8>)> = Vec::new();
        for (k, node) in nodes.iter_mut().enumerate() {
            let origin = Point::<F2>::at(k).coords();
            for e in node.step(Instant(0), Input::Command(Command::StartHeartbeat)) {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(j) = node_at_f2(to)
                            && !(origin == dark_from && j == dark_to)
                        {
                            bus.push((origin, j, frame));
                        }
                    }
                    Effect::Flood { frame } => {
                        for j in 0..n {
                            if j != k && !(origin == dark_from && j == dark_to) {
                                bus.push((origin, j, frame.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // The outage lasts exactly as long as the sharing phase.
        while !bus.is_empty() {
            let (from, target, frame) = bus.remove(0);
            clock += 1;
            let origin = Point::<F2>::at(target).coords();
            for e in nodes[target].step(Instant(clock), Input::Message { from, frame }) {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(k) = node_at_f2(to)
                            && !(origin == dark_from && k == dark_to)
                        {
                            bus.push((origin, k, frame));
                        }
                    }
                    Effect::Flood { frame } => {
                        for k in 0..n {
                            if k != target && !(origin == dark_from && k == dark_to) {
                                bus.push((origin, k, frame.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // Sharing deadline: node 1 asks dealer 0 for the commitment it never received. From here the link is
        // whole again, so the answer, the complaint and the justification all flow.
        for (k, node) in nodes.iter_mut().enumerate() {
            let origin = Point::<F2>::at(k).coords();
            for e in node.step(Instant(100), Input::Timer(DKG_SHARE_DEADLINE)) {
                match e {
                    Effect::Send { to, frame } => {
                        if let Some(j) = node_at_f2(to) {
                            bus.push((origin, j, frame));
                        }
                    }
                    Effect::Flood { frame } => {
                        for j in 0..n {
                            if j != k {
                                bus.push((origin, j, frame.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        drain(&mut nodes, &mut bus, &mut clock);
        for node in &mut nodes {
            let _ = node.step(Instant(200), Input::Timer(DKG_COMPLAINT_DEADLINE));
        }
        drain(&mut nodes, &mut bus, &mut clock);

        let agg_majority = nodes[0].aggregate_commitment().expect("the unaffected nodes complete");
        let agg_recovered = nodes[dark_to].aggregate_commitment().expect("the interrupted node completes");
        assert_eq!(
            agg_recovered.to_bytes(),
            agg_majority.to_bytes(),
            "a transient outage must not fork QUAL once the missing commitment can be asked for directly"
        );
        assert!(
            vss::verify_share(&nodes[dark_to].final_share(), &agg_majority),
            "and the recovered node's final share verifies against the group aggregate — it is beacon-ready, \
             not merely in agreement about the commitment"
        );
    }

    /// **A tripwire, and it asserts a defect rather than a property.** One node's inbox is censored — every
    /// frame from dealer 0 is dropped on its way to node 1, which is one lossy link, not an attack — and the
    /// two nodes then finalize on **different qualified sets**, so their aggregate commitments differ and
    /// node 1's final share does not verify against the group's.
    ///
    /// That is the cost of computing `QUAL` from what each node happened to receive, over `n − 1`
    /// point-addressed sends with no acknowledgement and no retransmission
    /// ([`DkgNode::broadcast_to_peers`]). `fanos_runtime::healer` states the governing rule and counts its
    /// own case as the seventh: *"a decision which must agree cell-wide is computed from closed published
    /// epochs, never from a live local read"*. This is the eighth, and the most severe — elsewhere a
    /// divergence costs provisioning quality, here it costs interoperable key material.
    ///
    /// **Invert this test when the published transcript lands.** The assertions below are `assert_ne!` and
    /// a `!verify_share`; both become their opposites, and this doc becomes a note that the rule now holds
    /// on the key-generation path too. Written this way so the repair cannot land silently and so nobody
    /// re-derives the failure from the comment alone.
    #[test]
    fn one_censored_link_gives_the_dkg_two_different_qualified_sets() {
        let (n, t) = (7usize, 4usize);
        let mut nodes: Vec<DkgNode<F2>> = (0..n)
            .map(|i| {
                DkgNode::<F2>::new(Point::at(i), t, [i as u8 + 1; 32], [(i as u8) ^ 0x5A; 32])
                    .with_deadlines(Duration::from_millis(10), Duration::from_millis(10))
            })
            .collect();
        // One directed link, dark in one direction: everything dealer 0 says to node 1 is lost. Node 1 still
        // hears every other dealer, and every other node still hears dealer 0 — so no participant is faulty
        // and no frame is forged. This is the mildest failure a real transport produces.
        let dark_from = Point::<F2>::at(0).coords();
        let dark_to = 1usize;

        let mut clock = 0u64;
        let mut bus: Vec<(Triple, usize, Vec<u8>)> = Vec::new();
        for (k, node) in nodes.iter_mut().enumerate() {
            for e in node.step(Instant(0), Input::Command(Command::StartHeartbeat)) {
                if let Effect::Send { to, frame } = e
                    && let Some(j) = node_at_f2(to)
                {
                    let from = Point::<F2>::at(k).coords();
                    if !(from == dark_from && j == dark_to) {
                        bus.push((from, j, frame));
                    }
                }
            }
        }
        // Both helpers take the dark edge as a parameter, so this test's transport is the shared one with
        // one link removed rather than a copy that can drift from it — and it did drift once: the copy this
        // replaces matched only `Effect::Send` while `broadcast_to_peers` returns `Effect::Flood`, so it
        // censored every complaint and justification in the cell instead of one directed link.
        let dark = Some((dark_from, dark_to));
        drain_over(&mut nodes, &mut bus, &mut clock, dark);
        // Each deadline in turn. The confirm round is a broadcast, so a phase whose effects are dropped
        // would make every node report a cell that never spoke — a different failure from the one under
        // test.
        let mut published: Vec<Vec<Effect>> = Vec::new();
        for token in [DKG_SHARE_DEADLINE, DKG_COMPLAINT_DEADLINE, DKG_CONFIRM_DEADLINE] {
            published = fire_over(&mut nodes, &mut bus, &mut clock, token, dark);
        }


        let agg_majority = nodes[0].aggregate_commitment().expect("the unaffected nodes complete");
        let agg_starved = nodes[dark_to].aggregate_commitment().expect("the starved node completes too — that is the point");
        assert_ne!(
            agg_starved.to_bytes(),
            agg_majority.to_bytes(),
            "one dropped link must be enough to fork QUAL while this is computed from each node's own inbox — \
             if this now passes, the published-transcript repair has landed and this test should be inverted"
        );
        assert!(
            !vss::verify_share(&nodes[dark_to].final_share(), &agg_majority),
            "and the divergence is not cosmetic: the starved node's final share does not verify against the \
             group's aggregate, so its beacon partials would be counted as forgeries for ever"
        );

        // **And the second half, which is what the confirm round buys.** The fork above is unrepaired; what
        // changed is that it can no longer be written to disk in silence. The starved node hears every peer
        // confirm an outcome that is not its own, so it publishes nothing and says how alone it is; the
        // other six confirm each other and publish.
        assert!(
            !completed(&published[dark_to]),
            "the starved node must NOT publish a joint key its cell does not hold — that file's beacon \
             partials would never combine, and nothing else would say so until the epoch clock failed to turn"
        );
        assert!(
            matches!(
                published[dark_to].as_slice(),
                [Effect::Notify(Notification::DkgDiverged { agreed: 1, heard })] if *heard as usize == n - 2
            ),
            "and it must say WHICH failure this is: {} of the 6 peers answered — every one of them except \
             the dealer whose link is dark — and not one agreed, which is a different operator action from \
             a ceremony nobody joined. Got {} effects.",
            n - 2,
            published[dark_to].len()
        );
        let agreeing = (0..n).filter(|&k| completed(&published[k])).count();
        assert_eq!(
            agreeing,
            n - 1,
            "the six that share an inbox agree and publish — a repair that silenced everyone would pass the \
             assertion above and be a worse outcome than the fork"
        );
    }

    /// **A founder that ran under a different roster does not quietly join the network.**
    ///
    /// The key material here is *identical* for everyone: one complete mesh, no losses, no adversary, so
    /// every node folds the same `QUAL` and computes the same aggregate commitment. What differs is the
    /// **context** — the value a host binds the ceremony to, which `fanos keygen` fills with the network id
    /// it derived from the roster file. Two founders holding rosters that differ by one line therefore run
    /// what is arithmetically the same ceremony and provision two different networks.
    ///
    /// Nothing in the key material can catch that, which is the whole reason the digest covers more than the
    /// key: without the context, this test's odd node out agrees with everyone and writes a file naming a
    /// network its peers have never heard of.
    ///
    /// Asserted in both directions — the mismatched node refuses and the rest publish — because a change
    /// that made *everyone* refuse would satisfy the first half and be a worse outcome than the defect.
    #[test]
    fn a_participant_on_a_different_context_agrees_with_nobody() {
        let (n, t) = (7usize, 4usize);
        let odd = 3usize;
        let mut nodes: Vec<DkgNode<F2>> = (0..n)
            .map(|i| {
                let node = DkgNode::<F2>::new(Point::at(i), t, [i as u8 + 1; 32], [(i as u8) ^ 0x5A; 32])
                    .with_deadlines(Duration::from_millis(10), Duration::from_millis(10));
                // Everyone but `odd` ran under the same roster; `odd` had one line more.
                node.with_context(if i == odd { [0xAB; 32] } else { [0xCD; 32] })
            })
            .collect();

        let mut clock = 0u64;
        let mut bus: Vec<(Triple, usize, Vec<u8>)> = Vec::new();
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
        fire(&mut nodes, &mut bus, &mut clock, DKG_SHARE_DEADLINE);
        fire(&mut nodes, &mut bus, &mut clock, DKG_COMPLAINT_DEADLINE);
        let published = fire(&mut nodes, &mut bus, &mut clock, DKG_CONFIRM_DEADLINE);

        // The premise: the ceremony really did agree on the key, so nothing but the context can be what
        // separates them. Without this the test could pass because the mesh broke.
        let agg = nodes[0].aggregate_commitment().expect("an all-honest mesh forms a key");
        for (k, node) in nodes.iter().enumerate() {
            assert_eq!(
                node.aggregate_commitment().map(|a| a.to_bytes()),
                Some(agg.to_bytes()),
                "node {k} must hold the SAME key material — the context is the only difference under test"
            );
        }

        assert!(
            matches!(
                published[odd].as_slice(),
                [Effect::Notify(Notification::DkgDiverged { agreed: 1, heard })] if *heard as usize == n - 1
            ),
            "the founder on a different roster must refuse its own file: it heard every peer and agreed with \
             none of them, which is exactly the operator error no key check can see"
        );
        assert_eq!(
            (0..n).filter(|&k| completed(&published[k])).count(),
            n - 1,
            "and the other six publish — a change that made the whole cell refuse would pass the assertion \
             above while destroying every ceremony that has a slow founder"
        );
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
        // Sharing deadline (no complaints — all honest), then complaint deadline ⇒ finalize, then the
        // confirm deadline, which is where the key is actually published. Each phase's effects go back on
        // the bus: the confirm round is a broadcast, so a phase whose effects are dropped is a cell that
        // never hears anyone agree.
        fire(&mut nodes, &mut bus, &mut clock, DKG_SHARE_DEADLINE);
        let finalized = fire(&mut nodes, &mut bus, &mut clock, DKG_COMPLAINT_DEADLINE);
        assert!(
            finalized.iter().all(|e| !completed(e)),
            "finalizing is not publishing: the key is withheld until a threshold of peers confirm it"
        );
        let published = fire(&mut nodes, &mut bus, &mut clock, DKG_CONFIRM_DEADLINE);
        let done = published.iter().filter(|e| completed(e)).count();
        assert_eq!(done, n, "all honest nodes complete the DKG");
        for (k, node) in nodes.iter().enumerate() {
            assert_eq!(
                node.agreement(),
                Some((n, n - 1)),
                "node {k} must count every peer as heard AND agreeing — a tally short of that would mean \
                 the key was published on a weaker witness than the test claims"
            );
        }

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
