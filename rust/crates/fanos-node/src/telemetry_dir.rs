//! The node's **differentially-private telemetry export** (audit C7).
//!
//! `fanos_telemetry::dp` has held the ε-DP mechanism and the sanctioned `CoherenceFrame::export` — privatize, then encode —
//! since the audit named it. Nothing called them. A guarantee with no export path is decorative: there was nothing to
//! privatize, so the mechanism's own doc warning ("a future export path has to *deliberately* bypass this rather than
//! merely forget it existed") had no path to warn.
//!
//! This is that path, and it is built the way every other FANOS directory is: the frame goes to a
//! coordinate-**and-epoch**-derived store slot, so an operator or a monitoring node resolves it over the overlay with no
//! new transport, no new protocol, and no central collector. Same shape as [`crate::mixdir`] and [`crate::capdir`].
//!
//! ## Two properties the shape gives for free
//!
//! **Opt-in.** Export runs only when the node is configured with an ε ([`NodeConfig::telemetry_epsilon`]). Absent, nothing
//! is published — a node does not start emitting its coherence readings because it was upgraded.
//!
//! **Privatized at the boundary, once.** The engine keeps the *exact* frame, because the reflexive loop needs the precise
//! syndrome to localize a fault, and it is sans-I/O so it has no entropy to add noise with. This module is the first place
//! that has both the frame and an RNG, which is exactly where the noise belongs. It reaches `export` and never `encode`.

use fanos_diaulos::Coord;
use fanos_field::Field;
use fanos_geometry::Plane;
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_quic::{Client, CoordinateProver};
use fanos_runtime::Notification;
use fanos_telemetry::dp::PrivacyBudget;
use fanos_telemetry::{AlarmLevel, CellId, CoherenceFrame};
use fanos_vrf::{VrfProof, VrfPublic};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::DIAGNOSIS_SLOT_EPOCHS;
use crate::bound::Entitlement;
use crate::resolve::{STORE_TIMEOUT, Read};

/// The store slot a node's privatized coherence frame is published at, keyed by its coordinate **and** the epoch.
///
/// Epoch-tagged for the same reason every other directory is: a reading is *about* an epoch, so a stale one has its own
/// address rather than overwriting the current one, and a resolver asks for the epoch it cares about instead of hoping.
fn coherence_slot(coord: Coord, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/telemetry/".to_vec();
    key.extend_from_slice(&fanos_geometry::encode_triple(coord));
    key.extend_from_slice(&epoch.get().to_be_bytes());
    key
}

/// Entropy for the DP noise draw: **seeded fresh from the OS per export**, then expanded.
///
/// `privatize` takes `rand_core::Rng`, whose contract is `TryRng<Error = Infallible>` — the generator may not fail. A
/// direct `getrandom` adapter cannot honour that, and the two ways to force it are both wrong: panicking turns an entropy
/// hiccup into a downed node, and falling back to a predictable draw voids the ε the export claims, which is the one
/// failure mode a DP mechanism must never have.
///
/// So the fallibility is moved to where it can be *handled*: [`new`](Self::new) reads a 32-byte OS seed and returns `None`
/// if that fails, and the caller simply does not export this round. After seeding, expansion is a domain-separated BLAKE3
/// XOF over `(seed ‖ counter)` — infallible, and cryptographically indistinguishable from more OS reads.
///
/// Seeded **per export**, never reused: `privatize`'s contract is that a draw is fresh per release, and a reused draw voids
/// the guarantee rather than merely weakening it.
struct FreshEntropy {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 64],
    used: usize,
}

impl FreshEntropy {
    /// A generator seeded from OS entropy, or `None` if that read failed.
    fn new() -> Option<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).ok()?;
        let mut me = Self { seed, counter: 0, block: [0u8; 64], used: 64 };
        me.refill();
        Some(me)
    }

    /// Expand the next block from `(seed ‖ counter)`.
    fn refill(&mut self) {
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&self.seed);
        input[32..].copy_from_slice(&self.counter.to_be_bytes());
        fanos_primitives::hash::hash_xof("FANOS-v1/telemetry-dp-noise", &input, &mut self.block);
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }

    /// The next `n` bytes, refilling as needed.
    ///
    /// Written with `get`/`get_mut` rather than slice syntax: the arithmetic is provably in range, but an entropy source
    /// that can panic is a node that can be downed by a telemetry export, and "provably" is not a thing a reader of this
    /// can check at a glance.
    fn take(&mut self, n: usize, out: &mut [u8]) {
        let mut written = 0;
        while written < n {
            if self.used >= self.block.len() {
                self.refill();
            }
            let take = (self.block.len() - self.used).min(n - written);
            let Some(src) = self.block.get(self.used..self.used + take) else { return };
            let Some(dst) = out.get_mut(written..written + take) else { return };
            dst.copy_from_slice(src);
            self.used += take;
            written += take;
        }
    }
}

impl rand_core::TryRng for FreshEntropy {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.take(4, &mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.take(8, &mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let n = dst.len();
        self.take(n, dst);
        Ok(())
    }
}

/// Publish `frame` for `epoch` at this node's live coordinate slot, **privatized**.
///
/// Goes through `CoherenceFrame::export` — privatize, then encode — never `encode` alone. That distinction is the whole of
/// audit C7: the exact frame is already in hand and shipping it is one line shorter, which is exactly how a DP guarantee
/// gets lost. `false` if the store rejected the write.
pub async fn publish_coherence(
    client: &Client,
    epoch: Epoch,
    frame: &CoherenceFrame,
    budget: PrivacyBudget,
    credential: Option<&(Vec<u8>, VrfPublic, VrfProof)>,
) -> bool {
    // No entropy, no export. Publishing an under-noised frame would be worse than publishing nothing, because a consumer
    // cannot tell the difference and the ε would be a claim about something that did not happen.
    let Some(mut rng) = FreshEntropy::new() else {
        return false;
    };
    let bytes = frame.export(budget, &mut rng);
    let landed = client
        .put_ephemeral(
            coherence_slot(client.address(), epoch),
            coherence_record(&bytes, credential),
            DIAGNOSIS_SLOT_EPOCHS,
        )
        .await;
    crate::note_publish(client, crate::Directory::Coherence, epoch, landed)
}

/// The bytes a coherence frame is stored as: the privatized frame, or that inside the coordinate-bound
/// [`Entitlement`] envelope when this deployment can prove coordinates (#262).
///
/// **The slot key names a coordinate; nothing used to make that name true.** `put_ephemeral` hands the store
/// `storage_digest(&key)`, so the store never sees the key and cannot check that the writer is the node the
/// slot names — it is content-addressed by construction, and no store-side rule will ever close this. So any
/// node could publish a coherence frame at any other node's slot, and `take_census` would attribute it.
///
/// **What that costs is a lie about a neighbour, not a broken control loop** — worth stating plainly, because
/// the sibling this pattern came from (`ingressdir`, bound in the same task) sits on the rotation path and
/// this one does not. The only consumer is `take_census`, reached from the CLI: a forged frame makes
/// `fanos census` report a Φ, a stability radius and an alarm level for a node that never said them. An
/// operator acts on those; nothing automatic does.
#[must_use]
fn coherence_record(exported: &[u8], credential: Option<&(Vec<u8>, VrfPublic, VrfProof)>) -> Vec<u8> {
    match credential {
        Some((id, public, proof)) => Entitlement::encode(id, public, proof, exported),
        None => exported.to_vec(),
    }
}

/// The inverse of [`coherence_record`]: the published frame, or `None` if malformed or — when `beacon` is
/// `Some` — not bound to `coord` for `epoch`.
#[must_use]
fn open_coherence_record<F: Field>(
    bytes: &[u8],
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<CoherenceFrame> {
    match beacon {
        Some(seed) => {
            let (_, payload) = Entitlement::open::<F>(bytes, coord, epoch, &seed)?;
            CoherenceFrame::decode(payload)
        }
        None => CoherenceFrame::decode(bytes),
    }
}

/// Resolve the coherence frame the node at `coord` published for `epoch`.
///
/// Three-valued: a read that **timed out** is not the same as a node that published nothing, and collapsing them is how a
/// monitor comes to believe a quiet cell is a healthy one. Same discipline as `capdir`'s `read_capability`.
///
/// A record that fails its coordinate binding lands in the same arm as a malformed one — `Absent` — and that
/// is the honest place for it: the node at `coord` did not publish this, so as far as this coordinate is
/// concerned nothing was published. It is not `Unknown`, which means "the store did not answer".
pub async fn read_coherence<F: Field>(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Read<CoherenceFrame> {
    Read::of(
        tokio::time::timeout(STORE_TIMEOUT, client.read(coherence_slot(coord, epoch))).await.ok(),
        |bytes| open_coherence_record::<F>(bytes, coord, epoch, beacon),
    )
}

/// Every point of the base cell of plane `F` — the coordinate list a monitor resolves telemetry over.
#[must_use]
pub fn cell_telemetry_coords<F: Field>() -> Vec<Coord> {
    (0..Plane::<F>::N as usize).map(|i| fanos_geometry::Point::<F>::at(i).coords()).collect()
}

/// Keep this node's privatized coherence reading **live** in the directory: publish each observation the engine emits.
///
/// Driven off `Notification::Observed`, which carries the encoded frame the reflexive loop just computed — so the export
/// cadence is the diagnosis cadence, with no separate timer to drift from it and no polling. Ends when the notification
/// stream closes; must run inside a tokio runtime.
#[must_use]
pub fn spawn_coherence_publisher(
    client: Client,
    budget: PrivacyBudget,
    prover: Option<CoordinateProver>,
) -> JoinHandle<()> {
    // Supervised: this actor's death is a capability the node loses, and the counters that would
    // have shown it are written by the actor itself (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let mut events = client.subscribe();
        let mut beacons = client.beacons();
        let mut epoch = Epoch::ZERO;
        loop {
            match events.recv().await {
                // The engine's own mandatory self-observation. It is the *exact* frame — this is the boundary that adds
                // noise, and the only place with both the frame and entropy.
                Ok(Notification::Observed(bytes)) => {
                    // Read the epoch at publish time from latest-state rather than tracking it off the
                    // stream: a reading published at a stale epoch lands at the address of a period that has
                    // passed, and the stream can drop the round that would have advanced the counter (#86).
                    let mut seed = client.genesis();
                    if let Some((e, s)) = *beacons.borrow_and_update() {
                        epoch = e;
                        seed = BeaconSeed::new(s);
                    }
                    if let Some(frame) = CoherenceFrame::decode(&bytes) {
                        // Proven per write, never once at spawn: the credential names an epoch, so one
                        // captured at startup would verify only in the epoch it was made — the rule every
                        // bound publisher here follows. Before the first beacon the seed is this NETWORK's
                        // genesis, not the shared constant, or the record would prove a coordinate this node
                        // does not occupy and no reader could verify it.
                        let credential = prover.as_ref().map(|prove| prove(epoch, &seed));
                        publish_coherence(&client, epoch, &frame, budget, credential.as_ref()).await;
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::CoherencePublisher, &supervised, task)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    /// A frame for the binding tests — the values do not matter, only that it round-trips.
    fn sample_frame() -> CoherenceFrame {
        CoherenceFrame {
            cell_id: CellId([9; 16]),
            epoch: 3,
            syndrome: 0,
            verdict: 0,
            phi: 1.5,
            purity: 0.37,
            reflection: 0.4,
            mean_r: 0.6,
            gap: 0.2,
            forecast: -3,
            heal_seq: 7,
        }
    }

    /// **A published coherence frame verifies only at a coordinate its publisher can prove** (#262).
    ///
    /// Driven through `coherence_record`/`open_coherence_record` — the pair the publisher and the census
    /// actually call — for the reason #80 recorded: its first version of this binding tested `Entitlement`
    /// in isolation and stayed green when the envelope was deleted from the publisher.
    #[test]
    fn a_coherence_frame_verifies_only_where_its_publisher_can_prove_a_coordinate() {
        use fanos_field::F7;
        use fanos_geometry::{Plane, Point};
        use fanos_vrf::VrfSecret;

        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let sk = VrfSecret::from_seed([21u8; 32]);
        let id = b"telemetry-member-21".to_vec();
        let (_, proof) = fanos_vrf::prove_coordinate::<F7>(&sk, &id, epoch, &beacon);
        let frame = sample_frame();
        let record = coherence_record(&frame.encode(), Some(&(id.clone(), sk.public(), proof)));
        let output = fanos_vrf::coordinate_output(&sk.public(), &id, epoch, &beacon, &proof)
            .expect("the publisher's own credential yields its walk");

        let mut refused = 0;
        for i in 0..Plane::<F7>::N as usize {
            let p = Point::<F7>::at(i);
            let got = open_coherence_record::<F7>(&record, p.coords(), epoch, Some(beacon));
            if fanos_vrf::probe_index_of::<F7>(&output, &p).is_some() {
                assert_eq!(got, Some(frame), "a point on the publisher's own walk verifies");
            } else {
                assert!(got.is_none(), "a coordinate the publisher cannot prove is refused");
                refused += 1;
            }
        }
        assert_eq!(refused, 49, "the forgery is refused at 49 of the plane's 57 points");
    }

    /// The binding is **epoch-scoped**, so a healthy-looking frame cannot be replayed forward to keep a node
    /// looking well after its real readings have turned.
    #[test]
    fn a_coherence_frame_does_not_verify_in_another_epoch() {
        use fanos_field::F7;
        use fanos_geometry::{Plane, Point};
        use fanos_vrf::VrfSecret;

        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let sk = VrfSecret::from_seed([22u8; 32]);
        let id = b"telemetry-member-22".to_vec();
        let (_, proof) = fanos_vrf::prove_coordinate::<F7>(&sk, &id, epoch, &beacon);
        let record = coherence_record(&sample_frame().encode(), Some(&(id.clone(), sk.public(), proof)));
        let output = fanos_vrf::coordinate_output(&sk.public(), &id, epoch, &beacon, &proof)
            .expect("the publisher's own credential yields its walk");
        let mine = (0..Plane::<F7>::N as usize)
            .map(Point::<F7>::at)
            .find(|p| fanos_vrf::probe_index_of::<F7>(&output, p).is_some())
            .expect("a walk reaches at least one point");

        assert!(
            open_coherence_record::<F7>(&record, mine.coords(), epoch, Some(beacon)).is_some(),
            "it verifies in the epoch it was made for"
        );
        assert!(
            open_coherence_record::<F7>(&record, mine.coords(), Epoch::new(4), Some(beacon)).is_none(),
            "and not in the next one — the credential names its epoch"
        );
    }

    /// A deployment that cannot prove coordinates still round-trips; the census asks with `None` there, so it
    /// stays as readable as it was rather than reporting an empty cell.
    #[test]
    fn an_unbound_deployment_still_round_trips_its_coherence_frame() {
        use fanos_field::F7;
        let frame = sample_frame();
        let record = coherence_record(&frame.encode(), None);
        assert_eq!(
            open_coherence_record::<F7>(&record, [1, 0, 1], Epoch::new(2), None),
            Some(frame),
            "no credential to check, so the bare frame is the whole record"
        );
    }


    /// The retention and the law that reads it must be the SAME number (#44).
    ///
    /// This is a correctness bound, not a tuning preference. `Reputation::from_published` folds the last
    /// `REP_WINDOW` closed epochs; if the store keeps fewer, a node reading a longer history than exists sees
    /// a record set that depends on *when* it read, and two nodes disagree permanently — the carried-score
    /// defect one layer down. If it keeps more, the surplus is retained for a law that cannot reach it.
    ///
    /// Asserted here rather than trusted to the `= REP_WINDOW` in the constant's definition, because the two
    /// live in different crates and the defect this closes was exactly that: the diagnosis directory borrowed
    /// `DIRECTORY_SLOT_EPOCHS = 1`, derived from the ONION RATCHET's grace window, while every reader asked
    /// for eight epochs.
    #[test]
    fn the_diagnosis_retention_is_exactly_the_reputation_window() {
        assert_eq!(
            u64::from(DIAGNOSIS_SLOT_EPOCHS),
            fanos_core::roles::REP_WINDOW,
            "the store must keep exactly the epochs the reputation law reads"
        );
        assert_ne!(
            DIAGNOSIS_SLOT_EPOCHS,
            crate::DIRECTORY_SLOT_EPOCHS,
            "and it must not be the routing retention again — different question, different derivation"
        );
    }

    #[test]
    fn a_slot_is_bound_to_both_the_coordinate_and_the_epoch() {
        // Neither binding is decoration. Without the coordinate a node could overwrite another's reading; without the
        // epoch a stale reading overwrites the current one and a monitor cannot tell which epoch it is looking at.
        let a = coherence_slot([1, 0, 0], Epoch::new(4));
        assert_ne!(a, coherence_slot([0, 1, 0], Epoch::new(4)), "a different coordinate is a different slot");
        assert_ne!(a, coherence_slot([1, 0, 0], Epoch::new(5)), "a different epoch is a different slot");
        assert_eq!(a, coherence_slot([1, 0, 0], Epoch::new(4)), "and the derivation is deterministic");
        assert!(a.starts_with(b"FANOS-v1/telemetry/"), "domain-separated from every other use of the store");
    }

    #[test]
    fn the_monitor_roster_is_the_whole_cell() {
        // Every point is a potential publisher, so a monitor reads the plane rather than a configured list — the same
        // derivation `capdir`/`mixdir` use, for the same reason: a hand-written roster is a roster that goes stale.
        let coords = cell_telemetry_coords::<F2>();
        assert_eq!(coords.len(), Plane::<F2>::N as usize, "all seven points of the Fano cell");
        assert_eq!(coords.iter().collect::<std::collections::HashSet<_>>().len(), coords.len(), "and distinct");
    }

    #[test]
    fn exporting_adds_noise_rather_than_shipping_the_exact_frame() {
        // The property audit C7 is about. `export` privatizes; `encode` does not. If an export ever equals the encoding of
        // the frame it came from across a range of readings, the noise is not being applied and the ε is a claim about
        // nothing.
        //
        // Not asserted on a single draw: Laplace noise can round to the same bucket, so this checks that *some* reading in
        // a batch differs. A mechanism that never differs is the failure being guarded against.
        let budget = PrivacyBudget::new(0.5);
        let mut differed = 0;
        for i in 0..32u32 {
            let frame = CoherenceFrame {
                cell_id: CellId([0; 16]),
                epoch: u64::from(i),
                syndrome: 0,
                verdict: 0,
                phi: 1.5,
                purity: 0.37,
                reflection: 0.4,
                mean_r: 0.6,
                gap: 0.2,
                forecast: 0,
                heal_seq: i,
            };
            let Some(mut rng) = FreshEntropy::new() else { unreachable!("OS entropy is available in a test") };
            if frame.export(budget, &mut rng) != frame.encode() {
                differed += 1;
            }
        }
        assert!(differed > 0, "no export differed from its exact frame — the DP mechanism is not being applied");
    }
}

/// A **census** of a set of cells' published health — the answer to an operator's first question.
///
/// Plan III.2. Every incident starts with *is this my cell, or the network?*, and nothing could answer it: each
/// cell diagnoses itself, a fault it cannot heal escalates to its parent (`ParentCell::observe`), and no view
/// existed that spanned cells at all. The input has been on the wire the whole time — nodes publish
/// ε-differentially-private coherence frames — and [`read_coherence`] had no caller.
///
/// ## Why a census and not a composed `Φ`
///
/// A federation-level coherence *matrix* would need the cross-cell entries, and no node measures one: a cell's
/// `Γ_net` is over its own points. Synthesising a network-wide `Φ` from cells' `Φ`s would be inventing a
/// quantity, and it would read exactly like a measured one.
///
/// The recursion that *does* compose is already built and is a different mechanism: a child cell is a **point**
/// of its parent, so an unhealable child becomes a degraded point and the parent's own reflex runs unchanged.
/// That is the control path. This is the observability path, and the honest thing for it to report is a
/// distribution: how many cells are healthy, how many are alarmed, how many could not be read.
///
/// ## Silence is not health
///
/// Unreadable coordinates are counted separately and never folded into "healthy". A monitor that treats a
/// quiet slot as a well one reports its best news exactly when a partition is at its worst — which is the
/// failure mode [`read_coherence`]'s three-valued result exists to prevent, and it would be undone here by a
/// single `unwrap_or_default`.
///
/// ## A coordinate is not a cell
///
/// The population asked is a list of *coordinates*, and what comes back describes a *cell* — those are
/// different things, and conflating them is how this type first shipped. `fanos census` polls
/// [`cell_telemetry_coords`], "every point of the base cell"; every one of those nodes publishes a frame
/// about the cell it belongs to; and `overlay::cell_id` is a pure function of `(genesis, plane order)`, so
/// "every node in the cell derives the same id". Seven readings, one cell. Counting them as seven let a
/// four-of-seven majority **inside one cell** print as `NETWORK`, which is the precise opposite of what an
/// operator does next — escalate rather than heal locally.
///
/// The discriminator was free and already on the wire: [`CoherenceFrame::cell_id`]. Readings are now folded
/// per cell, and a network verdict needs at least **two** answering cells, because with one cell "my cell"
/// and "the network" are the same population and the question this census exists for is unavailable.
///
/// A cell's level is the worst any of its members published, and disagreement among them is counted rather
/// than smoothed away. That errs the same way "silence is not health" does — away from false comfort — and
/// it has a stated cost: frames are not publisher-bound (see `coherence_record`), so one forged frame can
/// carry a cell to its worst level. `disagreed` is what tells an operator not to trust a single level, and
/// the honest summary is that a census is a lead to follow, never an input to anything automatic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Census {
    /// One entry per **distinct cell** that answered — never per coordinate.
    cells: Vec<CellReading>,
    /// Coordinates that answered, however few cells they turned out to describe.
    answering_coordinates: usize,
    /// Coordinates that published nothing for this epoch. A definite negative: the slot is empty. Counted as
    /// coordinates, not cells, because a coordinate that says nothing names no cell to attribute it to.
    silent: usize,
    /// Coordinates whose read did not conclude. **Not** a negative and not evidence of anything — a timeout.
    unreachable: usize,
}

/// One cell's reading, folded from however many of its members answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CellReading {
    id: CellId,
    /// The worst level any member published for this cell.
    worst: AlarmLevel,
    /// Whether members disagreed about their own cell's level.
    disagreed: bool,
}

/// How bad a level is, as a number that can be compared.
///
/// Written out rather than `derive(Ord)` on [`AlarmLevel`]: a derived order is a fact about *declaration
/// order* in another crate, and reordering the variants there would silently invert the fold here.
const fn severity(level: AlarmLevel) -> u8 {
    match level {
        AlarmLevel::Healthy => 0,
        AlarmLevel::Integration => 1,
        AlarmLevel::Structure => 2,
    }
}

/// What a census can conclude.
///
/// Four-valued, and the fourth is the point: [`SingleCell`](Verdict::SingleCell) is the state the shipped
/// deployment is actually in, and it is neither "the network is sick" nor "the network is well" — it is *the
/// question cannot be answered from here*. It still carries the cell's own alarm, because that half **is**
/// actionable and suppressing it would trade one silence for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// No cell answered. Not a healthy network and not a sick one.
    NoReading,
    /// Exactly one cell answered, at this level. "My cell" and "the network" are the same population.
    SingleCell(AlarmLevel),
    /// A majority of the answering cells are alarmed — the network is the story.
    NetworkWide,
    /// Most answering cells are healthy — whatever is wrong belongs to a cell, not the network.
    NotNetworkWide,
}

impl core::fmt::Display for Census {
    /// One line per count, plus the verdict — the shape `fanos status` and a person with `socat` both read.
    ///
    /// The units are in the key names. `asked`/`silent`/`unreachable` count **coordinates**; `healthy` and
    /// the two alarms count **cells**. Leaving that to the reader is what the defect above was made of.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "coordinates_asked: {}", self.asked())?;
        writeln!(f, "coordinates_answering: {}", self.answering_coordinates)?;
        writeln!(f, "cells_answering: {}", self.answering_cells())?;
        writeln!(f, "healthy_cells: {}", self.healthy())?;
        writeln!(f, "integration_alarm_cells: {}", self.integration())?;
        writeln!(f, "structure_alarm_cells: {}", self.structure())?;
        writeln!(f, "cells_whose_members_disagreed: {}", self.disagreed())?;
        writeln!(f, "coordinates_silent: {}", self.silent)?;
        writeln!(f, "coordinates_unreachable: {}", self.unreachable)?;
        // Stated rather than left to arithmetic: the verdict is over the cells that *answered*, and saying so
        // is what stops a reader treating the silent ones as a vote either way.
        writeln!(
            f,
            "verdict: {}",
            match self.verdict() {
                Verdict::NoReading => "no reading — no cell answered".to_owned(),
                Verdict::SingleCell(level) => format!(
                    "MY CELL ({}) — one cell answered, so this census cannot tell a cell fault from a \
                     network one; that needs a second cell to compare against",
                    level.as_str()
                ),
                Verdict::NetworkWide => "NETWORK — most answering cells are alarmed".to_owned(),
                Verdict::NotNetworkWide =>
                    "not network-wide — most answering cells are healthy".to_owned(),
            }
        )
    }
}

impl Census {
    /// How many distinct **cells** answered at all.
    #[must_use]
    pub fn answering_cells(&self) -> usize {
        self.cells.len()
    }

    /// Cells reporting `Φ ≥ 1` and `P ≥ 2/N` — integrated and above the viability floor.
    #[must_use]
    pub fn healthy(&self) -> usize {
        self.count(AlarmLevel::Healthy)
    }

    /// Cells reporting the **integration** alarm: `Φ < 1` but still viable. The earliest warning (V17).
    #[must_use]
    pub fn integration(&self) -> usize {
        self.count(AlarmLevel::Integration)
    }

    /// Cells reporting the **structure** alarm: `Φ < 1` and `P < 2/N` — below viability, where the
    /// V-preservation gate has closed and self-recovery is no longer possible without help.
    #[must_use]
    pub fn structure(&self) -> usize {
        self.count(AlarmLevel::Structure)
    }

    /// How many answering cells had members that did not agree on their own cell's level.
    #[must_use]
    pub fn disagreed(&self) -> usize {
        self.cells.iter().filter(|c| c.disagreed).count()
    }

    fn count(&self, level: AlarmLevel) -> usize {
        self.cells.iter().filter(|c| c.worst == level).count()
    }

    /// How many **coordinates** were asked.
    #[must_use]
    pub fn asked(&self) -> usize {
        self.answering_coordinates + self.silent + self.unreachable
    }

    /// What this census concludes — see [`Verdict`].
    ///
    /// The fraction is deliberately over the cells that **answered**, not over the coordinates asked.
    /// Counting silence as health would hide a partition; counting it as sickness would let one unreachable
    /// coordinate speak for the network. Neither is a reading, so the rest is carried alongside for the
    /// operator to weigh.
    pub fn verdict(&self) -> Verdict {
        match self.cells.as_slice() {
            [] => Verdict::NoReading,
            [only] => Verdict::SingleCell(only.worst),
            many => {
                let alarmed = many.iter().filter(|c| c.worst != AlarmLevel::Healthy).count();
                if alarmed * 2 > many.len() { Verdict::NetworkWide } else { Verdict::NotNetworkWide }
            }
        }
    }

    /// Fold one coordinate's read into the census, attributing it to the cell its frame names.
    fn observe(&mut self, read: &Read<CoherenceFrame>) {
        match read {
            Read::Found(frame) => {
                self.answering_coordinates += 1;
                let level = frame.alarm();
                if let Some(seen) = self.cells.iter_mut().find(|c| c.id == frame.cell_id) {
                    seen.disagreed |= seen.worst != level;
                    if severity(level) > severity(seen.worst) {
                        seen.worst = level;
                    }
                } else {
                    self.cells.push(CellReading { id: frame.cell_id, worst: level, disagreed: false });
                }
            }
            Read::Absent => self.silent += 1,
            Read::Unknown => self.unreachable += 1,
        }
    }
}

/// Read every coordinate's published coherence for `epoch` and compose a [`Census`].
///
/// Reads are issued one at a time rather than concurrently: this is an operator's occasional question, not a
/// data path, and a monitor that fans out over a whole federation at once is itself a load spike on a network
/// it may be asking about *because* it is under load.
pub async fn take_census<F: Field>(
    client: &Client,
    coords: &[Coord],
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Census {
    let mut census = Census::default();
    for &coord in coords {
        census.observe(&read_coherence::<F>(client, coord, epoch, beacon).await);
    }
    census
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod census_tests {
    use super::*;
    use fanos_telemetry::{CellId, CoherenceFrame};

    /// A frame carrying the given alarm level.
    ///
    /// The alarm is a **published byte**, not something the reader derives from `Φ` and `P` — the publisher
    /// computes it and the reader trusts it. A first version of this fixture set the measures and left the
    /// verdict at zero, so every cell read as healthy and the network test could not fail. Worth knowing about
    /// the frame: a consumer that recomputes the alarm from the measures would be second-guessing the cell
    /// that made it.
    fn frame_of(cell: CellId, alarm: u8) -> CoherenceFrame {
        CoherenceFrame {
            cell_id: cell,
            epoch: 1,
            syndrome: 0,
            verdict: alarm << 2, // ALARM_SHIFT
            phi: 1.0,
            purity: 0.5,
            reflection: 0.5,
            mean_r: 0.5,
            gap: 1.0,
            forecast: -1,
            heal_seq: 0,
        }
    }

    #[test]
    fn a_silent_coordinate_is_never_counted_as_a_healthy_cell() {
        // The property this type exists to protect. A monitor that folds silence into health reports its best
        // news exactly when a partition is at its worst — the failure mode `read_coherence`'s three-valued
        // result exists to prevent, and one `unwrap_or_default` here would undo it.
        let mut c = Census::default();
        c.observe(&Read::Found(frame_of(CellId([0u8; 16]), 0)));
        c.observe(&Read::Absent);
        c.observe(&Read::Unknown);
        assert_eq!(c.healthy(), 1, "only the cell that said so is healthy");
        assert_eq!(c.silent, 1, "an empty slot is a definite negative, kept apart");
        assert_eq!(c.unreachable, 1, "a timeout is not evidence of anything, kept apart again");
        assert_eq!(c.answering_cells(), 1, "one cell reported");
        assert_eq!(c.asked(), 3, "three coordinates were asked");
    }

    #[test]
    fn the_network_verdict_is_taken_over_the_cells_that_answered() {
        // Counting silence as health would hide a partition; counting it as sickness would let one unreachable
        // coordinate speak for the network. Neither is a reading, so the fraction is over those that reported.
        //
        // The cells here are DISTINCT, and that is the whole point: the first version of this test read one
        // cell four times and asserted the majority was "the network", which is the defect the type now
        // refuses. A fixture that cannot tell the two apart cannot pin the property either.
        let mut c = Census::default();
        for i in 0..3u8 {
            c.observe(&Read::Found(frame_of(CellId([i; 16]), 2))); // the structure alarm — below viability
        }
        c.observe(&Read::Found(frame_of(CellId([9u8; 16]), 0)));
        assert_eq!(
            c.verdict(),
            Verdict::NetworkWide,
            "three of four answering cells alarmed is the network, not a cell"
        );

        let mut quiet = Census::default();
        quiet.observe(&Read::Found(frame_of(CellId([0u8; 16]), 0)));
        for _ in 0..20 {
            quiet.observe(&Read::Unknown);
        }
        assert_eq!(
            quiet.verdict(),
            Verdict::SingleCell(AlarmLevel::Healthy),
            "twenty unreachable coordinates must not vote — and one healthy answer is not a network reading"
        );
    }

    #[test]
    fn an_empty_census_makes_no_claim() {
        // Zero answers is not a healthy network and not a sick one.
        assert_eq!(Census::default().verdict(), Verdict::NoReading);
        assert_eq!(Census::default().asked(), 0);
    }

    /// **The census must not answer "my cell or the network?" from one cell's members.**
    ///
    /// This is the exact population the shipped CLI polls: `fanos.rs` passes
    /// [`cell_telemetry_coords`], whose own doc says "every point of the base cell" and whose test is named
    /// `the_monitor_roster_is_the_whole_cell`. Every one of those nodes publishes a frame describing *its
    /// cell*, and `overlay::cell_id` is a pure function of `(genesis, plane order)` — "every node in the cell
    /// derives the same id". So the seven slots hold seven opinions about **one** cell, and folding them as
    /// seven cells makes a within-cell majority print as a network verdict.
    ///
    /// The operator's action inverts on that line: "NETWORK" says stop healing locally and escalate.
    #[test]
    fn a_cells_own_members_cannot_carry_a_network_verdict() {
        let mine = CellId([7u8; 16]);
        let mut c = Census::default();
        for _ in 0..4 {
            c.observe(&Read::Found(frame_of(mine, 2))); // four members in structure alarm
        }
        for _ in 0..3 {
            c.observe(&Read::Found(frame_of(mine, 0)));
        }
        assert_eq!(c.answering_cells(), 1, "seven members of one cell are one answering cell");
        assert_eq!(c.asked(), 7, "seven coordinates were asked — that number is about coordinates");
        assert_eq!(
            c.verdict(),
            Verdict::SingleCell(AlarmLevel::Structure),
            "one cell cannot distinguish itself from the network: the census must say so, and carry the \
             cell's own alarm, which is the part that IS actionable"
        );

        // And the rendering, because the operator reads the *string* — a correct verdict that prints the old
        // sentence would leave the defect exactly where it was.
        let printed = c.to_string();
        println!("{printed}");
        assert!(printed.contains("MY CELL (structure)"), "the verdict line must name the cell: {printed}");
        assert!(!printed.contains("NETWORK —"), "and must not carry the network sentence: {printed}");
        assert!(
            printed.contains("cells_answering: 1") && printed.contains("coordinates_asked: 7"),
            "the two populations must be printed with their units, never one number for both: {printed}"
        );
    }

    /// One vote per cell, worst reading wins — and members disagreeing about their own cell is its own fact.
    #[test]
    fn members_of_one_cell_are_one_vote_at_the_worst_level_they_reported() {
        let mine = CellId([1u8; 16]);
        let mut c = Census::default();
        c.observe(&Read::Found(frame_of(mine, 0)));
        c.observe(&Read::Found(frame_of(mine, 2)));
        c.observe(&Read::Found(frame_of(mine, 1)));
        assert_eq!(c.answering_cells(), 1);
        assert_eq!(c.structure(), 1, "the worst reading a member published is the cell's level");
        assert_eq!(c.healthy(), 0, "and it does not also count as healthy");
        assert_eq!(c.disagreed(), 1, "members disagreeing about their own cell is worth an operator's eye");
    }

    /// And the network verdict is still *reachable* — a guard that can only refuse is not a discriminator.
    #[test]
    fn two_cells_can_still_pronounce_on_the_network() {
        let mut c = Census::default();
        c.observe(&Read::Found(frame_of(CellId([1u8; 16]), 2)));
        c.observe(&Read::Found(frame_of(CellId([2u8; 16]), 2)));
        c.observe(&Read::Found(frame_of(CellId([3u8; 16]), 0)));
        assert_eq!(c.answering_cells(), 3);
        assert_eq!(c.verdict(), Verdict::NetworkWide, "two of three answering cells alarmed is the network");

        let mut healthy = Census::default();
        healthy.observe(&Read::Found(frame_of(CellId([1u8; 16]), 2)));
        healthy.observe(&Read::Found(frame_of(CellId([2u8; 16]), 0)));
        healthy.observe(&Read::Found(frame_of(CellId([3u8; 16]), 0)));
        assert_eq!(healthy.verdict(), Verdict::NotNetworkWide, "one sick cell of three is that cell's story");
    }
}

