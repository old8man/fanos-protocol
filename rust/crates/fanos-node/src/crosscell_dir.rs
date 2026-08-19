//! Live **L0 cross-cell directories** over the overlay store — the transport that carries the TAXIS L0
//! primitives (`fanos_taxis::{checkpoint, crosscell, hierarchy}`) between cells (task B).
//!
//! Two overlay-store directories, both the [`crate::capdir`] pattern:
//! - **Checkpoint directory** ([`publish_checkpoint`] / [`attest_children`]) — each cell publishes its latest
//!   [`ExecCertificate`] for the epoch at a cell-and-epoch slot; a parent cell reads its children's
//!   certificates and anchors their finality through a [`ChildRegistry`], giving *live* shared security.
//! - **Cross-cell receipt inbox** ([`publish_receipt`] / [`drain_inbox`]) — a source cell publishes a
//!   [`CrossCellReceipt`] to the destination cell's inbox slot; the destination reads and (its state machine)
//!   verifies + applies it, trusting no bridge.
//!
//! The trust model is the sibling directories': a certificate/receipt is self-verifying against the *source*
//! cell's committee keys ([`ExecCertificate::verify`] / [`CrossCellReceipt::verify`]), so a forged one at a
//! cell's slot is simply rejected — never a security break. The wire forms and verification they rely on are
//! complete and tested in `fanos-taxis`.
//!
//! ## Why nothing in a shipped binary calls any of this (#167)
//!
//! [`spawn_health_publisher`] has **no callers at all**, and [`crate::spawn_checkpoint_publisher`] has one,
//! in a test. That was read for a long time as "the wiring is pending", and it is not — the missing piece is
//! not a caller.
//!
//! **A FANOS deployment has exactly one cell, or none.** `Health::reflexive` is `config.plane_order == 2`,
//! and its doc says why: the DIAKRISIS unit is a seven-member cell, and only `PG(2,2)` forms one from the
//! plane itself; on a larger plane a node discovers peers but nothing tells it which seven are its cell
//! (#145). So at `q = 2` the cell *is* the network — a cross-cell publisher's counterpart is itself — and at
//! `q > 2` no cell forms to be a counterpart. There is never a second cell.
//!
//! That also relocates the blocker. It was recorded as an open *cell-identity* question, and identity is not
//! what is missing: `overlay::cell_id` already derives a stable id per `(genesis, plane order)`, which is
//! exactly right for the one cell that exists. What is missing is a cell-**formation** mechanism above
//! `q = 2`, which is #145. Wiring a publisher before then buys an address nobody can be at.
//!
//! The `cell: u32` these slots are keyed by is the visible edge of the same thing: every caller must supply a
//! number the platform has no way to derive, because the space it would index does not exist yet.
//!
//! The observability sibling of this is [`crate::telemetry_dir::Census`], and it is worth reading together:
//! there the same "one cell only" fact was not stated, and an operator-facing verdict claimed to compare
//! cells while reading one cell's members (#280).

use fanos_code::federation;
use fanos_code::golay::{self, Report};
use fanos_quic::Client;
use fanos_rendezvous::Epoch;
use fanos_taxis::checkpoint::ExecCertificate;
use fanos_taxis::crosscell::CrossCellReceipt;
use fanos_taxis::hierarchy::ChildRegistry;

use tokio::task::JoinHandle;

use fanos_field::Field;
use fanos_geometry::fano;
use fanos_primitives::BeaconSeed;

use crate::DIRECTORY_SLOT_EPOCHS;
use crate::bound::Entitlement;
use crate::resolve::{Read, STORE_TIMEOUT};

/// A cell's checkpoint slot: the store address its latest execution certificate for `epoch` lives at.
fn checkpoint_slot(cell: u32, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cell-checkpoint/".to_vec();
    key.extend_from_slice(&cell.to_be_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// The slot a cell publishes its **health report** at — domain-separated, keyed by cell and epoch, exactly like
/// [`checkpoint_slot`].
fn health_slot(cell: u32, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cell-health/".to_vec();
    key.extend_from_slice(&cell.to_be_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// A destination cell's cross-cell inbox slot for a specific `(source cell, nonce)` message.
fn receipt_slot(dest_cell: u32, source_cell: u32, nonce: u64) -> Vec<u8> {
    let mut key = b"FANOS-v1/xcell-inbox/".to_vec();
    key.extend_from_slice(&dest_cell.to_be_bytes());
    key.extend_from_slice(&source_cell.to_be_bytes());
    key.extend_from_slice(&nonce.to_be_bytes());
    key
}

/// Publish `cell`'s execution certificate for `epoch` so a parent can anchor its finality. `false` if rejected.
pub async fn publish_checkpoint(client: &Client, cell: u32, epoch: Epoch, cert: &ExecCertificate) -> bool {
    let landed =
        client.put_ephemeral(checkpoint_slot(cell, epoch), cert.to_bytes(), DIRECTORY_SLOT_EPOCHS).await;
    crate::note_publish(client, crate::Directory::Checkpoint, epoch, landed)
}

/// Resolve the execution certificate `cell` published for `epoch`, or `None` if none/timeout/malformed.
pub async fn resolve_checkpoint(client: &Client, cell: u32, epoch: Epoch) -> Option<ExecCertificate> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(checkpoint_slot(cell, epoch))).await.ok()??;
    ExecCertificate::from_bytes(&bytes)
}

/// A parent cell anchors its `children`'s finalities for `epoch`: resolve each child's published checkpoint
/// and [`attest_available`](ChildRegistry::attest_available) it into `registry` (each child's committee must
/// already be registered). Returns the `(cell, height, state_root)` newly anchored — a child that has not
/// published, or whose certificate fails to verify, does not advance, **or whose data is not available**, is
/// skipped. This is parent-attests-child made live.
///
/// **Each child is named with its availability mask, and that is deliberate (#173).** `ChildRegistry` had two
/// public doors — `attest` and `attest_available` — differing only in whether the parent refuses to vouch for
/// a state whose data is withheld, and this function went through the unguarded one. The safe door was
/// documented as the protection and had no caller anywhere; the guarded twin is now the only door, and the
/// evidence is an argument nobody can forget to pass.
///
/// A caller with no mask for a child has two honest options and no third: leave the child out, or pass a mask
/// that says what it actually knows. `0` means "nothing present" and refuses — the safe direction. Producing
/// a real mask needs the §L4.3 sampler, which no shipped binary issues yet (#173); this signature is where
/// that shows up rather than being skipped in silence.
pub async fn attest_children(
    client: &Client,
    registry: &mut ChildRegistry,
    children: &[(u32, u8)],
    epoch: Epoch,
) -> Vec<(u32, u64, [u8; 32])> {
    let mut anchored = Vec::new();
    for &(cell, present) in children {
        if let Some(cert) = resolve_checkpoint(client, cell, epoch).await
            && let Some((height, root)) = registry.attest_available(cell, cert, present)
        {
            anchored.push((cell, height, root));
        }
    }
    anchored
}

/// Publish this cell's **health report** for `epoch`: the bitmask of its degraded axes plus whether its own bus
/// attestation is damaged. `false` if the store rejected the write.
///
/// One byte, and it is the byte the federated grammar consumes: a cell's health was already represented as a 7-bit
/// degraded-axis mask throughout DIAKRISIS (`polar::rho_vector_from_degraded`), which is exactly `golay::Report::axes`, so
/// the wire format needed no invention. The bus occupies bit 7, which is where the code puts it too.
///
/// # ⚠️ The record is unauthenticated, and its consumer is a confident localizer
///
/// It is one bare byte at a `(cell, epoch)` slot, and [`resolve_health`] parses it with **no signature, no
/// envelope and no publisher binding** — while `diagnose_children` runs the Turyn federated covering over it
/// and localizes up to three faults to `(child, axis)`. **A covering designed to localize confidently will
/// mislocalize confidently on forged input.** Its sibling [`publish_checkpoint`] does not have this problem:
/// it carries an `ExecCertificate` and [`attest_children`] refuses a child whose certificate fails to verify.
///
/// The sibling directories solved exactly this and said why — `telemetry_dir.rs`: *"the slot key names a
/// coordinate; nothing used to make that name true"*, and `ingressdir.rs` on why it *"needed the envelope and
/// could not lean on the store"*. This slot is keyed `(cell, epoch)` rather than a coordinate, so the
/// coordinate-bound ownership rule those use does not cover it and an envelope has to be added.
///
/// This paragraph is a **tripwire**, not a note: `one_cell_premise.rs` watches for the phrase above and fails
/// the moment a cross-cell publisher gains a production caller while it is still here.
pub async fn publish_health<F: Field>(
    client: &Client,
    cell: u32,
    epoch: Epoch,
    report: Report,
    credential: Option<&(Vec<u8>, fanos_vrf::VrfPublic, fanos_vrf::VrfProof)>,
) -> bool {
    let payload = alloc_vec(report.block());
    // The same shape the five sibling directories use — `diagdir`, `ingressdir`, `exit`, `capdir`,
    // `loaddir` — and for the same reason: the publisher's entitlement travels *with* the record, so a
    // reader authenticates it without asking anyone. `None` writes the bare byte, which is what a node with
    // no self-certifying identity has and what every existing test drives.
    let record = match credential {
        Some((id, public, proof)) => Entitlement::encode(id, public, proof, &payload),
        None => payload.clone(),
    };
    let landed = client.put_ephemeral(health_slot(cell, epoch), record, DIRECTORY_SLOT_EPOCHS).await;
    let _ = core::marker::PhantomData::<F>;
    crate::note_publish(client, crate::Directory::Health, epoch, landed)
}

/// One byte as a `Vec` — spelled out so the codec is visibly a single byte rather than a struct that might grow one.
fn alloc_vec(byte: u8) -> Vec<u8> { vec![byte] }

/// Resolve the health report `cell` published for `epoch`, or `None` if none/timeout/malformed.
///
/// A wrong-width value is rejected rather than parsed leniently, and the safe direction is deliberate: an absent report
/// contributes a *clean* block to the federated word (a child that says nothing is not accused), while a mis-parsed one
/// would fabricate faults and could make the grammar accuse an innocent sibling.
pub async fn resolve_health<F: Field>(
    client: &Client,
    cell: u32,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<Report> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(health_slot(cell, epoch))).await.ok()??;
    open_health::<F>(&bytes, cell, epoch, beacon)
}

/// The inverse of the publish encoding — and, when `beacon` is `Some`, the **authentication** the federated
/// covering was running without.
///
/// **The slot is keyed by `(cell, epoch)`, so there is no single coordinate to bind to**, which is exactly
/// why the coordinate-bound rule the sibling directories use did not reach here. What replaces it is the
/// cell's own membership: `fano::cell_members_of` derives the seven points of `cell` from the plane, and the
/// record is accepted when its publisher is entitled to **one of them**. A cell's health may be spoken for
/// by a member of that cell and by nobody else.
///
/// **What that costs an attacker, said in the terms `bound.rs` already uses.** An `Entitlement` proves the
/// publisher's own probe walk reaches the point — `q + 1` of the plane's `q² + q + 1` — so speaking for a
/// chosen cell means holding a walk that touches one of its seven points, against **zero** for the bare byte
/// this replaces. It deliberately stops short of the exact settled index, which would need the publisher's
/// full `CoordinateClaim` witness chain; that is the stronger form and `bound.rs` names it as the natural
/// follow-up for the same reason.
///
/// ⚠️ **At `q = 2` it buys nothing, and the arithmetic says so rather than the doc hoping otherwise**: the
/// Fano plane is one cell, so *every* node is a member of it and the check is vacuous. It bites from
/// `PG(2,4)` up, where a cell is seven of twenty-one points — which is also the first plane at which a
/// second cell exists to publish for.
#[must_use]
fn open_health<F: Field>(
    bytes: &[u8],
    cell: u32,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<Report> {
    let payload = match beacon {
        Some(seed) => {
            let members = fano::cell_members_of::<F>(cell as usize)?;
            let (_, payload) = members
                .coords()
                .iter()
                .find_map(|&point| Entitlement::open::<F>(bytes, point, epoch, &seed))?;
            payload.to_vec()
        }
        None => bytes.to_vec(),
    };
    let [block] = <[u8; 1]>::try_from(payload.as_slice()).ok()?;
    Some(Report { axes: block & 0x7F, bus_fault: block >> golay::AXES & 1 == 1 })
}

/// A parent cell diagnoses its seven `children` for `epoch`: resolve each child's published health report and run the
/// **Turyn federated covering** over them (`docs/design-federation.md`).
///
/// This is the last mile of the federation work — the algebra was complete and had nothing feeding it. The parent gets a
/// verdict strictly stronger than per-child self-diagnosis: up to three faults anywhere across its children are localized to
/// `(child, axis)`, including all three inside one child, where that child's own Hamming(7,4) would have answered
/// confidently and wrongly. Beyond the grammar's reach the verdict is `Partial`, naming what remains unexplained rather
/// than inventing an attribution.
///
/// `children` is indexed by position in the parent's plane, so `children[p]` is the cell at point `p` — the covering's
/// federations are the parent's *lines*, and a line names points, not cells. A child that has not published is read as
/// clean for the reason `resolve_health` documents.
pub async fn diagnose_children<F: Field>(
    client: &Client,
    children: &[u32; federation::CHILDREN],
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> federation::Cell {
    let mut reports = [Report::default(); federation::CHILDREN];
    for (slot, &cell) in reports.iter_mut().zip(children.iter()) {
        // `beacon: None` reads the bare byte, which is what a build with no self-certifying identity writes
        // — and a caller that has a beacon and passes `None` is asking this covering to localize faults from
        // records anyone could have written. The parameter exists so that is a decision rather than a default.
        if let Some(r) = resolve_health::<F>(client, cell, epoch, beacon).await {
            *slot = r;
        }
    }
    // SELF-REPORTED, and the distinction is load-bearing: these masks are what each child says about *itself*, so a child
    // controlling its own eight coordinates could otherwise relocate blame onto a healthy sibling — the Golay decoder
    // corrects by moving to the nearest codeword, so injected coordinates do not add noise, they move the blame. See
    // `fanos_code::golay::Provenance`. A peer-measured source keeps the full `t = 3`; this one does not.
    federation::diagnose_cell(reports, golay::Provenance::SelfReported)
}

/// Keep this cell's health report **live**: spawn the task that publishes `health()`'s current view each epoch.
///
/// Mirrors [`crate::capdir::spawn_capability_publisher`] — a closure so this module stays agnostic to how a cell observes
/// its own axes, which is DIAKRISIS's business and not the directory's. Ends when the notification stream closes.
#[must_use]
pub fn spawn_health_publisher<F: Field>(
    client: Client,
    cell: u32,
    health: impl Fn() -> Report + Send + 'static,
    prover: Option<fanos_quic::CoordinateProver>,
) -> JoinHandle<()> {
    // Supervised: this actor's death is a capability the node loses, and the counters that would
    // have shown it are written by the actor itself (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let mut beacons = client.beacons();
        let mut epoch = Epoch::ZERO;
        // This network's epoch-0 seed rather than the constant, and re-proven on every write: a bound record
        // proves a coordinate against a *specific* beacon, so a proof captured once verifies only in the
        // epoch it was made — the same reasoning `capdir::spawn_capability_publisher` states.
        let mut seed = client.genesis();
        let credential = |epoch: Epoch, seed: &BeaconSeed| prover.as_ref().map(|prove| prove(epoch, seed));
        publish_health::<F>(&client, cell, epoch, health(), credential(epoch, &seed).as_ref()).await;
        // Latest-state, not the lossy stream: a cell whose health report is missing for an epoch reads to its
        // neighbours as a cell that has nothing to say, which is not the same as one that is healthy (#86).
        while let Some((e, s)) = crate::next_epoch(&mut beacons, epoch).await {
            epoch = e;
            seed = s;
            publish_health::<F>(&client, cell, epoch, health(), credential(epoch, &seed).as_ref()).await;
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::HealthPublisher, &supervised, task)
}

/// Publish a cross-cell `receipt` into the destination cell's inbox (addressed by source cell + message nonce).
/// `false` if the store rejected the write.
pub async fn publish_receipt(client: &Client, source_cell: u32, receipt: &CrossCellReceipt) -> bool {
    let slot = receipt_slot(receipt.msg.dest_cell, source_cell, receipt.msg.nonce);
    client.put(slot, receipt.to_bytes()).await
}

/// Read the cross-cell receipt for `(dest_cell, source_cell, nonce)` from the inbox, three-valued. The caller
/// verifies it against the source cell's committee ([`CrossCellReceipt::verify`]) before applying — no trust in
/// the relaying bridge or the store.
///
/// [`Read::Absent`] and [`Read::Unknown`] are kept apart because [`drain_inbox`] has to tell them apart: an
/// empty slot ends a walk, a timeout must not.
pub async fn read_receipt(
    client: &Client,
    dest_cell: u32,
    source_cell: u32,
    nonce: u64,
) -> Read<CrossCellReceipt> {
    // `read`, not `get`: `get` collapses "the slot is empty" and "the read did not conclude" into one
    // `None`, and telling those apart is the whole of the walk below.
    Read::of(
        tokio::time::timeout(STORE_TIMEOUT, client.read(receipt_slot(dest_cell, source_cell, nonce)))
            .await
            .ok(),
        CrossCellReceipt::from_bytes,
    )
}

/// What a drain does with one slot's read — the whole content of [`drain_inbox`], named.
///
/// Carries the receipt rather than reporting on it, so the walk applies the rule to the value it actually
/// read. A verdict computed from one read and then acted on by re-reading is two readings of two moments.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum Step<T> {
    /// A receipt is here: apply it and advance the cursor.
    Take(T),
    /// A **definite** gap — the source has published nothing at this nonce. Nonces are per-source monotonic
    /// (`fanos_taxis::crosscell`), so nothing beyond it can exist yet: the inbox is drained to here, and the
    /// cursor stops at this nonce because it is where the next message will land.
    Exhausted,
    /// The read did not conclude. The walk ends and **concludes nothing**: the cursor does not advance, and
    /// the result is not evidence of an empty inbox.
    ///
    /// This is the one distinction that makes a drain safe to run repeatedly. Folding it into `Exhausted`
    /// would let one timeout mark the inbox drained and skip every message behind the gap, permanently — the
    /// `Read` rule this crate states without exception: an incomplete scan may make a caller decline to act,
    /// never act on a substitute.
    Inconclusive,
}

/// The drain's rule, as a function of one read.
pub fn step<T>(read: Read<T>) -> Step<T> {
    match read {
        Read::Found(receipt) => Step::Take(receipt),
        Read::Absent => Step::Exhausted,
        Read::Unknown => Step::Inconclusive,
    }
}

/// What one drain pass recovered, and whether it saw the bottom of the inbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drained<T> {
    /// The receipts, in nonce order from the requested start. **Unverified** — the caller checks each
    /// against the source cell's committee before applying.
    pub receipts: Vec<T>,
    /// The nonce to resume from next time.
    pub next: u64,
    /// Whether the walk ended at a definite gap. `false` means a read did not conclude or the cap was hit,
    /// so the inbox may hold more at [`next`](Self::next) and this pass is **not** evidence of an empty one.
    pub complete: bool,
}

/// Walk `(dest_cell ← source_cell)` from nonce `from`, taking at most `max` receipts.
///
/// The inbox had a writer and no reader: [`publish_receipt`] addresses a slot by the nonce carried *inside*
/// the message, and [`read_receipt`] asks for a nonce, so a destination could only fetch a letter whose
/// serial number it already knew. Nothing enumerated the slots, and nothing could — which is why the module
/// header named a `drain_inbox` that was never written.
///
/// The walk is derived rather than chosen: nonces are **per-source monotonic** and the destination applies
/// each `(source, nonce)` at most once, so successive nonces from a remembered cursor *are* the enumeration.
/// The rule at each step is [`step`], and the whole reason it is three-valued is stated there.
///
/// `max` is the caller's, never a constant here: this is an unbounded read of a remote-controlled sequence,
/// and the ceiling belongs to whoever has to hold the result (#194).
pub async fn drain_inbox(
    client: &Client,
    dest_cell: u32,
    source_cell: u32,
    from: u64,
    max: usize,
) -> Drained<CrossCellReceipt> {
    drain_with(from, max, |nonce| read_receipt(client, dest_cell, source_cell, nonce)).await
}

/// [`drain_inbox`]'s walk with the store lifted out, so the loop can be tested without one.
///
/// The split is not for convenience. What can be wrong here is the *stopping rule* and the cursor, and a
/// test that needs a live overlay to reach them is a test that will not be written for a mechanism no
/// deployment can run yet (#167: there is never a second cell).
async fn drain_with<T, F, Fut>(from: u64, max: usize, read: F) -> Drained<T>
where
    F: Fn(u64) -> Fut,
    Fut: Future<Output = Read<T>>,
{
    let mut receipts = Vec::new();
    let mut nonce = from;
    loop {
        if receipts.len() >= max {
            // The cap is not a gap. Stopping here says nothing about what is at `nonce`.
            return Drained { receipts, next: nonce, complete: false };
        }
        match step(read(nonce).await) {
            Step::Take(receipt) => {
                receipts.push(receipt);
                nonce += 1;
            }
            Step::Exhausted => return Drained { receipts, next: nonce, complete: true },
            Step::Inconclusive => return Drained { receipts, next: nonce, complete: false },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// **A cell's health may be spoken for by a member of that cell and by nobody else** — the binding the
    /// federated covering was running without.
    ///
    /// `diagnose_children` localizes up to three faults to `(child, axis)` from these bytes, and a covering
    /// designed to localize confidently mislocalizes confidently on forged input. The slot is keyed by
    /// `(cell, epoch)` and not by a coordinate, which is why the rule its five sibling directories use — the
    /// publisher is entitled to the slot's own point — does not reach here. What replaces it is the cell's
    /// membership, derived from the plane by `fano::cell_members_of`.
    ///
    /// **On `PG(2,4)`, because `PG(2,2)` cannot express the negative case.** The Fano plane is one cell, so
    /// every node is a member of it and a refusal is unreachable — the doc says so and this fixture is what
    /// makes that statement checkable rather than a hope. `PG(2,4)` has three cells of seven points.
    ///
    /// Asserted in both directions: a member's record opens, an outsider's is refused, and the unauthenticated
    /// path still reads a bare byte — a change that refused everything would satisfy the middle assertion and
    /// break the directory.
    #[test]
    fn a_cells_health_is_spoken_for_by_a_member_of_that_cell_and_refused_from_anyone_else() {
        use fanos_field::F4;
        use fanos_primitives::BeaconSeed;
        use fanos_vrf::{VrfSecret, probe_index_of, prove_coordinate_ranked};

        let (epoch, beacon, cell) = (Epoch::new(4), BeaconSeed::GENESIS, 1u32);
        let members = fano::cell_members_of::<F4>(cell as usize).expect("PG(2,4) splits into three cells");
        let report = Report { axes: 0b010_1101, bus_fault: true };

        // Seal a record with `seed`'s identity, and say which of the cell's points its walk reaches.
        let sealed = |seed: u8| {
            let sk = VrfSecret::from_seed([seed; 32]);
            let id = format!("health-{seed}").into_bytes();
            let (_, proof, out) = prove_coordinate_ranked::<F4>(&sk, &id, epoch, &beacon);
            let reaches = members
                .coords()
                .iter()
                .any(|&c| fanos_geometry::Point::<F4>::new(c).and_then(|p| probe_index_of::<F4>(&out, &p)).is_some());
            (Entitlement::encode(&id, &sk.public(), &proof, &[report.block()]), reaches, out)
        };

        // A member: its walk reaches a point of the cell. A stranger: it reaches none. Both exist — the
        // walk is `q + 1 = 5` of twenty-one points and the cell is seven, so neither is a rare draw.
        let member = (0u8..=255).find_map(|s| { let (r, ok, _) = sealed(s); ok.then_some(r) });
        let stranger = (0u8..=255).find_map(|s| { let (r, ok, _) = sealed(s); (!ok).then_some(r) });
        let member = member.expect("some identity's walk reaches this cell — if none does, the fixture is wrong");
        let stranger = stranger.expect("some identity's walk misses all seven — the negative case must exist");

        assert!(
            open_health::<F4>(&member, cell, epoch, Some(beacon)).is_some(),
            "a member of the cell must be able to publish its health, or the directory refuses everyone and \
             the covering has no input at all"
        );
        assert!(
            open_health::<F4>(&stranger, cell, epoch, Some(beacon)).is_none(),
            "an identity entitled to no point of this cell spoke for it — which is the forged input the \
             Turyn covering localizes confidently and wrongly"
        );
        assert_eq!(
            open_health::<F4>(&member, cell, epoch, Some(beacon)).map(|r| (r.axes, r.bus_fault)),
            Some((report.axes, report.bus_fault)),
            "and the payload survives the envelope — an authenticated record that decodes to something else \
             is a different defect wearing this one's clothes"
        );

        // The unauthenticated path is unchanged: `None` reads a bare byte, which is what a build with no
        // self-certifying identity writes and what every existing caller drives.
        assert_eq!(
            open_health::<F4>(&[report.block()], cell, epoch, None).map(|r| r.axes),
            Some(report.axes),
            "the ungated path must still parse the bare byte"
        );
        // And an authenticated read of a bare byte is a refusal rather than a lenient parse: the record
        // carries no entitlement, so there is nobody to have written it.
        assert!(
            open_health::<F4>(&[report.block()], cell, epoch, Some(beacon)).is_none(),
            "a bare byte read under a beacon must be refused, or the envelope is optional in the direction \
             that matters"
        );
    }

    #[test]
    fn health_slots_are_deterministic_distinct_and_domain_separated() {
        let h = health_slot(3, Epoch::new(7));
        assert_eq!(h, health_slot(3, Epoch::new(7)));
        assert_ne!(h, health_slot(4, Epoch::new(7)), "distinct cell → distinct slot");
        assert_ne!(h, health_slot(3, Epoch::new(8)), "distinct epoch → distinct slot");
        assert!(h.starts_with(b"FANOS-v1/cell-health/"));
        assert!(!h.starts_with(b"FANOS-v1/cell-checkpoint/"), "a distinct domain from its sibling directory");
    }

    #[test]
    fn a_health_report_is_one_byte_and_round_trips_through_it() {
        // The wire format needed no invention: a cell's health was already a 7-bit degraded-axis mask throughout
        // DIAKRISIS, which is exactly golay::Report::axes, with the bus in bit 7 — where the code puts it too.
        for axes in 0u8..128 {
            for bus_fault in [false, true] {
                let r = Report { axes, bus_fault };
                let block = r.block();
                assert_eq!(block & 0x7F, axes);
                assert_eq!(block >> golay::AXES & 1 == 1, bus_fault);
                let decoded = Report { axes: block & 0x7F, bus_fault: block >> golay::AXES & 1 == 1 };
                assert_eq!(decoded, r, "one byte, and it round-trips");
            }
        }
        assert_eq!(alloc_vec(0x81).len(), 1, "a single byte on the wire, not a struct that might grow one");
    }

    #[test]
    fn an_absent_child_reads_as_clean_rather_than_accused() {
        // The safe direction, and it is the one that matters for a grammar: a child that has published nothing
        // contributes a clean block, so silence is never turned into an accusation against it — or, worse, into faults
        // that make the covering blame an innocent sibling.
        let quiet = Report::default();
        assert_eq!(quiet.block(), 0);
        assert_eq!(
            federation::diagnose_cell([Report::default(); federation::CHILDREN], golay::Provenance::Measured),
            federation::Cell::Healthy,
            "seven silent children are healthy, not seven accusations"
        );
    }

    #[test]
    fn a_parents_verdict_over_its_children_is_stronger_than_their_self_diagnosis() {
        // What the directory buys, expressed on the reports it carries. Three faulty axes inside one child: that child's
        // own Hamming(7,4) answers with a confident WRONG single-fault verdict, while the parent's federated covering
        // names all three, and the right child.
        let mut reports = [Report::default(); federation::CHILDREN];
        reports[5] = Report { axes: 0b0100_1001, bus_fault: false }; // axes 0, 3, 6
        let federation::Cell::Localized(f) = federation::diagnose_cell(reports, golay::Provenance::Measured) else {
            panic!("three faults must localize")
        };
        assert_eq!(f.axes[5], 0b0100_1001, "all three named, and attributed to child 5");
        assert_eq!(f.total(), 3);

        // The lone-cell contrast: Hamming returns *a* position for a triple fault — confidently, and wrongly.
        assert!(fanos_code::hamming::locate_single(0b0100_1001).is_some());
    }

    #[test]
    fn checkpoint_and_receipt_slots_are_deterministic_distinct_and_domain_separated() {
        // Checkpoint slots.
        let c = checkpoint_slot(1, Epoch::ZERO);
        assert_eq!(c, checkpoint_slot(1, Epoch::ZERO));
        assert_ne!(c, checkpoint_slot(2, Epoch::ZERO), "distinct cell → distinct slot");
        assert_ne!(c, checkpoint_slot(1, Epoch::new(1)), "distinct epoch → distinct slot");
        assert!(c.starts_with(b"FANOS-v1/cell-checkpoint/"));
        // Receipt slots.
        let r = receipt_slot(2, 1, 0);
        assert_eq!(r, receipt_slot(2, 1, 0));
        assert_ne!(r, receipt_slot(2, 1, 1), "distinct nonce → distinct inbox slot");
        assert_ne!(r, receipt_slot(3, 1, 0), "distinct destination → distinct inbox");
        assert_ne!(r, receipt_slot(2, 4, 0), "distinct source → distinct inbox");
        assert!(r.starts_with(b"FANOS-v1/xcell-inbox/"));
        // The two directories are domain-separated from each other and from the capability directory.
        assert!(!c.starts_with(b"FANOS-v1/xcell-inbox/") && !r.starts_with(b"FANOS-v1/cell-checkpoint/"));
        assert!(!c.starts_with(b"FANOS-v1/cap-desc/") && !r.starts_with(b"FANOS-v1/cap-desc/"));
    }

    // The walk is tested over `u64` rather than a receipt, because the walk does not depend on what it
    // carries — and a hand-built receipt fixture would be a second thing that can be wrong about a
    // mechanism nothing runs yet. Decoding is `CrossCellReceipt::from_bytes`, tested where it lives.

    /// One pass drains what is there, in order, and says it saw the bottom.
    #[tokio::test]
    async fn a_drain_walks_the_monotonic_nonces_and_stops_at_a_definite_gap() {
        let drained = drain_with(4, 100, |n| async move {
            if (4..7).contains(&n) { Read::Found(n) } else { Read::Absent }
        })
        .await;
        assert_eq!(drained.receipts, vec![4, 5, 6], "the walk takes successive nonces from the cursor");
        assert_eq!(drained.next, 7, "and resumes where the next message will land");
        assert!(drained.complete, "an empty slot is a definite bottom");
    }

    /// **The distinction the type exists for.** A timeout must not be read as an empty inbox.
    ///
    /// Falsify by mapping `Read::Unknown` to `Step::Exhausted`: this goes green on the receipts and red on
    /// `complete`, and the failure it stands for is permanent — a drain that concluded "empty" advances
    /// nothing, so every message behind the gap is skipped for good.
    #[tokio::test]
    async fn a_read_that_did_not_conclude_is_not_an_empty_inbox() {
        let drained = drain_with(0, 100, |n| async move {
            if n < 2 { Read::Found(n) } else { Read::Unknown }
        })
        .await;
        assert_eq!(drained.receipts.len(), 2, "what was read is still returned");
        assert_eq!(drained.next, 2, "the cursor stops at the slot that did not answer");
        assert!(!drained.complete, "and the pass must not claim the inbox is empty");
    }

    /// The cap is the caller's, and hitting it is not a gap either.
    #[tokio::test]
    async fn the_callers_cap_stops_the_walk_without_concluding_anything() {
        let drained = drain_with(0, 3, |n| async move { Read::Found(n) }).await;
        assert_eq!(drained.receipts.len(), 3);
        assert_eq!(drained.next, 3);
        assert!(!drained.complete, "an inbox longer than the cap is not an inbox that ended");
    }

    /// An empty inbox and an unreachable one are different answers to the same question.
    #[tokio::test]
    async fn an_empty_inbox_and_an_unreachable_one_are_told_apart() {
        let empty = drain_with::<u64, _, _>(0, 10, |_| async { Read::Absent }).await;
        let unreachable = drain_with::<u64, _, _>(0, 10, |_| async { Read::Unknown }).await;
        assert_eq!(empty.receipts, unreachable.receipts, "neither returns anything");
        assert_eq!(empty.next, unreachable.next, "neither moves the cursor");
        assert!(empty.complete && !unreachable.complete, "and only one of them is a reading");
    }
}
