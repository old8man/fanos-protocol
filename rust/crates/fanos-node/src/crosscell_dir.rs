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
//! **The reason has been three different things, and `fanos-node/tests/one_cell_premise.rs` is the tripwire
//! that made each one falsifiable.** The history matters because each answer looked final:
//!
//! 1. *"A FANOS deployment has exactly one cell, or none."* `Health::reflexive` was `plane_order == 2`, and
//!    only `PG(2,2)` formed a seven-member cell from the plane itself. **Closed by #145**: `fano::cell_of`
//!    is `index mod (N/7)`, a pure function every node computes identically, so any plane whose point count
//!    divides by seven forms cells and `compose_engine` seats a node in its own.
//! 2. *"A parent would decide on unsigned evidence."* [`publish_health`] wrote one bare byte into the Turyn
//!    federated covering. **Closed**: the record carries an [`Entitlement`] and [`open_health`] admits it
//!    only from a member of the cell it speaks for.
//! 3. *"Ratification can only say no."* [`attest_children`] took its availability mask as an argument and
//!    nothing could produce one, so the only safe value was `0` — which refuses every child. **Closed**:
//!    [`sample_child_availability`] establishes it from the child cell's own shards.
//!
//! **What is left is the committee.** [`ChildRegistry::attest_available`] resolves a child's registered
//! `ChildCommittee` before it verifies anything, and an unregistered child is refused outright. Nothing in
//! the workspace constructs one: there is no directory that publishes a cell's validator keys and none that
//! resolves them. So a parent can address its children, authenticate their health, and sample their data —
//! and still cannot check a single signature on their certificates.
//!
//! The `cell: u32` these slots are keyed by is no longer the same problem it was: `fano::cell_of` derives it.
//! What a caller still has no way to derive is *whose* keys sit at those seven points.
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
use fanos_taxis::consensus::ConsensusMsg;
use fanos_taxis::da::Sampler;
use fanos_taxis::hierarchy::ChildRegistry;
use fanos_taxis::wire::{ShardMsg, TaxisApp, parse_app_body, shard_to_frame};

use tokio::task::JoinHandle;

use fanos_field::Field;
use fanos_geometry::{Triple, fano};
use fanos_primitives::BeaconSeed;
use fanos_runtime::{Command, Notification};
use tokio::sync::broadcast;

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

/// **The `present` mask a parent must establish before it anchors a child (#173).** Bit `i` is set iff shard
/// `i` of the child's finalized `block` came back from the child cell's seat `i` *and* the gathered shards
/// rebuilt the payload. `0` — refuse — if the child cell is not on this plane, if no seat could supply the
/// skeleton, or if what came back does not reconstruct.
///
/// [`ChildRegistry::attest_available`] refuses to vouch for a child whose payload is withheld, and it takes
/// that evidence as an argument rather than assuming it. Nothing produced one, so every caller had to pass
/// `0`, which refuses every child: the guard could only ever say no, and the safe door was the unusable one.
/// This is the producer, and it is a real data-availability sample of a **foreign** cell.
///
/// # It needs no protocol of its own, and that is the finding
///
/// Every piece already ships, in three different crates that had never been put together:
///
/// * the child cell's seven seats are [`fano::cell_members_of`] — member `i` is validator `i`, the same
///   index the shard is coded at and the same one [`ExecVote`](fanos_taxis::checkpoint::ExecVote) attributes by;
///
///   ⚠️ **and the consensus driver disagrees above `q = 2`.** `TaxisParams::me` is documented as *"its Fano
///   point index — it must be seated at `Point::at(me)`"`, and `spawn_taxis` builds its address map as
///   `(0..Plane::<F>::N).map(Point::at)` — the whole plane, in index order. `cell_members_of(c)` seats member
///   `i` at `Point::at(c + i·cells)`. The two coincide exactly when the plane holds one cell (`cells = 1`,
///   i.e. `N = 7`, i.e. `q = 2`) and diverge everywhere else: on `PG(2,4)` cell 0 is points `0,3,6,9,12,15,18`
///   and the driver's first seven are `0..6`. This function follows the cell map, because that is the one
///   `fano::cell_of`, `open_health` and `federation::diagnose_cell` all use; the driver is what has to move,
///   and it needs a cell id `TaxisParams` does not carry;
/// * `ShardMsg::NeedSkeleton` and `ShardMsg::Request` are answered by `taxis_driver::on_shard` **for any
///   requester** — the DA transport is point-addressed ([`Command::Emit`]) and was never cell-confined, so a
///   parent is already able to ask; the `Propose` arm above it is the filtered one, not this;
/// * [`Sampler`] is the sans-I/O decision procedure, and its `reconstruct` re-encodes the recovered payload
///   and matches it against the header's `da_commit`.
///
/// # Why the mask is reconstruction and not who answered
///
/// A claim of possession is free, so "seat `i` replied" is worth nothing on its own — which is exactly why
/// §L4.3 sampling moves the shard rather than asking a yes/no question. The bits are set as shards arrive but
/// the mask is **discarded unless `reconstruct` succeeds**, and that check is cryptographic: a withholding
/// child (too few shards) and a tampering one (wrong bytes) both fail it. The sampler is seeded with a `me`
/// outside `0..7` because this node holds no shard of a foreign cell's block, so every index is genuinely
/// missing and none is assumed present.
///
/// A shard for index `i` is accepted **only from seat `i`**. Without that, one seat answers for all seven —
/// `on_shard` falls back to `ConsensusEngine::shard_of`, which regenerates any index from a held block — and
/// the mask would report seven custodians where there is one.
///
/// # ⚠️ What this establishes, and what it does not
///
/// That the child's finalized **payload** is retrievable from its own cell, now. It is not a durability
/// claim, and it is not a claim about any earlier height: `da::Sampler`'s `held` map is bounded at the child
/// too, so a parent that samples long after the fact is asking about data the honest cell may legitimately
/// have dropped. That is why this runs at attest time, per checkpoint, rather than as a sweep.
///
/// It also costs the parent's **own** driver a little noise, and the price is named rather than hidden: the
/// replies arrive as `Notification::App` on the shared broadcast, so the parent's `on_shard` sees a foreign
/// cell's shards too. It credits them to `note_shard_taken` and may retain one at its own index. Both are
/// bounded (`HELD_CAP`, and a foreign block's height is pruned by `prune_below`), and both disappear once the
/// driver's seat map is cell-scoped — the same fix the seat-map divergence above needs.
pub async fn sample_child_availability<F: Field>(client: &Client, cell: u32, block: [u8; 32]) -> u8 {
    let Some(members) = fano::cell_members_of::<F>(cell as usize) else {
        return 0; // the child cell is not a cell of this plane — there is nobody to ask
    };
    let seats = members.coords();
    // Subscribed **before** the first emit, for the reason every read on this client is: an answer that
    // arrives between the send and the subscribe is an answer nobody hears, and the sample would then wait
    // out its whole deadline to conclude the opposite of what the cell told it.
    let mut events = client.subscribe();

    // The skeleton first: it carries the `da_commit` every shard is checked against, so nothing can be
    // verified before it lands. Asked of every seat because any holder answers and the first one wins.
    for &to in &seats {
        client.command(Command::Emit { to, frame: shard_to_frame(&ShardMsg::NeedSkeleton { block }) });
    }
    let Some(skeleton) = await_skeleton(&mut events, block).await else {
        return 0; // no seat could name the block — nothing to sample against
    };

    let mut sampler = Sampler::new(NOT_A_CUSTODIAN);
    if !sampler.begin(skeleton) {
        return 0; // unreachable on a fresh sampler; a refusal is the safe reading of an impossible state
    }
    for (i, &to) in seats.iter().enumerate() {
        let Ok(index) = u8::try_from(i) else { continue };
        client.command(Command::Emit { to, frame: shard_to_frame(&ShardMsg::Request { block, index }) });
    }
    gather_shards(&mut events, &mut sampler, &seats, block).await
}

/// The sampler index a parent uses for a **foreign** cell's block: outside `0..7`, so `Sampler::missing`
/// reports every index and `accept` never mistakes an answer for this node's own dispersed shard.
const NOT_A_CUSTODIAN: u8 = u8::MAX;

/// How long one exchange of a cross-cell availability sample waits before giving up.
///
/// [`STORE_TIMEOUT`] — deliberately the same quantity rather than a new one, because this is the same thing:
/// a read of a value another node holds. The sample is two *dependent* exchanges (skeleton, then shards), so
/// one that concludes nothing costs at most twice it, which is the number a caller has to budget for.
const SAMPLE_EXCHANGE: std::time::Duration = STORE_TIMEOUT;

/// Wait for any seat to answer `NeedSkeleton` with the skeleton of `block`.
///
/// The hash is re-derived and compared, so a seat that answers with a *different* block — the cheap forgery,
/// since the reply is an ordinary `Propose` — is ignored rather than becoming the thing every shard is then
/// checked against.
async fn await_skeleton(
    events: &mut broadcast::Receiver<Notification>,
    block: [u8; 32],
) -> Option<fanos_taxis::Block> {
    let listen = async {
        loop {
            match events.recv().await {
                Ok(Notification::App { body, .. }) => {
                    if let Some(TaxisApp::Consensus(ConsensusMsg::Propose(skeleton))) = parse_app_body(&body)
                        && skeleton.hash() == block
                    {
                        return Some(skeleton);
                    }
                }
                // Someone else's notification, or a lag that *may* have dropped ours: neither is a
                // conclusion, so both keep waiting and the deadline below decides.
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    };
    tokio::time::timeout(SAMPLE_EXCHANGE, listen).await.ok().flatten()
}

/// Collect shard deliveries until the payload reconstructs, returning the mask of the seats that supplied it
/// — or `0` if the deadline passes first.
async fn gather_shards(
    events: &mut broadcast::Receiver<Notification>,
    sampler: &mut Sampler,
    seats: &[Triple],
    block: [u8; 32],
) -> u8 {
    let listen = async {
        let mut present = 0u8;
        loop {
            match events.recv().await {
                Ok(Notification::App { body, from }) => {
                    let Some(TaxisApp::Shard(ShardMsg::Deliver { block: b, index, data })) =
                        parse_app_body(&body)
                    else {
                        continue;
                    };
                    // Its own block, from its own seat. Both halves matter: the first keeps another block's
                    // dispersal out of this mask, the second keeps one seat from answering for seven.
                    if b != block || seats.get(usize::from(index)) != Some(&from) {
                        continue;
                    }
                    present |= 1u8 << index;
                    if sampler.accept(block, index, data).is_some() {
                        return present; // reconstructed and `da_commit`-checked — the mask is evidence now
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return 0,
            }
        }
    };
    tokio::time::timeout(SAMPLE_EXCHANGE, listen).await.unwrap_or(0)
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
/// **The mask is established here rather than demanded from the caller (#173).** It used to be an argument,
/// and the honest reading of that signature was that no caller could fill it: the only safe value available
/// was `0`, which refuses every child, so a parent could ratify nothing. [`sample_child_availability`] is the
/// producer, and it runs per child at attest time — which is also the only time the answer is meaningful,
/// since the child's own `held` shards are bounded and an old height is legitimately gone.
///
/// A child whose payload does not reconstruct is skipped exactly like one whose certificate fails to verify.
/// Both are the same refusal — the parent does not vouch — and neither is an error to report upward: a child
/// that is late this epoch is anchored the next one.
pub async fn attest_children<F: Field>(
    client: &Client,
    registry: &mut ChildRegistry,
    children: &[u32],
    epoch: Epoch,
) -> Vec<(u32, u64, [u8; 32])> {
    let mut anchored = Vec::new();
    for &cell in children {
        let Some(cert) = resolve_checkpoint(client, cell, epoch).await else { continue };
        let present = sample_child_availability::<F>(client, cell, cert.head).await;
        if let Some((height, root)) = registry.attest_available(cell, cert, present) {
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

/// What a parent learned about its seven children in one epoch: the covering's verdict, **and which children
/// were not in it**.
///
/// The two travel together because separating them is what made a dead federation read as a healthy one.
/// `federation::Cell::Healthy` means *"no child reports a fault"*, and a child that publishes nothing
/// contributes a clean block — so seven silent children decode to `Healthy`, which is the strongest possible
/// statement about a parent that heard from nobody.
///
/// The clean block is not the defect and must stay: injecting a fabricated "fully degraded" block for a
/// silent child would move blame rather than add noise (the Golay decoder corrects toward the nearest
/// codeword — `resolve_health` states this and `golay::Provenance` proves it with a measured 24.9 %
/// false-accusation rate). **Silence is an erasure, not an observation**, and this code has no erasure
/// decoder — so the honest place for it is beside the verdict, not inside the codeword.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChildDiagnosis {
    /// The covering's verdict over the children that **did** report.
    ///
    /// Reading this field alone is the misreading this type exists to prevent: it is scoped to the reporting
    /// children, so `Healthy` here means "nobody who spoke reported a fault", never "the federation is well".
    pub verdict: federation::Cell,
    /// Bit `p` set ⇒ the child at point `p` published no readable health report for this epoch.
    ///
    /// "No readable" folds three causes deliberately — nothing published, a lookup that timed out, and a
    /// record that failed authentication — because a parent cannot tell them apart and must not act as if it
    /// could. The refusal is counted separately by `note_authentication` in the sibling directories, which is
    /// where an operator distinguishes a quiet child from an attacked one.
    pub silent: u8,
}

impl ChildDiagnosis {
    /// Fold what the resolver returned per child into a verdict and a silence mask.
    ///
    /// **The whole decision, and it takes no client** — which is the point of it being a function. Written
    /// inline in [`diagnose_children`] it was reachable only through a live store, so the one property that
    /// matters (silence is not health) could be asserted about a type but never about the step that
    /// produces it: breaking `None => silent |= …` left every test green.
    ///
    /// `None` is *one* outcome deliberately. Nothing published, the lookup timed out, and the record failed
    /// authentication are three different facts, and a parent cannot tell them apart — `resolve_health`
    /// returns the same `None` for all three, and inventing a distinction here would be a claim about
    /// evidence this node does not have. `note_authentication` is where a refusal is counted apart, in the
    /// directories that can see it.
    fn from_resolved(resolved: &[Option<Report>; federation::CHILDREN]) -> Self {
        let mut reports = [Report::default(); federation::CHILDREN];
        let mut silent = 0u8;
        for (p, (slot, heard)) in reports.iter_mut().zip(resolved.iter()).enumerate() {
            match heard {
                Some(r) => *slot = *r,
                // `p < CHILDREN = 7`, so the shift is in range for the same reason the array is.
                None => silent |= 1u8 << p,
            }
        }
        Self { verdict: federation::diagnose_cell(reports, golay::Provenance::SelfReported), silent }
    }

    /// Whether the parent may act on this as a clean bill of health: every child reported, and none reports
    /// a fault. Anything else needs the fields read together.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.silent == 0 && matches!(self.verdict, federation::Cell::Healthy)
    }
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
/// federations are the parent's *lines*, and a line names points, not cells. A child that has not published still
/// contributes a clean block, and [`ChildDiagnosis::silent`] is what keeps that from reading as health.
///
/// ⚠️ **`children[p]` is a cell *identifier*, and the two things that derive one do not agree.** The live
/// derivation is `fano::cell_of` — `index mod (N/7)`, which partitions a plane into `N/7` sibling cells, so
/// on `PG(2,4)` the only valid ids are `0..3`. The reading this signature assumes is the hierarchical one —
/// point `p` of the parent hosts child cell `p`, which always gives exactly seven and is the only shape
/// `federation::CHILDREN` can be fed. They coincide nowhere: a partition never yields seven cells, since
/// `N/7 = 7` has no projective solution. The hierarchical id is #167 (*"no identity above the base cell to
/// fold in"*) and does not exist yet, so today [`open_health`]'s membership check can only authenticate a
/// partition id — and a child whose id it cannot resolve is refused, which lands in `silent` rather than
/// being taken on trust.
pub async fn diagnose_children<F: Field>(
    client: &Client,
    children: &[u32; federation::CHILDREN],
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> ChildDiagnosis {
    let mut resolved: [Option<Report>; federation::CHILDREN] = [None; federation::CHILDREN];
    for (slot, &cell) in resolved.iter_mut().zip(children.iter()) {
        // `beacon: None` reads the bare byte, which is what a build with no self-certifying identity writes
        // — and a caller that has a beacon and passes `None` is asking this covering to localize faults from
        // records anyone could have written. The parameter exists so that is a decision rather than a default.
        *slot = resolve_health::<F>(client, cell, epoch, beacon).await;
    }
    // SELF-REPORTED, and the distinction is load-bearing: these masks are what each child says about *itself*, so a child
    // controlling its own eight coordinates could otherwise relocate blame onto a healthy sibling — the Golay decoder
    // corrects by moving to the nearest codeword, so injected coordinates do not add noise, they move the blame. See
    // `fanos_code::golay::Provenance`. A peer-measured source keeps the full `t = 3`; this one does not.
    ChildDiagnosis::from_resolved(&resolved)
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::needless_range_loop)]
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

    /// A `Notification::App` body carrying `msg` — the bytes the receive path actually sees.
    ///
    /// Built by encoding the production frame and unwrapping it with the production decoder, rather than by
    /// hand-assembling `kind ‖ payload`: a hand-built body is a second spelling of the wire format, and the
    /// two would drift with nothing to notice.
    #[cfg(test)]
    fn app_body(frame: &[u8]) -> Vec<u8> {
        fanos_wire::decode_frame(frame).expect("a canonical App frame").0.body.to_vec()
    }

    /// **A parent's availability mask must be what reconstructed, not who answered** — and both ways it could
    /// stop being that are cheap for a child cell to arrange.
    ///
    /// The mask decides whether a parent anchors a child's finality (`ChildRegistry::attest_available`), so a
    /// mask that can be inflated is a parent vouching for a state whose data is withheld — the exact failure
    /// the guard exists to prevent, arrived at through its evidence instead of around it.
    ///
    /// Four properties, and the third and fourth are the ones an implementation gets wrong:
    ///
    /// 1. the honest case concludes — enough shards from their own seats rebuild the payload and the mask
    ///    names them;
    /// 2. a **shard that arrives from the wrong seat** sets no bit, so one node cannot answer for seven (it
    ///    can: `on_shard` falls back to `shard_of`, which regenerates any index from a held block);
    /// 3. **bits set without a reconstruction are discarded** — a child that sends two shards and withholds
    ///    the rest has told us nothing, and a mask of two bits is not "two shards are available", it is a
    ///    sample that did not conclude;
    /// 4. a skeleton for a **different block** is not adopted, because everything downstream is checked
    ///    against its `da_commit` and adopting a foreign one moves the whole test to the attacker's block.
    ///
    /// Time is paused: each negative case is a deadline, and asserting four of them at `STORE_TIMEOUT` apiece
    /// would cost twenty seconds of wall clock to learn nothing extra.
    #[tokio::test(start_paused = true)]
    async fn a_parents_availability_mask_is_what_reconstructed_and_not_who_answered() {
        use fanos_code::lrc::is_recoverable_fano;
        use fanos_field::F4;
        use fanos_taxis::wire::to_frame;
        use fanos_taxis::{Block, GENESIS_PARENT};

        let block = Block::assemble(GENESIS_PARENT, 1, Epoch::new(3), 4, vec![]);
        let (hash, skeleton, shards) = (block.hash(), block.skeleton(), block.da_shards());
        let seats = fano::cell_members_of::<F4>(1).expect("PG(2,4) has three cells").coords();
        let deliver = |i: usize| {
            let msg = ShardMsg::Deliver { block: hash, index: i as u8, data: shards[i].clone() };
            app_body(&shard_to_frame(&msg))
        };

        // ── 1. the honest case: shards from their own seats, and the sample concludes.
        let (tx, mut rx) = broadcast::channel(32);
        let mut sampler = Sampler::new(NOT_A_CUSTODIAN);
        assert!(sampler.begin(skeleton.clone()), "a fresh sampler begins");
        for i in 0..7 {
            let _ = tx.send(Notification::App { from: seats[i], body: deliver(i) });
        }
        let present = gather_shards(&mut rx, &mut sampler, &seats, hash).await;
        assert!(
            present.count_ones() >= 3 && is_recoverable_fano((!present) & 0x7F),
            "the sample concluded, so its mask must be one `attest_available` accepts — got {present:#09b}"
        );

        // ── 2. every shard from the wrong seat: nothing is credited, so nothing reconstructs.
        let (tx, mut rx) = broadcast::channel(32);
        let mut sampler = Sampler::new(NOT_A_CUSTODIAN);
        assert!(sampler.begin(skeleton.clone()));
        for i in 0..7 {
            let _ = tx.send(Notification::App { from: seats[(i + 1) % 7], body: deliver(i) });
        }
        assert_eq!(
            gather_shards(&mut rx, &mut sampler, &seats, hash).await,
            0,
            "a shard credited to the seat that did not send it lets one node answer for the whole cell"
        );

        // ── 3. two honest shards and silence: bits were set, and they are not a conclusion.
        let (tx, mut rx) = broadcast::channel(32);
        let mut sampler = Sampler::new(NOT_A_CUSTODIAN);
        assert!(sampler.begin(skeleton.clone()));
        for i in 0..2 {
            let _ = tx.send(Notification::App { from: seats[i], body: deliver(i) });
        }
        assert_eq!(
            gather_shards(&mut rx, &mut sampler, &seats, hash).await,
            0,
            "a mask survived a sample that never rebuilt the payload — presence was taken on the sender's word"
        );

        // ── 4. a skeleton for another block is not what the shards get checked against.
        let other = Block::assemble([9u8; 32], 2, Epoch::new(3), 1, vec![]);
        assert_ne!(other.hash(), hash, "the fixture needs two distinct blocks");
        let (tx, mut rx) = broadcast::channel(32);
        let _ = tx.send(Notification::App {
            from: seats[0],
            body: app_body(&to_frame(&ConsensusMsg::Propose(other.skeleton()))),
        });
        assert!(
            await_skeleton(&mut rx, hash).await.is_none(),
            "a seat answered `NeedSkeleton` with a different block and it was adopted"
        );

        // …and the same channel, given the right skeleton, does return it — so case 4 is a discrimination
        // and not a helper that refuses everything.
        let (tx, mut rx) = broadcast::channel(32);
        let _ = tx.send(Notification::App {
            from: seats[0],
            body: app_body(&to_frame(&ConsensusMsg::Propose(skeleton.clone()))),
        });
        assert_eq!(
            await_skeleton(&mut rx, hash).await.map(|b| b.hash()),
            Some(hash),
            "the skeleton of the block being sampled must be adopted"
        );
    }

    /// **A parent that heard from nobody must not report its federation healthy.**
    ///
    /// `federation::Cell::Healthy` means *"no child reports a fault"*, and a child that published nothing
    /// contributes a clean block — so seven silences decode to the strongest statement the covering can
    /// make, produced from no evidence at all — an alarm that cannot fire, sitting under the Turyn covering the
    /// whole cross-cell directory exists to feed.
    ///
    /// The clean block itself is **not** the defect and is deliberately kept: substituting a fabricated
    /// "fully degraded" block for a silent child would move blame rather than add noise, because the Golay
    /// decoder corrects toward the nearest codeword — `golay::Provenance`'s own note measures that at a
    /// 24.9 % false-accusation rate. Silence is an erasure, this code has no erasure decoder, so the honest
    /// place for it is beside the verdict.
    ///
    /// Both directions, because a `is_clean` that always refused would satisfy the first assertion alone.
    #[test]
    fn a_parent_that_heard_from_no_child_does_not_read_as_healthy() {
        let heard_nobody = ChildDiagnosis::from_resolved(&[None; federation::CHILDREN]);
        assert_eq!(
            heard_nobody.verdict,
            federation::Cell::Healthy,
            "the covering itself is unchanged — it still decodes seven clean blocks to Healthy, and that is \
             why the verdict alone cannot be the answer"
        );
        assert!(
            !heard_nobody.is_clean(),
            "seven children said nothing and the parent called its federation clean"
        );

        let all_well = [Some(Report::default()); federation::CHILDREN];
        assert!(
            ChildDiagnosis::from_resolved(&all_well).is_clean(),
            "every child reported and none reports a fault — refusing this would make the guard useless \
             rather than strict"
        );
        // One silent child is already enough: the covering carries `t = 3` faults, and a missing report is
        // not one of them — it is a child the verdict says nothing about.
        let mut one_quiet = all_well;
        one_quiet[2] = None;
        let one_quiet = ChildDiagnosis::from_resolved(&one_quiet);
        assert_eq!(one_quiet.silent, 0b000_0100, "the silent bit must name the child that said nothing");
        assert!(!one_quiet.is_clean(), "a single silent child must still deny a clean bill of health");
        // And a reported fault is not laundered by everyone else being present.
        let mut faulty = all_well;
        faulty[2] = Some(Report { axes: 0b000_0001, bus_fault: false });
        let faulty = ChildDiagnosis::from_resolved(&faulty);
        assert_eq!(faulty.silent, 0, "nobody was silent here — the mask must not borrow the fault's bit");
        assert!(!faulty.is_clean(), "a localized fault with nobody silent must not read clean either");
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
