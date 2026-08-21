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
//! 4. *"Nothing constructs a `ChildCommittee`."* [`ChildRegistry::attest_available`] resolves a child's
//!    registered committee before it verifies anything and refuses an unregistered child outright, and there
//!    was no directory publishing a cell's validator keys and none resolving them — so a parent could
//!    address its children, authenticate their health and sample their data, and still not check one
//!    signature. **Closed**: [`publish_seat_key`] / [`resolve_committee`], one slot per seat, each opened
//!    against *that seat's* coordinate rather than against the cell as a set.
//!
//! 5. *"A cell-wide record cannot be written from a local input."* The health slot was keyed `(cell, epoch)`
//!    — one record for a whole cell — while every input a node has is its own reading. Seven members would
//!    have raced for it and whoever wrote last would have spoken for the cell, with the `Entitlement`
//!    proving *a member* wrote it and unable to prove the cell agreed. **Closed by removing the requirement
//!    rather than by meeting it**: the record is per *seat* now, bound to that seat's coordinate, and
//!    [`resolve_health`] folds the answering members per axis by **majority** — no agreement to reach, a
//!    minority cannot accuse, and the reader gets strictly more than one block's worth of information.
//!
//! **[`spawn_health_publisher`] is wired** (`role_loop::spawn_self_organization`), reading this node's own
//! `degraded` mask off the liveness watch the role loop already runs. Five reasons, all closed; what stands
//! below is work rather than a rule.
//!
//! ## The next blocker is a level up, and it IS a missing rule
//!
//! Everything above is about a cell publishing and a parent reading. What nothing in this workspace derives
//! is **which cells are a parent's children** — there is no `children_of`, no `parent_of`, and no rule that
//! produces the seven `cell: u32` values [`diagnose_children`] takes as an argument.
//!
//! The arithmetic says they cannot be cells of one plane. `federation::CHILDREN` is `fano::N` = **7**, while
//! a plane holds `cells_in = N / 7` of them:
//!
//! | `q` | points | cells |
//! |---|---|---|
//! | 2 | 7 | **1** |
//! | 4 | 21 | **3** |
//! | 8 | 73 | none — 7 ∤ 73 |
//! | 16 | 273 | 39 |
//!
//! At `q = 2` a parent has no siblings at all; at `q = 4` there are two other cells and the covering's seven
//! slots cannot be filled; at `q = 16` there are 39 and **nothing says which seven**. So the federation's
//! children are not the plane's cells — they are sub-cells of the *hierarchy*, whose addresses are
//! `HierAddr` paths (`docs/design-hierarchy-recursion.md`, and `fanos_geometry::derive_address`).
//!
//! And a `HierAddr` path is exactly what a flat `cell: u32` cannot name. So the key space these directories
//! use is one level below the relation they exist to serve, and closing that is a **design** step — pick how
//! a path is keyed, and how a parent enumerates its children — rather than the wiring the five entries above
//! turned out to be.
//!
//! Two smaller things remain beside it, and neither is a missing rule:
//!
//! * Nothing in a shipped binary yet *runs* [`publish_seat_key`] / [`resolve_committee`]. A validator has to
//!   publish its consensus verifying key each epoch beside the keys it already publishes, and a parent has to
//!   resolve its children's committees before it attests them. Unlike the health record, this one is per
//!   seat and each writer speaks only for itself, so it has no agreement problem to solve first.
//! * [`resolve_committee`] is all-or-nothing, because `ChildCommittee::verifiers` is a dense `Vec` indexed
//!   by validator index and a hole cannot be expressed. `Q = 5` of `7` means a certificate is checkable
//!   whenever the five that signed it have keys present, so a partial committee is genuinely usable and this
//!   refuses it. Expressing that is a `fanos-taxis` change.
//!
//! The `cell: u32` these slots are keyed by is no longer a problem either: `fano::cell_of` derives it.
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
use fanos_taxis::hierarchy::{ChildCommittee, ChildRegistry};
use fanos_taxis::wire::{ShardMsg, TaxisApp, parse_app_body, shard_to_frame};

use tokio::task::JoinHandle;

use fanos_field::Field;
use fanos_geometry::{Triple, fano};
use fanos_primitives::BeaconSeed;
use fanos_pqcrypto::sig::HybridVerifier;
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

/// The slot **one member** of a cell publishes its health reading at — domain-separated, and keyed by seat as
/// well as by cell and epoch.
///
/// The seat is what makes the record bindable and the fold honest. Keyed `(cell, epoch)` alone it was one
/// record for seven writers: they raced, whoever wrote last spoke for the cell, and the `Entitlement` could
/// prove only that *a* member wrote it. Per seat each writer speaks for itself, the envelope binds to that
/// seat's own coordinate, and [`resolve_health`] folds whoever answered — see [`fold_member_reports`].
fn health_slot(cell: u32, seat: usize, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cell-health/".to_vec();
    key.extend_from_slice(&cell.to_be_bytes());
    key.extend_from_slice(&(seat as u32).to_be_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// Fold however many member readings answered into the cell's one block, **per axis by majority**.
///
/// The covering downstream localizes `(child, axis)` from one block per child, so a cell has to speak with
/// one voice — and seven members each have their own view. Two ways to get there, and only one of them
/// needs no agreement protocol:
///
/// * have the members agree and one of them publish. That is a cell-wide decision taken on local inputs,
///   which is the rule this platform does not break; and with a single `(cell, epoch)` slot it is not even
///   a decision, it is a race whose winner is whoever wrote last.
/// * have each member publish **its own** reading and let the reader fold. No agreement, strictly more
///   information, and the fold is where it belongs — with the party that is about to act on it.
///
/// Majority rather than OR, and the difference is who can accuse. Under OR a single member sets every axis
/// of its own cell, which is the input `golay::Provenance` warns about: the decoder corrects toward the
/// nearest codeword, so an injected coordinate does not add noise, it **moves the blame** onto a healthy
/// sibling. A majority requires the cell's own members to corroborate — the same rule `coord_alive` applies
/// to liveness, for the same reason.
///
/// `None` when nobody answered: a cell that said nothing is not a cell that said "healthy" — silence is an
/// erasure, which `ChildDiagnosis` counts separately.
fn fold_member_reports(reports: &[Report]) -> Option<Report> {
    if reports.is_empty() {
        return None;
    }
    let majority = reports.len() / 2 + 1;
    let axes = (0..golay::AXES)
        .filter(|&axis| reports.iter().filter(|r| r.axes >> axis & 1 == 1).count() >= majority)
        .fold(0u8, |mask, axis| mask | 1 << axis);
    Some(Report {
        axes,
        bus_fault: reports.iter().filter(|r| r.bus_fault).count() >= majority,
    })
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
    seat: usize,
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
    let landed =
        client.put_ephemeral(health_slot(cell, seat, epoch), record, DIRECTORY_SLOT_EPOCHS).await;
    let _ = core::marker::PhantomData::<F>;
    crate::note_publish(client, crate::Directory::Health, epoch, landed)
}


/// A cell's **seat-key slot**: `(cell, seat, epoch)`, one per validator index.
///
/// **One slot per seat rather than one per cell, and the reason is who can sign what.** A node knows the
/// seven coordinates of its cell (`fano::cell_of` + `cell_members_of`) and its own verifying key — and
/// nobody else's. A single per-cell record would therefore have to be written by somebody asserting six
/// keys it cannot vouch for, which is the shape the `Entitlement` envelope exists to refuse. Per seat, each
/// validator asserts exactly the one thing it can prove: *this key sits at this coordinate*.
fn committee_slot(cell: u32, seat: usize, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/cell-committee/".to_vec();
    key.extend_from_slice(&cell.to_be_bytes());
    key.extend_from_slice(&(seat as u32).to_be_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// Publish this validator's **consensus verifying key** at its seat in `cell` for `epoch` — the record a
/// parent cell needs before it can check a single signature on this cell's certificates.
///
/// **The last of four blockers on live cross-cell finality, and the only one that was about a missing
/// artefact rather than a missing rule.** This module's header records the other three and how each closed;
/// what remained was that `ChildRegistry::attest_available` resolves a child's `ChildCommittee` before it
/// verifies anything, refuses an unregistered child outright, and *nothing in the workspace constructed
/// one*. A parent could address its children, authenticate their health and sample their data, and still
/// not check one signature.
///
/// The envelope is the sibling directories': the `Entitlement` proves the publisher walked onto **this
/// seat's** coordinate, so a key filed at somebody else's seat does not open. Unlike `publish_health`, the
/// unentitled form is not offered — a committee key with no proof of who wrote it is precisely the input
/// that would let one node speak for its cell's whole validator set.
pub async fn publish_seat_key<F: Field>(
    client: &Client,
    cell: u32,
    seat: usize,
    epoch: Epoch,
    verifier: &HybridVerifier,
    credential: &(Vec<u8>, fanos_vrf::VrfPublic, fanos_vrf::VrfProof),
) -> bool {
    let Some(members) = fano::cell_members_of::<F>(cell as usize) else {
        return false; // the plane does not split into cells: there is no seat to speak for
    };
    if members.coords().get(seat).is_none() {
        return false;
    }
    let (id, public, proof) = credential;
    let record = Entitlement::encode(id, public, proof, &verifier.encode());
    let landed =
        client.put_ephemeral(committee_slot(cell, seat, epoch), record, DIRECTORY_SLOT_EPOCHS).await;
    crate::note_publish(client, crate::Directory::Health, epoch, landed)
}

/// Keep this validator's **consensus verifying key** live in its cell's committee directory: publish it at
/// this node's seat on every epoch boundary.
///
/// **The consumer is a parent cell, not this one.** A validator's own committee arrives by configuration
/// (`taxis_config`'s `verifiers`), so nothing here is discovering what it already knows; what has no
/// configuration is a *child's* committee, which is exactly what `ChildRegistry::attest_available` needs and
/// refuses to proceed without. This publisher is the half that makes [`resolve_committee`] answerable.
///
/// Both the cell and the seat are re-derived at every boundary from the coordinate this node holds *then*.
/// The beacon re-draws it, and the record is bound to the seat's coordinate — so a seat captured at spawn is
/// a record nobody can open.
///
/// **A node with no coordinate prover publishes nothing, and that is the fail-closed direction.**
/// [`publish_seat_key`] has no unentitled form: a committee key with no proof of who wrote it is precisely
/// the input the envelope exists to refuse, and a parent that accepted one would check every certificate
/// against keys chosen by whoever wrote last.
#[must_use]
pub fn spawn_seat_key_publisher<F: Field>(
    client: Client,
    verifier: HybridVerifier,
    prover: Option<fanos_quic::CoordinateProver>,
) -> JoinHandle<()> {
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let Some(prove) = prover else {
            return; // no proof to offer, and this directory admits nothing else
        };
        let mut beacons = client.beacons();
        let mut epoch = Epoch::ZERO;
        let mut seed = client.genesis();
        let seat_now = |client: &Client| {
            let coord = client.address();
            let cell = fanos_geometry::Point::<F>::new(coord).and_then(fano::cell_of::<F>)?;
            let members = fano::cell_members_of::<F>(cell)?;
            let seat = members.coords().iter().position(|&m| m == coord)?;
            Some((cell, seat))
        };
        if let Some((cell, seat)) = seat_now(&client) {
            publish_seat_key::<F>(&client, cell as u32, seat, epoch, &verifier, &prove(epoch, &seed)).await;
        }
        while let Some((e, s)) = crate::next_epoch(&mut beacons, epoch).await {
            epoch = e;
            seed = s;
            if let Some((cell, seat)) = seat_now(&client) {
                publish_seat_key::<F>(&client, cell as u32, seat, epoch, &verifier, &prove(epoch, &seed)).await;
            }
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::HealthPublisher, &supervised, task)
}

/// Assemble `cell`'s committee for `epoch` from its seven seat slots — **whichever of them answered**.
///
/// A seat that has not published is `None` rather than a reason to refuse the whole committee. `Q = 5` of
/// `7` means a certificate is checkable as soon as the five that signed it have keys here, so refusing on
/// any hole would make the quorum's own tolerance unusable; `ExecCertificate::verify_by` states what a hole
/// means downstream — an unchecked vote is not evidence, and it still claims its seat so duplicates stay
/// caught. `None` only when **no** seat answered, which is a cell that has published nothing rather than a
/// committee with gaps.
///
/// Each seat's record is opened against **its own** coordinate, never against the cell as a set: a key that
/// only proves membership somewhere in the cell would let one validator file every seat.
pub async fn resolve_committee<F: Field>(
    client: &Client,
    cell: u32,
    epoch: Epoch,
    beacon: BeaconSeed,
) -> Option<ChildCommittee> {
    let members = fano::cell_members_of::<F>(cell as usize)?;
    let mut verifiers = Vec::with_capacity(fano::N);
    for (seat, &point) in members.coords().iter().enumerate() {
        let key = match tokio::time::timeout(
            STORE_TIMEOUT,
            client.get(committee_slot(cell, seat, epoch)),
        )
        .await
        {
            Ok(Some(bytes)) => Entitlement::open::<F>(&bytes, point, epoch, &beacon)
                .and_then(|(_, payload)| HybridVerifier::decode(payload)),
            // Silent, unreachable, or a record that does not open at this seat — all three are "this parent
            // has not learned seat `seat`", and none of them is a statement about the child's other six.
            _ => None,
        };
        verifiers.push(key);
    }
    if verifiers.iter().all(Option::is_none) {
        return None; // the cell published nothing at all
    }
    Some(ChildCommittee { cell, verifiers, quorum: fanos_taxis::CellParams::FANO.quorum() })
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
    let members = fano::cell_members_of::<F>(cell as usize)?;
    let mut answered = Vec::with_capacity(fano::N);
    for (seat, &point) in members.coords().iter().enumerate() {
        let Ok(Some(bytes)) =
            tokio::time::timeout(STORE_TIMEOUT, client.get(health_slot(cell, seat, epoch))).await
        else {
            continue; // a silent or unreachable member is an erasure, not a clean block
        };
        if let Some(report) = open_health::<F>(&bytes, point, epoch, beacon) {
            answered.push(report);
        }
    }
    fold_member_reports(&answered)
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
    seat: Triple,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<Report> {
    let payload = match beacon {
        Some(seed) => {
            // **This seat's coordinate, not any of the cell's seven**, which is the binding a per-member
            // slot makes available and a per-cell one could not. Under the old rule a record was admitted
            // from a member of the cell *somewhere*, so one member could fill all seven seats and the
            // majority fold below would be a majority of one identity's opinions.
            let (_, payload) = Entitlement::open::<F>(bytes, seat, epoch, &seed)?;
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
        // **The cell is derived per epoch, not taken as an argument, because it MOVES.** `fano::cell_of` is
        // `index mod cells` over this node's coordinate (#145), and the beacon re-draws that coordinate at
        // every boundary — so a `cell: u32` fixed at spawn names the cell this node was in when it started
        // and publishes into it for ever after. A caller could not have supplied a correct value at all.
        // **The cell AND this node's seat in it, both derived from the coordinate it holds right now.**
        // The beacon re-draws that coordinate at every boundary, so a value fixed at spawn names the seat
        // the node had when it started; and the seat is what the record is bound to, so a stale one is a
        // record nobody can open.
        let seat_now = |client: &Client| {
            let coord = client.address();
            let cell = fanos_geometry::Point::<F>::new(coord).and_then(fano::cell_of::<F>)?;
            let members = fano::cell_members_of::<F>(cell)?;
            let seat = members.coords().iter().position(|&m| m == coord)?;
            Some((cell, seat))
        };
        if let Some((cell, seat)) = seat_now(&client) {
            publish_health::<F>(&client, cell as u32, seat, epoch, health(), credential(epoch, &seed).as_ref()).await;
        }
        // Latest-state, not the lossy stream: a cell whose health report is missing for an epoch reads to its
        // neighbours as a cell that has nothing to say, which is not the same as one that is healthy (#86).
        while let Some((e, s)) = crate::next_epoch(&mut beacons, epoch).await {
            epoch = e;
            seed = s;
            // Re-derived on every boundary, for the reason above: this is the instant the coordinate — and
            // therefore the cell — changes. A node that has left the plane's cell structure entirely (a plane
            // whose point count does not divide by seven) publishes nothing rather than into cell zero.
            if let Some((cell, seat)) = seat_now(&client) {
                publish_health::<F>(&client, cell as u32, seat, epoch, health(), credential(epoch, &seed).as_ref()).await;
            }
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

    /// **A member speaks for its own seat, and one member cannot speak for the cell.**
    ///
    /// The record used to be one byte at a `(cell, epoch)` slot, admitted from *any* member of the cell —
    /// so seven writers raced for one slot and whoever wrote last was the cell's voice, while the covering
    /// downstream localizes `(child, axis)` faults from that byte with `t = 3` confidence. Now each member
    /// publishes its own reading at its own seat and the **reader** folds, per axis by majority.
    ///
    /// Both halves are asserted here because either alone is a hole: the binding without the fold lets one
    /// member fill all seven seats, and the fold without the binding folds one identity's seven opinions.
    #[test]
    fn a_member_speaks_for_its_own_seat_and_a_minority_cannot_accuse_the_cell() {
        use fanos_field::F4;
        use fanos_vrf::{VrfSecret, probe_index_of, prove_coordinate_ranked};

        let (epoch, beacon, cell) = (Epoch::new(4), BeaconSeed::GENESIS, 1u32);
        let members = fano::cell_members_of::<F4>(cell as usize).expect("PG(2,4) splits into three cells");
        let report = Report { axes: 0b010_1101, bus_fault: true };

        let sealed = |seed: u8| {
            let sk = VrfSecret::from_seed([seed; 32]);
            let id = format!("health-{seed}").into_bytes();
            let (_, proof, out) = prove_coordinate_ranked::<F4>(&sk, &id, epoch, &beacon);
            let reached: Vec<usize> = members
                .coords()
                .iter()
                .enumerate()
                .filter(|&(_, &c)| {
                    fanos_geometry::Point::<F4>::new(c)
                        .and_then(|p| probe_index_of::<F4>(&out, &p))
                        .is_some()
                })
                .map(|(i, _)| i)
                .collect();
            (Entitlement::encode(&id, &sk.public(), &proof, &[report.block()]), reached)
        };
        // Exactly one seat, which is the case where "its own seat" and "some seat of the cell" differ — and
        // the walk is `q + 1 = 5` points of twenty-one against a cell of seven, so it is not a rare draw.
        let (record, seats) = (0u8..=255)
            .map(sealed)
            .find(|(_, reached)| reached.len() == 1)
            .expect("some identity reaches exactly one seat of this cell");
        let mine = seats[0];

        let own = members.coords().get(mine).copied().expect("the seat exists");
        assert_eq!(
            open_health::<F4>(&record, own, epoch, Some(beacon)).map(|r| (r.axes, r.bus_fault)),
            Some((report.axes, report.bus_fault)),
            "a member could not publish at the seat it holds, so no cell can report at all — and the payload \
             must survive the envelope, since an authenticated record decoding to something else is a \
             different defect wearing this one's clothes"
        );
        for (seat, &point) in members.coords().iter().enumerate() {
            if seat != mine {
                assert!(
                    open_health::<F4>(&record, point, epoch, Some(beacon)).is_none(),
                    "seat {seat} accepted a record entitled to seat {mine}: one member then fills all seven \
                     and the majority below is a majority of one identity's opinions"
                );
            }
        }

        // The fold. Axis 0 is set by one member of five, axis 1 by three — a minority cannot accuse, a
        // majority can, and the boundary between them is the whole rule.
        let say = |axes: u8| Report { axes, bus_fault: false };
        let mixed = [say(0b01), say(0b10), say(0b10), say(0b10), say(0b00)];
        assert_eq!(
            fold_member_reports(&mixed).map(|r| r.axes),
            Some(0b10),
            "a single member set an axis of its own cell — which is exactly the injected coordinate \
             `golay::Provenance` warns about: the decoder moves blame toward the nearest codeword rather \
             than adding noise, so one member could accuse a healthy sibling"
        );
        assert_eq!(
            fold_member_reports(&[]),
            None,
            "an empty fold must be silence, not a clean block — seven silent children reading `Healthy` is \
             the defect `ChildDiagnosis` counts separately"
        );
        assert_eq!(
            fold_member_reports(&[say(0b101)]).map(|r| r.axes),
            Some(0b101),
            "a cell of one answering member is its own majority; refusing there would make a single-member \
             reading unreportable rather than uncorroborated"
        );
    }

    /// **A seat key is admitted for THAT seat and for no other** — the binding a committee directory has to
    /// carry, and the one a cell-wide envelope cannot.
    ///
    /// `publish_health`'s rule is "a member of this cell may speak for it", which is right for a single
    /// per-cell record and wrong here: seven seats mean seven claims, and a rule that only proves *cell
    /// membership* lets one validator file all seven — every certificate the parent then checks is checked
    /// against keys that validator chose. So each seat's record is opened against **its own** coordinate.
    ///
    /// Both directions on one fixture, because a check that admits everything and a check that admits
    /// nothing both look like "the right key opened".
    #[test]
    fn a_seat_key_opens_at_its_own_seat_and_nowhere_else() {
        use fanos_field::F4;
        use fanos_pqcrypto::{SeedRng, sig::HybridSigSecret};
        use fanos_vrf::{VrfSecret, probe_index_of, prove_coordinate_ranked};

        let (epoch, beacon, cell) = (Epoch::new(4), BeaconSeed::GENESIS, 1u32);
        let members = fano::cell_members_of::<F4>(cell as usize).expect("PG(2,4) splits into three cells");
        // Deterministic: the test asserts *which slot* a key opens at, and a fresh key each run would make
        // the failure message name a different one every time.
        let (_, key) = HybridSigSecret::generate(&mut SeedRng::from_seed(&[9u8; 32]));

        // An identity whose walk reaches exactly one point of this cell — which is the ordinary case, and
        // the only one where "its own seat" and "some seat" differ.
        let sealed = |seed: u8| {
            let sk = VrfSecret::from_seed([seed; 32]);
            let id = format!("seat-{seed}").into_bytes();
            let (_, proof, out) = prove_coordinate_ranked::<F4>(&sk, &id, epoch, &beacon);
            let reached: Vec<usize> = members
                .coords()
                .iter()
                .enumerate()
                .filter(|&(_, &c)| {
                    fanos_geometry::Point::<F4>::new(c)
                        .and_then(|p| probe_index_of::<F4>(&out, &p))
                        .is_some()
                })
                .map(|(i, _)| i)
                .collect();
            (Entitlement::encode(&id, &sk.public(), &proof, &key.encode()), reached)
        };
        let (record, seats) = (0u8..=255)
            .map(sealed)
            .find(|(_, reached)| reached.len() == 1)
            .expect("some identity reaches exactly one seat of this cell");
        let mine = seats[0];

        let own = members.coords().get(mine).copied().expect("the seat exists");
        assert!(
            Entitlement::open::<F4>(&record, own, epoch, &beacon).is_some(),
            "a validator could not file a key at the seat it actually holds, so no committee can ever form"
        );
        for (seat, &point) in members.coords().iter().enumerate() {
            if seat == mine {
                continue;
            }
            assert!(
                Entitlement::open::<F4>(&record, point, epoch, &beacon).is_none(),
                "seat {seat}'s slot accepted a key entitled to seat {mine}: one validator can then file the \
                 whole committee, and every certificate the parent checks is checked against keys it chose"
            );
        }
    }

    /// The committee slots are distinct across every axis they are keyed by, and domain-separated from the
    /// health slots that sit one function away.
    #[test]
    fn committee_slots_separate_cell_seat_and_epoch() {
        let base = committee_slot(3, 2, Epoch::new(7));
        assert_ne!(base, committee_slot(4, 2, Epoch::new(7)), "two cells share a seat slot");
        assert_ne!(base, committee_slot(3, 5, Epoch::new(7)), "two seats of one cell share a slot");
        assert_ne!(base, committee_slot(3, 2, Epoch::new(8)), "two epochs share a slot");
        assert!(
            base.starts_with(b"FANOS-v1/cell-committee/"),
            "the domain tag is what keeps this out of every other directory's key space"
        );
        assert_ne!(base, health_slot(3, 2, Epoch::new(7)), "committee and health slots collide");
    }

    #[test]
    fn health_slots_are_deterministic_distinct_and_domain_separated() {
        let h = health_slot(3, 2, Epoch::new(7));
        assert_eq!(h, health_slot(3, 2, Epoch::new(7)));
        assert_ne!(h, health_slot(4, 2, Epoch::new(7)), "distinct cell → distinct slot");
        // The axis the record gained when it stopped being one per cell: seven members, seven slots, and a
        // collision here would put two members' readings on top of each other and fold one of them twice.
        assert_ne!(h, health_slot(3, 5, Epoch::new(7)), "distinct seat → distinct slot");
        assert_ne!(h, health_slot(3, 2, Epoch::new(8)), "distinct epoch → distinct slot");
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
