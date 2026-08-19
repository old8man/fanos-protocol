//! **Joining, announcing, and moving** for [`OverlayNode`] — the JOIN/`Announce` flood, the epoch advance and agreement,
//! and the per-epoch re-seat that carries this node to a new coordinate (spec §7.8, §L3). Split out of the facade's impl
//! (task 7a).
//!
//! Distinct from [`crate::membership`], which holds the *view* these handlers write: this is the protocol that maintains
//! it. Keeping them apart is why the view could be lifted to a sibling module while these stay a child of the facade —
//! they touch the node's whole state, the view touches only its own.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ports::stations::Station;
use fanos_core::PowAdmission;
use fanos_field::Field;
use fanos_geometry::{derive_address, fano, HierAddr, Plane, Point, Triple};
use fanos_primitives::Epoch;
use fanos_wire::error::ProtocolError;
use fanos_wire::FrameType;

use crate::frames::{encode_error_with, 
    admission_challenge, announce_body, descriptor_signature_ok, encode, parse_announce,
};
use crate::ports::{Effect, Notification};
use crate::router::{Peer, Router};

use super::{
    HEARTBEAT,
    OverlayNode,
};


impl<F: Field> OverlayNode<F> {
    /// Flood `frame` to every cell neighbour (the substrate for JOIN and beacon propagation).
    pub(super) fn flood(&self, frame: &[u8]) -> Vec<Effect> {
        self.peers
            .keys()
            .map(|&peer| Effect::Send {
                to: peer,
                frame: frame.to_vec(),
            })
            .collect()
    }

    /// `Command::Join` — record our own info and flood an announcement (carrying our overlay address)
    /// so every member learns our keys and how to route to us hierarchically.
    pub(super) fn on_join(&mut self, info: Vec<u8>) -> Vec<Effect> {
        let coord = self.coord.coords();
        let frame = encode(
            FrameType::Announce,
            &announce_body(
                coord,
                &self.router.address,
                &self.membership.identity,
                &self.membership.descriptor_sig,
                &self.membership.admission_proof,
                &info,
            ),
        );
        let effects = self.flood(&frame);
        self.membership.members.insert(coord, info);
        effects
    }

    /// A received announcement: on first sight of a member, record it, notify, and re-flood so the
    /// key propagates cell-wide; on a repeat, drop (the monotone guard terminates the flood).
    pub(super) fn on_announce(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some((coord, hier, id, sig, proof, info)) = parse_announce::<F>(body) else {
            return Vec::new();
        };
        // Validate: a member coordinate must be a real, canonical projective point of this plane.
        // Rejecting the zero vector and out-of-range triples both prevents state poisoning and
        // bounds `members` by the plane size `N` — a peer cannot grow it without limit with forged
        // coordinates (spec §7.8 membership). The hierarchical address was already validated by
        // `parse_announce` (canonical points, bounded depth), so a forged one is dropped before here.
        let Some(coord) = Point::<F>::new(coord).map(|p| p.coords()) else {
            // Unattributed by construction: the coordinate is not a point of this plane, so there is no line to
            // charge it to, and inventing one would put fabricated evidence against a line into the plane built
            // to end diagnosis on thin evidence.
            self.stations.record(Station::FrameDecodeFailed, None);
            return Vec::new();
        };
        // Sybil admission (opt-in, spec §L3, §7.8 JOIN step 2): the FIRST gate, ahead of
        // self-certification and membership — a per-admission cost is exactly what the
        // structural centrality cap alone does not provide (`sybil_cost.rs`). Fails **closed**:
        // requiring admission with no policy installed rejects every peer, never silently
        // admits. A rejection is not admitted to `members` and is told why (`SYBIL_REJECT`,
        // spec §7.5), sent to the *claimed* coordinate rather than the immediate relay hop —
        // `Announce` is flooded, so whoever forwarded it to us need not be the joiner itself.
        if self.config.require_admission {
            // The challenge binds the announcer's IDENTITY, not merely its coordinate. Without that a solved proof is
            // replayable by anyone claiming the same point: an attacker who wants a seat could present the *incumbent's
            // own* proof and pay nothing. Measured cost of the surrounding attack before this binding — grind ~20
            // identities until one collides with a chosen victim at a lower rank (`fanos-vrf/examples/grind_probe.rs`),
            // reuse the victim's proof, and the rank rule evicts the victim for zero proof-of-work.
            let challenge = admission_challenge(&id, coord, self.epoch);
            if !self.membership.admits(&challenge, &proof) {
                // Carry the price back. Under the adaptive gate the difficulty moves with the cell's stress, so a
                // joiner's proof can be honest work at a price that has since risen — and a rejection with no
                // number is, for that peer, an unexplained permanent refusal. Telling them costs nothing they
                // could not learn by trying again, which is the same argument that makes the adaptive price safe
                // to expose at all.
                self.stations.record(Station::AdmissionPowFailed, Some(coord));
                let required = self.membership.required_difficulty();
                return alloc::vec![Effect::Send {
                    to: coord,
                    frame: encode_error_with(
                        ProtocolError::SybilReject,
                        &required.map(|bits| bits.to_le_bytes().to_vec()).unwrap_or_default(),
                    ),
                }];
            }
        }
        // Self-certified membership (opt-in) drops the whole announcement unless BOTH hold:
        //  1. the overlay address is the identity's own derived descent chain — else it is a
        //     routing-table poisoning attempt (a peer claiming an address it did not earn to attract a
        //     target's `RouteHier` traffic); forging a match costs `≈ N^k` grinding (threat §79/B1);
        //  2. the descriptor signature binds this exact transport `coord` to the identity — else it is a
        //     transport hijack (re-announcing another identity's address at the attacker's own endpoint),
        //     which without the identity's private key cannot be signed (threat §80).
        // Under VRF coordinates (`config.vrf_coordinates`, spec §A7) the level-0 point is the beacon-seated
        // VRF coordinate, NOT the hash `address_point(id, 0)`, so the chain check starts at level 1 — level
        // 0's authenticity is the proof-of-coordinate HELLO + the descriptor signature (check 2). Without
        // this skip a legitimate VRF announcement fails check 1 and is rejected (audit C3).
        // Neither `members` nor the router's peer table is written on failure.
        let min_level = usize::from(self.config.vrf_coordinates);
        if self.config.require_self_certified_membership
            && (!fanos_primitives::address_matches_identity_from::<F>(&id, &hier, min_level)
                || !descriptor_signature_ok::<F>(coord, &hier, &id, &sig))
        {
            // The sharpest of the three and the one that was silent: an address that is not the identity's own
            // descent chain is a routing-table poisoning attempt, and a descriptor that does not sign this
            // transport coordinate is a transport hijack. Both simply vanished.
            self.stations.record(Station::AdmissionIdentityUnbound, Some(coord));
            return Vec::new();
        }
        // First sight only, with **one** exception that the descent made necessary. A repeat must not
        // overwrite the stored key bundle — otherwise any peer could silently replace a member's advertised
        // keys in our local view (and suppress the re-flood, diverging the cell) — and the monotone guard is
        // what ends the flood.
        //
        // The exception: **an identity may move its own overlay address.** A node that descends into a
        // sub-cell (§L0/§L1) re-announces from the coordinate it already holds, and under the plain
        // first-sight rule every peer read that as a repeat and dropped it — so the descendant announced a
        // sub-cell address nobody ever learned and stayed unroutable, which is the whole thing the descent
        // exists to fix. Admitted only when all three hold, and each one is load-bearing:
        //
        // * the announcer's identity **equals the one already recorded** at this coordinate — so a stranger
        //   still cannot touch a member's record, which is the property the guard protects;
        // * that identity is **non-empty** — under an unsigned deployment every announcer's `id` is empty
        //   and "equal" would admit anybody;
        // * the address **actually differs** from the one held — so a re-flood of an unchanged announcement
        //   still terminates, which is the guard's other job.
        //
        // The key bundle is left alone even on the admitted path: only the route moves.
        if self.membership.members.contains_key(&coord) {
            let same_identity = !id.is_empty() && self.membership.identities.get(&coord) == Some(&id);
            let moved = self.router.peers.get(&coord) != Some(&hier);
            if !(same_identity && moved) {
                // **Counted, because this branch refuses two different things and used to say nothing.** A
                // benign re-flood terminating is one; a node that arbitration legitimately seated at this
                // point being locked out of the cell's membership view is the other — and the second became
                // reachable the moment epochs began to advance, since the beacon re-draws every coordinate
                // while `members` is keyed by position and is not cleared at the boundary.
                self.stations.record(Station::MembershipRepeatIgnored, Some(coord));
                return Vec::new();
            }
            self.learn_hier_peer(hier.clone(), coord);
            let mut effects = self.flood(&encode(
                FrameType::Announce,
                &announce_body(coord, &hier, &id, &sig, &proof, &info),
            ));
            effects.push(Effect::Notify(Notification::PeerAddressed {
                coord,
                path: hier.points().iter().map(Point::coords).collect(),
            }));
            return effects;
        }
        self.membership.members.insert(coord, info.clone());
        // …and the identity behind it, which is what a contested sub-cell point is arbitrated on. Inserted
        // beside `members` and under the same first-sight rule, so the two cannot disagree about who is at
        // a coordinate.
        self.membership.identities.insert(coord, id.clone());
        // Seed the hierarchical routing table: this overlay address is reachable via `coord`. A
        // descended sub-cell member thus becomes routable cell-wide from its announcement alone (§L1);
        // a depth-1 announcer adds its own direct entry, so `send_hier` also delivers within one plane.
        self.learn_hier_peer(hier.clone(), coord);
        let frame = encode(
            FrameType::Announce,
            &announce_body(coord, &hier, &id, &sig, &proof, &info),
        );
        let mut effects = self.flood(&frame);
        // No `PeerAddressed` here: `MemberJoined` already says the cell learned this peer, and an extra
        // notification on every announce is broadcast pressure — on a channel whose own doc calls itself
        // lossy under lag — that every existing deployment would pay for nothing. The notification means
        // *changed*, and on first sight there is nothing that changed.
        effects.push(Effect::Notify(Notification::MemberJoined { coord, info }));
        effects
    }

    /// `Command::AdvanceEpoch` — bump the epoch and flood the epoch-agreement gossip so the cell adopts
    /// it. This carries only the epoch ordinal ([`FrameType::EpochAgree`]), never randomness — under a
    /// live threshold-DVRF beacon the composite drives this from an authoritative `Beacon` round instead
    /// and suppresses the flood (audit #102).
    /// Everything that must happen because **the epoch is now a different one**, in the one place both paths
    /// to that fact call — this node's own tick and a peer's gossip.
    ///
    /// It was duplicated, and the duplicate was already load-bearing: the sweep had to be repeated in the
    /// gossip path or whether a store filled depended on which node happened to drive the advance. #153 adds
    /// a second thing that must happen at exactly the same instant, and two of them is where a third gets
    /// added to one path only.
    fn on_epoch_changed(&mut self) {
        // Reclaim the directory slots the advance just killed. Here rather than on a timer, because the
        // epoch IS the lifetime: a slot keyed `(coordinate, epoch)` is dead exactly when the epoch it names
        // has passed, and this is the one place that fact becomes true.
        self.store.sweep_expired(self.epoch);
        // **And membership, for exactly the reason stated two lines below.** `members` is keyed by
        // coordinate, `on_announce` refuses a repeat at an occupied one ("first sight only", so no peer can
        // overwrite another's key bundle), and the beacon re-draws every coordinate at this instant — so a
        // map kept across the boundary describes the *previous* seating and locks out every node that
        // legitimately arrives at a point its former occupant still holds. Measured before this line existed:
        // `membership.repeat_ignored` went from `[0,0,0,0,0]` at genesis to `[52,54,69,51,107]` eight epochs
        // later on a five-node fleet, growing without bound, and silently until the station was added.
        //
        // **Clearing is the consistent action, not a new policy.** The comment below already says state
        // addressed by a position stops describing what its address names, and `grey_reported` is cleared for
        // precisely that; the directory slot above is reclaimed for precisely that. Membership was the one
        // position-keyed table the rule skipped.
        //
        // **What it costs, stated.** A node's view of the cell is empty for the moment after a boundary and
        // refills from the re-announce every node emits when it reseats (`on_reseat` → `on_join`). A peer
        // whose re-announce is lost is missing for one epoch — against being locked out permanently, which is
        // what the measurement above shows the alternative to be.
        // Recorded before the clear, so it reports what this epoch ended with — see `MembershipSize`. The
        // pair (`size` per epoch, `repeat_ignored` total) is what separates a draining flood from a lock-out.
        self.stations.record_tagged(
            Station::MembershipSize,
            None,
            u64::try_from(self.membership.members.len()).ok(),
            1,
        );
        self.membership.members.clear();
        // With them, and for the identical reason: `identities` is the same view keyed the same way, and a
        // stale entry there would arbitrate a sub-cell contest against a node that has left the point.
        self.membership.identities.clear();
        // The epoch re-draws every node's VRF coordinate, so every cell position keeps its name and changes
        // its occupant. State addressed by a position stops describing what its address says — see
        // [`Healer::on_seating_changed`] for the measurement and for the two things deliberately kept.
        self.healer.on_seating_changed();
        // Coordinate-named, and in the facade rather than the reflex: the dedup for "which node is currently
        // grey". Left set, the next genuinely-grey node at that point is *not* reported, because the engine
        // believes it already said so about the node that used to be there.
        self.grey_reported = None;
        // Claims the cell has now reached are worthless — they can never again be the newest thing a
        // quorum vouches for — and dropping them here is what lets the map need no window and no chosen
        // constant. What survives is exactly the claims still ahead of us, which is the population the
        // quorum is about (#351).
        let reached = self.epoch;
        self.epoch_claims.retain(|_, claimed| *claimed > reached);
    }

    pub(super) fn on_advance_epoch(&mut self) -> Vec<Effect> {
        self.epoch = self.epoch.next();
        self.on_epoch_changed();
        let mut effects = self.flood(&encode(FrameType::EpochAgree, &self.epoch.low32_be_bytes()));
        effects.push(Effect::Notify(Notification::EpochAdvanced(self.epoch)));
        effects
    }

    /// A received epoch-agreement gossip: adopt the newest epoch a **quorum of distinct members** vouches
    /// for, then re-flood and notify. The 4-byte body is the epoch ordinal — see [`FrameType::EpochAgree`].
    ///
    /// **Why one claimant is not enough, in the system's own units.** Every other decision in FANOS tolerates
    /// `f` faulty members; this one used to tolerate **zero**. It took the spec's `adopt-max` — sound for a
    /// threshold-DVRF round, which proves itself — and applied it to a bare ordinal that proves nothing, so a
    /// single member inside the fault budget set the whole cell's clock. The cost was not theoretical:
    /// `DIRECTORY_SLOT_EPOCHS = 1`, so a slot written at `E` is reclaimed once `now ≥ E+2`, and **a claim of
    /// `current + 2` — indistinguishable from a node whose beacon ran two rounds while it was busy —
    /// expired every directory slot on this node and on everyone it re-flooded to.**
    ///
    /// The rule is the one `coord_alive` already uses one file over, and the quantity is the one `Config`
    /// already owns: adopt the epoch that at least [`corroboration_quorum`](super::Config::corroboration_quorum)
    /// distinct claimants have reached. With `≤ f` liars they cannot occupy the whole of the top `q` claims,
    /// so the adopted value is always vouched for by at least one honest member. Calibrated to the standing
    /// assumption and no further: stronger than `q` buys nothing, because above `f` every other threshold in
    /// this system has already fallen.
    ///
    /// **Materiality is checked before anything is recorded**, which is `note_certified_height`'s rule in
    /// TAXIS and for its reason: a repeated or stale claim then costs nothing, and an attacker pays one frame
    /// per counted claim rather than driving an unbounded loop.
    ///
    /// **The residual, stated rather than papered over.** Claims are keyed by the claimant's coordinate, and
    /// this engine is crypto-free — it holds no stable identity for a peer (`Peer` carries liveness, not a
    /// `NodeId`), so it cannot link a member that reseats mid-epoch to the coordinate it left. Such a member
    /// leaves one stale claim behind, and an adversary that has legitimately held several cell points this
    /// epoch can leave one at each. That reduces the attack from *one frame, unbounded* to *`q` distinct cell
    /// points must be held*, which already means out-ranking incumbents beyond the fault budget — but it does
    /// not eliminate it. Closing it needs the layer where identity is known: the driver's
    /// `distrust.seat(from, identity_of(&cert))`.
    pub(super) fn on_epoch_agree(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some(bytes) = body.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
            return Vec::new();
        };
        let claimed = Epoch::from_low32_be_bytes(bytes);
        if claimed <= self.epoch {
            return Vec::new(); // not newer — drop (terminates the flood)
        }
        self.epoch_claims.insert(from, claimed);
        // The newest epoch at least `q` distinct claimants have reached: sort the claims descending and read
        // the `q`-th. An order statistic rather than a threshold test, because "three members claimed
        // something" and "three members claimed at least THIS" are different facts, and only the second is
        // what a quorum means.
        let quorum = self.config.corroboration_quorum;
        let mut reached: Vec<Epoch> = self.epoch_claims.values().copied().collect();
        reached.sort_unstable_by(|a, b| b.cmp(a));
        let Some(&epoch) = reached.get(quorum.saturating_sub(1)) else {
            // Fewer claimants than the quorum needs. Counted, tagged with how many vouched: FANOS's rule for
            // a node that cannot corroborate is to escalate rather than decide, and a stall nobody can see is
            // not an escalation — it is indistinguishable from a healthy quiet cell.
            self.stations
                .record_tagged(Station::EpochAgreeBelowQuorum, None, u64::try_from(reached.len()).ok(), 1);
            return Vec::new();
        };
        if epoch <= self.epoch {
            self.stations
                .record_tagged(Station::EpochAgreeBelowQuorum, None, u64::try_from(reached.len()).ok(), 1);
            return Vec::new();
        }
        self.epoch = epoch;
        // The gossip path advances the clock too, and a node that learns the epoch from a peer rather than
        // from its own tick must do exactly as much — otherwise whether a store fills, or whether a cell's
        // self-model is spliced across a reshuffle, depends on which node happened to drive the advance.
        self.on_epoch_changed();
        let mut effects = self.flood(&encode(FrameType::EpochAgree, &epoch.low32_be_bytes()));
        effects.push(Effect::Notify(Notification::EpochAdvanced(epoch)));
        effects
    }

    /// `Command::Reseat` — re-seat this node at `new_coord` for the per-epoch reshuffle (spec §L3 "epoch
    /// reshuffle", §3.2). The driver supplies the new VRF-derived coordinate (the engine is crypto-free and
    /// cannot compute it); this re-derives the node's cell neighbours and Fano index for the new placement,
    /// moves the level-0 of its hierarchical address to `new_coord` while **preserving the deeper descent
    /// levels** (identity-hash, epoch-stable — §L1), re-announces so the cell relearns how to route to it, and
    /// emits
    /// [`Notification::Reseated`] (a driver rebuilds its HELLO proof-of-coordinate; the simulator re-keys
    /// the node). The unpredictable reshuffle is the load-bearing anti-eclipse / anti-path-prediction
    /// defence (§3.2 assumption 2), the one q=2 grinding does not provide.
    ///
    /// **STORAGE is deliberately preserved.** Content addressing is epoch-stable (`MapToPoint(H(k))`, §L4)
    /// and the store is full-cell-replicated, so a within-cell reshuffle is a *placement* move, not a data
    /// migration ("fixed points, flowing nodes"): the node still holds every value it held and keeps serving
    /// them across the transition — that preservation **is** the one-epoch grace window (audit C2), so no
    /// key is lost on rotation. A per-shard prune of values a node is no longer a replica for belongs to the
    /// erasure-coded store (#115), where a replica can compute its own line-membership; under full
    /// replication every cell member is a replica for every key, so within a cell there is nothing to prune.
    ///
    /// A no-op if `new_coord` is not a canonical projective point or already equals this coordinate.
    /// `Command::ProposeAddress` — compute, and only report, the shortest hierarchical address this node may
    /// hold (spec §L0/§L1). Nothing moves; [`on_descend`](Self::on_descend) is what adopts.
    ///
    /// # Why level 0 is an argument and everything below it is derived here
    ///
    /// The two levels are arbitrated by different rules held in different places. Level 0 is settled by the
    /// **VRF claim order** — `(probe_index, VrfOutput)` verified against a beacon — which lives in the
    /// driver and is invisible from here: a rival for this node's own point is not in `router.peers`,
    /// because that table is keyed by transport coordinate and this node *is* that coordinate. So `contested`
    /// is the one fact the caller must supply.
    ///
    /// Levels ≥ 1 are settled by the strict total order on **identity bytes**, and the identities arrive
    /// only here — `on_announce` parses each peer's `id`, and `membership.identities` keeps it beside the
    /// `router.peers` address under the same key. Every node runs the same pure function over the same view,
    /// so of any identities contesting a position exactly one (the minimum id) keeps it and the rest descend,
    /// conflict-free and with no negotiation.
    ///
    /// [`fanos_primitives::derive_hierarchical_address`] is deliberately **not** reused: its level-0 rule is
    /// the same id order, which would contradict the VRF arbitration and let the two mechanisms disagree
    /// about who owns a point. What is shared is the primitive underneath — `derive_address`, the one
    /// implementation of "keep the shortest prefix nothing else holds".
    ///
    /// A `None` from that primitive means `MAX_DEPTH` consecutive levels were all occupied, and it is not a
    /// caller's mistake: it is a node that **cannot join at all**, counted apart for that reason.
    pub(super) fn on_propose_address(&mut self, contested: bool) -> Vec<Effect> {
        let own_id = self.membership.identity.clone();
        let own_point = self.coord;
        let derived = {
            // The pairs the tie-break needs, and only those: a peer whose address is known but whose
            // identity is not cannot be compared, so it does not get to displace anyone.
            let seated: Vec<(&[u8], &HierAddr<F>)> = self
                .router
                .peers
                .iter()
                .filter_map(|(coord, addr)| {
                    self.membership.identities.get(coord).map(|id| (id.as_slice(), addr))
                })
                .collect();
            derive_address::<F>(
                |level| if level == 0 { own_point } else { fanos_primitives::address_point::<F>(&own_id, level) },
                |path| match path.len() {
                    1 => contested,
                    _ => seated
                        .iter()
                        .any(|(pid, addr)| *pid < own_id.as_slice() && addr.points() == path),
                },
            )
        };
        let Some(addr) = derived else {
            self.stations.record(Station::AddressUnplaceable, Some(own_point.coords()));
            return Vec::new();
        };
        alloc::vec![Effect::Notify(Notification::AddressProposed {
            path: addr.points().iter().map(Point::coords).collect(),
        })]
    }

    /// `Command::Descend` — adopt `path` as this node's overlay hierarchical address and re-announce under it.
    ///
    /// **The transport coordinate does not move, and that is the whole design.** A descended node keeps
    /// `self.coord`, keeps its store, keeps its cell peers; what changes is the *overlay* address it is
    /// addressed by. `with_hier_address` already states the decoupling — *"the two need not coincide past
    /// depth 1"* — and this is the runtime path that finally uses it. The alternative, re-keying transport by
    /// the full path, moves every coordinate-keyed consumer in the tree (`cap_slot`, the erasure shard homes,
    /// the validator table) and buys nothing a descendant needs: it is reached inbound by `RouteHier` through
    /// an ancestor, which is dispatched and live.
    ///
    /// Depth 1 is the flat address and is accepted rather than refused — it is how a node that wins its point
    /// back **ascends** out of a sub-cell. `on_reseat` deliberately preserves the deep levels across a
    /// reshuffle (they are identity-derived and epoch-independent), so without an explicit ascent a node that
    /// descended once would stay descended for the life of the process.
    ///
    /// Refused, with no mutation and a counted station, when the path is not an address **of this node**:
    /// empty, deeper than `MAX_DEPTH`, carrying a point that is not canonical on this plane, or rooted
    /// anywhere but `self.coord` — a descendant hangs *under* the point it wanted, so a foreign level 0 is a
    /// different node's address and adopting it would make this node unreachable at an address nobody routes
    /// to it. Every one of those is a caller bug rather than a peer's doing, which is why the refusal is
    /// silent to the network and loud in the stations.
    pub(super) fn on_descend(&mut self, path: &[Triple]) -> Vec<Effect> {
        let refuse = |me: &mut Self| {
            me.stations.record(Station::DescendRefused, path.first().copied());
            Vec::new()
        };
        let Some(points) = path.iter().map(|&c| Point::<F>::new(c)).collect::<Option<Vec<_>>>() else {
            return refuse(self);
        };
        if points.first() != Some(&self.coord) {
            return refuse(self);
        }
        // Depth is `HierAddr::from_path`'s to enforce, not this function's: it already refuses an empty path
        // and anything past `MAX_DEPTH`, and a second copy of that bound here is a constant that can drift
        // from the one the wire codec uses.
        let Some(addr) = HierAddr::from_path(points) else {
            return refuse(self);
        };
        if addr == self.router.address {
            return Vec::new(); // already there — re-announcing would be a flood with no news in it
        }
        let deepened = addr.depth() > 1;
        self.router.address = addr;
        if deepened {
            self.stations.record(Station::Descended, Some(self.coord.coords()));
        }
        // Re-announce under the new address so peers can route to it: `on_announce` feeds `learn_hier_peer`,
        // which is what makes `RouteHier` able to reach a descendant at all. The membership entry is re-used
        // rather than removed and re-added — unlike a reseat, nothing about this node's *coordinate* changed,
        // so there is no stale entry to drop.
        let info = self.membership.members.get(&self.coord.coords()).cloned().unwrap_or_default();
        self.on_join(info)
    }

    pub(super) fn on_reseat(&mut self, new_coord: Triple) -> Vec<Effect> {
        let Some(new_pt) = Point::<F>::new(new_coord) else {
            return Vec::new(); // not a canonical projective point — ignore
        };
        if new_pt == self.coord {
            return Vec::new(); // already seated here
        }
        let old = self.coord.coords();
        // Re-derive the cell neighbour set for the new coordinate — with fresh liveness, exactly as a join
        // does: the node re-discovers which neighbours are live at its new position over the next heartbeat
        // round, so no stale "alive" carries over from the old placement into the responsibility set.
        let mut peers = BTreeMap::new();
        for line in Plane::<F>::lines_through(new_pt) {
            for member in Plane::<F>::points_on(line) {
                if member != new_pt {
                    peers.entry(member.coords()).or_insert(Peer {
                        last_seen: None,
                        reported_down: false,
                        loss: 0.0,
                        awaiting_pong: false,
                    });
                }
            }
        }
        self.peers = peers;
        // **A node seated in an explicit cell does not reseat out of it** (#145).
        //
        // `with_cell_members` sets `self_index` to this node's position in the ROSTER, and the reflex is
        // index-addressed off that: `polar_class(self_index)` names the three channels this node mediates,
        // and `cell_coord(i)` maps every other index through the same roster. Recomputing the index by the
        // BASE-PLANE rule here — which is what this did — silently substitutes a different question. At
        // `q = 2` the node would attest under its base-plane point instead of its cell position, so its polar
        // rates would be filed against the wrong three channels; above `q = 2` the rule yields `None` and the
        // whole reflex switches off. Neither is visible: every effect still fires, addressed wrongly.
        //
        // It is latent only because production never sets `cell_members` — which is exactly why it must be
        // right *before* it does, rather than after (the trap [[moving-a-seat-moves-its-whole-family]]
        // describes). An explicit cell is a provisioned committee at fixed transport points; the per-epoch
        // VRF reshuffle is a defence for a node's placement on the BASE plane, and the two are different
        // things. So a `Reseat` that would move a node out of its roster is refused, loudly, rather than
        // half-applied — and one that lands back inside it re-reads the index from the roster.
        //
        // **A DERIVED roster is the opposite case, and the same code would get it exactly wrong.** A cell
        // obtained from `fano::cell_of` is a function of the plane, not a provisioned committee, so the
        // node's cell FOLLOWS its coordinate: at each reshuffle it belongs to whichever cell its new point
        // is in. Defending the old roster there would make a node refuse its **own** epoch reshuffle and
        // freeze at its founding coordinate while the rest of the plane moved on. So a derived roster is
        // re-derived here, and only a provisioned one is defended.
        if self.cell_roster_derived {
            let derived = fano::cell_of(new_pt)
                .and_then(|index| fano::cell_members_of::<F>(index))
                .map(|cell| cell.coords());
            self.cell_members = derived;
            self.healer.cell_members = derived;
        }
        let seat = match &self.cell_members {
            // The roster's own index, never the base plane's — see above.
            Some(members) => members.iter().position(|&m| m == new_coord),
            // No explicit roster: the base plane IS the cell, and only at `N = 7` does it form one.
            None if Plane::<F>::N == 7 => (0..7).find(|&i| Point::<F>::at(i) == new_pt),
            None => None,
        };
        // No `&& !derived` here, and that is checked rather than assumed: the re-derivation above runs
        // BEFORE this lookup, so a derived roster always contains the new coordinate — it is the roster of
        // the very cell that coordinate is in — and `seat` cannot be `None` for one. Where the plane does
        // not split the re-derivation sets the roster to `None`, so the `is_some()` fails first. Guarding
        // it again passed every test, which is how the redundancy was found; the ORDER is what makes it
        // redundant, so moving the re-derivation below this line would need the guard back.
        if self.cell_members.is_some() && seat.is_none() {
            // Nothing is mutated — the node keeps its coordinate, its index and its peer set — and the
            // refusal is counted, because a silent one is indistinguishable from a `Reseat` that never
            // arrived. Nonzero here means a deployment combined an explicit roster with VRF coordinates,
            // which is a provisioning contradiction rather than a runtime fault.
            self.stations.record(Station::ReseatOutOfCell, Some(new_coord));
            return Vec::new();
        }
        self.self_index = seat;
        self.coord = new_pt;
        // Re-solve our Sybil-admission proof for the NEW `(coordinate, epoch)` (spec §L3), so a peer's
        // per-epoch admission check keeps passing as we reshuffle: seizing a coordinate costs a fresh PoW
        // *each epoch*, never a one-time grind (the "re-paid every epoch" cost of `anti_eclipse_reshuffle`).
        // `self.epoch` is already the new epoch here — the composite drives the overlay to the beacon epoch
        // before issuing this `Reseat`. Only when PoW admission is in use (`with_admission_pow`); cheap at a
        // modest difficulty, and deterministic (sans-I/O replay is preserved).
        if let Some(difficulty) = self.membership.paid_difficulty {
            self.membership.admission_proof =
                PowAdmission::new(difficulty).solve(&admission_challenge(&self.membership.identity, new_coord, self.epoch));
        }
        // Preserve the hierarchical DESCENT chain across the reshuffle (spec §L1): only the level-0 VRF
        // transport coordinate moves each epoch; the deeper sub-cell levels are identity-hash-derived
        // (`fanos_primitives::address_point`, epoch-INDEPENDENT), so a descended node keeps its sub-cell
        // placement. Resetting to a bare `root(new_pt)` here would silently drop a multi-level node's descent
        // chain every epoch (the depth-1 case is unchanged — its path is just `[new_pt]`). Learned peers ARE
        // cleared (via `Router::new`): every other node reshuffled too, so the transport-coord-keyed routing
        // table is stale and re-learns from the fresh `Announce`s below.
        let mut path: Vec<Point<F>> = self.router.address.points().to_vec();
        match path.first_mut() {
            Some(level0) => *level0 = new_pt,
            None => path.push(new_pt),
        }
        self.router = Router::new(new_pt);
        if let Some(addr) = HierAddr::from_path(path) {
            self.router.address = addr;
        }
        // Drop our now-stale self-entry at the old coordinate and re-announce at the new one (spec §7.8), so
        // the cell relearns our placement; then signal the reshuffle for the driver (rebuild HELLO) and the
        // simulator (re-key routing). The store, membership view of others, witnessed liveness, and epoch
        // are all preserved.
        let info = self.membership.members.remove(&old).unwrap_or_default();
        let mut effects = self.on_join(info);
        // Re-establish the liveness heartbeat at the new coordinate. A driver's heartbeat is not
        // coordinate-keyed, so this merely resets its interval; but under a coordinate-addressed transport
        // (the simulator) the timer armed at the OLD coordinate is now orphaned, so the reflex would fall
        // silent after a reshuffle without this — the node must keep pinging from its new placement.
        if self.heartbeating {
            effects.push(Effect::ArmTimer {
                token: HEARTBEAT,
                after: self.config.heartbeat,
            });
        }
        effects.push(Effect::Notify(Notification::Reseated {
            old,
            new: new_coord,
        }));
        effects
    }

    /// The current membership view (coordinate → announced info), for onion routing / observation.
    pub fn members(&self) -> impl Iterator<Item = (Triple, &[u8])> + '_ {
        self.membership
            .members
            .iter()
            .map(|(&c, i)| (c, i.as_slice()))
    }
}
