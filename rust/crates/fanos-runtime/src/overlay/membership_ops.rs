//! **Joining, announcing, and moving** for [`OverlayNode`] — the JOIN/`Announce` flood, the epoch advance and agreement,
//! and the per-epoch re-seat that carries this node to a new coordinate (spec §7.8, §L3). Split out of the facade's impl
//! (task 7a).
//!
//! Distinct from [`crate::membership`], which holds the *view* these handlers write: this is the protocol that maintains
//! it. Keeping them apart is why the view could be lifted to a sibling module while these stay a child of the facade —
//! they touch the node's whole state, the view touches only its own.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_core::PowAdmission;
use fanos_field::Field;
use fanos_geometry::{HierAddr, Plane, Point, Triple};
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
                let required = self.membership.required_difficulty();
                return alloc::vec![Effect::Send {
                    to: coord,
                    frame: encode_error_with(
                        ProtocolError::SybilReject,
                        required.map(|bits| bits.to_le_bytes().to_vec()).unwrap_or_default(),
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
            return Vec::new();
        }
        // First sight only. A repeat must NOT overwrite the stored key bundle — otherwise any peer
        // could silently replace a member's advertised keys in our local view (and suppress the
        // re-flood, diverging the cell). Ignore repeats entirely; the monotone guard ends the flood.
        if self.membership.members.contains_key(&coord) {
            return Vec::new();
        }
        self.membership.members.insert(coord, info.clone());
        // Seed the hierarchical routing table: this overlay address is reachable via `coord`. A
        // descended sub-cell member thus becomes routable cell-wide from its announcement alone (§L1);
        // a depth-1 announcer adds its own direct entry, so `send_hier` also delivers within one plane.
        self.learn_hier_peer(hier.clone(), coord);
        let frame = encode(
            FrameType::Announce,
            &announce_body(coord, &hier, &id, &sig, &proof, &info),
        );
        let mut effects = self.flood(&frame);
        effects.push(Effect::Notify(Notification::MemberJoined { coord, info }));
        effects
    }

    /// `Command::AdvanceEpoch` — bump the epoch and flood the epoch-agreement gossip so the cell adopts
    /// it. This carries only the epoch ordinal ([`FrameType::EpochAgree`]), never randomness — under a
    /// live threshold-DVRF beacon the composite drives this from an authoritative `Beacon` round instead
    /// and suppresses the flood (audit #102).
    pub(super) fn on_advance_epoch(&mut self) -> Vec<Effect> {
        self.epoch = self.epoch.next();
        let mut effects = self.flood(&encode(FrameType::EpochAgree, &self.epoch.low32_be_bytes()));
        effects.push(Effect::Notify(Notification::EpochAdvanced(self.epoch)));
        effects
    }

    /// A received epoch-agreement gossip: adopt it iff strictly newer (monotone), then re-flood and
    /// notify. The 4-byte body is the epoch ordinal — see [`FrameType::EpochAgree`].
    pub(super) fn on_epoch_agree(&mut self, body: &[u8]) -> Vec<Effect> {
        let Some(bytes) = body.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
            return Vec::new();
        };
        let epoch = Epoch::from_low32_be_bytes(bytes);
        if epoch <= self.epoch {
            return Vec::new(); // not newer — drop (terminates the flood)
        }
        self.epoch = epoch;
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
        self.self_index = if Plane::<F>::N == 7 {
            (0..7).find(|&i| Point::<F>::at(i) == new_pt)
        } else {
            None
        };
        self.coord = new_pt;
        // Re-solve our Sybil-admission proof for the NEW `(coordinate, epoch)` (spec §L3), so a peer's
        // per-epoch admission check keeps passing as we reshuffle: seizing a coordinate costs a fresh PoW
        // *each epoch*, never a one-time grind (the "re-paid every epoch" cost of `anti_eclipse_reshuffle`).
        // `self.epoch` is already the new epoch here — the composite drives the overlay to the beacon epoch
        // before issuing this `Reseat`. Only when PoW admission is in use (`with_admission_pow`); cheap at a
        // modest difficulty, and deterministic (sans-I/O replay is preserved).
        if let Some(difficulty) = self.membership.admission_difficulty {
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
