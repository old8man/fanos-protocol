//! `IngressNode` — a deployed node that also **hosts POROS censorship-resistant ingress** (design
//! authority `docs/design-anonymity-substrate.md` §6).
//!
//! A community's ingress descriptor (its reachable entry peers) is threshold-hosted across an ingress
//! **line**: no member holds it whole, and a combiner gathers `>= t` descriptor shares before serving a
//! new node a bucket of entry peers ([`crate::poros`]). The per-member logic is the [`PorosHost`] engine.
//! This composite lets a line member run that role **alongside its ordinary cell role** — overlay, beacon,
//! and (optionally) the mixnet relay — at one coordinate, exactly as [`ServiceNode`](crate::service_node)
//! composes a threshold service and [`CellNode`](crate::cell_node) composes the relay.
//!
//! ## Why one engine
//!
//! The sans-I/O model spawns one engine per coordinate, so a member that both participates in the cell and
//! hosts ingress must **compose** the two, not co-host them. `IngressNode` wraps an arbitrary `inner` engine
//! (a bare overlay, an [`OverlayBeaconNode`](crate::overlay_beacon::OverlayBeaconNode), a full
//! [`CellNode`](crate::cell_node::CellNode), or even a [`ServiceNode`](crate::service_node::ServiceNode))
//! together with a [`PorosHost`], dispatching each input to exactly one of them.
//!
//! ## Frame routing
//!
//! The POROS host wire types — [`PorosRequest`](FrameType::PorosRequest) (a new node's admission request to
//! the combiner), [`PorosShareReq`](FrameType::PorosShareReq) (a combiner asking a member for its descriptor
//! share), [`PorosShare`](FrameType::PorosShare) (a member's share), and [`PorosReshare`](FrameType::PorosReshare)
//! (a sealed reshare sub-share when the line rotates) — go to the [`PorosHost`]; every other input goes to
//! `inner`. This takes precedence over the inner engine's routing. The [`PorosResponse`](FrameType::PorosResponse)
//! is delivered to the *requesting client*, never to a host, so it is intentionally **not** routed here (an
//! inner engine ignores it, as it would any unknown frame).
//!
//! ## Timer namespacing
//!
//! Both the inner engine and the host are timer-driven and both number their tokens from zero (the host's
//! first gather deadline is `0`), so their spaces would collide on the shared wire clock. The host's tokens
//! are remapped into a range provably free of every inner token — **and** of the `ServiceNode` token range,
//! so an ingress host may itself wrap a service node. The tag is bits 63 clear, 62 set, 61 clear, 60 set
//! (`0b0101`, `INGRESS_FLAG`): a wrapped `CellNode` uses gather ids `< 2^62` (bit 62 clear), `COVER =
//! 1<<62` and the overlay heartbeat `(1<<62)|1` (both bit 60 clear), and `MIX_FLAG | id` (bit 63 set); a
//! wrapped `ServiceNode` uses `0b011` (bit 61 set) — none match `0b0101`. A fired token is dispatched by
//! that tag: `(token >> 60) == 0b0101` → the host (unmapped back), everything else → the inner engine.

use fanos_core::roles::{CONTROL_LOAD_READING, Role, encode_load_reading};
use fanos_geometry::Triple;
use fanos_pqcrypto::HybridKemPublic;
use fanos_rendezvous::{BeaconSeed, Epoch};
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_wire::{FrameType, decode_frame};

use crate::poros::{PorosHost, RotationArmed};

/// The four-bit tag (bits 63,62,61,60) that marks a timer token as the ingress host's: bits 63 and 61 clear,
/// bits 62 and 60 set. Chosen disjoint from every token an inner cell engine or a [`ServiceNode`] emits (see
/// the module docs).
const INGRESS_TAG: u64 = 0b0101;
/// The ingress-token flag: [`INGRESS_TAG`] shifted into the top four bits.
const INGRESS_FLAG: u64 = INGRESS_TAG << 60;
/// The low 60 bits carrying the host's own (inner) token beneath the flag.
const INGRESS_SEQ_MASK: u64 = (1 << 60) - 1;

/// A cell node that also hosts POROS ingress: an arbitrary `inner` cell engine plus a [`PorosHost`], both at
/// this node's coordinate, as one engine (see the module docs).
pub struct IngressNode {
    inner: Box<dyn Engine + Send>,
    host: PorosHost,
}

impl IngressNode {
    /// Compose `inner` (the node's ordinary cell engine) with an ingress `host`, both at this coordinate, into
    /// one engine that hosts POROS ingress alongside the cell role.
    #[must_use]
    pub fn new(inner: Box<dyn Engine + Send>, host: PorosHost) -> Self {
        Self { inner, host }
    }

    /// The epoch the ingress host currently serves — advances when a rotation completes. A driver polls this
    /// after driving reshare frames to detect that this node has adopted the new line.
    #[must_use]
    pub fn host_epoch(&self) -> Epoch {
        self.host.epoch()
    }

    /// **Emit this node's reshare contributions** when it is a member of the *current* (old) ingress line — the
    /// old-side of a rotation to `target_epoch`. Returns one [`PorosReshare`](FrameType::PorosReshare) send per
    /// new member, each sub-share KEM-sealed to it (`new_keys` in `new_line` order, resolved by the driver from
    /// the directory). A no-op (empty) if this node is not a current old-line host. The driver calls this only
    /// for nodes it has determined are on the old line (via `ingress_line(community, old_epoch, beacon)`).
    #[must_use]
    pub fn emit_reshares(
        &self,
        target_epoch: Epoch,
        new_line: &[Triple],
        new_keys: &[HybridKemPublic],
        key_randomness: &[u8],
        kem_seed: &[u8],
    ) -> Vec<Effect> {
        let key_refs: Vec<&HybridKemPublic> = new_keys.iter().collect();
        self.host.emit_reshare(target_epoch, new_line, &key_refs, key_randomness, kem_seed)
    }

    /// **Arm the receive side** of a rotation when this node is a member of the *new* (incoming) ingress line
    /// for `target_epoch`, receiving from the outgoing `old_line`: subsequent
    /// [`PorosReshare`](FrameType::PorosReshare) frames are **authenticated to their old member**, opened,
    /// gathered, and combined into this node's rotated share, which it adopts once a threshold arrive (advancing
    /// [`host_epoch`](Self::host_epoch)). A no-op if this node is not on `new_line`. The old-emit
    /// ([`emit_reshares`](Self::emit_reshares)) and this new-receive role are independent — a node on both lines
    /// (they meet in one point) calls both. `old_line` is the current-epoch roster the driver computed from the
    /// beacon; a sub-share claiming old index `x` must have arrived from `old_line[x-1]`.
    pub fn arm_rotation(
        &mut self,
        target_epoch: Epoch,
        new_line: Vec<Triple>,
        old_line: Vec<Triple>,
    ) -> RotationArmed {
        self.host.begin_rotation(target_epoch, new_line, old_line)
    }

    /// **Arm the receive side of a rotation from the cell's own epoch clock.**
    ///
    /// Watches the inner engine's effects for a `BeaconReady`, exactly as `OverlayBeaconNode` watches the
    /// beacon to drive the overlay's epoch, and arms the host for the incoming line. This half needs **no
    /// I/O**: both rosters are a pure function of `(community, epoch, beacon)`, so a node that will be on the
    /// next epoch's line can prepare to receive its rotated share without asking anyone anything.
    ///
    /// The *emit* half is not here and cannot be: sealing a sub-share needs each new member's KEM public,
    /// which lives in the directory. That asymmetry is the whole of why an ingress line does not yet rotate
    /// on its own — a driver has to supply those keys.
    fn arm_from_beacon(&mut self, effects: &[Effect]) {
        let ready = effects.iter().find_map(|e| match e {
            Effect::Notify(Notification::BeaconReady { epoch, seed }) => Some((*epoch, *seed)),
            _ => None,
        });
        let Some((epoch, seed)) = ready else { return };
        if epoch <= self.host.epoch() {
            return; // not a rotation: the clock has not moved past the epoch this host serves
        }
        let (old_line, new_line) = self.host.rotation_rosters(epoch, &BeaconSeed::new(seed));
        // The outcome is decided here rather than returned, because this path is driven by the beacon and has
        // no caller to hand it to. `NotOnNewLine` is the ordinary case for most members every epoch and says
        // nothing; `NoContributorSubset` means the community has drifted below the threshold its line was
        // dealt at, so the line will stop serving when the current share expires — the station records it and
        // the log names it, because an operator's answer is to re-deal rather than to wait (#243).
        match self.host.begin_rotation(epoch, new_line, old_line) {
            RotationArmed::Armed | RotationArmed::NotOnNewLine => {}
            RotationArmed::NoContributorSubset => {
                tracing::warn!(
                    ?epoch,
                    "poros: the outgoing line admits no valid contributor subset — this rotation arms nothing \
                     and the line stops serving when its current share expires; re-deal the line"
                );
            }
        }
    }

    /// Whether `frame` is one of the POROS host wire types the [`PorosHost`] owns (the combiner/member frames,
    /// not the client-bound [`PorosResponse`](FrameType::PorosResponse)).
    fn is_ingress_frame(frame: &[u8]) -> bool {
        matches!(
            decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
            Some(
                FrameType::PorosRequest
                    | FrameType::PorosShareReq
                    | FrameType::PorosShare
                    | FrameType::PorosReshare
            )
        )
    }

    /// Remap the host's outbound timer tokens into the [`INGRESS_FLAG`] range so they never collide with an
    /// inner-engine token; every other effect passes through untouched.
    fn tag_host_effects(effects: Vec<Effect>) -> Vec<Effect> {
        effects
            .into_iter()
            .map(|e| match e {
                Effect::ArmTimer { token, after } => Effect::ArmTimer {
                    token: TimerToken(INGRESS_FLAG | (token.0 & INGRESS_SEQ_MASK)),
                    after,
                },
                other => other,
            })
            .collect()
    }
}

impl Engine for IngressNode {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // A POROS host frame is the host's; every other frame is the inner engine's.
            Input::Message { .. } => {
                let to_host =
                    matches!(&input, Input::Message { frame, .. } if Self::is_ingress_frame(frame));
                if to_host {
                    Self::tag_host_effects(self.host.step(now, input))
                } else {
                    let effects = self.inner.step(now, input);
                    self.arm_from_beacon(&effects);
                    effects
                }
            }
            // An ingress-tagged timer fires: hand the host its own (unmapped) token.
            Input::Timer(token) if (token.0 >> 60) == INGRESS_TAG => {
                let inner = Input::Timer(TimerToken(token.0 & INGRESS_SEQ_MASK));
                Self::tag_host_effects(self.host.step(now, inner))
            }
            // Every other timer is the inner engine's; and the host is purely frame/timer-driven, so every
            // command drives the inner cell engine too.
            // **The rotation instruction** — the driver hands the host the incoming line's KEM publics and
            // the entropy to seal with, both of which a sans-I/O engine cannot obtain, and the host emits
            // its sealed sub-shares. Intercepted before the inner engine, because it names this composite's
            // own host and nothing below it would recognise the tag.
            Input::Command(Command::Control { tag, ref body })
                if tag == crate::ingressdir::CONTROL_INGRESS_ROTATION =>
            {
                let Some(r) = crate::ingressdir::decode_rotation(body) else {
                    return Vec::new();
                };
                let refs: Vec<&HybridKemPublic> = r.keys.iter().collect();
                Self::tag_host_effects(self.host.emit_reshare(
                    r.target_epoch, &r.new_line, &refs, &r.key_randomness, &r.kem_seed,
                ))
            }
            // An observation is where this composite reports the one role only *it* can see: the admission
            // requests this member is currently gathering for. Without it the ingress role falls back to the
            // node's own offer — supply standing in for demand on a host that knows what it is carrying.
            //
            // A **level**, not a rate, measured against the bound the host's own admission rule enforces
            // (`DEFAULT_MAX_PENDING`), so the numerator and the denominator count the same objects and no
            // observation window has to be reconciled with anyone else's.
            //
            // Routed as a `Control` command for `ServiceNode`'s reason: `inner` is a `dyn Engine`, so the type
            // that would let this call `observe_load` directly is erased by the composition. `Control` never
            // arrives off the wire, so no peer can forge a load reading.
            Input::Command(Command::Diagnose) => {
                let carried = u16::try_from(self.host.pending()).unwrap_or(u16::MAX);
                let reading = encode_load_reading(Role::Ingress, carried).to_vec();
                let mut out = self.inner.step(
                    now,
                    Input::Command(Command::Control { tag: CONTROL_LOAD_READING, body: reading }),
                );
                let effects = self.inner.step(now, input);
                self.arm_from_beacon(&effects);
                out.extend(effects);
                out
            }
            Input::Timer(_) | Input::Command(_) => {
                let effects = self.inner.step(now, input);
                self.arm_from_beacon(&effects);
                effects
            }
        }
    }

    fn address(&self) -> Triple {
        self.inner.address()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::net::SocketAddr;

    use fanos_field::F2;
    use fanos_geometry::Point;
    use fanos_rendezvous::{BeaconSeed, Epoch};
    use fanos_calypso::hosting::Share;
    use fanos_runtime::{Command, Config as OverlayConfig, OverlayNode};
    use fanos_wire::decode_frame;

    use super::*;
    use crate::config::Peer;
    use crate::poros::{IngressDescriptor, request_frame, shard_descriptor, solve_ingress_request, Sybil};

    const COMMUNITY: &[u8] = b"ingress-community";
    const EPOCH: Epoch = Epoch::new(1);
    const DIFFICULTY: u32 = 4;

    fn descriptor(n: usize) -> IngressDescriptor {
        IngressDescriptor {
            peers: (0..n)
                .map(|i| Peer {
                    coord: Point::<F2>::at(i % 7).coords(),
                    addr: SocketAddr::from(([10, 0, 0, i as u8], 9000 + i as u16)),
                })
                .collect(),
        }
    }

    /// A solo (1-of-1) ingress line so a single `IngressNode` is its own combiner and serves a bucket alone —
    /// enough to prove the composite dispatches POROS frames to the host and overlay frames to the inner engine.
    fn solo_ingress_node(seed: u8) -> (IngressNode, BeaconSeed) {
        let coord = Point::<F2>::at(0).coords();
        let beacon = BeaconSeed::new([seed; 32]);
        let desc = descriptor(6);
        let randomness = vec![0x33u8; desc.to_bytes().len() + 8];
        let dealt = shard_descriptor(&desc, 1, 1, &randomness).unwrap();
        let host = PorosHost::new(
            coord,
            dealt.shares[0].clone(),
            dealt.binding.clone(),
            vec![coord],
            1,
            COMMUNITY.to_vec(),
            EPOCH,
            beacon,
            DIFFICULTY,
                Sybil::Uncapped,
            );
        let overlay = OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
        (IngressNode::new(Box::new(overlay), host), beacon)
    }

    #[test]
    fn an_ingress_node_serves_a_request_and_still_runs_the_overlay() {
        let (mut node, beacon) = solo_ingress_node(0x21);

        // An overlay command reaches the inner engine: StartHeartbeat arms the overlay's heartbeat timer.
        let started = node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        assert!(
            started.iter().any(|e| matches!(e, Effect::ArmTimer { .. })),
            "the inner overlay armed its heartbeat — the composite delivered the command to it"
        );

        // A POROS frame reaches the host: a 1-of-1 line serves the (valid-PoW) request at once, sending the
        // requester a PorosResponse bucket. The overlay never sees the ingress frame.
        let requester = Point::<F2>::at(3).coords();
        let req = solve_ingress_request(requester, COMMUNITY, EPOCH, &beacon, DIFFICULTY);
        let served = node.step(Instant(1), Input::Message { from: requester, frame: request_frame(&req) });
        assert!(
            served.iter().any(|e| matches!(
                e,
                Effect::Send { to, frame }
                    if *to == requester
                        && decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()) == Some(FrameType::PorosResponse)
            )),
            "the composite routed the request to the POROS host, which served a PorosResponse bucket"
        );
        // Any timer the host armed rode out under the ingress tag, disjoint from every inner-engine token.
        for e in &served {
            if let Effect::ArmTimer { token, .. } = e {
                assert_eq!(token.0 >> 60, INGRESS_TAG, "a host timer is ingress-tagged");
            }
        }
    }

    #[test]
    fn an_ingress_gather_timer_is_tagged_and_routes_back_to_the_host() {
        // A 2-of-2 line cannot serve from the combiner alone, so the request stays pending behind a gather
        // deadline — armed under the ingress tag, and firing it must reach the host (dropping the pending
        // gather), never the inner overlay.
        let coord = Point::<F2>::at(0).coords();
        let other = Point::<F2>::at(1).coords();
        let beacon = BeaconSeed::new([0x44; 32]);
        let desc = descriptor(6);
        let randomness = vec![0x9u8; desc.to_bytes().len() + 8];
        let dealt = shard_descriptor(&desc, 2, 2, &randomness).unwrap();
        let host = PorosHost::new(
            coord,
            dealt.shares[0].clone(),
            dealt.binding.clone(),
            vec![coord, other],
            2,
            COMMUNITY.to_vec(),
            EPOCH,
            beacon,
            DIFFICULTY,
                Sybil::Uncapped,
            );
        let overlay = OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
        let mut node = IngressNode::new(Box::new(overlay), host);

        let requester = Point::<F2>::at(4).coords();
        let req = solve_ingress_request(requester, COMMUNITY, EPOCH, &beacon, DIFFICULTY);
        let effects = node.step(Instant(0), Input::Message { from: requester, frame: request_frame(&req) });
        let armed = effects
            .iter()
            .find_map(|e| match e {
                Effect::ArmTimer { token, .. } => Some(*token),
                _ => None,
            })
            .expect("the pending gather armed a deadline timer");
        assert_eq!(
            armed.0 >> 60,
            INGRESS_TAG,
            "the gather deadline is armed under the ingress tag, disjoint from inner-engine tokens"
        );

        // Firing that tagged token reaches the host (the pending gather is dropped): the same request is then
        // treated as fresh (accepted, re-arming a gather) rather than suppressed as a pending duplicate.
        assert!(node.step(Instant(1), Input::Timer(armed)).is_empty());
        let refired = node.step(Instant(2), Input::Message { from: requester, frame: request_frame(&req) });
        assert!(
            refired.iter().any(|e| matches!(e, Effect::ArmTimer { .. })),
            "after the deadline dropped the gather, the same request is accepted anew — the tick reached the \
             host, not the overlay"
        );
    }

    /// **The load the overlay cannot see, and the reading has to move.**
    ///
    /// `Role::Ingress` was the last role dividing by a placeholder capacity, described as "a bound with no
    /// sensor". The sensor existed — `PorosHost::pending` — and nothing read it, so this is the wiring plus
    /// the proof it measures something: a 2-of-2 line cannot serve from the combiner alone, so one admission
    /// request stays gathering, and the level must follow it up and back down again when the deadline drops
    /// it. Asserting only the idle `Some(0)` would have pinned the hand-off and not the quantity.
    #[test]
    fn an_ingress_node_reports_the_admission_load_the_overlay_cannot_see() {
        let coord = Point::<F2>::at(0).coords();
        let other = Point::<F2>::at(1).coords();
        let beacon = BeaconSeed::new([0x44; 32]);
        let desc = descriptor(6);
        let randomness = vec![0x9u8; desc.to_bytes().len() + 8];
        let dealt = shard_descriptor(&desc, 2, 2, &randomness).unwrap();
        let host = PorosHost::new(
            coord,
            dealt.shares[0].clone(),
            dealt.binding.clone(),
            vec![coord, other],
            2,
            COMMUNITY.to_vec(),
            EPOCH,
            beacon,
            DIFFICULTY,
            Sybil::Uncapped,
        );
        let overlay = OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
        let mut node = IngressNode::new(Box::new(overlay), host);

        let read = |node: &mut IngressNode, at: Instant| {
            node.step(at, Input::Command(Command::Diagnose))
                .iter()
                .find_map(|e| match e {
                    Effect::Notify(Notification::LoadReport { per_role }) => {
                        Some(fanos_core::roles::RoleReading::from_array(*per_role).of(Role::Ingress))
                    }
                    _ => None,
                })
                .expect("an observation reports the load it measured")
        };

        assert_eq!(
            read(&mut node, Instant(0)),
            Some(0),
            "an ingress point gathering nothing measured zero — it is not unsensed, which is what would put \
             its own offer back in place of a measurement"
        );

        let requester = Point::<F2>::at(4).coords();
        let req = solve_ingress_request(requester, COMMUNITY, EPOCH, &beacon, DIFFICULTY);
        let armed = node
            .step(Instant(1), Input::Message { from: requester, frame: request_frame(&req) })
            .iter()
            .find_map(|e| match e {
                Effect::ArmTimer { token, .. } => Some(*token),
                _ => None,
            })
            .expect("a 2-of-2 line leaves the request gathering behind a deadline");
        assert_eq!(read(&mut node, Instant(2)), Some(1), "one request gathering is one unit of load");

        node.step(Instant(3), Input::Timer(armed));
        assert_eq!(
            read(&mut node, Instant(4)),
            Some(0),
            "and it goes back down: the deadline dropped the gather, so the node is carrying nothing again"
        );
    }

    #[test]
    fn a_cell_rotates_its_ingress_line_and_the_new_line_serves_requests() {
        use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};

        use crate::poros::{IngressResponse, PorosHost};

        // The end-to-end wiring proof: a full old ingress line rotates to a new epoch line through IngressNode
        // composites (via `rotate`), and the NEW line then SERVES an ingress request — which can only succeed if
        // the descriptor was correctly reshared into the new hosts. Nothing reconstructs the descriptor in the
        // clear; the new hosts hold only rotated shares, and a threshold gather serves each request.
        let community = COMMUNITY.to_vec();
        let beacon = BeaconSeed::new([0x71; 32]);
        let (old_epoch, new_epoch) = (Epoch::new(1), Epoch::new(2));
        let (t, difficulty) = (2usize, DIFFICULTY);
        let desc = descriptor(6);
        let secret_len = desc.to_bytes().len();
        let old_coords: Vec<Triple> = (0..3).map(|i| Point::<F2>::at(i).coords()).collect();
        let new_idx = [3usize, 4, 5];
        let new_coords: Vec<Triple> = new_idx.iter().map(|&i| Point::<F2>::at(i).coords()).collect();
        let dealt =
            shard_descriptor(&desc, t as u8, 3, &vec![0x5Au8; secret_len * (t - 1) + 8]).unwrap();
        let (shares, binding) = (dealt.shares, dealt.binding);

        // Old-line IngressNodes (host + overlay), each holding its real descriptor share.
        let old_node = |i: usize| {
            let host = PorosHost::new(
                old_coords[i], shares[i].clone(), binding.clone(), old_coords.clone(), t, community.clone(), old_epoch, beacon, difficulty,
                Sybil::Uncapped,
            );
            let overlay = OverlayNode::<F2>::new(Point::<F2>::at(i), OverlayConfig::default());
            IngressNode::new(Box::new(overlay), host)
        };
        // New-line IngressNodes: placeholder share (rotation replaces it) + KEM secret (to open sealed sub-shares).
        let new_kp: Vec<(HybridKemSecret, HybridKemPublic)> =
            (0..3).map(|j| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xB1, j as u8]))).collect();
        let new_keys: Vec<HybridKemPublic> = new_kp.iter().map(|(_, p)| p.clone()).collect();
        let mut new_nodes: Vec<IngressNode> = (0..3)
            .map(|j| {
                let placeholder = Share::new(u8::try_from(j + 1).unwrap(), vec![0u8; secret_len]);
                let host = PorosHost::new(
                    new_coords[j], placeholder, binding.clone(), new_coords.clone(), t, community.clone(), old_epoch, beacon, difficulty,
                Sybil::Uncapped,
            )
                .with_kem_secret(HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xB1, j as u8])).0);
                let overlay = OverlayNode::<F2>::new(Point::<F2>::at(new_idx[j]), OverlayConfig::default());
                IngressNode::new(Box::new(overlay), host)
            })
            .collect();

        // New-line members arm their receive side (the driver would call this for every node it computes is on
        // the new line for target_epoch), passing the OLD roster so each sub-share is authenticated to its old
        // member.
        for n in &mut new_nodes {
            let _ = n.arm_rotation(new_epoch, new_coords.clone(), old_coords.clone());
        }
        // **Every** outgoing member emits, because that is what production does — `spawn_ingress_rotation`
        // says "Only an OUTGOING member emits" and all `n` of them are outgoing. Collect first and deliver
        // second, so each new member can be handed the contributions in a *different* order.
        let mut inbox: Vec<Vec<(Triple, Vec<u8>)>> = vec![Vec::new(); new_coords.len()];
        for (i, &from) in old_coords.iter().enumerate() {
            let key_rnd = vec![0x20u8 + i as u8; secret_len * (t - 1) + 8];
            let frames = old_node(i).emit_reshares(new_epoch, &new_coords, &new_keys, &key_rnd, &[0xC0, i as u8]);
            assert_eq!(frames.len(), new_coords.len(), "one reshare frame per new member");
            for e in frames {
                if let Effect::Send { to, frame } = e {
                    let j = new_coords.iter().position(|c| *c == to).unwrap();
                    inbox[j].push((from, frame));
                }
            }
        }
        // **The arrival race, made deterministic.** Member `j` sees the contributions rotated by `j`, so the
        // first two to reach each member are `{1,2}`, `{2,3}`, `{3,1}` — three *different* subsets. An engine
        // that combined whoever answered first would put the three members on three different polynomials
        // (they agree only at 0), and the SERVE below could not succeed; the earlier form of this test emitted
        // from exactly `t` members, which made the subset unique by construction and could never see it.
        for (j, mut msgs) in inbox.into_iter().enumerate() {
            msgs.rotate_left(j % old_coords.len());
            for (from, frame) in msgs {
                new_nodes[j].step(Instant(0), Input::Message { from, frame });
            }
        }
        // Every new node adopted the new epoch (the composite exposed it via `host_epoch`).
        for n in &new_nodes {
            assert_eq!(n.host_epoch(), new_epoch, "the new-line composite rotated to the new epoch");
        }

        // The new line now SERVES a request: a requester solves a PoW bound to the NEW epoch, contacts new
        // combiner 0, which gathers a threshold of rotated shares across the new line and returns a bucket.
        let requester = Point::<F2>::at(6).coords();
        let req = solve_ingress_request(requester, &community, new_epoch, &beacon, difficulty);
        let fanned = new_nodes[0].step(Instant(1), Input::Message { from: requester, frame: request_frame(&req) });
        // Route the combiner's PorosShareReq fan-out to new members 1 and 2, collect their PorosShare replies.
        let mut response: Option<Vec<u8>> = None;
        for e in fanned {
            if let Effect::Send { to, frame } = e
                && let Some(j) = new_coords.iter().position(|c| *c == to)
            {
                for reply in new_nodes[j].step(Instant(2), Input::Message { from: new_coords[0], frame }) {
                    if let Effect::Send { to: back, frame: share_frame } = reply
                        && back == new_coords[0]
                    {
                        for served in new_nodes[0].step(Instant(3), Input::Message { from: to, frame: share_frame }) {
                            if let Effect::Send { to: r, frame: resp } = served
                                && r == requester
                                && decode_frame(&resp).ok().and_then(|(f, _)| f.frame_type())
                                    == Some(FrameType::PorosResponse)
                            {
                                response = Some(resp);
                            }
                        }
                    }
                }
            }
        }
        let resp = response.expect("the rotated new line served a PorosResponse");
        let (decoded, _) = decode_frame(&resp).unwrap();
        let bucket = IngressResponse::from_bytes(decoded.body).expect("a valid response bucket");
        assert!(!bucket.peers.is_empty(), "the served bucket holds entry peers — the descriptor survived rotation");
        // Every served peer is a genuine descriptor entry (the reshared descriptor is the original).
        for p in &bucket.peers {
            assert!(desc.peers.iter().any(|d| d.coord == p.coord), "served peers come from the original descriptor");
        }
    }

    #[test]
    fn the_cells_own_beacon_arms_the_ingress_rotation_with_no_lookup() {
        use fanos_pqcrypto::{HybridKemSecret, SeedRng};
        use fanos_runtime::Notification;
        // An inner engine that emits a BeaconReady when told to advance — the shape `OverlayBeaconNode`
        // produces on the real path, reduced to the one effect this composite reacts to.
        struct Clock {
            coord: Triple,
            epoch: u64,
        }
        impl Engine for Clock {
            fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
                match input {
                    Input::Command(Command::AdvanceEpoch) => {
                        self.epoch += 1;
                        vec![Effect::Notify(Notification::BeaconReady {
                            epoch: Epoch::new(self.epoch),
                            seed: [0x31; 32],
                        })]
                    }
                    _ => Vec::new(),
                }
            }
            fn address(&self) -> Triple {
                self.coord
            }
        }


        use crate::poros::{PorosHost, shard_descriptor};

        // **Half of a rotation needs nothing from anyone.** Both rosters are a pure function of
        // `(community, epoch, beacon)`, so a host that will sit on next epoch's line can arm itself to
        // receive its rotated share the moment the cell's clock moves — no directory, no round trip. This
        // pins that the composite actually does it, because `arm_rotation` had no caller at all and a line
        // that never rotates forfeits the moving-target property the whole §6 derivation rests on.
        let coord = Point::<F2>::at(0).coords();
        let desc = descriptor(4);
        let (t, n) = (2u8, 3u8);
        let randomness = vec![0x6Bu8; desc.to_bytes().len() * usize::from(t) + 32];
        let dealt = shard_descriptor(&desc, t, n, &randomness).unwrap();
        let line: Vec<Triple> = (0..3).map(|i| Point::<F2>::at(i).coords()).collect();
        let (secret, _public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x5A; 2]));
        let host = PorosHost::new(
            coord,
            dealt.shares[0].clone(),
            dealt.binding.clone(),
            line.clone(),
            usize::from(t),
            COMMUNITY.to_vec(),
            EPOCH,
            BeaconSeed::new([0x31; 32]),
            DIFFICULTY,
                Sybil::Uncapped,
            )
        .with_kem_secret(secret);

        let mut node = IngressNode::new(Box::new(Clock { coord, epoch: EPOCH.get() }), host);
        assert_eq!(node.host.rotating_into(), None, "no rotation before the clock moves");

        // Arming is CONDITIONAL, and that condition is the property worth pinning: a host prepares to receive
        // a rotated share exactly when the incoming line passes through its own point, and stays inert
        // otherwise. Anything else would have every node in the cell gathering sub-shares for lines it is not
        // on. So walk the clock and check the composite's decision against the geometry directly.
        let beacon = BeaconSeed::new([0x31; 32]);
        let mut armed_at = Vec::new();
        let mut on_line_at = Vec::new();
        // The clock's epoch, not the host's: a host only advances its own when a rotation COMPLETES, and
        // nothing here delivers sub-shares, so reading `host.epoch()` would test the same target twelve times
        // — which is exactly what the first version of this test did, and why it reported no eligible epoch.
        let mut clock = EPOCH;
        for _ in 0..12 {
            node.step(Instant(0), Input::Command(Command::AdvanceEpoch));
            clock = clock.next();
            let target = clock;
            let members = fanos_rendezvous::line_member_coords::<F2>(
                crate::poros::ingress_line::<F2>(COMMUNITY, target, &beacon).coords(),
            );
            if members.contains(&coord) {
                on_line_at.push(target);
            }
            if node.host.rotating_into() == Some(target) {
                armed_at.push(target);
            }
        }
        assert!(
            !on_line_at.is_empty(),
            "the fixture must reach at least one epoch whose ingress line passes through this host, or the \
             test proves nothing",
        );
        assert_eq!(
            armed_at, on_line_at,
            "the composite must arm exactly on the epochs whose incoming line contains this host — the cell's \
             own beacon is the only thing that was ever going to call `arm_rotation`, and it must not arm a \
             node for a line it is not on",
        );
    }

    #[test]
    fn a_driver_supplied_rotation_makes_the_line_emit_its_sealed_reshares() {
        use fanos_pqcrypto::HybridKemPublic;

        use crate::ingressdir::{CONTROL_INGRESS_ROTATION, encode_rotation, ingress_keypair};
        use crate::poros::{PorosHost, shard_descriptor};

        // **The half a sans-I/O engine cannot do alone, and could not do at all until now.** Emitting a
        // reshare needs every INCOMING member's KEM public — those live at other nodes, the engine cannot
        // look anything up, and no slot published them, so `emit_reshares` had no caller and a dealt ingress
        // line served the epoch it was provisioned for and stayed there. `ingressdir` publishes the keys and
        // the driver hands them in over `Control`, which is local by construction: a peer cannot inject a
        // rotation and talk a line into resharing a community's descriptor to a roster of its choosing.
        let coord = Point::<F2>::at(0).coords();
        let desc = descriptor(4);
        let (t, n) = (2u8, 3u8);
        let secret_len = desc.to_bytes().len();
        let randomness = vec![0x7Cu8; secret_len * usize::from(t) + 32];
        let dealt = shard_descriptor(&desc, t, n, &randomness).unwrap();
        let old_line: Vec<Triple> = (0..3).map(|i| Point::<F2>::at(i).coords()).collect();
        let new_line: Vec<Triple> = (3..6).map(|i| Point::<F2>::at(i).coords()).collect();

        let host = PorosHost::new(
            coord,
            dealt.shares[0].clone(),
            dealt.binding.clone(),
            old_line.clone(),
            usize::from(t),
            COMMUNITY.to_vec(),
            EPOCH,
            BeaconSeed::new([0x2A; 32]),
            DIFFICULTY,
                Sybil::Uncapped,
            );
        let overlay = OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
        let mut node = IngressNode::new(Box::new(overlay), host);

        // The incoming line's members publish stable KEM publics; the driver would resolve these from the
        // store. Stable, not ratcheting: a rotation seals for a FUTURE epoch and its recipient must still be
        // able to open it after the turn, which a forward-secure mix key could not.
        let keys: Vec<HybridKemPublic> =
            (0..3).map(|j| ingress_keypair(&[0x3B + j as u8; 32]).1).collect();
        let body = encode_rotation(
            EPOCH.next(),
            &new_line,
            &keys,
            &vec![0x5Fu8; secret_len * usize::from(t) + 32],
            &[0x6E; 32],
        );

        let effects = node.step(Instant(0), Input::Command(Command::Control {
            tag: CONTROL_INGRESS_ROTATION,
            body,
        }));
        let sends: Vec<Triple> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Send { to, .. } => Some(*to),
                _ => None,
            })
            .collect();
        assert_eq!(
            sends, new_line,
            "an outgoing member must emit one sealed sub-share per INCOMING member, in roster order — one \
             short and the new line is below threshold, which is a line that looks provisioned and admits \
             nobody",
        );

        // A malformed instruction is refused rather than half-applied: it arrives over a local channel, so
        // this is a programming-error guard, but a partial rotation is worse than none.
        assert!(
            node.step(Instant(1), Input::Command(Command::Control {
                tag: CONTROL_INGRESS_ROTATION,
                body: vec![0xFF; 3],
            }))
            .is_empty(),
            "a malformed rotation emits nothing",
        );

    }
}
