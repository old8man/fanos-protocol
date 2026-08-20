//! **Liveness sensing** for [`OverlayNode`] — the heartbeat reflex, the corroborated per-coordinate aliveness view, and
//! the loss/health snapshots the DIAKRISIS reflex diagnoses from (spec §6.4, §6.9). Split out of the facade's impl
//! (task 7a).
//!
//! This is the *sensing* half of the boundary [`crate::healer`] documents from the other side: the facade senses, the
//! reflex acts. Both halves being separately readable is the point — a sensor that also actuates is the shape that made
//! the original 4,000-line file hard to reason about.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_wire::FrameType;

use crate::frames::{
    encode, encode_diag_attest,
};
use crate::ports::{Effect, Instant, Notification};

use super::{
    HEARTBEAT, LOSS_EWMA_ALPHA,
    OverlayNode,
};


impl<F: Field> OverlayNode<F> {
    /// Whether `coord` is live, corroborated across its line-witnesses (spec §6.4). Our own direct
    /// observation is fully trusted; otherwise a **quorum** of distinct fresh witnesses is required,
    /// so a lossy link cannot forge a PeerDown *and* a lone Byzantine liar cannot forge liveness.
    pub(super) fn coord_alive(&self, coord: Triple, now: Instant) -> bool {
        let timeout = self.config.liveness_timeout;
        // Trust our own eyes first.
        if let Some(seen) = self.peers.get(&coord).and_then(|p| p.last_seen)
            && now.since(seen) <= timeout
        {
            return true;
        }
        // Otherwise: a quorum of distinct witnesses must vouch for it within the window.
        let fresh = self.witnessed.get(&coord).map_or(0, |witnesses| {
            witnesses
                .values()
                .filter(|&&seen| now.since(seen) <= timeout)
                .count()
        });
        if fresh >= self.config.corroboration_quorum {
            return true;
        }
        // Startup grace: if nothing has been observed about this peer yet, assume alive briefly.
        let unobserved = self.peers.get(&coord).and_then(|p| p.last_seen).is_none()
            && self.witnessed.get(&coord).is_none_or(BTreeMap::is_empty);
        unobserved && now.since(self.started_at) <= timeout
    }

    pub(super) fn on_heartbeat(&mut self, now: Instant) -> Vec<Effect> {
        let mut effects = Vec::new();
        let ping = encode(FrameType::Ping, &[]);
        // The points this node has evidence for, not every point of the plane — see `fan_out`. A ping to an
        // empty coordinate is not a liveness measurement, it is a signed relay through a hub aimed at
        // nobody, and at `q = 4` that was three quarters of every heartbeat.
        let neighbours: Vec<Triple> = self.sweep_targets();
        // §6.3 grey detection: fold last round's per-neighbour ping outcome into the loss EWMA, then mark this
        // round's ping outstanding (the loop below pings every neighbour). Done before building the gossip so
        // the `DiagLoss` row carries this round's fresh loss estimate.
        for coord in &neighbours {
            if let Some(peer) = self.peers.get_mut(coord) {
                let miss = f64::from(u8::from(peer.awaiting_pong));
                peer.loss = LOSS_EWMA_ALPHA * miss + (1.0 - LOSS_EWMA_ALPHA) * peer.loss;
                peer.awaiting_pong = true;
            }
        }
        // A health-view (how stale this node's direct observation of each cell point is), a polar
        // cross-attestation (its honest per-channel rate report for the 3 channels it mediates), and its
        // measured per-neighbour loss vector (§6.3 grey): all base-cell-only, read from the SAME snapshot this
        // window, so the three stay mutually consistent (spec §6.4, §6.8, §6.2, §6.3).
        let gossip_attest = self.cell_liveness(now).map(|(self_index, degraded, _)| {
            (
                encode(FrameType::DiagGossip, &self.health_view(now)),
                encode(
                    FrameType::DiagAttest,
                    &encode_diag_attest(self_index, degraded),
                ),
                encode(FrameType::DiagLoss, &self.loss_view()),
            )
        });
        // Detect newly-down peers (by the corroborated view), and (re-)ping + gossip everyone.
        for coord in neighbours {
            let alive = self.coord_alive(coord, now);
            if let Some(peer) = self.peers.get_mut(&coord)
                && !alive
                && !peer.reported_down
            {
                peer.reported_down = true;
                effects.push(Effect::Notify(Notification::PeerDown(coord)));
            }
            effects.push(Effect::Send {
                to: coord,
                frame: ping.clone(),
            });
            if let Some((gossip, attest, loss)) = &gossip_attest {
                effects.push(Effect::Send {
                    to: coord,
                    frame: gossip.clone(),
                });
                effects.push(Effect::Send {
                    to: coord,
                    frame: attest.clone(),
                });
                effects.push(Effect::Send {
                    to: coord,
                    frame: loss.clone(),
                });
            }
        }
        // Read repair: advance any Get whose current replica has gone silent past the read timeout.
        self.sweep_pending_gets(now, &mut effects);
        // Fold this window's relay activity into the behavioural coherence self-model.
        self.healer.sample_behavior::<F>(self.self_index);
        // Close the reflex loop (audit #122): having sensed this window (liveness, behaviour, and the
        // peers' gossiped attestations accumulated since the last beat), run DIAKRISIS diagnosis and
        // actuate any healing — every heartbeat. This makes the self-healing layer self-driving off the
        // engine's own cadence under ANY driver; before this it depended on a `Command::Diagnose` no
        // production driver ever sends, so a deployed node's namesake reflex (reroute/repair/quarantine/
        // decouple/escalate) was inert. `Command::Diagnose` remains for an out-of-band forced diagnosis.
        effects.extend(self.on_diagnose(now));
        effects.push(Effect::ArmTimer {
            token: HEARTBEAT,
            after: self.config.heartbeat,
        });
        effects
    }

    /// Encode this node's direct-observation ages over the Fano cell: `7 × u16` little-endian
    /// milliseconds since it last heard each point (`u16::MAX` = never / stale). Self reads `0`.
    pub(super) fn health_view(&self, now: Instant) -> Vec<u8> {
        let mut body = Vec::with_capacity(14);
        for i in 0..7usize {
            let coord = self.cell_coord(i);
            let age = if coord == self.coord.coords() {
                0
            } else {
                match self.peers.get(&coord).and_then(|p| p.last_seen) {
                    Some(seen) => {
                        (now.since(seen).as_nanos() / 1_000_000).min(u64::from(u16::MAX)) as u16
                    }
                    None => u16::MAX,
                }
            };
            body.extend_from_slice(&age.to_le_bytes());
        }
        body
    }

    /// This node's measured **per-neighbour loss** row (§6.3 grey), one `u8` per Fano point (`loss × 255`,
    /// saturating). Self reads `0`; a point this node does not neighbour reads `0` (no measurement). The body
    /// of the `DiagLoss` frame flooded each heartbeat.
    pub(super) fn loss_view(&self) -> Vec<u8> {
        let self_c = self.coord.coords();
        (0..7usize)
            .map(|i| {
                let coord = self.cell_coord(i);
                if coord == self_c {
                    0
                } else {
                    self.peers
                        .get(&coord)
                        .map_or(0, |p| (p.loss.clamp(0.0, 1.0) * 255.0) as u8)
                }
            })
            .collect()
    }

    /// Store witness `from`'s gossiped `DiagLoss` row — its measured loss toward each cell point — for the
    /// grey-detection matrix assembly ([`grey_rate_matrix`](Self::grey_rate_matrix)). Malformed (short) bodies
    /// are ignored.
    pub(super) fn apply_diag_loss(&mut self, now: Instant, from: Triple, body: &[u8]) {
        // Member-only, for the same reason and with the same effect as `apply_health_view`: the grey matrix
        // reads this for cell members alone, so a non-member's row is written, never read, and never
        // evicted. Filtering here is also what makes the field's own doc — "Bounded by the cell size" —
        // true rather than aspirational.
        if self.cell_position(from).is_none() {
            return;
        }
        if let Some(slice) = body.get(..7)
            && let Ok(row) = <[u8; 7]>::try_from(slice)
        {
            self.loss_reports.insert(from, (row, now));
        }
    }

    /// Fold witness `from`'s health-view into the corroborated `witnessed` map: for each cell point
    /// the gossip reports a fresh direct observation of, remember the freshest time *this witness*
    /// vouched for it. Keeping witnesses distinct is what makes the quorum Byzantine-robust — a lone
    /// liar is one entry, not a majority.
    pub(super) fn apply_health_view(&mut self, now: Instant, from: Triple, body: &[u8]) {
        // **Only a cell member may witness.** The count below is a Byzantine quorum sized against this
        // cell's fault budget `f`; drawing it from a set larger than the cell voids the sizing, because an
        // adversary would not need cell seats at all — any admitted coordinate anywhere would do, and the
        // vouch-fabricator judge that backs this up can only quarantine *members*. The readers already
        // apply exactly this predicate (`attested_pairwise_rates` and the grey matrix read only
        // `cell_coord(k)`, `k < 7`); the write was the looser half.
        if self.cell_position(from).is_none() {
            return;
        }
        for i in 0..7usize {
            let (Some(&lo), Some(&hi)) = (body.get(i * 2), body.get(i * 2 + 1)) else {
                break;
            };
            let age_ms = u16::from_le_bytes([lo, hi]);
            if age_ms == u16::MAX {
                continue; // the gossiper had no fresh observation of point i
            }
            let observed = Instant(now.as_nanos().saturating_sub(u64::from(age_ms) * 1_000_000));
            let coord = self.cell_coord(i);
            let slot = self
                .witnessed
                .entry(coord)
                .or_default()
                .entry(from)
                .or_insert(observed);
            if observed > *slot {
                *slot = observed;
            }
        }
    }
}
