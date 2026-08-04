//! **Content storage and retrieval** for [`OverlayNode`] — the `Put`/`Get`/`Publish`/`Lookup`/`Value` handlers, erasure
//! shard distribution, DA sampling, and the consistent-hashing resolution that decides which occupied point owns a key
//! (spec §L4). Split out of the facade's impl (task 7a).
//!
//! A child module, so it reaches `OverlayNode`'s private state directly — the split costs no field visibility. What stays
//! in the facade is dispatch (`on_message`) and the state itself; this is what the node *does* with a key.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use fanos_code::{da, erasure, lrc};
use fanos_field::Field;
use fanos_geometry::{Point, Triple, fano};
use fanos_wire::{FrameType, Wire};

use crate::frames::{
    LookupBody, encode,
    encode_lookup, encode_publish, encode_value, fold_seed, parse_digest, parse_u64,
};
use crate::ports::{Effect, Instant, Notification};
use crate::store::{PendingGet, PendingSample};

use super::{
    ContentPoint, DA_SAMPLES, DIGEST, MAX_PENDING_GETS, MAX_READ_VERSIONS, MAX_VALUE_LEN,
    OverlayNode, PUBLISH_ORIGIN, PUBLISH_SHARD, reconstruct_highest, storage_digest,
    storage_point,
};


/// How many peers beyond the erasure threshold `K` a read asks even at full stress.
///
/// One. At width exactly `K` a single silent holder turns the read into a second round, which costs more than
/// the message the narrower fan-out saved — so the margin is not caution, it is the cheaper arithmetic. Larger
/// margins buy less: the second non-responder is already much rarer than the first.
const READ_FANOUT_MARGIN: usize = 1;

impl<F: Field> OverlayNode<F> {
    /// Account a permanent data loss (audit R-C3) for `digest` at a read's `Retrieved(None)` conclusion: if
    /// this node PROVABLY held a shard of it (so the value was stored) **and** the down shard-homes form a
    /// stopping set the `[7,3,4]` code cannot tolerate — so the corroborated-alive points can no longer
    /// reconstruct it — record it in the durable [`loss_ledger`] and emit [`Notification::DataLost`]. This
    /// turns silent permanent loss into accounted, visible loss.
    ///
    /// Timing-safe and R-H1-immune: it keys off the **corroborated-liveness** `degraded` mask (spec §6.4), not
    /// response latency or the append-only membership set — a slow peer never triggers a false loss, and a
    /// crashed peer that lingers in `members` is still counted down. Base `N = 7` cell only (where the code
    /// lives); off it the fine-grained placement is out of scope. Idempotent per key (the ledger is append-only).
    pub(super) fn account_data_loss(&mut self, now: Instant, digest: [u8; DIGEST], effects: &mut Vec<Effect>) {
        if !self.store.entries.contains_key(&digest) || self.store.loss_ledger.contains_key(&digest) {
            return; // never held a shard (cannot attest the key was stored), or already accounted
        }
        // The shard-homes that are down (not corroborated-alive). If they form a stopping set the [7,3,4] code
        // cannot recover, the value is gone for good — no future read completes.
        let Some((_, degraded, _)) = self.cell_liveness(now) else {
            return; // off the base Fano cell — not this layer's placement domain
        };
        if !lrc::is_recoverable_fano(degraded) {
            let epoch = self.epoch();
            self.store.loss_ledger.insert(digest, epoch);
            effects.push(Effect::Notify(Notification::DataLost { key: digest, epoch }));
        }
    }

    /// Conclude reads that have not assembled a reconstructable shard-set within `read_timeout` as
    /// `Retrieved(None)` (spec §L4). Under erasure the read fans out to every shard home at once, so a
    /// timeout means too few shards came back to recover the value (enough nodes down / withholding, or the
    /// key was never stored) — there is no further replica to walk. A held key whose live shard-homes can no
    /// longer reconstruct is additionally accounted a permanent loss ([`account_data_loss`], R-C3).
    pub(super) fn sweep_pending_gets(&mut self, now: Instant, effects: &mut Vec<Effect>) {
        let timeout = self.config.read_timeout;
        let stale: Vec<[u8; DIGEST]> = self
            .store
            .pending
            .iter()
            .filter(|(_, p)| now.since(p.issued) > timeout)
            .map(|(digest, _)| *digest)
            .collect();
        for digest in stale {
            self.store.pending.remove(&digest);
            self.account_data_loss(now, digest, effects); // R-C3: a held-but-unrecoverable key is accounted lost
            effects.push(Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
            }));
        }
        // Conclude timed-out DA samples (§L4.3): a sample that never saw every sampled line present within the
        // timeout is inconclusive → `available = false` (a passing sample would have concluded early).
        let stale_samples: Vec<[u8; DIGEST]> = self
            .store
            .pending_samples
            .iter()
            .filter(|(_, s)| now.since(s.issued) > timeout)
            .map(|(digest, _)| *digest)
            .collect();
        for digest in stale_samples {
            if let Some(sample) = self.store.pending_samples.remove(&digest) {
                effects.push(Effect::Notify(Notification::Availability {
                    key: digest,
                    available: da::samples_pass(sample.present, &sample.lines),
                }));
            }
        }
    }

    /// The DHT storage address of `key`: the digest and the **ideal** responsible point (spec §L4). The
    /// point is a [`ContentPoint`], not a routing target — the *actual* responsible node is
    /// [`responsible_point`](Self::responsible_point) applied to this ideal (the nearest occupied point),
    /// since a real cell rarely occupies every point exactly.
    pub(super) fn address_of(key: &[u8]) -> ([u8; DIGEST], ContentPoint<F>) {
        // The one storage-address rule (`fanos_primitives`): digest keys the store, point routes to it —
        // both on the STORAGE domain, so they can never drift to different hashes (audit C7).
        (storage_digest(key), ContentPoint(storage_point::<F>(key)))
    }

    /// The node responsible for an ideal storage point: the nearest **occupied** point at or after
    /// `ideal`'s canonical index, wrapping the ring — consistent hashing on projective coordinates
    /// (spec §L0 "the responsible node is the nearest occupied point"). This is the sole bridge from the
    /// content-address domain ([`ContentPoint`]) to a node coordinate: on a full cell it is `ideal` itself;
    /// on a sparse or churning cell — the *normal* condition, since independent VRF placement covers only a
    /// fraction of a plane's points — it routes the key to a live member instead of a never-occupied point
    /// where a `Put`/`Get` would be a silent send-to-nobody (audit #123). The occupied set is this node
    /// plus every announced member, so all nodes sharing a membership view resolve the same responsible
    /// node.
    pub(super) fn responsible_point(&self, ideal: ContentPoint<F>) -> Triple {
        self.nearest_occupied(ideal.0.index())
    }

    /// The occupied points of this cell, by canonical index: this node, every cell peer we have heard from
    /// (its algebraic slot is filled by a live node — liveness populates this even before any JOIN/Announce),
    /// and every announced member. A never-occupied point is simply absent; a heard-then-crashed occupant is
    /// handled downstream by `routed_send`'s reroute. Always contains this node.
    pub(super) fn occupied_points(&self) -> BTreeSet<usize> {
        let mut occupied: BTreeSet<usize> = self
            .peers
            .iter()
            .filter(|(_, p)| p.last_seen.is_some())
            .filter_map(|(&c, _)| Point::<F>::new(c).map(|pt| pt.index()))
            .chain(
                self.membership
                    .members
                    .keys()
                    .filter_map(|&c| Point::<F>::new(c).map(|pt| pt.index())),
            )
            .collect();
        occupied.insert(self.coord.index());
        occupied
    }

    /// The consistent-hashing home of the point at canonical index `ideal_idx`: the smallest occupied index
    /// `>= ideal_idx`, else wrap to the smallest occupied (successor on the index ring). This is the seam
    /// both content-routing ([`responsible_point`](Self::responsible_point)) and erasure shard-placement
    /// ([`distribute_shards`](Self::distribute_shards)) share — a shard for a point lands at that point when
    /// occupied, else its nearest-occupied successor. The occupied set always contains this node, so this is
    /// total (the `map_or` default is unreachable, kept only for totality).
    pub(super) fn nearest_occupied(&self, ideal_idx: usize) -> Triple {
        let occupied = self.occupied_points();
        occupied
            .range(ideal_idx..)
            .next()
            .or_else(|| occupied.iter().next())
            .map_or_else(
                || Point::<F>::at(ideal_idx).coords(),
                |&i| Point::<F>::at(i).coords(),
            )
    }

    /// `Command::Put` — erasure-code the value and distribute its shards across the cell (spec §L4). The
    /// write is stamped with a version (the responsible node's `now`) so a later write supersedes it
    /// (last-writer-wins) and a reader never mixes two writes' shards.
    pub(super) fn on_put(&mut self, now: Instant, key: &[u8], value: &[u8]) -> Vec<Effect> {
        let (digest, ideal) = Self::address_of(key);
        let primary = self.responsible_point(ideal);
        if primary == self.coord.coords() {
            // We are the responsible node: refuse an over-size value without distributing or claiming it
            // stored; otherwise erasure-code it into per-point shards, place each at its home, and ack.
            if value.len() > MAX_VALUE_LEN {
                return Vec::new();
            }
            let mut effects = self.distribute_shards(&digest, value, now.as_nanos());
            effects.push(Effect::Notify(Notification::Stored(digest)));
            effects
        } else {
            // Route the full value to the responsible node, which stamps the version and distributes shards.
            alloc::vec![self.routed_send(
                primary,
                encode_publish(PUBLISH_ORIGIN, 0, 0, &digest, value)
            )]
        }
    }

    /// `Command::Get` — gather a recoverable erasure shard-set from the cell and reconstruct (spec §L4).
    ///
    /// Under the projective LRC no single node holds the value: it lives as `N=7` shards, one per point.
    /// The read seeds any shards THIS node holds, and if they alone reconstruct (a small/degenerate cell)
    /// answers at once; otherwise it fans a `Lookup` out to *every* cell peer simultaneously and accumulates
    /// their shards ([`on_value`](Self::on_value)) until the present set is [`erasure::reconstruct`]-able —
    /// which tolerates any `≤3`-point loss, so the read succeeds even with several nodes down or withholding.
    /// The heartbeat sweep concludes `Retrieved(None)` if a recoverable set never assembles within the read
    /// timeout. The in-flight accumulator is tracked in the [`Store`]'s `pending` map.
    pub(super) fn on_get(&mut self, now: Instant, key: &[u8]) -> Vec<Effect> {
        let (digest, _ideal) = Self::address_of(key);
        // Seed the accumulator with any shards this node already holds (grouped by write-version); short-
        // circuit if the highest recoverable version reconstructs from local shards alone.
        let mut by_version = BTreeMap::new();
        self.store.seed_versions(&digest, &mut by_version);
        if let Some(value) = reconstruct_highest(&by_version) {
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: Some(value),
            })];
        }
        // Cap in-flight reads (A4 DoS backstop): once [`MAX_PENDING_GETS`] distinct reads are outstanding,
        // refuse a *new* one — concluding `Retrieved(None)` — rather than track it, so a flood of
        // distinct-key `Get`s cannot grow the pending map without bound. A repeat Get for an already-pending
        // digest is allowed through (it refreshes the existing entry, no growth).
        if self.store.pending.len() >= MAX_PENDING_GETS && !self.store.pending.contains_key(&digest)
        {
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
            })];
        }
        // Fan a `Lookup` out across cell peers — each is a potential shard home. Sent directly (not rerouted):
        // a down peer simply does not reply, and the erasure redundancy tolerates it.
        //
        // **How wide is a control decision.** Asking everyone spends `N` messages to recover `K` shards, and
        // under pressure that amplification lands on the very links that are struggling — so the width follows
        // the cell's measured headroom (`stability::read_fanout`). At rest it is every peer, which is the right
        // default for a read: fastest-`K` wins. The floor is the erasure code's own, never policy's — below `K`
        // a read cannot complete at all.
        let mut peers: Vec<Triple> = self.peers.keys().copied().collect();
        let width = fanos_diakrisis::stability::read_fanout(
            peers.len(),
            erasure::K,
            READ_FANOUT_MARGIN,
            self.healer.stress(),
        );
        peers.truncate(width);
        if peers.is_empty() {
            // No peer to gather from and the local shards did not reconstruct — the value is unreachable.
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: None,
            })];
        }
        // A fresh per-request nonce correlates this read's replies (audit C4); a repeat Get for the same
        // key supersedes the old one with a new nonce, so the old read's in-flight replies go stale.
        self.store.seq = self.store.seq.wrapping_add(1);
        let nonce = self.store.seq;
        self.store.pending.insert(
            digest,
            PendingGet {
                issued: now,
                by_version,
                nonce,
                queried: u16::try_from(peers.len()).unwrap_or(u16::MAX),
                negatives: 0,
            },
        );
        peers
            .into_iter()
            .map(|peer| Effect::Send {
                to: peer,
                frame: encode_lookup(&digest, nonce),
            })
            .collect()
    }

    /// `Command::SampleAvailability` — the light-client DA sample (spec §L4.3): probe a few unpredictable
    /// Fano lines to certify the value's shards are present, without downloading it. Seeds the `present` mask
    /// from local shards, picks `DA_SAMPLES` distinct lines ([`da::sample_lines`]) from an unpredictable seed
    /// (fold of the digest ⊕ a fresh nonce — so a withholding adversary cannot pre-position the lone external
    /// line), and probes only the sampled points' shard homes. Concludes `available` as soon as every sampled
    /// line is fully present ([`da::samples_pass`]); the sweep concludes it (unavailable) after the timeout.
    pub(super) fn on_sample(&mut self, now: Instant, key: &[u8]) -> Vec<Effect> {
        let (digest, _ideal) = Self::address_of(key);
        self.store.seq = self.store.seq.wrapping_add(1);
        let nonce = self.store.seq;
        let lines = da::sample_lines(fold_seed(&digest) ^ nonce, DA_SAMPLES);
        // Seed the DA `present` mask from any shards this node itself holds.
        let mut present = 0u8;
        if let Some(held) = self.store.entries.get(&digest) {
            for &i in held.keys() {
                if usize::from(i) < erasure::N {
                    present |= 1 << i;
                }
            }
        }
        // Probe the distinct shard homes of the sampled lines' points (self is already seeded).
        let me = self.coord.coords();
        let mut targets: BTreeSet<Triple> = BTreeSet::new();
        for &l in &lines {
            let Some(points) = fano::LINE_POINTS.get(l) else {
                continue;
            };
            for &p in points {
                let home = self.nearest_occupied(usize::from(p));
                if home != me {
                    targets.insert(home);
                }
            }
        }
        // Already satisfied locally, or nobody else to probe — conclude now.
        if da::samples_pass(present, &lines) || targets.is_empty() {
            return alloc::vec![Effect::Notify(Notification::Availability {
                key: digest,
                available: da::samples_pass(present, &lines),
            })];
        }
        // A4 DoS cap (shared spirit with reads): bound the in-flight sample map.
        if self.store.pending_samples.len() >= MAX_PENDING_GETS
            && !self.store.pending_samples.contains_key(&digest)
        {
            return alloc::vec![Effect::Notify(Notification::Availability {
                key: digest,
                available: false,
            })];
        }
        self.store.pending_samples.insert(
            digest,
            PendingSample {
                issued: now,
                nonce,
                lines,
                present,
            },
        );
        targets
            .into_iter()
            .map(|t| Effect::Send {
                to: t,
                frame: encode_lookup(&digest, nonce),
            })
            .collect()
    }

    /// Erasure-code `value` into `N=7` point-shards and place each at its point's nearest-occupied home
    /// (spec §L4 projective LRC): shard `i` → [`nearest_occupied`](Self::nearest_occupied)`(i)`. Shards homed
    /// at this node are stored locally; the rest are sent as `PUBLISH_SHARD` frames carrying the point index.
    /// On a full Fano cell this is shard `i` → point `i` (one shard per node, `N/K ≈ 2.33×` redundancy vs
    /// `N×` full replication); on a sparse cell several shards may share a home (graceful degradation — the
    /// cell simply has fewer independent failure domains).
    pub(super) fn distribute_shards(
        &mut self,
        digest: &[u8; DIGEST],
        value: &[u8],
        version: u64,
    ) -> Vec<Effect> {
        let me = self.coord.coords();
        let shards = erasure::encode(value);
        let mut effects = Vec::new();
        for (i, shard) in shards.into_iter().enumerate() {
            let home = self.nearest_occupied(i);
            #[allow(clippy::cast_possible_truncation)] // i < N = 7
            let index = i as u8;
            if home == me {
                self.store.insert_shard(*digest, index, version, shard);
            } else {
                effects.push(Effect::Send {
                    to: home,
                    frame: encode_publish(PUBLISH_SHARD, index, version, digest, &shard),
                });
            }
        }
        effects
    }

    pub(super) fn on_publish(&mut self, now: Instant, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some(&flag) = body.first() else {
            return Vec::new();
        };
        let Some(&index) = body.get(1) else {
            return Vec::new();
        };
        let Some(version) = parse_u64(body, 2) else {
            return Vec::new();
        };
        let Some(digest) = parse_digest(body.get(10..10 + DIGEST)) else {
            return Vec::new();
        };
        let payload = body.get(10 + DIGEST..).unwrap_or(&[]);
        // A4 DoS caps: a refused publish (over-size, or a new key over the store cap) is dropped without an
        // Ack or distribution — a relayed flood of distinct digests cannot exhaust this node's memory.
        if !self.store.admits(&digest, payload.len()) {
            return Vec::new();
        }
        match flag {
            PUBLISH_ORIGIN => {
                // We are the responsible node: stamp this write's version (our distribution time),
                // erasure-distribute the full value across the cell, and acknowledge the origin.
                let mut effects = self.distribute_shards(&digest, payload, now.as_nanos());
                effects.push(Effect::Send {
                    to: from,
                    frame: encode(FrameType::Ack, &digest),
                });
                effects
            }
            PUBLISH_SHARD => {
                // A single versioned shard for Fano point `index` — store it, keeping the higher version.
                //
                // **`version` is attacker-choosable and nothing here can currently stop it (task #79).** It
                // arrives off the wire and `insert_shard` keeps `version >= held`; a real distribution
                // stamps `now.as_nanos()` (~1.75e18) while `u64::MAX` is an order of magnitude above, so one
                // frame per (digest, index) pins that shard permanently, and reads take the highest version
                // group. That reaches every directory built on this store.
                //
                // The obvious guard — require `from` to be the node responsible for this digest — **cannot
                // be written here**, and the reason is structural rather than an oversight: responsibility
                // is `storage_point::<F>(key)`, a function of the KEY, and the shard frame carries only the
                // digest. A receiver therefore cannot recompute who should have sent it. (Checking
                // `nearest_occupied(index)` instead compares against the *receiver's* own home, which is
                // `me` for every legitimate publish — tried, and it rejects them all.)
                //
                // The ordering it protects was never sound either: `now` is `Instant(origin.elapsed())`,
                // time since *this node* started, so two nodes' versions are incomparable. The scheme works
                // only because one node stamps and the rest copy — which is exactly the invariant nothing
                // enforces. #79 carries the three real options and their costs.
                self.store
                    .insert_shard(digest, index, version, payload.to_vec());
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    pub(super) fn on_lookup(&self, from: Triple, body: &[u8]) -> Vec<Effect> {
        // Canonical derived codec (audit A1): rejects a short or trailing-byte Lookup.
        let Ok(LookupBody { key: digest, nonce }) = LookupBody::from_wire(body) else {
            return Vec::new();
        };
        // Return EVERY shard this node holds for the key, one `Value` each carrying its write-version (the
        // reader groups by version, then point index). No shard → a single `found=false` "not here".
        match self.store.entries.get(&digest) {
            Some(held) if !held.is_empty() => held
                .iter()
                .map(|(&index, (version, shard))| Effect::Send {
                    to: from,
                    frame: encode_value(&digest, true, index, *version, shard, nonce),
                })
                .collect(),
            _ => alloc::vec![Effect::Send {
                to: from,
                frame: encode_value(&digest, false, 0, 0, &[], nonce),
            }],
        }
    }

    /// A `Value` reply carrying one versioned erasure shard (spec §L4). Accumulate it into the in-flight
    /// read's version-grouped shard-set and, once the **highest** recoverable version reconstructs, deliver
    /// that value (last-writer-wins) and retire the read. A `found=false` reply (the peer holds no shard) is
    /// not accumulated; once every queried peer has said so, or the read times out, the value is absent.
    pub(super) fn on_value(&mut self, now: Instant, body: &[u8]) -> Vec<Effect> {
        let Some(digest) = parse_digest(body.get(..DIGEST)) else {
            return Vec::new();
        };
        let found = body.get(DIGEST).copied().unwrap_or(0) != 0;
        let index = body.get(DIGEST + 1).copied().unwrap_or(0);
        let Some(version) = parse_u64(body, DIGEST + 2) else {
            return Vec::new();
        };
        let Some(nonce) = parse_u64(body, DIGEST + 10) else {
            return Vec::new();
        };
        // A `Value` may answer an in-flight DA sample (§L4.3) rather than a read — the distinct per-request
        // nonce disambiguates. Route it there first: mark the point present and, once every sampled line is
        // present, conclude the value available.
        if let Some(sample) = self.store.pending_samples.get_mut(&digest)
            && sample.nonce == nonce
        {
            if found && usize::from(index) < erasure::N {
                sample.present |= 1u8 << index;
            }
            if da::samples_pass(sample.present, &sample.lines) {
                self.store.pending_samples.remove(&digest);
                return alloc::vec![Effect::Notify(Notification::Availability {
                    key: digest,
                    available: true,
                })];
            }
            return Vec::new();
        }
        // Otherwise correlate on the per-request nonce, NOT merely the key: a reply is accepted only for the
        // read currently in flight for this key. A stale/replayed `Value` from a prior get (old nonce), or one
        // with no in-flight read at all, is ignored — so it can never drain a later same-key get with an old
        // shard (read-your-writes, audit C4).
        let Some(pending) = self.store.pending.get_mut(&digest) else {
            return Vec::new();
        };
        if pending.nonce != nonce {
            return Vec::new();
        }
        if !found {
            // A peer holds no shard for this key. Once every queried peer has said so and no version's shards
            // reconstruct, conclude the value absent immediately (a fast miss, not a timeout wait).
            pending.negatives = pending.negatives.saturating_add(1);
            if pending.negatives >= pending.queried
                && reconstruct_highest(&pending.by_version).is_none()
            {
                self.store.pending.remove(&digest);
                let mut effects = alloc::vec![];
                self.account_data_loss(now, digest, &mut effects); // R-C3: all peers answered, none can supply it
                effects.push(Effect::Notify(Notification::Retrieved { key: digest, value: None }));
                return effects;
            }
            return Vec::new();
        }
        // shard bytes follow: digest(32) ‖ found(1) ‖ index(1) ‖ version(8) ‖ nonce(8) ‖ shard.
        let shard = body.get(DIGEST + 18..).unwrap_or(&[]).to_vec();
        if let Some(slot) = pending
            .by_version
            .entry(version)
            .or_default()
            .get_mut(index as usize)
        {
            *slot = Some(shard);
        }
        // Bound the version-grouped accumulator against a Byzantine peer spraying fabricated versions: keep
        // only the highest [`MAX_READ_VERSIONS`] (the freshest are what last-writer-wins wants anyway).
        while pending.by_version.len() > MAX_READ_VERSIONS {
            if let Some(&lowest) = pending.by_version.keys().next() {
                pending.by_version.remove(&lowest);
            }
        }
        // Deliver the highest write-version whose shard-set is now recoverable (a stale version completing
        // first can never mask a fresher one; mixed-version shards are never combined into a garbage value).
        if let Some(value) = reconstruct_highest(&pending.by_version) {
            self.store.pending.remove(&digest);
            return alloc::vec![Effect::Notify(Notification::Retrieved {
                key: digest,
                value: Some(value),
            })];
        }
        Vec::new()
    }

    pub(super) fn on_ack(body: &[u8]) -> Vec<Effect> {
        match parse_digest(body.get(..DIGEST)) {
            Some(digest) => alloc::vec![Effect::Notify(Notification::Stored(digest))],
            None => Vec::new(),
        }
    }
}
