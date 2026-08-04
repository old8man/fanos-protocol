//! The overlay's **local content store** and its in-flight request state, split out of `overlay.rs` (task 7a).
//!
//! `Store` holds what this node keeps and what it is waiting for: the key→value map, the erasure shards it is
//! custodian of, the loss ledger, and the pending `Get`/DA-sample state machines that a reply or a timeout resolves.
//! `OverlayNode` owns the *policy* — which point is responsible for a key, when to read-repair, when to give up —
//! and this owns the bookkeeping that policy reads.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_primitives::Epoch;

use crate::overlay::{DIGEST, HeldShards, MAX_STORE_ENTRIES, MAX_VALUE_LEN, VersionedShards};
use crate::ports::Instant;
/// An in-flight `Get` gathering erasure shards from the cell (spec §L4). No single node holds the value, so
/// the read fans a `Lookup` to every shard home and accumulates their replies — grouped by write-version, so
/// shards of two concurrent writes are never mixed into one (garbage) reconstruction — until the highest
/// recoverable version delivers (last-writer-wins), or the read times out / all peers report a miss.
#[derive(Clone, Debug)]
pub(crate) struct PendingGet {
    pub(crate) issued: Instant,
    /// Gathered shards grouped by write-version: `version → [shard per Fano point]`. A write stamps all its
    /// shards with one version, so grouping keeps a reconstruction internally consistent even while two
    /// writers race; the read reconstructs the **highest** version whose shard-set is recoverable
    /// ([`reconstruct_highest`]). Bounded by [`MAX_READ_VERSIONS`] (evict lowest) against version-spray DoS.
    pub(crate) by_version: VersionedShards,
    /// The per-request nonce this read is correlated on: a `Value` reply resolves it only if the reply
    /// echoes this exact nonce, so a stale/replayed reply from a prior get for the same key cannot drain
    /// it with an old value (audit C4).
    pub(crate) nonce: u64,
    /// How many `Lookup`s this read fanned out — the peers it is awaiting shard replies from.
    pub(crate) queried: u16,
    /// How many of those peers have replied `found=false` (they hold no shard for this key). Once this
    /// reaches [`queried`](Self::queried) and the gathered shards still do not reconstruct, the value is
    /// concluded absent immediately — a fast miss, instead of waiting out the read timeout.
    pub(crate) negatives: u16,
}

/// An in-flight [`Command::SampleAvailability`] (spec §L4.3): the distinct Fano lines being sampled and the
/// mask of points confirmed present so far. The sample probes only the sampled lines' shard homes (a cheap
/// availability check, not a full download); it concludes **available** as soon as every sampled line is
/// fully present, else the read-timeout sweep concludes it unavailable.
#[derive(Clone, Debug)]
pub(crate) struct PendingSample {
    pub(crate) issued: Instant,
    /// The per-request nonce correlating probe replies (shared with the read path's `Value` frames, C4).
    pub(crate) nonce: u64,
    /// The distinct Fano lines this sample is checking (from `da::sample_lines`).
    pub(crate) lines: Vec<usize>,
    /// Points confirmed present (bit `i` ⇒ point `i`'s shard was returned): the DA `present` mask.
    pub(crate) present: u8,
}

/// The DHT-storage concern factored out of [`OverlayNode`] (audit #125 decompose): this node's local
/// slice of the cell's distributed store plus its in-flight read-repair bookkeeping. The *orchestration*
/// of a Put/Get — resolving the responsible cell member, replicating across the cell — stays on
/// `OverlayNode`, which owns the membership view; this owns the local state and the read-repair walk.
#[derive(Default)]
pub(crate) struct Store {
    /// Key digest → this node's held **erasure shards** for that key: `point index → (write-version, shard
    /// bytes)`. A value is `erasure::encode`d into `N=7` point-shards, each stamped with the write's version
    /// and placed at its point's nearest-occupied home (spec §L4 projective LRC, #115); on a full Fano cell a
    /// node holds one shard (its own point), on a sparse cell several. Each index keeps the **highest**
    /// version seen (last-writer-wins), so a lookup returns each point's freshest shard.
    pub(crate) entries: BTreeMap<[u8; DIGEST], HeldShards>,
    /// In-flight `Get`s awaiting shards, keyed by digest — the gather-and-reconstruct accumulator.
    pub(crate) pending: BTreeMap<[u8; DIGEST], PendingGet>,
    /// In-flight DA samples ([`Command::SampleAvailability`]), keyed by digest (spec §L4.3).
    pub(crate) pending_samples: BTreeMap<[u8; DIGEST], PendingSample>,
    /// The loss ledger (audit R-C3): digests this node held a shard of that became permanently
    /// unrecoverable — more shard-homes gone than the `[7,3,4]` code tolerates — and the epoch each loss was
    /// accounted. Bounded by the store's own [`MAX_STORE_ENTRIES`] (it is a subset of held keys). Makes loss
    /// visible and auditable instead of silent, within one process lifetime.
    ///
    /// **It was called "durable" and said "a production node persists it", and neither is true.** Nothing in
    /// this tree writes the store to disk — the whole of it is these `BTreeMap`s, and a restart drops them.
    /// The claim mattered because it is an audit trail: a record of permanent data loss that itself does not
    /// survive a restart is a record of nothing. Corrected here rather than left as an aspiration in the
    /// present tense; the gap is tracked as a task, with the severity split out (a *single* node restarting
    /// is survivable by construction — the erasure code re-heals — while a whole-cell restart is not).
    pub(crate) loss_ledger: BTreeMap<[u8; DIGEST], Epoch>,
    /// Digests that **expire**, and the epoch after which each is dead — the soft-state half of the store.
    ///
    /// Six directories key their slots by `(coordinate, epoch)` and re-publish every epoch, so the cell
    /// mints new keys on a wall clock. Nothing here could tell those apart from content, because a key
    /// arrives as an opaque digest, so nothing ever removed one: the store filled at a rate fixed by the
    /// epoch period, and its admission rule is fail-closed, so a cell ran normally and then silently stopped
    /// being able to publish at all (`fanos-node/tests/store_lifetime.rs`).
    ///
    /// A digest absent from this map is content and is kept. The distinction is declared by the **publisher**
    /// ([`Command::PutEphemeral`](fanos_ports::Command::PutEphemeral)) because the publisher is the only
    /// party that knows a slot's lifetime — the store cannot read it out of a hash.
    pub(crate) expiry: BTreeMap<[u8; DIGEST], Epoch>,
    /// Monotone per-request nonce source, so a stale/replayed `Value` cannot resolve a newer read (C4).
    pub(crate) seq: u64,
}

impl Store {
    /// Record that `digest` is soft state that dies after `expires_after` — replacing any earlier expiry,
    /// so a re-publish extends rather than accumulating.
    pub(crate) fn expires(&mut self, digest: [u8; DIGEST], expires_after: Epoch) {
        self.expiry.insert(digest, expires_after);
    }

    /// Drop every expired entry, now that the clock reads `now`.
    ///
    /// **Reclamation, not eviction, and the difference decides the rule.** Eviction answers "the store is
    /// full, who goes" and must choose by age, which is why it cannot serve here: the entries that must go
    /// are the ones that are *dead*, and a dead directory slot may be newer than live content sitting beside
    /// it. Choosing by age would discard the content and keep the corpse.
    ///
    /// Content is never touched, because content never entered `expiry` — a caller has to say a write is
    /// soft state, and saying nothing means saying content.
    pub(crate) fn sweep_expired(&mut self, now: Epoch) -> usize {
        let dead: Vec<[u8; DIGEST]> =
            self.expiry.iter().filter(|&(_, until)| *until < now).map(|(d, _)| *d).collect();
        for digest in &dead {
            self.entries.remove(digest);
            self.expiry.remove(digest);
            // **The loss ledger goes with it, and leaving it would have been a leak of my own making.**
            // `loss_ledger`'s own doc claims it is "bounded by `MAX_STORE_ENTRIES` (it is a subset of held
            // keys)", and that is only true while nothing removes a held key — which is exactly what this
            // function does. An orphaned record would have survived every sweep and grown without bound,
            // reintroducing the shape this whole change exists to remove, one layer down.
            //
            // Dropping it is also right on the merits, not merely convenient: the ledger is an audit trail
            // of data that became unrecoverable, and a directory slot nobody will ever ask for again cannot
            // be lost in any sense an operator can act on. Content loss is untouched, because content is
            // never swept.
            self.loss_ledger.remove(digest);
        }
        dead.len()
    }

    /// Whether the local slice admits a shard of `shard_len` for `digest` under the A4 DoS caps: within
    /// [`MAX_VALUE_LEN`], and either the key already exists (adding/overwriting a shard of a held key — no
    /// key growth) or the store is below [`MAX_STORE_ENTRIES`] — so a `Publish` flood of distinct digests
    /// cannot displace already-stored shards, while shards of already-held keys always pass.
    pub(crate) fn admits(&self, digest: &[u8; DIGEST], shard_len: usize) -> bool {
        shard_len <= MAX_VALUE_LEN
            && (self.entries.len() < MAX_STORE_ENTRIES || self.entries.contains_key(digest))
    }

    /// Store one erasure shard for `digest` at Fano point `index`, keeping the **higher** write-version if
    /// this point already holds one (last-writer-wins) — so a stale replayed shard never overwrites a fresh
    /// one, and the store converges to the newest write's shards.
    pub(crate) fn insert_shard(&mut self, digest: [u8; DIGEST], index: u8, version: u64, shard: Vec<u8>) {
        let per_index = self.entries.entry(digest).or_default();
        if per_index
            .get(&index)
            .is_none_or(|(held, _)| version >= *held)
        {
            per_index.insert(index, (version, shard));
        }
    }

    /// Seed this node's held shards for `digest` into a read's version-grouped accumulator (each point's
    /// shard into its version's slot) — the local contribution before the network replies arrive.
    pub(crate) fn seed_versions(&self, digest: &[u8; DIGEST], by_version: &mut VersionedShards) {
        if let Some(held) = self.entries.get(digest) {
            for (&i, (version, shard)) in held {
                if let Some(slot) = by_version.entry(*version).or_default().get_mut(i as usize) {
                    *slot = Some(shard.clone());
                }
            }
        }
    }
}
