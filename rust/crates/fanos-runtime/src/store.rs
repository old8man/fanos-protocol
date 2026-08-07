//! The overlay's **local content store** and its in-flight request state, split out of `overlay.rs` (task 7a).
//!
//! `Store` holds what this node keeps and what it is waiting for: the key→value map, the erasure shards it is
//! custodian of, the loss ledger, and the pending `Get`/DA-sample state machines that a reply or a timeout resolves.
//! `OverlayNode` owns the *policy* — which point is responsible for a key, when to read-repair, when to give up —
//! and this owns the bookkeeping that policy reads.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_primitives::codec::{Reader, put_seq, put_u64, put_var_bytes};
use fanos_primitives::{Epoch, hash::hash_labeled};

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
    /// **Durable in the literal sense now, and it was not for a long time.** The word was here before the
    /// mechanism was: nothing in this tree wrote the store to disk, so a record of permanent data loss did
    /// not itself survive a restart, which makes it a record of nothing. It is carried in
    /// [`Store::snapshot`] and comes back through [`Store::restore`] (#77); a node whose configuration names
    /// no state directory still keeps nothing, and for that node the old caveat stands unchanged.
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

/// The snapshot format's domain separator and version. Bumping the version invalidates older files by
/// construction — a decode that does not recognise the header refuses, rather than reading a v1 layout as v2.
const SNAPSHOT_LABEL: &str = "FANOS-v1/store-snapshot";

/// The format revision, encoded in the header so a future layout change is a refusal and not a silent
/// misread. There is no migration path and there does not need to be: an unreadable snapshot costs this node
/// its local shards, which the `[7,3,4]` erasure code across the cell is *designed* to re-heal.
const SNAPSHOT_VERSION: u32 = 1;

/// Whether `bytes` is a snapshot **this build can adopt** — the question, exposed without the type.
///
/// [`Store`] is deliberately `pub(crate)`, so a host that wants to *report* the outcome of a restore had no
/// way to learn it: `OverlayNode::restore` returns the verdict but the composition swallows it, and the host
/// was left holding the byte count instead (#189). A byte count answers *"was there a file?"*; this answers
/// *"can it be read?"*, which is the fact the startup report claims.
///
/// Defined by calling the same [`Store::restore`] the adoption path uses, so the two **cannot** disagree —
/// a re-implementation of the header check here would be a second decoder to keep in step, which is the
/// shape that made the version constant above worth having in the first place.
///
/// At the one call site that matters this is *exact* rather than merely indicative: `compose_engine` invokes
/// `restore` immediately after `OverlayNode::new`, when the store is provably empty, so the only reachable
/// cause of a refusal is the decode — not the "already holding entries" arm.
///
/// Costs one extra decode of a file already in memory, once per process start.
#[must_use]
pub fn snapshot_is_readable(bytes: &[u8]) -> bool {
    Store::restore(bytes).is_some()
}

impl Store {
    /// This node's **durable** state as canonical bytes: the held shards, the expiry schedule, the loss
    /// ledger, and the read-nonce counter.
    ///
    /// # What is in it, and what deliberately is not
    ///
    /// `pending` and `pending_samples` are **in-flight**, not durable. A `Get` is a conversation with peers
    /// that a restart has already ended: the reply nonce is gone with the socket, the peers have forgotten
    /// the request, and restoring the accumulator would resurrect a read that can only time out. The caller
    /// re-issues; that is what a caller of a distributed store must be able to do anyway.
    ///
    /// `seq` **is** persisted, at a cost of eight bytes, so the read nonce is monotone across the process
    /// boundary. Not strictly required — a restored node has no `pending`, so a replayed `Value` resolves
    /// nothing regardless (audit C4) — but making the counter monotone means the C4 argument does not have to
    /// rest on that, and an argument that rests on one fewer thing is worth eight bytes.
    ///
    /// # Integrity, and what the checksum is not for
    ///
    /// The body is followed by a `BLAKE3` tag over itself, so a truncated or bit-rotted file is refused
    /// instead of half-loaded. It is a **checksum, not authentication**: anyone who can write this file can
    /// also write the identity key next to it, so a MAC keyed by anything on this disk would prove nothing an
    /// attacker could not forge. The threat it addresses is a machine that lost power mid-write, which is the
    /// one that actually happens.
    pub(crate) fn snapshot(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        put_u64(&mut body, self.seq);
        // Each map streams in its own sorted order, so the encoding is canonical: two nodes with equal state
        // produce equal bytes, which is what makes a snapshot comparable in a test at all.
        put_seq(&mut body, self.entries.len(), &self.entries, |out, (digest, held)| {
            out.extend_from_slice(digest);
            put_seq(out, held.len(), held, |out, (index, (version, shard))| {
                out.push(*index);
                put_u64(out, *version);
                put_var_bytes(out, shard);
            });
        });
        put_seq(&mut body, self.expiry.len(), &self.expiry, |out, (digest, until)| {
            out.extend_from_slice(digest);
            put_u64(out, until.get());
        });
        put_seq(&mut body, self.loss_ledger.len(), &self.loss_ledger, |out, (digest, at)| {
            out.extend_from_slice(digest);
            put_u64(out, at.get());
        });
        let tag = hash_labeled(SNAPSHOT_LABEL, &body);
        body.extend_from_slice(&tag);
        body
    }

    /// Restore from [`snapshot`](Self::snapshot) bytes, or `None` if they are not a snapshot this build
    /// wrote — wrong version, wrong length, failed checksum, trailing garbage, or **over this store's own
    /// caps**.
    ///
    /// **The caps are re-applied on the way in, and that is the whole security content of this function.**
    /// A snapshot is a file on disk, so it is provisioning, and provisioning is the surface that gets audited
    /// last: `MAX_STORE_ENTRIES` and `MAX_VALUE_LEN` bound what the *network* can make this node hold, and a
    /// restore path that did not re-check them would let a crafted file do what no peer can — allocate
    /// without limit before any of the runtime's admission logic has run. `admits` is not reachable from
    /// here (it consults the half-built store), so the bounds are checked directly, and a file that exceeds
    /// either is refused **whole** rather than truncated: a partially-loaded store silently claims custody of
    /// shards it does not have, and a node that lies about custody is worse for the cell than one that
    /// starts empty.
    pub(crate) fn restore(bytes: &[u8]) -> Option<Self> {
        let (body, tag) = bytes.split_at_checked(bytes.len().checked_sub(32)?)?;
        if hash_labeled(SNAPSHOT_LABEL, body) != *tag {
            return None;
        }
        let mut r = Reader::new(body);
        if u32::from_le_bytes(r.array()?) != SNAPSHOT_VERSION {
            return None;
        }
        let seq = r.u64()?;
        // `min_elem`: a digest plus a zero-length inner sequence is 32 + 4 bytes, so the count cannot claim
        // more entries than the remaining bytes could hold — the same bound `Reader::seq` exists to impose.
        let entries = r.seq(DIGEST + 4, |r| {
            let digest: [u8; DIGEST] = r.array()?;
            let held = r.seq(1 + 8 + 4, |r| {
                let index = r.u8()?;
                let version = r.u64()?;
                let shard = r.var_bytes()?;
                (shard.len() <= MAX_VALUE_LEN).then(|| (index, (version, shard.to_vec())))
            })?;
            Some((digest, held.into_iter().collect::<HeldShards>()))
        })?;
        let expiry = r.seq(DIGEST + 8, |r| Some((r.array::<DIGEST>()?, Epoch::new(r.u64()?))))?;
        let loss_ledger = r.seq(DIGEST + 8, |r| Some((r.array::<DIGEST>()?, Epoch::new(r.u64()?))))?;
        r.finish()?;

        let entries: BTreeMap<[u8; DIGEST], HeldShards> = entries.into_iter().collect();
        let loss_ledger: BTreeMap<[u8; DIGEST], Epoch> = loss_ledger.into_iter().collect();
        let expiry: BTreeMap<[u8; DIGEST], Epoch> = expiry.into_iter().collect();
        // **Every map, not just `entries`.** Capping the held shards alone would leave two side maps whose
        // only bound was the file's own length — a snapshot with no entries at all and forty million bytes of
        // expiry records is a memory amplification a peer has no way to perform, which is exactly the shape
        // this second door exists to refuse. Both are *documented* as subsets of the held keys, but that is
        // an invariant of the code that produced the file, and the whole premise here is that the file may
        // not have come from that code.
        if entries.len() > MAX_STORE_ENTRIES
            || loss_ledger.len() > MAX_STORE_ENTRIES
            || expiry.len() > MAX_STORE_ENTRIES
        {
            return None;
        }
        Some(Self {
            entries,
            pending: BTreeMap::new(),
            pending_samples: BTreeMap::new(),
            loss_ledger,
            expiry,
            seq,
        })
    }
}
