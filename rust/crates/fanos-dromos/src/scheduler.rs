//! The **deterministic parallel scheduler** — DROMOS's intra-cell (vertical) parallelism (`spec/platform.md`
//! §3.1, §3.3; the HOLARCH **DL — Regulation** channel). Consensus fixes the *order* of a block's transactions
//! serially and blind (anti-MEV); after the reveal, execution fans out: non-conflicting transactions run
//! concurrently. The load-bearing property is **determinism** — every validator must compute the *identical*
//! schedule and hence the identical state, so the schedule is a pure function of the ordered transactions and
//! their declared access lists, with no clocks, threads, or map iteration order leaking in.
//!
//! **The model.** Each transaction declares an [`AccessList`]: the state keys it reads and the keys it writes.
//! Two transactions *conflict* iff one writes a key the other reads or writes (read–read never conflicts).
//! Given the fixed order, [`schedule`] assigns each transaction to a **wave**: `1 + max(wave of any earlier
//! transaction it conflicts with)`, or wave 0 if it conflicts with none. This is a level assignment on the
//! conflict DAG (edges point forward in the committed order), and it has the two properties a parallel executor
//! needs, both proven in the tests:
//!
//! - **Waves are conflict-free** — if two transactions conflicted, the later one would be forced into a strictly
//!   higher wave, so no two transactions in the same wave conflict; a wave's transactions therefore commute and
//!   may execute in any order (in parallel).
//! - **Wave-by-wave execution equals serial execution** — every transaction's earlier conflicting transactions
//!   (its dependencies) sit in strictly lower waves, so it observes exactly the state it would under the serial
//!   order; independent transactions cannot affect it. The parallel result is the serial result.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A transaction's declared state footprint: the keys it reads and the keys it writes (32-byte state keys —
/// account ids, name keys, the shielded-pool marker, …). Shielded spends declare the whole pool as one shared
/// key, so they serialize against each other but parallelize against disjoint transparent work (§3.3).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct AccessList {
    /// The keys the transaction reads.
    pub reads: BTreeSet<[u8; 32]>,
    /// The keys the transaction writes.
    pub writes: BTreeSet<[u8; 32]>,
}

impl AccessList {
    /// An access list from read and write key iterators.
    #[must_use]
    pub fn new(reads: impl IntoIterator<Item = [u8; 32]>, writes: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self { reads: reads.into_iter().collect(), writes: writes.into_iter().collect() }
    }

    /// Whether this transaction conflicts with `other`: a write on either side against a read or write on the
    /// other (read–read does not conflict).
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        intersects(&self.writes, &other.writes)
            || intersects(&self.writes, &other.reads)
            || intersects(&self.reads, &other.writes)
    }
}

/// Whether two sorted key sets share any element (a linear merge over the `BTreeSet`s).
#[must_use]
fn intersects(a: &BTreeSet<[u8; 32]>, b: &BTreeSet<[u8; 32]>) -> bool {
    // Iterate the smaller against membership in the larger.
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    small.iter().any(|k| large.contains(k))
}

/// Partition the ordered `access` lists into conflict-free **waves** (each wave a list of transaction indices,
/// in ascending order). Executing the waves in order, with each wave's transactions run concurrently, produces
/// the identical state as executing the transactions serially in the given order — and the partition is a pure,
/// deterministic function of the input.
#[must_use]
pub fn schedule(access: &[AccessList]) -> Vec<Vec<usize>> {
    // `last_write[k]` / `last_read[k]` = the highest wave of a transaction that has written / read key `k` so
    // far. A transaction's wave is one past the highest wave it depends on; the maps make this O(accesses).
    let mut last_write: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut last_read: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut wave_of: Vec<usize> = Vec::with_capacity(access.len());

    for a in access {
        let mut wave = 0usize;
        // A write must follow every earlier read and write of the same key (WW, WR hazards).
        for k in &a.writes {
            if let Some(&w) = last_write.get(k) {
                wave = wave.max(w + 1);
            }
            if let Some(&r) = last_read.get(k) {
                wave = wave.max(r + 1);
            }
        }
        // A read must follow every earlier write of the same key (RW hazard).
        for k in &a.reads {
            if let Some(&w) = last_write.get(k) {
                wave = wave.max(w + 1);
            }
        }
        // Record this transaction's accesses at its wave (keep the max defensively).
        for k in &a.writes {
            let e = last_write.entry(*k).or_insert(wave);
            *e = (*e).max(wave);
        }
        for k in &a.reads {
            let e = last_read.entry(*k).or_insert(wave);
            *e = (*e).max(wave);
        }
        wave_of.push(wave);
    }

    let wave_count = wave_of.iter().copied().max().map_or(0, |m| m + 1);
    let mut waves = vec![Vec::new(); wave_count];
    for (i, &w) in wave_of.iter().enumerate() {
        if let Some(bucket) = waves.get_mut(w) {
            bucket.push(i);
        }
    }
    waves
}

/// The **width** of a schedule: the size of its largest wave — the peak parallelism the block admits. `1` means
/// fully serial (every transaction conflicts with the previous); `n` means fully independent.
#[must_use]
pub fn width(waves: &[Vec<usize>]) -> usize {
    waves.iter().map(Vec::len).max().unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// A transaction over integer accounts, for the equivalence oracle: it reads its `reads`, writes each of its
    /// `writes` with `sum(reads) + 1`. Non-commutative enough that a wrong schedule diverges.
    #[derive(Clone)]
    struct MockTx {
        reads: Vec<u8>,
        writes: Vec<u8>,
    }

    impl MockTx {
        fn access(&self) -> AccessList {
            AccessList::new(self.reads.iter().map(|&k| key(k)), self.writes.iter().map(|&k| key(k)))
        }

        fn apply(&self, state: &mut BTreeMap<u8, u64>) {
            let sum: u64 = self.reads.iter().map(|k| state.get(k).copied().unwrap_or(0)).sum();
            for w in &self.writes {
                state.insert(*w, sum.wrapping_add(1));
            }
        }
    }

    fn run_serial(txs: &[MockTx]) -> BTreeMap<u8, u64> {
        let mut state = BTreeMap::new();
        for tx in txs {
            tx.apply(&mut state);
        }
        state
    }

    fn run_scheduled(txs: &[MockTx], waves: &[Vec<usize>]) -> BTreeMap<u8, u64> {
        let mut state = BTreeMap::new();
        for wave in waves {
            // Within a wave the order does not matter (conflict-free); apply in index order for the reference.
            for &i in wave {
                txs[i].apply(&mut state);
            }
        }
        state
    }

    #[test]
    fn independent_transactions_all_land_in_one_wave() {
        // Disjoint accounts → no conflicts → a single parallel wave.
        let access: Vec<AccessList> = (0..8).map(|n| AccessList::new([], [key(n)])).collect();
        let waves = schedule(&access);
        assert_eq!(waves.len(), 1, "no conflicts → one wave");
        assert_eq!(width(&waves), 8, "all eight run in parallel");
        assert_eq!(waves[0], (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn a_write_chain_on_one_account_serializes() {
        // Every transaction writes the same account → each must follow the last → fully serial.
        let access: Vec<AccessList> = (0..5).map(|_| AccessList::new([key(0)], [key(0)])).collect();
        let waves = schedule(&access);
        assert_eq!(waves.len(), 5, "a write-after-write chain is fully serial");
        assert_eq!(width(&waves), 1);
        for (w, wave) in waves.iter().enumerate() {
            assert_eq!(wave, &[w], "each wave holds exactly its one transaction, in order");
        }
    }

    #[test]
    fn readers_parallelize_but_a_writer_is_a_barrier() {
        // tx0 writes A; tx1,tx2 read A (parallel, after the write); tx3 writes A (after the readers).
        let access = vec![
            AccessList::new([], [key(1)]),       // 0: write A
            AccessList::new([key(1)], []),       // 1: read A
            AccessList::new([key(1)], []),       // 2: read A
            AccessList::new([key(1)], [key(1)]), // 3: read+write A
        ];
        let waves = schedule(&access);
        assert_eq!(waves, vec![vec![0], vec![1, 2], vec![3]], "write | parallel reads | write");
    }

    #[test]
    fn waves_are_always_conflict_free_and_the_schedule_matches_serial_execution() {
        // Stochastic equivalence: over many pseudo-random transaction batches, (a) no two transactions in a wave
        // conflict, and (b) wave-by-wave execution reproduces serial execution exactly.
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            // splitmix64 — a deterministic, seeded PRNG (no wall-clock entropy, so the test is reproducible).
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };

        for _ in 0..500 {
            let n = (next() % 12) as usize + 1;
            let accounts = (next() % 5) as u8 + 1; // a small account space → frequent conflicts
            let txs: Vec<MockTx> = (0..n)
                .map(|_| {
                    let nr = (next() % 3) as usize;
                    let nw = (next() % 3) as usize;
                    MockTx {
                        reads: (0..nr).map(|_| (next() % u64::from(accounts)) as u8).collect(),
                        writes: (0..nw).map(|_| (next() % u64::from(accounts)) as u8).collect(),
                    }
                })
                .collect();
            let access: Vec<AccessList> = txs.iter().map(MockTx::access).collect();
            let waves = schedule(&access);

            // Determinism: re-scheduling the identical input yields the identical waves.
            assert_eq!(schedule(&access), waves, "the schedule is a pure function of its input");

            // (a) every wave is internally conflict-free.
            for wave in &waves {
                for (x, &i) in wave.iter().enumerate() {
                    for &j in &wave[x + 1..] {
                        assert!(!access[i].conflicts_with(&access[j]), "wave {i},{j} conflict");
                    }
                }
            }
            // Every transaction appears exactly once.
            let mut seen: Vec<usize> = waves.iter().flatten().copied().collect();
            seen.sort_unstable();
            assert_eq!(seen, (0..n).collect::<Vec<_>>(), "every transaction is scheduled exactly once");

            // (b) the parallel schedule reproduces serial execution.
            assert_eq!(run_scheduled(&txs, &waves), run_serial(&txs), "parallel result must equal serial");
        }
    }
}
