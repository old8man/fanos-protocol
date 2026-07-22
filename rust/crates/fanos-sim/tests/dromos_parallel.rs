//! DROMOS parallel-execution scenarios — how much intra-cell parallelism the deterministic scheduler actually
//! extracts as transaction *contention* varies (`spec/platform.md` §3.1, the "high-speed L1" thesis). The
//! hypothesis: with a large account space (independent transactions) a block collapses to a handful of parallel
//! waves — near-embarrassingly-parallel — and as the working set concentrates onto a few hot accounts the block
//! serializes, bottoming out at fully serial when every transaction touches one account. The scheduler's own
//! tests prove *correctness*; this measures the *throughput* the geometry-native parallelism buys.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_dromos::scheduler::{AccessList, schedule, width};

/// A 32-byte account key from an index.
fn acct(i: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&i.to_le_bytes());
    k
}

/// A deterministic, seeded PRNG (splitmix64) — reproducible, no wall-clock entropy.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A block of `n` transfer-shaped transactions, each writing two accounts drawn from a pool of `accounts`
/// (smaller pool ⇒ more contention).
fn block(n: usize, accounts: u64, seed: u64) -> Vec<AccessList> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            let a = splitmix(&mut s) % accounts;
            let b = splitmix(&mut s) % accounts;
            AccessList::new([], [acct(a), acct(b)])
        })
        .collect()
}

#[test]
fn parallelism_grows_as_contention_falls() {
    let n = 256;
    // The contention sweep: for each account-pool size, the ideal parallel time is the number of waves (each a
    // parallel step on unbounded cores), so speedup ≈ n / waves.
    eprintln!("DROMOS scheduler: {n} transactions, contention sweep");
    for &accounts in &[1u64, 2, 8, 32, 128, 1024, 1 << 20] {
        let waves = schedule(&block(n, accounts, 0xDEAD_BEEF));
        let speedup = n as f64 / waves.len() as f64;
        eprintln!(
            "  accounts={accounts:>8}  waves={:>4}  peak_width={:>4}  speedup={speedup:>5.1}x",
            waves.len(),
            width(&waves),
        );
    }

    // Boundary — one hot account: every transaction touches it, so the block is fully serial.
    let serial = schedule(&block(n, 1, 1));
    assert_eq!(serial.len(), n, "a single hot account serializes the whole block");
    assert_eq!(width(&serial), 1, "no two transactions can run together");

    // Boundary — a negligibly-contended account space: the block collapses to a few parallel waves.
    let wide = schedule(&block(n, 1 << 20, 2));
    assert!(wide.len() <= 3, "with negligible contention the block is a few waves (got {})", wide.len());
    assert!(width(&wide) >= n / 2, "most transactions run in parallel (peak width {})", width(&wide));

    // The trend: heavy contention yields many more waves than light contention (well-separated points, so the
    // comparison is robust to the pseudo-random draw).
    let heavy = schedule(&block(n, 8, 7)).len();
    let light = schedule(&block(n, 1024, 7)).len();
    assert!(heavy > 10, "256 transactions over 8 accounts are heavily serialized (waves={heavy})");
    assert!(light < 10, "256 transactions over 1024 accounts are largely parallel (waves={light})");
    assert!(light < heavy, "less contention ⇒ fewer waves ({light} < {heavy})");
}
