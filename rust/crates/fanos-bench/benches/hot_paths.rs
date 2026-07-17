//! Criterion micro-benchmarks for the FANOS hot paths — the operations that dominate a running
//! node: O(1) rendezvous (the cross product), storage/identity addressing (`MapToPoint` + hash),
//! and the DIAKRISIS coherence kernel (the SIMD Frobenius sum). Run: `cargo bench -p fanos-bench`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use fanos_crypto::hash::label;
use fanos_crypto::{hash_labeled, map_to_point};
use fanos_diakrisis::coherence::frobenius_sq;
use fanos_field::{F7, F256};
use fanos_geometry::cross;

fn rendezvous(c: &mut Criterion) {
    let u = [1u32, 2, 3];
    let v = [4u32, 5, 6];
    // The whole point of FANOS: routing is a single algebraic step, not an O(log n) walk.
    c.bench_function("rendezvous/cross_F7", |b| {
        b.iter(|| cross::<F7>(black_box(u), black_box(v)));
    });
    c.bench_function("rendezvous/cross_F256", |b| {
        b.iter(|| cross::<F256>(black_box(u), black_box(v)));
    });
}

fn addressing(c: &mut Criterion) {
    c.bench_function("addressing/hash_labeled", |b| {
        b.iter(|| hash_labeled(label::STORAGE, black_box(b"a-storage-key")));
    });
    c.bench_function("addressing/map_to_point_F256", |b| {
        b.iter(|| map_to_point::<F256>(label::STORAGE, black_box(b"a-storage-key")));
    });
}

fn coherence(c: &mut Criterion) {
    // A 7x7 coherence matrix's Frobenius sum — the DIAKRISIS Φ/P kernel (portable_simd).
    let matrix: Vec<f64> = (0..49).map(|i| f64::from(i) * 0.013 - 0.3).collect();
    c.bench_function("coherence/frobenius_sq_49", |b| {
        b.iter(|| frobenius_sq(black_box(&matrix)));
    });
}

criterion_group!(benches, rendezvous, addressing, coherence);
criterion_main!(benches);
