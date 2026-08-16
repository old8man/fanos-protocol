//! Criterion micro-benchmarks for the FANOS hot paths — the operations that dominate a running
//! node: O(1) rendezvous (the cross product), storage/identity addressing (`MapToPoint` + hash),
//! and the DIAKRISIS coherence kernel (the SIMD Frobenius sum). Run: `cargo bench -p fanos-bench`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use fanos_aphantos::threshold_onion::{HopLine, member_partial, seal_onion};
use fanos_diakrisis::coherence::frobenius_sq;
use fanos_field::{F4, F7, F256};
use fanos_geometry::{Point, cross};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_primitives::hash::label;
use fanos_primitives::{hash_labeled, map_to_point};

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

/// The three arms a line member can take when a combiner asks it for a partial — and they cost
/// **different amounts of time**, which is the residual `ThresholdRouter::decoy_share` records.
///
/// The decoy reply made refusal indistinguishable by *width*. It cannot make it indistinguishable by
/// *latency*, because `member_partial_detailed` parses slot 0 first and only then decapsulates, and the
/// router tries every mixing secret it holds (`find_map`). So a cover cell fails the parse `k` times and a
/// cargo cell addressed elsewhere pays `k` hybrid `X25519 ‖ ML-KEM-768` decapsulations — both answering
/// with a decoy, at costs that differ by whatever this benchmark says.
///
/// One member, one secret (`k = 1`), which is the lower bound on the gap: a node holding more secrets
/// multiplies both arms and widens it.
fn threshold_gather(c: &mut Criterion) {
    let keys: Vec<(HybridKemSecret, HybridKemPublic)> =
        (0..5u8).map(|i| HybridKemSecret::generate(&mut SeedRng::from_seed(&[55, i]))).collect();
    let pubs: Vec<&HybridKemPublic> = keys.iter().map(|(_, p)| p).collect();
    let hop = HopLine { line: Point::<F4>::at(1).coords(), members: &pubs };
    // The fixture is total — five generated keypairs, a fixed line, threshold 3 — so neither arm below can
    // be taken. They are written as early returns rather than a panic because a bench is shipping code to
    // `no_shipping_code_panics_on_an_impossibility_claim`, and the visible consequence of the impossible
    // case is three missing benchmark lines, not a wrong number.
    let Ok(onion) = seal_onion(&[hop], 3, b"deliver me", b"seed") else { return };
    let (Some((ours, _)), Some((other, _))) = (keys.first(), keys.get(2)) else { return };
    // A cover cell is keystream at the same width — indistinguishable on the wire, and it fails at the parse.
    let cover: Vec<u8> = (0..onion.len()).map(|i| (i * 131 + 7) as u8).collect();

    // Ok: parse, decapsulate, open. What a member addressed by this cell pays.
    c.bench_function("gather/partial_cargo_ours", |b| {
        b.iter(|| member_partial::<F4>(black_box(&onion), 0, ours));
    });
    // KeyMismatch: parse, then decapsulate to nothing. A cargo cell this member cannot answer — decoy arm.
    c.bench_function("gather/partial_cargo_not_ours", |b| {
        b.iter(|| member_partial::<F4>(black_box(&onion), 0, other));
    });
    // Malformed: the parse rejects it before any KEM work. A cover cell — the same decoy arm, cheaper.
    c.bench_function("gather/partial_cover", |b| {
        b.iter(|| member_partial::<F4>(black_box(&cover), 0, ours));
    });
    // How much of the arm above the parse is the KEM alone, and how much the AEAD open over a 20 KB
    // onion — which decides whether equalising the decoy path needs one decapsulation or a whole
    // well-formed probe onion. A genuinely encapsulated ciphertext, because `decapsulate` early-returns
    // on a non-contributory X25519 leg and a degenerate probe would measure that early return instead.
    let (Some((_, ours_pub)), Some(mut rng)) = (keys.first(), Some(SeedRng::from_seed(b"probe"))) else {
        return;
    };
    let Some((ct, _)) = ours_pub.encapsulate(&mut rng) else { return };
    c.bench_function("gather/hybrid_decapsulate", |b| {
        b.iter(|| ours.decapsulate(black_box(&ct)));
    });
}

criterion_group!(benches, rendezvous, addressing, coherence, threshold_gather);
criterion_main!(benches);
