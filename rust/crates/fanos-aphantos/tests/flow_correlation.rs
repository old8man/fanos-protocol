//! **C1 — traffic-confirmation / flow-correlation attack** (the dominant threat on low-latency
//! anonymity networks: Tor flow correlation, RAPTOR, DeepCorr). A global-ish adversary that can *count*
//! the cells a relay emits over time wants that observable output flow to track the relay's real input
//! flow — if it does, the adversary confirms which flow the relay carries by correlating the two.
//!
//! FANOS's defense is constant-rate cover (audit E1): a relay emits an indistinguishable cover cell on
//! a schedule, so its send pattern should be the same whether or not it is forwarding real traffic. The
//! calibrated question this measures is the one that matters: **does the relay's emitted cell volume
//! over a fixed run depend on how much real traffic it forwarded?** If output volume is independent of
//! input volume, the volume channel the adversary correlates on carries no signal.
//!
//! The measurement drives the real `NyxNode` engine over a deterministic virtual-time line, firing its
//! timers and injecting real cells, and counts every emitted cell. The *leak slope* dE/dN — extra
//! emitted cells per extra real cell forwarded — is the adversary's signal: `≈ 1` means real traffic
//! adds observable volume (a fingerprint), `≈ 0` means real traffic displaces cover and the flow is
//! hidden.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::sealed::{self, ONION_LEN};
use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F31;
use fanos_geometry::Point;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant, TimerToken};

fn keypair(seed: &[u8]) -> (HybridKemSecret, HybridKemPublic) {
    let mut rng = SeedRng::from_seed(seed);
    HybridKemSecret::generate(&mut rng)
}

/// A distinct real cell (fresh encapsulation per `ctr`, so the replay cache never drops it) sealed to
/// `relay` and delivering to `dest`, wrapped as the Tessera frame a relay receives.
fn real_frame(relay: &HybridKemPublic, dest: &HybridKemPublic, ctr: u64) -> Vec<u8> {
    let circuit =
        fanos_nyx::build_circuit(Point::<F31>::at(1), Point::<F31>::at(9), 2, b"flow").unwrap();
    let mut seed = b"cell-".to_vec();
    seed.extend_from_slice(&ctr.to_be_bytes());
    let onion = sealed::build(&circuit, &[relay, dest], b"payload", &seed).unwrap();
    assert_eq!(onion.len(), ONION_LEN);
    let mut frame = Vec::new();
    fanos_wire::encode_frame(fanos_wire::FrameType::Tessera.code(), &onion, &mut frame);
    frame
}

const MS: u64 = 1_000_000; // ns per ms

/// Run a cover-enabled relay over a `2000 ms` virtual-time line, injecting `real_cells` distinct real
/// cells spread over the first half, and return the total number of cells the relay emitted (real
/// forwards + cover). Deterministic: a fixed 1 ms tick fires the node's armed timers in order.
fn emissions(cover_ms: u64, delay_ms: u64, real_cells: usize) -> usize {
    let (secret_r, public_r) = keypair(b"flow-relay");
    let (_sd, public_d) = keypair(b"flow-dest");

    // A directory of cover destinations (a relay sends cover to a pseudo-random known peer).
    let mut dir = Directory::new();
    for i in 0..7u8 {
        dir.insert(
            Point::<F31>::at(usize::from(i) + 10).coords(),
            keypair(&[0xE, i]).1,
        );
    }
    let mut node = NyxNode::new(Point::<F31>::at(3), secret_r, dir, [0x5A; 32], [0u8; 32], 2)
        .with_mixing(
            Duration::from_millis(delay_ms),
            Duration::from_millis(cover_ms),
        );

    let from = Point::<F31>::at(0).coords();
    let mut now = 0u64;
    let mut armed: Vec<(u64, TimerToken)> = Vec::new();
    let mut emitted = 0usize;

    // Process a batch of effects: count sends, schedule armed timers.
    macro_rules! absorb {
        ($effects:expr) => {
            for e in $effects {
                match e {
                    Effect::Send { .. } => emitted += 1,
                    Effect::ArmTimer { token, after } => {
                        armed.push((now + after.as_nanos() as u64, token));
                    }
                    Effect::Notify(_) => {}
                }
            }
        };
    }

    absorb!(node.step(Instant(now), Input::Command(Command::StartHeartbeat)));

    let total = 2000 * MS;
    let half = total / 2;
    // Injection schedule: `real_cells` evenly spread over the first half.
    let step = if real_cells == 0 {
        half
    } else {
        half / real_cells as u64
    };
    let mut next_inject = 0u64;
    let mut injected = 0usize;
    let mut ctr = 0u64;

    while now < total {
        now += MS;
        // Fire every timer now due (a fired cover timer re-arms; a mix-delay timer releases a forward).
        let due: Vec<TimerToken> = armed
            .iter()
            .filter(|(d, _)| *d <= now)
            .map(|(_, t)| *t)
            .collect();
        armed.retain(|(d, _)| *d > now);
        for token in due {
            absorb!(node.step(Instant(now), Input::Timer(token)));
        }
        // Inject the real cells scheduled by now.
        while injected < real_cells && next_inject <= now {
            ctr += 1;
            let frame = real_frame(&public_r, &public_d, ctr);
            absorb!(node.step(Instant(now), Input::Message { from, frame }));
            injected += 1;
            next_inject += step;
        }
    }
    emitted
}

/// The leak slope dE/dN — extra emitted cells per extra real cell forwarded — is the adversary's
/// volume signal. Under constant-rate cover (real displaces cover) it is ≈ 0; under *additive* cover
/// (real adds volume on top of cover) it is ≈ 1, a flow fingerprint.
#[test]
fn a_relays_emitted_volume_does_not_leak_its_real_traffic_volume() {
    let (cover_ms, delay_ms) = (10u64, 5u64);
    let e0 = emissions(cover_ms, delay_ms, 0);
    let e30 = emissions(cover_ms, delay_ms, 30);
    let e60 = emissions(cover_ms, delay_ms, 60);

    // Extra emitted cells per extra real cell — averaged over the 0→60 span.
    let slope = (e60 as f64 - e0 as f64) / 60.0;
    eprintln!(
        "[C1 flow-corr] emissions: N=0 -> {e0}, N=30 -> {e30}, N=60 -> {e60}; leak slope dE/dN = {slope:.3}"
    );

    assert!(
        slope < 0.15,
        "the relay's emitted volume tracks its real traffic (leak slope {slope:.3} ≈ 1): a flow \
         fingerprint. Constant-rate cover must displace cover with real cells, not add to it."
    );
}
