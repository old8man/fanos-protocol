//! Adversarial probe: what does it cost to evict a chosen victim by grinding identities?
//!
//! The rank rule (`fanos_quic::Directory::insert_ranked`) decides a coordinate collision by VRF output, on the stated
//! grounds that "arrival order is attacker-controlled; rank is not". This measures whether an attacker who *chooses its
//! identity* can manufacture a favourable rank at a chosen point.
fn main() {
    use fanos_primitives::{BeaconSeed, Epoch};
    use fanos_vrf::{VrfSecret, outranks, prove_coordinate_ranked};
    use fanos_field::{F2, F4};

    let epoch = Epoch::new(9);
    let beacon = BeaconSeed::GENESIS;

    // The victim: an ordinary honest node.
    macro_rules! run {
        ($F:ty, $name:expr, $points:expr) => {{
            let victim_sk = VrfSecret::from_seed([7u8; 32]);
            let (vcoord, _, vrank) = prove_coordinate_ranked::<$F>(&victim_sk, b"victim", epoch, &beacon);
            let mut draws = 0u64;
            let mut found = None;
            for i in 0..2_000_000u64 {
                draws += 1;
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&i.to_le_bytes());
                let sk = VrfSecret::from_seed(seed);
                let id = i.to_be_bytes();
                let (c, _, rank) = prove_coordinate_ranked::<$F>(&sk, &id, epoch, &beacon);
                if c == vcoord && outranks(&rank, &vrank) {
                    found = Some(i);
                    break;
                }
            }
            println!(
                "{:<10} points={:<5} victim at {:?} -> collision-with-lower-rank after {} identity draws (found={})",
                $name, $points, vcoord.coords(), draws, found.is_some()
            );
        }};
    }
    run!(F2, "PG(2,2)", 7);
    run!(F4, "PG(2,4)", 21);
}
