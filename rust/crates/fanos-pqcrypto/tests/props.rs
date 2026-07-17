//! Property tests: the real hybrid KEM and signatures over random seeds and messages.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_pqcrypto::{HybridKemSecret, HybridSigSecret, Identity, SeedRng};
use proptest::prelude::*;

proptest! {
    // Post-quantum keygen is heavier than field arithmetic; a few dozen random runs per
    // property is enough to catch integration mistakes, and each is deterministic per seed.
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Hybrid KEM: sender and receiver always agree on the session key.
    #[test]
    fn kem_encapsulation_agrees(seed in proptest::collection::vec(any::<u8>(), 1..48)) {
        let mut rng = SeedRng::from_seed(&seed);
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        let (ciphertext, sender_key) = public.encapsulate(&mut rng);
        prop_assert_eq!(secret.decapsulate(&ciphertext), sender_key);
    }

    /// Hybrid signature: a valid signature verifies; a tampered message does not.
    #[test]
    fn signature_round_trips(
        seed in proptest::collection::vec(any::<u8>(), 1..48),
        message in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut rng = SeedRng::from_seed(&seed);
        let (secret, verifier) = HybridSigSecret::generate(&mut rng);
        let signature = secret.sign(&message);
        prop_assert!(verifier.verify(&message, &signature));
        if !message.is_empty() {
            let mut tampered = message.clone();
            tampered[0] ^= 1;
            prop_assert!(!verifier.verify(&tampered, &signature));
        }
    }

    /// Node identities are deterministic per seed and distinct across seeds.
    #[test]
    fn identity_node_ids_are_stable(seed_a in any::<u64>(), seed_b in any::<u64>()) {
        prop_assume!(seed_a != seed_b);
        let mut rng_a = SeedRng::from_seed(&seed_a.to_le_bytes());
        let mut rng_b = SeedRng::from_seed(&seed_b.to_le_bytes());
        let a = Identity::generate(&mut rng_a);
        let b = Identity::generate(&mut rng_b);
        prop_assert_eq!(a.node_id(), a.node_id());
        prop_assert_ne!(a.node_id(), b.node_id());
    }
}
