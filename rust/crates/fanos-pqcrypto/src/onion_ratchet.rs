//! Forward-secure per-epoch onion keys (audit E4).
//!
//! A threshold onion seals each hop to its line members' KEM keys. If those are a relay's **long-term**
//! keys, a global passive adversary that records onion ciphertexts and later compromises a relay's
//! secret decrypts every past hop through it — the standard mixnet forward-secrecy failure.
//!
//! [`OnionKeyRatchet`] gives each relay a **separate, rotating** onion-decap keypair — distinct from the
//! long-term *identity* KEM key in its node-ID bundle (rotating that would change `node_id`). The relay
//! keeps only the current epoch's key material; advancing overwrites the seed with a one-way hash, so a
//! compromise of the current state yields the current and all future keys but **never a past one**. An
//! onion recorded at epoch `e` becomes undecryptable once the relay ratchets past `e`.
//!
//! The genesis `seed` MUST be fresh entropy in production (a driver CSPRNG draw), **not** derived from
//! the node's long-term identity key — otherwise a compromise of that key would recompute every epoch's
//! onion key and the forward secrecy would be illusory. Under the deterministic simulator a fixed seed
//! is used: the ratchet's one-way property (and hence FS) is structural, independent of the seed source.

use fanos_primitives::hash::label;
use fanos_primitives::{Epoch, hash_labeled};

use crate::kem::{HybridKemPublic, HybridKemSecret};
use crate::rng::SeedRng;

/// A relay's forward-secure onion keypair for the current epoch (see the module docs).
pub struct OnionKeyRatchet {
    /// The current epoch's key seed. Overwritten one-way on every [`advance_to`](Self::advance_to), so a
    /// captured value cannot reconstruct any earlier epoch's seed.
    seed: [u8; 32],
    epoch: Epoch,
    secret: HybridKemSecret,
    public: HybridKemPublic,
}

impl OnionKeyRatchet {
    /// A ratchet whose epoch-`epoch` keypair is derived from `seed`. In production `seed` is a fresh
    /// CSPRNG draw discarded after this call keeps only the derived state; in the simulator it is a fixed
    /// test seed.
    #[must_use]
    pub fn new(seed: [u8; 32], epoch: Epoch) -> Self {
        let (secret, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&seed));
        Self {
            seed,
            epoch,
            secret,
            public,
        }
    }

    /// The epoch this ratchet's current keypair belongs to.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The current epoch's **public** onion key — the value the relay publishes for clients to seal to.
    #[must_use]
    pub fn public(&self) -> &HybridKemPublic {
        &self.public
    }

    /// The current epoch's **secret** onion key — what the relay decapsulates its Shamir shares with.
    #[must_use]
    pub fn secret(&self) -> &HybridKemSecret {
        &self.secret
    }

    /// Advance to `target` (a no-op if already at or past it). Each step overwrites the seed with
    /// `H(seed)` — a one-way hash — so past epochs' seeds (and thus keys) become unrecoverable, and
    /// re-derives the current keypair once at the end. The old [`HybridKemSecret`] is dropped (zeroized).
    /// Returns `true` iff the epoch actually moved, so a caller re-publishes only on a real advance.
    pub fn advance_to(&mut self, target: Epoch) -> bool {
        let moved = target > self.epoch;
        while self.epoch < target {
            self.seed = hash_labeled(label::ONION_RATCHET, &self.seed);
            self.epoch = self.epoch.next();
        }
        if moved {
            let (secret, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&self.seed));
            self.secret = secret; // the previous epoch's secret is dropped and zeroized here
            self.public = public;
        }
        moved
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_ratchet_that_advances_cannot_decrypt_a_past_epochs_onion() {
        // Relay at epoch 0. A client seals an onion layer to its epoch-0 public key.
        let mut relay = OnionKeyRatchet::new([7u8; 32], Epoch::ZERO);
        let epoch0_public = relay.public().clone();
        let (ciphertext, sealed_key) =
            epoch0_public.encapsulate(&mut SeedRng::from_seed(b"client"));

        // At epoch 0 the relay decapsulates it correctly.
        assert_eq!(
            relay.secret().decapsulate(&ciphertext),
            sealed_key,
            "the current-epoch relay peels a current-epoch onion"
        );

        // The relay ratchets forward (three epochs pass). The epoch-0 seed is overwritten one-way.
        assert!(relay.advance_to(Epoch::new(3)));
        assert_eq!(relay.epoch(), Epoch::new(3));

        // Forward secrecy: the relay can NO LONGER recover the epoch-0 onion's key — the epoch-0 secret is
        // gone and the current secret decapsulates to unrelated (implicit-reject) key material.
        assert_ne!(
            relay.secret().decapsulate(&ciphertext),
            sealed_key,
            "a past-epoch onion is unrecoverable after the ratchet advances (relay forward secrecy)"
        );
        // And the published key genuinely rotated.
        assert_ne!(
            relay.public().encode(),
            epoch0_public.encode(),
            "the onion public key rotates each epoch"
        );
    }

    #[test]
    fn advancing_is_deterministic_and_idempotent_within_an_epoch() {
        let mut a = OnionKeyRatchet::new([9u8; 32], Epoch::ZERO);
        let mut b = OnionKeyRatchet::new([9u8; 32], Epoch::ZERO);
        // Same seed → same rotation sequence (a relay resuming from its persisted seed re-derives the
        // same current key; a client resolving the published key seals to a matching one).
        assert!(a.advance_to(Epoch::new(5)));
        assert!(b.advance_to(Epoch::new(5)));
        assert_eq!(a.public().encode(), b.public().encode());
        // Re-advancing to the same or an earlier epoch is a no-op and does not move the key.
        assert!(!a.advance_to(Epoch::new(5)));
        assert!(!a.advance_to(Epoch::new(2)));
        assert_eq!(a.public().encode(), b.public().encode());
    }
}
