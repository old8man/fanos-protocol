//! Forward-secure per-epoch onion keys (audit E4).
//!
//! A threshold onion seals each hop to its line members' KEM keys. If those are a relay's **long-term**
//! keys, a global passive adversary that records onion ciphertexts and later compromises a relay's
//! secret decrypts every past hop through it — the standard mixnet forward-secrecy failure.
//!
//! [`OnionKeyRatchet`] gives each relay a **separate, rotating** onion-decap keypair — distinct from the
//! long-term *identity* KEM key in its node-ID bundle (rotating that would change `node_id`). Advancing
//! overwrites the seed with a one-way hash, so a compromise of the current state yields the current and
//! all future keys but **never** one older than the retention window below. An onion recorded at epoch
//! `e` becomes undecryptable once the relay ratchets more than `retain` epochs past `e`.
//!
//! ## The grace window (`retain`)
//!
//! Rotation and delivery race at every epoch boundary: a client seals an onion to the directory's
//! current key, but by the time it reaches a relay the relay may have rotated. If the relay kept *only*
//! the current secret, every rotation would silently drop the onions in flight across it — a periodic
//! liveness hole synchronised to the epoch clock. So the relay keeps a **bounded window** of the most
//! recent `retain` epochs' secrets (default 1) and tries them oldest-allowed-first on decap; anything
//! older is dropped and zeroized. This is the standard liveness/forward-secrecy boundary contract: FS
//! exposure is bounded to `retain` epochs (never the unbounded long-term key), while in-flight onions
//! still peel across a single rotation. `retain = 0` is fail-closed (only the current epoch peels).
//! Only epochs the ratchet actually *stopped at* are retained — a multi-epoch catch-up jump (a relay
//! resuming after downtime) materialises no intermediate key, so those epochs are unrecoverable.
//!
//! The genesis `seed` MUST be fresh entropy in production (a driver CSPRNG draw), **not** derived from
//! the node's long-term identity key — otherwise a compromise of that key would recompute every epoch's
//! onion key and the forward secrecy would be illusory. Under the deterministic simulator a fixed seed
//! is used: the ratchet's one-way property (and hence FS) is structural, independent of the seed source.

use alloc::collections::VecDeque;

use fanos_primitives::hash::label;
use fanos_primitives::{Epoch, hash_labeled};

use crate::kem::{HybridKemPublic, HybridKemSecret};
use crate::rng::SeedRng;

/// Default retention window: keep the immediately previous epoch's secret decap-able so onions in
/// flight across one rotation still peel (see the module's grace-window docs).
const DEFAULT_RETAIN: usize = 1;

/// A relay's forward-secure onion keypair for the current epoch, plus a bounded window of recent
/// epochs' secrets for graceful rotation (see the module docs).
pub struct OnionKeyRatchet {
    /// The current epoch's key seed. Overwritten one-way on every [`advance_to`](Self::advance_to), so a
    /// captured value cannot reconstruct any earlier epoch's seed.
    seed: [u8; 32],
    epoch: Epoch,
    secret: HybridKemSecret,
    public: HybridKemPublic,
    /// How many *past* epochs stay decap-able after rotation — the grace window. `0` is fail-closed.
    retain: usize,
    /// The retained `(epoch, secret)` of the most recent rotations, newest at the front, holding at most
    /// `retain` entries all within `retain` epochs of the current one. Evicted (and zeroized) once they
    /// fall outside the window, so forward-secrecy exposure never exceeds `retain` epochs.
    recent: VecDeque<(Epoch, HybridKemSecret)>,
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
            retain: DEFAULT_RETAIN,
            recent: VecDeque::new(),
        }
    }

    /// Set the grace window: how many *past* epochs stay decap-able after rotation (see the module's
    /// grace-window docs). `0` is fail-closed — only the current epoch peels, so an onion in flight
    /// across a rotation is dropped. The default ([`new`](Self::new)) is `1`. Truncates any already
    /// retained secrets to the new window.
    #[must_use]
    pub fn with_retain(mut self, retain: usize) -> Self {
        self.retain = retain;
        self.recent.truncate(retain);
        self
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

    /// The current epoch's **secret** onion key — what the relay decapsulates a *current-epoch* Shamir
    /// share with. To also peel onions in flight across a recent rotation, decapsulate against every key
    /// in [`secrets`](Self::secrets) instead — that is what the relay engine does.
    #[must_use]
    pub fn secret(&self) -> &HybridKemSecret {
        &self.secret
    }

    /// Every onion secret the relay will currently accept: the current epoch's, then the retained
    /// grace-window epochs' (newest first). A relay tries each in turn on decap, so an onion sealed for
    /// any epoch in the window `[epoch − retain, epoch]` still peels; onions older than the window match
    /// none and are unrecoverable (forward secrecy). In steady state (no recent rotation) this yields
    /// only the current secret, so the common path is a single decap.
    pub fn secrets(&self) -> impl Iterator<Item = &HybridKemSecret> {
        core::iter::once(&self.secret).chain(self.recent.iter().map(|(_, secret)| secret))
    }

    /// Advance to `target` (a no-op if already at or past it). Each step overwrites the seed with
    /// `H(seed)` — a one-way hash — so past epochs' seeds (and thus keys) become unrecoverable, and
    /// re-derives the current keypair once at the end. The epoch just left is moved into the grace
    /// window ([`secrets`](Self::secrets)); anything now older than `retain` epochs is dropped and
    /// zeroized. Returns `true` iff the epoch actually moved, so a caller re-publishes only on a real
    /// advance.
    pub fn advance_to(&mut self, target: Epoch) -> bool {
        if target <= self.epoch {
            return false;
        }
        let leaving = self.epoch;
        while self.epoch < target {
            self.seed = hash_labeled(label::ONION_RATCHET, &self.seed);
            self.epoch = self.epoch.next();
        }
        let (secret, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&self.seed));
        // Retain the epoch we just left in the grace window (newest first), then evict any entry now more
        // than `retain` epochs behind the current one — a single-step advance keeps exactly the last
        // `retain` epochs, while a multi-epoch catch-up jump leaves its stale outgoing key outside the
        // window and it is dropped at once (bounding FS exposure to `retain` epochs, never more).
        let outgoing = core::mem::replace(&mut self.secret, secret);
        self.public = public;
        if self.retain > 0 {
            self.recent.push_front((leaving, outgoing));
        }
        let cutoff = self.epoch.get().saturating_sub(self.retain as u64);
        while self
            .recent
            .back()
            .is_some_and(|(epoch, _)| epoch.get() < cutoff)
        {
            self.recent.pop_back();
        }
        self.recent.truncate(self.retain);
        true
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

        // The relay ratchets forward (three epochs pass, well past the retain=1 grace window). The
        // epoch-0 seed is overwritten one-way and epoch 0 falls out of the retained window.
        assert!(relay.advance_to(Epoch::new(3)));
        assert_eq!(relay.epoch(), Epoch::new(3));

        // Forward secrecy: NO key the relay still holds — current or retained — recovers the epoch-0
        // onion's key; the epoch-0 secret is gone and every live secret decapsulates to unrelated
        // (implicit-reject) key material.
        assert!(
            !relay
                .secrets()
                .any(|s| s.decapsulate(&ciphertext) == sealed_key),
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

    #[test]
    fn the_grace_window_peels_across_one_rotation_then_forward_secrecy_takes_over() {
        // retain = 1 (the default): an onion sealed to epoch 0 must still peel one rotation later (the
        // relay kept epoch 0 in its grace window), but must fail once the relay is TWO rotations on —
        // epoch 0 has fallen out of the window and its secret is gone (forward secrecy).
        let mut relay = OnionKeyRatchet::new([0x11; 32], Epoch::ZERO);
        let epoch0_public = relay.public().clone();
        let (ct, key) = epoch0_public.encapsulate(&mut SeedRng::from_seed(b"grace-client"));

        // Rotate once: epoch 0 is now the retained previous epoch, so some live relay secret still decaps.
        assert!(relay.advance_to(Epoch::new(1)));
        assert!(
            relay.secrets().any(|s| s.decapsulate(&ct) == key),
            "an onion in flight across one rotation still peels (grace window)"
        );
        // The CURRENT secret alone does not — only the retained one does, so the window is doing the work.
        assert_ne!(
            relay.secret().decapsulate(&ct),
            key,
            "the current epoch's key is a fresh key, not the epoch-0 one"
        );

        // Rotate again: epoch 0 falls outside the retain=1 window and is dropped — nothing decaps it now.
        assert!(relay.advance_to(Epoch::new(2)));
        assert!(
            !relay.secrets().any(|s| s.decapsulate(&ct) == key),
            "past the grace window the onion is unrecoverable (forward secrecy)"
        );
    }

    #[test]
    fn retain_zero_is_fail_closed_with_no_grace_window() {
        // with_retain(0): the previous epoch is NOT kept, so an onion in flight across a single rotation
        // is already unrecoverable — maximal forward secrecy at the cost of boundary liveness.
        let mut relay = OnionKeyRatchet::new([0x22; 32], Epoch::ZERO).with_retain(0);
        let (ct, key) = relay
            .public()
            .clone()
            .encapsulate(&mut SeedRng::from_seed(b"fc-client"));
        assert!(relay.advance_to(Epoch::new(1)));
        assert!(
            !relay.secrets().any(|s| s.decapsulate(&ct) == key),
            "with retain=0 even a single rotation drops the previous epoch's onion"
        );
        // `secrets()` yields exactly the current key — no retained entries.
        assert_eq!(relay.secrets().count(), 1);
    }

    #[test]
    fn a_multi_epoch_catch_up_jump_retains_no_stale_key() {
        // A relay resuming after downtime advances several epochs in one call. The epoch it left is
        // already outside the retain=1 window, so it is dropped immediately — a catch-up must not widen
        // forward-secrecy exposure beyond the window.
        let mut relay = OnionKeyRatchet::new([0x33; 32], Epoch::ZERO);
        let (ct, key) = relay
            .public()
            .clone()
            .encapsulate(&mut SeedRng::from_seed(b"jump-client"));
        assert!(relay.advance_to(Epoch::new(4))); // jump 0 → 4 in one call
        assert!(
            !relay.secrets().any(|s| s.decapsulate(&ct) == key),
            "a multi-epoch jump retains no key older than the window"
        );
        assert_eq!(
            relay.secrets().count(),
            1,
            "only the current key survives a catch-up jump"
        );
    }
}
