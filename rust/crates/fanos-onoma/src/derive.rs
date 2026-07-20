//! Per-epoch descriptor derivations — what makes ONOMA services **unenumerable** and
//! **address-gated** (`docs/design-names.md` §5).
//!
//! * [`lookup_key`] / [`lookup_point`] — the rotating store index `L = H(payload ‖ epoch)` and the
//!   projective coordinate `MapToPoint(L)` the descriptor lives at. Without the address, `L` is
//!   unguessable and one-way, so storage nodes cannot enumerate or confirm the services they hold.
//! * [`descriptor_key`] — the per-epoch symmetric key `K = H(payload ‖ epoch)` (distinct domain)
//!   the descriptor is encrypted under, so only holders of the address can decrypt it.
//!
//! Both rotate every epoch, giving forward secrecy across epochs.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Point;
use fanos_primitives::hash::{DIGEST_LEN, hash_labeled, label};
use fanos_primitives::{Epoch, storage_point};

use crate::address::Address;

/// `payload(addr) ‖ epoch_le` — the common pre-image for the epoch derivations.
fn epoch_input(addr: &Address, epoch: Epoch) -> Vec<u8> {
    let payload = addr.payload();
    let mut v = Vec::with_capacity(payload.len() + 8);
    v.extend_from_slice(&payload);
    v.extend_from_slice(&epoch.to_le_bytes());
    v
}

/// The rotating, unenumerable **lookup key** `L = H(addr ‖ epoch)` used to index the descriptor.
#[must_use]
pub fn lookup_key(addr: &Address, epoch: Epoch) -> [u8; DIGEST_LEN] {
    hash_labeled(label::ONOMA_LOOKUP, &epoch_input(addr, epoch))
}

/// The per-epoch descriptor **encryption key** `K = H(addr ‖ epoch)` (address-gated confidentiality).
#[must_use]
pub fn descriptor_key(addr: &Address, epoch: Epoch) -> [u8; DIGEST_LEN] {
    hash_labeled(label::ONOMA_ENC, &epoch_input(addr, epoch))
}

/// The projective coordinate the descriptor's replica line is anchored at — geometry-routed and
/// directory-free.
///
/// A descriptor is stored under its lookup **key** ([`lookup_key`]), and the DHT re-hashes that key on
/// its **storage** domain to choose the replica line (`fanos_primitives::storage_point`). So the actual
/// coordinate is `storage_point(lookup_key)`, NOT a direct `MapToPoint` of the lookup pre-image — this
/// derives it correctly, in lock-step with where the resolver's put/get land (audit #128/C5: the old
/// single-hash form named a *different* point, so code routing by it would have missed the descriptor).
#[must_use]
pub fn lookup_point<F: Field>(addr: &Address, epoch: Epoch) -> Point<F> {
    storage_point::<F>(&lookup_key(addr, epoch))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::F7;

    fn addr() -> Address {
        Address::from_bundle(b"onoma-derive-test-bundle")
    }

    #[test]
    fn lookup_and_enc_keys_differ_by_domain() {
        let a = addr();
        assert_ne!(
            lookup_key(&a, Epoch::new(5)),
            descriptor_key(&a, Epoch::new(5))
        );
    }

    #[test]
    fn derivations_rotate_per_epoch() {
        let a = addr();
        assert_ne!(lookup_key(&a, Epoch::new(5)), lookup_key(&a, Epoch::new(6)));
        assert_ne!(
            descriptor_key(&a, Epoch::new(5)),
            descriptor_key(&a, Epoch::new(6))
        );
        assert_ne!(
            lookup_point::<F7>(&a, Epoch::new(5)),
            lookup_point::<F7>(&a, Epoch::new(6))
        );
    }

    #[test]
    fn derivations_are_deterministic() {
        let a = addr();
        assert_eq!(lookup_key(&a, Epoch::new(9)), lookup_key(&a, Epoch::new(9)));
        assert_eq!(
            lookup_point::<F7>(&a, Epoch::new(9)),
            lookup_point::<F7>(&a, Epoch::new(9))
        );
    }

    #[test]
    fn lookup_point_is_the_actual_storage_anchor() {
        // #128/C5 lock-step: the descriptor lives where the DHT stores its lookup KEY —
        // storage_point(lookup_key), exactly where the resolver's Client::put/get land — never a direct
        // MapToPoint of the lookup pre-image. Guards against the two ever drifting apart again.
        let a = addr();
        let e = Epoch::new(11);
        assert_eq!(
            lookup_point::<F7>(&a, e),
            storage_point::<F7>(&lookup_key(&a, e))
        );
    }

    #[test]
    fn distinct_addresses_do_not_collide() {
        let a = Address::from_bundle(b"service-a");
        let b = Address::from_bundle(b"service-b");
        assert_ne!(lookup_key(&a, Epoch::new(1)), lookup_key(&b, Epoch::new(1)));
    }
}
