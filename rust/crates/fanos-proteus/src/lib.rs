//! # fanos-proteus — polymorphic transport & censorship resistance (Part XIII)
//!
//! An **optional, off-by-default** obfuscation layer built on the winning principle "look like
//! nothing, and look different at every deployment", plus one FANOS-native amplifier: the epoch
//! beacon *rotates the polymorphism*, so the signature also moves in time. It costs nothing
//! when the network is open.
//!
//! * [`morph`] — the obfuscation modes and per-environment fallback policy (§13.3, §13.7).
//! * [`shape`] — beacon-rotating shape `θ_epoch` (§13.4).
//! * [`obfuscate`] — the `polymorph` codec (§13.2).
//! * [`profile`] — the traffic-shaper: per-morph size + timing targets (§13.3, §13.1).
//! * [`shaper`] — the driver-facing [`ProteusShaper`]: morph-dispatched codec + shaping.
//! * [`bridge`] — moving-target bridges, no static list to block (§13.6).
//!
//! This layer does not end the arms race (spec §13.8); it makes the censor's cost recur every
//! epoch. The primitives are vetted; the novelty is beacon-rotating polymorphism + moving-target
//! bridges — no new hardness assumptions.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod bridge;
pub mod morph;
pub mod obfuscate;
pub mod profile;
pub mod shape;
pub mod shaper;

pub use bridge::{bridge_line, client_bridge_lines, reachable_fraction};
pub use fanos_primitives::Epoch;
pub use morph::{Environment, Morph};
pub use obfuscate::{deobfuscate, obfuscate};
pub use profile::ShapingProfile;
pub use shape::{ShapeParams, epoch_shape};
pub use shaper::{ProteusShaper, Shaped};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! The PROTEUS flow: pick a morph for the environment, shape the wire per epoch, obfuscate,
    //! and reach a moving-target bridge — all keyed by a shared community secret.
    use super::*;
    use fanos_field::F31;

    #[test]
    fn end_to_end_polymorph_flow() {
        let secret = b"community-bridge-secret";
        let epoch = Epoch::new(77);

        // A client in a censored environment selects the flagship morph.
        let env = Environment::DeepCensorship;
        assert_eq!(env.preferred_morph(), Morph::Polymorph);

        // It derives this epoch's shape and obfuscates a transport packet with a per-packet nonce.
        let shape = epoch_shape(secret, epoch);
        let packet = b"encrypted FANOS transport frame";
        let wire = obfuscate(&shape, packet, &[0u8; obfuscate::NONCE_LEN]);

        // The bridge (holding the same secret) derives the same shape and strips it.
        let bridge_shape = epoch_shape(secret, epoch);
        assert_eq!(deobfuscate(&bridge_shape, &wire).unwrap(), packet);

        // The client reaches the bridge at the epoch's moving-target line, which rotates.
        let entry = bridge_line::<F31>(secret, epoch);
        assert_ne!(entry, bridge_line::<F31>(secret, epoch.next()));
    }

    #[test]
    fn a_censor_must_re_enumerate_every_epoch() {
        use alloc::collections::BTreeSet;
        // The censor blocks this epoch's observed bridge lines; next epoch they have decayed.
        let secret = b"s";
        let mut blocked = BTreeSet::new();
        for e in 0u64..50 {
            blocked.insert(bridge_line::<F31>(secret, Epoch::new(e)).index());
        }
        // Over the *next* 5000 epochs the client is still reachable most of the time, because
        // the blocked set (≈50 lines of 993) barely dents future bridges.
        let reachable = reachable_fraction::<F31>(secret, &blocked, 5000);
        assert!(reachable > 0.9, "reachable={reachable}");
    }
}
