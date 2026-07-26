//! # fanos-nyx — the threshold-sheaf onion (L5 APHANTOS / NYX)
//!
//! NYX is FANOS's evolution of onion routing (spec Part V). It changes three things at once:
//!
//! * a hop is not a node but a **line** — a threshold group `t` of `q+1`, so no single node
//!   peels a layer and endpoint linkage drops to `P_hop²` ([`security`], and `sheaf` — see below);
//! * a path is not a random chain but a **geometric flag**, uniform by `PGL` transitivity and
//!   verifiable by algebra ([`path`]);
//! * **path integrity** comes from a **holonomic ratchet** on the incidence bundle ([`ratchet`]) — a
//!   path authenticator, not a source of forward secrecy (forward secrecy is a seed-hygiene property;
//!   see the [`ratchet`] and `fanos_aphantos::threshold` module docs).
//!
//! `tessera::Tessera` assembles these into a nested onion; [`mixing`] and [`profile`] provide
//! Poisson mixing and the configurable λ dial (one substrate, Tor-class to Nym+).
//!
//! The cryptographic primitives (ChaCha20-Poly1305, Shamir, BLAKE3) are vetted; the FANOS
//! novelty is composing them so a *line* is the unit of trust. Formal analysis of the packet
//! and ratchet is marked `[P]` in the specification.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod mathfns;

pub mod error;
pub mod guard;
pub mod mixing;
pub mod path;
pub mod profile;
pub mod ratchet;
pub mod security;

// The **transparent** onion forms, behind a non-default feature. Both carry Shamir shares in the CLEAR, so their
// below-threshold guarantee holds only if every share reaches its member over a private channel — an assumption the live
// path does not make. Production seals each share to its member's hybrid-KEM public key
// (`fanos_aphantos::threshold::ThresholdSealed`), which needs the post-quantum KEM and therefore cannot live in this
// `no_std` crate. Leaving these merely `pub` and documented was a footgun: an integrator reaching for the obvious name
// `fanos_nyx::Tessera` got the lower-assurance variant, and nothing failed to compile to tell them. Enabling
// `transparent-onion` is now a deliberate act — the simulator and the reference derivations want it; a deployment does not.
#[cfg(feature = "transparent-onion")]
pub mod sheaf;
#[cfg(feature = "transparent-onion")]
pub mod tessera;

pub use guard::GuardSet;
pub use path::{Circuit, build_circuit, build_circuit_via_guard};
pub use profile::{MixConfig, NyxConfig, Profile};
pub use ratchet::{Ratchet, circuit_holonomy, verify_holonomy};
pub use error::NyxError;
#[cfg(feature = "transparent-onion")]
pub use sheaf::ThresholdLayer;
#[cfg(feature = "transparent-onion")]
pub use tessera::{PeelResult, Tessera};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    //! End-to-end: build a geometric circuit, onion-route a payload through threshold hops,
    //! verify the holonomy, and confirm the security/anonymity numbers.
    use super::*;
    // Pathed through `crate::` rather than the re-exports, which are feature-gated: the transparent modules are always
    // compiled (private without `transparent-onion`), so the crate's own tests cover them at every feature setting.
    use fanos_field::F31;
    use fanos_geometry::Point;

    #[test]
    fn full_nyx_circuit_end_to_end() {
        // A 3-hop threshold circuit across the q=31 cell.
        let circuit =
            build_circuit(Point::<F31>::at(10), Point::<F31>::at(600), 3, b"session").unwrap();
        assert!(circuit.is_valid_flag_chain());

        let seed = [0x5Au8; 32];
        let (t, line_size) = (6u8, 8u8);
        let mut packet =
            Tessera::build(&circuit, b"hello anonymous world", t, line_size, &seed).unwrap();
        let holonomy = packet.holonomy();

        // Route it hop by hop; each hop peels with exactly t members.
        let mut hops_traversed = 0;
        let delivered = loop {
            let shares: Vec<_> = packet.current_hop_shares()[..usize::from(t)].to_vec();
            match packet.peel(&shares).unwrap() {
                PeelResult::Forward { packet: inner, .. } => {
                    assert_eq!(inner.holonomy(), holonomy);
                    hops_traversed += 1;
                    packet = inner;
                }
                PeelResult::Deliver { payload } => break payload,
            }
        };
        assert_eq!(delivered, b"hello anonymous world");
        assert_eq!(hops_traversed, 2, "3 hops → 2 forwards then a delivery");
    }

    #[test]
    fn security_and_anonymity_numbers_hold() {
        // The threshold curve (V5) and the mixing dial (V7) come from the same config.
        let cfg = NyxConfig::full(MixConfig::tor_class(), 6, 8).unwrap();
        let p_link =
            security::endpoint_linkage(u32::from(cfg.line_size), u32::from(cfg.threshold), 0.2);
        assert!(p_link < 2e-6, "endpoint linkage ≪ Tor's f² (V5)");
        let dial = cfg.mix.anonymity(50.0);
        assert!(
            dial.entropy_bits > 4.0,
            "mixing gives real anonymity entropy (V7)"
        );
    }
}
