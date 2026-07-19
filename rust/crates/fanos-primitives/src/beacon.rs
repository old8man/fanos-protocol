//! The randomness-beacon seed type (audit E5, spec §L3).
//!
//! A [`BeaconSeed`] is the 32-byte public output of the per-epoch distributed randomness beacon
//! (produced by `fanos_vrf::beacon`): unpredictable before its epoch, then public and agreed within it.
//! It is folded into the rendezvous meeting-line and descriptor-key derivations ([`crate::vrf`],
//! `fanos_calypso::rendezvous`) so a *future* epoch's meeting point cannot be computed in advance —
//! the defence against an adversary pre-positioning on a service's rendezvous line (spec §5.6, §L3).
//!
//! The seed is **public**, not secret: it carries no key material, so it is `Copy` and freely logged.
//! Secrecy is never the beacon's job — unpredictability-until-revealed and unbiasability are, and those
//! live in the beacon's threshold construction, not in this value.

/// A per-epoch randomness-beacon seed — 32 bytes of public, unpredictable-ahead randomness (see the
/// module docs). Folded into every rendezvous derivation so meeting points rotate unpredictably.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct BeaconSeed([u8; 32]);

impl BeaconSeed {
    /// The bootstrap seed for epochs before the first live beacon round — a well-known all-zero value,
    /// so a meeting-line derivation is always total. It is public and predictable, so a pre-beacon epoch
    /// is only as unpredictable as the pre-E5 build; a live deployment must run the beacon before relying
    /// on rendezvous unpredictability. Using it knowingly at genesis is explicit, not an accident.
    pub const GENESIS: BeaconSeed = BeaconSeed([0u8; 32]);

    /// Wrap 32 seed bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 seed bytes, for folding into a derivation hash or a wire encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for BeaconSeed {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
