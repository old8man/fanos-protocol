//! APHANTOS profiles and the λ (μ) dial — one substrate, configurable (spec §L5, §5.5).
//!
//! The same codebase serves three anonymity profiles by turning a dial; security ↔ latency is
//! a parameter, not a fork.

use crate::mixing::DialPoint;

/// The anonymity profile of a circuit (spec §L5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Profile {
    /// Open routing, minimum latency, no anonymity (libp2p/QUIC-class).
    Direct,
    /// Single-node Sphinx-class hops, PQ, low latency (≈ Tor, but PQ + unpredictable epochs).
    Lite,
    /// Threshold-line hops + verifiable mixing + Poisson delays (> Nym).
    Full,
}

impl Profile {
    /// Whether the profile provides anonymity at all.
    #[must_use]
    pub fn is_anonymous(self) -> bool {
        self != Self::Direct
    }

    /// Whether hops are threshold groups (`t` of `q+1`) — only the Full profile.
    #[must_use]
    pub fn uses_threshold(self) -> bool {
        self == Self::Full
    }

    /// A short description.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Direct => "open QUIC, no anonymity",
            Self::Lite => "Sphinx-class single-node hops, PQ (≈ Tor)",
            Self::Full => "threshold-line hops + verifiable mixing (> Nym)",
        }
    }
}

/// A mixing configuration — a point on the λ dial (spec §5.5).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct MixConfig {
    /// Poisson mixing rate `μ` (1/s); `0` disables mixing.
    pub mu: f64,
    /// Path length `L` (number of hops).
    pub hops: u32,
}

impl MixConfig {
    /// No mixing — for the Direct/Lite low-latency profiles.
    #[must_use]
    pub fn none(hops: u32) -> Self {
        Self { mu: 0.0, hops }
    }

    /// A low-latency, Tor-class operating point.
    #[must_use]
    pub fn tor_class() -> Self {
        Self { mu: 2.0, hops: 3 }
    }

    /// A high-anonymity, Nym+-class operating point.
    #[must_use]
    pub fn nym_plus() -> Self {
        Self { mu: 0.2, hops: 5 }
    }

    /// The anonymity metrics at this dial point given a system arrival rate.
    #[must_use]
    pub fn anonymity(self, arrival_rate: f64) -> DialPoint {
        DialPoint::new(self.mu, self.hops, arrival_rate)
    }
}

/// A full NYX circuit configuration.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct NyxConfig {
    /// The anonymity profile.
    pub profile: Profile,
    /// The mixing dial.
    pub mix: MixConfig,
    /// The per-hop threshold `t` (Full profile).
    pub threshold: u8,
    /// The line size `q + 1` (Full profile).
    pub line_size: u8,
}

impl NyxConfig {
    /// A validated Full-profile config; returns `None` if `threshold` exceeds `line_size` or
    /// is zero.
    #[must_use]
    pub fn full(mix: MixConfig, threshold: u8, line_size: u8) -> Option<Self> {
        if threshold == 0 || threshold > line_size {
            return None;
        }
        Some(Self {
            profile: Profile::Full,
            mix,
            threshold,
            line_size,
        })
    }

    /// A Lite-profile config (single-node hops, no threshold).
    #[must_use]
    pub fn lite(hops: u32) -> Self {
        Self {
            profile: Profile::Lite,
            mix: MixConfig::none(hops),
            threshold: 1,
            line_size: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_capabilities() {
        assert!(!Profile::Direct.is_anonymous());
        assert!(Profile::Lite.is_anonymous());
        assert!(Profile::Full.uses_threshold());
        assert!(!Profile::Lite.uses_threshold());
    }

    #[test]
    fn dial_presets_trade_latency_for_anonymity() {
        let fast = MixConfig::tor_class().anonymity(50.0);
        let slow = MixConfig::nym_plus().anonymity(1000.0);
        assert!(slow.entropy_bits > fast.entropy_bits);
        assert!(slow.latency_s > fast.latency_s);
    }

    #[test]
    fn full_config_validates_threshold() {
        assert!(NyxConfig::full(MixConfig::tor_class(), 6, 8).is_some());
        assert!(NyxConfig::full(MixConfig::tor_class(), 9, 8).is_none());
        assert!(NyxConfig::full(MixConfig::tor_class(), 0, 8).is_none());
    }
}
