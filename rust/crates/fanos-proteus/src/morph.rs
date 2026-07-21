//! Morphs and environment policies (spec §13.3, §13.7).
//!
//! A **morph** is an obfuscation mode; a policy selects one per environment and rotates to the
//! next when a morph starts failing (detected by the DIAKRISIS health loop). The flagship is
//! `polymorph` — "look like nothing", not imitation (the "Parrot is Dead" lesson).

/// A PROTEUS obfuscation mode (spec §13.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Morph {
    /// Native QUIC / HTTP-3 — zero overhead, for uncensored networks.
    Plain,
    /// The flagship: "look like nothing", configurable junk/padding, beacon-rotating.
    Polymorph,
    /// A real TLS-1.3 tunnel (Reality/uTLS class) — for SNI filtering + active probing.
    TlsTunnel,
    /// Ordinary HTTP-3 `CONNECT-UDP` (MASQUE) — where HTTP-3 is allowed.
    MasqueH3,
    /// Traffic to a large CDN domain (meek / domain-fronting) — collateral freedom.
    Fronted,
    /// A video/voice call (Snowflake) — WebRTC allowed, ephemeral volunteer proxies.
    Webrtc,
    /// A third-party pluggable transport (PT 2.0 SPI).
    Pluggable,
}

impl Morph {
    /// Whether the morph removes the signature ("look like nothing") rather than imitating.
    #[must_use]
    pub fn removes_signature(self) -> bool {
        matches!(self, Self::Polymorph)
    }

    /// Whether the morph imitates / tunnels through a cover protocol.
    #[must_use]
    pub fn imitates(self) -> bool {
        matches!(
            self,
            Self::TlsTunnel | Self::MasqueH3 | Self::Fronted | Self::Webrtc
        )
    }

    /// The canonical lowercase config/CLI name of this morph.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Polymorph => "polymorph",
            Self::TlsTunnel => "tls-tunnel",
            Self::MasqueH3 => "masque-h3",
            Self::Fronted => "fronted",
            Self::Webrtc => "webrtc",
            Self::Pluggable => "pluggable",
        }
    }

    /// Parse a morph from its canonical [`name`](Self::name) (as written in config/CLI); `None` if the name
    /// is unrecognised.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Plain,
            Self::Polymorph,
            Self::TlsTunnel,
            Self::MasqueH3,
            Self::Fronted,
            Self::Webrtc,
            Self::Pluggable,
        ]
        .into_iter()
        .find(|m| m.name() == name)
    }
}

/// A named environment policy (spec §13.7): each selects a morph fallback chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Environment {
    /// Uncensored — zero overhead.
    Open,
    /// DPI / ML classifiers in a corporate network.
    DpiCorporate,
    /// SNI/IP blocklists.
    SniFilter,
    /// Deep censorship (DPI + active probing + bridge enumeration).
    DeepCensorship,
}

impl Environment {
    /// The ordered morph fallback chain for this environment. `chain()[0]` is preferred; the
    /// auto-fallback rotates to the next when a morph fails (spec §13.7).
    #[must_use]
    pub fn chain(self) -> &'static [Morph] {
        match self {
            Self::Open => &[Morph::Plain, Morph::Polymorph],
            Self::DpiCorporate => &[Morph::Polymorph, Morph::MasqueH3, Morph::Fronted],
            Self::SniFilter => &[Morph::TlsTunnel, Morph::Fronted, Morph::Polymorph],
            Self::DeepCensorship => &[Morph::Polymorph, Morph::Fronted, Morph::Webrtc],
        }
    }

    /// The preferred (first) morph for this environment.
    #[must_use]
    pub fn preferred_morph(self) -> Morph {
        self.chain().first().copied().unwrap_or(Morph::Polymorph)
    }

    /// The next morph to try after `failed` fails, or `None` if the chain is exhausted
    /// (spec §13.7 auto-fallback).
    #[must_use]
    pub fn fallback_after(self, failed: Morph) -> Option<Morph> {
        let chain = self.chain();
        let idx = chain.iter().position(|&m| m == failed)?;
        chain.get(idx + 1).copied()
    }

    /// The canonical lowercase config/CLI name of this environment.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::DpiCorporate => "dpi-corporate",
            Self::SniFilter => "sni-filter",
            Self::DeepCensorship => "deep-censorship",
        }
    }

    /// Parse an environment from its canonical [`name`](Self::name); `None` if unrecognised.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [Self::Open, Self::DpiCorporate, Self::SniFilter, Self::DeepCensorship]
            .into_iter()
            .find(|e| e.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polymorph_is_the_look_like_nothing_flagship() {
        assert!(Morph::Polymorph.removes_signature());
        assert!(!Morph::Polymorph.imitates());
        assert!(Morph::TlsTunnel.imitates());
    }

    #[test]
    fn open_prefers_zero_overhead() {
        assert_eq!(Environment::Open.preferred_morph(), Morph::Plain);
        assert_eq!(
            Environment::DeepCensorship.preferred_morph(),
            Morph::Polymorph
        );
    }

    #[test]
    fn morph_names_round_trip() {
        for m in [
            Morph::Plain,
            Morph::Polymorph,
            Morph::TlsTunnel,
            Morph::MasqueH3,
            Morph::Fronted,
            Morph::Webrtc,
            Morph::Pluggable,
        ] {
            assert_eq!(Morph::from_name(m.name()), Some(m), "{m:?} name round-trips");
        }
        assert_eq!(Morph::from_name("nonsense"), None);
    }

    #[test]
    fn environment_names_round_trip() {
        for e in [
            Environment::Open,
            Environment::DpiCorporate,
            Environment::SniFilter,
            Environment::DeepCensorship,
        ] {
            assert_eq!(Environment::from_name(e.name()), Some(e), "{e:?} name round-trips");
        }
        assert_eq!(Environment::from_name("nonsense"), None);
    }

    #[test]
    fn auto_fallback_walks_the_chain() {
        let env = Environment::DeepCensorship;
        assert_eq!(env.fallback_after(Morph::Polymorph), Some(Morph::Fronted));
        assert_eq!(env.fallback_after(Morph::Fronted), Some(Morph::Webrtc));
        assert_eq!(env.fallback_after(Morph::Webrtc), None);
    }
}
