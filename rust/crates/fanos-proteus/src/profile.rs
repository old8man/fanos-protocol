//! The **traffic-shaper** component of a morph (spec §13.3) — the *statistical* signature, distinct from
//! the codec's *content* signature ([`crate::obfuscate`]). A censor's ML classifier keys on packet-**size**
//! and inter-packet-**timing** distributions even when the content carries no fixed bytes (§13.1, "flags
//! flows by timing/volume/entropy"); the shaper moves both toward a per-morph target. Like the codec, the
//! target is derived from `θ_epoch`, so it **rotates every epoch** (§13.4) and diversifies per packet by
//! the same cleartext nonce sequence.
//!
//! **Grounding (not magic constants).** The **size** target is a per-packet length sampled from a
//! morph-characteristic band whose endpoints cite the real protocol (a TLS-1.3 record MTU-fills near
//! ~1400 B; a WebRTC Opus frame is small, ~50 packets/s); the frame is padded *up* to it — never below,
//! the payload must fit — so an observer's size histogram matches the band, not FANOS's native length
//! distribution. The **timing** target is an exponential inter-packet delay `−mean·ln u`: the memoryless
//! Poisson model, the canonical traffic-timing family and the same one FANOS mixing uses (§5, and the
//! `−mean·ln u` sampler already in the threshold router); `mean` cites the morph's characteristic packet
//! rate. Both are the §13.7 "shaping target" runtime knob, with these cited defaults.

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use fanos_primitives::hash::hash_xof;

use crate::morph::Morph;

const SIZE_LABEL: &str = "FANOS-v1/proteus-shape-size";
const SIZE_PAD_LABEL: &str = "FANOS-v1/proteus-shape-sizepad";
#[cfg(any(feature = "std", feature = "libm"))]
const GAP_LABEL: &str = "FANOS-v1/proteus-shape-gap";

/// How many means to cap the exponential timing tail at — beyond `TAIL_CAP × mean` a rare deep sample can't
/// stall a connection. `exp(−8) ≈ 0.03 %` of the tail mass is clipped, negligibly biasing the mean.
#[cfg(any(feature = "std", feature = "libm"))]
const TAIL_CAP: f64 = 8.0;

/// A per-morph traffic-shaping target: a packet-size band and a mean inter-packet gap. `size_ceil <=
/// size_floor` disables size shaping (the codec's own padding carries the size defense); `mean_gap_us == 0`
/// disables timing shaping (zero added latency).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShapingProfile {
    /// Lower bound (inclusive) of the sampled target packet size, in bytes.
    size_floor: u16,
    /// Upper bound (exclusive) of the sampled target packet size, in bytes (`<= size_floor` ⇒ no size shaping).
    size_ceil: u16,
    /// Mean inter-packet delay in microseconds (`0` ⇒ no timing shaping).
    mean_gap_us: u32,
}

impl ShapingProfile {
    /// The default shaping target for `morph` — each band/mean cited to the morph's real-world statistical
    /// profile (see the module docs); all are overridable via [`custom`](Self::custom).
    // Several morphs coincide on `none()` for *distinct* documented reasons (Plain is off by design,
    // Polymorph's defense is the codec, Pluggable supplies its own via the SPI); the arms are kept separate
    // for that clarity rather than merged.
    #[allow(clippy::match_same_arms)]
    #[must_use]
    pub fn for_morph(morph: Morph) -> Self {
        match morph {
            // Zero overhead by design: the open-network path adds neither padding nor delay.
            Morph::Plain => Self::none(),
            // The flagship's defense is the codec (entropy + junk/padding), which costs nothing on the wire.
            // Timing pacing is a latency/throughput cost, so the default keeps it OFF ("costs nothing when
            // the network is open", §13); an operator dials it up with a shaping morph or a `custom` profile
            // (the λ-dial, §13.7) when a deep-censorship environment needs timing-classifier resistance.
            Morph::Polymorph => Self::none(),
            // A pluggable third-party transport supplies its own profile through the SPI; default to none.
            Morph::Pluggable => Self::none(),
            // TLS-1.3 / Reality: records MTU-fill; a browsing flow paces at roughly a millisecond apart.
            Morph::TlsTunnel => Self { size_floor: 1200, size_ceil: 1400, mean_gap_us: 1000 },
            // MASQUE / HTTP-3 CONNECT-UDP: H3 DATAGRAM-sized, similar pacing.
            Morph::MasqueH3 => Self { size_floor: 1000, size_ceil: 1350, mean_gap_us: 800 },
            // Domain-fronting to a CDN: HTTPS-like MTU-filled records.
            Morph::Fronted => Self { size_floor: 1200, size_ceil: 1400, mean_gap_us: 1200 },
            // WebRTC / Snowflake media: small-to-medium frames at ~50 packets/s (Opus 20 ms framing).
            Morph::Webrtc => Self { size_floor: 150, size_ceil: 1100, mean_gap_us: 20_000 },
        }
    }

    /// No shaping (identity): neither size padding nor timing delay.
    #[must_use]
    pub const fn none() -> Self {
        Self { size_floor: 0, size_ceil: 0, mean_gap_us: 0 }
    }

    /// An explicit shaping target (the §13.7 "shaping target" runtime knob): pad each packet to a length in
    /// `[size_floor, size_ceil)` and pace at a mean gap of `mean_gap_us` microseconds. `size_ceil <=
    /// size_floor` disables size shaping; `mean_gap_us == 0` disables timing.
    #[must_use]
    pub const fn custom(size_floor: u16, size_ceil: u16, mean_gap_us: u32) -> Self {
        Self { size_floor, size_ceil, mean_gap_us }
    }

    /// Whether this profile shapes size.
    #[must_use]
    pub const fn shapes_size(&self) -> bool {
        self.size_ceil > self.size_floor
    }

    /// Whether this profile shapes timing.
    #[must_use]
    pub const fn shapes_timing(&self) -> bool {
        self.mean_gap_us > 0
    }

    /// Pad `wire` *up* to a per-packet target length sampled from `[size_floor, size_ceil)` (θ-derived from
    /// `seed`, diversified by `seq`), filling with PRF bytes. A no-op when size shaping is disabled or the
    /// frame already exceeds the target. Transparent to decode: the codec's length field bounds the payload,
    /// so a receiver ignores the trailing pad.
    pub fn pad_to_target(&self, wire: &mut Vec<u8>, seed: &[u8; 32], seq: u64) {
        if !self.shapes_size() {
            return;
        }
        let span = u32::from(self.size_ceil - self.size_floor);
        let target = usize::from(self.size_floor) + (prf_u32(SIZE_LABEL, seed, seq) % span) as usize;
        if wire.len() < target {
            let mut pad = vec![0u8; target - wire.len()];
            hash_xof(SIZE_PAD_LABEL, &seq_material(seed, seq), &mut pad);
            wire.extend_from_slice(&pad);
        }
    }

    /// The per-packet inter-packet delay: an exponential `−mean·ln u` (Poisson) with `u ∈ (0, 1]` PRF-derived
    /// from `θ ‖ seq`, so it rotates per epoch and diversifies per packet. `Duration::ZERO` when timing
    /// shaping is off — or on a `no_std` build without a float backend (timing is *sender-local*, never
    /// re-derived by the receiver, so a build-dependent divergence here is wire-harmless; cf. the nyx
    /// mathfns note).
    #[must_use]
    pub fn packet_delay(&self, seed: &[u8; 32], seq: u64) -> Duration {
        if !self.shapes_timing() {
            return Duration::ZERO;
        }
        exp_delay(self.mean_gap_us, seed, seq)
    }
}

/// PRF material `seed ‖ seq_be` — the per-packet keystream input, built without indexing.
fn seq_material(seed: &[u8; 32], seq: u64) -> [u8; 40] {
    let mut material = [0u8; 40];
    let (head, tail) = material.split_at_mut(32);
    head.copy_from_slice(seed);
    tail.copy_from_slice(&seq.to_be_bytes());
    material
}

/// A label-separated 64-bit PRF draw over `θ ‖ seq`.
fn prf_u64(label: &str, seed: &[u8; 32], seq: u64) -> u64 {
    let mut out = [0u8; 8];
    hash_xof(label, &seq_material(seed, seq), &mut out);
    u64::from_be_bytes(out)
}

/// A label-separated 32-bit PRF draw (high half of [`prf_u64`]).
fn prf_u32(label: &str, seed: &[u8; 32], seq: u64) -> u32 {
    (prf_u64(label, seed, seq) >> 32) as u32
}

/// Sample an exponential inter-packet delay `−mean·ln u`, `u ∈ (0, 1]` from 53 PRF bits, capped at
/// [`TAIL_CAP`]`× mean`. Only compiled with a float backend; see [`ShapingProfile::packet_delay`].
#[cfg(any(feature = "std", feature = "libm"))]
fn exp_delay(mean_us: u32, seed: &[u8; 32], seq: u64) -> Duration {
    // 53-bit mantissa mapped to (0, 1]: (bits + 1) / 2^53, so ln u is always finite and ≤ 0.
    let bits = prf_u64(GAP_LABEL, seed, seq) >> 11;
    let u = (bits as f64 + 1.0) / 9_007_199_254_740_992.0_f64;
    let us = (-f64::from(mean_us) * ln(u)).min(f64::from(mean_us) * TAIL_CAP);
    Duration::from_micros(us as u64)
}

/// Timing shaping is unavailable without a float backend on `no_std`; the delay is sender-local, so a build
/// that cannot compute it simply paces at zero (harmless — see [`ShapingProfile::packet_delay`]).
#[cfg(not(any(feature = "std", feature = "libm")))]
fn exp_delay(_mean_us: u32, _seed: &[u8; 32], _seq: u64) -> Duration {
    Duration::ZERO
}

/// Natural logarithm, dispatched by target: the hardware intrinsic on `std`, `libm` on `no_std`. Feeds only
/// the sender-local timing delay (never a wire-visible decision), so a std/libm ULP divergence is harmless.
#[cfg(any(feature = "std", feature = "libm"))]
#[inline]
fn ln(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.ln()
    }
    #[cfg(all(not(feature = "std"), feature = "libm"))]
    {
        libm::log(x)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x5a; 32];

    #[test]
    fn zero_cost_morphs_do_not_shape() {
        // Plain (off by design), Polymorph (codec-only defense), and Pluggable (SPI-supplied) all default to
        // an identity profile — no size padding, no timing pacing.
        for m in [Morph::Plain, Morph::Polymorph, Morph::Pluggable] {
            let p = ShapingProfile::for_morph(m);
            assert!(!p.shapes_size() && !p.shapes_timing(), "{m:?} is identity");
        }
    }

    #[test]
    fn imitation_profiles_target_mtu_sized_packets() {
        // A short frame under an MTU-clustered profile pads up into the cited band.
        let tls = ShapingProfile::for_morph(Morph::TlsTunnel);
        assert!(tls.shapes_size());
        for seq in 0..64 {
            let mut wire = vec![0u8; 40];
            tls.pad_to_target(&mut wire, &SEED, seq);
            assert!((1200..1400).contains(&wire.len()), "padded into the TLS band: {}", wire.len());
        }
    }

    #[test]
    fn size_padding_never_shrinks_a_large_frame() {
        // A frame already larger than the band is left untouched (the payload must fit).
        let tls = ShapingProfile::for_morph(Morph::TlsTunnel);
        let mut wire = vec![0u8; 1500];
        tls.pad_to_target(&mut wire, &SEED, 7);
        assert_eq!(wire.len(), 1500, "an over-band frame is not shrunk");
    }

    #[test]
    fn size_target_rotates_with_the_seed() {
        // The same packet index under two epochs' seeds pads to (generally) different lengths.
        let tls = ShapingProfile::for_morph(Morph::TlsTunnel);
        let seed_a = [0x11; 32];
        let seed_b = [0x22; 32];
        let mut differ = 0;
        for seq in 0..32 {
            let (mut a, mut b) = (vec![0u8; 40], vec![0u8; 40]);
            tls.pad_to_target(&mut a, &seed_a, seq);
            tls.pad_to_target(&mut b, &seed_b, seq);
            if a.len() != b.len() {
                differ += 1;
            }
        }
        assert!(differ > 20, "size samples rotate with the epoch seed ({differ}/32 differ)");
    }

    #[cfg(feature = "std")]
    #[test]
    fn timing_delay_is_exponential_and_capped() {
        // A custom timing profile (Polymorph itself no longer paces — the flagship default is zero-cost).
        let paced = ShapingProfile::custom(0, 0, 250);
        assert!(paced.shapes_timing());
        let mean = 250.0_f64;
        let mut sum = 0.0;
        let n: u32 = 4000;
        for seq in 0..n {
            let d = paced.packet_delay(&SEED, u64::from(seq));
            // Every sample is capped at TAIL_CAP × mean.
            assert!(d.as_micros() as f64 <= mean * TAIL_CAP + 1.0, "capped tail");
            sum += d.as_micros() as f64;
        }
        // The empirical mean sits near the target (the tail cap biases it slightly low).
        let empirical = sum / f64::from(n);
        assert!(
            (mean * 0.6..mean * 1.2).contains(&empirical),
            "exponential mean ≈ target: {empirical} vs {mean}"
        );
    }

    #[test]
    fn a_zero_mean_profile_never_delays() {
        let none = ShapingProfile::none();
        assert_eq!(none.packet_delay(&SEED, 3), Duration::ZERO);
    }
}
