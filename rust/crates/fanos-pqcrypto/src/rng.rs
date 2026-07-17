//! A deterministic, seedable CSPRNG for reproducible key generation.
//!
//! Post-quantum keygen needs a `CryptoRng`. For reproducible tests and simulator runs we back
//! one with the BLAKE3 extendable output (a secure PRF): seed in, unbounded keystream out. In
//! production the same primitives are driven by the OS CSPRNG instead.
//!
//! `rand_core` 0.10 is structured around the fallible [`TryRng`]/[`TryCryptoRng`] traits; the
//! infallible [`Rng`](rand_core::Rng)/[`CryptoRng`](rand_core::CryptoRng) come for free by
//! blanket impl once we declare `Error = Infallible`.

use core::convert::Infallible;

use blake3::OutputReader;
use rand_core::{TryCryptoRng, TryRng};

/// A BLAKE3-XOF-backed deterministic RNG.
pub struct SeedRng {
    reader: OutputReader,
}

impl SeedRng {
    /// Seed the generator from arbitrary bytes (domain-separated).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FANOS-v1/pq-keygen-rng");
        hasher.update(seed);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Fill `dst` with keystream. Infallible (the BLAKE3 XOF never runs dry), so callers that only
    /// need bytes can avoid the `rand_core` `TryRng` machinery entirely.
    pub fn fill(&mut self, dst: &mut [u8]) {
        self.reader.fill(dst);
    }
}

impl TryRng for SeedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.reader.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.reader.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.reader.fill(dst);
        Ok(())
    }
}

/// The BLAKE3 XOF is a secure PRF, so a well-seeded `SeedRng` is a CSPRNG.
impl TryCryptoRng for SeedRng {}
