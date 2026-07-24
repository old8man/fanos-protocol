//! Validator **provisioning** for running the TAXIS blockchain from the `fanos` binary (`fanos taxis-deal` /
//! `fanos validator`). This closes the production gap the deep audit flagged — `spawn_taxis` had zero prod
//! callers, so the shipped node could not run a chain.
//!
//! A cell of `n` validators is *dealt* once ([`deal_validators`]) — like `fanos beacon-deal` deals the epoch
//! beacon — producing one [`ValidatorConfig`] per validator. Each holds **one secret**, a 32-byte `node_seed`
//! from which that validator's consensus signing key *and* its anti-MEV / keyper KEM key are both
//! deterministically re-derived (exactly as the reference cell is keyed), plus the *shared, public* cell
//! configuration every validator agrees on: the BFT quorum params, the full verifier set, the keyper
//! decryption-key commitment, and the epoch beacon. From it, [`ValidatorConfig::to_taxis_params`] rebuilds the
//! [`TaxisParams`](crate::taxis_driver::TaxisParams) `spawn_taxis` consumes.
//!
//! The `node_seed` is stored, not the derived secret keys: `HybridKemSecret` is deliberately non-serializable
//! (its own docs forbid an un-zeroized owned copy), so re-derivation from a seed is both the hygienic and the
//! canonical path (matching how the cell was dealt). The verifier set and keyper commitment are public.

use fanos_dromos::HybridLedger;
use fanos_dromos::token::TokenLedger;
use fanos_pqcrypto::rng::SeedRng;
use fanos_pqcrypto::{HybridKemSecret, HybridSigSecret, HybridVerifier};
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_taxis::keyper::{KeyperKeyCert, KeyperRegistry};
use fanos_taxis::params::CellParams;
use rand_core::CryptoRng;

use crate::taxis_driver::TaxisParams;

/// Re-derive a validator's `(consensus signing key, anti-MEV/keyper KEM secret)` from its `node_seed` — the
/// two keys drawn in sequence from one seeded CSPRNG, the exact order the cell was dealt in, so the derivation
/// is canonical and a validator never stores a raw secret key.
#[must_use]
pub fn keys_from_seed(node_seed: &[u8; 32]) -> (HybridSigSecret, HybridKemSecret) {
    let mut rng = SeedRng::from_seed(node_seed);
    let (sig, _sig_pub) = HybridSigSecret::generate(&mut rng);
    let (kem, _kem_pub) = HybridKemSecret::generate(&mut rng);
    (sig, kem)
}

/// The genesis ledger a freshly-provisioned cell starts from: an empty DROMOS hybrid ledger (empty token
/// accounts + empty shielded pool). Initial allocations are applied as ordinary transactions after genesis.
#[must_use]
pub fn genesis_ledger() -> HybridLedger {
    HybridLedger::new(TokenLedger::new())
}

/// One validator's complete provisioning — its single secret seed plus the shared public cell configuration.
/// Produced by [`deal_validators`], serialized to a `validator-<i>.taxis` file, and read by `fanos validator`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidatorConfig {
    /// This validator's index — it runs the consensus node seated at `Point::at(me)`.
    pub me: u8,
    /// This validator's **secret** seed (the only secret in the file): re-derives its signing + KEM keys.
    pub node_seed: [u8; 32],
    /// The cell's BFT quorum parameters `(q, n, f, Q)` — shared by every validator.
    pub cell: CellParams,
    /// The epoch this cell runs at.
    pub epoch: Epoch,
    /// The epoch beacon seed (fixes the leader schedule + keyper line).
    pub beacon: BeaconSeed,
    /// The agreed on-chain keyper decryption-key commitment.
    pub keyper_commit: [u8; 32],
    /// Every validator's consensus verifier, encoded, indexed by validator index.
    pub verifiers: Vec<Vec<u8>>,
}

impl ValidatorConfig {
    /// Rebuild the [`TaxisParams`] `spawn_taxis` consumes, running on `genesis`. `None` if a stored verifier is
    /// malformed.
    #[must_use]
    pub fn to_taxis_params(&self, genesis: HybridLedger) -> Option<TaxisParams<HybridLedger>> {
        let verifiers = self
            .verifiers
            .iter()
            .map(|v| HybridVerifier::decode(v))
            .collect::<Option<Vec<_>>>()?;
        let (signer, kem_secret) = keys_from_seed(&self.node_seed);
        Some(TaxisParams {
            cell: self.cell,
            me: self.me,
            signer,
            kem_secret,
            verifiers,
            keyper_commit: self.keyper_commit,
            seed: self.beacon,
            epoch: self.epoch,
            genesis_state: genesis,
            reward_per_block: 0,
            sortition: None,
        })
    }

    /// Canonical wire bytes: `me(1) ‖ node_seed(32) ‖ q(4) n(4) f(4) Q(4) ‖ epoch(8) ‖ beacon(32) ‖
    /// keyper_commit(32) ‖ verifier_count(4) ‖ [len(4) ‖ verifier]…` (all big-endian).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.me);
        out.extend_from_slice(&self.node_seed);
        out.extend_from_slice(&(self.cell.q).to_be_bytes());
        out.extend_from_slice(&u32_of(self.cell.n).to_be_bytes());
        out.extend_from_slice(&u32_of(self.cell.f).to_be_bytes());
        out.extend_from_slice(&u32_of(self.cell.quorum).to_be_bytes());
        out.extend_from_slice(&self.epoch.get().to_be_bytes());
        out.extend_from_slice(self.beacon.as_bytes());
        out.extend_from_slice(&self.keyper_commit);
        out.extend_from_slice(&u32_of(self.verifiers.len()).to_be_bytes());
        for v in &self.verifiers {
            out.extend_from_slice(&u32_of(v.len()).to_be_bytes());
            out.extend_from_slice(v);
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes); `None` on truncation or a bad length prefix.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Cursor::new(bytes);
        let me = r.u8()?;
        let node_seed = r.array32()?;
        let cell = CellParams {
            q: r.u32()?,
            n: r.u32()? as usize,
            f: r.u32()? as usize,
            quorum: r.u32()? as usize,
        };
        let epoch = Epoch::new(r.u64()?);
        let beacon = BeaconSeed::new(r.array32()?);
        let keyper_commit = r.array32()?;
        let count = r.u32()? as usize;
        let mut verifiers = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let len = r.u32()? as usize;
            verifiers.push(r.take(len)?.to_vec());
        }
        if !r.is_empty() {
            return None; // trailing bytes ⇒ non-canonical
        }
        Some(Self { me, node_seed, cell, epoch, beacon, keyper_commit, verifiers })
    }
}

/// Deal a fresh cell of validators: for each of the cell's `n` seats, draw a secret `node_seed` from `rng`,
/// derive its signing + KEM keys, and assemble the shared verifier set + keyper registry. Returns one
/// [`ValidatorConfig`] per validator, all sharing the same public cell configuration. `rng` is OS entropy in
/// production (`fanos taxis-deal`) or a seeded CSPRNG under test.
#[must_use]
pub fn deal_validators<R: CryptoRng>(cell: CellParams, epoch: Epoch, beacon: BeaconSeed, rng: &mut R) -> Vec<ValidatorConfig> {
    // Draw each validator's secret seed, and derive its public verifier + keyper KEM public in one pass.
    let mut node_seeds = Vec::with_capacity(cell.n);
    let mut verifiers: Vec<Vec<u8>> = Vec::with_capacity(cell.n);
    let mut certs = Vec::with_capacity(cell.n);
    for i in 0..cell.n {
        let mut node_seed = [0u8; 32];
        rng.fill_bytes(&mut node_seed);
        let mut kr = SeedRng::from_seed(&node_seed);
        let (sig, sig_pub) = HybridSigSecret::generate(&mut kr);
        let (_kem, kem_pub) = HybridKemSecret::generate(&mut kr);
        verifiers.push(sig_pub.encode());
        certs.push(KeyperKeyCert::register(u8_of(i), kem_pub, &sig));
        node_seeds.push(node_seed);
    }
    let keyper_commit = KeyperRegistry::new(certs).commit();
    node_seeds
        .into_iter()
        .enumerate()
        .map(|(i, node_seed)| ValidatorConfig {
            me: u8_of(i),
            node_seed,
            cell,
            epoch,
            beacon,
            keyper_commit,
            verifiers: verifiers.clone(),
        })
        .collect()
}

/// A `usize`/`u32` narrowed for the wire (saturating — a real cell is tiny; this only guards a pathological
/// value from silently truncating).
fn u32_of(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// A validator index narrowed to `u8` (a cell never exceeds 255 seats at the sizes TAXIS targets).
fn u8_of(v: usize) -> u8 {
    u8::try_from(v).unwrap_or(u8::MAX)
}

/// A minimal forward-only byte cursor with bounds-checked reads (the crate gates raw slice indexing).
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn array32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }

    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_dealt_cell_rebuilds_consistent_taxis_params_for_every_validator() {
        let cell = CellParams::FANO;
        let configs = deal_validators(cell, Epoch::new(5), BeaconSeed::new([0x5E; 32]), &mut SeedRng::from_seed(b"deal"));
        assert_eq!(configs.len(), cell.n, "one config per validator seat");

        // Every validator agrees on the SAME public cell config (verifiers, keyper commit, cell, beacon)…
        let shared = &configs[0];
        for (i, c) in configs.iter().enumerate() {
            assert_eq!(c.me as usize, i, "indices are 0..n in seat order");
            assert_eq!(c.verifiers, shared.verifiers, "the verifier set is shared");
            assert_eq!(c.keyper_commit, shared.keyper_commit, "the keyper commitment is shared");
            assert_eq!(c.cell, cell);
        }
        // …but each has a DISTINCT secret seed, and its own verifier is the one it re-derives from that seed.
        for c in &configs {
            let (sig, _kem) = keys_from_seed(&c.node_seed);
            let (_re_sig, re_pub) = HybridSigSecret::generate(&mut SeedRng::from_seed(&c.node_seed));
            let _ = sig; // the signer re-derives; the verifier below must match the shared set at this index.
            assert_eq!(
                c.verifiers[c.me as usize],
                re_pub.encode(),
                "a validator's own verifier is derived from its secret seed",
            );
        }
        // The params rebuild for every validator, seating each at its own index over a shared genesis.
        for c in &configs {
            let params = c.to_taxis_params(genesis_ledger()).expect("params rebuild");
            assert_eq!(params.me, c.me);
            assert_eq!(params.verifiers.len(), cell.n);
            assert_eq!(params.keyper_commit, shared.keyper_commit);
        }
    }

    #[test]
    fn distinct_validators_get_distinct_secret_seeds() {
        let configs = deal_validators(CellParams::FANO, Epoch::ZERO, BeaconSeed::GENESIS, &mut SeedRng::from_seed(b"d2"));
        for i in 0..configs.len() {
            for j in (i + 1)..configs.len() {
                assert_ne!(configs[i].node_seed, configs[j].node_seed, "each validator's seed is unique");
            }
        }
    }

    #[test]
    fn a_validator_config_round_trips_through_bytes() {
        let configs = deal_validators(CellParams::FANO, Epoch::new(9), BeaconSeed::new([7; 32]), &mut SeedRng::from_seed(b"rt"));
        let c = &configs[3];
        let bytes = c.to_bytes();
        assert_eq!(ValidatorConfig::from_bytes(&bytes).as_ref(), Some(c), "the provisioning round-trips");
        // Truncation and trailing bytes are rejected.
        assert!(ValidatorConfig::from_bytes(&bytes[..bytes.len() - 1]).is_none(), "a truncated file is rejected");
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(ValidatorConfig::from_bytes(&extra).is_none(), "trailing bytes are non-canonical");
    }
}
