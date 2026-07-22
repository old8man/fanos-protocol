//! The **capacity market** — the deal state machine that turns proofs of retrievability into payment
//! (`docs/design-storage.md` §6). A consumer escrows a price to store a chunk for a duration; the provider is
//! paid **in arrears, one slice per passing audit**, and paid *nothing* for an epoch it fails. This is the whole
//! incentive: FANOS forbids capital staking (it deanonymizes), so there is no bond to slash — a non-proving
//! provider simply earns nothing and (via the reputation signal these settlements emit) loses future
//! assignments, while the consumer is refunded every unproven epoch. Honest storage strictly dominates whenever
//! the per-epoch slice `p` clears the provider's cost `c`.
//!
//! This is the sans-I/O core: [`Deal::settle_epoch`] consumes an audit verdict (from [`crate::por::verify`]) and
//! returns a [`Settlement`] describing what the caller must do — release funds via the DROMOS keyless-sink
//! `move_system`, and feed the reputation observation to the role layer. The ledger integration (a
//! `TAG_STORAGE` arm on `HybridLedger`) drives this engine; the engine itself holds only accounting.

use alloc::vec::Vec;

use crate::content::Cid;

/// The fixed wire length of an encoded [`DealParams`].
pub const DEAL_PARAMS_LEN: usize = 32 + 8 + 8 + 1 + 4 + 4 + 4 + 8 + 32 + 32;

/// The on-record parameters of a storage deal — the commitment a consumer and provider agree to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DealParams {
    /// The chunk being stored (its content id / retrievability commitment).
    pub cid: Cid,
    /// The chunk size in bytes.
    pub size: u64,
    /// The number of audit epochs the deal runs for.
    pub duration: u64,
    /// The erasure replication factor requested.
    pub replication: u8,
    /// The audit soundness parameter (bits) the price was set against.
    pub lambda_bits: u32,
    /// The tolerated missing-fraction, in parts per thousand (the record of what `k` was derived from).
    pub f_tol_permille: u32,
    /// The per-audit leaf-sample count (derived off-chain via `por::required_samples`).
    pub k: u32,
    /// The total price escrowed for the whole duration.
    pub price: u64,
    /// The provider's account id (paid on each passing audit).
    pub provider: [u8; 32],
    /// The consumer's account id (refunded any unproven escrow at close).
    pub consumer: [u8; 32],
}

impl DealParams {
    /// Canonical bytes: `cid(32) ‖ size(8) ‖ duration(8) ‖ replication(1) ‖ lambda_bits(4) ‖ f_tol_permille(4)
    /// ‖ k(4) ‖ price(8) ‖ provider(32) ‖ consumer(32)`, all integers little-endian ([`DEAL_PARAMS_LEN`] bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DEAL_PARAMS_LEN);
        out.extend_from_slice(self.cid.as_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.duration.to_le_bytes());
        out.push(self.replication);
        out.extend_from_slice(&self.lambda_bits.to_le_bytes());
        out.extend_from_slice(&self.f_tol_permille.to_le_bytes());
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.price.to_le_bytes());
        out.extend_from_slice(&self.provider);
        out.extend_from_slice(&self.consumer);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if the length is wrong.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DEAL_PARAMS_LEN {
            return None;
        }
        let cid = Cid::new(bytes.get(..32)?.try_into().ok()?);
        let size = u64::from_le_bytes(bytes.get(32..40)?.try_into().ok()?);
        let duration = u64::from_le_bytes(bytes.get(40..48)?.try_into().ok()?);
        let replication = *bytes.get(48)?;
        let lambda_bits = u32::from_le_bytes(bytes.get(49..53)?.try_into().ok()?);
        let f_tol_permille = u32::from_le_bytes(bytes.get(53..57)?.try_into().ok()?);
        let k = u32::from_le_bytes(bytes.get(57..61)?.try_into().ok()?);
        let price = u64::from_le_bytes(bytes.get(61..69)?.try_into().ok()?);
        let provider = bytes.get(69..101)?.try_into().ok()?;
        let consumer = bytes.get(101..133)?.try_into().ok()?;
        Some(Self { cid, size, duration, replication, lambda_bits, f_tol_permille, k, price, provider, consumer })
    }
}

/// The lifecycle state of a deal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DealState {
    /// Auditing and paying per epoch.
    Active,
    /// Ran its full duration.
    Completed,
    /// Closed early; remaining escrow refunded.
    Closed,
}

/// What the caller must enact after one epoch's audit verdict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Settlement {
    /// The audit passed: release `amount` from escrow to the provider, and record a positive reputation
    /// observation for it.
    Pay {
        /// The provider to pay.
        provider: [u8; 32],
        /// The amount to release this epoch (may be 0 if the price rounds below one slice).
        amount: u64,
    },
    /// The audit failed or was missed: release nothing, and record a negative reputation observation.
    Miss {
        /// The provider that missed.
        provider: [u8; 32],
    },
}

/// A live storage deal — pure accounting over its parameters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Deal {
    params: DealParams,
    epoch: u64,
    passed: u64,
    released: u64,
    state: DealState,
}

impl Deal {
    /// Open a deal (its escrow is assumed funded by the caller). `None` if the duration is zero (a deal must run
    /// at least one epoch).
    #[must_use]
    pub fn open(params: DealParams) -> Option<Self> {
        if params.duration == 0 {
            return None;
        }
        Some(Self { params, epoch: 0, passed: 0, released: 0, state: DealState::Active })
    }

    /// The deal parameters.
    #[must_use]
    pub fn params(&self) -> &DealParams {
        &self.params
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> DealState {
        self.state
    }

    /// Audit epochs settled so far.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Audits passed so far.
    #[must_use]
    pub fn passed(&self) -> u64 {
        self.passed
    }

    /// Total released to the provider so far.
    #[must_use]
    pub fn released(&self) -> u64 {
        self.released
    }

    /// Escrow not yet released — refundable to the consumer at close.
    #[must_use]
    pub fn refundable(&self) -> u64 {
        self.params.price.saturating_sub(self.released)
    }

    /// The cumulative amount owed after `passed` passing audits: `price · passed / duration` (remainder is
    /// distributed across epochs, so `duration` passes release exactly `price`).
    #[must_use]
    fn owed_after_passes(&self) -> u64 {
        let owed = u128::from(self.params.price)
            .saturating_mul(u128::from(self.passed))
            / u128::from(self.params.duration);
        u64::try_from(owed).unwrap_or(self.params.price)
    }

    /// Settle one audit epoch against its verdict `proof_ok`. Advances the epoch, pays the provider **in
    /// arrears** on a pass (the delta to its cumulative entitlement) and nothing on a miss, and completes the
    /// deal after `duration` epochs. `None` if the deal is no longer active.
    #[must_use]
    pub fn settle_epoch(&mut self, proof_ok: bool) -> Option<Settlement> {
        if self.state != DealState::Active {
            return None;
        }
        self.epoch = self.epoch.saturating_add(1);
        let settlement = if proof_ok {
            self.passed = self.passed.saturating_add(1);
            let target = self.owed_after_passes();
            let amount = target.saturating_sub(self.released);
            self.released = target;
            Settlement::Pay { provider: self.params.provider, amount }
        } else {
            Settlement::Miss { provider: self.params.provider }
        };
        if self.epoch >= self.params.duration {
            self.state = DealState::Completed;
        }
        Some(settlement)
    }

    /// Close the deal early (a consumer/policy decision — e.g. the provider's reputation collapsed). Returns the
    /// refundable escrow to return to the consumer. Idempotent-safe: closing again refunds nothing.
    #[must_use]
    pub fn close(&mut self) -> u64 {
        let refund = self.refundable();
        self.released = self.params.price;
        self.state = DealState::Closed;
        refund
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn params(price: u64, duration: u64) -> DealParams {
        DealParams {
            cid: Cid::new([7u8; 32]),
            size: 262_144,
            duration,
            replication: 3,
            lambda_bits: 30,
            f_tol_permille: 100,
            k: 198,
            price,
            provider: [0xAA; 32],
            consumer: [0xBB; 32],
        }
    }

    #[test]
    fn a_zero_duration_deal_is_refused() {
        assert!(Deal::open(params(1000, 0)).is_none());
    }

    #[test]
    fn deal_params_round_trip_on_the_wire() {
        let p = params(123_456, 30);
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), DEAL_PARAMS_LEN);
        assert_eq!(DealParams::from_bytes(&bytes), Some(p));
        assert_eq!(DealParams::from_bytes(&bytes[..bytes.len() - 1]), None, "wrong length rejected");
    }

    #[test]
    fn an_honest_provider_earns_the_whole_price_over_the_duration() {
        let mut deal = Deal::open(params(1000, 10)).unwrap();
        let mut paid = 0u64;
        for _ in 0..10 {
            if let Some(Settlement::Pay { provider, amount }) = deal.settle_epoch(true) {
                assert_eq!(provider, [0xAA; 32]);
                paid += amount;
            } else {
                panic!("a passing audit pays");
            }
        }
        assert_eq!(paid, 1000, "the provider earns exactly the price over the full duration");
        assert_eq!(deal.state(), DealState::Completed);
        assert_eq!(deal.refundable(), 0, "nothing is refundable — the provider earned it all");
        assert!(deal.settle_epoch(true).is_none(), "a completed deal settles no further");
    }

    #[test]
    fn a_cheating_provider_earns_nothing_and_the_consumer_is_refunded() {
        let mut deal = Deal::open(params(1000, 10)).unwrap();
        for _ in 0..10 {
            assert_eq!(deal.settle_epoch(false), Some(Settlement::Miss { provider: [0xAA; 32] }));
        }
        assert_eq!(deal.released(), 0, "a provider that never proves earns nothing");
        assert_eq!(deal.refundable(), 1000, "the whole escrow is refundable to the consumer");
        assert_eq!(deal.state(), DealState::Completed);
    }

    #[test]
    fn partial_performance_pays_pro_rata_and_refunds_the_rest() {
        // 7 of 10 audits pass: the provider earns 7/10 of the price, the consumer is refunded 3/10.
        let mut deal = Deal::open(params(1000, 10)).unwrap();
        let verdicts = [true, false, true, true, false, true, true, false, true, true];
        let mut paid = 0u64;
        for ok in verdicts {
            match deal.settle_epoch(ok).unwrap() {
                Settlement::Pay { amount, .. } => paid += amount,
                Settlement::Miss { .. } => {}
            }
        }
        assert_eq!(deal.passed(), 7);
        assert_eq!(paid, 700, "seven passes of ten epochs earn 7/10 of the price");
        assert_eq!(deal.refundable(), 300, "the three unproven epochs are refundable");
    }

    #[test]
    fn honest_strictly_dominates_cheating_when_the_slice_clears_cost() {
        // The incentive statement, made concrete: with p·D = price and a per-epoch cost c,
        // honest earns price − c·D; cheating earns 0 − reputation loss. Honest wins iff p > c.
        let price = 1000u64;
        let duration = 10u64;
        let cost_per_epoch = 80u64; // c, with slice p = 100 > c
        let mut honest = Deal::open(params(price, duration)).unwrap();
        let mut earned = 0u64;
        for _ in 0..duration {
            if let Some(Settlement::Pay { amount, .. }) = honest.settle_epoch(true) {
                earned += amount;
            }
        }
        let honest_payoff = earned as i64 - (cost_per_epoch * duration) as i64;
        assert_eq!(honest_payoff, 200, "honest net = price − c·D > 0");
        // Cheating: earns nothing (no cost, but no income, and reputation decays — modeled by the role layer).
        let mut cheat = Deal::open(params(price, duration)).unwrap();
        let mut cheat_earned = 0u64;
        for _ in 0..duration {
            if let Some(Settlement::Pay { amount, .. }) = cheat.settle_epoch(false) {
                cheat_earned += amount;
            }
        }
        assert_eq!(cheat_earned, 0);
        assert!(honest_payoff > 0, "honest storage strictly dominates cheating");
    }

    #[test]
    fn closing_early_refunds_the_unreleased_escrow_once() {
        let mut deal = Deal::open(params(1000, 10)).unwrap();
        let _ = deal.settle_epoch(true); // provider earned 100
        let _ = deal.settle_epoch(true); // provider earned 200
        assert_eq!(deal.released(), 200);
        assert_eq!(deal.close(), 800, "the unreleased 800 is refunded to the consumer");
        assert_eq!(deal.state(), DealState::Closed);
        assert_eq!(deal.close(), 0, "closing again refunds nothing");
        assert!(deal.settle_epoch(true).is_none(), "a closed deal settles no further");
    }
}
