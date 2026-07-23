//! The finalized ledger — the ordered chain of committed headers and the executed state
//! (`docs/design-taxis.md` §4, §8).
//!
//! Consensus commits **headers** in order (the ledger's canonical ordering, fixed at the commit
//! certificate); execution then applies each block's reconstructed transactions to the [`StateMachine`] in
//! that order, once the anti-MEV reveals are in. The two are separated on purpose: the *order* is final the
//! instant a block gathers a commit certificate, even before its transactions are decrypted.

use alloc::vec::Vec;

use crate::block::{BlockHeader, GENESIS_PARENT};
use crate::state::StateMachine;
use crate::tx::Transaction;

/// The finalized chain over a state machine `S`: an append-only run of committed headers plus the state
/// obtained by executing their transactions in order.
#[derive(Clone, Debug)]
pub struct Chain<S: StateMachine> {
    /// Headers finalized **since genesis or the last state-sync restore** (a state-synced node keeps a
    /// truncated history below `base_height`, exactly as CometBFT does — consensus needs only the tip).
    headers: Vec<BlockHeader>,
    head: [u8; 32],
    state: S,
    /// The height of the first header in `headers` (0 for a genesis chain; `restored_height + 1` after a
    /// state-sync [`restore`](Self::restore)). `next_height = base_height + headers.len()`.
    base_height: u64,
}

impl<S: StateMachine> Chain<S> {
    /// A fresh chain over `genesis_state` (its balances/funding are the genesis allocation), with no blocks
    /// yet and the head at [`GENESIS_PARENT`].
    pub fn new(genesis_state: S) -> Self {
        Self { headers: Vec::new(), head: GENESIS_PARENT, state: genesis_state, base_height: 0 }
    }

    /// Install a **state-synced** chain: adopt `state` as the executed ledger at `height` (its `head` block
    /// hash), so the next height to decide is `height + 1` (audit §3.9 / §4 — a lagging or restarting node
    /// resumes here instead of wedging). The caller MUST have verified `state.state_root()` against a
    /// quorum-signed [`ExecCertificate`](crate::checkpoint::ExecCertificate) root and the `head` hash before
    /// calling — this method installs, it does not verify. Historical headers below `height` are not retained.
    pub fn restore(&mut self, height: u64, head: [u8; 32], state: S) {
        self.headers.clear();
        self.head = head;
        self.state = state;
        self.base_height = height.saturating_add(1);
    }

    /// The next height to decide — the number of finalized blocks (heights `0, 1, …`), offset by any
    /// state-sync [`restore`](Self::restore) base.
    #[must_use]
    pub fn next_height(&self) -> u64 {
        self.base_height + self.headers.len() as u64
    }

    /// The hash of the latest finalized block, or [`GENESIS_PARENT`] before the first.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// The executed state.
    #[must_use]
    pub fn state(&self) -> &S {
        &self.state
    }

    /// The current state root (the ledger's verifiable summary after all executed transactions).
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    /// The finalized headers in commit order.
    #[must_use]
    pub fn headers(&self) -> &[BlockHeader] {
        &self.headers
    }

    /// Whether `header` is a valid next block to finalize: it must build on the current head at the next
    /// height. (The proposer/quorum checks live in the consensus engine; this is the chain's own link rule.)
    #[must_use]
    pub fn links(&self, header: &BlockHeader) -> bool {
        header.parent == self.head && header.height == self.next_height()
    }

    /// Append a finalized header, advancing the head and the height. The caller must have verified it
    /// [`links`](Self::links) and gathered a commit certificate for it.
    pub fn finalize(&mut self, header: BlockHeader) {
        self.head = header.hash();
        self.headers.push(header);
    }

    /// Begin executing the block at `height`: forward the per-block clock to the state machine before its
    /// transactions (see [`StateMachine::begin_block`]).
    pub fn begin_block(&mut self, height: u64) {
        self.state.begin_block(height);
    }

    /// Forward the block's audit beacon (the parent hash) to the state machine before its transactions
    /// (see [`StateMachine::set_audit_beacon`]).
    pub fn set_audit_beacon(&mut self, beacon: [u8; 32]) {
        self.state.set_audit_beacon(beacon);
    }

    /// Execute one transaction against the state (applied in committed order after its block finalizes).
    pub fn execute(&mut self, tx: &Transaction) {
        let _ = self.state.apply(tx);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_primitives::Epoch;

    use crate::block::Block;
    use crate::state::{Accounts, Transfer};

    const ALICE: [u8; 32] = [0xA1; 32];
    const BOB: [u8; 32] = [0xB0; 32];

    #[test]
    fn a_fresh_chain_starts_at_genesis() {
        let chain = Chain::new(Accounts::new());
        assert_eq!(chain.next_height(), 0);
        assert_eq!(chain.head(), GENESIS_PARENT);
    }

    #[test]
    fn finalizing_links_and_advances_the_head() {
        let mut chain = Chain::new(Accounts::new());
        let block = Block::assemble(GENESIS_PARENT, 0, Epoch::new(1), 3, Vec::new());
        assert!(chain.links(&block.header), "an empty block on genesis links");
        chain.finalize(block.header.clone());
        assert_eq!(chain.next_height(), 1);
        assert_eq!(chain.head(), block.hash());
        // A second block must build on the new head at height 1.
        let next = Block::assemble(block.hash(), 1, Epoch::new(1), 4, Vec::new());
        assert!(chain.links(&next.header));
        // A block at the wrong height or parent does not link.
        let wrong = Block::assemble(GENESIS_PARENT, 1, Epoch::new(1), 4, Vec::new());
        assert!(!chain.links(&wrong.header));
    }

    #[test]
    fn restore_installs_a_synced_state_at_a_height() {
        // A state-synced node adopts a certified state at height H, resuming at H+1 on the given head.
        let mut chain = Chain::new(Accounts::new());
        let mut synced = Accounts::new();
        synced.credit(ALICE, 500);
        let head = [0x77; 32];
        chain.restore(9, head, synced);
        assert_eq!(chain.next_height(), 10, "resumes at height H+1");
        assert_eq!(chain.head(), head, "adopts the synced head");
        assert_eq!(chain.state().balance(&ALICE), 500, "adopts the synced state");
        // The next block, building on the synced head at H+1, links.
        let block = Block::assemble(head, 10, Epoch::new(1), 3, Vec::new());
        assert!(chain.links(&block.header), "the next block builds on the synced head at H+1");
    }

    #[test]
    fn executing_transactions_updates_the_state_root() {
        let mut state = Accounts::new();
        state.credit(ALICE, 100);
        let mut chain = Chain::new(state);
        let root0 = chain.state_root();
        chain.execute(&Transfer { from: ALICE, to: BOB, amount: 25, nonce: 0 }.into_tx());
        assert_ne!(chain.state_root(), root0);
        assert_eq!(chain.state().balance(&BOB), 25);
    }
}
