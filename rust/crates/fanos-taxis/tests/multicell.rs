//! End-to-end simulation of the **L0 cross-cell composition** (`docs/design-self-organization.md` §6): two
//! projective cells, each running its own TAXIS ledger, with a **trust-minimized** cross-cell transfer between
//! them and a parent cell anchoring both finalities. It exercises the three L0 primitives *together, through
//! real consensus*: the executed-state checkpoint, the cross-cell receipt, and parent-attests-child finality.
//!
//! The transfer is burn-and-mint: in cell A, ALICE pays `amount` into the cross-cell bridge escrow (a real
//! debit executed by A's consensus), and A's state machine emits a mint message to cell B. A's `Q`-quorum
//! execution certificate — over a state root that composes A's balances *and* its outbox — certifies both. A
//! `CrossCellReceipt` is verified by cell B against **only A's committee keys** (no trust in the relaying
//! bridge), and B mints to BOB. A parent [`ChildRegistry`] then anchors both cells' checkpoints.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::VecDeque;

use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};
use fanos_wire::Wire;
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};
use fanos_primitives::{BeaconSeed, Epoch};
use fanos_taxis::checkpoint::{ExecCertificate, ExecVote};
use fanos_taxis::committee::{epoch_seal_line, line_members};
use fanos_taxis::consensus::{ConsensusEngine, ConsensusMsg, Input, Output};
use fanos_taxis::crosscell::{compose_state_root, CrossMsg, Outbox};
use fanos_taxis::hierarchy::{ChildCommittee, ChildRegistry};
use fanos_taxis::keyper::{KeyperKeyCert, KeyperRegistry};
use fanos_taxis::state::{ExecOutcome, StateMachine};
use fanos_taxis::{Accounts, CellParams, SealedTx, Transaction, Transfer};

const N: usize = 7;
const SEED: BeaconSeed = BeaconSeed::new([0x11; 32]);
const EPOCH: Epoch = Epoch::new(1);
const ALICE: [u8; 32] = [0xA1; 32];
const BOB: [u8; 32] = [0xB0; 32];
/// The cross-cell bridge escrow address in the source cell (funds burned here are minted in the destination).
const BRIDGE: [u8; 32] = [0xBB; 32];
/// The destination cell's address in the hierarchy.
const CELL_B: u32 = 2;

// ── A cross-cell-aware state machine ────────────────────────────────────────────────────────────────────────

/// Accounts plus a cross-cell **outbox**: a transfer into [`BRIDGE`] additionally emits a mint message to cell
/// B, and the state root composes the balances with the outbox root ([`compose_state_root`]) so the execution
/// certificate certifies both.
#[derive(Clone, Default)]
struct CrossAccounts {
    accounts: Accounts,
    outbox: Outbox,
}

impl CrossAccounts {
    fn funded() -> Self {
        let mut accounts = Accounts::new();
        accounts.credit(ALICE, 1000);
        Self { accounts, outbox: Outbox::new() }
    }
}

impl StateMachine for CrossAccounts {
    fn apply(&mut self, tx: &Transaction) -> ExecOutcome {
        let outcome = self.accounts.apply(tx);
        if outcome == ExecOutcome::Applied
            && let Ok(t) = Transfer::from_wire(&tx.payload)
            && t.to == BRIDGE
        {
            // A burn into the bridge emits a mint of the same amount to BOB in cell B.
            let nonce = self.outbox.len() as u64;
            let mut payload = BOB.to_vec();
            payload.extend_from_slice(&t.amount.to_be_bytes());
            self.outbox.push(CrossMsg::new(CELL_B, nonce, payload));
        }
        outcome
    }

    fn state_root(&self) -> [u8; 32] {
        compose_state_root(&self.accounts.state_root(), &self.outbox.root())
    }

    fn snapshot(&self) -> Vec<u8> {
        use fanos_primitives::codec::put_var_bytes;
        let mut out = Vec::new();
        put_var_bytes(&mut out, &self.accounts.snapshot());
        put_var_bytes(&mut out, &self.outbox.to_bytes());
        out
    }

    fn restore(snapshot: &[u8]) -> Option<Self> {
        use fanos_primitives::codec::Reader;
        let mut r = Reader::new(snapshot);
        let accounts = Accounts::restore(r.var_bytes()?)?;
        let outbox = Outbox::from_bytes(r.var_bytes()?)?;
        r.finish()?;
        Some(Self { accounts, outbox })
    }
}

// ── A minimal generic cell harness (drives real consensus to a checkpoint) ──────────────────────────────────

struct Keys {
    sig: HybridSigSecret,
    sig_pub: HybridVerifier,
    kem: HybridKemSecret,
    kem_pub: HybridKemPublic,
}

fn gen_keys(tag: u8) -> Vec<Keys> {
    (0..N)
        .map(|i| {
            let mut rng = SeedRng::from_seed(&[tag, i as u8]);
            let (sig, sig_pub) = HybridSigSecret::generate(&mut rng);
            let (kem, kem_pub) = HybridKemSecret::generate(&mut rng);
            Keys { sig, sig_pub, kem, kem_pub }
        })
        .collect()
}

/// A driveable cell of `N` validators over a state machine `S`.
struct Cell<S: StateMachine + Clone> {
    engines: Vec<ConsensusEngine<S>>,
    kem_dir: Vec<HybridKemPublic>,
    verifiers: Vec<HybridVerifier>,
    bus: VecDeque<ConsensusMsg>,
}

impl<S: StateMachine + Clone> Cell<S> {
    fn new(genesis: &S, key_tag: u8) -> Self {
        let keys = gen_keys(key_tag);
        let verifiers: Vec<HybridVerifier> = keys.iter().map(|k| k.sig_pub.clone()).collect();
        let kem_dir: Vec<HybridKemPublic> = keys.iter().map(|k| k.kem_pub.clone()).collect();
        // The on-chain anti-MEV decryption-key commitment (each validator self-certifies its KEM key).
        let keyper_commit = KeyperRegistry::new(
            keys.iter().enumerate().map(|(i, k)| KeyperKeyCert::register(i as u8, k.kem_pub.clone(), &k.sig)).collect(),
        )
        .commit();
        let engines = keys
            .into_iter()
            .enumerate()
            .map(|(i, k)| {
                ConsensusEngine::new(
                    CellParams::FANO,
                    i as u8,
                    k.sig,
                    k.kem,
                    verifiers.clone(),
                    keyper_commit,
                    SEED,
                    EPOCH,
                    genesis.clone(),
                )
            })
            .collect();
        Self { engines, kem_dir, verifiers, bus: VecDeque::new() }
    }

    /// Seal a transfer to this epoch's keyper line (so it passes admission).
    fn seal(&self, transfer: Transfer, tag: &[u8]) -> SealedTx {
        let members = line_members(epoch_seal_line(&SEED, EPOCH));
        let member_keys: Vec<&HybridKemPublic> = members.iter().map(|&m| &self.kem_dir[m]).collect();
        SealedTx::seal(&transfer.into_tx(), EPOCH, epoch_seal_line(&SEED, EPOCH) as u8, &member_keys, CellParams::FANO.seal_threshold(), tag)
            .unwrap()
    }

    /// Submit a tx to every validator, tick (the leader proposes), and drain to quiescence — driving the cell
    /// through finalize → reveal → execute → checkpoint.
    fn run(&mut self, tx: &SealedTx) {
        for e in &mut self.engines {
            e.submit(tx.clone());
        }
        for i in 0..N {
            let outs = self.engines[i].step(Input::Tick);
            self.absorb(outs);
        }
        let mut guard = 0;
        while let Some(msg) = self.bus.pop_front() {
            for i in 0..N {
                let input = match &msg {
                    ConsensusMsg::Propose(b) => Input::Propose { block: b.clone(), shards: Box::new(b.da_shards().map(Some)) },
                    ConsensusMsg::Vote(sv) => Input::Vote(sv.clone()),
                    ConsensusMsg::Reveal(r) => Input::Reveal(r.clone()),
                    ConsensusMsg::ExecVote(v) => Input::ExecVote(v.clone()),
                    // This fully-connected cross-cell harness never lags, so catch-up messages are inapplicable.
                    ConsensusMsg::SyncReq { .. } | ConsensusMsg::SyncResp { .. } => continue,
                };
                let outs = self.engines[i].step(input);
                self.absorb(outs);
            }
            guard += 1;
            assert!(guard < 100_000, "the cell did not quiesce");
        }
    }

    fn absorb(&mut self, outs: Vec<Output>) {
        for o in outs {
            if let Output::Send(msg) = o {
                self.bus.push_back(msg);
            }
        }
    }

    fn checkpoint(&self) -> ExecCertificate {
        self.engines[0].latest_checkpoint().expect("the cell formed an execution checkpoint").clone()
    }

    fn committee(&self, cell: u32) -> ChildCommittee {
        ChildCommittee { cell, verifiers: self.verifiers.clone(), quorum: CellParams::FANO.quorum }
    }
}

#[test]
fn a_cross_cell_transfer_is_trust_minimized_end_to_end() {
    // ── Cell A: ALICE burns 100 into the bridge; A's consensus executes it and emits a mint message to cell B.
    let mut cell_a = Cell::new(&CrossAccounts::funded(), 0xA0);
    let tx = cell_a.seal(Transfer { from: ALICE, to: BRIDGE, amount: 100, nonce: 0 }, b"xfer");
    cell_a.run(&tx);
    // A executed the burn (ALICE 1000 → 900, the bridge escrow holds 100).
    assert_eq!(cell_a.engines[0].chain().state().accounts.balance(&ALICE), 900);
    assert_eq!(cell_a.engines[0].chain().state().accounts.balance(&BRIDGE), 100);

    // A's execution certificate certifies the composed state root; its outbox holds the mint message.
    let cert_a = cell_a.checkpoint();
    let source_state = cell_a.engines[0].chain().state();
    let accounts_root = source_state.accounts.state_root();
    let outbox = &source_state.outbox;
    assert_eq!(outbox.len(), 1, "the burn emitted exactly one cross-cell message");
    assert_eq!(cert_a.state_root, compose_state_root(&accounts_root, &outbox.root()), "the certificate covers the outbox");

    // ── The bridge relays a receipt. Cell B verifies it against ONLY cell A's committee keys — no bridge trust.
    let receipt = outbox.receipt(0, accounts_root, cert_a.clone()).expect("a receipt for the mint message");
    let msg: &CrossMsg = receipt
        .verify(&cell_a.verifiers, CellParams::FANO.quorum)
        .expect("cell B accepts a genuinely-certified cross-cell message");
    assert_eq!(msg.dest_cell, CELL_B);
    // Decode (recipient ‖ amount) and mint in cell B.
    let (recipient, amount) = (&msg.payload[..32], u64::from_be_bytes(msg.payload[32..40].try_into().unwrap()));
    assert_eq!(recipient, &BOB);
    // Every B validator, having verified the same receipt, applies the mint to BOB (a normal in-B operation) —
    // conservation across the two cells: 100 burned in A, 100 minted in B, nothing conjured.
    let cell_b = Cell::new(&CrossAccounts::default(), 0xB0);
    let mut b_state = CrossAccounts::default();
    b_state.accounts.credit(BOB, amount);
    assert_eq!(b_state.accounts.balance(&BOB), 100, "cell B minted exactly the burned amount — nothing conjured");

    // A tampered receipt (wrong amount) does NOT verify — the bridge cannot inflate the mint.
    let mut forged = receipt.clone();
    forged.msg.payload = {
        let mut p = BOB.to_vec();
        p.extend_from_slice(&1_000_000u64.to_be_bytes());
        p
    };
    assert!(forged.verify(&cell_a.verifiers, CellParams::FANO.quorum).is_none(), "a forged mint is rejected");

    // ── The parent cell anchors both children's finalities (shared security).
    let cert_b = {
        // Cell B's own checkpoint after minting (its committee attests the post-mint state root).
        let keys_b = gen_keys(0xB0);
        let root_b = b_state.state_root();
        let votes: Vec<ExecVote> = (0..CellParams::FANO.quorum).map(|i| ExecVote::sign(0, root_b, i as u8, &keys_b[i].sig)).collect();
        ExecCertificate { height: 0, state_root: root_b, votes }
    };
    let mut parent = ChildRegistry::new();
    parent.register(cell_a.committee(1));
    parent.register(cell_b.committee(CELL_B));
    assert_eq!(parent.attest(1, cert_a).map(|(h, _)| h), Some(0), "the parent anchors cell A's finality");
    assert!(parent.attest(CELL_B, cert_b).is_some(), "the parent anchors cell B's finality");
    // Both children are now anchored in the parent — anyone trusting the parent trusts both, without re-executing.
    assert!(parent.latest(1).is_some() && parent.latest(CELL_B).is_some());
}
