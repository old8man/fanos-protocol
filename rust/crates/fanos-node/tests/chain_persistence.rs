//! **A restarted validator comes back on the chain, and a tampered file cannot fork it.**
//!
//! One validator restarting was always survivable: it state-syncs from its neighbours. A **whole-cell**
//! restart was total, permanent loss of the ledger, because no validator wrote anything down — if every
//! neighbour also starts at genesis there is nothing to sync from (#57).
//!
//! The design is one sentence: **the disk is a peer that happens to be local.** A validator persists the
//! `(ExecCertificate, snapshot)` pair it could serve a peer, and at startup feeds it back through
//! `Input::SyncResp` — the same path a peer's answer takes. So the quorum certificate is verified, the head it
//! binds is checked, and the snapshot must restore to the certified root, all by the code that already
//! refuses a forged answer on the wire. **Persistence adds no trust in the filesystem**, and this file's
//! second test is what says so: the same bytes with one signature swapped are refused, and the validator
//! starts clean rather than on an attacker's state.
//!
//! Driven at the engine, not over QUIC. The property is about what a certificate proves, and a seven-node
//! real-socket cell would add minutes of scheduling noise to a question that has none in it.

#![cfg(feature = "validator")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_dromos::HybridLedger;
use fanos_node::taxis_config::deal_validators;
use fanos_pqcrypto::rng::SeedRng;
use fanos_rendezvous::{BeaconSeed, Epoch};
use fanos_taxis::checkpoint::{ExecCertificate, ExecVote};
use fanos_taxis::consensus::{ConsensusEngine, Input};
use fanos_taxis::state::StateMachine;
use fanos_taxis::params::CellParams;

/// A dealt cell: its validator configs and the signing keys behind them.
///
/// `deal_validators` is the production ceremony, so the verifier set an engine checks a certificate against is
/// the same one these signatures are made with — which is the whole point of building the certificate by hand
/// rather than mocking one.
fn dealt() -> Vec<fanos_node::taxis_config::ValidatorConfig> {
    let (configs, _registry) = deal_validators(
        CellParams::FANO,
        Epoch::ZERO,
        BeaconSeed::GENESIS,
        &[([9u8; 32], 1_000_000)],
        &mut SeedRng::from_seed(b"chain-persistence"),
    );
    configs
}

/// One validator's engine, at genesis.
fn engine(config: &fanos_node::taxis_config::ValidatorConfig) -> ConsensusEngine<HybridLedger> {
    let p = config.to_taxis_params(None).expect("params rebuild");
    ConsensusEngine::new(
        p.cell,
        p.me,
        p.signer,
        p.kem_secret,
        p.verifiers,
        p.keyper_commit,
        p.seed,
        p.epoch,
        p.genesis_state,
    )
}

/// A **genuine** quorum certificate over `(height, root, head)`, signed by the dealt validators' own keys.
///
/// Built directly rather than by running consensus, because the property under test is what a certificate
/// *proves*, not how one comes to exist — and a seven-node round-driving harness would add minutes of
/// scheduling noise to a question that contains none.
fn certify(
    configs: &[fanos_node::taxis_config::ValidatorConfig],
    height: u64,
    root: [u8; 32],
    head: [u8; 32],
) -> ExecCertificate {
    let votes: Vec<ExecVote> = configs
        .iter()
        .take(CellParams::FANO.quorum())
        .map(|c| {
            let p = c.to_taxis_params(None).expect("params rebuild");
            ExecVote::sign(height, root, head, p.me, &p.signer)
        })
        .collect();
    ExecCertificate { height, state_root: root, head, votes }
}

/// **The property: a validator that persists its certified state comes back on it, not at genesis.**
///
/// The falsification is in the same test: an engine given *nothing* stays at genesis, so a `SyncResp` that
/// silently did nothing could not make both assertions hold at once.
#[test]
fn a_validator_that_kept_its_certified_state_comes_back_on_it() {
    /// The height the quorum attested — any height above genesis; the property does not depend on which.
    const CERTIFIED: u64 = 12;

    let configs = dealt();
    // The state a running cell would have certified. Taken from the *genesis ledger the config builds* —
    // the same object the engine starts on — so the root the certificate names is one this validator can
    // actually restore to. No new engine accessor is needed for it, which is the point: the pair a validator
    // persists is `(certificate, StateMachine::snapshot)`, and both halves are already public.
    let genesis = configs[0].to_taxis_params(None).expect("params rebuild").genesis_state;
    let (root, snapshot) = (genesis.state_root(), genesis.snapshot());
    let cert = certify(&configs, CERTIFIED, root, [7u8; 32]);

    // The restart: a fresh engine on the same dealt config, seeded from the persisted pair.
    let mut restarted = engine(&configs[0]);
    assert_eq!(restarted.height(), 0, "a fresh validator starts at genesis");
    restarted.step(Input::SyncResp { cert: cert.clone(), snapshot: snapshot.clone() });
    // `height()` is the height being *decided*, so a validator that has executed `CERTIFIED` is deciding the
    // one after it. Asserted as the exact value rather than "greater than zero": the difference between
    // resuming at the certified point and resuming somewhere plausible is the whole property.
    assert_eq!(
        restarted.height(),
        CERTIFIED + 1,
        "a validator handed its own certified state must resume deciding the height after it, not start over"
    );

    // And the falsification: without the pair, the same engine stays where it started.
    let cold = engine(&configs[0]);
    assert_eq!(
        cold.height(),
        0,
        "without a persisted state a validator starts at genesis — so the assertion above is about the \
         certified state and not about the engine"
    );
}

/// **A tampered file cannot fork a validator, and the check is not a new one.**
///
/// This is the whole reason the disk goes through `SyncResp`. Each mutation below is refused by a check that
/// already existed for the wire: the quorum signature, the head binding (the T-H6 site), and the requirement
/// that the snapshot restore to the certified root.
#[test]
fn a_chain_state_that_is_not_certified_is_refused() {
    let configs = dealt();
    let genesis = configs[0].to_taxis_params(None).expect("params rebuild").genesis_state;
    let (root, snapshot) = (genesis.state_root(), genesis.snapshot());
    let good = certify(&configs, 12, root, [7u8; 32]);

    // A forged root: the certificate claims a state its signatures never attested.
    let mut forged_root = good.clone();
    forged_root.state_root = [0xAA; 32];

    // A forged head: the T-H6 shape — a genuine certificate paired with another tip.
    let mut forged_head = good.clone();
    forged_head.head = [0xBB; 32];

    // A truncated quorum: enough votes to look like a certificate, too few to be one.
    let mut short = good.clone();
    short.votes.truncate(1);

    for (what, cert) in
        [("a forged state root", forged_root), ("a forged head", forged_head), ("a short quorum", short)]
    {
        let mut victim = engine(&configs[0]);
        victim.step(Input::SyncResp { cert, snapshot: snapshot.clone() });
        assert_eq!(
            victim.height(),
            0,
            "{what}: must be refused and leave the validator at genesis — a validator that adopts an \
             uncertified state has been forked by whoever could write the file"
        );
    }

    // A snapshot swapped for one the certificate does not describe: the certificate itself still verifies,
    // so this is caught only by re-deriving the root from the restored state.
    let mut victim = engine(&configs[0]);
    victim.step(Input::SyncResp { cert: good.clone(), snapshot: b"not a state".to_vec() });
    assert_eq!(victim.height(), 0, "a snapshot that does not restore to the certified root must be refused");

    // The good pair still works, so the loop above is refusing bad certificates rather than everything.
    let mut ok = engine(&configs[0]);
    ok.step(Input::SyncResp { cert: good, snapshot });
    assert!(ok.height() > 0, "the honest pair is still adopted");
}

/// **The pair must survive the file**, and the engine test above says nothing about that.
///
/// Two halves of one property, deliberately split: the engine decides whether a `(cert, snapshot)` may be
/// adopted, and the codec decides whether the pair that comes back off disk is the one that went down. A test
/// that only drove `Input::SyncResp` would stay green if the file format lost the snapshot's last byte.
#[test]
fn the_persisted_pair_is_the_pair_that_comes_back() {
    use fanos_node::taxis_driver::{CHAIN_FILE, decode_chain_state, encode_chain_state};

    let configs = dealt();
    let genesis = configs[0].to_taxis_params(None).expect("params rebuild").genesis_state;
    let (root, snapshot) = (genesis.state_root(), genesis.snapshot());
    let cert = certify(&configs, 12, root, [7u8; 32]);

    // Through the real atomic writer, at the real filename.
    let dir = std::env::temp_dir().join(format!("fanos-chain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join(CHAIN_FILE);
    fanos_node::durable::write_bytes(&path, &encode_chain_state(&cert, &snapshot)).expect("write");

    let (back_cert, back_snapshot) =
        decode_chain_state(&std::fs::read(&path).expect("read")).expect("decode");
    assert_eq!(back_cert, cert, "the certificate must round-trip exactly — a quorum is signatures, not a gist");
    assert_eq!(back_snapshot, snapshot, "and so must the snapshot, byte for byte");

    // And the pair off the disk is adopted, which is the only thing that makes the round trip matter.
    let mut restarted = engine(&configs[0]);
    restarted.step(Input::SyncResp { cert: back_cert, snapshot: back_snapshot });
    assert_eq!(restarted.height(), 13, "the pair read back from disk resumes the chain");

    // Truncation is refused rather than half-decoded: a file cut short is not a shorter certificate.
    let bytes = encode_chain_state(&cert, &snapshot);
    assert!(decode_chain_state(&bytes[..3]).is_none(), "too short to hold even the length prefix");
    let mut lying = bytes.clone();
    lying[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    // Refused, and — the part worth stating — **without panicking**. A crafted length is the one field in
    // this format an attacker fully controls, and the naive `split_at` aborts the validator on it. Measured:
    // replacing `split_at_checked` with `split_at` turns this line into a panic rather than a failed
    // assertion, which is the difference between refusing a file and being killed by one.
    assert!(decode_chain_state(&lying).is_none(), "a length past the end of the file is refused, not panicked on");

    std::fs::remove_dir_all(&dir).expect("cleanup");
}
