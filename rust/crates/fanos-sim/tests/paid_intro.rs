//! Anonymous **paid** introduction, end to end over the live overlay. A CALYPSO intro is gated by
//! two independent costs: a hashcash PoW (anti-flood) *and* an anonymous relay credit — a
//! ristretto255 VOPRF blind token (spec L7). The relay bank blind-signs the client's token (learning
//! nothing that links it to the client), the client spends the unblinded credit inside the intro
//! payload, and the service redeems it exactly once. Payment therefore cannot deanonymise the client
//! (the redeemed credit is unlinkable to the issuance the bank saw), a forged credit buys nothing,
//! and one credit buys exactly one introduction (double-spend is caught). This composes the shipping
//! `OverlayNode` (Send/Get/Put), CALYPSO addressing, and the incentive layer — no extra stack.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use fanos_calypso::{HiddenService, client_descriptor_key, descriptor_key, pow};
use fanos_field::F2;
use fanos_incentives::{Credit, CreditIssuer, Redemption, finalize, request};
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Sim, spawn_cell};
use rand_core::{CryptoRng, RngCore};

/// The PoW difficulty gating an introduction (small, for a fast test).
const POW_BITS: u32 = 8;

/// A deterministic `rand_core` 0.6 RNG (SplitMix64) — reproducible credit issuance for the test.
struct SplitMix64(u64);
impl SplitMix64 {
    fn seeded(tag: &str) -> Self {
        // Fold the tag into a 64-bit state (FNV-1a) — deterministic, no external hash dependency.
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for &b in tag.as_bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        Self(h)
    }
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
impl RngCore for SplitMix64 {
    fn next_u32(&mut self) -> u32 {
        self.step() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.step()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.step().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for SplitMix64 {}

fn triple_bytes(t: Triple) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    for w in t {
        v.extend_from_slice(&w.to_le_bytes());
    }
    v
}

fn parse_triple(b: &[u8]) -> Option<Triple> {
    let x = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?);
    let y = u32::from_le_bytes(b.get(4..8)?.try_into().ok()?);
    let z = u32::from_le_bytes(b.get(8..12)?.try_into().ok()?);
    Some([x, y, z])
}

/// An intro payload: `credit(64) ‖ nonce(8, LE) ‖ message`.
fn intro_payload(credit: &Credit, nonce: u64, msg: &[u8]) -> Vec<u8> {
    let mut v = credit.to_bytes().to_vec();
    v.extend_from_slice(&nonce.to_le_bytes());
    v.extend_from_slice(msg);
    v
}

fn parse_intro(bytes: &[u8]) -> Option<(Credit, u64, &[u8])> {
    let credit = Credit::from_bytes(bytes.get(0..64)?.try_into().ok()?)?;
    let nonce = u64::from_le_bytes(bytes.get(64..72)?.try_into().ok()?);
    Some((credit, nonce, bytes.get(72..)?))
}

#[test]
fn an_anonymous_credit_pays_for_a_calypso_introduction_exactly_once() {
    let mut sim = Sim::new(0x9A1D);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    // The relay bank blind-issues the client an anonymous credit (unlinkable to its identity).
    let mut bank = CreditIssuer::from_seed(b"fanos-relay-bank");
    let mut wallet = SplitMix64::seeded("client-wallet");
    let (req, blinded) = request(&mut wallet);
    let signed = bank.issue(&blinded, &mut wallet);
    let credit = finalize(req, &blinded, &signed, &bank.public()).expect("valid DLEQ proof");
    // The unblinded credit is a different group element than the blinded point the bank signed —
    // the bank cannot link this redemption back to that issuance (VOPRF unlinkability).
    assert_ne!(
        &credit.to_bytes()[32..64],
        &blinded.to_bytes()[..],
        "the credit is unlinkable to the issuance transcript"
    );

    // The service publishes its contact descriptor at the per-epoch rendezvous key.
    let service = HiddenService::new(b"paid-service-pubkey".to_vec());
    let address = service.address().clone();
    let epoch = 5;
    let service_node = cell[0];
    let client_node = cell[3];
    let key = descriptor_key(service.pubkey(), epoch);
    sim.inject(
        service_node,
        Command::Put {
            key: key.clone(),
            value: triple_bytes(service_node),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    // Client: verify the self-certifying address, compute the same key, fetch the descriptor.
    let client_key = client_descriptor_key(&address, service.pubkey(), epoch).unwrap();
    sim.inject(
        client_node,
        Command::Get {
            key: client_key.clone(),
        },
    );
    sim.run_for(Duration::from_millis(1000));
    let descriptor = sim
        .report()
        .retrievals()
        .filter(|(who, _, _)| *who == client_node)
        .find_map(|(_, _, v)| v.map(<[u8]>::to_vec))
        .expect("client retrieved the service descriptor");
    let service_coord = parse_triple(&descriptor).expect("descriptor is a coordinate");

    // Client solves the PoW and sends the PAID intro (credit ‖ pow ‖ message) over the overlay.
    let nonce = pow::solve(&client_key, POW_BITS);
    sim.inject(
        client_node,
        Command::Send {
            to: service_coord,
            payload: intro_payload(&credit, nonce, b"hello, i paid"),
        },
    );
    sim.run_for(Duration::from_millis(500));

    // Service side: parse the delivered intro, enforce PoW, and redeem the credit once.
    let (recv, sender, bytes) = sim.report().deliveries().last().unwrap();
    assert_eq!(recv, service_node, "the service received the intro");
    assert_eq!(sender, client_node);
    let (spent, got_nonce, msg) = parse_intro(bytes).expect("well-formed intro");
    assert!(
        pow::verify(&client_key, got_nonce, POW_BITS),
        "the intro PoW checks out"
    );
    assert_eq!(
        bank.redeem(&spent),
        Redemption::Accepted,
        "the anonymous credit is accepted for the introduction"
    );
    assert_eq!(msg, b"hello, i paid");

    // One credit, one introduction: replaying the same credit is caught as a double-spend.
    assert_eq!(
        bank.redeem(&spent),
        Redemption::DoubleSpent,
        "the credit cannot be spent twice"
    );
}

#[test]
fn a_forged_credit_does_not_buy_an_introduction() {
    // A credit signed by some *other* bank (or self-minted) does not verify under our bank's key —
    // payment is cryptographically enforced, so an unpaid intro is refused.
    let mut bank = CreditIssuer::from_seed(b"fanos-relay-bank");
    let other = CreditIssuer::from_seed(b"an-impostor-bank");
    let mut rng = SplitMix64::seeded("forger");
    let (req, blinded) = request(&mut rng);
    let signed = other.issue(&blinded, &mut rng);
    let forged = finalize(req, &blinded, &signed, &other.public()).expect("valid under other key");

    assert_eq!(
        bank.redeem(&forged),
        Redemption::Invalid,
        "a credit not signed by our bank buys nothing"
    );
}
