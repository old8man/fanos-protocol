//! **The descriptor's epoch axis, turned by a beacon that really advances** (#347 — the residual #344
//! stated in its own commit message).
//!
//! #344 gave the hidden-service descriptor the three things a rotating slot needs: a republish loop
//! ([`spawn_descriptor_publisher`]), a bounded lifetime on the write (`put_ephemeral`), and a read window on
//! the resolver ([`NodeResolver`] with `pinned: None`). Each was checked at the unit level, and the unit
//! level cannot reach the claim: it proves the window's arithmetic against a constant, not that a *running*
//! node republishes when its own beacon rolls over, and not that the store ever reclaims the slot it left
//! behind. Those are properties of a system with a clock in it.
//!
//! The fixture is `epoch_clock.rs`'s: a **1-of-1 beacon anchor**, which self-buffers its own partial, so a
//! threshold round assembles on one node and the wall-clock driver advances the epoch for real — driver →
//! `AdvanceEpoch` → partial → round → `BeaconReady` — with no cell to stand up.
//!
//! **What each test claims.** The first: a service stays resolvable across ≥ 3 distinct real advances, three
//! rather than one because a single success is satisfied by one lucky write. The second: the rotation bought
//! something — a rotation whose old slots never expire is not a rotation, since an observer watching one
//! fixed slot still sees every access to the service, for ever. So it asserts the genesis slot is **gone**,
//! and asserts first that it was ever **there**: without that, "absent at epoch 4" is equally true of a build
//! that published nothing at all.
//!
//! **Why no reading here is timed, and what it took to learn that.** A store read that MISSES costs one
//! `read_timeout` and concludes on the next heartbeat — 2.1 s together — while the publisher's write is *not*
//! synchronous with the advance: it wakes on the beacon watch, pays the descriptor PoW and a store round
//! trip. A resolve issued while the publisher is still late therefore misses, and the miss can outlast the
//! grace slot it would have fallen back to, so the resolver reports a vanished service that is in fact
//! published.
//!
//! This file measured that the hard way, twice. Its first version resolved on the `BeaconReady` edge and was
//! red; its second slept to the half-epoch mark and was **intermittent** — green alone, red inside the full
//! `-p fanos-node` run, then green and red on successive solo runs at the same period. **Any fixed fraction
//! of the epoch is a margin dressed as a derivation.** So both tests now wait for the *observable* instead:
//! [`slot_written`] blocks until the live epoch's slot is really there, which is what "the loop republishes"
//! means, and which makes the resolve that follows race-free at any period — the slot it saw is alive for
//! this epoch and the next, so a turn of the clock in between leaves the resolver's window still populated.
//!
//! The other half of the discipline is monotonicity: a swept slot never comes back, so a `None` stays true
//! however long the read took, while a `Some` is only about the instant it was taken. Every slow reading
//! below is therefore an absence, and the one presence reading is taken first, while its sample is fresh.
//!
//! **The fixture's epoch is computed, not chosen** — see [`epoch_period`]. Production satisfies the same
//! inequality with a factor of 286 to spare (600 s against 2.1 s), and nothing in the tree compares the two:
//! `resolve.rs`'s `timeout_ordering` module pins a chain of three bounds and the epoch period is not in it.
//! That gap is #348's subject, not this file's — but this fixture is now a configuration it would accept, so
//! the two cannot drift apart silently.
//!
//! Not claimed here either: that the wall clock issues the tick at all (`epoch_clock.rs`), the exact width of
//! the read window (`resolve.rs`'s unit test, against the constant), or the store's expiry arithmetic
//! (`fanos-runtime`'s own tests, and `store_lifetime.rs` for what it buys).

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use fanos_diaulos::{Coord, bundle_from_kem_public};
use fanos_field::F2;
use fanos_node::diaulos::ServiceResolver;
use fanos_node::{
    BeaconParams, Epoch, NetworkId, Node, NodeConfig, NodeResolver, publish_service,
    spawn_descriptor_publisher,
};
use fanos_onoma::{Address, lookup_key};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_quic::Client;
use fanos_runtime::Notification;
use fanos_vrf::vss::{DeterministicRng, deal};

/// The fixture's epoch, **computed from the two constants whose relation it has to respect**.
///
/// A read that misses costs `read_timeout` and concludes on the next heartbeat, because the sweep that
/// concludes absence is paced by the beat (#216). The tests read at the half-epoch mark, so half a period is
/// what a miss has to fit inside for the grace slot to still be alive when the fallback reaches it — hence
/// **twice** that sum, and the factor is the reading position rather than a margin someone liked.
///
/// Read from `Config::default()` and not written as a number: these are the same fields a deployed node
/// carries (`node.rs` hands the node's `epoch_period` to the very `Config` that holds `read_timeout`), so a
/// change to either constant moves this fixture with it instead of turning it flaky.
fn epoch_period() -> Duration {
    let c = fanos_runtime::Config::default();
    2 * (Duration::from_nanos(c.read_timeout.0) + Duration::from_nanos(c.heartbeat.0))
}

/// Where the service says it can be reached. Round-tripped through the descriptor's metadata, so a resolver
/// that returned a default or a truncated coordinate would be caught rather than read as success.
const COORD: Coord = [3, 5, 7];

/// The opaque profile bytes that follow the coordinate in the metadata — present so the metadata is not
/// exactly the coordinate, which is the shape a decoder bug would pass on.
const PROFILES: &[u8] = b"profiles=direct";

/// A real hybrid-KEM identity and the `.fanos` address that self-certifies it.
///
/// A junk bundle would make both tests pass for the wrong reason: `NodeResolver::resolve` calls
/// `service_public_from_bundle` on its **last** line and drops the answer if the bundle carries no usable
/// KEM key, so the whole path has to be fed something a service would really publish.
fn service_identity() -> (Vec<u8>, Address) {
    let mut rng = SeedRng::from_seed(b"descriptor-rotation-e2e");
    let (_secret, public) = HybridKemSecret::generate(&mut rng);
    let bundle = bundle_from_kem_public(&public);
    let address = Address::from_bundle(&bundle);
    (bundle, address)
}

/// A node whose own beacon advances on the wall clock — the 1-of-1 anchor of `epoch_clock.rs`.
fn anchored() -> NodeConfig {
    let (shares, commitment) = deal(
        &[0x5A; 32],
        1,
        1,
        &mut DeterministicRng::new(b"descriptor-rotation"),
    )
    .expect("deal a 1-of-1 beacon");
    let share = shares
        .into_iter()
        .next()
        .expect("a 1-of-1 sharing yields one share");
    NodeConfig {
        listen: "127.0.0.1:0".parse().expect("loopback addr"),
        beacon: Some(BeaconParams {
            network_id: NetworkId::from_seed(b"descriptor-rotation-net"),
            commitment,
            threshold: 1,
            share: Some(share),
            authority: None,
        }),
        epoch_period: epoch_period(),
        // Explicit although it is also the default, because this test *depends* on it: the heartbeat paces
        // the store's read sweep, and the sweep is the one place a read concludes `Absent` (#216). With the
        // heartbeat off, a lookup for a reclaimed slot never concludes, and "the slot is gone" would be
        // indistinguishable from "the read never finished" — the two readings #215 exists to separate.
        start_heartbeat: true,
        ..NodeConfig::default()
    }
}

/// Block until the publisher has written the **live** epoch's slot, and return the epoch it wrote.
///
/// **Polls the slot rather than sleeping a fraction of the period, and the difference was measured.** The
/// publisher's write is not synchronous with the advance: it wakes on the beacon watch, pays the descriptor
/// PoW and a store round trip, and on a loaded machine that lateness is an appreciable part of a short epoch.
/// A version of this file slept to the half-epoch mark instead and was **intermittent** — green alone, red
/// inside the full `-p fanos-node` run, and then green and red on successive solo runs at the same period.
/// Any fixed fraction is a margin dressed as a derivation; waiting for the observable is the property itself.
///
/// It is also what makes the resolve below race-free at any period: once this returns, the slot it saw is
/// alive for this epoch and the next, so whether the clock turns between here and the lookup, the resolver's
/// window still contains a slot that exists.
///
/// The live epoch is re-read every round because a miss costs one read timeout and the clock does not wait.
/// The deadline exists to fail rather than hang: a loop that is keeping up writes within one epoch, so six
/// epochs of retries can only be reached by a publisher that has stopped.
async fn slot_written(client: &Client, address: &Address) -> Epoch {
    let deadline = tokio::time::Instant::now() + epoch_period() * 6;
    loop {
        let live = live_epoch(client);
        if client
            .get(lookup_key(address, live).to_vec())
            .await
            .is_some()
        {
            return live;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no epoch's slot was written within six epochs — the republish loop is not keeping up with the \
             beacon, which is the defect this file exists to catch and not a slow machine"
        );
    }
}

/// The live epoch as the resolver itself reads it, so a message names the epoch the answer was about.
fn live_epoch(client: &Client) -> Epoch {
    client.beacons().borrow().map_or(Epoch::ZERO, |(e, _)| e)
}

/// Block until the node's own beacon reports `target`, returning the epochs seen on the way.
///
/// Reads the notification stream rather than the `beacons()` watch deliberately: this is a test of a system
/// with a clock, and the stream is what says an advance *happened* rather than what the state is now.
async fn advance_to(node: &mut Node, target: u64) -> BTreeSet<u64> {
    let mut seen = BTreeSet::new();
    // Counted in EPOCHS, not seconds: this test's clock is the fixture's period, so a wall-clock ceiling
    // would have to be re-guessed every time that period is re-derived — and a stale one fires as a fixture
    // failure that reads like a rotation failure. Four times what it needs leaves room on a loaded machine
    // while still bounding a beacon that has genuinely stopped.
    let ceiling = epoch_period() * u32::try_from(target).unwrap_or(u32::MAX).saturating_mul(4);
    let wait = tokio::time::timeout(ceiling, async {
        loop {
            match node.next_notification().await {
                Some(Notification::BeaconReady { epoch, .. }) => {
                    seen.insert(epoch.get());
                    if epoch.get() >= target {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the node's notification stream ended before epoch {target}"),
            }
        }
    })
    .await;
    assert!(
        wait.is_ok(),
        "the anchor's beacon never reached epoch {target} — saw {seen:?}; this is the fixture failing, not \
         the rotation"
    );
    seen
}

/// **The loop republishes on real advances, and the resolver follows them.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_stays_resolvable_across_real_beacon_advances() {
    let (bundle, address) = service_identity();
    let host = address.to_name();
    let mut node = Node::start::<F2>(anchored()).await.expect("the node starts");
    let client = node.client();

    // The genesis publish on the production path, awaited: what follows is then about ROTATION, and a store
    // that could not take a descriptor at all fails here instead of masquerading as a rotation defect.
    publish_service(&client, &bundle, COORD, Epoch::ZERO, 0, PROFILES)
        .await
        .expect("the genesis descriptor lands");
    let _publisher =
        spawn_descriptor_publisher(client.clone(), bundle.clone(), COORD, 0, PROFILES.to_vec());

    // `pinned: None` — follow the beacon. This is the production default and the mode under test; the
    // pinned mode is an operator override, and the test below shows the two answer differently.
    let resolver = NodeResolver::new(client.clone(), None, 0);

    // Thirty epochs for three advances: each round costs one epoch of waiting, half of one for the mid-epoch
    // read and — when the read misses — the other half timing out, so ten epochs of slack per advance is
    // room for contention rather than for a defect. In epochs for the reason `advance_to` states.
    let resolved_at = tokio::time::timeout(epoch_period() * 30, async {
        let mut at: BTreeSet<u64> = BTreeSet::new();
        while at.len() < 3 {
            match node.next_notification().await {
                Some(Notification::BeaconReady { .. }) => {}
                Some(_) => continue,
                None => panic!("the node's notification stream ended with {at:?} resolved"),
            }
            // The advance has happened; wait for the loop to have written an epoch's slot before asking.
            // This is an assertion in its own right — it is what "the loop republishes" means — and it is
            // what stops the resolve below from racing a publisher that has not run yet.
            let epoch = slot_written(&client, &address).await;
            let (coord, got) = resolver.resolve(&host).await.unwrap_or_else(|| {
                panic!(
                    "the service is unresolvable at epoch {} — the republish loop did not write this \
                     epoch's slot, and the previous epoch's grace slot did not cover it either",
                    epoch.get()
                )
            });
            assert_eq!(
                coord,
                COORD,
                "the coordinate came back wrong at epoch {} — the descriptor resolved, so this is the \
                 metadata round trip and not the rotation",
                epoch.get()
            );
            assert_eq!(
                got, bundle,
                "the resolver returned a different identity than the one published at epoch {}",
                epoch.get()
            );
            at.insert(epoch.get());
        }
        at
    })
    .await
    .expect("three distinct advances, each with the service resolvable, must fit in the timeout");

    assert!(
        resolved_at.iter().all(|&e| e >= 1),
        "beacon rounds fire only past genesis, so a 0 here means the fixture, not the rotation: \
         {resolved_at:?}"
    );
    assert!(
        resolved_at.len() >= 3,
        "the service must stay resolvable across repeated advances, not once: {resolved_at:?}"
    );

    node.shutdown().await;
}

/// **The rotation bought something: the slot it left behind is reclaimed**, and a resolver pinned to that
/// slot no longer finds the service while one that follows the beacon still does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_genesis_slot_is_reclaimed_and_only_a_following_resolver_still_finds_the_service() {
    let (bundle, address) = service_identity();
    let host = address.to_name();
    let mut node = Node::start::<F2>(anchored()).await.expect("the node starts");
    let client = node.client();
    let genesis_slot = lookup_key(&address, Epoch::ZERO).to_vec();

    publish_service(&client, &bundle, COORD, Epoch::ZERO, 0, PROFILES)
        .await
        .expect("the genesis descriptor lands");
    // THE SETUP, ASSERTED. Without this the reclamation below is satisfied by a build that never wrote
    // anything: "absent at epoch 4" would be a claim about nothing.
    assert!(
        client.get(genesis_slot.clone()).await.is_some(),
        "the genesis slot must hold the descriptor before anything can be said about it being reclaimed"
    );

    let _publisher =
        spawn_descriptor_publisher(client.clone(), bundle.clone(), COORD, 0, PROFILES.to_vec());

    // Epoch 4, not the first advance that can have swept the genesis slot. The boundary — which advance
    // exactly kills it — is `DIRECTORY_SLOT_EPOCHS`, pinned in `resolve.rs`'s unit test against the constant
    // itself. Sitting on the boundary here would make this test fail for a reason it cannot report.
    let seen = advance_to(&mut node, 4).await;
    // Not a sleep: wait for the rotation to have actually landed somewhere past genesis, so the resolve
    // below is a claim about the resolver's window rather than about the publisher's latency.
    let live = slot_written(&client, &address).await;
    assert!(
        live > Epoch::ZERO,
        "the slot the publisher wrote is still genesis at {live:?} — nothing has rotated, and the two \
         resolvers below would agree for that reason rather than for the one under test"
    );

    // The presence reading FIRST, while the sample is fresh: it is the only claim here that is about an
    // instant rather than about a monotone fact, and the two readings below each cost a full read timeout.
    let following = NodeResolver::new(client.clone(), None, 0);
    let (coord, got) = following.resolve(&host).await.unwrap_or_else(|| {
        panic!("a resolver that follows the beacon must find the service at epoch {live:?}")
    });
    assert_eq!(coord, COORD, "the coordinate survived the rotation");
    assert_eq!(got, bundle, "and so did the identity");

    // Monotone, so it stays true however far the clock runs during the read: the publisher only ever writes
    // the epoch it is in, so a swept slot is never written again.
    assert_eq!(
        client.get(genesis_slot).await,
        None,
        "the genesis slot outlived its epochs (saw {seen:?}) — the descriptor write is not soft state, so \
         an observer watching that one slot sees every access to this service for as long as it runs"
    );

    // The discriminator, and the reason the resolve above is not passing on a resolver that finds everything
    // everywhere: the same store answers differently depending only on which epoch the reader asks about.
    // Monotone for the same reason, so taking it last costs nothing.
    let pinned = NodeResolver::new(client.clone(), Some(Epoch::ZERO), 0);
    assert!(
        pinned.resolve(&host).await.is_none(),
        "a resolver pinned at genesis must NOT find a service whose slot has moved on — if it does, the \
         old slot is still live and the rotation is cosmetic"
    );

    node.shutdown().await;
}
