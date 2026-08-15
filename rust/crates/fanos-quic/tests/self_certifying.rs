//! Self-certifying identity over real QUIC (mutual TLS). Each node's overlay coordinate is
//! `MapToPoint(H(cert))`; the mutual-TLS handshake proves the peer holds that certificate's key,
//! so the peer's coordinate is *authenticated by the handshake* — no HELLO, no directory-trust for
//! identity. An impostor at a resolved address (wrong cert → wrong coordinate) is rejected.
//!
//! Runtime: multi-threaded with **four** workers — a current-thread harness cannot see a parallelism
//! defect at all (#84), and two workers see it only 3 times in 8 where four see it 8 of 8. Measured
//! against the reverted fix for #83; the table is in `fanos-quic/tests/store_acks.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration as StdDuration;

use fanos_field::F7;
use fanos_geometry::{Point, Triple};
use fanos_quic::{
    Directory, NodeCredentials, NodeHandle, spawn_self_certifying, spawn_self_certifying_persistent,
};
use fanos_runtime::{Command, Config, Engine, Notification, OverlayNode};

fn make_node(coord: Point<F7>) -> Box<dyn Engine + Send> {
    Box::new(OverlayNode::<F7>::new(coord, Config::default()))
}

/// Spawn a self-certifying node whose cert-derived coordinate (`MapToPoint(H(cert))`) differs from
/// every one already in `taken`. A cell's members occupy **distinct** points, but two fresh
/// identities collide on the same point `1/N` of the time — retry until distinct, otherwise the
/// coordinate→node mapping is ambiguous and routing between the colliding pair breaks.
async fn spawn_distinct(dir: &Directory, taken: &[Triple]) -> NodeHandle {
    loop {
        let node = spawn_self_certifying::<F7>(make_node, dir.clone())
            .await
            .expect("spawn");
        if !taken.contains(&node.address()) {
            return node;
        }
        node.shutdown();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cert_bound_identity_delivers_and_authenticates_the_sender() {
    // A *delivery* assertion, so it is guarded. Its two siblings here are not, deliberately: an impostor
    // being rejected and a coordinate surviving a restart are structural, and a starved box cannot make
    // either of them wrongly pass — guarding them would weaken a test for no reason.
    fanos_testkit::require_quiet_host("whether a cert-bound identity delivers and authenticates its sender");
    let dir = Directory::new();
    // A and B sit at their cert-derived coordinates (none was assigned), at distinct points.
    let a = spawn_distinct(&dir, &[]).await;
    let mut b = spawn_distinct(&dir, &[a.address()]).await;

    let payload = b"authenticated by my certificate".to_vec();
    a.command(Command::Send {
        to: b.address(),
        payload: payload.clone(),
    });

    let (from, got) = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let Some(Notification::Delivered { from, payload }) = b.next_notification().await {
                return (from, payload);
            }
        }
    })
    .await
    .expect("delivery timed out");

    assert_eq!(got, payload);
    // The sender coordinate B sees is A's cert-derived coordinate — proven by A's client cert,
    // not merely claimed. B never read a HELLO.
    assert_eq!(from, a.address());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_impostor_at_the_resolved_address_is_rejected() {
    let dir = Directory::new();
    let a = spawn_distinct(&dir, &[]).await;
    let mut b = spawn_distinct(&dir, &[a.address()]).await;
    let c = spawn_distinct(&dir, &[a.address(), b.address()]).await;

    // **Wait for B's binding to be PROVEN before testing that a proof cannot be overwritten.** `spawn_inner`
    // seeds an unranked entry and the reshuffle loop replaces it with the ranked one on a spawned task, so
    // "B has a proven claim" is not true the instant `spawn_distinct` returns — it is true a moment later.
    // Asserting through that window passed whenever the task happened to win the race and failed under load,
    // which is a property of the machine rather than of the rank rule.
    //
    // `claim_at` is the oracle that already answers this — `None` covers "free" and "occupied but unranked"
    // alike, which is exactly the distinction being waited on. A second accessor was written for it and
    // deleted: the architecture ratchet flagged it as public-and-uncalled, and it was right, because the
    // question already had an answer with a production caller (`Node::health`'s `probe_index`).
    tokio::time::timeout(StdDuration::from_secs(5), async {
        while dir.claim_at(b.address()).is_none() {
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("B's own coordinate claim must be seated before the arbitration rule can be tested");

    // A naive overwrite no longer poisons anything, and that is the rank rule working: B's binding was made *with* its
    // verified rank when B spawned, and an unranked write carries no evidence, so it cannot evict a proven claim
    // (`Directory::supersedes`). This assertion is the reason the test below has to reach for a realistic stale entry.
    let _ = dir.insert(b.address(), c.local_addr());
    assert_eq!(dir.resolve(b.address()), Some(b.local_addr()), "an unranked write must not evict a proven binding");

    // The realistic stale entry: B vacates its point (an epoch reshuffle does exactly this) and C is bound there
    // afterwards, so a send to B's *old* coordinate reaches C. Nothing about that is forgery — it is why the dialer must
    // still check the certificate against the coordinate it asked for.
    assert!(
        dir.remove_if(b.address(), b.local_addr()),
        "B vacates the point it actually holds — a compare-and-remove, so the setup cannot silently \
         delete someone else's binding and leave the precondition unmet (#241)"
    );
    let _ = dir.insert(b.address(), c.local_addr());
    assert_eq!(dir.resolve(b.address()), Some(c.local_addr()), "a vacated point is free to rebind");

    // A dials "B" but reaches C, whose certificate certifies C's coordinate, not B's → A rejects
    // the connection and the frame is dropped. B receives nothing.
    a.command(Command::Send {
        to: b.address(),
        payload: b"should not arrive".to_vec(),
    });
    let delivered = tokio::time::timeout(StdDuration::from_secs(2), b.next_notification()).await;
    assert!(
        delivered.is_err(),
        "an impostor whose cert does not certify the dialed coordinate must be rejected"
    );
    let _ = c; // keep C alive for the duration
}

/// The same construction as the test above, asking the other half of the question (#240).
///
/// **Non-delivery was never the whole property.** Its sibling asserts that B receives nothing, and that
/// assertion is satisfied by a dial that was refused *and* by a dial that never happened — three separate
/// harnesses were built against this code path before that was noticed, and each failed because the path
/// only exists in self-certifying mode. `directory.stale_coordinate` is the discriminator: it is written on
/// exactly one arm, so a non-zero count is proof the dialer reached the peer, read its proof, and judged it.
///
/// **What the judgement must be.** `peer != Some(to)` used to cover two situations with one `return None`:
/// a peer that proved nothing (an impostor), and a peer that proved a *different* coordinate. The second is
/// a seat rotation — routine under §L3, where every coordinate is redrawn each epoch — and the correction
/// travels inside the rejection, because the peer has just proved where it actually is. Discarding it left
/// the stale entry in place, so the next frame dialed the same wrong address and got the same right answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_answered_by_a_different_proved_coordinate_repairs_the_stale_entry() {
    let dir = Directory::new();
    let a = spawn_distinct(&dir, &[]).await;
    let b = spawn_distinct(&dir, &[a.address()]).await;
    let c = spawn_distinct(&dir, &[a.address(), b.address()]).await;

    tokio::time::timeout(StdDuration::from_secs(5), async {
        while dir.claim_at(b.address()).is_none() {
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("B's own claim must be seated before it can be made stale");

    // B vacates its point and C is bound there, exactly as the sibling test does: a send to B's old
    // coordinate now resolves to C's address.
    assert!(
        dir.remove_if(b.address(), b.local_addr()),
        "B vacates the point it actually holds — a compare-and-remove, so the setup cannot silently \
         delete someone else's binding and leave the precondition unmet (#241)"
    );
    let _ = dir.insert(b.address(), c.local_addr());
    assert_eq!(dir.resolve(b.address()), Some(c.local_addr()), "a vacated point is free to rebind");
    assert_eq!(stale_repairs(&a), 0, "nothing has been diagnosed before the dial");

    a.command(Command::Send {
        to: b.address(),
        payload: b"addressed to a seat its occupant has left".to_vec(),
    });

    let repairs = tokio::time::timeout(StdDuration::from_secs(10), async {
        loop {
            let n = stale_repairs(&a);
            if n > 0 {
                return n;
            }
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
    })
    .await
    .expect("a dial answered by a different PROVED coordinate is a stale directory entry, not a forgery, and must be counted as one");
    assert_eq!(repairs, 1, "one dial, one diagnosis");

    // The repair itself, and the reason it is not asserted as `resolve(..) == None`: B is still running, so
    // its own reshuffle loop may re-seat its proven binding at any moment after the retraction. The property
    // is that B's coordinate no longer names C's address — which is true whether the slot is now empty or
    // holds B's real one.
    assert_ne!(
        dir.resolve(b.address()),
        Some(c.local_addr()),
        "the entry that sent the dial to the wrong node must not survive the dial that proved it wrong"
    );
    // And the coordinate C proved is bound to the address it was proved at.
    assert_eq!(dir.resolve(c.address()), Some(c.local_addr()));

    // **The connection is KEPT, not thrown away** (#264) — the half this test did not ask about.
    //
    // A dialed C, C's accept loop filed that connection under A's coordinate as its route back (#119), and
    // that write is unconditional — so it replaced whatever live connection C held for A. A then discarding
    // its end closed the very connection C's map now points at. A coordinate move is routine (this test is
    // the routine case), so the throwaway was routine too, and each one silently cost the answering peer its
    // route home.
    //
    // Asserted on the retention counter rather than on a delivery, because a delivery cannot discriminate:
    // A holds C's address in the shared directory, so a send to C would dial cleanly whether or not this
    // connection survived, and the test would pass against the defect. The counter fires on exactly the
    // branch under test.
    let retained = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            let n = moved_peers_retained(&a);
            if n > 0 {
                return n;
            }
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
    })
    .await
    .expect(
        "the dial proved C at its own coordinate, so A holds a live authenticated connection to a proven \
         peer — exactly what the connection map is for. Dropping it is what closed C's route back to A.",
    );
    assert_eq!(retained, 1, "one dial, one diagnosis, one connection kept");
}

/// Count of `directory.moved_peer_retained` on a node's transport driver.
fn moved_peers_retained(node: &NodeHandle) -> u64 {
    node.client()
        .driver_stations()
        .iter()
        .filter(|o| o.station.name() == "directory.moved_peer_retained")
        .map(|o| o.count)
        .sum()
}

/// Count of `directory.stale_coordinate` on a node's transport driver.
fn stale_repairs(node: &NodeHandle) -> u64 {
    node.client()
        .driver_stations()
        .iter()
        .filter(|o| o.station.name() == "directory.stale_coordinate")
        .map(|o| o.count)
        .sum()
}

fn seat_refusals(node: &NodeHandle) -> u64 {
    node.client()
        .driver_stations()
        .iter()
        .filter(|o| o.station.name() == "directory.seat_superseded")
        .map(|o| o.count)
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_whose_own_seat_is_already_proven_taken_says_so_instead_of_writing_nothing() {
    // The PROPERTY: when the arbitration rule refuses this node's write of its OWN coordinate, the node reports it.
    // Before #241 every `Directory` write returned `()`, so a node could start up, announce a coordinate, and be
    // absent from its own address book at that very point with nothing anywhere saying so.
    //
    // Constructed with persistent credentials because the seat has to be known BEFORE the node exists: a
    // self-certifying coordinate is `MapToPoint(H(cert))`, so the same credentials land on the same point twice, and
    // the first spawn is only there to learn where the second one will sit.
    let creds = NodeCredentials::generate().expect("generate credentials");
    let probe = spawn_self_certifying_persistent::<F7>(&creds, make_node, Directory::new())
        .await
        .expect("spawn to learn the seat");
    let seat = probe.address();
    probe.shutdown();
    let decoy: std::net::SocketAddr = "127.0.0.1:9".parse().expect("decoy address");

    // World 1 — the seat is held by a PROVEN claim (index 0, the minimum rank, so nothing beats it). The node's own
    // write must lose, and the loss must be visible.
    let contested = Directory::new();
    assert_eq!(
        contested.insert_claimed(seat, decoy, [0u8; 64], 0),
        fanos_quic::WriteOutcome::Bound,
        "the setup write itself must land, or this test measures an empty directory"
    );
    let node = spawn_self_certifying_persistent::<F7>(&creds, make_node, contested.clone())
        .await
        .expect("spawn onto a contested seat");
    assert_eq!(node.address(), seat, "the same credentials must land on the same point, or nothing is contested");
    assert!(
        seat_refusals(&node) >= 1,
        "a node refused its own seat must count it; stations: {:?}",
        node.client().driver_stations()
    );
    assert_eq!(
        contested.resolve(seat),
        Some(decoy),
        "and the refusal is real rather than reported — the proven claim still holds the point"
    );
    node.shutdown();

    // World 2 — the discriminator. The same seat, the same decoy, the same startup path, and the ONLY difference is
    // that the incumbent is unranked (a bootstrap seed, which is what a directory is normally pre-filled with). That
    // write lands, so the station must stay silent: a counter that fires in both worlds measures the startup, not the
    // refusal.
    let seeded = Directory::new();
    let _ = seeded.insert(seat, decoy);
    let node = spawn_self_certifying_persistent::<F7>(&creds, make_node, seeded)
        .await
        .expect("spawn onto a seeded seat");
    assert_eq!(seat_refusals(&node), 0, "an unranked seed yields to this node, so there is nothing to report");
    node.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_credentials_keep_the_same_coordinate_across_restarts() {
    // Mint an identity, persist it to bytes, and reload it (as an app would across a restart).
    let creds = NodeCredentials::generate().expect("generate credentials");
    let reloaded = NodeCredentials::from_bytes(&creds.to_bytes()).expect("reload credentials");

    let a = spawn_self_certifying_persistent::<F7>(&creds, make_node, Directory::new())
        .await
        .expect("spawn with credentials");
    let coord = a.address();
    a.shutdown();

    // A fresh node from the *same* persisted credentials occupies the *same* coordinate — a durable
    // overlay identity, not a new one each boot.
    let b = spawn_self_certifying_persistent::<F7>(&reloaded, make_node, Directory::new())
        .await
        .expect("spawn from reloaded credentials");
    assert_eq!(b.address(), coord, "coordinate is stable across restarts");
}

/// **The send ladder's last rung reaches a configured entry address** (#263).
///
/// A coordinate with no directory address, no cached connection and no relay hub used to be a bare drop.
/// That is exactly the state a node lands in when its own lawful reseat overwrote the one address it was
/// given (#263), and the address it needs is the one the operator configured — held outside the coordinate
/// map so nothing can arbitrate it away.
///
/// **Asserted on the attempt, not a delivery.** The rung is recovery: the frame that triggered it is dropped
/// and the dial runs detached, because awaiting it would put a `DIAL_TIMEOUT` on the drop path (#129). What
/// the dial buys is the next frame.
///
/// Falsified by not arming the entry list — the station never fires, because the ladder has nothing below
/// the hub. That is also the pre-#263 behaviour, so the same edit reproduces the defect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unroutable_coordinate_falls_back_to_a_configured_entry_address() {
    let dir = Directory::new();
    let a = spawn_distinct(&dir, &[]).await;
    let b = spawn_distinct(&dir, &[a.address()]).await;

    // The operator's bootstrap line, recorded the way `seed_directory` does: the ADDRESS on its own, with
    // no coordinate attached, because the coordinate is the perishable half.
    dir.note_entry(b.local_addr());

    // A point nobody holds and the directory does not name, so the ladder falls through every rung above.
    let orphan = [1u32, 1, 1];
    assert_ne!(orphan, a.address());
    assert_ne!(orphan, b.address());
    assert_eq!(dir.resolve(orphan), None, "the precondition is an UNROUTABLE coordinate, not a slow one");

    a.command(Command::Send { to: orphan, payload: b"nobody holds this point".to_vec() });

    let fell_back = tokio::time::timeout(StdDuration::from_secs(10), async {
        loop {
            let n = entry_fallbacks(&a);
            if n > 0 {
                return n;
            }
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
    })
    .await
    .expect(
        "with no address, no cached connection and no hub, the configured entry address is the only thing \
         left — and before #263 the ladder simply dropped the frame there",
    );
    assert!(fell_back > 0);
}

/// Count of `directory.entry_fallback` on a node's transport driver.
fn entry_fallbacks(node: &NodeHandle) -> u64 {
    node.client()
        .driver_stations()
        .iter()
        .filter(|o| o.station.name() == "directory.entry_fallback")
        .map(|o| o.count)
        .sum()
}

/// Count of `transport.self_connection` on a node's transport driver.
fn self_connections(node: &NodeHandle) -> u64 {
    node.client()
        .driver_stations()
        .iter()
        .filter(|o| o.station.name() == "transport.self_connection")
        .map(|o| o.count)
        .sum()
}

/// **A node addressing its own coordinate reaches itself, and that is refused and counted** (#350).
///
/// The production condition is a coordinate collision: `MapToPoint(H(cert))` is drawn independently per
/// identity, so on `PG(2, q)` two nodes share a point about once in `q² + q + 1` draws — measured on this
/// tree at 20 collisions in 966 pairs, against a derived 1 in 57. The directory then serves that point as
/// one address, the incumbent's, so the incumbent addressing the *other* claimant dials itself. Measured
/// before this refusal existed: **20 of 20** payloads were delivered to the sender and 0 to the addressee,
/// with no counter anywhere — the symptom reaching a maintainer was an unrelated test hanging 1 run in 9.
///
/// Reproduced here **without the lottery**: one node, addressed at its own point, which is the same
/// condition the collision produces and is reached deterministically. `spawn_distinct` (top of this file)
/// exists precisely because the collision is real, and its doc has said so all along — "routing between the
/// colliding pair breaks". It avoids the condition; this asserts what happens when a deployment meets it.
///
/// Asserts BOTH halves, because either alone is satisfiable by a broken node: nothing is delivered (the
/// frame did not loop back into our own engine) AND the refusal is counted (we did not merely fail to dial).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_reaches_itself_refuses_the_connection_and_counts_it() {
    let dir = Directory::new();
    let mut node = spawn_self_certifying::<F7>(make_node, dir.clone())
        .await
        .expect("spawn");

    // The setup took effect: our own point really does resolve to our own socket, so the send below is a
    // dial at ourselves and not a dial into the void. Without this the test passes on a node that never
    // dialled at all, which is the vacuous form of every "nothing arrived" assertion.
    assert_eq!(
        dir.resolve(node.address()),
        Some(node.local_addr()),
        "our own coordinate must resolve to our own socket, or this test is not exercising a self-dial",
    );
    assert_eq!(self_connections(&node), 0, "no self-connection has happened yet");

    node.command(Command::Send {
        to: node.address(),
        payload: b"addressed at the point we ourselves hold".to_vec(),
    });

    // Run until EITHER outcome shows itself, then let the assertions below speak. The loop exits early on
    // the refusal (the correct world) and early on a delivery (the defect's world), so the full bound is
    // paid only when neither happens — fast when right, bounded when wrong.
    //
    // **The deadline is deliberately NOT an assertion of its own.** It was one, and falsifying this test
    // caught the mistake: folding "timed out" into a single message made that message lie in the world where
    // the refusal fires but goes uncounted — it accused the dial path of never reaching the check, which was
    // false. Each fact now carries its own verdict, so a run that reaches the bound fails at whichever
    // property is actually unmet.
    let deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
    let mut delivered_to_self = false;
    while self_connections(&node) == 0 && !delivered_to_self && tokio::time::Instant::now() < deadline {
        tokio::select! {
            n = node.next_notification() => {
                if matches!(n, Some(Notification::Delivered { .. })) {
                    delivered_to_self = true;
                }
                if n.is_none() {
                    break;
                }
            }
            () = tokio::time::sleep(StdDuration::from_millis(20)) => {}
        }
    }

    assert!(
        !delivered_to_self,
        "the frame was delivered to the sender: a node completed a mutual-TLS handshake with itself and \
         handed its own frame to its own engine as though a peer had sent it. This is the defect #350 \
         measured 20 times out of 20, and the addressee — a different node holding the same point — got \
         nothing",
    );
    assert_eq!(
        self_connections(&node),
        1,
        "the loop-back must be counted exactly once at `transport.self_connection`. Zero here means the \
         refusal happened silently — folded into an existing verdict, or dropped before the station — which \
         is the state this whole task started from: an operator reading a dial failure and a self-connection \
         the same way cannot tell a network fault from a placement collision, and only the second is fixed \
         by reseating. (A zero can also mean the dial never reached `hello_exchange` within ten seconds; the \
         delivery assertion above distinguishes them, since the defect's world delivers.)",
    );

    node.shutdown();
}
