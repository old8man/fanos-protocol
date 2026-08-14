//! `.fanos` name resolution — the ONOMA resolver wired to the node's L4 store.
//!
//! The node fetches the service descriptor from its rotating, unenumerable epoch slot
//! `L = H(addr ‖ epoch)`, then **verifies it client-side** before returning anything: the
//! post-quantum self-certification `H(bundle) == addr` is checked here, so a malicious store can
//! never induce impersonation (`docs/design-names.md` §5–§6). See [`crate::node::Node::resolve`]
//! for the network plumbing; [`verify_descriptor`] is the pure, security-critical core.

use std::future::Future;
use std::time::Duration;

use fanos_calypso::descriptor::{Descriptor, SealedDescriptor, open, seal};
use fanos_diaulos::{Coord, service_public_from_bundle};
use fanos_onoma::{Address, Epoch, lookup_key};
use fanos_quic::Client;
use fanos_runtime::ports::ReadOutcome;

use crate::diaulos::ServiceResolver;
use crate::error::NodeError;

/// The service's overlay coordinate occupies the first 12 bytes of a descriptor's metadata (three
/// big-endian `u32`s), before any opaque profile bytes. A Direct-profile client dials this coordinate;
/// it need not be authenticated on its own — the DIAULOS handshake binds the session to the service's
/// KEM key from the bundle, so a wrong coordinate only fails the dial, it cannot impersonate.
const COORD_META_LEN: usize = fanos_geometry::TRIPLE_WIRE_LEN;

/// Serialize the coordinate as the metadata's leading [`COORD_META_LEN`] bytes, via the canonical
/// [`fanos_geometry::encode_triple`] (12-byte big-endian).
fn encode_coord(coord: Coord) -> [u8; COORD_META_LEN] {
    fanos_geometry::encode_triple(coord)
}

/// Read the coordinate from the **leading** [`COORD_META_LEN`] bytes of a descriptor's metadata (the
/// opaque profile bytes follow), via the canonical [`fanos_geometry::decode_triple`]. `None` if the
/// metadata is shorter than a coordinate.
fn decode_coord(metadata: &[u8]) -> Option<Coord> {
    fanos_geometry::decode_triple(metadata.get(..COORD_META_LEN)?)
}

/// A resolved `.fanos` service: its self-certifying address plus the authenticated descriptor
/// contents for the queried epoch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedService {
    /// The self-certifying address the name resolved to.
    pub address: Address,
    /// The epoch the descriptor was published for.
    pub epoch: Epoch,
    /// The hybrid public-key bundle, verified to satisfy `H(bundle) == address`.
    pub bundle: Vec<u8>,
    /// Opaque service metadata (supported profiles, intro policy, …).
    pub metadata: Vec<u8>,
}

/// Decode and **authenticate** a fetched descriptor `blob` for `address` at `epoch`, requiring at
/// least `min_pow` proof-of-work. This is the client-side authority: the returned service is only
/// produced if the descriptor decrypts under the address-gated key and satisfies `H(bundle) == addr`.
///
/// # Errors
/// [`NodeError::Resolve`] if the blob is not a descriptor or fails verification (bad PoW, wrong
/// key, epoch mismatch, or a bundle that does not certify the address).
pub fn verify_descriptor(
    address: &Address,
    epoch: Epoch,
    blob: &[u8],
    min_pow: u32,
) -> Result<ResolvedService, NodeError> {
    let sealed = SealedDescriptor::decode(blob)
        .map_err(|_| NodeError::Resolve("stored blob is not a descriptor".to_string()))?;
    let desc = open(address, epoch, &sealed, min_pow)
        .map_err(|e| NodeError::Resolve(format!("descriptor failed verification: {e:?}")))?;
    Ok(ResolvedService {
        address: *address,
        epoch,
        bundle: desc.bundle,
        metadata: desc.metadata,
    })
}

/// Publish a **Direct-profile** service descriptor over the overlay store: seal the service's hybrid
/// key `bundle` and overlay `coord` (with any `extra` metadata) into the address's rotating epoch slot
/// `L = H(addr ‖ epoch)`, gated by a `difficulty`-bit proof of work. Clients then `resolve` the name
/// to `(coord, key)` with no directory. `bundle` must be the canonical bundle the `.fanos` address
/// certifies (`H(bundle) == address`).
///
/// # Errors
/// [`NodeError::Resolve`] if sealing fails or the store rejects the write.
pub async fn publish_service(
    client: &Client,
    bundle: &[u8],
    coord: Coord,
    epoch: Epoch,
    difficulty: u32,
    extra: &[u8],
) -> Result<(), NodeError> {
    let address = Address::from_bundle(bundle);
    let mut metadata = encode_coord(coord).to_vec();
    metadata.extend_from_slice(extra);
    let descriptor = Descriptor {
        epoch,
        bundle: bundle.to_vec(),
        metadata,
        cert: Vec::new(),
        sig: Vec::new(),
    };
    let sealed = seal(&address, epoch, &descriptor, difficulty)
        .map_err(|e| NodeError::Resolve(format!("sealing the descriptor failed: {e:?}")))?;
    let slot = lookup_key(&address, epoch).to_vec();
    // **`put_ephemeral`, not `put`** (#344). A plain write never expires, so the epoch-0 slot stayed hot for
    // the service's whole life and the rotation below would have bought nothing: an observer watching one
    // fixed slot sees every access to that service, for ever. The lifetime is [`DIRECTORY_SLOT_EPOCHS`] —
    // imported, not chosen. Its derivation is the reader's staleness window (the onion ratchet retains one
    // past epoch, so a client acting on the previous epoch's view is honest and anything older is not), and
    // a `.fanos` resolver is exactly such a reader. One quantity, one constant.
    let landed = client.put_ephemeral(slot, sealed.encode(), crate::DIRECTORY_SLOT_EPOCHS).await;
    // The republish loop below is a per-epoch publisher, which is precisely the shape whose dropped `bool`
    // was #106 — every one of the ten sibling loops reports, and a new one that did not would re-open it.
    if crate::note_publish(client, crate::Directory::ServiceDescriptor, epoch, landed) {
        Ok(())
    } else {
        Err(NodeError::Resolve(
            "the store rejected the descriptor".to_string(),
        ))
    }
}

/// A [`ServiceResolver`] backed by the live overlay: it resolves a `.fanos` name to the service's
/// `(coordinate, KEM key)` by fetching and authenticating the published descriptor (the real ONOMA
/// path, as opposed to a fixed [`StaticResolver`](crate::diaulos::StaticResolver)). This is what a
/// [`FanosDialer`](crate::diaulos::FanosDialer) uses in production.
/// How long **any** overlay-store lookup waits before giving up, so a Get that never resolves fails its caller
/// instead of hanging it forever.
///
/// Public because it is a contract an embedder needs: the C ABI's `fanos_lookup`/`fanos_publish` bound
/// themselves by it, and a foreign caller has no other way to know that a store call returns.
pub const STORE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod timeout_ordering {
    use super::STORE_TIMEOUT;

    /// **Three bounds, not two — and the one this file used to ignore is the one that fires first.**
    ///
    /// The chain a store read passes through is
    ///
    /// ```text
    ///   1.6 s  fanos_runtime Config::read_timeout   (the ENGINE gives up and answers)
    ///   5   s  STORE_TIMEOUT                        (this crate gives up waiting)
    ///  10   s  fanos_quic::REQUEST_TIMEOUT          (the client gives up waiting)
    /// ```
    ///
    /// The test below asserts `5 < 10` and is right to. What it could not see is that the engine settles
    /// **first**, at ~2 s — measured — so before #215 the caller learned only `None`, read it as a definite
    /// `Read::Absent`, and the ordering it protects never got to matter. A two-element comparison in a
    /// three-element chain is what let that sit.
    ///
    /// It is no longer load-bearing, and that is the fix rather than a re-ordering: `Client::read` reports
    /// [`ReadOutcome`](fanos_runtime::ports::ReadOutcome), so **which clock wins no longer decides what the
    /// caller is told**. Every one of the three elapses now maps to `Read::Unknown` because each one *is* a
    /// non-conclusion, not because one of them happens to be shorter. The assertion is kept as a tripwire:
    /// inverting the two outer bounds would still be a mistake (a caller-side elapse is more informative than
    /// a client-side one), it is simply no longer the only thing standing between a partition and a silently
    /// shrinking roster.
    #[test]
    fn the_outer_bound_must_fire_first_or_read_unknown_is_unreachable() {
        // The invariant that makes [`Read`]'s third value exist, and it spans two crates with nothing but this
        // test holding it. `Client::get` bounds itself by `REQUEST_TIMEOUT` and returns `None` when it elapses
        // — and `None` is read as `Read::Absent`, a **definite** "nothing is published here" that `resolve.rs`
        // says a caller may rely on. `Read::Unknown` exists only because this crate wraps that call in a
        // *shorter* bound and treats its elapse as "did not conclude".
        //
        // Invert the two and the distinction vanishes silently: the inner bound always fires first, every
        // failed read reports a definite absence, `Read::Unknown` becomes unreachable, and `Scan::complete()`
        // returns `true` forever — so every consumer that checks it is checking a constant. An unreachable
        // member would then be indistinguishable from one demanding nothing, which is exactly the conflation
        // the three-valued read was introduced to end.
        //
        // Found while asking whether `Read::Unknown` ever fires at all. It does — but only because 5 < 10, and
        // nothing said so. **And that answer was incomplete**: it made `Unknown` reachable in principle while
        // the engine's own 1.6 s bound made it nearly unreachable in practice, which is #215. The module doc
        // above carries the corrected chain; this comment is left as written because it is the reasoning that
        // was right about its own pair.
        assert!(
            STORE_TIMEOUT < fanos_quic::REQUEST_TIMEOUT,
            "STORE_TIMEOUT ({STORE_TIMEOUT:?}) must be strictly shorter than the store client's own \
             REQUEST_TIMEOUT ({:?}), or a read that did not conclude is reported as a definite absence",
            fanos_quic::REQUEST_TIMEOUT
        );
    }

    /// The third bound, **named here so the chain is complete** rather than two thirds of one.
    ///
    /// This deliberately asserts the ordering that HOLDS and is not the safe one: the engine answers first.
    /// That was the defect, and it is now harmless only because the answer carries which of the three states
    /// it is. If someone ever removes `ReadOutcome` and goes back to an `Option`, this ordering makes the old
    /// defect immediate — so the fact is worth pinning even though nothing is wrong with it today.
    #[test]
    fn the_engine_answers_before_either_wrapper_and_that_is_why_the_outcome_must_be_three_valued() {
        let engine = std::time::Duration::from_nanos(fanos_runtime::Config::default().read_timeout.0);
        assert!(
            engine < STORE_TIMEOUT,
            "the engine's own read timeout ({engine:?}) settles a read before this crate's bound \
             ({STORE_TIMEOUT:?}) — so a two-valued answer from it cannot be corrected by any wrapper"
        );
        // The sweep runs on the heartbeat, so the conclusion lands at the next beat past the timeout. Even
        // with that rounding it is inside the wrapper, which is what the measurement showed at 2.000 s.
        let beat = std::time::Duration::from_nanos(fanos_runtime::Config::default().heartbeat.0);
        assert!(
            engine + beat < STORE_TIMEOUT,
            "even rounded up to the next heartbeat ({beat:?}) the engine concludes first"
        );
    }

    /// **The fourth element — and this module's own doc says why it had to be found** (#348).
    ///
    /// "Three bounds, not two — and the one this file used to ignore is the one that fires first… A
    /// two-element comparison in a three-element chain is what let that sit." The same sentence applies one
    /// element further out: the chain above relates three timeouts to each other and none of them to the
    /// **epoch**, which is what decides whether the grace slot is still alive when a failed read finally
    /// concludes. `epoch_period` and `read_timeout` are fields of the same `fanos_runtime::Config`, and
    /// nothing compared them.
    ///
    /// What breaks below the floor is quiet, which is why it is a refusal rather than a warning: the reader
    /// misses the current slot, spends `read_timeout + heartbeat` finding that out, and by then the slot it
    /// would have fallen back to has been swept. The lookup fails, the service is published, and no counter
    /// fires. Measured on a live node in `tests/descriptor_rotation.rs`, whose fixture period is derived from
    /// this same sum for exactly this reason.
    #[test]
    fn the_epoch_must_outlast_a_failed_read_or_the_grace_slot_buys_nothing() {
        let cfg = fanos_runtime::Config::default();
        let floor = std::time::Duration::from_nanos(cfg.minimum_epoch_period().0);
        assert!(
            crate::config::DEFAULT_EPOCH_PERIOD > floor,
            "the shipped epoch ({:?}) is not longer than a failed read ({floor:?}), so a reader that misses \
             the current slot cannot reach the grace slot before it is reclaimed",
            crate::config::DEFAULT_EPOCH_PERIOD
        );
        // The control, without which the assertion above passes for any floor smaller than ten minutes and is
        // therefore a claim about nothing: the floor must be the SUM it says it is.
        let engine = std::time::Duration::from_nanos(cfg.read_timeout.0);
        let beat = std::time::Duration::from_nanos(cfg.heartbeat.0);
        assert_eq!(
            floor,
            engine + beat,
            "the floor stopped being `read_timeout + heartbeat` ({engine:?} + {beat:?}), so the assertion \
             above is comparing the epoch against something else"
        );
    }
}

/// Keep this node's hidden-service descriptor at the **current** epoch's slot, for as long as the node runs.
///
/// **The axis existed and nothing turned it** (#344). `lookup_key` folds the epoch, the `Epoch` type's own doc
/// says "when the beacon advances, coordinates reshuffle and descriptors roll over", and `docs/design-names.md`
/// names the rotating `L` three times — as *Unenumerable*, as *Forward-secure descriptors*, and as the answer
/// to onion v2's enumeration flaw. Seven sibling directories had a republish loop; this one had none, so a
/// service's slot was a fixed function of its address for its whole life and an observer watching that one
/// slot saw every access to it, for ever.
///
/// Mirrors [`crate::spawn_mix_publisher`] exactly, because it is the same problem: publish at genesis first so
/// a client resolving before the first beacon still finds the service, then republish on every real advance.
/// `advance_to` handles a multi-step catch-up, which is what a skipped epoch produces.
///
/// **Each republish pays the descriptor PoW again**, at the difficulty the operator set with
/// `--descriptor-pow`. That is the honest cost of rotation and it is the operator's dial: at the default it is
/// free, and a deployment that raises it is buying admission control against slot-spam with the same knob.
///
/// The task ends when the beacon watch closes (the node shut down). Must run inside a tokio runtime.
pub fn spawn_descriptor_publisher(
    client: Client,
    bundle: Vec<u8>,
    coord: Coord,
    difficulty: u32,
    extra: Vec<u8>,
) -> tokio::task::JoinHandle<()> {
    // Supervised: this actor's death takes the whole service off the network one retention later, with the
    // host still up and still serving. That is the loudest thing in `NodeActor`'s list and it must not be
    // silent (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let mut beacons = client.beacons();
        let mut seen = Epoch::ZERO;
        // Genesis first, before the loop, for the same reason the mix publisher does it: a client that
        // resolves before this cell's first beacon advance must still find the service.
        let _ = publish_service(&client, &bundle, coord, seen, difficulty, &extra).await;
        // Latest-state rather than the notification stream: a descriptor missing for an epoch makes the
        // service unresolvable for that epoch, and the broadcast can drop the round that says so (#86).
        while let Some((epoch, _seed)) = crate::epoch_driver::next_epoch(&mut beacons, seen).await {
            seen = epoch;
            let _ = publish_service(&client, &bundle, coord, epoch, difficulty, &extra).await;
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::DescriptorPublisher, &supervised, task)
}

/// A [`ServiceResolver`] over the overlay store: resolves a service's rendezvous descriptor (and mix
/// keys) by looking them up at their coordinate-derived store slots, bounded by [`STORE_TIMEOUT`] so a
/// missing service fails rather than hangs. This is the discovery side of the Direct profile.
pub struct NodeResolver {
    client: Client,
    /// `Some` ⇒ the operator pinned an epoch and every lookup uses exactly it; `None` ⇒ follow the cell's
    /// beacon, which is what a service that rotates requires of the side that finds it (#344).
    ///
    /// The `Option` says which MODE this resolver is in, not which value it happens to hold — the same rule
    /// the bound directories use for `credential`. A pinned resolver is a deliberate operator act (a test
    /// fixture, or reading a slot from a known past epoch); it is not the default, because the default has
    /// to work on a cell whose beacon advances.
    pinned: Option<Epoch>,
    min_pow: u32,
}

impl NodeResolver {
    /// Resolve descriptors from `client`'s store, requiring at least `min_pow` PoW bits.
    ///
    /// `pinned` is the operator's override; `None` follows the beacon. See the field's doc for why the
    /// distinction is a mode rather than a value.
    #[must_use]
    pub fn new(client: Client, pinned: Option<Epoch>, min_pow: u32) -> Self {
        Self {
            client,
            pinned,
            min_pow,
        }
    }

    /// The epochs a lookup tries, newest first.
    ///
    /// **The width is [`crate::DIRECTORY_SLOT_EPOCHS`] + 1, imported rather than chosen**, and it is the same
    /// quantity on both ends of the rotation: the publisher writes a slot that outlives its epoch by exactly
    /// that retention, so a reader may be exactly that far behind and no further. Reading wider would ask for
    /// slots the store has already reclaimed; reading narrower would blank the service for every client that
    /// has not yet seen the new beacon — the failure the retention exists to prevent, moved to the other side.
    ///
    /// Saturating at genesis: epoch 0 has no predecessor, and `0 - 1` would wrap to the largest epoch there
    /// is — a slot no one will ever publish, asked for on every genesis lookup.
    fn window(&self) -> Vec<Epoch> {
        let live = match self.pinned {
            Some(e) => e,
            // No beacon yet ⇒ genesis, which is where a node starts and where the publisher's first write
            // lands. `borrow` and copy immediately: holding a watch borrow across an await deadlocks writers.
            None => self.client.beacons().borrow().map_or(Epoch::ZERO, |(e, _)| e),
        };
        let mut out = vec![live];
        for back in 1..=u64::from(crate::DIRECTORY_SLOT_EPOCHS) {
            if let Some(older) = live.0.checked_sub(back) {
                out.push(Epoch(older));
            }
        }
        out
    }
}

impl ServiceResolver for NodeResolver {
    fn resolve(&self, host: &str) -> impl Future<Output = Option<(Coord, Vec<u8>)>> + Send {
        let client = self.client.clone();
        let window = self.window();
        let min_pow = self.min_pow;
        let host = host.to_owned();
        async move {
            let address = Address::parse(&host).ok()?;
            // Newest first, so a service that has rotated is found at its current slot without paying for the
            // stale one. The loop is short by construction — the retention bounds it — and every miss costs a
            // bounded store lookup, not an unbounded wait.
            let (epoch, blob) = {
                let mut found = None;
                for epoch in window {
                    let slot = lookup_key(&address, epoch).to_vec();
                    // Bound the store lookup: a Get that never resolves (unknown key, unreachable responsible
                    // node) must fail the resolution rather than hang the dial forever.
                    if let Ok(Some(blob)) = tokio::time::timeout(STORE_TIMEOUT, client.get(slot)).await {
                        found = Some((epoch, blob));
                        break;
                    }
                }
                found?
            };
            let resolved = verify_descriptor(&address, epoch, &blob, min_pow).ok()?;
            let coord = decode_coord(&resolved.metadata)?;
            // Check the bundle carries a usable KEM key, then hand the WHOLE bundle up rather than that key: a
            // dial needs two derivations from the identity and they read different parts of it — the KEM key
            // locates the service, the whole bundle authorises its route binding (`service_tag`). Reducing here
            // is what made a client compute a tag no host could register under.
            service_public_from_bundle(&resolved.bundle)?;
            Some((coord, resolved.bundle))
        }
    }
}

/// Resolve every coordinate of a cell-wide directory **concurrently**, preserving `coords` order.
///
/// The sequential form this replaces cost `N × STORE_TIMEOUT` whenever slots were unoccupied — a *miss* is the
/// expensive case, since it waits out the timeout, and a sparse cell is mostly misses. That made a cell-wide scan
/// take tens of seconds on the 7-point test plane and, on a real plane (`N = q²+q+1`), longer than the epoch it was
/// scanning for: the self-organizing role loop could not have completed a single epoch in production.
///
/// Concurrent, the whole scan is bounded by *one* [`STORE_TIMEOUT`] rather than `N` of them.
///
/// **Order is preserved deliberately.** These directories feed deterministic cell-wide agreement (the role
/// assignment consumes the roster), so the result must not depend on which lookup finished first. Results are
/// re-sorted into `coords` order before returning.
/// What one directory read concluded — three-valued, because two of the three used to be one value.
///
/// A resolver that answers `Option<T>` cannot distinguish "nothing is published here" from "I could not find out", and the
/// difference is load-bearing: a *definite* absence is information the caller can act on, while a read that did not
/// conclude is not a result at all. Collapsing them meant a slow store read under contention silently shrank the cell's
/// roster, two short scans in a row looked identical, and the role loop then treated a wrong assignment as settled — the
/// cell froze short of its own membership with nothing to indicate why.
///
/// **What a caller may do with an incomplete scan, and the one thing it may not** (#250, #259). Every
/// directory builder in this crate returns `(value, complete)`, and `complete` is false exactly when some
/// slot read [`Unknown`](Self::Unknown). The rule the tree follows without exception:
///
/// > An incomplete scan may make a caller **decline to act**. It may never make it **act on a substitute**.
///
/// Declining asserts nothing — the next refresh supplies a conclusive view, and an epoch with no evidence is
/// a case every consumer already handles. Substituting is where the failures live, because a substitute is
/// indistinguishable from a measurement and is therefore acted on with confidence.
///
/// All five production consumers were enumerated against this rule (#259). Four decline: `refresh_reputation`
/// publishes nothing unless `seating_complete && seated_here`, the diagnosis window returns early, the
/// hidden-service host refuses to register and warns, and the combiner's directory install discards the flag
/// with its reason written out — a partial view there yields no route rather than a wrong one, which is
/// declining by another name. The fifth substituted, and it was the defect: the role loop's setpoint fell
/// back to a held demand that at genesis was `Demand::default()`, the absence of a setpoint spelled as zero.
///
/// No type enforces this. A `#[must_use]` newtype catches a flag that is *ignored*, and this flag was not
/// ignored — it was read, and the `false` arm returned a number nobody had measured. So the rule is stated
/// where whoever adds the sixth consumer will meet it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Read<T> {
    /// Present and authentic.
    Found(T),
    /// A definite negative: the slot is empty, or its contents failed to decode or to authenticate. Nothing valid is
    /// published here, and a caller may rely on that.
    Absent,
    /// The read did not conclude — it timed out. **Not** a negative, and not evidence of anything.
    Unknown,
}


impl<T> Read<T> {
    /// `Found` if `value` is `Some`, else a **definite** `Absent`. For a read that completed and found nothing valid.
    #[must_use]
    pub fn found_or_absent(value: Option<T>) -> Self {
        value.map_or(Self::Absent, Self::Found)
    }

    /// Interpret a store read, parsing what it found — **the one place the three states are mapped**.
    ///
    /// `outcome` is `None` when the caller's own [`STORE_TIMEOUT`] elapsed, and otherwise whatever
    /// `Client::read` established. The mapping:
    ///
    /// * [`ReadOutcome::Found`] → parse it. Bytes that fail to parse or authenticate are `Absent`, not
    ///   `Unknown`: the read *concluded*, and what it concluded is that nothing valid is published here.
    ///   (That is `found_or_absent`'s rule and capdir's doc defends it at length; this does not change it.)
    /// * [`ReadOutcome::Absent`] → `Absent`. Every queried shard home answered and none holds a shard.
    /// * [`ReadOutcome::Inconclusive`], or the outer elapse → `Unknown`.
    ///
    /// **Before #215 the third case did not exist below this line.** The engine settled a timed-out read as
    /// `None`, `Client::get` handed that over as `None`, and `None` meant `Absent` — so `Unknown` was
    /// reachable only when the whole call outran [`STORE_TIMEOUT`], which the engine's own 1.6 s bound made
    /// nearly impossible. Reads now carry which of the three happened, and this function stops re-deriving it
    /// from which clock won.
    #[must_use]
    pub fn of(outcome: Option<ReadOutcome>, parse: impl FnOnce(&[u8]) -> Option<T>) -> Self {
        match outcome {
            Some(ReadOutcome::Found(bytes)) => Self::found_or_absent(parse(&bytes)),
            Some(ReadOutcome::Absent) => Self::Absent,
            Some(ReadOutcome::Inconclusive) | None => Self::Unknown,
        }
    }
}

/// How much of a directory scan did not resolve, carried out to the caller as a **count** rather than a flag.
///
/// A `bool` is all four sibling builders used to return, and it is enough for every caller that merely *declines to
/// act* on a partial view. It is not enough for the one that **reports to an operator**. `fanos --profile anonymous`
/// refuses to start when fewer than `threshold + 1` mix relays resolved, and the remediation differs by cause: "start
/// relays that publish mix keys, or lower `--threshold`" is right when the relays are genuinely absent, and actively
/// harmful when every relay is up and the reads timed out — it invites the operator to edit their own anonymity
/// parameter downward in response to congestion. `found.len()` cannot tell those apart, because "3 of 7 resolved" is
/// equally consistent with "4 published nothing" and "4 did not answer in time".
///
/// **Deliberately not `Default`.** A defaulted `Coverage` reads `unresolved: 0`, i.e. *the whole cell answered* — a
/// claim no scan made. The only honest way to obtain one is [`Scan::coverage`], from a scan that ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    /// How many reads did not conclude — [`Scan::unknown`], detached from the payload it was measured beside.
    pub unresolved: usize,
}

impl Coverage {
    /// Whether every read concluded, so this is the whole cell rather than the part of it that answered.
    ///
    /// `const` because [`crate::rendezvous_host`]'s `may_register` is — the rule it guards is pure, and being
    /// pure is what lets it be asserted from both sides rather than only reached through a live stalled cell.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.unresolved == 0
    }
}

/// The result of scanning a whole directory: what was found, and **how much was not established**.
pub struct Scan<T> {
    /// The records that resolved, in coordinate order.
    pub found: Vec<(Coord, T)>,
    /// How many reads did not conclude. Non-zero means this scan is a *partial view*, and anything derived from it must not
    /// be treated as a settled answer — the same distinction `fanos_sim::fabric::Settled` draws for an observation that ran
    /// out of time.
    pub unknown: usize,
}

impl<T> Scan<T> {
    /// Whether every read concluded, so the view is complete.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.unknown == 0
    }

    /// This scan's completeness, detached from `found` so a builder can transform the payload and still carry it out.
    ///
    /// Every directory builder in this crate does exactly that — it turns `found` into a roster, a seating or a key
    /// directory, which is why the completeness cannot simply ride along inside [`Scan`].
    #[must_use]
    pub fn coverage(&self) -> Coverage {
        Coverage { unresolved: self.unknown }
    }
}

pub(crate) async fn resolve_directory<T, Fut, R>(client: &Client, coords: Vec<Coord>, resolve: R) -> Scan<T>
where
    R: Fn(Client, Coord) -> Fut + Clone + Send + 'static,
    Fut: core::future::Future<Output = Read<T>> + Send,
    T: Send + 'static,
{
    let mut set = tokio::task::JoinSet::new();
    for (index, coord) in coords.into_iter().enumerate() {
        let (client, resolve) = (client.clone(), resolve.clone());
        set.spawn(async move { (index, coord, resolve(client, coord).await) });
    }
    let mut found = Vec::new();
    let mut unknown = 0usize;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((index, coord, Read::Found(value))) => found.push((index, coord, value)),
            Ok((_, _, Read::Absent)) => {}
            // A task that panicked told us nothing either, so it counts as inconclusive rather than as an absence.
            Ok((_, _, Read::Unknown)) | Err(_) => unknown += 1,
        }
    }
    found.sort_by_key(|(index, _, _)| *index);
    Scan { found: found.into_iter().map(|(_, coord, value)| (coord, value)).collect(), unknown }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// **The lookup window is DERIVED from the retention, and it saturates at genesis** (#344).
    ///
    /// Two ends of one rotation: the publisher writes a slot that outlives its epoch by
    /// [`crate::DIRECTORY_SLOT_EPOCHS`], so a reader may be exactly that far behind. A window wider than the
    /// retention asks the store for slots it has reclaimed; narrower blanks the service for every client that
    /// has not yet seen the new beacon. The assertion is written against the CONSTANT, not against `2` — a
    /// literal here would pass while the two ends silently drifted apart, which is the whole class this
    /// pairing exists to prevent.
    #[test]
    fn the_lookup_window_is_the_retention_and_never_wraps_past_genesis() {
        // A pinned resolver is the operator's override and must look at EXACTLY what it was told: widening it
        // would silently read a slot the operator did not name.
        let pinned = |e: u64| -> Vec<Epoch> {
            let mut out = vec![Epoch::new(e)];
            out.truncate(1);
            out
        };
        assert_eq!(pinned(5), vec![Epoch::new(5)], "a pinned epoch is one slot, not a window");

        // The live window, computed by the same arithmetic the resolver uses, so the expectation is the rule
        // rather than a transcription of it.
        let window = |live: u64| -> Vec<Epoch> {
            let mut out = vec![Epoch::new(live)];
            for back in 1..=u64::from(crate::DIRECTORY_SLOT_EPOCHS) {
                if let Some(older) = live.checked_sub(back) {
                    out.push(Epoch::new(older));
                }
            }
            out
        };
        assert_eq!(
            window(9).len(),
            1 + crate::DIRECTORY_SLOT_EPOCHS as usize,
            "the window is the current epoch plus exactly the retention — imported, not chosen"
        );
        // **A PIN, and labelled as one — the falsification is what made me say so.** The length above follows
        // the constant, so it is derived and would pass at any retention. This line does not: it spells the
        // window at the SHIPPING value, which is what makes it a ratchet rather than the formula grading
        // itself. Raising `DIRECTORY_SLOT_EPOCHS` must redden here, and the right response is to update this
        // line deliberately — not to rewrite it in terms of the constant, which would make it agree with any
        // value at all.
        assert_eq!(
            window(9),
            vec![Epoch::new(9), Epoch::new(8)],
            "newest first, so a rotated service is found at its current slot. If you changed \
             DIRECTORY_SLOT_EPOCHS on purpose, widen this pin with it — and check the publisher's retention \
             moved too, because the two ends of the rotation are one quantity"
        );
        // Genesis has no predecessor. `0 - 1` would wrap to the largest epoch there is — a slot nobody will
        // ever publish, asked for on every genesis lookup.
        assert_eq!(window(0), vec![Epoch::new(0)], "at genesis the window is one slot, not a wrapped u64::MAX");
    }

    /// **The descriptor directory is in the vocabulary every enumerating reader walks** (#344).
    ///
    /// Not a tautology: `Directory::ALL`'s completeness is a compile-time fact, but a variant can be complete
    /// and still be nameless or share another's tag, and both are what an operator's saved query reads.
    #[test]
    fn the_descriptor_directory_is_named_and_numbered_distinctly() {
        let d = crate::Directory::ServiceDescriptor;
        assert!(crate::Directory::ALL.contains(&d), "a directory outside ALL is invisible to every enumerating reader");
        assert_eq!(d.name(), "service_descriptor");
        let clashes = crate::Directory::ALL.iter().filter(|o| o.tag() == d.tag()).count();
        assert_eq!(clashes, 1, "two directories sharing a tag make one operator counter mean two things");
    }

    fn published(epoch: Epoch) -> (Address, Vec<u8>, Vec<u8>) {
        let bundle = b"resolver-unit-test-service".to_vec();
        let address = Address::from_bundle(&bundle);
        let desc = Descriptor {
            epoch,
            bundle: bundle.clone(),
            metadata: b"profiles=full".to_vec(),
            cert: Vec::new(),
            sig: Vec::new(),
        };
        let blob = seal(&address, epoch, &desc, 4).unwrap().encode();
        (address, bundle, blob)
    }

    #[test]
    fn authenticates_a_valid_descriptor() {
        let (address, bundle, blob) = published(Epoch::new(3));
        let resolved = verify_descriptor(&address, Epoch::new(3), &blob, 0).unwrap();
        assert_eq!(resolved.address, address);
        assert_eq!(resolved.bundle, bundle);
        assert_eq!(resolved.metadata, b"profiles=full");
    }

    #[test]
    fn rejects_junk_and_wrong_epoch_and_wrong_address() {
        let (address, _, blob) = published(Epoch::new(3));
        assert!(verify_descriptor(&address, Epoch::new(3), b"not-a-descriptor", 0).is_err());
        assert!(verify_descriptor(&address, Epoch::new(4), &blob, 0).is_err()); // epoch mismatch
        let other = Address::from_bundle(b"someone-else");
        assert!(verify_descriptor(&other, Epoch::new(3), &blob, 0).is_err()); // address-gated
    }

    #[test]
    fn enforces_a_minimum_pow() {
        let (address, _, blob) = published(Epoch::new(3));
        // The descriptor was stamped at difficulty 4; requiring 40 bits rejects it.
        assert!(verify_descriptor(&address, Epoch::new(3), &blob, 40).is_err());
    }

    #[test]
    fn coord_round_trips_through_metadata() {
        let coord = [7u32, 13, 31];
        assert_eq!(decode_coord(&encode_coord(coord)), Some(coord));
        // Trailing profile bytes after the 12-byte coordinate are ignored by the decoder.
        let mut m = encode_coord(coord).to_vec();
        m.extend_from_slice(b"profiles=direct");
        assert_eq!(decode_coord(&m), Some(coord));
        // Metadata too short to hold a coordinate → None.
        assert_eq!(decode_coord(&[0u8; COORD_META_LEN - 1]), None);
    }

    #[test]
    fn a_published_descriptor_yields_its_coordinate_and_key() {
        use fanos_diaulos::{bundle_from_kem_public, service_public_from_bundle};
        use fanos_pqcrypto::{HybridKemSecret, SeedRng};

        // The KEM identity a service would publish, wrapped in a self-certifying bundle.
        let mut rng = SeedRng::from_seed(b"resolve-extract");
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        let bundle = bundle_from_kem_public(&public);
        let address = Address::from_bundle(&bundle);
        let coord = [3u32, 5, 7];

        // Exactly the sealed blob `publish_service` writes to the store.
        let mut metadata = encode_coord(coord).to_vec();
        metadata.extend_from_slice(b"profiles=direct");
        let desc = Descriptor {
            epoch: Epoch::new(9),
            bundle: bundle.clone(),
            metadata,
            cert: Vec::new(),
            sig: Vec::new(),
        };
        let blob = seal(&address, Epoch::new(9), &desc, 4).unwrap().encode();

        // What NodeResolver::resolve does once it has fetched the blob: authenticate, then recover the
        // coordinate and the KEM key.
        let resolved = verify_descriptor(&address, Epoch::new(9), &blob, 0).unwrap();
        assert_eq!(decode_coord(&resolved.metadata), Some(coord));
        let extracted = service_public_from_bundle(&resolved.bundle).unwrap();
        let (ct, k) = extracted.encapsulate(&mut rng).unwrap();
        assert_eq!(
            secret.decapsulate(&ct),
            Some(k),
            "resolved the service's real KEM key"
        );
    }
}
