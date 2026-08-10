//! **The POROS ingress line's key directory** — what a rotation needs and could not have.
//!
//! An ingress line rotates every epoch (`docs/design-anonymity-substrate.md` §6): the moving target is the
//! whole point, because a blocklist must go stale. Rotating means resharing the community's descriptor from
//! the outgoing line to the incoming one, and each sub-share is **KEM-sealed to its recipient** — so an old
//! member has to hold each *new* member's hybrid-KEM public key.
//!
//! That is where the rotation stopped. `PorosHost::emit_reshare` takes those keys as an argument and
//! `IngressNode::emit_reshares` passes them through, but nothing could supply them: they live at the other
//! nodes, a `PorosHost` is a sans-I/O engine that cannot look anything up, and no slot published them. The
//! receive half needs no I/O at all (both rosters are a pure function of `(community, epoch, beacon)`), so it
//! was wired first; this module is the emit half's missing input.
//!
//! ## Why a slot of its own rather than reusing the mix key
//!
//! A relay's mix key is *forward-secure*: it ratchets each epoch and the old secret is destroyed
//! (`fanos-pqcrypto::onion_ratchet`, audit E4), which is exactly right for onion layers and exactly wrong
//! here. A rotation seals to a member's key **for a future epoch** and that member must still be able to
//! open it after the epoch turns — a ratcheted key would be gone. So an ingress member publishes a *stable*
//! KEM public, regenerated deterministically from the seed its provisioning file carries
//! (`IngressParams::kem_seed`), and the two keys are deliberately different keys with different lifetimes.
//!
//! The slot is still `(coordinate, epoch)`-keyed and still published as **soft state**
//! ([`Client::put_ephemeral`]): the coordinate rotates with the beacon, so last epoch's slot names a seat
//! this node no longer holds, and a directory slot that nothing reclaims is what filled a cell's store in a
//! day (`fanos-node/tests/store_lifetime.rs`).

use fanos_geometry::Triple;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_quic::{Client, CoordinateProver};
use fanos_vrf::{VrfProof, VrfPublic};
use fanos_field::Field;
use fanos_primitives::BeaconSeed;
use fanos_rendezvous::Epoch;

use fanos_primitives::codec::{Reader, put_seq, put_var_bytes};

use crate::DIRECTORY_SLOT_EPOCHS;
use crate::bound::Entitlement;
use crate::resolve::STORE_TIMEOUT;

/// **The control tag that hands a `PorosHost` what it cannot look up.**
///
/// Tag `3`, distinct from `CONTROL_MIX_DIRECTORY` (1) and `CONTROL_LOAD_READING` (2) — the space is
/// documented as per-sub-engine but matched flatly by the composites that route it, so a value must be
/// unique across all of them.
///
/// `Control` is the right carrier and not merely a convenient one: it is **local by construction**, entering
/// only through the node handle, so a peer cannot inject a rotation and talk an ingress line into resharing
/// a community's descriptor to a roster of its choosing. That property is why the keys travel this way
/// rather than as a wire frame.
pub const CONTROL_INGRESS_ROTATION: u16 = 3;

/// Encode a rotation instruction: `target_epoch(8) ‖ [member coord ‖ KEM public]* ‖ key_randomness ‖ kem_seed`.
///
/// The **randomness comes from the driver**, and that split is the design rather than a convenience: sealing
/// needs entropy, a sans-I/O engine must stay deterministic to remain simulable, and the driver is the party
/// that can draw from the OS. The engine holds the share; the driver holds the clock, the directory and the
/// randomness. Neither can rotate alone, which is exactly the seam.
#[must_use]
pub fn encode_rotation(
    target_epoch: Epoch,
    new_line: &[Triple],
    keys: &[HybridKemPublic],
    key_randomness: &[u8],
    kem_seed: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&target_epoch.to_be_bytes());
    put_seq(&mut out, new_line.len().min(keys.len()), new_line.iter().zip(keys), |o, (coord, key)| {
        o.extend_from_slice(&fanos_geometry::encode_triple(*coord));
        put_var_bytes(o, &key.encode());
    });
    put_var_bytes(&mut out, key_randomness);
    put_var_bytes(&mut out, kem_seed);
    out
}

/// A decoded rotation instruction — everything an outgoing member needs to emit its sealed sub-shares, and
/// nothing it could have obtained itself.
pub struct Rotation {
    /// The epoch the incoming line takes over at.
    pub target_epoch: Epoch,
    /// The incoming line's member coordinates, in roster order.
    pub new_line: Vec<Triple>,
    /// Each incoming member's KEM public, in the same order — the driver resolved these from the store.
    pub keys: Vec<HybridKemPublic>,
    /// Fresh polynomial randomness for the resharing, drawn by the driver.
    pub key_randomness: Vec<u8>,
    /// A fresh KEM seed, drawn independently of `key_randomness`.
    pub kem_seed: Vec<u8>,
}

/// Decode [`encode_rotation`], or `None` if malformed.
#[must_use]
pub fn decode_rotation(body: &[u8]) -> Option<Rotation> {
    let mut r = Reader::new(body);
    let target_epoch = Epoch::from_be_bytes(r.array::<8>()?);
    // Smallest element: a coordinate (12) plus a length-prefixed key (4 + at least 1).
    let members = r.seq(17, |r| {
        let coord = fanos_geometry::decode_triple(r.bytes(fanos_geometry::TRIPLE_WIRE_LEN)?)?;
        let key = HybridKemPublic::decode(r.var_bytes()?)?;
        Some((coord, key))
    })?;
    let key_randomness = r.var_bytes()?.to_vec();
    let kem_seed = r.var_bytes()?.to_vec();
    r.finish()?;
    let (new_line, keys) = members.into_iter().unzip();
    Some(Rotation { target_epoch, new_line, keys, key_randomness, kem_seed })
}

/// The store slot an ingress-line member publishes its **stable** KEM public at, for `epoch`.
///
/// Domain-separated from the mix-key slot on purpose rather than by accident: the two carry different keys
/// with different lifetimes (see the module docs), and sharing an address would let a rotation seal to a
/// ratcheting key that its recipient can no longer open.
fn ingress_key_slot(coord: Triple, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/ingress-key/".to_vec();
    key.extend_from_slice(&fanos_geometry::encode_triple(coord));
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// This member's stable ingress KEM keypair, regenerated in memory from its provisioning seed.
///
/// Deterministic in the seed, so the published public is the same across restarts — a rotation sealing to it
/// mid-epoch must not find a different key than the one it resolved.
#[must_use]
pub fn ingress_keypair(kem_seed: &[u8; 32]) -> (HybridKemSecret, HybridKemPublic) {
    HybridKemSecret::generate(&mut SeedRng::from_seed(kem_seed))
}

/// Publish this ingress member's KEM public for `epoch`, so the outgoing line can seal its reshare
/// sub-shares to this node. `false` if the store rejected the write.
pub async fn publish_ingress_key(
    client: &Client,
    coord: Triple,
    epoch: Epoch,
    public: &HybridKemPublic,
    credential: Option<&(Vec<u8>, VrfPublic, VrfProof)>,
) -> bool {
    let landed = client
        .put_ephemeral(ingress_key_slot(coord, epoch), ingress_key_record(public, credential), DIRECTORY_SLOT_EPOCHS)
        .await;
    crate::note_publish(client, crate::Directory::IngressKey, epoch, landed)
}

/// The bytes an ingress key is stored as: the bare encoded public, or that inside the coordinate-bound
/// [`Entitlement`] envelope when this deployment can prove coordinates (#262).
///
/// **Why this directory needed the envelope and could not lean on the store.** `put_ephemeral` hands the
/// store `storage_digest(&key)` — the store never sees the key, so it cannot check that the writer is the
/// node the slot names, and no store-side rule ever will: it is content-addressed by construction. Publisher
/// authenticity therefore lives in the payload or nowhere, which is the same conclusion `loaddir` reached in
/// #80 and `capdir` before it.
///
/// **What an unbound slot cost here specifically.** This is not a reporting directory. `resolve_ingress_line`
/// reads it inside the rotation and the emitter seals each new member's reshare sub-share to the key it
/// finds; a key nobody holds the secret for makes the rotated line one sub-share short of its threshold, and
/// the symptom is the one this module's own doc calls out — an ingress that looks provisioned and admits
/// nobody. One forged slot is enough, because the resolve is fail-closed on ALL members.
#[must_use]
fn ingress_key_record(
    public: &HybridKemPublic,
    credential: Option<&(Vec<u8>, VrfPublic, VrfProof)>,
) -> Vec<u8> {
    let payload = public.encode();
    match credential {
        Some((id, vrf_public, proof)) => Entitlement::encode(id, vrf_public, proof, &payload),
        None => payload,
    }
}

/// The inverse of [`ingress_key_record`]: the published KEM public, or `None` if malformed or — when
/// `beacon` is `Some` — not bound to `coord` for `epoch`.
#[must_use]
fn open_ingress_key_record<F: Field>(
    bytes: &[u8],
    coord: Triple,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<HybridKemPublic> {
    match beacon {
        Some(seed) => {
            let (_, payload) = Entitlement::open::<F>(bytes, coord, epoch, &seed)?;
            HybridKemPublic::decode(payload)
        }
        None => HybridKemPublic::decode(bytes),
    }
}

/// Resolve one incoming line member's ingress KEM public for `epoch`.
///
/// `beacon` is `Some` wherever the deployment proves coordinates, and then a record not bound to `coord` for
/// `epoch` is refused rather than returned — the same three-way shape `loaddir::resolve_load` uses, and for
/// the same reason: a reader that cannot check the binding must not pretend it did.
pub async fn resolve_ingress_key<F: Field>(
    client: &Client,
    coord: Triple,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<HybridKemPublic> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(ingress_key_slot(coord, epoch)))
        .await
        .ok()??;
    open_ingress_key_record::<F>(&bytes, coord, epoch, beacon)
}

/// Resolve **every** member of the incoming line, in roster order — what `emit_reshare` needs.
///
/// `None` if any member's key is missing, and that is fail-closed by design rather than best-effort: an
/// emission that skipped a member would seal that member no sub-share, so the new line would be one short of
/// the threshold and the rotation would silently produce a line that cannot serve. Better to emit nothing
/// this epoch — the old line keeps serving, and the next epoch tries again — than to hand the community an
/// ingress that looks provisioned and admits nobody.
pub async fn resolve_ingress_line<F: Field>(
    client: &Client,
    line: &[Triple],
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<Vec<HybridKemPublic>> {
    let mut keys = Vec::with_capacity(line.len());
    for &coord in line {
        keys.push(resolve_ingress_key::<F>(client, coord, epoch, beacon).await?);
    }
    Some(keys)
}

/// How many bytes of polynomial randomness one reshare needs.
///
/// Byte-wise Shamir over `GF(256)` consumes `(t − 1)` random bytes per secret byte, and the secret here is
/// an encoded [`IngressDescriptor`](crate::poros::IngressDescriptor) whose length depends on how many entry
/// peers a community published — which this driver does not know and must not need to. So the figure is a
/// **ceiling** rather than an exact size: a descriptor of `MAX_ENTRY_PEERS` peers at the largest threshold a
/// Fano-order line can carry, plus a margin. Oversupplying is free (`shard_service_key` reads a prefix);
/// undersupplying fails the sharing, which is why the bound errs high.
const RESHARE_RANDOMNESS_LEN: usize = 8192;

/// **The rotation driver** — the one task that closes the loop an ingress line could not close itself.
///
/// Each epoch it does three things, in an order that matters:
///
/// 1. **Publishes** this member's stable KEM public at the *next* epoch's slot, so the outgoing line can
///    resolve it. Ahead of the turn rather than at it, because the emission happens at the boundary and a
///    key published only then is a key nobody could have read.
/// 2. **Resolves** the incoming line's keys, if this node sits on the outgoing line.
/// 3. **Emits** the sealed reshare contributions, injected as raw sends — the engine produced the effects
///    and cannot perform I/O, so the driver carries them.
///
/// The receive half is not here: `IngressNode` arms it directly from the cell's own `BeaconReady`, because
/// both rosters are a pure function of `(community, epoch, beacon)` and need no lookup at all. This
/// asymmetry — receive is pure, emit is not — is the whole reason the rotation needed a driver rather than
/// living inside the engine.
///
/// **A failed epoch is not a failed line.** If any incoming member's key is unresolvable the emission is
/// skipped whole (see [`resolve_ingress_line`]): the outgoing line keeps serving its own epoch, and the next
/// advance tries again. A partial emission would leave the new line below threshold — provisioned-looking
/// and unable to admit anyone.
pub fn spawn_ingress_rotation<F: Field + 'static>(
    client: Client,
    community: Vec<u8>,
    kem_seed: [u8; 32],
    prover: Option<CoordinateProver>,
) -> tokio::task::JoinHandle<()> {
    // Supervised: this actor's death is a capability the node loses, and the counters that would
    // have shown it are written by the actor itself (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        let (_secret, public) = ingress_keypair(&kem_seed);
        let mut beacons = client.beacons();
        // Genesis first, so a line rotating out of epoch 0 can already resolve this member. Bound against
        // THIS NETWORK's epoch-0 seed, not the shared constant: a record bound against the wrong seed proves
        // a coordinate this node does not occupy, so no reader could verify it (`docs/design-genesis.md`).
        let genesis_credential = prover.as_ref().map(|prove| prove(Epoch::new(0), &client.genesis()));
        publish_ingress_key(&client, client.address(), Epoch::new(0), &public, genesis_credential.as_ref())
            .await;
        let mut current = Epoch::new(0);
        // Latest-state, not the lossy stream: a missed round is a rotation that never happens, and an ingress
        // line that stops rotating forfeits the moving-target property §6 rests on — its blocklist stops
        // going stale (#86).
        while let Some((epoch, beacon)) = crate::next_epoch(&mut beacons, current).await {
            let next = epoch.next();
            // Publish for the epoch AFTER this one: the rotation into it happens at that boundary,
            // and a key published at the boundary is a key the outgoing line could not have read.
            // Proven per write, never once at spawn: the credential names an epoch, so one captured at
            // startup would verify only in the epoch it was made — the same rule `loaddir` and `capdir`
            // follow. Bound to `next`, the epoch the record is FOR, because that is what a reader checks.
            let credential = prover.as_ref().map(|prove| prove(next, &beacon));
            publish_ingress_key(&client, client.address(), next, &public, credential.as_ref()).await;

            let old_line = crate::poros::ingress_line::<F>(&community, current, &beacon);
            let new_line = crate::poros::ingress_line::<F>(&community, epoch, &beacon);
            let old_members = fanos_rendezvous::line_member_coords::<F>(old_line.coords());
            let new_members = fanos_rendezvous::line_member_coords::<F>(new_line.coords());
            current = epoch;

            // Only an OUTGOING member emits. A node on neither line has nothing to do; a node on
            // only the incoming line was armed by `IngressNode` and waits for sub-shares.
            if !old_members.contains(&client.address()) {
                continue;
            }
            // The beacon this epoch's records are bound against — present exactly when this node can prove
            // coordinates, so the check is on wherever the binding is.
            let verify_against = prover.as_ref().map(|_| beacon);
            let Some(keys) = resolve_ingress_line::<F>(&client, &new_members, epoch, verify_against).await
            else {
                // Fail-closed and quiet on the wire, which is why it must not be quiet to an
                // operator: a line that stops rotating is a line whose blocklist stops going stale.
                tracing::warn!(
                    epoch = epoch.get(),
                    "ingress rotation skipped: an incoming line member published no key"
                );
                continue;
            };
            // Fresh entropy per rotation, drawn here because the engine must stay deterministic.
            // Two independent draws: the Shamir polynomial and the KEM seed must not share
            // material, or a sub-share's confidentiality would rest on the same bytes that
            // determine its value.
            let (mut key_rnd, mut kem_seed) = (vec![0u8; RESHARE_RANDOMNESS_LEN], [0u8; 32]);
            if getrandom::fill(&mut key_rnd).is_err() || getrandom::fill(&mut kem_seed).is_err() {
                tracing::warn!("ingress rotation skipped: OS entropy unavailable");
                continue;
            }
            let body = encode_rotation(epoch, &new_members, &keys, &key_rnd, &kem_seed);
            client.command(fanos_runtime::Command::Control {
                tag: CONTROL_INGRESS_ROTATION,
                body,
            });
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::IngressRotation, &supervised, task)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// **A published ingress key verifies only at a coordinate its publisher can prove** (#262).
    ///
    /// Driven through `ingress_key_record`/`open_ingress_key_record` — the functions the publisher and the
    /// resolver actually call — and not through `Entitlement` directly. #80 recorded why: its first version
    /// of this binding tested the envelope in isolation and stayed green when the envelope was deleted from
    /// `publish_load`, proving something the capability directory had already proven and nothing about this
    /// directory. A test that survives the removal of what it tests is not a test.
    #[test]
    fn an_ingress_key_verifies_only_where_its_publisher_can_prove_a_coordinate() {
        use fanos_field::F7;
        use fanos_geometry::{Plane, Point};
        use fanos_vrf::VrfSecret;

        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let sk = VrfSecret::from_seed([11u8; 32]);
        let id = b"ingress-member-11".to_vec();
        let (_, proof) = fanos_vrf::prove_coordinate::<F7>(&sk, &id, epoch, &beacon);
        let (_secret, public) = ingress_keypair(&[3u8; 32]);
        let record = ingress_key_record(&public, Some(&(id.clone(), sk.public(), proof)));
        let output = fanos_vrf::coordinate_output(&sk.public(), &id, epoch, &beacon, &proof)
            .expect("the publisher's own credential yields its walk");

        let mut refused = 0;
        for i in 0..Plane::<F7>::N as usize {
            let p = Point::<F7>::at(i);
            let got = open_ingress_key_record::<F7>(&record, p.coords(), epoch, Some(beacon));
            if fanos_vrf::probe_index_of::<F7>(&output, &p).is_some() {
                assert_eq!(
                    got.map(|k| k.encode()),
                    Some(public.encode()),
                    "a point on the publisher's own walk verifies"
                );
            } else {
                assert!(got.is_none(), "a coordinate the publisher cannot prove is refused");
                refused += 1;
            }
        }
        // Same arithmetic the load directory's binding test states: PG(2,7) holds 57 points, a line holds
        // q + 1 = 8, so 49 are unreachable for this publisher.
        assert_eq!(refused, 49, "the forgery is refused at 49 of the plane's 57 points");
    }

    /// The binding is **epoch-scoped**, so a key cannot be replayed into the next epoch to hold a retired
    /// member in the rotation after the line has moved on.
    #[test]
    fn an_ingress_key_does_not_verify_in_another_epoch() {
        use fanos_field::F7;
        use fanos_geometry::{Plane, Point};
        use fanos_vrf::VrfSecret;

        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let sk = VrfSecret::from_seed([12u8; 32]);
        let id = b"ingress-member-12".to_vec();
        let (_, proof) = fanos_vrf::prove_coordinate::<F7>(&sk, &id, epoch, &beacon);
        let (_secret, public) = ingress_keypair(&[4u8; 32]);
        let record = ingress_key_record(&public, Some(&(id.clone(), sk.public(), proof)));
        let output = fanos_vrf::coordinate_output(&sk.public(), &id, epoch, &beacon, &proof)
            .expect("the publisher's own credential yields its walk");
        let mine = (0..Plane::<F7>::N as usize)
            .map(Point::<F7>::at)
            .find(|p| fanos_vrf::probe_index_of::<F7>(&output, p).is_some())
            .expect("a walk reaches at least one point");

        assert!(
            open_ingress_key_record::<F7>(&record, mine.coords(), epoch, Some(beacon)).is_some(),
            "it verifies in the epoch it was made for"
        );
        assert!(
            open_ingress_key_record::<F7>(&record, mine.coords(), Epoch::new(4), Some(beacon)).is_none(),
            "and not in the next one — the credential names its epoch"
        );
    }

    /// A deployment that cannot prove coordinates still round-trips, and the reader says so by asking with
    /// `None`. Asserted because the alternative — a bound-only reader — would take every such deployment's
    /// ingress line offline rather than leave it as unprotected as it was.
    #[test]
    fn an_unbound_deployment_still_round_trips_its_ingress_key() {
        use fanos_field::F7;
        let (_secret, public) = ingress_keypair(&[5u8; 32]);
        let record = ingress_key_record(&public, None);
        assert_eq!(
            open_ingress_key_record::<F7>(&record, [1, 0, 1], Epoch::new(2), None).map(|k| k.encode()),
            Some(public.encode()),
            "no credential to check, so the bare public is the whole record"
        );
    }

    #[test]
    fn ingress_key_slots_are_deterministic_distinct_and_domain_separated() {
        let (a, b) = ([1u32, 0, 1], [2u32, 0, 1]);
        let (e0, e1) = (Epoch::new(0), Epoch::new(1));
        assert_eq!(ingress_key_slot(a, e0), ingress_key_slot(a, e0), "deterministic");
        assert_ne!(ingress_key_slot(a, e0), ingress_key_slot(b, e0), "distinct per member");
        assert_ne!(ingress_key_slot(a, e0), ingress_key_slot(a, e1), "and per epoch");
        assert!(
            ingress_key_slot(a, e0).starts_with(b"FANOS-v1/ingress-key/"),
            "domain-separated from every other use of the store — sharing an address with the mix key would \
             let a rotation seal to a ratcheting key its recipient can no longer open",
        );
    }

    #[test]
    fn an_ingress_keypair_is_stable_across_restarts() {
        // A rotation resolves a member's key and seals to it; if the member regenerated a different key on
        // restart, the sub-share would be undecryptable and the rotation would fail with no diagnosis.
        let seed = [0x4Du8; 32];
        let (_s1, p1) = ingress_keypair(&seed);
        let (_s2, p2) = ingress_keypair(&seed);
        assert_eq!(p1.encode(), p2.encode(), "the published public must not move across restarts");
        let (_s3, p3) = ingress_keypair(&[0x4Eu8; 32]);
        assert_ne!(p1.encode(), p3.encode(), "and a different member's seed yields a different key");
    }
}



