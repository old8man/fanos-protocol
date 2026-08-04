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
use fanos_quic::Client;
use fanos_rendezvous::Epoch;

use fanos_primitives::codec::{Reader, put_seq, put_var_bytes};

use crate::DIRECTORY_SLOT_EPOCHS;
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
) -> bool {
    client
        .put_ephemeral(ingress_key_slot(coord, epoch), public.encode(), DIRECTORY_SLOT_EPOCHS)
        .await
}

/// Resolve one incoming line member's ingress KEM public for `epoch`.
pub async fn resolve_ingress_key(
    client: &Client,
    coord: Triple,
    epoch: Epoch,
) -> Option<HybridKemPublic> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(ingress_key_slot(coord, epoch)))
        .await
        .ok()??;
    HybridKemPublic::decode(&bytes)
}

/// Resolve **every** member of the incoming line, in roster order — what `emit_reshare` needs.
///
/// `None` if any member's key is missing, and that is fail-closed by design rather than best-effort: an
/// emission that skipped a member would seal that member no sub-share, so the new line would be one short of
/// the threshold and the rotation would silently produce a line that cannot serve. Better to emit nothing
/// this epoch — the old line keeps serving, and the next epoch tries again — than to hand the community an
/// ingress that looks provisioned and admits nobody.
pub async fn resolve_ingress_line(
    client: &Client,
    line: &[Triple],
    epoch: Epoch,
) -> Option<Vec<HybridKemPublic>> {
    let mut keys = Vec::with_capacity(line.len());
    for &coord in line {
        keys.push(resolve_ingress_key(client, coord, epoch).await?);
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
pub fn spawn_ingress_rotation<F: fanos_field::Field + 'static>(
    client: Client,
    community: Vec<u8>,
    kem_seed: [u8; 32],
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (_secret, public) = ingress_keypair(&kem_seed);
        let mut beacons = client.beacons();
        // Genesis first, so a line rotating out of epoch 0 can already resolve this member.
        publish_ingress_key(&client, client.address(), Epoch::new(0), &public).await;
        let mut current = Epoch::new(0);
        // Latest-state, not the lossy stream: a missed round is a rotation that never happens, and an ingress
        // line that stops rotating forfeits the moving-target property §6 rests on — its blocklist stops
        // going stale (#86).
        while let Some((epoch, beacon)) = crate::next_epoch(&mut beacons, current).await {
            let next = epoch.next();
            // Publish for the epoch AFTER this one: the rotation into it happens at that boundary,
            // and a key published at the boundary is a key the outgoing line could not have read.
            publish_ingress_key(&client, client.address(), next, &public).await;

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
            let Some(keys) = resolve_ingress_line(&client, &new_members, epoch).await else {
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
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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



