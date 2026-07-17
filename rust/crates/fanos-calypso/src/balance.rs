//! CALYPSO-Balance — high-availability, load-balanced hidden services (spec §12.6).
//!
//! The problem OnionBalance solves — one hidden-service address served by a fleet of backends — but
//! designed around FANOS's structure to shed OnionBalance's drawbacks rather than inherit them:
//!
//! * **No intro-point cap.** OnionBalance packs backend intro points into one fixed-size descriptor
//!   (~10–30 max). A [`MasterDescriptor`] here is L4-store bytes, replicated across the responsible
//!   cell (LRC) — the fleet size is bounded by the store, not a protocol constant.
//! * **Offline root, bounded online key.** A single long-lived master key that must sign fresh
//!   descriptors is either an online target or goes stale. Instead an **offline root identity** (the
//!   one the `.fanos` address certifies) signs a short-lived [`SigningKeyCert`] authorizing an
//!   **epoch signing key**; that online key signs the per-epoch descriptor and the backend
//!   delegations. A compromised signing key is confined to its epoch window and revoked by simply
//!   not re-certifying it — the root never touches the serving path.
//! * **Consistent, capacity-aware load balancing.** OnionBalance clients pick a random intro point
//!   (hotspots), and a naive modulo assignment reshuffles *every* client when the fleet changes.
//!   [`select_instance`](MasterDescriptor::select_instance) uses **weighted rendezvous hashing
//!   (HRW)**: each request deterministically maps to the highest-scoring backend, load spreads in
//!   proportion to per-backend `weight`, and adding or removing a backend remaps only that backend's
//!   ~1/N share of requests. Failover walks down the HRW ranking, so a down backend costs one step.
//! * **Time-bounded delegations.** Every delegation binds the epoch, so authority expires and a
//!   backend cannot be replayed into a later epoch.
//!
//! End to end it is **self-certifying**: the `.fanos` address certifies the root, the root certifies
//! the signing key, the signing key certifies each backend — no directory, and nothing is forgeable
//! without the offline root secret. The module is signature-scheme-agnostic (it defines the
//! canonical to-be-signed bytes and the trust logic, verifying through a caller-supplied predicate),
//! so the `no_std` core stays primitive-free while production wires in the hybrid post-quantum
//! signature (Ed25519 ‖ ML-DSA-65), exactly as the node identity does.

use alloc::vec::Vec;

use fanos_crypto::hash_labeled;
use fanos_geometry::Triple;

use crate::ServiceAddress;

/// Domain tag for the root→signing-key certificate.
const SIGNING_CERT_LABEL: &str = "FANOS-v1/calypso-balance-signing-cert";
/// Domain tag for the per-instance delegation signature (signing key authorizes a backend).
const DELEGATION_LABEL: &str = "FANOS-v1/calypso-balance-delegation";
/// Domain tag for the whole-descriptor signature (signing key authorizes the instance list).
const DESCRIPTOR_LABEL: &str = "FANOS-v1/calypso-balance-descriptor";
/// Domain tag for the rendezvous-hashing instance score.
const HRW_LABEL: &str = "FANOS-v1/calypso-balance-hrw";

/// A root-signed certificate authorizing an **epoch signing key** for a validity window. The root
/// identity (which the `.fanos` address certifies) can stay offline: it issues this once, and the
/// online signing key does the per-epoch work. Outside `[valid_from, valid_until]` the key is not
/// trusted, so a compromise is bounded and revocation is "don't re-issue".
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningKeyCert {
    /// The epoch signing key's public key.
    pub signing_pubkey: Vec<u8>,
    /// First epoch the signing key is valid for (inclusive).
    pub valid_from: u32,
    /// Last epoch the signing key is valid for (inclusive).
    pub valid_until: u32,
    /// The root's signature over [`SigningKeyCert::signing_message`].
    pub root_sig: Vec<u8>,
}

impl SigningKeyCert {
    /// The canonical bytes the root signs to authorize this signing key (domain-separated).
    #[must_use]
    pub fn signing_message(
        root_pubkey: &[u8],
        signing_pubkey: &[u8],
        from: u32,
        until: u32,
    ) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(SIGNING_CERT_LABEL.as_bytes());
        put_bytes(&mut m, root_pubkey);
        put_bytes(&mut m, signing_pubkey);
        m.extend_from_slice(&from.to_be_bytes());
        m.extend_from_slice(&until.to_be_bytes());
        m
    }

    /// Whether the signing key is authorized for `epoch` and the root signature checks out.
    fn is_valid<V: Fn(&[u8], &[u8], &[u8]) -> bool>(
        &self,
        root_pubkey: &[u8],
        epoch: u32,
        verify: &V,
    ) -> bool {
        (self.valid_from..=self.valid_until).contains(&epoch)
            && verify(
                root_pubkey,
                &Self::signing_message(
                    root_pubkey,
                    &self.signing_pubkey,
                    self.valid_from,
                    self.valid_until,
                ),
                &self.root_sig,
            )
    }
}

/// A backend instance within a master descriptor: its public key, its overlay coordinate (where a
/// client meets it), a relative load `weight`, and the signing key's delegation signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InstanceRef {
    /// The backend's own public key (distinct from the root and signing keys).
    pub instance_pubkey: Vec<u8>,
    /// The backend's overlay coordinate — the point a client routes to.
    pub coordinate: Triple,
    /// Relative capacity weight for load balancing (`0` drains the backend; default `1`).
    pub weight: u16,
    /// The signing key's signature over this instance's [`delegation_message`].
    pub delegation_sig: Vec<u8>,
}

/// The canonical bytes the **signing key** signs to delegate authority to one backend for a given
/// `(root, epoch)`. Domain-separated and epoch-bound, so a delegation cannot be confused with any
/// other signature nor replayed into a different epoch.
#[must_use]
pub fn delegation_message(
    root_pubkey: &[u8],
    epoch: u32,
    instance_pubkey: &[u8],
    coordinate: Triple,
    weight: u16,
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DELEGATION_LABEL.as_bytes());
    put_bytes(&mut m, root_pubkey);
    m.extend_from_slice(&epoch.to_be_bytes());
    put_bytes(&mut m, instance_pubkey);
    for w in coordinate {
        m.extend_from_slice(&w.to_be_bytes());
    }
    m.extend_from_slice(&weight.to_be_bytes());
    m
}

/// The master's signed, load-balanced descriptor for an epoch — the published bulletin that maps a
/// master `.fanos` address to its backend fleet, under the offline-root / epoch-signing-key hierarchy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MasterDescriptor {
    /// The root identity's public key (the `.fanos` address certifies this).
    pub root_pubkey: Vec<u8>,
    /// The root-signed certificate authorizing the epoch signing key.
    pub signing_cert: SigningKeyCert,
    /// The epoch this descriptor is valid for.
    pub epoch: u32,
    /// The backend instances, each with its delegation signature by the signing key.
    pub instances: Vec<InstanceRef>,
    /// The **signing key's** signature over [`MasterDescriptor::signing_bytes`] — binds the whole
    /// instance list so a backend cannot add, drop, or reorder instances.
    pub descriptor_sig: Vec<u8>,
}

impl MasterDescriptor {
    /// The parseable descriptor *body* (everything signed, minus the domain label): root key,
    /// signing cert, epoch, and every instance's identity, coordinate, weight, and delegation.
    fn body_bytes(&self) -> Vec<u8> {
        let mut m = Vec::new();
        put_bytes(&mut m, &self.root_pubkey);
        put_bytes(&mut m, &self.signing_cert.signing_pubkey);
        m.extend_from_slice(&self.signing_cert.valid_from.to_be_bytes());
        m.extend_from_slice(&self.signing_cert.valid_until.to_be_bytes());
        put_bytes(&mut m, &self.signing_cert.root_sig);
        m.extend_from_slice(&self.epoch.to_be_bytes());
        m.extend_from_slice(&(self.instances.len() as u32).to_be_bytes());
        for inst in &self.instances {
            put_bytes(&mut m, &inst.instance_pubkey);
            for w in inst.coordinate {
                m.extend_from_slice(&w.to_be_bytes());
            }
            m.extend_from_slice(&inst.weight.to_be_bytes());
            put_bytes(&mut m, &inst.delegation_sig);
        }
        m
    }

    /// The canonical bytes the signing key signs over the whole descriptor (domain-separated).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(DESCRIPTOR_LABEL.len() + 64);
        m.extend_from_slice(DESCRIPTOR_LABEL.as_bytes());
        m.extend_from_slice(&self.body_bytes());
        m
    }

    /// Canonically serialize the descriptor for publication at the master's `descriptor_key`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body_bytes();
        put_bytes(&mut out, &self.descriptor_sig);
        out
    }

    /// Decode a descriptor from its canonical bytes, or `None` if malformed.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(bytes);
        let root_pubkey = c.take_bytes()?.to_vec();
        let signing_pubkey = c.take_bytes()?.to_vec();
        let valid_from = u32::from_be_bytes(c.take_array()?);
        let valid_until = u32::from_be_bytes(c.take_array()?);
        let root_sig = c.take_bytes()?.to_vec();
        let epoch = u32::from_be_bytes(c.take_array()?);
        let count = u32::from_be_bytes(c.take_array()?) as usize;
        let mut instances = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let instance_pubkey = c.take_bytes()?.to_vec();
            let coordinate = [
                u32::from_be_bytes(c.take_array()?),
                u32::from_be_bytes(c.take_array()?),
                u32::from_be_bytes(c.take_array()?),
            ];
            let weight = u16::from_be_bytes(c.take_array()?);
            let delegation_sig = c.take_bytes()?.to_vec();
            instances.push(InstanceRef {
                instance_pubkey,
                coordinate,
                weight,
                delegation_sig,
            });
        }
        let descriptor_sig = c.take_bytes()?.to_vec();
        Some(Self {
            root_pubkey,
            signing_cert: SigningKeyCert {
                signing_pubkey,
                valid_from,
                valid_until,
                root_sig,
            },
            epoch,
            instances,
            descriptor_sig,
        })
    }

    /// Fully verify the descriptor against the master's `address` using the signature predicate
    /// `verify(public_key, message, signature) -> bool`. All of the following must hold:
    ///
    /// 1. the address self-certifies `root_pubkey`;
    /// 2. the root's [`SigningKeyCert`] authorizes the signing key for this `epoch`;
    /// 3. the signing key's `descriptor_sig` is valid over [`signing_bytes`](Self::signing_bytes);
    /// 4. **every** instance's `delegation_sig` is valid under the *signing* key over its
    ///    [`delegation_message`].
    ///
    /// So a client never routes to an undelegated backend, a tampered instance list is rejected
    /// wholesale, and a signing key is trusted only inside its certified epoch window.
    #[must_use]
    pub fn verify<V>(&self, address: &ServiceAddress, verify: V) -> bool
    where
        V: Fn(&[u8], &[u8], &[u8]) -> bool,
    {
        if !address.certifies(&self.root_pubkey) {
            return false;
        }
        if !self
            .signing_cert
            .is_valid(&self.root_pubkey, self.epoch, &verify)
        {
            return false;
        }
        let signing_pk = &self.signing_cert.signing_pubkey;
        if !verify(signing_pk, &self.signing_bytes(), &self.descriptor_sig) {
            return false;
        }
        self.instances.iter().all(|inst| {
            let msg = delegation_message(
                &self.root_pubkey,
                self.epoch,
                &inst.instance_pubkey,
                inst.coordinate,
                inst.weight,
            );
            verify(signing_pk, &msg, &inst.delegation_sig)
        })
    }

    /// Select a backend for a client request by **weighted rendezvous hashing (HRW)**. Each live
    /// instance scores `weight · H(selector ‖ instance_pubkey)`; the request maps to the highest
    /// score, so load spreads in proportion to weight and adding/removing a backend remaps only its
    /// own share. `attempt` walks down the ranking for failover (0 = primary, 1 = next, …); a
    /// zero-weight backend is skipped (drained). Returns `None` if no positive-weight instance ranks
    /// at `attempt`.
    #[must_use]
    pub fn select_instance(&self, selector: &[u8], attempt: usize) -> Option<&InstanceRef> {
        let mut ranked: Vec<(u128, usize)> = self
            .instances
            .iter()
            .enumerate()
            .filter(|(_, inst)| inst.weight > 0)
            .map(|(i, inst)| (hrw_score(selector, inst), i))
            .collect();
        // Highest score first; the instance index breaks ties deterministically.
        ranked.sort_unstable_by(|a, b| b.cmp(a));
        ranked
            .get(attempt)
            .and_then(|(_, i)| self.instances.get(*i))
    }
}

/// The L4 storage key under which a master publishes its balanced descriptor for `epoch` — the same
/// per-epoch rendezvous key a single service uses, so a client with only the root key and address
/// finds it with no directory. (Alias of [`crate::descriptor_key`] over the root key.)
#[must_use]
pub fn master_descriptor_key(root_pubkey: &[u8], epoch: u32) -> Vec<u8> {
    crate::descriptor_key(root_pubkey, epoch)
}

/// The weighted rendezvous score of one instance for a selector: `weight · uniform_hash`.
fn hrw_score(selector: &[u8], inst: &InstanceRef) -> u128 {
    let mut input = Vec::with_capacity(selector.len() + inst.instance_pubkey.len());
    input.extend_from_slice(selector);
    input.extend_from_slice(&inst.instance_pubkey);
    let digest = hash_labeled(HRW_LABEL, &input);
    let h = u64::from_be_bytes(
        digest
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0; 8]),
    );
    u128::from(h) * u128::from(inst.weight)
}

// --- canonical length-prefixed encoding (u32 big-endian length ‖ bytes) ---

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let slice = self.buf.get(self.pos..self.pos.checked_add(N)?)?;
        self.pos += N;
        slice.try_into().ok()
    }

    fn take_bytes(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.take_array()?) as usize;
        let slice = self.buf.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos += len;
        Some(slice)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A key registry mapping toy public keys back to their secrets, for the toy verifier.
    type Registry = Vec<(Vec<u8>, Vec<u8>)>;

    fn toy_pub(secret: &[u8]) -> Vec<u8> {
        hash_labeled("toy-pk", secret).to_vec()
    }
    fn toy_sign(secret: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut input = secret.to_vec();
        input.extend_from_slice(msg);
        hash_labeled("toy-sig", &input).to_vec()
    }
    fn toy_verify(registry: &Registry) -> impl Fn(&[u8], &[u8], &[u8]) -> bool + '_ {
        move |pubkey: &[u8], msg: &[u8], sig: &[u8]| {
            registry
                .iter()
                .find(|(pk, _)| pk == pubkey)
                .is_some_and(|(_, sk)| toy_sign(sk, msg) == sig)
        }
    }

    struct Setup {
        address: ServiceAddress,
        desc: MasterDescriptor,
        registry: Registry,
        root_sk: Vec<u8>,
        signing_sk: Vec<u8>,
    }

    fn setup(epoch: u32, weights: &[u16]) -> Setup {
        let root_sk = b"root-offline-secret".to_vec();
        let root_pk = toy_pub(&root_sk);
        let address = ServiceAddress::from_pubkey(&root_pk);
        let signing_sk = b"epoch-signing-secret".to_vec();
        let signing_pk = toy_pub(&signing_sk);

        let mut registry = alloc::vec![
            (root_pk.clone(), root_sk.clone()),
            (signing_pk.clone(), signing_sk.clone())
        ];
        let (valid_from, valid_until) = (epoch.saturating_sub(1), epoch + 2);
        let root_sig = toy_sign(
            &root_sk,
            &SigningKeyCert::signing_message(&root_pk, &signing_pk, valid_from, valid_until),
        );
        let signing_cert = SigningKeyCert {
            signing_pubkey: signing_pk.clone(),
            valid_from,
            valid_until,
            root_sig,
        };

        let instances = weights
            .iter()
            .enumerate()
            .map(|(i, &weight)| {
                let sk = alloc::vec![0xB0, i as u8];
                let pk = toy_pub(&sk);
                registry.push((pk.clone(), sk));
                let coordinate = [1, i as u32, 2];
                let sig = toy_sign(
                    &signing_sk,
                    &delegation_message(&root_pk, epoch, &pk, coordinate, weight),
                );
                InstanceRef {
                    instance_pubkey: pk,
                    coordinate,
                    weight,
                    delegation_sig: sig,
                }
            })
            .collect();

        let mut desc = MasterDescriptor {
            root_pubkey: root_pk,
            signing_cert,
            epoch,
            instances,
            descriptor_sig: Vec::new(),
        };
        desc.descriptor_sig = toy_sign(&signing_sk, &desc.signing_bytes());
        Setup {
            address,
            desc,
            registry,
            root_sk,
            signing_sk,
        }
    }

    #[test]
    fn a_valid_descriptor_verifies_through_the_root_signing_key_hierarchy() {
        let s = setup(9, &[1, 1, 1]);
        assert!(s.desc.verify(&s.address, toy_verify(&s.registry)));
    }

    #[test]
    fn a_descriptor_round_trips_through_its_wire_encoding() {
        let s = setup(9, &[1, 2, 3]);
        let decoded = MasterDescriptor::decode(&s.desc.encode()).unwrap();
        assert_eq!(decoded, s.desc);
        assert!(decoded.verify(&s.address, toy_verify(&s.registry)));
    }

    #[test]
    fn a_signing_key_outside_its_epoch_window_is_rejected() {
        // The cert authorizes [epoch-1, epoch+2]; a descriptor claiming a far epoch fails.
        let mut s = setup(9, &[1, 1]);
        s.desc.epoch = 100;
        // Re-sign the delegations + descriptor for the new epoch so only the *cert window* is wrong.
        for inst in &mut s.desc.instances {
            inst.delegation_sig = toy_sign(
                &s.signing_sk,
                &delegation_message(
                    &s.desc.root_pubkey,
                    100,
                    &inst.instance_pubkey,
                    inst.coordinate,
                    inst.weight,
                ),
            );
        }
        s.desc.descriptor_sig = toy_sign(&s.signing_sk, &s.desc.signing_bytes());
        assert!(
            !s.desc.verify(&s.address, toy_verify(&s.registry)),
            "a signing key used outside its certified window must be rejected"
        );
    }

    #[test]
    fn an_undelegated_or_tampered_backend_is_rejected() {
        let s = setup(9, &[1, 1, 1]);
        // Undelegated injected backend.
        let mut d1 = s.desc.clone();
        d1.instances.push(InstanceRef {
            instance_pubkey: toy_pub(b"attacker"),
            coordinate: [1, 9, 9],
            weight: 1,
            delegation_sig: alloc::vec![0u8; 32],
        });
        assert!(!d1.verify(&s.address, toy_verify(&s.registry)));

        // Tampered coordinate without re-signing → descriptor signature breaks.
        let mut d2 = s.desc.clone();
        d2.instances[0].coordinate = [1, 42, 2];
        assert!(!d2.verify(&s.address, toy_verify(&s.registry)));
    }

    #[test]
    fn a_forged_signing_cert_from_a_non_root_key_is_rejected() {
        // The signing cert must be signed by the ROOT; a cert signed by anyone else fails even if
        // that key then signs everything else consistently.
        let mut s = setup(9, &[1, 1]);
        let evil_sk = b"not-the-root".to_vec();
        s.desc.signing_cert.root_sig = toy_sign(
            &evil_sk,
            &SigningKeyCert::signing_message(
                &s.desc.root_pubkey,
                &s.desc.signing_cert.signing_pubkey,
                s.desc.signing_cert.valid_from,
                s.desc.signing_cert.valid_until,
            ),
        );
        assert!(!s.desc.verify(&s.address, toy_verify(&s.registry)));
        let _ = &s.root_sk;
    }

    #[test]
    fn weighted_hrw_is_consistent_and_capacity_aware() {
        let s = setup(9, &[1, 1, 1]);
        // Deterministic per selector; failover walks the ranking.
        let a = s.desc.select_instance(b"req", 0).unwrap().coordinate;
        assert_eq!(a, s.desc.select_instance(b"req", 0).unwrap().coordinate);
        let b = s.desc.select_instance(b"req", 1).unwrap().coordinate;
        assert_ne!(a, b, "failover picks the next-ranked backend");

        // Consistency: removing a non-selected backend does not change this request's primary.
        let removed_idx = s
            .desc
            .instances
            .iter()
            .position(|i| i.coordinate != a)
            .unwrap();
        let mut fewer = s.desc.clone();
        fewer.instances.remove(removed_idx);
        assert_eq!(
            fewer.select_instance(b"req", 0).unwrap().coordinate,
            a,
            "removing a different backend leaves this request's mapping intact (HRW consistency)"
        );

        // Capacity: a heavily-weighted backend wins a large majority of requests.
        let heavy = setup(9, &[1, 1, 50]);
        let heavy_coord = heavy.desc.instances[2].coordinate;
        let hits = (0..300u32)
            .filter(|i| {
                heavy
                    .desc
                    .select_instance(&i.to_be_bytes(), 0)
                    .unwrap()
                    .coordinate
                    == heavy_coord
            })
            .count();
        assert!(
            hits > 200,
            "weight-50 backend takes the lion's share: {hits}/300"
        );

        // A zero-weight backend is drained (never selected).
        let drained = setup(9, &[0, 1]);
        for i in 0..50u32 {
            assert_ne!(
                drained
                    .desc
                    .select_instance(&i.to_be_bytes(), 0)
                    .unwrap()
                    .coordinate,
                drained.desc.instances[0].coordinate,
                "a zero-weight backend is never selected"
            );
        }
    }
}
