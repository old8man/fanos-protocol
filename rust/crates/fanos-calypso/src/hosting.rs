//! Threshold-hosted services — no single host to raid (spec §12.3).
//!
//! A classic hidden service runs on one host; seize it and the service dies. A CALYPSO service is
//! hosted **across the `q+1` members of a service-line**: fewer than `t` seized/colluding members
//! learn **nothing** (0-knowledge — the same threshold guarantee as NYX §5.2). The service *is the
//! line*, not a machine — there is nothing to raid, and a corrupt host is caught by DIAKRISIS and
//! repaired. Two complementary mechanisms realize this:
//!
//! 1. **Identity custody** ([`deal_service_key`] / [`open_service_share`] / [`recover_service_key`]).
//!    The service's persistent identity secret (e.g. the offline root behind its signing key, spec
//!    §12.6) is Shamir-shared at bootstrap ([`shard_service_key`]) and each raw share
//!    [`SealedShare`]-wrapped to its member — **dealt-and-sealed**, so a single seized host can
//!    neither impersonate the service nor recover the identity secret.
//! 2. **Intro confidentiality** ([`SealedIntro`]). Each client `RDV_INTRO` is sealed to the *line*
//!    (not any one member): `t` members each reveal only their own share (a "PartialDec", spec
//!    §5.2), and a combiner Lagrange-combines them — mirroring the KEM-sealed-share construction
//!    `fanos_aphantos::threshold` already uses for NYX hop-peeling, so no single member ever reads
//!    an intro alone.
//!
//! ## Why dealt-and-sealed, not a DKG
//! A DKG (e.g. the GJKR round `fanos_vrf::dkg` runs for the beacon committee) exists to guarantee
//! that *no party — including the dealer — ever learns the joint secret*, which matters when the
//! `q+1` parties are mutually distrusting. That is not this threat model: a CALYPSO service's
//! identity secret is generated **by its own operator, for their own service**, before any sharing
//! happens — the operator legitimately holds the whole secret at `t = 0` regardless of how it is
//! later shared, so a DKG buys nothing against the threat this module actually defends against (a
//! *later* seizure of `< t` hosts). What matters is that after dealing, the secret exists **only**
//! as `t`-of-`(q+1)` KEM-sealed shares — the operator should then erase its own copy of
//! `service_secret` — which dealt-and-sealed delivers exactly, and is the same trust model
//! `fanos_aphantos::threshold::ThresholdSealed` already uses for every NYX onion layer in this
//! codebase (a single sender/circuit-builder deals each layer's shares; nothing here is weaker than
//! the already-accepted NYX construction). A DKG would only earn its extra complexity if the dealer
//! itself might be adversarial *at deal time* — a real concern for the beacon committee's mutually
//! distrusting members, not for an operator bootstrapping its own service.
//!
//! ## Live wiring (integration point)
//! TODO(#99 follow-up): wire this into `fanos_rendezvous::RendezvousService`
//! (`crates/fanos-rendezvous/src/transport.rs:125`), which today holds one opaque `secret` used only
//! to seed its reply-onion RNG (`:136`, `RendezvousService::new`) and decodes each delivered
//! `Request` directly (`:149`, `ingest`) — i.e. whichever single host runs it reads every intro
//! alone, and alone holds whatever identity secret it was booted with. Lifting it to a genuinely
//! threshold-hosted service means: (a) replace that one `secret` with `Vec<SealedShare>` — one per
//! service-line member — opened via [`open_service_share`] and combined via [`recover_service_key`]
//! whenever the service needs its identity (e.g. re-signing an epoch cert, spec §12.6); and (b)
//! replace the direct `ingest` with a per-member `Engine` that seals/collects
//! [`SealedIntro::member_partial`]s over the overlay before calling [`SealedIntro::open`] —
//! `crates/fanos-sim/tests/threshold_calypso.rs` runs exactly this combiner protocol end to end
//! (`ServiceMember`) as the template to lift into a real engine.

use alloc::vec::Vec;

use fanos_geometry::Triple;
use fanos_pqcrypto::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_primitives::aead;
use fanos_primitives::hash_labeled;
use fanos_primitives::shamir::{self, ShamirError};

pub use fanos_primitives::shamir::Share;

/// Shard a service secret across the `line_size` members of a service-line, so any `threshold`
/// of them can reconstruct it (spec §12.3). `randomness` supplies the sharing polynomial.
pub fn shard_service_key(
    service_secret: &[u8],
    threshold: u8,
    line_size: u8,
    randomness: &[u8],
) -> Result<Vec<Share>, ShamirError> {
    shamir::split(service_secret, threshold, line_size, randomness)
}

/// **Proactively reshare** a hosted secret to a *new* line without reconstructing it — for a rotating
/// threshold committee (CHURP-style). Each old member's contribution is [`shard_service_key`] of its OWN
/// share value over the new line's positions; a new member then combines the contributions it received (one
/// per old member in a threshold subset at `old_xs`) with this call, obtaining its share of the SAME secret
/// under the new line. The secret is never materialized, and the new shares lie on a fresh polynomial, so
/// stale old shares cannot be mixed with new ones. See [`shamir::combine_contributions`].
pub fn combine_reshares(new_x: u8, contributions: &[Share], old_xs: &[u8]) -> Result<Share, ShamirError> {
    shamir::combine_contributions(new_x, contributions, old_xs)
}

/// Recover the service secret from `threshold` (or more) member shares.
pub fn recover_service_key(host_shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    shamir::reconstruct(host_shares)
}

/// An error dealing, sealing, or opening threshold-hosted service material.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostingError {
    /// Bytes were malformed (bad length, or a reconstructed key of the wrong width).
    Malformed,
    /// AEAD authentication failed — wrong key (below-threshold reconstruction), or a tamper.
    Aead,
    /// The Shamir sharing/reconstruction parameters or shares were invalid.
    Sharing,
}

impl core::fmt::Display for HostingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed bytes or reconstructed key",
            Self::Aead => "AEAD authentication failed (wrong key, below-threshold, or tamper)",
            Self::Sharing => "invalid secret-sharing parameters or shares",
        })
    }
}

impl core::error::Error for HostingError {}

/// A Shamir share wrapped so that only its intended line member can read it — the "each member
/// holds one share, KEM-sealed to that member" leg of §12.3: even a passive read of every
/// `SealedShare` a dealer produces (a compromised store, a wiretapped distribution channel)
/// discloses nothing, because each slot opens under a *different* member's [`HybridKemSecret`]
/// alone, and each carries its own AEAD nonce (self-describing — opening needs nothing out of
/// band beyond the member's secret). Used both for a dealt **identity**-secret share
/// ([`deal_service_key`]) and a per-**intro** message-key share ([`SealedIntro`]) — structurally
/// identical; the domain label passed to the private sealing helper keeps the two apart.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct SealedShare {
    /// The hybrid-KEM ciphertext this share is encapsulated under ([`HybridCiphertext::to_bytes`]).
    pub kem_ct: Vec<u8>,
    /// The AEAD nonce for `ciphertext`.
    pub nonce: [u8; aead::NONCE_LEN],
    /// `AEAD(H(label ‖ session), nonce, x(1B) ‖ y)` — the wrapped Shamir share.
    pub ciphertext: Vec<u8>,
}

/// Domain label for a dealt **identity**-secret share (bootstrap custody, [`deal_service_key`]).
const IDENTITY_SHARE_LABEL: &str = "FANOS-v1/calypso-hosting-identity-share";
/// Domain label for a per-**intro** Shamir share (message confidentiality, [`SealedIntro`]).
const INTRO_SHARE_LABEL: &str = "FANOS-v1/calypso-hosting-intro-share";

/// Serialize a Shamir share as `x(1B) ‖ y` — self-delimiting because it is always the *entire* AEAD
/// plaintext of its [`SealedShare`] slot (the ciphertext length already bounds `y`).
fn encode_share(share: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + share.y().len());
    out.push(share.x());
    out.extend_from_slice(share.y());
    out
}

/// Parse a share from [`encode_share`] bytes; `None` only on an empty slice (never produced by
/// [`encode_share`], but AEAD-opened bytes are adversarial in general).
fn decode_share(bytes: &[u8]) -> Option<Share> {
    let (&x, y) = bytes.split_first()?;
    Some(Share::new(x, y.to_vec()))
}

/// A domain-separated nonce derived from `seed` — used where a fixed, non-secret nonce is safe
/// because the AEAD *key* it pairs with is always fresh (a per-member KEM session, or a per-seal
/// derivation), so there is no key/nonce pair ever reused.
fn derive_nonce(label: &str, seed: &[u8]) -> [u8; aead::NONCE_LEN] {
    let digest = hash_labeled(label, seed);
    let mut n = [0u8; aead::NONCE_LEN];
    if let Some(prefix) = digest.get(..aead::NONCE_LEN) {
        n.copy_from_slice(prefix);
    }
    n
}

/// KEM-seal `share` to `member_public`: a fresh hybrid encapsulation under `member_seed`, then
/// `AEAD(H(label ‖ session), H(label ‖ member_seed), encode_share(share))`. `label` domain-separates
/// the two callers ([`deal_service_key`] vs [`SealedIntro::seal`]) so their derived keys/nonces never
/// collide even if a `member_seed` were ever reused across the two.
fn seal_share_to_member(
    label: &str,
    share: &Share,
    member_public: &HybridKemPublic,
    member_seed: &[u8],
) -> Result<SealedShare, HostingError> {
    let mut rng = SeedRng::from_seed(member_seed);
    // `None` only for a degenerate (low-order-point) member key — malformed, not this dealer's fault.
    let (kem_ct, session) = member_public
        .encapsulate(&mut rng)
        .ok_or(HostingError::Malformed)?;
    let nonce = derive_nonce(label, member_seed);
    let ciphertext = aead::seal(&hash_labeled(label, &session), &nonce, &encode_share(share))
        .ok_or(HostingError::Aead)?;
    Ok(SealedShare {
        kem_ct: kem_ct.to_bytes(),
        nonce,
        ciphertext,
    })
}

/// The member-side inverse of [`seal_share_to_member`]: decapsulate `sealed.kem_ct` under
/// `member_secret` and open the AEAD slot. `None` if `sealed` is not addressed to this member's
/// secret (wrong key) or was tampered.
fn open_sealed_share(label: &str, sealed: &SealedShare, member_secret: &HybridKemSecret) -> Option<Share> {
    let kem_ct = HybridCiphertext::from_bytes(&sealed.kem_ct)?;
    let session = member_secret.decapsulate(&kem_ct)?;
    let bytes = aead::open(&hash_labeled(label, &session), &sealed.nonce, &sealed.ciphertext)?;
    decode_share(&bytes)
}

/// Deal `service_secret` to a service-line: Shamir-share it at `threshold` across
/// `member_keys.len()` members ([`shard_service_key`]) and KEM-seal each raw share to its member —
/// **dealt-and-sealed** bootstrap custody (spec §12.3; see the module docs for why dealt-and-sealed,
/// not a DKG, is the right choice for *this* threat model). `key_randomness` is the
/// sharing-polynomial randomness ([`shard_service_key`]); `kem_seed` derives each member's per-share
/// KEM encapsulation randomness (a real CSPRNG draw in production, a fixed seed under the
/// deterministic simulator). The dealer should then **erase its own copy of `service_secret`**,
/// after which it exists only as these `t`-of-`n` sealed shares.
///
/// # Errors
/// [`HostingError::Sharing`] if `member_keys` is empty, exceeds 255, or `threshold` is invalid;
/// [`HostingError::Aead`] on the (practically unreachable) sealing failure.
pub fn deal_service_key(
    service_secret: &[u8],
    threshold: u8,
    member_keys: &[&HybridKemPublic],
    key_randomness: &[u8],
    kem_seed: &[u8],
) -> Result<Vec<SealedShare>, HostingError> {
    let line_size = u8::try_from(member_keys.len()).map_err(|_| HostingError::Sharing)?;
    let shares = shard_service_key(service_secret, threshold, line_size, key_randomness)
        .map_err(|_| HostingError::Sharing)?;
    member_keys
        .iter()
        .zip(&shares)
        .enumerate()
        .map(|(i, (public, share))| {
            let mut seed = kem_seed.to_vec();
            seed.extend_from_slice(&(i as u32).to_be_bytes());
            seal_share_to_member(IDENTITY_SHARE_LABEL, share, public, &seed)
        })
        .collect()
}

/// A member's side of [`deal_service_key`]: open its own sealed identity share. `None` if `sealed`
/// was not addressed to `member_secret` (not this member's slot) or was tampered. `threshold` (or
/// more) members' opened shares [`recover_service_key`] the identity secret; fewer reconstruct
/// nothing (Shamir's information-theoretic guarantee).
#[must_use]
pub fn open_service_share(sealed: &SealedShare, member_secret: &HybridKemSecret) -> Option<Share> {
    open_sealed_share(IDENTITY_SHARE_LABEL, sealed, member_secret)
}

/// `(threshold − 1) · 32` bytes of deterministic sharing randomness from a seed (the intro key is
/// always 32 bytes, so this is fixed-width unlike [`shard_service_key`]'s caller-supplied
/// randomness for an arbitrary-length identity secret).
fn sharing_randomness(seed: &[u8], threshold: u8) -> Vec<u8> {
    let n = usize::from(threshold.saturating_sub(1)) * 32;
    let mut out = alloc::vec![0u8; n];
    fanos_primitives::hash::hash_xof("FANOS-v1/calypso-intro-sharing", seed, &mut out);
    out
}

/// A client's `RDV_INTRO`, threshold-sealed to a service-line: AEAD-encrypted under a fresh
/// per-intro key `K`, with `K` itself Shamir-shared at `threshold` and each share
/// [`SealedShare`]-wrapped to a line member (spec §12.3–§12.4). Mirrors
/// `fanos_aphantos::threshold::ThresholdSealed` (the same construction already proven for NYX
/// hop-peeling) rather than depending on it, so `fanos-calypso` stays self-contained — see the
/// module docs.
///
/// **No single line member ever holds `K`.** Each member decapsulates only *its own* slot — a
/// [`member_partial`](Self::member_partial), the "PartialDec" of spec §5.2/§12.3 — and a combiner
/// [`Lagrange`-combines them](Self::open). Below `threshold`, `K` is information-theoretically
/// unrecoverable (Shamir), and every individual share is additionally gated by its member's private
/// [`HybridKemSecret`] (so even a store of every `SealedShare`, absent member secrets, discloses
/// nothing): the same two-layer 0-knowledge-below-`t` guarantee NYX §5.2 gives onion hops, applied
/// here to intro confidentiality.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct SealedIntro {
    nonce: [u8; aead::NONCE_LEN],
    ciphertext: Vec<u8>,
    sealed_shares: Vec<SealedShare>,
}

impl SealedIntro {
    /// The number of line members this intro is sealed to (`q + 1`).
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.sealed_shares.len()
    }

    /// Seal `payload` (the `RDV_INTRO` body: cookie + first NYX hop, spec §12.4) to a service-line
    /// of `member_keys.len()` members so that any `threshold` can recover it. Everything — the AEAD
    /// key, its nonce, the Shamir sharing randomness, and each member's KEM randomness — derives
    /// from `seed` (a real CSPRNG draw in production; a fixed seed under the deterministic
    /// simulator), mirroring `fanos_aphantos::threshold::seal_onion`'s single-seed ergonomics.
    ///
    /// # Errors
    /// [`HostingError::Sharing`] for a bad `threshold`/member count; [`HostingError::Aead`] on the
    /// (practically unreachable) sealing failure.
    pub fn seal(
        payload: &[u8],
        threshold: u8,
        member_keys: &[&HybridKemPublic],
        seed: &[u8],
    ) -> Result<Self, HostingError> {
        let line_size = u8::try_from(member_keys.len()).map_err(|_| HostingError::Sharing)?;
        let tag = |label: &str| {
            let mut s = seed.to_vec();
            s.extend_from_slice(label.as_bytes());
            s
        };
        let key = hash_labeled("FANOS-v1/calypso-intro-key", &tag("k"));
        let nonce = derive_nonce("FANOS-v1/calypso-intro-nonce", &tag("n"));
        let ciphertext = aead::seal(&key, &nonce, payload).ok_or(HostingError::Aead)?;

        let key_randomness = sharing_randomness(&tag("r"), threshold);
        let shares = shamir::split(&key, threshold, line_size, &key_randomness)
            .map_err(|_| HostingError::Sharing)?;
        let kem_seed = tag("kem");
        let sealed_shares: Vec<SealedShare> = member_keys
            .iter()
            .zip(&shares)
            .enumerate()
            .map(|(i, (public, share))| {
                let mut s = kem_seed.clone();
                s.extend_from_slice(&(i as u32).to_be_bytes());
                seal_share_to_member(INTRO_SHARE_LABEL, share, public, &s)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            nonce,
            ciphertext,
            sealed_shares,
        })
    }

    /// Member `i`'s own Shamir share of this intro's key — the "PartialDec" it returns to the
    /// combiner (spec §5.2/§12.3). `i` is the member's position in the same order [`seal`](Self::seal)
    /// was given `member_keys`. `None` if `i` is out of range or the slot does not open under
    /// `member_secret` (not this member's share).
    #[must_use]
    pub fn member_partial(&self, i: usize, member_secret: &HybridKemSecret) -> Option<Share> {
        let sealed = self.sealed_shares.get(i)?;
        open_sealed_share(INTRO_SHARE_LABEL, sealed, member_secret)
    }

    /// Reconstruct the intro key from `threshold` (or more)
    /// [`member_partial`](Self::member_partial) shares and decrypt the payload. Fewer than
    /// `threshold` shares reconstruct the *wrong* key, so AEAD authentication fails —
    /// 0-knowledge below threshold (spec §12.3).
    ///
    /// # Errors
    /// [`HostingError::Sharing`] on malformed/insufficient shares; [`HostingError::Malformed`] if a
    /// reconstructed "key" is not 32 bytes (only reachable with forged shares);
    /// [`HostingError::Aead`] below threshold, or on any tamper.
    pub fn open(&self, shares: &[Share]) -> Result<Vec<u8>, HostingError> {
        let key = shamir::reconstruct(shares).map_err(|_| HostingError::Sharing)?;
        let key: [u8; 32] = key.try_into().map_err(|_| HostingError::Malformed)?;
        aead::open(&key, &self.nonce, &self.ciphertext).ok_or(HostingError::Aead)
    }
}

/// One member of a threshold service-line as published in its roster (spec §12.3): the member's hybrid-KEM
/// public — what a client seals its Shamir share to — and the overlay `coordinate` where the client routes
/// to reach it. Public data only; a roster carries no secret.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct LineMember {
    /// The member's hybrid-KEM public key ([`HybridKemPublic::encode`]).
    pub member_pubkey: Vec<u8>,
    /// The member's overlay coordinate.
    pub coordinate: Triple,
}

/// The published **roster** of a threshold-hosted service-line — its members in **seal order** (a member's
/// position is its Shamir share index) and the cooperation `threshold`. A client discovers this
/// (root-signed, e.g. carried in a CALYPSO descriptor's metadata), verifies it, and seals its intro to the
/// whole line with [`seal_intro`](Self::seal_intro) — so it can contact a threshold-hosted service knowing
/// only public keys and coordinates, and no single member ever reads the intro. Wire-serializable; carries
/// no secret.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct ServiceLine {
    /// How many members must cooperate to threshold-decrypt an intro (`t` of `members.len()`).
    pub threshold: u8,
    /// The line's members, in the exact order their keys were dealt — index = share index.
    pub members: Vec<LineMember>,
}

impl ServiceLine {
    /// The designated combiner a client sends its sealed intro to: the first member, by convention
    /// (mirroring `ThresholdRouter`'s canonical combiner). `None` for an empty roster.
    #[must_use]
    pub fn combiner(&self) -> Option<Triple> {
        self.members.first().map(|m| m.coordinate)
    }

    /// Decode the members' public keys in roster order; `None` if any is malformed.
    fn member_keys(&self) -> Option<Vec<HybridKemPublic>> {
        self.members
            .iter()
            .map(|m| HybridKemPublic::decode(&m.member_pubkey))
            .collect()
    }

    /// Seal `payload` (the `RDV_INTRO` body: cookie + reply circuit + `ClientHello`) to this line at its
    /// `threshold`, so any `threshold` of its members jointly recover it and none alone can. `seed` supplies
    /// all key material (a CSPRNG draw in production; a fixed seed under the deterministic simulator).
    ///
    /// # Errors
    /// [`HostingError::Malformed`] if the roster holds a malformed member key; otherwise the errors of
    /// [`SealedIntro::seal`] (a bad `threshold`/member count).
    pub fn seal_intro(&self, payload: &[u8], seed: &[u8]) -> Result<SealedIntro, HostingError> {
        let keys = self.member_keys().ok_or(HostingError::Malformed)?;
        let refs: Vec<&HybridKemPublic> = keys.iter().collect();
        SealedIntro::seal(payload, self.threshold, &refs, seed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_wire::Wire;

    fn fixture_randomness(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 149 + 5) % 251) as u8).collect()
    }

    #[test]
    fn any_threshold_of_hosts_serves_the_request() {
        // A service hosted 5-of-8 across its line.
        let secret = b"service private key material";
        let rnd = fixture_randomness(4 * secret.len());
        let shares = shard_service_key(secret, 5, 8, &rnd).unwrap();
        assert_eq!(shares.len(), 8);
        // Any 5 members reconstruct.
        assert_eq!(recover_service_key(&shares[1..6]).unwrap(), secret);
        assert_eq!(recover_service_key(&shares[3..8]).unwrap(), secret);
    }

    #[test]
    fn below_threshold_seizure_learns_nothing() {
        let secret = b"seizure-proof key";
        let rnd = fixture_randomness(4 * secret.len());
        let shares = shard_service_key(secret, 5, 8, &rnd).unwrap();
        // Four seized hosts (t-1) cannot recover the key.
        assert_ne!(recover_service_key(&shares[0..4]).unwrap(), secret);
    }

    /// `n` member KEM keypairs (secret, public), deterministic per `seed`.
    fn member_keys(n: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[seed, i as u8]);
                HybridKemSecret::generate(&mut rng)
            })
            .collect()
    }

    #[test]
    fn dealt_shares_open_only_under_their_own_member_secret() {
        let members = member_keys(8, 0x10);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let secret = b"service identity secret";
        let rnd = fixture_randomness(4 * secret.len());
        let sealed = deal_service_key(secret, 5, &pubs, &rnd, b"deal-seed").unwrap();
        assert_eq!(sealed.len(), 8);

        // Member 3 opens its own slot...
        let share3 = open_service_share(&sealed[3], &members[3].0).unwrap();
        assert_eq!(share3.x(), 4); // Shamir x-coordinates are 1-indexed

        // ...but member 3's secret does not open member 4's slot (wrong KEM key ⇒ None).
        assert!(open_service_share(&sealed[4], &members[3].0).is_none());
    }

    #[test]
    fn any_threshold_of_dealt_members_recovers_the_identity_secret_but_fewer_cannot() {
        let members = member_keys(8, 0x20);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let secret = b"raid-proof identity";
        let rnd = fixture_randomness(4 * secret.len());
        let sealed = deal_service_key(secret, 5, &pubs, &rnd, b"deal-seed-2").unwrap();

        // Members 1..6 (any 5) each open their own share and jointly recover the identity secret.
        let opened: Vec<Share> = (1..6)
            .map(|i| open_service_share(&sealed[i], &members[i].0).unwrap())
            .collect();
        assert_eq!(recover_service_key(&opened).unwrap(), secret);

        // A DIFFERENT 5-subset also works — availability is not pinned to one fixed quorum.
        let opened_other: Vec<Share> = (3..8)
            .map(|i| open_service_share(&sealed[i], &members[i].0).unwrap())
            .collect();
        assert_eq!(recover_service_key(&opened_other).unwrap(), secret);

        // Four seized/opened shares (t-1 = 4) do NOT recover the real secret — 0-knowledge below t.
        let below: Vec<Share> = (0..4)
            .map(|i| open_service_share(&sealed[i], &members[i].0).unwrap())
            .collect();
        assert_ne!(recover_service_key(&below).unwrap(), secret);
    }

    #[test]
    fn sealed_intro_round_trips_through_wire() {
        let members = member_keys(3, 0x30);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let intro = SealedIntro::seal(b"cookie+first-hop", 2, &pubs, b"wire-seed").unwrap();
        let decoded = SealedIntro::from_wire(&intro.to_wire()).unwrap();
        assert_eq!(decoded, intro);
    }

    #[test]
    fn any_threshold_of_members_opens_the_intro_but_fewer_cannot() {
        // A service-line of 5, threshold 3.
        let members = member_keys(5, 0x40);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let payload = b"RDV_INTRO: cookie + first NYX hop";
        let intro = SealedIntro::seal(payload, 3, &pubs, b"intro-seed").unwrap();
        assert_eq!(intro.member_count(), 5);

        // Members 0, 2, 4 each independently compute their PartialDec.
        let partials: Vec<Share> = [0usize, 2, 4]
            .iter()
            .map(|&i| intro.member_partial(i, &members[i].0).unwrap())
            .collect();
        assert_eq!(intro.open(&partials).unwrap(), payload);

        // Fewer than threshold (2 of 3) cannot recover the intro — 0-knowledge below t.
        let too_few: Vec<Share> = [0usize, 2]
            .iter()
            .map(|&i| intro.member_partial(i, &members[i].0).unwrap())
            .collect();
        assert_eq!(intro.open(&too_few), Err(HostingError::Aead));
    }

    #[test]
    fn a_wrong_member_secret_cannot_open_an_intro_share() {
        let members = member_keys(4, 0x50);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let intro = SealedIntro::seal(b"x", 2, &pubs, b"s").unwrap();
        // Member 0's slot does not open under member 1's secret.
        assert!(intro.member_partial(0, &members[1].0).is_none());
    }

    #[test]
    fn a_service_line_roster_wire_round_trips_and_seals_an_openable_intro() {
        // The published roster a client discovers: 5 members (seal order), threshold 3.
        let members = member_keys(5, 0x77);
        let line = ServiceLine {
            threshold: 3,
            members: members
                .iter()
                .enumerate()
                .map(|(i, (_, p))| LineMember {
                    member_pubkey: p.encode(),
                    coordinate: [i as u32 + 1, 0, 0],
                })
                .collect(),
        };
        // Public wire data — it round-trips byte-exact, and its combiner is the first member.
        let wire = line.to_wire();
        assert_eq!(ServiceLine::from_wire(&wire).unwrap(), line);
        assert_eq!(line.combiner(), Some([1, 0, 0]));

        // A client holding only the roster seals an intro to the whole line; any 3 members open it.
        let payload = b"cookie + reply-circuit + ClientHello";
        let intro = line.seal_intro(payload, b"roster-seal-seed").unwrap();
        assert_eq!(intro.member_count(), 5);
        let partials: Vec<Share> = [1usize, 3, 4]
            .iter()
            .map(|&i| intro.member_partial(i, &members[i].0).unwrap())
            .collect();
        assert_eq!(intro.open(&partials).unwrap(), payload);
        // Below threshold, still 0-knowledge.
        let too_few: Vec<Share> = [1usize, 3]
            .iter()
            .map(|&i| intro.member_partial(i, &members[i].0).unwrap())
            .collect();
        assert_eq!(intro.open(&too_few), Err(HostingError::Aead));
    }
}
