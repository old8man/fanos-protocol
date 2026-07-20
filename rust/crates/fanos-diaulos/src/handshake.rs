//! The DIAULOS 1-RTT handshake — a hybrid, KEM-only, service-authenticated key exchange.
//!
//! A client that already knows a `.fanos` service's **static** hybrid public key (published via
//! ONOMA) establishes forward-secret end-to-end keys in one round trip, revealing no client identity.
//! The construction is the KEMTLS / "IK-KEM" pattern, run over the hybrid X25519+ML-KEM-768 KEM
//! ([`fanos_pqcrypto::kem`]) so it is secure while *either* primitive is:
//!
//! ```text
//!   client ── ClientHello:  ephemeral_pk ‖ ct→service_static ──▶ service
//!   client ◀── ServerHello: ct→ephemeral ──────────────────────  service
//! ```
//!
//! Two hybrid secrets are mixed:
//! * `ss_static` — the client encapsulates to the service's **static** key, so only the holder of the
//!   static secret can derive it. This **authenticates** the service (implicit auth: the first cell
//!   that opens is the key confirmation) and binds the session to the addressed identity.
//! * `ss_ephemeral` — the service encapsulates to the client's **ephemeral** key, discarded after the
//!   handshake. This gives **forward secrecy**: even if the service static secret later leaks, the
//!   session key cannot be recovered (the combiner needs `ss_ephemeral`, whose secret is gone).
//!
//! The session key is `KDF(ss_static ‖ ss_ephemeral ‖ H(transcript))`, where the transcript binds the
//! service static key and both hellos, ruling out unknown-key-share and mix-and-match. It is expanded
//! to the two direction keys `key_c2s ‖ key_s2c` a [`Connection`] uses. The client is the connection
//! *initiator* (even stream ids); the service is the *responder* (odd).

use fanos_pqcrypto::kem::{
    CIPHERTEXT_LEN, HybridCiphertext, HybridKemPublic, HybridKemSecret, PUBLIC_LEN, SessionKey,
};
use fanos_primitives::hash::{hash_labeled, hash_xof, label};
use fanos_primitives::keys::{ED25519_PK_LEN, MLDSA65_PK_LEN};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::conn::Connection;

/// `ClientHello` wire length: ephemeral public key ‖ ciphertext to the service static key.
pub const CLIENT_HELLO_LEN: usize = PUBLIC_LEN + CIPHERTEXT_LEN;
/// `ServerHello` wire length: the ciphertext to the client's ephemeral key.
pub const SERVER_HELLO_LEN: usize = CIPHERTEXT_LEN;

/// The offset of the hybrid KEM key within a canonical identity bundle, whose layout is
/// `Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768` (`fanos_primitives::keys::HybridPublicKey::encode`). The
/// trailing [`PUBLIC_LEN`] bytes from here are exactly the KEM key the handshake needs.
const KEM_OFFSET_IN_BUNDLE: usize = ED25519_PK_LEN + MLDSA65_PK_LEN;

/// Extract a service's [`HybridKemPublic`] (the handshake input) from its canonical ONOMA identity
/// bundle — the `bundle` field a `.fanos` resolution yields. The KEM key is byte-identical whether
/// produced by `fanos_primitives::keys::KemPublicKey` or `fanos_pqcrypto`, so the trailing `PUBLIC_LEN`
/// bytes decode directly. Returns `None` if the bundle is malformed (too short or an invalid key).
#[must_use]
pub fn service_public_from_bundle(bundle: &[u8]) -> Option<HybridKemPublic> {
    HybridKemPublic::decode(bundle.get(KEM_OFFSET_IN_BUNDLE..)?)
}

/// Build a minimal identity bundle carrying just this KEM key — the inverse of
/// [`service_public_from_bundle`] (`service_public_from_bundle(bundle_from_kem_public(pk)) == pk`). The
/// signature-key prefix is zero-filled, so this is for a KEM-only service that publishes a Direct
/// descriptor without an offline signing root; a full identity bundle carries real signing keys there.
#[must_use]
pub fn bundle_from_kem_public(public: &HybridKemPublic) -> Vec<u8> {
    let mut bundle = vec![0u8; KEM_OFFSET_IN_BUNDLE];
    bundle.extend_from_slice(&public.encode());
    bundle
}

/// A service's long-term hybrid KEM identity — the secret it keeps and the public key it publishes
/// (via ONOMA). A client authenticates the service by encapsulating to [`public`](Self::public).
///
/// Both fields are **private**: the decapsulation `secret` never leaves this module (it is read only
/// by [`ServerHandshake::respond`], and has no accessor at all — a caller cannot copy, log, or
/// serialize it), and the `public` key is exposed read-only via [`public`](Self::public). This keeps
/// the secret's exposure surface exactly one function wide.
pub struct StaticKeypair {
    /// The decapsulation secret (never leaves the service — no accessor, module-private).
    secret: HybridKemSecret,
    /// The published encapsulation key (the service's stable identity).
    public: HybridKemPublic,
}

impl StaticKeypair {
    /// Generate a fresh static identity from a CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let (secret, public) = HybridKemSecret::generate(rng);
        Self { secret, public }
    }

    /// The published encapsulation key — the service's stable identity a client encapsulates to.
    /// Read-only: the matching decapsulation secret is unreachable from outside this module.
    #[must_use]
    pub fn public(&self) -> &HybridKemPublic {
        &self.public
    }
}

/// The two direction keys established by a handshake, ready to drive a [`Connection`].
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Key protecting client→service cells.
    pub key_c2s: [u8; 32],
    /// Key protecting service→client cells.
    pub key_s2c: [u8; 32],
}

impl core::fmt::Debug for SessionKeys {
    /// Redacted — key material must never be printed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys(<redacted>)")
    }
}

impl Drop for SessionKeys {
    /// Wipe both direction keys from memory on drop.
    fn drop(&mut self) {
        self.key_c2s.zeroize();
        self.key_s2c.zeroize();
    }
}

impl ZeroizeOnDrop for SessionKeys {}

impl SessionKeys {
    /// Build the client's (initiator) multiplexed connection: seals with `key_c2s`, opens `key_s2c`.
    #[must_use]
    pub fn client_connection(&self) -> Connection {
        Connection::new(self.key_c2s, self.key_s2c, true)
    }

    /// Build the service's (responder) multiplexed connection: seals with `key_s2c`, opens `key_c2s`.
    #[must_use]
    pub fn server_connection(&self) -> Connection {
        Connection::new(self.key_s2c, self.key_c2s, false)
    }
}

/// Expand the two hybrid secrets and the transcript into the pair of direction keys.
fn derive_keys(
    ss_static: &SessionKey,
    ss_ephemeral: &SessionKey,
    transcript: &[u8],
) -> SessionKeys {
    let th = hash_labeled(label::DIAULOS_TH, transcript);
    let mut ikm = Vec::with_capacity(3 * 32);
    ikm.extend_from_slice(ss_static);
    ikm.extend_from_slice(ss_ephemeral);
    ikm.extend_from_slice(&th);
    let mut okm = [0u8; 64];
    hash_xof(label::DIAULOS_KEY, &ikm, &mut okm);
    let (a, b) = okm.split_at(32);
    let mut key_c2s = [0u8; 32];
    let mut key_s2c = [0u8; 32];
    key_c2s.copy_from_slice(a);
    key_s2c.copy_from_slice(b);
    SessionKeys { key_c2s, key_s2c }
}

/// The client's in-flight handshake: hold this between sending [`ClientHello`](ClientHandshake::start)
/// and receiving the `ServerHello`, then [`finish`](ClientHandshake::finish) it.
pub struct ClientHandshake {
    ephemeral_secret: HybridKemSecret,
    /// The hybrid shared secret from the service's static key; wiped on drop. (`ephemeral_secret`
    /// already wipes itself via its X25519/ML-KEM fields' own `ZeroizeOnDrop`.)
    ss_static: Zeroizing<SessionKey>,
    /// `service_public ‖ client_hello` — the transcript so far; `server_hello` is appended at finish.
    transcript_pre: Vec<u8>,
}

impl ClientHandshake {
    /// Begin a handshake to a service whose static public key is `service_public`. Returns the state
    /// to keep and the `ClientHello` bytes ([`CLIENT_HELLO_LEN`] long) to send, or `None` if
    /// `service_public`'s X25519 leg is non-contributory (audit B5) — a malformed or malicious
    /// service key, which no choice of ephemeral secret can rescue (see
    /// [`HybridKemPublic::encapsulate`](fanos_pqcrypto::kem::HybridKemPublic::encapsulate)).
    #[must_use]
    pub fn start<R: CryptoRng>(
        service_public: &HybridKemPublic,
        rng: &mut R,
    ) -> Option<(Self, Vec<u8>)> {
        let (ephemeral_secret, ephemeral_public) = HybridKemSecret::generate(rng);
        let (ct_static, ss_static) = service_public.encapsulate(rng)?;

        let mut hello = Vec::with_capacity(CLIENT_HELLO_LEN);
        hello.extend_from_slice(&ephemeral_public.encode());
        hello.extend_from_slice(&ct_static.to_bytes());

        let mut transcript_pre = Vec::with_capacity(PUBLIC_LEN + CLIENT_HELLO_LEN);
        transcript_pre.extend_from_slice(&service_public.encode());
        transcript_pre.extend_from_slice(&hello);

        Some((
            Self {
                ephemeral_secret,
                ss_static: Zeroizing::new(ss_static),
                transcript_pre,
            },
            hello,
        ))
    }

    /// Complete the handshake from the received `ServerHello`. Returns the session keys, or `None` if
    /// the `ServerHello` is malformed or its X25519 leg is non-contributory (audit B5) — e.g. a
    /// tampered or malicious ciphertext forcing the ephemeral decapsulation to the degenerate result.
    #[must_use]
    pub fn finish(self, server_hello: &[u8]) -> Option<SessionKeys> {
        if server_hello.len() != SERVER_HELLO_LEN {
            return None;
        }
        let ct_ephemeral = HybridCiphertext::from_bytes(server_hello)?;
        let ss_ephemeral = self.ephemeral_secret.decapsulate(&ct_ephemeral)?;
        let mut transcript = self.transcript_pre;
        transcript.extend_from_slice(server_hello);
        Some(derive_keys(&self.ss_static, &ss_ephemeral, &transcript))
    }
}

/// The service's side of the handshake — a single pure step (the responder keeps no per-handshake
/// state before this point).
pub struct ServerHandshake;

impl ServerHandshake {
    /// Respond to a `ClientHello` with the service's static identity. Returns the session keys and the
    /// `ServerHello` bytes ([`SERVER_HELLO_LEN`] long) to send back, or `None` if the hello is
    /// malformed, or either KEM leg's X25519 component is non-contributory (audit B5) — a tampered
    /// `ct_static` or a malformed client ephemeral key, neither of which can be rescued by re-trying.
    #[must_use]
    pub fn respond<R: CryptoRng>(
        keypair: &StaticKeypair,
        client_hello: &[u8],
        rng: &mut R,
    ) -> Option<(SessionKeys, Vec<u8>)> {
        if client_hello.len() != CLIENT_HELLO_LEN {
            return None;
        }
        let ephemeral_public = HybridKemPublic::decode(client_hello.get(..PUBLIC_LEN)?)?;
        let ct_static = HybridCiphertext::from_bytes(client_hello.get(PUBLIC_LEN..)?)?;

        // Only the holder of the static secret derives this — the client's assurance of *who* it is.
        let ss_static = keypair.secret.decapsulate(&ct_static)?;
        // Encapsulate to the client's ephemeral key for forward secrecy.
        let (ct_ephemeral, ss_ephemeral) = ephemeral_public.encapsulate(rng)?;
        let server_hello = ct_ephemeral.to_bytes();

        let mut transcript = Vec::with_capacity(PUBLIC_LEN + CLIENT_HELLO_LEN + SERVER_HELLO_LEN);
        transcript.extend_from_slice(&keypair.public.encode());
        transcript.extend_from_slice(client_hello);
        transcript.extend_from_slice(&server_hello);

        Some((
            derive_keys(&ss_static, &ss_ephemeral, &transcript),
            server_hello,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::kem::HybridKemSecret;
    use fanos_pqcrypto::rng::SeedRng;

    #[test]
    fn service_public_extracts_from_a_canonical_identity_bundle() {
        let mut rng = SeedRng::from_seed(b"bundle-extract");
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        // A canonical bundle is `Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768`; fill the signature part
        // with filler and append the real KEM key.
        let mut bundle = vec![0xABu8; ED25519_PK_LEN + MLDSA65_PK_LEN];
        bundle.extend_from_slice(&public.encode());
        let extracted = service_public_from_bundle(&bundle).expect("valid bundle");
        // The extracted key is the service's — it encapsulates to the same secret.
        let (ct, k) = extracted.encapsulate(&mut rng).expect("honest keys contribute");
        assert_eq!(
            secret.decapsulate(&ct),
            Some(k),
            "extracted the service's real KEM key"
        );
        // A truncated bundle is rejected.
        assert!(service_public_from_bundle(&bundle[..100]).is_none());
        // Exact boundary: the full bundle parses; one byte short does not.
        let exact = ED25519_PK_LEN + MLDSA65_PK_LEN + PUBLIC_LEN;
        assert_eq!(bundle.len(), exact);
        assert!(service_public_from_bundle(&bundle[..exact - 1]).is_none());
    }

    #[test]
    fn bundle_from_kem_public_round_trips() {
        let mut rng = SeedRng::from_seed(b"bundle-build");
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        let bundle = bundle_from_kem_public(&public);
        let extracted = service_public_from_bundle(&bundle).expect("valid KEM-only bundle");
        // The extracted key is the same one — it encapsulates to the same secret.
        let (ct, k) = extracted.encapsulate(&mut rng).expect("honest keys contribute");
        assert_eq!(secret.decapsulate(&ct), Some(k), "round-trips the KEM key");
    }

    #[test]
    fn client_and_service_agree_on_keys_and_talk() {
        let mut srng = SeedRng::from_seed(b"diaulos-hs-service");
        let service = StaticKeypair::generate(&mut srng);

        // 1-RTT: client sends hello, service responds, client finishes.
        let mut crng = SeedRng::from_seed(b"diaulos-hs-client");
        let (client_hs, client_hello) =
            ClientHandshake::start(&service.public, &mut crng).expect("honest keys contribute");
        assert_eq!(client_hello.len(), CLIENT_HELLO_LEN);

        let mut rrng = SeedRng::from_seed(b"diaulos-hs-respond");
        let (server_keys, server_hello) =
            ServerHandshake::respond(&service, &client_hello, &mut rrng).expect("valid hello");
        assert_eq!(server_hello.len(), SERVER_HELLO_LEN);

        let client_keys = client_hs.finish(&server_hello).expect("valid server hello");
        assert_eq!(client_keys, server_keys, "both sides derive identical keys");

        // The derived keys actually drive a working multiplexed connection.
        let mut client = client_keys.client_connection();
        let mut service_conn = server_keys.server_connection();
        let sid = client.open_stream();
        let payload: Vec<u8> = (0..1500u32).map(|i| i as u8).collect();
        client.write(sid, &payload);
        client.finish(sid);

        let mut got = Vec::new();
        for _ in 0..20 {
            for cell in client.outbound() {
                service_conn.on_cell(&cell);
            }
            while let Some(id) = service_conn.accept() {
                let _ = id;
            }
            got.extend_from_slice(&service_conn.read(sid));
            for cell in service_conn.outbound() {
                client.on_cell(&cell);
            }
            if service_conn.receiver_finished(sid) && client.sender_complete(sid) {
                break;
            }
        }
        got.extend_from_slice(&service_conn.read(sid));
        assert_eq!(got, payload, "the handshake keys carry a real stream");
    }

    #[test]
    fn a_wrong_service_key_yields_different_keys() {
        // A man-in-the-middle that does not hold the service static secret cannot land on the client's
        // keys: it can only offer its *own* static key, giving a different ss_static.
        let mut rng = SeedRng::from_seed(b"diaulos-hs-mitm");
        let real = StaticKeypair::generate(&mut rng);
        let impostor = StaticKeypair::generate(&mut rng);

        let (client_hs, client_hello) =
            ClientHandshake::start(&real.public, &mut rng).expect("honest keys contribute");
        // The impostor answers with its own secret (it cannot decapsulate ct→real).
        let (impostor_keys, server_hello) =
            ServerHandshake::respond(&impostor, &client_hello, &mut rng).unwrap();
        let client_keys = client_hs.finish(&server_hello).unwrap();
        assert_ne!(
            client_keys, impostor_keys,
            "the client's keys bind the real service, not the impostor"
        );
    }

    #[test]
    fn malformed_hellos_are_rejected() {
        let mut rng = SeedRng::from_seed(b"diaulos-hs-malformed");
        let service = StaticKeypair::generate(&mut rng);
        assert!(ServerHandshake::respond(&service, &[0u8; 10], &mut rng).is_none());
        let (client_hs, _) =
            ClientHandshake::start(&service.public, &mut rng).expect("honest keys contribute");
        assert!(client_hs.finish(&[0u8; 10]).is_none());
    }

    #[test]
    fn hellos_one_byte_off_the_exact_length_are_rejected() {
        // The length gates are exact equality, so both the short and long neighbours must be refused.
        let mut rng = SeedRng::from_seed(b"diaulos-hs-len");
        let service = StaticKeypair::generate(&mut rng);
        assert!(
            ServerHandshake::respond(&service, &vec![0u8; CLIENT_HELLO_LEN - 1], &mut rng)
                .is_none()
        );
        assert!(
            ServerHandshake::respond(&service, &vec![0u8; CLIENT_HELLO_LEN + 1], &mut rng)
                .is_none()
        );
        let (hs_short, _) =
            ClientHandshake::start(&service.public, &mut rng).expect("honest keys contribute");
        assert!(hs_short.finish(&vec![0u8; SERVER_HELLO_LEN - 1]).is_none());
        let (hs_long, _) =
            ClientHandshake::start(&service.public, &mut rng).expect("honest keys contribute");
        assert!(hs_long.finish(&vec![0u8; SERVER_HELLO_LEN + 1]).is_none());
    }

    #[test]
    fn a_tampered_client_hello_prevents_a_shared_key() {
        // A network attacker that flips a byte of the ClientHello's ciphertext-to-static cannot force
        // agreement: the service decapsulates a different ss_static (and its transcript differs from
        // the client's), so the two sides never land on the same key. Fail-closed.
        let mut rng = SeedRng::from_seed(b"diaulos-hs-tamper-ch");
        let service = StaticKeypair::generate(&mut rng);
        let (client_hs, mut client_hello) =
            ClientHandshake::start(&service.public, &mut rng).expect("honest keys contribute");
        client_hello[PUBLIC_LEN + 5] ^= 0xFF;
        let (server_keys, server_hello) =
            ServerHandshake::respond(&service, &client_hello, &mut rng).unwrap();
        let client_keys = client_hs.finish(&server_hello).unwrap();
        assert_ne!(
            client_keys, server_keys,
            "tampering the ClientHello prevents a shared session key"
        );
    }

    #[test]
    fn a_tampered_server_hello_prevents_a_shared_key() {
        // Symmetrically, flipping a byte of the ServerHello makes the client decapsulate a different
        // ss_ephemeral, so it cannot match the service's keys.
        let mut rng = SeedRng::from_seed(b"diaulos-hs-tamper-sh");
        let service = StaticKeypair::generate(&mut rng);
        let (client_hs, client_hello) =
            ClientHandshake::start(&service.public, &mut rng).expect("honest keys contribute");
        let (server_keys, mut server_hello) =
            ServerHandshake::respond(&service, &client_hello, &mut rng).unwrap();
        server_hello[3] ^= 0xFF;
        let client_keys = client_hs
            .finish(&server_hello)
            .expect("still the right length");
        assert_ne!(
            client_keys, server_keys,
            "tampering the ServerHello prevents a shared session key"
        );
    }

    #[test]
    fn two_sessions_to_the_same_service_derive_distinct_keys() {
        // Each session draws a fresh ephemeral, so no two sessions to the same static identity share a
        // key — the forward-secrecy contribution of the ephemeral encapsulation.
        let mut srng = SeedRng::from_seed(b"diaulos-hs-distinct-svc");
        let service = StaticKeypair::generate(&mut srng);
        let mut rng = SeedRng::from_seed(b"diaulos-hs-distinct");

        let (hs1, ch1) =
            ClientHandshake::start(&service.public, &mut rng).expect("honest keys contribute");
        let (k1, sh1) = ServerHandshake::respond(&service, &ch1, &mut rng).unwrap();
        let ck1 = hs1.finish(&sh1).unwrap();

        let (hs2, ch2) =
            ClientHandshake::start(&service.public, &mut rng).expect("honest keys contribute");
        let (k2, sh2) = ServerHandshake::respond(&service, &ch2, &mut rng).unwrap();
        let ck2 = hs2.finish(&sh2).unwrap();

        assert_eq!(ck1, k1, "session 1 agrees");
        assert_eq!(ck2, k2, "session 2 agrees");
        assert_ne!(ck1, ck2, "fresh ephemerals give each session distinct keys");
        assert_ne!(ch1, ch2, "and distinct client hellos");
    }
}
