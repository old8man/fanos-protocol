//! Per-node TLS 1.3 identity for the QUIC endpoint.
//!
//! Every node mints a fresh self-signed certificate at start-up. FANOS does **not** derive trust
//! from a PKI: the overlay identity is the projective coordinate, bound to a network address by
//! the [`Directory`](crate::Directory) (in production, by the DHT — the self-certifying CALYPSO
//! model). So the QUIC layer's job is only to give every link confidentiality and integrity, not
//! to authenticate a name. The client verifier therefore accepts any certificate but still checks
//! the handshake signature, exactly the pattern overlay networks use to run real TLS over
//! app-layer identity.
//!
//! The crypto provider is pinned to `ring` and passed explicitly, so no process-wide default
//! provider needs installing and builds stay portable (no aws-lc-rs C toolchain).

use std::sync::Arc;

use zeroize::Zeroize;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig};
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

/// The ALPN token every FANOS QUIC endpoint negotiates (rejects non-FANOS peers early).
///
/// It is also, today, the protocol's **name in plaintext on the wire**: a QUIC Initial is protected with keys
/// derived from a well-known salt (RFC 9001 §5.2), so any middlebox reads the ClientHello — this token and the
/// `fanos.node` SNI below with it. No morph changes either, because shaping starts at the stream. See
/// `tests/probe_resistance.rs` for the measurement and [`crate::spawn_shaped`] for the scope note.
const ALPN: &[u8] = b"fanos/1";

/// The OID of the custom X.509 extension that carries a node's 32-byte coordinate-VRF public key in its
/// self-signed certificate (a FANOS private-use enterprise arc). rcgen embeds it at generation;
/// [`crate::identity::vrf_public_from_cert`] reads it back from a peer's authenticated certificate.
pub(crate) const FANOS_VRF_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 61234, 1];

/// Derive a node's coordinate-VRF secret deterministically from its certificate private-key DER, so the
/// VRF key is bound to — and as durable as — the TLS identity (spec §L0): a domain-separated hash of the
/// key seeds `VrfSecret::from_seed` (total). Reloading the same credentials reproduces the same VRF key,
/// so no extra persisted field is needed.
pub(crate) fn vrf_secret_from_key(key_der: &[u8]) -> fanos_vrf::VrfSecret {
    let mut seed = [0u8; 32];
    fanos_primitives::hash::hash_xof("FANOS-v1/node-vrf-key", key_der, &mut seed);
    fanos_vrf::VrfSecret::from_seed(seed)
}

/// Derive a node's **descriptor signing key** deterministically from the same certificate private key, under
/// its own domain — the hybrid `Ed25519 ‖ ML-DSA-65` identity whose public bundle *is* the node's `id`
/// (spec §80, `fanos_runtime::descriptor_message`).
///
/// Same argument as [`vrf_secret_from_key`] and the same shape: reloading the credentials reproduces the key,
/// so the identity file still round-trips the whole identity and nothing new has to be persisted. It also
/// makes `id` a **function of the certificate**, so `H(cert)` — the anchor the coordinate VRF is proved
/// against — commits to it, and an identity bundle cannot be transplanted onto another certificate.
///
/// `SeedRng` is the PQ stack's own domain-separated XOF generator, so this is a key-**derivation** step
/// rather than a second source of randomness — and it is the right one rather than `fanos_vrf`'s
/// `DeterministicRng`, which implements `rand_core` **0.6** against the RustCrypto crates' 0.10.
pub(crate) fn descriptor_identity_from_key(
    key_der: &[u8],
) -> (Vec<u8>, fanos_pqcrypto::HybridSigSecret) {
    let mut seed = [0u8; 32];
    fanos_primitives::hash::hash_xof("FANOS-v1/node-descriptor-key", key_der, &mut seed);
    let (secret, verifier) =
        fanos_pqcrypto::HybridSigSecret::generate(&mut fanos_pqcrypto::SeedRng::from_seed(&seed));
    seed.zeroize();
    (verifier.encode(), secret)
}

/// A TLS setup failure (certificate generation or config assembly).
#[derive(Debug)]
pub enum TlsError {
    /// Self-signed certificate generation failed.
    Cert,
    /// Assembling the rustls/QUIC config failed (e.g. no TLS 1.3 cipher suite).
    Config,
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cert => f.write_str("self-signed certificate generation failed"),
            Self::Config => f.write_str("TLS/QUIC configuration assembly failed"),
        }
    }
}

impl std::error::Error for TlsError {}

/// Build a fresh `(server, client)` QUIC config pair for one node, with a newly minted
/// self-signed certificate and the permissive-but-signature-checking client verifier.
pub(crate) fn node_configs() -> Result<(ServerConfig, ClientConfig), TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let certified = rcgen::generate_simple_self_signed(vec!["fanos.node".to_owned()])
        .map_err(|_| TlsError::Cert)?;
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Config)?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|_| TlsError::Config)?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let server = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).map_err(|_| TlsError::Config)?,
    ));

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Config)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let client = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(|_| TlsError::Config)?,
    ));

    Ok((server, client))
}

/// A node's long-term TLS identity — its certificate and private key. Persist these bytes
/// ([`to_bytes`](NodeCredentials::to_bytes)) and reload them ([`from_bytes`](NodeCredentials::from_bytes))
/// to keep the same self-certifying coordinate `MapToPoint(H(cert))` across restarts.
/// `#[derive(Wire)]` emits the canonical `cert_der ‖ key_der` (each `Vec<u8>` varint-length-prefixed,
/// spec §7.1); the [`to_bytes`](Self::to_bytes)/[`from_bytes`](Self::from_bytes) persistence API wraps it.
#[derive(Clone, fanos_wire_derive::Wire)]
pub struct NodeCredentials {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

// Redacted Debug + zeroize-on-drop (audit #124): `key_der` is the node's raw PKCS8 TLS/QUIC private key —
// its compromise lets an attacker clone the node's overlay coordinate. The derived Debug would print it;
// this one redacts it (showing only the certificate length). Drop wipes the key bytes from freed memory.
impl core::fmt::Debug for NodeCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeCredentials")
            .field("cert_der_len", &self.cert_der.len())
            .field("key_der", &"<redacted>")
            .finish()
    }
}

impl Drop for NodeCredentials {
    fn drop(&mut self) {
        self.key_der.zeroize();
    }
}

impl NodeCredentials {
    /// Mint fresh credentials: a self-signed certificate + key, with the node's **coordinate-VRF public
    /// key embedded** as a custom extension (spec §L0). The VRF secret is derived deterministically from
    /// the certificate's private key, so persistence is unchanged (`cert_der ‖ key_der` still round-trips
    /// the whole identity) and reloading reconstructs the same VRF key. Because the VRF public is in the
    /// certificate, `H(cert)` — the node's identity anchor — commits to the key that earns its coordinate,
    /// and a peer's coordinate proof cannot be transplanted onto another certificate.
    pub fn generate() -> Result<Self, TlsError> {
        Self::from_key_pair(&rcgen::KeyPair::generate().map_err(|_| TlsError::Cert)?)
    }

    /// [`generate`](Self::generate) over a key the caller already holds — the same certificate, the same
    /// embedded VRF public, the same derivation, with the entropy supplied instead of drawn.
    ///
    /// Exists for one caller: `crate::harness::credentials_from_seed`, which needs a *reproducible* identity
    /// so a fleet can replay a draw rather than sample a new one. Everything a deployment reaches still goes
    /// through `generate`, and this changes nothing about what a credential is — only where its randomness
    /// came from.
    pub fn from_key_pair(key: &rcgen::KeyPair) -> Result<Self, TlsError> {
        let key_der = key.serialize_der();
        let vrf_public = vrf_secret_from_key(&key_der).public();
        let mut params = rcgen::CertificateParams::new(vec!["fanos.node".to_owned()])
            .map_err(|_| TlsError::Cert)?;
        params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
            FANOS_VRF_OID,
            vrf_public.to_bytes().to_vec(),
        ));
        let cert = params.self_signed(key).map_err(|_| TlsError::Cert)?;
        Ok(Self {
            cert_der: cert.der().to_vec(),
            key_der,
        })
    }

    /// This node's coordinate-VRF secret key — derived from the certificate's private key, so it is as
    /// durable as the identity itself (reloaded credentials reproduce it). Proves the node's verifiable
    /// coordinate `MapToPoint(VRF(vrf_sk, H(cert)‖epoch‖beacon))` (spec §L0/§L3).
    #[must_use]
    pub fn vrf_secret(&self) -> fanos_vrf::VrfSecret {
        vrf_secret_from_key(&self.key_der)
    }

    /// This node's **descriptor signing key** — the hybrid identity whose public bundle is its `id` (§80),
    /// derived from the certificate's private key so it is as durable as the identity itself.
    ///
    /// Used to sign `descriptor_message(coord, hier, id)` at every reseat: the message binds the **transport
    /// coordinate**, and the per-epoch reshuffle re-draws it, so a signature made once at provisioning is
    /// stale at the first boundary. That is why this is a runtime capability rather than a config field.
    ///
    /// Returned with its **identity bundle** — the encoded verifier, which is what `id` is on the wire and
    /// what a receiver checks the signature against — because the two are one derivation and handing them
    /// out separately is how a signature and the key it is checked with come to disagree.
    #[must_use]
    pub fn descriptor_identity(&self) -> (Vec<u8>, fanos_pqcrypto::HybridSigSecret) {
        descriptor_identity_from_key(&self.key_der)
    }

    /// The certificate DER — the node's identity (its coordinate is `MapToPoint(H(cert))`).
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Serialize for persistence: a [`stored`](fanos_wire::stored) frame over the canonical
    /// [`Wire`](fanos_wire::Wire) codec.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        fanos_wire::stored::write_header(&mut out, IDENTITY_MAGIC, IDENTITY_FORMAT_VERSION);
        out.extend_from_slice(&fanos_wire::Wire::to_wire(self));
        out
    }

    /// Reload persisted credentials, saying **which** of four things the bytes are (#309).
    ///
    /// `from_bytes` used to answer `Option`, and its one production caller turned that into
    /// `NodeError::Identity` — a single sentence for a truncated file, a file of the wrong kind (a mistyped
    /// `--identity`), and a file from a build with a different layout. Those need different actions from an
    /// operator, and the last one is why the layout could never change: add a field and every live node's
    /// identity file becomes indistinguishable from a corrupt one — which for this file means the node's
    /// coordinate.
    ///
    /// # Errors
    ///
    /// [`IdentityFormat`] naming the case. `Legacy` is not an error the caller must refuse — see there.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityFormat> {
        match fanos_wire::stored::classify(bytes, IDENTITY_MAGIC, IDENTITY_FORMAT_VERSION) {
            fanos_wire::stored::StoredFormat::Current => {
                let body = bytes.get(fanos_wire::stored::HEADER_LEN..).unwrap_or_default();
                fanos_wire::Wire::from_wire(body).map_err(|_| IdentityFormat::Corrupt)
            }
            fanos_wire::stored::StoredFormat::OtherVersion(v) => Err(IdentityFormat::OtherVersion(v)),
            // **Unframed is read as legacy, and that decision is the whole migration** (#309). Every
            // identity file written before this frame existed is unframed, and refusing them would not be
            // strict — it would DELETE those nodes: the file is the coordinate, so a node that cannot load
            // it comes back as a stranger and the cell sees the old one simply vanish. So the body is tried
            // as-is, and a caller that wants to tell an operator "this file predates the frame" gets
            // `Legacy` to say it with. A file that is not an identity at all fails the same decode and
            // arrives as `Corrupt`, which is the honest limit: at this layer the two are the same bytes.
            fanos_wire::stored::StoredFormat::Unframed => match fanos_wire::Wire::from_wire(bytes) {
                Ok(creds) => Err(IdentityFormat::Legacy(Box::new(creds))),
                Err(_) => Err(IdentityFormat::Corrupt),
            },
        }
    }
}

/// A stored identity's kind marker — `FNID`, in the four-byte shape every on-disk format here uses.
pub const IDENTITY_MAGIC: fanos_wire::stored::Magic = *b"FNID";

/// The identity file's **layout** version, and deliberately not the provisioning family's (#309).
///
/// `cert_der ‖ key_der` is written by `fanos-quic` and read by every node at start; a TAXIS validator config
/// is written by a ceremony and read by one role. They change for unrelated reasons, so they count
/// separately — sharing one number would declare every node's identity out of date the day a validator
/// config gained a field.
pub const IDENTITY_FORMAT_VERSION: u8 = 1;

/// What a persisted identity's bytes turned out to be, when they are not simply this build's.
///
/// Four answers rather than `None`, because the operator's next action differs in each and the caller is the
/// only one that can phrase it.
#[derive(Debug)]
pub enum IdentityFormat {
    /// **Written before the frame existed** — and it decoded, so it is a real identity and the node keeps
    /// its coordinate. Carried out rather than swallowed so a caller can say so once: an operator has no
    /// other way to learn that this file is on the old layout and will stay readable only while this
    /// build's legacy path exists.
    ///
    /// Boxed because the credentials are much larger than the other variants, and a `Result`'s error arm
    /// sized by its largest member would make every `?` on this type carry the whole certificate.
    Legacy(Box<NodeCredentials>),
    /// This kind of file, at a **different** layout version. The node must not guess at a body it cannot
    /// read: doing so would derive a coordinate from misparsed bytes and join the cell as somebody else.
    OtherVersion(u8),
    /// The frame is this build's (or absent) and the body did not decode: truncated, corrupt, or not an
    /// identity file at all.
    Corrupt,
}

/// Build a **mutual-TLS** `(server, client, cert)` triple from given credentials. Both ends present
/// the node's certificate and require the peer's, so the connection is authenticated to that
/// certificate; each side then proves its VRF coordinate in a HELLO the other verifies against it
/// (spec §7.3 — the certificate carries the coordinate-VRF public key). Returns
/// the node's own certificate DER (its identity), used to derive its coordinate.
pub(crate) fn node_configs_mutual_from(
    creds: &NodeCredentials,
) -> Result<(ServerConfig, ClientConfig, CertificateDer<'static>), TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let cert_der: CertificateDer<'static> = CertificateDer::from(creds.cert_der.clone());
    let server_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(creds.key_der.clone()));
    let client_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(creds.key_der.clone()));

    // Server: require and accept any client certificate (identity is the key, not a CA).
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Config)?
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCert {
            provider: provider.clone(),
        }))
        .with_single_cert(vec![cert_der.clone()], server_key)
        .map_err(|_| TlsError::Config)?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let server = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).map_err(|_| TlsError::Config)?,
    ));

    // Client: accept any server certificate, and present our own for the server to authenticate.
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Config)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
        .with_client_auth_cert(vec![cert_der.clone()], client_key)
        .map_err(|_| TlsError::Config)?;
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let client = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(|_| TlsError::Config)?,
    ));

    Ok((server, client, cert_der))
}

/// A verifier that accepts any presented certificate (overlay identity is directory-bound, not
/// PKI-bound) but still validates the handshake signature against the presented key — so the
/// channel is genuinely authenticated end-to-end at the TLS layer, just not to a CA/hostname.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The mirror of [`AcceptAnyServerCert`] for client certificates: require a client cert and accept
/// any (identity is the key), while still checking the handshake signature. This is what lets the
/// acceptor authenticate the dialer's key — and hence derive its self-certifying coordinate.
#[derive(Debug)]
struct AcceptAnyClientCert {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AcceptAnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
