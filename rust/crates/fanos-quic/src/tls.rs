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
        let key = rcgen::KeyPair::generate().map_err(|_| TlsError::Cert)?;
        let key_der = key.serialize_der();
        let vrf_public = vrf_secret_from_key(&key_der).public();
        let mut params = rcgen::CertificateParams::new(vec!["fanos.node".to_owned()])
            .map_err(|_| TlsError::Cert)?;
        params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
            FANOS_VRF_OID,
            vrf_public.to_bytes().to_vec(),
        ));
        let cert = params.self_signed(&key).map_err(|_| TlsError::Cert)?;
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

    /// The certificate DER — the node's identity (its coordinate is `MapToPoint(H(cert))`).
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Serialize for persistence (the canonical [`Wire`](fanos_wire::Wire) codec).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        fanos_wire::Wire::to_wire(self)
    }

    /// Reload persisted credentials, or `None` if the bytes are malformed or carry trailing data.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        fanos_wire::Wire::from_wire(bytes).ok()
    }
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
