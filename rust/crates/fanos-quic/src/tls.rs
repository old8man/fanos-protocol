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

/// Build a **mutual-TLS** `(server, client, cert)` triple for a self-certifying node. Both ends
/// present the node's certificate and require the peer's, so each can derive the peer's overlay
/// coordinate `MapToPoint(H(cert))` from the authenticated handshake — no directory-trust, no
/// HELLO. Returns the node's own certificate DER (its identity), used to derive its coordinate.
pub(crate) fn node_configs_mutual()
-> Result<(ServerConfig, ClientConfig, CertificateDer<'static>), TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let certified = rcgen::generate_simple_self_signed(vec!["fanos.node".to_owned()])
        .map_err(|_| TlsError::Cert)?;
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_bytes = certified.signing_key.serialize_der();
    let server_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_bytes.clone()));
    let client_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_bytes));

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
