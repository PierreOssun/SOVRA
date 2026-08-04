//! The one home for runtime TLS plumbing on the internal planes. Every internal
//! socket is mTLS: servers require a leaf signed by the project CA, clients pin
//! that CA (never WebPKI) and present their own leaf — so a local process
//! without CA-signed material is refused at the handshake, before any handler,
//! lock, or MPC message. Provisioning lives in `sovra-certs`; this module only
//! loads what exists and refuses to start otherwise, like the policy loader.
//!
//! ALPN is deliberately left empty everywhere: tungstenite has no h2 upgrade
//! path and reqwest here has no http2 feature, so an empty list negotiates
//! http/1.1 consistently instead of inviting a client that can't upgrade.

use std::{path::Path, sync::Arc, time::Duration};

use axum::Router;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, pki_types, pki_types::pem::PemObject,
    server::WebPkiClientVerifier,
};

/// The three PEMs an mTLS peer needs, loaded once at startup and turned into
/// per-plane configs on demand. Missing or malformed material is an error at
/// load — fail-closed, with the offending path in the message.
pub struct TlsMaterials {
    ca: pki_types::CertificateDer<'static>,
    cert_chain: Vec<pki_types::CertificateDer<'static>>,
    key: pki_types::PrivateKeyDer<'static>,
    /// Raw PEM copies for reqwest, which takes PEM bytes rather than DER:
    /// the CA alone, and the leaf cert + PKCS#8 key concatenated (the shape
    /// `Identity::from_pem` expects; rcgen writes keys as PKCS#8).
    ca_pem: Vec<u8>,
    identity_pem: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("TLS material {path}: {source}")]
    Load {
        path: std::path::PathBuf,
        #[source]
        source: pki_types::pem::Error,
    },
    #[error("TLS material {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("building TLS config: {0}")]
    Config(#[from] rustls::Error),
    #[error("building client-cert verifier: {0}")]
    Verifier(#[from] rustls::server::VerifierBuilderError),
    #[error("building HTTP client: {0}")]
    Http(#[from] reqwest::Error),
    #[error("serving TLS: {0}")]
    Serve(#[from] std::io::Error),
}

impl TlsMaterials {
    /// Load CA cert, own leaf cert (chain), and own key. Any missing or
    /// unparsable file fails here with its path — startup is the only caller,
    /// and a process without TLS material must not come up.
    pub fn load(ca: &Path, cert: &Path, key: &Path) -> Result<Self, TlsError> {
        let read = |path: &Path| {
            std::fs::read(path).map_err(|source| TlsError::Read {
                path: path.to_path_buf(),
                source,
            })
        };
        let parse_err = |path: &Path| {
            let path = path.to_path_buf();
            move |source| TlsError::Load { path, source }
        };

        let ca_pem = read(ca)?;
        let ca_der = pki_types::CertificateDer::from_pem_slice(&ca_pem).map_err(parse_err(ca))?;

        let cert_pem = read(cert)?;
        let cert_chain: Vec<_> = pki_types::CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<_, _>>()
            .map_err(parse_err(cert))?;
        if cert_chain.is_empty() {
            // An empty-but-readable file would otherwise die much later, in
            // with_single_cert, without the offending path.
            return Err(parse_err(cert)(pki_types::pem::Error::NoItemsFound));
        }

        let key_pem = read(key)?;
        let key_der = pki_types::PrivateKeyDer::from_pem_slice(&key_pem).map_err(parse_err(key))?;

        // The shape Identity::from_pem expects: leaf cert + PKCS#8 key, one buffer.
        let mut identity_pem = cert_pem;
        identity_pem.extend_from_slice(&key_pem);

        Ok(Self {
            ca: ca_der,
            cert_chain,
            key: key_der,
            ca_pem,
            identity_pem,
        })
    }

    fn root_store(&self) -> Result<RootCertStore, TlsError> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone())?;
        Ok(roots)
    }

    /// Server side of both internal planes: presents our leaf, requires the
    /// peer to present one signed by the project CA.
    pub fn server_config(&self) -> Result<ServerConfig, TlsError> {
        let verifier = WebPkiClientVerifier::builder(Arc::new(self.root_store()?)).build()?;
        Ok(ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.cert_chain.clone(), self.key.clone_key())?)
    }

    /// Client config for the relay plane (`WsRelay::connect`): trusts only the
    /// project CA and presents our leaf.
    pub fn ws_client_config(&self) -> Result<Arc<ClientConfig>, TlsError> {
        Ok(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(self.root_store()?)
                .with_client_auth_cert(self.cert_chain.clone(), self.key.clone_key())?,
        ))
    }

    /// Control-plane client: `tls_certs_only` (not `add_root_certificate`)
    /// drops the platform/WebPKI roots, so the *only* servers this client will
    /// speak to are ones holding a project-CA leaf.
    pub fn http_client(&self, timeout: Duration) -> Result<reqwest::Client, TlsError> {
        Ok(reqwest::Client::builder()
            .timeout(timeout)
            .tls_certs_only([reqwest::Certificate::from_pem(&self.ca_pem)?])
            .identity(reqwest::Identity::from_pem(&self.identity_pem)?)
            .build()?)
    }

    /// Blocking twin of [`Self::http_client`] for synchronous callers (xtask's
    /// readiness probes). Feature-gated so the async binaries never compile
    /// reqwest's blocking runtime.
    #[cfg(feature = "blocking")]
    pub fn blocking_http_client(
        &self,
        timeout: Duration,
    ) -> Result<reqwest::blocking::Client, TlsError> {
        Ok(reqwest::blocking::Client::builder()
            .timeout(timeout)
            .tls_certs_only([reqwest::Certificate::from_pem(&self.ca_pem)?])
            .identity(reqwest::Identity::from_pem(&self.identity_pem)?)
            .build()?)
    }
}

/// Serve `router` on `listener` behind required-client-cert TLS — the single
/// call-site pattern for every internal listener (cosigner control APIs, relay
/// hub) in binaries and tests alike. axum-server rides hyper's upgrade path,
/// so WebSocket upgrades on the hub work unchanged.
pub async fn serve_mtls(
    listener: std::net::TcpListener,
    router: Router,
    materials: &TlsMaterials,
) -> Result<(), TlsError> {
    let config =
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(materials.server_config()?));
    axum_server::from_tcp_rustls(listener, config)?
        .serve(router.into_make_service())
        .await?;
    Ok(())
}
