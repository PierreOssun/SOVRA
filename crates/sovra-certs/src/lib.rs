//! Certificate provisioning for the internal planes: one private CA under
//! `certs/`, one leaf per process (`orchestrator`, `cosigner0`, …). Everything
//! mTLS trusts flows from here.
//!
//! Why a dedicated crate instead of a module in sovra-ipc: rcgen must provably
//! never link into the shipped binaries — xtask depends on this crate normally,
//! the server/client crates only as a dev-dependency for their TLS tests.
//! Load-if-exists / generate-if-absent / refuse-to-overwrite mirrors the
//! ed25519 identity-seeding precedent, so a re-run is always additive: adding a
//! party or re-issuing for a new host (`--san`) never rewrites existing
//! material, and a half-present pair (cert without key, or vice versa) is a
//! hard error rather than a silent regeneration — a regenerated CA would
//! strand every peer still trusting the old root.

use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

/// CA file names under the certs dir. The CA *key* never leaves the
/// provisioning machine; a deployed box gets its own leaf plus the CA cert.
pub const CA_CERT_FILE: &str = "ca.cert.pem";
pub const CA_KEY_FILE: &str = "ca.key.pem";

/// Rotation = delete the pem pair and re-run provisioning.
const CA_VALIDITY_DAYS: i64 = 3650;
const LEAF_VALIDITY_DAYS: i64 = 730;

/// SANs every leaf gets by default; deployment-specific hosts are appended via
/// `cargo xtask certs --san <dns-or-ip>`. Over-broad SANs are harmless inside
/// a single-CA closed system.
pub fn default_sans() -> Vec<String> {
    vec!["127.0.0.1".into(), "localhost".into()]
}

#[derive(Debug, thiserror::Error)]
pub enum CertsError {
    #[error(
        "half-present pair in {dir}: found {found} but not {missing} — restore the missing \
         file, or delete the survivor (and, for a CA, every leaf it issued) and re-provision"
    )]
    HalfPresent {
        dir: PathBuf,
        found: String,
        missing: String,
    },
    #[error(
        "stale leaf {path}: it predates the freshly minted CA and no longer chains to the \
         trust root — delete every leftover leaf pair and re-run provisioning"
    )]
    StaleLeaf { path: PathBuf },
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),
    #[error(transparent)]
    State(#[from] sovra_state::StateError),
}

/// A loaded-or-minted CA, able to issue leaves in the same run.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
}

/// Where a leaf's material lives — handed back so callers (tests, xtask
/// messages) never re-derive the naming scheme.
#[derive(Debug)]
pub struct LeafPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Load the CA under `dir`, minting it first if absent (10-year validity,
/// CN `sovra-ca`). Existing material is never rewritten.
pub fn ensure_ca(dir: &Path) -> Result<Ca, CertsError> {
    std::fs::create_dir_all(dir).map_err(|e| CertsError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    let cert_path = dir.join(CA_CERT_FILE);
    let key_path = dir.join(CA_KEY_FILE);

    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            let key = KeyPair::from_pem(&read(&key_path)?)?;
            let issuer = Issuer::from_ca_cert_pem(&read(&cert_path)?, key)?;
            Ok(Ca { issuer })
        }
        (false, false) => {
            // Refuse to mint a fresh root over surviving leaves: they chain to
            // the old CA and would fail every future handshake with an opaque
            // UnknownIssuer alert — catch the botched rotation here instead.
            if let Some(leaf) = any_leaf(dir)? {
                return Err(CertsError::StaleLeaf { path: leaf });
            }
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(DnType::CommonName, "sovra-ca");
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            (params.not_before, params.not_after) = validity(CA_VALIDITY_DAYS);
            let cert = params.self_signed(&key)?;
            sovra_state::write_atomic(&key_path, key.serialize_pem().as_bytes())?;
            sovra_state::write_atomic(&cert_path, cert.pem().as_bytes())?;
            Ok(Ca {
                issuer: Issuer::new(params, key),
            })
        }
        (true, false) => Err(half_present(dir, CA_CERT_FILE, CA_KEY_FILE)),
        (false, true) => Err(half_present(dir, CA_KEY_FILE, CA_CERT_FILE)),
    }
}

/// Ensure `<file_stem>.{cert,key}.pem` exist under `dir`, minting a CA-signed
/// leaf if absent. CN carries the process identity (`sovra-orchestrator`,
/// `sovra-cosigner-<party_id>`) — that is what a later role-binding check will
/// read; the file stem is only the on-disk name.
pub fn ensure_leaf(
    dir: &Path,
    file_stem: &str,
    common_name: &str,
    sans: &[String],
    ca: &Ca,
) -> Result<LeafPaths, CertsError> {
    let cert_file = format!("{file_stem}.cert.pem");
    let key_file = format!("{file_stem}.key.pem");
    let cert_path = dir.join(&cert_file);
    let key_path = dir.join(&key_file);

    match (cert_path.exists(), key_path.exists()) {
        // Refuse overwrite: existing material wins, so provisioning is additive.
        (true, true) => {}
        (false, false) => {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
            let mut params = CertificateParams::new(sans.to_vec())?;
            params
                .distinguished_name
                .push(DnType::CommonName, common_name);
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            // Both EKUs on every leaf: each process is a server on one plane and
            // a client on the other; a single-EKU leaf fails on exactly one
            // plane with an opaque handshake alert.
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            (params.not_before, params.not_after) = validity(LEAF_VALIDITY_DAYS);
            let cert = params.signed_by(&key, &ca.issuer)?;
            sovra_state::write_atomic(&key_path, key.serialize_pem().as_bytes())?;
            sovra_state::write_atomic(&cert_path, cert.pem().as_bytes())?;
        }
        (true, false) => return Err(half_present(dir, &cert_file, &key_file)),
        (false, true) => return Err(half_present(dir, &key_file, &cert_file)),
    }
    Ok(LeafPaths {
        cert: cert_path,
        key: key_path,
    })
}

/// First non-CA `.pem` under `dir`, if any — only consulted before minting a
/// fresh root, where any survivor is by definition orphaned.
fn any_leaf(dir: &Path) -> Result<Option<PathBuf>, CertsError> {
    let entries = std::fs::read_dir(dir).map_err(|e| CertsError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|e| CertsError::Io {
                path: dir.to_path_buf(),
                source: e,
            })?
            .path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.ends_with(".pem") && name != CA_CERT_FILE && name != CA_KEY_FILE {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn validity(days: i64) -> (time::OffsetDateTime, time::OffsetDateTime) {
    let now = time::OffsetDateTime::now_utc();
    (now, now + time::Duration::days(days))
}

fn half_present(dir: &Path, found: &str, missing: &str) -> CertsError {
    CertsError::HalfPresent {
        dir: dir.to_path_buf(),
        found: found.to_owned(),
        missing: missing.to_owned(),
    }
}

fn read(path: &Path) -> Result<String, CertsError> {
    std::fs::read_to_string(path).map_err(|e| CertsError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    use super::*;

    fn mint(dir: &Path) -> (Ca, LeafPaths) {
        let ca = ensure_ca(dir).expect("ensure_ca");
        let leaf = ensure_leaf(dir, "cosigner0", "sovra-cosigner-0", &default_sans(), &ca)
            .expect("ensure_leaf");
        (ca, leaf)
    }

    fn parse_der(pem: &str) -> Vec<u8> {
        let (_, doc) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("pem");
        doc.contents
    }

    #[test]
    fn ca_and_leaf_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (_, leaf) = mint(dir.path());
        let ca_bytes = std::fs::read(dir.path().join(CA_CERT_FILE)).unwrap();
        let leaf_bytes = std::fs::read(&leaf.cert).unwrap();

        // Second run: everything loads, nothing is rewritten.
        let (_, leaf2) = mint(dir.path());
        assert_eq!(
            std::fs::read(dir.path().join(CA_CERT_FILE)).unwrap(),
            ca_bytes
        );
        assert_eq!(std::fs::read(&leaf2.cert).unwrap(), leaf_bytes);
    }

    #[test]
    fn half_present_ca_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        ensure_ca(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join(CA_KEY_FILE)).unwrap();
        // .err() instead of .unwrap_err(): Ca holds the CA key and derives no Debug.
        let err = ensure_ca(dir.path()).err().expect("expected an error");
        assert!(matches!(err, CertsError::HalfPresent { .. }), "{err}");
    }

    #[test]
    fn half_present_leaf_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, leaf) = mint(dir.path());
        std::fs::remove_file(&leaf.key).unwrap();
        let err = ensure_leaf(
            dir.path(),
            "cosigner0",
            "sovra-cosigner-0",
            &default_sans(),
            &ca,
        )
        .unwrap_err();
        assert!(matches!(err, CertsError::HalfPresent { .. }), "{err}");
    }

    #[test]
    fn leaf_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, leaf) = mint(dir.path());
        let before = std::fs::read(&leaf.cert).unwrap();
        // Same stem, different SANs: existing material must win.
        ensure_leaf(
            dir.path(),
            "cosigner0",
            "other-name",
            &["10.0.0.1".into()],
            &ca,
        )
        .unwrap();
        assert_eq!(std::fs::read(&leaf.cert).unwrap(), before);
    }

    /// The botched-rotation trap: deleting only `ca.*.pem` and re-provisioning
    /// must not silently keep leaves that chain to the dead root — that would
    /// surface weeks later as an opaque handshake failure instead of now.
    #[test]
    fn regenerated_ca_refuses_stale_leaves() {
        let dir = tempfile::tempdir().unwrap();
        mint(dir.path());
        std::fs::remove_file(dir.path().join(CA_CERT_FILE)).unwrap();
        std::fs::remove_file(dir.path().join(CA_KEY_FILE)).unwrap();

        let err = ensure_ca(dir.path()).err().expect("expected an error");
        assert!(matches!(err, CertsError::StaleLeaf { .. }), "{err}");
    }

    /// The additive path that makes t-of-n and the Pi flow work: a CA
    /// *reloaded from disk* (not the freshly minted issuer) must be able to
    /// issue a new leaf, and `--san` extras must land in it alongside the
    /// defaults. Chain validity under the same root is proven by the real
    /// mTLS handshakes in the sovra-ipc/api tests; here we pin the issuer DN.
    #[test]
    fn reloaded_ca_issues_new_leaves_with_extra_sans() {
        let dir = tempfile::tempdir().unwrap();
        mint(dir.path()); // run 1: fresh CA + cosigner0

        // Run 2: CA comes back via Issuer::from_ca_cert_pem, new party appears.
        let ca = ensure_ca(dir.path()).expect("reload CA");
        let mut sans = default_sans();
        sans.push("192.168.7.42".into());
        let leaf = ensure_leaf(dir.path(), "cosigner2", "sovra-cosigner-2", &sans, &ca)
            .expect("new leaf from reloaded CA");

        let der = parse_der(&std::fs::read_to_string(&leaf.cert).unwrap());
        let (_, cert) = X509Certificate::from_der(&der).expect("x509");
        let issuer_cn = cert
            .issuer()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok());
        assert_eq!(issuer_cn, Some("sovra-ca"));

        let san = cert
            .subject_alternative_name()
            .expect("well-formed SAN")
            .expect("SAN extension present");
        let names = &san.value.general_names;
        assert!(names.contains(&GeneralName::DNSName("localhost")));
        assert!(
            names.contains(&GeneralName::IPAddress(&[192, 168, 7, 42])),
            "{names:?}"
        );
    }

    /// Watch-point: WebPkiClientVerifier demands clientAuth, server
    /// verification demands serverAuth, and every process is both — a
    /// single-EKU leaf fails on exactly one plane with an opaque alert.
    #[test]
    fn leaf_carries_both_ekus_default_sans_and_cn() {
        let dir = tempfile::tempdir().unwrap();
        let (_, leaf) = mint(dir.path());
        let der = parse_der(&std::fs::read_to_string(&leaf.cert).unwrap());
        let (_, cert) = X509Certificate::from_der(&der).expect("x509");

        let eku = cert
            .extended_key_usage()
            .expect("well-formed EKU")
            .expect("EKU extension present");
        assert!(eku.value.server_auth && eku.value.client_auth);

        let san = cert
            .subject_alternative_name()
            .expect("well-formed SAN")
            .expect("SAN extension present");
        let names = &san.value.general_names;
        assert!(names.contains(&GeneralName::DNSName("localhost")));
        assert!(
            names.contains(&GeneralName::IPAddress(&[127, 0, 0, 1])),
            "{names:?}"
        );

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok());
        assert_eq!(cn, Some("sovra-cosigner-0"));
    }
}
