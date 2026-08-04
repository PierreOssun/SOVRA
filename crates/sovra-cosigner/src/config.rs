//! Cosigner configuration: file path passed as `argv[1]` (two processes, two
//! files), overridable per key by `SOVRA_COSIGNER_*` environment variables.
//!
//! Why the `config` crate: same file + env layering as sovra-api, one idiom
//! across both binaries. `party_id` is validated here (must be 0 or 1) so the
//! rest of the crate can index `[T; 2]` arrays positionally without checking.
//! `ttl_secs` (default 60) is the MPC run timeout — kept below the
//! orchestrator's 90s HTTP timeout by convention.
//! Pattern: layered configuration, validated at the edge.

use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub party_id: u8,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    pub data_dir: String,
    /// No default on purpose: a cosigner without a policy file is a blind
    /// signer, so a missing key must fail config load, not fall back.
    pub policy_path: String,
    /// Same rule as `policy_path` for all three TLS keys: a cosigner without
    /// mTLS material is an open signer — refuse to start, no plaintext mode.
    pub tls_ca_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    #[serde(default = "default_relay_url")]
    pub relay_url: String,
    pub peer_verifying_key: Option<String>,
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
}

fn default_bind_addr() -> String {
    "127.0.0.1:4100".into()
}
fn default_relay_url() -> String {
    "ws://127.0.0.1:3100/ws".into()
}
fn default_ttl_secs() -> u64 {
    60
}

impl Config {
    /// Unlike sovra-api's fixed `config/sepolia`, the file is a parameter —
    /// two cosigner processes need two configs.
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let cfg: Self = RawConfig::builder()
            .add_source(File::with_name(path).required(true))
            .add_source(Environment::with_prefix("SOVRA_COSIGNER").try_parsing(true))
            .build()?
            .try_deserialize()?;
        if cfg.party_id > 1 {
            return Err(ConfigError::Message(format!(
                "party_id must be 0 or 1, got {}",
                cfg.party_id
            )));
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    fn write_config(dir: &tempfile::TempDir, body: &str) -> String {
        let path = dir.path().join("cosigner.toml");
        std::fs::write(&path, body).unwrap();
        path.to_str().unwrap().to_owned()
    }

    const REQUIRED_SANS_TLS: &str = concat!(
        "party_id = 0\n",
        "data_dir = \"data\"\n",
        "policy_path = \"policy.toml\"\n",
    );

    /// Startup mirror of the policy rule: a config without TLS material must
    /// not load — there is no plaintext mode to fall back to.
    #[test]
    fn missing_tls_keys_refuse_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(&dir, REQUIRED_SANS_TLS);
        assert!(super::Config::load(&path).is_err());
    }

    #[test]
    fn full_config_loads_and_defaults_apply() {
        let dir = tempfile::tempdir().unwrap();
        let body = format!(
            "{REQUIRED_SANS_TLS}tls_ca_path = \"ca.pem\"\ntls_cert_path = \"c.pem\"\ntls_key_path = \"k.pem\"\n"
        );
        let cfg = super::Config::load(&write_config(&dir, &body)).unwrap();
        assert_eq!(cfg.bind_addr, "127.0.0.1:4100"); // serde default applied
        assert_eq!(cfg.ttl_secs, 60);
    }
}
