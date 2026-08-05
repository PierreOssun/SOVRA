//! Cosigner configuration: file path passed as `argv[1]` (one process per
//! party, one file each), overridable per key by `SOVRA_COSIGNER_*`
//! environment variables.
//!
//! Why the `config` crate: same file + env layering as sovra-api, one idiom
//! across both binaries. `participants` is the full ordered ed25519 roster
//! (hex verifying keys, index = global party id, **including this party's
//! own**) — validated here together with `party_id`/`threshold` so the rest
//! of the crate can index it positionally without checking. `ttl_secs`
//! (default 60) is the MPC run timeout — kept below the orchestrator's 90s
//! HTTP timeout by convention.
//! Pattern: layered configuration, validated at the edge.

use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub party_id: u8,
    /// t in t-of-n; n is the length of `participants`.
    #[serde(default = "default_threshold")]
    pub threshold: u8,
    /// Full roster of hex ed25519 verifying keys, index = party id, own key
    /// included. `None` = bootstrap mode: the process serves `/identity` so
    /// operators can collect the keys, but dkg/sign 409 until it is set.
    /// Env override: `SOVRA_COSIGNER_PARTICIPANTS=hex0,hex1,hex2`.
    pub participants: Option<Vec<String>>,
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
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
}

fn default_bind_addr() -> String {
    "127.0.0.1:4100".into()
}
fn default_relay_url() -> String {
    "wss://127.0.0.1:3100/ws".into()
}
fn default_ttl_secs() -> u64 {
    60
}
fn default_threshold() -> u8 {
    2
}

impl Config {
    /// Unlike sovra-api's fixed `config/sepolia`, the file is a parameter —
    /// each cosigner process needs its own config.
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let cfg: Self = RawConfig::builder()
            .add_source(File::with_name(path).required(true))
            .add_source(
                Environment::with_prefix("SOVRA_COSIGNER")
                    .try_parsing(true)
                    .list_separator(",")
                    .with_list_parse_key("participants"),
            )
            .build()?
            .try_deserialize()?;
        if let Some(participants) = &cfg.participants {
            let n = participants.len();
            if n < 2 {
                return Err(ConfigError::Message(format!(
                    "participants must list at least 2 parties, got {n}"
                )));
            }
            if cfg.party_id as usize >= n {
                return Err(ConfigError::Message(format!(
                    "party_id {} out of range for {n} participants",
                    cfg.party_id
                )));
            }
            if !(2..=n).contains(&(cfg.threshold as usize)) {
                return Err(ConfigError::Message(format!(
                    "threshold {} out of bounds for {n} participants",
                    cfg.threshold
                )));
            }
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

    const TLS: &str = concat!(
        "tls_ca_path = \"ca.pem\"\n",
        "tls_cert_path = \"c.pem\"\n",
        "tls_key_path = \"k.pem\"\n",
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
        let body = format!("{REQUIRED_SANS_TLS}{TLS}");
        let cfg = super::Config::load(&write_config(&dir, &body)).unwrap();
        assert_eq!(cfg.bind_addr, "127.0.0.1:4100"); // serde default applied
        assert_eq!(cfg.ttl_secs, 60);
        assert_eq!(cfg.threshold, 2); // t-of-n default
        assert!(cfg.participants.is_none()); // bootstrap mode is legal
    }

    /// The roster invariants are validated at load: party_id must index into
    /// the list, and the threshold must fit 2..=n.
    #[test]
    fn roster_bounds_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let roster3 = "participants = [\"aa\", \"bb\", \"cc\"]\n";

        let body = format!("party_id = 3\ndata_dir = \"d\"\npolicy_path = \"p\"\n{TLS}{roster3}");
        assert!(super::Config::load(&write_config(&dir, &body)).is_err()); // id 3 of n=3

        let body = format!("{REQUIRED_SANS_TLS}{TLS}{roster3}threshold = 4\n");
        assert!(super::Config::load(&write_config(&dir, &body)).is_err()); // t > n

        let body = format!("{REQUIRED_SANS_TLS}{TLS}participants = [\"aa\"]\n");
        assert!(super::Config::load(&write_config(&dir, &body)).is_err()); // n < 2

        let body = format!("{REQUIRED_SANS_TLS}{TLS}{roster3}");
        let cfg = super::Config::load(&write_config(&dir, &body)).unwrap();
        assert_eq!(cfg.participants.unwrap().len(), 3); // 2-of-3 loads
    }
}
