use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub party_id: u8,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    pub data_dir: String,
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
