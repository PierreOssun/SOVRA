use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rpc_url: String,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        RawConfig::builder()
            .add_source(File::with_name("config/sepolia").required(true))
            .add_source(
                Environment::with_prefix("SOVRA")
                    .separator("_")
                    .try_parsing(true),
            )
            .build()?
            .try_deserialize()
    }
}
