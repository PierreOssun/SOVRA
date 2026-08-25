//! Orchestrator configuration: a TOML file (path from `SOVRA_CONFIG`,
//! default `config/sepolia`), overridable per key by `SOVRA_*` environment
//! variables (e.g. `SOVRA_BIND_ADDR`) — so a container can run on `.env`
//! alone, with no config file mounted.
//!
//! Why the `config` crate: file + env layering with serde deserialization in
//! a few lines, instead of hand-rolling precedence. Defaults live in serde
//! `#[serde(default)]` attributes so the file only needs to state what
//! deviates. The cosigner list is the one key the crate's env source cannot
//! express (a table array), so it gets its own hand-parsed variable —
//! `SOVRA_COSIGNER_URLS`, deliberately NOT `SOVRA_COSIGNERS`, which the env
//! source would map onto the `cosigners` key and fail to deserialize.
//! Pattern: layered (12-factor-style) configuration.

use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

/// One cosigner endpoint. The list's order is the signing preference order —
/// the cold recovery party goes last so it is only selected when a preferred
/// party is down.
#[derive(Debug, Clone, Deserialize)]
pub struct CosignerEntry {
    pub party_id: u8,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rpc_url: String,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// From the file's `[[cosigners]]`, or `SOVRA_COSIGNER_URLS` (which wins;
    /// format `<party_id>=<url>,...`, order = preference). One of the two
    /// must be present.
    #[serde(default)]
    pub cosigners: Vec<CosignerEntry>,
    /// t in t-of-n; n is the length of `cosigners`.
    #[serde(default = "default_threshold")]
    pub threshold: u8,
    #[serde(default = "default_relay_bind")]
    pub relay_bind: String,
    /// No defaults on purpose (mirrors the cosigner's rule): the control
    /// plane is mTLS-only, so missing material must fail startup, not fall
    /// back to plaintext.
    pub tls_ca_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
}
fn default_bind_addr() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_relay_bind() -> String {
    "127.0.0.1:3100".into()
}

fn default_threshold() -> u8 {
    2
}

impl Config {
    /// Deserialization only — the cosigner-set invariants (unique party ids,
    /// threshold bounds, https) are enforced in `RemoteBackend::new`, the
    /// seam that owns them; `run()` constructs it before anything slow, so a
    /// bad set still fails startup immediately.
    pub fn load() -> Result<Self, ConfigError> {
        // An explicitly requested file must exist; the default path is
        // best-effort so an env-only container needs no file at all (missing
        // required keys then fail with their own named errors).
        let (path, explicit) = match std::env::var("SOVRA_CONFIG") {
            Ok(p) => (p, true),
            Err(_) => ("config/sepolia".to_string(), false),
        };
        let mut config: Config = RawConfig::builder()
            .add_source(File::with_name(&path).required(explicit))
            .add_source(
                Environment::with_prefix("SOVRA")
                    .ignore_empty(true)
                    .try_parsing(true),
            )
            .build()?
            .try_deserialize()?;

        // Empty-as-unset, matching the layered source's ignore_empty: an
        // unfilled `.env` line must not shadow the file. (Nested if, not a
        // let-chain: those need 1.88 and the workspace pledges MSRV 1.85.)
        #[allow(clippy::collapsible_if)]
        if let Ok(urls) = std::env::var("SOVRA_COSIGNER_URLS") {
            if !urls.trim().is_empty() {
                config.cosigners = parse_cosigner_urls(&urls).map_err(ConfigError::Message)?;
            }
        }
        if config.cosigners.is_empty() {
            return Err(ConfigError::Message(
                "no cosigners configured: set [[cosigners]] in the config file \
                 or SOVRA_COSIGNER_URLS=<party_id>=<url>,..."
                    .into(),
            ));
        }
        Ok(config)
    }
}

/// `0=https://100.1.2.3:4100,1=https://100.1.2.4:4101` → entries in the
/// given order (= signing preference, exactly like the file's table order).
fn parse_cosigner_urls(s: &str) -> Result<Vec<CosignerEntry>, String> {
    s.split(',')
        .map(|pair| {
            let pair = pair.trim();
            let (id, url) = pair
                .split_once('=')
                .ok_or_else(|| format!("`{pair}`: expected <party_id>=<url>"))?;
            Ok(CosignerEntry {
                party_id: id
                    .trim()
                    .parse()
                    .map_err(|e| format!("`{pair}`: bad party id: {e}"))?,
                url: url.trim().to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosigner_urls_parse_in_preference_order() {
        let entries =
            parse_cosigner_urls("1=https://b:4101, 0=https://a:4100 ,2=https://c:4102").unwrap();
        let seen: Vec<(u8, &str)> = entries
            .iter()
            .map(|e| (e.party_id, e.url.as_str()))
            .collect();
        assert_eq!(
            seen,
            vec![
                (1, "https://b:4101"),
                (0, "https://a:4100"),
                (2, "https://c:4102"),
            ]
        );
    }

    #[test]
    fn cosigner_urls_reject_malformed_pairs() {
        for bad in ["https://a:4100", "x=https://a:4100", "0", ""] {
            let err = parse_cosigner_urls(bad).unwrap_err();
            assert!(err.starts_with('`'), "named the offending pair: {err}");
        }
    }
}
