//! Operator CLI mirroring the `sovra-api` orchestrator endpoints (M3).
//!
//! One subcommand per endpoint — `dkg`, `prepare`, `sign` — each a thin HTTP
//! call that pretty-prints the JSON response. It holds no key material and no
//! state: all crypto and persistence happen server-side; this exists so the
//! whole vertical slice (provision once, sign later) can be driven end-to-end
//! from a shell without hand-writing curl bodies.
//!
//! Composable by design: stdout carries only the response JSON (errors go to
//! stderr, non-2xx exits 1), so `prepare | jq -r .unsigned_transaction` feeds
//! straight into `sign --tx`.

mod types;

use std::process::ExitCode;

use clap::Parser;
use reqwest::Client;
use serde_json::{Value, json};
use types::*;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let (path, body) = match &cli.command {
        Command::Dkg => ("/v1/dkg", None),
        Command::Prepare { to, value, data } => (
            "/v1/prepare",
            Some(json!({ "to": to, "value": value, "data": data })),
        ),
        Command::Sign { tx } => ("/v1/sign", Some(json!({ "unsigned_transaction": tx }))),
    };
    // all three are POST, so Method can drop out entirely

    let base = cli.api_url.trim_end_matches('/');
    let mut req = Client::new().post(format!("{base}{path}"));
    if let Some(body) = &body {
        req = req.json(body);
    }
    let response = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            // reqwest's Display hides the cause; walk the source chain
            let mut msg = err.to_string();
            let mut source = std::error::Error::source(&err);
            while let Some(cause) = source {
                msg.push_str(&format!(": {cause}"));
                source = cause.source();
            }
            eprintln!("request failed: {msg}");
            return ExitCode::FAILURE;
        }
    };

    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    // round-trip through Value: valid JSON gets pretty-printed, anything else passes through
    let pretty = serde_json::from_str::<Value>(&text)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or(text);

    if status.is_success() {
        println!("{pretty}");
        ExitCode::SUCCESS
    } else {
        eprintln!("{status}\n{pretty}");
        ExitCode::FAILURE
    }
}
