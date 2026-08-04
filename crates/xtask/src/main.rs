//! xtask — one-command local launcher (the cargo-xtask pattern). `cargo xtask up`
//! seeds each cosigner's identity and the TLS material (project CA + one leaf
//! per process) on first run (loads them after), spawns the orchestrator + two
//! cosigners wired together in a 3-pane tmux window, then runs the one-time DKG
//! so the system is immediately sign-ready. `cargo xtask down` tears the
//! session down; `cargo xtask certs` provisions the TLS material standalone.
//!
//! Why a Rust crate instead of a shell script: the pairing bootstrap must generate
//! ed25519 identities and pin each peer's verifying key *before* any process starts
//! — a cosigner only mints its key on startup, yet its peer must already know it.
//! xtask reuses the cosigner's own `identity::load_or_generate` and `config::Config`
//! loader, so the on-disk key format and the data/bind locations have exactly one
//! definition each.
//! Pattern: build-tooling as a workspace binary.

use std::{
    error::Error,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use sovra_cosigner::{config::Config as CosignerConfig, identity};

/// tmux session name. Always targeted as `=sovra` (see [`exact`]) — a bare `-t name`
/// is a PREFIX match in tmux, so `-t sovra` would also match e.g. `sovra-notes`.
const SESSION: &str = "sovra";
/// Cosigner config files, relative to the workspace root; index = party id.
const CONFIGS: [&str; 2] = ["config/cosigner0.toml", "config/cosigner1.toml"];
/// Readiness bound per waited-on process. Generous on purpose: a first run
/// compiles three heavy binaries serialized on cargo's build lock, which can
/// take several minutes on a cold target dir.
const READY_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Parser)]
#[command(name = "xtask", about = "Local dev orchestration for SOVRA")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Seed/load storage, spawn the 3-process system in tmux, provision DKG, attach.
    Up,
    /// Kill the tmux session.
    Down,
    /// Run every local CI check in sequence, stopping at the first failure.
    Ci,
    /// Seed-or-load the project CA and one leaf per process under `certs/`.
    /// Re-runs are additive (existing material is never rewritten) — rotation
    /// is `rm certs/<name>.*.pem` then re-running this.
    Certs {
        /// Extra SAN (DNS name or IP) appended to every leaf — the deployment
        /// knob: re-issue a deleted leaf with the target host's address.
        /// Repeatable.
        #[arg(long)]
        san: Vec<String>,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Cmd::Up => up(),
        Cmd::Down => down(),
        Cmd::Ci => ci(),
        Cmd::Certs { san } => certs(&san),
    }
}

fn up() -> Result<(), Box<dyn Error>> {
    require_tmux()?;
    if session_exists() {
        return Err(
            format!("tmux session '{SESSION}' already running — `cargo xtask down` first").into(),
        );
    }
    let root = workspace_root();
    let root_str = root.to_str().ok_or("workspace path is not UTF-8")?;

    // 1. Load the same configs the cosigners will read and seed-or-load each
    //    identity with the cosigner's own load_or_generate — the TOML files and
    //    the cosigner crate stay the single source of truth for paths, ports,
    //    and the on-disk key format. Knowing both verifying keys before any
    //    process starts is what dissolves the pairing chicken-and-egg.
    let mut parties: Vec<(CosignerConfig, String)> = Vec::with_capacity(CONFIGS.len());
    for cfg in load_cosigner_configs(&root)? {
        let key = identity::load_or_generate(&root.join(&cfg.data_dir))?;
        let vk = alloy_primitives::hex::encode(key.verifying_key().as_bytes());
        parties.push((cfg, vk));
    }

    // 1.5 Same pattern for the TLS material: the CA and every leaf must exist
    //     before any process starts (each binary refuses to come up without
    //     its material), and re-runs load rather than regenerate.
    let party_ids: Vec<u8> = parties.iter().map(|(cfg, _)| cfg.party_id).collect();
    seed_certs(&root, &party_ids, &[])?;

    // 2. Lay out the panes: cosigner0 | cosigner1 on top, orchestrator full-width
    //    below. `-c root` anchors every pane's cwd at the workspace root so the
    //    relative config/data paths resolve no matter where xtask was invoked.
    let top_left = new_pane(&[
        "new-session",
        "-d",
        "-s",
        SESSION,
        "-n",
        "system",
        "-c",
        root_str,
    ])?;
    let bottom = new_pane(&["split-window", "-v", "-t", &top_left, "-c", root_str])?;
    let top_right = new_pane(&["split-window", "-h", "-t", &top_left, "-c", root_str])?;

    // 3. Launch the cosigners. `env KEY=VAL cmd` instead of shell `KEY=VAL cmd`:
    //    send-keys types into the user's login shell, and non-POSIX shells (fish)
    //    reject prefix assignments — the `env` program works everywhere.
    let cosigner_panes = [&top_left, &top_right];
    for (i, pane) in cosigner_panes.into_iter().enumerate() {
        let (_, peer_vk) = &parties[1 - i]; // party i pins its PEER's key
        let cmd = format!(
            "env SOVRA_COSIGNER_PEER_VERIFYING_KEY={peer_vk} cargo run -p sovra-cosigner -- {}",
            CONFIGS[i],
        );
        send(pane, &cmd)?;
    }

    // 4. Gate the orchestrator on both cosigners answering /health. sovra-api's
    //    startup recovery hard-exits after ~10s of unreachable cosigners, and
    //    cargo's build lock makes pane start order nondeterministic — send order
    //    guarantees nothing about bind order.
    let client = reqwest::blocking::Client::builder()
        // Above the system's own DKG budget (cosigner ttl 60s, orchestrator HTTP
        // timeout 90s) — reqwest's 30s default would abort an in-budget DKG.
        .timeout(Duration::from_secs(120))
        .build()?;
    for (cfg, _) in &parties {
        wait_for(
            &client,
            &format!("http://{}/health", cfg.bind_addr),
            "cosigner",
        )?;
    }
    send(&bottom, "cargo run -p sovra-api")?;

    // 5. Provision DKG on first run; idempotent thereafter.
    provision_dkg(&client, &api_url())?;

    // 6. Hand the terminal over to the running session.
    Command::new("tmux")
        .args(["attach", "-t", &exact()])
        .status()?;
    Ok(())
}

fn down() -> Result<(), Box<dyn Error>> {
    require_tmux()?;
    if !session_exists() {
        println!("no tmux session '{SESSION}' to kill");
        return Ok(());
    }
    tmux_ok(&["kill-session", "-t", &exact()])?;
    println!("killed tmux session '{SESSION}'");
    Ok(())
}

/// The pre-commit gate: the same commands `.github/workflows/build_check.yml`
/// runs, chained with `&&` semantics — each step runs only if the previous one
/// passed, from the workspace root regardless of the invoking cwd.
/// (The CI-only `cargo build --release` job is omitted: `clippy --all-targets`
/// already compiles the whole workspace with warnings denied.)
fn ci() -> Result<(), Box<dyn Error>> {
    // (binary, args, install hint shown if the binary is missing)
    const STEPS: &[(&str, &[&str], &str)] = &[
        ("cargo", &["fmt", "--all", "--check"], ""),
        (
            "taplo",
            &["fmt", "--check"],
            "cargo install taplo-cli --locked",
        ),
        (
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
            "",
        ),
        ("cargo", &["test", "--workspace"], ""),
        (
            "cargo",
            &["deny", "check"],
            "cargo install cargo-deny --locked",
        ),
    ];

    let root = workspace_root();
    for (bin, args, hint) in STEPS {
        println!("\n=== {bin} {} ===", args.join(" "));
        let status = match Command::new(bin).args(*args).current_dir(&root).status() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !hint.is_empty() => {
                return Err(format!("`{bin}` not found — install it with `{hint}`").into());
            }
            Err(e) => return Err(e.into()),
        };
        if !status.success() {
            return Err(format!("`{bin} {}` failed", args.join(" ")).into());
        }
    }
    println!("\nall CI checks passed — safe to commit");
    Ok(())
}

/// `cargo xtask certs [--san <dns-or-ip>]...` — standalone provisioning for
/// hand-run binaries and the deployment flow (mint a leaf whose SANs include
/// the target host, then ship it with the CA *cert* — never `ca.key.pem`).
fn certs(extra_sans: &[String]) -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let party_ids: Vec<u8> = load_cosigner_configs(&root)?
        .iter()
        .map(|cfg| cfg.party_id)
        .collect();
    seed_certs(&root, &party_ids, extra_sans)?;
    println!("certs ready under {}", root.join("certs").display());
    Ok(())
}

/// Load every entry of [`CONFIGS`] with the cosigner's own loader — ids,
/// ports, and data dirs keep exactly one definition (the TOML files).
fn load_cosigner_configs(root: &Path) -> Result<Vec<CosignerConfig>, Box<dyn Error>> {
    CONFIGS
        .iter()
        .map(|config| -> Result<CosignerConfig, Box<dyn Error>> {
            let path = root.join(config);
            Ok(CosignerConfig::load(
                path.to_str().ok_or("config path is not UTF-8")?,
            )?)
        })
        .collect()
}

/// One CA + one leaf per process. The leaf set is derived from the config list
/// plus the orchestrator, so adding a party is a config file + a re-run, and
/// nothing here knows the number "2". CN carries the identity a later
/// role-binding check will read; the file stem is only the on-disk name.
fn seed_certs(root: &Path, party_ids: &[u8], extra_sans: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = root.join("certs");
    let ca = sovra_certs::ensure_ca(&dir)?;
    let mut sans = sovra_certs::default_sans();
    sans.extend_from_slice(extra_sans);
    sovra_certs::ensure_leaf(&dir, "orchestrator", "sovra-orchestrator", &sans, &ca)?;
    for id in party_ids {
        sovra_certs::ensure_leaf(
            &dir,
            &format!("cosigner{id}"),
            &format!("sovra-cosigner-{id}"),
            &sans,
            &ca,
        )?;
    }
    Ok(())
}

/// Wait for the orchestrator to come up, then run the one-time DKG if it hasn't
/// happened yet — so `up` leaves a system that can sign immediately.
/// `GET /v1/dkg` is 404 before DKG and 200 after; `POST /v1/dkg` returns the
/// derived address, or 409 if a shard already exists.
fn provision_dkg(client: &reqwest::blocking::Client, api_url: &str) -> Result<(), Box<dyn Error>> {
    let dkg_url = format!("{api_url}/v1/dkg");
    let probe = wait_for(client, &dkg_url, "orchestrator")?;

    if probe.status().is_success() {
        println!("DKG already provisioned: {}", address_of(probe)?);
        return Ok(());
    }

    println!("running one-time DKG...");
    let post = client.post(&dkg_url).send()?;
    match post.status() {
        s if s.is_success() => println!("DKG complete: {}", address_of(post)?),
        reqwest::StatusCode::CONFLICT => println!("DKG already provisioned (409)"),
        s => {
            return Err(format!(
                "POST /v1/dkg failed: {s} {}",
                post.text().unwrap_or_default()
            )
            .into());
        }
    }
    Ok(())
}

/// Poll `url` until it answers with any HTTP status, tolerating the transport
/// errors thrown while `cargo run` is still compiling/binding. Bounded by
/// [`READY_TIMEOUT`]; prints one line up front so the wait is legible.
fn wait_for(
    client: &reqwest::blocking::Client,
    url: &str,
    what: &str,
) -> Result<reqwest::blocking::Response, Box<dyn Error>> {
    println!("waiting for {what} at {url} (a cold build can take minutes)...");
    let start = Instant::now();
    loop {
        match client.get(url).send() {
            Ok(resp) => return Ok(resp),
            Err(_) if start.elapsed() < READY_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(500))
            }
            Err(e) => return Err(format!("{what} never came up at {url}: {e}").into()),
        }
    }
}

/// Pull `address` out of a `/v1/dkg` JSON body (`{ "address": "0x.." }`),
/// falling back to the raw body so an unexpected shape still surfaces something.
fn address_of(resp: reqwest::blocking::Response) -> Result<String, Box<dyn Error>> {
    let body = resp.text()?;
    let addr = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("address").and_then(|a| a.as_str()).map(str::to_owned))
        .unwrap_or(body);
    Ok(addr)
}

/// Mirror sovra-api's bind config (`SOVRA_BIND_ADDR`, same default) so xtask polls
/// wherever the orchestrator it spawned will actually listen.
fn api_url() -> String {
    let bind = std::env::var("SOVRA_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    format!("http://{bind}")
}

/// xtask's manifest dir is `crates/xtask`; the workspace root is two levels up.
/// Anchoring on this (not the cwd — `cargo run` keeps the invoker's cwd) lets
/// `cargo xtask up` work from any subdirectory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/xtask sits two levels below the workspace root")
        .to_path_buf()
}

/// Exact-match tmux target: `=name` — bare names are prefix matches.
fn exact() -> String {
    format!("={SESSION}")
}

/// Run a pane-creating tmux command with `-P -F '#{pane_id}'` and return the new
/// pane's stable id (`%N`) — a handle that survives later splits, unlike indices.
fn new_pane(args: &[&str]) -> Result<String, Box<dyn Error>> {
    let mut full = args.to_vec();
    full.extend_from_slice(&["-P", "-F", "#{pane_id}"]);
    let out = Command::new("tmux").args(&full).output()?;
    if !out.status.success() {
        return Err(format!(
            "`tmux {}` failed: {}",
            full.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn send(target: &str, cmd: &str) -> Result<(), Box<dyn Error>> {
    tmux_ok(&["send-keys", "-t", target, cmd, "C-m"])
}

fn tmux_ok(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new("tmux").args(args).status()?;
    if !status.success() {
        return Err(format!("`tmux {}` failed", args.join(" ")).into());
    }
    Ok(())
}

/// Fail early with a clear message if tmux is missing, instead of letting a raw
/// `Os { code: 2, NotFound }` leak out of the first `Command::new("tmux")`.
fn require_tmux() -> Result<(), Box<dyn Error>> {
    match Command::new("tmux").arg("-V").output() {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("tmux not found on PATH — install it (e.g. `brew install tmux`) and retry".into())
        }
        Err(e) => Err(e.into()),
    }
}

fn session_exists() -> bool {
    Command::new("tmux")
        .args(["has-session", "-t", &exact()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
