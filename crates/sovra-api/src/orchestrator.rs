//! Startup recovery: rebuild the in-memory "active public key" from the
//! cosigners' shard stores, since the orchestrator persists nothing itself.
//!
//! Why probe all n and compare: after a crash mid-DKG the stores can disagree
//! (some shards written, some not). Serving with a half-provisioned key would
//! be unsound, so divergent public keys among *reachable* parties refuse
//! startup with an operator-facing remedy instead of guessing. Unreachable
//! parties are tolerated as long as at least `threshold` answer — the cold
//! recovery party is expected to be offline in normal operation — and a
//! reachable party with an EMPTY store is tolerated when a t-quorum of
//! agreeing shards exists: that is a rebuilt host awaiting its `/v1/recover`
//! ceremony, and refusing to boot would deadlock the recovery runbook.
//! All reachable 404 → fresh install. Pattern: fail-fast startup gate.

use sovra_ipc::remote::fetch_signer;
use sovra_types::PubkeySec1;
use url::Url;

#[derive(thiserror::Error, Debug)]
pub enum RecoverError {
    #[error(
        "reachable shard stores disagree ({reports:?}); \
         partial dkg state — wipe the store dirs and re-run dkg"
    )]
    Inconsistent {
        reports: Vec<(u8, Option<PubkeySec1>)>,
    },
    /// The retryable variant: fewer than `required` cosigners answered.
    #[error("startup recovery needs {required} reachable cosigners, got {reachable}: {detail}")]
    Transport {
        reachable: usize,
        required: usize,
        detail: String,
    },
}

/// Probe every cosigner; require at least `threshold` reachable ("any t", so
/// the system also boots with a preferred party down) and full agreement
/// among those that answered.
pub async fn recover_active(
    http: &reqwest::Client,
    cosigners: &[(u8, Url)],
    threshold: usize,
) -> Result<Option<PubkeySec1>, RecoverError> {
    let probes = cosigners
        .iter()
        .map(|(party, url)| async move { (*party, fetch_signer(http, url).await) });
    let results = futures_util::future::join_all(probes).await;

    let mut reports: Vec<(u8, Option<PubkeySec1>)> = Vec::with_capacity(results.len());
    let mut unreachable: Vec<String> = Vec::new();
    for (party, result) in results {
        match result {
            Ok(public_key) => reports.push((party, public_key)),
            Err(e) => {
                tracing::warn!(
                    party,
                    error = %e,
                    "cosigner unreachable during startup recovery (tolerated — party may be cold)"
                );
                unreachable.push(format!("cosigner{party}: {e}"));
            }
        }
    }
    if reports.len() < threshold {
        return Err(RecoverError::Transport {
            reachable: reports.len(),
            required: threshold,
            detail: unreachable.join("; "),
        });
    }
    // A t-quorum of AGREEING shards is authoritative; a reachable party with
    // an empty store is then "awaiting recovery" (a rebuilt host before its
    // /v1/recover ceremony), not evidence of a torn DKG — refusing to start
    // here would deadlock the recovery runbook. Divergent public keys, or
    // shards without a t-quorum, remain fatal.
    let somes: Vec<(u8, PubkeySec1)> = reports
        .iter()
        .filter_map(|(party, public_key)| public_key.map(|pk| (*party, pk)))
        .collect();
    if somes.is_empty() {
        return Ok(None);
    }
    let consensus = somes[0].1;
    if somes.len() < threshold || somes.iter().any(|(_, pk)| *pk != consensus) {
        return Err(RecoverError::Inconsistent { reports });
    }
    for (party, public_key) in &reports {
        if public_key.is_none() {
            tracing::warn!(
                party,
                "cosigner reachable but has no shard — awaiting recovery (POST /v1/recover)"
            );
        }
    }
    Ok(Some(consensus))
}
