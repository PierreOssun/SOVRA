//! Startup recovery: rebuild the in-memory "active address" from the
//! cosigners' shard stores, since the orchestrator persists nothing itself.
//!
//! Why probe all n and compare: after a crash mid-DKG the stores can disagree
//! (some shards written, some not). Serving with a half-provisioned key would
//! be unsound, so disagreement among *reachable* parties refuses startup with
//! an operator-facing remedy instead of guessing. Unreachable parties are
//! tolerated as long as at least `threshold` answer — the cold recovery
//! party is expected to be offline in normal operation. All reachable 404 →
//! fresh install; all agree → recovered. Pattern: fail-fast startup gate.

use alloy_primitives::Address;
use sovra_ipc::remote::fetch_signer;
use url::Url;

#[derive(thiserror::Error, Debug)]
pub enum RecoverError {
    #[error(
        "reachable shard stores disagree ({reports:?}); \
         partial dkg state — wipe the store dirs and re-run dkg"
    )]
    Inconsistent { reports: Vec<(u8, Option<Address>)> },
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
) -> Result<Option<Address>, RecoverError> {
    let probes = cosigners
        .iter()
        .map(|(party, url)| async move { (*party, fetch_signer(http, url).await) });
    let results = futures_util::future::join_all(probes).await;

    let mut reports: Vec<(u8, Option<Address>)> = Vec::with_capacity(results.len());
    let mut unreachable: Vec<String> = Vec::new();
    for (party, result) in results {
        match result {
            Ok(address) => reports.push((party, address)),
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
    let consensus = reports[0].1;
    if reports.iter().any(|(_, address)| *address != consensus) {
        return Err(RecoverError::Inconsistent { reports });
    }
    Ok(consensus)
}
