use alloy_primitives::Address;
use sovra_ipc::remote::fetch_signer;
use url::Url;

#[derive(thiserror::Error, Debug)]
pub enum RecoverError {
    #[error(
        "shard stores disagree (party0: {party0:?}, party1: {party1:?}); \
         partial dkg state — wipe both store dirs and re-run dkg"
    )]
    Inconsistent {
        party0: Option<Address>,
        party1: Option<Address>,
    },
    #[error("cosigner unreachable during startup recovery: {0}")]
    Transport(String),
}

/// remote: both 404 → fresh; same address → active; else refuse to start.
pub async fn recover_active(
    http: &reqwest::Client,
    cosigners: &[Url; 2],
) -> Result<Option<Address>, RecoverError> {
    let (a0, a1) = tokio::join!(
        fetch_signer(http, &cosigners[0]),
        fetch_signer(http, &cosigners[1])
    );
    let (party0, party1) = (
        a0.map_err(|e| RecoverError::Transport(e.to_string()))?,
        a1.map_err(|e| RecoverError::Transport(e.to_string()))?,
    );
    match (party0, party1) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) if a == b => Ok(Some(a)),
        (party0, party1) => Err(RecoverError::Inconsistent { party0, party1 }),
    }
}
