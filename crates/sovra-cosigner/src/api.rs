//! Control-plane handlers: `/dkg` and `/sign` run this party's half of an MPC
//! protocol; `/signer` is the recovery probe; `/identity` and `/health` serve
//! operator setup and liveness.
//!
//! The shape both MPC handlers share is deliberate: `try_lock` the op mutex
//! (busy = 409, never queue) → check shard preconditions → build the
//! `PartyContext` → dial the hub fresh (`WsEnvelopeRelay::connect`, one connection per
//! run, dropped at the end — no reconnect state to manage) → drive the party
//! runner under `tokio::time::timeout(ttl)`. The timeout is what frees the op
//! lock when the peer never joins; without it one dead peer would wedge this
//! cosigner forever (a bug the split_flow gate test caught).
//! `/sign` receives the unsigned tx *preimage*, never a digest: it decodes
//! and validates the bytes and derives the signing hash itself, so this
//! party can only ever sign well-formed transactions of a supported type
//! (legacy/EIP-2930/EIP-1559) it inspected.
//! Pattern: thin controllers delegating to the active `PartyRunner`
//! backend (the [`crate::backend`] alias — the whole backend swap is that
//! one line); wire types come from `sovra_ipc::control`.

use std::sync::Arc;

use alloy_primitives::B256;
use axum::{Json, extract::State};
use sovra_eth::Ethereum;
use sovra_ipc::control::{
    Identity, PublicKeyInfo, RosterInfo, SignaturesInfo, StartDkgRequest, StartRefreshRequest,
    StartSignRequest,
};
use sovra_mpc::{PartyRunner, sub_instance};
use sovra_network::Network;
use sovra_policy::{Policy, Verdict};
use sovra_state::StateError;
use sovra_types::{ACTIVE_SIGNER_ID, NetworkId, SignerId, SignerMetadata};

use crate::{backend::ActiveRunner, errors::CosignerError, state::CosignerState};

pub async fn dkg(
    State(state): State<Arc<CosignerState>>,
    Json(req): Json<StartDkgRequest>,
) -> Result<Json<PublicKeyInfo>, CosignerError> {
    let _op = state.op.try_lock().map_err(|_| CosignerError::Busy)?;
    let id = SignerId::new(ACTIVE_SIGNER_ID);
    match state.store.load_metadata(&id) {
        Ok(_) => return Err(CosignerError::ShardExists),
        Err(StateError::NotFound(_)) => {}
        Err(e) => return Err(e.into()),
    }
    let ctx = state.ctx(req.instance)?;
    assert_scheme(&state, ctx.party_vks.len(), req.n_parties, req.threshold)?;
    // dial per run, 502 on refusal
    let mut relay = state.dial(req.instance).await?;
    let (share, public_key) =
        tokio::time::timeout(state.ttl, ActiveRunner::default().keygen(&ctx, &mut relay))
            .await
            .map_err(|_| CosignerError::RunTimeout)??;
    state.store.save_shard(
        &SignerMetadata {
            signer_id: id,
            public_key,
        },
        &share,
    )?;
    Ok(Json(PublicKeyInfo { public_key }))
}

pub async fn sign(
    State(state): State<Arc<CosignerState>>,
    Json(req): Json<StartSignRequest>,
) -> Result<Json<SignaturesInfo>, CosignerError> {
    let _op = state.op.try_lock().map_err(|_| CosignerError::Busy)?;
    // Subset validation precedes vetting on purpose: a subset that is
    // malformed or excludes this party is an orchestrator bug, not a signing
    // decision — the policy log must not record a verdict for a request this
    // party was never actually part of.
    let n = state
        .roster
        .as_ref()
        .ok_or(CosignerError::RosterUnset)?
        .len();
    let subset = &req.participants;
    if subset.len() != state.threshold as usize
        || !subset.windows(2).all(|w| w[0] < w[1])
        || subset.iter().any(|&p| p as usize >= n)
    {
        return Err(CosignerError::InvalidSubset(format!(
            "{subset:?} is not {} strictly ascending party ids < {n}",
            state.threshold
        )));
    }
    if !subset.contains(&state.party_id) {
        return Err(CosignerError::InvalidSubset(format!(
            "party {} is not in {subset:?}",
            state.party_id
        )));
    }
    // The wire tag selects the decoder; each decoder is strict, so a tag
    // that mismatches the bytes fails closed right here.
    let digests = match req.network {
        NetworkId::Ethereum => vet::<Ethereum>(&state.policy, &req.unsigned_transaction)?,
    };
    let share = match state.store.load_shard(&SignerId::new(ACTIVE_SIGNER_ID)) {
        Ok(s) => s,
        Err(StateError::NotFound(_)) => return Err(CosignerError::NoShard),
        Err(e) => return Err(e.into()),
    };
    // One MPC run per digest, sequentially, each on its own derived instance
    // (identical at every party) and fresh relay connection, each under its
    // own ttl — one stalled run must not eat the whole batch's budget.
    let mut signatures = Vec::with_capacity(digests.len());
    for (index, digest) in digests.iter().enumerate() {
        let run_instance = sub_instance(req.instance, index as u32);
        let ctx = state.ctx(run_instance)?;
        let mut relay = state.dial(run_instance).await?;
        let parts = tokio::time::timeout(
            state.ttl,
            ActiveRunner::default().sign(&ctx, &share, (*digest).into(), subset, &mut relay),
        )
        .await
        .map_err(|_| CosignerError::RunTimeout)??;
        signatures.push(parts.into());
    }
    Ok(Json(SignaturesInfo { signatures }))
}

/// Parse, don't trust: everything this party signs is derived here, from
/// bytes it decoded and validated itself — before any MPC message. Policy
/// runs before the shard is even loaded: on deny nothing was dialed, there
/// is no session to clean up, and the op lock frees on return. The verdict
/// logs (allow AND deny, digest + correlation id via the request span) are
/// the future signature-receipt data source.
fn vet<N: Network>(policy: &Policy, bytes: &[u8]) -> Result<Vec<[u8; 32]>, CosignerError> {
    let tx = N::decode_unsigned(bytes).map_err(|e| CosignerError::Undecodable(e.to_string()))?;
    N::validate(&tx).map_err(|e| CosignerError::Undecodable(e.to_string()))?;
    let digests = N::signing_digests(&tx);
    if let Verdict::Deny(reason) = policy.evaluate(&N::policy_view(&tx)) {
        tracing::warn!(tx_digest = %B256::from(digests[0]), %reason, "policy denied");
        return Err(CosignerError::PolicyDenied(reason));
    }
    tracing::info!(tx_digest = %B256::from(digests[0]), "policy allowed");
    Ok(digests)
}

/// DKG pre-flight probe: what scheme this party believes it is in, with the
/// roster committed to as a hash — never the keys themselves.
pub async fn roster(
    State(state): State<Arc<CosignerState>>,
) -> Result<Json<RosterInfo>, CosignerError> {
    Ok(Json(state.roster_info()?))
}

/// The wallet's compressed public key, derived from this party's shard —
/// what a recovery ceremony's lost party adopts as its reconstruction
/// target. Public data (recoverable from any on-chain signature).
pub async fn pubkey(
    State(state): State<Arc<CosignerState>>,
) -> Result<Json<PublicKeyInfo>, CosignerError> {
    let share = match state.store.load_shard(&SignerId::new(ACTIVE_SIGNER_ID)) {
        Ok(s) => s,
        Err(StateError::NotFound(_)) => return Err(CosignerError::NoSigner),
        Err(e) => return Err(e.into()),
    };
    Ok(Json(PublicKeyInfo {
        public_key: ActiveRunner::default().public_key_of(&share)?,
    }))
}

/// The (n, t) assertions shared by `/dkg` and `/refresh`: request fields are
/// never protocol inputs — the ceremony setup is always built from this
/// party's own config, and divergence is a 409 so a misconfigured fleet
/// fails as config instead of an opaque MPC timeout.
fn assert_scheme(
    state: &CosignerState,
    n: usize,
    req_n: u8,
    req_t: u8,
) -> Result<(), CosignerError> {
    if req_n as usize != n || req_t != state.threshold {
        return Err(CosignerError::RosterMismatch(format!(
            "orchestrator expects {req_t}-of-{req_n}, this party is configured {}-of-{n}",
            state.threshold
        )));
    }
    Ok(())
}

/// All-parties proactive re-randomize: same shape as `dkg` (op lock →
/// scheme assertions → dial → run under the ttl), and every party must hold
/// a shard — a missing one is the operator's cue that this host needs the
/// recovery flow (degraded signing + fresh DKG), not a refresh. `save_shard`
/// overwrites atomically: the old generation is dead the moment the
/// ceremony completes.
pub async fn refresh(
    State(state): State<Arc<CosignerState>>,
    Json(req): Json<StartRefreshRequest>,
) -> Result<Json<PublicKeyInfo>, CosignerError> {
    let _op = state.op.try_lock().map_err(|_| CosignerError::Busy)?;
    let ctx = state.ctx(req.instance)?;
    let n = ctx.party_vks.len();
    assert_scheme(&state, n, req.n_parties, req.threshold)?;
    let id = SignerId::new(ACTIVE_SIGNER_ID);
    let old_share = match state.store.load_shard(&id) {
        Ok(s) => s,
        Err(StateError::NotFound(_)) => return Err(CosignerError::NoShard),
        Err(e) => return Err(e.into()),
    };

    let mut relay = state.dial(req.instance).await?;
    let (share, public_key) = tokio::time::timeout(
        state.ttl,
        ActiveRunner::default().refresh(&ctx, &old_share, &req.public_key, &mut relay),
    )
    .await
    .map_err(|_| CosignerError::RunTimeout)??;
    state.store.save_shard(
        &SignerMetadata {
            signer_id: id,
            public_key,
        },
        &share,
    )?;
    Ok(Json(PublicKeyInfo { public_key }))
}

pub async fn signer(
    State(state): State<Arc<CosignerState>>,
) -> Result<Json<PublicKeyInfo>, CosignerError> {
    match state.store.load_active(&SignerId::new(ACTIVE_SIGNER_ID)) {
        Ok(Some(public_key)) => Ok(Json(PublicKeyInfo { public_key })),
        Ok(None) => Err(CosignerError::NoSigner),
        Err(e) => Err(e.into()),
    }
}

pub async fn identity(State(state): State<Arc<CosignerState>>) -> Json<Identity> {
    Json(Identity {
        verifying_key: alloy_primitives::hex::encode(state.signing_key.verifying_key().as_bytes()),
    })
}

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
