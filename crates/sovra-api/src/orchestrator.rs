//! Orchestration glue between the HTTP layer and the MPC/persistence seams:
//! splits a DKG result across the two per-party stores and recovers the
//! active generation from disk at startup.

use alloy_primitives::Address;
use sovra_mpc::MpcBackend;
use sovra_mpc_dkls23_silence::SilenceBackend;
use sovra_state::{SignerStore, StateError};
use sovra_types::{KeyShare, SignerId, SignerMetadata};

use crate::errors::ApiError;

/// The single active generation's signer id. The PoC has no rotation:
/// one DKG per store lifetime, always stored under this id.
pub const ACTIVE_SIGNER_ID: &str = "default";

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
    #[error(transparent)]
    State(#[from] StateError),
    #[error(
        "store has metadata for {address} but no shard; partial dkg persistence — \
     wipe both store dirs and re-run dkg"
    )]
    PartialStore { address: Address },
}

/// Recover the active generation from disk at startup.
///
/// Both stores empty → no generation. Both stores holding the same address
/// → that generation. Anything else is partial/corrupt DKG persistence and
/// refuses to start.
pub fn recover_active(stores: &[SignerStore; 2]) -> Result<Option<Address>, RecoverError> {
    let id = SignerId::new(ACTIVE_SIGNER_ID);
    let party0 = load_address(&stores[0], &id)?;
    let party1 = load_address(&stores[1], &id)?;

    match (party0, party1) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) if a == b => Ok(Some(a)),
        (party0, party1) => Err(RecoverError::Inconsistent { party0, party1 }),
    }
}

/// Run the 2-of-2 DKG and persist one shard per party store.
///
/// Caller must hold the global op lock.
pub async fn run_dkg(
    backend: &SilenceBackend,
    stores: &[SignerStore; 2],
) -> Result<Address, ApiError> {
    let dkg = backend.dkg().await?;

    let [share0, share1] = dkg.shares.as_slice() else {
        return Err(ApiError::Mpc(sovra_mpc::MpcError::Dkg(format!(
            "expected 2 shares, got {}",
            dkg.shares.len()
        ))));
    };

    let meta = SignerMetadata {
        signer_id: SignerId::new(ACTIVE_SIGNER_ID),
        address: dkg.address,
    };

    stores[0].save_shard(&meta, share0)?;
    stores[1].save_shard(&meta, share1)?;

    Ok(dkg.address)
}

/// Load both parties' shards for the active signer, ordered by party id
/// (index 0 = party 0) — the order `MpcBackend::sign` expects.
pub fn load_shards(stores: &[SignerStore; 2]) -> Result<Vec<KeyShare>, StateError> {
    let id = SignerId::new(ACTIVE_SIGNER_ID);
    Ok(vec![stores[0].load_shard(&id)?, stores[1].load_shard(&id)?])
}

fn load_address(store: &SignerStore, id: &SignerId) -> Result<Option<Address>, RecoverError> {
    let meta = match store.load_metadata(id) {
        Ok(meta) => meta,
        Err(StateError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    // Metadata alone is not a generation: save_shard writes metadata before
    // the shard, so a crash between the two leaves exactly this half-state.
    match store.load_shard(id) {
        Ok(_) => Ok(Some(meta.address)),
        Err(StateError::NotFound(_)) => Err(RecoverError::PartialStore {
            address: meta.address,
        }),
        Err(e) => Err(e.into()),
    }
}
