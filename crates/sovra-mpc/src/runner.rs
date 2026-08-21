//! The per-party seam: [`PartyContext`] (moved here from the silence backend
//! so every backend shares it), [`EnvelopeRelay`] (the transport a runner is
//! driven over), and [`PartyRunner`] (the operations one cosigner performs).
//!
//! [`MpcBackend`](crate::MpcBackend) is the *orchestrator's* port; this is
//! the *cosigner's*. Formalizing it as a trait — the silence backend exposed
//! free functions whose signatures leaked `sl_mpc_mate::coord::Relay` — is
//! what makes the backend swappable behind one type alias. Same RPITIT +
//! `Send` style as `MpcBackend`, and likewise not dyn-safe: callers are
//! generic or name a concrete runner. Pattern: hexagonal port.

use std::time::Duration;

use alloy_primitives::B256;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sovra_types::{KeyShare, PubkeySec1};

use crate::{EcdsaParts, MpcError, envelope::SignedEnvelope};

/// Everything one party needs to join a protocol run: its global id, the
/// shared instance id, its ed25519 identity, the full roster of pinned
/// verifying keys (positional by party id — order is a protocol invariant),
/// the scheme threshold, and the run TTL. Bundled as one struct so runner
/// signatures don't take seven loose parameters and callers can't mix
/// arguments from different runs. Pattern: parameter object.
#[derive(Clone)]
pub struct PartyContext {
    pub party_id: u8,            // global id, 0..n-1 — also the index into party_vks
    pub instance: B256,          // shared 32-byte run id, minted by orchestrator
    pub signing_key: SigningKey, // this party's secret identity (SigningKey: Clone)
    pub party_vks: Vec<VerifyingKey>, // full roster, ordered by party id; n = len()
    pub threshold: u8,           // t in t-of-n
    pub ttl: Duration,
}

/// One party's connection to the relay plane: send a signed envelope toward
/// its `to` party, receive the next one addressed to us. Implementations are
/// [`MemoryRelay`](crate::MemoryRelay) (tests, in-process backend) and the
/// WebSocket client in `sovra-ipc` (production). Ordering is per-sender FIFO
/// at best; [`Exchange`](crate::Exchange) owns cross-round reordering.
pub trait EnvelopeRelay: Send {
    fn send(&mut self, env: SignedEnvelope) -> impl Future<Output = Result<(), MpcError>> + Send;
    fn recv(&mut self) -> impl Future<Output = Result<SignedEnvelope, MpcError>> + Send;
}

/// The operations one cosigner runs in a ceremony. Mirrors the silence
/// backend's free functions minus two sl-isms: the transport is the sovra
/// envelope relay, and `refresh` takes no lost party — recovery is now
/// "sign with survivors, fresh DKG, migrate funds" at the product layer, so
/// a refresh is always the all-parties proactive re-randomize.
pub trait PartyRunner: Send + Sync {
    /// This party's share of a t-of-n DKG over the full roster: returns its
    /// own shard (opaque bytes for the store) and the public key it
    /// independently derived from that shard.
    fn keygen(
        &self,
        ctx: &PartyContext,
        relay: &mut impl EnvelopeRelay,
    ) -> impl Future<Output = Result<(KeyShare, PubkeySec1), MpcError>> + Send;

    /// This party's share of signing one digest with the given subset of t
    /// global party ids (strictly ascending, must contain this party).
    fn sign(
        &self,
        ctx: &PartyContext,
        share: &KeyShare,
        digest: B256,
        subset: &[u8],
        relay: &mut impl EnvelopeRelay,
    ) -> impl Future<Output = Result<EcdsaParts, MpcError>> + Send;

    /// All-parties proactive re-randomize: every party brings its shard,
    /// every shard is replaced, the public key is unchanged (verified against
    /// the caller-supplied expected key). Old shards become useless.
    fn refresh(
        &self,
        ctx: &PartyContext,
        share: &KeyShare,
        public_key: &PubkeySec1,
        relay: &mut impl EnvelopeRelay,
    ) -> impl Future<Output = Result<(KeyShare, PubkeySec1), MpcError>> + Send;

    /// Backend-neutral "public key of this shard" — replaces the cosigner's
    /// direct deserialization of the backend's keyshare type (`GET /pubkey`).
    fn public_key_of(&self, share: &KeyShare) -> Result<PubkeySec1, MpcError>;
}
