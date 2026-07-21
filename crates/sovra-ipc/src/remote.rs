//! Orchestrator side of the control plane. [`RemoteBackend`] implements the
//! `MpcBackend` trait by POSTing each operation to **both** cosigners in
//! parallel with one shared random instance id, then cross-checking the two
//! responses — both parties must succeed *and agree* (`PartyMismatch`
//! otherwise), so a buggy or compromised cosigner can't return a divergent
//! result undetected. [`fetch_signer`] is the startup-recovery probe.
//!
//! Why reqwest/JSON: plain HTTP keeps the cosigner API curl-debuggable and
//! reuses the workspace HTTP stack; no streaming is needed on this plane.
//! `fetch_signer` takes the caller's `reqwest::Client` rather than the
//! backend's because recovery wants its own short probe timeout, not the
//! 90s operation timeout below.
//! Pattern: hexagonal port/adapter — the remote implementation of the
//! `MpcBackend` port (the test-only in-process one lives in
//! `sovra-mpc-dkls23-silence`).

use std::time::Duration;

use alloy_primitives::{Address, B256};
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use sovra_mpc::{EcdsaParts, MpcBackend, MpcError};
use url::Url;

use crate::{
    control::{
        CORRELATION_HEADER, CORRELATION_ID, SignParts, SignerInfo, StartDkgRequest,
        StartSignRequest,
    },
    types::IpcError,
};

/// Above the cosigner-side MPC timeout (60s TTL) so a live run is never cut
/// mid-flight; this only catches a cosigner that stops responding entirely.
const HTTP_TIMEOUT: Duration = Duration::from_secs(90);

pub struct RemoteBackend {
    cosigners: [Url; 2],
    http: reqwest::Client,
}

impl MpcBackend for RemoteBackend {
    async fn dkg(&self) -> Result<Address, MpcError> {
        let req = StartDkgRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
        };
        self.broadcast::<_, SignerInfo>("dkg", &req)
            .await
            .map(|i| i.address)
    }

    async fn sign(&self, signing_hash: B256) -> Result<EcdsaParts, MpcError> {
        let req = StartSignRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
            tx_digest: signing_hash,
        };
        self.broadcast::<_, SignParts>("sign", &req)
            .await
            .map(Into::into)
    }
}

impl RemoteBackend {
    pub fn new(cosigner0: Url, cosigner1: Url) -> Self {
        Self {
            cosigners: [cosigner0, cosigner1],
            http: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .build()
                .expect("reqwest client with static config"),
        }
    }

    /// POST the same request to both cosigners; both must succeed and agree.
    async fn broadcast<Req, Resp>(&self, path: &str, req: &Req) -> Result<Resp, MpcError>
    where
        Req: Serialize,
        Resp: DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let (r0, r1) = tokio::join!(
            self.post::<_, Resp>(0, path, req),
            self.post::<_, Resp>(1, path, req)
        );
        let (a, b) = (r0?, r1?);
        if a != b {
            return Err(MpcError::PartyMismatch(format!("{path}: {a:?} != {b:?}")));
        }
        Ok(a)
    }

    async fn post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        party: usize,
        path: &str,
        body: &Req,
    ) -> Result<Resp, MpcError> {
        let url = self.cosigners[party]
            .join(path)
            .map_err(|e| MpcError::Transport(format!("cosigner{party} url: {e}")))?;
        let correlation_id = CORRELATION_ID
            .try_with(Clone::clone)
            .unwrap_or_else(|_| format!("{:032x}", rand::random::<u128>()));

        let resp = self
            .http
            .post(url)
            .header(CORRELATION_HEADER, correlation_id)
            .json(body)
            .send()
            .await
            .map_err(|e| MpcError::Transport(format!("cosigner{party} {path}: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(MpcError::Transport(format!(
                "cosigner{party} {path}: {status}: {text}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| MpcError::Transport(format!("cosigner{party} {path}: bad response: {e}")))
    }
}

/// Startup-recovery probe: 200 → active address, 404 → no shard, anything else → error.
pub async fn fetch_signer(
    http: &reqwest::Client,
    cosigner: &Url,
) -> Result<Option<Address>, IpcError> {
    let url = cosigner
        .join("signer")
        .map_err(|e| IpcError::Http(format!("bad url: {e}")))?;
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| IpcError::Http(e.to_string()))?;
    match resp.status() {
        StatusCode::NOT_FOUND => Ok(None),
        s if s.is_success() => {
            let info: SignerInfo = resp
                .json()
                .await
                .map_err(|e| IpcError::Http(e.to_string()))?;
            Ok(Some(info.address))
        }
        s => Err(IpcError::Http(format!("GET /signer returned {s}"))),
    }
}
