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
        let (r0, r1) = tokio::join!(
            self.post::<_, SignerInfo>(0, "dkg", &req),
            self.post::<_, SignerInfo>(1, "dkg", &req),
        );
        let (a0, a1) = (r0?.address, r1?.address);
        if a0 != a1 {
            return Err(MpcError::PartyMismatch(format!(
                "dkg addresses differ: {a0} != {a1}"
            )));
        }
        Ok(a0)
    }

    async fn sign(&self, signing_hash: B256) -> Result<EcdsaParts, MpcError> {
        let req = StartSignRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
            tx_digest: signing_hash,
        };
        let (r0, r1) = tokio::join!(
            self.post::<_, SignParts>(0, "sign", &req),
            self.post::<_, SignParts>(1, "sign", &req),
        );
        let (p0, p1) = (r0?, r1?);
        if p0 != p1 {
            return Err(MpcError::PartyMismatch(
                "sign parts differ between parties".into(),
            ));
        }
        Ok(p0.into())
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
