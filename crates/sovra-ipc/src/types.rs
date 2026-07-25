//! Crate error type. Deliberately coarse: two variants — WebSocket connect
//! failure (relay plane) and HTTP failure (control plane) — because callers
//! only propagate or log these; nothing branches on finer detail. The `Http`
//! payload is a plain string for the same reason (revisit when policy
//! rejections need structured surfacing). MPC-operation errors are *not*
//! here — `RemoteBackend` reports those through `sovra_mpc::MpcError`, the
//! trait's own error type.

#[derive(thiserror::Error, Debug)]
pub enum IpcError {
    #[error("websocket connect failed: {0}")]
    Connect(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("cosigner http request failed: {0}")]
    Http(String),
}
