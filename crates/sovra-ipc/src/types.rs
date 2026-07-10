#[derive(thiserror::Error, Debug)]
pub enum IpcError {
    #[error("websocket connect failed: {0}")]
    Connect(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("cosigner http request failed: {0}")]
    Http(String),
}
