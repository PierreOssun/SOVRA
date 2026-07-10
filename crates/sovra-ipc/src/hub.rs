use std::sync::Arc;

use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use sl_mpc_mate::coord::SimpleMessageRelay;

#[derive(Clone, Default)]
pub struct RelayHub {
    relay: Arc<SimpleMessageRelay>,
}

pub fn ws_router(hub: RelayHub) -> Router {
    Router::new().route("/ws", get(ws_handler)).with_state(hub)
}

async fn ws_handler(State(hub): State<RelayHub>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| serve_socket(hub, socket))
}

async fn serve_socket(hub: RelayHub, mut socket: WebSocket) {
    let mut relay = hub.relay.connect();
    loop {
        tokio::select! {
            frame = socket.recv() => {
                let Some(Ok(msg)) = frame else { break };           // closed or ws error
                let Message::Binary(bytes) = msg else { continue }; // ping/pong/text
                if relay.send(bytes.into()).await.is_err() {
                    // start_send's only error path is a frame too short for a header
                    tracing::warn!("dropping malformed relay frame");
                }
            }
            out = relay.next() => {
                let Some(msg) = out else { break };
                if socket.send(Message::Binary(msg.into())).await.is_err() { break }
            }
        }
    }
    // Dropping the MessageRelay is the cleanup: its waiter senders fail their
    // spawned sends (upstream ignores that) and entries TTL-expire.
}
