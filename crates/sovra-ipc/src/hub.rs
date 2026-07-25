//! Server side of the relay plane: [`RelayHub`] wraps
//! `sl_mpc_mate::coord::SimpleMessageRelay` behind an axum `GET /ws` upgrade.
//! Hosted inside the sovra-api process (bound before the API router, since
//! cosigners dial in mid-operation); both cosigners connect here and the relay
//! matches their MPC round messages by instance id.
//!
//! Why this shape: `SimpleMessageRelay` already implements ask/put matching
//! with TTL expiry, so the hub only pumps binary frames between the socket and
//! a `relay.connect()` handle — no custom routing to maintain. axum (`ws`
//! feature) is used because sovra-api already serves axum. The hub is
//! deliberately dumb: frames are opaque, trust lives in the MPC protocol.
//! Pattern: message broker (server half of the [`crate::client`] adapter pair).

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
