//! Transport layer for the sovra process split (orchestrator + 2 cosigners).
//!
//! Two independent planes:
//! - **Relay plane** (WebSocket, binary frames): [`hub`] is the server side,
//!   hosted inside the sovra-api process; [`client`] is the cosigner-side
//!   dialer. Together they carry the opaque `sl-dkls23` MPC round messages,
//!   matched by instance id. The relay never interprets frames —
//!   authentication lives inside the MPC protocol (pinned ed25519 keys).
//! - **Control plane** (HTTP/JSON): [`remote`] lets the orchestrator command
//!   both cosigners and cross-check their answers; [`control`] holds the wire
//!   types shared by both ends.
//!
//! WebSocket + HTTP/JSON were chosen over gRPC to keep the PoC dependency-light
//! and curl-debuggable;

pub mod client;
pub mod control;
pub mod hub;
pub mod remote;
pub mod types;
