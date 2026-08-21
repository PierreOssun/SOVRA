//! Transport layer for the sovra process split (orchestrator + 2 cosigners).
//!
//! Two independent planes:
//! - **Relay plane** (WebSocket, binary frames): [`hub`] is the server side,
//!   hosted inside the sovra-api process; [`envelope_client`] is the
//!   cosigner-side dialer. Together they carry the signed/sealed MPC round
//!   envelopes, routed by `(instance, recipient)`. The hub never verifies —
//!   envelope authentication and unsealing happen at the recipients against
//!   their pinned ed25519 roster.
//! - **Control plane** (HTTP/JSON): [`remote`] lets the orchestrator command
//!   both cosigners and cross-check their answers; [`control`] holds the wire
//!   types shared by both ends.
//!
//! WebSocket + HTTP/JSON were chosen over gRPC to keep the PoC dependency-light
//! and curl-debuggable;

pub mod control;
pub mod envelope_client;
pub mod hub;
pub mod remote;
pub mod tls;
pub mod types;
