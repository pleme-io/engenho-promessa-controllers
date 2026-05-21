//! WebSocket endpoint — typed `WatchEvent` stream on phase transitions.
//!
//! Per NIX-AST emission discipline: every frame is a typed
//! [`WatchEvent`] serialized via serde, never an inline JSON literal.
//! M1.5: opens the socket, sends a typed `Hello` frame, then keeps it
//! open. Full transition stream (`PhaseTransition`, `GateDecided`,
//! `OutcomeAppended`) lands in P3 when controllers emit denshin events.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::projection::ValidationProjection;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WatchEvent {
    Hello(HelloPayload),
    PhaseTransition(PhaseTransitionPayload),
    GateDecided(GateDecidedPayload),
    OutcomeAppended(OutcomeAppendedPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloPayload {
    pub server_version: String,
    pub ts: DateTime<Utc>,
    pub projection_size: ProjectionSize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionSize {
    pub validations: u32,
    pub tenants: u32,
    pub scan_jobs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseTransitionPayload {
    pub kind: String, // AkeylessImageValidation | AkeylessEphemeralTenant | ScanJob
    pub namespace: String,
    pub name: String,
    pub from_phase: Option<String>,
    pub to_phase: String,
    pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateDecidedPayload {
    pub namespace: String,
    pub name: String,
    pub severity: String,
    pub verdict: String,
    pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeAppendedPayload {
    pub namespace: String,
    pub name: String,
    pub blake3_hash: String,
    pub minio_path: String,
    pub ts: DateTime<Utc>,
}

pub async fn watch(
    ws: WebSocketUpgrade,
    State(p): State<Arc<ValidationProjection>>,
) -> Response {
    ws.on_upgrade(|socket| handle_socket(socket, p))
}

async fn handle_socket(mut socket: WebSocket, p: Arc<ValidationProjection>) {
    let snap = p.snapshot().await;
    let event = WatchEvent::Hello(HelloPayload {
        server_version: env!("CARGO_PKG_VERSION").into(),
        ts: Utc::now(),
        projection_size: ProjectionSize {
            validations: snap.validations.len() as u32,
            tenants: snap.tenants.len() as u32,
            scan_jobs: snap.scan_jobs.len() as u32,
        },
    });
    if let Ok(payload) = serde_json::to_string(&event) {
        let _ = socket.send(Message::Text(payload.into())).await;
    }
    // Hold open until client closes; transition stream wire-up in P3.
    while let Some(Ok(_)) = socket.recv().await {}
}
