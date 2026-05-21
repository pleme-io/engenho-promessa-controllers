//! Shared typed enums + conditions used across all three CRDs.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Cartorio ArtifactState (mirror of pleme-io/cartorio's typed surface).
/// Observed from the cartorio ledger; not authored locally.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CartorioArtifactState {
    Pending,
    Active,
    Quarantined,
    Revoked,
    Superseded,
}

/// K8s-style typed condition. Lifted onto `.status.conditions[]` so kubectl
/// can render the standard READY/PROGRESSING/AVAILABLE columns.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct TypedCondition {
    #[serde(rename = "type")]
    pub ty: ConditionType,
    pub status: ConditionStatus,
    pub last_transition_time: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub observed_generation: i64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionType {
    Ready,
    Progressing,
    Available,
    Failed,
    Reconciled,
    AttestationVerified,
    GateDecided,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}
