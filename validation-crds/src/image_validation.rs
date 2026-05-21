//! `AkeylessImageValidation` CRD — the top-level CR. One per (image
//! digest × promessa). Spec is immutable after admission; status is
//! reconciler-managed.

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::{r#gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Serialize};

fn preserve_unknown_object_schema(_: &mut SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true
    }))
    .expect("static schema")
}

use crate::scan_job::{ScanJobPhase, ScannerKind};
use crate::shared::{CartorioArtifactState, TypedCondition};

#[derive(CustomResource, Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[kube(
    group = "validation.pleme.io",
    version = "v1",
    kind = "AkeylessImageValidation",
    plural = "akeylessimagevalidations",
    shortname = "aiv",
    namespaced,
    status = "AkeylessImageValidationStatus",
    printcolumn = r#"{"name":"Service","type":"string","jsonPath":".spec.service"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Severity","type":"string","jsonPath":".status.gateDecision.severity"}"#,
    printcolumn = r#"{"name":"Verdict","type":"string","jsonPath":".status.gateDecision.verdict"}"#,
    printcolumn = r#"{"name":"Cartorio","type":"string","jsonPath":".status.cartorioArtifactState"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct AkeylessImageValidationSpec {
    /// The sha256 digest being validated, e.g. `sha256:abc123...`.
    pub image_digest: String,

    /// Image repository, e.g. `ghcr.io/akeylesslabs/akeyless-auth`.
    pub image_repo: String,

    /// One of the 9 services in akeyless-nix-images/lib/service-defs.nix.
    pub service: String,

    /// Reference to the governing promessa (by name; resolved by the controller
    /// against the promessa-runtime registry).
    pub promessa_ref: String,

    /// Compliance pack identifier.
    pub pack: String,

    /// How long to retain after terminal phase. None = forever.
    /// Format: ISO 8601 duration (e.g. `P30D`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_for: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AkeylessImageValidationPhase {
    Pending,
    Provisioning,
    Scanning,
    Aggregating,
    Attesting,
    Gating,
    Passed,
    Failed,
    Quarantined,
}

impl AkeylessImageValidationPhase {
    /// Is this a terminal phase? (no further reconciler-driven transitions)
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Passed | Self::Failed | Self::Quarantined)
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct AkeylessImageValidationStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<AkeylessImageValidationPhase>,

    /// Child AkeylessEphemeralTenant CR name (same namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_tenant_ref: Option<String>,

    /// One entry per scanner that will run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scan_jobs: Vec<ScanJobSummary>,

    /// blake3 of canonical(union(findings)) — populated at Aggregating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_bundle_hash: Option<String>,

    /// Observed cartorio ArtifactState — populated at Attesting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cartorio_artifact_state: Option<CartorioArtifactState>,

    /// Filled at Gating by the SecurityController.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_decision: Option<GateDecision>,

    /// Filled at terminal phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_receipt_ref: Option<OutcomeReceiptRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<TypedCondition>,

    #[serde(default)]
    pub observed_generation: i64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanJobSummary {
    pub name: String,
    pub scanner: ScannerKind,
    pub phase: ScanJobPhase,
    #[serde(default)]
    pub findings_count: u64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GateDecision {
    /// Cosmetic | Functional | Critical — mirrors `promessa_types::Severity`.
    pub severity: String,
    /// Passed | Failed | Quarantined.
    pub verdict: GateVerdict,
    /// Canonical JSON of the `TypedAction` dispatched (may be Compose-of-N).
    #[schemars(schema_with = "preserve_unknown_object_schema")]
    pub action: serde_json::Value,
    /// Optional human-readable explanation aggregated from drift entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub decided_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateVerdict {
    Passed,
    Failed,
    Quarantined,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeReceiptRef {
    /// blake3 hex digest of the canonical receipt bytes.
    pub blake3_hash: String,
    /// Ed25519 signature over `blake3_hash`.
    pub ed25519_sig: String,
    /// MinIO object path (s3://outcome-chains-<cluster>/<promessa>/<receipt>.json).
    pub minio_path: String,
    pub signed_at: DateTime<Utc>,
}
