//! `AkeylessEphemeralTenant` CRD — one per scan wave. Materializes a
//! minimal Akeyless SaaS deployment for DAST + STIG/CIS scanning,
//! then tears down.

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::shared::TypedCondition;

#[derive(CustomResource, Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[kube(
    group = "validation.pleme.io",
    version = "v1",
    kind = "AkeylessEphemeralTenant",
    plural = "akeylessephemeraltenants",
    shortname = "eph",
    namespaced,
    status = "AkeylessEphemeralTenantStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"PodsReady","type":"string","jsonPath":".status.podsReadyOverTotal"}"#,
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".status.ingressUrl"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct AkeylessEphemeralTenantSpec {
    /// List of `{service, digest}` the tenant runs. The chart values.yaml
    /// resolves each `{service}` to the right image-pin via the digest.
    pub digest_set: Vec<DigestSetEntry>,

    /// Anchor validation; drives lifecycle (teardown when parent terminal).
    pub parent_validation: String,

    /// Pangea-Ruby template name (typically `akeyless-eph-saas`).
    pub infra_template: String,

    /// Optional override; falls back to controller default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_pool: Option<String>,

    /// Safety-net TTL — controller force-teardowns after this duration
    /// regardless of parent state. Default: 1h (3600s).
    #[serde(default = "default_ttl", skip_serializing_if = "is_default_ttl")]
    pub ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    3600
}
fn is_default_ttl(v: &u64) -> bool {
    *v == 3600
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DigestSetEntry {
    pub service: String,
    pub digest: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AkeylessEphemeralTenantPhase {
    Pending,
    InfraProvisioning,
    ChartRendering,
    PodsRunning,
    Ready,
    Scanning,
    Teardown,
    Reaped,
    Failed,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct AkeylessEphemeralTenantStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<AkeylessEphemeralTenantPhase>,

    /// pangea-operator-managed cloud resource refs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub infra_resource_refs: Vec<InfraResourceRef>,

    /// Rendered caixa-helm HelmRelease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helm_release_ref: Option<String>,

    /// DAST target URL — populated when `phase=Ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_url: Option<String>,

    #[serde(default)]
    pub pods_ready: u32,
    #[serde(default)]
    pub pods_total: u32,

    /// Convenience string `"ready/total"` for kubectl print column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pods_ready_over_total: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_started_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<TypedCondition>,

    #[serde(default)]
    pub observed_generation: i64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InfraResourceRef {
    pub kind: String,
    pub name: String,
    pub status: String,
}
