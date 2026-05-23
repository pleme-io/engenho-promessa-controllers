//! `ScanJob` CRD — one per (scanner × validation). Wraps a single
//! scanner invocation. Status carries the typed `Finding` list.

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::shared::TypedCondition;

/// The canonical typed scanner kinds — every scanner the validation
/// platform knows how to spawn. Matches
/// `security-controller::RequiredScanner` byte-for-byte (Compounding #1:
/// one source of truth for the scanner enum, fleet-wide).
///
/// ## Reusability across ecosystems
///
/// This enum is the typed contract reused by:
/// - `validation-controllers::scan_job` — spawns Kubernetes Jobs per kind
/// - `scanner-catalog` (sibling crate) — maps each kind to its OCI image
///   + CLI args template + output parser shape
/// - `security-controller` — projects `RequiredScanner` from this set
/// - `helmworks-akeyless/charts/lareira-akeyless-validation` — values
///   block per kind for enable/disable + image override
/// - any future consumer (kenshi BuildPipeline, etc.) just imports it
///
/// Three classes of variants:
/// - **OSS CNCF-leaning** (default-enabled, no creds required): Trivy,
///   Grype, Syft, Trufflehog, Semgrep, KubeLinter, KubeBench,
///   KubeHunter, Polaris, Zap, StigCisValidator
/// - **commercial / SaaS** (default-disabled, gated on cofre creds):
///   Snyk, DockerScout, JfrogXray, Wiz, PrismaCloud, BurpEnterprise
/// - **heavy / setup-required** (default-disabled, opt-in): Codeql
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScannerKind {
    // ── OSS CNCF (CVE) ─────────────────────────────────────────────
    Trivy,
    Grype,
    // ── OSS CNCF (SBOM) ────────────────────────────────────────────
    Syft,
    // ── OSS CNCF (secrets) ─────────────────────────────────────────
    Trufflehog,
    // ── OSS CNCF (SAST) ────────────────────────────────────────────
    Semgrep,
    // ── OSS CNCF (K8s posture / hardening) ─────────────────────────
    KubeLinter,
    KubeBench,
    KubeHunter,
    Polaris,
    StigCisValidator,
    // ── OSS DAST ───────────────────────────────────────────────────
    Zap,
    // ── Commercial (default-disabled; require credentials) ─────────
    Snyk,
    DockerScout,
    JfrogXray,
    Wiz,
    PrismaCloud,
    BurpEnterprise,
    // ── Heavy / setup-required ─────────────────────────────────────
    Codeql,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScannerClass {
    Cve,
    Sast,
    Dast,
    Hardening,
}

#[derive(CustomResource, Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[kube(
    group = "validation.pleme.io",
    version = "v1",
    kind = "ScanJob",
    plural = "scanjobs",
    shortname = "sjob",
    namespaced,
    status = "ScanJobStatus",
    printcolumn = r#"{"name":"Scanner","type":"string","jsonPath":".spec.scanner"}"#,
    printcolumn = r#"{"name":"Class","type":"string","jsonPath":".spec.scannerClass"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Findings","type":"integer","jsonPath":".status.findingsCount"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ScanJobSpec {
    pub scanner: ScannerKind,
    pub scanner_class: ScannerClass,

    /// For CVE scanners — the image digest to scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_digest: Option<String>,

    /// For SAST scanners — the source git URL+ref to scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_source: Option<String>,

    /// For DAST scanners — the URL of the ephemeral tenant to probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_tenant_url: Option<String>,

    /// Parent AkeylessImageValidation name (same namespace).
    pub parent_validation: String,

    /// Compliance pack identifier (e.g. `fedramp-high-akeyless-go-image@1`).
    pub pack: String,

    /// Optional override of the scanner image (else taken from the chart's
    /// values.yaml at controller-render time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_override: Option<String>,
}

/// Phases reuse tatara-reconciler's 8-phase Process lifecycle byte-for-byte
/// (Compounding #1: solve once). The ScanJob controller is a thin wrapper
/// that translates Process.status into typed Findings.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanJobPhase {
    Pending,
    Forking,
    Execing,
    Running,
    Attested,
    Reconverging,
    Exiting,
    Failed,
    Zombie,
    Reaped,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanJobStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<ScanJobPhase>,

    /// Backing tatara-reconciler Process CR name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_ref: Option<String>,

    /// Typed findings emitted by the scanner. Matches
    /// `security-controller::Finding` field-by-field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ScanFinding>,

    /// Convenience aggregate.
    #[serde(default)]
    pub findings_count: u64,

    /// BLAKE3 of canonical(findings) — anchor for the evidence bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<AttestationRef>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<TypedCondition>,

    #[serde(default)]
    pub observed_generation: i64,
}

// PartialEq only (no Eq) because cvss_v3 is f32.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScanFinding {
    pub scanner: ScannerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    pub severity: ScanFindingSeverity,
    pub first_seen: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_v3: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScanFindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationRef {
    /// blake3 hex digest of canonical(findings).
    pub hash: String,
    /// Optional ed25519 signature (populated when tameshi signs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_sig: Option<String>,
    pub signed_at: DateTime<Utc>,
}
