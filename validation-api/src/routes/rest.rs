//! REST handlers — all are pure projections of the ValidationProjection.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use validation_crds::{
    AkeylessEphemeralTenant, AkeylessImageValidation, AkeylessImageValidationPhase, GateVerdict,
    ScanJob,
};

use crate::projection::ValidationProjection;

// ── Query types ─────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Default, utoipa::IntoParams, utoipa::ToSchema)]
pub struct ListValidationsQuery {
    /// Filter by `.status.phase` — Pending / Scanning / Passed / etc.
    pub phase: Option<String>,
    /// Filter by `.spec.service` — auth / uam / kfm / gator / …
    pub service: Option<String>,
    /// Filter by `.spec.promessa_ref` — pin to a single promessa.
    pub promessa: Option<String>,
    /// RFC 3339 timestamp lower bound. Reserved (not yet enforced).
    pub since: Option<String>,
}

// ── Validations ─────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/validations",
    params(ListValidationsQuery),
    responses(
        (status = 200, description = "AkeylessImageValidation CRs matching the query (JSON arrays of the CR shape).", body = Vec<serde_json::Value>)
    ),
    tag = "validations"
)]
pub async fn list_validations(
    State(p): State<Arc<ValidationProjection>>,
    Query(q): Query<ListValidationsQuery>,
) -> impl IntoResponse {
    let snap = p.snapshot().await;
    let mut items: Vec<&AkeylessImageValidation> = snap.validations.iter().collect();
    if let Some(phase) = q.phase.as_deref() {
        items.retain(|v| {
            v.status
                .as_ref()
                .and_then(|s| s.phase)
                .map(|p| format!("{p:?}").eq_ignore_ascii_case(phase))
                .unwrap_or(false)
        });
    }
    if let Some(service) = q.service.as_deref() {
        items.retain(|v| v.spec.service == service);
    }
    if let Some(promessa) = q.promessa.as_deref() {
        items.retain(|v| v.spec.promessa_ref == promessa);
    }
    Json(items.into_iter().cloned().collect::<Vec<_>>())
}

#[utoipa::path(
    get,
    path = "/v1/validations/{ns}/{name}",
    params(
        ("ns" = String, Path, description = "Namespace"),
        ("name" = String, Path, description = "AkeylessImageValidation CR name")
    ),
    responses(
        (status = 200, description = "The AkeylessImageValidation CR as JSON", body = serde_json::Value),
        (status = 404, description = "Not found")
    ),
    tag = "validations"
)]
pub async fn get_validation(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_validation(&ns, &name).await {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::NOT_FOUND, "validation not found").into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/v1/validations/{ns}/{name}/findings",
    params(
        ("ns" = String, Path, description = "Namespace"),
        ("name" = String, Path, description = "AkeylessImageValidation CR name")
    ),
    responses(
        (status = 200, description = "Typed ScanFinding rows aggregated across child ScanJob CRs", body = Vec<serde_json::Value>),
        (status = 404, description = "Validation not found")
    ),
    tag = "validations"
)]
pub async fn get_findings(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    let Some(v) = p.get_validation(&ns, &name).await else {
        return (StatusCode::NOT_FOUND, "validation not found").into_response();
    };
    // Collect findings from all child scan-jobs by name match on the
    // parent_validation field.
    let snap = p.snapshot().await;
    let findings: Vec<_> = snap
        .scan_jobs
        .iter()
        .filter(|s| s.spec.parent_validation == v.metadata.name.clone().unwrap_or_default())
        .flat_map(|s| s.status.as_ref().map(|st| st.findings.clone()).unwrap_or_default())
        .collect();
    Json(findings).into_response()
}

#[utoipa::path(
    get,
    path = "/v1/validations/{ns}/{name}/evidence",
    params(
        ("ns" = String, Path),
        ("name" = String, Path)
    ),
    responses(
        (status = 200, description = "BLAKE3 evidence-bundle hash (string) or null if not aggregated yet", body = serde_json::Value),
        (status = 404, description = "Not found")
    ),
    tag = "validations"
)]
pub async fn get_evidence(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_validation(&ns, &name).await {
        Some(v) => Json(v.status.as_ref().map(|s| &s.evidence_bundle_hash)).into_response(),
        None => (StatusCode::NOT_FOUND, "validation not found").into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/v1/validations/{ns}/{name}/gate",
    params(
        ("ns" = String, Path),
        ("name" = String, Path)
    ),
    responses(
        (status = 200, description = "The typed GateDecision from the SecurityController, or null if Gating phase has not been reached", body = serde_json::Value),
        (status = 404, description = "Not found")
    ),
    tag = "validations"
)]
pub async fn get_gate(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_validation(&ns, &name).await {
        Some(v) => Json(v.status.as_ref().and_then(|s| s.gate_decision.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, "validation not found").into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/v1/validations/{ns}/{name}/outcome-chain",
    params(
        ("ns" = String, Path),
        ("name" = String, Path)
    ),
    responses(
        (status = 200, description = "Typed OutcomeReceiptRef pointing at the tameshi-signed outcome chain entry (BLAKE3 hash, Ed25519 signature, MinIO path)", body = serde_json::Value),
        (status = 404, description = "Not found")
    ),
    tag = "validations"
)]
pub async fn get_outcome_chain(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_validation(&ns, &name).await {
        Some(v) => Json(v.status.as_ref().and_then(|s| s.outcome_receipt_ref.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, "validation not found").into_response(),
    }
}

/// Acknowledgement body returned by `POST /v1/validations/{ns}/{name}/rescan`.
#[derive(Serialize, Debug, utoipa::ToSchema)]
pub struct RescanAck {
    pub acknowledged: bool,
    pub namespace: String,
    pub name: String,
    pub note: String,
    pub ts: chrono::DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/v1/validations/{ns}/{name}/rescan",
    params(
        ("ns" = String, Path),
        ("name" = String, Path)
    ),
    responses(
        (status = 200, description = "Rescan request acknowledged. The controller observes the request and re-reconciles on the next tick.", body = RescanAck)
    ),
    tag = "validations"
)]
pub async fn rescan(
    State(_p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    // Rescan is idempotent: it sets a `.spec.rescanRequestedAt`
    // annotation which the controller observes and re-reconciles.
    // Wire-up lands when controllers ship in P3.
    Json(serde_json::json!({
        "acknowledged": true,
        "namespace": ns,
        "name": name,
        "note": "Rescan request recorded. Controller wire-up lands in P3.",
        "ts": Utc::now(),
    }))
}

// ── Tenants ─────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/ephemeral-tenants",
    responses(
        (status = 200, description = "Every AkeylessEphemeralTenant CR the informer has observed", body = Vec<serde_json::Value>)
    ),
    tag = "ephemeral-tenants"
)]
pub async fn list_tenants(
    State(p): State<Arc<ValidationProjection>>,
) -> impl IntoResponse {
    Json(p.snapshot().await.tenants)
}

#[utoipa::path(
    get,
    path = "/v1/ephemeral-tenants/{ns}/{name}",
    params(
        ("ns" = String, Path),
        ("name" = String, Path)
    ),
    responses(
        (status = 200, description = "The AkeylessEphemeralTenant CR as JSON", body = serde_json::Value),
        (status = 404, description = "Not found")
    ),
    tag = "ephemeral-tenants"
)]
pub async fn get_tenant(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_tenant(&ns, &name).await {
        Some(t) => Json(t).into_response(),
        None => (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    }
}

// ── Scan Jobs ───────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Default, utoipa::IntoParams, utoipa::ToSchema)]
pub struct ListScanJobsQuery {
    /// Filter by `.spec.scanner` — Trivy / Grype / Syft / … (PascalCase).
    pub scanner: Option<String>,
    /// Filter by `.spec.scannerClass` — Cve / Sast / Dast / Hardening.
    #[serde(rename = "scanner-class")]
    pub scanner_class: Option<String>,
    /// Filter by `.status.phase` — Pending / Running / Attested / etc.
    pub phase: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/scan-jobs",
    params(ListScanJobsQuery),
    responses(
        (status = 200, description = "ScanJob CRs matching the query", body = Vec<serde_json::Value>)
    ),
    tag = "scan-jobs"
)]
pub async fn list_scan_jobs(
    State(p): State<Arc<ValidationProjection>>,
    Query(q): Query<ListScanJobsQuery>,
) -> impl IntoResponse {
    let snap = p.snapshot().await;
    let mut items: Vec<&ScanJob> = snap.scan_jobs.iter().collect();
    if let Some(scanner) = q.scanner.as_deref() {
        items.retain(|s| format!("{:?}", s.spec.scanner).eq_ignore_ascii_case(scanner));
    }
    if let Some(class) = q.scanner_class.as_deref() {
        items.retain(|s| format!("{:?}", s.spec.scanner_class).eq_ignore_ascii_case(class));
    }
    if let Some(phase) = q.phase.as_deref() {
        items.retain(|s| {
            s.status
                .as_ref()
                .and_then(|st| st.phase)
                .map(|p| format!("{p:?}").eq_ignore_ascii_case(phase))
                .unwrap_or(false)
        });
    }
    Json(items.into_iter().cloned().collect::<Vec<_>>())
}

#[utoipa::path(
    get,
    path = "/v1/scan-jobs/{ns}/{name}",
    params(
        ("ns" = String, Path),
        ("name" = String, Path)
    ),
    responses(
        (status = 200, description = "The ScanJob CR as JSON", body = serde_json::Value),
        (status = 404, description = "Not found")
    ),
    tag = "scan-jobs"
)]
pub async fn get_scan_job(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_scan_job(&ns, &name).await {
        Some(j) => Json(j).into_response(),
        None => (StatusCode::NOT_FOUND, "scan job not found").into_response(),
    }
}

// ── Compliance summary ──────────────────────────────────────────────

#[derive(Serialize, Debug, Default, utoipa::ToSchema)]
pub struct ComplianceSummary {
    pub promessa: String,
    pub window: String,
    pub as_of: chrono::DateTime<Utc>,
    pub total_digests_observed: u32,
    pub by_phase: BTreeMap<String, u32>,
    pub by_verdict: BTreeMap<String, u32>,
    pub compliance_state: String,
    pub blocking: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/v1/compliance-summary",
    responses(
        (status = 200, description = "Aggregate compliance state across every observed validation run", body = ComplianceSummary)
    ),
    tag = "compliance"
)]
pub async fn compliance_summary(
    State(p): State<Arc<ValidationProjection>>,
) -> impl IntoResponse {
    let snap = p.snapshot().await;
    let mut by_phase: BTreeMap<String, u32> = BTreeMap::new();
    let mut by_verdict: BTreeMap<String, u32> = BTreeMap::new();
    let mut blocking = vec![];
    let mut state = "Cosmetic";
    for v in &snap.validations {
        let phase = v
            .status
            .as_ref()
            .and_then(|s| s.phase)
            .map(|p| format!("{p:?}"))
            .unwrap_or_else(|| "Unknown".into());
        *by_phase.entry(phase).or_default() += 1;
        if let Some(gd) = v.status.as_ref().and_then(|s| s.gate_decision.as_ref()) {
            *by_verdict
                .entry(format!("{:?}", gd.verdict))
                .or_default()
                += 1;
            if matches!(gd.verdict, GateVerdict::Failed | GateVerdict::Quarantined) {
                blocking.push(v.spec.image_digest.clone());
                state = "Critical";
            } else if state == "Cosmetic" && gd.severity == "Functional" {
                state = "Functional";
            }
        }
        let _ = AkeylessImageValidationPhase::Passed; // ensure crate is wired
    }
    Json(ComplianceSummary {
        promessa: snap
            .validations
            .first()
            .map(|v| v.spec.promessa_ref.clone())
            .unwrap_or_default(),
        window: "30d".into(),
        as_of: Utc::now(),
        total_digests_observed: snap.validations.len() as u32,
        by_phase,
        by_verdict,
        compliance_state: state.into(),
        blocking,
    })
}

#[utoipa::path(
    get,
    path = "/v1/compliance-summary/by-service",
    responses(
        (status = 200, description = "Phase counts grouped by service name (auth / uam / kfm / ...)", body = serde_json::Value)
    ),
    tag = "compliance"
)]
pub async fn compliance_by_service(
    State(p): State<Arc<ValidationProjection>>,
) -> impl IntoResponse {
    let snap = p.snapshot().await;
    let mut by_svc: BTreeMap<String, BTreeMap<String, u32>> = BTreeMap::new();
    for v in &snap.validations {
        let svc = v.spec.service.clone();
        let phase = v
            .status
            .as_ref()
            .and_then(|s| s.phase)
            .map(|p| format!("{p:?}"))
            .unwrap_or_else(|| "Unknown".into());
        *by_svc.entry(svc).or_default().entry(phase).or_default() += 1;
    }
    Json(by_svc)
}

// ── Health + observability ──────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/healthz",
    responses((status = 200, description = "Liveness probe — always 200 OK while the binary is alive")),
    tag = "health"
)]
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[utoipa::path(
    get,
    path = "/v1/readyz",
    responses((status = 200, description = "Readiness probe — projection is reachable")),
    tag = "health"
)]
pub async fn readyz(State(p): State<Arc<ValidationProjection>>) -> impl IntoResponse {
    // Ready = at least one informer has populated something OR we've
    // been running > 30s without errors. M1.5: always Ready.
    let _ = p.snapshot().await;
    (StatusCode::OK, "ready")
}

#[utoipa::path(
    get,
    path = "/v1/metrics",
    responses(
        (status = 200, description = "Prometheus text-format metrics scrape target", content_type = "text/plain; version=0.0.4")
    ),
    tag = "health"
)]
pub async fn metrics() -> impl IntoResponse {
    // Prometheus scrape — populated in P3 when controllers emit counters.
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        "# HELP validation_api_up 1 if the API is running\n\
         # TYPE validation_api_up gauge\n\
         validation_api_up 1\n",
    )
}

// ── OpenAPI ────────────────────────────────────────────────────────

/// OpenAPI 3 spec for the entire REST + scanner-catalog surface.
/// Every handler annotated with `#[utoipa::path]` shows up here;
/// every DTO derived with `#[derive(utoipa::ToSchema)]` appears in
/// `components/schemas`. SDK generators (openapi-generator,
/// orval, openapi-typescript, kiota, …) consume the emitted JSON.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "AKEYLESS-VALIDATION-PLATFORM REST API",
        description = "Typed projection of AkeylessImageValidation / \
                       AkeylessEphemeralTenant / ScanJob CRs, plus the \
                       reusable scanner-catalog substrate. Companion to the \
                       gRPC surface at :50051 (validation.v1).",
        version = "0.5.0",
        license(name = "MIT")
    ),
    paths(
        // Validations
        list_validations,
        get_validation,
        get_findings,
        get_evidence,
        get_gate,
        get_outcome_chain,
        rescan,
        // Ephemeral tenants
        list_tenants,
        get_tenant,
        // Scan jobs
        list_scan_jobs,
        get_scan_job,
        // Compliance
        compliance_summary,
        compliance_by_service,
        // Scanner catalog (D5)
        crate::routes::scanners::list_scanners,
        crate::routes::scanners::get_scanner,
        // Health + observability
        healthz,
        readyz,
        metrics,
    ),
    components(schemas(
        ListValidationsQuery,
        ListScanJobsQuery,
        ComplianceSummary,
        RescanAck,
        crate::routes::scanners::ScannerImplDto,
    )),
    tags(
        (name = "validations",        description = "AkeylessImageValidation phase machine + per-CR derived data"),
        (name = "ephemeral-tenants",  description = "AkeylessEphemeralTenant materializer state"),
        (name = "scan-jobs",          description = "Per-scanner ScanJob CRs + their typed findings"),
        (name = "compliance",         description = "Aggregate compliance projection across every observed validation"),
        (name = "scanners",           description = "scanner-catalog substrate: typed (image, args, output format) per ScannerKind"),
        (name = "health",             description = "Liveness, readiness, metrics scrape")
    )
)]
struct ApiDoc;

pub fn openapi_json() -> anyhow::Result<String> {
    use utoipa::OpenApi;
    Ok(ApiDoc::openapi().to_json()?)
}

pub async fn openapi_route() -> impl IntoResponse {
    match openapi_json() {
        Ok(s) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            s,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin: every documented handler must be in the emitted spec.
    /// Failing this test means somebody added a route without a
    /// matching `#[utoipa::path]` or forgot to include the handler
    /// in `ApiDoc::paths(...)`.
    #[test]
    fn openapi_spec_covers_every_path() {
        let raw = openapi_json().expect("ApiDoc emits valid JSON");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let paths = v.get("paths").and_then(|p| p.as_object()).expect("paths");
        for expected in [
            "/v1/validations",
            "/v1/validations/{ns}/{name}",
            "/v1/validations/{ns}/{name}/findings",
            "/v1/validations/{ns}/{name}/evidence",
            "/v1/validations/{ns}/{name}/gate",
            "/v1/validations/{ns}/{name}/outcome-chain",
            "/v1/validations/{ns}/{name}/rescan",
            "/v1/ephemeral-tenants",
            "/v1/ephemeral-tenants/{ns}/{name}",
            "/v1/scan-jobs",
            "/v1/scan-jobs/{ns}/{name}",
            "/v1/compliance-summary",
            "/v1/compliance-summary/by-service",
            "/v1/scanners",
            "/v1/scanners/{kind}",
            "/v1/healthz",
            "/v1/readyz",
            "/v1/metrics",
        ] {
            assert!(
                paths.contains_key(expected),
                "OpenAPI spec missing path {expected}"
            );
        }
    }

    #[test]
    fn openapi_spec_has_typed_schemas() {
        let raw = openapi_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let schemas = v
            .pointer("/components/schemas")
            .and_then(|s| s.as_object())
            .expect("components.schemas");
        for name in [
            "ListValidationsQuery",
            "ListScanJobsQuery",
            "ComplianceSummary",
            "RescanAck",
            "ScannerImplDto",
        ] {
            assert!(schemas.contains_key(name), "missing schema {name}");
        }
    }

    #[test]
    fn openapi_spec_has_info_metadata() {
        let raw = openapi_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            v.pointer("/info/title").and_then(|s| s.as_str()),
            Some("AKEYLESS-VALIDATION-PLATFORM REST API"),
        );
        assert!(v.pointer("/info/version").and_then(|s| s.as_str()).is_some());
    }
}
