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

#[derive(Deserialize, Debug, Default)]
pub struct ListValidationsQuery {
    pub phase: Option<String>,
    pub service: Option<String>,
    pub promessa: Option<String>,
    pub since: Option<String>,
}

// ── Validations ─────────────────────────────────────────────────────

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

pub async fn get_validation(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_validation(&ns, &name).await {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::NOT_FOUND, "validation not found").into_response(),
    }
}

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

pub async fn get_evidence(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_validation(&ns, &name).await {
        Some(v) => Json(v.status.as_ref().map(|s| &s.evidence_bundle_hash)).into_response(),
        None => (StatusCode::NOT_FOUND, "validation not found").into_response(),
    }
}

pub async fn get_gate(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_validation(&ns, &name).await {
        Some(v) => Json(v.status.as_ref().and_then(|s| s.gate_decision.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, "validation not found").into_response(),
    }
}

pub async fn get_outcome_chain(
    State(p): State<Arc<ValidationProjection>>,
    Path((ns, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match p.get_validation(&ns, &name).await {
        Some(v) => Json(v.status.as_ref().and_then(|s| s.outcome_receipt_ref.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, "validation not found").into_response(),
    }
}

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

pub async fn list_tenants(
    State(p): State<Arc<ValidationProjection>>,
) -> impl IntoResponse {
    Json(p.snapshot().await.tenants)
}

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

#[derive(Deserialize, Debug, Default)]
pub struct ListScanJobsQuery {
    pub scanner: Option<String>,
    #[serde(rename = "scanner-class")]
    pub scanner_class: Option<String>,
    pub phase: Option<String>,
}

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

#[derive(Serialize, Debug, Default)]
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

pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn readyz(State(p): State<Arc<ValidationProjection>>) -> impl IntoResponse {
    // Ready = at least one informer has populated something OR we've
    // been running > 30s without errors. M1.5: always Ready.
    let _ = p.snapshot().await;
    (StatusCode::OK, "ready")
}

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

#[derive(utoipa::OpenApi)]
#[openapi(paths(), components(schemas()))]
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
