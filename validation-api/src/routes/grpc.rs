//! gRPC face — tonic services backed by the same data the REST face
//! reads:
//!
//! - [`ValidationServiceImpl`] — live projection of
//!   `AkeylessImageValidation` CRs from the kube-rs informer cache;
//!   audit reads (findings / outcomes / decisions) come from
//!   `validation-store`.
//! - [`ScannerCatalogServiceImpl`] — static `scanner-catalog::Catalog`.
//! - [`ComplianceServiceImpl`] — phase counts from `validation-store`.
//!
//! Generated protobuf code (from `build.rs`) is `include!`-ed below.
//!
//! Reflection: a `tonic-reflection` server is wired in [`spawn_grpc`]
//! so `grpcurl -plaintext localhost:50051 list` works.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use scanner_catalog::Catalog;
use tonic::{Request, Response, Status};
use validation_store::ValidationStore;

use crate::projection::ValidationProjection;

// ── Generated protobuf module ─────────────────────────────────────
pub mod proto {
    #![allow(clippy::pedantic, clippy::all)]
    tonic::include_proto!("validation.v1");

    /// Encoded `FileDescriptorSet` for tonic-reflection.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("validation_descriptor");
}

pub use proto::{
    compliance_service_server::{ComplianceService, ComplianceServiceServer},
    scanner_catalog_service_server::{ScannerCatalogService, ScannerCatalogServiceServer},
    validation_service_server::{ValidationService, ValidationServiceServer},
};

/// Convert a `chrono::DateTime<Utc>` to the proto `Timestamp` wrapper.
fn ts(t: DateTime<Utc>) -> proto::Timestamp {
    proto::Timestamp {
        rfc3339: t.to_rfc3339(),
    }
}

fn opt_ts(t: Option<DateTime<Utc>>) -> Option<proto::Timestamp> {
    t.map(ts)
}

// ── ValidationServiceImpl ─────────────────────────────────────────

pub struct ValidationServiceImpl {
    /// Reserved — gRPC `ValidationService` currently reads exclusively
    /// from the durable [`ValidationStore`] (audit-grade, queryable by
    /// phase / severity / time). A FOLLOWUP can wire a "live view"
    /// flavor of the same RPCs that reads from [`ValidationProjection`]
    /// for sub-second latency on cluster state. The field is held so
    /// the impl signature stays stable across that change.
    #[allow(dead_code)]
    pub projection: Arc<ValidationProjection>,
    pub store: Arc<ValidationStore>,
}

#[tonic::async_trait]
impl ValidationService for ValidationServiceImpl {
    async fn list_validations(
        &self,
        req: Request<proto::ListValidationsRequest>,
    ) -> Result<Response<proto::ListValidationsResponse>, Status> {
        let req = req.into_inner();
        let rows = if let Some(phase) = req.phase.as_deref() {
            validation_store::ops::query::validation_runs_by_phase(self.store.db(), phase)
                .await
                .map_err(|e| Status::internal(format!("store: {e}")))?
        } else {
            // No phase filter — fall back to "by-digest" with empty
            // digest? Simpler: a sea-orm find().all() via the API.
            // We keep this restricted to phase filtering for now.
            return Err(Status::invalid_argument(
                "ListValidationsRequest: provide `phase` filter (broad list not yet wired — \
                 use REST `/v1/validations` for the live informer projection instead)"
                    .to_owned(),
            ));
        };
        let items = rows
            .into_iter()
            .filter(|r| {
                req.namespace.as_deref().is_none_or(|ns| r.namespace == ns)
            })
            .take(req.limit.unwrap_or(u32::MAX) as usize)
            .map(model_to_proto_validation)
            .collect();
        Ok(Response::new(proto::ListValidationsResponse { items }))
    }

    async fn get_validation(
        &self,
        req: Request<proto::GetValidationRequest>,
    ) -> Result<Response<proto::ValidationRun>, Status> {
        let req = req.into_inner();
        let row = validation_store::ops::query::validation_run_by_uid(self.store.db(), &req.uid)
            .await
            .map_err(|e| Status::internal(format!("store: {e}")))?
            .ok_or_else(|| Status::not_found(format!("validation uid={} not found", req.uid)))?;
        Ok(Response::new(model_to_proto_validation(row)))
    }

    async fn list_findings(
        &self,
        req: Request<proto::ListFindingsRequest>,
    ) -> Result<Response<proto::ListFindingsResponse>, Status> {
        let req = req.into_inner();
        let rows = if let Some(severity) = req.severity.as_deref() {
            validation_store::ops::query::findings_by_run_and_severity(
                self.store.db(),
                &req.validation_run_uid,
                severity,
            )
            .await
        } else {
            validation_store::ops::query::findings_by_run(
                self.store.db(),
                &req.validation_run_uid,
            )
            .await
        }
        .map_err(|e| Status::internal(format!("store: {e}")))?;
        let items = rows.into_iter().map(model_to_proto_finding).collect();
        Ok(Response::new(proto::ListFindingsResponse { items }))
    }

    async fn list_outcomes(
        &self,
        req: Request<proto::ListOutcomesRequest>,
    ) -> Result<Response<proto::ListOutcomesResponse>, Status> {
        let req = req.into_inner();
        let rows = validation_store::ops::query::outcomes_by_run(
            self.store.db(),
            &req.validation_run_uid,
        )
        .await
        .map_err(|e| Status::internal(format!("store: {e}")))?;
        let items = rows.into_iter().map(model_to_proto_outcome).collect();
        Ok(Response::new(proto::ListOutcomesResponse { items }))
    }

    async fn list_decisions(
        &self,
        req: Request<proto::ListDecisionsRequest>,
    ) -> Result<Response<proto::ListDecisionsResponse>, Status> {
        let req = req.into_inner();
        let rows = validation_store::ops::query::decisions_by_run(
            self.store.db(),
            &req.validation_run_uid,
        )
        .await
        .map_err(|e| Status::internal(format!("store: {e}")))?;
        let items = rows.into_iter().map(model_to_proto_decision).collect();
        Ok(Response::new(proto::ListDecisionsResponse { items }))
    }
}

fn model_to_proto_validation(
    m: validation_store::entities::validation_run::Model,
) -> proto::ValidationRun {
    proto::ValidationRun {
        uid: m.uid,
        namespace: m.namespace,
        name: m.name,
        image_digest: m.image_digest,
        image_repo: m.image_repo,
        phase: m.phase,
        evidence_bundle_hash: m.evidence_bundle_hash,
        outcome_receipt_ref_json: m
            .outcome_receipt_ref
            .map(|v| serde_json::to_string(&v).unwrap_or_default()),
        observed_generation: m.observed_generation,
        started_at: Some(ts(m.started_at)),
        last_seen_at: Some(ts(m.last_seen_at)),
        terminal_at: opt_ts(m.terminal_at),
    }
}

fn model_to_proto_finding(
    m: validation_store::entities::scan_finding::Model,
) -> proto::ScanFinding {
    proto::ScanFinding {
        id: m.id,
        validation_run_uid: m.validation_run_uid,
        scan_job_name: m.scan_job_name,
        scanner: m.scanner,
        severity: m.severity,
        cve_id: m.cve_id,
        cvss_v3: m.cvss_v3,
        package: m.package,
        fixed_in: m.fixed_in,
        exception_id: m.exception_id,
        message: m.message,
        first_seen_at: Some(ts(m.first_seen_at)),
        recorded_at: Some(ts(m.recorded_at)),
    }
}

fn model_to_proto_outcome(
    m: validation_store::entities::reconciler_outcome::Model,
) -> proto::ReconcilerOutcome {
    proto::ReconcilerOutcome {
        id: m.id,
        validation_run_uid: m.validation_run_uid,
        action_kind: m.action_kind,
        reconciler_kind: m.reconciler_kind,
        action_payload_json: m.action_payload.to_string(),
        outcome: m.outcome,
        outcome_flag: m.outcome_flag,
        outcome_payload_json: m.outcome_payload.map(|v| v.to_string()),
        gate_decision_decided_at: Some(ts(m.gate_decision_decided_at)),
        dispatched_at: Some(ts(m.dispatched_at)),
    }
}

fn model_to_proto_decision(
    m: validation_store::entities::decision_audit::Model,
) -> proto::DecisionAudit {
    proto::DecisionAudit {
        id: m.id,
        validation_run_uid: m.validation_run_uid,
        severity: m.severity,
        verdict: m.verdict,
        action_payload_json: m.action_payload.to_string(),
        reason: m.reason,
        drift_snapshot_json: m.drift_snapshot.to_string(),
        decided_at: Some(ts(m.decided_at)),
        recorded_at: Some(ts(m.recorded_at)),
    }
}

// ── ScannerCatalogServiceImpl ─────────────────────────────────────

pub struct ScannerCatalogServiceImpl;

#[tonic::async_trait]
impl ScannerCatalogService for ScannerCatalogServiceImpl {
    async fn list_scanners(
        &self,
        _req: Request<proto::Empty>,
    ) -> Result<Response<proto::ListScannersResponse>, Status> {
        let items = Catalog::all().map(scanner_impl_to_proto).collect();
        Ok(Response::new(proto::ListScannersResponse { items }))
    }

    async fn get_scanner(
        &self,
        req: Request<proto::GetScannerRequest>,
    ) -> Result<Response<proto::ScannerImpl>, Status> {
        let kind_str = req.into_inner().kind;
        let kind = parse_scanner_kind(&kind_str)
            .ok_or_else(|| Status::invalid_argument(format!("unknown ScannerKind {kind_str}")))?;
        Ok(Response::new(scanner_impl_to_proto(Catalog::for_kind(kind))))
    }
}

fn scanner_impl_to_proto(s: scanner_catalog::ScannerImpl) -> proto::ScannerImpl {
    proto::ScannerImpl {
        kind: format!("{:?}", s.kind),
        class: format!("{:?}", s.class),
        default_enabled: s.default_enabled,
        image: s.image.to_owned(),
        target_field: format!("{:?}", s.target_field),
        args_template: s.args.render(Some("${target}")),
        output_format: format!("{:?}", s.output_format),
        upstream_url: s.upstream_url.to_owned(),
    }
}

fn parse_scanner_kind(s: &str) -> Option<validation_crds::ScannerKind> {
    use validation_crds::ScannerKind as K;
    match s {
        "Trivy" => Some(K::Trivy),
        "Grype" => Some(K::Grype),
        "Syft" => Some(K::Syft),
        "Trufflehog" => Some(K::Trufflehog),
        "Semgrep" => Some(K::Semgrep),
        "KubeLinter" => Some(K::KubeLinter),
        "KubeBench" => Some(K::KubeBench),
        "KubeHunter" => Some(K::KubeHunter),
        "Polaris" => Some(K::Polaris),
        "StigCisValidator" => Some(K::StigCisValidator),
        "Zap" => Some(K::Zap),
        "Snyk" => Some(K::Snyk),
        "DockerScout" => Some(K::DockerScout),
        "JfrogXray" => Some(K::JfrogXray),
        "Wiz" => Some(K::Wiz),
        "PrismaCloud" => Some(K::PrismaCloud),
        "BurpEnterprise" => Some(K::BurpEnterprise),
        "Codeql" => Some(K::Codeql),
        _ => None,
    }
}

// ── ComplianceServiceImpl ─────────────────────────────────────────

pub struct ComplianceServiceImpl {
    pub store: Arc<ValidationStore>,
}

#[tonic::async_trait]
impl ComplianceService for ComplianceServiceImpl {
    async fn get_summary(
        &self,
        _req: Request<proto::Empty>,
    ) -> Result<Response<proto::ComplianceSummary>, Status> {
        let summary = validation_store::ops::query::compliance_summary(self.store.db())
            .await
            .map_err(|e| Status::internal(format!("store: {e}")))?;
        let total: u64 = summary.values().copied().sum();
        let by_phase = summary
            .into_iter()
            .map(|(phase, count)| proto::PhaseCount { phase, count })
            .collect();
        Ok(Response::new(proto::ComplianceSummary { by_phase, total }))
    }
}

// ── Server spawn helper ───────────────────────────────────────────

/// Build the tonic Server with all three services + reflection.
pub fn build_server(
    projection: Arc<ValidationProjection>,
    store: Arc<ValidationStore>,
) -> tonic::transport::server::Router {
    let validation_svc = ValidationServiceServer::new(ValidationServiceImpl {
        projection,
        store: store.clone(),
    });
    let scanner_svc = ScannerCatalogServiceServer::new(ScannerCatalogServiceImpl);
    let compliance_svc = ComplianceServiceServer::new(ComplianceServiceImpl { store });

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()
        .expect("tonic-reflection v1 builder");

    tonic::transport::Server::builder()
        .add_service(validation_svc)
        .add_service(scanner_svc)
        .add_service(compliance_svc)
        .add_service(reflection)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scanner_kind_total() {
        // Every catalog kind round-trips through the parser.
        for s in Catalog::all() {
            let label = format!("{:?}", s.kind);
            assert_eq!(parse_scanner_kind(&label), Some(s.kind), "round-trip {label}");
        }
        assert_eq!(parse_scanner_kind("UnknownThing"), None);
    }

    #[test]
    fn scanner_impl_to_proto_renders_fields() {
        let s = scanner_impl_to_proto(Catalog::for_kind(validation_crds::ScannerKind::Trivy));
        assert_eq!(s.kind, "Trivy");
        assert_eq!(s.class, "Cve");
        assert!(s.default_enabled);
        assert!(s.image.contains("trivy"));
        assert!(!s.args_template.is_empty());
        assert!(s.upstream_url.starts_with("https://"));
    }
}
