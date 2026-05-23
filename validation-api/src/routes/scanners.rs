//! REST face for the `scanner-catalog` substrate crate. Exposes the
//! typed catalog at:
//!
//! - `GET /v1/scanners` — list every ScannerKind + ScannerImpl
//! - `GET /v1/scanners/:kind` — fetch one entry
//!
//! Both endpoints are read-only. The catalog is static (Rust code),
//! so introspection is cheap and deterministic.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use scanner_catalog::Catalog;
use serde::Serialize;

use crate::projection::ValidationProjection;

/// Serializable shape of a [`scanner_catalog::ScannerImpl`]. Same
/// field set as the gRPC `ScannerImpl` message — REST + gRPC speak
/// the same names.
#[derive(Serialize, Debug, Clone, utoipa::ToSchema)]
pub struct ScannerImplDto {
    pub kind: String,
    pub class: String,
    pub default_enabled: bool,
    pub image: String,
    pub target_field: String,
    pub args_template: Vec<String>,
    pub output_format: String,
    pub upstream_url: String,
}

impl From<scanner_catalog::ScannerImpl> for ScannerImplDto {
    fn from(s: scanner_catalog::ScannerImpl) -> Self {
        Self {
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
}

/// `GET /v1/scanners` — list every catalog entry.
#[utoipa::path(
    get,
    path = "/v1/scanners",
    responses(
        (status = 200, description = "Every scanner kind known to the platform",
         body = Vec<ScannerImplDto>)
    ),
    tag = "scanners"
)]
pub async fn list_scanners(
    State(_p): State<Arc<ValidationProjection>>,
) -> impl IntoResponse {
    let items: Vec<ScannerImplDto> = Catalog::all().map(Into::into).collect();
    (StatusCode::OK, Json(items))
}

/// `GET /v1/scanners/:kind` — fetch one entry. `:kind` is the
/// PascalCase ScannerKind variant (e.g. `Trivy`, `KubeLinter`).
#[utoipa::path(
    get,
    path = "/v1/scanners/{kind}",
    params(
        ("kind" = String, Path, description = "ScannerKind variant (PascalCase)")
    ),
    responses(
        (status = 200, description = "The catalog entry for the requested kind",
         body = ScannerImplDto),
        (status = 404, description = "Unknown ScannerKind")
    ),
    tag = "scanners"
)]
pub async fn get_scanner(
    State(_p): State<Arc<ValidationProjection>>,
    Path(kind): Path<String>,
) -> impl IntoResponse {
    let parsed = parse_kind(&kind);
    match parsed {
        Some(k) => (StatusCode::OK, Json(ScannerImplDto::from(Catalog::for_kind(k)))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            format!("unknown ScannerKind: {kind}"),
        )
            .into_response(),
    }
}

fn parse_kind(s: &str) -> Option<validation_crds::ScannerKind> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dto_roundtrip_trivy() {
        let dto: ScannerImplDto = Catalog::for_kind(validation_crds::ScannerKind::Trivy).into();
        assert_eq!(dto.kind, "Trivy");
        assert_eq!(dto.class, "Cve");
        assert!(dto.default_enabled);
        assert!(dto.image.contains("trivy"));
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("\"kind\":\"Trivy\""));
        assert!(json.contains("\"args_template\""));
    }

    #[test]
    fn parse_kind_total() {
        for entry in Catalog::all() {
            let label = format!("{:?}", entry.kind);
            assert_eq!(parse_kind(&label), Some(entry.kind), "parse {label}");
        }
        assert!(parse_kind("Frobnicator").is_none());
    }
}
