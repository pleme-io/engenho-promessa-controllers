//! Per-scanner output parsers. Each parser maps the scanner's native
//! JSON shape into a typed `Vec<ScanFinding>`. Severity normalized to
//! [`validation_crds::ScanFindingSeverity`] (Low/Medium/High/Critical
//! — anything Negligible or Info collapses to Low).
//!
//! Dispatch via [`parse_scanner_output`] which reads the kind's
//! [`crate::catalog::OutputFormat`] from the catalog and routes to
//! the right parser.

use chrono::Utc;
use thiserror::Error;
use validation_crds::{ScanFinding, ScanFindingSeverity, ScannerKind};

use crate::catalog::{Catalog, OutputFormat};

pub mod grype;
pub mod kube_bench;
pub mod kube_hunter;
pub mod kubelinter;
pub mod polaris;
pub mod semgrep_sarif;
pub mod syft;
pub mod trivy;
pub mod trufflehog;
pub mod zap;

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("malformed JSON for {scanner:?}: {detail}")]
    Json {
        scanner: ScannerKind,
        detail: String,
    },
    #[error("no parser for {scanner:?} (output_format = NoOp)")]
    NoParser { scanner: ScannerKind },
}

/// Dispatch the raw scanner stdout to the right parser.
///
/// Returns `Ok(findings)` on a successful parse (even if the findings
/// vector is empty — a clean scan).
///
/// Returns `Err(ParserError::Json)` if the JSON shape doesn't match
/// the scanner's documented schema (regression / version drift). The
/// scan_job reconciler treats this as a `Failed` phase.
///
/// Returns `Err(ParserError::NoParser)` for scanners whose
/// `output_format == NoOp` (commercial/heavy scanners we don't yet
/// interpret). Callers may treat this as "scanner ran but findings
/// not surfaced" and log a tracing warning.
///
/// # Errors
///
/// See variants of [`ParserError`].
pub fn parse_scanner_output(
    raw: &str,
    scanner: ScannerKind,
) -> Result<Vec<ScanFinding>, ParserError> {
    let impl_ = Catalog::for_kind(scanner);
    match impl_.output_format {
        OutputFormat::TrivyJson => trivy::parse(raw, scanner),
        OutputFormat::GrypeJson => grype::parse(raw, scanner),
        OutputFormat::SyftSpdx => syft::parse(raw, scanner),
        OutputFormat::TrufflehogNdjson => trufflehog::parse(raw, scanner),
        OutputFormat::SemgrepSarif => semgrep_sarif::parse(raw, scanner),
        OutputFormat::KubeLinterJson => kubelinter::parse(raw, scanner),
        OutputFormat::KubeBenchJson => kube_bench::parse(raw, scanner),
        OutputFormat::KubeHunterJson => kube_hunter::parse(raw, scanner),
        OutputFormat::PolarisJson => polaris::parse(raw, scanner),
        OutputFormat::ZapJson => zap::parse(raw, scanner),
        OutputFormat::NoOp => Err(ParserError::NoParser { scanner }),
    }
}

/// Normalize an arbitrary severity string to
/// [`ScanFindingSeverity`]. Case-insensitive. Falls through to Low
/// for unknown values (defense — don't drop a finding because
/// upstream renamed a tier).
#[must_use]
pub fn normalize_severity(raw: &str) -> ScanFindingSeverity {
    match raw.to_ascii_uppercase().as_str() {
        "CRITICAL" | "VERY-HIGH" | "VERY_HIGH" => ScanFindingSeverity::Critical,
        "HIGH" => ScanFindingSeverity::High,
        "MEDIUM" | "MODERATE" | "WARNING" => ScanFindingSeverity::Medium,
        "LOW" | "INFO" | "INFORMATIONAL" | "NEGLIGIBLE" | "UNKNOWN" => ScanFindingSeverity::Low,
        _ => ScanFindingSeverity::Low,
    }
}

/// Helper — construct a finding with the scanner stamped + a fresh
/// `first_seen` timestamp. Used by every parser.
#[must_use]
pub fn make_finding(
    scanner: ScannerKind,
    cve_id: Option<String>,
    severity: ScanFindingSeverity,
    cvss_v3: Option<f32>,
    fixed_in: Option<String>,
    message: Option<String>,
) -> ScanFinding {
    ScanFinding {
        scanner,
        cve_id,
        severity,
        first_seen: Utc::now(),
        fixed_in,
        exception_id: None,
        cvss_v3,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_normalization() {
        assert_eq!(normalize_severity("Critical"), ScanFindingSeverity::Critical);
        assert_eq!(normalize_severity("HIGH"), ScanFindingSeverity::High);
        assert_eq!(normalize_severity("Moderate"), ScanFindingSeverity::Medium);
        assert_eq!(normalize_severity("info"), ScanFindingSeverity::Low);
        assert_eq!(normalize_severity("zomg-extreme"), ScanFindingSeverity::Low);
    }

    #[test]
    fn no_parser_for_noop_kinds() {
        // Snyk has OutputFormat::NoOp by default — calls return NoParser.
        let err = parse_scanner_output("{}", ScannerKind::Snyk).unwrap_err();
        match err {
            ParserError::NoParser { scanner: ScannerKind::Snyk } => {}
            other => panic!("expected NoParser for Snyk, got {other:?}"),
        }
    }
}
