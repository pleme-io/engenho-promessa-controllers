//! Trivy native JSON parser. Schema:
//!
//! ```text
//! { "Results": [{ "Vulnerabilities": [{ "VulnerabilityID", "Severity",
//!     "CVSS": {"nvd": {"V3Score": 7.5}}, "FixedVersion", "Title",
//!     "PkgName" }, ...] }, ...] }
//! ```
//!
//! Empty `Vulnerabilities` arrays (and missing `Results`) yield an
//! empty findings vector — a clean scan, not a parser failure.

use validation_crds::{ScanFinding, ScannerKind};

use super::{make_finding, normalize_severity, ParserError};

pub fn parse(raw: &str, scanner: ScannerKind) -> Result<Vec<ScanFinding>, ParserError> {
    let value: serde_json::Value = serde_json::from_str(raw.trim_start())
        .map_err(|e| ParserError::Json {
            scanner,
            detail: e.to_string(),
        })?;

    let mut out = Vec::new();
    let results = value.get("Results").and_then(|v| v.as_array());
    let Some(results) = results else {
        return Ok(out);
    };
    for r in results {
        let Some(vulns) = r.get("Vulnerabilities").and_then(|v| v.as_array()) else {
            continue;
        };
        for v in vulns {
            let cve_id = v
                .get("VulnerabilityID")
                .and_then(|s| s.as_str())
                .map(str::to_owned);
            let severity = v
                .get("Severity")
                .and_then(|s| s.as_str())
                .map(normalize_severity)
                .unwrap_or(validation_crds::ScanFindingSeverity::Low);
            let cvss_v3 = v
                .get("CVSS")
                .and_then(|c| c.get("nvd"))
                .and_then(|n| n.get("V3Score"))
                .and_then(serde_json::Value::as_f64)
                .map(|f| f as f32);
            let fixed_in = v
                .get("FixedVersion")
                .and_then(|s| s.as_str())
                .map(str::to_owned);
            let pkg = v
                .get("PkgName")
                .and_then(|s| s.as_str())
                .map(str::to_owned);
            let title = v
                .get("Title")
                .and_then(|s| s.as_str())
                .map(str::to_owned);
            let message = match (pkg, title) {
                (Some(p), Some(t)) => Some(format!("{p}: {t}")),
                (Some(p), None) => Some(p),
                (None, Some(t)) => Some(t),
                (None, None) => None,
            };
            out.push(make_finding(scanner, cve_id, severity, cvss_v3, fixed_in, message));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use validation_crds::ScanFindingSeverity;

    #[test]
    fn parse_two_vulns() {
        let raw = r#"{
            "Results": [{
                "Target": "alpine:3.18 (alpine 3.18.0)",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH",
                     "CVSS": {"nvd": {"V3Score": 7.5}},
                     "FixedVersion": "1.2.3", "PkgName": "libfoo",
                     "Title": "libfoo buffer overflow"},
                    {"VulnerabilityID": "CVE-2024-0002", "Severity": "MEDIUM",
                     "PkgName": "libbar"}
                ]
            }]
        }"#;
        let f = parse(raw, ScannerKind::Trivy).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].scanner, ScannerKind::Trivy);
        assert_eq!(f[0].cve_id.as_deref(), Some("CVE-2024-0001"));
        assert_eq!(f[0].severity, ScanFindingSeverity::High);
        assert_eq!(f[0].cvss_v3, Some(7.5));
        assert_eq!(f[0].fixed_in.as_deref(), Some("1.2.3"));
        assert!(f[0].message.as_deref().unwrap().contains("libfoo"));
        assert_eq!(f[1].severity, ScanFindingSeverity::Medium);
    }

    #[test]
    fn empty_results_is_clean() {
        let raw = r#"{"Results": []}"#;
        assert!(parse(raw, ScannerKind::Trivy).unwrap().is_empty());
    }

    #[test]
    fn missing_results_is_clean() {
        let raw = r#"{}"#;
        assert!(parse(raw, ScannerKind::Trivy).unwrap().is_empty());
    }

    #[test]
    fn malformed_json_errors() {
        let err = parse("{not json", ScannerKind::Trivy).unwrap_err();
        assert!(matches!(err, ParserError::Json { .. }));
    }
}
