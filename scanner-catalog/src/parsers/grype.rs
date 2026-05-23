//! Grype native JSON parser. Schema:
//!
//! ```text
//! { "matches": [{
//!     "vulnerability": {"id": "CVE-2024-0001", "severity": "High",
//!                       "cvss": [{"version": "3.1", "metrics": {"baseScore": 7.5}}],
//!                       "fix": {"versions": ["1.2.3"], "state": "fixed"}},
//!     "artifact": {"name": "libfoo", "version": "1.0.0"}
//! }] }
//! ```

use validation_crds::{ScanFinding, ScannerKind};

use super::{make_finding, normalize_severity, ParserError};

pub fn parse(raw: &str, scanner: ScannerKind) -> Result<Vec<ScanFinding>, ParserError> {
    let value: serde_json::Value =
        serde_json::from_str(raw.trim_start()).map_err(|e| ParserError::Json {
            scanner,
            detail: e.to_string(),
        })?;

    let mut out = Vec::new();
    let Some(matches) = value.get("matches").and_then(|v| v.as_array()) else {
        return Ok(out);
    };
    for m in matches {
        let vuln = m.get("vulnerability");
        let cve_id = vuln
            .and_then(|v| v.get("id"))
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        let severity = vuln
            .and_then(|v| v.get("severity"))
            .and_then(|s| s.as_str())
            .map(normalize_severity)
            .unwrap_or(validation_crds::ScanFindingSeverity::Low);
        let cvss_v3 = vuln
            .and_then(|v| v.get("cvss"))
            .and_then(|a| a.as_array())
            .and_then(|a| {
                a.iter().find_map(|entry| {
                    let v = entry.get("version").and_then(serde_json::Value::as_str)?;
                    if v.starts_with("3.") {
                        entry
                            .get("metrics")
                            .and_then(|m| m.get("baseScore"))
                            .and_then(serde_json::Value::as_f64)
                            .map(|f| f as f32)
                    } else {
                        None
                    }
                })
            });
        let fixed_in = vuln
            .and_then(|v| v.get("fix"))
            .and_then(|f| f.get("versions"))
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let pkg = m
            .get("artifact")
            .and_then(|a| a.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let message = pkg.map(|p| format!("{p}"));
        out.push(make_finding(scanner, cve_id, severity, cvss_v3, fixed_in, message));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use validation_crds::ScanFindingSeverity;

    #[test]
    fn parse_with_cvss_v3_and_fix() {
        let raw = r#"{
          "matches": [{
            "vulnerability": {
              "id": "CVE-2024-9999",
              "severity": "Critical",
              "cvss": [{"version": "3.1", "metrics": {"baseScore": 9.8}}],
              "fix": {"versions": ["2.0.1"], "state": "fixed"}
            },
            "artifact": {"name": "openssl", "version": "1.0.0"}
          }]
        }"#;
        let f = parse(raw, ScannerKind::Grype).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, ScanFindingSeverity::Critical);
        assert_eq!(f[0].cvss_v3, Some(9.8));
        assert_eq!(f[0].fixed_in.as_deref(), Some("2.0.1"));
        assert!(f[0].message.as_deref().unwrap().contains("openssl"));
    }

    #[test]
    fn missing_matches_is_clean() {
        assert!(parse(r#"{}"#, ScannerKind::Grype).unwrap().is_empty());
    }
}
