//! kube-bench JSON parser. Schema:
//!
//! ```text
//! { "Controls": [{
//!     "tests": [{
//!         "results": [{
//!             "test_number": "1.1.1",
//!             "test_desc": "Ensure that the API server pod specification file permissions are set",
//!             "status": "FAIL",   // PASS | FAIL | WARN
//!             "remediation": "chmod 644 ..."
//!         }]
//!     }]
//! }] }
//! ```
//!
//! Maps FAIL → High, WARN → Medium, PASS → skipped (no finding).

use validation_crds::{ScanFinding, ScanFindingSeverity, ScannerKind};

use super::{make_finding, ParserError};

pub fn parse(raw: &str, scanner: ScannerKind) -> Result<Vec<ScanFinding>, ParserError> {
    let value: serde_json::Value =
        serde_json::from_str(raw.trim_start()).map_err(|e| ParserError::Json {
            scanner,
            detail: e.to_string(),
        })?;
    let mut out = Vec::new();
    let Some(controls) = value.get("Controls").and_then(|v| v.as_array()) else {
        return Ok(out);
    };
    for c in controls {
        let Some(tests) = c.get("tests").and_then(|v| v.as_array()) else { continue };
        for t in tests {
            let Some(results) = t.get("results").and_then(|v| v.as_array()) else { continue };
            for r in results {
                let status = r
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("PASS");
                let severity = match status {
                    "FAIL" => ScanFindingSeverity::High,
                    "WARN" => ScanFindingSeverity::Medium,
                    _ => continue, // PASS / INFO — skip
                };
                let test_no = r
                    .get("test_number")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let desc = r
                    .get("test_desc")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let message = format!("CIS {test_no}: {desc}");
                out.push(make_finding(scanner, None, severity, None, None, Some(message)));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fail_and_warn_and_pass() {
        let raw = r#"{
          "Controls": [{
            "tests": [{
              "results": [
                {"test_number":"1.1.1","test_desc":"perms","status":"FAIL"},
                {"test_number":"1.1.2","test_desc":"owners","status":"WARN"},
                {"test_number":"1.1.3","test_desc":"ok","status":"PASS"}
              ]
            }]
          }]
        }"#;
        let f = parse(raw, ScannerKind::KubeBench).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, ScanFindingSeverity::High);
        assert_eq!(f[1].severity, ScanFindingSeverity::Medium);
    }
}
