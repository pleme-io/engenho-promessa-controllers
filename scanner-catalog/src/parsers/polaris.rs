//! Polaris JSON parser. Schema:
//!
//! ```text
//! { "Results": [{
//!     "Name": "deployment-foo", "Namespace": "default",
//!     "Kind": "Deployment",
//!     "Results": {"check-id": {"Success": false, "Severity": "warning",
//!                              "Message": "..."}}
//! }]}
//! ```

use validation_crds::{ScanFinding, ScanFindingSeverity, ScannerKind};

use super::{make_finding, normalize_severity, ParserError};

pub fn parse(raw: &str, scanner: ScannerKind) -> Result<Vec<ScanFinding>, ParserError> {
    let value: serde_json::Value =
        serde_json::from_str(raw.trim_start()).map_err(|e| ParserError::Json {
            scanner,
            detail: e.to_string(),
        })?;
    let mut out = Vec::new();
    let Some(items) = value.get("Results").and_then(|v| v.as_array()) else {
        return Ok(out);
    };
    for item in items {
        let ns = item
            .get("Namespace")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let name = item.get("Name").and_then(serde_json::Value::as_str).unwrap_or("");
        let kind = item.get("Kind").and_then(serde_json::Value::as_str).unwrap_or("");
        let target = format!("{kind}/{ns}/{name}");

        let Some(check_results) = item.get("Results").and_then(|v| v.as_object()) else {
            continue;
        };
        for (check_id, body) in check_results {
            let success = body
                .get("Success")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            if success {
                continue;
            }
            let severity = body
                .get("Severity")
                .and_then(serde_json::Value::as_str)
                .map(normalize_severity)
                .unwrap_or(ScanFindingSeverity::Medium);
            let msg = body
                .get("Message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let message = format!("{check_id} on {target}: {msg}");
            out.push(make_finding(scanner, None, severity, None, None, Some(message)));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_failing_check() {
        let raw = r#"{
          "Results": [{
            "Name": "foo", "Namespace": "default", "Kind": "Deployment",
            "Results": {
              "runAsRootAllowed": {"Success": false, "Severity": "danger",
                                   "Message": "should not run as root"}
            }
          }]
        }"#;
        let f = parse(raw, ScannerKind::Polaris).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].message.as_deref().unwrap().contains("runAsRootAllowed"));
    }
}
