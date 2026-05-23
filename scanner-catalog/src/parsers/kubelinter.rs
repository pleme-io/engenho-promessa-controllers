//! KubeLinter JSON parser. Schema:
//!
//! ```text
//! { "Reports": [{
//!     "Diagnostic": {"Message": "...", "Severity": "warning"},
//!     "Check": "no-extensions-v1beta",
//!     "Object": {"K8sObject": {"GroupVersionKind": "apps/v1/Deployment",
//!                              "Namespace": "default", "Name": "foo"}}
//! }] }
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
    let Some(reports) = value.get("Reports").and_then(|v| v.as_array()) else {
        return Ok(out);
    };
    for r in reports {
        let check = r
            .get("Check")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let diag = r.get("Diagnostic");
        let msg = diag
            .and_then(|d| d.get("Message"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let severity = diag
            .and_then(|d| d.get("Severity"))
            .and_then(serde_json::Value::as_str)
            .map(normalize_severity)
            .unwrap_or(ScanFindingSeverity::Medium);
        let obj = r
            .get("Object")
            .and_then(|o| o.get("K8sObject"));
        let target = match (
            obj.and_then(|o| o.get("Namespace")).and_then(serde_json::Value::as_str),
            obj.and_then(|o| o.get("Name")).and_then(serde_json::Value::as_str),
        ) {
            (Some(ns), Some(n)) => format!("{ns}/{n}"),
            (None, Some(n)) => n.to_owned(),
            _ => String::new(),
        };
        let message = if target.is_empty() {
            format!("{check}: {msg}")
        } else {
            format!("{check} on {target}: {msg}")
        };
        out.push(make_finding(scanner, None, severity, None, None, Some(message)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reports() {
        let raw = r#"{
          "Reports": [{
            "Diagnostic": {"Message": "no liveness probe", "Severity": "warning"},
            "Check": "unset-cpu-requirements",
            "Object": {"K8sObject": {"Namespace": "default", "Name": "foo"}}
          }]
        }"#;
        let f = parse(raw, ScannerKind::KubeLinter).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, ScanFindingSeverity::Medium);
        assert!(f[0].message.as_deref().unwrap().contains("default/foo"));
    }

    #[test]
    fn empty_reports_clean() {
        assert!(parse(r#"{"Reports":[]}"#, ScannerKind::KubeLinter).unwrap().is_empty());
    }
}
