//! kube-hunter JSON parser. Schema:
//!
//! ```text
//! { "vulnerabilities": [{
//!     "vid": "KHV002", "category": "Information Disclosure",
//!     "severity": "medium", "vulnerability": "K8s API server exposed",
//!     "description": "..." }]}
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
    let Some(vulns) = value.get("vulnerabilities").and_then(|v| v.as_array()) else {
        return Ok(out);
    };
    for v in vulns {
        let severity = v
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .map(normalize_severity)
            .unwrap_or(validation_crds::ScanFindingSeverity::Medium);
        let vid = v.get("vid").and_then(serde_json::Value::as_str).unwrap_or("?");
        let name = v
            .get("vulnerability")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let message = format!("{vid}: {name}");
        out.push(make_finding(scanner, None, severity, None, None, Some(message)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_high_vuln() {
        let raw = r#"{"vulnerabilities":[{"vid":"KHV050","severity":"high","vulnerability":"Read access to pod logs"}]}"#;
        let f = parse(raw, ScannerKind::KubeHunter).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].message.as_deref().unwrap().contains("KHV050"));
    }
}
