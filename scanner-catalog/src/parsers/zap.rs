//! OWASP ZAP JSON parser (zap-baseline.py output).
//!
//! Schema (simplified):
//!
//! ```text
//! { "site": [{
//!     "@name": "https://target",
//!     "alerts": [{
//!         "pluginid": "10038",
//!         "alert": "Content Security Policy (CSP) Header Not Set",
//!         "riskdesc": "Medium (High)",   // "Risk (Confidence)"
//!         "cweid": "693",
//!         "wascid": "15",
//!         "desc": "..."
//!     }]
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
    let Some(sites) = value.get("site").and_then(|v| v.as_array()) else {
        return Ok(out);
    };
    for site in sites {
        let Some(alerts) = site.get("alerts").and_then(|v| v.as_array()) else { continue };
        for a in alerts {
            let name = a.get("alert").and_then(serde_json::Value::as_str).unwrap_or("");
            let risk = a
                .get("riskdesc")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Low");
            // "Medium (High)" → take the first token before space
            let severity_str = risk.split_whitespace().next().unwrap_or("Low");
            let severity = normalize_severity(severity_str);
            let message = format!("ZAP: {name}");
            out.push(make_finding(scanner, None, severity, None, None, Some(message)));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use validation_crds::ScanFindingSeverity;

    #[test]
    fn parse_medium_alert() {
        let raw = r#"{
          "site": [{
            "@name": "https://test.example",
            "alerts": [{"alert": "CSP Header Not Set", "riskdesc": "Medium (High)"}]
          }]
        }"#;
        let f = parse(raw, ScannerKind::Zap).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, ScanFindingSeverity::Medium);
        assert!(f[0].message.as_deref().unwrap().contains("CSP"));
    }

    #[test]
    fn empty_site_clean() {
        assert!(parse(r#"{"site":[]}"#, ScannerKind::Zap).unwrap().is_empty());
    }
}
