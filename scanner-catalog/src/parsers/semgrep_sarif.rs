//! SARIF v2.1.0 parser — Semgrep + CodeQL + many other SAST tools
//! emit this format. Single reusable parser.
//!
//! Schema (subset):
//!
//! ```text
//! { "runs": [{
//!     "tool": {"driver": {"name": "semgrep"}},
//!     "results": [{
//!         "ruleId": "rules/dangerous-eval",
//!         "level": "error",
//!         "message": {"text": "use of eval()"},
//!         "properties": {"severity": "HIGH"},
//!         "locations": [{
//!             "physicalLocation": {
//!                 "artifactLocation": {"uri": "src/foo.py"},
//!                 "region": {"startLine": 42}
//!             }
//!         }]
//!     }]
//! }]}
//! ```
//!
//! SARIF's `level` field is {"none","note","warning","error"} — we
//! map to severity. Many SARIF emitters ALSO ship a
//! `properties.severity` with Semgrep's own scale; if present, that
//! takes precedence (closer to the tool's intent).

use validation_crds::{ScanFinding, ScanFindingSeverity, ScannerKind};

use super::{make_finding, normalize_severity, ParserError};

pub fn parse(raw: &str, scanner: ScannerKind) -> Result<Vec<ScanFinding>, ParserError> {
    let value: serde_json::Value =
        serde_json::from_str(raw.trim_start()).map_err(|e| ParserError::Json {
            scanner,
            detail: e.to_string(),
        })?;
    let mut out = Vec::new();
    let runs = value.get("runs").and_then(|v| v.as_array());
    let Some(runs) = runs else { return Ok(out); };
    for run in runs {
        let Some(results) = run.get("results").and_then(|v| v.as_array()) else {
            continue;
        };
        for r in results {
            let rule_id = r
                .get("ruleId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            // Prefer properties.severity over SARIF level.
            let severity = r
                .get("properties")
                .and_then(|p| p.get("severity"))
                .and_then(serde_json::Value::as_str)
                .map(normalize_severity)
                .or_else(|| {
                    r.get("level")
                        .and_then(serde_json::Value::as_str)
                        .map(map_sarif_level)
                })
                .unwrap_or(ScanFindingSeverity::Low);
            let msg_text = r
                .get("message")
                .and_then(|m| m.get("text"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let loc = r
                .get("locations")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|l| l.get("physicalLocation"))
                .and_then(|p| p.get("artifactLocation"))
                .and_then(|a| a.get("uri"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let message = match (rule_id.as_deref(), msg_text, loc) {
                (Some(r), "", "") => Some(r.to_owned()),
                (Some(r), m, "") => Some(format!("{r}: {m}")),
                (Some(r), m, l) => Some(format!("{r} at {l}: {m}")),
                (None, m, l) if !l.is_empty() => Some(format!("at {l}: {m}")),
                (None, m, _) => Some(m.to_owned()),
            };
            // SARIF `ruleId` isn't a CVE; stash it in cve_id only
            // when it actually looks like one.
            let cve_id = rule_id
                .as_deref()
                .filter(|s| s.starts_with("CVE-"))
                .map(str::to_owned);
            out.push(make_finding(scanner, cve_id, severity, None, None, message));
        }
    }
    Ok(out)
}

fn map_sarif_level(level: &str) -> ScanFindingSeverity {
    match level {
        "error" => ScanFindingSeverity::High,
        "warning" => ScanFindingSeverity::Medium,
        _ => ScanFindingSeverity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_semgrep_sarif_with_properties_severity() {
        let raw = r#"{
          "runs": [{
            "results": [{
              "ruleId": "python.lang.security.audit.exec-use",
              "level": "error",
              "properties": {"severity": "ERROR"},
              "message": {"text": "Use of exec() is dangerous"},
              "locations": [{"physicalLocation":
                {"artifactLocation": {"uri": "src/foo.py"},
                 "region": {"startLine": 42}}}]
            }]
          }]
        }"#;
        let f = parse(raw, ScannerKind::Semgrep).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].message.as_deref().unwrap().contains("python.lang.security"));
        assert!(f[0].message.as_deref().unwrap().contains("src/foo.py"));
    }

    #[test]
    fn empty_runs_is_clean() {
        assert!(parse(r#"{"runs":[]}"#, ScannerKind::Semgrep).unwrap().is_empty());
    }
}
