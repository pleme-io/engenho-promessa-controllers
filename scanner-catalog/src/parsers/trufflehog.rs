//! Trufflehog NDJSON parser — one JSON object per line. Each row is
//! a secret hit. We map every Trufflehog hit to a High-severity
//! finding (secrets in source are uniformly serious).
//!
//! Schema (per line):
//!
//! ```text
//! {"DetectorName":"AWS","DetectorType":2,"Verified":true,
//!  "Raw":"AKIA...","SourceMetadata":{"Data":{"Git":{"file":"...",
//!  "commit":"abc","line":12}}}}
//! ```

use validation_crds::{ScanFinding, ScanFindingSeverity, ScannerKind};

use super::{make_finding, ParserError};

pub fn parse(raw: &str, scanner: ScannerKind) -> Result<Vec<ScanFinding>, ParserError> {
    let mut out = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                // First line might be a banner / non-JSON header in some
                // Trufflehog versions. Tolerate one such non-JSON line
                // at the start; error otherwise.
                if idx == 0 {
                    continue;
                }
                return Err(ParserError::Json {
                    scanner,
                    detail: format!("line {idx}: {e}"),
                });
            }
        };
        let detector = v.get("DetectorName").and_then(serde_json::Value::as_str).unwrap_or("?");
        let verified = v.get("Verified").and_then(serde_json::Value::as_bool).unwrap_or(false);
        let path = v
            .get("SourceMetadata")
            .and_then(|m| m.get("Data"))
            .and_then(|d| d.get("Git"))
            .and_then(|g| g.get("file"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        let message = if verified {
            format!("verified secret ({detector}) at {path}")
        } else {
            format!("unverified secret ({detector}) at {path}")
        };
        let severity = if verified {
            ScanFindingSeverity::Critical
        } else {
            ScanFindingSeverity::High
        };
        out.push(make_finding(scanner, None, severity, None, None, Some(message)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verified_and_unverified() {
        let raw = "\
{\"DetectorName\":\"AWS\",\"Verified\":true,\"SourceMetadata\":{\"Data\":{\"Git\":{\"file\":\"src/cfg.go\"}}}}
{\"DetectorName\":\"GitHub\",\"Verified\":false,\"SourceMetadata\":{\"Data\":{\"Git\":{\"file\":\"README.md\"}}}}
";
        let f = parse(raw, ScannerKind::Trufflehog).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, ScanFindingSeverity::Critical);
        assert!(f[0].message.as_deref().unwrap().contains("AWS"));
        assert_eq!(f[1].severity, ScanFindingSeverity::High);
    }

    #[test]
    fn skip_first_non_json_banner() {
        let raw = "🐷 Trufflehog v3.78.0 starting…\n{\"DetectorName\":\"Slack\",\"Verified\":true,\"SourceMetadata\":{\"Data\":{\"Git\":{\"file\":\"x\"}}}}\n";
        let f = parse(raw, ScannerKind::Trufflehog).unwrap();
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn empty_is_clean() {
        assert!(parse("", ScannerKind::Trufflehog).unwrap().is_empty());
    }
}
