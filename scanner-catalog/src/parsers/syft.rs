//! Syft SPDX-JSON SBOM parser. Syft doesn't report vulnerabilities —
//! it catalogs packages. We emit one Low-severity "sbom-package"
//! finding per package so the security-controller's
//! `RequiredAttestation::SbomSpdx` check sees the SBOM coverage as
//! present.
//!
//! Schema (subset):
//!
//! ```text
//! { "packages": [
//!     { "name": "openssl", "versionInfo": "1.1.1k",
//!       "externalRefs": [{ "referenceType": "purl",
//!                          "referenceLocator": "pkg:..." }] },
//!     ...
//! ]}
//! ```

use validation_crds::{ScanFinding, ScanFindingSeverity, ScannerKind};

use super::{make_finding, ParserError};

pub fn parse(raw: &str, scanner: ScannerKind) -> Result<Vec<ScanFinding>, ParserError> {
    let value: serde_json::Value =
        serde_json::from_str(raw.trim_start()).map_err(|e| ParserError::Json {
            scanner,
            detail: e.to_string(),
        })?;
    let Some(packages) = value.get("packages").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };
    let mut out = Vec::with_capacity(packages.len());
    for p in packages {
        let name = p.get("name").and_then(serde_json::Value::as_str).unwrap_or("");
        let version = p
            .get("versionInfo")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let message = if version.is_empty() {
            format!("sbom-package: {name}")
        } else {
            format!("sbom-package: {name}@{version}")
        };
        // SBOM entries are informational, not vulnerabilities — Low
        // severity with no CVE. The security-controller's
        // `RequiredAttestation::SbomSpdx` is satisfied by the
        // *presence* of these rows.
        out.push(make_finding(
            scanner,
            None,
            ScanFindingSeverity::Low,
            None,
            None,
            Some(message),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sbom_emits_one_finding_per_package() {
        let raw = r#"{
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "openssl", "versionInfo": "1.1.1k"},
                {"name": "zlib", "versionInfo": "1.2.13"},
                {"name": "no-version-pkg"}
            ]
        }"#;
        let f = parse(raw, ScannerKind::Syft).unwrap();
        assert_eq!(f.len(), 3);
        assert!(f[0].message.as_deref().unwrap().contains("openssl@1.1.1k"));
        assert!(f[2].message.as_deref().unwrap().contains("no-version-pkg"));
        assert!(f.iter().all(|x| x.severity == ScanFindingSeverity::Low));
        assert!(f.iter().all(|x| x.cve_id.is_none()));
    }

    #[test]
    fn empty_sbom_is_clean() {
        assert!(parse(r#"{"packages":[]}"#, ScannerKind::Syft).unwrap().is_empty());
    }
}
