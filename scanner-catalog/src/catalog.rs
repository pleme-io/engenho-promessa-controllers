//! Typed `ScannerImpl` per [`ScannerKind`] — the canonical catalog.
//!
//! Every entry pins:
//! - The OCI image to spawn (pinned major+minor; floating patch OK)
//! - Where the scan target threads in (`Digest` / `Source` /
//!   `TenantUrl` / `None`) — controls which `ScanJob.spec` field the
//!   reconciler reads
//! - The CLI args template — `${target}` substituted at runtime
//! - The output format — drives which parser in [`crate::parsers`]
//!   interprets the scanner's stdout JSON
//! - `default_enabled`: OSS without creds → true; commercial gated
//!   on cofre tokens → false; heavy setup → false
//! - `upstream_url`: doc-only pointer to the scanner's project page

use validation_crds::{ScannerClass, ScannerKind};

/// What field on a [`validation_crds::ScanJobSpec`] carries the
/// target for this scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetField {
    /// `.spec.target_digest` — CVE / SBOM scanners that operate on an
    /// OCI image.
    Digest,
    /// `.spec.target_source` — SAST / secret scanners that operate on
    /// a source git URL+ref.
    Source,
    /// `.spec.target_tenant_url` — DAST scanners that probe a live
    /// ephemeral-tenant URL.
    TenantUrl,
    /// No per-target arg — the scanner is "scan the cluster" / "scan
    /// these YAMLs" / etc. and doesn't pull a value from the CR.
    None,
}

/// CLI args for a scanner — static for now; `${target}` is the only
/// supported placeholder, substituted at runtime via
/// [`ArgsTemplate::render`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgsTemplate {
    /// Static argv. Any element equal to `"${target}"` is replaced by
    /// the resolved target value.
    Static(&'static [&'static str]),
}

impl ArgsTemplate {
    /// Render the template against the target value (if any). Empty
    /// substitution for `None`-targeted scanners.
    #[must_use]
    pub fn render(&self, target: Option<&str>) -> Vec<String> {
        match self {
            ArgsTemplate::Static(args) => args
                .iter()
                .map(|s| {
                    if *s == "${target}" {
                        target.unwrap_or_default().to_owned()
                    } else {
                        (*s).to_owned()
                    }
                })
                .collect(),
        }
    }
}

/// How the scanner emits findings. Each variant pins one parser in
/// [`crate::parsers`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// Trivy's native JSON shape (`Results[].Vulnerabilities[]`).
    TrivyJson,
    /// Grype's native JSON shape (`matches[].vulnerability`).
    GrypeJson,
    /// Syft's SPDX-JSON SBOM (`packages[]`) — emits one info-severity
    /// finding per detected package so callers can audit the catalog.
    SyftSpdx,
    /// Trufflehog's NDJSON (one JSON object per line). The parser is
    /// line-delimited.
    TrufflehogNdjson,
    /// Semgrep SARIF output (`runs[].results[]`).
    SemgrepSarif,
    /// KubeLinter JSON output (`Reports[]`).
    KubeLinterJson,
    /// kube-bench JSON output (`Controls[].tests[].results[]`).
    KubeBenchJson,
    /// kube-hunter JSON output (`vulnerabilities[]`).
    KubeHunterJson,
    /// Polaris JSON output (`Results[]`).
    PolarisJson,
    /// OWASP ZAP JSON output (`site[].alerts[]`).
    ZapJson,
    /// No parser yet — scanners we can spawn but don't yet interpret.
    /// Falls through to an empty `Vec<ScanFinding>` with a tracing
    /// warning so operators see the scanner ran but didn't surface.
    NoOp,
}

/// One catalog entry — the typed bag of `(image, args, target,
/// output)` for a single [`ScannerKind`].
#[derive(Clone, Debug)]
pub struct ScannerImpl {
    pub kind: ScannerKind,
    pub class: ScannerClass,
    pub default_enabled: bool,
    pub image: &'static str,
    pub target_field: TargetField,
    pub args: ArgsTemplate,
    pub output_format: OutputFormat,
    pub upstream_url: &'static str,
}

/// The catalog. Zero-sized; methods are all static / const-ish.
pub struct Catalog;

impl Catalog {
    /// Resolve the [`ScannerImpl`] for a kind. Total — every variant
    /// has an entry, even commercial / heavy ones (their entries set
    /// `default_enabled: false` + `output_format: NoOp`).
    #[must_use]
    pub fn for_kind(kind: ScannerKind) -> ScannerImpl {
        use OutputFormat as O;
        use ScannerClass as C;
        use ScannerKind as K;
        use TargetField as T;
        match kind {
            // ── OSS CVE ───────────────────────────────────────────
            K::Trivy => ScannerImpl {
                kind: K::Trivy,
                class: C::Cve,
                default_enabled: true,
                image: "aquasec/trivy:0.50.0",
                target_field: T::Digest,
                args: ArgsTemplate::Static(&[
                    "image",
                    "--format=json",
                    "--severity=CRITICAL,HIGH,MEDIUM,LOW",
                    "--output=/scan/result.json",
                    "${target}",
                ]),
                output_format: O::TrivyJson,
                upstream_url: "https://github.com/aquasecurity/trivy",
            },
            K::Grype => ScannerImpl {
                kind: K::Grype,
                class: C::Cve,
                default_enabled: true,
                image: "anchore/grype:v0.74.7",
                target_field: T::Digest,
                args: ArgsTemplate::Static(&[
                    "${target}",
                    "-o", "json",
                    "--file", "/scan/result.json",
                    "--fail-on", "negligible",
                ]),
                output_format: O::GrypeJson,
                upstream_url: "https://github.com/anchore/grype",
            },
            // ── OSS SBOM ──────────────────────────────────────────
            K::Syft => ScannerImpl {
                kind: K::Syft,
                class: C::Cve, // SBOM rides on CVE class; parser emits info-level rows
                default_enabled: true,
                image: "anchore/syft:v1.4.1",
                target_field: T::Digest,
                args: ArgsTemplate::Static(&[
                    "${target}",
                    "-o", "spdx-json=/scan/result.json",
                ]),
                output_format: O::SyftSpdx,
                upstream_url: "https://github.com/anchore/syft",
            },
            // ── OSS secrets ───────────────────────────────────────
            K::Trufflehog => ScannerImpl {
                kind: K::Trufflehog,
                class: C::Sast,
                default_enabled: true,
                image: "trufflesecurity/trufflehog:3.78.0",
                target_field: T::Source,
                args: ArgsTemplate::Static(&[
                    "git",
                    "${target}",
                    "--json",
                    "--no-update",
                ]),
                output_format: O::TrufflehogNdjson,
                upstream_url: "https://github.com/trufflesecurity/trufflehog",
            },
            // ── OSS SAST ──────────────────────────────────────────
            K::Semgrep => ScannerImpl {
                kind: K::Semgrep,
                class: C::Sast,
                default_enabled: true,
                image: "returntocorp/semgrep:1.78.0",
                target_field: T::Source,
                args: ArgsTemplate::Static(&[
                    "semgrep",
                    "--config=auto",
                    "--sarif",
                    "--output=/scan/result.json",
                    "${target}",
                ]),
                output_format: O::SemgrepSarif,
                upstream_url: "https://github.com/semgrep/semgrep",
            },
            // ── OSS K8s posture ───────────────────────────────────
            K::KubeLinter => ScannerImpl {
                kind: K::KubeLinter,
                class: C::Hardening,
                default_enabled: true,
                image: "stackrox/kube-linter:v0.6.8",
                target_field: T::Source,
                args: ArgsTemplate::Static(&[
                    "lint",
                    "${target}",
                    "--format=json",
                ]),
                output_format: O::KubeLinterJson,
                upstream_url: "https://github.com/stackrox/kube-linter",
            },
            K::KubeBench => ScannerImpl {
                kind: K::KubeBench,
                class: C::Hardening,
                default_enabled: true,
                image: "aquasec/kube-bench:v0.7.3",
                target_field: T::None,
                args: ArgsTemplate::Static(&["run", "--json"]),
                output_format: O::KubeBenchJson,
                upstream_url: "https://github.com/aquasecurity/kube-bench",
            },
            K::KubeHunter => ScannerImpl {
                kind: K::KubeHunter,
                class: C::Hardening,
                default_enabled: true,
                image: "aquasec/kube-hunter:0.6.10",
                target_field: T::None,
                args: ArgsTemplate::Static(&["--pod", "--report", "json"]),
                output_format: O::KubeHunterJson,
                upstream_url: "https://github.com/aquasecurity/kube-hunter",
            },
            K::Polaris => ScannerImpl {
                kind: K::Polaris,
                class: C::Hardening,
                default_enabled: true,
                image: "quay.io/fairwinds/polaris:8.5",
                target_field: T::None,
                args: ArgsTemplate::Static(&["audit", "--format=json"]),
                output_format: O::PolarisJson,
                upstream_url: "https://github.com/FairwindsOps/polaris",
            },
            K::StigCisValidator => ScannerImpl {
                kind: K::StigCisValidator,
                class: C::Hardening,
                default_enabled: true,
                // Reuse Trivy's k8s posture mode — same image, different verb.
                image: "aquasec/trivy:0.50.0",
                target_field: T::None,
                args: ArgsTemplate::Static(&[
                    "k8s",
                    "--report=summary",
                    "--format=json",
                    "--compliance=k8s-cis",
                    "--output=/scan/result.json",
                ]),
                output_format: O::TrivyJson,
                upstream_url: "https://aquasecurity.github.io/trivy/latest/docs/target/kubernetes/",
            },
            // ── OSS DAST ──────────────────────────────────────────
            K::Zap => ScannerImpl {
                kind: K::Zap,
                class: C::Dast,
                default_enabled: true,
                image: "softwaresecurityproject/zap-stable:2.15.0",
                target_field: T::TenantUrl,
                args: ArgsTemplate::Static(&[
                    "zap-baseline.py",
                    "-t", "${target}",
                    "-J", "/scan/result.json",
                ]),
                output_format: O::ZapJson,
                upstream_url: "https://www.zaproxy.org/",
            },
            // ── Commercial (default-disabled — require cofre creds)
            K::Snyk => ScannerImpl {
                kind: K::Snyk,
                class: C::Cve,
                default_enabled: false,
                image: "snyk/snyk:docker",
                target_field: T::Digest,
                args: ArgsTemplate::Static(&[
                    "container", "test", "${target}", "--json-file-output=/scan/result.json",
                ]),
                output_format: O::NoOp,
                upstream_url: "https://snyk.io/",
            },
            K::DockerScout => ScannerImpl {
                kind: K::DockerScout,
                class: C::Cve,
                default_enabled: false,
                image: "docker/scout-cli:1.18.0",
                target_field: T::Digest,
                args: ArgsTemplate::Static(&[
                    "cves", "${target}", "--format=sarif", "--output=/scan/result.json",
                ]),
                output_format: O::NoOp,
                upstream_url: "https://docs.docker.com/scout/",
            },
            K::JfrogXray => ScannerImpl {
                kind: K::JfrogXray,
                class: C::Cve,
                default_enabled: false,
                image: "releases-docker.jfrog.io/jfrog/jfrog-cli-v2:2.55.0",
                target_field: T::Digest,
                args: ArgsTemplate::Static(&["docker", "scan", "${target}"]),
                output_format: O::NoOp,
                upstream_url: "https://jfrog.com/xray/",
            },
            K::Wiz => ScannerImpl {
                kind: K::Wiz,
                class: C::Cve,
                default_enabled: false,
                image: "wiziocli/wizcli:latest",
                target_field: T::Digest,
                args: ArgsTemplate::Static(&[
                    "docker", "scan", "--image", "${target}", "--output=json",
                ]),
                output_format: O::NoOp,
                upstream_url: "https://www.wiz.io/",
            },
            K::PrismaCloud => ScannerImpl {
                kind: K::PrismaCloud,
                class: C::Cve,
                default_enabled: false,
                image: "twistlock/twistcli:latest",
                target_field: T::Digest,
                args: ArgsTemplate::Static(&[
                    "images", "scan", "--output-file=/scan/result.json", "${target}",
                ]),
                output_format: O::NoOp,
                upstream_url: "https://www.paloaltonetworks.com/prisma/cloud",
            },
            K::BurpEnterprise => ScannerImpl {
                kind: K::BurpEnterprise,
                class: C::Dast,
                default_enabled: false,
                image: "portswigger/burp-enterprise-edition:latest",
                target_field: T::TenantUrl,
                args: ArgsTemplate::Static(&["scan", "--target=${target}"]),
                output_format: O::NoOp,
                upstream_url: "https://portswigger.net/burp/enterprise",
            },
            // ── Heavy / setup-required ────────────────────────────
            K::Codeql => ScannerImpl {
                kind: K::Codeql,
                class: C::Sast,
                default_enabled: false, // requires database build
                image: "ghcr.io/github/codeql-cli:2.17.0",
                target_field: T::Source,
                args: ArgsTemplate::Static(&[
                    "database", "analyze", "${target}",
                    "--format=sarifv2.1.0", "--output=/scan/result.json",
                ]),
                output_format: O::SemgrepSarif, // SARIF reuse
                upstream_url: "https://codeql.github.com/",
            },
        }
    }

    /// Iterator over every scanner the catalog knows about.
    pub fn all() -> impl Iterator<Item = ScannerImpl> {
        use ScannerKind as K;
        [
            K::Trivy, K::Grype, K::Syft, K::Trufflehog, K::Semgrep,
            K::KubeLinter, K::KubeBench, K::KubeHunter, K::Polaris,
            K::StigCisValidator, K::Zap,
            K::Snyk, K::DockerScout, K::JfrogXray, K::Wiz,
            K::PrismaCloud, K::BurpEnterprise, K::Codeql,
        ]
        .into_iter()
        .map(Self::for_kind)
    }

    /// Iterator over the default-enabled OSS scanner set — what the
    /// `SecuritySpec::default()` populates `required_scanners` with.
    pub fn default_enabled() -> impl Iterator<Item = ScannerImpl> {
        Self::all().filter(|s| s.default_enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_a_catalog_entry() {
        use ScannerKind as K;
        for kind in [
            K::Trivy, K::Grype, K::Syft, K::Trufflehog, K::Semgrep,
            K::KubeLinter, K::KubeBench, K::KubeHunter, K::Polaris,
            K::StigCisValidator, K::Zap,
            K::Snyk, K::DockerScout, K::JfrogXray, K::Wiz,
            K::PrismaCloud, K::BurpEnterprise, K::Codeql,
        ] {
            let entry = Catalog::for_kind(kind);
            assert_eq!(entry.kind, kind, "kind mismatch in catalog entry");
            assert!(!entry.image.is_empty(), "{kind:?} has empty image");
            assert!(!entry.upstream_url.is_empty(), "{kind:?} has empty upstream_url");
        }
    }

    #[test]
    fn default_enabled_is_oss_only() {
        let defaults: Vec<_> = Catalog::default_enabled().map(|s| s.kind).collect();
        // OSS scanners default-on.
        for k in [
            ScannerKind::Trivy, ScannerKind::Grype, ScannerKind::Syft,
            ScannerKind::Trufflehog, ScannerKind::Semgrep,
            ScannerKind::KubeLinter, ScannerKind::KubeBench,
            ScannerKind::KubeHunter, ScannerKind::Polaris,
            ScannerKind::StigCisValidator, ScannerKind::Zap,
        ] {
            assert!(defaults.contains(&k), "expected {k:?} default-on");
        }
        // Commercial + heavy default-off.
        for k in [
            ScannerKind::Snyk, ScannerKind::DockerScout,
            ScannerKind::JfrogXray, ScannerKind::Wiz,
            ScannerKind::PrismaCloud, ScannerKind::BurpEnterprise,
            ScannerKind::Codeql,
        ] {
            assert!(!defaults.contains(&k), "expected {k:?} default-off");
        }
    }

    #[test]
    fn args_template_substitutes_target() {
        let trivy = Catalog::for_kind(ScannerKind::Trivy);
        let rendered = trivy.args.render(Some("sha256:abc"));
        assert!(rendered.last() == Some(&"sha256:abc".to_owned()));
        // Non-target args preserved verbatim
        assert!(rendered.contains(&"--format=json".to_owned()));
    }

    #[test]
    fn no_target_renders_empty_substitution() {
        let kb = Catalog::for_kind(ScannerKind::KubeBench);
        // KubeBench has TargetField::None — render with no target.
        let rendered = kb.args.render(None);
        assert_eq!(rendered, vec!["run".to_owned(), "--json".to_owned()]);
    }
}
