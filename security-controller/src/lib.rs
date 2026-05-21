//! `security-controller` — Viggy M1 SecurityController.
//!
//! Drives the Akeyless FedRAMP High SCR program (ASM-17571). The
//! canonical promessa it serves lives at
//! `akeylesslabs/akeyless-nix-images/promessas/akeyless-nix-images-fedramp-scr.tatara`.
//!
//! M1.5: diff / classify / decide bodies implemented as pure functions
//! over the typed Snapshot shape. Observation wiring (shinryu →
//! Snapshot projection) is the runtime's job (`promessa-runtime`); this
//! crate is just the pure compute that turns a Snapshot into a Decision.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use promessa_controller_common::trait_laws_obeyed;
use promessa_types::{
    action::{ReconcilerKind, TypedAction},
    Decision, PromessaTargetKind, Severity, TargetController,
};
use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────
// SPEC
// ────────────────────────────────────────────────────────────────────

/// SecurityPromessa spec — the typed form of `(defpromessa … :kind
/// Security …)`. Maps 1:1 to the .tatara source-of-truth.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SecuritySpec {
    pub scope_artifact_class: String,
    pub window_days: u32,
    pub max_critical_age_days: u32,
    pub max_high_age_days: u32,
    pub max_medium_age_days: u32,
    pub required_attestations: BTreeSet<RequiredAttestation>,
    pub required_scanners: BTreeSet<RequiredScanner>,
    pub harbor_forwarding_enabled: bool,
    pub harbor_target_registry: String,
}

impl Default for SecuritySpec {
    fn default() -> Self {
        Self {
            scope_artifact_class: "ghcr.io/akeylesslabs/akeyless-*".into(),
            window_days: 30,
            max_critical_age_days: 0,
            max_high_age_days: 15,
            max_medium_age_days: 90,
            required_attestations: [
                RequiredAttestation::CartorioActive,
                RequiredAttestation::CosignSig,
                RequiredAttestation::SbomSpdx,
                RequiredAttestation::SlsaProvenance,
            ]
            .into(),
            required_scanners: [
                RequiredScanner::Trivy,
                RequiredScanner::Snyk,
                RequiredScanner::DockerScout,
                RequiredScanner::JfrogXray,
                RequiredScanner::Wiz,
                RequiredScanner::PrismaCloud,
                RequiredScanner::Semgrep,
                RequiredScanner::StigCisValidator,
            ]
            .into(),
            harbor_forwarding_enabled: false,
            harbor_target_registry: "registry.secondfront.com".into(),
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// SNAPSHOT
// ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SecuritySnapshot {
    pub image_digests: Vec<DigestObservation>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DigestObservation {
    pub digest: String,
    pub service: String,
    pub cartorio_status: CartorioStatus,
    pub findings: Vec<Finding>,
    pub attestations_present: BTreeSet<RequiredAttestation>,
    pub scanners_reported: BTreeSet<RequiredScanner>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub scanner: RequiredScanner,
    pub cve_id: Option<String>,
    pub severity: FindingSeverity,
    pub first_seen: DateTime<Utc>,
    pub fixed_in: Option<String>,
    pub exception_id: Option<String>,
}

impl Finding {
    fn age_days(&self, now: DateTime<Utc>) -> i64 {
        (now - self.first_seen).num_days()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredScanner {
    Trivy,
    Snyk,
    DockerScout,
    JfrogXray,
    Wiz,
    PrismaCloud,
    Semgrep,
    Codeql,
    BurpEnterprise,
    Zap,
    StigCisValidator,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredAttestation {
    CartorioActive,
    CosignSig,
    SbomSpdx,
    SlsaProvenance,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CartorioStatus {
    Pending,
    Active,
    Revoked,
    Quarantined,
    Superseded,
}

// ────────────────────────────────────────────────────────────────────
// DRIFT
// ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityDrift {
    pub critical_cves: Vec<DigestCveAge>,
    pub aged_high_cves: Vec<DigestCveAge>,
    pub aged_medium_cves: Vec<DigestCveAge>,
    pub missing_attestations: Vec<(String, Vec<RequiredAttestation>)>,
    pub missing_scanners: Vec<(String, Vec<RequiredScanner>)>,
    pub revoked_or_quarantined: Vec<String>,
    pub all_clean_digests: Vec<DigestService>,
    pub total_digests_observed: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DigestCveAge {
    pub digest: String,
    pub service: String,
    pub cve_id: String,
    pub scanner: RequiredScanner,
    pub age_days: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DigestService {
    pub digest: String,
    pub service: String,
}

// ────────────────────────────────────────────────────────────────────
// CONTROLLER
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SecurityController;

impl TargetController for SecurityController {
    type Spec = SecuritySpec;
    type Snapshot = SecuritySnapshot;
    type Drift = SecurityDrift;

    const KIND: PromessaTargetKind = PromessaTargetKind::Security;

    fn diff(&self, spec: &Self::Spec, snapshot: &Self::Snapshot) -> Self::Drift {
        let now = snapshot.observed_at;
        let mut drift = SecurityDrift {
            total_digests_observed: snapshot.image_digests.len(),
            ..Default::default()
        };

        for obs in &snapshot.image_digests {
            let mut digest_clean = true;

            match obs.cartorio_status {
                CartorioStatus::Revoked
                | CartorioStatus::Quarantined
                | CartorioStatus::Superseded => {
                    drift.revoked_or_quarantined.push(obs.digest.clone());
                    digest_clean = false;
                }
                CartorioStatus::Active | CartorioStatus::Pending => {}
            }

            let missing_atts: Vec<RequiredAttestation> = spec
                .required_attestations
                .difference(&obs.attestations_present)
                .copied()
                .collect();
            if !missing_atts.is_empty() {
                drift
                    .missing_attestations
                    .push((obs.digest.clone(), missing_atts));
                digest_clean = false;
            }

            let missing_scanners: Vec<RequiredScanner> = spec
                .required_scanners
                .difference(&obs.scanners_reported)
                .copied()
                .collect();
            if !missing_scanners.is_empty() {
                drift
                    .missing_scanners
                    .push((obs.digest.clone(), missing_scanners));
                digest_clean = false;
            }

            for f in &obs.findings {
                if f.exception_id.is_some() {
                    continue;
                }
                let Some(cve_id) = f.cve_id.clone() else {
                    continue;
                };
                let age = f.age_days(now);
                let entry = DigestCveAge {
                    digest: obs.digest.clone(),
                    service: obs.service.clone(),
                    cve_id,
                    scanner: f.scanner,
                    age_days: age,
                };
                match f.severity {
                    FindingSeverity::Critical => {
                        drift.critical_cves.push(entry);
                        digest_clean = false;
                    }
                    FindingSeverity::High if age > i64::from(spec.max_high_age_days) => {
                        drift.aged_high_cves.push(entry);
                        digest_clean = false;
                    }
                    FindingSeverity::Medium if age > i64::from(spec.max_medium_age_days) => {
                        drift.aged_medium_cves.push(entry);
                        digest_clean = false;
                    }
                    _ => {}
                }
            }

            if digest_clean && obs.cartorio_status == CartorioStatus::Active {
                drift.all_clean_digests.push(DigestService {
                    digest: obs.digest.clone(),
                    service: obs.service.clone(),
                });
            }
        }

        drift
    }

    fn classify(&self, drift: &Self::Drift) -> Severity {
        if !drift.critical_cves.is_empty() || !drift.revoked_or_quarantined.is_empty() {
            return Severity::Critical;
        }
        if !drift.aged_high_cves.is_empty()
            || !drift.missing_attestations.is_empty()
            || !drift.missing_scanners.is_empty()
        {
            return Severity::Functional;
        }
        Severity::Cosmetic
    }

    fn decide(&self, spec: &Self::Spec, severity: Severity, drift: &Self::Drift) -> Decision {
        match severity {
            Severity::Critical => {
                let mut actions: Vec<TypedAction> = vec![];
                for c in &drift.critical_cves {
                    actions.push(TypedAction::ReconcilerApply {
                        reconciler: ReconcilerKind::CartorioAdmit,
                        spec: serde_json::json!({
                            "digest": c.digest,
                            "transition": "Revoked",
                            "reason": format!("Critical CVE {} via {:?}", c.cve_id, c.scanner),
                        }),
                    });
                    actions.push(TypedAction::ReconcilerApply {
                        reconciler: ReconcilerKind::GhcrTagRevoke,
                        spec: serde_json::json!({
                            "repo": format!("akeylesslabs/akeyless-{}", c.service),
                            "tag": "release",
                            "reason": c.cve_id,
                        }),
                    });
                    actions.push(TypedAction::FluxCommit {
                        path: "helmworks-akeyless/architectures/fedramp-high.yaml".into(),
                        patch: serde_json::json!({
                            "service": c.service,
                            "pin_to_previous_known_good": true,
                            "reason": format!("Critical CVE {}", c.cve_id),
                        }),
                    });
                }
                Decision::AutoCorrect(TypedAction::Compose(actions))
            }

            Severity::Functional => {
                let mut actions: Vec<TypedAction> = vec![];
                for (digest, missing) in &drift.missing_attestations {
                    for att in missing {
                        let reconciler = match att {
                            RequiredAttestation::CartorioActive => ReconcilerKind::CartorioAdmit,
                            RequiredAttestation::CosignSig => ReconcilerKind::CosignAttest,
                            RequiredAttestation::SbomSpdx => ReconcilerKind::SbomGenerate,
                            RequiredAttestation::SlsaProvenance => ReconcilerKind::SlsaProvenance,
                        };
                        actions.push(TypedAction::ReconcilerApply {
                            reconciler,
                            spec: serde_json::json!({ "digest": digest, "force": true }),
                        });
                    }
                }
                for h in &drift.aged_high_cves {
                    actions.push(TypedAction::ReconcilerApply {
                        reconciler: ReconcilerKind::RenovateBaseImageBump,
                        spec: serde_json::json!({
                            "cve_id": h.cve_id,
                            "image_digest": h.digest,
                            "target_repo": "akeylesslabs/akeyless-main-repo",
                        }),
                    });
                }
                if actions.is_empty() {
                    Decision::Alert
                } else {
                    Decision::AutoCorrect(TypedAction::Compose(actions))
                }
            }

            Severity::Cosmetic => {
                if !spec.harbor_forwarding_enabled || drift.all_clean_digests.is_empty() {
                    return Decision::NoAction;
                }
                let actions = drift
                    .all_clean_digests
                    .iter()
                    .map(|d| TypedAction::ReconcilerApply {
                        reconciler: ReconcilerKind::HarborMirror,
                        spec: serde_json::json!({
                            "source_repo": format!("akeylesslabs/akeyless-{}", d.service),
                            "source_digest": d.digest,
                            "target_registry": spec.harbor_target_registry,
                            "target_project": "akeyless",
                            "preserve_digest": true,
                        }),
                    })
                    .collect::<Vec<_>>();
                Decision::AutoCorrect(TypedAction::Compose(actions))
            }
        }
    }
}

trait_laws_obeyed!(SecurityController);

// ────────────────────────────────────────────────────────────────────
// TESTS
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-21T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn clean_obs(svc: &str) -> DigestObservation {
        DigestObservation {
            digest: format!("sha256:{svc}clean"),
            service: svc.into(),
            cartorio_status: CartorioStatus::Active,
            findings: vec![],
            attestations_present: [
                RequiredAttestation::CartorioActive,
                RequiredAttestation::CosignSig,
                RequiredAttestation::SbomSpdx,
                RequiredAttestation::SlsaProvenance,
            ]
            .into(),
            scanners_reported: [
                RequiredScanner::Trivy,
                RequiredScanner::Snyk,
                RequiredScanner::DockerScout,
                RequiredScanner::JfrogXray,
                RequiredScanner::Wiz,
                RequiredScanner::PrismaCloud,
                RequiredScanner::Semgrep,
                RequiredScanner::StigCisValidator,
            ]
            .into(),
        }
    }

    #[test]
    fn all_clean_classifies_cosmetic() {
        let s = SecuritySpec::default();
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![clean_obs("auth"), clean_obs("uam")],
        };
        let d = SecurityController.diff(&s, &snap);
        assert_eq!(d.all_clean_digests.len(), 2);
        assert_eq!(SecurityController.classify(&d), Severity::Cosmetic);
    }

    #[test]
    fn critical_cve_classifies_critical() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("auth");
        obs.findings.push(Finding {
            scanner: RequiredScanner::Trivy,
            cve_id: Some("CVE-2024-12345".into()),
            severity: FindingSeverity::Critical,
            first_seen: now() - Duration::hours(1),
            fixed_in: Some("1.2.3".into()),
            exception_id: None,
        });
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        assert_eq!(d.critical_cves.len(), 1);
        assert_eq!(SecurityController.classify(&d), Severity::Critical);
    }

    #[test]
    fn aged_high_classifies_functional() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("uam");
        obs.findings.push(Finding {
            scanner: RequiredScanner::Wiz,
            cve_id: Some("CVE-2024-99999".into()),
            severity: FindingSeverity::High,
            first_seen: now() - Duration::days(30),
            fixed_in: None,
            exception_id: None,
        });
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        assert_eq!(d.aged_high_cves.len(), 1);
        assert_eq!(SecurityController.classify(&d), Severity::Functional);
    }

    #[test]
    fn high_within_sla_does_not_drift() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("kfm");
        obs.findings.push(Finding {
            scanner: RequiredScanner::Snyk,
            cve_id: Some("CVE-2026-00001".into()),
            severity: FindingSeverity::High,
            first_seen: now() - Duration::days(7),
            fixed_in: None,
            exception_id: None,
        });
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        assert!(d.aged_high_cves.is_empty());
        assert_eq!(SecurityController.classify(&d), Severity::Cosmetic);
    }

    #[test]
    fn exception_excludes_finding_from_drift() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("gator");
        obs.findings.push(Finding {
            scanner: RequiredScanner::PrismaCloud,
            cve_id: Some("CVE-2024-77777".into()),
            severity: FindingSeverity::Critical,
            first_seen: now() - Duration::days(1),
            fixed_in: None,
            exception_id: Some("ex-2026-0001".into()),
        });
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        assert!(d.critical_cves.is_empty(), "approved exception suppressed");
        assert_eq!(SecurityController.classify(&d), Severity::Cosmetic);
    }

    #[test]
    fn revoked_cartorio_status_classifies_critical() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("bis");
        obs.cartorio_status = CartorioStatus::Revoked;
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        assert_eq!(d.revoked_or_quarantined.len(), 1);
        assert_eq!(SecurityController.classify(&d), Severity::Critical);
    }

    #[test]
    fn missing_attestation_classifies_functional() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("logan");
        obs.attestations_present.remove(&RequiredAttestation::SbomSpdx);
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        assert_eq!(d.missing_attestations.len(), 1);
        assert_eq!(SecurityController.classify(&d), Severity::Functional);
    }

    #[test]
    fn missing_scanner_classifies_functional() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("mark");
        obs.scanners_reported.remove(&RequiredScanner::Wiz);
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        assert_eq!(d.missing_scanners.len(), 1);
        assert_eq!(SecurityController.classify(&d), Severity::Functional);
    }

    #[test]
    fn cosmetic_with_flag_off_decides_no_action() {
        let s = SecuritySpec { harbor_forwarding_enabled: false, ..Default::default() };
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![clean_obs("auth")],
        };
        let d = SecurityController.diff(&s, &snap);
        match SecurityController.decide(&s, Severity::Cosmetic, &d) {
            Decision::NoAction => {}
            other => panic!("expected NoAction, got {other:?}"),
        }
    }

    #[test]
    fn cosmetic_with_flag_on_decides_harbor_mirror() {
        let s = SecuritySpec { harbor_forwarding_enabled: true, ..Default::default() };
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![clean_obs("auth")],
        };
        let d = SecurityController.diff(&s, &snap);
        match SecurityController.decide(&s, Severity::Cosmetic, &d) {
            Decision::AutoCorrect(TypedAction::Compose(actions)) => {
                assert!(actions.iter().any(|a| matches!(
                    a,
                    TypedAction::ReconcilerApply { reconciler: ReconcilerKind::HarborMirror, .. }
                )));
            }
            other => panic!("expected HarborMirror dispatch, got {other:?}"),
        }
    }

    #[test]
    fn critical_decides_revoke_plus_block_plus_pin() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("auth");
        obs.findings.push(Finding {
            scanner: RequiredScanner::Trivy,
            cve_id: Some("CVE-2024-12345".into()),
            severity: FindingSeverity::Critical,
            first_seen: now(),
            fixed_in: None,
            exception_id: None,
        });
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        let dec = SecurityController.decide(&s, Severity::Critical, &d);
        match dec {
            Decision::AutoCorrect(TypedAction::Compose(actions)) => {
                let has_revoke = actions.iter().any(|a| matches!(
                    a,
                    TypedAction::ReconcilerApply { reconciler: ReconcilerKind::CartorioAdmit, .. }
                ));
                let has_tag_revoke = actions.iter().any(|a| matches!(
                    a,
                    TypedAction::ReconcilerApply { reconciler: ReconcilerKind::GhcrTagRevoke, .. }
                ));
                let has_pin = actions.iter().any(|a| matches!(a, TypedAction::FluxCommit { .. }));
                assert!(has_revoke && has_tag_revoke && has_pin);
            }
            other => panic!("expected AutoCorrect Compose, got {other:?}"),
        }
    }

    #[test]
    fn classify_monotonic_critical_dominates() {
        let s = SecuritySpec::default();
        let mut obs = clean_obs("auth");
        obs.findings.push(Finding {
            scanner: RequiredScanner::Trivy,
            cve_id: Some("CVE-X".into()),
            severity: FindingSeverity::Critical,
            first_seen: now(),
            fixed_in: None,
            exception_id: None,
        });
        obs.attestations_present.remove(&RequiredAttestation::SbomSpdx);
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![obs],
        };
        let d = SecurityController.diff(&s, &snap);
        assert!(!d.critical_cves.is_empty());
        assert!(!d.missing_attestations.is_empty());
        assert_eq!(SecurityController.classify(&d), Severity::Critical);
    }

    #[test]
    fn diff_is_deterministic() {
        let s = SecuritySpec::default();
        let snap = SecuritySnapshot {
            observed_at: now(),
            image_digests: vec![clean_obs("a"), clean_obs("b"), clean_obs("c")],
        };
        let d1 = SecurityController.diff(&s, &snap);
        let d2 = SecurityController.diff(&s, &snap);
        assert_eq!(d1, d2);
    }
}
