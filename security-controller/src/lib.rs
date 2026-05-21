//! `security-controller` — the Viggy M1 SecurityController, the first
//! TargetController kind to ship.
//!
//! Drives the Akeyless FedRAMP High SCR program (ASM-17571). The
//! canonical promessa it serves lives at
//! `akeylesslabs/akeyless-nix-images/promessas/akeyless-nix-images-fedramp-scr.tatara`.
//!
//! Status: M1 skeleton. The TargetController trait is implemented;
//! diff/classify/decide bodies are `todo!()` until the shinryu +
//! cartorio observation surfaces are wired (M1.5). See
//! pleme-io/theory/VIGGY-LEGOS.md Part VII.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use promessa_controller_common::trait_laws_obeyed;
use promessa_types::{
    Decision, PromessaTargetKind, Severity, TargetController, TypedAction,
};
use serde::{Deserialize, Serialize};

// ── Per-kind typed surface ──────────────────────────────────────────

/// SecurityPromessa spec — the typed form of `(defpromessa … :kind
/// Security …)`.
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
}

/// What the observation pipeline returns. Composite-of shinryu +
/// cartorio + tameshi per the .tatara source.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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

/// The drift type — what `diff(spec, snapshot)` returns.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SecurityDrift {
    pub critical_cves: Vec<(String, String)>,             // (digest, cve_id)
    pub aged_high_cves: Vec<(String, String, u32)>,       // (digest, cve_id, age_days)
    pub aged_medium_cves: Vec<(String, String, u32)>,
    pub missing_attestations: Vec<(String, RequiredAttestation)>,
    pub revoked_or_quarantined: Vec<String>,
    pub all_clean_digests: Vec<String>,
}

// ── The controller ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SecurityController;

impl TargetController for SecurityController {
    type Spec = SecuritySpec;
    type Snapshot = SecuritySnapshot;
    type Drift = SecurityDrift;

    const KIND: PromessaTargetKind = PromessaTargetKind::Security;

    fn diff(&self, _spec: &Self::Spec, _snapshot: &Self::Snapshot) -> Self::Drift {
        // M1 skeleton. Implementation lands in M1.5 once shinryu
        // observation source is wired. The .tatara source already
        // declares the typed query — this fn just projects the
        // resulting rows into the typed Drift shape.
        todo!("SecurityController::diff — M1.5 (shinryu wiring)")
    }

    fn classify(&self, _drift: &Self::Drift) -> Severity {
        // Cosmetic when all_clean_digests dominates;
        // Functional on aged_high or missing_attestations;
        // Critical on any critical_cve OR revoked_or_quarantined.
        todo!("SecurityController::classify — M1.5")
    }

    fn decide(
        &self,
        _spec: &Self::Spec,
        _severity: Severity,
        _drift: &Self::Drift,
    ) -> Decision {
        // RemediationPolicy from spec drives the verdict. Default
        // shape per VIGGY-AUTHORING §5.1 dispatches via
        // ReconcilerApply{CartorioAdmit} on Cosmetic+,
        // FluxCommit{block-image} on Critical,
        // ReconcilerApply{HarborMirror} guarded by
        // harbor_forwarding_enabled.
        todo!("SecurityController::decide — M1.5")
    }
}

trait_laws_obeyed!(SecurityController);
