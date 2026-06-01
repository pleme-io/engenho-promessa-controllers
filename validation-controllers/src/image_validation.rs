//! `AkeylessImageValidationController` — top-level reconciler that
//! drives an AkeylessImageValidation CR through its typed phases.
//!
//! Phase chain per AKEYLESS-VALIDATION-PLATFORM.md §IV.1:
//!
//!   Pending → Provisioning → Scanning → Aggregating → Attesting →
//!   Gating → {Passed | Failed | Quarantined}
//!
//! No timers. Every transition reads typed predecessor state from
//! child CRs (Tenant, ScanJob) and writes typed successor state via
//! `Api::patch_status`. Failure is the typed `.status.phase = Failed`
//! event, never an inferred deadline.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use kube::api::{ListParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config;
use kube::runtime::Controller;
use kube::{Api, ResourceExt};
use promessa_types::TargetController;
use security_controller::{
    CartorioStatus, DigestObservation, Finding as ScFinding, FindingSeverity, RequiredAttestation,
    RequiredScanner, SecuritySnapshot, SecuritySpec,
};
use serde_json::json;
use tracing::{info, warn};
use validation_crds::{
    AkeylessEphemeralTenant, AkeylessEphemeralTenantPhase, AkeylessEphemeralTenantSpec,
    AkeylessImageValidation, AkeylessImageValidationPhase, AkeylessImageValidationStatus,
    DigestSetEntry, GateDecision, GateVerdict, ScanJob, ScanJobPhase, ScanJobSpec, ScanJobSummary,
    ScannerClass, ScannerKind,
};

use crate::context::ReconcileCtx;

#[derive(Debug, Clone, Default)]
pub struct AkeylessImageValidationController;

/// Spawn the reconciler. Returns when the watcher stream closes.
pub async fn run(ctx: Arc<ReconcileCtx>) -> anyhow::Result<()> {
    let api: Api<AkeylessImageValidation> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };
    info!("AkeylessImageValidationController starting");
    Controller::new(api.clone(), Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                warn!(error = %e, "reconcile error");
            }
        })
        .await;
    Ok(())
}

async fn reconcile(
    obj: Arc<AkeylessImageValidation>,
    ctx: Arc<ReconcileCtx>,
) -> Result<Action, kube::Error> {
    let name = obj.name_any();
    let ns = obj.namespace().unwrap_or_default();
    let current = obj
        .status
        .as_ref()
        .and_then(|s| s.phase)
        .unwrap_or(AkeylessImageValidationPhase::Pending);

    info!(name = %name, ns = %ns, ?current, "reconcile");

    let api: Api<AkeylessImageValidation> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::namespaced(ctx.client.clone(), &ns),
    };

    let next_status = match current {
        AkeylessImageValidationPhase::Pending => handle_pending(&obj, &ctx).await?,
        AkeylessImageValidationPhase::Provisioning => handle_provisioning(&obj, &ctx).await?,
        AkeylessImageValidationPhase::Scanning => handle_scanning(&obj, &ctx).await?,
        AkeylessImageValidationPhase::Aggregating => handle_aggregating(&obj, &ctx).await?,
        AkeylessImageValidationPhase::Attesting => handle_attesting(&obj, &ctx).await?,
        AkeylessImageValidationPhase::Gating => handle_gating(&obj, &ctx).await?,
        // Terminal phases — no transition; long requeue.
        AkeylessImageValidationPhase::Passed
        | AkeylessImageValidationPhase::Failed
        | AkeylessImageValidationPhase::Quarantined => return Ok(Action::requeue(Duration::from_secs(3600))),
    };

    if let Some(new_status) = next_status {
        let patch = json!({ "status": new_status });
        api.patch_status(&name, &PatchParams::apply("validation-controllers"), &Patch::Merge(&patch))
            .await?;
        // ── Emit typed events for cross-process consumers ──────────
        // Single intercept point — every phase transition + every
        // newly-emitted GateDecision fans out to NATS here. The
        // events_publisher is Disconnected when NATS_URL is unset,
        // so this is a typed no-op outside cluster.
        emit_post_patch(&obj, &ctx, current, &new_status).await;
    }

    // Short requeue so phase transitions cascade promptly.
    Ok(Action::requeue(Duration::from_secs(15)))
}

/// Compare the previous CR state against the just-patched status
/// and publish typed events for every observable change.
async fn emit_post_patch(
    obj: &AkeylessImageValidation,
    ctx: &ReconcileCtx,
    previous_phase: AkeylessImageValidationPhase,
    new_status: &AkeylessImageValidationStatus,
) {
    use validation_events::{
        DecisionEmitted, PhaseChanged, ValidationEvent,
    };

    let service = obj.spec.service.clone();
    let image_digest = obj.spec.image_digest.clone();
    let image_repo = obj.spec.image_repo.clone();
    let uid = obj.metadata.uid.clone().unwrap_or_default();
    let now = Utc::now();

    // PhaseChanged — fires only when the phase actually moved.
    if let Some(new_phase) = new_status.phase {
        if new_phase != previous_phase {
            let event = ValidationEvent::PhaseChanged(PhaseChanged {
                event_id: validation_events::new_event_id(),
                validation_run_uid: uid.clone(),
                service: service.clone(),
                image_digest: image_digest.clone(),
                image_repo: image_repo.clone(),
                observed_at: now,
                from: Some(previous_phase),
                to: new_phase,
            });
            ctx.events_publisher.publish(&event).await;
        }
    }

    // DecisionEmitted — fires when the gate just landed (previous
    // status had no decision; the new one does).
    let previously_had_decision = obj
        .status
        .as_ref()
        .and_then(|s| s.gate_decision.as_ref())
        .is_some();
    if !previously_had_decision {
        if let Some(gd) = new_status.gate_decision.as_ref() {
            let event = ValidationEvent::DecisionEmitted(DecisionEmitted {
                event_id: validation_events::new_event_id(),
                validation_run_uid: uid,
                service,
                image_digest,
                image_repo,
                observed_at: now,
                severity: gd.severity.clone(),
                verdict: gd.verdict,
                reason: gd.reason.clone(),
            });
            ctx.events_publisher.publish(&event).await;
        }
    }
}

fn error_policy(
    _obj: Arc<AkeylessImageValidation>,
    _err: &kube::Error,
    _ctx: Arc<ReconcileCtx>,
) -> Action {
    Action::requeue(Duration::from_secs(30))
}

// ────────────────────────────────────────────────────────────────────
// Phase handlers — each is pure plus exactly one side effect (create
// child CR OR patch own status). Returns the new status if transition.
// ────────────────────────────────────────────────────────────────────

/// Pending → Provisioning. Create child AkeylessEphemeralTenant.
async fn handle_pending(
    obj: &AkeylessImageValidation,
    ctx: &ReconcileCtx,
) -> Result<Option<AkeylessImageValidationStatus>, kube::Error> {
    let name = obj.name_any();
    let ns = obj.namespace().unwrap_or_default();
    let tenant_name = format!("eph-{name}");

    let tenants: Api<AkeylessEphemeralTenant> = Api::namespaced(ctx.client.clone(), &ns);
    let exists = tenants.get_opt(&tenant_name).await?.is_some();

    if !exists {
        let tenant = AkeylessEphemeralTenant {
            metadata: ObjectMeta {
                name: Some(tenant_name.clone()),
                namespace: Some(ns.clone()),
                labels: Some({
                    let mut m = BTreeMap::new();
                    m.insert("validation".into(), name.clone());
                    m
                }),
                owner_references: owner_refs_of(obj),
                ..Default::default()
            },
            spec: AkeylessEphemeralTenantSpec {
                digest_set: vec![DigestSetEntry {
                    service: obj.spec.service.clone(),
                    digest: obj.spec.image_digest.clone(),
                }],
                parent_validation: name.clone(),
                infra_template: "akeyless-eph-saas".into(),
                warm_pool: None,
                ttl_seconds: 3600,
            },
            status: None,
        };
        tenants.create(&PostParams::default(), &tenant).await?;
        info!(tenant = %tenant_name, "created child tenant");
    }

    let mut new = obj.status.clone().unwrap_or_default();
    new.phase = Some(AkeylessImageValidationPhase::Provisioning);
    new.ephemeral_tenant_ref = Some(tenant_name);
    new.started_at = new.started_at.or_else(|| Some(Utc::now()));
    new.observed_generation = obj.metadata.generation.unwrap_or(0);
    Ok(Some(new))
}

/// Provisioning → Scanning when child tenant.status.phase == Ready.
async fn handle_provisioning(
    obj: &AkeylessImageValidation,
    ctx: &ReconcileCtx,
) -> Result<Option<AkeylessImageValidationStatus>, kube::Error> {
    let ns = obj.namespace().unwrap_or_default();
    let tenant_name = obj
        .status
        .as_ref()
        .and_then(|s| s.ephemeral_tenant_ref.clone())
        .unwrap_or_else(|| format!("eph-{}", obj.name_any()));

    let tenants: Api<AkeylessEphemeralTenant> = Api::namespaced(ctx.client.clone(), &ns);
    let Some(tenant) = tenants.get_opt(&tenant_name).await? else {
        // Child got deleted; recreate by re-entering Pending logic.
        return handle_pending(obj, ctx).await;
    };
    let tenant_ready = tenant
        .status
        .as_ref()
        .and_then(|s| s.phase)
        .map(|p| matches!(p, AkeylessEphemeralTenantPhase::Ready | AkeylessEphemeralTenantPhase::Scanning))
        .unwrap_or(false);

    if !tenant_ready {
        return Ok(None); // wait
    }

    // Emit ScanJob CRs — one per required scanner.
    let sjs: Api<ScanJob> = Api::namespaced(ctx.client.clone(), &ns);
    let spec = security_spec_for(&obj.spec.promessa_ref);
    let mut summaries = vec![];
    for scanner in &spec.required_scanners {
        let sjob_name = format!("sj-{}-{}", scanner_kebab(*scanner), obj.name_any());
        if sjs.get_opt(&sjob_name).await?.is_none() {
            let sj = build_scan_job(&sjob_name, &ns, obj, &tenant, *scanner);
            sjs.create(&PostParams::default(), &sj).await?;
            info!(sjob = %sjob_name, ?scanner, "created scan job");
        }
        summaries.push(ScanJobSummary {
            name: sjob_name,
            scanner: scanner_kind_from_required(*scanner),
            phase: ScanJobPhase::Pending,
            findings_count: 0,
        });
    }

    let mut new = obj.status.clone().unwrap_or_default();
    new.phase = Some(AkeylessImageValidationPhase::Scanning);
    new.scan_jobs = summaries;
    new.observed_generation = obj.metadata.generation.unwrap_or(0);
    Ok(Some(new))
}

/// Scanning → Aggregating when every child ScanJob is Attested or Failed.
async fn handle_scanning(
    obj: &AkeylessImageValidation,
    ctx: &ReconcileCtx,
) -> Result<Option<AkeylessImageValidationStatus>, kube::Error> {
    let ns = obj.namespace().unwrap_or_default();
    let parent = obj.name_any();
    let sjs: Api<ScanJob> = Api::namespaced(ctx.client.clone(), &ns);
    let children = sjs
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|sj| sj.spec.parent_validation == parent)
        .collect::<Vec<_>>();

    if children.is_empty() {
        // Edge case: parent skipped Provisioning's emit step; rerun it.
        return handle_provisioning(obj, ctx).await;
    }

    let all_terminal = children.iter().all(|sj| {
        matches!(
            sj.status.as_ref().and_then(|s| s.phase),
            Some(ScanJobPhase::Attested) | Some(ScanJobPhase::Failed) | Some(ScanJobPhase::Reaped)
        )
    });

    let summaries: Vec<ScanJobSummary> = children
        .iter()
        .map(|sj| ScanJobSummary {
            name: sj.name_any(),
            scanner: sj.spec.scanner,
            phase: sj.status.as_ref().and_then(|s| s.phase).unwrap_or(ScanJobPhase::Pending),
            findings_count: sj.status.as_ref().map(|s| s.findings_count).unwrap_or(0),
        })
        .collect();

    let mut new = obj.status.clone().unwrap_or_default();
    new.scan_jobs = summaries;

    if all_terminal {
        new.phase = Some(AkeylessImageValidationPhase::Aggregating);
    }
    new.observed_generation = obj.metadata.generation.unwrap_or(0);
    Ok(Some(new))
}

/// Aggregating → Attesting. Compute evidence-bundle blake3 over the
/// canonical bytes of the union of findings.
async fn handle_aggregating(
    obj: &AkeylessImageValidation,
    ctx: &ReconcileCtx,
) -> Result<Option<AkeylessImageValidationStatus>, kube::Error> {
    let ns = obj.namespace().unwrap_or_default();
    let parent = obj.name_any();
    let sjs: Api<ScanJob> = Api::namespaced(ctx.client.clone(), &ns);
    let children = sjs
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|sj| sj.spec.parent_validation == parent)
        .collect::<Vec<_>>();

    let canonical = canonical_findings_bytes(&children);
    let evidence_hash = blake3::hash(&canonical).to_hex().to_string();

    let mut new = obj.status.clone().unwrap_or_default();
    new.phase = Some(AkeylessImageValidationPhase::Attesting);
    new.evidence_bundle_hash = Some(evidence_hash);
    new.observed_generation = obj.metadata.generation.unwrap_or(0);
    Ok(Some(new))
}

/// Attesting → Gating. Clean pass-through: attestation is configured
/// OFF (scan-only), so we record Cartorio state as `Pending` (honestly
/// "not attested") rather than fabricating `Active`. Real cartorio +
/// OutcomeChain dispatch lands when attestation is turned back on.
async fn handle_attesting(
    obj: &AkeylessImageValidation,
    _ctx: &ReconcileCtx,
) -> Result<Option<AkeylessImageValidationStatus>, kube::Error> {
    let mut new = obj.status.clone().unwrap_or_default();
    new.phase = Some(AkeylessImageValidationPhase::Gating);
    new.cartorio_artifact_state = Some(validation_crds::CartorioArtifactState::Pending);
    new.observed_generation = obj.metadata.generation.unwrap_or(0);
    Ok(Some(new))
}

/// Gating → terminal. Build a SecuritySnapshot from the children's
/// typed findings, call SecurityController.diff/classify/decide, write
/// the verdict. Transition to Passed / Failed / Quarantined per verdict.
async fn handle_gating(
    obj: &AkeylessImageValidation,
    ctx: &ReconcileCtx,
) -> Result<Option<AkeylessImageValidationStatus>, kube::Error> {
    let ns = obj.namespace().unwrap_or_default();
    let parent = obj.name_any();
    let sjs: Api<ScanJob> = Api::namespaced(ctx.client.clone(), &ns);
    let children = sjs
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|sj| sj.spec.parent_validation == parent)
        .collect::<Vec<_>>();

    let spec = security_spec_for(&obj.spec.promessa_ref);
    let snapshot = build_security_snapshot(obj, &children);
    let drift = ctx.security_controller.diff(&spec, &snapshot);
    let severity = ctx.security_controller.classify(&drift);
    let decision = ctx.security_controller.decide(&spec, severity, &drift);

    // Map Decision to GateVerdict + canonical-JSON action. The schema
    // pins `action` to type=object, so empty/no-op decisions render as `{}`.
    let empty = json!({});
    let (verdict, action_json) = match &decision {
        promessa_types::Decision::NoAction => (GateVerdict::Passed, empty.clone()),
        promessa_types::Decision::AutoCorrect(action) => {
            let verdict = if severity == promessa_types::Severity::Critical {
                GateVerdict::Failed
            } else {
                GateVerdict::Passed
            };
            (verdict, serde_json::to_value(action).unwrap_or_else(|_| empty.clone()))
        }
        promessa_types::Decision::RequireApproval(action) => (
            GateVerdict::Quarantined,
            serde_json::to_value(action).unwrap_or_else(|_| empty.clone()),
        ),
        promessa_types::Decision::Alert => (GateVerdict::Passed, empty.clone()),
        promessa_types::Decision::SuppressedAfterRepeatedFailure { failure_count } => (
            GateVerdict::Quarantined,
            json!({"suppressed": true, "failure_count": failure_count}),
        ),
    };

    // Scan-only: keep the verdict (e.g. Failed on a Critical CVE) but
    // drop remediation actions — do not auto-revoke/quarantine against
    // the disabled attestation/cartorio infra.
    let action_json = if scan_only_mode() {
        empty.clone()
    } else {
        action_json
    };

    let mut new = obj.status.clone().unwrap_or_default();
    new.gate_decision = Some(GateDecision {
        severity: format!("{severity:?}"),
        verdict,
        action: action_json,
        reason: Some(format_drift_reason(&drift)),
        decided_at: Utc::now(),
    });
    new.phase = Some(match verdict {
        GateVerdict::Passed => AkeylessImageValidationPhase::Passed,
        GateVerdict::Failed => AkeylessImageValidationPhase::Failed,
        GateVerdict::Quarantined => AkeylessImageValidationPhase::Quarantined,
    });
    new.terminal_at = Some(Utc::now());
    new.observed_generation = obj.metadata.generation.unwrap_or(0);
    Ok(Some(new))
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn owner_refs_of(parent: &AkeylessImageValidation) -> Option<Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>> {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
    Some(vec![OwnerReference {
        api_version: "validation.pleme.io/v1".into(),
        kind: "AkeylessImageValidation".into(),
        name: parent.name_any(),
        uid: parent.uid().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }])
}

fn scanner_kebab(s: RequiredScanner) -> &'static str {
    use RequiredScanner::*;
    match s {
        Trivy => "trivy",
        Grype => "grype",
        Syft => "syft",
        Trufflehog => "trufflehog",
        Semgrep => "semgrep",
        KubeLinter => "kubelinter",
        KubeBench => "kubebench",
        KubeHunter => "kubehunter",
        Polaris => "polaris",
        StigCisValidator => "stig",
        Zap => "zap",
        Snyk => "snyk",
        DockerScout => "scout",
        JfrogXray => "xray",
        Wiz => "wiz",
        PrismaCloud => "prisma",
        BurpEnterprise => "burp",
        Codeql => "codeql",
    }
}

fn scanner_kind_from_required(s: RequiredScanner) -> ScannerKind {
    use RequiredScanner as R;
    use ScannerKind as K;
    match s {
        R::Trivy => K::Trivy,
        R::Grype => K::Grype,
        R::Syft => K::Syft,
        R::Trufflehog => K::Trufflehog,
        R::Semgrep => K::Semgrep,
        R::KubeLinter => K::KubeLinter,
        R::KubeBench => K::KubeBench,
        R::KubeHunter => K::KubeHunter,
        R::Polaris => K::Polaris,
        R::StigCisValidator => K::StigCisValidator,
        R::Zap => K::Zap,
        R::Snyk => K::Snyk,
        R::DockerScout => K::DockerScout,
        R::JfrogXray => K::JfrogXray,
        R::Wiz => K::Wiz,
        R::PrismaCloud => K::PrismaCloud,
        R::BurpEnterprise => K::BurpEnterprise,
        R::Codeql => K::Codeql,
    }
}

fn scanner_class_for(s: RequiredScanner) -> ScannerClass {
    use RequiredScanner::*;
    match s {
        // CVE scanners (vulnerabilities in OCI image layers)
        Trivy | Grype | Snyk | DockerScout | JfrogXray | Wiz | PrismaCloud => ScannerClass::Cve,
        // SBOM (catalog only — no findings, emits package set)
        Syft => ScannerClass::Cve,
        // Secret/credential scanning of source trees
        Trufflehog => ScannerClass::Sast,
        // SAST (source-level static analysis)
        Semgrep | Codeql => ScannerClass::Sast,
        // K8s posture + hardening scanners
        KubeLinter | KubeBench | KubeHunter | Polaris | StigCisValidator => ScannerClass::Hardening,
        // DAST (runtime probing of live tenant URL)
        BurpEnterprise | Zap => ScannerClass::Dast,
    }
}

fn build_scan_job(
    name: &str,
    ns: &str,
    parent: &AkeylessImageValidation,
    tenant: &AkeylessEphemeralTenant,
    scanner: RequiredScanner,
) -> ScanJob {
    let kind = scanner_kind_from_required(scanner);
    let class = scanner_class_for(scanner);
    // Which CR target field a scanner reads is owned by the
    // scanner-catalog (single source of truth), not guessed from the
    // class. CVE/SBOM scanners pull a fully-qualified, pullable image
    // ref from the in-cluster Zot mirror — NOT a bare `sha256:…` digest,
    // which `trivy image sha256:…` cannot resolve. SAST/secret scanners
    // read the source git URL; DAST scanners read the live tenant URL.
    let (digest, source, url) = match scanner_catalog::Catalog::for_kind(kind).target_field {
        scanner_catalog::TargetField::Digest => (
            Some(pullable_image_ref(
                &parent.spec.image_repo,
                &parent.spec.image_digest,
            )),
            None,
            None,
        ),
        scanner_catalog::TargetField::Source => (
            None,
            // Akeyless images all build from akeyless-main-repo; that
            // monorepo is the SAST/secret-scan source of record. Plain
            // URL (no `git+` prefix — trufflehog/semgrep reject it).
            Some("https://github.com/akeylesslabs/akeyless-main-repo".to_owned()),
            None,
        ),
        scanner_catalog::TargetField::TenantUrl => (
            None,
            None,
            tenant.status.as_ref().and_then(|s| s.ingress_url.clone()),
        ),
        scanner_catalog::TargetField::None => (None, None, None),
    };
    ScanJob {
        metadata: ObjectMeta {
            name: Some(name.into()),
            namespace: Some(ns.into()),
            labels: Some({
                let mut m = BTreeMap::new();
                m.insert("validation".into(), parent.name_any());
                m.insert("scanner".into(), scanner_kebab(scanner).into());
                m
            }),
            owner_references: owner_refs_of(parent),
            ..Default::default()
        },
        spec: ScanJobSpec {
            scanner: kind,
            scanner_class: class,
            target_digest: digest,
            target_source: source,
            target_tenant_url: url,
            parent_validation: parent.name_any(),
            pack: parent.spec.pack.clone(),
            image_override: None,
        },
        status: None,
    }
}

fn build_security_snapshot(
    parent: &AkeylessImageValidation,
    children: &[ScanJob],
) -> SecuritySnapshot {
    let mut findings = vec![];
    let mut scanners_reported = BTreeSet::new();
    for c in children {
        let kind = scanner_required_from_kind(c.spec.scanner);
        scanners_reported.insert(kind);
        if let Some(st) = c.status.as_ref() {
            for f in &st.findings {
                findings.push(ScFinding {
                    scanner: scanner_required_from_kind(f.scanner),
                    cve_id: f.cve_id.clone(),
                    severity: map_severity(f.severity),
                    first_seen: f.first_seen,
                    fixed_in: f.fixed_in.clone(),
                    exception_id: f.exception_id.clone(),
                });
            }
        }
    }
    // Observe attestations HONESTLY: none are wired yet, so report
    // none present and Cartorio status Pending. With attestation off
    // (scan-only) `SecuritySpec::scan_only()` requires no attestations,
    // so an empty set is non-drifting; with attestation on, the empty
    // set honestly surfaces as missing-attestation drift rather than a
    // fabricated pass. (Previously this hard-coded all four present +
    // Cartorio Active — a fake that let unattested digests pass the gate.)
    let attestations_present: BTreeSet<RequiredAttestation> = BTreeSet::new();

    SecuritySnapshot {
        image_digests: vec![DigestObservation {
            digest: parent.spec.image_digest.clone(),
            service: parent.spec.service.clone(),
            cartorio_status: CartorioStatus::Pending,
            findings,
            attestations_present,
            scanners_reported,
        }],
        observed_at: Utc::now(),
    }
}

fn scanner_required_from_kind(k: ScannerKind) -> RequiredScanner {
    use RequiredScanner as R;
    use ScannerKind as K;
    match k {
        K::Trivy => R::Trivy,
        K::Grype => R::Grype,
        K::Syft => R::Syft,
        K::Trufflehog => R::Trufflehog,
        K::Semgrep => R::Semgrep,
        K::KubeLinter => R::KubeLinter,
        K::KubeBench => R::KubeBench,
        K::KubeHunter => R::KubeHunter,
        K::Polaris => R::Polaris,
        K::StigCisValidator => R::StigCisValidator,
        K::Zap => R::Zap,
        K::Snyk => R::Snyk,
        K::DockerScout => R::DockerScout,
        K::JfrogXray => R::JfrogXray,
        K::Wiz => R::Wiz,
        K::PrismaCloud => R::PrismaCloud,
        K::BurpEnterprise => R::BurpEnterprise,
        K::Codeql => R::Codeql,
    }
}

fn map_severity(s: validation_crds::ScanFindingSeverity) -> FindingSeverity {
    use validation_crds::ScanFindingSeverity as V;
    use FindingSeverity as F;
    match s {
        V::Low => F::Low,
        V::Medium => F::Medium,
        V::High => F::High,
        V::Critical => F::Critical,
    }
}

fn canonical_findings_bytes(children: &[ScanJob]) -> Vec<u8> {
    // Canonical: sort by (scanner, cve_id), serialize as canonical JSON.
    let mut all = vec![];
    for c in children {
        if let Some(st) = c.status.as_ref() {
            for f in &st.findings {
                all.push(f.clone());
            }
        }
    }
    all.sort_by(|a, b| {
        a.scanner
            .cmp(&b.scanner)
            .then(a.cve_id.cmp(&b.cve_id))
            .then(a.first_seen.cmp(&b.first_seen))
    });
    serde_json::to_vec(&all).unwrap_or_default()
}

fn format_drift_reason(drift: &security_controller::SecurityDrift) -> String {
    let mut bits = vec![];
    if !drift.critical_cves.is_empty() {
        bits.push(format!("{} critical CVE(s)", drift.critical_cves.len()));
    }
    if !drift.aged_high_cves.is_empty() {
        bits.push(format!("{} aged High CVE(s)", drift.aged_high_cves.len()));
    }
    if !drift.aged_medium_cves.is_empty() {
        bits.push(format!("{} aged Medium CVE(s)", drift.aged_medium_cves.len()));
    }
    if !drift.missing_attestations.is_empty() {
        bits.push(format!("{} missing attestation(s)", drift.missing_attestations.len()));
    }
    if !drift.missing_scanners.is_empty() {
        bits.push(format!("{} missing scanner(s)", drift.missing_scanners.len()));
    }
    if !drift.revoked_or_quarantined.is_empty() {
        bits.push(format!("{} revoked/quarantined", drift.revoked_or_quarantined.len()));
    }
    if bits.is_empty() {
        "no drift".into()
    } else {
        bits.join("; ")
    }
}

/// Whether the controller runs in scan-only mode — attestation/signing
/// turned OFF. Set `VALIDATION_SCAN_ONLY=true` on the controller
/// Deployment to judge verdicts purely on CVE/SAST/DAST findings
/// without requiring (or fabricating) Cartorio/Cosign/SBOM/SLSA
/// attestations.
fn scan_only_mode() -> bool {
    std::env::var("VALIDATION_SCAN_ONLY")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false)
}

/// Build a fully-qualified, pullable image reference for a CVE scanner
/// from the image's repo + digest. Prefers the in-cluster Zot mirror
/// (`SCANNER_REGISTRY_MIRROR`, e.g.
/// `zot.zot-system.svc.cluster.local:5000`) so scanner Jobs pull
/// privately + air-gapped; falls back to bare `<repo>@<digest>` when no
/// mirror is configured.
fn pullable_image_ref(repo: &str, digest: &str) -> String {
    match std::env::var("SCANNER_REGISTRY_MIRROR")
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(mirror) => format!("{}/{}@{}", mirror.trim_end_matches('/'), repo, digest),
        None => format!("{repo}@{digest}"),
    }
}

fn security_spec_for(_promessa_ref: &str) -> SecuritySpec {
    // M1.5: resolve the promessa name to a typed SecuritySpec. With
    // attestation turned off (VALIDATION_SCAN_ONLY) we drop the
    // required-attestation set so verdicts rest purely on scan
    // findings. M2 wires this to promessa-runtime which reads the
    // .tatara source-of-truth and caches it.
    if scan_only_mode() {
        SecuritySpec::scan_only()
    } else {
        SecuritySpec::default()
    }
}
