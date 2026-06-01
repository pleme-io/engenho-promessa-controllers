//! `ScanJobController` — drives a ScanJob CR through tatara-reconciler's
//! 8-phase lifecycle. M1.5 PoC: skips the tatara Process CR layer and
//! runs a kube Job directly; full Process wrap-in lands in M2 once
//! tatara-reconciler is reachable from this cluster.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config;
use kube::runtime::Controller;
use kube::{Api, ResourceExt};
use serde_json::json;
use tracing::{info, warn};
use validation_crds::{
    AkeylessImageValidation, AttestationRef, ScanFinding, ScanJob, ScanJobPhase, ScannerKind,
};

use crate::context::ReconcileCtx;

#[derive(Debug, Clone, Default)]
pub struct ScanJobController;

pub async fn run(ctx: Arc<ReconcileCtx>) -> anyhow::Result<()> {
    let api: Api<ScanJob> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };
    info!("ScanJobController starting");
    Controller::new(api, Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                warn!(error = %e, "reconcile error");
            }
        })
        .await;
    Ok(())
}

async fn reconcile(obj: Arc<ScanJob>, ctx: Arc<ReconcileCtx>) -> Result<Action, kube::Error> {
    let name = obj.name_any();
    let ns = obj.namespace().unwrap_or_default();
    let current = obj
        .status
        .as_ref()
        .and_then(|s| s.phase)
        .unwrap_or(ScanJobPhase::Pending);

    let api: Api<ScanJob> = Api::namespaced(ctx.client.clone(), &ns);

    match current {
        ScanJobPhase::Pending => {
            create_scanner_job(&ctx, &obj).await?;
            patch_phase(&api, &name, ScanJobPhase::Forking, None, None).await?;
        }
        ScanJobPhase::Forking => {
            patch_phase(&api, &name, ScanJobPhase::Execing, None, None).await?;
        }
        ScanJobPhase::Execing => {
            patch_phase(&api, &name, ScanJobPhase::Running, None, None).await?;
        }
        ScanJobPhase::Running => {
            if let Some((findings, hash)) = collect_results(&ctx, &obj).await? {
                let attestation = AttestationRef {
                    hash,
                    ed25519_sig: None,
                    signed_at: Utc::now(),
                };
                patch_phase(
                    &api,
                    &name,
                    ScanJobPhase::Attested,
                    Some(findings.clone()),
                    Some(attestation),
                )
                .await?;
                // One FindingRecorded event per finding — emit once at
                // the Running→Attested transition. Idempotent because
                // subsequent reconciles see `current == Attested` and
                // skip this arm entirely.
                emit_findings_recorded(&ctx, &obj, &findings).await;
            }
        }
        ScanJobPhase::Attested
        | ScanJobPhase::Reconverging
        | ScanJobPhase::Exiting
        | ScanJobPhase::Failed
        | ScanJobPhase::Zombie
        | ScanJobPhase::Reaped => {
            return Ok(Action::requeue(Duration::from_secs(3600)));
        }
    }

    Ok(Action::requeue(Duration::from_secs(15)))
}

fn error_policy(_obj: Arc<ScanJob>, _err: &kube::Error, _ctx: Arc<ReconcileCtx>) -> Action {
    Action::requeue(Duration::from_secs(30))
}

async fn patch_phase(
    api: &Api<ScanJob>,
    name: &str,
    phase: ScanJobPhase,
    findings: Option<Vec<ScanFinding>>,
    attestation: Option<AttestationRef>,
) -> Result<(), kube::Error> {
    let mut status = json!({ "phase": phase });
    if let Some(f) = findings {
        status["findingsCount"] = json!(f.len() as u64);
        status["findings"] = json!(f);
    }
    if let Some(a) = attestation {
        status["attestationRef"] = json!(a);
    }
    let patch = json!({ "status": status });
    api.patch_status(name, &PatchParams::apply("validation-controllers"), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

async fn create_scanner_job(ctx: &ReconcileCtx, sj: &ScanJob) -> Result<(), kube::Error> {
    let ns = sj.namespace().unwrap_or_default();
    let jobs: Api<Job> = Api::namespaced(ctx.client.clone(), &ns);
    let job_name = format!("job-{}", sj.name_any());
    if jobs.get_opt(&job_name).await?.is_some() {
        return Ok(());
    }
    let job = render_job(&job_name, sj);
    jobs.create(&PostParams::default(), &job).await?;
    info!(job = %job_name, scanner = ?sj.spec.scanner, "scanner job created");
    Ok(())
}

fn render_job(job_name: &str, sj: &ScanJob) -> Job {
    use k8s_openapi::api::batch::v1::JobSpec;
    use k8s_openapi::api::core::v1::{
        Capabilities, Container, EmptyDirVolumeSource, EnvVar, LocalObjectReference,
        PodSecurityContext, PodSpec, PodTemplateSpec, SeccompProfile, SecurityContext, Volume,
        VolumeMount,
    };

    let ns = sj.namespace().unwrap_or_default();
    let (image, args) = scanner_image_and_args(sj);

    Job {
        metadata: ObjectMeta {
            name: Some(job_name.into()),
            namespace: Some(ns.clone()),
            labels: Some({
                let mut m = BTreeMap::new();
                m.insert("scan-job".into(), sj.name_any());
                m.insert("scanner".into(), format!("{:?}", sj.spec.scanner).to_lowercase());
                m
            }),
            owner_references: owner_refs_of(sj),
            ..Default::default()
        },
        spec: Some(JobSpec {
            backoff_limit: Some(2),
            ttl_seconds_after_finished: Some(3600),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some({
                        let mut m = BTreeMap::new();
                        m.insert("scan-job".into(), sj.name_any());
                        m
                    }),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    restart_policy: Some("Never".into()),
                    // Pull the scanner tool image (and, for kubelet-side
                    // pulls, the target) from the private Zot. Harmless if
                    // Zot allows anonymous read; required if it doesn't.
                    image_pull_secrets: Some(vec![LocalObjectReference {
                        name: "zot-pull-secret".into(),
                    }]),
                    security_context: Some(PodSecurityContext {
                        run_as_non_root: Some(true),
                        run_as_user: Some(65532),
                        fs_group: Some(65532),
                        seccomp_profile: Some(SeccompProfile {
                            type_: "RuntimeDefault".into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    containers: vec![Container {
                        name: "scanner".into(),
                        image: Some(image),
                        args: Some(args),
                        security_context: Some(SecurityContext {
                            allow_privilege_escalation: Some(false),
                            read_only_root_filesystem: Some(true),
                            capabilities: Some(Capabilities {
                                drop: Some(vec!["ALL".into()]),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        // Let the OSS scanners reach the plain-HTTP
                        // in-cluster Zot for the image-under-test. Trivy /
                        // Grype / Syft each have their own insecure-registry
                        // toggles; setting all is harmless to scanners that
                        // ignore them.
                        env: Some(
                            [
                                ("TRIVY_CACHE_DIR", "/scan/cache"),
                                ("TRIVY_INSECURE", "true"),
                                ("TRIVY_NON_SSL", "true"),
                                ("GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY", "true"),
                                ("GRYPE_REGISTRY_INSECURE_USE_HTTP", "true"),
                                ("SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY", "true"),
                                ("SYFT_REGISTRY_INSECURE_USE_HTTP", "true"),
                            ]
                            .into_iter()
                            .map(|(k, v)| EnvVar {
                                name: k.into(),
                                value: Some(v.into()),
                                ..Default::default()
                            })
                            .collect(),
                        ),
                        volume_mounts: Some(vec![
                            VolumeMount {
                                name: "scan-result".into(),
                                mount_path: "/scan".into(),
                                ..Default::default()
                            },
                            VolumeMount {
                                name: "tmp".into(),
                                mount_path: "/tmp".into(),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }],
                    volumes: Some(vec![
                        Volume {
                            name: "scan-result".into(),
                            empty_dir: Some(EmptyDirVolumeSource::default()),
                            ..Default::default()
                        },
                        Volume {
                            name: "tmp".into(),
                            empty_dir: Some(EmptyDirVolumeSource::default()),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Resolve (image, args) for a ScanJob from the canonical
/// `scanner-catalog` (reusable substrate). The image string is
/// optionally rewritten via `scanner_catalog::mirror_image` when the
/// `SCANNER_REGISTRY_MIRROR` env var is set — pleme-dev sets this to
/// `zot.zot-system.svc.cluster.local:5000` so scanner Jobs pull
/// from the in-cluster private Zot instead of public Docker Hub /
/// ghcr.io / quay.io.
fn scanner_image_and_args(sj: &ScanJob) -> (String, Vec<String>) {
    use scanner_catalog::{mirror_image, Catalog, TargetField};
    let entry = Catalog::for_kind(sj.spec.scanner);
    let target = match entry.target_field {
        TargetField::Digest => sj.spec.target_digest.as_deref(),
        TargetField::Source => sj.spec.target_source.as_deref(),
        TargetField::TenantUrl => sj.spec.target_tenant_url.as_deref(),
        TargetField::None => None,
    };
    let args = entry.args.render(target);
    let mirror = std::env::var("SCANNER_REGISTRY_MIRROR").ok();
    let image = mirror_image(entry.image, mirror.as_deref());
    (image, args)
}

fn owner_refs_of(
    parent: &ScanJob,
) -> Option<Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>> {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
    Some(vec![OwnerReference {
        api_version: "validation.pleme.io/v1".into(),
        kind: "ScanJob".into(),
        name: parent.name_any(),
        uid: parent.uid().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }])
}

async fn collect_results(
    ctx: &ReconcileCtx,
    sj: &ScanJob,
) -> Result<Option<(Vec<ScanFinding>, String)>, kube::Error> {
    let ns = sj.namespace().unwrap_or_default();
    let job_name = format!("job-{}", sj.name_any());

    let jobs: Api<Job> = Api::namespaced(ctx.client.clone(), &ns);
    let Some(job) = jobs.get_opt(&job_name).await? else {
        return Ok(None);
    };
    let succeeded = job.status.as_ref().and_then(|s| s.succeeded).unwrap_or(0) > 0;
    let failed = job.status.as_ref().and_then(|s| s.failed).unwrap_or(0) > 0;
    if !succeeded && !failed {
        return Ok(None);
    }

    use k8s_openapi::api::core::v1::Pod;
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &ns);
    let label = format!("scan-job={}", sj.name_any());
    let pod_list = pods
        .list(&kube::api::ListParams::default().labels(&label))
        .await?;
    let Some(pod) = pod_list.items.first() else {
        return Ok(Some((vec![], blake3::hash(b"[]").to_hex().to_string())));
    };
    let pod_name = pod.name_any();
    let logs = pods
        .logs(&pod_name, &kube::api::LogParams::default())
        .await
        .unwrap_or_default();
    let findings = parse_scanner_output(&logs, sj.spec.scanner);
    let canonical = serde_json::to_vec(&findings).unwrap_or_default();
    let hash = blake3::hash(&canonical).to_hex().to_string();

    // ConfigMap snapshot for inspection.
    let cms: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &ns);
    let cm_name = format!("scan-result-{}", sj.name_any());
    let mut data = BTreeMap::new();
    data.insert("result.json".into(), logs);
    data.insert("scanner".into(), format!("{:?}", sj.spec.scanner));
    data.insert("findings-count".into(), findings.len().to_string());
    let cm = ConfigMap {
        metadata: ObjectMeta {
            name: Some(cm_name.clone()),
            namespace: Some(ns.clone()),
            labels: Some({
                let mut m = BTreeMap::new();
                m.insert("scan-result".into(), sj.name_any());
                m
            }),
            owner_references: owner_refs_of(sj),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    if cms.get_opt(&cm_name).await?.is_none() {
        let _ = cms.create(&PostParams::default(), &cm).await;
    }

    Ok(Some((findings, hash)))
}

/// Parse scanner stdout via the canonical `scanner-catalog::parsers`
/// dispatch. The catalog owns the output-format → parser mapping;
/// this function is the substrate-facing seam.
///
/// On `ParserError::NoParser` (scanners we can spawn but don't yet
/// interpret — commercial / heavy), returns an empty Vec with a
/// tracing warning so operators see the scanner ran but didn't
/// surface. On `ParserError::Json` (schema drift / regression),
/// returns empty + a tracing error.
fn parse_scanner_output(raw: &str, scanner: ScannerKind) -> Vec<ScanFinding> {
    match scanner_catalog::parse_scanner_output(raw, scanner) {
        Ok(findings) => findings,
        Err(scanner_catalog::ParserError::NoParser { scanner }) => {
            tracing::warn!(
                ?scanner,
                "scanner-catalog has no parser yet (OutputFormat::NoOp) — \
                 findings not surfaced for this run"
            );
            vec![]
        }
        Err(err) => {
            tracing::error!(?scanner, %err, "scanner-catalog parser error");
            vec![]
        }
    }
}

/// Emit one `FindingRecorded` event per finding to the security-posture
/// NATS stream. Looks up the parent `AkeylessImageValidation` once for
/// image identity (digest/repo/service/uid) — if the lookup fails (CR
/// already deleted / wrong namespace), the findings still land in the
/// ScanJob CR status; only the event tap goes dark.
///
/// The publisher is `Disconnected` when NATS_URL is unset → every
/// `publish` is a typed no-op. So this code path is cheap to keep in
/// the hot loop even when no broker is wired.
async fn emit_findings_recorded(
    ctx: &ReconcileCtx,
    sj: &ScanJob,
    findings: &[ScanFinding],
) {
    if findings.is_empty() {
        return;
    }
    use validation_events::{FindingRecorded, ValidationEvent};

    let ns = sj.namespace().unwrap_or_default();
    let parent_api: Api<AkeylessImageValidation> =
        Api::namespaced(ctx.client.clone(), &ns);
    let Ok(Some(parent)) = parent_api.get_opt(&sj.spec.parent_validation).await else {
        tracing::debug!(
            scan_job = %sj.name_any(),
            parent = %sj.spec.parent_validation,
            "FindingRecorded: parent AkeylessImageValidation not found — partial emit skipped"
        );
        return;
    };

    let uid = parent.metadata.uid.clone().unwrap_or_default();
    let service = parent.spec.service.clone();
    let image_digest = parent.spec.image_digest.clone();
    let image_repo = parent.spec.image_repo.clone();
    let scanner_class = scanner_catalog::Catalog::for_kind(sj.spec.scanner).class;

    for f in findings {
        let event = ValidationEvent::FindingRecorded(FindingRecorded {
            event_id: validation_events::new_event_id(),
            validation_run_uid: uid.clone(),
            service: service.clone(),
            image_digest: image_digest.clone(),
            image_repo: image_repo.clone(),
            observed_at: Utc::now(),
            scanner: f.scanner,
            scanner_class,
            severity: f.severity,
            cve_id: f.cve_id.clone(),
            // ScanFinding has no package field today; subscribers see
            // None and can fall back to the `message` channel on the
            // store row when they need the package coordinate.
            package: None,
        });
        ctx.events_publisher.publish(&event).await;
    }
}
