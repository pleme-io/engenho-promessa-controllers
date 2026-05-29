//! `AkeylessEphemeralTenantController` — materializes a real ephemeral
//! Akeyless environment from a tenant CR and drives it through its
//! typed phases.
//!
//! This is where the two halves of the solution unify: the tenant's
//! **`digest_set`** (the scanned + signed image digests) derives a
//! deterministic **`ephemeral_id`** (`BLAKE3(sorted service@digest)[:8]`)
//! that names BOTH the `akeyless-eph-<id>` namespace AND the
//! consistent-hash DNS hostname. The controller emits a
//! `lareira-akeyless-deployment` HelmRelease with
//! `hostnames.ephemeral.id=<id>` + digest-pinned images, waits for pods
//! to become ready, then publishes the real ingress URL DAST scans.
//!
//! Design follows the codebase's controller idiom: pure, unit-tested
//! decision/render helpers (`ephemeral_id`, `tenant_namespace`,
//! `ingress_url`, `render_helmrelease`, `is_expired`,
//! `decide_next_phase`) + a thin `reconcile` that performs the kube
//! I/O. Infra provisioning (pangea `InfrastructureTemplate` for external
//! RDS/Redis/RabbitMQ) is the chart's in-cluster data tier in this M2
//! cut; the `infra_template` spec field drives the external variant
//! later.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams};
use kube::core::ApiResource;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config;
use kube::runtime::Controller;
use kube::{Api, ResourceExt};
use serde_json::{json, Value};
use tracing::{info, warn};
use validation_crds::{
    AkeylessEphemeralTenant, AkeylessEphemeralTenantPhase, DigestSetEntry,
};

use crate::context::ReconcileCtx;

#[derive(Debug, Clone, Default)]
pub struct AkeylessEphemeralTenantController;

/// Fleet routing segments for the ephemeral env's hash-DNS hostname.
/// Mirrors tatara's `TATARA_FLEET_*` so the URL the tenant publishes is
/// byte-identical to what the lareira chart renders for the same id.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FleetConfig {
    cluster: String,
    location: String,
    domain: String,
}

impl FleetConfig {
    fn from_env() -> Self {
        Self {
            cluster: env_or("TATARA_FLEET_CLUSTER", "pleme-dev"),
            location: env_or("TATARA_FLEET_LOCATION", "use1"),
            domain: env_or("TATARA_FLEET_DOMAIN", "quero.lol"),
        }
    }
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

/// Deterministic ephemeral id from the scanned digest set.
///
/// `BLAKE3(sorted "service@digest" lines)[:8]`. Binds the env's
/// IDENTITY (namespace + DNS) to its image PROVENANCE: the same set of
/// scanned/signed digests always yields the same id — reproducible,
/// and the same 8-hex shape tatara stamps for its Process eph_id.
fn ephemeral_id(digest_set: &[DigestSetEntry]) -> String {
    let mut lines: Vec<String> = digest_set
        .iter()
        .map(|e| format!("{}@{}", e.service, e.digest))
        .collect();
    lines.sort();
    let canonical = lines.join("\n");
    blake3::hash(canonical.as_bytes()).to_hex()[..8].to_string()
}

/// The namespace the tenant's workloads land in.
fn tenant_namespace(id: &str) -> String {
    format!("akeyless-eph-{id}")
}

/// The flux-system name of the emitted HelmRelease.
fn helmrelease_name(id: &str) -> String {
    format!("akeyless-eph-{id}")
}

/// The real hash-DNS ingress URL DAST probes — the SaaS component's
/// ephemeral hostname, byte-identical to the lareira chart's render for
/// `hostnames.ephemeral.id=<id>`.
fn ingress_url(id: &str, fleet: &FleetConfig) -> String {
    format!(
        "https://akeyless-saas.{id}.{}.{}.{}",
        fleet.cluster, fleet.location, fleet.domain
    )
}

/// TTL safety-net: force teardown once `ttl_seconds` past `allocated_at`.
fn is_expired(allocated_at: Option<DateTime<Utc>>, ttl_seconds: u64, now: DateTime<Utc>) -> bool {
    match allocated_at {
        Some(t) => now >= t + chrono::Duration::seconds(ttl_seconds as i64),
        None => false,
    }
}

/// Render the `lareira-akeyless-deployment` HelmRelease that
/// materializes the tenant: gateway-with-internal-saas profile, the
/// consistent-hash DNS, the `akeyless-eph-<id>` namespace, and
/// digest-pinned images from the scanned `digest_set` (pulled from the
/// in-cluster private zot).
fn render_helmrelease(
    tenant_name: &str,
    id: &str,
    ns: &str,
    fleet: &FleetConfig,
    digest_set: &[DigestSetEntry],
) -> Value {
    let mut per_service = serde_json::Map::new();
    for e in digest_set {
        per_service.insert(e.service.clone(), json!({ "digest": e.digest }));
    }
    json!({
        "apiVersion": "helm.toolkit.fluxcd.io/v2",
        "kind": "HelmRelease",
        "metadata": {
            "name": helmrelease_name(id),
            "namespace": "flux-system",
            "labels": {
                "validation.pleme.io/ephemeral-tenant": tenant_name,
                "validation.pleme.io/ephemeral-id": id,
            }
        },
        "spec": {
            "interval": "5m",
            "install": { "remediation": { "retries": 0 } },
            "chart": { "spec": {
                "chart": "lareira-akeyless-deployment",
                "version": ">=0.6.0",
                "sourceRef": { "kind": "HelmRepository", "name": "pleme-charts", "namespace": "mesh-system" }
            }},
            "values": {
                "profile": "gateway-with-internal-saas",
                "cluster": { "name": fleet.cluster, "namespace": ns, "createNamespace": true },
                "hostnames": {
                    "enabled": true,
                    "domain": fleet.domain,
                    "location": fleet.location,
                    "cluster": fleet.cluster,
                    "ingressClassName": "nginx",
                    "ephemeral": { "enabled": true, "id": id }
                },
                // Digest-pinned images from the scanned/signed cohort in
                // the in-cluster private zot — the fedramp-high overlay
                // enforces sha256 pins.
                "images": {
                    "registry": "zot.zot-system.svc.cluster.local:5000",
                    "perService": Value::Object(per_service)
                }
            }
        }
    })
}

/// What the controller observed about the world this tick.
#[derive(Clone, Copy, Debug)]
struct Observed {
    hr_applied: bool,
    pods_ready: u32,
    pods_total: u32,
    expired: bool,
}

/// Pure phase decision from current phase + observed cluster state.
fn decide_next_phase(
    current: AkeylessEphemeralTenantPhase,
    obs: Observed,
) -> AkeylessEphemeralTenantPhase {
    use AkeylessEphemeralTenantPhase::*;
    // Expiry (or an already-running teardown) wins, except once Reaped.
    if obs.expired && !matches!(current, Teardown | Reaped | Failed) {
        return Teardown;
    }
    match current {
        Pending => InfraProvisioning,
        // M2 cut: the chart carries the in-cluster data tier, so infra
        // provisioning is a no-op pass-through (the external pangea
        // InfraTemplate variant slots in here later).
        InfraProvisioning => ChartRendering,
        ChartRendering => {
            if obs.hr_applied {
                PodsRunning
            } else {
                ChartRendering
            }
        }
        PodsRunning => {
            if obs.pods_total > 0 && obs.pods_ready >= obs.pods_total {
                Ready
            } else {
                PodsRunning
            }
        }
        Ready => Ready,         // hold; expiry / parent-terminal drives teardown
        Scanning => Scanning,   // parent (DAST) owns this phase
        Teardown => Reaped,
        Reaped => Reaped,
        Failed => Failed,
    }
}

pub async fn run(ctx: Arc<ReconcileCtx>) -> anyhow::Result<()> {
    let api: Api<AkeylessEphemeralTenant> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };
    info!("AkeylessEphemeralTenantController starting");
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

/// Dynamic Api handle for Flux HelmReleases in flux-system.
fn helmrelease_api(ctx: &ReconcileCtx) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk("helm.toolkit.fluxcd.io", "v2", "HelmRelease");
    let ar = ApiResource::from_gvk(&gvk);
    Api::namespaced_with(ctx.client.clone(), "flux-system", &ar)
}

/// Count ready / total pods in the tenant namespace.
async fn observe_pods(ctx: &ReconcileCtx, ns: &str) -> (u32, u32) {
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), ns);
    match pods.list(&ListParams::default()).await {
        Ok(list) => {
            let total = list.items.len() as u32;
            let ready = list
                .items
                .iter()
                .filter(|p| pod_is_ready(p))
                .count() as u32;
            (ready, total)
        }
        Err(_) => (0, 0),
    }
}

/// A pod is ready when its `Ready` condition is `True`.
fn pod_is_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|cs| {
            cs.iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        })
        .unwrap_or(false)
}

async fn reconcile(
    obj: Arc<AkeylessEphemeralTenant>,
    ctx: Arc<ReconcileCtx>,
) -> Result<Action, kube::Error> {
    let name = obj.name_any();
    let cr_ns = obj.namespace().unwrap_or_default();
    let fleet = FleetConfig::from_env();
    let id = ephemeral_id(&obj.spec.digest_set);
    let ns = tenant_namespace(&id);

    let status = obj.status.clone().unwrap_or_default();
    let current = status.phase.unwrap_or(AkeylessEphemeralTenantPhase::Pending);
    let now = Utc::now();

    // ── Observe ──────────────────────────────────────────────────────
    let expired = is_expired(status.allocated_at, obj.spec.ttl_seconds, now);
    let hr_applied = status.helm_release_ref.is_some();
    let (pods_ready, pods_total) = if matches!(
        current,
        AkeylessEphemeralTenantPhase::PodsRunning | AkeylessEphemeralTenantPhase::Ready
    ) {
        observe_pods(&ctx, &ns).await
    } else {
        (0, 0)
    };
    let obs = Observed { hr_applied, pods_ready, pods_total, expired };

    let next = decide_next_phase(current, obs);

    // Steady state with nothing to refresh → long requeue.
    if next == current
        && !matches!(current, AkeylessEphemeralTenantPhase::PodsRunning)
    {
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    let mut new = status;
    new.phase = Some(next);
    new.observed_generation = obj.metadata.generation.unwrap_or(0);

    // ── Act on the transition ────────────────────────────────────────
    match next {
        AkeylessEphemeralTenantPhase::InfraProvisioning => {
            if new.allocated_at.is_none() {
                new.allocated_at = Some(now);
            }
        }
        AkeylessEphemeralTenantPhase::ChartRendering => {
            // Emit the lareira HelmRelease that materializes the tenant.
            let manifest = render_helmrelease(&name, &id, &ns, &fleet, &obj.spec.digest_set);
            let hr: DynamicObject = serde_json::from_value(manifest)
                .map_err(|e| kube::Error::Service(Box::new(e)))?;
            let hr_name = helmrelease_name(&id);
            helmrelease_api(&ctx)
                .patch(
                    &hr_name,
                    &PatchParams::apply("validation-controllers").force(),
                    &Patch::Apply(&hr),
                )
                .await?;
            new.helm_release_ref = Some(format!("flux-system/{hr_name}"));
            info!(name = %name, id = %id, ns = %ns, "emitted ephemeral HelmRelease");
        }
        AkeylessEphemeralTenantPhase::PodsRunning => {
            new.pods_ready = pods_ready;
            new.pods_total = pods_total;
            new.pods_ready_over_total = Some(format!("{pods_ready}/{pods_total}"));
        }
        AkeylessEphemeralTenantPhase::Ready => {
            new.ready_at = Some(now);
            new.ingress_url = Some(ingress_url(&id, &fleet));
            new.pods_ready = pods_ready;
            new.pods_total = pods_total;
            new.pods_ready_over_total = Some(format!("{pods_ready}/{pods_total}"));
            info!(name = %name, url = %ingress_url(&id, &fleet), "ephemeral tenant Ready");
        }
        AkeylessEphemeralTenantPhase::Teardown => {
            // Deleting the HelmRelease prunes the workloads + namespace.
            if let Some(hr_ref) = &new.helm_release_ref {
                let hr_name = hr_ref.rsplit('/').next().unwrap_or(hr_ref).to_string();
                if let Err(e) = helmrelease_api(&ctx)
                    .delete(&hr_name, &Default::default())
                    .await
                {
                    warn!(error = %e, "failed to delete ephemeral HelmRelease (will retry)");
                }
            }
            new.teardown_started_at = Some(now);
            info!(name = %name, id = %id, "ephemeral tenant teardown");
        }
        _ => {}
    }

    let api: Api<AkeylessEphemeralTenant> = Api::namespaced(ctx.client.clone(), &cr_ns);
    let patch = json!({ "status": new });
    api.patch_status(
        &name,
        &PatchParams::apply("validation-controllers"),
        &Patch::Merge(&patch),
    )
    .await?;
    info!(name = %name, ?next, "tenant phase advanced");

    Ok(Action::requeue(Duration::from_secs(10)))
}

fn error_policy(
    _obj: Arc<AkeylessEphemeralTenant>,
    _err: &kube::Error,
    _ctx: Arc<ReconcileCtx>,
) -> Action {
    Action::requeue(Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ds(pairs: &[(&str, &str)]) -> Vec<DigestSetEntry> {
        pairs
            .iter()
            .map(|(s, d)| DigestSetEntry { service: s.to_string(), digest: d.to_string() })
            .collect()
    }

    fn fleet() -> FleetConfig {
        FleetConfig {
            cluster: "pleme-dev".into(),
            location: "use1".into(),
            domain: "quero.lol".into(),
        }
    }

    #[test]
    fn ephemeral_id_is_deterministic_and_order_independent() {
        let a = ephemeral_id(&ds(&[("auth", "sha256:aa"), ("uam", "sha256:bb")]));
        let b = ephemeral_id(&ds(&[("uam", "sha256:bb"), ("auth", "sha256:aa")]));
        assert_eq!(a, b, "id must be independent of digest_set ordering");
        assert_eq!(a.len(), 8, "id is 8 hex chars (tatara eph_id shape)");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ephemeral_id_changes_with_provenance() {
        let a = ephemeral_id(&ds(&[("auth", "sha256:aa")]));
        let b = ephemeral_id(&ds(&[("auth", "sha256:CHANGED")]));
        assert_ne!(a, b, "a different scanned digest → a different env id");
    }

    #[test]
    fn namespace_and_dns_share_the_id() {
        let id = ephemeral_id(&ds(&[("auth", "sha256:aa")]));
        assert_eq!(tenant_namespace(&id), format!("akeyless-eph-{id}"));
        assert_eq!(
            ingress_url(&id, &fleet()),
            format!("https://akeyless-saas.{id}.pleme-dev.use1.quero.lol")
        );
    }

    #[test]
    fn helmrelease_pins_digests_and_sets_hash_dns() {
        let id = "9a3f0b2c";
        let hr = render_helmrelease(
            "tenant-x",
            id,
            "akeyless-eph-9a3f0b2c",
            &fleet(),
            &ds(&[("auth", "sha256:aaa"), ("gateway", "sha256:ggg")]),
        );
        let v = &hr["spec"]["values"];
        assert_eq!(v["hostnames"]["ephemeral"]["id"], json!(id));
        assert_eq!(v["hostnames"]["ephemeral"]["enabled"], json!(true));
        assert_eq!(v["cluster"]["namespace"], json!("akeyless-eph-9a3f0b2c"));
        assert_eq!(v["images"]["perService"]["auth"]["digest"], json!("sha256:aaa"));
        assert_eq!(v["images"]["perService"]["gateway"]["digest"], json!("sha256:ggg"));
        assert_eq!(hr["kind"], json!("HelmRelease"));
    }

    #[test]
    fn ttl_expiry() {
        let t0 = Utc::now();
        assert!(!is_expired(Some(t0), 3600, t0 + chrono::Duration::seconds(10)));
        assert!(is_expired(Some(t0), 3600, t0 + chrono::Duration::seconds(3601)));
        assert!(!is_expired(None, 3600, t0), "no allocation → never expired");
    }

    #[test]
    fn phase_machine_drives_on_observed_state() {
        use AkeylessEphemeralTenantPhase::*;
        let not_ready = Observed { hr_applied: false, pods_ready: 0, pods_total: 0, expired: false };
        assert_eq!(decide_next_phase(Pending, not_ready), InfraProvisioning);
        assert_eq!(decide_next_phase(InfraProvisioning, not_ready), ChartRendering);
        // ChartRendering holds until the HR is applied.
        assert_eq!(decide_next_phase(ChartRendering, not_ready), ChartRendering);
        let hr_up = Observed { hr_applied: true, pods_ready: 0, pods_total: 3, expired: false };
        assert_eq!(decide_next_phase(ChartRendering, hr_up), PodsRunning);
        // PodsRunning holds until all pods ready.
        assert_eq!(decide_next_phase(PodsRunning, hr_up), PodsRunning);
        let all_ready = Observed { hr_applied: true, pods_ready: 3, pods_total: 3, expired: false };
        assert_eq!(decide_next_phase(PodsRunning, all_ready), Ready);
        assert_eq!(decide_next_phase(Ready, all_ready), Ready);
    }

    #[test]
    fn expiry_forces_teardown_then_reaped() {
        use AkeylessEphemeralTenantPhase::*;
        let expired = Observed { hr_applied: true, pods_ready: 3, pods_total: 3, expired: true };
        assert_eq!(decide_next_phase(Ready, expired), Teardown);
        assert_eq!(decide_next_phase(PodsRunning, expired), Teardown);
        assert_eq!(decide_next_phase(Teardown, expired), Reaped);
        assert_eq!(decide_next_phase(Reaped, expired), Reaped, "reaped is terminal");
    }
}
