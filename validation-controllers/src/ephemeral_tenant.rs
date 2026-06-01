//! `AkeylessEphemeralTenantController` — resolves the live DAST target
//! for a validation and exposes it as the tenant `ingress_url` the OSS
//! ZAP ScanJob probes (alongside the OSS CVE + SAST scanners).
//!
//! ## Architecture: feed a target now, generate one later
//!
//! DAST needs a LIVE HTTP target. A single akeyless service image can't
//! serve HTTP on its own (it needs the full auth/uam/kfm/gator mesh +
//! DB), so we do NOT stand up a fresh per-image mesh. Per the operator
//! decision (2026-06-01), this controller **resolves a fed target** —
//! `DAST_TARGET_URL`, pointing at the already-deployed self-hosted
//! akeyless SaaS Service — verifies it exists, and reports it as
//! `ingress_url`. When no target is configured it reports
//! `ingress_url = None` and DAST cleanly skips (empty findings) — never
//! a fabricated URL the scanner would fail against.
//!
//! The `resolve_dast_target` → `assess_target` seam is the extension
//! point for the future "generate one" mode (M2): an ephemeral
//! lareira-akeyless-deployment HelmRelease per validation. Today it
//! resolves; later `assess_target` can materialize.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config;
use kube::runtime::Controller;
use kube::{Api, ResourceExt};
use serde_json::json;
use tracing::{info, warn};
use validation_crds::{
    AkeylessEphemeralTenant, AkeylessEphemeralTenantPhase, AkeylessEphemeralTenantStatus,
};

use crate::context::ReconcileCtx;

#[derive(Debug, Clone, Default)]
pub struct AkeylessEphemeralTenantController;

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

/// Resolution of the fed DAST target.
enum TargetReadiness {
    /// Target resolved + verified reachable; carries the URL.
    ReadyAt(String),
    /// Target configured but its in-cluster Service isn't up yet — hold
    /// short of Ready so ZAP doesn't probe a missing endpoint.
    Waiting,
    /// No target configured — DAST is skipped (honest empty, not faked).
    NoTarget,
}

async fn reconcile(
    obj: Arc<AkeylessEphemeralTenant>,
    ctx: Arc<ReconcileCtx>,
) -> Result<Action, kube::Error> {
    use AkeylessEphemeralTenantPhase as P;
    let name = obj.name_any();
    let ns = obj.namespace().unwrap_or_default();
    let generation = obj.metadata.generation.unwrap_or(0);
    let current = obj
        .status
        .as_ref()
        .and_then(|s| s.phase)
        .unwrap_or(P::Pending);

    // Terminal / hold phases: nothing to do but requeue.
    match current {
        P::Ready | P::Scanning => return Ok(Action::requeue(Duration::from_secs(600))),
        P::Reaped | P::Failed => return Ok(Action::requeue(Duration::from_secs(3600))),
        P::Teardown => {
            let mut new = obj.status.clone().unwrap_or_default();
            new.observed_generation = generation;
            new.phase = Some(P::Reaped);
            new.teardown_started_at = Some(Utc::now());
            patch_status(&ctx, &ns, &name, &new).await?;
            return Ok(Action::requeue(Duration::from_secs(3600)));
        }
        _ => {}
    }

    // Resolve + assess the fed DAST target (the deployed self-hosted SaaS).
    let target = resolve_dast_target();
    let now = Utc::now();
    let mut new = obj.status.clone().unwrap_or_default();
    new.observed_generation = generation;
    if new.allocated_at.is_none() {
        new.allocated_at = Some(now);
    }

    let requeue = match assess_target(&ctx, target.as_deref()).await? {
        TargetReadiness::ReadyAt(url) => {
            new.phase = Some(P::Ready);
            new.ready_at = Some(now);
            new.ingress_url = Some(url);
            new.pods_ready = 1;
            new.pods_total = 1;
            new.pods_ready_over_total = Some("1/1".into());
            Duration::from_secs(600)
        }
        TargetReadiness::NoTarget => {
            warn!(
                tenant = %name,
                "DAST_TARGET_URL unset — DAST will be skipped (no fabricated target). \
                 Feed a target via the controller env or wire the generate-one mode (M2)."
            );
            new.phase = Some(P::Ready);
            new.ready_at = Some(now);
            new.ingress_url = None;
            new.pods_ready = 0;
            new.pods_total = 0;
            new.pods_ready_over_total = Some("0/0".into());
            Duration::from_secs(600)
        }
        TargetReadiness::Waiting => {
            // Configured but the SaaS Service isn't up yet — hold.
            new.phase = Some(P::PodsRunning);
            new.ingress_url = target.clone();
            Duration::from_secs(15)
        }
    };

    patch_status(&ctx, &ns, &name, &new).await?;
    info!(name = %name, phase = ?new.phase, target = ?new.ingress_url, "tenant reconciled");
    Ok(Action::requeue(requeue))
}

async fn patch_status(
    ctx: &ReconcileCtx,
    ns: &str,
    name: &str,
    status: &AkeylessEphemeralTenantStatus,
) -> Result<(), kube::Error> {
    let api: Api<AkeylessEphemeralTenant> = Api::namespaced(ctx.client.clone(), ns);
    let patch = json!({ "status": status });
    api.patch_status(name, &PatchParams::apply("validation-controllers"), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

/// The fed DAST target — `DAST_TARGET_URL`, typically the in-cluster
/// deployed-SaaS Service URL (e.g.
/// `http://akeyless-saas-dev.akeyless.svc.cluster.local:8080`). Unset =>
/// no DAST target => DAST skips honestly.
fn resolve_dast_target() -> Option<String> {
    std::env::var("DAST_TARGET_URL")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Parse an in-cluster Service URL
/// `scheme://<name>.<namespace>.svc(.cluster.local)?(:port)?/…` into
/// `(namespace, name)`. Returns `None` for external URLs (which we treat
/// as reachable without a Service check).
fn in_cluster_service_ref(url: &str) -> Option<(String, String)> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme.split(['/', ':']).next().unwrap_or("");
    if !host.contains(".svc") {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    // <name>.<ns>.svc[.cluster.local]
    if labels.len() >= 3 && labels[2] == "svc" {
        return Some((labels[1].to_owned(), labels[0].to_owned()));
    }
    None
}

/// Decide whether the fed target is ready. In-cluster Service targets are
/// gated on the Service existing (the deployed SaaS being up); external
/// URLs are assumed reachable; no target => skip.
async fn assess_target(
    ctx: &ReconcileCtx,
    target: Option<&str>,
) -> Result<TargetReadiness, kube::Error> {
    let Some(url) = target else {
        return Ok(TargetReadiness::NoTarget);
    };
    match in_cluster_service_ref(url) {
        Some((svc_ns, svc_name)) => {
            let svcs: Api<Service> = Api::namespaced(ctx.client.clone(), &svc_ns);
            if svcs.get_opt(&svc_name).await?.is_some() {
                Ok(TargetReadiness::ReadyAt(url.to_owned()))
            } else {
                Ok(TargetReadiness::Waiting)
            }
        }
        None => Ok(TargetReadiness::ReadyAt(url.to_owned())),
    }
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

    #[test]
    fn parses_in_cluster_service_url() {
        assert_eq!(
            in_cluster_service_ref("http://akeyless-saas-dev.akeyless.svc.cluster.local:8080/"),
            Some(("akeyless".into(), "akeyless-saas-dev".into()))
        );
        assert_eq!(
            in_cluster_service_ref("https://akeyless-gateway-dev.akeyless.svc:443"),
            Some(("akeyless".into(), "akeyless-gateway-dev".into()))
        );
    }

    #[test]
    fn external_url_is_not_an_in_cluster_service() {
        assert_eq!(in_cluster_service_ref("https://vault.staging.akeyless.io"), None);
        assert_eq!(in_cluster_service_ref("https://example.com/scan"), None);
    }
}
