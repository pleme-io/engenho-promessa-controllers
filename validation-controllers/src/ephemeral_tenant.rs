//! `AkeylessEphemeralTenantController` — drives a tenant CR through
//! its typed phases. M1.5 PoC: short-circuits to Ready immediately
//! without materializing real infrastructure (pangea + caixa-helm +
//! tatara-pool integration is the M2 deliverable). The typed phase
//! shape is correct so the rest of the chain advances; only the
//! "what runs underneath" is stubbed.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config;
use kube::runtime::Controller;
use kube::{Api, ResourceExt};
use serde_json::json;
use tracing::{info, warn};
use validation_crds::{AkeylessEphemeralTenant, AkeylessEphemeralTenantPhase};

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

async fn reconcile(
    obj: Arc<AkeylessEphemeralTenant>,
    ctx: Arc<ReconcileCtx>,
) -> Result<Action, kube::Error> {
    let name = obj.name_any();
    let ns = obj.namespace().unwrap_or_default();
    let current = obj
        .status
        .as_ref()
        .and_then(|s| s.phase)
        .unwrap_or(AkeylessEphemeralTenantPhase::Pending);

    let next = next_phase(current);
    if next == current {
        return Ok(Action::requeue(Duration::from_secs(600)));
    }

    let mut new = obj.status.clone().unwrap_or_default();
    new.phase = Some(next);
    new.observed_generation = obj.metadata.generation.unwrap_or(0);
    let now = Utc::now();
    if next == AkeylessEphemeralTenantPhase::Ready {
        new.ready_at = Some(now);
        new.ingress_url = Some(format!("https://{}-eph.dev.use1.quero.lol", obj.name_any()));
        // PoC: claim 1/1 pods (no real Deployment created).
        new.pods_ready = 1;
        new.pods_total = 1;
        new.pods_ready_over_total = Some("1/1".into());
    } else if next == AkeylessEphemeralTenantPhase::Reaped {
        new.teardown_started_at = Some(now);
    } else if matches!(current, AkeylessEphemeralTenantPhase::Pending)
        && matches!(next, AkeylessEphemeralTenantPhase::InfraProvisioning)
    {
        new.allocated_at = Some(now);
    }

    let api: Api<AkeylessEphemeralTenant> = Api::namespaced(ctx.client.clone(), &ns);
    let patch = json!({ "status": new });
    api.patch_status(&name, &PatchParams::apply("validation-controllers"), &Patch::Merge(&patch))
        .await?;
    info!(name = %name, ?next, "tenant phase advanced");

    Ok(Action::requeue(Duration::from_secs(5)))
}

fn next_phase(p: AkeylessEphemeralTenantPhase) -> AkeylessEphemeralTenantPhase {
    use AkeylessEphemeralTenantPhase::*;
    // M1.5 PoC: linear progression through all phases with no actual
    // infrastructure work. Each phase advances on next reconcile tick.
    match p {
        Pending => InfraProvisioning,
        InfraProvisioning => ChartRendering,
        ChartRendering => PodsRunning,
        PodsRunning => Ready,
        Ready => Ready, // hold; parent drives teardown
        Scanning => Scanning,
        Teardown => Reaped,
        Reaped => Reaped,
        Failed => Failed,
    }
}

fn error_policy(
    _obj: Arc<AkeylessEphemeralTenant>,
    _err: &kube::Error,
    _ctx: Arc<ReconcileCtx>,
) -> Action {
    Action::requeue(Duration::from_secs(30))
}
