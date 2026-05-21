//! `validation-controllers` — the four reconcilers driving the
//! AKEYLESS-VALIDATION-PLATFORM lifecycle. See
//! pleme-io/theory/AKEYLESS-VALIDATION-PLATFORM.md Part IV.
//!
//! Each reconciler is a kube-rs `Controller` watching one CRD; phases
//! advance through typed `.status` writes; failure modes are
//! observable `.status.phase = Failed` events, never timeouts.

use std::sync::Arc;

use kube::Client;

pub mod context;
pub mod ephemeral_tenant;
pub mod image_validation;
pub mod outcome_chain;
pub mod scan_job;

pub use context::ReconcileCtx;
pub use ephemeral_tenant::AkeylessEphemeralTenantController;
pub use image_validation::AkeylessImageValidationController;
pub use outcome_chain::OutcomeChainAppender;
pub use scan_job::ScanJobController;

/// Spawn all four reconcilers concurrently. Returns when any one
/// terminates (typically meaning the cluster lost connection — caller
/// should restart the process per the K8s deployment liveness probe).
pub async fn run_all(client: Client, namespace: Option<String>) -> anyhow::Result<()> {
    let ctx = Arc::new(ReconcileCtx::new(client, namespace));

    let h_iv = tokio::spawn(image_validation::run(ctx.clone()));
    let h_eph = tokio::spawn(ephemeral_tenant::run(ctx.clone()));
    let h_sj = tokio::spawn(scan_job::run(ctx.clone()));
    let h_oc = tokio::spawn(outcome_chain::run(ctx));

    tokio::select! {
        r = h_iv  => { tracing::error!(?r, "image_validation reconciler exited"); r??; }
        r = h_eph => { tracing::error!(?r, "ephemeral_tenant reconciler exited"); r??; }
        r = h_sj  => { tracing::error!(?r, "scan_job reconciler exited"); r??; }
        r = h_oc  => { tracing::error!(?r, "outcome_chain appender exited"); r??; }
    }
    Ok(())
}
