//! `validation-controllers` — the five reconcilers driving the
//! AKEYLESS-VALIDATION-PLATFORM lifecycle. See
//! pleme-io/theory/AKEYLESS-VALIDATION-PLATFORM.md Part IV.
//!
//! Each reconciler is a kube-rs `Controller` watching one CRD; phases
//! advance through typed `.status` writes; failure modes are
//! observable `.status.phase = Failed` events, never timeouts.
//!
//! ## Reconciler roster
//!
//! 1. [`image_validation`] — drives `AkeylessImageValidation` phases.
//! 2. [`ephemeral_tenant`] — drives `AkeylessEphemeralTenant` phases.
//! 3. [`scan_job`] — drives `ScanJob` phases.
//! 4. [`outcome_chain`] — appends terminal-phase receipts to MinIO.
//! 5. [`action_dispatcher`] — routes `.status.gateDecision.action`
//!    typed actions through [`reconciler_engine::ActionExecutor`].

use std::sync::Arc;

use kube::Client;
use validation_store::ValidationStore;

pub mod action_dispatcher;
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

/// Spawn all five reconcilers concurrently. Returns when any one
/// terminates (typically meaning the cluster lost connection — caller
/// should restart the process per the K8s deployment liveness probe).
pub async fn run_all(
    client: Client,
    namespace: Option<String>,
    validation_store: Arc<ValidationStore>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(ReconcileCtx::new(client, namespace, validation_store));

    let h_iv = tokio::spawn(image_validation::run(ctx.clone()));
    let h_eph = tokio::spawn(ephemeral_tenant::run(ctx.clone()));
    let h_sj = tokio::spawn(scan_job::run(ctx.clone()));
    let h_oc = tokio::spawn(outcome_chain::run(ctx.clone()));
    let h_ad = tokio::spawn(action_dispatcher::run(ctx));

    tokio::select! {
        r = h_iv  => { tracing::error!(?r, "image_validation reconciler exited"); r??; }
        r = h_eph => { tracing::error!(?r, "ephemeral_tenant reconciler exited"); r??; }
        r = h_sj  => { tracing::error!(?r, "scan_job reconciler exited"); r??; }
        r = h_oc  => { tracing::error!(?r, "outcome_chain appender exited"); r??; }
        r = h_ad  => { tracing::error!(?r, "action_dispatcher exited"); r??; }
    }
    Ok(())
}
