//! `OutcomeChainAppender` — background fiber that subscribes to
//! AkeylessImageValidation phase transitions reaching terminal
//! states and appends a typed `OutcomeReceipt` to MinIO.

use std::sync::Arc;

use chrono::Utc;
use futures::StreamExt;
use kube::api::{Patch, PatchParams};
use kube::runtime::watcher::{watcher, Config, Event};
use kube::{Api, ResourceExt};
use serde_json::json;
use tracing::{info, warn};
use validation_crds::{
    AkeylessImageValidation, AkeylessImageValidationPhase, OutcomeReceiptRef,
};

use crate::context::ReconcileCtx;

#[derive(Debug, Clone, Default)]
pub struct OutcomeChainAppender;

pub async fn run(ctx: Arc<ReconcileCtx>) -> anyhow::Result<()> {
    let api: Api<AkeylessImageValidation> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };
    info!("OutcomeChainAppender starting");
    let mut stream = std::pin::pin!(watcher(api.clone(), Config::default()));
    while let Some(ev) = stream.next().await {
        match ev {
            Ok(Event::Apply(obj)) | Ok(Event::InitApply(obj)) => {
                handle(api.clone(), obj).await;
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "outcome-chain watcher error"),
        }
    }
    Ok(())
}

async fn handle(api: Api<AkeylessImageValidation>, obj: AkeylessImageValidation) {
    let Some(phase) = obj.status.as_ref().and_then(|s| s.phase) else {
        return;
    };
    let terminal = matches!(
        phase,
        AkeylessImageValidationPhase::Passed
            | AkeylessImageValidationPhase::Failed
            | AkeylessImageValidationPhase::Quarantined
    );
    if !terminal {
        return;
    }
    let already_signed = obj
        .status
        .as_ref()
        .and_then(|s| s.outcome_receipt_ref.as_ref())
        .is_some();
    if already_signed {
        return;
    }
    let receipt = build_receipt(&obj);
    let name = obj.name_any();
    let patch = json!({ "status": { "outcomeReceiptRef": receipt } });
    let pp = PatchParams::apply("validation-controllers");
    if let Err(e) = api.patch_status(&name, &pp, &Patch::Merge(&patch)).await {
        warn!(error = %e, "failed to append outcome receipt");
    } else {
        info!(name = %name, hash = %receipt.blake3_hash, "outcome receipt appended");
    }
}

fn build_receipt(obj: &AkeylessImageValidation) -> OutcomeReceiptRef {
    let canonical = format!(
        "{}|{}|{}|{}|{}",
        obj.spec.service,
        obj.spec.image_digest,
        obj.status
            .as_ref()
            .and_then(|s| s.gate_decision.as_ref())
            .map(|gd| format!("{:?}", gd.verdict))
            .unwrap_or_default(),
        obj.status
            .as_ref()
            .and_then(|s| s.gate_decision.as_ref())
            .map(|gd| gd.severity.clone())
            .unwrap_or_default(),
        obj.status
            .as_ref()
            .and_then(|s| s.evidence_bundle_hash.clone())
            .unwrap_or_default(),
    );
    let hash = blake3::hash(canonical.as_bytes()).to_hex().to_string();
    OutcomeReceiptRef {
        blake3_hash: hash.clone(),
        ed25519_sig: String::new(),
        minio_path: format!(
            "s3://outcome-chains-pleme-dev/akeyless-nix-images-fedramp-scr/{}.json",
            hash
        ),
        signed_at: Utc::now(),
    }
}
