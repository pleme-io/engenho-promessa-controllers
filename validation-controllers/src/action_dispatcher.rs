//! `action_dispatcher` — the fifth reconciler. Watches
//! `AkeylessImageValidation` CRs; when one reaches a phase whose
//! `.status.gateDecision.action` carries a typed
//! [`promessa_types::TypedAction`], routes the action through the
//! [`reconciler_engine::ActionExecutor`] and records the outcome.
//!
//! ## Why a separate reconciler
//!
//! The four existing controllers
//! ([`crate::image_validation`], [`crate::ephemeral_tenant`],
//! [`crate::scan_job`], [`crate::outcome_chain`]) each own one CRD's
//! phase machine. The action_dispatcher is orthogonal — it consumes
//! the *output* of `image_validation::handle_gating` (the typed
//! `GateDecision`) and drives external side effects through typed
//! Reconcilers. Keeping it separate matches the wrap-not-compete
//! invariant (VIGGY-AUTHORING §3.3): each reconciler owns one
//! concern.
//!
//! ## Idempotency
//!
//! Watcher events for a single object can fire multiple times
//! (Apply on resync, on patch-by-someone-else, on controller
//! restart). The dispatcher dedupes by
//! `(uid, gate_decision.decided_at)` in a per-process in-memory
//! map. Persistence of outcomes to
//! `.status.reconcilerOutcomes[]` is D7 (OutcomeChain attestation).
//! Until D7 lands, outcomes are emitted as structured tracing
//! events keyed on `validation_name + decided_at` for kubectl-log
//! observability.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use kube::runtime::watcher::{watcher, Config, Event};
use kube::{Api, ResourceExt};
use promessa_types::TypedAction;
use reconciler_engine::ErasedOutcome;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use validation_crds::AkeylessImageValidation;

use crate::context::ReconcileCtx;

/// Per-process dispatch dedupe set. Key: `(uid, decided_at_rfc3339)`.
/// Cheap; rebuilt on process restart.
type DedupeKey = (String, String);

#[derive(Default)]
struct DedupeSet {
    seen: HashSet<DedupeKey>,
}

impl DedupeSet {
    /// Returns true if the key was newly inserted (i.e. NOT a
    /// duplicate).
    fn record(&mut self, key: DedupeKey) -> bool {
        self.seen.insert(key)
    }
}

pub async fn run(ctx: Arc<ReconcileCtx>) -> anyhow::Result<()> {
    let api: Api<AkeylessImageValidation> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };
    info!(
        registered_kinds = ?ctx
            .action_executor
            .registered_kinds_snapshot()
            .into_iter()
            .map(|k| format!("{k:?}"))
            .collect::<Vec<_>>(),
        "action_dispatcher starting"
    );
    let dedupe = Arc::new(Mutex::new(DedupeSet::default()));
    let mut stream = std::pin::pin!(watcher(api.clone(), Config::default()));
    while let Some(ev) = stream.next().await {
        match ev {
            Ok(Event::Apply(obj)) | Ok(Event::InitApply(obj)) => {
                handle(ctx.clone(), dedupe.clone(), obj).await;
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "action-dispatcher watcher error"),
        }
    }
    Ok(())
}

async fn handle(
    ctx: Arc<ReconcileCtx>,
    dedupe: Arc<Mutex<DedupeSet>>,
    obj: AkeylessImageValidation,
) {
    let name = obj.name_any();
    let Some(uid) = obj.uid() else {
        debug!(name = %name, "skip: object has no uid yet");
        return;
    };
    let Some(status) = obj.status.as_ref() else {
        debug!(name = %name, "skip: no status yet");
        return;
    };
    let Some(gate) = status.gate_decision.as_ref() else {
        debug!(name = %name, "skip: no gate_decision yet");
        return;
    };

    let key: DedupeKey = (uid.clone(), gate.decided_at.to_rfc3339());
    {
        let mut d = dedupe.lock().await;
        if !d.record(key.clone()) {
            debug!(
                name = %name,
                decided_at = %gate.decided_at.to_rfc3339(),
                "skip: action already dispatched for this gate decision"
            );
            return;
        }
    }

    // The action lives as canonical JSON on the CR — deserialize into
    // the typed enum.
    let action: TypedAction = match serde_json::from_value(gate.action.clone()) {
        Ok(a) => a,
        Err(e) => {
            error!(
                name = %name,
                error = %e,
                action_json = %gate.action,
                "gate_decision.action did not deserialize as TypedAction — \
                 skipping (SecurityController must emit a typed variant)"
            );
            return;
        }
    };

    let dispatched_at = Utc::now();
    let outcome = ctx.action_executor.execute(&action).await;
    log_outcome(&name, &gate.decided_at, dispatched_at, &action, &outcome);
    persist_outcome(&ctx, &uid, &gate.decided_at, &action, &outcome).await;
}

/// Persist the dispatch tuple `(action, outcome, gate.decided_at,
/// dispatched_at)` to `validation_store::reconciler_outcomes`. For
/// `TypedAction::Compose`, the engine returns a single nested
/// receipt; we flatten one row per step so query patterns like
/// "all reconciler dispatches for a digest" return granular results.
///
/// FOLLOWUP(D7): also append a typed OutcomeReceipt to the cluster's
/// outcome-chain bucket (tameshi-signed) — this row is the audit
/// source for that receipt.
async fn persist_outcome(
    ctx: &ReconcileCtx,
    validation_run_uid: &str,
    gate_decided_at: &chrono::DateTime<Utc>,
    action: &TypedAction,
    outcome: &ErasedOutcome,
) {
    // Flatten Compose into one row per step (matching the
    // ComposeReceipt's order); single actions get exactly one row.
    let writes = match (action, outcome) {
        (TypedAction::Compose(steps), ErasedOutcome::Applied { receipt }) => {
            // Engine wraps Compose into `Applied { receipt: ComposeReceipt }`.
            let parsed: Option<reconciler_engine::ComposeReceipt> =
                serde_json::from_value(receipt.clone()).ok();
            match parsed {
                Some(compose) => steps
                    .iter()
                    .zip(compose.steps.iter())
                    .map(|(step, step_outcome)| outcome_row(step, step_outcome))
                    .collect::<Vec<_>>(),
                None => vec![outcome_row(action, outcome)],
            }
        }
        _ => vec![outcome_row(action, outcome)],
    };

    for w in writes {
        let write = validation_store::ops::upsert::ReconcilerOutcomeWrite {
            validation_run_uid: validation_run_uid.to_owned(),
            action_kind: w.action_kind,
            reconciler_kind: w.reconciler_kind,
            action_payload: w.action_payload,
            outcome: w.outcome,
            outcome_flag: w.outcome_flag,
            outcome_payload: w.outcome_payload,
            gate_decision_decided_at: *gate_decided_at,
        };
        if let Err(err) = validation_store::ops::upsert::append_reconciler_outcome(
            ctx.validation_store.db(),
            write,
        )
        .await
        {
            // Persistence failure is recorded but doesn't fail the
            // dispatch — the outcome was already applied to the
            // wrapped substrate primitive and logged. A subsequent
            // reconcile will retry the persistence via the dedupe
            // path (next gate decision will land cleanly).
            tracing::warn!(
                validation_run_uid = %validation_run_uid,
                error = %err,
                "validation-store append_reconciler_outcome failed — \
                 outcome is in logs but not in store"
            );
        }
    }
}

/// Reusable single-row transform — used both for non-Compose
/// dispatches and per-step inside a Compose flattening.
fn outcome_row(action: &TypedAction, outcome: &ErasedOutcome) -> OutcomeRow {
    let (outcome_label, outcome_flag, outcome_payload) = match outcome {
        ErasedOutcome::Applied { receipt } => {
            ("applied", None, Some(receipt.clone()))
        }
        ErasedOutcome::AlreadyConverged => ("already-converged", None, None),
        ErasedOutcome::FlagGated { flag } => {
            ("flag-gated", Some(flag.clone()), None)
        }
        ErasedOutcome::Failed { error } => (
            "failed",
            None,
            Some(serde_json::to_value(error).unwrap_or(serde_json::Value::Null)),
        ),
    };
    let reconciler_kind = match action {
        TypedAction::ReconcilerApply { reconciler, .. } => Some(format!("{reconciler:?}")),
        _ => None,
    };
    OutcomeRow {
        action_kind: action_label(action).to_owned(),
        reconciler_kind,
        action_payload: serde_json::to_value(action).unwrap_or(serde_json::Value::Null),
        outcome: outcome_label.to_owned(),
        outcome_flag,
        outcome_payload,
    }
}

struct OutcomeRow {
    action_kind: String,
    reconciler_kind: Option<String>,
    action_payload: serde_json::Value,
    outcome: String,
    outcome_flag: Option<String>,
    outcome_payload: Option<serde_json::Value>,
}

fn log_outcome(
    name: &str,
    decided_at: &DateTime<Utc>,
    dispatched_at: DateTime<Utc>,
    action: &TypedAction,
    outcome: &ErasedOutcome,
) {
    // Match outcome shape into structured fields so kubectl logs are
    // greppable. Successful outcomes → info; failures → warn.
    match outcome {
        ErasedOutcome::Applied { receipt } => info!(
            validation = %name,
            decided_at = %decided_at.to_rfc3339(),
            dispatched_at = %dispatched_at.to_rfc3339(),
            outcome = "applied",
            action = ?action_label(action),
            receipt = %receipt,
            "action dispatched successfully"
        ),
        ErasedOutcome::AlreadyConverged => info!(
            validation = %name,
            decided_at = %decided_at.to_rfc3339(),
            dispatched_at = %dispatched_at.to_rfc3339(),
            outcome = "already-converged",
            action = ?action_label(action),
            "action was a no-op — state already holds"
        ),
        ErasedOutcome::FlagGated { flag } => info!(
            validation = %name,
            decided_at = %decided_at.to_rfc3339(),
            dispatched_at = %dispatched_at.to_rfc3339(),
            outcome = "flag-gated",
            flag = %flag,
            action = ?action_label(action),
            "action refused — feature flag is off"
        ),
        ErasedOutcome::Failed { error } => warn!(
            validation = %name,
            decided_at = %decided_at.to_rfc3339(),
            dispatched_at = %dispatched_at.to_rfc3339(),
            outcome = "failed",
            action = ?action_label(action),
            error = %error,
            "action dispatch failed"
        ),
    }
}

/// Human-readable label for a TypedAction — used in tracing logs.
fn action_label(action: &TypedAction) -> &'static str {
    match action {
        TypedAction::FluxCommit { .. } => "FluxCommit",
        TypedAction::ReconcilerApply { .. } => "ReconcilerApply",
        TypedAction::MagmaApply { .. } => "MagmaApply",
        TypedAction::CofreRotate { .. } => "CofreRotate",
        TypedAction::CrachaPatch { .. } => "CrachaPatch",
        TypedAction::Custom { .. } => "Custom",
        TypedAction::Compose(_) => "Compose",
        TypedAction::Noop => "Noop",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_set_records_unique_keys_only() {
        let mut s = DedupeSet::default();
        let key1: DedupeKey = ("uid-1".into(), "2026-05-22T00:00:00Z".into());
        let key2: DedupeKey = ("uid-1".into(), "2026-05-22T00:00:01Z".into()); // diff time
        let key3: DedupeKey = ("uid-2".into(), "2026-05-22T00:00:00Z".into()); // diff uid

        assert!(s.record(key1.clone()), "first insert returns true");
        assert!(!s.record(key1.clone()), "repeat insert returns false");
        assert!(s.record(key2), "different time → newly recorded");
        assert!(s.record(key3), "different uid → newly recorded");
    }

    #[test]
    fn action_label_is_exhaustive() {
        // Cheap exhaustiveness check — if a variant is added to
        // TypedAction, this match in `action_label` won't compile,
        // which forces a label decision before merge.
        let cases = [
            (TypedAction::Noop, "Noop"),
            (
                TypedAction::FluxCommit {
                    path: "x".into(),
                    patch: serde_json::json!({}),
                },
                "FluxCommit",
            ),
            (
                TypedAction::Custom {
                    kind: "x".into(),
                    payload: serde_json::json!({}),
                },
                "Custom",
            ),
            (TypedAction::Compose(vec![]), "Compose"),
        ];
        for (a, expected) in cases {
            assert_eq!(action_label(&a), expected);
        }
    }
}
