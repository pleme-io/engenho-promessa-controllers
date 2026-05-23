//! Write-side helpers. Every function here takes a `&DatabaseConnection`
//! so callers can mix sync and async without spawning extra tasks.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue, IntoActiveModel};
use validation_crds::{AkeylessImageValidationPhase, GateDecision, ScanFinding};

use crate::entities::{
    decision_audit, digest_provenance, reconciler_outcome, scan_finding, validation_run,
};
use crate::ops::{ids, phase};

/// Typed input for [`upsert_validation_run`]. Carries only the
/// fields the store needs — the full CR shape stays in
/// `validation_crds` and isn't a dep of this helper's signature.
#[derive(Debug, Clone)]
pub struct ValidationRunWrite {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub image_digest: String,
    pub image_repo: String,
    pub phase: AkeylessImageValidationPhase,
    pub evidence_bundle_hash: Option<String>,
    pub outcome_receipt_ref: Option<serde_json::Value>,
    pub observed_generation: i64,
}

/// Upsert a validation run. If the row exists, updates phase +
/// evidence + outcome + observed_generation + last_seen_at;
/// preserves started_at. If the phase is terminal, sets
/// terminal_at to now (once — subsequent observations of the same
/// terminal phase don't reset it).
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on insert/update failure.
pub async fn upsert_validation_run(
    db: &DatabaseConnection,
    write: ValidationRunWrite,
) -> Result<validation_run::Model, DbErr> {
    let now = Utc::now();
    let phase_str = phase::serialize_phase(write.phase);
    let phase_is_terminal = phase::is_terminal_phase(&phase_str);

    if let Some(existing) = validation_run::Entity::find_by_id(&write.uid).one(db).await? {
        let terminal_at = match existing.terminal_at {
            Some(t) => Some(t),
            None if phase_is_terminal => Some(now),
            None => None,
        };
        let mut active: validation_run::ActiveModel = existing.into_active_model();
        active.phase = ActiveValue::Set(phase_str);
        active.evidence_bundle_hash = ActiveValue::Set(write.evidence_bundle_hash);
        active.outcome_receipt_ref = ActiveValue::Set(write.outcome_receipt_ref);
        active.observed_generation = ActiveValue::Set(write.observed_generation);
        active.last_seen_at = ActiveValue::Set(now);
        active.terminal_at = ActiveValue::Set(terminal_at);
        active.update(db).await
    } else {
        let model = validation_run::ActiveModel {
            uid: ActiveValue::Set(write.uid),
            namespace: ActiveValue::Set(write.namespace),
            name: ActiveValue::Set(write.name),
            image_digest: ActiveValue::Set(write.image_digest),
            image_repo: ActiveValue::Set(write.image_repo),
            phase: ActiveValue::Set(phase_str),
            evidence_bundle_hash: ActiveValue::Set(write.evidence_bundle_hash),
            outcome_receipt_ref: ActiveValue::Set(write.outcome_receipt_ref),
            observed_generation: ActiveValue::Set(write.observed_generation),
            started_at: ActiveValue::Set(now),
            last_seen_at: ActiveValue::Set(now),
            terminal_at: ActiveValue::Set(if phase_is_terminal { Some(now) } else { None }),
        };
        model.insert(db).await
    }
}

/// Append typed scan findings from one ScanJob into the store. Each
/// finding gets a fresh ULID; the caller can subsequently query by
/// `(validation_run_uid, scan_job_name, severity)`.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on insert failure.
pub async fn append_scan_findings(
    db: &DatabaseConnection,
    validation_run_uid: &str,
    scan_job_name: &str,
    findings: &[ScanFinding],
) -> Result<u64, DbErr> {
    if findings.is_empty() {
        return Ok(0);
    }
    let now = Utc::now();
    let rows: Vec<scan_finding::ActiveModel> = findings
        .iter()
        .map(|f| scan_finding::ActiveModel {
            id: ActiveValue::Set(ids::ulid_string()),
            validation_run_uid: ActiveValue::Set(validation_run_uid.into()),
            scan_job_name: ActiveValue::Set(scan_job_name.into()),
            scanner: ActiveValue::Set(format!("{:?}", f.scanner)),
            severity: ActiveValue::Set(format!("{:?}", f.severity)),
            cve_id: ActiveValue::Set(f.cve_id.clone()),
            cvss_v3: ActiveValue::Set(f.cvss_v3),
            // ScanFinding doesn't carry `package` on the CRD today.
            // The scanner-specific payload lives in `message` for now.
            package: ActiveValue::Set(None),
            fixed_in: ActiveValue::Set(f.fixed_in.clone()),
            exception_id: ActiveValue::Set(f.exception_id.clone()),
            message: ActiveValue::Set(f.message.clone()),
            first_seen_at: ActiveValue::Set(f.first_seen),
            recorded_at: ActiveValue::Set(now),
        })
        .collect();
    let count = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    scan_finding::Entity::insert_many(rows).exec(db).await?;
    Ok(count)
}

/// Typed input for [`append_reconciler_outcome`]. Captures the
/// `validation-controllers::action_dispatcher` dispatch context.
#[derive(Debug, Clone)]
pub struct ReconcilerOutcomeWrite {
    pub validation_run_uid: String,
    /// `TypedAction` variant label.
    pub action_kind: String,
    /// `ReconcilerKind` for `ReconcilerApply`, else None.
    pub reconciler_kind: Option<String>,
    pub action_payload: serde_json::Value,
    /// `"applied"` / `"already-converged"` / `"flag-gated"` / `"failed"`.
    pub outcome: String,
    pub outcome_flag: Option<String>,
    pub outcome_payload: Option<serde_json::Value>,
    pub gate_decision_decided_at: DateTime<Utc>,
}

/// Append one reconciler outcome row. Composite `Compose` actions
/// call this once per step (caller's responsibility — see
/// `validation-controllers::action_dispatcher`).
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on insert failure.
pub async fn append_reconciler_outcome(
    db: &DatabaseConnection,
    write: ReconcilerOutcomeWrite,
) -> Result<reconciler_outcome::Model, DbErr> {
    let now = Utc::now();
    let model = reconciler_outcome::ActiveModel {
        id: ActiveValue::Set(ids::ulid_string()),
        validation_run_uid: ActiveValue::Set(write.validation_run_uid),
        action_kind: ActiveValue::Set(write.action_kind),
        reconciler_kind: ActiveValue::Set(write.reconciler_kind),
        action_payload: ActiveValue::Set(write.action_payload),
        outcome: ActiveValue::Set(write.outcome),
        outcome_flag: ActiveValue::Set(write.outcome_flag),
        outcome_payload: ActiveValue::Set(write.outcome_payload),
        gate_decision_decided_at: ActiveValue::Set(write.gate_decision_decided_at),
        dispatched_at: ActiveValue::Set(now),
    };
    model.insert(db).await
}

/// Record a SecurityController gate decision. The
/// `(validation_run_uid, decided_at)` pair is logically unique per
/// re-scan, but the schema doesn't enforce it — re-scoring the same
/// decision deliberately appends a new row so the audit trail is
/// append-only.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on insert failure.
pub async fn record_decision_audit(
    db: &DatabaseConnection,
    validation_run_uid: &str,
    gate: &GateDecision,
    drift_snapshot: serde_json::Value,
) -> Result<decision_audit::Model, DbErr> {
    let now = Utc::now();
    let model = decision_audit::ActiveModel {
        id: ActiveValue::Set(ids::ulid_string()),
        validation_run_uid: ActiveValue::Set(validation_run_uid.into()),
        severity: ActiveValue::Set(gate.severity.clone()),
        verdict: ActiveValue::Set(format!("{:?}", gate.verdict)),
        action_payload: ActiveValue::Set(gate.action.clone()),
        reason: ActiveValue::Set(gate.reason.clone()),
        drift_snapshot: ActiveValue::Set(drift_snapshot),
        decided_at: ActiveValue::Set(gate.decided_at),
        recorded_at: ActiveValue::Set(now),
    };
    model.insert(db).await
}

/// Upsert a digest's provenance row. If the row exists, refreshes
/// the cartorio_status + last_observed_at and merges any newly-known
/// attestation fields; preserves first_observed_at.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on insert/update failure.
pub async fn observe_digest_provenance(
    db: &DatabaseConnection,
    image_digest: &str,
    image_repo: &str,
    attestation_chain: serde_json::Value,
    cartorio_status: Option<&str>,
    cartorio_artifact_id: Option<&str>,
) -> Result<digest_provenance::Model, DbErr> {
    let now = Utc::now();
    // Pull git_* fields out of the chain if present (best-effort —
    // store them flat for fast queries; full chain remains in
    // attestation_chain).
    let git_commit = attestation_chain
        .get("source")
        .and_then(|s| s.get("git_commit"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let git_tree_hash = attestation_chain
        .get("source")
        .and_then(|s| s.get("tree_hash"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let flake_lock_hash = attestation_chain
        .get("source")
        .and_then(|s| s.get("flake_lock_hash"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    if let Some(existing) = digest_provenance::Entity::find_by_id(image_digest).one(db).await? {
        let mut active: digest_provenance::ActiveModel = existing.into_active_model();
        active.image_repo = ActiveValue::Set(image_repo.into());
        if git_commit.is_some() {
            active.git_commit = ActiveValue::Set(git_commit);
        }
        if git_tree_hash.is_some() {
            active.git_tree_hash = ActiveValue::Set(git_tree_hash);
        }
        if flake_lock_hash.is_some() {
            active.flake_lock_hash = ActiveValue::Set(flake_lock_hash);
        }
        active.attestation_chain = ActiveValue::Set(attestation_chain);
        active.cartorio_status = ActiveValue::Set(cartorio_status.map(str::to_owned));
        active.cartorio_artifact_id = ActiveValue::Set(cartorio_artifact_id.map(str::to_owned));
        active.last_observed_at = ActiveValue::Set(now);
        active.update(db).await
    } else {
        let model = digest_provenance::ActiveModel {
            image_digest: ActiveValue::Set(image_digest.into()),
            image_repo: ActiveValue::Set(image_repo.into()),
            git_commit: ActiveValue::Set(git_commit),
            git_tree_hash: ActiveValue::Set(git_tree_hash),
            flake_lock_hash: ActiveValue::Set(flake_lock_hash),
            attestation_chain: ActiveValue::Set(attestation_chain),
            cartorio_status: ActiveValue::Set(cartorio_status.map(str::to_owned)),
            cartorio_artifact_id: ActiveValue::Set(cartorio_artifact_id.map(str::to_owned)),
            first_observed_at: ActiveValue::Set(now),
            last_observed_at: ActiveValue::Set(now),
        };
        model.insert(db).await
    }
}
