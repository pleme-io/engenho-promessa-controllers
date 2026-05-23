//! Read-side helpers. Every function returns the typed `Model`
//! struct from `crate::entities::*` — callers serialize / project
//! into API-face shapes (REST, gRPC, GraphQL, MCP) themselves.

use sea_orm::entity::prelude::*;
use sea_orm::{QueryFilter, QueryOrder};

use crate::entities::{
    decision_audit, digest_provenance, reconciler_outcome, scan_finding, validation_run,
};

/// Find a validation run by its CR UID.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn validation_run_by_uid(
    db: &DatabaseConnection,
    uid: &str,
) -> Result<Option<validation_run::Model>, DbErr> {
    validation_run::Entity::find_by_id(uid).one(db).await
}

/// All validation runs in a given phase (serialized form). Use the
/// strings from [`crate::ops::phase::serialize_phase`].
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn validation_runs_by_phase(
    db: &DatabaseConnection,
    phase_serialized: &str,
) -> Result<Vec<validation_run::Model>, DbErr> {
    validation_run::Entity::find()
        .filter(validation_run::Column::Phase.eq(phase_serialized))
        .order_by_desc(validation_run::Column::LastSeenAt)
        .all(db)
        .await
}

/// All findings for a given validation run. Order: most-recent first.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn findings_by_run(
    db: &DatabaseConnection,
    validation_run_uid: &str,
) -> Result<Vec<scan_finding::Model>, DbErr> {
    scan_finding::Entity::find()
        .filter(scan_finding::Column::ValidationRunUid.eq(validation_run_uid))
        .order_by_desc(scan_finding::Column::RecordedAt)
        .all(db)
        .await
}

/// All findings for a given validation run with a specific severity
/// (e.g. `"Critical"`).
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn findings_by_run_and_severity(
    db: &DatabaseConnection,
    validation_run_uid: &str,
    severity_serialized: &str,
) -> Result<Vec<scan_finding::Model>, DbErr> {
    scan_finding::Entity::find()
        .filter(scan_finding::Column::ValidationRunUid.eq(validation_run_uid))
        .filter(scan_finding::Column::Severity.eq(severity_serialized))
        .order_by_desc(scan_finding::Column::FirstSeenAt)
        .all(db)
        .await
}

/// All decision audit rows for a given validation run, most recent
/// first. A run with multiple re-scans has multiple rows.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn decisions_by_run(
    db: &DatabaseConnection,
    validation_run_uid: &str,
) -> Result<Vec<decision_audit::Model>, DbErr> {
    decision_audit::Entity::find()
        .filter(decision_audit::Column::ValidationRunUid.eq(validation_run_uid))
        .order_by_desc(decision_audit::Column::DecidedAt)
        .all(db)
        .await
}

/// All reconciler outcomes for a given validation run, most recent
/// dispatch first.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn outcomes_by_run(
    db: &DatabaseConnection,
    validation_run_uid: &str,
) -> Result<Vec<reconciler_outcome::Model>, DbErr> {
    reconciler_outcome::Entity::find()
        .filter(reconciler_outcome::Column::ValidationRunUid.eq(validation_run_uid))
        .order_by_desc(reconciler_outcome::Column::DispatchedAt)
        .all(db)
        .await
}

/// Provenance for a digest, if observed.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn provenance_by_digest(
    db: &DatabaseConnection,
    image_digest: &str,
) -> Result<Option<digest_provenance::Model>, DbErr> {
    digest_provenance::Entity::find_by_id(image_digest).one(db).await
}

/// All validation runs that referenced a given digest. Useful for
/// answering "what scans has this digest been through?"
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn validation_runs_by_digest(
    db: &DatabaseConnection,
    image_digest: &str,
) -> Result<Vec<validation_run::Model>, DbErr> {
    validation_run::Entity::find()
        .filter(validation_run::Column::ImageDigest.eq(image_digest))
        .order_by_desc(validation_run::Column::LastSeenAt)
        .all(db)
        .await
}

/// Compliance summary — how many runs are in each phase. Used by
/// `/v1/compliance-summary` (REST face), the GraphQL summary query,
/// the gRPC `ComplianceSummary` RPC.
///
/// # Errors
///
/// Returns the underlying SeaORM `DbErr` on query failure.
pub async fn compliance_summary(
    db: &DatabaseConnection,
) -> Result<std::collections::BTreeMap<String, u64>, DbErr> {
    let runs = validation_run::Entity::find().all(db).await?;
    let mut by_phase: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for r in runs {
        *by_phase.entry(r.phase).or_insert(0) += 1;
    }
    Ok(by_phase)
}
