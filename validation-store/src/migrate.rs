//! Single-call migration — creates every entity's table idempotently.
//!
//! For dev (SQLite) this is the canonical setup path. For prod
//! (Postgres) you'd typically want versioned migrations via
//! `sea-orm-migration`; that lands in D2.1 as an upgrade. For M1
//! scope, `ensure_all_tables` keeps the boot path single-line.

use sea_orm::DatabaseConnection;

use crate::cli::DbCli;
use crate::entities::{decision_audit, digest_provenance, reconciler_outcome, scan_finding, validation_run};
use crate::store::StoreError;

/// Create every validation-store table if absent. Idempotent — safe
/// to call on every binary startup.
///
/// # Errors
///
/// Returns [`StoreError::Connect`] if any `CREATE TABLE` fails.
pub async fn ensure_all_tables(db: &DatabaseConnection) -> Result<(), StoreError> {
    DbCli::create_table::<validation_run::Entity>(db).await?;
    DbCli::create_table::<scan_finding::Entity>(db).await?;
    DbCli::create_table::<reconciler_outcome::Entity>(db).await?;
    DbCli::create_table::<decision_audit::Entity>(db).await?;
    DbCli::create_table::<digest_provenance::Entity>(db).await?;
    Ok(())
}

/// Drop every validation-store table. Dev/test only.
pub async fn drop_all_tables(db: &DatabaseConnection) -> Result<(), StoreError> {
    // Order: children before parents (FKs aren't enforced today but
    // keeping intuitive ordering for the day they are).
    DbCli::reset_table::<scan_finding::Entity>(db).await?;
    DbCli::reset_table::<reconciler_outcome::Entity>(db).await?;
    DbCli::reset_table::<decision_audit::Entity>(db).await?;
    DbCli::reset_table::<digest_provenance::Entity>(db).await?;
    DbCli::reset_table::<validation_run::Entity>(db).await?;
    Ok(())
}
