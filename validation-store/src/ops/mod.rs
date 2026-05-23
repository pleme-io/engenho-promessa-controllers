//! Typed operations layer. Wraps SeaORM ActiveModel constructions
//! into named, intent-revealing functions so call sites read like
//! the validation domain language:
//!
//! ```ignore
//! ops::upsert_validation_run(&db, &cr).await?;
//! ops::append_scan_findings(&db, &validation_uid, &scan_job_name, findings).await?;
//! ops::record_decision_audit(&db, &validation_uid, &gate_decision).await?;
//! let provenance = ops::query::provenance_by_digest(&db, "sha256:...").await?;
//! ```

pub mod ids;
pub mod phase;
pub mod query;
pub mod upsert;

pub use ids::ulid_string;
pub use phase::{parse_phase, serialize_phase};
pub use upsert::{
    append_reconciler_outcome, append_scan_findings, observe_digest_provenance,
    record_decision_audit, upsert_validation_run, ReconcilerOutcomeWrite,
    ValidationRunWrite,
};
