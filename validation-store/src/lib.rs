//! `validation-store` — SeaORM-backed typed persistence for the
//! AKEYLESS-VALIDATION-PLATFORM domain.
//!
//! Single source-of-truth for everything downstream of the
//! `validation-controllers` reconcilers. Every API face
//! (REST, gRPC, GraphQL, MCP, future SDK) projects from this store.
//!
//! ## Reading order
//!
//! 1. [`entities`] — the five typed entities mirroring
//!    `validation-crds` (validation_run, scan_finding,
//!    reconciler_outcome, decision_audit, digest_provenance).
//! 2. [`store`] — [`ValidationStore`] dual sync/async wrapper.
//! 3. [`migrate`] — [`migrate::ensure_all_tables`] idempotent boot.
//! 4. [`ops`] — named write/query helpers that read like the
//!    validation domain language.
//!
//! ## Quickstart
//!
//! ```no_run
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! use validation_store::{
//!     migrate, ops, ValidationStore,
//! };
//!
//! let store = ValidationStore::connect_async("sqlite::memory:").await?;
//! migrate::ensure_all_tables(store.db()).await?;
//!
//! let summary = ops::query::compliance_summary(store.db()).await?;
//! println!("phase counts: {summary:?}");
//! # Ok(()) }
//! ```
//!
//! ## Schema discipline
//!
//! Entities mirror `validation-crds` shapes 1:1 — when the CRDs add
//! a field, this crate adds the matching column. Enums are stored
//! as strings (cross-backend portability) with typed parse helpers
//! in [`ops::phase`]. The typed CRD enums remain the canonical
//! shape; the store is a queryable projection of them.

pub mod cli;
pub mod entities;
pub mod migrate;
pub mod ops;
pub mod store;

pub use cli::DbCli;
pub use migrate::{drop_all_tables, ensure_all_tables};
pub use store::{StoreError, ValidationStore};

// Re-export sea_orm so consumers get the DbErr / DatabaseConnection
// types without a parallel dependency declaration.
pub use sea_orm;
