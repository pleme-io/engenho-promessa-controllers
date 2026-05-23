//! `validation_run` — one row per `AkeylessImageValidation` CR.
//!
//! Mirrors `validation_crds::image_validation::AkeylessImageValidation`:
//! - PK: the CR's `metadata.uid` (immutable across reconciles)
//! - Phase: `AkeylessImageValidationPhase` serialized as JSON string
//!   ("Pending" / "Scanning" / "Passed" / etc.)
//! - Digest + image repo: from the CR spec
//! - Bundle hash + outcome receipt ref: populated as phases advance
//!
//! ## Why store phase as String
//!
//! Per [`crate::entities`] module docs: SeaORM/SQLite handles strings
//! across all backends without per-DB ENUM schema noise. The typed
//! [`validation_crds::AkeylessImageValidationPhase`] re-parses cleanly
//! via the helpers in [`crate::ops::phase`].

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "validation_runs")]
pub struct Model {
    /// CR `metadata.uid` (RFC 4122). Stable across reconciles.
    #[sea_orm(primary_key, auto_increment = false)]
    pub uid: String,

    /// CR `metadata.namespace`.
    #[sea_orm(indexed)]
    pub namespace: String,

    /// CR `metadata.name` (digest-suffixed per the validator's naming
    /// convention).
    #[sea_orm(indexed)]
    pub name: String,

    /// `spec.imageDigest` — `sha256:...` form.
    #[sea_orm(indexed)]
    pub image_digest: String,

    /// `spec.imageRepo` — e.g. `akeyless-auth`.
    pub image_repo: String,

    /// Serialized [`validation_crds::AkeylessImageValidationPhase`].
    /// Use [`crate::ops::phase::parse`] for the typed value.
    #[sea_orm(indexed)]
    pub phase: String,

    /// BLAKE3 of `canonical(union(findings))` — set at Aggregating
    /// phase by the image-validation reconciler.
    pub evidence_bundle_hash: Option<String>,

    /// JSON-encoded [`validation_crds::OutcomeReceiptRef`] — set
    /// when the OutcomeChain appender writes the receipt.
    pub outcome_receipt_ref: Option<serde_json::Value>,

    /// `.status.observed_generation` — for change-tracking parity
    /// with the CR.
    pub observed_generation: i64,

    /// First observation by the store (UTC).
    pub started_at: DateTime<Utc>,

    /// Last observation by the store (UTC) — updated on every
    /// upsert.
    pub last_seen_at: DateTime<Utc>,

    /// Set when phase reaches a terminal state (Passed / Failed /
    /// Quarantined).
    pub terminal_at: Option<DateTime<Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
