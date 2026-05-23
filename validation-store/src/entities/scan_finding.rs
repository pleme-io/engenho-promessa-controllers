//! `scan_finding` — one row per typed
//! [`validation_crds::ScanFinding`] emitted by any scanner across
//! any ScanJob under a validation run. Flattened so query patterns
//! like "all Critical CVEs for digest X across all scanners" are a
//! single SQL filter.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "scan_findings")]
pub struct Model {
    /// ULID — generated on insert per [`crate::ops::ids`].
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    /// FK to `validation_runs.uid`. Indexed for "findings by run"
    /// queries.
    #[sea_orm(indexed)]
    pub validation_run_uid: String,

    /// Source ScanJob CR name — lets you trace a finding back to the
    /// scanner Job that emitted it.
    #[sea_orm(indexed)]
    pub scan_job_name: String,

    /// Serialized [`validation_crds::ScannerKind`] (e.g. "Trivy",
    /// "Semgrep", "Zap"). Stored as string for cross-backend
    /// compatibility.
    #[sea_orm(indexed)]
    pub scanner: String,

    /// Serialized [`validation_crds::ScanFindingSeverity`].
    #[sea_orm(indexed)]
    pub severity: String,

    /// CVE identifier when applicable (CVE-yyyy-nnnnn). NULL for
    /// SAST/DAST/hardening findings.
    #[sea_orm(indexed)]
    pub cve_id: Option<String>,

    /// CVSS v3 base score when scanner provides it (0.0–10.0).
    pub cvss_v3: Option<f32>,

    /// Affected package + version when scanner provides it.
    pub package: Option<String>,

    /// Version range that fixes the finding ("1.2.3 < x"). NULL when
    /// no fix is available.
    pub fixed_in: Option<String>,

    /// Reference to a `:exception` row in the promessa pack —
    /// populated when the security-controller suppressed this finding.
    pub exception_id: Option<String>,

    /// Human-readable summary.
    pub message: Option<String>,

    /// `.first_seen` from the typed CRD ScanFinding — the moment the
    /// scanner first reported this issue.
    pub first_seen_at: DateTime<Utc>,

    /// When this row was inserted into the store.
    pub recorded_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
