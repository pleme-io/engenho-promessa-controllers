//! `decision_audit` — one row per
//! [`validation_crds::GateDecision`] emitted by the
//! SecurityController. 1:1 with `validation_run` rows in the typical
//! lifecycle (Gating phase writes exactly one decision); the
//! `(validation_run_uid, decided_at)` pair is unique so re-decisions
//! after a re-scan get appended cleanly.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "decision_audits")]
pub struct Model {
    /// ULID — generated on insert.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    /// FK to `validation_runs.uid`.
    #[sea_orm(indexed)]
    pub validation_run_uid: String,

    /// `gate_decision.severity` — "Cosmetic" / "Functional" /
    /// "Critical". Mirrors [`promessa_types::Severity`].
    #[sea_orm(indexed)]
    pub severity: String,

    /// Serialized [`validation_crds::GateVerdict`] — "Passed" /
    /// "Failed" / "Quarantined".
    #[sea_orm(indexed)]
    pub verdict: String,

    /// Canonical JSON of the dispatched
    /// [`promessa_types::TypedAction`] (may be `Compose-of-N`).
    pub action_payload: serde_json::Value,

    /// Aggregated human-readable explanation across drift entries.
    pub reason: Option<String>,

    /// Snapshot of the typed Drift the SecurityController computed
    /// at this decision tick. Lets an auditor replay
    /// `diff/classify/decide` deterministically.
    pub drift_snapshot: serde_json::Value,

    /// `.gate_decision.decided_at` — the SecurityController's clock.
    #[sea_orm(indexed)]
    pub decided_at: DateTime<Utc>,

    /// When the store recorded this audit row.
    pub recorded_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
