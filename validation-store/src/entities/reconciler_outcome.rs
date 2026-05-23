//! `reconciler_outcome` — one row per TypedAction dispatch by
//! `validation-controllers::action_dispatcher`. The history of how
//! the engine routed each [`promessa_types::TypedAction`] emitted by
//! the SecurityController.
//!
//! Composite actions ([`promessa_types::TypedAction::Compose`])
//! produce *one* row per step, all sharing the same
//! `gate_decision_decided_at` so the original dispatch context is
//! recoverable.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "reconciler_outcomes")]
pub struct Model {
    /// ULID — generated on insert.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    /// FK to `validation_runs.uid`.
    #[sea_orm(indexed)]
    pub validation_run_uid: String,

    /// `TypedAction` variant label (e.g. `"ReconcilerApply"`,
    /// `"FluxCommit"`, `"Noop"`, `"Compose"`).
    #[sea_orm(indexed)]
    pub action_kind: String,

    /// For `ReconcilerApply` variants: serialized
    /// [`promessa_types::ReconcilerKind`] (e.g. `"CartorioAdmit"`).
    /// NULL for other action kinds.
    #[sea_orm(indexed)]
    pub reconciler_kind: Option<String>,

    /// Canonical JSON of the dispatched TypedAction (spec body
    /// included). Lets an auditor replay the call.
    pub action_payload: serde_json::Value,

    /// Outcome variant label: `"applied"` / `"already-converged"` /
    /// `"flag-gated"` / `"failed"`.
    #[sea_orm(indexed)]
    pub outcome: String,

    /// For `flag-gated`: the flag name. NULL otherwise.
    pub outcome_flag: Option<String>,

    /// For `applied`: the typed receipt JSON. For `failed`: the
    /// typed [`promessa_types::ReconcilerError`] JSON. NULL for
    /// `already-converged`.
    pub outcome_payload: Option<serde_json::Value>,

    /// The `.status.gateDecision.decided_at` this dispatch
    /// corresponds to. Same value for every step of a Compose.
    #[sea_orm(indexed)]
    pub gate_decision_decided_at: DateTime<Utc>,

    /// When the dispatcher executed this action.
    pub dispatched_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
