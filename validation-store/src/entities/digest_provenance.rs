//! `digest_provenance` — the build-and-admission story for a single
//! image digest. Keyed on the digest itself (not the validation run),
//! so multiple validation runs of the same digest share one
//! provenance row.
//!
//! Mirrors the relevant pieces of
//! [`validation_crds::CartorioArtifactState`] + cartorio's
//! `AttestationChain` (source + build + image + compliance pillars).
//! Source data comes from the cartorio HTTP API; the store caches
//! the latest observation so API faces don't have to round-trip.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "digest_provenance")]
pub struct Model {
    /// The OCI manifest digest — `sha256:...`. PK.
    #[sea_orm(primary_key, auto_increment = false)]
    pub image_digest: String,

    /// The akeylesslabs-org-relative repo — e.g. `"akeyless-auth"`.
    #[sea_orm(indexed)]
    pub image_repo: String,

    /// `attestation.source.git_commit` from cartorio.
    pub git_commit: Option<String>,

    /// `attestation.source.tree_hash` — BLAKE3 of the source tree at
    /// the time of build.
    pub git_tree_hash: Option<String>,

    /// `attestation.source.flake_lock_hash` — BLAKE3 of `flake.lock`
    /// for nix-flake-built images.
    pub flake_lock_hash: Option<String>,

    /// Canonical JSON of the full
    /// `cartorio::core::types::AttestationChain` (source + build +
    /// image + compliance).
    pub attestation_chain: serde_json::Value,

    /// Serialized [`validation_crds::CartorioArtifactState`] —
    /// `"Pending"` / `"Active"` / `"Quarantined"` / `"Revoked"` /
    /// `"Superseded"`. Last value observed from the cartorio HTTP
    /// API.
    #[sea_orm(indexed)]
    pub cartorio_status: Option<String>,

    /// The cartorio internal artifact UUID (returned in cartorio's
    /// admit response).
    pub cartorio_artifact_id: Option<String>,

    /// When the store first observed this digest.
    pub first_observed_at: DateTime<Utc>,

    /// Latest observation (cartorio_status may have changed).
    pub last_observed_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
