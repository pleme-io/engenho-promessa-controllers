//! SeaORM entities mirroring the `validation-crds` typed surface.
//!
//! Each entity is a 1:1 projection of a CRD struct or sub-struct:
//!
//! | Entity                | Mirrors                                                |
//! |-----------------------|--------------------------------------------------------|
//! | [`validation_run`]    | `AkeylessImageValidation` (CR metadata + status digest)|
//! | [`scan_finding`]      | `ScanJobStatus.findings[]` flattened across all ScanJobs|
//! | [`reconciler_outcome`]| Per-dispatch row from `validation-controllers::action_dispatcher` |
//! | [`decision_audit`]    | `AkeylessImageValidationStatus.gate_decision` snapshot at decided_at |
//! | [`digest_provenance`] | The build attestation chain for a digest               |
//!
//! Per VIGGY-AUTHORING §3.3 wrap-not-compete: the CRDs remain
//! canonical; this store is a queryable projection of them, not a
//! redefinition. Enums (`AkeylessImageValidationPhase`,
//! `ScannerKind`, `ScanFindingSeverity`, `GateVerdict`,
//! `CartorioArtifactState`) are stored as `serde_json::to_string`
//! values so a single column type covers every enum without per-DB
//! ENUM-vs-CHECK schema noise. Read-side helpers in [`crate::ops`]
//! re-parse them into the typed CRD enums.

pub mod decision_audit;
pub mod digest_provenance;
pub mod reconciler_outcome;
pub mod scan_finding;
pub mod validation_run;
