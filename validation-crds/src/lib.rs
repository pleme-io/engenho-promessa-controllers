//! `validation-crds` — three typed CRDs for the AKEYLESS-VALIDATION-
//! PLATFORM substrate per pleme-io/theory/AKEYLESS-VALIDATION-PLATFORM.md.
//!
//! All under `validation.pleme.io/v1`. Every transition is a typed
//! `.status.phase` advancement observed by a Rust reconciler — no
//! timeouts, no polling, no shell-script back-channels.
//!
//! ## Type hierarchy
//!
//! - [`AkeylessImageValidation`] — top-level. One per (digest × promessa).
//! - [`AkeylessEphemeralTenant`] — one per scan wave. Sibling of validation.
//! - [`ScanJob`] — one per (scanner × validation). Wraps a tatara Process CR.
//!
//! ## Phase enums
//!
//! Each CRD owns a typed `*Phase` enum. Transitions are linear with
//! typed failure variants — failure is observable, not inferred.
//!
//! ## Canonical reference
//!
//! [pleme-io/theory/AKEYLESS-VALIDATION-PLATFORM.md] Part III.

pub mod ephemeral_tenant;
pub mod image_validation;
pub mod scan_job;
pub mod shared;

pub use ephemeral_tenant::{
    AkeylessEphemeralTenant, AkeylessEphemeralTenantPhase, AkeylessEphemeralTenantSpec,
    AkeylessEphemeralTenantStatus, DigestSetEntry, InfraResourceRef,
};
pub use image_validation::{
    AkeylessImageValidation, AkeylessImageValidationPhase, AkeylessImageValidationSpec,
    AkeylessImageValidationStatus, GateDecision, GateVerdict, OutcomeReceiptRef,
    ScanJobSummary,
};
pub use scan_job::{
    AttestationRef, ScanFinding, ScanFindingSeverity, ScanJob, ScanJobPhase, ScanJobSpec,
    ScanJobStatus, ScannerClass, ScannerKind,
};
pub use shared::{CartorioArtifactState, ConditionStatus, ConditionType, TypedCondition};

/// Group + version for every CRD in this crate.
pub const GROUP: &str = "validation.pleme.io";
pub const VERSION: &str = "v1";
