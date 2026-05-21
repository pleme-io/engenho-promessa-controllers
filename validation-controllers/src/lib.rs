//! `validation-controllers` — the four reconcilers driving the
//! AKEYLESS-VALIDATION-PLATFORM lifecycle. See
//! pleme-io/theory/AKEYLESS-VALIDATION-PLATFORM.md Part IV.
//!
//! P3 ships AkeylessImageValidationController + scaffolding;
//! P4 ships AkeylessEphemeralTenantController + ScanJobController;
//! OutcomeChainAppender is a background fiber spawned by the engenho-
//! promessa binary.

pub mod image_validation;
pub mod ephemeral_tenant;
pub mod scan_job;
pub mod outcome_chain;

pub use image_validation::AkeylessImageValidationController;
pub use ephemeral_tenant::AkeylessEphemeralTenantController;
pub use scan_job::ScanJobController;
pub use outcome_chain::OutcomeChainAppender;
