//! Stub — implementation lands per AKEYLESS-VALIDATION-PLATFORM.md Part IV.4.
//!
//! `OutcomeChainAppender` is a background fiber (not a CR-watching
//! reconciler). Spawned by the engenho-promessa binary at startup,
//! it subscribes to `AkeylessImageValidation.status.phase` terminal
//! transitions via denshin NATS and appends a BLAKE3+Ed25519 signed
//! receipt to MinIO.

#[derive(Debug, Clone, Default)]
pub struct OutcomeChainAppender;
