//! `validation-events` — typed event schema for the AKEYLESS-
//! VALIDATION-PLATFORM security-posture stream.
//!
//! Every meaningful change in the validation pipeline emits one
//! [`ValidationEvent`]. Producers (validation-controllers) serialize
//! the variant to JSON and publish to NATS under the canonical
//! subject hierarchy:
//!
//! ```text
//! validation.posture.<service>.<event-kind>
//!
//! validation.posture.auth.phase-changed
//! validation.posture.uam.finding-recorded
//! validation.posture.kfm.decision-emitted
//! validation.posture.gator.reconciler-dispatched
//! ```
//!
//! Consumers subscribe via wildcards:
//! - `validation.posture.>`         — all posture events, all services
//! - `validation.posture.auth.>`    — just auth's posture
//! - `validation.posture.*.phase-changed`  — phase chain across all services
//!
//! ## Pure types — no NATS client dep
//!
//! This crate intentionally has zero I/O. The wire format is
//! `serde_json::to_vec(&event)`; consumers parse via
//! `serde_json::from_slice`. NATS client wiring lives in
//! `validation-controllers::events_publisher`.
//!
//! ## Why a separate crate
//!
//! `Compounding #1: solve once`. Pulling validation-events as a dep
//! is cheap — no transitive kube-rs / sea-orm / async-nats blowup.
//! External consumers (alerting workers, dashboards, the future SDK
//! gen pipeline) import just the typed schema.

#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use validation_crds::{
    AkeylessImageValidationPhase, GateVerdict, ScanFindingSeverity, ScannerClass, ScannerKind,
};

/// The canonical NATS subject prefix every event is published under.
/// Consumers should wildcard from here.
pub const SUBJECT_PREFIX: &str = "validation.posture";

/// One emission. Variants are tagged on the wire under the `kind`
/// field for cheap consumer-side discrimination.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ValidationEvent {
    /// AkeylessImageValidation `.status.phase` transitioned from
    /// `from` → `to`.
    PhaseChanged(PhaseChanged),

    /// A new ScanFinding was recorded by `scanner` for `validation_run_uid`.
    /// Coarse — one event per finding can be high-volume; subscribers
    /// throttle or filter at the consumer.
    FindingRecorded(FindingRecorded),

    /// The SecurityController emitted a typed gate Decision.
    DecisionEmitted(DecisionEmitted),

    /// The action_dispatcher routed a TypedAction through the
    /// reconciler-engine and recorded an outcome.
    ReconcilerDispatched(ReconcilerDispatched),
}

impl ValidationEvent {
    /// The NATS subject this event publishes under. Derived from the
    /// service name + event kind so consumer wildcards work cleanly.
    #[must_use]
    pub fn subject(&self) -> String {
        let (service, kind) = match self {
            ValidationEvent::PhaseChanged(e) => (e.service.as_str(), "phase-changed"),
            ValidationEvent::FindingRecorded(e) => (e.service.as_str(), "finding-recorded"),
            ValidationEvent::DecisionEmitted(e) => (e.service.as_str(), "decision-emitted"),
            ValidationEvent::ReconcilerDispatched(e) => {
                (e.service.as_str(), "reconciler-dispatched")
            }
        };
        format!("{SUBJECT_PREFIX}.{service}.{kind}")
    }

    /// Universal observed-at — every variant carries one. Returned
    /// generically so consumers can sort/window without matching.
    #[must_use]
    pub fn observed_at(&self) -> DateTime<Utc> {
        match self {
            ValidationEvent::PhaseChanged(e) => e.observed_at,
            ValidationEvent::FindingRecorded(e) => e.observed_at,
            ValidationEvent::DecisionEmitted(e) => e.observed_at,
            ValidationEvent::ReconcilerDispatched(e) => e.observed_at,
        }
    }

    /// The validation_run uid this event references.
    #[must_use]
    pub fn validation_run_uid(&self) -> &str {
        match self {
            ValidationEvent::PhaseChanged(e) => &e.validation_run_uid,
            ValidationEvent::FindingRecorded(e) => &e.validation_run_uid,
            ValidationEvent::DecisionEmitted(e) => &e.validation_run_uid,
            ValidationEvent::ReconcilerDispatched(e) => &e.validation_run_uid,
        }
    }
}

/// Shared metadata every event carries — service + image identity +
/// observed timestamp. Lifted out so each variant only declares its
/// kind-specific fields.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct PhaseChanged {
    pub event_id: String,
    pub validation_run_uid: String,
    pub service: String,
    pub image_digest: String,
    pub image_repo: String,
    pub observed_at: DateTime<Utc>,
    pub from: Option<AkeylessImageValidationPhase>,
    pub to: AkeylessImageValidationPhase,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct FindingRecorded {
    pub event_id: String,
    pub validation_run_uid: String,
    pub service: String,
    pub image_digest: String,
    pub image_repo: String,
    pub observed_at: DateTime<Utc>,
    pub scanner: ScannerKind,
    pub scanner_class: ScannerClass,
    pub severity: ScanFindingSeverity,
    pub cve_id: Option<String>,
    pub package: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct DecisionEmitted {
    pub event_id: String,
    pub validation_run_uid: String,
    pub service: String,
    pub image_digest: String,
    pub image_repo: String,
    pub observed_at: DateTime<Utc>,
    pub severity: String,   // "Cosmetic" | "Functional" | "Critical"
    pub verdict: GateVerdict,
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct ReconcilerDispatched {
    pub event_id: String,
    pub validation_run_uid: String,
    pub service: String,
    pub image_digest: String,
    pub image_repo: String,
    pub observed_at: DateTime<Utc>,
    pub action_kind: String,           // FluxCommit | ReconcilerApply | …
    pub reconciler_kind: Option<String>, // CartorioAdmit | GhcrTagRevoke | HarborMirror | …
    pub outcome: String,                // applied | already-converged | flag-gated | failed
    pub outcome_flag: Option<String>,   // for flag-gated, e.g. gameWardenForwarding.enabled
}

/// Generate a fresh event_id (ULID — time-sortable, 26 chars).
#[must_use]
pub fn new_event_id() -> String {
    ulid::Ulid::new().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_phase_changed() -> ValidationEvent {
        ValidationEvent::PhaseChanged(PhaseChanged {
            event_id: new_event_id(),
            validation_run_uid: "uid-1".into(),
            service: "auth".into(),
            image_digest: "sha256:abc".into(),
            image_repo: "akeyless-auth".into(),
            observed_at: Utc::now(),
            from: Some(AkeylessImageValidationPhase::Scanning),
            to: AkeylessImageValidationPhase::Passed,
        })
    }

    #[test]
    fn subject_for_phase_changed() {
        assert_eq!(sample_phase_changed().subject(), "validation.posture.auth.phase-changed");
    }

    #[test]
    fn subject_for_finding_recorded() {
        let e = ValidationEvent::FindingRecorded(FindingRecorded {
            event_id: new_event_id(),
            validation_run_uid: "uid-1".into(),
            service: "uam".into(),
            image_digest: "sha256:abc".into(),
            image_repo: "akeyless-uam".into(),
            observed_at: Utc::now(),
            scanner: ScannerKind::Trivy,
            scanner_class: ScannerClass::Cve,
            severity: ScanFindingSeverity::High,
            cve_id: Some("CVE-2024-0001".into()),
            package: Some("openssl".into()),
        });
        assert_eq!(e.subject(), "validation.posture.uam.finding-recorded");
    }

    #[test]
    fn subject_for_decision_emitted() {
        let e = ValidationEvent::DecisionEmitted(DecisionEmitted {
            event_id: new_event_id(),
            validation_run_uid: "uid-1".into(),
            service: "kfm".into(),
            image_digest: "sha256:abc".into(),
            image_repo: "akeyless-kfm".into(),
            observed_at: Utc::now(),
            severity: "Critical".into(),
            verdict: GateVerdict::Failed,
            reason: Some("3 critical CVEs".into()),
        });
        assert_eq!(e.subject(), "validation.posture.kfm.decision-emitted");
    }

    #[test]
    fn subject_for_reconciler_dispatched() {
        let e = ValidationEvent::ReconcilerDispatched(ReconcilerDispatched {
            event_id: new_event_id(),
            validation_run_uid: "uid-1".into(),
            service: "gator".into(),
            image_digest: "sha256:abc".into(),
            image_repo: "akeyless-gator".into(),
            observed_at: Utc::now(),
            action_kind: "ReconcilerApply".into(),
            reconciler_kind: Some("HarborMirror".into()),
            outcome: "flag-gated".into(),
            outcome_flag: Some("gameWardenForwarding.enabled".into()),
        });
        assert_eq!(
            e.subject(),
            "validation.posture.gator.reconciler-dispatched"
        );
    }

    #[test]
    fn wire_format_is_kind_tagged_json() {
        let e = sample_phase_changed();
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["kind"], "phase-changed");
        assert!(v.get("event_id").is_some());
        assert!(v.get("service").is_some());
        assert!(v.get("to").is_some());
    }

    #[test]
    fn round_trip_through_json() {
        let e = sample_phase_changed();
        let json = serde_json::to_vec(&e).unwrap();
        let back: ValidationEvent = serde_json::from_slice(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn helpers_return_universal_fields() {
        let e = sample_phase_changed();
        assert_eq!(e.validation_run_uid(), "uid-1");
        assert!(e.observed_at() <= Utc::now());
    }

    #[test]
    fn subject_prefix_is_canonical() {
        assert_eq!(SUBJECT_PREFIX, "validation.posture");
    }

    #[test]
    fn event_id_is_ulid_shape() {
        // 26 chars, Crockford base32 alphabet
        let id = new_event_id();
        assert_eq!(id.len(), 26);
        for c in id.chars() {
            assert!(c.is_ascii_alphanumeric(), "non-ulid char: {c}");
        }
    }
}
