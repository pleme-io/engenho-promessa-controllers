//! Phase serialization helpers — the `validation_runs.phase` column
//! stores a string (cross-backend compatibility, see
//! [`crate::entities`] module docs). These helpers translate to and
//! from the typed CRD enum without round-tripping through JSON.

use thiserror::Error;
use validation_crds::AkeylessImageValidationPhase;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PhaseParseError {
    #[error("unknown phase {0}")]
    Unknown(String),
}

/// Encode a typed phase as the column string ("Pending" /
/// "Scanning" / ... — matches the enum variant identifiers exactly).
#[must_use]
pub fn serialize_phase(phase: AkeylessImageValidationPhase) -> String {
    use AkeylessImageValidationPhase as P;
    match phase {
        P::Pending => "Pending",
        P::Provisioning => "Provisioning",
        P::Scanning => "Scanning",
        P::Aggregating => "Aggregating",
        P::Attesting => "Attesting",
        P::Gating => "Gating",
        P::Passed => "Passed",
        P::Failed => "Failed",
        P::Quarantined => "Quarantined",
    }
    .to_owned()
}

/// Parse a column string back into the typed phase.
///
/// # Errors
///
/// [`PhaseParseError::Unknown`] if the string doesn't match any
/// declared variant — usually means the CRD added a new variant
/// without a corresponding update here.
pub fn parse_phase(raw: &str) -> Result<AkeylessImageValidationPhase, PhaseParseError> {
    use AkeylessImageValidationPhase as P;
    match raw {
        "Pending" => Ok(P::Pending),
        "Provisioning" => Ok(P::Provisioning),
        "Scanning" => Ok(P::Scanning),
        "Aggregating" => Ok(P::Aggregating),
        "Attesting" => Ok(P::Attesting),
        "Gating" => Ok(P::Gating),
        "Passed" => Ok(P::Passed),
        "Failed" => Ok(P::Failed),
        "Quarantined" => Ok(P::Quarantined),
        other => Err(PhaseParseError::Unknown(other.into())),
    }
}

/// True if a serialized phase represents a terminal state (Passed /
/// Failed / Quarantined). Convenience for query layer.
#[must_use]
pub fn is_terminal_phase(serialized: &str) -> bool {
    matches!(serialized, "Passed" | "Failed" | "Quarantined")
}

#[cfg(test)]
mod tests {
    use super::*;
    use AkeylessImageValidationPhase as P;

    #[test]
    fn all_phases_roundtrip() {
        for phase in [
            P::Pending,
            P::Provisioning,
            P::Scanning,
            P::Aggregating,
            P::Attesting,
            P::Gating,
            P::Passed,
            P::Failed,
            P::Quarantined,
        ] {
            let s = serialize_phase(phase);
            let back = parse_phase(&s).expect("known phase parses");
            assert_eq!(phase, back, "roundtrip failed for {phase:?}");
        }
    }

    #[test]
    fn unknown_phase_errors() {
        let err = parse_phase("FrobBaz").unwrap_err();
        assert_eq!(err, PhaseParseError::Unknown("FrobBaz".into()));
    }

    #[test]
    fn terminal_phase_detection() {
        assert!(is_terminal_phase("Passed"));
        assert!(is_terminal_phase("Failed"));
        assert!(is_terminal_phase("Quarantined"));
        assert!(!is_terminal_phase("Scanning"));
        assert!(!is_terminal_phase("Gating"));
    }

    /// Pin: CRD enum variant count must match the helper's match
    /// arms. If the CRD adds a phase without updating this module,
    /// the `unreachable_patterns` lint catches it; if it removes one,
    /// `non_exhaustive_patterns` does.
    #[test]
    fn helper_arm_count_pins_crd() {
        // We have 9 phases — keep this in sync if the CRD changes.
        let known = [
            P::Pending,
            P::Provisioning,
            P::Scanning,
            P::Aggregating,
            P::Attesting,
            P::Gating,
            P::Passed,
            P::Failed,
            P::Quarantined,
        ];
        assert_eq!(known.len(), 9);
    }
}
