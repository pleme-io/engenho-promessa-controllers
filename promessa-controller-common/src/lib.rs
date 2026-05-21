//! Shared TargetController helpers. The `trait_laws_obeyed!` macro
//! lives here; per VIGGY-AUTHORING §10.1 it expands to the canonical
//! ten-invariant proptest suite for any controller it's invoked on.
//!
//! The macro is currently a stub — full expansion lands in M2.

/// Expand the canonical ten trait-law invariants (VIGGY-AUTHORING
/// §10.1) as a proptest suite for the named controller.
///
/// Stub: emits one assertion as a marker so consumers can wire it in
/// today. Full expansion (observe_referentially_transparent,
/// diff_deterministic, classify_deterministic, classify_monotonic,
/// decide_deterministic, act_idempotent_on_noop, tick_converges,
/// attest_canonical, no_action_without_observation,
/// repeated_failure_terminates) lands in M2 with `MockObservationSource`.
#[macro_export]
macro_rules! trait_laws_obeyed {
    ($controller:ty) => {
        #[cfg(test)]
        mod _trait_laws {
            use super::*;
            #[test]
            fn placeholder_until_m2() {
                // Marker: confirms the macro expanded against the
                // controller type. Full proptest suite pending
                // M2 substrate (MockObservationSource shipping).
                let _phantom: Option<$controller> = None;
            }
        }
    };
}
