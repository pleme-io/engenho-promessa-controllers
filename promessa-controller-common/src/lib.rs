//! Shared TargetController + Reconciler helpers. The
//! `trait_laws_obeyed!` and `reconciler_laws_obeyed!` macros live
//! here; per VIGGY-AUTHORING §10.1 they expand to the canonical
//! law-invariant suites for any controller/reconciler they're invoked
//! on.
//!
//! Both macros are currently stubs that emit a placeholder test as a
//! marker so consumers can wire them in today. Full expansion lands
//! in D2 with `MockObservationSource` (TargetController) and
//! `MockSubstratePrimitive` (Reconciler).

/// Expand the canonical ten trait-law invariants (VIGGY-AUTHORING
/// §10.1) as a proptest suite for the named controller.
///
/// Stub: emits one assertion as a marker so consumers can wire it in
/// today. Full expansion (observe_referentially_transparent,
/// diff_deterministic, classify_deterministic, classify_monotonic,
/// decide_deterministic, act_idempotent_on_noop, tick_converges,
/// attest_canonical, no_action_without_observation,
/// repeated_failure_terminates) lands in D2 with `MockObservationSource`.
#[macro_export]
macro_rules! trait_laws_obeyed {
    ($controller:ty) => {
        #[cfg(test)]
        mod _trait_laws {
            use super::*;
            #[test]
            fn placeholder_until_d2() {
                // Marker: confirms the macro expanded against the
                // controller type. Full proptest suite pending
                // D2 substrate (MockObservationSource shipping).
                let _phantom: Option<$controller> = None;
            }
        }
    };
}

/// Expand the canonical Reconciler-side trait-law invariants
/// (VIGGY-AUTHORING §5.2 + VIGGY-LEGOS Part IV.7) as a proptest suite
/// for the named Reconciler impl.
///
/// Stub: emits a placeholder test as a marker. Full expansion (laws
/// 1–4: act_idempotent_on_noop, act_deterministic_for_same_input,
/// observe_receipt_typed, flag_gated_returns_typed) lands in D2
/// alongside `MockSubstratePrimitive`.
///
/// Law 5 (repeated_failure_terminates) is engine-enforced, not
/// per-Reconciler — covered by the engine's integration tests.
#[macro_export]
macro_rules! reconciler_laws_obeyed {
    ($reconciler:ty) => {
        #[cfg(test)]
        mod _reconciler_laws {
            use super::*;
            #[test]
            fn placeholder_until_d2() {
                // Marker: confirms the macro expanded against the
                // Reconciler type. Full proptest suite pending D2
                // substrate (MockSubstratePrimitive shipping).
                let _phantom: Option<$reconciler> = None;
            }
        }
    };
}
