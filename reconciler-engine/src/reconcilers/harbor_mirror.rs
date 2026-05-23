//! `HarborMirrorReconciler` — copy a Zot-resident digest forward to
//! Second Front's Harbor registry (`registry.secondfront.com`).
//!
//! ## Standing rule (2026-05-22, Luis)
//!
//! > "right now sending to second front should be turned off"
//!
//! This Reconciler is **shipped dormant**. Its [`Reconciler::act`]
//! returns [`promessa_types::ReconcilerOutcome::FlagGated`] whenever
//! `spec.flag_enabled` is `false` — which is the standing default
//! per [`helmworks-akeyless/charts/lareira-akeyless-validation/
//! values.yaml:91`] (`gameWardenForwarding.enabled: false`).
//!
//! Flipping the flag is intentionally a two-PR maneuver per D6
//! (sekiban CompliancePolicy `forbid-harbor-mirror-without-approval`).
//!
//! ## Defense in depth
//!
//! The security-controller already checks the flag before emitting
//! a HarborMirror typed action (security-controller/src/lib.rs:365).
//! This Reconciler re-checks the flag at execution time — if either
//! layer is buggy, the other catches it. Both must agree for any
//! image to flow to Second Front.
//!
//! ## What it would wrap (when un-flag-gated)
//!
//! ```text
//! skopeo copy --preserve-digests --all \
//!     docker://<zot>/akeyless-X@<digest> \
//!     docker://registry.secondfront.com/akeyless/X@<digest>
//! ```
//!
//! plus pre-flight verification that:
//!   * the digest's cartorio status is `Active`,
//!   * the digest's `AkeylessImageValidation.status.phase == Passed`,
//!   * an `ApprovedHarborForwarding` CR exists for the digest set
//!     (admission-gated by sekiban per D6).
//!
//! The full impl lands as a separate D1+ deliverable. It belongs
//! here in the same crate so the flag-gated stub and the active
//! impl share a typed surface.

use async_trait::async_trait;
use promessa_controller_common::reconciler_laws_obeyed;
use promessa_types::{Reconciler, ReconcilerError, ReconcilerKind, ReconcilerOutcome};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The canonical name for the feature flag this Reconciler checks.
/// Matches `helmworks-akeyless/charts/lareira-akeyless-validation/
/// values.yaml` key `gameWardenForwarding.enabled` and the
/// security-controller's `SecuritySpec::harbor_forwarding_enabled`.
pub const HARBOR_FLAG: &str = "gameWardenForwarding.enabled";

/// Typed input for [`HarborMirrorReconciler::act`].
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct HarborMirrorSpec {
    /// Source repository — the akeylesslabs-org-relative name.
    /// Example: `"akeyless-auth"`. The full source URL is built from
    /// the engine's Zot base URL.
    pub source_repo: String,

    /// Source digest — the OCI manifest digest at the source.
    /// Example: `"sha256:abc..."`. Preserved at the target.
    pub source_digest: String,

    /// Target Harbor project. For Second Front, always `"akeyless"`.
    pub target_project: String,

    /// Whether to preserve the source digest at the target (always
    /// `true` in production; existing field for skopeo flag-shape
    /// parity).
    pub preserve_digest: bool,

    /// **Defense-in-depth final guard.** The security-controller
    /// gates emission of HarborMirror on the same flag; this field
    /// is the Reconciler-side re-check. If `false`, the Reconciler
    /// refuses without contacting Harbor.
    pub flag_enabled: bool,
}

/// Typed receipt — when the active path eventually ships. For
/// dormant calls returning `FlagGated`, this type is unused.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct HarborMirrorReceipt {
    pub source_url: String,
    pub target_url: String,
    pub source_digest: String,
    pub target_digest: String,
    pub bytes_copied: u64,
}

/// The Reconciler. Holds the Harbor base URL for the future active
/// path; unused while the flag is off.
pub struct HarborMirrorReconciler {
    #[allow(dead_code, reason = "active path (skopeo wrapper) lands in D1+")]
    harbor_base_url: String,
}

impl HarborMirrorReconciler {
    #[must_use]
    pub fn new(harbor_base_url: String) -> Self {
        Self { harbor_base_url }
    }
}

#[async_trait]
impl Reconciler for HarborMirrorReconciler {
    const KIND: ReconcilerKind = ReconcilerKind::HarborMirror;

    type Spec = HarborMirrorSpec;
    type Receipt = HarborMirrorReceipt;

    async fn act(&self, spec: Self::Spec) -> ReconcilerOutcome<Self::Receipt> {
        if !spec.flag_enabled {
            tracing::info!(
                source = %spec.source_repo,
                digest = %spec.source_digest,
                flag = HARBOR_FLAG,
                "harbor-mirror refused — flag is off (standing rule)"
            );
            return ReconcilerOutcome::FlagGated { flag: HARBOR_FLAG.into() };
        }

        // The flag is on but the active path is intentionally not
        // shipped yet. The security-controller should never have
        // emitted with flag_enabled=true while the dormant Reconciler
        // is the only one deployed — this branch is a sentinel for
        // mis-configured deployments. Return a SubstrateRefused so
        // the engine's retry policy doesn't burn cycles.
        ReconcilerOutcome::Failed {
            error: ReconcilerError::SubstrateRefused {
                detail: format!(
                    "harbor-mirror active path not shipped — flag {HARBOR_FLAG} should be \
                     false until D1+ deliverable lands. spec.source_repo={} digest={}",
                    spec.source_repo, spec.source_digest
                ),
            },
        }
    }
}

reconciler_laws_obeyed!(HarborMirrorReconciler);

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(flag_enabled: bool) -> HarborMirrorSpec {
        HarborMirrorSpec {
            source_repo: "akeyless-auth".into(),
            source_digest: "sha256:abc123".into(),
            target_project: "akeyless".into(),
            preserve_digest: true,
            flag_enabled,
        }
    }

    #[tokio::test]
    async fn flag_off_returns_flag_gated() {
        let r = HarborMirrorReconciler::new("https://registry.secondfront.com".into());
        let outcome = r.act(spec(false)).await;
        match outcome {
            ReconcilerOutcome::FlagGated { flag } => {
                assert_eq!(flag, HARBOR_FLAG);
            }
            other => panic!("expected FlagGated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn flag_on_refused_until_active_path_ships() {
        let r = HarborMirrorReconciler::new("https://registry.secondfront.com".into());
        let outcome = r.act(spec(true)).await;
        match outcome {
            ReconcilerOutcome::Failed {
                error: ReconcilerError::SubstrateRefused { detail },
            } => {
                assert!(detail.contains("not shipped"));
                assert!(detail.contains("akeyless-auth"));
            }
            other => panic!("expected SubstrateRefused, got {other:?}"),
        }
    }

    #[test]
    fn spec_roundtrips() {
        let s = spec(false);
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["flag_enabled"], false);
        let back: HarborMirrorSpec = serde_json::from_value(j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn flag_constant_matches_values_yaml() {
        // Pin: the Helm chart values key must stay in sync with this
        // constant. If you change the chart's flag path, change
        // this constant too — or the dormant guard silently fails.
        assert_eq!(HARBOR_FLAG, "gameWardenForwarding.enabled");
    }

    #[test]
    fn flag_gated_outcome_is_terminal_success() {
        let o: ReconcilerOutcome<HarborMirrorReceipt> =
            ReconcilerOutcome::FlagGated { flag: HARBOR_FLAG.into() };
        // The engine treats FlagGated as terminal success — the
        // SecurityController already considered the flag in its
        // Decision, and the Reconciler is the second defensive layer.
        assert!(o.is_terminal_success());
    }
}
