//! `reconciler-engine` — the universal dispatcher for
//! `TypedAction::ReconcilerApply` emissions per VIGGY-LEGOS Part IV +
//! CONVERGENCE-SUBSTRATE §III.2.
//!
//! ## Architecture
//!
//! ```text
//! TargetController.decide() → Decision::AutoCorrect(TypedAction)
//!                                  │
//!                                  ▼
//!                          ActionExecutor::execute()
//!                          ┌─────────┴──────────┐
//!                          │                    │
//!                ReconcilerApply              FluxCommit │ CofreRotate │ …
//!                          │                    │
//!                          ▼                    ▼
//!                  ReconcilerEngine        (dedicated executors,
//!                  ┌──────┴──────┐           future deliverables)
//!                  │ CartorioAdmit│
//!                  │ GhcrTagRevoke│
//!                  │ HarborMirror │ ← flag-gated
//!                  │ ...          │
//!                  └──────────────┘
//! ```
//!
//! ## Two layers
//!
//! 1. [`ReconcilerEngine`] — keyed on [`ReconcilerKind`], dispatches
//!    `ReconcilerApply` variants only. Each handler is a concrete
//!    [`promessa_types::Reconciler`] impl wrapping a substrate
//!    primitive.
//!
//! 2. [`ActionExecutor`] — wraps [`ReconcilerEngine`] and handles the
//!    remaining [`promessa_types::TypedAction`] variants
//!    ([`promessa_types::TypedAction::FluxCommit`],
//!    [`promessa_types::TypedAction::CofreRotate`],
//!    [`promessa_types::TypedAction::MagmaApply`],
//!    [`promessa_types::TypedAction::CrachaPatch`],
//!    [`promessa_types::TypedAction::Compose`],
//!    [`promessa_types::TypedAction::Noop`]).
//!
//! For D1 (this deliverable), the engine ships three concrete
//! Reconcilers (CartorioAdmit full impl, GhcrTagRevoke full impl,
//! HarborMirror flag-gated stub) and the ActionExecutor handles
//! `Compose` + `Noop` directly; other variants return an explicit
//! `Failed` outcome with a `FOLLOWUP` doc-comment pointer.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use promessa_types::{
    Reconciler, ReconcilerError, ReconcilerKind, ReconcilerOutcome, TypedAction,
};
use serde::{Deserialize, Serialize};

pub mod reconcilers;

pub use reconcilers::{
    cartorio_admit::{CartorioAdmitReceipt, CartorioAdmitReconciler, CartorioAdmitSpec},
    ghcr_tag_revoke::{GhcrTagRevokeReceipt, GhcrTagRevokeReconciler, GhcrTagRevokeSpec},
    harbor_mirror::{HarborMirrorReceipt, HarborMirrorReconciler, HarborMirrorSpec},
};

/// Erased outcome type — every dispatch returns a
/// [`ReconcilerOutcome`] whose `Applied` payload is a typed-but-erased
/// [`serde_json::Value`]. The caller's CR controller re-serializes
/// the value into the parent CR's `.status.reconcilerOutcomes[]`
/// without needing to know the concrete [`Reconciler::Receipt`] type.
pub type ErasedOutcome = ReconcilerOutcome<serde_json::Value>;

/// Type-erased Reconciler trait. Blanket-impl'd for any
/// [`Reconciler`]. Lives behind a `Box<dyn>` in the engine's dispatch
/// table.
#[async_trait]
pub trait ErasedReconciler: Send + Sync + 'static {
    fn kind(&self) -> ReconcilerKind;
    async fn act_erased(&self, spec: serde_json::Value) -> ErasedOutcome;
}

#[async_trait]
impl<R> ErasedReconciler for R
where
    R: Reconciler,
{
    fn kind(&self) -> ReconcilerKind {
        <R as Reconciler>::KIND
    }

    async fn act_erased(&self, spec: serde_json::Value) -> ErasedOutcome {
        let typed = match serde_json::from_value::<R::Spec>(spec) {
            Ok(s) => s,
            Err(e) => {
                return ReconcilerOutcome::Failed {
                    error: ReconcilerError::InvalidSpec {
                        detail: format!("deserialize spec for {:?}: {e}", R::KIND),
                    },
                };
            }
        };
        match self.act(typed).await {
            ReconcilerOutcome::Applied { receipt } => {
                let receipt_json = serde_json::to_value(&receipt).unwrap_or_else(|e| {
                    serde_json::json!({
                        "_serialize_error": e.to_string(),
                    })
                });
                ReconcilerOutcome::Applied { receipt: receipt_json }
            }
            ReconcilerOutcome::AlreadyConverged => ReconcilerOutcome::AlreadyConverged,
            ReconcilerOutcome::FlagGated { flag } => ReconcilerOutcome::FlagGated { flag },
            ReconcilerOutcome::Failed { error } => ReconcilerOutcome::Failed { error },
        }
    }
}

/// The universal Reconciler dispatcher. Construct via
/// [`ReconcilerEngine::builder`] or [`ReconcilerEngine::with_defaults`].
pub struct ReconcilerEngine {
    handlers: HashMap<ReconcilerKind, Arc<dyn ErasedReconciler>>,
}

impl ReconcilerEngine {
    /// Empty engine — register handlers explicitly. Useful for tests
    /// that want narrow coverage.
    #[must_use]
    pub fn builder() -> ReconcilerEngineBuilder {
        ReconcilerEngineBuilder { handlers: HashMap::new() }
    }

    /// Engine populated with the D1 default handlers:
    /// CartorioAdmit (live), GhcrTagRevoke (live), HarborMirror
    /// (flag-gated). Other [`ReconcilerKind`] variants return
    /// `NoHandlerRegistered` when dispatched against this engine —
    /// see [`ReconcilerEngine::dispatch`].
    #[must_use]
    pub fn with_defaults(config: EngineConfig) -> Self {
        Self::builder()
            .register(CartorioAdmitReconciler::new(config.cartorio_base_url.clone()))
            .register(GhcrTagRevokeReconciler::new(
                config.zot_base_url.clone(),
                config.zot_basic_auth.clone(),
            ))
            .register(HarborMirrorReconciler::new(config.harbor_base_url.clone()))
            .build()
    }

    /// Dispatch a [`TypedAction::ReconcilerApply`]. Other
    /// [`TypedAction`] variants return `InvalidSpec` — only the
    /// [`ActionExecutor`] wrapper dispatches non-Reconciler variants.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerOutcome::Failed`] with
    /// [`ReconcilerError::Internal`] if the action is not a
    /// `ReconcilerApply`, and [`ReconcilerError::Internal`] again if
    /// no handler is registered for the requested
    /// [`ReconcilerKind`].
    pub async fn dispatch(&self, action: &TypedAction) -> ErasedOutcome {
        let TypedAction::ReconcilerApply { reconciler, spec } = action else {
            return ReconcilerOutcome::Failed {
                error: ReconcilerError::Internal {
                    detail: format!(
                        "ReconcilerEngine only dispatches ReconcilerApply, got {action:?}"
                    ),
                },
            };
        };
        let Some(handler) = self.handlers.get(reconciler) else {
            return ReconcilerOutcome::Failed {
                error: ReconcilerError::Internal {
                    detail: format!("no handler registered for {reconciler:?}"),
                },
            };
        };
        handler.act_erased(spec.clone()).await
    }

    /// Which [`ReconcilerKind`] variants does this engine know how to
    /// dispatch? Useful for boot-time exhaustiveness logging.
    pub fn registered_kinds(&self) -> impl Iterator<Item = ReconcilerKind> + '_ {
        self.handlers.keys().copied()
    }
}

/// Engine builder so registration order is explicit.
pub struct ReconcilerEngineBuilder {
    handlers: HashMap<ReconcilerKind, Arc<dyn ErasedReconciler>>,
}

impl ReconcilerEngineBuilder {
    #[must_use]
    pub fn register<R: Reconciler>(mut self, handler: R) -> Self {
        let kind = <R as Reconciler>::KIND;
        let prior = self.handlers.insert(kind, Arc::new(handler));
        debug_assert!(prior.is_none(), "duplicate registration for {kind:?}");
        self
    }

    #[must_use]
    pub fn build(self) -> ReconcilerEngine {
        ReconcilerEngine { handlers: self.handlers }
    }
}

/// Engine boot-time configuration. Each field maps to one substrate
/// primitive the Reconcilers wrap.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Base URL of the cartorio HTTP API. Example:
    /// `http://cartorio.cartorio.svc.cluster.local:8080`
    pub cartorio_base_url: String,

    /// Base URL of the Zot private registry. Example:
    /// `https://zot.zot-system.svc.cluster.local:5000` (in-cluster)
    /// or `https://zot-dev.quero.cloud` (laptop pushes).
    pub zot_base_url: String,

    /// Optional Basic-auth credentials for Zot. `None` means
    /// anonymous (read-only) access — write operations will 401.
    pub zot_basic_auth: Option<BasicAuth>,

    /// Base URL of the Second Front Harbor registry. Example:
    /// `https://registry.secondfront.com`. Reconciler is flag-gated;
    /// see [`HarborMirrorReconciler`].
    pub harbor_base_url: String,
}

/// HTTP Basic-auth credentials — used by GhcrTagRevoke when talking
/// to Zot.
#[derive(Clone, Debug)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

/// `ActionExecutor` — wraps [`ReconcilerEngine`] and handles the
/// non-Reconciler [`TypedAction`] variants.
///
/// For D1: `Compose` and `Noop` are handled directly here. Other
/// non-Reconciler variants (`FluxCommit`, `CofreRotate`,
/// `MagmaApply`, `CrachaPatch`, `Custom`) return an explicit
/// `Failed` outcome with a FOLLOWUP message — they get dedicated
/// executors in later deliverables.
pub struct ActionExecutor {
    engine: Arc<ReconcilerEngine>,
}

/// Compose result: the typed outcome from each step in a
/// [`TypedAction::Compose`] sequence. Order-preserving.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ComposeReceipt {
    pub steps: Vec<ErasedOutcome>,
}

impl ActionExecutor {
    #[must_use]
    pub fn new(engine: Arc<ReconcilerEngine>) -> Self {
        Self { engine }
    }

    /// Snapshot of which [`ReconcilerKind`] variants the wrapped
    /// engine knows how to dispatch. Useful for boot-time logging.
    #[must_use]
    pub fn registered_kinds_snapshot(&self) -> Vec<ReconcilerKind> {
        self.engine.registered_kinds().collect()
    }

    /// Dispatch any [`TypedAction`] variant. Recursive for
    /// `Compose`; trivial for `Noop`; routes `ReconcilerApply` to
    /// the engine.
    pub async fn execute(&self, action: &TypedAction) -> ErasedOutcome {
        match action {
            TypedAction::ReconcilerApply { .. } => self.engine.dispatch(action).await,
            TypedAction::Noop => ReconcilerOutcome::AlreadyConverged,
            TypedAction::Compose(steps) => {
                let mut receipts = Vec::with_capacity(steps.len());
                for step in steps {
                    let outcome = Box::pin(self.execute(step)).await;
                    let terminal_success = outcome.is_terminal_success();
                    receipts.push(outcome);
                    if !terminal_success {
                        // Short-circuit on first non-success per
                        // VIGGY-AUTHORING §5.2 trait law `act_atomic`.
                        break;
                    }
                }
                let json = serde_json::to_value(ComposeReceipt { steps: receipts })
                    .unwrap_or(serde_json::Value::Null);
                ReconcilerOutcome::Applied { receipt: json }
            }
            // FOLLOWUP(D1+): FluxCommit executor wrapping FluxCD
            // GitRepository commit-and-push to clusters/<cluster>/.
            TypedAction::FluxCommit { .. } => ReconcilerOutcome::Failed {
                error: ReconcilerError::Internal {
                    detail: "FluxCommit executor not yet shipped — D1+ deliverable. \
                             SecurityController emits this for Critical-severity \
                             pin-to-previous-good. Track at FOLLOWUP(reconciler-engine#flux-commit)."
                        .into(),
                },
            },
            // FOLLOWUP(D1+): CofreRotate executor wrapping cofre CLI
            // (currently CLI-only per VIGGY-LEGOS V.3).
            TypedAction::CofreRotate { .. } => ReconcilerOutcome::Failed {
                error: ReconcilerError::Internal {
                    detail: "CofreRotate executor not yet shipped — D1+ deliverable. \
                             Track at FOLLOWUP(reconciler-engine#cofre-rotate)."
                        .into(),
                },
            },
            // FOLLOWUP(D1+): MagmaApply executor wrapping
            // pangea-operator MagmaExecutor.
            TypedAction::MagmaApply { .. } => ReconcilerOutcome::Failed {
                error: ReconcilerError::Internal {
                    detail: "MagmaApply executor not yet shipped — D1+ deliverable. \
                             Track at FOLLOWUP(reconciler-engine#magma-apply)."
                        .into(),
                },
            },
            // FOLLOWUP(D1+): CrachaPatch executor wrapping
            // saguao crachá API.
            TypedAction::CrachaPatch { .. } => ReconcilerOutcome::Failed {
                error: ReconcilerError::Internal {
                    detail: "CrachaPatch executor not yet shipped — D1+ deliverable. \
                             Track at FOLLOWUP(reconciler-engine#cracha-patch)."
                        .into(),
                },
            },
            // Per VIGGY-AUTHORING §5.3 anti-patterns: `Custom`
            // should never reach the executor — three Custom uses
            // forces extraction of a typed variant. Engine refuses.
            TypedAction::Custom { kind, .. } => ReconcilerOutcome::Failed {
                error: ReconcilerError::InvalidSpec {
                    detail: format!(
                        "TypedAction::Custom rejected — extract a typed variant for kind={kind} \
                         (VIGGY-AUTHORING §5.3 three-times rule)."
                    ),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatch_unknown_kind_returns_failed_internal() {
        let engine = ReconcilerEngine::builder().build();
        let action = TypedAction::ReconcilerApply {
            reconciler: ReconcilerKind::CartorioAdmit,
            spec: serde_json::json!({}),
        };
        let outcome = engine.dispatch(&action).await;
        match outcome {
            ReconcilerOutcome::Failed { error: ReconcilerError::Internal { detail } } => {
                assert!(detail.contains("no handler registered"));
            }
            other => panic!("expected Failed Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_non_reconciler_apply_returns_failed() {
        let engine = ReconcilerEngine::builder().build();
        let action = TypedAction::Noop;
        let outcome = engine.dispatch(&action).await;
        assert!(matches!(outcome, ReconcilerOutcome::Failed { .. }));
    }

    #[tokio::test]
    async fn action_executor_noop_succeeds() {
        let engine = Arc::new(ReconcilerEngine::builder().build());
        let exec = ActionExecutor::new(engine);
        let outcome = exec.execute(&TypedAction::Noop).await;
        assert!(matches!(outcome, ReconcilerOutcome::AlreadyConverged));
    }

    #[tokio::test]
    async fn action_executor_custom_rejected() {
        let engine = Arc::new(ReconcilerEngine::builder().build());
        let exec = ActionExecutor::new(engine);
        let action = TypedAction::Custom {
            kind: "test-something".into(),
            payload: serde_json::json!({}),
        };
        let outcome = exec.execute(&action).await;
        match outcome {
            ReconcilerOutcome::Failed { error: ReconcilerError::InvalidSpec { detail } } => {
                assert!(detail.contains("three-times rule"));
            }
            other => panic!("expected InvalidSpec rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn action_executor_flux_commit_marked_followup() {
        let engine = Arc::new(ReconcilerEngine::builder().build());
        let exec = ActionExecutor::new(engine);
        let action = TypedAction::FluxCommit {
            path: "clusters/pleme-dev/apps/akeyless-minimal/helmrelease.yaml".into(),
            patch: serde_json::json!({}),
        };
        let outcome = exec.execute(&action).await;
        match outcome {
            ReconcilerOutcome::Failed { error: ReconcilerError::Internal { detail } } => {
                assert!(detail.contains("FOLLOWUP"));
            }
            other => panic!("expected FOLLOWUP marker, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn compose_short_circuits_on_failure() {
        let engine = Arc::new(ReconcilerEngine::builder().build());
        let exec = ActionExecutor::new(engine);
        let action = TypedAction::Compose(vec![
            TypedAction::Noop,
            TypedAction::FluxCommit {
                path: "x".into(),
                patch: serde_json::json!({}),
            },
            // This Noop should never run — the FluxCommit step
            // returns Failed and Compose short-circuits.
            TypedAction::Noop,
        ]);
        let outcome = exec.execute(&action).await;
        let ReconcilerOutcome::Applied { receipt } = outcome else {
            panic!("expected Applied with ComposeReceipt");
        };
        let parsed: ComposeReceipt = serde_json::from_value(receipt).unwrap();
        assert_eq!(parsed.steps.len(), 2, "should short-circuit after second step");
        assert!(matches!(parsed.steps[0], ReconcilerOutcome::AlreadyConverged));
        assert!(matches!(parsed.steps[1], ReconcilerOutcome::Failed { .. }));
    }
}
