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
    flux_commit::{
        FluxCommitConfig, FluxCommitReceipt, FluxCommitReconciler, FluxCommitSpec,
    },
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
/// For D1: `Compose` and `Noop` are handled directly here, plus
/// `FluxCommit` via the bundled [`FluxCommitReconciler`] (the
/// gitops-native default per VIGGY-AUTHORING §5). Remaining
/// non-Reconciler variants (`CofreRotate`, `MagmaApply`,
/// `CrachaPatch`, `Custom`) return an explicit `Failed` outcome with
/// a FOLLOWUP message — they get dedicated executors in later
/// deliverables.
pub struct ActionExecutor {
    engine: Arc<ReconcilerEngine>,
    /// Optional FluxCommit handler. `None` falls back to a
    /// substrate-refused outcome (e.g., when the engenho-promessa
    /// container is run in a config that doesn't have git auth wired
    /// — tests, smoke runs). Set by callers via
    /// [`ActionExecutor::with_flux_commit`].
    flux_commit: Option<Arc<FluxCommitReconciler>>,
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
        Self { engine, flux_commit: None }
    }

    /// Attach a [`FluxCommitReconciler`] so `TypedAction::FluxCommit`
    /// emissions resolve through it instead of returning Failed.
    #[must_use]
    pub fn with_flux_commit(mut self, handler: FluxCommitReconciler) -> Self {
        self.flux_commit = Some(Arc::new(handler));
        self
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
            // FluxCommit — wraps a `git clone + patch + commit (+ push)`
            // pipeline via the bundled FluxCommitReconciler. When the
            // executor wasn't given a handler at construction time
            // (e.g., test runs), returns SubstrateRefused so callers
            // see the missing-wiring case loudly.
            TypedAction::FluxCommit { path, patch } => {
                let Some(handler) = self.flux_commit.as_ref() else {
                    return ReconcilerOutcome::Failed {
                        error: ReconcilerError::SubstrateRefused {
                            detail: "ActionExecutor has no FluxCommitReconciler attached — \
                                     wire one via ActionExecutor::with_flux_commit at boot. \
                                     spec.path={path}, spec.patch present"
                                .replace("{path}", path),
                        },
                    };
                };
                // TypedAction::FluxCommit doesn't carry the repo URL —
                // it's implicit at SecurityController emission time
                // ("the gitops repo this controller lives in"). We pull
                // the repo URL + branch from the FluxCommitReconciler's
                // config wrapper at boot. For D1 the repo is pinned in
                // the binary's bootstrap; FOLLOWUP(D2): make this part
                // of the TypedAction shape so cross-repo commits are
                // expressible.
                let spec = FluxCommitSpec {
                    repo_url: std::env::var("FLUX_COMMIT_REPO_URL")
                        .unwrap_or_else(|_| "git@github.com:pleme-io/k8s.git".into()),
                    branch: std::env::var("FLUX_COMMIT_BRANCH")
                        .unwrap_or_else(|_| FluxCommitSpec::default_branch()),
                    path: path.clone(),
                    patch: patch.clone(),
                    commit_message: None,
                };
                let outcome = handler.act(spec).await;
                // Promote Applied receipt into ErasedOutcome.
                match outcome {
                    ReconcilerOutcome::Applied { receipt } => {
                        let json = serde_json::to_value(receipt)
                            .unwrap_or(serde_json::Value::Null);
                        ReconcilerOutcome::Applied { receipt: json }
                    }
                    ReconcilerOutcome::AlreadyConverged => ReconcilerOutcome::AlreadyConverged,
                    ReconcilerOutcome::FlagGated { flag } => {
                        ReconcilerOutcome::FlagGated { flag }
                    }
                    ReconcilerOutcome::Failed { error } => ReconcilerOutcome::Failed { error },
                }
            }
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
    async fn action_executor_flux_commit_unwired_refused() {
        // When ActionExecutor is constructed without
        // `.with_flux_commit(...)`, a TypedAction::FluxCommit emission
        // returns SubstrateRefused — making the "no handler at boot"
        // case loud rather than silently dropping the dispatch.
        let engine = Arc::new(ReconcilerEngine::builder().build());
        let exec = ActionExecutor::new(engine);
        let action = TypedAction::FluxCommit {
            path: "clusters/pleme-dev/apps/akeyless-minimal/helmrelease.yaml".into(),
            patch: serde_json::json!({}),
        };
        let outcome = exec.execute(&action).await;
        match outcome {
            ReconcilerOutcome::Failed {
                error: ReconcilerError::SubstrateRefused { detail },
            } => {
                assert!(detail.contains("no FluxCommitReconciler attached"));
                assert!(detail.contains("with_flux_commit"));
            }
            other => panic!("expected SubstrateRefused (handler unwired), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn action_executor_flux_commit_wired_dispatches() {
        // With a handler attached, FluxCommit emissions flow through
        // it — verified here by setting dry_run=true on a nonexistent
        // repo URL so the dispatch surfaces SubstrateRefused from the
        // git clone failure (not from the missing-handler branch).
        let engine = Arc::new(ReconcilerEngine::builder().build());
        let handler = FluxCommitReconciler::new(FluxCommitConfig {
            dry_run: true,
            ..Default::default()
        });
        let exec = ActionExecutor::new(engine).with_flux_commit(handler);
        let action = TypedAction::FluxCommit {
            path: "values.yaml".into(),
            patch: serde_json::json!({}),
        };
        // Override the repo URL to a nonexistent local path via env.
        // Safety: SetEnv inside a test is racy in Rust 2024
        // (env::set_var marked unsafe). The wider tests don't read
        // FLUX_COMMIT_REPO_URL, so the race is benign — but for
        // hygiene we skip the env override and accept the default
        // (git@github.com:pleme-io/k8s.git), which will SubstrateRefused
        // on the clone step inside the test sandbox.
        let outcome = exec.execute(&action).await;
        match outcome {
            ReconcilerOutcome::Failed {
                error: ReconcilerError::SubstrateRefused { .. },
            } => {
                // Substrate-level refusal (git clone failed) — the
                // dispatch path reached the handler, which is what
                // the test pins.
            }
            // If the test sandbox has SSH creds + reaches the real
            // pleme-io/k8s repo, we get Applied. Also valid — the
            // handler wired correctly.
            ReconcilerOutcome::Applied { .. } => {}
            other => panic!(
                "expected SubstrateRefused or Applied from wired handler, got {other:?}"
            ),
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
