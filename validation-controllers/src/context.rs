//! Shared reconciler context — a single `ReconcileCtx` is passed to
//! every reconcile-call across all five controllers. Holds the kube
//! client + namespace scope + typed deps (security-controller
//! SecurityController, reconciler-engine ActionExecutor).

use std::sync::Arc;

use kube::Client;
use reconciler_engine::{ActionExecutor, EngineConfig, ReconcilerEngine};
use security_controller::SecurityController;

#[derive(Clone)]
pub struct ReconcileCtx {
    pub client: Client,
    /// If set, reconcilers scope to a single namespace. None = cluster-wide.
    pub namespace: Option<String>,
    /// The Viggy Security TargetController instance. Pure function set —
    /// safe to clone freely.
    pub security_controller: SecurityController,
    /// Universal `TypedAction` executor — routes
    /// `TypedAction::ReconcilerApply` emissions through the registered
    /// concrete Reconcilers (CartorioAdmit / GhcrTagRevoke /
    /// HarborMirror).
    pub action_executor: Arc<ActionExecutor>,
}

impl ReconcileCtx {
    pub fn new(client: Client, namespace: Option<String>) -> Self {
        // Engine boot config — endpoints sourced from env so the same
        // binary runs against any cluster's substrate primitives.
        // Per pleme-dev defaults (cartorio in cartorio ns, Zot in
        // zot-system ns, Harbor at registry.secondfront.com).
        let engine_config = EngineConfig {
            cartorio_base_url: std::env::var("CARTORIO_BASE_URL").unwrap_or_else(|_| {
                "http://cartorio.cartorio.svc.cluster.local:8080".into()
            }),
            zot_base_url: std::env::var("ZOT_BASE_URL").unwrap_or_else(|_| {
                "http://zot.zot-system.svc.cluster.local:5000".into()
            }),
            zot_basic_auth: zot_basic_auth_from_env(),
            harbor_base_url: std::env::var("HARBOR_BASE_URL")
                .unwrap_or_else(|_| "https://registry.secondfront.com".into()),
        };
        let engine = Arc::new(ReconcilerEngine::with_defaults(engine_config));
        let action_executor = Arc::new(ActionExecutor::new(engine));
        Self {
            client,
            namespace,
            security_controller: SecurityController,
            action_executor,
        }
    }
}

/// Read Zot Basic-auth from env. Mounted from the SOPS-encrypted
/// Secret in `pleme-io/k8s/clusters/pleme-dev/infrastructure/zot-stack/zot/zot-push-token.sops.yaml`
/// by the lareira-akeyless-validation chart.
fn zot_basic_auth_from_env() -> Option<reconciler_engine::BasicAuth> {
    let username = std::env::var("ZOT_USERNAME").ok()?;
    let password = std::env::var("ZOT_PASSWORD").ok()?;
    Some(reconciler_engine::BasicAuth { username, password })
}
