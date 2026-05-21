//! Shared reconciler context — a single `ReconcileCtx` is passed to
//! every reconcile-call across all four controllers. Holds the kube
//! client + namespace scope + typed deps (security-controller
//! SecurityController, future cartorio client).

use kube::Client;
use security_controller::SecurityController;

#[derive(Clone)]
pub struct ReconcileCtx {
    pub client: Client,
    /// If set, reconcilers scope to a single namespace. None = cluster-wide.
    pub namespace: Option<String>,
    /// The Viggy Security TargetController instance. Pure function set —
    /// safe to clone freely.
    pub security_controller: SecurityController,
}

impl ReconcileCtx {
    pub fn new(client: Client, namespace: Option<String>) -> Self {
        Self {
            client,
            namespace,
            security_controller: SecurityController,
        }
    }
}
