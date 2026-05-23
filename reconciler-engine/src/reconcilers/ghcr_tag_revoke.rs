//! `GhcrTagRevokeReconciler` — revoke a tag/manifest reference from
//! the cluster-singleton Zot private registry.
//!
//! ## Naming note (FOLLOWUP)
//!
//! The [`promessa_types::ReconcilerKind::GhcrTagRevoke`] variant was
//! named when GHCR was the planned registry. As of 2026-05-21
//! (`pleme-io/k8s` commit `9b734ad` "push target: ghcr → cluster-
//! singleton Zot on pleme-dev") the canonical registry for Akeyless
//! images is `zot-dev.quero.cloud` (Zot v2.1.5). The enum variant
//! name is retained because rename = breaking change; track upgrade
//! at FOLLOWUP(promessa-types#rename-ghcr-to-zot).
//!
//! ## What it wraps
//!
//! The OCI Distribution Spec v2 manifest-delete route:
//!
//! ```text
//! DELETE /v2/{name}/manifests/{reference}
//! ```
//!
//! where `reference` is either a tag (e.g. `release-candidate`) or
//! a digest (e.g. `sha256:abc…`). Zot accepts both. Deleting by
//! digest is the canonical "revoke" — the manifest blob is no longer
//! addressable. Deleting by tag leaves the blob in place for GC but
//! removes the human-readable handle.
//!
//! ## Auth
//!
//! Zot enforces htpasswd Basic auth on mutating routes. The
//! Reconciler accepts Basic credentials from
//! [`crate::EngineConfig::zot_basic_auth`]. The token comes from
//! `pleme-io/k8s/clusters/pleme-dev/infrastructure/zot-stack/zot/zot-push-token.sops.yaml`.
//!
//! ## Idempotency
//!
//! Zot returns 404 when the reference is already absent — the
//! Reconciler maps this to
//! [`promessa_types::ReconcilerOutcome::AlreadyConverged`] (trait law
//! `act_idempotent_on_noop`).

use async_trait::async_trait;
use promessa_controller_common::reconciler_laws_obeyed;
use promessa_types::{Reconciler, ReconcilerError, ReconcilerKind, ReconcilerOutcome};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::BasicAuth;

/// Typed input for [`GhcrTagRevokeReconciler::act`].
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct GhcrTagRevokeSpec {
    /// OCI repository name. Example: `"akeyless-auth"`.
    pub repository: String,

    /// Manifest reference. Either a tag (`"release-candidate"`) or a
    /// digest (`"sha256:abc…"`). Prefer digest for irreversibility.
    pub reference: String,
}

/// Typed receipt — captures the call signature + Zot's response, so
/// an auditor can replay the revoke from the receipt alone.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct GhcrTagRevokeReceipt {
    pub url: String,
    pub repository: String,
    pub reference: String,
    pub status: u16,
    /// `true` if the registry actually deleted (2xx), `false` if it
    /// was already absent (404 → AlreadyConverged path, not surfaced
    /// in `Applied`).
    pub deleted: bool,
    /// The Zot response body when present (some 2xx responses are
    /// empty per OCI spec).
    pub response: Option<serde_json::Value>,
}

/// The Reconciler. Holds the registry base URL + optional Basic-auth
/// credentials.
pub struct GhcrTagRevokeReconciler {
    base_url: String,
    auth: Option<BasicAuth>,
    http: reqwest::Client,
}

impl GhcrTagRevokeReconciler {
    #[must_use]
    pub fn new(base_url: String, auth: Option<BasicAuth>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("reqwest client builds with defaults");
        Self { base_url, auth, http }
    }

    #[must_use]
    pub fn with_client(
        base_url: String,
        auth: Option<BasicAuth>,
        http: reqwest::Client,
    ) -> Self {
        Self { base_url, auth, http }
    }
}

#[async_trait]
impl Reconciler for GhcrTagRevokeReconciler {
    const KIND: ReconcilerKind = ReconcilerKind::GhcrTagRevoke;

    type Spec = GhcrTagRevokeSpec;
    type Receipt = GhcrTagRevokeReceipt;

    async fn act(&self, spec: Self::Spec) -> ReconcilerOutcome<Self::Receipt> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            self.base_url.trim_end_matches('/'),
            spec.repository,
            spec.reference,
        );
        tracing::info!(
            repo = %spec.repository,
            reference = %spec.reference,
            url = %url,
            "ghcr-tag-revoke (Zot DELETE) dispatching"
        );

        let mut req = self.http.delete(&url);
        if let Some(auth) = &self.auth {
            req = req.basic_auth(&auth.username, Some(&auth.password));
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() || e.is_connect() => {
                return ReconcilerOutcome::Failed {
                    error: ReconcilerError::Transient {
                        detail: format!("zot delete {url}: {e}"),
                    },
                };
            }
            Err(e) => {
                return ReconcilerOutcome::Failed {
                    error: ReconcilerError::Internal {
                        detail: format!("zot delete {url}: {e}"),
                    },
                };
            }
        };

        let status = resp.status();
        // Try to capture body (often empty for 202/204) for the
        // receipt; tolerate parse failures.
        let body: Option<serde_json::Value> = match resp.json().await {
            Ok(b) => Some(b),
            Err(_) => None,
        };

        // OCI Distribution spec §4.1 — 202 Accepted for async delete;
        // 200 OK for synchronous. Both are success.
        if status.is_success() {
            return ReconcilerOutcome::Applied {
                receipt: GhcrTagRevokeReceipt {
                    url,
                    repository: spec.repository,
                    reference: spec.reference,
                    status: status.as_u16(),
                    deleted: true,
                    response: body,
                },
            };
        }

        // Reference already absent — idempotent no-op.
        if status == reqwest::StatusCode::NOT_FOUND {
            return ReconcilerOutcome::AlreadyConverged;
        }

        // 401/403 = auth/policy refusal. 4xx generally = clean refusal.
        if status.is_client_error() {
            return ReconcilerOutcome::Failed {
                error: ReconcilerError::SubstrateRefused {
                    detail: format!(
                        "zot delete {url} → {status}: {}",
                        body.as_ref().map_or_else(String::new, ToString::to_string)
                    ),
                },
            };
        }
        ReconcilerOutcome::Failed {
            error: ReconcilerError::Transient {
                detail: format!("zot delete {url} → {status}"),
            },
        }
    }
}

reconciler_laws_obeyed!(GhcrTagRevokeReconciler);

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn spec(repo: &str, reference: &str) -> GhcrTagRevokeSpec {
        GhcrTagRevokeSpec {
            repository: repo.into(),
            reference: reference.into(),
        }
    }

    #[test]
    fn spec_roundtrips() {
        let s = spec("akeyless-auth", "sha256:abc");
        let j = serde_json::to_value(&s).unwrap();
        let back: GhcrTagRevokeSpec = serde_json::from_value(j).unwrap();
        assert_eq!(s, back);
    }

    #[tokio::test]
    async fn delete_2xx_produces_applied() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v2/akeyless-auth/manifests/sha256:abc"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let r = GhcrTagRevokeReconciler::new(server.uri(), None);
        let outcome = r.act(spec("akeyless-auth", "sha256:abc")).await;
        let ReconcilerOutcome::Applied { receipt } = outcome else {
            panic!("expected Applied, got {outcome:?}");
        };
        assert!(receipt.deleted);
        assert_eq!(receipt.status, 202);
        assert_eq!(receipt.repository, "akeyless-auth");
    }

    #[tokio::test]
    async fn delete_404_maps_to_already_converged() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v2/akeyless-auth/manifests/sha256:missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let r = GhcrTagRevokeReconciler::new(server.uri(), None);
        let outcome = r.act(spec("akeyless-auth", "sha256:missing")).await;
        assert!(matches!(outcome, ReconcilerOutcome::AlreadyConverged));
    }

    #[tokio::test]
    async fn delete_401_substrate_refused() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v2/akeyless-auth/manifests/x"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let r = GhcrTagRevokeReconciler::new(server.uri(), None);
        let outcome = r.act(spec("akeyless-auth", "x")).await;
        match outcome {
            ReconcilerOutcome::Failed {
                error: ReconcilerError::SubstrateRefused { detail },
            } => {
                assert!(detail.contains("401"));
            }
            other => panic!("expected SubstrateRefused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn basic_auth_header_set_when_creds_provided() {
        let server = MockServer::start().await;
        // "akeyless-builder:supersecret" base64 → YWtleWxlc3MtYnVpbGRlcjpzdXBlcnNlY3JldA==
        Mock::given(method("DELETE"))
            .and(path("/v2/akeyless-auth/manifests/x"))
            .and(header(
                "authorization",
                "Basic YWtleWxlc3MtYnVpbGRlcjpzdXBlcnNlY3JldA==",
            ))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let r = GhcrTagRevokeReconciler::new(
            server.uri(),
            Some(BasicAuth {
                username: "akeyless-builder".into(),
                password: "supersecret".into(),
            }),
        );
        let outcome = r.act(spec("akeyless-auth", "x")).await;
        assert!(matches!(outcome, ReconcilerOutcome::Applied { .. }));
    }

    #[tokio::test]
    async fn delete_500_transient() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v2/akeyless-auth/manifests/x"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let r = GhcrTagRevokeReconciler::new(server.uri(), None);
        let outcome = r.act(spec("akeyless-auth", "x")).await;
        match outcome {
            ReconcilerOutcome::Failed { error } => {
                assert!(error.is_retryable());
            }
            other => panic!("expected retryable Failed, got {other:?}"),
        }
    }
}
