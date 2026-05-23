//! `CartorioAdmitReconciler` — the canonical demonstrator for the
//! Reconciler pattern. Wraps cartorio's HTTP API
//! (`pleme-io/cartorio/src/api.rs`) at the URL+body level so the
//! Reconciler is never out of sync with cartorio's typed surface.
//!
//! ## What it wraps
//!
//! The cartorio HTTP API exposes one route per artifact-state
//! transition:
//!
//! | Transition  | Method | Path                                       |
//! |-------------|--------|--------------------------------------------|
//! | Admit       | POST   | `/api/v1/artifacts`                        |
//! | Revoke      | POST   | `/api/v1/artifacts/{id}/revoke`            |
//! | Quarantine  | POST   | `/api/v1/artifacts/{id}/quarantine`        |
//! | Reactivate  | POST   | `/api/v1/artifacts/{id}/reactivate`        |
//! | Supersede   | POST   | `/api/v1/artifacts/{id}/supersede`         |
//!
//! The Reconciler maps a typed [`CartorioTransition`] to the right
//! URL, forwards the body, and surfaces the response as a
//! [`CartorioAdmitReceipt`].
//!
//! ## Idempotency
//!
//! Cartorio's admit handler returns HTTP 409 Conflict if the digest
//! is already admitted. The Reconciler maps this to
//! [`promessa_types::ReconcilerOutcome::AlreadyConverged`] per trait
//! law `act_idempotent_on_noop`.
//!
//! ## Spec serialization
//!
//! Specs serialize using internally-tagged `kind` field:
//!
//! ```text
//! transition:
//!   kind: revoke
//!   artifact_id: "01HXYZ..."
//!   body:
//!     reason: "Critical CVE CVE-2026-12345"
//!     modifier: { publisher_id: "alice@pleme.io" }
//!     signed_root: { ... }
//! ```

use async_trait::async_trait;
use promessa_controller_common::reconciler_laws_obeyed;
use promessa_types::{Reconciler, ReconcilerError, ReconcilerKind, ReconcilerOutcome};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The cartorio transition this Reconciler should drive. One variant
/// per HTTP route on cartorio's mutation surface.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CartorioTransition {
    /// POST /api/v1/artifacts. `body` is the cartorio
    /// `AdmitArtifactInput` JSON.
    Admit { body: serde_json::Value },

    /// POST /api/v1/artifacts/{id}/revoke. `body` is the cartorio
    /// `RevokeArtifactInput` JSON.
    Revoke { artifact_id: String, body: serde_json::Value },

    /// POST /api/v1/artifacts/{id}/quarantine.
    Quarantine { artifact_id: String, body: serde_json::Value },

    /// POST /api/v1/artifacts/{id}/reactivate.
    Reactivate { artifact_id: String, body: serde_json::Value },

    /// POST /api/v1/artifacts/{id}/supersede.
    Supersede { artifact_id: String, body: serde_json::Value },
}

impl CartorioTransition {
    /// The cartorio URL path this transition targets. Used by the
    /// Reconciler to build the full request URL.
    fn path(&self) -> String {
        match self {
            CartorioTransition::Admit { .. } => "/api/v1/artifacts".into(),
            CartorioTransition::Revoke { artifact_id, .. } => {
                format!("/api/v1/artifacts/{artifact_id}/revoke")
            }
            CartorioTransition::Quarantine { artifact_id, .. } => {
                format!("/api/v1/artifacts/{artifact_id}/quarantine")
            }
            CartorioTransition::Reactivate { artifact_id, .. } => {
                format!("/api/v1/artifacts/{artifact_id}/reactivate")
            }
            CartorioTransition::Supersede { artifact_id, .. } => {
                format!("/api/v1/artifacts/{artifact_id}/supersede")
            }
        }
    }

    fn body(&self) -> &serde_json::Value {
        match self {
            CartorioTransition::Admit { body }
            | CartorioTransition::Revoke { body, .. }
            | CartorioTransition::Quarantine { body, .. }
            | CartorioTransition::Reactivate { body, .. }
            | CartorioTransition::Supersede { body, .. } => body,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            CartorioTransition::Admit { .. } => "admit",
            CartorioTransition::Revoke { .. } => "revoke",
            CartorioTransition::Quarantine { .. } => "quarantine",
            CartorioTransition::Reactivate { .. } => "reactivate",
            CartorioTransition::Supersede { .. } => "supersede",
        }
    }
}

/// Typed input for [`CartorioAdmitReconciler::act`].
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct CartorioAdmitSpec {
    /// Which cartorio transition this Reconciler call drives.
    pub transition: CartorioTransition,
}

/// Typed receipt — the cartorio HTTP response body as JSON plus the
/// transition + URL we drove, so an auditor can reconstruct the call
/// from the receipt alone.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct CartorioAdmitReceipt {
    /// The label of the transition driven (e.g. `"admit"`, `"revoke"`).
    pub transition: String,

    /// Fully-qualified URL we POSTed to.
    pub url: String,

    /// HTTP status returned by cartorio.
    pub status: u16,

    /// Response body as parsed JSON. For Admit, contains
    /// `{id, composed_root, event_id, admitted}`. For mutations,
    /// contains `{event_id, new_status, new_state_root}`.
    pub response: serde_json::Value,
}

/// The Reconciler. Holds a [`reqwest::Client`] + the cartorio base
/// URL; one instance is shared by the engine via [`std::sync::Arc`].
pub struct CartorioAdmitReconciler {
    base_url: String,
    http: reqwest::Client,
}

impl CartorioAdmitReconciler {
    /// Construct with the cartorio API base URL (no trailing slash),
    /// e.g. `http://cartorio.cartorio.svc.cluster.local:8080`.
    #[must_use]
    pub fn new(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("reqwest client builds with defaults");
        Self { base_url, http }
    }

    /// Test helper: inject an explicit [`reqwest::Client`] (used by
    /// wiremock-backed integration tests with custom timeouts).
    #[must_use]
    pub fn with_client(base_url: String, http: reqwest::Client) -> Self {
        Self { base_url, http }
    }
}

#[async_trait]
impl Reconciler for CartorioAdmitReconciler {
    const KIND: ReconcilerKind = ReconcilerKind::CartorioAdmit;

    type Spec = CartorioAdmitSpec;
    type Receipt = CartorioAdmitReceipt;

    async fn act(&self, spec: Self::Spec) -> ReconcilerOutcome<Self::Receipt> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), spec.transition.path());
        let label = spec.transition.label();
        tracing::info!(transition = label, url = %url, "cartorio-admit dispatching");

        let resp = match self.http.post(&url).json(spec.transition.body()).send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() || e.is_connect() => {
                return ReconcilerOutcome::Failed {
                    error: ReconcilerError::Transient {
                        detail: format!("cartorio {label} {url}: {e}"),
                    },
                };
            }
            Err(e) => {
                return ReconcilerOutcome::Failed {
                    error: ReconcilerError::Internal {
                        detail: format!("cartorio {label} {url}: {e}"),
                    },
                };
            }
        };

        let status = resp.status();
        let body: serde_json::Value = match resp.json().await {
            Ok(b) => b,
            Err(e) => serde_json::json!({ "_body_parse_error": e.to_string() }),
        };

        // Idempotent admit: cartorio returns 409 if digest already
        // admitted (api.rs:402 — "artifact with digest {} already
        // admitted"). This is the canonical AlreadyConverged signal.
        if status == reqwest::StatusCode::CONFLICT {
            tracing::info!(
                transition = label,
                url = %url,
                "cartorio reports digest already admitted — AlreadyConverged"
            );
            return ReconcilerOutcome::AlreadyConverged;
        }

        if status.is_success() {
            return ReconcilerOutcome::Applied {
                receipt: CartorioAdmitReceipt {
                    transition: label.into(),
                    url,
                    status: status.as_u16(),
                    response: body,
                },
            };
        }

        // 4xx = clean refusal (validation error, signature failure,
        // org mismatch). 5xx = transient (overload, restart mid-mutate).
        if status.is_client_error() {
            return ReconcilerOutcome::Failed {
                error: ReconcilerError::SubstrateRefused {
                    detail: format!("cartorio {label} {url} → {status}: {body}"),
                },
            };
        }
        ReconcilerOutcome::Failed {
            error: ReconcilerError::Transient {
                detail: format!("cartorio {label} {url} → {status}: {body}"),
            },
        }
    }
}

reconciler_laws_obeyed!(CartorioAdmitReconciler);

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{body_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn rev_spec(artifact_id: &str, reason: &str) -> CartorioAdmitSpec {
        CartorioAdmitSpec {
            transition: CartorioTransition::Revoke {
                artifact_id: artifact_id.into(),
                body: serde_json::json!({
                    "reason": reason,
                    "modifier": { "publisher_id": "test@pleme.io" },
                    "signed_root": { "alg": "ed25519", "sig": "deadbeef" },
                }),
            },
        }
    }

    #[test]
    fn transition_paths_are_canonical() {
        assert_eq!(
            CartorioTransition::Admit { body: serde_json::json!({}) }.path(),
            "/api/v1/artifacts"
        );
        assert_eq!(
            CartorioTransition::Revoke {
                artifact_id: "abc".into(),
                body: serde_json::json!({})
            }
            .path(),
            "/api/v1/artifacts/abc/revoke"
        );
        assert_eq!(
            CartorioTransition::Quarantine {
                artifact_id: "abc".into(),
                body: serde_json::json!({})
            }
            .path(),
            "/api/v1/artifacts/abc/quarantine"
        );
    }

    #[test]
    fn spec_roundtrips_through_serde_json() {
        let s = CartorioAdmitSpec {
            transition: CartorioTransition::Admit {
                body: serde_json::json!({"name": "auth", "digest": "sha256:abc"}),
            },
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["transition"]["kind"], "admit");
        let back: CartorioAdmitSpec = serde_json::from_value(j).unwrap();
        assert_eq!(s, back);
    }

    #[tokio::test]
    async fn revoke_2xx_produces_applied_receipt() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/artifacts/art-123/revoke"))
            .and(body_json(serde_json::json!({
                "reason": "test-critical",
                "modifier": { "publisher_id": "test@pleme.io" },
                "signed_root": { "alg": "ed25519", "sig": "deadbeef" },
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "event_id": "evt-xyz",
                "new_status": "Revoked",
                "new_state_root": "blake3:cafe",
            })))
            .mount(&server)
            .await;

        let r = CartorioAdmitReconciler::new(server.uri());
        let outcome = r.act(rev_spec("art-123", "test-critical")).await;
        let ReconcilerOutcome::Applied { receipt } = outcome else {
            panic!("expected Applied, got {outcome:?}");
        };
        assert_eq!(receipt.transition, "revoke");
        assert_eq!(receipt.status, 200);
        assert_eq!(receipt.response["event_id"], "evt-xyz");
        assert_eq!(receipt.response["new_status"], "Revoked");
    }

    #[tokio::test]
    async fn admit_409_maps_to_already_converged() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/artifacts"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error": "artifact with digest sha256:abc already admitted"
            })))
            .mount(&server)
            .await;

        let r = CartorioAdmitReconciler::new(server.uri());
        let spec = CartorioAdmitSpec {
            transition: CartorioTransition::Admit {
                body: serde_json::json!({"digest": "sha256:abc"}),
            },
        };
        let outcome = r.act(spec).await;
        assert!(matches!(outcome, ReconcilerOutcome::AlreadyConverged));
    }

    #[tokio::test]
    async fn admit_400_maps_to_substrate_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/artifacts"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "org mismatch"
            })))
            .mount(&server)
            .await;

        let r = CartorioAdmitReconciler::new(server.uri());
        let spec = CartorioAdmitSpec {
            transition: CartorioTransition::Admit { body: serde_json::json!({}) },
        };
        let outcome = r.act(spec).await;
        match outcome {
            ReconcilerOutcome::Failed {
                error: ReconcilerError::SubstrateRefused { detail },
            } => {
                assert!(detail.contains("400"));
                assert!(detail.contains("org mismatch"));
            }
            other => panic!("expected SubstrateRefused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn admit_500_maps_to_transient() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/artifacts"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let r = CartorioAdmitReconciler::new(server.uri());
        let spec = CartorioAdmitSpec {
            transition: CartorioTransition::Admit { body: serde_json::json!({}) },
        };
        let outcome = r.act(spec).await;
        match outcome {
            ReconcilerOutcome::Failed {
                error: ReconcilerError::Transient { .. },
            } => {}
            other => panic!("expected Transient (5xx is retryable), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connection_refused_maps_to_transient() {
        // Point at a port nobody's listening on — reqwest should
        // surface a connect error.
        let r = CartorioAdmitReconciler::with_client(
            "http://127.0.0.1:1".into(),
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(250))
                .build()
                .unwrap(),
        );
        let spec = CartorioAdmitSpec {
            transition: CartorioTransition::Admit { body: serde_json::json!({}) },
        };
        let outcome = r.act(spec).await;
        let ReconcilerOutcome::Failed { error } = outcome else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert!(error.is_retryable(), "connect errors are retryable, got {error:?}");
    }
}
