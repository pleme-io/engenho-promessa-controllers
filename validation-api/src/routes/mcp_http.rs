//! MCP HTTP transport — `POST /v1/mcp` accepts JSON-RPC 2.0 requests
//! (`initialize`, `tools/list`, `tools/call`) and returns typed
//! responses. Lets any MCP client (Claude Desktop, OpenAI tools, a
//! custom agent) reach in over HTTPS and query the cluster's full
//! compliance state from anywhere.
//!
//! ## Security
//!
//! - **Bearer token** — operator sets `MCP_BEARER_TOKEN` env on the
//!   validation-api pod (SOPS-encrypted Secret + env injection). The
//!   handler enforces a constant-time-ish compare against the
//!   `Authorization: Bearer <token>` header. Missing/wrong → 401.
//! - **Token absent (env unset)** — endpoint refuses all calls and
//!   logs a `mcp.unconfigured` event. Deploys without explicit
//!   token never accidentally expose the cluster to anonymous
//!   queries. (Operator can set `MCP_ALLOW_ANONYMOUS=1` for dev.)
//! - **HTTPS termination** — chart Ingress configures cert-manager
//!   letsencrypt-prod; MCP traffic is TLS-terminated at the
//!   ingress, then in-cluster Service → pod plaintext (standard
//!   K8s pattern). For end-to-end mTLS to the pod (FedRAMP track),
//!   add an Istio sidecar — FOLLOWUP.
//!
//! ## Wire format (JSON-RPC 2.0)
//!
//! Request:
//! ```text
//! { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }
//! ```
//! Response:
//! ```text
//! { "jsonrpc": "2.0", "id": 1, "result": { … } }
//! ```
//! Error:
//! ```text
//! { "jsonrpc": "2.0", "id": 1, "error": { "code": -32601, "message": "method not found" } }
//! ```
//!
//! ## Tool surface (mirrors `McpToolCatalog::canonical()`)
//!
//! - `list_validations(phase?, service?, promessa?)`
//! - `get_validation(namespace, name)`
//! - `query_findings(severity?, age_days?)`
//! - `compliance_summary()`
//! - `list_blocked()`
//! - `trigger_rescan(namespace, name)` — returns ack (controller
//!   wire-up lands in P3 per the REST face's existing note)

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::projection::ValidationProjection;
use crate::routes::mcp::McpToolCatalog;

/// JSON-RPC 2.0 request envelope.
#[derive(Deserialize, Debug)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Serialize, Debug)]
pub struct McpResponse {
    pub jsonrpc: &'static str,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
}

#[derive(Serialize, Debug)]
pub struct McpError {
    pub code: i32,
    pub message: String,
}

impl McpResponse {
    fn ok(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }

    fn err(id: Option<serde_json::Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(McpError { code, message: message.into() }),
        }
    }
}

/// Constant-time-ish string compare. Stdlib-only — avoid an extra
/// `subtle` dep. Returns true only when both strings are equal in
/// length and content; iteration is constant-time over the longer
/// length so we don't leak length info via timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    let n = aa.len().max(bb.len());
    let mut acc: u8 = (aa.len() ^ bb.len()) as u8;
    for i in 0..n {
        let x = *aa.get(i).unwrap_or(&0);
        let y = *bb.get(i).unwrap_or(&0);
        acc |= x ^ y;
    }
    acc == 0
}

/// Authorization config — read from env once at startup; tests
/// construct directly without touching process-global env.
pub struct AuthConfig {
    pub expected_token: Option<String>,
    pub allow_anonymous: bool,
}

impl AuthConfig {
    /// Resolve from env. Called once when the router boots.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            expected_token: std::env::var("MCP_BEARER_TOKEN").ok(),
            allow_anonymous: std::env::var("MCP_ALLOW_ANONYMOUS").ok().is_some(),
        }
    }
}

/// Authorization check. Returns `Ok(())` if authorized, else `Err`
/// with the response shape to return.
fn authorize(
    headers: &axum::http::HeaderMap,
    cfg: &AuthConfig,
) -> Result<(), McpResponse> {
    match (cfg.expected_token.as_deref(), cfg.allow_anonymous) {
        (Some(tok), _) => {
            let Some(auth) = headers.get("authorization") else {
                tracing::warn!("mcp.unauthorized — Authorization header missing");
                return Err(McpResponse::err(None, -32001, "missing bearer token"));
            };
            let Ok(auth) = auth.to_str() else {
                return Err(McpResponse::err(None, -32001, "invalid authorization header encoding"));
            };
            let Some(given) = auth.strip_prefix("Bearer ") else {
                return Err(McpResponse::err(
                    None,
                    -32001,
                    "Authorization scheme must be Bearer",
                ));
            };
            if !ct_eq(given, tok) {
                tracing::warn!("mcp.unauthorized — bearer token mismatch");
                return Err(McpResponse::err(None, -32001, "bearer token mismatch"));
            }
            Ok(())
        }
        (None, true) => {
            tracing::warn!(
                "mcp.anonymous — MCP_BEARER_TOKEN unset but MCP_ALLOW_ANONYMOUS=1; \
                 do NOT run this way in pleme-dev let alone prod"
            );
            Ok(())
        }
        (None, false) => {
            tracing::error!(
                "mcp.unconfigured — MCP_BEARER_TOKEN env unset; refusing all calls. \
                 Set the env on the validation-api Deployment from a SOPS-encrypted Secret, \
                 or set MCP_ALLOW_ANONYMOUS=1 if dev."
            );
            Err(McpResponse::err(
                None,
                -32001,
                "MCP endpoint not configured (MCP_BEARER_TOKEN env unset on validation-api pod)",
            ))
        }
    }
}

/// `POST /v1/mcp` — the single endpoint. Dispatches by `method`.
pub async fn handler(
    State(p): State<Arc<ValidationProjection>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<McpRequest>,
) -> impl IntoResponse {
    // Resolve auth config from env on every request — cheap, env
    // changes after rollout are picked up without a restart.
    let cfg = AuthConfig::from_env();
    if let Err(unauth) = authorize(&headers, &cfg) {
        return (StatusCode::UNAUTHORIZED, Json(unauth)).into_response();
    }
    if req.jsonrpc != "2.0" {
        return (
            StatusCode::OK,
            Json(McpResponse::err(req.id, -32600, "jsonrpc must be 2.0")),
        )
            .into_response();
    }

    let id = req.id.clone();
    let response = match req.method.as_str() {
        "initialize" => initialize_response(id),
        "tools/list" => tools_list_response(id),
        "tools/call" => tools_call_response(id, &req.params, &p).await,
        _ => McpResponse::err(id, -32601, format!("method not found: {}", req.method)),
    };
    (StatusCode::OK, Json(response)).into_response()
}

fn initialize_response(id: Option<serde_json::Value>) -> McpResponse {
    McpResponse::ok(
        id,
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "akeyless-validation-api",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": {
                "tools": { "listChanged": false }
            }
        }),
    )
}

fn tools_list_response(id: Option<serde_json::Value>) -> McpResponse {
    let catalog = McpToolCatalog::canonical();
    // Reshape into MCP `tools/list` format. Each tool needs
    // `inputSchema` (JSON-schema-like) so MCP clients can validate
    // call args before invocation.
    let tools: Vec<serde_json::Value> = catalog
        .tools
        .iter()
        .map(|t| {
            let properties: serde_json::Map<String, serde_json::Value> = t
                .input
                .iter()
                .map(|p| {
                    (
                        p.name.clone(),
                        serde_json::json!({
                            "type": match p.ty {
                                crate::routes::mcp::ParamType::Int => "integer",
                                crate::routes::mcp::ParamType::Bool => "boolean",
                                _ => "string",
                            },
                            "description": p.description,
                        }),
                    )
                })
                .collect();
            let required: Vec<&String> =
                t.input.iter().filter(|p| p.required).map(|p| &p.name).collect();
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                }
            })
        })
        .collect();
    McpResponse::ok(id, serde_json::json!({ "tools": tools }))
}

async fn tools_call_response(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    p: &Arc<ValidationProjection>,
) -> McpResponse {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));
    match name {
        "list_validations" => execute_list_validations(id, &args, p).await,
        "get_validation" => execute_get_validation(id, &args, p).await,
        "query_findings" => execute_query_findings(id, &args, p).await,
        "compliance_summary" => execute_compliance_summary(id, p).await,
        "list_blocked" => execute_list_blocked(id, p).await,
        "trigger_rescan" => execute_trigger_rescan(id, &args).await,
        other => McpResponse::err(id, -32602, format!("unknown tool: {other}")),
    }
}

async fn execute_list_validations(
    id: Option<serde_json::Value>,
    args: &serde_json::Value,
    p: &Arc<ValidationProjection>,
) -> McpResponse {
    let phase = args.get("phase").and_then(|v| v.as_str());
    let service = args.get("service").and_then(|v| v.as_str());
    let promessa = args.get("promessa").and_then(|v| v.as_str());
    let snap = p.snapshot().await;
    let items: Vec<_> = snap
        .validations
        .into_iter()
        .filter(|v| {
            phase.is_none_or(|ph| {
                v.status
                    .as_ref()
                    .and_then(|s| s.phase)
                    .map(|x| format!("{x:?}").eq_ignore_ascii_case(ph))
                    .unwrap_or(false)
            })
        })
        .filter(|v| service.is_none_or(|s| v.spec.service == s))
        .filter(|v| promessa.is_none_or(|pr| v.spec.promessa_ref == pr))
        .collect();
    let n = items.len();
    McpResponse::ok(
        id,
        wrap_text_result(&format!("Returned {n} AkeylessImageValidation(s)."), serde_json::json!(items)),
    )
}

async fn execute_get_validation(
    id: Option<serde_json::Value>,
    args: &serde_json::Value,
    p: &Arc<ValidationProjection>,
) -> McpResponse {
    let Some(ns) = args.get("namespace").and_then(|v| v.as_str()) else {
        return McpResponse::err(id, -32602, "missing required arg: namespace");
    };
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return McpResponse::err(id, -32602, "missing required arg: name");
    };
    match p.get_validation(ns, name).await {
        Some(v) => {
            let summary = format!(
                "{ns}/{name}: phase={:?}",
                v.status.as_ref().and_then(|s| s.phase)
            );
            McpResponse::ok(id, wrap_text_result(&summary, serde_json::json!(v)))
        }
        None => McpResponse::err(id, -32004, format!("not found: {ns}/{name}")),
    }
}

async fn execute_query_findings(
    id: Option<serde_json::Value>,
    args: &serde_json::Value,
    p: &Arc<ValidationProjection>,
) -> McpResponse {
    let severity = args
        .get("severity")
        .and_then(|v| v.as_str())
        .map(str::to_ascii_lowercase);
    let snap = p.snapshot().await;
    let all_findings: Vec<_> = snap
        .scan_jobs
        .iter()
        .flat_map(|j| {
            j.status
                .as_ref()
                .map(|s| s.findings.clone())
                .unwrap_or_default()
        })
        .filter(|f| {
            severity.as_deref().is_none_or(|sev| {
                format!("{:?}", f.severity).to_ascii_lowercase() == sev
            })
        })
        .collect();
    let n = all_findings.len();
    let msg = match severity.as_deref() {
        Some(sev) => format!("Returned {n} {sev}-severity finding(s)."),
        None => format!("Returned {n} finding(s) across all severities."),
    };
    McpResponse::ok(id, wrap_text_result(&msg, serde_json::json!(all_findings)))
}

async fn execute_compliance_summary(
    id: Option<serde_json::Value>,
    p: &Arc<ValidationProjection>,
) -> McpResponse {
    use std::collections::BTreeMap;
    let snap = p.snapshot().await;
    let mut by_phase: BTreeMap<String, u32> = BTreeMap::new();
    let mut by_verdict: BTreeMap<String, u32> = BTreeMap::new();
    for v in &snap.validations {
        let phase = v
            .status
            .as_ref()
            .and_then(|s| s.phase)
            .map(|p| format!("{p:?}"))
            .unwrap_or_else(|| "Unknown".into());
        *by_phase.entry(phase).or_default() += 1;
        if let Some(gd) = v.status.as_ref().and_then(|s| s.gate_decision.as_ref()) {
            *by_verdict.entry(format!("{:?}", gd.verdict)).or_default() += 1;
        }
    }
    let total = snap.validations.len();
    let msg = format!(
        "Compliance summary: {total} validation(s), by_phase={by_phase:?}, by_verdict={by_verdict:?}"
    );
    McpResponse::ok(
        id,
        wrap_text_result(
            &msg,
            serde_json::json!({
                "total_validations": total,
                "by_phase": by_phase,
                "by_verdict": by_verdict,
            }),
        ),
    )
}

async fn execute_list_blocked(
    id: Option<serde_json::Value>,
    p: &Arc<ValidationProjection>,
) -> McpResponse {
    use validation_crds::GateVerdict;
    let snap = p.snapshot().await;
    let blocked: Vec<_> = snap
        .validations
        .into_iter()
        .filter(|v| {
            matches!(
                v.status.as_ref().and_then(|s| s.gate_decision.as_ref()).map(|g| &g.verdict),
                Some(GateVerdict::Failed | GateVerdict::Quarantined)
            )
        })
        .collect();
    let n = blocked.len();
    McpResponse::ok(
        id,
        wrap_text_result(
            &format!("Returned {n} blocked validation(s) (Failed/Quarantined)."),
            serde_json::json!(blocked),
        ),
    )
}

async fn execute_trigger_rescan(
    id: Option<serde_json::Value>,
    args: &serde_json::Value,
) -> McpResponse {
    let Some(ns) = args.get("namespace").and_then(|v| v.as_str()) else {
        return McpResponse::err(id, -32602, "missing required arg: namespace");
    };
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return McpResponse::err(id, -32602, "missing required arg: name");
    };
    McpResponse::ok(
        id,
        wrap_text_result(
            &format!("Rescan request acknowledged for {ns}/{name}."),
            serde_json::json!({
                "acknowledged": true,
                "namespace": ns,
                "name": name,
                "ts": chrono::Utc::now(),
            }),
        ),
    )
}

/// MCP `tools/call` results are typed: an array of content blocks
/// where the first block is the human-readable summary and the
/// second carries the JSON structured data. Wrapping centralizes
/// that shape so every tool handler stays consistent.
fn wrap_text_result(summary: &str, data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "content": [
            { "type": "text", "text": summary },
            { "type": "text", "text": serde_json::to_string_pretty(&data).unwrap_or_default() },
        ],
        "isError": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq("hello", "hello"));
        assert!(!ct_eq("hello", "world"));
        assert!(!ct_eq("hello", "hello!"));
        assert!(!ct_eq("", "x"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn jsonrpc_envelope_ok() {
        let r = McpResponse::ok(Some(serde_json::json!(7)), serde_json::json!({"ok": true}));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["ok"], true);
        assert!(v.get("error").is_none());
    }

    #[test]
    fn jsonrpc_envelope_err() {
        let r = McpResponse::err(None, -32601, "method not found");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["error"]["code"], -32601);
        assert_eq!(v["error"]["message"], "method not found");
        assert!(v.get("result").is_none());
    }

    #[test]
    fn initialize_returns_server_info() {
        let r = initialize_response(Some(serde_json::json!(1)));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["result"]["serverInfo"]["name"], "akeyless-validation-api");
        assert_eq!(v["result"]["protocolVersion"], "2024-11-05");
    }

    #[test]
    fn tools_list_emits_every_catalog_tool_with_input_schema() {
        let r = tools_list_response(Some(serde_json::json!(2)));
        let v = serde_json::to_value(&r).unwrap();
        let tools = v["result"]["tools"].as_array().unwrap();
        let names: Vec<_> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        for expected in [
            "list_validations",
            "get_validation",
            "query_findings",
            "trigger_rescan",
            "compliance_summary",
            "list_blocked",
        ] {
            assert!(names.contains(&expected), "missing tool: {expected}");
        }
        // inputSchema is shaped as JSON-Schema-ish
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object");
            assert!(t["inputSchema"]["properties"].is_object());
            assert!(t["inputSchema"]["required"].is_array());
        }
    }

    /// Authorization paths — tested via `AuthConfig` constructed
    /// directly, NOT via process-global env mutation (env mutation
    /// is `unsafe` in Rust 2024 + race-prone across parallel tests).

    #[test]
    fn authorize_rejects_no_token_no_anon() {
        let cfg = AuthConfig { expected_token: None, allow_anonymous: false };
        let h = axum::http::HeaderMap::new();
        let err = authorize(&h, &cfg).unwrap_err();
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v["error"]["code"], -32001);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("MCP endpoint not configured"));
    }

    #[test]
    fn authorize_accepts_anon_when_flag_set() {
        let cfg = AuthConfig { expected_token: None, allow_anonymous: true };
        let h = axum::http::HeaderMap::new();
        assert!(authorize(&h, &cfg).is_ok());
    }

    #[test]
    fn authorize_rejects_missing_bearer_when_token_set() {
        let cfg = AuthConfig {
            expected_token: Some("secret".into()),
            allow_anonymous: false,
        };
        let h = axum::http::HeaderMap::new();
        let err = authorize(&h, &cfg).unwrap_err();
        let v = serde_json::to_value(&err).unwrap();
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("missing bearer token"));
    }

    #[test]
    fn authorize_rejects_wrong_bearer() {
        let cfg = AuthConfig {
            expected_token: Some("secret".into()),
            allow_anonymous: false,
        };
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", "Bearer wrong".parse().unwrap());
        let err = authorize(&h, &cfg).unwrap_err();
        let v = serde_json::to_value(&err).unwrap();
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("mismatch"));
    }

    #[test]
    fn authorize_accepts_matching_bearer() {
        let cfg = AuthConfig {
            expected_token: Some("secret".into()),
            allow_anonymous: false,
        };
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", "Bearer secret".parse().unwrap());
        assert!(authorize(&h, &cfg).is_ok());
    }

    #[test]
    fn authorize_rejects_non_bearer_scheme() {
        let cfg = AuthConfig {
            expected_token: Some("secret".into()),
            allow_anonymous: false,
        };
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", "Basic dXNlcjpzZWNyZXQ=".parse().unwrap());
        let err = authorize(&h, &cfg).unwrap_err();
        let v = serde_json::to_value(&err).unwrap();
        assert!(v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Bearer"));
    }
}
