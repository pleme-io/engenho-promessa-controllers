//! `validation-api mcp-proxy` — stdio → HTTP bridge.
//!
//! Claude Code (and most MCP clients) speak stdio JSON-RPC. The
//! validation-api ships an HTTP MCP endpoint at `POST /v1/mcp`. This
//! subcommand bridges the two: reads JSON-RPC requests from stdin
//! (one per line), POSTs each to the configured endpoint with a
//! bearer token, writes responses to stdout.
//!
//! ## Why bridge in-binary (not a separate proxy tool)
//!
//! The same binary already ships the typed MCP catalog + HTTP
//! dispatcher. Adding stdio→HTTP keeps everything in one
//! distributable: operators install ONE `validation-api` binary and
//! get both server-side (`validation-api serve`) and client-side
//! (`validation-api mcp-proxy`) capability.
//!
//! ## blackmatter-anvil wiring
//!
//! Drop into `anvil.mcp.servers` like any other stdio MCP server:
//!
//! ```nix
//! anvil.mcp.servers.akeyless-validation = {
//!   description = "Akeyless validation pipeline compliance state";
//!   command     = "validation-api";
//!   args        = [
//!     "mcp-proxy"
//!     "--endpoint" "https://validation-api.dev.use1.quero.lol/v1/mcp"
//!   ];
//!   envFiles.MCP_BEARER_TOKEN = "/run/secrets/akeyless-mcp-bearer";
//! };
//! anvil.agents.claude-akeyless.scope = "akeyless";
//! ```
//!
//! Then `claude-akeyless` (the org-scoped Claude Code wrapper)
//! auto-includes the MCP server. Operator runs `claude-akeyless`
//! anywhere with network access to the validation-api ingress.

use std::io::Write;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Args (parsed by clap in main.rs).
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub endpoint: String,
    /// Bearer token. Loaded via `--bearer-file <path>` (preferred —
    /// avoids token in argv/env) or `$MCP_BEARER_TOKEN` env.
    pub bearer: String,
    /// HTTP read/write timeout per request.
    pub timeout_secs: u64,
}

/// Run the stdio bridge until EOF on stdin. Each line of stdin must
/// be a JSON-RPC 2.0 request envelope; each line of stdout is the
/// matching response.
pub async fn run(cfg: ProxyConfig) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        // Some MCP gateways still self-sign; we trust whatever the
        // operator's CA bundle resolves to but accept self-signed
        // when MCP_PROXY_INSECURE_TLS=1 (dev only).
        .danger_accept_invalid_certs(std::env::var("MCP_PROXY_INSECURE_TLS").is_ok())
        .build()
        .context("build reqwest client for mcp-proxy")?;

    let auth_header = format!("Bearer {}", cfg.bearer);
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = std::io::stdout().lock();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let resp_body = forward(&client, &cfg.endpoint, &auth_header, &line).await;
        let resp_line = match resp_body {
            Ok(body) => body,
            Err(e) => {
                // Per JSON-RPC 2.0: emit a typed error envelope on
                // proxy failure so the client sees something parseable.
                make_proxy_error(&line, e.to_string())
            }
        };
        writeln!(stdout, "{resp_line}").context("write response to stdout")?;
        stdout.flush().ok();
    }
    Ok(())
}

async fn forward(
    client: &reqwest::Client,
    endpoint: &str,
    auth: &str,
    body: &str,
) -> Result<String> {
    let resp = client
        .post(endpoint)
        .header("authorization", auth)
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send()
        .await
        .context("POST to MCP endpoint")?;
    let status = resp.status();
    let text = resp.text().await.context("read response body")?;
    if !status.is_success() {
        return Err(anyhow!("MCP endpoint returned {status}: {text}"));
    }
    Ok(text)
}

/// Build a JSON-RPC error envelope keyed off the (possibly partial)
/// request's `id`. Best-effort — if we can't parse the request, emit
/// a null-id envelope so the client at least gets a parseable error.
fn make_proxy_error(req_line: &str, message: String) -> String {
    let id = serde_json::from_str::<serde_json::Value>(req_line)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32099, "message": format!("mcp-proxy: {message}") },
    })
    .to_string()
}

/// Load the bearer token. Order: --bearer-file flag, env, then error.
pub fn load_bearer(bearer_file: Option<&std::path::Path>) -> Result<String> {
    if let Some(p) = bearer_file {
        let s = std::fs::read_to_string(p)
            .with_context(|| format!("read bearer-file {}", p.display()))?;
        return Ok(s.trim().to_owned());
    }
    if let Ok(s) = std::env::var("MCP_BEARER_TOKEN") {
        return Ok(s);
    }
    Err(anyhow!(
        "no bearer token — pass --bearer-file <path> or set MCP_BEARER_TOKEN env"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_error_preserves_request_id() {
        let req = r#"{"jsonrpc":"2.0","id":42,"method":"tools/list"}"#;
        let err = make_proxy_error(req, "timeout".into());
        let v: serde_json::Value = serde_json::from_str(&err).unwrap();
        assert_eq!(v["id"], 42);
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["error"]["code"], -32099);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("mcp-proxy"));
    }

    #[test]
    fn proxy_error_handles_unparseable_request() {
        let err = make_proxy_error("not json", "bad gateway".into());
        let v: serde_json::Value = serde_json::from_str(&err).unwrap();
        assert!(v["id"].is_null());
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("bad gateway"));
    }

    #[test]
    fn proxy_error_handles_string_id() {
        let req = r#"{"jsonrpc":"2.0","id":"abc-123","method":"tools/list"}"#;
        let err = make_proxy_error(req, "timeout".into());
        let v: serde_json::Value = serde_json::from_str(&err).unwrap();
        assert_eq!(v["id"], "abc-123");
    }

    #[test]
    fn load_bearer_from_env_falls_back() {
        // We avoid setting env in tests (Rust 2024 unsafe + race).
        // The fallback behavior (no env → Err) is implicit; just
        // assert load_bearer with None returns Err when env unset.
        // If env IS set in the test runner, we tolerate either path.
        let r = load_bearer(None);
        if std::env::var("MCP_BEARER_TOKEN").is_err() {
            assert!(r.is_err(), "with no env + no file, expected Err");
        }
    }
}
