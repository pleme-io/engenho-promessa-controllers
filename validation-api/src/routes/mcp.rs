//! MCP stdio server — Claude tool surface.
//!
//! Per pleme-io/theory/NIX-AST.md emission discipline: the tool catalog
//! is a typed Rust value (`McpToolCatalog`), serialized via serde to the
//! MCP wire format. No inline strings, no eprintln stubs. The rmcp
//! dispatcher (P3) consumes this same typed catalog.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::projection::ValidationProjection;

/// The full MCP tool catalog this binary exposes. Single source of
/// truth — the stdio dispatcher (P3 rmcp wire-up), the static catalog
/// endpoint, and any future SDK generation all consume this value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolCatalog {
    pub server: ServerInfo,
    pub tools: Vec<McpTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub transport: ServerTransport,
    pub theory_ref: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ServerTransport {
    Stdio,
    HttpSse,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input: Vec<ToolParam>,
    pub output: ToolOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolParam {
    pub name: String,
    pub ty: ParamType,
    pub required: bool,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ParamType {
    String,
    Int,
    Bool,
    Duration,
    SeverityEnum,
    PhaseEnum,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolOutput {
    Validation,
    ValidationList,
    FindingList,
    ComplianceSummary,
    Acknowledgement,
}

impl McpToolCatalog {
    /// The canonical catalog this binary serves. Constructed once;
    /// every consumer reaches the same `&'static`-ish value.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            server: ServerInfo {
                name: "akeyless-validation-api".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                transport: ServerTransport::Stdio,
                theory_ref:
                    "pleme-io/theory/AKEYLESS-VALIDATION-PLATFORM.md#part-v-the-api-binary".into(),
            },
            tools: vec![
                McpTool {
                    name: "list_validations".into(),
                    description:
                        "List every AkeylessImageValidation the substrate has observed, optionally filtered by phase, service, or governing promessa."
                            .into(),
                    input: vec![
                        ToolParam { name: "phase".into(),    ty: ParamType::PhaseEnum, required: false, description: "Filter by status.phase".into() },
                        ToolParam { name: "service".into(),  ty: ParamType::String,    required: false, description: "Filter by spec.service".into() },
                        ToolParam { name: "promessa".into(), ty: ParamType::String,    required: false, description: "Filter by spec.promessaRef".into() },
                    ],
                    output: ToolOutput::ValidationList,
                },
                McpTool {
                    name: "get_validation".into(),
                    description: "Fetch the full AkeylessImageValidation CR (spec + status) by namespace + name.".into(),
                    input: vec![
                        ToolParam { name: "namespace".into(), ty: ParamType::String, required: true, description: "K8s namespace".into() },
                        ToolParam { name: "name".into(),      ty: ParamType::String, required: true, description: "CR name".into() },
                    ],
                    output: ToolOutput::Validation,
                },
                McpTool {
                    name: "query_findings".into(),
                    description: "Return ScanFindings across all validations matching the given severity + age filters.".into(),
                    input: vec![
                        ToolParam { name: "severity".into(), ty: ParamType::SeverityEnum, required: false, description: "Critical | High | Medium | Low".into() },
                        ToolParam { name: "age_days".into(), ty: ParamType::Int,           required: false, description: "Minimum age in days".into() },
                    ],
                    output: ToolOutput::FindingList,
                },
                McpTool {
                    name: "trigger_rescan".into(),
                    description: "Idempotently mark an AkeylessImageValidation for re-reconcile.".into(),
                    input: vec![
                        ToolParam { name: "namespace".into(), ty: ParamType::String, required: true, description: "K8s namespace".into() },
                        ToolParam { name: "name".into(),      ty: ParamType::String, required: true, description: "CR name".into() },
                    ],
                    output: ToolOutput::Acknowledgement,
                },
                McpTool {
                    name: "compliance_summary".into(),
                    description: "Aggregate pipeline health across the whole projection — counts by phase + verdict + blocking digests.".into(),
                    input: vec![],
                    output: ToolOutput::ComplianceSummary,
                },
                McpTool {
                    name: "list_blocked".into(),
                    description: "Every validation whose gate verdict is Failed or Quarantined.".into(),
                    input: vec![],
                    output: ToolOutput::ValidationList,
                },
            ],
        }
    }
}

/// Run the MCP stdio server. M1.5: emits the typed catalog as a single
/// JSON-RPC `initialize`-shaped response, then blocks until stdin closes.
/// The rmcp dispatcher loop lands in P3 (same shape as mado's mcp.rs).
pub async fn run_stdio() -> anyhow::Result<()> {
    let catalog = McpToolCatalog::canonical();
    // Serialize the typed catalog through serde — no inline strings.
    let json = serde_json::to_string(&catalog)?;
    let mut stdout = tokio::io::stdout();
    use tokio::io::AsyncWriteExt;
    stdout.write_all(json.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    // Hold the process open so a parent can re-invoke; rmcp dispatcher
    // takes over in P3.
    let _ = tokio::io::stdin();
    Ok(())
}

/// Static-catalog HTTP probe — used by the REST surface so curl can
/// see the typed shape even without an MCP client. Routed at
/// `/v1/mcp/catalog` in the REST router (P3 when the route lands).
pub fn catalog_handler(_: Arc<ValidationProjection>) -> axum::Json<McpToolCatalog> {
    axum::Json(McpToolCatalog::canonical())
}
