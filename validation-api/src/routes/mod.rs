//! HTTP routing tree. Composes REST + GraphQL + WebSocket + metrics
//! under a single axum router. MCP runs as its own subcommand (stdio).

pub mod graphql;
pub mod mcp;
pub mod rest;
pub mod ws;

use std::sync::Arc;

use async_graphql_axum::{GraphQL, GraphQLSubscription};
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::projection::ValidationProjection;

pub fn router(projection: Arc<ValidationProjection>) -> Router {
    let gql_schema = graphql::build_schema(projection.clone());

    Router::new()
        // ── REST ───────────────────────────────────────────────────
        .route("/v1/validations", get(rest::list_validations))
        .route("/v1/validations/:ns/:name", get(rest::get_validation))
        .route("/v1/validations/:ns/:name/findings", get(rest::get_findings))
        .route("/v1/validations/:ns/:name/evidence", get(rest::get_evidence))
        .route("/v1/validations/:ns/:name/gate", get(rest::get_gate))
        .route("/v1/validations/:ns/:name/outcome-chain", get(rest::get_outcome_chain))
        .route("/v1/validations/:ns/:name/rescan", post(rest::rescan))
        .route("/v1/ephemeral-tenants", get(rest::list_tenants))
        .route("/v1/ephemeral-tenants/:ns/:name", get(rest::get_tenant))
        .route("/v1/scan-jobs", get(rest::list_scan_jobs))
        .route("/v1/scan-jobs/:ns/:name", get(rest::get_scan_job))
        .route("/v1/compliance-summary", get(rest::compliance_summary))
        .route("/v1/compliance-summary/by-service", get(rest::compliance_by_service))
        .route("/v1/healthz", get(rest::healthz))
        .route("/v1/readyz", get(rest::readyz))
        .route("/v1/metrics", get(rest::metrics))
        // ── GraphQL ────────────────────────────────────────────────
        // GraphQL implements Service, not Handler — use route_service.
        .route_service("/graphql", GraphQL::new(gql_schema.clone()))
        .route_service("/graphql/subscription", GraphQLSubscription::new(gql_schema))
        // ── WebSocket ──────────────────────────────────────────────
        .route("/v1/watch", get(ws::watch))
        // ── Static ────────────────────────────────────────────────
        .route("/v1/openapi.json", get(rest::openapi_route))
        // ── State ─────────────────────────────────────────────────
        .with_state(projection)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
