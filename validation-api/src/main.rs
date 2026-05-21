//! `akeyless-validation-api` — single Rust binary serving the typed
//! projection of the three AKEYLESS-VALIDATION-PLATFORM CRDs over
//! REST + GraphQL + WebSocket (+ MCP via the `mcp` subcommand).
//!
//! Architecture:
//!
//! ```text
//!   kube-rs informers → Arc<RwLock<Projection>> → transports
//! ```
//!
//! Determinism guarantee: every API response is derivable from the
//! current CR set. The informer is the only path that mutates the
//! projection; transports are read-only.

mod projection;
mod routes;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use projection::ValidationProjection;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "validation-api", about = "AKEYLESS-VALIDATION-PLATFORM API")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the HTTP server (REST + GraphQL + WebSocket + metrics).
    /// Default subcommand when none specified.
    Serve(ServeArgs),
    /// Run as an MCP stdio server. Pipes tool requests over stdin/stdout.
    Mcp,
    /// Print all REST routes as OpenAPI 3 JSON to stdout.
    OpenApi,
    /// Print the GraphQL SDL to stdout.
    GraphqlSdl,
}

#[derive(Parser, Debug)]
struct ServeArgs {
    /// HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:8080", env = "VALIDATION_API_ADDR")]
    addr: SocketAddr,

    /// Skip starting kube-rs informers — serve a static empty projection.
    /// Useful for local smoke tests + the M1.5 placeholder mode.
    #[arg(long, env = "VALIDATION_API_OFFLINE")]
    offline: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Serve(ServeArgs {
        addr: "0.0.0.0:8080".parse().unwrap(),
        offline: false,
    })) {
        Cmd::Serve(args) => serve(args).await,
        Cmd::Mcp => routes::mcp::run_stdio().await,
        Cmd::OpenApi => {
            println!("{}", routes::rest::openapi_json()?);
            Ok(())
        }
        Cmd::GraphqlSdl => {
            println!("{}", routes::graphql::sdl());
            Ok(())
        }
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let projection = Arc::new(ValidationProjection::new());
    info!(addr = %args.addr, offline = args.offline, "validation-api starting");

    if !args.offline {
        projection.clone().spawn_informers().await?;
    } else {
        info!("offline mode — informers not started; projection stays empty");
    }

    let app = routes::router(projection.clone());
    let listener = tokio::net::TcpListener::bind(args.addr).await?;
    info!(addr = %args.addr, "validation-api ready");
    axum::serve(listener, app).await?;
    Ok(())
}
