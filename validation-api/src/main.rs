//! `akeyless-validation-api` — single Rust binary serving the typed
//! projection of the three AKEYLESS-VALIDATION-PLATFORM CRDs over:
//!
//! - **REST + GraphQL + WebSocket** on `--addr` (default `:8080`)
//! - **gRPC** on `--grpc-addr` (default `:50051`) via tonic
//! - **MCP** via the `mcp` subcommand (stdio)
//!
//! Architecture:
//!
//! ```text
//!   kube-rs informers ──► Arc<RwLock<Projection>> (live)
//!                                                        ──► REST / GraphQL / WS
//!   validation-store  ──► SQLite/Postgres durable rows ──► REST / gRPC (audit)
//!   scanner-catalog   ──► static Catalog (compile-time) ──► REST / gRPC
//! ```
//!
//! Determinism guarantee: every API response is derivable from the
//! current state. Informers + the validation-store reconciler writes
//! are the only paths that mutate state; transports are read-only.

mod projection;
mod routes;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use projection::ValidationProjection;
use tracing::info;
use validation_store::{ensure_all_tables, ValidationStore};

#[derive(Parser, Debug)]
#[command(name = "validation-api", about = "AKEYLESS-VALIDATION-PLATFORM API")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the HTTP + gRPC servers concurrently.
    /// Default subcommand when none specified.
    Serve(ServeArgs),
    /// Run as an MCP stdio server. Pipes tool requests over stdin/stdout.
    Mcp,
    /// Print all REST routes as OpenAPI 3 JSON to stdout.
    OpenApi,
    /// Print the GraphQL SDL to stdout.
    GraphqlSdl,
    /// Stdio→HTTP MCP bridge for Claude Code et al. — POSTs each
    /// JSON-RPC line on stdin to a remote `/v1/mcp` endpoint and
    /// emits the response on stdout. Wire into blackmatter-anvil as
    /// `anvil.mcp.servers.akeyless-validation`.
    McpProxy(McpProxyArgs),
}

#[derive(Parser, Debug)]
struct McpProxyArgs {
    /// Remote MCP endpoint URL.
    #[arg(long, env = "MCP_PROXY_ENDPOINT")]
    endpoint: String,

    /// File containing the bearer token (one line). Preferred over
    /// $MCP_BEARER_TOKEN since the file path is in argv but the
    /// token isn't.
    #[arg(long)]
    bearer_file: Option<std::path::PathBuf>,

    /// HTTP timeout per request, seconds.
    #[arg(long, default_value = "30")]
    timeout_secs: u64,
}

#[derive(Parser, Debug)]
struct ServeArgs {
    /// HTTP listen address (REST + GraphQL + WebSocket).
    #[arg(long, default_value = "0.0.0.0:8080", env = "VALIDATION_API_ADDR")]
    addr: SocketAddr,

    /// gRPC (tonic) listen address. Set to empty string in env to
    /// disable the gRPC server.
    #[arg(long, default_value = "0.0.0.0:50051", env = "VALIDATION_API_GRPC_ADDR")]
    grpc_addr: SocketAddr,

    /// SeaORM database URL for validation-store. Default matches the
    /// chart's PVC mount.
    #[arg(
        long,
        env = "VALIDATION_DB_URL",
        default_value = "sqlite:///var/lib/validation-store/validation.db?mode=rwc"
    )]
    db_url: String,

    /// Skip starting kube-rs informers — serve a static empty projection.
    /// Useful for local smoke tests + the M1.5 placeholder mode.
    #[arg(long, env = "VALIDATION_API_OFFLINE")]
    offline: bool,

    /// Use an in-memory SQLite for the validation-store instead of
    /// opening the configured URL. Implies a fresh empty store on
    /// every boot — for tests and smoke runs.
    #[arg(long, env = "VALIDATION_API_STORE_IN_MEMORY")]
    store_in_memory: bool,
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
    match cli.cmd.unwrap_or_else(|| Cmd::Serve(ServeArgs {
        addr: "0.0.0.0:8080".parse().unwrap(),
        grpc_addr: "0.0.0.0:50051".parse().unwrap(),
        db_url: "sqlite:///var/lib/validation-store/validation.db?mode=rwc".into(),
        offline: false,
        store_in_memory: false,
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
        Cmd::McpProxy(args) => {
            let bearer = routes::mcp_proxy::load_bearer(args.bearer_file.as_deref())?;
            let cfg = routes::mcp_proxy::ProxyConfig {
                endpoint: args.endpoint,
                bearer,
                timeout_secs: args.timeout_secs,
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(routes::mcp_proxy::run(cfg))
        }
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let projection = Arc::new(ValidationProjection::new());

    // ── validation-store: open, ensure tables ──────────────────────
    let store = if args.store_in_memory {
        info!("validation-store: in-memory mode");
        Arc::new(ValidationStore::in_memory().await?)
    } else {
        info!(db_url = %args.db_url, "validation-store: opening");
        Arc::new(ValidationStore::connect_async(&args.db_url).await?)
    };
    ensure_all_tables(store.db()).await?;
    info!("validation-store: schema ensured (idempotent)");

    if !args.offline {
        projection.clone().spawn_informers().await?;
    } else {
        info!("offline mode — informers not started; projection stays empty");
    }

    // ── axum (REST + GraphQL + WS) ─────────────────────────────────
    let app = routes::router(projection.clone());
    let http_listener = tokio::net::TcpListener::bind(args.addr).await?;
    info!(addr = %args.addr, "validation-api HTTP face ready");
    let http_task = tokio::spawn(async move {
        axum::serve(http_listener, app)
            .await
            .map_err(anyhow::Error::from)
    });

    // ── tonic (gRPC) ──────────────────────────────────────────────
    let grpc_server = routes::grpc::build_server(projection.clone(), store.clone());
    info!(addr = %args.grpc_addr, "validation-api gRPC face ready");
    let grpc_addr = args.grpc_addr;
    let grpc_task = tokio::spawn(async move {
        grpc_server
            .serve(grpc_addr)
            .await
            .map_err(anyhow::Error::from)
    });

    // Whichever face exits first wins — propagate the error so K8s
    // restarts the pod (liveness probe will catch a hung face too).
    tokio::select! {
        r = http_task => {
            tracing::error!(?r, "validation-api HTTP face exited");
            r??;
        }
        r = grpc_task => {
            tracing::error!(?r, "validation-api gRPC face exited");
            r??;
        }
    }
    Ok(())
}
