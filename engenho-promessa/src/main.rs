//! `engenho-promessa` — controller binary. Boots tracing, builds a
//! kube::Client, hands off to `validation_controllers::run_all` which
//! spawns the four reconcilers concurrently.

use std::sync::Arc;

use clap::Parser;
use kube::Client;
use validation_store::{ensure_all_tables, ValidationStore};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Restrict watches to a single namespace. Defaults to all.
    #[arg(long, env = "VALIDATION_NAMESPACE")]
    namespace: Option<String>,

    /// SeaORM database URL for the validation-store. Default points
    /// at a SQLite file in the StatefulSet's persistent volume.
    /// Override with `postgres://...` for shared-replica deployments.
    #[arg(
        long,
        env = "VALIDATION_DB_URL",
        default_value = "sqlite:///var/lib/validation-store/validation.db?mode=rwc"
    )]
    db_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,validation_controllers=debug".into()),
        )
        .init();

    let args = Args::parse();

    tracing::info!(db_url = %args.db_url, "engenho-promessa — opening validation-store");
    let validation_store = Arc::new(ValidationStore::connect_async(&args.db_url).await?);
    ensure_all_tables(validation_store.db()).await?;
    tracing::info!("validation-store schema ensured (idempotent)");

    let client = Client::try_default().await?;
    tracing::info!(
        namespace = ?args.namespace,
        "engenho-promessa — booting validation-controllers (5 reconcilers)"
    );
    validation_controllers::run_all(client, args.namespace, validation_store).await
}
