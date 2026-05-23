//! `engenho-promessa` — controller binary. Boots tracing, builds a
//! kube::Client, hands off to `validation_controllers::run_all` which
//! spawns the four reconcilers concurrently.

use clap::Parser;
use kube::Client;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Restrict watches to a single namespace. Defaults to all.
    #[arg(long, env = "VALIDATION_NAMESPACE")]
    namespace: Option<String>,
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
    let client = Client::try_default().await?;
    tracing::info!(
        namespace = ?args.namespace,
        "engenho-promessa — booting validation-controllers (5 reconcilers)"
    );
    validation_controllers::run_all(client, args.namespace).await
}
