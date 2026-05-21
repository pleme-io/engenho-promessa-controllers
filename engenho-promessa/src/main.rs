//! `engenho-promessa` — controller-binary that registers each
//! per-kind TargetController with engenho's kube-rs informer.
//!
//! Status: M1 skeleton. Registers SecurityController only; future
//! kinds (SLA / CostBudget / Compliance / CustomerKpi) plug in via
//! the same registration shape.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!(
        "engenho-promessa M1 — SecurityController registered (skeleton); \
         kube-rs informer wire-up pending M1.5"
    );
    Ok(())
}
