//! `private-push` — typed Rust replacement for the shell scripts.
//!
//! Pushes OCI images from a local nix build to the cluster-singleton
//! Zot, bypassing Cloudflare Edge entirely; then optionally creates
//! AkeylessImageValidation CRs so every pushed digest enters the
//! validation pipeline.
//!
//! The byte path for the push subcommands:
//!
//! ```text
//!   nix build  ──► docker-archive tarball
//!                          │
//!                          ▼
//!   skopeo copy  ──► localhost:<port>  (kubectl port-forward target)
//!                          │
//!                          ▼
//!     ─────────  kubectl port-forward  ─────────
//!                          │
//!                          ▼
//!   in-cluster Zot Service ──► Zot blob store
//!                          │
//!                          ▼
//!     ─────────  cosign sign --keyless --tlog-upload=false  ──────
//! ```
//!
//! No third-party plane in the path; no public Rekor transparency
//! entry. The TLS hop is laptop → EKS/k3s control plane (same plane
//! kubectl already uses for everything else); past the apiserver,
//! traffic is in-VPC.
//!
//! ## Three flavors
//!
//! - `substrate` — pleme-io binaries (`engenho-promessa`,
//!   `validation-api`) at a given `--tag`. nix output:
//!   `.#image:<binary>`. Target path:
//!   `localhost:5000/pleme-io/<binary>:<tag>`.
//!
//! - `akeyless` — Akeyless service images (`auth`, `uam`, `kfm`,
//!   `gator`, `bis`, `logan`, `mark`, `sdr`, `gateway`). nix output:
//!   `.#dockerImage:<service>`. Target path:
//!   `localhost:5000/akeyless-<service>:<tag>` where `<tag>` is the
//!   tag the docker-archive baked in (or `--tag` if provided).
//!
//! - `submit-validations` — pure Rust; no kubectl/curl subprocess.
//!   Talks to Zot's v2 OCI API via reqwest, applies typed
//!   AkeylessImageValidation CRs via kube-rs Api::patch with the
//!   Apply patch-type (idempotent). Every Akeyless image in Zot is
//!   subjected to the validation pipeline.

mod oci;
mod orchestrator;
mod submit;
mod subprocess;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "private-push",
    about = "Laptop → in-cluster Zot push + AkeylessImageValidation submission"
)]
struct Cli {
    /// Override kubectl context. Default is your current context.
    #[arg(long, env = "PRIVATE_PUSH_KUBE_CONTEXT", global = true)]
    kube_context: Option<String>,

    /// Namespace hosting the Zot Service.
    #[arg(long, env = "PRIVATE_PUSH_K8S_NS", default_value = "zot-system", global = true)]
    namespace: String,

    /// Zot Service name.
    #[arg(long, env = "PRIVATE_PUSH_SVC", default_value = "zot", global = true)]
    service: String,

    /// Local port for the port-forward.
    #[arg(long, env = "PRIVATE_PUSH_PORT", default_value = "5000", global = true)]
    port: u16,

    /// Path to the SOPS-encrypted zot-push-token YAML.
    #[arg(
        long,
        env = "PRIVATE_PUSH_TOKEN_PATH",
        default_value = "~/code/github/pleme-io/k8s/clusters/pleme-dev/infrastructure/zot-stack/zot/zot-push-token.sops.yaml",
        global = true,
    )]
    token_path: PathBuf,

    /// Skip cosign signing — useful when iterating; production push
    /// should always sign. Only applies to substrate/akeyless.
    #[arg(long, env = "PRIVATE_PUSH_NO_COSIGN", global = true)]
    no_cosign: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Push pleme-io substrate binaries by tag.
    Substrate(SubstrateArgs),
    /// Push Akeyless service images. Tag is auto-discovered from the
    /// nix-built docker-archive unless `--tag` is given.
    Akeyless(AkeylessArgs),
    /// Submit AkeylessImageValidation CRs for every `akeyless-<svc>`
    /// image found in Zot — kicks off the validation loop for each
    /// pushed digest. Pure Rust: kube-rs Api::patch with Apply
    /// patch-type (idempotent), reqwest for the Zot v2 OCI API
    /// digest discovery. No kubectl/curl subprocess.
    SubmitValidations(SubmitArgs),
}

#[derive(Parser, Debug)]
struct SubstrateArgs {
    /// Tag to push under — matches the chart's image.tag.
    #[arg(long)]
    tag: String,

    /// nix-flake directory containing `image:<binary>` outputs.
    #[arg(long, default_value = ".")]
    source_flake: PathBuf,

    /// Binaries to push. Default: engenho-promessa + validation-api.
    binaries: Vec<String>,
}

#[derive(Parser, Debug)]
struct AkeylessArgs {
    /// Override tag instead of using the docker-archive's baked tag.
    #[arg(long)]
    tag: Option<String>,

    /// nix-flake directory containing `dockerImage:<service>` outputs.
    #[arg(long, default_value = ".")]
    source_flake: PathBuf,

    /// Services to push. Default: all 9 (auth, uam, kfm, gator, bis,
    /// logan, mark, sdr, gateway).
    services: Vec<String>,
}

#[derive(Parser, Debug)]
struct SubmitArgs {
    /// Zot endpoint as seen from this process — typically
    /// `localhost:5000` (after `kubectl port-forward`) or
    /// `zot.zot-system.svc.cluster.local:5000` (in-cluster run).
    #[arg(long, env = "PRIVATE_PUSH_ZOT_ENDPOINT", default_value = "localhost:5000")]
    zot_endpoint: String,

    /// Namespace for the AkeylessImageValidation CRs.
    #[arg(
        long,
        env = "PRIVATE_PUSH_VALIDATION_NS",
        default_value = "akeyless-validation"
    )]
    cr_namespace: String,

    /// Promessa to reference on every emitted CR.
    #[arg(
        long,
        env = "PRIVATE_PUSH_PROMESSA_REF",
        default_value = "akeyless-nix-images-fedramp-scr"
    )]
    promessa_ref: String,

    /// Compliance pack to reference on every emitted CR.
    #[arg(
        long,
        env = "PRIVATE_PUSH_PACK",
        default_value = "fedramp-high-akeyless-go-image@1"
    )]
    pack: String,

    /// Print would-be CRs without applying.
    #[arg(long)]
    dry_run: bool,

    /// Only submit for these services; empty = every `akeyless-*`
    /// repo in Zot's catalog.
    services: Vec<String>,
}

const SUBSTRATE_DEFAULTS: &[&str] = &["engenho-promessa", "validation-api"];
const AKEYLESS_DEFAULTS: &[&str] = &[
    "auth", "uam", "kfm", "gator", "bis", "logan", "mark", "sdr", "gateway",
];

/// Expand a leading `~/` against `$HOME`. Stdlib-only; we avoid a
/// `shellexpand` dep so the build stays narrow.
fn expand_tilde(p: &PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    p.clone()
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,private_push=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    // submit-validations is async (kube-rs + reqwest). Spin a tokio
    // runtime only for that subcommand — substrate/akeyless are
    // pure-sync and pay no tokio cost.
    if let Cmd::SubmitValidations(args) = &cli.cmd {
        let basic_auth = std::env::var("PRIVATE_PUSH_BASIC_AUTH")
            .ok()
            .and_then(|s| s.split_once(':').map(|(u, p)| (u.to_owned(), p.to_owned())));
        let submit_args = submit::SubmitArgs {
            zot_endpoint: args.zot_endpoint.clone(),
            namespace: args.cr_namespace.clone(),
            promessa_ref: args.promessa_ref.clone(),
            pack: args.pack.clone(),
            services: args.services.clone(),
            basic_auth,
            dry_run: args.dry_run,
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("build tokio runtime: {e}"))?;
        return rt.block_on(submit::run(submit_args));
    }

    let common = orchestrator::Common {
        kube_context: cli.kube_context,
        namespace: cli.namespace,
        service: cli.service,
        port: cli.port,
        token_path: expand_tilde(&cli.token_path),
        cosign: !cli.no_cosign,
    };

    match cli.cmd {
        Cmd::Substrate(args) => {
            let binaries = if args.binaries.is_empty() {
                SUBSTRATE_DEFAULTS.iter().map(|s| (*s).to_owned()).collect()
            } else {
                args.binaries
            };
            orchestrator::run_substrate(
                &common,
                &args.source_flake,
                &args.tag,
                &binaries,
            )
        }
        Cmd::Akeyless(args) => {
            let services = if args.services.is_empty() {
                AKEYLESS_DEFAULTS.iter().map(|s| (*s).to_owned()).collect()
            } else {
                args.services
            };
            orchestrator::run_akeyless(
                &common,
                &args.source_flake,
                args.tag.as_deref(),
                &services,
            )
        }
        Cmd::SubmitValidations(_) => unreachable!("handled above before orchestrator::Common"),
    }
}
