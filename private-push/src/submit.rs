//! `submit-validations` subcommand — pure Rust, no kubectl
//! subprocess. After `private-push akeyless` lands all 9 service
//! images in Zot, this subcommand:
//!
//! 1. Talks directly to the in-cluster Zot's v2 OCI API via the
//!    same `localhost:<port>` you'd skopeo-copy to (operator runs
//!    a port-forward separately, or pipes through `kubectl exec`
//!    against the controller pod).
//! 2. For each `akeyless-<service>` repo, enumerates tags and
//!    resolves the latest manifest digest (HEAD …/manifests/<tag>
//!    → `Docker-Content-Digest` header).
//! 3. Constructs a typed [`validation_crds::AkeylessImageValidation`]
//!    CR per digest.
//! 4. Applies via kube-rs `Api::patch` with `PatchParams::apply` —
//!    idempotent re-runs no-op.
//!
//! The result: every Akeyless image in Zot is subject to the
//! validation pipeline. No shell anywhere in the path.

use anyhow::{anyhow, Context, Result};
use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use serde::Deserialize;
use validation_crds::{AkeylessImageValidation, AkeylessImageValidationSpec};

const FIELD_MANAGER: &str = "private-push.submit-validations";

#[derive(Debug, Clone)]
pub struct SubmitArgs {
    /// Pull-time Zot endpoint as seen from this process — typically
    /// `localhost:5000` (after a port-forward) or
    /// `zot.zot-system.svc.cluster.local:5000` (when running
    /// in-cluster).
    pub zot_endpoint: String,
    /// AkeylessImageValidation CR namespace.
    pub namespace: String,
    /// Promessa to reference on every emitted CR.
    pub promessa_ref: String,
    /// Compliance pack to reference on every emitted CR.
    pub pack: String,
    /// Service-name allowlist; empty = every `akeyless-<svc>` repo
    /// found in Zot's catalog.
    pub services: Vec<String>,
    /// HTTP Basic auth (akeyless-builder + token).
    pub basic_auth: Option<(String, String)>,
    /// Print would-be CRs without applying.
    pub dry_run: bool,
}

#[derive(Deserialize)]
struct CatalogResp {
    repositories: Vec<String>,
}

#[derive(Deserialize)]
struct TagsResp {
    tags: Vec<String>,
}

/// Discover every `akeyless-<service>` repo in Zot, resolve each
/// repo's most recent tag's digest, and apply an
/// AkeylessImageValidation CR per digest.
pub async fn run(args: SubmitArgs) -> Result<()> {
    tracing::info!(zot = %args.zot_endpoint, ns = %args.namespace, "submit-validations starting");

    let http = http_client()?;
    let catalog = fetch_catalog(&http, &args).await?;
    let akeyless_repos: Vec<String> = catalog
        .repositories
        .into_iter()
        .filter(|r| r.starts_with("akeyless-"))
        .filter(|r| {
            args.services.is_empty()
                || args.services.iter().any(|s| r == &format!("akeyless-{s}"))
        })
        .collect();

    if akeyless_repos.is_empty() {
        return Err(anyhow!(
            "Zot catalog has no akeyless-* repos — run `private-push akeyless` first"
        ));
    }

    let client = if args.dry_run {
        None
    } else {
        Some(Client::try_default().await.context("kube::Client::try_default")?)
    };

    for repo in &akeyless_repos {
        match resolve_latest_digest(&http, &args, repo).await {
            Ok((tag, digest)) => {
                let service = repo
                    .strip_prefix("akeyless-")
                    .unwrap_or(repo)
                    .to_owned();
                let cr = build_cr(&args, &service, repo, &digest);
                let cr_name = cr.metadata.name.clone().unwrap_or_default();
                tracing::info!(repo = %repo, tag = %tag, digest = %digest, cr = %cr_name, "resolved");

                if let Some(client) = client.as_ref() {
                    apply_cr(client.clone(), &args.namespace, cr).await?;
                } else {
                    println!("---");
                    println!("{}", serde_json::to_string_pretty(&cr)?);
                }
            }
            Err(e) => tracing::warn!(repo = %repo, error = %e, "skipping — could not resolve digest"),
        }
    }

    tracing::info!("submit-validations done");
    Ok(())
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        // localhost over port-forward has no TLS; in-cluster Zot
        // Service is plain HTTP. The chain is private regardless
        // (host-local + cluster-internal).
        .danger_accept_invalid_certs(true)
        .build()
        .context("build reqwest client")
}

async fn fetch_catalog(http: &reqwest::Client, args: &SubmitArgs) -> Result<CatalogResp> {
    let url = format!("http://{}/v2/_catalog?n=200", args.zot_endpoint);
    let mut req = http.get(&url);
    if let Some((u, p)) = &args.basic_auth {
        req = req.basic_auth(u, Some(p));
    }
    let r = req.send().await.with_context(|| format!("GET {url}"))?;
    if !r.status().is_success() {
        return Err(anyhow!("zot catalog: {} {}", url, r.status()));
    }
    r.json().await.context("parse /v2/_catalog json")
}

async fn resolve_latest_digest(
    http: &reqwest::Client,
    args: &SubmitArgs,
    repo: &str,
) -> Result<(String, String)> {
    let url = format!("http://{}/v2/{}/tags/list", args.zot_endpoint, repo);
    let mut req = http.get(&url);
    if let Some((u, p)) = &args.basic_auth {
        req = req.basic_auth(u, Some(p));
    }
    let resp: TagsResp = req
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .json()
        .await
        .context("parse tags list")?;
    let tag = resp
        .tags
        .last()
        .ok_or_else(|| anyhow!("repo {repo} has no tags"))?
        .clone();

    // HEAD the manifest for the Docker-Content-Digest header. The
    // OCI Image Manifest Accept header is required for Zot to return
    // the digest properly.
    let murl = format!("http://{}/v2/{}/manifests/{}", args.zot_endpoint, repo, tag);
    let mut req = http
        .head(&murl)
        .header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
        );
    if let Some((u, p)) = &args.basic_auth {
        req = req.basic_auth(u, Some(p));
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("HEAD {murl}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("zot manifest head: {} {}", murl, resp.status()));
    }
    let digest = resp
        .headers()
        .get("docker-content-digest")
        .ok_or_else(|| anyhow!("no docker-content-digest header from {murl}"))?
        .to_str()
        .context("digest header non-ascii")?
        .to_owned();
    Ok((tag, digest))
}

/// Build the typed CR. `name` is digest-suffixed so re-pushes at a
/// new tag create distinct CRs (the controller can clean stale ones
/// via the `keep_for` field).
pub fn build_cr(
    args: &SubmitArgs,
    service: &str,
    repo: &str,
    digest: &str,
) -> AkeylessImageValidation {
    use kube::api::ObjectMeta;
    let suffix = digest
        .trim_start_matches("sha256:")
        .chars()
        .take(12)
        .collect::<String>();
    let name = format!("{}-{}", repo, suffix);
    AkeylessImageValidation {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: Some(args.namespace.clone()),
            ..Default::default()
        },
        spec: AkeylessImageValidationSpec {
            image_digest: digest.to_owned(),
            image_repo: repo.to_owned(),
            service: service.to_owned(),
            promessa_ref: args.promessa_ref.clone(),
            pack: args.pack.clone(),
            keep_for: Some("P30D".into()),
        },
        status: None,
    }
}

async fn apply_cr(
    client: Client,
    namespace: &str,
    cr: AkeylessImageValidation,
) -> Result<()> {
    let api: Api<AkeylessImageValidation> = Api::namespaced(client, namespace);
    let name = cr.metadata.name.clone().unwrap_or_default();
    let pp = PatchParams::apply(FIELD_MANAGER).force();
    api.patch(&name, &pp, &Patch::Apply(&cr))
        .await
        .with_context(|| format!("apply AkeylessImageValidation {name}"))?;
    tracing::info!(name = %name, "applied AkeylessImageValidation");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> SubmitArgs {
        SubmitArgs {
            zot_endpoint: "localhost:5000".into(),
            namespace: "akeyless-validation".into(),
            promessa_ref: "akeyless-nix-images-fedramp-scr".into(),
            pack: "fedramp-high-akeyless-go-image@1".into(),
            services: vec![],
            basic_auth: None,
            dry_run: false,
        }
    }

    #[test]
    fn cr_name_suffix_is_first_12_of_digest() {
        let cr = build_cr(
            &args(),
            "auth",
            "akeyless-auth",
            "sha256:abcdef0123456789aaaabbbbccccdddd",
        );
        let name = cr.metadata.name.as_deref().unwrap();
        assert_eq!(name, "akeyless-auth-abcdef012345");
    }

    #[test]
    fn cr_spec_fields_populated_from_args() {
        let cr = build_cr(&args(), "uam", "akeyless-uam", "sha256:abc");
        assert_eq!(cr.spec.image_digest, "sha256:abc");
        assert_eq!(cr.spec.image_repo, "akeyless-uam");
        assert_eq!(cr.spec.service, "uam");
        assert_eq!(cr.spec.promessa_ref, "akeyless-nix-images-fedramp-scr");
        assert_eq!(cr.spec.pack, "fedramp-high-akeyless-go-image@1");
        assert_eq!(cr.spec.keep_for.as_deref(), Some("P30D"));
        assert_eq!(cr.metadata.namespace.as_deref(), Some("akeyless-validation"));
    }

    #[test]
    fn cr_is_json_serializable() {
        let cr = build_cr(&args(), "auth", "akeyless-auth", "sha256:def");
        let json = serde_json::to_value(&cr).expect("serialize CR");
        assert_eq!(json["spec"]["service"], "auth");
        assert_eq!(json["apiVersion"], "validation.pleme.io/v1");
        assert_eq!(json["kind"], "AkeylessImageValidation");
    }
}
