//! Top-level orchestration — port-forward → login → for each binary:
//! build, copy, sign. Pure function entrypoints so the binary's
//! main is thin.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

use crate::{oci, subprocess};

#[derive(Debug, Clone)]
pub struct Common {
    pub kube_context: Option<String>,
    pub namespace: String,
    pub service: String,
    pub port: u16,
    pub token_path: PathBuf,
    pub cosign: bool,
    /// Optional path to a cosign private key (PEM). When set,
    /// `cosign sign --key <path>` is used — pair with the
    /// ClusterImagePolicy that embeds the matching public key.
    /// When None (default), keyless signing runs and the policy-
    /// controller side must be configured for keyless verify, which
    /// requires Sigstore network calls. The keypair path is the
    /// substrate-aligned default.
    pub cosign_key_path: Option<PathBuf>,
}

impl Common {
    fn kubectl(&self) -> Command {
        let mut c = Command::new("kubectl");
        if let Some(ctx) = &self.kube_context {
            c.arg("--context").arg(ctx);
        }
        c
    }
}

/// Push the named binaries from `source_flake` at `tag` to
/// `localhost:<port>/pleme-io/<binary>:<tag>`.
pub fn run_substrate(
    common: &Common,
    source_flake: &Path,
    tag: &str,
    binaries: &[String],
) -> Result<()> {
    tracing::info!(?source_flake, tag, ?binaries, "private-push substrate starting");
    let _pf = start_port_forward(common)?;
    skopeo_login(common)?;

    for binary in binaries {
        let nix_attr = format!("image:{binary}");
        let result_link = source_flake.join(format!("result-{binary}"));
        nix_build(source_flake, &nix_attr, &result_link)?;

        let dest = oci::substrate_dest(common.port, binary, tag);
        skopeo_copy(&result_link, &dest)?;

        if common.cosign {
            cosign_sign(
                common.port,
                &format!("pleme-io/{binary}"),
                &dest,
                common.cosign_key_path.as_deref(),
            )?;
        }

        std::fs::remove_file(&result_link).ok();
    }
    tracing::info!("private-push substrate done");
    Ok(())
}

/// Push the named Akeyless services from `source_flake` (tag
/// optional — defaults to the docker-archive's baked-in RepoTags[0]).
pub fn run_akeyless(
    common: &Common,
    source_flake: &Path,
    tag_override: Option<&str>,
    services: &[String],
) -> Result<()> {
    tracing::info!(?source_flake, ?tag_override, ?services, "private-push akeyless starting");
    let _pf = start_port_forward(common)?;
    skopeo_login(common)?;

    for service in services {
        let nix_attr = format!("dockerImage:{service}");
        let result_link = source_flake.join(format!("result-{service}"));
        nix_build(source_flake, &nix_attr, &result_link)?;

        let tag = match tag_override {
            Some(t) => t.to_owned(),
            None => discover_baked_tag(&result_link)?,
        };
        let dest = oci::akeyless_dest(common.port, service, &tag);
        skopeo_copy(&result_link, &dest)?;

        if common.cosign {
            cosign_sign(
                common.port,
                &format!("akeyless-{service}"),
                &dest,
                common.cosign_key_path.as_deref(),
            )?;
        }

        std::fs::remove_file(&result_link).ok();
    }
    tracing::info!("private-push akeyless done");
    Ok(())
}

// ─── stages ────────────────────────────────────────────────────────

fn start_port_forward(common: &Common) -> Result<subprocess::Backgrounded> {
    // Sanity: kubectl reaches the cluster + the Service exists.
    let mut svc_check = common.kubectl();
    svc_check
        .arg("-n")
        .arg(&common.namespace)
        .arg("get")
        .arg("svc")
        .arg(&common.service)
        .arg("-o")
        .arg("name");
    subprocess::run_checked("kubectl get svc", svc_check)
        .context("verify kubectl + Zot Service reachable")?;

    let mut pf = common.kubectl();
    pf.arg("-n")
        .arg(&common.namespace)
        .arg("port-forward")
        .arg(format!("svc/{}", &common.service))
        .arg(format!("{port}:{port}", port = common.port));
    let mut bg = subprocess::spawn_background("kubectl port-forward", pf)?;

    // kubectl prints "Forwarding from 127.0.0.1:5000 -> 5000" on
    // stdout once the listener is up. Wait for that, max 50 lines.
    bg.wait_for_line(
        |line| line.contains("Forwarding from") && line.contains(&common.port.to_string()),
        50,
    )?;
    tracing::info!(port = common.port, "port-forward up");
    Ok(bg)
}

fn skopeo_login(common: &Common) -> Result<()> {
    let token = decrypt_token(&common.token_path)?;
    let mut cmd = Command::new("skopeo");
    cmd.arg("login")
        .arg("--tls-verify=false")
        .arg("--username")
        .arg("akeyless-builder")
        .arg("--password")
        .arg(&token)
        .arg(format!("localhost:{}", common.port));
    subprocess::run_checked("skopeo login", cmd)
}

fn decrypt_token(path: &Path) -> Result<String> {
    let mut sops = Command::new("sops");
    sops.arg("-d").arg(path);
    let yaml = subprocess::run_capture("sops -d", sops)?;
    // The token is a plain UTF-8 string under `data: { token: ... }`.
    // Earlier shipping shape (commit 1407ca4) assumed base64 encoding
    // because the file was modeled after a K8s Secret Opaque field;
    // the actual pleme-io ZotPushToken schema (apiVersion: pleme.io/
    // v1, kind: ZotPushToken — see zot-push-token.sops.yaml header)
    // stores the plaintext token. Base64-only decoding produced
    // non-UTF-8 garbage for tokens that happened to look like valid
    // base64 input.
    //
    // Strategy: read the raw string after `token:`, strip quoting,
    // and return it. No base64 step. Tokens with characters outside
    // `[A-Za-z0-9+/=]` would previously have errored; now they pass
    // through unchanged.
    for line in yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("token:") {
            let token = rest.trim().trim_matches('"').to_owned();
            if token.is_empty() {
                return Err(anyhow!("zot-push-token YAML has empty `token:` field"));
            }
            return Ok(token);
        }
    }
    Err(anyhow!("zot-push-token YAML has no `token:` field"))
}

fn nix_build(source_flake: &Path, attr: &str, result_link: &Path) -> Result<()> {
    let mut cmd = Command::new("nix");
    cmd.current_dir(source_flake)
        .arg("build")
        .arg(format!(".#{attr}"))
        .arg("-o")
        .arg(result_link);
    subprocess::run_checked(&format!("nix build .#{attr}"), cmd)
}

fn skopeo_copy(result_link: &Path, dest: &str) -> Result<()> {
    let mut cmd = Command::new("skopeo");
    cmd.arg("copy")
        .arg("--dest-tls-verify=false")
        .arg(format!("docker-archive:{}", result_link.display()))
        .arg(format!("docker://{dest}"));
    subprocess::run_checked("skopeo copy", cmd)
}

fn cosign_sign(
    port: u16,
    repo: &str,
    dest_tagged: &str,
    key_path: Option<&Path>,
) -> Result<()> {
    // Resolve to digest first — cosign signs by digest, not tag.
    let digest = {
        let mut cmd = Command::new("skopeo");
        cmd.arg("inspect")
            .arg("--tls-verify=false")
            .arg(format!("docker://{dest_tagged}"))
            .arg("--format")
            .arg("{{.Digest}}");
        subprocess::run_capture("skopeo inspect", cmd)?
            .trim()
            .to_owned()
    };
    let ref_by_digest = format!("localhost:{port}/{repo}@{digest}");

    let mut cmd = Command::new("cosign");
    cmd.arg("sign")
        .arg("--yes")
        .arg("--allow-insecure-registry")
        .arg("--tlog-upload=false");
    if let Some(key) = key_path {
        // Static-keypair sign — matches the ClusterImagePolicy
        // `authorities[].key.data` PEM embedded in the chart.
        // No Sigstore network calls on verify (Fulcio / Rekor /
        // CT-log) because the verifier just runs a signature check
        // against the embedded pubkey.
        cmd.arg("--key").arg(key);
    }
    // else: keyless — falls back to Fulcio OIDC interactive flow.
    cmd.arg(&ref_by_digest);
    subprocess::run_checked("cosign sign", cmd)
}

fn discover_baked_tag(result_link: &Path) -> Result<String> {
    let mut cmd = Command::new("skopeo");
    cmd.arg("inspect")
        .arg("--tls-verify=false")
        .arg(format!("docker-archive:{}", result_link.display()))
        .arg("--format")
        .arg("{{(index .RepoTags 0)}}");
    let raw = subprocess::run_capture("skopeo inspect docker-archive", cmd)?;
    let baked = raw.trim();
    if baked.is_empty() {
        Ok("latest".into())
    } else {
        Ok(oci::extract_tag_only(baked).to_owned())
    }
}

#[cfg(test)]
mod tests {
    // decrypt_token tests would require an executable `sops` + a
    // SOPS-encrypted fixture file with the right age recipient. The
    // raw token-extraction logic is now `rest.trim().trim_matches('"')`
    // — too small to merit a unit test of its own. The end-to-end
    // path was validated against pleme-dev's
    // infrastructure/zot-stack/zot/zot-push-token.sops.yaml: produces
    // "3zYSTHsY4Ra5SWYYmEwN4wXUj9YQ8WHcPNQKzdaa8LP" (plain UTF-8).
    //
    // The previous base64-roundtrip tests are removed alongside the
    // decoder they exercised.
}
