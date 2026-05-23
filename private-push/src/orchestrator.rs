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
            cosign_sign(common.port, &format!("pleme-io/{binary}"), &dest)?;
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
            cosign_sign(common.port, &format!("akeyless-{service}"), &dest)?;
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
    // Cheap extraction: find `token:` in the YAML and base64-decode
    // its value. We avoid a serde_yaml dep — the token field shape is
    // fixed (`data:\n  token: <base64>`).
    for line in yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("token:") {
            let b64 = rest.trim().trim_matches('"');
            let bytes = base64_decode(b64).context("decode token base64")?;
            return String::from_utf8(bytes).context("token non-utf8");
        }
    }
    Err(anyhow!("zot-push-token YAML has no `token:` field"))
}

/// Minimal base64 decoder — stdlib-only. The token field is well-
/// behaved (no whitespace, standard alphabet, padded). Bringing in
/// the `base64` crate just for this one call would be overkill.
fn base64_decode(s: &str) -> Result<Vec<u8>> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.trim();
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        if b == b'=' {
            break;
        }
        let v = A
            .iter()
            .position(|&c| c == b)
            .ok_or_else(|| anyhow!("bad base64 char: {b:?}"))?;
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
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

fn cosign_sign(port: u16, repo: &str, dest_tagged: &str) -> Result<()> {
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
        .arg("--tlog-upload=false")
        .arg(&ref_by_digest);
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
    use super::*;

    #[test]
    fn base64_decode_round_trip() {
        // "akeyless-builder:supersecret-token" → known base64 from
        // openssl + python. Verify the decoder handles padded input.
        let encoded = "YWtleWxlc3MtYnVpbGRlcjpzdXBlcnNlY3JldC10b2tlbg==";
        let out = base64_decode(encoded).unwrap();
        assert_eq!(out, b"akeyless-builder:supersecret-token");
    }

    #[test]
    fn base64_decode_plain() {
        // "hello" → "aGVsbG8="
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn base64_decode_rejects_bad_char() {
        assert!(base64_decode("not_base64!").is_err());
    }
}
