//! Pure URL/tag/attr derivation logic. Pure → unit-testable.

use serde::Serialize;

/// Nix system for an image arch. `amd64` → `x86_64-linux` (pleme-dev's
/// x86_64 nodes), `arm64` → `aarch64-linux`.
#[must_use]
pub fn nix_system_for_arch(arch: &str) -> &'static str {
    match arch {
        "arm64" | "aarch64" => "aarch64-linux",
        _ => "x86_64-linux",
    }
}

/// The flake attribute for an Akeyless service's OCI image.
///
/// The akeyless-nix-images flake exposes images as
/// `packages.<system>."dockerImage:<arch>:<service>"`. The system is
/// pinned explicitly because the host (typically darwin) cannot build a
/// Linux image locally — the Nix daemon routes the build to the
/// matching Linux builder. (The earlier `dockerImage:<service>` attr
/// predated the arch split and no longer resolves.)
#[must_use]
pub fn akeyless_image_attr(arch: &str, service: &str) -> String {
    let system = nix_system_for_arch(arch);
    format!("packages.{system}.\"dockerImage:{arch}:{service}\"")
}

/// One image pushed to Zot — the typed record emitted as the push
/// manifest. The `{service → digest}` set is exactly the `digest_set`
/// the AkeylessEphemeralTenant consumes and the admission gate pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PushedImage {
    pub service: String,
    pub repo: String,
    pub tag: String,
    pub digest: String,
}

/// Derive the Zot destination URL for a substrate binary at `host`.
///
/// `<host>/pleme-io/<binary>:<tag>` — `host` is `localhost:<port>`
/// (port-forward) or e.g. `zot-dev.quero.cloud` (tunnel).
#[must_use]
pub fn substrate_dest(host: &str, binary: &str, tag: &str) -> String {
    format!("{host}/pleme-io/{binary}:{tag}")
}

/// Derive the Zot destination URL for an Akeyless service at `host`.
///
/// `<host>/akeyless-<service>:<tag>`
#[must_use]
pub fn akeyless_dest(host: &str, service: &str, tag: &str) -> String {
    format!("{host}/akeyless-{service}:{tag}")
}

/// Strip a docker-archive `RepoTags[0]` value down to just the tag
/// (right of the last `:`). The full value is shaped like
/// `host/repo:tag` or `repo:tag` or just `tag`. We always want only
/// the tag — destination repo path is controlled by the caller.
#[must_use]
pub fn extract_tag_only(repo_tag: &str) -> &str {
    repo_tag.rsplit_once(':').map_or(repo_tag, |(_, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrate_dest_format() {
        assert_eq!(
            substrate_dest("localhost:5000", "engenho-promessa", "0.6.0"),
            "localhost:5000/pleme-io/engenho-promessa:0.6.0"
        );
    }

    #[test]
    fn akeyless_dest_format() {
        assert_eq!(
            akeyless_dest("localhost:5000", "auth", "v1.2.3"),
            "localhost:5000/akeyless-auth:v1.2.3"
        );
        // Tunnel host (VPN-free push) produces the same shape.
        assert_eq!(
            akeyless_dest("zot-dev.quero.cloud", "auth", "amd64-latest"),
            "zot-dev.quero.cloud/akeyless-auth:amd64-latest"
        );
    }

    #[test]
    fn extract_tag_from_full_ref() {
        assert_eq!(extract_tag_only("docker.io/library/foo:1.0.0"), "1.0.0");
        assert_eq!(extract_tag_only("foo:bar"), "bar");
        assert_eq!(extract_tag_only("latest"), "latest");
    }

    #[test]
    fn akeyless_image_attr_matches_flake_shape() {
        assert_eq!(
            akeyless_image_attr("amd64", "auth"),
            "packages.x86_64-linux.\"dockerImage:amd64:auth\""
        );
        assert_eq!(
            akeyless_image_attr("arm64", "gateway"),
            "packages.aarch64-linux.\"dockerImage:arm64:gateway\""
        );
    }

    #[test]
    fn nix_system_maps_arch() {
        assert_eq!(nix_system_for_arch("amd64"), "x86_64-linux");
        assert_eq!(nix_system_for_arch("arm64"), "aarch64-linux");
        assert_eq!(nix_system_for_arch("aarch64"), "aarch64-linux");
        // Unknown arch defaults to x86_64-linux (pleme-dev's nodes).
        assert_eq!(nix_system_for_arch("riscv"), "x86_64-linux");
    }

    #[test]
    fn pushed_image_serializes_to_digest_set_shape() {
        let p = PushedImage {
            service: "auth".into(),
            repo: "akeyless-auth".into(),
            tag: "amd64-latest".into(),
            digest: "sha256:abc".into(),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["service"], "auth");
        assert_eq!(v["digest"], "sha256:abc");
    }

    #[test]
    fn destinations_never_contain_third_party_host() {
        let s = substrate_dest("localhost:5000", "x", "y");
        let a = akeyless_dest("localhost:5000", "x", "y");
        for u in [&s, &a] {
            assert!(u.starts_with("localhost:"), "got {u}");
            assert!(!u.contains("ghcr.io"), "got {u}");
            assert!(!u.contains("docker.io"), "got {u}");
            assert!(!u.contains("quay.io"), "got {u}");
        }
    }
}
