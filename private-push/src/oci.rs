//! Pure URL/tag derivation logic. Pure → unit-testable.

/// Derive the in-cluster Zot destination URL for a substrate binary.
///
/// `localhost:<port>/pleme-io/<binary>:<tag>`
#[must_use]
pub fn substrate_dest(port: u16, binary: &str, tag: &str) -> String {
    format!("localhost:{port}/pleme-io/{binary}:{tag}")
}

/// Derive the in-cluster Zot destination URL for an Akeyless service.
///
/// `localhost:<port>/akeyless-<service>:<tag>`
#[must_use]
pub fn akeyless_dest(port: u16, service: &str, tag: &str) -> String {
    format!("localhost:{port}/akeyless-{service}:{tag}")
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
            substrate_dest(5000, "engenho-promessa", "0.6.0"),
            "localhost:5000/pleme-io/engenho-promessa:0.6.0"
        );
    }

    #[test]
    fn akeyless_dest_format() {
        assert_eq!(
            akeyless_dest(5000, "auth", "v1.2.3"),
            "localhost:5000/akeyless-auth:v1.2.3"
        );
    }

    #[test]
    fn extract_tag_from_full_ref() {
        assert_eq!(extract_tag_only("docker.io/library/foo:1.0.0"), "1.0.0");
        assert_eq!(extract_tag_only("foo:bar"), "bar");
        assert_eq!(extract_tag_only("latest"), "latest");
    }

    #[test]
    fn destinations_never_contain_third_party_host() {
        let s = substrate_dest(5000, "x", "y");
        let a = akeyless_dest(5000, "x", "y");
        for u in [&s, &a] {
            assert!(u.starts_with("localhost:"), "got {u}");
            assert!(!u.contains("ghcr.io"), "got {u}");
            assert!(!u.contains("docker.io"), "got {u}");
            assert!(!u.contains("quay.io"), "got {u}");
        }
    }
}
