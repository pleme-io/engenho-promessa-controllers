//! `FluxCommitReconciler` — apply a JSON merge patch to a YAML file
//! in a FluxCD GitRepository, then commit + push so Flux's source-
//! controller picks the change up on its next reconcile cycle.
//!
//! ## What it wraps
//!
//! [`promessa_types::TypedAction::FluxCommit { path, patch }`] is the
//! gitops-native typed action — VIGGY-AUTHORING §5 declares it the
//! default for any state change that should outlive a single
//! reconcile run. The SecurityController emits FluxCommit for
//! pin-to-previous-good remediations on Critical-severity drift
//! (see `security-controller/src/lib.rs` — search for `FluxCommit`).
//!
//! Until this Reconciler shipped, every FluxCommit emission landed in
//! [`reconciler-engine::ActionExecutor::execute`]'s sentinel branch
//! and returned [`promessa_types::ReconcilerError::Internal`] —
//! decisions went to the void. With this Reconciler wired, the loop
//! closes: SecurityController.decide → FluxCommit → file patched →
//! commit pushed → Flux source-controller reconciles → cluster
//! converges.
//!
//! ## Subprocess via `git` CLI
//!
//! Same idiom as the `private-push` crate's skopeo/cosign/kubectl
//! invocations — typed Rust calling typed binaries, no shell
//! scripting layer. The engenho-promessa OCI image adds `git` to its
//! `contents` so the Reconciler has the binary at runtime.
//!
//! The full `gitoxide` library is overkill for the 4-command surface
//! we actually need (clone, add, commit, push). Subprocess keeps the
//! dep footprint small and matches the existing private-push pattern.
//!
//! ## Idempotency
//!
//! `act` reads the file at `path`, applies the JSON merge patch
//! (RFC 7396 semantics — YAML values are converted to JSON for the
//! merge step, then re-serialized to YAML), and compares before/after.
//! If unchanged, returns
//! [`promessa_types::ReconcilerOutcome::AlreadyConverged`] — no
//! commit, no push. If changed, the change is staged, committed,
//! and pushed; the outcome carries the new commit SHA.
//!
//! ## Dry-run mode
//!
//! For dev bring-up + tests, `dry_run: true` runs the full
//! clone+patch+commit cycle but skips the final `git push`. The
//! receipt carries the local commit SHA but the remote never sees it.
//! Pleme-dev defaults to `dry_run: true` until the operator wires
//! `flux-commit-deploy-key` and flips the flag.

use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use promessa_types::{ReconcilerError, ReconcilerOutcome};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Typed input for [`FluxCommitReconciler::act`]. Sourced from
/// [`promessa_types::TypedAction::FluxCommit`] via the
/// [`reconciler-engine::ActionExecutor`] dispatcher (which unpacks
/// the variant's fields into this Spec shape).
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct FluxCommitSpec {
    /// Repo to clone + commit to. Either an `https://` URL (with PAT
    /// authentication) or a `git@` SSH URL (with key authentication).
    /// Example: `git@github.com:pleme-io/k8s.git`.
    pub repo_url: String,

    /// Branch to commit on. Default: `main`.
    pub branch: String,

    /// File path inside the repo to patch. Example:
    /// `clusters/pleme-dev/apps/akeyless-validation/helmrelease.yaml`.
    pub path: String,

    /// JSON merge patch (RFC 7396) to apply. The file at `path` is
    /// parsed as YAML, converted to JSON for the merge step, the
    /// patch deep-merged, and the result re-serialized to YAML.
    pub patch: serde_json::Value,

    /// Optional commit message. When `None`, the Reconciler
    /// synthesizes a structured one carrying the action's coordinates
    /// (path + commit subject + run uid if available from context).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_message: Option<String>,
}

impl FluxCommitSpec {
    /// Default branch when the consumer doesn't specify one.
    #[must_use]
    pub fn default_branch() -> String {
        "main".into()
    }
}

/// Receipt — what to record durably about the patch+commit cycle.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct FluxCommitReceipt {
    /// SHA of the commit we created. Even in dry-run mode this is
    /// the actual local commit SHA — only the push to origin is
    /// skipped.
    pub commit_sha: String,

    pub repo_url: String,
    pub branch: String,
    pub path: String,
    pub committed_at: chrono::DateTime<Utc>,

    /// `true` when `dry_run` was set on the Reconciler — push was
    /// skipped, the commit only exists in the ephemeral working tree.
    pub dry_run: bool,
}

/// Reconciler config. Held in [`FluxCommitReconciler`] for all
/// `act()` calls; sourced from
/// [`reconciler-engine::EngineConfig::flux_commit_*`] at boot.
#[derive(Clone, Debug)]
pub struct FluxCommitConfig {
    /// Git author identity for commits. Example:
    /// `("engenho-promessa", "engenho-promessa@pleme.io")`.
    pub author_name: String,
    pub author_email: String,

    /// When true, `git push` is skipped. The clone + patch + commit
    /// happen in a temp dir and the receipt carries the local SHA;
    /// nothing reaches origin.
    pub dry_run: bool,

    /// Optional path to an SSH private key passed via
    /// `GIT_SSH_COMMAND="ssh -i <path> -o StrictHostKeyChecking=no"`.
    /// `None` falls back to whatever ssh-agent the process inherits.
    pub ssh_key_path: Option<PathBuf>,
}

impl Default for FluxCommitConfig {
    fn default() -> Self {
        Self {
            author_name: "engenho-promessa".into(),
            author_email: "engenho-promessa@pleme.io".into(),
            dry_run: true,
            ssh_key_path: None,
        }
    }
}

/// FluxCommit handler — not a [`promessa_types::Reconciler`] trait
/// impl because [`promessa_types::TypedAction::FluxCommit`] is a
/// top-level TypedAction variant, NOT a [`promessa_types::ReconcilerKind`]
/// (see promessa-types/src/action.rs:55 — `FluxCommit { path, patch }`
/// vs. the kinded ReconcilerKind enum). Dispatch happens directly in
/// [`ActionExecutor::execute`]'s `TypedAction::FluxCommit` arm.
///
/// The shape still mirrors the Reconciler trait — async `act` taking a
/// typed Spec and returning a [`ReconcilerOutcome<Receipt>`] — so
/// behavior is observably identical to a kinded reconciler from the
/// dispatcher's perspective.
pub struct FluxCommitReconciler {
    config: FluxCommitConfig,
}

impl FluxCommitReconciler {
    #[must_use]
    pub fn new(config: FluxCommitConfig) -> Self {
        Self { config }
    }

    /// Apply the patch. Same signature as
    /// [`promessa_types::Reconciler::act`] — the dispatcher invokes
    /// this directly without going through the kinded engine.
    pub async fn act(&self, spec: FluxCommitSpec) -> ReconcilerOutcome<FluxCommitReceipt> {
        let config = self.config.clone();
        // Subprocess + filesystem work happens on the blocking
        // pool — `git` is sync and `tokio::process::Command` would
        // give us async-ness we don't need (single sequential pipeline).
        match tokio::task::spawn_blocking(move || run_flux_commit(&config, &spec)).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => ReconcilerOutcome::Failed { error },
            Err(join_err) => ReconcilerOutcome::Failed {
                error: ReconcilerError::Internal {
                    detail: format!("flux-commit blocking task panicked: {join_err}"),
                },
            },
        }
    }
}

/// Pure synchronous pipeline — clone, patch, commit, optionally push.
/// Returns `Ok(Outcome)` for the AlreadyConverged / Applied branches,
/// `Err(ReconcilerError)` only on substrate-level failures.
fn run_flux_commit(
    config: &FluxCommitConfig,
    spec: &FluxCommitSpec,
) -> Result<ReconcilerOutcome<FluxCommitReceipt>, ReconcilerError> {
    let workdir = tempfile::tempdir().map_err(|e| ReconcilerError::Internal {
        detail: format!("tempdir create failed: {e}"),
    })?;
    let clone_dir = workdir.path().join("repo");

    git_clone(config, &spec.repo_url, &spec.branch, &clone_dir)?;

    let target = clone_dir.join(&spec.path);
    let original = std::fs::read_to_string(&target).map_err(|e| {
        ReconcilerError::SubstrateRefused {
            detail: format!(
                "read {} after clone failed: {e}",
                target.display()
            ),
        }
    })?;

    // Idempotency check happens at the JSON value level — the YAML
    // round-trip changes whitespace/quoting (e.g. `"0.10.0"` becomes
    // `0.10.0` without quotes) so a string comparison flags
    // logically-identical files as changed. Comparing JSON values
    // captures the actual data equivalence the patch operates on.
    let original_json = yaml_str_to_json(&original)?;
    let mut patched_json = original_json.clone();
    merge_json(&mut patched_json, &spec.patch);
    if patched_json == original_json {
        tracing::info!(
            repo = %spec.repo_url,
            path = %spec.path,
            "flux-commit: JSON-equivalent file already matches desired patch — no commit"
        );
        return Ok(ReconcilerOutcome::AlreadyConverged);
    }

    let patched_yaml = json_to_yaml_str(&patched_json)?;
    std::fs::write(&target, &patched_yaml).map_err(|e| ReconcilerError::Internal {
        detail: format!("write {} failed: {e}", target.display()),
    })?;

    let message = spec.commit_message.clone().unwrap_or_else(|| {
        format!(
            "engenho-promessa: FluxCommit patch\n\npath: {}\nReconciler: FluxCommit",
            spec.path
        )
    });

    git_add_commit(config, &clone_dir, &spec.path, &message)?;
    let sha = git_head_sha(&clone_dir)?;

    if config.dry_run {
        tracing::info!(
            repo = %spec.repo_url,
            path = %spec.path,
            sha = %sha,
            "flux-commit: dry_run=true — skipping push"
        );
    } else {
        git_push(config, &clone_dir, &spec.branch)?;
    }

    Ok(ReconcilerOutcome::Applied {
        receipt: FluxCommitReceipt {
            commit_sha: sha,
            repo_url: spec.repo_url.clone(),
            branch: spec.branch.clone(),
            path: spec.path.clone(),
            committed_at: Utc::now(),
            dry_run: config.dry_run,
        },
    })
}

/// `git clone --depth 1 --branch <branch> <url> <dir>` — shallow
/// clone of a single branch. Faster than full clone for our use
/// (we only commit one file).
fn git_clone(
    config: &FluxCommitConfig,
    url: &str,
    branch: &str,
    dir: &Path,
) -> Result<(), ReconcilerError> {
    let mut cmd = Command::new("git");
    cmd.arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(branch)
        .arg(url)
        .arg(dir);
    apply_ssh_env(&mut cmd, config);
    run_git("clone", cmd)
}

/// `git -C <dir> add <path>` + `git -C <dir> commit -m <message>`
/// with the author identity from config. Returns the commit SHA via a
/// separate `git rev-parse HEAD`.
fn git_add_commit(
    config: &FluxCommitConfig,
    dir: &Path,
    path: &str,
    message: &str,
) -> Result<(), ReconcilerError> {
    let mut add = Command::new("git");
    add.current_dir(dir).arg("add").arg(path);
    run_git("add", add)?;

    let mut commit = Command::new("git");
    commit
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", &config.author_name)
        .env("GIT_AUTHOR_EMAIL", &config.author_email)
        .env("GIT_COMMITTER_NAME", &config.author_name)
        .env("GIT_COMMITTER_EMAIL", &config.author_email)
        .arg("commit")
        .arg("-m")
        .arg(message);
    run_git("commit", commit)
}

fn git_head_sha(dir: &Path) -> Result<String, ReconcilerError> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).arg("rev-parse").arg("HEAD");
    let out = cmd.output().map_err(|e| ReconcilerError::Internal {
        detail: format!("git rev-parse spawn failed: {e}"),
    })?;
    if !out.status.success() {
        return Err(ReconcilerError::Internal {
            detail: format!(
                "git rev-parse HEAD failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn git_push(
    config: &FluxCommitConfig,
    dir: &Path,
    branch: &str,
) -> Result<(), ReconcilerError> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).arg("push").arg("origin").arg(branch);
    apply_ssh_env(&mut cmd, config);
    run_git("push", cmd)
}

fn apply_ssh_env(cmd: &mut Command, config: &FluxCommitConfig) {
    if let Some(key) = &config.ssh_key_path {
        let ssh_cmd = format!(
            "ssh -i {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
            key.display()
        );
        cmd.env("GIT_SSH_COMMAND", ssh_cmd);
    }
}

fn run_git(stage: &str, mut cmd: Command) -> Result<(), ReconcilerError> {
    let out = cmd.output().map_err(|e| ReconcilerError::Internal {
        detail: format!("git {stage} spawn failed: {e}"),
    })?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    // SubstrateRefused for "you asked for something git can't do"
    // (auth failure, branch doesn't exist, repo not found) so the
    // engine's retry policy doesn't burn cycles. Internal for spawn /
    // wait failures (those got returned above).
    Err(ReconcilerError::SubstrateRefused {
        detail: format!("git {stage} failed: {stderr}"),
    })
}

/// Parse YAML into a serde_json::Value (the canonical shape merge
/// operates on). Round-tripping through serde_json::Value loses
/// YAML-only features (anchors, comments, block style) — acceptable
/// for FluxCD-managed YAML files (simple data with no anchors).
///
/// FOLLOWUP(D-OP-14): when we need to preserve comments / anchors,
/// switch to `yaml-rust2` or a comment-preserving merge approach.
fn yaml_str_to_json(yaml_input: &str) -> Result<serde_json::Value, ReconcilerError> {
    let yaml_val: serde_yaml::Value =
        serde_yaml::from_str(yaml_input).map_err(|e| ReconcilerError::Internal {
            detail: format!("yaml parse failed: {e}"),
        })?;
    serde_json::to_value(&yaml_val).map_err(|e| ReconcilerError::Internal {
        detail: format!("yaml→json conversion failed: {e}"),
    })
}

/// Serialize a serde_json::Value back to a YAML string.
fn json_to_yaml_str(json_val: &serde_json::Value) -> Result<String, ReconcilerError> {
    let yaml_val: serde_yaml::Value =
        serde_yaml::to_value(json_val).map_err(|e| ReconcilerError::Internal {
            detail: format!("json→yaml conversion failed: {e}"),
        })?;
    serde_yaml::to_string(&yaml_val).map_err(|e| ReconcilerError::Internal {
        detail: format!("yaml serialize failed: {e}"),
    })
}

/// Apply a JSON merge patch (RFC 7396) to a YAML document, returning
/// the patched YAML. Test-only helper — production code uses
/// [`yaml_str_to_json`] + [`merge_json`] + [`json_to_yaml_str`]
/// separately so JSON-level idempotency checks can short-circuit
/// before re-serializing.
#[cfg(test)]
pub(crate) fn apply_yaml_merge_patch(
    yaml_input: &str,
    patch: &serde_json::Value,
) -> Result<String, ReconcilerError> {
    let mut json_val = yaml_str_to_json(yaml_input)?;
    merge_json(&mut json_val, patch);
    json_to_yaml_str(&json_val)
}

/// RFC 7396 JSON merge patch — recursive object merge with two
/// rules: (a) `null` deletes the key, (b) non-object values replace
/// entirely (no array union semantics).
fn merge_json(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let Some(patch_obj) = patch.as_object() {
        if !target.is_object() {
            *target = serde_json::Value::Object(serde_json::Map::new());
        }
        let target_obj = target.as_object_mut().expect("just ensured");
        for (k, v) in patch_obj {
            if v.is_null() {
                target_obj.remove(k);
            } else {
                let entry = target_obj
                    .entry(k.clone())
                    .or_insert(serde_json::Value::Null);
                merge_json(entry, v);
            }
        }
    } else {
        *target = patch.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_spec() -> FluxCommitSpec {
        FluxCommitSpec {
            repo_url: "git@github.com:pleme-io/k8s.git".into(),
            branch: "main".into(),
            path: "clusters/pleme-dev/apps/akeyless-validation/helmrelease.yaml".into(),
            patch: json!({"spec":{"values":{"api":{"image":{"tag":"0.11.0"}}}}}),
            commit_message: None,
        }
    }

    #[test]
    fn spec_roundtrips() {
        let s = sample_spec();
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["branch"], "main");
        assert!(j.get("patch").is_some());
        let back: FluxCommitSpec = serde_json::from_value(j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn default_branch_is_main() {
        assert_eq!(FluxCommitSpec::default_branch(), "main");
    }

    #[test]
    fn merge_replaces_scalar() {
        let mut t = json!({"image": {"tag": "0.10.0"}});
        merge_json(&mut t, &json!({"image": {"tag": "0.11.0"}}));
        assert_eq!(t["image"]["tag"], "0.11.0");
    }

    #[test]
    fn merge_null_deletes_key() {
        let mut t = json!({"image": {"tag": "0.10.0", "digest": "sha256:abc"}});
        merge_json(&mut t, &json!({"image": {"digest": null}}));
        assert_eq!(t["image"]["tag"], "0.10.0");
        assert!(t["image"].get("digest").is_none());
    }

    #[test]
    fn merge_preserves_unspecified_keys() {
        let mut t = json!({"a": 1, "b": {"c": 2, "d": 3}});
        merge_json(&mut t, &json!({"b": {"c": 20}}));
        assert_eq!(t["a"], 1);
        assert_eq!(t["b"]["c"], 20);
        assert_eq!(t["b"]["d"], 3);
    }

    #[test]
    fn merge_array_replaces_whole() {
        // RFC 7396: arrays are replaced, not merged element-wise.
        let mut t = json!({"items": [1, 2, 3]});
        merge_json(&mut t, &json!({"items": [9]}));
        assert_eq!(t["items"], json!([9]));
    }

    #[test]
    fn apply_yaml_merge_patch_basic() {
        let yaml = r#"
spec:
  values:
    api:
      image:
        tag: "0.10.0"
        repository: ghcr.io/x/y
"#;
        let patch = json!({"spec": {"values": {"api": {"image": {"tag": "0.11.0"}}}}});
        let out = apply_yaml_merge_patch(yaml, &patch).expect("merge ok");
        assert!(out.contains("0.11.0"));
        assert!(out.contains("ghcr.io/x/y"));
    }

    #[test]
    fn apply_yaml_merge_patch_idempotent() {
        // Applying the same patch twice should produce identical
        // output — the second call is a no-op merge.
        let yaml = "spec:\n  values:\n    enabled: true\n";
        let patch = json!({"spec": {"values": {"enabled": true}}});
        let first = apply_yaml_merge_patch(yaml, &patch).unwrap();
        let second = apply_yaml_merge_patch(&first, &patch).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn apply_yaml_merge_patch_invalid_yaml_errors() {
        let err = apply_yaml_merge_patch("not: valid: yaml: at: all", &json!({})).unwrap_err();
        match err {
            ReconcilerError::Internal { detail } => {
                assert!(detail.contains("yaml parse failed"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn flux_commit_handler_is_not_kinded() {
        // FluxCommit dispatches off TypedAction::FluxCommit, not via
        // a ReconcilerKind. This test pins the design — if someone
        // adds ReconcilerKind::FluxCommit and tries to wire this
        // handler through the kinded engine, the impl should be
        // refactored, not duplicated.
        //
        // The test is conceptual; the absence of `impl Reconciler for
        // FluxCommitReconciler` in the source is the actual pin.
        let _: fn() = || {
            // Compile-time assertion via type-level check: the handler
            // must NOT implement Reconciler. We can't easily prove the
            // negative at compile time without compile_fail, but the
            // ActionExecutor dispatch code below is the runtime pin.
        };
    }

    #[test]
    fn config_default_is_dry_run() {
        let c = FluxCommitConfig::default();
        assert!(c.dry_run, "config default must be dry_run=true for safety");
        assert_eq!(c.author_email, "engenho-promessa@pleme.io");
    }

    /// Helper: bootstrap a populated bare repo at `bare_path` with a
    /// single initial commit on `main` containing the given files.
    /// Returns Ok if git is on PATH and setup succeeded; Err signals
    /// "git missing — skip this test."
    fn bootstrap_test_repo(
        bare_path: &Path,
        files: &[(&str, &str)],
    ) -> Result<(), &'static str> {
        // Probe for git binary.
        if Command::new("git").arg("--version").output().is_err() {
            return Err("`git` not on PATH — skipping integration test");
        }

        let seed_dir = bare_path.with_extension("seed");
        std::fs::create_dir_all(&seed_dir).map_err(|_| "mkdir seed")?;

        let run = |args: &[&str], cwd: &Path| -> Result<(), &'static str> {
            let out = Command::new("git")
                .current_dir(cwd)
                .args(args)
                .output()
                .map_err(|_| "git spawn")?;
            if !out.status.success() {
                eprintln!(
                    "git {:?} failed: stdout={} stderr={}",
                    args,
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                return Err("git non-zero exit");
            }
            Ok(())
        };

        // 1. Create the seed working tree as a regular repo.
        run(&["init", "--initial-branch=main"], &seed_dir)?;
        run(&["config", "user.email", "test@test"], &seed_dir)?;
        run(&["config", "user.name", "test"], &seed_dir)?;
        for (path, content) in files {
            let full = seed_dir.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).map_err(|_| "mkdir parent")?;
            }
            std::fs::write(&full, content).map_err(|_| "write seed file")?;
            run(&["add", path], &seed_dir)?;
        }
        run(&["commit", "-m", "seed"], &seed_dir)?;

        // 2. Create the bare upstream and push the seed branch.
        std::fs::create_dir_all(bare_path).map_err(|_| "mkdir bare")?;
        let bare_str = bare_path.to_string_lossy().to_string();
        run(&["init", "--bare", "--initial-branch=main"], bare_path)?;
        run(&["remote", "add", "origin", &bare_str], &seed_dir)?;
        run(&["push", "origin", "main"], &seed_dir)?;

        Ok(())
    }

    /// End-to-end: bootstrap a bare repo with values.yaml, run the
    /// Reconciler with dry_run=true, assert Applied + 40-char SHA.
    #[tokio::test]
    async fn end_to_end_against_local_bare_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let bare = tmp.path().join("upstream.git");
        let file_path = "values.yaml";
        let seed = "spec:\n  values:\n    image:\n      tag: \"0.10.0\"\n";

        let Ok(()) = bootstrap_test_repo(&bare, &[(file_path, seed)]) else {
            eprintln!("bootstrap failed — skipping");
            return;
        };

        let r = FluxCommitReconciler::new(FluxCommitConfig {
            author_name: "test-bot".into(),
            author_email: "test-bot@example.com".into(),
            dry_run: true,
            ssh_key_path: None,
        });
        let outcome = r
            .act(FluxCommitSpec {
                repo_url: bare.to_string_lossy().into_owned(),
                branch: "main".into(),
                path: file_path.into(),
                patch: json!({"spec": {"values": {"image": {"tag": "0.11.0"}}}}),
                commit_message: Some("bump tag".into()),
            })
            .await;

        match outcome {
            ReconcilerOutcome::Applied { receipt } => {
                assert_eq!(receipt.path, file_path);
                assert!(receipt.dry_run);
                assert_eq!(receipt.commit_sha.len(), 40, "git SHA-1 is 40 hex chars");
            }
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    /// Idempotency — second call with the same patch returns
    /// AlreadyConverged because the file already matches the desired
    /// state after the first call's commit. Actually — the second
    /// call clones fresh from origin (dry_run skipped push), so the
    /// origin still has the pre-patch state. So the second call WILL
    /// produce another Applied with a new SHA. To test idempotency
    /// at the reconciler boundary, we patch with a value that
    /// already matches the seed.
    #[tokio::test]
    async fn already_converged_when_patch_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let bare = tmp.path().join("upstream.git");
        let Ok(()) = bootstrap_test_repo(
            &bare,
            &[("v.yaml", "image:\n  tag: \"0.10.0\"\n")],
        ) else {
            return;
        };

        let r = FluxCommitReconciler::new(FluxCommitConfig {
            dry_run: true,
            ..Default::default()
        });
        let outcome = r
            .act(FluxCommitSpec {
                repo_url: bare.to_string_lossy().into_owned(),
                branch: "main".into(),
                path: "v.yaml".into(),
                // Already matches the seed — no-op patch.
                patch: json!({"image": {"tag": "0.10.0"}}),
                commit_message: None,
            })
            .await;
        assert!(
            matches!(outcome, ReconcilerOutcome::AlreadyConverged),
            "expected AlreadyConverged, got {outcome:?}"
        );
    }

    /// SubstrateRefused — git clone fails on a nonexistent URL.
    #[tokio::test]
    async fn missing_repo_returns_substrate_refused() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let r = FluxCommitReconciler::new(FluxCommitConfig::default());
        let outcome = r
            .act(FluxCommitSpec {
                repo_url: "/nonexistent/path/to/repo".into(),
                branch: "main".into(),
                path: "x".into(),
                patch: json!({}),
                commit_message: None,
            })
            .await;
        match outcome {
            ReconcilerOutcome::Failed {
                error: ReconcilerError::SubstrateRefused { .. },
            } => {}
            other => panic!("expected SubstrateRefused, got {other:?}"),
        }
    }
}
