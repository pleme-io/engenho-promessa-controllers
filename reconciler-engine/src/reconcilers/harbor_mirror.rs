//! `HarborMirrorReconciler` — copy a Zot-resident digest forward to
//! Second Front's Harbor registry (`registry.secondfront.com`).
//!
//! ## Standing rule (2026-05-22, Luis)
//!
//! > "right now sending to second front should be turned off"
//!
//! This Reconciler ships with its full copy path implemented, but the
//! standing default keeps it dormant: [`Reconciler::act`] returns
//! [`promessa_types::ReconcilerOutcome::FlagGated`] whenever
//! `spec.flag_enabled` is `false` — which is the standing default per
//! [`helmworks-akeyless/charts/lareira-akeyless-validation/
//! values.yaml:237`] (`gameWardenForwarding.enabled: false`). That
//! flag-gate check is the FIRST thing `act` does, unconditionally,
//! before any I/O against Zot or Harbor — do not reorder it below the
//! `skopeo copy` dispatch.
//!
//! Flipping the flag is intentionally a two-PR maneuver per D6
//! (sekiban CompliancePolicy `forbid-harbor-mirror-without-approval`).
//!
//! ## Defense in depth
//!
//! The security-controller already checks the flag before emitting a
//! HarborMirror typed action (security-controller/src/lib.rs — search
//! `harbor_forwarding_enabled`). This Reconciler re-checks the flag at
//! execution time — if either layer is buggy, the other catches it.
//! Both must agree for any image to flow to Second Front.
//!
//! ## What it wraps
//!
//! ```text
//! skopeo copy --preserve-digests --all \
//!     docker://<zot>/<source_repo>@<digest> \
//!     docker://registry.secondfront.com/<target_project>/<image>@<digest>
//! ```
//!
//! where `<image>` is the last path segment of `source_repo` — see
//! [`image_name_for`]. The destination is addressed by digest (not a
//! tag), so `--preserve-digests` plus a digest-pinned destination is
//! itself skopeo's guarantee that the copy either lands at exactly
//! `spec.source_digest` or fails; [`act`](Reconciler::act) additionally
//! re-checks the digest skopeo reports back (via `--digestfile`)
//! against `spec.source_digest` as a second, typed confirmation.
//!
//! Subprocess execution is abstracted behind [`SkopeoRunner`] — the
//! Environment-trait testability contract from the ★★ TYPED-SPEC +
//! INTERPRETER TRIPLET rule (same shape as `validation-jobs::ScanExecutor`).
//! [`SystemSkopeoRunner`] is the real impl (shells out to the `skopeo`
//! binary via `std::process::Command`, matching the
//! [`crate::reconcilers::flux_commit`] subprocess idiom); tests inject
//! a mock so the copy logic is exercised without a real registry.
//!
//! Pre-flight verification that the digest's cartorio status is
//! `Active`, that `AkeylessImageValidation.status.phase == Passed`,
//! and that an `ApprovedHarborForwarding` CR exists for the digest set
//! (admission-gated by sekiban per D6) happens upstream of this
//! Reconciler — in the SecurityController's `decide` step that
//! constructs the `TypedAction::ReconcilerApply` in the first place.
//! This Reconciler's only job is the copy + the flag re-check.

use std::process::Command;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use promessa_controller_common::reconciler_laws_obeyed;
use promessa_types::{Reconciler, ReconcilerError, ReconcilerKind, ReconcilerOutcome};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::BasicAuth;

/// The canonical name for the feature flag this Reconciler checks.
/// Matches `helmworks-akeyless/charts/lareira-akeyless-validation/
/// values.yaml` key `gameWardenForwarding.enabled` and the
/// security-controller's `SecuritySpec::harbor_forwarding_enabled`.
pub const HARBOR_FLAG: &str = "gameWardenForwarding.enabled";

/// Typed input for [`HarborMirrorReconciler::act`].
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct HarborMirrorSpec {
    /// Source repository — the akeylesslabs-org-relative name.
    /// Example: `"akeyless-auth"`. The full source URL is built from
    /// the engine's Zot base URL.
    pub source_repo: String,

    /// Source digest — the OCI manifest digest at the source.
    /// Example: `"sha256:abc..."`. Preserved at the target.
    pub source_digest: String,

    /// Target Harbor project. For Second Front, always `"akeyless"`.
    pub target_project: String,

    /// Whether to preserve the source digest at the target (always
    /// `true` in production). Threaded straight into skopeo's
    /// `--preserve-digests` flag.
    pub preserve_digest: bool,

    /// **Defense-in-depth final guard.** The security-controller
    /// gates emission of HarborMirror on the same flag; this field
    /// is the Reconciler-side re-check. If `false`, the Reconciler
    /// refuses without contacting Harbor.
    pub flag_enabled: bool,
}

/// Typed receipt for a successful mirror.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
pub struct HarborMirrorReceipt {
    pub source_url: String,
    pub target_url: String,
    pub source_digest: String,
    /// Digest skopeo reported back via `--digestfile` after the copy.
    /// `act` refuses (`Failed { error: Internal }`) if this ever
    /// diverges from `source_digest` — see the module doc.
    pub target_digest: String,
    /// FOLLOWUP: skopeo has no machine-readable bytes-transferred
    /// report over `copy`; precise accounting would need a follow-up
    /// `skopeo inspect` blob-size summation. Always `0` today — an
    /// honest placeholder, not a measured value.
    pub bytes_copied: u64,
    pub copied_at: chrono::DateTime<Utc>,
}

/// Side-effect boundary for the `skopeo copy` invocation — the
/// Environment-trait testability contract (★★ TYPED-SPEC + INTERPRETER
/// TRIPLET). [`SystemSkopeoRunner`] is the production impl; tests
/// inject a mock so [`HarborMirrorReconciler::act`]'s branching logic
/// (success / auth failure / transient failure / digest mismatch) is
/// covered without a real skopeo subprocess or a real registry.
#[async_trait]
pub trait SkopeoRunner: Send + Sync + 'static {
    async fn copy(&self, req: &SkopeoCopyRequest) -> Result<SkopeoCopyOutcome, ReconcilerError>;
}

/// One `skopeo copy` request, fully resolved (URLs built, creds
/// attached) by [`HarborMirrorReconciler::act`] before it reaches the
/// [`SkopeoRunner`].
#[derive(Debug, Clone)]
pub struct SkopeoCopyRequest {
    /// `docker://<zot>/<repo>@<digest>`
    pub source_url: String,
    /// `docker://registry.secondfront.com/<project>/<image>@<digest>`
    pub target_url: String,
    pub preserve_digests: bool,
    pub src_creds: Option<BasicAuth>,
    pub dest_creds: Option<BasicAuth>,
}

/// What a successful `skopeo copy` reports back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkopeoCopyOutcome {
    /// The digest skopeo wrote to `--digestfile` — what actually
    /// landed at the destination.
    pub digest: String,
}

/// Production [`SkopeoRunner`] — shells out to the real `skopeo`
/// binary. The `engenho-promessa` OCI image adds `skopeo` to its
/// `contents` so the Reconciler has the binary at runtime (same
/// pattern as `flux_commit`'s `git` dependency).
pub struct SystemSkopeoRunner;

#[async_trait]
impl SkopeoRunner for SystemSkopeoRunner {
    async fn copy(&self, req: &SkopeoCopyRequest) -> Result<SkopeoCopyOutcome, ReconcilerError> {
        let req = req.clone();
        // Subprocess is sync; same `spawn_blocking` idiom as
        // `flux_commit::FluxCommitReconciler::act` for a single
        // sequential CLI call.
        match tokio::task::spawn_blocking(move || run_skopeo_copy(&req)).await {
            Ok(result) => result,
            Err(join_err) => Err(ReconcilerError::Internal {
                detail: format!("skopeo copy blocking task panicked: {join_err}"),
            }),
        }
    }
}

/// Pure synchronous pipeline: build the argv, run `skopeo copy`,
/// read back the digest it wrote to `--digestfile`.
fn run_skopeo_copy(req: &SkopeoCopyRequest) -> Result<SkopeoCopyOutcome, ReconcilerError> {
    let digest_file = tempfile::NamedTempFile::new().map_err(|e| ReconcilerError::Internal {
        detail: format!("skopeo copy: tempfile create failed: {e}"),
    })?;

    let mut cmd = Command::new("skopeo");
    cmd.arg("copy");
    if req.preserve_digests {
        cmd.arg("--preserve-digests");
    }
    cmd.arg("--all");
    if let Some(creds) = &req.src_creds {
        cmd.arg("--src-creds").arg(creds.as_skopeo_creds());
    }
    if let Some(creds) = &req.dest_creds {
        cmd.arg("--dest-creds").arg(creds.as_skopeo_creds());
    }
    cmd.arg("--digestfile").arg(digest_file.path());
    cmd.arg(&req.source_url);
    cmd.arg(&req.target_url);

    // Never log the Command's full Debug repr — it would include the
    // `--src-creds`/`--dest-creds` plaintext values. Log only the
    // non-sensitive coordinates + whether creds were present.
    tracing::info!(
        source = %req.source_url,
        target = %req.target_url,
        src_creds = req.src_creds.is_some(),
        dest_creds = req.dest_creds.is_some(),
        "harbor-mirror dispatching skopeo copy"
    );

    let out = cmd.output().map_err(|e| ReconcilerError::Internal {
        detail: format!("skopeo copy spawn failed: {e}"),
    })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return Err(classify_skopeo_failure(out.status.code(), &stderr));
    }

    let digest = std::fs::read_to_string(digest_file.path())
        .map_err(|e| ReconcilerError::Internal {
            detail: format!("skopeo copy: read --digestfile output failed: {e}"),
        })?
        .trim()
        .to_owned();
    if digest.is_empty() {
        return Err(ReconcilerError::Internal {
            detail: "skopeo copy exited 0 but --digestfile was empty".into(),
        });
    }

    Ok(SkopeoCopyOutcome { digest })
}

/// Map skopeo's exit status + stderr onto the engine's typed failure
/// modes. skopeo has no structured/machine-readable error taxonomy
/// (it always exits 1 on failure), so classification is signature
/// matching on stderr — the same idiom this crate already uses for
/// wrapped CLIs that don't expose typed errors (`flux_commit::run_git`
/// classifies every non-zero git exit as `SubstrateRefused`; here we
/// go one step further and split out the two failure classes the
/// engine's retry policy actually treats differently).
fn classify_skopeo_failure(code: Option<i32>, stderr: &str) -> ReconcilerError {
    let lower = stderr.to_lowercase();

    const AUTH_SIGNATURES: &[&str] = &[
        "unauthorized",
        "401",
        "403",
        "authentication required",
        "access denied",
        "forbidden",
    ];
    if AUTH_SIGNATURES.iter().any(|needle| lower.contains(needle)) {
        return ReconcilerError::SubstrateRefused {
            detail: format!("skopeo copy auth failure (exit {code:?}): {stderr}"),
        };
    }

    const NETWORK_SIGNATURES: &[&str] = &[
        "connection refused",
        "connection reset",
        "timed out",
        "timeout",
        "no such host",
        "temporary failure in name resolution",
        "dial tcp",
        "i/o timeout",
    ];
    if NETWORK_SIGNATURES.iter().any(|needle| lower.contains(needle)) {
        return ReconcilerError::Transient {
            detail: format!("skopeo copy transient failure (exit {code:?}): {stderr}"),
        };
    }

    // Anything else (manifest not found, digest mismatch skopeo
    // itself caught, malformed reference, ...) is a clean,
    // deterministic refusal — no retry.
    ReconcilerError::SubstrateRefused {
        detail: format!("skopeo copy failed (exit {code:?}): {stderr}"),
    }
}

/// Strip a `docker://`-incompatible URL scheme + trailing slash so a
/// `EngineConfig` base URL (`https://registry.secondfront.com`,
/// `http://zot.zot-system.svc.cluster.local:5000`) can be embedded in
/// a `docker://host/repo@digest` reference. skopeo's docker transport
/// takes a bare host, never an `http(s)://` prefix.
fn strip_scheme(url: &str) -> &str {
    url.trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
}

/// Derive the destination image name under `target_project` from the
/// source repo's last path segment. `source_repo` in production is
/// the full Zot-relative repo name (e.g. `"akeylesslabs/akeyless-auth"`
/// or `"akeyless-auth"`) — deliberately NOT stripped of any
/// `"akeyless-"` prefix, since that prefix is part of the real,
/// fleet-wide canonical image name (every other Reconciler in this
/// crate treats `"akeyless-<service>"` as an atomic name, never
/// splits it) and inventing a strip rule here would silently rename
/// images in Harbor relative to their Zot identity.
fn image_name_for(source_repo: &str) -> &str {
    source_repo.rsplit('/').next().unwrap_or(source_repo)
}

/// The Reconciler. Holds registry endpoints + credentials for both
/// legs of the copy (Zot as source, Harbor as destination) plus the
/// [`SkopeoRunner`] the copy dispatches through.
pub struct HarborMirrorReconciler {
    harbor_base_url: String,
    harbor_auth: Option<BasicAuth>,
    zot_base_url: String,
    zot_auth: Option<BasicAuth>,
    runner: Arc<dyn SkopeoRunner>,
}

impl HarborMirrorReconciler {
    /// Production constructor — copies dispatch through the real
    /// `skopeo` binary via [`SystemSkopeoRunner`].
    #[must_use]
    pub fn new(
        harbor_base_url: String,
        harbor_auth: Option<BasicAuth>,
        zot_base_url: String,
        zot_auth: Option<BasicAuth>,
    ) -> Self {
        Self::with_runner(
            harbor_base_url,
            harbor_auth,
            zot_base_url,
            zot_auth,
            Arc::new(SystemSkopeoRunner),
        )
    }

    /// Test/advanced constructor — inject any [`SkopeoRunner`],
    /// typically a mock, so `act`'s branching logic is exercised
    /// without a real subprocess or registry.
    #[must_use]
    pub fn with_runner(
        harbor_base_url: String,
        harbor_auth: Option<BasicAuth>,
        zot_base_url: String,
        zot_auth: Option<BasicAuth>,
        runner: Arc<dyn SkopeoRunner>,
    ) -> Self {
        Self { harbor_base_url, harbor_auth, zot_base_url, zot_auth, runner }
    }
}

#[async_trait]
impl Reconciler for HarborMirrorReconciler {
    const KIND: ReconcilerKind = ReconcilerKind::HarborMirror;

    type Spec = HarborMirrorSpec;
    type Receipt = HarborMirrorReceipt;

    async fn act(&self, spec: Self::Spec) -> ReconcilerOutcome<Self::Receipt> {
        // ── Flag-gate — UNCHANGED, must stay first. ──────────────
        // This is the standing-off default (2026-05-22) plus the
        // sekiban-gated Reconciler-side half of the defense-in-depth
        // pair described in the module doc. Nothing below this
        // branch may run before it.
        if !spec.flag_enabled {
            tracing::info!(
                source = %spec.source_repo,
                digest = %spec.source_digest,
                flag = HARBOR_FLAG,
                "harbor-mirror refused — flag is off (standing rule)"
            );
            return ReconcilerOutcome::FlagGated { flag: HARBOR_FLAG.into() };
        }

        // ── Active path — only ever reached when an operator has
        // flipped the flag through the two-PR sekiban maneuver. ────
        let image_name = image_name_for(&spec.source_repo);
        let source_url = format!(
            "docker://{}/{}@{}",
            strip_scheme(&self.zot_base_url),
            spec.source_repo,
            spec.source_digest,
        );
        let target_url = format!(
            "docker://{}/{}/{}@{}",
            strip_scheme(&self.harbor_base_url),
            spec.target_project,
            image_name,
            spec.source_digest,
        );

        let req = SkopeoCopyRequest {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            preserve_digests: spec.preserve_digest,
            src_creds: self.zot_auth.clone(),
            dest_creds: self.harbor_auth.clone(),
        };

        match self.runner.copy(&req).await {
            Ok(outcome) => {
                // Defensive digest confirmation: preserve_digest=true
                // asked skopeo to land exactly at spec.source_digest.
                // If the runner ever reports something else, that's a
                // substrate-primitive invariant violation (or a
                // misconfigured SkopeoRunner), not a normal failure
                // mode — surface it loudly rather than writing a
                // receipt that silently lies about what was mirrored.
                if outcome.digest != spec.source_digest {
                    return ReconcilerOutcome::Failed {
                        error: ReconcilerError::Internal {
                            detail: format!(
                                "harbor-mirror: skopeo reported target digest {} but expected {} \
                                 (preserve-digests violated) — source={source_url} \
                                 target={target_url}",
                                outcome.digest, spec.source_digest
                            ),
                        },
                    };
                }
                ReconcilerOutcome::Applied {
                    receipt: HarborMirrorReceipt {
                        source_url,
                        target_url,
                        source_digest: spec.source_digest.clone(),
                        target_digest: outcome.digest,
                        bytes_copied: 0,
                        copied_at: Utc::now(),
                    },
                }
            }
            Err(error) => ReconcilerOutcome::Failed { error },
        }
    }
}

reconciler_laws_obeyed!(HarborMirrorReconciler);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn spec(flag_enabled: bool) -> HarborMirrorSpec {
        HarborMirrorSpec {
            source_repo: "akeylesslabs/akeyless-auth".into(),
            source_digest: "sha256:abc123".into(),
            target_project: "akeyless".into(),
            preserve_digest: true,
            flag_enabled,
        }
    }

    fn reconciler(runner: Arc<dyn SkopeoRunner>) -> HarborMirrorReconciler {
        HarborMirrorReconciler::with_runner(
            "https://registry.secondfront.com".into(),
            None,
            "http://zot.zot-system.svc.cluster.local:5000".into(),
            None,
            runner,
        )
    }

    /// Mock that panics if ever called — makes the flag-gate test a
    /// structural proof (not just an outcome-shape check): if the
    /// gate check in `act` ever moved below the runner dispatch, this
    /// panics instead of quietly asserting the wrong outcome.
    struct PanicIfCalledRunner;

    #[async_trait]
    impl SkopeoRunner for PanicIfCalledRunner {
        async fn copy(
            &self,
            _req: &SkopeoCopyRequest,
        ) -> Result<SkopeoCopyOutcome, ReconcilerError> {
            panic!("SkopeoRunner::copy must never be called while spec.flag_enabled is false");
        }
    }

    /// Mock returning one canned result, capturing the request it was
    /// called with so tests can assert on what `act` would have sent
    /// to skopeo (creds, preserve-digests, URLs).
    struct MockRunner {
        result: Mutex<Option<Result<SkopeoCopyOutcome, ReconcilerError>>>,
        last_request: Mutex<Option<SkopeoCopyRequest>>,
    }

    impl MockRunner {
        fn new(result: Result<SkopeoCopyOutcome, ReconcilerError>) -> Self {
            Self { result: Mutex::new(Some(result)), last_request: Mutex::new(None) }
        }
    }

    #[async_trait]
    impl SkopeoRunner for MockRunner {
        async fn copy(
            &self,
            req: &SkopeoCopyRequest,
        ) -> Result<SkopeoCopyOutcome, ReconcilerError> {
            *self.last_request.lock().expect("lock poisoned") = Some(req.clone());
            self.result
                .lock()
                .expect("lock poisoned")
                .take()
                .expect("MockRunner::copy called more than once in this test")
        }
    }

    // ── Flag-gate: unchanged behavior, re-proven structurally ──────

    #[tokio::test]
    async fn flag_off_short_circuits_before_any_runner_call() {
        let r = reconciler(Arc::new(PanicIfCalledRunner));
        let outcome = r.act(spec(false)).await;
        match outcome {
            ReconcilerOutcome::FlagGated { flag } => {
                assert_eq!(flag, HARBOR_FLAG);
            }
            other => panic!("expected FlagGated, got {other:?}"),
        }
    }

    // ── Active path: success ────────────────────────────────────────

    #[tokio::test]
    async fn flag_on_successful_copy_produces_applied_receipt() {
        let runner = MockRunner::new(Ok(SkopeoCopyOutcome { digest: "sha256:abc123".into() }));
        let r = reconciler(Arc::new(runner));
        let outcome = r.act(spec(true)).await;
        match outcome {
            ReconcilerOutcome::Applied { receipt } => {
                assert_eq!(receipt.source_digest, "sha256:abc123");
                assert_eq!(receipt.target_digest, "sha256:abc123");
                assert_eq!(
                    receipt.source_url,
                    "docker://zot.zot-system.svc.cluster.local:5000/akeylesslabs/akeyless-auth@sha256:abc123"
                );
                assert_eq!(
                    receipt.target_url,
                    "docker://registry.secondfront.com/akeyless/akeyless-auth@sha256:abc123"
                );
            }
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn flag_on_passes_preserve_digests_and_creds_through_to_runner() {
        let runner =
            Arc::new(MockRunner::new(Ok(SkopeoCopyOutcome { digest: "sha256:abc123".into() })));
        let r = HarborMirrorReconciler::with_runner(
            "https://registry.secondfront.com".into(),
            Some(BasicAuth { username: "harbor-bot".into(), password: "hpw".into() }),
            "http://zot.local:5000".into(),
            Some(BasicAuth { username: "zot-bot".into(), password: "zpw".into() }),
            runner.clone(),
        );
        let outcome = r.act(spec(true)).await;
        assert!(matches!(outcome, ReconcilerOutcome::Applied { .. }));

        let req = runner
            .last_request
            .lock()
            .expect("lock poisoned")
            .clone()
            .expect("runner was called");
        assert!(req.preserve_digests);
        assert_eq!(req.src_creds.expect("src creds set").username, "zot-bot");
        assert_eq!(req.dest_creds.expect("dest creds set").username, "harbor-bot");
    }

    // ── Active path: failures ───────────────────────────────────────

    #[tokio::test]
    async fn flag_on_skopeo_exit_failure_maps_to_substrate_refused() {
        let runner = MockRunner::new(Err(classify_skopeo_failure(
            Some(1),
            "manifest unknown: manifest tagged by \"x\" is not found",
        )));
        let r = reconciler(Arc::new(runner));
        let outcome = r.act(spec(true)).await;
        match outcome {
            ReconcilerOutcome::Failed { error: ReconcilerError::SubstrateRefused { detail } } => {
                assert!(detail.contains("manifest unknown"));
            }
            other => panic!("expected SubstrateRefused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn flag_on_auth_failure_maps_to_substrate_refused_not_retryable() {
        let runner = MockRunner::new(Err(classify_skopeo_failure(
            Some(1),
            "unauthorized: authentication required",
        )));
        let r = reconciler(Arc::new(runner));
        let outcome = r.act(spec(true)).await;
        match outcome {
            ReconcilerOutcome::Failed { error } => {
                assert!(!error.is_retryable(), "auth failures must not auto-retry");
                match error {
                    ReconcilerError::SubstrateRefused { detail } => {
                        assert!(detail.to_lowercase().contains("unauthorized"));
                    }
                    other => panic!("expected SubstrateRefused, got {other:?}"),
                }
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn flag_on_network_failure_is_retryable_transient() {
        let runner = MockRunner::new(Err(classify_skopeo_failure(None, "dial tcp: connection refused")));
        let r = reconciler(Arc::new(runner));
        let outcome = r.act(spec(true)).await;
        match outcome {
            ReconcilerOutcome::Failed { error } => {
                assert!(error.is_retryable(), "transient registry errors must be retryable");
                assert!(matches!(error, ReconcilerError::Transient { .. }));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn flag_on_digest_mismatch_maps_to_internal_error() {
        // Defensive check: preserve_digest=true asked skopeo to land
        // at spec.source_digest; if the runner ever reports a
        // different digest, that's an invariant violation, not a
        // normal failure mode.
        let runner = MockRunner::new(Ok(SkopeoCopyOutcome { digest: "sha256:different".into() }));
        let r = reconciler(Arc::new(runner));
        let outcome = r.act(spec(true)).await;
        match outcome {
            ReconcilerOutcome::Failed { error: ReconcilerError::Internal { detail } } => {
                assert!(detail.contains("preserve-digests violated"));
            }
            other => panic!("expected Internal digest-mismatch error, got {other:?}"),
        }
    }

    // ── Pure-function unit coverage ─────────────────────────────────

    #[test]
    fn classify_skopeo_failure_detects_auth() {
        let e = classify_skopeo_failure(Some(1), "Error: unauthorized: authentication required");
        assert!(matches!(e, ReconcilerError::SubstrateRefused { .. }));
        assert!(!e.is_retryable());
    }

    #[test]
    fn classify_skopeo_failure_detects_network() {
        let e = classify_skopeo_failure(Some(1), "dial tcp: connection refused");
        assert!(matches!(e, ReconcilerError::Transient { .. }));
        assert!(e.is_retryable());
    }

    #[test]
    fn classify_skopeo_failure_generic_is_substrate_refused_not_retryable() {
        let e = classify_skopeo_failure(Some(1), "manifest unknown: not found");
        assert!(matches!(e, ReconcilerError::SubstrateRefused { .. }));
        assert!(!e.is_retryable());
    }

    #[test]
    fn image_name_for_takes_last_path_segment_no_prefix_stripping() {
        assert_eq!(image_name_for("akeylesslabs/akeyless-auth"), "akeyless-auth");
        assert_eq!(image_name_for("akeyless-auth"), "akeyless-auth");
    }

    #[test]
    fn strip_scheme_removes_scheme_and_trailing_slash() {
        assert_eq!(strip_scheme("https://registry.secondfront.com/"), "registry.secondfront.com");
        assert_eq!(strip_scheme("http://zot.local:5000"), "zot.local:5000");
    }

    #[test]
    fn spec_roundtrips() {
        let s = spec(false);
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["flag_enabled"], false);
        let back: HarborMirrorSpec = serde_json::from_value(j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn flag_constant_matches_values_yaml() {
        // Pin: the Helm chart values key must stay in sync with this
        // constant. If you change the chart's flag path, change
        // this constant too — or the dormant guard silently fails.
        assert_eq!(HARBOR_FLAG, "gameWardenForwarding.enabled");
    }

    #[test]
    fn flag_gated_outcome_is_terminal_success() {
        let o: ReconcilerOutcome<HarborMirrorReceipt> =
            ReconcilerOutcome::FlagGated { flag: HARBOR_FLAG.into() };
        // The engine treats FlagGated as terminal success — the
        // SecurityController already considered the flag in its
        // Decision, and the Reconciler is the second defensive layer.
        assert!(o.is_terminal_success());
    }
}
