//! `validation-jobs` — the per-image scan work graph as a typed
//! `shigoto` Dag of Jobs.
//!
//! Per the org ★★ "shigoto for every work graph" directive, the
//! controllers' internal work graph is a shigoto Dag, not a hand-rolled
//! phase ladder + `all_terminal` poll. The kube-rs reconcilers stay the
//! TRIGGER (watch CRs); this crate owns the WORK GRAPH each reconcile
//! drives:
//!
//! ```text
//!   epc.scan-cve  ─┐
//!   epc.scan-sast ─┼─▶ epc.aggregate        (fan-out → fan-in)
//!   epc.scan-dast ─┘
//! ```
//!
//! The fan-in barrier is structural: shigoto's implicit
//! `AllUpstreamsTerminal` gate holds `epc.aggregate` until every
//! `epc.scan-*` is terminal — replacing the brittle
//! `image_validation.rs` "list children, check all_terminal" poll. The
//! three scans run concurrently in one scheduler wave (JoinSet).
//!
//! Side effects (creating the K8s scan Job, collecting pod logs) are
//! abstracted behind the [`ScanExecutor`] trait — the Environment-trait
//! testability contract from the ★★ TYPED-SPEC + INTERPRETER TRIPLET
//! rule. Real impls talk to kube; tests mock it. This module is the
//! minimal proof-of-pattern slice (M0); the live-reconcile integration
//! (call this from `handle_scanning`) and the build/push/submit Jobs are
//! the follow-on.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shigoto_dag::Dag;
use shigoto_scheduler::InProcessScheduler;
use shigoto_types::{Job, JobId, JobScope, JobSubject, OutputSink, RecordingJob};

// ── Job kind ids ─────────────────────────────────────────────────────
pub const SCAN_KIND: &str = "epc.scan";
pub const AGGREGATE_KIND: &str = "epc.aggregate";

// ── Typed outcomes ───────────────────────────────────────────────────

/// One finding surfaced by a scanner (simplified projection of the
/// CRD `ScanFinding` — the crate boundary stays dependency-light).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub scanner: String,
    pub severity: String,
    pub cve_id: Option<String>,
}

/// Output of one `epc.scan-*` Job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub scanner: String,
    pub findings: Vec<Finding>,
    /// blake3 over the canonical findings bytes.
    pub hash: String,
}

/// Output of the `epc.aggregate` Job (the fan-in).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateOutcome {
    pub digest: String,
    pub total_findings: usize,
    pub scanners_reported: usize,
    pub evidence_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("scan invocation failed: {0}")]
    Invocation(String),
}

// ── Environment trait (the testability contract) ─────────────────────

/// Side-effect boundary for running one scanner against one image. Real
/// impls render + create a K8s Job and collect its pod logs; tests mock.
#[async_trait]
pub trait ScanExecutor: Send + Sync + 'static {
    async fn run_scan(&self, scanner: &str, image_ref: &str) -> Result<ScanOutcome, ScanError>;
}

// ── Output capture sink ──────────────────────────────────────────────

/// In-memory [`OutputSink`] keyed by `JobId`. The scan Jobs write their
/// `ScanOutcome` here on success; the aggregate Job reads them back
/// (it runs after all scans per the DAG edges, so the map is complete).
#[derive(Clone, Default)]
pub struct ScanResultSink {
    inner: Arc<Mutex<HashMap<JobId, ScanOutcome>>>,
}

impl ScanResultSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every captured outcome.
    #[must_use]
    pub fn outcomes(&self) -> Vec<ScanOutcome> {
        self.inner.lock().expect("sink poisoned").values().cloned().collect()
    }
}

#[async_trait]
impl OutputSink<ScanOutcome> for ScanResultSink {
    async fn record(&self, job_id: &JobId, output: &ScanOutcome) {
        self.inner
            .lock()
            .expect("sink poisoned")
            .insert(job_id.clone(), output.clone());
    }
}

// ── epc.scan-* Job ───────────────────────────────────────────────────

/// One scanner against one image. `subject = Pinned(image_digest)` (the
/// shigoto identity escape hatch for non-repo subjects); `kind` carries
/// the scanner. Generic over the [`ScanExecutor`] so production wiring
/// and tests share the type.
pub struct ScanJob<E: ScanExecutor> {
    pub namespace: String,
    pub image_digest: String,
    pub image_ref: String,
    pub scanner: String,
    executor: Arc<E>,
    sink: Arc<dyn OutputSink<ScanOutcome>>,
}

impl<E: ScanExecutor> ScanJob<E> {
    pub fn new(
        namespace: impl Into<String>,
        image_digest: impl Into<String>,
        image_ref: impl Into<String>,
        scanner: impl Into<String>,
        executor: Arc<E>,
        sink: Arc<dyn OutputSink<ScanOutcome>>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            image_digest: image_digest.into(),
            image_ref: image_ref.into(),
            scanner: scanner.into(),
            executor,
            sink,
        }
    }
}

#[async_trait]
impl<E: ScanExecutor> RecordingJob for ScanJob<E> {
    type Output = ScanOutcome;
    type Error = ScanError;
    // One kind id per scanner class would let the scheduler cap each
    // class's concurrency via BudgetTree.by_kind; M0 keeps one kind.
    const KIND: &'static str = SCAN_KIND;

    fn scope(&self) -> JobScope {
        JobScope::Workspace(self.namespace.clone())
    }

    fn subject(&self) -> JobSubject {
        // The image digest is not a repo — `Pinned` is the typed escape
        // hatch. Combined with `kind`+scanner the JobId is unique per
        // (image, scanner).
        JobSubject::Pinned(format!("{}@{}", self.scanner, self.image_digest))
    }

    fn output_sink(&self) -> Option<&Arc<dyn OutputSink<Self::Output>>> {
        Some(&self.sink)
    }

    async fn execute_body(&self) -> Result<ScanOutcome, ScanError> {
        self.executor.run_scan(&self.scanner, &self.image_ref).await
    }
}

// ── epc.aggregate Job ────────────────────────────────────────────────

/// Fan-in: reads every upstream `ScanOutcome` from the shared sink and
/// folds them into one [`AggregateOutcome`] with a blake3 evidence hash.
/// Runs only after all scans are terminal (DAG edges + AllUpstreamsTerminal).
pub struct AggregateJob {
    pub namespace: String,
    pub image_digest: String,
    results: ScanResultSink,
}

impl AggregateJob {
    pub fn new(
        namespace: impl Into<String>,
        image_digest: impl Into<String>,
        results: ScanResultSink,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            image_digest: image_digest.into(),
            results,
        }
    }
}

#[async_trait]
impl RecordingJob for AggregateJob {
    type Output = AggregateOutcome;
    type Error = ScanError;
    const KIND: &'static str = AGGREGATE_KIND;

    fn scope(&self) -> JobScope {
        JobScope::Workspace(self.namespace.clone())
    }

    fn subject(&self) -> JobSubject {
        JobSubject::Pinned(self.image_digest.clone())
    }

    fn output_sink(&self) -> Option<&Arc<dyn OutputSink<Self::Output>>> {
        None
    }

    async fn execute_body(&self) -> Result<AggregateOutcome, ScanError> {
        let outcomes = self.results.outcomes();
        let mut findings: Vec<Finding> = outcomes.iter().flat_map(|o| o.findings.clone()).collect();
        // Canonical order: (scanner, cve_id).
        findings.sort_by(|a, b| {
            a.scanner.cmp(&b.scanner).then(a.cve_id.cmp(&b.cve_id))
        });
        let canonical = serde_bytes_of(&findings);
        let evidence_hash = blake3::hash(&canonical).to_hex().to_string();
        Ok(AggregateOutcome {
            digest: self.image_digest.clone(),
            total_findings: findings.len(),
            scanners_reported: outcomes.len(),
            evidence_hash,
        })
    }
}

fn serde_bytes_of(findings: &[Finding]) -> Vec<u8> {
    // Stable byte view for hashing — length-prefixed fields, no serde dep.
    let mut out = Vec::new();
    for f in findings {
        out.extend_from_slice(f.scanner.as_bytes());
        out.push(0);
        out.extend_from_slice(f.severity.as_bytes());
        out.push(0);
        out.extend_from_slice(f.cve_id.as_deref().unwrap_or("").as_bytes());
        out.push(0);
    }
    out
}

// ── Dag assembly ─────────────────────────────────────────────────────

/// Build the scan-fanout → aggregate Dag for one image and register
/// every Job on the scheduler. Returns the assembled Dag ready to tick.
///
/// `scanners` is the per-image scanner roster (CVE/SAST/DAST...). Each
/// becomes an `epc.scan` node with an edge into the single
/// `epc.aggregate` node — the structural fan-in barrier.
pub async fn build_scan_dag<E: ScanExecutor>(
    scheduler: &InProcessScheduler,
    namespace: &str,
    image_digest: &str,
    image_ref: &str,
    scanners: &[&str],
    executor: Arc<E>,
    sink: ScanResultSink,
) -> Dag {
    let mut dag = Dag::new();

    let aggregate = Arc::new(AggregateJob::new(namespace, image_digest, sink.clone()));
    let aggregate_id = Job::id(&*aggregate);
    dag.ensure_node(aggregate_id.clone());

    for scanner in scanners {
        let job_sink: Arc<dyn OutputSink<ScanOutcome>> = Arc::new(sink.clone());
        let job = Arc::new(ScanJob::new(
            namespace,
            image_digest,
            image_ref,
            *scanner,
            executor.clone(),
            job_sink,
        ));
        let scan_id = Job::id(&*job);
        dag.ensure_node(scan_id.clone());
        // scan → aggregate: aggregate waits for every scan to be terminal.
        dag.add_edge(scan_id, aggregate_id.clone());
        scheduler.register_job(job).await;
    }
    scheduler.register_job(aggregate).await;
    dag
}

#[cfg(test)]
mod tests {
    use super::*;
    // `tick` / `snapshot` are on the Scheduler trait.
    use shigoto_scheduler::Scheduler;

    struct MockExecutor;

    #[async_trait]
    impl ScanExecutor for MockExecutor {
        async fn run_scan(&self, scanner: &str, _image_ref: &str) -> Result<ScanOutcome, ScanError> {
            // CVE scanner finds one High; others clean.
            let findings = if scanner == "trivy" {
                vec![Finding {
                    scanner: scanner.to_owned(),
                    severity: "High".to_owned(),
                    cve_id: Some("CVE-2025-0001".to_owned()),
                }]
            } else {
                vec![]
            };
            let hash = blake3::hash(scanner.as_bytes()).to_hex().to_string();
            Ok(ScanOutcome { scanner: scanner.to_owned(), findings, hash })
        }
    }

    #[tokio::test]
    async fn scan_fanout_aggregates_via_dag() {
        let scheduler = InProcessScheduler::new("validation-jobs-test");
        let sink = ScanResultSink::new();
        let mut dag = build_scan_dag(
            &scheduler,
            "akeyless-validation",
            "sha256:abc",
            "zot.local:5000/akeyless-auth@sha256:abc",
            &["trivy", "semgrep", "zap"], // CVE, SAST, DAST
            Arc::new(MockExecutor),
            sink.clone(),
        )
        .await;

        // Tick to quiescence (tend's reconcile.rs pattern).
        for _ in 0..32 {
            let receipt = scheduler.tick(&mut dag).await.expect("tick");
            if receipt.transitions_this_tick.is_empty() {
                break;
            }
        }

        // All three scan outcomes captured via the OutputSink.
        let outcomes = sink.outcomes();
        assert_eq!(outcomes.len(), 3, "all 3 scanners recorded");
        let total: usize = outcomes.iter().map(|o| o.findings.len()).sum();
        assert_eq!(total, 1, "trivy's single High finding fanned in");

        // Every node reached a terminal phase.
        let snap = scheduler.snapshot(&dag).await;
        assert!(
            snap.phase_counts().get("succeeded").copied().unwrap_or(0) >= 4,
            "3 scans + 1 aggregate succeeded: {:?}",
            snap.phase_counts()
        );
    }
}
