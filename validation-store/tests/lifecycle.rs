//! End-to-end lifecycle test — walks a single validation run from
//! Pending through Passed, writing every entity in order, and
//! reading them all back via the query helpers. SQLite in-memory.

use chrono::Utc;
use validation_crds::{
    AkeylessImageValidationPhase, GateDecision, GateVerdict, ScanFinding, ScanFindingSeverity,
    ScannerKind,
};
use validation_store::{
    ensure_all_tables, ops,
    ops::upsert::{ReconcilerOutcomeWrite, ValidationRunWrite},
    ValidationStore,
};

#[tokio::test]
async fn full_lifecycle_round_trips_through_every_entity() {
    let store = ValidationStore::in_memory().await.unwrap();
    let db = store.db();
    ensure_all_tables(db).await.unwrap();

    // ── Step 1 — observe a digest's provenance (cartorio admit) ─────
    let provenance = ops::observe_digest_provenance(
        db,
        "sha256:abcd1234",
        "akeyless-auth",
        serde_json::json!({
            "source": {
                "git_commit": "deadbeef",
                "tree_hash": "blake3:treehash",
                "flake_lock_hash": "blake3:flakehash",
            },
            "build": { "builder_id": "kenshi" },
        }),
        Some("Pending"),
        Some("art-uuid-123"),
    )
    .await
    .unwrap();
    assert_eq!(provenance.image_repo, "akeyless-auth");
    assert_eq!(provenance.git_commit.as_deref(), Some("deadbeef"));
    assert_eq!(provenance.cartorio_status.as_deref(), Some("Pending"));

    // ── Step 2 — upsert validation run at Pending ──────────────────
    let run_uid = "test-uid-001";
    let _run = ops::upsert_validation_run(
        db,
        ValidationRunWrite {
            uid: run_uid.into(),
            namespace: "akeyless-validation".into(),
            name: "akeyless-auth-abcd".into(),
            image_digest: "sha256:abcd1234".into(),
            image_repo: "akeyless-auth".into(),
            phase: AkeylessImageValidationPhase::Pending,
            evidence_bundle_hash: None,
            outcome_receipt_ref: None,
            observed_generation: 1,
        },
    )
    .await
    .unwrap();

    // ── Step 3 — advance to Scanning + append findings ─────────────
    ops::upsert_validation_run(
        db,
        ValidationRunWrite {
            uid: run_uid.into(),
            namespace: "akeyless-validation".into(),
            name: "akeyless-auth-abcd".into(),
            image_digest: "sha256:abcd1234".into(),
            image_repo: "akeyless-auth".into(),
            phase: AkeylessImageValidationPhase::Scanning,
            evidence_bundle_hash: None,
            outcome_receipt_ref: None,
            observed_generation: 2,
        },
    )
    .await
    .unwrap();

    let findings = vec![
        ScanFinding {
            scanner: ScannerKind::Trivy,
            cve_id: Some("CVE-2026-0001".into()),
            severity: ScanFindingSeverity::Medium,
            first_seen: Utc::now(),
            fixed_in: Some("1.2.3".into()),
            exception_id: None,
            cvss_v3: Some(5.5),
            message: Some("medium libfoo CVE".into()),
        },
        ScanFinding {
            scanner: ScannerKind::Semgrep,
            cve_id: None,
            severity: ScanFindingSeverity::Low,
            first_seen: Utc::now(),
            fixed_in: None,
            exception_id: None,
            cvss_v3: None,
            message: Some("style finding".into()),
        },
    ];
    let n = ops::append_scan_findings(db, run_uid, "scan-trivy-auth", &findings)
        .await
        .unwrap();
    assert_eq!(n, 2);

    // ── Step 4 — record decision audit (Cosmetic / Passed) ─────────
    let gate = GateDecision {
        severity: "Cosmetic".into(),
        verdict: GateVerdict::Passed,
        action: serde_json::json!({ "action": "noop" }),
        reason: Some("no critical/high findings".into()),
        decided_at: Utc::now(),
    };
    ops::record_decision_audit(
        db,
        run_uid,
        &gate,
        serde_json::json!({ "drift": "clean" }),
    )
    .await
    .unwrap();

    // ── Step 5 — append a reconciler outcome (Noop) ────────────────
    ops::append_reconciler_outcome(
        db,
        ReconcilerOutcomeWrite {
            validation_run_uid: run_uid.into(),
            action_kind: "Noop".into(),
            reconciler_kind: None,
            action_payload: serde_json::json!({ "action": "noop" }),
            outcome: "already-converged".into(),
            outcome_flag: None,
            outcome_payload: None,
            gate_decision_decided_at: gate.decided_at,
        },
    )
    .await
    .unwrap();

    // ── Step 6 — advance to Passed (terminal) ──────────────────────
    let _terminal = ops::upsert_validation_run(
        db,
        ValidationRunWrite {
            uid: run_uid.into(),
            namespace: "akeyless-validation".into(),
            name: "akeyless-auth-abcd".into(),
            image_digest: "sha256:abcd1234".into(),
            image_repo: "akeyless-auth".into(),
            phase: AkeylessImageValidationPhase::Passed,
            evidence_bundle_hash: Some("blake3:bundlehash".into()),
            outcome_receipt_ref: None,
            observed_generation: 3,
        },
    )
    .await
    .unwrap();

    // ── Read-side: every helper must surface the data ──────────────
    let run = ops::query::validation_run_by_uid(db, run_uid)
        .await
        .unwrap()
        .expect("run exists");
    assert_eq!(run.phase, "Passed");
    assert!(run.terminal_at.is_some(), "terminal_at set on Passed");
    assert_eq!(run.evidence_bundle_hash.as_deref(), Some("blake3:bundlehash"));

    let passed_runs = ops::query::validation_runs_by_phase(db, "Passed")
        .await
        .unwrap();
    assert_eq!(passed_runs.len(), 1);

    let by_digest = ops::query::validation_runs_by_digest(db, "sha256:abcd1234")
        .await
        .unwrap();
    assert_eq!(by_digest.len(), 1);

    let found = ops::query::findings_by_run(db, run_uid).await.unwrap();
    assert_eq!(found.len(), 2);
    let mediums = ops::query::findings_by_run_and_severity(db, run_uid, "Medium")
        .await
        .unwrap();
    assert_eq!(mediums.len(), 1);
    assert_eq!(mediums[0].cve_id.as_deref(), Some("CVE-2026-0001"));

    let decisions = ops::query::decisions_by_run(db, run_uid).await.unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].verdict, "Passed");

    let outcomes = ops::query::outcomes_by_run(db, run_uid).await.unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].outcome, "already-converged");

    let prov = ops::query::provenance_by_digest(db, "sha256:abcd1234")
        .await
        .unwrap()
        .expect("provenance exists");
    assert_eq!(prov.image_repo, "akeyless-auth");

    let summary = ops::query::compliance_summary(db).await.unwrap();
    assert_eq!(summary.get("Passed"), Some(&1));
    assert!(summary.get("Pending").is_none(), "no pending runs left");
}

#[tokio::test]
async fn upsert_preserves_started_at_across_phases() {
    let store = ValidationStore::in_memory().await.unwrap();
    let db = store.db();
    ensure_all_tables(db).await.unwrap();

    let uid = "u-001";
    let pending = ops::upsert_validation_run(
        db,
        ValidationRunWrite {
            uid: uid.into(),
            namespace: "ns".into(),
            name: "n".into(),
            image_digest: "sha256:x".into(),
            image_repo: "repo".into(),
            phase: AkeylessImageValidationPhase::Pending,
            evidence_bundle_hash: None,
            outcome_receipt_ref: None,
            observed_generation: 1,
        },
    )
    .await
    .unwrap();
    let started = pending.started_at;

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    let later = ops::upsert_validation_run(
        db,
        ValidationRunWrite {
            uid: uid.into(),
            namespace: "ns".into(),
            name: "n".into(),
            image_digest: "sha256:x".into(),
            image_repo: "repo".into(),
            phase: AkeylessImageValidationPhase::Scanning,
            evidence_bundle_hash: None,
            outcome_receipt_ref: None,
            observed_generation: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(later.started_at, started, "started_at must be preserved");
    assert!(later.last_seen_at > started, "last_seen_at advances");
}

#[tokio::test]
async fn terminal_at_only_set_on_first_terminal_observation() {
    let store = ValidationStore::in_memory().await.unwrap();
    let db = store.db();
    ensure_all_tables(db).await.unwrap();

    let uid = "u-term";
    let first_terminal = ops::upsert_validation_run(
        db,
        ValidationRunWrite {
            uid: uid.into(),
            namespace: "ns".into(),
            name: "n".into(),
            image_digest: "sha256:x".into(),
            image_repo: "repo".into(),
            phase: AkeylessImageValidationPhase::Passed,
            evidence_bundle_hash: None,
            outcome_receipt_ref: None,
            observed_generation: 1,
        },
    )
    .await
    .unwrap();
    let t1 = first_terminal.terminal_at.expect("set on first terminal");

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    let second = ops::upsert_validation_run(
        db,
        ValidationRunWrite {
            uid: uid.into(),
            namespace: "ns".into(),
            name: "n".into(),
            image_digest: "sha256:x".into(),
            image_repo: "repo".into(),
            phase: AkeylessImageValidationPhase::Passed,
            evidence_bundle_hash: None,
            outcome_receipt_ref: None,
            observed_generation: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(second.terminal_at, Some(t1), "preserved on re-observation");
}

#[tokio::test]
async fn observe_digest_provenance_updates_status() {
    let store = ValidationStore::in_memory().await.unwrap();
    let db = store.db();
    ensure_all_tables(db).await.unwrap();

    let chain = serde_json::json!({ "source": { "git_commit": "abc" } });
    let v1 = ops::observe_digest_provenance(
        db,
        "sha256:d",
        "akeyless-auth",
        chain.clone(),
        Some("Pending"),
        None,
    )
    .await
    .unwrap();
    let first_observed = v1.first_observed_at;

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    let v2 = ops::observe_digest_provenance(
        db,
        "sha256:d",
        "akeyless-auth",
        chain,
        Some("Active"),
        Some("art-x"),
    )
    .await
    .unwrap();
    assert_eq!(v2.cartorio_status.as_deref(), Some("Active"));
    assert_eq!(v2.cartorio_artifact_id.as_deref(), Some("art-x"));
    assert_eq!(v2.first_observed_at, first_observed, "preserved");
    assert!(v2.last_observed_at >= first_observed, "advances");
}

#[tokio::test]
async fn empty_findings_insert_is_a_noop() {
    let store = ValidationStore::in_memory().await.unwrap();
    let db = store.db();
    ensure_all_tables(db).await.unwrap();
    let n = ops::append_scan_findings(db, "no-such-run", "no-such-job", &[])
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn drop_all_then_ensure_all_is_idempotent() {
    let store = ValidationStore::in_memory().await.unwrap();
    let db = store.db();
    ensure_all_tables(db).await.unwrap();
    validation_store::drop_all_tables(db).await.unwrap();
    ensure_all_tables(db).await.unwrap();
    // Sanity: tables present + empty
    let summary = ops::query::compliance_summary(db).await.unwrap();
    assert!(summary.is_empty());
}
