//! Acceptance tests for quicken-attest (AC2–AC7).
// Tests use `.expect()`, `panic!`, `assert`, and indexing as is conventional for test code.
#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use chrono::DateTime;
use quicken_attest::{DeltaKind, ReceiptStore, attest, streak_band};
use quicken_probe::{Evidence, PrimitiveReport, Verdict};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ts(s: &str) -> DateTime<chrono::Utc> {
    s.parse().expect("parse timestamp in test")
}

fn report(name: &str, verdict: Verdict, evidence: Evidence) -> PrimitiveReport {
    PrimitiveReport {
        name: name.into(),
        verdict,
        evidence,
        checked_at: ts("2026-06-05T10:00:00Z"),
    }
}

fn inert(name: &str) -> PrimitiveReport {
    report(name, Verdict::Inert, Evidence::empty())
}

fn live(name: &str) -> PrimitiveReport {
    report(name, Verdict::Live, Evidence::empty())
}

struct FixedClock(DateTime<chrono::Utc>);
impl quicken_attest::AttestClock for FixedClock {
    fn now(&self) -> DateTime<chrono::Utc> {
        self.0
    }
}

fn fixed_clock(ts_str: &str) -> FixedClock {
    FixedClock(ts(ts_str))
}

// ---------------------------------------------------------------------------
// AC2: Receipt roundtrip golden test
// ---------------------------------------------------------------------------

#[test]
fn ac2_receipt_write_and_read_roundtrip() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = ReceiptStore::new(tmp.path());
    let clock = fixed_clock("2026-06-05T10:00:00Z");

    let reports = vec![inert("memlog"), live("agentns")];
    let result = attest(&reports, &clock, "boot-abc", &store).expect("attest");

    // Write the receipt.
    store.write(&result.receipt).expect("write receipt");

    // Reload and verify round-trip.
    let loaded = store.load_all().expect("load_all");
    assert_eq!(loaded.len(), 1, "exactly one receipt expected");
    let r = &loaded[0];
    assert_eq!(r.boot_id, "boot-abc");
    assert_eq!(r.reports.len(), 2);
    assert_eq!(r.reports[0].name, "memlog");
    assert_eq!(r.reports[0].verdict, Verdict::Inert);
    assert_eq!(r.reports[1].name, "agentns");
    assert_eq!(r.reports[1].verdict, Verdict::Live);
}

// ---------------------------------------------------------------------------
// AC3: Delta correctness — all four cases
// ---------------------------------------------------------------------------

#[test]
fn ac3_delta_unchanged() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = ReceiptStore::new(tmp.path());
    let clock1 = fixed_clock("2026-06-04T10:00:00Z");
    let clock2 = fixed_clock("2026-06-05T10:00:00Z");

    // Seed prior receipt.
    let prior_reports = vec![inert("memlog")];
    let prior_result = attest(&prior_reports, &clock1, "boot-1", &store).expect("attest 1");
    store.write(&prior_result.receipt).expect("write prior");

    // Current: same verdict.
    let cur_reports = vec![inert("memlog")];
    let result = attest(&cur_reports, &clock2, "boot-2", &store).expect("attest 2");
    let (name, delta) = &result.deltas[0];
    assert_eq!(name, "memlog");
    assert_eq!(delta.kind, DeltaKind::Unchanged, "same verdict must be Unchanged");
}

#[test]
fn ac3_delta_regressed_live_to_inert() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = ReceiptStore::new(tmp.path());
    let clock1 = fixed_clock("2026-06-04T10:00:00Z");
    let clock2 = fixed_clock("2026-06-05T10:00:00Z");

    let prior_reports = vec![live("memlog")];
    let prior = attest(&prior_reports, &clock1, "boot-1", &store).expect("attest 1");
    store.write(&prior.receipt).expect("write");

    let cur_reports = vec![inert("memlog")];
    let result = attest(&cur_reports, &clock2, "boot-2", &store).expect("attest 2");
    assert_eq!(result.deltas[0].1.kind, DeltaKind::Regressed);
}

#[test]
fn ac3_delta_improved_inert_to_live() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = ReceiptStore::new(tmp.path());
    let clock1 = fixed_clock("2026-06-04T10:00:00Z");
    let clock2 = fixed_clock("2026-06-05T10:00:00Z");

    let prior_reports = vec![inert("memlog")];
    let prior = attest(&prior_reports, &clock1, "boot-1", &store).expect("attest 1");
    store.write(&prior.receipt).expect("write");

    let cur_reports = vec![live("memlog")];
    let result = attest(&cur_reports, &clock2, "boot-2", &store).expect("attest 2");
    assert_eq!(result.deltas[0].1.kind, DeltaKind::Improved);
}

#[test]
fn ac3_delta_evidence_changed_pkgrel() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = ReceiptStore::new(tmp.path());
    let clock1 = fixed_clock("2026-06-04T10:00:00Z");
    let clock2 = fixed_clock("2026-06-05T10:00:00Z");

    let prior_ev = Evidence::single("installed_pkgrel", "5").with("staged_pkgrel", "6");
    let prior_reports = vec![report("memlog", Verdict::StagedNotInstalled, prior_ev)];
    let prior = attest(&prior_reports, &clock1, "boot-1", &store).expect("attest 1");
    store.write(&prior.receipt).expect("write");

    let cur_ev = Evidence::single("installed_pkgrel", "5").with("staged_pkgrel", "11");
    let cur_reports = vec![report("memlog", Verdict::StagedNotInstalled, cur_ev)];
    let result = attest(&cur_reports, &clock2, "boot-2", &store).expect("attest 2");

    match &result.deltas[0].1.kind {
        DeltaKind::EvidenceChanged { detail } => {
            assert!(
                detail.contains("staged_pkgrel"),
                "EvidenceChanged detail must mention staged_pkgrel: {detail}"
            );
        }
        other => panic!("expected EvidenceChanged, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// AC4: inert_streak counts only distinct boot_ids
// ---------------------------------------------------------------------------

#[test]
fn ac4_streak_counts_distinct_boot_ids_not_receipts() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = ReceiptStore::new(tmp.path());

    // Write three prior receipts across two boot_ids, all dark.
    let r1 = quicken_attest::receipt::Receipt {
        taken_at: ts("2026-06-03T09:00:00Z"),
        boot_id: "boot-A".into(),
        reports: vec![inert("memlog")],
    };
    let r2 = quicken_attest::receipt::Receipt {
        taken_at: ts("2026-06-03T10:00:00Z"),
        boot_id: "boot-A".into(), // same boot_id as r1
        reports: vec![inert("memlog")],
    };
    let r3 = quicken_attest::receipt::Receipt {
        taken_at: ts("2026-06-04T10:00:00Z"),
        boot_id: "boot-B".into(),
        reports: vec![inert("memlog")],
    };
    store.write(&r1).expect("write r1");
    store.write(&r2).expect("write r2");
    store.write(&r3).expect("write r3");

    let clock = fixed_clock("2026-06-05T10:00:00Z");
    let cur = vec![inert("memlog")];
    let result = attest(&cur, &clock, "boot-C", &store).expect("attest");

    let (_, streak_info) = result
        .streaks
        .iter()
        .find(|(name, _)| name == "memlog")
        .expect("memlog streak");

    // boot-A and boot-B → 2 distinct dark boots, not 3 receipts.
    assert_eq!(streak_info.inert_streak, 2, "streak must count distinct boot_ids");
}

// ---------------------------------------------------------------------------
// AC5: Streak severity escalates at band boundaries
// ---------------------------------------------------------------------------

#[test]
fn ac5_streak_band_escalates() {
    let s1 = streak_band(1);
    let s3 = streak_band(3);
    let s7 = streak_band(7);

    assert!(!s1.is_empty(), "streak 1 must produce non-empty severity");
    assert!(!s3.is_empty(), "streak 3 must produce non-empty severity");
    assert!(!s7.is_empty(), "streak 7 must produce non-empty severity");

    // All three must be distinct.
    assert_ne!(s1, s3, "streak 1 and 3 must have different wording");
    assert_ne!(s3, s7, "streak 3 and 7 must have different wording");
    assert_ne!(s1, s7, "streak 1 and 7 must have different wording");

    // streak 7 must be loudest (uppercase indicator).
    assert!(
        s7.contains("DARK FOR"),
        "streak 7 must contain 'DARK FOR': {s7}"
    );
}

// ---------------------------------------------------------------------------
// AC6: --no-write leaves store unchanged (logic test)
// ---------------------------------------------------------------------------

#[test]
fn ac6_no_write_does_not_persist() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = ReceiptStore::new(tmp.path());
    let clock = fixed_clock("2026-06-05T10:00:00Z");

    let reports = vec![inert("memlog")];
    let result = attest(&reports, &clock, "boot-1", &store).expect("attest");

    // Simulate --no-write: do NOT call store.write(&result.receipt).
    // The store directory should still be empty.
    let loaded = store.load_all().expect("load_all");
    assert!(
        loaded.is_empty(),
        "store must be empty when we don't call write"
    );

    // Result is still valid.
    assert_eq!(result.receipt.boot_id, "boot-1");
}

// ---------------------------------------------------------------------------
// AC7: Zero network access and writes only in injected tmpdir (structural)
// This is enforced by construction: store path is always injected tmpdir,
// boot_id and clock are injected parameters — no real /proc or system reads
// in any test above.
// ---------------------------------------------------------------------------

#[test]
fn ac7_all_tests_use_injected_store_and_clock() {
    // Structural: every test above uses a tempdir store and FixedClock.
    // This test documents the invariant: if someone changes to SystemClock or
    // a real path, the test is no longer AC7-safe.
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = ReceiptStore::new(tmp.path());
    // Use a FixedClock, not SystemClock, and an injected boot_id.
    let clock = FixedClock(ts("2026-06-05T12:00:00Z"));
    let result = attest(&[inert("memlog")], &clock, "test-boot-id", &store)
        .expect("attest must succeed with injected inputs");
    assert_eq!(result.receipt.boot_id, "test-boot-id");
    assert_eq!(
        result.receipt.taken_at,
        ts("2026-06-05T12:00:00Z"),
        "taken_at must use injected clock"
    );
}
