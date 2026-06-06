//! AC6: No probe panics on a missing surface (absent dev node, unreadable
//! proc file, no xattr) — each maps to `Unknown` or `Inert` with evidence,
//! never a crash.

use quicken_probe::{
    AgentnsProbe, MemlogProbe, Probe, ProbeEnv, ProvfsProbe, Verdict, WardenProbe,
};

fn empty_env() -> (ProbeEnv, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let env = ProbeEnv::default()
        .with_dev_root(tmp.path().join("empty_dev"))
        .with_pacman_local_db(tmp.path().join("empty_pacman"))
        .with_pkg_staging_dir(tmp.path().join("empty_staging"))
        .with_agent_session("/nonexistent/___ac6_agent___")
        .with_provfs_xattr_path("/nonexistent/___ac6_provfs___");
    // Note: no bpolicy fixture → WardenProbe will try to run the binary.
    // If bpolicy is absent, it returns Unknown.
    (env, tmp)
}

#[test]
fn memlog_probe_no_panic_on_missing_surfaces() {
    let (env, _tmp) = empty_env();
    let report = MemlogProbe.probe(&env);
    // Should be Inert or Unknown, never panics.
    assert!(
        matches!(report.verdict, Verdict::Inert | Verdict::Unknown),
        "expected Inert or Unknown on empty env, got {:?}",
        report.verdict
    );
    // Evidence must be non-empty (probe recorded something).
    assert!(
        !report.evidence.pairs.is_empty(),
        "evidence must not be empty even on missing surfaces"
    );
}

#[test]
fn agentns_probe_no_panic_on_missing_file() {
    let (env, _tmp) = empty_env();
    let report = AgentnsProbe.probe(&env);
    assert_eq!(
        report.verdict,
        Verdict::Unknown,
        "absent agent_session should give Unknown"
    );
    assert!(!report.evidence.pairs.is_empty());
}

#[test]
fn warden_probe_no_panic_on_missing_binary() {
    let (env, _tmp) = empty_env();
    // WardenProbe in production mode (no fixture) — bpolicy likely absent in CI.
    // Should not panic regardless.
    let report = WardenProbe.probe(&env);
    assert!(
        matches!(
            report.verdict,
            Verdict::Inert | Verdict::Live | Verdict::Unknown
        ),
        "WardenProbe should not panic, got {:?}",
        report.verdict
    );
}

#[test]
fn provfs_probe_no_panic_on_missing_path() {
    let (env, _tmp) = empty_env();
    let report = ProvfsProbe.probe(&env);
    assert_eq!(
        report.verdict,
        Verdict::Unknown,
        "absent provfs path should give Unknown"
    );
    assert!(!report.evidence.pairs.is_empty());
}

#[test]
fn all_probes_no_panic_combined() {
    let (env, _tmp) = empty_env();
    // Run all probes simultaneously — if any panics, the test fails.
    let probes: Vec<Box<dyn Probe>> = vec![
        Box::new(MemlogProbe),
        Box::new(AgentnsProbe),
        Box::new(WardenProbe),
        Box::new(ProvfsProbe),
    ];
    for probe in &probes {
        let report = probe.probe(&env);
        // Just assert that we got a report without panic.
        assert!(!report.name.is_empty(), "probe should have a name");
    }
}
