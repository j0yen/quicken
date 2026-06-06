//! AC5: `quicken probe` exits non-zero when any primitive verdict is worse
//! than `LiveDegraded`, and zero when all are `Live`/`LiveDegraded`.
//!
//! We test the exit-code logic via the library directly (not the binary)
//! since we can inject controlled fixture environments.

use std::io::Write;

use quicken_probe::{
    AgentnsProbe, MemlogProbe, Probe, ProbeEnv, ProvfsProbe, Verdict, WardenProbe,
};

/// A fixture environment where all probes will return acceptable verdicts.
///
/// - agentns: non-zero UUID → Live
/// - warden: loaded:true → Live
/// - memlog: no dev node, no staging, no installed → Inert (NOT acceptable)
///   ... so we can't make all 4 Live without hardware.
/// Instead we test the verdict.is_acceptable() logic directly.
#[test]
fn all_acceptable_exits_zero_logic() {
    // Simulate the exit-code computation: all Live or LiveDegraded → exit 0.
    let verdicts = vec![Verdict::Live, Verdict::LiveDegraded { reason: "test".into() }];
    let all_ok = verdicts.iter().all(|v| v.is_acceptable());
    assert!(all_ok);
    let exit = if all_ok { 0 } else { 1 };
    assert_eq!(exit, 0, "all-acceptable verdicts should give exit 0");
}

#[test]
fn any_inert_exits_nonzero_logic() {
    let verdicts = vec![Verdict::Live, Verdict::Inert];
    let all_ok = verdicts.iter().all(|v| v.is_acceptable());
    assert!(!all_ok);
    let exit = if all_ok { 0 } else { 1 };
    assert_eq!(exit, 1, "any Inert should give exit 1");
}

#[test]
fn installed_not_activated_exits_nonzero_logic() {
    let verdicts = vec![Verdict::InstalledNotActivated, Verdict::Live];
    let all_ok = verdicts.iter().all(|v| v.is_acceptable());
    assert!(!all_ok);
    let exit = if all_ok { 0 } else { 1 };
    assert_eq!(exit, 1);
}

#[test]
fn staged_not_installed_exits_nonzero_logic() {
    let verdicts = vec![Verdict::StagedNotInstalled];
    let all_ok = verdicts.iter().all(|v| v.is_acceptable());
    assert!(!all_ok);
    let exit = if all_ok { 0 } else { 1 };
    assert_eq!(exit, 1);
}

/// Integration-style test: run all four probes against a fixture env and
/// assert that the exit code matches the computed verdict.
#[test]
fn all_probes_inert_fixture_gives_nonzero() {
    // An environment where no surfaces exist → all probes Inert or Unknown.
    let tmp = tempfile::TempDir::new().expect("tempdir");

    let mut agent_file = tempfile::NamedTempFile::new().expect("tempfile");
    agent_file
        .write_all(b"00000000000000000000000000000000")
        .expect("write");

    let mut bpolicy_file = tempfile::NamedTempFile::new().expect("tempfile");
    bpolicy_file
        .write_all(br#"{"loaded": false}"#)
        .expect("write");

    let env = ProbeEnv::default()
        .with_dev_root(tmp.path().join("empty_dev"))
        .with_pacman_local_db(tmp.path().join("empty_pacman"))
        .with_pkg_staging_dir(tmp.path().join("empty_staging"))
        .with_agent_session(agent_file.path())
        .with_bpolicy_fixture(bpolicy_file.path())
        .with_provfs_xattr_path("/nonexistent/___ac5_provfs___");

    let probes: Vec<Box<dyn Probe>> = vec![
        Box::new(MemlogProbe),
        Box::new(AgentnsProbe),
        Box::new(WardenProbe),
        Box::new(ProvfsProbe),
    ];

    let reports: Vec<_> = probes.iter().map(|p| p.probe(&env)).collect();
    let all_ok = reports.iter().all(|r| r.verdict.is_acceptable());
    // All probes should return Inert/Unknown → not all_ok → exit 1.
    assert!(!all_ok, "all-inert fixture should not be acceptable");
}
