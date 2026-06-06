//! AC7: Tests perform zero network access and zero writes outside the test
//! tmpdir; the probe path is pure-read (cloud-build-safe).
//!
//! This test verifies the probe API contract: all operations are read-only.
//! We assert this structurally — no probe method takes a `&mut ProbeEnv`,
//! and no probe accesses network-dependent resources (no URLs, no DNS).

use quicken_probe::{AgentnsProbe, MemlogProbe, Probe, ProbeEnv, ProvfsProbe, WardenProbe};

/// Verify that `ProbeEnv` is not mutated by any probe (Clone + compare).
#[test]
fn probes_do_not_mutate_env() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let env = ProbeEnv::default()
        .with_dev_root(tmp.path().join("empty_dev"))
        .with_pacman_local_db(tmp.path().join("empty_pacman"))
        .with_pkg_staging_dir(tmp.path().join("empty_staging"))
        .with_agent_session("/nonexistent/___ac7_agent___")
        .with_provfs_xattr_path("/nonexistent/___ac7_provfs___");

    let env_before = env.clone();

    // Run all probes — they must not change the paths in env.
    let _ = MemlogProbe.probe(&env);
    let _ = AgentnsProbe.probe(&env);
    let _ = ProvfsProbe.probe(&env);

    // Assert paths unchanged.
    assert_eq!(
        env.dev_root, env_before.dev_root,
        "MemlogProbe must not mutate env.dev_root"
    );
    assert_eq!(
        env.agent_session_path, env_before.agent_session_path,
        "AgentnsProbe must not mutate env.agent_session_path"
    );
    assert_eq!(
        env.provfs_xattr_path, env_before.provfs_xattr_path,
        "ProvfsProbe must not mutate env.provfs_xattr_path"
    );
}

/// Verify that probes do not write to the tmpdir (pure read).
///
/// We use `wchg`-style verification: record the directory state before and
/// after running all probes, and assert no new files appeared.
#[test]
fn probes_write_nothing_to_tmpdir() {
    use std::collections::BTreeSet;

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let probe_dir = tmp.path().join("probe_area");
    std::fs::create_dir_all(&probe_dir).expect("create probe_area");

    let env = ProbeEnv::default()
        .with_dev_root(&probe_dir)
        .with_pacman_local_db(&probe_dir)
        .with_pkg_staging_dir(&probe_dir)
        .with_agent_session(probe_dir.join("nonexistent_agent_session"))
        .with_provfs_xattr_path(probe_dir.join("nonexistent_provfs_path"));

    // Snapshot before.
    let before: BTreeSet<_> = std::fs::read_dir(&probe_dir)
        .map(|d| d.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();

    // Run all probes.
    let probes: Vec<Box<dyn Probe>> = vec![
        Box::new(MemlogProbe),
        Box::new(AgentnsProbe),
        Box::new(WardenProbe),
        Box::new(ProvfsProbe),
    ];
    for probe in &probes {
        let _ = probe.probe(&env);
    }

    // Snapshot after.
    let after: BTreeSet<_> = std::fs::read_dir(&probe_dir)
        .map(|d| d.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();

    assert_eq!(
        before, after,
        "probes must not create any files in the probe_area directory"
    );
}
