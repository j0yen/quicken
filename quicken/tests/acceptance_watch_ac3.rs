//! AC3 (quicken-watch): With no bus reachable, `quicken watch --once` exits 0
//! and logs a fail-open notice (no panic, no hang). With `--require-bus`, the
//! same condition exits non-zero.
//!
//! These tests run the binary with a fake/absent `agorabus` binary so the bus
//! is always unreachable.

use std::process::Command;

fn quicken_binary() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set by cargo test");
    let crate_dir = std::path::Path::new(&manifest_dir);
    let workspace_root = crate_dir.parent().unwrap_or(crate_dir);
    workspace_root.join("target/release/quicken")
}

/// Returns a PATH that only contains a directory with a stub `agorabus` that exits 1.
fn make_stub_path(tmp: &tempfile::TempDir) -> String {
    use std::os::unix::fs::PermissionsExt;

    let stub = tmp.path().join("agorabus");
    std::fs::write(&stub, "#!/bin/sh\nexit 1\n").expect("write stub");
    let mut perms = std::fs::metadata(&stub).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&stub, perms).expect("set permissions");
    tmp.path().to_str().expect("path is UTF-8").to_owned()
}

#[test]
fn no_bus_fail_open_exits_zero() {
    let binary = quicken_binary();
    if !binary.exists() {
        eprintln!("SKIP: release binary not found");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let stub_path = make_stub_path(&tmp);

    let out = Command::new(&binary)
        .args(["watch", "--once"])
        .env("PATH", &stub_path)
        .output()
        .expect("run quicken watch --once");

    assert_eq!(
        out.status.code(),
        Some(0),
        "fail-open: must exit 0 when bus is unreachable (no --require-bus); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Must log a fail-open notice to stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("fail-open") || stderr.contains("bus"),
        "must log a fail-open notice to stderr; got: {stderr}"
    );
}

#[test]
fn require_bus_exits_nonzero_when_bus_down() {
    let binary = quicken_binary();
    if !binary.exists() {
        eprintln!("SKIP: release binary not found");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let stub_path = make_stub_path(&tmp);

    let out = Command::new(&binary)
        .args(["watch", "--once", "--require-bus"])
        .env("PATH", &stub_path)
        .output()
        .expect("run quicken watch --once --require-bus");

    assert_ne!(
        out.status.code(),
        Some(0),
        "--require-bus: must exit non-zero when bus is unreachable; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
