//! AC1 (quicken-watch): `quicken watch --once --format json` runs the full
//! Fleet-1 probe set and prints one JSON event per primitive on the
//! `wm.health.*` envelope shape, with a valid `verdict` from the closed set
//! and a non-empty `evidence_digest`.
//!
//! AC8: `quicken watch --help` documents `--once`, `--format`, `--require-bus`,
//! and the published topic.

use std::process::Command;

fn quicken_binary() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set by cargo test");
    let crate_dir = std::path::Path::new(&manifest_dir);
    let workspace_root = crate_dir.parent().unwrap_or(crate_dir);
    workspace_root.join("target/release/quicken")
}

#[test]
fn watch_json_emits_one_event_per_primitive_with_valid_verdict() {
    let binary = quicken_binary();
    if !binary.exists() {
        eprintln!("SKIP: release binary not found; run `cargo build --release` first");
        return;
    }

    let out = Command::new(&binary)
        .args(["watch", "--once", "--format", "json"])
        .output()
        .expect("failed to run quicken watch --once --format json");

    // Exit 0 = published (or fail-open bus error).
    assert!(
        out.status.code() != Some(2),
        "must not exit 2 (internal error); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_str = String::from_utf8(out.stdout).expect("stdout must be UTF-8");
    let arr: serde_json::Value = serde_json::from_str(&json_str)
        .expect("--format json output must be valid JSON");

    assert!(arr.is_array(), "output must be a JSON array");
    let arr = arr.as_array().expect("is array");

    // Exactly 4 primitives (memlog, agentns, warden, provfs).
    assert_eq!(arr.len(), 4, "expected 4 events, got {}", arr.len());

    let valid_verdicts = [
        "live", "live-degraded", "staged-not-installed",
        "installed-not-activated", "inert", "unknown",
    ];

    for ev in arr {
        // subject must start with "primitive."
        let subject = ev["subject"].as_str().expect("subject must be a string");
        assert!(
            subject.starts_with("primitive."),
            "subject must start with 'primitive.', got: {subject}"
        );

        // verdict must be from the closed set
        let verdict = ev["verdict"].as_str().expect("verdict must be a string");
        assert!(
            valid_verdicts.contains(&verdict),
            "verdict '{verdict}' is not in closed set"
        );

        // evidence_digest must be non-empty
        let digest = ev["evidence_digest"].as_str().expect("evidence_digest must be string");
        assert!(!digest.is_empty(), "evidence_digest must be non-empty");

        // ts must be present
        assert!(ev["ts"].is_string(), "ts must be a string");

        // inert_streak must be a non-negative integer
        assert!(
            ev["inert_streak"].as_u64().is_some(),
            "inert_streak must be a non-negative integer"
        );
    }
}

#[test]
fn watch_help_documents_required_flags() {
    let binary = quicken_binary();
    if !binary.exists() {
        return;
    }

    let out = Command::new(&binary)
        .args(["watch", "--help"])
        .output()
        .expect("failed to run quicken watch --help");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(combined.contains("--once"), "watch --help must document --once, got:\n{combined}");
    assert!(combined.contains("--format"), "watch --help must document --format, got:\n{combined}");
    assert!(combined.contains("--require-bus"), "watch --help must document --require-bus, got:\n{combined}");
    assert!(
        combined.contains("wm.health.primitive"),
        "watch --help must mention published topic wm.health.primitive, got:\n{combined}"
    );
}
