//! AC4: `quicken probe --json` emits valid JSON deserializable back into
//! `Vec<PrimitiveReport>` (round-trip test).
//!
//! This test exercises the binary directly to ensure the full CLI stack
//! produces well-formed JSON.

use quicken_probe::PrimitiveReport;

fn quicken_binary() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set by cargo test");
    let crate_dir = std::path::Path::new(&manifest_dir);
    let workspace_root = crate_dir.parent().unwrap_or(crate_dir);
    workspace_root.join("target/release/quicken")
}

#[test]
fn probe_json_output_is_valid_and_roundtrippable() {
    let binary = quicken_binary();
    if !binary.exists() {
        // Binary not built in release mode — skip gracefully.
        eprintln!("SKIP: release binary not found; run `cargo build --release` first");
        return;
    }

    let out = std::process::Command::new(&binary)
        .args(["probe", "--json"])
        .output()
        .expect("failed to run quicken probe --json");

    // Exit code may be 0 or 1 depending on system state; both are valid.
    // Exit 2 would indicate an internal error.
    assert_ne!(
        out.status.code(),
        Some(2),
        "quicken probe --json must not exit 2; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_str = String::from_utf8(out.stdout).expect("stdout must be UTF-8");

    // Must be valid JSON.
    let value: serde_json::Value =
        serde_json::from_str(&json_str).expect("quicken probe --json must emit valid JSON");

    // Must be an array.
    assert!(
        value.is_array(),
        "quicken probe --json must emit a JSON array, got: {value}"
    );

    // Must be deserializable as Vec<PrimitiveReport>.
    let reports: Vec<PrimitiveReport> = serde_json::from_str(&json_str)
        .expect("JSON must deserialize into Vec<PrimitiveReport>");

    // Must have exactly 4 reports (one per primitive).
    assert_eq!(reports.len(), 4, "expected 4 primitive reports, got {}", reports.len());

    // Each report must have a non-empty name.
    for r in &reports {
        assert!(!r.name.is_empty(), "report name must not be empty");
    }
}
