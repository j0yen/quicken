//! `WardenProbe` — checks whether the bpolicy/warden eBPF-LSM is loaded.
//!
//! Runs `{bpolicy_path} status` and parses the JSON output for `{"loaded": bool}`.
//!
//! In test mode (`env.bpolicy_status_fixture` is `Some`), reads the fixture
//! file directly instead of executing the binary.
//!
//! Verdict:
//! - `{"loaded": true}`  → `Live`
//! - `{"loaded": false}` → `Inert`
//! - Binary absent or JSON invalid → `Unknown`

use crate::{Evidence, PrimitiveReport, Probe, ProbeEnv, Verdict};

/// Probe for the warden/bpolicy eBPF-LSM primitive.
pub struct WardenProbe;

impl Probe for WardenProbe {
    fn name(&self) -> &'static str {
        "warden"
    }

    fn probe(&self, env: &ProbeEnv) -> PrimitiveReport {
        let status_json = if let Some(fixture) = &env.bpolicy_status_fixture {
            // Test path: read fixture file.
            match std::fs::read_to_string(fixture) {
                Ok(s) => s,
                Err(e) => {
                    return PrimitiveReport::new(
                        self.name(),
                        Verdict::Unknown,
                        Evidence::single("error", format!("fixture read failed: {e}")),
                    );
                }
            }
        } else {
            // Production path: execute bpolicy status.
            run_bpolicy_status(env)
        };

        parse_bpolicy_output(self.name(), &status_json)
    }
}

/// Run `bpolicy status` and return its stdout as a string.
/// Returns an error-evidence JSON string on failure.
fn run_bpolicy_status(env: &ProbeEnv) -> String {
    if !env.bpolicy_path.exists() {
        return format!(
            r#"{{"error":"bpolicy not found at {}"}}"#,
            env.bpolicy_path.display()
        );
    }

    match std::process::Command::new(&env.bpolicy_path)
        .arg("status")
        .output()
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Err(e) => format!(r#"{{"error":"exec failed: {e}"}}"#),
    }
}

/// Parse the bpolicy status JSON and return a `PrimitiveReport`.
fn parse_bpolicy_output(probe_name: &str, json_str: &str) -> PrimitiveReport {
    #[derive(serde::Deserialize)]
    struct BpolicyStatus {
        loaded: Option<bool>,
        error: Option<String>,
    }

    let ev_base =
        Evidence::single("bpolicy_status_raw", json_str.trim().to_owned());

    match serde_json::from_str::<BpolicyStatus>(json_str) {
        Ok(s) => {
            if let Some(err) = s.error {
                return PrimitiveReport::new(
                    probe_name,
                    Verdict::Unknown,
                    ev_base.with_detail(err),
                );
            }
            match s.loaded {
                Some(true) => {
                    PrimitiveReport::new(probe_name, Verdict::Live, ev_base)
                }
                Some(false) => {
                    PrimitiveReport::new(probe_name, Verdict::Inert, ev_base)
                }
                None => PrimitiveReport::new(
                    probe_name,
                    Verdict::Unknown,
                    ev_base.with_detail("'loaded' field absent in JSON"),
                ),
            }
        }
        Err(e) => PrimitiveReport::new(
            probe_name,
            Verdict::Unknown,
            ev_base
                .with_detail(format!("JSON parse error: {e}")),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn env_with_fixture(json: &str) -> (ProbeEnv, tempfile::NamedTempFile) {
        let mut f = tempfile::NamedTempFile::new()
            .expect("tempfile should be creatable in tests");
        f.write_all(json.as_bytes())
            .expect("write should succeed");
        let env = ProbeEnv::default().with_bpolicy_fixture(f.path().to_path_buf());
        (env, f)
    }

    #[test]
    fn loaded_true_is_live() {
        let (env, _f) = env_with_fixture(r#"{"loaded": true}"#);
        let report = WardenProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Live);
    }

    #[test]
    fn loaded_false_is_inert() {
        let (env, _f) = env_with_fixture(r#"{"loaded": false}"#);
        let report = WardenProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Inert);
    }

    #[test]
    fn missing_fixture_is_unknown() {
        let env = ProbeEnv::default()
            .with_bpolicy_fixture("/nonexistent/___bpolicy_fixture___");
        let report = WardenProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Unknown);
    }

    #[test]
    fn invalid_json_is_unknown() {
        let (env, _f) = env_with_fixture("not json at all");
        let report = WardenProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Unknown);
    }

    #[test]
    fn error_field_in_json_is_unknown() {
        let (env, _f) =
            env_with_fixture(r#"{"error":"bpolicy not found at /dev/null"}"#);
        let report = WardenProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Unknown);
    }

    #[test]
    fn probe_name_is_warden() {
        let (env, _f) = env_with_fixture(r#"{"loaded": false}"#);
        let report = WardenProbe.probe(&env);
        assert_eq!(report.name, "warden");
    }

    #[test]
    fn evidence_records_raw_json() {
        let raw = r#"{"loaded": false}"#;
        let (env, _f) = env_with_fixture(raw);
        let report = WardenProbe.probe(&env);
        assert!(report
            .evidence
            .get("bpolicy_status_raw")
            .map_or(false, |v| v.contains("loaded")));
    }
}
