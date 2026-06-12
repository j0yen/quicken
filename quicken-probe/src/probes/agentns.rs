//! `AgentnsProbe` — checks whether the agentns kernel module is active.
//!
//! Reads `/proc/self/agent_session` (or `env.agent_session_path`).
//! - All-zeros UUID → calls `assay agentns --json` (if available) to
//!   distinguish a kernel-side flag rejection from a missing launch wrap.
//!   - `assay` reports `FlagRejected` → `Inert` with cause/remediation evidence.
//!   - `assay` reports `Live` → `MechanismLiveNotWired` with launch-wrap advice.
//!   - `assay` absent / errors → `Inert` (fail-open, identical to old behaviour).
//! - Non-zero 128-bit hex → `Live`.
//! - File absent or unreadable → `Unknown`.

use std::process::Command;

use crate::{
    env::read_trimmed, Evidence, PrimitiveReport, Probe, ProbeEnv, Verdict,
};

/// Probe for the agentns kernel primitive.
pub struct AgentnsProbe;

// ──────────────────────────────────────────────────────────────────
// Internal types for parsing `assay agentns --json` output.
// We parse only what we need; unknown fields are ignored.
// ──────────────────────────────────────────────────────────────────

/// The subset of the `AssayReport` JSON we care about.
#[derive(serde::Deserialize, Debug)]
struct AssayReport {
    verdict: AssayVerdict,
    #[serde(default)]
    evidence: serde_json::Value,
}

#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum AssayVerdict {
    /// Kernel rejected `unshare(CLONE_NEWAGENT)` — the flag is broken.
    FlagRejected {
        detail: FlagRejectedDetail,
    },
    /// Kernel accepted the call and a new namespace was created.
    Live {
        /// Additional detail from assay (forward-compat capture; not currently inspected).
        #[serde(default)]
        #[allow(dead_code)]
        detail: serde_json::Value,
    },
    /// Any other verdict we don't specifically handle.
    #[serde(other)]
    Other,
}

#[derive(serde::Deserialize, Debug)]
struct FlagRejectedDetail {
    flag: u64,
    collides_with: Option<String>,
    errno: Option<i32>,
}

// ──────────────────────────────────────────────────────────────────

impl AgentnsProbe {
    /// Resolve the path to the `assay` binary.
    ///
    /// Returns `None` if neither `env.assay_path` is set nor `assay` can be
    /// found on `$PATH`.
    fn assay_binary(env: &ProbeEnv) -> Option<std::path::PathBuf> {
        if let Some(ref p) = env.assay_path {
            // Explicit override (e.g. test fixture script).
            if p.exists() {
                return Some(p.clone());
            }
            return None;
        }
        // Fall back to PATH lookup.
        which_assay()
    }

    /// Run `assay agentns --json` and parse the output.
    ///
    /// Returns `None` on any error (binary missing, non-zero exit, bad JSON).
    fn run_assay(env: &ProbeEnv) -> Option<AssayReport> {
        let bin = Self::assay_binary(env)?;
        let out = Command::new(&bin)
            .args(["agentns", "--json"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        serde_json::from_slice(&out.stdout).ok()
    }

    /// Build enriched evidence from a `FlagRejected` assay report.
    fn flag_rejected_evidence(
        base: Evidence,
        report: &AssayReport,
        detail: &FlagRejectedDetail,
    ) -> Evidence {
        let collision = detail.collides_with.as_deref().unwrap_or("unknown");
        let errno_str = detail
            .errno
            .map_or_else(|| "unknown".to_owned(), |e| e.to_string());
        let flag_hex = format!("{:#x}", detail.flag);

        // Pull compiled_flag from assay evidence if present.
        let compiled_flag = report
            .evidence
            .get("compiled_flag")
            .and_then(|v| v.as_str())
            .unwrap_or(&flag_hex)
            .to_owned();

        base.with("assay_verdict", "FlagRejected")
            .with("assay_compiled_flag", compiled_flag)
            .with("assay_collides_with", collision.to_owned())
            .with("assay_unshare_errno", errno_str)
            .with(
                "cause",
                format!(
                    "kernel rejects CLONE_NEWAGENT (flag {flag_hex} == {collision}), errno EINVAL"
                ),
            )
            .with(
                "remediation",
                "PRD-agentns-clone-flag-fix; launch-wrap will not help",
            )
    }
}

impl Probe for AgentnsProbe {
    fn name(&self) -> &'static str {
        "agentns"
    }

    fn probe(&self, env: &ProbeEnv) -> PrimitiveReport {
        let Some(raw) = read_trimmed(&env.agent_session_path) else {
            return PrimitiveReport::new(
                self.name(),
                Verdict::Unknown,
                Evidence::single(
                    "agent_session_path",
                    env.agent_session_path.display().to_string(),
                )
                .with("error", "file absent or unreadable"),
            );
        };

        let base_evidence = Evidence::single("agent_session_raw", raw.clone()).with(
            "agent_session_path",
            env.agent_session_path.display().to_string(),
        );

        // All-zeros: 32 hex chars all '0', possibly with dashes (UUID form).
        let stripped = raw.replace('-', "");
        let is_all_zeros = stripped.len() == 32 && stripped.chars().all(|c| c == '0');

        // Non-zero 128-bit hex form: 32 hex digits (possibly with dashes).
        let is_valid_uuid_form =
            stripped.len() == 32 && stripped.chars().all(|c| c.is_ascii_hexdigit());

        if is_all_zeros {
            // Attempt assay enrichment — at most one fork per probe run.
            if let Some(report) = Self::run_assay(env) {
                match &report.verdict {
                    AssayVerdict::FlagRejected { detail } => {
                        let evidence =
                            Self::flag_rejected_evidence(base_evidence, &report, detail);
                        return PrimitiveReport::new(self.name(), Verdict::Inert, evidence);
                    }
                    AssayVerdict::Live { .. } => {
                        let evidence = base_evidence
                            .with("assay_verdict", "Live")
                            .with(
                                "remediation",
                                "wrap the launch (onramp claude-agentns-wrap)",
                            );
                        return PrimitiveReport::new(
                            self.name(),
                            Verdict::MechanismLiveNotWired {
                                remediation: "wrap the launch (onramp claude-agentns-wrap)"
                                    .to_owned(),
                            },
                            evidence,
                        );
                    }
                    AssayVerdict::Other => {
                        // Unknown assay verdict — fall through to plain Inert.
                    }
                }
            }
            // assay absent / errored / unknown verdict — fail-open.
            PrimitiveReport::new(self.name(), Verdict::Inert, base_evidence)
        } else if is_valid_uuid_form {
            PrimitiveReport::new(self.name(), Verdict::Live, base_evidence)
        } else {
            PrimitiveReport::new(self.name(), Verdict::Unknown, base_evidence)
        }
    }
}

/// Minimal PATH-search for `assay` without pulling in the `which` crate.
fn which_assay() -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("assay");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    // ── helpers ──────────────────────────────────────────────────────────

    fn env_with_content(content: &str) -> (ProbeEnv, tempfile::NamedTempFile) {
        let mut f =
            tempfile::NamedTempFile::new().expect("tempfile creation should succeed in tests");
        f.write_all(content.as_bytes())
            .expect("write to tempfile should succeed");
        let env = ProbeEnv::default().with_agent_session(f.path().to_path_buf());
        (env, f)
    }

    /// Create a temporary fixture shell script that emits `json_body` on stdout
    /// and exits 0.  Returns a `TempPath` (caller must keep it alive).
    ///
    /// We return `TempPath` rather than `NamedTempFile` so the write handle is
    /// closed before we try to execute the script.  On Linux, executing an
    /// open file produces ETXTBUSY (os error 26).
    fn fixture_assay_script(json_body: &str) -> tempfile::TempPath {
        let mut f =
            tempfile::NamedTempFile::new().expect("fixture script creation should succeed");
        // Use a heredoc-style approach to avoid quoting issues with the JSON.
        let script = format!(
            "#!/bin/sh\ncat <<'ENDJSON'\n{}\nENDJSON\n",
            json_body
        );
        f.write_all(script.as_bytes())
            .expect("write fixture script should succeed");
        // Make executable.
        let meta = f.as_file().metadata().expect("metadata should be readable");
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        f.as_file()
            .set_permissions(perms)
            .expect("chmod fixture script should succeed");
        // Close the write handle — executing an open file on Linux yields ETXTBUSY.
        f.into_temp_path()
    }

    // ── existing behaviour (regression tests) ────────────────────────────

    #[test]
    fn all_zeros_is_inert_without_assay() {
        let (env, _f) = env_with_content("00000000000000000000000000000000");
        // No assay path configured → fail-open → plain Inert.
        let env = env.with_assay_path("/nonexistent/___assay___");
        let report = AgentnsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Inert);
        assert_eq!(report.name, "agentns");
    }

    #[test]
    fn all_zeros_with_dashes_is_inert() {
        let (env, _f) = env_with_content("00000000-0000-0000-0000-000000000000");
        let env = env.with_assay_path("/nonexistent/___assay___");
        let report = AgentnsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Inert);
    }

    #[test]
    fn non_zero_hex_is_live() {
        let (env, _f) = env_with_content("a1b2c3d4e5f6789012345678aabbccdd");
        let report = AgentnsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Live);
    }

    #[test]
    fn non_zero_uuid_form_is_live() {
        let (env, _f) = env_with_content("a1b2c3d4-e5f6-7890-1234-5678aabbccdd");
        let report = AgentnsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Live);
    }

    #[test]
    fn absent_file_is_unknown() {
        let env =
            ProbeEnv::default().with_agent_session("/nonexistent/___agent_session___");
        let report = AgentnsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Unknown);
    }

    #[test]
    fn garbage_content_is_unknown() {
        let (env, _f) = env_with_content("not-a-uuid-at-all!");
        let report = AgentnsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Unknown);
    }

    #[test]
    fn evidence_records_raw_value() {
        let (env, _f) = env_with_content("00000000000000000000000000000000");
        let env = env.with_assay_path("/nonexistent/___assay___");
        let report = AgentnsProbe.probe(&env);
        assert!(report.evidence.get("agent_session_raw").is_some());
    }

    // ── AC2: FlagRejected assay → Inert + cause/remediation ──────────────

    #[test]
    fn flag_rejected_assay_yields_inert_with_cause() {
        let flag_rejected_json = r#"{
            "primitive": "agentns",
            "verdict": {
                "type": "FlagRejected",
                "detail": { "flag": 256, "collides_with": "CLONE_VM", "errno": 22 }
            },
            "layers_passed": [],
            "evidence": {
                "compiled_flag": "0x100",
                "unshare_errno": "22"
            },
            "kernel_release": "7.0.10-test",
            "checked_at": "2026-06-09T00:00:00Z"
        }"#;

        let script = fixture_assay_script(flag_rejected_json);
        let (env, _f) = env_with_content("00000000000000000000000000000000");
        let env = env.with_assay_path(&*script);

        let report = AgentnsProbe.probe(&env);
        assert_eq!(
            report.verdict,
            Verdict::Inert,
            "verdict must be Inert for FlagRejected"
        );

        let cause = report
            .evidence
            .get("cause")
            .expect("cause must be present");
        assert!(
            cause.contains("CLONE_NEWAGENT"),
            "cause must mention CLONE_NEWAGENT; got: {cause}"
        );
        assert!(
            cause.contains("CLONE_VM"),
            "cause must mention collision; got: {cause}"
        );
        assert!(
            cause.contains("EINVAL"),
            "cause must mention EINVAL; got: {cause}"
        );

        let rem = report
            .evidence
            .get("remediation")
            .expect("remediation must be present");
        assert!(
            rem.contains("PRD-agentns-clone-flag-fix"),
            "remediation must reference the PRD; got: {rem}"
        );
        assert!(
            rem.contains("launch-wrap will not help"),
            "remediation must warn against launch-wrap; got: {rem}"
        );

        assert_eq!(
            report.evidence.get("assay_compiled_flag"),
            Some("0x100"),
            "compiled flag must be 0x100"
        );
        assert_eq!(
            report.evidence.get("assay_collides_with"),
            Some("CLONE_VM")
        );
    }

    // ── AC3: Live assay → MechanismLiveNotWired ───────────────────────────

    #[test]
    fn live_assay_yields_mechanism_live_not_wired() {
        let live_json = r#"{
            "primitive": "agentns",
            "verdict": {
                "type": "Live",
                "detail": { "session": "a1b2c3d4e5f6789012345678aabbccdd" }
            },
            "layers_passed": ["agentns"],
            "evidence": {},
            "kernel_release": "7.0.10-test",
            "checked_at": "2026-06-09T00:00:00Z"
        }"#;

        let script = fixture_assay_script(live_json);
        let (env, _f) = env_with_content("00000000000000000000000000000000");
        let env = env.with_assay_path(&*script);

        let report = AgentnsProbe.probe(&env);
        match &report.verdict {
            Verdict::MechanismLiveNotWired { remediation } => {
                assert!(
                    remediation.contains("onramp") || remediation.contains("launch"),
                    "remediation must mention launch-wrap; got: {remediation}"
                );
            }
            other => panic!("expected MechanismLiveNotWired, got {other:?}"),
        }

        let rem = report
            .evidence
            .get("remediation")
            .expect("remediation must be in evidence");
        assert!(
            rem.contains("onramp") || rem.contains("launch"),
            "evidence remediation must mention launch-wrap"
        );
    }

    // ── AC4: assay absent → byte-identical Inert (fail-open) ─────────────

    #[test]
    fn assay_absent_falls_back_to_plain_inert() {
        let (env, _f) = env_with_content("00000000000000000000000000000000");
        // Point at a definitely-absent path.
        let env = env.with_assay_path("/nonexistent/___assay_fixture___");

        let report = AgentnsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Inert);
        // No cause/remediation should be present (fail-open = no enrichment).
        assert!(
            report.evidence.get("cause").is_none(),
            "fail-open: no cause expected"
        );
        assert!(
            report.evidence.get("remediation").is_none(),
            "fail-open: no remediation expected"
        );
    }

    // ── AC5: JSON backward-compatibility ─────────────────────────────────

    #[test]
    fn old_shaped_inert_deserializes_with_new_enum() {
        // Simulate a JSON payload that was produced before MechanismLiveNotWired
        // was added (old Inert shape, no extra fields).
        let old_json = r#"{"name":"agentns","verdict":{"kind":"Inert"},"evidence":{"pairs":[{"key":"agent_session_raw","value":"00000000000000000000000000000000"},{"key":"agent_session_path","value":"/proc/self/agent_session"}],"detail":null},"checked_at":"2026-06-09T00:00:00Z"}"#;
        let decoded: crate::PrimitiveReport =
            serde_json::from_str(old_json).expect("old-shaped JSON must still deserialize");
        assert_eq!(decoded.verdict, Verdict::Inert);
        assert_eq!(decoded.name, "agentns");
    }

    // ── AC6: assay NOT called when session is non-zero ────────────────────

    #[test]
    fn assay_not_called_when_session_live() {
        // Even if an assay path is configured, it must not be invoked when the
        // session is non-zero (already Live).  We use a script that exits 1 to
        // detect if it's ever called.
        let bad_script = make_failing_script();

        let (env, _f) = env_with_content("a1b2c3d4e5f6789012345678aabbccdd");
        let env = env.with_assay_path(&*bad_script);

        let report = AgentnsProbe.probe(&env);
        // Must be Live (assay was not called — if it had been, we'd get an error).
        assert_eq!(report.verdict, Verdict::Live);
    }

    // ── assay errors / bad JSON → fail-open ──────────────────────────────

    #[test]
    fn assay_exits_nonzero_falls_back_to_inert() {
        let bad_script = make_failing_script();

        let (env, _f) = env_with_content("00000000000000000000000000000000");
        let env = env.with_assay_path(&*bad_script);

        let report = AgentnsProbe.probe(&env);
        assert_eq!(
            report.verdict,
            Verdict::Inert,
            "non-zero assay exit must fall back to Inert"
        );
        assert!(report.evidence.get("cause").is_none());
    }

    #[test]
    fn assay_bad_json_falls_back_to_inert() {
        let bad_json_script = {
            let mut f =
                tempfile::NamedTempFile::new().expect("tempfile should be creatable");
            f.write_all(b"#!/bin/sh\nprintf 'not json at all'\n")
                .expect("write should succeed");
            let meta = f.as_file().metadata().unwrap();
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            f.as_file().set_permissions(perms).unwrap();
            // Close write handle to avoid ETXTBUSY on Linux.
            f.into_temp_path()
        };

        let (env, _f) = env_with_content("00000000000000000000000000000000");
        let env = env.with_assay_path(&*bad_json_script);

        let report = AgentnsProbe.probe(&env);
        assert_eq!(
            report.verdict,
            Verdict::Inert,
            "bad JSON from assay must fall back to Inert"
        );
    }

    // ── helper: script that always exits 1 ───────────────────────────────

    fn make_failing_script() -> tempfile::TempPath {
        let mut f =
            tempfile::NamedTempFile::new().expect("tempfile should be creatable");
        f.write_all(b"#!/bin/sh\nexit 1\n")
            .expect("write should succeed");
        let meta = f.as_file().metadata().unwrap();
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        f.as_file().set_permissions(perms).unwrap();
        // Close write handle to avoid ETXTBUSY on Linux.
        f.into_temp_path()
    }
}
