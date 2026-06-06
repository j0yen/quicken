//! `AgentnsProbe` — checks whether the agentns kernel module is active.
//!
//! Reads `/proc/self/agent_session` (or `env.agent_session_path`).
//! - All-zeros UUID → `Inert` (module loaded but no session assigned).
//! - Non-zero 128-bit hex → `Live`.
//! - File absent or unreadable → `Unknown`.

use crate::{
    env::read_trimmed, Evidence, PrimitiveReport, Probe, ProbeEnv, Verdict,
};

/// Probe for the agentns kernel primitive.
pub struct AgentnsProbe;

impl Probe for AgentnsProbe {
    fn name(&self) -> &'static str {
        "agentns"
    }

    fn probe(&self, env: &ProbeEnv) -> PrimitiveReport {
        let Some(raw) = read_trimmed(&env.agent_session_path) else {
            return PrimitiveReport::new(
                self.name(),
                Verdict::Unknown,
                Evidence::single("agent_session_path", env.agent_session_path.display().to_string())
                    .with("error", "file absent or unreadable"),
            );
        };

        let evidence = Evidence::single("agent_session_raw", raw.clone())
            .with("agent_session_path", env.agent_session_path.display().to_string());

        // All-zeros: 32 hex chars all '0', possibly with dashes (UUID form).
        let stripped = raw.replace('-', "");
        let is_all_zeros = stripped.len() == 32 && stripped.chars().all(|c| c == '0');

        // Non-zero 128-bit hex form: 32 hex digits (possibly with dashes).
        let is_valid_uuid_form =
            stripped.len() == 32 && stripped.chars().all(|c| c.is_ascii_hexdigit());

        let verdict = if is_all_zeros {
            Verdict::Inert
        } else if is_valid_uuid_form {
            Verdict::Live
        } else {
            Verdict::Unknown
        };

        PrimitiveReport::new(self.name(), verdict, evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn env_with_content(content: &str) -> (ProbeEnv, tempfile::NamedTempFile) {
        let mut f =
            tempfile::NamedTempFile::new().expect("tempfile creation should succeed in tests");
        f.write_all(content.as_bytes())
            .expect("write to tempfile should succeed");
        let env = ProbeEnv::default().with_agent_session(f.path().to_path_buf());
        (env, f)
    }

    #[test]
    fn all_zeros_is_inert() {
        let (env, _f) = env_with_content("00000000000000000000000000000000");
        let report = AgentnsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Inert);
        assert_eq!(report.name, "agentns");
    }

    #[test]
    fn all_zeros_with_dashes_is_inert() {
        let (env, _f) = env_with_content("00000000-0000-0000-0000-000000000000");
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
        let env = ProbeEnv::default()
            .with_agent_session("/nonexistent/___agent_session___");
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
        let report = AgentnsProbe.probe(&env);
        assert!(report.evidence.get("agent_session_raw").is_some());
    }
}
