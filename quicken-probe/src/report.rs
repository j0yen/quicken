//! `PrimitiveReport` — the output of one probe run.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Evidence, Verdict};

/// The complete report produced by a single `Probe::probe()` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimitiveReport {
    /// Short probe identifier (e.g. `"memlog"`, `"agentns"`).
    pub name: String,
    /// Classification of this primitive's liveness.
    pub verdict: Verdict,
    /// The observations the verdict was derived from.
    pub evidence: Evidence,
    /// When this probe was run (UTC).
    pub checked_at: DateTime<Utc>,
}

impl PrimitiveReport {
    /// Create a new report stamped with the current UTC time.
    #[must_use]
    pub fn new(name: impl Into<String>, verdict: Verdict, evidence: Evidence) -> Self {
        Self {
            name: name.into(),
            verdict,
            evidence,
            checked_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize_roundtrip() {
        let report = PrimitiveReport::new(
            "memlog",
            Verdict::InstalledNotActivated,
            Evidence::single("dev_node_exists", "true"),
        );
        let json = serde_json::to_string(&report)
            .expect("serialize should not fail in tests with valid data");
        let decoded: PrimitiveReport = serde_json::from_str(&json)
            .expect("deserialize should not fail with valid json");
        assert_eq!(decoded.name, "memlog");
        assert_eq!(decoded.verdict, Verdict::InstalledNotActivated);
    }

    #[test]
    fn serialize_vec_roundtrip() {
        let reports = vec![
            PrimitiveReport::new("agentns", Verdict::Inert, Evidence::empty()),
            PrimitiveReport::new(
                "provfs",
                Verdict::LiveDegraded { reason: "agentns-fallback session id".into() },
                Evidence::single("xattr_value", "comm:zsh:pid:1234:uid:1000"),
            ),
        ];
        let json = serde_json::to_string(&reports)
            .expect("serialize vec should succeed");
        let decoded: Vec<PrimitiveReport> = serde_json::from_str(&json)
            .expect("deserialize vec should succeed");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].verdict, Verdict::Inert);
        match &decoded[1].verdict {
            Verdict::LiveDegraded { reason } => {
                assert!(reason.contains("agentns-fallback"));
            }
            other => panic!("expected LiveDegraded, got {other:?}"),
        }
    }
}
