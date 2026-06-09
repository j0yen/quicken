//! `Verdict` — classification of a primitive's liveness.

use serde::{Deserialize, Serialize};

/// Liveness classification for a wintermute kernel primitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail")]
#[non_exhaustive]
pub enum Verdict {
    /// The primitive is fully operational.
    Live,

    /// The primitive is running but with degraded behaviour.
    ///
    /// Example: provfs is stamping xattrs using the fallback `comm:` form
    /// because agentns is inert rather than the full 128-bit session UUID.
    LiveDegraded {
        /// Human-readable explanation of the degradation.
        reason: String,
    },

    /// A newer package version exists in the staging pkg dir but it has not
    /// been installed yet (e.g. kernel pkgrel 11 built but pkgrel 5 installed).
    StagedNotInstalled,

    /// The package is installed at the correct version but activation has not
    /// occurred (e.g. `/dev/memlog` exists with wrong perms, user not in group).
    InstalledNotActivated,

    /// The primitive is entirely inert at runtime
    /// (e.g. `/proc/self/agent_session` returns all-zeros).
    Inert,

    /// The kernel mechanism works (assay confirms it creates a namespace
    /// successfully) but the live process was not wrapped at launch.
    ///
    /// Remediation: wrap the launch (e.g. `onramp claude-agentns-wrap`).
    /// This verdict only appears for agentns when `assay agentns --json`
    /// reports `Live` but the live session reads all-zeros.
    MechanismLiveNotWired {
        /// Human-readable remediation advice.
        remediation: String,
    },

    /// The probe could not determine liveness because a required surface was
    /// absent, unreadable, or returned unexpected data.
    Unknown,
}

impl Verdict {
    /// Returns `true` when the verdict is at least as good as `LiveDegraded`.
    ///
    /// Used by `quicken probe` exit-code logic: exit 0 iff all primitives pass
    /// this threshold.
    #[must_use]
    pub const fn is_acceptable(&self) -> bool {
        matches!(self, Self::Live | Self::LiveDegraded { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_is_acceptable() {
        assert!(Verdict::Live.is_acceptable());
    }

    #[test]
    fn live_degraded_is_acceptable() {
        assert!(Verdict::LiveDegraded { reason: "test".into() }.is_acceptable());
    }

    #[test]
    fn inert_not_acceptable() {
        assert!(!Verdict::Inert.is_acceptable());
    }

    #[test]
    fn installed_not_activated_not_acceptable() {
        assert!(!Verdict::InstalledNotActivated.is_acceptable());
    }

    #[test]
    fn staged_not_installed_not_acceptable() {
        assert!(!Verdict::StagedNotInstalled.is_acceptable());
    }

    #[test]
    fn unknown_not_acceptable() {
        assert!(!Verdict::Unknown.is_acceptable());
    }

    #[test]
    fn mechanism_live_not_wired_not_acceptable() {
        assert!(!Verdict::MechanismLiveNotWired {
            remediation: "wrap the launch".into()
        }
        .is_acceptable());
    }
}
