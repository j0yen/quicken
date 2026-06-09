//! `ProbeEnv` — abstraction over filesystem roots and tool paths.
//!
//! This lets tests point probes at fixture directories rather than the real
//! system, so all tests are deterministic and network-free.

use std::path::{Path, PathBuf};

/// Environment context injected into every `Probe::probe()` call.
///
/// All paths default to real system paths. Tests construct a `ProbeEnv`
/// with fixture roots to run probes deterministically.
#[derive(Debug, Clone)]
pub struct ProbeEnv {
    /// Root of the device filesystem (real: `/dev`).
    pub dev_root: PathBuf,
    /// Path to the agent-session pseudo-file (real: `/proc/self/agent_session`).
    pub agent_session_path: PathBuf,
    /// Path to the xattr source file for provfs probing.
    /// Real: any file provfs stamps (e.g. `~/.local/share/wintermute/last-run`).
    pub provfs_xattr_path: PathBuf,
    /// Path to the pacman local database (real: `/var/lib/pacman/local`).
    pub pacman_local_db: PathBuf,
    /// Directory containing staged `.pkg.tar.zst` files (real: `~/wintermute/wintermute-kernel/pkg`).
    pub pkg_staging_dir: PathBuf,
    /// Path to the `bpolicy` binary (real: `~/.local/bin/bpolicy`).
    pub bpolicy_path: PathBuf,
    /// Optional: path to a `bpolicy status` output fixture file.
    /// When `Some`, `WardenProbe` reads this file instead of running `bpolicy`.
    pub bpolicy_status_fixture: Option<PathBuf>,
    /// Optional override for the `assay` binary path.
    ///
    /// When `None` (the default), `AgentnsProbe` searches `$PATH` for `assay`.
    /// Tests inject an explicit fixture script path here so the probe never
    /// touches the real `assay` binary.
    pub assay_path: Option<PathBuf>,
}

impl Default for ProbeEnv {
    fn default() -> Self {
        let home = dirs_or_fallback();
        Self {
            dev_root: PathBuf::from("/dev"),
            agent_session_path: PathBuf::from("/proc/self/agent_session"),
            provfs_xattr_path: home
                .join(".local/share/wintermute/last-run"),
            pacman_local_db: PathBuf::from("/var/lib/pacman/local"),
            pkg_staging_dir: home
                .join("wintermute/wintermute-kernel/pkg"),
            bpolicy_path: home.join(".local/bin/bpolicy"),
            bpolicy_status_fixture: None,
            assay_path: None,
        }
    }
}

impl ProbeEnv {
    /// Create a new `ProbeEnv` with the given dev root (for testing).
    #[must_use]
    pub fn with_dev_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.dev_root = path.into();
        self
    }

    /// Override the `agent_session` path (for testing).
    #[must_use]
    pub fn with_agent_session(mut self, path: impl Into<PathBuf>) -> Self {
        self.agent_session_path = path.into();
        self
    }

    /// Override the provfs xattr source path (for testing).
    #[must_use]
    pub fn with_provfs_xattr_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.provfs_xattr_path = path.into();
        self
    }

    /// Override the pacman local db root (for testing).
    #[must_use]
    pub fn with_pacman_local_db(mut self, path: impl Into<PathBuf>) -> Self {
        self.pacman_local_db = path.into();
        self
    }

    /// Override the pkg staging dir (for testing).
    #[must_use]
    pub fn with_pkg_staging_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.pkg_staging_dir = path.into();
        self
    }

    /// Point `WardenProbe` at a fixture status file instead of running bpolicy.
    #[must_use]
    pub fn with_bpolicy_fixture(mut self, path: impl Into<PathBuf>) -> Self {
        self.bpolicy_status_fixture = Some(path.into());
        self
    }

    /// Override the `assay` binary path (for testing).
    ///
    /// Tests should inject a fixture shell script that emits a known JSON
    /// payload so `AgentnsProbe` bridge logic can be exercised deterministically.
    #[must_use]
    pub fn with_assay_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.assay_path = Some(path.into());
        self
    }

    /// Convenience: does the memlog device node exist in `dev_root`?
    #[must_use]
    pub fn memlog_dev_node(&self) -> PathBuf {
        self.dev_root.join("memlog")
    }
}

/// Helper that does not pull in the `dirs` crate.
fn dirs_or_fallback() -> PathBuf {
    std::env::var("HOME").map_or_else(|_| PathBuf::from("/root"), PathBuf::from)
}

/// Reads the content of a path as a UTF-8 string, mapping any I/O or encoding
/// error to `None` (the probes treat `None` as `Unknown`).
///
/// Trims trailing whitespace so callers don't need to worry about newlines.
pub(crate) fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_env_paths_are_absolute() {
        let env = ProbeEnv::default();
        assert!(env.dev_root.is_absolute());
        assert!(env.agent_session_path.is_absolute());
    }

    #[test]
    fn read_trimmed_missing_returns_none() {
        assert_eq!(read_trimmed(Path::new("/nonexistent/___path___")), None);
    }

    #[test]
    fn read_trimmed_strips_newline() {
        let mut f = tempfile::NamedTempFile::new()
            .expect("tempfile should be creatable in tests");
        f.write_all(b"hello\n").expect("write should succeed");
        let path = f.path().to_path_buf();
        assert_eq!(read_trimmed(&path).as_deref(), Some("hello"));
    }
}
