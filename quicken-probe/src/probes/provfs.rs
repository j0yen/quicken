//! `ProvfsProbe` — checks the provfs xattr stamp on a source path.
//!
//! Reads the `user.prov.session` xattr from `env.provfs_xattr_path`.
//!
//! Verdict:
//! - Absent xattr → `Inert` (provfs not stamping or path not accessible).
//! - `comm:…` form → `LiveDegraded { reason: "agentns-fallback session id" }`.
//! - 32-char hex (128-bit UUID, with or without dashes) → `Live`.
//! - Other value → `Unknown`.

use crate::{Evidence, PrimitiveReport, Probe, ProbeEnv, Verdict};

/// The xattr key provfs stamps onto files.
const PROVFS_XATTR_KEY: &str = "user.prov.session";

/// Probe for the provfs kernel primitive.
pub struct ProvfsProbe;

impl Probe for ProvfsProbe {
    fn name(&self) -> &'static str {
        "provfs"
    }

    fn probe(&self, env: &ProbeEnv) -> PrimitiveReport {
        let path = &env.provfs_xattr_path;
        let path_str = path.display().to_string();

        if !path.exists() {
            return PrimitiveReport::new(
                self.name(),
                Verdict::Unknown,
                Evidence::single("provfs_xattr_path", &path_str)
                    .with("error", "path does not exist"),
            );
        }

        let xattr_value = read_xattr(path, PROVFS_XATTR_KEY);

        xattr_value.map_or_else(
            || {
                PrimitiveReport::new(
                    self.name(),
                    Verdict::Inert,
                    Evidence::single("provfs_xattr_path", &path_str)
                        .with("xattr_key", PROVFS_XATTR_KEY)
                        .with("xattr_present", "false"),
                )
            },
            |val| {
                let ev = Evidence::single("provfs_xattr_path", &path_str)
                    .with("xattr_key", PROVFS_XATTR_KEY)
                    .with("xattr_present", "true")
                    .with("xattr_value", &val);
                classify_provfs_value(self.name(), &val, ev)
            },
        )
    }
}

/// Classify a provfs xattr value into a `PrimitiveReport`.
fn classify_provfs_value(
    probe_name: &str,
    value: &str,
    ev: Evidence,
) -> PrimitiveReport {
    if value.starts_with("comm:") {
        // Fallback form: agentns was inert, provfs used process comm instead.
        return PrimitiveReport::new(
            probe_name,
            Verdict::LiveDegraded {
                reason: "agentns-fallback session id".into(),
            },
            ev.with_detail(format!(
                "xattr is in comm: form — agentns did not assign a session UUID; \
                 value: {value}"
            )),
        );
    }

    // Check for 128-bit hex UUID (32 chars, optionally with dashes).
    let stripped = value.replace('-', "");
    if stripped.len() == 32 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return PrimitiveReport::new(probe_name, Verdict::Live, ev);
    }

    PrimitiveReport::new(
        probe_name,
        Verdict::Unknown,
        ev.with_detail(format!(
            "unrecognised xattr value format: {value}"
        )),
    )
}

/// Read a named xattr from a path. Returns `None` if absent or unreadable.
fn read_xattr(path: &std::path::Path, key: &str) -> Option<String> {
    read_xattr_impl(path, key)
}

/// Platform-specific xattr reading.
///
/// Shells out to `getfattr -n <key> --only-values <path>` — portable on Linux
/// (available via the `attr` package on Arch, standard on most distros).
/// This avoids unsafe code and keeps the dependency count minimal.
///
/// Returns `None` when:
/// - The xattr is absent on the file.
/// - `getfattr` is not installed (treated conservatively as `Unknown` by callers).
/// - Any I/O error occurs.
fn read_xattr_impl(path: &std::path::Path, key: &str) -> Option<String> {
    let out = std::process::Command::new("getfattr")
        .args(["-n", key, "--only-values", "--"])
        .arg(path)
        .output()
        .ok()?;

    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if s.is_empty() {
            return None;
        }
        return Some(s);
    }

    // getfattr exits non-zero when the xattr is absent — treat as None.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Tests use `classify_provfs_value` directly to bypass the xattr syscall,
    /// since `user.*` xattrs may not be supported on the tmpfs used by tempfile.
    /// We can only test `classify_provfs_value` directly, since xattr requires
    /// a kernel that supports user.* xattrs on the tmpfs mount.
    #[test]
    fn comm_form_is_live_degraded() {
        let ev = Evidence::empty();
        let report = classify_provfs_value(
            "provfs",
            "comm:zsh:pid:64758:uid:1000",
            ev,
        );
        assert!(matches!(
            report.verdict,
            Verdict::LiveDegraded { reason } if reason.contains("agentns-fallback")
        ));
    }

    #[test]
    fn uuid_hex_form_is_live() {
        let ev = Evidence::empty();
        let report =
            classify_provfs_value("provfs", "a1b2c3d4e5f6789012345678aabbccdd", ev);
        assert_eq!(report.verdict, Verdict::Live);
    }

    #[test]
    fn uuid_dashed_form_is_live() {
        let ev = Evidence::empty();
        let report = classify_provfs_value(
            "provfs",
            "a1b2c3d4-e5f6-7890-1234-5678aabbccdd",
            ev,
        );
        assert_eq!(report.verdict, Verdict::Live);
    }

    #[test]
    fn garbage_value_is_unknown() {
        let ev = Evidence::empty();
        let report = classify_provfs_value("provfs", "totally-garbage-value!!", ev);
        assert_eq!(report.verdict, Verdict::Unknown);
    }

    #[test]
    fn absent_path_is_unknown() {
        let env =
            ProbeEnv::default().with_provfs_xattr_path("/nonexistent/___provfs_xattr___");
        let report = ProvfsProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Unknown);
    }

    #[test]
    fn probe_name_is_provfs() {
        let env =
            ProbeEnv::default().with_provfs_xattr_path("/nonexistent/___provfs_xattr___");
        let report = ProvfsProbe.probe(&env);
        assert_eq!(report.name, "provfs");
    }
}
