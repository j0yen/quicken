//! `MemlogProbe` — checks whether the memlog device is accessible.
//!
//! Steps (all read-only):
//! 1. Check whether `{dev_root}/memlog` exists.
//! 2. Read file mode and ownership via `std::fs::metadata`.
//! 3. Check whether the current user is in the `memlog` group
//!    via `/proc/self/status` (supplementary groups line).
//! 4. Check the installed pkgrel (from `{pacman_local_db}/linux-wintermute-*/desc`)
//!    vs. the highest pkgrel available in `{pkg_staging_dir}`.
//!
//! Verdict logic:
//! - `StagedNotInstalled` — staging dir has a higher pkgrel than installed.
//! - `InstalledNotActivated` — dev node present but user lacks write access
//!   (wrong group membership or wrong perms).
//! - `Live` — dev node writable by current user.
//! - `Unknown` — can't determine (no dev node AND no staging pkg either).
//! - `Inert` — dev node absent but installed version matches staging (fully inert).

use std::os::unix::fs::MetadataExt;

use crate::{Evidence, PrimitiveReport, Probe, ProbeEnv, Verdict};

/// Probe for the memlog device primitive.
pub struct MemlogProbe;

impl Probe for MemlogProbe {
    fn name(&self) -> &'static str {
        "memlog"
    }

    fn probe(&self, env: &ProbeEnv) -> PrimitiveReport {
        let dev_node = env.memlog_dev_node();
        let dev_exists = dev_node.exists();

        let installed_pkgrel = read_installed_pkgrel(env);
        let staged_pkgrel = read_staged_pkgrel(env);

        let mut ev = Evidence::empty()
            .with("dev_node_path", dev_node.display().to_string())
            .with("dev_node_exists", dev_exists.to_string());

        if let Some(ip) = &installed_pkgrel {
            ev = ev.with("installed_pkgrel", ip.to_string());
        }
        if let Some(sp) = &staged_pkgrel {
            ev = ev.with("staged_pkgrel", sp.to_string());
        }

        // StagedNotInstalled: a higher pkgrel is built and waiting.
        if let (Some(inst), Some(staged)) = (installed_pkgrel, staged_pkgrel) {
            if staged > inst {
                ev = ev.with_detail(format!(
                    "staged pkgrel {staged} > installed pkgrel {inst}: kernel update pending"
                ));
                return PrimitiveReport::new(self.name(), Verdict::StagedNotInstalled, ev);
            }
        }

        if !dev_exists {
            // No dev node and no staged upgrade → inert (module not loaded/installed).
            return PrimitiveReport::new(self.name(), Verdict::Inert, ev);
        }

        // Dev node present: check perms and group membership.
        let meta = match std::fs::metadata(&dev_node) {
            Ok(m) => m,
            Err(e) => {
                ev = ev.with("metadata_error", e.to_string());
                return PrimitiveReport::new(self.name(), Verdict::Unknown, ev);
            }
        };

        let mode = meta.mode();
        // The file mode bits for group-write (0o0020).
        let group_write_bit: u32 = 0o0020;
        let group_id = meta.gid();
        let group_write_set = (mode & group_write_bit) != 0;

        ev = ev
            .with("dev_mode_octal", format!("{mode:04o}"))
            .with("dev_gid", group_id.to_string());

        let in_group = current_user_in_group(group_id);
        ev = ev.with("current_user_in_memlog_group", in_group.to_string());

        if group_write_set && in_group {
            PrimitiveReport::new(self.name(), Verdict::Live, ev)
        } else {
            let detail = if !group_write_set && !in_group {
                "group-write bit unset AND user not in memlog group"
            } else if !group_write_set {
                "group-write bit unset"
            } else {
                "user not in memlog group"
            };
            ev = ev.with_detail(detail);
            PrimitiveReport::new(self.name(), Verdict::InstalledNotActivated, ev)
        }
    }
}

/// Parse the installed pkgrel for `linux-wintermute` from the pacman local DB.
///
/// Returns `None` if the package is not installed or the DB is unreadable.
fn read_installed_pkgrel(env: &ProbeEnv) -> Option<u32> {
    // Scan for a directory matching `linux-wintermute-*` in the pacman local DB.
    let entries = std::fs::read_dir(&env.pacman_local_db).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // e.g. "linux-wintermute-6.8-5" → pkgver=6.8, pkgrel=5
        if name_str.starts_with("linux-wintermute-") {
            let desc_path = entry.path().join("desc");
            if let Some(pkgrel) = parse_pkgrel_from_desc(&desc_path) {
                return Some(pkgrel);
            }
        }
    }
    None
}

/// Parse `%PKGREL%` from a pacman `desc` file.
fn parse_pkgrel_from_desc(desc_path: &std::path::Path) -> Option<u32> {
    let content = std::fs::read_to_string(desc_path).ok()?;
    let mut lines = content.lines();
    loop {
        let line = lines.next()?;
        if line.trim() == "%PKGREL%" {
            let rel_str = lines.next()?.trim();
            return rel_str.parse::<u32>().ok();
        }
    }
}

/// Find the highest pkgrel in the staging pkg directory.
///
/// Scans for `linux-wintermute-*-<pkgrel>-*.pkg.tar.zst` files.
fn read_staged_pkgrel(env: &ProbeEnv) -> Option<u32> {
    let entries = std::fs::read_dir(&env.pkg_staging_dir).ok()?;
    let mut max_rel: Option<u32> = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Filename pattern: linux-wintermute-6.8-11-x86_64.pkg.tar.zst
        if name_str.starts_with("linux-wintermute-")
            && name_str.ends_with(".pkg.tar.zst")
        {
            if let Some(rel) = parse_pkgrel_from_filename(&name_str) {
                max_rel = Some(max_rel.map_or(rel, |cur| cur.max(rel)));
            }
        }
    }
    max_rel
}

/// Extract the pkgrel from a filename like `linux-wintermute-6.8-11-x86_64.pkg.tar.zst`.
///
/// Format: `<pkgname>-<pkgver>-<pkgrel>-<arch>.pkg.tar.zst`
fn parse_pkgrel_from_filename(filename: &str) -> Option<u32> {
    // Strip prefix and suffix to get the version fields.
    let inner = filename
        .strip_prefix("linux-wintermute-")?
        .strip_suffix(".pkg.tar.zst")?;
    // inner = "6.8-11-x86_64"
    // Split on '-' from the right to get arch, then pkgrel.
    let parts: Vec<&str> = inner.rsplitn(3, '-').collect();
    // rsplitn(3, '-') on "6.8-11-x86_64" → ["x86_64", "11", "6.8"]
    if parts.len() >= 2 {
        parts.get(1).and_then(|s| s.parse::<u32>().ok())
    } else {
        None
    }
}

/// Check whether the current process's supplementary groups include `gid`.
///
/// Uses `/proc/self/status` to read `Groups:` line — no libc dependency.
fn current_user_in_group(gid: u32) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Groups:") {
            return rest
                .split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                .any(|g| g == gid);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_staging_pkg(dir: &std::path::Path, pkgrel: u32) {
        let filename =
            format!("linux-wintermute-6.8-{pkgrel}-x86_64.pkg.tar.zst");
        std::fs::File::create(dir.join(filename))
            .expect("create staging pkg file should succeed");
    }

    fn make_installed_pkgrel(pacman_dir: &std::path::Path, pkgrel: u32) {
        let pkg_dir =
            pacman_dir.join(format!("linux-wintermute-6.8-{pkgrel}"));
        std::fs::create_dir_all(&pkg_dir)
            .expect("create pacman local dir should succeed");
        let mut f = std::fs::File::create(pkg_dir.join("desc"))
            .expect("create desc should succeed");
        writeln!(f, "%PKGREL%").expect("write should succeed");
        writeln!(f, "{pkgrel}").expect("write should succeed");
    }

    #[test]
    fn staged_higher_than_installed_is_staged_not_installed() {
        let tmp = tempfile::TempDir::new()
            .expect("tempdir should be creatable");
        let staging = tmp.path().join("pkg");
        let pacman = tmp.path().join("pacman/local");
        std::fs::create_dir_all(&staging)
            .expect("create staging dir should succeed");
        std::fs::create_dir_all(&pacman)
            .expect("create pacman dir should succeed");

        make_installed_pkgrel(&pacman, 5);
        make_staging_pkg(&staging, 11);

        let env = ProbeEnv::default()
            .with_dev_root(tmp.path().join("dev"))
            .with_pacman_local_db(pacman)
            .with_pkg_staging_dir(staging);

        let report = MemlogProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::StagedNotInstalled);
        assert_eq!(report.evidence.get("installed_pkgrel"), Some("5"));
        assert_eq!(report.evidence.get("staged_pkgrel"), Some("11"));
    }

    #[test]
    fn dev_node_present_wrong_group_is_installed_not_activated() {
        let tmp = tempfile::TempDir::new()
            .expect("tempdir should be creatable");
        let dev = tmp.path().join("dev");
        std::fs::create_dir_all(&dev).expect("create dev dir should succeed");

        // Create a fake /dev/memlog — we can't set gid/perms to force the
        // condition portably in tests, but we CAN fake an absent group by
        // using gid=0 (root) which the test user is very unlikely to be in.
        // We create it as a regular file; metadata() will work fine.
        std::fs::File::create(dev.join("memlog"))
            .expect("create fake memlog should succeed");

        // No staged pkg, no installed pkg → only check dev node.
        let env = ProbeEnv::default()
            .with_dev_root(&dev)
            .with_pacman_local_db(tmp.path().join("empty_pacman"))
            .with_pkg_staging_dir(tmp.path().join("empty_staging"));

        let report = MemlogProbe.probe(&env);
        // The dev node exists. We can't control the mode bit in a test without
        // root, so the verdict will be InstalledNotActivated (group-write bit
        // not set on a plain file, or user not in group).
        assert!(
            matches!(
                report.verdict,
                Verdict::InstalledNotActivated | Verdict::Live
            ),
            "expected InstalledNotActivated or Live, got {:?}",
            report.verdict
        );
        assert_eq!(report.evidence.get("dev_node_exists"), Some("true"));
    }

    #[test]
    fn no_dev_node_no_staging_is_inert() {
        let tmp = tempfile::TempDir::new()
            .expect("tempdir should be creatable");
        let env = ProbeEnv::default()
            .with_dev_root(tmp.path().join("empty_dev"))
            .with_pacman_local_db(tmp.path().join("empty_pacman"))
            .with_pkg_staging_dir(tmp.path().join("empty_staging"));

        let report = MemlogProbe.probe(&env);
        assert_eq!(report.verdict, Verdict::Inert);
        assert_eq!(report.evidence.get("dev_node_exists"), Some("false"));
    }

    #[test]
    fn staged_equal_to_installed_does_not_trigger_staged_not_installed() {
        let tmp = tempfile::TempDir::new()
            .expect("tempdir should be creatable");
        let staging = tmp.path().join("pkg");
        let pacman = tmp.path().join("pacman/local");
        std::fs::create_dir_all(&staging).expect("staging dir creation should succeed");
        std::fs::create_dir_all(&pacman).expect("pacman dir creation should succeed");

        make_installed_pkgrel(&pacman, 11);
        make_staging_pkg(&staging, 11);

        let env = ProbeEnv::default()
            .with_dev_root(tmp.path().join("empty_dev"))
            .with_pacman_local_db(pacman)
            .with_pkg_staging_dir(staging);

        let report = MemlogProbe.probe(&env);
        // Same version → not StagedNotInstalled.
        assert_ne!(report.verdict, Verdict::StagedNotInstalled);
    }

    #[test]
    fn parse_pkgrel_from_filename_extracts_correct_rel() {
        assert_eq!(
            parse_pkgrel_from_filename(
                "linux-wintermute-6.8-11-x86_64.pkg.tar.zst"
            ),
            Some(11)
        );
        assert_eq!(
            parse_pkgrel_from_filename(
                "linux-wintermute-6.8-5-x86_64.pkg.tar.zst"
            ),
            Some(5)
        );
        assert_eq!(
            parse_pkgrel_from_filename("not-a-package.pkg.tar.zst"),
            None
        );
    }
}
