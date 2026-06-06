//! AC3: `MemlogProbe` returns `StagedNotInstalled` when the fixture pkg dir
//! contains a higher pkgrel than the fixture installed version, and the
//! evidence records both pkgrels (deterministic on the known 5-vs-11 fixture).

use std::io::Write;

use quicken_probe::{MemlogProbe, Probe, ProbeEnv, Verdict};

fn make_staging_pkg(dir: &std::path::Path, pkgrel: u32) {
    let filename = format!("linux-wintermute-6.8-{pkgrel}-x86_64.pkg.tar.zst");
    std::fs::File::create(dir.join(filename)).expect("create staging pkg");
}

fn make_installed_pkgrel(pacman_dir: &std::path::Path, pkgrel: u32) {
    let pkg_dir = pacman_dir.join(format!("linux-wintermute-6.8-{pkgrel}"));
    std::fs::create_dir_all(&pkg_dir).expect("create pacman pkg dir");
    let mut f = std::fs::File::create(pkg_dir.join("desc")).expect("create desc");
    writeln!(f, "%PKGREL%").expect("write");
    writeln!(f, "{pkgrel}").expect("write");
}

#[test]
fn pkgrel_5_installed_11_staged_gives_staged_not_installed() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let staging = tmp.path().join("pkg");
    let pacman = tmp.path().join("pacman/local");
    std::fs::create_dir_all(&staging).expect("create staging");
    std::fs::create_dir_all(&pacman).expect("create pacman");

    make_installed_pkgrel(&pacman, 5);
    make_staging_pkg(&staging, 11);

    let env = ProbeEnv::default()
        // No dev node in empty_dev → don't confuse the devnode check.
        .with_dev_root(tmp.path().join("empty_dev"))
        .with_pacman_local_db(&pacman)
        .with_pkg_staging_dir(&staging);

    let report = MemlogProbe.probe(&env);

    assert_eq!(
        report.verdict,
        Verdict::StagedNotInstalled,
        "installed=5, staged=11 should give StagedNotInstalled, got {:?}",
        report.verdict
    );
}

#[test]
fn evidence_records_both_pkgrels_for_5_vs_11() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let staging = tmp.path().join("pkg");
    let pacman = tmp.path().join("pacman/local");
    std::fs::create_dir_all(&staging).expect("create staging");
    std::fs::create_dir_all(&pacman).expect("create pacman");

    make_installed_pkgrel(&pacman, 5);
    make_staging_pkg(&staging, 11);

    let env = ProbeEnv::default()
        .with_dev_root(tmp.path().join("empty_dev"))
        .with_pacman_local_db(&pacman)
        .with_pkg_staging_dir(&staging);

    let report = MemlogProbe.probe(&env);

    assert_eq!(
        report.evidence.get("installed_pkgrel"),
        Some("5"),
        "evidence should record installed_pkgrel=5"
    );
    assert_eq!(
        report.evidence.get("staged_pkgrel"),
        Some("11"),
        "evidence should record staged_pkgrel=11"
    );
}
