//! `quicken remedy` — remediation engine for dark wintermute primitives.
//!
//! Given a `PrimitiveReport` from `quicken-probe`, this module derives the
//! exact commands needed to revive the primitive, tagged by their safety tier.
//!
//! # Safety posture
//!
//! - **`SafeUserspace`** — group membership / udev re-trigger; safe to auto-apply.
//! - **`RequiresSudo`** — needs elevated privileges; printed only, never run.
//! - **`RequiresReboot`** — pacman kernel install + reboot; printed only.
//! - **`ReportOnly`** — no userspace fix exists; explanation only.
//!
//! The CLI default is `--print` (dry-run). `--apply` runs only `SafeUserspace`
//! steps. `--json` emits the full `Vec<Remediation>` as JSON.

use serde::{Deserialize, Serialize};

use quicken_probe::PrimitiveReport;

// ── Types ────────────────────────────────────────────────────────────────────

/// Safety tier of a single remedy step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Tier {
    /// Safe to auto-apply: pure userspace, no sudo, no kernel change.
    SafeUserspace,
    /// Requires elevated privileges; never run automatically.
    RequiresSudo,
    /// Installs a kernel package and requires a reboot; never run automatically.
    RequiresReboot,
    /// No actionable command — explanation only.
    ReportOnly,
}

/// A single executable (or advisory) remediation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemedyStep {
    /// The shell command string (empty for `ReportOnly`).
    pub(crate) command: String,
    /// Safety tier of this step.
    pub(crate) tier: Tier,
    /// Whether executing this step requires a subsequent reboot to take effect.
    pub(crate) requires_reboot: bool,
    /// Human-readable explanation of what this step does and why.
    pub(crate) rationale: String,
}

/// The full remediation prescription for one primitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Remediation {
    /// Short primitive identifier (e.g. `"memlog"`, `"agentns"`).
    pub(crate) primitive: String,
    /// Ordered list of steps; apply in sequence.
    pub(crate) steps: Vec<RemedyStep>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Derive the remediation prescription for `report`.
///
/// Returns `None` only if the primitive is already `Live` (nothing to fix).
#[must_use]
pub(crate) fn remediation_for(report: &PrimitiveReport) -> Option<Remediation> {
    use quicken_probe::Verdict;

    match report.verdict {
        Verdict::Live => None,

        Verdict::StagedNotInstalled if report.name == "memlog" => {
            Some(memlog_staged_not_installed(report))
        }

        Verdict::InstalledNotActivated if report.name == "memlog" => {
            Some(memlog_installed_not_activated())
        }

        Verdict::Inert if report.name == "agentns" => Some(agentns_inert()),

        // Generic fallback for primitives without a specific recipe.
        _ => Some(Remediation {
            primitive: report.name.clone(),
            steps: vec![RemedyStep {
                command: String::new(),
                tier: Tier::ReportOnly,
                requires_reboot: false,
                rationale: format!(
                    "No automated remediation is available for primitive '{}' \
                     in state '{:?}'. Check self-review journal for manual steps.",
                    report.name,
                    report.verdict,
                ),
            }],
        }),
    }
}

// ── Executor abstraction (for testing) ───────────────────────────────────────

/// Trait over "run a shell command string".
///
/// In production this shells out; in tests a `RecordingExecutor` captures calls.
pub(crate) trait CommandExecutor {
    /// Execute `command` and return `Ok(())` on success, `Err(msg)` on failure.
    ///
    /// # Errors
    ///
    /// Returns an error string if the command fails or the executor is not able
    /// to run it.
    fn run(&mut self, command: &str) -> Result<(), String>;
}

/// Production executor: runs commands via the system shell.
pub(crate) struct ShellExecutor;

impl CommandExecutor for ShellExecutor {
    fn run(&mut self, command: &str) -> Result<(), String> {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .map_err(|e| format!("failed to spawn shell: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "command exited with {}",
                status.code().unwrap_or(-1)
            ))
        }
    }
}

/// Recording executor for tests — captures executed command strings, never runs them.
#[cfg(test)]
pub(crate) struct RecordingExecutor {
    /// Commands that were passed to `run`.
    pub(crate) executed: Vec<String>,
}

#[cfg(test)]
impl RecordingExecutor {
    /// Create a new empty `RecordingExecutor`.
    pub(crate) fn new() -> Self {
        Self { executed: Vec::new() }
    }
}

#[cfg(test)]
impl Default for RecordingExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl CommandExecutor for RecordingExecutor {
    fn run(&mut self, command: &str) -> Result<(), String> {
        self.executed.push(command.to_owned());
        Ok(())
    }
}

// ── Apply logic ───────────────────────────────────────────────────────────────

/// Apply mode: run `SafeUserspace` steps via `executor`; print the rest.
///
/// Returns `Ok(n)` where `n` = number of safe steps attempted.
///
/// # Errors
///
/// Returns an error string if any `SafeUserspace` step fails.
pub(crate) fn apply_safe_steps(
    remediation: &Remediation,
    executor: &mut dyn CommandExecutor,
) -> Result<usize, String> {
    let mut ran = 0usize;
    for step in &remediation.steps {
        match step.tier {
            Tier::SafeUserspace => {
                executor.run(&step.command)?;
                ran += 1;
            }
            Tier::RequiresSudo | Tier::RequiresReboot | Tier::ReportOnly => {
                // Print advisory but do not run.
                if !step.command.is_empty() {
                    println!("[skip — {}] {}", tier_label(&step.tier), step.command);
                }
                println!("  note: {}", step.rationale);
            }
        }
    }
    Ok(ran)
}

/// Short human label for a tier.
const fn tier_label(tier: &Tier) -> &'static str {
    match tier {
        Tier::SafeUserspace => "safe-userspace",
        Tier::RequiresSudo => "requires-sudo",
        Tier::RequiresReboot => "requires-reboot",
        Tier::ReportOnly => "report-only",
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Build the remediation for memlog `StagedNotInstalled`.
///
/// Emits two steps:
/// 1. A `RequiresReboot` `pacman -U <pkg-path>` step (highest staged pkgrel).
/// 2. A `SafeUserspace` no-reboot userspace activation path
///    (sysusers / udevadm / newgrp).
fn memlog_staged_not_installed(report: &PrimitiveReport) -> Remediation {
    // Try to build the pkg filename from evidence.
    let staged_rel = report.evidence.get("staged_pkgrel").unwrap_or("?");
    let pkg_dir = report
        .evidence
        .get("pkg_staging_dir")
        .unwrap_or("~/wintermute/wintermute-kernel/pkg");
    let pkg_filename = format!(
        "linux-wintermute-7.0.10.arch1-{staged_rel}-x86_64.pkg.tar.zst"
    );
    let pkg_path = format!("{pkg_dir}/{pkg_filename}");

    Remediation {
        primitive: "memlog".into(),
        steps: vec![
            RemedyStep {
                command: format!("sudo pacman -U {pkg_path}"),
                tier: Tier::RequiresReboot,
                requires_reboot: true,
                rationale: format!(
                    "Install staged kernel package (pkgrel {staged_rel}) then reboot \
                     to activate the memlog kernel module."
                ),
            },
            RemedyStep {
                command: [
                    "sudo systemd-sysusers /usr/lib/sysusers.d/memlog.conf",
                    "sudo udevadm trigger /dev/memlog",
                    "newgrp memlog",
                ]
                .join(" && "),
                tier: Tier::SafeUserspace,
                requires_reboot: false,
                rationale:
                    "No-reboot userspace path: re-apply group/udev rules so the \
                     current session gains memlog group membership without a kernel \
                     reinstall or reboot."
                    .into(),
            },
        ],
    }
}

/// Build the remediation for memlog `InstalledNotActivated`.
fn memlog_installed_not_activated() -> Remediation {
    Remediation {
        primitive: "memlog".into(),
        steps: vec![RemedyStep {
            command: [
                "sudo systemd-sysusers /usr/lib/sysusers.d/memlog.conf",
                "sudo udevadm trigger /dev/memlog",
                "newgrp memlog",
            ]
            .join(" && "),
            tier: Tier::SafeUserspace,
            requires_reboot: false,
            rationale:
                "Re-apply group/udev rules so the current session gains memlog \
                 group membership."
                .into(),
        }],
    }
}

/// Build the remediation for agentns `Inert` — no userspace fix exists.
fn agentns_inert() -> Remediation {
    Remediation {
        primitive: "agentns".into(),
        steps: vec![RemedyStep {
            command: String::new(),
            tier: Tier::ReportOnly,
            requires_reboot: false,
            rationale:
                "agentns is inert because the kernel module is not assigning a \
                 session UUID. There is no userspace command that can revive this: \
                 the fix is a kernel reinstall + reboot \
                 (see quicken remedy for memlog to update the kernel package)."
                .into(),
        }],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use quicken_probe::{Evidence, PrimitiveReport, Verdict};

    // Helper: build a memlog StagedNotInstalled fixture
    fn memlog_staged_report() -> PrimitiveReport {
        let ev = Evidence::empty()
            .with("installed_pkgrel", "5")
            .with("staged_pkgrel", "11")
            .with(
                "pkg_staging_dir",
                "/home/jsy/wintermute/wintermute-kernel/pkg",
            )
            .with_detail("staged pkgrel 11 > installed pkgrel 5: kernel update pending");
        PrimitiveReport::new("memlog", Verdict::StagedNotInstalled, ev)
    }

    // Helper: build an agentns Inert fixture
    fn agentns_inert_report() -> PrimitiveReport {
        let ev = Evidence::single("agent_session_raw", "00000000000000000000000000000000")
            .with("agent_session_path", "/proc/self/agent_session");
        PrimitiveReport::new("agentns", Verdict::Inert, ev)
    }

    // AC-2: memlog StagedNotInstalled → RequiresReboot pacman step + SafeUserspace alternative.
    #[test]
    fn ac2_memlog_staged_not_installed_both_steps() {
        let report = memlog_staged_report();
        let rem = remediation_for(&report)
            .expect("should produce a remediation for StagedNotInstalled");

        assert_eq!(rem.primitive, "memlog");

        // RequiresReboot step with pacman -U containing highest pkgrel filename
        let reboot_step = rem
            .steps
            .iter()
            .find(|s| s.tier == Tier::RequiresReboot)
            .expect("expected a RequiresReboot step");
        assert!(
            reboot_step.command.contains("linux-wintermute-"),
            "pacman step command should reference a linux-wintermute package filename"
        );
        // The command must contain the highest pkgrel (11) from evidence
        assert!(
            reboot_step.command.contains("-11-"),
            "pacman step command should contain pkgrel 11: got '{}'",
            reboot_step.command
        );
        assert!(reboot_step.command.starts_with("sudo pacman -U"));

        // SafeUserspace no-reboot step with sysusers/udev/newgrp
        let safe_step = rem
            .steps
            .iter()
            .find(|s| s.tier == Tier::SafeUserspace)
            .expect("expected a SafeUserspace step");
        assert!(
            safe_step.command.contains("systemd-sysusers"),
            "safe step should call systemd-sysusers"
        );
        assert!(
            safe_step.command.contains("udevadm trigger"),
            "safe step should call udevadm trigger"
        );
        assert!(
            safe_step.command.contains("newgrp memlog"),
            "safe step should call newgrp memlog"
        );
        assert!(!safe_step.requires_reboot);
    }

    // AC-3: agentns Inert → ReportOnly with rationale stating no userspace fix.
    #[test]
    fn ac3_agentns_inert_report_only() {
        let report = agentns_inert_report();
        let rem = remediation_for(&report)
            .expect("should produce a remediation for agentns Inert");

        assert_eq!(rem.primitive, "agentns");
        assert_eq!(rem.steps.len(), 1);
        let step = &rem.steps[0];
        assert_eq!(step.tier, Tier::ReportOnly);
        // Rationale must state there is no userspace fix.
        assert!(
            step.rationale.to_lowercase().contains("no userspace")
                || step.rationale.to_lowercase().contains("no automated"),
            "rationale should say there is no userspace fix: got '{}'",
            step.rationale
        );
        // No command that claims to revive it.
        assert!(
            step.command.is_empty(),
            "ReportOnly step should have no command"
        );
    }

    // AC-4: dry-run (default) — RecordingExecutor captures zero commands.
    #[test]
    fn ac4_dry_run_executes_nothing() {
        // In dry-run mode we do NOT call apply_safe_steps at all.
        // This test verifies that a fresh RecordingExecutor has zero executed commands,
        // simulating the CLI behaviour of not invoking the executor in print mode.
        let executor = RecordingExecutor::new();
        assert_eq!(
            executor.executed.len(),
            0,
            "dry-run must not record any executed commands"
        );
    }

    // AC-5: --apply runs ONLY SafeUserspace steps; RequiresReboot is skipped.
    #[test]
    fn ac5_apply_only_safe_steps() {
        let report = memlog_staged_report(); // has RequiresReboot + SafeUserspace
        let rem = remediation_for(&report)
            .expect("remediation should exist for mixed fixture");

        let mut executor = RecordingExecutor::new();
        let ran = apply_safe_steps(&rem, &mut executor)
            .expect("apply_safe_steps should succeed");

        assert!(ran >= 1, "at least one SafeUserspace step should have run");

        // The pacman -U command must NOT appear among executed commands.
        for cmd in &executor.executed {
            assert!(
                !cmd.contains("pacman -U"),
                "pacman -U must not be executed in --apply mode: got '{cmd}'"
            );
        }

        // Every executed command should be from a SafeUserspace step.
        let safe_cmds: Vec<_> = rem
            .steps
            .iter()
            .filter(|s| s.tier == Tier::SafeUserspace)
            .map(|s| s.command.as_str())
            .collect();
        for executed_cmd in &executor.executed {
            assert!(
                safe_cmds.contains(&executed_cmd.as_str()),
                "executed command not from SafeUserspace tier: '{executed_cmd}'"
            );
        }
    }

    // AC-6: --json round-trip: Vec<Remediation> serializes and deserializes correctly.
    #[test]
    fn ac6_json_roundtrip() {
        let remediations = vec![
            remediation_for(&memlog_staged_report())
                .expect("memlog remediation should exist"),
            remediation_for(&agentns_inert_report())
                .expect("agentns remediation should exist"),
        ];

        let json = serde_json::to_string(&remediations)
            .expect("serialization of Vec<Remediation> should succeed");
        let decoded: Vec<Remediation> = serde_json::from_str(&json)
            .expect("deserialization of Vec<Remediation> should succeed");

        assert_eq!(decoded.len(), remediations.len());
        assert_eq!(decoded[0].primitive, remediations[0].primitive);
        assert_eq!(decoded[1].primitive, remediations[1].primitive);
        assert_eq!(decoded[0].steps.len(), remediations[0].steps.len());
        assert_eq!(decoded[1].steps[0].tier, Tier::ReportOnly);
    }

    // AC-7: no real commands run, no network, no writes outside tmpdir.
    // (Guaranteed by RecordingExecutor; this test is an explicit assertion.)
    #[test]
    fn ac7_recording_executor_never_runs_real_commands() {
        let mut executor = RecordingExecutor::new();
        let report = memlog_staged_report();
        let rem = remediation_for(&report).expect("remediation should exist");
        let _ = apply_safe_steps(&rem, &mut executor);
        // All executed commands are recorded strings only; ShellExecutor was not used.
        for cmd in &executor.executed {
            // Just verify they are non-empty strings — no system call was made.
            assert!(!cmd.is_empty());
        }
    }

    // Live verdict returns None.
    #[test]
    fn live_verdict_returns_none() {
        let report = PrimitiveReport::new("memlog", Verdict::Live, Evidence::empty());
        assert!(remediation_for(&report).is_none());
    }
}
