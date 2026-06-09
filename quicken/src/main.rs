//! `quicken` — wintermute kernel primitive liveness checker and remediation tool.
//!
//! Subcommands:
//!   quicken probe              — human-readable table of all primitive verdicts
//!   quicken probe --json       — JSON array of `PrimitiveReport` (with dep graph)
//!   quicken probe --deps       — table with blocked-by / would-upgrade column
//!   quicken deps               — print the static enablement edge set
//!   quicken remedy             — print (dry-run) remediation for all dark primitives
//!   quicken remedy --apply     — apply `SafeUserspace` steps; print the rest
//!   quicken remedy --json      — JSON array of `Remediation`
//!   quicken attest             — probe + write receipt + print delta/streaks
//!   quicken attest --json      — machine-readable attest output
//!   quicken attest --no-write  — probe + print delta/streaks without writing
//!   quicken watch --once       — probe all primitives and publish verdicts to agorabus
//!
//! Exit codes:
//!   0 — all primitives are `Live` or `LiveDegraded` (probe); or remediation succeeded
//!   1 — at least one primitive is worse than `LiveDegraded`
//!   2 — internal error (should not occur in normal use)

mod remedy;
mod watch;

use std::process;

use clap::{Parser, Subcommand};
use quicken_probe::{
    annotate, canonical_edges, AgentnsProbe, AnnotatedReport, MemlogProbe, Probe, ProbeEnv,
    ProvfsProbe, Verdict, WardenProbe,
};

use remedy::{apply_safe_steps, remediation_for, CommandExecutor, ShellExecutor};

fn main() {
    // SIGPIPE: prevent panic on broken pipe (e.g. `quicken probe | head`).
    // Per self_sigpipe_panic_toolkit memory note.
    sigpipe::reset();

    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Probe { json, deps } => run_probe(json, deps),
        Command::Deps => run_deps(),
        Command::Remedy { apply, json } => run_remedy(apply, json),
        Command::Attest { json, no_write } => run_attest(json, no_write),
        Command::Watch { once: _, format, require_bus } => {
            let opts = watch::WatchOptions {
                json_format: format.as_deref() == Some("json"),
                require_bus,
                agorabus_bin: "agorabus".to_owned(),
            };
            let publisher = watch::ShellBusPublisher { bin: opts.agorabus_bin.clone() };
            watch::run_watch(&opts, &publisher)
        }
    };
    process::exit(exit_code);
}

/// Wintermute kernel primitive liveness checker.
///
/// Classifies every wintermute kernel primitive's liveness in one command.
///
/// Exit codes: 0=all-live, 1=any-degraded-or-worse, 2=internal-error
#[derive(Debug, Parser)]
#[command(
    name = "quicken",
    version = env!("CARGO_PKG_VERSION"),
    about = "Wintermute kernel primitive liveness checker",
    long_about = "Classifies every wintermute kernel primitive's liveness.\n\
    \n\
    The `watch --once` subcommand publishes each verdict to agorabus on\n\
    `wm.health.primitive.<name>` — same envelope as wintermute_watchdog.\n\
    Pair with the quicken-watch.timer unit for continuous mid-day coverage.\n\
    \n\
    Primitives checked:\n  \
      memlog   — /dev/memlog device node (memlog kernel module)\n  \
      agentns  — /proc/self/agent_session (agentns session id)\n  \
      warden   — bpolicy status (eBPF-LSM loaded flag)\n  \
      provfs   — user.prov.session xattr (provfs stamping)\n\
    \n\
    Verdicts:\n  \
      Live               — fully operational\n  \
      LiveDegraded       — running but degraded (reason printed)\n  \
      InstalledNotActivated — installed but activation incomplete\n  \
      StagedNotInstalled — newer package built but not installed\n  \
      Inert              — not active at runtime\n  \
      Unknown            — could not determine\n\
    \n\
    Exit codes: 0=all-live-or-degraded, 1=any-worse, 2=error"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run all primitive probes and report verdicts.
    ///
    /// Default output is a human-readable table.
    /// Use --json for machine-parseable output (includes `blocked_by` / `would_upgrade`).
    /// Use --deps for a table with cross-dependency annotations (blocked-by / would-upgrade column).
    ///
    /// Exit codes: 0=all-Live/LiveDegraded, 1=any-worse, 2=error
    Probe {
        /// Emit JSON array of annotated `PrimitiveReport` instead of a table.
        /// Includes `blocked_by` and `would_upgrade` fields from the dependency graph.
        #[arg(long)]
        json: bool,

        /// Show the dependency view: adds a blocked-by / would-upgrade column to the table.
        /// When combined with --json, the JSON output includes cross-dep annotations.
        #[arg(long)]
        deps: bool,
    },

    /// Print the static primitive enablement edge set (for inspection).
    ///
    /// Shows the causal relationships between primitives: which dark primitives
    /// block or degrade which live ones.
    ///
    /// Output is JSON by default.
    Deps,

    /// Show remediation steps for all dark primitives.
    ///
    /// Default (--dry-run / --print): prints the ordered remediation steps for
    /// every non-live primitive, tagged by tier. No commands are executed.
    ///
    /// --apply: executes only `SafeUserspace` steps and prints (but does not run)
    /// all `RequiresSudo` / `RequiresReboot` / `ReportOnly` steps. Re-probes affected
    /// primitives afterwards and reports the new verdict.
    ///
    /// --json: emits a machine-readable JSON array of `Remediation` objects.
    Remedy {
        /// Execute `SafeUserspace` steps. Print (do not run) all other tiers.
        #[arg(long, conflicts_with = "json")]
        apply: bool,

        /// Emit JSON array of `Remediation` instead of a human-readable table.
        #[arg(long, conflicts_with = "apply")]
        json: bool,
    },

    /// Probe primitives, persist a liveness receipt, and print delta/streaks.
    ///
    /// Writes a timestamped receipt to ~/.local/share/quicken/receipts/,
    /// loads the most recent prior receipt, computes a per-primitive delta,
    /// and tracks an inert-streak counter per primitive.
    ///
    /// Exit codes: 0=all-Live/LiveDegraded, 1=any-worse, 2=error
    Attest {
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,

        /// Compute and print results without writing a receipt file.
        #[arg(long = "no-write")]
        no_write: bool,
    },

    /// Run all probes and publish each verdict to agorabus.
    ///
    /// Publishes one event per primitive to `wm.health.primitive.<name>` on
    /// the `wm.health.*` envelope (same schema as `wintermute_watchdog`).
    ///
    /// Fail-open: if the bus is unreachable, exits 0 and logs a notice.
    /// Use `--require-bus` to exit non-zero on bus failure instead.
    ///
    /// Pair with `quicken-watch.service` / `quicken-watch.timer` for
    /// automatic mid-day liveness publishing.
    ///
    /// Exit codes: 0=published (or fail-open), 1=bus error with --require-bus, 2=internal error
    Watch {
        /// Required flag — run the probe set once and exit.
        ///
        /// (Reserved for future `--watch` long-running mode; currently --once is required.)
        #[arg(long = "once", required = true)]
        once: bool,

        /// Output format: `json` emits the published events as a JSON array on stdout.
        ///
        /// Published topic: `wm.health.primitive.<name>`
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,

        /// Exit non-zero if the bus is unreachable instead of logging and continuing.
        #[arg(long = "require-bus")]
        require_bus: bool,
    },
}

/// Run all probes and return an exit code.
fn run_probe(json_output: bool, show_deps: bool) -> i32 {
    let env = ProbeEnv::default();
    let probes: Vec<Box<dyn Probe>> = vec![
        Box::new(MemlogProbe),
        Box::new(AgentnsProbe),
        Box::new(WardenProbe),
        Box::new(ProvfsProbe),
    ];

    let reports: Vec<_> = probes.iter().map(|p| p.probe(&env)).collect();
    let edges = canonical_edges();
    let annotated = annotate(&reports, &edges);

    if json_output {
        // Always emit annotated reports when --json (includes blocked_by / would_upgrade).
        match serde_json::to_string_pretty(&annotated) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("quicken: JSON serialization error: {e}");
                return 2;
            }
        }
    } else if show_deps {
        print_deps_table(&annotated);
    } else {
        print_table(&reports);
    }

    let all_acceptable = reports.iter().all(|r| r.verdict.is_acceptable());
    i32::from(!all_acceptable)
}

/// Print the static enablement edge set as JSON.
fn run_deps() -> i32 {
    let edges = canonical_edges();
    match serde_json::to_string_pretty(&edges) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("quicken: JSON serialization error: {e}");
            return 2;
        }
    }
    0
}

/// Run the remedy subcommand and return an exit code.
fn run_remedy(apply: bool, json_output: bool) -> i32 {
    let env = ProbeEnv::default();
    let probes: Vec<Box<dyn Probe>> = vec![
        Box::new(MemlogProbe),
        Box::new(AgentnsProbe),
        Box::new(WardenProbe),
        Box::new(ProvfsProbe),
    ];

    let reports: Vec<_> = probes.iter().map(|p| p.probe(&env)).collect();

    // Collect remediations for non-live primitives only.
    let remediations: Vec<_> = reports.iter().filter_map(remediation_for).collect();

    if remediations.is_empty() {
        println!("All primitives are Live — nothing to remedy.");
        return 0;
    }

    if json_output {
        match serde_json::to_string_pretty(&remediations) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("quicken: JSON serialization error: {e}");
                return 2;
            }
        }
        return 0;
    }

    if apply {
        // --apply: run SafeUserspace steps; print everything else.
        let mut executor: Box<dyn CommandExecutor> = Box::new(ShellExecutor);
        for rem in &remediations {
            println!("\n=== Remediation: {} ===", rem.primitive);
            match apply_safe_steps(rem, executor.as_mut()) {
                Ok(n) => println!("  {n} SafeUserspace step(s) applied."),
                Err(e) => {
                    eprintln!("quicken: remedy apply failed for '{}': {e}", rem.primitive);
                    return 1;
                }
            }
        }

        // Re-probe affected primitives.
        println!("\n=== Re-probe after apply ===");
        let recheck: Vec<_> = probes.iter().map(|p| p.probe(&env)).collect();
        print_table(&recheck);
        let all_ok = recheck.iter().all(|r| r.verdict.is_acceptable());
        return i32::from(!all_ok);
    }

    // Default: dry-run / print.
    print_remediations(&remediations);
    // Exit 1 = there are primitives that need remediation.
    1
}

/// Run attest: probe + receipt + delta + streaks.
fn run_attest(json_output: bool, no_write: bool) -> i32 {
    let env = ProbeEnv::default();
    let probes: Vec<Box<dyn Probe>> = vec![
        Box::new(MemlogProbe),
        Box::new(AgentnsProbe),
        Box::new(WardenProbe),
        Box::new(ProvfsProbe),
    ];

    let reports: Vec<_> = probes.iter().map(|p| p.probe(&env)).collect();

    let store_path = quicken_attest::ReceiptStore::default_path();
    let store = quicken_attest::ReceiptStore::new(&store_path);
    let clock = quicken_attest::SystemClock;

    // Read boot_id from /proc/sys/kernel/random/boot_id (real system).
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_or_else(|_| "unknown".to_owned(), |s| s.trim().to_owned());

    let result = match quicken_attest::attest(&reports, &clock, &boot_id, &store) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("quicken attest: error computing receipt: {e}");
            return 2;
        }
    };

    if !no_write {
        if let Err(e) = store.write(&result.receipt) {
            eprintln!("quicken attest: failed to write receipt: {e}");
            return 2;
        }
    }

    if json_output {
        print_attest_json(&result);
    } else {
        print_attest_table(&result);
    }

    let all_acceptable = reports.iter().all(|r| r.verdict.is_acceptable());
    i32::from(!all_acceptable)
}

/// Print attest result as JSON.
fn print_attest_json(result: &quicken_attest::AttestResult) {
    let deltas: Vec<serde_json::Value> = result
        .deltas
        .iter()
        .map(|(name, d)| {
            let kind_str = match &d.kind {
                quicken_attest::DeltaKind::NoPrior => "NoPrior".to_owned(),
                quicken_attest::DeltaKind::Unchanged => "Unchanged".to_owned(),
                quicken_attest::DeltaKind::Improved => "Improved".to_owned(),
                quicken_attest::DeltaKind::Regressed => "Regressed".to_owned(),
                quicken_attest::DeltaKind::EvidenceChanged { detail } => {
                    format!("EvidenceChanged: {detail}")
                }
                quicken_attest::DeltaKind::NewPrimitive => "NewPrimitive".to_owned(),
            };
            serde_json::json!({ "name": name, "delta": kind_str })
        })
        .collect();

    let streaks: Vec<serde_json::Value> = result
        .streaks
        .iter()
        .map(|(name, s)| {
            serde_json::json!({
                "name": name,
                "inert_streak": s.inert_streak,
                "severity": s.severity,
            })
        })
        .collect();

    let out = serde_json::json!({
        "taken_at": result.receipt.taken_at,
        "boot_id": result.receipt.boot_id,
        "reports": result.receipt.reports,
        "deltas": deltas,
        "streaks": streaks,
    });

    match serde_json::to_string_pretty(&out) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("quicken attest: JSON serialization error: {e}"),
    }
}

/// Print attest result as a human-readable table.
fn print_attest_table(result: &quicken_attest::AttestResult) {
    println!("Liveness receipt — {}", result.receipt.taken_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("boot_id: {}", result.receipt.boot_id);
    println!();
    println!("{:<12}  {:<28}  {:<14}  STREAK", "PRIMITIVE", "VERDICT", "DELTA");
    println!("{}", "-".repeat(90));

    for r in &result.receipt.reports {
        let verdict_str = verdict_display(&r.verdict);
        let delta_str = result
            .deltas
            .iter()
            .find(|(n, _)| n == &r.name)
            .map_or("-".to_owned(), |(_, d)| match &d.kind {
                quicken_attest::DeltaKind::NoPrior => "no-prior".to_owned(),
                quicken_attest::DeltaKind::Unchanged => "unchanged".to_owned(),
                quicken_attest::DeltaKind::Improved => "improved".to_owned(),
                quicken_attest::DeltaKind::Regressed => "REGRESSED".to_owned(),
                quicken_attest::DeltaKind::EvidenceChanged { detail } => {
                    format!("evidence: {detail}")
                }
                quicken_attest::DeltaKind::NewPrimitive => "new".to_owned(),
            });
        let streak_str = result
            .streaks
            .iter()
            .find(|(n, _)| n == &r.name)
            .map_or(String::new(), |(_, s)| s.severity.clone());
        println!("{:<12}  {:<28}  {:<14}  {streak_str}", r.name, verdict_str, delta_str);
    }
    println!();
}

/// Print remediation steps in a human-readable format.
fn print_remediations(remediations: &[remedy::Remediation]) {
    for rem in remediations {
        println!("\n=== Remedy: {} ===", rem.primitive);
        for (i, step) in rem.steps.iter().enumerate() {
            let tier_label = match step.tier {
                remedy::Tier::SafeUserspace => "[safe-userspace]",
                remedy::Tier::RequiresSudo => "[requires-sudo]",
                remedy::Tier::RequiresReboot => "[requires-reboot]",
                remedy::Tier::ReportOnly => "[report-only]",
            };
            println!("  Step {}: {tier_label}", i + 1);
            if !step.command.is_empty() {
                println!("    command:  {}", step.command);
            }
            if step.requires_reboot {
                println!("    reboot:   yes");
            }
            println!("    rationale: {}", step.rationale);
        }
    }
    println!();
}

/// Print a human-readable table of probe results (plain, no dep annotations).
fn print_table(reports: &[quicken_probe::PrimitiveReport]) {
    // Header
    println!("{:<12}  {:<28}  EVIDENCE", "PRIMITIVE", "VERDICT");
    println!("{}", "-".repeat(80));
    for r in reports {
        let verdict_str = verdict_display(&r.verdict);
        let evidence_str = evidence_summary(&r.evidence);
        println!("{:<12}  {:<28}  {evidence_str}", r.name, verdict_str);
        // Print detail on its own line if present.
        if let Some(detail) = &r.evidence.detail {
            println!("{:<12}  {:<28}  note: {detail}", "", "");
        }
    }
}

/// Print a human-readable table with cross-dependency annotations.
fn print_deps_table(annotated: &[AnnotatedReport]) {
    println!("{:<12}  {:<28}  {:<20}  WOULD-UPGRADE", "PRIMITIVE", "VERDICT", "BLOCKED-BY");
    println!("{}", "-".repeat(100));
    for a in annotated {
        let verdict_str = verdict_display(&a.report.verdict);
        let blocked_str = if a.blocked_by.is_empty() {
            "-".to_owned()
        } else {
            a.blocked_by.join(", ")
        };
        let upgrade_str = if a.would_upgrade.is_empty() {
            "-".to_owned()
        } else {
            a.would_upgrade.join(", ")
        };
        println!(
            "{:<12}  {:<28}  {:<20}  {}",
            a.report.name, verdict_str, blocked_str, upgrade_str
        );
    }
}

/// Format a `Verdict` for display.
fn verdict_display(v: &Verdict) -> String {
    match v {
        Verdict::Live => "Live".into(),
        Verdict::LiveDegraded { reason } => format!("LiveDegraded ({reason})"),
        Verdict::StagedNotInstalled => "StagedNotInstalled".into(),
        Verdict::InstalledNotActivated => "InstalledNotActivated".into(),
        Verdict::Inert => "Inert".into(),
        _ => "Unknown".into(),
    }
}

/// Summarize evidence key/value pairs into a one-liner.
fn evidence_summary(ev: &quicken_probe::Evidence) -> String {
    if ev.pairs.is_empty() {
        return String::new();
    }
    ev.pairs
        .iter()
        .map(|p| format!("{}={}", p.key, p.value))
        .collect::<Vec<_>>()
        .join(" ")
}
