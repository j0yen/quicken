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
//!
//! Exit codes:
//!   0 — all primitives are `Live` or `LiveDegraded` (probe); or remediation succeeded
//!   1 — at least one primitive is worse than `LiveDegraded`
//!   2 — internal error (should not occur in normal use)

mod remedy;

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
    /// Use --json for machine-parseable output (includes blocked_by / would_upgrade).
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
    println!(
        "{:<12}  {:<28}  {:<20}  {}",
        "PRIMITIVE", "VERDICT", "BLOCKED-BY", "WOULD-UPGRADE"
    );
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
