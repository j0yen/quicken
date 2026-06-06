//! `quicken` — wintermute kernel primitive liveness checker.
//!
//! Runs all four primitive probes and reports their verdicts.
//!
//! Usage:
//!   quicken probe           — human-readable table
//!   quicken probe --json    — JSON array of `PrimitiveReport`
//!
//! Exit codes:
//!   0 — all primitives are `Live` or `LiveDegraded`
//!   1 — at least one primitive is worse than `LiveDegraded`
//!   2 — internal error (should not occur in normal use)

use std::process;

use clap::{Parser, Subcommand};
use quicken_probe::{
    AgentnsProbe, MemlogProbe, Probe, ProbeEnv, ProvfsProbe, Verdict, WardenProbe,
};

fn main() {
    // SIGPIPE: prevent panic on broken pipe (e.g. `quicken probe | head`).
    // Per self_sigpipe_panic_toolkit memory note.
    sigpipe::reset();

    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Probe { json } => run_probe(json),
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
    /// Use --json for machine-parseable output.
    ///
    /// Exit codes: 0=all-Live/LiveDegraded, 1=any-worse, 2=error
    Probe {
        /// Emit JSON array of `PrimitiveReport` instead of a table.
        #[arg(long)]
        json: bool,
    },
}

/// Run all probes and return an exit code.
fn run_probe(json_output: bool) -> i32 {
    let env = ProbeEnv::default();
    let probes: Vec<Box<dyn Probe>> = vec![
        Box::new(MemlogProbe),
        Box::new(AgentnsProbe),
        Box::new(WardenProbe),
        Box::new(ProvfsProbe),
    ];

    let reports: Vec<_> = probes.iter().map(|p| p.probe(&env)).collect();

    if json_output {
        match serde_json::to_string_pretty(&reports) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("quicken: JSON serialization error: {e}");
                return 2;
            }
        }
    } else {
        print_table(&reports);
    }

    let all_acceptable = reports.iter().all(|r| r.verdict.is_acceptable());
    i32::from(!all_acceptable)
}

/// Print a human-readable table of probe results.
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
