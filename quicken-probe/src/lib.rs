//! `quicken-probe` — wintermute kernel primitive liveness detection library.
//!
//! Every wintermute kernel primitive (memlog, agentns, warden/bpolicy, provfs)
//! can be compiled, packaged, and installed and still be runtime-inert.
//! This library provides a `Probe` trait and four concrete implementations that
//! classify each primitive's **liveness** with a structured `Verdict` and its
//! supporting `Evidence`, all read-only and with no network access.
//!
//! The [`crossdep`] module adds a primitive→primitive enablement graph so each
//! verdict can name what it is `blocked_by` and what reviving a dark primitive
//! `would_upgrade`.
//!
//! # Usage
//!
//! ```
//! use quicken_probe::{ProbeEnv, MemlogProbe, Probe};
//! let env = ProbeEnv::default();
//! let probe = MemlogProbe;
//! let report = probe.probe(&env);
//! println!("{}: {:?}", report.name, report.verdict);
//! ```

pub mod crossdep;
pub mod env;
pub mod evidence;
pub mod probes;
pub mod report;
pub mod verdict;

pub use crossdep::{annotate, canonical_edges, AnnotatedReport, Effect, EnablementEdge};
pub use env::ProbeEnv;
pub use evidence::{Evidence, EvidencePair};
pub use probes::{AgentnsProbe, MemlogProbe, ProvfsProbe, WardenProbe};
pub use report::PrimitiveReport;
pub use verdict::Verdict;

/// The `Probe` trait: each primitive implements this.
pub trait Probe {
    /// Short identifier for this primitive (e.g. `"memlog"`).
    fn name(&self) -> &'static str;

    /// Run the probe against `env` and return a report.
    /// This operation is **read-only** — no writes, no network.
    fn probe(&self, env: &ProbeEnv) -> PrimitiveReport;
}
