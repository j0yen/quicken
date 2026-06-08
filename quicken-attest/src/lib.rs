//! `quicken-attest` — persist liveness receipts, compute deltas, track inert streaks.
//!
//! # Overview
//!
//! Exposes:
//! - [`Receipt`] — a timestamped snapshot of all primitive reports for one session.
//! - [`ReceiptStore`] — reads/writes receipts from a configurable directory.
//! - [`Delta`] — per-primitive change classification between two receipts.
//! - [`StreakInfo`] — inert-streak count and human-readable severity wording.
//! - [`AttestResult`] — the full output of one `quicken attest` run.
//! - [`attest`] — core logic (injectable clock + `boot_id` for deterministic tests).

pub mod delta;
pub mod receipt;
pub mod store;
pub mod streak;

pub use delta::{Delta, DeltaKind};
pub use receipt::{AttestClock, Receipt, SystemClock};
pub use store::{ReceiptStore, StoreError};
pub use streak::{StreakInfo, streak_band};

use quicken_probe::PrimitiveReport;

/// The complete result of one `quicken attest` run.
#[derive(Debug, Clone)]
pub struct AttestResult {
    /// The receipt written (or that would be written) this run.
    pub receipt: Receipt,
    /// Per-primitive deltas against the most recent prior receipt (if any).
    pub deltas: Vec<(String, Delta)>,
    /// Per-primitive inert streaks (consecutive distinct `boot_ids` with verdict worse than `LiveDegraded`).
    pub streaks: Vec<(String, StreakInfo)>,
}

/// Run the attest logic.
///
/// - `reports`: the current probe results.
/// - `clock`: injectable clock (use [`SystemClock`] in production, a fixture in tests).
/// - `boot_id`: the current boot identifier (injectable for tests).
/// - `store`: the receipt store to load prior receipts from.
///
/// Returns the [`AttestResult`]; the caller decides whether to persist.
///
/// # Errors
///
/// Returns a [`StoreError`] if loading prior receipts fails in an unrecoverable way.
/// A missing store directory is not an error — it means no prior receipts exist.
pub fn attest(
    reports: &[PrimitiveReport],
    clock: &dyn AttestClock,
    boot_id: &str,
    store: &ReceiptStore,
) -> Result<AttestResult, StoreError> {
    // Build the new receipt.
    let receipt = Receipt {
        taken_at: clock.now(),
        boot_id: boot_id.to_owned(),
        reports: reports.to_vec(),
    };

    // Load the full prior history for streak computation.
    let history = store.load_all()?;

    // Compute deltas against the most recent prior receipt.
    let deltas = history.last().map_or_else(
        // No prior receipt: all deltas are "no prior data".
        || {
            reports
                .iter()
                .map(|r| (r.name.clone(), Delta { kind: DeltaKind::NoPrior }))
                .collect()
        },
        |prev| delta::compute_deltas(&prev.reports, reports),
    );

    // Compute streaks from history.
    let streaks = streak::compute_streaks(reports, &history);

    Ok(AttestResult { receipt, deltas, streaks })
}
