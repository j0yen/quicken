//! Delta — per-primitive change classification between two receipts.

use quicken_probe::{PrimitiveReport, Verdict};

/// How a primitive's verdict changed between two receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaKind {
    /// No prior receipt exists to compare against.
    NoPrior,
    /// Verdict is identical between the two receipts.
    Unchanged,
    /// Verdict improved (e.g. Inert → Live).
    Improved,
    /// Verdict regressed (e.g. Live → Inert).
    Regressed,
    /// Verdict category unchanged but evidence values differ
    /// (e.g. memlog pkgrel 5→11 with verdict still `StagedNotInstalled`).
    EvidenceChanged {
        /// Human-readable description of what changed.
        detail: String,
    },
    /// This primitive was not present in the prior receipt.
    NewPrimitive,
}

/// A delta for a single primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    /// The kind of change.
    pub kind: DeltaKind,
}

/// Total ordering of verdicts for "better" / "worse" comparisons.
///
/// Higher = better.
const fn verdict_rank(v: &Verdict) -> u8 {
    match v {
        Verdict::Live => 5,
        Verdict::LiveDegraded { .. } => 4,
        Verdict::InstalledNotActivated => 3,
        Verdict::StagedNotInstalled => 2,
        Verdict::Inert => 1,
        // Non-exhaustive: treat any future variant as Unknown rank (0).
        _ => 0,
    }
}

/// Returns `true` when two verdicts have the same *kind* (ignoring embedded data).
const fn same_verdict_kind(a: &Verdict, b: &Verdict) -> bool {
    matches!(
        (a, b),
        (Verdict::Live, Verdict::Live)
            | (Verdict::LiveDegraded { .. }, Verdict::LiveDegraded { .. })
            | (Verdict::InstalledNotActivated, Verdict::InstalledNotActivated)
            | (Verdict::StagedNotInstalled, Verdict::StagedNotInstalled)
            | (Verdict::Inert, Verdict::Inert)
            | (Verdict::Unknown, Verdict::Unknown)
    )
}

/// Classify the delta between a previous and current report for one primitive.
fn classify(prev: &PrimitiveReport, current: &PrimitiveReport) -> Delta {
    let prev_rank = verdict_rank(&prev.verdict);
    let cur_rank = verdict_rank(&current.verdict);

    if cur_rank > prev_rank {
        return Delta { kind: DeltaKind::Improved };
    }
    if cur_rank < prev_rank {
        return Delta { kind: DeltaKind::Regressed };
    }

    // Same rank: check for evidence changes.
    if same_verdict_kind(&prev.verdict, &current.verdict) {
        // Look for any evidence pair that changed.
        let prev_pairs = &prev.evidence.pairs;
        let cur_pairs = &current.evidence.pairs;

        let mut changes: Vec<String> = Vec::new();
        // For each current key, check if value changed vs prior.
        for cp in cur_pairs {
            if let Some(pp) = prev_pairs.iter().find(|p| p.key == cp.key) {
                if pp.value != cp.value {
                    changes.push(format!("{}:{}->{}", cp.key, pp.value, cp.value));
                }
            }
        }
        // Check for new keys in current that weren't in prior.
        for cp in cur_pairs {
            if !prev_pairs.iter().any(|p| p.key == cp.key) {
                changes.push(format!("{}:+{}", cp.key, cp.value));
            }
        }

        if changes.is_empty() {
            Delta { kind: DeltaKind::Unchanged }
        } else {
            Delta {
                kind: DeltaKind::EvidenceChanged {
                    detail: changes.join(", "),
                },
            }
        }
    } else {
        // Same rank but different kind (e.g. two different rank-0 variants).
        Delta { kind: DeltaKind::Regressed }
    }
}

/// Compute per-primitive deltas between a prior set of reports and the current set.
///
/// Primitives absent in `prior` get [`DeltaKind::NewPrimitive`].
#[must_use]
pub fn compute_deltas(
    prior: &[PrimitiveReport],
    current: &[PrimitiveReport],
) -> Vec<(String, Delta)> {
    current
        .iter()
        .map(|cur| {
            let delta = prior
                .iter()
                .find(|p| p.name == cur.name)
                .map_or(Delta { kind: DeltaKind::NewPrimitive }, |prev| classify(prev, cur));
            (cur.name.clone(), delta)
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::single_char_pattern)]
mod tests {
    use super::*;
    use chrono::Utc;
    use quicken_probe::Evidence;

    fn report(name: &str, verdict: Verdict, evidence: Evidence) -> PrimitiveReport {
        PrimitiveReport {
            name: name.into(),
            verdict,
            evidence,
            checked_at: Utc::now(),
        }
    }

    #[test]
    fn unchanged_verdict_same_evidence() {
        let prev = report("memlog", Verdict::Inert, Evidence::empty());
        let cur = report("memlog", Verdict::Inert, Evidence::empty());
        let delta = compute_deltas(&[prev], &[cur]);
        assert_eq!(delta[0].1.kind, DeltaKind::Unchanged);
    }

    #[test]
    fn regressed_live_to_inert() {
        let prev = report("memlog", Verdict::Live, Evidence::empty());
        let cur = report("memlog", Verdict::Inert, Evidence::empty());
        let delta = compute_deltas(&[prev], &[cur]);
        assert_eq!(delta[0].1.kind, DeltaKind::Regressed);
    }

    #[test]
    fn improved_inert_to_live() {
        let prev = report("memlog", Verdict::Inert, Evidence::empty());
        let cur = report("memlog", Verdict::Live, Evidence::empty());
        let delta = compute_deltas(&[prev], &[cur]);
        assert_eq!(delta[0].1.kind, DeltaKind::Improved);
    }

    #[test]
    fn evidence_changed_pkgrel() {
        let prev = report(
            "memlog",
            Verdict::StagedNotInstalled,
            Evidence::single("installed_pkgrel", "5").with("staged_pkgrel", "6"),
        );
        let cur = report(
            "memlog",
            Verdict::StagedNotInstalled,
            Evidence::single("installed_pkgrel", "5").with("staged_pkgrel", "11"),
        );
        let delta = compute_deltas(&[prev], &[cur]);
        match &delta[0].1.kind {
            DeltaKind::EvidenceChanged { detail } => {
                assert!(
                    detail.contains("staged_pkgrel"),
                    "detail should mention staged_pkgrel: {detail}"
                );
                assert!(detail.contains('6'), "detail should contain old value: {detail}");
                assert!(detail.contains("11"), "detail should contain new value: {detail}");
            }
            other => panic!("expected EvidenceChanged, got {other:?}"),
        }
    }

    #[test]
    fn new_primitive_not_in_prior() {
        let cur = report("newprim", Verdict::Inert, Evidence::empty());
        let delta = compute_deltas(&[], &[cur]);
        assert_eq!(delta[0].1.kind, DeltaKind::NewPrimitive);
    }
}
