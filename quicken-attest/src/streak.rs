//! Streak — consecutive inert-boot counting and severity banding.

use quicken_probe::{PrimitiveReport, Verdict};

use crate::receipt::Receipt;

/// Inert-streak information for a single primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreakInfo {
    /// Number of consecutive distinct boot IDs where this primitive was worse than `LiveDegraded`.
    pub inert_streak: u32,
    /// Human-readable severity string.
    pub severity: String,
}

/// Returns the severity wording for a given inert streak count.
///
/// Bands:
/// - 0 → "" (not dark)
/// - 1..=2 → "dark"
/// - 3..=6 → "dark for N boots"
/// - ≥7 → "DARK FOR N BOOTS — needs attention"
#[must_use]
pub fn streak_band(streak: u32) -> String {
    match streak {
        0 => String::new(),
        1 | 2 => "dark".to_owned(),
        3..=6 => format!("dark for {streak} boots"),
        _ => format!("DARK FOR {streak} BOOTS — needs attention"),
    }
}

/// Returns `true` when a verdict is "inert" for streak purposes
/// (i.e. worse than `LiveDegraded`).
const fn is_streak_dark(verdict: &Verdict) -> bool {
    !matches!(verdict, Verdict::Live | Verdict::LiveDegraded { .. })
}

/// Compute inert streaks for each current primitive, using the full receipt history.
///
/// A streak is the count of *distinct boot IDs* (most recent first) in which
/// the primitive was dark, counting only consecutive matches from the end of
/// history (i.e. streak resets to 0 if any prior receipt shows the primitive
/// acceptable).
///
/// Only distinct boot IDs are counted; multiple receipts from the same boot
/// count as one boot for streak purposes.
#[must_use]
pub fn compute_streaks(
    current: &[PrimitiveReport],
    history: &[Receipt],
) -> Vec<(String, StreakInfo)> {
    current
        .iter()
        .map(|cur| {
            let streak = inert_streak_for(&cur.name, history);
            let severity = streak_band(streak);
            (cur.name.clone(), StreakInfo { inert_streak: streak, severity })
        })
        .collect()
}

/// Compute the inert streak for `name` over the history (oldest-first).
///
/// Walk backwards through distinct boot IDs; count consecutive boots where
/// the primitive was dark. Stop at the first boot where it was acceptable.
fn inert_streak_for(name: &str, history: &[Receipt]) -> u32 {
    // Collect (boot_id, was_dark) pairs, de-duplicated by boot_id.
    // We de-duplicate by taking the LAST receipt per boot_id (most recent state for that boot).
    // history is oldest-first, so we iterate in reverse.
    let mut per_boot: Vec<(String, bool)> = Vec::new();

    for receipt in history.iter().rev() {
        let boot_id = receipt.boot_id.clone();
        // Skip if we already have this boot recorded (took the latest).
        if per_boot.iter().any(|(b, _)| b == &boot_id) {
            continue;
        }
        // Find the verdict for this primitive in this receipt.
        let dark = receipt
            .reports
            .iter()
            .find(|r| r.name == name)
            .is_some_and(|r| is_streak_dark(&r.verdict));
        per_boot.push((boot_id, dark));
    }

    // per_boot is now newest-first. Count consecutive dark boots from the front.
    let mut streak = 0u32;
    for (_, dark) in &per_boot {
        if *dark {
            streak += 1;
        } else {
            break;
        }
    }
    streak
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use quicken_probe::Evidence;

    fn make_receipt(ts: &str, boot_id: &str, name: &str, verdict: Verdict) -> Receipt {
        let taken_at: DateTime<chrono::Utc> = ts.parse().expect("parse timestamp");
        Receipt {
            taken_at,
            boot_id: boot_id.to_owned(),
            reports: vec![PrimitiveReport {
                name: name.into(),
                verdict,
                evidence: Evidence::empty(),
                checked_at: taken_at,
            }],
        }
    }

    #[test]
    fn streak_band_wording() {
        assert_eq!(streak_band(0), "");
        assert_eq!(streak_band(1), "dark");
        assert_eq!(streak_band(2), "dark");
        assert_eq!(streak_band(3), "dark for 3 boots");
        assert_eq!(streak_band(6), "dark for 6 boots");
        assert_eq!(streak_band(7), "DARK FOR 7 BOOTS — needs attention");
        assert_eq!(streak_band(10), "DARK FOR 10 BOOTS — needs attention");
    }

    #[test]
    fn no_history_streak_is_zero() {
        let cur = vec![PrimitiveReport {
            name: "memlog".into(),
            verdict: Verdict::Inert,
            evidence: Evidence::empty(),
            checked_at: "2026-06-05T10:00:00Z".parse().expect("ts"),
        }];
        let streaks = compute_streaks(&cur, &[]);
        assert_eq!(streaks[0].1.inert_streak, 0);
    }

    #[test]
    fn two_boot_ids_both_dark_streak_two() {
        let history = vec![
            make_receipt("2026-06-03T10:00:00Z", "boot-1", "memlog", Verdict::Inert),
            make_receipt("2026-06-04T10:00:00Z", "boot-2", "memlog", Verdict::Inert),
        ];
        let cur = vec![PrimitiveReport {
            name: "memlog".into(),
            verdict: Verdict::Inert,
            evidence: Evidence::empty(),
            checked_at: "2026-06-05T10:00:00Z".parse().expect("ts"),
        }];
        let streaks = compute_streaks(&cur, &history);
        // Two distinct boot_ids, both dark → streak = 2.
        assert_eq!(streaks[0].1.inert_streak, 2);
    }

    #[test]
    fn three_receipts_two_boot_ids_both_dark_streak_two() {
        // AC4: three prior receipts across two boot IDs with the primitive dark
        // → correct consecutive-boot streak.
        let history = vec![
            make_receipt("2026-06-03T09:00:00Z", "boot-1", "memlog", Verdict::Inert),
            make_receipt("2026-06-03T10:00:00Z", "boot-1", "memlog", Verdict::Inert), // same boot, extra receipt
            make_receipt("2026-06-04T10:00:00Z", "boot-2", "memlog", Verdict::Inert),
        ];
        let cur = vec![PrimitiveReport {
            name: "memlog".into(),
            verdict: Verdict::Inert,
            evidence: Evidence::empty(),
            checked_at: "2026-06-05T10:00:00Z".parse().expect("ts"),
        }];
        let streaks = compute_streaks(&cur, &history);
        // Two distinct boot_ids (boot-1, boot-2), both dark → streak = 2, not 3.
        assert_eq!(streaks[0].1.inert_streak, 2, "streak must count distinct boot ids");
    }

    #[test]
    fn streak_resets_on_live_boot() {
        // boot-1: dark, boot-2: live, boot-3: dark → streak = 1 (only boot-3 counted).
        let history = vec![
            make_receipt("2026-06-03T10:00:00Z", "boot-1", "memlog", Verdict::Inert),
            make_receipt("2026-06-04T10:00:00Z", "boot-2", "memlog", Verdict::Live),
            make_receipt("2026-06-05T10:00:00Z", "boot-3", "memlog", Verdict::Inert),
        ];
        let cur = vec![PrimitiveReport {
            name: "memlog".into(),
            verdict: Verdict::Inert,
            evidence: Evidence::empty(),
            checked_at: "2026-06-05T11:00:00Z".parse().expect("ts"),
        }];
        let streaks = compute_streaks(&cur, &history);
        // boot-3 dark, boot-2 live → streak breaks. Only boot-3.
        assert_eq!(streaks[0].1.inert_streak, 1);
    }

    #[test]
    fn streak_severity_escalates_at_1_3_7() {
        // AC5: streak 1, 3, 7 produce distinct severity strings.
        assert_eq!(streak_band(1), "dark");
        assert_eq!(streak_band(3), "dark for 3 boots");
        assert_eq!(streak_band(7), "DARK FOR 7 BOOTS — needs attention");
        // All three are distinct.
        assert_ne!(streak_band(1), streak_band(3));
        assert_ne!(streak_band(3), streak_band(7));
        assert_ne!(streak_band(1), streak_band(7));
    }
}
