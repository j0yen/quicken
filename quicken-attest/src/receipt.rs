//! Receipt — a timestamped snapshot of all primitive reports.

use chrono::{DateTime, Utc};
use quicken_probe::PrimitiveReport;
use serde::{Deserialize, Serialize};

/// Injectable clock abstraction for deterministic tests.
pub trait AttestClock {
    /// Return the current UTC time.
    fn now(&self) -> DateTime<Utc>;
}

/// Production clock — reads the real system time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl AttestClock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A persisted liveness receipt: one snapshot per `quicken attest` run.
///
/// Stored as JSON under `~/.local/share/quicken/receipts/<taken_at_rfc3339>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// When this receipt was taken (UTC, injected in tests).
    pub taken_at: DateTime<Utc>,
    /// Kernel boot identifier (`/proc/sys/kernel/random/boot_id`), injected in tests.
    pub boot_id: String,
    /// The probe reports captured at this moment.
    pub reports: Vec<PrimitiveReport>,
}

impl Receipt {
    /// Filename component derived from `taken_at` (RFC 3339, colons replaced with `_`).
    #[must_use]
    pub fn filename(&self) -> String {
        // Colons are not safe in filenames on all filesystems; replace with `_`.
        let ts = self.taken_at.format("%Y-%m-%dT%H_%M_%S%.3fZ").to_string();
        format!("{ts}.json")
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::case_sensitive_file_extension_comparisons)]
mod tests {
    use super::*;
    use quicken_probe::{Evidence, Verdict};

    fn make_receipt(ts: &str, boot_id: &str) -> Receipt {
        let taken_at: DateTime<Utc> = ts.parse().expect("parse timestamp");
        Receipt {
            taken_at,
            boot_id: boot_id.to_owned(),
            reports: vec![quicken_probe::PrimitiveReport {
                name: "memlog".into(),
                verdict: Verdict::Inert,
                evidence: Evidence::empty(),
                checked_at: taken_at,
            }],
        }
    }

    #[test]
    fn receipt_roundtrip() {
        let r = make_receipt("2026-06-05T10:00:00Z", "boot-1");
        let json = serde_json::to_string(&r).expect("serialize");
        let decoded: Receipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.boot_id, "boot-1");
        assert_eq!(decoded.reports.len(), 1);
        assert_eq!(decoded.reports[0].name, "memlog");
    }

    #[test]
    fn filename_does_not_contain_colons() {
        let r = make_receipt("2026-06-05T10:30:45.123Z", "boot-1");
        let name = r.filename();
        assert!(!name.contains(':'), "filename must not contain colons: {name}");
        assert!(name.ends_with(".json"), "must end with .json: {name}");
    }
}
