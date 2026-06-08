//! `ReceiptStore` — reads and writes receipts to a configurable directory.

use std::path::{Path, PathBuf};

use crate::receipt::Receipt;

/// Errors that can occur when reading or writing receipts.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// I/O error accessing the store directory.
    #[error("store I/O error at {path}: {source}")]
    Io {
        /// Path involved in the error.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// JSON serialization or deserialization failure.
    #[error("JSON error for receipt {path}: {source}")]
    Json {
        /// Path of the receipt file.
        path: PathBuf,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
}

/// A directory-backed store of [`Receipt`] files.
///
/// Files are stored as `<taken_at_formatted>.json` inside the configured
/// directory. Loading is done via directory scan + sort, so ordering is
/// determined by filename (timestamp-prefixed ISO 8601).
#[derive(Debug, Clone)]
pub struct ReceiptStore {
    dir: PathBuf,
}

impl ReceiptStore {
    /// Create a store backed by `dir`.
    ///
    /// The directory is created lazily on first write.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Default production store path: `~/.local/share/quicken/receipts/`.
    ///
    /// Falls back to `/tmp/quicken-receipts` if `HOME` is unset.
    #[must_use]
    pub fn default_path() -> PathBuf {
        std::env::var("HOME").map_or_else(|_| PathBuf::from("/tmp"), PathBuf::from)
            .join(".local/share/quicken/receipts")
    }

    /// The directory this store writes to.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write a receipt to the store.
    ///
    /// Creates the directory if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on I/O or JSON failure.
    pub fn write(&self, receipt: &Receipt) -> Result<PathBuf, StoreError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| StoreError::Io {
            path: self.dir.clone(),
            source: e,
        })?;
        let path = self.dir.join(receipt.filename());
        let json = serde_json::to_string_pretty(receipt).map_err(|e| StoreError::Json {
            path: path.clone(),
            source: e,
        })?;
        std::fs::write(&path, json.as_bytes()).map_err(|e| StoreError::Io {
            path: path.clone(),
            source: e,
        })?;
        Ok(path)
    }

    /// Load all receipts in chronological order (oldest first).
    ///
    /// Skips files that cannot be parsed (with a warning to stderr).
    /// Returns an empty `Vec` if the directory does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] only on I/O errors reading the directory itself.
    pub fn load_all(&self) -> Result<Vec<Receipt>, StoreError> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .map_err(|e| StoreError::Io { path: self.dir.clone(), source: e })?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();

        // Sort by filename → chronological order (ISO 8601 timestamps sort correctly).
        entries.sort();

        let mut receipts = Vec::new();
        for path in entries {
            let raw = std::fs::read_to_string(&path).map_err(|e| StoreError::Io {
                path: path.clone(),
                source: e,
            })?;
            match serde_json::from_str::<Receipt>(&raw) {
                Ok(r) => receipts.push(r),
                Err(e) => {
                    eprintln!(
                        "quicken-attest: skipping malformed receipt {}: {e}",
                        path.display()
                    );
                }
            }
        }
        Ok(receipts)
    }

    /// Load only the most recent receipt, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on I/O failure.
    pub fn load_latest(&self) -> Result<Option<Receipt>, StoreError> {
        let mut all = self.load_all()?;
        Ok(all.pop())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use quicken_probe::{Evidence, Verdict};

    fn make_receipt(ts: &str, boot_id: &str, verdict: Verdict) -> Receipt {
        let taken_at: DateTime<chrono::Utc> = ts.parse().expect("parse timestamp");
        Receipt {
            taken_at,
            boot_id: boot_id.to_owned(),
            reports: vec![quicken_probe::PrimitiveReport {
                name: "memlog".into(),
                verdict,
                evidence: Evidence::empty(),
                checked_at: taken_at,
            }],
        }
    }

    #[test]
    fn write_and_read_roundtrip() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = ReceiptStore::new(tmp.path().join("receipts"));

        let r = make_receipt("2026-06-05T10:00:00Z", "boot-abc", Verdict::Inert);
        let path = store.write(&r).expect("write");
        assert!(path.exists(), "receipt file must exist after write");

        let loaded = store.load_all().expect("load_all");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].boot_id, "boot-abc");
        assert_eq!(loaded[0].reports[0].verdict, Verdict::Inert);
    }

    #[test]
    fn load_all_returns_chronological_order() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = ReceiptStore::new(tmp.path().join("receipts"));

        // Write in non-chronological order.
        store
            .write(&make_receipt("2026-06-05T10:02:00Z", "boot-1", Verdict::Live))
            .expect("write");
        store
            .write(&make_receipt("2026-06-05T10:00:00Z", "boot-1", Verdict::Inert))
            .expect("write");
        store
            .write(&make_receipt("2026-06-05T10:01:00Z", "boot-1", Verdict::InstalledNotActivated))
            .expect("write");

        let loaded = store.load_all().expect("load_all");
        assert_eq!(loaded.len(), 3);
        // Must be oldest-first.
        assert_eq!(loaded[0].reports[0].verdict, Verdict::Inert);
        assert_eq!(loaded[1].reports[0].verdict, Verdict::InstalledNotActivated);
        assert_eq!(loaded[2].reports[0].verdict, Verdict::Live);
    }

    #[test]
    fn missing_dir_returns_empty() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = ReceiptStore::new(tmp.path().join("nonexistent"));
        let loaded = store.load_all().expect("load_all");
        assert!(loaded.is_empty());
    }
}
