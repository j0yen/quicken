//! `Evidence` — structured record of the bytes a verdict was derived from.

use serde::{Deserialize, Serialize};

/// A single key/value observation made during probing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePair {
    /// Short label (e.g. `"dev_node_exists"`, `"installed_pkgrel"`).
    pub key: String,
    /// Stringified observed value (e.g. `"true"`, `"5"`, `"crw-rw----"`).
    pub value: String,
}

impl EvidencePair {
    /// Construct a new key/value pair.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self { key: key.into(), value: value.into() }
    }
}

/// The full evidence record attached to a `PrimitiveReport`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Structured key/value observations (serializable, queryable).
    pub pairs: Vec<EvidencePair>,
    /// Optional free-text detail for context that doesn't fit in pairs.
    pub detail: Option<String>,
}

impl Evidence {
    /// Create an empty evidence record.
    #[must_use]
    pub const fn empty() -> Self {
        Self { pairs: Vec::new(), detail: None }
    }

    /// Create an evidence record with a single key/value pair.
    #[must_use]
    pub fn single(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            pairs: vec![EvidencePair::new(key, value)],
            detail: None,
        }
    }

    /// Add a key/value pair and return `self` for chaining.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.pairs.push(EvidencePair::new(key, value));
        self
    }

    /// Set the free-text detail and return `self` for chaining.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Look up a value by key (linear scan — evidence sets are small).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_roundtrip() {
        let e = Evidence::single("foo", "bar");
        assert_eq!(e.get("foo"), Some("bar"));
        assert_eq!(e.get("baz"), None);
    }

    #[test]
    fn chaining() {
        let e = Evidence::empty()
            .with("a", "1")
            .with("b", "2")
            .with_detail("some context");
        assert_eq!(e.get("a"), Some("1"));
        assert_eq!(e.get("b"), Some("2"));
        assert_eq!(e.detail.as_deref(), Some("some context"));
    }
}
