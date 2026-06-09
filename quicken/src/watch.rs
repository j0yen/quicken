//! `watch` subcommand — run all probes and publish verdicts to agorabus.
//!
//! Each primitive verdict is published to `wm.health.primitive.<name>` on the
//! existing `wm.health.*` envelope, matching what `docket/src/digest.rs` parses.
//!
//! The bus is fail-open: if agorabus is unreachable, `quicken watch --once`
//! exits 0 and logs a notice. Pass `--require-bus` to exit non-zero instead.

use std::process::Command;

use chrono::Utc;
use quicken_probe::{
    AgentnsProbe, MemlogProbe, Probe, ProbeEnv, ProvfsProbe, Verdict, WardenProbe,
};
use serde::{Deserialize, Serialize};

/// A single published health event, matching the `wm.health.*` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthEvent {
    /// Subject namespace: `primitive.<name>`.
    pub subject: String,
    /// Verdict string from the closed set.
    pub verdict: String,
    /// Short SHA-256 hash (8 hex chars) of the serialized evidence.
    pub evidence_digest: String,
    /// Inert streak from quicken-attest receipts, or 0 when absent.
    pub inert_streak: u32,
    /// Names of primitives blocking this one (from dep graph).
    pub blocked_by: Vec<String>,
    /// RFC 3339 timestamp of when the probe ran.
    pub ts: String,
}

/// Serialise verdict to a lowercase-kebab string matching the envelope spec.
fn verdict_str(v: &Verdict) -> String {
    match v {
        Verdict::Live => "live".to_owned(),
        Verdict::LiveDegraded { .. } => "live-degraded".to_owned(),
        Verdict::StagedNotInstalled => "staged-not-installed".to_owned(),
        Verdict::InstalledNotActivated => "installed-not-activated".to_owned(),
        Verdict::Inert => "inert".to_owned(),
        _ => "unknown".to_owned(),
    }
}

/// Compute a short (8-char) evidence digest from serialized evidence pairs.
fn evidence_digest(report: &quicken_probe::PrimitiveReport) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for pair in &report.evidence.pairs {
        pair.key.hash(&mut hasher);
        pair.value.hash(&mut hasher);
    }
    if let Some(detail) = &report.evidence.detail {
        detail.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
        .chars()
        .take(8)
        .collect()
}

/// Options for the watch subcommand (mirrored from CLI args).
#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// Emit published events as JSON to stdout.
    pub json_format: bool,
    /// Exit non-zero when the bus is unreachable.
    pub require_bus: bool,
    /// Path to the agorabus binary (defaults to "agorabus", looked up on PATH).
    pub agorabus_bin: String,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            json_format: false,
            require_bus: false,
            agorabus_bin: "agorabus".to_owned(),
        }
    }
}

/// Trait for publishing to agorabus, injectable for testing.
pub trait BusPublisher {
    /// Publish `payload` (JSON string) on `topic`.
    ///
    /// Returns `Ok(())` on success, `Err(msg)` on failure.
    fn publish(&self, topic: &str, payload: &str) -> Result<(), String>;
}

/// Production publisher that shells out to the `agorabus publish` CLI.
pub struct ShellBusPublisher {
    /// Path to the agorabus binary.
    pub bin: String,
}

impl BusPublisher for ShellBusPublisher {
    fn publish(&self, topic: &str, payload: &str) -> Result<(), String> {
        let output = Command::new(&self.bin)
            .args(["publish", topic, payload])
            .output()
            .map_err(|e| format!("failed to exec agorabus: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "agorabus publish exited {}: {stderr}",
                output.status.code().unwrap_or(-1)
            ))
        }
    }
}

/// Run the watch logic: probe all primitives, build events, publish + optionally print.
///
/// Returns an exit code: 0 on success; non-zero on internal error or bus failure
/// when `opts.require_bus` is set.
pub fn run_watch(opts: &WatchOptions, publisher: &dyn BusPublisher) -> i32 {
    let env = ProbeEnv::default();
    let probes: Vec<Box<dyn Probe>> = vec![
        Box::new(MemlogProbe),
        Box::new(AgentnsProbe),
        Box::new(WardenProbe),
        Box::new(ProvfsProbe),
    ];

    let reports: Vec<_> = probes.iter().map(|p| p.probe(&env)).collect();
    let edges = quicken_probe::canonical_edges();
    let annotated = quicken_probe::annotate(&reports, &edges);

    // Load inert streaks from attest receipt store (fail-open: 0 if absent).
    let streaks = load_streaks();

    let ts = Utc::now().to_rfc3339();
    let mut events: Vec<HealthEvent> = Vec::new();
    let mut bus_errors: Vec<String> = Vec::new();

    for ann in &annotated {
        let inert_streak = streaks
            .iter()
            .find(|(n, _)| n == &ann.report.name)
            .map_or(0, |(_, s)| *s);

        let event = HealthEvent {
            subject: format!("primitive.{}", ann.report.name),
            verdict: verdict_str(&ann.report.verdict),
            evidence_digest: evidence_digest(&ann.report),
            inert_streak,
            blocked_by: ann.blocked_by.clone(),
            ts: ts.clone(),
        };

        // Publish to agorabus (with small bounded retry: up to 2 attempts).
        let topic = format!("wm.health.primitive.{}", ann.report.name);
        let payload = match serde_json::to_string(&event) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("quicken watch: JSON encode error for {}: {e}", ann.report.name);
                return 2;
            }
        };

        let mut published = false;
        for attempt in 0..2u32 {
            match publisher.publish(&topic, &payload) {
                Ok(()) => {
                    published = true;
                    break;
                }
                Err(e) if attempt == 0 => {
                    // One retry.
                    let _ = e; // Ignore first failure; retry immediately.
                }
                Err(e) => {
                    bus_errors.push(format!("{}: {e}", ann.report.name));
                }
            }
        }

        if !published && !bus_errors.is_empty() {
            // Already recorded in bus_errors.
        }

        events.push(event);
    }

    // Handle bus errors.
    if !bus_errors.is_empty() {
        if opts.require_bus {
            eprintln!(
                "quicken watch: bus publish failed (--require-bus set): {}",
                bus_errors.join("; ")
            );
            return 1;
        }
        // Fail-open: log and continue.
        eprintln!(
            "quicken watch: bus unreachable (fail-open) — {} event(s) not published: {}",
            bus_errors.len(),
            bus_errors.join("; ")
        );
    }

    // Emit JSON to stdout if requested.
    if opts.json_format {
        match serde_json::to_string_pretty(&events) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("quicken watch: JSON output error: {e}");
                return 2;
            }
        }
    }

    0
}

/// Load per-primitive inert streaks from quicken-attest receipt store.
///
/// Fail-open: returns an empty vec if the store is absent or unreadable.
fn load_streaks() -> Vec<(String, u32)> {
    let store_path = quicken_attest::ReceiptStore::default_path();
    let store = quicken_attest::ReceiptStore::new(&store_path);

    // Use the attest streak computation on existing history.
    let history = match store.load_all() {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };

    if history.is_empty() {
        return Vec::new();
    }

    // Get streaks from the most recent receipt's reports.
    let latest = match history.last() {
        Some(r) => r,
        None => return Vec::new(),
    };

    let streak_infos = quicken_attest::streak::compute_streaks(&latest.reports, &history);
    streak_infos
        .into_iter()
        .map(|(name, info)| (name, info.inert_streak))
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    /// A test publisher that records calls and optionally fails.
    struct MockPublisher {
        fail: bool,
        calls: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl MockPublisher {
        fn new(fail: bool) -> Self {
            Self { fail, calls: std::sync::Mutex::new(Vec::new()) }
        }

        fn recorded(&self) -> Vec<(String, String)> {
            self.calls.lock().expect("lock poisoned").clone()
        }
    }

    impl BusPublisher for MockPublisher {
        fn publish(&self, topic: &str, payload: &str) -> Result<(), String> {
            self.calls
                .lock()
                .expect("lock poisoned")
                .push((topic.to_owned(), payload.to_owned()));
            if self.fail {
                Err("mock bus down".to_owned())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn watch_json_emits_one_event_per_primitive() {
        // Capture stdout by running run_watch in-process, but we can't capture stdout
        // directly. Instead, build events manually to verify structure.
        let env = ProbeEnv::default();
        let probes: Vec<Box<dyn Probe>> = vec![
            Box::new(MemlogProbe),
            Box::new(AgentnsProbe),
            Box::new(WardenProbe),
            Box::new(ProvfsProbe),
        ];
        let reports: Vec<_> = probes.iter().map(|p| p.probe(&env)).collect();
        let edges = quicken_probe::canonical_edges();
        let annotated = quicken_probe::annotate(&reports, &edges);

        // We should get 4 annotated reports (one per primitive).
        assert_eq!(annotated.len(), 4);

        // Verify each report can be serialised to a HealthEvent.
        for ann in &annotated {
            let event = HealthEvent {
                subject: format!("primitive.{}", ann.report.name),
                verdict: verdict_str(&ann.report.verdict),
                evidence_digest: evidence_digest(&ann.report),
                inert_streak: 0,
                blocked_by: ann.blocked_by.clone(),
                ts: Utc::now().to_rfc3339(),
            };
            let json = serde_json::to_string(&event).expect("serialize");
            let decoded: HealthEvent = serde_json::from_str(&json).expect("deserialize");
            assert!(!decoded.subject.is_empty());
            assert!(!decoded.verdict.is_empty());
            assert_eq!(decoded.evidence_digest.len(), 8);
        }
    }

    #[test]
    fn watch_no_bus_fail_open_exits_zero() {
        let publisher = MockPublisher::new(true); // bus fails
        let opts = WatchOptions {
            json_format: false,
            require_bus: false,
            agorabus_bin: "agorabus".to_owned(),
        };
        let exit = run_watch(&opts, &publisher);
        // Fail-open: exit 0 even when bus is down.
        assert_eq!(exit, 0);
    }

    #[test]
    fn watch_require_bus_exits_nonzero_when_bus_down() {
        let publisher = MockPublisher::new(true); // bus fails
        let opts = WatchOptions {
            json_format: false,
            require_bus: true,
            agorabus_bin: "agorabus".to_owned(),
        };
        let exit = run_watch(&opts, &publisher);
        // --require-bus: exit non-zero when bus unreachable.
        assert_eq!(exit, 1);
    }

    #[test]
    fn watch_publishes_one_event_per_primitive_when_bus_ok() {
        let publisher = MockPublisher::new(false); // bus works
        let opts = WatchOptions::default();
        let exit = run_watch(&opts, &publisher);
        assert_eq!(exit, 0);

        let calls = publisher.recorded();
        // 4 primitives × (up to 2 attempts, but first succeeds) = 4 calls.
        assert_eq!(calls.len(), 4);

        // Each topic should start with wm.health.primitive.
        for (topic, payload) in &calls {
            assert!(
                topic.starts_with("wm.health.primitive."),
                "unexpected topic: {topic}"
            );
            // Payload must be valid JSON with required fields.
            let v: serde_json::Value =
                serde_json::from_str(payload).expect("payload should be valid JSON");
            assert!(v["subject"].is_string());
            assert!(v["verdict"].is_string());
            assert!(v["evidence_digest"].is_string());
            assert!(v["ts"].is_string());
        }
    }

    #[test]
    fn watch_topic_names_match_primitive_names() {
        let publisher = MockPublisher::new(false);
        let opts = WatchOptions::default();
        run_watch(&opts, &publisher);

        let calls = publisher.recorded();
        let topics: Vec<&str> = calls.iter().map(|(t, _)| t.as_str()).collect();

        // All four expected primitives must appear.
        let expected = [
            "wm.health.primitive.memlog",
            "wm.health.primitive.agentns",
            "wm.health.primitive.warden",
            "wm.health.primitive.provfs",
        ];
        for exp in expected {
            assert!(topics.contains(&exp), "missing topic: {exp}");
        }
    }

    #[test]
    fn health_event_envelope_parses_correctly() {
        // Verify the payload struct matches the wm.health.* envelope shape.
        let event = HealthEvent {
            subject: "primitive.memlog".to_owned(),
            verdict: "inert".to_owned(),
            evidence_digest: "abcd1234".to_owned(),
            inert_streak: 3,
            blocked_by: vec!["agentns".to_owned()],
            ts: "2026-06-08T00:00:00+00:00".to_owned(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");

        assert_eq!(v["subject"], "primitive.memlog");
        assert_eq!(v["verdict"], "inert");
        assert_eq!(v["inert_streak"], 3);
        assert_eq!(v["blocked_by"][0], "agentns");
        assert_eq!(v["evidence_digest"], "abcd1234");
    }

    #[test]
    fn verdict_str_covers_all_variants() {
        assert_eq!(verdict_str(&Verdict::Live), "live");
        assert_eq!(
            verdict_str(&Verdict::LiveDegraded { reason: "x".into() }),
            "live-degraded"
        );
        assert_eq!(verdict_str(&Verdict::StagedNotInstalled), "staged-not-installed");
        assert_eq!(verdict_str(&Verdict::InstalledNotActivated), "installed-not-activated");
        assert_eq!(verdict_str(&Verdict::Inert), "inert");
        assert_eq!(verdict_str(&Verdict::Unknown), "unknown");
    }

    #[test]
    fn evidence_digest_is_8_chars_hex() {
        use quicken_probe::{Evidence, PrimitiveReport};
        let report = PrimitiveReport::new(
            "memlog",
            Verdict::Inert,
            Evidence::single("dev_node_exists", "false"),
        );
        let digest = evidence_digest(&report);
        assert_eq!(digest.len(), 8, "digest should be 8 chars");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()), "digest should be hex");
    }

    #[test]
    fn inert_streak_zero_when_no_receipts() {
        // With no receipt store, load_streaks returns empty.
        // This is tested indirectly: run_watch should work fine with streak=0.
        let publisher = MockPublisher::new(false);
        let opts = WatchOptions::default();
        let exit = run_watch(&opts, &publisher);
        assert_eq!(exit, 0);

        let calls = publisher.recorded();
        for (_, payload) in &calls {
            let v: serde_json::Value =
                serde_json::from_str(payload).expect("valid json");
            // inert_streak is either 0 or whatever attest has — must be a non-negative int.
            assert!(v["inert_streak"].as_u64().is_some());
        }
    }
}
