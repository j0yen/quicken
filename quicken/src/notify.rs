//! `notify` subcommand — subscribe to `wm.health.primitive.*` and surface
//! darkening transitions as `SessionStart` banner fragments and optional peon-ping.
// This is a binary-internal module; `pub` items are visible only within the crate.
#![allow(unreachable_pub)]
//!
//! # Design
//!
//! This module implements two modes:
//!
//! - **`--once`**: reads the edge-state store, consults the latest quicken-attest
//!   receipt (or a supplied fixture stream), emits one line per *new* darkening
//!   transition, then exits. Used by the `SessionStart` hook.
//!
//! - **`--watch`**: long-lived; subscribes via `agorabus subscribe
//!   wm.health.primitive.` and processes each event in a loop, checking for
//!   transitions against the persisted edge-state store. Fires once per edge,
//!   stays silent on plateaus.
//!
//! # State
//!
//! The edge-state store is a JSON file at
//! `~/.local/state/quicken/notify.json` (configurable via `QUICKEN_NOTIFY_STATE`).
//! It maps `primitive_name → last_seen_verdict_str`. On first run (missing file),
//! all primitives are treated as first-seen — fail-open, no panic.
//!
//! # Signal sinks
//!
//! 1. **stdout** — one-line fragment:
//!    `quicken: ⚠ <name> went dark (streak <n>) — quicken remedy <name>`
//!
//! 2. **peon-ping** — invoked only when `--ping` is set.
//!
//! 3. **Recovery** — emitted only when `--notify-recovery` is set.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default inert-streak threshold to fire a notification (matches the
/// docket / self-review 3-run escalation convention).
pub const DEFAULT_STREAK_THRESHOLD: u32 = 3;

// ── Edge-state store ─────────────────────────────────────────────────────────

/// Persisted last-seen state for each primitive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeState {
    /// Maps primitive name → last verdict string that was *signalled*.
    ///
    /// An absent entry means first-seen (fail-open).
    pub last_verdict: HashMap<String, String>,
    /// Maps primitive name → last inert streak that fired a threshold notification.
    ///
    /// An absent entry means the threshold has never fired.
    pub last_streak_fired: HashMap<String, u32>,
}

impl EdgeState {
    /// Load the edge-state from `path`, or return a default (fail-open) on any error.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    /// Persist the edge-state to `path`, creating parent dirs as needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created or the file
    /// cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create state dir {}: {e}", parent.display()))?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialize error: {e}"))?;
        std::fs::write(path, text)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
        Ok(())
    }

    /// Return the default path for the edge-state file:
    /// `~/.local/state/quicken/notify.json` or `QUICKEN_NOTIFY_STATE` if set.
    #[must_use]
    pub fn default_path() -> PathBuf {
        if let Ok(v) = std::env::var("QUICKEN_NOTIFY_STATE") {
            return PathBuf::from(v);
        }
        std::env::var("HOME")
            .map_or_else(|_| PathBuf::from("/tmp"), PathBuf::from)
            .join(".local/state/quicken/notify.json")
    }
}

// ── Verdict helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `verdict_str` represents a "dark" verdict (worse than live-degraded).
#[must_use]
pub fn is_dark(verdict_str: &str) -> bool {
    !matches!(verdict_str, "live" | "live-degraded")
}

/// Returns `true` if a transition from `from` to `to` is a darkening edge.
///
/// A darkening edge means the primitive was live (or live-degraded) and is now dark,
/// OR the primitive was already dark but the verdict category changed.
#[must_use]
pub fn is_darkening_edge(from: Option<&str>, to: &str) -> bool {
    match from {
        // First-seen and dark → darkening edge.
        None => is_dark(to),
        // Was live/live-degraded, now dark → darkening edge.
        Some(prev) if !is_dark(prev) && is_dark(to) => true,
        // Already dark, same verdict string → plateau (debounce).
        _ => false,
    }
}

/// Returns `true` if a transition from `from` to `to` is a recovery edge.
#[must_use]
pub fn is_recovery_edge(from: Option<&str>, to: &str) -> bool {
    matches!(from, Some(prev) if is_dark(prev) && !is_dark(to))
}

// ── Event types ───────────────────────────────────────────────────────────────

/// A single health event consumed from the bus or fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthEvent {
    /// Subject: `primitive.<name>`.
    pub subject: String,
    /// Verdict string.
    pub verdict: String,
    /// Inert streak count.
    #[serde(default)]
    pub inert_streak: u32,
    /// RFC 3339 timestamp.
    #[serde(default)]
    pub ts: String,
    /// Names of primitives blocking this one.
    #[serde(default)]
    pub blocked_by: Vec<String>,
}

impl HealthEvent {
    /// Extract the primitive name from the subject field (`primitive.<name>` → `<name>`).
    #[must_use]
    pub fn primitive_name(&self) -> &str {
        self.subject
            .strip_prefix("primitive.")
            .unwrap_or(&self.subject)
    }
}

// ── Signal emission ───────────────────────────────────────────────────────────

/// Options controlling notify behaviour.
#[derive(Debug, Clone)]
pub struct NotifyOptions {
    /// Path to the edge-state store.
    pub state_path: PathBuf,
    /// Inert-streak threshold to fire a streak-crossing notification.
    pub streak_threshold: u32,
    /// Emit a recovery signal when a dark → live edge is observed.
    pub notify_recovery: bool,
    /// Invoke `peon-ping` on a transition.
    pub ping: bool,
    /// Path to agorabus binary.
    pub agorabus_bin: String,
}

impl Default for NotifyOptions {
    fn default() -> Self {
        Self {
            state_path: EdgeState::default_path(),
            streak_threshold: DEFAULT_STREAK_THRESHOLD,
            notify_recovery: false,
            ping: false,
            agorabus_bin: "agorabus".to_owned(),
        }
    }
}

/// A single notification signal to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    /// The one-line message for stdout.
    pub line: String,
    /// Whether to invoke peon-ping for this signal.
    pub should_ping: bool,
}

/// Trait for the ping sink, injectable for testing.
pub trait PingEmitter {
    /// Fire a peon-ping notification with `message`.
    fn ping(&self, message: &str);
}

/// Production peon-ping emitter: shells out to `peon-ping`.
pub struct ShellPingEmitter;

impl PingEmitter for ShellPingEmitter {
    fn ping(&self, message: &str) {
        // peon-ping is a fire-and-forget; ignore errors.
        let _ = Command::new("peon-ping").arg(message).status();
    }
}

/// No-op emitter for testing.
pub struct NullPingEmitter;

impl PingEmitter for NullPingEmitter {
    fn ping(&self, _message: &str) {}
}

/// Emit `signal` to stdout (and optionally peon-ping).
pub fn emit_signal(signal: &Signal, opts: &NotifyOptions, pinger: &dyn PingEmitter) {
    println!("{}", signal.line);
    if opts.ping && signal.should_ping {
        pinger.ping(&signal.line);
    }
}

// ── Core transition logic ─────────────────────────────────────────────────────

/// Classify an incoming event against the current edge state, returning any
/// signal to emit plus the updated state entry.
///
/// Returns `(Option<Signal>, new_verdict_str, new_streak_fired)`.
#[must_use]
pub fn classify_event(
    event: &HealthEvent,
    state: &EdgeState,
    opts: &NotifyOptions,
) -> Option<Signal> {
    let name = event.primitive_name();
    let prev = state.last_verdict.get(name).map(String::as_str);
    let verdict = event.verdict.as_str();

    // ── Darkening edge (live → dark) ─────────────────────────────────
    if is_darkening_edge(prev, verdict) {
        let streak_suffix = if event.inert_streak > 0 {
            format!(" (streak {})", event.inert_streak)
        } else {
            String::new()
        };
        let line = format!(
            "quicken: \u{26a0} {name} went dark{streak_suffix} — quicken remedy {name}"
        );
        return Some(Signal { line, should_ping: true });
    }

    // ── Streak threshold crossing (already-dark, streak just crossed N) ──
    if is_dark(verdict) {
        let prev_fired = state.last_streak_fired.get(name).copied().unwrap_or(0);
        let threshold = opts.streak_threshold;
        // Fire if streak just crossed the threshold and hasn't fired at this level yet.
        if event.inert_streak >= threshold && prev_fired < threshold {
            let line = format!(
                "quicken: \u{26a0} {name} inert streak {} crossed threshold {threshold} — quicken remedy {name}",
                event.inert_streak
            );
            return Some(Signal { line, should_ping: true });
        }
    }

    // ── Recovery edge (dark → live), only when --notify-recovery ────────
    if opts.notify_recovery && is_recovery_edge(prev, verdict) {
        let line = format!("quicken: \u{2705} {name} recovered (now {verdict})");
        return Some(Signal { line, should_ping: false });
    }

    // ── Plateau / unchanged dark / recovery without flag → silence ───────
    None
}

/// Apply an event to the edge state (updating `last_verdict` and `last_streak_fired`).
pub fn apply_event_to_state(event: &HealthEvent, state: &mut EdgeState) {
    let name = event.primitive_name().to_owned();
    state.last_verdict.insert(name.clone(), event.verdict.clone());

    // Track last fired streak threshold: if we just fired, record the streak.
    // This is updated externally (after classify_event returns Some) by the caller.
    // For the plateau/recovery case, update last_streak_fired to current streak
    // so crossing is only detected once.
    if is_dark(&event.verdict) {
        let prev_fired = state.last_streak_fired.get(&name).copied().unwrap_or(0);
        if event.inert_streak >= prev_fired {
            state.last_streak_fired.insert(name, event.inert_streak);
        }
    } else {
        // Recovered: reset streak fired counter.
        state.last_streak_fired.remove(&name);
    }
}

// ── --once mode ───────────────────────────────────────────────────────────────

/// Process a batch of events (used by `--once` mode).
///
/// Loads current edge state, classifies each event, emits signals,
/// and persists updated state. Returns an exit code (0 = ok, 2 = error).
pub fn run_once(events: &[HealthEvent], opts: &NotifyOptions, pinger: &dyn PingEmitter) -> i32 {
    let mut state = EdgeState::load(&opts.state_path);

    for event in events {
        if let Some(signal) = classify_event(event, &state, opts) {
            emit_signal(&signal, opts, pinger);
        }
        apply_event_to_state(event, &mut state);
    }

    if let Err(e) = state.save(&opts.state_path) {
        eprintln!("quicken notify: failed to save state: {e}");
        return 2;
    }

    0
}

/// Build the `--once` event list from the latest quicken-attest receipt.
///
/// Fail-open: if no receipts exist, returns an empty vec.
#[must_use]
pub fn events_from_attest() -> Vec<HealthEvent> {
    let store_path = quicken_attest::ReceiptStore::default_path();
    let store = quicken_attest::ReceiptStore::new(&store_path);

    let Ok(history) = store.load_all() else {
        return Vec::new();
    };

    let Some(latest) = history.last() else {
        return Vec::new();
    };

    // Compute current streaks from history.
    let streaks = quicken_attest::streak::compute_streaks(&latest.reports, &history);
    let edges = quicken_probe::canonical_edges();
    let annotated = quicken_probe::annotate(&latest.reports, &edges);

    latest
        .reports
        .iter()
        .map(|r| {
            let inert_streak = streaks
                .iter()
                .find(|(n, _)| n == &r.name)
                .map_or(0, |(_, s)| s.inert_streak);
            let blocked_by = annotated
                .iter()
                .find(|a| a.report.name == r.name)
                .map_or_else(Vec::new, |a| a.blocked_by.clone());
            let verdict = verdict_str_from_probe(&r.verdict);
            HealthEvent {
                subject: format!("primitive.{}", r.name),
                verdict,
                inert_streak,
                ts: latest.taken_at.to_rfc3339(),
                blocked_by,
            }
        })
        .collect()
}

fn verdict_str_from_probe(v: &quicken_probe::Verdict) -> String {
    match v {
        quicken_probe::Verdict::Live => "live".to_owned(),
        quicken_probe::Verdict::LiveDegraded { .. } => "live-degraded".to_owned(),
        quicken_probe::Verdict::StagedNotInstalled => "staged-not-installed".to_owned(),
        quicken_probe::Verdict::InstalledNotActivated => "installed-not-activated".to_owned(),
        quicken_probe::Verdict::Inert => "inert".to_owned(),
        _ => "unknown".to_owned(),
    }
}

// ── --watch mode ──────────────────────────────────────────────────────────────

/// Run the long-lived watch loop: subscribe to `wm.health.primitive.` on agorabus
/// and process each event.
///
/// Returns an exit code (0 = normal exit, 1 = bus error, 2 = internal error).
pub fn run_watch(opts: &NotifyOptions, pinger: &dyn PingEmitter) -> i32 {
    let mut child = match Command::new(&opts.agorabus_bin)
        .args(["subscribe", "wm.health.primitive."])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("quicken notify --watch: failed to spawn agorabus: {e}");
            return 1;
        }
    };

    let Some(stdout) = child.stdout.take() else {
        eprintln!("quicken notify --watch: failed to get agorabus stdout");
        return 2;
    };

    let reader = BufReader::new(stdout);
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("quicken notify --watch: read error: {e}");
                break;
            }
        };

        // agorabus subscribe emits: `<topic> <json_payload>` (space-separated)
        // or just the JSON payload depending on version. Try JSON-only first.
        let payload = if line.starts_with('{') {
            line.as_str()
        } else if let Some(pos) = line.find('{') {
            &line[pos..]
        } else {
            continue; // Skip non-payload lines (e.g. reconnect banners).
        };

        let event: HealthEvent = match serde_json::from_str(payload) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut state = EdgeState::load(&opts.state_path);
        if let Some(signal) = classify_event(&event, &state, opts) {
            emit_signal(&signal, opts, pinger);
        }
        apply_event_to_state(&event, &mut state);

        if let Err(e) = state.save(&opts.state_path) {
            eprintln!("quicken notify --watch: state save error: {e}");
        }
    }

    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct RecordingPinger {
        calls: RefCell<Vec<String>>,
    }

    impl RecordingPinger {
        fn new() -> Self {
            Self { calls: RefCell::new(Vec::new()) }
        }

        fn recorded(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl PingEmitter for RecordingPinger {
        fn ping(&self, message: &str) {
            self.calls.borrow_mut().push(message.to_owned());
        }
    }

    fn opts_with_tmpdir(tmp: &tempfile::TempDir) -> NotifyOptions {
        NotifyOptions {
            state_path: tmp.path().join("notify.json"),
            streak_threshold: DEFAULT_STREAK_THRESHOLD,
            notify_recovery: false,
            ping: false,
            agorabus_bin: "agorabus".to_owned(),
        }
    }

    fn dark_event(name: &str, verdict: &str, streak: u32) -> HealthEvent {
        HealthEvent {
            subject: format!("primitive.{name}"),
            verdict: verdict.to_owned(),
            inert_streak: streak,
            ts: "2026-06-09T00:00:00Z".to_owned(),
            blocked_by: Vec::new(),
        }
    }

    // AC1: --once emits one-line, remedy-prefilled fragment for new darkening
    // transition; silent for unchanged dark; silent for recovery (default).
    #[test]
    fn once_emits_darkening_fragment() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let opts = opts_with_tmpdir(&tmp);
        let pinger = NullPingEmitter;

        // First-seen dark event → should classify as darkening.
        let event = dark_event("memlog", "inert", 1);
        let state = EdgeState::default();
        let signal = classify_event(&event, &state, &opts);
        assert!(signal.is_some(), "first-seen dark should produce signal");
        let s = signal.unwrap();
        assert!(s.line.contains("memlog"), "line should name the primitive");
        assert!(s.line.contains("went dark"), "line should say 'went dark'");
        assert!(s.line.contains("quicken remedy memlog"), "line should be actionable");
    }

    #[test]
    fn once_silent_for_unchanged_dark() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let opts = opts_with_tmpdir(&tmp);

        // State already has memlog as dark.
        let mut state = EdgeState::default();
        state.last_verdict.insert("memlog".to_owned(), "inert".to_owned());

        let event = dark_event("memlog", "inert", 2);
        let signal = classify_event(&event, &state, &opts);
        assert!(signal.is_none(), "unchanged dark should be silent (debounced)");
    }

    #[test]
    fn once_silent_for_recovery_without_flag() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let opts = opts_with_tmpdir(&tmp);

        // State: memlog was dark.
        let mut state = EdgeState::default();
        state.last_verdict.insert("memlog".to_owned(), "inert".to_owned());

        // Now recovering.
        let event = HealthEvent {
            subject: "primitive.memlog".to_owned(),
            verdict: "live".to_owned(),
            inert_streak: 0,
            ts: String::new(),
            blocked_by: Vec::new(),
        };
        let signal = classify_event(&event, &state, &opts);
        assert!(signal.is_none(), "recovery without --notify-recovery should be silent");
    }

    // AC2: Debounce holds — same dark verdict twice → signal on first only.
    #[test]
    fn debounce_second_dark_is_silent() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let opts = opts_with_tmpdir(&tmp);
        let pinger = NullPingEmitter;

        let events = vec![
            dark_event("agentns", "inert", 0),
            dark_event("agentns", "inert", 0),
        ];

        let mut state = EdgeState::default();
        let mut signals = 0u32;
        for event in &events {
            if classify_event(event, &state, &opts).is_some() {
                signals += 1;
            }
            apply_event_to_state(event, &mut state);
        }
        assert_eq!(signals, 1, "debounce: only first dark transition fires");

        // Also test via run_once with a temp dir.
        let tmp2 = tempfile::tempdir().expect("tmpdir2");
        let opts2 = opts_with_tmpdir(&tmp2);
        // First run: fire.
        run_once(&[dark_event("agentns", "inert", 0)], &opts2, &pinger);
        // State is persisted; second run with same verdict should be silent.
        let state2 = EdgeState::load(&opts2.state_path);
        let signal2 = classify_event(&dark_event("agentns", "inert", 0), &state2, &opts2);
        assert!(signal2.is_none(), "persisted state suppresses re-alarm");
    }

    // AC3: Streak threshold — inert_streak crossing threshold fires once.
    #[test]
    fn streak_threshold_fires_at_crossing() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let opts = opts_with_tmpdir(&tmp);

        // State: memlog already dark (debounce passed), streak hasn't crossed yet.
        let mut state = EdgeState::default();
        state.last_verdict.insert("memlog".to_owned(), "inert".to_owned());
        // streak_fired = 0 (never fired).

        // streak=2 → below threshold (default 3), no fire.
        let ev2 = dark_event("memlog", "inert", 2);
        let sig2 = classify_event(&ev2, &state, &opts);
        assert!(sig2.is_none(), "streak 2 below threshold 3: silent");

        // streak=3 → crosses threshold → fire.
        let ev3 = dark_event("memlog", "inert", 3);
        let sig3 = classify_event(&ev3, &state, &opts);
        assert!(sig3.is_some(), "streak 3 at threshold 3: fires");
        let s = sig3.unwrap();
        assert!(s.line.contains("streak"), "signal mentions streak");

        // Apply, then re-check: same streak → no second fire.
        apply_event_to_state(&ev3, &mut state);
        let sig3b = classify_event(&ev3, &state, &opts);
        assert!(sig3b.is_none(), "streak plateau: no second fire");
    }

    // AC4: --notify-recovery emits recovery signal; without it, silent.
    #[test]
    fn notify_recovery_flag_controls_recovery_signal() {
        let tmp = tempfile::tempdir().expect("tmpdir");

        let mut state = EdgeState::default();
        state.last_verdict.insert("memlog".to_owned(), "inert".to_owned());

        let recovery_event = HealthEvent {
            subject: "primitive.memlog".to_owned(),
            verdict: "live".to_owned(),
            inert_streak: 0,
            ts: String::new(),
            blocked_by: Vec::new(),
        };

        // Without flag: silent.
        let opts_no_recovery = NotifyOptions {
            state_path: tmp.path().join("notify.json"),
            notify_recovery: false,
            ..NotifyOptions::default()
        };
        let sig_no = classify_event(&recovery_event, &state, &opts_no_recovery);
        assert!(sig_no.is_none(), "without --notify-recovery: silent");

        // With flag: emits recovery.
        let opts_recovery = NotifyOptions {
            state_path: tmp.path().join("notify.json"),
            notify_recovery: true,
            ..NotifyOptions::default()
        };
        let sig_yes = classify_event(&recovery_event, &state, &opts_recovery);
        assert!(sig_yes.is_some(), "with --notify-recovery: emits recovery signal");
        let s = sig_yes.unwrap();
        assert!(s.line.contains("recovered"), "recovery line mentions 'recovered'");
        assert!(s.line.contains("memlog"), "recovery line names primitive");
    }

    // AC6: --ping invokes peon-ping; absent the flag, no ping.
    #[test]
    fn ping_flag_controls_peon_ping() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let state = EdgeState::default();
        let event = dark_event("warden", "inert", 0);

        // ping=false → no ping.
        let opts_no_ping = NotifyOptions {
            state_path: tmp.path().join("notify.json"),
            ping: false,
            ..NotifyOptions::default()
        };
        let pinger_no = RecordingPinger::new();
        if let Some(signal) = classify_event(&event, &state, &opts_no_ping) {
            emit_signal(&signal, &opts_no_ping, &pinger_no);
        }
        assert!(pinger_no.recorded().is_empty(), "no ping without --ping");

        // ping=true → ping is called.
        let opts_ping = NotifyOptions {
            state_path: tmp.path().join("notify.json"),
            ping: true,
            ..NotifyOptions::default()
        };
        let pinger_yes = RecordingPinger::new();
        let state2 = EdgeState::default();
        if let Some(signal) = classify_event(&event, &state2, &opts_ping) {
            emit_signal(&signal, &opts_ping, &pinger_yes);
        }
        assert!(!pinger_yes.recorded().is_empty(), "ping with --ping set");
    }

    // AC7: Edge-state store round-trips and tolerates missing/corrupt file.
    #[test]
    fn edge_state_roundtrip() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("notify.json");

        let mut state = EdgeState::default();
        state.last_verdict.insert("memlog".to_owned(), "inert".to_owned());
        state.last_streak_fired.insert("memlog".to_owned(), 3);

        state.save(&path).expect("save");
        let loaded = EdgeState::load(&path);
        assert_eq!(loaded.last_verdict.get("memlog").map(String::as_str), Some("inert"));
        assert_eq!(loaded.last_streak_fired.get("memlog").copied(), Some(3));
    }

    #[test]
    fn edge_state_tolerates_missing_file() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("nonexistent.json");
        let state = EdgeState::load(&path);
        // Fail-open: empty state.
        assert!(state.last_verdict.is_empty());
    }

    #[test]
    fn edge_state_tolerates_corrupt_file() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("notify.json");
        std::fs::write(&path, b"not-valid-json!!!").expect("write corrupt");
        let state = EdgeState::load(&path);
        // Fail-open: default state.
        assert!(state.last_verdict.is_empty());
    }

    // Extra: run_once with fixture events, verify signal count.
    #[test]
    fn run_once_with_fixture_events() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let opts = opts_with_tmpdir(&tmp);
        let pinger = NullPingEmitter;

        let events = vec![
            dark_event("memlog", "inert", 1),        // new dark → signal
            dark_event("agentns", "inert", 1),       // new dark → signal
            dark_event("warden", "live", 0),         // live → no signal
        ];

        let code = run_once(&events, &opts, &pinger);
        assert_eq!(code, 0, "run_once should exit 0");

        // After run_once, state should be persisted.
        let state = EdgeState::load(&opts.state_path);
        assert_eq!(state.last_verdict.get("memlog").map(String::as_str), Some("inert"));
        assert_eq!(state.last_verdict.get("agentns").map(String::as_str), Some("inert"));
        assert_eq!(state.last_verdict.get("warden").map(String::as_str), Some("live"));
    }

    #[test]
    fn is_dark_verdicts() {
        assert!(is_dark("inert"));
        assert!(is_dark("unknown"));
        assert!(is_dark("installed-not-activated"));
        assert!(is_dark("staged-not-installed"));
        assert!(!is_dark("live"));
        assert!(!is_dark("live-degraded"));
    }

    #[test]
    fn is_darkening_edge_cases() {
        // First-seen dark.
        assert!(is_darkening_edge(None, "inert"));
        // First-seen live: not darkening.
        assert!(!is_darkening_edge(None, "live"));
        // live → inert: darkening.
        assert!(is_darkening_edge(Some("live"), "inert"));
        // live-degraded → unknown: darkening.
        assert!(is_darkening_edge(Some("live-degraded"), "unknown"));
        // inert → inert: plateau (not darkening).
        assert!(!is_darkening_edge(Some("inert"), "inert"));
        // inert → live: not darkening.
        assert!(!is_darkening_edge(Some("inert"), "live"));
    }
}
