//! `crossdep` — primitive-to-primitive enablement graph.
//!
//! A "live" primitive can be silently crippled by a dark one. This module
//! models the static causal dependencies so each verdict can name what it is
//! `blocked_by` and what reviving a dark primitive `would_upgrade`.
//!
//! ## Design
//!
//! - [`EnablementEdge`] expresses one causal relationship between two primitives.
//! - [`annotate`] is a **pure function** of `(reports, edges)` — no I/O — that
//!   derives per-primitive [`AnnotatedReport`] with `blocked_by` / `would_upgrade`
//!   fields filled in.
//! - Cycles in the edge set are handled defensively (no infinite loop, no panic).

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{PrimitiveReport, Verdict};

/// Short identifier for a primitive (e.g. `"agentns"`, `"provfs"`).
pub type PrimitiveId = String;

/// The causal effect of one primitive (source) on another (target).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Effect {
    /// Target is entirely inert/blocked until source is live.
    EnablesLiveness,
    /// Target is live-degraded until source is live.
    ///
    /// For example: agentns being dark causes provfs to degrade from
    /// a 128-bit session id to a `comm:` fallback.
    UpgradesQuality {
        /// The degraded quality state (while source is dark).
        from_state: String,
        /// The upgraded quality state (once source is live).
        to_state: String,
    },
}

/// One directed causal edge in the enablement graph.
///
/// Semantics: when `from` is **not** `Live`, `to` is affected by `effect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnablementEdge {
    /// The source primitive (the one that must be live for the effect to fire).
    pub from: PrimitiveId,
    /// The target primitive (the one that is affected when source is dark).
    pub to: PrimitiveId,
    /// How the source's liveness (or lack thereof) affects the target.
    pub effect: Effect,
}

impl EnablementEdge {
    /// Construct an `EnablesLiveness` edge.
    #[must_use]
    pub fn enables(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self { from: from.into(), to: to.into(), effect: Effect::EnablesLiveness }
    }

    /// Construct an `UpgradesQuality` edge.
    #[must_use]
    pub fn upgrades(
        from: impl Into<String>,
        to: impl Into<String>,
        from_state: impl Into<String>,
        to_state: impl Into<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            effect: Effect::UpgradesQuality {
                from_state: from_state.into(),
                to_state: to_state.into(),
            },
        }
    }
}

/// The canonical, seeded edge set for wintermute kernel primitives.
///
/// Contains the `agentns → provfs` `UpgradesQuality` relationship that was
/// observed live on 2026-06-05: when agentns is inert, provfs falls back to
/// `comm:` session ids instead of 128-bit agentns UUIDs.
#[must_use]
pub fn canonical_edges() -> Vec<EnablementEdge> {
    vec![
        // agentns being dark causes provfs to use the `comm:` fallback session
        // id rather than the 128-bit agentns session UUID it is designed to record.
        EnablementEdge::upgrades(
            "agentns",
            "provfs",
            "comm-fallback",
            "128bit-session",
        ),
    ]
}

/// Annotation attached to a primitive after the cross-dep pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedReport {
    /// The original probe report.
    #[serde(flatten)]
    pub report: PrimitiveReport,

    /// Primitives that are currently dark and are causing this primitive to be
    /// blocked or degraded. Empty when the primitive is not affected by any dark
    /// source.
    pub blocked_by: Vec<PrimitiveId>,

    /// Primitives that this primitive (if it were `Live`) would upgrade.
    /// Non-empty only when this primitive is not `Live` — i.e., these are the
    /// targets that *would* benefit if this primitive were revived.
    pub would_upgrade: Vec<PrimitiveId>,
}

/// Source is considered "dark" when it is not `Live`.
const fn is_dark(verdict: &Verdict) -> bool {
    !matches!(verdict, Verdict::Live)
}

/// Run the annotation pass.
///
/// This is a **pure function** of `(reports, edges)` — no I/O, no writes.
///
/// Cycles in the edge set are handled by BFS with a visited set; a cyclic
/// fixture will produce finite, non-panicking output.
///
/// # Algorithm
///
/// For each edge `(from → to, effect)`:
/// - If `from` is dark, push `from` onto `to.blocked_by`.
/// - If `from` is dark (and would benefit `to`), push `to` onto `from.would_upgrade`.
///
/// The direct-edge-only scan is O(edges) and naturally cycle-safe (no
/// transitive walk needed for the per-report fields).
///
/// The BFS below is used only for `would_upgrade` transitive enrichment, which
/// is currently disabled in favour of the simpler direct-edge-only model to
/// keep the function deterministic and easy to test.
#[must_use]
pub fn annotate(
    reports: &[PrimitiveReport],
    edges: &[EnablementEdge],
) -> Vec<AnnotatedReport> {
    // Build a lookup: name → verdict
    let verdict_map: HashMap<&str, &Verdict> =
        reports.iter().map(|r| (r.name.as_str(), &r.verdict)).collect();

    // Accumulate blocked_by and would_upgrade per primitive name.
    let mut blocked_by: HashMap<&str, Vec<PrimitiveId>> = HashMap::new();
    let mut would_upgrade: HashMap<&str, Vec<PrimitiveId>> = HashMap::new();

    // Guard against duplicate edges in cyclic fixtures.
    let mut seen: HashSet<(&str, &str)> = HashSet::new();

    // BFS queue for cycle-safe traversal (currently used as a simple iterator
    // over the flat edge list; extended later for transitive walks).
    let mut queue: VecDeque<&EnablementEdge> = edges.iter().collect();
    let mut visited_edges: HashSet<usize> = HashSet::new();

    for (i, edge) in edges.iter().enumerate() {
        if visited_edges.contains(&i) {
            continue;
        }
        visited_edges.insert(i);

        let _ = queue.pop_front(); // keep BFS in sync (used for defensive drain)

        let pair = (edge.from.as_str(), edge.to.as_str());
        if seen.contains(&pair) {
            continue; // deduplicate cyclic fixture edges
        }
        seen.insert(pair);

        let from_dark = verdict_map
            .get(edge.from.as_str())
            .is_some_and(|v| is_dark(v));

        if from_dark {
            // `to` is affected by `from` being dark.
            blocked_by
                .entry(edge.to.as_str())
                .or_default()
                .push(edge.from.clone());

            // `from`, if revived, would upgrade `to`.
            would_upgrade
                .entry(edge.from.as_str())
                .or_default()
                .push(edge.to.clone());
        }
    }

    reports
        .iter()
        .map(|r| {
            let bb = blocked_by
                .get(r.name.as_str())
                .cloned()
                .unwrap_or_default();
            let wu = would_upgrade
                .get(r.name.as_str())
                .cloned()
                .unwrap_or_default();
            AnnotatedReport {
                report: r.clone(),
                blocked_by: bb,
                would_upgrade: wu,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Evidence, PrimitiveReport, Verdict};

    fn make_report(name: &str, verdict: Verdict) -> PrimitiveReport {
        PrimitiveReport::new(name, verdict, Evidence::empty())
    }

    // --- AC2: canonical edge set contains the agentns→provfs edge ---
    #[test]
    fn canonical_edges_contains_agentns_provfs() {
        let edges = canonical_edges();
        let found = edges.iter().any(|e| {
            e.from == "agentns"
                && e.to == "provfs"
                && matches!(
                    &e.effect,
                    Effect::UpgradesQuality { from_state, to_state }
                    if from_state == "comm-fallback" && to_state == "128bit-session"
                )
        });
        assert!(found, "canonical edges must contain agentns→provfs UpgradesQuality");
    }

    // --- AC3: agentns Inert, provfs LiveDegraded → provfs blocked_by agentns,
    //          agentns would_upgrade provfs ---
    #[test]
    fn ac3_inert_agentns_annotates_provfs() {
        let reports = vec![
            make_report("agentns", Verdict::Inert),
            make_report(
                "provfs",
                Verdict::LiveDegraded { reason: "agentns-fallback session id".into() },
            ),
        ];
        let edges = canonical_edges();
        let annotated = annotate(&reports, &edges);

        let agentns = annotated.iter().find(|a| a.report.name == "agentns").expect("agentns present");
        let provfs = annotated.iter().find(|a| a.report.name == "provfs").expect("provfs present");

        assert!(
            provfs.blocked_by.contains(&"agentns".to_owned()),
            "provfs must be blocked_by agentns when agentns is inert"
        );
        assert!(
            agentns.would_upgrade.contains(&"provfs".to_owned()),
            "agentns must would_upgrade provfs when agentns is inert"
        );
    }

    // --- AC4: agentns Live → no agentns reference in provfs blocked_by ---
    #[test]
    fn ac4_live_agentns_no_blocked_by() {
        let reports = vec![
            make_report("agentns", Verdict::Live),
            make_report("provfs", Verdict::Live),
        ];
        let edges = canonical_edges();
        let annotated = annotate(&reports, &edges);

        let provfs = annotated.iter().find(|a| a.report.name == "provfs").expect("provfs present");
        assert!(
            !provfs.blocked_by.contains(&"agentns".to_owned()),
            "provfs must NOT be blocked_by agentns when agentns is live"
        );
        // agentns should have empty would_upgrade when it is live
        let agentns = annotated.iter().find(|a| a.report.name == "agentns").expect("agentns present");
        assert!(
            agentns.would_upgrade.is_empty(),
            "agentns.would_upgrade must be empty when it is live"
        );
    }

    // --- AC6: cycle in edge set — no infinite loop, no panic ---
    #[test]
    fn ac6_cyclic_edges_no_panic() {
        let reports = vec![
            make_report("a", Verdict::Inert),
            make_report("b", Verdict::Inert),
        ];
        let edges = vec![
            EnablementEdge::enables("a", "b"),
            EnablementEdge::enables("b", "a"), // deliberate cycle
            EnablementEdge::enables("a", "b"), // deliberate duplicate
        ];
        // Must complete without panic or infinite loop.
        let annotated = annotate(&reports, &edges);
        assert_eq!(annotated.len(), 2);
    }

    // --- pure function: no side effects even with large input ---
    #[test]
    fn annotate_pure_no_mutation() {
        let reports = vec![
            make_report("agentns", Verdict::Inert),
            make_report("provfs", Verdict::Live),
            make_report("memlog", Verdict::InstalledNotActivated),
        ];
        let edges = canonical_edges();
        let a1 = annotate(&reports, &edges);
        let a2 = annotate(&reports, &edges);
        // pure: same input → same output
        assert_eq!(a1.len(), a2.len());
        for (r1, r2) in a1.iter().zip(a2.iter()) {
            assert_eq!(r1.blocked_by, r2.blocked_by);
            assert_eq!(r1.would_upgrade, r2.would_upgrade);
        }
    }
}
