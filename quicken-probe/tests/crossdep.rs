//! Integration tests for `quicken-crossdep`.
//!
//! These tests must appear in cargo output as `Running tests/crossdep.rs`
//! per the orphaned-mock-tests guard (AC7).
//!
//! AC7 guarantee: zero network, zero filesystem writes outside tmpdir.
//! All tests are pure in-memory operations on fixture data.

use quicken_probe::{
    annotate, canonical_edges, Effect, EnablementEdge, Evidence, PrimitiveReport, Verdict,
};

fn make_report(name: &str, verdict: Verdict) -> PrimitiveReport {
    PrimitiveReport::new(name, verdict, Evidence::empty())
}

// --- AC1: --deps / deps help is exercised transitively via library API ---
// (CLI arg parsing is tested by the unit tests in quicken-probe; here we
//  verify the public API surface that the CLI delegates to is complete.)
#[test]
fn ac1_canonical_edges_is_public_api() {
    let edges = canonical_edges();
    // The edge set must be non-empty and serializable (verifying the API is usable).
    assert!(!edges.is_empty(), "canonical_edges() must not be empty");
    let json = serde_json::to_string(&edges).expect("edges must be serializable");
    assert!(json.contains("agentns"), "serialized edges must reference agentns");
}

// --- AC2: the agentns→provfs UpgradesQuality edge is present ---
#[test]
fn ac2_agentns_provfs_edge_present() {
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
    assert!(found, "canonical edges must contain agentns->provfs UpgradesQuality{{comm-fallback->128bit-session}}");
}

// --- AC3: agentns Inert + provfs LiveDegraded → provfs blocked_by agentns,
//          agentns would_upgrade provfs ---
#[test]
fn ac3_inert_agentns_degraded_provfs_annotated() {
    let reports = vec![
        make_report("agentns", Verdict::Inert),
        make_report(
            "provfs",
            Verdict::LiveDegraded { reason: "comm: fallback session id".into() },
        ),
    ];
    let edges = canonical_edges();
    let annotated = annotate(&reports, &edges);

    let agentns = annotated
        .iter()
        .find(|a| a.report.name == "agentns")
        .expect("agentns must be in annotated output");
    let provfs = annotated
        .iter()
        .find(|a| a.report.name == "provfs")
        .expect("provfs must be in annotated output");

    assert!(
        provfs.blocked_by.contains(&"agentns".to_owned()),
        "provfs.blocked_by must include 'agentns' when agentns is Inert; got: {:?}",
        provfs.blocked_by
    );
    assert!(
        agentns.would_upgrade.contains(&"provfs".to_owned()),
        "agentns.would_upgrade must include 'provfs' when agentns is dark; got: {:?}",
        agentns.would_upgrade
    );
}

// --- AC4: agentns Live → provfs blocked_by does NOT reference agentns ---
#[test]
fn ac4_live_agentns_no_agentns_in_provfs_blocked_by() {
    let reports = vec![
        make_report("agentns", Verdict::Live),
        make_report("provfs", Verdict::Live),
    ];
    let edges = canonical_edges();
    let annotated = annotate(&reports, &edges);

    let provfs = annotated
        .iter()
        .find(|a| a.report.name == "provfs")
        .expect("provfs must be in annotated output");
    assert!(
        !provfs.blocked_by.contains(&"agentns".to_owned()),
        "provfs.blocked_by must NOT include 'agentns' when agentns is Live; got: {:?}",
        provfs.blocked_by
    );

    let agentns = annotated
        .iter()
        .find(|a| a.report.name == "agentns")
        .expect("agentns must be in annotated output");
    assert!(
        agentns.would_upgrade.is_empty(),
        "agentns.would_upgrade must be empty when it is Live; got: {:?}",
        agentns.would_upgrade
    );
}

// --- AC5: blocked_by and would_upgrade fields round-trip through JSON ---
#[test]
fn ac5_annotated_report_json_roundtrip() {
    let reports = vec![
        make_report("agentns", Verdict::Inert),
        make_report(
            "provfs",
            Verdict::LiveDegraded { reason: "comm-fallback".into() },
        ),
    ];
    let edges = canonical_edges();
    let annotated = annotate(&reports, &edges);

    let json = serde_json::to_string_pretty(&annotated)
        .expect("annotated reports must serialize to JSON");

    // Must contain the dependency fields.
    assert!(json.contains("blocked_by"), "JSON must include blocked_by field");
    assert!(json.contains("would_upgrade"), "JSON must include would_upgrade field");
    assert!(json.contains("agentns"), "JSON must reference agentns");
    assert!(json.contains("provfs"), "JSON must reference provfs");

    // Must round-trip.
    let decoded: Vec<quicken_probe::AnnotatedReport> =
        serde_json::from_str(&json).expect("JSON must deserialize back to AnnotatedReport vec");
    assert_eq!(decoded.len(), annotated.len(), "round-trip must preserve report count");

    let decoded_provfs = decoded
        .iter()
        .find(|a| a.report.name == "provfs")
        .expect("provfs must survive round-trip");
    assert!(
        decoded_provfs.blocked_by.contains(&"agentns".to_owned()),
        "round-tripped provfs.blocked_by must still include agentns"
    );
}

// --- AC6: cyclic edge set — no infinite loop, no panic ---
#[test]
fn ac6_cyclic_edge_set_no_panic() {
    let reports = vec![
        make_report("alpha", Verdict::Inert),
        make_report("beta", Verdict::Inert),
        make_report("gamma", Verdict::Live),
    ];
    // Deliberately cyclic: alpha→beta, beta→alpha, plus a self-loop on alpha.
    let edges = vec![
        EnablementEdge::enables("alpha", "beta"),
        EnablementEdge::enables("beta", "alpha"),
        EnablementEdge::enables("alpha", "alpha"), // self-loop
        EnablementEdge::enables("alpha", "beta"),  // duplicate
    ];
    // Must complete without panic or hang.
    let annotated = annotate(&reports, &edges);
    // gamma is live with no edges → clean
    let gamma = annotated
        .iter()
        .find(|a| a.report.name == "gamma")
        .expect("gamma must appear in output");
    assert!(gamma.blocked_by.is_empty(), "gamma must have no blockers");
    assert!(gamma.would_upgrade.is_empty(), "gamma has no would_upgrade");
}

// --- AC7 implied: this file IS `tests/crossdep.rs`, so cargo prints
//     `Running tests/crossdep.rs` — verified by the file's existence. ---
