# Changelog

## v0.3.0 — 2026-06-05

Add quicken remedy subcommand: remediation engine for dark wintermute primitives.
Implements Remediation type with Tier classification (SafeUserspace/RequiresSudo/
RequiresReboot/ReportOnly), remediation_for() mapping from PrimitiveReport to steps,
and CLI with --apply/--json/--print modes. All ACs 1-7 covered; AC8 deferred (live-only).

## v0.2.0 — 2026-06-05

add crossdep enablement graph: annotate() pure fn, canonical agentns->provfs edge, --deps CLI flag, quicken deps subcommand, tests/crossdep.rs 6-test suite

## v0.1.0 — initial release

Initial quicken workspace — primitive liveness probe (quicken-probe) and CLI (quicken).
