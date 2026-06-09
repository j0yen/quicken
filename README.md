# quicken

The reason dark primitives rot is that the self-review escalates each one

## Overview

The reason dark primitives rot is that the self-review escalates each one
"once" and then goes silent — so the same finding reappears boot after boot with
no sense of *how long* it's been broken or whether it's getting worse.
`quicken-attest` extends the `quicken` workspace to persist a timestamped
liveness receipt, compute a delta against the previous one, and keep a monotonic
per-primitive **inert-streak counter** so a primitive that stays dark gets
*louder* over consecutive boots instead of fading into the noise.


## Acceptance


1. `quicken attest --help` documents `--json` and `--no-write`.
2. `quicken attest` writes a well-formed receipt to the injected store path and
   the file round-trips back into the receipt type (golden test).
3. Given a seeded prior receipt and a current set of reports, the computed
   `Delta` is correct for each case — `Unchanged`, `Regressed` (Live→Inert),
   `Improved` (Inert→Live), and `EvidenceChanged` (memlog pkgrel 5→11, verdict
   unchanged) — asserted on fixtures.
4. `inert_streak` counts only distinct `boot_id`s: three prior receipts across
   two boot ids with the primitive dark yields the correct consecutive-boot
   streak (tested on a seeded receipt history).
5. The streak-band wording escalates: a fixture with streak `1`, `3`, and `7`
   produces the three distinct severity strings (asserted).
6. `quicken attest --no-write` produces identical stdout to `quicken attest` but
   creates no receipt file (asserted: store dir unchanged).
7. Tests perform **zero network access and write only inside the injected store
   tmpdir** (cloud-build-safe); `boot_id` and clock are injected, never read from
   the real host in tests (consistent with the no-`Date::now` constraint).

## quicken watch — continuous mid-day liveness publishing

`quicken watch --once` runs the full probe set and publishes each verdict to
agorabus on `wm.health.primitive.<name>`, using the existing `wm.health.*`
envelope. Pair with the provided systemd-user units for automatic mid-day
coverage:

```sh
# Copy units to the user systemd directory.
cp scripts/quicken-watch.service ~/.config/systemd/user/
cp scripts/quicken-watch.timer   ~/.config/systemd/user/

# Enable and start the timer (runs 2 min after boot, then every 30 min).
systemctl --user enable --now quicken-watch.timer
```

**Boundary**: `wintermute_watchdog` watches daemon heartbeat liveness.
`quicken-watch` watches a disjoint axis — kernel/userspace primitive liveness
(`primitive.<name>` subject namespace). Same envelope, no overlap.

**Flags**:

| Flag | Description |
|------|-------------|
| `--once` | Required; run probe set once and exit. |
| `--format json` | Also emit published events as a JSON array on stdout. |
| `--require-bus` | Exit non-zero if the bus is unreachable (default: fail-open). |

**Published topic**: `wm.health.primitive.<name>` (one event per primitive).

## agentns verdicts and the optional `assay` integration

The `AgentnsProbe` reads `/proc/self/agent_session`. When the file contains
all-zeros it knows the session is inert, but it cannot on its own tell whether:

- **the kernel flag is broken** (the mechanism itself is rejected by the kernel), or
- **the launch is not wrapped** (the kernel works but the process was started
  without the agentns wrapper).

When `assay` is on `$PATH` (or injected via `ProbeEnv::with_assay_path`), the
probe shells out to `assay agentns --json` exactly once per run (and only when
the session reads all-zeros) to get an active attestation. This enriches the
verdict:

| `assay agentns` result | quicken verdict | Evidence fields added |
|---|---|---|
| `FlagRejected` (kernel rejects `CLONE_NEWAGENT`) | `Inert` | `cause`, `remediation` ("PRD-agentns-clone-flag-fix; launch-wrap will not help"), `assay_compiled_flag`, `assay_collides_with`, `assay_unshare_errno` |
| `Live` (kernel works; process not wrapped) | `MechanismLiveNotWired` | `remediation` ("wrap the launch (onramp claude-agentns-wrap)") |
| absent / error | `Inert` (no enrichment) | — |

The `assay` dependency is **optional and fail-open**: if `assay` is absent or
returns a non-zero exit code the probe falls back to the same plain `Inert`
verdict it has always produced.

### Before the kernel fix (current state)

```
agentns: Inert
  cause: kernel rejects CLONE_NEWAGENT (flag 0x100 == CLONE_VM), errno EINVAL
  remediation: PRD-agentns-clone-flag-fix; launch-wrap will not help
```

### After the kernel fix (once PRD-agentns-clone-flag-fix lands)

```
agentns: MechanismLiveNotWired
  remediation: wrap the launch (onramp claude-agentns-wrap)
```

## Install

```sh
cargo install --path .
```

## License

MIT © Joe Yen
