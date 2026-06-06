# quicken

Wintermute kernel primitive liveness checker — one command, full verdict.

`quicken` classifies every wintermute kernel primitive's runtime liveness with a structured verdict and its supporting evidence. A primitive can be compiled, packaged, installed, and still be runtime-inert (`/dev/memlog` exists but the user isn't in the `memlog` group; `/proc/self/agent_session` is all-zeros; `bpolicy status` says `loaded: false`). `quicken probe` surfaces all of that in one command.

## Usage

```
quicken probe           # human-readable table
quicken probe --json    # JSON array of PrimitiveReport
```

Example output:

```
PRIMITIVE     VERDICT                       EVIDENCE
--------------------------------------------------------------------------------
memlog        InstalledNotActivated         dev_node_path=/dev/memlog dev_node_exists=true ...
agentns       Inert                         agent_session_raw=000...000
warden        Inert                         bpolicy_status_raw={"loaded": false}
provfs        Unknown                       error=path does not exist
```

Exit codes: `0` = all primitives are `Live` or `LiveDegraded`; `1` = at least one is worse.

## Verdict taxonomy

| Verdict | Meaning |
|---|---|
| `Live` | Fully operational |
| `LiveDegraded` | Running but degraded (reason printed) |
| `InstalledNotActivated` | Installed but activation incomplete |
| `StagedNotInstalled` | Newer package built but not installed |
| `Inert` | Not active at runtime |
| `Unknown` | Could not determine |

## Primitives checked

| Primitive | What it probes |
|---|---|
| `memlog` | `/dev/memlog` device node, permissions, group membership, pkgrel drift |
| `agentns` | `/proc/self/agent_session` — all-zeros → Inert, non-zero UUID → Live |
| `warden` | `bpolicy status` JSON — `loaded: false` → Inert |
| `provfs` | `user.prov.session` xattr — `comm:` fallback form → LiveDegraded |

## Workspace layout

```
quicken/
├── quicken-probe/   # lib crate: Verdict, Evidence, PrimitiveReport, Probe trait
└── quicken/         # binary crate: `quicken` CLI
```

Sibling PRDs `quicken-attest`, `quicken-crossdep`, and `quicken-remedy` extend this workspace.

## Acceptance criteria (all 7 MUST ACs satisfied)

1. `cargo build --release` produces `quicken`; `quicken probe --help` lists `--json`.
2. All four probes return correct verdicts against fixture `ProbeEnv` (golden tests).
3. `MemlogProbe` returns `StagedNotInstalled` for fixture pkgrel 5-vs-11 with both pkgrels in evidence.
4. `quicken probe --json` emits valid JSON round-trippable as `Vec<PrimitiveReport>`.
5. Exit non-zero when any verdict is worse than `LiveDegraded`; zero when all acceptable.
6. No probe panics on missing surfaces — maps to `Unknown`/`Inert`, never crashes.
7. Tests perform zero network access and zero writes outside the test tmpdir.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
