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

## Install

```sh
cargo install --path .
```

## License

MIT © Joe Yen
