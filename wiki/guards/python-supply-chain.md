---
type: Guard
title: "python-supply-chain"
description: "Python (uv) dependency supply-chain hardening (lockfile + hashes + cooldown)."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "python-supply-chain"
checklist_section: ["4", "5"]
standards: ["OWASP-LLM:LLM03", "OWASP:A06", "SOC2:CC8.1"]
---

# Python (uv) dependency supply-chain hardening (lockfile + hashes + cooldown)

_Backfilled 2026-06-12 — documents Dean's guard to the shared guard-design convention._

---

## The threat

The Python analog of the JS supply-chain risk. Without integrity-verified locks and a
release-age cooldown, an install can silently adopt a freshly-published, possibly-compromised
package version — the consumer-side failure behind incidents like the May-2026 TanStack
compromise (84 malicious versions, caught in ~20 min). Four hardening gaps the guard checks:

1. **No hash-verified lock** — installs are version-pinned but not integrity-checked, so a
   tampered artifact at the same version installs cleanly.
2. **No cooldown** — a brand-new version is adopted before the ecosystem has time to catch and
   yank a compromise.
3. **Loose pinning / multi-index** — unpinned direct deps and `--extra-index-url` /
   `unsafe-best-match` / `http://` indexes are the **dependency-confusion** vectors.
4. **Stale CVE waivers** — a `pip-audit-exceptions.json` entry with no expiring `review_by` is a
   silent forever-ignore.

`pip` itself has no native cooldown and no expiring-waiver mechanism, so remediations point at
`uv`. Findings carry **OWASP-LLM:LLM03** + **OWASP:A06**.

## Why this guard fits the stack

The FastAPI backend's dependencies are the server-side supply chain. The guard encodes the
project's uv-based hardening recipe (`uv.lock` + `exclude-newer` + an honest waiver DB) so any
Python project in the stack is held to it.

## Detection design

1. **`applies()` gate** — `"python" in profile.features`.
2. **Scan unit** — each dependency directory (`dependency_dirs`); the exceptions-DB check runs
   once at root. Dependency-free (stdlib `tomllib`).
3. **Checks & findings** (rule prefix `python-supply-chain/`):
   - `no-locked-hashes` (**HIGH**) — no `uv.lock`/`poetry.lock`/`pdm.lock`/`Pipfile.lock` and no
     `--hash=` lines in any `requirements*.txt`.
   - `no-cooldown` (**MEDIUM**) / `cooldown-too-short` (**LOW**) — uv `exclude-newer` /
     `UV_EXCLUDE_NEWER` absent, or below the recommended 48h (`_REQUIRED_HOURS = 48`; friendly
     durations like "2 days"/"1 week" are parsed).
   - `unpinned` (**MEDIUM**) — loose/absent direct `==` specifiers.
   - `extra-index-url` (**MEDIUM**) — multi-index / `unsafe-best-match`.
   - `insecure-index` (**HIGH**) — a plain `http://` index.
   - `exception-no-expiry` (**MEDIUM**) / `exception-lapsed` (**MEDIUM**) — a CVE waiver in
     `pip-audit-exceptions.json` with no `review_by`, or one whose `review_by` has passed
     (ties into the expiring-exception philosophy used across the tool).
4. **Opt-out pragmas**: a `# security: allow-no-cooldown` comment in `pyproject.toml`, `uv.toml` or
   a `.env*` file, and a `# security: allow-extra-index` comment in `pyproject.toml` or a
   `requirements*.txt`. A quoted TOML or `.env` value carrying the phrase does not count (#424).

## When NOT to flag

A project with a hash-verified lock (or `--hash=` requirements), a ≥48h `exclude-newer`, `==`
pins, a single `https://` index, and a waiver DB where every entry has a future `review_by`
passes clean. The pragmas cover deliberate, documented opt-outs (e.g. an internal extra index
that is genuinely trusted). A malformed exceptions file is swallowed, not raised
(`parse()`/`run()` never crash).

## Tests

| Test | What it checks |
|---|---|
| `test_pysc_flags_requirements_without_hashed_lock` | requirements with no hashes/lock → HIGH |
| `test_pysc_passes_with_uv_lock_and_cooldown` | uv.lock + cooldown → silent |
| `test_pysc_flags_missing_cooldown` | no `exclude-newer` → MEDIUM |
| `test_pysc_cooldown_too_short_and_ok` | cooldown < 48h → LOW; ≥48h → silent |
| `test_pysc_cooldown_pragma_opt_out` | `allow-no-cooldown` → silent |
| `test_python_supply_chain_pragma_quoted_in_a_string_does_not_suppress_cooldown_pyproject`, `test_python_supply_chain_pragma_quoted_in_a_string_does_not_suppress_cooldown_uv_toml`, `test_python_supply_chain_pragma_quoted_in_a_string_does_not_suppress_cooldown_env`, `test_python_supply_chain_pragma_quoted_in_a_string_does_not_suppress_extra_index_pyproject`, `test_python_supply_chain_pragma_comment_suppresses_uv_toml`, `test_python_supply_chain_pragma_comment_suppresses_env`, `test_python_supply_chain_pragma_comment_suppresses_extra_index_pyproject`, `test_python_supply_chain_pragma_comment_suppresses_extra_index_requirements` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_pysc_flags_unpinned_and_extra_index` | loose pins + extra index → MEDIUM ×2 |
| `test_pysc_flags_insecure_http_index` | `http://` index → HIGH |
| `test_pysc_exception_db_no_expiry_and_lapsed` | waiver without/past `review_by` → MEDIUM |
| `test_pysc_exception_db_malformed_no_crash` | malformed JSON → no crash, no finding |
| `test_pysc_utf16_requirements_pins_not_flagged_unpinned` | UTF-16 requirements decoded correctly |
| `test_pysc_na_for_non_python` | `applies()` False without Python |

## Known bypasses

- **Cooldown via CLI/CI only** — `uv --exclude-newer` passed on the command line (not in
  config/env) isn't visible to a static scan.
- **Hashes elsewhere** — a constraints file or private index policy enforcing integrity outside
  the scanned manifests reads as "no hashes."
- **Pin indirection** — versions pinned in a constraints file rather than the primary manifest.
- **Trusted-but-flagged internal index** — a legitimately-trusted extra index still flags
  unless pragma-suppressed.

## What this guard does NOT prove

That installed packages are safe — only that the project's *posture* (locked hashes, cooldown,
pinning, single trusted index, non-stale waivers) is hardened. Package contents are the job of
`pip-audit`/`bandit`, not this guard.

# Citations

[1] agentsec checklist item `4-hallucinated-dependency-pinning` (§4)
[2] agentsec checklist item `5-lockfile-committed` (§5)
[3] agentsec checklist item `5-low-medium-cve-tracking` (§5)
[4] OWASP-LLM:LLM03
[5] OWASP:A06
[6] SOC2:CC8.1
