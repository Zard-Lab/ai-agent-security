---
type: Guard
title: "js-supply-chain"
description: "JS/TS dependency supply-chain hardening (lockfile, cooldown, scripts, pinning, registry)."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "js-supply-chain"
checklist_section: ["5"]
standards: ["OWASP-LLM:LLM03", "OWASP:A06", "SOC2:CC8.1"]
---

# JS/TS dependency supply-chain hardening (lockfile, cooldown, scripts, pinning, registry)

_Backfilled 2026-06-12 — documents Dean's guard to the shared guard-design convention._

---

## The threat

A JS/TS dependency tree is the largest untrusted-code surface in the stack. The guard is the
consumer-side defense against npm supply-chain worms — concretely **Shai-Hulud** (Sept 2025: a
`postinstall` worm that ran TruffleHog, stole npm tokens, and self-republished into ~500
packages incl. `@ctrl/tinycolor`; the Nov 2025 "Second Coming" moved to `preinstall`, ~796
packages / 25k+ repos, with a destructive payload). The attack executes the moment you
`install` a compromised version. The defenses are structural: pin what you run, don't run
install scripts, age new releases before adopting them, and resolve from one trusted registry.
Findings carry **OWASP-LLM:LLM03 (Supply Chain)** + **OWASP:A06**.

## Why this guard fits the stack

The flagship is a React frontend migrated npm → pnpm 11 with a documented `.npmrc` +
`pnpm-workspace.yaml` hardening recipe. This guard encodes that recipe so any FastAPI+React app
gets the same checks, including workspace/monorepo layouts.

## Detection design

1. **`applies()` gate** — `"frontend" in profile.features` OR a detected JS package manager
   (`pnpm`/`npm`/`bun`/`yarn`).
2. **Scan unit** — each directory with a `package.json` that *declares dependencies*
   (`js_dependency_dirs`). For each, config is gathered across the **workspace ancestor chain**
   (`ancestors`) so a sub-package inherits the root lockfile / `.npmrc` / `pnpm-workspace.yaml`.
3. **Checks & findings** (rule prefix `js-supply-chain/`, standards `["OWASP-LLM:LLM03","OWASP:A06"]`
   unless noted):
   - `lockfile-missing` (**HIGH**) — no lockfile anywhere up the chain. Recognized lockfiles:
     `pnpm-lock.yaml`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `bun.lockb`
     (legacy binary), and `bun.lock` (the text lockfile Bun ≥1.2 writes by default).
   - `lifecycle-scripts` (**HIGH**) — npm/yarn without `ignore-scripts=true`, or pnpm with
     `dangerouslyAllowAllBuilds`. *This is THE Shai-Hulud defense.*
   - `no-cooldown` (**MEDIUM**) / `cooldown-too-short` (**LOW**, standards LLM03 only) — release-age
     cooldown absent, or below 48h (`_REQUIRED_MINUTES = 2880`). The guard normalizes the
     key/unit matrix: pnpm `minimum-release-age` (.npmrc, **minutes**), `minimumReleaseAge`
     (yaml/json, **minutes**), npm `min-release-age` (.npmrc, **days** → ×1440).
   - `unpinned` (**MEDIUM**) — floating/exotic direct specs (`^`,`~`,`*`,`latest`, partial
     `19`, git/url sources), via the `_is_floating` heuristic (which correctly treats
     `workspace:`/`catalog:`/`link:` and exact `1.2.3`/`=1.2.3` as fine).
   - `no-packagemanager-pin` (**LOW**, A06) — no `packageManager` field.
   - `packagemanager-vulnerable` (**HIGH**) — the `packageManager` pin is a toolchain version
     **below the curated CVE floor** for that tool (`version_floors.json` entries with
     `ecosystem: "packageManager"`; e.g. pnpm < `11.9.0` — the Nov-2025 lockfile/patch/alias
     toolchain CVEs). A pinned-but-vulnerable toolchain is worse than an unpinned one: it
     reproducibly installs the affected version on every machine and in CI (Corepack). Conservative:
     only a parseable `major.minor[.patch]` pin below a floor fires — a bare-major pin (`pnpm@11`)
     floats to the newest 11.x via Corepack and is too coarse to flag. Reuses the
     `dependency-version-floor` version-compare helpers; the `packageManager` ecosystem is enforced
     here (not by `dependency-version-floor`, which scopes to pip/npm dependency pins).
   - `insecure-registry` (**HIGH**) — an `http://` registry.
   - `exotic-subdeps` (**MEDIUM**) — `blockExoticSubdeps` explicitly disabled.
   - `insecure-dependency-transport` (**HIGH**) — a direct dependency whose OWN version spec
     resolves over plaintext `http://`/`ftp://` (exact-prefix match, so `git+http://github.com/...`
     — the existing `git+` exotic-source case — does NOT match). Added 2026-08 as a
     distinct, more specific rule than the generic `unpinned`/exotic-source classification:
     CodeQL's `javascript/ql/src/Security/CWE-300/InsecureDependencyResolution.ql` rates a
     plaintext-transport dependency (MITM-vulnerable) as materially worse than an `https://`
     dependency that's merely unpinned (transport is fine, just not version-pinned; that case
     stays under `unpinned`, unchanged). The more-specific rule wins: a dependency matched here is
     excluded from `unpinned`'s tally for the same manifest, so the same line never reads as two
     findings. Unlike `unpinned`, a committed lockfile + cooldown do **not** suppress this — the
     lockfile would still record (and re-fetch from, on install) the same plaintext URL, so the
     MITM exposure is independent of pinning.
   - `trust-downgrade` (**LOW**, LLM03) — pnpm without `trustPolicy: no-downgrade`.
   - `lockfile-manifest-drift` (**MEDIUM**, added 2026-08) — a dependency declared in
     `package.json` (`dependencies`/`devDependencies`/`optionalDependencies`) that does not
     appear in the committed lockfile's own *resolved* set: the manifest was edited without
     regenerating the lockfile, so a `--frozen-lockfile`/`npm ci` build either fails outright or
     silently resolves the drifted dependency unlocked. Distinct from `lockfile-missing` — this
     fires only when a lockfile IS present but disagrees with the manifest. Scoped to **npm-format
     lockfiles only** (`package-lock.json`/`npm-shrinkwrap.json`); `pnpm-lock.yaml`/`yarn.lock` are
     YAML/custom text formats agentsec's stdlib-only design doesn't parse, so those are silently
     not checked rather than guessed at with a fragile text parse. Handles both lockfile shapes:
     `lockfileVersion` 2/3's flat `packages` map (keyed `node_modules/<name>`, scoped packages as
     `node_modules/@scope/name`) and `lockfileVersion` 1's `dependencies` map (keyed directly by
     name) — a version-conflict-hoisted nested dependency is matched on the name *after* the last
     `node_modules/` segment, so it isn't misread as missing.
4. **Opt-out pragmas** (in `.npmrc`/`pnpm-workspace.yaml`/`package.json`): `security:
   allow-no-cooldown`, `allow-lifecycle-scripts`, `allow-exotic-subdeps` (also gates
   `insecure-dependency-transport` — a plaintext-URL dependency is a kind of exotic source, so it
   reuses the existing pragma rather than inventing a new one), `allow-lockfile-manifest-drift`
   (`.npmrc`/`pnpm-workspace.yaml` only — a `#`/`//` comment inside `package.json` itself would
   break the JSON parse this rule reads declared dependencies from). In `pnpm-workspace.yaml` only a
   `#` comment counts (the `yaml` comment view, #1040 T5), so a YAML scalar quoting the phrase does
   not suppress. `package.json` (no comment syntax, so a `"//"` string value) and `.npmrc` stay a
   raw-text match: `.npmrc` is ini, where `;` also starts a comment, which the `hash` view does not
   read, the same decision `npm-ignore-scripts` records.

## When NOT to flag

A pnpm project (which blocks build scripts by default) without `dangerouslyAllowAllBuilds`
passes the lifecycle check. An exact-pinned dep, a committed lockfile anywhere up the workspace
chain, a ≥48h cooldown in any supported key/unit, and an `https://` registry all pass. The
pragmas cover deliberate, documented exceptions (e.g. a build that legitimately needs a
lifecycle script).

## Tests

A dedicated suite (`tests/guards/test_js_supply_chain.py`) plus `tests/test_js_harden.py`. Representative:

| Test | What it checks |
|---|---|
| `test_js_clean_hardened_pnpm_passes` | fully-hardened pnpm project → silent |
| `test_js_missing_lockfile_and_no_cooldown` | no lockfile + no cooldown → HIGH + MEDIUM |
| `test_js_lifecycle_npm_without_ignore_scripts` | npm without `ignore-scripts` → HIGH (Shai-Hulud vector) |
| `test_js_cooldown_too_short_pnpm` | cooldown < 48h → LOW |
| `test_js_unpinned_and_packagemanager` | floating specs + no `packageManager` → MEDIUM + LOW |
| `test_js_packagemanager_vulnerable_pnpm_floor` | pin below the CVE floor (pnpm < 11.9.0) → HIGH; at-floor + bare-major → silent |
| `test_js_insecure_registry_and_exotic` | `http://` registry + exotic-subdeps off → HIGH + MEDIUM |
| `test_js_workspace_subpackage_inherits_parent_config` | sub-package inherits root lockfile/.npmrc → silent |
| `test_js_pragma_suppresses` | allow-pragmas → silent |
| `test_js_not_applicable_without_js` | `applies()` False without JS |
| `test_js_insecure_transport_http_fires_high` | `http://` dep URL → new HIGH `insecure-dependency-transport`, not double-counted into `unpinned` |
| `test_js_insecure_transport_ftp_fires_high` | same for `ftp://` |
| `test_js_https_dependency_still_fires_generic_unpinned` | regression: `https://` dep URL still fires the old `unpinned` MEDIUM, unchanged |
| `test_js_git_plus_http_dependency_not_insecure_transport` | adversarial: `git+http://...` is the existing git-protocol exotic-source case, not the new rule |
| `test_js_insecure_transport_pragma_suppresses` | `allow-exotic-subdeps` pragma also suppresses the new rule |
| `test_js_insecure_transport_independent_of_http_registry` | adversarial: per-dependency URL check and the `.npmrc` registry-level check fire independently |
| `test_js_lockfile_drift_fires_v2_shape` | dep declared, absent from `lockfileVersion` 2/3's `packages` map → MEDIUM |
| `test_js_lockfile_drift_fires_v1_shape` | same, `lockfileVersion` 1's `dependencies` map |
| `test_js_lockfile_drift_recognizes_scoped_and_nested_packages` | `@scope/pkg` + a hoisted-nested dep both resolve correctly → silent |
| `test_js_lockfile_drift_silent_when_all_deps_present` | every declared dep IS in the lockfile → silent |
| `test_js_lockfile_drift_silent_with_no_lockfile` | no lockfile at all → this rule stays silent (that's `lockfile-missing`'s job) |
| `test_js_lockfile_drift_silent_on_yarn_pnpm_lockfiles` | `pnpm-lock.yaml` present → silent (unparsed format, by design) |
| `test_js_lockfile_drift_fires_when_packagemanager_pins_npm_despite_pnpm_lock` / `..._yarn_lock` | explicit `packageManager: "npm@..."` pin → fires despite a coexisting non-npm lockfile |
| `test_js_lockfile_drift_silent_when_packagemanager_pins_pnpm_and_pnpm_lock_present` | a pin naming a different tool → keeps the presence-based skip |
| `test_js_lockfile_drift_silent_when_no_packagemanager_field_and_pnpm_lock_present` | no pin at all → keeps the presence-based skip (the real-world flagship-frontend FP shape) |
| `test_js_lockfile_drift_fires_on_npm_pin_with_exotic_version_suffix` | a malformed version suffix still names the tool (`_pm_pin_tool` is unparsed, by design) |
| `test_js_lockfile_drift_pragma_suppresses` | `allow-lockfile-manifest-drift` in `.npmrc` → silent |

## Known bypasses

- **Config indirection** — cooldown/registry set via env var (`NPM_CONFIG_*`) or a nested
  `.npmrc` the ancestor walk doesn't reach.
- **Transitive lifecycle scripts under pnpm allowlist** — a genuinely-needed `onlyBuiltDependencies`
  entry is trusted; the guard doesn't audit *what* those build scripts do.
- **Lockfile present but stale (npm-format lockfiles only)** — `lockfile-manifest-drift` (added
  2026-08) closes the manifest-vs-lockfile *presence* gap for `package-lock.json`/
  `npm-shrinkwrap.json`, but not for `pnpm-lock.yaml`/`yarn.lock` (unparsed, stdlib-only design),
  and it checks *whether a declared dependency resolves at all*, not that its *version* matches
  what the manifest's range would actually re-resolve to, and not tamper-freedom (integrity
  hashes are `_check_lockfile`'s presence check, not this rule's content-comparison job).
- **Presence-vs-recency (closed 2026-08-27):** an active, drifting `package-lock.json`
  coexisting with an abandoned pnpm/yarn/bun lockfile used to stay silent even with
  `packageManager` explicitly pinned to npm — the presence check ran before the pin was ever
  consulted. `packageManager` is now treated as AUTHORITATIVE: an explicit npm pin (`_pm_pin_tool`,
  a bare split on the first `@` — unparsed format, by design, so an exotic/malformed version
  suffix still names the tool) runs the drift check regardless of coexisting lockfiles; anything
  else, or no pin at all, keeps the presence-based skip. One residual worth naming: a manifest
  pinning `npm` while the team actually builds with yarn (an inconsistent/stale pin) now fires —
  arguably a misconfiguration worth surfacing on its own, not a false positive to suppress.
  **Workspace monorepos (closed 2026-08-29):** `packageManager` conventionally lives
  only in a workspace's ROOT manifest, while the manifests actually scanned for drift are the
  sub-packages that declare dependencies — the pin lookup (`_pm_pin_tool_chain`) walks the same
  workspace `chain` `is_pnpm` already does, so a sub-package with no pin of its own inherits the
  nearest ancestor's, and a root-level npm pin reaches its own workspace's drift check too.
- **`_is_floating` unknowns** — unusual range syntaxes default to "pinned" to avoid FPs.

## What this guard does NOT prove

That the dependency tree is free of malicious code — it verifies *hardening posture*
(lockfile, script-blocking, cooldown, pinning, registry, trust policy), not the contents of any
package. It is the structural seatbelt, not a malware scanner (that's `node-audit` /
`npm audit signatures`).

# Citations

[1] agentsec checklist item `5-lockfile-committed` (§5)
[2] agentsec checklist item `5-lockfile-manifest-drift` (§5)
[3] OWASP-LLM:LLM03
[4] OWASP:A06
[5] SOC2:CC8.1
