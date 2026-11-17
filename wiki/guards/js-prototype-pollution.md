---
type: Guard
title: "js-prototype-pollution"
description: "Prototype-polluting property assignment."
timestamp: "2026-07-11T20:10:00+08:00"
guard_id: "js-prototype-pollution"
checklist_section: ["6a"]
standards: ["OWASP:A08"]
---

# Prototype-polluting property assignment

_Marconi (research-cycle: codeql-security-queries) — 2026-07-11_

---

## The threat

A computed property assignment `obj[key] = value` where `key` is derived from request input lets
an attacker pass `key = "__proto__"` (or `"constructor"`/`"prototype"`) and mutate
`Object.prototype` itself — a single write that every object in the process inherits, not just the
one being assigned to. The same risk applies to a recursive merge/extend helper (`_.merge`,
`Object.assign`, `deepmerge`) fed an attacker-controlled object, typically `JSON.parse(req.body)`:
the merge walks nested keys and can reach `__proto__` the same way.

Impact depends entirely on what the polluted property later gates — an `isAdmin` flag read
elsewhere, a template-engine option, a shell/exec option — ranging from privilege escalation to
remote code execution. CWE-1321 (prototype pollution), CWE-915 (improperly controlled modification
of object prototype attributes), CWE-471 (modification of assumed-immutable data). OWASP A08:2021
(Software and Data Integrity Failures).

## Why this guard fits the stack

Zero prior coverage — confirmed via `grep -rli "prototype" agentsec/guards/` returning nothing
before this guard. **Triple-corroborated** in the 2026-07-11 research pass (see
`guard-candidates.md`'s "Mass discovery pass" section): independently flagged by (1) Strix's
vulnerability taxonomy (`skills/vulnerabilities/prototype_pollution.md`), (2) CodeQL's own 3
dedicated queries under `javascript/ql/src/Security/CWE-915/`
(`PrototypePollutingAssignment`/`PrototypePollutingFunction`/`PrototypePollutingMergeCall`), and (3)
keyword-clustering 1,314 real npm critical-severity GHSA advisories pulled via
`gh api "advisories?ecosystem=npm&severity=critical"` — prototype pollution accounts for 169 of
them (12%), the 3rd-largest cluster after supply-chain and command-injection/RCE, both already
covered elsewhere.

## Detection design

1. `applies()` gates on `"javascript" in profile.features or "typescript" in profile.features`
   — matching every server-side JS sibling (`js_ssrf`). Every sink this guard looks for is
   server-side (`req.body`/`req.query`/`req.params`/`JSON.parse`), so gating on the React/Vite-only
   `frontend` feature left it dead on a backend-only Node/Express repo — its exact target (PR #395 C1).
2. Scans `.js`/`.jsx`/`.ts`/`.tsx` files via `iter_files`, skipping test/fixture paths
   (`is_nonproduct_path`).
3. Two independent sink patterns, both verified against the real CodeQL source
   (`PrototypePollutingAssignmentCustomizations.qll`, not just its paraphrase):
   - `js-prototype-pollution/tainted-key-assign` — `obj[<computed key>] = value` where the key
     expression textually references `req.`/`request.` (e.g. `obj[req.body.key] = ...`).
   - `js-prototype-pollution/tainted-merge` — a call to `merge`/`extend`/`deepmerge`/`assign`
     (bare or `_.`-prefixed) whose arguments reference `JSON.parse(` or
     `req.`/`request.body`/`.query`/`.params`.
4. Both check a ±3-line window (same pattern as `jsx-href-scheme`'s `_SAFE_WINDOW`) for a
   `__proto__`/`constructor`/`prototype` denylist mention or `hasOwnProperty` — if present, silent.
5. Severity HIGH for both rules (`standards=["OWASP:A08", "CWE-1321"]`). Suppress with
   `// security: allow-proto-pollution` anywhere in the file.

## When NOT to flag

- A static string/numeric key (`obj['fixedKey'] = value`) — not computed, not attacker-influenced.
- A computed key that isn't request-derived (e.g. `obj[localVar] = value` where `localVar` comes
  from a loop counter or a hardcoded array) — deliberately narrow to request-derived keys only, to
  avoid flagging every dynamic-key assignment in a codebase.
- A denylist check or `hasOwnProperty` guard within ±3 lines of the sink.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_tainted_key_assignment` | `obj[req.body.key] = req.body.value` → HIGH, `tainted-key-assign` |
| `test_flags_tainted_merge_call` | `_.merge(target, JSON.parse(req.body.data))` → HIGH, `tainted-merge` |
| `test_silent_when_denylist_check_nearby` | `__proto__`/`constructor`/`prototype` denylist present → silent |
| `test_silent_on_static_key_assignment` | `obj['fixedKey'] = value` → silent |
| `test_pragma_suppresses` | `// security: allow-proto-pollution` → silent |
| `test_not_applicable_without_frontend` | `applies()` returns False without `frontend` |

## Known bypasses (honest limits)

- **No interprocedural tracking** (call-site/line-scoped only, same limitation class as every other
  regex-based guard in this codebase): `const key = req.body.key; obj[key] = req.body.value;` on
  separate lines is NOT flagged — the computed-key regex only recognizes the taint reference
  written directly inside the brackets, not a variable assigned from it earlier. Verified live
  during this guard's adversarial self-test — this is an accepted, documented gap, not an
  unreviewed one.
- A merge call fed a variable that was populated from `req.*` several lines earlier (rather than
  inline in the same call) is not flagged for the same reason.
- Non-literal denylist checks (a shared constant array imported from another file, e.g.
  `import { DANGEROUS_KEYS } from './constants'`) won't be recognized as a sanitizer — the window
  check only looks for the literal words `__proto__`/`constructor`/`prototype`/`hasOwnProperty`.

**Known limitation (fixed, review #395 Low finding):** the sanitizer's string-literal match
previously accepted only `'` / `"` quotes, so a denylist check written as a backtick template
literal (`` [`__proto__`, `constructor`, `prototype`] ``) was not recognized — the quote class
now includes backticks.

## What this guard does NOT prove

It flags a plausible sink reachable from request input in the same statement; it does not prove the
key is actually attacker-controlled at runtime (framework-level input validation elsewhere could
already constrain it), nor does it prove the *absence* of prototype pollution — a vulnerability
reached via a longer call chain, a third-party library's own internals, or cross-file data flow is
invisible to a single-file, single-line heuristic.

# Citations

[1] agentsec checklist item `6a-no-prototype-pollution` (§6a)
[2] OWASP:A08
