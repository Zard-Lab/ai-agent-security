---
type: Guard
title: "path-prefix-authz-bypass"
description: "Path containment checked with a naive startswith() (sibling-directory bypass)."
timestamp: "2026-07-03T11:12:37+08:00"
guard_id: "path-prefix-authz-bypass"
checklist_section: ["3a"]
standards: ["OWASP:A01"]
---

# Path containment checked with a naive startswith() (sibling-directory bypass)

_Author — Marconi, 2026-07-03_

---

## The threat

`requested_path.startswith(allowed_root)` looks like a directory-containment check but
provides no real boundary: `"/data/users"` is a genuine string prefix of
`"/data/users_evil"` even though the second path is a **sibling directory**, not a
descendant of the first. An attacker who controls the requested path chooses a sibling
directory name that merely shares the prefix character-for-character and the check
passes — the app then serves, deletes, or otherwise acts on a file the author believed
was contained to a safe root. CWE-22 (Path Traversal) / OWASP:A01 (Broken Access
Control) — this is a *containment* bug, not a missing-check bug, so it's a different
failure mode than the guards that fire on the *absence* of any safety marker.

## Why this guard fits the stack

FastAPI + Postgres/RLS apps that build a multi-tenant file store, plugin sandbox, or
export directory commonly reach for `startswith()` as the first (and, without review,
only) containment check because it reads as obviously correct:

```python
def serve(requested_path, allowed_root):
    if requested_path.startswith(allowed_root):   # looks safe, isn't
        return open(requested_path).read()
    raise PermissionError
```

`allowed_root = "/data/tenant-42"` also matches `/data/tenant-420-shared` — a name
collision that's easy to construct deliberately (register a tenant/plugin/username that
happens to extend an existing prefix) and easy to miss in review, because the code
*looks* like it has a containment check.

## Detection design

1. `applies()` gate — `"python" in profile.features`.
2. Scans every `.py` file under `python_scan_dirs(root, profile)`.
3. Per line (after a file-wide pragma check — see below), fires when ALL of:
   - the line contains a boolean-gate keyword: `if`/`elif`/`while`/`assert`
     (`_GATE_KEYWORD`) — a bare `x.startswith(y)` expression statement (e.g. logged, or
     assigned to a variable used elsewhere) is not itself a security decision;
   - a `<receiver>.startswith(<arg>)` call (`_STARTSWITH`, captures both operands);
   - the receiver looks path-shaped: `path`, `filepath`, `requested`, `target`,
     `resolved`, `dir`, or a name ending in one of those (`_PATH_RECEIVER`);
   - the argument looks like a trusted-root/allowlist boundary: `allowed`, `base`,
     `root`, `safe`, or a name ending in `_dir`/`_root`/`_path`/`_prefix`
     (`_ROOT_ARG`).
4. Inline opt-out: `# security: allow-path-prefix-authz-bypass` anywhere in the file
   (file-wide, matching `mass-assignment`'s and `langchain-serialization`'s convention
   — not line-scoped, since the containment decision and the pragma-worthy review often
   sit a few lines apart).
5. Severity: `medium` (a real containment gap, but exploitation needs the attacker to
   also control or predict the sibling path — one notch below `path-traversal`'s HIGH,
   which fires on *no* containment marker at all). Rule id:
   `path-prefix-authz-bypass/naive-startswith-containment`. Standards:
   `["OWASP:A01", "CWE-22"]`.

## When NOT to flag

- A bare `startswith()` call not used as a boolean gate (logging, a non-branching
  expression) — not a security decision.
- `startswith()` on a receiver that isn't path-shaped (a URL scheme check, a string
  prefix unrelated to file paths).
- `startswith()` gated on an argument that isn't root/allowlist-shaped (an arbitrary
  string prefix check with no security framing).
- The boundary-aware fix itself: `Path(...).is_relative_to(...)` /
  `os.path.commonpath(...)` never call `startswith()`, and the `os.sep`-boundary-aware
  `startswith(root + os.sep)` / `startswith(root + "/")` form is explicitly suppressed
  (`_BOUNDARY_SUFFIX`) — appending a separator is exactly what gives the prefix check a
  path-segment boundary, so it is not the vulnerable shape.
- An audited case, suppressed with `# security: allow-path-prefix-authz-bypass`
  anywhere in the file.

## Tests

| Test | What it checks |
|---|---|
| `test_path_prefix_authz_bypass_fires_on_if_startswith` | Positive: `if requested_path.startswith(allowed_root):` fires medium (**verified_by**). |
| `test_path_prefix_authz_bypass_fires_on_assert` | Positive: the `assert` gate form also fires. |
| `test_path_prefix_authz_bypass_silent_on_bare_call` | FP-bait: a non-branching `startswith()` (logged, not gated) → silent. |
| `test_path_prefix_authz_bypass_silent_on_non_path_receiver` | FP-bait: `startswith()` on a non-path receiver (URL scheme) → silent. |
| `test_path_prefix_authz_bypass_silent_on_non_root_arg` | FP-bait: `startswith()` gated on a non-root-shaped argument → silent. |
| `test_path_prefix_authz_bypass_pragma_silences` | Suppress pragma (file-wide) → silent. |
| `test_path_prefix_authz_bypass_not_applies_without_python` | `applies()` gate false without `python`. |
| `test_path_prefix_authz_bypass_silent_with_is_relative_to` | FP-bait: the correct fix pattern (`is_relative_to`) never calls `startswith()` → silent. |

## Known bypasses

- **Naming-vocabulary evasion**: the receiver/argument name heuristics
  (`_PATH_RECEIVER`/`_ROOT_ARG`) are the whole gate — a naive containment check using
  unconventionally-named variables (`p.startswith(r)`) slips past entirely. This is a
  deliberate precision/recall trade-off (the same one `bola`/`privileged-field-
  assignment` make with their vocabulary-based auth-signal checks): narrow, readable
  names keep the false-positive rate low at the cost of missing obfuscated or
  unconventionally-styled code.
- **Multi-line conditions**: `if (\n    requested_path.startswith(allowed_root)\n):`
  spread across lines is invisible to the single-line regex — a determined (or just
  black-formatted) codebase can defeat detection by line-wrapping.
- **Indirect containment helper**: a project-defined `is_within(requested, allowed)`
  helper that internally uses `startswith()` isn't textually visible at the call site —
  the guard only sees the direct `.startswith(` call, not through function-call
  resolution.
- **Tuple argument / wrapped receiver**: `_STARTSWITH`'s operand classes exclude
  parentheses, so the multi-root `requested_path.startswith((root_a, root_b))` tuple
  form and a wrapped receiver `os.path.normpath(requested_path).startswith(base_dir)`
  are missed. Widening the arg class to tolerate one level of nesting is a natural
  follow-up if these shapes show up in the field (deferred from the #303 review).
- **Compound receiver names without a separator**: `_PATH_RECEIVER` needs the path
  keyword at a `.`/`_` boundary or the start of the name, so `dirpath` (the `os.walk()`
  loop-variable idiom) and `pathname` don't match (deferred from the #303 review).

## What this guard does NOT prove

A silent guard does not mean path containment is correct — it only means no *naive
startswith-shaped* containment check was found by this narrow vocabulary/gate pattern.
It says nothing about `os.path.commonpath`/`is_relative_to` usage being *correct*
either (e.g. comparing an unresolved, non-normalized path still permits `../` traversal
even with the "right" API) — this guard targets one specific, common anti-pattern, not
path-containment correctness as a whole.

# Citations

[1] agentsec checklist item `3a-path-traversal-file-serving` (§3a)
[2] OWASP:A01
