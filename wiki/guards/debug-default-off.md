---
type: Guard
title: "debug-default-off"
description: "DEBUG defaults to False."
timestamp: "2026-06-16T13:56:15+08:00"
guard_id: "debug-default-off"
checklist_section: ["6a"]
standards: ["OWASP:A05"]
---

# DEBUG defaults to False

Flags a hardcoded `debug = True` (assignment, `FastAPI(debug=True)`, or a settings-class default).
Closes checklist item `6a-debug-false-default`.

## The threat

`DEBUG = True` in production turns error responses into detailed stack traces exposing file paths,
configuration, and code structure — reconnaissance gold, and in some frameworks an interactive
debugger that is direct remote code execution (the classic Werkzeug/Flask debug-pin case). The
fail-safe posture is DEBUG off by default, switched on only by an explicit dev-only env toggle.
OWASP A05 (Security Misconfiguration).

## Exploitability rationale

Any unhandled error on a public endpoint leaks internals to the attacker with zero effort; a debug
console escalates to RCE. HIGH: trivially reachable (trigger any error) with high blast radius.

## When NOT to flag (and the pragma)

- **Env-driven** — `DEBUG = os.getenv("DEBUG", "") == "1"` (RHS is not the literal `True`) → silent.
- **`DEBUG = False`** → silent.
- **Commented-out** lines (`# DEBUG = True`) → silent.
- A genuinely intentional case (a local-only script) → suppress that line with
  `# security: allow-debug-true`.

## Known bypasses (honest limits)

- A truthy value other than the literal `True` (`DEBUG = 1`, `DEBUG = "true"`,
  `DEBUG = bool(os.getenv("X"))`) is not matched — the rule keys on a literal `True` RHS to stay
  low-FP.
- `DEBUG` set via a dict/`settings["DEBUG"] = True` or a framework config call is not matched.
- A `DEBUG = True` inside a string literal would be a (rare) false positive — pragma covers it.

## What this guard does NOT prove

It catches a hardcoded debug-on; it does **not** prove DEBUG is off at *runtime* (the value may come
from an env var the scan can't see), nor that other debug-style flags (SQL echo, verbose tracebacks,
profilers) are disabled. Absence of a finding ≠ debug is provably off.

# Citations

[1] agentsec checklist item `6a-debug-false-default` (§6a)
[2] OWASP:A05
