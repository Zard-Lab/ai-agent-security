---
type: Guard
title: "path-traversal"
description: "No path traversal in file serving / opening."
timestamp: "2026-06-16T15:05:58+08:00"
guard_id: "path-traversal"
checklist_section: ["3a", "4"]
standards: ["OWASP-LLM:LLM02", "OWASP:A01"]
---

# No path traversal in file serving / opening

Flags a file-serving sink (`send_file`/`send_from_directory`/`FileResponse`) or `open()` whose path
is built from a variable (concat / f-string / `os.path.join` with a variable) and carries no
safety marker. Closes (as a guard) checklist item `3a-path-traversal-file-serving`.

## The threat

A path assembled from user input without a base-directory check lets `../../etc/passwd` escape the
intended folder — arbitrary file read when serving, arbitrary file *write/plant* (`shell.php`) when
opening for write. The fix is to resolve the final path and assert containment:
`p = Path(base).joinpath(name).resolve(); assert p.is_relative_to(base)`, or a vetted `safe_join` /
`secure_filename`. CWE-22 / CWE-98, OWASP A01 (Broken Access Control).

## Exploitability rationale

HIGH. Direct file disclosure (creds, source, `.env`) or write-to-RCE, reachable through a normal
request parameter.

## When NOT to flag (and the pragma)

- **Safety marker on the line** — `.resolve()`, `is_relative_to`, `safe_join`, `secure_filename`,
  `realpath` → treated as guarded, silent.
- **Static path** — `open("config.toml")` → silent.
- **Bare `open(var)`** — a lone variable (no concat/join/f-string) is *not* flagged (too common, often
  a trusted handle); only assembled paths fire. Serving sinks are stricter (any non-literal fires).
- An audited case → `# security: allow-path-traversal`.

## Known bypasses (honest limits)

- The containment check is recognized only when its marker is on the **same line** as the sink; a
  resolve/assert split across lines reads as unguarded (false positive — pragma covers it).
- A path laundered through an intermediate variable before the sink can evade the concat/join
  heuristic (false negative).

## What this guard does NOT prove

It flags an assembled path at a file sink; it does not prove the input is attacker-controlled nor that
a multi-line containment check is absent. Absence of a finding ≠ no traversal.

## Wave 5 extensions (2026-06-28)

Three new rules extend the guard without changing its id or class name.

### Rule A — MEDUSA-OUTPUT-PATH-001: LLM output used as file path (CRITICAL)

A two-pass **per-function** scan. Pass 1 collects variables assigned from LLM call results —
LLM-specific verbs only: `.invoke`/`.ainvoke`/`.run_sync`; `.run`/`.arun`/`.generate`/
`.complete` only on an LLM-shaped receiver (`llm`/`agent`/`chain`/`model`/`client`/`graph`),
so ORM/SDK `.create()` is excluded; plus `chat.completions.create` / `.messages.create` —
recording the assignment line. Pass 2 checks whether those variables (or their `.content` /
`.text` / `["content"]` proxies) appear inside file-sink calls (`open`, `send_file`,
`send_from_directory`, `FileResponse`, `Path`, and — widened for destructive/file-mutation sinks —
`shutil.copy`/`copy2`/`copytree`/`move`/`rmtree` and `os.remove`/`unlink`/`rmdir`/`rename`)
**within the same function** (no column-0 line between the assignment and the sink — so a
`response` LLM var in one function and an unrelated `open(response)` in another do not associate).
CRITICAL because the model output is attacker-controllable via prompt injection; the widened sink
list means the same trust failure now also reaches an overwrite-or-delete outcome, not just a read.

Rule id: `path-traversal/llm-output-as-path`

### Rule B — load_prompt: NOT owned by this guard

`load_prompt()` / `load_prompt_from_config()` traversal (CVE-2026-34070) is owned by the
**dedicated `langchain-load-prompt-traversal` guard**, which is more precise (it exempts
`settings.`/`config.` attrs, `Path(...)`, literal `os.path.join`, and has a multi-line
containment look-back). An earlier draft of this PR added a duplicate `langchain-load-prompt`
rule here; it was dropped to avoid double-firing — defer entirely to the dedicated guard.

### Rule C — Path() constructor with dynamic arg (MEDIUM)

`Path(f"{base}/{name}")` / `Path(a + b)` assembles a path via string interpolation. MEDIUM
(not HIGH): constructing a `Path` is one step removed from an actual file operation, and the
idiomatic `Path(base) / name` (the `/` operator) is NOT matched. `__file__`-based calls, lines
with a safety marker, and **`settings.`/`config.`/`conf.`/`cfg.` interpolations** (app-internal
config assembly, not request-derived) are exempt.

Rule id: `path-traversal/path-constructor`

### Shared suppression

The new rules respect the existing `# security: allow-path-traversal` pragma and the `_SAFE`
marker set (`.resolve()`, `is_relative_to`, `safe_join`, `secure_filename`, `realpath`,
`werkzeug.utils`).

# Citations

[1] agentsec checklist item `3a-path-constructor-dynamic` (§3a)
[2] agentsec checklist item `3a-path-traversal-file-serving` (§3a)
[3] agentsec checklist item `4-llm-output-not-used-as-path` (§4)
[4] OWASP-LLM:LLM02
[5] OWASP:A01
