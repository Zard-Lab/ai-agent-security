---
type: Guard
title: "llm-output-to-sink"
description: "LLM output flows into a code/command sink — model-driven RCE."
timestamp: "2026-06-20T12:09:10+08:00"
guard_id: "llm-output-to-sink"
checklist_section: ["3b", "4"]
standards: ["CWE-94", "OWASP-LLM:LLM02", "OWASP-LLM:LLM05", "OWASP:A03"]
---

# LLM output flows into a code/command sink — model-driven RCE

Flags LLM output flowing directly into a code/command execution sink. Closes the new checklist item
`4-llm-output-not-executed`. OWASP-LLM:LLM05 (Insecure Output Handling) / OWASP:A03 / CWE-94.

## Why this guard (the agentic wedge)

Per the director review, agentsec's differentiator is the LLM/agentic layer, and agentic CVEs are the
fastest-growing class (+255% YoY). The defining agentic-era RCE is "the app runs the model's answer."
This is a concrete, detectable *sink*, so it is the right place to start deepening agentic detection
(Phase 4) rather than the FP-prone absence-of-control agentic checks.

## The threat

An app asks the model for something, then executes the answer: `exec(agent.run_sync(prompt))`,
`os.system(llm.invoke(task))`, `eval(model.predict(q))`. Because an attacker can steer the model through
prompt injection (direct or via poisoned RAG content), they control what gets executed — remote code or
command execution. This is insecure output handling at its most severe: the output is not just rendered,
it is run.

## Exploitability rationale

The checklist item is CRITICAL (RCE). The **finding** is HIGH: an LLM call inside a code/command sink is
a very high-confidence bug, but a genuinely sandboxed execution environment is conceivable, so HIGH plus a
pragma rather than an unescapable critical.

## What counts as a hit (and what doesn't)

A line where a code/command sink (`exec`, `eval`, `compile`, `os.system`, `subprocess.run/call/
check_output/Popen`, `commands.getoutput`) contains an **LLM call expression** (`.run_sync(`, `.run(`,
`.invoke(`/`.ainvoke(`, `.predict(`, `.generate(`, `.complete(`, `completions.create(`). It does **not**
fire on: an LLM call with no sink (`reply = agent.run_sync(p)`), a sink with no LLM (`os.system(cmd)`),
or LLM output going into a **safe parse** (`json.loads(model.generate(x))` — parsing is not executing).

## When NOT to flag (and the pragma)

- The model output is parsed / validated / allowlisted, not executed → silent.
- A reviewed, genuinely sandboxed executor → suppress the line with `# security: allow-llm-sink`.

## Known bypasses (honest limits)

- **Renamed client.** An LLM client wrapped behind a custom method name is not recognized.
- **Tool-layer execution.** A model that triggers a registered tool which then execs is not modeled here;
  that is the broader agent-tool-authorization problem (separate, mostly manual).

## Additional patterns (ext6)

Both new rules are gated by an LLM **call** somewhere in the file (`_LLM_CALL_ANYWHERE`, narrowed to
real call/client forms — bare `.run(`/`.generate(`/`.complete(` and the `openai.`/`anthropic.` import
substrings are NOT accepted, so a test runner or a generic generator does not flip the gate).
Test/fixture paths are excluded via `is_nonproduct_path`; the guard's own message/docstring examples
are blanked (`_blank_string_contents` + `strip_python_strings`) so it does not self-fire.

- **`eval-variable-mediated`** (HIGH, rule `llm-output-to-sink/eval-variable-mediated`): the two-line
  RCE pattern `response = llm.invoke(prompt)` then `eval(response)`. Fires when the **builtin**
  `eval()`/`exec()` is called with a bare variable. The regex is anchored (`(?<![.\w])`) so a method
  call like `df.eval(...)` (pandas/numexpr) does NOT fire; string literals and `True/False/None` are
  excluded.

- **`sql-execute-variable`** (HIGH, rule `llm-output-to-sink/sql-execute-variable`): a DB `execute()`
  whose argument is **attacker-influenceable** — either (a) a dynamically-built SQL string (an
  f-string, `+`-concatenation, or `.format()`), or (b) a bare variable that this file assigns from an
  LLM call (`q = llm.invoke(...); cursor.execute(q)`). It deliberately does NOT fire on a literal SQL
  string, a parameterized call (`execute(QUERY, params)`), or a SQLAlchemy Core construct
  (`session.execute(select(...))` / `db.execute(stmt)`) — those dominate real DB code and are safe.
  (`%`-formatting is not treated as dynamic-build, since `%s` is a parameter placeholder, not
  interpolation — a documented FN.)

These precision conditions replaced an earlier draft that fired on **any** non-literal `execute()`
arg in an LLM-using file; a synthetic check showed that draft firing HIGH on
`session.execute(select(...))` and `cursor.execute(QUERY, params)` (the standard safe idioms), so the
rule now requires dynamic-build or proven LLM-derivation.

## What this guard does NOT prove

It proves the call-form of model-output-to-sink on one line; it does not trace dataflow, tool routing, or
whether the model is actually attacker-influenced. Absence of a finding ≠ output handling is safe (the
sibling items `4-llm-output-sanitized` / `4-llm-output-truncation` cover the client-facing side). It is
the fast, dep-free, high-precision static check for the most dangerous LLM output-handling mistake.

# Citations

[1] agentsec checklist item `4-llm-output-not-executed` (§4)
[2] agentsec checklist item `4-llm-output-sanitized` (§4)
[3] agentsec checklist item `3b-llm-output-sanitized` (§3b) — this guard also closes the
    single-endpoint case (no full lethal-trifecta needed) that `lethal-trifecta` alone missed
[4] CWE-94
[5] OWASP-LLM:LLM02
[6] OWASP-LLM:LLM05
[7] OWASP:A03
