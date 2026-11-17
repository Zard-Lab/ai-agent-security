---
type: Guard
title: "ssti"
description: "No server-side template injection."
timestamp: "2026-06-16T15:05:58+08:00"
guard_id: "ssti"
checklist_section: ["3b"]
standards: ["OWASP:A03"]
---

# No server-side template injection

Flags `render_template_string()` with a non-literal argument, a Jinja `Environment(autoescape=
False)`, and (2026-07-03) a raw `Template(...)`/`.from_string(...)` constructor given a
non-literal template string. Closes checklist item `3b-ssti`.

## The threat

Rendering user/model input *as a template* (not as template data) hands it to the engine's evaluator:
`render_template_string("Hi " + name)` with `name = "{{7*7}}"` evaluates server-side, and on Jinja
escalates to RCE via the object graph (`{{''.__class__.__mro__[1].__subclasses__()...}}`).
`autoescape=False` removes the output-escaping backstop. The fix is to render a fixed template file
and pass input as *data* (`render_template("p.html", name=user)`). CWE-94 (Injection), OWASP A03.

A second, distinct shape reaches the same evaluator without ever calling
`render_template_string()`: constructing a Jinja2 `Template` object directly from a non-literal
string (`Template(user_template).render()`), or building one via `Environment().from_string(...)`.
Any code that lets a caller supply and render an arbitrary template — not just a Flask app calling
`render_template_string` — has the same RCE exposure. CVE-2024-41950 (Haystack) was this exact shape:
components let a caller create and render a Jinja2 template directly, with no Flask wrapper in sight,
so the original absence-only check (which required the specific `render_template_string(` name)
missed it entirely.

## Exploitability rationale

HIGH. SSTI on Jinja is an RCE primitive; reachable wherever user input feeds the template string.
Scored high (not critical) because the worst case depends on the engine and sandboxing, and the
common case is data disclosure / reflected injection.

## When NOT to flag (and the pragma)

- **Constant template** — `render_template_string("<p>static</p>")` / `Template("Hi {{ name }}")`
  (a single literal) → silent.
- **Template data** — `render_template("p.html", name=user)` (the `_string` variant is what's
  dangerous) → not matched.
- An audited case → `# security: allow-ssti`.

## Known bypasses (honest limits)

- A template string built on a previous line then passed as a bare variable *does* fire (no-literal
  rule); a constant returned by a helper is a rare false positive (pragma covers it).
- **`Template`/`from_string`-scoped, not fully general**: templating libraries other than Jinja2 that
  don't use the names `Template(...)` or `.from_string(...)` are not matched — the rule targets the
  two highest-signal Jinja2-specific construction sites, not every possible templating API.
- A `Template(` call aliased through a re-export (`from mymodule import Template as T; T(dynamic)`)
  is not matched — the regex requires the literal identifier `Template`.

## What this guard does NOT prove

It flags the dynamic-template sink, disabled autoescape, or a raw template constructed from a
non-literal string; it does not prove the input is attacker-controlled, nor cover every templating
library. Absence of a finding ≠ no SSTI.

# Citations

[1] agentsec checklist item `3b-ssti` (§3b)
[2] OWASP:A03
