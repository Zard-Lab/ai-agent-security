---
type: Guard
title: "langchain-prompt-template-injection"
description: "LangChain PromptTemplate built from a dynamic template string."
timestamp: "2026-07-03T11:25:43+08:00"
guard_id: "langchain-prompt-template-injection"
checklist_section: ["3a"]
standards: ["OWASP-LLM:LLM01"]
---

# LangChain PromptTemplate built from a dynamic template string

_Author — Marconi, 2026-07-03_

---

## The threat

`PromptTemplate(template=user_supplied)` / `ChatPromptTemplate.from_template(built)`
build a template whose **structure**, not just its filled-in variables, is dynamic.
LangChain's default template format uses Python `str.format()`-style `{variable}`
substitution. If the template *string itself* — not the values later passed in to fill
it — is influenced by an attacker (a config value they control, LLM output fed back
into template construction, a user-editable "custom instructions" field concatenated
into a template), they can:

- inject additional `{...}` placeholders that pull unintended values out of whatever
  kwargs the app happens to pass at render time (`{system_prompt}`, `{api_key}`,
  `{secret}` — any variable name the render call's kwargs dict might contain);
- use Python format-spec attribute/index traversal syntax (`{obj.__class__.__mro__}`,
  `{cfg.__init__.__globals__}`) to walk object internals reachable from whatever
  objects the render call passes as format arguments.

This is CVE-2025-65106's underlying class: attacker-influenced template *structure*,
not template *values*. OWASP-LLM:LLM01 (Prompt Injection). (CVE-2026-40087 is a
*different* LangChain vector — `load_prompt(...)` path traversal — covered by the
separate `langchain-load-prompt-traversal` guard, not this one.)

## Why this guard fits the stack

LLM apps that let a user customize their assistant's behavior ("write your own system
prompt prefix") or that assemble a template from LLM output (a self-improving agent
that revises its own prompts) commonly build the template string dynamically:

```python
template_str = f"Answer using: {user_supplied_instructions}"
prompt = ChatPromptTemplate.from_template(template_str)   # the TEMPLATE is now dynamic
```

The author's intent is usually just to prepend some instructions — but because the
*whole resulting string* becomes the template grammar, any `{...}` the user typed is
now a live substitution point, not literal text.

## Detection design

1. `applies()` gate — `"python" in profile.features and "llm" in profile.features`
   (same gate as `langchain-load-prompt-traversal`).
2. Scans every `.py` file under `python_scan_dirs(root, profile)` (file-wide pragma
   check first, like `mass-assignment`).
3. Per line, matches either call shape:
   - `ChatPromptTemplate.from_template(<arg>)` (`_FROM_TEMPLATE`) — first positional
     argument;
   - `PromptTemplate(...)` (`_PROMPT_TEMPLATE_CTOR`) — the `template=` keyword argument
     if present (`_TEMPLATE_KWARG`), else the first positional argument.
4. `_first_arg()` extracts just the top-level argument text (balanced paren/bracket-
   aware, stops at the first top-level comma), reused from the same pattern
   `langchain-load-prompt-traversal`/`path-traversal` use.
5. `_is_dynamic_template()` classifies the argument:
   - an f-string prefix (`f"..."`/`f'...'`) → dynamic (HIGH confidence — explicit
     Python interpolation syntax);
   - an UPPER_SNAKE module constant name → **not** dynamic (trusted, in-repo);
   - a `settings.`/`config.`/`conf.`/`cfg.` attribute → **not** dynamic (app-internal
     config, mirrors `langchain-load-prompt-traversal`'s `_CONFIG_ATTR` carve-out);
   - a plain string literal with no `+` → **not** dynamic (the safe, common case);
   - anything else (concatenation, a bare variable, a function call, an f-string caught
     by the first rule) → dynamic.
6. Inline opt-out: `# security: allow-prompt-template-injection` anywhere in the file.
7. Severity: `high` (matches `prompt-string-interp`'s tier — direct prompt-injection
   surface). Rule id: `langchain-prompt-template-injection/dynamic-template-string`.
   Standards: `["OWASP-LLM:LLM01"]`.

## When NOT to flag

- A plain string literal template (`"Answer: {question}"`) — the overwhelmingly common,
  safe case.
- A template loaded from an UPPER_SNAKE module constant or a `settings.`/`config.`
  attribute — trusted, app-internal sources.
- `prompt-string-interp`'s territory: values substituted *into* an already-fixed
  template (`prompt.format(question=user_input)`) — this guard only looks at the
  template-construction call itself, never the later `.format()`/`.invoke()` call that
  fills it in.
- An audited case, suppressed with `# security: allow-prompt-template-injection`
  anywhere in the file.

## Tests

| Test | What it checks |
|---|---|
| `test_langchain_prompt_template_injection_fires_on_from_template_fstring` | Positive: `ChatPromptTemplate.from_template(f"...")`-built variable fires HIGH (**verified_by**). |
| `test_langchain_prompt_template_injection_fires_on_prompttemplate_kwarg` | Positive: `PromptTemplate(template=user_template, ...)` also fires. |
| `test_langchain_prompt_template_injection_fires_on_concat` | Positive: string concatenation (`'...' + var`) fires. |
| `test_langchain_prompt_template_injection_silent_on_literal` | FP-bait: a plain string-literal template → silent. |
| `test_langchain_prompt_template_injection_silent_on_module_constant` | FP-bait: an UPPER_SNAKE module constant → silent. |
| `test_langchain_prompt_template_injection_silent_on_config_attr` | FP-bait: a `settings.` attribute → silent. |
| `test_langchain_prompt_template_injection_pragma_silences` | Suppress pragma (file-wide) → silent. |
| `test_langchain_prompt_template_injection_not_applies_without_llm` | `applies()` gate false without `llm`. |
| `test_langchain_prompt_template_injection_not_applies_without_python` | `applies()` gate false without `python`. |

## Known bypasses

- **Multi-line calls**: `PromptTemplate(\n    template=user_template,\n    ...\n)` spread
  across lines is invisible to the single-line regex — the `template=` keyword and its
  value must be on the same line as (or immediately after, on the SAME line) the
  matched text.
- **Indirection**: `t = user_template; prompt = ChatPromptTemplate.from_template(t)`
  — `t` is a bare variable, which IS classified as dynamic (falls through to the
  default `return True`), so this specific indirection is actually still caught. The
  real gap is the opposite direction: a genuinely-safe bare variable holding a literal
  constant (`SAFE = "..."`; `x = SAFE`; `from_template(x)`) is *conservatively* flagged
  even though it's safe — a known false positive, not a false negative, accepted to
  keep the guard simple (no data-flow tracking of variable assignments).
- **`.partial()` / two-stage construction**: a template built via `.partial(...)` after
  initial construction, or assembled through LangChain's `PipelinePromptTemplate`, is
  outside this guard's single-call-site pattern.

## What this guard does NOT prove

A silent guard does not mean the template is safe from injection — it only means no
*textually dynamic* argument was found at the `PromptTemplate(...)`/`.from_template(...)`
call site by this narrow literal/constant/config-attr classification. It does not track
whether a variable classified as "dynamic" (a bare identifier) actually holds
attacker-reachable data — that requires real data-flow analysis, out of scope for a
regex-based static guard. This is a **presence-based, conservative** guard: it may
over-flag safe indirection (see Known bypasses) in exchange for never silently missing
an f-string or concatenation built from tainted input.

# Citations

[1] agentsec checklist item `3a-user-content-sanitized-before-llm` (§3a)
[2] OWASP-LLM:LLM01
