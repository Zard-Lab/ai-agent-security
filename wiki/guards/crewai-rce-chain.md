---
type: Guard
title: "crewai-rce-chain"
description: "CrewAI tool usage matches the 2026-04-02 exploit chain (unsafe code exec, path traversal, or SSRF)."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "crewai-rce-chain"
checklist_section: ["4"]
standards: ["CWE-94", "CWE-22", "CWE-918", "OWASP-ASI:ASI04", "OWASP:A10"]
---

# CrewAI tool usage matches the 2026-04-02 exploit chain

_Author — 2026-09-26_

---

## The threat

ThaiCERT and CERT/CC (VU#221883) disclosed a chain through CrewAI 0.x that turns an untrusted
prompt into host remote code execution, combining tool-level primitives: `CodeInterpreterTool`
run with `unsafe_mode=True` executes LLM-generated code directly on the host with no Docker
sandbox at all (CVE-2026-2275); `JSONSearchTool`/`JSONLoader` given a caller/LLM-influenced file
path can read arbitrary host files via path traversal (CVE-2026-2285); `RagTool`/
`WebsiteSearchTool` given a caller/LLM-influenced URL is SSRF with no allow-list (CVE-2026-2286).
Sourced from `agent-audit-kit`'s `crewai_rce_chain.py` (AAK-CREWAI-CHAIN-2026-04-001), verified
against the real repo source.

**Deliberately not ported: the chain's 4th component (CVE-2026-2287)** — `CodeInterpreterTool`'s
sandbox silently falling back to unsandboxed host execution when the Docker daemon is
unreachable, with no liveness check. That is a defect inside the `crewai_tools` package's own
implementation, not a pattern an application's source code exhibits; no source-level rule can
detect "did the library's internal Docker-availability check run." Closing that gap is a
version-floor entry (a minimum patched `crewai`/`crewai-tools` version), added only after
independently verifying the CVE-to-fixed-version mapping against real GitHub Advisory/PyPI data —
tracked as a separate, not-yet-done task rather than fabricated here.

## Why it's often introduced

`unsafe_mode=True` is documented by CrewAI itself as a way to skip Docker when it's inconvenient
in a dev environment, and that convenience choice easily survives into production. The
JSON/website tools are built to take whatever path or URL an agent decides is relevant to a
task — passing that value straight from an LLM's own output, with no validation, is the path of
least resistance when wiring up a new tool quickly.

## Detection design

1. `applies()` returns `True` when the profile has both `python` and `llm` features.
   **Dependency note:** on a CrewAI-only app (`crewai` / `crewai-tools` in the requirements, no
   other LLM SDK), the `llm` feature is only set once `agentsec/detect.py` recognises `crewai` and
   `crewai-tools` as LLM distributions and `crewai` as an LLM import. That detect change ships
   separately (branch `fix/detect-crewai-llm-feature`), so until it lands `applies()` is False on
   such an app and the guard is never selected, even though `run()` called directly finds the
   `CodeInterpreterTool(unsafe_mode=True)` call. This guard does not depend on it in code.
2. `safe_ast_parse` resolves real `ast.Call` nodes for three known class names — a structural
   check, not a substring match, so `CodeInterpreterTool(` is only counted when it is an actual
   call expression.
3. **unsafe-code-interpreter** (CRITICAL): `CodeInterpreterTool(...)` where the `unsafe_mode`
   keyword argument is the literal `True` (or the string `"True"`).
4. **json-tool-path-traversal** (HIGH): `JSONSearchTool(...)`/`JSONLoader(...)` where at least one
   positional or keyword argument is neither a literal nor a TRUSTED configuration value (below) —
   the path is not fixed and comes from somewhere that can carry caller/LLM data.
5. **rag-tool-dynamic-url-ssrf** (HIGH): `RagTool(...)`/`WebsiteSearchTool(...)` where at least one
   argument is similarly untrusted — the URL is not fixed.

   **Trusted arguments** (do not count as dynamic): string/number/bool literals; a module-level
   ALL_CAPS constant (`BASE_DIR`, or `__file__`); an attribute read off a module-level
   `settings`/`config`/`cfg`/`conf` object; and a pure path/string build over those
   (`os.path.join`, `Path(...) / "x"`, `.joinpath`, an f-string, `+`/`%`, a list/dict of them). A
   function parameter (including one that shadows `settings`), a local, a lower-case module
   variable, or any other call stays untrusted.
6. Suppress with a `# security: allow-crewai-rce-chain` comment anywhere in the file, which silences
   the file (a string literal or docstring quoting the phrase does not count, #424).

## When NOT to flag

- `CodeInterpreterTool()` with no `unsafe_mode` argument, or `unsafe_mode=False` — the
  default/explicit sandboxed mode.
- `JSONSearchTool`/`JSONLoader`/`RagTool`/`WebsiteSearchTool` instantiated with only literal
  string/number/bool arguments, or no arguments at all.
- The same tools configured only from module constants and settings reads
  (`os.path.join(BASE_DIR, 'catalog.json')`, `RagTool(website=settings.DOCS_URL)`).

## Tests

| Test | What it checks |
|---|---|
| `test_unsafe_mode_true_fires_critical` / `test_default_code_interpreter_is_safe` / `test_unsafe_mode_false_is_safe` | `unsafe_mode=True` vs. default vs. explicit `False` |
| `test_json_search_tool_dynamic_path_fires_high` / `test_json_loader_dynamic_path_fires_high` | Dynamic-path variants both fire |
| `test_json_search_tool_static_path_is_safe` / `test_json_search_tool_no_args_is_safe` | A literal path, and no args at all, stay silent |
| `test_rag_tool_dynamic_url_fires_high` / `test_website_search_tool_dynamic_url_fires_high` | Dynamic-URL variants both fire |
| `test_rag_tool_static_url_is_safe` | A literal URL stays silent |
| `test_module_constant_path_and_settings_url_are_safe` | FP-bait: module constant / settings reads configure the tools |
| `test_parameter_local_and_shadowed_settings_still_fire` | Still fires: parameters, locals and a shadowed `settings` stay dynamic |
| `test_pragma_suppresses_all_findings` | Inline pragma silences every rule |
| `test_crewai_rce_chain_pragma_quoted_in_a_string_does_not_suppress` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_applies_requires_python_and_llm` | `applies()` requires both `python` and `llm` |

## Known bypasses

- **Untrusted ≠ proven attacker-controlled.** The dynamic-argument rules (4 and 5) fire on any
  argument that is not a literal or a module constant / settings read, including a parameter or
  local that is actually a trusted, internally-computed path or URL — the guard cannot statically
  prove taint back to an untrusted source. Conversely, a module constant or settings value is
  trusted even if the deployment lets an operator point it somewhere unsafe. This is the same "surfacing an architecture, not proving an
  exploit" posture several sibling AI-agent guards already take.
- **`unsafe_mode` detection is keyword-only.** A positional `CodeInterpreterTool(True)` (if the
  library's signature ever allowed positional `unsafe_mode`) is not resolved — this guard requires
  the explicit `unsafe_mode=` keyword.
- **Aliased/wrapped imports.** A factory function or a re-exported alias for these class names
  (`from crewai_tools import CodeInterpreterTool as Interp; Interp(unsafe_mode=True)`) is not
  resolved — the guard matches the literal call-site name, not import provenance.
- **The 4th chain component (Docker-liveness fallback) is entirely out of scope**, as explained
  above — it is a library defect, not a source pattern.

## What this guard does NOT prove

Silence does not prove a CrewAI-based application is safe from this exploit chain — only that
none of these three source-level shapes were found. It does not verify the `crewai_tools` package
version is patched for CVE-2026-2287 (the unported Docker-fallback component), which needs a
verified version-floor entry, not a source-pattern guard.

# Citations

[1] agentsec checklist item `4-crewai-rce-chain` (§4)
[2] CVE-2026-2275, CVE-2026-2285, CVE-2026-2286, CVE-2026-2287; CERT/CC VU#221883
[3] ThaiCERT disclosure, 2026-04-02
[4] agent-audit-kit `crewai_rce_chain.py`, rule AAK-CREWAI-CHAIN-2026-04-001
