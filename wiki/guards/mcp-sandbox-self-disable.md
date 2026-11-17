---
type: Guard
title: "mcp-sandbox-self-disable"
description: "A tool/function JSON schema exposes an LLM-settable parameter that disables or weakens sandboxing."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "mcp-sandbox-self-disable"
checklist_section: ["4"]
standards: ["CWE-284", "CWE-306", "OWASP-ASI:ASI04"]
---

# Tool schema exposes an LLM-settable sandbox-disable parameter

_Author — 2026-09-26_

---

## The threat

CVE-2026-42074: OpenClaude before 0.5.1 exposed `dangerouslyDisableSandbox` as part of the
BashTool's model-facing input schema, so the LLM could set it to `true` in any tool call
(CWE-284 Improper Access Control, CWE-306 Missing Authentication, CVSS 9.8). A tool-call
argument is the one input surface a caller (here, the LLM acting on prompt-injected or
adversarial input) directly controls. A parameter that lets that surface turn off the
sandbox containing its own execution is not a bypass of the sandbox — it IS the sandbox
turned off, by design, the moment the model decides to set it. OWASP-ASI:ASI04 (Agentic
Supply Chain Vulnerabilities). Sourced from `agent-audit-kit`'s `sandbox_self_disable.py`
(AAK-MCP-SANDBOX-SELFDISABLE-001), verified against the real repo source.

## Why it's often introduced

A sandbox flag is genuinely useful for local development and debugging — being able to
turn it off while iterating is a real, legitimate need. The bug is exposing that same flag
in the SAME schema the model reads to construct tool calls, rather than gating it as an
operator-only startup config or environment variable the LLM never sees or influences.

## Detection design

1. `applies()` gates on `"mcp" in profile.features or "llm" in profile.features` — the
   same schema shape (MCP `inputSchema`, Anthropic `input_schema`, OpenAI `parameters`)
   appears across agent-tooling stacks generally, not only MCP servers specifically.
2. Scans every `.json` file (`iter_files`), pre-filtered by a cheap text-marker check
   (`"inputSchema"`/`"input_schema"`/`"parameters"`/`"properties"`/`"type": "function"`)
   before parsing.
3. Walks the parsed document for any dict value under an `inputSchema`/`input_schema`/
   `parameters` key at any nesting depth (covers `tools[].inputSchema`, Anthropic's
   top-level `input_schema`, and OpenAI's `function.parameters`), plus a bare schema file
   whose own top-level object carries `properties`. Within each schema container, walks
   `properties` (recursing into nested objects, `items`, and `anyOf`/`allOf`/`oneOf`
   branches, capped at depth 8) for a property NAME matching
   `dangerous(ly)?[-_]?disable|disable[-_]?sandbox|no[-_]?sandbox|skip[-_]?isolation`, or
   `allow[-_]?unsafe` ANCHORED to a sandbox/exec context. `allow_unsafe*` alone also names
   rendering switches (`allowUnsafeHtml` on a markdown renderer), so it only counts when the
   parameter name, the property's own description, or the enclosing tool's name/title/
   description also mentions sandbox, isolation, exec, shell, bash, command, subprocess,
   filesystem, eval, container, interpreter or terminal. Each schema OBJECT is reported
   separately, so two tools exposing the same parameter give two findings, each located at
   its own property's line (`file.json:<line>`).
4. A matched property is NOT flagged when annotated `readOnly: true`,
   `"x-llm-settable": false`, or `"x-mcp-sandbox-control": "ops-only"|"operator-only"|"server-only"`.
5. Inline opt-out: the plain string `security: allow-mcp-sandbox-self-disable` anywhere in
   the raw file text (a substring match, not a `#`-prefixed comment pragma — JSON has no
   comment syntax, so it lives in a JSON string value such as a `_note` field instead).
6. Severity CRITICAL, rule `mcp-sandbox-self-disable/llm-settable-disable`, standards
   `["CWE-284", "CWE-306", "OWASP-ASI:ASI04"]`.

## When NOT to flag

- A dangerous-named parameter explicitly annotated as not model-settable
  (`readOnly`/`x-llm-settable: false`/`x-mcp-sandbox-control: ops-only`).
- An ordinary boolean/string parameter whose name doesn't match the dangerous vocabulary —
  this guard is deliberately name-based, not a semantic analysis of every parameter.

## Tests

| Test | What it checks |
|---|---|
| `test_dangerously_disable_sandbox_fires` | MCP `inputSchema` shape — fires critical |
| `test_readonly_marked_param_is_safe` | `readOnly: true` — silent |
| `test_ops_only_marker_is_safe` | `x-mcp-sandbox-control: ops-only` — silent |
| `test_openai_parameters_shape_fires` | OpenAI `function.parameters` shape — fires |
| `test_anthropic_input_schema_shape_fires` | Anthropic `input_schema` shape — fires |
| `test_unrelated_boolean_param_is_safe` | A non-dangerous-named param — silent |
| `test_allow_unsafe_html_on_a_renderer_is_not_a_sandbox_disable` | `allowUnsafeHtml` on a markdown renderer — silent |
| `test_allow_unsafe_on_a_tool_described_as_running_shell_commands_still_fires`, `..._with_an_anchor_in_the_parameter_name_...`, `..._in_the_property_description_...` | Anchored `allow_unsafe*` — fires |
| `test_self_anchored_names_need_no_context` | `skipIsolation` etc. fire with no context |
| `test_findings_carry_the_line_of_the_offending_property` | Two tools in one file — two findings, each at its own line |
| `test_pragma_suppresses_finding` | Pragma in a JSON string value — silent |
| `test_guard_applies_to_llm_feature_without_mcp` | `applies()` fires on `llm` alone |
| `test_guard_not_applicable_without_mcp_or_llm` | `applies()` gates correctly |

## Known bypasses

- The dangerous-parameter name vocabulary is fixed; a differently-named equivalent
  (`"unsafe_mode"`, `"legacy_exec"`) is invisible to this guard.
- A parameter nested more than 8 levels deep, or reached only through a schema
  `$ref` this guard does not resolve, is not seen.
- The annotation-based suppression trusts the schema's own metadata — a schema that
  falsely claims `readOnly: true` on a parameter the runtime actually honors from the
  request body would silently suppress a real finding.

## What this guard does NOT prove

Silence does not prove no sandbox-disable capability exists at all — only that no
model-facing schema property NAME matches the dangerous vocabulary. A sandbox toggle
reachable through a differently-shaped mechanism (a free-text command argument that
happens to accept a disable flag, a separate non-schema-declared side channel) is outside
this guard's detection surface.

# Citations

[1] agentsec checklist item `4-mcp-sandbox-self-disable` (§4)
[2] CVE-2026-42074 (OpenClaude < 0.5.1, CVSS 9.8)
[3] CWE-284, CWE-306, OWASP-ASI:ASI04
[4] agent-audit-kit `sandbox_self_disable.py`, rule AAK-MCP-SANDBOX-SELFDISABLE-001
