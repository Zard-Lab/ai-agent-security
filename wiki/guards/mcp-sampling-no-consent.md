---
type: Guard
title: "mcp-sampling-no-consent"
description: "MCP sampling capability wired up with no consent/elicitation gate anywhere in the repo."
timestamp: "2026-09-22T12:00:00+08:00"
guard_id: "mcp-sampling-no-consent"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-ASI:ASI01"]
---

# MCP sampling capability wired up with no consent/elicitation gate

_Author — 2026-09-22_

---

## The threat

MCP servers can request LLM completions back through the connected CLIENT via the
`sampling/createMessage` request (MCP 2025-06-18 §6.3, the `sampling` capability). This inverts
the usual trust direction: normally a client/host calls the model and the server only handles
tool calls, but `sampling` lets the SERVER become a privileged caller of the host's own LLM. Any
completion the server receives back must be treated as untrusted tool input — the server chose
the prompt, and the host has no way to know what that prompt actually asked for.

The MCP spec's 2025-03-26 revision added the `elicitation/create` consent flow specifically to
gate this: a well-behaved host is supposed to ask the user before honoring a sampling request,
the same way a tool call itself should be confirmed for a destructive action. A server that
implements sampling with no corresponding consent wiring — anywhere in the reachable code — has
built exactly the shape the spec's own consent mechanism exists to prevent. WHO reaches this: any
MCP client connected to the server. WHAT privilege: the ability to have the HOST's own LLM
generate content on the server's behalf, silently. TO WHAT EFFECT: prompt injection surface
(the server can craft a prompt designed to manipulate the host's model), resource/cost abuse (an
unbounded stream of sampling requests billed to the host's LLM budget — see the neighboring
`mcp-tools-list-unbounded` guard for the sibling "nothing bounds what the other side can make us
do" shape), or using the sampling channel to exfiltrate context the host's LLM has access to but
the server does not. Standards: OWASP-LLM:LLM01 (Prompt Injection — a sampling response is
untrusted content flowing back into the host's context), OWASP-ASI:ASI01 (Agent Goal Hijack — an
uncontested channel for a server to influence the host's own model).

## Why it's often introduced / Why this guard fits the stack

`sampling` is a genuinely useful capability — a tool that wants to summarize a large intermediate
result, or ask the model to reformat something, without round-tripping through the full agent
loop. The consent-flow requirement is easy to treat as optional in early development ("I'll add
the confirmation dialog later") and easy to simply forget once the feature works end-to-end,
because the capability functions identically with or without it — the only difference is whether
the user ever gets a say. Unlike a tool call's destructive-action confirmation (which a
`tool_callback_enforcement`-style guard can catch by looking for a `confirm`/`approve` pattern
directly at the call site), sampling's consent gate is a protocol-level, cross-cutting concern
that doesn't have one obvious call site to check — it has to be wired in wherever the host
actually decides to honor a `sampling/createMessage` request, which this guard cannot see if the
host itself lives outside the scanned repo.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features` — reused directly instead of
   re-implementing manifest/SDK detection (see "Deliberate adaptations" below).
2. **Files scanned:** `iter_files(root, (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".java",
   ".kt", ".rs"))` — cross-language, since MCP servers ship in all of these.
3. **Source-side check (`mcp-sampling-no-consent/source-participation`, MEDIUM):**
   - Collect `_sampling_hits()`: every file matching any of `_SAMPLING_MARKERS` — a
     `capabilities.sampling` declaration, `ServerCapabilities(...sampling=...)`,
     `SamplingCapability(...)`, a `CreateMessageRequestSchema` handler installation, a bare
     `sampling/createMessage` string, a `create_message(` call, `.sampling.create(`, or
     `RequestSampling` — verbatim regex set from the real source.
   - If any hit exists, check `_has_consent_marker()` REPO-WIDE (not same-file): any of
     `elicitation/create`, `ElicitRequestSchema`, `elicit_create`/`elicit_input`/`elicitation(`,
     `ElicitInput`, `requires_consent`/`require_consent`/`user_consent`,
     `human_in_the_loop`/`human-in-the-loop`, `confirmSampling`/`approveSampling`,
     `samplingConsent`, or `human_approval` — verbatim regex set.
   - If sampling participation exists and NO consent marker is found anywhere in the repo, fire
     on the FIRST sampling hit found.
4. **Config-side check (`mcp-sampling-no-consent/config-declaration`, MEDIUM), independent of the
   source-side check:** for each MCP config file (`.mcp.json`, `.cursor/mcp.json`,
   `.vscode/mcp.json`, `.amazonq/mcp.json`, `.windsurf/mcp.json`, `.continue/config.json`,
   `.roo/mcp.json`, `.kiro/mcp.json`, `mcp.json`), parse `mcpServers`; for each server entry
   whose `capabilities` (list or dict) includes `"sampling"`, fire unless `requires_consent`,
   `requiresConsent`, `consent`, or `human_in_the_loop` is explicitly `true` on the same entry.
5. **Inline opt-out pragma:** `# security: allow-mcp-sampling-no-consent` (checked per-file for
   the source-side markers, and on the config file's raw text for the config-side check).
6. **Severity/standards:** `medium`, `["OWASP-LLM:LLM01", "OWASP-ASI:ASI01"]`. Lowered from
   `high` in PR #923 round 3, and the `4-mcp-sampling-no-consent` checklist item with it: the
   biggest known false-positive class (consent implemented in a HOST repo this guard never
   scans, see "Known bypasses") is structural, so the finding should not trip the default
   `--fail-on high` CI gate. `surfacing` does not do that, since it only changes report order.

## Deliberate adaptations vs. the real source (disclosed)

- **SDK-declaration gate.** The real `mcp_sampling_capability.py` requires a dependency-manifest
  MCP-SDK declaration (`pyproject.toml`/`requirements*.txt`/`package.json`/`pom.xml`/
  `build.gradle*`/`Cargo.toml`) before its source-side check runs, re-implementing that detection
  itself. agentsec's `detect.py` already performs the equivalent anchored SDK/import/config
  detection to set the `mcp` feature — reusing `applies()` avoids a second, divergent copy of
  that logic living in this one guard.
- **Risk-acceptance escape hatch.** The real source reads a bespoke `.agent-audit-kit.yml` file
  with an `accepts_sampling_risk: true` + `justification:` pair. agentsec has no equivalent
  anywhere in this codebase — every other guard uses the shared inline pragma convention
  instead, so this guard does too (`# security: allow-mcp-sampling-no-consent`) rather than
  introducing a new per-guard YAML config file.

## When NOT to flag

- **No sampling participation at all** — a repo that only implements `tools`/`resources` (the
  overwhelming majority of MCP servers) never reaches either check.
- **A consent marker present anywhere in the repo**, even in a file unrelated to the specific
  sampling handler — the source-side check is deliberately repo-wide, not same-file, matching
  the real source's own design (a consent flow is often implemented once, centrally, not
  duplicated at every sampling call site).
- **A config entry with `requires_consent: true`** (or `requiresConsent`/`consent`/
  `human_in_the_loop`) sibling to its `sampling` capability declaration.
- **A config entry with no `sampling` in its capabilities list** at all.
- An audited, intentional case suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_sampling_handler_with_no_consent_marker` | Source-side fires on a `CreateMessageRequestSchema` handler with no consent marker anywhere |
| `test_fires_on_sampling_createmessage_call` | Source-side fires on a bare `sampling/createMessage` string marker |
| `test_silent_when_consent_marker_present_anywhere_in_repo` | FP-bait: a consent marker in a DIFFERENT file silences the source-side finding (repo-wide check) |
| `test_no_sampling_participation_is_safe` | FP-bait: an MCP repo with no sampling markers at all stays silent |
| `test_pragma_suppresses_source_finding` | the inline pragma silences the source-side finding |
| `test_fires_on_config_sampling_capability_no_consent` | Config-side fires on `"capabilities": ["sampling"]` with no consent sibling flag |
| `test_config_sampling_with_requires_consent_is_safe` | FP-bait: `requires_consent: true` sibling silences the config-side finding |
| `test_config_no_sampling_capability_is_safe` | FP-bait: a server with no `sampling` capability stays silent |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` is False without the `mcp` feature |
| `test_guard_applicable_with_mcp_feature` | `applies()` is True with the `mcp` feature |
| `test_nonproduct_path_skipped` | files under `tests/fixtures/` are skipped |

## Known bypasses

- **Host-side consent, scanned repo is server-only.** If the consent flow is implemented in the
  HOST application (a separate repo this guard never scans — the common case for an MCP server
  published as a standalone package consumed by Claude Desktop/Cursor/etc.), this guard has no
  way to see it and will fire even though the actual deployment is safe. This is the guard's
  single biggest known false-positive class, inherent to static single-repo scanning of a
  cross-process protocol.
- **Unlisted consent phrasing.** The consent-marker vocabulary is curated; a project using
  different terminology entirely (no `consent`/`elicit`/`approve`/`human` substring anywhere)
  would not be recognized even if a real gate exists.
- **Unlisted sampling markers.** Similarly, a sampling implementation that doesn't match any of
  the curated `_SAMPLING_MARKERS` patterns (an unusual SDK wrapper, a fully custom JSON-RPC
  client) gets no coverage.
- **Config-side check is JSON-only** — a YAML/TOML MCP config declaring `sampling` in its
  capabilities gets no coverage from the config-side rule (the source-side rule may still catch
  the corresponding code, if any).
- **Text-presence, not call-graph proof.** Both checks are marker-presence searches, not a proof
  that the consent marker actually gates the specific sampling call path — a `human_in_the_loop`
  string appearing anywhere (a comment, an unrelated feature, a dead code path) silences the
  finding.

## What this guard does NOT prove

- That a recognized consent marker is genuinely wired into the sampling request path — see
  "Known bypasses" above.
- That the absence of a marker means no consent flow exists — it may live outside this repo
  entirely (the host-side case), which this guard structurally cannot see.
- That a sampling request, once consented to, is otherwise handled safely (its response content
  treated as untrusted, rate-limited, or bounded) — this guard only checks for the presence of
  a consent gate, not what happens after consent is granted.

# Citations

[1] agentsec checklist item `4-mcp-sampling-no-consent` (§4)
[2] OWASP-LLM:LLM01
[3] OWASP-ASI:ASI01
[4] MCP spec 2025-06-18 §6.3 (`sampling/createMessage`) and the 2025-03-26 revision's
    `elicitation/create` consent flow
[5] agent-audit-kit (sattyamjjain/agent-audit-kit), `mcp_sampling_capability.py`
