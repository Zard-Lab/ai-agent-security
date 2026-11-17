---
type: Guard
title: "acp-vulnerabilities"
description: "Agent Communication Protocol (ACP) implementation has security vulnerabilities."
timestamp: "2026-06-28T22:09:16+08:00"
guard_id: "acp-vulnerabilities"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP:A02", "OWASP:A07"]
---

# Agent Communication Protocol (ACP) implementation has security vulnerabilities

_Author — 2026-06-28_

---

## The threat

ACP (Agent Communication Protocol, implemented by `acp-sdk` and `beamlit`) is an emerging
Python protocol for agent-to-agent communication. Because it is new, security primitives are
sparse and developers frequently make four classes of mistake:

**ACP-047 — MINJA (Memory INJection Attack)**
An ACP message handler writes the raw, untrusted incoming message content directly to a
persistent memory store (vectorstore, key-value, conversation buffer). An adversary crafts
a message whose content contains instruction payloads that persist in the agent's durable
memory and steer future decisions — a cross-session, persistent variant of prompt injection.
Affected standards: OWASP-LLM:LLM01, OWASP-LLM:LLM02.

**ACP-072 — Hot-reload without token invalidation**
A hot-reload or reconfigure path swaps the live agent configuration without revoking
existing session tokens. Sessions established under the old config silently inherit the
new (potentially different-privilege) config without re-authentication — a confused-deputy
that may grant escalated or reduced scope to active callers.
Affected standards: OWASP-LLM:LLM02, OWASP:A07.

**ACP-079 — Org-scoped token literal**
An organization- or workspace-scoped API token or secret is assigned as a string literal
in source code. Org-scoped tokens typically carry elevated privilege across all agents in
the organization; committing one to source control makes it extractable from any git history,
CI artifact, or log diff.
Affected standards: OWASP-LLM:LLM02, OWASP:A07.

**ACP-082 — Unclamped sampling parameters from caller**
LLM sampling parameters (temperature, top_p, top_k, max_tokens) are forwarded from the
incoming ACP request or message object with no clamping or range check. An adversary can
force extreme values (temperature=100, max_tokens=10000000) to destabilise output quality,
exhaust token quota, or cause a denial of service against the downstream LLM provider.
Affected standards: OWASP-LLM:LLM01.

## Why it's often introduced / Why this guard fits the stack

ACP is young. Developers copy minimal examples from the SDK docs, which do not highlight
security considerations. The four patterns fall out naturally from following the quick-start:

```python
# ACP-047: canonical "remember what the user said" pattern
@agent.on_message
async def handle(msg: Message):
    memory.add(msg.content)        # raw content → memory, no sanitisation

# ACP-072: "live update config without restart"
def hot_reload(cfg):
    agent.config = cfg             # no revoke() / invalidate_sessions()

# ACP-079: "just try it out" token
org_token = "sk-org-abc123xyz456" # committed to dev branch, never rotated

# ACP-082: "let the caller control quality"
def chat(request):
    llm.invoke(prompt, temperature=request.temperature)  # no min()/max()
```

## Detection design

1. **`applies()` gate** — scans `.py` files for `from acp import`, `from acp_sdk import`,
   `import acp`, `import acp_sdk`, or `import beamlit`. Returns `True` if any match is
   found; returns `False` otherwise (guard is N/A for non-ACP repos).

2. **Files scanned** — all `.py` files under `python_scan_dirs(root, profile)`,
   skipping non-product paths via `is_nonproduct_path(rel, profile.archive_segments)`
   and skipping files that don't contain an ACP import (`_ACP_IMPORT`).

3. **Patterns per rule:**

   All window scans run over `_code_lines` (string contents blanked + comments removed).

   - **ACP-047**: match `_HANDLER_DECL` (`@<name>.on_message` or `async def <name>(... :
     [Acp|Agent]Message)` — a TYPED message param, not any fn mentioning "Message");
     decorator+def collapse to one region; within 30 lines look for `_MEM_WRITE` (a write
     to a memory/store-named receiver); if found AND no genuine `_SANITIZE`
     (sanitize/clean/scrub/guardrail/validate — NOT a whitespace `.strip()`) — fire.

   - **ACP-072**: match `_RELOAD_CALL` (`hot_reload(`, `reload_config(`, `update_agent(`,
     `reconfigure(`) or `_RELOAD_FUNC` (`def *reload*` / `def *reconfigure*`); within 20
     lines fire UNLESS an invalidation verb (revoke/invalidate/expire/deauth/logout/reset)
     AND a session/token/auth noun BOTH appear (so an unrelated `cache.invalidate` doesn't
     suppress).

   - **ACP-079**: match `_ORG_TOKEN_LITERAL` on any non-comment line — an `org/organization/
     workspace` prefixed variable assigned a string literal of 10+ alphanumeric chars.

   - **ACP-082**: match `_SAMPLING_FROM_CALLER` (sampling param assigned DIRECTLY from
     `request/msg/message/event/data/params/payload/body.`); fire unless the same param is
     re-clamped with `min(`/`max(`/`clamp(` on one of the next few lines. (A clamped
     `temperature = min(request.x, 1.0)` doesn't match the direct-assignment pattern at all.)

4. **Inline opt-out pragma**: `# security: allow-acp-vulnerabilities` anywhere in a file
   skips that entire file for all four rules.

5. **Severities and rule ids:**

   | Rule | Severity | Standards |
   |---|---|---|
   | `acp-vulnerabilities/minja-memory-injection` | HIGH | OWASP-LLM:LLM01, OWASP-LLM:LLM02 |
   | `acp-vulnerabilities/hot-reload-no-token-invalidation` | HIGH | OWASP-LLM:LLM02, OWASP:A07 |
   | `acp-vulnerabilities/org-scoped-token` | HIGH | OWASP:A02, CWE-798 |
   | `acp-vulnerabilities/unclamped-sampling-params` | MEDIUM | OWASP-LLM:LLM01 |

   (Each rule carries the standards its own threat narrative above claims — the org-scoped-token
   rule is a hardcoded-secret finding, CWE-798 / OWASP:A02, not an LLM-prompt-injection one.)

## When NOT to flag

  Comments and string contents are blanked before any window scan (`_code_lines`), so a
  comment that merely *mentions* a suppression word cannot silence a rule.

- **ACP-047**: a genuine sanitisation call (`sanitize`/`clean`/`scrub`/`guardrail`/
  `validate`) in the 30-line handler window silences the rule. A plain whitespace `.strip()`
  or the `filter` builtin do NOT count. The handler decorator + its typed `def` collapse to
  one region, so a handler reports once. Use the pragma when sanitisation is applied upstream
  at the ACP framework middleware layer.

- **ACP-072**: an invalidation **verb co-located with a session/token/auth noun** in the
  20-line window silences the rule (so an unrelated `cache.invalidate('key')` does not). Use
  the pragma when the ACP runtime automatically invalidates sessions on config change.

- **ACP-079**: an env-var lookup (`os.environ[...]`, `os.getenv(...)`) does not match the
  literal pattern; comment lines are skipped. Use the pragma only for placeholder values in
  documentation or example code.

- **ACP-082**: the rule only matches a sampling param assigned **directly** from a caller
  object (a clamped `min(request.x, …)` does not match at all), and a same-param re-clamp on
  one of the next few lines also silences it. Use the pragma when the caller is fully trusted
  and clamping is enforced at the ACP router boundary.

## Tests

| Test | What it checks |
|---|---|
| `test_acp_vulnerabilities_applies_when_acp_import_present` | applies() returns True with acp_sdk import |
| `test_acp_vulnerabilities_applies_with_beamlit_import` | applies() returns True with beamlit import |
| `test_acp_vulnerabilities_not_applicable_without_acp_import` | applies() returns False with no ACP import |
| `test_acp_minja_fires_on_unsanitised_handler` | ACP-047 fires on @on_message + memory.add(msg.content) |
| `test_acp_minja_fires_on_message_type_annotation` | ACP-047 fires on handler with AcpMessage annotation |
| `test_acp_minja_silent_when_sanitised` | ACP-047 stays silent when sanitize() is in the window |
| `test_acp_minja_severity_is_high` | ACP-047 severity=high, OWASP-LLM:LLM01 in standards |
| `test_acp_hot_reload_fires_on_missing_invalidation` | ACP-072 fires on def hot_reload without revoke |
| `test_acp_hot_reload_fires_via_call_pattern` | ACP-072 fires on hot_reload() call without invalidation |
| `test_acp_hot_reload_silent_with_invalidation` | ACP-072 stays silent when invalidate_sessions() present |
| `test_acp_hot_reload_severity_is_high` | ACP-072 severity=high |
| `test_acp_org_token_fires_on_literal` | ACP-079 fires on org_token = "sk-org-..." |
| `test_acp_org_token_fires_on_workspace_key` | ACP-079 fires on workspace_api_key = "wk-..." |
| `test_acp_org_token_silent_when_from_env` | ACP-079 stays silent when value from os.environ |
| `test_acp_org_token_severity_is_high` | ACP-079 severity=high |
| `test_acp_sampling_fires_on_unclamped_temperature` | ACP-082 fires on temperature=request.temperature |
| `test_acp_sampling_fires_on_unclamped_max_tokens` | ACP-082 fires on max_tokens=msg.max_tokens |
| `test_acp_sampling_silent_when_clamped` | ACP-082 stays silent when min() wraps the value |
| `test_acp_sampling_severity_is_medium` | ACP-082 severity=medium |
| `test_acp_pragma_silences_all_rules` | pragma suppresses all four rules in the file |
| `test_acp_check_id_is_set` | check_id="acp-vulnerabilities" and OWASP-LLM:LLM01 in all findings |

## Known bypasses

- **ACP-047**: indirect assignment (`content = msg.content; memory.add(content)`) where
  the variable is assigned on one line and written on another outside the 30-line window.
  Aliased method calls (`m = memory.add; m(msg.content)`) also bypass the write pattern.

- **ACP-072**: session invalidation implemented via a callback registered at startup
  rather than an inline call inside the reload function — the guard cannot see registered
  callbacks.

- **ACP-079**: token split across multiple concatenated string literals, or loaded from a
  config file rather than assigned inline.

- **ACP-082**: clamping applied in a separate helper function called on a different line
  outside the ±20-line window; or clamping implemented as a custom `clamp()` name not in
  the `_CLAMP_SIGNAL` pattern.

## What this guard does NOT prove

- That sanitisation (when detected) is semantically sufficient — the guard checks for the
  presence of a sanitisation call, not its correctness. A stub `sanitize(x) -> x` would
  silence the rule.

- That the hot-reload session invalidation (when detected) is actually effective — a
  `revoke()` that silently no-ops would pass.

- That org-scoped tokens loaded from environment variables are not themselves leaked via
  other channels (logs, error responses, debug endpoints).

- That clamping applied to sampling parameters uses the correct upper bounds — `min(x, 9999)`
  would satisfy the pattern check but still allow near-unbounded max_tokens.

# Citations

[1] agentsec checklist item `4-acp-hot-reload-token-invalidation` (§4)
[2] agentsec checklist item `4-acp-minja-memory-injection` (§4)
[3] agentsec checklist item `4-acp-org-token-not-literal` (§4)
[4] agentsec checklist item `4-acp-sampling-params-clamped` (§4)
[5] OWASP-LLM:LLM01
[6] OWASP-LLM:LLM02
[7] OWASP:A02
[8] OWASP:A07
