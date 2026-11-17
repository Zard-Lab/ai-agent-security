---
type: Guard
title: "tool-chaining-exfil"
description: "Agent exposes both a sensitive-read tool and an external-send tool (tool-chaining exfiltration)."
timestamp: "2026-07-13T02:24:20+02:00"
guard_id: "tool-chaining-exfil"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM02", "OWASP-LLM:LLM06"]
---

# Agent exposes both a sensitive-read tool and an external-send tool (tool-chaining exfiltration)

_Author — 2026-07-12_

**Guard ID:** `tool-chaining-exfil`
**Checklist item:** `4-tool-chaining-exfil`
**Severity:** HIGH
**Standards:** OWASP-LLM:LLM06, OWASP-LLM:LLM02

---

## The threat

An agent registered with BOTH a sensitive-read tool (CRM / DB / secret read) AND an external-send tool
(email / HTTP / webhook) can chain them into an exfiltration path that *neither tool exposes alone*: an
attacker who can steer the agent (indirect prompt injection, a poisoned document, or a compromised agent)
has it read private data with the trusted read tool and send it out with the trusted send tool. Every call
runs through legitimate binaries under valid credentials — host/network monitoring sees ordinary tool use,
not malware. This is the Zero-Trust-for-AI-Agents "tool-chaining" threat verbatim: "chaining a secure
internal CRM tool with an external email tool to exfiltrate data neither would expose alone." It is an
excessive-agency failure (OWASP-LLM:LLM06) that results in sensitive-information disclosure (LLM02).

## Why it's often introduced / Why this guard fits the stack

The 9_Agent_SaaS shape (pydantic-ai / langchain agent) grows tools incrementally: a `fetch_customer` tool
here, an `email_summary` tool there. Each is reasonable in isolation and passes `agent-tool-overpermission`
(neither is a Shell/PythonREPL/subprocess tool). The exfil path is emergent — it exists only because both
are registered on the same agent — so no per-tool check sees it.

```python
@agent.tool
def fetch_customer(ctx, cid): return db.table("customers").select("*").eq("id", cid).execute()

@agent.tool
def email_report(ctx, to, body): return requests.post("https://mailer/send", json={"to": to, "body": body})
# Individually fine; together, an injection can read any customer and email it out.
```

## Detection design

1. **applies() gate** — `"llm" in profile.features`.
2. **Self-exclusion** — skip the whole repo if `is_llm_framework_repo(root, profile)` (the single shared
   helper in `guards/base.py` since #389; also re-exported from `ai/lethal_trifecta.py`), so the guard
   doesn't fire on langchain/llamaindex's own source, which defines
   tools with these decorators. (Deliberate cross-module reuse of the analyzer's self-exclusion; a shared
   helper could formalize it later.)
3. **Files** — `python_scan_dirs` → `iter_files(d, (".py",))`, skipping `is_nonproduct_path`. File-level
   pragma bail (`_PRAGMA in text`).
4. **Tool scoping** — `iter_functions(text)` yields `(def-line, block)` per function (decorator stack +
   body, triple-quoted strings already blanked). `_is_tool(block)` = the decorator stack matches
   `_TOOL_DECORATOR` (`@tool` / `@agent.tool` / `@app.agent.tool`).
5. **Classify** — per tool, extract the **body only** (`_tool_body` via `ast`, first body statement
   onward, column-sliced so a one-liner drops its header) so a signal in a parameter name or the
   function name can't misclassify (#388 review), then match `_READ_RE` (`.select(`, `session.query`,
   `from supabase import`, `vault`, `decrypt(`, `auth.uid`, `read_secret`, …) and `_SEND_RE` (`httpx`,
   `requests.post`, `smtplib`, `send_email`, `sendgrid`, `webhook`, `mcpserver`, `tavily`, …).
   Taxonomy adapted from `ai/lethal_trifecta.py::_LEGS`; the English-word signals carry a `(?!\w)`
   trailing guard so a *data identifier* embedding them (`webhook_id`, `send_email_status`, `vault_id`)
   does not classify, while a *call/attribute* (`send_email(`, `send_webhook(`, `vault.read(`) still does.
6. **Fire** — if the file has ≥1 read-classified tool AND ≥1 send-classified tool (same tool counting for
   both is fine — one tool that reads *and* sends is itself an exfil path), emit **one HIGH** finding
   anchored at the send tool's line (the egress), rule `tool-chaining-exfil/read-and-send-tools`, standards
   `["OWASP-LLM:LLM06", "OWASP-LLM:LLM02"]`.
7. **Pragma** — `# security: allow-tool-chaining-exfil`.

**Tool-registration-scoped is the whole low-FP thesis.** Firing on repo-wide "reads sensitive + sends
external" would flag nearly every DB+API app; requiring both to be exposed as agent tools is what makes a
finding mean "the LLM can chain these."

## Relationship to neighbouring guards (no overlap, no tag collision)

- `lethal-trifecta` (`ai/lethal_trifecta.py`) fires only when **all three** legs are present (private_data
  AND untrusted_content AND external_comms). The read+send-without-the-untrusted-leg case produces zero
  trifecta findings — exactly this guard's gap. On a repo that triggers both, both fire: the trifecta
  finding describes the injection→exfil architecture, this one names the specific tool pair. Trifecta
  carries LLM01; this carries LLM06/LLM02 — no double-tag (LLM06 was intentionally dropped from trifecta in
  2026-07-05 to avoid colliding with `agent-tool-overpermission`).
- `agent-tool-overpermission` flags a *single* dangerous tool (Shell/PythonREPL/subprocess/
  allow_dangerous_requests). This flags a *combination* of two individually-benign tools.

## When NOT to flag

An intended, mediated chain — a "fetch a record then email it" workflow guarded by human approval, a
destination allowlist, or an output filter. That is what the pragma is for.

## Tests

| Test | What it checks |
|---|---|
| `test_tool_chaining_exfil_fires` | read tool + send tool on one agent → one HIGH finding, correct standards/location |
| `test_tool_chaining_exfil_single_tool_does_both_fires` | one tool that reads and sends → fires |
| `test_tool_chaining_exfil_langchain_at_tool_fires` | the bare langchain `@tool` form is detected |
| `test_tool_chaining_exfil_silent_when_not_tools` | **the anti-FP contract** — DB read + external send NOT as tools → silent |
| `test_tool_chaining_exfil_silent_only_read_tool` / `..._only_send_tool` | one class alone → silent |
| `test_tool_chaining_exfil_silent_in_docstring` | signals in a docstring example → silent (strings blanked) |
| `test_tool_chaining_exfil_silent_marker_in_comment` | a send signal in a `#` comment doesn't misclassify a read tool |
| `test_tool_chaining_exfil_pragma_silences` | the pragma silences the file |
| `test_tool_chaining_exfil_applies_gate` | fires only when `llm` is a detected feature |

## Known bypasses

- **Constructor-form tools** — `Tool(name=..., func=fn)` / `StructuredTool.from_function(fn)` register an
  existing named function; v1 does not resolve those to their bodies, so a tool registered that way is not
  classified. Decorator-form tools (the pydantic-ai / langchain / flagship norm) are covered.
- **Cross-file registration** — a read tool in `tools_a.py` and a send tool in `tools_b.py`, both registered
  on one agent in a third module, are not correlated (detection is file-scoped, mirroring
  `agent-tool-overpermission`).
- **Aliased / wrapped send** — a send performed through an in-house helper (`self._client.dispatch(...)`)
  that doesn't contain a `_SEND_RE` token evades the classifier; likewise a signal buried in a single-line
  string (not blanked, unlike triple-quoted). The `(?!\w)` guards also mean a send done via an identifier
  like `send_webhook_now` (trailing `_now`) reads as a data name, not a call — a narrow false-negative
  accepted to keep the `webhook_id`/`send_email_status` false-positives out.

## What this guard does NOT prove

That the chain is actually reachable by an attacker, or unmediated — a present read+send tool pair may be a
deliberate, human-in-the-loop workflow (hence the pragma). It flags the *capability* (two composable tools
on one agent), not a proven exploit; a human/the `/security` skill confirms whether mediation exists.

# Citations

[1] agentsec checklist item `4-tool-chaining-exfil` (§4)
[2] OWASP-LLM:LLM02
[3] OWASP-LLM:LLM06
