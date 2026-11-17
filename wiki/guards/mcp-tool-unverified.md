---
type: Guard
title: "mcp-tool-unverified"
description: "MCP server auto-loaded without explicit trust verification or allowlist."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "mcp-tool-unverified"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM03"]
---

# MCP server auto-loaded without explicit trust verification or allowlist

**Guard ID:** `mcp-tool-unverified`
**Module:** `agentsec/guards/mcp_tool_unverified.py`
**Severity:** HIGH
**Standards:** OWASP-LLM:LLM03, OWASP-LLM:LLM01

## Threat

MCP (Model Context Protocol) lets an LLM host connect to external "tool servers" that
expose callable functions described by natural-language specs. The model receives those
specs and treats them as authoritative descriptions of what the tool does and how it
should be invoked.

If a server is auto-connected without an explicit allowlist or trust check, that server
can supply arbitrary tool descriptions to the model. A malicious or compromised server
can use this channel to:

- Override prior system instructions (tool poisoning — OWASP-LLM:LLM03)
- Redirect the agent's actions to attacker-controlled endpoints
- Exfiltrate conversation history or context window contents
- Inject follow-on prompt injection payloads into the model's execution context

This is the MCP-specific variant of indirect prompt injection (OWASP-LLM:LLM01): the
injection arrives through the tool-description channel rather than through user input or
retrieved documents. The model has no independent mechanism to distinguish a legitimate
tool description from a poisoned one — the only reliable defense is an allowlist enforced
at connection time, before the server's tool specs are loaded.

## Detection design

Two independent checks, both emitting at most one finding each (the guard returns on
the first unflagged match in Python files; config files emit one finding per flagged
file, stopping after the first):

### 1. Python — `mcp-server-auto-loaded` (HIGH)

**Signal:** An `mcp` SDK usage pattern appears in a Python file with no trust marker
in the surrounding 20 lines.

**MCP usage patterns:**

```python
# Regex: r"^\s*from\s+mcp\b | \bMCPClient\s*\( | \bClientSession\s*\("

# Fires — bare import, no trust check nearby:
from mcp import ClientSession
from mcp.client.stdio import stdio_client

# Fires — client construction without allowlist:
server = MCPClient(command="python", args=["server.py"])

# Fires — session open with no verified server:
async with ClientSession(read_stream, write_stream) as session:
    await session.initialize()
```

**Trust markers (silence the check within 20 lines of the import/construction):**

```python
# Regex (case-insensitive): allowlist | allow_list | trusted | verified |
#                            approved | whitelist | APPROVED_SERVERS | ALLOWED_SERVERS

# Silent — allowlist checked before ClientSession:
APPROVED_SERVERS = {"mcp://internal.example.com/tools"}
if server_url not in APPROVED_SERVERS:
    raise ValueError("untrusted MCP server")
async with ClientSession(read_stream, write_stream) as session:
    await session.initialize()

# Silent — inline comment pragma:
# security: allow-mcp-unverified
from mcp import ClientSession  # internal controlled server
```

**Context window:** 20 lines before and after the import/construction line.

### 2. Config — `mcp-server-auto-loaded` (HIGH)

**Signal:** A JSON or YAML file whose name matches `*mcp*.json`, `*mcp*.yaml`,
`*mcp*.yml`, or `claude*.json` contains a `mcpServers` or `mcp_servers` key where at
least one entry lacks `"trusted": true`.

```jsonc
// Fires — server entry without "trusted": true:
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}

// Silent — every entry has "trusted": true:
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "trusted": true
    }
  }
}
```

For YAML files, a lightweight text scan is used (no PyYAML runtime dependency). If
`trusted: true` appears anywhere in the file, the file is considered safe. This may
produce false negatives when `trusted: true` is present but not associated with a
server entry — acceptable given the zero-dependency constraint.

## Severity rationale

HIGH because an unverified MCP server has direct write access to the model's tool
context. Unlike prompt injection via user input (which the model may partially resist
depending on system prompt construction), tool-description injection arrives in a
privileged channel the model is designed to trust unconditionally. A single malicious
server connection can compromise the entire agent session.

## Known bypasses (false negatives)

| Pattern | Caught? | Notes |
|---|---|---|
| Trust check in the same file, within 20 lines of import | Yes (silent) | Primary mitigation pattern |
| Trust check in a separate helper module | No (FN) | Suppress with pragma; multi-file dataflow out of scope |
| `MCPClient` subclass that enforces allowlist internally | No (FN) | Import of subclass still fires; pragma required |
| Dynamic server URL from env var, allowlist checked at runtime | No (FN) | Static analysis cannot trace runtime values |
| YAML with `trusted: true` in a comment, not a key | FP risk | Text scan may silence incorrectly; use JSON for precision |
| `mcp_servers` in a variable name, not a config key | FP risk | Regex match on name; rarely triggers in practice |

## FP scenarios

| Scenario | Why it fires | Suppression |
|---|---|---|
| Internal private MCP server, always trusted | No trust marker visible near import | `# security: allow-mcp-unverified` in file |
| MCP SDK used in tests against a mock server | Mock server still fires (mock not verified) | Pragma in test file or trust-marker in test setup |
| Config file with `mcpServers` that are all internal | No `"trusted": true` field | Add `"trusted": true` to each entry |
| Multi-file trust: allowlist module imported, check 30+ lines from import | Window too narrow | Move import closer to check, or add pragma |

### 3. package.json — `cve-2025-6514-mcp-remote` (CRITICAL)

**Signal:** A `package.json` file lists `mcp-remote` in `dependencies` or
`devDependencies` at a version in the vulnerable range 0.0.5–0.1.15.

**CVE-2025-6514** (CVSS 9.6): The mcp-remote npm package concatenates the OAuth
`authorization_endpoint` URL without validation. An attacker-controlled MCP server
can redirect the OAuth authorization flow to an arbitrary URL, stealing access tokens
or credentials with no additional user interaction beyond connecting to the server.

**Vulnerable range:** 0.0.5 through 0.1.15 (inclusive), including ranges like `^0.0.5`,
`~0.0.5`, `>=0.0.5 <0.2.0`, `0.0.x`, `0.1.x`.

**Safe:** `>=0.1.16`, `^0.1.16`, `^0.2.0`, `0.2.0`, major version >= 1.

**Ambiguous:** `latest`, `*` — flagged at MEDIUM (may resolve to vulnerable version).

## Checklist items flipped

| Item ID | Before | After | Reason |
|---|---|---|---|
| `4-mcp-tool-trust` | `partial` | `partial` | Extended to cover CVE-2025-6514 mcp-remote OAuth URL injection; severity upgraded to critical |

## Tests

| Test | Validates |
|---|---|
| `test_mcp_tool_unverified_fires_on_bare_import` | `from mcp import ClientSession` without trust check fires |
| `test_mcp_tool_unverified_fires_on_mcp_client_construction` | `MCPClient(` without trust check fires |
| `test_mcp_tool_unverified_silent_with_trust_marker_nearby` | `APPROVED_SERVERS` within 20 lines silences check |
| `test_mcp_tool_unverified_silent_with_pragma` | `# security: allow-mcp-unverified` silences all Python findings |
| `test_mcp_tool_unverified_fires_on_json_config_no_trusted` | JSON `mcpServers` without `"trusted": true` fires |
| `test_mcp_tool_unverified_silent_on_json_config_trusted` | JSON `mcpServers` with `"trusted": true` on all entries is silent |
| `test_mcp_tool_unverified_not_applicable_without_llm_feature` | `applies()` returns False when `llm` not in features |

# Citations

[1] agentsec checklist item `4-mcp-tool-trust` (§4)
[2] OWASP-LLM:LLM01
[3] OWASP-LLM:LLM03
