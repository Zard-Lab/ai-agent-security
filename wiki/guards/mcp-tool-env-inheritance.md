---
type: Guard
title: "mcp-tool-env-inheritance"
description: "MCP server / agent-tool subprocess spawned with the full parent environment."
timestamp: "2026-07-07T15:25:38+08:00"
guard_id: "mcp-tool-env-inheritance"
checklist_section: ["4"]
standards: ["CWE-200", "OWASP-LLM:LLM02"]
---

# MCP server / agent-tool subprocess spawned with the full parent environment

_Author — 2026-07-07_

---

## The threat

An MCP server, or any subprocess an agent spawns as a tool, runs code the model can indirectly
steer — through a prompt-injected instruction, a poisoned tool response, or a compromised
upstream package the tool itself depends on. If that subprocess inherits the agent's *entire*
process environment, every API key, database URL, and internal token the agent holds is now
reachable from a process the model can influence. Compromising one tool then leaks every secret
the agent has, not just the one that tool was actually supposed to use.

This is Pattern 1 from an external credentials-management analysis surfaced this session
("materialize into process environment" — the weakest of five architectural patterns for
delivering credentials to an agentic system), applied to the specific, statically-detectable
moment it happens: the subprocess spawn call itself. WHO reaches it: anyone who can influence
what the spawned tool does (prompt injection, a malicious MCP server response, a compromised
tool dependency). WHAT privilege: read access to every env var the parent agent process holds.
TO WHAT EFFECT: credential exfiltration — the spawned process can read and forward any secret in
its env, and it doesn't need the vulnerability to be "yours"; a bug in the *tool's* code is
enough. Standards: OWASP-LLM:LLM02 (Sensitive Information Disclosure), CWE-200 (Exposure of
Sensitive Information to an Unauthorized Actor).

## Why it's often introduced / Why this guard fits the stack

The official MCP Python SDK's own default is actually safe — `StdioServerParameters(env=None)`
spawns the child with a minimal, curated environment, not the caller's full one. The anti-pattern
is a *deliberate* override back to the dangerous default, usually for one of two reasons:

```python
# "I just want the subprocess to see PATH / normal shell stuff":
params = StdioServerParameters(command="npx", args=[...], env=os.environ.copy())

# "I want to add one variable, so I'll spread the rest":
proc = subprocess.Popen(["mcp-server"], env={**os.environ, "TOOL_MODE": "strict"})
```

Both look reasonable locally — the developer is thinking "make sure the subprocess has what it
needs to run," not "I am handing this subprocess every secret in the process." The spread-merge
form is especially easy to reach for: it *looks* like a scoped, deliberate env dict, but the
`**os.environ` spread means every existing key rides along before the one new key is added.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features` — scoped to repos where MCP usage is
   actually detected (a real `import mcp`/`from mcp`, an `mcp` dependency, an `[tool.mcp]`
   section, or an MCP config file — see `detect.py`). Keeps the guard's precision-vs-recall
   tradeoff tight: an explicit `env=os.environ` pattern is rare enough in general Python that a
   broader gate is plausible, but scoping to `mcp` matches this guard's exact threat framing and
   avoids flagging unrelated subprocess usage in non-agentic code.
2. **Files scanned:** `python_scan_dirs(root, profile)` + `iter_files(d, (".py",))` — the same
   plain-text Python source scan `tls-verify-disabled` and `command-injection` use. No AST, no
   runtime dependency.
3. **Patterns:**
   - `_SPAWN_CALL` matches `subprocess.(Popen|run|call|check_call|check_output)(`, the async
     `asyncio.create_subprocess_(exec|shell)(`, or `StdioServerParameters(` — the shapes that
     actually launch a tool/server subprocess (async included; it's idiomatic in agent code — #374).
   - `_FULL_ENV` matches `env=os.environ`, `env=os.environ.copy()`, `env=dict(os.environ)`, or a
     `{... **os.environ ...}` spread with the spread anywhere in the dict — the spellings of
     "forward everything." Plus, only in a file that did `from os import environ`, a bare
     `env=environ` (import-gated so an unrelated local `environ` doesn't false-positive) — #374.
   - **Multi-line handling:** `env=` frequently sits on its own line in a multi-line call. Rather
     than full bracket-balance parsing, the guard takes a bounded lookahead
     (`_CONTEXT_WINDOW = 15` lines, mirroring the fixed-window convention already used in
     `guardrail_architecture.py`) from the spawn-call line and searches that block for
     `_FULL_ENV`. Good enough for the realistic call shapes this guard targets; see Known
     bypasses for where it can mis-attribute.
4. **Inline opt-out pragma:** `# security: allow-mcp-tool-env-inheritance`, checked once per file
   (a file-level suppress, matching `tls-verify-disabled`'s convention — not per-line, since the
   flagged `env=` can be several lines below the pragma-bearing call).
5. **Severity/standards:** `high`, `["OWASP-LLM:LLM02", "CWE-200"]`. Rule id:
   `mcp-tool-env-inheritance/full-env-forwarded`.

## When NOT to flag

- **No `env=` at all on `StdioServerParameters`.** The MCP SDK's own default is already the safe,
  minimal environment — the guard fires only on an *explicit* widening back to the dangerous
  case, never on the absence of an override.
- **An explicit, minimal env dict** (`env={"PATH": os.environ["PATH"]}`) — assembling a named
  subset by hand is exactly the fix this guard is asking for, and does not match `_FULL_ENV`
  (the pattern requires `os.environ`/`dict(os.environ)`/`{**os.environ` to appear immediately
  after `env=`, not a value merely *built from* `os.environ` elsewhere).
- **`env=None`**, or any subprocess call with no `env=` kwarg — deliberately out of scope; see
  "What this guard does NOT prove."
- **A normal subprocess call unrelated to a tool/server spawn** — the `_SPAWN_CALL` gate only
  matches the specific constructor/functions above, so a plain `subprocess.run(["git", "status"])`
  with no `env=` never enters the `_FULL_ENV` check at all.

Use the pragma `# security: allow-mcp-tool-env-inheritance` for an audited, intentional case
(e.g. a fully sandboxed subprocess with genuinely no secrets in the parent env).

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_stdio_server_parameters_os_environ` | `StdioServerParameters(..., env=os.environ)` fires |
| `test_fires_on_multiline_call_with_env_copy` | multi-line call, `env=` several lines below the opener — the context-window match |
| `test_fires_on_subprocess_popen_dict_os_environ` | `subprocess.Popen(..., env=dict(os.environ))` fires |
| `test_fires_on_env_spread_merge` | `env={**os.environ, ...}` fires (the "add one var" mistake) |
| `test_silent_on_no_env_kwarg` | FP-bait: no `env=` at all on `StdioServerParameters` (SDK's safe default) stays silent |
| `test_silent_on_scoped_env_dict` | FP-bait: an explicit minimal `env={"PATH": ...}` stays silent |
| `test_silent_on_env_none` | FP-bait: `env=None` stays silent |
| `test_silent_on_unrelated_subprocess_call` | FP-bait: a plain subprocess call with no `env=` at all stays silent |
| `test_pragma_suppresses` | the inline pragma silences the finding |
| `test_not_applicable_without_mcp_feature` | `applies()` is False without the `mcp` feature |
| `test_applicable_with_mcp_feature` | `applies()` is True with the `mcp` feature |

## Known bypasses

- **Implicit full-env inheritance is out of scope.** A bare `subprocess.Popen(cmd)` with no
  `env=` at all *also* inherits the full parent environment (stdlib's own default, unlike the
  MCP SDK's safe default) — but flagging every subprocess call lacking an `env=` kwarg would be
  enormous noise (git, ffmpeg, any ordinary shell-out), so this guard only catches the *explicit*
  widening, not the *implicit* one. A repo whose tool-spawning code never explicitly sets `env=`
  at all gets no signal from this guard either way.
- **Context-window mis-attribution.** The bounded 15-line lookahead can occasionally attribute an
  `env=os.environ` a few lines below to the wrong nearby call if two spawn calls sit close
  together with no `env=` on the first — a rare code-density edge case, not the common shape.
- **Indirection.** `env = os.environ.copy(); env["EXTRA"] = "x"; subprocess.Popen(cmd, env=env)`
  builds the dangerous dict on a separate line, then passes a bare variable name — the guard has
  no data-flow tracking and does not follow the assignment back to its source.
- **Non-Python MCP servers/tools.** TypeScript/Node MCP servers using
  `child_process.spawn(cmd, {env: process.env})` are not covered — this guard is Python-source
  only in v1.
- **Aliased imports.** `import subprocess as sp; sp.Popen(..., env=os.environ)` is not matched —
  `_SPAWN_CALL` looks for the literal `subprocess.` prefix.

## What this guard does NOT prove

- That the subprocess, once scoped correctly, is otherwise sandboxed (filesystem access, network
  egress, resource limits) — this guard only checks what environment variables it receives.
- That a subprocess with a *scoped* env dict was scoped to the *right* variables — an
  `env={"OPENAI_API_KEY": key, "STRIPE_SECRET": key}` passing two unrelated secrets to a
  filesystem tool is silent here; the guard checks for full-inheritance, not over-broad-but-partial
  scoping.
- That the underlying deployment has any of the stronger patterns (network-layer credential
  brokering, per-tool scoped proxies, short-lived dynamic credentials) that close the exfiltration
  gap architecturally — those are deployment decisions invisible to static source scanning, and
  stay out of scope for a guard the same way CSRF and rate-limiting do.

# Citations

[1] agentsec checklist item `4-mcp-tool-env-inheritance` (§4)
[2] CWE-200
[3] OWASP-LLM:LLM02
