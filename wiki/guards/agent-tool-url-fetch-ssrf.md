---
type: Guard
title: "agent-tool-url-fetch-ssrf"
description: "Agent tool wraps a URL-fetching sink (WebBaseLoader, requests/httpx/urlopen, sibling LangChain URL loaders) with an unvalidated, non-literal URL."
timestamp: "2026-08-22T00:00:00+08:00"
guard_id: "agent-tool-url-fetch-ssrf"
checklist_section: ["3a"]
standards: ["OWASP-LLM:LLM02", "OWASP-LLM:LLM06", "OWASP:A10"]
---

# Agent tool wraps a URL-fetching sink with an unvalidated, non-literal URL

_Author — 2026-07-12; extended 2026-08-22_

---

## The threat

An agent tool that wraps `WebBaseLoader` (`langchain_community.document_loaders.WebBaseLoader`)
performs a server-side HTTP GET against whatever URL it is constructed with. When the URL is a tool
parameter or any other value the LLM decides at call time — rather than a hardcoded, developer-chosen
string — a prompt injection (from a retrieved document, a user message, or a poisoned upstream tool
result) can instruct the agent to fetch an internal service or the cloud metadata endpoint
(`http://169.254.169.254/`), or to encode sensitive data into the URL of an attacker-controlled host
for exfiltration. WHO: anyone who can influence the agent's reasoning context (a user message, or
content the agent retrieves/reads). WHAT PRIVILEGE: none beyond normal use of the agent. WHAT EFFECT:
SSRF against internal infrastructure/cloud metadata, or covert data exfiltration. OWASP:A10 (SSRF) /
CWE-918; OWASP-LLM:LLM06 (Excessive Agency) for the agent-controlled fetch.

This class of vulnerability — a known-risky tool class whose URL/parameter is agent-controlled — is
catalogued generically by external agent-framework static analyzers; `WebBaseLoader` specifically is
named (matched by exact tool name, category `document_loader`, tagged "Unrestricted External Access
leading to SSRF" + "Data Exfiltration") in `splx-ai/agentic-radar`'s tool-vulnerability registry
(`agentic_radar/mapper/vulnerabilities.json`, verified by fetching the raw file this session).

## Why it's often introduced

`WebBaseLoader` is the standard LangChain way to pull a webpage into a RAG pipeline, and it is easy to
promote from "load this one known doc URL" to "let the agent choose which page to read" by wrapping the
same loader in a `@tool`-decorated function that takes a `url` parameter:

```python
from langchain_community.document_loaders import WebBaseLoader

@agent.tool
async def fetch_page(ctx, url: str) -> str:
    loader = WebBaseLoader(url)          # url is whatever the LLM passes
    return loader.load()[0].page_content
```

Nothing here looks unusual in review — it reads like any other RAG ingestion snippet — but the fetch now
runs with a URL the model (and therefore an attacker who can influence the model) controls.

## Detection design

1. **`applies()` gate:** `"llm" in profile.features` — same gate as the sibling multi-agent/MCP/tool
   guards; this is an LLM-agent-specific pattern.
2. **Files scanned:** all `.py` files under `python_scan_dirs(root, profile)`, via `iter_files`, skipping
   non-product paths (`is_nonproduct_path`).
3. **Patterns (co-occurrence, mirroring `agent-tool-overpermission`'s `subprocess-in-agent-tool` rule):**
   the SAME file must contain BOTH:
   - a tool-registration marker: `@\w+\.tool\b`, `class \w+(BaseTool)`, `Tool(name=`, or
     `StructuredTool.from_function(`;
   - a `WebBaseLoader(...)` construction (or a call to a locally aliased name — `from ... import
     WebBaseLoader as WBL` is tracked so `WBL(url)` is still recognised) whose argument is **not** a pure
     string literal (or a list/tuple of only string literals). The literal check strips a single leading
     `keyword=` prefix, removes quoted string-literal tokens, and treats any leftover identifier/expression
     text (after stripping brackets/commas/whitespace) as dynamic. An f-string containing an interpolation
     brace (`f"http://{host}"`) is always treated as dynamic, even though it is textually quoted.
   - AND no allowlist/validation marker anywhere in the file (`allowed_domains`, `allowlist`,
     `allow_list`, `whitelist`, `urlparse`, `netloc`, `validate_url`, `is_allowed_domain`,
     `ALLOWED_HOSTS`, `allowed_hosts`).
4. **Pragma:** `# security: allow-tool-url-fetch-ssrf` (checked anywhere in the file) silences the
   finding for that file.
5. **Severity/rule/standards:** HIGH, `rule="agent-tool-url-fetch-ssrf/webbaseloader-dynamic-url"`,
   `standards=["OWASP:A10", "OWASP-LLM:LLM06"]`.

## When NOT to flag

- `WebBaseLoader("https://docs.example.com/page")` — a literal URL, or a list of only literal URLs —
  stays silent regardless of tool-registration context; this is the normal fixed-ingestion pattern.
- `WebBaseLoader(url)` in a file with **no** tool-registration marker anywhere (a plain RAG-ingestion
  script where a developer, not the agent, chooses the URL) — different, much lower-risk shape, silent.
- Any file containing an allowlist/validation marker — the guard cannot prove the marker actually gates
  the fetch before it runs, but it is the documented escape hatch (see Known bypasses).
- Suppress a reviewed, intentional case with `# security: allow-tool-url-fetch-ssrf`.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_dynamic_url_in_tool` | Planted violation: `@agent.tool` function passes a bare `url` param straight into `WebBaseLoader(url)` — fires. |
| `test_fires_on_dynamic_kwarg_url` | Same violation via the `web_path=` keyword form — fires. |
| `test_fires_on_list_wrapped_variable` | A list literal wrapping a variable (`[target]`) is still dynamic — fires (guards against the naive "it's inside brackets" miss). |
| `test_fires_on_fstring_url` | An f-string with an interpolated host (`f"http://{host}/status"`) is dynamic despite being textually quoted — fires. |
| `test_fires_on_aliased_import_bypass` | Adversarial bypass check: `WebBaseLoader as WBL` then `WBL(url)` — still fires (the alias-tracking regex). |
| `test_silent_on_literal_url` | FP-bait: a hardcoded literal URL inside a `@tool` function — silent. |
| `test_silent_on_literal_url_list` | FP-bait: a list of only literal URLs — silent. |
| `test_silent_without_tool_registration` | FP-bait: a plain ingestion script with a dynamic `url` param but no tool-registration marker anywhere in the file — silent. |
| `test_silent_when_allowlist_marker_present` | FP-bait: an `ALLOWED_HOSTS` constant present anywhere in the file — silent (see Known bypasses for the honest limit here). |
| `test_pragma_suppresses` | The inline pragma silences the file. |
| `test_not_applicable_without_llm_feature` / `test_applicable_with_llm_feature` | `applies()` gating on `profile.features`. |

## Known bypasses

- **Allowlist marker is a text search, not a control-flow proof.** A file with an unused
  `ALLOWED_HOSTS` constant defined but never actually consulted before the fetch will silence a
  genuinely unguarded call — same class of limitation as every other "trust marker nearby" guard in
  this codebase (e.g. `mcp-tool-unverified`).
- **Multi-file wrapping.** If the `@tool` function lives in one module and imports a `fetch()` helper
  from another module that constructs `WebBaseLoader`, the co-occurrence check (same-file only) misses
  it — same limitation as `agent-tool-overpermission`'s `subprocess-in-agent-tool` rule.
- **Indirection through several variables.** `raw = url; safe = raw; WebBaseLoader(safe)` is still
  caught (the literal check only exempts pure string literals), but a value laundered through an
  unrelated-looking function call before reaching `WebBaseLoader` is not specially tracked — it is
  simply "not a literal," so it still fires correctly; the real gap is the reverse direction: nothing
  disproves that a *dynamic-looking* argument is actually always safe.
- **Only `WebBaseLoader` and its direct import aliases are covered.** Sibling LangChain URL-fetching
  loaders (`AsyncHtmlLoader`, `SeleniumURLLoader`, `PlaywrightURLLoader`) share the same SSRF shape but
  are not in this guard's name list — `WebBaseLoader` is the one specific name verified against
  agentic-radar's real tool-vulnerability registry this session; widening the list is a natural,
  low-risk follow-up but was kept out of scope here to stay strictly evidence-backed.

## What this guard does NOT prove

Silence does not prove the fetch is safe — it only means neither a tool-registration marker, a dynamic
`WebBaseLoader` argument, nor the absence of an allowlist marker were all present together in the same
file. A genuinely dangerous pattern split across files, gated by a marker that doesn't actually validate
the host, or built on a different URL-fetching loader class entirely, will not be caught. The fix is
still the real control: an explicit host/domain allow-list enforced in code, plus RFC-1918/link-local/
metadata-IP blocking (resolve the host, then check) before the fetch executes.

## 2026-08-22 — widened to general-purpose HTTP-client and sibling LangChain URL-loader sinks

The checklist item this guard maps to (`3a-ssrf-guard`, "SSRF guard on all URL-accepting
endpoints") only had `WebBaseLoader` recognized as a sink. A bare-tool-parameter call like
`requests.get(url)` inside an `@agent.tool` function was silent: `agent-tool-url-fetch-ssrf`
didn't match `requests.get`, and the separate `ssrf-general` guard (different checklist item,
`3a-ssrf-general`) deliberately does not fire on a bare-variable URL argument — so the exact
LLM-controlled-URL scenario this checklist item cares about fell through both guards. This was
an acknowledged, already-documented limitation ("Known bypasses" above, and the guard's own
docstring) — widening the sink list was flagged as a natural, low-risk follow-up kept out of
the original scope to stay strictly evidence-backed.

**New pattern (HIGH): `agent-tool-url-fetch-ssrf/http-client-dynamic-url`.** Same co-occurrence
shape (tool-registration marker + no allowlist marker, same file) widened to:

- `requests.get/post/put/delete/head/patch/options/request(...)`
- `httpx.get/post/put/delete/head/patch/options/request(...)`
- `urllib.request.urlopen(...)` / a bare `urlopen(...)`
- `AsyncHtmlLoader(...)`, `SeleniumURLLoader(...)`, `PlaywrightURLLoader(...)` (and their
  tracked `... as Alias` import aliases) — sibling LangChain URL loaders, judged the same
  whole-argument-literal way `WebBaseLoader` already is.

**URL-argument isolation (the http-client-specific FP guard):** for the `requests.*`/
`httpx.*`/`urlopen` sinks, only the URL argument itself is inspected — the first positional
argument, or an explicit `url=` keyword — never unrelated kwargs (`json=`, `params=`,
`headers=`, `data=`, ...). These are general-purpose HTTP clients where a literal, fixed URL
with a dynamic body/params/headers kwarg is a completely ordinary, safe pattern
(`requests.post("https://hooks.slack.com/services/XXX", json=payload)`); judging the whole
call's argument blob (as `WebBaseLoader`'s check does, safely, because its own kwargs are
scalar) would have made this common shape a false positive. This is the same #423
benign-kwarg lesson, extended: a *dynamic* unrelated kwarg must not make an otherwise-literal
URL argument look dynamic, just as a *benign scalar* kwarg must not either.

**Path-vs-host distinction for f-strings:** an f-string URL argument whose interpolation
braces occur only AFTER a literal `scheme://host/` prefix (e.g.
`f"https://api.example.com/resource/{resource_id}"`) is treated as a dynamic PATH segment on
an otherwise-fixed, developer-controlled host — NOT flagged. An interpolation in the host
position itself (`f"http://{host}/status"`), or an f-string with no literal scheme+host prefix
at all before the first brace, is still treated as dynamic and fires.

**Known false positive (review M8, 2026-09-03):** `_LITERAL_SCHEME_HOST_PREFIX` requires the
scheme AND host to be a literal string before the first brace — `f"{BASE_URL}/resource/{id}"`
does NOT qualify (the string opens on a brace, so there is no literal prefix at all) and DOES
fire, even though `BASE_URL` is typically a fixed, developer-controlled module constant, not
attacker input. This is the dominant real-world REST-client idiom, so it is a live source of
noise, not a hypothetical one; an earlier draft of this doc incorrectly claimed this exact
shape was covered by the exemption above. Until the guard can distinguish a constant-bound
name from a genuinely dynamic one, suppress a confirmed-fixed `BASE_URL` with
`# security: allow-tool-url-fetch-ssrf` or the allowlist-marker convention.

**Canary:** the new rule owns its own plant file (`web_fetch_tool_http_client.py`, on the
guard's `canary_plant.files` — #617 convention, every guard owns its plant) — a bare
`@agent.tool` parameter passed straight into `requests.get(...)`, no allowlist marker. The
pre-existing `WebBaseLoader` rule stays EXPECTS-ONLY against the shared `web_fetch_tool.py`
base file, unchanged.

**Tests added** (`tests/guards/test_agent_tool_url_fetch_ssrf.py`):

| Test | What it checks |
|---|---|
| `test_fires_on_bare_requests_get_url_in_tool` | Planted violation — THE gap this closes: bare tool parameter straight into `requests.get(url)`. |
| `test_fires_on_bare_httpx_post_url_in_tool` | Same shape on `httpx.post`. |
| `test_fires_on_bare_urlopen_url_in_tool` | Same shape on a bare `urlopen(url)`. |
| `test_fires_on_sibling_url_loader_dynamic_url` | `AsyncHtmlLoader([url])` — a sibling LangChain loader, not just `WebBaseLoader`. |
| `test_fires_on_fstring_host_position_http_client` | An f-string with the interpolation in HOST position still fires on the widened sinks. |
| `test_silent_without_tool_registration_http_client` | FP-bait: no tool-registration marker — silent, mirroring the `WebBaseLoader` co-occurrence requirement. |
| `test_silent_when_allowlist_marker_present_http_client` | FP-bait: an `ALLOWED_HOSTS` marker anywhere in the file — silent. |
| `test_pragma_suppresses_http_client` | The inline pragma silences the widened sinks too. |
| `test_silent_on_literal_url_with_dynamic_kwarg_http_client` | FP-bait: the main new FP risk — literal, fixed URL + a dynamic `json=` payload kwarg (Slack-webhook-style call) — silent. |
| `test_silent_on_fstring_path_segment_only_http_client` | FP-bait: an f-string interpolating only a path segment on a literal, fixed host — silent. |
| `test_silent_on_literal_url_http_client` | FP-bait: a plain hardcoded literal URL — silent. |

**Known bypass added by this widening:** a module-level constant assigned a literal URL
elsewhere in the file (`SLACK_WEBHOOK_URL = "https://..."`, then referenced later as a bare
name, e.g. `requests.post(SLACK_WEBHOOK_URL, json=payload)`) is textually indistinguishable
from a tool parameter and is judged dynamic like any other bare identifier — no cross-line
dataflow tracking. This is the same accepted limitation `WebBaseLoader`'s own bare-variable
case already documents; closing it would require AST-level dataflow analysis, out of scope
for this text/regex-based guard.

**What is still NOT closed (checklist status stays `partial`):** this widening only closes
the *sink-coverage* half of the gap (which functions can leak a dynamic URL). It does not
address the secondary gap already named in "Known bypasses" above: the allowlist-marker
suppression is a whole-file text search, not verification that the file's validation logic
actually blocks RFC-1918 / link-local / metadata ranges before the fetch. The checklist item's
title ("block RFC1918, link-local, metadata") describes an *enforcement* guarantee this guard
does not, and was never designed to, verify — it only detects the absence of an unvalidated
dynamic fetch and the absence of any validation marker. `3a-ssrf-guard` stays `status: partial`
in `checklist.json` for that reason.

# Citations

[1] agentsec checklist item `3a-ssrf-guard` (§3a)
[2] OWASP-LLM:LLM02
[3] OWASP-LLM:LLM06
[4] OWASP:A10
