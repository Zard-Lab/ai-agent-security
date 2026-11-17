---
type: Guard
title: "mcp-tools-list-unbounded"
description: "MCP tool catalogue assembled from an unbounded upstream tools/list response."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "mcp-tools-list-unbounded"
checklist_section: ["4"]
standards: ["CWE-400", "OWASP-ASI:ASI04"]
---

# MCP tool catalogue assembled from an unbounded upstream response

_Author — 2026-09-22_

---

## The threat

An MCP client or aggregator that talks to multiple configured servers asks each one for its
tools (`tools/list`) and assembles one combined catalogue from the responses. In a naive
implementation, nothing bounds what an upstream server may answer with — the size of the
resulting allocation (how many tools, how large each tool's input schema) is chosen entirely by
whoever controls the upstream server, not by the aggregator itself.

**CVE-2026-84289** is the real-world instance: Hermes Agent's `list_tools` in
`tools/mcp_tool.py` reads every tool from every configured server, keeps the name, description,
and full input schema for each, and returns the lot — no cap on count, no cap on schema size.
CWE-400 (Uncontrolled Resource Consumption) / CWE-789 (Uncontrolled Memory Allocation). WHO
reaches this: any MCP server the aggregator connects to — including one added by a user, or a
compromised/malicious server on an otherwise-legitimate registry. WHAT privilege: the ability to
make the aggregator allocate memory proportional to whatever the attacker sends back. TO WHAT
EFFECT: a memory-exhaustion denial of service against the aggregator process, or — if the
oversized catalogue is later serialized/logged/rendered without its own bound — a secondary
amplification into whatever consumes that catalogue next.

## Why it's often introduced / Why this guard fits the stack

The `tools/list` request/response pair is designed to be simple: ask, get a list back, use it.
Nothing about the protocol itself signals "this response might be adversarial" — a developer
writing the aggregation loop is thinking about the happy path (a well-behaved server returning a
handful of tools), not about a hostile or misconfigured upstream returning thousands of
megabyte-sized tool schemas. This is architecturally the same class of bug as an unbounded
inbound request body, just facing the opposite direction — and because agentsec already has a
guard for the inbound case (`request-body-size-unbounded`/`llm-input-size-cap`), it's easy to
assume that coverage extends here. It doesn't: those guards bound what a CALLER sends TO this
server; this guard bounds what an UPSTREAM sends back when this server acts as an MCP CLIENT.

```python
async def list_tools(server_url: str) -> list[dict]:
    tools = []
    resp = await httpx.get(server_url + "/tools")
    for tool in resp.json()["tools"]:   # however many the upstream feels like sending
        tools.append(tool)              # each one however large the upstream feels like making it
    return tools
```

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`.
2. **Files scanned:** `iter_files(root, (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"))` —
   cross-language, same set the guard's siblings use.
3. **Comment stripping (TS/JS only):** `_strip_comments()` removes block and line comments
   before matching, so a comment mentioning any of the signal words below cannot mask (or
   falsely trigger) the check. Python is left as-is — its comment syntax (`#`) doesn't
   collide with any of the regex patterns used here the way `//`/`/* */` could.
4. **Three co-occurring signals, ALL required, same file:**
   - **Discovery site** (`_TOOLS_LIST_RE`): `def list_tools`/`async def list_tools`,
     `list_tools(`, `ListToolsRequestSchema`, the literal `"tools/list"`, or `listTools(`.
   - **Remote source** (`_REMOTE_SOURCE_RE`): the collection comes off the wire, not out of a
     literal in this file — `.json()`, an awaited client/session/resp/response/http-prefixed
     call, `httpx.`, `requests.get(`/`requests.post(`, `fetch(`, or `axios.`.
   - **Accumulation** (`_ACCUMULATE_RE`): `.append(`, `.extend(`, `.push(`, `.map(`, a `for`
     loop, or `.concat(`.
   - **Python scope (PR #923 rounds 1-3).** In Python the three signals must share ONE function:
     the discovery function's own body, plus (one hop) the body of every same-file helper it
     calls by bare name AND whose result it uses (returned, assigned, iterated, or passed on).
     A helper called as a bare statement (`record_metrics(tools)` or `await
     record_metrics(tools)` on its own line) discards its result, so it is joined in only when it
     fills a parameter the caller passed in (`param.append(...)`/`.extend`/`.insert`/`.add`/
     `.update`/`.setdefault`, `param[k] = v`, `param += ...`): the out-parameter idiom
     `_fetch_into(tools, url)`. A metrics helper that accumulates into its OWN local is not
     joined in. TS/JS stays a whole-file co-occurrence check.
   - **TS/JS live code (#1055).** Each of the three signals must start in live code on the shared
     anchor mask (`strip_js_comments(..., strip_strings=True, keep_substitutions=True)`),
     including code inside a `${...}` substitution. The literal `'tools/list'` anchors on its
     opening quote, which a real literal keeps and a quote inside prose does not. A docs string
     such as `'listTools( then fetch( then .push( is the pattern'` no longer fires, and the
     reported line is the first LIVE discovery site (it used to come from the raw text, so a
     commented or quoted copy above the real one won).
5. **Bound check (`_BOUND_RE`) — any ONE of these anywhere in the file silences the finding:**
   a slice (`tools[:200]`), `.slice(0, ...)`, `islice(`, a `len(...)`/`.length` comparison, a
   `MAX_`/`max_`-prefixed identifier, `limit`/`cap`/`truncat*`, or a `break` statement.
   In TS/JS (#1055) the bound must start in live code, or in a string literal whose content is
   one identifier-shaped token (`process.env['MAX_TOOLS']`, `{ 'limit': 50 }`), the rule
   `mcp-toolgate-asymmetry` applies to its gate (Python H-7b). Every match is tried, so a prose
   copy first cannot hide a real bound after it. Prose no longer bounds: `'no limit configured'`
   or `` `no limit for ${UPSTREAM}` `` used to silence the finding. Neither does a `limit` inside
   a URL (`'/tools?limit=100'`): a query parameter asks the upstream for fewer tools, and the
   upstream still decides.
6. **Deliberately narrow conjunction.** "Builds a list of tools" alone describes every MCP
   client ever written — the real source's own docstring makes this explicit. What makes it a
   finding is specifically that the collection being accumulated came off the wire AND nothing
   bounds it; adding any one bound signal silences the rule, which is what the FP-bait tests
   assert.
7. **Inline opt-out pragma:** `# security: allow-mcp-tools-list-unbounded`, file-level. It is
   matched as a plain substring, so the `// security: ...` form works in a TS/JS file.
8. **Severity/standards:** `high`, `["CWE-400", "OWASP-ASI:ASI04"]`. Rule id:
   `mcp-tools-list-unbounded/no-catalogue-bound`.

## Why this is not `AAK-MCP-016`/`request-body-size-unbounded` (verified, not assumed)

Before building this, the real source's own docstring was checked against a different-seeming
candidate (`AAK-MCP-016`, whose text is *"An MCP server endpoint accepts request bodies without
a maximum-size limit"*) — confirmed to be the INBOUND direction, a value a caller sends TO this
process. This rule's allocation is driven by the UPSTREAM RESPONSE, arriving from the opposite
direction, that no inbound body-size limit ever touches. The real source's author scanned the
disclosed CVE-2026-84289 shape against their whole engine before writing this rule and confirmed
nothing else fired — ported here on the same verified basis (agentsec's own
`request-body-size-unbounded`/`llm-input-size-cap` were checked directly and confirmed to be
inbound-only, not assumed).

## When NOT to flag

- **A tool catalogue built from a local literal**, not a remote response — no `_REMOTE_SOURCE_RE`
  signal, so the file never reaches the bound check at all.
- **A remote-response aggregation with no `tools/list`-shaped discovery marker** — unrelated
  data-fetching code (e.g. a log aggregator) that happens to share the fetch+accumulate shape.
- **Any bound present anywhere in the file** — a slice, a length comparison, a `MAX_`-prefixed
  constant, `limit`/`cap`/`truncat*`, or a `break`.
- An audited, intentional case suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_unbounded_python_aggregation` | Fires: `list_tools()` accumulates an upstream JSON response with no bound anywhere — CVE-2026-84289's own shape |
| `test_fires_on_unbounded_ts_aggregation` | Fires: the same shape in TypeScript |
| `test_bounded_with_slice_is_safe` | FP-bait: `tools[:200]` anywhere in the file silences it |
| `test_bounded_with_length_check_is_safe` | FP-bait: a `len(tools) > MAX_TOOLS` + `break` bound silences it |
| `test_local_literal_source_is_safe` | FP-bait: a catalogue built from a local literal (no remote-source signal) stays silent |
| `test_no_discovery_site_is_safe` | FP-bait: a fetch+accumulate file with no `tools/list` discovery marker stays silent |
| `test_delegating_list_tools_wrapper_still_fires` | still-fires: `return helper(url)` where the helper fetches and accumulates |
| `test_delegating_list_tools_that_uses_the_result_still_fires` | still-fires: the helper's result assigned from an `await`, or passed to `.extend(...)` |
| `test_static_registry_calling_an_unrelated_batching_helper_is_safe` | FP-bait: a static registry that calls a batching/posting helper as a bare statement (sync and awaited) |
| `test_bare_call_to_a_helper_that_fills_the_callers_list_still_fires` | still-fires: a bare call to a helper that fills the caller's list/dict (append, awaited, subscript, `+=`) |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` is False without the `mcp` feature |
| `test_guard_applicable_with_mcp_feature` | `applies()` is True with the `mcp` feature |
| `test_nonproduct_path_skipped` | files under `tests/fixtures/` are skipped |
| `test_ts_quoted_bound_no_longer_clears` | #1055 FN direction: a bound word in a string, template text or URL query no longer silences it |
| `test_ts_real_bound_still_clears` | a real bound still silences: code, a one-identifier env/config key, one nested in `${...}`, one after a prose copy |
| `test_ts_signal_spelled_in_a_string_does_not_fire` | #1055 FP direction: discovery/fetch/accumulation named in a docs or log string do not count |
| `test_ts_signals_in_a_substitution_still_fire` | the remote source and accumulation inside `${...}` still count |
| `test_ts_finding_line_is_the_first_live_discovery_site` | the reported line skips a quoted copy of `listTools(` above the real site |
| `test_ts_pragma_still_suppresses_a_live_finding` | the `//` pragma silences a live finding (fire-then-silence pair) |

## Known bypasses

- **Same-file only.** All four signals (discovery, remote source, accumulation, and any bound)
  must appear in the SAME file. A bound implemented in a helper function in a different module
  (`tools = cap_catalogue(raw_tools)`) is not recognized — the guard has no cross-file
  resolution, matching every other regex-based guard's documented limitation.
- **One hop, and only by use.** A helper that itself delegates further (two hops) is not
  followed. Conversely, a helper whose result `list_tools()` uses for something unrelated
  (`count = record_metrics(tools)`) is still joined in, which can fire on a static registry.
- **Non-literal bound markers.** A bound expressed through a variable whose name doesn't match
  `MAX_`/`max_`/`limit`/`cap` (e.g. `n = config.tool_ceiling`) is not recognized as a bound.
- **Bound applied AFTER the vulnerable window.** The check is presence-based across the whole
  file, not control-flow-aware — a bound that exists in the file but doesn't actually run before
  the unbounded accumulation completes (e.g. a dead code path, or a bound applied only in an
  error branch) still silences the finding.
- **Unlisted discovery/remote-source/accumulate idioms.** All three signal regex sets are
  curated; an unusual client library, a GraphQL-style tool query, or a non-standard accumulation
  idiom (e.g. `functools.reduce`) is not recognized.
- **TS/JS string anchoring (#1055).** The signals and the bound used to match string text, so
  `const E = 'no limit configured'` silenced a HIGH and a docs string naming the three calls
  fired one. They now need a live-code anchor (the bound may also be a one-identifier string).
  Accepted residuals: a one-token literal holding a bound word (`log('truncated')`, `'break'`)
  still bounds, as on main; the Python branch still reads the raw text, so a `# TODO limit`
  comment silences it (a separate defect, out of scope for #1055); and the anchor mask inherits
  the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then
  a `}` in a later one, rebalances the frame, so the code between the two reads as template text
  and an anchor there is not code (the accepted trade pinned by
  `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`).

## What this guard does NOT prove

- That a recognized bound marker actually caps the SPECIFIC accumulation this guard flagged —
  see "Bound applied after the vulnerable window" above.
- That the bounded catalogue, once capped, is safe to use downstream — a capped-but-still-large
  tool schema can still carry a malicious description (see `mcp-tool-description-injection`,
  a separate, already-covered concern).
- That every MCP aggregation surface in the repo is covered — this guard only recognizes the
  curated `tools/list` discovery-site vocabulary; a custom aggregation protocol layered on top
  of MCP is out of scope.

# Citations

[1] agentsec checklist item `4-mcp-tools-list-unbounded` (§4)
[2] CWE-400
[3] OWASP-ASI:ASI04
[4] CVE-2026-84289 (Hermes Agent, unbounded MCP tool-catalogue accumulation)
[5] agent-audit-kit (sattyamjjain/agent-audit-kit), `mcp_tools_list_unbounded.py`
