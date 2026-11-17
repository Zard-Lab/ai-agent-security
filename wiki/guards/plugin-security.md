---
type: Guard
title: "plugin-security"
description: "LLM tool/plugin definition missing security controls."
timestamp: "2026-10-01T18:19:05+00:00"
guard_id: "plugin-security"
checklist_section: ["2b", "4"]
standards: ["OWASP-LLM:LLM06", "OWASP:A01", "OWASP:A03"]
---

# LLM tool/plugin definition missing security controls

_Marconi Sim — 2026-06-28_

---

## The threat

LLM-callable tools are the primary attack amplifiers in agentic systems. Four distinct
security gaps at the tool definition boundary enable escalating impact:

**PLG003 (HIGH) — Confused deputy / missing auth (OWASP-LLM:LLM06, OWASP:A01):**
An @tool decorated function accesses a database, filesystem, or external API without verifying
who invoked it. The LLM controls the tool's arguments at runtime. A prompt-injected agent or
a low-privilege user can supply arbitrary arguments to a tool that trusts the LLM's context
rather than the authenticated end-user's identity — the tool "acts for" the wrong principal.
Concrete attack: a retrieval tool calls `db.query(User)` with no user scope; a malicious
document in the knowledge base instructs the agent to call the tool with another user's ID.

**PLG001 (MEDIUM) — Unvalidated tool input (OWASP-LLM:LLM01, OWASP:A03):**
An @tool function accepts `dict` or `Any`, or a bare untyped parameter. LLMs generate tool
arguments from natural language — without a Pydantic schema the model may supply malformed,
oversized, or adversarially crafted JSON that bypasses expected constraints downstream.

**PLG005 (HIGH) — Wildcard capabilities in plugin manifest (OWASP-LLM:LLM06, OWASP:A01):**
A JSON or YAML plugin manifest declares `"capabilities": "*"` or `"permissions": ["*"]`.
Wildcard capability scopes violate least-privilege and give a prompt-injected plugin
unrestricted access to whatever the manifest governs.

**PLG007 (MEDIUM) — Tool data overexposure (OWASP-LLM:LLM02, OWASP:A01):**
An @tool returns `.dict()` or `.model_dump()` on an ORM/Pydantic model without field
filtering. ORM models typically include sensitive internal fields (password_hash, api_key,
billing_id). Returning them whole leaks these fields into the LLM context window — which
may be logged, cached, or exfiltrated via a prompt injection continuation. (`.json()` is
deliberately NOT matched — it is the universal `response.json()` HTTP body-parse idiom.)

**PLG008 (HIGH) — Tool auth parameter bound to a shared service identity (OWASP-LLM:LLM06,
OWASP:A01):** An @tool makes a sensitive call AND carries an auth-named parameter (so PLG003
stays silent), but that parameter's own default value is a hardcoded/shared SERVICE
credential — a bare `SCREAMING_SNAKE_CASE` module constant, or an `os.getenv(...)` /
`os.environ[...]` lookup — rather than a per-request injection (`Depends(...)`, `Header(...)`,
`Security(...)`). PLG003 only checks whether an auth-shaped NAME is present in the signature;
it never inspects what that parameter is actually BOUND to. This closes the narrow, fully
static slice of that blind spot: a tool can satisfy PLG003's name check while still
authenticating every caller as the same static service principal (confused deputy) — visible
by reading the parameter's own default-value expression in source text, no dataflow needed.

Standards (per rule): PLG003 + PLG005 + PLG008 are excessive-agency / least-privilege failures
(`OWASP-LLM:LLM06`, `OWASP:A01`); PLG001 is adversarial tool-input / injection
(`OWASP-LLM:LLM01`, `OWASP:A03`); PLG007 is sensitive-information disclosure
(`OWASP-LLM:LLM02`, `OWASP:A01`).

---

## Why it's often introduced / Why this guard fits the stack

In FastAPI + pydantic-ai / LangChain apps, developers write @tool decorated functions
rapidly and focus on the "happy path" of tool functionality without thinking about the
security implications of the LLM controlling arguments.

Bad pattern (PLG003):
```python
@agent.tool
def get_user_files(query: str) -> list:
    return db.query(File).filter(File.name.contains(query)).all()
    # No user scope — LLM can retrieve any file from any user
```

Bad pattern (PLG001):
```python
@agent.tool
def search(params: dict) -> list:  # LLM can pass arbitrary structure
    return index.search(**params)
```

Bad pattern (PLG005 — manifest):
```json
{"name": "my-plugin", "capabilities": "*"}
```

Bad pattern (PLG007):
```python
@agent.tool
def get_profile(user_id: str) -> dict:
    return db.query(User).get(user_id).model_dump()  # exposes password_hash etc.
```

Bad pattern (PLG008 — the name looks like auth, the value is a shared service secret):
```python
SERVICE_API_KEY = os.environ["SERVICE_API_KEY"]  # one static value for every caller

@agent.tool
def get_data(query: str, api_key: str = SERVICE_API_KEY) -> list:
    return cursor.execute(query).fetchall()
    # `api_key` satisfies PLG003's name check, but every caller — legitimate or
    # prompt-injected — authenticates this call with the SAME service credential.
```

---

## Detection design

1. **applies() gate:** `"llm" in profile.features` — only fires on repos with LLM/agent tooling.

2. **Files scanned:**
   - PLG003, PLG001, PLG007: Python files via `python_scan_dirs(root, profile)` + `iter_files(..., (".py",))`
   - PLG005: JSON and YAML files via `iter_files(root, (".json", ".yaml", ".yml"))` filtered by
     name patterns: `plugin*.json/yaml`, `tools*.json/yaml`, `tool-manifest*.json/yaml`,
     `ai-plugin.json`, `openapi*.json/yaml`, `api-spec*.json/yaml`

3. **Patterns:**
   - Decorator detection: `r"@(?:\w+\.)*tool\s*[\(\n]"` on a line
   - Function signature: `r"^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)"` on subsequent lines
   - PLG003: sensitive call in the bounded function body (`db.query`, `cursor.execute`, `open(`,
     real `os.*` filesystem ops [open/remove/unlink/rename/mkdir/listdir/...], `requests.*`,
     `httpx.*`) AND no auth param in signature (`current_user`, `user_id`, `user`, `auth`,
     `token`, `api_key`, `requester`). NB: bare `os.path.*` (path construction) is NOT a sink.
   - PLG001: `dict` / `Dict` / `Any` annotation in signature, OR a bare untyped parameter name
     (the `*` keyword-only and `/` positional-only separators are skipped).
   - PLG005: a `capabilities|permissions|access|scopes` key (quoted-JSON **or** unquoted-YAML)
     with a wildcard value (`*` / `"*"` / `all` / `["*"]` / `[all]`); quoted `all` must be exact
     and bare YAML `all` must end the value, so `all_users` does not false-fire.
   - PLG007: `.dict()` / `.model_dump()` with empty args in the bounded body, excluding filtered
     variants. `.json()` is excluded (it is `response.json()`, not a model export).
   - PLG008: a NARROWER sensitive-call body gate than PLG003 — DB/file/OS calls only
     (`_SENSITIVE_CALL_SHARED_IDENTITY`), deliberately excluding a generic outbound
     `requests.*`/`httpx.*` call to a third-party API. An @tool sending its own env-sourced or
     module-constant key to an external provider (Brave Search, Stripe, ...) is this rule's own
     documented safe pattern, not a confused deputy — F2 needs the downstream resource to
     enforce per-principal authorization across multiple callers with differing entitlements,
     which a static provider key sent to an arbitrary external API does not establish (a call
     with no auth parameter AT ALL still fires under PLG003's broader, unchanged gate).
     PLUS at least one auth-named parameter
     (`_AUTH_PARAM`, the same list PLG003 uses) whose default-value expression is EITHER a bare
     `SCREAMING_SNAKE_CASE` identifier (`^[A-Z][A-Z0-9_]{2,}$`, anchored to the whole default —
     a call like `SERVICE_FACTORY()` or an attribute access like `settings.SERVICE_KEY` does
     NOT match, only an unadorned module constant standing alone) OR an
     `os.getenv(...)`/`os.environ.get(...)`/`os.environ[...]` lookup. A default wrapped in
     `Depends(...)`, `Header(...)`, or `Security(...)` is excluded first, regardless of what it
     wraps — that is the per-request-injection idiom PLG003's own remediation recommends.
     Parameter boundaries and the name/default split are found with a quote- and
     bracket-depth-aware scanner (`_split_top_level_commas` / `_param_name_and_default`) so a
     comma inside a nested call's arguments (`os.getenv("X", "a,b")`) cannot mis-split the
     signature.
   - The function body is bounded at the next same-or-outer-indent statement (capped at 20 lines)
     so a sibling helper's sinks defined right after a short tool are not attributed to it.

4. **Inline opt-out pragma:** `# security: allow-plugin-security` in any file silences all
   plugin-security checks in that file.

5. **Severities, rules, and standards:**
   - `plugin-security/tool-no-auth-check` — HIGH — `["OWASP-LLM:LLM06", "OWASP:A01"]`
   - `plugin-security/tool-unvalidated-input` — MEDIUM — `["OWASP-LLM:LLM01", "OWASP:A03"]`
   - `plugin-security/wildcard-capabilities` — HIGH — `["OWASP-LLM:LLM06", "OWASP:A01"]`
   - `plugin-security/tool-data-overexposure` — MEDIUM — `["OWASP-LLM:LLM02", "OWASP:A01"]`
   - `plugin-security/tool-shared-service-identity` — HIGH — `["OWASP-LLM:LLM06", "OWASP:A01"]`

6. **Granularity:** every rule reports in every scanned file. The four `@tool` rules give one
   finding per offending tool, anchored at its decorator line. A tool with several offending
   parameters (PLG008, PLG001), or one that is both `dict`-typed and has a bare parameter
   (PLG001), still gives one finding, since all of them would share that anchor. PLG005 gives
   one finding per manifest file. Until #425 each rule returned its first hit from inside the
   all-files loop, so it reported one finding per *repo*, and an exception or baseline entry on
   that one hid every other unauthenticated tool, wildcard manifest, and so on.

---

## When NOT to flag

- PLG003: The function signature contains `current_user`, `user_id`, `user`, `auth`, `token`,
  `api_key`, or `requester`. The guard cannot verify the parameter is actually used to scope
  data access, but its presence signals intent — use the pragma for confirmed-safe tools.

- PLG001: `str`, `int`, `float`, `bool`, or a named Pydantic model type. Primitive types are
  acceptable for simple tools; Pydantic models provide structural validation. The guard fires
  only on `dict` / `Any` / untyped.

- PLG005: The capabilities/permissions/access/scopes value is a non-wildcard array
  (e.g. `["read_documents", "write_files"]`) or a specific string.

- PLG007: `.model_dump(exclude=...)` or `.model_dump(include=...)` — field filtering is present.

- PLG008: the auth-named parameter's default is wrapped in `Depends(...)`, `Header(...)`, or
  `Security(...)` (per-request injection) — regardless of what it wraps. Also silent when the
  function has no sensitive call in its body (same gate PLG003 itself requires), or when the
  default is anything other than a bare ALL-CAPS identifier / `os.getenv`-shaped call — a
  literal string secret, an attribute access (`settings.SERVICE_KEY`), or a factory call
  (`get_key()`) do not fire (see "Known bypasses" below). Also silent when the only sensitive
  call in the body is a generic outbound `requests.*`/`httpx.*` call to a third-party API — an
  @tool calling Brave Search or Stripe with its own service key is the documented safe pattern,
  not a confused deputy (review H4; see item 3 above).

**Pragma:** `# security: allow-plugin-security` silences all five checks in the file.
Use when tools are in a hardened sandbox with explicit capability bounding at a higher layer.

---

## Tests

| Test | What it checks |
|---|---|
| `test_plugin_security_tool_no_auth_db_query_fires` | PLG003: cursor.execute without auth param fires HIGH |
| `test_plugin_security_tool_no_auth_requests_fires` | PLG003: requests.get without auth param fires |
| `test_plugin_security_tool_with_current_user_silent` | PLG003: current_user in signature stays silent |
| `test_plugin_security_tool_with_user_id_silent` | PLG003: user_id in signature stays silent |
| `test_plugin_security_tool_no_auth_pragma_silences` | PLG003: pragma suppresses the finding |
| `test_plugin_security_tool_dict_param_fires` | PLG001: dict-typed param fires MEDIUM |
| `test_plugin_security_tool_any_param_fires` | PLG001: Any-typed param fires MEDIUM |
| `test_plugin_security_tool_untyped_param_fires` | PLG001: bare untyped param fires MEDIUM |
| `test_plugin_security_tool_pydantic_model_silent` | PLG001: Pydantic model param stays silent |
| `test_plugin_security_tool_str_param_silent` | PLG001: str param stays silent |
| `test_plugin_security_wildcard_cap_star_fires` | PLG005: capabilities "*" fires HIGH |
| `test_plugin_security_wildcard_permissions_array_fires` | PLG005: permissions ["*"] fires |
| `test_plugin_security_wildcard_all_fires` | PLG005: permissions "all" fires |
| `test_plugin_security_explicit_capabilities_silent` | PLG005: specific capability list stays silent |
| `test_plugin_security_ai_plugin_json_wildcard_fires` | PLG005: ai-plugin.json wildcard fires |
| `test_plugin_security_tool_model_dump_fires` | PLG007: model_dump() without filter fires MEDIUM |
| `test_plugin_security_tool_dict_method_fires` | PLG007: .dict() fires MEDIUM |
| `test_plugin_security_tool_filtered_dump_silent` | PLG007: model_dump(exclude=...) stays silent |
| `test_plugin_security_tool_include_dump_silent` | PLG007: model_dump(include=...) stays silent |
| `test_plugin_security_response_json_silent` | PLG007: `resp.json()` HTTP idiom stays silent (FP-bait) |
| `test_plugin_security_os_path_build_silent` | PLG003: `os.path.join/dirname` only stays silent (FP-bait) |
| `test_plugin_security_keyword_only_separator_silent` | PLG001: `*` keyword-only separator stays silent (FP-bait) |
| `test_plugin_security_wildcard_yaml_fires` | PLG005: YAML `permissions: "*"` fires HIGH |
| `test_plugin_security_yaml_all_substring_silent` | PLG005: YAML `access: all_users` stays silent (FP-bait) |
| `test_plugin_security_not_llm_stack_silent` | Guard is NOP when llm not in features |
| `test_plugin_security_shared_identity_allcaps_constant_fires` | PLG008: `api_key` defaulted to a bare ALL-CAPS module constant fires HIGH (PLG003 stays silent) |
| `test_plugin_security_shared_identity_env_getenv_fires` | PLG008: `token` defaulted to `os.getenv(...)` fires HIGH |
| `test_plugin_security_shared_identity_depends_silent` | PLG008: `Depends(...)`-wrapped default stays silent (FP-bait) |
| `test_plugin_security_shared_identity_no_sensitive_call_silent` | PLG008: no sensitive call in body stays silent (FP-bait) |
| `test_plugin_security_shared_identity_third_party_http_call_silent` | PLG008: env-sourced key sent to a third-party HTTP API (Brave Search) stays silent (FP-bait, review H4) |
| `test_plugin_security_shared_identity_service_charge_call_silent` | PLG008: module-constant key sent to a third-party payments API (Stripe) stays silent (FP-bait, review H4) |
| `test_plugin_security_shared_identity_auth_mode_param_silent` | PLG008: `auth_mode` (not an `_AUTH_PARAM` match) stays silent (FP-bait) |
| `test_plugin_security_shared_identity_pragma_silences` | PLG008: pragma suppresses the finding |
| `test_plugin_security_reports_every_unauthenticated_tool` | PLG003: three tools over two files give three findings, each at its decorator (#425, the issue's own repro) |
| `test_plugin_security_safe_tools_after_an_unauthenticated_one_stay_silent` | PLG003: an identity-taking tool and a data-free tool after a hit stay silent (FP-bait for the #425 widening) |
| `test_plugin_security_reports_every_shared_identity_tool` | PLG008: one finding per tool, every file (#425) |
| `test_plugin_security_shared_identity_one_finding_per_tool_with_two_bad_params` | PLG008: two shared-credential params on one tool give one finding (#425) |
| `test_plugin_security_per_request_identity_after_a_shared_one_stays_silent` | PLG008: a `Depends(...)` identity after a hit stays silent (FP-bait for the #425 widening) |
| `test_plugin_security_reports_every_unvalidated_input_tool` | PLG001: one finding per tool across both branches, every file (#425) |
| `test_plugin_security_unvalidated_input_one_finding_per_tool` | PLG001: dict-typed plus bare param, or two bare params, give one finding per tool (#425) |
| `test_plugin_security_typed_tools_after_an_unvalidated_one_stay_silent` | PLG001: fully typed tools after a hit stay silent (FP-bait for the #425 widening) |
| `test_plugin_security_reports_every_wildcard_manifest` | PLG005: one finding per wildcard manifest (#425) |
| `test_plugin_security_scoped_manifest_next_to_a_wildcard_one_stays_silent` | PLG005: an explicit capability list next to a wildcard manifest stays silent (FP-bait for the #425 widening) |
| `test_plugin_security_reports_every_overexposing_tool` | PLG007: one finding per tool, every file (#425) |
| `test_plugin_security_filtered_dump_after_a_full_one_stays_silent` | PLG007: a field-limited dump after a full one stays silent (FP-bait for the #425 widening) |
| `test_plugin_security_per_file_pragma_still_scopes_to_its_file` | The per-file pragma silences only its own file; the other keeps every rule's findings (#425) |

---

## Known bypasses

- **PLG003 aliased auth param:** A developer names the auth parameter `identity` or `caller` —
  not in the `_AUTH_PARAM` list — so the guard fires even though auth is present. Fix: add
  the alias to the pattern, or use the pragma.

- **PLG003 multi-file auth:** The tool function itself has no auth param, but the caller always
  passes auth context via a dependency injected at a higher layer. The guard cannot trace the
  call graph across modules.

- **PLG001 indirect Any:** `from typing import Any as Schema` and then `def tool(x: Schema):`
  — the guard looks for the literal token `Any`, not imported aliases.

- **PLG005 YAML without PyYAML:** The guard scans YAML manifests as text using a regex. The
  common scalar/flow-list wildcard forms (`permissions: "*"`, `access: all`, `scopes: ['*']`)
  ARE detected, but complex YAML anchors, block sequences (`- "*"` on its own line), or
  multi-line values may produce false negatives.

- **PLG007 variable-based dump:** `args = {}; return item.model_dump(**args)` — the guard
  detects the empty-call form `.model_dump()` (parentheses with no content) only. Passing
  a variable instead of literals would bypass the pattern.

- **PLG008 indirect binding:** `_SERVICE_KEY = SERVICE_API_KEY; def get_data(query, api_key: str
  = _SERVICE_KEY)` — `_ALLCAPS_CONSTANT_DEFAULT` requires the FIRST character to be `A-Z`, so a
  leading-underscore alias (`_SERVICE_KEY`) does not match — a silent bypass. More generally, ANY
  indirection between the true shared secret and the parameter default — a lowercase alias, a
  config-object attribute (`settings.SERVICE_KEY`), a factory call (`get_service_key()`), or a
  value threaded through another function before landing as the default — is invisible to a
  single-signature, single-file scan. The guard proves the narrow, literal case (the default IS
  the shared identity, spelled out plainly in the signature); it does not trace where a
  default's value ultimately comes from.

- **PLG008 class-based tools:** like PLG003/PLG001/PLG007, this rule only scans
  `@tool`/`@agent.tool` decorated functions — a class-based tool (subclassing `BaseTool`) with
  the identical shared-credential-default shape is invisible here; see `agent-tool-overpermission`.

---

## What this guard does NOT prove

- PLG003 does NOT prove that the auth parameter is actually used to scope data access. A function
  with `user_id: str` that ignores it and returns all rows is flagged safe. Code review is
  required to confirm the parameter is used in a WHERE clause or equivalent.

- PLG001 does NOT verify that the Pydantic model has sufficient validation constraints
  (e.g. `max_length`, `pattern`, no `model_config = ConfigDict(extra="allow")`).

- PLG005 does NOT verify runtime enforcement. A manifest may declare narrow capabilities that
  the plugin runtime ignores.

- PLG007 does NOT inspect the actual ORM model schema to confirm which fields are sensitive.
  A model with no sensitive fields that returns `.model_dump()` is still flagged.

- PLG008 does NOT trace where a default's value ultimately comes from — only whether the
  literal expression written IN the signature is a bare ALL-CAPS constant or an `os.getenv`
  call. An alias, a config-object attribute, or a factory call between the real secret and the
  parameter default defeats it (see "Known bypasses"). It also does NOT prove the opposite
  direction PLG003 already disclaims: a `Depends(...)`-wrapped default is assumed safe without
  verifying the injected callable actually scopes access to the caller.

- None of the rules detect security gaps in tools defined via class-based approaches
  (subclassing `BaseTool`) rather than function decorators — that pattern is covered
  by `agent-tool-overpermission`.

# Citations

[1] agentsec checklist item `2b-excessive-data-exposure` (§2b)
[2] agentsec checklist item `4-agent-identity-propagation` (§4)
[3] OWASP-LLM:LLM06
[4] OWASP:A01
[5] OWASP:A03
