---
type: Guard
title: "mcp-oauth-flow-hardening"
description: "An MCP OAuth 2.1 client flow is missing PKCE, forwards tokens, or doesn't conform to the 2026-07-28 auth profile."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-oauth-flow-hardening"
checklist_section: ["4"]
standards: ["OWASP:A07", "OWASP-ASI:ASI04"]
---

# MCP OAuth flow is missing PKCE, forwards tokens, or doesn't conform to the 2026-07-28 auth profile

_Author — 2026-09-26_

---

## The threat

MCP spec 2025-11-25 makes OAuth 2.1 mandatory with PKCE+S256, RFC 8707 Resource
Indicators, and RFC 9728 Protected Resource Metadata; the 2026-07-28 profile adds RFC 9207
issuer validation. OWASP:A07 (Identification and Authentication Failures),
OWASP-ASI:ASI04. Eight distinct, real failure modes recur across MCP OAuth
implementations — missing PKCE (authorization-code interception), plain-method PKCE
(downgrade attack), token passthrough (the caller's own credential reused as the server's),
wildcard redirect URIs (code exfiltration to any destination), bearer-only auth with no
proof-of-possession (a leaked token is directly usable by anyone), and three
2026-07-28-profile conformance gaps. Sourced from `agent-audit-kit`'s `oauth_misconfig.py`
(AAK-OAUTH-001..008), verified against the real repo source.

**Distinct from `mcp-oauth-scope-creep`**, which checks scope BREADTH (a wildcard/`admin`
scope value) and a dangerous authorization-URL scheme — none of the eight checks here
overlap it.

## Why it's often introduced

OAuth 2.1's PKCE/DPoP/resource-indicator requirements are recent (relative to OAuth 2.0's
much older adoption), so example code and quickstarts an implementer copies from often
predate the requirement. The 2026-07-28 profile's `iss`/`resource`/PRM checks are newer
still — most existing MCP client code was written before they existed.

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. Scans `.py`/`.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.json`/`.yaml`/`.yml`/`.toml` files
   (`iter_files`).
3. **Anchors only on the MCP surface (#1023).** The `mcp` feature is repo-wide: one MCP config
   or SDK dependency turns it on for every file. The rule vocabulary is generic OAuth text, so
   before this rule a product monorepo's lockfile, generated route tree, NextAuth provider,
   Slack installer, SSO validator and API-gateway config all fired gating HIGHs (langfuse 7,
   supabase 26). A finding may now anchor only in a file that is:
   - **an MCP marker**: a Python file importing `mcp` or `fastmcp`; a JS/TS file importing
     (`from`, `require(`, `import(`) `@modelcontextprotocol/*`, `fastmcp`, `agents/mcp`
     (Cloudflare), `mcp-handler` or `@vercel/mcp-adapter`, `mcp-framework`, `@mastra/mcp` or
     `xmcp`, read with comments and Python docstrings blanked; or a JSON/YAML/TOML config whose
     filename carries an `mcp` token (`mcp.json`, `.mcp.json`, `mcp-servers.json`,
     `mcp_config.toml`), one of detect's other MCP config names (`servers.json`,
     `claude_desktop_config.json`), a file under `.mcp/`, or a file with an `mcpServers` /
     `mcp_servers` key; **or**
   - **one hop from a product-path marker**: a file the marker imports directly. JS/TS relative
     specifiers resolve with each extension, the ESM `.js` to `.ts` mapping and `dir/index.*`;
     Python relative imports resolve from the importer's package, and package-absolute ones under
     each of the importer's ancestor directories. This is what keeps the
     `remote-mcp-server-with-auth` handler (`src/auth/github-handler.ts`, which imports no MCP
     SDK but is imported by the entry point that does) in scope. A marker on a test or example
     path does not extend the surface.

   Independently of the surface, an **artifact** never anchors: `pnpm-lock.yaml`,
   `package-lock.json`, `npm-shrinkwrap.json`, `*.gen.{ts,tsx,js,jsx,mjs}`, `*.d.ts`, anything
   under `__snapshots__/`, and a file whose first ten lines carry a generated header
   (`@generated`, or `generated` with `do not edit`). A generated MCP marker still extends the
   surface to the hand-written modules it imports.

   The surface narrows where a finding may ANCHOR, never what the guard reads: the class
   hierarchy and PKCE/`resource` indexes (item 9) still read every scanned file.
4. Seven of the eight rules are gated behind a whole-file OAuth-context hint (`oauth`,
   `authorization_endpoint`, `token_endpoint` or `client_id`; `authorize(` was dropped from the
   hint because a plain permission-check function shares the name) — matching the
   real source's own design, since these patterns only mean something in an actual OAuth
   flow file: **missing-pkce** (HIGH — an `authorize(`/`authorization_endpoint` site with no
   PKCE field anywhere), **pkce-plain-method** (HIGH — `code_challenge_method=plain`),
   **token-passthrough** (HIGH — `Authorization` header set directly from the inbound
   request), **wildcard-redirect-uri** (HIGH: `*`, `http(s)://*`, a bare `http://localhost`
   with an optional trailing `/` and no port or path pin, or a localhost port or path wildcard
   such as `http://localhost:*` or `http://localhost/*`; `http://localhost:3000/cb` is pinned
   and does not fire, nor does a `*` past a `?`, `#`, `&`, `,` or `;` separator, as in
   `http://localhost:3000/cb&scope=*`),
   **bearer-only-no-dpop** (MEDIUM — an outgoing `Authorization` header assigned a Bearer
   literal or f-string/template-literal interpolation, with no `DPoP`/`cnf` marker anywhere), **missing-iss-validation** (HIGH,
   RFC 9207 — an authorization-code response handled with no `iss` reference anywhere), and
   **missing-resource-indicator** (HIGH, RFC 8707: a token-acquisition flow shape with no
   `resource` parameter anywhere).
5. One rule runs independently of the OAuth-context hint: **missing-prm-discovery** (MEDIUM,
   RFC 9728 — an MCP remote-transport config or server-side bearer-auth marker with no
   Protected Resource Metadata discovery anywhere).
6. Inline opt-out: a `# security: allow-mcp-oauth-flow-hardening` comment (`// …` in JS/TS)
   anywhere in the file silences the file (a string literal or quoted scalar quoting the phrase
   does not count, #424). A `.json` config has no comments, so there the raw text is matched.
7. Standards `["OWASP:A07", "OWASP-ASI:ASI04"]` on every rule.
8. **Skips and scoping.** A `.json` file that is itself a JSON-Schema document (top-level
   `properties`/`$defs`/`definitions` with `$schema` at a json-schema.org meta-schema) is
   skipped. A real config that merely carries a `$schema` key (an editor or schemastore
   addition) is still scanned. Quoted slash-path strings in `.json`/`.yaml`/`.toml` are
   masked before the OAuth-context hint search (this closes the Mintlify `docs.json` and
   docs-navigation-fragment FPs); the RFC 9728 marker is matched against the UNMASKED text,
   since `".well-known/oauth-protected-resource"` is itself a path-like string. Whole-line
   comments never count as call sites (`authorize(` in a comment), but a comment naming a
   mitigation still counts as the mitigation (the conservative direction).
9. **Cross-file resolution.** A class hierarchy index is built over the scanned tree
   (Python `class A(B)` and TS/JS `class A extends B`, matched by class name). `missing-pkce`
   is not reported when a class the file declares inherits, transitively, from a class whose
   file carries a PKCE marker, or when the file constructs an OAuth-flavoured class (name
   contains oauth/auth/proxy/provider/pkce) defined in such a file. `missing-resource-
   indicator` resolves through inheritance the same way.
10. **Client-side call site for `bearer-only-no-dpop`.** The rule needs an outgoing
   `Authorization` header being assigned a Bearer value (dict item, subscript or kwarg). A
   server building a `WWW-Authenticate: Bearer` challenge, or validating an inbound token,
   never matches.
11. `grant_type` is a token-request signal only as a quoted dict key or a `grant_type=` field,
    not as a type annotation or the tail of a constant name.
12. Every finding carries `path:line` of its anchor (the call site, header assignment, or
    marker that triggered it).
13. The absence rules (`missing-*`) and `bearer-only-no-dpop` are declared via
    `surfacing_rule_prefixes`: they show a mitigation is not visible to a text scan, not that
    it is missing, so they are review signals. `pkce-plain-method`, `token-passthrough` and
    `wildcard-redirect-uri` stay proven findings.

## When NOT to flag

- PKCE present (`code_verifier`/`code_challenge`/`pkce`), with `S256` as the method. An
  authorization server that advertises it (`code_challenge_methods_supported=["S256"]`, the
  RFC 8414 metadata field) counts too; one that advertises only `plain` does not.
- An `Authorization` header built from the server's own credential, not the inbound
  request's.
- A specific, exact `redirect_uri`, including a port- or path-pinned loopback one
  (`http://localhost:3000/callback`, which RFC 8252 permits for native clients).
- An OAuth flow that is not MCP code: a NextAuth credentials provider, a Slack installer, an
  SSO config validator or an API-gateway route config in a repo that also ships an MCP server
  (it is off the surface unless an MCP module imports it directly).
- A lockfile, a generated module or type declaration, or a test snapshot.
- A `DPoP`/`cnf` marker present alongside Bearer auth.
- `iss` referenced anywhere near an authorization-code handler.
- A `resource` parameter present anywhere in a token-acquisition-shaped file.
- PRM discovery markers present anywhere in an MCP remote-auth-surface file.

## Tests

| Test | What it checks |
|---|---|
| `test_missing_pkce_fires` / `test_pkce_present_is_safe` | PKCE absence/presence |
| `test_pkce_plain_method_fires` / `test_pkce_s256_is_safe` | `plain` vs `S256` |
| `test_token_passthrough_fires` | Inbound header forwarded verbatim — fires |
| `test_wildcard_redirect_uri_fires` / `test_specific_redirect_uri_is_safe` | Wildcard vs exact redirect |
| `test_bearer_only_no_dpop_fires` / `test_dpop_present_is_safe` | DPoP absence/presence |
| `test_missing_iss_validation_fires` / `test_iss_validated_is_safe` | `iss` absence/presence |
| `test_missing_resource_indicator_fires` / `test_resource_indicator_present_is_safe` | `resource` param absence/presence |
| `test_missing_prm_discovery_fires` / `test_prm_discovery_present_is_safe` | PRM discovery absence/presence |
| `test_live_config_carrying_a_schema_key_still_fires` / `test_json_schema_document_is_not_a_live_config` / `test_metaschema_pointing_file_without_schema_body_still_scanned` | `$schema` handling, both directions |
| `test_relative_prm_path_in_json_counts_as_discovery` / `test_json_without_prm_marker_still_fires_prm` | RFC 9728 marker matched pre-mask |
| `test_subclass_of_pkce_implementing_base_is_not_missing_pkce` / `test_transitive_inheritance_resolves` / `test_subclass_of_base_without_pkce_still_fires` / `test_instantiating_a_pkce_proxy_is_not_missing_pkce` | Class-hierarchy PKCE / resource resolution |
| `test_authorize_only_in_a_comment_is_not_a_call_site` | Comment lines are not call sites |
| `test_server_side_bearer_challenge_is_not_bearer_only_client` / `test_client_bearer_assignment_still_fires_bearer_only` | Client-side call site for bearer-only |
| `test_grant_type_annotation_and_constant_are_not_token_requests` / `test_grant_type_dict_field_still_fires_resource_indicator` | `grant_type` as a request field only |
| `test_findings_carry_line_numbers_and_absence_rules_are_surfacing` | `path:line` locations, surfacing split |
| `test_pragma_suppresses_all_findings` | Inline pragma silences every rule |
| `test_same_flow_fires_on_the_surface_and_is_silent_off_it` | The surface rule on one fixture, both directions |
| `test_one_hop_ts_handler_imported_by_the_mcp_entry_fires` / `test_one_hop_ts_specifier_shapes_resolve` / `test_one_hop_python_import_shapes_resolve` / `test_one_hop_python_package_import_from_a_src_layout` / `test_one_hop_python_unicode_module_name_resolves` | One hop keeps an imported handler in scope (remote-mcp-server-with-auth, ESM `.js`, `dir/index`, Python relative/absolute/package forms, a `src/` layout resolved through an ancestor directory, a module name that starts with a non-ASCII letter) |
| `test_bom_prefixed_python_mcp_module_stays_on_the_surface` / `test_bom_prefixed_python_module_without_a_marker_stays_off_the_surface` | A leading UTF-8 BOM neither drops a Python MCP module (or its first-line import) off the surface nor puts a non-MCP one on it |
| `test_two_hop_helper_does_not_anchor` | The radius is pinned at one hop |
| `test_non_mcp_oauth_in_an_mcp_repo_is_silent` / `test_gateway_config_without_mcp_marker_is_silent` | langfuse's NextAuth/Slack shapes and supabase's `kong.yml` stay silent |
| `test_generated_and_declaration_files_never_anchor` / `test_artifact_imported_by_the_mcp_entry_never_anchors` / `test_generated_mcp_entry_still_extends_to_hand_written_auth` / `test_generated_header_never_anchors` / `test_snapshot_and_lockfile_never_anchor` / `test_is_artifact` | Artifact anchor skip, with an ordinary-module control each time |
| `test_config_markers` / `test_mcp_servers_key_marks_a_config` | Config markers: filename, `.mcp/`, `mcp_servers` key; supabase's `config.toml` is not one |
| `test_non_sdk_mcp_framework_markers` / `test_marker_must_be_a_real_import` | Framework markers fire; a comment, docstring, look-alike package or bare identifier is not a marker |
| `test_test_path_marker_does_not_extend_the_surface` / `test_pragma_on_the_mcp_entry_does_not_silence_the_module_it_imports` | What extends the surface, and the pragma's reach |
| `test_pkce_base_off_the_surface_still_vouches_for_its_mcp_subclass` / `test_subclass_of_a_base_without_pkce_off_the_surface_still_fires` | Rule 4: the class index reads off-surface and artifact files |
| `test_localhost_redirect_fires_only_when_bare` / `test_localhost_redirect_in_config_shapes` | Bare loopback and a localhost port or path wildcard fire; a pinned one does not, nor a `*` in the next value or past a query, fragment or list separator |
| `test_mcp_surface_scan_is_linear_on_long_whitespace_runs` / `test_python_import_resolution_is_linear` / `test_python_import_resolution_after_the_linearity_fix` / `test_wildcard_redirect_scan_is_linear` | The marker, import-resolution and wildcard-redirect regexes stay linear on the shapes that backtracked (JS/TS whitespace runs; a Python dot run, unclosed parens, a space run after `from`; a long run of `redirect_uri=http://localhost:`), and the bounded Python regex still resolves the ordinary shapes |
| `test_mcp_oauth_flow_hardening_pragma_quoted_in_a_string_does_not_suppress`, `test_mcp_oauth_flow_hardening_pragma_quoted_in_a_string_does_not_suppress_ts`, `test_mcp_oauth_flow_hardening_ts_slash_comment_pragma_suppresses`, `test_mcp_oauth_flow_hardening_pragma_quoted_in_a_string_does_not_suppress_yaml`, `test_mcp_oauth_flow_hardening_pragma_comment_suppresses_yaml`, `test_mcp_oauth_flow_hardening_pragma_quoted_in_a_string_does_not_suppress_toml`, `test_mcp_oauth_flow_hardening_pragma_comment_suppresses_toml` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6); a `//` comment now opts a JS/TS file out too, and a TS string quoting either form does not |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |

## Known bypasses

- The MCP surface (detection item 3) resolves only relative and package imports in the scanned
  tree. An OAuth handler reached through a tsconfig `paths` alias (`@/auth/handler`,
  `~/auth`), a workspace package (`@acme/shared`), a dynamic import with a computed
  specifier, or a helper two or more hops from the MCP module is off the surface and silent.
  A Python package re-export is such a second hop: `server.py` importing `pkg`, whose
  `__init__.py` re-exports `pkg.auth`, does not reach `auth.py`. A bare JS/TS `"."` or `".."`
  specifier is not resolved to its `index` module either.
  A Python package-absolute import resolves only under the importer's own ancestor
  directories, so a `src/` layout imported from a sibling top-level directory is missed.
- An MCP server built on a framework that is not in the marker list (detection item 3) is
  invisible unless its OAuth module also imports one that is. A file whose first ten lines say
  `generated` and `do not edit` is treated as generated even when a person wrote it.
- `wildcard-redirect-uri` reads only the FIRST entry of a comma- or semicolon-joined value: the
  `*` scan stops at a separator, so `http://localhost:3000/cb,http://localhost:*` is silent
  (`http://localhost:*,http://localhost:3000` fires). The list arm matches only `["*"]`, so a
  localhost wildcard inside a JSON/TOML/YAML list is not seen either.
- The JS/TS marker scan blanks comments but not strings (an import specifier is a string), so
  a string that reads like an import (`"x from '@modelcontextprotocol/sdk'"`) puts its file on
  the surface. The Python marker must start a line, so a Python string never does.

- Advertised S256 is file-wide PKCE evidence when written as a kwarg or an UNQUOTED object key
  (`code_challenge_methods_supported=["S256"]`, a server building its RFC 8414 metadata). A
  quoted key (`{'code_challenge_methods_supported': ['S256']}`, a client holding metadata it
  fetched) does not count, but a TypeScript client that stores fetched metadata as an unquoted
  object literal next to a PKCE-less authorize call is silenced.
- Crediting a configured PKCE class (`OAuthProxy(upstream_authorization_endpoint=...)`) needs
  its call's closing paren. Parens are paired on a copy with each language's strings and
  comments blanked (Python: quotes, triple quotes, `#`; JS/TS: quotes, template literals, `//`,
  `/* */`), so a stray `(` in a string or comment cannot unbalance it. The scan is lexical, not a
  parser: an apostrophe in JSX text or a JS regex literal containing a quote can still mispair,
  and the result can be either a missed or an extra finding for that file.
- Whole-file presence checks: a PKCE field present ANYWHERE in the file (even unrelated to
  the specific `authorize(` call being evaluated) suppresses the finding — no per-call-site
  correlation.
- Class resolution is by NAME across the scanned tree, not by import: two unrelated classes
  sharing a name can mask or manufacture a resolution. Only PKCE and the RFC 8707 `resource`
  parameter are resolved across files; `iss` (RFC 9207), DPoP and RFC 9728 discovery remain
  single-file. A mitigation delivered by composition (a helper object, a wrapper package, a
  function call rather than a base class) is not resolved and is still reported. Cross-file
  PKCE resolution via instantiation requires the constructor call to carry at least one
  keyword argument (the genuine fastmcp shape, `OAuthProxy(upstream_authorization_endpoint=
  ...)`); a bare, no-config `Foo()` built for an unrelated reason does not credit the file.
  Cross-file resolution via inheritance is still name-based only: a subclass that overrides
  `authorize()` without PKCE while its base class implements PKCE elsewhere is not checked
  for whether the override actually reaches the base's PKCE method.
- The `missing-pkce` anchor and the resource-indicator anchor both exclude a type annotation
  (`authorization_endpoint: str` on a plain data-schema class) and text inside a Python
  triple-quoted docstring/string literal — an RFC 8414 metadata model or a docstring's
  example prose mentioning `oauth/authorize` is not a call site.
- Client versus server is inferred only for `bearer-only-no-dpop` (an outgoing Bearer
  `Authorization` assignment). The other absence rules cannot tell a client from a
  resource/authorization server and so can fire on server code that legitimately has no
  `resource` parameter of its own. Measured on the fastmcp and python-sdk clones, the
  remaining `missing-resource-indicator` hits are of this kind (an OAuth device-flow helper,
  a `token_endpoint` used in an f-string cache key, a shared-types module).
- `bearer-only-no-dpop` fires on a client that calls an upstream API which offers no DPoP
  (GitHub, Discord userinfo endpoints): the rule is true to its definition, but nothing the
  caller can do makes it actionable, so treat it as a review signal.
- The `$schema` skip covers JSON-Schema documents only. A YAML/TOML schema, or an OpenAPI
  document, is not recognised and is scanned like any other file.
- Class-hierarchy and comment handling cover Python and TS/JS. Other languages fall back to
  the single-file behaviour.
- The OAuth-context hint and all eight sub-pattern vocabularies are fixed regexes; unusually
  named identifiers are invisible.
- `_BEARER_ONLY_RE` was widened during this guard's own build to also match
  f-string/template-literal interpolation (`f'Bearer {token}'`) after the real source's
  narrower literal-only character class missed this extremely common shape in testing —
  disclosed here since it's a real, verified improvement over the ported source, not an
  assumption.

## What this guard does NOT prove

Silence does not prove the OAuth flow is cryptographically sound end-to-end — only that
none of these eight specific, spec-named gaps are present. A correct PKCE implementation
with a flawed state-parameter CSRF check, for example, is outside this guard's scope.

# Citations

[1] agentsec checklist item `4-mcp-oauth-flow-hardening` (§4)
[2] MCP spec 2025-11-25 (OAuth 2.1 + PKCE mandatory), 2026-07-28 profile (RFC 9207 issuer validation, SEP-2468)
[3] RFC 8707 (Resource Indicators), RFC 9728 (Protected Resource Metadata), RFC 9207 (Issuer in Authorization Response)
[4] OWASP:A07, OWASP-ASI:ASI04
[5] agent-audit-kit `oauth_misconfig.py`, rules AAK-OAUTH-001..008
