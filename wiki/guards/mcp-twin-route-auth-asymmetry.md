---
type: Guard
title: "mcp-twin-route-auth-asymmetry"
description: "An MCP route has no auth middleware while a sibling MCP route in the same file is authenticated."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-twin-route-auth-asymmetry"
checklist_section: ["4"]
standards: ["OWASP:A01", "CWE-862"]
---

# An MCP route has no auth middleware while a sibling MCP route is authenticated

_Author — 2026-09-26_

---

## The threat

CVE-2026-33032 / "MCPwn" (nginx-ui, CVSS 9.8, KEV-listed 2026-04-13): `/mcp` was wrapped
in an auth middleware, but its sibling `/mcp_message` route — the same underlying
handler surface — was not. An attacker reaches full functionality through the
unauthenticated twin. CWE-862 (Missing Authorization), OWASP:A01 (Broken Access Control).
Unlike a server with no auth at all, this is a REVIEW-DEFEATING shape: a reviewer checking
"is `/mcp` authenticated?" gets a correct yes, and the vulnerable sibling route sits a few
lines away, easy to miss. Sourced from `agent-audit-kit`'s `mcp_middleware.py`
(AAK-MCPWN-001), verified against the real repo source.

## Why it's often introduced

MCP endpoint families commonly split across a "main" route and one or more auxiliary
routes (a message-relay endpoint, an invoke endpoint, a tool-call endpoint) that share
the same trust boundary conceptually but get wired up as separate route declarations.
Auth middleware is naturally added to the route a developer is actively working on first;
the sibling gets added later, often by copy-pasting the route declaration but not the
middleware wrapper.

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. Scans `.py`/`.ts`/`.tsx`/`.js`/`.mjs` files (`iter_files`), with a cheap `"/mcp"`
   text pre-filter before the real regex pass.
3. Extracts MCP-endpoint-shaped route declarations (`/mcp`, `/mcp_message`,
   `/mcp-messages`, `/mcp/invoke`, `/mcp_tool`, `/mcp_msg`) via a FastAPI decorator regex
   (`.py`) or an Express call regex (`.ts`/`.tsx`/`.js`/`.mjs`), checking each route's
   decorator/middleware segment against a recognized auth-marker vocabulary
   (`Depends(auth)`, `HTTPBearer`, `require_auth`, `authMw`, `requireAuth`,
   `passport.authenticate`, ...).
   The FastAPI extractor anchors on the route decorator and then walks the decorator stack
   and the `def` signature with bounded code (balanced parentheses, at most 12 stacked
   decorators, 1500 characters per decorator/signature), so the scan is linear; the
   signature is read whole, so an auth dependency after a nested `Depends(get_db)` is seen.
3a. Auth that is not written on the route still counts, so the PROTECTED route is not flagged
   as the open one: a router authed as a whole (`APIRouter(dependencies=[Depends(auth)])`,
   or mounted from another file with `include_router(mod.router, dependencies=[...])`,
   resolved through the shared cross-file router-auth resolvers in `guards/base.py`); an
   app-wide auth middleware anywhere in the repo (`app.add_middleware(<auth-named class>)`,
   or an auth-named `@app.middleware("http")` function) which suppresses every Python route
   finding; and, for Express, a path-less `app.use(authMw)` registered before the route.
   Because the middleware check suppresses so much, only LIVE code may satisfy it. A registration
   in a comment, a docstring, a comment on a docstring's closing line, or a one-line string
   (`DOC = "app.add_middleware(AuthMiddleware)"`) does not count. The regex runs on the shared
   `router_resolver_view`, since the `"http"` marker is a string value, and a match counts only
   if its first character is code in the offset-aligned `router_code_view` (#538).
4. Fires HIGH for every unauthenticated MCP route in a file that ALSO has at least one
   authenticated MCP-route sibling — the asymmetry itself is the signal, not the mere
   absence of auth (that is `mcp-transport-no-auth`'s scope).
5. Inline opt-out: a `# security: allow-mcp-twin-route-auth-asymmetry` comment (`// …` in JS/TS)
   anywhere in the file silences the file (a string literal quoting the phrase does not count, #424).
6. Severity HIGH, rule `mcp-twin-route-auth-asymmetry/unauthed-sibling`, standards
   `["OWASP:A01", "CWE-862"]`.

## When NOT to flag

- Both sibling routes carry the same (or an equivalent) auth requirement.
- Neither sibling route is authenticated at all — a file with zero auth anchors has no
  asymmetry to detect; that shape belongs to `mcp-transport-no-auth`.
- Only one MCP route exists in the file — there is no sibling to compare against.

## Tests

| Test | What it checks |
|---|---|
| `test_unauthed_sibling_route_fires` | `/mcp` authed, `/mcp_message` not — fires |
| `test_both_routes_authenticated_is_safe` | Both routes share the same auth — silent |
| `test_neither_route_authenticated_is_out_of_scope` | No authenticated anchor at all — silent |
| `test_single_route_no_sibling_is_safe` | Only one MCP route — silent |
| `test_express_unauthed_sibling_fires` | Express/TS shape — fires |
| `test_app_wide_auth_middleware_covers_the_route` | App-wide auth middleware — silent |
| `test_middleware_registered_in_another_file_covers_routes_multi_file` | Middleware in `main.py`, routes in `routes/mcp.py` — silent |
| `test_router_mounted_with_auth_from_another_file_multi_file` / `..._bare_..._still_fires_multi_file` | Cross-file router mount with and without auth |
| `test_router_level_dependency_covers_the_route` | `APIRouter(dependencies=[Depends(auth)])` — silent |
| `test_non_auth_middleware_does_not_count` / `test_commented_out_middleware_does_not_count` | CORS/session/author-named or commented-out middleware does not protect |
| `test_middleware_quoted_in_dead_text_does_not_count` | #538: a one-line string, or a comment on a docstring's closing line, naming `add_middleware(AuthMiddleware)` or an `@app.middleware("http")` auth gate — fires (was silent) |
| `test_live_middleware_beside_a_string_that_names_it_still_counts` | #538 FP bait: the string is skipped, the live registration beside it still protects |
| `test_express_global_auth_*` | Express `app.use(authMw)` covers later routes only |
| `test_extractors_stay_linear_on_unterminated_decorators` / `test_express_extractor_stays_linear_on_unclosed_route_lines` | Growth-ratio pins |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_mcp_twin_route_auth_asymmetry_pragma_quoted_in_a_string_does_not_suppress`, `test_mcp_twin_route_auth_asymmetry_pragma_quoted_in_a_string_does_not_suppress_ts`, `test_mcp_twin_route_auth_asymmetry_ts_slash_comment_pragma_suppresses` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6); a `//` comment now opts a JS/TS file out too, and a TS string quoting either form does not |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |

## Known bypasses

- Sibling routes are correlated per FILE: two MCP routes declared in different
  files/modules are not compared with each other. (Auth applied from another file IS
  resolved, through the router-mount and app-wide-middleware handling above.)
- An auth-named app-wide middleware anywhere in the repo suppresses every Python route
  finding, even if it is mounted on a different sub-application than the MCP routes, or
  excludes them by path.
- The middleware detector is NAME-only, with no behavior check: `_AUTH_MW_NAME`
  (`auth(?!or)|jwt|bearer|token|login|api_?key`) matches a class name regardless of what its
  body actually does. A middleware named `AuthLoggingMiddleware`, `TokenUsageMiddleware` or
  `LoginPageMetricsMiddleware` that only logs or counts requests (and never gates one) still
  suppresses every same-file finding, while `AuthorBannerMiddleware` correctly does not (the
  `(?!or)` exclusion). This is narrower than, and separate from, the whole-repo suppression
  above: it is a name collision on a middleware that gates nothing at all, not a real auth
  control applied to the wrong scope. Requiring the middleware's own body to contain something
  call-shaped (a conditional `raise`/`401`/`403`, a call to a `verify`/`authenticate`-named
  function) would close this, at the cost of the "regex, not full AST" simplicity this guard is
  deliberately built on; left as a human judgment call rather than a forced fix.
- The auth-marker vocabulary is fixed; a bespoke, unrecognized auth wrapper on the
  "authenticated" route would make the whole file read as having no anchor at all
  (silent, not a false fire — the safe direction, but a missed true positive).
- Go/Gin route grouping is out of scope for this first pass (agentsec's other
  source-scanning guards are Python/JS-TS focused; the real CVE's own nginx-ui codebase
  is Go, but porting Gin-specific route-group semantics is deferred).

## What this guard does NOT prove

Silence does not prove the authenticated anchor route's auth check is itself correct or
unbypassable — only that no detected sibling route in the same file lacks a recognized
marker.

# Citations

[1] agentsec checklist item `4-mcp-twin-route-auth-asymmetry` (§4)
[2] CVE-2026-33032 (nginx-ui, CVSS 9.8), GHSA-h6c2-x2m2-mwhf, KEV-listed 2026-04-13
[3] CWE-862, OWASP:A01
[4] agent-audit-kit `mcp_middleware.py`, rule AAK-MCPWN-001
