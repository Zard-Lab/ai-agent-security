---
type: Research
title: sentrymcp — MCP Static-Rule Catalog Patterns
description: Statically-detectable MCP tool-argument and auth/permission patterns distilled from a declarative TOML rule catalog, including one genuine gap (MCP tool-argument taint for JS/TS code-execution sinks) found by cross-checking the catalog against real guard source.
tags: [research, mcp, path-traversal, code-injection, authentication, credentials]
status: stable
generated: { by: agent:research-cycle, at: 2026-10-09T00:00:00Z }
stale_after: 2027-01-09
---

# sentrymcp — MCP Static-Rule Catalog Patterns

## What this covers

A declarative TOML rule catalog for MCP server security — each rule is a per-line sink regex plus
optional file-wide `safe_indicators` suppression regexes, rather than a general-purpose AST
engine. Its value for cross-checking an existing scanner is exactly that declarative shape: every
rule's exact trigger condition is readable in full without reverse-engineering code. Sixteen
rules across two categories (`code_sink`, `auth_permission`); the patterns below are the subset
that was genuinely novel or, in one case, exposed a real gap once checked against real guard
source rather than assumed from a catalog comparison. Pure reference — no tool-specific or
process details.

## JS/TS MCP tool-argument path traversal

A filesystem path built directly from a tool-call argument with no visible containment check:

```js
function readFile(args, root) {
  fs.readFile(path.join(root, args.path), (err, data) => data);
}
```

`path.join(`/`path.resolve(`/`fs.readFile(Sync)?(`/`fs.readdir(Sync)?(` fed an `args.`/`params.`/
`toolArgs.`/`input.` property access, with no `path.relative(`/`path.isAbsolute(`/
`path.normalize(`/root-prefix check anywhere in the file. The Python-equivalent shape
(`arguments["path"]` reaching `Path(`/`os.path.join(`/`open(`) is a long-established pattern; the
JS/TS SDK-based MCP server population (an increasingly common shape as more MCP servers ship in
Node) needed the same coverage independently, since a regex-level guard built for Python call
syntax does not transfer to JS/TS call syntax for free.

## JS/TS MCP transport with no auth marker

An HTTP/SSE transport declaration with no recognizable auth pattern anywhere in the file:

```js
const app = express();
app.listen(8080, '0.0.0.0', () => console.log('listening'));
```

`new SSEServerTransport(`/`app.listen(`/`createServer(` with none of `Authorization`/`Bearer`/
`verifyToken(`/`checkAuth(`/`requireAuth`/`authenticate(`/`X-API-Key` appearing anywhere in the
file. This is inherently an absence-of-pattern heuristic — the file could authenticate in a way
these markers don't recognize — so it stays a review signal, not a proven vulnerability. An
explicit loopback bind (`.listen(8080, 'localhost', ...)`) is exempt: a server bound to loopback
only inherits OS-level process isolation and isn't reachable the same way a `0.0.0.0`/public bind
is.

## Hardcoded MCP credential literal

A variable or object field named like a credential, assigned a quoted string literal directly
rather than read from an environment variable or secret store:

```python
API_KEY = "sk-live-..."
```
```js
const accessKey = "AKIA...";
```

`api_key`/`secret`/`token`/`password`/`access_key` (case-insensitive, with a combined-name
alternative like `access_key` to catch the compound case directly) assigned a quoted literal of
8+ non-whitespace characters. Deliberately no placeholder/env-var-read exclusion mirrored from the
source rule: a file-wide "an env-var read appears somewhere in this file" suppressor would hide a
real hardcoded credential sitting next to legitimate env-var reads elsewhere in the same file —
narrowing on the SAME LINE (a quoted literal directly after the operator) already excludes a
genuine `os.environ.get("API_KEY")` read by construction, so a broader suppressor would only
reduce true positives, not false ones. Disclosed scope limit, not a bug: a compound name like
`secret_token` doesn't match the word-boundary-anchored vocabulary unless it's one of the explicit
combined alternatives, and a quoted object-literal key (`{ "password": "..." }`) doesn't match —
only an unquoted key or bare variable name immediately followed by the operator does.

**Correction (2026-10-12, review rounds 1 and 2 of #1058).** Two statements above no longer
describe the shipped guard. The guard does exclude value shapes, though still not env-var reads,
which remain excluded by construction: placeholders, masks, all-lowercase key and header names,
and values that locate or date a secret (a URL without userinfo, a path, an ARN, an ISO-8601
date). And a compound name such as `secret_token` or `GITHUB_TOKEN` now matches, because the name
is split into segments rather than matched against a word-boundary vocabulary. The guard's design
doc, `wiki/guards/mcp-hardcoded-credential.md`, is the current description.

## Overprivileged MCP scope declaration

A scope-boundary-named variable assigned the filesystem root or a bare wildcard:

```python
ROOT_PATH = "/"
```
```js
const allowed_origins = ["*"];
```

`root_path`/`root_dir`/`allowed_root`/`base_path`/`scope`/`allowed_hosts`/`allowed_origins`/
`allowed_paths`/bare `root` assigned exactly `"/"`, `"*"`, or `"**"` (directly, or as the first
element of a list literal). Deliberately LOW severity and heuristic/informational: a broad
path/host wildcard isn't inherently wrong — some tools genuinely need it — so this is a review
signal that something should be double-checked, not a proven misconfiguration. Distinct from a
config-file-level check of the same shape: a server whose CONFIG file is correctly scoped but
whose own SOURCE hardcodes (or simply ignores) a broader default is invisible to a config-only
check and needs the source read directly.

## The gap: MCP tool-argument taint for JS/TS code-execution sinks

A general-purpose JS/Node code-injection detector that gates a dynamic-evaluation sink (`eval`/
`new Function`/`vm.run*`/`node-serialize` `unserialize`) on an HTTP-request taint source
(`req.*`/`request.*`) has a structural blind spot against MCP: a stdio/SDK-based MCP tool server
has no `req`/`request` object anywhere in the file at all. Its handler receives tool-call
arguments directly:

```js
server.tool("calc", async (args) => {
  return eval(`result = ${args.formula}`);
});
```

This is the exact shape a tool-argument-aware eval/Function sink rule targets, and it is a
genuinely different taint SOURCE vocabulary (`args.`/`params.`/`toolArgs.`/`input.`) from an
HTTP-request-shaped one — not a narrower or broader version of the same thing. The fix generalizes
cleanly: treat the MCP-specific vocabulary as an ADDITIONAL taint source alongside the existing
HTTP-request one, gated specifically on the repo actually being MCP-shaped (those property names
are far too generic in ordinary web-app JS/TS to treat as an untrusted-input signal
unconditionally) — and apply it to every sink the guard already understands, since the same
"tool argument reaches a dynamic-evaluation sink" risk applies uniformly across all of them, not
just the two sinks a narrower source rule happened to name.

**The methodological point, not just the specific fix:** a catalog comparison that trusts a
checklist's "this item is covered" status, or a prior session's own classification, without
re-reading the actual guard SOURCE for every individually-claimed-covered rule, can miss exactly
this shape of gap — a taint-source vocabulary that was correct for the surface the guard was
originally built against, but incomplete for a newer, structurally different surface (MCP tool
handlers vs. HTTP request handlers) sharing the same sink class.

## Coverage note

Most of this catalog's `code_sink` category (path traversal, command injection, eval/exec on the
Python side, command injection on the JS/TS side) was already covered, in several cases more
rigorously than the source's own line-level regex — a general-purpose command-injection detector
that resolves real import bindings and fires on any dynamic (not just f-string/concatenation)
argument is strictly broader than a rule requiring one specific string-building shape. The
genuinely novel subset was narrow: two JS/TS-coverage gaps on existing guards, one new credential
guard, one new overprivileged-scope guard, and — found only by reading the "already covered"
guard's source directly rather than trusting the comparison — one real taint-vocabulary gap on a
fifth, pre-existing guard.
