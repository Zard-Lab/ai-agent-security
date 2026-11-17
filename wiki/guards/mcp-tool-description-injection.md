---
type: Guard
title: "mcp-tool-description-injection"
description: "MCP tool descriptions loaded without injection scanning."
timestamp: "2026-10-11T00:00:00Z"
guard_id: "mcp-tool-description-injection"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM03", "OWASP-LLM:LLM06", "OWASP-ASI:ASI02"]
---

# MCP tool descriptions loaded without injection scanning

## Threat

MCP servers supply natural-language tool descriptions that the model reads to decide
which tools to call and how to call them. An adversarial or compromised MCP server
can embed prompt injection payloads in a tool's `name`, `description`, or parameter
schema — instructing the model to exfiltrate data, override system-prompt instructions,
or call unintended tools. Johann Rehberger's research (Month of AI Bugs 2024) shows
adversarial tool descriptions achieve 79%+ tool-call compliance even when the same
instructions embedded in plaintext are refused.

MITRE ATLAS classifies this as AML.T0051.003 (LLM Prompt Injection via Tool Specs).
OWASP-LLM:LLM01 (Prompt Injection) is the primary mapping — the tool description IS the injection
vector; LLM03 (Supply Chain) covers the untrusted third-party MCP server the schemas come from.

This guard addresses a different attack surface than `mcp-tool-unverified`:
- `mcp-tool-unverified` detects when there is no server allowlist (missing connection-time trust gate).
- This guard detects when tool *descriptions* arrive from an approved server but their *content* is not scanned for injection payloads before being passed to the model.

Even a fully allowlisted server can be compromised. Description content scanning is the
second defence layer.

## Detection logic

The guard fires when all three conditions are true in the same Python file:

1. `from mcp` import or `MCPClient(` (file is consuming MCP tools, not just defining them)
2. `.list_tools()` or `.get_tools()` call (tool schemas are actually retrieved from a server)
3. No description-content safety signal in the file (no `sanitize*description`,
   `filter*description`, `scan_tools`, `filter_tools`, `tool_validator`, `injection_check`,
   `payload_check`, `content_filter`, or equivalent)

Files that only *define* MCP server tools (contain `FastMCP(`, `@mcp.tool`, `from mcp.server`)
without explicit client calls are excluded — they publish tools, they don't consume them.

## Sub-rules

| Rule | Severity |
|---|---|
| `mcp-tool-description-injection/tool-description-unscanned` | MEDIUM |
| `mcp-tool-description-injection/missing-destructive-hint` | MEDIUM |
| `mcp-tool-description-injection/suspicious-description-content` | MEDIUM |
| `mcp-tool-description-injection/shadow-schema-parameter` | MEDIUM |
| `mcp-tool-description-injection/readonly-hint-contradicts-name` | HIGH |
| `mcp-tool-description-injection/destructive-tool-missing-confirmation-param` | MEDIUM |
| `mcp-tool-description-injection/resource-embedded-secret` | HIGH |
| `mcp-tool-description-injection/duplicate-tool-name-across-files` | MEDIUM |
| `mcp-tool-description-injection/encoded-payload-in-description` | HIGH |
| `mcp-tool-description-injection/invisible-unicode-in-metadata` | CRITICAL |
| `mcp-tool-description-injection/html-hidden-instruction` | CRITICAL |
| `mcp-tool-description-injection/hidden-instruction-brackets` | MEDIUM (surfacing) |
| `mcp-tool-description-injection/mandatory-shell-command` | MEDIUM (surfacing) |
| `mcp-tool-description-injection/user-intent-override` | MEDIUM (surfacing) |
| `mcp-tool-description-injection/quoted-cross-tool-prerequisite` | MEDIUM (surfacing) |
| `mcp-tool-description-injection/forced-argument-change` | MEDIUM (surfacing) |
| `mcp-tool-description-injection/preference-manipulation` | MEDIUM (surfacing) |
| `mcp-tool-description-injection/confusable-tool-name-across-files` | HIGH |

## Remediation

Scan each tool's `name`, `description`, and parameter descriptions for injection markers
before passing them to the model. Common patterns:

```python
INJECTION_PATTERNS = [
    r"ignore.{0,20}previous",
    r"\n{2,}",
    r"system\s*prompt",
    r"exfiltrate|exfil",
]

def scan_description(desc: str) -> bool:
    """Return True if description is safe."""
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, desc, re.IGNORECASE):
            return False
    if len(desc) > 2000:  # abnormally long description
        return False
    return True

tools = await session.list_tools()
safe_tools = [t for t in tools.tools if scan_description(t.description)]
```

If the scanning logic is implemented in a helper module (not in the file that calls
`list_tools()`), suppress this finding with:

```python
# security: allow-mcp-description-unscanned
```

The comment silences the file wherever it sits; a docstring or string literal quoting the
phrase does not count (#424).

## Additional pattern: `missing-destructive-hint` (MEDIUM)

MCP tool definitions can include `annotations.destructiveHint` to signal whether the
tool modifies state. Without this annotation, orchestrating agents cannot identify
state-mutating tools for confirmation policies or safe auto-approval decisions.

This sub-check fires only when **all** of the following hold (scoping added after review
found it firing on ordinary `{"name": "create_x"}` config/payload dicts in any LLM repo):

1. the file contains an **MCP client import** (`_MCP_CLIENT_IMPORT` — the same gate the
   `tool-description-unscanned` rule uses);
2. a dict literal has a `name` whose value carries a mutating verb (write/delete/update/create/
   remove/drop/execute/modify/purge) as a **whole word segment** (delimited by the string's
   start/end or `_`/`-`, so `is_deleted`/`executed_at` do NOT match);
3. that same dict has an **MCP tool-schema marker** key (`inputSchema`, the MCP spec's required
   tool key, or `description`), in any value form, so `"inputSchema": DELETE_SCHEMA` counts and a
   coincidental `{"name": ..., "value": ...}` dict inside an MCP file is not flagged;
4. the file does not declare `destructiveHint` anywhere (a file-wide skip, not a per-tool one).

Read-only prefixes (`get_`, `list_`, `fetch_`, `read_`, `search_`) are also excluded. One finding
per file, reported on the first matching tool's `"name"` line.

The dict scoping comes from an AST walk over `ast.Dict` literals, so a neighbouring tool in the same
list cannot satisfy the marker. This rule shipped before that walk existed, as a line-window scan
(the marker anywhere within -2..+15 lines of the `"name"` key). A file the parser rejects (a
Python 2 module, or syntax newer than the interpreter running agentsec) falls back to that window
scan rather than being skipped, so the rule keeps the coverage it shipped with; on that path a
neighbouring dict's marker can still count.

It is silenced by `# security: allow-mcp-description-unscanned`, not by the schema pragma below: it
predates the pragma split, and moving it would make an opt-out users already wrote stop working.

Standards: `OWASP-LLM:LLM06` (Excessive Agency) — a missing destructive-hint is a
confirmation-policy/agency gap, not an injection vector (so this finding does not carry
the guard's LLM01/LLM03 injection tags).

## Additional pattern: `suspicious-description-content` (MEDIUM)

Where the two patterns above check whether a file scans description content at all (structural,
absence-based), this checks the description TEXT itself for injection-style vocabulary, sourced
from SAF-MCP's SAF-T1001 detection-rule keyword lists (verified against real source). Fires when a
hardcoded tool-schema dict's `description` string value co-occurs a control-style directive
("always"/"must"/"before calling"/"override"/"first use") with a sensitive-data term
("credential"/"token"/"secret"/"account"/"record"/"message"/"file"/"recipient"/"destination"), or
matches a cross-tool directive shape (`call|use|invoke|retrieve` near `tool|reader|search|lookup|
mail|message|file`) — the description instructing the model to act on other tools/data rather than
describing what the tool itself does.

Deliberately excludes bare "retrieve"/"include" from the control-verb list: those alone are
ordinary description vocabulary ("Retrieves the account balance") and co-occur with a sensitive
term constantly in genuine, correct tool descriptions — including them would fire on routine code,
not injection payloads. Same MCP-file scoping as the sibling rules (client import or server
definition present).

`suspicious-description-content` also fires on six more description-text shapes (
added mined from AgentPostmortem/MCP-audit's rule pack, verified against real source), all
reported under the same rule id since they're the same underlying pattern — the description
instructing the model or misrepresenting the tool, not describing what it does:

- **cross-tool-directive** (widened): the original `call|use|invoke|retrieve` +
  `tool|reader|search|lookup|mail|message|file` shape required a *singular* noun, so "use your
  other **tools**" (plural) and a "**next**, run X" step-chaining directive never matched. Both
  are now caught, narrowly: the plural only as "use your/the other/available tools" ("list the
  tools a server exposes" stays silent), and "then"/"next" only with a comma or colon before the
  verb ("the next run of a scheduled job" stays silent).
- **privilege-escalation**: role-redefinition or privilege-escalation phrasing a tool's
  own description has no legitimate reason to use ("new instructions: you are", "grants you admin
  access", "bypass security checks", "developer mode enabled"). An admin grant counts only when it
  targets the model itself (you/your/me/the model/the assistant), so "grants admin access to a
  repository collaborator" stays silent.
- **hidden-secondary-behavior**: an "also/additionally" data-handling verb
  (collects/sends/logs/stores/…) co-occurring a benign-sounding pretext ("for caching/analytics/
  backup purposes") — co-occurrence is the signal, not either alone, same style as
  control-plus-sensitive above.
- **covert-transfer-admission**: an explicit admission the action is hidden from the
  user ("silently sends", "without user knowledge", "don't tell the user").
- **credential-file-transfer-claim**: a transfer/read verb (reads/sends/uploads/
  attaches/exfiltrates/…) within 20 characters before a credential-file path (`~/.ssh`,
  `.aws/credentials`, `id_rsa`/`id_ed25519`, a private-key marker). The verb must act on the path,
  so "uploads a file over SSH using your private key" stays silent. Bare `.env` is not on the list:
  it is ordinary config as often as a secret, and it also matched inside `process.env`.
- **vague-capability**: overly-broad capability language ("read any file",
  "unrestricted access", "full system access") rather than a scoped, specific action.

## Schema-structure checks

Distinct from the description-TEXT checks above, these inspect the tool-SCHEMA structure —
mined from Cisco AI Defense's mcp-scanner YARA rules and AgentPostmortem/MCP-audit, verified
against real source (see our research notes on mcp-scanner and
mcp-audit, kept outside this repo).

- **`shadow-schema-parameter`** (MEDIUM): `inputSchema.properties` declares a parameter
  name reading as an internal/hidden control channel (`internalOnly`, `hiddenParam`,
  `shadowTool`, `bypassChecks`, `sandboxEscape`, `_internal`, `debugOverride`, `adminOverride`) —
  a hidden flag a compromised client could set that the visible description never explains.
- **`readonly-hint-contradicts-name`** (HIGH): a mutating-named tool declares
  `annotations.readOnlyHint: true` — an *active false safety claim*, stronger than merely missing
  `destructiveHint`, since an orchestrator that trusts `readOnlyHint` may auto-approve the call.
- **`destructive-tool-missing-confirmation-param`** (MEDIUM, surfacing): a mutating-named
  tool exposes a real `inputSchema.properties` block with no confirmation-style parameter
  (`confirm`, `confirmation`, `force`, `dry_run`/`dryrun`, `acknowledge`, `approve`,
  `require_confirmation`). A human-in-the-loop UI aid, not a control; see below.
- **`resource-embedded-secret`** (HIGH): an MCP *resource* declaration (`@*.resource(...)`
  or a `"uri": "scheme://…"` dict) embeds a high-confidence provider secret literal (the same
  allowlist-free OpenAI/Anthropic/AWS/GitHub/Google/GitLab prefixes
  `client_side_secret_literal.py` uses). A resource's content is read back verbatim by the
  connecting client, unlike a tool description. Deduplicated per (file, secret span): the
  `@*.resource(...)` decorator and a nearby `"uri"` key both anchor a search window, and without
  dedup the same literal secret under one idiomatic FastMCP resource produced two identical
  findings from this one check alone. Comments are stripped before matching so a commented-out
  example key doesn't fire.
- **`duplicate-tool-name-across-files`** (MEDIUM): the same tool `name` is declared as an
  MCP tool schema in more than one file. A second, compromised definition can shadow or replace
  the trusted one depending on registration order; scoped to genuinely cross-file duplicates
  (same name in two different files), not a same-file re-declaration. Requires an `inputSchema`
  sibling key specifically (not `description` alone), so an MCP `PromptArgument` dict — which also
  pairs `name` with `description` but never declares `inputSchema` — doesn't collide across files
  on an ordinary shared argument name like `path`/`id`/`query`.

Three of these checks (`readonly-hint-contradicts-name`,
`destructive-tool-missing-confirmation-param` and `duplicate-tool-name-across-files`) scope to the
single enclosing tool-dict literal via an AST walk (`ast.Dict` nodes with a literal-string `"name"`
key), not a fixed-line text window after a regex match, so a neighbouring tool's annotations in a
multi-tool list can no longer silence or falsely implicate a different tool. These three skip a file
the parser rejects; they are new, so there is no earlier coverage to keep, unlike
`missing-destructive-hint` above, which falls back to its window scan. The skip is not silent: the
audit names every file that does not parse in a coverage notice (#1001). `shadow-schema-parameter`
and `resource-embedded-secret` are text scans, so they run on such a file as usual.

`destructive-tool-missing-confirmation-param` is marked `surfacing` rather than a plain finding: a
schema-level confirm/dry-run parameter helps a human-in-the-loop UI catch an accidental model
mistake, but it is not a control against this guard's own threat model (a compromised server or an
injected model fills every argument, confirm included, as easily as any other). It also only fires
when the tool's `annotations.destructiveHint` is `true` or absent — never when it is explicitly
`false` — so a tool that has already opted out of the destructive classification doesn't get a
second, contradictory finding.

These five rules share their own suppress pragma, separate from the description-text rules above
(again a comment anywhere in the file; a docstring or string quoting it does not count, #424):

```python
# security: allow-mcp-schema-unscanned
```

A file correctly pragma'd with `allow-mcp-description-unscanned` because its description scanning
lives in a helper module still gets these five schema-structure checks — they're a different trust
boundary (schema shape, not description content) and need their own opt-out. The exception is
`missing-destructive-hint`, which stays on `allow-mcp-description-unscanned` (see its section).

## Additional pattern: `encoded-payload-in-description` (HIGH)

Extends `agent-audit-kit`'s `tool_poisoning.py` (AAK-POISON-004, verified against real source).
Where `suspicious-description-content` catches plaintext directive language, this catches an
obfuscated payload that never appears as literal instruction text at all — invisible to both a
human reviewer skimming the description and the plaintext-directive rule above. Fires when a
hardcoded tool-schema dict's `description` string value contains:

- 3+ consecutive backslash-x-hex escapes (`\x69\x67...`), or
- 3+ consecutive percent-hex escapes (`%69%67...`), or
- a 24+ character run of the base64 alphabet that DECODES to mostly printable text, tried as
  ASCII first and then as UTF-16LE (the encoding PowerShell's own `-EncodedCommand` convention
  uses; a length floor excludes short, ordinary-looking tokens like a version string or a build
  ID; the decode check excludes sha256/md5/commit SHAs, keys and other binary ids, which decode
  to mostly non-printable bytes, and pure-hex runs of a digest length are skipped outright).

The payload only becomes a live instruction if something — the tool's own logic, or the model's
own reasoning — decodes it at runtime; the description itself gives no indication of what it
contains until then. Same MCP-file scoping as the sibling rules.

**Known bypasses (this rule).** Only a literal `"description": "..."` string in a tool-schema dict
is read. The other two FastMCP shapes, the `@mcp.tool(description=...)` keyword argument and a
function docstring, are not inspected, so an encoded payload there is a false negative. A payload
that is base64 of non-text bytes (a compressed or encrypted blob) also stays silent by design, as
does base64 split across several strings. Raw hex digits with no `\x` escaping are a subset of the
base64 alphabet, so a run at a non-digest length is checked on the same decode-to-text path; hex
decodes as base64 to garbage bytes, so it stays silent too — a genuine unescaped-hex instruction
payload is not a shape this rule catches, only `\x`-escaped hex and base64 (ASCII or UTF-16LE).

## Checklist mapping

- `4-mcp-tool-description-injection` (section 4 — AI Agent Security): MCP/tool connector
  schemas scanned for embedded instruction payloads before agent loads them; mutating
  tools annotated with `destructiveHint`.

## Standards

- OWASP-LLM:LLM01 (Prompt Injection) — the description is the injection vector
- OWASP-LLM:LLM03 (Supply Chain) — the untrusted third-party MCP server
- OWASP-LLM:LLM06 (Excessive Agency) — the annotation/confirmation-gap rules
- OWASP-ASI:ASI02 (Tool Misuse & Exploitation) — a legitimate tool bent toward an illegitimate
  outcome via deceptive schema/description/resource content the model reads as trusted metadata
- MITRE ATLAS AML.T0051.003 (LLM Prompt Injection via Tool Specs)

## Canary plant

The original 3 rules are planted in the canary's shared `mcp_client.py` (which
`mcp-tool-unverified` also trips): `from mcp import ClientSession` + `await
session.list_tools()`, a mutating tool dict with no `destructiveHint`, and a description
co-occurring "Always call ..." with "... account credential". That file stays in `canary.py`'s
base, owned by no single guard (see `xxe_safe.py`'s ownership rule); this guard declares
`expects` only for those three.

The 5 the rules are new, independent violation shapes with no other owning guard, so
they get their own plant files declared directly on `McpToolDescriptionInjectionGuard.canary_plant`:

- `mcp_tool_trust_extensions.py` — a shadow `internalOnly` schema parameter, a `readOnlyHint:
  true` on a `purge_cache` tool, a `remove_user` tool with a real `properties` block but no
  confirmation key, a `sync_workspace` tool name, and an `@mcp.resource(...)` embedding an
  OpenAI-shaped secret literal.
- `mcp_tool_trust_extensions_secondary.py` — a second `sync_workspace` tool declaration, so
  `duplicate-tool-name-across-files` has a genuine cross-file match.

`mcp_poisoned_tool.py` (own plant file, not the shared base) — a tool description containing a
hex-escape run. Expected rule: `mcp-tool-description-injection/encoded-payload-in-description`.

`mcp_tool_poison_markers.py` — one tool dict per high-risk category, each
description crafted to match exactly its own category and verified not to also match an
earlier category in the check order. `mcp_tool_confusable_name.py` — a `sync_workspace` variant
with a Cyrillic о (U+043E) in place of the Latin o, pairing against the two existing
`sync_workspace` declarations above to trip `confusable-tool-name-across-files`.

## Relation to mcp-tool-unverified

| Guard | Catches |
|---|---|
| `mcp-tool-unverified` | MCP client import or config with no server allowlist |
| `mcp-tool-description-injection` | Tool schemas loaded without description content scan |

Both can fire on the same file. Together they cover the two-layer MCP trust model:
(1) only connect to approved servers; (2) even approved servers can be compromised,
so scan their tool descriptions before use.

## Additional patterns: eight high-risk description markers (mined from MCPVul)

Mined from MCPVul (BarDavid2394)'s `TOOL_POISONING_PATTERNS` catalog, verified against real
fetched source. Each is kept as its own rule with its own severity (the existing
`suspicious-description-content` category chain above is uniformly MEDIUM, so a CRITICAL-grade
shape could not be added there without changing that rule's blanket severity). Only the two
structural carriers (invisible Unicode, an HTML comment) stay CRITICAL. The other six are
keyword/phrase heuristics over free text, which keep a residual false-positive rate no regex
closes, so they are MEDIUM and surfacing: review signal that does not gate CI at the default
`--fail-on high` (#1053 review H1):

| Rule | Severity | Shape |
|---|---|---|
| `invisible-unicode-in-metadata` | CRITICAL | A zero-width space/non-joiner, word joiner, BOM or bidi-override control character in the description. The zero-width JOINER (U+200D) is excluded: it is a normal part of emoji ZWJ sequences. |
| `html-hidden-instruction` | CRITICAL | An instruction-like directive hidden inside an HTML comment (`<!-- ignore previous instructions -->`). |
| `hidden-instruction-brackets` | MEDIUM (surfacing) | A bracketed marker word (`[Important]`/`[System]`/`[Instruction]`/`[Hidden]`/`[Internal]`). `[Note]` is ordinary documentation and does not count. |
| `mandatory-shell-command` | MEDIUM (surfacing) | The description mandates execution of a literal shell command: a mandate verb, then `run`/`execute`, then a literal command token (`sudo`, `curl -`, `rm -rf`, ...), a command category (`system command`), or `the following command:` with the colon. A bare "run the following command to install ..." without the colon does not count. The colon form also fires on legitimate install text ("Please run the following command: ls"); that is accepted at this non-gating severity, so read it as a review signal, not a low-FP rule. |
| `user-intent-override` | MEDIUM (surfacing) | The description claims precedence over the user's own request/instruction. "Works even if the user does not supply X" is an optional-argument sentence and does not count. |
| `quoted-cross-tool-prerequisite` | MEDIUM (surfacing) | A mandatory prerequisite naming a specific, QUOTED tool literal (e.g. "you must call 'read_file'"). The mandate verbs are `call`/`invoke`/`run`/`execute`, and they fire on any quoted name, server-prefixed ones included (`'github_create_issue'`). `use`/`using` is deliberately NOT a mandate verb: no shape of the quoted name separates a tool from a parameter ('send_email' vs 'search_query'), and both shapes tried fired on ordinary parameters or missed real tools (#1053 review rounds 3-4). So "must use 'send_email'" is a known gap, while "use 'utf-8' encoding" and "use 'page_size'" stay silent. The rule is distinct from the plaintext `cross-tool-directive` category above, which requires a generic noun near the verb rather than a quoted identifier. |
| `forced-argument-change` | MEDIUM (surfacing) | The description coerces an automatic/mandatory change to an argument, parameter, value, query, or request. A passive validation sentence ("must be set to a valid value") does not count. |
| `preference-manipulation` | MEDIUM (surfacing) | The description claims this tool should be preferred/prioritized/"most reliable" over others. |

All eight are checked against the same literal `description` string VALUE the
`suspicious-description-content` rule above scans (same `_DESCRIPTION_VALUE` extraction, same
MCP-file scoping, same `# security: allow-mcp-description-unscanned` pragma). The first category
to match a given description is the one reported.

## Additional pattern: confusable (homoglyph-varied) duplicate tool names

Widens `duplicate-tool-name-across-files` above, which compares names by exact string equality.
A homoglyph-substituted duplicate (a Cyrillic/Greek look-alike letter swapped into one
occurrence) never matched that rule. Unicode NFKC normalization does **not** fix this —
verified directly: `unicodedata.normalize("NFKC", "sync_wоrkspace")` leaves the Cyrillic о
untouched, since NFKC only merges compatibility-equivalent forms within a script, never
cross-script confusables.

Instead, every pair of distinct literal tool names found anywhere in the repo is compared
structurally: same length, and differing only at positions where one side is a plain ASCII
Latin letter and the other is one of the same vetted confusable codepoints
`homoglyph-source-chars` checks for (own local copy — each guard's constants are self-contained
by this codebase's convention). Two ordinary ASCII names that merely happen to share a length
(`search_docs`/`search_logs`) never match, since an ASCII/ASCII differing position is never a
confusable codepoint on either side.

Fires `mcp-tool-description-injection/confusable-tool-name-across-files` (HIGH — stronger than
the plain `duplicate-tool-name-across-files` MEDIUM, since the deception here is active, not
incidental).

# Citations

[1] agentsec checklist item `4-mcp-tool-description-injection` (§4)
[2] OWASP-LLM:LLM01
[3] agent-audit-kit `tool_poisoning.py`, rule AAK-POISON-004 — the encoded-payload-in-description extension
[4] OWASP-LLM:LLM03
[5] OWASP-LLM:LLM06
[6] MCPVul (BarDavid2394) `mcp_scanner/patterns/signatures.py` `TOOL_POISONING_PATTERNS` — the eight high-risk description-marker rules
