---
type: Guard
title: "mcp-marketplace-fetch-stdio-spawn"
description: "A network fetch feeds directly into an MCP stdio server spawn in the same function."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "mcp-marketplace-fetch-stdio-spawn"
checklist_section: ["4"]
standards: ["CWE-829", "OWASP:A08", "OWASP-ASI:ASI04"]
---

# Network fetch feeds directly into an MCP stdio server spawn

_Author — 2026-09-22_

---

## The threat

An MCP client that supports discovering servers from a marketplace or registry fetches a server
manifest over the network and then spawns a stdio server from whatever that manifest says:

```python
config = requests.get("https://marketplace.example/manifest").json()
StdioServerParameters(command=config["cmd"], args=config["args"])
```

Cloudflare's MCP-defender reframe (2026-04-25) called this out as the highest-risk single-line
bug shape in the wild — not because the code is complex, but because it's the SIMPLEST possible
way to wire "network content" to "command execution": the fetch response IS the exec target,
with no further exploitation step required. A marketplace compromise — a hijacked registry, a
DNS/TLS MITM on the fetch, a poisoned CDN cache, or simply an attacker registering a malicious
listing on an otherwise-legitimate open registry — becomes client-side remote code execution on
every consumer, the moment they next refresh their server list. WHO reaches this: whoever
controls the marketplace/registry response (an attacker who compromised it, or who got a
malicious listing accepted). WHAT privilege: full code execution as the MCP client process, no
constraint from the client's own sandboxing (there is none at this point — the fetched content
directly becomes the launched process). TO WHAT EFFECT: RCE on every consumer of the
marketplace, not a single targeted victim — the amplification a supply-chain compromise always
carries. CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

## Why it's often introduced / Why this guard fits the stack

Marketplace/registry-driven server discovery is a genuinely useful feature — the whole point of
an MCP marketplace is "browse a catalogue, click to add a server," which necessarily means
fetching a manifest and then launching whatever it describes. The vulnerable and the intended
version of this feature look almost identical in code; the difference is entirely in what
happens BETWEEN the fetch and the spawn — is the manifest verified (a signature, a hash pin, an
explicit user confirmation) before it's trusted to become a `command`/`args` pair, or does it go
straight through? A developer building the happy-path "discover and connect" flow is thinking
about UX (minimize friction — no extra confirmation dialog), not about the manifest being
adversarial.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`.
2. **Files scanned:** `iter_files(root, (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"))`.
3. **Python (`_scan_python`, AST via `safe_ast_parse`):**
   - For each `FunctionDef`/`AsyncFunctionDef`, collect all `Call` nodes and sort them by
     source position (`lineno`, `col_offset`) — a per-function call SEQUENCE, not a set.
   - Walk the sequence: once a fetch call is seen (`_is_fetch_call` — a `requests`/`httpx`/
     `urllib` dotted call ending in `.get`/`.post`/`.request`, or a bare `urlopen`), remember
     its line; if a STDIO-SPAWN call (`_is_stdio_call` — `StdioServerParameters(...)`/
     `StdioClientTransport(...)`, matched on the attribute chain's last component so an aliased
     import is still recognized) appears LATER in the same sequence, fire.
   - The fetch's RETURN VALUE is not traced into the spawn call's arguments — this is a
     same-function call-ORDER heuristic (fetch-then-spawn), not a data-flow proof that the
     spawn's `command`/`args` actually came from the fetch response. Disclosed narrowing, see
     "What this guard does NOT prove" below.
4. **TS/JS (`_scan_ts`, bounded-window regex):**
   - `_TS_FETCH_RE` finds every `await fetch(`.
   - For each match, a `_TS_LOOKAHEAD_WINDOW` = 2048-character window immediately after it is
     searched for `_TS_STDIO_NEW_RE` (`new StdioClientTransport`/`new StdioServerTransport`).
   - A bounded lookahead rather than full-scope AST correlation (no TS/JS AST engine in this
     project), matching the real source's own choice — 2KB is enough to span the typical
     `await fetch(...)` → `.json()` → `new Stdio*Transport(...)` idiom without needing to parse
     function boundaries.
   - Both regexes match on the comment-blanked view (`strip_js_comments`), not the raw text, so a
     commented-out pair does not fire, and each match must be live code (#1055): the fetch's `(`
     and the `n` of the spawn's `new` are tested against the anchor mask
     (`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`) through
     `js_code_matches`. A fetch or spawn spelled out in a docs string or a multi-line template is
     not a call, and every match is tried, so a quoted copy cannot hide a real one after it.
5. **Mitigation markers (PR #923 rounds 1-3).** The finding's own three remediations clear it:
   hash/signature verification, an explicit user-confirmation gate, or a diff against a
   known-good manifest. `_MITIGATION_RE` looks for them in the Python function, or in the TS
   2048-character window after `fetch(`. It matches CODE only: comments and every string literal
   are blanked first (on TS, by the same anchor mask, which keeps `${...}` substitution code, so a
   real verifier nested in a substitution counts; plain `strip_strings=True`, used before #1055,
   blanked it), so a `# TODO: verify signature` comment, a docstring saying "callers must
   verify signature", or a `log.warn('add signature verification')` does not count. Real
   verification whose name is a code token still counts (`hashlib`, `hmac`, `verify_signature`,
   camelCase `verifySignature`, `createHash`/`createHmac`/`createVerify`, `timingSafeEqual`,
   `crypto.subtle.verify(`, `confirm(`). A string literal that is a single token also counts
   (`'sha256'`, `'x-signature'`, `'RSA-SHA256'`), because blanking those broke real
   `createHash('sha256')` and `headers.get('x-signature')` checks when measured. Only prose
   strings (containing whitespace) are ignored.
6. **Inline opt-out pragma:** `# security: allow-mcp-marketplace-fetch-stdio-spawn`, file-level.
   It is matched as a plain substring, so the `// security: ...` form works in a TS/JS file.
7. **Severity/standards:** `high`, `["CWE-829", "OWASP:A08", "OWASP-ASI:ASI04"]`. Rule id:
   `mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn`.

## Deliberate adaptation vs. the real source (disclosed)

The real `mcp_marketplace_fetch.py` reads a bespoke `.aak-mcp-marketplace-trust.yml` file
listing pre-approved manifest URLs with a `justification:` field, letting a legitimate internal
artifact registry be exempted without silencing the check entirely. agentsec has no equivalent
convention anywhere in this codebase (the same adaptation `mcp-sampling-no-consent` documents
for its own risk-acceptance escape hatch) — this guard uses the shared inline pragma instead.

## When NOT to flag

- **A fetch with no stdio spawn anywhere in the same function** — an ordinary API call (fetching
  a user profile, posting telemetry) that never reaches a `StdioServerParameters`/
  `StdioClientTransport` construction.
- **A stdio spawn with a hardcoded/static command, in a function that has no fetch call of its
  own** — even if a DIFFERENT function elsewhere in the file does an unrelated fetch, the check
  is same-function only.
- **A stdio spawn that occurs BEFORE the fetch in the same function's call sequence** — the
  guard specifically looks for fetch-THEN-spawn ordering; a spawn using a static command,
  followed later by an unrelated fetch whose result is never used for the spawn, does not match.
- **The manifest is verified or confirmed before the spawn**: a pinned hash or signature
  check, or an explicit user confirmation, in the same function (see "Mitigation markers").
- An audited, intentional case suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_fetch_then_stdio_server_parameters` | Fires: `requests.get(...).json()` feeds `StdioServerParameters(...)` in the same function — the Cloudflare-flagged shape |
| `test_fires_on_httpx_then_stdio_client_transport` | Fires: `httpx.get(...)` feeding `StdioClientTransport(...)` also fires |
| `test_fires_on_ts_fetch_then_stdio_transport` | Fires: `await fetch(...)` followed by `new StdioClientTransport(...)` in TypeScript |
| `test_fetch_with_no_stdio_spawn_is_safe` | FP-bait: a fetch with no stdio spawn anywhere stays silent |
| `test_stdio_spawn_with_static_command_is_safe` | FP-bait: a static-command spawn in a DIFFERENT function from an unrelated fetch stays silent (same-function only) |
| `test_stdio_spawn_before_fetch_is_safe` | FP-bait: a spawn that occurs BEFORE the fetch in call order does not match |
| `test_comment_only_mitigation_still_fires` / `_ts` | still-fires: a comment naming a mitigation is not code (the TS comment sits inside the scanned window) |
| `test_string_only_mitigation_still_fires` | still-fires: a docstring (one- or multi-line) or a log string naming a mitigation |
| `test_string_only_mitigation_still_fires_ts` | still-fires, TS: a quoted or template-literal prose string |
| `test_real_ts_verification_is_safe` | FP-bait: each real TS verification form stays silent (one param per marker) |
| `test_token_string_verification_is_safe_python` | FP-bait: a single-token header name such as `'X-Manifest-Sha256'` still counts |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` is False without the `mcp` feature |
| `test_guard_applicable_with_mcp_feature` | `applies()` is True with the `mcp` feature |
| `test_nonproduct_path_skipped` | files under `tests/fixtures/` are skipped |
| `test_ts_fetch_or_spawn_spelled_out_stays_silent` | #1055 FP direction: a commented-out pair, a pair in a docs template, and a fetch or a spawn only in a string stay silent |
| `test_ts_real_fetch_then_spawn_still_fires` | #1055: the real pair fires, including after a quoted spawn in the window and with prose inside a substitution string |
| `test_ts_real_fetch_after_a_quoted_fetch_still_fires` | #1055: a quoted `await fetch(` earlier on the line does not hide the real one |
| `test_ts_verifier_nested_in_a_substitution_clears_the_finding` | #1055: a real verifier nested in `${...}` clears the finding (plain `strip_strings=True` lost it) |
| `test_ts_pragma_still_suppresses_a_code_anchored_finding` | the pragma still silences a finding the anchor rule kept |

## Known bypasses

- **No data-flow proof (Python).** The fetch-then-spawn check is a call-ORDER heuristic, not a
  taint proof that the spawn's `command`/`args` actually derive from the fetch response — a
  function that happens to fetch something unrelated and later spawn a server with a genuinely
  static command, in that order, with no other signal, would still fire (a real FP risk the real
  source's own design accepts in exchange for simplicity and no missed true positives).
- **Mitigation presence, not correctness.** A recognized marker anywhere in the function (or
  the TS window) clears the finding, even if the check does not actually gate the spawn. A
  single-token string that merely contains a marker word also counts, including an unrelated
  one such as a form-field name `'email-signature'` or a button id `'user-approve'` (measured;
  the token rule narrows prose, not vocabulary).
- **Anchor-mask residual (#543, TS).** A `{` inside a regex or comment in one `${...}`
  substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads
  as template text (the accepted trade pinned by
  `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A verifier there
  is missed, which errs toward firing; a fetch or spawn there is missed, which errs toward silence.
- **Cross-function indirection.** The fetched manifest passed to a helper function that performs
  the actual spawn (`config = fetch_manifest(url); spawn_from_config(config)`) is not
  recognized — same same-function limitation every other single-function-scoped guard in this
  project documents.
- **TS/JS bounded-window miss.** A `.json()` parse or other intervening logic that pushes the
  `new Stdio*Transport(...)` call beyond the 2048-character lookahead window is not recognized.
- **Non-literal manifest source.** A manifest URL built dynamically, or fetched through a
  wrapped/aliased client method not matching `_is_fetch_call`'s recognized dotted-call shapes
  (`requests`/`httpx`/`urllib`/bare `urlopen`), is not recognized as the fetch signal.
- **Aliased Python stdio imports at the call-attribute level.** `_is_stdio_call` matches on the
  LAST attribute-chain component (`StdioServerParameters`/`StdioClientTransport`), so a renamed
  import (`from mcp import StdioServerParameters as SSP`) is NOT recognized unless the call site
  still uses the literal target name somewhere in the chain — a real gap for a heavily aliased
  import.

## What this guard does NOT prove

- That the spawn's `command`/`args` actually derive from the preceding fetch's response — see
  "No data-flow proof" above; this is an ordering heuristic, not a taint proof.
- That a manifest fetch NOT immediately followed by a spawn in the same function is safe — the
  vulnerable pattern could be split across a helper function this guard's same-function scope
  cannot see.
- That a spawn using a verified/pinned manifest (a signature check, a hash comparison) is safe
  from OTHER MCP stdio-launcher risks — see the neighboring `mcp-stdio-launcher-inline-code-flag`
  rule (part of `mcp-config-security`) for the inline-eval-flag/template-token class, a
  different concern from this guard's fetch-then-spawn correlation.

# Citations

[1] agentsec checklist item `4-mcp-marketplace-fetch-stdio-spawn` (§4)
[2] CWE-829
[3] OWASP:A08
[4] OWASP-ASI:ASI04
[5] Cloudflare MCP-defender reframe (2026-04-25), marketplace-fetch-to-spawn as the
    highest-risk single-line MCP bug shape
[6] agent-audit-kit (sattyamjjain/agent-audit-kit), `mcp_marketplace_fetch.py`
