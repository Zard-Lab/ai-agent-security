---
type: Guard
title: "mcp-session-id-security"
description: "MCP session identifier is predictable or used as sole authorization."
timestamp: "2026-10-11T00:00:00Z"
guard_id: "mcp-session-id-security"
checklist_section: ["4"]
standards: ["OWASP-ASI:ASI04"]
---

# MCP session identifier is predictable or used as sole authorization

_Author — 2026-10-09_

---

## The threat

An MCP server that issues session identifiers is making an identity claim: whoever presents a
given session id IS the party that session was created for. Two ways that claim breaks down,
both mined from MCPVul (BarDavid2394)'s `analyzers/project_risks.py` (`MCP14-WEAK-SESSION`/
`MCP14-SESSION-AUTH` rules, verified against real fetched source):

1. **Predictable or client-supplied session ids.** `uuid.uuid1()` derives its value from the
   host's MAC address and the current timestamp — not cryptographically random. An attacker who
   can observe one session id (or simply knows roughly when a victim connected) can narrow or
   reconstruct another session's id. A server that lets the client CHOOSE the id of a new
   session is worse still, but that is not statically separable from the correct pattern:
   the streamable-HTTP transport sends the session id back in the `Mcp-Session-Id` header and
   the server MUST read it (`request.headers.get('mcp-session-id')`) to look the session up.
   Reading and choosing are the same statement shape, so this guard detects only the
   predictable-generation half (an earlier client-value rule flagged every correct server and
   was deleted, #1053 review H2).

2. **Session-id possession treated as authorization.** `if session_id in sessions:` — with no
   further check — means stealing or guessing a session id IS a successful login. There is no
   separate credential or permission check at all.

Standards: OWASP-ASI:ASI04 (Resource and Identity Management) — an agentic session boundary that
can be forged or replayed is an identity-management failure.

## Why this guard fits the stack

MCP servers commonly implement their own lightweight session layer rather than reusing a
framework's battle-tested session middleware (Flask-Session, FastAPI's signed cookies, etc.),
because the MCP transport layer is young and most example code predates any session-hardening
guidance. A quick, naive implementation reaches for `uuid.uuid1()` (the first result for
"generate a unique id in python" in older tutorials) and a plain dict lookup for "is this
session real" — exactly the two patterns this guard targets.

```python
# The naive, vulnerable shape:
def create_session():
    session_id = str(uuid.uuid1())   # predictable
    return session_id

def is_authorized(sessions, session_id):
    if session_id in sessions:       # possession == authorization
        return True
    return False
```

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features` — the repo declares/uses the MCP SDK, the
   same gate `mcp-oauth-flow-hardening` uses.
2. **Files scanned:** all `.py` files under `python_scan_dirs(root, profile)`, deduplicated,
   excluding non-product paths, and only files that import the MCP SDK themselves
   (`from mcp`/`import mcp`/`fastmcp`, the file-level marker `mcp-oauth-flow-hardening`
   anchors to). A same-named variable in an unrelated file of an MCP repo does not fire. The
   pragma check runs first, on every scanned file.
3. **Patterns (per line, independent of each other):**
   - `weak-session-id-generation`: a `session_id`/`mcp_session_id`/`mcpsessionid` variable
     assigned from `uuid.uuid1()` (optionally wrapped in `str(...)`). Reading a session id out
     of a request is not flagged (see The threat).
   - `session-id-as-sole-authorization`: an `if` statement whose entire condition is
     `session_id in sessions`/`session_store`, `sessions.get(session_id)`, or
     `sessions[session_id]` — anchored with `\s*:` immediately after the condition, so an
     ANDed additional check (a real auth signal) breaks the match.
4. **Inline opt-out pragma:** `# security: allow-mcp-session-id-security` anywhere in the file
   silences both rules for that file (whole-file reach — see
   `tests/test_pragma_anchoring.py::_FILE_SCOPED_PRAGMA`).
5. **Severity and rules:**
   - `mcp-session-id-security/weak-session-id-generation` — HIGH
   - `mcp-session-id-security/session-id-as-sole-authorization` — MEDIUM, surfacing (it asks a
     human to confirm that no other check exists in the auth path, so it ranks below a proven
     finding of the same severity)
   - Standards: `["OWASP-ASI:ASI04"]`

## When NOT to flag

```python
# Safe — cryptographically random:
session_id = str(uuid.uuid4())
# or:
session_id = secrets.token_urlsafe(32)

# Safe — an additional, real authorization check is ANDed in:
if session_id in sessions and user.is_admin:
    ...
```

Suppress a reviewed, intentional case (e.g. a local-dev-only server with no real identity
boundary) with `# security: allow-mcp-session-id-security` in the file.

## Tests

| Test | What it checks |
|---|---|
| `test_weak_session_id_fires_on_uuid1` | `uuid.uuid1()` assigned to `session_id` fires |
| `test_weak_session_id_silent_on_reading_the_client_sent_header` | FP-bait: reading `request.headers.get('mcp-session-id')` (the correct server pattern) stays silent |
| `test_weak_session_id_silent_on_uuid4` | FP-bait: `uuid.uuid4()` (the safe form) stays silent |
| `test_weak_session_id_silent_without_file_level_mcp_marker` | FP-bait: `uuid.uuid1()` in a file that does not import the MCP SDK stays silent |
| `test_weak_session_id_finding_does_not_claim_the_deleted_client_value_detection` | the finding's message, title and remediation describe only what the rule detects |
| `test_session_id_as_sole_auth_fires_on_bare_membership_check` | `if session_id in sessions:` fires |
| `test_session_id_as_sole_auth_is_a_medium_surfacing_finding` | the rule reports MEDIUM and is classified as surfacing |
| `test_session_id_as_sole_auth_silent_with_additional_condition` | FP-bait: an ANDed real auth check stays silent |
| `test_session_id_as_sole_auth_silent_without_file_level_mcp_marker` | FP-bait: the same check in a file that does not import the MCP SDK stays silent |
| `test_mcp_session_id_security_applies_gate` | `applies()` gates on `"mcp"` in profile features |
| `test_mcp_session_id_security_pragma_silences` | file-level pragma suppresses both rules |

## Known bypasses

- A session id built across several statements (not a single-line assignment) is invisible to
  the single-line regex.
- An authorization check split across multiple `if` statements, or expressed as a ternary/
  ``assert``, is not recognized by the anchored `session-id-as-sole-authorization` pattern.
- A session-id variable under a different name (not `session_id`/`mcp_session_id`/
  `mcpsessionid`) is not tracked.
- `uuid.uuid1()` wrapped in an intermediate helper function (`make_id()` that itself calls
  `uuid.uuid1()`) is not traced back to the `session_id =` assignment line. Neither is a bare
  `uuid1()` after `from uuid import uuid1`, a `.hex` form, or an annotated assignment
  (`session_id: str = str(uuid.uuid1())`).
- A server that lets the client choose the id of a NEW session is not detected (see The
  threat for why reading the client's id cannot be told apart statically).
- A session layer split across files, where the module holding the `uuid1()` call does not
  itself import the MCP SDK, is not scanned (the file-level marker).

## What this guard does NOT prove

- That the session store itself is safe from other attacks (fixation, lack of expiry, no
  rotation on privilege change) — only the two generation/authorization shapes above are
  checked.
- That a `uuid4()`-generated session id is transmitted and stored safely (e.g. not logged in
  plaintext, not placed in a URL query string — see `6a-no-secret-in-url-query`).
- Coverage of non-Python MCP server implementations (TypeScript/Java/Rust) — this guard is
  Python-only.

# Citations

[1] agentsec checklist item `4-mcp-session-id-security` (§4)
[2] OWASP-ASI:ASI04
[3] MCPVul (BarDavid2394) `mcp_scanner/analyzers/project_risks.py` — `MCP14-WEAK-SESSION`/`MCP14-SESSION-AUTH` rules
