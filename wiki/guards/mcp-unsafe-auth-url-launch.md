---
type: Guard
title: "mcp-unsafe-auth-url-launch"
description: "MCP OAuth authorization URL opened without scheme validation or via a shell."
timestamp: "2026-10-11T00:00:00Z"
guard_id: "mcp-unsafe-auth-url-launch"
checklist_section: ["4"]
standards: ["OWASP-ASI:ASI04"]
---

# MCP OAuth authorization URL opened without scheme validation or via a shell

_Author — 2026-10-09_

---

## The threat

MCP clients commonly drive the user through an OAuth authorization-code flow by opening a
browser at a dynamically-constructed authorization URL. Mined from MCPVul (BarDavid2394)'s
`analyzers/project_risks.py` (`MCP15-UNSAFE-AUTH-URL` rule, verified against real fetched
source), two ways that step goes wrong:

1. **No scheme validation before opening.** `webbrowser.open(auth_url)`/`os.startfile(auth_url)`
   hands the OS whatever string the code built. If an attacker can influence any part of that
   URL (a redirected OAuth discovery document, a malformed client-supplied callback parameter),
   a `file://` or `javascript:` scheme reaches the OS opener with no check that it is actually
   `https://`.

2. **Opened through a shell.** `subprocess.run(f"open {auth_url}", shell=True)` or
   `os.system(f"start {auth_url}")` re-invokes a shell with the URL embedded in the command
   line — shell metacharacters in the URL become OS command injection, not merely an unexpected
   browser tab.

Standards: OWASP-ASI:ASI04 (Resource and Identity Management) — the OAuth flow this URL belongs
to is how the agent establishes its own identity/credentials; launching it unsafely compromises
that whole boundary.

## Why this guard fits the stack

The MCP SDK does not ship a browser-launch helper, so every client implements this step itself,
usually by reaching for the first thing that works:

```python
# The naive, vulnerable shape:
def start_login(auth_url):
    webbrowser.open(auth_url)          # no scheme check

def start_login_fallback(auth_url):
    subprocess.run(f"open {auth_url}", shell=True)   # shell, not just no scheme check
```

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`.
2. **Files scanned:** all `.py` files under `python_scan_dirs(root, profile)`, deduplicated,
   excluding non-product paths, and only files that import the MCP SDK themselves
   (`from mcp`/`import mcp`/`fastmcp`, the file-level marker `mcp-oauth-flow-hardening`
   anchors to). The pragma check runs first, on every scanned file.
3. **Patterns:**
   - `browser-opener-no-scheme-check`: `webbrowser.open(...)`/`os.startfile(...)` called with an
     argument referencing `auth`/`oauth`/`authorize`/`authorization` that does not run on into a
     longer word: after it comes no lowercase letter, or a lowercase `url`/`uri`/`link` ending the
     word (`auth_url`, `authUrl`, `authurl`, `oauthurl`, `server_auth_url`, `googleauth_url`,
     `/oauth/`; not `author_page`, `authority`, `author_url` or `authenticated_url`; a bare
     `url`/`endpoint` is not an OAuth hint), AND the file shows no scheme
     check anywhere: `.startswith("https`/`.startswith('https`, or a `urlparse(...).scheme`
     `==`/`!=` comparison against `"https"`.
   - `auth-url-opened-via-shell`: `subprocess.run/Popen/call/check_call/check_output(...)` or
     `os.system(...)` called with an argument referencing an auth-url-shaped variable name
     (`auth_url`/`authorization_url`/etc.), when the call hands a string to a shell:
     `os.system` always; a subprocess call with `shell=True`, with a non-list first argument
     (a command string), or with a list whose program is a shell (`sh`/`bash`/`zsh`/`dash`/
     `ksh`/`fish`/`csh`/`tcsh`/`cmd`/`powershell`/`pwsh`, bare or path-qualified, optionally
     `.exe`, optionally reached through an `env`/`wsl`/`busybox` first element). `["cmd", "/c", "start",
     auth_url]` re-parses the URL, so a `&` in it is command injection on Windows (the
     CVE-2025-6514 class). A list naming a non-shell program (`['xdg-open', auth_url]`,
     positional or `args=`) passes no string to a shell and does not fire.
4. **Inline opt-out pragma:** `# security: allow-mcp-unsafe-auth-url-launch` anywhere in the
   file silences both rules for that file.
5. **Severity and rules:**
   - `mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check` — HIGH
   - `mcp-unsafe-auth-url-launch/auth-url-opened-via-shell` — HIGH
   - Standards: `["OWASP-ASI:ASI04"]`

## When NOT to flag

```python
# Safe — scheme validated before opening:
if not auth_url.startswith("https://"):
    raise ValueError("refusing to open a non-HTTPS authorization URL")
webbrowser.open(auth_url)

# Safe — webbrowser.open() with no auth-flow-shaped argument (unrelated to this guard):
webbrowser.open(docs_path)
```

Suppress a reviewed, intentional case with `# security: allow-mcp-unsafe-auth-url-launch` in
the file.

## Tests

| Test | What it checks |
|---|---|
| `test_browser_open_fires_without_scheme_check` | `webbrowser.open(auth_url)` with no scheme check fires |
| `test_browser_open_fires_on_startfile` | `os.startfile(authorization_endpoint)` fires |
| `test_browser_open_silent_with_scheme_check` | FP-bait: a `.startswith("https://")` check anywhere silences it |
| `test_browser_open_silent_on_unrelated_call` | FP-bait: `webbrowser.open()` with no auth-flow argument stays silent |
| `test_shell_open_fires_on_subprocess_run` | `subprocess.run(f'open {auth_url}', shell=True)` fires |
| `test_shell_open_fires_on_os_system` | `os.system(f'start {authorization_url}')` fires |
| `test_shell_open_silent_on_unrelated_subprocess_call` | FP-bait: an unrelated subprocess call stays silent |
| `test_shell_open_silent_on_argv_list_form` (+ `_with_extra_kwarg`) | FP-bait: `['xdg-open', auth_url]` and `['git', 'clone', auth_url]` stay silent |
| `test_shell_open_fires_on_argv_list_that_invokes_a_shell_interpreter` | `cmd /c start`, `cmd.exe`, a path-qualified `cmd.exe`, `powershell`, `pwsh`, `sh -c`, `/bin/bash -c` and an `args=` cmd list all fire |
| `test_shell_open_silent_on_argv_list_of_a_non_shell_program` | FP-bait: `cmdline-tool`, `sha256sum`, `/usr/bin/open` and `args=['xdg-open', auth_url]` stay silent |
| `test_shell_open_fires_on_argv_list_with_shell_true` | a list with `shell=True` and an f-string command fires |
| `test_shell_open_silent_without_file_level_mcp_marker` | FP-bait: the unsafe shape in a file that does not import the MCP SDK stays silent |
| `test_browser_open_silent_with_urlparse_scheme_check` | FP-bait: a `urlparse(...).scheme != 'https'` check silences it |
| `test_browser_open_silent_on_bare_url_argument` | FP-bait: `webbrowser.open(url)` with no auth word stays silent |
| `test_browser_open_silent_on_auth_lookalike_names` | FP-bait: `author_page`, `authority`, `authors_url` stay silent |
| `test_browser_open_fires_on_auth_segment_names` | snake, camel and screaming-case auth names, a prefix segment, an attribute and an inline `/oauth/` path all fire |
| `test_browser_open_fires_on_concatenated_and_prefixed_auth_names` | `authurl`, `oauthurl`, `authlink`, `AUTHURL`, `googleauth_url`, `reauth_url` fire |
| `test_browser_open_silent_when_url_follows_a_longer_auth_word` | FP-bait: `author_url`, `authority_url`, `authenticated_url` stay silent |
| `test_shell_open_fires_on_launcher_wrapped_or_extra_shells` | `bash.exe`, `/usr/bin/env sh`, `env bash`, `wsl bash`, `busybox sh`, `fish` and `tcsh` lists fire |
| `test_shell_open_silent_on_launcher_running_a_non_shell_program` | FP-bait: `env xdg-open`, `wsl xdg-open`, `envoy` and `fishy-tool` stay silent |
| `test_browser_open_silent_without_file_level_mcp_marker` | FP-bait: the same opener call in a file that does not import the MCP SDK stays silent |
| `test_mcp_unsafe_auth_url_launch_applies_gate` | `applies()` gates on `"mcp"` in profile features |
| `test_mcp_unsafe_auth_url_launch_pragma_silences` | file-level pragma suppresses both rules |

## Known bypasses

- A URL built across several statements before being passed to the opener is still detected
  (the pattern matches the opener call line itself, regardless of how the argument was built) —
  but a scheme check performed in a different function the opener call doesn't see textually
  (the whole-file presence check only looks for the literal `.startswith("https` substring or a
  `urlparse(...).scheme ==/!= "https"` comparison, not its call site) could under-report if
  neither appears verbatim. Conversely a mitigated file still fires when the check is spelled
  another way: `.startswith(("https://",))`, `urlparse(x).scheme in ("https",)`, a two-step
  `scheme = urlparse(x).scheme`, or `.startswith("http")`.
- An opener call wrapped in a local helper function (`def open_url(u): webbrowser.open(u)`,
  called as `open_url(auth_url)`) is not traced back to the real opener.
- Non-Python MCP clients (TypeScript/Java/Rust) are not covered — this guard is Python-only.
- An OAuth launch in a helper module that does not itself import the MCP SDK is not scanned
  (the file-level marker). A multi-line `subprocess.run(` call whose auth-url argument sits on
  a later line is not matched either (line-based).
- A launcher with flags or `VAR=value` before the shell (`["wsl", "-e", "bash", ...]`,
  `["env", "FOO=1", "sh", ...]`) is not recognized as invoking a shell.

## What this guard does NOT prove

- That the authorization URL itself is built safely upstream (e.g. that `redirect_uri` is
  validated, or `state`/PKCE is present) — see `mcp-oauth-flow-hardening` for those checks.
- That a scheme check elsewhere in the file is actually applied to THIS specific opener call
  (a whole-file presence check, not a per-call-site proof).

# Citations

[1] agentsec checklist item `4-mcp-unsafe-auth-url-launch` (§4)
[2] OWASP-ASI:ASI04
[3] MCPVul (BarDavid2394) `mcp_scanner/analyzers/project_risks.py` — `MCP15-UNSAFE-AUTH-URL` rule
