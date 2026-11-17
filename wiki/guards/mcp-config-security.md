---
type: Guard
title: "mcp-config-security"
description: "MCP server configuration contains dangerous misconfigurations."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "mcp-config-security"
checklist_section: ["4"]
standards: ["CWE-78", "OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP-LLM:LLM03", "OWASP:A02", "OWASP:A05", "OWASP:A08"]
---

# MCP server configuration contains dangerous misconfigurations

_Author — 2026-06-28_

---

## The threat

MCP (Model Context Protocol) server configuration files are JSON/YAML/TOML files that declare
how an LLM host connects to external tool servers. They are typically committed to source control
and are read by every developer, CI pipeline, and deployment environment that clones the repo.

Concrete attacks this guard targets (the summary below predates several rules the Detection
design section covers in full, including `secret-in-url-query` and `remote-no-auth-field`;
that section is the current, complete list — this paragraph is the historical overview):

**MCP001-005 — Hardcoded credential in env block (CRITICAL):** An operator copies a real API
key into the ``env`` block of an MCP server definition so the server process can access an
external API. The key is now in git history forever. Any prompt injection through any MCP
tool can instruct the model to read and exfiltrate the value. Standards: OWASP:A02, OWASP:A05.

**MCP006 — Root filesystem grant (HIGH):** A filesystem MCP server is configured with
``"roots": ["/"]``. A single prompt injection payload delivered through any tool's content —
document, email, web page — gives an attacker full read/write access to the host filesystem
via the model's filesystem tool calls. Standards: OWASP-LLM:LLM02, OWASP:A05.

**MCP007 — HTTP (non-HTTPS) transport (HIGH):** A remote MCP server is reachable over
cleartext HTTP. Any on-path attacker can intercept tool invocations, log parameters (which
often include sensitive context), and inject responses that redirect the model's actions.
Standards: OWASP:A05.

**MCP018 — Parameter name injection (HIGH):** A malicious MCP server definition encodes
prompt injection instructions in a tool parameter's **name** rather than its description
text. Description-content scanners (``mcp-tool-description-injection``) only scan the
``description`` field; this attack evades that layer by hiding instructions in the JSON key.
Standards: OWASP-LLM:LLM02.

**MCP013 / BCC exfil — Email BCC without allowlist (HIGH):** An MCP email tool exposes a
``bcc`` parameter with no ``allowed_domains`` or ``allowed_recipients`` restriction. A prompt
injection through any tool in the MCP session can silently BCC arbitrary email content —
including conversation history and attachments — to an attacker-controlled address.
Standards: OWASP-LLM:LLM02.

**MCP-EXEC — Dangerous exec-target command field (CRITICAL, added 2026-08-04 batch,
mined from `agent-threat-rules`):** A server's ``command`` field resolves to ``curl``/``wget``
directly, or to a bare shell wrapper (``bash``/``sh``/``cmd``/``powershell``) whose ``args``
carry a real payload marker (a URL fetch, pipe-to-shell, or base64/encoded-command), instead of
a package-manager runner (``npx``/``uvx``/``pipx``) or language interpreter
(``node``/``python``/``docker``). A config only an attacker can write — via a poisoned
repository, a supply-chain commit, or an unauthenticated registration endpoint — achieves code
execution the moment the server is spawned, no prompt injection required. Real precedent:
CVE-2025-54136 (Cursor's `.cursor/mcp.json` auto-loaded on workspace open, `command` resolved
via `child_process.spawn` with no integrity check) and CVE-2026-22688 (WeKnora's MCP plugin
loader treating a user-writable config's `command` as an OS-exec target). Standards: OWASP:A08,
CWE-78.

**MCP-ENV-HIJACK — Process-hijacking env var in a stdio server's env block (CRITICAL, added
2026-08-04 batch, mined from `agent-threat-rules`):** A server's ``env`` block sets a
well-known process-hijacking variable (``NODE_OPTIONS`` with a require/loader payload,
``LD_PRELOAD``, ``DYLD_INSERT_LIBRARIES``, ``BASH_ENV``, ``PYTHONSTARTUP``, ``PERL5OPT``,
``RUBYOPT``, ``GCONV_PATH``) — variables with no benign flag-only mode, since their value IS the
hijack payload. The ``env`` block is trusted verbatim and forwarded to the spawned server
process, so a workspace/repository shipping a poisoned config makes the MCP child load
attacker-controlled code the moment an operator starts a session using that server. Real
precedent: GHSA-mj59-h3q9-ghfh (OpenClaw, CVE-2026-44995). Standards: OWASP:A08, CWE-78.

**MCP-CONSENT — Consent bypass via `autoApprove`/`alwaysAllow` (HIGH, added 2026-08-22,
checklist `4-mcp-tool-trust` gap closure):** A server entry sets `autoApprove` (or the
`alwaysAllow` alias used by some client forks) to `true` — approving every tool call from
that server with no user confirmation — or to a non-empty array of specific tool names —
auto-approving only those tools. Real MCP clients (Claude Desktop, Cline, Roo-Code, and
forks) read this field at call time to skip the per-call consent prompt entirely; it is the
literal implementation of "consent before external calls" for MCP, and until this rule it
went entirely undetected. Critically, this is orthogonal to connection-time trust: a server
can be fully `"trusted": true` per `mcp-tool-unverified` (Rule 1 of that guard) and clean on
every other rule in *this* guard, and still ship `"autoApprove": ["send_email",
"delete_file"]` on the exact tools where a poisoned or injected instruction would otherwise
be caught by the human before it executes. Standards: OWASP-LLM:LLM03, OWASP-LLM:LLM01.

**MCP-STDIO-LAUNCHER-INJECT — Stdio launcher injection, two arms (CRITICAL, added 2026-09-22,
ported from `agent-audit-kit`'s real `mcp_stdio_launcher.py`):** A server's
``command``/``args`` combination is a launcher-injection sink in either of two independent ways.
**Arm 1:** ``command`` resolves to a shell-style launcher (``npx``/``node``/``bash``/``sh``/
``python``/``python3``) that is otherwise the legitimate MCP stdio launcher shape — but ``args``
carries an inline-code-execution flag (``-c``/``-e``/``-eval``/``--eval``) rather than a path to a
script file. The normal, reviewable shape is "launch this file"; the dangerous shape is "the
config's args ARE the executed code," exactly like MCP-EXEC above but for a launcher class that
MCP-EXEC's own allowlist (Rule 6) treats as always-legitimate. **Arm 2:** ``args`` carries a
non-pinned template/interpolation token — ``${...}`` embedded in a larger string (not a standalone
``${VAR}`` reference, which is host-resolved and safe), ``{{...}}``, or ``%s`` — regardless of which
launcher is used; this value is not a static literal, so its actual content at spawn time is
whatever produced the config, not what a reviewer reads in the file. A config only an attacker can
write — via a poisoned repository, a supply-chain commit, or an unauthenticated registration
endpoint — achieves code execution the moment the server is spawned, no prompt injection required.
Real precedent: CVE-2026-40933 (Flowise < 3.1.0, CVSS 9.9) — an authenticated actor registered a
stdio server whose allowlisted launcher (``npx``) was combined with ``-c`` to run arbitrary OS
commands. Standards: OWASP:A08, CWE-78.
**Corrected same day:** the guard initially shipped with an independently-invented, narrower Arm 1
only (``node``/``python``/``python3``/``ruby``/``perl``, no ``npx``/``bash``/``sh``, no Arm 2) before
the real `mcp_stdio_launcher.py` source was fully read — the earlier draft had only captured a
truncated prefix of the fetched file. Corrected to a faithful port once the rest of the source was
recovered; see Detection design below for the verbatim constants.

WHO reaches this: any code path that reads the MCP config file — local dev, CI, deployment.
WHAT privilege: depends on the tool; root filesystem grants, a dangerous exec command, and an
env-hijack variable are all host-level. BCC exfil requires only that the email tool is
reachable. A consent bypass hands whatever privilege the auto-approved tool itself carries —
often the most destructive tool in the server (file delete, email send, payment, exec) —
directly to a prompt-injected instruction, since the one gate designed to interrupt it before
irreversible action (the user confirmation prompt) has been configured away.
TO WHAT EFFECT: credential exfiltration, arbitrary file read/write, MITM of tool traffic,
silent email exfiltration, direct remote code execution at server-spawn time, or a silently
auto-executed destructive tool call with no human in the loop.

## Why it's often introduced / Why this guard fits the stack

MCP config files are patterned after ``claude_desktop_config.json``, which ships with examples
that use hardcoded env values for ease of getting started. Developers copy those examples
verbatim. A typical introduced misconfiguration:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_realTokenFromGetStartedGuide"
      }
    }
  }
}
```

Root path grants appear in filesystem server quickstarts that grant ``/`` so users do not
have to think about which directories to allow. HTTP transport appears when teams use internal
non-TLS-terminated load balancers. Parameter name injection is a supply-chain attack vector
from a compromised MCP server registry.

`autoApprove`/`alwaysAllow` is introduced for the most benign possible reason: the per-call
confirmation dialog is genuinely annoying during iterative development, so a developer adds
their whole toolset to `autoApprove` to stop the interruptions and then commits the config
file (or the team's shared `.mcp.json`) with the setting left in. Client documentation
presents it as a productivity feature, not a security control being switched off — there is
no warning that the field removes the one interruption point that would otherwise catch a
poisoned tool description or an injected instruction before it acts.

## Detection design

1. **applies() gate:** ``"mcp" in profile.features`` — only scans repos where MCP server
   configuration is detected (the ``mcp`` feature is set by ``detect.py`` when MCP-related
   files are present).

2. **File selection:** ``iter_files_named()`` is used for named glob patterns
   (``mcp.json``, ``mcp-*.json``, ``claude_desktop_config.json``, ``mcp_config.yaml``,
   ``mcp_config.toml``, ``pyproject.toml``, ``servers.json``, ``mcp-servers.json``,
   ``.mcp.json``). The ``.mcp/`` directory is scanned through the same shared walker with
   ``respect_gitignore=False`` (a config that a ``.mcp/.gitignore`` ignores stays in scope;
   subdirectories in the walker's ``DEFAULT_EXCLUDE_DIRS``, nested worktrees and symlinks under
   it do not, #1042).
   ``pyproject.toml`` is only inspected if it contains ``[tool.mcp]``.
   Non-product paths are skipped via ``is_nonproduct_path()`` — with ``credential_scan=True``, so
   the DEPLOYMENT trees (``migrations/``, ``alembic/``) stay in scope while the fake-secret trees
   (``tests/``, ``fixtures/``, ``examples/``) are still skipped. Rule 1
   (``hardcoded-secret-in-env``) is CRITICAL, and a real key committed under a migration tree is a
   real leak (#483).

3. **Parsing strategy:**
   - JSON files: ``json.loads()`` — structural walk for all seven rules.
   - YAML files: text-only scan (PyYAML is dev-only; zero runtime deps policy).
     Only Rule 3 (HTTP transport regex) and Rule 6's direct ``curl``/``wget`` case
     (``_COMMAND_DANGEROUS_TEXT``) are applied to YAML — Rule 6's shell-wrapper+payload-marker
     case and Rule 7 (env-hijack var) need the JSON structural walk to correlate ``command``
     with its sibling ``args``, and to reliably locate an ``env`` dict.
   - TOML files: text-only scan for the same reason.
   - Malformed JSON: falls back to text-only scan (Rules 3 and 6's direct case only).

4. **Rules / patterns (verbatim from ``Finding(...)`` calls):**
   - Rule 1: ``_walk_env_blocks()`` recursively finds all ``env`` dicts;
     ``_is_hardcoded_secret()`` checks key name against ``_SECRET_KEY`` and value
     against ``_ENV_VAR_REF`` / ``_OPAQUE_VALUE``.
     Rule: ``"mcp-config/hardcoded-secret-in-env"``, severity ``"critical"``.
   - Rule 2: ``_find_roots_and_paths()`` collects values under ``allowed_paths`` /
     ``roots`` / ``allowed_dirs``; ``_ROOT_PATH`` matches ``/`` or drive roots.
     Rule: ``"mcp-config/wildcard-path-grant"``, severity ``"high"``.
   - Rule 3: JSON path — ``_check_http_transport_json()`` walks ``url`` / ``endpoint`` /
     ``baseUrl`` / ``base_url`` keys recursively; text path — ``_HTTP_TRANSPORT`` regex.
     Both exempt ``http://localhost`` and ``http://127.0.0.1``.
     Rule: ``"mcp-config/http-transport"``, severity ``"high"``.
   - Rule 4: ``_find_tool_defs()`` collects tool dicts; ``_extract_param_names()`` reads
     ``parameters.properties`` / ``inputSchema``; ``_INJECTION_PARAM_NAME`` regex on names.
     Rule: ``"mcp-config/parameter-name-injection"``, severity ``"high"``.
   - Rule 5: ``_find_tool_defs()`` + email name match (``_EMAIL_TOOL_NAME``); checks
     for ``bcc`` / ``blind_copy`` parameter and absence of ``_RECIPIENT_ALLOWLIST``.
     Rule: ``"mcp-config/email-bcc-no-allowlist"``, severity ``"high"``.
   - Rule 6: ``_find_command_defs()`` collects all dicts with a string ``command`` key
     (normalized: basename, lowercased, ``.exe`` stripped). Direct case —
     ``command in _DANGEROUS_COMMAND_DIRECT`` (``curl``/``wget``) fires unconditionally.
     Shell-wrapper case — ``command in _DANGEROUS_COMMAND_SHELL`` (``bash``/``sh``/``cmd``/
     ``powershell``/``pwsh``) fires only if ``args`` joined together matches
     ``_SHELL_PAYLOAD_MARKER`` (a URL, pipe-to-shell, or base64/encoded-command marker) — a
     bare local-script launcher (``bash -c /abs/path/own-binary``) stays silent.
     Rule: ``"mcp-config/dangerous-exec-command"``, severity ``"critical"``.
   - Rule 7: ``_walk_env_blocks()`` (same helper as Rule 1) walks every ``env`` dict; a key
     (case-insensitive) in ``_PROCESS_HIJACK_ENV_VARS`` fires unconditionally, and
     ``NODE_OPTIONS`` fires only if its value matches ``_NODE_OPTIONS_PAYLOAD`` (a
     require/loader flag — not a memory/debug flag or the safe ``--import`` idiom).
     Rule: ``"mcp-config/dangerous-env-hijack-var"``, severity ``"critical"``.
   - Rule 8: ``_find_server_entries()`` — a new structural walker, same iterative-worklist
     shape as ``_walk_env_blocks()`` one level up: it collects the server dicts directly
     under any ``mcpServers``/``mcp_servers``/``servers`` key rather than diving into their ``env``
     sub-block. For each server entry, ``autoApprove``/``alwaysAllow`` fires if the value is
     ``True`` (server-wide bypass) or a non-empty list containing at least one non-empty
     string (a specific-tool bypass); ``False`` and ``[]`` are the safe/default states and
     do not fire. The check runs independently of Rule-1's ``"trusted"`` check — a server
     can pass every other rule in this guard and still fire this one.
     Text-fallback (YAML/TOML): ``_AUTO_APPROVE_BYPASS_TEXT`` matches
     ``autoApprove``/``alwaysAllow`` followed by ``true`` or an opening ``[`` immediately
     followed by a non-empty quoted string — this is weaker than the JSON structural walk
     (not anchored to the ``mcpServers``/``mcp_servers``/``servers`` scope) and is a documented
     FP/FN tradeoff, same as the guard's other YAML/TOML-only rules.
     Rule: ``"mcp-config/consent-bypass-auto-approve"``, severity ``"high"``.
     **Fixed 2026-08-23 (#692 review, H3):** ``_find_server_entries()`` originally recognized
     only ``mcpServers``/``mcp_servers`` as the top-level key, missing the ``servers`` form
     some real MCP client configs use (e.g. VS Code's ``mcp.json``) — a config using that key
     form was never walked at all, and a real consent-bypass entry under it went undetected.

   - Rule 9 (added 2026-09-22, corrected same day to a faithful port):
     ``_find_command_defs()`` (same helper as Rule 6) collects all dicts with a string
     ``command`` key (same basename/lowercase/``.exe``-strip normalization); ``args`` tokens
     are taken as-is (not lowercased, except when compared against the flag set). Two
     independent arms, checked per server entry:
     - **Arm 1** — the normalized command is in ``_STDIO_LAUNCHERS`` (``npx``/``node``/
       ``bash``/``sh``/``python``/``python3``, verbatim from the real source's
       ``_SHELL_LAUNCHERS``) AND any ``args`` token (lowercased for comparison) is in
       ``_INLINE_CODE_FLAGS`` (``-c``/``-e``/``-eval``/``--eval``, verbatim from
       ``_EXEC_FLAGS`` — note the single-dash ``-eval`` form alongside ``--eval``). ``npx``/
       ``bash``/``sh`` are deliberately included even though Rule 6 above already inspects
       them for a payload-marker shape — a different criterion (an exec flag vs a URL/pipe/
       base64 marker), so this is not a duplicate check, it's the real source's own design.
     - **Arm 2** — ANY ``args`` token (any launcher, not gated on Arm 1's set) matches
       ``_interpolation_hit()``: contains ``{{...}}``, contains ``%s``, or contains ``${`` and
       is NOT a standalone ``${VAR}`` reference (``_STANDALONE_ENV_TOKEN`` — the whole token,
       stripped, must match exactly, or it counts as unpinned). A standalone env reference is
       host-resolved at spawn time and treated as safe; anything embedded in a larger string,
       or a non-env template placeholder, is not a static literal.
     A script-file-path argument (``server.js``, ``-m my_mcp_server``) with no exec flag and no
     interpolation token stays silent — the normal MCP stdio launcher shape. JSON structural
     path only, same as Rule 6's shell-wrapper case — no text-scan fallback (see Rule 6's own
     note above). Rule: ``"mcp-config/stdio-launcher-inline-code-flag"`` (both arms share the
     rule id, matching the real source's single ``AAK-MCP-STDIO-LAUNCHER-INJECT-001``), severity
     ``"critical"``.
   - **Rule 10 — `secret-in-url-query`** (HIGH): ``_check_url_query_secret()`` walks every
     ``url``/``endpoint``/``baseUrl``/``base_url`` string. The ``#fragment`` is stripped first, and
     the ``?`` is looked for in the STRIPPED string (a ``?`` that lives only inside the fragment is
     client-side routing state, not a query). Each ``k=v`` pair is percent-decoded on both sides
     (``api%5Fkey`` is ``api_key``), then fires when the key matches ``_URL_QUERY_SECRET_KEY`` and
     the value is a 20+ character opaque literal that is not a ``${VAR}`` reference. No ``urllib``
     (banned in guard modules), so the split and the ``%XX`` decode are manual.
   - **Rule 11 — `remote-no-auth-field`** (HIGH): ``_check_remote_no_auth_field()`` over
     ``_find_server_entries()``. An entry with no ``command`` and a remote hint (``sse``/
     ``streamable-http`` transport, or an ``http(s)://``/``ws(s)://`` url) fires unless
     ``_entry_declares_auth()`` finds, anywhere in the entry, a KEY naming an auth mechanism
     whose value is a credential-like truthy value. A key names one when its HEAD word (the last
     camelCase/snake/kebab word, after a trailing version suffix such as ``2`` or ``v2`` is
     dropped) is an auth noun (``token``, ``secret``/``secrets``, ``password``, ``passwd``,
     ``credential``/``credentials``, ``authorization``, ``bearer``, ``oauth``, ``auth``,
     ``apikey``) or its last two words are ``api key``: ``apiToken``, ``accessToken``,
     ``GITHUB_TOKEN``, ``clientSecrets``, ``oauth2`` and ``x-api-key`` count, while
     ``maxTokens``, ``tokenizerModel``, ``secretSauceEnabled`` and an env block's ``MAX_TOKENS``
     do not (plural ``tokens`` is deliberately not an auth noun).
     Keys and values are checked structurally, never by regex over the serialised entry, so
     ``"auth": false``, ``"auth": {"enabled": false}``, ``"auth": "none"``, an empty
     ``Authorization`` header, a ``no_auth`` key and prose that merely contains the word "auth"
     all still fire. A literal loopback host (``localhost``, ``127.0.0.0/8``, ``::1``, the
     IPv4-mapped form; userinfo is stripped first so ``localhost@evil.example`` is not
     loopback) is skipped, since a local dev server in ``mcp.json`` needs no credential.
   - **Rule 3 extension:** ``ws://`` is treated as cleartext exactly like ``http://``
     (``localhost``/``127.0.0.1`` exempt).
   - **Config discovery extension:** besides the named globs and ``.mcp/``, any ``.json``
     file that itself contains an ``"mcpServers"``/``"mcp_servers"`` key is scanned (content-gated,
     so an unrelated JSON file is not picked up).

4a. **Rules 12–14 (added 2026-09-26, `agent-audit-kit`'s `mcp_config.py`
   AAK-MCP-005/006/007/009, verified against real source):** per-server-entry checks, reusing
   ``_find_server_entries()``.
   - **Rule 12 — `unpinned-npx-uvx-fetcher`** (MEDIUM): the entry's ``command`` is ``npx``/
     ``uvx`` and its first non-flag ``args`` token (the package spec) carries no version pin —
     ``@<digit>``/``@^<digit>``/``@~<digit>`` for npx, ``==`` for uvx. ``@latest``/``@next``/
     ``@beta`` are deliberately NOT treated as pins (they are floating dist-tags, exactly the
     shape this rule exists to catch); an entry with no ``args`` at all makes no unpinned claim
     and stays silent.
   - **Rule 13 — `relative-path-command-hijack`** (HIGH): the entry's ``command`` contains a
     path separator (``/`` or ``\``) but does not start from an absolute root (``/``, ``~``, a
     drive letter, or a UNC ``\\`` prefix) — it resolves relative to the current working
     directory at spawn time. A bare command name with no separator at all (``node``, ``npx``)
     is PATH-resolved, not this rule's shape, and stays silent.
   - **Rule 14 — `remote-url-loopback-pivot`** (HIGH): a remote (no ``command`` field) entry's
     ``url``/``endpoint`` resolves to a DISGUISED loopback/link-local/unspecified address (an
     ``ipaddress``-verified match that is not the literal ``localhost``/``127.0.0.1``/``::1`` —
     see Known bypasses) — a "remote" server declaration that actually points at the local
     machine or an internal-only address.

5. **Inline opt-out pragma:** ``security: allow-mcp-config`` anywhere in the file. In a YAML or
   TOML config only a ``#`` comment counts (the comment view ``comment_dialect_for`` names, #1040
   T5), so a string value quoting the phrase does not suppress. A JSON config has no comment
   syntax, so there the phrase counts anywhere, string values included.

6. **Standards:** ``["OWASP-LLM:LLM02", "OWASP:A05", "OWASP:A02", "OWASP:A08", "CWE-78"]`` across
   all findings (Rules 6, 7, and 9 carry A08/CWE-78; the other rules carry the original three).

## When NOT to flag

- ``env`` values using ``${VAR}`` substitution syntax — these are safe env-var references.
- Non-secret key names (``PORT``, ``LOG_LEVEL``, ``MAX_RETRIES``) — ``_SECRET_KEY`` regex
  must match.
- ``allowed_paths`` with specific non-root directories — ``_ROOT_PATH`` only matches ``/``
  and drive roots like ``C:\``.
- ``http://localhost`` and ``http://127.0.0.1`` URLs — localhost is acceptable for local
  development and does not traverse a network path a MITM can reach.
- Tool parameter names that are legitimate but contain substring matches (e.g. ``bypass_cache``
  could match ``bypass_``); this is a known FP risk, mitigated by requiring the phrase to be
  the leading component of the name.
- Email tools that have ``allowed_domains`` or ``allowed_recipients`` restriction — these
  prove the operator has thought about recipient scope.
- ``command`` resolving to a package-manager runner or language interpreter
  (``npx``/``uvx``/``pipx``/``node``/``python``/``docker``) — the legitimate MCP stdio launcher
  shape.
- A shell wrapper (``bash``/``sh``/``cmd``/``powershell``) whose ``args`` carry no URL fetch,
  pipe-to-shell, or encoded-command marker — e.g. ``bash -c /absolute/path/own-built-binary``,
  a self-referential local launch idiom.
- ``NODE_OPTIONS`` set to a routine memory/debug flag (``--max-old-space-size``, ``--inspect``)
  or the blessed ``--import`` ESM-instrumentation idiom (Sentry/OpenTelemetry) — neither carries
  a require/loader code-loading capability.
- Any env var name not in the process-hijacking list — an ordinary ``API_KEY``/``PORT``/
  ``LOG_LEVEL`` entry stays silent.
- ``autoApprove: false`` or ``autoApprove: []`` (empty array) — these are the safe/default
  states; only ``true`` or a non-empty tool-name array fires.
- An ``autoApprove``/``alwaysAllow`` key that is NOT inside an ``mcpServers``/``mcp_servers``/``servers``
  entry (JSON structural path only) — e.g. an unrelated top-level flag in some other tool's
  config sharing the same key name.
- A stdio launcher (``npx``/``node``/``python``/etc.) with a script-file-path argument, or any
  passthrough flag not in ``_INLINE_CODE_FLAGS`` (``-m``, a plain package name) — the ordinary
  MCP stdio launcher shape.
- A command NOT in ``_STDIO_LAUNCHERS`` (e.g. ``docker``, ``uvx``) whose ``args`` happen to
  contain an ``-e`` token for an unrelated legitimate reason (``docker run -e VAR=x`` — ``-e``
  is Docker's own env-var flag) — Arm 1 only inspects the curated launcher set.
- A standalone ``${VAR}`` argv token (the whole token, nothing else) — host-resolved at spawn
  time and treated as pinned/safe by Arm 2.

Use the pragma ``# security: allow-mcp-config`` to suppress known-intentional findings.

## Tests

| Test | What it checks |
|---|---|
| `test_hardcoded_secret_in_env_fires` | Rule 1 fires on a literal API key in env block |
| `test_hardcoded_secret_env_var_reference_is_safe` | `${VAR}` reference does not fire (FP-bait) |
| `test_hardcoded_secret_non_secret_key_is_safe` | Non-secret key names do not fire (FP-bait) |
| `test_wildcard_path_grant_fires_on_root` | Rule 2 fires on `roots: ["/"]` |
| `test_wildcard_path_grant_fires_on_drive_root` | Rule 2 fires on `C:\` drive root |
| `test_wildcard_path_grant_specific_path_is_safe` | Specific paths `/app/data` do not fire (FP-bait) |
| `test_http_transport_fires_on_non_localhost` | Rule 3 fires on `http://internal.host/` |
| `test_http_transport_localhost_is_safe` | `http://localhost` does not fire (FP-bait) |
| `test_http_transport_https_is_safe` | `https://` does not fire (FP-bait) |
| `test_parameter_name_injection_fires` | Rule 4 fires on parameter named `ignore_previous` |
| `test_parameter_name_injection_normal_params_safe` | Injection text in description (not name) does not fire (FP-bait) |
| `test_email_bcc_no_allowlist_fires` | Rule 5 fires on `send_email` with `bcc` and no allowlist |
| `test_email_bcc_with_domain_allowlist_is_safe` | `bcc` + `allowed_domains` does not fire (FP-bait) |
| `test_pragma_suppresses_all_findings` | Pragma suppresses all rules |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` returns False without mcp feature |
| `test_guard_applicable_with_mcp_feature` | `applies()` returns True with mcp feature |
| `test_nonproduct_path_skipped` | Files under `tests/fixtures/` are skipped |
| `test_deployment_tree_is_still_scanned_for_secrets` | A key in `migrations/mcp.json` still fires (the `credential_scan=True` wiring, #483) |
| `test_dangerous_exec_command_curl_fires` | Rule 6 fires on `command: "curl"` |
| `test_dangerous_exec_command_shell_wrapper_with_payload_fires` | Rule 6 fires on `bash -c` wrapping a pipe-to-shell payload (indirect bypass check) |
| `test_dangerous_exec_command_legit_launcher_is_safe` | `npx`/`uvx`/`node`/`python`/`docker` launchers do not fire (FP-bait) |
| `test_dangerous_exec_command_shell_wrapper_without_payload_is_safe` | `bash -c` launching a local self-built binary does not fire (FP-bait) |
| `test_env_hijack_ld_preload_fires` | Rule 7 fires on `LD_PRELOAD` in an env block |
| `test_env_hijack_node_options_require_fires` | Rule 7 fires on `NODE_OPTIONS=--require ...` (CVE-2026-44995 pattern) |
| `test_env_hijack_node_options_memory_tuning_is_safe` | `NODE_OPTIONS=--max-old-space-size` does not fire (FP-bait) |
| `test_env_hijack_node_options_import_instrumentation_is_safe` | `NODE_OPTIONS=--import ./instrument.mjs` does not fire (FP-bait) |
| `test_env_hijack_ordinary_api_key_is_safe` | An ordinary `API_KEY` env var does not fire (FP-bait) |
| `test_consent_bypass_auto_approve_array_fires` | Rule 8 fires on `autoApprove: ["send_email", "delete_file"]` |
| `test_consent_bypass_auto_approve_true_fires` | Rule 8 fires on `autoApprove: true` |
| `test_consent_bypass_always_allow_alias_fires` | Rule 8 fires on the `alwaysAllow` alias |
| `test_consent_bypass_fires_even_when_server_is_trusted` | Rule 8 fires even on a server marked `"trusted": true` (the exact gap this rule closes) |
| `test_consent_bypass_auto_approve_false_is_safe` | `autoApprove: false` does not fire (FP-bait) |
| `test_consent_bypass_auto_approve_empty_array_is_safe` | `autoApprove: []` does not fire (FP-bait) |
| `test_consent_bypass_unrelated_top_level_key_is_safe` | An `autoApprove` key outside any server entry does not fire (FP-bait) |
| `test_consent_bypass_servers_key_form_fires` | Rule 8 fires under the `servers` top-level key form (e.g. VS Code's `mcp.json`) — 2026-08-23 fix, #692 review H3 |
| `test_consent_bypass_yaml_text_fallback_fires` | The YAML text-fallback path still catches the array form |
| `test_consent_bypass_yaml_text_fallback_false_is_safe` | The YAML text-fallback does not fire on `autoApprove: false` (FP-bait) |
| `test_stdio_launcher_node_eval_flag_fires` | Rule 9 Arm 1 fires on `node -e '<code>'` |
| `test_stdio_launcher_python_c_flag_fires` | Rule 9 Arm 1 fires on `python -c '<code>'` |
| `test_stdio_launcher_long_eval_flag_fires` | Rule 9 Arm 1 fires on the long `--eval` flag form |
| `test_stdio_launcher_npx_eval_flag_fires` | Rule 9 Arm 1 fires on `npx -c '<code>'` — CVE-2026-40933's own (Flowise) shape |
| `test_stdio_launcher_embedded_template_token_fires` | Rule 9 Arm 2 fires on a non-standalone `${BASE_DIR}` embedded in a larger argv string |
| `test_stdio_launcher_double_brace_template_token_fires` | Rule 9 Arm 2 fires on a `{{...}}` templating token, regardless of launcher |
| `test_stdio_launcher_script_file_arg_is_safe` | A stdio launcher with a script-file path does not fire (FP-bait) |
| `test_stdio_launcher_non_interpreter_command_with_e_flag_is_safe` | Docker's own `-e` env-var flag does not fire — `docker` is not in `_STDIO_LAUNCHERS` (FP-bait) |
| `test_stdio_launcher_standalone_env_ref_is_safe` | A standalone `${VAR}` argv token does not fire — host-resolved and pinned (FP-bait) |
| `test_stdio_launcher_yaml_text_fallback_does_not_fire` | Documented scope-narrowing: YAML configs get no Rule 9 coverage (no text-scan fallback) |

## Known bypasses

- **Environment variable indirection:** If the secret is loaded from a separate file (e.g. a
  ``.env`` file loaded at runtime) rather than in the ``env`` block, Rule 1 does not fire.
  The ``service-role-key`` and ``vite-client-secret`` guards cover some of those patterns.
- **YAML / TOML structural parsing absent:** Rules 1, 2, 4, 5 are only applied structurally
  to JSON. YAML and TOML files (incl. `pyproject.toml [tool.mcp]`) receive only the text-based
  Rule 3 check. A team using YAML for their MCP config can have hardcoded secrets or root grants
  that this guard misses.
- **Short secrets (Rule 1):** the secret-value heuristic requires a 20+ char opaque run
  (`_OPAQUE_VALUE`) to avoid flagging placeholders/paths — so a short literal secret
  (`"password": "hunter2"`, a 16-char key) under a credential-named key is a false negative.
- **`mcp` feature detection** is anchored (a real `import mcp` / `from mcp`, an `mcp` dependency
  spec, a `[tool.mcp]` section, or `@modelcontextprotocol/sdk` as a package.json dependency key
  for a JS/TS server, #981) rather than a bare "mcp" substring, so a package merely
  containing the letters "mcp" (e.g. `fastmcp`) no longer flips the feature (PR #228 review).
  Per-rule `standards` corrected the same review (Rule 4 → LLM01; Rule 1 → A02/CWE-798).
- **Aliased key names:** If an operator uses a non-standard key for credentials (e.g.
  ``my_custom_key``) that does not match ``_SECRET_KEY``, Rule 1 does not fire.
- **Indirect path grants:** If ``allowed_paths`` is built dynamically at runtime (not in the
  static config file), the guard cannot detect a root grant.
- **Email tool name variants:** If an email tool is named something not matching
  ``_EMAIL_TOOL_NAME`` (e.g. ``compose_message``), Rule 5 does not fire.
- **YAML/TOML shell-wrapper case (Rule 6):** the ``command in _DANGEROUS_COMMAND_SHELL`` +
  ``args`` payload-marker check only runs on the JSON structural path — a YAML/TOML config
  using a shell wrapper with a payload in its args list is not caught by the text-only fallback
  (only the direct ``curl``/``wget`` case is).
- **Path-obscured commands (Rule 6):** the normalization strips a leading path and ``.exe``
  suffix, but an unusual quoting or environment-variable-expanded command
  (``"command": "$SHELL"``) is not resolved and so does not match ``_DANGEROUS_COMMAND_DIRECT``/
  ``_DANGEROUS_COMMAND_SHELL``.
- **YAML/TOML env-hijack case (Rule 7):** only applied to the JSON structural path — a YAML/TOML
  config with a process-hijacking env var is not caught by the text-only fallback.
- **Unlisted hijack variables (Rule 7):** the variable list (``LD_PRELOAD``, ``NODE_OPTIONS``,
  etc.) is curated from documented process-hijacking primitives; a less common or newly
  discovered hijack vector under a different variable name would not fire.
- **YAML/TOML consent-bypass anchoring (Rule 8):** the text-fallback regex is not anchored
  to the ``mcpServers``/``mcp_servers``/``servers`` scope the JSON structural walk enforces — an
  unrelated ``autoApprove``/``alwaysAllow`` key elsewhere in a YAML/TOML file could be a false
  positive, the same limitation this guard already accepts for its other YAML/TOML-only
  rules.
- **Non-array-of-strings tool lists (Rule 8):** an ``autoApprove`` value that is a non-empty
  array containing only non-string elements (unusual, but not disallowed by any client spec)
  would not fire — the check requires at least one non-empty string element.
- **Runtime-toggled consent (Rule 8):** if a client's consent bypass is configured outside
  the static MCP config file (a runtime setting, an environment variable read by the client
  itself, or a UI toggle persisted elsewhere), this guard — which only reads the config file
  — cannot see it.
- **YAML/TOML inline-code-flag case (Rule 9):** like Rule 6's shell-wrapper case, this needs
  the JSON structural walk to correlate ``command`` with its sibling ``args`` array — a
  YAML/TOML config using the same inline-eval shape is not caught by any text-only fallback
  (there isn't one for this rule at all).
- **Unlisted launchers (Rule 9, Arm 1):** the launcher list (``npx``/``node``/``bash``/``sh``/
  ``python``/``python3``) is curated, verbatim from the real source; an inline-eval flag on a
  launcher not in that list (``deno``, ``ruby``, ``perl``, a less common runtime) would not fire.
- **Multi-token flag construction (Rule 9, Arm 1):** an inline-eval flag built dynamically from
  config templating or string concatenation before reaching the ``args`` array (rather than
  appearing as a literal token) is not resolved by the guard's static list-membership check.
- **Multiple env references in one token (Rule 9, Arm 2):** ``${A}${B}`` is not a standalone
  single reference (the whole-token regex requires exactly one), so it fires even though each
  half is individually host-resolved — a narrow over-fire the real source's own carve-out
  inherits, not something this port introduced.

- **Auth key present but not real (Rule 11):** the structural check accepts any auth-named key
  with a truthy value, so a placeholder (``"token": "changeme"``) or an auth key the server never
  reads counts as auth. It proves a credential is DECLARED, not that it is enforced.
- **Auth carried outside the entry (Rule 11):** a credential injected by the client at runtime
  (a global header setting, an OS keychain, a proxy in front of the server) is invisible to a
  static config read, so a truthful remote entry can still fire. The rule is HIGH but its message
  hedges for exactly this reason; a public docs server with no auth is a legitimate intended case.
- **Obfuscated loopback (Rule 11):** the loopback carve-out is literal only (``localhost``,
  a parsed IP literal). ``127.1``, ``0x7f.1``, a DNS name that resolves to loopback, or
  ``*.localhost`` are not exempt and will fire.
- **Non-ASCII / double-encoded query keys (Rule 10):** the key is percent-decoded once, so
  ``%255F`` (double-encoded) and non-ASCII keys are not normalised. A short (under 20 character)
  literal value also stays silent, as with Rule 1.

- **Unpinned launcher (Rule 12):** only `npx` and `uvx` are read, and only the first package-looking
  argument (the first non-flag one). `pnpm dlx`, `bunx` and `pipx run` are not covered. A pin is any `@<digit>`/`@^<digit>`/`@~<digit>` or `==`, so a pinned
  major only (`@1`) counts as pinned even though it floats within that major.
- **Relative-path command (Rule 13):** a bare command name (`server`, `node`) is resolved through
  `PATH`, which is a different hijack surface this rule does not model; only a path that contains a
  separator and is not absolute or `~`-rooted is flagged.
- **Loopback pivot (Rule 14):** the literal words `localhost`, `127.0.0.1` and `::1` are
  deliberately exempt (a local dev server in `mcp.json` is the most common shape there is, and the
  transport rule already treats `http://localhost` as acceptable). The rule fires on what
  DISGUISES loopback or internal reach: the rest of `127.0.0.0/8`, the legacy numeric spellings
  (`127.1`, `0x7f.1`, `0177.0.0.1`, a bare integer), an IPv4-mapped IPv6 literal, `0.0.0.0`,
  and link-local / cloud-metadata addresses (`169.254.169.254`, `fe80::`). A DNS name that merely
  resolves to loopback (`localtest.me`, an attacker-controlled record) is not resolved offline and
  stays silent. Bracketed IPv6 hosts and userinfo (`user:pw@127.1`) are parsed correctly.

## What this guard does NOT prove

- That the MCP server config is correctly placed in ``.gitignore`` (secrets in config may
  still be committed if the file is not gitignored).
- That dynamically constructed MCP server configs (built at runtime from environment
  variables) are safe — only static files are scanned.
- That YAML or TOML MCP configs do not have hardcoded secrets, wildcard paths, parameter
  name injection, or BCC-capable email tools (structural checks require parsing, which
  requires PyYAML/tomllib as runtime deps that violate the zero-runtime-dep policy).
- That the MCP server binary actually validates the ``allowed_paths`` restriction at runtime.

# Citations

[1] agentsec checklist item `4-mcp-config-security` (§4)
[2] agentsec checklist item `4-mcp-tool-trust` (§4)
[3] CWE-78
[4] OWASP-LLM:LLM01
[5] OWASP-LLM:LLM02
[6] OWASP-LLM:LLM03
[7] OWASP:A02
[8] OWASP:A05
[9] OWASP:A08
[10] CVE-2026-40933 (Flowise, inline-eval MCP stdio launcher, CVSS 9.9)
[11] agent-audit-kit (sattyamjjain/agent-audit-kit), MCP stdio launcher-injection scanner
[12] agent-audit-kit `mcp_config.py`, rules AAK-MCP-005/006/007/009 (Rules 12-14: unpinned
     npx/uvx fetcher, relative-path command hijack, remote-URL loopback pivot)
