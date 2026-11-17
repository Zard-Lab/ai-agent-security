---
type: Guard
title: "command-injection"
description: "No OS-command injection via a shell sink."
timestamp: "2026-10-06T16:40:12+00:00"
guard_id: "command-injection"
checklist_section: ["3b"]
standards: ["OWASP-LLM:LLM05", "OWASP:A03"]
---

# No OS-command injection via a shell sink

Flags an OS shell sink whose argument is **dynamic** (f-string / `+`/`%`/`.format` / a bare variable).
Closes checklist item `3b-command-injection`. The OS-shell sibling of `3b-sql-parameterized`.

## The threat

`os.system(f"ping {host}")` with `host = "8.8.8.8; rm -rf /"` runs the attacker's command — remote
code execution on the host. Always-shell sinks (`os.system`, `os.popen`, `subprocess.getoutput`,
`subprocess.getstatusoutput`, `commands.getoutput`) pass their string to `/bin/sh`, so any steerable
input is injectable; `subprocess.<fn>(..., shell=True)` is the same hazard. For an AI agent that shells
out, this turns one prompt injection into host RCE (OWASP-LLM:LLM05 excessive agency → real action).
OWASP A03 (Injection), CWE-78.

## Exploitability rationale

CRITICAL. Direct, unauthenticated-reachable RCE when the steered input crosses a request/tool boundary;
maximal blast radius (host shell). Tracks the SQLi severity for the same reason.

## Argv-list form: an interpreter re-invoked one level down

`subprocess.run(["bash", "-c", user_cmd])` never sets `shell=True` and is not an always-shell sink
— but its own array re-invokes a shell/interpreter (`bash`/`sh`/`python`/`python3`/`node`/`perl`/
`ruby`/...) with a dynamic trailing argument after a code-exec flag (`-c`/`-e`/`--eval`), which is
the same attacker-controlled-command outcome one layer down. Fires the same CRITICAL rule id family
(`command-injection/argv-interpreter-untrusted`); `subprocess.run(["python3", "-c",
"print('static')"])` does NOT fire — the interpreter's own argument is a literal.

## What counts as "dynamic" (and what doesn't)

Dynamic (fires): an f-string (`f"..."`/`rf"..."`), `.format(`, a format `%` (`%s`/`"... " % x`), a
quote-adjacent `+` concat (`"cat " + p`), or **no string literal at all** (a bare variable/expression).
Static (silent): a single quoted literal with none of the above (`os.system("ls -la")`).

Only the sink's **command argument** is judged: the first positional argument, else the `args=`
keyword's value (`subprocess.run(shell=True, args=cmd)`). Other arguments and code after the call on
the same line never affect the verdict. So `subprocess.run(cmd, cwd="/tmp", shell=True)` and
`os.popen(cmd, "r")` fire, because the command is a bare variable whatever literal sits beside it.
`subprocess.run("make", cwd=base + "/x", shell=True)` stays silent, because the dynamic text is in
`cwd=`, not in the command. A comma inside the command's own literal or nested brackets
(`"%s %s" % (a, b)`, `env={"A": "1", "B": x}`) is not an argument boundary. A command reachable
only through a `**mapping` unpack (`subprocess.run(**opts, shell=True)`) is judged as that variable.

## When NOT to flag (and the pragma)

- **Array-form exec** — `subprocess.run(["ping", host])` (no `shell=True`) → silent, even with a
  variable; no shell is involved, so there is nothing to inject. This is the recommended fix.
- **Static literal command** → silent.
- **`shell=True` only inside a string literal** → silent. For `subprocess.<fn>(...)`, `shell=True`
  counts only as a real keyword argument. Text inside a single-line string literal neither enables
  the check (`subprocess.run(cmd + " --flag shell=True")` runs no shell) nor marks where the command
  ends. So `subprocess.run("usermod --shell=/bin/zsh " + user, shell=True)` keeps its dynamic
  command intact, and it fires.
- **Commented-out** lines → silent.
- An audited-safe shell call → suppress that line with `# security: allow-shell-exec`.

## Known bypasses (honest limits)

- **Multi-line calls.** Detection is line-oriented; a `subprocess.run(` whose `shell=True` sits on a
  later line, or an `os.system(` whose argument is built on previous lines, is not matched. (bandit's
  B602/B605, an optional runner, catches some of these — defense in depth.)
- **Indirection.** `cmd = f"..."; os.system(cmd)` — the sink sees a bare variable, so it *does* fire
  (no-literal rule), but `os.system(build())` where `build` returns a constant is a (rare) false
  positive; pragma covers it.
- A literal containing an unusual `%`/`+` pattern could mis-fire; pragma covers it.
- **A literal subscript key reads as static.** `subprocess.run(cfg["cmd"], shell=True)` and
  `os.system(env["CMD"])` carry a literal (the key), so the command looks like a static string and
  stays silent.
- **A list command with `shell=True` reads as static.** `subprocess.run([cmd, "x"], shell=True)`
  carries a literal element, so it stays silent, although with `shell=True` the first element is
  still run by the shell.

## What this guard does NOT prove

It catches a dynamic shell sink in source; it does **not** prove the input is actually
attacker-controlled (it may be a trusted constant resolved elsewhere) nor that every exec path is
shell-free. Absence of a finding ≠ the app is provably free of command injection — array-form exec and
input validation are still the controls.

# Citations

[1] agentsec checklist item `3b-command-injection` (§3b)
[2] OWASP-LLM:LLM05
[3] OWASP:A03
