---
type: Guard
title: "php-command-injection"
description: "No PHP OS-command injection via system()/exec()/passthru()/popen()/shell_exec()/proc_open() called with a tainted argument."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-command-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03", "OWASP-LLM:LLM05"]
---

# No OS-command injection via a PHP shell sink

Flags PHP's six OS-shell-executing functions — `system()`, `exec()`, `passthru()`, `popen()`,
`shell_exec()`, `proc_open()` — called with an argument that is not a fixed command string. Closes
checklist item `3b-command-injection` for the `php` stack feature, alongside the existing Python
(`command-injection`) and JS/TS (`js-command-injection`) siblings. CWE-78 (OS Command Injection),
OWASP:A03, OWASP-LLM:LLM05.

## The threat

A shell sink that receives interpolated, concatenated, or variable input runs whatever the
attacker can steer that string to. `system($_GET['host'])` with `host = "8.8.8.8; rm -rf /"` is
remote code execution on the host. This is a top agent-tool risk too: a PHP tool endpoint that
shells out turns one piece of untrusted input (a user request, or model output in an LLM-backed
app) into host RCE.

## Exploitability rationale

CRITICAL. A direct code-execution primitive once attacker-controlled data reaches the sink — the
same severity class as the Python `command-injection` guard and `code-injection-eval-exec`.

## What counts as a hit (and what doesn't)

Fires when one of the six functions is called with a first argument that is **not a sole string
literal**:

- a bare variable (`$cmd`) or a superglobal (`$_GET[...]`, `$_POST[...]`, `$_REQUEST[...]`,
  `$_COOKIE[...]`, `$_ENV[...]`, `$_SERVER[...]`);
- string concatenation with `.` — even of two literals, since the *shape* (building the command at
  runtime) is the risk signal, matching the Python sibling's stance on f-strings/concat/`.format()`;
- a function-call result (`popen(getUserCmd(), 'r')`);
- a **double-quoted** string literal that itself contains a `$` — PHP interpolates variables
  inside `"..."` (unlike `'...'`), so `system("ping $host")` is exactly as tainted as
  `system($host)`.

Silent when the argument is a fixed command:

- `system('ls -la')` — single-quoted literal, never interpolated by PHP.
- `system("ls -la")` — double-quoted literal with no `$` inside it, so nothing to interpolate.
- Commented out (`// exec($cmd);`) or inside a real `#` line comment — silent; `strip_php_comments`
  is string-aware, so a mention only inside a string literal on the same line is not mistaken for a
  real call.

## When NOT to flag (and the pragma)

A value that is validated/allow-listed immediately before the call, or a deliberately reviewed
exception, should be suppressed explicitly rather than left to trip the guard on every scan:

```php
exec($cmd); // security: allow-php-shell-exec
```

**Sink-name string-literal awareness (#848 corpus scan, round 2).** A sink function name appearing
as literal TEXT inside a quoted string — e.g. `matomo-org/matomo`'s `core/CliMulti/Process.php`
building a diagnostic message with `'shell_exec(' . self::PS_COMMAND . '...'` — read as a real call
under the old text-only match. The guard now tracks PHP single-/double-quoted string state
(escape-aware, carried across lines since a `.`-concatenated string can span a literal newline) and
skips a sink match whose position sits inside an active string literal. A real call is, by
definition, never itself inside a string literal, so this costs nothing on the true-positive path
(verified both directions, including a genuine call on the line right after an unrelated string
closes).

## Known bypasses (honest limits)

- **No dataflow, no context.** Fires on the call-site shape alone — a variable/superglobal/
  concatenation/interpolation argument — with no attempt to trace whether that value is actually
  attacker-reachable or was already sanitized higher up (e.g. via `escapeshellarg()` on a prior
  line). The pragma is the intended correction, not a guard limitation to fix later.
- **Single-line, textual.** A first argument built across multiple lines, or a modifier/flags
  string assembled elsewhere and passed in by reference, is not traced. The first-argument
  extraction is quote- and paren-depth-aware but only within one source line.
- **Heredoc/nowdoc are not recognized.** `strip_php_comments` (and this guard's own argument
  scanner) does not special-case PHP's `<<<EOT ... EOT` string forms — a shell-sink call whose
  first argument is a heredoc rather than a quoted literal or bare variable is not reliably
  classified. Rare in the call-site shapes this guard targets, documented rather than silently
  assumed away.
- **`escapeshellarg()`/`escapeshellcmd()` wrapping the tainted value still fires.** The guard has
  no concept of "already escaped" — `exec('ping ' . escapeshellarg($host))` still trips the
  concatenation rule, because proving the escape call is correct and covers every reachable code
  path is exactly the dataflow reasoning this guard does not attempt. A reviewed, escaped call is
  a pragma candidate, not a false positive to silently special-case.

## What this guard does NOT prove

A clean scan means no shell-sink call-site with a dynamic-looking argument was found in the
scanned PHP source — it says nothing about equivalent behavior reached via a wrapper function, a
dependency's own internal use of the shell, or a value that looks like a literal today but is
templated/generated before deployment.

## Canary plant

`CommandInjection.php` — `system($_GET['host'])` inside a function body, no pragma. Expected rule:
`php-command-injection/tainted-shell-sink`.

# Citations

[1] agentsec checklist item `3b-command-injection` (§3b)
[2] OWASP:A03 (Injection)
[3] OWASP-LLM:LLM05 (Improper Output Handling)
[4] CWE-78 (Improper Neutralization of Special Elements used in an OS Command / OS Command
    Injection)
[5] graudit (`wireghoul/graudit`) — `signatures/php.db` (provenance for the six-function PHP
    shell-sink surface only; the "dynamic argument" detection logic here is original)
