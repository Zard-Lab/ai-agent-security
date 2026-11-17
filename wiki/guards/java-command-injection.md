---
type: Guard
title: "java-command-injection"
description: "No OS-command injection via a Java Runtime.exec/ProcessBuilder sink built from concatenated or variable input."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-command-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03", "OWASP-LLM:LLM05"]
---

# No OS-command injection via a Java process-exec sink

Flags `Runtime.getRuntime().exec(...)`/`Runtime.exec(...)`, `new ProcessBuilder(...)`, and
`.command(...)` (on a presumed `ProcessBuilder` instance) called with a concatenated or
variable argument. Closes checklist item `3b-command-injection` — the Java counterpart to
the existing `command-injection` (Python) and `js-command-injection` (JS/Node) guards,
extending the same checklist item rather than duplicating it. OWASP:A03, OWASP-LLM:LLM05,
CWE-78.

## The threat

A process-exec sink that receives a command string built from concatenation, or a bare
variable, runs whatever an attacker can steer that value to. Java's single-string
`Runtime.exec(String)` overload tokenizes the string itself with a naive whitespace split
before handing the pieces to the OS — not a real shell, but functionally the same
attacker-steerable shape as Python's `os.system(f"...")` or `subprocess.run(...,
shell=True)`: `Runtime.getRuntime().exec("ping " + host)` with `host = "8.8.8.8 &
rm -rf /tmp"` lets an attacker inject additional argv tokens. This is a top agent-tool
risk too — a tool that shells out to run a command turns one prompt injection into host
RCE.

## Exploitability rationale

CRITICAL. A tainted single-string `exec()`/`ProcessBuilder` call, reachable from any
external input (an HTTP parameter, a tool argument an LLM agent controls, a config value
sourced from user data), is remote code execution on the host — the same severity class
as the Python and JS siblings.

## What counts as a hit (and what doesn't)

- **`Runtime.getRuntime().exec("cmd " + userInput)`** fires — the classic single-string,
  concatenated idiom.
- **`Runtime.getRuntime().exec(cmd)`** (a bare variable, no string literal at all) fires.
- **`Runtime.exec(cmd)`** (the bare spelling, also listed as a sink by Find Security
  Bugs) fires the same way.
- **`new ProcessBuilder(cmd)`** and **`pb.command(cmd)`** fire under the identical
  concatenation-or-bare-variable test.
- **`Runtime.getRuntime().exec("ls -la")`** (a fully static string literal) does **not**
  fire — nothing to inject into.
- **`Runtime.getRuntime().exec(new String[]{"ls", "-la"})`** (the array-argument form,
  all elements literal) does **not** fire — no shell-like tokenizer is invoked when every
  argv element is passed separately.

## When NOT to flag (and the pragma)

- A file on a non-product path (`is_nonproduct_path`) → silent. Maven and Gradle put test
  sources under `src/test/java`, whose `test` segment reads as non-product, alongside the shared
  `fixtures/`/`examples/` list and a repo's own configured `archive_segments`.
- A fully static exec()/ProcessBuilder call → silent (the safe form).
- Commented out (`// Runtime.getRuntime().exec(cmd)`) → silent; comment stripping is
  string-aware, matching `java-weak-crypto`'s handling.
- Inside a real `/** ... */` Javadoc block mentioning the pattern → silent.
- A deliberately audited case → suppress explicitly:

```java
Runtime.getRuntime().exec(cmd); // security: allow-java-command-injection
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Like every sibling command-injection guard, this fires on
  the call shape directly, with no attempt to prove the variable argument is actually
  attacker-reachable. The pragma is the intended correction, not a guard limitation to
  fix later.
- **Array-literal arguments are never reasoned about — this is the deliberate scope
  gap, not an assumption of safety.** `exec(new String[]{"cmd", "arg"})` with every
  element a literal is correctly silent (no shell invoked), but `exec(new
  String[]{"cmd", userInput})` with one tainted element is **also silent**: this guard
  does not inspect array-literal contents at all. The same gap applies to a
  comma-separated varargs call mixing literals and a variable (`new
  ProcessBuilder("sh", "-c", cmd)`) — reasoning about individual elements of a
  multi-argument call is out of scope for a text/regex-only guard with no dataflow.
  Tracked as a known bypass, matching Find Security Bugs' own more-nuanced (bytecode
  dataflow) handling of the same shapes, which this guard does not attempt to replicate.
- **`.command(...)` is matched on the bare method name.** Without type resolution, this
  guard cannot prove the receiver is actually a `java.lang.ProcessBuilder` — any other
  class exposing a `.command(...)` method with a concatenated/variable argument would
  also fire. A documented, accepted FP source rather than a silent one.
- **Single-line, textual.** An `exec`/`ProcessBuilder` call whose argument is assembled
  across several lines is not traced — same textual scope as
  `command_injection.py`/`js_command_injection.py`.

## What this guard does NOT prove

A clean scan means no `Runtime.exec`/`ProcessBuilder`/`.command()` call site with a
concatenated-or-bare-variable argument was found in the scanned Java source — it says
nothing about a process spawned via a native library, a dependency that wraps
`Runtime.exec` internally, an array-literal argument with a tainted element (see "Known
bypasses" above), or a command string built and passed in from outside the scanned
source tree.

## Canary plant

`Deploy.java` — `Runtime.getRuntime().exec("systemctl restart " + service)` inside a
method body, no pragma. Expected rule: `java-command-injection/runtime-exec-tainted`.

# Examples

Fires:

```java
Runtime.getRuntime().exec("systemctl restart " + service);
Runtime.getRuntime().exec(cmd);
new ProcessBuilder(cmd).start();
pb.command(cmd);
```

Silent:

```java
Runtime.getRuntime().exec("ls -la");
Runtime.getRuntime().exec(new String[]{"ls", "-la"});
Runtime.getRuntime().exec(cmd); // security: allow-java-command-injection
```

# Citations

[1] agentsec checklist item `3b-command-injection` (§3b)
[2] OWASP:A03 (Injection)
[3] OWASP-LLM:LLM05 (Improper Output Handling)
[4] CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
[5] Find Security Bugs — `COMMAND_INJECTION` rule, `injection-sinks/command.txt`
    (provenance only; detection logic here is original)
