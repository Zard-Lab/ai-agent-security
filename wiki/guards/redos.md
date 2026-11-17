---
type: Guard
title: "redos"
description: "No catastrophic-backtracking regex (ReDoS)."
timestamp: "2026-10-06T07:33:53+00:00"
guard_id: "redos"
checklist_section: ["3a"]
standards: ["OWASP:A03", "OWASP:A05"]
---

# No catastrophic-backtracking regex (ReDoS)

Flags a `re.*` call whose pattern contains a nested quantifier (`(a+)+`, `(.*)*`, `(\d+){2,}`).
Closes checklist item `3a-no-redos`. Applies on `python`.

Also flags regex INJECTION (sub-rule `redos/regex-injection`, CWE-730/CWE-943) — a distinct bug
class mined from CodeQL's `python/ql/src/Security/CWE-730/RegexInjection.ql` (verified against the
real query's `RegexInjectionCustomizations.qll`: sink is any `RegexExecution`'s pattern argument,
sanitizer is the OUTPUT of `re.escape()`).

## The threat
A nested quantifier can backtrack exponentially on a crafted input, pinning a CPU core and hanging the
worker evaluating it (CWE-1333, ReDoS). On a request path, one such pattern plus one malicious string
is a denial of service.

**Regex injection** is a separate threat: if the PATTERN itself (not the subject string) is built from
untrusted input, an attacker controls what the regex matches or rejects, regardless of whether it also
backtracks catastrophically — e.g. a validation regex an attacker can widen to always match, or an
access-control check they can make always pass.

## Exploitability rationale
MEDIUM for both sub-checks. The backtracking case is availability-only (a hung worker). The injection
case's impact depends entirely on what the regex gates — could be low (a cosmetic validation) or high
(an authorization check) — MEDIUM reflects that this guard can't tell which without more context.

## When NOT to flag (and the pragma)
- A safe regex (no nested quantifier) → silent.
- The nested-quantifier text outside a `re.*` call (e.g. in a doc string) → silent (scoped to actual
  regex calls).
- A pattern built dynamically but wrapped in `re.escape()` on the same line → silent (regex-injection
  sub-check only).
- A pattern composed only from names the file proves clean → silent (regex-injection sub-check only,
  #688). Only the PATTERN argument is checked; the subject string is not, so
  `re.match(BASE + "$", value)` is silent. Every dynamic `re.` call on a line is checked on its own
  pattern, so a constant first call does not clear a dynamic second one, and a call written in a
  trailing comment is not checked (unless the line also holds an f-string the scan cannot read: the
  comment cut's string mask cannot read one either, so that line is scanned whole). An f-string field is read whole: a nested format spec counts
  (`f"{u:{W}}"` reads `u` and `W`), a nested f-string's fields count, `{{`/`}}` escapes are literal
  text, and a quoted key is not a name (`f"{CONFIG['date']}"` reads `CONFIG`, exactly as the `+`
  operand `CONFIG["date"]` does). An interpolated name is clean when:
  - it is ALL_CAPS (`BASE_PATTERN`, `MAX_LEN`): a constant by naming convention, the original rule; or
  - EVERY binding of it in the module is a single-name `=`, `: T =` or `:=` of a str/int literal,
    `re.escape(...)`, a clean name, or an f-string or `+` composition of those. That covers
    `date_expr = r"..."`, and `domain = re.escape(host)` on the line above the call (#689); or
  - it is `self.X` / `cls.X` where `X` is such a name, assigned plainly (no annotation) in the body of
    the class enclosing the call, never annotated in any class body in the file, and never an
    attribute store target in the file (celery's `self._range`).
- An audited case → `# security: allow-redos` on the line (covers both sub-checks).

## Known bypasses (honest limits)
- Detects the common nested-quantifier shape; some catastrophic patterns (overlapping alternations like
  `(a|a)*`, polynomial cases) are not matched.
- A pattern built from a variable (`re.compile(var)`) is not inspected — only inline literals. That holds
  on a line with a dynamic call too: `re.match(u, s) and re.match(f"{BASE}", s)` is silent.
- **Regex-injection sub-check is call-site-only, no interprocedural tracking**: `pattern = "^" + u + "$"`
  on one line, then `re.compile(pattern)` on the next, is not flagged — the same accepted limitation as
  the backtracking check above (and documented elsewhere in this codebase for other regex-based guards).
  `re.escape()` detection is line-scoped too: if a line interpolates two untrusted values and
  only one is escaped, the guard stays silent — a coarse heuristic, not a proof of safety.
- **Binding resolution fails closed, so some literal compositions still fire.** Bindings are unioned
  module-wide rather than per function, so a name that is a literal in one function and a parameter in
  another fires in both. Any other binding kind (parameter, loop or `with` target, unpacking, augassign,
  import, `del`) makes the name unresolvable. A star import or a dynamic namespace write anywhere in the
  file (`setattr`, `globals()`, `locals()`, `vars()`, `exec`, `__dict__`, `__setattr__`, or any
  `sys.modules` reference) switches resolution off for the whole file. An f-string whose field the line
  scan cannot read fires outright: a same-quote string inside it (`f"{d["k"]}"`, legal since Python
  3.12), a stray `}`, or an unterminated quote inside a field (one quote used as a format-spec fill
  character, `f"{x:'>9}"`, is read this way too). Two fill quotes in one f-string are the exception:
  they pair up as a string and hide whatever lies between them (`f"{W:'>5} {u:'>5}"` is silent), a
  known limit of the line scan, which does not tell a field's expression from its format spec. `self.X` inherited from a base class is not resolved, and neither is `ClassName.X` or a
  bare `escape` imported via `from re import escape`. An unparseable file falls back to the ALL_CAPS rule.
- **Binding resolution does not model other modules.** A module literal rebound from another module
  (`mod.prefix = v`), or a class literal overridden by a subclass in another module, is cleared here even
  though it can be tainted at runtime. A dataclass, pydantic or attrs field (an annotated class-body
  default) is never cleared, because its value is constructor-supplied.

## What this guard does NOT prove
It flags a risky inline pattern; it does not prove the input is unbounded, that no other ReDoS exists
(e.g. in a dependency), or that a dynamically-built pattern is actually reachable by an attacker.
Absence of a finding ≠ ReDoS-free or injection-free.

# Citations

[1] agentsec checklist item `3a-no-redos` (§3a)
[2] OWASP:A03
[3] OWASP:A05
