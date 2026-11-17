---
type: Guard
title: "ldap-injection"
description: "LDAP query built from unescaped untrusted input."
timestamp: "2026-07-11T20:19:21+08:00"
guard_id: "ldap-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03"]
---

# LDAP query built from unescaped untrusted input

_Marconi (research-cycle: codeql-security-queries) — 2026-07-11_

---

## The threat

An LDAP search call whose base-DN or filter argument is built from untrusted input — an f-string
or string concatenation — without escaping lets an attacker inject LDAP filter/DN syntax (e.g.
`*)(uid=*))(|(uid=*`), altering which directory entries match. Depending on what the query gates
(an auth check, a permission lookup), this ranges from information disclosure to authentication
bypass. CWE-90. OWASP A03:2021 — Injection.

## Why this guard fits the stack

Mined from CodeQL's `python/ql/src/Security/CWE-090/LdapInjection.ql`, verified against the real
`LdapInjectionCustomizations.qll`: two distinct sinks (`LdapExecutionAsDnSink`,
`LdapExecutionAsFilterSink` — the base-DN and filter arguments of an LDAP search), sanitized by an
escaping call (`LdapDnEscapingSanitizer`/`LdapFilterEscapingSanitizer`, i.e.
`escape_dn_chars`/`escape_filter_chars` from `python-ldap` or `ldap3`).

**Corpus-prevalence note, said plainly:** this was flagged as a lower-priority candidate in the
2026-07-11 research pass — LDAP is a niche integration for a FastAPI + React + Postgres + LLM/RAG
stack, not a common one. Built anyway because the detection is clean and the underlying pattern is
real (CodeQL itself gives it a dedicated query), same reasoning as building `xpath-injection`
alongside it — Marconi approved both at the research-cycle human gate with the low-prevalence
caveat named up front, not discovered after the fact.

## Detection design

1. `applies()` gates on `"python" in profile.features`.
2. Scans `.py` files via `python_scan_dirs` + `iter_files`.
3. `_LDAP_SEARCH_S_CALL` matches `.search_s(`/`.search_ext_s(` (python-ldap) as a bare method-name
   match — those names are distinctive enough on their own. `_LDAP3_SEARCH_CALL` matches ldap3's
   bare `.search(` **only when the call also carries `search_base=`/`search_filter=`** on the same
   line. **Real bug caught and fixed during this guard's build**: an earlier version matched bare
   `.search(` unconditionally, which collided with the stdlib's `re.search(...)` — confirmed as an
   actual false positive against agentsec's own source (`detect.py:24`, `detect.py:273`,
   `js_harden.py:49`, `js_harden.py:66`, all `re.search(rf"...")` calls) when the full-batch
   self-audit gate ran. Requiring ldap3's own distinctive kwargs removes the false positive without
   losing real detection, since that's ldap3's actual calling convention anyway.
4. `_DYNAMIC_ARG` reuses the same shape as `redos.py`'s regex-injection sub-check: an f-string, `+`
   concatenation, or `.format(` call, present ANYWHERE on the same line as the search call.
5. `_ESCAPE_SANITIZER` (`escape_dn_chars`/`escape_filter_chars` on the line) suppresses.
6. Severity MEDIUM (`standards=["OWASP:A03"]`). Suppress with `# security: allow-ldap-injection`.

## When NOT to flag

- A static filter string (`"(objectClass=*)"`) — no dynamic construction, silent.
- A dynamically-built filter where the untrusted portion is wrapped in
  `escape_filter_chars(...)`/`escape_dn_chars(...)` on the same line.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_fstring_filter` | `search_s(..., f"(uid={username})")` → MEDIUM |
| `test_flags_same_line_concatenation` | `search_s(..., "(uid=" + username + ")")` → fires |
| `test_silent_when_escaped` | `escape_filter_chars(username)` wrapping the tainted part → silent |
| `test_silent_on_static_filter` | Static literal filter → silent |
| `test_pragma_suppresses` | `# security: allow-ldap-injection` → silent |
| `test_na_without_python` | `applies()` returns False without `python` |
| `test_flags_ldap3_style_search_kwargs` | `conn.search(search_base=..., search_filter=f"...")` → fires |
| `test_silent_on_bare_re_search` | `re.search(rf"...")` (the actual FP caught) → silent |
| `test_silent_on_generic_dot_search` | An unrelated `.search(` (e.g. a cache client) → silent |

## Known bypasses (honest limits)

- **No interprocedural tracking**, same class of limitation as every other regex-based guard in
  this codebase: `filt = "(uid=" + username + ")"` on one line, then `conn.search_s(base, scope,
  filt)` on the next, is NOT flagged — verified during this guard's own adversarial self-test
  (deliberately constructed as a bypass case, confirmed silent, and left that way rather than
  over-fitting the regex to catch it).
- A custom or wrapped escaping helper (not literally named `escape_dn_chars`/`escape_filter_chars`)
  is not recognized and would cause a false positive.
- ldap3's `.search(` is only recognized with its own `search_base=`/`search_filter=` kwargs present
  on the same line — a call that passes those as positional args instead (unusual but valid) would
  be missed. Accepted: the kwarg form is the overwhelmingly common convention in real ldap3 code,
  and the alternative (bare `.search(`) is the exact false-positive already caught once.

## What this guard does NOT prove

It flags a plausible same-line sink reachable from a same-line dynamic-construction pattern; it
does not prove the input is actually attacker-reachable, nor that no LDAP injection exists via a
longer call chain or a custom query-builder this guard doesn't recognize.

# Citations

[1] agentsec checklist item `3b-ldap-injection` (§3b)
[2] OWASP:A03
