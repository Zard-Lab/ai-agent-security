---
type: Guard
title: "java-ldap-injection"
description: "LDAP query built from string concatenation in Java application code."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-ldap-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03"]
---

# LDAP query built from string concatenation (Java)

Flags a JNDI (`javax.naming.directory`) or Spring LDAP directory search/lookup whose base-DN or
filter argument is built via `+` string concatenation. Closes checklist item `3b-ldap-injection` —
the Java counterpart to the existing `ldap-injection` (Python) guard, extending the same checklist
item rather than duplicating it. CWE-90, OWASP:A03 (Injection).

## The threat

An LDAP search call whose base-DN or filter argument is built from untrusted input without
escaping lets an attacker inject LDAP filter/DN syntax (e.g. `*)(uid=*))(|(uid=*`), altering which
directory entries match. Depending on what the query gates (an auth check, a permission lookup),
this ranges from information disclosure to authentication bypass.

## Why this guard fits the stack

Mined from Find Security Bugs' real source (`LdapInjectionDetector.java`, rule `LDAP_INJECTION`,
sink list `injection-sinks/ldap.txt`), which covers `DirContext.search`, `InitialDirContext.search`,
`LdapContext.search`, and Spring LDAP's `LdapTemplate.search`/`.lookup` — the class name and rule
id are cited for provenance; the detection logic and test fixtures here are original, developed
independently against the pattern description, not copied or derived from that (Java) source.

## Exploitability rationale

MEDIUM, matching the sibling Python `ldap-injection` guard's severity: not a one-shot RCE, but a
real filter/DN-syntax injection whose blast radius depends entirely on what the query gates (an
auth check makes this an authentication-bypass primitive; a directory browse makes it information
disclosure). LDAP is a niche integration for this stack, same corpus-prevalence caveat the Python
guard already carries.

## Detection design

1. `applies()` gates on `"java" in profile.features`.
2. Scans `.java` files via `java_scan_dirs` + `iter_files`, per-line, exactly like
   `java-weak-crypto` (comment-stripped `code_lines` for the match, raw `raw_lines` for the
   pragma, paired with `zip(..., strict=True)`).
3. Two call-shape patterns, both receiver-name-scoped (no symbol table in this codebase — regex
   only):
   - `_DIR_CONTEXT_SEARCH` — `.search(` on a receiver literally named `ctx`, or any identifier
     containing `DirContext`/`LdapContext` (case-insensitive) — covers JNDI's `DirContext`,
     `InitialDirContext`, `LdapContext`, `InitialLdapContext`. `.lookup(` is deliberately NOT
     included for this family — plain `Context.lookup(name)` is a much broader, non-LDAP-specific
     JNDI API, out of scope here.
   - `_LDAP_TEMPLATE_CALL` — `.search(` or `.lookup(` on a receiver containing `LdapTemplate`
     (Spring LDAP; both are real methods that take a filter/name argument there).
4. `_CONCAT` — a quoted literal or identifier, `+`, another quoted literal or identifier — must
   appear on the **same line** as the call.
5. Fires MEDIUM, rule `java-ldap-injection/concatenated-filter`. Suppress with
   `// security: allow-ldap-injection`.

## What counts as a hit (and what doesn't)

- `ctx.search("ou=users,dc=example,dc=com", "(uid=" + username + ")", controls)` fires — inline
  concatenation, receiver named `ctx`.
- `dirContext.search(base, "(cn=" + name + ")", null)` fires — receiver name contains
  `DirContext`.
- `ldapTemplate.search(base, "(uid=" + username + ")")` and
  `ldapTemplate.lookup("uid=" + username + ",ou=users")` both fire.
- `ctx.search("ou=users,dc=example,dc=com", "(uid=admin)", controls)` (fully literal filter, no
  `+`) does **not** fire.
- `results.search(prefix + suffix)` on an unrelated receiver (e.g. a `List`) does **not** fire —
  the receiver name doesn't look LDAP-related.

## When NOT to flag (and the pragma)

- A file on a non-product path (`is_nonproduct_path`) → silent. Maven and Gradle put test
  sources under `src/test/java`, whose `test` segment reads as non-product, alongside the shared
  `fixtures/`/`examples/` list and a repo's own configured `archive_segments`.
- A static filter string — no dynamic construction, silent.
- Commented out (`// ctx.search(...)`) or inside a real `/** ... */` Javadoc block — silent
  (comment stripping is string-aware, same as `java-weak-crypto`).
- A deliberately audited case (the concatenated portion is a compile-time constant, or already
  escaped by a helper this guard doesn't recognize) — suppress explicitly:

```java
ctx.search(base, "(uid=" + username + ")", controls); // security: allow-ldap-injection
```

## Known bypasses (honest limits)

- **Deliberate receiver-name scoping tradeoff.** This is a regex/text scanner with no symbol
  table, so it cannot resolve `.search(`/`.lookup(`'s receiver to its declared type. A bare
  `.search(` is far too generic a method name to trust alone — it collides with cache clients,
  collection lookups, and more — so this guard requires the receiver's *name* to look LDAP-related
  (`ctx`, or containing `DirContext`/`LdapContext`/`LdapTemplate`). This is narrower than real type
  resolution: a `DirContext`-typed variable named something unconventional (e.g. `conn`, `d`) is
  **missed**. Conversely, any unrelated object a developer happens to name `ctx` (or
  `*DirContext*`) with its own unrelated `.search(` method is a **possible false positive**. This
  is the same class of naming-convention tradeoff the sibling Python `ldap-injection` guard already
  makes for ldap3's bare `.search(` (there, gated on `search_base=`/`search_filter=` kwargs
  instead of a name) — not overclaimed as precise, just the necessary condition for this codebase's
  zero-runtime-dependency, no-AST constraint.
- **Single-line, textual.** Like `java-weak-crypto`, this only sees concatenation that appears on
  the same physical line as the call. `String filter = "(uid=" + username + ")"; ctx.search(base,
  filter, controls);` — filter built on one line, used on the next — is **NOT** flagged. Verified
  during this guard's own adversarial self-test (deliberately constructed as a bypass case,
  confirmed silent, left that way rather than over-fitting the regex).
- **No dataflow.** No attempt is made to prove the concatenated portion is actually
  attacker-controlled — same posture as every other guard in this codebase; the pragma is the
  intended correction, not a guard limitation to fix later.
- **Java 17+ text blocks** are not comment/string-aware in `strip_java_comments` — a documented,
  pre-existing residual shared with every Java guard on this branch, not something this guard adds.

## What this guard does NOT prove

A clean scan means no same-line, name-scoped LDAP search/lookup call with inline `+` concatenation
was found — it says nothing about a filter built across multiple statements, a custom
query-builder wrapper this guard doesn't recognize, or a receiver named outside the scoped naming
convention.

## Canary plant

`LdapAuth.java` — `ctx.search("ou=users,dc=example,dc=com", "(uid=" + username + ")", new
SearchControls())` inside a method body, no pragma. Expected rule:
`java-ldap-injection/concatenated-filter`.

# Citations

[1] agentsec checklist item `3b-ldap-injection` (§3b)
[2] OWASP:A03
[3] CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query)
[4] Find Security Bugs — `LdapInjectionDetector.java`, rule `LDAP_INJECTION`
    (provenance only; detection logic here is original)
