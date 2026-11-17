---
type: Guard
title: "java-hardcoded-password-key"
description: "Hardcoded password/key literal passed as an argument to a named security-sensitive Java API."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-hardcoded-password-key"
checklist_section: ["8"]
standards: ["OWASP:A04"]
---

# Hardcoded password/key literal passed to a security-sensitive Java API

Flags a **constant string/char-array literal** passed directly as the password or key argument to
one of a small set of named security-sensitive Java APIs. Extends checklist item
`8-hardcoded-private-key-in-source` — the same weakness class (CWE-321, Use of Hard-coded
Cryptographic Key) as agentsec's existing `hardcoded-private-key-in-source` guard, but a
genuinely different detection mechanism and code surface. OWASP:A04, CWE-321.

## The threat

A password or cryptographic key literal embedded in source and passed to a named JDBC/JCE API is
committed to version control the same way any other secret is — readable by anyone with repo
access (contributors, CI logs, forks, scraped public mirrors), and it survives even after the
line is later removed, since git history retains it. Unlike a generic "secret-looking string"
scan, this guard anchors on a **known API call shape**, so the argument position is unambiguous:
by the JDBC/JCE contract, the flagged argument genuinely is the password or key, not a guess based
on a variable name.

## Exploitability rationale

CRITICAL. A hardcoded JDBC password is a direct path to the database with no further exploitation
required — anyone who reads the source has a live credential. A hardcoded PBE/AES key is
equivalent for whatever it protects. This is a straight secret disclosure, not a technique that
requires chaining.

## Relationship to `hardcoded-private-key-in-source`

The existing `hardcoded-private-key-in-source` guard greps for a literal PEM private-key header
(`-----BEGIN ... PRIVATE KEY-----`) anywhere in any file, language-agnostic — it has no concept of
a method call at all. This guard is Java-specific and shape-specific: it recognizes a **named API
call** (`DriverManager.getConnection`, `new PBEKeySpec`, `new SecretKeySpec`) and fires only when
the security-sensitive argument is a literal. A password embedded in `DriverManager.getConnection`
has no PEM header and would never trip the PEM guard; a PEM key committed as a `.pem` file has no
Java method call around it and would never trip this one. Both extend the same checklist item
rather than duplicating each other's detection.

## What counts as a hit (and what doesn't)

- **`DriverManager.getConnection(url, user, "literalPassword")`** — the JDBC 3-argument form,
  when the third (password) argument is a plain double-quoted string literal. This is the
  **primary, most reliable pattern** implemented here (lowest false-positive risk: the JDBC API
  contract makes the third argument's role unambiguous) and the guard's canary plant.
  `DriverManager.getConnection(url, user, password)` (a variable) or
  `DriverManager.getConnection(url, user, System.getenv("DB_PASSWORD"))` does **not** fire.
- **`new PBEKeySpec("literalPassword".toCharArray(), ...)`** — a literal string converted directly
  via `.toCharArray()` and passed as PBE key material. `new PBEKeySpec(passwordVar.toCharArray(), ...)`
  does not fire.
- **`new SecretKeySpec("literalKey".getBytes(), ...)`** — a literal string converted directly via
  `.getBytes()` and passed as raw key material. `new SecretKeySpec(keyBytesVar, "AES")` does not
  fire.
- A 2-argument `DriverManager.getConnection(url)` (no separate password argument) does not fire —
  only the 3-argument form is in scope.

## When NOT to flag (and the pragma)

- A file on a non-product path (`is_nonproduct_path`) → silent: a JDBC password under
  Maven/Gradle's `src/test/java` or a `fixtures/` tree is deliberately fake. DEPLOYMENT trees are
  the carve-out (`credential_scan=True`), so Flyway's Java migrations at
  `src/main/java/db/migration/` are still scanned — a password committed there is a real leak.
- Commented out (`// DriverManager.getConnection(url, "user", "pass")`) → silent; comment
  stripping is string-aware, so a `//`/`/*` inside a genuine string literal on the same line is
  not mistaken for a comment start.
- Inside a real `/** ... */` Javadoc block mentioning the pattern → silent.
- A documented decoy/test fixture → suppress explicitly:

```java
DriverManager.getConnection(url, "dbuser", "s3cr3tP@ss"); // security: allow-hardcoded-password-key
```

## Known bypasses (honest limits)

- **No dataflow, no context.** The guard fires on the literal syntactic shape at the call site; it
  does not trace whether the literal originated from a constant defined elsewhere and referenced by
  name (a `private static final String PASSWORD = "s3cr3t";` followed by
  `DriverManager.getConnection(url, user, PASSWORD)` would NOT fire, since the call-site argument is
  an identifier, not a literal — a real false negative, accepted for this pass).
- **Single-line, textual.** Like every other guard in this codebase, matching happens against one
  physical line; a call whose arguments are split across multiple lines is not traced.
- **Scope deliberately narrowed to three call shapes.** Find Security Bugs' real sink list
  (`password-methods-all.txt`) covers additional password/key-accepting methods across the JDK and
  common libraries beyond the three implemented here. `KeyStore.load(InputStream, char[])` was
  considered but deferred — the password argument there is frequently a `char[]` literal array
  (`new char[]{'p','a','s','s'}`) rather than a `String` literal converted via `.toCharArray()`,
  a distinct shape not covered by this guard's regexes; tracked as a possible future extension, not
  silently assumed covered.
- **`.toCharArray()`/`.getBytes()` are the only literal-to-array conversions recognized.** A literal
  wrapped in an intermediate variable before conversion (`String pw = "s3cr3t"; new
  PBEKeySpec(pw.toCharArray(), ...)`) is not traced back to its literal origin and will not fire.

## What this guard does NOT prove

A clean scan means no literal password/key argument was found at one of the three named call
sites in the scanned Java source — it says nothing about a credential embedded via a named
constant, a `char[]` array literal, a different security-sensitive API not in this guard's scope,
or a secret injected via build-time string concatenation.

## Canary plant

`HardcodedJdbcPassword.java` — `DriverManager.getConnection("jdbc:mysql://db/app", "dbuser",
"s3cr3tP@ss")` inside a method body, no pragma. Expected rule:
`java-hardcoded-password-key/literal-jdbc-password`.

# Citations

[1] agentsec checklist item `8-hardcoded-private-key-in-source` (§8)
[2] OWASP:A04 (Insecure Design) / CWE-321 (Use of Hard-coded Cryptographic Key)
[3] Find Security Bugs — `password-methods/password-methods-all.txt`, rules `HARD_CODE_PASSWORD` /
    `HARD_CODE_KEY` (provenance only; detection logic here is original)
