---
type: Guard
title: "java-tls-verify-disabled"
description: "Empty (no-op) X509TrustManager checkServerTrusted/checkClientTrusted body — a client-side TLS certificate verification bypass."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-tls-verify-disabled"
checklist_section: ["8"]
standards: ["CWE-295"]
---

# Empty TrustManager (checkServerTrusted/checkClientTrusted does not validate)

Flags a Java `X509TrustManager`/`TrustManager` implementation whose `checkServerTrusted` and/or
`checkClientTrusted` method body is empty or comment-only — the textbook "trust every certificate"
TLS bypass idiom. Closes checklist item `8-tls-verify-disabled` alongside the existing Python
(`tls-verify-disabled`) and Go (`go-tls-verify-disabled`) guards, extending the same checklist item
rather than duplicating it. CWE-295 (Improper Certificate Validation).

## The threat

`javax.net.ssl.X509TrustManager` (extends `javax.net.ssl.TrustManager`) is Java's certificate-trust
extension point. `SSLContext.init(KeyManager[], TrustManager[], SecureRandom)` hands certificate
validation entirely to the supplied `TrustManager`s: `checkServerTrusted`/`checkClientTrusted` are
expected to throw `CertificateException` when the presented chain is untrustworthy. An
implementation with an empty method body never throws, so every chain is unconditionally accepted —
no chain-of-trust check, no expiry check, no hostname binding.

- **WHO reaches it:** any network-positioned attacker able to intercept traffic between the Java
  process and the server it's connecting to — a compromised router, a rogue Wi-Fi AP, a malicious
  or coerced proxy, or an attacker with DNS-spoofing capability on that path.
- **WITH WHAT PRIVILEGE:** none beyond network position. No credential or prior access to either
  endpoint is required.
- **TO WHAT EFFECT:** full man-in-the-middle — the attacker can read and modify every byte of the
  "TLS-protected" connection undetected.

This is the Java-language counterpart to `go-tls-verify-disabled` (`InsecureSkipVerify: true`) and
`tls-verify-disabled` (`requests.get(url, verify=False)`) — same underlying failure mode (a
client-side TLS verification bypass), reached through Java's own idiom: implementing the validation
callback and doing nothing in it, rather than flipping a boolean flag.

## Why it's often introduced

A developer needs to connect to a server presenting a self-signed certificate (local dev, an
internal CA not yet trusted by the JVM's trust store, a staging environment) and reaches for a
permissive `TrustManager` as the fastest way past `SSLHandshakeException:
PKIX path building failed`:

```java
TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] chain, String authType) { }
    public void checkServerTrusted(X509Certificate[] chain, String authType) { }
    public X509Certificate[] getAcceptedIssuers() { return null; }
} };
SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAllCerts, new java.security.SecureRandom());
```

It is a well-known copy-paste snippet from Stack Overflow answers and outdated tutorials offered as
a quick fix, with no mention of the tradeoff, and easy to forget to remove before shipping.

## Detection design

1. **`applies()` gate** — `"java" in profile.features`. Fires only on repos where Java source was
   actually detected.
2. **Files scanned** — every `.java` file under the detected Java dirs (`java_scan_dirs(root,
   profile)`), via `iter_files(d, (".java",))`.
3. **Pattern** — `\b(?:checkServerTrusted|checkClientTrusted)\s*\(`, matched on the method name
   ALONE, no `TrustManager`/`X509TrustManager` proximity requirement — the same "distinctive name
   carries the signal" reasoning `go-tls-verify-disabled` uses for `InsecureSkipVerify`. Neither
   name is a generic word; both are the exact, literal method names
   `javax.net.ssl.X509TrustManager` declares, with one well-documented, security-relevant contract.
4. **Definition vs. call site vs. abstract declaration** — a raw name match could be any of three
   things: a method DEFINITION (has a real `{...}` body), an abstract interface declaration (ends
   in `;`, no body at all), or a CALL SITE (`defaultTrustManager.checkServerTrusted(chain,
   authType);`, which also ends in `;`). The guard resolves the parameter list with
   `matching_close_paren` (shared helper, `guards/base.py`), then looks at whichever comes first
   after it: a `{` (real body — proceed) or a `;` (declaration or call — skip, nothing to
   inspect). This is what keeps a delegating call like
   `defaultTrustManager.checkServerTrusted(chain, authType);` inside a REAL validating method from
   being mistaken for its own empty definition.
5. **Body-empty test** — a small local brace-counter (`_matching_close_brace`, NOT quote-aware —
   see "Known bypasses") finds the method body's matching `}`. The body slice, from a copy of the
   file with `strip_java_comments` already applied, is fired on if `body.strip()` is empty:
   truly empty, or containing only what was a comment before stripping.
6. **Pragma check runs on the COMMENT-ONLY view of the line** — `security: allow-java-tls-verify-disabled`,
   checked against the comment-only view (`comment_view(…, "java")`, #424) of the line the method
   signature starts on, since the pragma IS a `//` comment `strip_java_comments` would otherwise
   blank away before a check against the stripped copy ever saw it, and a string literal quoting
   the phrase must not count. Two methods on the same anonymous class are evaluated
   independently — suppressing `checkServerTrusted` does not silence an unsuppressed, also-empty
   `checkClientTrusted` in the same file.
7. **Severity / rule / standards** — HIGH. A single rule id,
   `java-tls-verify-disabled/empty-trust-manager`, for both method names (same underlying
   vulnerability — an unconditionally-trusting validation callback — regardless of which of the
   two interface methods is empty). Standards: `["CWE-295"]`.

## What counts as a hit (and what doesn't)

- An empty `checkServerTrusted(...)` or `checkClientTrusted(...)` body (`{ }`, or a body containing
  only what was a `//`/`/** */` comment) → fires.
- Either method calling a real validating implementation
  (`defaultTrustManager.checkServerTrusted(chain, authType);`) or performing any real check
  (`chain[0].checkValidity()`, an `if`/`throw`) → does **not** fire — the body is non-empty.
- An interface's own abstract declaration (`void checkServerTrusted(...) throws Exception;`, no
  body) → does not fire; there is nothing to inspect.
- A call SITE (`d.checkServerTrusted(chain, authType);`, invoking someone else's `TrustManager`)
  → does not fire; it is a statement, not a definition.
- A mention only inside a `//` line comment or a `/** */` Javadoc block → does not fire; comments
  are blanked before the pattern match runs, so the method-name regex never matches inside one.

## When NOT to flag (and the pragma)

A file on a non-product path (`is_nonproduct_path`) is silent without a pragma at all. Maven and
Gradle put test sources under `src/test/java`, whose `test` segment reads as non-product — and a
deliberately permissive `TrustManager` confined to a test harness is exactly what lives there.

Suppress an audited case (e.g. a deliberately permissive `TrustManager` confirmed to be confined to
an isolated, non-production test harness that never reaches a real network path) with:

```java
public void checkServerTrusted(X509Certificate[] chain, String authType) { } // security: allow-java-tls-verify-disabled
```

## Known bypasses (honest limits)

- **No dataflow, no context.** The guard proves an empty validation callback exists in the scanned
  source; it does not trace whether the resulting `TrustManager` is ever actually installed via
  `SSLContext.init()`, or confirm the reverse (that a non-empty implementation is installed
  correctly and used consistently everywhere a connection is made).
- **`_matching_close_brace` is a plain nesting counter, NOT quote-aware** (unlike
  `matching_close_paren`, used for the parameter list). A `{` or `}` inside a string literal
  *within* the method body (e.g. a log message) would desync the brace count — most plausibly
  pulling trailing code into what the guard treats as "the body" (which only makes an
  empty-looking body register as non-empty, i.e. a missed detection, not a false one), but in
  principle a stray `}` inside a string could also close the count early and truncate a real body.
  This is the same class of textual-scanning tradeoff `strip_java_comments` already documents for
  Java 17+ text blocks, and that every regex/brace-counting guard in this codebase accepts by
  design (no AST, zero runtime dependencies) — the pragma is the intended correction for a false
  positive that results, not a guard limitation to fix later.
- **Indirection.** A body that calls out to a helper method which itself does nothing
  (`private void noop() {}`, then `checkServerTrusted` just calls `noop();`) is a non-empty body
  textually and does not fire, even though it is functionally identical to the direct empty case.
- **Single-file, textual.** A `TrustManager` implementation split across an interface in one file
  and its body defined via some generated/bytecode-manipulation mechanism is out of scope — same
  textual scope as every sibling guard on this branch.
- **Java 17+ text blocks** are not comment/string-aware in `strip_java_comments` (its own
  documented residual) — a body consisting solely of a text-block string literal is a rare shape
  for this specific method and not specially handled here.

## What this guard does NOT prove

A clean scan means no `checkServerTrusted`/`checkClientTrusted` implementation with an empty body
was found in the scanned Java source. It says nothing about a permissive trust manager built via
reflection, a third-party library that ships its own equivalent bypass internally, a
`HostnameVerifier` that unconditionally returns `true` (a related but distinct TLS-bypass surface,
not this guard's scope), or a `TrustManager` implementation that validates the chain but skips
hostname verification separately.

## Canary plant

`TrustAll.java` — an anonymous `X509TrustManager` with both `checkClientTrusted` and
`checkServerTrusted` bodies empty, `getAcceptedIssuers()` returning `null`. Expected rule:
`java-tls-verify-disabled/empty-trust-manager`.

# Citations

[1] agentsec checklist item `8-tls-verify-disabled` (§8)
[2] CWE-295 (Improper Certificate Validation)
[3] graudit Java bonus signature rules — `checkServerTrusted(`/`checkClientTrusted(`/
    `TrustManager` (provenance only; detection logic here is original, reconciled as non-duplicate
    against Find Security Bugs' 10 candidate rules during this session's research phase)
