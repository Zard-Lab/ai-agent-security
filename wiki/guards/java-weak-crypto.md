---
type: Guard
title: "java-weak-crypto"
description: "No weak / broken hash algorithm or cipher mode in Java application code."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-weak-crypto"
checklist_section: ["8"]
standards: ["OWASP:A02"]
---

# No weak / broken cryptography (Java)

Flags weak hash algorithms and weak block-cipher modes in Java source. Closes checklist item
`8-weak-crypto` — the Java counterpart to the existing `weak-crypto` (Python), `js-weak-crypto`
(JS/TS) guards, extending the same checklist item rather than duplicating it (agentsec's first
Java-language guard). OWASP:A02 (Cryptographic Failures), CWE-327.

## The threat

Two distinct broken-primitive shapes, both under the same checklist item:

- `MessageDigest.getInstance("MD5")` — MD5 and SHA-1 are collision-broken (SHAttered, 2017). A
  signature, token, or integrity check built on either is forgeable.
- `Cipher.getInstance("AES")` — Java's built-in SunJCE provider silently defaults an unqualified
  transformation string to ECB mode. ECB encrypts identical plaintext blocks to identical
  ciphertext blocks, leaking structural patterns in the plaintext (the textbook "ECB penguin"
  finding) — this is the single most common real-world Java crypto misconfiguration, precisely
  because `Cipher.getInstance("AES")` reads like "just AES," not "AES in the weakest mode."

## Exploitability rationale

HIGH for both shapes. Neither is a one-shot RCE, but each silently voids a security control the
rest of the system trusts (a forgeable signature, or ciphertext that leaks plaintext structure).
Likelihood is real: both are the first thing a developer reaches for from the JCA/JCE API
surface, with no default steering toward the safe choice.

## What counts as a hit (and what doesn't)

- **`MessageDigest.getInstance("MD5"|"MD4"|"MD2"|"SHA1"|"SHA-1"|"SHA")`** fires (case-sensitive on
  the algorithm name — a lowercase spelling is not a valid JCA lookup, so it would never resolve
  to the weak digest at runtime and is deliberately not matched).
  `MessageDigest.getInstance("SHA-256")` does not (not broken).
- **`DigestUtils.md5*`/`DigestUtils.sha1*`** (Apache Commons Codec convenience wrappers — `md5Hex`,
  `md5`, `sha1Hex`, `sha1`, `getMd5Digest`, `getSha1Digest`, ...) fires.
- **`Cipher.getInstance("AES")`** (the bare transformation string, no explicit mode) fires — the
  silent-ECB-default case.
- **`Cipher.getInstance("AES/ECB/...")`, `"DES/ECB/..."`, `"DESede/ECB/..."`** (explicit ECB mode)
  fires.
- `Cipher.getInstance("AES/GCM/NoPadding")` and other explicit authenticated/non-ECB modes do
  **not** fire — only bare-AES and explicit ECB are in scope, not every non-AEAD mode (CBC without
  authentication is a real but separate weakness, out of scope for this guard; see "Known
  bypasses").

## When NOT to flag (and the pragma)

- A file on a non-product path (`is_nonproduct_path`) → silent. Maven and Gradle put test
  sources under `src/test/java`, whose `test` segment reads as non-product, alongside the shared
  `fixtures/`/`examples/` list and a repo's own configured `archive_segments`.
- `MessageDigest.getInstance("SHA-256")` / `Cipher.getInstance("AES/GCM/NoPadding")` → silent
  (the fix).
- Commented out (`// MessageDigest.getInstance("MD5")`) → silent; comment stripping is
  string-aware, so a `//`/`/*` inside a genuine string literal on the same line is not mistaken
  for a comment start.
- Inside a real `/** ... */` Javadoc block mentioning the pattern → silent.
- A content-dedup / cache-key / non-security MD5 use, or a deliberately audited ECB use → suppress
  explicitly:

```java
MessageDigest.getInstance("MD5"); // security: allow-weak-crypto
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Like every sibling weak-crypto guard, this fires on the algorithm
  name directly, with no attempt to prove the hashed/encrypted input is security-relevant. The
  pragma is the intended correction, not a guard limitation to fix later.
- **Single-line, textual.** A `Cipher`/`MessageDigest` instance built from a transformation string
  assembled across several lines or passed in as a variable is not traced — same textual scope as
  `weak_crypto.py`/`js_weak_crypto.py`.
- **CBC-without-authentication is deliberately out of scope for this guard.** Find Security Bugs'
  own `PADDING_ORACLE` rule flags `"...CBC/PKCS5Padding"` as a padding-oracle risk — narrower and
  more nuanced (CBC is not broken the way ECB is; it becomes exploitable specifically when
  unauthenticated and an oracle exists) than this guard's blunter ECB/bare-AES scope. Not ported
  here to avoid a broad, dataflow-free CBC blanket-flag; tracked as a possible future guard
  extension, not silently assumed covered.
- **Java 17+ text blocks are not comment/string-aware.** `strip_java_comments` deliberately does
  not special-case triple-double-quoted text blocks (rare in the call-site shapes this guard
  targets) — see its docstring for the exact, documented residual.

## What this guard does NOT prove

A clean scan means no weak-hash or weak-cipher-mode call-site was found in the scanned Java
source — it says nothing about a hash/cipher invoked via a native library, a dependency that
wraps a weak primitive internally without going through `MessageDigest`/`Cipher` directly, or a
digest/ciphertext the application receives pre-computed from an external service.

## Canary plant

`WeakHash.java` — `MessageDigest.getInstance("MD5")` inside a method body, no pragma. Expected
rule: `java-weak-crypto/insecure-hash`.

# Citations

[1] agentsec checklist item `8-weak-crypto` (§8)
[2] OWASP:A02 (Cryptographic Failures)
[3] CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
[4] SHAttered (Google/CWI, 2017) — practical SHA-1 collision
[5] Find Security Bugs — `WeakMessageDigestDetector.java`, `CipherWithNoIntegrityDetector.java`
    (provenance only; detection logic here is original)
