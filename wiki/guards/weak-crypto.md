---
type: Guard
title: "weak-crypto"
description: "No weak / broken cryptography."
timestamp: "2026-06-17T13:52:01+08:00"
guard_id: "weak-crypto"
checklist_section: ["8"]
standards: ["OWASP:A02"]
---

# No weak / broken cryptography

Flags four high-signal, low-FP cryptographic failures in application code, each from a single line.
Closes checklist item `8-weak-crypto`. OWASP:A02 (Cryptographic Failures).

## The threat

Four distinct failures, one guard:

- **Insecure hash for security** — `hashlib.md5(...)` / `hashlib.sha1(...)` (or `hashlib.new("md5"
  |"sha1")`) without `usedforsecurity=False`. MD5 and SHA-1 are collision-broken; anything built on
  them for security (signatures, token derivation, file-integrity checks, dedup of security tokens) is
  forgeable. CWE-327 / CWE-328.
- **ECB cipher mode** — `MODE_ECB` encrypts identical plaintext blocks to identical ciphertext, leaking
  structure (the classic "ECB penguin"). It provides no semantic security. CWE-327.
- **Insecure randomness for a secret** — a security-named value (`token`, `secret`, `password`,
  `api_key`, `private_key`, `nonce`, `salt`, `otp`, `session_id`, `csrf_token`) assigned from the
  `random` module, a deterministic PRNG seeded from the clock. Its output is predictable, so a token /
  key / nonce derived from it is guessable. CWE-330 / CWE-338.
- **Weak RSA/DSA key size** (added 2026-07-10, from a CodeQL `py/weak-crypto-key` cross-check) — a
  generated key below 2048 bits is breakable with realistic compute (factoring/discrete-log attacks
  against small keys are practical today). Detected on pycryptodome's `RSA.generate(<bits>)` /
  `DSA.generate(<bits>)` (positional bit count) and the `cryptography` library's
  `generate_private_key(..., key_size=<bits>, ...)` keyword form. CWE-326.

## Exploitability rationale

HIGH. None is a one-shot RCE, but each silently voids a security control the rest of the system trusts
(a forgeable signature, a recoverable plaintext, a predictable token). High likelihood in vibe-coded
apps — `hashlib.md5` and `random` are the first things autocomplete suggests.

## What counts as a hit (and what doesn't)

- Insecure-hash fires only when `usedforsecurity=False` is **absent** on the line — a declared
  non-security use (cache key, ETag) is silent.
- ECB fires on the literal token `MODE_ECB`.
- Insecure-random fires only when the lvalue name matches the security-name list **and** the RHS calls
  `random.<weak-fn>`; `colour = random.choice(colours)` is silent (non-secret name).
- Weak-key-size fires only when the numeric bit count on the same line as `RSA.generate(`/
  `DSA.generate(`/`generate_private_key(...key_size=...)` is below 2048; `RSA.generate(2048)` or
  larger is silent.

## When NOT to flag (and the pragma)

- `hashlib.md5(data, usedforsecurity=False)` → silent (declared non-security). A content-dedup /
  file-idempotency / cache-key / ETag MD5 (e.g. `_md5_of_file`) is a **true positive until that flag is
  added** — adding it IS the fix, not a suppression. The `insecure-hash` remediation now leads with this
  escape hatch so a non-security use is easy to resolve correctly (backlog #4; no detection/severity
  change — a raw `hashlib.md5(...)` without the flag still fires HIGH).
- `hashlib.sha256(...)` / `secrets.token_urlsafe(...)` / `os.urandom(...)` → silent (these are the fix).
- `random.*` for a non-secret variable → silent.
- Commented-out lines → silent.
- An audited-safe case → suppress that line with `# security: allow-weak-crypto`.

## Known bypasses (honest limits)

- **Multi-line calls.** Line-oriented; a hash/cipher call split across lines is not matched.
- **Aliased imports.** `from hashlib import md5; md5(x)` is not matched (the guard keys on the
  `hashlib.` / `MODE_ECB` / `random.` surface). bandit's B303/B324/B311 (an optional runner) catches
  some of these — defense in depth.
- **Indirection.** A secret built from `random` two statements away from the security-named assignment
  is not matched.
- **EC (elliptic-curve) key weakness.** Only RSA/DSA numeric bit-size is checked; a weak EC curve
  choice (e.g. `SECP192R1`) is a different detection shape (curve-name allowlist, not a numeric
  compare) and is out of scope for this pass.
- **Multi-line key-generation calls.** `RSA.generate(\n    1024,\n)` spread across lines is invisible
  to the single-line regex, same limitation as the other three checks. The `cryptography` library's
  `generate_private_key(...)` check is the exception (fixed, review #395 M finding, below).

**Known limitation (fixed, review #395):** `generate_private_key(...)`'s `key_size=` extraction
used to be a `[^)]*` scan that stopped at the first `)`, including one from a nested call earlier
in the arg list (`backend=default_backend()`), silently missing a real weak key when the args
weren't in `key_size`-first order. It now extracts the call's balanced argument list via the
shared `split_call_args` helper (`agentsec/guards/base.py`, also used by `regex_html_sanitizer`
and `dom_xss_sinks`), which is order-independent and, as a side effect, also now spans a
multi-line call for this one check.

## What this guard does NOT prove

It catches the three named patterns in source; it does not prove the hash output is actually used for
security, nor that all crypto in the app is sound. Absence of a finding ≠ provably-correct cryptography.

# Citations

[1] agentsec checklist item `8-weak-crypto` (§8)
[2] OWASP:A02
