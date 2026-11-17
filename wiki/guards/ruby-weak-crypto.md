---
type: Guard
title: "ruby-weak-crypto"
description: "No weak / broken hash algorithm in Ruby application code."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "ruby-weak-crypto"
checklist_section: ["8"]
standards: ["OWASP:A02"]
---

# No weak / broken hash algorithm (Ruby)

Flags MD5/SHA-1 hash usage in Ruby source. Closes checklist item `8-weak-crypto` — the Ruby
counterpart to the existing `weak-crypto` (Python) and `js-weak-crypto` (JS/TS) guards, extending
the same checklist item rather than duplicating it (agentsec's first Ruby-language guard,
added with Ruby support). OWASP:A02 (Cryptographic Failures), CWE-327.

## The threat

`Digest::MD5.hexdigest(data)` or `OpenSSL::Digest::SHA1.new` — MD5 and SHA-1 are collision-broken
(SHAttered, 2017). A signature, token, or integrity check built on either is forgeable: an
attacker who can find a second input with the same digest can substitute it wherever the digest
was trusted as a proof of content or identity.

## Exploitability rationale

HIGH. Not a one-shot RCE, but silently voids a security control the rest of the system trusts (a
forgeable signature, a spoofable integrity check). Likelihood is real: `Digest::MD5` is the first
thing Ruby's own standard library documentation shows for "compute a hash," with no built-in
guidance steering a developer toward SHA-256 for security use.

## What counts as a hit (and what doesn't)

- **`Digest::MD5`/`Digest::SHA1`** (any method call — `.hexdigest`, `.new`, `.digest`,
  `.base64digest`, ...) fires. `Digest::SHA256`/`Digest::SHA512` do not (not broken).
- **`OpenSSL::Digest::MD5`/`::SHA1`** (constant form) and **`OpenSSL::Digest.new("MD5"|"SHA1")`**
  (string-argument form) both fire — the same broken algorithms via OpenSSL's Ruby binding.
- Unlike Python's `hashlib.md5(data, usedforsecurity=False)`, Ruby's `Digest` API has no
  "declared non-security use" opt-out — every use fires unconditionally (mirrors Brakeman's own
  `CheckWeakHash`, which does the same). The pragma below is the only escape hatch.

## When NOT to flag (and the pragma)

- `Digest::SHA256.hexdigest(...)` → silent (the fix).
- Commented out (`# Digest::MD5...`) → silent; comment stripping is string-aware, so a `#` inside
  a genuine string literal on the same line is not mistaken for a comment start.
- A real Ruby `=begin`/`=end` block comment mentioning the pattern → silent.
- A content-dedup / cache-key / non-security MD5 use → suppress explicitly:

```ruby
Digest::MD5.hexdigest(data)  # security: allow-weak-crypto
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Like every sibling weak-crypto guard, this fires on the algorithm
  name directly, with no attempt to prove the hashed input is security-relevant. A cache-key MD5
  with no pragma fires HIGH just as loudly as a password-hash MD5 — the pragma is the intended
  correction, not a guard limitation to fix later.
- **Single-line, textual.** A hash call assigned to a variable and invoked indirectly through
  several layers of indirection is not traced — same textual scope as `weak_crypto.py`.
- **`%w[]`/heredoc-embedded mentions are not comment/string-aware.** `strip_ruby_comments`
  deliberately does not track Ruby's percent-literal or heredoc string forms (rare in the
  call-site shapes this guard targets) — a `Digest::MD5` string literal written inside a heredoc
  body would not be correctly recognized as "inside a string" and could false-fire. Not observed
  in practice; documented rather than silently assumed away.

## What this guard does NOT prove

A clean scan means no MD5/SHA-1 call-site was found in the scanned Ruby source — it says nothing
about a hash computed via a native extension, a gem that wraps a C implementation without going
through `Digest`/`OpenSSL::Digest`, or a hash the application receives pre-computed from an
external service.

## Canary plant

`checksum.rb` — `Digest::MD5.hexdigest(data)` inside a method body, no pragma. Expected rule:
`ruby-weak-crypto/insecure-hash`.

# Citations

[1] agentsec checklist item `8-weak-crypto` (§8)
[2] OWASP:A02 (Cryptographic Failures)
[3] CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
[4] SHAttered (Google/CWI, 2017) — practical SHA-1 collision
