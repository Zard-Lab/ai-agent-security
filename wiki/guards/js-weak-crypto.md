---
type: Guard
title: "js-weak-crypto"
description: "No weak / broken cryptography (JS/TS)."
timestamp: "2026-08-09T11:26:14+08:00"
guard_id: "js-weak-crypto"
checklist_section: ["8"]
standards: ["OWASP:A02"]
---

# No weak / broken cryptography (JS/TS)

_Author — 2026-08-09_

---

## The threat

Three related, name-based cryptographic failures in Node's built-in `crypto` module and the
popular `crypto-js` npm package — the JS/TS surface of the same checklist item Python's
`weak-crypto` guard already covers (`8-weak-crypto`). OWASP:A02 (Cryptographic Failures).

- **Weak hash algorithm** — `crypto.createHash('md5'|'sha1')` or `CryptoJS.MD5(...)` /
  `CryptoJS.SHA1(...)`. MD5 and SHA-1 are collision-broken; anything built on them for security
  (signatures, token derivation, integrity checks, dedup of security tokens) is forgeable.
  CWE-327 / CWE-328.
- **Deprecated cipher function** — `crypto.createCipher(...)` / `crypto.createDecipher(...)`.
  Node's own docs mark this function itself as deprecated: it derives the key and IV from a
  password via a single, non-salted, weak hash (`EVP_BytesToKey`-style), so it is insecure
  *regardless of the algorithm argument*. Any use is the vulnerability, not a specific algorithm
  name. CWE-327.
- **Weak cipher algorithm** — `crypto.createCipheriv(...)` / `crypto.createDecipheriv(...)` (the
  modern, safe replacement functions) called with a weak algorithm string — `'des'`,
  `'des-ede3'`, `'rc4'`, `'rc2'` — or `CryptoJS.DES.encrypt/.decrypt(...)`,
  `CryptoJS.RC4.encrypt/.decrypt(...)`. DES/3DES/RC4/RC2 have small block/key sizes and known
  practical attacks. CWE-327.

WHO reaches this: anyone whose code path hashes or encrypts data with one of these primitives —
password reset tokens, signed cookies, cache keys claimed as security-relevant, session secrets,
data-at-rest "encryption". WHAT privilege: none needed to exploit — the weakness is in the
primitive itself, not access control. WHAT effect: a forgeable signature/token, or recoverable
ciphertext, silently voiding a security control the rest of the app trusts.

## Why this guard fits the stack

Any FastAPI + React app with a Node-based frontend/tooling layer (or a Node backend service) can
reach into `crypto`/`crypto-js` the same way a Python service reaches into `hashlib`. `crypto.
createHash('md5')` and `CryptoJS.MD5(...)` are exactly the autocomplete-first suggestions for "hash
this string in JS" — the same failure mode `weak_crypto.py`'s docstring names for `hashlib.md5` and
`random` in Python.

```js
// The bad pattern this guard catches:
const crypto = require('crypto');
const token = crypto.createHash('md5').update(userId).digest('hex');   // forgeable
const cipher = crypto.createCipher('aes-256-cbc', password);            // deprecated, weak KDF
const enc = crypto.createCipheriv('des-ede3', key, iv);                 // broken cipher
```

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "typescript" in profile.features`
   (same gate as the sibling JS guards, e.g. `js_command_injection.py`).
2. **Files scanned** — `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`, skipping
   `is_nonproduct_path` (tests/fixtures/examples), the shared JS-guard convention.
3. **Patterns** — single-line, regex-based, one rule per surface, checked in this order per line
   (mirrors `weak_crypto.py`'s "multiple distinct rules under one guard class" shape):
   - `_CREATE_HASH` — `(?:crypto\.)?createHash\s*\(\s*['"]([\w-]+)['"]`, weak iff the captured
     algorithm lowercases to `md5`/`sha1`.
   - `_CRYPTOJS_HASH` — `CryptoJS\.(MD5|SHA1)\s*\(`.
   - `_CREATE_CIPHER_DEPRECATED` — `(?:crypto\.)?create(?:De)?Cipher\s*\(` — fires on ANY
     algorithm; this is the one rule in the guard that is NOT algorithm-name-gated, matching how
     `weak_crypto.py`'s own ECB-mode rule fires on the mode token alone with no algorithm check.
   - `_CREATE_CIPHERIV` — `(?:crypto\.)?create(?:De)?Cipheriv\s*\(\s*['"]([\w-]+)['"]`, weak iff
     the captured algorithm lowercases to one of `des`/`des-ede3`/`rc4`/`rc2`.
   - `_CRYPTOJS_CIPHER` — `CryptoJS\.(DES|RC4)\.(?:encrypt|decrypt)\s*\(`.
   Each line is scanned via `strip_js_comments` (blanks `//`/`/* */`, string/regex-literal aware)
   so a commented-out example doesn't fire, matching every other JS guard in this codebase.
4. **Inline opt-out pragma** — `// security: allow-js-weak-crypto`, checked against the
   comment-only view of the line (#424) so the pragma itself stays visible even though code is matched
   post-strip.
5. **Severity / rule ids / standards** — all HIGH (matches `weak_crypto.py`'s severity for the
   equivalent Python findings), standards `["OWASP:A02"]`, rule ids:
   - `js-weak-crypto/weak-hash-algorithm`
   - `js-weak-crypto/deprecated-cipher-function`
   - `js-weak-crypto/weak-cipher-algorithm`
   - `js-weak-crypto/ecb-cipher-mode`

   The ECB and legacy-name shapes were mined from eslint-plugin-security-rules' banned-algorithm
   list:
   - `createCipheriv`/`createDecipheriv` with a name that ends in `-ecb` (`aes-256-ecb`,
     `camellia-128-ecb`, `bf-ecb`, any case) fires `ecb-cipher-mode`, HIGH, and so does
     `CryptoJS.mode.ECB`.
   - A name whose leading family is DES, 3DES (`des-ede`, `des-ede3`, `des3`, `desx`), RC2, RC4,
     Blowfish (`bf`) or CAST5 (`bf-cbc`, `des-cbc`, `rc4-hmac-md5`, `rc2-40-cbc`, `cast5-cbc`) fires
     `weak-cipher-algorithm` as MEDIUM. The four exact names `des`, `des-ede3`, `rc4`, `rc2` keep
     their original HIGH.
   - `aes-*-cbc`, `aes-*-gcm`, `chacha20-poly1305` and `CryptoJS.mode.CBC` stay silent.

## When NOT to flag

- `crypto.createHash('sha256')` / `CryptoJS.SHA256(...)` → silent (strong hash).
- `crypto.createCipheriv('aes-256-gcm', key, iv)` → silent — the modern, safe replacement
  function with a strong algorithm. This is the precision case the guard is built to get right:
  merely containing the substring "Cipher" (as `createCipheriv` does) must NOT trip the
  `createCipher`-deprecated rule; only an exact `createCipher(`/`createDecipher(` call (no `iv`
  before the opening paren) does.
- `CryptoJS.AES.encrypt(...)` → silent (strong cipher).
- `crypto.createHmac('sha1', key)` → **silent, by deliberate design** (see "Known bypasses" and
  the guard's module docstring) — HMAC-SHA1 is not the same weak-algorithm class as bare SHA-1
  hashing; this mirrors `weak_crypto.py`'s own Python-side scope, which likewise only matches
  `hashlib.md5`/`hashlib.sha1` and never `hmac.new(..., hashlib.sha1)`.
- Commented-out lines → silent (`strip_js_comments`).
- An audited-safe case → suppress that line with `// security: allow-js-weak-crypto`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_create_hash_md5` | `crypto.createHash('md5')` fires |
| `test_silent_on_create_hash_sha256` | `crypto.createHash('sha256')` stays silent (FP-bait) |
| `test_flags_create_cipher_any_algorithm` | `crypto.createCipher('aes-256-cbc', key)` fires — the function itself, any algorithm |
| `test_flags_create_decipher` | `crypto.createDecipher(...)` fires |
| `test_silent_on_create_cipheriv_safe_replacement` | `crypto.createCipheriv('aes-256-cbc', ...)` does NOT trip the createCipher rule (regex precision) |
| `test_flags_create_cipheriv_weak_algorithm` | `crypto.createCipheriv('des-ede3', ...)` fires |
| `test_flags_create_decipheriv_rc4` | `crypto.createDecipheriv('rc4', ...)` fires |
| `test_silent_on_create_cipheriv_strong_algorithm` | `crypto.createCipheriv('aes-256-gcm', ...)` stays silent |
| `test_flags_cryptojs_md5` | `CryptoJS.MD5(data)` fires |
| `test_silent_on_cryptojs_sha256` | `CryptoJS.SHA256(data)` stays silent |
| `test_flags_cryptojs_des_encrypt` | `CryptoJS.DES.encrypt(...)` fires |
| `test_flags_cryptojs_rc4_encrypt` | `CryptoJS.RC4.encrypt(...)` fires |
| `test_silent_on_cryptojs_aes_encrypt` | `CryptoJS.AES.encrypt(...)` stays silent |
| `test_pragma_suppresses` | inline `// security: allow-js-weak-crypto` suppresses |
| `test_silent_on_comment_mentioning_pattern` | a commented-out example does not fire |
| `test_not_applies_without_js_or_ts` / `test_applies_with_typescript` | `applies()` gate |
| `test_nonproduct_path_skipped` | an `examples/` path is skipped |
| `test_silent_on_create_hmac_sha1` | `createHmac('sha1', ...)` never fires — deliberate scope decision |
| `test_known_bypass_algorithm_via_variable_not_flagged` | algorithm passed via a variable (`crypto.createHash(algo)`) is not caught — documented known bypass |
| `test_ecb_mode_is_high` | `-ecb` names (any case, destructured or aliased `createCipheriv`) and `CryptoJS.mode.ECB` fire HIGH `ecb-cipher-mode` |
| `test_legacy_cipher_family_is_medium` | `bf-cbc`, `des-cbc`, `des-ede3-cbc`, `rc4-hmac-md5`, `rc2-40-cbc`, `cast5-cbc`, `desx-cbc` fire MEDIUM |
| `test_exact_legacy_names_stay_high` | `des-ede3` keeps its original HIGH |
| `test_strong_or_commented_ciphers_silent` | gcm, cbc, chacha20, a look-alike `bfx-custom`, a comment and `CryptoJS.mode.CBC` stay silent |
| `test_ecb_pragma_suppresses` | the inline pragma silences an ECB line |

## Known bypasses

- **Variable indirection.** `const algo = 'md5'; crypto.createHash(algo);` is invisible — the
  guard requires the algorithm as a string literal directly in the call, the same trade-off
  `weak_crypto.py` already accepts (its own "Indirection" bypass: "a secret built from `random`
  two statements away from the security-named assignment is not matched").
- **Multi-line calls.** Line-oriented, like every other single-line JS guard in this codebase
  (`js-command-injection`, `js-client-side-open-redirect`); a call whose algorithm argument is on
  a different physical line than the call itself is not matched.
- **Aliased/destructured imports beyond the bare-name form.** `const { createHash: h } =
  require('crypto'); h('md5')` (a renamed destructure) is not matched — only the literal
  `createHash`/`crypto.createHash` spelling is.
- **Other weak-cipher-adjacent surfaces.** `crypto.createCipheriv` is checked against the
  `-ecb` suffix and the DES/RC2/RC4/Blowfish/CAST5 families; a non-standard or custom cipher name
  outside those is not evaluated for strength, and `CryptoJS.AES.encrypt(m, k, { mode })` with the
  mode held in a variable is not followed.
- **No dataflow proof.** Deliberate, not a gap to close later (see "What this guard does NOT
  prove").

## What this guard does NOT prove

It catches the three named patterns by algorithm/function NAME in source; it does **not** prove
the hashed or encrypted value is actually sensitive data, nor that all cryptography in the app is
sound. This is the same accepted trade-off `weak_crypto.py`'s own module docstring states for the
Python side — CodeQL's real JS query (`javascript/ql/src/experimental/Security/CWE-327/
BrokenCryptoAlgorithm.ql`) requires a full dataflow proof that sensitive data reaches the weak
algorithm before firing; this guard does not attempt that proof, by design, matching the
precedent the Python sibling already set. Absence of a finding ≠ provably-correct cryptography.

# Citations

[1] agentsec checklist item `8-weak-crypto` (§8)
[2] OWASP:A02
