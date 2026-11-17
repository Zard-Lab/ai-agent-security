---
type: Guard
title: "jwt-key-source-allowlist"
description: "JWT verification key sourced from an unverified token header (jku/x5u/jwk)."
timestamp: "2026-08-19T00:00:00+08:00"
guard_id: "jwt-key-source-allowlist"
checklist_section: ["2a"]
standards: ["OWASP:A02", "OWASP:A07", "ASVS:9.1.3"]
---

# JWT verification key sourced from an unverified token header (jku/x5u/jwk)

_Author — 2026-08-19_

---

## The threat

§2a of the checklist (ASVS 9.1.3): *"JWT key-source headers (jku/x5u/jwk) validated against an
allowlist — never fetch verification keys from a token-supplied URL/key."*

`jku` (JWK Set URL), `x5u` (X.509 Certificate URL), and `jwk` (an embedded JSON Web Key) are all
fields the JWS spec defines for the token to *tell the verifier where to find, or what, the
verification key is* — and all three live in the token **header**, which is read before the
signature is ever checked (`jwt.get_unverified_header()` / `jose.jwt.get_unverified_header()`).
An attacker controls the entire token, header included, so all three are attacker-controlled input.

Two distinct exploit shapes:

1. **`jwk` embedded directly.** The attacker generates their own key pair, embeds the public half
   in the `jwk` header field, signs the token with the matching private key, and sends it. If the
   verifier extracts the key from `jwk` and uses it to check the token's own signature, the check
   trivially passes — the attacker verified their own forgery with their own key. No network
   access, no other flaw needed. This is the same defect class as CVE-2018-0114 (node-jsonwebtoken).
2. **`jku`/`x5u` fetched from a URL.** The URL is also attacker-controlled — a forged token can
   point it at a server the attacker runs (serves back whatever key matches their forged
   signature) or at an internal address the service can reach (SSRF).

Both defeat the entire point of verifying a JWT signature: proving the token was issued by a party
holding a key **the verifier already trusts**, not a key the token brought along with it.

## Why this guard fits the stack

Any FastAPI (or other Python) service that verifies its own JWTs — rather than delegating entirely
to a fixed, hardcoded JWKS endpoint it configured itself — is a candidate for this bug the moment
someone tries to add "key rotation" support by trusting the token's own header:

```python
header = jwt.get_unverified_header(token)
jwk_url = header["jku"]                       # attacker-controlled
key = requests.get(jwk_url).json()             # SSRF + forged-key fetch
return jwt.decode(token, key, algorithms=["RS256"])
```

## Detection design

1. **`applies()` gate:** `"python" in profile.features`.
2. **Files scanned:** all `.py` files under `python_scan_dirs(root, profile)` via `iter_files()`.
3. **Anchor:** the file must contain a `get_unverified_header(` call (PyJWT and python-jose both
   expose this exact name) — `jku`/`x5u`/`jwk` only carry this meaning in that context, so this
   keeps the check precise without full data-flow tracing.
4. **Pattern:** within an anchored file, `["jku"]` / `.get("jku")` (same shape for `x5u`/`jwk`,
   single or double quotes) fires once per distinct `(field, line)` pair. Docstrings/string
   literals are blanked first via `strip_python_strings` so an example in a comment doesn't fire.
   The whole file is scanned in one pass (not line by line), so a formatter-wrapped multi-line
   access (`h[\n    "jku"\n]`) and a field name nested inside an f-string interpolation
   (`f"jku is {h['jku']}"`) are both still recognized as real accesses (fixed 2026-08-26, #686
   fix-commit round, Highs 2 and 3 — the original per-line scan couldn't match across a line
   break, and the standalone-quoted-string check wasn't f-string aware).
5. **Pragma:** `# security: allow-jwt-key-source-header` anywhere in the file skips it entirely.
6. **Severity / rule:** `jwt-key-source-allowlist/untrusted-key-source` — **CRITICAL** for `jwk`
   (no network step needed, the embedded key does everything), **HIGH** for `jku`/`x5u` (matches
   the checklist item's declared severity — a fetch step is required, but the target is still
   attacker-chosen).

## When NOT to flag

A service that validates the `jku`/`x5u` URL's host against a real, server-side allowlist *before*
fetching is doing the right thing — this guard does not attempt to verify that the check is
correct (a proximity heuristic for "looks like an allowlist" is easy to fool and easy to miss a
real one with different phrasing), so it still fires and expects the pragma for the reviewed case.
Reading `get_unverified_header()` for something unrelated to key sourcing (logging the `kid` for
diagnostics, checking `typ`) never fires — only an actual `jku`/`x5u`/`jwk` access does.

## Tests

| Test | What it checks |
|---|---|
| `test_jwt_key_source_allowlist_flags_jku` | `header["jku"]` after `get_unverified_header` fires HIGH |
| `test_jwt_key_source_allowlist_flags_x5u` | `header.get("x5u")` fires HIGH |
| `test_jwt_key_source_allowlist_flags_jwk_as_critical` | `header["jwk"]` (embedded key) fires CRITICAL |
| `test_jwt_key_source_allowlist_dedupes_same_field_same_line` | one access, one finding (no double-count) |
| `test_jwt_key_source_allowlist_silent_without_unverified_header` | `header["jku"]` on an unrelated dict, no `get_unverified_header` anywhere in the file, stays silent |
| `test_jwt_key_source_allowlist_silent_ordinary_claim_access` | `payload["sub"]`/`payload.get("exp")` after `get_unverified_header` stays silent (not jku/x5u/jwk) |
| `test_jwt_key_source_allowlist_pragma_silences` | file-level pragma suppresses all findings |
| `test_jwt_key_source_allowlist_applies_gate` | guard does not apply when `python` not in features |
| `test_jwt_key_source_allowlist_applies_with_python` | guard applies when `python` in features |

## Known bypasses

- The field access must be a literal string subscript/`.get()` call (`header["jku"]`); reading it
  via `getattr`, `**header`-unpacking, or an intermediate `dict(header)` copy under a different
  variable name is not traced.
- `get_unverified_header` called via an aliased import (`from jwt import get_unverified_header as
  guh`) is not recognized — only the `get_unverified_header(` call-site text itself is matched.
- A library other than PyJWT/python-jose that exposes the same three header fields under a
  differently-named accessor is not covered.

## What this guard does NOT prove

A file with no finding may still be vulnerable via a mechanism this guard doesn't recognize — a
hand-rolled base64 decode of the JWT header segment (`json.loads(base64.urlsafe_b64decode(token
.split(".")[0] + "=="))`) that reads `jku`/`x5u`/`jwk` without ever calling
`get_unverified_header()`, or a non-Python service (Node/Go) doing the same thing. It also does not
verify that a *present* allowlist check is actually correct — only that the guard's pragma was
used, which asserts the case was reviewed, not that the review was right.

# Citations

[1] agentsec checklist item `2a-jwt-key-source-allowlist` (§2a)
[2] OWASP:A02 (Cryptographic Failures) · OWASP:A07 (Identification and Authentication Failures)
[3] ASVS:9.1.3
[4] CVE-2018-0114 (node-jsonwebtoken `jwk`-embedding key-confusion precedent)
