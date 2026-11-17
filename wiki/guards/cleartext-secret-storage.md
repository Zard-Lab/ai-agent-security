---
type: Guard
title: "cleartext-secret-storage"
description: "Secret written to a cleartext sink (cookie or plaintext file)."
timestamp: "2026-07-10T15:42:25+08:00"
guard_id: "cleartext-secret-storage"
checklist_section: ["8"]
standards: ["OWASP:A02"]
---

# Secret written to a cleartext sink (cookie or plaintext file)

_Author — Marconi, 2026-07-10 — from the codeql-security-queries research pass._

---

## The threat

A password, private key, or other raw secret persisted without encryption into a store an
attacker can read without needing the application at all: a cookie (client-side, readable by
anyone with browser DevTools or a MITM position on plain HTTP), or a plaintext file on disk
(readable via a leaked backup, a misconfigured volume mount, or any other process on the same
host). CodeQL's `py/clear-text-storage-sensitive-data` (CWE-312 / CWE-315 / CWE-359) flags this
as a dataflow query across arbitrary sinks; this guard approximates the two most common
same-file cases in a FastAPI + LLM/RAG stack.

## Why it's often introduced / Why this guard fits the stack

Two concrete shapes:

```python
# a "remember me" feature stores the raw password to skip re-prompting
response.set_cookie("remember", password)

# a local dev/debug helper dumps credentials to disk "just to check"
with open("last_login.txt", "w") as f:
    f.write(client_secret)
```

Neither looks alarming in a quick review — `set_cookie` and `.write(` are completely ordinary
calls. The bug is entirely in what value is being passed, which is easy to miss without a tool
looking specifically at the argument name.

## Detection design

1. **`applies()` gate** — `"python" in profile.features`.
2. **Scanned files** — every `.py` under `python_scan_dirs`, skipping `is_nonproduct_path`
   (tests/fixtures) and any file carrying the file-wide pragma.
3. **Patterns** (both same-line, single-line regex — no multi-line call support):
   - `cookie-value`: `_SET_COOKIE_VALUE` matches `set_cookie("<literal name>", <value>)` and
     captures `<value>` — the value must be a **bare identifier** (not a nested call or string
     literal).
   - `plaintext-file-write`: `_FILE_WRITE_VALUE` matches `<anything>.write(<value>)` or
     `<anything>.write_text(<value>)`, same bare-identifier requirement.
   - Both then test the captured identifier with `_is_cleartext_secret_name()`: it must contain
     one of `password`/`passwd`/`secret`/`private_key`/`credential` as a substring (loose match,
     so `raw_password`/`user_password`/`client_secret` all qualify), **and** must NOT also
     contain a "looks already protected" hint (`hash`/`encrypt`/`digest`/`cipher`/`bcrypt`/
     `argon2`/`pbkdf2`/`redact`/`mask`/`scrypt`) — so `hashed_password`/`password_hash`/
     `encrypted_secret` are silent.
4. **Inline opt-out** — `# security: allow-cleartext-secret-storage` anywhere in the file.
5. **Severity** — HIGH for both rules (a raw secret in either sink is a real, unconditional
   exposure once present, not a signal of one). Rule ids: `cleartext-secret-storage/cookie-value`,
   `cleartext-secret-storage/plaintext-file-write`. Standards: `["OWASP:A02", "CWE-312"]`.

**Deliberately excludes `token`/`session_id`/`api_key` from the marker set** — those are
designed as opaque bearer values that legitimately live client-side (a session token in a
cookie is the correct architecture, not a bug); `insecure-cookies` already covers the actual
risk on that value (missing HttpOnly/Secure/SameSite). This guard is narrower and more severe:
a *password or private key itself* has no business in either sink at all, regardless of flags.

**Deliberately requires a bare identifier, not a nested call** — `f.write(hash_password(pw))` or
`response.set_cookie("k", encrypt(secret))` do not match. The guard cannot evaluate what a
nested call does; treating every wrapped case as unsafe would be far too noisy. This mirrors
`weak-crypto`'s `_INSECURE_RANDOM` design (recall traded for precision).

## When NOT to flag

- `set_cookie("token", raw_token)` / `set_cookie("session_id", session_id)` — the correct,
  intended pattern for a session credential. Silent (marker set excludes these names).
- `f.write(hashed_password)` / `f.write(password_hash)` — the value has already been through a
  one-way transform. Silent (`_PROTECTED_NAME_HINT` exclusion).
- `f.write(encrypt(secret_key))` — nested call, not a bare identifier. Silent.
- An audited, reviewed case → `# security: allow-cleartext-secret-storage` anywhere in the file.

## Tests

| Test | What it checks |
|---|---|
| `test_cleartext_secret_storage_fires_on_cookie_value` | `set_cookie("remember", password)` → HIGH `cookie-value` |
| `test_cleartext_secret_storage_fires_on_file_write` | `f.write(client_secret)` → HIGH `plaintext-file-write` |
| `test_cleartext_secret_storage_fires_on_write_text` | `path.write_text(private_key)` → HIGH `plaintext-file-write` |
| `test_cleartext_secret_storage_silent_on_token_cookie` | FP-bait: `set_cookie("token", raw_token)` → silent (legitimate session-token pattern) |
| `test_cleartext_secret_storage_silent_on_hashed_password` | FP-bait: `f.write(hashed_password)` → silent (`_PROTECTED_NAME_HINT`) |
| `test_cleartext_secret_storage_silent_on_nested_call` | FP-bait: `f.write(encrypt(secret_key))` → silent (not a bare identifier) |
| `test_cleartext_secret_storage_pragma_silences` | file-wide pragma → silent |
| `test_cleartext_secret_storage_not_applies_without_python` | `applies()` gate false without `python` |

## Known bypasses

- **Multi-line calls** — `set_cookie(\n    "k",\n    password,\n)` spread across lines is
  invisible to the single-line regex, same limitation as several sibling guards in this codebase.
- **Indirection through a second variable** — `tmp = password; f.write(tmp)` is not tracked
  (single-line, no dataflow).
- **Non-conventional variable names** — a password stored in a variable named `x` or `val` is
  invisible; the guard is entirely name-based.
- **kwarg-form `set_cookie` calls** — `set_cookie(key="remember", value=password)` is not
  matched (the regex expects two positional args).
- **Other cleartext sinks** — `json.dump({"password": password}, f)`, database columns, or a
  message queue payload are not covered; only the two sinks named above.

## What this guard does NOT prove

That no secret is ever persisted in cleartext anywhere in the app. It proves only that these two
specific same-line, bare-identifier patterns are absent from the scanned source. A secret routed
through any indirection, a differently-named variable, a third sink (database column, message
queue, third-party API log), or a multi-line call is invisible to this guard.

**Known limitation (fixed, review #395):** the plaintext-file-write sink is now scoped to actual
file-like objects — a bare in-memory stream (`io.StringIO().write(secret)`, or a variable
assigned from `StringIO()`/`BytesIO()` earlier in the file) is excluded; before this fix it fired
with a misleading "filesystem/backup" message on a value that never touches disk.

# Citations

[1] agentsec checklist item `8-secrets-not-stored-cleartext` (§8)
[2] OWASP:A02
