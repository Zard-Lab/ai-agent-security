---
type: Guard
title: "refresh-token-plaintext"
description: "Refresh token written to database without hashing."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "refresh-token-plaintext"
checklist_section: ["7"]
standards: ["OWASP:A02"]
---

# Refresh token written to database without hashing

_Author — 2026-06-21_

---

## The threat

**Who reaches this, with what privilege, to what effect?**

An attacker who gains read access to the tokens table — via SQL injection, a leaked
database backup, an accidental RLS misconfiguration, or a compromised DB credential —
obtains a list of raw refresh tokens. Because those tokens are stored in plaintext, the
attacker can immediately use any of them to generate new access tokens and impersonate
the corresponding users indefinitely, until each token is revoked. No cracking step is
required.

Contrast with password storage: a leaked plaintext password also allows direct reuse,
which is why OWASP:A02 mandates hashing. Refresh tokens are long-lived session
credentials and must be treated identically.

Standards: **OWASP:A02** (Cryptographic Failures), **CWE:257** (Storing Passwords in a
Recoverable Format).

## Why it's often introduced

FastAPI token-auth tutorials commonly show:

```python
raw = secrets.token_urlsafe(32)
db.add(RefreshToken(user_id=uid, token=raw))
db.commit()
```

The generation line looks secure (`secrets.token_urlsafe` is the right call), so
developers assume the token is "already secure" and don't realize the storage step
needs a hashing layer too.

## Detection design

1. **`applies()` gate** — fires when `"python"` is in `profile.features` (any Python
   backend, not limited to FastAPI).

2. **Files scanned** — all `.py` files under `python_scan_dirs(root, profile)`, de-
   duplicated, via `iter_files(d, (".py",))`.

3. **Pragma check** — if `"security: allow-refresh-token-plaintext"` appears anywhere
   in the file text, the entire file is skipped.

4. **Detection pattern** — per file, per line:

   a. **Token generation regex** (`_TOKEN_GEN`) matches a line where a variable named
      `refresh_token`, `refresh`, or `token` (case-insensitive) is assigned from
      `secrets.token_urlsafe(`, `secrets.token_hex(`, or `uuid.uuid4(`:

      ```
      \b(?:refresh_token|refresh|token)\b\s*=\s*
      (?:secrets\.token_urlsafe\s*\(|secrets\.token_hex\s*\(|uuid\.uuid4\s*\()
      ```

   b. When a token-gen line is found, the guard scans the **next 10 lines** for:
      - a **hash call** (`_HASH_CALL`): `hashlib.`, `bcrypt.`, `argon2.`, or `.hash(`
      - a **DB write call** (`_DB_WRITE`): `db.add(`, `session.add(`, `.create(`,
        `crud.create`, or `db.execute(`

   c. If a DB write is found before any hash call, the **DB write line** is flagged.
      If a hash call appears before the DB write, the window is considered safe and
      scanning continues. One finding per token-gen line.

5. **Severity / rule / standards**:
   - Severity: `"high"`
   - Rule: `"refresh-token-plaintext/token-stored-unhashed"`
   - Standards: `["OWASP:A02", "CWE:257"]`

6. **Inline opt-out pragma**: `# security: allow-refresh-token-plaintext` (file-level).

## When NOT to flag

| Scenario | Why it is safe |
|---|---|
| `hashed = hashlib.sha256(raw.encode()).hexdigest()` then `db.add(...)` | Hash call precedes the DB write within the 10-line window |
| `token_hash = bcrypt.hashpw(raw, salt)` then `session.add(...)` | bcrypt hash detected before write |
| `hashed = argon2_hasher.hash(raw)` then `.create(token=hashed)` | argon2 `.hash(` detected |
| File contains `# security: allow-refresh-token-plaintext` | Explicit audited opt-out |

## FP scenarios

| Pattern | Would fire? | Notes |
|---|---|---|
| Non-token variable assigned from `secrets.token_urlsafe` | No | Variable name must match `refresh_token`, `refresh`, or `token` |
| Token generated then hashed then stored | No | Hash call detected before DB write |
| Generation and storage in separate functions / modules | No (false negative) | Guard only looks 10 lines ahead in same file |
| `uuid.uuid4()` used as a primary key (not a credential) | Possible FP | Variable name must match; suppress with pragma if intentional |

## Known bypasses

| Bypass | Notes |
|---|---|
| Generate in one function, store in another (cross-function) | Not detected — requires interprocedural dataflow |
| Generate and store in same file but more than 10 lines apart | Not detected — window is 10 lines |
| Alias variable: `t = secrets.token_urlsafe(32)` then `token = t` | `t` does not match the name pattern; not detected |
| Custom hashing wrapper: `my_hash(raw)` instead of `hashlib.` | Not detected unless wrapper name matches `_HASH_CALL` patterns |
| Token stored via ORM `update()` rather than `add()`/`create()` | `update` call not in `_DB_WRITE` patterns |

## Checklist items flipped

| Checklist item ID | Description | Status when guard fires |
|---|---|---|
| `7-refresh-tokens-hashed` | Refresh tokens are hashed before database storage | Not covered — finding emitted |

## Tests

| Test | What it checks |
|---|---|
| `test_refresh_token_plaintext_fires` | Bare `secrets.token_urlsafe` → `db.add(` within 10 lines emits one HIGH finding |
| `test_refresh_token_plaintext_silent_with_hash` | `hashlib.sha256` between generation and `db.add(` suppresses the finding |
| `test_refresh_token_plaintext_pragma_opt_out` | File with `# security: allow-refresh-token-plaintext` emits no finding |
| `test_refresh_token_plaintext_not_applicable_without_python` | `applies()` returns False when `"python"` not in features |
| `test_refresh_token_plaintext_uuid_fires` | `uuid.uuid4()` assigned to `token` then `session.add(` fires |
| `test_refresh_token_plaintext_bcrypt_silent` | `bcrypt.hashpw` between generation and write suppresses the finding |

# Citations

[1] agentsec checklist item `7-refresh-tokens-hashed` (§7)
[2] OWASP:A02
