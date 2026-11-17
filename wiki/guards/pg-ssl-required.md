---
type: Guard
title: "pg-ssl-required"
description: "PostgreSQL connection requires SSL."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "pg-ssl-required"
checklist_section: ["7"]
standards: ["OWASP:A02", "SOC2:CC6.7"]
---

# PostgreSQL connection requires SSL

Flags a Postgres connection string (`postgres://` / `postgresql://`, incl. `+driver` forms) that has
no `sslmode=require|verify-ca|verify-full` (or `ssl=true`). Closes checklist item `7-pg-ssl-required`.

## The threat

A Postgres DSN without SSL sends the auth handshake (username + password) and every row of query
traffic in cleartext. Anyone on the network path — a shared host, a misconfigured VPC peer, a
provider's internal hop, an on-path MITM — reads the credentials and the data. Supabase and most
managed Postgres providers terminate TLS, so omitting `sslmode` silently downgrades a connection the
provider was willing to encrypt. The fail-safe posture is `sslmode=require` at minimum, `verify-full`
to actually validate the server certificate (require alone encrypts but does not stop an active MITM
presenting any cert). OWASP A02 (Cryptographic Failures).

## Exploitability rationale

MEDIUM. The downgrade is real and the payload (DB credentials + all data) is maximal, but it requires
the attacker to already be on the network path — not a remote, zero-position attack like an open
endpoint. Severity tracks reachability: high-value target, but a precondition (network position)
gates it.

## When NOT to flag (and the pragma)

- **Local DSNs** — `@localhost` / `@127.0.0.1` → silent (local dev never crosses a network).
- **Internal compose service hosts** — a **bare single-label host** with no dot (`@postgres:5432`,
  `@db/app`, `@my-db`) is a Docker-compose service name reached container-to-container on the internal
  bridge network, where external TLS is not applicable → silent. This generalizes the loopback exemption
  to "not a real external host". The check is **host-anchored**, parsed straight off RFC 3986: the
  authority ends at the **first `/`, `?` or `#`**, and the host is what follows the **last `@` inside
  it**. So neither an unescaped `@` in a password, nor one in a path segment, nor one in a query-string
  parameter can fool it. Only a bare label with no
  dot is exempt: a **dotted** host (`@db.example.com`) and a **bracketed IPv6** host (`@[2001:db8::1]`)
  are treated as external and still fire.

  All three delimiters matter, and each was learned the same way. Bounding on none of them let a query
  `@` win; bounding on `?`/`#` but not `/` let a **path** `@` win, so
  `postgresql://prod:pw@db.prod.example.com:5432/tickets@acme` resolved to host `acme` and went silent
  (#471 review rounds 1 and 4). `/` is the delimiter the spec puts first and the one three successive
  hand-rolled scans all forgot.

  **The exemption fails loud.** This is the one path in the guard that can *suppress* a finding, so an
  authority it cannot parse with confidence resolves toward firing, never toward silence. Concretely: a
  DSN carrying userinfo where no `@` position yields a parseable `host[:port]` (a password containing a
  raw `?` or `#`, which truncates the authority bound) is reported as external and **fires**. Both
  characters must be percent-encoded in userinfo per RFC 3986, so a valid DSN pays nothing for this.

  **False-positive surface of that choice, disclosed:** an *internal* host whose password contains a raw
  `/`, `?` or `#` fires even though the host is a compose service name, because that character truncates
  the authority and the parse cannot see past it. All three must be percent-encoded in userinfo per RFC
  3986, so a well-formed DSN never lands here, but base64 secrets containing `/` do occur. The pragma
  covers it. This is the deliberate direction of the trade — a scanner that guesses wrong should be loud
  — but it is a real FP class, not a theoretical one.

  Also fires, deliberately: any DSN with an `@` in its **path**, because that is indistinguishable from
  a truncated authority.

  What does **not** defeat the exemption is a stray `@` in the **query or fragment** of a
  credential-less DSN (`postgresql://postgres:5432/db?application_name=svc@worker`). Query and fragment
  are past the authority by definition and `?application_name=svc@worker` is an ordinary libpq
  connection label, so those stay silent. An earlier cut of the check treated any `@` in the string as
  evidence of userinfo and fired on the guard's own canonical exemption case (#471 review round 3).

  The bound is not theoretical. Without it, a query-string `@` won the backwards scan outright: a real
  external `db.example.com` carrying the ordinary libpq parameter `?application_name=svc@worker`
  resolved to the host `worker`, and being dotless was read as a compose service name, silencing the
  finding completely (#471 review round 2). (Widening note: any single-label host is exempt, so a real host
  addressed by a bare name on a flat network is a false negative — rare; use `sslmode=require` regardless
  as defense in depth.)
- **Already encrypted** — the DSN carries `sslmode=require|verify-ca|verify-full` or `ssl=true` → silent.
- **`.env.example`** — templates are documentation, not live config → skipped.
- A genuinely intentional plaintext case → suppress that line with `# security: allow-no-pg-ssl`. It counts
  only as a real `#` comment: the Python view for `.py`, the `hash` view for YAML, TOML, INI and `.env`,
  so the phrase inside a quoted DSN or string does not (#1040). YAML takes `hash`, not `yaml`, because a
  DSN often sits in a block scalar (a ConfigMap's `app.ini: |`) whose `#` is a comment of the embedded
  config, which the `yaml` view would read as content and void. The cost: a `#` inside a block scalar
  of any kind counts.

## What it scans

Python scan dirs + repo-root config files (`.py .toml .yaml .yml .ini .cfg`) and every `.env*` file
except `.env.example`. One finding per line (a DSN appearing once per config line is the norm).

## Known bypasses (honest limits)

- SSL forced *outside the DSN* — `connect(..., sslmode="require")` as a kwarg, a `sslmode` set in
  `PGSSLMODE` env, or `ssl=ssl.create_default_context()` passed to the driver — is not seen, so such a
  connection is a false positive; the pragma covers it.
- A DSN assembled from parts at runtime (`f"postgresql://{host}/{db}"` with the host in a var) is not
  matched — the guard keys on a literal DSN substring.
- `sslmode=prefer` / `allow` is treated as NOT ok (they fall back to cleartext), by design — only
  `require` and stronger silence the guard.

## What this guard does NOT prove

It catches a literal plaintext DSN in committed config; it does **not** prove the *runtime* connection
is encrypted (the effective DSN may come from an env var the scan can't read) nor that the cert is
actually verified (`require` ≠ `verify-full`). Absence of a finding ≠ SSL is provably enforced.

# Citations

[1] agentsec checklist item `7-pg-ssl-required` (§7)
[2] OWASP:A02
[3] SOC2:CC6.7
