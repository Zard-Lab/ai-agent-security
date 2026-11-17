---
type: Guard
title: "php-tls-verify-disabled"
description: "No PHP cURL call disabling TLS certificate verification (CURLOPT_SSL_VERIFYHOST/VERIFYPEER)."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-tls-verify-disabled"
checklist_section: ["8"]
standards: ["CWE-295"]
---

# cURL TLS certificate verification disabled (CURLOPT_SSL_VERIFYHOST/VERIFYPEER)

Flags PHP cURL calls that disable TLS certificate verification via
`CURLOPT_SSL_VERIFYHOST`/`CURLOPT_SSL_VERIFYPEER`. Extends checklist item `8-tls-verify-disabled`
(previously covered for python/express/go) to PHP — the PHP-specific idiom for the same
underlying weakness the Python `requests.get(verify=False)` and Go `InsecureSkipVerify: true`
guards already cover on this checklist item. CWE-295 (Improper Certificate Validation).

## The threat

PHP's cURL extension exposes two options that together gate TLS certificate validation on a
`curl_setopt()`/`curl_setopt_array()`-configured handle:

- `CURLOPT_SSL_VERIFYPEER` — whether the peer's certificate is verified against a trusted CA at
  all. Disabling it (`false`/`0`) accepts any certificate, self-signed or not.
- `CURLOPT_SSL_VERIFYHOST` — whether the certificate's Common Name / Subject Alternative Name is
  checked against the requested hostname. The correct/strict value is `2`; `0`/`false` disables
  the hostname check entirely.

Disabling either option means the client will accept a certificate from any origin — untrusted
CA, mismatched hostname, or both — over what looks like a normal HTTPS connection. This is
functionally identical in spirit to the Python `requests.get(url, verify=False)` pattern
(`tls_verify_disabled.py`) and to Go's `InsecureSkipVerify: true`
(`go_tls_verify_disabled.py`), both already on this same checklist item.

## Exploitability rationale

HIGH — matches the severity of the sibling `tls-verify-disabled`/`go-tls-verify-disabled` guards
on the same checklist item. A man-in-the-middle attacker anywhere on the network path between
the PHP process and the remote server can intercept, read, and tamper with the connection
undetected. Not CRITICAL because it requires an active network-position attacker rather than
being a direct remote code-execution primitive.

## What counts as a hit (and what doesn't)

- `curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false)` / `curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0)`
  → fires.
- `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)` / `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0)`
  → fires.
- `curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, null)` / `..., CURLOPT_SSL_VERIFYPEER, null)` → fires
  (PHP coerces `null` to falsy, same disabled effect).
- The array-literal form is also covered: `curl_setopt_array($ch, [CURLOPT_SSL_VERIFYPEER =>
  false, ...])` fires per disabled `CURLOPT_SSL_VERIFY(HOST|PEER) => <value>` entry, matched
  independently of line boundaries so an array literal spread across multiple lines is still
  caught.
- `CURLOPT_SSL_VERIFYHOST` set to `2` (the correct strict value) → silent.
- `CURLOPT_SSL_VERIFYPEER` set to `true` or `1` → silent.
- An unrelated cURL option set to `0` (e.g. `CURLOPT_TIMEOUT, 0`) → silent; the guard anchors on
  the two named constants, not on a bare `0` anywhere in a `curl_setopt()` call.
- A bare digit that merely starts with `0` inside a longer number (e.g. `..., 10)`) → silent; the
  value match requires a word boundary immediately after `false`/`0`/`null`, so `10` cannot be
  mistaken for a truncated `0`.

## When NOT to flag (and the pragma)

- Commented out (`// curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);`) or inside a real `#` line
  comment → silent; comment stripping is string-aware, matching the sibling PHP guard's
  `strip_php_comments` behavior.
- A deliberately mitigated case (e.g. an internal CA already pinned via `CURLOPT_CAINFO`, with
  the disable kept only as a documented, audited fallback) → suppress explicitly:

```php
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // security: allow-php-tls-verify-disabled
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Fires on the disabled value's presence alone in a `curl_setopt`
  call or a `CURLOPT_SSL_VERIFY* => <value>` array entry, with no attempt to prove the handle is
  actually `curl_exec()`'d against a network-reachable URL. The pragma is the intended
  correction, not a guard limitation to fix later.
- **Single-line, textual.** A value built from a variable (`curl_setopt($ch,
  CURLOPT_SSL_VERIFYHOST, $verifyHost)`) or assembled across a conditional is not traced — only a
  literal `false`/`0`/`null` at the call site is recognized.
- **`curl_setopt_array()` scope decision.** The array-entry pattern (`CURLOPT_SSL_VERIFY(HOST|PEER)
  => <disabled-value>`) is matched as a standalone key-value shape, NOT anchored to actually
  being textually inside a `curl_setopt_array(...)` call. In the extremely unlikely case a
  codebase declares an unrelated PHP array literal that happens to use the identical
  `CONSTANT => value` key spelling for some other purpose, this guard would still fire. Judged an
  acceptable trade given `CURLOPT_SSL_VERIFYHOST`/`CURLOPT_SSL_VERIFYPEER` are cURL-specific
  constant names with no other plausible use, the same trust-the-distinctive-name reasoning
  `go-tls-verify-disabled` uses for `InsecureSkipVerify`.
- **Heredoc/nowdoc and PHP/HTML mode-switching** are not specially handled — inherited limits of
  `strip_php_comments`, documented there.

## What this guard does NOT prove

A clean scan means no `curl_setopt()`/`curl_setopt_array()` call-site in the scanned PHP source
sets `CURLOPT_SSL_VERIFYHOST`/`CURLOPT_SSL_VERIFYPEER` to a disabled literal value — it says
nothing about TLS verification disabled through some other mechanism (a custom HTTP client
wrapper, a Guzzle-level `verify => false` option, a dependency's own internal cURL configuration,
or a dynamically-computed option value).

## Canary plant

`CurlTls.php` — `curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false)` inside a function body, no
pragma. Expected rule: `php-tls-verify-disabled/curl-ssl-verify-disabled`.

# Citations

[1] agentsec checklist item `8-tls-verify-disabled` (§8)
[2] CWE-295 (Improper Certificate Validation)
[3] PHP manual, `curl_setopt()` — `CURLOPT_SSL_VERIFYHOST` / `CURLOPT_SSL_VERIFYPEER`
[4] graudit (`wireghoul/graudit`) — `signatures/php.db` (provenance only; detection logic here is
    original)
