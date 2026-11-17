---
type: Guard
title: "php-unsafe-deserialization"
description: "No unserialize() call on data that is not a hardcoded string literal."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-unsafe-deserialization"
checklist_section: ["3b"]
standards: ["OWASP:A08", "OWASP-LLM:LLM03"]
---

# unserialize() called on untrusted or dynamic data — PHP Object Injection

Flags PHP `unserialize()` calls whose first argument is not a hardcoded string literal — a
superglobal (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/...), a bare variable, a string concatenation,
or a function-call result. Closes checklist item `3b-unsafe-deserialization` for PHP, extending the
existing cross-language `unsafe-deserialization` guard (Python `pickle`/`yaml`/`torch`/Haystack, JS
`js-yaml`) to PHP's own deserialization sink. Second PHP-language guard on this branch (
2/9). CWE-502, OWASP:A08.

## The threat

The real term of art for this is **PHP Object Injection (POI)**. `unserialize()` reconstructs a
PHP value — including full objects — from a serialized byte string. When it reconstructs an
object, PHP automatically calls that class's `__wakeup()` magic method immediately, and its
`__destruct()` method later when the object is garbage-collected. Neither call requires the
attacker to invoke the method directly: simply getting `unserialize()` to run on attacker-supplied
bytes is enough to trigger whatever `__wakeup`/`__destruct`/`__toString`/etc. does on any class
that autoloading can reach — including classes never intended to be touched this way. Chaining
several such classes together ("gadget chaining") is exactly how a string of real-world PHP
Object Injection CVEs — in WordPress plugins, Magento, phpMyAdmin, and other PHP CMSs/frameworks —
turned into full remote code execution, file deletion, or SQL injection, entirely from a crafted
`unserialize()` payload.

## Exploitability rationale

CRITICAL. `unserialize()` on attacker-controlled bytes is a direct object-instantiation primitive,
not merely an architecture signal to confirm by hand — the same severity class as the sibling
Python/JS `unsafe-deserialization` guard's `pickle.loads`/`yaml.load` findings. Whether it
*actually* reaches RCE depends on which classes are autoloadable in the target application (a
gadget chain must exist), which this guard cannot see — but the call shape itself is the standard
industry signal for "audit this," the same posture graudit's own PHP signature set takes.

## What counts as a hit (and what doesn't)

- `unserialize($_GET['data'])`, `unserialize($_POST[...])`, `unserialize($_REQUEST[...])`,
  `unserialize($_COOKIE[...])` — any PHP superglobal → fires (obviously attacker-reachable).
- `unserialize($payload)` — a bare variable → fires. This scanner has no dataflow, so it cannot
  tell a tainted variable from a trusted one by name; see Known bypasses.
- `unserialize('prefix' . $suffix)` — string concatenation → fires (the argument is not a sole
  literal, so at least part of it is dynamic).
- `unserialize(file_get_contents($path))` — a function-call result → fires.
- `unserialize('a:1:{i:0;s:3:"foo";}')` — a hardcoded, sole string literal argument → **silent**.
  This is the one shape a textual scanner can actually prove is not attacker-reachable at the call
  site itself.
- `unserialize()` with no arguments (not valid PHP, but tolerated defensively) → silent.

## When NOT to flag (and the pragma)

- A sole string literal argument → silent, no pragma needed.
- Commented out (`// unserialize($_GET['data']);`) or inside a real `#` line comment → silent;
  comment stripping is string-aware, matching the sibling `php-preg-replace-eval-modifier` guard.
- A variable that genuinely never carries attacker input (e.g. a value read back from a trusted,
  server-controlled cache file) → suppress explicitly, since this scanner cannot distinguish that
  case from a tainted one by the variable's name alone:

```php
unserialize($trustedInternalConfig); // security: allow-php-unsafe-deserialization
```

## Known bypasses (honest limits)

- **No dataflow, no context — the core limitation.** This is a textual/regex scanner, not a real
  parser or a taint tracker. It fires on the *shape* of the call (argument is not a sole literal),
  with no attempt to trace where a variable's value actually comes from. `unserialize($_GET['x'])`
  (obviously tainted) and `unserialize($cachedInternalBlob)` (very likely trusted) are textually
  identical to this guard — both are "a bare variable" and both fire. The pragma is the intended
  correction for an audited case, not a guard limitation to fix later.
- **Single-line only.** Detection runs per physical line; a call whose argument list spans
  multiple lines, or a pattern string/payload assembled across several statements before being
  passed in, is not traced.
- **Method calls named `unserialize` are not distinguished from the built-in function.** A class
  implementing PHP's `Serializable` interface defines its own `unserialize($serialized)` method,
  called as `$obj->unserialize($data)`. This guard's regex only anchors on a word boundary before
  `unserialize(`, which a `->` also satisfies, so such a method call is matched the same way as
  the global function. This is an accepted over-match: `Serializable::unserialize()`
  implementations themselves very often pass `$serialized` straight into the real built-in
  internally, so flagging the call site is not unreasonable, but it does mean the finding may
  point at a method signature rather than the actual deserialization line.
- **`allowed_classes` is not credited.** PHP 7+'s `unserialize($data, ['allowed_classes' =>
  false])` form (which disables object instantiation entirely, closing the POI vector even on
  tainted input) is not recognized as a mitigation — the guard fires the same way regardless of a
  second argument. Suppress with the pragma once the options array is confirmed safe.

## What this guard does NOT prove

A clean scan means no `unserialize()` call-site with a non-literal argument was found in the
scanned PHP source on a single line — it says nothing about whether any autoloadable class in the
application actually has an exploitable `__wakeup`/`__destruct`/`__toString` gadget, whether a
flagged variable is truly attacker-reachable, or about equivalent behavior reached through a
wrapper function or a dependency's own internal `unserialize()` use.

## Canary plant

`SessionHandler.php` — `unserialize($_COOKIE['session'])` inside a function body, no pragma.
Expected rule: `php-unsafe-deserialization/tainted-unserialize`.

# Citations

[1] agentsec checklist item `3b-unsafe-deserialization` (§3b)
[2] OWASP:A08 (Software and Data Integrity Failures)
[3] OWASP-LLM:LLM03 (Supply Chain Vulnerabilities)
[4] CWE-502 (Deserialization of Untrusted Data)
[5] PHP manual, `unserialize()` — object instantiation, `__wakeup()`/`__destruct()` magic methods,
    the `allowed_classes` option
[6] graudit (`wireghoul/graudit`) — `signatures/php.db`, the `unserialize(` entry (provenance
    only; detection logic here is original)
