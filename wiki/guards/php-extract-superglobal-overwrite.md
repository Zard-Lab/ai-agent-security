---
type: Guard
title: "php-extract-superglobal-overwrite"
description: "No extract() call directly on a request superglobal — arbitrary local-variable overwrite from user input."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-extract-superglobal-overwrite"
checklist_section: ["3b"]
standards: ["OWASP:A08"]
---

# extract() called directly on a request superglobal

Flags `extract()` calls whose argument is one of PHP's request superglobals — `$_GET`, `$_POST`,
`$_REQUEST`, `$_COOKIE`. Closes checklist item `3b-php-extract-superglobal-overwrite` — a genuinely
PHP-specific concept with no existing sibling guard (agentsec's second PHP-language guard,
added with PHP support). CWE-473 (PHP External Variable Modification), OWASP:A08 (Software and Data Integrity
Failures).

## The threat

`extract()` imports every key of the given array into the current symbol table as a variable. Called
on unfiltered user input — `extract($_GET)`, `extract($_POST)`, `extract($_REQUEST)`,
`extract($_COOKIE)` — an attacker chooses which local variables get defined or overwritten simply by
choosing the request's parameter names. A request to `?is_admin=1` silently creates
`$is_admin = "1"` in the calling scope; if that variable is later trusted for an authorization check,
a config flag, or any other logic decision, the attacker has effectively injected it.

This is the modern-day resurgence of the notorious `register_globals` vulnerability class.
`register_globals` was a PHP configuration directive that auto-populated the global scope from
request data; it defaulted to off from PHP 4.2 and was removed entirely in PHP 5.4 specifically
because of this exact risk. `extract()` on a superglobal recreates the identical primitive
deliberately, in application code, on any PHP version — the platform-level fix does not protect code
that reintroduces the pattern by hand.

## Exploitability rationale

HIGH, not CRITICAL. `extract()` on a superglobal is a real, serious variable-injection primitive —
an attacker gets to choose which variables exist and what they hold. But unlike a direct RCE sink
(`preg_replace()` with `/e`, `eval()`, `system()` on tainted input), the actual impact here is
entirely conditional on what the surrounding code does with the newly-defined variables. If nothing
downstream trusts an unexpected variable name, the practical damage is limited; if an auth check or
include path does, it can be as severe as any other logic-bypass or injection bug. That
downstream-dependency is why this sits one severity notch below the guard's `preg_replace()` sibling,
the same class of judgment call this project's other severity assignments already make.

## What counts as a hit (and what doesn't)

- `extract($_GET)`, `extract($_POST)`, `extract($_REQUEST)`, `extract($_COOKIE)` fire — a direct
  call with one of the four request superglobals as the argument, regardless of whitespace between
  `extract(` and the `$_...` name, and regardless of an optional trailing `EXTR_*` flags argument
  (the flags argument changes collision behavior, not whether the superglobal's own keys still drive
  which variables get created).
- `extract($_ENV)` and `extract($_SERVER)` do **not** fire — deliberately scoped out. See "When NOT
  to flag" below for the reasoning.
- `extract($someLocalArray)` does **not** fire, even when `$someLocalArray` is built entirely from
  request data a few lines earlier — the guard is textual/regex-only and cannot trace where a local
  array's contents came from. See "Known bypasses."

## When NOT to flag (and the pragma)

- `extract($_ENV)` / `extract($_SERVER)` → silent by design. Both are populated from the server/CGI
  environment and PHP's own request metadata, not directly and arbitrarily from attacker-chosen
  request *parameter names* the way `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` are — an attacker
  does not get to invent new `$_SERVER` keys by adding a query parameter. This is a real risk
  scoping decision, not an accidental gap: `$_SERVER` in particular does carry some
  attacker-influenced values (e.g. `HTTP_*` headers), but its key set itself is not attacker-chosen
  the way a superglobal's request-parameter keys are, so it is excluded to keep the guard's signal
  honest rather than diluted by a much noisier, lower-confidence case.
- `extract($someLocalArray)` where the array is visibly hardcoded/internal → silent (this is the
  common, legitimate use of `extract()` — e.g. unpacking a config array from a trusted source file).
- Commented out (`// extract($_GET);`) or inside a real `#` line comment → silent; comment stripping
  is string-aware, matching the sibling `preg_replace()` guard's behavior.
- A call that is genuinely audited (the array is filtered/allowlisted before `extract()`, or the
  superglobal's keys are provably unreachable by an attacker in this deployment) → suppress
  explicitly:

```php
extract($_GET); // security: allow-extract-superglobal-overwrite
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Fires on the direct-superglobal-argument shape alone, with no attempt
  to prove which variables an attacker could realistically set or what downstream code does with
  them. The pragma is the intended correction for an audited case, not a guard limitation to fix
  later.
- **Single-line, textual.** The guard textually cannot tell trusted from untrusted data beyond the
  literal `extract($_GET)`/`$_POST`/`$_REQUEST`/`$_COOKIE` shape. `extract($someLocalArray)` where
  `$someLocalArray = $_GET;` was assigned one line above is NOT flagged — tracing an intermediate
  variable back to a superglobal is out of scope for a textual/regex-only guard (the task
  description calls this out explicitly as an optional bonus beyond the primary target, not
  implemented here to keep the detection shape unambiguous and low-noise).
- **`$_ENV`/`$_SERVER` scoping is a judgment call, not a guarantee.** See "When NOT to flag" above —
  documented honestly as a deliberate narrowing, not proof those two superglobals can never carry
  attacker influence.
- **Impact is entirely conditional on downstream code.** A clean report from this guard proves
  nothing about the actual exploitability of any `extract()` call it does not see (e.g. through an
  intermediate variable) — and a finding from this guard proves the primitive exists, not that it is
  reachable to real impact.

## What this guard does NOT prove

A clean scan means no `extract()` call was found with a request superglobal as its direct argument
in the scanned PHP source — it says nothing about equivalent behavior reached via an intermediate
variable, a wrapper function, or a dependency's own internal use of `extract()`.

## Canary plant

`ExtractOverwrite.php` — `extract($_GET);` inside a function body, no pragma. Expected rule:
`php-extract-superglobal-overwrite/direct-superglobal-extract`.

# Examples

```php
<?php
// Flagged: attacker chooses which local variables get defined via GET parameter names.
function importRequest() {
    extract($_GET);
    return $is_admin ?? false;
}
```

```php
<?php
// Not flagged: extracting a hardcoded, internal config array.
function loadDefaults() {
    $config = ['timeout' => 30, 'retries' => 3];
    extract($config);
    return $timeout;
}
```

# Citations

[1] agentsec checklist item `3b-php-extract-superglobal-overwrite` (§3b)
[2] OWASP:A08 (Software and Data Integrity Failures)
[3] CWE-473 (PHP External Variable Modification)
[4] PHP manual, `extract()` — symbol-table import semantics
[5] PHP manual / historical `register_globals` directive — removed in PHP 5.4, the precedent this
    pattern recreates deliberately
[6] graudit (`wireghoul/graudit`) — `signatures/php.db`, the `extract(` entry (provenance only;
    detection logic here is original)
