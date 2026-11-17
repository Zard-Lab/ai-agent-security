---
type: Guard
title: "php-preg-replace-eval-modifier"
description: "No preg_replace() call using the deprecated /e (eval) modifier."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-preg-replace-eval-modifier"
checklist_section: ["3b"]
standards: ["OWASP:A03"]
---

# preg_replace() with the deprecated /e (eval) modifier

Flags `preg_replace()` calls whose pattern string carries the `/e` regex modifier. Closes checklist
item `3b-preg-replace-eval-modifier` — a genuinely PHP-specific concept with no existing sibling
guard (agentsec's first PHP-language guard). CWE-95 (Eval Injection), OWASP:A03.

## The threat

`preg_replace('/(.*)/e', $replacement, $subject)` — when the `/e` modifier is set, PHP evaluates
the REPLACEMENT string as literal PHP code after performing backreference substitution. If either
the pattern or the replacement argument incorporates attacker-controlled input, an attacker can
inject arbitrary PHP code that gets `eval()`'d. This was one of the most common real-world PHP RCE
vectors before the modifier was deprecated in PHP 5.5 and removed entirely in PHP 7.0 — legacy
PHP 5.x codebases (and code still written to target them) can still carry it.

## Exploitability rationale

CRITICAL. A direct code-execution primitive when either input reaches the call, not a "confirm by
hand" architecture signal — the same severity class as `code-injection-eval-exec`.

## What counts as a hit (and what doesn't)

- `preg_replace('/pattern/e', ...)` fires — the delimiter can be any non-alphanumeric character
  PHP allows (`/`, `#`, `~`, etc.), matched and backreferenced, not hardcoded to `/`.
- The `e` flag combined with any other modifier, in any order (`/ie`, `/ei`, `/gse`, ...) still
  fires — PHP does not require a fixed modifier order.
- `preg_replace('/pattern/i', ...)` (no `e` flag) → silent.
- `preg_replace_callback(...)` (the safe alternative — a real PHP callback, never an eval'd
  string) → silent even when its own arguments happen to contain the substring `e`; the guard
  requires `(` to follow `preg_replace` with only whitespace between, so
  `preg_replace_callback(` never matches.

## When NOT to flag (and the pragma)

- `preg_replace('/pattern/i', ...)` → silent (a non-eval modifier).
- `preg_replace_callback(...)` → silent (the modern, safe replacement).
- Commented out (`// preg_replace('/(.*)/e', ...)`) or inside a real `#` line comment → silent;
  comment stripping is string-aware, so a delimiter/flag mention only inside a string literal on
  the same line is not mistaken for a real call.
- A hardcoded, non-attacker-reachable pattern/replacement pair → suppress explicitly:

```php
preg_replace('/(.*)/e', $replacement, $subject); // security: allow-preg-replace-e-modifier
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Fires on the `/e` modifier's presence alone, with no attempt to
  prove the pattern/replacement is attacker-reachable. The pragma is the intended correction, not
  a guard limitation to fix later.
- **Single-line, textual.** A pattern string assembled across several lines or built from a
  variable holding the modifier is not traced.
- **Heredoc/nowdoc patterns are not recognized.** `strip_php_comments` (and this guard's own
  regex) does not special-case PHP's `<<<EOT ... EOT` string forms — a `preg_replace()` call whose
  pattern argument is a heredoc rather than a quoted literal is not matched. Rare in the call-site
  shapes this guard targets (a regex pattern is almost always a short quoted literal), documented
  rather than silently assumed away.

## What this guard does NOT prove

A clean scan means no `/e`-modifier `preg_replace()` call-site was found in the scanned PHP
source — it says nothing about equivalent behavior reached via a dynamically-built modifier string,
a wrapper function, or a dependency's own internal use of the pattern.

## Canary plant

`RegexEval.php` — `preg_replace('/(.*)/e', $replacement, $subject)` inside a function body, no
pragma. Expected rule: `php-preg-replace-eval-modifier/e-modifier-set`.

# Citations

[1] agentsec checklist item `3b-preg-replace-eval-modifier` (§3b)
[2] OWASP:A03 (Injection)
[3] CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code / Eval Injection)
[4] PHP manual, `preg_replace()` — the `/e` modifier, deprecated PHP 5.5, removed PHP 7.0
[5] graudit (`wireghoul/graudit`) — `signatures/php.db` (provenance only; detection logic here is
    original)
