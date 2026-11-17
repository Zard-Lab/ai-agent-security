---
type: Guard
title: "php-reflected-xss"
description: "No reflected XSS via a superglobal echoed/printed directly with no escaping call in the same statement."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-reflected-xss"
checklist_section: ["3b"]
standards: ["OWASP:A03"]
---

# Reflected XSS via unescaped superglobal output (echo/print/short-echo-tag)

Flags `echo`/`print`/the short-echo-tag `<?=` outputting a bare superglobal (`$_GET`/`$_POST`/
`$_REQUEST`/`$_COOKIE`) with no escaping call anywhere in that output statement. Closes checklist
item `3b-php-reflected-xss` — agentsec's second PHP-language guard (2/9), distinct from
the existing client-side `6a-dom-xss-sinks` item (JS/browser DOM XSS): this fires on PHP
server-side code that echoes unescaped request data straight into an HTML response.
CWE-79, OWASP:A03.

## The threat

`echo $_GET['name'];` — PHP superglobals carry attacker-controlled request data verbatim. Output
that data into an HTML response with no encoding and an attacker who controls the query string,
POST body, or a cookie can inject markup or script that executes in the victim's browser: classic
reflected XSS. This is one of the oldest and most common PHP vulnerability classes — it predates
and outlives specific frameworks, because raw `echo`/`print`/`<?=` is still how a large share of
PHP code renders output.

## Exploitability rationale

HIGH — a well-understood, directly exploitable web vulnerability class with attacker-controlled
input and no proof-of-reachability gap (the superglobal read and the unescaped output are the same
statement), one notch below the direct-RCE items (e.g. `php-preg-replace-eval-modifier`,
`code-injection-eval-exec`) because the impact is client-side script execution in the victim's
browser rather than server-side code execution.

## What counts as a hit (and what doesn't)

- `echo $_GET['name'];`, `print $_POST['x'];`, `<?= $_REQUEST['y'] ?>` — a direct, unescaped
  superglobal in an output statement — all fire.
- String concatenation around the superglobal (`echo "Hi " . $_GET['name'];`) still fires — the
  guard scans the whole output statement (from the `echo`/`print`/`<?=` keyword to the next `;`,
  or end of line if there is none), not just the token immediately after the keyword.
- **The escaping-function exclusion list is the core of this guard's false-positive defense**
  (graudit's own `signatures/php.db` documentation explicitly calls out escaping-context FP risk
  for this exact pattern). A statement stays silent if it contains a call to any of these four
  functions anywhere in it, regardless of whether it strictly wraps the superglobal token:
  - `htmlspecialchars(...)` — `echo htmlspecialchars($_GET['name']);` → silent.
  - `htmlentities(...)` — `echo htmlentities($_POST['x']);` → silent.
  - `strip_tags(...)` — `echo strip_tags($_REQUEST['y']);` → silent.
  - `filter_var(...)` — `echo filter_var($_COOKIE['x'], FILTER_SANITIZE_STRING);` → silent.
- `echo "Hello, world!";` (no superglobal reference at all) → silent.
- `print_r($_GET);` → silent — the function-name match requires a word boundary after
  `echo`/`print`, so `print_r` (a different function) is never mistaken for the `print` keyword.
- Commented out (`// echo $_GET['name'];`) or inside a real `#` line comment → silent; comment
  stripping is string-aware, so a mention only inside a string literal is not mistaken for a real
  statement.

## When NOT to flag (and the pragma)

- Output that is genuinely not an HTML response context (plain text, a JSON field encoded
  elsewhere, a CLI script) is a false positive this guard cannot distinguish textually — suppress
  explicitly:

```php
echo $_GET['name']; // security: allow-php-reflected-xss
```

## Known bypasses (honest limits)

- **No dataflow, no context — textual/regex-only.** The guard has no notion of whether the output
  actually reaches an HTML response; it fires on the syntactic shape alone.
- **Same-line/same-statement scope, not cross-line.** A superglobal assigned to a variable and
  echoed later — even many lines away, even through a chain of otherwise-safe code — is not
  traced:

  ```php
  $name = $_GET['name'];
  // ... other code ...
  echo $name;   // NOT detected — the superglobal reference and the echo are on different lines
  ```

  This is a real, deliberate limitation, not an oversight: tracing dataflow across statements would
  require a real parser and a much higher false-positive/false-negative tradeoff than this guard's
  textual scope is designed for. The corollary also holds and is not treated as a bug: if a
  superglobal is assigned through a variable that a **separate** line escapes, this guard cannot
  confirm that either — it simply never looks at that later `echo`.
- **The escaping check is "anywhere on the statement," not "provably wrapping the superglobal."**
  A statement with the superglobal token and an escaping-function call anywhere in it, even on an
  unrelated argument, is treated as escaped. This trades a theoretical false negative for
  eliminating the far more common false positive (the straightforward `echo htmlspecialchars(...)`
  idiom) — consistent with graudit's own documented caution about this pattern.
- **Heredoc/nowdoc and PHP/HTML mode-switching are not tracked** (inherited limitations of
  `strip_php_comments`, documented on that helper) — a superglobal echoed inside a heredoc block is
  not specially handled.
- **Only the four named functions count as escaping.** A custom sanitizer wrapper, a templating
  engine's auto-escaping, or output through a framework response object is not recognized and will
  false-positive; the pragma is the intended correction.

## What this guard does NOT prove

A clean scan means no unescaped-superglobal `echo`/`print`/`<?=` statement was found in the scanned
PHP source on the file's own lines — it says nothing about a superglobal reaching output through a
variable, a framework template, a function return value, or any path this guard's same-line scope
does not cover.

## Canary plant

`Reflected.php` — `echo $_GET['name'];` inside a function body, no pragma. Expected rule:
`php-reflected-xss/unescaped-superglobal-echo`.

# Examples

Fires:

```php
<?php
echo $_GET['name'];
print $_POST['comment'];
?>
<?= $_REQUEST['q'] ?>
```

Silent (escaped):

```php
<?php
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

# Citations

[1] agentsec checklist item `3b-php-reflected-xss` (§3b)
[2] OWASP:A03 (Injection)
[3] CWE-79 (Improper Neutralization of Input During Web Page Generation / Cross-site Scripting)
[4] graudit (`wireghoul/graudit`) — `signatures/php.db`, PHP reflected-XSS signatures keyed off
    `echo`/`print`/short-echo-tag output of a superglobal (provenance only; detection logic and the
    escaping-function exclusion list here are original, not copied). graudit's own documentation
    flags this exact pattern as needing extra escaping-context care to avoid false positives — that
    caveat is what shaped this guard's four-function exclusion list.
