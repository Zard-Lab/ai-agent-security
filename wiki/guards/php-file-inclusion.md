---
type: Guard
title: "php-file-inclusion"
description: "No PHP local/remote file inclusion (LFI/RFI) via tainted include/require or dangerous stream wrappers."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-file-inclusion"
checklist_section: ["3b"]
standards: ["OWASP:A01"]
---

# PHP local/remote file inclusion (LFI/RFI)

Flags two reconciled patterns from the same threat family — untrusted input reaching PHP's
file-inclusion machinery — rather than treating them as two separate concerns. Closes checklist
item `3b-php-file-inclusion`, a genuinely PHP-specific concept with no existing sibling guard
(agentsec's second PHP-language guard, 2/9). CWE-98 (Improper Control of Filename for
Include/Require Statement in PHP Program), OWASP:A01.

## The threat

PHP's `include`/`include_once`/`require`/`require_once` pull in and execute another file's PHP
code at the call site. When the path argument is built from user input rather than a fixed
literal, an attacker controls what gets executed:

- **Remote File Inclusion (RFI):** if `allow_url_include` is enabled (or on older PHP versions
  where it defaulted on), a tainted path can point at an attacker-hosted URL
  (`http://evil.example/shell.txt`), and PHP fetches and executes it as code — full remote code
  execution with no local foothold required.
- **Local File Inclusion (LFI):** even with `allow_url_include` off, an attacker can direct the
  include at an unintended *local* file: a config file (leaking secrets when it errors or is
  included in a context that prints it), an uploaded "image" whose bytes are actually
  `<?php ... ?>`, or an application/access log the attacker has poisoned with a PHP payload
  (log-poisoning RCE, a well-known LFI-to-RCE chain).

**Dangerous stream wrappers** compound this. PHP treats certain URI prefixes as pluggable I/O
backends ("stream wrappers"), and several of them are commonly chained with `include`/
`file_get_contents`/`fopen`/etc. to turn an otherwise-bounded read into code execution or data
exfiltration:

- `php://filter` — applies a filter chain to a stream. Chained with `include()`, it can be used to
  convert file content to obtain LFI-to-RCE without needing PHP-tag-looking content; chained
  filter lists have also been used to build PHP object-injection ("filter chain") gadgets.
- `php://input` — the raw HTTP request body. Reading it as an "included" file means the POST body
  itself is attacker-controlled PHP code.
- `phar://` — accesses a `.phar` archive's internal file table, and merely `stat`-ing or reading
  through this wrapper triggers PHP's automatic Phar metadata unserialization ("phar
  deserialization"), a PHP object-injection primitive even without a direct `include`.
- `expect://` — when the `expect` PECL extension is loaded, this wrapper runs its argument as a
  shell command directly. Rare in production, but an immediate RCE primitive wherever it is used.

## Exploitability rationale

CRITICAL for both rules. Tainted `include`/`require` is a direct code-execution primitive once an
attacker controls the resolved path; the `php://filter`/`phar://`/`expect://` literals are
dangerous wherever they appear because they are the enabling ingredient for LFI-to-RCE and
deserialization chains, not a "confirm by hand" architecture signal. `php://input` is the one
wrapper with a routine benign use (reading the request body), so it carries a context gate rather
than firing on the bare literal.

## What counts as a hit (and what doesn't)

**Rule 1 — `php-file-inclusion/tainted-include`:**

- `include($_GET['page'])`, `require($path)`, `include_once($_REQUEST['x'])`,
  `require_once($p . '.php')` fire — any `include`/`require`(`_once`) call whose parenthesized
  argument contains a `$` (a variable, superglobal, or a concatenation involving one).
- `include('config.php')`, `require_once('vendor/autoload.php')` — an all-literal string argument,
  no `$` present — silent.
- A `->include(...)`/`_include(...)`-style identifier that merely *contains* the word `include` as
  part of a longer method/function name is boundary-checked (`\b`), so an ordinary identifier like
  `autoinclude(...)` reached through `$loader->autoinclude(...)` does not match the bare keyword
  form this guard targets.

**Rule 2 — `php-file-inclusion/dangerous-stream-wrapper`:**

- `php://filter`, `phar://`, or `expect://` appearing anywhere in PHP source fires, independent of
  which function it is passed to. None of the three has a common benign first-party use.
- `php://input` is the deliberate exception and is **gated**: it fires only as an include/require
  target, or when the line also carries user input (a superglobal, or a `. $` concatenation).
  Bare `file_get_contents('php://input')` and `fopen('php://input', 'rb')` are the canonical way
  to read a raw request body — present in essentially every PHP JSON API and every PSR-7
  implementation — so firing on the bare literal at CRITICAL red-gated ordinary code.
- The same strings inside a `//` or `#` comment, or on a pragma-suppressed line, do not fire (see
  below).

## When NOT to flag (and the pragma)

- An all-literal include/require path with no `$` in its argument list → silent (rule 1).
- Commented out (`// include($_GET['page']);` or `# php://input is an example`) → silent for both
  rules; comment stripping is string-aware, so a delimiter/wrapper mention only inside a string
  literal on the same line is not mistaken for a real comment boundary.
- A reviewed, intentionally safe use of either shape → suppress explicitly, one shared pragma for
  both rules:

```php
include($page); // security: allow-php-file-inclusion
```

```php
$x = file_get_contents('php://filter/resource=' . $name); // security: allow-php-file-inclusion
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Rule 1 fires on the mere presence of a `$` inside the call's
  argument list, with no attempt to prove that variable is attacker-reachable, or conversely to
  recognize when it has already been validated against an allowlist a few lines earlier. The
  pragma is the intended correction, not a guard limitation to fix later.
- **Single-line, textual, regex-only.** Neither rule tracks PHP's actual parenthesis/quote
  grammar beyond one line; a path argument or wrapper string assembled across several lines, or
  built up piecewise into a variable before being passed to `include`, is not traced.
- **A literal `$` inside a single-quoted string is not distinguished from a real variable.**
  `include('file_$1.php')` (a literal dollar sign, no interpolation in single-quoted PHP strings)
  would still match rule 1's `$`-presence check — the same broad, textual shape graudit's own
  signature has. Rare in practice; documented rather than silently assumed away.
- **Heredoc/nowdoc are not recognized.** `strip_php_comments` (and this guard's own regexes) does
  not special-case PHP's `<<<EOT ... EOT` string forms.
- **PHP/HTML mode-switching is not tracked.** The whole file is scanned uniformly; a stray
  wrapper-looking string in literal HTML/markup content could in principle be matched, though this
  is not observed in the call-site shapes this guard targets.

## What this guard does NOT prove

A clean scan means no tainted `include`/`require` call and no dangerous stream-wrapper literal was
found in the scanned PHP source — it says nothing about equivalent behavior reached through a
wrapper function, a dynamically-built wrapper string (`'php:' . '//filter/...'`), or a
dependency's own internal use of either pattern.

## Canary plant

`FileInclude.php` — `include($_GET['page'])` inside a function body, no pragma. Expected rule:
`php-file-inclusion/tainted-include`.

# Examples

```php
<?php
// Vulnerable — attacker controls which file gets included.
function loadPage() {
    include($_GET['page']);
}

// Vulnerable — a chained stream-wrapper read, independent of any include.
$src = file_get_contents('php://filter/read=convert.base64-encode/resource=index.php');

// Vulnerable — php://input as an include target executes the raw POST body as PHP.
include('php://input');

// Safe — the same wrapper simply read as a request body, the canonical PHP JSON-API idiom.
$body = json_decode(file_get_contents('php://input'), true);

// Safe — the path is resolved through a fixed allowlist, never built from input directly.
function loadPage() {
    $pages = ['home' => 'home.php', 'about' => 'about.php'];
    $key = $_GET['page'] ?? 'home';
    include($pages[$key] ?? $pages['home']);
}
```

# Citations

[1] agentsec checklist item `3b-php-file-inclusion` (§3b)
[2] OWASP:A01 (Broken Access Control — includes improper handling of untrusted paths)
[3] CWE-98 (Improper Control of Filename for Include/Require Statement in PHP Program)
[4] PHP manual, "Remote file inclusion" and "Supported Protocols and Wrappers"
    (`php://filter`, `php://input`, `phar://`, `expect://`)
[5] graudit (`wireghoul/graudit`) — `signatures/php.db` (provenance only; detection logic here is
    original)
