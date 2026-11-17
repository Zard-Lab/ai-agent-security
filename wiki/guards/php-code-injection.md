---
type: Guard
title: "php-code-injection"
description: "No PHP code injection via a non-literal eval()/assert()/create_function()/backtick sink."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-code-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03", "ASVS:1.3.2"]
---

# No code injection via a PHP eval()/assert()/create_function()/backtick sink

Flags PHP's classic dynamic-code-evaluation sinks — `eval()`, `assert()` (its pre-PHP 8
string-eval behavior), `create_function()`, and the backtick shell-execution operator — when called
with an argument that is not a sole string literal. Extends checklist item `3b-eval-exec-injection`
(the same item `code-injection-eval-exec` and `js-code-injection` cover for Python and JS/Node) with
the PHP surface. CWE-95 (Eval Injection), OWASP:A03, ASVS:1.3.2.

## The threat

- `eval($code)` — PHP compiles and runs `$code` as PHP source. If an attacker influences `$code`
  (directly or through concatenation/a helper function), this is arbitrary PHP code execution.
- `assert($code)` — before PHP 8, when `zend.assertions` was enabled, `assert()` evaluated a STRING
  argument as PHP code exactly like `eval()` (not merely tested it truthy). This behavior was
  deprecated in PHP 7.2 and removed in PHP 8.0, but a regex-only, version-blind scan cannot tell
  which runtime a given codebase targets — legacy PHP 5.x/7.x code (and code still written to run
  on it) can still carry this pattern for real.
- `create_function($args, $code)` — deprecated since PHP 7.2, removed in PHP 8.0. Builds an
  anonymous function by internally `eval()`-ing a synthesized function definition built from its
  two string arguments. Either argument being non-literal is the same code-injection primitive.
- The backtick operator (`` `$cmd` ``) — PHP shorthand for `shell_exec()`. A backtick expression
  that interpolates a variable is command injection if that variable is attacker-influenceable.
  Grouped into this guard (rather than a standalone one) because graudit's own signature dictionary
  groups it alongside the eval/exec sinks as the same class of "attacker text fed to an
  interpreter."

## Exploitability rationale

HIGH — the same severity `code-injection-eval-exec`/`js-code-injection` use: a real code-execution
primitive whenever the argument is attacker-reachable, but (like its Python/JS siblings) this guard
proves only that the sink was called with non-literal content, not that the content is actually
attacker-controlled — no dataflow tracing is attempted.

## What counts as a hit (and what doesn't)

Fires when the sink's argument (both arguments, for `create_function()`) is **not a sole string
literal** — a bare `$variable`, a superglobal subscript (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/
`$_ENV`/`$_SERVER`), `.`-concatenation, or a function-call result all count as non-literal:

```php
eval($_GET['code']);                              // superglobal -> fires
assert($userInput);                                // bare variable -> fires
create_function($_POST['args'], $_POST['code']);   // superglobal args -> fires
eval('prefix ' . $suffix);                          // concatenation -> fires
eval(buildPayload());                               // function-call result -> fires
$out = `rm -rf $target`;                            // backtick interpolates a variable -> fires
$out = `wget http://$_GET[h]/x`;                    // backtick with a URL -> fires (see below)
assert($obj->getPayload() . $b);                    // member call in a concatenation -> fires
```

Does NOT fire:

```php
eval("2 + 2;");                    // sole string literal -> silent (see below)
create_function('$a,$b', 'return $a+$b;');   // both args sole literals -> silent
$out = `ls -la`;                    // pure-literal backtick, no variable -> silent
$obj->eval($thing);                 // a method call, not the global builtin -> silent
assert(true);                       // boolean literal, never string-eval'd -> silent
assert($x > 5);                     // top-level comparison, always bool -> silent
assert(($a ?? 0) > 5);              // the `?` of `??` is not a ternary -> still silent
assert($this->logger instanceof X); // instanceof is bool-valued -> silent
```

**"Top level" is load-bearing for the `assert()` exclusions.** An operator character only counts as
proof the expression is bool-valued when it is genuinely at the top level of the argument. Before
the check is applied, the argument is reduced: string literals are dropped (`$in . " >= 5"` is a
tainted concatenation, not a comparison), member-access arrows `->`/`?->` are dropped (their `>` is
not a comparison and their `?` is not a ternary), and parenthesized sub-expressions are collapsed
(so `($a ?? 0) > 5` and `($a ?: 0) > 5` are correctly seen as bool-valued, while the `?` of a real
top-level ternary `$a > 1 ? $b : $c` survives and correctly waives the exclusion, since a ternary's
value is one of its branches and may be a tainted string).

**The backtick sink is matched against the RAW line, not the comment-stripped one.** PHP's backtick
is a shell-exec literal that `strip_php_comments` does not track, so a `//` or `#` *inside* the
command (any URL, `git clone http://…`, a `#`-bearing flag) would otherwise blank the rest of the
line and take the closing backtick with it, silently voiding the detection. A position check
(`_live()`, mirroring `ruby_command_injection.py`, which solved the identical problem for Ruby
backticks) restores the comment suppression the stripped line used to provide incidentally.

**A backtick that is quoted string DATA, not PHP's own operator, does not fire (#848 corpus scan,
round 2).** A SQL identifier quote (`` `col` ``) embedded in a query string built via `.`
concatenation is common real PHP (`matomo-org/matomo`'s `core/Access.php`: `"... FROM \`" .
$access . "\` ..."`) — the raw line has two backtick characters with a `$variable` textually
between them, which the naive match read as a tainted backtick shell-exec. The guard now tracks
PHP single-/double-quoted string state (escape-aware, comment-stripped-text-based so an apostrophe
inside a `//`/`#` comment can't confuse it) and rejects a backtick match when either backtick sits
inside an active string literal — including one opened on a PRIOR line, since a `.`-concatenated
query string commonly spans a literal newline. A real backtick operator is, by definition, never
itself inside a string literal, so this costs nothing on the true-positive path (verified both
directions, including a real backtick sink appearing on the line immediately after an unrelated
multi-line string closes).

An all-literal `eval("some hardcoded string")` not firing is a deliberate, narrow scope choice: a
purely hardcoded eval is unusual (why eval a constant at all?) but is not itself the vulnerability
this guard targets — there is no injection point when nothing external reaches the call. It IS real
FP-bait, since a hardcoded eval is still an eyebrow-raising pattern worth a human's attention in
other contexts; this guard deliberately stays out of that lane.

## When NOT to flag (and the pragma)

- A `//` or `#` line comment mentioning any of these sinks → silent (comment stripping is
  string-aware, mirroring `php-preg-replace-eval-modifier`'s own comment handling).
- Suppress an audited case explicitly:

```php
eval($trustedConstant); // security: allow-php-code-injection
```

## Known bypasses (honest limits)

- **No dataflow, no taint tracking.** Unlike `js-code-injection` (which requires the argument to
  trace back to `req.*`/`request.*`), this guard fires on structural non-literalness alone — any
  bare variable counts, regardless of where it came from. This is deliberately broader than the JS
  sibling: PHP request data commonly flows through superglobals accessed many call-frames away from
  the sink, and a regex scan cannot trace that, so the guard accepts more false positives (any
  variable) rather than more false negatives (missing a genuinely tainted call whose superglobal
  read happens elsewhere). The pragma is the intended correction.
- **Single-line, textual.** An argument built across multiple lines, or a modifier string held in a
  variable, is not traced.
- **Double-quoted string interpolation is not resolved.** A double-quoted literal that itself
  interpolates a variable (`eval("cmd: $var")`) is read by this guard's "sole string literal" check
  as a plain literal and does NOT fire — a real, documented gap (the same class of residual
  `strip_php_comments` already discloses for heredoc/nowdoc forms), not silently assumed away.
- **Heredoc/nowdoc arguments are not recognized**, inherited from `strip_php_comments`'s own
  documented scope (see that helper's docstring) — an argument built from `<<<EOT ... EOT` is not
  matched.
- **`assert()`'s PHP-version blindness.** The guard cannot tell whether a scanned codebase targets
  PHP 8+ (where `assert()` no longer evaluates strings at all) — it flags the pattern unconditionally
  wherever it appears, which is a deliberate, disclosed trade-off given the tool has no reliable way
  to detect the target PHP version from source alone.
- **`create_function()`'s own deprecation is not itself flagged** when both arguments are literal —
  only the non-literal-argument case is in scope here (the function's *removal* in PHP 8 is a
  portability concern, not this guard's job).

## What this guard does NOT prove

A clean scan means no `eval()`/`assert()`/`create_function()`/backtick call-site in the scanned PHP
source was found with a structurally non-literal argument — it says nothing about a genuinely
tainted call this guard's `$variable`-is-enough-to-fire policy should have caught but didn't (a
comment-stripping edge case, a heredoc argument, a dependency's own internal use), and nothing about
whether an argument that DID fire is actually attacker-reachable (that judgment is exactly what the
pragma exists for).

## Canary plant

`CodeInject.php` — `eval($_GET['code'])` inside a function body, no pragma. Expected rule:
`php-code-injection/eval-tainted-arg`.

# Examples

See "What counts as a hit" above for the full fire/silent matrix.

# Citations

[1] agentsec checklist item `3b-eval-exec-injection` (§3b)
[2] OWASP:A03 (Injection), ASVS:1.3.2
[3] CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code / Eval Injection)
[4] PHP manual, `eval()`, `assert()` (`zend.assertions`, deprecated PHP 7.2 / behavior changed
    PHP 8.0), `create_function()` (deprecated PHP 7.2, removed PHP 8.0), and the backtick
    operator (execution operator, equivalent to `shell_exec()`)
[5] graudit (`wireghoul/graudit`) — `signatures/php.db` (provenance for the eval/assert/
    create_function/backtick sink grouping; detection logic here is original)
[6] agentsec's own `code-injection-eval-exec` (Python) and `js-code-injection` (JS/Node) guards —
    the same checklist item, sibling language surfaces
