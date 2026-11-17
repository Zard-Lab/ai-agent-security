"""Guard: a secret read directly from the environment is nested inside a logging call
(checklist §10 — Logging & Monitoring; inspired by Bearer's environment-variable taint tracking).

Bearer (`Bearer/bearer`, `pkg/detectors/python/python.go::environmentVariableQuery`) tags
EVERY `os.environ[...]` / `os.environ.get(...)` / `os.getenv(...)` read as tainted
"environment" data and then tracks that taint through its generic dataflow engine to
any sink — a log call, an HTTP request, a data store. agentsec has no dataflow engine,
so this guard narrows the same underlying concept to one high-value, statically
detectable sink: the secret is read and logged **on the same line, in the same call**.

This is a genuinely different blind spot from the existing `sensitive-logging` guard.
`sensitive-logging` looks for a sensitive **field name** in the logged argument text, but
it strips string literals before matching (`_code_view`) so the sensitive name in a
message stays silent. That stripping has a side effect: it also erases the secret-sounding
KEY NAME passed as a string-literal argument to `os.getenv(...)`/`os.environ.get(...)`,
so a direct pass-through like:

    logger.info(os.getenv("DB_PASSWORD"))
    print(os.environ["OPENAI_API_KEY"])

is NOT caught by `sensitive-logging` — the literal `"DB_PASSWORD"` is stripped as a string
literal before the sensitive-field regex ever runs, and there is no separately-named
variable for the field-name check to catch. `env-secret-in-prompt` is the closest existing
guard to catching an `os.environ`/`os.getenv` read, but it only fires when the profile has
`llm` AND the line is an f-string — it does not cover the plain `logger.info(os.getenv(...))`
call (no f-string) or non-LLM stacks.

One statically detectable pattern:

  **`direct-log-sink`** (HIGH): A Python line containing a logging call
  (`logger.<level>(`, `logging.<level>(`, or `print(`) where, AFTER the call's opening
  parenthesis, an `os.environ.get(...)`/`os.getenv(...)`/`os.environ[...]` read appears
  whose key-name string literal matches a secret-sounding pattern (KEY, SECRET, PASSWORD,
  TOKEN, PASS, CRED, PRIVATE, AUTH).

**Why HIGH?** The secret's actual VALUE (not just a field name) is written verbatim to the
log stream on every call — no redaction, no field-name heuristic needed. Logs are shipped to
aggregators, retained for months, and read by people without secret-access rights.

**False-negative scope (documented, matches sibling guards' style):**
  - Two-line patterns (`token = os.getenv("API_KEY"); logger.info(token)`) are not caught —
    dataflow analysis beyond this guard's line-level scope.
  - Aliased imports (`from os import getenv; print(getenv("SECRET"))`) are not caught —
    only the `os.getenv`/`os.environ` spelling is matched, mirroring `env-secret-in-prompt`.

**Checklist item:** extends `10-no-sensitive-data-in-logs` (currently `covered` via
`sensitive-logging` alone) with a second, narrower check_id.

**Suppress:** `# security: allow-env-secret-logged` anywhere in a file silences this
check for that file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-env-secret-logged"

_STANDARDS = ["OWASP:A09", "OWASP:A02"]

# A logging or print call: `logger.<level>(`, `logging.<level>(`, `log.<level>(`,
# `self.logger.<level>(`, aliases ending in `log`/`logger`, or a bare `print(`.
_LOG_CALL = re.compile(
    r"(?:\bprint\s*\("
    # `logging.<level>(` (the stdlib module's convenience functions, no `logger =` alias),
    # `get_logger(...).<level>(`, or any name ending in log/logger. `\blogging\b` is listed
    # explicitly because "logging" does not end in "log"/"logger" (PR #397 review #2).
    r"|(?:\bget_?logger\s*\([^)]*\)|\blogging\b|\b[\w.]*log(?:ger)?)"
    r"\.(?:debug|info|warning|warn|error|critical|exception|log)\s*\()",
    re.IGNORECASE,
)

# A direct env-secret read: os.environ.get(...)/os.getenv(...) with a secret-sounding key,
# or an os.environ[...] subscript with a secret-sounding key. The secret-sounding word must
# be a whole `_`/`.`-delimited SEGMENT of the env-var name, so a substring like TOKEN inside
# MAX_TOKENS (a token-count config, not a secret), PASS inside BYPASS_CACHE, or KEY inside
# MONKEY does NOT false-fire (PR #397 review #1).
# The secret word must be a whole `_`/`.`-delimited SEGMENT, which is what keeps `TOKEN` out of
# `MAX_TOKENS`, `PASS` out of `BYPASS_CACHE` and `KEY` out of `MONKEY` (#423). That also missed
# the FUSED and PLURAL spellings `SENDGRID_APIKEY` and `AWS_SECRETS` (#445 review), so those are
# added as explicit alternatives.
#
# Deliberately NOT generalised to "segment ends with a secret word" or "any plural": `MONKEY`
# ends with KEY, and `MAX_TOKENS` is `TOKEN` + plural — structurally identical to `AWS_SECRETS`,
# and ubiquitous in LLM code. There is no way to admit `TOKENS` without re-admitting `MAX_TOKENS`,
# so the plural is allowed only for words whose plural is not itself a common non-secret term
# (`SECRETS`, `PASSWORDS`, `CREDS`) and `APIKEY` is spelled out rather than inferred.
_SECRET_WORD = r"(?:APIKEYS?|KEY|SECRETS?|PASSWORDS?|TOKEN|PASS|CREDS?|PRIVATE|AUTH)"  # nosec B105 (detection pattern, not a credential)

# Issue #986: the prefix/suffix segment groups below are UNBOUNDED (`*`), so an unterminated
# name (no closing quote/bracket found anywhere in the file — the reachable shape, since a real
# `os.getenv(...)` call is always on one line but the closing quote can be attacker-omitted) lets
# the engine retry every split between "prefix segment count" and "suffix segment count" before
# giving up: O(N^2) (measured 0.6s at 2000 segments, growing x4 per doubling). Bounding both
# repeats to `{0,20}` fixes it — no real env-var name is anywhere near 20 `_`/`.`-delimited
# segments, so this costs no true positive, and it turns the worst case into a small constant
# per `.search()` starting position regardless of how long a hostile line is.
_SNAKE_SECRET_NAME = rf"(?:[A-Za-z0-9]+[_.]){{0,20}}{_SECRET_WORD}(?:[_.][A-Za-z0-9]+){{0,20}}"

# Issue #987: `re.IGNORECASE` (needed so the snake-case alternative above matches lower/upper
# indifferently) erases the lower-to-upper transition camelCase segmentation depends on
# entirely, so `dbPassword`/`authToken`/`clientSecret`/`awsSecretKey` never matched as camelCase
# — only `apiKey` matched, and only because `APIKEY` is spelled as one fused word in
# `_SECRET_WORD` already. `(?-i:...)` locally disables case-folding for this branch only, so
# segmentation is genuine: a segment is an initial lowercase run or a capital-led run, matched
# WHOLE (never a substring) against `_CAMEL_SECRET_WORD`, as `_SNAKE_SECRET_NAME` matches its
# `_`/`.` segments whole — `Tokens`/`Bypass`/`Monkey`/`Author` as whole segments never equal
# `Token`/`Pass`/`Key`/`Auth`, so `maxTokens`/`bypassCache`/`monkeyPatch`/`authorName` stay silent
# exactly like their snake-case counterparts already do.
#
# One deliberate difference from the snake branch: `_CAMEL_SECRET_WORD` is capital-led only, so the
# secret word is never the LEADING lowercase segment. `secretArn`/`tokenValue`/`authHeader` stay
# silent while `SECRET_ARN`/`TOKEN_VALUE`/`AUTH_HEADER` fire (a known miss), and in exchange
# `keyCount`/`passThrough` stay silent where their snake twins `KEY_COUNT`/`PASS_THROUGH` are false
# positives. A bare one-word name (`secret`, `token`) still fires through the snake branch. Admitting
# the leading segment would import those snake-branch false positives into camelCase; pinned by
# `test_env_secret_logged_camelcase_leading_lowercase_secret_word_is_a_known_miss`.
#
# Each segment is wrapped in an ATOMIC group `(?>...)`: once a segment's greedy `[a-z0-9]*` tail
# commits, it can never give characters back to try a different split with the next segment.
# Without this, a bounded `{0,20}` outer repeat count still exploded combinatorially (measured
# ~24s, roughly CONSTANT regardless of input size, not even growing with N — each of up to 20
# segments has its own internal split freedom, and 20 segments' worth of freedom compounds
# exponentially even though the repeat COUNT itself is bounded). The atomic group removes that
# per-segment freedom; only the bounded repeat COUNT remains as a choice point, which is O(20)
# per starting position, not exponential.
_CAMEL_SECRET_WORD = r"(?:ApiKeys?|Key|Secrets?|Passwords?|Token|Pass|Creds?|Private|Auth)"  # nosec B105 (detection pattern, not a credential)
_CAMEL_SEG = r"(?:(?>[A-Z][a-z0-9]*)|(?>[a-z][a-z0-9]*))"
_CAMEL_SECRET_NAME = rf"(?-i:{_CAMEL_SEG}{{0,20}}{_CAMEL_SECRET_WORD}(?>[A-Z][a-z0-9]*){{0,20}})"

_SECRET_NAME = rf"(?:{_SNAKE_SECRET_NAME}|{_CAMEL_SECRET_NAME})"
_ENV_SECRET_ACCESS = re.compile(
    rf"""(?:os\.environ\.get|os\.getenv)\s*\(\s*['"]{_SECRET_NAME}['"]"""
    rf"""|os\.environ\s*\[\s*['"]{_SECRET_NAME}['"]\s*\]""",
    re.IGNORECASE,
)


class EnvSecretLoggedGuard(Guard):
    id = "env-secret-logged"
    title = "Environment secret read directly inside a logging call"
    area = "Logging"

    # fires env-secret-logged/direct-log-sink (research batch: bearer, 2026-07-12) — an
    # env-var secret read directly inside a logging call, same physical line.
    canary_plant = CanaryPlant(
        files={
            "startup_diagnostics.py": (
                "import logging\n"
                "import os\n"
                "\n"
                "\n"
                "def log_startup_config() -> None:\n"
                '    logging.getLogger("startup").info(os.getenv("DB_PASSWORD"))\n'
            ),
        },
        expects=frozenset({"env-secret-logged/direct-log-sink"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Blank triple-quoted docstring/template CONTENT so an anti-pattern EXAMPLE in a
        # docstring (this guard's own module docstring self-matches, issue #424) doesn't fire.
        # Single-line string literals are left intact, so the env-secret key-name match
        # still works on real code.
        for lineno, line in enumerate(strip_python_strings(text, filename=path).splitlines(), 1):
            m = _LOG_CALL.search(line)
            if not m:
                continue
            # The env-secret read must appear AFTER the log/print call's opening
            # parenthesis, so an unrelated env read earlier on the same physical
            # line (e.g. `key = os.getenv("API_KEY"); logger.info("done")`) does
            # not fire.
            rest = line[m.end():]
            if not _ENV_SECRET_ACCESS.search(rest):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, path)}:{lineno}",
                    message=(
                        "A secret is read directly from the environment "
                        "(`os.environ`/`os.getenv`, keyed by a secret-sounding name) "
                        "and passed straight into a logging/print call. The secret's "
                        "actual VALUE — not just its field name — is written verbatim "
                        "to the log stream on every call, with no redaction step."
                    ),
                    remediation=(
                        "Never pass an environment secret read directly to a log/print "
                        "call. Read it into a named variable once at startup and use it "
                        "only where required (e.g. an SDK's auth parameter), or log a "
                        "boolean presence check instead: `logger.info('key present: %s', "
                        "bool(os.getenv(\"API_KEY\")))`. Suppress with "
                        f"`# {_PRAGMA}` only after confirming the log destination is "
                        "not persisted/shipped anywhere."
                    ),
                    rule="env-secret-logged/direct-log-sink",
                    standards=list(_STANDARDS),
                )
            )
        return out
