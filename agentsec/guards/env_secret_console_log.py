"""Guard: a secret read directly from `process.env` is nested inside a `console.*` call
(checklist §10 — Logging & Monitoring; JS/TS analogue of `env-secret-logged`, inspired by
Bearer's environment-variable taint tracking).

Bearer (`Bearer/bearer`, `pkg/detectors/javascript/javascript.go::environmentVariableQuery`)
tags every `process.env.X` / `process.env["X"]` read as tainted "environment" data and
tracks that taint through its generic dataflow engine to any sink. agentsec has no
dataflow engine, so this guard narrows the same concept to one high-value, statically
detectable sink: the secret is read and printed to the browser/Node console **on the same
line, in the same call**.

Distinct from existing frontend guards:

  - `vite-client-secret` only scans `.env*` FILES for a `VITE_`-prefixed secret name — it
    never looks at application SOURCE CODE, so it does not see a `console.log` call at all.
  - `token-in-localstorage` matches `localStorage`/`sessionStorage.setItem(...)`, an
    unrelated sink.
  - No existing guard scans for `console.*` calls at all.

A `console.log(process.env.STRIPE_SECRET_KEY)` in application code ships the secret's
actual VALUE to:

  - The browser DevTools console (if this code runs client-side, e.g. a misconfigured
    Next.js/webpack build that inlines a server-only env var into a client bundle) —
    readable by anyone with the page open.
  - Server-side Node console output, which is very commonly captured by process managers
    (pm2, systemd journal), container log drivers, and error-monitoring SDKs that patch
    `console.*` to forward output (Sentry, LogRocket, Datadog RUM) for session replay.

One statically detectable pattern:

  **`direct-console-sink`** (HIGH): A .js/.jsx/.ts/.tsx line containing a console call
  (`console.log/debug/info/warn/error(`) where, AFTER the call's opening parenthesis, a
  `process.env.X` or `process.env["X"]` read appears whose key name has a secret-sounding
  segment (KEY, APIKEY(S), SECRET(S), PASSWORD(S), TOKEN, PASS, CRED(S), PRIVATE, AUTH) —
  the same name pattern `env-secret-logged` uses, imported from it.

**When NOT to flag:** Logging only a boolean PRESENCE check does not leak the secret's
value, so a read immediately coerced to boolean is excluded:

    console.log(!!process.env.API_KEY)               // silent — presence only
    console.log(Boolean(process.env.API_KEY))         // silent — presence only
    console.log(typeof process.env.API_KEY)            // silent — reveals only the JS type

**Why HIGH?** The secret's actual value — not just a field name or a boolean — is written
verbatim to a console sink that is routinely captured by log drivers, process managers, and
session-replay tooling, with no redaction step.

**False-negative scope (documented, matches sibling guards' style):**
  - Two-line patterns (`const k = process.env.API_KEY; console.log(k)`) are not caught —
    dataflow analysis beyond this guard's line-level scope.
  - Destructured access (`const { API_KEY } = process.env; console.log(API_KEY)`) is not
    caught for the same reason.
  - Wrapping the read in a helper function (`console.log(getSecret())`) bypasses detection.

**Checklist item:** extends `10-no-sensitive-data-in-logs` (currently `covered` via
`sensitive-logging`, a Python-only guard) with a JS/TS check_id.

**Suppress:** `// security: allow-env-secret-console-log` anywhere in a file silences this
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
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)
from .env_secret_logged import _SECRET_NAME

_PRAGMA = "security: allow-env-secret-console-log"

_STANDARDS = ["OWASP:A09", "OWASP:A02"]

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# console.log/debug/info/warn/error(
_CONSOLE_CALL = re.compile(r"console\.(?:log|debug|info|warn|error)\s*\(", re.IGNORECASE)

# process.env.SECRET_NAME or process.env["SECRET_NAME"] / process.env['SECRET_NAME'], where
# the key contains a secret-sounding word. `_SECRET_NAME` is shared with `env_secret_logged`
# (#560), so the two siblings cannot drift apart again: the secret word must be a whole
# `_`/`.`-delimited SEGMENT of the env-var name, so TOKEN inside MAX_TOKENS (a token-count
# config, not a secret), PASS inside BYPASS_CACHE, or KEY inside MONKEY does NOT false-fire
# (PR #397 review #1), and the fused/plural spellings `SENDGRID_APIKEY` / `AWS_SECRETS` do
# fire (#445). The Python key is always quoted; here the attribute arm has no closing
# delimiter, so its trailing `\b` plays the closing quote's role: every character that could
# continue a segment is a word character, so `process.env.MAX_TOKENS` cannot match on its
# `TOKEN` prefix. That `\b` is load-bearing.
_ENV_SECRET_ACCESS = re.compile(
    rf"""process\.env\.{_SECRET_NAME}\b"""
    rf"""|process\.env\[\s*['"`]{_SECRET_NAME}['"`]\s*\]""",
    re.IGNORECASE,
)

# Immediately-preceding boolean/type coercion that means only presence (not the secret
# value) reaches the console — `!!process.env.X`, `Boolean(process.env.X)`,
# `typeof process.env.X`.
_SAFE_COERCION_PREFIX = re.compile(r"(?:!!|typeof\s+|Boolean\s*\(\s*)$")


class EnvSecretConsoleLogGuard(Guard):
    id = "env-secret-console-log"
    title = "Environment secret read directly inside a console.* call"
    area = "Logging"

    # frontend/src/analytics.ts: fires env-secret-console-log/direct-console-sink (research
    # batch: bearer, 2026-07-12) — a process.env secret read directly inside a console.* call,
    # same physical line, no boolean/typeof coercion in between.
    canary_plant = CanaryPlant(
        files={
            "frontend/src/analytics.ts": (
                "export function logConfig(): void {\n"
                "  console.log(process.env.VITE_API_SECRET_KEY);\n"
                "}\n"
            ),
        },
        expects=frozenset({"env-secret-console-log/direct-console-sink"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features or "javascript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Blank `//` and `/* */` comments (line numbers preserved) so a commented-out or documented
        # `console.log(process.env.SECRET)` EXAMPLE doesn't fire (issue #424).
        for lineno, line in enumerate(strip_js_comments(text).splitlines(), 1):
            m = _CONSOLE_CALL.search(line)
            if not m:
                continue
            rest = line[m.end():]
            env_m = _ENV_SECRET_ACCESS.search(rest)
            if not env_m:
                continue
            before = rest[: env_m.start()]
            if _SAFE_COERCION_PREFIX.search(before):
                continue  # presence/type check only — the secret value never reaches the sink
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, path)}:{lineno}",
                    message=(
                        "A secret is read directly from `process.env` (keyed by a "
                        "secret-sounding name) and passed straight into a `console.*` "
                        "call. The secret's actual VALUE is written to a console sink "
                        "that is routinely captured by process managers, container log "
                        "drivers, and session-replay/error-monitoring tools that patch "
                        "`console.*` (Sentry, LogRocket, Datadog RUM)."
                    ),
                    remediation=(
                        "Never pass an environment secret read directly to a console "
                        "call. If you need to confirm the variable is set, log only a "
                        "boolean presence check: `console.log(!!process.env.API_KEY)`. "
                        "Suppress with `// security: allow-env-secret-console-log` only "
                        "after confirming the console sink is not captured or persisted "
                        "anywhere."
                    ),
                    rule="env-secret-console-log/direct-console-sink",
                    standards=list(_STANDARDS),
                )
            )
        return out
