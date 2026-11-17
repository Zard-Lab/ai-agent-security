"""Guard: bulk enumeration of all environment variables (checklist §7).

    for name, value in os.environ.items():
        send_to_remote(name, value)

Iterating the ENTIRE environment (rather than reading one named variable) is a
strong signal of secret harvesting: a typical application reads `DATABASE_URL` or
`API_KEY` by name, but has no legitimate reason to enumerate every environment
variable it has — API keys, database URLs, and internal tokens for services that
have nothing to do with the code doing the enumerating are all swept up together.
This is the SkillSpector project's E2 category ("Env Variable Harvesting"), applied
to application/agent-tool code generally. CWE-200 (Exposure of Sensitive
Information), OWASP:A02.

Fires HIGH on:

  * `for ... in os.environ.items()` — iterating every variable;
  * JavaScript/TypeScript's `Object.keys(process.env)` — enumerating every variable
    name (the equivalent full-environment-exposure signal in Node).

**Deliberately does NOT fire on a *filtered* comprehension** — e.g.
`{k: v for k, v in os.environ.items() if k.startswith("MYAPP_")}`, which reads a
namespaced *subset* of the environment (a common, benign config idiom), not every
variable. Only the comprehension form (where `for` is not the leading token of the line)
is carved out. A `for`-loop **statement** (`for k, v in os.environ.items(): ...`)
enumerates every variable regardless of any conditional in its body — a trailing ternary
like `send(v if v else "")` is not a key filter — so it always fires HIGH, as does an
unfiltered comprehension.

**Deliberately does NOT fire on bare `os.environ.copy()` / `dict(os.environ)`** —
an earlier version of this guard did, and it false-positived on a genuinely benign,
common idiom found in this project's own `net.py`: making a local immutable copy of
the environment to safely read a *few* specific named keys (`environ.get("X")`),
which is functionally equivalent to reading named variables, not harvesting all of
them. Only explicit iteration/enumeration (`.items()`, `Object.keys(...)`) is an
unambiguous signal; a bare copy is not. The existing `mcp-tool-env-inheritance`
guard separately covers `env=os.environ.copy()`/`env=dict(os.environ)` used as a
subprocess/MCP-server launch's `env=` keyword argument — a different, genuinely
dangerous shape (the full environment passed through to a child process) that this
guard does not overlap with.

Suppress an audited case (e.g. a diagnostics/support-bundle tool that legitimately
dumps the environment for a support ticket, with the user's explicit action) with
`# security: allow-bulk-env-harvesting` anywhere in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_ENVIRON_ITEMS = re.compile(r"\bos\s*\.\s*environ\s*\.\s*items\s*\(\s*\)")
# A comprehension that iterates `os.environ.items()` but carries an `if` filter clause is
# reading a *bounded* subset (`{k: v for k, v in os.environ.items() if k.startswith("APP_")}`),
# not harvesting the whole environment — a common, benign namespaced-config idiom. Only the
# unfiltered iteration is the harvesting signal, so the filtered comprehension is carved out.
_ENVIRON_ITEMS_FILTERED = re.compile(
    r"\bfor\b.*\bos\s*\.\s*environ\s*\.\s*items\s*\(\s*\).*\bif\b"
)
# ...but the carve-out must NOT catch a `for`-loop STATEMENT — `for k, v in os.environ.items():`
# enumerates every variable regardless of any conditional in its body (a trailing ternary like
# `exfiltrate(v if v else "")` is not a key filter), so a statement loop always fires. Only a
# comprehension (where `for` is not the leading token of the line) is a bounded subset read.
_FOR_STATEMENT = re.compile(r"^\s*(?:async\s+)?for\b")
_JS_ENV_KEYS = re.compile(r"\bObject\s*\.\s*keys\s*\(\s*process\s*\.\s*env\s*\)")
_PRAGMA = re.compile(r"#\s*security:\s*allow-bulk-env-harvesting")

_SUFFIXES = (".py", ".js", ".ts", ".jsx", ".tsx")
_STANDARDS = ["OWASP:A02", "CWE-200"]


class BulkEnvVarHarvestingGuard(Guard):
    id = "bulk-env-var-harvesting"
    title = "Bulk enumeration of all environment variables"
    area = "Secrets"

    # env_dump.py: os.environ.items() iteration -> fires bulk-env-var-harvesting.
    # Must NOT contain: allow-bulk-env-harvesting pragma, or env= on the same line.
    canary_plant = CanaryPlant(
        files={
            "env_dump.py": (
                "for name, value in os.environ.items():\n"
                "    send_to_remote(name, value)\n"
            ),
        },
        expects=frozenset({"bulk-env-var-harvesting/environment-enumeration"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Universal: the Python/JS source this scans (and its env-harvesting signal) can
        # appear in any project regardless of the detected stack — a language-feature gate
        # would silently drop the JS `Object.keys(process.env)` path on a Node-only repo.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return out
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            m = self._match(line)
            if not m:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"This line ({m}) enumerates the ENTIRE environment rather "
                        "than reading a single named variable. Application code "
                        "typically reads a specific variable by name — bulk "
                        "enumeration sweeps up every secret, API key, and internal "
                        "token the process has, regardless of whether they're "
                        "relevant to the code doing the enumerating."
                    ),
                    remediation=(
                        "Read the specific environment variable(s) actually needed by "
                        "name (`os.environ['DATABASE_URL']`) instead of enumerating "
                        "the whole environment. Suppress an audited case (e.g. a "
                        "user-initiated diagnostics/support-bundle tool) with "
                        "`# security: allow-bulk-env-harvesting` anywhere in the file."
                    ),
                    rule="bulk-env-var-harvesting/environment-enumeration",
                    standards=list(_STANDARDS),
                )
            )
        return out

    def _match(self, line: str) -> str | None:
        if _ENVIRON_ITEMS.search(line):
            if _ENVIRON_ITEMS_FILTERED.search(line) and not _FOR_STATEMENT.match(line):
                return None  # filtered comprehension = bounded subset read, not harvesting
            return "os.environ.items()"
        if _JS_ENV_KEYS.search(line):
            return "Object.keys(process.env)"
        return None
