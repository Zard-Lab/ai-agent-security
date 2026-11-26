"""Guard: a Node database driver is configured with a hardcoded password (checklist §8).

`new Pool({ user: 'app', password: 'Sup3rS3cretPw!' })` (pg), `mysql.createConnection({ password:
'...' })` / `createPool({...})` (mysql, mysql2), `new sql.ConnectionPool({...})` (mssql), and a
literal `postgres://app:secret@host/db` URL all put a live database credential in source control. The
repository, every fork and every build artifact then carries it, and rotating it means a code change.

Mined from eslint-plugin-security-rules' `no-hardcoded-credentials` rules (pg, mysql), which flag a
non-empty literal `password` property on a `Pool`/`Client`/`createConnection`/`createPool` config and
treat empty and `test`-prefixed values as safe. The generic secret guards here are provider-prefix
based (`hardcoded-llm-provider-key`, `client-side-secret-literal`) and `mcp-hardcoded-credential` only
runs on MCP servers, so a plain Express or Next.js service with a literal DB password was invisible.

Two rules:

  * **`driver-config-literal-password`** — a `password` property whose value is a plain string
    literal inside the object argument of `new Pool/Client/ConnectionPool(...)`,
    `createConnection(...)` or `createPool(...)`.
  * **`connection-url-embedded-password`** — a `postgres://`, `postgresql://`, `mysql://`,
    `mysql2://`, `mssql://` or `sqlserver://` URL literal with `user:password@` embedded.

A file is scanned only if it imports one of the drivers (`pg`, `pg-promise`, `mysql`, `mysql2`,
`mssql`), the same import gate `js-sql-injection` uses, so a `Client` from an unrelated SDK is never
read. Silent for: `process.env` / `config.x` / any non-literal value, an empty string, a value under
four characters, template literals with `${}` substitutions, placeholders (`changeme`, `your-...`,
`<...>`, `xxx`, `test...`, `example`, `dummy`, `password`, `secret`) and the stock local-dev
passwords (`postgres`, `root`, `admin`, `mysql`), and test, fixture, example and mock paths. A reviewed
case is suppressed with `// security: allow-node-db-driver-hardcoded-password`.

CWE-798, OWASP:A02. Gated on `javascript`/`typescript`. HIGH: the credential is live in source.
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
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_PRAGMA = "security: allow-node-db-driver-hardcoded-password"

_DRIVER_IMPORT = re.compile(
    r"""require\s*\(\s*['"](?:mysql2?(?:/promise)?|pg|pg-promise|mssql)['"]\s*\)"""
    r"""|from\s+['"](?:mysql2?(?:/promise)?|pg|pg-promise|mssql)['"]"""
)

# The constructors / factories whose first argument is the connection config object.
_CONFIG_CALL = re.compile(
    r"\bnew\s+(?:[\w$]+\.)?(?:Pool|Client|ConnectionPool)\s*\(\s*\{"
    r"|\b(?:createConnection|createPool)\s*\(\s*\{"
)
_PASSWORD_PROP = re.compile(
    r"""(?<![\w$.])["']?password["']?\s*:\s*(["'`])((?:\\.|(?!\1)[^\\\n])*)\1""", re.IGNORECASE
)
_URL_PASSWORD = re.compile(
    r"""(?:postgres(?:ql)?|mysql2?|mssql|sqlserver)://[^:/@\s'"`$]+:([^@\s'"`/]+)@""", re.IGNORECASE
)

# Values that are not a real secret: a placeholder, a template hole, a stock local-dev password.
_NOT_A_SECRET = re.compile(
    r"^(?:test.*|change[-_ ]?me.*|your[-_ ].*|<.*>|\[.*\]|\{.*\}|x{3,}.*|\*+|example.*|dummy.*|fake.*"
    r"|todo.*|placeholder.*|password|passwd|pass|secret|postgres|root|admin|mysql|redacted.*|\.\.\.)$",
    re.IGNORECASE,
)
_MIN_LENGTH = 4


def _is_secret(value: str) -> bool:
    value = value.strip()
    if len(value) < _MIN_LENGTH or "${" in value or "%s" in value or "{{" in value:
        return False
    return _NOT_A_SECRET.match(value) is None


def _balanced_body(mask: str, brace: int) -> int:
    """Index of the `}` closing the `{` at `brace` on the string-blanked mask, or -1."""
    depth = 0
    for i in range(brace, min(len(mask), brace + 6000)):
        if mask[i] == "{":
            depth += 1
        elif mask[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _start(m: re.Match[str]) -> int:
    return m.start()


class NodeDbDriverHardcodedPasswordGuard(Guard):
    id = "node-db-driver-hardcoded-password"
    title = "Node DB driver configured with a hardcoded password"
    area = "Secrets"

    # node_db_hardcoded_password.js: pg Pool with a literal password, plus a postgres:// URL with
    # an embedded password -> fires both rules.
    canary_plant = CanaryPlant(
        files={
            "node_db_hardcoded_password.js": (
                "const { Pool } = require('pg');\n"
                "const pool = new Pool({ user: 'app', host: 'db', password: 'Sup3rS3cretPw!' });\n"
                "const url = 'postgres://app:Sup3rS3cretPw@db:5432/app';\n"
            ),
        },
        expects=frozenset({
            "node-db-driver-hardcoded-password/driver-config-literal-password",
            "node-db-driver-hardcoded-password/connection-url-embedded-password",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments, credential_scan=True):
                continue
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="js") or not _DRIVER_IMPORT.search(raw):
                continue
            text = strip_js_comments(raw)
            mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
            for line in self._config_password_lines(text, mask):
                out.append(self._finding(root, f, line, "driver-config-literal-password",
                    "Database driver config has a hardcoded password",
                    "A database connection config passes the password as a string literal, so "
                    "the credential lives in source control, every clone and every build.",
                    "Read the password from the environment or a secret manager "
                    "(`password: process.env.DB_PASSWORD`) and rotate the exposed one."))
            for line in self._url_password_lines(text):
                out.append(self._finding(root, f, line, "connection-url-embedded-password",
                    "Database connection URL embeds a password",
                    "A database URL literal carries `user:password@`, so the credential lives in "
                    "source control, every clone and every build.",
                    "Build the URL from environment variables (`process.env.DATABASE_URL`) and "
                    "rotate the exposed password."))
        return out

    @staticmethod
    def _config_password_lines(text: str, mask: str) -> list[int]:
        lines: list[int] = []
        for call in js_code_matches(_CONFIG_CALL, text, mask, anchor=_start):
            brace = call.end() - 1
            end = _balanced_body(mask, brace)
            if end < 0:
                continue
            body = text[brace:end]
            body_mask = mask[brace:end]
            for pm in js_code_matches(_PASSWORD_PROP, body, body_mask, anchor=_start, literal_ok=True):
                if _is_secret(pm.group(2)):
                    lines.append(text.count("\n", 0, brace + pm.start()) + 1)
        return lines

    @staticmethod
    def _url_password_lines(text: str) -> list[int]:
        return [
            text.count("\n", 0, m.start()) + 1
            for m in _URL_PASSWORD.finditer(text)
            if _is_secret(m.group(1))
        ]

    def _finding(
        self, root: Path, f: Path, line: int, rule: str, title: str, message: str, remediation: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=remediation + " If reviewed, suppress with "
            "`// security: allow-node-db-driver-hardcoded-password`.",
            rule=f"{self.id}/{rule}",
            standards=["OWASP:A02", "CWE-798"],
        )
