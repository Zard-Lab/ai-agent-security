"""Guard: no NoSQL operator injection (checklist §3b).

A MongoDB query that lets user input reach a query **operator** is NoSQL injection
(CWE-943): `{"$where": user}` runs attacker JavaScript on the database; a `$regex`
/ `$ne` / `$gt` built from request input rewrites the query logic (auth bypass,
data exfiltration). The fix is to validate/cast inputs to plain values and never
let a `$`-operator come from user data.

Self-gating to avoid false positives on the SQL/Postgres stack: only files that use
pymongo/motor (or contain a `$where`/`$regex` query) are scanned. Fires HIGH on a
`$where` (always JS-exec) or a `$`-operator whose value is an f-string / variable /
concatenation. Suppress with `# security: allow-nosql-operator` on the line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, python_scan_dirs, read, rel

_USES_MONGO = re.compile(r"\b(?:import\s+pymongo|from\s+pymongo|import\s+motor|from\s+motor)\b|\$where|\$regex")
_WHERE = re.compile(r'["\']\$where["\']\s*:')
# A $-operator key, up to and including the `:` + whitespace before its value.
_OP_KEY = re.compile(
    r'["\']\$(?:where|regex|ne|gt|lt|gte|lte|in|nin|expr|function)["\']\s*:\s*'
)
# An f-string value (dynamic): `f"`, `F'`, `rf"`, `fr'`… but NOT a plain raw string.
_FSTR = re.compile(r'[fF][rRbB]?["\']|[rRbB][fF]["\']')
# A single-line string literal WITH its optional r/b/u prefix (dropped so a `+`/identifier
# INSIDE a literal is not read as code).
_STR_LITERAL = re.compile(r'[rRbBuU]{0,2}(?:"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\')')
# A bare-variable value: a Python identifier that is NOT a None/True/False literal.
_BARE_VAR = re.compile(r'\b(?!(?:None|True|False)\b)[A-Za-z_]\w*')
_PRAGMA = re.compile(r"#\s*security:\s*allow-nosql-operator")


def _op_value(after_colon: str) -> str:
    """The operator's value token: text up to the first top-level `,` `}` `)` `]`.

    Bounds the classification to THIS operator's value so a dynamic value on a later,
    unrelated key in the same dict literal is not attributed to the operator. Quote-aware:
    a `,` (or bracket) INSIDE a string literal does not terminate the value, so
    `{"$regex": "foo,bar"}` is kept whole rather than truncated mid-string (PR #444 review)."""
    depth = 0
    quote: str | None = None
    j = 0
    while j < len(after_colon):
        ch = after_colon[j]
        if quote is not None:
            if ch == "\\":
                j += 2  # skip the escaped char
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return after_colon[:j]
            depth -= 1
        elif ch == "," and depth == 0:
            return after_colon[:j]
        j += 1
    return after_colon


def _value_is_dynamic(value: str) -> bool:
    """True iff a $-operator value is dynamic (f-string, bare variable, or a real
    concatenation) rather than a static literal.

    Fixes three FP shapes (#423): `{"$ne": None}` (a None/True/False literal is not a
    variable), `{"$regex": r"^a$"}` (a raw string is static, not an f-string), and
    `{"$regex": "C++"}` (a `+` INSIDE a string literal is not a concatenation)."""
    # The f-string test must run at the START of the value, not anywhere inside it. `_FSTR`
    # matches a prefix letter followed by a quote, so unanchored it also matched the `f"`
    # sequence formed by the LAST character of a static string and the quote that closes it:
    # `{"$regex": "\\.pdf"}`, `{"$ne": "staff"}`, `{"$regex": "^conf"}` and
    # `{"$in": ["pdf","doc"]}` each drew a HIGH (#444 review). An f-string prefix can only sit
    # where the literal begins.
    if _FSTR.match(value.lstrip()):
        return True
    code = _STR_LITERAL.sub("", value)  # drop string literals (incl. r/b/u prefixes)
    if "+" in code:  # a `+` that survived blanking is a real (code-level) concat
        return True
    return bool(_BARE_VAR.search(code))


class NoSqlMetadataInjectionGuard(Guard):
    id = "nosql-metadata-injection"
    title = "No NoSQL operator injection (Mongo $-operators from user input)"
    area = "Code safety"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # mongo.py: pymongo $where with a variable -> fires nosql-metadata-injection.
    canary_plant = CanaryPlant(
        files={
            "mongo.py": (
                "from pymongo import MongoClient  # noqa: F401\n\n\n"
                "def find(db, user):\n    return db.users.find({\"$where\": user})\n"
            ),
        },
        expects=frozenset({"nosql-metadata-injection/dynamic-operator"}),
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
                if not _USES_MONGO.search(text):
                    continue
                # The pragma counts only as a real comment on the line, never quoted in a string
                # there (#1040).
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                for i, line in enumerate(text.splitlines(), start=1):
                    if line.lstrip().startswith("#") or i in pragmas:
                        continue
                    dyn_op = any(
                        _value_is_dynamic(_op_value(line[km.end():]))
                        for km in _OP_KEY.finditer(line)
                    )
                    if _WHERE.search(line) or dyn_op:
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title="NoSQL query operator built from untrusted input",
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "A MongoDB query operator here takes dynamic/user input — `$where` "
                                    "runs attacker JavaScript on the DB, and a dynamic `$regex`/`$ne` "
                                    "rewrites the query (auth bypass, data exfiltration)."
                                ),
                                remediation=(
                                    "Validate and cast inputs to plain values; never let a `$`-operator "
                                    "come from user data, and avoid `$where` entirely. Suppress an "
                                    "audited case with `# security: allow-nosql-operator`."
                                ),
                                rule="nosql-metadata-injection/dynamic-operator",
                                standards=["OWASP:A03"],
                            )
                        )
        return out
