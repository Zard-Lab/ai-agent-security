"""Guard: NoSQL query filter built from unvalidated request input (checklist §3b-nosql-injection).

The JS/Node counterpart to agentsec's existing (Python-only) `nosql-metadata-injection` guard —
same requirement (a MongoDB query letting user input reach a query operator is CWE-943), a
genuinely different vulnerable shape on this side, so it extends the same `3b-nosql-injection`
checklist item rather than duplicating it.

`nosql_metadata_injection.py`'s Python-side shape targets a developer who wrote a literal
`$where`/`$regex`/`$ne`/... operator KEY with a dynamic VALUE. The real-world Node incident this
guard is modeled on (Rocket.Chat CVE-2026-30833, GHSL advisory, confirmed against the published
fix) has no such literal operator anywhere in the app's own source: a login/lookup query passes
raw request input straight into a filter VALUE slot with no type check —

    Users.findOne({ username: req.body.username })

— and because Node's JSON body parser accepts arbitrary nested types, an attacker submits
`{"username": {"$regex": ".*"}}` as the request body. Mongo receives that object as the FILTER
VALUE, not a string, and interprets its own `$regex` key as a live query operator the app's source
never wrote — a type-confusion NoSQL injection distinct from (and, per the CVE, more common than)
the literal-operator-in-source shape. This guard targets that class: a Mongoose/MongoDB query
filter whose value is a direct, unvalidated Express request-input reference.

Detection is import-scoped (`mongoose` or `mongodb`, require or ES import — mirrors
`js_sql_injection.py`'s driver-import gate, for the same reason: `.find()`/`.findOne()` are common
method names on unrelated objects, so scanning every JS/TS file unconditionally would false-positive
on non-Mongo code). Within a scanned file's `.find(`/`.findOne(`/`.findOneAndUpdate(`/
`.findOneAndDelete(`/`.updateOne(`/`.updateMany(`/`.deleteOne(`/`.deleteMany(`/`.countDocuments(`
call, the first argument (the filter object) is checked for a raw `req.body.x`/`req.query.x`/
`req.params.x` reference NOT wrapped by a type-coercing call (`String(...)`, `Number(...)`,
`Boolean(...)`, `.toString()`) or a sanitizer (`mongoSanitize(...)`, `sanitize(...)`, `escape(...)`).
A value cast to a plain type can no longer carry a nested `$operator` object, so it is safe
regardless of what the attacker submits.

Fires CRITICAL — matching the real-world impact (CVE-2026-30833 was an authentication-bypass /
data-exfiltration primitive via `$regex`, not a lesser info leak). A reviewed case (a value the
caller has already validated upstream, or a deliberately permissive admin-only query) can suppress
the line with `// security: allow-js-nosql-injection`.

Known accepted false negative (deliberate, matches `js_sql_injection.py`'s own receiver-level
trade-off): the guard scopes to whichever driver/ODM the file imports, not to which specific
identifier is the actual Mongoose model — a file that imports `mongoose` and separately calls an
unrelated object's own `.find()`/`.update()` with raw request input can still false-positive.
Receiver-level dataflow is beyond this single-line heuristic.

CWE-943, OWASP:A03. Gated on `javascript`/`typescript`.
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
    js_anchor_is_code,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-nosql-injection"

# The known Node Mongo driver/ODM packages this guard scopes to, mirroring
# js_sql_injection.py's `_DRIVER_IMPORT` gate for the identical reason: `.find()`/`.update()` are
# common method names on unrelated objects (a search client, a cache, an ORM), so a file is only
# scanned once it imports one of these.
_DRIVER_IMPORT = re.compile(
    r"""require\s*\(\s*['"]mongo(?:ose|db)['"]\s*\)"""
    r"""|from\s+['"]mongo(?:ose|db)['"]"""
)

# `.find(`/`.findOne(`/... called on SOME object — the leading `.` requires a method call on a
# receiver, not a bare/unrelated function of the same name.
_CALL = re.compile(
    r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\("
)

# A raw Express request-input reference: `req.body.x` / `req.query.x` / `req.params.x`, or the
# bracket form `req.body['x']`/`req.body["x"]`.
_RAW_REQ_INPUT = re.compile(
    r"\breq\.(?:body|query|params)\.[A-Za-z_$][\w$]*|\breq\.(?:body|query|params)\s*\[\s*['\"]"
)

# A type-coercing call or sanitizer immediately WRAPPING the request-input reference — the value
# can no longer carry a nested `$operator` object once cast to a plain type. Checked against the
# text immediately preceding the match, not the whole line, so an unrelated earlier cast on a
# different key in the same filter object does not clear this one (mirrors
# nosql_metadata_injection.py's own per-operator, not per-line, precision).
_SAFE_CAST = re.compile(r"(?:String|Number|Boolean|mongoSanitize|sanitize|escape)\s*\($")


def _first_arg(line: str, open_paren: int) -> str:
    """The first positional argument of the call whose `(` is at `open_paren`.

    Bracket- and quote-aware: stops at a depth-0 comma or the call's own closing `)`, so a
    SEPARATE options-object argument (`db.updateOne(filter, update)`) never leaks into the check.
    Ported from js_sql_injection.py's identical extractor."""
    rest = line[open_paren + 1 :]
    depth = 0
    quote: str | None = None
    i = 0
    n = len(rest)
    while i < n:
        ch = rest[i]
        if quote is not None:
            if ch == "\\":
                i += 2  # skip the escaped char
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:i]  # the call's own closing paren
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:i]
        i += 1
    return rest


def _has_unguarded_request_input(arg: str) -> bool:
    """True if `arg` (a query filter's first-argument text) contains a raw request-input
    reference not wrapped by a type-coercing call or sanitizer."""
    return any(
        not _SAFE_CAST.search(arg[: m.start()])
        for m in _RAW_REQ_INPUT.finditer(arg)
    )


class NoSqlInjectionJsGuard(Guard):
    id = "nosql-injection-js"
    title = "NoSQL query filter built from unvalidated request input (Node/Mongoose)"
    area = "Code safety"

    # nosql_query.js: imports mongoose, then a filter passing req.body.username straight through
    # with no type cast -> fires nosql-injection-js.
    canary_plant = CanaryPlant(
        files={
            "nosql_query.js": (
                "const mongoose = require('mongoose');\n"
                "app.post('/login', (req, res) => {\n"
                "  Users.findOne({ username: req.body.username });\n"
                "});\n"
            ),
        },
        expects=frozenset({"nosql-injection-js/unvalidated-filter-value"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            if not _DRIVER_IMPORT.search(text):
                continue
            # strip_js_comments blanks a trailing `// ...` comment too (not just a whole-line
            # one), string/regex-literal aware — mirrors js_sql_injection.py's same reasoning.
            stripped = strip_js_comments(text)
            # The anchor mask (#749) drops a `.findOne(` that only appears inside a string (a docs
            # example, an error message), while a real call in a `${...}` substitution stays code.
            # The filter argument is still read from the strings-intact `line`, so the bracket form
            # `req.body['x']` and a `$where` template keep their quoted text.
            masked = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
            lines = zip(stripped.splitlines(), masked.splitlines(), strict=True)
            for i, (line, mask_line) in enumerate(lines, start=1):
                tainted = any(
                    _has_unguarded_request_input(_first_arg(line, m.end() - 1))
                    for m in _CALL.finditer(line)
                    if js_anchor_is_code(line, mask_line, m.end() - 1)
                )
                if not tainted:
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This MongoDB/Mongoose query filter passes a raw `req.body`/"
                            "`req.query`/`req.params` value straight through with no type "
                            "check. Node's JSON body parser accepts nested objects, so an "
                            "attacker can submit `{\"$regex\": \".*\"}` (or `$ne`/`$gt`/...) "
                            "as the field value — Mongo interprets it as a live query "
                            "operator your source never wrote, bypassing the intended match "
                            "(auth bypass, data exfiltration)."
                        ),
                        remediation=(
                            "Cast the value to a plain type before it reaches the filter — "
                            "`String(req.body.username)` — or validate its type explicitly "
                            "(`typeof x === 'string'`) before use. A value that cannot be an "
                            "object can no longer carry a nested `$operator`. If this value "
                            "is already validated upstream, suppress with "
                            "`// security: allow-js-nosql-injection`."
                        ),
                        rule="nosql-injection-js/unvalidated-filter-value",
                        standards=["OWASP:A03", "CWE-943"],
                    )
                )
        return out
