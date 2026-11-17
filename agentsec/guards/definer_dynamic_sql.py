"""Guard: SECURITY DEFINER functions must not EXECUTE arbitrary/dynamic SQL.

A `SECURITY DEFINER` function runs with its **owner's** privileges (often `postgres`),
so Row-Level Security is bypassed inside its body. When such a function then runs
**dynamic SQL built from an argument** — `EXECUTE query`, `RETURN QUERY EXECUTE q`,
`EXECUTE format(...)` — it becomes an *arbitrary-SQL execution primitive*: any caller
that can reach it can read (or write) any table with RLS bypassed and no table
restriction. Reached from an LLM agent tool (a `sql_query: str` tool arg forwarded to
the `execute_custom_sql` RPC), a prompt-injected query exfiltrates data.

This is the DB half of a critical flagship finding (`execute_custom_sql(text)` —
`SECURITY DEFINER` owned by `postgres`, `RETURN QUERY EXECUTE query`). Crucially, the
existing definer guards **do not** catch it:
  - `definer-function-grants` reasons about *who can call it* (unrevoked EXECUTE) and
    goes silent once EXECUTE is revoked to `service_role` — the arbitrary-SQL primitive
    is intact for any reachable caller.
  - `pg-function-search-path` reasons about `search_path` pinning — orthogonal.
Neither inspects the function *body* for a dynamic `EXECUTE`. This guard does.

Detection (DB-independent, comment-stripped, per-`CREATE FUNCTION` block):
  - collect every `CREATE [OR REPLACE] FUNCTION` block that is `SECURITY DEFINER`;
  - flag it if its body runs a **dynamic** `EXECUTE` — `EXECUTE <identifier>` (a
    variable/parameter), `EXECUTE format(...)`, `EXECUTE 'sql ' || …`, or the
    parenthesized `EXECUTE (query)` form, **with or without a space before the paren**
    (`EXECUTE(query)` is equally valid PL/pgSQL — `(` is self-delimiting) — while
    excluding a purely static `EXECUTE 'literal'` (bare or parenthesized:
    `EXECUTE ('literal')`/`EXECUTE('literal')`) and the trigger/grant forms
    (`EXECUTE FUNCTION|PROCEDURE`, `... EXECUTE ON ...`).

Severity is **critical** (arbitrary SQL with the owner's privileges = RLS bypass).
Opt out an audited case (e.g. a function whose dynamic SQL is provably constrained)
with an inline pragma on (or just above) the `CREATE FUNCTION` line:
`-- security: allow-definer-dynamic-sql`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, read, rel, strip_sql_comments

_CREATE_FN = re.compile(r"create\s+(?:or\s+replace\s+)?function\s+(?P<name>[\w\".]+)\s*\(", re.I)
_SEC_DEFINER = re.compile(r"security\s+definer", re.I)
# A DYNAMIC EXECUTE: the EXECUTE keyword followed by a variable/param, format(...), a
# string concatenation, or a parenthesized expression — NOT a static `EXECUTE 'literal'`
# (bare or parenthesized), and not the trigger/grant forms (`EXECUTE FUNCTION|PROCEDURE`,
# `GRANT/REVOKE EXECUTE ON …`).
_EXECUTE_DYNAMIC = re.compile(
    r"\bexecute\b"
    r"(?!\s+function\b|\s+procedure\b|\s+on\b)"  # exclude EXECUTE FUNCTION/PROCEDURE/ON
    r"(?:"
    r"\s+format\s*\("                       # EXECUTE format(...)
    r"|\s+'[^']*'\s*\|\|"                   # EXECUTE 'sql ' || var
    r"|\s*\((?!\s*'[^']*'\s*\))"             # EXECUTE(expr) / EXECUTE (expr) — no space required
                                             #   before the paren; excl. static EXECUTE ('literal')
    r"|\s+[a-z_][\w.]*"                     # EXECUTE <identifier / variable / parameter>
    r")",
    re.I,
)
_PRAGMA = "security: allow-definer-dynamic-sql"
# Opening/closing dollar-quote tag of a function body (`$$` or `$name$`); the same literal
# tag closes it. Postgres requires nested bodies to use *distinct* tags, so the first
# matching tag is the real close.
_DOLLAR = re.compile(r"\$\w*\$")
_STRLIT = re.compile(r"'[^']*'")
# The function BODY opens right after the `AS` keyword: `AS $tag$…$tag$`. Anchor to `AS` so a
# dollar-quoted *parameter default* (`DEFAULT $tag$…$tag$`, valid Postgres) earlier in the
# region is not mistaken for the body. `\bas\s*\$\w*\$` only matches `AS` immediately followed
# by a dollar-tag (not `CAST(x AS text)`, not `alias`), so a single-quoted body yields no match.
_AS_BODY = re.compile(r"\bas\s*(\$\w*\$)", re.I)


def _fn_base(name: str) -> str:
    """Base function name: drop schema qualifier + quotes, lowercase."""
    return name.split(".")[-1].strip('"').lower()


def _blank_string_literals(s: str) -> str:
    """Blank single-quoted literal *contents* so a keyword appearing inside a string
    (e.g. `RAISE EXCEPTION 'cannot execute this'`) is not read as code. Keeps the empty
    quotes so a genuine `EXECUTE '' || v` still matches the concatenation arm."""
    return _STRLIT.sub("''", s)


def _mask_quoted(text: str) -> str:
    """Return a **same-length** copy of `text` with the *content* of every `'…'` string and
    every `$tag$…$tag$` dollar body replaced by spaces (the delimiters — quotes and `$tag$`
    — are kept). This is a single stateful pass, so it is correct where regex is not: plpgsql
    interleaves three quoting contexts (`'…'` with `''` escaping, `$tag$` bodies that hold
    arbitrary text including bare `'` and `$$`, and comments — already stripped upstream), and
    only a stateful scan can tell whether a given `'`, `$$`, `create function`, or `execute`
    is real structure or content. Masking lets the structural regexes (`_CREATE_FN`,
    `_SEC_DEFINER`, `_DOLLAR`) run safely, and because length is preserved the offsets index
    straight back into the original text to recover a body's real content for the EXECUTE scan.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":  # '' escapes a quote inside the literal
                        out[j] = out[j + 1] = " "
                        j += 2
                        continue
                    break  # closing quote
                out[j] = " "
                j += 1
            i = j + 1  # step past the closing quote (or off the end)
        elif ch == "$":
            dm = _DOLLAR.match(text, i)
            if dm is None:
                i += 1
                continue
            tag = dm.group(0)
            close = text.find(tag, i + len(tag))
            body_end = close if close != -1 else n
            for k in range(i + len(tag), body_end):  # blank the body content, keep both $tag$
                out[k] = " "
            i = body_end + len(tag) if close != -1 else n
        else:
            i += 1
    return "".join(out)


def _definer_dynamic_functions(stripped: str) -> set[str]:
    """Base names of `SECURITY DEFINER` functions whose **body** runs a dynamic EXECUTE.

    Structure is resolved on a `_mask_quoted` copy (string/dollar-body *content* spaced out,
    delimiters kept, same length). So `CREATE FUNCTION` / `SECURITY DEFINER` are found only at
    top level (never inside a string or a body), and each function's own `$tag$…$tag$` body is
    delimited correctly regardless of bare apostrophes, `$$`/`create function`/`execute`
    substrings inside strings, or a single-quoted body (no `$tag$` → cleanly skipped). The
    dynamic `EXECUTE` is then scanned in the body's *real* content (sliced from the original at
    the mask's offsets, with its own literals blanked), so a `DO` block or trailing SQL is
    never misattributed. `SECURITY DEFINER` may sit before or after the `AS $tag$…$tag$`.
    """
    out: set[str] = set()
    masked = _mask_quoted(stripped)
    matches = list(_CREATE_FN.finditer(masked))
    for i, m in enumerate(matches):
        region_end = matches[i + 1].start() if i + 1 < len(matches) else len(masked)
        region = masked[m.end():region_end]      # masked: delimiters kept, content spaced
        mb = _AS_BODY.search(region)             # the body opens at `AS $tag$` (not a $-quoted DEFAULT)
        if mb is None:
            continue  # no dollar-quoted body (LANGUAGE sql / single-quoted body): can't EXECUTE dynamically
        tag = mb.group(1)
        body_start = mb.end()
        close = region.find(tag, body_start)
        if close == -1:
            continue
        header = region[:mb.start()]             # params) RETURNS … LANGUAGE … [SECURITY DEFINER] before AS
        attrs = region[close + len(tag):]        # attrs after the body (SECURITY DEFINER may sit here)
        semi = attrs.find(";")
        if semi != -1:
            attrs = attrs[:semi]
        # Body EXECUTE scan uses the ORIGINAL content (same offsets), with its strings blanked.
        abs_start = m.end() + body_start
        abs_end = m.end() + close
        body = _blank_string_literals(stripped[abs_start:abs_end])
        if _SEC_DEFINER.search(header + attrs) and _EXECUTE_DYNAMIC.search(body):
            out.add(_fn_base(m.group("name")))
    return out


def _pragma_allowed(raw: str) -> set[str]:
    """Functions whose CREATE line (or the line above) carries the allow pragma."""
    allowed: set[str] = set()
    pragma_lines = pragma_line_set(_PRAGMA, raw, dialect="sql")  # 1-based lines whose COMMENT carries it (#424)
    for i, line in enumerate(raw.splitlines()):
        m = _CREATE_FN.search(line)
        if m and (i + 1 in pragma_lines or i in pragma_lines):  # this line, or the one above it
            allowed.add(_fn_base(m.group("name")))
    return allowed


class DefinerDynamicSqlGuard(Guard):
    id = "definer-dynamic-sql"
    title = "SECURITY DEFINER function executes arbitrary/dynamic SQL"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # sql/definer_dynamic.sql: a SECURITY DEFINER function that runs `RETURN QUERY EXECUTE
    # query` (argument-derived dynamic SQL) -> fires definer-dynamic-sql/dynamic-execute.
    # Deliberately HARDENED on the other definer axes so ONLY this guard fires (exactly the
    # flagship `execute_custom_sql` shape): search_path is pinned (no pg-function-search-path)
    # and EXECUTE is revoked to service_role (no definer-function-grants). Its own name isn't
    # secretish and the revoke targets only this function, so it can't disturb the other plants.
    canary_plant = CanaryPlant(
        files={
            "sql/definer_dynamic.sql": (
                "CREATE FUNCTION public.canary_execute_custom_sql(query text)\n"
                "RETURNS SETOF record LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$\n"
                "BEGIN RETURN QUERY EXECUTE query; END $$;\n"
                "REVOKE EXECUTE ON FUNCTION public.canary_execute_custom_sql(text) FROM PUBLIC, anon, authenticated;\n"
                "GRANT EXECUTE ON FUNCTION public.canary_execute_custom_sql(text) TO service_role;\n"
            ),
        },
        expects=frozenset({"definer-dynamic-sql/dynamic-execute"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        # A function is often created in one migration; aggregate names + the file each
        # was defined in, then drop pragma-allowed ones.
        offenders: dict[str, str] = {}  # base name -> file location of its CREATE
        allowed: set[str] = set()
        for f in iter_files(sql_dir, (".sql",)):
            raw = read(f)
            for name in _definer_dynamic_functions(strip_sql_comments(raw)):
                offenders.setdefault(name, rel(root, f))
            allowed |= _pragma_allowed(raw)

        out: list[Finding] = []
        for name in sorted(offenders.keys() - allowed):
            out.append(
                Finding(
                    check_id=self.id,
                    severity="critical",
                    title=self.title,
                    location=offenders[name],
                    message=(
                        f"`{name}()` is SECURITY DEFINER and runs dynamic SQL (`EXECUTE` of a "
                        "variable/argument) — it executes arbitrary SQL with the owner's privileges, "
                        "bypassing RLS on any table, regardless of who is allowed to call it. Reached "
                        "from an LLM agent tool, a prompt-injected query becomes a read/write primitive."
                    ),
                    remediation=(
                        "Do not run argument-derived SQL in a SECURITY DEFINER function. Replace it with "
                        "specific parameterized queries (fixed statements with bind parameters), or make "
                        "the function SECURITY INVOKER so RLS applies to the caller. If the dynamic SQL is "
                        f"provably constrained and audited, add `-- {_PRAGMA}` on the CREATE line."
                    ),
                    rule="definer-dynamic-sql/dynamic-execute",
                    standards=["OWASP:A01", "OWASP-LLM:LLM08"],
                )
            )
        return out
