"""Guard: Supabase Vault exposure a schema dump cannot vouch for (§7, Database Security).

`supabase-vault-exposure` checks who can reach vault material through grants, views and SECURITY
DEFINER functions on the app's own objects: ACL state a pg_dump of the app schema reproduces, so a
dump the repo ships supersedes its migration copies (`schema_state = True`). This guard holds the
vault rules a dump cannot vouch for, so it must not be demotable by one (`schema_state` stays
`False`):

  **`literal-secret-in-sql`** (HIGH): a non-placeholder string literal is passed as the secret to
  `create_secret(...)` / `update_secret(...)` or written by `INSERT INTO vault.secrets` /
  `UPDATE vault.secrets SET secret = …`. A committed migration then carries the plaintext, and a
  dump carries no data rows. The value is never echoed; the message gives its length only.

  **`statement-logging-enabled`** (MEDIUM): in a repo that uses vault, `log_statement` is set to
  `all` or `mod`. The vault README: "the statement logs will contain the _unencrypted_ secrets".
  A schema dump carries no server or database settings.

  **`vault-schema-exposed`** (CRITICAL): `vault` is in the exposed-schema list, so PostgREST serves
  `vault.decrypted_secrets` itself: `pgrst.db_schemas` (an `ALTER ROLE authenticator SET`, a role
  setting a schema dump omits) or `[api] schemas` in a `supabase/config.toml` (any depth, so a
  monorepo's `apps/x/supabase/config.toml` counts; multi-line arrays too).

  **`vault-schema-granted`** (CRITICAL): `vault` itself is handed to `anon`/`authenticated`/
  `PUBLIC`: a `GRANT` on `SCHEMA vault`, on a `vault.<object>`, on `ALL … IN SCHEMA vault`, or an
  `ALTER DEFAULT PRIVILEGES IN SCHEMA vault GRANT`. `vault` is a Supabase-managed schema, and a
  `supabase db dump` of the app schema need not carry its ACL, so a dump's silence proves nothing.

The N/A gate and the file model are `supabase-vault-exposure`'s: no vault reference in any product
`.sql` file and no `config.toml` listing `vault` means no findings.

**Suppress:** `-- security: allow-supabase-vault-plaintext-leak <reason>` as a SQL comment inside
the flagged statement, or `# security: allow-supabase-vault-plaintext-leak <reason>` on the
`schemas = [...]` lines of a `config.toml`. For a finding inside a DO block or a function body, the
statement is the enclosing `DO` / `CREATE FUNCTION`, so the comment may sit on any of its lines: a
header line, a line inside the body (a `$$` body is code to the SQL comment view, #1040), or the
line of the closing `$$;`.

**Checklist item:** `7-supabase-vault-material-exposed` (§7, Database Security).
"""
from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from itertools import accumulate
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    find_statement_end,
    is_reference_sql_path,
    iter_files_named,
    matching_close_paren,
    pragma_line_set,
    read,
    rel,
    split_call_args,
    strip_hash_comments,
)
from .supabase_vault_exposure import (
    _acls,
    _bounded,
    _dollar_spans,
    _File,
    _fmt,
    _line,
    _vault_files,
)

_PRAGMA = "security: allow-supabase-vault-plaintext-leak"

_STANDARDS = ["OWASP:A02", "CWE-312"]

_TITLES = {
    "literal-secret-in-sql": "Literal secret stored in Supabase Vault from committed SQL",
    "statement-logging-enabled": "Statement logging enabled in a repo that uses Supabase Vault",
    "vault-schema-exposed": "The vault schema is in the Data API's exposed-schema list",
    "vault-schema-granted": "The vault schema (or an object in it) is granted to anon/authenticated/PUBLIC",
}

_PGRST_SCHEMAS = re.compile(r"pgrst\.db_schemas\s*(?:=|\bTO\b)\s*'(?P<l>[^'\n]{0,1000})'", re.I)
# `schemas = [...]`, single- or multi-line, matched on the comment-stripped text (a `]` inside a
# `# comment` must not close the array), and only inside the `[api]` table.
_CONFIG_SCHEMAS = re.compile(r"^[ \t]*schemas[ \t]*=[ \t]*\[(?P<list>[^\]]{0,2000})\]", re.M)
_NONSPACE = re.compile(r"\S")
_TOML_TABLE = re.compile(r"^[ \t]*\[(?P<t>[^\[\]\n]{1,200})\][ \t]*$", re.M)

# Literal secrets. `_ID` is `supabase_vault_exposure._ID`, kept local so
# `scripts/lint_regex_redos.py` resolves (and so scans) `_SECRET_CALL`; it cannot follow an import.
_ID = r'(?:"[^"\n]{1,128}"|[A-Za-z_][\w$]{0,127})'
_SECRET_CALL = re.compile(rf"(?:{_ID}\s*\.\s*)?\"?(?P<fn>create_secret|update_secret)\"?\s*\(", re.I)
_FUNCTION_WORD_BEFORE = re.compile(r"\b(?:FUNCTION|ROUTINE)\s+(?:\S+\s*\.\s*)?\"?$", re.I)
_NAMED_ARG = re.compile(r"^\s*\"?(?P<name>\w+)\"?\s*=>\s*(?P<val>.*)$", re.S)
_INSERT_SECRETS = re.compile(r'\bINSERT\s+INTO\s+"?vault"?\s*\.\s*"?secrets"?\s*\(', re.I)
_UPDATE_SECRETS = re.compile(r'\bUPDATE\s+"?vault"?\s*\.\s*"?secrets"?\s+SET\b', re.I)
_SET_SECRET = re.compile(r"\bsecret\s*=\s*", re.I)
_VALUES = re.compile(r"\bVALUES\s*\(", re.I)
_UPDATE_LITERAL = re.compile(r"\s*(E?'(?:[^']|'')*'|(\$\w*\$).*?\2)", re.S)
_PLACEHOLDER = re.compile(
    r"replace[_-]?me|change[_-]?me|<[^<>\n]{0,200}>|\byour[_-]|placeholder|example|dummy|xxx|\.\.\.|"
    r"%[sIL]|\{\{|\$\{",
    re.I,
)

_LOG_STATEMENT = re.compile(
    r"\b(?:ALTER\s+(?:SYSTEM|DATABASE\s+\S+|ROLE\s+\S+|USER\s+\S+)(?:\s+IN\s+DATABASE\s+\S+)?\s+)?"
    r"SET\s+(?:SESSION\s+|LOCAL\s+)?\"?log_statement\"?\s*(?:=|\bTO\b)\s*'?(?P<val>all|mod)\b",
    re.I,
)


def _literal(arg: str) -> str | None:
    """The content of a string-literal argument (`'…'`, `E'…'`, `$tag$…$tag$`, optional `::type`)."""
    a = re.sub(r"\s*::\s*[\w\s\"\[\]]+$", "", arg.strip())
    if a[:2].upper() == "E'":
        a = a[1:]
    if len(a) >= 2 and a[0] == "'" and a[-1] == "'":
        return a[1:-1].replace("''", "'")
    dm = re.fullmatch(r"(\$\w*\$)(.*)\1", a, re.S)
    return dm.group(2) if dm else None


def _is_secret(value: str) -> bool:
    return bool(value.strip()) and not _PLACEHOLDER.search(value)


def _literal_secrets(f: _File) -> list[tuple[int, int, str]]:
    """`(start, end, value)` of each non-placeholder literal stored as a vault secret in executed SQL."""
    out: list[tuple[int, int, str]] = []
    for m, end in _bounded(f.deep, _SECRET_CALL):
        if _FUNCTION_WORD_BEFORE.search(f.deep[max(0, m.start() - 64):m.start()]):
            continue  # a definition, or a GRANT/REVOKE ON FUNCTION head, not a call
        args = split_call_args(f.code[m.start():end], m.end() - 1 - m.start())
        if not args:
            continue
        chosen: str | None = None
        for a in args:
            na = _NAMED_ARG.match(a)
            if na and "secret" in na.group("name").lower() and "id" not in na.group("name").lower():
                chosen = na.group("val")
        positional = [a for a in args if not _NAMED_ARG.match(a)]
        pos = 0 if m.group("fn").lower() == "create_secret" else 1
        if chosen is None and len(positional) == len(args) and len(args) > pos:
            chosen = args[pos]
        val = _literal(chosen) if chosen is not None else None
        if val is not None and _is_secret(val):
            out.append((m.start(), m.end(), val))
    for m, end in _bounded(f.deep, _INSERT_SECRETS):
        window = f.code[m.start():end]
        close = matching_close_paren(window, m.end() - 1 - m.start())
        cols = split_call_args(window, m.end() - 1 - m.start())
        if close is None or not cols:
            continue
        names = [c.strip().strip('"').lower() for c in cols]
        vm = _VALUES.search(f.deep, m.start() + close, end)
        if "secret" not in names or not vm:
            continue
        vals = split_call_args(window, vm.end() - 1 - m.start()) or []
        idx = names.index("secret")
        val = _literal(vals[idx]) if idx < len(vals) else None
        if val is not None and _is_secret(val):
            out.append((m.start(), m.end(), val))
    for m, end in _bounded(f.deep, _UPDATE_SECRETS):
        sm = _SET_SECRET.search(f.deep, m.end(), end)
        if not sm:
            continue
        lm = _UPDATE_LITERAL.match(f.code, sm.end(), end)
        val = _literal(lm.group(1)) if lm else None
        if val is not None and _is_secret(val):
            out.append((m.start(), m.end(), val))
    return out


def _config_files(root: Path) -> list[Path]:
    """Every product `supabase/config.toml` (the Supabase CLI's project config), at any depth."""
    return [
        p for p in iter_files_named(root, "config.toml")
        if p.parent.name == "supabase" and not is_reference_sql_path(rel(root, p))
    ]


def _config_vault_lists(view: str) -> list[re.Match[str]]:
    """Each `[api]` `schemas = [...]` array in `view` (a comment-stripped `config.toml`) that lists
    `vault`. A key before any table header, or under another table, is not the API's list."""
    tables = [(m.start(), m.group("t").strip().strip("'\"").lower()) for m in _TOML_TABLE.finditer(view)]
    out: list[re.Match[str]] = []
    for m in _CONFIG_SCHEMAS.finditer(view):
        i = bisect_right([s for s, _t in tables], m.start()) - 1
        if i < 0 or tables[i][1] != "api":
            continue
        if "vault" in {s.strip().strip("'\"").lower() for s in m.group("list").split(",")}:
            out.append(m)
    return out


def _statement_ends(struct: str) -> list[int]:
    """Every statement-ending `;` offset in `struct`, as `find_statement_end` reports them walking the
    file statement by statement. A raw `;` index is not the same: `struct` blanks literals and dollar
    bodies but keeps identifier text, and a `;` inside a one-line `"..."` identifier is content, not
    a terminator (#559; #1095 round-3 re-review M1). Each call resumes where the last one stopped.
    Measured linear (1.95x to 2.07x per doubling, on stray, far-partner, alternating-kind and
    escaped quotes; #1095 round-4 re-review), not proven: a stray quote's fallback rescans a stretch.

    It is not the same answer as a fresh `find_statement_end` from each span's tail, which starts
    with no quote open. They differ wherever a quote's close lies on a later line, which includes
    valid multi-line literals and identifiers as well as malformed quoting. One valid-SQL result:
    a multi-line quote plus a `;` inside a later `"a;b"` identifier in the same statement flips
    the walk's pairing, so a DO block's statement can run on into the next statement and that
    statement's pragma reaches the DO's finding (#1111, a known Low)."""
    out: list[int] = []
    pos = 0
    while (end := find_statement_end(struct, pos)) != -1:
        out.append(end)
        pos = end + 1
    return out


class _Scopes:
    """Where a pragma may sit for a finding at an offset: its own statement's lines, or, when the
    offset is inside a top-level dollar body (a DO block, a function body), the whole enclosing
    statement, from its keyword (`DO`, `CREATE`) through the `;` after the closing `$$`. Only the
    lines outside the body carry real SQL comments. Spans and statement ends are indexed once per
    file and each span's bounds are cached, so a lookup is a bisect."""

    def __init__(self, f: _File) -> None:
        self.f = f
        self.spans = _dollar_spans(f.struct)
        self.inner_starts = [s for _t, s, _e in self.spans]
        self.ends = _statement_ends(f.struct) if self.spans else []
        self.bounds: dict[int, tuple[int, int]] = {}

    def of(self, start: int, end: int) -> tuple[int, int]:
        i = bisect_right(self.inner_starts, start) - 1
        if i < 0 or not self.spans[i][1] <= start < self.spans[i][2]:
            return start, end
        if i not in self.bounds:
            tag_start, inner_s, inner_e = self.spans[i]
            j = bisect_right(self.ends, tag_start) - 1
            kw = _NONSPACE.search(self.f.struct, self.ends[j] + 1 if j >= 0 else 0, tag_start)
            tail = min(inner_e + (inner_s - tag_start), len(self.f.struct))
            # The statement-end index, not a scan to EOF from every span: a `;`-less body would
            # rescan the rest of the file once per span (quadratic, #1095 re-review M2).
            k = bisect_left(self.ends, tail)
            stop = self.ends[k] + 1 if k < len(self.ends) else len(self.f.struct)
            self.bounds[i] = (kw.start() if kw else tag_start, stop)
        head, stop = self.bounds[i]
        return head, max(end, stop)


class SupabaseVaultPlaintextLeakGuard(Guard):
    id = "supabase-vault-plaintext-leak"
    title = "Supabase Vault exposure a schema dump cannot vouch for (literal secret, statement logging, vault schema granted or exposed)"
    area = "Database"
    # schema_state stays False: a dump cannot vouch for any of these, so it must never demote them (#829).

    # FIRE-strings: a non-placeholder literal passed to `vault.create_secret(...)`. Deliberately
    # not key-shaped, so secret scanners reading this module do not match it.
    canary_plant = CanaryPlant(
        files={
            "sql/supabase_vault_plaintext_leak.sql": (
                "-- Seed migration that stores a literal secret in vault.\n"
                "SELECT vault.create_secret('canary-plaintext-q7Wm2', 'canary_key');\n"
            )
        },
        expects=frozenset({"supabase-vault-plaintext-leak/literal-secret-in-sql"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files = _vault_files(root, _PRAGMA)
        out: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        scopes: dict[int, _Scopes] = {}

        def emit(f: _File, start: int, end: int, rule: str, severity: Severity, message: str,
                 remediation: str, extra: tuple[str, ...] = ()) -> None:
            loc = f"{rel(root, f.path)}:{_line(f, start)}"
            sc = scopes.get(id(f))
            if sc is None:
                sc = scopes[id(f)] = _Scopes(f)
            lo, hi = sc.of(start, end)
            first, last = _line(f, lo), _line(f, max(lo, hi - 1))
            if (rule, loc) in seen or any(first <= ln <= last for ln in f.pragma_lines):
                return
            seen.add((rule, loc))
            out.append(Finding(
                check_id=self.id, severity=severity, title=_TITLES[rule], location=loc, message=message,
                remediation=remediation, rule=f"{self.id}/{rule}", standards=[*_STANDARDS, *extra],
            ))

        for f in files:
            for a in _acls(f):
                if a.grant and a.target[0] == "vault":
                    emit(f, a.start, a.end, "vault-schema-granted", "critical",
                         f"This GRANT hands the `vault` schema (or an object in it) to {_fmt(a.roles)}. "
                         "`vault.decrypted_secrets` decrypts on read, so whoever reaches it reads every secret.",
                         "Remove the grant. Expose vault material only through narrowly scoped SECURITY DEFINER "
                         "functions executable by `service_role` alone.", ("OWASP:A01", "CWE-732"))
            for m in _PGRST_SCHEMAS.finditer(f.code):
                if f.struct[m.start():m.start() + 5].strip() and "vault" in {
                    s.strip().strip('"').lower() for s in m.group("l").split(",")
                }:
                    emit(f, m.start(), m.end(), "vault-schema-exposed", "critical",
                         "`pgrst.db_schemas` lists `vault`, so PostgREST serves `vault.decrypted_secrets` "
                         "to any API key holder.",
                         "Remove `vault` from the exposed schemas.", ("OWASP:A01",))
        for config in _config_files(root):
            text = read(config)
            view = strip_hash_comments(text)  # line-for-line, so line numbers still match `text`
            if view.startswith("\ufeff"):  # a BOM hides a first-line `[api]` from `^[ \t]*\[` (#1095 re-review L3)
                view = " " + view[1:]  # same length, so every offset still matches `text`
            hits = _config_vault_lists(view)
            if not hits:
                continue
            starts = list(accumulate(map(len, view.splitlines(keepends=True)), initial=0))
            toml = pragma_line_set(_PRAGMA, text, dialect="hash")
            for m in hits:
                first, last = bisect_right(starts, m.start()), bisect_right(starts, max(m.start(), m.end() - 1))
                loc = f"{rel(root, config)}:{first}"
                if any(first <= ln <= last for ln in toml) or ("vault-schema-exposed", loc) in seen:
                    continue
                seen.add(("vault-schema-exposed", loc))
                out.append(Finding(
                    check_id=self.id, severity="critical", title=_TITLES["vault-schema-exposed"], location=loc,
                    message="This `supabase/config.toml` exposes the `vault` schema through the Data API, which "
                            "then serves `vault.decrypted_secrets` to any key holder.",
                    remediation="Remove `vault` from `[api] schemas`.",
                    rule=f"{self.id}/vault-schema-exposed", standards=[*_STANDARDS, "OWASP:A01"],
                ))

        # Executed SQL. A dump file carries no data rows, so a literal secret is read from migrations
        # only; a `pg_dump -C` / `pg_dumpall` file can carry `ALTER DATABASE ... SET log_statement`,
        # so logging is read everywhere.
        for f in files:
            for start, end, val in ([] if f.dump else _literal_secrets(f)):
                emit(f, start, end, "literal-secret-in-sql", "high",
                     f"A {len(val)}-character string literal is stored as a Supabase Vault secret here, so the "
                     "plaintext is committed with this file (and lands in any statement log that captured "
                     "it). The value is not shown.",
                     "Never put the secret in SQL source: insert it at deploy time from the environment "
                     "(a client call or a one-off `psql -v`), and rotate this one, since it is in git history.",
                     ("CWE-798",))
            for m in _LOG_STATEMENT.finditer(f.code):
                if not f.deep[m.start():m.start() + 3].strip():
                    continue  # inside a string literal: not executed
                emit(f, m.start(), m.end(), "statement-logging-enabled", "medium",
                     f"`log_statement = '{m.group('val').lower()}'` logs every statement's text, and the "
                     "Supabase Vault docs warn the statement logs will then contain the unencrypted secrets "
                     "passed to `vault.create_secret(...)`.",
                     "Keep `log_statement` at `none` or `ddl` on any database that uses Vault.",
                     ("CWE-532",))
        return out
