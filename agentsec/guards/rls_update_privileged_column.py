"""Guard: a self-update RLS policy lets the owner write privileged columns (checklist 7-rls-update-privileged-column).

A common AI-generated pattern scopes an `UPDATE` policy to the row owner but tries
to protect authorization columns with a *denylist* `WITH CHECK` that pins only one
or two of them:

    CREATE POLICY "Users can update their own profile" ON user_profiles
      FOR UPDATE
      USING  (auth.uid() = id)
      WITH CHECK (auth.uid() = id AND is_admin IS NOT DISTINCT FROM FALSE);

RLS is enabled, the policy is scoped (not `USING (true)`), and it doesn't gate on
`user_metadata` — so the other RLS guards stay silent. But a `WITH CHECK` is
evaluated on the **NEW** row only and cannot pin a column to its prior value, so
every *other* privilege column (`tokens`, `is_pro`, `roles`, `*_access_token`, …)
is writable by any authenticated user via a direct `UPDATE` on their own row —
column-level mass-assignment / privilege escalation (CWE-639 / CWE-915).

Fires HIGH on a `CREATE POLICY ... FOR UPDATE|ALL` that targets a privilege-bearing
table, is self-scoped (`auth.uid()`/`auth.jwt()`), targets a client role
(`authenticated`/`public`/`anon`, or no `TO`), and leaves ≥1 of the table's
privilege columns out of its `WITH CHECK`. The sound, future-proof fix is a
`BEFORE UPDATE` trigger that resets the row (`NEW := OLD`) then re-applies only a
self-service allowlist (so new columns are protected by default), or column-level
`REVOKE UPDATE … ; GRANT UPDATE (safe_cols) …`. The guard treats either of those
on the table as protection (suppress); a reviewed case can use
`-- security: allow-self-update-privileged-column` on the policy's first line or the line above it.

OWASP:A01 (Broken Access Control). Mirrors the "scoped row, unprotected privileged
columns" class an audit of the flagship surfaced that the other RLS guards missed.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    iter_bounded_matches,
    iter_files,
    iter_statement_spans,
    read,
    rel,
    strip_sql_comments,
)

# Privilege/authorization columns a row owner must not be able to self-write.
# Word-boundary, case-insensitive, full-column-name match (see `_is_priv`).
_PRIV_COL = re.compile(
    r"is_admin|is_superuser|is_staff|is_owner|is_pro|is_premium|is_paid|is_trainer|is_coach"
    r"|is_verified|is_banned|roles?|[a-z_]*permissions?|[a-z_]*access_token"
    r"|subscription_[a-z_]+|plan|tier|credits?|balance|quota|tokens?|external_id",
    re.IGNORECASE,
)
# An admin-gated policy REQUIRES the caller to already be an admin (is_admin()/=true) —
# the legit admin path; never a self-grant. Distinct from a vulnerable WITH CHECK that
# *pins* `is_admin` to FALSE (`is_admin IS NOT DISTINCT FROM FALSE`), which must still fire.
_ADMIN_GATE = re.compile(
    r"is_admin\s*\(\s*\)|is_superuser\s*\(\s*\)|is_admin\s*=\s*true|is_admin\s+is\s+true",
    re.IGNORECASE,
)
# Scoping columns are NOT privileges (avoid FP on the policy's own predicate).
_SCOPING_COLS = frozenset({"id", "user_id", "owner_id", "auth_id", "owner", "uid"})

_CREATE_TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?\s*\(",
    re.IGNORECASE,
)
_ADD_COLUMN = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?"
    r"\s+add\s+column\s+(?:if\s+not\s+exists\s+)?\"?(?P<col>\w+)\"?",
    re.IGNORECASE,
)
# Statement-spanning (chained via `iter_bounded_matches` — the old multi-`[^;]*?` lazy
# regexes re-scanned from every candidate head, quadratic on hostile `;`-less SQL,
# issue #419): the real fix puts BEFORE UPDATE and ON <t> on separate lines.
_TRIGGER_HEAD = re.compile(r"create\s+(?:constraint\s+)?trigger\b", re.IGNORECASE)
_BEFORE_UPDATE = re.compile(r"\bbefore\s+update\b", re.IGNORECASE)
_TRIGGER_ON = re.compile(
    r"\bon\s+(?:only\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
# Role-gated: a REVOKE that protects must target the policy's client role. A bare
# `REVOKE ALL … FROM anon` (RLS already blocks anon DML) is NOT protection and must NOT match.
_REVOKE_HEAD = re.compile(r"revoke\s+(?:update|all(?:\s+privileges)?)\b", re.IGNORECASE)
_REVOKE_ON = re.compile(
    r"\bon\s+(?:table\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_FROM_KW = re.compile(r"\bfrom\b", re.IGNORECASE)
_CLIENT_ROLE_TOKEN = re.compile(r"\b(?:authenticated|public)\b", re.IGNORECASE)
# Via `iter_statement_spans`. The old `create\s+policy\b[^;]+;` required ≥1 char before the
# `;`; the helper allows zero, so a bare `create policy;` (invalid SQL) now yields an
# empty-content span — which `_POLICY_TABLE` then rejects, so guard output is unchanged
# (PR #430 review).
_POLICY_HEAD = re.compile(r"create\s+policy\b", re.IGNORECASE)
# The table in `... ON <t> {AS|FOR|TO|USING|WITH CHECK} ...` — anchored on a trailing
# policy keyword so a policy NAME containing " on " can't be mistaken for the table.
_POLICY_TABLE = re.compile(
    r"\bon\s+(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?\s+(?:as\b|for\b|to\b|using\b|with\s+check\b)",
    re.IGNORECASE,
)
# The quoted policy NAME, so it can be masked before the table is read. Requiring a trailing
# clause keyword (#423) stopped a name containing a bare " on … " from being read as the table,
# but a name that also contains the keyword still poisons it: with
# `CREATE POLICY "allow on orders for select" ON public.notes FOR UPDATE …` the pattern matches
# inside the NAME and extracts `orders` instead of `notes`.
#
# MEASURED consequence, BOTH arms (#445 gate finding 2; two earlier versions of this note each
# stated one arm as if it were the whole story). The poisoned table is looked up in pass A's
# privileged-column map, and which arm you get depends on whether that table exists:
#   * usually it was never declared, so it has no privileged columns and the `if not cols` guard
#     below drops the finding — a SILENT MISS of a real HIGH (clean name 1 finding, poisoned 0);
#   * if the poisoned name happens to name a table that IS declared with privileged columns, the
#     finding is emitted against that WRONG table instead, pointing an operator at the wrong place.
# Both measured on `main`. The silent miss is the more dangerous of the two, which is why the
# earlier "reports the WRONG table" note read as milder than the truth; stating only the miss was
# no better. A measurement over one fixture is not a property of the code.
# A policy name is free text and can contain anything; it must not be scanned as SQL structure.
# Pass C masks it once per statement, so the FOR, self-scope, admin, TO and WITH CHECK reads see
# the masked statement too; #445 applied it to the table lookup alone (#957).
# (A `;` inside the name used to truncate the statement before this mask ever ran — the carve
# happens first. Closed by #559: `find_statement_end` reads a single-line quoted `;` as content,
# so the mask now sees the whole statement.)
#
# ANCHORED to the statement head (`\A`), which both callers guarantee: `iter_statement_spans`
# yields spans that begin at the `create policy` match. An unanchored `(?<=\bpolicy\s)"…"` fired on
# ANY `policy` + `"` inside the statement and ran greedily to the next quote, so a block comment
# like `create policy p /* policy " */ on "public"."notes" for update …` had its real `ON` token
# blanked, `_POLICY_TABLE` then failed, and a real HIGH vanished — a silent miss `main` does not
# have. Pass C blanked only `--` comments then, so block comments reached this; it blanks both
# since #442, and the anchor still guards a `policy` + `"` inside a string literal. (#445 gate,
# finding 3.)
_POLICY_NAME_SPAN = re.compile(r'\A(create\s+policy\s+)("(?:[^"]|"")*")', re.IGNORECASE)


def policy_stmt_without_name(stmt: str) -> str:
    """`stmt` with the quoted policy name blanked, length- and newline-preserving.

    Equal length so any character offset computed against the result still maps onto the
    original; newlines kept so the `count("\\n", 0, off) + 1` line-number idiom used
    everywhere else in these guards stays valid on a multi-line policy name."""
    return _POLICY_NAME_SPAN.sub(
        lambda m: m.group(1) + "".join("\n" if c == "\n" else " " for c in m.group(2)), stmt
    )


# The `TO <roles>` list, found in a loop rather than by one regex (#429). The retired regex was
# `\bto\s+(?P<roles>[\w,\s"]+?)(?=\busing\b|\bwith\s+check\b|\bas\b|;|$)`, and on a hostile policy
# statement it was O(n²) in two independent ways, each re-walking the same role-class run:
#   1. `re.search` retried from every `to` in the run (`to to to … (`), each walking to the same
#      blocking character;
#   2. from a SINGLE `to`, greedy `\s+` gave back one whitespace char at a time, and the lazy class
#      (which also matches `\s`) re-walked the run from every shorter split.
# Fixing only one leaves the other quadratic. `_to_clause_roles` returns exactly what that regex's
# `roles` group did (the test file's differential oracle holds it to that) in linear time.
_TO_HEAD = re.compile(r"\bto\s+", re.IGNORECASE)
_NOT_ROLE_CHAR = re.compile(r"[^\w,\s\"]")
_TO_TERM = re.compile(r"\busing\b|\bwith\s+check\b|\bas\b|;|$", re.IGNORECASE)


def _to_clause_roles(stmt: str) -> str | None:
    """The `TO` role span of a policy statement, or None when it has no `TO` clause (PUBLIC)."""
    pos = 0
    while (head := _TO_HEAD.search(stmt, pos)) is not None:
        t, w = head.span()  # greedy `\s+`: `w` is the end of the whole whitespace run
        stop = _NOT_ROLE_CHAR.search(stmt, w)
        f = stop.start() if stop else len(stmt)  # end of the role-class run
        # Lazy roles: the earliest terminator in [w+1, f]. `endpos=f+1` bounds the scan, but `$`
        # also matches AT endpos, so a hit past `f` is rejected rather than trusted. A `\b` at `pos`
        # still reads the real preceding character, so the `\busing` / `\bas` edges stay exact.
        term = _TO_TERM.search(stmt, w + 1, f + 1) if w + 1 <= f else None
        if term is not None and term.start() <= f:
            return stmt[w : term.start()]
        # The one reachable `\s+` backtrack: `\s+` gives back its last whitespace char, which becomes
        # the whole role span, when a terminator starts right at `w` (`TO  USING`, no role at all).
        if w >= t + 4 and _TO_TERM.match(stmt, w) is not None:
            return stmt[w - 1 : w]
        pos = f  # every `to` inside [t, f) fails the same way, so skip them all (mechanism 1)
    return None


_WITH_CHECK = re.compile(r"with\s+check\s*\(", re.IGNORECASE)
_FOR_UPDATE_OR_ALL = re.compile(r"\bfor\s+(?:update|all)\b", re.IGNORECASE)
_FOR_OTHER = re.compile(r"\bfor\s+(?:select|insert|delete)\b", re.IGNORECASE)
_SELF_SCOPE = re.compile(r"auth\.(?:uid|jwt)\s*\(", re.IGNORECASE)
_CLIENT_ROLE = re.compile(r"\b(?:authenticated|public|anon)\b", re.IGNORECASE)
_PRAGMA = re.compile(r"--\s*security:\s*allow-self-update-privileged-column", re.IGNORECASE)


def _norm(token: str | None, default: str = "public") -> str:
    return token.strip('"').lower() if token else default


def _qual(schema: str | None, name: str) -> str:
    return f"{_norm(schema)}.{_norm(name)}"


def _is_priv(col: str) -> bool:
    c = col.strip('"').lower()
    return c not in _SCOPING_COLS and _PRIV_COL.fullmatch(c) is not None


def _balanced(text: str, open_idx: int) -> str:
    """Substring inside the parentheses whose opening `(` is at `open_idx`."""
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : j]
    return text[open_idx + 1 :]


def _split_top_level(body: str) -> list[str]:
    """Split a CREATE TABLE body on top-level (paren-depth-0) commas."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _table_priv_columns(text: str, priv: dict[str, set[str]]) -> None:
    """Accumulate privilege columns per qualified table from CREATE TABLE + ADD COLUMN."""
    for m in _CREATE_TABLE.finditer(text):
        table = _qual(m.group("schema"), m.group("name"))
        body = _balanced(text, m.end() - 1)
        for part in _split_top_level(body):
            name_m = re.match(r'\s*"?(\w+)"?', part)
            if name_m and _is_priv(name_m.group(1)):
                priv.setdefault(table, set()).add(name_m.group(1).strip('"').lower())
    for m in _ADD_COLUMN.finditer(text):
        if _is_priv(m.group("col")):
            table = _qual(m.group("schema"), m.group("name"))
            priv.setdefault(table, set()).add(m.group("col").strip('"').lower())


class RlsUpdatePrivilegedColumnGuard(Guard):
    id = "rls-update-privileged-column"
    title = "Self-update RLS policy lets the owner write privileged columns"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # canary_priv: scoped self-update policy pins is_admin but leaves `tokens` writable.
    canary_plant = CanaryPlant(expects=frozenset({"rls-update-privileged-column/unpinned-column"}))

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        files = list(iter_files(sql_dir, (".sql",)))
        if not files:
            return []

        # Pass A + B: privilege columns and write-hardened tables, aggregated across ALL
        # files first (a policy in one migration + the table/trigger in another is fine).
        priv: dict[str, set[str]] = {}
        protected: set[str] = set()
        for f in files:
            clean = strip_sql_comments(read(f))
            _table_priv_columns(clean, priv)
            for _bu, tm in iter_bounded_matches(clean, _TRIGGER_HEAD, _BEFORE_UPDATE, _TRIGGER_ON):
                protected.add(_qual(tm.group("schema"), tm.group("name")))
            for rm, _fr, _role in iter_bounded_matches(
                clean, _REVOKE_HEAD, _REVOKE_ON, _FROM_KW, _CLIENT_ROLE_TOKEN
            ):
                protected.add(_qual(rm.group("schema"), rm.group("name")))

        # Pass C: emit. Comments are BLANKED, not deleted, so every offset into `scanned` is the
        # same offset into `raw` (#442). Blank mode is string-aware, so a `--` inside a literal
        # (`USING (x = 'a--b')`) no longer swallows the rest of the line, and a policy inside a
        # `/* … */` block is no longer read as live SQL.
        out: list[Finding] = []
        for f in files:
            raw = read(f)
            scanned = strip_sql_comments(raw, blank=True)
            view_lines = comment_view(raw, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            # `str.splitlines()` line starts, so the finding's line and the pragma's line are
            # numbered the same way even after a form feed or a lone `\r`.
            line_starts = list(accumulate(map(len, raw.splitlines(keepends=True)), initial=0))
            for s_start, s_end in iter_statement_spans(scanned, _POLICY_HEAD):
                # Mask the free-text policy NAME first — see `policy_stmt_without_name`. Every read
                # below is structural, so all of them run on the masked statement (#957).
                stmt = policy_stmt_without_name(scanned[s_start:s_end])
                tbl_m = _POLICY_TABLE.search(stmt)
                if not tbl_m:
                    continue
                table = _qual(tbl_m.group("schema"), tbl_m.group("name"))
                cols = priv.get(table)
                if not cols or table in protected:
                    continue
                # UPDATE-capable: explicit FOR UPDATE/ALL, or no FOR clause (defaults to ALL).
                if not (_FOR_UPDATE_OR_ALL.search(stmt) or not _FOR_OTHER.search(stmt)):
                    continue
                if not _SELF_SCOPE.search(stmt):
                    continue
                if _ADMIN_GATE.search(stmt):
                    continue  # admin-only policy (requires is_admin) — the legit admin path
                roles = _to_clause_roles(stmt)
                if roles is not None and not _CLIENT_ROLE.search(roles):
                    continue  # e.g. TO service_role — the legit admin/backend path
                wc = _WITH_CHECK.search(stmt)
                with_check_expr = _balanced(stmt, stmt.index("(", wc.end() - 1)) if wc else ""
                unpinned = sorted(
                    c for c in cols if not re.search(rf"\b{re.escape(c)}\b", with_check_expr, re.I)
                )
                if not unpinned:
                    continue
                line = bisect_right(line_starts, s_start)
                # The pragma reaches the policy's first line or the line above it, where the
                # opt-out for a multi-line policy is naturally written. It is read from the SQL
                # comment view's line, which reads a `$$…$$` body as code (#1040 T2), so the opt-out
                # of an idempotent `DO $$ … CREATE POLICY … $$` migration, written inside the body,
                # still counts, while a pragma phrase inside a literal does not.
                if any(_PRAGMA.search(view_lines[n - 1]) for n in (line - 1, line) if n >= 1):
                    continue
                cols_list = ", ".join(unpinned)
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{line}",
                        message=(
                            f"This self-update RLS policy on `{table}` scopes rows to their owner but its "
                            f"WITH CHECK leaves privilege column(s) unconstrained: {cols_list}. A WITH CHECK "
                            "sees only the NEW row and cannot pin a column to its prior value, so any "
                            "authenticated user can self-grant these via a direct UPDATE on their own row."
                        ),
                        remediation=(
                            "Enforce a column allowlist a WITH CHECK cannot: a BEFORE UPDATE trigger that "
                            "resets the row (`NEW := OLD`) then re-applies only the self-service columns "
                            "(so new columns are protected by default), or `REVOKE UPDATE … ; "
                            "GRANT UPDATE (safe_cols) …`. Exempt admins/service_role. If intentional, "
                            "suppress with `-- security: allow-self-update-privileged-column`."
                        ),
                        rule="rls-update-privileged-column/unpinned-column",
                        standards=["OWASP:A01"],
                    )
                )
        return out
