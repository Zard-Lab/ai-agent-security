"""Guard: a table has an RLS policy but RLS is never enabled (checklist 7-policy-exists-rls-disabled).

A `CREATE POLICY` does nothing unless the table also runs
`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`. Postgres does **not** enforce a
policy on a table whose RLS is off — the policy sits there inert and the table is
open to every role that has table privileges. The Supabase dashboard still shows a
policy, so the table *looks* protected; it is not. This is the mirror image of the
permissive-policy bug: there the policy is present but useless because it says
`true`; here the policy is present but useless because RLS is switched off.

Fires HIGH on a `CREATE POLICY ... ON <table>` whose target table is never
`ENABLE ROW LEVEL SECURITY`'d (and never dropped) anywhere in the migration SQL.
The fix is to enable RLS on the table. A genuinely intentional case can suppress
the audited policy line with `-- security: allow-policy-without-rls`.

OWASP:A01 (Broken Access Control). Mirrors Supabase Splinter's
`policy_exists_rls_disabled` lint, caught statically in migration SQL pre-deploy.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    blank_policy_names,
    comment_view,
    find_statement_end,
    iter_bounded_matches,
    iter_files,
    read,
    rel,
    strip_sql_comments,
)

# `ALTER TABLE [ONLY] <t> ENABLE ROW LEVEL SECURITY`. The optional `ONLY` (which stops the
# change cascading to inheriting child tables) is what `pg_dump` emits, so a schema restored
# from a dump read as "RLS never enabled" and every policy in it was reported — a false
# positive on the most common way a real Postgres schema is checked in (#422).
_ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?"
    r'(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?'
    r"\s+enable\s+row\s+level\s+security",
    re.I,
)
_DROP = re.compile(
    r'drop\s+table\s+(?:if\s+exists\s+)?(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?', re.I
)
# `CREATE POLICY <name> ON <schema>.<table>` — matched as head + bounded ON search via
# `iter_bounded_matches` (linear; a `[^;]*?` lazy scan re-ran from every head on one hostile
# long line — quadratic, issue #419). The head and its `ON` clause are matched across the
# whole file rather than within one physical line: Postgres and the Supabase docs both write
# the statement over several lines, with `ON <table>` below the policy name, and a per-line
# search saw a `CREATE POLICY` with no table and dropped it (#422). `iter_bounded_matches`
# already bounds the search at the statement's `;`, so the multi-line form costs no extra scan
# and cannot run past its own statement.
_POLICY_HEAD = re.compile(r"create\s+policy\b", re.I)
_POLICY_ON = re.compile(r'\bon\s+(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?', re.I)
_PRAGMA = re.compile(r"--\s*security:\s*allow-policy-without-rls")


# Schemas whose tables SUPABASE owns and has already RLS-enabled, so an application migration
# writes policies against them and never an `ALTER TABLE … ENABLE ROW LEVEL SECURITY` — it has no
# privilege to, and none is needed. Supabase enables RLS on `storage.objects` / `storage.buckets`,
# on the `auth` tables, and on the `realtime` / `vault` schemas it manages the same way.
#
# Without this, the multi-line detection above reports every repo that writes storage policies
# (the flagship writes 8 of them, all in the multi-line form) and the message it prints —
# "the policy is inert and the table is open" — is simply false there: RLS is ON.
#
# Gated on the SUPABASE FEATURE, not applied unconditionally. `applies()` admits any repo with
# SQL, and naming your own auth tables' schema `auth` is an ordinary Postgres convention with
# nothing to do with Supabase — so without the feature gate this silently suppressed a genuine
# HIGH on a hand-rolled `CREATE POLICY … ON auth.sessions` with no ENABLE anywhere (#587 review,
# High 1). The exemption may only speak for schemas some other system is known to own.
#
# Matched on the SCHEMA, so a user table of the same name in `public` (`public.objects`) is
# unaffected and still reported even in a Supabase repo.
_PLATFORM_RLS_SCHEMAS = frozenset({"storage", "auth", "realtime", "vault"})


def _norm(token: str | None, default: str = "public") -> str:
    return token.strip('"').lower() if token else default


def _qual(schema: str | None, name: str) -> str:
    return f"{_norm(schema)}.{_norm(name)}"


class PolicyExistsRlsDisabledGuard(Guard):
    id = "policy-exists-rls-disabled"
    title = "RLS policy defined but RLS not enabled — the policy is inert, the table is open"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # One of the RLS pack siblings in sql/schema.sql: canary_orphan has a policy but no ENABLE RLS.
    canary_plant = CanaryPlant(expects=frozenset({"policy-exists-rls-disabled/rls-off"}))

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        files = list(iter_files(sql_dir, (".sql",)))
        if not files:
            return []

        # Aggregate the protected (RLS-enabled or dropped) tables across ALL files —
        # order- and file-independent: a policy in one migration and the ENABLE in
        # another is fine. Comment-stripped so a commented-out ENABLE does not count.
        protected: set[str] = set()
        for f in files:
            text = strip_sql_comments(read(f))
            for m in _ENABLE_RLS.finditer(text):
                protected.add(_qual(m.group("schema"), m.group("name")))
            for m in _DROP.finditer(text):
                protected.add(_qual(m.group("schema"), m.group("name")))

        out: list[Finding] = []
        seen: set[str] = set()
        platform_exempt = "supabase" in profile.features
        for f in files:
            raw = read(f)
            view_lines = comment_view(raw, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            clean = strip_sql_comments(raw, blank=True)
            # Structure is read from `masked`: the free-text policy NAME is space-filled (same
            # length, same newlines, so every offset below maps onto `clean` and `view_lines`).
            # `_POLICY_ON` is unanchored, and a name like `"foo on bar"` otherwise reads as
            # `ON bar`, attributing the policy to the WRONG table — `documents`' real finding goes
            # silent when `bar` happens to have RLS (#824 review). See `blank_policy_names`.
            masked = blank_policy_names(clean)
            # Statement heads, in file order — the anchor a finding is reported against, and the
            # only thing `iter_bounded_matches` (which yields the tail matches) does not hand back.
            heads = [m.start() for m in _POLICY_HEAD.finditer(masked)]
            hi = 0            # walks `heads` forward, never rewinds → linear overall
            consumed = 0      # end of the last paired `ON`; heads before it are already spoken for
            # Newline offsets, built ONCE per file, so an offset→line lookup is a bisect rather
            # than a rescan. `clean.count("\n", 0, pos)` reads as O(1) and is not: it walks from
            # the start of the file EVERY time, so a file with many reported policies cost
            # O(file × findings). Measured on 32k well-formed one-line policies: 1.1s on the
            # per-line scan this replaced, 23.9s with the rescan, 1.2s with this (#587 re-review).
            # The existing hostile-input tests could not catch it — they construct inputs that
            # yield ZERO findings, so they never enter this loop body.
            newlines = [i for i, ch in enumerate(clean) if ch == "\n"]
            file_rel = rel(root, f)  # once per file: pathlib work the per-finding loop below must not repeat
            for (on,) in iter_bounded_matches(masked, _POLICY_HEAD, _POLICY_ON):
                # Re-derive the head THIS `ON` was paired with, the way the helper paired it: the
                # first head not already consumed by an earlier pairing that also shares a statement
                # with the `ON` (no `;` between them). A plain "nearest head before the ON" lookup
                # is not the same thing — with two head-shaped matches before one `ON` it picks the
                # LATER one, which is not the statement the helper matched, so the finding was
                # anchored on the wrong line AND the pragma window started below a pragma written on
                # the real head line, silently voiding a user's own opt-out (#587 review, Medium 1).
                # The boundary test is quote-aware (`find_statement_end`, bounded to the span it
                # asks about): a `;` inside the quoted name or a literal is not a boundary, else a
                # multi-line `CREATE POLICY "own; rows"` skipped its own head and a pragma on that
                # head line was voided the same way (#824 fix-review).
                while hi < len(heads) and (
                    heads[hi] < consumed or find_statement_end(masked, heads[hi], on.start()) != -1
                ):
                    hi += 1
                # `heads` cannot be exhausted here (the helper found its head with this very
                # pattern), but never index blindly on attacker-supplied SQL.
                start = heads[hi] if hi < len(heads) else on.start()
                consumed = on.end()
                i = bisect_right(newlines, start - 1) + 1   # 1-based line of the head
                # The pragma opt-out is honored anywhere in the statement it suppresses, not only
                # on the `CREATE POLICY` line. On the multi-line form this scan now detects, the
                # natural place to write it is the end of the statement, several lines below the
                # keyword — a head-line-only check made the documented suppression unusable there.
                # The span stops at the statement's own `;`, so a pragma on a FOLLOWING statement
                # cannot reach back and silence this one. Quote-aware: a `;` inside a `USING`
                # literal (`'closed; for now'`) used to end the window a line early and a pragma
                # written at the statement's real end was silently voided (#824 review, Medium 2).
                semi = find_statement_end(masked, on.end())
                end_line = bisect_right(newlines, (len(clean) if semi == -1 else semi) - 1) + 1
                if any(
                    _PRAGMA.search(ln) for ln in view_lines[i - 1 : min(end_line, len(view_lines))]
                ):
                    continue
                table = _qual(on.group("schema"), on.group("name"))
                if platform_exempt and table.split(".", 1)[0] in _PLATFORM_RLS_SCHEMAS:
                    continue  # Supabase-owned table — RLS is already on, no ALTER to look for
                if table in protected or table in seen:
                    continue
                seen.add(table)
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{file_rel}:{i}",
                        message=(
                            f"`{table}` has an RLS policy but the table is never "
                            "`ENABLE ROW LEVEL SECURITY`'d. Postgres does not enforce a policy "
                            "on a table with RLS off, so the policy is inert and the table is open "
                            "to every role with table privileges."
                        ),
                        remediation=(
                            f"`ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;` so the policy is "
                            "enforced (or drop the table if it is unused). If the open access is "
                            "intentional, suppress with `-- security: allow-policy-without-rls`."
                        ),
                        rule="policy-exists-rls-disabled/rls-off",
                        standards=["OWASP:A01"],
                    )
                )
        return out
