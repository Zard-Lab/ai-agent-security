"""Guard: Supabase storage bucket created with public=true (§7 — Database Security).

Every file uploaded to a public Supabase Storage bucket is reachable via an
unauthenticated URL of the form:

    https://<project>.supabase.co/storage/v1/object/public/<bucket>/<file>

No JWT, no service-role key, no RLS policy — a plain HTTP GET is all an attacker
needs. Developers often set public=true to skip the signed-URL flow during
development and then ship the setting to production, exposing user photos, documents,
contract PDFs, and any other uploaded PII to the open internet.

Two detection signals are supported:

  **sql-public-bucket** (HIGH): an `INSERT INTO storage.buckets` (VALUES clause) or an
  `UPDATE storage.buckets SET` that sets `public = true` (or `public=true`). This pattern
  appears in Supabase migration files (`supabase/migrations/*.sql`). A write statement is
  required — a bare `storage.buckets` substring also matches READ queries, most notably
  Supabase's own official Database Linter (Splinter) query (issue #328).

  **python-public-bucket** (HIGH): A Python call to
  `supabase.storage().create_bucket(...)` (the supabase-py client) where the
  options argument contains `"public": True` or `public=True`.

**Suppress** either signal with `# security: allow-public-bucket` anywhere in the
file. Use only when the bucket is intentionally public (e.g. a CDN bucket for
pre-compressed static assets that carry no user data).
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
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_sql_comments,
)

_PRAGMA = "security: allow-public-bucket"

_STANDARDS = ["OWASP:A01", "CIS:6.3"]

# SQL: INSERT INTO storage.buckets ... with public bucket flag set to true.
#
# Supabase migrations use two forms:
#   1. Positional VALUES: INSERT INTO storage.buckets (id, name, public) VALUES ('x', 'x', true)
#   2. SET syntax / literal: UPDATE storage.buckets SET public = true ...
#
# We require an actual write statement (INSERT/UPDATE) rather than a bare "storage.buckets"
# substring — a bare match also fires on a READ query mentioning storage.buckets, most notably
# Supabase's own official Database Linter (Splinter) query, which a repo commonly saves locally
# (e.g. security/splinter.sql) and which itself queries storage.buckets to detect this exact
# misconfiguration (issue #328).
_SQL_BUCKET_WRITE = re.compile(
    r"insert\s+into\s+storage\s*\.\s*buckets\b|update\s+storage\s*\.\s*buckets\s+set\b",
    re.IGNORECASE,
)
# We detect: a write statement + "public" keyword + "true" keyword,
# but NOT when "false" appears after "public" (which catches both VALUES=false and public=false forms).
_SQL_HAS_PUBLIC = re.compile(r"\bpublic\b", re.IGNORECASE)
_SQL_HAS_TRUE = re.compile(r"\btrue\b", re.IGNORECASE)
# An EXPLICIT `public = false` — the `update storage.buckets set public = false` /
# `on conflict … do update set public = false` form. This is the real "bucket is private"
# signal, and it is what the old suppressor was reaching for.
#
# That suppressor was `\bpublic\b.*\bfalse\b` under DOTALL, so ANY `false` token appearing
# later in the same statement silenced the finding — including one belonging to a completely
# different column. A real public-bucket insert followed by
# `on conflict (id) do update set avif_autodetection = false` went silent, and
# `avif_autodetection` is a genuine `storage.buckets` column, so this is ordinary SQL rather
# than a crafted case (#437 review). It also defeated this PR's own new multi-line support,
# because spanning more of the statement only gave the stray `false` more places to hide.
_SQL_PUBLIC_EQ_FALSE = re.compile(r"\bpublic\s*=\s*false\b", re.IGNORECASE)
# `insert into storage.buckets (…cols…) values (…vals…)` — read the value sitting in the same
# position as the `public` column instead of guessing from loose keyword adjacency.
_SQL_INSERT_COLS_VALUES = re.compile(
    r"insert\s+into\s+storage\s*\.\s*buckets\s*\(([^()]*)\)\s*values\s*\(([^()]*)\)",
    re.IGNORECASE | re.DOTALL,
)


def _insert_public_value(stmt: str) -> bool | None:
    """The `public` column's value in a positional bucket INSERT, or None if undeterminable.

    Column lists and VALUES tuples are positional, so the only correct read is by index. Falls
    back to None (caller keeps its keyword heuristic) on any shape this cannot parse — nested
    parens in the values tuple, a multi-row insert, a select-based insert."""
    m = _SQL_INSERT_COLS_VALUES.search(stmt)
    if not m:
        return None
    cols = [c.strip().strip('"').lower() for c in m.group(1).split(",")]
    vals = [v.strip().lower() for v in m.group(2).split(",")]
    if len(cols) != len(vals) or "public" not in cols:
        return None
    val = vals[cols.index("public")]
    if val == "true":
        return True
    if val == "false":
        return False
    return None


def _sql_statements(clean: str) -> list[tuple[int, str]]:
    """Split comment-stripped SQL into ;-separated statements, quote-aware.

    A `;` inside a '...'/"..." string literal does not end a statement (#437 review
    High-3: a naive split fragments a real bucket INSERT whose name/description value
    contains `;`, and no fragment then carries all three required signals). SQL's ''
    escape needs no special casing here: the scanner closes and immediately reopens the
    string, which classifies every `;` between the quotes as in-string either way.
    Returns (lineno, statement_text) pairs, where lineno is the 1-based line of the
    statement's first non-blank character. Statement-level evaluation keeps adjacent
    statements isolated while allowing one statement to span multiple lines."""
    out: list[tuple[int, str]] = []

    def _emit(start: int, end: int, start_line: int) -> None:
        stmt = clean[start:end]
        if stmt.strip():
            leading = stmt[: len(stmt) - len(stmt.lstrip())]
            out.append((start_line + leading.count("\n"), stmt))

    in_str = ""
    start = 0
    start_line = 1
    line = 1
    for i, ch in enumerate(clean):
        if ch == "\n":
            line += 1
        elif in_str:
            if ch == in_str:
                in_str = ""
        elif ch in "'\"":
            in_str = ch
        elif ch == ";":
            _emit(start, i, start_line)
            start = i + 1
            start_line = line
    _emit(start, len(clean), start_line)
    return out

# Python: supabase.storage().create_bucket( call
_PY_CREATE_BUCKET = re.compile(
    r"""supabase\s*\.\s*storage\s*\(\s*\)\s*\.\s*create_bucket\s*\(""",
    re.IGNORECASE,
)

# Python/JS: {"public": true} or public=True inside the options
_PY_PUBLIC_TRUE = re.compile(
    r"""(?:["']public["']\s*:\s*True\b|(?<!\w)public\s*=\s*True\b)""",
)

# JS: createBucket( call
_JS_CREATE_BUCKET = re.compile(
    r"""\bcreate[Bb]ucket\s*\(""",
)

# JS: { "public": true } (lowercase true, as in JS)
_JS_PUBLIC_TRUE = re.compile(
    r"""["']public["']\s*:\s*true\b""",
)


class SupabaseStoragePublicGuard(Guard):
    id = "supabase-storage-public"
    title = "Supabase storage bucket configured as public (unauthenticated read access)"
    area = "Database"
    # NOT `schema_state`: the SQL rule matches bucket DML (`INSERT INTO storage.buckets
    # ... public = true`), and a schema-only dump carries no rows — nothing would re-flag
    # a demoted public bucket at full priority. Default False = keeps gating.

    # sql/storage_buckets.sql: INSERT into storage.buckets with public = true.
    # Must NOT contain: security: allow-public-bucket (pragma silences guard repo-wide).
    canary_plant = CanaryPlant(
        files={
            "sql/storage_buckets.sql": (
                "INSERT INTO storage.buckets (id, name, public) VALUES ('uploads', 'uploads', true);\n"
            ),
        },
        expects=frozenset({"supabase-storage-public/public-storage-bucket"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []

        # --- SQL migrations ---------------------------------------------------
        for f in iter_files(root, (".sql",)):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            clean = strip_sql_comments(text)
            for lineno, stmt in _sql_statements(clean):
                # Decide from the `public` column's ACTUAL value where that is knowable, and
                # only fall back to keyword adjacency when it is not.
                positional = _insert_public_value(stmt)
                if positional is None:
                    public_is_on = bool(
                        _SQL_HAS_PUBLIC.search(stmt)
                        and _SQL_HAS_TRUE.search(stmt)
                        and not _SQL_PUBLIC_EQ_FALSE.search(stmt)
                    )
                else:
                    public_is_on = positional and not _SQL_PUBLIC_EQ_FALSE.search(stmt)
                if _SQL_BUCKET_WRITE.search(stmt) and public_is_on:
                    findings.append(self._make_finding(
                        root, f, lineno,
                        "SQL migration creates a public storage bucket",
                    ))
                    break  # one finding per file for SQL is enough

        # --- Python files -----------------------------------------------------
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    if _PY_CREATE_BUCKET.search(line) and _PY_PUBLIC_TRUE.search(line):
                        findings.append(self._make_finding(
                            root, f, lineno,
                            "Python call creates a public Supabase storage bucket",
                        ))
                        break  # one finding per file

        # --- JavaScript / TypeScript files ------------------------------------
        for f in iter_files(root, (".js", ".ts", ".jsx", ".tsx")):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if _JS_CREATE_BUCKET.search(line) and _JS_PUBLIC_TRUE.search(line):
                    findings.append(self._make_finding(
                        root, f, lineno,
                        "JS/TS call creates a public Supabase storage bucket",
                    ))
                    break

        return findings

    def _make_finding(
        self,
        root: Path,
        f: Path,
        lineno: int,
        title: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "A Supabase storage bucket is being created with `public = true`. "
                "Every file in this bucket is accessible via an unauthenticated HTTP GET "
                "request — no JWT, no RLS policy, no signed URL is required. User-uploaded "
                "content (photos, documents, PII) is exposed to the open internet."
            ),
            remediation=(
                "Remove `public = true` (or set it to `false`). Use Supabase signed URLs "
                "(`storage.from_('bucket').create_signed_url(path, expires_in)`) to grant "
                "time-limited read access, or configure Storage RLS policies to restrict "
                "reads to authenticated users. If the bucket is intentionally public "
                "(e.g. a CDN bucket for static assets with no user data), suppress with "
                "`# security: allow-public-bucket`."
            ),
            rule="supabase-storage-public/public-storage-bucket",
            standards=list(_STANDARDS),
        )
