"""Guard: Supabase storage bucket marked private (`public = false`) with no matching
`CREATE POLICY ... ON storage.objects` anywhere in the scanned SQL (checklist
7-storage-objects-no-rls).

`storage.objects` carries its **own, separate** RLS policy set from the bucket's
`public`/`private` flag. Marking a bucket `public = false` only stops the anonymous
`.../storage/v1/object/public/<bucket>/<file>` URL shortcut checked by
`supabase_storage_public.py` (a DIFFERENT guard, a DIFFERENT gap) — it says nothing
about whether `storage.objects` itself grants any access at all. Supabase migrations
enable RLS on `storage.objects` by default, so a private bucket with zero policies
referencing it ends up in one of two bad states:

  * **RLS enforced, no matching policy** — Postgres denies every SELECT/INSERT/UPDATE/
    DELETE by default. This is usually an accidental lockout: the developer marked the
    bucket private and stopped, assuming that alone restricts access, and never wrote
    the policy that would actually let anyone (including the app's own authenticated
    users) read or write to it.
  * **RLS not enforced on that table** — the bucket is wide open to any request that
    reaches `storage.objects` directly, despite `public = false` looking safe in the
    bucket config. `public=false` is cosmetic without a policy backing it.

Either way, "private-looking bucket, zero object-level policies" is a genuine RLS-
coverage gap distinct from the already-covered `supabase-storage-public` bucket-flag
check.

Detect: scan Supabase migration SQL (the primary, most attributable source for this
signal) for `storage.buckets` writes that explicitly set `public = false` for a named
bucket id, and for `CREATE POLICY ... ON storage.objects` statements. A policy is
credited to a bucket when it filters on `bucket_id = '<id>'`, `bucket_id IN (...)`, or
the folder-path convention `(storage.foldername(name))[1] = '<id>'`. A policy with NO
bucket_id filter at all applies to every bucket and silences the whole guard (a
deliberately global policy is a legitimate, if broad, mitigation).

Scope, deliberately narrower than a "cross-language" reading of the source candidate:
SQL migrations only, not the Python/JS/TS storage-client SDK calls
`supabase_storage_public.py` also scans. A bucket created via `create_bucket(...)` in
application code has no reliable, low-FP way to cross-reference against a SQL policy's
`bucket_id` literal — the bucket name/id lives in a different file, a different
language, and often a runtime variable. Narrowing to SQL keeps both signals (bucket
definition, policy scope) in the same well-structured, statically-parseable source,
which is what keeps the false-positive rate low on a "prove a mitigation is ABSENT"
check.

A bucket whose `public` value is contradicted across migrations (declared both `true`
and `false` at different points) is treated as ambiguous and is NOT flagged.

Suppress with `-- security: allow-storage-no-rls` anywhere in the file that declares
the bucket. Use when the bucket is intentionally policy-less (e.g. all access goes
through the service-role key, never through `storage.objects` RLS).

OWASP:A01, CIS:6.3.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_reference_sql_path,
    iter_files,
    iter_statement_spans,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)

_PRAGMA = "security: allow-storage-no-rls"

_STANDARDS = ["OWASP:A01", "CIS:6.3"]

# --- bucket definitions: INSERT INTO storage.buckets(...) / UPDATE storage.buckets SET ---------

_BUCKET_STMT_HEAD = re.compile(
    r"insert\s+into\s+storage\s*\.\s*buckets\b|update\s+storage\s*\.\s*buckets\s+set\b",
    re.IGNORECASE,
)
_IS_UPDATE_STMT = re.compile(r"^\s*update\b", re.IGNORECASE)

# insert into storage.buckets (id, name, public, ...) values ('x', 'x', false, ...) — positional,
# same limitation as supabase_storage_public.py's _SQL_INSERT_COLS_VALUES: no nested parens, no
# multi-row insert, no select-based insert. Falls back to "undeterminable" on those shapes rather
# than guessing.
_INSERT_COLS_VALUES = re.compile(
    r"insert\s+into\s+storage\s*\.\s*buckets\s*\(([^()]*)\)\s*values\s*\(([^()]*)\)",
    re.IGNORECASE | re.DOTALL,
)


def _insert_id_and_public(stmt: str) -> tuple[str | None, bool | None]:
    """The bucket `id` and `public` column values from a positional bucket INSERT, or
    (None, None)/partial on any shape this cannot parse by index."""
    m = _INSERT_COLS_VALUES.search(stmt)
    if not m:
        return None, None
    cols = [c.strip().strip('"').lower() for c in m.group(1).split(",")]
    vals = [v.strip() for v in m.group(2).split(",")]
    if len(cols) != len(vals):
        return None, None
    bucket_id: str | None = None
    if "id" in cols:
        raw = vals[cols.index("id")].strip().strip("'\"").lower()
        bucket_id = raw or None
    public_val: bool | None = None
    if "public" in cols:
        v = vals[cols.index("public")].strip().lower()
        if v == "true":
            public_val = True
        elif v == "false":
            public_val = False
    return bucket_id, public_val


# update storage.buckets set ... public = false ... where id = 'x' — both signals must be
# present in the same (already statement-bounded) span.
_UPDATE_PUBLIC_VALUE = re.compile(r"\bpublic\s*=\s*(true|false)\b", re.IGNORECASE)
_UPDATE_WHERE_ID = re.compile(r"\bid\s*=\s*'([^']*)'", re.IGNORECASE)


def _update_id_and_public(stmt: str) -> tuple[str | None, bool | None]:
    pub_m = _UPDATE_PUBLIC_VALUE.search(stmt)
    id_m = _UPDATE_WHERE_ID.search(stmt)
    if pub_m is None or id_m is None:
        return None, None
    bucket_id = id_m.group(1).strip().lower() or None
    return bucket_id, pub_m.group(1).lower() == "true"


# --- storage.objects policies ---------------------------------------------------------

_CREATE_POLICY_HEAD = re.compile(r"create\s+policy\b", re.IGNORECASE)
_ON_STORAGE_OBJECTS = re.compile(r"\bon\s+storage\s*\.\s*objects\b", re.IGNORECASE)
_BUCKET_ID_EQ = re.compile(r"bucket_id\s*=\s*'([^']*)'", re.IGNORECASE)
_BUCKET_ID_IN = re.compile(r"bucket_id\s+in\s*\(([^)]*)\)", re.IGNORECASE)
_FOLDERNAME_BUCKET = re.compile(
    r"storage\s*\.\s*foldername\s*\(\s*name\s*\)\s*\)\s*\[\s*1\s*\]\s*=\s*'([^']*)'",
    re.IGNORECASE,
)


def _policy_bucket_refs(stmt: str) -> tuple[set[str], bool]:
    """Bucket ids a `storage.objects` `CREATE POLICY` statement scopes itself to, and
    whether it applies globally (no `bucket_id` filter at all -- covers every bucket)."""
    ids: set[str] = set()
    for m in _BUCKET_ID_EQ.finditer(stmt):
        ids.add(m.group(1).strip().lower())
    for m in _BUCKET_ID_IN.finditer(stmt):
        for piece in m.group(1).split(","):
            piece = piece.strip().strip("'\"")
            if piece:
                ids.add(piece.lower())
    for m in _FOLDERNAME_BUCKET.finditer(stmt):
        ids.add(m.group(1).strip().lower())
    return ids, not ids


class StorageNoRlsGuard(Guard):
    id = "storage-no-rls"
    title = "Supabase storage bucket is private with no storage.objects RLS policy referencing it"
    area = "Database"
    # NOT `schema_state`: the finding anchors on the bucket's DML declaration, which a
    # schema-only dump does not reproduce (the `CREATE POLICY` rules here are the minority).
    # Default False = keeps gating.

    # sql/storage_buckets_private.sql: a bucket created with public = false and NO
    # accompanying `CREATE POLICY ... ON storage.objects` referencing it anywhere in the
    # assembled canary -> fires storage-no-rls/private-bucket-no-object-policy.
    # CRITICAL: no CREATE POLICY ... ON storage.objects referencing 'canary-private-docs'
    # (or a bucket-unscoped storage.objects policy) may appear in ANY sql file in the canary.
    canary_plant = CanaryPlant(
        files={
            "sql/storage_buckets_private.sql": (
                "INSERT INTO storage.buckets (id, name, public) "
                "VALUES ('canary-private-docs', 'canary-private-docs', false);\n"
            ),
        },
        expects=frozenset({"storage-no-rls/private-bucket-no-object-policy"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        files = [
            f for f in iter_files(sql_dir, (".sql",))
            if not is_reference_sql_path(rel(root, f))
        ]
        if not files:
            return []

        file_texts: list[tuple[Path, str]] = [(f, read(f)) for f in files]

        # Pass 1: collect every storage.objects policy's bucket scoping, across ALL files —
        # a bucket may be defined in one migration and policed in a later one.
        covered_bucket_ids: set[str] = set()
        global_policy = False
        for _f, text in file_texts:
            stripped = strip_sql_comments(text)
            for start, end in iter_statement_spans(stripped, _CREATE_POLICY_HEAD):
                stmt = stripped[start:end]
                if not _ON_STORAGE_OBJECTS.search(stmt):
                    continue
                ids, is_global = _policy_bucket_refs(stmt)
                covered_bucket_ids |= ids
                if is_global:
                    global_policy = True

        if global_policy:
            # A bucket-unscoped policy on storage.objects covers every bucket — a
            # deliberate, broad mitigation. Nothing left to flag.
            return []

        # Pass 2: collect private-bucket declarations. A bucket whose public value is
        # contradicted across migrations is ambiguous and is never flagged.
        private_buckets: dict[str, tuple[str, Path]] = {}
        public_buckets: set[str] = set()
        pragma_files: set[Path] = set()
        for f, text in file_texts:
            if pragma_present(_PRAGMA, text, dialect="sql"):
                pragma_files.add(f)
            stripped = strip_sql_comments(text)
            for start, end in iter_statement_spans(stripped, _BUCKET_STMT_HEAD):
                stmt = stripped[start:end]
                if _IS_UPDATE_STMT.match(stmt.lstrip()):
                    bucket_id, public_val = _update_id_and_public(stmt)
                else:
                    bucket_id, public_val = _insert_id_and_public(stmt)
                if bucket_id is None or public_val is None:
                    continue
                if public_val:
                    public_buckets.add(bucket_id)
                else:
                    private_buckets.setdefault(bucket_id, (rel(root, f), f))

        out: list[Finding] = []
        for bucket_id, (loc, f) in sorted(private_buckets.items()):
            if bucket_id in public_buckets:
                continue  # contradictory across migrations -- ambiguous, stay silent
            if bucket_id in covered_bucket_ids:
                continue
            if f in pragma_files:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=loc,
                    message=(
                        f"Storage bucket `{bucket_id}` is created with `public = false`, "
                        "but no `CREATE POLICY ... ON storage.objects` anywhere in the "
                        "scanned SQL references it. `storage.objects` carries its own RLS "
                        "policy set, separate from the bucket's `public` flag: with RLS "
                        "enabled on that table (the Supabase default) and no matching "
                        "policy, every read and write against this bucket is silently "
                        "blocked -- an accidental lockout. If RLS is somehow not enforced "
                        "on `storage.objects`, the opposite is true and the bucket is wide "
                        "open despite looking private."
                    ),
                    remediation=(
                        f"Add at least one `CREATE POLICY ... ON storage.objects` scoped "
                        f"to `bucket_id = '{bucket_id}'` (or a `storage.foldername(name)` "
                        "path-based policy) granting the intended access. If this bucket "
                        "is intentionally policy-less (e.g. accessed only via the "
                        "service-role key, never through `storage.objects` RLS), suppress "
                        "with `-- security: allow-storage-no-rls`."
                    ),
                    rule="storage-no-rls/private-bucket-no-object-policy",
                    standards=list(_STANDARDS),
                )
            )
        return out
