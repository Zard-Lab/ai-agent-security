"""Guard: every table in an API-exposed schema must enable RLS.

Ported from donor `scripts/security/check_public_table_rls.py`, then **broadened
beyond `public`**. DB-independent, order-independent: parses CREATE / DROP /
ENABLE-RLS / SET-SCHEMA from the sql files. A table is a violation iff it is
created in an **API-exposed** schema AND never RLS-enabled AND never dropped AND
never moved out of that schema.

**Why "exposed", not just `public`.** Supabase's Data API (PostgREST) serves any
schema listed in `pgrst.db_schemas` on the `authenticator` role — not only
`public`. A repo that moves a domain into its own schema (e.g. `workbook`) and
grants it to `anon`/`authenticated` exposes those tables to the anon key exactly
like `public`. Splinter's `rls_disabled_in_public` lint gates on
`current_setting('pgrst.db_schemas')`, so it silently misses these when run as a
role where that GUC is empty (see docs/knowledge/exposed-schema-rls-blind-spot.md).
We detect the exposed-schema set from executable SQL (`GRANT … TO anon/
authenticated`, plus any literal `pgrst.db_schemas='…'`) and flag RLS-off tables
in *any* of them. Tables in a non-exposed schema (e.g. an internal `private`
schema, `auth`, `storage`) are NOT flagged — they are not reachable by the API.

**Schema-variant aware.** Many repos ship *two* install paths: granular
per-feature migrations (`1-...sql`, `2-...sql`, …) **and** a consolidated bundle
(`0-all-tables.sql`) that re-creates everything. Those are mutually exclusive —
you run one or the other. Naively aggregating every file lets an `ENABLE` in the
bundle excuse a `CREATE` in the granular path (a false negative: the granular
deploy actually leaves the table exposed). So we split files into *variants* —
the granular set as one combined path, plus each consolidated bundle as its own
path — and flag a table if it is unprotected in **any** variant. (Validated:
this is exactly how `9_Agent_SaaS` leaves `documents` / `document_metadata` /
`document_rows` exposed on the granular path while the bundle protects them.)
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel, strip_sql_comments

_CREATE = re.compile(
    r'create\s+table\s+(?:if\s+not\s+exists\s+)?(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?', re.I
)
_DROP = re.compile(
    r'drop\s+table\s+(?:if\s+exists\s+)?(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?', re.I
)
_ENABLE_RLS = re.compile(
    r'alter\s+table\s+(?:if\s+exists\s+)?(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?\s+enable\s+row\s+level\s+security',
    re.I,
)
_SET_SCHEMA = re.compile(
    r'alter\s+table\s+(?:if\s+exists\s+)?(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?\s+set\s+schema\s+"?(?P<target>\w+)"?',
    re.I,
)

# Exposed-schema detection (all over comment-stripped SQL).
_ANON_AUTH = re.compile(r"\b(anon|authenticated)\b", re.I)
_GRANT_SCHEMA_USAGE = re.compile(
    r"grant\s+usage\s+on\s+schema\s+(?P<schema>\"?\w+\"?)\s+to\s+(?P<roles>[^;]+)", re.I
)
# The privilege list between `grant` and `on` is length-capped: an UNbounded lazy
# `[\w\s,]+?` re-scans from every `grant` token inside one long word/space run —
# quadratic on hostile SQL (issue #419). A real privilege list ("SELECT, INSERT, …")
# is far under 400 chars, so the cap changes no legitimate match.
_GRANT_ALL_TABLES = re.compile(
    r"grant\b[\w\s,]{1,400}?\bon\s+all\s+tables\s+in\s+schema\s+(?P<schema>\"?\w+\"?)\s+to\s+(?P<roles>[^;]+)",
    re.I,
)
_GRANT_TABLE = re.compile(
    r"grant\b[\w\s,]{1,400}?\bon\s+(?:table\s+)?(?P<schema>\"?\w+\"?)\.(?P<name>\"?\w+\"?)\s+to\s+(?P<roles>[^;]+)",
    re.I,
)
_PGRST_DB_SCHEMAS = re.compile(r"pgrst\.db_schemas\s*=\s*'(?P<list>[^']*)'", re.I)

# A file is treated as a "consolidated bundle" (an alternative full-schema install
# path) when it re-creates at least this many tables that are *also* created in
# other files. Below this, a multi-table file is just a normal migration.
_BUNDLE_MIN_DUP_TABLES = 3


def _norm(token: str | None, default: str = "public") -> str:
    return token.strip('"').lower() if token else default


def _qual(schema: str | None, name: str) -> str:
    """Schema-qualified, lowercased table key (unqualified → public)."""
    return f"{_norm(schema)}.{_norm(name)}"


def _schema_of(qkey: str) -> str:
    return qkey.split(".", 1)[0]


def detect_exposed_schemas(texts: list[str], *, data_api_default_public: bool = True) -> set[str]:
    """The set of PostgREST-exposed schemas inferred from executable SQL.

    `public` is the Data API default **only when the repo actually has a PostgREST/Supabase Data API
    surface** (`data_api_default_public=True`). Without one — a plain-Postgres app behind a privileged
    `pg`/driver connection, no anon key — the `public` schema is NOT anon-reachable, so RLS is not the
    applicable control and its tables must not be flagged (round-2 §D.4). Regardless of that default, a
    schema (including `public`) is treated as exposed when it (or a table in it) is GRANTed to `anon`/
    `authenticated`, or when it appears in a literal `pgrst.db_schemas='…'` setting — so a self-hosted
    PostgREST that explicitly grants `public` to anon is still caught. Comment-only documentation of the
    exposed list is NOT seen (callers pass comment-stripped text), so GRANTs are the reliable signal.
    """
    exposed = {"public"} if data_api_default_public else set()
    for text in texts:
        for m in _GRANT_SCHEMA_USAGE.finditer(text):
            if _ANON_AUTH.search(m.group("roles")):
                exposed.add(_norm(m.group("schema")))
        for m in _GRANT_ALL_TABLES.finditer(text):
            if _ANON_AUTH.search(m.group("roles")):
                exposed.add(_norm(m.group("schema")))
        for m in _GRANT_TABLE.finditer(text):
            if _ANON_AUTH.search(m.group("roles")):
                exposed.add(_norm(m.group("schema")))
        for m in _PGRST_DB_SCHEMAS.finditer(text):
            for s in m.group("list").split(","):
                if s.strip():
                    exposed.add(s.strip().strip('"').lower())
    return exposed


@dataclass
class _FileFacts:
    """What one .sql file does, keyed by schema-qualified table name."""

    path: Path
    created: set[str] = field(default_factory=set)
    rls: set[str] = field(default_factory=set)
    dropped: set[str] = field(default_factory=set)
    moved_out: set[str] = field(default_factory=set)


@dataclass
class _Variant:
    """One coherent install path (the granular set, or a single bundle file)."""

    label: str
    location: str
    created: set[str] = field(default_factory=set)
    rls: set[str] = field(default_factory=set)
    dropped: set[str] = field(default_factory=set)
    moved_out: set[str] = field(default_factory=set)

    def unprotected(self) -> set[str]:
        return self.created - self.rls - self.dropped - self.moved_out


def _parse(text: str, path: Path) -> _FileFacts:
    facts = _FileFacts(path=path)
    for m in _CREATE.finditer(text):
        facts.created.add(_qual(m.group("schema"), m.group("name")))
    for m in _ENABLE_RLS.finditer(text):
        facts.rls.add(_qual(m.group("schema"), m.group("name")))
    for m in _DROP.finditer(text):
        facts.dropped.add(_qual(m.group("schema"), m.group("name")))
    for m in _SET_SCHEMA.finditer(text):
        src = _norm(m.group("schema"))
        if _norm(m.group("target")) != src:
            facts.moved_out.add(_qual(m.group("schema"), m.group("name")))
    return facts


def _build_variants(root: Path, sql_dir: Path, facts: list[_FileFacts]) -> list[_Variant]:
    """Split `facts` into coherent install-path variants (the granular set, plus each
    consolidated bundle as its own variant) — see the module docstring's "Schema-variant aware"
    section. Module-level (not a method): `detect_exposed_schemas` was already extracted this way
    for the same reason (PR #742 review, Major 2) — `supabase_anon_key_rls_reachable.py` needs the
    identical variant-aware machinery, not a simplified reimplementation the two guards could
    silently disagree with."""
    create_counts: Counter[str] = Counter()
    for f in facts:
        create_counts.update(f.created)

    bundles: list[_FileFacts] = []
    granular: list[_FileFacts] = []
    for f in facts:
        dup = sum(1 for t in f.created if create_counts[t] > 1)
        is_bundle = dup >= _BUNDLE_MIN_DUP_TABLES and dup >= len(f.created) / 2
        (bundles if is_bundle else granular).append(f)

    variants: list[_Variant] = []
    if granular:
        combined = _Variant(label="the granular migration set", location=f"{rel(root, sql_dir)}/")
        for f in granular:
            combined.created |= f.created
            combined.rls |= f.rls
            combined.dropped |= f.dropped
            combined.moved_out |= f.moved_out
        variants.append(combined)
    for f in bundles:
        loc = rel(root, f.path)
        variants.append(
            _Variant(
                label=f"`{loc}`", location=loc,
                created=f.created, rls=f.rls, dropped=f.dropped, moved_out=f.moved_out,
            )
        )
    return variants


def rls_gap_tables(root: Path, sql_dir: Path, profile: StackProfile) -> dict[str, str]:
    """Schema-qualified table name -> its own file location, for every table exposed via ANY
    install-path variant with RLS never enabled in that variant — the exact set
    `PublicTableRlsGuard.run()` flags, factored out (PR #742 review, Major 2) so
    `supabase_anon_key_rls_reachable.py`'s correlation reuses the real variant-aware analysis
    instead of a simplified, non-variant-aware reimplementation that silently missed the
    granular-vs-bundle case this guard's own docstring cites as its reason to exist.
    `elsewhere`-protected tables (RLS enabled in a DIFFERENT variant) are correctly still
    returned here — a table exposed in the granular path is a real gap on that deploy path,
    regardless of what the bundle path does."""
    sql_files = list(iter_files(sql_dir, (".sql",)))
    texts = [strip_sql_comments(read(f)) for f in sql_files]
    facts = [_parse(t, f) for t, f in zip(texts, sql_files, strict=True)]
    if not facts:
        return {}
    exposed = detect_exposed_schemas(texts, data_api_default_public="supabase" in profile.features)
    variants = _build_variants(root, sql_dir, facts)
    gap: dict[str, str] = {}
    for v in variants:
        for t in v.unprotected():
            if _schema_of(t) in exposed and t not in gap:
                gap[t] = v.location
    return gap


class PublicTableRlsGuard(Guard):
    id = "public-table-rls"
    title = "Exposed-schema table created without RLS"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which nine guards trip at once, so that file stays in `canary.py`'s base
    # owned by no guard. This guard anchors its finding at the DIRECTORY `sql/`, so it has no
    # `_BASE_FILES` key of its own to move (the batch-9 trap). The ownership rule this follows is
    # documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"public-table-rls/rls-disabled-in-public"}))

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        sql_files = list(iter_files(sql_dir, (".sql",)))
        texts = [strip_sql_comments(read(f)) for f in sql_files]
        facts = [_parse(t, f) for t, f in zip(texts, sql_files, strict=True)]
        if not facts:
            return []

        # `public` is anon-reachable by default only under a PostgREST/Supabase Data API. Without one
        # (a plain-Postgres app), its tables are not anon-exposed and RLS is not the applicable control
        # (round-2 §D.4). An explicit `GRANT … TO anon` still exposes a schema on any stack.
        exposed = detect_exposed_schemas(texts, data_api_default_public="supabase" in profile.features)
        variants = _build_variants(root, sql_dir, facts)
        # A table protected in some *other* variant is the false-negative case
        # the naive aggregate used to miss — call it out specifically.
        protected_anywhere: set[str] = set()
        for v in variants:
            protected_anywhere |= v.rls | v.dropped | v.moved_out

        flagged: dict[str, _Variant] = {}
        withheld: set[str] = set()
        for v in variants:
            for t in v.unprotected():
                if _schema_of(t) in exposed:  # only API-reachable schemas are a risk
                    flagged.setdefault(t, v)
                else:
                    withheld.add(t)

        out = [
            self._finding(t, v, elsewhere=t in protected_anywhere)
            for t, v in sorted(flagged.items())
        ]
        # NOT-ANALYSED disclosure. The Data-API gate suppresses the whole guard when no
        # PostgREST/Supabase surface is detected — but `applies()` still returned True, so the guard
        # ran, returned nothing, and the report showed a PASSING check on a repo whose RLS was never
        # actually assessed. A detection miss (there are many possible Supabase project shapes) then
        # reads as a green light (#481 review). Say so instead: one `info` finding naming the tables
        # whose exposure could not be determined.
        if withheld and not exposed:
            out.append(self._not_analysed(root, sql_dir, sorted(withheld)))
        return out

    def _not_analysed(self, root: Path, sql_dir: Path, tables: list[str]) -> Finding:
        shown = ", ".join(f"`{t}`" for t in tables[:5])
        more = f" (+{len(tables) - 5} more)" if len(tables) > 5 else ""
        return Finding(
            check_id=self.id,
            severity="info",
            title="RLS not assessed — no Data API surface detected",
            location=f"{rel(root, sql_dir)}/",
            message=(
                f"{len(tables)} table(s) without RLS were found ({shown}{more}), but no "
                "PostgREST/Supabase Data API surface was detected for this repo, so they are not "
                "treated as anon-reachable and no finding was raised. This is NOT a pass: if the "
                "app does expose a Data API (a Supabase project shape detection missed, a "
                "self-hosted PostgREST, or an API gateway over the database), every one of these "
                "tables is readable by any client holding the anon key."
            ),
            remediation=(
                "Confirm how the database is reached. If there is a Data API, enable RLS on these "
                "tables (`ALTER TABLE … ENABLE ROW LEVEL SECURITY` plus policies) and re-run — the "
                "guard will then flag them as findings. If the database is only reachable through "
                "a privileged server-side connection, no action is needed."
            ),
            rule="public-table-rls/not-analysed-no-data-api",
            standards=["OWASP:A01", "OWASP-LLM:LLM08"],
        )

    def _finding(self, table: str, variant: _Variant, *, elsewhere: bool) -> Finding:
        if elsewhere:
            message = (
                f"`{table}` is created in {variant.label} but never "
                f"`ENABLE ROW LEVEL SECURITY` there — RLS is only enabled in a different "
                f"schema variant (e.g. a consolidated bundle), so deploying {variant.label} "
                f"leaves it reachable by the anon key."
            )
        else:
            message = (
                f"`{table}` is created in an API-exposed schema but never "
                f"`ENABLE ROW LEVEL SECURITY` — reachable by the anon key."
            )
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=variant.location,
            message=message,
            remediation=(
                f"`ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;` (+ policies) in that "
                "install path, or drop it, or move it to a non-exposed schema, or allowlist with a reason."
            ),
            rule="public-table-rls/rls-disabled-in-public",
            standards=["OWASP:A01", "OWASP-LLM:LLM08"],
        )
