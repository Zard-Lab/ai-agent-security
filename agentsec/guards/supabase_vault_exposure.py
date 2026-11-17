"""Guard: Supabase Vault material reachable by anon/authenticated (§7, Database Security).

Supabase Vault (`supabase_vault`) stores secrets encrypted in `vault.secrets` and decrypts them at
query time in the `vault.decrypted_secrets` view. Apps wrap it in the PostgREST-exposed schema: a
view over `vault.decrypted_secrets` (`public.api_keys_with_secrets`) and `SECURITY DEFINER` RPCs
that read or write the vault (`public.read_secret_logged(uuid)`). In an exposed schema those
objects' grants are the only thing between `anon`/`authenticated` and plaintext secrets.

Two Supabase facts drive every rule here:

* **Default privileges re-expose every new object.** Supabase's `pg_default_acl` in `public`
  grants `anon` and `authenticated` all privileges on new tables and views and EXECUTE on new
  functions, and Postgres also grants EXECUTE on every new function to `PUBLIC`. So
  `REVOKE … FROM PUBLIC` alone leaves anon and authenticated their DIRECT grant, and a
  `DROP` + `CREATE` resets the object's ACL to those defaults. (`CREATE OR REPLACE` keeps it.)
* **A definer FUNCTION is the crown jewel; a definer VIEW is defence in depth.** On vault 0.3.x
  the decrypt step is `vault._crypto_aead_det_decrypt(...)`, whose EXECUTE Postgres checks
  against the CALLING role even through an owner-rights view, so an anon grant on a definer view
  fails with `permission denied for function _crypto_aead_det_decrypt` (measured on a live
  project). A `SECURITY DEFINER` function runs as its owner, who holds that EXECUTE, so an
  anon-executable vault-reading RPC returns every secret. The older pgsodium-based vault (0.2.x)
  has no such gate, so view exposure is still HIGH.

Rules (`supabase-vault-exposure/<rule>`):

  **`definer-function-executable`** (CRITICAL): a `SECURITY DEFINER` function in an exposed schema
  whose BODY touches vault material is executable by `PUBLIC`, `anon` or `authenticated`. Vault
  material is detected in the body, never by the function's name: `vault.decrypted_secrets`,
  `vault.secrets`, `vault.create_secret`, `vault.update_secret`, `vault._crypto_aead_det_decrypt`,
  or (transitively) a view or function this guard already classified as vault material.

  **`decrypted-view-readable`** (HIGH): a view or materialized view in an exposed schema that
  reads `vault.decrypted_secrets` (directly or through another such view), is not
  `security_invoker`, and is readable by `anon` or `authenticated`.

  **`recreated-without-revoke`** (CRITICAL for a function, HIGH for a view): a file DROPs one of
  the two objects above and re-CREATEs it, so its ACL is reset to the defaults, and neither that
  file (after the CREATE) nor any file sorting after it revokes the required roles again.

  **`definer-search-path-writable`** (LOW): a vault-material definer function pins `search_path`
  to something other than empty / `pg_catalog` / `pg_temp` (e.g. `public, vault`). Unpinned is
  left to `pg-function-search-path`. Low because Supabase on PG15+ revokes CREATE on `public` from
  anon/authenticated; it is a hardening signal, not a proven hole.

Everything here is ACL state on `public` objects that a pg_dump of the app schema reproduces
(`schema_state = True`). Vault exposure a dump cannot vouch for (a literal secret committed in SQL,
statement logging, `vault` in the exposed-schema list, a grant on the `vault` schema itself, which a
`supabase db dump` of the app schema need not carry) is `supabase_vault_plaintext_leak.py`, which a
dump must never demote.

**Privileges.** A GRANT or REVOKE counts for an object only when it names a privilege that reaches
it: EXECUTE/ALL on a function, SELECT/ALL on a relation (a granted column-level `SELECT (col)` also
reaches; a revoked one leaves the table-level grant). So `GRANT INSERT ON v TO anon` does not make
`v` readable, and `REVOKE INSERT, UPDATE, DELETE ON v` does not stop it being read.

**Bulk ACLs.** `GRANT`/`REVOKE … ON ALL FUNCTIONS|ROUTINES|TABLES IN SCHEMA s` reaches only the
objects that exist when it runs, so it counts for an object only when it sits after that object's
FIRST CREATE in the migrations (later in the file, or in a file sorting after it); `CREATE OR
REPLACE` keeps the ACL, so a later replace does not move that point. Bulk statements are NOT
ordered against each other or against per-object ones: like every ACL here they join the
cross-file union.

**Two modes.** A file `sql_state.find_dumps` recognises as a pg_dump spells out the real ACL: there a
function is exposed iff its `REVOKE ALL … FROM PUBLIC` is ABSENT or a GRANT to one of the three
roles is present, and a view is exposed iff such a GRANT is present. Every other `.sql` file is a
migration and Supabase's defaults are assumed, so the object is exposed unless REVOKEs found
anywhere in the repo's migrations cover each required role, and no migration GRANTs one back. The
dynamic DO-loop form `EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon,
authenticated', r.sig)` over an `ARRAY['name', …]` counts as a name-level REVOKE. The guard fails
closed: an unterminated body runs to EOF, and a file not recognised as a dump gets the stricter
migration semantics.

Function keys are overload-aware: `(schema, name, input arg types)`. A REVOKE naming a signature
covers that overload only; a REVOKE with no argument list, or a dynamic loop over names, covers all
of them.

**Suppress:** `-- security: allow-supabase-vault-exposure <reason>` as a comment INSIDE the flagged
statement (its CREATE / GRANT line or any line through its `;`), but outside a function's
dollar-quoted body: a `--` there is part of the body's text, not a SQL comment.

**Checklist item:** `7-supabase-vault-material-exposed` (§7, Database Security).
"""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from itertools import accumulate
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity
from agentsec.sql_state import find_dumps

from .base import (
    CanaryPlant,
    Guard,
    blank_sql_literals,
    find_statement_end,
    is_reference_sql_path,
    iter_files,
    matching_close_paren,
    pragma_line_set,
    read,
    rel,
    split_call_args,
    strip_sql_comments,
)
from .public_table_rls import detect_exposed_schemas

_PRAGMA = "security: allow-supabase-vault-exposure"

_STANDARDS = ["OWASP:A01", "OWASP:A02", "CWE-200", "CWE-732"]

# One title per rule, so a low search-path finding does not read as an exposed secret.
_TITLES = {
    "definer-function-executable": "Vault-reading SECURITY DEFINER function is executable by anon/authenticated",
    "decrypted-view-readable": "View over vault.decrypted_secrets is readable by anon/authenticated",
    "recreated-without-revoke": "Vault object DROPped and re-created without re-revoking anon/authenticated",
    "definer-search-path-writable": "Vault-reading SECURITY DEFINER function pins a writable search_path",
}

_ROLES = frozenset({"public", "anon", "authenticated"})
_FN_REQUIRED = _ROLES
_VIEW_REQUIRED = frozenset({"anon", "authenticated"})

# An identifier: bare, or double-quoted (pg_dump quotes everything). Bounded, so no rescans.
_ID = r'(?:"[^"\n]{1,128}"|[A-Za-z_][\w$]{0,127})'
_QN = rf"{_ID}(?:\s*\.\s*{_ID})?"

_CREATE_FN = re.compile(rf"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?P<name>{_QN})\s*\(", re.I)
_CREATE_VIEW = re.compile(
    rf"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:TEMP|TEMPORARY|RECURSIVE)\s+)?"
    rf"(?:MATERIALIZED\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>{_QN})",
    re.I,
)
_DROP = re.compile(
    rf"\bDROP\s+(?P<kind>FUNCTION|VIEW|MATERIALIZED\s+VIEW)\s+(?:IF\s+EXISTS\s+)?(?P<name>{_QN})\s*(?P<paren>\()?",
    re.I,
)
_DOLLAR_TAG = re.compile(r"(?<![\w$])\$(?:[A-Za-z_]\w{0,63})?\$")
_DO_HEAD = re.compile(r"\bDO\s+(?:LANGUAGE\s+\w+\s+)?(?=\$(?:[A-Za-z_]\w{0,63})?\$)", re.I)
_ACL_HEAD = re.compile(r"\b(?:GRANT|REVOKE)\b", re.I)
_ADP_HEAD = re.compile(r"\bALTER\s+DEFAULT\s+PRIVILEGES\b", re.I)
_ON_KW = re.compile(r"\bON\b", re.I)
_TO_KW = re.compile(r"\bTO\b", re.I)
_FROM_KW = re.compile(r"\bFROM\b", re.I)
_GRANT_KW = re.compile(r"\bGRANT\b", re.I)
_ACL_TARGET = re.compile(rf"\s*(?P<n>{_QN})\s*")
_COMMA = re.compile(r"\s*,\s*")
_ROLE_TAIL = re.compile(r"\bWITH\s+GRANT\b|\bGRANTED\s+BY\b|\bCASCADE\b|\bRESTRICT\b|;", re.I)
_ADP_SCHEMA = re.compile(rf"\bIN\s+SCHEMA\s+(?P<s>{_ID}(?:\s*,\s*{_ID}){{0,32}})", re.I)
_ACL_KIND = re.compile(
    r"\s*(?P<k>(?:ALL\s+(?:TABLES|FUNCTIONS|ROUTINES|PROCEDURES|SEQUENCES)\s+IN\s+SCHEMA|SCHEMA|FUNCTION|"
    r"ROUTINE|PROCEDURE|TABLE|SEQUENCE|FOREIGN\s+TABLE|MATERIALIZED\s+VIEW|VIEW)\b)?\s*",
    re.I,
)
_ALTER_VIEW_SET = re.compile(
    rf"\bALTER\s+(?:MATERIALIZED\s+)?VIEW\s+(?:IF\s+EXISTS\s+)?(?P<name>{_QN})\s+SET\s*\((?P<opts>[^;)]{{0,500}})\)",
    re.I,
)
_ALTER_FN = re.compile(rf"\bALTER\s+FUNCTION\s+(?P<name>{_QN})", re.I)
_INVOKER_ON = re.compile(r"""\bsecurity_invoker"?\s*(?:=\s*'?(?:true|on|yes|1)'?)?\s*(?:[,)]|$)""", re.I)
_SECURITY_INVOKER_CLAUSE = re.compile(r"\bSECURITY\s+INVOKER\b", re.I)
_SEC_DEFINER = re.compile(r"\bSECURITY\s+DEFINER\b", re.I)
_AS_KW = re.compile(r"\bAS\b", re.I)
_SEARCH_PATH = re.compile(r"""\bSET\s+"?search_path"?\s*(?:=|\bTO\b)\s*(?P<val>[^;\n]{0,300})""", re.I)
_PATH_TOKEN = re.compile(r"""'([^'\n]*)'|"([^"\n]*)"|([A-Za-z_$][\w$]*)""")
_PATH_STOP = frozenset({
    "as", "language", "security", "set", "stable", "immutable", "volatile", "cost", "rows", "parallel",
    "strict", "called", "returns", "leakproof", "window", "begin", "support", "from",
})
_SAFE_PATH = frozenset({"", "pg_catalog", "pg_temp"})

# Every (optionally qualified, optionally quoted) name in a body or view definition, and whether it
# is called. One static pattern + set lookups, instead of a regex alternation built per run.
_REF = re.compile(rf"(?<![\w$])(?P<a>{_ID})(?:\s*\.\s*(?P<b>{_ID}))?(?P<call>\s*\()?")
_VAULT_OBJECTS = frozenset(
    ("vault", n) for n in ("decrypted_secrets", "secrets", "create_secret", "update_secret", "_crypto_aead_det_decrypt")
)
_DECRYPTED = ("vault", "decrypted_secrets")
# N/A gate: a qualified `vault.` reference, a `search_path` / `pgrst.db_schemas` that includes vault,
# or the schema itself named in a statement (`ON SCHEMA vault`, `IN SCHEMA public, vault`). A repo
# whose only vault SQL is the grant handing it out is the clearest exposure, not "no Vault".
_ANY_VAULT = re.compile(
    r'(?:"vault"|\bvault)\s*\.|\b(?:search_path|db_schemas)\b[^;\n]{0,300}\bvault\b'
    r'|\bSCHEMA\s+(?:"?\w{1,63}"?\s*,\s*){0,32}"?vault"?(?![\w$])',
    re.I,
)

# The dynamic DO-loop REVOKE (`EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM …', r.sig)`).
_DYNAMIC_REVOKE = re.compile(
    r"\bformat\s*\(\s*'\s*REVOKE\s+(?:ALL(?:\s+PRIVILEGES)?|EXECUTE)\s+ON\s+(?:FUNCTION|ROUTINE)\s+"
    r"%[sIL]\s+FROM\s+(?P<roles>[^'\n]{1,200})'",
    re.I,
)
_ARRAY_LIT = re.compile(r"\bARRAY\s*\[(?P<body>[^\]]{0,4000})\]", re.I)
_ARRAY_NAME = re.compile(r"'(\w{1,128})'")
_NSPNAME = re.compile(r"\bnspname\s*=\s*'(\w{1,128})'", re.I)

# A REVOKE takes away only the privileges it names: `REVOKE INSERT, UPDATE, DELETE ON v` leaves
# SELECT. These are the privileges that make each kind of object reachable.
_REACHING_PRIVS = {"function": frozenset({"all", "execute"}), "relation": frozenset({"all", "select"})}
_BULK_KIND = {"functions": "function", "routines": "function", "tables": "relation"}
_COLUMN_LIST = re.compile(r"\([^()]{0,2000}\)")

_TYPE_ALIASES = {
    "int": "integer", "int4": "integer", "int8": "bigint", "int2": "smallint", "bool": "boolean",
    "varchar": "character varying", "float8": "double precision", "float4": "real",
    "timestamptz": "timestamp with time zone", "timetz": "time with time zone",
}
_MULTIWORD_TYPE_START = frozenset({"character", "double", "timestamp", "time", "bit", "interval", "national"})
_ARG_MODES = frozenset({"in", "out", "inout", "variadic"})

# (schema, name, input arg types). Types None = the whole overload set (a name-level REVOKE).
_FnKey = tuple[str, str, tuple[str, ...] | None]


def _unquote(ident: str) -> str:
    ident = ident.strip()
    if len(ident) >= 2 and ident[0] == '"' and ident[-1] == '"':
        return ident[1:-1]
    return ident.lower()


def _split_qname(qname: str) -> tuple[str, str]:
    """`(schema, name)` of a possibly-qualified, possibly-quoted name; unqualified is `public`."""
    parts = re.findall(_ID, qname)
    if len(parts) >= 2:
        return _unquote(parts[0]), _unquote(parts[1])
    return "public", _unquote(parts[0]) if parts else ""


def _norm_type(arg: str) -> str | None:
    """One argument's normalised TYPE, or None for an OUT parameter (not part of the signature)."""
    a = re.split(r"\s+DEFAULT\b|\s*=", arg, maxsplit=1, flags=re.I)[0]
    a = re.sub(r"\s*\[\s*\]", "[]", a.replace('"', " ").lower())
    toks = a.split()
    if toks and toks[0] in _ARG_MODES:
        if toks[0] == "out":
            return None
        toks = toks[1:]
    if len(toks) > 1 and toks[0] not in _MULTIWORD_TYPE_START:
        toks = toks[1:]  # drop the parameter name
    t = " ".join(toks)
    for prefix in ("pg_catalog.", "public."):
        if t.startswith(prefix):
            t = t[len(prefix):]
    base, arr = (t[:-2], "[]") if t.endswith("[]") else (t, "")
    base = re.sub(r"\s*\([^()]*\)$", "", base)  # numeric(10,2) -> numeric
    return _TYPE_ALIASES.get(base, base) + arr


def _arg_types(view: str, open_idx: int) -> tuple[tuple[str, ...] | None, int]:
    """Normalised input arg types of the `(` at `open_idx`, and the index after its `)`. Unbalanced
    parens give `(None, open_idx + 1)`: an unknown signature, matched name-level (fail closed)."""
    close = matching_close_paren(view, open_idx)
    if close is None:
        return None, open_idx + 1
    args = split_call_args(view, open_idx) or []
    types = [_norm_type(a) for a in args if a.strip()]
    return tuple(t for t in types if t is not None), close + 1


@dataclass
class _File:
    """One `.sql` file under four same-length views, so an offset means the same character in all.

    `code` blanks comments only. `struct` also blanks every literal's content, `$tag$` bodies
    included, so only top-level structure is left. `acl` is `struct` with each DO block's body put
    back (its own literals blanked): REVOKEs there run when the migration runs. `deep` puts back
    every top-level dollar body (DO blocks and function bodies), for the checks that care what any
    executed SQL says (a literal secret, a `log_statement` setting)."""

    path: Path
    raw: str
    code: str
    struct: str
    acl: str
    deep: str
    dump: bool
    line_starts: list[int]
    pragma: str = _PRAGMA
    _pragma_lines: frozenset[int] | None = None

    @property
    def pragma_lines(self) -> frozenset[int]:
        """Lines whose COMMENT carries the pragma, computed on first use (only files that emit)."""
        if self._pragma_lines is None:
            self._pragma_lines = pragma_line_set(self.pragma, self.raw, dialect="sql")
        return self._pragma_lines


def _dollar_spans(
    struct: str, start: int = 0, end: int | None = None, *, limit: int | None = None
) -> list[tuple[int, int, int]]:
    """`(open_tag_start, inner_start, inner_end)` of each top-level `$tag$…$tag$` span of `struct`
    (whose literal contents are already blanked, so delimiters pair in sequence), at most `limit`
    of them. An unterminated span runs to the end (fail closed)."""
    stop = len(struct) if end is None else end
    out: list[tuple[int, int, int]] = []
    pos = start
    while limit is None or len(out) < limit:
        m = _DOLLAR_TAG.search(struct, pos, stop)
        if not m:
            return out
        close = struct.find(m.group(0), m.end(), stop)
        inner_end = close if close != -1 else stop
        out.append((m.start(), m.end(), inner_end))
        pos = inner_end + len(m.group(0)) if close != -1 else stop
    return out


def _prepare(path: Path, raw: str, dump: bool, pragma: str = _PRAGMA) -> _File:
    code = strip_sql_comments(raw, blank=True)
    struct = blank_sql_literals(code)
    acl_parts: list[str] = []
    deep_parts: list[str] = []
    prev = 0
    do_inners = {m.end() for m in _DO_HEAD.finditer(struct)}
    for tag_start, inner_s, inner_e in _dollar_spans(struct):
        restored = blank_sql_literals(code[inner_s:inner_e])
        acl_parts.append(struct[prev:inner_s])
        deep_parts.append(struct[prev:inner_s])
        acl_parts.append(restored if tag_start in do_inners else struct[inner_s:inner_e])
        deep_parts.append(restored)
        prev = inner_e
    acl_parts.append(struct[prev:])
    deep_parts.append(struct[prev:])
    starts = list(accumulate(map(len, raw.splitlines(keepends=True)), initial=0))
    return _File(path, raw, code, struct, "".join(acl_parts), "".join(deep_parts), dump, starts, pragma)


def _vault_files(root: Path, pragma: str = _PRAGMA) -> list[_File]:
    """Every product `.sql` file in natural order, prepared, or `[]` when none mentions Vault (N/A)."""
    paths = sorted(
        (p for p in iter_files(root, (".sql",)) if not is_reference_sql_path(rel(root, p))), key=_natural
    )
    raws = {p: read(p) for p in paths}
    if not any(_ANY_VAULT.search(strip_sql_comments(t)) for t in raws.values()):
        return []
    dumps = set(find_dumps(paths))
    return [_prepare(p, raws[p], p in dumps, pragma) for p in paths]


def _line(f: _File, off: int) -> int:
    return bisect_right(f.line_starts, off)


def _stmt_end(view: str, start: int, bound: int | None = None) -> int:
    """End (past the `;`) of the statement continuing at `start`, never past `bound`."""
    stop = len(view) if bound is None else bound
    end = find_statement_end(view, start, stop)
    return end + 1 if end != -1 else stop


def _bounded(view: str, head: re.Pattern[str]) -> list[tuple[re.Match[str], int]]:
    """Each `head` match with its statement end, bounded at the next head: the windows tile the
    text, so a `;`-less file is not rescanned to EOF from every head (quadratic on hostile SQL,
    #419). No real statement of these kinds contains a second head of its own kind."""
    heads = list(head.finditer(view))
    out: list[tuple[re.Match[str], int]] = []
    for i, m in enumerate(heads):
        bound = heads[i + 1].start() if i + 1 < len(heads) else len(view)
        out.append((m, _stmt_end(view, m.end(), bound)))
    return out


@dataclass
class _Fn:
    key: _FnKey
    file: _File
    start: int
    end: int
    body: str  # the body with its own literals blanked
    definer: bool
    search_path: tuple[str, ...] | None


@dataclass
class _View:
    key: tuple[str, str]
    file: _File
    start: int
    end: int
    definition: str
    invoker: bool


@dataclass
class _Acl:
    grant: bool
    kind: str  # function | relation | schema | all-in-schema | default-privs
    target: _FnKey
    roles: frozenset[str]
    file: _File
    start: int
    end: int
    # The statement names a privilege that reaches the object (EXECUTE/ALL on a function,
    # SELECT/ALL on a relation). A GRANT that does not (`GRANT INSERT ON v TO anon`) leaves the
    # object unreadable, so exposure ignores it (`supabase-vault-plaintext-leak` reads every vault grant).
    reaches: bool = True


def _search_path(attrs: str) -> tuple[str, ...] | None:
    m = _SEARCH_PATH.search(attrs)
    if not m:
        return None
    vals: list[str] = []
    for t in _PATH_TOKEN.finditer(m.group("val")):
        sq, dq, bare = t.groups()
        if bare is not None:
            if bare.lower() in _PATH_STOP:
                break
            vals.append(bare.lower())
        elif sq is not None:
            vals.extend(p.strip().strip('"').lower() for p in sq.split(","))
        else:
            vals.append((dq or "").lower())
    return tuple(vals)


def _functions(f: _File) -> list[_Fn]:
    """Every `CREATE FUNCTION` in the file. Each head's window ends at the next head: a later head
    can never sit inside this function's body (`struct` blanks bodies), so the windows tile the
    file and a `;`-less or paren-less hostile file is not rescanned from every head (#419)."""
    out: list[_Fn] = []
    heads = list(_CREATE_FN.finditer(f.struct))
    done = 0
    for i, m in enumerate(heads):
        if m.start() < done:
            continue
        bound = heads[i + 1].start() if i + 1 < len(heads) else len(f.struct)
        schema, name = _split_qname(m.group("name"))
        types, after_rel = _arg_types(f.struct[m.start():bound], m.end() - 1 - m.start())
        after = m.start() + after_rel
        semi = f.struct.find(";", after, bound)
        spans = _dollar_spans(f.struct, after, semi if semi != -1 else bound, limit=1)
        body = ""
        if spans:
            tag_start, inner_s, inner_e = spans[0]
            body = f.code[inner_s:inner_e]
            tail = inner_e + (inner_s - tag_start)
            end = _stmt_end(f.struct, min(tail, len(f.struct)), max(bound, min(tail, len(f.struct))))
            attrs_struct = f.struct[after:tag_start] + " " + f.struct[tail:end]
            attrs_code = f.code[after:tag_start] + " " + f.code[tail:end]
        else:
            end = semi + 1 if semi != -1 else bound
            q = f.struct.find("'", after, end)
            if q != -1 and _AS_KW.search(f.struct, after, q):  # single-quoted body (`AS '…'`)
                qc = f.struct.find("'", q + 1, end)
                body = f.code[q + 1:qc if qc != -1 else end]
            attrs_struct, attrs_code = f.struct[after:end], f.code[after:end]
        out.append(_Fn(
            key=(schema, name, types), file=f, start=m.start(), end=end, body=blank_sql_literals(body),
            definer=bool(_SEC_DEFINER.search(attrs_struct)), search_path=_search_path(attrs_code),
        ))
        done = max(end, m.end())
    return out


def _views(f: _File) -> list[_View]:
    out: list[_View] = []
    for m, end in _bounded(f.struct, _CREATE_VIEW):
        as_m = _AS_KW.search(f.struct, m.end(), end)
        options = f.code[m.end():as_m.start() if as_m else end]
        invoker = bool(_INVOKER_ON.search(options) or _SECURITY_INVOKER_CLAUSE.search(f.struct[m.end():end]))
        out.append(_View(_split_qname(m.group("name")), f, m.start(), end, f.struct[m.end():end], invoker))
    return out


def _roles(text: str) -> frozenset[str]:
    out = set()
    for part in text.split(","):
        toks = part.replace('"', " ").split()
        if len(toks) > 1 and toks[0].lower() == "group":
            toks = toks[1:]
        if toks and toks[0].lower() in _ROLES:
            out.add(toks[0].lower())
    return frozenset(out)


def _acls(f: _File) -> list[_Acl]:
    out: list[_Acl] = []
    view = f.acl
    adp: list[tuple[int, int]] = []
    for m, end in _bounded(view, _ADP_HEAD):
        adp.append((m.start(), end))
        stmt = view[m.start():end]
        g = _ADP_SCHEMA.search(stmt)
        gr = _GRANT_KW.search(stmt, g.end()) if g else None
        to = _TO_KW.search(stmt, gr.end()) if gr else None
        if g and to and "vault" in {_unquote(s) for s in g.group("s").split(",")}:
            roles = _roles(_ROLE_TAIL.split(stmt[to.end():])[0])
            if roles:
                out.append(_Acl(True, "default-privs", ("vault", "", None), roles, f, m.start(), end))
    adp_starts = [s for s, _e in adp]
    for m, end in _bounded(view, _ACL_HEAD):
        i = bisect_right(adp_starts, m.start()) - 1
        if i >= 0 and m.start() < adp[i][1]:
            continue  # the GRANT/REVOKE inside an ALTER DEFAULT PRIVILEGES, handled above
        out.extend(_parse_acl(f, view, m.start(), end))
    out.extend(_dynamic_revokes(f))
    return out


def _parse_acl(f: _File, view: str, start: int, end: int) -> list[_Acl]:
    stmt = view[start:end]
    grant = stmt[:5].upper() == "GRANT"
    on = _ON_KW.search(stmt)
    if not on:
        return []  # role membership (`GRANT role TO user`)
    role_kw = _TO_KW if grant else _FROM_KW
    pos = on.end()
    km = _ACL_KIND.match(stmt, pos)
    k = (km.group("k") or "TABLE").upper() if km else "TABLE"
    k = re.sub(r"\s+", " ", k)
    pos = km.end() if km else pos
    is_fn = k in {"FUNCTION", "ROUTINE", "PROCEDURE"}
    if is_fn:
        reach = "function"
    elif k.startswith("ALL "):
        reach = _BULK_KIND.get(k.split()[1].lower(), "")
    else:
        reach = "" if k == "SCHEMA" else "relation"
    privs = _privileges(stmt[len("GRANT" if grant else "REVOKE"):on.start()], columns=grant)
    reaches = not reach or bool(privs & _REACHING_PRIVS[reach])
    if not grant and not reaches:
        return []  # it revokes something, but not what reaches the object
    targets: list[_FnKey] = []
    while pos < len(stmt):
        nm = _ACL_TARGET.match(stmt, pos)
        if not nm or role_kw.fullmatch(nm.group("n")):
            break
        pos = nm.end()
        types: tuple[str, ...] | None = None
        if is_fn and pos < len(stmt) and stmt[pos] == "(":
            types, pos = _arg_types(stmt, pos)
        if k == "SCHEMA":
            targets.append((_unquote(nm.group("n")), "", None))
        elif k.startswith("ALL "):  # keyed by object kind: `("public", "functions", None)`
            targets.append((_unquote(nm.group("n")), k.split()[1].lower(), None))
        else:
            schema, name = _split_qname(nm.group("n"))
            targets.append((schema, name, types))
        sep = _COMMA.match(stmt, pos)
        if not sep:
            break
        pos = sep.end()
    rk = role_kw.search(stmt, pos)
    if not rk or not targets:
        return []
    role_text = _ROLE_TAIL.split(stmt[rk.end():])[0]
    roles = _roles(role_text)
    if not roles:
        return []
    kind = (
        "function" if is_fn else "schema" if k == "SCHEMA" else "all-in-schema" if k.startswith("ALL ") else "relation"
    )
    return [_Acl(grant, kind, t, roles, f, start, end, reaches) for t in targets]


def _privileges(text: str, *, columns: bool) -> frozenset[str]:
    """The privileges a GRANT/REVOKE privilege list (between the verb and `ON`) names. A
    column-level `SELECT (col)` counts only when `columns`: granted, it does make the object
    readable; revoked, it leaves the table-level grant. The list is replaced by ` (cols)` with a
    leading space, so the unspaced `SELECT(col)` (the common spelling) still splits to `select`.
    `REVOKE GRANT OPTION FOR ...` (which keeps the privilege) never counts: its first token is
    `grant`, and `_bounded` already splits the statement at that inner GRANT head."""
    out: set[str] = set()
    for item in _COLUMN_LIST.sub(" (cols)", text).split(","):
        toks = item.lower().split()
        if toks and (columns or "(cols)" not in item):
            out.add(toks[0])
    return frozenset(out)


def _dynamic_revokes(f: _File) -> list[_Acl]:
    """The sql/169 shape: a DO block whose loop `EXECUTE format('REVOKE … ON FUNCTION %s FROM <roles>')`
    over `pg_proc` rows named in an `ARRAY['name', …]`: a name-level REVOKE of every overload."""
    out: list[_Acl] = []
    for m in _DO_HEAD.finditer(f.struct):
        spans = _dollar_spans(f.struct, m.end(), limit=1)
        if not spans:
            continue
        _tag, s, e = spans[0]
        inner = f.code[s:e]
        for d in _DYNAMIC_REVOKE.finditer(inner):
            roles = _roles(d.group("roles"))
            if not roles:
                continue
            ns = _NSPNAME.search(inner)
            schema = ns.group(1).lower() if ns else "public"
            for arr in _ARRAY_LIT.finditer(inner):
                for name in _ARRAY_NAME.findall(arr.group("body")):
                    out.append(_Acl(False, "function", (schema, name.lower(), None), roles, f, s, e))
    return out


def _drops(f: _File) -> list[tuple[int, str, _FnKey]]:
    out: list[tuple[int, str, _FnKey]] = []
    for m, end in _bounded(f.struct, _DROP):
        schema, name = _split_qname(m.group("name"))
        kind = "function" if m.group("kind").upper() == "FUNCTION" else "view"
        types: tuple[str, ...] | None = None
        if kind == "function" and m.group("paren"):
            types, _ = _arg_types(f.struct[m.start():end], m.end() - 1 - m.start())
        out.append((m.start(), kind, (schema, name, types)))
    return out


def _natural(path: Path) -> list[str]:
    """Natural sort key (`sql/9-x.sql` before `sql/10-x.sql`), digits zero-padded so it is all `str`."""
    return [t.zfill(12) if t.isdigit() else t for t in re.split(r"(\d+)", path.as_posix())]


def _sig_match(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> bool:
    return a is None or b is None or a == b


def _refs(text: str, path: tuple[str, ...] | None) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """`(referenced, called)` `(schema, name)` pairs in `text`. An unqualified name resolves against
    `path` (the function's pinned `search_path`; `public` when unpinned), so a body pinned to
    `public, vault` that reads a bare `decrypted_secrets` still counts as reading vault."""
    schemas = ("public",) if path is None else tuple(x for x in path if x not in _SAFE_PATH)
    refs: set[tuple[str, str]] = set()
    calls: set[tuple[str, str]] = set()
    for m in _REF.finditer(text):
        a, b = m.group("a"), m.group("b")
        keys = [(_unquote(a), _unquote(b))] if b else [(sc, _unquote(a)) for sc in schemas]
        refs.update(keys)
        if m.group("call"):
            calls.update(keys)
    return refs, calls


def _sig(key: _FnKey) -> str:
    schema, name, types = key
    return f"{schema}.{name}({', '.join(types)})" if types is not None else f"{schema}.{name}"


def _fmt(roles: frozenset[str] | set[str]) -> str:
    return ", ".join(f"`{'PUBLIC' if r == 'public' else r}`" for r in ("public", "anon", "authenticated") if r in roles)


class SupabaseVaultExposureGuard(Guard):
    id = "supabase-vault-exposure"
    title = "Supabase Vault material reachable by anon/authenticated (definer RPC, decrypted view, vault grant, literal secret)"
    area = "Database"
    schema_state = True  # grants/functions/views a schema dump reproduces

    # FIRE-strings: a SECURITY DEFINER function in `public` whose body reads
    # `vault.decrypted_secrets`, with no REVOKE at all. Must NOT contain a REVOKE (static, or a
    # dynamic `%s` loop over an ARRAY of names, which would also silence definer-function-grants)
    # nor any `security: allow-…` comment.
    canary_plant = CanaryPlant(
        files={
            "sql/supabase_vault_exposure.sql": (
                # A leading line, so a probe inserted at the top of the file never lands directly
                # above the CREATE (definer-function-grants also reads the line above its CREATE).
                "-- Vault-reading RPC with no REVOKE at all.\n"
                "CREATE OR REPLACE FUNCTION public.canary_vault_read(p_id uuid) RETURNS text\n"
                "LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$\n"
                "  SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id = p_id;\n"
                "$$;\n"
            )
        },
        expects=frozenset({"supabase-vault-exposure/definer-function-executable"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files = _vault_files(root)
        if not files:
            return []  # no Vault in this repo: N/A
        order = {id(f): i for i, f in enumerate(files)}
        fns = [fn for f in files for fn in _functions(f)]
        views = [v for f in files for v in _views(f)]
        acls = [a for f in files for a in _acls(f)]
        by_target: dict[tuple[str, str, str], list[_Acl]] = {}
        for a in acls:
            by_target.setdefault((a.kind, a.target[0], a.target[1]), []).append(a)
        hardenings = _hardenings(files)
        drops = {id(f): _drops(f) for f in files}
        exposed = detect_exposed_schemas([f.code for f in files]) - {"vault"}

        # Classify: views over decrypted secrets (transitively), then functions touching vault
        # material in their BODY (transitively, through those views and through each other).
        view_refs = [(v, _refs(v.definition, None)[0]) for v in views]
        decrypted = {v.key for v, refs in view_refs if _DECRYPTED in refs}
        for _ in range(4):
            grown = decrypted | {v.key for v, refs in view_refs if refs & decrypted}
            if grown == decrypted:
                break
            decrypted = grown
        fn_refs = [(fn, *_refs(fn.body, fn.search_path)) for fn in fns]
        vault_names: set[tuple[str, str]] = set()
        for _ in range(4):
            grown = vault_names | {
                fn.key[:2] for fn, refs, calls in fn_refs
                if refs & _VAULT_OBJECTS or refs & decrypted or calls & vault_names
            }
            if grown == vault_names:
                break
            vault_names = grown
        vault_fns = [fn for fn in fns if fn.definer and fn.key[:2] in vault_names]

        out: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        def emit(f: _File, start: int, end: int, rule: str, severity: Severity, message: str,
                 remediation: str, extra: tuple[str, ...] = ()) -> None:
            loc = f"{rel(root, f.path)}:{_line(f, start)}"
            first, last = _line(f, start), _line(f, max(start, end - 1))
            if (rule, loc) in seen or any(first <= ln <= last for ln in f.pragma_lines):
                return
            seen.add((rule, loc))
            out.append(Finding(
                check_id=self.id, severity=severity, title=_TITLES[rule], location=loc, message=message,
                remediation=remediation, rule=f"{self.id}/{rule}", standards=[*_STANDARDS, *extra],
            ))

        def after(a: _Acl, f: _File, start: int) -> bool:
            """`a` runs after the CREATE at `f:start`: later in its file, or in a file sorting after it."""
            return (a.file is f and a.start > start) or order[id(a.file)] > order[id(f)]

        def bulk(target: _FnKey, kind: str, f: _File, start: int) -> list[_Acl]:
            """The `ON ALL … IN SCHEMA` statements that reach the object CREATEd at `f:start`: only the
            ones after it, since a bulk GRANT/REVOKE affects the objects that exist when it runs."""
            return [
                a for b, k in _BULK_KIND.items() if k == kind
                for a in by_target.get(("all-in-schema", target[0], b), []) if after(a, f, start)
            ]

        # Each object's FIRST CREATE in the migrations. A bulk statement is ordered against that,
        # not against every CREATE: `CREATE OR REPLACE` keeps the ACL, so a bulk REVOKE between the
        # first CREATE and a later replace still covers the object. (A DROP + re-CREATE does reset
        # it; R3 checks that from the re-CREATE.)
        first: dict[tuple[str, _FnKey], tuple[_File, int]] = {}
        for fn in fns:
            if not fn.file.dump:
                first.setdefault(("function", fn.key), (fn.file, fn.start))
        for v in views:
            if not v.file.dump:
                first.setdefault(("relation", (v.key[0], v.key[1], None)), (v.file, v.start))

        def roles_for(target: _FnKey, kind: str, grant: bool, f: _File, start: int) -> set[str]:
            dump = f if f.dump else None
            got: set[str] = set()
            f0, s0 = (f, start) if f.dump else first.get((kind, target), (f, start))
            for a in [*by_target.get((kind, target[0], target[1]), []), *bulk(target, kind, f0, s0)]:
                if a.grant != grant or not a.reaches:
                    continue
                if (dump is not None and a.file is not dump) or (dump is None and a.file.dump):
                    continue
                if kind == "function" and a.kind == "function" and not _sig_match(a.target[2], target[2]):
                    continue
                got |= a.roles
            return got

        def exposed_to(target: _FnKey, kind: str, f: _File, start: int, required: frozenset[str]) -> set[str]:
            dump = f if f.dump else None
            granted = roles_for(target, kind, True, f, start)
            revoked = roles_for(target, kind, False, f, start)
            if dump is not None:  # the dump spells out the real ACL
                return granted | ({"public"} - revoked if kind == "function" else set())
            return (set(required) - revoked) | granted

        # R1 + R7: vault-material SECURITY DEFINER functions.
        for fn in vault_fns:
            sig = _sig(fn.key)
            if fn.key[0] in exposed:
                who = exposed_to(fn.key, "function", fn.file, fn.start, _FN_REQUIRED)
                if who:
                    emit(fn.file, fn.start, fn.end, "definer-function-executable", "critical",
                         f"`{sig}` is SECURITY DEFINER, its body reads or writes Supabase Vault material, and "
                         f"it is executable by {_fmt(who)}. It runs as its owner, who can decrypt every vault "
                         "secret, so any caller holding EXECUTE reads (or overwrites) them through the Data "
                         "API. On Supabase, `REVOKE ... FROM PUBLIC` alone is not enough: default privileges "
                         "grant anon and authenticated EXECUTE directly.",
                         f"REVOKE EXECUTE ON FUNCTION {sig} FROM PUBLIC, anon, authenticated; "
                         f"GRANT EXECUTE ON FUNCTION {sig} TO service_role;")
            sp = fn.search_path
            writable = sp is not None and any(s not in _SAFE_PATH for s in sp)
            if writable and not _hardened_later("function", fn.key[:2], fn.file, fn.start, hardenings):
                emit(fn.file, fn.start, fn.end, "definer-search-path-writable", "low",
                     f"`{sig}` reads Supabase Vault material as SECURITY DEFINER with `search_path` pinned to "
                     f"`{', '.join(sp or ())}`. Any role that can CREATE in one of those schemas can shadow an "
                     "unqualified name the body resolves and run code as the owner.",
                     f"ALTER FUNCTION {sig} SET search_path = ''; and schema-qualify every reference in the body.")

        # R2: views over decrypted secrets.
        for v in views:
            if v.key not in decrypted or v.key[0] not in exposed or v.invoker:
                continue
            if _hardened_later("view", v.key, v.file, v.start, hardenings):
                continue
            name = f"{v.key[0]}.{v.key[1]}"
            who = exposed_to((v.key[0], v.key[1], None), "relation", v.file, v.start, _VIEW_REQUIRED)
            if who:
                emit(v.file, v.start, v.end, "decrypted-view-readable", "high",
                     f"`{name}` reads `vault.decrypted_secrets` with its owner's rights (no "
                     f"`security_invoker`) and is readable by {_fmt(who)} through the Data API. Vault 0.3+ "
                     "still checks the caller's EXECUTE on its decrypt function, but the older "
                     "pgsodium-based vault does not, and the grant is the only layer this repo controls.",
                     f"ALTER VIEW {name} SET (security_invoker = true); REVOKE ALL ON {name} FROM PUBLIC, anon, "
                     f"authenticated; GRANT SELECT ON {name} TO service_role; (or move it out of the exposed "
                     "schema).")

        # R3: a DROP + re-CREATE resets the ACL to Supabase's defaults.
        recreated: list[tuple[str, _FnKey, _File, int, int]] = [
            ("function", fn.key, fn.file, fn.start, fn.end) for fn in vault_fns if fn.key[0] in exposed
        ] + [
            ("view", (v.key[0], v.key[1], None), v.file, v.start, v.end)
            for v in views if v.key in decrypted and v.key[0] in exposed and not v.invoker
        ]
        for kind, key, f, start, end in recreated:
            if f.dump or not any(
                dk == kind and dkey[:2] == key[:2] and _sig_match(dkey[2], key[2]) and doff < start
                for doff, dk, dkey in drops[id(f)]
            ):
                continue
            acl_kind = "function" if kind == "function" else "relation"
            revoked: set[str] = set()
            for a in [*by_target.get((acl_kind, key[0], key[1]), []), *bulk(key, acl_kind, f, start)]:
                if a.grant or a.file.dump:
                    continue
                if a.kind == "function" and not _sig_match(a.target[2], key[2]):
                    continue
                if after(a, f, start):
                    revoked |= a.roles
            missing = set(_FN_REQUIRED if kind == "function" else _VIEW_REQUIRED) - revoked
            if not missing:
                continue
            if kind == "function":
                sig = _sig(key)
                emit(f, start, end, "recreated-without-revoke", "critical",
                     f"`{sig}` (a vault-material SECURITY DEFINER function) is DROPped and re-created in this "
                     "file, which resets its ACL to the defaults (EXECUTE for PUBLIC, anon and authenticated "
                     f"on Supabase), and nothing after the CREATE revokes {_fmt(missing)} again.",
                     f"After the CREATE: REVOKE EXECUTE ON FUNCTION {sig} FROM PUBLIC, anon, authenticated; "
                     f"GRANT EXECUTE ON FUNCTION {sig} TO service_role;")
            else:
                name = f"{key[0]}.{key[1]}"
                emit(f, start, end, "recreated-without-revoke", "high",
                     f"`{name}` (a view over `vault.decrypted_secrets`) is DROPped and re-created in this "
                     "file, which resets its ACL to Supabase's defaults, and nothing after the CREATE "
                     f"revokes {_fmt(missing)} again.",
                     f"After the CREATE: REVOKE ALL ON {name} FROM PUBLIC, anon, authenticated; GRANT SELECT ON "
                     f"{name} TO service_role; (CREATE OR REPLACE keeps the existing ACL).")

        return out


_Hardenings = dict[tuple[str, str, str], list[tuple[_File, int]]]


def _hardenings(files: list[_File]) -> _Hardenings:
    """Every later-fix statement, indexed once: `ALTER FUNCTION <f> … SET search_path` to a safe value
    (key `("function", schema, name)`) and `ALTER VIEW <v> SET (security_invoker = true)` (key
    `("view", schema, name)`), each with its file and offset."""
    out: _Hardenings = {}
    for g in files:
        for m, end in _bounded(g.struct, _ALTER_FN):
            sp = _search_path(g.code[m.start():end])
            if sp is not None and all(x in _SAFE_PATH for x in sp):
                out.setdefault(("function", *_split_qname(m.group("name"))), []).append((g, m.start()))
        for m in _ALTER_VIEW_SET.finditer(g.code):
            if g.struct[m.start():m.start() + 5].strip() and _INVOKER_ON.search(m.group("opts") + ")"):
                out.setdefault(("view", *_split_qname(m.group("name"))), []).append((g, m.start()))
    return out


def _hardened_later(kind: str, key: tuple[str, str], f: _File, start: int, hardenings: _Hardenings) -> bool:
    """A fix for this object later in its own file, or anywhere in another file of the same mode
    (migration files union across the repo; a dump only answers for itself). No replay."""
    for g, off in hardenings.get((kind, key[0], key[1]), []):
        if g.dump != f.dump or (g.dump and g is not f) or (g is f and off < start):
            continue
        return True
    return False
