"""Guard: SECURITY DEFINER functions must not be EXECUTE-able by anon/authenticated.

A `SECURITY DEFINER` function runs with the privileges of its **owner**, not the
caller. Postgres grants `EXECUTE` to `PUBLIC` by default, so unless that grant is
revoked, **anon and authenticated can call it** — and a definer function that
reads privileged data (decrypting a vault secret, returning an API key) becomes a
direct exfiltration vector regardless of RLS.

This mirrors Supabase Splinter's `security_definer_function_executable` lint —
which the flagship's CI silently missed for months (it gates on
`pgrst.db_schemas`; see docs/knowledge/exposed-schema-rls-blind-spot.md). On that
app, 9 vault/secret definer functions were anon/authenticated-executable, e.g.
`read_secret_logged(uuid, text)` which decrypts `vault.decrypted_secrets` by id
and returns it. The fix (`sql/169`) was
`REVOKE EXECUTE … FROM PUBLIC, anon, authenticated; GRANT EXECUTE … TO service_role`.

Detection (DB-independent, cross-file, comment-stripped):
  - collect every `CREATE [OR REPLACE] FUNCTION` whose body is `SECURITY DEFINER`, keyed by
    `(schema, name)` (unqualified is `public`), so a revoke on `private.x` never covers `public.x`;
  - collect, per function, the SET of roles its `EXECUTE` is `REVOKE`d from, unioned across
    files (direct statements, multi-target `ON FUNCTION a(), b()`, plus the dynamic
    `format('REVOKE … %s FROM <roles>')` DO-loop that `sql/169` uses, which credits only the
    roles in that block's own `format()` to the names in that block's own `ARRAY[…]`);
  - flag each definer function whose revoked set misses `PUBLIC` or `anon`.

A revoke from ONE role is not a lockdown (#1096). Postgres grants EXECUTE to PUBLIC, and on
Supabase the default privileges (`ALTER DEFAULT PRIVILEGES … GRANT ALL ON FUNCTIONS TO anon`)
also grant `anon` and `authenticated` directly. So `REVOKE … FROM PUBLIC` leaves anon able to
call the function, and `REVOKE … FROM anon` leaves it reachable through PUBLIC. `authenticated`
is deliberately NOT required: an RLS-predicate helper must stay callable by signed-in users, and
whether such a function checks ownership is the second rule's job (below). In a pg_dump file
(`sql_state.find_dumps`) the ACL is spelled out: there, a function the dump creates with no
`GRANT … TO anon` is credited as revoked from anon. GRANTs are otherwise not replayed (a known
bypass, documented in the wiki doc): migrations re-grant early and revoke later, so an
order-unaware "any GRANT re-exposes" rule would fire on correctly locked-down functions.

Severity is **critical** when the name looks secret-bearing
(secret/vault/decrypt/api_key/token/credential/password), else **high**.
Opt out a known-safe definer with an inline pragma on (or just above) the
`CREATE FUNCTION` line: `-- security: allow-definer-public`.

A SECOND, orthogonal rule (checklist §7): a definer function can be CORRECTLY scoped at the
GRANT level (EXECUTE revoked from PUBLIC/anon, left only to `authenticated`) — the rule above
stays silent, exactly as intended, since a legitimate authenticated user is supposed to be able
to call it — and still be exploitable if its BODY never checks that the AUTHENTICATED CALLER
owns the row/org it is about to mutate. Since the function runs with the owner's privileges, it
bypasses RLS entirely, so any authenticated user can act on ANY org's/user's data, not just their
own — a pure authorization (IDOR/BOLA) bug hiding behind a correctly-scoped grant. Real-world
precedent: CVE-2026-56239 (Capgo, CVSS 7.2) — `public.apply_usage_overage`, a SECURITY DEFINER
billing function, performed sensitive quota/overage operations with no `auth.uid()`/org-membership
check in its body, letting an authenticated user manipulate billing data for arbitrary
organizations. Flags a definer function whose body contains a data-modifying statement
(INSERT/UPDATE/DELETE) but no internal ownership/authorization check
(`auth.uid()`/`auth.jwt()`/`auth.role()`/`current_setting('request.jwt...')`) anywhere in its
body. Severity **high**, rule `definer-function-grants/no-internal-ownership-check`. Opt out a
function that is intentionally unscoped (a migration helper, system-wide config write) with the
SAME pragma as above — the pragma silences both rules for that function, since both concern the
same underlying "who can do what to this function" question.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.sql_state import find_dumps

from .base import (
    CanaryPlant,
    Guard,
    blank_sql_literals_nested,
    comment_view,
    iter_files,
    iter_statement_spans,
    matching_close_paren,
    pg_auth_call_pattern,
    read,
    rel,
    sql_execute_literals,
    sql_role_names,
    strip_sql_comments,
)

_CREATE_FN = re.compile(r"create\s+(?:or\s+replace\s+)?function\s+(?P<name>[\w\".]+)\s*\(", re.I)
_SEC_DEFINER = re.compile(r"security\s+definer", re.I)
# A function GRANT/REVOKE of EXECUTE (or ALL), up to its first target. `REVOKE GRANT OPTION FOR
# EXECUTE` does not match: it keeps the privilege, so it revokes nothing that reaches the function.
_ACL_HEAD = re.compile(r"\b(?:grant|revoke)\b", re.I)
_FN_ACL = re.compile(
    r"(?P<verb>grant|revoke)\s+(?:all(?:\s+privileges)?|execute)\s+on\s+(?:function|routine|procedure)\s+",
    re.I,
)
_FN_TARGET = re.compile(r'\s*(?P<name>(?:"[^"\n]{1,128}"|\w+)(?:\s*\.\s*(?:"[^"\n]{1,128}"|\w+))?)\s*')
_IDENT = re.compile(r'"[^"\n]{1,128}"|\w+')
_COMMA = re.compile(r"\s*,")
_TO_KW = re.compile(r"\bto\b", re.I)
_FROM_KW = re.compile(r"\bfrom\b", re.I)
# The sql/169 shape: a DO block whose loop runs `format('REVOKE … ON FUNCTION %s FROM <roles>')`
# over the pg_proc rows named in an `ARRAY['name', …]`, optionally filtered by `nspname = '…'`.
_DO_HEAD = re.compile(r"\bdo\s+(?:language\s+\w+\s+)?(?P<tag>\$(?:[A-Za-z_]\w{0,63})?\$)", re.I)
_DYNAMIC_REVOKE = re.compile(
    r"'\s*revoke\s+(?:all(?:\s+privileges)?|execute)\s+on\s+(?:function|routine|procedure)\s+"
    r"%[sIL]\s+from\s+(?P<roles>[^'\n]{1,200})'",
    re.I,
)
# The body excludes `[` as well as `]`, so a flood of unclosed `array[` heads stops each attempt at
# the next head instead of scanning the full 4000-char window from every one of them.
_ARRAY_LIT = re.compile(r"\barray\s*\[(?P<body>[^\[\]]{0,4000})\]", re.I)
_ARRAY_NAME = re.compile(r"'(\w{1,128})'")
_NSPNAME = re.compile(r"\bnspname\s*=\s*'(\w{1,128})'", re.I)
# What a definer's EXECUTE must be revoked from. `authenticated` is deliberately absent: see the
# module docstring (the IDOR risk a correctly-scoped authenticated grant leaves is NS-10's job).
_REQUIRED = frozenset({"public", "anon"})
_PRAGMA = "security: allow-definer-public"
_SECRETISH = re.compile(r"secret|vault|decrypt|api_?key|token|credential|password", re.I)

# NS-10: a data-modifying statement inside a definer function's own body — the write surface
# an internal ownership check would need to guard. The `update` branch deliberately has no
# trailing `\b`: `\s+\S` already ensures "update" is followed by whitespace then a table
# reference (disambiguating it from an identifier like `updated_at`, which has no whitespace
# after "update"), and a trailing `\b` right after a single arbitrary `\S` character can never
# match when that character is itself followed by more word characters (e.g. "UPDATE public…"
# — `\S` consumes just "p", and "p" is immediately followed by "ublic", so no boundary exists
# at that position) — a real bug caught by this rule's own first test, not a hypothetical.
_DATA_MODIFYING = re.compile(r"\b(?:insert\s+into\b|update\s+\S|delete\s+from\b)", re.I)
# Any internal ownership/authorization check: the caller's own identity (auth.uid/auth.jwt),
# an explicit role check (auth.role — e.g. gating on service_role), or the GUC form the same
# checks take when read via current_setting(...) rather than the auth.* helpers.
# M6: the auth.* legs use `pg_auth_call_pattern` (same root cause as H3/H5/H6) — a
# bare `auth\.uid\s*\(` was silent on a pg_dump/migration-tool quoted-identifier spelling
# (`"auth"."uid"()`), which would falsely report a definer function as having NO internal
# ownership check when it actually has one, just quoted.
_OWNERSHIP_CHECK = re.compile(
    rf"{pg_auth_call_pattern('uid', 'jwt', 'role')}|current_setting\s*\(\s*['\"]request\.jwt",
    re.I,
)


_FnKey = tuple[str, str]  # (schema, name), lowercased and unquoted


def _fn_key(name: str) -> _FnKey:
    """`(schema, name)` of a possibly-qualified, possibly-quoted function name, lowercased;
    an unqualified name is `public` (the schema the Data API exposes by default)."""
    parts = [p.strip('"').lower() for p in _IDENT.findall(name)]
    if not parts:
        return ("public", "")
    return (parts[-2], parts[-1]) if len(parts) >= 2 else ("public", parts[0])


def _shown(key: _FnKey) -> str:
    """How a finding names the function: bare in `public` (as it always has), qualified elsewhere."""
    return key[1] if key[0] == "public" else f"{key[0]}.{key[1]}"


def _definer_function_blocks(stripped: str) -> dict[_FnKey, str]:
    """Key -> full body text (up to the next CREATE FUNCTION or EOF) for every function
    defined `SECURITY DEFINER` in this (stripped) text. The single source both the grant-surface
    rule and the internal-ownership-check rule (NS-10) read the block from —
    same block, two different questions asked of it."""
    out: dict[_FnKey, str] = {}
    matches = list(_CREATE_FN.finditer(stripped))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(stripped)
        block = stripped[m.start():end]
        if _SEC_DEFINER.search(block):
            out[_fn_key(m.group("name"))] = block
    return out


def _function_acls(stripped: str) -> list[tuple[bool, list[_FnKey], frozenset[str]]]:
    """`(is_grant, targets, roles)` for every static `GRANT|REVOKE {ALL|EXECUTE} ON FUNCTION a(…),
    b(…) {TO|FROM} roles` in this (stripped) text. Read on `blank_sql_literals_nested`, so a statement
    quoted inside a string (`RAISE NOTICE 'revoke …'`, a `format()` template) is not one; dollar
    bodies stay visible, so a REVOKE inside a DO block still counts. The literal an `EXECUTE` runs
    IS a statement, so each one is parsed as well (#1100 R1-M1); a `format()` placeholder target
    (`%s`, `public.%I`) names no function, so it credits nothing (#1100 R2-L1)."""
    views = [blank_sql_literals_nested(stripped)]
    views += [blank_sql_literals_nested(text + ";") for text in sql_execute_literals(stripped)]
    out: list[tuple[bool, list[_FnKey], frozenset[str]]] = []
    for view in views:
        out.extend(_parse_function_acls(view))
    return out


def _parse_function_acls(view: str) -> list[tuple[bool, list[_FnKey], frozenset[str]]]:
    """`_function_acls` for one literal-blanked view."""
    out: list[tuple[bool, list[_FnKey], frozenset[str]]] = []
    for start, end in iter_statement_spans(view, _ACL_HEAD):
        stmt = view[start:end]
        m = _FN_ACL.match(stmt)
        if not m:
            continue
        grant = m.group("verb").lower() == "grant"
        targets: list[_FnKey] = []
        pos = m.end()
        while True:
            nm = _FN_TARGET.match(stmt, pos)
            if not nm or stmt[nm.end():nm.end() + 1] in (".", "%"):
                break  # `public.%I`: only the schema matched, so the target names no function
            targets.append(_fn_key(nm.group("name")))
            pos = nm.end()
            if pos < len(stmt) and stmt[pos] == "(":
                close = matching_close_paren(stmt, pos)
                if close is None:
                    break
                pos = close + 1
            sep = _COMMA.match(stmt, pos)
            if not sep:
                break
            pos = sep.end()
        kw = (_TO_KW if grant else _FROM_KW).search(stmt, pos)
        if targets and kw:
            out.append((grant, targets, sql_role_names(stmt[kw.end():])))
    return out


def _dynamic_revokes(stripped: str) -> dict[_FnKey, set[str]]:
    """Roles revoked by each `DO $$ … $$` block's `format('REVOKE … ON FUNCTION %s FROM <roles>')`
    loop, credited to the names in THAT block's `ARRAY[…]` (in its `nspname` schema, else `public`).
    Scoped per block, so an unrelated `ARRAY['x']` elsewhere in the file is not a revoke of `x`,
    and a loop that revokes only from PUBLIC credits only PUBLIC. An unterminated block credits
    nothing (fail closed: the definer keeps firing)."""
    out: dict[_FnKey, set[str]] = {}
    pos = 0
    while (m := _DO_HEAD.search(stripped, pos)) is not None:
        close = stripped.find(m.group("tag"), m.end())
        if close == -1:
            break
        body = stripped[m.end():close]
        pos = close + len(m.group("tag"))
        roles: set[str] = set()
        for d in _DYNAMIC_REVOKE.finditer(body):
            roles |= sql_role_names(d.group("roles"))
        if not roles:
            continue
        ns = _NSPNAME.search(body)
        schema = ns.group(1).lower() if ns else "public"
        for arr in _ARRAY_LIT.finditer(body):
            for name in _ARRAY_NAME.findall(arr.group("body")):
                out.setdefault((schema, name.lower()), set()).update(roles)
    return out


def _pragma_allowed(raw: str) -> set[_FnKey]:
    """Functions whose CREATE line (or the line above) carries the allow pragma, as a real comment:
    read from the SQL comment view's line at the same index (#1040), so a trailing comment after
    the line's `AS $$` (in the body, which the view reads as code) still counts."""
    allowed: set[_FnKey] = set()
    view = comment_view(raw, "sql").splitlines()
    for i, line in enumerate(raw.splitlines()):
        m = _CREATE_FN.search(line)
        if m and (_PRAGMA in view[i] or (i > 0 and _PRAGMA in view[i - 1])):
            allowed.add(_fn_key(m.group("name")))
    return allowed


class DefinerFunctionGrantsGuard(Guard):
    id = "definer-function-grants"
    title = "SECURITY DEFINER function executable by anon/authenticated"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    #
    # No canary demonstration for the internal-ownership-check rule (NS-10): the shared
    # `sql/schema.sql` is a base file several guards trip on, and adding a data-modifying
    # definer function with no ownership check there risks tripping other SQL guards
    # unexpectedly on a file this guard doesn't own. Coverage is its dedicated unit tests
    # below; `canary_plant` still declares (non-None), satisfying
    # `test_every_guard_declares_its_own_plant`'s per-GUARD (not per-rule) requirement.
    canary_plant = CanaryPlant(expects=frozenset({"definer-function-grants/executable-by-public"}))

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        # Aggregate across all files: a function is often created in an early
        # migration and revoked in a later one (e.g. sql/169).
        files = iter_files(sql_dir, (".sql",))
        dumps = set(find_dumps(files))
        definers: dict[_FnKey, str] = {}  # key -> file location of its CREATE
        blocks: dict[_FnKey, str] = {}  # key -> its own body text (last occurrence wins)
        revoked: dict[_FnKey, set[str]] = {}  # key -> every role its EXECUTE is revoked from
        allowed: set[_FnKey] = set()
        for f in files:
            raw = read(f)
            stripped = strip_sql_comments(raw)
            created = _definer_function_blocks(stripped)
            for key, block in created.items():
                definers.setdefault(key, rel(root, f))
                blocks[key] = block
            anon_granted: set[_FnKey] = set()
            for grant, targets, roles in _function_acls(stripped):
                for key in targets:
                    if not grant:
                        revoked.setdefault(key, set()).update(roles)
                    elif "anon" in roles:
                        anon_granted.add(key)
            for key, dyn_roles in _dynamic_revokes(stripped).items():
                revoked.setdefault(key, set()).update(dyn_roles)
            if f in dumps:
                # A pg_dump spells out every grant: no `GRANT … TO anon` on a function the dump
                # creates means anon holds nothing on it directly (PUBLIC still has to be revoked).
                for key in created.keys() - anon_granted:
                    revoked.setdefault(key, set()).add("anon")
            allowed |= _pragma_allowed(raw)

        out: list[Finding] = []
        for key in sorted(definers.keys() - allowed):
            name = _shown(key)
            block = blocks.get(key, "")
            if _DATA_MODIFYING.search(block) and not _OWNERSHIP_CHECK.search(block):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="SECURITY DEFINER function has no internal ownership check",
                        location=definers[key],
                        message=(
                            f"`{name}()` is SECURITY DEFINER and modifies data (INSERT/UPDATE/"
                            "DELETE) but its body never checks the caller's own identity "
                            "(auth.uid()/auth.jwt()/auth.role()) before doing so. Because the "
                            "function runs with the owner's privileges, it bypasses RLS entirely "
                            "— even a caller who is correctly GRANTed EXECUTE can act on any "
                            "org's/user's data, not just their own."
                        ),
                        remediation=(
                            f"Add an ownership check at the top of `{name}()`'s body, e.g. "  # nosec B608 (example SQL in remediation prose, not a real query)
                            "`IF NOT EXISTS (SELECT 1 FROM <table> WHERE id = <arg> AND "
                            "owner_id = auth.uid()) THEN RAISE EXCEPTION 'not authorized'; "
                            f"END IF;`. If `{name}()` is intentionally unscoped (a migration "
                            "helper, system-wide config write), add "
                            f"`-- {_PRAGMA}` on the CREATE line."
                        ),
                        rule="definer-function-grants/no-internal-ownership-check",
                        standards=["OWASP:A01"],
                    )
                )

        for key in sorted(definers.keys() - allowed):
            missing = _REQUIRED - revoked.get(key, set())
            if not missing:
                continue
            name = _shown(key)
            secretish = bool(_SECRETISH.search(name))
            not_revoked = " and ".join("PUBLIC" if r == "public" else r for r in sorted(missing, reverse=True))
            why = (
                "(Supabase's default privileges grant anon EXECUTE directly, so revoking from "
                "PUBLIC alone does not remove it)"
                if "anon" in missing
                else "through the default EXECUTE grant to PUBLIC, which anon is a member of "
                "(revoking from anon alone does not remove it)"
            )
            out.append(
                Finding(
                    check_id=self.id,
                    severity="critical" if secretish else "high",
                    title=self.title,
                    location=definers[key],
                    message=(
                        f"`{name}()` is SECURITY DEFINER and its EXECUTE is never revoked from "
                        f"{not_revoked} — anon can call it with the owner's privileges {why}"
                        + (", and its name suggests it handles secrets/vault material." if secretish
                           else ".")
                    ),
                    remediation=(
                        f"`REVOKE EXECUTE ON FUNCTION {name}(...) FROM PUBLIC, anon, authenticated;` "
                        "and grant it back only to the roles that need it (e.g. service_role, or "
                        "authenticated for an RLS helper signed-in users must call). "
                        f"If intentionally public, add `-- {_PRAGMA}` on the CREATE line."
                    ),
                    rule="definer-function-grants/executable-by-public",
                    standards=["OWASP:A01", "OWASP-LLM:LLM08"],
                )
            )
        return out
