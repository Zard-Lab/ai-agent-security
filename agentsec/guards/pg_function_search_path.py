"""Guard: SECURITY DEFINER functions must pin their search_path (CIS:6.7).

A PostgreSQL function declared `SECURITY DEFINER` runs with the privileges of
its **owner**, not the caller. By default, functions inherit the session's
`search_path` at call time — this means a sufficiently-privileged attacker
(or any role that can create objects in a schema on the search path) can plant
a trojan table or function that the definer function resolves instead of the
intended system object. The attack is known as "search_path poisoning" or
"schema-injection via search_path".

The fix is one clause on the function definition:

    CREATE FUNCTION safe_fn() RETURNS void LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
    AS $$ BEGIN END $$;

Without `SET search_path`, any object reference inside the definer body
(pg_catalog functions, vault.decrypted_secrets, etc.) is resolved at call time
using the session path, not a fixed path controlled by the function author.

This guard is DISTINCT from `definer-function-grants` (which checks REVOKE/GRANT
on EXECUTE). A function can have its EXECUTE revoked and still be vulnerable to
search_path poisoning if called by the owner directly. Both guards should pass.

**Detection strategy:** For each file, scan comment-stripped SQL for occurrences
of `SECURITY DEFINER`. For each match, inspect a ~500-char window around it
(from the preceding CREATE FUNCTION keyword up to the match plus look-ahead)
for `SET search_path`. If absent, emit one HIGH finding pointing to the
SECURITY DEFINER line.

**Suppress** an intentional case with:
    -- security: allow-pg-definer-search-path

anywhere in the file. This is a file-level opt-out (not per-function) — use
when a migration file is known-safe and pinning is handled by a session-level
`SET` or wrapper.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_sql_comments

_PRAGMA = "security: allow-pg-definer-search-path"

_STANDARDS = ["CIS:6.7", "OWASP:A08"]

# Matches SECURITY DEFINER (with optional whitespace between words).
_SEC_DEFINER = re.compile(r"security\s+definer", re.I)

# Matches SET search_path — including the quoted-identifier form a pg_dump emits
# (`SET "search_path" TO ''`), which the bare form missed (a snapshot-file FP source).
_SET_SEARCH_PATH = re.compile(r'set\s+"?search_path"?', re.I)

# Matches CREATE [OR REPLACE] FUNCTION to anchor the look-back window.
_CREATE_FN = re.compile(r"create\s+(?:or\s+replace\s+)?function", re.I)
# The same, but capturing the function NAME (optionally schema-qualified, optionally quoted).
_CREATE_FN_NAMED = re.compile(
    r"create\s+(?:or\s+replace\s+)?function\s+(?:\"?[\w$]+\"?\s*\.\s*)?\"?([\w$]+)\"?",
    re.I,
)
# `ALTER FUNCTION <name>(…) SET search_path = …` — the remediation this guard's own text
# recommends. It NAMES the function it hardens, so unlike an inline `SET search_path` it can
# vouch for that function from anywhere in the file. Cutting the look-forward at the next
# CREATE FUNCTION (to stop a neighbour's INLINE setting vouching for this one) also discarded
# these, so a function hardened by an ALTER that happened to sit after another definition fired
# a false HIGH on correctly hardened code (#437 review).
_ALTER_FN_SEARCH_PATH = re.compile(
    r"alter\s+function\s+(?:\"?[\w$]+\"?\s*\.\s*)?\"?([\w$]+)\"?[^;]*?set\s+\"?search_path\"?",
    re.I | re.DOTALL,
)

# How many characters before and after a SECURITY DEFINER match to inspect.
_WINDOW = 500


def _code_ordinals(text: str, starts: list[int]) -> list[int]:
    """For each offset in the ascending `starts`, how many non-whitespace characters of `text` come
    before it. Deleting a SQL comment and blanking it to whitespace leave the same non-whitespace
    characters in the same order, so this names one code position in either text (#1006)."""
    out: list[int] = []
    count = prev = 0
    for start in starts:
        count += len("".join(text[prev:start].split()))
        out.append(count)
        prev = start
    return out


class PgFunctionSearchPathGuard(Guard):
    id = "pg-function-search-path"
    title = "SECURITY DEFINER function missing SET search_path (search_path poisoning risk)"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # sql/schema.sql already has SECURITY DEFINER without SET search_path ->
    # security-definer-no-search-path fires from schema.sql.
    canary_plant = CanaryPlant(expects=frozenset({"pg-function-search-path/security-definer-no-search-path"}))

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".sql",)):
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="sql"):
                continue

            stripped = strip_sql_comments(raw)
            # Every function hardened by a name-qualified ALTER anywhere in this file.
            altered_names = {m.group(1).lower() for m in _ALTER_FN_SEARCH_PATH.finditer(stripped)}
            # ALTER statements are matched BY NAME above, so blank them out of the text the
            # proximity window is sliced from. The window then measures exactly one thing —
            # an INLINE `SET search_path` on this definition — and an ALTER hardening some
            # OTHER function can no longer vouch for this one just by being nearby. Blanked to
            # equal length so every offset below still lines up with `stripped`.
            windowed = _ALTER_FN_SEARCH_PATH.sub(lambda m: " " * len(m.group()), stripped)
            raw_lines = raw.splitlines()
            # Line numbers come from a comment-BLANKED copy, whose offsets are the raw file's.
            # `stripped` deletes a `/* … */` block together with its newlines, so counting lines
            # on it reported every definer below a multi-line license header too high (#442).
            # Detection stays on `stripped`: the 500-char windows above are measured on it, and
            # blanking would count a body's comments against them and push `CREATE FUNCTION` out
            # of the look-back, a silent miss. A match is paired with the blanked match at the same
            # code position, never with the k-th one: a comment can weld a match into one text only
            # (`SECURITY/**/DEFINER` matches once blanked, `SECURITY DEF/**/INER` once deleted), and
            # one of each leaves the counts equal and every pairing shifted (#1006 review). A match
            # with no blanked counterpart keeps the line counted on `stripped`.
            blanked = strip_sql_comments(raw, blank=True)
            blank_starts = [b.start() for b in _SEC_DEFINER.finditer(blanked)]
            raw_start_at = dict(zip(_code_ordinals(blanked, blank_starts), blank_starts, strict=True))
            matches = list(_SEC_DEFINER.finditer(stripped))
            ordinals = _code_ordinals(stripped, [m.start() for m in matches])

            for m, ordinal in zip(matches, ordinals, strict=True):
                pos = m.start()
                # Look backwards from this match for the nearest CREATE FUNCTION.
                look_back = windowed[max(0, pos - _WINDOW): pos]
                look_fwd = windowed[pos: pos + _WINDOW]

                # Anchor to a real function definition: a "SECURITY DEFINER" with no
                # CREATE FUNCTION in the look-back is prose/a string literal (e.g. a
                # RAISE NOTICE or a Splinter lint description), not a definer function.
                back_anchors = list(_CREATE_FN.finditer(look_back))
                if not back_anchors:
                    continue

                # Bound the window at the neighboring function definitions (issue #422 S6):
                # start the look-back at THIS function's CREATE (the nearest one before the
                # match) and cut the look-forward at the NEXT CREATE FUNCTION, so an adjacent
                # function's SET search_path can never vouch for this one. The 500-char cap
                # stays the outer limit.
                look_back = look_back[back_anchors[-1].start():]
                next_fn = _CREATE_FN.search(look_fwd)
                if next_fn:
                    look_fwd = look_fwd[: next_fn.start()]
                # A name-qualified `ALTER FUNCTION <this one> … SET search_path` hardens THIS
                # function wherever it sits, so it is checked file-wide rather than inside the
                # window — the window bound exists only to stop a NEIGHBOUR's inline setting
                # vouching for this function, which a named ALTER cannot be confused with.
                named = _CREATE_FN_NAMED.search(look_back)
                if named and named.group(1).lower() in altered_names:
                    continue
                window = look_back + look_fwd

                if _SET_SEARCH_PATH.search(window):
                    continue  # search_path is pinned — safe

                raw_start = raw_start_at.get(ordinal)
                if raw_start is not None:
                    lineno = raw.count("\n", 0, raw_start) + 1
                else:
                    lineno = stripped.count("\n", 0, pos) + 1
                # Clamp to valid range.
                lineno = max(1, min(lineno, len(raw_lines)))

                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="SECURITY DEFINER function missing SET search_path",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "This SECURITY DEFINER function does not pin its `search_path`. "
                            "The function body resolves object names (tables, functions, "
                            "operators) using the caller's session search_path, which can be "
                            "manipulated by any role that can create objects in a schema on "
                            "that path. An attacker can shadow a trusted object (e.g. a "
                            "pg_catalog function or vault table) with a malicious one, "
                            "executing arbitrary logic with the function owner's privileges."
                        ),
                        remediation=(
                            "Add `SET search_path = public, pg_temp` (or a more restrictive "
                            "fixed path) to the function definition:\n\n"
                            "    CREATE FUNCTION f() ... SECURITY DEFINER\n"
                            "    SET search_path = public, pg_temp\n"
                            "    AS $$ ... $$;\n\n"
                            "Including `pg_temp` last prevents temp-schema injection. "
                            "To suppress for a known-safe file, add "
                            "`-- security: allow-pg-definer-search-path`."
                        ),
                        rule="pg-function-search-path/security-definer-no-search-path",
                        standards=list(_STANDARDS),
                    )
                )

        return out
