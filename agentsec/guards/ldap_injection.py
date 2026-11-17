"""Guard: LDAP query built from unescaped untrusted input (CWE-90).

An LDAP search call (`python-ldap`'s `search_s`/`search_ext_s`, or `ldap3`'s
`Connection.search(search_base=..., search_filter=...)`) whose base-DN or filter
argument is built from untrusted input — an f-string or string concatenation — without
escaping lets an attacker inject LDAP filter/DN syntax (e.g. `*)(uid=*))(|(uid=*`),
altering which directory entries match. Depending on what the query gates (an auth
check, a permission lookup), this ranges from information disclosure to authentication
bypass.

Mined from CodeQL's `python/ql/src/Security/CWE-090/LdapInjection.ql`, verified against
the real `LdapInjectionCustomizations.qll`: two distinct sinks (the base-DN argument and
the filter argument of an LDAP search), sanitized by an escaping call (`escape_dn_chars`/
`escape_filter_chars`, from either `python-ldap` or `ldap3`).

**Corpus-prevalence note:** flagged as a lower-priority candidate in the research pass
that produced this guard — LDAP is a niche integration for this stack (FastAPI + React +
Postgres + LLM/RAG). Built anyway since the detection is clean and the pattern is real,
same treatment CodeQL itself gives it (a dedicated query despite being a narrower use
case than, say, SQL injection).

Fires MEDIUM on a `.search_s(`/`.search_ext_s(`/`.search(` call whose arguments are built
from an f-string or `+` concatenation, unless `escape_dn_chars`/`escape_filter_chars`
appears on the same line. Suppress with `# security: allow-ldap-injection`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    split_call_args,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-ldap-injection")

# An LDAP search call opening. python-ldap's search_s/search_ext_s method names are distinctive
# enough to match bare; bare `.search(` (ldap3's API) is NOT — it collides with the extremely
# common `re.search(pattern, string)` from the stdlib (a real FP caught against agentsec's own
# source during this guard's build). So a bare `.search(` counts as an LDAP sink ONLY when its
# arguments carry ldap3's distinctive kwargs (`search_base=`/`search_filter=`) — checked against
# the WHOLE call's arguments below, so a call written across lines is seen (review #395 H4).
_LDAP_CALL_OPEN = re.compile(r"""\.(?P<m>search_ext_s|search_s|search)\s*\(""")
_LDAP3_KWARGS = re.compile(r"""(?:search_base|search_filter)\s*=""")

# Same dynamic-construction shape as the regex-injection sub-check: f-string, `+`
# concatenation, or `.format(`.
_DYNAMIC_ARG = re.compile(
    r"""f['"]|(?:['"][^'"]*['"]|\w[\w.\[\]]*)\s*\+\s*(?:['"][^'"]*['"]|\w[\w.\[\]]*)|['"][^'"]*['"]\s*\.\s*format\s*\("""
)

_ESCAPE_SANITIZER = re.compile(r"""escape_dn_chars|escape_filter_chars""")


class LdapInjectionGuard(Guard):
    id = "ldap-injection"
    title = "LDAP query built from unescaped untrusted input"
    area = "Code safety"

    # ldap_auth.py: search_s filter built from an f-string with untrusted input, unescaped ->
    # fires ldap-injection.
    canary_plant = CanaryPlant(
        files={
            "ldap_auth.py": (
                "import ldap\n\n"
                "def find_user(conn, username):\n"
                "    return conn.search_s(\"ou=users,dc=example,dc=com\", ldap.SCOPE_SUBTREE, f\"(uid={username})\")\n"
            ),
        },
        expects=frozenset({"ldap-injection/unescaped-search"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f, read(f)))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        pragma_lines = pragma_line_set(_PRAGMA, text, dialect="python")
        for m in _LDAP_CALL_OPEN.finditer(text):
            arglist = split_call_args(text, m.end() - 1, python=True)
            if arglist is None:
                continue  # unbalanced parens — don't guess
            args = ",".join(arglist)
            # A bare `.search(` needs ldap3's distinctive kwargs to count (avoid re.search FP).
            if m.group("m") == "search" and not _LDAP3_KWARGS.search(args):
                continue
            if not _DYNAMIC_ARG.search(args):
                continue
            if _ESCAPE_SANITIZER.search(args):
                continue
            start_line = text.count("\n", 0, m.start()) + 1
            end_line = start_line + args.count("\n")
            # The pragma may sit on any line the (possibly multi-line) call spans, or the one after
            # its closing paren — the same window as before, read on the comment view (#424): a
            # string quoting the phrase inside the call no longer counts.
            if pragma_lines.intersection(range(start_line, end_line + 2)):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="LDAP search built from unescaped untrusted input",
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        "This LDAP search call's base-DN or filter argument is built "
                        "from an f-string, concatenation, or .format() call. An "
                        "attacker who controls that input can inject LDAP filter/DN "
                        "syntax, altering which directory entries match."
                    ),
                    remediation=(
                        "Escape the untrusted portion with escape_dn_chars() (for the "
                        "base DN) or escape_filter_chars() (for the filter) before it "
                        "reaches the query — from python-ldap's ldap.dn/ldap.filter "
                        "modules, or ldap3.utils.conv. Suppress an audited case with "
                        "`# security: allow-ldap-injection`."
                    ),
                    rule="ldap-injection/unescaped-search",
                    standards=["OWASP:A03"],
                )
            )
        return out
