"""Guard: policy's current_setting() call names an unqualified parameter (pgrls SEC024).

An RLS policy reads per-request tenant/session context from a **customized** run-time parameter
the application sets on every connection: `USING (tenant_id = current_setting('app.tenant_id'))`.
Postgres requires the name of such a customized parameter to be *qualified* — `prefix.name`,
containing a period. The prefix namespaces application parameters away from the server's own
settings; an unqualified name like `tenant_id` cannot be defined or `SET` as a customized
parameter at all (`SET tenant_id = ...` raises `unrecognized configuration parameter`).

Flags a policy whose `current_setting()` call names an unqualified parameter — a string literal
with no period, and not one of Postgres's own built-in unqualified settings (`search_path`,
`timezone`, `role`, `application_name`, and similar). This is almost always a dropped prefix —
the application sets `app.tenant_id` but the policy reads `tenant_id`. The failure is quiet: with
the two-argument form the unset parameter yields NULL and the comparison matches no rows (the
table looks empty); with the one-argument form every query against the table errors instead.
Either way the policy never sees the context it was written to read.

Suppress: `-- security: allow-current-setting-unqualified` on the statement's own line (or
anywhere in the same file).

OWASP:A01.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    iter_files,
    iter_statement_spans,
    read,
    rel,
    strip_sql_comments,
)
from .rls_inverted_auth_check import _USING_HEAD, _WITH_CHECK_HEAD, _clause_body
from .rls_permissive_policy import _CREATE_POLICY_HEAD

# Postgres's own built-in settings that are legitimately unqualified (not an exhaustive GUC list
# -- just the common ones a policy might plausibly reference, to avoid a false positive on a
# genuine built-in read).
_BUILTIN_SETTINGS = frozenset({
    "search_path", "timezone", "role", "application_name", "client_encoding",
    "datestyle", "lc_monetary", "statement_timeout", "server_version",
})
_CURRENT_SETTING_CALL = re.compile(
    r"\bcurrent_setting\s*\(\s*'([^']*)'",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-current-setting-unqualified")


def _unqualified_names(clause: str) -> list[str]:
    out = []
    for m in _CURRENT_SETTING_CALL.finditer(clause):
        name = m.group(1)
        if "." not in name and name.lower() not in _BUILTIN_SETTINGS:
            out.append(name)
    return out


class RlsCurrentSettingUnqualifiedGuard(Guard):
    id = "rls-current-setting-unqualified"
    title = "Policy's current_setting() names an unqualified parameter — likely a dropped app-namespace prefix"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_current_setting_unqualified.sql": (
                "CREATE TABLE public.canary_setting_unqualified (id uuid PRIMARY KEY, tenant_id int);\n"
                "ALTER TABLE public.canary_setting_unqualified ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_setting_unqualified_p ON public.canary_setting_unqualified "
                "USING (tenant_id = current_setting('tenant_id', true)::int);\n"
            ),
        },
        expects=frozenset({"rls-current-setting-unqualified/no-namespace-prefix"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            text = read(f)
            view_lines = comment_view(text, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            blanked = strip_sql_comments(text, blank=True)
            for start, end in iter_statement_spans(blanked, _CREATE_POLICY_HEAD):
                stmt = blanked[start:end]
                s_line = blanked.count("\n", 0, start)
                e_line = blanked.count("\n", 0, end)
                window = "\n".join(view_lines[max(0, s_line - 1) : e_line + 1])
                if _PRAGMA.search(window):
                    continue
                using_body = _clause_body(stmt, _USING_HEAD) or ""
                check_body = _clause_body(stmt, _WITH_CHECK_HEAD) or ""
                names = set(_unqualified_names(using_body)) | set(_unqualified_names(check_body))
                if not names:
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                for name in sorted(names):
                    out.append(self._finding(loc, name))
        return out

    def _finding(self, loc: str, name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="low",
            title=self.title,
            location=loc,
            message=(
                f"This RLS policy calls `current_setting('{name}')` — an unqualified parameter "
                "name (no period). Postgres requires a customized run-time parameter's name to be "
                "namespace-qualified (`prefix.name`); an unqualified name like this one cannot be "
                "`SET` as a customized parameter at all. This is almost always a dropped app "
                "namespace prefix (e.g. the application sets `app." + name + "` but the policy "
                "reads plain `" + name + "`), which silently never sees the session context it "
                "was written to read."
            ),
            remediation=(
                f"Add the application's namespace prefix, e.g. `current_setting('app.{name}')`, "
                "matching whatever prefix the application actually SETs per request. If this name "
                "is genuinely a built-in Postgres setting this guard doesn't recognize, suppress "
                "with `-- security: allow-current-setting-unqualified`."
            ),
            rule="rls-current-setting-unqualified/no-namespace-prefix",
            standards=["OWASP:A01"],
        )
