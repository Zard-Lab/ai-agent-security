"""Guard: empty password field in a checked-in JSON/YAML config file (CWE-862, checklist §8, new item).

    {
      "database": {
        "credentials": {
          "password": ""
        }
      }
    }

A key literally named ``password`` (case-insensitive) whose value is the empty string is a
config-file auth-bypass-by-omission (CWE-862, Missing Authorization): many services treat a
blank password field as "no authentication required" rather than "not yet filled in", so a
checked-in empty password field silently disables auth for whoever deploys that config
verbatim. Unlike `12-db-password-strong` (the REAL deployed credential value, invisible to a
static scan by design — a `surface: "ops"` manual-forever item), this is a fully repo-visible
static fact: the literal string is sitting in the file the guard can read.

Ported from CodeQL's ``javascript/ql/src/Security/CWE-862/EmptyPasswordInConfigurationFile.ql``
(and its shared ``PasswordInConfigurationFileQuery.qll`` library). CodeQL's ``config()``
predicate matches **only JSON objects and YAML mappings** — despite the CWE-862 tag, it does
NOT match ``.env``/``.ini``/``.properties`` files. This guard mirrors that scope exactly:

  - ``*.json`` — parsed with stdlib ``json``, walked recursively (dicts and arrays-of-dicts,
    at any nesting depth) for a key whose name is exactly ``password`` (case-insensitive,
    never a substring match — ``password_hint``/``password_placeholder`` do not match).
  - ``*.yaml``/``*.yml`` — agentsec has no PyYAML runtime dependency (stdlib-only by design;
    see ``npm_ignore_scripts.py`` for the same regex-line-match precedent on workflow YAML), so
    YAML mappings are matched per-line: ``password:`` followed by nothing, or an explicit
    empty-string value (``""``/``''``). A bare ``password:`` line only fires when the next
    non-blank, non-comment line is **not** more deeply indented — a more-indented next line means
    ``password:`` opens a nested YAML mapping (an OpenAPI schema property, a Helm
    ``valueFrom``/``secretKeyRef`` block, ...), not an empty/null scalar, and CWE-862 (a *value*
    that is the empty string) does not apply to it. An explicit ``""``/``''`` always fires
    regardless of what follows, since that is unambiguously an empty-string value.
  - NOT ``.env``/``.ini``/``.properties`` — out of scope, matching the CodeQL predicate this
    guard was ported from.

Excludes, mirroring CodeQL's upstream exclusion list:
  - test/example/fixture/migration paths (``is_nonproduct_path``) — a blank password in a test
    fixture is deliberately fake, not a real leak.
  - locale/language/i18n paths and any file whose stem is ``translation``/``translations`` —
    not config files at all; ``is_nonproduct_path`` doesn't cover this bucket, so it's added
    locally.
  - any file literally named ``package.json`` — dependency blocks are version strings, never
    password fields, but excluded defensively for the JSON case regardless.

Fires **HIGH** — an empty password is a complete, silent auth bypass, not a lesser-severity
hygiene issue.

Suppress an audited/intentional case (e.g. a documented decoy fixture outside the excluded
paths) with ``security: allow-empty-password-in-config`` anywhere in the file: as a ``#`` comment
in YAML (only a comment counts there: a YAML scalar quoting the phrase does not), or (JSON has no
comment syntax) as any string value in JSON, e.g. ``"_note": "security: allow-empty-password-in-config"``.
"""
from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_PRAGMA = "security: allow-empty-password-in-config"

_STANDARDS = ["OWASP:A02", "CWE-862"]

# Locale/i18n/translation paths — NOT covered by the shared `is_nonproduct_path` list (that list
# is tests/examples/fixtures/migrations, not localization trees), so added locally. Mirrors
# CodeQL's own exclusion (`(lang(uage)?s?|locale?s?|i18n)/` + a `translations?` filename stem).
_LOCALE_SEGMENT = re.compile(r"(?:^|/)(?:lang(?:uages?)?|locales?|i18n)(?:/|$)", re.IGNORECASE)


def _is_locale_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    if _LOCALE_SEGMENT.search(norm):
        return True
    name = norm.rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return stem.lower() in ("translation", "translations")


# A YAML mapping key literally named `password` with an explicit empty-string value (`""`/`''`) —
# unambiguous regardless of what follows. Group 1 captures the key's indentation (unused here, kept
# for symmetry with `_YAML_PASSWORD_BARE`). Never a runtime-parsed value, so this is a per-line
# regex match, not a real YAML parse (agentsec is stdlib-only; see module docstring).
_YAML_PASSWORD_EMPTY_VALUE = re.compile(r'^(\s*)password\s*:\s*(?:""|\'\')\s*$', re.IGNORECASE)

# A YAML mapping key literally named `password` followed by nothing at all on the line — in real
# YAML this is either a null/empty scalar (no auth value at all — CWE-862 applies the same way an
# explicit `""` does) OR the opening of a nested mapping (`password:` with more deeply indented
# child keys below it, e.g. an OpenAPI `properties.password` schema stanza or a Helm
# `valueFrom.secretKeyRef` block) — those are structurally NOT a password value at all, empty or
# otherwise, so they must not fire. Disambiguating between the two requires looking at the next
# line's indentation, which `_opens_nested_mapping` below does; this regex alone only locates the
# candidate line and captures its indentation in group 1.
_YAML_PASSWORD_BARE = re.compile(r'^(\s*)password\s*:\s*$', re.IGNORECASE)

# A line that is blank or a full-line `#` comment — skipped when walking forward for the next
# syntactic sibling of a bare `password:` line, since neither affects YAML structure.
_YAML_BLANK_OR_COMMENT = re.compile(r"^\s*(?:#.*)?$")


def _find_empty_password_paths(data: object) -> list[str]:
    """Iterative walk (never native recursion — the JSON comes from an untrusted repo, and a
    deeply-nested file must not RecursionError the guard, the same reasoning `mcp_config_security`
    documents) for a key literally named `password` (case-insensitive) whose value is the empty
    string, at any nesting depth including inside arrays of objects.

    Returns the dotted key-path of each match (e.g. `database.credentials.password`), for the
    finding message. Matches on exact key equality only — `password_hint`/`password_placeholder`
    never match, by construction (no substring/prefix check anywhere in this function)."""
    matches: list[str] = []
    work: list[tuple[object, str]] = [(data, "")]
    while work:
        node, path = work.pop()
        if isinstance(node, dict):
            for key, val in node.items():
                child_path = f"{path}.{key}" if path else str(key)
                if isinstance(key, str) and key.lower() == "password" and val == "":
                    matches.append(child_path)
                else:
                    work.append((val, child_path))
        elif isinstance(node, list):
            for item in node:
                work.append((item, path))
    return matches


class EmptyPasswordInConfigGuard(Guard):
    id = "empty-password-in-config"
    title = "Empty password field in checked-in config file"
    area = "Secrets"

    # empty_password_config.json: a "password" key with an empty string value ->
    # fires empty-password-in-config/empty-password.
    canary_plant = CanaryPlant(
        files={
            "empty_password_config.json": '{"username": "admin", "password": ""}',  # nosec B105 (canary plant fixture text, not a real credential)
        },
        expects=frozenset({"empty-password-in-config/empty-password"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Stack-agnostic: a blank password field in a checked-in JSON/YAML config is bad on any
        # stack, so this guard is not gated on any detected `profile.features`.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        for f in iter_files(root, (".json",)):
            r = rel(root, f)
            if self._skip(r, profile):
                continue
            if f.name.lower() == "package.json":
                continue
            text = read(f)
            # JSON has no comment syntax, so the documented opt-out is a string value: raw (#1040 T5).
            if not text or pragma_present(_PRAGMA, text, dialect=None):
                continue
            out.extend(self._scan_json(r, text))

        for f in iter_files(root, (".yaml", ".yml")):
            r = rel(root, f)
            if self._skip(r, profile):
                continue
            text = read(f)
            # YAML's opt-out is a `#` comment, so a scalar quoting the phrase does not count (#1040 T5).
            if not text or pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            out.extend(self._scan_yaml(r, text))

        return out

    def _skip(self, r: str, profile: StackProfile) -> bool:
        return is_nonproduct_path(r, profile.archive_segments) or _is_locale_path(r)

    def _scan_json(self, r: str, text: str) -> list[Finding]:
        with contextlib.suppress(json.JSONDecodeError, RecursionError):
            data = json.loads(text)
            if isinstance(data, (dict, list)):
                return [self._finding(r, path) for path in _find_empty_password_paths(data)]
        return []

    def _scan_yaml(self, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if _YAML_PASSWORD_EMPTY_VALUE.match(line):
                out.append(self._finding(f"{r}:{lineno}", "password"))
                continue
            m = _YAML_PASSWORD_BARE.match(line)
            if m and not self._opens_nested_mapping(lines, lineno, len(m.group(1))):
                out.append(self._finding(f"{r}:{lineno}", "password"))
        return out

    def _opens_nested_mapping(self, lines: list[str], lineno: int, indent: int) -> bool:
        """True if the bare `password:` at 1-based `lineno` (whose key starts at column `indent`)
        is followed by a more-deeply-indented line — meaning it opens a nested YAML mapping rather
        than being an empty/null scalar. Blank lines and full-line comments are skipped while
        looking for that next syntactic sibling, since neither changes YAML structure. `lines` is
        the whole file (0-indexed), so `lines[lineno:]` is everything strictly after the
        `password:` line."""
        for next_line in lines[lineno:]:
            if _YAML_BLANK_OR_COMMENT.match(next_line):
                continue
            next_indent = len(next_line) - len(next_line.lstrip(" \t"))
            return next_indent > indent
        return False

    def _finding(self, location: str, key_path: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=location,
            message=(
                f"The key `{key_path}` is named `password` and its value is the empty string. "
                "Many services treat a blank password field as authentication being disabled "
                "rather than merely unset, so a checked-in empty password can silently turn off "
                "auth for whoever deploys this config as-is (CWE-862: Missing Authorization)."
            ),
            remediation=(
                "Never check in a real password value, empty or otherwise. Remove the key "
                "entirely (so a missing-credential error surfaces at startup) or reference an "
                "environment variable / secrets manager, e.g. `\"password\": \"${DB_PASSWORD}\"`. "
                "If this is a genuinely intentional decoy/fixture outside the excluded test "
                "paths, suppress it with a `# security: allow-empty-password-in-config` "
                "comment on any line of the YAML file, or (for JSON, which has no comment "
                "syntax) the same string as any string VALUE in the file, e.g. "
                "`\"_note\": \"security: allow-empty-password-in-config\"`."
            ),
            rule="empty-password-in-config/empty-password",
            standards=list(_STANDARDS),
        )
