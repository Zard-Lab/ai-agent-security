"""Guard: no package installed directly from a URL/git ref instead of the registry
(checklist §5, new item).

`pip install <name>`/`npm install <name>` resolve a package through the registry
(PyPI/npm), which applies whatever integrity controls the registry provides (package
signing where available, `npm audit signatures`, yanked-release enforcement). Installing
directly from a URL or a git ref (`pip install git+https://...`, `npm install
https://.../tarball/master`, `npm install github:user/repo`) bypasses the registry
entirely: there is no version pinning to a released, indexed artifact, no way to
detect a yanked/malicious release, and the exact code that lands often depends on
whatever a mutable branch/tag currently points to. This is a common technique in
malicious agent-skill install scripts and compromised setup instructions: fetch the
real payload straight from an attacker-controlled (or attacker-compromised) git
remote/URL, skipping the registry's review/scanning entirely. OWASP:A08 (Software and
Data Integrity Failures).

This is distinct from `js-supply-chain`'s floating-version check, which reads
`package.json` *dependency specifiers* (`"pkg": "*"` / `"latest"`) — this guard scans
*install commands* in shell scripts and Dockerfiles for a non-registry source, an
independent signal `js-supply-chain` never sees.

Two rules, matched on a `.sh`/`.bash` line or a Dockerfile `RUN` line. Each line is first
stripped of a trailing `#` comment and split on shell separators (`;`/`&`/`|`), so the
URL/git-ref must be an argument of the install command's OWN segment — a URL in an
unrelated chained command (`pip install x && wget https://.../t.tgz`) or a trailing
comment does not fire:

  * **`pip-url-source`** (HIGH): a `pip`/`pip3 install` line containing a `git+`
    scheme (`git+https://`, `git+ssh://`, `git+git://`) or a bare URL ending in a
    package-archive extension (`.tar.gz`, `.tgz`, `.whl`, `.zip`). A private/internal
    registry-mirror flag and its VALUE (`--index-url <url>`, `--extra-index-url <url>`,
    `--trusted-host <host>`, or pip's short alias `-i <url>`) are stripped out BEFORE the
    source-ref test: a mirror is a
    legitimate, common pattern whose value contains an `https://` substring but installs
    a normal named package. Scoping the strip to the flag+value (not the whole segment)
    means a mirror flag can no longer blind detection of an INDEPENDENT direct install
    target on the same command (`pip install --index-url URL git+https://.../x.git`).
  * **`npm-url-source`** (HIGH): an `npm`/`yarn`/`pnpm install`/`add`/`i` line
    containing a `git+`/bare `git://` scheme, a `github:owner/repo` shorthand, or a
    bare URL ending in a package-archive extension.

Fires HIGH. Suppress an audited case with:

    pip install git+https://github.com/trusted-org/pkg.git  # security: allow-untrusted-package-install-source
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_dockerfiles,
    iter_files,
    pragma_line_set,
    read,
    rel,
    strip_hash_comments,
)

_PIP_INSTALL = re.compile(r"\bpip3?\s+install\b")
_NODE_INSTALL = re.compile(r"\b(?:npm|yarn|pnpm)\s+(?:install|add|i)\b")
# A private-mirror flag AND its value (`--index-url URL` / `--index-url=URL` / `-i URL` / ...).
# Stripped out before the source-ref test so the flag's `https://` value can't be read as an
# install target, WITHOUT blinding an independent direct install target on the same command.
# The long-form flag names are case-insensitive (via the inline `(?i:...)`); the short alias
# `-i` (pip's `--index-url`) is deliberately case-SENSITIVE — `-I` is `--ignore-installed`, a
# valueless flag, so stripping it (and the token after it) would drop a real install target.
_INDEX_FLAG = re.compile(
    r"(?i:--(?:index-url|extra-index-url|trusted-host))(?:=|\s+)\S+"
    r"|(?<!\S)-i(?:=|\s+)?\S+"
)

_GIT_SCHEME = re.compile(r"\bgit\+(?:https?|ssh|git)://|(?<![\w.])git://")
_ARCHIVE_URL = re.compile(r"https?://\S+\.(?:tar\.gz|tgz|whl|zip)\b", re.IGNORECASE)
_GITHUB_SHORTHAND = re.compile(r"(?<![\w/-])github:[\w.-]+/[\w.-]+")

_PRAGMA = re.compile(r"#\s*security:\s*allow-untrusted-package-install-source")

# Shell command separators. Splitting on a run of `; & |` isolates each command on the
# line so the URL/git-ref must be an argument of the install command's OWN segment, not
# an unrelated command chained after it (`pip install x && wget https://.../t.tgz`).
_SEPARATORS = re.compile(r"[;&|]+")

_STANDARDS = ["OWASP:A08"]

# rule id -> the package-manager label used in the finding message.
_TOOLS = {"pip-url-source": "pip", "npm-url-source": "npm/yarn/pnpm"}


class UntrustedPackageInstallSourceGuard(Guard):
    id = "untrusted-package-install-source"
    title = "No package installed directly from a URL/git ref instead of the registry"
    area = "Dependencies"

    # fetch_pkg.sh: pip install git+https://... -> fires
    # untrusted-package-install-source/pip-url-source. Must NOT contain: security:
    # allow-untrusted-package-install-source pragma.
    canary_plant = CanaryPlant(
        files={
            "fetch_pkg.sh": (
                "#!/bin/bash\n"
                "pip install git+https://github.com/some-org/some-pkg.git\n"
            ),
        },
        expects=frozenset({"untrusted-package-install-source/pip-url-source"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # universal: an install command's source is a property of the script, not the stack

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        files = list(iter_files(root, (".sh", ".bash"))) + iter_dockerfiles(root)
        for f in files:
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        pragma_lines = pragma_line_set(_PRAGMA, text, dialect="hash")
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or i in pragma_lines:
                continue

            # Drop a trailing `#` comment (a URL/git-ref in a comment is not an install
            # target) via the shared helper, then evaluate each `;`/`&`/`|`-separated command
            # SEPARATELY so the source ref must be an argument of the install command itself,
            # not an unrelated command sharing the same line (a common Dockerfile RUN idiom).
            for seg in _SEPARATORS.split(strip_hash_comments(line)):
                rule = self._segment_rule(seg)
                if rule:
                    out.append(self._finding(root, f, i, rule, _TOOLS[rule]))
                    break  # one finding per line is enough
        return out

    @staticmethod
    def _segment_rule(seg: str) -> str | None:
        # For pip, drop any `--index-url/--extra-index-url/--trusted-host <value>` token first,
        # so a private-mirror flag's own `https://` value isn't read as a source ref AND a mirror
        # flag can't mask an independent direct install target elsewhere on the same command.
        if _PIP_INSTALL.search(seg):
            pip_seg = _INDEX_FLAG.sub("", seg)
            if _GIT_SCHEME.search(pip_seg) or _ARCHIVE_URL.search(pip_seg):
                return "pip-url-source"
        if _NODE_INSTALL.search(seg) and (
            _GIT_SCHEME.search(seg) or _ARCHIVE_URL.search(seg) or _GITHUB_SHORTHAND.search(seg)
        ):
            return "npm-url-source"
        return None

    def _finding(self, root: Path, f: Path, line: int, rule: str, tool: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                f"This {tool} install command sources a package directly from a URL/git "
                "ref instead of the registry, bypassing whatever version-pinning and "
                "integrity controls the registry provides. The exact code installed can "
                "depend on whatever a mutable branch/tag currently points to."
            ),
            remediation=(
                "Install from the registry with a pinned version instead "
                "(`pip install pkg==1.2.3`, `npm install pkg@1.2.3`). If a fork/patch "
                "genuinely must be installed from source, pin to an immutable commit SHA "
                "(not a branch/tag) and document why the registry release isn't used."
            ),
            rule=f"untrusted-package-install-source/{rule}",
            standards=list(_STANDARDS),
        )
