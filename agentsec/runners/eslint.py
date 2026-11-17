"""ESLint — JavaScript/TypeScript SAST.

Runs the **target project's own** ESLint (flat config) with the JSON formatter and
maps results into `Finding`s. agentsec ships no eslint config — it relies on the
project's `eslint.config.*` / `.eslintrc*` (which, in the donor stack, loads
`eslint-plugin-security`). Only `security/*` rules map to actionable severities;
everything else is reported at `info` so style lint doesn't trip the gate.

Mirrors the donor's `frontend-eslint.yml`: `eslint . --format json`.

**Precondition (#714).** This runner scans with the project's own ESLint, so it runs only
when that ESLint can actually run: its binary resolves under `node_modules/.bin`, a config
is discoverable, AND the installed major version accepts that config's vocabulary (eslint 9
refuses a legacy-only project). `run()` reports a disclosed skip otherwise — see
`_runnable()` for why the base class's `which()` gate cannot answer this and why the skip
is not an error.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, normalize_severity

from .base import Runner, RunnerResult, as_list, exec_capture_or_raise

_SECURITY_PREFIX = "security/"

# The config names ESLint itself resolves: flat config (v9+) first, then the legacy
# `.eslintrc` family. `package.json` may also carry an `eslintConfig` key (v8), checked
# separately. ESLint exits non-zero with an empty report when it finds none of these, which
# is the same "errored" trap as a missing binary, so config presence gates too.
_FLAT_CONFIGS = (
    "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
    "eslint.config.ts", "eslint.config.mts", "eslint.config.cts",
)
_LEGACY_CONFIGS = (
    ".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.mjs",
    ".eslintrc.json", ".eslintrc.yml", ".eslintrc.yaml",
)
_ESLINT_CONFIGS = _FLAT_CONFIGS + _LEGACY_CONFIGS
# The deprecated escape hatch that still makes eslintrc valid on ESLint 9. Checking the
# environment is exact rather than a guess: `exec_capture` builds the child env from
# `child_env()`, which is `dict(os.environ)` plus a PATH append, so the scanner subprocess
# sees precisely what we see here.
_FLAT_OPT_OUT = "ESLINT_USE_FLAT_CONFIG"
# npm/pnpm/bun all write the shim under `node_modules/.bin`; Windows adds .cmd/.ps1 wrappers.
_ESLINT_BINS = ("eslint", "eslint.cmd", "eslint.ps1")


def _search_dirs(root: Path, profile: StackProfile) -> tuple[Path, ...]:
    """The frontend dir, plus the repo root when they differ.

    Workspace/hoisted layouts (pnpm workspaces, npm workspaces) install `node_modules` and
    keep the shared eslint config at the REPO ROOT while the frontend lives in a subdir, so
    checking only `frontend_dir` would invent a new false skip on exactly the monorepos the
    tool targets.
    """
    fe = root / profile.frontend_dir if profile.frontend_dir else root
    return (fe,) if fe.resolve() == root.resolve() else (fe, root)


def _has_local_eslint(dirs: tuple[Path, ...]) -> bool:
    """Project-local installs only, deliberately: a PATH/global eslint is NOT accepted
    because `npx --no-install` ignores one anyway (measured: with a global eslint first on
    PATH it still fetched the manifest and exited `npm ERR! canceled`). So this gate loses
    no coverage the runner ever had, it just stops the unwinnable attempt."""
    return any((d / "node_modules" / ".bin" / n).exists() for d in dirs for n in _ESLINT_BINS)


def _has_eslint_config(dirs: tuple[Path, ...]) -> bool:
    for d in dirs:
        if any((d / n).exists() for n in _ESLINT_CONFIGS):
            return True
        pkg = d / "package.json"
        try:
            data: Any = json.loads(pkg.read_text(encoding="utf-8", errors="ignore") or "{}")
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if isinstance(data, dict) and data.get("eslintConfig"):
            return True
    return False


def _eslint_major(dirs: tuple[Path, ...]) -> int | None:
    """Major version of the INSTALLED eslint, or None when it can't be determined."""
    for d in dirs:
        pkg = d / "node_modules" / "eslint" / "package.json"
        try:
            data: Any = json.loads(pkg.read_text(encoding="utf-8", errors="ignore") or "{}")
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        head = str(data.get("version") or "").split(".", 1)[0]
        if head.isdigit():
            return int(head)
    return None


def _config_vocabulary_matches(dirs: tuple[Path, ...]) -> bool:
    """True unless the installed eslint refuses the config vocabulary the project uses.

    A config file existing is not the same as a config eslint will ACCEPT. From v9 the flat
    config is the default and eslint refuses to run on a legacy-only project, exiting
    non-zero with an empty report — which is the same `errored` trap a missing binary was,
    just through a different door (#720 review). Measured against a real eslint 9.39.5 with
    only `.eslintrc.json`: "ESLint couldn't find an eslint.config.(js|mjs|cjs) file."

    Deliberately permissive in the two uncertain directions, because a false SKIP is a
    silent coverage loss and strictly worse than the error it would avoid:
    - version unreadable (`None`) or < 9 → accept either vocabulary, as today;
    - `ESLINT_USE_FLAT_CONFIG=false` explicitly set → the user opted legacy back in, so
      honor it rather than second-guessing their deliberate configuration.
    """
    major = _eslint_major(dirs)
    if major is None or major < 9:
        return True
    if any((d / n).exists() for d in dirs for n in _FLAT_CONFIGS):
        return True
    return os.environ.get(_FLAT_OPT_OUT, "").strip().lower() == "false"


class EslintRunner(Runner):
    id = "eslint"
    area = "Web & browser"
    binary = "npx"  # node ships npx; binary_name() picks pnpm when present
    install_hint = "npm/pnpm + eslint in the project (e.g. eslint-plugin-security)"

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def binary_name(self, profile: StackProfile) -> str:
        return "pnpm" if "pnpm" in profile.package_managers else "npx"

    def _runnable(self, root: Path, profile: StackProfile) -> bool:
        """True when the project's OWN eslint can actually run here.

        `binary`/`binary_name()` resolve the package MANAGER, and npx ships with every Node
        install, so the base class's `which()` gate cannot answer this question: it is true
        on any machine with Node, whatever the project actually uses. Without this check a
        Biome/oxlint/no-linter frontend took the failure path by construction and reported as
        a scanner ERROR rather than a disclosed skip, which reads as "agentsec is broken"
        when the truth is "this project does not use that linter" (#714).

        It also closes an undisclosed Tier-0 egress. `npx --no-install` suppresses the
        INSTALL, not the LOOKUP: npm 9 translates it to `--yes false` and still resolves the
        manifest against registry.npmjs.org before declining (measured: `http fetch GET 200
        https://registry.npmjs.org/eslint`, then `npm ERR! canceled`). That request happens
        only on this failure path — with eslint installed locally, npm resolves from
        `node_modules/.bin` and makes no request at all (also measured). Never executing the
        unwinnable case is what keeps `tier_required = 0` and eslint's absence from
        `_EGRESS_CATALOG` true statements rather than assumed ones (G5 / RFC #135).
        """
        dirs = _search_dirs(root, profile)
        return (
            _has_local_eslint(dirs)
            and _has_eslint_config(dirs)
            and _config_vocabulary_matches(dirs)
        )

    def run(self, root: Path, profile: StackProfile) -> RunnerResult:
        if not self._runnable(root, profile):
            # `available=False` is the existing disclosed-skip channel ("Scanners not
            # installed (skipped)") — NOT an error, and nothing is executed, so nothing
            # egresses. Deliberately gated here and not in `applies()`: select_runners()
            # drops a non-applying runner with no bucket at all, and silence is the wrong
            # trade for a tool whose value is honest coverage.
            return RunnerResult(self.id, available=False)
        return super().run(root, profile)

    def invoke(self, root: Path, profile: StackProfile) -> str:
        fe = root / profile.frontend_dir if profile.frontend_dir else root
        tool = self.binary_name(profile)
        # eslint is project-local (node_modules/.bin) — run via the package manager.
        # eslint exits non-zero when it finds problems; the JSON is still on stdout.
        args = (
            ["pnpm", "exec", "eslint", ".", "--format", "json"]
            if tool == "pnpm"
            else ["npx", "--no-install", "eslint", ".", "--format", "json"]
        )
        _, out, _ = exec_capture_or_raise(args, cwd=fe)
        return out or "[]"

    def parse(self, raw: str) -> list[Finding]:
        data: Any = json.loads(raw)
        out: list[Finding] = []
        for file_obj in data if isinstance(data, list) else []:
            if not isinstance(file_obj, dict):
                continue
            file_path = str(file_obj.get("filePath") or "?")
            for m in as_list(file_obj.get("messages")):
                if not isinstance(m, dict):
                    continue
                rule_id = str(m.get("ruleId") or "")
                line = m.get("line")
                loc = f"{file_path}:{line}" if line else file_path
                eslint_sev = m.get("severity")
                if rule_id.startswith(_SECURITY_PREFIX):
                    sev = "high" if eslint_sev == 2 else "medium"
                else:
                    sev = "info"
                out.append(
                    Finding(
                        check_id=self.id,
                        severity=normalize_severity(sev),
                        title=rule_id or "eslint",
                        location=loc,
                        message=str(m.get("message") or "")[:200],
                        rule=rule_id or "eslint",
                        standards=["OWASP:A03"] if rule_id.startswith(_SECURITY_PREFIX) else [],
                    )
                )
        return out
