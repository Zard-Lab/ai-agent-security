"""Guard: static-file-serving middleware configured to serve a private directory (CWE-200).

`express.static(...)` / `connect.static(...)`, the standalone `serve-static` package, and
`serve-handler` are the three JS/TS ways to hand a filesystem directory to an HTTP server as
static content. This is a STRUCTURAL config-misuse check, not a taint check: no request input is
involved at all — the bug is fully present the moment the served directory argument is one of a
small set of directories that must never be public:

- a path that IS or CONTAINS `node_modules` (dependency source, often including `.env`-reading
  install scripts, private git-installed packages, or build tooling with embedded secrets)
- the bare source directory the file lives in (`__dirname` used alone, or a same-file variable
  assigned straight from `__dirname`) — the whole project folder (`.env`, `.git`, source, configs)
  becomes public
- `os.homedir()` — the user's entire home directory, including SSH keys and shell config
- the filesystem root or current working directory (`'/'`, `'.'`, `'./'`)

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-200/PrivateFileExposure.ql` — the
three entry points and the dangerous-argument shape (bare `__dirname`, `node_modules`, home
directory, root/cwd) are taken from that query's `PrivateFileExposure` predicate. Adapted from
CodeQL's dataflow model to same-file regex/text matching (agentsec has no JS dataflow engine): the
argument (or, for `serve-handler`, the `public` OPTION value) is classified directly from its own
source text rather than traced through assignments — except for one narrow, deliberate exception,
a same-file `const root = __dirname;` alias, tracked below because it is common and cheap to catch.

This is always a real misconfiguration wherever it appears — legitimate static-file serving points
at a small `public`/`assets`/`static` subdirectory, never at `node_modules`, the whole project
root, or a user's home directory — so this guard applies NO security-context gate and needs none
(same precision philosophy as other single-shape structural misconfig guards in this batch: the
pattern itself IS the bug).

This is a genuinely new checklist gap: agentsec had no "static middleware serves a private
directory" concept before. Proposed as a new item, `3a-js-private-file-exposure`.

Fires HIGH per match:

    app.use(express.static(__dirname));  // security: allow-js-private-file-exposure
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, split_call_args, strip_js_comments

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-private-file-exposure"

# Entry point 1: `express.static(...)` / `connect.static(...)` — matches the bare identifier
# convention (`const express = require('express')`), same simplicity as the sibling
# `js-helmet-header-disabled` guard's `helmet(...)` match.
_STATIC_CALL = re.compile(r"\b(?:express|connect)\.static\s*\(")

# Entry point 2: the standalone `serve-static` package, invoked directly off `require(...)`.
_SERVE_STATIC_CALL = re.compile(r"""require\s*\(\s*['"]serve-static['"]\s*\)\s*\(""")

# Entry point 3: `serve-handler` — the dangerous value lives inside a `{ public: ... }` OPTION,
# not a positional argument, so this only locates the call; the `public` key is extracted from
# its argument text separately (see `_extract_public_option`).
_SERVE_HANDLER_CALL = re.compile(r"""require\s*\(\s*['"]serve-handler['"]\s*\)\s*\(""")

# A same-file `const/let/var X = __dirname;` alias — the one indirection hop this guard follows
# (see module docstring). Anything past one hop (reassignment, destructuring, a second alias of
# an alias, a cross-file import) is NOT tracked; see the design doc's Known Bypasses.
_DIRNAME_ALIAS = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*__dirname\s*;")

# A quoted string literal that IS or CONTAINS `node_modules` anywhere in its text — covers
# `'node_modules'`, `'./node_modules'`, and a `path.join(__dirname, 'node_modules', ...)` whose
# node_modules segment is itself a plain string literal.
_NODE_MODULES_LITERAL = re.compile(r"""['"][^'"]*node_modules[^'"]*['"]""")

# `os.homedir()` called anywhere within the argument expression.
_HOMEDIR_CALL = re.compile(r"\bos\.homedir\s*\(\s*\)")

# The WHOLE argument is a bare filesystem-root / cwd string literal — `'/'`, `'.'`, or `'./'`.
_ROOT_OR_CWD_LITERAL = re.compile(r"""^['"](?:/|\.|\./)['"]$""")

_REASON_MESSAGE = {
    "dirname": (
        "This serves `__dirname` itself — the whole directory the current source file lives in "
        "(source code, config files, and any `.env`) — as public static content."
    ),
    "node_modules": (
        "This serves `node_modules` (or a path inside it) as public static content — dependency "
        "source, install scripts, and any embedded secrets become directly downloadable."
    ),
    "homedir": (
        "This serves the user's home directory (`os.homedir()`) as public static content — SSH "
        "keys, shell configuration, and any other file under the home directory become "
        "downloadable."
    ),
    "root_or_cwd": (
        "This serves the filesystem root or current working directory as public static content — "
        "effectively the whole accessible filesystem becomes downloadable."
    ),
}


def _matching_close_paren(text: str, open_idx: int) -> int | None:
    """Index of the `)` that closes the `(` at `open_idx`, or None if unbalanced."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _scan_value(text: str, start: int) -> str:
    """The value text starting at `start`, up to the first TOP-LEVEL comma or unmatched closer.

    Tracks `(`/`[`/`{` depth so a value like `path.join(__dirname, 'node_modules')` is captured
    whole — a naive stop-at-comma split would cut it at the comma nested inside `path.join(...)`."""
    depth = 0
    i, n = start, len(text)
    while i < n:
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        i += 1
    return text[start:i]


_PUBLIC_KEY = re.compile(r"\bpublic\s*:\s*")


def _extract_public_option(args_text: str) -> str | None:
    """The value of a `public: <value>` key inside a `serve-handler` options object's text."""
    m = _PUBLIC_KEY.search(args_text)
    if m is None:
        return None
    return _scan_value(args_text, m.end())


def _classify_arg(expr: str, dirname_aliases: frozenset[str]) -> str | None:
    """Which dangerous-directory reason (if any) this argument expression matches."""
    e = expr.strip()
    if not e:
        return None
    if e == "__dirname" or e in dirname_aliases:
        return "dirname"
    if _HOMEDIR_CALL.search(e):
        return "homedir"
    if _NODE_MODULES_LITERAL.search(e):
        return "node_modules"
    if _ROOT_OR_CWD_LITERAL.match(e):
        return "root_or_cwd"
    return None


class JsPrivateFileExposureGuard(Guard):
    id = "js-private-file-exposure"
    title = "Static-file-serving middleware configured to serve a private directory"
    area = "Files"

    # express_private_file_exposure.js: express.static(__dirname) ->
    # fires js-private-file-exposure/dirname.
    canary_plant = CanaryPlant(
        files={
            "express_private_file_exposure.js": (
                "const express = require('express');\n"
                "const app = express();\n"
                "app.use(express.static(__dirname));\n"
            ),
        },
        expects=frozenset({"js-private-file-exposure/dirname"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        # Gated on "express" specifically (not the broader javascript/typescript check): the
        # detected entry points are Express/connect-shaped (`express.static`/`connect.static`) or
        # npm packages (`serve-static`, `serve-handler`) whose real-world usage is overwhelmingly
        # inside an Express (or Express-like connect) app in agentsec's target stack. A repo with
        # no Express signal at all is unlikely to run this guard's population and scanning it
        # anyway would just add noise to non-Express JS/TS projects (e.g. a frontend-only React
        # app) with zero true positives to show for it.
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            raw = read(f)
            if not raw:
                continue
            code = strip_js_comments(raw)
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)

            dirname_aliases = frozenset(_DIRNAME_ALIAS.findall(code))

            for call_pattern in (_STATIC_CALL, _SERVE_STATIC_CALL):
                for m in call_pattern.finditer(code):
                    open_idx = m.end() - 1
                    args = split_call_args(code, open_idx)
                    if not args:
                        continue
                    reason = _classify_arg(args[0], dirname_aliases)
                    if reason is None:
                        continue
                    self._emit(out, root, f, code, view_lines, m.start(), reason)

            for m in _SERVE_HANDLER_CALL.finditer(code):
                open_idx = m.end() - 1
                close_idx = _matching_close_paren(code, open_idx)
                if close_idx is None:
                    continue
                args_text = code[open_idx + 1:close_idx]
                value = _extract_public_option(args_text)
                if value is None:
                    continue
                reason = _classify_arg(value, dirname_aliases)
                if reason is None:
                    continue
                self._emit(out, root, f, code, view_lines, m.start(), reason)
        return out

    def _emit(
        self,
        out: list[Finding],
        root: Path,
        f: Path,
        code: str,
        view_lines: list[str],
        match_start: int,
        reason: str,
    ) -> None:
        line_no = code.count("\n", 0, match_start) + 1
        view_line = view_lines[line_no - 1] if 0 < line_no <= len(view_lines) else ""
        if _PRAGMA in view_line:
            return
        out.append(
            Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{rel(root, f)}:{line_no}",
                message=_REASON_MESSAGE[reason],
                remediation=(
                    "Point static-file-serving middleware at a dedicated, minimal public-assets "
                    "directory (e.g. `public/`, `dist/`, `static/`) — never at `node_modules`, "
                    "`__dirname` itself, the home directory, or the filesystem root/cwd. "
                    "Suppress a reviewed, intentional case with "
                    "`// security: allow-js-private-file-exposure`."
                ),
                rule=f"js-private-file-exposure/{reason}",
                standards=["OWASP:A01", "CWE-200"],
            )
        )
