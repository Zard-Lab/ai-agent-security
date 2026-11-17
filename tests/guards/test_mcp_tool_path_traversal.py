from __future__ import annotations

import pytest

from agentsec.guards.mcp_tool_path_traversal import McpToolPathTraversalGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def _mcp_js_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "javascript"})


# --- Rule 1: tool-argument-unvalidated --------------------------------------------------


def test_flags_open_of_bare_tool_argument_subscript(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "def read_file(arguments):\n"
        "    path = arguments['path']\n"
        "    with open(path) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-path-traversal/tool-argument-unvalidated"
    assert findings[0].severity == "high"


def test_flags_open_of_tool_argument_subscript_direct(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "def read_file(arguments):\n"
        "    with open(arguments['path']) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-path-traversal/tool-argument-unvalidated"


def test_flags_pathlib_path_of_tool_argument_subscript(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from pathlib import Path\n\n"
        "def read_file(args):\n"
        "    p = Path(args['file'])\n"
        "    return p.read_text()\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-path-traversal/tool-argument-unvalidated"


def test_flags_os_path_join_of_tool_argument_subscript(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import os\n\n"
        "ROOT = '/srv/data'\n\n"
        "def read_file(params):\n"
        "    full = os.path.join(ROOT, params['name'])\n"
        "    return open(full).read()\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tool-path-traversal/tool-argument-unvalidated" for f in findings)


def test_rule1_stays_silent_with_containment_check(tmp_path: Path) -> None:
    # FP bait: a real containment check (resolve + is_relative_to) in the same function.
    (tmp_path / "server.py").write_text(
        "from pathlib import Path\n\n"
        "ROOT = Path('/srv/data')\n\n"
        "def read_file(arguments):\n"
        "    p = (ROOT / arguments['path']).resolve()\n"
        "    if not p.is_relative_to(ROOT.resolve()):\n"
        "        raise PermissionError\n"
        "    return open(p).read()\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_rule1_stays_silent_on_positional_args_index(tmp_path: Path) -> None:
    # (Dean's review): `args[0]` is an INTEGER index into a plain `*args` tuple --
    # a totally ordinary Python idiom unrelated to an MCP tool-call argument dict -- and used
    # to fire as if it were `args["path"]`. Only a STRING key counts as a dict lookup now.
    (tmp_path / "server.py").write_text(
        "def main(*args):\n"
        "    with open(args[0]) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_rule1_stays_silent_on_string_join(tmp_path: Path) -> None:
    # (Dean's review): `", ".join(params["names"])` was firing as a path sink --
    # `.join` on a bare callee name collides with `os.path.join`, but a string literal's own
    # `.join(` method has nothing to do with filesystem paths at all.
    (tmp_path / "server.py").write_text(
        "def summarize(params):\n"
        "    return ', '.join(params['names'])\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_rule1_stays_silent_on_fstring_separator_join(tmp_path: Path) -> None:
    # FP bait companion: an f-string used as the join separator is the same str.join idiom.
    (tmp_path / "server.py").write_text(
        "def summarize(params, sep):\n"
        "    return f'{sep}'.join(params['names'])\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_rule1_stays_silent_on_bare_variable_not_from_arguments(tmp_path: Path) -> None:
    # FP bait: a bare, non-dict-subscript variable (e.g. sys.argv[1] assigned to a plain
    # name first) is exactly the shape the existing generic path-traversal guard already
    # declines to flag -- this guard must not widen onto ordinary local variables either.
    (tmp_path / "server.py").write_text(
        "import sys\n\n"
        "def main():\n"
        "    path = sys.argv[1]\n"
        "    with open(path) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


# --- Rule 2: token-in-session-path -------------------------------------------------------


def test_flags_bearer_token_joined_into_session_path(tmp_path: Path) -> None:
    # CVE-2026-52830 shape: a bearer token is joined into the session-file path with no
    # separator/containment check, then reaches an existence check.
    (tmp_path / "auth.py").write_text(
        "import os\n\n"
        "SESSION_DIR = '/var/sessions'\n\n"
        "def check_session(token):\n"
        "    session_path = os.path.join(SESSION_DIR, token)\n"
        "    return os.path.exists(session_path)\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-path-traversal/token-in-session-path"
    assert findings[0].severity == "critical"


def test_flags_bearer_token_fstring_session_path(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "from pathlib import Path\n\n"
        "def check_session(session_id):\n"
        "    p = Path(f'/var/sessions/{session_id}')\n"
        "    return p.exists()\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-path-traversal/token-in-session-path"


def test_rule2_stays_silent_with_separator_rejection_marker(tmp_path: Path) -> None:
    # FP bait: a real containment/resolve check on the token-derived path silences it, same
    # shared containment-marker check as rule 1.
    (tmp_path / "auth.py").write_text(
        "import os\n\n"
        "SESSION_DIR = os.path.realpath('/var/sessions')\n\n"
        "def check_session(token):\n"
        "    session_path = os.path.realpath(os.path.join(SESSION_DIR, token))\n"
        "    if not session_path.startswith(SESSION_DIR):\n"
        "        raise PermissionError\n"
        "    return os.path.exists(session_path)\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_rule2_stays_silent_with_dotdot_rejection_marker(tmp_path: Path) -> None:
    # (Dean's review): the module's own docstring documents an explicit `".." in`
    # check as a recognized marker, and this guard's OWN finding remediation text tells a user
    # to add exactly this check -- but the marker regex never actually included it, so a user
    # following the guard's own advice verbatim still got the same CRITICAL. No resolve()/
    # realpath/other marker present -- this is the ONLY containment check, isolating the fix.
    (tmp_path / "auth.py").write_text(
        "import os\n\n"
        "SESSION_DIR = '/var/sessions'\n\n"
        "def check_session(token):\n"
        "    if '..' in token or os.sep in token:\n"
        "        raise PermissionError\n"
        "    session_path = os.path.join(SESSION_DIR, token)\n"
        "    return os.path.exists(session_path)\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_rule2_fires_when_a_docstring_only_mentions_the_dotdot_check(tmp_path: Path) -> None:
    # PR #917 re-review: the markers were matched against `ast.unparse(fn)`, which keeps the
    # docstring, so a TODO quoting this guard's own remediation voided a real CRITICAL. The
    # check is only MENTIONED here, never performed.
    (tmp_path / "auth.py").write_text(
        "import os\n\n"
        "SESSION_DIR = '/var/sessions'\n\n"
        "def check_session(token):\n"
        '    """FIXME: reject any token containing \'..\' in it."""\n'
        "    session_path = os.path.join(SESSION_DIR, token)\n"
        "    return os.path.exists(session_path)\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [(f.rule, f.severity) for f in findings] == [
        ("mcp-tool-path-traversal/token-in-session-path", "critical")
    ]


@pytest.mark.parametrize(
    "mention",
    [
        '    """TODO: reject \'..\' in the path."""\n',
        '    """TODO: call os.path.realpath() and is_relative_to(ROOT) here."""\n',
        "    logging.info('remember to .resolve() and check os.sep in the name')\n",
    ],
    ids=["docstring-dotdot", "docstring-realpath", "log-string-resolve"],
)
def test_rule1_fires_when_a_string_only_mentions_a_marker(tmp_path: Path, mention: str) -> None:
    # Same bug, rule 1, and every marker spelling: a string is not a containment check.
    (tmp_path / "server.py").write_text(
        "import logging\n\n"
        "def read_file(arguments):\n"
        f"{mention}"
        "    with open(arguments['path']) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.rule for f in findings] == ["mcp-tool-path-traversal/tool-argument-unvalidated"]


@pytest.mark.parametrize(
    "check",
    [
        "    assert '..' not in arguments['path']\n",
        "    if os.path.commonpath([ROOT, os.path.join(ROOT, arguments['path'])]) != ROOT:\n"
        "        raise PermissionError\n",
        "    Path(ROOT, arguments['path']).relative_to(ROOT)\n",
        "    safe = secure_filename(arguments['path'])\n",
        "    safe = safe_join(ROOT, arguments['path'])\n",
        "    if not str(Path(ROOT, arguments['path']).resolve()).startswith(ROOT):\n"
        "        raise PermissionError\n",
        "    def _inside(p):\n"
        "        return Path(p).resolve().is_relative_to(ROOT)\n",
        "    from os.path import realpath as rp\n"
        "    safe = rp(os.path.join(ROOT, arguments['path']))\n",
    ],
    ids=["assert-dotdot", "commonpath-attr", "relative-to", "secure-filename-name",
         "safe-join-name", "resolve-call", "nested-helper", "local-import-alias"],
)
def test_rule1_stays_silent_with_each_real_marker_spelling(tmp_path: Path, check: str) -> None:
    # FP bait for the fix above, which stopped matching marker TEXT: every marker written as
    # real code (a Name, an Attribute, a `.resolve(` call, an `in` comparison, inside a
    # nested helper) must still silence the finding.
    (tmp_path / "server.py").write_text(
        "import os\n"
        "from pathlib import Path\n\n"
        "ROOT = '/srv/data'\n\n"
        "def read_file(arguments):\n"
        f"{check}"
        "    with open(arguments['path']) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_rule2_stays_silent_on_static_session_path(tmp_path: Path) -> None:
    # FP bait: token used for something other than path construction -- no traversal risk.
    (tmp_path / "auth.py").write_text(
        "import os\n\n"
        "def check_session(token):\n"
        "    if token != 'expected-static-value':\n"
        "        raise PermissionError\n"
        "    return os.path.exists('/var/sessions/fixed.json')\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


# --- shared: pragma, applies() -----------------------------------------------------------


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "# security: allow-mcp-path-traversal\n"
        "def read_file(arguments):\n"
        "    with open(arguments['path']) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    assert McpToolPathTraversalGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_applies_requires_mcp_and_python_features(tmp_path: Path) -> None:
    guard = McpToolPathTraversalGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False
    # widening: Rule 3 (js-tool-argument-unvalidated) applies on mcp + javascript/
    # typescript too, so this is no longer gated to python alone.
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"typescript"})) is False


# --- Rule 3: js-tool-argument-unvalidated --------------------------------------

def test_js_rule3_fires_on_readfile_path_join_with_args(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const fs = require('fs');\n"
        "const path = require('path');\n\n"
        "function readFile(args, root) {\n"
        "  fs.readFile(path.join(root, args.path), (err, data) => data);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert any(f.rule == "mcp-tool-path-traversal/js-tool-argument-unvalidated" for f in findings)


def test_js_rule3_fires_on_typescript_toolargs(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "import * as fs from 'fs';\n"
        "import * as path from 'path';\n\n"
        "function readFile(toolArgs: { path: string }, root: string) {\n"
        "  fs.readFileSync(path.join(root, toolArgs.path));\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, mkprofile(tmp_path, features={"mcp", "typescript"}))
    assert any(f.rule == "mcp-tool-path-traversal/js-tool-argument-unvalidated" for f in findings)


def test_js_rule3_silent_with_containment_check(tmp_path: Path) -> None:
    """FP-bait: a containment marker anywhere in the file silences the finding."""
    (tmp_path / "server.js").write_text(
        "const fs = require('fs');\n"
        "const path = require('path');\n\n"
        "function readFile(args, root) {\n"
        "  const p = path.join(root, args.path);\n"
        "  const rel = path.relative(root, p);\n"
        "  if (rel.startsWith('..')) throw new Error('bad path');\n"
        "  fs.readFile(p, (err, data) => data);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == "mcp-tool-path-traversal/js-tool-argument-unvalidated" for f in findings)


def test_js_rule3_silent_on_ordinary_variable_named_args(tmp_path: Path) -> None:
    """FP-bait, the important one: an ordinary JS function with a parameter literally named
    `args` that has nothing to do with an MCP tool call must not fire -- this is exactly why
    the generic `js-path-traversal` guard's taint vocabulary was NOT widened to include
    `args`/`toolArgs`/`input`. Scoping this rule to MCP repos (`applies()`) is the real
    control; the FP-bait here is about the SINK/TAINT SHAPE staying narrow regardless."""
    (tmp_path / "unrelated.js").write_text(
        "const fs = require('fs');\n\n"
        "function logStatus(args) {\n"
        "  console.log('status', args.verbose);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpToolPathTraversalGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == "mcp-tool-path-traversal/js-tool-argument-unvalidated" for f in findings)


def test_js_rule3_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    """FP-bait: a repo with no MCP feature detected never reaches Rule 3 at all -- this rule
    is deliberately MCP-scoped (`applies()`), not a general JS path-traversal widening. The
    orchestrator never calls `run()` when `applies()` is False, so that is the real contract
    to assert, not `run()`'s own behavior on a profile it was never meant to receive."""
    guard = McpToolPathTraversalGuard()
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is False
