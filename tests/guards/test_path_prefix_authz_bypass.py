from __future__ import annotations

from agentsec.guards.path_prefix_authz_bypass import PathPrefixAuthzBypassGuard
from tests.guards._common import *  # noqa: F401,F403


def test_path_prefix_authz_bypass_fires_on_if_startswith(tmp_path: Path) -> None:
    (tmp_path / "files.py").write_text(
        "def serve(requested_path, allowed_root):\n"
        "    if requested_path.startswith(allowed_root):\n"
        "        return open(requested_path).read()\n"
        "    raise PermissionError\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = PathPrefixAuthzBypassGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "path-prefix-authz-bypass/naive-startswith-containment"
    assert findings[0].severity == "medium"


def test_path_prefix_authz_bypass_fires_on_assert(tmp_path: Path) -> None:
    (tmp_path / "authz.py").write_text(
        "def check(target_dir, base_dir):\n"
        "    assert target_dir.startswith(base_dir)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = PathPrefixAuthzBypassGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_path_prefix_authz_bypass_silent_on_bare_call(tmp_path: Path) -> None:
    # FP-bait: a bare startswith() not used as a boolean gate (no if/assert/while/elif)
    # isn't a security decision — e.g. logging or a non-branching expression.
    (tmp_path / "logging_only.py").write_text(
        "logger.info('matched: %s', requested_path.startswith(allowed_root))\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_authz_bypass_silent_on_non_path_receiver(tmp_path: Path) -> None:
    # FP-bait: startswith() on an unrelated string (e.g. checking a URL scheme) must not fire.
    (tmp_path / "scheme_check.py").write_text(
        "def check(url, allowed_scheme):\n"
        "    if url.startswith(allowed_scheme):\n"
        "        return True\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_authz_bypass_silent_on_non_root_arg(tmp_path: Path) -> None:
    # FP-bait: startswith() gating on something that isn't a trusted-root-shaped name.
    (tmp_path / "misc.py").write_text(
        "def check(file_path, prefix_str):\n"
        "    if file_path.startswith(prefix_str):\n"
        "        return True\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_authz_bypass_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "files.py").write_text(
        "# security: allow-path-prefix-authz-bypass\n"
        "def serve(requested_path, allowed_root):\n"
        "    if requested_path.startswith(allowed_root):\n"
        "        return open(requested_path).read()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_authz_bypass_silent_on_sep_boundary_fix(tmp_path: Path) -> None:
    # Regression (#303 review): the boundary-aware fix — appending a separator — must NOT
    # fire; it is the correct remediation, not the vulnerable naive-prefix shape.
    (tmp_path / "safe.py").write_text(
        "import os\n"
        "def serve(requested_path, allowed_root):\n"
        "    if requested_path.startswith(allowed_root + os.sep):\n"
        "        return open(requested_path).read()\n"
        "    if requested_path.startswith(allowed_root + '/'):\n"
        "        return open(requested_path).read()\n"
        "    raise PermissionError\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_authz_bypass_silent_on_substring_root_arg(tmp_path: Path) -> None:
    # Regression (#303 review): `_ROOT_ARG` must match a root-shaped *word*, not a bare
    # substring — `database` ("base") and `unsafe_input` ("safe") are not trusted roots.
    (tmp_path / "misc.py").write_text(
        "def q(file_path, database, unsafe_input):\n"
        "    if file_path.startswith(database):\n"
        "        return 1\n"
        "    if file_path.startswith(unsafe_input):\n"
        "        return 2\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_authz_bypass_silent_on_gate_word_in_comment(tmp_path: Path) -> None:
    # Regression (#303 review): a non-gated call must stay silent even when a trailing
    # comment contains a gate word ("if") — the gate check runs on code, not comments.
    (tmp_path / "note.py").write_text(
        "matched = requested_path.startswith(allowed_root)  # decide if allowed later\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_authz_bypass_fires_on_call_receiver(tmp_path: Path) -> None:
    # Regression (#422 S7): the textbook CWE-22 shape has a call-suffixed receiver;
    # `os.path.abspath(p).startswith(base_dir)` must fire like a bare-name receiver does.
    (tmp_path / "serve.py").write_text(
        "import os\n"
        "def serve(path, base_dir):\n"
        "    if os.path.abspath(path).startswith(base_dir):\n"
        "        return open(path).read()\n"
        "    raise PermissionError\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = PathPrefixAuthzBypassGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "path-prefix-authz-bypass/naive-startswith-containment"


def test_path_prefix_authz_bypass_silent_on_call_receiver_with_sep_boundary(tmp_path: Path) -> None:
    # FP-bait for the widened receiver: the boundary-aware fix stays silent even when the
    # receiver is a call, since appending a separator makes the prefix check boundary-safe.
    (tmp_path / "safe_call.py").write_text(
        "import os\n"
        "def serve(path, base_dir):\n"
        "    if os.path.abspath(path).startswith(base_dir + os.sep):\n"
        "        return open(path).read()\n"
        "    raise PermissionError\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_authz_bypass_not_applies_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"frontend"})
    assert PathPrefixAuthzBypassGuard().applies(profile) is False


def test_path_prefix_authz_bypass_silent_with_is_relative_to(tmp_path: Path) -> None:
    # FP-bait: the boundary-aware fix pattern must not fire this guard at all — it never
    # calls startswith().
    (tmp_path / "safe.py").write_text(
        "def serve(requested_path, allowed_root):\n"
        "    p = Path(requested_path).resolve()\n"
        "    if p.is_relative_to(Path(allowed_root).resolve()):\n"
        "        return p.read_text()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []

def test_path_prefix_authz_bypass_silent_when_path_vocab_only_in_call_arg(tmp_path: Path) -> None:
    # FP regression (#437 review High-4): path vocabulary inside a call's ARGUMENT must not
    # make the receiver path-shaped; get_user() returns a user, not a path.
    (tmp_path / "auth.py").write_text(
        "def check(session_dir, allowed_prefix):\n"
        "    if get_user(session_dir).startswith(allowed_prefix):\n"
        "        return True\n"
        "    return False\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert PathPrefixAuthzBypassGuard().run(tmp_path, profile) == []


def test_path_prefix_basename_receiver_is_not_a_prefix_check(tmp_path: Path) -> None:
    # Regression (#437 review): `basename(...)` strips every directory component, so its result
    # is a LEAF NAME and can never begin with a directory prefix. A prefix check on it is not
    # the CWE-22 bypass — but the receiver still contains the word `path`, so it matched.
    (tmp_path / "a.py").write_text(
        "import os\nSAFE_PREFIX = '/srv/data'\n"
        "def check(name):\n"
        "    if os.path.basename(name).startswith(SAFE_PREFIX):\n"
        "        return True\n",
        encoding="utf-8",
    )
    assert PathPrefixAuthzBypassGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_path_prefix_abspath_and_dirname_still_fire(tmp_path: Path) -> None:
    # The textbook shape must survive, and `dirname` is deliberately NOT excluded: it keeps the
    # directory, so a naive prefix check on it is still the real bypass.
    (tmp_path / "a.py").write_text(
        "import os\nBASE_DIR = '/srv/data'\n"
        "def check(p):\n    if os.path.abspath(p).startswith(BASE_DIR):\n        return True\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "import os\nBASE_DIR = '/srv/data'\n"
        "def check(p):\n    if os.path.dirname(p).startswith(BASE_DIR):\n        return True\n",
        encoding="utf-8",
    )
    assert len(PathPrefixAuthzBypassGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))) == 2
