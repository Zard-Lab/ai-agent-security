"""Tests for the compose-no-new-privileges guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_no_new_privileges import ComposeNoNewPrivilegesGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-no-new-privileges/missing"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeNoNewPrivilegesGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str, name: str = "docker-compose.yml") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_no_security_opt_at_all_fires(tmp_path: Path) -> None:
    """The common case: no security_opt: key anywhere -> must fire."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "medium"
    assert match.check_id == "compose-no-new-privileges"


def test_security_opt_without_the_flag_fires(tmp_path: Path) -> None:
    """Indirect/bypass case: a security_opt: list that names something ELSE (already
    flagged by docker-privileged-flags) must still fire here — its presence alone
    must not be mistaken for the specific no-new-privileges flag being set."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    security_opt:\n      - apparmor:unconfined\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_commented_out_flag_still_fires(tmp_path: Path) -> None:
    """A mention of no-new-privileges:true inside a comment must not be mistaken for
    it actually being set."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n"
        "    security_opt:\n      - apparmor:unconfined  # no-new-privileges:true not set\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_multiple_services_each_evaluated(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n"
        "  app:\n    image: alpine\n"
        "  worker:\n    image: alpine\n",
    )
    assert len([f for f in _run(tmp_path) if f.rule == _RULE]) == 2


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_no_new_privileges_present_block_form_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n"
        "    security_opt:\n      - no-new-privileges:true\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_no_new_privileges_present_flow_form_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        'services:\n  app:\n    image: alpine\n    security_opt: ["no-new-privileges:true"]\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_no_new_privileges_quoted_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n"
        '    security_opt:\n      - "no-new-privileges:true"\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-no-new-privileges\n"
        "services:\n  app:\n    image: alpine\n",
    )
    assert _run(tmp_path) == []


def test_dev_compose_out_of_scope(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n", name="docker-compose.dev.yml")
    assert _run(tmp_path) == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeNoNewPrivilegesGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeNoNewPrivilegesGuard().applies(profile) is True


def test_no_compose_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_pragma_quoted_in_a_scalar_does_not_suppress(tmp_path: Path) -> None:
    # #424 E2: the documented `# security: …` form inside a YAML scalar — a quoted label, or a
    # shell comment inside a `command: |` block — is compose CONTENT, not a YAML comment. Only a
    # real comment (the test above) opts out.
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n"
        '    labels:\n      help: "opt out with # security: allow-no-new-privileges"\n'
        "    command: |\n      # security: allow-no-new-privileges\n      run\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))
