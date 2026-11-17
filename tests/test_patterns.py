"""Pin the shared regexes in `agentsec.patterns` — used by BOTH `detect.py` (the host-config
signal) and the `auto-updates-absent` guard (its per-line anchor), so an accidental change can't
silently break one consumer. Table-driven match / no-match cases (review #257)."""
from __future__ import annotations

import pytest

from agentsec.patterns import APT_INSTALL


@pytest.mark.parametrize("line", [
    "apt install nginx",
    "apt-get install -y foo",
    "apt-get -y install foo",
    "sudo apt install foo",
    "apt-get install",
    "RUN apt-get install -y gcc",
    "  apt install curl   # with trailing comment",
])
def test_apt_install_matches(line: str) -> None:
    assert APT_INSTALL.search(line) is not None


@pytest.mark.parametrize("line", [
    "apt-get update",              # update, not install
    "apt list --installed",        # 'install' only inside 'installed'
    "rapt install foo",            # \bapt word boundary must not match 'rapt'
    "pip install requests",        # different tool
    "echo apt then newline\ninstall",  # gap class excludes newlines -> can't span lines
    "",
])
def test_apt_install_non_matches(line: str) -> None:
    assert APT_INSTALL.search(line) is None
