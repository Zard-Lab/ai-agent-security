from __future__ import annotations

from agentsec.guards.ansible_host_key_checking_disabled import AnsibleHostKeyCheckingDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_env_block_false(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  environment:\n"
        "    ANSIBLE_HOST_KEY_CHECKING: False\n"
        "  tasks:\n"
        "    - name: x\n"
        "      debug: msg=hi\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleHostKeyCheckingDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ansible-host-key-checking-disabled/env-override"


def test_flags_in_dockerfile_env(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nENV ANSIBLE_HOST_KEY_CHECKING=false\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleHostKeyCheckingDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_when_true_or_absent(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  environment:\n    ANSIBLE_HOST_KEY_CHECKING: True\n  tasks:\n    - debug: msg=hi\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleHostKeyCheckingDisabledGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# Never set ANSIBLE_HOST_KEY_CHECKING: False\n"
        "- hosts: all\n  tasks:\n    - debug: msg=hi\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleHostKeyCheckingDisabledGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# security: allow-ansible-host-key-checking-disabled\n"
        "- hosts: all\n  environment:\n    ANSIBLE_HOST_KEY_CHECKING: False\n  tasks:\n    - debug: msg=hi\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleHostKeyCheckingDisabledGuard().run(tmp_path, profile) == []


def test_not_applies_without_ansible_feature(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  environment:\n    ANSIBLE_HOST_KEY_CHECKING: False\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features=set())
    assert not AnsibleHostKeyCheckingDisabledGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.yml").write_text(
        "- hosts: all\n  environment:\n    ANSIBLE_HOST_KEY_CHECKING: False\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleHostKeyCheckingDisabledGuard().run(tmp_path, profile) == []


def test_silent_on_prefixed_custom_env_var(tmp_path: Path) -> None:
    # A custom env var that merely ends in the Ansible name has no effect on Ansible and must not
    # fire -- only the real, unprefixed ANSIBLE_HOST_KEY_CHECKING does (regression: #408 Minor #8).
    (tmp_path / "playbook.yml").write_text(
        "- hosts: all\n"
        "  environment:\n"
        "    MY_ANSIBLE_HOST_KEY_CHECKING: False\n"
        "  tasks:\n"
        "    - name: noop\n"
        "      ansible.builtin.command: /bin/true\n",
        encoding="utf-8",
    )
    from agentsec.guards.ansible_host_key_checking_disabled import (
        AnsibleHostKeyCheckingDisabledGuard,
    )
    assert AnsibleHostKeyCheckingDisabledGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"})) == []
