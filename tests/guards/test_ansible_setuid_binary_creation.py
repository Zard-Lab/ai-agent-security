from __future__ import annotations

from agentsec.guards.ansible_setuid_binary_creation import AnsibleSetuidBinaryCreationGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_chmod_4755(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: x\n      shell: chmod 4755 /usr/local/bin/foo\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleSetuidBinaryCreationGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ansible-setuid-binary-creation/setuid-bit-set"
    assert findings[0].severity == "critical"


def test_flags_chmod_symbolic_u_plus_s(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: x\n      shell: chmod u+s /usr/local/bin/foo\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert len(AnsibleSetuidBinaryCreationGuard().run(tmp_path, profile)) == 1


def test_flags_ansible_mode_attribute(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: install helper with setuid\n"
        "      ansible.builtin.file:\n"
        "        path: /usr/local/bin/helper\n"
        "        mode: '4755'\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert len(AnsibleSetuidBinaryCreationGuard().run(tmp_path, profile)) == 1


def test_silent_on_benign_chmod(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: x\n      shell: chmod 0640 /etc/app/config.yml\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSetuidBinaryCreationGuard().run(tmp_path, profile) == []


def test_silent_on_benign_mode_attribute(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: x\n"
        "      ansible.builtin.file:\n"
        "        path: /etc/app/config.yml\n"
        "        mode: '0640'\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSetuidBinaryCreationGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# Never run chmod 4755 in a playbook\n- hosts: all\n  tasks:\n    - debug: msg=hi\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSetuidBinaryCreationGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# security: allow-ansible-setuid-binary-creation\n"
        "- hosts: all\n  tasks:\n    - shell: chmod 4755 /usr/local/bin/foo\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSetuidBinaryCreationGuard().run(tmp_path, profile) == []


def test_not_applies_without_ansible_feature(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text("shell: chmod 4755 /usr/local/bin/foo\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features=set())
    assert not AnsibleSetuidBinaryCreationGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.yml").write_text("shell: chmod 4755 /usr/local/bin/foo\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSetuidBinaryCreationGuard().run(tmp_path, profile) == []
