from __future__ import annotations

from agentsec.guards.ansible_ignore_errors_on_security_task import (
    AnsibleIgnoreErrorsOnSecurityTaskGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_flags_ignore_errors_on_ssl_task(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: ensure SSL certificate is checked\n"
        "      ansible.builtin.command: openssl verify {{ cert_path }}\n"
        "      ignore_errors: true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ansible-ignore-errors-on-security-task/silent-failure"


def test_flags_ignore_errors_on_firewall_task(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: configure firewall rule\n"
        "      ansible.builtin.command: ufw allow 443\n"
        "      ignore_errors: yes\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert len(AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, profile)) == 1


def test_silent_on_ignore_errors_non_security_task(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: restart the web app\n"
        "      ansible.builtin.service: name=webapp state=restarted\n"
        "      ignore_errors: true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, profile) == []


def test_silent_on_security_task_without_ignore_errors(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: ensure SSL certificate is checked\n"
        "      ansible.builtin.command: openssl verify {{ cert_path }}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# Never set ignore_errors: true on a firewall task\n"
        "- hosts: all\n  tasks:\n    - debug: msg=hi\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# security: allow-ansible-ignore-errors-on-security-task\n"
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: ensure SSL certificate is checked\n"
        "      command: openssl verify {{ cert_path }}\n"
        "      ignore_errors: true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, profile) == []


def test_not_applies_without_ansible_feature(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: ssl check\n      command: x\n      ignore_errors: true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert not AnsibleIgnoreErrorsOnSecurityTaskGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: ssl check\n      command: x\n      ignore_errors: true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, profile) == []


def test_silent_on_substring_collision_concert(tmp_path: Path) -> None:
    # `concert` contains `cert`, `spam_filter` contains `pam_` -- boundaried keywords must not
    # false-fire on ordinary words (regression: #408 Major #4).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: import concert ticket sales report\n"
        "      ansible.builtin.command: /usr/bin/import-spam_filter-config\n"
        "      ignore_errors: true\n",
        encoding="utf-8",
    )
    assert AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"})) == []


def test_silent_when_ignore_errors_belongs_to_a_different_task(tmp_path: Path) -> None:
    # The security keyword is one task; the `ignore_errors: true` belongs to a SEPARATE later task.
    # The proximity window must not cross the `- name:` boundary (regression: #408 Major #5).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: configure firewall rule\n"
        "      ansible.builtin.command: ufw allow 443\n"
        "    - name: fetch optional MOTD banner\n"
        "      ansible.builtin.get_url:\n"
        "        url: https://example.com/motd.txt\n"
        "        dest: /etc/motd\n"
        "      ignore_errors: true\n",
        encoding="utf-8",
    )
    assert AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"})) == []


def test_flags_ignore_errors_placed_before_the_security_keyword(tmp_path: Path) -> None:
    # Reversed key order: `ignore_errors: true` appears BEFORE the security-keyword module-arg line
    # (here `path: /etc/pam.d/sshd`) in the same task. Symmetric with the no_log guard -- must still
    # fire (regression: #408 Minor #6).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: apply access policy\n"
        "      ignore_errors: true\n"
        "      ansible.builtin.lineinfile:\n"
        "        path: /etc/pam.d/sshd\n"
        "        line: \"auth required pam_deny.so\"\n",
        encoding="utf-8",
    )
    assert len(AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"}))) == 1


def test_silent_across_nameless_tasks(tmp_path: Path) -> None:
    # The task-boundary temper must recognize NAMELESS tasks (`- <module>:`), not just `- name:` --
    # a firewall task and a DIFFERENT nameless task's ignore_errors must not combine (#408 fix-round).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - ansible.builtin.command: /usr/sbin/ufw enable\n"
        "    - ansible.builtin.get_url:\n"
        "        url: https://example.com/motd\n"
        "        dest: /etc/motd\n"
        "      ignore_errors: true\n",
        encoding="utf-8",
    )
    assert AnsibleIgnoreErrorsOnSecurityTaskGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"})) == []
