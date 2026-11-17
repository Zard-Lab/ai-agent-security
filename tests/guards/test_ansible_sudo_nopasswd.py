from __future__ import annotations

from agentsec.guards.ansible_sudo_nopasswd import AnsibleSudoNopasswdGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_nopasswd_all(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: allow bitcoin group passwordless sudo\n"
        "      lineinfile:\n"
        "        dest: /etc/sudoers\n"
        "        line: '%bitcoin ALL=(ALL) NOPASSWD:ALL'\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleSudoNopasswdGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ansible-sudo-nopasswd/blanket-nopasswd-all"


def test_silent_on_generic_sudoers_nopasswd_without_all(tmp_path: Path) -> None:
    # A "sudoers ... NOPASSWD" mention that is NOT a blanket `NOPASSWD: ALL` no longer fires: the
    # over-broad `sudoers.*NOPASSWD` branch was dropped because it false-flagged scoped drop-ins
    # (the exact remediation the guard recommends). Only blanket NOPASSWD:ALL fires now (#408 #7).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: x\n      shell: echo 'deploy sudoers NOPASSWD entry' > /etc/sudoers.d/deploy\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSudoNopasswdGuard().run(tmp_path, profile) == []


def test_silent_on_scoped_nopasswd(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: allow deploy user to restart nginx only\n"
        "      lineinfile:\n"
        "        dest: /etc/sudoers.d/deploy\n"
        "        line: 'deploy ALL=(ALL) NOPASSWD: /usr/sbin/systemctl restart nginx'\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSudoNopasswdGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# Never grant NOPASSWD: ALL to any user\n- hosts: all\n  tasks:\n    - debug: msg=hi\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSudoNopasswdGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# security: allow-ansible-sudo-nopasswd\n"
        "- hosts: all\n  tasks:\n    - lineinfile: line='%bitcoin ALL=(ALL) NOPASSWD:ALL'\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSudoNopasswdGuard().run(tmp_path, profile) == []


def test_not_applies_without_ansible_feature(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text("line: 'ALL ALL=(ALL) NOPASSWD:ALL'\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features=set())
    assert not AnsibleSudoNopasswdGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.yml").write_text("line: 'ALL ALL=(ALL) NOPASSWD:ALL'\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleSudoNopasswdGuard().run(tmp_path, profile) == []


def test_silent_on_scoped_sudoers_dropin(tmp_path: Path) -> None:
    # A SCOPED /etc/sudoers.d/ drop-in granting NOPASSWD on a specific command (the exact fix this
    # guard recommends) must NOT fire -- only blanket NOPASSWD: ALL does (regression: #408 Major #7).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: scoped passwordless restart for deploy user\n"
        "      ansible.builtin.copy:\n"
        "        dest: /etc/sudoers.d/deploy\n"
        "        content: \"deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx\"\n",
        encoding="utf-8",
    )
    from agentsec.guards.ansible_sudo_nopasswd import AnsibleSudoNopasswdGuard
    assert AnsibleSudoNopasswdGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"})) == []
