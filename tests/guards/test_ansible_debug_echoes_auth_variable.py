from __future__ import annotations

from agentsec.guards.ansible_debug_echoes_auth_variable import AnsibleDebugEchoesAuthVariableGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_debug_var_of_ansible_password(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: show the password\n"
        "      debug:\n"
        "        var: ansible_password\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ansible-debug-echoes-auth-variable/debug-prints-auth-magic-var"
    assert findings[0].severity == "critical"


def test_flags_debug_msg_of_become_password(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: show become password in message\n"
        "      ansible.builtin.debug:\n"
        "        msg: \"Using {{ ansible_become_password }} for {{ inventory_hostname }}\"\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_flags_msg_with_quoted_hash_before_auth_var(tmp_path: Path) -> None:
    # A `#` INSIDE the quoted msg (a quote-unaware trailing-comment strip would truncate the line
    # here and drop the real leak) must NOT hide the credential echo (regression: #408 Critical #1).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: info\n"
        "      debug:\n"
        "        msg: \"Info #1: password is {{ ansible_become_password }}\"\n",
        encoding="utf-8",
    )
    findings = AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"}))
    assert len(findings) == 1


def test_flags_block_scalar_msg_with_auth_var(tmp_path: Path) -> None:
    # A YAML block scalar (`msg: >`) with the auth var on a following line must fire (#408 Major #2).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: connect\n"
        "      debug:\n"
        "        msg: >\n"
        "          Using {{ ansible_become_password }} to connect to the host\n",
        encoding="utf-8",
    )
    findings = AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"}))
    assert len(findings) == 1


def test_silent_on_fully_commented_out_debug_task(tmp_path: Path) -> None:
    # A whole-line-commented debug task must NOT fire — the full-line-comment strip still guards
    # the #407 comment-blindness FP class, even though trailing `#` is now preserved.
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: real task\n"
        "      command: /bin/true\n"
        "#    - name: old debug\n"
        "#      debug:\n"
        "#        var: ansible_password\n",
        encoding="utf-8",
    )
    findings = AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"}))
    assert findings == []


def test_silent_on_debug_of_ansible_user(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: show which user\n"
        "      debug:\n"
        "        var: ansible_user\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, profile) == []


def test_silent_on_debug_of_custom_passthrough_var(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: show custom var\n"
        "      debug:\n"
        "        var: ansible_passthrough_config\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# Never do: debug: var: ansible_become_password\n"
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: safe task\n"
        "      debug:\n"
        "        var: ansible_user\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# security: allow-ansible-debug-echoes-auth-variable\n"
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: show the password\n"
        "      debug:\n"
        "        var: ansible_password\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, profile) == []


def test_not_applies_without_ansible_feature(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: x\n      debug:\n        var: ansible_password\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert not AnsibleDebugEchoesAuthVariableGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: x\n      debug:\n        var: ansible_password\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, profile) == []


def test_silent_when_auth_var_is_in_a_following_task(tmp_path: Path) -> None:
    # The block-scalar/line-spanning msg branch must NOT reach a LATER task's auth var and fire
    # CRITICAL against an innocent debug task (regression: #408 fix-round Critical).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: announce\n"
        "      debug:\n"
        "        msg: \"starting the deployment now\"\n"
        "    - name: stash creds\n"
        "      ansible.builtin.set_fact:\n"
        "        saved: \"{{ ansible_become_password }}\"\n",
        encoding="utf-8",
    )
    assert AnsibleDebugEchoesAuthVariableGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"})) == []
