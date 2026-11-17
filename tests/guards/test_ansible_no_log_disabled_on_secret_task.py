from __future__ import annotations

from agentsec.guards.ansible_no_log_disabled_on_secret_task import AnsibleNoLogDisabledOnSecretTaskGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_no_log_false_before_jinja_secret_var(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: fetch db credentials\n"
        "      no_log: false\n"
        "      uri:\n"
        "        url: https://vault.internal/v1/db\n"
        "        headers:\n"
        "          Authorization: \"Bearer {{ vault_db_token }}\"\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ansible-no-log-disabled-on-secret-task/no-log-false-near-secret"
    assert findings[0].severity == "high"


def test_flags_no_log_false_after_literal_secret_arg_key(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: create db user\n"
        "      mysql_user:\n"
        "        password: \"{{ new_password }}\"\n"
        "      no_log: no\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_when_no_log_true(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: fetch db credentials\n"
        "      no_log: true\n"
        "      uri:\n"
        "        headers:\n"
        "          Authorization: \"Bearer {{ vault_db_token }}\"\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, profile) == []


def test_silent_when_no_log_false_but_no_secret_nearby(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: print current time\n"
        "      no_log: false\n"
        "      debug:\n"
        "        msg: \"{{ ansible_date_time.iso8601 }}\"\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    # A doc comment merely mentioning the anti-pattern must NOT fire (FP-bait) — no real task.
    (tmp_path / "site.yml").write_text(
        "# Avoid this anti-pattern: no_log: false near password: fields\n"
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: safe task\n"
        "      debug:\n"
        "        msg: hello\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "# security: allow-ansible-no-log-disabled-on-secret-task\n"
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: fetch db credentials\n"
        "      no_log: false\n"
        "      uri:\n"
        "        headers:\n"
        "          Authorization: \"Bearer {{ vault_db_token }}\"\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, profile) == []


def test_not_applies_without_ansible_feature(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: x\n      no_log: false\n      uri:\n        headers:\n          Authorization: \"Bearer {{ vault_db_token }}\"\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert not AnsibleNoLogDisabledOnSecretTaskGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: x\n      no_log: false\n      uri:\n        headers:\n          Authorization: \"Bearer {{ vault_db_token }}\"\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, profile) == []


def test_silent_when_no_log_false_belongs_to_a_different_task(tmp_path: Path) -> None:
    # `no_log: false` is a benign toggle on one (non-secret) task; a DIFFERENT later task handles a
    # password. The proximity window must not cross the `- name:` boundary and misattribute the
    # override to the secret task (regression: #408 Major #3).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - name: print a friendly banner\n"
        "      no_log: false\n"
        "      ansible.builtin.debug:\n"
        "        msg: starting run\n"
        "    - name: create app user\n"
        "      ansible.builtin.user:\n"
        "        name: app\n"
        "        password: \"{{ vault_app_password }}\"\n",
        encoding="utf-8",
    )
    from agentsec.guards.ansible_no_log_disabled_on_secret_task import (
        AnsibleNoLogDisabledOnSecretTaskGuard,
    )
    assert AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"})) == []


def test_silent_across_nameless_tasks(tmp_path: Path) -> None:
    # The task-boundary temper must recognize NAMELESS tasks (`- <module>:`, no name:), not just
    # `- name:` -- otherwise the cross-task FP persists between nameless tasks (#408 fix-round High).
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n"
        "  tasks:\n"
        "    - debug:\n"
        "        msg: hello\n"
        "      no_log: false\n"
        "    - ansible.builtin.user:\n"
        "        name: app\n"
        "        password: \"{{ vault_app_password }}\"\n",
        encoding="utf-8",
    )
    from agentsec.guards.ansible_no_log_disabled_on_secret_task import (
        AnsibleNoLogDisabledOnSecretTaskGuard,
    )
    assert AnsibleNoLogDisabledOnSecretTaskGuard().run(tmp_path, mkprofile(tmp_path, features={"ansible"})) == []
