from __future__ import annotations

from agentsec.guards.ansible_unsafe_lookups_enabled import AnsibleUnsafeLookupsEnabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_yaml_vars_true(tmp_path: Path) -> None:
    (tmp_path / "group_vars_all.yml").write_text(
        "allow_unsafe_lookups: true\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleUnsafeLookupsEnabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ansible-unsafe-lookups-enabled/global-override"


def test_flags_ansible_cfg(tmp_path: Path) -> None:
    (tmp_path / "ansible.cfg").write_text(
        "[defaults]\ninventory = hosts\nallow_unsafe_lookups = True\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    findings = AnsibleUnsafeLookupsEnabledGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_when_false_or_absent(tmp_path: Path) -> None:
    (tmp_path / "group_vars_all.yml").write_text(
        "allow_unsafe_lookups: false\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleUnsafeLookupsEnabledGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "group_vars_all.yml").write_text(
        "# Never set allow_unsafe_lookups: true\nother_var: 1\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleUnsafeLookupsEnabledGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "group_vars_all.yml").write_text(
        "# security: allow-ansible-unsafe-lookups-enabled\nallow_unsafe_lookups: true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleUnsafeLookupsEnabledGuard().run(tmp_path, profile) == []


def test_not_applies_without_ansible_feature(tmp_path: Path) -> None:
    (tmp_path / "group_vars_all.yml").write_text("allow_unsafe_lookups: true\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features=set())
    assert not AnsibleUnsafeLookupsEnabledGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.yml").write_text("allow_unsafe_lookups: true\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"ansible"})
    assert AnsibleUnsafeLookupsEnabledGuard().run(tmp_path, profile) == []
