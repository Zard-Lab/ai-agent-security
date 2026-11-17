"""Tests for the Claude skill pack (`claude-skills/`).

This file was `tests/test_templates.py` until the `templates/` CI scaffold was removed; its
render tests went with it. The audit workflow now ships as the repo-root `action.yml` (tested in
`tests/test_action.py`) and the pre-commit hook as `.pre-commit-hooks.yaml`
(`tests/test_precommit_hooks.py`).
"""
from __future__ import annotations

from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parent.parent
_SKILLS = _REPO / "claude-skills"


def test_skill_pack_frontmatter() -> None:
    # Every skill directory must carry a SKILL.md — derived from the directory listing, NOT a
    # hard-coded name set. A strict set equality here is a merge hazard: two branches each adding
    # one skill both rewrite this single line, and an ours/theirs resolution silently drops one
    # name and fails this test on main (#467/#478 cross-PR collision).
    skills = sorted(p for p in _SKILLS.glob("*/SKILL.md"))
    dirs = {d.name for d in _SKILLS.iterdir() if d.is_dir() and not d.name.startswith(".")}
    assert {p.parent.name for p in skills} == dirs, "every skill directory needs a SKILL.md"
    # Floor, not an exact count: an exact number is the merge hazard above, but a floor set BELOW
    # the real count is not a regression guard at all — at `>= 8` against 10 shipped skills the pack
    # could silently lose two and stay green (#467 re-gate). Track the real count; raise this line
    # when a skill is added, which is a one-line, conflict-free edit for the branch that adds it.
    # Raised 10 -> 11 here: this branch adds `/security-prime`, which is that one-line edit.
    assert len(skills) >= 11, "the skill pack lost skills — expected the full set"
    for p in skills:
        # UTF-8 explicitly, per the CLAUDE.md cross-platform rule. A bare read_text() here decoded
        # with the platform default and had TWO failure modes on Windows, not one (#478):
        #   * loud: `security-prime/SKILL.md` carries `⚠️`, whose U+FE0F variation selector encodes
        #     as EF B8 8F, and 0x8f has no cp1252 mapping, so read_text() raised UnicodeDecodeError
        #     and the windows leg went red;
        #   * silent, and older: an em dash is E2 80 94, every byte of which IS mapped in cp1252, so
        #     every other SKILL.md file never raised. They just decoded to `â€"` mojibake and the
        #     assertions below ran against corrupted text. That had been true since this test was
        #     written; the emoji is only the first character loud enough to fail.
        # The silent mode is the worse one: a green Windows leg was not evidence the file parsed.
        text = p.read_text(encoding="utf-8")
        assert text.startswith("---\n"), f"{p} missing YAML frontmatter"
        fm = yaml.safe_load(text.split("---\n", 2)[1])
        assert fm["name"] == p.parent.name
        assert fm["description"].strip()
        assert "agentsec" in text  # each skill drives the CLI
