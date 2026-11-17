"""Tests for HardcodedLlmProviderKeyGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.base import strip_python_strings
from agentsec.guards.hardcoded_llm_provider_key import HardcodedLlmProviderKeyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_openai_key_fires(tmp_path: Path) -> None:
    """HIGH: a real-shaped OpenAI key literal fires."""
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "hardcoded-llm-provider-key/known-provider-prefix"
    assert findings[0].severity == "high"
    assert "OpenAI" in findings[0].message


def test_anthropic_key_fires(tmp_path: Path) -> None:
    """HIGH: an Anthropic sk-ant- key fires and is labeled correctly."""
    (tmp_path / "client.py").write_text(
        'client = anthropic.Anthropic(api_key="sk-ant-api03-abcdefghijklmnopqrstuvwx")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "Anthropic" in findings[0].message


def test_google_key_fires(tmp_path: Path) -> None:
    """HIGH: a Google AI AIza key fires."""
    (tmp_path / "config.py").write_text(
        'GEMINI_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuv"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "Google" in findings[0].message


def test_huggingface_token_fires(tmp_path: Path) -> None:
    """HIGH: a Hugging Face hf_ token fires."""
    (tmp_path / "config.py").write_text(
        'HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz1234567"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "Hugging Face" in findings[0].message


def test_pinecone_key_fires(tmp_path: Path) -> None:
    """HIGH: — a Pinecone key literal fires."""
    (tmp_path / "config.py").write_text(
        'PINECONE_API_KEY = "pcsk_abcde_'
        + "f" * 63
        + '"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "Pinecone" in findings[0].message


def test_pinecone_key_too_short_is_safe(tmp_path: Path) -> None:
    """FP-bait: a Pinecone-prefixed token too short to be real stays silent."""
    (tmp_path / "config.py").write_text(
        'PINECONE_API_KEY = "pcsk_abcde_tooshort"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_pinecone_key_one_char_short_of_the_real_length_is_safe(tmp_path: Path) -> None:
    """FP-bait near-miss: 62 chars after the second `_` (real limit is 63) stays silent."""
    (tmp_path / "config.py").write_text(
        'PINECONE_API_KEY = "pcsk_abcde_' + "f" * 62 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_replicate_key_fires(tmp_path: Path) -> None:
    """HIGH: — a Replicate key literal fires."""
    (tmp_path / "config.py").write_text(
        'REPLICATE_API_TOKEN = "r8_' + "A" * 37 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "Replicate" in findings[0].message


def test_replicate_key_too_short_is_safe(tmp_path: Path) -> None:
    """FP-bait: a Replicate-prefixed token too short to be real stays silent."""
    (tmp_path / "config.py").write_text('REPLICATE_API_TOKEN = "r8_tooshort"\n', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_replicate_key_one_char_short_of_the_real_length_is_safe(tmp_path: Path) -> None:
    """FP-bait near-miss: 36 chars after `r8_` (real limit is 37) stays silent."""
    (tmp_path / "config.py").write_text(
        'REPLICATE_API_TOKEN = "r8_' + "A" * 36 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_groq_key_fires(tmp_path: Path) -> None:
    """HIGH: — a Groq key literal fires."""
    (tmp_path / "config.py").write_text(
        'GROQ_API_KEY = "gsk_' + "a" * 52 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "Groq" in findings[0].message


def test_groq_key_too_short_is_safe(tmp_path: Path) -> None:
    """FP-bait: a Groq-prefixed token too short to be real stays silent."""
    (tmp_path / "config.py").write_text('GROQ_API_KEY = "gsk_tooshort"\n', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_groq_key_one_char_short_of_the_real_length_is_safe(tmp_path: Path) -> None:
    """FP-bait near-miss: 51 chars after `gsk_` (real limit is 52) stays silent."""
    (tmp_path / "config.py").write_text(
        'GROQ_API_KEY = "gsk_' + "a" * 51 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_langsmith_key_fires(tmp_path: Path) -> None:
    """HIGH: — a LangSmith key literal fires."""
    (tmp_path / "config.py").write_text(
        'LANGCHAIN_API_KEY = "lsv2_pt_' + "a" * 32 + "_" + "b" * 10 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "LangSmith" in findings[0].message


def test_langsmith_key_wrong_shape_is_safe(tmp_path: Path) -> None:
    """FP-bait: a lsv2_ prefix with the wrong body shape (uppercase hex, wrong length) stays silent."""
    (tmp_path / "config.py").write_text(
        'LANGCHAIN_API_KEY = "lsv2_pt_tooshort_alsoshort"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_langsmith_key_one_char_short_on_first_segment_is_safe(tmp_path: Path) -> None:
    """FP-bait near-miss: 31 hex chars before the `_` (real limit is 32) stays silent."""
    (tmp_path / "config.py").write_text(
        'LANGCHAIN_API_KEY = "lsv2_pt_' + "a" * 31 + "_" + "b" * 10 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_langsmith_key_one_char_short_on_second_segment_is_safe(tmp_path: Path) -> None:
    """FP-bait near-miss: 9 hex chars after the `_` (real limit is 10) stays silent."""
    (tmp_path / "config.py").write_text(
        'LANGCHAIN_API_KEY = "lsv2_pt_' + "a" * 32 + "_" + "b" * 9 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_supabase_pat_fires(tmp_path: Path) -> None:
    """HIGH: — a Supabase personal access token literal fires."""
    (tmp_path / "config.py").write_text(
        'SUPABASE_PAT = "sbp_' + "a" * 40 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "Supabase" in findings[0].message


def test_supabase_pat_too_short_is_safe(tmp_path: Path) -> None:
    """FP-bait: a sbp_-prefixed token too short to be real stays silent."""
    (tmp_path / "config.py").write_text('SUPABASE_PAT = "sbp_tooshort"\n', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_supabase_pat_one_char_short_of_the_real_length_is_safe(tmp_path: Path) -> None:
    """FP-bait near-miss: 39 chars after `sbp_` (real limit is 40) stays silent."""
    (tmp_path / "config.py").write_text(
        'SUPABASE_PAT = "sbp_' + "a" * 39 + '"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_openai_key_no_space_single_quote_still_fires(tmp_path: Path) -> None:
    """Bypass check: no whitespace around '=' and single quotes must not evade detection."""
    (tmp_path / "config.py").write_text(
        "OPENAI_API_KEY='sk-proj-abc123def456ghi789jkl012mno345'\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_env_var_reference_is_safe(tmp_path: Path) -> None:
    """FP-bait: loading the key from an env var (no literal) stays silent."""
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_test_marker_on_line_is_safe(tmp_path: Path) -> None:
    """FP-bait: a test/fake/mock marker anywhere on the line silences the finding."""
    (tmp_path / "config.py").write_text(
        'TEST_KEY = "sk-proj-abc123def456ghi789jkl012mno345"  # fake test key\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_placeholder_value_is_safe(tmp_path: Path) -> None:
    """FP-bait: a documentation placeholder embedded in the token itself stays silent."""
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-proj-your-key-here-0123456789"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_url_slug_without_digit_is_safe(tmp_path: Path) -> None:
    """FP-bait: a hyphenated URL/doc slug with no digit in the random portion stays silent
    (the OpenAI pattern's digit requirement, ported from llmarmor, exists for exactly this)."""
    (tmp_path / "docs.py").write_text(
        'slug = "sk-the-model-to-adopt-a-persona-for-chat"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    """The inline pragma silences the finding on that line."""
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"  '
        "# security: allow-llm-provider-key\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_comment_only_mention_is_safe(tmp_path: Path) -> None:
    """FP-bait: a key shown only in a comment (not a real assignment) stays silent."""
    (tmp_path / "config.py").write_text(
        "# Example: OPENAI_API_KEY = 'sk-proj-abc123def456ghi789jkl012mno345'\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_nonproduct_path_downgraded_not_dropped(tmp_path: Path) -> None:
    """a key literal in a fixture/test file is DOWNGRADED to `medium`, not dropped
    entirely — a real key accidentally pasted into a test fixture is still a live leak, and a
    silent skip cannot be told apart from "no key in this file". Non-vacuous: before this fix
    the guard used `continue` on `is_nonproduct_path` and this exact input produced zero
    findings; it must now produce exactly one, at reduced severity. `medium` (not `low`, PR #583
    review) so this class stays gateable by a repo that opts into `--fail-on medium` — one of the
    three values the action's `fail-on` input (`action.yml`) accepts; `low` is not."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_config.py").write_text(
        'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].rule == "hardcoded-llm-provider-key/known-provider-prefix"
    assert "test/fixture/example path" in findings[0].message


def test_nonproduct_path_marker_worded_key_stays_silent(tmp_path: Path) -> None:
    """PR #583 review, Minor 2: the real behavior change here is that test/fixture files are now
    FULLY SCANNED instead of skipped outright at the file level — a widening of what gets read,
    even though the severity narrows what gets reported. Rule 1's FP-bait direction: a
    marker-worded (test/fake/mock) key under a now-scanned-not-skipped test path must still stay
    silent, the same as it always has in a production path. Scope, measured on #583's round-2 review:
    breaking the marker suppression fails this test, so it does pin that property — but it does NOT
    discriminate against the pre-fix code, which skipped the file entirely and was silent for a
    different reason. FP-bait for a newly-scanned path is structurally weak in that one direction."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_config.py").write_text(
        'FAKE_OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"  # fake test key\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_nonproduct_path_pragma_still_fully_suppresses(tmp_path: Path) -> None:
    """The downgrade above must not blunt the user's own opt-out: a pragma on the line still
    silences the finding completely, in a test path exactly as in a production one (CLAUDE.md
    rule 4 — a suppression must not void a user's own opt-out, and vice versa: the new downgrade
    path must not accidentally bypass the pragma)."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_config.py").write_text(
        'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"  '
        "# security: allow-llm-provider-key\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_marker_only_in_trailing_comment_does_not_suppress(tmp_path: Path) -> None:
    """A marker word that appears ONLY in the trailing `#` comment must NOT suppress a real key
    on the same line — comments are stripped before the line-level marker check runs (#529
    review: the design doc previously claimed the opposite with this exact example, and was
    wrong about the ordering, not the code)."""
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-proj-real-leaked-key-123456"  # test this later\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_google_key_with_appended_placeholder_suffix_is_safe(tmp_path: Path) -> None:
    """FP-bait: a placeholder word appended directly after a real-length Google key body must
    still be visible to the token-level exclusion. The pattern used to be a fixed `{35}` count,
    which truncated the match right before the appended placeholder — the excluded text landed
    outside `m.group(0)` entirely and this check never saw it (#529 review)."""
    (tmp_path / "config.py").write_text(
        'GEMINI_KEY = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ01234exampleDoNotUse"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_real_key_after_a_placeholder_key_on_the_same_line_still_fires(tmp_path: Path) -> None:
    """A placeholder-shaped key earlier on a line must not shield a real key literal appearing
    after it — only the first regex match per line was being considered, so a placeholder token
    ended the scan before the real key later on the line was ever examined (#529 review)."""
    (tmp_path / "config.py").write_text(
        'KEYS = ["sk-proj-your-key-here-000000", "sk-proj-realLeakedKeyAbc123456789zzz999"]\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_applies_universally() -> None:
    """Universal guard: a hardcoded key is dangerous on any stack, not framework-gated."""
    assert HardcodedLlmProviderKeyGuard().applies(mkprofile(Path("/tmp"), features={"java"})) is True
    assert HardcodedLlmProviderKeyGuard().applies(mkprofile(Path("/tmp"), features=set())) is True


# --------------------------------------------------------------------------- #
# Go support (#553 review follow-up)
# --------------------------------------------------------------------------- #


def test_go_openai_key_fires(tmp_path: Path) -> None:
    (tmp_path / "config.go").write_text(
        'const OpenAIKey = "sk-proj-abc123def456ghi789jkl012mno345"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "OpenAI" in findings[0].message


def test_go_anthropic_key_fires(tmp_path: Path) -> None:
    (tmp_path / "client.go").write_text(
        'client := anthropic.NewClient("sk-ant-api03-abcdefghijklmnopqrstuvwx")\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "Anthropic" in findings[0].message


def test_go_groq_and_supabase_pat_fire(tmp_path: Path) -> None:
    """Go side: the widened regex set is shared between the Python and Go scan
    paths, so the new providers must fire there too, not just in the Python-side tests above."""
    (tmp_path / "config.go").write_text(
        'const GroqKey = "gsk_' + "a" * 52 + '"\n'
        'const SupabasePAT = "sbp_' + "a" * 40 + '"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 2
    assert any("Groq" in f.message for f in findings)
    assert any("Supabase" in f.message for f in findings)


def test_go_comment_only_mention_is_safe(tmp_path: Path) -> None:
    # FP-bait: strip_go_comments blanks the // comment before the line is ever examined, same
    # protection the Python path gets from its own comment-stripping step.
    (tmp_path / "config.go").write_text(
        '// Example: OpenAIKey = "sk-proj-abc123def456ghi789jkl012mno345"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_go_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "config.go").write_text(
        'const OpenAIKey = "sk-proj-abc123def456ghi789jkl012mno345" '
        "// security: allow-llm-provider-key\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_go_test_marker_on_line_is_safe(tmp_path: Path) -> None:
    # Marker word bounded by non-alphanumeric chars on both sides (a bare "test" prefix glued
    # onto an identifier, testOpenAIKey, would NOT match _TEST_VAR_MARKER's word-boundary regex —
    # same as the Python-side guard's TEST_KEY example uses an underscore boundary).
    (tmp_path / "config.go").write_text(
        'const TEST_OpenAIKey = "sk-proj-abc123def456ghi789jkl012mno345"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_go_placeholder_value_is_safe(tmp_path: Path) -> None:
    (tmp_path / "config.go").write_text(
        'const OpenAIKey = "sk-proj-your-key-here-000000"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_go_nonproduct_path_downgraded_not_dropped(tmp_path: Path) -> None:
    """Go side: same downgrade-not-drop contract as the Python path."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "config_test.go").write_text(
        'const OpenAIKey = "sk-proj-abc123def456ghi789jkl012mno345"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_go_nonproduct_path_marker_worded_key_stays_silent(tmp_path: Path) -> None:
    """PR #583 review, Minor 2, Go side: same FP-bait direction as the Python-side test — a
    marker-worded key under a now-scanned-not-skipped test path stays silent."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "config_test.go").write_text(
        'const TEST_OpenAIKey = "sk-proj-abc123def456ghi789jkl012mno345"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert HardcodedLlmProviderKeyGuard().run(tmp_path, profile) == []


def test_go_scan_does_not_duplicate_python_scan_when_both_present(tmp_path: Path) -> None:
    # Coordination test: a polyglot repo with both a Python dir and a Go dir gets both scanned,
    # neither shadowing the other (the real regression this fix targets — python_scan_dirs alone
    # would have missed the Go subdirectory entirely in this shape).
    py_dir = tmp_path / "backend"
    py_dir.mkdir()
    (py_dir / "config.py").write_text(
        'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"\n', encoding="utf-8"
    )
    go_dir = tmp_path / "svc"
    go_dir.mkdir()
    (go_dir / "config.go").write_text(
        'const HFToken = "hf_abcdefghijklmnopqrstuvwxyz1234567"\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python", "go"}, python_dirs=["backend"], go_dirs=["svc"])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    assert len(findings) == 2
    assert any("OpenAI" in f.message for f in findings)
    assert any("Hugging Face" in f.message for f in findings)


def test_pragma_quoted_in_a_string_on_the_line_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line check reads the same-length Python comment-only view (the strings
    # blanker keeps single-line strings), so a string on the key's own line quoting the pragma
    # is content - only a real `#` comment (`test_pragma_suppresses`) opts out.
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"; '
        'HELP = "opt out with # security: allow-llm-provider-key"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert len(HardcodedLlmProviderKeyGuard().run(tmp_path, profile)) == 1


def test_go_pragma_quoted_in_a_string_on_the_line_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the Go per-line check reads the same-length Go comment-only view, so a string on
    # the key's own line quoting the pragma is content - only a real `//` comment opts out.
    (tmp_path / "config.go").write_text(
        'const OpenAIKey = "sk-proj-abc123def456ghi789jkl012mno345"; '
        'const Help = "opt out with // security: allow-llm-provider-key"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert len(HardcodedLlmProviderKeyGuard().run(tmp_path, profile)) == 1


@pytest.mark.parametrize("sep", ["\x0b", "\x0c", "\x1c", "\x85", "\u2028"])
def test_separator_char_inside_a_docstring_does_not_desync_the_pragma_view(tmp_path: Path, sep: str) -> None:
    # #996 round-2 M2: a `str.splitlines()` boundary other than `\n` inside a triple-quoted string
    # is removed or kept by the strings blanker on its own terms, so a comment view taken of the
    # RAW file could have more rows than the blanked text and the strict zip raised, blinding the
    # guard for the whole run. The view is now taken of the same blanked text the loop splits: no
    # raise, the key fires on ITS row of that text (never the pragma'd key's row, the one-off
    # misalignment the strict zip exists to catch), and the pragma still opts out.
    src = (
        f'DOC = """ab{sep}cd\ngh"""\n'
        'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"\n'
        'OTHER_KEY = "sk-proj-abc123def456ghi789jkl012mno345"  # security: allow-llm-provider-key\n'
    )
    (tmp_path / "mod.py").write_text(src, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = HardcodedLlmProviderKeyGuard().run(tmp_path, profile)
    rows = strip_python_strings(src).splitlines()
    key_row = next(i for i, row in enumerate(rows, 1) if "OPENAI_API_KEY" in row)
    assert [f.location.rsplit(":", 1)[1] for f in findings] == [str(key_row)]
