from __future__ import annotations

from agentsec.guards.regex_html_sanitizer import RegexHtmlSanitizerGuard
from tests.guards._common import *  # noqa: F401,F403


def test_regex_html_sanitizer_flags_dot_star_pattern(tmp_path: Path) -> None:
    (tmp_path / "sanitize.py").write_text(
        'clean = re.sub(r"<.*?>", "", user_input)\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "regex-html-sanitizer/wildcard-tag-strip"
    assert findings[0].severity == "medium"

def test_regex_html_sanitizer_flags_negated_class_pattern(tmp_path: Path) -> None:
    (tmp_path / "sanitize.py").write_text(
        'clean = re.sub(r"<[^>]+>", "", llm_output)\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "regex-html-sanitizer/wildcard-tag-strip"


def test_regex_html_sanitizer_benign_strip_to_plaintext_fires_medium_not_high(tmp_path: Path) -> None:
    # Review #395: `re.sub(r"<[^>]+>", "", html)` used only to build a plaintext preview/word
    # count (the output is never re-rendered as HTML) previously fired HIGH — demoted to MEDIUM
    # since narrowing to a render/`|safe`/innerHTML sink would need real dataflow this guard
    # doesn't have.
    (tmp_path / "preview.py").write_text(
        'def word_count(html):\n'
        '    text = re.sub(r"<[^>]+>", "", html)\n'
        '    return len(text.split())\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "medium"

def test_regex_html_sanitizer_silent_literal_tag(tmp_path: Path) -> None:
    # A single literal tag (no wildcard construct) is out of scope for this guard.
    (tmp_path / "sanitize.py").write_text(
        'clean = re.sub(r"<b>", "", user_input)\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert findings == []

def test_regex_html_sanitizer_silent_non_empty_replacement(tmp_path: Path) -> None:
    (tmp_path / "sanitize.py").write_text(
        'clean = re.sub(r"<.*?>", "[REDACTED]", user_input)\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert findings == []

def test_regex_html_sanitizer_silent_unrelated_re_sub(tmp_path: Path) -> None:
    (tmp_path / "format.py").write_text(
        'clean = re.sub(r"\\s+", " ", text)\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert findings == []

def test_regex_html_sanitizer_pragma_silences(tmp_path: Path) -> None:
    content = (
        'clean = re.sub(r"<.*?>", "", user_input)\n'
        "# security: allow-regex-html-sanitizer\n"
    )
    (tmp_path / "sanitize.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert findings == []

def test_regex_html_sanitizer_prose_mention_does_not_suppress(tmp_path: Path) -> None:
    # #395 M: a file that merely QUOTES the pragma phrase in prose (a string, not a `#` comment)
    # must not go blind — the pragma is anchored to an actual line comment.
    content = (
        'HELP = "pass security: allow-regex-html-sanitizer to skip this"\n'
        'clean = re.sub(r"<.*?>", "", user_input)\n'
    )
    (tmp_path / "sanitize.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_regex_html_sanitizer_documented_pragma_form_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424: the STRONGER shape the test above never covered — the exact `# security: …` syntax the
    # remediation text tells users to write, quoted inside a string. Under the raw-text match the
    # `#`-prefixed regex still matched (a `#` is a character, not a comment token) and the file went
    # blind; on the comment view a string is not a comment.
    content = (
        'HELP = "add `# security: allow-regex-html-sanitizer` to the line to skip this"\n'
        'clean = re.sub(r"<.*?>", "", user_input)\n'
    )
    (tmp_path / "sanitize.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = RegexHtmlSanitizerGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_regex_html_sanitizer_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"java"})
    assert RegexHtmlSanitizerGuard().applies(profile) is False

def test_regex_html_sanitizer_applies_with_python() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert RegexHtmlSanitizerGuard().applies(profile) is True
