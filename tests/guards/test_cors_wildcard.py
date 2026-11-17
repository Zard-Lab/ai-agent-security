from __future__ import annotations

from agentsec.guards.cors_wildcard import CorsWildcardGuard
from tests.guards._common import *  # noqa: F401,F403


def test_cors_wildcard_flags_allow_origins_star(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n', encoding="utf-8"
    )
    findings = CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cors-wildcard/allow-origins-star"
    assert findings[0].severity == "high"

def test_cors_wildcard_passes_explicit_origins(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        'app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])\n', encoding="utf-8"
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_cors_wildcard_passes_with_pragma(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        'app.add_middleware(CORSMiddleware, allow_origins=["*"])  # security: allow-cors-wildcard\n', encoding="utf-8"
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_cors_wildcard_no_cors_middleware_silent(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n", encoding="utf-8"
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_cors_wildcard_flags_multiline_origins_list(tmp_path: Path) -> None:
    # #424: a wildcard in a MULTI-LINE origins list must fire (the old per-line scan missed it).
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        "    allow_origins=[\n"
        '        "*",\n'
        "    ],\n"
        ")\n",
        encoding="utf-8",
    )
    findings = CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cors-wildcard/allow-origins-star"

def test_cors_wildcard_silent_on_docstring_and_comment(tmp_path: Path) -> None:
    # FP-bait (#424): a wildcard shown in a docstring or a `#` comment must not fire.
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from fastapi.middleware.cors import CORSMiddleware\n"
        '"""Example: app.add_middleware(CORSMiddleware, allow_origins=["*"])"""\n'
        '# app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
        "app = FastAPI()\n",
        encoding="utf-8",
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_cors_wildcard_not_applicable_without_fastapi() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert CorsWildcardGuard().applies(prof) is False

def test_cors_wildcard_flags_origin_regex_catchall(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        'app.add_middleware(CORSMiddleware, allow_origin_regex=r".*", allow_credentials=True)\n', encoding="utf-8"
    )
    findings = CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cors-wildcard/origin-regex-catchall"
    assert findings[0].severity == "high"

def test_cors_wildcard_flags_origin_regex_anchored_catchall(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        'app.add_middleware(CORSMiddleware, allow_origin_regex=r"^.*$")\n', encoding="utf-8"
    )
    assert len(CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))) == 1

def test_cors_wildcard_passes_narrowed_origin_regex(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        r'app.add_middleware(CORSMiddleware, allow_origin_regex=r"https://.*\.example\.com")' "\n", encoding="utf-8"
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_cors_wildcard_origin_regex_pragma(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        'app.add_middleware(CORSMiddleware, allow_origin_regex=r".*")  # security: allow-cors-wildcard\n', encoding="utf-8"
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []



def test_cors_wildcard_fires_with_a_comment_inside_the_origins_list(tmp_path: Path) -> None:
    # Regression (#439 review): `_WILDCARD_ORIGINS` spans newlines with `\s*`, which an
    # ordinary `# TODO` line inside the list interrupts — so this PR's own new multi-line
    # support was defeated by a comment, and a real wildcard went unreported.
    (tmp_path / "main.py").write_text(
        "app.add_middleware(CORSMiddleware,\n"
        "    allow_origins=[\n"
        "        # TODO tighten this before launch\n"
        '        "*",\n'
        "    ],\n"
        "    allow_credentials=True,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "cors-wildcard/allow-origins-star"


def test_cors_wildcard_silent_on_commented_out_occurrence(tmp_path: Path) -> None:
    # FP-bait: a wildcard that is itself commented out is not configured. Comment stripping
    # removes it from the matched text entirely, which is why the old explicit skip went.
    (tmp_path / "main.py").write_text(
        "app.add_middleware(CORSMiddleware,\n"
        '    # allow_origins=["*"],\n'
        '    allow_origins=["https://app.example.com"],\n'
        ")\n",
        encoding="utf-8",
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_cors_wildcard_pragma_still_suppresses(tmp_path: Path) -> None:
    # FP-bait: the pragma IS a comment, so it must be read from the ORIGINAL lines rather
    # than the comment-stripped copy the match now runs against.
    (tmp_path / "main.py").write_text(
        "app.add_middleware(CORSMiddleware,\n"
        '    allow_origins=["*"],  # security: allow-cors-wildcard\n'
        ")\n",
        encoding="utf-8",
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def _cors_star_with_note(note: str) -> str:
    return (
        "from fastapi.middleware.cors import CORSMiddleware\n"
        f'app.add_middleware(CORSMiddleware, allow_origins=["*"]); _note = "{note}"\n'
    )


def test_cors_wildcard_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma phrase inside a string on the match line is not a comment, so it must not suppress.
    for note in ("# security: allow-cors-wildcard", "# neutral note"):
        (tmp_path / "main.py").write_text(_cors_star_with_note(note), encoding="utf-8")
        findings = CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))
        assert [f.rule for f in findings] == ["cors-wildcard/allow-origins-star"], note
        assert findings[0].location.endswith("main.py:2")


def test_cors_wildcard_origin_regex_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: same contract for the `allow_origin_regex` catch-all rule's flagged line.
    for note in ("# security: allow-cors-wildcard", "# neutral note"):
        (tmp_path / "main.py").write_text(
            "from fastapi.middleware.cors import CORSMiddleware\n"
            f'app.add_middleware(CORSMiddleware, allow_origin_regex=r".*"); _note = "{note}"\n',
            encoding="utf-8",
        )
        findings = CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))
        assert [f.rule for f in findings] == ["cors-wildcard/origin-regex-catchall"], note


def test_cors_wildcard_pragma_comment_on_a_continuation_line_of_the_span_suppresses(tmp_path: Path) -> None:
    # #1040 reach: a real pragma comment on ANY line of a multi-line origins match still suppresses.
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        "    allow_origins=[\n"
        '        "*",  # security: allow-cors-wildcard\n'
        "    ],\n"
        ")\n",
        encoding="utf-8",
    )
    assert CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_cors_wildcard_pragma_comment_outside_the_match_span_does_not_suppress(tmp_path: Path) -> None:
    # #1040 reach: the match span starts at `allow_origins=`, so a pragma comment above it reaches nothing.
    (tmp_path / "main.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "# security: allow-cors-wildcard\n"
        "\n"
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        '    allow_origins=["*"],\n'
        ")\n",
        encoding="utf-8",
    )
    findings = CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert [f.rule for f in findings] == ["cors-wildcard/allow-origins-star"]
    assert findings[0].location.endswith("main.py:6")


def test_cors_wildcard_multiline_pragma_after_a_form_feed_docstring_keeps_its_reach(tmp_path: Path) -> None:
    # #1040: the multi-line rule numbers its span by "\n" on the stripped text. A pragma set numbered on
    # the raw text counts the form feed in the docstring as a line break, one line low below it.
    def rules(above: str, closing: str) -> list[str]:
        (tmp_path / "main.py").write_text(
            f'"""doc{chr(12)}x\nmore"""\n'
            f"from fastapi.middleware.cors import CORSMiddleware\nx = 1{above}\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=[\n"
            '        "*",\n'
            f"    ]{closing},\n"
            ")\n",
            encoding="utf-8",
        )
        return [f.rule for f in CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))]

    pragma = "  # security: allow-cors-wildcard"
    assert rules("", "") == ["cors-wildcard/allow-origins-star"]  # control
    assert rules("", pragma) == []  # a comment on the span's closing line still suppresses
    assert rules(pragma, "") == ["cors-wildcard/allow-origins-star"]  # one above the call does not reach


def test_cors_wildcard_multiline_pragma_below_a_bare_form_feed_line_keeps_its_reach(tmp_path: Path) -> None:
    # #1154 round 1, M1: a bare form feed (a page break, outside any string) survives the stripper.
    # The span is numbered by "\n", so its pragma lines must be too, or they sit one line low.
    def rules(above: str, closing: str) -> list[str]:
        (tmp_path / "main.py").write_text(
            f"from fastapi.middleware.cors import CORSMiddleware\n{chr(12)}\nx = 1{above}\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=[\n"
            '        "*",\n'
            f"    ]{closing},\n"
            ")\n",
            encoding="utf-8",
        )
        return [f.rule for f in CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))]

    pragma = "  # security: allow-cors-wildcard"
    assert rules("", "") == ["cors-wildcard/allow-origins-star"]  # control
    assert rules("", pragma) == []  # a comment on the span's closing line still suppresses
    assert rules(pragma, "") == ["cors-wildcard/allow-origins-star"]  # one above the call does not reach


def test_cors_wildcard_origin_regex_pragma_below_a_bare_form_feed_line_stays_on_its_line(tmp_path: Path) -> None:
    # The origin-regex rule walks `splitlines()` rows, so its own set stays on that basis.
    def rules(above: str, own: str) -> list[str]:
        (tmp_path / "main.py").write_text(
            f"from fastapi.middleware.cors import CORSMiddleware\n{chr(12)}\nx = 1{above}\n"
            f'app.add_middleware(CORSMiddleware, allow_origin_regex=".*"){own}\n',
            encoding="utf-8",
        )
        return [f.rule for f in CorsWildcardGuard().run(tmp_path, _fastapi_prof(tmp_path))]

    pragma = "  # security: allow-cors-wildcard"
    control = rules("", "")
    assert control  # the plant fires
    assert rules("", pragma) == []
    assert rules(pragma, "") == control
