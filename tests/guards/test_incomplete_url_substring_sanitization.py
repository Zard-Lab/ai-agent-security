from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.incomplete_url_substring_sanitization import (
    IncompleteUrlSubstringSanitizationGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_incomplete_url_substring_sanitization_fires_on_includes(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        "function isTrustedTarget(redirectUrl) {\n"
        "  return redirectUrl.includes('trusted.com');\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    )
    assert len(findings) == 1
    assert findings[0].rule == "incomplete-url-substring-sanitization/raw-substring-check"
    assert findings[0].severity == "high"


def test_incomplete_url_substring_sanitization_fires_on_starts_with(tmp_path: Path) -> None:
    (tmp_path / "fetch.js").write_text(
        "function isTrusted(targetUrl) {\n"
        "  return targetUrl.startsWith('trusted.com');\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    )
    assert len(findings) == 1


def test_incomplete_url_substring_sanitization_silent_when_hostname_parsed(tmp_path: Path) -> None:
    # FP-bait: the receiver DOES reach the `.startsWith(`/URL-ish gate (unlike the old
    # fixture here, which was `new URL(redirectUrl).hostname === 'trusted.com'` — that line
    # has no `.includes`/`.indexOf`/`.startsWith` call at all, so `_URL_ISH_RECEIVER` never
    # matched and the guard returned `[]` for a reason that had nothing to do with
    # `_ALREADY_PARSED`; the assertion passed identically even with `_ALREADY_PARSED`
    # neutered, so it was not actually testing the exclusion. This fixture's
    # receiver (`urlHostname`) is url-ish and its `.startsWith(` call is real, so the only
    # thing that can suppress it is `_ALREADY_PARSED` correctly recognizing the `new
    # URL(redirectUrl).hostname` construction earlier on the same line — confirmed by
    # running this fixture with `_ALREADY_PARSED` neutered, which DOES produce a finding.
    (tmp_path / "redirect.js").write_text(
        "function isTrustedTarget(redirectUrl) {\n"
        "  const urlHostname = new URL(redirectUrl).hostname; "
        "return urlHostname.startsWith('trusted.com');\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    ) == []


def test_incomplete_url_substring_sanitization_unrelated_hostname_does_not_hide_real_bypass(
    tmp_path: Path,
) -> None:
    # Regression (FN, #548 Critical 2): an unrelated `.hostname`/`new URL(` call
    # LATER on the same line — belonging to a totally different value — must not trip the
    # `_ALREADY_PARSED` same-line exclusion and silently hide a real substring-check bypass
    # on `redirectUrl`. Before the fix, `_ALREADY_PARSED` scanned the whole line, so the
    # `new URL(other).hostname` fragment (irrelevant to `redirectUrl`) suppressed this
    # finding entirely.
    (tmp_path / "redirect.js").write_text(
        "function check(redirectUrl, other) {\n"
        "  if (redirectUrl.includes('trusted.com') && new URL(other).hostname === 'x') "
        "{ allow(); }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    )
    assert len(findings) == 1
    assert findings[0].rule == "incomplete-url-substring-sanitization/raw-substring-check"


def test_incomplete_url_substring_sanitization_unrelated_literal_not_swept_into_call(
    tmp_path: Path,
) -> None:
    # Regression (FP, #548 Critical 2): the real `.includes()` call's argument is a
    # variable (`someVar`), not a domain-shaped literal — but an unrelated string literal
    # (`'trusted.com'` inside a sibling `logHost(...)` call) sits later on the SAME line,
    # outside the actual call. Before the fix, the arg scan ran from the opening "(" to
    # end-of-line, sweeping that unrelated literal in and firing a spurious finding.
    (tmp_path / "redirect.js").write_text(
        "function check(redirectUrl, someVar) {\n"
        "  if (redirectUrl.includes(someVar)) { logHost('trusted.com'); }\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    ) == []


def test_incomplete_url_substring_sanitization_silent_non_url_receiver(tmp_path: Path) -> None:
    # FP-bait: an ordinary string .includes() call on a variable with no URL-ish name.
    (tmp_path / "search.js").write_text(
        "function matches(query) {\n"
        "  return query.includes('example.com');\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    ) == []


def test_incomplete_url_substring_sanitization_silent_non_domain_arg(tmp_path: Path) -> None:
    # FP-bait: the .includes() argument isn't a domain-shaped string at all.
    (tmp_path / "redirect.js").write_text(
        "function hasQueryParam(redirectUrl) {\n"
        "  return redirectUrl.includes('?next=');\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    ) == []


def test_incomplete_url_substring_sanitization_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        "function isTrustedTarget(redirectUrl) {\n"
        "  return redirectUrl.includes('trusted.com');  // security: allow-incomplete-url-substring-sanitization\n"
        "}\n",
        encoding="utf-8",
    )
    assert IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    ) == []


def test_incomplete_url_substring_sanitization_does_not_apply_without_js(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert IncompleteUrlSubstringSanitizationGuard().applies(profile) is False
    assert IncompleteUrlSubstringSanitizationGuard().run(tmp_path, profile) == []


def test_incomplete_url_substring_sanitization_applies_with_typescript_only(tmp_path: Path) -> None:
    # Regression (#548 gate review, systemic High): a TS-only repo (no .js, no Express) must
    # not be silently skipped.
    profile = mkprofile(tmp_path, features={"typescript"})
    assert IncompleteUrlSubstringSanitizationGuard().applies(profile) is True


# --- #1055: a check call or parse evidence counts only when it is live code ------------------------


def _run_line(tmp_path: Path, line: str) -> list[Finding]:
    (tmp_path / "check.js").write_text(f"function gate(redirectUrl, targetUrl) {{\n  {line}\n}}\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"javascript"})
    guard = IncompleteUrlSubstringSanitizationGuard()
    assert guard.applies(prof)
    return guard.run(tmp_path, prof)


@pytest.mark.parametrize(
    "line",
    [
        "log('TODO: use new URL( here'); if (redirectUrl.includes('trusted.com')) go();",
        "log(`compare the .hostname for ${id}`); if (redirectUrl.includes('trusted.com')) go();",
    ],
)
def test_incomplete_url_substring_quoted_parse_no_longer_clears(tmp_path: Path, line: str) -> None:
    # The FN direction (#1055): parse evidence named in a log string used to clear a real finding.
    findings = _run_line(tmp_path, line)
    assert [f.rule for f in findings] == ["incomplete-url-substring-sanitization/raw-substring-check"]
    assert findings[0].location.replace("\\", "/").endswith("check.js:2")


@pytest.mark.parametrize(
    "line",
    [
        "const host = new URL(targetUrl).hostname; if (targetUrl.includes('trusted.com')) go();",
        # Real parse evidence nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        "log(`${new URL(targetUrl).hostname}`); if (targetUrl.startsWith('trusted.com')) go();",
        # A quoted copy earlier on the line must not decide for the real evidence after it.
        "log('new URL('); const t = new URL(targetUrl).hostname; if (targetUrl.startsWith('trusted.com')) go();",
    ],
)
def test_incomplete_url_substring_real_parse_still_clears(tmp_path: Path, line: str) -> None:
    assert _run_line(tmp_path, line) == []


@pytest.mark.parametrize(
    "line",
    [
        "const HELP = \"never write redirectUrl.includes('trusted.com')\";",
        "const HELP = `never write redirectUrl.includes('trusted.com') for ${id}`;",
    ],
)
def test_incomplete_url_substring_quoted_check_stays_silent(tmp_path: Path, line: str) -> None:
    # The FP direction (#1055): a check spelled out in a docs string is not a check.
    assert _run_line(tmp_path, line) == []


@pytest.mark.parametrize(
    "line",
    [
        "log(`ok=${redirectUrl.includes('trusted.com')}`);",
        # First-match shadowing, a FN before #1055: `.search` took only the first call on the line,
        # whether a quoted copy or a real call with no domain argument.
        "log('redirectUrl.includes(x)'); if (redirectUrl.includes('trusted.com')) go();",
        "if (redirectUrl.includes(q) || redirectUrl.includes('trusted.com')) go();",
    ],
)
def test_incomplete_url_substring_real_check_still_fires(tmp_path: Path, line: str) -> None:
    findings = _run_line(tmp_path, line)
    assert [f.rule for f in findings] == ["incomplete-url-substring-sanitization/raw-substring-check"]


def test_incomplete_url_substring_later_call_after_parse_stays_silent(tmp_path: Path) -> None:
    # FP bait for the shadowing widening: the second call on the line is now reached, and the
    # parse evidence before it still clears it.
    line = "if (redirectUrl.includes(q) && new URL(targetUrl).hostname && targetUrl.includes('trusted.com')) go();"
    assert _run_line(tmp_path, line) == []


def test_incomplete_url_substring_pragma_still_suppresses_a_code_anchored_check(tmp_path: Path) -> None:
    line = (
        "log(`ok=${redirectUrl.includes('trusted.com')}`); "
        "// security: allow-incomplete-url-substring-sanitization"
    )
    assert _run_line(tmp_path, line) == []


def test_incomplete_url_substring_sanitization_quoted_close_paren_does_not_hide_the_domain(
    tmp_path: Path,
) -> None:
    # #548's own repro, end to end (it was only pinned at the `split_call_args` level). A `)` inside
    # the first string argument used to end the split there, so the domain literal after it was
    # never seen. JS stays on the splitter's default mode, which #613's Python mode leaves unchanged.
    (tmp_path / "redirect.js").write_text(
        "function go(redirectUrl) {\n"
        "  if (redirectUrl.includes('note)' + 'trusted.com')) { fetch(redirectUrl); }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IncompleteUrlSubstringSanitizationGuard().run(
        tmp_path, mkprofile(tmp_path, features={"javascript"})
    )
    assert [(f.rule, f.location) for f in findings] == [
        ("incomplete-url-substring-sanitization/raw-substring-check", "redirect.js:2")
    ]
