from __future__ import annotations

from agentsec.guards.hostname_regex_unsafe import HostnameRegexUnsafeGuard
from tests.guards._common import *  # noqa: F401,F403


def test_hostname_regex_unsafe_fires_on_unescaped_dot(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "const TRUSTED_HOST = /^https:\\/\\/trusted.com$/;\n"
        "function isTrusted(target) {\n"
        "  return TRUSTED_HOST.test(new URL(target).hostname);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = HostnameRegexUnsafeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    rules = [f.rule for f in findings]
    assert "hostname-regex-unsafe/unescaped-dot" in rules


def test_hostname_regex_unsafe_fires_on_missing_end_anchor(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "const TRUSTED_HOST = /^https:\\/\\/trusted\\.com/;\n"
        "function isTrusted(target) {\n"
        "  return TRUSTED_HOST.test(new URL(target).hostname);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = HostnameRegexUnsafeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    rules = [f.rule for f in findings]
    assert "hostname-regex-unsafe/missing-end-anchor" in rules


def test_hostname_regex_unsafe_silent_on_safe_pattern(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "const TRUSTED_HOST = /^https:\\/\\/trusted\\.com$/;\n"
        "function isTrusted(target) {\n"
        "  return TRUSTED_HOST.test(new URL(target).hostname);\n"
        "}\n",
        encoding="utf-8",
    )
    assert HostnameRegexUnsafeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_hostname_regex_unsafe_silent_without_hostname_context(tmp_path: Path) -> None:
    # FP-bait: an unanchored regex with an unescaped dot is fine if it's not a
    # hostname/URL-allowlist check at all (e.g. an ordinary form-field pattern).
    (tmp_path / "form.js").write_text(
        "const PRICE_PATTERN = /^\\d+.\\d{2}/;\n"
        "function isPrice(value) {\n"
        "  return PRICE_PATTERN.test(value);\n"
        "}\n",
        encoding="utf-8",
    )
    assert HostnameRegexUnsafeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_hostname_regex_unsafe_fires_via_test_call_context(tmp_path: Path) -> None:
    # True positive via the OTHER context gate: no hostname-ish variable name, but the
    # .test() call argument names "hostname" directly.
    (tmp_path / "auth.js").write_text(
        "const p = /^trusted.com/;\n"
        "function check(u) {\n"
        "  return p.test(new URL(u).hostname);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = HostnameRegexUnsafeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) >= 1


def test_hostname_regex_unsafe_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "const TRUSTED_HOST = /^https:\\/\\/trusted.com/;  // security: allow-hostname-regex-unsafe\n"
        "function isTrusted(target) {\n"
        "  return TRUSTED_HOST.test(new URL(target).hostname);\n"
        "}\n",
        encoding="utf-8",
    )
    assert HostnameRegexUnsafeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_hostname_regex_unsafe_does_not_apply_without_js(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert HostnameRegexUnsafeGuard().applies(profile) is False
    assert HostnameRegexUnsafeGuard().run(tmp_path, profile) == []


def test_hostname_regex_unsafe_applies_with_typescript_only(tmp_path: Path) -> None:
    # Regression (#548 gate review, systemic High): a TS-only repo (no .js, no Express) must
    # not be silently skipped.
    profile = mkprofile(tmp_path, features={"typescript"})
    assert HostnameRegexUnsafeGuard().applies(profile) is True


def test_hostname_regex_unsafe_silent_on_url_substring_in_arg_name(tmp_path: Path) -> None:
    # FP-bait (#548 review High 4): the `.test()` context gate keyed on the bare
    # substring "url" appearing ANYWHERE in the call argument's name, so a pure asset-filename
    # check whose parameter merely ends in "Url" (no hostname/URL parsing involved at all) fired
    # HIGH. `reportUrl` contains "Url" as a camelCase tail, not a standalone "url" token — the
    # `\b` word-boundary fix must not treat that as a hostname/URL-parsing signal.
    (tmp_path / "reports.js").write_text(
        "const REPORT_PATTERN = /^report\\.pdf/;\n"
        "function isQuarterlyReport(reportUrl) {\n"
        "  return REPORT_PATTERN.test(reportUrl);\n"
        "}\n",
        encoding="utf-8",
    )
    assert HostnameRegexUnsafeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_hostname_regex_unsafe_still_fires_on_bare_url_arg_name(tmp_path: Path) -> None:
    # True-positive companion to the FP-bait above: a `.test()` call whose argument is the
    # WHOLE identifier "url" (not a substring of a longer name) is still a real hostname/URL
    # context signal and must still fire.
    (tmp_path / "auth.js").write_text(
        "const ALLOWED = /^https:\\/\\/trusted\\.com/;\n"
        "function isTrusted(url) {\n"
        "  return ALLOWED.test(url);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = HostnameRegexUnsafeGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    rules = [f.rule for f in findings]
    assert "hostname-regex-unsafe/missing-end-anchor" in rules
