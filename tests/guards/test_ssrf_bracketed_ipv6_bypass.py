"""Tests for SsrfBracketedIpv6BypassGuard — planted-violation + FP-bait."""
from __future__ import annotations

from agentsec.guards.ssrf_bracketed_ipv6_bypass import SsrfBracketedIpv6BypassGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"typescript"}, python_dirs=["."])


def test_bracketed_ipv6_bypass_fires(tmp_path: Path) -> None:
    (tmp_path / "url_guard.ts").write_text(
        "function isSafeUrl(raw: string): boolean {\n"
        "  const host = new URL(raw).hostname;\n"
        "  if (net.isIP(host)) {\n"
        "    if (host === '::1') return false;\n"
        "    return true;\n"
        "  }\n"
        "  return true;\n"
        "}\n\n"
        "if (isSafeUrl(target)) {\n"
        "  fetch(target);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = SsrfBracketedIpv6BypassGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "ssrf-bracketed-ipv6-bypass/no-bracket-normalization")
    assert hit.severity == "high"


def test_bracket_stripped_before_classification_is_safe(tmp_path: Path) -> None:
    """FP-bait: the same shape, but the host is unbracketed before isIP() -- safe."""
    (tmp_path / "url_guard.ts").write_text(
        "function isSafeUrl(raw: string): boolean {\n"
        "  let host = new URL(raw).hostname;\n"
        "  host = host.replace(/^\\[|\\]$/g, '');\n"
        "  if (net.isIP(host)) {\n"
        "    if (host === '::1') return false;\n"
        "    return true;\n"
        "  }\n"
        "  return true;\n"
        "}\n\n"
        "if (isSafeUrl(target)) {\n"
        "  fetch(target);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = SsrfBracketedIpv6BypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_fetch_call_is_safe(tmp_path: Path) -> None:
    """FP-bait: the classification shape exists, but no outbound fetch in this file --
    this isn't a guard-for-something, just incidental URL parsing."""
    (tmp_path / "url_guard.ts").write_text(
        "function isSafeUrl(raw: string): boolean {\n"
        "  const host = new URL(raw).hostname;\n"
        "  return net.isIP(host) === 0;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = SsrfBracketedIpv6BypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_guard_context_is_safe(tmp_path: Path) -> None:
    """FP-bait: hostname + isIP + fetch, but nothing reads like an SSRF guard at all --
    e.g. plain diagnostic logging."""
    (tmp_path / "logger.ts").write_text(
        "const host = new URL(target).hostname;\n"
        "console.log(net.isIP(host));\n"
        "fetch(target);\n",
        encoding="utf-8",
    )
    findings = SsrfBracketedIpv6BypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_python_equivalent_shape_is_not_flagged(tmp_path: Path) -> None:
    """FP-bait: Python's urlsplit().hostname strips brackets, so the same shape there
    is not vulnerable -- and this guard is JS/TS-only by scope anyway (.py isn't scanned)."""
    (tmp_path / "url_guard.py").write_text(
        "from urllib.parse import urlsplit\n"
        "import ipaddress\n\n"
        "def is_safe_url(raw):\n"
        "    host = urlsplit(raw).hostname\n"
        "    if ipaddress.ip_address(host).is_loopback:\n"
        "        return False\n"
        "    return True\n",
        encoding="utf-8",
    )
    findings = SsrfBracketedIpv6BypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "url_guard.ts").write_text(
        "// security: allow-ssrf-bracketed-ipv6-bypass\n"
        "function isSafeUrl(raw: string): boolean {\n"
        "  const host = new URL(raw).hostname;\n"
        "  if (net.isIP(host)) { return true; }\n"
        "  return true;\n"
        "}\n"
        "fetch(target);\n",
        encoding="utf-8",
    )
    findings = SsrfBracketedIpv6BypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# --------------------------------------------------------------------------- PR #963 review round
def _guard_src(tail: str, *, header: str = "function isSafeUrl(raw: string): boolean {") -> str:
    return (
        f"{header}\n"
        "  const host = new URL(raw).hostname;\n"
        "  if (net.isIP(host)) {\n"
        "    if (host === '::1') return false;\n"
        "    return true;\n"
        "  }\n"
        f"  {tail}\n"
        "}\n\n"
        "if (isSafeUrl(target)) {\n"
        "  fetch(target);\n"
        "}\n"
    )


def _run(tmp_path: Path, src: str, name: str = "url_guard.ts") -> list[str]:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return [f.location for f in SsrfBracketedIpv6BypassGuard().run(tmp_path, _prof(tmp_path))]


def test_default_deny_tail_is_not_reported(tmp_path: Path) -> None:
    """The review's repro: the fires-fixture with its last `return true;` replaced by a lookup.
    Bracketed `[::1]` reaches `isAllowedDomain` and is refused; nothing falls through to allow."""
    assert _run(tmp_path, _guard_src("return isAllowedDomain(host);")) == []


def test_default_deny_literal_false_tail_is_not_reported(tmp_path: Path) -> None:
    assert _run(tmp_path, _guard_src("return false;")) == []


def test_literal_true_tail_still_fires_and_carries_the_line(tmp_path: Path) -> None:
    assert _run(tmp_path, _guard_src("return true;")) == ["url_guard.ts:3"]


def test_arrow_function_with_a_true_tail_still_fires(tmp_path: Path) -> None:
    src = _guard_src("return true;", header="const isSafeUrl = (raw: string): boolean => {")
    assert _run(tmp_path, src) == ["url_guard.ts:3"]


def test_blocking_predicate_returning_false_at_the_tail_still_fires(tmp_path: Path) -> None:
    """`isBlockedHost` returning false means "not blocked": the same fall-through-to-allow."""
    src = (
        "const blocklist = ['::1'];\n"
        "function isBlockedHost(raw: string): boolean {\n"
        "  const host = new URL(raw).hostname;\n"
        "  if (net.isIP(host)) {\n"
        "    return host === '::1';\n"
        "  }\n"
        "  return false;\n"
        "}\n\n"
        "if (!isBlockedHost(target)) {\n"
        "  fetch(target);\n"
        "}\n"
    )
    assert _run(tmp_path, src) == ["url_guard.ts:4"]


def test_unlocatable_tail_still_fires(tmp_path: Path) -> None:
    """An arrow expression body has no braces to inspect: keep the pre-existing behaviour."""
    src = (
        "const isSafeUrl = (raw: string) => !net.isIP(new URL(raw).hostname);\n"
        "if (isSafeUrl(target)) { fetch(target); }\n"
    )
    assert _run(tmp_path, src) == ["url_guard.ts:1"]


def test_line_survives_a_block_comment_above(tmp_path: Path) -> None:
    """Comment stripping keeps newlines, so the reported line is the real one."""
    src = "/* one\n   two\n   three */\n" + _guard_src("return true;")
    assert _run(tmp_path, src) == ["url_guard.ts:6"]


def test_applies_only_to_js_ts_repos(tmp_path: Path) -> None:
    g = SsrfBracketedIpv6BypassGuard()
    assert g.applies(mkprofile(tmp_path, features={"python"}, python_dirs=["."])) is False
    assert g.applies(mkprofile(tmp_path, features={"go"}, python_dirs=["."])) is False
    assert g.applies(mkprofile(tmp_path, features={"typescript"}, python_dirs=["."])) is True
    assert g.applies(mkprofile(tmp_path, features={"javascript"}, python_dirs=["."])) is True


def test_ssrf_bracketed_ipv6_bypass_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the js comment view, so a string literal quoting
    # the pragma is content. Only a real `//` comment (`test_pragma_suppresses_finding`) opts out.
    src = 'const help = "opt out with // security: allow-ssrf-bracketed-ipv6-bypass";\n' + _guard_src(
        "return true;"
    )
    assert _run(tmp_path, src) == ["url_guard.ts:4"]
