from __future__ import annotations

import json

from agentsec.detect import detect
from agentsec.guards.dependency_version_floor import (
    _DOCKER_TAG_EXACT,
    _FLOORS_PATH,
    DependencyVersionFloorGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_version_floor_flags_old_pin(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi\nlangchain-core==0.3.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/below-patched-version"
    assert findings[0].severity == "critical" and "CVE-2025-68664" in findings[0].title

def test_version_floor_passes_patched_pin(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain-core==0.3.81\nlangchain==1.3.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_pydantic_ai(tmp_path: Path) -> None:
    # pydantic-ai SSRF (CVE-2026-25580, incomplete-fix bypass CVE-2026-46678), fixed 1.99.0
    (tmp_path / "requirements.txt").write_text("pydantic-ai==1.98.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/below-patched-version"
    assert findings[0].severity == "high" and "CVE-2026-25580" in findings[0].title

def test_version_floor_passes_patched_pydantic_ai(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pydantic-ai==1.99.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_respects_backport_line(tmp_path: Path) -> None:
    # starlette fixed in 0.46.2 (0.x line) and 1.0.1; 0.46.2 is patched, 0.46.1 is not.
    # starlette ALSO carries a second, independent floor entry (CVE-2026-54283, the
    # request.form() DoS, fixed only at 1.3.1 -- not backported to 0.x/1.0.x), so both
    # pins below 1.3.1 additionally trip that entry; filter to the BadHost CVE to isolate
    # the backport-line behavior this test targets.
    (tmp_path / "a.txt").write_text("starlette==0.46.2\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("starlette==0.46.1\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    badhost = [f for f in findings if "CVE-2026-48710" in f.title]
    assert len(badhost) == 1 and "0.46.1" in badhost[0].title

def test_version_floor_flags_starlette_dos_across_both_lines(tmp_path: Path) -> None:
    # CVE-2026-54283 (request.form() urlencoded DoS) is fixed only at 1.3.1 -- no backport to
    # the 0.x or 1.0.x lines -- so a pin patched against BadHost (1.0.1) is still vulnerable here.
    (tmp_path / "requirements.txt").write_text("starlette==1.0.1\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    dos = [f for f in findings if "CVE-2026-54283" in f.title]
    assert len(dos) == 1 and "1.0.1" in dos[0].title
    assert not any("CVE-2026-48710" in f.title for f in findings)  # BadHost itself is patched here

def test_version_floor_passes_patched_starlette_dos(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("starlette==1.3.1\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_langflow(tmp_path: Path) -> None:
    # Floor set at 1.10.1 to close three independent unauth-RCEs in one upgrade: CVE-2025-3248
    # (missing auth, fixed 1.3.0, CISA KEV since May 2025, JADEPUFFER's initial-access vector),
    # CVE-2026-33017 (exec() sink via the public flow-build endpoint, fixed 1.9.0), and
    # CVE-2026-9198 (auto_login superuser-token mint chained into validate/code exec(), CVSS 9.8,
    # CISA KEV since 2026-08-04, actively exploited, fixed 1.10.1). The primary `cve` is
    # CVE-2026-9198, the one whose OWN fix version == fixed_in (1.10.1), so the generated
    # "vulnerable to {cve}; patched in {fixed}" message stays truthful (#338 review).
    # KEV stamping still fires because CVE-2025-3248 is in the `name` prose and kev.py:stamp_kev
    # scans the whole message text, not just the structured `cve` field.
    (tmp_path / "requirements.txt").write_text("langflow==1.8.2\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/below-patched-version"
    assert findings[0].severity == "critical"
    assert "CVE-2026-9198" in findings[0].title       # primary CVE == the fix-matching one
    assert "CVE-2025-3248" in findings[0].message      # KEV context preserved in name prose
    assert "CVE-2026-33017" in findings[0].message     # 2nd co-fixed CVE also preserved

def test_version_floor_langflow_message_self_consistent_in_gap(tmp_path: Path) -> None:
    # #338 review (Major): a pin in the 1.3.0-1.9.0 gap is already patched against CVE-2025-3248
    # (fixed 1.3.0) and CVE-2026-33017 (fixed 1.9.0) yet still vulnerable to CVE-2026-9198 (fixed
    # 1.10.1). The cited CVE must be the operative one, and the message must NOT claim the pin is
    # "vulnerable to CVE-2025-3248 ... patched in 1.10.1" -- the self-contradiction an earlier-
    # fixed CVE as the cited primary would produce.
    (tmp_path / "requirements.txt").write_text("langflow==1.9.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    msg = findings[0].message
    assert "vulnerable to CVE-2026-9198; patched in 1.10.1" in msg
    assert "vulnerable to CVE-2025-3248" not in msg
    assert "vulnerable to CVE-2026-33017" not in msg
    assert findings[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2026-9198"

def test_version_floor_passes_patched_langflow(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langflow==1.10.1\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_ignores_open_range(tmp_path: Path) -> None:
    # not an exact pin -> ambiguous, not flagged
    (tmp_path / "requirements.txt").write_text("langchain-core>=0.3.0\nstarlette~=0.46.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "langchain-core==0.3.0  # security: allow-old-langchain-core\n", encoding="utf-8"
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_npm_exact_pin(tmp_path: Path) -> None:
    # npm floors only fire on an exact (non-range) version; none seeded -> no finding here,
    # but the applies() gate covers frontend, and a substring package must not false-match
    (tmp_path / "requirements.txt").write_text("langchain-corex==0.1.0\n", encoding="utf-8")  # not langchain-core
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []
    assert DependencyVersionFloorGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is True

def test_version_floor_flags_poetry_lock(tmp_path: Path) -> None:
    # the v2 lockfile path: a resolved version below the floor (even from an open range)
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "langchain-core"\nversion = "0.3.0"\n'
        'description = "x"\n\n[[package]]\nname = "other"\nversion = "1.0.0"\n', encoding="utf-8"
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1 and "CVE-2025-68664" in findings[0].title

def test_version_floor_poetry_lock_patched_passes(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "langchain-core"\nversion = "0.3.81"\n', encoding="utf-8"
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []



# ── Folded from #226 (dependency-version-floors) — upper-bound tier + TOML parsing ──

def test_version_floor_upper_bound_compound_range_fires(tmp_path: Path) -> None:
    # A compound `>=a,<floor` cannot reach the patched floor -> HIGH (the blocking half is caught).
    (tmp_path / "requirements.txt").write_text("langchain-core>=0.3.0,<0.3.81\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/upper-bound-below-floor"
    assert findings[0].severity == "high"


def test_version_floor_sole_upper_bound_fires(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("starlette<0.40\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "dependency-version-floor/upper-bound-below-floor" for f in findings)


def test_version_floor_upper_bound_reaching_floor_silent(tmp_path: Path) -> None:
    # `<0.4.0` CAN resolve to the patched 0.3.81 -> ambiguous -> not flagged (conservative).
    (tmp_path / "requirements.txt").write_text("langchain-core<0.4.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_version_floor_bare_name_not_flagged(tmp_path: Path) -> None:
    # A bare (unpinned) listing resolves to the latest (patched) version -> no FP.
    (tmp_path / "requirements.txt").write_text("langchain-core\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_version_floor_pep621_exact_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["langchain-core==0.3.0"]\n', encoding="utf-8"
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "dependency-version-floor/below-patched-version" for f in findings)


def test_version_floor_poetry_exact_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\nlangchain-core = "==0.3.0"\n', encoding="utf-8"
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "dependency-version-floor/below-patched-version" for f in findings)


def test_version_floor_toml_comment_mention_not_flagged(tmp_path: Path) -> None:
    # A floor package named only in a trailing comment (different constraint) must not fire.
    # Pinned to a patched uvicorn (uvicorn gained its own floor, fixed 0.11.7) so this line's
    # own pin can't fire on its own account — only the comment-parsing behavior is under test.
    (tmp_path / "requirements.txt").write_text("uvicorn==1.0.0  # pairs with langchain-core\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []


# ── MCP SDK/ecosystem CVE floors ────────────────────────────────────

def _frontend_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"frontend", "python"}, python_dirs=["."], frontend_dir=".")


def test_version_floor_flags_old_mcp_python_sdk(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp==1.5.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    # Title carries the entry's current primary CVE (CVE-2026-59950, whose own fix == fixed_in);
    # the earlier co-fixed CVEs (CVE-2025-53366, CVE-2025-66416, CVE-2026-52869, CVE-2026-52870)
    # are named in the finding's `name`/message text, not the title -- see the still-fires
    # intermediate-range test below.
    assert findings[0].severity == "high" and "CVE-2026-59950" in findings[0].title


def test_version_floor_flags_old_litellm(tmp_path: Path) -> None:
    # litellm==1.70.0 is below BOTH the CVE-2026-30623 floor (1.83.7, MCP stdio command
    # injection) and the CVE-2026-59822 floor (1.84.0, MCP OAuth2 passthrough auth bypass,
    # added 2026-09-26) -- two distinct defects on the same package, each its own
    # finding (the supply-chain 1.82.7-1.83.0 `affected_from` entry does not apply here,
    # since 1.70.0 predates that affected range entirely).
    (tmp_path / "requirements.txt").write_text("litellm==1.70.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 2
    titles = " ".join(f.title for f in findings)
    assert "CVE-2026-30623" in titles and "CVE-2026-59822" in titles
    assert all(f.severity in ("critical", "high") for f in findings)


def test_version_floor_flags_old_mcp_server_git(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-server-git==2025.6.1\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1 and findings[0].severity == "critical"
    assert "CVE-2025-68145" in findings[0].title


def test_version_floor_flags_mcp_in_intermediate_range(tmp_path: Path) -> None:
    # `mcp` collapses five CVEs (CVE-2025-53366 @1.9.4, CVE-2025-66416 @1.23.0,
    # CVE-2026-52869/52870 @1.27.2, CVE-2026-59950 @1.28.1) into one floor at 1.28.1. A user
    # above the earliest fixes but below the current floor is still vulnerable to the DNS-rebind
    # CVE -- named in the message (from the entry's `name` field), while the title carries only
    # the entry's current primary CVE.
    (tmp_path / "requirements.txt").write_text("mcp==1.15.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert "CVE-2026-59950" in findings[0].title
    assert "CVE-2025-66416" in findings[0].message


def test_version_floor_flags_mcp_below_session_hijack_fix(tmp_path: Path) -> None:
    # `mcp` bumped 1.23.0 -> 1.27.2 for CVE-2026-52869 (SSE/Streamable-HTTP session
    # hijack — no check that a request's OAuth client ID/token issuer/subject matches the
    # session's creator). A pin in the newly-vulnerable 1.23.0-1.27.1 band — previously reported
    # "patched" under the old floor — must now fire on the new, higher-severity-relevant CVE.
    (tmp_path / "requirements.txt").write_text("mcp==1.25.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high" and "CVE-2026-59950" in findings[0].title
    assert "CVE-2026-52869" in findings[0].message


def test_version_floor_flags_mcp_below_websocket_dns_rebind_fix(tmp_path: Path) -> None:
    # (round-3 MCP research): `mcp` bumped 1.27.2 -> 1.28.1 for CVE-2026-59950 -- the
    # deprecated WebSocket transport shipped with NO Host/Origin validation at all, a second,
    # distinct DNS-rebinding path from the HTTP/SSE one CVE-2025-66416 already covered. A pin at
    # exactly the previous floor (1.27.2) — previously reported "patched" — must now fire on
    # this newly-added, higher CVE.
    (tmp_path / "requirements.txt").write_text("mcp==1.27.2\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high" and "CVE-2026-59950" in findings[0].title


def test_version_floor_flags_old_fastmcp_oauth_proxy(tmp_path: Path) -> None:
    # FastMCP (jlowin/fastmcp)'s OAuth Proxy issued tokens bound to its own base_url
    # instead of the client's requested RFC 8707 `resource` parameter, so a token obtained via
    # one MCP server behind the proxy was accepted by every other server behind it.
    (tmp_path / "requirements.txt").write_text("fastmcp==2.10.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high" and "CVE-2025-69196" in findings[0].title


def test_version_floor_flags_old_mcp_scoped_npm_package(tmp_path: Path) -> None:
    # scoped package names (@scope/name) must match as a literal dependency key
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "1.20.0"}}', encoding="utf-8"
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 1 and "CVE-2026-25536" in findings[0].title


def test_version_floor_flags_old_mcp_inspector_and_filesystem(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {'
        '"@modelcontextprotocol/inspector": "0.10.0", '
        '"@modelcontextprotocol/server-filesystem": "2025.6.0", '
        '"@cyanheads/git-mcp-server": "2.0.0"'
        '}}', encoding="utf-8"
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 3
    titles = " ".join(f.title for f in findings)
    assert "CVE-2025-49596" in titles and "CVE-2025-53109" in titles and "CVE-2025-53107" in titles


def test_version_floor_mcp_packages_patched_pass(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {'
        '"@modelcontextprotocol/sdk": "1.26.0", '
        '"@modelcontextprotocol/inspector": "0.14.1", '
        '"@modelcontextprotocol/server-filesystem": "2025.7.1", '
        '"@cyanheads/git-mcp-server": "2.1.5"'
        '}}', encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text(
        "mcp==1.28.1\nmcp-server-git==2025.12.18\nlitellm==1.84.0\nfastmcp==2.14.2\n", encoding="utf-8"
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_version_floor_filesystem_patched_on_0x_line_passes(tmp_path: Path) -> None:
    # CVE-2025-53109 was patched on BOTH release lines — 0.6.4 (0.x backport) and 2025.7.1.
    # A user pinned to the 0.x patch must NOT be flagged (regression for the #299 review FP:
    # fixed_in previously listed only 2025.7.1, so 0.6.4 users got a false positive).
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/server-filesystem": "0.6.4"}}', encoding="utf-8"
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_version_floor_flags_filesystem_below_0x_patch(tmp_path: Path) -> None:
    # The multi-line fix must not over-suppress: a truly-vulnerable 0.x version still fires.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/server-filesystem": "0.6.3"}}', encoding="utf-8"
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 1 and "CVE-2025-53109" in findings[0].title


def test_version_floor_mcp_package_name_not_confused_with_similar(tmp_path: Path) -> None:
    # a differently-named/scoped package must not false-match the "mcp" or scoped floors.
    # `fastmcp` is itself a real floor package as of (CVE-2025-69196), so it's pinned
    # patched here — this test's own point is that "mcp-pypi" doesn't false-match "mcp"'s floor,
    # not that fastmcp is unmonitored (that direction has its own test above).
    (tmp_path / "requirements.txt").write_text("mcp-pypi==0.1.0\nfastmcp==2.14.2\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@othermcp/sdk": "0.1.0", "modelcontextprotocol-sdk": "0.1.0"}}', encoding="utf-8"
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


# --- B28: PEP 440 pre-release ordering ----------------------------------------------------------

def test_version_parses_pep440_prerelease_ordering() -> None:
    # `_version` was `re.search(r"\d+(?:\.\d+)*")`, so every pre-release marker was DROPPED:
    # `2.0.0b3` and `2.0.0b2` both parsed to `(2, 0, 0)`. That made a prerelease unusable as a floor
    # at all, not just for one advisory (#492 review, B28).
    from agentsec.guards.dependency_version_floor import _version

    ordered = [
        "1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0b2", "1.0rc1", "1.0", "1.0.post1",
        "1.0.1", "1.99.0", "1.102.0", "2.0.0b2", "2.0.0b3", "2.0.0",
    ]
    parsed = [_version(s) for s in ordered]
    assert all(p is not None for p in parsed)
    for lo, hi, lo_s, hi_s in zip(parsed, parsed[1:], ordered, ordered[1:], strict=False):
        assert lo < hi, f"{lo_s} should sort below {hi_s}"


def test_version_prerelease_spellings_and_separators() -> None:
    from agentsec.guards.dependency_version_floor import _version

    # `alpha`/`beta`/`c`/`preview` are PEP 440 spellings of a/b/rc, and `.`/`-`/`_` are all legal
    # separators. The alternation is longest-first so `rc` is not shadowed by `c`.
    assert _version("1.0alpha1") == _version("1.0a1")
    assert _version("1.0beta2") == _version("1.0b2")
    assert _version("1.0-rc.1") == _version("1.0rc1")
    assert _version("1.0c1") == _version("1.0rc1")
    assert _version("1.0b") == _version("1.0b0")          # bare marker means 0


def test_prerelease_floor_flags_an_earlier_prerelease_pin() -> None:
    # THE B28 FALSE NEGATIVE. With a `2.0.0b3` floor, a project pinned `2.0.0b2` compared
    # `>= max(fixed_in)` and was reported PATCHED — a false negative on exactly the pin a prerelease
    # floor exists to catch.
    from agentsec.guards.dependency_version_floor import _version, _vulnerable

    floor = [v for v in [_version("2.0.0b3")] if v]
    assert _vulnerable(_version("2.0.0b2"), floor) is True     # was False before the fix
    assert _vulnerable(_version("2.0.0b3"), floor) is False
    assert _vulnerable(_version("2.0.0"), floor) is False      # the final release is above its own b3
    assert _vulnerable(_version("2.0.0rc1"), floor) is False   # rc sorts above b


def test_prerelease_floor_with_a_backport_line() -> None:
    # The realistic shape the pydantic-ai advisory would use: fixed on both the 1.x line and a 2.0
    # prerelease. Each line is judged on its own fix.
    from agentsec.guards.dependency_version_floor import _version, _vulnerable

    floor = [v for v in (_version("1.102.0"), _version("2.0.0b3")) if v]
    assert _vulnerable(_version("1.101.9"), floor) is True
    assert _vulnerable(_version("1.102.0"), floor) is False
    assert _vulnerable(_version("2.0.0b2"), floor) is True
    assert _vulnerable(_version("2.0.0b3"), floor) is False
    assert _vulnerable(_version("2.0.0"), floor) is False


def test_vulnerable_affected_from_lower_bound() -> None:
    # A CVE that only affects a range starting partway through the package's history (not every
    # version below fixed_in) must not flag a declared version that predates the range entirely.
    from agentsec.guards.dependency_version_floor import _version, _vulnerable

    fixed = [v for v in [_version("0.87.0")] if v]
    lower = _version("0.86.0")
    assert _vulnerable(_version("0.30.0"), fixed, lower) is False   # predates the affected range
    assert _vulnerable(_version("0.86.0"), fixed, lower) is True    # start of the affected range
    assert _vulnerable(_version("0.86.5"), fixed, lower) is True    # inside the affected range
    assert _vulnerable(_version("0.87.0"), fixed, lower) is False   # patched
    # No affected_from given (the default, and every pre-existing floor entry): unchanged
    # behavior — every version below fixed_in is vulnerable, including one this far below.
    assert _vulnerable(_version("0.30.0"), fixed) is True


def test_upper_bound_unreachable_respects_affected_from() -> None:
    # An upper-bound pin that already caps the resolver below the affected range's own start was
    # never able to install a vulnerable version — the guard's HIGH "capped below the fix" signal
    # should not fire for that case, only for a genuine "capped below the fix, but reaches into
    # the affected range" pin.
    from agentsec.guards.dependency_version_floor import _upper_bound_unreachable, _version

    fixed = [v for v in [_version("0.87.0")] if v]
    lower = _version("0.86.0")
    assert _upper_bound_unreachable([("<", "0.50.0")], fixed, lower) is False  # never reaches it
    assert _upper_bound_unreachable([("<", "0.86.5")], fixed, lower) is True   # reaches, capped
    assert _upper_bound_unreachable([("<", "0.50.0")], fixed) is True          # no affected_from: unchanged


def test_upper_bound_unreachable_le_operator_at_affected_from_boundary() -> None:
    # Real bug found by review (fix-commit round): `<X` cannot install X itself, so `<=affected_from`
    # is safe, but `<=X` CAN install X, so `<=affected_from` is NOT safe -- it reaches the first
    # vulnerable release. Sharing one condition for both operators let `anthropic<=0.86.0` go
    # unflagged even though it can install 0.86.0, the affected range's own start.
    from agentsec.guards.dependency_version_floor import _upper_bound_unreachable, _version

    fixed = [v for v in [_version("0.87.0")] if v]
    lower = _version("0.86.0")
    assert _upper_bound_unreachable([("<", "0.86.0")], fixed, lower) is False    # cannot install 0.86.0: safe
    assert _upper_bound_unreachable([("<=", "0.86.0")], fixed, lower) is True    # CAN install 0.86.0: unreachable-below-fix
    assert _upper_bound_unreachable([("<", "0.87")], fixed, lower) is True       # reaches into affected range
    assert _upper_bound_unreachable([("<=", "0.87.0")], fixed, lower) is False   # reaches the fix itself: safe


def test_spec_regex_keeps_the_prerelease_marker() -> None:
    # The marker was dropped a SECOND time, independently of `_version`: `_SPEC_RE`'s version group
    # was a bare release tuple, so an upper bound of `<2.0.0b3` captured only `2.0.0` (#492 review).
    from agentsec.guards.dependency_version_floor import _SPEC_RE

    assert _SPEC_RE.findall("<2.0.0b3") == [("<", "2.0.0b3")]
    assert _SPEC_RE.findall(">=1.99.0,<2.0.0b3") == [(">=", "1.99.0"), ("<", "2.0.0b3")]
    assert _SPEC_RE.findall("==2.0.0b2") == [("==", "2.0.0b2")]
    assert _SPEC_RE.findall("<=1.102.0") == [("<=", "1.102.0")]


def test_existing_final_release_floors_are_unchanged(tmp_path: Path) -> None:
    # The other direction (F4): adding a phase dimension must not move any verdict on the
    # final-release floors that are actually shipped. The live pydantic-ai floor is 1.99.0.
    from agentsec.guards.dependency_version_floor import _version, _vulnerable

    live = [v for v in [_version("1.99.0")] if v]
    assert _vulnerable(_version("1.56.0"), live) is True
    assert _vulnerable(_version("1.98.9"), live) is True
    assert _vulnerable(_version("1.99.0"), live) is False
    assert _vulnerable(_version("1.102.0"), live) is False
    # ...and end-to-end through the real floor table.
    (tmp_path / "requirements.txt").write_text("pydantic-ai==1.99.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []


# pyjwt carries three floor entries, one per fix version (the starlette shape): CVE-2026-48526
# (public-key JWK as HMAC secret, high, fixed 2.13.0), CVE-2026-102268 (#988: a mutated PEM public
# key skips the HMAC-confusion guard, HS256 forgery, critical, fixed 2.14.0) and CVE-2026-101918
# (an unauthenticated RecursionError DoS, medium, fixed 2.15.0, affected from 2.0.0a1). The 2.15.0
# entry also names CVE-2026-102275 (OKP x/d identity confusion, affected only from 2.1.0), but it
# cites CVE-2026-101918 because that range is the wider one: the finding says "the pinned version
# is vulnerable to <cve>", which must hold for every pin the entry fires on (#1054 R1-M1).
def _pyjwt_cves(tmp_path: Path, manifest: str) -> dict[str, str]:
    (tmp_path / "requirements.txt").write_text(manifest, encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert all(f.rule == "dependency-version-floor/below-patched-version" for f in findings)
    by_cve = {f.title.rsplit("(", 1)[1].rstrip(")"): f.severity for f in findings}
    assert len(by_cve) == len(findings)  # one finding per entry, no duplicate CVE
    return by_cve

def test_version_floor_flags_old_pyjwt(tmp_path: Path) -> None:
    # Below all three floors, so the original CVE-2026-48526 detection still fires next to the new ones.
    assert _pyjwt_cves(tmp_path, "pyjwt==2.12.1\n") == {
        "CVE-2026-48526": "high", "CVE-2026-102268": "critical", "CVE-2026-101918": "medium",
    }

def test_version_floor_flags_pyjwt_2_13_hs256_forgery(tmp_path: Path) -> None:
    # #988, the reported miss: 2.13.0 passed clean although it is exposed to the critical HS256
    # forgery (GHSA-ffc3-869f-jxw9), which sat in PyJWT's repository advisories for 18 days
    # before GitHub's global advisory database carried it.
    assert _pyjwt_cves(tmp_path, "pyjwt==2.13.0\n") == {
        "CVE-2026-102268": "critical", "CVE-2026-101918": "medium",
    }
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    critical = next(f for f in findings if f.severity == "critical")
    assert "patched in 2.14.0" in critical.message

def test_version_floor_flags_pyjwt_2_14_only_the_medium(tmp_path: Path) -> None:
    # 2.14.0 fixes the critical; only the two 2.15.0 mediums (42vr, x33g) remain.
    assert _pyjwt_cves(tmp_path, "pyjwt==2.14.0\n") == {"CVE-2026-101918": "medium"}
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert "patched in 2.15.0" in findings[0].message

def test_version_floor_passes_patched_pyjwt(tmp_path: Path) -> None:
    # The FP-bait for the #988 widening (Rule 1): the first fixed release and the latest stay silent.
    assert _pyjwt_cves(tmp_path, "pyjwt==2.15.0\n") == {}
    assert _pyjwt_cves(tmp_path, "pyjwt==2.15.1\n") == {}

def test_version_floor_pyjwt_2_15_floor_covers_the_2_0_line(tmp_path: Path) -> None:
    # #1054 R1-M1: with affected_from 2.1.0 (the OKP CVE's bound) a 2.0.x pin got no 2.15.0 finding,
    # although CVE-2026-101918, which the same entry names, affects it. Both pin spellings of the
    # first 2.x release fire: the bound is written "2.0a1" (PEP 440-equal to the advisory's 2.0.0a1)
    # because `_version` does not pad release tuples, so "2.0.0a1" would sort above `pyjwt==2.0`.
    for pin in ("2.0", "2.0.0", "2.0.1"):
        assert _pyjwt_cves(tmp_path, f"pyjwt=={pin}\n") == {
            "CVE-2026-48526": "high", "CVE-2026-102268": "critical", "CVE-2026-101918": "medium",
        }, pin

def test_version_floor_pyjwt_2_15_floor_respects_affected_from(tmp_path: Path) -> None:
    # The direction traded against: neither 2.15.0 CVE reaches the 1.x line, so a 1.x pin is not
    # told it is exposed to one, while the two floors with no lower bound still fire.
    assert _pyjwt_cves(tmp_path, "pyjwt==1.7.1\n") == {
        "CVE-2026-48526": "high", "CVE-2026-102268": "critical",
    }

def test_version_floor_pyjwt_pragma_silences_every_entry(tmp_path: Path) -> None:
    # Rule 4: the per-package opt-out the user wrote must reach the new entries too.
    assert _pyjwt_cves(tmp_path, "pyjwt==2.13.0  # security: allow-old-pyjwt\n") == {}

def test_version_floor_flags_old_python_jose(tmp_path: Path) -> None:
    # python-jose algorithm confusion with OpenSSH ECDSA keys (CVE-2024-33663), fixed 3.4.0
    (tmp_path / "requirements.txt").write_text("python-jose==3.3.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "critical" and "CVE-2024-33663" in findings[0].title

def test_version_floor_passes_patched_python_jose(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("python-jose==3.4.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_sqlalchemy(tmp_path: Path) -> None:
    # SQL injection via order_by/group_by (CVE-2019-7164), fixed 1.3.0
    (tmp_path / "requirements.txt").write_text("sqlalchemy==1.2.18\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "critical" and "CVE-2019-7164" in findings[0].title

def test_version_floor_passes_patched_sqlalchemy(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("sqlalchemy==1.3.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_uvicorn(tmp_path: Path) -> None:
    # HTTP response splitting + log injection (CVE-2020-7695), fixed 0.11.7
    (tmp_path / "requirements.txt").write_text("uvicorn==0.11.6\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high" and "CVE-2020-7695" in findings[0].title

def test_version_floor_passes_patched_uvicorn(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("uvicorn==0.11.7\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_httpx(tmp_path: Path) -> None:
    # Improper input validation (CVE-2021-41945), fixed 0.23.0
    (tmp_path / "requirements.txt").write_text("httpx==0.22.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "critical" and "CVE-2021-41945" in findings[0].title

def test_version_floor_passes_patched_httpx(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("httpx==0.23.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_fastapi(tmp_path: Path) -> None:
    # CSRF (CVE-2021-32677), fixed 0.65.2
    (tmp_path / "requirements.txt").write_text("fastapi==0.65.1\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high" and "CVE-2021-32677" in findings[0].title

def test_version_floor_passes_patched_fastapi(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi==0.65.2\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_llama_index(tmp_path: Path) -> None:
    # Insecure temporary file (CVE-2025-7707), fixed 0.13.0
    (tmp_path / "requirements.txt").write_text("llama-index==0.12.99\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high" and "CVE-2025-7707" in findings[0].title

def test_version_floor_passes_patched_llama_index(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("llama-index==0.13.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_langsmith(tmp_path: Path) -> None:
    # TracingMiddleware arbitrary server-side file read (no CVE assigned, GHSA-f4xh-w4cj-qxq8), fixed 0.8.18
    (tmp_path / "requirements.txt").write_text("langsmith==0.8.17\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high" and "GHSA-f4xh-w4cj-qxq8" in findings[0].title

def test_version_floor_passes_patched_langsmith(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langsmith==0.8.18\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_anthropic(tmp_path: Path) -> None:
    # Memory-tool path validation race condition, sandbox escape (CVE-2026-34452), fixed 0.87.0
    (tmp_path / "requirements.txt").write_text("anthropic==0.86.5\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "medium" and "CVE-2026-34452" in findings[0].title

def test_version_floor_passes_patched_anthropic(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("anthropic==0.87.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_anthropic_predates_affected_range_silent(tmp_path: Path) -> None:
    # Real FP found by review: CVE-2026-34452 (GHSA-w828-4qhx-vxx3) affects only the 0.86.x
    # line, not every anthropic release below the 0.87.0 fix. Without a lower bound, a common
    # real-world pin like 0.30.0 (which predates the affected range entirely) was reported
    # vulnerable to a sandbox-escape CVE it was never exposed to.
    (tmp_path / "requirements.txt").write_text("anthropic==0.30.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_anthropic_still_flags_within_affected_range(tmp_path: Path) -> None:
    # Narrowing-still-fires control for the fix above: 0.86.0 itself (the start of the affected
    # range) must still fire — the lower bound must not swallow the genuinely vulnerable case.
    (tmp_path / "requirements.txt").write_text("anthropic==0.86.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "medium" and "CVE-2026-34452" in findings[0].title

# --- NotebookLM sweep Tier 0 batch (NS-*): one planted-violation + FP-bait pair per new floor.
# Added in review of #740: four of the six new entries shipped without a dedicated pair, which
# left no regression net against a future typo in the package name, ecosystem or fixed_in list.

def test_version_floor_flags_old_ormar(tmp_path: Path) -> None:
    # ormar model-constructor Pydantic validation bypass -- `__pk_only__`/`__excluded__` kwarg
    # injection skips field validation before persist (CVE-2026-27953), fixed 0.23.1
    (tmp_path / "requirements.txt").write_text("ormar==0.23.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/below-patched-version"
    assert findings[0].severity == "high" and "CVE-2026-27953" in findings[0].title

def test_version_floor_passes_patched_ormar(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("ormar==0.23.1\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_mlflow(tmp_path: Path) -> None:
    # mlflow permission middleware only guards /gateway/, leaving the Job API and OTel trace
    # ingestion unauthenticated (CVE-2026-2652), fixed 3.10.0. The pin is 3.9.0 on purpose:
    # a naive string compare orders "3.9.0" ABOVE "3.10.0" and would read this as patched,
    # so this pair also pins PEP440 numeric-segment ordering for the batch.
    (tmp_path / "requirements.txt").write_text("mlflow==3.9.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/below-patched-version"
    assert findings[0].severity == "high" and "CVE-2026-2652" in findings[0].title

def test_version_floor_passes_patched_mlflow(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mlflow==3.10.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_flags_old_mastra_mcp_docs_server(tmp_path: Path) -> None:
    # Mastra Docs MCP Server directory-listing disclosure via the suggestion fallback
    # (CVE-2025-61685), fixed 0.17.0. Scoped npm name -- must match as a literal dep key.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@mastra/mcp-docs-server": "0.16.0"}}', encoding="utf-8"
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "medium" and "CVE-2025-61685" in findings[0].title

def test_version_floor_passes_patched_mastra_mcp_docs_server(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@mastra/mcp-docs-server": "0.17.0"}}', encoding="utf-8"
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []

def test_version_floor_flags_old_vite_on_every_backport_line(tmp_path: Path) -> None:
    # vite dev-server `fetchModule` RPC ignores the server.fs allow-list, so a `vite:invoke`
    # with a file:// path reads any host file (CVE-2026-39363). Fixed independently on THREE
    # lines -- 6.4.2, 7.3.2, 8.0.5 -- so a pin one patch below each must fire on its own line.
    for sub, pin in (("six", "6.4.1"), ("seven", "7.3.1"), ("eight", "8.0.4")):
        d = tmp_path / sub
        d.mkdir()
        (d / "package.json").write_text(
            f'{{"dependencies": {{"vite": "{pin}"}}}}', encoding="utf-8"
        )
    findings = DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 3, [f.location for f in findings]
    assert all("CVE-2026-39363" in f.title and f.severity == "high" for f in findings)

def test_version_floor_passes_patched_vite_on_every_backport_line(tmp_path: Path) -> None:
    # The FP-bait direction of the pair above: the first patched release on each line is silent.
    # 6.4.2 must NOT be reported vulnerable just because it is below the 8.0.5 top-line fix.
    for sub, pin in (("six", "6.4.2"), ("seven", "7.3.2"), ("eight", "8.0.5")):
        d = tmp_path / sub
        d.mkdir()
        (d / "package.json").write_text(
            f'{{"dependencies": {{"vite": "{pin}"}}}}', encoding="utf-8"
        )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


# --- 2026 supply-chain compromises (TeamPCP LiteLLM, Mini Shai-Hulud, Mastra) -------
# These are malicious-publish floors, not CVE-fixed-by-upgrade floors: `affected_from` brackets the
# malicious version(s) actually published, and `fixed_in` is the first confirmed-clean release the
# registry shows afterward (verified against the npm/PyPI registries directly, not just an advisory's
# prose). Each pair below tests both directions: predates-the-compromise stays silent AND the
# malicious pin still fires (and, where the package carries an older, unrelated floor too --
# litellm -- the two entries are isolated by id so one doesn't mask the other, mirroring the
# starlette dual-floor tests above).

def test_version_floor_flags_litellm_teampcp_compromise(tmp_path: Path) -> None:
    # TeamPCP PyPI supply-chain compromise (2026-03-24): litellm 1.82.7/1.82.8 were never
    # legitimate releases -- a credential-harvesting .pth file, not a code vulnerability.
    (tmp_path / "requirements.txt").write_text("litellm==1.82.8\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    ghsa = [f for f in findings if "GHSA-5mg7-485q-xm76" in f.title]
    assert len(ghsa) == 1 and ghsa[0].severity == "critical"

def test_version_floor_litellm_predates_teampcp_compromise_silent(tmp_path: Path) -> None:
    # 1.82.6 predates the compromised range entirely -- must not be flagged for the TeamPCP
    # incident (it still trips the older, unrelated CVE-2026-30623 floor, which this isolates past).
    (tmp_path / "requirements.txt").write_text("litellm==1.82.6\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any("GHSA-5mg7-485q-xm76" in f.title for f in findings)

def test_version_floor_passes_patched_litellm_teampcp_incident(tmp_path: Path) -> None:
    # 1.83.0 is the first confirmed-clean release from the rebuilt CI/CD pipeline after the
    # compromise (docs.litellm.ai). Still below the unrelated 1.83.7 command-injection floor,
    # so isolate to the TeamPCP GHSA to confirm THIS entry specifically is silent here.
    (tmp_path / "requirements.txt").write_text("litellm==1.83.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any("GHSA-5mg7-485q-xm76" in f.title for f in findings)


def test_version_floor_flags_tanstack_router_family_mini_shai_hulud(tmp_path: Path) -> None:
    # Mini Shai-Hulud (2026-05-11): a GitHub Actions pwn-request chain published self-propagating
    # credential-stealing malware as 1.169.5/1.169.8 across the whole @tanstack/*-router family.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {'
        '"@tanstack/react-router": "1.169.8", '
        '"@tanstack/router-core": "1.169.5", '
        '"@tanstack/vue-router": "1.169.8", '
        '"@tanstack/solid-router": "1.169.5"'
        '}}',
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 4
    assert all("CVE-2026-45321" in f.title and f.severity == "critical" for f in findings)

def test_version_floor_tanstack_router_predates_mini_shai_hulud_silent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@tanstack/react-router": "1.169.2"}}', encoding="utf-8"
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []

def test_version_floor_passes_patched_tanstack_router(tmp_path: Path) -> None:
    # 1.169.9 is the first patched release per GHSA-g7cv-rxg3-hmpx's own advisory table.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {'
        '"@tanstack/react-router": "1.169.9", '
        '"@tanstack/router-core": "1.169.9", '
        '"@tanstack/vue-router": "1.169.9", '
        '"@tanstack/solid-router": "1.169.9"'
        '}}',
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_version_floor_flags_mistralai_pypi_dropper(tmp_path: Path) -> None:
    # Mini Shai-Hulud PyPI arm: mistralai 2.4.6 was published outside Mistral's Trusted-Publishing
    # workflow with a backdoor that downloads/executes a payload on import (incl. a geofenced
    # destructive branch).
    (tmp_path / "requirements.txt").write_text("mistralai==2.4.6\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "critical" and "GHSA-wx9m-wx4f-4cmg" in findings[0].title

def test_version_floor_mistralai_pypi_predates_compromise_silent(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mistralai==2.4.5\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_passes_patched_mistralai_pypi(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mistralai==2.5.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_version_floor_flags_mistralai_npm_broken_dropper(tmp_path: Path) -> None:
    # Same Mini Shai-Hulud campaign, npm SDKs: GitHub's own advisory rates this Low -- a filename
    # mismatch made the payload fail to execute -- but it is still a genuine unauthorized publish.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {'
        '"@mistralai/mistralai": "2.2.3", '
        '"@mistralai/mistralai-azure": "1.7.2", '
        '"@mistralai/mistralai-gcp": "1.7.3"'
        '}}',
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 3
    assert all("GHSA-jgg6-4rpr-wfh7" in f.title and f.severity == "low" for f in findings)

def test_version_floor_mistralai_npm_predates_compromise_silent(tmp_path: Path) -> None:
    # Below each entry's `affected_from` (mistralai 2.2.2, azure/gcp 1.7.1): pre-compromise
    # versions predate the malicious-publish range entirely and must stay silent.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {'
        '"@mistralai/mistralai": "2.2.1", '
        '"@mistralai/mistralai-azure": "1.7.0", '
        '"@mistralai/mistralai-gcp": "1.7.0"'
        '}}',
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []

def test_version_floor_passes_patched_mistralai_npm(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {'
        '"@mistralai/mistralai": "2.2.5", '
        '"@mistralai/mistralai-azure": "2.0.0", '
        '"@mistralai/mistralai-gcp": "2.0.0"'
        '}}',
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_version_floor_flags_guardrails_ai_dropper(tmp_path: Path) -> None:
    # Mini Shai-Hulud PyPI arm: guardrails-ai 0.10.1 shipped malicious code injected into
    # guardrails/__init__.py, detected and quarantined within ~2 hours.
    (tmp_path / "requirements.txt").write_text("guardrails-ai==0.10.1\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "critical" and "CVE-2026-45758" in findings[0].title

def test_version_floor_guardrails_ai_predates_incident_silent(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("guardrails-ai==0.10.0\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_version_floor_passes_patched_guardrails_ai(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("guardrails-ai==0.10.2\n", encoding="utf-8")
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_version_floor_flags_mastra_scope_takeover(tmp_path: Path) -> None:
    # Mastra npm scope takeover (2026-06-17): the hijacked ehindero account republished
    # @mastra/core and create-mastra depending on the easy-day-js dayjs typosquat (postinstall
    # crypto-wallet stealer + RAT), across ~140 @mastra/* packages in under 20 minutes.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@mastra/core": "1.42.1", "create-mastra": "1.13.1"}}',
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 2
    titles = " ".join(f.title for f in findings)
    assert "GHSA-pp62-grrw-hvfp" in titles and "GHSA-jgwq-x2m5-mxhm" in titles
    assert all(f.severity == "critical" for f in findings)

def test_version_floor_mastra_predates_scope_takeover_silent(tmp_path: Path) -> None:
    # Below each entry's `affected_from` (@mastra/core 1.42.1, create-mastra 1.13.1): versions
    # from before the 2026-06-17 ehindero account takeover predate the range and must stay silent.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@mastra/core": "1.42.0", "create-mastra": "1.13.0"}}',
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []

def test_version_floor_passes_patched_mastra(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@mastra/core": "1.43.0", "create-mastra": "1.14.0"}}',
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


# ── Go ecosystem support (go.sum-resolved versions) ──

def _goprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, languages={"go"}, go_dirs=["."])


def test_version_floor_flags_old_go_sdk_in_go_sum(tmp_path: Path) -> None:
    # MCP Go SDK -- DNS-rebinding/CSRF-class/JSON-RPC-parsing bugs, fixed 1.4.1 (CVE-2026-33252).
    (tmp_path / "go.sum").write_text(
        "github.com/modelcontextprotocol/go-sdk v1.3.0 h1:abc123==\n"
        "github.com/modelcontextprotocol/go-sdk v1.3.0/go.mod h1:def456==\n"
        "golang.org/x/net v0.10.0 h1:xyz789==\n",
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _goprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/below-patched-version"
    assert findings[0].severity == "high" and "CVE-2026-33252" in findings[0].title


def test_version_floor_go_sdk_patched_passes(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "github.com/modelcontextprotocol/go-sdk v1.4.1 h1:abc123==\n"
        "github.com/modelcontextprotocol/go-sdk v1.4.1/go.mod h1:def456==\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_version_floor_go_mod_alone_is_not_scanned(tmp_path: Path) -> None:
    # FP bait: go.mod's own `require` line is a LOWER bound under Go's MVS, not a resolved
    # version -- deliberately not scanned (see _go_sum_resolved's docstring). No go.sum present
    # at all -> no finding, even though go.mod alone names an old version.
    (tmp_path / "go.mod").write_text(
        "module example.com/myserver\n\ngo 1.22\n\n"
        "require github.com/modelcontextprotocol/go-sdk v1.0.0\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_version_floor_applies_on_go_language_alone(tmp_path: Path) -> None:
    guard = DependencyVersionFloorGuard()
    assert guard.applies(mkprofile(tmp_path, languages={"go"})) is True
    assert guard.applies(mkprofile(tmp_path, languages={"ruby"})) is False


def test_version_floor_go_unrelated_package_not_flagged(tmp_path: Path) -> None:
    # FP bait: an unrelated Go module, even at a very old version, must not fire -- only
    # packages with a real floor entry are checked.
    (tmp_path / "go.sum").write_text(
        "example.com/unrelated-package v0.0.1 h1:abc123==\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_version_floor_go_sum_takes_max_resolved_version_not_first_line(tmp_path: Path) -> None:
    # (Dean's review): an upgraded-but-not-yet-`go mod tidy`'d repo can carry BOTH
    # the old and new resolved versions of the same module in go.sum. First-line-wins used to
    # lock onto whichever sorted first in the file -- here that's the vulnerable v1.3.0, even
    # though the patched v1.4.1 is genuinely also present. Must NOT fire: the max version wins.
    (tmp_path / "go.sum").write_text(
        "github.com/modelcontextprotocol/go-sdk v1.3.0 h1:abc123==\n"
        "github.com/modelcontextprotocol/go-sdk v1.3.0/go.mod h1:def456==\n"
        "github.com/modelcontextprotocol/go-sdk v1.4.1 h1:ghi789==\n"
        "github.com/modelcontextprotocol/go-sdk v1.4.1/go.mod h1:jkl012==\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_version_floor_go_mod_line_still_flags_when_it_sorts_first(tmp_path: Path) -> None:
    # Still-fires companion to the max-version fix above: when the vulnerable version is the
    # ONLY (and therefore also the max) resolved version, it must still fire -- the fix changes
    # which line wins on a tie/multi-version file, not whether a genuinely below-floor pin fires.
    (tmp_path / "go.sum").write_text(
        "github.com/modelcontextprotocol/go-sdk v1.3.0 h1:abc123==\n"
        "github.com/modelcontextprotocol/go-sdk v1.3.0/go.mod h1:def456==\n",
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _goprof(tmp_path))
    assert len(findings) == 1
    assert "CVE-2026-33252" in findings[0].title


def test_version_floor_go_mod_suffix_line_never_treated_as_a_resolved_version(tmp_path: Path) -> None:
    # FP bait: a `/go.mod` line is a build-graph edge, not itself a resolved version -- even
    # when no matching content line exists for that module at all, it must never be read as one.
    (tmp_path / "go.sum").write_text(
        "github.com/modelcontextprotocol/go-sdk v1.3.0/go.mod h1:def456==\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _goprof(tmp_path)) == []


# ── #921 review: go.sum honest limits + an opt-out that works on every path ──

_GO_SDK = "github.com/modelcontextprotocol/go-sdk"


def test_version_floor_non_pip_remediation_names_the_opt_out_that_works(tmp_path: Path) -> None:
    # M3: every finding used to advertise `# security: allow-old-<pkg>`, but only `_scan_pip` reads
    # it. package.json / poetry.lock / package-lock.json / go.sum findings kept firing with the
    # pragma written (and JSON / go.sum cannot even hold it), so the advice must name the exception
    # registry instead: the one opt-out that applies to any finding.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "1.20.0"}}', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/@modelcontextprotocol/sdk": {"version": "1.20.0"}}}',
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "langchain-core"\nversion = "0.3.0"\n', encoding="utf-8"
    )
    (tmp_path / "go.sum").write_text(f"{_GO_SDK} v1.3.0 h1:abc123==\n", encoding="utf-8")
    prof = mkprofile(
        tmp_path, features={"frontend", "python"}, languages={"go"},
        python_dirs=["."], frontend_dir=".", go_dirs=["."],
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    by_file = {f.location: f for f in findings}
    assert set(by_file) == {"package.json", "package-lock.json", "poetry.lock", "go.sum"}
    for loc, f in by_file.items():
        assert "agentsec-exceptions.json" in f.remediation, loc
        assert "allow-old-" not in f.remediation, loc


def test_version_floor_pip_remediation_keeps_the_pragma_it_honours(tmp_path: Path) -> None:
    # The direction traded against (Rule 1): the pip-manifest path DOES read the pragma
    # (test_version_floor_pragma_opt_out), so its findings must keep advertising it.
    (tmp_path / "requirements.txt").write_text("langchain-core==0.3.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert "`# security: allow-old-langchain-core`" in findings[0].remediation
    assert "agentsec-exceptions.json" not in findings[0].remediation


def test_version_floor_go_sum_finding_is_waivable_via_the_exceptions_registry(tmp_path: Path) -> None:
    # Assert the artifact, not the advice: follow the go.sum remediation literally through the real
    # pipeline (detect -> guard -> exceptions) and prove the finding actually goes away.
    import json

    from agentsec import audit as audit_mod

    rule = "dependency-version-floor/below-patched-version"
    (tmp_path / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    (tmp_path / "go.sum").write_text(
        f"{_GO_SDK} v1.3.0 h1:abc123==\n{_GO_SDK} v1.3.0/go.mod h1:def456==\n", encoding="utf-8"
    )
    hits = [f for f in audit_mod.audit(tmp_path, run_scanners=False).findings if f.rule == rule]
    assert [f.location for f in hits] == ["go.sum"]
    assert "agentsec-exceptions.json" in hits[0].remediation
    (tmp_path / "agentsec-exceptions.json").write_text(
        json.dumps({"exceptions": [
            {"rule": rule, "location": "go.sum", "reason": "audited", "review_by": "2099-01-01"},
        ]}),
        encoding="utf-8",
    )
    assert [f for f in audit_mod.audit(tmp_path, run_scanners=False).findings if f.rule == rule] == []


def test_version_floor_go_sum_downgrade_without_tidy_is_a_known_false_negative(tmp_path: Path) -> None:
    # Documented limit (wiki: Known bypasses). `go get go-sdk@v1.3.0` after v1.4.1 was recorded
    # leaves BOTH content lines in go.sum until `go mod tidy`: the build uses v1.3.0 (go.mod says
    # so), but the max rule reports v1.4.1. It is the same go.sum as the upgraded-not-tidied FP-bait
    # above, which is the point: go.sum alone cannot tell the two apart. Pinned so the silence is a
    # stated trade; if a go.mod cross-check ever lands and this fires, flip it and drop the bullet.
    (tmp_path / "go.mod").write_text(
        f"module example.com/svc\n\ngo 1.22\n\nrequire {_GO_SDK} v1.3.0\n", encoding="utf-8"
    )
    (tmp_path / "go.sum").write_text(
        f"{_GO_SDK} v1.3.0 h1:abc123==\n{_GO_SDK} v1.3.0/go.mod h1:def456==\n"
        f"{_GO_SDK} v1.4.1 h1:ghi789==\n{_GO_SDK} v1.4.1/go.mod h1:jkl012==\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _goprof(tmp_path)) == []


def test_version_floor_go_major_suffix_path_needs_its_own_floor_entry(tmp_path: Path) -> None:
    # Documented limit (wiki: Known bypasses; version_floors.json note). A `/vN` major-version path
    # is a distinct Go module and is kept verbatim as the key, so a floor matches it only when the
    # entry names that exact path. Synthetic floors: no real /v2 advisory exists today.
    from agentsec.guards.base import read
    from agentsec.guards.dependency_version_floor import _go_sum_resolved

    f = tmp_path / "go.sum"
    f.write_text(f"{_GO_SDK}/v2 v2.0.0 h1:abc123==\n", encoding="utf-8")
    resolved = _go_sum_resolved(read(f))
    guard = DependencyVersionFloorGuard()
    floor: dict[str, object] = {"fixed_in": ["2.1.0"], "cve": "CVE-0000-0000", "severity": "high"}
    assert guard._flag_resolved(tmp_path, f, [{**floor, "package": _GO_SDK}], resolved) == []
    assert len(guard._flag_resolved(tmp_path, f, [{**floor, "package": f"{_GO_SDK}/v2"}], resolved)) == 1


def test_version_floor_upper_bound_advertises_the_pragma_it_honours(tmp_path: Path) -> None:
    # Pin (#921 re-review Low): `_upper_finding` now takes its advice from `_opt_out` too. The
    # upper-bound path is `_scan_pip`, which reads the pragma, so the advice must name it, and
    # following that advice must actually silence the finding (assert the artifact, Rule 3).
    (tmp_path / "requirements.txt").write_text("langchain-core<0.3.0\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["dependency-version-floor/upper-bound-below-floor"]
    assert findings[0].remediation.endswith(
        "Suppress an audited case with `# security: allow-old-langchain-core`."
    )
    (tmp_path / "requirements.txt").write_text(
        "langchain-core<0.3.0  # security: allow-old-langchain-core\n", encoding="utf-8"
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_version_floor_python_repo_stray_go_sum_is_read(tmp_path: Path) -> None:
    # Pin (#937): `applies()` is an OR over python/frontend/go, so a Python repo with a go.sum and
    # no `.go` file still gets that go.sum read (go_dirs is empty, so `go_scan_dirs` falls back to
    # the root). The docs state this; #937 decides whether it is intended, so flip this with it.
    (tmp_path / "go.sum").write_text(f"{_GO_SDK} v1.3.0 h1:abc123==\n", encoding="utf-8")
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.location for f in findings] == ["go.sum"]


# ── Java/Maven ecosystem support (pom.xml + build.gradle) ──

def _javaprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, languages={"java"}, java_dirs=["."])


def test_version_floor_flags_old_java_mcp_core_in_pom_xml(tmp_path: Path) -> None:
    # MCP Java SDK -- DNS rebinding + wildcard CORS, fixed 1.0.1/1.1.1 (CVE-2026-34237).
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>io.modelcontextprotocol.sdk</groupId>\n"
        "      <artifactId>mcp-core</artifactId>\n"
        "      <version>1.0.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/below-patched-version"
    assert findings[0].severity == "medium" and "CVE-2026-34237" in findings[0].title


def test_version_floor_finds_pom_xml_with_canonical_maven_source_layout(tmp_path: Path) -> None:
    # (Dean's review): the guard used to walk java_scan_dirs(root, profile) -- the
    # TOP-LEVEL dir containing a .java file -- looking for pom.xml INSIDE it. On a real, canonical
    # `src/main/java/...` Maven layout that top-level dir is "src", but pom.xml lives at the repo
    # ROOT, outside "src" entirely -- so the scan found nothing. The _javaprof() fixture's own
    # java_dirs=["."] masked this (it always scans root, sidestepping the bug). Here java_dirs is
    # the REAL value detect() would produce for this layout ("src"), proving the fix: pom.xml at
    # root must still be found regardless of where the .java source files themselves live.
    (tmp_path / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)
    (tmp_path / "src" / "main" / "java" / "com" / "example" / "App.java").write_text(
        "package com.example;\nclass App {}\n", encoding="utf-8"
    )
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>io.modelcontextprotocol.sdk</groupId>\n"
        "      <artifactId>mcp-core</artifactId>\n"
        "      <version>1.0.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, languages={"java"}, java_dirs=["src"])
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert "CVE-2026-34237" in findings[0].title


def _mcp_core_pom(version: str) -> str:
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency>'
        "<groupId>io.modelcontextprotocol.sdk</groupId><artifactId>mcp-core</artifactId>"
        f"<version>{version}</version></dependency></dependencies></project>\n"
    )


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")


def test_version_floor_skips_maven_target_pom_copy(tmp_path: Path) -> None:
    # #922 re-review: `mvn package` copies each module's POM to
    # `target/classes/META-INF/maven/<g>/<a>/pom.xml`, and the whole-root walk reached it,
    # so one CVE was reported twice. The real root POM and a real module POM must still fire.
    _write(tmp_path, {
        "pom.xml": _mcp_core_pom("1.0.0"),
        "target/classes/META-INF/maven/io.x/app/pom.xml": _mcp_core_pom("1.0.0"),
        "service/pom.xml": _mcp_core_pom("1.0.0"),
        "service/target/classes/META-INF/maven/io.x/svc/pom.xml": _mcp_core_pom("1.0.0"),
    })
    prof = mkprofile(tmp_path, languages={"java"}, java_dirs=["src"])
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert sorted(f.location.replace("\\", "/") for f in findings) == ["pom.xml", "service/pom.xml"]


def test_version_floor_target_skip_is_relative_to_the_scanned_root(tmp_path: Path) -> None:
    # Still-fires for the `target/` narrowing: a checkout that itself lives under a directory
    # named `target` is scanned normally, for both the POM and the Cargo.lock path.
    repo = tmp_path / "target" / "repo"
    _write(repo, {
        "pom.xml": _mcp_core_pom("1.0.0"),
        "Cargo.lock": '[[package]]\nname = "rmcp"\nversion = "1.3.0"\n',
    })
    prof = mkprofile(repo, languages={"java", "rust"}, java_dirs=["src"])
    findings = DependencyVersionFloorGuard().run(repo, prof)
    assert sorted(f.location for f in findings) == ["Cargo.lock", "pom.xml"]


def test_version_floor_java_mcp_core_patched_1_0_1_passes(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>io.modelcontextprotocol.sdk</groupId>\n"
        "      <artifactId>mcp-core</artifactId>\n"
        "      <version>1.0.1</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_version_floor_java_mcp_core_vulnerable_1_1_0_on_its_own_line(tmp_path: Path) -> None:
    # The 1.1.x line has its own fix (1.1.1) below the 1.0.x line's fix (1.0.1) -- 1.1.0 must
    # still fire even though it's numerically "above" 1.0.1 (same-line backport logic).
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>io.modelcontextprotocol.sdk</groupId>\n"
        "      <artifactId>mcp-core</artifactId>\n"
        "      <version>1.1.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_version_floor_flags_old_java_mcp_core_in_gradle_groovy(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'io.modelcontextprotocol.sdk:mcp-core:1.0.0'\n"
        "}\n",
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_version_floor_flags_old_java_mcp_core_in_gradle_kts(tmp_path: Path) -> None:
    (tmp_path / "build.gradle.kts").write_text(
        "dependencies {\n"
        '    implementation("io.modelcontextprotocol.sdk:mcp-core:1.0.0")\n'
        "}\n",
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_version_floor_java_property_placeholder_version_not_resolved(tmp_path: Path) -> None:
    # FP bait / disclosed gap: a ${property}-substituted <version> is not resolved -- must not
    # crash and must not fire on an unresolvable version.
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>io.modelcontextprotocol.sdk</groupId>\n"
        "      <artifactId>mcp-core</artifactId>\n"
        "      <version>${mcp.version}</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_version_floor_java_unrelated_package_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>com.example</groupId>\n"
        "      <artifactId>unrelated-lib</artifactId>\n"
        "      <version>0.0.1</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_version_floor_applies_on_java_language_alone(tmp_path: Path) -> None:
    guard = DependencyVersionFloorGuard()
    assert guard.applies(mkprofile(tmp_path, languages={"java"})) is True
    assert guard.applies(mkprofile(tmp_path, languages={"ruby"})) is False


# ── Rust/Cargo ecosystem support (Cargo.lock) ──

def _rustprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, languages={"rust"})


def test_version_floor_flags_old_rmcp_in_cargo_lock(tmp_path: Path) -> None:
    # Official MCP Rust SDK -- Streamable HTTP DNS rebinding, fixed 1.4.0 (CVE-2026-42559).
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "rmcp"\nversion = "1.3.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
        '[[package]]\nname = "unrelated-crate"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _rustprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/below-patched-version"
    assert findings[0].severity == "high" and "CVE-2026-42559" in findings[0].title


def test_version_floor_rmcp_patched_passes(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "rmcp"\nversion = "1.4.0"\n',
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _rustprof(tmp_path)) == []


def test_version_floor_flags_old_apollo_mcp_server_in_cargo_lock(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "apollo-mcp-server"\nversion = "1.6.0"\n',
        encoding="utf-8",
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _rustprof(tmp_path))
    assert len(findings) == 1
    assert "CVE-2026-35577" in findings[0].title


def test_version_floor_cargo_toml_alone_is_not_scanned(tmp_path: Path) -> None:
    # FP bait: Cargo.toml's own [dependencies] entry is a caret-range lower bound (Cargo's
    # default requirement operator), the same "ambiguous manifest" shape this guard already
    # declines to flag for pip/npm/Go -- no Cargo.lock present at all -> no finding, even
    # though Cargo.toml alone names an old version.
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "myserver"\nversion = "0.1.0"\n\n'
        '[dependencies]\nrmcp = "1.0.0"\n',
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _rustprof(tmp_path)) == []


def test_version_floor_skips_cargo_package_lock_copy(tmp_path: Path) -> None:
    # #922 review M3: `cargo package` writes `target/package/<crate>-<ver>/Cargo.lock`, a copy of
    # the real lock. The root lock and a nested workspace crate's lock must still fire.
    lock = '[[package]]\nname = "rmcp"\nversion = "1.3.0"\n'
    _write(tmp_path, {
        "Cargo.lock": lock,
        "target/package/app-0.1.0/Cargo.lock": lock,
        "crates/sub/Cargo.lock": lock,
    })
    findings = DependencyVersionFloorGuard().run(tmp_path, _rustprof(tmp_path))
    assert sorted(f.location.replace("\\", "/") for f in findings) == ["Cargo.lock", "crates/sub/Cargo.lock"]


def test_version_floor_maven_and_cargo_remediation_names_the_opt_out_that_works(tmp_path: Path) -> None:
    # #922 review M5: pom.xml / build.gradle / Cargo.lock go through `_flag_resolved`, which reads no
    # pragma, so their findings must name the exception registry (#921's `_opt_out`), not
    # `# security: allow-old-<pkg>` -- the sibling of the package.json / lockfile / go.sum test above.
    _write(tmp_path, {
        "pom.xml": _mcp_core_pom("1.0.0"),
        "build.gradle": "dependencies { implementation 'io.modelcontextprotocol.sdk:mcp-core:1.0.0' }\n",
        "Cargo.lock": '[[package]]\nname = "rmcp"\nversion = "1.3.0"\n',
    })
    prof = mkprofile(tmp_path, languages={"java", "rust"}, java_dirs=["."])
    by_file = {f.location: f for f in DependencyVersionFloorGuard().run(tmp_path, prof)}
    assert set(by_file) == {"pom.xml", "build.gradle", "Cargo.lock"}
    for loc, f in by_file.items():
        assert "agentsec-exceptions.json" in f.remediation, loc
        assert "allow-old-" not in f.remediation, loc


def test_version_floor_applies_on_rust_language_alone(tmp_path: Path) -> None:
    guard = DependencyVersionFloorGuard()
    assert guard.applies(mkprofile(tmp_path, languages={"rust"})) is True
    assert guard.applies(mkprofile(tmp_path, languages={"scala"})) is False


# ── Pragma anchoring (#1040): `# security: allow-old-<pkg>` counts only as a `#` comment ──

def test_dependency_version_floor_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # A TOML string value quoting the pragma is not a comment, so the pyproject pin still fires (#1040).
    def run(note: str) -> list:
        (tmp_path / "pyproject.toml").write_text(
            f'[project]\nname = "x"\ndescription = "{note}"\ndependencies = ["langchain-core==0.3.0"]\n',
            encoding="utf-8",
        )
        return DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))

    assert len(run("neutral")) == 1
    findings = run("# security: allow-old-langchain-core")
    assert len(findings) == 1 and "CVE-2025-68664" in findings[0].title


def test_dependency_version_floor_toml_real_comment_anywhere_still_suppresses(tmp_path: Path) -> None:
    # pyproject.toml keeps its documented whole-file reach: a real comment on any line suppresses (#1040).
    (tmp_path / "pyproject.toml").write_text(
        '# security: allow-old-langchain-core\n[project]\nname = "x"\n'
        'dependencies = ["langchain-core==0.3.0"]\n',
        encoding="utf-8",
    )
    assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_dependency_version_floor_requirements_comment_on_another_line_does_not_suppress(
    tmp_path: Path,
) -> None:
    # requirements.txt keeps its per-line reach: only the pin's own trailing comment suppresses (#1040);
    # the same-line case is test_version_floor_pragma_opt_out.
    (tmp_path / "requirements.txt").write_text(
        "# security: allow-old-langchain-core\nlangchain-core==0.3.0\n", encoding="utf-8"
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1 and "CVE-2025-68664" in findings[0].title


def test_dependency_version_floor_in_and_lock_pin_trailing_comment_suppresses(tmp_path: Path) -> None:
    # `.in` / `.lock` pip manifests are read under the `hash` dialect too, so a real trailing comment
    # on the pin line still suppresses there (#1040: no dropped opt-out on a comment-less suffix).
    for name in ("requirements.in", "requirements.lock"):
        for other in (tmp_path / "requirements.in", tmp_path / "requirements.lock"):
            other.unlink(missing_ok=True)
        (tmp_path / name).write_text("langchain-core==0.3.0\n", encoding="utf-8")
        assert len(DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path))) == 1, name
        (tmp_path / name).write_text(
            "langchain-core==0.3.0  # security: allow-old-langchain-core\n", encoding="utf-8"
        )
        assert DependencyVersionFloorGuard().run(tmp_path, _pyprof(tmp_path)) == [], name


# --- Docker base-image ecosystem (the Contabo PHP-interpreter-RCE notice that --------
# surfaced the gap -- `version_floors.json` had no runtime/interpreter ecosystem at all) --------

def _dockerprof(tmp_path: Path, images: set[tuple[str, str, str]]) -> StackProfile:
    return mkprofile(tmp_path, has_docker=True, docker_base_images=images)


def test_version_floor_flags_old_php_docker_base_image(tmp_path: Path) -> None:
    # CVE-2026-109618 (the Contabo notice): PHP interpreter RCE, fixed 8.2.35 on the 8.2.x line.
    prof = _dockerprof(tmp_path, {("php", "8.2.34-fpm", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/docker-base-image-below-floor"
    assert findings[0].severity == "critical" and "CVE-2026-109618" in findings[0].title
    assert findings[0].location == "Dockerfile"


def test_version_floor_passes_patched_php_docker_base_image(tmp_path: Path) -> None:
    prof = _dockerprof(tmp_path, {("php", "8.2.35-fpm", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof) == []


def test_version_floor_php_affected_from_5_4_0_predates_range_silent(tmp_path: Path) -> None:
    # Dean's #1134 review: the Contabo pair's affected range starts at 5.4.0, not "every version
    # ever shipped" -- a declared version below that predates the CVE entirely and must stay
    # silent, the same `affected_from` mechanism this guard's own module docstring documents for
    # the anthropic/GHSA-w828-4qhx-vxx3 case.
    prof = _dockerprof(tmp_path, {("php", "5.3.29", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof) == []

    # At/above 5.4.0 and still below the fix, the affected range is live and it fires as before.
    prof2 = _dockerprof(tmp_path, {("php", "5.4.0", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof2)
    assert len(findings) == 1 and "CVE-2026-109618" in findings[0].title


def test_version_floor_docker_custom_registry_path_named_php_is_a_known_fp(tmp_path: Path) -> None:
    # Dean's #1134 review: the bare image name is taken from the LAST `/`-path segment only
    # (`_bare_image_name`), so a private/custom image that merely happens to share a curated
    # floor's basename is indistinguishable from the real thing. `ghcr.io/acme/php` is some org's
    # own, unrelated image -- not the official PHP interpreter -- but it reads as `php` anyway.
    # End-to-end through the real `FROM`-line parser (not the `_dockerprof` mock) because the
    # mismatch happens in `detect.py`, not in this guard. 7.4.33 is deliberately above the
    # `affected_from: 5.4.0` floor added by the fix above, so this is not silenced by that fix --
    # it is a genuinely separate, disclosed-but-unfixed gap (see wiki's Known bypasses).
    (tmp_path / "Dockerfile").write_text("FROM ghcr.io/acme/php:7.4.33\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.docker_base_images == {("php", "7.4.33", "Dockerfile")}
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "CVE-2026-109618" in findings[0].title


def test_version_floor_docker_floating_tag_not_flagged(tmp_path: Path) -> None:
    # FP bait / narrowing-direction check: a floating minor tag never names an exact version --
    # it tracks whatever patch is current at pull time, so it must stay silent, the same
    # "ambiguous range, decline to flag" rule applied to an open pip/npm version spec.
    for tag in ("8.2", "8", "latest"):
        prof = _dockerprof(tmp_path, {("php", tag, "Dockerfile")})
        assert DependencyVersionFloorGuard().run(tmp_path, prof) == [], tag


def test_version_floor_docker_unrelated_image_not_flagged(tmp_path: Path) -> None:
    # Only an image with a real floor entry is checked -- an exact-pinned but unrelated image,
    # even a very old one, must not fire.
    prof = _dockerprof(tmp_path, {("nginx", "1.1.1", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof) == []


def test_version_floor_docker_patch_floor_respects_release_line(tmp_path: Path) -> None:
    # Same backport-line semantics as every other ecosystem: 8.5.0 (on the 8.5 line, below its
    # own 8.5.12 fix) is vulnerable; 8.3.36 exactly at the 8.3 line's own fix is not.
    prof = _dockerprof(tmp_path, {("php", "8.5.0", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "CVE-2026-109618" in findings[0].title

    prof2 = _dockerprof(tmp_path, {("php", "8.3.36", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof2) == []


def test_version_floor_docker_multiple_dockerfiles_each_reported(tmp_path: Path) -> None:
    # Two different Dockerfiles pinning the same vulnerable image each get their own finding,
    # pointing at their own file -- not deduplicated away.
    prof = _dockerprof(
        tmp_path,
        {
            ("php", "8.1.0", "Dockerfile"),
            ("php", "8.1.0", "docker/worker.Dockerfile"),
        },
    )
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 2
    assert {f.location for f in findings} == {"Dockerfile", "docker/worker.Dockerfile"}


# --- python/node docker floors (extending the docker floors beyond php, "where it pays off for -
# our stack" per Dean's review) ----------------------------------------------------------------

def test_version_floor_flags_old_python_docker_base_image(tmp_path: Path) -> None:
    # CVE-2026-19445 (CVSS 9.2): CPython ssl use-after-free, fixed 3.12.15 on the 3.12.x line.
    prof = _dockerprof(tmp_path, {("python", "3.12.14-slim", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].severity == "critical" and "CVE-2026-19445" in findings[0].title


def test_version_floor_passes_patched_python_docker_base_image(tmp_path: Path) -> None:
    prof = _dockerprof(tmp_path, {("python", "3.12.15-slim", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof) == []


def test_version_floor_python_docker_patch_floor_respects_release_line(tmp_path: Path) -> None:
    # 3.14.0 (on the 3.14 line, below its own 3.14.8 fix) is vulnerable; 3.11.17 exactly at the
    # 3.11 line's own fix is not -- same backport-line semantics as every other ecosystem.
    prof = _dockerprof(tmp_path, {("python", "3.14.0", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "CVE-2026-19445" in findings[0].title

    prof2 = _dockerprof(tmp_path, {("python", "3.11.17", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof2) == []


def test_version_floor_flags_old_node_docker_base_image(tmp_path: Path) -> None:
    # CVE-2026-111497: node:zlib Brotli-decoder OOB write, fixed 22.23.4 on the 22.x line.
    prof = _dockerprof(tmp_path, {("node", "22.23.3-alpine", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].severity == "high" and "CVE-2026-111497" in findings[0].title


def test_version_floor_passes_patched_node_docker_base_image(tmp_path: Path) -> None:
    prof = _dockerprof(tmp_path, {("node", "22.23.4-alpine", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof) == []


def test_version_floor_node_docker_patch_floor_respects_release_line(tmp_path: Path) -> None:
    prof = _dockerprof(tmp_path, {("node", "26.12.0", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "CVE-2026-111497" in findings[0].title

    prof2 = _dockerprof(tmp_path, {("node", "24.22.1", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof2) == []


def test_version_floor_flags_old_python_multi_hyphen_docker_tag(tmp_path: Path) -> None:
    # Review H1 (PR #1161): `_DOCKER_TAG_EXACT`'s suffix used to be `[\w.]*` -- `\w` excludes
    # `-`, so a SECOND hyphenated segment on a real, common official-image tag shape
    # (`python:3.12.14-slim-bookworm`) failed `fullmatch` entirely and this guard silently never
    # checked it, even though 3.12.14 is below the 3.12.15 fix.
    prof = _dockerprof(tmp_path, {("python", "3.12.14-slim-bookworm", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].severity == "critical" and "CVE-2026-19445" in findings[0].title


def test_version_floor_passes_patched_python_multi_hyphen_docker_tag(tmp_path: Path) -> None:
    # At-or-above the floor, same multi-hyphen suffix shape: must stay silent.
    prof = _dockerprof(tmp_path, {("python", "3.12.15-slim-bookworm", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof) == []


def test_version_floor_flags_old_node_multi_hyphen_docker_tag(tmp_path: Path) -> None:
    # Same gap, node's own real tag shape (`node:22.23.3-bookworm-slim`): 22.23.3 is below the
    # 22.23.4 fix.
    prof = _dockerprof(tmp_path, {("node", "22.23.3-bookworm-slim", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].severity == "high" and "CVE-2026-111497" in findings[0].title


def test_version_floor_passes_patched_node_multi_hyphen_docker_tag(tmp_path: Path) -> None:
    prof = _dockerprof(tmp_path, {("node", "22.23.4-bookworm-slim", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof) == []


def test_version_floor_docker_rc_suffix_does_not_mask_a_vulnerable_release(tmp_path: Path) -> None:
    # Review H1 follow-up: the widened suffix class (`[\w.-]*`, now allowing a second hyphenated
    # segment) must not let an `-rc`/pre-release-flavored suffix cause a vulnerable release to be
    # read as patched. The declared version is parsed from the captured release group alone
    # (`m.group(1)`), never from the suffix, so a `-rc1-bookworm`-style tag on the still-vulnerable
    # 3.12.14 release must fire exactly as the plain-suffix case does above.
    prof = _dockerprof(tmp_path, {("python", "3.12.14-rc1-bookworm", "Dockerfile")})
    findings = DependencyVersionFloorGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].severity == "critical" and "CVE-2026-19445" in findings[0].title

    # Pins the documented limit: the suffix is ignored, not interpreted, so a `-rc1` tag on the
    # patched release number reads as that final release and stays silent.
    prof2 = _dockerprof(tmp_path, {("python", "3.12.15-rc1-bookworm", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof2) == []


def test_version_floor_docker_postgres_tag_shape_cannot_match_today(tmp_path: Path) -> None:
    # (not the scope either): deliberately NOT extended to postgres. The official
    # postgres image's own real tags are 2-component ("16.15"), confirmed against Docker Hub's
    # tag list, not 3-component like php/python/node ("8.3.36"/"3.12.15"/"22.23.4") -- so even a
    # genuinely exact, pinned postgres tag never satisfies `_DOCKER_TAG_EXACT`'s 3-component
    # requirement. Adding a postgres floor entry today would be silently dead on every real
    # Dockerfile, which is worse than no entry -- left as a follow-on rather than shipped.
    # This test pins both halves: the floor data has no postgres entry, and the exact-tag regex
    # rejects postgres's real 2-component tag shape (so adding an entry alone would not fire).
    floors = json.loads(_FLOORS_PATH.read_text(encoding="utf-8"))["floors"]
    assert not any(f.get("ecosystem") == "docker" and f.get("package") == "postgres" for f in floors)
    assert _DOCKER_TAG_EXACT.fullmatch("16.15") is None
    prof = _dockerprof(tmp_path, {("postgres", "16.15", "Dockerfile")})
    assert DependencyVersionFloorGuard().run(tmp_path, prof) == []


def test_version_floor_docker_release_line_without_a_floor_entry_fires(tmp_path: Path) -> None:
    # #1161 review M3: a release line with no fixed-in entry (an EOL line such as python 3.9 or
    # node 20, or an EOL or unlisted line such as node 25) below the highest fix falls through
    # to "vulnerable", the same as every other ecosystem here. Pinned so a change to the
    # comparison cannot flip it silently.
    for image, tag in (("python", "3.9.20"), ("node", "20.19.0"), ("node", "25.1.0")):
        findings = DependencyVersionFloorGuard().run(tmp_path, _dockerprof(tmp_path, {(image, tag, "Dockerfile")}))
        assert len(findings) == 1, (image, tag)


def test_version_floor_docker_pragma_above_from_silences_and_only_there(tmp_path: Path) -> None:
    # #1134 review M1: the per-package pragma every other pip path honours was ignored in a
    # Dockerfile. Docker allows no trailing comment on an instruction, so the pragma goes in the
    # `#` comment lines directly above the `FROM`. Both directions, through the real detect().
    guard = DependencyVersionFloorGuard()

    def _run(dockerfile: str) -> list[Finding]:
        (tmp_path / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        return guard.run(tmp_path, detect(tmp_path))

    assert _run("# audited: base image patched downstream\n# security: allow-old-php\nFROM php:8.1.0\n") == []
    # The same file without the pragma fires.
    assert len(_run("# audited: base image patched downstream\nFROM php:8.1.0\n")) == 1
    # Not directly above the FROM (a blank line, or a non-comment instruction, in between).
    assert len(_run("# security: allow-old-php\n\nFROM php:8.1.0\n")) == 1
    assert len(_run('# security: allow-old-php\nARG X="1"\nFROM php:8.1.0\n')) == 1
    # Not a comment: the phrase inside an instruction's value does not count.
    assert len(_run('LABEL note="# security: allow-old-php"\nFROM php:8.1.0\n')) == 1
    # A pragma for a different image does not cover this one.
    assert len(_run("# security: allow-old-node\nFROM php:8.1.0\n")) == 1
    # Fails closed: two FROMs of the same image:tag, only one carrying the pragma, still fire.
    two = "# security: allow-old-php\nFROM php:8.1.0 AS build\nRUN true\nFROM php:8.1.0\n"
    assert len(_run(two)) == 1


def test_version_floor_docker_findings_are_in_a_stable_order(tmp_path: Path) -> None:
    # #1134 review M2: `docker_base_images` is a set and two findings in one Dockerfile tie on
    # `Finding.sort_key`, so the guard must not emit them in set-iteration order.
    images = {("php", "8.2.34", "Dockerfile"), ("php", "8.1.0", "Dockerfile"), ("php", "8.3.35", "Dockerfile")}
    findings = DependencyVersionFloorGuard().run(tmp_path, _dockerprof(tmp_path, images))
    assert [f.title.split(":")[1].split(" ")[0] for f in findings] == ["8.1.0", "8.2.34", "8.3.35"]

def test_version_floor_applies_on_docker_alone(tmp_path: Path) -> None:
    guard = DependencyVersionFloorGuard()
    assert guard.applies(mkprofile(tmp_path, has_docker=True)) is True
    assert guard.applies(mkprofile(tmp_path, has_docker=False, languages=set(), features=set())) is False


def test_version_floor_fires_on_non_canonical_dockerfile_name_end_to_end(tmp_path: Path) -> None:
    # Review H1: `detect.py::has_docker` is True only for a file named exactly
    # `Dockerfile` or `docker-compose*`, but `docker_base_images` is populated by a separate,
    # broader walk that also reads `Dockerfile.<x>`/`*.dockerfile`. A repo whose only Dockerfile
    # is named e.g. `Dockerfile.prod` therefore has `has_docker is False` while
    # `docker_base_images` is non-empty -- `applies()` used to gate on `has_docker` alone, so the
    # guard was silently skipped even though it had a vulnerable image to flag. Goes through the
    # real `detect()` -> `applies()` -> `run()` pipeline (not a hand-built `mkprofile(...)`),
    # since the gap is in how `detect()` populates the profile, not in the guard's own logic.
    (tmp_path / "Dockerfile.prod").write_text("FROM php:8.1.0\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.has_docker is False
    assert prof.docker_base_images == {("php", "8.1.0", "Dockerfile.prod")}

    guard = DependencyVersionFloorGuard()
    assert guard.applies(prof) is True

    findings = guard.run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].rule == "dependency-version-floor/docker-base-image-below-floor"
    assert findings[0].location == "Dockerfile.prod"
    assert "CVE-2026-109618" in findings[0].title
