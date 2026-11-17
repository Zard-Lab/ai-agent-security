"""Tests for the dns-egress-allowlist guard (§6d)."""
from __future__ import annotations

from agentsec.guards.dns_egress_allowlist import DnsEgressAllowlistGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "dns-egress-allowlist/no-default-deny"

_OPEN = (
    "server:\n"
    "    interface: 172.20.0.53\n"
    "    access-control: 172.20.0.0/16 allow\n"
    "forward-zone:\n"
    '    name: "."\n'
    "    forward-addr: 1.1.1.1\n"
)
_DENY = 'server:\n    local-zone: "." refuse\n    local-zone: "supabase.co." transparent\n'


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"host-config"})


def _run(tmp_path: Path):
    return DnsEgressAllowlistGuard().run(tmp_path, _prof(tmp_path))


def _unbound(tmp_path: Path, body: str, rel: str = "unbound.conf") -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_dns_egress_open_unbound_fires(tmp_path: Path) -> None:
    _unbound(tmp_path, _OPEN)
    findings = _run(tmp_path)
    assert [f.rule for f in findings] == [_RULE]
    f = findings[0]
    assert f.severity == "medium"
    assert f.check_id == "dns-egress-allowlist"
    assert f.standards == ["OWASP:A05", "OWASP-LLM:LLM02"]


def test_dns_egress_under_unbound_dir_fires(tmp_path: Path) -> None:
    """A *.conf under an unbound/ dir is scanned."""
    _unbound(tmp_path, _OPEN, rel="unbound/server.conf")
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_dns_egress_default_deny_silent(tmp_path: Path) -> None:
    """local-zone: \".\" refuse present -> it's an allowlist -> silent (the HWH shape)."""
    _unbound(tmp_path, _DENY)
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_dns_egress_always_nxdomain_silent(tmp_path: Path) -> None:
    _unbound(tmp_path, 'server:\n    local-zone: "." always_nxdomain\n')
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_dns_egress_deny_in_split_file_silent(tmp_path: Path) -> None:
    """Default-deny in a sibling unbound/*.conf still counts (collective check)."""
    _unbound(tmp_path, _OPEN, rel="unbound/forward.conf")
    _unbound(tmp_path, 'server:\n    local-zone: "." refuse\n', rel="unbound/deny.conf")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_dns_egress_no_unbound_silent(tmp_path: Path) -> None:
    """host-config but no unbound config -> silent (no claim about other egress mechanisms)."""
    (tmp_path / "sshd_config").write_text("Port 22\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_dns_egress_pragma_silences(tmp_path: Path) -> None:
    _unbound(tmp_path, "# security: allow-open-dns-egress\n" + _OPEN)
    assert _run(tmp_path) == []


def test_dns_egress_commented_deny_still_fires(tmp_path: Path) -> None:
    """A commented-out default-deny must NOT read as present — the comment-stripping FN
    (review #250 / Marconi). The resolver is effectively open, so the guard must fire."""
    _unbound(tmp_path, 'server:\n    # local-zone: "." refuse   # TODO re-enable\n    interface: 0.0.0.0\n')
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_dns_egress_always_nodata_silent(tmp_path: Path) -> None:
    """`always_nodata` is a real Unbound blocking action — a resolver using it IS default-deny,
    so the guard must stay silent (review #250 regex gap)."""
    _unbound(tmp_path, 'server:\n    local-zone: "." always_nodata\n')
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_dns_egress_unquoted_deny_silent(tmp_path: Path) -> None:
    """The unquoted form `local-zone: . refuse` is valid Unbound and must silence the guard."""
    _unbound(tmp_path, "server:\n    local-zone: . refuse\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_dns_egress_transparent_root_zone_fires(tmp_path: Path) -> None:
    """A non-blocking action (`local-zone: "." transparent`) does NOT deny — the guard must still
    fire, guarding against a future widening of _DEFAULT_DENY that would silence real findings."""
    _unbound(tmp_path, 'server:\n    local-zone: "." transparent\n')
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_dns_egress_applies_gate(tmp_path: Path) -> None:
    g = DnsEgressAllowlistGuard()
    assert g.applies(mkprofile(tmp_path, features={"host-config"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False
