"""Tests for the compose-dns-bypass guard (§6d — DNS egress-allowlist wiring)."""
from __future__ import annotations

from agentsec.guards.compose_dns_bypass import ComposeDnsBypassGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-dns-bypass/service-skips-resolver"

# The HWH shape: an in-compose Unbound resolver at a fixed private IP that peers route DNS to.
_UNBOUND = (
    "  unbound:\n"
    "    image: mvance/unbound:1.22.0\n"
    "    networks:\n"
    "      appnet:\n"
    "        ipv4_address: 172.20.0.53\n"
)
_ROUTED = (
    "  agent-api:\n"
    "    image: agent-api:latest\n"
    "    dns:\n"
    "      - 172.20.0.53\n"
    "    networks:\n"
    "      appnet:\n"
    "        ipv4_address: 172.20.0.10\n"
    "  rag-pipeline:\n"
    "    image: rag-pipeline:latest\n"
    "    dns:\n"
    "      - 172.20.0.53\n"
    "    networks:\n"
    "      appnet:\n"
    "        ipv4_address: 172.20.0.11\n"
)


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeDnsBypassGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str, name: str = "docker-compose.yml") -> None:
    (tmp_path / name).write_text("services:\n" + body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_compose_dns_bypass_missing_dns_fires(tmp_path: Path) -> None:
    """A service with no `dns:` while peers route through the resolver must fire (the canonical case)."""
    worker = "  worker:\n    image: worker:latest\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.12\n"
    _compose(tmp_path, _UNBOUND + _ROUTED + worker)
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert f.check_id == "compose-dns-bypass"
    assert f.standards == ["OWASP:A05", "OWASP-LLM:LLM02"]
    assert "worker" in f.title


def test_compose_dns_bypass_dns_elsewhere_fires(tmp_path: Path) -> None:
    """A service whose `dns:` points at a different (public) resolver still bypasses the allowlist."""
    rogue = "  worker:\n    image: worker:latest\n    dns:\n      - 8.8.8.8\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.12\n"
    _compose(tmp_path, _UNBOUND + _ROUTED + rogue)
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_compose_dns_bypass_dns_elsewhere_message_says_change(tmp_path: Path) -> None:
    """The points-elsewhere finding must not claim Docker-embedded-resolver fallback (the service
    uses the IP it set), and must say to CHANGE the existing `dns:`, not ADD one (review #378 Medium)."""
    rogue = "  worker:\n    image: worker:latest\n    dns:\n      - 8.8.8.8\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.12\n"
    _compose(tmp_path, _UNBOUND + _ROUTED + rogue)
    f = next(f for f in _run(tmp_path) if f.rule == _RULE)
    assert "embedded resolver" not in f.message
    assert "Change" in f.remediation and "Add `dns:" not in f.remediation


def test_compose_dns_bypass_flow_list_routed_silent_but_bypass_fires(tmp_path: Path) -> None:
    """Flow-syntax `dns: [ip]` counts as routed; a bare service still fires."""
    routed_flow = (
        "  api:\n    image: api\n    dns: [172.20.0.53]\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.10\n"
        "  api2:\n    image: api2\n    dns: [172.20.0.53]\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.11\n"
    )
    worker = "  worker:\n    image: worker:latest\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.12\n"
    _compose(tmp_path, _UNBOUND + routed_flow + worker)
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert [f.title.split("'")[1] for f in findings] == ["worker"]


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_compose_dns_bypass_all_routed_silent(tmp_path: Path) -> None:
    """Every app service routes through the resolver (the correct HWH shape) -> silent."""
    _compose(tmp_path, _UNBOUND + _ROUTED)
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_dns_bypass_resolver_service_not_flagged(tmp_path: Path) -> None:
    """The resolver service itself has no `dns:` but must NOT be flagged as a bypass."""
    _compose(tmp_path, _UNBOUND + _ROUTED)
    assert not any("unbound" in f.title for f in _run(tmp_path))


def test_compose_dns_bypass_no_routing_pattern_silent(tmp_path: Path) -> None:
    """No service routes DNS to an in-compose IP -> no resolver-routing pattern -> silent."""
    body = (
        "  db:\n    image: postgres:16\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.20\n"
        "  api:\n    image: api\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.10\n"
    )
    _compose(tmp_path, body)
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_dns_bypass_single_incidental_pointer_silent(tmp_path: Path) -> None:
    """One service routing `dns:` at an in-compose sidecar (e.g. a Consul service-discovery agent) is
    NOT a shared egress-allowlist resolver — the <2-router floor must keep it from designating a
    resolver and flooding the sibling services with findings (review #378 High FP)."""
    body = (
        "  consul:\n    image: consul:1.15\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.99\n"
        "  legacy:\n    image: legacy\n    dns:\n      - 172.20.0.99\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.50\n"
        "  api:\n    image: api\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.10\n"
        "  frontend:\n    image: frontend\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.11\n"
    )
    _compose(tmp_path, body)
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_dns_bypass_resolver_self_vote_silent(tmp_path: Path) -> None:
    """A resolver that lists its OWN ip in `dns:` (e.g. a shared dns: fragment applied to every
    service) must not supply one of its own >=2 quorum votes — with only one genuine external router
    the pattern is not established, so siblings stay silent (review #378 second-pass Medium)."""
    body = (
        "  unbound:\n    image: mvance/unbound\n    dns:\n      - 172.20.0.53\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.53\n"
        "  legacy:\n    image: legacy\n    dns:\n      - 172.20.0.53\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.50\n"
        "  api:\n    image: api\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.10\n"
        "  frontend:\n    image: frontend\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.11\n"
    )
    _compose(tmp_path, body)
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_dns_bypass_self_listing_resolver_still_fires_with_two_routers(tmp_path: Path) -> None:
    """FN-guard for the self-vote exclusion: a self-listing resolver + TWO genuine routers still
    establishes the pattern, so a bypassing sibling fires (the exclusion must not over-suppress)."""
    body = (
        "  unbound:\n    image: mvance/unbound\n    dns:\n      - 172.20.0.53\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.53\n"
        "  api:\n    image: api\n    dns:\n      - 172.20.0.53\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.10\n"
        "  rag:\n    image: rag\n    dns:\n      - 172.20.0.53\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.11\n"
        "  worker:\n    image: worker\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.12\n"
    )
    _compose(tmp_path, body)
    assert [f.title.split("'")[1] for f in _run(tmp_path) if f.rule == _RULE] == ["worker"]


def test_compose_dns_bypass_public_shared_dns_silent(tmp_path: Path) -> None:
    """Two services sharing a PUBLIC DNS (8.8.8.8, not an in-compose service) is not an allowlist
    to bypass -> silent (FP-bait)."""
    body = (
        "  api:\n    image: api\n    dns:\n      - 8.8.8.8\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.10\n"
        "  api2:\n    image: api2\n    dns:\n      - 8.8.8.8\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.11\n"
        "  worker:\n    image: worker\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.12\n"
    )
    _compose(tmp_path, body)
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_dns_bypass_pragma_silences(tmp_path: Path) -> None:
    worker = "  worker:\n    image: worker:latest\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.12\n"
    (tmp_path / "docker-compose.yml").write_text(
        "# security: allow-dns-bypass\nservices:\n" + _UNBOUND + _ROUTED + worker, encoding="utf-8"
    )
    assert _run(tmp_path) == []


def test_compose_dns_bypass_no_compose_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_compose_dns_bypass_inline_comment_ip_not_absorbed(tmp_path: Path) -> None:
    """An IP in an inline comment must not leak into the wiring sets (comment-stripping)."""
    body = (
        "  api:\n    image: api  # talks to 172.20.0.53\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.10\n"
        "  api2:\n    image: api2\n    networks:\n      appnet:\n        ipv4_address: 172.20.0.11\n"
    )
    _compose(tmp_path, _UNBOUND + body)
    # No real `dns:` routing exists, so the commented IP must not conjure a resolver pattern.
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_compose_dns_bypass_applies_gate(tmp_path: Path) -> None:
    g = ComposeDnsBypassGuard()
    assert g.applies(mkprofile(tmp_path, features={"docker"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False
