"""The network chokepoint: tier resolution + Tier-0 refusal + manifest disclosure."""
from __future__ import annotations

import pytest

from agentsec import net


def test_tier_resolution_precedence() -> None:
    # DO_NOT_TRACK wins over everything → 0
    assert net.resolve_tier(config_tier=2, cli="tier2", env={"DO_NOT_TRACK": "1", "AGENTSEC_NETWORK": "tier2"}) == 0
    # CLI over env over config
    assert net.resolve_tier(config_tier=0, cli="tier2", env={"AGENTSEC_NETWORK": "tier1"}) == 2
    assert net.resolve_tier(config_tier=0, cli=None, env={"AGENTSEC_NETWORK": "tier1"}) == 1
    assert net.resolve_tier(config_tier=2, cli=None, env={}) == 2
    assert net.resolve_tier(env={}) == 0          # default offline


def test_parse_tier_fail_closed() -> None:
    assert net.parse_tier("tier1") == 1 and net.parse_tier("2") == 2 and net.parse_tier(0) == 0
    assert net.parse_tier("garbage") == 0         # unrecognized → offline


def test_get_refuses_below_required_tier() -> None:
    m = net.Manifest(tier=0)
    with pytest.raises(net.EgressRefused) as exc:
        net.get("https://www.cisa.gov/x.json", tier_required=1, sends="nothing", feature="--kev", tier=0, manifest=m)
    assert "tier 1" in str(exc.value) and "DO_NOT_TRACK" in str(exc.value)
    # the op is still recorded in the manifest (disclosure happens even on refusal)
    assert m.ops and m.ops[0].feature == "--kev" and m.ops[0].dest == "www.cisa.gov"


def test_get_performs_when_tier_sufficient(monkeypatch) -> None:
    calls: dict[str, object] = {}

    def fake_raw(
        url: str, *, body: bytes | None = None, timeout: int = 20,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        calls["url"] = url
        calls["headers"] = headers
        return b"OK"

    monkeypatch.setattr(net, "_raw_request", fake_raw)
    m = net.Manifest(tier=1)
    out = net.get("https://www.cisa.gov/kev.json", tier_required=1, sends="nothing", feature="--kev", tier=1, manifest=m)
    assert out == b"OK" and calls["url"].endswith("kev.json")


def test_manifest_render() -> None:
    m = net.Manifest(tier=1)
    assert "offline" in m.render()                # empty → offline line
    m.record(net.EgressOp("--kev", "www.cisa.gov", "nothing (public KEV catalog)", 1))
    r = m.render()
    assert "TIER 1" in r and "--kev" in r and "www.cisa.gov" in r and "DO_NOT_TRACK" in r
