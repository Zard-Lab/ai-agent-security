"""Tests for the compose-no-network-segmentation guard (§6c) — a cross-service,
whole-file check, unlike its per-service siblings in this batch."""
from __future__ import annotations

from agentsec.findings import _is_review_finding
from agentsec.guards.compose_no_network_segmentation import ComposeNoNetworkSegmentationGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-no-network-segmentation/default-network-only"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeNoNetworkSegmentationGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str, name: str = "docker-compose.yml") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_no_service_declares_networks_fires_once(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n"
        "  web:\n    image: nginx\n"
        "  worker:\n    image: alpine\n"
        "  db:\n    image: postgres:16\n",
    )
    findings = _run(tmp_path)
    matches = [f for f in findings if f.rule == _RULE]
    assert len(matches) == 1  # ONE finding for the whole file, not per-service
    assert matches[0].severity == "medium"
    assert matches[0].check_id == "compose-no-network-segmentation"


def test_default_network_only_is_a_review_signal(tmp_path: Path) -> None:
    # #766: the rule's `surfacing_rule_prefixes` declaration had no behavioral pin, so emptying it
    # left the suite green. The checkmeta gate checks the declaration's text, not what it does.
    _compose(
        tmp_path,
        "services:\n"
        "  web:\n    image: nginx\n"
        "  db:\n    image: postgres:16\n",
    )
    matches = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(matches) == 1
    assert _is_review_finding(matches[0]) is True


def test_top_level_networks_block_unattached_still_fires(tmp_path: Path) -> None:
    """Indirect/bypass case: declaring custom networks at the TOP LEVEL without any
    SERVICE actually joining one via its own `networks:` key changes nothing about the
    default-bridge blast radius — must still fire."""
    _compose(
        tmp_path,
        "services:\n"
        "  web:\n    image: nginx\n"
        "  db:\n    image: postgres:16\n"
        "networks:\n"
        "  internal:\n"
        "    driver: bridge\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_two_services_minimum_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n"
        "  web:\n    image: nginx\n"
        "  db:\n    image: postgres:16\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_one_service_with_explicit_networks_silences_whole_file(tmp_path: Path) -> None:
    """The given FP-bait case: at least ONE service declaring an explicit `networks:`
    must silence the whole-file finding, even though other services declare none."""
    _compose(
        tmp_path,
        "services:\n"
        "  web:\n    image: nginx\n"
        "  db:\n    image: postgres:16\n"
        "    networks:\n      - internal\n"
        "networks:\n"
        "  internal:\n"
        "    driver: bridge\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_single_service_file_silent(tmp_path: Path) -> None:
    """A single-service compose file has no peer to laterally move to — must not fire."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_inline_networks_list_counts_as_segmented(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n"
        "  web:\n    image: nginx\n    networks: [internal]\n"
        "  db:\n    image: postgres:16\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-no-network-segmentation\n"
        "services:\n"
        "  web:\n    image: nginx\n"
        "  db:\n    image: postgres:16\n",
    )
    assert _run(tmp_path) == []


def test_dev_compose_out_of_scope(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  web:\n    image: nginx\n  db:\n    image: postgres:16\n",
        name="docker-compose.dev.yml",
    )
    assert _run(tmp_path) == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeNoNetworkSegmentationGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeNoNetworkSegmentationGuard().applies(profile) is True


def test_no_compose_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert _run(tmp_path) == []
