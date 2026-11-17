from __future__ import annotations

import time

import pytest

from agentsec.guards.docker_latest_base_tag import DockerLatestBaseTagGuard
from tests._timing import (
    NormalizedCostBudget,
    TimingBudget,
    assert_growth,
    assert_normalized_cost,
    assert_within,
    calibration_seconds,
    register,
    register_normalized,
)
from tests.guards._common import *  # noqa: F401,F403


def test_docker_latest_base_tag_no_tag_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python\nCOPY . /app\nCMD ["python", "app.py"]\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-latest-base-tag/unpinned-from"
    assert findings[0].severity == "medium"
    assert findings[0].check_id == "docker-latest-base-tag"


def test_docker_latest_base_tag_explicit_latest_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-latest-base-tag/unpinned-from"


def test_docker_latest_base_tag_pinned_version_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_latest_base_tag_digest_pinned_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_latest_base_tag_scratch_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_latest_base_tag_multistage_reference_silent(tmp_path: Path) -> None:
    # FP-bait: `FROM builder` in a later stage references a build stage name, not a
    # pullable registry image — nothing to pin, must stay silent.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim AS builder\nRUN pip install build\nFROM builder\nCMD [\"x\"]\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_latest_base_tag_registry_port_no_tag_fires(tmp_path: Path) -> None:
    # A registry host:port must not be mistaken for image:tag.
    (tmp_path / "Dockerfile").write_text("FROM registry:5000/app\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-latest-base-tag/unpinned-from"


def test_docker_latest_base_tag_registry_port_pinned_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM registry:5000/app:1.2.3\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_latest_base_tag_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:latest\n# security: allow-latest-tag\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_latest_base_tag_applies_always(tmp_path: Path) -> None:
    profile_empty = mkprofile(tmp_path, features=set())
    assert DockerLatestBaseTagGuard().applies(profile_empty) is True


def test_docker_latest_base_tag_skips_example_template(tmp_path: Path) -> None:
    # §D.7: a `*.example` / `*.user.example` Dockerfile is a user-customization TEMPLATE, not a
    # built image. A real Dockerfile beside it still fires — proving the skip is per-file.
    (tmp_path / "Dockerfile").write_text("FROM python\n", encoding="utf-8")
    (tmp_path / "Dockerfile.user.example").write_text("FROM archon\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert len(findings) == 1  # only the real Dockerfile, not the .example template
    assert findings[0].location.startswith("Dockerfile:") or findings[0].location == "Dockerfile"


# ---------------------------------------------------------------------------
# #676: catastrophic backtracking in _stage_names
# ---------------------------------------------------------------------------

# `FROM\s+.+\s+AS` overlapped on the space character, and join_dockerfile_continuations
# contributes one space per `\`-continued line, so the pathological whitespace run is
# MANUFACTURED by the guard from ordinary continuation syntax (the #673 mechanism): no long
# line exists anywhere in the source. pytest-timeout cannot preempt this hang class (see
# pyproject.toml), so the test asserts the wall clock itself. The window is wide (sub-10ms
# healthy against ~26s broken), which is the case an absolute TimingBudget is for
# (tests/_timing.py).
_C676_BUDGET = register(
    TimingBudget(
        name="docker-latest-base-tag/stage-names-backtracking",
        seconds=5.0,
        measured=0.0010,
        regression=25.97,
        why="catastrophic FROM..AS stage-name backtracking reintroduced (#676)",
    )
)


def test_docker_latest_base_tag_many_continuations_stays_fast(tmp_path: Path) -> None:
    # ~1,500 continuation lines, longest SOURCE line 6 chars, whole file ~6KB: benign-looking
    # formatting, not a hostile file.
    (tmp_path / "Dockerfile").write_text(
        "FROM \\\n" + " \\\n" * 1500 + "alpine\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    start = time.monotonic()
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    elapsed = time.monotonic() - start
    # The joined FROM still parses: `alpine` is untagged, so the unpinned finding still fires.
    assert [f.rule for f in findings] == ["docker-latest-base-tag/unpinned-from"]
    assert_within(elapsed, _C676_BUDGET)


def test_docker_latest_base_tag_continued_stage_alias_still_excluded(tmp_path: Path) -> None:
    # Still-fires for the #676 narrowing, through the same joiner: a stage alias split across
    # a `\` continuation is joined (with the extra space the joiner adds) and must still be
    # recognised, so the later `FROM builder` stays a stage reference, not an unpinned image.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim \\\n    AS builder\nFROM builder\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert DockerLatestBaseTagGuard().run(tmp_path, profile) == []


# ---------------------------------------------------------------------------
# #696 review round: the MIRRORED continuation shape, and the span bound it forced
# ---------------------------------------------------------------------------

# The #696 review found the trailing-side mirror of the shape above: whitespace runs AFTER the
# image token with no ` AS <stage>` anywhere. Two distinct mechanisms had to be closed (see the
# comment on `_stage_names`): the unbounded span backtracking against the trailing `\s+AS`, and
# `^\s*` re-anchoring across the blank-line run the joiner emits for line-number stability.
# A wall-clock budget at a single size cannot discriminate the partially-fixed variants (each
# measured ~1.3s at n=20,000, comfortably under any honestly-calibrated budget), so the growth
# CLASS is the primary assertion — ratios cancel machine speed and constants — and the two
# budgets below are backstops for a true hang and a constant-factor blowup (tests/_timing.py).
_C696_MIRROR_BUDGET = register(
    TimingBudget(
        name="docker-latest-base-tag/trailing-continuation-backtracking",
        seconds=5.0,
        measured=0.14,
        regression=10.51,
        why="quadratic trailing FROM..AS scan reintroduced (#696 review)",
    )
)
_C696_MIRROR_COST = register_normalized(
    NormalizedCostBudget(
        name="docker-latest-base-tag/cost-per-continuation-line",
        units_per_item=0.25,
        measured=0.0593,  # WORST over 9 repeated runs (median 0.0576, spread 5.5%) — round 2, Low 2
        regression=4.18,
        why="constant-factor slowdown in the joined-FROM stage scan",
    )
)


def _trailing_continuation_tree(tmp_path: Path, n: int) -> Path:
    root = tmp_path / f"n{n}"
    root.mkdir()
    (root / "Dockerfile").write_text(
        "FROM alpine \\\n" + " \\\n" * n + "\nRUN echo hi\n", encoding="utf-8"
    )
    return root


@pytest.mark.slow
def test_docker_latest_base_tag_trailing_continuations_stay_linear(tmp_path: Path) -> None:
    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). The fourth size is prepended rather than
    # appended because the assertions below key on `elapsed[-1]` against budgets measured at
    # the current top size — extending upward would restate them and cost seconds, while the
    # extra ratio is only needed as a third VOTE for the median.
    sizes = [312, 1250, 5000, 20000]
    roots = {n: _trailing_continuation_tree(tmp_path, n) for n in sizes}
    guard = DockerLatestBaseTagGuard()
    findings: dict[int, list[str]] = {}

    def scan(n: int) -> None:
        findings[n] = [f.rule for f in guard.run(roots[n], mkprofile(roots[n], features={"python"}))]

    calibration = calibration_seconds()
    elapsed = assert_growth(scan, sizes, expected="linear")
    # The joined FROM must still PARSE at every size: `alpine` is untagged, so the unpinned
    # finding still fires. A scan that stopped matching entirely would report [] and fail here
    # rather than passing as "fast".
    assert all(findings[n] == ["docker-latest-base-tag/unpinned-from"] for n in sizes)
    assert_normalized_cost(elapsed[-1], sizes[-1], _C696_MIRROR_COST, calibration=calibration)
    assert_within(elapsed[-1], _C696_MIRROR_BUDGET)


def _alias_dockerfile(tmp_path: Path, image: str) -> None:
    (tmp_path / "Dockerfile").write_text(
        f"FROM {image} AS builder\nFROM builder\n", encoding="utf-8"
    )


def test_docker_latest_base_tag_nbsp_indented_from_still_fires(tmp_path: Path) -> None:
    # #696 round 2 (Low 1): Docker's parser trims leading whitespace with Go's unicode.IsSpace,
    # which includes NBSP, so an NBSP-indented Dockerfile builds — classic copy-pasted
    # indentation. The anchor class is `[^\S\n]*` and not `[ \t]*` exactly so this keeps
    # firing; `[ \t]*` was measured to miss it silently.
    (tmp_path / "Dockerfile").write_text(" FROM python\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["docker-latest-base-tag/unpinned-from"]


def test_docker_latest_base_tag_alias_at_the_span_bound_still_excluded(tmp_path: Path) -> None:
    # Still-excluded at the documented limit: `[^\s]` plus `.{0,300}` spans at most 301 chars,
    # so a 301-char image ref is the last alias that may be registered, and it must be.
    _alias_dockerfile(tmp_path, "i" * 297 + ":3.1")  # 301 chars, tagged
    profile = mkprofile(tmp_path, features={"python"})
    assert DockerLatestBaseTagGuard().run(tmp_path, profile) == []


def test_docker_latest_base_tag_alias_past_the_span_bound_is_a_known_limit(tmp_path: Path) -> None:
    # The disclosed cost of the span cap, pinned so it cannot drift silently: one char past
    # the limit the alias stops registering, so the later `FROM builder` reads as an unpinned
    # image. A FALSE POSITIVE, accepted deliberately — no real registry reference approaches
    # 302 chars — because widening the span back reopens the trailing-`\s+AS` quadratic the
    # growth test above pins.
    _alias_dockerfile(tmp_path, "i" * 298 + ":3.1")  # 302 chars, tagged
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerLatestBaseTagGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["docker-latest-base-tag/unpinned-from"]
    assert findings[0].location.endswith(":2")  # the stage REFERENCE, not the tagged FROM above it
