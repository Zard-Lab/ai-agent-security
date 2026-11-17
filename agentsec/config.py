"""Per-repo configuration — an optional, dependency-free `.agentsec/config.json`.

Two non-product path tiers, both **opt-in by design** (with no config nothing changes — a real
directory merely named `old/` or `evals/` is never silently dropped or demoted):

- **`archive_paths`** — directory-segment names treated as NON-product and **dropped** (the
  lossy guard SUPPRESSION via `guards.base.is_nonproduct_path`, applied across all guards). For
  vendored-in / generated / dead-code trees where no real bug can hide.

      {"archive_paths": ["old", "legacy"]}     # drop these trees
      {"archive_paths": true}                  # drop the recommended default (detect.ARCHIVE_SEGMENTS)

- **`nonproduct_paths`** — directory-segment names that are still scanned but **demoted** (ranked
  low via `prioritize.reachability`, never dropped). The robust home for `evals/`, `scripts/`,
  `seed/` and the like — a real bug there stays visible, just deprioritized.

      {"nonproduct_paths": ["evals", "seed"]}  # demote these trees
      {"nonproduct_paths": true}               # demote the recommended default set

Both tiers are surfaced/populated by the **exclude advisor** (`agentsec suggest-excludes`), which
suggests candidates and writes accepted ones here via `write_repo_config` (never auto-applied).

Loading is **total**: a missing file, a non-UTF-8 file, malformed JSON, or an unexpected shape yields an empty config
rather than raising — a broken config never aborts an audit. A file that is present but unusable also
prints one stderr warning per path, so the user's settings never stop applying in silence.
"""
from __future__ import annotations

import contextlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.detect import ARCHIVE_SEGMENTS

_CONFIG_REL = (".agentsec", "config.json")

# Recommended DEFAULT set for `{"nonproduct_paths": true}` — common non-product dirs that are NOT
# universal enough to hardwire in `detect.NONPRODUCT_DIR_ALT` (Layer 1), so they stay opt-in per
# repo. The advisor suggests these plus any repo-specific ones it discovers.
_DEFAULT_NONPRODUCT_PATHS = frozenset(
    {"scripts", "tools", "docs", "evals", "seed", "seeds", "benchmarks", "notebooks", "alembic"}
)


@dataclass
class RepoConfig:
    """Resolved per-repo settings (all optional, with safe empty defaults)."""

    archive_segments: frozenset[str] = field(default_factory=frozenset)
    nonproduct_segments: frozenset[str] = field(default_factory=frozenset)
    # Network-egress tier from `.agentsec/config.json` `{"network": {"tier": 0|1|2}}` — see
    # `net.resolve_tier` (CLI/env/DO_NOT_TRACK override this). None = unset (→ default 0).
    network_tier: int | None = None


def _coerce_tier(value: object) -> int | None:
    if isinstance(value, dict):
        value = value.get("tier")
    return value if isinstance(value, int) and value in (0, 1, 2) else None


def _coerce_segments(value: object, default: frozenset[str]) -> frozenset[str]:
    """`true` -> `default`; a list of strings -> those segment names (lowercased,
    slash/space-stripped). Anything else -> empty (opt-out)."""
    if value is True:
        return default
    if isinstance(value, list):
        return frozenset(
            s.strip().strip("/").lower() for s in value if isinstance(s, str) and s.strip()
        )
    return frozenset()


_WARNED: set[tuple[Path, str]] = set()


def _ignore(path: Path, why: str) -> RepoConfig:
    """Warn that a present config is unusable, once per path and reason per process (the loader runs
    2-4 times per `audit`; a file that breaks a second, different way is reported again), and return
    the empty config. The `load_triage` shape: fail safe, but say so."""
    key = (path.absolute(), why)
    if key not in _WARNED:
        _WARNED.add(key)
        # A closed stderr, or a non-ASCII path on a cp1252 one outside the CLI's `force_utf8_stdio`,
        # must not turn the warning into the very raise this loader promises never to make.
        with contextlib.suppress(OSError, ValueError):
            print(f"warning: ignoring {path} ({why}); running with the default config", file=sys.stderr)
    return RepoConfig()


def load_repo_config(root: Path) -> RepoConfig:
    """Read `<root>/.agentsec/config.json` if present. Never raises; a present but unusable file
    falls back to the empty config with one stderr warning (`_ignore`)."""
    path = root.joinpath(*_CONFIG_REL)
    try:
        # `utf-8-sig`: a BOM'd file (Notepad "UTF-8 with BOM") must not fail `json.loads` and be
        # silently ignored. `UnicodeDecodeError` is a ValueError, NOT an OSError — an un-decodable
        # file (UTF-16 / Latin-1) is "unparseable", so it falls back to empty like bad JSON (#513).
        raw = path.read_text(encoding="utf-8-sig")
    except OSError:
        return RepoConfig()  # absent, the normal case
    except UnicodeDecodeError:
        return _ignore(path, "not UTF-8 text")
    if not raw.strip():
        return RepoConfig()  # a blank (`touch`ed) file, which `write_repo_config` also treats as fresh
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return _ignore(path, "not valid JSON")
    if not isinstance(data, dict):
        return _ignore(path, "not a JSON object")
    return RepoConfig(
        archive_segments=_coerce_segments(data.get("archive_paths"), ARCHIVE_SEGMENTS),
        nonproduct_segments=_coerce_segments(data.get("nonproduct_paths"), _DEFAULT_NONPRODUCT_PATHS),
        network_tier=_coerce_tier(data.get("network")),
    )


def _merge_key(data: dict[str, object], key: str, add: tuple[str, ...], default: frozenset[str]) -> list[str]:
    """Union `add` into `data[key]`'s segment list in place; return the sorted result. Handles the
    `true` shorthand (expand to `default` first) and a missing/odd existing value (treated as empty).
    Names are lowercased / slash+space-stripped, matching `_coerce_segments`."""
    existing = _coerce_segments(data.get(key), default) if key in data else frozenset()
    clean = {s.strip().strip("/").lower() for s in add if s and s.strip()}
    merged = sorted(existing | clean)
    if merged:
        data[key] = merged
    return merged


def write_repo_config(
    root: Path,
    *,
    archive_add: tuple[str, ...] = (),
    nonproduct_add: tuple[str, ...] = (),
    review_by: str | None = None,
) -> dict[str, list[str]]:
    """Merge the given segment names into `<root>/.agentsec/config.json` and write it back.

    **Merge-safe**: reads any existing file, preserves unknown keys, unions (never clobbers) the
    `archive_paths` / `nonproduct_paths` lists, and writes UTF-8 with a trailing newline. The `true`
    shorthand is expanded to its default set before union (so the result is an explicit list).
    Returns `{key: added-or-final sorted list}` for the keys that changed (for the advisor's
    "added N dirs" message).

    **Raises `ValueError` on a malformed or non-UTF-8 existing config** rather than overwriting it
    (a UTF-8 BOM is tolerated, as on the read side). A present but
    unparseable file was previously treated as empty and then written over unconditionally, so a
    hand-written `network.tier` or `nonproduct_paths` entry vanished with exit 0 — while the skill
    promised the writer "never clobbers" (#478 review). Refusing mirrors `merge_exceptions`. Note
    this is deliberately STRICTER than `load_repo_config`, which stays total: a broken config must
    never abort an audit, but it must also never be silently destroyed by a write."""
    path = root.joinpath(*_CONFIG_REL)
    data: dict[str, object] = {}
    try:
        raw = path.read_text(encoding="utf-8-sig")  # BOM-tolerant, matching `load_repo_config`
    except OSError:
        raw = ""  # absent (or unreadable) — start from empty; the write below reports any failure
    except UnicodeDecodeError as exc:
        # A SEPARATE arm, never folded into the one above: treating an un-decodable file as empty
        # would overwrite it — the clobber the #478 review closed (#513).
        raise ValueError(f"{path} is not UTF-8 text ({exc}); refusing to overwrite it") from exc
    if raw.strip():
        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise ValueError(f"{path} is not valid JSON ({exc}); refusing to overwrite it") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"{path} is not a JSON object; refusing to overwrite it")
        data = parsed

    changed: dict[str, list[str]] = {}
    if archive_add:
        changed["archive_paths"] = _merge_key(data, "archive_paths", archive_add, ARCHIVE_SEGMENTS)
    if nonproduct_add:
        changed["nonproduct_paths"] = _merge_key(
            data, "nonproduct_paths", nonproduct_add, _DEFAULT_NONPRODUCT_PATHS
        )
    if review_by:
        data["review_by"] = review_by

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return changed
