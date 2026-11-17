#!/usr/bin/env python3
"""Check built PyPI artifacts before they are uploaded: the last look at what becomes public for good.

    python scripts/check_dist.py dist/ --version 0.22.1

`dist/` must hold exactly one sdist and one wheel. They pass when:

- every sdist member sits under a root `pyproject.toml`'s `[tool.hatch.build.targets.sdist] only-include`
  lists (plus the `PKG-INFO` and `.gitignore` hatchling always adds);
- neither artifact carries a private path (`.claude/`, `docs/knowledge/`, `CLAUDE.md`, a workflow of the
  repo itself, ...). The CI component templates under `agentsec/ci/components/` ship on purpose;
- the wheel holds only the `agentsec/` package and its `.dist-info/`;
- with `--version`, both file names carry that version.

Run by the public repo's `release.yml` between `python -m build` and the upload, and by
`scripts/export_public.py` on every export. Stdlib only, so it runs on a bare runner Python.
"""
from __future__ import annotations

import argparse
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path

PRIVATE_PATH = re.compile(
    r"^(\.claude|docs/knowledge|docs/ledger|docs/plan|\.github/workflows)(/|$)"
    r"|^(CLAUDE\.md|agentsec-exceptions\.json|\.privacy-terms)$"
)
SDIST_ALWAYS = frozenset({"PKG-INFO", ".gitignore"})


def sdist_roots(pyproject: Path) -> set[str]:
    with pyproject.open("rb") as fh:
        config = tomllib.load(fh)
    return set(config["tool"]["hatch"]["build"]["targets"]["sdist"]["only-include"]) | SDIST_ALWAYS


def problems(pyproject: Path, sdist: Path, wheel: Path, version: str | None = None) -> list[str]:
    """Every reason the pair must not be uploaded; empty when it may."""
    prefix = sdist.name.removesuffix(".tar.gz") + "/"
    with tarfile.open(sdist) as tar:
        names_in_tar = [m.name for m in tar.getmembers()]
    # Every member sits under `<name>-<version>/`; one that does not is outside every check below.
    found = [f"sdist member outside {prefix}: {n}" for n in names_in_tar
             if not n.startswith(prefix) and n != prefix.rstrip("/")]
    members = [n[len(prefix):] for n in names_in_tar if n.startswith(prefix) and n != prefix]
    with zipfile.ZipFile(wheel) as whl:
        names = whl.namelist()
    found += [f"sdist root not in only-include: {r}"
              for r in sorted({m.split("/", 1)[0] for m in members} - sdist_roots(pyproject))]
    found += [f"private path: {p}" for p in sorted(set(members + names)) if PRIVATE_PATH.search(p)]
    found += [f"wheel file outside the package: {n}" for n in sorted(names)
              if not n.startswith("agentsec/") and not re.match(r"[^/]+\.dist-info/", n)]
    if not members:
        found.append(f"{sdist.name} is empty")
    if version is not None:
        # Exact: `0.22.1` must not be satisfied by `0.22.10` or `0.22.1rc1`.
        named = re.compile(rf"^[A-Za-z0-9_.]+-{re.escape(version)}(\.tar\.gz|-[^-]+-[^-]+-[^-]+\.whl)$")
        found += [f"{a.name} is not version {version}" for a in (sdist, wheel) if not named.match(a.name)]
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dist", type=Path, help="the directory holding the built sdist and wheel")
    ap.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    ap.add_argument("--version", help="the version both artifacts must carry, without the leading v")
    args = ap.parse_args(argv)
    sdists, wheels = sorted(args.dist.glob("*.tar.gz")), sorted(args.dist.glob("*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        print(f"FAIL: expected one sdist and one wheel in {args.dist}, found {sdists + wheels}")
        return 1
    found = problems(args.pyproject, sdists[0], wheels[0], args.version)
    for p in found:
        print(f"FAIL: {p}")
    if not found:
        print(f"OK: {sdists[0].name}, {wheels[0].name}")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
