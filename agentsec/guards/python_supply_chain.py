"""Guard: Python (uv) dependencies need hashes, pinning, a cooldown + clean waivers.

Supply-chain hardening (OWASP-LLM **LLM03 — Supply Chain**), the Python analog of
the JS/TS ``dependency-cooldown`` guard. A hardened Python project should:

1. **resolve to a hash-verified lock** (``uv.lock`` / ``poetry.lock`` / a
   ``requirements*.txt`` carrying ``--hash=`` lines) so installs are integrity-
   checked, not just version-pinned;
2. **configure an install "release-age" cooldown** (uv ``exclude-newer`` /
   ``UV_EXCLUDE_NEWER``) so a freshly published — possibly compromised — version
   is not adopted until it has been public long enough to be caught and yanked
   (the consumer-side defense for incidents like the May-2026 TanStack npm
   compromise: 84 malicious versions, caught in ~20 min). Recommended window: 48h;
3. **pin direct dependencies** (``==``) and resolve from a **single trusted
   index** (no ``--extra-index-url`` / ``unsafe-best-match`` / ``http://`` —
   the dependency-confusion vectors); and
4. keep its **CVE waiver database** (``pip-audit-exceptions.json``) honest — every
   entry carries an expiring ``review_by`` (no silent forever-ignores).

pip itself has **no** native cooldown and **no** expiring-waiver mechanism, so the
remediations point at ``uv``.

Findings:
- ``python-supply-chain/no-locked-hashes`` — deps without a hash-verified lock (HIGH).
- ``python-supply-chain/no-cooldown`` — no ``exclude-newer`` configured (MEDIUM).
- ``python-supply-chain/cooldown-too-short`` — cooldown < 48h (LOW).
- ``python-supply-chain/unpinned`` — loose/absent direct version specifiers (MEDIUM).
- ``python-supply-chain/extra-index-url`` — multi-index / ``unsafe-best-match`` (MEDIUM).
- ``python-supply-chain/insecure-index`` — plain ``http://`` index (HIGH).
- ``python-supply-chain/exception-no-expiry`` — CVE waiver without ``review_by`` (MEDIUM).
- ``python-supply-chain/exception-lapsed`` — CVE waiver past ``review_by`` (MEDIUM).

The cooldown/index checks honor a ``# security: allow-no-cooldown`` /
``# security: allow-extra-index`` comment in the file (explicit, documented opt-outs; a
quoted TOML or ``.env`` value carrying the phrase does not count), mirroring the
allow-pragma convention of the other guards. Dependency-free (stdlib
``tomllib``); never raises.
"""
from __future__ import annotations

import json
import re
import tomllib
from datetime import date
from pathlib import Path

from agentsec.detect import NONPRODUCT_DIR_ALT, StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

# Nonproduct path segments (same set as guards/base.py _NONPROD_PATH) — skip
# pyproject.toml / requirements.txt files inside test/docs/example trees; those are
# scaffolding for tutorials and tests, not the app's actual dependency declarations.
_NONPROD_SEG = re.compile(rf"(?:^|/)(?:{NONPRODUCT_DIR_ALT})(?:/|$)")

_REQUIRED_HOURS = 48
_ALLOW_COOLDOWN = "security: allow-no-cooldown"
_ALLOW_INDEX = "security: allow-extra-index"
_STANDARDS = ["OWASP-LLM:LLM03", "OWASP:A06"]

_HASHED_LOCKS = ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock")
_EXCEPTIONS_FILE = "pip-audit-exceptions.json"

# uv friendly durations ("48 hours", "2 days", "1 week") → hours.
_FRIENDLY_DUR = re.compile(r"(\d+(?:\.\d+)?)\s*(second|minute|hour|day|week|month|year)s?", re.I)
_ISO_DUR = re.compile(r"^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$", re.I)
_UNIT_HOURS = {
    "second": 1 / 3600,
    "minute": 1 / 60,
    "hour": 1.0,
    "day": 24.0,
    "week": 168.0,
    "month": 730.0,
    "year": 8760.0,
}

# Index flags in requirements / pip.conf text.
_INDEX_URL_RE = re.compile(r"(?:--extra-index-url|--index-url|-i)[ =]+(\S+)")
_EXTRA_INDEX_URL_RE = re.compile(r"--extra-index-url[ =]+(\S+)")

# Well-known additional indexes that are NOT a dependency-confusion vector: they serve packages
# (CPU/CUDA torch wheels) that are not published to PyPI in that build, from a trusted vendor host.
# An extra index limited to these is benign; any OTHER extra index (or `unsafe-best-match`) still fires.
_BENIGN_INDEX_HOSTS = ("download.pytorch.org", "pytorch.org/whl", "data.pyg.org")


def _is_benign_index(url: str) -> bool:
    return any(h in url for h in _BENIGN_INDEX_HOSTS)


# ---------------------------------------------------------------------------
# Module helpers (stdlib only)
# ---------------------------------------------------------------------------

def _decode(path: Path) -> str:
    """Read text, honoring a UTF-16/UTF-8 BOM (the starter requirements.txt is
    UTF-16; the default utf-8 reader would mangle it and break == / --hash detection)."""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="ignore")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw.decode("utf-8-sig", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def _load_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _table(d: dict[str, object], *keys: str) -> dict[str, object]:
    """Walk nested TOML tables; return {} if any hop is missing/not a table."""
    cur: object = d
    for k in keys:
        if not isinstance(cur, dict):
            return {}
        cur = cur.get(k)
    return cur if isinstance(cur, dict) else {}


def _parse_duration_hours(value: str) -> float | None:
    """Hours for a uv ``exclude-newer`` duration, or None for a date/timestamp
    form (a hard cutoff — counts as 'configured', not a rolling window) or an
    unparseable value."""
    s = value.strip()
    if not s or re.match(r"^\d{4}-\d{2}-\d{2}", s):  # date / RFC-3339 timestamp
        return None
    iso = _ISO_DUR.match(s)
    if iso and any(iso.groups()):
        w, d, h, mi, se = (int(x) if x else 0 for x in iso.groups())
        return w * 168 + d * 24 + h + mi / 60 + se / 3600
    total = 0.0
    found = False
    for m in _FRIENDLY_DUR.finditer(s):
        found = True
        total += float(m.group(1)) * _UNIT_HOURS[m.group(2).lower()]
    return total if found else None


def _loose_dep_name(spec: str) -> str | None:
    """The package name if ``spec`` (a PEP 508 / requirements line) is unpinned
    (loose operator or no specifier), else None. Heuristic, not a full resolver."""
    s = spec.split(";", 1)[0].strip()  # drop env marker
    if not s:
        return None
    if "@" in s or "://" in s or s.startswith((".", "/", "-")):
        return None  # direct URL / VCS / path / option line — explicit, skip
    name = re.split(r"[<>=!~^ \[]", s, maxsplit=1)[0].strip()
    if not name:
        return None
    if "==" in s or "===" in s:
        return None  # pinned
    if re.search(r"(>=|<=|>|<|~=|!=|\^|\*)", s):
        return name  # loose operator
    if re.fullmatch(r"[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?", s):
        return name  # bare name, no specifier
    return None


def _project_deps(data: dict[str, object]) -> list[str]:
    """Direct PEP 621 deps from [project].dependencies + optional-dependencies."""
    out: list[str] = []
    proj = _table(data, "project")
    deps = proj.get("dependencies")
    if isinstance(deps, list):
        out += [x for x in deps if isinstance(x, str)]
    opt = proj.get("optional-dependencies")
    if isinstance(opt, dict):
        for group in opt.values():
            if isinstance(group, list):
                out += [x for x in group if isinstance(x, str)]
    return out


def _pyproject_has_deps(data: dict[str, object]) -> bool:
    proj = _table(data, "project")
    if isinstance(proj.get("dependencies"), list) and proj.get("dependencies"):
        return True
    if isinstance(proj.get("optional-dependencies"), dict) and proj.get("optional-dependencies"):
        return True
    return bool(_table(data, "tool", "poetry"))  # poetry project


def dependency_dirs(root: Path, profile: StackProfile) -> list[Path]:  # noqa: ARG001
    """Dirs that declare Python deps (a pyproject with deps, or a
    requirements*.txt), de-duplicated. Shared by the guard and `harden-python`."""
    dirs: set[Path] = set()
    for f in iter_files(root, (".txt", ".toml")):
        # Skip manifests inside test / docs / example trees — those are scaffolding.
        rel_str = f.relative_to(root).as_posix()
        if _NONPROD_SEG.search(rel_str):
            continue
        if f.name == "pyproject.toml":
            data = _load_toml(f)
            if not _pyproject_has_deps(data):
                continue
            # Skip publishable sub-packages in a monorepo: a pyproject.toml with
            # [build-system] that lives below the repo root is a library sub-package.
            # Its consumers manage the lockfile; scanning it produces noise on every
            # monorepo (langchain, pydantic-ai, etc. each have hundreds of them).
            if f.parent != root and _table(data, "build-system"):
                continue
            dirs.add(f.parent)
        elif re.fullmatch(r"requirements.*\.txt", f.name):
            dirs.add(f.parent)
    return sorted(dirs)


def _req_files(dep_dir: Path) -> list[Path]:
    return sorted(p for p in dep_dir.glob("requirements*.txt") if p.is_file())


def _has_hashed_lock(dep_dir: Path) -> bool:
    """True if this dir resolves through a hash-verified lock — a `_HASHED_LOCKS` file, or a
    `requirements*.txt` with `--hash=` lines (e.g. `requirements-locked.txt`). When present, the
    pyproject / abstract requirements are the *source*, not the install set: their loose specifiers
    are pinned to exact hashed versions in the lock, so flagging them `unpinned` is a false positive."""
    return any((dep_dir / lf).is_file() for lf in _HASHED_LOCKS) or any(
        "--hash=" in _decode(f) for f in _req_files(dep_dir)
    )


def _primary_manifest(dep_dir: Path) -> Path:
    pp = dep_dir / "pyproject.toml"
    if pp.is_file():
        return pp
    reqs = _req_files(dep_dir)
    return reqs[0] if reqs else dep_dir


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

class PythonSupplyChainGuard(Guard):
    id = "python-supply-chain"
    title = "Python (uv) dependency supply-chain hardening (lockfile + hashes + cooldown)"
    area = "Dependencies"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # Canary plant: EXPECTS-ONLY — no `files`. Two of its rules anchor in the canary's shared
    # `requirements.txt` (which `dependency-version-floor` also trips) and `no-cooldown` anchors at the repo
    # root, which is no file at all — so there is nothing to own and the manifest stays in `canary.py`'s base.
    # The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({
        "python-supply-chain/no-locked-hashes",
        "python-supply-chain/no-cooldown",
        "python-supply-chain/unpinned",
    }))

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for dep_dir in dependency_dirs(root, profile):
            out.extend(self._check_lock_hashes(root, dep_dir))
            out.extend(self._check_cooldown(root, dep_dir))
            out.extend(self._check_pinning_and_index(root, dep_dir))
        out.extend(self._check_exception_db(root, profile.today))
        return out

    # --- 1. hashes / lock integrity --------------------------------------

    def _check_lock_hashes(self, root: Path, dep_dir: Path) -> list[Finding]:
        if _has_hashed_lock(dep_dir):
            return []
        manifest = _primary_manifest(dep_dir)
        return [
            Finding(
                check_id=self.id,
                severity="high",
                title="Dependencies without a hash-verified lock",
                location=rel(root, manifest),
                message=(
                    "Python dependencies here resolve without a hash-verified lock "
                    f"({' / '.join(_HASHED_LOCKS)}, or a requirements file with "
                    "`--hash=` lines) — installs aren't integrity-checked and can pull "
                    "a tampered or substituted artifact."
                ),
                remediation=(
                    "Generate a hashed lock with uv (`uv lock`, or "
                    "`uv pip compile requirements.txt -o requirements-locked.txt "
                    "--generate-hashes`) and install with `uv sync --frozen` / "
                    "`pip install --require-hashes`."
                ),
                rule="python-supply-chain/no-locked-hashes",
                standards=_STANDARDS,
            )
        ]

    # --- 2. release-age cooldown -----------------------------------------

    def _check_cooldown(self, root: Path, dep_dir: Path) -> list[Finding]:
        durations: list[float | None] = []
        configured = False
        suppressed = False

        def consume(value: object) -> None:
            nonlocal configured
            if isinstance(value, str):
                configured = True
                durations.append(_parse_duration_hours(value))

        pp = dep_dir / "pyproject.toml"
        if pp.is_file():
            consume(_table(_load_toml(pp), "tool", "uv").get("exclude-newer"))
            if pragma_present(_ALLOW_COOLDOWN, _decode(pp), dialect="hash"):
                suppressed = True

        seen: set[Path] = set()
        for base in (dep_dir, root):
            ut = base / "uv.toml"
            if ut not in seen and ut.is_file():
                seen.add(ut)
                data = _load_toml(ut)
                consume(data.get("exclude-newer"))
                if pragma_present(_ALLOW_COOLDOWN, _decode(ut), dialect="hash"):
                    suppressed = True
            for envf in sorted(base.glob(".env*")):
                if envf in seen or not envf.is_file():
                    continue
                seen.add(envf)
                text = _decode(envf)
                if pragma_present(_ALLOW_COOLDOWN, text, dialect="hash"):
                    suppressed = True
                # Strip `#` comments so a commented-out `# UV_EXCLUDE_NEWER=1h` in a .env is NOT
                # counted as a configured cooldown (a false negative that would hide the
                # missing-cooldown finding, issue #424).
                m = re.search(r'UV_EXCLUDE_NEWER\s*=\s*"?([^"\n]+)', strip_hash_comments(text))
                if m:
                    consume(m.group(1).strip())

        if suppressed:
            return []
        if not configured:
            return [
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="No dependency install cooldown configured",
                    location=rel(root, pp if pp.is_file() else dep_dir),
                    message=(
                        "No release-age cooldown (`exclude-newer` / `UV_EXCLUDE_NEWER`) "
                        "is configured — a freshly published, possibly compromised "
                        "version can be adopted immediately. (A cooldown set only on the "
                        "uv CLI isn't committed config and is still flagged.)"
                    ),
                    remediation=(
                        f'Add `exclude-newer = "{_REQUIRED_HOURS} hours"` to `[tool.uv]` '
                        "in pyproject.toml (or set `UV_EXCLUDE_NEWER`) to wait 48h before "
                        "adopting new versions."
                    ),
                    rule="python-supply-chain/no-cooldown",
                    standards=_STANDARDS,
                )
            ]
        known = [d for d in durations if d is not None]
        if known and max(known) < _REQUIRED_HOURS:
            return [
                Finding(
                    check_id=self.id,
                    severity="low",
                    title="Dependency install cooldown is shorter than 48h",
                    location=rel(root, pp if pp.is_file() else dep_dir),
                    message=(
                        f"Configured `exclude-newer` is {max(known):g}h; the recommended "
                        f"minimum is {_REQUIRED_HOURS}h."
                    ),
                    remediation=f'Raise it to at least `exclude-newer = "{_REQUIRED_HOURS} hours"`.',
                    rule="python-supply-chain/cooldown-too-short",
                    standards=_STANDARDS,
                )
            ]
        return []

    # --- 3. pinning + dependency-confusion -------------------------------

    def _check_pinning_and_index(self, root: Path, dep_dir: Path) -> list[Finding]:
        out: list[Finding] = []
        loose: list[str] = []
        index_suppressed = False
        unsafe_strategy = False
        http_urls: list[str] = []
        extra_index_urls: list[str] = []

        pp = dep_dir / "pyproject.toml"
        if pp.is_file():
            data = _load_toml(pp)
            if pragma_present(_ALLOW_INDEX, _decode(pp), dialect="hash"):
                index_suppressed = True
            for spec in _project_deps(data):
                name = _loose_dep_name(spec)
                if name:
                    loose.append(name)
            tool_uv = _table(data, "tool", "uv")
            extra = tool_uv.get("extra-index-url")
            if isinstance(extra, str):
                extra_index_urls.append(extra)
            elif isinstance(extra, list):
                extra_index_urls += [u for u in extra if isinstance(u, str)]
            if tool_uv.get("index-strategy") == "unsafe-best-match":
                unsafe_strategy = True
            http_urls += _http_index_urls(tool_uv)

        for f in _req_files(dep_dir):
            text = _decode(f)
            if pragma_present(_ALLOW_INDEX, text, dialect="hash"):
                index_suppressed = True
            # Comment-aware view for the index-URL scan so a commented `# --extra-index-url http://…`
            # in a requirements file isn't counted as a real insecure index (issue #424).
            stripped_text = strip_hash_comments(text)
            for line in text.splitlines():
                stripped = strip_hash_comments(line).rstrip(" \\").strip()
                name = _loose_dep_name(stripped)
                if name:
                    loose.append(name)
            extra_index_urls += _EXTRA_INDEX_URL_RE.findall(stripped_text)
            http_urls += [u for u in _INDEX_URL_RE.findall(stripped_text) if u.startswith("http://")]

        # An extra index limited to well-known vendor wheel hosts (PyTorch CPU/CUDA) is not a
        # dependency-confusion vector; only a NON-benign extra index (or unsafe-best-match) is.
        non_benign_extra = any(not _is_benign_index(u) for u in extra_index_urls)

        # A hashed lock makes the pyproject / abstract requirements the source, not the install set,
        # so their loose specifiers are pinned in the lock — flagging them `unpinned` is a false positive.
        if loose and not _has_hashed_lock(dep_dir):
            uniq = sorted(dict.fromkeys(loose))
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="Unpinned direct dependencies",
                    location=rel(root, _primary_manifest(dep_dir)),
                    message=(
                        f"{len(uniq)} direct dependency(ies) use a loose/absent version "
                        f"specifier (e.g. {', '.join(uniq[:5])}) — a build can resolve to "
                        "a newer (possibly compromised) release than was reviewed."
                    ),
                    remediation="Pin with `==` and let `uv lock` resolve the full graph.",
                    rule="python-supply-chain/unpinned",
                    standards=_STANDARDS,
                )
            )

        if not index_suppressed and (non_benign_extra or unsafe_strategy):
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="Multi-index resolution (dependency-confusion risk)",
                    location=rel(root, _primary_manifest(dep_dir)),
                    message=(
                        "An `extra-index-url` / `unsafe-best-match` strategy lets a public "
                        "index outrank your private one for the same name (dependency "
                        "confusion)."
                    ),
                    remediation=(
                        "Resolve from a single `index-url` (a registry that proxies PyPI) "
                        'and keep `index-strategy = "first-index"`.'
                    ),
                    rule="python-supply-chain/extra-index-url",
                    standards=_STANDARDS,
                )
            )

        if http_urls:
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="Package index served over plain HTTP",
                    location=rel(root, _primary_manifest(dep_dir)),
                    message=f"Index URL uses http:// (man-in-the-middle risk): {http_urls[0]}",
                    remediation="Use an https:// index URL.",
                    rule="python-supply-chain/insecure-index",
                    standards=_STANDARDS,
                )
            )
        return out

    # --- 4. CVE waiver hygiene -------------------------------------------

    def _check_exception_db(self, root: Path, today: date | None) -> list[Finding]:
        # `today` is threaded in from audit() (never read off the wall clock here) so
        # the guard is a pure function of file bytes + the explicit date. When it is
        # None (a guard run outside audit, e.g. a unit test that didn't set it), the
        # structural checks still fire but the lapse comparison is skipped — a missing
        # date can't make a waiver "lapsed", and it never falls back to date.today().
        out: list[Finding] = []
        for f in iter_files(root, (".json",)):
            if f.name != _EXCEPTIONS_FILE:
                continue
            try:
                data = json.loads(read(f) or "{}")
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            excs = data.get("exceptions")
            if not isinstance(excs, list):
                continue
            for e in excs:
                if not isinstance(e, dict):
                    continue
                ident = str(e.get("id") or e.get("package") or "?")
                rb = e.get("review_by")
                if not rb or not isinstance(rb, str):
                    out.append(self._exc_finding(root, f, ident, expired=False))
                    continue
                if today is None:
                    continue  # no explicit date → can't evaluate lapse (stay pure)
                try:
                    lapsed = date.fromisoformat(rb) < today
                except ValueError:
                    out.append(self._exc_finding(root, f, ident, expired=False))
                    continue
                if lapsed:
                    out.append(self._exc_finding(root, f, ident, expired=True))
        return out

    def _exc_finding(self, root: Path, f: Path, ident: str, *, expired: bool) -> Finding:
        if expired:
            return Finding(
                check_id=self.id,
                severity="medium",
                title="Lapsed CVE waiver",
                location=rel(root, f),
                message=f"CVE waiver '{ident}' is past its review_by — re-triage or remove it.",
                remediation="Re-evaluate the vulnerability; bump the fix or set a new review_by.",
                rule="python-supply-chain/exception-lapsed",
                standards=_STANDARDS,
            )
        return Finding(
            check_id=self.id,
            severity="medium",
            title="CVE waiver without an expiry",
            location=rel(root, f),
            message=f"CVE waiver '{ident}' has no valid `review_by` — a silent forever-ignore.",
            remediation="Add a `review_by` date so the waiver expires and re-surfaces for review.",
            rule="python-supply-chain/exception-no-expiry",
            standards=_STANDARDS,
        )


def _http_index_urls(tool_uv: dict[str, object]) -> list[str]:
    """Collect http:// index URLs from a [tool.uv] table (index-url,
    extra-index-url, [[tool.uv.index]].url)."""
    urls: list[str] = []
    for key in ("index-url", "extra-index-url"):
        val = tool_uv.get(key)
        if isinstance(val, str):
            urls.append(val)
        elif isinstance(val, list):
            urls += [v for v in val if isinstance(v, str)]
    indexes = tool_uv.get("index")
    if isinstance(indexes, list):
        for entry in indexes:
            if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                urls.append(entry["url"])
    return [u for u in urls if u.startswith("http://")]
