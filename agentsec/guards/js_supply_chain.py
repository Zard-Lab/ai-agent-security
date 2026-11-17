"""Guard: JS/TS dependencies need a lockfile, cooldown, script-blocking, pinning.

Supply-chain hardening (OWASP-LLM **LLM03 — Supply Chain**); the JS/TS sibling of
the ``python-supply-chain`` guard. Derived from how the production app migrated
**npm → pnpm 11** and added a documented ``.npmrc`` + ``pnpm-workspace.yaml``
hardening recipe. The consumer-side defense against worms like **Shai-Hulud**
(Sept 2025: a ``postinstall`` worm that ran TruffleHog, stole npm tokens, and
self-republished into ~500 packages incl. ``@ctrl/tinycolor``; Nov 2025 "Second
Coming": moved to ``preinstall``, ~796 packages / 25k+ repos, destructive payload).

A hardened JS/TS project should:

1. **commit a lockfile** (``pnpm-lock.yaml`` / ``package-lock.json`` / ``yarn.lock``
   / ``bun.lockb`` / ``bun.lock``) and build ``--frozen-lockfile``;
2. **block install lifecycle scripts** — npm ``ignore-scripts=true``; pnpm 10+
   blocks build scripts by default (allowlist via ``onlyBuiltDependencies`` /
   ``allowBuilds``; never ``dangerouslyAllowAllBuilds``). This is THE Shai-Hulud
   defense — the worm runs on ``postinstall``/``preinstall``;
3. **configure a release-age cooldown** — npm ``min-release-age`` (days) / pnpm
   ``minimumReleaseAge`` (minutes) — so a freshly published, possibly compromised
   version is not adopted until it has aged past the detection window (48h);
4. **pin direct deps** (no ``^``/``~``/``*``/``latest``/partial) and resolve from a
   **single trusted registry** (no ``http://``, no disabled exotic-subdep blocking).

Findings (rule prefix ``js-supply-chain/``): ``lockfile-missing`` (HIGH),
``lockfile-manifest-drift`` (MEDIUM), ``lifecycle-scripts`` (HIGH), ``no-cooldown``
(MEDIUM), ``cooldown-too-short`` (LOW), ``unpinned`` (MEDIUM), ``insecure-registry``
(HIGH), ``exotic-subdeps`` (MEDIUM), ``insecure-dependency-transport`` (HIGH),
``no-packagemanager-pin`` (LOW), ``packagemanager-vulnerable`` (HIGH),
``trust-downgrade`` (LOW).

``lockfile-manifest-drift`` (MEDIUM) is distinct from ``lockfile-missing``: a
dependency declared in ``package.json`` that does not appear anywhere in the committed
``package-lock.json``/``npm-shrinkwrap.json``'s resolved set means the manifest was edited
without regenerating the lockfile — the two files disagree about what's actually installed.
Scoped to npm-format lockfiles only (``pnpm-lock.yaml``/``yarn.lock`` are YAML/custom text
formats agentsec's stdlib-only design doesn't parse). Suppress with ``security:
allow-lockfile-manifest-drift`` in ``.npmrc``/``pnpm-workspace.yaml`` (not ``package.json``
itself — a ``#``/``//`` comment there would break JSON parsing of the manifest it's meant to
annotate, the same reason every other pragma in this guard lives in those two files too).

``insecure-dependency-transport`` (HIGH) is a distinct, more specific rule than the
generic ``unpinned``/exotic-source classification: a direct dependency whose version
spec resolves over plaintext ``http://``/``ftp://`` (not ``https://``, not
``git+http://`` — a different, already-covered git-protocol-source case) is a
CWE-300-style MITM exposure (see CodeQL's
``javascript/ql/src/Security/CWE-300/InsecureDependencyResolution.ql``), not merely an
unpinned version. When it fires for a given dependency, that dependency is excluded
from the generic ``unpinned`` finding's tally for the same manifest — the more specific
rule wins so the same dependency doesn't read as two findings.

Honors inline opt-out pragmas (``security: allow-no-cooldown`` /
``allow-lifecycle-scripts`` / ``allow-exotic-subdeps``) in ``.npmrc`` /
``pnpm-workspace.yaml``. ``insecure-dependency-transport`` reuses
``allow-exotic-subdeps`` (a plaintext-URL dependency is a kind of exotic source).
Dependency-free; never raises.

Note the cooldown key/unit matrix: pnpm ``minimum-release-age`` (.npmrc, minutes)
& ``minimumReleaseAge`` (pnpm-workspace.yaml / package.json, minutes) vs npm
``min-release-age`` (.npmrc, **days**). All normalized to minutes.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    CommentDialect,
    Guard,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)
from .dependency_version_floor import (
    _FLOORS_PATH,
    _fixed_str,
    _fixed_versions,
    _version,
    _vulnerable,
)

# `packageManager` pin: "<tool>@<version>" (Corepack), e.g. "pnpm@11.1.2", optional +hash suffix.
_PM_PIN = re.compile(r"^([a-z][a-z0-9-]*)@(\d[\w.\-]*)")


def _packagemanager_floors() -> list[dict[str, object]]:
    """The version_floors.json entries scoped to the packageManager toolchain (pnpm/npm/yarn),
    keyed by ecosystem so they never collide with the pip/npm dependency floors. Total: a
    missing/malformed file yields no floors (the guard simply skips the CVE check)."""
    try:
        data = json.loads(_FLOORS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [
        f
        for f in data.get("floors", [])
        if isinstance(f, dict) and f.get("ecosystem") == "packageManager"
    ]


_LOCKFILES = (
    "pnpm-lock.yaml",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "bun.lockb",
    "bun.lock",
)
_REQUIRED_MINUTES = 2880  # 48 hours
_STANDARDS = ["OWASP-LLM:LLM03", "OWASP:A06"]

_ALLOW_COOLDOWN = "security: allow-no-cooldown"
_ALLOW_SCRIPTS = "security: allow-lifecycle-scripts"
_ALLOW_EXOTIC = "security: allow-exotic-subdeps"
_ALLOW_LOCKFILE_DRIFT = "security: allow-lockfile-manifest-drift"

# Cooldown sources (tolerant regexes; agentsec core is stdlib-only — no YAML dep).
_MIN_AGE_NPMRC = re.compile(r"^[^\S\n]*minimum-release-age\s*=\s*(\d+)", re.M)   # pnpm .npmrc, minutes
_MIN_AGE_NPM = re.compile(r"^[^\S\n]*min-release-age\s*=\s*(\d+)", re.M)         # npm .npmrc, DAYS
_MIN_AGE_YAML = re.compile(r"^[^\S\n]*minimumReleaseAge\s*:\s*(\d+)", re.M)      # pnpm-workspace.yaml, minutes
_MIN_AGE_JSON = re.compile(r'"minimumReleaseAge"\s*:\s*(\d+)')             # package.json pnpm block

_IGNORE_SCRIPTS = re.compile(r"^[^\S\n]*ignore-scripts\s*=\s*true\s*$", re.M | re.I)
_DANGEROUS_BUILDS = re.compile(r"dangerouslyAllowAllBuilds\s*[:=]\s*true", re.I)

# npm lifecycle hooks that run automatically on install — the supply-chain risk vector.
# dev-only hooks (build/dev/test/lint) do NOT run on install and are not a risk.
_OWN_LIFECYCLE = frozenset({"postinstall", "preinstall", "prepare"})
# `[^\S\n]*` after the optional `^`: an .npmrc key is preceded only by same-line indentation. With
# `\s*` the `^` arm anchored at every blank line and then scanned the rest of the run before failing
# on `registry` — quadratic in the run length (#697).
_HTTP_REGISTRY = re.compile(r"(?:^|@[\w.-]+:)?[^\S\n]*registry\s*=\s*(http://\S+)", re.M | re.I)
_EXOTIC_OFF = re.compile(r"block[-_]?exotic[-_]?subdeps\s*[:=]\s*false", re.I)
_TRUST_NO_DOWNGRADE = re.compile(r"trustPolicy\s*[:=]\s*['\"]?no-downgrade", re.I)


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict[str, object]:
    try:
        obj = json.loads(read(path) or "{}")
    except (json.JSONDecodeError, ValueError):
        return {}
    return obj if isinstance(obj, dict) else {}


def _npm_lockfile_resolved_names(lock_data: dict[str, object]) -> set[str] | None:
    """Names of dependencies an npm-format lockfile actually resolves, or None if the shape
    isn't one this check understands. Scoped to npm's `package-lock.json` /
    `npm-shrinkwrap.json` only — yarn.lock/pnpm-lock.yaml are YAML/custom text formats and
    agentsec is stdlib-only (no YAML dependency), so those two are silently not checked
    rather than guessed at with a fragile text parse.

    `lockfileVersion` 2/3 use a flat `packages` map keyed by path (`node_modules/<name>`, a
    scoped package as `node_modules/@scope/name`, the root project itself as `""`); a
    version-conflict hoists the loser under a NESTED `node_modules/`, so the key is taken
    after the LAST `node_modules/` segment, not the first, or every nested dependency would
    read as declared-but-unresolved. `lockfileVersion` 1 uses a `dependencies` map keyed
    directly by name."""
    packages = lock_data.get("packages")
    if isinstance(packages, dict):
        names: set[str] = set()
        for key in packages:
            if not isinstance(key, str) or "node_modules/" not in key:
                continue
            names.add(key.rsplit("node_modules/", 1)[-1])
        return names
    deps = lock_data.get("dependencies")
    if isinstance(deps, dict):
        return {k for k in deps if isinstance(k, str)}
    return None


def _declares_deps(data: dict[str, object]) -> bool:
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        val = data.get(key)
        if isinstance(val, dict) and val:
            return True
    return False


def js_dependency_dirs(root: Path) -> list[Path]:
    """Dirs with a package.json that declares dependencies (shared with harden-js)."""
    dirs: set[Path] = set()
    for manifest in iter_files(root, (".json",)):
        if manifest.name == "package.json" and _declares_deps(_load_json(manifest)):
            dirs.add(manifest.parent)
    return sorted(dirs)


def ancestors(pkg_dir: Path, root: Path) -> list[Path]:
    """`pkg_dir` and every parent up to (and including) `root`.

    Lets a workspace sub-package inherit the lockfile / `.npmrc` /
    `pnpm-workspace.yaml` that lives at the workspace root (e.g. a package under
    ``frontend/packages/ui`` sees ``frontend/`` and the repo root)."""
    dirs = [pkg_dir]
    try:
        steps = len(pkg_dir.relative_to(root).parts)
    except ValueError:
        return dirs  # pkg_dir not under root
    cur = pkg_dir
    for _ in range(steps):
        cur = cur.parent
        dirs.append(cur)
    return dirs


def is_pnpm(dirs: list[Path], data: dict[str, object]) -> bool:
    """True if the project uses pnpm (which blocks build scripts by default).

    `dirs` is the package dir + its workspace ancestors (see `ancestors`)."""
    for d in dirs:
        if (d / "pnpm-lock.yaml").is_file() or (d / "pnpm-workspace.yaml").is_file():
            return True
    pm = data.get("packageManager")
    if isinstance(pm, str) and pm.startswith("pnpm"):
        return True
    engines = data.get("engines")
    return isinstance(engines, dict) and "pnpm" in engines


def _is_floating(spec: str) -> bool:
    """Heuristic: True if a package.json dep spec is a floating/exotic range."""
    s = spec.strip()
    if not s or s.startswith(("workspace:", "catalog:", "link:")):
        return False  # internal protocols
    if s.startswith("npm:"):  # alias: npm:pkg@1.2.3 — judge the version part
        # Strip the prefix first so we don't re-enter this branch; an unversioned alias
        # (`npm:bar`, no `@`) is floating (resolves to latest). rsplit on the bare inner
        # avoids the `"npm:bar".rsplit("@",1)[-1] == "npm:bar"` self-recursion (RecursionError).
        inner = s[len("npm:"):]
        return _is_floating(inner.rsplit("@", 1)[-1]) if "@" in inner else True
    if s.startswith(("git+", "git:", "github:", "http://", "https://", "file:")):
        return True  # exotic source
    if s in ("*", "latest", "x"):
        return True
    if s.startswith(("^", "~", ">", "<")):
        return True
    if s.startswith("="):
        return False  # =1.2.3 exact
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return True  # partial: "19" / "5.2" == 19.x / 5.2.x
    if re.fullmatch(r"\d+\.\d+\.\d+([-+].*)?", s):
        return False  # exact 1.2.3 (+ prerelease/build)
    # x-ranges / OR / hyphen ranges → floating; anything else unknown → treat as pinned
    return any(c in s for c in ("x", "X", "*", "|", " ", ","))


# Plaintext transport a dependency can itself be fetched over — the CWE-300 MITM case
# (CodeQL InsecureDependencyResolution.ql). Deliberately NOT `https://` (transport is fine,
# only unpinned) and matched via `startswith` (exact prefix) so `git+http://github.com/...`
# (a git-protocol source, `_is_floating`'s existing `git+` exotic-source case) does not match —
# only a spec whose OWN scheme is plaintext http/ftp does.
_INSECURE_TRANSPORT = ("http://", "ftp://")


def _insecure_transport_spec(spec: str) -> bool:
    """True if a package.json dep version spec fetches the package directly over
    plaintext http/ftp (not https, not git+http — see `_INSECURE_TRANSPORT`)."""
    return spec.strip().startswith(_INSECURE_TRANSPORT)


def _pm_pin_tool(data: dict[str, object]) -> str | None:
    """The Corepack `packageManager` pin's tool name (the segment before the first `@`), or None
    if the field is absent/not a string/carries no `@` at all.

    Deliberately a bare split on the first `@`, NOT `_PM_PIN` (which also requires the version
    half to be digit-led and well-formed) — presence-vs-recency only needs to know
    WHICH tool is pinned, not whether the version half parses; an exotic/malformed version suffix
    still names the tool just as reliably. Unparsed format, by design."""
    pm = data.get("packageManager")
    if not isinstance(pm, str) or "@" not in pm:
        return None
    return pm.split("@", 1)[0].strip().lower() or None


def _pm_pin_tool_chain(chain: list[Path], data: dict[str, object]) -> str | None:
    """`_pm_pin_tool`, walked up the workspace `chain` — mirrors `is_pnpm`'s own chain walk
    (PR #737 review finding 1). `packageManager` conventionally lives only in a
    workspace's ROOT manifest, while the manifests `_gather` actually scans for drift are the
    sub-packages that declare dependencies — a sub-package with no pin of its own must inherit
    the nearest ancestor's, or a root-level npm pin never reaches its own workspace's drift check.
    `data` (already parsed for `chain[0]`) is reused rather than re-read from disk."""
    for i, d in enumerate(chain):
        pm_data = data if i == 0 else _load_json(d / "package.json")
        tool = _pm_pin_tool(pm_data)
        if tool is not None:
            return tool
    return None


@dataclass
class _Signals:
    cooldown_min: int | None
    suppress_cooldown: bool
    is_pnpm: bool
    pm_pin_tool: str | None
    ignore_scripts: bool
    dangerous_builds: bool
    allow_scripts: bool
    http_registry: str | None
    exotic_off: bool
    allow_exotic: bool
    trust_no_downgrade: bool
    suppress_lockfile_drift: bool


class JsSupplyChainGuard(Guard):
    id = "js-supply-chain"
    title = "JS/TS dependency supply-chain hardening (lockfile, cooldown, scripts, pinning, registry)"
    area = "Dependencies"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # "react" stays unpinned (^-prefixed) for js-supply-chain/unpinned; "legacy-widget" is an
    # http:// dependency URL -> fires js-supply-chain/insecure-dependency-transport,
    # a distinct rule from the generic unpinned/exotic-subdeps path "react" exercises.
    canary_plant = CanaryPlant(
        files={
            "frontend/package.json": (
                '{\n  "name": "canary-frontend",\n  "dependencies": {\n'
                '    "react": "^18.3.0",\n'
                '    "legacy-widget": "http://example.com/legacy-widget.tgz"\n'
                "  }\n}\n"
            ),
        },
        expects=frozenset({
            "js-supply-chain/lockfile-missing",
            "js-supply-chain/unpinned",
            "js-supply-chain/insecure-dependency-transport",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features or bool(
            profile.package_managers & {"pnpm", "npm", "bun", "yarn"}
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for pkg_dir in js_dependency_dirs(root):
            manifest = pkg_dir / "package.json"
            data = _load_json(manifest)
            chain = ancestors(pkg_dir, root)
            sig = self._gather(chain, data)
            out.extend(self._check_lockfile(root, chain, manifest))
            out.extend(self._check_lockfile_drift(root, chain, manifest, data, sig))
            out.extend(self._check_lifecycle(root, manifest, data, sig))
            out.extend(self._check_cooldown(root, manifest, sig))
            out.extend(self._check_pinning(root, manifest, data, chain, sig))
            out.extend(self._check_insecure_transport(root, manifest, data, sig))
            out.extend(self._check_packagemanager(root, manifest, data))
            out.extend(self._check_registry_exotic(root, manifest, sig))
            out.extend(self._check_trust(root, manifest, sig))
        return out

    # --- signal gathering ------------------------------------------------

    def _gather(self, chain: list[Path], data: dict[str, object]) -> _Signals:
        # `chain` = the package dir + its workspace ancestors up to the repo root,
        # so a sub-package inherits the config that lives at the workspace root.
        blob = read(chain[0] / "package.json")
        # Where the `_ALLOW_*` pragmas are read, per file (#1040 T5). `package.json` has no comment
        # syntax, so its opt-out is a `"//"` string value: raw. `.npmrc` stays raw by the decision in
        # `npm_ignore_scripts.py`: it is ini, where `;` also starts a comment, and the `hash` view
        # would void a `; security: allow-*` line (rule 4). `pnpm-workspace.yaml` takes the `yaml`
        # view, so a YAML scalar quoting the phrase does not count.
        pragma_texts: list[tuple[str, CommentDialect | None]] = [(blob, None)]
        seen: set[Path] = set()
        npmrc_text = ""
        for base in chain:
            for name in (".npmrc", "pnpm-workspace.yaml"):
                p = base / name
                if p in seen or not p.is_file():
                    continue
                seen.add(p)
                text = read(p)
                # `blob` stays RAW for the anchored `_MIN_AGE_*` regexes (comment-safe by their `^\s*`
                # anchor). Comment-awareness for the unanchored flag regexes is handled via `blob_nc`
                # before `_Signals` (issue #424); the pragmas read `pragma_texts` instead.
                blob += "\n" + text
                pragma_texts.append((text, None if name == ".npmrc" else "yaml"))
                if name == ".npmrc":
                    # `.npmrc` is a `#`-comment format; npmrc_text (stripped) feeds
                    # _HTTP_REGISTRY/_IGNORE_SCRIPTS/_MIN_AGE_NPM so a commented `# registry=http://…`
                    # / `# ignore-scripts` / `# min-release-age` doesn't fire (issue #424).
                    npmrc_text += "\n" + strip_hash_comments(text)

        minutes: list[int] = []
        pnpm_cfg = data.get("pnpm")
        if isinstance(pnpm_cfg, dict):
            raw = pnpm_cfg.get("minimumReleaseAge")
            if isinstance(raw, int):
                minutes.append(raw)
            elif isinstance(raw, str) and raw.isdigit():
                minutes.append(int(raw))
        minutes += [int(m) for m in _MIN_AGE_NPMRC.findall(blob)]          # pnpm .npmrc, minutes
        minutes += [int(m) for m in _MIN_AGE_YAML.findall(blob)]           # pnpm-workspace, minutes
        minutes += [int(m) for m in _MIN_AGE_JSON.findall(blob)]           # package.json, minutes
        minutes += [int(m) * 1440 for m in _MIN_AGE_NPM.findall(npmrc_text)]  # npm .npmrc, DAYS

        # Comment-stripped view of blob for the three UNanchored flag regexes only, so a commented
        # `# dangerouslyAllowAllBuilds` / `# blockExoticSubdeps=false` / `# trustPolicy=…` doesn't
        # fire (issue #424 / PR #441 review). The anchored min-age regexes keep using raw blob.
        # package.json JSON in blob is unaffected: a real flag has no ` #`, and stripping only clips a
        # whitespace-prefixed `#` run (not a `#` mid-token).
        blob_nc = strip_hash_comments(blob)

        def allowed(pragma: str) -> bool:
            return any(pragma_present(pragma, text, dialect=d) for text, d in pragma_texts)

        return _Signals(
            cooldown_min=max(minutes) if minutes else None,
            suppress_cooldown=allowed(_ALLOW_COOLDOWN),
            is_pnpm=is_pnpm(chain, data),
            pm_pin_tool=_pm_pin_tool_chain(chain, data),
            ignore_scripts=bool(_IGNORE_SCRIPTS.search(npmrc_text)),
            dangerous_builds=bool(_DANGEROUS_BUILDS.search(blob_nc)),
            allow_scripts=allowed(_ALLOW_SCRIPTS),
            http_registry=(m.group(1) if (m := _HTTP_REGISTRY.search(npmrc_text)) else None),
            exotic_off=bool(_EXOTIC_OFF.search(blob_nc)),
            allow_exotic=allowed(_ALLOW_EXOTIC),
            trust_no_downgrade=bool(_TRUST_NO_DOWNGRADE.search(blob_nc)),
            suppress_lockfile_drift=allowed(_ALLOW_LOCKFILE_DRIFT),
        )

    # --- checks ----------------------------------------------------------

    def _check_lockfile(self, root: Path, chain: list[Path], manifest: Path) -> list[Finding]:
        # A lockfile anywhere from the package dir up to the workspace root counts
        # (npm/pnpm/yarn workspaces keep one lockfile at the workspace root).
        if any((d / lf).is_file() for d in chain for lf in _LOCKFILES):
            return []
        return [
            Finding(
                check_id=self.id, severity="high",
                title="Dependencies without a committed lockfile",
                location=rel(root, manifest),
                message=(
                    "package.json declares dependencies but no lockfile "
                    f"({' / '.join(_LOCKFILES)}) is committed beside it — builds can "
                    "silently resolve to different (possibly malicious) versions."
                ),
                remediation="Commit a lockfile (`pnpm install` → `pnpm-lock.yaml`) and build with `--frozen-lockfile`.",
                rule="js-supply-chain/lockfile-missing", standards=_STANDARDS,
            )
        ]

    def _check_lockfile_drift(
        self, root: Path, chain: list[Path], manifest: Path, data: dict[str, object], sig: _Signals,
    ) -> list[Finding]:
        """a declared dependency missing from the lockfile's resolved set means the
        manifest was edited without regenerating the lockfile — a `--frozen-lockfile` build
        either fails outright or (worse) silently resolves the drifted package unlocked.
        Presence/pinning/hashing are `_check_lockfile`/`_check_pinning`'s job; this is
        specifically about the two files disagreeing with each other. npm-format lockfiles
        only (see `_npm_lockfile_resolved_names`)."""
        if sig.suppress_lockfile_drift:
            return []
        # A stale `package-lock.json` left over from a package-manager migration (documented for
        # this guard's own flagship: "migrated npm -> pnpm 11") is not ground truth once a newer-
        # generation lockfile also exists up the same ancestor chain — it stops being updated on
        # install, so every dependency added since the migration reads as "drifted" even though the
        # project actually builds from the newer lockfile.
        #
        # presence alone is not recency — an ACTIVE, drifting `package-lock.json` next
        # to an ABANDONED `pnpm-lock.yaml`/yarn/bun lockfile also stayed silent here, even with
        # `packageManager` explicitly pinned to npm. `packageManager` is Corepack's own
        # ground-truth declaration of which toolchain a project actually builds with — treated as
        # AUTHORITATIVE over incidental lockfile presence when the two disagree: an explicit `npm`
        # pin runs the drift check regardless of what other lockfiles happen to sit on disk.
        # Anything else (a pin naming a different tool, or no pin at all) keeps the presence-based
        # skip — the strongest ground-truth signal available closes the FN without reopening either
        # known real-world FP shape (a project with no `packageManager` field, or one pinning a
        # non-npm tool, both stay silent exactly as before).
        if sig.pm_pin_tool != "npm" and (sig.is_pnpm or any(
            (d / lf).is_file() for d in chain for lf in ("yarn.lock", "bun.lockb", "bun.lock")
        )):
            return []
        lock_path = next(
            (d / lf for d in chain for lf in ("package-lock.json", "npm-shrinkwrap.json")
             if (d / lf).is_file()),
            None,
        )
        if lock_path is None:
            return []  # no npm-format lockfile — _check_lockfile covers "no lockfile at all"
        resolved = _npm_lockfile_resolved_names(_load_json(lock_path))
        if resolved is None:
            return []  # lockfile present but unparseable/unrecognized shape — not this check's job
        declared: set[str] = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            val = data.get(key)
            if isinstance(val, dict):
                declared.update(k for k in val if isinstance(k, str))
        missing = sorted(n for n in declared if n not in resolved)
        if not missing:
            return []
        shown = ", ".join(missing[:5]) + (", …" if len(missing) > 5 else "")
        return [
            Finding(
                check_id=self.id, severity="medium",
                title="package-lock.json is out of sync with package.json",
                location=rel(root, manifest),
                message=(
                    f"{len(missing)} dependenc{'y' if len(missing) == 1 else 'ies'} declared in "
                    f"package.json ({shown}) do not appear in {lock_path.name}'s resolved "
                    "dependency set. The manifest was edited without regenerating the lockfile — "
                    "a `--frozen-lockfile`/`npm ci` build either fails outright or, if the "
                    "install falls back to a non-frozen mode, silently resolves the drifted "
                    "dependency unlocked."
                ),
                remediation=(
                    f"Regenerate the lockfile (`npm install`) and commit {lock_path.name} "
                    "alongside the manifest edit."
                ),
                rule="js-supply-chain/lockfile-manifest-drift", standards=_STANDARDS,
            )
        ]

    def _check_lifecycle(
        self, root: Path, manifest: Path, data: dict[str, object], sig: _Signals,
    ) -> list[Finding]:
        if sig.allow_scripts:
            return []
        if sig.dangerous_builds:
            why = "`dangerouslyAllowAllBuilds` is enabled — it disables pnpm's default build-script blocking."
        elif not sig.is_pnpm and not sig.ignore_scripts:
            # Only fire when the project itself defines an install-time lifecycle hook.
            # Dev-only hooks (build/dev/test/lint) don't run on `npm install` and are
            # not a supply-chain vector; flagging them produces FPs on all npm projects.
            own_scripts = data.get("scripts")
            if not isinstance(own_scripts, dict) or not any(
                k in _OWN_LIFECYCLE for k in own_scripts
            ):
                return []
            why = ("npm/yarn run dependency lifecycle scripts on install and `ignore-scripts=true` "
                   "is not set — the Shai-Hulud worm's `postinstall`/`preinstall` execution vector.")
        else:
            return []
        return [
            Finding(
                check_id=self.id, severity="high",
                title="Dependency install scripts can execute",
                location=rel(root, manifest), message=why,
                remediation=(
                    "Set `ignore-scripts=true` in `.npmrc` (and prefer pnpm, which blocks build scripts by "
                    "default with a bounded `onlyBuiltDependencies`/`allowBuilds` allowlist — never "
                    "`dangerouslyAllowAllBuilds`)."
                ),
                rule="js-supply-chain/lifecycle-scripts", standards=_STANDARDS,
            )
        ]

    def _check_cooldown(self, root: Path, manifest: Path, sig: _Signals) -> list[Finding]:
        if sig.suppress_cooldown:
            return []
        if sig.cooldown_min is None:
            return [
                Finding(
                    check_id=self.id, severity="medium",
                    title="No dependency install cooldown configured",
                    location=rel(root, manifest),
                    message=(
                        "No release-age cooldown (`minimumReleaseAge` / `min-release-age`) is configured — "
                        "a freshly published, possibly compromised version can be adopted immediately."
                    ),
                    remediation=(
                        f"Add `minimumReleaseAge: {_REQUIRED_MINUTES}` to `pnpm-workspace.yaml` "
                        f"(pnpm, minutes) or `min-release-age={_REQUIRED_MINUTES // 1440}` to `.npmrc` "
                        "(npm, days) to wait 48h before adopting new versions."
                    ),
                    rule="js-supply-chain/no-cooldown", standards=_STANDARDS,
                )
            ]
        if sig.cooldown_min < _REQUIRED_MINUTES:
            return [
                Finding(
                    check_id=self.id, severity="low",
                    title="Dependency install cooldown is shorter than 48h",
                    location=rel(root, manifest),
                    message=f"Configured cooldown is {sig.cooldown_min} min; the recommended minimum is {_REQUIRED_MINUTES} min (48h).",
                    remediation=f"Raise the cooldown to at least {_REQUIRED_MINUTES} minutes.",
                    rule="js-supply-chain/cooldown-too-short", standards=["OWASP-LLM:LLM03"],
                )
            ]
        return []

    def _check_pinning(
        self, root: Path, manifest: Path, data: dict[str, object],
        chain: list[Path], sig: _Signals,
    ) -> list[Finding]:
        loose: list[str] = []
        for key in ("dependencies", "devDependencies"):
            deps = data.get(key)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                # A plaintext http:// / ftp:// dep gets its own, more specific
                # `insecure-dependency-transport` HIGH finding below — exclude it here so the
                # same dependency isn't also counted into the generic `unpinned` MEDIUM tally
                # (the more specific/severe rule wins for that hit; https:// is unaffected and
                # still counts here exactly as before). BUT that more specific rule suppresses
                # entirely under the `allow-exotic-subdeps` pragma (`sig.allow_exotic`, see
                # `_check_insecure_transport` below) — so this exclusion must not apply then,
                # or a genuinely plaintext-transport dep falls through both checks silently
                # (#548 High 3). Fall back to `unpinned` in that case, restoring
                # pre-PR behavior under the pragma.
                if _insecure_transport_spec(spec) and not sig.allow_exotic:
                    continue
                if _is_floating(spec):
                    loose.append(name)
        if not loose:
            return []
        # A floating direct spec (`^1.2.3`) is only a real exposure if a `pnpm update` could adopt a
        # newer version than reviewed. A committed lockfile (`--frozen-lockfile` installs the exact
        # resolved tree) PLUS a sufficient release-age cooldown (a fresh republish can't be adopted
        # for N hours) together neutralize that — so a fully-hardened workspace is not flagged. A
        # lockfile WITHOUT a cooldown still leaves the fresh-republish window, so it still fires.
        has_lockfile = any((d / lf).is_file() for d in chain for lf in _LOCKFILES)
        cooldown_ok = sig.suppress_cooldown or (
            sig.cooldown_min is not None and sig.cooldown_min >= _REQUIRED_MINUTES
        )
        if has_lockfile and cooldown_ok:
            return []
        uniq = sorted(dict.fromkeys(loose))
        return [
            Finding(
                check_id=self.id, severity="medium",
                title="Unpinned direct dependencies",
                location=rel(root, manifest),
                message=(
                    f"{len(uniq)} direct dependency(ies) use a floating/exotic version "
                    f"(e.g. {', '.join(uniq[:5])}) — a build can adopt a newer (possibly "
                    "republished/compromised) version than was reviewed."
                ),
                remediation="Pin exact versions (`1.2.3`, not `^1.2.3`) and rely on the lockfile for transitive pins.",
                rule="js-supply-chain/unpinned", standards=_STANDARDS,
            )
        ]

    def _check_insecure_transport(
        self, root: Path, manifest: Path, data: dict[str, object], sig: _Signals,
    ) -> list[Finding]:
        """A direct dependency fetched over plaintext http://ftp:// (CWE-300: a
        network-path attacker can substitute a malicious package during install) —
        distinct from, and more severe than, the generic `unpinned`/exotic-source
        classification (`_check_pinning`, above), which covers `https://` and other
        exotic-but-transport-safe sources. Unlike `unpinned`, a committed lockfile /
        cooldown does NOT neutralize this: the lockfile itself would still record (and
        re-fetch from, on a fresh `install`) the same plaintext URL, so the MITM
        exposure is independent of pinning and always fires when present."""
        if sig.allow_exotic:
            return []
        hits: list[str] = []
        for key in ("dependencies", "devDependencies"):
            deps = data.get(key)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if isinstance(spec, str) and _insecure_transport_spec(spec):
                    hits.append(f"{name} ({spec.strip()})")
        if not hits:
            return []
        uniq = sorted(dict.fromkeys(hits))
        return [
            Finding(
                check_id=self.id, severity="high",
                title="Dependency resolved over insecure (plaintext) transport",
                location=rel(root, manifest),
                message=(
                    f"{len(uniq)} direct dependency(ies) are fetched over plaintext http://ftp:// "
                    f"(e.g. {', '.join(uniq[:5])}) — a man-in-the-middle attacker on the network "
                    "path can substitute a malicious package during install; unlike an unpinned "
                    "version, this is a transport-level exposure a lockfile alone does not close."
                ),
                remediation=(
                    "Resolve the dependency from the registry (pin an exact version) or use an "
                    "https:// source instead of a plaintext http://ftp:// URL."
                ),
                rule="js-supply-chain/insecure-dependency-transport", standards=_STANDARDS,
            )
        ]

    def _check_packagemanager(self, root: Path, manifest: Path, data: dict[str, object]) -> list[Finding]:
        pm = data.get("packageManager")
        if isinstance(pm, str) and pm:
            return self._check_packagemanager_cve(root, manifest, pm)
        return [
            Finding(
                check_id=self.id, severity="low",
                title="No pinned packageManager",
                location=rel(root, manifest),
                message="package.json has no `packageManager` field — the toolchain version (and its security defaults) is not reproducible.",
                remediation='Add `"packageManager": "pnpm@<version>"` (Corepack) so installs use a fixed, hardened toolchain.',
                rule="js-supply-chain/no-packagemanager-pin", standards=["OWASP:A06"],
            )
        ]

    def _check_packagemanager_cve(self, root: Path, manifest: Path, pm: str) -> list[Finding]:
        """A pinned `packageManager` is good for reproducibility — but a *pinned-and-vulnerable*
        toolchain is worse than none: it reproducibly installs a version with a known CVE. Flag a
        pin that sits below the curated floor for that tool (e.g. pnpm < 11.9.0 — the Nov-2025
        lockfile/patch/alias toolchain CVEs). Conservative: only an exact, parseable pin below a
        floor fires; an unrecognized tool, unparseable version, or no matching floor passes."""
        m = _PM_PIN.match(pm.strip())
        if not m:
            return []
        tool, declared = m.group(1).lower(), _version(m.group(2))
        if declared is None or len(declared.release) < 2:
            return []  # a bare-major pin (e.g. "pnpm@11") floats to the newest 11.x via Corepack —
            # too coarse to assert "below the floor"; only a major.minor[.patch] pin is flagged.
            # `.release`, NOT `len(declared)`: `_version` returns a `_Ver` NamedTuple whose length is
            # always 3 (release, phase, phase_num), so a bare `len()` silently made this bail-out
            # dead and `pnpm@11` started firing. Caught by the full suite when `_Ver` landed (B28).
        for floor in _packagemanager_floors():
            if str(floor.get("package", "")).lower() != tool:
                continue
            if not _vulnerable(declared, _fixed_versions(floor)):
                continue
            cves = floor.get("cves")
            ids = (
                [str(c) for c in cves]
                if isinstance(cves, list) and cves
                else ([str(floor["cve"])] if floor.get("cve") else [])
            )
            cve_str = ", ".join(ids) if ids else "a known CVE"
            fixed = _fixed_str(floor)
            return [
                Finding(
                    check_id=self.id, severity="high",
                    title=f"`packageManager` pins a vulnerable {tool} toolchain",
                    location=rel(root, manifest),
                    message=(
                        f"package.json pins `packageManager: \"{pm}\"`, which is below the patched "
                        f"floor `{tool}@{fixed}` for {cve_str} — {floor.get('name', '')}. A pinned-but-"
                        f"vulnerable toolchain reproducibly installs the affected {tool} on every machine "
                        "and in CI (Corepack)."
                    ),
                    remediation=(
                        f"Bump the pin to `\"packageManager\": \"{tool}@{fixed}\"` (or later) and run "
                        f"`corepack use {tool}@{fixed}` so the lockfile/CI adopt the patched toolchain."
                    ),
                    rule="js-supply-chain/packagemanager-vulnerable",
                    standards=list(_STANDARDS),
                )
            ]
        return []

    def _check_registry_exotic(self, root: Path, manifest: Path, sig: _Signals) -> list[Finding]:
        out: list[Finding] = []
        if sig.http_registry:
            out.append(
                Finding(
                    check_id=self.id, severity="high",
                    title="Package registry served over plain HTTP",
                    location=rel(root, manifest),
                    message=f"A registry is configured over http:// (man-in-the-middle risk): {sig.http_registry}",
                    remediation="Use an https:// registry URL.",
                    rule="js-supply-chain/insecure-registry", standards=_STANDARDS,
                )
            )
        if sig.exotic_off and not sig.allow_exotic:
            out.append(
                Finding(
                    check_id=self.id, severity="medium",
                    title="Exotic transitive sources are not blocked",
                    location=rel(root, manifest),
                    message="`blockExoticSubdeps` is explicitly disabled — a transitive dep can resolve from a git/tarball/file: source instead of the registry.",
                    remediation="Remove the override (pnpm 11 blocks exotic subdeps by default) or set `blockExoticSubdeps: true`.",
                    rule="js-supply-chain/exotic-subdeps", standards=_STANDARDS,
                )
            )
        return out

    def _check_trust(self, root: Path, manifest: Path, sig: _Signals) -> list[Finding]:
        if not sig.is_pnpm or sig.trust_no_downgrade:
            return []
        return [
            Finding(
                check_id=self.id, severity="low",
                title="No trust-downgrade policy",
                location=rel(root, manifest),
                message="pnpm `trustPolicy: no-downgrade` is not set — an update whose provenance/signature trust weakens vs the locked version would be accepted.",
                remediation="Add `trustPolicy: no-downgrade` to `pnpm-workspace.yaml`; also run `pnpm/npm audit signatures` in CI.",
                rule="js-supply-chain/trust-downgrade", standards=["OWASP-LLM:LLM03"],
            )
        ]
