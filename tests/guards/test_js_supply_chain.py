from __future__ import annotations

from agentsec.guards.js_supply_chain import JsSupplyChainGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_clean_hardened_pnpm_passes(tmp_path: Path) -> None:
    _harden_pnpm(tmp_path)
    assert JsSupplyChainGuard().run(tmp_path, _frontend_prof(tmp_path)) == []

def test_js_packagemanager_vulnerable_pnpm_floor(tmp_path: Path) -> None:
    # A pinned-but-vulnerable toolchain reproducibly installs an affected pnpm. A `packageManager`
    # pin BELOW the curated floor (pnpm < 11.9.0 — the Nov-2025 lockfile/patch/alias toolchain CVEs)
    # fires HIGH; the at-floor version and a bare-major pin do not.
    _harden_pnpm(tmp_path)  # lockfile + cooldown + trustPolicy → only the toolchain pin is in question
    (tmp_path / "package.json").write_text(
        '{"packageManager": "pnpm@11.1.2", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    hits = [
        f for f in JsSupplyChainGuard().run(tmp_path, _frontend_prof(tmp_path))
        if f.rule == "js-supply-chain/packagemanager-vulnerable"
    ]
    assert len(hits) == 1 and hits[0].severity == "high"
    assert "11.9.0" in hits[0].message and "CVE-2026-50014" in hits[0].message

    # at the floor → clean
    (tmp_path / "package.json").write_text(
        '{"packageManager": "pnpm@11.9.0", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    assert "js-supply-chain/packagemanager-vulnerable" not in _js_rules(tmp_path)

    # a bare-major pin floats to the newest 11.x via Corepack → too coarse to flag (conservative)
    (tmp_path / "package.json").write_text(
        '{"packageManager": "pnpm@11", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    assert "js-supply-chain/packagemanager-vulnerable" not in _js_rules(tmp_path)

def test_js_missing_lockfile_and_no_cooldown(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"packageManager": "pnpm@11", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/lockfile-missing" in rules
    assert "js-supply-chain/no-cooldown" in rules

def test_js_bun_text_lockfile_silences_missing(tmp_path: Path) -> None:
    # FP fix: Bun >=1.2 writes a TEXT lockfile `bun.lock` (not the legacy binary `bun.lockb`).
    # A committed `bun.lock` is a real lockfile and must satisfy the lockfile check.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "bun@1.2.0", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "bun.lock").write_text('{"lockfileVersion": 1, "workspaces": {}}\n', encoding="utf-8")
    bun_prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".", package_managers={"bun"})
    assert "js-supply-chain/lockfile-missing" not in {
        f.rule for f in JsSupplyChainGuard().run(tmp_path, bun_prof)
    }

# ── package-lock.json drift from package.json ──────────────────────────────────

def test_js_lockfile_drift_fires_v2_shape(tmp_path: Path) -> None:
    # lockfileVersion 2/3 shape: a flat `packages` map keyed by `node_modules/<name>`. `left-pad`
    # is declared but absent from the lockfile's resolved set — the manifest was edited without
    # regenerating the lockfile.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.0"}}}\n',
        encoding="utf-8",
    )
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/lockfile-manifest-drift" in rules
    hit = next(
        f for f in JsSupplyChainGuard().run(tmp_path, _frontend_prof(tmp_path))
        if f.rule == "js-supply-chain/lockfile-manifest-drift"
    )
    assert hit.severity == "medium"
    assert "left-pad" in hit.message


def test_js_lockfile_drift_fires_v1_shape(tmp_path: Path) -> None:
    # lockfileVersion 1 shape: `dependencies` keyed directly by name.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 1, "dependencies": {"react": {"version": "19.0.0"}}}\n',
        encoding="utf-8",
    )
    assert "js-supply-chain/lockfile-manifest-drift" in _js_rules(tmp_path)


def test_js_lockfile_drift_recognizes_scoped_and_nested_packages(tmp_path: Path) -> None:
    # FP-bait: a scoped package (`@scope/name`) and a version-conflict-hoisted nested dependency
    # (under a NESTED node_modules/, not the top-level one) must still both resolve correctly —
    # neither should read as "missing" just because of how the key is spelled.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@scope/pkg": "1.0.0", "nested-dep": "2.0.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, '
        '"node_modules/@scope/pkg": {"version": "1.0.0"}, '
        '"node_modules/some-other/node_modules/nested-dep": {"version": "2.0.0"}}}\n',
        encoding="utf-8",
    )
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_silent_when_all_deps_present(tmp_path: Path) -> None:
    # FP-bait: every declared dependency IS in the lockfile's resolved set — must stay silent.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0"}, "devDependencies": {"typescript": "5.0.0"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, '
        '"node_modules/react": {"version": "19.0.0"}, '
        '"node_modules/typescript": {"version": "5.0.0"}}}\n',
        encoding="utf-8",
    )
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_silent_with_no_lockfile(tmp_path: Path) -> None:
    # FP-bait / scope check: no lockfile at all is `lockfile-missing`'s job, not this rule's —
    # must not double-fire or crash on a missing lockfile.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_silent_on_yarn_pnpm_lockfiles(tmp_path: Path) -> None:
    # Scope check: yarn.lock/pnpm-lock.yaml are YAML/custom text formats this check deliberately
    # does not parse (stdlib-only design) — must stay silent rather than misparse and false-fire.
    # A genuinely drifted package-lock.json is planted too (#681 review) — without one, this test
    # is vacuous: is_pnpm alone (from pnpm-lock.yaml) already short-circuits `_check_lockfile_drift`
    # to `[]` before `lock_path` is ever resolved, so it proved nothing about drift being
    # suppressed. The single-lockfile pnpm/yarn coexistence cases are proven with real teeth by
    # the two migration regression tests below; this one additionally covers both non-npm
    # lockfiles present together.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_silent_on_stale_package_lock_after_pnpm_migration(tmp_path: Path) -> None:
    # Regression: a project that migrated npm -> pnpm and left the old package-lock.json
    # committed must not have every dependency added since the migration read as "drifted" —
    # the stale, no-longer-updated npm lockfile is not ground truth once pnpm-lock.yaml exists.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_silent_on_stale_package_lock_after_yarn_migration(tmp_path: Path) -> None:
    # Same class, yarn side: a genuine yarn.lock coexisting with a stale package-lock.json.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_still_fires_npm_only(tmp_path: Path) -> None:
    # Control for the two regression tests above: a genuinely npm-only project (no coexisting
    # pnpm/yarn/bun lockfile) must still fire on real drift — the narrowing didn't cost the
    # true positive.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    assert "js-supply-chain/lockfile-manifest-drift" in _js_rules(tmp_path)


def test_js_lockfile_drift_fires_when_packagemanager_pins_npm_despite_pnpm_lock(tmp_path: Path) -> None:
    # presence alone is not recency. An explicit `packageManager: "npm@..."` pin is
    # Corepack's own ground-truth declaration of the toolchain this project actually builds
    # with — an ACTIVE, drifting package-lock.json next to an ABANDONED pnpm-lock.yaml must not
    # stay silent just because the stray file is still on disk.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm@10.8.2", '
        '"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" in _js_rules(tmp_path)


def test_js_lockfile_drift_fires_when_packagemanager_pins_npm_despite_yarn_lock(tmp_path: Path) -> None:
    # Same class, yarn side.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm@10.8.2", '
        '"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" in _js_rules(tmp_path)


def test_js_lockfile_drift_silent_when_packagemanager_pins_pnpm_and_pnpm_lock_present(tmp_path: Path) -> None:
    # FP shape (a real reviewed project, per PR discussion): a `packageManager` pin naming
    # anything other than npm keeps the presence-based skip — pinning is not itself grounds to
    # override, only a pin that names npm specifically closes the FN.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "pnpm@11.15.0", '
        '"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_fires_on_npm_pin_with_exotic_version_suffix(tmp_path: Path) -> None:
    # Unparsed format, by design: `_pm_pin_tool` is a bare split on the first `@`, not `_PM_PIN`
    # (which also requires a digit-led, well-formed version) — a malformed/exotic version suffix
    # still names the tool just as reliably.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm@not-a-real-version", '
        '"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" in _js_rules(tmp_path)


def test_js_lockfile_drift_silent_when_packagemanager_has_no_at_sign(tmp_path: Path) -> None:
    # A `packageManager` value with no `@` at all (not a valid Corepack pin) parses to "no pin" —
    # keeps the presence-based skip rather than guessing at a tool name.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm", '
        '"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_silent_when_no_packagemanager_field_and_pnpm_lock_present(tmp_path: Path) -> None:
    # FP shape (a real reviewed project, per PR discussion): no `packageManager` field at all
    # keeps the presence-based skip — absence of a pin is not evidence of npm, so this must not
    # regress the already-closed real-world FP.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_lockfile_drift_pragma_suppresses(tmp_path: Path) -> None:
    # Pragma lives in .npmrc, not package.json — a `#`/`//` comment in package.json itself
    # would break JSON parsing of the manifest this check reads declared deps from (same
    # reason every other pragma in this guard lives outside package.json too).
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.0"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / ".npmrc").write_text("# security: allow-lockfile-manifest-drift (vetted)\n", encoding="utf-8")
    assert "js-supply-chain/lockfile-manifest-drift" not in _js_rules(tmp_path)


def test_js_cooldown_too_short_pnpm(tmp_path: Path) -> None:
    _harden_pnpm(tmp_path)
    (tmp_path / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 60\ntrustPolicy: no-downgrade\n", encoding="utf-8")
    assert "js-supply-chain/cooldown-too-short" in _js_rules(tmp_path)

def test_js_npm_min_release_age_days(tmp_path: Path) -> None:
    # npm `min-release-age` is in DAYS: 2 days == 2880 min (passes), 1 day too short.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm@10", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\nmin-release-age=2\n", encoding="utf-8")
    npm_prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".", package_managers={"npm"})
    rules = {f.rule for f in JsSupplyChainGuard().run(tmp_path, npm_prof)}
    assert "js-supply-chain/no-cooldown" not in rules and "js-supply-chain/cooldown-too-short" not in rules
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\nmin-release-age=1\n", encoding="utf-8")
    assert "js-supply-chain/cooldown-too-short" in {
        f.rule for f in JsSupplyChainGuard().run(tmp_path, npm_prof)
    }

def test_js_lifecycle_npm_without_ignore_scripts_and_own_lifecycle_fires(tmp_path: Path) -> None:
    # npm project without ignore-scripts AND project defines a postinstall script → HIGH.
    # The project-defined lifecycle hook is the discriminating signal: a project that uses
    # postinstall/prepare/preinstall is aware of and dependent on lifecycle execution.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm@10", "dependencies": {"react": "19.0.0"},'
        ' "scripts": {"postinstall": "node setup.js", "build": "vite build"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    npm_prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".", package_managers={"npm"})
    hits = [f for f in JsSupplyChainGuard().run(tmp_path, npm_prof)
            if f.rule == "js-supply-chain/lifecycle-scripts"]
    assert len(hits) == 1 and hits[0].severity == "high"

def test_js_lifecycle_npm_without_ignore_scripts_dev_only_silent(tmp_path: Path) -> None:
    # FP fix: npm project without ignore-scripts but ONLY dev-only scripts (build/dev/test)
    # does NOT fire — dev-only scripts don't run on `npm install`.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm@10", "dependencies": {"react": "19.0.0"},'
        ' "scripts": {"build": "vite build", "dev": "vite", "test": "vitest"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    npm_prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".", package_managers={"npm"})
    rules = {f.rule for f in JsSupplyChainGuard().run(tmp_path, npm_prof)}
    assert "js-supply-chain/lifecycle-scripts" not in rules

def test_js_lifecycle_npm_prepare_fires(tmp_path: Path) -> None:
    # `prepare` is an install-time lifecycle hook — must still fire.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm@10", "dependencies": {"react": "19.0.0"},'
        ' "scripts": {"prepare": "husky install", "build": "tsc"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    npm_prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".", package_managers={"npm"})
    rules = {f.rule for f in JsSupplyChainGuard().run(tmp_path, npm_prof)}
    assert "js-supply-chain/lifecycle-scripts" in rules

def test_js_lifecycle_npm_ignore_scripts_ok(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"packageManager": "npm@10", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\nmin-release-age=2\n", encoding="utf-8")
    npm_prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".", package_managers={"npm"})
    rules = {f.rule for f in JsSupplyChainGuard().run(tmp_path, npm_prof)}
    assert "js-supply-chain/lifecycle-scripts" not in rules

def test_js_lifecycle_pnpm_clean_but_dangerous_builds_fires(tmp_path: Path) -> None:
    _harden_pnpm(tmp_path)
    assert "js-supply-chain/lifecycle-scripts" not in _js_rules(tmp_path)  # pnpm blocks by default
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "minimumReleaseAge: 2880\ntrustPolicy: no-downgrade\ndangerouslyAllowAllBuilds: true\n", encoding="utf-8"
    )
    assert "js-supply-chain/lifecycle-scripts" in _js_rules(tmp_path)

def test_js_unpinned_and_packagemanager(tmp_path: Path) -> None:
    # lock present but NO cooldown -> a `pnpm update` can still adopt a fresh republish, so a
    # floating caret IS a real exposure: unpinned must fire (the Test-FE scenario).
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "^19.0.0", "vite": "5"}}\n', encoding="utf-8")
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/unpinned" in rules
    assert "js-supply-chain/no-packagemanager-pin" in rules

def test_js_unpinned_suppressed_when_lock_and_cooldown(tmp_path: Path) -> None:
    # T2b precision: a committed lockfile (--frozen-lockfile pins the exact tree) PLUS a sufficient
    # release-age cooldown neutralizes a floating caret -> a fully-hardened workspace is not flagged.
    (tmp_path / "package.json").write_text(
        '{"packageManager": "pnpm@11.9.0", "dependencies": {"react": "^19.0.0", "vite": "^5.0.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 4320\ntrustPolicy: no-downgrade\n", encoding="utf-8")
    assert "js-supply-chain/unpinned" not in _js_rules(tmp_path)

def test_js_unpinned_fires_with_cooldown_but_no_lock(tmp_path: Path) -> None:
    # cooldown but NO lockfile -> versions aren't pinned at all; unpinned must still fire (no FN).
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "^19.0.0"}}\n', encoding="utf-8")
    (tmp_path / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 4320\n", encoding="utf-8")
    assert "js-supply-chain/unpinned" in _js_rules(tmp_path)

def test_js_insecure_registry_and_exotic(tmp_path: Path) -> None:
    _harden_pnpm(tmp_path)
    (tmp_path / ".npmrc").write_text("registry=http://internal/registry\n", encoding="utf-8")
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "minimumReleaseAge: 2880\ntrustPolicy: no-downgrade\nblockExoticSubdeps: false\n", encoding="utf-8"
    )
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/insecure-registry" in rules
    assert "js-supply-chain/exotic-subdeps" in rules

def test_js_trust_downgrade_pnpm_only(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"packageManager": "pnpm@11", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 2880\n", encoding="utf-8")  # no trustPolicy
    assert "js-supply-chain/trust-downgrade" in _js_rules(tmp_path)

def test_js_pragma_suppresses(tmp_path: Path) -> None:
    _harden_pnpm(tmp_path)
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "trustPolicy: no-downgrade\n# security: allow-no-cooldown (vetted)\n", encoding="utf-8"
    )
    assert "js-supply-chain/no-cooldown" not in _js_rules(tmp_path)

def test_js_workspace_subpackage_inherits_parent_config(tmp_path: Path) -> None:
    # A pnpm workspace: the lockfile + hardened config live at frontend/; a nested
    # sub-package must INHERIT them, not fire lockfile-missing / no-cooldown /
    # lifecycle (it has no config of its own).
    fe = tmp_path / "frontend"
    (fe / "packages" / "ui").mkdir(parents=True)
    (fe / "package.json").write_text(
        '{"packageManager": "pnpm@11", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    (fe / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (fe / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 2880\ntrustPolicy: no-downgrade\n", encoding="utf-8")
    (fe / "packages" / "ui" / "package.json").write_text(
        '{"packageManager": "pnpm@11", "dependencies": {"preact": "10.0.0"}}\n', encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="frontend", package_managers={"pnpm"})
    nested = "frontend/packages/ui/package.json"
    nested_rules = {f.rule for f in JsSupplyChainGuard().run(tmp_path, prof) if f.location == nested}
    assert "js-supply-chain/lockfile-missing" not in nested_rules  # inherits frontend/pnpm-lock.yaml
    assert "js-supply-chain/no-cooldown" not in nested_rules        # inherits frontend/pnpm-workspace.yaml
    assert "js-supply-chain/lifecycle-scripts" not in nested_rules  # pnpm (inherited)
    assert "js-supply-chain/trust-downgrade" not in nested_rules    # trustPolicy inherited


def test_js_lockfile_drift_nearest_packagemanager_pin_wins_over_ancestor(tmp_path: Path) -> None:
    # precedence: `_pm_pin_tool_chain` walks `ancestors()`, which is ordered
    # NEAREST-FIRST, so a sub-package's OWN pin must beat the workspace root's. The sibling
    # inheritance tests cannot catch a regression here (an accidental `reversed(chain)`, or
    # checking ancestors before `chain[0]`) because they pin the SAME tool at both levels.
    # Here the two levels disagree: root says npm, the sub-package says pnpm.
    #
    # The sub-package carries BOTH lockfiles, so the resolved tool alone decides the outcome:
    # resolve pnpm (correct, nearest) -> its pnpm-lock.yaml governs, no drift. Resolve npm
    # (wrong, ancestor) -> the drifted package-lock.json governs and drift fires.
    fe = tmp_path / "frontend"
    (fe / "packages" / "web").mkdir(parents=True)
    (fe / "package.json").write_text('{"packageManager": "npm@10.8.2"}\n', encoding="utf-8")
    # `left-pad` is declared but ABSENT from package-lock.json below — a genuine drift. Without
    # it `missing` is empty and the check returns [] for both tools, so the test would pass
    # vacuously no matter which pin won.
    (fe / "packages" / "web" / "package.json").write_text(
        '{"packageManager": "pnpm@11.9.0", '
        '"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n',
        encoding="utf-8",
    )
    # Agrees with the manifest -> pnpm sees no drift.
    (fe / "packages" / "web" / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      react:\n"
        "        specifier: 19.0.0\n        version: 19.0.0\n",
        encoding="utf-8",
    )
    # DRIFTED against the manifest -> npm would see drift. Only reachable if precedence breaks.
    (fe / "packages" / "web" / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="frontend", package_managers={"pnpm"})
    sub_rules = {
        f.rule for f in JsSupplyChainGuard().run(tmp_path, prof)
        if f.location.replace("\\", "/") == "frontend/packages/web/package.json"
    }
    assert "js-supply-chain/lockfile-manifest-drift" not in sub_rules


def test_js_lockfile_drift_fires_when_root_pins_npm_for_workspace_subpackage(tmp_path: Path) -> None:
    # (PR #737 review finding 1): packageManager conventionally lives only in a
    # workspace's ROOT manifest, while the manifests actually scanned for drift are the
    # sub-packages that declare dependencies. A root-level npm pin must reach its own
    # workspace's sub-package drift check via the chain walk, not just the manifest that
    # literally carries the field.
    fe = tmp_path / "frontend"
    (fe / "packages" / "web").mkdir(parents=True)
    (fe / "package.json").write_text('{"packageManager": "npm@10.8.2"}\n', encoding="utf-8")
    (fe / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (fe / "packages" / "web" / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (fe / "packages" / "web" / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="frontend", package_managers={"npm"})
    sub_rules = {
        f.rule for f in JsSupplyChainGuard().run(tmp_path, prof)
        if f.location.replace("\\", "/") == "frontend/packages/web/package.json"
    }
    assert "js-supply-chain/lockfile-manifest-drift" in sub_rules


def test_js_lockfile_drift_silent_when_root_pins_pnpm_for_workspace_subpackage(tmp_path: Path) -> None:
    # FP-bait direction: the chain-walk must only OVERRIDE when the inherited pin names npm
    # specifically — a root pin naming pnpm must not force an unrelated stray package-lock.json
    # in a sub-package to fire.
    fe = tmp_path / "frontend"
    (fe / "packages" / "web").mkdir(parents=True)
    (fe / "package.json").write_text('{"packageManager": "pnpm@11.15.0"}\n', encoding="utf-8")
    (fe / "packages" / "web" / "package.json").write_text(
        '{"dependencies": {"react": "19.0.0", "left-pad": "1.3.0"}}\n', encoding="utf-8"
    )
    (fe / "packages" / "web" / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react": {"version": "19.0.2"}}}\n',
        encoding="utf-8",
    )
    (fe / "packages" / "web" / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="frontend", package_managers={"pnpm"})
    sub_rules = {
        f.rule for f in JsSupplyChainGuard().run(tmp_path, prof)
        if f.location.replace("\\", "/") == "frontend/packages/web/package.json"
    }
    assert "js-supply-chain/lockfile-manifest-drift" not in sub_rules


def test_js_ignores_manifest_without_deps(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "no-deps"}\n', encoding="utf-8")
    assert JsSupplyChainGuard().run(tmp_path, _frontend_prof(tmp_path)) == []

def test_js_not_applicable_without_js() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"}, package_managers={"pip"})
    assert JsSupplyChainGuard().applies(prof) is False


def test_js_is_floating_npm_alias_no_version_terminates() -> None:
    """An unversioned `npm:` alias must not infinite-recurse (was RecursionError)."""
    from agentsec.guards.js_supply_chain import _is_floating
    assert _is_floating("npm:bar") is True          # alias-to-latest = floating
    assert _is_floating("npm:") is True
    assert _is_floating("npm:bar@1.2.3") is False    # pinned version still resolves


def test_js_insecure_registry_silent_when_commented(tmp_path: Path) -> None:
    # FP-bait (#424): a commented `# registry=http://...` in .npmrc must not fire insecure-registry.
    (tmp_path / ".npmrc").write_text(
        "# registry=http://internal/registry\nregistry=https://safe.example/\n", encoding="utf-8"
    )
    assert "js-supply-chain/insecure-registry" not in _js_rules(tmp_path)


def test_js_commented_dangerous_builds_not_flagged(tmp_path: Path) -> None:
    # #441 review (Medium): a commented `# dangerouslyAllowAllBuilds` in .npmrc must not fire
    # lifecycle-scripts (blob's hash-comment sources are now stripped too, not just npmrc_text).
    (tmp_path / ".npmrc").write_text(
        "# dangerouslyAllowAllBuilds: true\nignore-scripts=true\nmin-release-age=3\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text('{"dependencies":{"x":"1.0.0"}}', encoding="utf-8")
    assert "js-supply-chain/lifecycle-scripts" not in _js_rules(tmp_path)


def test_js_real_dangerous_builds_still_flagged(tmp_path: Path) -> None:
    # The strip must NOT hide a REAL (uncommented) dangerouslyAllowAllBuilds.
    (tmp_path / ".npmrc").write_text("dangerouslyAllowAllBuilds: true\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies":{"x":"1.0.0"}}', encoding="utf-8")
    assert "js-supply-chain/lifecycle-scripts" in _js_rules(tmp_path)


def test_js_insecure_registry_still_fires_with_trailing_comment(tmp_path: Path) -> None:
    # #441 review (Low): a real setting with a TRAILING comment must still fire (the real
    # value survives the comment strip).
    (tmp_path / "package.json").write_text('{"dependencies":{"x":"1.0.0"}}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("registry=http://internal/registry  # legacy\n", encoding="utf-8")
    assert "js-supply-chain/insecure-registry" in _js_rules(tmp_path)


# --- insecure-dependency-transport (http/ftp dep URL, distinct from generic unpinned) ---

def test_js_insecure_transport_http_fires_high(tmp_path: Path) -> None:
    # Planted violation: a direct dependency resolved over plain http:// (CWE-300 MITM risk,
    # CodeQL InsecureDependencyResolution.ql) must fire the NEW, more specific HIGH rule.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"evil-pkg": "http://example.com/evil-pkg.tgz"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    hits = [
        f for f in JsSupplyChainGuard().run(tmp_path, _frontend_prof(tmp_path))
        if f.rule == "js-supply-chain/insecure-dependency-transport"
    ]
    assert len(hits) == 1
    assert hits[0].severity == "high"
    assert "man-in-the-middle" in hits[0].message.lower()
    assert "evil-pkg" in hits[0].message
    # The more-specific rule wins: the same dependency must NOT also be double-counted into
    # the generic `unpinned` MEDIUM finding (it is the only dependency in this manifest).
    assert "js-supply-chain/unpinned" not in _js_rules(tmp_path)


def test_js_insecure_transport_ftp_fires_high(tmp_path: Path) -> None:
    # Planted violation: same case for ftp://.
    (tmp_path / "package.json").write_text(
        '{"devDependencies": {"evil-tool": "ftp://example.com/evil-tool.tgz"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    hits = [
        f for f in JsSupplyChainGuard().run(tmp_path, _frontend_prof(tmp_path))
        if f.rule == "js-supply-chain/insecure-dependency-transport"
    ]
    assert len(hits) == 1
    assert hits[0].severity == "high"
    assert "evil-tool" in hits[0].message


def test_js_https_dependency_still_fires_generic_unpinned(tmp_path: Path) -> None:
    # FP-bait / regression (the direction NOT changed): an https:// dependency URL is transport-
    # safe — it must still be classified under the existing exotic-source/`unpinned` MEDIUM path
    # exactly as before, and must NOT fire the new insecure-dependency-transport rule.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"pkg": "https://example.com/pkg.tgz"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/unpinned" in rules
    assert "js-supply-chain/insecure-dependency-transport" not in rules


def test_js_git_plus_http_dependency_not_insecure_transport(tmp_path: Path) -> None:
    # Adversarial self-test: `git+http://...` is a git-protocol-over-http dependency spec — a
    # DIFFERENT, already-existing `git+` exotic-source case (still `unpinned`), not the plain-URL
    # dependency case CodeQL's query targets. The new rule must match on an EXACT `http://`/
    # `ftp://` prefix, not merely "contains http://".
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"pkg": "git+http://github.com/example/pkg.git"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/insecure-dependency-transport" not in rules
    assert "js-supply-chain/unpinned" in rules


def test_js_insecure_transport_pragma_suppresses(tmp_path: Path) -> None:
    # Reuses the existing `security: allow-exotic-subdeps` pragma (a plaintext-URL dependency
    # is a kind of exotic source) — no new pragma invented.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"evil-pkg": "http://example.com/evil-pkg.tgz"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("# security: allow-exotic-subdeps (vetted)\n", encoding="utf-8")
    assert "js-supply-chain/insecure-dependency-transport" not in _js_rules(tmp_path)


def test_js_insecure_transport_pragma_falls_back_to_unpinned(tmp_path: Path) -> None:
    # #548 High 3 regression test (the direction traded against, missing from the
    # original pragma test above): under `allow-exotic-subdeps`, the new, more specific
    # `insecure-dependency-transport` rule suppresses entirely (asserted above) — but a genuinely
    # plaintext-transport dependency (e.g. an http:// reference to left-pad) must NOT fall through
    # both checks silently. The line-428 exclusion in `_check_pinning` must stop excluding
    # http(s)/ftp specs from the `unpinned` tally once the pragma is present, so `unpinned` fires
    # as a fallback and pre-PR behavior (this case WAS caught, via `unpinned`, before this PR) is
    # restored under the pragma.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"left-pad": "http://example.com/left-pad.tgz"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("# security: allow-exotic-subdeps (vetted)\n", encoding="utf-8")
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/insecure-dependency-transport" not in rules
    assert "js-supply-chain/unpinned" in rules


def test_js_insecure_transport_independent_of_http_registry(tmp_path: Path) -> None:
    # Adversarial self-test: the per-dependency http:// URL check (insecure-dependency-transport)
    # and the separate .npmrc-level `registry = http://...` check (insecure-registry) are two
    # different rules for two different things (a single dependency's own URL vs. the whole
    # registry's URL) — both must fire independently, unconflated.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"evil-pkg": "http://example.com/evil-pkg.tgz"}}\n', encoding="utf-8"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("registry=http://internal/registry\n", encoding="utf-8")
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/insecure-dependency-transport" in rules
    assert "js-supply-chain/insecure-registry" in rules


# ---------------------------------------------------------------------------
# #697 / #702: still-fires coverage for the converted anchors here
#
# The #702 fix-commit round checked the claim that `doctor --canary` already covers the narrowing
# direction for every converted guard, and found it false for THIS file: the canary tree contains no
# `.npmrc` and no `pnpm-workspace.yaml` at all, and none of `minimum-release-age` /
# `min-release-age` / `minimumReleaseAge` appears anywhere in it. So the cooldown patterns whose
# anchors changed from `^\s*` to `^[^\S\n]*` had NO net. These are it, per Rule 1: the narrowed
# anchor must still accept ordinary same-line indentation, and must still find a key that follows a
# run of blank lines.
#
# Round 3 note: the first version of these tests built on `_harden_pnpm`, which ALREADY satisfies the
# cooldown check (its `pnpm-workspace.yaml` carries `minimumReleaseAge: 2880`) and pins pnpm (which
# skips the lifecycle-scripts branch outright). All three therefore stayed green with the very
# patterns they name replaced by a never-matching regex -- tests pinning nothing. The fixtures below
# make the `.npmrc` key the ONLY thing that can satisfy each check, so a regression in these anchors
# is what turns them red. Each was confirmed to fail with its own pattern neutered.
# ---------------------------------------------------------------------------

_NBSP = "\u00a0"  # spelled as an escape: an inline NBSP is indistinguishable from a space in source


def _pnpm_cooldown_only_in_npmrc(root: Path) -> None:
    """A hardened pnpm project whose ONLY cooldown source is `.npmrc` (the caller writes it).

    Deliberately NOT `_harden_pnpm`: that helper writes `minimumReleaseAge: 2880` into
    `pnpm-workspace.yaml`, which satisfies the cooldown check by itself and would mask whatever the
    `.npmrc` key does. Everything else it sets (pinned toolchain, lockfile) is kept.
    """
    (root / "package.json").write_text(
        '{"packageManager": "pnpm@11.9.0", "dependencies": {"react": "19.0.0"}}\n', encoding="utf-8"
    )
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")


def _npm_with_install_hook(root: Path) -> None:
    """An npm project with an install-time lifecycle hook, so `_IGNORE_SCRIPTS` is load-bearing.

    `lifecycle-scripts` only reaches its `not sig.ignore_scripts` test for a NON-pnpm project that
    defines its own `postinstall`/`preinstall`/`prepare` -- pnpm blocks build scripts by default, so
    under a pnpm fixture the rule returns early and `_IGNORE_SCRIPTS` is never consulted at all.
    """
    (root / "package.json").write_text(
        '{"packageManager": "npm@10", "dependencies": {"react": "19.0.0"},'
        ' "scripts": {"postinstall": "node ./setup.js"}}\n',
        encoding="utf-8",
    )
    (root / "package-lock.json").write_text("{}\n", encoding="utf-8")


def _npm_rules(root: Path) -> set[str]:
    prof = mkprofile(root, features={"frontend"}, frontend_dir=".", package_managers={"npm"})
    return {f.rule for f in JsSupplyChainGuard().run(root, prof)}


def test_js_cooldown_still_read_from_an_indented_npmrc_key(tmp_path: Path) -> None:
    """`[^\\S\\n]*` keeps the full same-line whitespace vocabulary; only the newline is excluded.

    The NBSP case is the load-bearing one: it is what an over-narrowing to `[ \\t]*` would drop,
    which is the exact regression the #696 round caught on the Dockerfile anchors.
    """
    for label, indent in (("two spaces", "  "), ("a tab", "\t"), ("an NBSP", _NBSP)):
        _pnpm_cooldown_only_in_npmrc(tmp_path)
        (tmp_path / ".npmrc").write_text(
            f"ignore-scripts=true\n{indent}minimum-release-age=4320\n", encoding="utf-8"
        )
        rules = _js_rules(tmp_path)
        assert "js-supply-chain/no-cooldown" not in rules, f"indentation by {label} lost"
        assert "js-supply-chain/cooldown-too-short" not in rules, f"indentation by {label} lost"


def test_js_cooldown_absent_still_fires_without_the_npmrc_key(tmp_path: Path) -> None:
    """The other direction for the fixture above: with no cooldown anywhere, `no-cooldown` MUST fire.

    Without this, the test above would still pass if the fixture had quietly stopped being able to
    produce the finding at all -- which is exactly how the round-2 version of it went green.
    """
    _pnpm_cooldown_only_in_npmrc(tmp_path)
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    assert "js-supply-chain/no-cooldown" in _js_rules(tmp_path)


def test_js_cooldown_still_read_after_a_blank_line_run(tmp_path: Path) -> None:
    """The blank run is what the old anchor used to scan across. The key after it must still be
    found -- a conversion that stopped matching here would silently report `no-cooldown` on a
    correctly hardened repo, which is a false POSITIVE on the user's own mitigation."""
    _pnpm_cooldown_only_in_npmrc(tmp_path)
    (tmp_path / ".npmrc").write_text(
        "ignore-scripts=true\n" + "\n" * 200 + "minimum-release-age=4320\n", encoding="utf-8"
    )
    rules = _js_rules(tmp_path)
    assert "js-supply-chain/no-cooldown" not in rules
    assert "js-supply-chain/cooldown-too-short" not in rules


def test_js_ignore_scripts_still_read_when_indented_after_a_blank_run(tmp_path: Path) -> None:
    """`_IGNORE_SCRIPTS` took the same conversion, and its miss direction is the same: reading it as
    absent would fire a lifecycle-scripts finding against a repo that had already set it."""
    for label, indent in (("two spaces", "  "), ("an NBSP", _NBSP)):
        _npm_with_install_hook(tmp_path)
        (tmp_path / ".npmrc").write_text(
            "min-release-age=3\n" + "\n" * 100 + f"{indent}ignore-scripts=true\n",
            encoding="utf-8",
        )
        assert "js-supply-chain/lifecycle-scripts" not in _npm_rules(tmp_path), (
            f"indentation by {label} lost"
        )


def test_js_ignore_scripts_absent_still_fires_on_an_install_hook(tmp_path: Path) -> None:
    """The other direction for the npm fixture: with no `ignore-scripts` at all it MUST fire."""
    _npm_with_install_hook(tmp_path)
    (tmp_path / ".npmrc").write_text("min-release-age=3\n", encoding="utf-8")
    assert "js-supply-chain/lifecycle-scripts" in _npm_rules(tmp_path)


def test_js_http_registry_still_flagged_when_indented_after_a_blank_run(tmp_path: Path) -> None:
    """`_HTTP_REGISTRY` is the opposite direction: it must still FIRE after the conversion.

    Scope note: this is an end-to-end still-fires check, NOT a test of the whitespace class. That
    pattern's `^` sits inside an OPTIONAL group (`(?:^|@[\\w.-]+:)?`), so it matches `registry=`
    anywhere on the line and keeps matching even with the class deleted outright -- no anchor change
    can turn this red. Kept for the end-to-end path; the class itself is pinned by the tests above.
    """
    _harden_pnpm(tmp_path)
    (tmp_path / ".npmrc").write_text(
        "ignore-scripts=true\nminimum-release-age=4320\n"
        + "\n" * 100
        + "  registry=http://registry.internal/\n",
        encoding="utf-8",
    )
    assert "js-supply-chain/insecure-registry" in _js_rules(tmp_path)
