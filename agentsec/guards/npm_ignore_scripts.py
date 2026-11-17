"""Guard: npm install scripts not blocked via ignore-scripts=true (OWASP:A06, CIS:2.2).

When npm installs a package it executes any `preinstall`, `install`, and `postinstall`
lifecycle scripts declared in that package's `package.json`. This is a well-known supply-
chain attack surface: a malicious dependency (or a legitimate one that has been compromised
in a typosquatting or account-takeover incident) can run arbitrary code **at install time**
— before any code review, before the app even starts. The attack vector requires no
runtime exploitation; installation alone is sufficient to:

- Exfiltrate secrets from the CI environment (API keys, tokens read from env vars)
- Plant backdoors in the installed files that the application then runs
- Harvest developer credentials from the local machine
- Pivot into the build pipeline (e.g. modify pipeline scripts or artifacts)

The mitigation is simple and almost never breaks legitimate packages: set
`ignore-scripts=true` in `.npmrc` at the repo root. This suppresses all lifecycle
script execution during `npm install`. Projects that genuinely need a package's build
step can whitelist it with `--ignore-scripts=false` on a per-install basis, keeping
the default safe.

This guard also scans CI workflow files for `npm install` without `--ignore-scripts`,
because a CI environment that does not pass the flag skips the `.npmrc` setting when
the flag is missing from npm@<6.x, and more importantly, CI is the highest-value target
(it has the most secrets, the most trust, and produces the artifacts that reach prod).

**Two detectable signals:**

  **`missing-ignore-scripts`** (HIGH): A `package.json` exists but `.npmrc` either does
  not exist or does not contain `ignore-scripts=true`. Also fires for each CI workflow
  line that invokes `npm install` without the `--ignore-scripts` flag.

**Why HIGH?** Supply-chain attacks via npm lifecycle scripts are active and well-documented
(event-stream, node-ipc, colors/faker, xz-utils-style implants). They are particularly
dangerous in CI because the environment typically holds production secrets and the attacker
gets code execution on the build machine itself.

**False-negative scope:** This guard checks for the `.npmrc` setting, the CI flag, and the
`NPM_CONFIG_IGNORE_SCRIPTS` environment-variable form (below). It does not detect
per-package `scripts.ignore` overrides in advanced configurations — an accepted,
pragmatic omission for a static guard.

**The environment-variable form.** npm honors any OS environment variable prefixed
`NPM_CONFIG_` as equivalent to the matching kebab-case config key — `NPM_CONFIG_IGNORE_
SCRIPTS=true` is functionally identical to `ignore-scripts=true` in `.npmrc`. This guard
recognizes a truthy assignment (`true` or `1`, quoted or bare) in two places: a `.env`/
`.env.*` file or a `docker-compose*.yml`/`.yaml` file (either suppresses the repo-level
`.npmrc` finding — a compose service's `environment:` block, or a `.env` file compose
loads for interpolation, governs the `npm install` that runs inside that container), and
a CI workflow file's own text (suppresses that workflow's per-line CI finding — an `env:`
block at workflow/job/step level, or an inline `KEY=value npm install` on the run line
itself). Deliberately file-scoped, not job/step-scoped: a per-job `env:` block protecting
one job's install is read as protecting every `npm install` line in the same workflow
FILE, the same coarse-grained trade-off this guard already makes for `.npmrc` (repo-wide,
not per-route). Deliberately NOT extended to `process.env`/`os.environ` reads inside
application source: `npm install` runs as a separate process before any application code
executes, so a value assigned to `process.env.NPM_CONFIG_IGNORE_SCRIPTS` in server code
has no effect on the install that already happened — recognizing that pattern would
silence a genuinely unprotected install, not correctly suppress a protected one.
Both the `.env`/compose check and the CI-file check run against `#`-comment-stripped
text (#685 fix-commit round, High 2): without it, a line that only MENTIONS the
variable inside a comment read as real protection on a genuinely unprotected repo.

**Checklist item:** `5-npm-install-scripts-blocked`.

**Suppress:** `# security: allow-npm-scripts`, only when lifecycle scripts are intentionally
required and the risk is accepted (e.g. native addons that require a `node-gyp` build step).
Its reach differs per signal. Anywhere in `.npmrc`, it silences the repo-level finding (that
finding is about the file). In a CI workflow it silences ONE install (#539): written as a
comment on that install's line (a backslash-continued command counts as one line), or on a
comment-only line directly above it. A pragma elsewhere in the workflow file, or one inside
a quoted string, does not count.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    iter_files,
    iter_files_named,
    join_dockerfile_continuations,
    read,
    rel,
    strip_hash_comments,
)

_PRAGMA = "security: allow-npm-scripts"

_STANDARDS = ["OWASP:A06", "CIS:2.2"]

# `.npmrc` line setting ignore-scripts true — npm trims whitespace around `=`, so both
# `ignore-scripts=true` and the spaced `ignore-scripts = true` are valid hardening.
_IGNORE_SCRIPTS_TRUE = re.compile(r"^[^\S\n]*ignore-scripts\s*=\s*true\s*$", re.MULTILINE | re.IGNORECASE)

# The environment-variable form of the same setting: npm maps any `NPM_CONFIG_<KEY>` env var
# onto the matching kebab-case config key, so `NPM_CONFIG_IGNORE_SCRIPTS=true` is equivalent
# to `ignore-scripts=true` in `.npmrc`. Matches a `.env` literal (`NPM_CONFIG_IGNORE_SCRIPTS=
# true`), a YAML mapping/list entry (`NPM_CONFIG_IGNORE_SCRIPTS: "true"` / `- NPM_CONFIG_
# IGNORE_SCRIPTS=true`), or an inline shell assignment on a CI run line. Truthy per npm's own
# boolean-config parsing: `true`/`1`, quoted or bare — a `false`/`0` value, or the variable
# being merely mentioned some other way, does not match.
#
# Both call sites run this against `strip_hash_comments()`-cleaned text (#685 fix-commit
# round, High 2), not the raw file text: without it, a `.env`/CI-file line that only
# MENTIONS `NPM_CONFIG_IGNORE_SCRIPTS=true` inside a `#` comment ("# NPM_CONFIG_IGNORE_
# SCRIPTS=true once we roll this out") reported the repo as protected when nothing is
# actually set — reopening the exact #533 bug class already fixed for `_NPM_INSTALL_NO_FLAG`
# on a different regex. `strip_hash_comments` is the same quote-aware, already-shared
# `#`-comment stripper other guards use, not a bespoke re-implementation.
_NPM_CONFIG_ENV_TRUE = re.compile(
    r"""\bNPM_CONFIG_IGNORE_SCRIPTS\b\s*[:=]\s*["']?(?:true|1)\b["']?""",
    re.IGNORECASE,
)

# Detects `npm install` (with optional flags before/after) but NOT `npm install --ignore-scripts`.
# Also catches `npm ci` without `--ignore-scripts` (same risk surface).
#
# The exemption lookahead is bounded, because only a flag actually passed to THIS command may
# claim it (#533). Unbounded, it ran to end of line, so `npm install  # TODO: add
# --ignore-scripts` and `npm install && npm ci --ignore-scripts` both went silent while the
# first install stayed genuinely unprotected — a mention read as a directive.
#
# `#` is conditional here, unlike the unconditional `[^\n;|&#]` in claude_code_compromise.py's
# `_NET_CHANNEL`, and that divergence is deliberate rather than drift: in npm context `#` is
# also the git-ref and URL-fragment separator, so `npm install git+https://…/r.git#v1.2.3
# --ignore-scripts` is a protected install, not a comment. Requiring a preceding space
# (`(?<=\S)#` keeps a glued `#` INSIDE the span) is what separates the two. Measured over 14
# shapes: unbounded 10/14, a bare `[^\n#]` 8/14 — below the unfixed code — the sibling's class
# 11/14.
#
# Separators are only separators OUTSIDE quotes, so a quoted span is opaque to the scan (#540
# review, H1). A registry URL gets quoted precisely BECAUSE it contains `&`, and treating that
# `&` as a hard stop made `npm install --registry "https://r.example/?a=1&b=2" --ignore-scripts`
# — a protected install — report HIGH. The `["'](?=--ignore-scripts)` alternative is the one
# narrow way into a quoted span, so a quoted flag (`npm install "--ignore-scripts"`) is still
# seen; a LATER command's quoted flag is still not, because its separator stops the span first.
#
# DO NOT make the quotes ambiguous (matchable both as an opaque span and as an ordinary
# character) to buy the last edge case. That variant scores one point higher and backtracks
# catastrophically: 7.4 SECONDS on a failing match at 18 quote pairs, growing exponentially.
# Workflow files are attacker-influenceable input here, and pytest-timeout cannot preempt a
# C-level regex loop (see the pyproject.toml caveat). This form stays linear: 0.39 ms at 1000
# quote pairs. Measured 22/22 on the 14 shapes plus 8 adversarial additions.
_NPM_INSTALL_NO_FLAG = re.compile(
    r"\bnpm\s+(?:install|ci)\b"
    r"(?!(?:[^\n;|&#\"']|[\"'](?=--ignore-scripts)|\"[^\"\n]*\"|'[^'\n]*'|(?<=\S)#)*--ignore-scripts)",
)


class NpmIgnoreScriptsGuard(Guard):
    id = "npm-ignore-scripts"
    title = "npm install scripts not blocked (missing ignore-scripts=true)"
    area = "Dependencies"

    # Canary plant: EXPECTS-ONLY — no `files`. This is a file-ABSENCE check: it is tripped by the canary's
    # shared `package.json` (which `js-supply-chain` also trips) and anchors at `.npmrc`, a file that
    # deliberately does not exist. There is nothing to own. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # package.json at root with no .npmrc containing ignore-scripts=true ->
    # missing-ignore-scripts (file-absence guard).
    canary_plant = CanaryPlant(expects=frozenset({"npm-ignore-scripts/missing-ignore-scripts"}))

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features or "javascript" in profile.features

    @staticmethod
    def _env_ignore_scripts_enabled(root: Path) -> bool:
        """True if `NPM_CONFIG_IGNORE_SCRIPTS` is set truthy in a `.env`/`.env.*` file or a
        docker-compose file — the env-var equivalent of `.npmrc`'s `ignore-scripts=true`,
        scoped to config sinks that actually govern the environment `npm install` runs in
        (see the module docstring's "environment-variable form" section)."""
        for f in iter_files_named(root, ".env", ".env.*", respect_gitignore=False):
            if _NPM_CONFIG_ENV_TRUE.search(strip_hash_comments(read(f))):
                return True
        for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml"):
            if _NPM_CONFIG_ENV_TRUE.search(strip_hash_comments(read(f))):
                return True
        return False

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []

        pkg_json = root / "package.json"
        if not pkg_json.exists():
            # Nothing to check — no Node project here.
            return []

        # --- Check .npmrc ---
        npmrc = root / ".npmrc"
        npmrc_text = read(npmrc) if npmrc.exists() else ""

        # Raw by decision, and still owned by #1040 T4: `.npmrc` is ini, where `;` also starts a
        # comment, so the `hash` view would void a `; security: allow-npm-scripts` opt-out. The
        # CI site below routes through a view, which hides this one from the anchoring gate.
        if _PRAGMA not in npmrc_text:
            # npm trims whitespace around the `=`, so the spaced INI form `ignore-scripts = true`
            # is equally valid — a plain substring check false-fired on a hardened repo (#423).
            has_ignore = bool(_IGNORE_SCRIPTS_TRUE.search(npmrc_text))
            if not has_ignore:
                # The env-var equivalent: NPM_CONFIG_IGNORE_SCRIPTS=true set in a .env file or
                # a docker-compose service's environment, either of which governs the npm
                # install that runs inside that context just as .npmrc does.
                has_ignore = self._env_ignore_scripts_enabled(root)
            if not has_ignore:
                location = rel(root, npmrc) if npmrc.exists() else ".npmrc"
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="npm install scripts not blocked",
                        location=location,
                        message=(
                            "No `ignore-scripts=true` found in `.npmrc`. "
                            "Without this setting, npm executes `preinstall`, `install`, and "
                            "`postinstall` lifecycle scripts during `npm install`. A malicious "
                            "or compromised dependency can run arbitrary code at install time, "
                            "exfiltrating secrets from the environment, planting backdoors in "
                            "installed files, or pivoting into the build pipeline."
                        ),
                        remediation=(
                            "Create (or update) `.npmrc` at the repo root with the line:\n\n"
                            "    ignore-scripts=true\n\n"
                            "This suppresses all lifecycle scripts by default. If a specific "
                            "package genuinely needs its build step (e.g. native addons), "
                            "run `npm install --ignore-scripts=false <pkg>` for that package "
                            "only, keeping the default safe. Suppress this check in `.npmrc` "
                            "by adding `# security: allow-npm-scripts` only after confirming "
                            "the risk is accepted."
                        ),
                        rule="npm-ignore-scripts/missing-ignore-scripts",
                        standards=list(_STANDARDS),
                    )
                )

        # --- Check CI workflow files ---
        # Both spellings: GitHub Actions honors `.yml` and `.yaml` alike, and the other two
        # workflow scanners (actions_sha_pin.py, ci_secret_env_unscoped.py) already pass both.
        # Case variants are deliberately excluded — `walk_files` matches suffixes case-
        # sensitively and Actions itself only recognizes the lowercase forms.
        for wf in iter_files(root / ".github" / "workflows", (".yml", ".yaml")):
            text = read(wf)
            # The CI pragma covers ONE install (#539): the logical line it is written on, or the
            # line directly below a comment-only pragma line. It used to be a raw `_PRAGMA in
            # text` over the whole file, so one step's opt-out, a comment DECLINING the pragma,
            # or the phrase in an `echo` string silenced every install in the workflow, while
            # the remediation below told users it was per line.
            # - Backslash continuations are joined first (line numbers preserved, the finding
            #   anchors at the command's first physical line), so a `--ignore-scripts` on a
            #   continuation line is seen, and a pragma at the end of a continued command lands
            #   on the line the finding anchors to. Judging the pragma on the raw text instead
            #   voids that opt-out.
            # - The view is `hash`, not the `yaml` that `comment_dialect_for(".yml")` answers:
            #   `yaml` reads a `run: |` block scalar as content, so a shell comment inside the
            #   script (`npm install  # security: allow-npm-scripts`), a real opt-out, would stop
            #   counting (rule 4; agent_headless_trust_surface.py made the same call, #1000).
            # - "Directly above" means a COMMENT-ONLY line. The `lineno - 1 in pragma_lines`
            #   reach jwt_alg.py uses would let a pragma trailing one command cover the next
            #   step too: the file-wide bug again, one line over.
            joined = join_dockerfile_continuations(text)
            lines = joined.splitlines()
            view = comment_view(joined, "hash").splitlines()
            pragma_lines = {i for i, v in enumerate(view, 1) if _PRAGMA in v}
            pragma_above = {i + 1 for i in pragma_lines if lines[i - 1].strip() == view[i - 1].strip()}
            # The env-var equivalent, file-scoped: an `env:` block at workflow/job/step level
            # (or an inline `NPM_CONFIG_IGNORE_SCRIPTS=true npm install` on the run line
            # itself) protects every npm install/ci line in THIS file. Coarser than a real
            # job/step-scope resolution (a per-job env var reads as protecting a sibling job's
            # unrelated install too), the same file-wide trade-off this guard already makes
            # for `.npmrc` — see the module docstring's "environment-variable form" section.
            wf_env_protected = bool(_NPM_CONFIG_ENV_TRUE.search(strip_hash_comments(text)))
            for lineno, line in enumerate(lines, 1):
                if wf_env_protected or lineno in pragma_lines or lineno in pragma_above:
                    continue
                if _NPM_INSTALL_NO_FLAG.search(line):
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="CI workflow runs npm install without --ignore-scripts",
                            location=f"{rel(root, wf)}:{lineno}",
                            message=(
                                "`npm install` (or `npm ci`) in this CI step does not pass "
                                "`--ignore-scripts`. CI environments hold production secrets "
                                "and produce trusted artifacts — a lifecycle script from a "
                                "compromised dependency can exfiltrate those secrets or tamper "
                                "with build outputs before they reach production."
                            ),
                            remediation=(
                                "Add `--ignore-scripts` to the `npm install` / `npm ci` call:\n\n"
                                "    npm ci --ignore-scripts\n\n"
                                "Alternatively, set `ignore-scripts=true` in `.npmrc` at the "
                                "repo root (applies to all npm invocations). Suppress this "
                                "install with `# security: allow-npm-scripts` as a comment on "
                                "the same line, or on a comment line directly above it, only "
                                "after confirming the risk is accepted."
                            ),
                            rule="npm-ignore-scripts/missing-ignore-scripts",
                            standards=list(_STANDARDS),
                        )
                    )

        return out
