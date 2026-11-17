---
type: Guard
title: "npm-ignore-scripts"
description: "npm install scripts not blocked (missing ignore-scripts=true)."
timestamp: "2026-10-15T14:15:54Z"
guard_id: "npm-ignore-scripts"
checklist_section: ["5"]
standards: ["CIS:2.2", "OWASP:A06", "OWASP:A08"]
---

# npm install scripts not blocked (missing ignore-scripts=true)

## Threat

npm package installation executes arbitrary lifecycle scripts (`preinstall`, `install`,
`postinstall`) declared in any installed package's `package.json`. A malicious or
supply-chain-compromised dependency runs code **at install time** — before any code review,
before the application starts, and often before anyone notices. High-profile incidents
include event-stream (2018), node-ipc (2022), and the broader pattern of typosquatting
attacks that plant scripts to harvest environment variables and send them to attacker-
controlled servers.

CI environments are the highest-value target: they hold production secrets (API keys,
signing certificates, deploy tokens), run as trusted pipeline principals, and produce the
artifacts that reach production. A lifecycle script executed in CI is indistinguishable from
any other build step from the network and secrets perspective.

**OWASP A06** (Vulnerable and Outdated Components) covers supply-chain compromise via
package managers. **CIS Control 2.2** (Ensure Software is Supported by a Vendor) maps to
maintaining an authorized software inventory and rejecting unauthorized code execution
during the build.

## Detection design

The guard fires when a `package.json` is found at the repo root (indicating a Node project),
`.npmrc` either doesn't exist or doesn't contain `ignore-scripts=true` (spaced form included,
see #423), and no `NPM_CONFIG_IGNORE_SCRIPTS` env-var equivalent is found either (see "The
environment-variable form" below) — i.e. NONE of `.npmrc`, `.env`/`.env.*`, or
`docker-compose*.yml`/`*.yaml` shows the setting enabled.

It also scans CI workflow files for `npm install` or `npm ci` invocations that lack the
`--ignore-scripts` flag, using the pattern:

```regex
\bnpm\s+(?:install|ci)\b(?!(?:[^\n;|&#"']|["'](?=--ignore-scripts)|"[^"\n]*"|'[^'\n]*'|(?<=\S)#)*--ignore-scripts)
```

This is a negative lookahead: it matches `npm install` or `npm ci` only when `--ignore-scripts`
is actually passed **to that command**. The `\b` word boundary prevents matching `npminstall` (a
hypothetical binary name), and `\s+` absorbs any whitespace between `npm` and the subcommand.

### The exemption boundary (#533)

The lookahead span stops at a shell separator (`;`, `|`, `&`) and at a comment `#`. Only a flag
inside that span exempts the command. Without the boundary the span ran to end of line, so text
that never executes — or that belongs to a *later* command — silenced a genuinely unprotected
install:

| line | why it must still fire |
|---|---|
| `npm install  # TODO: use --ignore-scripts later` | a comment mentioning the flag is not the flag |
| `npm install && npm ci --ignore-scripts` | the second command's flag never protected the first |
| `npm install ; echo --ignore-scripts` | the flag is an argument to `echo` |

**`#` is conditional here, and that divergence from the sibling guard is deliberate.**
`claude_code_compromise.py` bounds with an unconditional `[^\n;|&#]`, which is right for shell
text but wrong for npm: `#` is also npm's git-ref and URL-fragment separator, so
`npm install git+https://github.com/o/r.git#v1.2.3 --ignore-scripts` is a *protected* install.
The `(?<=\S)#` alternative keeps a `#` glued to a non-space character inside the span, and only a
space-preceded `#` ends it. Measured across 14 shapes: the unbounded original scored 10/14, a
bare `[^\n#]` 8/14 (**below the unfixed code** — it trades one false negative for three false
positives on pinned git dependencies), and the sibling's class 11/14.

**A separator is only a separator outside quotes.** A quoted span is opaque to the scan, because a
registry URL gets quoted precisely *because* it contains `&`:

| line | behavior |
|---|---|
| `npm install --registry "https://r.example/?a=1&b=2" --ignore-scripts` | silent — the `&` is inside quotes, the flag is passed |
| `npm install --registry https://r.example/?a=1&b=2 --ignore-scripts` | **fires** — an unquoted `&` backgrounds the command, so the flag belongs to a different one |
| `npm install "--ignore-scripts"` | silent — quoting the flag does not stop it being passed |
| `npm install && echo "--ignore-scripts"` | **fires** — the quoted flag belongs to `echo` |

`["'](?=--ignore-scripts)` is the single narrow way *into* a quoted span, which is what keeps the
third row silent without making the fourth one silent too.

### Backslash continuations (#539)

The regex runs once per **logical** line: a workflow's backslash continuations are joined first
(`join_dockerfile_continuations`, which keeps line numbers), so a flag on a continuation line is
passed to the command it continues. A finding anchors at the command's first physical line.

| `run: \|` script | behavior |
|---|---|
| `npm install \` / `--ignore-scripts` | silent (it fired before #539) |
| `npm install \` / `--save-dev foo` | **fires**: no flag on any line of the command |
| `npm install \` / `&& npm ci --ignore-scripts` | **fires**: the flag belongs to the second command |
| `npm install git+https://h/r.git#v1 \` / `--ignore-scripts` | silent: the join keeps the #533 `#` rule |

### The opt-out pragma and its reach

`# security: allow-npm-scripts` has a different reach for each of the two signals:

- **`.npmrc`: the whole file.** The repo-level finding is about that file, so the pragma anywhere in
  it silences it. This site still matches the raw text by decision: `.npmrc` is ini, where `;` also
  starts a comment, and the `hash` view would void a `; security: allow-npm-scripts` opt-out. #1040
  owns it.
- **A CI workflow: one install (#539).** The pragma silences the install it is written on, as a
  comment on that logical line, or on a comment-only line directly above it:

  ```yaml
  - run: npm ci  # security: allow-npm-scripts
  # security: allow-npm-scripts
  - run: npm install
  - run: |
      npm install \
        --build-from-source  # security: allow-npm-scripts
  ```

  It counts only as a real comment. The view is `hash`, not `yaml`, so a shell comment inside a
  `run: |` script still counts. A pragma inside a quoted string does not count, and neither does a
  pragma anywhere else in the file. The "line above" must be comment-only: a pragma trailing one
  command does not also cover the next command.

Before #539 the CI pragma was a raw substring test over the whole workflow file. One step's opt-out,
a comment *declining* the pragma, or the phrase inside an `echo` string silenced every install in
the file, while the printed remediation said "on the same line".

> **Do not make the quotes ambiguous** (matchable both as an opaque span *and* as an ordinary
> character) to buy the last edge case. That variant scores one point higher and backtracks
> catastrophically: **7.4 seconds** on a failing match at 18 quote pairs, growing exponentially.
> Workflow files are attacker-influenceable input to this scanner, and `pytest-timeout` cannot
> preempt a C-level regex loop (see the `pyproject.toml` caveat). The shipped form stays linear:
> 0.39 ms at 1000 quote pairs. Final score: **22/22** on the 14 shapes plus 8 adversarial
> additions.

**Files scanned:**

- `<root>/package.json` — presence triggers the check
- `<root>/.npmrc` — checked for `ignore-scripts=true`
- `<root>/.env` and `.env.*` (`respect_gitignore=False`) — checked for a truthy
  `NPM_CONFIG_IGNORE_SCRIPTS` (see below); suppresses the repo-level `.npmrc` finding
- `<root>/docker-compose*.yml` and `*.yaml` — same env-var check, for a service's
  `environment:` block; also suppresses the repo-level `.npmrc` finding
- `<root>/.github/workflows/*.yml` and `*.yaml` — scanned for npm install without flag, and
  for the same env-var check (suppresses that file's CI-line findings only, see below).
  Both spellings, matching `actions_sha_pin` and `ci_secret_env_unscoped`; case variants
  (`.YML`) are deliberately excluded, since suffix matching is case-sensitive and GitHub
  Actions only recognizes the lowercase forms. The walk is rooted at the workflows directory,
  so a `.yaml` elsewhere in the repo is not scanned.

### The environment-variable form (`NPM_CONFIG_IGNORE_SCRIPTS`)

npm maps any `NPM_CONFIG_<KEY>` environment variable onto the matching kebab-case config
key, so `NPM_CONFIG_IGNORE_SCRIPTS=true` is functionally identical to `ignore-scripts=true`
in `.npmrc`. The guard recognizes a truthy assignment (`true`/`1`, quoted or bare) via:

```regex
\bNPM_CONFIG_IGNORE_SCRIPTS\b\s*[:=]\s*["']?(?:true|1)\b["']?
```

matched against two independent sink groups:

1. **Repo-level (suppresses the `.npmrc` finding):** any `.env`/`.env.*` file, or any
   `docker-compose*.yml`/`*.yaml` file — a compose service's `environment:` block (mapping
   or list form) or a `.env` file compose loads for interpolation both govern the `npm
   install` that runs inside that container, the same way `.npmrc` governs a bare local
   install.
2. **CI-level (suppresses that workflow file's CI-line findings only):** the workflow
   file's own text — an `env:` block at workflow, job, or step level, or an inline
   `NPM_CONFIG_IGNORE_SCRIPTS=true npm install` shell assignment on the run line itself.

Both are deliberately **file-scoped, not job/step-scoped** — a per-job `env:` block is read
as protecting every `npm install`/`npm ci` line in the same workflow *file*, including a
sibling job that doesn't actually inherit it. This is the same coarse-grained trade-off the
guard already makes for `.npmrc` (repo-wide, not per-route): true job/step resolution would
need to parse the YAML structure, not just search its text.

Deliberately **NOT** extended to `process.env`/`os.environ` reads inside application source:
`npm install` runs as a separate process, before any application code executes, so a value
assigned to `process.env.NPM_CONFIG_IGNORE_SCRIPTS` in server code has no effect on the
install that already happened. Recognizing that pattern would silence a genuinely
unprotected install rather than correctly suppress a protected one — the wrong direction for
a HIGH-severity finding.

**Comment-aware (fixed 2026-09-02, #685 fix-commit round, High 2).** Both sink groups run
the file text through `strip_hash_comments()` (the same shared, quote-aware `#`-comment
stripper other guards use) before matching — reopening the exact #533 bug class already
fixed for the CI-line regex, but on this env-var regex: a `.env`/CI-file line that only
*mentions* `NPM_CONFIG_IGNORE_SCRIPTS=true` inside a `#` comment ("once we roll this out")
previously read as real protection on a genuinely unprotected repo.

## Severity rationale

**HIGH.** Supply-chain attacks via npm lifecycle scripts are active, well-documented, and have
a proven track record of exfiltrating secrets. The mitigation (`ignore-scripts=true`) is a
one-line change with negligible false-positive risk for the vast majority of Node projects.
The attack requires no runtime exploitation — installation is sufficient. CI-targeting
elevates the impact to potential full pipeline compromise.

## Known bypasses / false negatives

| Bypass | Notes |
|---|---|
| `NPM_CONFIG_IGNORE_SCRIPTS=true` set somewhere other than `.env`/`.env.*`, a `docker-compose*.yml`/`.yaml` file, or the CI workflow file's own text | Detected in those three sink groups (see "The environment-variable form" above); a project setting it through some OTHER mechanism (a shell profile, a Kubernetes manifest, a Makefile `export`) still trips the `.npmrc` finding |
| Per-job/per-step `NPM_CONFIG_IGNORE_SCRIPTS` in one CI job protecting only that job | The CI-side check is file-scoped, not job/step-scoped — a sibling job's genuinely unprotected `npm install` in the same workflow FILE also goes silent |
| Per-package `scripts.ignore` in advanced npm configs | Not detected; very uncommon. |
| `pnpm` or `yarn` | This guard targets npm only. `pnpm` has its own `ignore-scripts` config. A project using pnpm exclusively will still trigger if `package.json` is present, because the `.npmrc` check is npm-centric. |
| Multi-step CI: flag on one step, not another | Each `npm install` line is checked independently. A step that omits the flag fires even if a different step includes it. |
| A comment-only line directly above an install that *mentions* the pragma (`# do NOT add security: allow-npm-scripts`) | The comment line above an install is read as an opt-out of that install whatever else it says. Only that one install is affected. A mention anywhere else no longer silences anything (#539) |
| A shell comment ending in `\` (`npm install  # see docs \`) followed by a pragma'd command | The joiner continues the commented line (correct for Dockerfiles; in shell the `\` belongs to the comment), so the next command's pragma lands on the first install's logical line and silences it. A rare shape, and the guard got it wrong before #539 too |
| `.npmrc` in a subdirectory (monorepo) | Only the root `.npmrc` is checked; package-level `.npmrc` files are not scanned. |

## False positive scenarios

| Scenario | Guard behavior | Recommended action |
|---|---|---|
| `.npmrc` exists with `ignore-scripts=true` | Silent — no finding | None needed |
| `npm install --ignore-scripts` in CI | Silent — regex lookahead prevents match | None needed |
| `npm install` in a comment or doc string in a YAML step | May fire (regex is not YAML-aware) | Suppress with `# security: allow-npm-scripts` on that line |
| `npm install \` with `--ignore-scripts` on a continuation line | Silent: continuations are joined (#539) | None needed |
| Project uses pnpm/yarn exclusively, `.npmrc` is pnpm-specific | May fire for `.npmrc` missing `ignore-scripts=true` | Add `ignore-scripts=true` to `.npmrc` (safe for pnpm too) or suppress |
| `package.json` at root is not a runnable Node project (e.g. a monorepo workspace manifest only) | May fire | Add `ignore-scripts=true` to root `.npmrc`; the setting is harmless |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| 5-npm-install-scripts-blocked | uncovered | covered | Guard detects absent `ignore-scripts=true` in `.npmrc` and unguarded `npm install` in CI workflows |

## Tests

| Test | Validates |
|---|---|
| `test_npm_ignore_scripts_no_npmrc_fires` | True positive: `package.json` present, no `.npmrc` — finding emitted |
| `test_npm_ignore_scripts_npmrc_without_flag_fires` | True positive: `.npmrc` exists but lacks `ignore-scripts=true` |
| `test_npm_ignore_scripts_silent_when_flag_set` | False positive guard: `.npmrc` has `ignore-scripts=true` — no finding |
| `test_npm_ignore_scripts_ci_workflow_fires` | True positive: CI workflow has `npm install` without `--ignore-scripts` |
| `test_npm_ignore_scripts_ci_workflow_with_flag_silent` | False positive guard: CI has `npm ci --ignore-scripts` — no finding |
| `test_npm_ignore_scripts_pragma_silences_npmrc` | Pragma suppression: `.npmrc` with pragma but no flag — silent |
| `test_npm_ignore_scripts_pragma_silences_ci` | Pragma suppression: the pragma on the install's own line, as the remediation prints it, is silent (#539: this test used to plant the pragma on line 1 and the install on line 5, which pinned file scope) |
| `test_npm_ignore_scripts_no_package_json_silent` | Applies gate: no `package.json` — no finding regardless of `.npmrc` |
| `test_npm_ignore_scripts_silent_with_spaced_form` | False positive guard: the spaced INI form `ignore-scripts = true` is valid hardening (#423) |
| `test_npm_ignore_scripts_applies_gate` | Feature gate: guard does not apply to non-frontend stacks |
| `test_npm_ignore_scripts_ci_trailing_comment_fires` | True positive (#533): a comment mentioning `--ignore-scripts` does not exempt the install |
| `test_npm_ignore_scripts_ci_shell_separator_shapes_fire` | True positive (#533): a flag after `&&` / `;` / `\|` belongs to a later command |
| `test_npm_ignore_scripts_ci_protected_stays_silent` | False positive guard: a flag genuinely passed to the command still exempts it (incl. `=true`, and with a trailing comment) |
| `test_npm_ignore_scripts_ci_git_ref_fragment_stays_silent` | False positive guard, **load-bearing**: `#` as a git-ref / URL fragment is not a comment. Goes red if the pattern is simplified to `[^\n#]` or to the sibling's `[^\n;\|&#]` |
| `test_npm_ignore_scripts_ci_hash_before_the_command_stays_silent` | False positive guard: a `#` in an earlier quoted string precedes the match start |
| `test_npm_ignore_scripts_ci_quoted_separator_stays_silent` | False positive guard (#540 review): `;` / `\|` / `&` inside a quoted argument are not separators |
| `test_npm_ignore_scripts_ci_quoted_flag_stays_silent` | False positive guard: a quoted flag is still passed. Goes red on the opaque-quotes simplification |
| `test_npm_ignore_scripts_ci_quoted_flag_of_later_command_fires` | True positive: making a quoted flag visible must not become a new bypass |
| `test_npm_ignore_scripts_ci_unquoted_separator_still_fires` | True positive: an unquoted `&` really does background the command. Goes red on a blanket "ignore all separators" over-correction |
| `test_npm_ignore_scripts_yaml_extension_workflow_fires` | True positive: the `.yaml` workflow spelling is scanned |
| `test_npm_ignore_scripts_yaml_extension_protected_stays_silent` | False positive guard: the widened extension set brings no new FPs |
| `test_npm_ignore_scripts_yaml_outside_workflows_not_scanned` | Scope guard: a `.yaml` outside `.github/workflows` stays unscanned |
| `test_npm_ignore_scripts_env_file_truthy_silences_repo_finding` | False negative closed: `NPM_CONFIG_IGNORE_SCRIPTS=true` in `.env` (no `.npmrc` at all) suppresses the repo-level finding |
| `test_npm_ignore_scripts_env_file_dotenv_variant_silences` | False positive guard: the `.env.*` glob (e.g. `.env.production`) is scanned, and `1` is a valid truthy spelling |
| `test_npm_ignore_scripts_compose_environment_block_silences` | False negative closed: a compose service's mapping-form `environment:` block is recognized |
| `test_npm_ignore_scripts_compose_environment_list_form_silences` | False negative closed: a compose service's list-form `environment:` entry is recognized |
| `test_npm_ignore_scripts_env_var_falsy_still_fires` | True positive (traded-against direction): a `false` value is not protection |
| `test_npm_ignore_scripts_env_var_absent_still_fires` | True positive (traded-against direction): no `.npmrc`/`.env`/compose protection at all still fires |
| `test_npm_ignore_scripts_ci_env_block_silences_ci_line` | False negative closed: a workflow-level `env:` block suppresses that file's CI-line finding |
| `test_npm_ignore_scripts_ci_inline_env_assignment_silences_ci_line` | False negative closed: an inline `NPM_CONFIG_IGNORE_SCRIPTS=true npm install` shell assignment is recognized |
| `test_npm_ignore_scripts_ci_env_block_missing_still_fires` | True positive (traded-against direction): a workflow with no env-var protection still fires |
| `test_npm_ignore_scripts_env_var_in_unrelated_file_not_scanned` | Scope guard: the env var mentioned in an unrelated file (e.g. `README.md`) is not a recognized sink |
| `test_npm_ignore_scripts_ci_pragma_is_line_scoped` | True positive (#539): one step's pragma does not silence a later step |
| `test_npm_ignore_scripts_ci_pragma_mention_in_comment_does_not_blind_file` | True positive (#539): a top-of-file comment declining the pragma silences nothing |
| `test_npm_ignore_scripts_ci_pragma_in_string_does_not_suppress` | True positive (#539, #424): the phrase in an `echo` string is not a pragma |
| `test_npm_ignore_scripts_ci_trailing_pragma_does_not_cover_next_command` | True positive (#539): a trailing pragma does not reach the next command. Goes red on the naive `lineno - 1` reach |
| `test_npm_ignore_scripts_ci_pragma_in_run_block_shell_comment_silences` | False positive guard, rule 4: a shell-comment pragma inside `run: \|` still counts. Goes red on the `yaml` view |
| `test_npm_ignore_scripts_ci_pragma_on_continuation_line_silences` | False positive guard: a pragma at the end of a continued command counts. Goes red if the pragma is judged on the raw text |
| `test_npm_ignore_scripts_ci_pragma_comment_line_above_silences` | False positive guard: a comment-only pragma line covers the install directly below it, and only that one. Goes red on same-line-only |
| `test_npm_ignore_scripts_ci_far_pragma_no_longer_silences` | The #539 behavior change: a pragma at the top of the file, or two lines above the `run:`, no longer reaches the install |
| `test_npm_ignore_scripts_ci_backslash_continuation_flag_silent` | False positive closed (#539): a flag on a continuation line, including a third line and CRLF, protects the install |
| `test_npm_ignore_scripts_ci_backslash_continuation_without_flag_fires` | True positive (#539): a continued install with no flag of its own still fires, at the command's first line |
| `test_npm_ignore_scripts_ci_continuation_keeps_separator_semantics` | The join composes with the #533/#540 lookahead: a git-ref `#` and a quoted `&` stay in the span; a commented flag still does not count |

# Citations

[1] agentsec checklist item `5-npm-install-scripts-blocked` (§5)
[2] CIS:2.2
[3] OWASP:A06
[4] OWASP:A08
