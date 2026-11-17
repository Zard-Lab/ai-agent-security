# Breaking Changes

_Issue and PR numbers below (`#NNN`) refer to the maintainers' development tracker, not to this repository's issues._

Every backward-incompatible change to agentsec's behavior, output, CI gate, or a user-authored on-disk file. Read
this before upgrading across a **MINOR** bump (`v0.MINOR.0`); PATCH releases (`v0.MINOR.Z`, Z > 0) never break.

Entries are reverse-chronological. Each names the version it ships in, what broke, who is affected, and how to
migrate. The versioning policy is summarised at the top of [`CHANGELOG.md`](CHANGELOG.md). The topmost
entry's version must not fall behind the current checklist MINOR (enforced by `tests/test_versioning_policy.py`).

---

## v0.22.0

_Unreleased. Targets the next MINOR._

### The copier CI template is removed; use the GitHub Action, `ci add` and the pre-commit manifest

**What changed:** the `templates/` copier template is gone, and `copier` is no longer a `[dev]`
dependency. Its two outputs have new homes: the audit workflow is the composite GitHub Action at the
agentsec repo root (`action.yml`), and the pre-commit hook is a hook manifest (`.pre-commit-hooks.yaml`)
you reference by `repo:` + `rev:`. The extra gates its `ci_components` selection used to install are
`agentsec ci add <id>`, as they always were underneath.

**Why:** the template rendered a workflow frozen at `agentsec_ref` (default `main`, unpinned) until
someone ran `copier update`, could not install agentsec from a private repo, needed `copier copy --trust`
(which lets a template run commands on your machine), and its `language: system` hook only worked when
agentsec was already on your `PATH`. A pinned action ref gets Dependabot/Renovate bumps for free, and a
`language: python` hook lets pre-commit install agentsec itself.

**Who is affected:** a repo that ran `copier copy` against `templates/`; it carries a
`.copier-answers.yml` and a `.github/workflows/agentsec-security.yml`. Nothing breaks on its own: the old
workflow keeps running, unpinned at `main`, but `copier update` can no longer refresh it. `agentsec ci
doctor` flags that workflow's `@main` install.

**How to migrate:**
1. Delete `.github/workflows/agentsec-security.yml` and `.copier-answers.yml`.
2. Add the action to a workflow, pinned by commit SHA (user guide section 16 has the full inputs table):
   ```yaml
   - uses: actions/checkout@<sha>
   - uses: Zard-Lab/ai-agent-security@<40-hex sha>   # vX.Y.Z
     with:
       fail-on: high
   ```
3. If you used the template's pre-commit hook, replace its `repo: local` block in
   `.pre-commit-config.yaml` with:
   ```yaml
   repos:
     - repo: https://github.com/Zard-Lab/ai-agent-security
       rev: vX.Y.Z
       hooks:
         - id: agentsec-guards
   ```
   pre-commit now installs agentsec into the hook's own environment, built with the Python version
   pre-commit runs on. agentsec needs Python 3.12 or newer, so if pre-commit runs on an older Python,
   add `language_version: python3.12` under the hook.
4. Re-add any extra gates you had selected with `agentsec ci add <id> [<id> ...] .`.

### A waiver carrying a `fingerprint` no longer falls back to its `rule` + `location`

**What changed:** in `agentsec-exceptions.json` (and a repo's `.agentsec/suppress.json`), an entry that
carries a `fingerprint` is now matched on that fingerprint **alone**. Previously the fields were OR-ed:
if the fingerprint did not match, the entry still fell back to matching by `rule` plus `location`.

**Why:** the triage bridge (`agentsec triage --write-exception`) writes `rule` + a line-stripped,
file-scoped `location` + `fingerprint` into a single entry. The OR meant one `fp` verdict about one
finding also suppressed every other finding of that guard anywhere in that file, including findings with
a different fingerprint that had never been triaged. Measured on a two-secret fixture: a verdict about a
pair of AWS keys silently suppressed a pair of unrelated OpenAI keys in the same file (issue #507).

**Who is affected:** anyone whose registry was generated or extended by `agentsec triage
--write-exception`. Findings that were being suppressed by the rule+location fallback rather than by the
fingerprint itself **will re-surface**, and may fail a `--fail-on` gate that previously passed. Registries
written by `agentsec audit --write-baseline` are unaffected: those entries record the full
`path:line:col`, so the fallback was never doing any work for them. Hand-written entries with no
`fingerprint` are unaffected and keep their existing rule/location semantics.

**How to migrate:** re-triage the re-surfaced findings, or, if a deliberate whole-file waiver is what you
want, write it explicitly as an entry with a `rule` and `location` and **no** `fingerprint`.

### The report now names waivers that suppressed more than one finding

**What changed:** the audit report footer gains a `_Broad waiver:_` line for every waiver that suppressed
two or more findings, alongside the existing `_Accepted via exceptions (suppressed):_` total.

**Why:** the fingerprint basis deliberately collapses same-rule/same-file/same-message findings to one
identity, so one waiver legitimately covering several findings is expected. A bare total made that
indistinguishable from one-waiver-per-finding: on agentsec's own tree a single waiver covered 485
findings and the report said nothing (issue #507).

**Who is affected:** anyone diffing report text or asserting on the footer. The line is additive; no
existing line changed.

### A URL port is no longer stripped from a finding's triage identity

**What changed:** `Finding.stable_fingerprint()`, the line-insensitive identity the triage layer keys on,
stripped a trailing `:line[:col]` with no URL guard, so `scheme://host:9200` lost its **port** the same way
a line number is lost. Two findings differing only by port collapsed to one identity (`_TRIAGE_VERSION` 2 to
3). Because `Exception_.matches` tests the fingerprint before the location and returns early, one port's
waiver suppressed the other: triaging a MEDIUM at `:9200` as a false positive silently waived an unrelated
CRITICAL at `:6379`, with exit 0 and no diagnostic (issue #567, PR #700).

**Who is affected:** anyone with an `agentsec-triage.json` (or a waiver bridged from one into
`agentsec-exceptions.json`) holding a verdict on a location of the form `scheme://host:port`, which in
practice means findings ingested via `--ingest sarif=PATH` from a network-facing SARIF producer. Guard
findings use repo-relative paths and are unaffected; so are ZAP alerts, whose locations drop the scheme and
host before they are stored. Verdicts on ordinary `path:line` locations still match and do not re-surface.

**Migration:** re-run `agentsec triage <repo>` to re-classify anything that re-surfaces. The direction is
fail-closed: an affected verdict goes inert and its finding comes back as untriaged rather than staying
hidden, so the upgrade cannot lose a suppression silently. On load, `agentsec` prints the older-scheme
warning for any triage file written under `v2`. Anything that re-surfaces is worth reading rather than
re-waiving on sight: a finding that was waived by a collapse was never actually reviewed.

### An inline suppress pragma counts only when it is written as a comment

**What changed:** a guard's inline opt-out (`# security: allow-<id>`, `// …`, `-- …`) is now matched against a
comment-only view of the file (`comment_view` / `pragma_present` in `agentsec/guards/base.py`). The same
phrase inside a string literal, docstring, YAML block scalar, SQL literal or SQL quoted identifier no longer
suppresses, in every file type that has a comment dialect (Python, JS/TS, SQL, YAML, the `#`-comment configs
and shell, HCL, Go, PHP, Java, Ruby); a grammar without one yet (Rust, the C family, Perl, JSON) is still
matched on its raw text. A pragma's **reach** is unchanged: whichever line, block, file or repo scope a guard
documented is exactly the scope it keeps. The CloudFormation `cfn-*` per-resource checks have moved: in a YAML
template the pragma counts only as a `#` comment inside the flagged resource, so the phrase in a
`Description:` or `Metadata:` value no longer suppresses (a JSON template, which has no comments, is still
matched on its raw text). The first Python guards have moved too: in `api-docs-exposed`,
`auth-dependency-not-applied`, `auth-disabled-by-default`, `bola`, `checkout-price-from-server`,
`code-injection-eval-exec`, `command-injection`, `cors-wildcard`, `csv-injection`, `debug-default-off`,
`dynamic-import-non-literal`, `fulfill-on-completed-not-created`, `graphql-mutation-idor`,
`hardcoded-password-default-arg`, `insecure-file-permissions`, `jwt-exp-too-long`,
`langchain-load-prompt-traversal`, `llm-output-to-sink`, `llm-tool-dynamic-dispatch`, `ml-model-provenance`
and `xxe-safe`, the phrase in a string on the flagged line (or in the flagged route or resolver) no longer
suppresses. In `dependency-version-floor`, `# security: allow-old-<package>` now counts only as a `#` comment,
so a TOML string value carrying it no longer silences a `pyproject.toml` floor. The rest of the Python guards
followed: in `llm-output-html-sink`, `no-pan-stored`, `nosql-metadata-injection`,
`obfuscated-payload-execution` (its Python rules and its shell scripts; a SKILL.md is still matched raw),
`open-redirect`, `paramiko-host-key-trust`, `path-traversal`, `privileged-field-assignment`, `redos`,
`response-model-set` (both of its pragmas), `secret-str-serialized`, `sensitive-logging`,
`sqlalchemy-text-parameterized`, `ssrf-general`, `ssti`, `stripe-payments` (its subscription-state and
live-key rules), `unauthenticated-file-download`, `unrestricted-file-upload`, `weak-crypto`,
`weak-password-length-check` and `weak-secret-key-literal`, the phrase in a string on the flagged line (or the
line above, where the guard reads it, or in the flagged route) no longer suppresses. In SQL a dollar-quoted
body is read as code, so a `--` comment inside a `DO $$ … $$` block or a function body is a real opt-out; a
phrase inside a dollar-quoted string that is not such a body (`COMMENT ON … IS $$…$$`) is read the same way
and still counts. The shell, Dockerfile, workflow and server-config checks (`sshd_config`, nginx, Caddy,
Unbound, `.gitignore`) have moved: the phrase in a quoted string on the flagged line no longer suppresses, and
a `#` comment inside a workflow `run: |` script still does. VS Code's `tasks.json` and `launch.json` are JSONC
and are now read on the JS comment view, so a JSON string quoting the phrase no longer suppresses
`vscode-tasks-auto-exec`. The guards that read JSON or Markdown alongside a commented type count only a
comment in that type: YAML for `empty-password-in-config`, YAML and TOML for `mcp-config-security`,
`pnpm-workspace.yaml` for `js-supply-chain`, and shell scripts, Makefiles, `.env*`, YAML and git hooks for
`claude-code-compromise`.

**Why:** the match used to run over the raw file text, so a module that merely *documented* the opt-out —
the exact `# security: allow-<id>` string every remediation message tells users to write — silenced every
real finding in its scope with no trace, and for the repo-wide-scoped guards one such docstring anywhere
blinded the guard across the whole tree. Measured on agentsec's own canary, close to half of all guards went
silent that way (issue #424, the pragma-anchoring rider).

**Who is affected:** anyone whose pragma sits inside a string, docstring, YAML `run: |` script body, SQL
literal or SQL quoted identifier rather than in a comment. No documentation ever showed that form, but it
worked, so the findings it was hiding **will re-surface** and may fail a `--fail-on` gate that previously
passed. A pragma written as a comment, in the file's own comment syntax, is unaffected.

**How to migrate:** move the phrase into a real comment at the scope the guard's wiki page states, or waive
the finding through the expiring exception registry. A pragma inside a YAML block scalar (`run: |`) is string
content to YAML: put it on a `#` comment line of the YAML document, outside the scalar, instead.

### The `npm-ignore-scripts` CI pragma covers one install, not the whole workflow file

**What changed:** in a GitHub Actions workflow, `# security: allow-npm-scripts` now silences only the
`npm install` / `npm ci` it is written on: as a comment on that line (a backslash-continued command
counts as one line), or on a comment-only line directly above it. It used to silence every install in
the workflow file, from anywhere in the file, and it matched the raw text. So a comment *declining* the
pragma, or the phrase inside an `echo` string, also counted. This is the one deliberate exception to
the #424 entry above, whose reach stayed unchanged. The pragma in `.npmrc` still covers that whole
file, unchanged.

**Why:** the remediation printed with every CI finding has always said to put the pragma "on the same
line". The code behaved otherwise, so one step's opt-out silently blinded every other install in the
file, including installs added later by someone who never saw it (issue #539).

**Who is affected:** workflows whose pragma is neither on the install it is meant for nor on the comment
line directly above it, such as a pragma at the top of the file or above a step's `- name:`. Those
installs **will re-surface** as HIGH findings and may fail a `--fail-on` gate that previously passed.
A pragma written the way the remediation shows is unaffected. A separate change in the same fix: an
install whose `--ignore-scripts` sits on a backslash-continuation line is now recognised as protected,
and stops reporting.

**How to migrate:** move the pragma onto each install line it is meant for, or onto a comment line
directly above it. For this guard, unlike the #424 note above, a shell comment inside a `run: |`
script also counts: `npm ci  # security: allow-npm-scripts`.

## v0.21.0

_Released 2026-07-18._

### Machine-ledger files relocated from `docs/knowledge/` to `docs/ledger/`

**What changed:** the seven machine-maintained ledger / staging files moved into a new dedicated
directory, `docs/ledger/`. `docs/knowledge/` is now human knowledge only. The files:
`intake-ledger.json`, `guard-improvement-ledger.json`, `proposed-items.json`,
`deps-monitor-exceptions.json`, `feeds.json`, `marconi-merge-ledger.md`, and
`checklist-proposed-additions.md`.

**Who is affected:** anyone whose automation, scripts, or forks reference these files by their old
`docs/knowledge/` path. In particular the `/threat-intake` skill/command + workflow, the deps-monitor
waiver loader, and the `land-pr` / `scripts/branch-status.sh` merge-ledger flow all moved with the
files, so a branch cut before this release that stages any of them lands on the old path and conflicts
on rebase.

**Migration:** update every reference to the new `docs/ledger/<file>` path (or `git mv` the files on
your fork). In-flight threat-intake proposal PRs must relocate their staged `intake-ledger.json` /
`proposed-items.json` / `checklist-proposed-additions.md` edits into `docs/ledger/` before merging.
The tool's runtime behavior, report output, and CI gate are otherwise unchanged; only on-disk paths moved.

## v0.20.0

_Released 2026-07-05 (PR #330, issue #325)._

### Triage + exception fingerprints unified on one canonical identity

**What changed:** the fingerprint scheme that matches findings to recorded triage verdicts changed
(`_TRIAGE_VERSION` 1 to 2). A finding's identity is now computed the same way for both triage and exceptions.

**Who is affected:** anyone with an `agentsec-triage.json` written by a pre-`v0.20.0` version. Existing verdicts
no longer match the newly-computed fingerprints, so previously-triaged findings re-surface as untriaged.

**Migration:** re-run `agentsec triage <repo>` to re-classify the re-surfaced findings under the new scheme. The
old verdicts are not lost from the file, but they no longer apply; re-triaging writes fresh entries under the
`v2` scheme. On load, `agentsec` now prints an actionable warning when it reads a triage file written under an
older fingerprint scheme (added in #330) instead of silently dropping the matches.
