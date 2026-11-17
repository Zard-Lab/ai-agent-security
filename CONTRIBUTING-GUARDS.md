# Contributing a guard

`agentsec` accepts guard contributions. This document is the bar every guard PR is held to — it
distills the CI gate that already enforces this (the drift tests + canary), so the requirements
here are not aspirational, they are literally what merges and what doesn't.

This is Phase 1 of the maintainers' community-guards RFC:
publish the bar before opening the contribution path further. A quarantined `COMMUNITY_GUARDS` pool
(Phase 2 of that RFC) is planned but not yet built — today, a contributed guard lands the same way a
maintainer-built one does: in `agentsec/guards/`, registered in `ALL_GUARDS`, after human review.

## The 6-file recipe

A new guard touches exactly these files (`CLAUDE.md`'s "Adding a check" section is the canonical
copy of this list — this is the contributor-facing mirror):

1. **`agentsec/guards/<id>.py`** — the guard module. The module stem is the `id` with underscores;
   `test_guard_module_stem_matches_its_id` enforces it (a pinned legacy set is exempt). Subclass
   `Guard`, set `id`/`title`, implement
   `applies(profile)` (gate on `profile.features`) and `run()`. Map findings via `Finding.standards`
   (e.g. `["OWASP-LLM:LLM01"]`). Reuse the `guards/base.py` helpers rather than re-implementing
   file walking or parsing. `iter_files`, `read`, `rel`, `python_scan_dirs` and `strip_sql_comments`
   cover most guards; the **full grouped index of every public helper is the module docstring at the
   top of `agentsec/guards/base.py`**, generated from the helpers' own docstrings so it cannot drift.
   Comment stripping, path classification, Terraform/compose block iteration and the cross-file
   router-auth resolvers all already exist there.
2. **`agentsec/registry.py`** — import the guard and add one instance to `ALL_GUARDS`.
3. **`tests/guards/test_<id>.py`** — the guard's own test file, named for the `id` and not the
   module stem; `test_every_guard_has_a_test_file` enforces that in both directions (a guard with no
   `test_<id>.py`, and a `test_*.py` matching no guard, both fail). At minimum: one planted-violation
   test (it fires) and one FP-bait test (it stays silent on a look-alike safe pattern). Copy the
   shape of an existing test file for a similar guard rather than starting from scratch.
4. **`wiki/guards/<id>.md`** — the design doc, from `wiki/guards/TEMPLATE.md`.
   `test_every_guard_has_a_design_doc` fails CI without it. It is an **OKF concept doc**, so it
   opens with frontmatter: the four required OKF fields (`type: Guard`, `title`, a one-sentence
   `description` ending in a period, a quoted ISO-8601 `timestamp`) plus `guard_id`,
   `checklist_section` and `standards`. Body order is prose → your `##` sections → `# Citations`
   last.
   - **The checklist section goes in `checklist_section`, never in the heading.** It is always a
     list (`["6a"]`), and the drift test checks every id in it against the sections
     `checklist.json` maps your guard to via `check_ids`. Guard docs written before 2026-08 put a
     `§` in the H1; that convention is gone.
   - Write it in `wiki/`, never in `docs/knowledge/` — that tree is private dev-process only. If
     your branch predates this move and you already wrote one at the old path, rebase and run
     `python scripts/migrate_guard_docs.py --write` to relocate it.
5. **What your guard declares about itself** — four class attributes directly under `id`/`title`.
   This is still a **six-file** recipe: they all live in file 1, next to the guard they describe,
   so adding a guard never means editing a file every other guard branch is also editing.
   - **`area`** (required) — which app-area section your finding appears under in
     `agentsec audit --format summary`, the plain-English "vibe view". Pick a value from
     `agentsec/checkmeta.py::AREA_ORDER`; the vocabulary is closed, so a new bucket means adding it
     there first. `test_every_registered_check_declares_an_area` fails CI if you skip it.
   - **`tier`** — leave it alone unless your guard is universal hygiene that should run before and
     regardless of stack detection, in which case set `tier = "baseline"`.
   - **`surfacing`** — set `True` only if your guard points at an *architecture to review* rather
     than proving a bug (`bola`, `lethal-trifecta`). It ranks the finding below proven ones of the
     same severity, so do not set it on a guard that asserts a real defect. If only some of your
     rules are review signals, use `surfacing_rule_prefixes = ("<prefix>/",)` instead.
   - **`canary_plant`** — declare one unambiguous violation next to the guard itself:
     `canary_plant = CanaryPlant(files={"<path>": "<content>"}, expects=frozenset({"<rule>"}))`.
     `agentsec doctor --canary` proves the guard fires end-to-end against the real pipeline; a
     guard with no live-firing plant is reported DEAD.
     - If the violation belongs in a **scaffolding file several guards share** (`app.py`,
       `sql/schema.sql`), leave that file in `canary.py`'s `_BASE_FILES` and declare `expects`
       only — a shared file is owned by no single guard. Copy `guards/xxe_safe.py`.
     - Guards written before this existed still keep their plant in `agentsec/canary.py`, and both
       mechanisms work — `canary.py` assembles the base and the declarations into one canary. New
       guards declare their own, so adding a guard no longer means appending to a shared file that
       every other guard branch is also appending to. `agentsec doctor --canary` prints the split.
6. **`agentsec/checklist/checklist.json`** — map the guard to a checklist item via `check_ids`. A
   `covered` item must cite a real test in `verified_by` (`test_covered_requires_verifier` enforces
   this) — an item can't claim coverage without a test that proves it.

The `/guard-factory` skill runs this whole recipe end-to-end and is the recommended way to build a
guard, whether you're a maintainer or an outside contributor.

## The CI gate (what actually has to pass)

Every guard PR runs this battery. CI runs all of it on Linux, but only pytest and the canary on
Windows: ruff, mypy and pyright run on **Linux only**. The type-checkers model the host platform,
so CI does not catch a Windows-only type error (#1031). It shows up only in a local run on Windows,
or on any host with `mypy agentsec scripts --platform win32` /
`pyright agentsec scripts --pythonplatform Windows`.

1. `ruff check .` — lint, clean.
2. `mypy agentsec scripts` (strict) and `pyright agentsec scripts`: both type-checkers clean.
   Two, by design: a security project benefits from the cross-check (pyright has caught mismatches
   mypy tolerated).
3. The full pytest suite, which includes the drift battery:
   - **Guard Sandbox Contract** (`agentsec/guard_sandbox.py`) — an AST scan of every module in
     `agentsec/guards/` banning `os`, `subprocess`, `socket`, any network import, `eval`, `exec`,
     `__import__`, `pickle`, and `open` (any mode — read files via the `read` / `iter_files` helpers
     in `guards/base.py`, never `open()` directly). A guard that imports or calls any of these fails
     CI, full stop — this is what makes a contributed guard safe to import into every user's audit
     process.
   - **Canary manifest + liveness** — every guard in `ALL_GUARDS` must have a canary plant (declared
     via `canary_plant` or held in `canary.py`'s base), and `agentsec doctor --canary` must show it
     firing (not DEAD) and not producing an FP on its own FP-bait fixture. Two further gates apply
     if you move an existing plant onto its guard: `test_assembled_canary_matches_golden` fails
     unless the move is byte-identical (a `CHANGED` entry means fix the plant, **not** re-pin
     `tests/canary_golden.json`), and `test_no_plant_is_declared_twice` fails if the old base entry
     is left behind alongside the new declaration.
   - **Checklist mapping** — `check_ids` must resolve to real checklist items; every guard must map
     to at least one item; a `covered` item must cite a real verifying test.
   - **Design-doc existence** — see file 4 above.
4. `agentsec doctor --canary` — the final end-to-end proof, run again outside pytest.

A PR that is green on all of the above is **necessary** for merge. It is not **sufficient** — see
Governance below.

## The exploitability bar (F2)

A guard should exist because a pattern is a real, reachable vulnerability class, not because it's
easy to pattern-match. Apply the same F2 rubric threat-intake uses to propose checklist items:

> A pattern isn't a finding. Confidence ≥ 8/10 or discard. Auto-exclude noise (DoS, rate-limiting,
> open-redirect-as-the-only-issue, generic validation with no proven impact).

If you can't state who reaches the flagged code, with what privilege, to what effect — the guard
isn't ready yet.

## The design-doc rubric

Every `wiki/guards/<id>.md` must answer four questions. A design doc that can't answer these is
rote pattern-matching, not a security guard, and will be rejected on review even if CI is green:

1. **Exploitability rationale** — who reaches it, with what privilege, to what effect?
2. **When NOT to flag** — what legitimate pattern looks similar to the violation; what the
   guard's inline suppress pragma (`# security: allow-<token>`, a short token the guard defines —
   e.g. guard `code-injection-eval-exec` uses `allow-eval-exec`) is for.
3. **Known bypasses** — honestly listed (whitespace tricks, aliasing, indirect assignment, string
   concatenation instead of an f-string, …). A guard that claims zero bypasses is a guard nobody has
   adversarially tested yet.
4. **What this guard does NOT prove** — the coverage gap it leaves, stated plainly. Absence of a
   finding from this guard is not a security claim beyond what the guard actually checks.

## Governance

Green CI is necessary; a maintainer's hand-review is sufficient. That ordering never inverts — no
guard reaches `ALL_GUARDS` on a passing pipeline alone.

Merge rights on this repository are held by the two maintainers (see `.github/CODEOWNERS`) and are
**permanent** — contribution earns credit and review priority, never merge access, regardless of
contribution history or trust built up over time. This is a deliberate choice, not a slight: a
patiently-built reputation followed by a single malicious commit is exactly the failure mode a
two-person open-source security tool has to design against (the xz-utils backdoor is the reference
case). Every prior-art rule-contribution ecosystem examined for this RFC (Semgrep, Sigma, CodeQL,
Nuclei, Trivy checks) draws the same line: a contributed *rule* or *check* can be reviewed and
merged by an outside contributor's growing trust, but *merge rights themselves* stay with a small,
named, permanent set of maintainers.

Credit is public: `Co-Authored-By` on the merge commit, and a contributors mention in the project's
own history. Contributing here does not currently confer any additional access.

## The Contributor License Agreement

You sign the project's [Contributor License Agreement](CLA.md) once, on your first pull request, and
a maintainer checks that you have before landing it. A bot asks on that pull request; you reply with
the sign-off comment `CLA.md` shows, and that covers every later contribution too. If your employer
owns the work you contribute, your employer signs the [Corporate agreement](CCLA.md) instead.

What you are agreeing to, plainly (the agreements themselves are what apply):

- **You keep the copyright** in everything you write. Nothing is assigned to anyone.
- **You give the two maintainers a licence** to use, change and distribute your contribution, and to
  **sublicense** it. That last part is what lets the project change its licence in future without
  asking every past contributor again; it is the reason the agreement exists.
- **A patent licence** for any of your patents your contribution needs, which ends for anyone who
  sues the project over patents.
- **The work is yours to give:** you wrote it, or your employer has agreed or signed the corporate
  agreement.
- **No obligations either way:** you owe no support for what you contribute, and the maintainers are
  not obliged to merge it.

The agreement is adapted from the Apache Software Foundation's, so it is the same deal many large
open-source projects use.

## What this document does not cover

- **Runner contributions** (`agentsec/runners/`, wrapping an external scanner binary) — different
  shape (an `applies()`/`invoke()`/`parse()` triple, no canary plant). Ask before starting one.
- **Checklist-item-only proposals** with no accompanying guard — the maintainers' threat-intake
  process adds checklist items, not a guard PR. Open an issue describing the threat instead.
- **The community-guards pool** (RFC Phase 2) — not yet built. When it lands, this document will be
  updated to describe how a guard moves from the quarantined pool into `ALL_GUARDS`.
