---
name: guard-tune
description: Tune an existing agentsec guard to fix a false positive or false negative surfaced by a triage guard-improvement verdict — edit the guard's detection logic, add a regression test that pins the fix, keep the design doc and canary honest, run the full gate, and stop for maintainer review. Use when a triage run flags a guard as firing too broadly (or missing a real case), or when the user wants to "fix a guard FP", "tune a guard", "reduce false positives", "fix a false negative", act on a "guard-improvement verdict", or invokes /guard-tune. The EDIT counterpart to /guard-factory (which CREATES new guards).
argument-hint: "<guard-id> [--triage-file <path>]  (blank = read the report's Guard Improvement Catalog)"
---

# /guard-tune

The EDIT counterpart to `/guard-factory`. Where guard-factory *creates* a new guard from an approved
checklist gap, guard-tune *edits* an already-registered guard to fix a false positive (fires on a
legitimate pattern) or false negative (misses a real case) surfaced by the self-improvement loop. It is
the **back half** of scan → triage → tune: it consumes `agentsec` triage `guard-improvement` verdicts
and produces the same gate-passing, un-committed diff a hand-done tune does, as a repeatable recipe.

**Inputs:** one guard `id` plus its `guard-improvement` evidence (a triage verdict's `reason` +
`improvement`, or the report's Guard Improvement Catalog). The maintainer reviews the *judgment* of
whether the guard should change — do not invent the fix intent. **Output:** an unstaged, validated
diff for the maintainer to review and open as a PR. **Never auto-commit.**

**What guard-tune does NOT do** (these are guard-factory's, not a tune's): it does **not** add a
`registry.py` entry (the guard is already registered) and does **not** flip a `checklist.json` item or
bump the version (the item is already `covered`). A tune touches the guard's **triad** — module + test +
design doc — plus the **canary** when detection logic changes. That is the whole move.

## Steps

1. **Verify the tool & gather the input.** `agentsec --version`. Identify the target guard and its
   guard-improvement evidence. Easiest path: `agentsec report <repo>` and read the **Guard Improvement
   Catalog** (`Guard | FP Pattern (reason) | Recommended Fix (improvement)`). Or load
   `agentsec-triage.json` and filter `verdict == "guard-improvement"` for the guard, reading each
   entry's `reason` (the FP/FN pattern) and `improvement` (the proposed fix). The triage file defaults
   to `<repo>/agentsec-triage.json`; if `--triage-file <path>` was given, read verdicts from `<path>`
   instead (the same override `agentsec triage --triage-file` uses). Note: the triage file
   stores `guard_id`, `file`, `rule`, `reason`, `improvement`, `fingerprint` — **not** severity or line
   number. To recover the live location/severity, re-run `audit(repo, run_scanners=False)` (the
   guard-only set; `agentsec triage` itself runs the installed scanners too by default and takes
   `--guards-only` for this set) + `apply_triage` and join on the stable fingerprint. Skip any verdict
   whose `guard_id` is a scanner (`bandit`, `semgrep`, `pip-audit`, ...): those are feedback for the
   scanner's own config, and there is no `wiki/guards/<scanner>.md` triad to tune.
   State the guard `id`, the exact pattern the verdict is about, and classify it: **false positive**
   (guard fires on a legitimate pattern) or **false negative** (guard misses a real case).

2. **Fix or waive?** A `guard-improvement` verdict has two legitimate outcomes. If the finding is a
   genuine one-off — target-specific, not worth a code change — prefer the **waive** arm and stop:
   ```bash
   agentsec triage <repo> --guard <guard-id> --verdict guard-improvement \
     --reason "why" --improvement "why a code change isn't warranted" --write-exception
   ```
   That records an *expiring* waiver in `agentsec-exceptions.json` (re-surfaces when `review_by` lapses).
   Otherwise — the pattern is general and will recur across repos — continue and fix the guard.

3. **Branch.** `git checkout -b fix/<guard-id>-guard-tune` (Loop-B `fix/…` naming). Keep `<guard-id>`
   equal to the guard's `id` attribute.

4. **Locate the triad and READ all three before editing.** The usual shape — the guard `id` is
   **hyphenated**, the module and test filenames use **underscores**, the design-doc filename uses
   **hyphens**:
   - guard module: `agentsec/guards/<guard_id>.py` (underscores)
   - test file: `tests/guards/test_<guard_id>.py` (underscores)
   - design doc: `wiki/guards/<guard-id>.md` (hyphens)

   **This is a convention, not a rule — RESOLVE it, don't assume it.** A handful of guards predate
   the convention and live in a differently-named module (`stripe-payments` ->
   `stripe_webhook.py`, `lethal-trifecta` -> `lethal_trifecta_guard.py`, `error-info-leak` ->
   `error_response_info_leak.py`, and more). guard-factory never hits this because it CREATES the
   file; a tune EDITS one that already exists. Ask the registry:

   ```bash
   uv run --extra dev python -c "
   from agentsec.registry import ALL_GUARDS
   g = next(g for g in ALL_GUARDS if g.id == '<guard-id>')
   print(type(g).__module__.replace('.', '/') + '.py')"
   ```

   Then find its test file by the guard CLASS it imports, not by name:
   `grep -rl '<GuardClassName>' tests/guards/`. If either path does not exist under the
   conventional name, use what these two commands report — do not create a second module.

   Read the guard's `run()`, its `applies()` gate, its `Finding(...)` calls (for the `rule`/`severity`
   to preserve), its pragma (if any), and the FP-bait tests already present. Understand *why* it
   currently fires before changing where it fires.

5. **Make the minimal edit.** Change as little as possible — do not rewrite the guard.
   - **False positive:** reach for the shared levers first, in `agentsec/guards/base.py`:
     `is_nonproduct_path` (skip test/example/fixture/migration paths — the #1 FP lever), the `strip_*`
     comment/string helpers (`strip_sql_comments`, `strip_js_comments`, `strip_hash_comments`,
     `strip_python_strings`) so the guard ignores commented-out or docstring examples, or add/scope an
     inline opt-out **pragma** (`# security: allow-<guard-token>`), checked through `pragma_present` /
     `pragma_line_set` (`base.py`), never a raw `in text`: a pragma counts only as a comment, never
     inside a string or docstring (#424). Pick the pragma scope that fits:
     **per-line** (`pg_ssl_required`), **call-span** (`weak_crypto`), or **whole-file**
     (`target_blank_noopener`) are the three worked examples.
   - **False negative:** broaden the pattern/regex, or the shared auth signals (`AUTH_DEP_SIGNAL`,
     `boundaried_stems` in `base.py`) for the authz-family guards. If the miss is a cross-file/app-wiring
     case (e.g. `main.py` including `routes/*.py`), the fix likely needs multi-file reasoning — plan a
     multi-file fixture in step 6.
   - **Invariants to keep:** `run()` stays **total** (never raises on unexpected input); `severity=` is a
     **literal** (`"medium"`, `"high"`, …), never a `str` variable (pyright gates the `Severity`
     Literal) — and it need NOT match the checklist item's severity: guard severity ranks *this
     finding's* urgency, item severity ranks *the control*, and they are independent axes on purpose,
     so a tune must not "align" them (a low-severity control can still fail urgently); imports stay
     sandbox-safe (stdlib + `agentsec.*` only — never
     `os`/`subprocess`/network/`eval`/`exec`/`open`); every text read passes `encoding="utf-8"`.

6. **Add a regression test that pins the fix** — extend `tests/guards/test_<guard_id>.py`; **never delete
   the existing positive test** (the guard must still fire on real violations):
   - for an **FP** fix: add the exact look-alike-but-legitimate pattern the tune now silences → assert
     `run(...) == []` (the false-positive bait);
   - for an **FN** fix: add the previously-missed violation → assert it now fires with the right `rule`
     and `severity`.
   Give the new test a descriptive name. If the fix reasons about app wiring split across files, add ≥1
   **multi-file fixture** (a single-file test can't see the bug). If the tune introduced or rescoped a
   **pragma**, add a test for the pragma itself — one asserting it suppresses, one asserting a
   violation just OUTSIDE its scope still fires, and one asserting the phrase inside a string literal
   does NOT suppress (#424). An untested pragma is an untested suppression path.

   Then prove the test is not vacuous: revert your guard edit, re-run just this test file, and confirm
   the new test FAILS. A regression test that passes against the unfixed guard pins nothing.

7. **Keep the design doc honest.** Update `wiki/guards/<guard-id>.md`: add the
   newly-excluded pattern to **When NOT to flag** (FP) or tighten **Known bypasses** (FN), and add the
   new test to the **Tests** table. A guard that over-claims is worse than one that says plainly what it
   does not cover — mirror that discipline.

8. **Canary coupling — only when detection logic changed.**

   **Every guard declares its own `canary_plant`** (#617 batch 16 drained the base), so the
   expectation is always edited on the guard class, never in `agentsec/canary.py`. A guard that
   declares `expects` with **no** `files` has its violation in a shared scaffolding file that stays
   in `canary.py`'s `_BASE_FILES` — in that one case edit the file in `canary.py` and the
   expectation on the guard. (`grep -n canary_plant agentsec/guards/<id>.py` shows the shape;
   `agentsec doctor --canary` prints the split, now 263 declared / 0 base.)

   Read `_FILES`/`EXPECTED_RULES` below as "wherever this guard's plant lives":
   - The existing plant **must still fire** — if a narrowing edit silences it, re-fire the
     plant (fix the plant, never relax the expectation).
   - If the tune adds a new FP-suppression, plant the FP-bait and add its distinctive marker to
     `EXPECTED_ABSENT` in `canary.py` (the must-stay-silent manifest is not per-guard).
   - If the tune changes or adds a `rule=` value, update the guard's `expects` **in lockstep** —
     otherwise `doctor --canary` reports it DEAD.
   - If the tune introduces a new suppressor token (a pragma or a "mitigation present" marker), register
     it in `_GLOBAL_SUPPRESSORS` in `canary.py` so the cross-plant collision tests can catch it.
   - **Tuning is not migrating.** There is nothing left to migrate (#617 is complete), but the rule
     generalizes to moving a plant between homes at all — e.g. pulling a shared `_BASE_FILES` file
     onto a guard as `files`. That changes the self-audit baseline (Loop C) and belongs in its own
     change, not a drive-by in a tune PR. If you do move one, `tests/canary_golden.json` must show a
     **zero** diff.

   **The guard-rail these two bullets collide on:** a token registered in `_GLOBAL_SUPPRESSORS`
   must NEVER appear anywhere in `_FILES` — it would silence that guard repo-wide and report it
   DEAD. So if step 5 fixed an FP by adding an inline pragma, do NOT also plant a bait containing
   that pragma. Plant a bait that is legitimately *shaped* like the FP instead, with no suppressor
   token in it. `test_no_suppressor_marker_in_plants` fails on the collision, naming marker + file
   + silenced guard; run `uv run --extra dev python -m pytest tests/test_canary.py -q` right after
   touching the canary, before the full gate.

   **`EXPECTED_ABSENT` matches FINDING TEXT, not plant source.** It is compared against the text of
   the findings the canary run produced, so a marker copied out of the bait's source never appears
   there and the protection is vacuously green forever. Use something a WRONG finding would carry
   — the bait's file path is the reliable choice (see the existing `/src/main.tsx` entry), since
   every finding carries its location. Prove it: temporarily revert your suppression, re-run
   `agentsec doctor --canary`, and confirm the entry actually trips.

   Do NOT add a registry entry or flip a checklist item.

9. **Run the full gate — all must pass:**
   ```bash
   uv run --extra dev python -m pytest tests/guards/test_<guard_id>.py -q   # scope first (fast)
   uv run --extra dev python -m pytest -q                                    # then the full suite (2700+)
   uv run --extra dev ruff check .
   uv run --extra dev mypy agentsec
   uv run --extra dev pyright agentsec
   agentsec doctor --canary      # the guard STILL fires; no FP-bait tripped; peers alive
   agentsec doctor --sandbox     # the edited guard stays import/call-sandboxed
   ```
   `doctor --canary` is the honesty check a narrowing tune most often breaks — fix red before proceeding.
   A guard that can't pass `--sandbox` after the edit (reaches for `os`/`subprocess`/network/`eval`/
   `open`) must be reworked, not exempted.

10. **Stop — do not auto-commit.** Summarize: the guard, the FP/FN it fixed, the regression test that
    pins it, any canary change, and the green gate. Surface the diff and let the **maintainer** review
    the judgment and open the PR (a Loop-B `fix/…` branch). The
    end user only reviews *actions*; the maintainer reviews *judgment*.

## Resources
- `../guard-factory/SKILL.md` — the CREATE sibling; mirror its cadence, invert its semantics (this skill
  edits an existing guard rather than adding one).
- `wiki/guards/TEMPLATE.md` — the design-doc rubric whose "When NOT to flag" / "Known
  bypasses" / Tests sections a tune keeps current. It is an OKF concept doc: refresh its
  `timestamp` frontmatter field on a substantive revision (`type: Guard` is OKF's one revisable
  type, so rewriting prose and headings is allowed here).
