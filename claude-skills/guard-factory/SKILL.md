---
name: guard-factory
description: Turn one approved agentsec checklist item into a complete, convention-compliant guard contribution — guard module + adversarial tests + design doc + registry entry + canary + checklist flip — gated by the full validation suite (incl. the Guard Sandbox Contract). Use when closing a checklist gap with a new static guard.
---

# /guard-factory

An assembly line for the enforced branch-per-guard convention. It produces the
same artifact a hand-built guard does (see `security-headers` PR #20 and
`system-prompt-leak` PR #25 as the worked references), but as a repeatable recipe
so every guard ships under all the enforcement layers and passes the same gate.

**Inputs:** one **approved** `checklist.json` item id (the maintainer reviews the
*judgment* of whether the item should be guarded — the two-persona rule; you do
not invent items). **Output:** an unstaged, validated diff for the maintainer to
review and open as a PR. **Never auto-commit.**

## Steps

1. **Verify the tool & pick the item.** `agentsec --version`. Read
   `agentsec/checklist/checklist.json` and locate the target item. Confirm it is
   currently `status: "partial"` or `"manual"` and that the maintainer approved
   guarding it. State its `id`, `section`, `title`, `severity`, `standards`, and
   `applies_when` — these drive the guard's gate and `Finding` fields.

2. **Branch.** `git checkout -b feat/<guard-id>-guard` (branch-per-guard). Pick a
   kebab-case `<guard-id>` that will equal the guard's `id` attribute, the design
   doc stem, the test filename, and the module stem (`agentsec/guards/<guard_id>.py`,
   underscores). All four are gated: `test_guard_module_stem_matches_its_id`,
   `test_every_guard_has_a_test_file`, `test_every_guard_has_a_design_doc`.

3. **Generate the guard** under `agentsec/guards/<guard_id>.py`. Template from the
   closest worked example: `system_prompt_leak.py` (LLM / absence-detection) or
   `security_headers.py` (FastAPI / absence-detection). Requirements:
   - `applies(profile)` gated on the item's `applies_when` features.
   - Use the shared helpers in `guards/base.py` (`iter_files`, `read`, `rel`,
     `python_scan_dirs`, `strip_sql_comments`) — never roll your own file I/O.
     The **full grouped index of every public helper is the module docstring at
     the top of `guards/base.py`**: read it before writing a comment stripper, a
     path classifier or a cross-file router-auth walk, because they exist there.
   - `severity=` is a **literal** (`"medium"`, `"high"`, …) — never a `str`
     variable (pyright gates on the `Severity` Literal). It need NOT match the
     checklist item's severity: guard severity ranks *this finding's* urgency,
     item severity ranks *the control*, and they are independent axes on
     purpose: a low-severity control can still fail in a way that is urgent
     to fix. Do not "align" them.
   - `run()` is **total** — it must never raise on unexpected input.
   - An inline opt-out **pragma** (`# security: allow-<something>`) for FP-prone
     guards, honored repo-globally where that matches the design. Check it through
     `pragma_present(...)` / `pragma_line_set(...)` (`guards/base.py`), never a raw
     `_PRAGMA in text` / `.search(text)`: a pragma counts only as a COMMENT, never
     inside a string or docstring (#424), and `tests/test_pragma_anchoring.py` fails a
     raw match. A whole-file (or repo) reach is declared there in `_FILE_SCOPED_PRAGMA`.
   - Map findings to standards via `Finding.standards` (e.g. `["OWASP-LLM:LLM01"]`).
   - **Sandbox Contract:** import only stdlib-safe modules + `agentsec.*`; never
     `os`/`subprocess`/network, never `eval`/`exec`/`open`. The contract test
     (step 9) enforces this structurally.

4. **Adversarial tests (F3 — self-verification).** Add `tests/guards/test_<guard-id>.py`
   (copy a sibling like `tests/guards/test_system_prompt_leak.py`). Import your guard class
   directly (`from agentsec.guards.<guard-id> import <Guard>`); `tests/guards/_common.py`
   (star-imported) is for shared fixtures only, never guard-class imports *for re-export* (a few
   fixture helpers instantiate a guard internally — a narrow exception, kept out of `__all__`).
   **≥5 tests**, and crucially include
   **look-alike-but-legitimate FP-bait that MUST stay silent**:
   - the positive planted violation → fires (exact `rule` + `severity`); this is
     the `verified_by` test — note its exact name,
   - the legitimate-but-similar pattern → `== []` (the false-positive bait),
   - the pragma opt-out written as a comment → `== []`, and the same phrase inside a
     string literal → still fires (the comment-only contract, #424),
   - the not-applicable gate (wrong/missing feature) → `applies(...) is False`,
   - any silent edge case the design names (e.g. evidence present → `== []`).
   Honestly document any known bypass you find — it belongs in the design doc.

   **If the guard reasons about app wiring split across files** (router auth via `include_router`,
   middleware / CORS / TrustedHost / rate-limit registration in `main.py` that governs routes in
   `routes/*.py`), add **≥1 multi-file fixture** — a `main.py` that composes a separate route module.
   Single-file tests cannot catch the cross-file blind spot: `auth-dependency-not-applied` had 30+
   single-file tests yet shipped a Critical false-negative that only surfaced on a real multi-file
   repo (fixed on #473, which absorbed and closed #464). The shared cross-file resolver lands in
   `guards/base.py` with #473; use those helpers rather than re-deriving the wiring.

   **If you are CHANGING an existing guard rather than adding one, the both-directions rule binds you**
   (CLAUDE.md "Changing a check"): a **narrowing**
   (an FP fix, a new skip or suppression) needs a test proving the vulnerable case **still fires**, and a
   **widening** needs FP-bait proving the benign neighbour **still stays silent**. A change tested only in
   the direction it was about is how a round of FP fixes silently killed real detections.

   **Two traps worth naming, both of which have shipped here:**
   - **Check your test actually discriminates.** Write the test, then confirm it FAILS against the
     unfixed code (or re-run the old logic against the same fixture). A fixture that passes either way
     proves nothing, and this batch shipped several.
   - **Watch for a fixture that trips the guard's own vocabulary.** A "no user input here" fixture using
     the literal `'static prompt'` fired, because `prompt` is itself one of the tokens that guard matches.

5. **Design doc** from `wiki/guards/TEMPLATE.md` → `wiki/guards/<guard-id>.md`. It is an
   **OKF concept doc**, so it opens with frontmatter, not a heading:

   ```yaml
   ---
   type: Guard
   title: "<guard-id>"
   description: "<the guard's title, one sentence, ending with a period.>"
   timestamp: "2026-08-14T09:00:00Z"
   guard_id: "<guard-id>"
   checklist_section: ["<section>"]
   standards: ["OWASP:A0N"]
   ---
   ```

   The checklist section lives in `checklist_section` (always a **list**), **not** in the
   heading — the drift test asserts every id in it is one `checklist.json` maps this guard
   to via `check_ids`, so a `§` in the H1 is now wrong and a bogus section fails CI. The H1
   is the guard's title as prose. Body order is prose → your `##` sections → `# Citations`
   last. Answer all four rubric questions: the threat / when NOT to flag / known bypasses /
   **what this guard does NOT prove**. If it overlaps an existing check, add a "Scope"
   section partitioning the space (see `wiki/guards/jwt-alg.md` and
   `wiki/guards/system-prompt-leak.md`).

   Then regenerate the index: `python scripts/gen_wiki_guards_index.py --write`
   (`tests/test_wiki_guards_okf.py` fails if it is stale).

6. **Register.** Import the guard in `agentsec/registry.py` and append an instance
   to `ALL_GUARDS` (near a peer with the same `applies_when`). Confirm ids stay
   unique.

7. **Declare what the guard knows about itself** — the reporting metadata and the
   canary plant, all **on the guard class**, directly under `id`/`title`. None of it
   goes in `agentsec/canary.py`, `agentsec/findings.py` or `agentsec/registry.py`;
   that is the whole point of declaring it here.

   ```python
   from .base import CanaryPlant, Guard

   class MyGuard(Guard):
       id = "my-guard"
       title = "..."
       # Which section of `agentsec audit --format summary` this guard's findings
       # appear under. REQUIRED, and must be one of `agentsec/checkmeta.py::AREA_ORDER`
       # — `test_every_registered_check_declares_an_area` and
       # `test_declared_areas_are_in_the_vocabulary` both gate it.
       area = "AI agent"
       # Optional. `tier = "baseline"` ONLY for universal hygiene that should run before
       # and regardless of stack detection; the default `"stack"` is almost always right.
       # Optional. `surfacing = True` ONLY when the guard flags an architecture for a
       # human to confirm rather than proving a bug — it ranks the finding BELOW a proven
       # one of the same severity, so never set it on a guard that asserts a real defect.
       # When only SOME of this check's rules are review signals, declare the prefixes
       # instead: `surfacing_rule_prefixes = ("my-guard/unproven-",)`. These are matched
       # with `str.startswith` against a finding's `rule`, so each one selects a FAMILY of
       # rules rather than naming a single rule id. The real example is `runners/trivy.py`:
       # `("trivy-image/",)` surfaces every `trivy-image/<CVE>` base-image finding while
       # that same runner's bare fs-scan CVE ids stay proven. Either form, pin it in the
       # guard's test file with a real run asserting `_is_review_finding(f) is True` (and
       # `False` for a proven sibling rule): the checkmeta gate checks only the
       # declaration's text, not what it does (#766).

       # FIRE-strings: <what makes it fire>. Must NOT contain: <this guard's own
       # suppressor markers, if any>.
       canary_plant = CanaryPlant(
           files={"path/in/canary/repo.py": "…verbatim content…"},
           expects=frozenset({"my-guard/some-rule"}),
       )
   ```

   `canary.py` assembles its shrinking base plus every guard's declaration, so a new
   guard no longer appends to the one file every other guard branch is appending to.

   The canary is guard-granular: an `expects` rule counts as alive if it fires from ANY
   file, so it proves neither every rule nor every file surface. If a rule scans several
   file names or globs, step 4's tests must plant each one at a literal path (never a
   list imported from the guard), so dropping a surface fails a test (#632).

   - **Shared scaffolding file?** If your violation belongs in a file several guards
     share (`app.py`, `sql/schema.sql`, `k8s-deployment.yaml`), that file stays in
     `canary.py`'s `_BASE_FILES` and you declare `expects` **only**, with no `files`.
     Copy `agentsec/guards/xxe_safe.py`. Do not tear a shared file apart.
   - The planted strings are load-bearing, but you do NOT need to memorize the
     cross-plant coupling: declare it, then run `tests/test_canary.py` —
     `test_no_suppressor_marker_in_plants` names any collision with another guard's
     `_GLOBAL_SUPPRESSORS` marker (marker + file + silenced guard), and
     `diagnose_suppression()` names the offending file if a guard dies. Keep your
     plant clear of the `EXPECTED_ABSENT` FP-bait. Verify peer guards still fire.
   - A new guard legitimately ADDS to the golden manifest, so re-pin it:
     `python scripts/repin-canary-golden.py`. (Only ever re-pin for additions. A
     `CHANGED` entry means a plant lost content — fix the plant.)

8. **Checklist** (`agentsec/checklist/checklist.json`). On the item: set
   `"status": "covered"`, add `<guard-id>` to `check_ids` (keep any existing ones),
   set `"verified_by"` to the exact positive test from step 4
   (`tests/guards/test_<guard-id>.py::test_...`). Bump the top-level `version` (patch). Then
   regenerate the tracker: `agentsec coverage . --write-tracker`.

9. **Run the full gate — all must pass:**
   ```bash
   uv run --extra dev python -m pytest -q
   uv run --extra dev ruff check .
   uv run --extra dev mypy agentsec
   uv run --extra dev pyright agentsec
   agentsec doctor --canary      # the new guard fires end-to-end; peers still alive
   agentsec doctor --sandbox     # the new guard is import/call-sandboxed
   agentsec coverage .           # the item now shows covered
   ```
   Fix anything red before proceeding. A guard that can't pass `--sandbox` (reaches
   for `os`/`subprocess`/network/`eval`/`open`) must be reworked, not exempted.

10. **Stop — do not auto-commit.** Summarize the new guard, the FP-bait you proved
    silent, and the gate results. Surface the diff and let the **maintainer** review
    the judgment and open the PR (the `.github/pull_request_template.md` new-guard
    checklist). The end user only ever reviews *actions*; the maintainer reviews
    *judgment*.
