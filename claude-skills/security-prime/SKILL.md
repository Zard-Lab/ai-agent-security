---
name: security-prime
description: Prime a repo for a security audit — review the detected stack, discover non-product directories (archives, examples, migrations, dev tooling), and interactively write the chosen exclusions to .agentsec/config.json so the audit runs high-signal. Run once per repo, before /security-audit.
---

# /security-prime

Scope the ground before you audit, so `/security-audit` reports real product findings instead of
wrong-surface noise from code nobody deploys (archives, examples, migrations, dev tooling).

## 1. Confirm the tool + review the detected stack

```bash
agentsec --version || pipx install ai-agent-security
agentsec detect .
```

Read the `StackProfile`. Sanity-check it against the repo:

- If it fingerprints `llm=-` but the repo clearly uses an LLM/agent SDK, or `db=` looks wrong for the
  code, note it. Detection gaps silently suppress or mis-fire whole guard families, so a wrong profile
  makes every later step less trustworthy.
- Note the `db target [...]` locality lines (parsed from env files, value never shown). Flag any DSN
  aimed at production before you run a live audit against it.

## 2. Discover non-product directories (the exclude advisor)

```bash
agentsec suggest-excludes . --format json
```

Each candidate carries:

- `directory` — repo-relative path.
- `kind` — `exclude` (dropped from scanning; lossy) or `demote` (still scanned, ranked low).
- `confidence` — `high` or `heuristic`.
- `signals` — the "why" (import-unreachable, test/notebook shape, already gitignored, name convention).

`--format json` is a **read-only listing**. Combining it with `--write`/`--yes`/`--accept` is refused
(exit **2**) rather than silently listing and writing nothing — do the write in step 5, without it.

The advisor only suggests a directory when at least two independent signals agree, so it is
conservative by design. If it suggests nothing, the repo is already tightly scoped. Skip to step 7.

## 3. Verify ambiguous candidates by reading the files (read-the-line discipline)

Do NOT accept on the directory name alone. For any candidate with `confidence: heuristic` (or anything
you are unsure about), open a couple of its files and confirm it is genuinely non-product: an archive
(`old/`, `legacy/`), an example/template, a migration tree, a generated dump, or an offline script. Make
sure it is not live product code that merely sits under a suggestively named folder.

A directory name plus its scan location is not enough to judge it. A prior triage that skipped this step
mislabelled roughly twenty findings until the files were actually opened.

## 4. Let the user choose (interactive)

Present the verified candidates and use `AskUserQuestion` (multiSelect) so the user picks which to accept.
For each, show its `kind`, the top signal, and any finding count. Make the drop-vs-demote distinction
explicit:

- `exclude` -> `archive_paths`: lossy. A real bug in that tree disappears from the report. Use only for
  vendored / generated / dead code where no real bug can hide.
- `demote` -> `nonproduct_paths`: keeps the code visible, just ranked low. The safe default.

When in doubt, prefer demote — but note the *kind* is the advisor's call, not yours: `--accept`
routes each accepted directory by the `kind` it was suggested with. To demote something the advisor
marked `exclude`, skip it here and add the name to `nonproduct_paths` in `.agentsec/config.json` by
hand.

## 5. Write the chosen subset

```bash
agentsec suggest-excludes . --write --accept old,evals,notebooks
```

Pass the accepted directories to `--accept`, comma-separated, spelled either as the full repo-relative
path the listing printed (`backend/evals`) or as the bare directory name (`evals`). This routes the
named subset through the merge-safe config writer: it unions into any existing
`.agentsec/config.json`, preserves unknown keys, and classifies each name into `archive_paths` vs
`nonproduct_paths` by its `kind`. A malformed existing config is **refused**, not overwritten.

Three outcomes, and the exit code distinguishes all three:

- **exit 0, "Wrote …"** — the named subset was persisted.
- **exit 0, "Already non-product, nothing to do: `<name>` (`<tier>`)"** — that name's directories are
  already covered, so nothing was written and nothing needed to be. The tier in parentheses is what
  actually holds it: `archive_paths` / `nonproduct_paths` from `.agentsec/config.json`, or `built-in`
  for agentsec's hardwired conventions (`tests/`, `fixtures/`, `migrations/`, …). If it says
  `nonproduct_paths` for a directory the advisor called `kind: exclude` (or the reverse), the *kind*
  differs from what you asked for — change it by hand in `.agentsec/config.json`, because `--accept`
  cannot move a name between tiers.
- **exit non-zero** — a failed priming run, not a no-op. A name that matched no candidate *and* names
  no covered directory in the repo is reported and skipped (so is an empty `--accept ""`, e.g. an unset
  shell variable). A failed request never CLOBBERS an existing config, but a MIXED request is applied
  in part: every name that did match is still written, and only the unmatched ones are reported. So a
  non-zero exit does not mean nothing changed - read the `Wrote ...` line before assuming a no-op.
  (`test_accept_mixed_known_and_unknown_persists_the_known_subset` pins this behaviour deliberately;
  the earlier wording here asserted the opposite. #478 review.)

Then read stderr. The config matches by directory **NAME**, not by path, so accepting one
`backend/evals` also covers a `frontend/evals` — and accepting a vendored `libs/vendor` into
`archive_paths` also **drops every finding** in a live `app/vendor/` package. The command scans the
whole repo tree and names every directory that inherits an accepted segment, with a `⚠️ … LOSSY …
DROPPED in:` line for the `archive_paths` tier. Do not move on past that line without confirming those
directories are non-product; it is the only notice you get that guard coverage was disabled.

Re-run `agentsec suggest-excludes .` to confirm the accepted directories no longer appear as
suggestions.

## 6. Baseline note (optional hand-off)

If the repo already carries accepted-risk HIGH/CRITICAL findings you do not intend to fix now, that is a
baseline decision, not an exclusion. Snapshot them with `agentsec audit . --write-baseline agentsec-exceptions.json` (the flag takes a
FILE; bare `--write-baseline` exits 2) (or triage
and waive them in `/security-audit`'s closing step). Keep the exclusion config about *surface* (where the
product is), never about *hiding* a real finding.

## 7. Hand off

The repo is now scoped. Run **`/security-audit`** for the full dated sweep (it reads the same
`.agentsec/config.json`), or **`/security-review`** for a fast pre-merge gate.
