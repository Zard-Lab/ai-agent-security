---
type: Guard
title: "dependency-typosquat-popular"
description: "A declared dependency name is one typing slip away from a popular PyPI or npm package."
timestamp: "2026-11-21T00:00:00Z"
guard_id: "dependency-typosquat-popular"
checklist_section: ["5"]
standards: ["CWE-829", "OWASP-ASI:ASI04"]
---

# A declared dependency name is one typing slip away from a popular PyPI or npm package

_Author — 2026-11-21_

---

## The threat

A typo'd dependency name resolves to whatever an attacker registered under it, and installing it
runs their code (`reqeusts`, `expres`, `dateutil-python`). Mined from typomania's squat checks
(omitted character, repeated character, swapped adjacent characters, swapped words). The guard
reads `requirements*.txt`, `pyproject.toml` (`[project]` dependencies, optional dependencies,
dependency groups, Poetry dependencies) and `package.json` (`dependencies`, `devDependencies`,
`optionalDependencies`).

## Why it's often introduced

Hand-typed requirement lines, AI-suggested package names that are slightly wrong, and copy-paste
from untrusted snippets. Nothing in `pip install` or `npm install` warns when a name is close to a
famous one.

## Detection design

1. `applies()` returns `True`. Names are PEP 503-normalised for PyPI and lower-cased for npm.
2. A declared name is flagged (MEDIUM) only when ALL hold: length >= 6; not in the embedded corpus
   (a few hundred popular names per ecosystem, checked across both) or the real-name allowlist; it
   is exactly one squat shape away from exactly ONE corpus name of the same ecosystem.
3. The squat shapes: one letter omitted (never the first letter, never a digit), one letter
   doubled, two adjacent letters swapped, two hyphen-separated words swapped (each >= 3 chars).
   Substitutions and arbitrary insertions are deliberately out of scope: too many real package pairs.
4. Direct URL, VCS, path and option lines in requirements files are skipped.
5. Suppress with `# security: allow-dependency-typosquat-popular` as a comment on that dependency's own
   line (requirements/TOML). In `package.json` (no comments) write the literal followed by the audited
   names in any string value, e.g. `"//": "security: allow-dependency-typosquat-popular expres"`. The
   pragma covers only the names on its line; a bare literal in `package.json` suppresses nothing.

## When NOT to flag

- A name in the corpus or the allowlist, including the real near-neighbours `authlib` (`oauthlib`
  minus its first letter), `psycopg-binary` (`psycopg2-binary` minus a version digit), and the real
  packages `mongod`, `prop-type` and `deprecate`. The guard has no download signal, so another real
  package one edit from a corpus name can still be flagged until it is added to the allowlist.
- Names under six characters; internal names far from any popular name.
- Names that are one edit from two different popular names (ambiguous).

Measured while building: 0 hits across 504 distinct declared names in 119 real manifests, and 0
hits across 254 installed PyPI distributions and 780 installed npm packages. The first version hit
`authlib` and `psycopg-binary` (both real), which is what produced the first-letter and digit
exclusions.

## Tests

| Test | What it checks |
|---|---|
| `test_requirements_typo_fires` | Swap, omission, repeat, swapped words, extras/specifier handling |
| `test_package_json_typo_fires` / `test_pyproject_typo_fires_in_dependencies_groups_and_poetry` | npm and pyproject sources |
| `test_real_or_unrelated_names_are_safe` | FP-bait: real names, URL/VCS/option lines, comments, real near-neighbours |
| `test_substitution_is_out_of_scope` | Substitutions stay silent |
| `test_real_near_neighbours_are_not_flagged` | `mongod`, `prop-type`, `deprecate` stay silent |
| `test_*_pragma_*` | The pragma covers only its own entry (requirements, TOML, `package.json` name list) |

## Known bypasses

- A typo that is a substitution or an arbitrary insertion is not caught.
- Only names near a corpus name are recognised; the corpus is curated, not a registry mirror.
- A squat of a name below six characters is invisible.
- Ecosystem-crossing (a PyPI name squatting an npm package) is out of scope.

## What this guard does NOT prove

Silence does not prove a dependency is legitimate, only that it is not a near-miss of a name in the
corpus. A flagged name may be a real package; the finding is a prompt to re-read the name.

# Citations

[1] agentsec checklist item `5-dependency-typosquat-popular` (§5)
[2] typomania (Rust Foundation) squat checks: omitted, repeated, swapped characters, swapped words
[3] PEP 503 name normalisation; CWE-829, OWASP-ASI:ASI04
