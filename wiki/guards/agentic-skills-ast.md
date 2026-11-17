---
type: Guard
title: "agentic-skills-ast"
description: "A skill's static shape carries an unpinned external resource, a deserialization tag, or a cross-platform manifest disagreement."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "agentic-skills-ast"
checklist_section: ["4"]
standards: ["CWE-829", "CWE-502", "CWE-706", "OWASP-ASI:ASI04", "OWASP-LLM:LLM06"]
---

# Skill's static shape carries an unpinned resource, a deserialization tag, or a manifest mismatch

_Author — 2026-09-26_

---

## The threat

Three independent composition-layer risks in how a Claude Code / Claude Agent SDK skill is
packaged and described, each distinct from the content-poisoning risks [[skill-poisoning]] already
covers: (1) an install step that fetches an unpinned external resource, so the skill's effective
behavior can change on every run without the skill file itself changing; (2) a YAML/JSON
deserialization tag or unsafe loader call sitting in frontmatter, an object-construction primitive
with no legitimate role in declarative metadata (CWE-502); (3) a skill described two different ways
across `SKILL.md` and a sibling manifest, so a human review of one does not guarantee it matches
what an install or tool-selection path actually reads (CWE-706, Improper Handling of Inconsistency).
Sourced from `agent-audit-kit`'s `agentic_skills.py` (AAK-AST02-001/AAK-AST04-001/AAK-AST10-001),
verified against the real repo source.

## Why it's often introduced

Skill authors copy install-script idioms from general shell-script culture (`curl | sh`, `npx
tool`) where pinning is often skipped for convenience; a deserialization tag can slip into
frontmatter from a copy-pasted YAML snippet nobody scrutinized as executable; and a manifest field
drifts from `SKILL.md` simply because the two files are edited at different times by different
people, with nothing enforcing agreement between them.

## Detection design

1. `applies()` returns `True` unconditionally.
2. Scans every `SKILL.md` (`iter_files_named`, `respect_gitignore=False`).
3. **unpinned-external-resource** (MEDIUM): a `curl`/`wget` fetch of a URL with no pin marker
   (no `@<sha>`/`@vN`/`#<sha>` suffix and no bare hex commit-sha path segment, e.g.
   `raw.githubusercontent.com/org/repo/<sha>/...`), or an `npx <pkg>`/`pip install <pkg>` with no
   version pin (`@<version>` / `==<version>`). Loopback fetches (`localhost`, `127.*`, `::1`,
   `0.0.0.0`) are skipped (a local health check has no upstream to pin), and option tokens
   (`-r`, `--index-strategy`, `--yes`) are not package names. A leading UTF-8 BOM on `SKILL.md`
   or the manifest is ignored.
4. **deserialization-tag-in-frontmatter** (HIGH): the frontmatter block contains
   `!!python/object`/`!!python/module`/`!!python/name`, a bare `pickle.loads(`/`pickle.load(`, or
   `yaml.load(` without an explicit `Loader=SafeLoader`/`yaml.SafeLoader` argument.
5. **cross-platform-manifest-disagreement** (MEDIUM): a sibling `skill.json`/`manifest.json` in the
   same directory declares a `name` or `version` that disagrees with the value in `SKILL.md`'s own
   frontmatter.
6. Inline opt-out: `# security: allow-agentic-skills-ast` (checked per-file; suppressing on
   `SKILL.md` also skips its manifest cross-check for that skill, and a manifest can independently
   carry its own pragma).

## When NOT to flag

- Every external fetch/install command is pinned to a specific version or commit.
- No deserialization tag or unsafe loader call anywhere in frontmatter.
- No sibling manifest file exists, or the manifest's `name`/`version` agree with `SKILL.md`'s.

## Tests

| Test | What it checks |
|---|---|
| `test_unpinned_curl_fetch_fires` / `test_pinned_curl_fetch_is_safe` | Unpinned vs. commit-sha-pinned URL fetch |
| `test_unpinned_npx_package_fires` / `test_pinned_npx_package_is_safe` | Unpinned vs. version-pinned `npx` package |
| `test_deserialization_tag_fires` / `test_ordinary_frontmatter_is_safe` | Deserialization tag presence/absence |
| `test_manifest_name_mismatch_fires` / `test_matching_manifest_is_safe` / `test_no_manifest_is_safe` | Manifest agreement, disagreement, and absence |
| `test_pragma_suppresses_all_findings` | Inline pragma silences every rule |
| `test_localhost_health_check_is_not_unpinned` / `test_remote_curl_still_fires_next_to_localhost` | Loopback skipped; a remote fetch beside it still fires |
| `test_pip_flags_are_not_package_names` / `test_unpinned_pip_package_still_fires` | Option tokens skipped; a bare package still fires |
| `test_npx_flags_are_skipped_but_the_package_is_still_judged` | `npx --yes pkg` judges `pkg`, not `--yes` |
| `test_utf8_bom_manifest_and_skill_still_checked` | A BOM does not hide the frontmatter or the manifest |
| `test_guard_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- Pin detection is regex-based on the literal URL/package string; a pin expressed indirectly (a
  variable, a separate lockfile the skill body references but doesn't inline) is not traced.
- The commit-sha-path heuristic (a bare 7-40 char hex path segment) can rarely misfire on a URL
  path segment that happens to be all-hex-looking text with no actual pinning semantics.
- `pip install` version-pin detection only recognizes `==`; a `>=`/`~=` range constraint is not
  treated as unpinned even though it permits drift, since a range constraint is a deliberate
  compatibility choice rather than the "no version specified at all" shape this rule targets.
- The manifest check only compares `name`/`version`; other manifest fields (permissions, entry
  points) can disagree without being caught.
- The loopback carve-out (`localhost`/`127.0.0.1`/`::1`/`0.0.0.0`, plus a strict `ipaddress` parse
  of the whole `127.0.0.0/8` range) is IP-literal only. A DNS name that merely resolves to
  loopback (`localtest.me`, an attacker-controlled record pointed at `127.0.0.1`) is not resolved
  offline and is treated as a genuine remote fetch that needs a pin.
- Only the FIRST token after `pip install` is examined. `--user`/`-U` are recognized and skipped
  to reach the package name behind them; any other flag (`--index-strategy unsafe-best-match`,
  `-r requirements.txt`) is itself treated as the "package" candidate, recognized as a flag by its
  leading `-`, and the check for THIS command stops there — a real unpinned package name later in
  the same `pip install` line is never reached. Verified: `pip install --index-strategy
  unsafe-best-match somepkg` reports no finding.

## What this guard does NOT prove

Silence does not prove a skill's supply chain is trustworthy — only that these three specific
static shapes are absent. A pinned resource can still point at a compromised commit; this guard
proves pinning exists, not that the pinned target is safe.

# Citations

[1] agentsec checklist item `4-agentic-skills-ast` (§4)
[2] CWE-829, CWE-502, CWE-706, OWASP-ASI:ASI04, OWASP-LLM:LLM06
[3] agent-audit-kit `agentic_skills.py`, rules AAK-AST02-001/AAK-AST04-001/AAK-AST10-001
