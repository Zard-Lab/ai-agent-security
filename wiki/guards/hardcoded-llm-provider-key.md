---
type: Guard
title: "hardcoded-llm-provider-key"
description: "Hardcoded LLM provider API key literal in source."
timestamp: "2026-11-04T00:00:00Z"
guard_id: "hardcoded-llm-provider-key"
checklist_section: ["8"]
standards: ["CWE-798", "OWASP:A02"]
---

# Hardcoded LLM provider API key literal in source

_Author — 2026-08-06_

---

## The threat

**CWE-798 (Use of Hard-coded Credentials), OWASP:A02 (Cryptographic Failures).** A hardcoded
LLM provider API key ships to git history forever, is visible to every developer with
repository access, and cannot be rotated without a code change and a redeploy. Anyone who
reads the source — a leaked repo, a public fork, a compromised CI log, a screen-share — can
spend against the key immediately, or pivot with it if the provider account has broader
access (fine-tuning, org-level billing, other API scopes).

- **WHO reaches it:** anyone who can read the source — repo collaborators, a public fork,
  anyone with access to a CI log that echoes the file, anyone who receives a leaked copy.
- **WITH WHAT PRIVILEGE:** whatever the key itself is scoped to — typically full API access
  under the account's billing, sometimes org-level scopes.
- **TO WHAT EFFECT:** immediate ability to spend against the key (cost abuse), and if the
  provider account has broader permissions, a pivot point beyond just LLM calls.

Mined from `llmarmor/llmarmor`'s LLM02 rule and its shared `secret_patterns.py` module,
re-verified against the actual llmarmor source (not assumed from a description) before
building.

## Why it's often introduced

A developer pastes a real key straight into a config module or a client constructor call
while prototyping, meaning to move it to an environment variable "later":

```python
OPENAI_API_KEY = "sk-proj-abc123..."          # meant to be temporary
client = anthropic.Anthropic(api_key="sk-ant-api03-...")   # or inline in a constructor call
```

The commit happens before "later" does. Unlike a `.env` file (which a `.gitignore` entry can
exclude before the first commit), a literal in a `.py` file is committed by the same act that
writes the code.

## Detection design

1. **`applies()` gate** — returns `True` unconditionally. A hardcoded key is dangerous on any
   stack, not gated on a detected framework — same convention as `weak-secret-key-literal`
   and `auth-disabled-by-default`.
2. **Files scanned** — every `.py` file under the detected Python dirs
   (`python_scan_dirs(root, profile)`), via `iter_files(d, (".py",))`, then every `.go` file under
   `go_scan_dirs(root, profile)` in a separate pass, so a Go service in its own
   subdirectory of a polyglot repo is not missed. Non-product paths are
   still scanned, not skipped, via `is_nonproduct_path(..., credential_scan=True)` — the
   `credential_scan` flag keeps DEPLOYMENT trees (`migrations/`, `alembic/`) at full severity,
   since a key in `alembic/env.py` is a real committed credential, not a deliberately-fake test
   fixture (same reasoning as `weak-secret-key-literal` and `credential-file-path-reference`). A
   genuine test/fixture/example path (added after the first review round) is
   **downgraded to `medium`, not dropped**: most keys under `tests/`/`fixtures/`/`examples/` really
   are deliberately fake, but "usually" is not "always", and a silent skip cannot be told apart
   from "no key in this file at all" — the same "downgrade, not suppress" contract the sibling
   `client-side-secret-literal` guard already applies to its public-browser-key allowlist (#488
   B3). `medium` sits below the default `--fail-on high` gate, so it cannot produce an unfixable
   CI failure out of the box on the deliberately-fake majority case, while keeping the rare real
   leak visible — and, unlike `low`, it stays gateable by a repo that explicitly opts into
   `--fail-on medium`, since that's one of the three values the action's `fail-on` input
   (`action.yml`) accepts and `low` is not. This was decided explicitly
   on PR #583's review rather than left as a default: `low` would have made this class of finding
   un-gateable through the shipped CI channel at ANY setting, which the "downgrade, not suppress"
   framing doesn't fully convey on its own.
3. **Pattern** — `strip_python_strings()` first blanks triple-quoted docstring/template
   content (line numbers preserved) so a documented anti-pattern example doesn't self-fire.
   Each physical line then has its trailing/whole-line `#` comment removed via
   `strip_python_line_comment()` before the value regex is applied. Nine provider-key
   patterns: the original four ported verbatim from `llmarmor/llmarmor`'s `secret_patterns.py`,
   plus five more (2026-11-04) mined from `trufflesecurity/trufflehog`'s own
   detector source and verified against its real regex, not assumed from a description:

   - **OpenAI**: `sk-` (excluding `sk-ant-`) followed by 20+ alphanumeric/dash/underscore
     chars, requiring at least one digit in the random portion. The digit requirement is
     llmarmor's own disambiguator, eliminating two real FP classes it documented: a
     hyphenated URL/doc slug (`sk-the-model-to-adopt-a-persona`, no digit) and an env-var-name
     reference (`sk-OPENAI_API_KEY_HERE`, no digit).
   - **Anthropic**: `sk-ant-` followed by 20+ alphanumeric/dash/underscore chars.
   - **Google AI**: `AIza` followed by 35+ alphanumeric/dash/underscore chars (open-ended, not
     an exact count — see the note on the digit/length choices below).
   - **Hugging Face**: `hf_` followed by 20+ alphanumeric chars.
   - **Pinecone**: `pcsk_` + 5-6 alphanumeric chars + `_` + exactly 63 alphanumeric chars.
   - **Replicate**: `r8_` followed by exactly 37 alphanumeric/dash/underscore chars.
   - **Groq**: `gsk_` followed by exactly 52 alphanumeric chars.
   - **LangSmith**: `lsv2_pt_` or `lsv2_sk_` + 32 hex chars + `_` + 10 hex chars.
   - **Supabase personal access token**: `sbp_` followed by exactly 40
     lowercase-alphanumeric chars — distinct from the service-role/anon JWT keys this project
     already covers elsewhere (`public-table-rls` and friends); a PAT authenticates the
     Supabase *management API* itself, a different and broader blast radius.

   Each pattern has a left boundary (`(?<![A-Za-z0-9])`) so an identifier merely containing
   the prefix (`mysk-ant-token_name`) does not match.

4. **Two independent exclusions, both ported from llmarmor's own source:**
   - **Line-level test marker**: if the CODE portion of the line (after `strip_python_line_comment`
     has already removed a trailing/whole-line `#` comment) contains `test`/`fake`/`mock`/
     `example`/`dummy`/`placeholder` (word-boundaried) anywhere, the match is silenced —
     llmarmor applies this to the whole line, not just the variable name, so an unrelated word
     elsewhere in the CODE also silences it. **A marker that appears only inside the trailing
     comment does NOT silence anything**, since the comment is already gone by the time this
     check runs (see "Known bypasses" below — an earlier version of this doc got the ordering
     backwards).
   - **Token-level placeholder value**: if the MATCHED TOKEN ITSELF contains a documentation
     word (`your`/`example`/`test`/`fake`/`mock`/`dummy`/`placeholder`/`replace`/`insert`/
     `put`/`change`/`fill`/`xxx`/`sample`/`demo`/`here`), the match is silenced — a real key's
     random portion never legitimately contains one of these words. The Google pattern is
     open-ended (`{35,}`, not `{35}`) specifically so this check sees the full token: a fixed
     count truncated the match at exactly 35 chars, so a placeholder word appended right after
     a real-looking 35-char body landed outside `m.group(0)` entirely and this check never saw
     it (found in review, #529 — fixed together with making the scan consider every match on a
     line, not just the first, so a placeholder token earlier on a line can no longer shield a
     real key literal later on the same line).
5. **Opt-out pragma** — `# security: allow-llm-provider-key` (`//` in Go) as a comment on the
   offending physical line. Only a real comment counts: a string on the key's own line quoting
   the pragma is content and still fires (#424, #996).
6. **Severity / rule / standards** — HIGH, rule
   `hardcoded-llm-provider-key/known-provider-prefix`, standards
   `["OWASP:A02", "CWE-798"]`.

## Relationship to other guards

- **`client-side-secret-literal`** — the JS/TS counterpart, scoped to `.js/.jsx/.ts/.tsx` and
  gated on `frontend`, `javascript` **or `typescript`**. The `typescript` arm was added by #1082:
  before it, a TS-only backend's provider key fell between the two guards and passed
  `--guards-only`. Broader provider coverage (also AWS, GitHub, Slack, GitLab) since it targets
  the general committed-secret problem, not LLM keys specifically. This guard is
  Python/Go-source-scoped and LLM-provider-specific; neither re-detects the other's file scope.
- **`cleartext-secret-storage`** — cookies and plaintext file writes, a different sink
  entirely (a secret flowing OUT to persistent storage, not a literal sitting in source).
- **`terraform-hardcoded-secret-literal`** — Terraform-resource-scoped, not Python.
- **`weak-secret-key-literal`** — a different secret class (Django/Flask `SECRET_KEY`,
  which signs sessions/CSRF tokens, not an LLM provider's own API key).

None of the four cover a bare LLM provider key literal in general Python/Go backend source —
confirmed by reading each guard's actual source before classifying this as a genuine gap,
not assumed from checklist status or guard names.

## When NOT to flag

- `OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")` — the value is resolved at runtime from an
  environment variable, not a literal in source. Not flagged (no matching literal on the
  line).
- A line containing a test/fake/mock/example/dummy/placeholder marker anywhere — silenced by
  the line-level exclusion.
- A matched token whose value contains a documentation-placeholder word (`your-key-here`,
  `xxx`, `replace-me`) — silenced by the token-level exclusion.
- A hyphenated URL slug or doc heading that happens to start with `sk-` but has no digit in
  the random portion (`sk-the-model-to-adopt-a-persona`) — the OpenAI pattern's digit
  requirement excludes it.
- A key shown only in a comment describing the anti-pattern — comments are stripped before
  the pattern is applied.
- A reviewed, intentionally-committed fixture key never deployed: suppress with
  `# security: allow-llm-provider-key` on that line.
- A key literal under a test/fixture/example path is not silenced — it fires at `medium` instead of
  `high`. Use the pragma above for an audited case; the path alone is no longer
  sufficient to drop the finding.

## Tests

| Test | What it checks |
|---|---|
| `test_openai_key_fires` | A real-shaped OpenAI `sk-proj-...` key fires HIGH |
| `test_anthropic_key_fires` | An Anthropic `sk-ant-...` key fires, labeled correctly |
| `test_google_key_fires` | A Google AI `AIza...` key fires |
| `test_huggingface_token_fires` | A Hugging Face `hf_...` token fires |
| `test_openai_key_no_space_single_quote_still_fires` | Bypass check: no whitespace / single quotes don't evade detection |
| `test_env_var_reference_is_safe` | FP-bait: `os.getenv(...)` (no literal) stays silent |
| `test_test_marker_on_line_is_safe` | FP-bait: a `test`/`fake`/`mock` marker on the line silences the finding |
| `test_placeholder_value_is_safe` | FP-bait: a documentation placeholder inside the token stays silent |
| `test_url_slug_without_digit_is_safe` | FP-bait: a digit-less `sk-`-prefixed slug stays silent (the OpenAI disambiguator) |
| `test_pragma_suppresses` | The inline pragma silences the finding on that line |
| `test_pragma_quoted_in_a_string_on_the_line_does_not_suppress` | A string on the key's own line quoting the pragma is content → still fires (#424) |
| `test_go_pragma_quoted_in_a_string_on_the_line_does_not_suppress` | Go: a string on the key's own line quoting the pragma is content → still fires (#424) |
| `test_separator_char_inside_a_docstring_does_not_desync_the_pragma_view` | A `\v`/`\f` separator inside a docstring must not desync the comment view from the blanked text: no raise, the key still fires, the pragma still opts out (#996 round-2 M2) |
| `test_comment_only_mention_is_safe` | FP-bait: a key shown only in a comment stays silent |
| `test_nonproduct_path_downgraded_not_dropped` | a fixture/test file key downgrades to `medium`, is not dropped |
| `test_nonproduct_path_pragma_still_fully_suppresses` | The pragma still fully silences a finding even under a test path |
| `test_applies_universally` | `applies()` is `True` even against a feature-less profile |
| `test_marker_only_in_trailing_comment_does_not_suppress` | A marker word ONLY in the trailing comment does not silence a real key (comments strip first) |
| `test_google_key_with_appended_placeholder_suffix_is_safe` | FP-bait: a placeholder word appended right after a real-length Google key body is still seen by the token-level exclusion |
| `test_real_key_after_a_placeholder_key_on_the_same_line_still_fires` | A placeholder key earlier on a line no longer shields a real key literal after it |
| `test_pinecone_key_fires` / `test_pinecone_key_too_short_is_safe` | a real-shaped Pinecone key fires; a too-short one stays silent |
| `test_replicate_key_fires` / `test_replicate_key_too_short_is_safe` | a real-shaped Replicate key fires; a too-short one stays silent |
| `test_groq_key_fires` / `test_groq_key_too_short_is_safe` | a real-shaped Groq key fires; a too-short one stays silent |
| `test_langsmith_key_fires` / `test_langsmith_key_wrong_shape_is_safe` | a real-shaped LangSmith key fires; a wrong-shaped one stays silent |
| `test_supabase_pat_fires` / `test_supabase_pat_too_short_is_safe` | a real-shaped Supabase PAT fires; a too-short one stays silent |
| `test_go_groq_and_supabase_pat_fire` | The widened regex set also fires through the Go scan path, not just Python |

## Fixed since the first review round (#529)

- **Google pattern truncation let an appended placeholder escape both exclusions.** `{35}` (an
  exact count) captured only the first 35 chars of the key body, so a placeholder word appended
  directly after a real-length body landed outside `m.group(0)` and neither exclusion ever saw
  it — the finding fired on what was actually a placeholder. Fixed by widening to `{35,}`; a
  real key with nothing appended still matches exactly 35 chars, unaffected.
- **Only the first match per line was considered.** A placeholder-shaped key earlier on a line
  ended the scan (`.search()`, not `.finditer()`) before a real key literal later on the same
  line was ever examined. Fixed by evaluating every match on the line independently against the
  token-level exclusion; the line-level marker check is unchanged (still whole-line, by design).

## Fixed since (external-tool convergence review)

- **Test/fixture-path findings were fully dropped instead of downgraded.** Two independent
  external tools converged on "severity-downgrade rather than full suppression for a secret
  literal under a test/fixture path" as a discipline this guard did not yet match — verified by
  reading the actual `run()`/`_finding()` code (not assumed from the guard's name or checklist
  status), which used `continue` on `is_nonproduct_path(...)` before ever reaching the pattern
  match. Fixed by scanning the file regardless and downgrading the finding's severity to `medium`
  instead. The **token-level placeholder-value check** (`_PLACEHOLDER_VALUE`, deliberately
  unanchored so it catches a placeholder word appended without a delimiter right after a
  real-length key body — see #529 above and `test_google_key_with_appended_placeholder_suffix_is_safe`)
  was investigated for the same "exact-match, not substring" claim and found to be a considered,
  already-tested trade-off, not an unexamined gap — see "Known bypasses" below, which already
  documents the risk in the opposite direction. It was left unchanged.

## Known bypasses

- **Indirect assignment / aliasing / string building** — `_k = "sk-" + "proj-" + rest` or a
  key assembled via concatenation, `.join()`, or base64 decoding at runtime. The guard only
  matches a literal token sitting directly in source; it does not track data flow.
- **A provider/format outside the curated 9** — a Mistral or Cohere key, or a future
  OpenAI/Anthropic key format change, is not covered. Kept intentionally tight, mirroring
  `weak-secret-key-literal`'s own precision-first posture, rather than a broad entropy
  heuristic that would need per-provider FP tuning.
- **Non-`.py`/`.go` config** — `.env` files, YAML/TOML/JSON config are out of scope for this
  guard's file scan (a different guard's job; `env_secret_in_prompt.py` and friends cover
  adjacent but distinct concerns).
- **A line-level test marker anywhere in the CODE portion of the line** —
  `OPENAI_API_KEY = "sk-proj-real-leaked-key-123"  # let's rotate this test key` would silence
  a genuinely real key if the marker sat in the assignment itself; the whole-line check applies
  to any code on the line, not just the variable name. This is llmarmor's own design choice,
  ported verbatim rather than tightened, since narrowing it risks reintroducing the FP classes
  the whole-line check was built to catch. **This is narrower than it first looks**: a marker
  word that appears ONLY in a trailing `#` comment does NOT trigger this bypass, because
  `strip_python_line_comment` removes the comment before the marker check runs —
  `OPENAI_API_KEY = "sk-proj-real-leaked-key-123456"  # test this later` still fires (verified:
  1 finding). An earlier draft of this doc claimed the opposite with that exact example; it was
  wrong about the ordering, not the code.

## What this guard does NOT prove

A silent guard does **not** mean no LLM provider key is exposed. It does not check: whether
the key is loaded from a secrets manager correctly at runtime (only that no LITERAL sits in
source); whether the key has already been rotated after a past leak; whether a key of a
provider/format outside the curated 9 sits hardcoded; or whether the key is exposed via a
different channel entirely (a log line, an error response, a `.env` file committed despite
`.gitignore`). It is a narrow, high-confidence signal for the exact hardcoded-literal pattern
`llmarmor`'s LLM02 rule targets, adapted to agentsec's Python and Go source scope (JS/TS is
`client-side-secret-literal`'s).

# Citations

[1] agentsec checklist item `8-hardcoded-llm-provider-key` (§8)
[2] CWE-798
[3] OWASP:A02
