---
type: Guard
title: "llm-output-secrets-unscanned"
description: "LLM-generated output flows to a file-write or git-commit sink with no secret scan in between."
timestamp: "2026-08-24T09:00:00Z"
guard_id: "llm-output-secrets-unscanned"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM02", "OWASP:A02"]
---

# LLM-generated output flows to a file-write or git-commit sink with no secret scan in between

_Author — 2026-08-24_

---

## The threat

An LLM completion is attacker-influenceable through prompt injection, and can also
simply hallucinate or regurgitate a memorized-looking credential — a plausible
`sk-...` / `AKIA...` / private-key-shaped token embedded in generated code, a config
file, a commit message, or documentation the model was asked to produce. A pipeline
that writes that text straight to disk, or commits it, with no secret-scanning step in
between risks landing an LLM-hallucinated-or-leaked secret straight into a repo or a
persisted file — the same problem Guardrails AI hub's `secrets_present` validator
exists to close (it wraps `detect-secrets` on LLM output before the app trusts it).
OWASP-LLM:LLM02 (Sensitive Information Disclosure) and OWASP:A02 (Cryptographic
Failures / secret exposure).

Once a secret reaches a file write or a git commit, it is either shipped to disk
(readable by anything with filesystem access, likely backed up/synced) or written into
git history — the same "cannot be un-shipped" problem `hardcoded-llm-provider-key`
treats as HIGH for a human-authored key, except here the secret is attacker- or
model-supplied and was never reviewed by a human before it landed.

This is a DIFFERENT gap from two things already covered elsewhere in agentsec:
- **`gitleaks`** (the runner) scans repo HISTORY for secrets already committed — it says
  nothing about a code-generation flow that is about to commit one.
- **`env-secret-logged`** / **`hardcoded-llm-provider-key`** / **`client-side-secret-literal`**
  catch a SOURCE-AUTHORED secret (a developer's own literal or env read) — not a secret
  that flows out of a model's generated output into a new sink.

## Why it's often introduced

An agent pipeline that generates content (release notes, a config file, a code patch,
documentation) and then persists it feels finished once the write/commit works in a
demo — the scanning step is invisible until a hallucinated-but-plausible credential
actually appears in the model's output and gets shipped:

```python
def publish_changelog(prompt):
    summary = llm_client.invoke(prompt)
    with open("CHANGELOG.md", "w") as f:
        f.write(summary.content)          # never scanned
    subprocess.run(["git", "commit", "-m", "auto-update"], check=True)
```

## Detection design

1. **applies() gate:** `"llm" in profile.features` — only runs for detected LLM stacks.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`no-secret-scan-before-persist`, HIGH):**
   - Collects LLM-result variable names assigned within the sink line's **enclosing
     function** (`_enclosing_def_span`, adapted from `llm-json-output-unvalidated`) —
     the same unambiguous-method / `.create()`-requires-SDK-import signal that guard
     uses.
   - Also tracks a ONE-HOP derived variable: `content = response.text` counts `content`
     as tracked too (a simple attribute/subscript pass-through, not a function-call
     transform — `parsed = json.loads(response.content)` is NOT a derivation).
   - Looks for two sink shapes on each candidate line:
     - **File write:** `open(...).write(<tracked>)` inline, or `<handle>.write(<tracked>)`
       where `<handle>` was bound by `open(...)` (an assignment or `with open(...) as
       <handle>:`) earlier in the same function.
     - **Git commit:** `subprocess.run/call/check_call/check_output([...])` whose call
       (scanned over an 8-line lookahead window, to tolerate the common multi-line
       `subprocess.run([...], check=True)` shape) contains both a quoted `"git"` and a
       quoted `"commit"` token, or a GitPython `<repo>.index.commit(...)` call — this
       sink fires once an LLM result exists anywhere earlier in the function, since a
       commit call rarely carries the file content as an argument (the content already
       reached disk via a prior write).
   - If a sink is found, scans every line from the LLM generation call through the sink
     (inclusive) for a secret-scan indicator (`detect_secrets`/`detect-secrets`,
     `gitleaks`, or `bandit`, case-insensitive). Present anywhere in that range → silent.
     Absent → fire.

4. **Inline opt-out pragma:** `# security: allow-llm-output-secrets-unscanned`

5. **Severity and rule:** `"high"`, rule
   `"llm-output-secrets-unscanned/no-secret-scan-before-persist"`, standards
   `["OWASP-LLM:LLM02", "OWASP:A02"]`.

## When NOT to flag

- LLM output that never reaches a file-write or git-commit-shaped sink in the same
  function (logged, returned, used only for a decision) — no persistence risk this
  guard covers.
- A file write whose argument has no relationship to any tracked LLM-result variable —
  a static header, a config value, a different variable entirely.
- A `.write(...)` call on a handle never bound via `open(...)` (a socket, a `StringIO`
  passed in) — not treated as a file-write sink.
- A secret-scan call (`detect_secrets`/`gitleaks`/`bandit`) anywhere between the
  generation call and the sink — the guard does not care whether the scan actually
  ran successfully or what it did with a hit, only that the call exists in that range
  (a real-world scan step still needs to reject/redact on a positive; this guard only
  checks that the step is present at all).

## Tests

| Test | What it checks |
|---|---|
| `test_applies_when_llm_feature_present` / `test_not_applies_without_llm_feature` | `applies()` gate |
| `test_fires_on_file_write_with_no_scan` | Fires: `f.write(response.content)`, no scan |
| `test_fires_on_inline_open_write` | Fires: `open(...).write(response.content)` inline chain |
| `test_fires_on_derived_variable_written` | Fires: one-hop derived var (`content = response.text`) written |
| `test_fires_on_git_commit_subprocess_sink` | Fires: `subprocess.run(["git","commit",...])`, no scan |
| `test_fires_on_gitpython_commit_sink` | Fires: `repo.index.commit(...)`, no scan |
| `test_fires_on_await_llm_call` | Fires: `await client.ainvoke(...)` tracked |
| `test_fires_on_create_when_llm_sdk_imported` | Fires: `.create(` counted when an LLM SDK is imported |
| `test_fp_bait_detect_secrets_scan_between_generation_and_write` | Silent: a `detect_secrets` call before the write |
| `test_fp_bait_gitleaks_scan_between_generation_and_commit` | Silent: a `gitleaks` call before both sinks |
| `test_fp_bait_bandit_scan_silences` | Silent: a `bandit` call before the write |
| `test_fp_bait_no_sink_reached` | Silent: LLM output only logged/returned |
| `test_fp_bait_write_unrelated_to_llm_output` | Silent: a write whose argument isn't the LLM result |
| `test_fp_bait_write_handle_not_from_open` | Silent: `.write()` on a non-`open()`-bound handle |
| `test_fp_bait_create_on_non_llm_sdk` | Silent: `.create()` with no LLM SDK import (stripe) |
| `test_fp_bait_same_named_var_in_another_function` | Silent: same-named var in an unrelated function |
| `test_fp_bait_scan_only_after_the_sink_does_not_count` | Fires: a scan call AFTER the sink does not retroactively protect it |
| `test_fp_bait_when_pragma_present` | Silent: file-level pragma |
| `test_reports_every_violation_across_files` | Every violation across files surfaces, not capped at one |

## Known bypasses

- The LLM-result variable renamed via more than ONE hop (`content = response.text`
  then `body = content` then `f.write(body)`) is not tracked — only a direct,
  single-hop pass-through is recognized.
- A secret-scan call that exists but is a no-op (never checked, exceptions swallowed,
  called with the wrong argument) silences the rule without providing real protection —
  this guard only checks that a call with the right NAME exists in range, not that it
  does anything with its result.
- A secret-scan step that lives in a DIFFERENT file (a pre-commit hook, a separate CI
  job) is invisible to this guard — detection is single-file, per-function.
- A file-write sink via a lower-level API (`os.write(fd, ...)`, `Path.write_text(...)`,
  `shutil.copy`) is not recognized — only `open(...).write(...)` / `<handle>.write(...)`
  where the handle traces to `open(...)`.
- A git-commit sink invoked through a wrapper function (`git_helpers.commit(msg)`) is
  not recognized — only the two literal shapes (`subprocess` with `git`/`commit`
  tokens, or `.index.commit(`) are matched.
- The pragma `# security: allow-llm-output-secrets-unscanned` silences the rule for the
  entire file.

## What this guard does NOT prove

- That the secret-scan call, if present, actually catches anything — a
  `detect_secrets.scan_string(...)` call whose result is never checked passes this
  guard while providing zero real protection.
- That the LLM output actually contains a secret at all — this guard fires on the
  ABSENCE of a scanning step in the flow, the same way `llm-json-output-unvalidated`
  fires on the absence of schema validation regardless of whether the model's output
  was ever actually malformed.
- Multi-file or multi-function dataflow: an LLM result stored, passed to another
  function, and persisted there is not tracked.

# Citations

[1] agentsec checklist item `4-llm-output-secrets-scanned` (§4)
[2] OWASP-LLM:LLM02
[3] OWASP:A02
[4] Guardrails AI hub `secrets_present` validator (wraps `detect-secrets` on LLM output before persistence) — https://hub.guardrailsai.com/validator/guardrails/secrets_present
