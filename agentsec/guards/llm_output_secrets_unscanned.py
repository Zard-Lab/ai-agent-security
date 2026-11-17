"""Guard: LLM-generated output flows to a file-write or git-commit sink with no secret scan
in between (checklist §4, new item — Agentic AI / RAG Security).

An LLM completion is attacker-influenceable (prompt injection) and can also simply
hallucinate or regurgitate a memorized-looking credential (a plausible `sk-...` /
`AKIA...` / private-key-shaped token embedded in generated code, a config file, a
commit message, or documentation). A pipeline that writes that text straight to a file
— or commits it — with no secret-scanning step in between risks landing an
LLM-hallucinated-or-leaked secret straight into a repo or a persisted file, exactly the
gap Guardrails AI hub's `secrets_present` validator exists to close (it wraps
`detect-secrets` on LLM output before the app trusts it).

This is a DIFFERENT gap from two things already covered elsewhere:
- `gitleaks` (the runner) scans repo HISTORY for secrets already committed — it says
  nothing about a code-generation flow that is about to commit one.
- `env-secret-logged` / `hardcoded-llm-provider-key` / `client-side-secret-literal` catch
  a SOURCE-AUTHORED secret (a developer's own literal or env read) — not a secret that
  flows out of a MODEL's generated output into a new sink.

One statically detectable pattern:

  **`no-secret-scan-before-persist`** (HIGH): a variable is assigned from an LLM
  generation call (`.invoke`/`.generate`/`.chat`/`.complete`/`.ainvoke`, or `.create(`
  when the file imports a known LLM SDK — the same signal `llm-json-output-unvalidated`
  tracks), and that variable (or a variable assigned directly from it — one-hop
  derivation, e.g. `content = response.text`) is passed to:

  - a **file-write sink**: `open(...).write(<tracked>)` inline, or `<handle>.write(<tracked>)`
    where `<handle>` was bound by `open(...)` (an assignment or a `with open(...) as
    <handle>:`) earlier in the same function, OR
  - a **git-commit-shaped sink**: `subprocess.run/call/check_call/check_output([...,
    "git", ..., "commit", ...])` (list-form, allowing the call to span a few lines — the
    common multi-line `subprocess.run([...], check=True)` shape), or a GitPython
    `<repo>.index.commit(...)` call — once an LLM result exists anywhere earlier in the
    same function, since a commit call rarely carries the file content as an argument
    (the content already reached disk via a prior write); the risk is that this call
    persists it into git history,

  with NO secret-scan indicator (`detect_secrets`/`detect-secrets`, `gitleaks`, or
  `bandit`, case-insensitive) anywhere between the LLM generation call's line and the
  sink's line, in the same function.

**Why HIGH?** Once a secret reaches a file write or a git commit, it is either shipped to
disk (readable by anything with filesystem access, and likely to be backed up/synced) or
written into git history — the exact "cannot be un-shipped" problem `hardcoded-llm-
provider-key` treats as HIGH for a human-authored key, except here the secret is
attacker- or model-supplied and never reviewed by a human before it lands.

**Silence conditions:**
- A secret-scan call (`detect_secrets`/`gitleaks`/`bandit`) appears anywhere between the
  generation call and the sink, in the same function — assumed scanned.
- The tracked variable (or its one-hop derivative) never reaches a file-write or
  git-commit-shaped sink in the same function — it may be logged, returned, or used for
  something with no persistence risk.
- The file contains `# security: allow-llm-output-secrets-unscanned` anywhere.

**False-negative scope:** Single-file, per-function, name-based dataflow (mirrors
`llm-json-output-unvalidated`): a variable renamed more than one hop away, a value
threaded through a second function call, or a secret-scan call that lives in a
different file (a pre-commit hook, a separate CI step) is not tracked — this guard only
sees what happens *inside the same function*, in the same file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-llm-output-secrets-unscanned"

_STANDARDS = ["OWASP-LLM:LLM02", "OWASP:A02"]

# --- LLM generation-call tracking (same signal `llm-json-output-unvalidated` uses) --------------

_LLM_RESULT_VAR = re.compile(
    r"(\w+)\s*=\s*(?:await\s+)?[\w.]+\.(?:invoke|generate|complete|chat|ainvoke)\s*\(",
    re.IGNORECASE,
)
_LLM_RESULT_VAR_CREATE = re.compile(r"(\w+)\s*=\s*(?:await\s+)?[\w.]+\.create\s*\(", re.IGNORECASE)

_LLM_SDK_IMPORT = re.compile(
    r"(?:from|import)\s+(?:"
    r"openai|anthropic|langchain\w*|llama_index|llama_cpp|litellm|cohere|mistralai|groq|ollama"
    r"|google\.generativeai|google\.genai|vertexai|together|replicate|transformers|vllm|huggingface_hub"
    r")\b",
    re.IGNORECASE,
)

# One-hop derivation: `content = response.text` / `msg = response["content"]` — the RHS's head
# identifier is what matters; a derived var counts as "the LLM output" too (task scope: "that
# variable, or something derived from it"). Bounded to a SIMPLE reference (no call), so
# `parsed = json.loads(response.content)` is NOT treated as a derivation of `response` — that is
# a structural transform, not a pass-through, and tracking it would over-widen this guard into
# flagging any value that ever touched an LLM result.
_DERIVED_VAR = re.compile(r"(\w{1,80})\s*=\s*(?:await\s+)?(\w{1,80})(?:\.\w{1,80}|\[[^\]\n]{0,80}\])*\s*$")

_DEF = re.compile(r"[ \t]*(?:async[ \t]+)?def[ \t]")


def _enclosing_def_span(lines: list[str], i: int) -> tuple[int, int] | None:
    """(start, end) line indices of the function whose body contains line `i`, or None if `i` is
    at module level. Adapted verbatim from `llm_json_output_unvalidated._enclosing_def_span` —
    scopes tracking to the function a sink line sits in, so a same-named variable in an unrelated
    function can't cross-taint."""
    if not lines[i].strip():
        return None
    line_indent = len(lines[i]) - len(lines[i].lstrip())
    j = i - 1
    while j >= 0:
        s = lines[j]
        if s.strip():
            ind = len(s) - len(s.lstrip())
            if ind < line_indent:
                if _DEF.match(s):
                    k = j + 1
                    while k < len(lines):
                        ln = lines[k]
                        if ln.strip() and (len(ln) - len(ln.lstrip())) <= ind:
                            break
                        k += 1
                    return j, k
                line_indent = ind
        j -= 1
    return None


def _llm_result_vars(scope_lines: list[str], has_sdk: bool) -> dict[str, int]:
    """LLM-result variable name -> the (0-based, scope-relative) line index of its assignment.
    Unambiguous methods always count; `.create(` only when the file imports an LLM SDK."""
    out: dict[str, int] = {}
    for i, line in enumerate(scope_lines):
        m = _LLM_RESULT_VAR.search(line)
        if m:
            out.setdefault(m.group(1), i)
        elif has_sdk:
            m2 = _LLM_RESULT_VAR_CREATE.search(line)
            if m2:
                out.setdefault(m2.group(1), i)
    return out


def _derived_vars(scope_lines: list[str], llm_vars: dict[str, int]) -> dict[str, int]:
    """One-hop derived variable name -> its own assignment line index, for any RHS whose head
    identifier is a tracked LLM-result variable."""
    out: dict[str, int] = {}
    for i, line in enumerate(scope_lines):
        m = _DERIVED_VAR.search(line.rstrip())
        if m and m.group(2) in llm_vars and m.group(1) not in llm_vars:
            out.setdefault(m.group(1), i)
    return out


# --- sinks ----------------------------------------------------------------------------------

# `open(...).write(<arg>)` inline chain. Bounded capture (`.{0,300}`) mirrors the ReDoS-safe
# style `llm-json-output-unvalidated._JSON_LOADS` uses.
_INLINE_OPEN_WRITE = re.compile(
    r"open\s*\([^)\n]{0,300}\)\s*\.write\s*\(\s*([^\s].{0,300}?)\s*\)"
)
# `<handle>.write(<arg>)` — `<handle>` is checked against file-handle names collected separately.
_NAMED_WRITE = re.compile(r"\b(\w+)\.write\s*\(\s*([^\s].{0,300}?)\s*\)")
_OPEN_ASSIGN = re.compile(r"\b(\w+)\s*=\s*open\s*\(")
_WITH_OPEN_AS = re.compile(r"with\s+open\s*\([^)\n]{0,300}\)\s*as\s+(\w+)")

# git-commit-shaped sinks.
_SUBPROCESS_CALL = re.compile(
    r"subprocess\.(?:run|call|check_call|check_output)\s*\(", re.IGNORECASE
)
_GIT_TOKEN = re.compile(r"""["']git["']""", re.IGNORECASE)
_COMMIT_TOKEN = re.compile(r"""["']commit["']""", re.IGNORECASE)
_GITPYTHON_COMMIT = re.compile(r"\.index\.commit\s*\(")
_SUBPROCESS_WINDOW = 8  # lines of lookahead for a multi-line `subprocess.run([...])` call

_SECRET_SCAN_CALL = re.compile(r"detect[-_]secrets|gitleaks|bandit", re.IGNORECASE)


def _file_handle_names(scope_lines: list[str]) -> set[str]:
    names = {m.group(1) for m in (_OPEN_ASSIGN.search(ln) for ln in scope_lines) if m}
    names |= {m.group(1) for m in (_WITH_OPEN_AS.search(ln) for ln in scope_lines) if m}
    return names


def _references_any(text: str, names: set[str]) -> bool:
    return any(re.search(r"\b" + re.escape(n) + r"\b", text) for n in names)


class LlmOutputSecretsUnscannedGuard(Guard):
    id = "llm-output-secrets-unscanned"
    title = "LLM output persisted to a file or git commit with no secret scan"
    area = "Secrets"

    # llm_output_secrets.py: LLM completion written to a file via `f.write(response.content)`,
    # no detect-secrets/gitleaks/bandit call anywhere in the function ->
    # fires llm-output-secrets-unscanned/no-secret-scan-before-persist (HIGH).
    canary_plant = CanaryPlant(
        files={
            "llm_output_secrets.py": (
                "def sync_notes(prompt):\n"
                "    response = llm_client.invoke(prompt)\n"
                '    with open("notes.md", "w") as f:\n'
                "        f.write(response.content)\n"
            ),
        },
        expects=frozenset({
            "llm-output-secrets-unscanned/no-secret-scan-before-persist",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                findings.extend(self._scan(root, f, text))
        return findings

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        has_sdk = bool(_LLM_SDK_IMPORT.search(text))

        for i, line in enumerate(lines):
            # Cheap pre-filter: only pay for the enclosing-scope walk + variable tracking on a
            # line that could plausibly be a sink at all.
            m_inline = _INLINE_OPEN_WRITE.search(line)
            m_named = None if m_inline else _NAMED_WRITE.search(line)
            is_git_sink_candidate = _GITPYTHON_COMMIT.search(line) or _SUBPROCESS_CALL.search(line)
            if not (m_inline or m_named or is_git_sink_candidate):
                continue

            span = _enclosing_def_span(lines, i)
            scope_start, scope_end = span if span else (0, len(lines))
            scope_lines = lines[scope_start:scope_end]
            rel_i = i - scope_start

            llm_vars = _llm_result_vars(scope_lines, has_sdk)
            if not llm_vars:
                continue
            derived = _derived_vars(scope_lines, llm_vars)
            tracked = set(llm_vars) | set(derived)
            gen_line = min(llm_vars.values())  # earliest generation-call line, scope-relative

            kind: str | None = None

            if m_inline and _references_any(m_inline.group(1), tracked):
                kind = "write"
            elif m_named:
                handle_names = _file_handle_names(scope_lines)
                if m_named.group(1) in handle_names and _references_any(
                    m_named.group(2), tracked
                ):
                    kind = "write"

            if kind is None and _GITPYTHON_COMMIT.search(line):
                kind = "commit"

            if kind is None and _SUBPROCESS_CALL.search(line):
                window = "\n".join(scope_lines[rel_i : rel_i + _SUBPROCESS_WINDOW])
                if _GIT_TOKEN.search(window) and _COMMIT_TOKEN.search(window):
                    kind = "commit"

            if kind is None:
                continue

            between = "\n".join(scope_lines[gen_line : rel_i + 1])
            if _SECRET_SCAN_CALL.search(between):
                continue

            out.append(self._finding(root, f, i + 1, kind))
        return out

    def _finding(self, root: Path, f: Path, lineno: int, kind: str) -> Finding:
        sink_desc = (
            "a file write (`open(...).write(...)`)"
            if kind == "write"
            else "a git-commit-shaped call (`subprocess` git commit / `repo.index.commit(...)`)"
        )
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "An LLM completion's output reaches "
                f"{sink_desc} with no detect-secrets/gitleaks/bandit-style scan call "
                "anywhere between the generation call and this sink, in the same "
                "function. LLM output is attacker-influenceable (prompt injection) or "
                "can simply hallucinate/regurgitate a plausible-looking credential — "
                "persisting it unscanned risks writing a real or fake secret straight "
                "into a file or git history."
            ),
            remediation=(
                "Scan LLM-generated content for secrets before it is written or "
                "committed — e.g. run `detect-secrets scan` (or `gitleaks detect "
                "--no-git -s -`) over the text and reject/redact on a hit, mirroring "
                "Guardrails AI hub's `secrets_present` validator. Suppress with "
                f"`# {_PRAGMA}` only after confirming a scan step exists outside this "
                "function (a pre-commit hook, a separate CI gate)."
            ),
            rule="llm-output-secrets-unscanned/no-secret-scan-before-persist",
            standards=list(_STANDARDS),
        )
