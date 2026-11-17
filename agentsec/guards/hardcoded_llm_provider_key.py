"""Guard: hardcoded LLM provider API key literal in source (CWE-798).

    OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
    client = anthropic.Anthropic(api_key="sk-ant-api03-abcdefghijklmnopqrstuvwxyz")

A hardcoded LLM provider key ships to git history forever, is visible to every developer
with repo access, and cannot be rotated without a code change. Anyone who reads the source
(a leaked repo, a public fork, a compromised CI log) can spend against the key immediately.

This is the Python/Go counterpart to `client-side-secret-literal`, which owns `.js/.jsx/.ts/.tsx`
whenever `frontend`, `javascript` or `typescript` is detected, backend TS included (#1082). It is a
narrower, LLM-specific complement to `cleartext-secret-storage` (cookies/file writes) and
`terraform-hardcoded-secret-literal` (Terraform resources). None of the three scan general
Python/Go backend source for a bare LLM provider key literal, which is this guard's job.
Mined from `llmarmor/llmarmor`'s LLM02 rule and its shared `secret_patterns.py` module.

Fires HIGH when a `.py` or `.go` file contains a literal token matching one of nine provider key
formats:

  * **OpenAI** — `sk-` (not `sk-ant-`) followed by 20+ alphanumeric/dash/underscore chars,
    with at least one digit in the random portion. The digit requirement is what
    `llmarmor` uses to eliminate two false-positive classes: a URL-path slug like
    `sk-the-model-to-adopt-a-persona` (no digit) and an env-var-name reference like
    `sk-OPENAI_API_KEY_HERE` (no digit).
  * **Anthropic** — `sk-ant-` followed by 20+ alphanumeric/dash/underscore chars.
  * **Google AI** — `AIza` followed by 35+ alphanumeric/dash/underscore chars.
  * **Hugging Face** — `hf_` followed by 20+ alphanumeric chars.
  * **Pinecone** — `pcsk_` + 5-6 alphanumeric chars + `_` + 63 alphanumeric chars.
  * **Replicate** — `r8_` followed by 37 alphanumeric/dash/underscore chars.
  * **Groq** — `gsk_` followed by 52 alphanumeric chars.
  * **LangSmith** — `lsv2_pt_` or `lsv2_sk_` + 32 hex chars + `_` + 10 hex chars.
  * **Supabase personal access token** — `sbp_` followed by 40 lowercase-alphanumeric chars
 — distinct from the service-role/anon JWT keys this project already covers
    elsewhere; a PAT authenticates the Supabase *management API* itself.

The last five were mined from `trufflesecurity/trufflehog`'s own detector source (`pkg/detectors/`),
the single most-starred credential-detector catalog surveyed to date, and verified against the real
regex in each detector file, not assumed from a description.

A match is suppressed when the CODE portion of the line (comments already stripped) contains
a test/placeholder marker word (`test`/`fake`/`mock`/`example`/`dummy`/`placeholder`) OR when
the MATCHED TOKEN ITSELF looks like a documentation placeholder (`your`/`example`/`test`/
`fake`/`mock`/`dummy`/`placeholder`/`replace`/`insert`/`put`/`change`/`fill`/`xxx`/`sample`/
`demo`/`here`) — both checks mirror `llmarmor`'s own exclusions verbatim, verified against its
source rather than assumed. Because a trailing `#` comment is stripped BEFORE the line-level
check runs, a marker word that appears only in a comment (`... # test this later`) does NOT
suppress a real key on the same line — the marker has to be in the code itself (a variable
name, a string, an argument) to count.

Suppress an audited case (e.g. a documented-fake key in a fixture the walker doesn't
already exclude) with:

    OPENAI_API_KEY = "sk-proj-..."  # security: allow-llm-provider-key

Go source (#553 review follow-up) uses the same key-format patterns and marker/
placeholder exclusions, scanned via `go_scan_dirs`/`strip_go_comments` instead of
`python_scan_dirs`/`strip_python_strings` — a separate pass, not just a suffix widening, since
`python_scan_dirs` only falls back to repo root when NO Python dirs exist at all, and would
otherwise miss a Go subdirectory in a polyglot repo. The suppress pragma is a `//` comment:

    apiKey := "sk-proj-..." // security: allow-llm-provider-key
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    go_scan_dirs,
    is_nonproduct_path,
    iter_files,
    python_scan_dirs,
    read,
    rel,
    strip_go_comments,
    strip_python_line_comment,
    strip_python_strings,
)

# Provider key patterns, each with a left boundary so an identifier merely containing the
# prefix (`mysk-ant-...`) does not match. Ported verbatim from llmarmor's secret_patterns.py.
_OPENAI_KEY = r"(?<![A-Za-z0-9])sk-(?!ant-)(?=[A-Za-z0-9_-]*[0-9])(?:[A-Za-z0-9_-]{20,})"
_ANTHROPIC_KEY = r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}"
_GOOGLE_KEY = r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{35,}"
_HF_TOKEN = r"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{20,}"  # nosec B105 (detection pattern, not a credential)

# (trufflehog cross-check, 2026-11-04): widened from the original 4 providers to 9.
# Each verified against trufflehog's real detector regex, not assumed from a description.
_PINECONE_KEY = r"(?<![A-Za-z0-9])pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}"
_REPLICATE_KEY = r"(?<![A-Za-z0-9])r8_[A-Za-z0-9_-]{37}"
_GROQ_KEY = r"(?<![A-Za-z0-9])gsk_[A-Za-z0-9]{52}"
_LANGSMITH_KEY = r"(?<![A-Za-z0-9])lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}"
_SUPABASE_PAT = r"(?<![A-Za-z0-9])sbp_[a-z0-9]{40}"

_PROVIDER_KEY = re.compile(
    "(?:" + "|".join([
        _OPENAI_KEY, _ANTHROPIC_KEY, _GOOGLE_KEY, _HF_TOKEN,
        _PINECONE_KEY, _REPLICATE_KEY, _GROQ_KEY, _LANGSMITH_KEY, _SUPABASE_PAT,
    ]) + ")"
)


def _provider_label(token: str) -> str:
    if token.startswith("sk-ant-"):
        return "Anthropic"
    if token.startswith("sk-"):
        return "OpenAI"
    if token.startswith("AIza"):
        return "Google AI"
    if token.startswith("hf_"):
        return "Hugging Face"
    if token.startswith("pcsk_"):
        return "Pinecone"
    if token.startswith("r8_"):
        return "Replicate"
    if token.startswith("gsk_"):
        return "Groq"
    if token.startswith("lsv2_"):
        return "LangSmith"
    if token.startswith("sbp_"):
        return "Supabase"
    return "provider"  # pragma: no cover — unreachable, every branch above is exhaustive


# A test/placeholder marker anywhere on the line — llmarmor applies this to the whole line,
# not just the variable name, so a comment or unrelated word on the same line also silences it.
_TEST_VAR_MARKER = re.compile(
    r"(?<![A-Za-z0-9])(?:test|fake|mock|example|dummy|placeholder)(?![A-Za-z0-9])",
    re.IGNORECASE,
)

# A documentation-placeholder word INSIDE the matched token itself (not the surrounding line) —
# a real key never legitimately contains "your"/"replace"/"xxx"/etc. in its random portion.
_PLACEHOLDER_VALUE = re.compile(
    r"(?:your|example|test|fake|mock|dummy|placeholder|replace|insert|put|change|fill"
    r"|xxx|sample|demo|here)",
    re.IGNORECASE,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-llm-provider-key")
# Go has no `#` comment syntax — a plain substring check (mirrors the JS guards' convention,
# e.g. js_command_injection.py) works inside a `//` line comment without needing a second
# language-specific regex.
_GO_PRAGMA = "security: allow-llm-provider-key"

_STANDARDS = ["OWASP:A02", "CWE-798"]


class HardcodedLlmProviderKeyGuard(Guard):
    id = "hardcoded-llm-provider-key"
    title = "Hardcoded LLM provider API key literal in source"
    area = "Secrets"

    # llm_key.py: OpenAI-shaped key literal (has a digit, no test/placeholder marker) ->
    # fires hardcoded-llm-provider-key/known-provider-prefix (HIGH).
    # Must NOT contain: test/fake/mock/example/dummy/placeholder anywhere on the line, or
    # a placeholder word inside the token itself (both would silence the finding), or the
    # allow-llm-provider-key pragma.
    # llm_key.py: OPENAI_API_KEY = "sk-proj-..." -> fires known-provider-prefix.
    canary_plant = CanaryPlant(
        files={
            "llm_key.py": 'OPENAI_API_KEY = "sk-proj-canary1234567890abcdefghijk"\n',
        },
        expects=frozenset({
            "hardcoded-llm-provider-key/known-provider-prefix",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # a hardcoded key in source is dangerous on any stack, not framework-gated

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                # credential_scan=True: a key in a DEPLOYMENT tree (alembic/env.py-style) is a
                # real committed credential, unlike the deliberately-fake ones in tests/fixtures.
                # A genuine test/fixture/example path is DOWNGRADED, not dropped: a
                # real key accidentally committed to a test fixture is still a live leak, and a
                # silent skip cannot be told apart from "no key in this file" — see `_finding`'s
                # `nonprod` argument. `credential_scan=True` keeps deployment trees at full
                # severity, unaffected by this.
                nonprod = is_nonproduct_path(rel(root, f), profile.archive_segments, credential_scan=True)
                out.extend(self._scan(root, f, nonprod))
        # (#553 review follow-up): a separate go_scan_dirs pass, not just widening the
        # suffix tuple above — python_scan_dirs only falls back to root when NO python dirs were
        # detected at all, so a polyglot repo (a Python backend + a Go microservice in its own
        # subdirectory) would have python_scan_dirs return only the Python dir, silently missing
        # the Go one even with ".go" added to the suffix filter.
        for d in go_scan_dirs(root, profile):
            for f in iter_files(d, (".go",)):
                if f in seen:
                    continue
                seen.add(f)
                nonprod = is_nonproduct_path(rel(root, f), profile.archive_segments, credential_scan=True)
                out.extend(self._scan_go(root, f, nonprod))
        return out

    def _scan(self, root: Path, f: Path, nonprod: bool) -> list[Finding]:
        out: list[Finding] = []
        text = strip_python_strings(read(f), filename=f)  # blank triple-quoted docstring/template content
        # The pragma is read off the same-length COMMENT-ONLY view of `text` - the SAME blanked
        # text the loop splits, so the two line lists agree by comment_view's tested invariant. (A
        # raw-line match would let a single-line string on the key's own line quoting the pragma
        # silence it, #424; a view of the RAW file desynced from `text` whenever a `\v`/`\f`
        # separator sat inside a docstring, because the strings blanker removes it - #996 round-2
        # M2.) strict=True keeps a broken invariant loud rather than silently misaligning every
        # line number after it.
        view_lines = comment_view(text, "python").splitlines()
        for i, (raw_line, view_line) in enumerate(zip(text.splitlines(), view_lines, strict=True), start=1):
            code = strip_python_line_comment(raw_line)  # drop a trailing/whole-line `#` comment
            if not code.strip():
                continue
            if _TEST_VAR_MARKER.search(code):
                continue
            if _PRAGMA.search(view_line):
                continue
            # Every match on the line, not just the first: a placeholder token earlier on
            # the line must not shield a real key literal appearing after it (each match is
            # judged independently against the token-level exclusion).
            for m in _PROVIDER_KEY.finditer(code):
                if _PLACEHOLDER_VALUE.search(m.group(0)):
                    continue
                out.append(self._finding(root, f, i, _provider_label(m.group(0)), nonprod))
        return out

    def _scan_go(self, root: Path, f: Path, nonprod: bool) -> list[Finding]:
        # Two parallel views of the same file, same split as the Python path: the marker/regex
        # checks run against the COMMENT-STRIPPED line (a marker word or a key format only
        # mentioned in a comment must not fire/suppress on that basis alone), while the pragma
        # check runs against the COMMENT-ONLY view of the line, since the pragma IS a comment by
        # definition: strip_go_comments would blank it, and a string quoting it must not count
        # (#424). Mirrors the Python path's view_line (pragma) vs code (marker/regex) split exactly.
        out: list[Finding] = []
        raw_text = read(f)
        stripped_text = strip_go_comments(raw_text)
        view_lines = comment_view(raw_text, "go").splitlines()  # same length: comments only (#424)
        stripped_lines = stripped_text.splitlines()
        # strict=True: strip_go_comments and comment_view guarantee an identical splitlines() count
        # (their own invariants, tested) — a mismatch here would mean that guarantee broke, and
        # silently truncating to the shorter list would misalign every line number after the break.
        for i, (view_line, code) in enumerate(zip(view_lines, stripped_lines, strict=True), start=1):
            if not code.strip():
                continue
            if _TEST_VAR_MARKER.search(code):
                continue
            if _GO_PRAGMA in view_line:
                continue
            for m in _PROVIDER_KEY.finditer(code):
                if _PLACEHOLDER_VALUE.search(m.group(0)):
                    continue
                out.append(self._finding(root, f, i, _provider_label(m.group(0)), nonprod))
        return out

    def _finding(self, root: Path, f: Path, line: int, provider: str, nonprod: bool = False) -> Finding:
        # DOWNGRADE, not drop. A test/fixture/example path is usually a deliberately
        # fake key, but "usually" is not "always" — a real key pasted into a fixture during
        # debugging is a live leak, and dropping the finding entirely means the report cannot
        # distinguish that case from "no key in this file at all". `medium` sits below the default
        # `--fail-on high` gate, so it still cannot produce an unfixable CI failure out of the box,
        # while staying visible to a human reader AND still gateable by a repo that opts into
        # `--fail-on medium` (one of the three choices the action's `fail-on` input, `action.yml`,
        # accepts — `low` is not, so a `low` downgrade here would have been un-gateable through the
        # action at ANY setting; decided explicitly on PR #583's review, not left as a default).
        severity: Severity = "medium" if nonprod else "high"
        message = (
            f"This line contains what looks like a real {provider} API key literal. "
            "Committing a provider key to source control exposes it in git history "
            "forever, to every developer with repository access, and it cannot be "
            "rotated without a code change and redeploy."
        )
        if nonprod:
            message += (
                " This file is under a test/fixture/example path, where keys are usually "
                "deliberately fake — but this one still matches a real provider key shape, so "
                "it is disclosed at reduced severity rather than dropped silently."
            )
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=(
                "Load the key from an environment variable or a secrets manager at "
                "runtime, never a literal in source. Rotate this key immediately if it "
                "was ever committed to a real repository — assume it is compromised."
            ),
            rule="hardcoded-llm-provider-key/known-provider-prefix",
            standards=list(_STANDARDS),
        )
