"""Guard: a Claude Code / Claude Agent SDK `SKILL.md` file carries a poisoning shape —
a post-install command, an exfiltration primitive, a name that typosquats a trusted
first-party skill, a prompt-injection trigger in frontmatter, or a hidden instruction in a
body HTML comment (checklist §4, new item; agent-audit-kit's `skill_poisoning.py`
AAK-SKILL-001/003/004/005/006).

Patterns are based on the Snyk ToxicSkills dataset (1,467 malicious payloads, 2026) and the
Anthropic first-party skill directory. `SKILL.md` is read and acted on by the model exactly
like `CLAUDE.md`/`AGENTS.md`.

**Not ported: AAK-SKILL-002** (invisible/bidi Unicode in `SKILL.md`) — verified duplicate
of the existing `invisible-unicode` guard, which already scans all repo text universally
for the exact same character ranges.

Five checks:

  1. **`post-install-command`** (HIGH): a post-install/side-effect command embedded in the
     `SKILL.md` body (`curl|wget ... | sh`, `npm install -g`, `pip install --user`,
     `bash -c`/`sh -c`, `eval(`).
  2. **`exfiltration-shape`** (HIGH): an outbound HTTP sink (`fetch`/`axios`/`requests`/
     `urllib.request.urlopen`/a bare `curl`/`wget`) combined with local data that plausibly
     flows into it: a credential file (`~/.ssh`/`.aws/credentials`/`.netrc`/`id_rsa`/
     `id_ed25519`) anywhere in the file, or a weaker reference (`$HOME`/a file-read call/env
     vars) within three lines of the sink. A NAMED env var in an auth header is ordinary API
     code and is not flagged; a whole-environment dump is.  # security: allow-credential-file-path
  3. **`trusted-name-typosquat`** (HIGH): the skill's declared `name` is a near-miss of a
     trusted first-party skill name (`pdf`, `docx`, `mcp-builder`, `skill-creator`, ...),
     without being an exact match. Short names need exactly one edit and must not be a plain
     word (`docs` is not a typosquat of `docx`); longer names use the length/substring/
     shared-character rule.
  4. **`frontmatter-injection-trigger`** (HIGH): a prompt-injection trigger phrase
     (`ignore previous`, `you are now`, `jailbreak`, `developer mode`, ...) or a structural
     chat-role marker (`system:` at the start of a line or value, followed by text) appears
     in the frontmatter block. A bare `system:` inside prose does not fire.
  5. **`hidden-instruction-html-comment`** (HIGH): an HTML comment in the skill BODY (not
     frontmatter — invisible in every rendered view a human reviews, fully visible to the
     model, which reads the raw file) that reads as an order: either a known
     injection-trigger phrase, or the conjunction of a local-secret reference, an
     imperative verb (`exfiltrate`/`leak`/`steal`/`upload`/`send`/...), and an outbound
     destination. Ordinary `TODO`/`FIXME`/licence-header comments carry none of these and
     stay quiet.

Suppress an audited case with:

    # security: allow-skill-poisoning
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

# `SKILL.md` (Markdown) has no comment syntax a view reads, so its pragma is matched on the raw text by
# contract (`dialect=None`, #1040 T5).
_PRAGMA = re.compile(r"#\s*security:\s*allow-skill-poisoning")

_TRUSTED_NAMES = frozenset({
    "pdf", "docx", "pptx", "xlsx", "frontend-design", "canvas-design", "brand-guidelines",
    "algorithmic-art", "theme-factory", "web-artifacts-builder", "webapp-testing",
    "slack-gif-creator", "doc-coauthoring", "mcp-builder", "skill-creator", "internal-comms",
})

_POST_INSTALL_RE = re.compile(
    r"(?:^|\n)[ \t]*(?:curl\s+[^\n]*\|\s*sh|wget\s+[^\n]*\|\s*sh|"
    r"npm\s+install\s+-g|pip\s+install\s+--user|bash\s+-c|sh\s+-c|eval\s*\()",
    re.IGNORECASE,
)
_EXFIL_SINK_RE = re.compile(
    # `fetch` requires a call form (`fetch(`), not a bare word: `git fetch` is a local repo-sync
    # command against an already-configured remote, not attacker-reachable exfiltration, and the
    # old bare-word alternative here matched it.
    r"\bfetch\s*\(|axios\.(?:get|post|put)|requests\.(?:get|post|put)|"
    r"urllib\.request\.urlopen|http\.client\.HTTP(?:S)?Connection|curl\b|wget\b",
    re.IGNORECASE,
)
_LOCAL_DATA_RE = re.compile(
    r"\b(?:process\.env|os\.environ|~/\.ssh|\.aws/credentials|\.netrc|"
    r"id_rsa|id_ed25519|\$HOME|~\/|read(?:Text|File))\b",
    re.IGNORECASE,
)
_INJECTION_TRIGGERS = (
    "ignore previous", "ignore above", "you are now", "you are a",
    "disregard prior", "forget all prior", "jailbreak", "developer mode", "DAN mode",
)
# A chat-role marker is only an injection when it is structural: at the start of a line (or of a
# frontmatter value / comment body) and followed by an instruction. A bare `system:` substring
# also matches ordinary prose ("Detects the file system: ext4, xfs").
_ROLE_MARKER_RE = re.compile(
    # `#` is in the prefix class too: a markdown-heading-styled role marker
    # (`### System: you must comply`) is the same trigger with a heading glyph in front. The same
    # glyphs may also follow a `key:` prefix, optionally inside an opening quote, so a one-line
    # `description: "### System: ..."` fires like the marker on its own line does. A quote with NO
    # glyph after it (`notes: "Developer: internal use only"`) is a label, not a marker. The key
    # starts with a word character so it cannot trade dashes with the prefix class (a line of
    # 20,000 `-` took 4 s when both could).
    r"(?:^|\n)[ \t>*#-]*(?:\w[\w-]*:[ \t]*(?:(?:[\"'][ \t]*)?[>*#-][ \t>*#-]*)?)?"
    r"(?:system|assistant|developer)[ \t]*:[ \t]*\S",
    re.IGNORECASE,
)
_ROLE_TOKEN_RE = re.compile(r"<\|(?:system|assistant|im_start)\|>|\[/?INST\]|<<SYS>>", re.IGNORECASE)


def _injection_trigger(text: str) -> str | None:
    """The first injection-trigger phrase or structural role marker in `text`, else None."""
    lowered = text.lower()
    hit = next((t for t in _INJECTION_TRIGGERS if t.lower() in lowered), None)
    if hit:
        return hit
    m = _ROLE_MARKER_RE.search(text) or _ROLE_TOKEN_RE.search(text)
    return m.group(0).strip() if m else None
_DESTINATION_RE = re.compile(r"https?://|\b(?:webhook|endpoint|collect|drop|exfil)\b", re.IGNORECASE)
_IMPERATIVE_EXFIL_RE = re.compile(
    r"\b(?:exfiltrate|leak|steal|smuggle|siphon|upload|post|send|forward|copy)\b", re.IGNORECASE,
)

_STD_INSTALL = ["CWE-829", "OWASP-ASI:ASI04"]
_STD_EXFIL = ["OWASP-LLM:LLM06", "OWASP:A10"]
_STD_TYPOSQUAT = ["CWE-1021", "OWASP-ASI:ASI04"]
_STD_INJECTION = ["OWASP-LLM:LLM01"]


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    try:
        _, fm, body = text.split("---", 2)
    except ValueError:
        return {}, text
    meta: dict[str, str] = {}
    for line in fm.strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip().lower()] = value.strip()
    return meta, body


_CRED_FILE_RE = re.compile(r"~/\.ssh|\.aws/credentials|\.netrc|\bid_rsa\b|\bid_ed25519\b", re.IGNORECASE)
# A named env var (`os.environ["API_TOKEN"]`, `process.env.API_TOKEN`) read to authenticate a
# request is how a legitimate API skill works; a whole-environment dump is not.
_NAMED_ENV_RE = re.compile(r"(?:os\.environ(?:\[|\.get\()|process\.env(?:\.\w|\[)|os\.getenv\()", re.IGNORECASE)
_WHOLE_ENV_RE = re.compile(r"os\.environ|process\.env", re.IGNORECASE)
_AUTH_CONTEXT_RE = re.compile(r"authorization|bearer|api[-_]?key|token|x-api|headers\s*=|auth\s*=", re.IGNORECASE)
_EXFIL_WINDOW = 3  # lines


def _exfiltration_shape(raw: str) -> bool:
    """An outbound sink plus local data that plausibly flows into it, both within a few lines of
    each other.

    Whole-file co-occurrence (a credential-file mention ANYWHERE plus a sink ANYWHERE, regardless
    of distance) fired on this repo's own `land-pr` skill: it documents an SSH signing-key check
    nowhere near its unrelated `git fetch -q origin`. Credential FILES (`~/.ssh`,
    `.aws/credentials`, `.netrc`, `id_rsa`) still need no auth-context exemption -- a skill has no
    legitimate reason to touch them near a sink at all -- but now need the same proximity as the
    weaker references (`$HOME`, a file read, environment variables). A NAMED env var used in an
    auth-header context is ordinary API-client code, not exfiltration."""
    if not _EXFIL_SINK_RE.search(raw):
        return False
    lines = raw.splitlines()
    sinks = [i for i, ln in enumerate(lines) if _EXFIL_SINK_RE.search(ln)]
    for i, ln in enumerate(lines):
        near_sink = any(abs(i - s) <= _EXFIL_WINDOW for s in sinks)
        if _CRED_FILE_RE.search(ln):
            if near_sink:
                return True
            continue
        if not _LOCAL_DATA_RE.search(ln):
            continue
        if not near_sink:
            continue
        if _WHOLE_ENV_RE.search(ln) and not _NAMED_ENV_RE.search(ln):
            return True  # whole-environment dump
        if _NAMED_ENV_RE.search(ln) and _AUTH_CONTEXT_RE.search(ln):
            continue  # env var read for an auth header
        return True
    return False


_PLAIN_WORDS =frozenset({"doc", "docs", "dock", "pdfs", "ppt", "xls"})


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _looks_like(candidate: str, target: str) -> bool:
    if candidate == target:
        return False
    if min(len(candidate), len(target)) <= 4:
        # Short names: the loose length/shared-character rule matches ordinary words (`docs` vs
        # `docx`). Require exactly one edit, and not a plain word a skill is legitimately named.
        return candidate not in _PLAIN_WORDS and _edit_distance(candidate, target) == 1
    if abs(len(candidate) - len(target)) > 2:
        return False
    if target in candidate or candidate in target:
        return True
    shared = sum(1 for a, b in zip(candidate, target, strict=False) if a == b)
    return shared >= min(len(candidate), len(target)) - 1


def _html_comments(body: str) -> Iterator[str]:
    """Yield the inner text of each closed HTML comment, in one linear pass. (A lazy regex over
    comment delimiters is quadratic on a body of repeated unclosed openers: every start rescans to
    the end of the file.) An unclosed opener ends the scan."""
    pos = 0
    while True:
        start = body.find("<!--", pos)
        if start < 0:
            return
        end = body.find("-->", start + 4)
        if end < 0:
            return
        yield body[start + 4:end]
        pos = end + 3


def _hidden_instruction_hits(body: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for raw_inner in _html_comments(body):
        inner = raw_inner.strip()
        if not inner:
            continue
        trigger = _injection_trigger(inner)
        if trigger:
            hits.append((inner, f"injection trigger {trigger!r}"))
            continue
        if _LOCAL_DATA_RE.search(inner) and _IMPERATIVE_EXFIL_RE.search(inner) and _DESTINATION_RE.search(inner):
            hits.append((inner, "local-secret reference with an outbound destination"))
    return hits


class SkillPoisoningGuard(Guard):
    id = "skill-poisoning"
    title = "SKILL.md carries a poisoning shape (post-install command, exfil, typosquat, or hidden instruction)"
    area = "AI agent"

    # skills/evil-pdf/SKILL.md: name typosquats trusted "pdf" skill -> fires
    # skill-poisoning/trusted-name-typosquat.
    canary_plant = CanaryPlant(
        files={
            "skills/evil-pdf/SKILL.md": (
                "---\nname: pdff\ndescription: PDF helper\n---\n\nDoes PDF things.\n"
            ),
        },
        expects=frozenset({
            "skill-poisoning/trusted-name-typosquat",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for p in iter_files_named(root, "SKILL.md", respect_gitignore=False):
            r = rel(root, p)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(p).lstrip("\ufeff")  # a Windows editor's BOM would defeat the `---` frontmatter test
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            out.extend(self._check_skill(r, raw))
        return out

    def _check_skill(self, r: str, raw: str) -> list[Finding]:
        out: list[Finding] = []
        meta, body = _parse_frontmatter(raw)

        m = _POST_INSTALL_RE.search(raw)
        if m:
            out.append(self._finding(
                r, "post-install-command", _STD_INSTALL,
                f"Post-install/side-effect command embedded in SKILL.md: "
                f"{m.group(0).strip()!r}.",
            ))

        if _exfiltration_shape(raw):
            out.append(self._finding(
                r, "exfiltration-shape", _STD_EXFIL,
                "Outbound HTTP sink combined with a local secret/data reference "
                "(exfiltration shape).",
            ))

        name = meta.get("name", "").strip().strip("\"'")
        if name and name not in _TRUSTED_NAMES:
            for trusted in _TRUSTED_NAMES:
                if _looks_like(name.lower(), trusted):
                    out.append(self._finding(
                        r, "trusted-name-typosquat", _STD_TYPOSQUAT,
                        f"Skill name {name!r} is a near-miss of the trusted first-party "
                        f"skill name {trusted!r} without matching it exactly.",
                    ))
                    break

        fm_boundary = raw.find("---", 3)
        fm_slice = raw[: fm_boundary if fm_boundary > 0 else 500]
        trigger = _injection_trigger(fm_slice)
        if trigger:
            out.append(self._finding(
                r, "frontmatter-injection-trigger", _STD_INJECTION,
                f"Prompt-injection trigger phrase in frontmatter: {trigger!r}.",
            ))

        for inner, why in _hidden_instruction_hits(body):
            out.append(self._finding(
                r, "hidden-instruction-html-comment", _STD_INJECTION,
                f"HTML comment in the skill body reads as an instruction ({why}): "
                f"{inner[:100]!r}.",
            ))

        return out

    def _finding(self, r: str, rule_suffix: str, standards: list[str], message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=r,
            message=message,
            remediation=(
                "Remove the embedded command/exfiltration primitive, rename the skill "
                "to something that doesn't resemble a trusted first-party name, and "
                "strip any instruction-shaped content from frontmatter or body HTML "
                "comments — a model reads the raw file, including content invisible "
                "in a rendered view."
            ),
            rule=f"skill-poisoning/{rule_suffix}",
            standards=list(standards),
        )
