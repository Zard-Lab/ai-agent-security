"""Drift gate: a suppress pragma is honoured only as a COMMENT (issue #424, the pragma-anchoring rider).

Nearly every guard honours `# security: allow-<id>` by a bare substring / regex match over the raw
file text, so the phrase inside a docstring or string literal — the exact string the guard's own
remediation text tells users to write — silences a real finding with no trace. Measured on the
canary, 199 of 421 guards went silent that way (the RCA at `.claude/issues/issue-424.md`). This
module turns that measurement into a permanent, both-directions gate over `ALL_GUARDS` on the
real canary repo, in the `_AREA_LEGACY` / `_LEGACY_EXPECTED` drained-and-pinned pattern:

* **Direction 1 — a pragma inside string content must not suppress.** Each guard's plant file(s)
  get a STRING LITERAL (never a comment) quoting the guard's own pragma phrase(s). A guard whose
  findings survive is anchored. The ones that go silent today are pinned in `_LEGACY_UNANCHORED`,
  which each adopting sub-PR drains (E1 Python, E2 hash/YAML, E3 SQL, E4 JS/HCL/Go/PHP/Java/Ruby):
  a fixed guard left in the set fails ("drain it"), and a guard that regresses — or a NEW guard
  added with a raw match — fails ("anchor it through `pragma_present`"). The set is the progress
  meter; it must reach empty and then stay empty.
* **Direction 2 — a pragma in a REAL comment must keep exactly the reach it has today.** The
  same plant files get a real comment carrying the phrase at the top of the file. A guard that
  goes silent on that has whole-file (or repo-wide) pragma scope — #622 established that scope is
  deliberate UX — and is pinned in `_FILE_SCOPED_PRAGMA`; every other guard must still fire, so
  adopting the same-length view can neither void a user's opt-out (CLAUDE.md rule 4) nor widen a
  per-line pragma to the whole file. The two guards whose scope is a unit SMALLER than the file
  that the first line falls inside (a YAML document, a handler function) are pinned with their
  reason in `_PARTIAL_TOP_COMMENT_SCOPE`. A guard's own line-scoped opt-out stays covered by its
  own test file; this gate pins the SCOPE, which is the thing an adoption edit can silently move.
* **Directions 3 and 4 — the same two, AT the finding's anchor (#1040).** Directions 1 and 2 place
  the phrase at the top or end of the file, which a guard that checks only the flagged line, its
  SQL statement or its CloudFormation resource never reads, so they passed whatever its pragma
  handling. Direction 3 puts the string on each canary finding's own line (or inside its statement
  or resource) and pins what goes silent in `_LEGACY_ANCHOR_UNANCHORED`, the #1040 meter; direction
  4 puts a real comment there and requires it to suppress, so an adoption that maps the view's lines
  wrong voids no opt-out unseen. Their limits are pinned with the reason (`_ANCHOR_UNMEASURABLE`,
  `_ANCHOR_COMMENT_LEAVES`, and the whole-file guards the file-level tests measure instead in
  `_ANCHOR_*_FILE_LEVEL_ONLY`), and a static complement reads every guard module's AST and accounts
  for each pragma read that does not trace to a view, site by site, which covers the plant types no
  placement reaches and the sites a canary plant never exercises.

Every mutant is measured against a CONTROL carrying a neutral phrase in the identical shape (at the
anchor: the same phrase with its `security:` marker broken), and `applies()` is re-checked on the
mutated repo (a direct `run()` after a mutation that flipped the stack profile would fake a result),
so a broken mutation shape fails loudly rather than reading as "anchored". Guards whose plant type
has no safe injection shape are SKIPPED with the reason named, never silently passed.
"""
from __future__ import annotations

import ast
import contextlib
import functools
import inspect
import io
import re
import sys
import tokenize
import types
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import pytest

import agentsec.detect as detect_module
from agentsec import walk
from agentsec.canary import report_from_audit, write_canary_repo
from agentsec.detect import StackProfile, detect
from agentsec.guards.base import Guard, comment_dialect_for, comment_view, derived_state_run
from agentsec.registry import ALL_GUARDS
from tests.conftest import SharedAudit

# --- the two pinned sets -----------------------------------------------------------------------
# Guards a STRING LITERAL quoting their own pragma silences on the canary today. Measured on the
# tree this file first landed on; drained by the adopting sub-PRs of #424 and never grown.
# E1-E4 drained the original 217 -> 0. The 21 that landed on main after this file's first
# measurement (19 new guards, python-supply-chain once its plant moved onto the guard, and
# mcp-tool-description-injection's post-E1 raw sites from #966/#992) were pinned at landing and
# drained by #1000 (E6). The set is now empty and pinned so: a guard added with a raw match fails.
_LEGACY_UNANCHORED: frozenset[str] = frozenset()

# Guards a top-of-file COMMENT pragma silences on the canary: whole-file or repo-wide pragma scope.
# This is a SCOPE declaration, not a defect list — a new guard with whole-file scope is added here
# on purpose, and moving a guard in or out is a #622-class decision, never a side effect.
_FILE_SCOPED_PRAGMA: frozenset[str] = frozenset({
    "acp-vulnerabilities", "agent-iam-control-plane-exposure", "agent-iam-killchain-combination",
    "agent-iam-tool-resource-unscoped", "agent-loop-circuit-breaker", "agent-memory-retention", "agent-memory-security",
    "agent-memory-user-scope", "agent-resume-unverified-trigger", "agent-tool-audit-log",
    "agent-tool-overpermission", "agent-tool-url-fetch-ssrf", "ai-docker", "ansi-escape-llm-output",
    "ansible-debug-echoes-auth-variable", "ansible-host-key-checking-disabled",
    "ansible-ignore-errors-on-security-task", "ansible-no-log-disabled-on-secret-task",
    "ansible-setuid-binary-creation", "ansible-sudo-nopasswd", "ansible-unsafe-lookups-enabled",
    "async-blocking-io", "auth-rate-limit-absent", "auto-updates-absent",
    "autostart-persistence-mechanism", "browser-credential-store-access", "bulk-env-var-harvesting",
    "cfn-vpc-flow-log-missing", "ci-image-build-no-sbom-provenance", "ci-secret-env-unscoped",
    "cleartext-secret-storage", "client-side-auth-decision", "client-side-secret-literal",
    "cloud-metadata-endpoint-literal", "compose-connection-string-credential",
    "compose-credential-env-literal", "compose-db-port-exposed", "compose-dns-bypass",
    "compose-image-digest-missing", "compose-logging-disabled", "compose-no-network-segmentation",
    "compose-no-new-privileges", "compose-resource-limits-absent", "compose-sensitive-host-mount",
    "compose-shared-mount-propagation", "compose-tmpfs-insecure-options", "compose-user-directive-missing",
    "compose-writable-host-root-mount", "compose-writable-root-filesystem", "content-type-magic-bytes",
    "credential-file-path-reference", "cron-systemd-persistence-write", "ctypes-load-downloaded-library",
    "datastore-auth-absent", "db-role-privilege-excessive",
    "debug-route-exposed", "default-service-credential", "definer-dynamic-sql",
    "destructive-filesystem-command", "dns-exfiltration-pattern", "docker-add-misuse",
    "docker-expose-ssh", "docker-latest-base-tag", "docker-nonroot-user", "docker-privileged-flags",
    "docker-run-sudo", "docker-socket-access",
    "dockerfile-credential-in-instruction", "dockerfile-run-isolation-weakening",
    "dockerfile-workdir-sensitive-path",
    "dom-xss-sinks", "download-execute-chain",
    "electron-security-misconfig",
    "env-secret-console-log", "env-secret-in-prompt", "env-secret-logged",
    "environ-dump-to-network", "error-info-leak",
    "fail-safe-exception", "forwarded-header-blind-trust", "git-in-docker", "guardrail-architecture",
    "header-injection", "hidden-executable-dotfile", "homoglyph-source-chars",
    "iam-escalation-action-no-condition", "iam-notaction-with-allow", "iam-resource-scopable-wildcard",
    "iam-service-wildcard", "incomplete-url-scheme-check", "input-delimiters", "insecure-tempfile-mktemp",
    "invisible-unicode",
    "js-buffer-noassert", "js-client-side-open-redirect", "js-code-injection", "js-command-injection",
    "js-cors-wildcard", "js-insecure-download-sensitive-file", "js-loop-bound-injection",
    "js-path-traversal", "js-prototype-pollution", "js-sql-injection", "js-ssrf",
    "js-system-prompt-injection", "jsx-href-scheme", "jwt-claims-validated", "jwt-key-source-allowlist",
    "k8s-allow-privilege-escalation", "k8s-automount-serviceaccount-token", "k8s-default-namespace",
    "k8s-docker-sock-mount", "k8s-host-namespace-sharing", "k8s-hostpath-writable-mount",
    "k8s-privileged-capabilities", "k8s-privileged-container", "k8s-rbac-anonymous-binding",
    "k8s-rbac-cluster-admin-binding", "k8s-rbac-wildcard-rule", "k8s-readonly-root-filesystem",
    "k8s-resource-limits-absent", "k8s-run-as-non-root", "k8s-seccomp-apparmor-unconfined",
    "k8s-unmasked-proc-mount", "k8s-unsafe-sysctl", "keylogging-pattern",
    "langchain-prompt-template-injection",
    "langchain-serialization", "langchain-unsafe-chain", "llm-input-size-cap",
    "llm-json-output-unvalidated", "llm-output-secrets-unscanned", "llm-query-engine-execution",
    "llm-rate-limit-absent", "llm-response-logged", "llm-tool-result-leak", "log-injection",
    "markdown-render-xss", "mass-assignment", "matview-exposed", "mcp-env-placeholder-exfil",
    "mcp-hardcoded-credential", "mcp-marketplace-fetch-stdio-spawn", "mcp-oauth-scope-creep",
    "mcp-overprivileged-scope", "mcp-raw-execution-tool-name", "mcp-routing-desync", "mcp-sampling-no-consent",
    "mcp-session-id-security", "mcp-ssrf-unvalidated-destination", "mcp-tool-description-injection",
    "mcp-tool-env-inheritance", "mcp-tool-path-traversal", "mcp-tool-unverified", "mcp-toolgate-asymmetry",
    "mcp-tools-list-unbounded", "mcp-transport-dns-rebinding", "mcp-transport-no-auth",
    "mcp-unsafe-auth-url-launch",
    "multi-agent-prompt-origin", "next-api-route-auth-missing", "next-public-client-secret",
    "next-server-action-no-auth", "no-cache-on-sensitive", "node-db-driver-hardcoded-password", "nosql-injection-js", "npm-lifecycle-script-source-sinks", "path-prefix-authz-bypass",
    "payments-user-scope", "pg-anon-grant", "pg-default-privileges-public", "pg-extension-in-public",
    "pg-foreign-table-exposed", "pg-function-immutable-reads-session", "pg-function-leakproof",
    "pg-function-search-path", "pg-graphql-table-exposed", "pg-rls-no-policy", "pg-rls-not-forced",
    "pg-role-bypassrls", "pg-security-definer-view", "pgmq-queue-exposed-in-api", "pii-llm-roundtrip",
    "plugin-security", "postmessage-origin", "prompt-string-interp", "pydantic-model-construct",
    "rag-isolation", "rag-no-instruction-filter", "rag-scoped-retrieval", "rag-trust-boundary",
    "rate-limit-no-persistent-store", "rate-limit-no-user-key", "react-native-insecure-token-storage",
    "redis-glob-pattern-injection", "refresh-token-plaintext", "regex-html-sanitizer",
    "request-body-size-unbounded", "request-model-extra-forbid", "reverse-shell-pattern",
    "rls-auth-uid-unwrapped",
    "rls-fkey-to-auth-non-primary", "rls-multiple-permissive-policies", "rls-partition-inherits-bypass",
    "rls-realtime-published-no-rls", "rls-restrictive-only", "secret-in-url-query", "security-headers",
    "sensitive-columns", "session-no-csrf", "setup-network-call", "slopsquatting", "sql-race-check-then-insert",
    "ssrf-ipv6-bypass", "staticfiles-broad-mount", "storage-no-rls", "string-format-injection",
    "supabase-filter-injection", "supabase-storage-public", "system-prompt-exposure", "system-prompt-leak",
    "target-blank-noopener", "tls-verify-disabled", "token-in-localstorage", "tool-callback-enforcement",
    "tool-chaining-exfil", "trusted-host-absent", "truthy-ownership-check", "unawaited-async-truthy",
    "upload-no-size-limit", "upstream-response-unvalidated", "vite-client-secret", "vite-sourcemap-prod",
    "webhook-signature-not-verified", "websocket-no-auth", "websocket-origin", "xpath-injection",
    "zip-bomb", "zip-slip"
}) | frozenset({
    # The #1000 (E6) guards: whole-file scope as measured when they were pinned at E0's landing.
    # E6 anchored them and kept it (rule 4); python-supply-chain is partial, pinned below.
    "agent-headless-trust-surface", "approval-parser-shell-desync", "argv-toctou", "crewai-rce-chain",
    "mcp-apps-ui-isolation", "mcp-noauth-default", "mcp-oauth-flow-hardening", "mcp-stateless-migration",
    "mcp-stdio-no-sanitizer", "mcp-tasks-lifecycle", "mcp-transport-session-unauth",
    "mcp-tunnel-config-security", "mcp-twin-route-auth-asymmetry", "policy-truncation",
    "sandbox-denylist-bypass", "skill-untrusted-exec-path", "ssrf-bracketed-ipv6-bypass",
    "ssrf-dns-rebind-toctou", "ssrf-redirect-bypass",
})

# Guards a top-of-file comment reaches SOME of, because their pragma scope is a unit smaller than
# the file that its first line happens to fall inside — pinned WITH the reason, so a partial
# result is a declared scope and never an unexplained number.
_PARTIAL_TOP_COMMENT_SCOPE: dict[str, str] = {
    "go-template-html-escaping": "file-wide for the import signal, per-handler function for the escape one",
    "k8s-rbac-dangerous-verb": "per YAML document (`---`); the top-of-file comment sits in the first one",
    "python-supply-chain": "file-wide for the cooldown and extra-index pragmas; the pinning rules have none",
    "obfuscated-payload-execution": (
        "file-wide for the JS decoded-eval rule (added 2026-10-07, checked via whole-file "
        "pragma_present); the Python decode-exec-chain/hex-blob rules stay window/line-scoped"
    ),
}

# A phrase no guard defines, in the identical shape, so the CONTROL proves the shape itself is inert.
_NEUTRAL = "allow-nothing-here-zz"
_PREFIXES = ("#", "//", "--")
_CONSTANT = re.compile(r"_?[A-Z][A-Z0-9_]*")
# Not a token cut short by a template slot: `allow-old-{pkg}` (`dependency-version-floor`) names no
# phrase a plant could carry, and `allow-old-` would be planted as one. The static tests cover it.
_TOKEN = re.compile(r"allow-[\w-]+(?![\w{-])")


def _pragma_tokens(guard: Guard) -> tuple[str, ...]:
    """Every `allow-…` token in the guard module's constant `str`/`re.Pattern` values that mention
    `security:` — its `_PRAGMA*` constants first and foremost, but also the handful of guards that
    keep the phrase under another name (`_ALLOW`, a remediation template)."""
    mod = sys.modules[type(guard).__module__]
    tokens: set[str] = set()
    for name, value in vars(mod).items():
        if not _CONSTANT.fullmatch(name):
            continue
        text = value.pattern if isinstance(value, re.Pattern) else value if isinstance(value, str) else None
        if text is not None and "security:" in text:
            tokens.update(_TOKEN.findall(text))
    return tuple(sorted(tokens))


def _body(tokens: tuple[str, ...]) -> str:
    """The phrase every pragma shape in the tree matches: each token bare (`security: allow-x`, the
    plain-`str` and unprefixed-regex guards) and then under every comment prefix (`#`, `//`, `--`),
    so one body satisfies a `#\\s*security:` regex inside a `//` comment and vice versa."""
    bare = " ; ".join(f"security: {t}" for t in tokens)
    prefixed = " ; ".join(f"{p} security: {t}" for t in tokens for p in _PREFIXES)
    return f"{bare} ; {prefixed}"


def _after_opener(content: str, line: str) -> str:
    """Insert `line` at the top, or after a first line that must stay first (a shebang, `<?php`)."""
    first, nl, rest = content.partition("\n")
    if first.startswith(("#!", "<?php")):
        return first + nl + line + rest
    return line + content


def _append(content: str, line: str) -> str:
    return content + ("" if not content or content.endswith("\n") else "\n") + line


_Mutator = Callable[[str, str], str]  # (content, body) -> mutated content


def _string_shape(path: str) -> _Mutator | None:
    """A STRING LITERAL carrying `body`, in the file's own grammar, placed where it is valid."""
    suffix, name = Path(path).suffix.lower(), Path(path).name.lower()
    if suffix == ".py":  # a triple-quoted statement AND a single-line string: both string forms
        return lambda c, b: _append(c, f'"""Opt out: add {b} to the line."""\n__agentsec_doc = "Opt out: add {b}"\n')
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return lambda c, b: _after_opener(c, f'const __agentsecDoc = "Opt out: add {b} to the line";\n')
    if suffix == ".sql":
        return lambda c, b: f"SELECT 'Opt out: add {b} to the line';\n" + c
    if suffix in {".yaml", ".yml"}:
        return lambda c, b: f'__agentsec_doc: "Opt out: add {b} to the line"\n' + c
    if suffix == ".toml":
        return lambda c, b: f'__agentsec_doc = "Opt out: add {b} to the line"\n' + c
    if name.startswith(".env") or suffix == ".env" or suffix == ".sh":
        return lambda c, b: _after_opener(c, f'__AGENTSEC_DOC="Opt out: add {b} to the line"\n')
    if suffix == ".tf":
        return lambda c, b: f'variable "__agentsec_doc" {{ default = "Opt out: add {b} to the line" }}\n' + c
    if suffix == ".rb":
        return lambda c, b: _after_opener(c, f'__agentsec_doc = "Opt out: add {b} to the line"\n')
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return lambda c, b: _append(c, f'ENV __AGENTSEC_DOC="Opt out: add {b} to the line"\n')
    if suffix == ".go":
        return lambda c, b: _append(c, f'var __agentsecDoc = "Opt out: add {b} to the line"\n')
    if suffix == ".java":
        return lambda c, b: _append(c, f'class __AgentsecDoc {{ String d = "Opt out: add {b} to the line"; }}\n')
    if suffix == ".php":
        return lambda c, b: _append(c, f'$__agentsecDoc = "Opt out: add {b} to the line";\n')
    return None


def _comment_shape(path: str) -> _Mutator | None:
    """A REAL COMMENT carrying `body` at the top of the file, in the file's own grammar."""
    suffix = Path(path).suffix.lower()
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".php"}:
        return lambda c, b: _after_opener(c, f"// {b}\n")
    if suffix == ".sql":
        return lambda c, b: f"-- {b}\n" + c
    if _string_shape(path) is not None:  # every remaining shape is a `#` grammar
        return lambda c, b: _after_opener(c, f"# {b}\n")
    return None


def _location_anchor(location: str) -> tuple[str, int | None]:
    """`path:line[:col]` -> `(path, line)`, forward-slashed (a Windows `rel()` gives backslashes);
    `line` is None for a finding anchored on a whole file or resource."""
    parts = location.replace("\\", "/").split(":")
    numbers: list[int] = []
    while len(parts) > 1 and parts[-1].isdigit():
        numbers.insert(0, int(parts.pop()))
    return ":".join(parts), (numbers[0] if numbers else None)


def _location_file(location: str) -> str:
    return _location_anchor(location)[0]


@dataclass(frozen=True)
class _Canary:
    root: Path
    profile: StackProfile
    files_by_guard: dict[str, tuple[str, ...]]  # guard id -> plant files its findings anchor in
    # guard id -> plant file -> the 1-based lines its findings anchor on (empty: whole file/resource)
    anchors_by_guard: dict[str, dict[str, frozenset[int]]]
    # detect()'s reads of UNMUTATED plant files, filled as they happen: path as detect() passed it -> text
    reads: dict[Path, str] = field(default_factory=dict)


@pytest.fixture(scope="module", autouse=True)
def _audit_run_scopes() -> Iterator[None]:
    """Run every probe inside the per-run caches `audit()` itself runs its guards in.

    `audit()` wraps guards in `walk.walk_run()` + `derived_state_run()` (`audit.py::_with_run_caches`);
    the probes call `detect()` and `guard.run()` directly, so without this each of those calls
    re-walked the canary and re-derived the stripped views of every file it read. Running inside the same
    scopes is more faithful to production, not less, and cannot serve a stale answer to a mutant:
    `walk_run` memoises the file LIST only, and no mutation shape adds or removes a file or touches
    a `.gitignore`; the `derived_state_run` tables are keyed by file CONTENT, so a mutated file can
    never hit an entry computed for the original. Module-scoped, so pytest closes both scopes at
    this module's boundary (under xdist too) and no other module's tests ever run inside them."""
    with walk.walk_run(), derived_state_run():
        yield


@pytest.fixture(scope="session")
def canary(canary_audit: SharedAudit, tmp_path_factory: pytest.TempPathFactory) -> _Canary:
    """This module's OWN canary tree (the probes mutate it; nothing else ever reads it), with the
    finding anchors taken from the session's one shared canary audit (conftest), which is an audit
    of a byte-identical `write_canary_repo` tree. SESSION-scoped so a worker that leaves this module
    and comes back (xdist worksteal) keeps it instead of rebuilding it: `_written` restores every
    file it touches, so the tree is the pristine canary between probes. Being session-scoped it is
    built OUTSIDE the module's `_audit_run_scopes` (which only the probes need), so its one
    `detect(root)` runs uncached; the audit it reads opened its own run scopes."""
    root = write_canary_repo(tmp_path_factory.mktemp("i424-canary"))
    result = canary_audit.load()
    # Rule 3: a guard the shared audit lost has no anchor, so its probes would SKIP ("no canary
    # finding to mutate") rather than fail. `test_canary_every_guard_alive` catches that only when
    # it runs in the same session; this makes the gate fail on its own.
    dead = report_from_audit(result).dead
    assert not dead, f"the canary audit the probes anchor on lost these guards' plants: {dead}"
    anchors: dict[str, dict[str, set[int]]] = {}
    for finding in result.findings:
        path, line = _location_anchor(finding.location)
        # A shared audit ran on ANOTHER root: an absolute or escaping anchor would point the probes
        # at that tree, so it fails here rather than measuring the wrong file. ("" is a repo-level
        # finding, e.g. compounding-risk, which no placement shape matches, exactly as before.)
        assert not Path(path).is_absolute() and ".." not in Path(path).parts, finding.location
        lines = anchors.setdefault(finding.check_id, {}).setdefault(path, set())
        if line is not None:
            lines.add(line)
    return _Canary(
        root,
        detect(root),
        {gid: tuple(sorted(by_file)) for gid, by_file in anchors.items()},
        {gid: {p: frozenset(ls) for p, ls in by_file.items()} for gid, by_file in anchors.items()},
    )


_Kind = Literal["string", "comment"]


@contextlib.contextmanager
def _written(canary: _Canary, mutated: dict[str, str]) -> Iterator[None]:
    """The `mutated` plant files (path -> new content) written in place, every original restored on
    exit. The only writer of the canary in this module, which is what keeps `_detect` exact."""
    originals = {p: (canary.root / p).read_text(encoding="utf-8") for p in mutated}
    try:
        for p, content in mutated.items():
            (canary.root / p).write_text(content, encoding="utf-8")
        yield
    finally:
        for p, content in originals.items():
            (canary.root / p).write_text(content, encoding="utf-8")


def _detect(canary: _Canary, mutated: dict[str, str]) -> StackProfile:
    """`detect()` on the canary while `mutated` is written, with every OTHER file's read served
    from its unmutated text instead of the disk.

    Reading the ~270 files `detect()` reads was ~90% of each probe's cost (0.38s of a 0.43s call on
    the Windows CI runner), and every probe re-read the same unchanged files twice. Exact, not an
    approximation: `_written` is the only writer and restores every original, so an unmutated file
    holds the text cached for it, and a mutated file is never served from the cache, it is read
    from disk like any other run. A read `detect()` makes some other way than `_read` goes to the
    disk too, so it can only lose speed, never return a stale profile.
    `test_the_detect_read_cache_never_serves_a_mutated_file` pins the mutated-file half."""
    root = canary.root.resolve()  # detect() walks the resolved root, so its paths are under it
    dirty = {root / p for p in mutated}
    disk = detect_module._read

    def read(path: Path) -> str:
        if path in dirty:
            return disk(path)
        if path not in canary.reads:
            canary.reads[path] = disk(path)
        return canary.reads[path]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(detect_module, "_read", read)
        return detect(canary.root)


def _count(canary: _Canary, guard: Guard, mutated: dict[str, str], what: str) -> int:
    """The guard's findings in the `mutated` plant files (path -> new content) with those contents
    written in place, every original restored afterwards. `applies()` is re-checked on the mutant:
    a direct `run()` after a mutation that flipped the stack profile would fake a result."""
    with _written(canary, mutated):
        profile = _detect(canary, mutated)
        if not guard.applies(profile):
            pytest.fail(f"{guard.id}: the {what} mutation flipped the stack profile; applies() is False")
        return sum(1 for f in guard.run(canary.root, profile) if _location_file(f.location) in mutated)


def _plan(canary: _Canary, guard: Guard, kind: _Kind) -> tuple[tuple[str, ...], tuple[str, ...]] | str:
    """`(pragma tokens, mutable plant files)` for the guard under the `kind` mutation, or the
    reason it cannot be measured. Only files with an injection shape count, so a guard whose
    findings span a file with none is measured on the files that have one."""
    tokens = _pragma_tokens(guard)
    if not tokens:
        return "declares no suppress pragma"
    files = canary.files_by_guard.get(guard.id, ())
    if not files:
        return "no canary finding to mutate (CANARY_EXEMPT)"
    shape = _string_shape if kind == "string" else _comment_shape
    mutable = tuple(f for f in files if shape(f) is not None)
    if not mutable:
        return f"no {kind} injection shape for {sorted({Path(f).suffix or Path(f).name for f in files})}"
    return tokens, mutable


def _probe(canary: _Canary, guard: Guard, kind: _Kind) -> tuple[int, int] | str:
    """`(control, probe)` finding counts for the guard under the `kind` mutation of its plant
    files (see `_plan`), or the reason it cannot be measured. The neutral-phrase CONTROL must
    fire, and `applies()` is re-checked on every mutant: a mutation that breaks the plant or the
    stack profile is a harness bug and fails, never a silent "anchored"."""
    planned = _plan(canary, guard, kind)
    if isinstance(planned, str):
        return planned
    tokens, mutable = planned
    shape = _string_shape if kind == "string" else _comment_shape

    def run(body: str) -> int:
        mutated: dict[str, str] = {}
        for p in mutable:
            mutate = shape(p)
            assert mutate is not None
            mutated[p] = mutate((canary.root / p).read_text(encoding="utf-8"), body)
        return _count(canary, guard, mutated, kind)

    control = run(_body((_NEUTRAL,)))
    if control == 0:
        pytest.fail(
            f"{guard.id}: the {kind} mutation shape broke its plant ({mutable}) — the control with a "
            "neutral phrase no longer fires, so this gate cannot measure it; fix the shape in this file"
        )
    return control, run(_body(tokens))


_GUARDS = sorted(ALL_GUARDS, key=lambda g: g.id)
_IDS = [g.id for g in _GUARDS]


@pytest.mark.slow
@pytest.mark.parametrize("guard", _GUARDS, ids=_IDS)
def test_a_pragma_inside_a_string_literal_does_not_suppress(guard: Guard, canary: _Canary) -> None:
    measured = _probe(canary, guard, "string")
    if isinstance(measured, str):
        pytest.skip(f"{guard.id}: {measured}")
    control, probe = measured
    unanchored = probe < control
    if guard.id in _LEGACY_UNANCHORED:
        assert unanchored, (
            f"{guard.id} is now anchored ({probe}/{control} findings survive a string-literal pragma): "
            "drain it from _LEGACY_UNANCHORED"
        )
    else:
        assert not unanchored, (
            f"{guard.id}: a pragma quoted inside a STRING LITERAL silenced {control - probe} of {control} "
            "findings — route the check through `pragma_present(...)` (guards/base.py) so only a real "
            "comment counts; do not add the guard to _LEGACY_UNANCHORED"
        )


@pytest.mark.slow
@pytest.mark.parametrize("guard", _GUARDS, ids=_IDS)
def test_a_pragma_in_a_real_comment_keeps_its_declared_scope(guard: Guard, canary: _Canary) -> None:
    measured = _probe(canary, guard, "comment")
    if isinstance(measured, str):
        pytest.skip(f"{guard.id}: {measured}")
    control, probe = measured
    assert probe <= control, f"{guard.id}: a pragma comment ADDED findings ({control} -> {probe})"
    if guard.id in _FILE_SCOPED_PRAGMA:
        assert probe == 0, (
            f"{guard.id} declares whole-file pragma scope but {probe}/{control} findings survived a "
            "top-of-file comment pragma — the opt-out stopped working (rule 4), or the scope moved: "
            "if the move is deliberate (#622), remove it from _FILE_SCOPED_PRAGMA in the same PR"
        )
    elif guard.id in _PARTIAL_TOP_COMMENT_SCOPE:
        assert 0 < probe < control, (
            f"{guard.id} is pinned as partial scope ({_PARTIAL_TOP_COMMENT_SCOPE[guard.id]}) but a top-of-file "
            f"comment pragma left {probe}/{control} findings — its scope moved; re-pin it deliberately"
        )
    else:
        assert probe == control, (
            f"{guard.id}: a top-of-file comment pragma silenced {control - probe}/{control} findings, "
            "so its pragma reaches the whole file (or repo). If that is its declared scope, add it to "
            "_FILE_SCOPED_PRAGMA; if it used to be line-scoped, the adoption widened it — same-length "
            "view, same slice"
        )


# --- direction 3 and 4: at the finding's ANCHOR (#1040) ---------------------------------------------
# The two tests above put their pragma at the top (or the end) of each plant file. A guard that
# checks its pragma only on the FLAGGED line, inside its SQL statement or inside its CloudFormation
# resource never looks there, so it passed them whatever its pragma handling. These two put the
# string, and the real comment, AT the anchor each canary finding names. Each placement is built
# once as a template with `_SLOT` where the body goes, so control and probe differ in that phrase only.

# Guards a STRING at the finding's anchor silences on the canary: the #1040 meter, measured when this
# test landed (T0) and drained by its tranches (T1 Python, T2 SQL, T3 CloudFormation, T4 shell /
# workflow / config). A fixed guard left in the set fails ("drain it"), and a guard outside it that
# goes silent fails ("anchor it"), so the set only shrinks.
_LEGACY_ANCHOR_UNANCHORED: frozenset[str] = frozenset()

# Guards with a raw pragma site the anchor STRING placements cannot measure, with the reason. The
# string test skips them, and fails if one becomes measurable and silent (it then moves above).
_ANCHOR_UNMEASURABLE: dict[str, str] = {}

# Guards that matched their pragma on raw text in a plant type with no comment syntax a view reads
# (JSON, Markdown, PEM, PDF, SVG, prose). #1040's T5 drained all 20: each site now calls
# `pragma_present` / `pragma_line_set` with the dialect its file type has, and `dialect=None` (the
# raw text, by contract) where it has none, so the decision is written at the site. VS Code's
# `tasks.json` and `launch.json` are JSONC and read on the `js` view. Drained and pinned empty
# (`test_raw_commentless_stays_drained`): a new guard reading a comment-less type routes through
# `pragma_present(..., dialect=None)` rather than joining a list.
_RAW_COMMENTLESS: dict[str, str] = {}

# Guards a real comment AT the anchor does not reach every finding of: id -> (findings it leaves,
# reason). The count is exact, so an adoption that voids one more opt-out (rule 4) cannot hide
# behind the pin.
_ANCHOR_COMMENT_LEAVES: dict[str, tuple[int, str]] = {
    "service-role-key": (1, "its `.env*` client-key rule honours no pragma; only its frontend-code rule does"),
    "stripe-payments": (1, "its `.env*` client-key rule (`_secret_key_client_side`) honours no pragma"),
}

# Guards whose every canary finding at the anchor comes from a rule that honours NO pragma, so a
# string there cannot silence anything whatever the pragma handling: the string test would pass
# vacuously, so it skips them instead. Each is also in `_ANCHOR_COMMENT_LEAVES`, which is where a
# new one shows up first (a comment cannot reach such a finding either). Not every guard pinned
# there belongs here: one whose comment is unseen for a lexing reason (as a `$$` body was before
# #1040 T2) still has a string a raw match at that anchor would show.
_ANCHOR_STRING_VACUOUS: dict[str, str] = {
    "service-role-key": "the canary plants only its `.env*` client-key finding, not the frontend-code rule that "
    "honours the pragma",
}

# Whole-file-scoped guards (`_FILE_SCOPED_PRAGMA`) that no anchor placement can measure: each one
# changes what the guard detects on the flagged line, so the matched control stops firing. Their
# pragma reads the whole file, so the file-level tests above measure the same check, and the anchor
# tests require that they did. One set per direction, exact both ways: a guard that becomes
# measurable at its anchor fails until it is dropped, and a new one fails until it is pinned here.
_ANCHOR_STRING_FILE_LEVEL_ONLY: frozenset[str] = frozenset({
    "ansible-ignore-errors-on-security-task", "ansible-no-log-disabled-on-secret-task",
    "ansible-unsafe-lookups-enabled", "ci-secret-env-unscoped", "compose-db-port-exposed",
    "compose-shared-mount-propagation", "compose-tmpfs-insecure-options", "default-service-credential",
    "destructive-filesystem-command", "docker-latest-base-tag", "dockerfile-workdir-sensitive-path",
    "fail-safe-exception", "mcp-noauth-default",
    "mcp-raw-execution-tool-name", "mcp-ssrf-unvalidated-destination", "no-cache-on-sensitive",
    "truthy-ownership-check",
})
_ANCHOR_COMMENT_FILE_LEVEL_ONLY: frozenset[str] = frozenset({
    "compose-shared-mount-propagation", "compose-tmpfs-insecure-options", "docker-latest-base-tag",
    "dockerfile-workdir-sensitive-path", "fail-safe-exception", "mcp-twin-route-auth-asymmetry",
})

_SLOT = "@@agentsec-pragma-slot@@"
_Placement = Callable[[str, str, frozenset[int]], "str | None"]  # (path, content, anchor lines) -> template
_CONTROL_BROKEN = "every anchor placement broke the plant"


def _matched_control(tokens: tuple[str, ...]) -> str:
    """The probe body with only its `security:` marker broken: the same words at the same length.
    A placement here sits INSIDE functions and statements, where a guard's mitigation heuristic can
    read string content (`allow-mcp-ssrf-unvalidated-destination` carries "validat", which counts
    as a validator there), so the shorter `_NEUTRAL` phrase would credit the pragma for that drop."""
    return _body(tokens).replace("security:", "securitx:")


def _anchor_kind(path: str) -> str | None:
    """The placement family for a plant file, by name. `sshd_config`, nginx/unbound `.conf` and
    `.npmrc` are measured here only: the whole-file tests above have no shape for them."""
    p = Path(path)
    suffix, name = p.suffix.lower(), p.name.lower()
    if suffix == ".py":
        return "py"
    if suffix == ".sql":
        return "sql"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if (
        suffix in {".sh", ".bash", ".conf", ".toml", ".ini", ".cfg", ".dockerfile"}
        or name.startswith((".env", "dockerfile"))
        or name in {".npmrc", "sshd_config"}
    ):
        return "hash"
    return None


# -- Python: a line takes a string only where the module still compiles, so a placement never turns
# the plant into a file the guard reads as broken. A line's own comment stays last: text appended
# after it would land INSIDE that comment.

def _compiles(source: str) -> bool:
    try:
        compile(source, "<plant>", "exec")
    except (SyntaxError, ValueError):
        return False
    return True


def _py_comment_cols(source: str) -> dict[int, int] | None:
    """Row -> column of the COMMENT token on that row, or None when the file does not tokenize."""
    try:
        return {
            tok.start[0]: tok.start[1] for tok in tokenize.generate_tokens(io.StringIO(source).readline)
            if tok.type == tokenize.COMMENT
        }
    except (tokenize.TokenError, SyntaxError):
        return None


_PY_HEADER = re.compile(r"\s*(?:async\s+)?(?P<kw>def|if|elif|while|for|with)\b")
_PY_PLAIN_STRING = re.compile(r"""(?<![\w"'])("|')(?:\\.|(?!\1)[^\\\n])*\1""")


def _py_string_rewrites(code: str, *, anchored: bool) -> Iterator[str]:
    """Ways to put a string literal on one physical line of code (its comment split off): a trailing
    simple statement; then, on an anchor line that cannot take one, a string INSIDE the line: in a
    compound-statement header, or by implicit concatenation onto a literal already there."""
    literal = f'"{_SLOT}"'
    yield f"{code}; __agentsec_doc = {literal}"
    if not anchored:
        return
    m = _PY_HEADER.match(code)
    if m and code.endswith(":"):
        head = code[:-1]
        if m.group("kw") == "def":
            yield f"{head} -> {literal}:"  # a string return annotation
        elif m.group("kw") == "with":
            yield f"{head}, {literal}:"
        else:
            yield f"{head} or {literal}:"
    if s := _PY_PLAIN_STRING.search(code):
        yield f"{code[: s.end()]} {literal}{code[s.end():]}"


@functools.cache
def _py_string_lines(content: str, lines: frozenset[int] | None) -> tuple[str, ...] | None:
    """`content`'s lines with a string placed on each of `lines` (every line when None) that can
    take one; None when nothing could be placed."""
    comments = _py_comment_cols(content)
    if comments is None:
        return None
    out = content.split("\n")
    placed = False
    for i, line in enumerate(content.split("\n"), start=1):
        col = comments.get(i, len(line))
        code, comment = line[:col].rstrip(), line[col:]
        if not code.strip() or (lines is not None and i not in lines):
            continue
        for candidate in _py_string_rewrites(code, anchored=lines is not None):
            trial = [*out[: i - 1], f"{candidate}  {comment}" if comment else candidate, *out[i:]]
            if _compiles("\n".join(trial)):
                out, placed = trial, True
                break
    return tuple(out) if placed else None


def _py_string(path: str, content: str, anchors: frozenset[int], *, saturate: bool) -> str | None:
    """Saturated: every line that takes a simple statement, then the anchor lines that cannot on
    top, so it reaches a block-scoped pragma (the `def` or decorator above the flagged call) as
    well as a per-line one. Anchor-only is the fallback for a plant that saturation breaks."""
    if not saturate:
        placed = _py_string_lines(content, anchors) if anchors else None
        return None if placed is None else "\n".join(placed)
    base = _py_string_lines(content, None)
    if base is None:
        return None
    joined = "\n".join(base)
    rest = frozenset(i for i in anchors if 0 < i <= len(base) and _SLOT not in base[i - 1])
    on_top = _py_string_lines(joined, rest) if rest else None
    return joined if on_top is None else "\n".join(on_top)


def _py_string_before(path: str, content: str, anchors: frozenset[int]) -> str | None:
    """The string as a simple statement BEFORE the code on each anchor line (`x = "…"; return f(y)`),
    for a guard that reads everything after its sink on the line as the sink's argument, where a
    trailing string turns the argument into a literal and breaks the plant (`llm-output-html-sink`)."""
    out = content.split("\n")
    placed = False
    for i in sorted(anchors):
        if not 0 < i <= len(out):
            continue
        line = out[i - 1]
        body = line.lstrip()
        if not body or body.startswith("#"):
            continue
        trial = [*out[: i - 1], f'{line[: len(line) - len(body)]}__agentsec_doc = "{_SLOT}"; {body}', *out[i:]]
        if _compiles("\n".join(trial)):
            out, placed = trial, True
    return "\n".join(out) if placed else None


def _py_comment(path: str, content: str, anchors: frozenset[int]) -> str | None:
    """A real `#` comment on each anchor line (extending a comment the line already carries)."""
    comments = _py_comment_cols(content)
    if comments is None:
        return None
    out = content.split("\n")
    placed = False
    for i in sorted(anchors):
        if not 0 < i <= len(out) or out[i - 1].rstrip().endswith("\\"):
            continue
        code = out[i - 1].rstrip()
        trial = [*out[: i - 1], f"{code} {_SLOT}" if i in comments else f"{code}  # {_SLOT}", *out[i:]]
        source = "\n".join(trial)
        if _compiles(source) and i in (_py_comment_cols(source) or {}):
            out, placed = trial, True
    return "\n".join(out) if placed else None


# -- SQL: the body twice, in a single-quoted literal and in a quoted identifier. The body's ` ; `
# separators put a `;` before its `--` form, which is the shape the comment view once read as a
# comment inside an identifier (#1040: `strip_sql_comments` revokes a span's immunity at a `;`).

_SQL_STATEMENT_START = re.compile(
    r"\s*(?:create|alter|grant|revoke|do|comment|insert|update|delete|drop|select)\b", re.IGNORECASE
)


def _sql_targets(content: str, anchors: frozenset[int]) -> list[int]:
    """The anchor lines, or (for a finding with no line) every line that opens a statement."""
    lines = content.split("\n")
    targets = anchors or frozenset(i for i, ln in enumerate(lines, 1) if _SQL_STATEMENT_START.match(ln))
    return sorted((i for i in targets if 0 < i <= len(lines)), reverse=True)


def _sql_string(path: str, content: str, anchors: frozenset[int], *, above: bool, inline: bool) -> str | None:
    """`SELECT '<body>', "<body>";` on its own line above the target (a line-or-line-above window)
    and/or on the target line itself, after the statement's `;` or before its first keyword (a window
    made of the statement's own lines)."""
    literal = f"SELECT '{_SLOT}', \"{_SLOT}\";"
    out = content.split("\n")
    placed = False
    for i in _sql_targets(content, anchors):
        code = out[i - 1].rstrip()
        if inline and "--" not in code:
            if code.endswith(";"):
                out[i - 1], placed = f"{code} {literal}", True
            elif _SQL_STATEMENT_START.match(code):
                indent = code[: len(code) - len(code.lstrip())]
                out[i - 1], placed = f"{indent}{literal} {code.lstrip()}", True
        if above:
            out.insert(i - 1, literal)
            placed = True
    return "\n".join(out) if placed else None


def _sql_comment(path: str, content: str, anchors: frozenset[int]) -> str | None:
    out = content.split("\n")
    targets = _sql_targets(content, anchors)
    for i in targets:
        out[i - 1] = f"{out[i - 1].rstrip()}  -- {_SLOT}"
    return "\n".join(out) if targets else None


# -- YAML: a CloudFormation finding names no line, so its unit is the resource: the string or the
# comment goes beside every `Type: AWS::…`. Any other YAML finding gets its own line's value
# re-quoted with the phrase inside the quotes (a plain scalar cannot carry it: ` #` would start a
# YAML comment there).

_CFN_TYPE = re.compile(r"(?P<indent>\s+)Type:\s*['\"]?AWS::")
_YAML_VALUE = re.compile(r"(?P<lead>\s*(?:-\s+)*(?:[\w.$/-]+:\s+)?)(?P<value>[^\s|>{}\[\]&*!#].*?)\s*")
_YAML_KEY = re.compile(r"[\w.$/-]+:(?:\s|$)")


def _cfn_insert(content: str, line: Callable[[str], str]) -> str | None:
    out: list[str] = []
    for ln in content.split("\n"):
        out.append(ln)
        if m := _CFN_TYPE.match(ln):
            out.append(line(m.group("indent")))
    return "\n".join(out) if len(out) > content.count("\n") + 1 else None


def _yaml_string(path: str, content: str, anchors: frozenset[int]) -> str | None:
    if not anchors:
        return _cfn_insert(content, lambda indent: f'{indent}Metadata: "{_SLOT}"')
    out = content.split("\n")
    placed = False
    for i in anchors:
        line = out[i - 1] if 0 < i <= len(out) else ""
        if comment_view(line, "yaml").strip() or line.rstrip().endswith(":"):
            continue  # a comment already there, or a bare `key:` opening a nested mapping (no value)
        m = _YAML_VALUE.fullmatch(line)
        if m and not _YAML_KEY.match(m.group("value")):  # else the key's value is a block/flow opener
            value = m.group("value").replace("'", "''")
            out[i - 1], placed = f"{m.group('lead')}'{value} {_SLOT}'", True
    return "\n".join(out) if placed else None


def _yaml_comment(path: str, content: str, anchors: frozenset[int]) -> str | None:
    if not anchors:
        return _cfn_insert(content, lambda indent: f"{indent}# {_SLOT}")
    return _trailing_hash_comment(content, anchors)


# -- `#`-comment configs and scripts (shell, Dockerfile, `.env`, TOML, sshd_config, nginx, `.npmrc`):
# the string is one more double-quoted word on the anchor line, before a trailing `;`, `{` or `\`.
# A whole-file finding gets a line of its own at the top, but only in a type the file-level tests
# above have no shape for (they already measure the rest).

def _hash_string(path: str, content: str, anchors: frozenset[int]) -> str | None:
    if not anchors:
        return None if _string_shape(path) else _after_opener(content, f'__AGENTSEC_DOC="{_SLOT}"\n')
    out = content.split("\n")
    placed = False
    for i in anchors:
        code = out[i - 1].rstrip() if 0 < i <= len(out) else ""
        if not code.strip() or comment_view(code, "hash").strip():
            continue
        if code.endswith(("\\", ";", "{")):
            out[i - 1] = f'{code[:-1].rstrip()} "{_SLOT}" {code[-1]}'
        else:
            out[i - 1] = f'{code} "{_SLOT}"'
        placed = True
    return "\n".join(out) if placed else None


def _trailing_hash_comment(content: str, anchors: frozenset[int]) -> str | None:
    out = content.split("\n")
    placed = False
    for i in anchors:
        code = out[i - 1].rstrip() if 0 < i <= len(out) else ""
        if code.strip() and not code.endswith("\\"):
            out[i - 1], placed = f"{code}  # {_SLOT}", True
    return "\n".join(out) if placed else None


def _hash_comment(path: str, content: str, anchors: frozenset[int]) -> str | None:
    if not anchors:
        return None if _comment_shape(path) else _after_opener(content, f"# {_SLOT}\n")
    return _trailing_hash_comment(content, anchors)


# Widest reach first; a later placement is the fallback when an earlier one breaks the plant (its
# control stops firing), and the first one whose control fires is the measurement.
_ANCHOR_STRING: dict[str, tuple[_Placement, ...]] = {
    "py": (
        functools.partial(_py_string, saturate=True), functools.partial(_py_string, saturate=False),
        _py_string_before,
    ),
    "sql": (
        functools.partial(_sql_string, above=True, inline=True),
        functools.partial(_sql_string, above=True, inline=False),
        functools.partial(_sql_string, above=False, inline=True),
    ),
    "yaml": (_yaml_string,),
    "hash": (_hash_string,),
}
_ANCHOR_COMMENT: dict[str, tuple[_Placement, ...]] = {
    "py": (_py_comment,), "sql": (_sql_comment,), "yaml": (_yaml_comment,), "hash": (_hash_comment,),
}

_AnchorKind = Literal["anchor-string", "anchor-comment"]


def _assert_string_stays_content(guard: Guard, path: str, original: str, mutated: str) -> None:
    """A string placement that lands in a comment would read as an unanchored guard: fail on it as
    the harness bug it is, under the comment view the guards are anchored through."""
    dialect = comment_dialect_for(path)
    if dialect is None:
        return
    before, after = comment_view(original, dialect), comment_view(mutated, dialect)
    for token in _pragma_tokens(guard):
        if after.count(token) > before.count(token):
            pytest.fail(f"{guard.id}: the anchor string shape put `{token}` in a comment of {path}; fix it")


def _probe_anchor(
    canary: _Canary, guard: Guard, kind: _AnchorKind, table: dict[str, tuple[_Placement, ...]] | None = None
) -> tuple[int, int] | str:
    """`(control, probe)` with the pragma placed at every anchor of the guard's canary findings, or
    the reason that cannot be measured. A placement whose control stops firing broke the plant and
    hands over to the next; when every one breaks it the answer is `_CONTROL_BROKEN`, never a pass.
    `table` overrides the kind's placement families (the form-feed parity test below)."""
    tokens = _pragma_tokens(guard)
    if not tokens:
        return "declares no suppress pragma"
    anchors = canary.anchors_by_guard.get(guard.id, {})
    if not anchors:
        return "no canary finding to mutate (CANARY_EXEMPT)"
    if table is None:
        table = _ANCHOR_STRING if kind == "anchor-string" else _ANCHOR_COMMENT
    originals = {  # a finding can name an ABSENT file (`npm-ignore-scripts` flags a missing `.npmrc`)
        p: (canary.root / p).read_text(encoding="utf-8")
        for p in anchors if _anchor_kind(p) in table and (canary.root / p).is_file()
    }
    families = {p: table[k] for p in originals if (k := _anchor_kind(p)) is not None}
    attempted = False
    for n in range(max((len(f) for f in families.values()), default=0)):
        templates = {
            p: t for p, placements in families.items()
            if (t := placements[min(n, len(placements) - 1)](p, originals[p], anchors[p])) is not None
        }
        if not templates:
            continue
        attempted = True
        controls = {p: t.replace(_SLOT, _matched_control(tokens)) for p, t in templates.items()}
        control = _count(canary, guard, controls, kind)
        if control == 0:
            continue
        mutated = {p: t.replace(_SLOT, _body(tokens)) for p, t in templates.items()}
        if kind == "anchor-string":
            for p, m in mutated.items():
                _assert_string_stays_content(guard, p, originals[p], m)
        return control, _count(canary, guard, mutated, kind)
    if attempted:
        return _CONTROL_BROKEN
    return f"no {kind} placement for {sorted({Path(p).suffix or Path(p).name for p in anchors})}"


def _file_level_only(kind: _AnchorKind) -> tuple[str, frozenset[str]]:
    if kind == "anchor-string":
        return "_ANCHOR_STRING_FILE_LEVEL_ONLY", _ANCHOR_STRING_FILE_LEVEL_ONLY
    return "_ANCHOR_COMMENT_FILE_LEVEL_ONLY", _ANCHOR_COMMENT_FILE_LEVEL_ONLY


def _skip_or_fail_unmeasured(canary: _Canary, guard: Guard, kind: _AnchorKind, why: str) -> None:
    """Skip a guard the anchor placements cannot measure, but only with a reason that is checked: a
    shape limit (`why`), or a pinned whole-file guard whose file-level test DID measure it."""
    name, pinned = _file_level_only(kind)
    if why != _CONTROL_BROKEN:
        assert guard.id not in pinned, f"{guard.id} is pinned in {name} but now skips for another reason ({why})"
        pytest.skip(f"{guard.id}: {why}")
    if guard.id not in pinned:
        pytest.fail(
            f"{guard.id}: {why} (the matched control stopped firing), so this gate cannot measure it: fix a "
            f"placement in this file, or, for a guard in _FILE_SCOPED_PRAGMA, pin it in {name}"
        )
    file_kind: _Kind = "string" if kind == "anchor-string" else "comment"
    file_level = _probe(canary, guard, file_kind)
    assert not isinstance(file_level, str), (
        f"{guard.id} is pinned in {name} as measured by the file-level {file_kind} test, which cannot measure "
        f"it either ({file_level}): fix a placement in this file"
    )
    pytest.skip(
        f"{guard.id}: {why}; NOT measured at its anchor; its whole-file pragma is measured by the file-level "
        f"{file_kind} test ({file_level[0]} control findings)"
    )


@pytest.mark.slow
@pytest.mark.parametrize("guard", _GUARDS, ids=_IDS)
def test_a_pragma_in_a_string_at_the_finding_anchor_does_not_suppress(guard: Guard, canary: _Canary) -> None:
    measured = _probe_anchor(canary, guard, "anchor-string")
    if isinstance(measured, str):
        assert guard.id not in _LEGACY_ANCHOR_UNANCHORED, (
            f"{guard.id} is pinned in _LEGACY_ANCHOR_UNANCHORED but can no longer be measured "
            f"({measured}); the meter must stay honest; restore a placement that reaches it"
        )
        _skip_or_fail_unmeasured(canary, guard, "anchor-string", _ANCHOR_UNMEASURABLE.get(guard.id, measured))
        return
    control, probe = measured
    unanchored = probe < control
    assert guard.id not in _ANCHOR_STRING_FILE_LEVEL_ONLY, (
        f"{guard.id} is measurable at its anchor now ({probe}/{control}): drop it from _ANCHOR_STRING_FILE_LEVEL_ONLY"
    )
    if guard.id in _ANCHOR_STRING_VACUOUS:
        left = _ANCHOR_COMMENT_LEAVES.get(guard.id, (0, ""))[0]
        assert probe == control <= left, (
            f"{guard.id} is pinned in _ANCHOR_STRING_VACUOUS but {probe}/{control} findings survive a string at "
            f"its anchor where {left} come from a rule with no pragma: it is measurable now, drop the pin"
        )
        pytest.skip(f"{guard.id}: NOT measured at its anchor: {_ANCHOR_STRING_VACUOUS[guard.id]}")
    if guard.id in _ANCHOR_UNMEASURABLE:
        assert not unanchored, (
            f"{guard.id}: a string at its anchor now silences {control - probe}/{control} findings, so it is "
            "measurable after all; move it from _ANCHOR_UNMEASURABLE to _LEGACY_ANCHOR_UNANCHORED"
        )
        pytest.skip(f"{guard.id}: {_ANCHOR_UNMEASURABLE[guard.id]}")
    if guard.id in _LEGACY_ANCHOR_UNANCHORED:
        assert unanchored, (
            f"{guard.id} is now anchored ({probe}/{control} findings survive a string pragma at their "
            "anchor): drain it from _LEGACY_ANCHOR_UNANCHORED"
        )
    else:
        assert not unanchored, (
            f"{guard.id}: a pragma quoted inside a STRING at the finding's anchor (its line, statement or "
            f"resource) silenced {control - probe} of {control} findings: match it through "
            "`pragma_line_set(...)` / `comment_view(...)` (guards/base.py) over the SAME slice, so only a real "
            "comment counts; do not add the guard to _LEGACY_ANCHOR_UNANCHORED"
        )


@pytest.mark.slow
@pytest.mark.parametrize("guard", _GUARDS, ids=_IDS)
def test_a_pragma_comment_at_the_finding_anchor_still_suppresses(guard: Guard, canary: _Canary) -> None:
    measured = _probe_anchor(canary, guard, "anchor-comment")
    if isinstance(measured, str):
        assert guard.id not in _ANCHOR_COMMENT_LEAVES, (
            f"{guard.id} is pinned in _ANCHOR_COMMENT_LEAVES but can no longer be measured ({measured}); "
            "a pin nothing checks says nothing; restore a placement that reaches it, or drop the pin"
        )
        _skip_or_fail_unmeasured(canary, guard, "anchor-comment", measured)
        return
    control, probe = measured
    assert guard.id not in _ANCHOR_COMMENT_FILE_LEVEL_ONLY, (
        f"{guard.id} is measurable at its anchor now ({probe}/{control}): drop it from _ANCHOR_COMMENT_FILE_LEVEL_ONLY"
    )
    assert probe <= control, f"{guard.id}: a pragma comment ADDED findings ({control} -> {probe})"
    if guard.id in _ANCHOR_COMMENT_LEAVES:
        left, why = _ANCHOR_COMMENT_LEAVES[guard.id]
        assert probe == left, (
            f"{guard.id} is pinned as leaving {left} finding(s) to a comment at its anchor ({why}) but "
            f"{probe}/{control} survived: its opt-out reach moved; re-pin it deliberately (rule 4)"
        )
    else:
        assert probe == 0, (
            f"{guard.id}: a real comment pragma at the finding's anchor left {probe}/{control} findings: "
            "the opt-out stopped working where users write it (rule 4): keep the view's slice and line mapping "
            "identical to the raw check's. If the guard's declared scope excludes the anchor, pin it in "
            "_ANCHOR_COMMENT_LEAVES with the reason"
        )


# A form feed (chr(12)) is a line break to `str.splitlines()` but not to Python, so a guard that
# numbers its pragma lines on one text and walks the lines of another (the raw file vs its
# `strip_python_strings` copy, which blanks the form feed inside a triple-quoted string) puts every
# pragma below that string on the wrong line: the user's opt-out stops working and a neighbouring
# line is silenced instead (#1132 review, H1). Built with `chr` so no tool rewrites the escape. The
# string spans a real newline too: on a one-line string `strip_python_strings`' own `ast`-lineno
# indexing of its `splitlines()` rows leaves the form feed standing, so the two counts would agree.
_FF_STATEMENT = f'__agentsec_ff = """a{chr(12)}b\nc"""'


def _py_comment_after_ff(path: str, content: str, anchors: frozenset[int]) -> str | None:
    """`_py_comment`'s placement plus a statement holding a triple-quoted form feed ABOVE the first
    anchor: on the nearest non-blank line at or above it where the module still compiles, at that
    line's indentation (above a decorator or a multi-line call's opening line, when it must)."""
    placed = _py_comment(path, content, anchors)
    if placed is None or not anchors:
        return None
    lines = placed.split("\n")
    for at in range(min(min(anchors), len(lines)), 0, -1):
        line = lines[at - 1]
        if not line.strip():
            continue
        indent = line[: len(line) - len(line.lstrip())]
        source = "\n".join([*lines[: at - 1], f"{indent}{_FF_STATEMENT}", *lines[at - 1:]])
        if _compiles(source):
            return source
    return None


# Guards converted before #1132 (T1a and earlier) whose pragma lines were numbered on the raw text
# (or split by `splitlines`) while their findings were numbered on the stripped text (or by `\n`).
# Measured on #1132's round-1 fix and drained by #1040's last tranche, which numbers each set on the
# text the guard enumerates. Pinned empty: a guard that numbers the two on different texts fails the
# test below rather than joining a list.
_FF_PRAGMA_MISALIGNED: frozenset[str] = frozenset()

_PY_COMMENT_ONLY: dict[str, tuple[_Placement, ...]] = {"py": (_py_comment,)}
_PY_COMMENT_AFTER_FF: dict[str, tuple[_Placement, ...]] = {"py": (_py_comment_after_ff,)}


@pytest.mark.slow
@pytest.mark.parametrize("guard", _GUARDS, ids=_IDS)
def test_a_form_feed_in_a_string_above_does_not_move_a_pragma_comment(guard: Guard, canary: _Canary) -> None:
    """Direction 4 again on the Python anchors, with a form feed inside a triple-quoted string above
    the first one: when the guard still fires exactly as often (the control), the real comment must
    still silence exactly as much (the probe). A control that moves is a DETECTION shift, the
    stripper's own pre-existing form-feed limit, which this pragma gate does not measure (skipped,
    with the counts). Guards pinned in `_FF_PRAGMA_MISALIGNED` must still fail it; drain on a fix."""
    plain = _probe_anchor(canary, guard, "anchor-comment", table=_PY_COMMENT_ONLY)
    if isinstance(plain, str):
        pytest.skip(f"{guard.id}: no Python anchor-comment measurement ({plain})")
    shifted = _probe_anchor(canary, guard, "anchor-comment", table=_PY_COMMENT_AFTER_FF)
    if isinstance(shifted, str) or shifted[0] != plain[0]:
        assert guard.id not in _FF_PRAGMA_MISALIGNED, (
            f"{guard.id} is pinned in _FF_PRAGMA_MISALIGNED but is no longer measured ({plain} -> {shifted})"
        )
        pytest.skip(f"{guard.id}: the form feed moves detection, not only the pragma ({plain} -> {shifted})")
    misaligned = shifted[1] != plain[1]
    if guard.id in _FF_PRAGMA_MISALIGNED:
        assert misaligned, f"{guard.id} keeps its pragma lines past a form feed now: drain _FF_PRAGMA_MISALIGNED"
        return
    assert not misaligned, (
        f"{guard.id}: a real comment at its anchors silences {plain[0] - plain[1]}/{plain[0]} findings, but "
        f"{shifted[0] - shifted[1]}/{shifted[0]} with a form feed in a string above them: its pragma lines and "
        "the lines it walks are numbered on different texts; build `pragma_line_set` from the text it enumerates"
    )


# --- the static complement: every raw pragma site is accounted for ---------------------------------
# A proxy, not a measurement: it cannot see a view applied to the wrong slice. It covers what no
# placement above reaches: a plant type with no anchor placement (JS, Go, HCL, comment-less types),
# the pinned shape limits, and every site of a module the canary plant does not exercise, so a NEW
# guard with a raw match fails here whatever its language.
#
# It reads each guard module's AST PER SITE (#1040 T1). It used to ask whether the module called a
# view helper ANYWHERE, so one converted site hid every raw one beside it: `obfuscated-payload-
# execution` read as anchored on the strength of its JS rule while five Python sites stayed raw. A
# READ is `P.search/match/fullmatch/finditer/findall(x)`, `re.<fn>(P…, x)` or `P in x`, where `P`
# is a pragma constant (a module constant whose value mentions `security:`) or a local alias of one
# (`p = _A if md else _B`, `p = re.compile(_TEMPLATE.format(...))`). It is raw unless `x` traces to
# a view: an expression that calls a view helper, or a name bound (assignment, loop or comprehension
# target, in the same outermost function) from one, transitively.

_VIEW_CALLS = frozenset({"comment_view", "pragma_present", "pragma_line_set"})
_READ_METHODS = frozenset({"search", "match", "fullmatch", "finditer", "findall"})
_RE_FUNCS = _READ_METHODS | {"compile"}

# Raw sites read by hand and kept, keyed `(guard id, the read's source text)`. The key is the code,
# not a line number, so an edit to the site drops the pin and the site fails until it is re-read.
_RAW_SITE_BY_DECISION: dict[tuple[str, str], str] = {
    ("npm-ignore-scripts", "_PRAGMA not in npmrc_text"): (
        "`.npmrc` is ini, whose `;` comment form no view reads, so the raw match is the more-view side (#539)"
    ),
}
# Sites that DO read a view, through a route the tracer does not follow, each traced by hand.
_VIEWED_BY_HAND: dict[tuple[str, str], str] = {
    ("js-private-file-exposure", "_PRAGMA in view_line"): (
        "`view_lines` is a parameter; its one caller passes `comment_view(text, 'js').splitlines()`"
    ),
}


def _pragma_constants(module: object) -> frozenset[str]:
    """The module constants whose `str` / `re.Pattern` value mentions `security:`."""
    names: set[str] = set()
    for name, value in vars(module).items():
        text = value.pattern if isinstance(value, re.Pattern) else value if isinstance(value, str) else None
        if _CONSTANT.fullmatch(name) and text is not None and "security:" in text:
            names.add(name)
    return frozenset(names)


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _calls_a_view(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call) and (
            (isinstance(n.func, ast.Name) and n.func.id in _VIEW_CALLS)
            or (isinstance(n.func, ast.Attribute) and n.func.attr in _VIEW_CALLS)
        )
        for n in ast.walk(node)
    )


def _re_call(node: ast.AST, funcs: frozenset[str]) -> ast.Call | None:
    """`node` when it is a `re.<fn>(…)` call with `fn` in `funcs` and at least one argument."""
    if (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "re" and node.func.attr in funcs
    ):
        return node
    return None


def _aliases_a_pragma(value: ast.AST, aliases: set[str]) -> bool:
    if isinstance(value, ast.Name):
        return value.id in aliases
    if isinstance(value, ast.IfExp):
        return _aliases_a_pragma(value.body, aliases) and _aliases_a_pragma(value.orelse, aliases)
    return _re_call(value, frozenset({"compile"})) is not None and bool(_names(value) & aliases)


def _units(tree: ast.Module) -> Iterator[ast.AST]:
    """The outermost functions (methods included), then the module's remaining top-level code."""
    top: list[ast.stmt] = []
    stack = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node
        elif isinstance(node, ast.ClassDef):
            stack.extend(node.body)
        else:
            top.append(node)
    yield ast.Module(body=top, type_ignores=[])


def _bindings(unit: ast.AST) -> list[tuple[ast.AST, ast.AST]]:
    out: list[tuple[ast.AST, ast.AST]] = []
    for n in ast.walk(unit):
        if isinstance(n, ast.Assign):
            out.extend((t, n.value) for t in n.targets)
        elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and n.value is not None:
            out.append((n.target, n.value))
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
            out.append((n.target, n.iter))
    return out


def _read_subject(node: ast.AST, aliases: set[str]) -> ast.AST | None:
    """The text a pragma READ matches against, or None when `node` is not one."""
    if (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args
        and isinstance(node.func.value, ast.Name) and node.func.value.id in aliases
        and node.func.attr in _READ_METHODS
    ):
        return node.args[0]
    call = _re_call(node, _READ_METHODS)
    if call is not None and len(call.args) >= 2 and _names(call.args[0]) & aliases:
        return call.args[1]
    if (
        isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id in aliases
        and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
    ):
        return node.comparators[0]
    return None


@functools.cache
def _raw_pragma_sites(module_name: str) -> tuple[str, ...]:
    """The source text of every pragma read in the module that does not trace to a view."""
    module = sys.modules[module_name]
    source = inspect.getsource(module)
    constants = _pragma_constants(module)
    sites: list[str] = []
    for unit in _units(ast.parse(source)):
        aliases, viewed = set(constants), set[str]()
        bindings = _bindings(unit)
        changed = True
        while changed:  # a fixpoint: a view flows through any number of bindings
            changed = False
            for target, value in bindings:
                bound = _names(target)
                if (_calls_a_view(value) or _names(value) & viewed) and not bound <= viewed:
                    viewed |= bound
                    changed = True
                if isinstance(target, ast.Name) and target.id not in aliases and _aliases_a_pragma(value, aliases):
                    aliases.add(target.id)
                    changed = True
        for node in ast.walk(unit):
            subject = _read_subject(node, aliases)
            if subject is not None and not _calls_a_view(subject) and not _names(subject) & viewed:
                sites.append(ast.get_source_segment(source, node) or ast.dump(node))
    return tuple(sorted(set(sites)))


def _raw_sites(guard: Guard) -> tuple[str, ...]:
    """The guard's raw pragma sites, minus the pinned decisions and the hand-traced views."""
    pinned = _RAW_SITE_BY_DECISION.keys() | _VIEWED_BY_HAND.keys()
    return tuple(s for s in _raw_pragma_sites(type(guard).__module__) if (guard.id, s) not in pinned)


def test_every_raw_pragma_guard_is_accounted_for() -> None:
    # Both directions. A raw guard outside the pins fails ("anchor it"), and so does a pinned guard
    # with no raw site left: for `_LEGACY_ANCHOR_UNANCHORED` that is the drain, and the anchor test
    # agrees with it only when it measured the module's last raw site, which is the false drain the
    # per-module reading allowed. A pin of the two unmeasured sets has no other check.
    raw = {g.id: sites for g in _GUARDS if (sites := _raw_sites(g))}
    pinned = _LEGACY_ANCHOR_UNANCHORED | frozenset(_ANCHOR_UNMEASURABLE) | frozenset(_RAW_COMMENTLESS)
    unaccounted = {gid: raw[gid] for gid in sorted(raw.keys() - pinned)}
    assert not unaccounted, (
        f"{unaccounted} match a suppress pragma on raw text, so a string quoting it suppresses: read it "
        "through `pragma_present` / `pragma_line_set` / `comment_view` (guards/base.py) over the same slice"
    )
    stale = sorted(pinned - raw.keys())
    assert not stale, (
        f"{stale} are pinned as raw but no raw pragma site is left in their module: drop them from their pin "
        "(and from _LEGACY_ANCHOR_UNANCHORED only once the anchor test agrees); if a read is still raw, "
        "the site classifier here missed its shape: teach it the shape"
    )


def test_raw_commentless_stays_drained() -> None:
    # #1040 T5 emptied it. A comment-less type is written as `dialect=None` at its site instead, where
    # the next reader sees the decision; a new pin here would hide it in the test file.
    assert not _RAW_COMMENTLESS, (
        f"{sorted(_RAW_COMMENTLESS)} pinned in _RAW_COMMENTLESS: route the pragma through "
        "`pragma_present(..., dialect=None)` at its site instead"
    )


@pytest.mark.parametrize(
    ("name", "pinned"),
    [("_RAW_SITE_BY_DECISION", _RAW_SITE_BY_DECISION), ("_VIEWED_BY_HAND", _VIEWED_BY_HAND)],
    ids=["raw-by-decision", "viewed-by-hand"],
)
def test_a_site_pin_names_a_site_the_classifier_still_flags(name: str, pinned: dict[tuple[str, str], str]) -> None:
    # A pin whose site was edited or removed would excuse nothing and still read as a decision.
    by_id = {g.id: g for g in _GUARDS}
    stale = sorted(
        key for key in pinned
        if key[0] not in by_id or key[1] not in _raw_pragma_sites(type(by_id[key[0]]).__module__)
    )
    assert not stale, f"{name} pins sites the classifier no longer flags: {stale}; drop them"


def test_the_site_classifier_reads_each_shape() -> None:
    # The classifier is a regex-free AST walk, so pin what it calls raw and viewed on known inputs:
    # a silent classifier would read every guard as anchored.
    module = types.ModuleType("agentsec_classifier_probe")
    vars(module).update(_PRAGMA=re.compile(r"#\s*security:\s*allow-x"), _TEMPLATE=r"#\s*security:\s*allow-old-{pkg}")
    source = (
        "def raw_line(lines):\n"
        "    for line in lines:\n"
        "        if _PRAGMA.search(line):\n"
        "            pass\n"
        "def raw_alias(text, md):\n"
        "    p = _PRAGMA if md else _PRAGMA\n"
        "    return p.search(text)\n"
        "def raw_template(raw, pkg):\n"
        "    return re.search(_TEMPLATE.format(pkg=pkg), raw)\n"
        "def raw_in(block):\n"
        "    return _PRAGMA in block\n"
        "def viewed(text):\n"
        "    view = comment_view(text, 'python')\n"
        "    for i, vline in enumerate(view.splitlines()):\n"
        "        if _PRAGMA.search(vline):\n"
        "            return i\n"
        "    return pragma_present(_PRAGMA, text, dialect='python')\n"
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(sys.modules, module.__name__, module)
        mp.setattr(inspect, "getsource", lambda _m: source)
        sites = _raw_pragma_sites.__wrapped__(module.__name__)
    assert sites == (
        "_PRAGMA in block", "_PRAGMA.search(line)", "p.search(text)", "re.search(_TEMPLATE.format(pkg=pkg), raw)",
    )


def _inline_pragma_patterns(module_name: str) -> list[str]:
    """`security:` patterns built anywhere but a module constant's value: `re.<fn>("…security:…")`
    or `"…security:…" in x`. `_pragma_tokens` and the site classifier both key on module constants,
    so a pattern built inline is invisible to every test in this file."""
    source = inspect.getsource(sys.modules[module_name])
    tree = ast.parse(source)
    inside_a_constant: set[int] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if all(isinstance(t, ast.Name) and _CONSTANT.fullmatch(t.id) for t in targets):
                inside_a_constant.update(id(n) for n in ast.walk(stmt.value))
    found: list[str] = []
    for node in ast.walk(tree):
        if id(node) in inside_a_constant:
            continue
        call = _re_call(node, _RE_FUNCS)
        if call is not None:
            pattern: ast.AST = call.args[0]
        elif isinstance(node, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            pattern = node.left
        else:
            continue
        literal = "".join(
            n.value for n in ast.walk(pattern) if isinstance(n, ast.Constant) and isinstance(n.value, str)
        )
        if "security:" in literal:
            found.append(ast.get_source_segment(source, node) or ast.dump(node))
    return found


def test_every_pragma_pattern_is_a_module_constant() -> None:
    # `dependency-version-floor` built `rf"#\s*security:\s*allow-old-{pkg}\b"` inline and matched it
    # on a whole TOML manifest, so a TOML string silenced a CVE floor and no test here could see it.
    modules = sorted({type(g).__module__ for g in _GUARDS})
    inline = {m: found for m in modules if (found := _inline_pragma_patterns(m))}
    assert not inline, (
        f"{inline} build a suppress-pragma pattern inline: make it a module constant (a template filled "
        "with `.format(...)` for a per-name pragma), so this gate can see it"
    )


def test_a_vacuous_string_pin_is_also_a_comment_leaves_pin() -> None:
    # The skip's claim is that no pragma reaches those findings, so a comment cannot either.
    loose = sorted(set(_ANCHOR_STRING_VACUOUS) - set(_ANCHOR_COMMENT_LEAVES))
    assert not loose, f"{loose} are pinned in _ANCHOR_STRING_VACUOUS but not in _ANCHOR_COMMENT_LEAVES"


def test_a_file_level_only_pin_has_whole_file_scope() -> None:
    # The pin's claim is that the file-level tests measure the same whole-file pragma check.
    for name, pinned in (_file_level_only("anchor-string"), _file_level_only("anchor-comment")):
        narrow = sorted(pinned - _FILE_SCOPED_PRAGMA)
        assert not narrow, f"{narrow} are pinned in {name} but are not in _FILE_SCOPED_PRAGMA"


# --- the pins name real guards, and stay measurable -----------------------------------------------

@pytest.mark.parametrize(
    "pinned",
    [
        _LEGACY_UNANCHORED, _FILE_SCOPED_PRAGMA, frozenset(_PARTIAL_TOP_COMMENT_SCOPE),
        _LEGACY_ANCHOR_UNANCHORED, frozenset(_ANCHOR_UNMEASURABLE), frozenset(_RAW_COMMENTLESS),
        frozenset(_ANCHOR_COMMENT_LEAVES), _ANCHOR_STRING_FILE_LEVEL_ONLY, _ANCHOR_COMMENT_FILE_LEVEL_ONLY,
        frozenset(_ANCHOR_STRING_VACUOUS),
    ],
    ids=[
        "legacy-unanchored", "file-scoped", "partial-scope",
        "legacy-anchor-unanchored", "anchor-unmeasurable", "raw-commentless", "anchor-comment-leaves",
        "anchor-string-file-level-only", "anchor-comment-file-level-only", "anchor-string-vacuous",
    ],
)
def test_pinned_ids_are_registered_guards(pinned: frozenset[str]) -> None:
    unknown = sorted(pinned - set(_IDS))
    assert not unknown, f"pinned ids that are not registered guards: {unknown}"


def test_scope_pins_are_disjoint() -> None:
    # A guard has ONE top-of-file comment scope; listing it twice would let either assertion win.
    both = _FILE_SCOPED_PRAGMA & frozenset(_PARTIAL_TOP_COMMENT_SCOPE)
    assert not both, f"pinned as both file-scoped and partial: {sorted(both)}"


def test_raw_site_pins_are_disjoint() -> None:
    # One status per raw guard: measured and unanchored, unmeasurable by shape, or a comment-less type.
    pins = {
        "legacy-anchor-unanchored": _LEGACY_ANCHOR_UNANCHORED,
        "anchor-unmeasurable": frozenset(_ANCHOR_UNMEASURABLE),
        "raw-commentless": frozenset(_RAW_COMMENTLESS),
    }
    overlaps = {
        f"{a} & {b}": sorted(pins[a] & pins[b]) for a in pins for b in pins if a < b and pins[a] & pins[b]
    }
    assert not overlaps, f"guards pinned twice: {overlaps}"


@pytest.mark.slow
def test_every_legacy_unanchored_guard_is_still_measurable(canary: _Canary) -> None:
    # An id the gate can no longer measure (its plant moved to a type with no injection shape) would
    # sit in the legacy set forever and never drain — the meter must stay honest.
    planned = {gid: _plan(canary, g, "string") for g in _GUARDS if (gid := g.id) in _LEGACY_UNANCHORED}
    unmeasurable = {gid: why for gid, why in planned.items() if isinstance(why, str)}
    assert not unmeasurable, f"legacy ids the gate can no longer measure: {unmeasurable}"


# --- the detect() read cache stays exact ---------------------------------------------------------

@pytest.mark.slow
def test_the_detect_read_cache_never_serves_a_mutated_file(canary: _Canary) -> None:
    # `_detect` is only exact while a mutated file is read from disk. If its dirty set stopped
    # matching the paths detect() passes (a resolve or separator mismatch), every mutant would be
    # profiled as the UNMUTATED canary, and the `applies()` re-check in `_count` would pass on
    # anything with no sign it had stopped looking. So blank every file detect() reads: the profile
    # must move, and the cached call must move with the uncached one.
    assert _detect(canary, {}) == canary.profile  # also fills the cache with every unmutated read
    root = canary.root.resolve()
    blank = {path.relative_to(root).as_posix(): "" for path in canary.reads}
    with _written(canary, blank):
        cached = _detect(canary, blank)
        uncached = detect(canary.root)
    assert uncached != canary.profile, "blanking every file detect() reads left the profile as it was"
    assert cached == uncached, "the read cache served a mutated file's old text to detect()"
