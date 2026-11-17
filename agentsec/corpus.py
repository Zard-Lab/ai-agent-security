"""Corpus scan pipeline — ephemeral clone + audit of public repos to surface FP/gap candidates.

Runner-layer module: uses subprocess, tempfile, and agentsec.net (the sole urllib importer).
Does NOT import urllib.request directly — test_net_sandbox.py enforces that only net.py may do so.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess  # nosec B404
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import SplitResult, unquote, urlsplit  # URL string-handling only, no egress

from agentsec import net
from agentsec.audit import audit
from agentsec.checklist import load_checklist
from agentsec.detect import detect
from agentsec.findings import SEVERITY_RANK, Finding, sanitize_finding
from agentsec.guard_worker import DEFAULT_GUARD_BUDGET
from agentsec.text_sanitize import neutralize_delivery_markers

SEED_REPOS: list[str] = [
    # Core stack — FastAPI / Supabase / LLM (original 5)
    "https://github.com/fastapi/fastapi",
    "https://github.com/tiangolo/full-stack-fastapi-template",
    "https://github.com/supabase/supabase",
    "https://github.com/langchain-ai/langchain",
    "https://github.com/pydantic/pydantic-ai",
    # RAG / LLM routing — LLM08, rate-limit, system-prompt, input-size signal
    "https://github.com/run-llama/llama_index",
    "https://github.com/BerriAI/litellm",
    # MCP protocol — mcp-tool-unverified, mcp-tool-description-injection direct signal
    "https://github.com/modelcontextprotocol/python-sdk",
    # LLM client + observability — env-secret-in-prompt, llm-input-size-cap, sensitive-logging signal
    "https://github.com/openai/openai-python",
    "https://github.com/langfuse/langfuse",
    # Web framework base — cors-wildcard, error-info-leak, trusted-host signal
    "https://github.com/encode/starlette",
    "https://github.com/pallets/flask",
    # Async task runner — background-tasks, agent-loop-circuit-breaker signal
    "https://github.com/celery/celery",
    # Multi-agent frameworks — agent-tool-overpermission, agent-loop signal
    "https://github.com/ag2ai/ag2",
    "https://github.com/microsoft/semantic-kernel",
    # Anthropic LLM client + agentic tooling — parity with openai-python (env-secret-in-prompt,
    # llm-input-size-cap signal); claude-code adds agent-loop / tool-permission signal.
    "https://github.com/anthropics/anthropic-sdk-python",
    "https://github.com/anthropics/claude-code",
    # Assembled agent apps (coleam00/Cole Medin) — real tool/memory/auth wiring on top of the
    # frameworks above, not just the framework itself. Added after a trial corpus-scan
    # (2026-08-16, local-only, not part of this repo) found mcp-mem0 shipping a hardcoded
    # `user_id` constant on a real Mem0 write — the concrete case that motivated
    # agent-memory-user-scope's hollow-scoping rule (see PR for that guard change). The other
    # two add stack shapes no existing seed exercises: a real OAuth-bearing MCP server, and an
    # LLM-backed app with an unattended auto-merge pipeline (4-high-impact-action-confirmation
    # signal — not yet a guard, corpus evidence for prioritizing it).
    "https://github.com/coleam00/mcp-mem0",
    "https://github.com/coleam00/remote-mcp-server-with-auth",
    "https://github.com/coleam00/dark-factory-experiment",
    # the MCP seeds above are Python/TypeScript only — zero Go MCP server, the
    # exact gap the PHP/Ruby/Java precedent warns about (a guard shipped without a
    # real repo of its target shape in the corpus gets no FP/gap signal). github/github-mcp-server
    # is Dean-named real Go MCP-server population (verified real, 33k+ stars, active).
    # harishsg993010/damn-vulnerable-MCP-server is a deliberately-vulnerable Python MCP server
    # with easy/medium/hard challenge tiers exercising many vulnerability classes (transport
    # auth, path traversal) at once (verified real, 1.3k+ stars) — good gap-detection signal
    # alongside a real production repo for FP-checking, not instead of one.
    "https://github.com/github/github-mcp-server",
    "https://github.com/harishsg993010/damn-vulnerable-MCP-server",
    # Go — zero Go repos meant the six Go GUARDS (go-ssh-host-key-trust,
    # go-pprof-exposed, go-tls-verify-disabled, go-sql-injection, go-template-html-escaping,
    # go-build-supply-chain-footgun) got no real-world FP/gap signal from the routine scan.
    # (go-osv-hygiene is a Runner, not a guard, and scan_repo() runs audit(run_scanners=False),
    # so NO runner is ever exercised by corpus-scan — a seed change can't give it signal; see #4.)
    # Two real production Go services, not toy repos, matching the rest of this list's own pattern.
    "https://github.com/caddyserver/caddy",
    "https://github.com/hashicorp/vault",
    # Public repos only. This list ships in the wheel and in the public source, so an access-gated
    # repo belongs in a maintainer's own `--repos-file`, never here
    # (`test_seed_repos_name_no_access_gated_repo`).
    # PHP / Ruby / Java — #848: the 27 guards from the PHP (9), Ruby (8), and Java (10) stack
    # batches shipped with zero real-world FP/gap signal, since SEED_REPOS had no repo in any of
    # those three languages and `agentsec corpus-scan`'s curated list is the only thing a routine
    # scan actually exercises (auto-discovery alone never touched them either). One real,
    # security-sensitive production repo per language, matching the rest of this list's own
    # "real assembled app, not a toy" pattern (see the Go entries above for the same reasoning):
    "https://github.com/matomo-org/matomo",         # PHP — real production web-analytics platform;
                                                     # handles auth, SQL, and user-supplied tracking data
    "https://github.com/discourse/discourse",       # Ruby (Rails) — real production forum software;
                                                     # auth, mass-assignment-prone models, real SQL/crypto use
    "https://github.com/keycloak/keycloak",         # Java — real production identity/auth server; LDAP,
                                                     # crypto, SAML/XML parsing, and deserialization surfaces
                                                     # are exactly what the 10 Java guards target
]

_GH_SEARCH_QUERIES = [
    "language:python+stars:%3E10000+sort:stars",
    "fastapi+in:readme+language:python+stars:%3E500",
    "supabase+language:python+stars:%3E200",
    # Added per Dean's review hygiene ask: this list was 100% language:python-scoped, so the
    # routine corpus-scan discovery pass never sampled the ~25% TS/JS population or the
    # MCP-server shape — a query-source gap, not a sample-size one. `topic:mcp-server` targets
    # the fastest-growing shape in agentsec's own audience (Dean's Tier 1 #1); the Next.js query
    # mirrors the existing fastapi query's in:readme+language+stars pattern for the other side
    # of the wedge. Adding them was necessary but not sufficient: `discover_repos` then had to
    # be taught to spread `count` across the list, or these trailing entries stayed unreachable
    # below count=91/121 — see the per-round cap there (PR #913 re-review, H-1).
    "topic:mcp-server+stars:%3E10",
    "nextjs+in:readme+language:typescript+stars:%3E500",
]


@dataclass
class RepoScan:
    url: str
    features: list[str]     # sorted(profile.features) — JSON-safe (no Path/date objects)
    stack_summary: str      # profile.summary() string
    findings: list[Finding]
    ran: list[str]          # guard IDs that ran
    skipped: list[str]      # guard IDs skipped (N/A for this stack)
    error: str = ""         # non-empty if any step failed; scan still included in report
    # #677 fallback lapse: the guard worker failed to start and the guards ran in-process,
    # unbudgeted. Coverage is COMPLETE (every guard ran), so the repo STAYS in the fp/gap
    # analyses (unlike `.error`) — but the per-repo line and the report's scanned-repos
    # status disclose it, because "clean scan" and "clean scan with hang protection
    # lapsed" must not render identically (Rule 3; #821 follow-up review, Medium).
    unbudgeted: bool = False


@dataclass
class FpCandidate:
    guard_id: str
    fired_ratio: float
    repos_fired: list[str]
    repos_applicable: list[str]
    sample_finding: Finding
    fp_sample_locations: list[str]  # up to 5 unique location strings for pattern tightening
    max_repo_findings: int = 0      # peak finding-count on any single repo (the over-fire magnitude)
    outlier: bool = False           # surfaced by the single-repo over-fire signal, not cross-repo prevalence


@dataclass
class GapCandidate:
    item_id: str
    item_title: str
    item_severity: str
    item_section: str
    applies_when: list[str]
    standards: list[str]
    cwe: str | None
    atlas_techniques: list[str]
    repos_affected: int
    stacks_seen: list[list[str]]    # one feature list per affected repo


@dataclass
class CorpusReport:
    scanned: list[RepoScan]
    fp_candidates: list[FpCandidate]
    gap_candidates: list[GapCandidate]
    run_date: str           # YYYY-MM-DD, caller-provided; never date.today() inside this module
    corpus_size: int        # total repos attempted
    stack_match_count: int  # repos that passed stack gate and had no error
    # Scanned repos the single-repo outlier signal left out of its comparison basis (see
    # `_FP_OUTLIER_EXCLUDED_REPOS`), so the report can say so instead of leaving them reading as
    # "not applicable" to every guard in fp-candidates.json.
    outlier_excluded_repos: list[str] = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def discover_repos(
    count: int, *, tier: int, token: str = "", manifest: net.Manifest | None = None,
) -> list[str]:
    """Return up to *count* clone URLs from GitHub Search, deduped.

    count=0 returns [] immediately (skip GitHub API). Discovery sends only repo-search terms
    (nothing about your code) → a Tier-1 fetch via `net.get` (disclosed + DO_NOT_TRACK-honoring),
    routed through agentsec.net (the sole urllib importer; test_net_sandbox.py enforces it).

    Cost: one search call per query per round, so a run that reaches `count` in a single round
    spends `min(count, len(_GH_SEARCH_QUERIES))` calls — 5 at the shipped default of 10, not 1.
    A run that does NOT finish in one round costs more: a degraded pass where four of the five
    queries 403 was measured at 9 calls for count=10, since the surviving query has to be asked
    once per round. Still comfortably inside the limit.

    Note the limit that applies here is the SEARCH one — 10 req/min unauthenticated, 30 req/min
    with a token — not the 60 req/hr core-REST figure. They are different budgets and this
    endpoint is only ever charged against the former. `GH_TOKEN` (warned about when unset) is
    what buys headroom for large-`count` runs that page several times per query.
    """
    if count <= 0:
        return []

    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    seen: dict[str, None] = {}

    # Round-robin the queries, capping what any ONE of them may contribute per round. Rotating
    # pages alone is not enough: `per_page=30` items arrive in hand, so query #1's first page
    # satisfies any `count <= 30` outright and the `len(seen) >= count` break exits the round
    # before query #2 is ever requested — measured at the shipped default (count=10, the CLI
    # *and* cron value): exactly ONE search call fired, so the mcp-server/Next.js queries added
    # to widen sampling were unreachable below count=91/121 (PR #913 re-review, H-1).
    #
    # The cap is a FLOOR divide, deliberately: `count // len(queries)` means a full round takes
    # at most `count` repos, so the break can only fire after every query has had its turn.
    # That yields the guarantee "every query is sampled whenever count >= len(queries)" — which
    # a ceil() cap does NOT give (at count=7 or 12 it lets 4 queries eat the whole budget and
    # the 5th never runs). Below that, `count` itself is the binding limit: fewer slots than
    # queries means the first `count` queries run, and no distribution can do better.
    per_round = max(1, count // len(_GH_SEARCH_QUERIES))
    pages = dict.fromkeys(_GH_SEARCH_QUERIES, 1)
    exhausted: set[str] = set()
    while len(seen) < count and len(exhausted) < len(_GH_SEARCH_QUERIES):
        for query in _GH_SEARCH_QUERIES:
            if len(seen) >= count:
                break
            if query in exhausted:
                continue
            url = (
                f"https://api.github.com/search/repositories"
                f"?q={query}&per_page=30&page={pages[query]}"
            )
            try:
                raw = net.get(
                    url, tier_required=1, feature="corpus-scan", tier=tier, manifest=manifest,
                    sends="GitHub repo-search terms (nothing about your code)", headers=headers,
                )
                data = json.loads(raw.decode())
                items = data.get("items", [])
                if not items:
                    exhausted.add(query)
                    continue
                took = 0
                for repo in items:
                    clone_url = repo.get("clone_url", "")
                    if clone_url and clone_url not in seen:
                        seen[clone_url] = None
                        took += 1
                    if len(seen) >= count or took >= per_round:
                        break
                pages[query] += 1
            except Exception as exc:
                print(f"  [corpus] discover_repos query failed: {exc}", file=sys.stderr)
                exhausted.add(query)

    return list(seen)[:count]


# ---------------------------------------------------------------------------
# Clone
# ---------------------------------------------------------------------------

# The only two authorities that mean "this machine" in a `file://` URL (RFC 8089 §2). Compared
# against `SplitResult.hostname`, which urllib has already lower-cased, so `file://LOCALHOST/x`
# and `FILE://localhost/x` both land here (the previous slice-the-raw-string version answered
# those two spellings differently).
_LOCAL_FILE_HOSTS = frozenset({"", "localhost"})

# Every separator Win32 accepts in front of an authority. Explorer's address bar yields
# `\\host\share`, but `//host/share`, `\/host/share` and `/\host\share` all resolve the same way.
_PATH_SEPS = ("/", "\\")


def _names_a_remote_authority(candidate: str) -> bool:
    """True if *candidate* is a scheme-less path whose first component is an authority (a host
    name), i.e. a UNC path: `\\\\host\\share\\repo` or `//host/share/repo`.

    TWO OR MORE leading separators, in any mix of `/` and `\\`, are what makes the next component an
    authority. Consuming the whole run rather than exactly two is deliberate: `/\\\\host\\share` and
    `///host/share` are the same UNC to a Win32 path parser that skips a separator run, and they are
    reachable by percent-decoding a `file:` path. A single leading separator (`/path`) is never one.
    """
    text = candidate.strip()
    if len(text) < 2 or text[0] not in _PATH_SEPS or text[1] not in _PATH_SEPS:
        return False
    authority = text.lstrip("/\\")
    for sep in _PATH_SEPS:
        authority = authority.split(sep, 1)[0]
    return authority != ""


def _is_windows_drive_authority(netloc: str) -> bool:
    """True if *netloc* is a Windows DRIVE that landed in the authority slot, not a host name.

    `file://C:/path/to/repo` and `file://C:\\path\\to\\repo` are what a Windows user gets by putting
    `file://` in front of a native path, and exactly what `f"file://{tmp_path}"` produces on a
    Windows runner. `urlsplit` ends the authority at the first `/`, so the two spellings land
    differently: the forward-slash one leaves `C:` in the authority, while the backslash one leaves
    the WHOLE `C:\\path\\to\\repo` there, because a backslash is not a urlsplit delimiter.

    The drive reading must account for the ENTIRE authority or there is no drive. That is what keeps
    this from becoming a bypass of the load-bearing authority rule: `file://C:@evil.example.com/x`
    has a host sitting after the colon, its remainder does not start with a path separator, and it
    stays REMOTE. Only `<letter>:` optionally followed by a `\\`-rooted path qualifies.

    Note the drive letter anchors the whole URL to a local volume, so nothing after it can be read
    as UNC by Win32: `C:\\\\host\\share` is a drive-rooted path with a doubled separator, not a
    network location. The caller still runs the shared path test afterwards, which costs only the
    unrealistic `file://C://host/share` spelling and keeps one code path for every `file:` URL.

    `file://C|/path`, the legacy bar spelling, deliberately does NOT qualify and stays REMOTE. RFC
    8089 Appendix E.2 documents the bar only in the PATH (`file:///c|/path`), which has an empty
    authority and already classifies LOCAL here. The bar is legal in neither a host name nor a
    Win32 path, so the authority-position spelling is malformed under both readings, and a loosening
    of the authority rule is the last place to be generous.
    """
    if len(netloc) < 2 or not netloc[0].isascii() or not netloc[0].isalpha() or netloc[1] != ":":
        return False
    rest = netloc[2:]
    return rest == "" or rest[0] == "\\"


def _file_url_is_local(parts: SplitResult) -> bool:
    """RFC 8089 §2: a `file://` URL names THIS machine only when its authority is empty
    (`file:///path`) or exactly `localhost` (`file://localhost/path`), plus the Windows drive letter
    that `urlsplit` parks in the authority slot (see `_is_windows_drive_authority`)."""
    netloc = parts.netloc
    if netloc and not _is_windows_drive_authority(netloc):
        # Userinfo (`file://user@host/path`) or a port is not the RFC 8089 local form. Reject it
        # rather than reason about which part of it git would honour. This also short-circuits the
        # loopback literals (`file://127.0.0.1/repo`, `file://[::1]/repo`), which stay REMOTE by
        # deliberate choice: RFC 8089 lists only the empty authority and `localhost`, and on Windows
        # git rewrites `file://127.0.0.1/share` to `\\127.0.0.1\share`, a real trip through the SMB
        # stack. On POSIX git ignores the authority entirely (verified: `git clone file://127.0.0.1/
        # <path>` clones locally), so calling them remote costs an offline run a visible "needs
        # network tier 1" message. That is the fail-safe direction, and it is a decision, not an
        # accident: a wrong LOCAL answer is a silent broken Tier 0 promise.
        if "@" in netloc or ":" in netloc:
            return False
        if (parts.hostname or "") not in _LOCAL_FILE_HOSTS:
            return False
    # An empty/localhost authority is not sufficient: the PATH can carry a UNC authority of its own
    # (`file:////host/share/repo`, `file://localhost//host/share/repo`, or percent-encoded as
    # `file:///%5C%5Chost%5Cshare`). Decode once, then apply the same authority test.
    return not _names_a_remote_authority(unquote(parts.path))


def is_local_repo(url: str) -> bool:
    """True if *url* names a repo on the local filesystem (an existing directory, or a `file://`
    URL with no remote authority), as opposed to a remote clone URL (`https://`, `git@...`). Local
    repos need no egress, so the CLI can scan them offline (Tier 0), and they bypass the clone cache
    (a local clone is cheap and you almost always want the current committed state, not a day-old
    cached snapshot).

    INVARIANT. True means "resolvable entirely by this machine, with no off-machine name resolution
    or connection", and *deciding that must itself be free of any network-touching I/O*. Both halves
    are load-bearing. `cli.py::_cmd_corpus_scan` calls this to compute `needs_network`, which picks
    the default tier, so classification necessarily runs BEFORE `net.resolve_tier`: any probe done
    here is egress the manifest has already failed to record. So every authority-bearing spelling is
    answered from the string alone and never reaches the filesystem. `agentsec/net.py`'s G5 sandbox
    cannot help, it polices `urllib`/`socket`/`http` imports and a UNC resolution happens below that
    at the filesystem layer.

    The spelling that motivated this (#466 review): a bare `\\\\evil.example.com\\share\\repo` or
    `//evil.example.com/share/repo`, literally what Windows Explorer's address bar produces for a
    network location. `file://` was carved out first, the scheme-less form was not, so it fell
    through to `Path(url).is_dir()`, and on Windows that performs real SMB/NetBIOS resolution as a
    side effect of mere classification. On POSIX those strings are inert, so the harm is
    Windows-specific, on a platform CI validates.

    Known, deliberate false negatives, all of them fail-safe (a visible "needs network tier 1"
    message, never a silent wrong LOCAL answer): a POSIX `//foo/bar` or `///foo/bar`, which are
    legal local paths but implementation-defined per POSIX; and Win32 extended-length
    `\\\\?\\C:\\repo`. Each is accepted in its unambiguous spelling (`/foo/bar`, `C:\\repo`). One
    rule on every platform is the point: a repo list is portable, and the Tier 0 claim CI makes on
    Linux must be the one a Windows dev gets.

    One limitation is inherent rather than chosen: a MAPPED network drive (`Z:\\repo`, `file://Z:/
    repo`) is a network share wearing a drive letter, and no amount of string inspection can tell it
    from a local volume. It classifies LOCAL. That is pre-existing for every plain path this
    predicate has ever accepted (`Path.is_dir()` on a mapped drive also goes over SMB) and is not
    something this rule widens; the string simply does not carry the answer.
    """
    probe = url.strip()
    # `urlsplit` SILENTLY DELETES tab/CR/LF anywhere in the URL (the WHATWG mitigation), so
    # `file://loca\nlhost/x` would parse as host `localhost` and be called local. git does no such
    # thing: it keeps the raw host and resolves it off-machine. Refuse to classify any URL carrying
    # a character whose removal changes the parse.
    if any(c in probe for c in "\t\r\n"):
        return False
    try:
        parts = urlsplit(probe)
    except ValueError:
        return False    # unparseable (e.g. a malformed IPv6 literal); never assume local
    scheme = parts.scheme.lower()
    if scheme == "file":
        return _file_url_is_local(parts)
    # Any other scheme with an authority is a remote transport (`https://`, `ssh://`, `git://`).
    # A ONE-letter scheme is a Windows drive letter, not a URL: `C://repo` splits as scheme "c" +
    # netloc "repo", and it is a perfectly good local path. No registered URI scheme is one letter.
    if parts.netloc and len(scheme) != 1:
        return False
    if _names_a_remote_authority(url):
        return False
    try:
        return Path(url).is_dir()
    except (OSError, ValueError):
        return False


# The scp-like clone spelling git understands: `git@github.com:org/repo.git`. Anchored, and neither
# side may contain `/` or whitespace, so `/home/user@corp/repo` and `C:\Users\me@corp\repo` (which
# has no later `:`) do not match. It is the one clone spelling `urlsplit` cannot see, because it has
# no scheme and no authority.
_SCP_LIKE = re.compile(r"^[^/\s]+@[^/\s]+:")


def is_url_like(url: str) -> bool:
    """True if *url* carries any URL/UNC shape — a `file:` URL, a `scheme://authority`, a leading
    `//` / `\\\\` authority run, or the scp-like `git@host:path` form. Such an entry is NOT a plain
    filesystem path.

    INVARIANT this exists to hold: *every `--repos` entry is either a plain filesystem path or a
    URL-shaped entry, and ONLY a plain filesystem path that does not exist is a typo.* The predicate
    it replaces (`is_remote_url`) asserted the different, false claim `not remote ⇒ local path`: it
    knew only `https?|ssh|git://` plus the scp form, so every other authority-bearing spelling
    (`file://198.51.100.7/share`, `\\\\host\\share`, `//host/share`, `FILE://…`, `HTTPS://…`) fell
    into a third "neither local nor remote" bucket and was reported to the user as a *missing local
    path* — a hard `rc=2` with a factually wrong diagnosis, in place of the tier gate's graceful
    "needs network tier 1" (#477 review, M1). So an `is_local_repo` miss on a url-like entry is a
    ROUTING decision for the tier gate, never a typo.

    DERIVED FROM `is_local_repo`, branch for branch, and that is the point rather than a convenience:
    this is exactly the question *"does `is_local_repo` answer from the string alone, or does it fall
    through to `Path(url).is_dir()`?"* — url-like means the former, plain path means the latter. Two
    subtly different readings of one string is how the M1 gap opened in the first place, so the
    one-letter-scheme carve-out (`C://repo` is a Windows drive, not a URL) and the mixed-separator
    UNC run (`/\\host\\share`) are shared with the classifier instead of being re-derived here.
    """
    probe = url.strip()
    try:
        parts = urlsplit(probe)
    except ValueError:
        return True     # unparseable as a URL — but URL-shaped enough that "missing PATH" is a lie
    scheme = parts.scheme.lower()
    if scheme == "file":
        return True
    if parts.netloc and len(scheme) != 1:   # len 1 = a Windows drive letter, not a scheme
        return True
    if _names_a_remote_authority(probe):
        return True
    return bool(_SCP_LIKE.match(probe))


# Characters no NTFS filename may contain. `:` is the alternate-data-stream separator, so
# `raw/git@github.com:org-repo.json` silently becomes a visible 0-byte `git@github.com` carrying an
# invisible stream — and EVERY scp URL from that host lands on that one file. Worse, git cannot
# check out a path containing `:` on Windows at all (`error: invalid path`), and `corpus-scan.yml`
# does `git add -f corpus-out/`. `/` and `\` are here so a stem can never escape `raw/`.
_FS_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

# RFC 8089 §2 / Appendix E.2 drive-in-path forms: `/C:/x` and the legacy bar `/C|/x`.
_DRIVE_URL_PATH = re.compile(r"^/([A-Za-z])[:|](?=[/\\]|$)")


def _fs_safe(stem: str) -> str:
    """A filename stem that is legal on every platform agentsec runs on."""
    return _FS_UNSAFE.sub("-", stem).strip("-") or "repo"


def _file_url_to_path(url: str) -> str:
    """The filesystem path a `file:` URL names, on THIS platform, from the string alone.

    This is `urllib.request.url2pathname` reimplemented deliberately: `urllib.request` is the egress
    module and `tests/test_net_sandbox.py` pins `agentsec/net.py` as the only module in the package
    allowed to import it (`urllib.parse` — URL *string* handling, no sockets — is explicitly exempt
    there, so the parse half is imported normally).

    Only meaningful for a URL `is_local_repo` has already accepted; a remote authority is not a path.
    """
    parts = urlsplit(url.strip())
    if parts.netloc and _is_windows_drive_authority(parts.netloc):
        # `file://C:/repo` / `file://C:\repo` — urlsplit parks the drive in the AUTHORITY slot and,
        # for the backslash spelling (backslash is not a urlsplit delimiter), the whole path with it.
        return unquote(parts.netloc) + unquote(parts.path)
    path = unquote(parts.path)
    if os.name == "nt":
        # `file:///C:/x` names a drive-rooted Win32 path, so the URL's leading `/` is not part of it.
        # On POSIX the very same string IS a legal absolute path (a directory literally named `C:`),
        # which is why url2pathname is platform-dispatched too. Normalise the legacy bar to a colon.
        drive = _DRIVE_URL_PATH.match(path)
        if drive:
            return drive.group(1) + ":" + path[drive.end():]
    return path


def repo_identity_key(url: str) -> str:
    """The canonical identity of a repo entry — the key that decides whether two `--repos` entries
    are the SAME repo.

    INVARIANT: *the key `corpus_scan` dedupes on and the key `raw_scan_name` names from are the same
    key.* They were not, so `--repos /r /r/ file:///r` reported "Scanning 3 repos" and three rows
    while `raw/` held two files — one silently overwrote another, exit 0, no warning (#477 review,
    M4). Deduping on the raw string also scanned the one repo three times.

    For a LOCAL entry the key is the resolved absolute path, so every spelling of one repo
    (`/srv/repo`, `/srv/repo/`, `file:///srv/repo`, `file://localhost/srv/repo`) collapses to one.
    For a remote entry the URL string is its own identity — two hosts are two repos even when the
    last two path segments match, so resolving is neither possible nor wanted.
    """
    probe = url.strip()
    if not is_local_repo(probe):
        return probe
    raw = _file_url_to_path(probe) if probe.lower().startswith("file:") else probe
    try:
        return str(Path(raw).resolve())
    except (OSError, ValueError):
        return raw


def raw_scan_name(url: str) -> str:
    """Filename stem (no extension) for a repo's raw scan dump under `raw/`. `<org>-<repo>` from the
    last two path segments so remote forks sharing a final segment don't collide. For a LOCAL path —
    which can share its last two segments with a different checkout (`~/a/backend` vs `~/b/backend`) —
    also append a short hash of `repo_identity_key` (the resolved absolute path) so two distinct
    local repos never overwrite each other's `raw/*.json` (backlog #8c).

    The stem is always run through `_fs_safe`, because `raw/` is committed by `corpus-scan.yml` and a
    name git cannot check out on Windows breaks the repo for the platform CI validates. Two ways the
    unsanitized version produced one: an scp URL kept its `git@host:` prefix verbatim, and a local
    `file://` URL was handed to `Path(...)` unconverted, so `file:///tmp` resolved to the literal
    `<cwd>/file:/tmp` — a colon in the name, plus a hash over a bogus CWD-relative path that made the
    same repo's dump name depend on where the scan was run from (#477 review, M2/M3).
    """
    if is_local_repo(url):
        key = repo_identity_key(url)
        resolved = Path(key)
        # A local path uses the OS separator (`\` on Windows), so derive the base via pathlib —
        # NOT str.split("/"), which would leave a Windows path as one giant segment.
        base = _fs_safe(f"{resolved.parent.name}-{resolved.name}")
        return f"{base}-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:8]}"
    # Remote clone URLs are always '/'-separated — but the scp form carries `user@host:` in front of
    # the path, and that colon must not reach the filename.
    path_part = _SCP_LIKE.sub("", url.strip())
    return _fs_safe("-".join(path_part.rstrip("/").removesuffix(".git").split("/")[-2:]))


def _short_name(url: str) -> str:
    """`<parent>/<name>` label for the progress line.

    Same pathlib derivation as `raw_scan_name`, for the same reason: `str.split("/")` leaves a
    Windows path as ONE giant segment, so the progress display printed the whole absolute path as
    the "short" name and `name_width` then padded every other row out to match. `bd364f01` fixed
    that in `raw_scan_name` and left the identical idiom restated here (#477 review, L2).
    """
    if is_local_repo(url):
        resolved = Path(repo_identity_key(url))
        return f"{resolved.parent.name}/{resolved.name}".strip("/") or str(resolved)
    return "/".join(url.rstrip("/").removesuffix(".git").split("/")[-2:])


def unique_raw_scan_names(urls: Sequence[str]) -> list[str]:
    """`raw_scan_name` for each URL, with any residual duplicate stem disambiguated by a hash of the
    URL that would have lost.

    The last line of defence for the invariant *N scanned rows ⇒ N files in `raw/`*. Deduping on
    `repo_identity_key` removes the aliasing cases, but the remote stem is only the last two path
    segments, so `github.com/org/repo` and `gitlab.com/org/repo` are two different repos with one
    name. Rather than widen every existing remote name with a hash (which would rewrite the whole
    committed `raw/` corpus for a rare case), keep the common name and disambiguate on collision —
    so a silent overwrite is not reachable by any input.
    """
    names: list[str] = []
    seen: set[str] = set()
    for url in urls:
        name = raw_scan_name(url)
        if name in seen:
            name = f"{name}-{hashlib.sha256(url.encode('utf-8')).hexdigest()[:8]}"
        seen.add(name)
        names.append(name)
    return names


def local_entry_is_not_a_git_repo(url: str) -> bool:
    """True if *url* is a LOCAL entry that resolves to an existing directory carrying no git
    repository.

    corpus-scan reaches a local repo through `git clone --depth 1 --single-branch <path>`, so
    pointing `--repos` at a plain app directory fails as an opaque `clone-failed` row with nothing
    to act on (#477 review, L3). Now that `--repos` invites local paths and #8e promises "scanned at
    its committed HEAD", `not a git repository` is the likelier of the two user errors — the typo
    gate beside this one only catches a path that does not exist at all.

    Both repository shapes count, so this can never refuse something git could actually clone: a
    WORK TREE has `.git` (a directory, or a FILE for a submodule / linked worktree), and a BARE repo
    has no `.git` at all but does have `HEAD` plus `objects/`. Anything else — including every
    unreadable or racing path — answers False, because this gate is a diagnosis, not a security
    boundary, and a wrong True is a hard `rc=2` on a legitimate repo.
    """
    if not is_local_repo(url):
        return False
    try:
        root = Path(repo_identity_key(url))
        if not root.is_dir():
            return False
        if (root / ".git").exists():            # work tree: .git dir, or .git FILE (worktree/submodule)
            return False
        return not ((root / "HEAD").is_file() and (root / "objects").is_dir())   # bare repo
    except (OSError, ValueError):
        return False


def clone_repo(url: str, dest: Path) -> bool:
    """Shallow-clone *url* into *dest*. Returns True on success. Never raises."""
    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", "clone", "--depth", "1", "--single-branch", url, str(dest)],
            timeout=120,
            capture_output=True,
            encoding="utf-8",
        )
        return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Clone cache — reuse a repo across corpus-scan runs instead of re-cloning fresh
# every time. This is what made routine, repeated corpus-scan runs slow: every
# run re-cloned all ~27 repos from scratch over the network, even though most
# hadn't changed since the last run minutes/hours ago. A cached clone younger
# than `max_age_hours` is reused with ZERO network calls; `force_refresh=True`
# always re-clones an existing cache entry, ignoring its age, so a caller can
# refresh the cache in place without waiting for it to expire. (The CLI's
# `--fresh-corpus` flag takes a different route entirely: it sets `use_cache=False`
# in `corpus_scan`, which clones into a throwaway tempdir and never touches this
# persistent cache at all — see the `use_cache` branch there.)
# ---------------------------------------------------------------------------

_CACHE_MARKER = ".agentsec-cloned-at"


def _corpus_cache_root() -> Path:
    """Persistent local cache dir, OS-appropriate, never inside the repo being audited or
    agentsec's own source tree (so it can't be mistaken for product code by any guard)."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    return base / "agentsec" / "corpus-repos"


def _cache_key(url: str) -> str:
    """A filesystem-safe, collision-resistant directory name for a repo URL."""
    norm = url.rstrip("/").removesuffix(".git")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", norm).strip("-").lower()
    digest = hashlib.sha256(norm.encode("utf-8")).hexdigest()[:10]
    return f"{slug}-{digest}"


def _cache_is_fresh(dest: Path, max_age_hours: float) -> bool:
    marker = dest / _CACHE_MARKER
    if not marker.is_file():
        return False
    try:
        cloned_at = datetime.fromisoformat(marker.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return False  # corrupt/missing marker -> treat as stale, re-clone
    age_hours = (datetime.now(UTC) - cloned_at).total_seconds() / 3600
    return age_hours < max_age_hours


def _clear_readonly_and_retry(func: Callable[..., object], target: str, exc: BaseException) -> None:
    """`shutil.rmtree` error hook (the `onexc` signature: `(func, path, exc)`): fix a
    STATE-dependent failure (a read-only file — e.g. git marks its `.git/objects/pack/*.pack`
    files read-only) before giving up on it.

    A bare re-issued `shutil.rmtree(..., ignore_errors=True)` can only ever recover a
    TIME-dependent lock (a process that eventually releases its handle) — a read-only file
    fails the exact same way on every retry, no matter how many times `_rmtree_robust` loops,
    because nothing about its state changed between attempts (Medium 4 reopen
    review). `os.chmod` + re-invoking the failed removal `func` (`os.unlink`/`os.rmdir`) covers
    that case; anything still unremovable after that (a genuinely open handle, a permission we
    can't change) is swallowed here exactly as `ignore_errors=True` used to swallow everything,
    so `_rmtree_robust` keeps its "never raises" contract either way.

    ADD the write bit onto the existing mode, never ASSIGN `stat.S_IWRITE` outright — that clears
    every other bit too, and on a DIRECTORY it strips read+execute, making the directory
    untraversable and turning a retry's `os.open` into a `PermissionError` that `shutil.rmtree`'s
    fd-based POSIX implementation then routes through this same hook with `func=os.open` — a
    1-arg call that raises `TypeError`, which escapes `_rmtree_robust`'s 'never raises' contract
    and takes the whole corpus-scan run down with it (round-2 Critical 1). The execute
    bit is added only for a directory (`stat.S_ISDIR`), never for a plain file. `except` widened
    to catch that `TypeError` too, alongside the pre-existing `OSError`/`ValueError` cases — the
    contract is 'never raises', so nothing raised here may propagate."""
    del exc  # unused -- we only need func+target to retry; unfixable errors are swallowed below
    try:
        mode = os.lstat(target).st_mode
        add = stat.S_IWUSR | (stat.S_IXUSR if stat.S_ISDIR(mode) else 0)
        os.chmod(target, mode | add)
        func(target)
    except (OSError, TypeError, ValueError):
        pass  # still genuinely stuck -- the retry loop / final exists() check reports that honestly


def _rmtree_robust(path: Path, *, retries: int = 3, delay_seconds: float = 0.5) -> bool:
    """Delete `path` and everything under it, retrying briefly on a failed delete.

    `shutil.rmtree(..., ignore_errors=True)` alone silently gives up on the first failure —
    on Windows, a `git clone` subprocess killed for timing out (see `clone_repo`'s
    `timeout=120`) can leave an orphaned helper process (git spawns a separate transport
    process for https/ssh) holding a file lock for a moment after the parent is gone, so an
    immediate delete right after the kill can fail even though nothing is really still using
    the files. A short retry covers that window (a TIME-dependent lock). It does nothing for a
    STATE-dependent one (e.g. read-only pack files), which is why every attempt also installs
    `_clear_readonly_and_retry` as the `onexc` hook instead of just `ignore_errors=True` —
    that fixes what a bare retry structurally cannot. Returns True if `path` is gone afterward,
    False if something is genuinely still holding it (a real problem worth surfacing, not
    silently swallowing) -- never raises."""
    for attempt in range(retries):
        shutil.rmtree(path, onexc=_clear_readonly_and_retry)
        if not path.exists():
            return True
        if attempt < retries - 1:
            time.sleep(delay_seconds)
    return not path.exists()


# Tri-state, deliberately NOT a `bool` (reopen review, Critical 1/2). The caller used to
# get `(path, used_cache: bool)` and, for the leftover-can't-be-cleared case, `used_cache=False`
# — the EXACT SAME value a clean fresh clone or a clone-failed-and-cleaned-up returns. A caller
# cannot recover the missing distinction from `path` either: it re-derived "is this usable?" from
# `path.is_dir() and any(path.iterdir())`, which reads a corrupted-but-non-empty leftover as
# indistinguishable from a genuinely successful clone (both are a non-empty directory). Three real
# situations were colliding onto one bit. "stuck" is the one that must never again be silently
# folded into "cloned": the caller MUST refuse to hand `path` to `scan_repo()` when it sees this.
CloneCacheStatus = Literal["hit", "cloned", "stuck"]


def clone_repo_cached(
    url: str,
    *,
    cache_root: Path | None = None,
    max_age_hours: float = 168,  # 7 days -- matches this project's existing staleness convention
    force_refresh: bool = False,
) -> tuple[Path, CloneCacheStatus]:
    """Clone into a persistent local cache instead of a fresh tempdir every run.

    Returns `(path, status)`:
      - `"hit"` — a cached clone younger than `max_age_hours` was reused as-is, zero network
        calls (unless `force_refresh` is set, which always re-clones regardless of age).
      - `"cloned"` — a fresh `clone_repo` attempt was made into `path` (no usable cache entry
        existed, or one was cleared first). It may have succeeded or failed; `path` may not
        exist or may be empty on failure — the caller checks that exactly the way it already
        checks `clone_repo`'s own return value.
      - `"stuck"` — a leftover entry from a previous run exists and could NOT be cleared (see
        `_rmtree_robust`). `path` still points at the corrupted, non-empty leftover on purpose
        (so a caller that wants to inspect/report it can), but the caller MUST treat this as
        distinctly unusable: never a valid cache hit, and never handed to `scan_repo()`. This
        deliberately does NOT attempt `clone_repo` into it either: `git clone` refuses a
        non-empty destination and would just fail instantly, silently re-creating the exact
        same stuck half-clone on every future run instead of ever getting a chance
        to retry cleanly."""
    root = cache_root or _corpus_cache_root()
    dest = root / _cache_key(url)
    if not force_refresh and dest.is_dir() and _cache_is_fresh(dest, max_age_hours):
        return dest, "hit"
    if dest.exists() and not _rmtree_robust(dest):
        return dest, "stuck"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if clone_repo(url, dest):
        (dest / _CACHE_MARKER).write_text(datetime.now(UTC).isoformat(), encoding="utf-8")
        return dest, "cloned"
    # A clone that dies mid-flight can leave a corrupted, non-empty `dest` behind. If the cleanup
    # below then ALSO fails (the same Windows kill-then-lock window this module's docstrings
    # describe), dropping that return value used to fall through to "cloned" anyway — the same
    # one-bit collision the pre-existing-leftover branch above already guards against, just on
    # its sibling path (round-2 Critical 2). Check it the same way.
    if not _rmtree_robust(dest):
        return dest, "stuck"
    return dest, "cloned"


def evict_stale_cache(cache_root: Path | None = None, *, evict_after_hours: float = 720) -> int:
    """Delete cache entries not touched within `evict_after_hours` (default 30 days).

    Without this, entries for repos that drop out of the corpus (renamed, unstarred, no longer
    discovered) would accumulate on disk forever — a cached clone is only ever *reused* while fresh,
    but nothing removes it once stale. Entries with a missing/corrupt marker are also evicted (they
    can't be trusted for reuse anyway). Returns the number of entries removed. Never raises."""
    root = cache_root or _corpus_cache_root()
    removed = 0
    try:
        entries = list(root.iterdir()) if root.is_dir() else []
    except OSError:
        return 0
    now = datetime.now(UTC)
    for entry in entries:
        try:
            if not entry.is_dir():  # is_dir() can raise (e.g. PermissionError) on an odd fs
                continue
            marker = entry / _CACHE_MARKER
            try:
                cloned_at = datetime.fromisoformat(marker.read_text(encoding="utf-8").strip())
                stale = (now - cloned_at).total_seconds() / 3600 >= evict_after_hours
            except (ValueError, OSError):
                stale = True  # missing/corrupt marker -> untrustworthy, evict
            if stale:
                shutil.rmtree(entry, ignore_errors=True)
                removed += 1
        except Exception:  # nosec B112 - deliberate: one unreadable cache entry must never abort the eviction pass (runner-layer "never raises", mirrors clone_repo's broad-except)
            continue
    return removed


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def scan_repo(url: str, clone_path: Path, today: date, min_features: int = 3,
              guard_budget: float = DEFAULT_GUARD_BUDGET) -> RepoScan:
    """Detect stack, gate on features, run guards-only audit. All errors captured in .error.

    `guard_budget` (#677) is on by default here above all places: corpus repos are arbitrary
    public clones — exactly the hostile input that hung three scheduled runs at the job
    timeout with zero attribution. A budget kill lands in `.error` and the corpus loop moves
    on to the next repo instead of wedging the whole run."""
    _empty: list[Finding] = []

    # Step 1 — detect
    try:
        profile = detect(clone_path)
    except Exception as exc:
        return RepoScan(
            url=url, features=[], stack_summary="",
            findings=_empty, ran=[], skipped=[],
            error=f"detect-failed: {exc}",
        )

    # Step 2 — stack gate
    if len(profile.features) < min_features:
        return RepoScan(
            url=url,
            features=sorted(profile.features),
            stack_summary=profile.summary(),
            findings=_empty, ran=[], skipped=[],
            error=f"stack-mismatch: {len(profile.features)} features",
        )

    # Step 3 — audit (guards only, no external scanners)
    try:
        result = audit(clone_path, run_scanners=False, today=today, guard_budget=guard_budget)
    except Exception as exc:
        return RepoScan(
            url=url,
            features=sorted(profile.features),
            stack_summary=profile.summary(),
            findings=_empty, ran=[], skipped=[],
            error=f"audit-failed: {exc}",
        )

    # A budget kill is carried in `.error` (#677): the per-repo report line shows it ("!"),
    # and the fp/gap analyses — which filter on `not error` — exclude the repo, because a
    # partial scan is a biased sample for prevalence ratios. The findings that DID complete
    # are still kept on the RepoScan for the artifact.
    error = ""
    if result.guards_budget_exceeded:
        error = "budget-exceeded: " + ", ".join(result.guards_budget_exceeded)

    return RepoScan(
        url=url,
        features=sorted(profile.features),
        stack_summary=profile.summary(),
        unbudgeted=result.guards_unbudgeted,
        findings=result.findings,
        ran=result.ran,
        skipped=result.skipped,
        error=error,
    )


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _guard_count(scan: RepoScan, guard_id: str) -> int:
    """How many findings *guard_id* produced on this one repo."""
    return sum(1 for f in scan.findings if f.check_id == guard_id)


def _sample_and_locations(scans: list[RepoScan], guard_id: str) -> tuple[Finding | None, list[str]]:
    """First finding for *guard_id* across *scans* (the sample) + up to 5 unique locations."""
    sample: Finding | None = None
    locations: list[str] = []
    seen_locs: set[str] = set()
    for s in scans:
        for f in s.findings:
            if f.check_id == guard_id:
                if sample is None:
                    sample = f
                if f.location and f.location not in seen_locs and len(locations) < 5:
                    locations.append(f.location)
                    seen_locs.add(f.location)
    return sample, locations


# The outlier signal is a COMPARISON, so it needs something to compare against: at least two
# distinct applicable repos. Not a tunable — one repo means no basis at all, at any threshold.
_OUTLIER_MIN_REPOS = 2


# M3: `harishsg993010/damn-vulnerable-MCP-server` is SEED_REPOS' one deliberately-
# vulnerable repo -- small, dense, and intentionally packed with real vulnerabilities across its
# `challenges/*` tiers. That is exactly the shape signal 2 (single-repo over-fire outlier) is tuned
# to catch, so its own TRUE positives get misread as FP candidates purely from concentration, not
# from any guard actually over-firing. Verified empirically against a real scoped corpus-scan
# (not assumed from Dean's read-only diagnosis, review): `api-docs-exposed` and
# `command-injection` both outlier-flagged with 100% of their findings landing in this repo's own
# `challenges/*/server*.py` fixtures, each one a real command-injection/exposed-docs vulnerability
# the repo exists to contain, not a guard bug. Excluded from the outlier signal's comparison basis
# entirely (never the spike, never part of "others") -- Dean's "move it to a recall/canary target"
# framing, not his "exclude it" framing, since it stays fully counted for signal 1 (prevalence,
# which needs broad multi-repo agreement and isn't single-repo-exploitable the same way) and for
# gap-candidate analysis elsewhere in this module, where its real vulnerabilities are exactly the
# recall signal the SEED_REPOS comment already says it's there for.
_FP_OUTLIER_EXCLUDED_REPOS = frozenset({
    "https://github.com/harishsg993010/damn-vulnerable-MCP-server",
})


def _fp_outlier_exclusion_key(url: str) -> str:
    """Normalize a URL for matching against `_FP_OUTLIER_EXCLUDED_REPOS` only -- NOT
    `repo_identity_key`, which deliberately keeps distinct remote URL spellings distinct for scan
    deduping/naming. An exact string match on the exclusion set let any other spelling of the
    same excluded repo silently bypass it, including the exact spelling (a trailing `.git`) that
    GitHub search discovery's own `clone_url` (see `discover_repos` above) produces for this repo
    if it is ever auto-discovered rather than seeded, plus a trailing `/`, a different case in the
    owner segment, and `http://` in place of `https://`. Lowercase, strip the scheme, strip a
    trailing `/`, strip a trailing `.git`.
    """
    key = url.strip().lower()
    key = re.sub(r"^https?://", "", key)
    key = key.rstrip("/")
    if key.endswith(".git"):
        key = key[: -len(".git")]
    return key


_FP_OUTLIER_EXCLUDED_REPO_KEYS = frozenset(
    _fp_outlier_exclusion_key(u) for u in _FP_OUTLIER_EXCLUDED_REPOS
)


def outlier_excluded_repos(scans: list[RepoScan]) -> list[str]:
    """The scanned repos `analyze_fps`' single-repo outlier signal leaves out of its comparison
    basis, in scan order, so emitters can disclose the exclusion (round-1 review M1 on #1164).
    An errored scan is not listed: `analyze_fps` skips it entirely, so it was never "excluded"
    from anything, and the disclosure's "still counts for prevalence" would be false for it."""
    return [
        s.url for s in scans
        if not s.error and _fp_outlier_exclusion_key(s.url) in _FP_OUTLIER_EXCLUDED_REPO_KEYS
    ]


def analyze_fps(
    scans: list[RepoScan],
    threshold: float = 0.5,
    min_repos: int = 3,
    outlier_min_count: int = 5,
    outlier_multiple: float = 3.0,
) -> list[FpCandidate]:
    """Surface guards that are likely over-firing, by two complementary signals:

    1. **Cross-repo prevalence** — a guard firing above *threshold* across at least *min_repos*
       applicable repos (the original signal; broad, needs a sample of repos).
    2. **Single-repo over-fire outlier** — a guard producing an anomalously high finding count on
       ONE repo relative to the others. Requires all of: at least two DISTINCT applicable repos (a
       comparison basis); peak-per-repo count >= *outlier_min_count* (absolute magnitude); and the
       peak >= *outlier_multiple* x the next-highest count (concentration); and the peak repo's
       SHARE of its own total findings strictly exceeds every other repo's (size normalization, so
       a raw spike that is really just "this repo is 10x bigger" does not surface). This catches a concentrated FP cluster (e.g. the `auth-dependency`
       cross-file blow-up on a single app repo) that prevalence misses — it needs no `min_repos`
       sample and keys on magnitude, not on fired-or-not. Guards already surfaced by signal 1 are
       not re-emitted. Repos in `_FP_OUTLIER_EXCLUDED_REPOS` (deliberately-vulnerable recall
       targets, not representative app code) never count as the spike or as comparison basis for
       this signal — see that constant's own comment (M3).

       Repos are deduped by URL first: the same repo scanned twice used to become its own
       comparison basis and silently cancel the signal (#476 review).
    """
    # DEDUPE BY URL, once, for BOTH signals. The same repo passed twice (a `--repos` entry that is
    # also in SEED_REPOS, or listed twice in a `--repos-file`) scanned to two identical RepoScans.
    # That inflated the prevalence sample — two copies satisfying `min_repos=3` — and, worse, made
    # a repo its own comparison basis in the outlier test: `peak == rest_peak`, so a duplicate
    # entry silently KILLED the signal it was meant to strengthen (#476 review).
    clean = list({s.url: s for s in scans if not s.error}.values())

    # collect every guard_id seen in any .ran
    all_guard_ids: set[str] = set()
    for s in clean:
        all_guard_ids.update(s.ran)

    prevalence: list[FpCandidate] = []
    seen_guards: set[str] = set()
    for guard_id in sorted(all_guard_ids):
        applicable = [s for s in clean if guard_id in s.ran]
        if len(applicable) < min_repos:
            continue
        fired = [s for s in applicable if _guard_count(s, guard_id) > 0]
        ratio = len(fired) / len(applicable)
        if ratio <= threshold:
            continue
        sample, locations = _sample_and_locations(fired, guard_id)
        if sample is None:
            continue
        prevalence.append(FpCandidate(
            guard_id=guard_id,
            fired_ratio=ratio,
            repos_fired=[s.url for s in fired],
            repos_applicable=[s.url for s in applicable],
            sample_finding=sample,
            fp_sample_locations=locations,
            max_repo_findings=max(_guard_count(s, guard_id) for s in applicable),
            outlier=False,
        ))
        seen_guards.add(guard_id)

    # Signal 2 — single-repo over-fire outliers (guards prevalence didn't already flag).
    outliers: list[FpCandidate] = []
    for guard_id in sorted(all_guard_ids):
        if guard_id in seen_guards:
            continue
        applicable = [
            s for s in clean
            if guard_id in s.ran and _fp_outlier_exclusion_key(s.url) not in _FP_OUTLIER_EXCLUDED_REPO_KEYS
        ]
        # A comparison basis is required. With a single applicable repo, `rest_peak` is 0 and the
        # concentration test degenerates to the absolute floor alone (`peak >= outlier_min_count`),
        # which flags a correctly-working guard on the only repo it applies to (#476 review).
        if len(applicable) < _OUTLIER_MIN_REPOS:
            continue
        spike = max(applicable, key=lambda s: _guard_count(s, guard_id))
        others = [s for s in applicable if s is not spike]
        peak = _guard_count(spike, guard_id)
        rest_peak = max(_guard_count(s, guard_id) for s in others)
        # SIZE NORMALIZATION. Raw counts scale with repo size, so the biggest repo tops the peak on
        # nearly every guard and a raw multiple alone reports "this repo is large", not "this guard
        # misfires". Each repo's guard count is also read as a SHARE of that repo's total findings
        # — the proxy for how much code/noise it has — and the spike must carry a strictly larger
        # share than any other repo. A guard that fires 20 times on a repo with 10x everything and
        # 2 times on a small one is proportionate, and no longer surfaces (#476 review).
        def _share(s: RepoScan, _g: str = guard_id) -> float:
            return _guard_count(s, _g) / max(1, len(s.findings))

        if peak < outlier_min_count or peak < outlier_multiple * rest_peak:
            continue
        if _share(spike) <= max(_share(s) for s in others):
            continue
        fired = [s for s in applicable if _guard_count(s, guard_id) > 0]
        # sample/locations from the spike repo (the one carrying the cluster)
        sample, locations = _sample_and_locations([spike], guard_id)
        if sample is None:
            continue
        outliers.append(FpCandidate(
            guard_id=guard_id,
            fired_ratio=len(fired) / len(applicable),
            repos_fired=[s.url for s in fired],
            repos_applicable=[s.url for s in applicable],
            sample_finding=sample,
            fp_sample_locations=locations,
            max_repo_findings=peak,
            outlier=True,
        ))

    prevalence.sort(key=lambda c: -c.fired_ratio)
    outliers.sort(key=lambda c: -c.max_repo_findings)
    return prevalence + outliers


def analyze_gaps(scans: list[RepoScan]) -> list[GapCandidate]:
    """Return manual checklist items that apply to at least one corpus repo."""
    clean = [s for s in scans if not s.error]
    checklist = load_checklist()
    candidates: list[GapCandidate] = []

    for item in checklist.items:
        if item.status != "manual":
            continue
        # applies_when uses ANY-of semantics (empty = always applies)
        applicable = [
            s for s in clean
            if not item.applies_when or any(f in s.features for f in item.applies_when)
        ]
        if not applicable:
            continue
        candidates.append(GapCandidate(
            item_id=item.id,
            item_title=item.title,
            item_severity=item.severity,
            item_section=item.section,
            applies_when=list(item.applies_when),
            standards=list(item.standards),
            cwe=item.cwe,
            atlas_techniques=list(item.atlas_techniques),
            repos_affected=len(applicable),
            stacks_seen=[s.features for s in applicable],
        ))

    return sorted(
        candidates,
        key=lambda c: (SEVERITY_RANK.get(c.item_severity, 99), -c.repos_affected),
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def _scan_holding_stderr(
    url: str, dest: Path, today: date, min_features: int, held: io.StringIO
) -> RepoScan:
    """`scan_repo` with its stderr held in `held`. `corpus_scan` leaves the `[i/total] name` progress
    line open while a repo scans, so a warning printed mid-scan (an unusable `.agentsec/config.json`,
    detect's read-cap disclosure) split that line and orphaned the result from its repo (#961
    round-2). The caller prints what was held, indented, under the completed line.

    If the scan raises instead (a Ctrl+C; a guard worker that fails to start, which `guard_worker`
    lets propagate on purpose), the held text is printed here, on its own line, before the exception
    propagates: an interrupted scan must not discard what it already said (#961 round-3)."""
    try:
        with contextlib.redirect_stderr(held):
            return scan_repo(url, dest, today, min_features)
    except BaseException:
        if held.getvalue():
            print(file=sys.stderr)  # close the open progress line first
            _print_held(held)
        raise


def _print_held(held: io.StringIO) -> None:
    """Print the stderr `_scan_holding_stderr` held back, indented under its repo's progress line."""
    for line in held.getvalue().splitlines():
        print(f"      {line}", file=sys.stderr)


def corpus_scan(
    repos: list[str] | None,
    count: int,
    today: date,
    *,
    tier: int,
    token: str = "",
    min_features: int = 3,
    manifest: net.Manifest | None = None,
    max_repos: int | None = None,
    use_cache: bool = True,
    cache_max_age_hours: float = 168,
    cache_evict_after_hours: float = 720,
    cache_root: Path | None = None,
    include_seeds: bool = True,
) -> CorpusReport:
    """Clone, scan, and analyse repos. repos=None or [] → auto-discover + seed list.

    `include_seeds` (default True) prepends the curated public `SEED_REPOS`. Set False (CLI:
    `--no-seeds`) to scan EXACTLY the given `repos` — the way to point the loop at a private/local
    app corpus (e.g. real client apps you have access to) without also cloning the public seed set.

    `tier` is the resolved egress tier (corpus-scan is inherently networked — it clones repos —
    so the CLI short-circuits the whole command at tier 0; discovery is a Tier-1 `net.get`).

    `max_repos` is an optional hard ceiling on the total number of repos cloned in one run. Seeds
    are prioritized (the curated baseline stays complete); only the discovered tail is trimmed.
    Default None = no cap (manual/explicit-repo runs are unaffected).

    `use_cache` (default True) reuses a persistent local clone across runs instead of re-cloning
    every repo fresh every time — a repo cloned within `cache_max_age_hours` (default 7 days)
    costs zero network calls on a repeat run. Set `use_cache=False` (CLI: `--fresh-corpus`) for
    the periodic deep-scan mode that always wants the latest code, ignoring cache age entirely.

    `cache_root` overrides the persistent cache location (default `_corpus_cache_root()`); tests
    MUST pass a `tmp_path` here (or rely on the autouse conftest guard) so the suite never mutates a
    developer's real `~/.cache/agentsec/corpus-repos`. `cache_evict_after_hours` (default 30 days)
    bounds how long an unused clone lingers before the pre-scan eviction pass prunes it."""
    discovered = discover_repos(count, tier=tier, token=token, manifest=manifest) if not repos else []
    # Deduplicate on `repo_identity_key`, NOT the raw string — the raw string made `/r`, `/r/` and
    # `file:///r` three entries that were each cloned and scanned, then named onto two files in
    # `raw/`, so the report claimed one more repo than it dumped (#477 review, M4). Insertion order
    # is preserved and the FIRST spelling wins, so the display/scan URL stays what the user typed.
    base = list(SEED_REPOS) if include_seeds else []
    urls: list[str] = []
    _seen_keys: set[str] = set()
    for _entry in base + (repos or discovered):
        _key = repo_identity_key(_entry)
        if _key in _seen_keys:
            continue
        _seen_keys.add(_key)
        urls.append(_entry)
    # Hard ceiling on total clones (cost guard for the scheduled run). Seeds are first in the list,
    # so trimming the tail keeps the full curated baseline and drops only exploratory discovered repos.
    if max_repos is not None and len(urls) > max_repos:
        print(
            f"Capping {len(urls)} repos to --max-repos={max_repos} (seeds prioritized)",
            file=sys.stderr,
        )
        urls = urls[:max_repos]

    if use_cache:
        # Never let a cache-cleanup hiccup abort the run (runner-layer "never raises" contract).
        # evict_stale_cache is itself total; this is belt-and-suspenders (exercised by
        # test_corpus_scan_eviction_failure_does_not_abort_the_run).
        try:
            evicted = evict_stale_cache(cache_root, evict_after_hours=cache_evict_after_hours)
        except Exception as exc:
            print(f"  [corpus] cache eviction skipped: {exc}", file=sys.stderr)
            evicted = 0
        if evicted:
            print(f"  [corpus] evicted {evicted} stale cache entr{'y' if evicted == 1 else 'ies'}",
                  file=sys.stderr)

    scans: list[RepoScan] = []
    total = len(urls)
    short_names = [_short_name(u) for u in urls]
    name_width = max((len(n) for n in short_names), default=0)
    print(f"Scanning {total} repos...", file=sys.stderr)
    for i, (url, sn) in enumerate(zip(urls, short_names, strict=True), 1):
        print(f"  [{i}/{total}] {sn:<{name_width}}", file=sys.stderr, end="  ")
        held = io.StringIO()
        cached = False
        # Egress safety (defense-in-depth for the G5/RFC #135 tier policy): a REMOTE clone is
        # network egress, so refuse it at Tier 0 HERE in the pipeline — independent of whatever the
        # CLI's `needs_network` gate computed — mirroring how `discover_repos` routes through
        # `net.get(tier_required=1)`. A local repo (existing dir / file://) never touches the network,
        # so it is always allowed. This keeps the egress-off-by-default invariant from resting on a
        # single call site.
        if not is_local_repo(url) and tier < 1:
            scan = RepoScan(
                url=url, features=[], stack_summary="",
                findings=[], ran=[], skipped=[],
                error="tier0-network-required",
            )
        # Local repos always clone fresh (a local clone is cheap and staleness is worse than a
        # re-clone); only remote repos use the persistent age-based cache.
        elif use_cache and not is_local_repo(url):
            dest, cache_status = clone_repo_cached(
                url, cache_root=cache_root, max_age_hours=cache_max_age_hours, force_refresh=False,
            )
            cached = cache_status == "hit"
            if cache_status == "stuck":
                # reopen, Critical 1/2: `dest` is a corrupted, non-empty leftover that
                # could not be cleared. It is NOT a valid cache hit -- do not re-derive that from
                # `dest.is_dir() and any(dest.iterdir())` below, which cannot tell a corrupted
                # leftover apart from a genuinely successful clone (both are non-empty). Surface it
                # distinctly (a dedicated .error, not folded into the ordinary "clone-failed" skip)
                # and never hand it to scan_repo().
                scan = RepoScan(
                    url=url, features=[], stack_summary="",
                    findings=[], ran=[], skipped=[],
                    error=f"cache-stuck: leftover clone at {dest} could not be cleared",
                )
            else:
                clone_ok = dest.is_dir() and any(dest.iterdir())
                if not clone_ok:
                    scan = RepoScan(
                        url=url, features=[], stack_summary="",
                        findings=[], ran=[], skipped=[],
                        error="clone-failed",
                    )
                else:
                    scan = _scan_holding_stderr(url, dest, today, min_features, held)
        else:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                dest = Path(tmp) / "repo"
                if not clone_repo(url, dest):
                    scan = RepoScan(
                        url=url, features=[], stack_summary="",
                        findings=[], ran=[], skipped=[],
                        error="clone-failed",
                    )
                else:
                    scan = _scan_holding_stderr(url, dest, today, min_features, held)
        scans.append(scan)
        cache_note = " (cached)" if cached else ""
        if scan.error:
            desc = "stack mismatch" if "mismatch" in scan.error else scan.error[:40]
            sym = "-" if "mismatch" in scan.error else "!"
            print(f"{desc}  {sym}{cache_note}", file=sys.stderr)
        else:
            feats = ", ".join(scan.features[:3])
            n = len(scan.findings)
            unb = " · guards unbudgeted" if scan.unbudgeted else ""
            print(f"{feats}  ✓  {n} finding{'s' if n != 1 else ''}{unb}{cache_note}", file=sys.stderr)
        _print_held(held)

    stack_match_count = sum(1 for s in scans if not s.error)
    return CorpusReport(
        scanned=scans,
        fp_candidates=analyze_fps(scans),
        gap_candidates=analyze_gaps(scans),
        run_date=today.isoformat(),
        corpus_size=len(urls),
        stack_match_count=stack_match_count,
        outlier_excluded_repos=outlier_excluded_repos(scans),
    )


# ---------------------------------------------------------------------------
# Emitters
# ---------------------------------------------------------------------------

def report_to_markdown(report: CorpusReport) -> str:
    lines = [
        f"## Corpus Scan — {report.run_date}",
        f"Scanned {report.stack_match_count}/{report.corpus_size} repos matched target stack",
        "",
    ]

    lines += [f"### FP Candidates ({len(report.fp_candidates)}) — guards that may need tighter patterns", ""]
    if report.outlier_excluded_repos:
        lines += [
            "_The single-repo outlier signal excludes "
            f"{len(report.outlier_excluded_repos)} deliberately-vulnerable recall "
            f"repo{'s' if len(report.outlier_excluded_repos) != 1 else ''} from its comparison basis: "
            + ", ".join(report.outlier_excluded_repos)
            + ". They still count for prevalence and gap analysis._",
            "",
        ]
    if report.fp_candidates:
        lines += ["| Guard | Fire ratio | Peak/repo | Applicable repos | Sample location |",
                  "|---|---|---|---|---|"]
        for c in report.fp_candidates:
            # Both sources are externally-scanned-repo content - `fp_sample_locations` a raw
            # location string, `sample_finding.location` a `Finding` field routed through the
            # same `sanitize_finding()` choke point every emitter must use.
            loc = (
                neutralize_delivery_markers(c.fp_sample_locations[0])
                if c.fp_sample_locations
                else sanitize_finding(c.sample_finding).location
            )
            guard = f"{c.guard_id} ⚠️" if c.outlier else c.guard_id  # ⚠️ = single-repo over-fire outlier
            lines.append(
                f"| {guard} | {c.fired_ratio:.0%} | {c.max_repo_findings} | {len(c.repos_applicable)} | {loc} |"
            )
        lines += ["", "_⚠️ = single-repo over-fire outlier (a concentrated FP cluster on one repo, "
                  "surfaced by count magnitude rather than cross-repo prevalence)._"]
    else:
        lines.append("_None_")
    lines.append("")

    lines += [f"### Gap Candidates ({len(report.gap_candidates)}) — manual items with corpus evidence", ""]
    if report.gap_candidates:
        lines += ["| Item | Severity | Section | CWE | Repos affected |", "|---|---|---|---|---|"]
        for g in report.gap_candidates:
            lines.append(
                f"| {g.item_title} | {g.item_severity} | {g.item_section} "
                f"| {g.cwe or ''} | {g.repos_affected} |"
            )
    else:
        lines.append("_None_")
    lines.append("")

    lines += ["### Scanned repos", ""]
    for s in report.scanned:
        status = s.error if s.error else f"{len(s.findings)} findings · {s.stack_summary}"
        if s.unbudgeted:
            status += " · guards ran unbudgeted (worker failed to start)"
        lines.append(f"- {s.url} — {status}")

    return "\n".join(lines) + "\n"


def report_to_json(report: CorpusReport) -> str:
    """Full CorpusReport as JSON string. default=str handles any stray non-serializable types."""
    return json.dumps(dataclasses.asdict(report), indent=2, ensure_ascii=False, default=str)


def report_to_terminal(report: CorpusReport) -> str:
    """TTY-optimised summary. Technical (guard IDs, ratios) + non-technical (titles) in one view."""
    SEP = "─" * 65
    lines = [
        SEP,
        f"  Corpus Scan — {report.run_date}  "
        f"{report.stack_match_count}/{report.corpus_size} repos matched",
        SEP,
        "",
    ]

    if report.fp_candidates:
        lines.append("  Guards that may need tightening")
        for c in report.fp_candidates[:5]:
            count_str = f"{len(c.repos_fired)}/{len(c.repos_applicable)} repos ({c.fired_ratio:.0%})"
            tag = f"  [outlier: {c.max_repo_findings} on 1 repo]" if c.outlier else ""
            # `sample_finding` is sourced from an EXTERNALLY-SCANNED repo (corpus-scan target),
            # so `sanitize_finding()` here is the same choke point every emitter of a `Finding`
            # must use, not just a defensive extra.
            title = sanitize_finding(c.sample_finding).title
            lines.append(f"  {c.guard_id:<26} {count_str:<22}  {title}{tag}")
        if len(report.fp_candidates) > 5:
            lines.append(f"  ... and {len(report.fp_candidates) - 5} more in fp-candidates.json")
    else:
        lines.append("  No guards fired on 50%+ of repos — patterns look tight")
    if report.outlier_excluded_repos:
        n = len(report.outlier_excluded_repos)
        lines.append(f"  (outlier signal excludes {n} recall repo{'s' if n != 1 else ''}: "
                     + ", ".join(report.outlier_excluded_repos) + ")")
    lines.append("")

    if report.gap_candidates:
        lines.append("  Risks in real repos without a guard yet")
        for g in report.gap_candidates[:5]:
            sev = g.item_severity.upper()[:4]
            lines.append(
                f"  {sev:<6}  {g.item_title[:44]:<44}  {g.repos_affected} repos  [{g.item_id}]"
            )
        if len(report.gap_candidates) > 5:
            lines.append(f"  ... and {len(report.gap_candidates) - 5} more in gap-candidates.json")
    else:
        lines.append("  No undetected risks found in corpus")
    lines.append("")

    lines += [
        f"  Saved to corpus-out/{report.run_date}/",
        f"  fp-candidates.json ({len(report.fp_candidates)})"
        f"  ·  gap-candidates.json ({len(report.gap_candidates)})"
        f"  ·  corpus-report.md",
        SEP,
    ]
    return "\n".join(lines)
