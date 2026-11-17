"""Stack detection — fingerprint a target repo into a `StackProfile`.

The profile's `features` set is what the check registry maps onto: a check only
runs when the stack feature it guards is present (the applicability/N/A rule).
Detection is glob + manifest + bounded import-scan; dependency-free and bounded
(skips vendored/build dirs and caps how many files it reads).
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from agentsec.arm import is_arm_template_text
from agentsec.cfn import is_cfn_template_text
from agentsec.k8s import is_k8s_manifest_text
from agentsec.patterns import APT_INSTALL
from agentsec.walk import walk_files


def _names_dep(blob: str, name: str) -> bool:
    """True if `name` appears in the manifest blob as a real dependency token
    (`django==`, `"flask"`, `flask>=…`) — not as a substring of a plugin
    (`flask-cors`) or in prose. `blob` is already lowercased."""
    return re.search(rf"""(?:^|[\s"'(]){re.escape(name)}(?:[=<>~!\[\s"')]|$)""", blob, re.M) is not None


# Python LLM SDK distribution names, checked against the dependency MANIFEST.
#
# The import scan alone is not enough: it covers only the first `_MAX_PY_SCAN` .py files in
# sorted walk order, so on a real-sized app `alembic/versions/*` wins the alphabet and the
# `app/` module that does `from openai import OpenAI` is never read. Measured: the same repo
# detects `llm` with 10 alembic files and does NOT with 250, dropping ~40 guards and every
# checklist item gated on `llm` (#465 review). `langchain` and `pydantic-ai` were already
# matched on the manifest, so the SDKs were the odd ones out. Since #566 the scan skips non-owned
# trees (`alembic/`, `examples/`, …), so that particular crowding is gone, but a repo with more
# than `_MAX_PY_SCAN` owned files still hits the cap, and the manifest arm still covers it.
#
# `_declares_py_dep` anchors to a real dependency DECLARATION shape, so a model-name string
# (`"openai/text-embedding-3-small"`), a `#` comment, or a prose `description` does not match — the
# same protection the import-side pattern documents.
_PY_LLM_DISTS = (
    "openai", "anthropic", "litellm", "cohere", "groq", "together", "mistralai", "ollama",
    "instructor", "openai-agents", "llama-index", "llama-index-core", "dspy", "dspy-ai",
    "google-generativeai", "google-genai", "vertexai", "google-cloud-aiplatform", "transformers",
    # CrewAI drives an LLM by construction (agents, tasks, `crewai[tools]`); a CrewAI app that
    # declares only these is an LLM app, so `llm`-gated guards (crewai-rce-chain) must select it.
    "crewai", "crewai-tools",
)


# A `keywords` array is prose, not a dependency list, and it wears the same quoted-entry shape a
# real dependency array does (`["openai"]`), so a package advertising itself with the keyword would
# be read as depending on the SDK — the exact false positive review #395 hit on the import side.
# Blanked before the dependency check below (both the TOML `keywords = [...]` and the package.json
# `"keywords": [...]` spellings).
_KEYWORDS_ARRAY = re.compile(r"""["']?keywords["']?\s*[:=]\s*\[[^\]]*\]""", re.I | re.S)

# Extensions for programming languages `detect()` never reads — genuinely different from "not
# code" (docs/config/data), which this table deliberately never lists (docs/knowledge/design-
# stack-coverage-disclosure.md's "allowlist, not blocklist" rationale: the set of non-code
# extensions is unbounded, the set of real language extensions is small and stable). Only
# extensions here, or in the suffix set `detect()` already parses below, ever count toward
# `foreign_languages` — a `.md`/`.json`/`.yaml` file is invisible to this feature, never
# misclassified as an unscanned language.
#
# `.go`/`.rb`/`.java` intentionally NOT here: once a language gets real detect() support (Go,
# then Ruby, then Java — for both of the latter, real guard coverage
# lands in the same PR as detection, so neither ever spends a session in uncovered_stacks the way
# Go's own comment describes but its code never actually enforced), it moves out of "foreign" and
# into the primary suffix-detection block below — never counted in both places at once (a repo
# would otherwise be double-reported as "unscanned language" AND "no guards yet" for the same
# language). See feat/go-stack-detection.
# `.php` intentionally NOT here for the same reason: PHP has real guards from the
# moment detection lands, so it graduates straight from "foreign" to fully covered — it never
# passes through `uncovered_stacks` at all (same shape as Ruby/Java, feat/prob328/feat/prob329).
# `.rs` intentionally NOT here either: Rust gained real detect() support the same way
# — dependency-version-floor's Cargo.lock scan is real guard coverage from the moment detection
# lands, so it never passes through `uncovered_stacks`, same shape as PHP/Ruby/Java.
_FOREIGN_LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".cs": "C#",
    ".kt": "Kotlin", ".kts": "Kotlin", ".swift": "Swift", ".cpp": "C++", ".cc": "C++",
    ".hpp": "C++", ".c": "C", ".h": "C", ".scala": "Scala", ".dart": "Dart",
}
# Below this file count, a single incidental script (a one-off `deploy.rb` helper in an
# otherwise pure-Python repo) doesn't warrant a warning on every scan — see the design doc's
# "Rejected approaches" for why this is a flat count, not a percentage.
_FOREIGN_LANGUAGE_FLOOR = 5

# Docker base images that ship a COMPILED Go binary as their documented primary process, with
# zero Go *source* anywhere in the repo that merely `FROM`s them — the artifact-layer sibling of
# the foreign-language census above. A `.go`-file walk (`foreign_languages`/`uncovered_stacks`
# below) reports "nothing to see" for a repo that runs `FROM caddy:2` and never touches Go source
# at all, which is a TRUE statement about the repo's own tree that leads to a FALSE conclusion
# ("no Go here" when Go is very much here, just not as source). Every real Go security incident on
# such a repo comes from the artifact layer (a stale prebuilt binary, transitive deps in a
# builder's own go.mod nobody re-reads, a wrong scan target between builder/final Docker stages) —
# none of which a source census could ever see. Logged as a known gap after Dean ran this exact table
# against his own production repo (the Caddy example); this table is
# Dean's own suggested smallest v0 — "a grep and a dict", the same shape as Mechanism B
# (`_UNGUARDED_DEPENDENCIES` below).
#
# Keys are the BARE image name: the final `/`-separated path segment, tag/digest stripped
# (`bitnami/vault:1.15` -> `vault`, `caddy:2` -> `caddy`), matched EXACTLY — never a substring —
# so an unrelated image whose name merely CONTAINS a known one (`vaultwarden`, an unrelated
# password manager with no relation to HashiCorp Vault) does not false-positive. See
# `_bare_image_name` below. Curated and evidenced, not exhaustive — a short, high-confidence list
# of images whose own docs describe a Go binary as the thing the image runs:
_GO_BASE_IMAGES: dict[str, str] = {
    "caddy": "Caddy",              # hub.docker.com/_/caddy — Go web server / reverse proxy
    "traefik": "Traefik",          # hub.docker.com/_/traefik — Go reverse proxy / ingress controller
    "vault": "HashiCorp Vault",    # hub.docker.com/r/hashicorp/vault — Go secrets manager
    "consul": "HashiCorp Consul",  # hub.docker.com/r/hashicorp/consul — Go service mesh / discovery
    "nomad": "HashiCorp Nomad",    # hub.docker.com/r/hashicorp/nomad — Go workload orchestrator
    "terraform": "Terraform",      # hub.docker.com/r/hashicorp/terraform — Go infrastructure-as-code CLI
    "grafana": "Grafana",          # hub.docker.com/r/grafana/grafana — Go backend server
    "prometheus": "Prometheus",    # hub.docker.com/prom/prometheus — Go metrics / monitoring server
    "minio": "MinIO",              # hub.docker.com/r/minio/minio — Go S3-compatible object storage
    "etcd": "etcd",                # quay.io/coreos/etcd — Go distributed key-value store
    "cockroach": "CockroachDB",    # hub.docker.com/r/cockroachdb/cockroach — Go distributed SQL database
    "influxdb": "InfluxDB",        # hub.docker.com/_/influxdb — Go time-series database
}
# ingress-nginx's controller image ("registry.k8s.io/ingress-nginx/controller") was considered and
# rejected: its bare last-path-segment is "controller", a name too generic to key a table on — any
# unrelated, non-Go image someone names "controller" would false-positive. Fixing that needs
# multi-segment path matching this table's exact-bare-name design doesn't do; not worth the
# complexity for one entry. Revisit if multi-segment matching is ever added for another reason.

# Dependencies naming a technology agentsec recognizes but has no guard for yet — the
# generalized form of the uncovered-stack recogniser below. Every entry gets `_names_dep`'s
# substring-safe declaration matching for free (`django==`, `"flask"`, not `flask-cors`). A
# name only belongs here if no guard currently covers it — verified, not assumed, before each
# addition (`test_unguarded_dependency_names_have_no_existing_guard` is the drift gate that
# keeps it honest if a guard is built for one of these later). `pymongo`/`motor` were
# considered and rejected: `nosql_metadata_injection.py` already detects them directly.
_UNGUARDED_DEPENDENCIES: dict[str, str] = {
    "django": "django",
    "flask": "flask",
    "celery": "celery",
}

# `FROM [--platform=...] <image>[:<tag>|@<digest>] [AS <stage>]` — structurally the same shape
# `guards/docker_latest_base_tag.py`'s `_FROM_INSTRUCTION` matches. Re-derived here rather than
# imported: `guards/base.py` imports `StackProfile` FROM this module, so importing back from there
# would be circular. Group 2 (the `AS <stage>` alias, if any) lets later `FROM <stage>` references
# be told apart from a real pullable image, same as that guard does.
_FROM_INSTRUCTION = re.compile(
    r"^[^\S\n]*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def _bare_image_name(image_ref: str) -> str:
    """The bare, matchable name from a `FROM` image reference: a content digest stripped, the
    final `/`-path segment taken (so a registry host with its own colon — `registry:5000/app` —
    is never mistaken for a tag), then the `:tag` suffix stripped. Lowercased so `_GO_BASE_IMAGES`'
    keys (already lowercase, the registry convention) match regardless of source casing.
    `bitnami/vault:1.15` -> `vault`; `caddy:2` -> `caddy`; `registry:5000/caddy` -> `caddy`."""
    image_ref = image_ref.split("@", 1)[0]  # drop a content digest, if present
    last_segment = image_ref.rsplit("/", 1)[-1]
    return last_segment.split(":", 1)[0].lower()


def _image_tag(image_ref: str) -> str | None:
    """The explicit `:tag` suffix from a `FROM` image reference, or `None` when there is none
    (an implicit `:latest`, or a `@digest`-pinned reference instead). Mirrors `_bare_image_name`'s
    own digest-then-path-segment handling so the two always agree on what the taggable part is —
    used alongside it (not merged into it) to keep that function's existing callers/tests untouched
    while `StackProfile.docker_base_images` also needs the tag, not just the bare name."""
    image_ref = image_ref.split("@", 1)[0]
    last_segment = image_ref.rsplit("/", 1)[-1]
    return last_segment.split(":", 1)[1] if ":" in last_segment else None


def _strip_trailing_comment(line: str) -> str:
    """`line` with a whole-line or trailing `#`/`//` comment removed.

    THE INVARIANT: **a `#`/`//` begins a comment only when it is OUTSIDE a string literal and is
    not glued to the token on its left** (i.e. it is at line start or preceded by whitespace).

    Both halves are load-bearing and each has already cost a bug:

    - *not glued* keeps `pass#word`, `http://host` and a PEP 508 direct-URL fragment
      (`openai @ https://host/o.whl#sha256=…`) intact.
    - *outside a string* is the half the first cut of this helper missed. A regex that strips from
      the first whitespace-preceded `#` to end of PHYSICAL line deletes everything after a `#` that
      merely sits inside an earlier quoted value — and `["requests # legacy note", "openai>=1.0"]`
      is valid TOML whose second entry is a REAL dependency (`tomllib` parses both entries; an
      installer installs both). Eating it makes `_py_llm_manifest_dep` fail closed on an app that
      really does ship an LLM SDK, and 41 guards gate on the `llm` feature it feeds — the fail-open
      direction, and the reason this helper exists at all.

    So the scan is a one-pass, quote-state machine over the line:

    - a `"`/`'` OPENS a string only when it is not glued to the right of a word character — an
      apostrophe in prose (`it's`, `don't`, `O'Neil`) is not a delimiter, and treating it as one
      would leave the rest of the line looking "in string" and its real comment unstripped;
    - inside a string only the MATCHING delimiter closes it, so `"it's fine"` is one string and a
      `#` inside it is text, not a comment;
    - a backslash escapes the next character inside a `"…"` string only (TOML literal `'…'`
      strings and their requirements/env cousins have no escapes).

    State is per line, never carried across lines: the callers' dependency-declaration shapes are
    line-anchored, and a per-line reset means one unbalanced quote (a TOML `\"\"\"` block opener, a
    stray apostrophe) can never poison the lines that follow. Total: never raises."""
    quote = ""  # the delimiter of the string literal we are inside; "" when outside
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2  # escaped char (\" \\ …) — never closes the string
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ('"', "'") and not (i and (line[i - 1].isalnum() or line[i - 1] == "_")):
            quote = ch
            i += 1
            continue
        if (ch == "#" or line.startswith("//", i)) and (i == 0 or line[i - 1].isspace()):
            return line[:i]
        i += 1
    return line


def _strip_manifest_comments(blob: str) -> str:
    """`blob` with every whole-line and trailing `#`/`//` comment removed, line structure kept
    (the dependency-declaration shapes below are line-anchored, so lines must not be joined).
    `splitlines()` also normalizes a CRLF checkout, so the `$` anchors below still bite."""
    return "\n".join(_strip_trailing_comment(line) for line in blob.splitlines())


def _declares_py_dep(blob: str, name: str) -> bool:
    """True if `name` is DECLARED as a Python dependency in the manifest blob.

    Unlike `_names_dep` — which matches a token ANYWHERE, including inside prose — this is anchored
    to the two shapes a Python dependency declaration actually takes, mirroring how `_PY_LLM_IMPORT`
    is anchored to the `import` keyword rather than to a bare occurrence:

    - a LINE whose first token is the name: a `requirements.txt` entry (`openai`, `openai==1.2.3`,
      `openai[datalib] >= 1.0`, `openai ; python_version >= "3.9"`, `openai @ https://…`) or a
      poetry `[tool.poetry.dependencies]` table key (`openai = "^1.2.3"`);
    - a QUOTED entry: a PEP 621 `dependencies = ["openai>=1.0"]` array item (single- or multi-line)
      or a package.json dependency key (`"openai": "^4.20.0"`).

    A mention that is NOT a declaration therefore cannot match: a `#` comment
    (`# migrated off openai in 2024`, a commented-out `# "openai>=1.0",` array line — comments are
    stripped by the caller), a prose field (`description = "…not an openai wrapper"`, where the name
    is preceded by a space rather than a quote or line-start), or a model-name string
    (`"openai/text-embedding-3-small"`, where `/` is not a version specifier). Detection is upstream
    of the whole guard layer, so a false positive here switches on every `llm`-gated guard for an app
    with no LLM dependency at all. `blob` is already lowercased."""
    n = re.escape(name)
    extras = r"(?:[ \t]*\[[^\]\n]*\])?"           # PEP 508 extras: `openai[datalib]`
    spec = r"[=<>~!;@]|$"                          # version specifier / marker / end of declaration
    line_form = rf"^[ \t]*{n}{extras}[ \t]*(?:{spec})"
    quoted_form = rf"""["']{n}{extras}[ \t]*(?:["']|{spec})"""
    return re.search(rf"(?:{line_form})|(?:{quoted_form})", blob, re.M) is not None


def _py_llm_manifest_dep(manifest_text: str) -> bool:
    """True if the dependency manifest DECLARES a Python LLM SDK."""
    blob = _KEYWORDS_ARRAY.sub(" ", _strip_manifest_comments(manifest_text))
    return any(_declares_py_dep(blob, name) for name in _PY_LLM_DISTS)


def _py_graphql_manifest_dep(manifest_text: str) -> bool:
    """True if the dependency manifest DECLARES a Python GraphQL server library."""
    blob = _KEYWORDS_ARRAY.sub(" ", _strip_manifest_comments(manifest_text))
    return any(_declares_py_dep(blob, name) for name in _PY_GRAPHQL_DISTS)


def _js_dep(blob: str, name: str) -> bool:
    """True if `name` appears in the manifest blob as a package.json dependency-declaration
    KEY (`"openai": "^4.20.0"`) — not as a bare string elsewhere, e.g. a `"keywords": ["openai"]`
    tag, which names the package without the project actually depending on it (review #395 Major
    finding: that exact shape previously set the `js-llm-sdk`/`llm` feature on a project with no
    real LLM SDK dependency, activating every LLM-gated guard). The scoped-package form
    (`"@anthropic-ai/sdk"`) works the same way. `blob` is already lowercased."""
    return re.search(rf'"{re.escape(name)}"\s*:', blob) is not None


# Common Python LLM/agent SDK imports. Anchored to the `import` / `from ... import` keyword so a bare
# occurrence — a model-name string (`"openai/text-embedding-3-small"`), a comment, a requirements
# pin (`openai==1.2`), or a pyproject `keywords = ["openai"]` — does NOT false-positive the `llm`
# feature (mirrors the review #395 anchoring lesson: activating every LLM-gated guard on a non-LLM
# app is a Major bug). `import_blob` is already lowercased. The `\b` after each name keeps
# `openai_helpers` / `anthropic_utils` (unrelated third-party libs) from matching.
_PY_LLM_IMPORT = re.compile(
    r"(?:^|\n)[ \t]*(?:"
    # `import openai` / `from openai import ...` (and the SDK's dotted google forms
    # `import google.genai` / `from google.generativeai import ...`).
    r"(?:from|import)[ \t]+"
    r"(?:openai|anthropic|litellm|cohere|groq|together|mistralai|ollama|instructor"
    r"|google\.(?:generativeai|genai)|crewai(?:_tools)?)\b"
    # The google-genai SDK's documented headline form is `from google import genai` — the package
    # name alone is `google`, too broad to match, so this shape is called out explicitly. Match
    # genai/generativeai ANYWHERE in the imported-name list — a single-line list
    # (`from google import types, genai`) or a parenthesized multi-line one — while staying bounded
    # to the import statement (the single-line list stops at the newline, the parenthesized one at
    # `)`), so a `genai` on a later unrelated line can't be swept in.
    r"|from[ \t]+google[ \t]+import[ \t]+(?:\([^)]*?|[\w, \t]*?)\b(?:genai|generativeai)\b"
    r")"
)

# Python GraphQL server library distribution names, checked against the dependency MANIFEST —
# gates the `graphql` stack feature (the `graphql-mutation-idor` guard, NS-2). Scoped to
# Python-side libraries only: the guard this feeds resolves resolver functions via `iter_functions`
# (Python AST), so a JS/TS GraphQL server (Apollo, GraphQL Yoga) would set a feature no guard yet
# consumes — out of scope until a JS-side resolver guard exists.
_PY_GRAPHQL_DISTS = ("strawberry-graphql", "ariadne", "graphene", "graphql-core")

# Anchored to the `import`/`from ... import` keyword, mirroring `_PY_LLM_IMPORT`'s reasoning: a bare
# occurrence (a comment, a requirements pin already caught by `_declares_py_dep`, a prose mention)
# must not flip a stack feature that gates a whole guard on.
_PY_GRAPHQL_IMPORT = re.compile(
    r"(?:^|\n)[ \t]*(?:from|import)[ \t]+(?:strawberry|ariadne|graphene|graphql)\b"
)

_MANIFESTS = (
    "requirements.txt", "pyproject.toml", "package.json", ".env.example", ".env.sample",
)
# "go.mod" deliberately NOT here (#554 review, Dean, Major, verified) — several detectors search
# the shared `manifest_text` blob with UNANCHORED substring checks (`"stripe" in manifest_text`),
# and a Go module path is a full URL, so an ordinary Go dependency
# collides: `github.com/stripe/stripe-go` or `github.com/supabase-community/supabase-go` in go.mod
# would flip `payments`/`db` on for a repo agentsec cannot actually scan, sending 14 Python/SQL-only
# guards into "Checks run" with zero findings instead of "Skipped (N/A)" — a clean bill of health
# for a stack that was never read. Go detection does not need this: `.go`-suffix presence alone
# drives `prof.languages`/`uncovered_stacks` (below), independent of manifest content. If a future
# guard needs real go.mod content (module graph, replace directives), read it as its own dedicated
# parse — never add it back to this shared blob, since any covered technology's name inside a Go
# module path (github.com/prisma/…, github.com/vercel/…) collides the same way.
#
# `"supabase" in manifest_text` was the second example this rationale cited, and #481 has since
# ANCHORED it (a real import / `@supabase/*` key / dep line / `SUPABASE_*` assignment / project
# host / CLI layout), so `github.com/supabase-community/supabase-go` would no longer flip `db`.
# The conclusion is unchanged and the example above is the live one: the payments arm is still a
# bare substring, so go.mod stays out. Anchoring the remaining detectors is the way to retire this
# constraint, one detector at a time — not adding go.mod back while any of them is unanchored.
_MAX_PY_SCAN = 200  # cap the import-scan so detection stays fast on big repos
_MAX_SH_SCAN = 200  # cap the provisioning-script (*.sh) content scan (mirrors _MAX_PY_SCAN)
_MAX_YAML_SCAN = 200  # cap the YAML content scan (K8s-manifest + Ansible playbook-shape; mirrors _MAX_SH_SCAN)
# Path segments that mark archived/dead trees — a finding in archived code is far less
# likely to be live/exploitable. Three consumers: here, to keep an old/**/sql copy from
# shadowing the live top-level sql/ (see #111); `prioritize.reachability`, which always
# DEMOTES findings in these trees (never drops); and `config`, which exposes this as the
# recommended default set a repo can opt into for the stronger guard SUPPRESSION.
ARCHIVE_SEGMENTS = frozenset(
    {"old", "archive", "archived", "deprecated", "backup", "backups", "legacy"}
)

# The single hardwired list of UNIVERSAL non-product source conventions (test/fixture/migration/
# story trees) — a regex alternation of directory-segment names, shared as the one source of truth
# by BOTH the guard DROP gate (`guards.base._NONPROD_PATH` / `is_nonproduct_path`) and the report
# DEMOTE gate (`prioritize._NON_PRODUCT`). They differ by ACTION (drop vs demote), not membership.
# The bar for inclusion here: a *universal* convention with ~zero product-code overlap (mostly the
# names Semgrep/SonarQube ship as defaults; `alembic` migration plumbing was added from the round-2
# corpus, §A.2). Fuzzy / repo-specific dirs (`evals`, `seed`, `scripts`, `tools`, `docs`, …) are
# deliberately NOT here — they are opt-in per repo via `.agentsec/config.json` `nonproduct_paths` and
# surfaced by the exclude advisor. Package-manager/build dirs are NOT here either —
# `walk.DEFAULT_EXCLUDE_DIRS` already drops them at scan time (Layer 0), so they never reach a
# finding. A HAND-vendored tree (`third_party/`, `vendor/`) is not dropped by Layer 0; detect
# scopes those itself, for stack signals only, via `_VENDORED_DIRS` below (#481, #566).
# NOTE: `.claude/` is deliberately NOT here — it is the *attack surface* for `ai-instruction-poisoning`
# / `claude-code-compromise` / the MCP guards (poisoned agent instructions live there), so those guards
# MUST scan it. A per-guard `.claude/` skip (e.g. a doc-prose false positive) belongs in that guard, not
# in this shared default list.
NONPRODUCT_DIR_ALT = (
    r"tests?|__tests__|__mocks__|fixtures?|examples?|samples?|migrations?|alembic|e2e|"
    r"specs?|stories|\.storybook|docs_src|testdata"
)

# Directory names holding code this repo did not write. `walk.DEFAULT_EXCLUDE_DIRS` drops the
# package-manager ones (`node_modules`, `site-packages`, …) before anything sees them, but a
# hand-vendored tree is not dropped anywhere, so a detector keying on a directory LAYOUT has to
# exclude it explicitly or it will read somebody else's project as this one (#481 review round 3).
# `thirdparty` (no separator) and `testdata` (the Go convention, newly relevant now that Go
# detection has landed) are here rather than in NONPRODUCT_DIR_ALT because that list is shared with
# the guard/prioritize layers, where widening changes which FINDINGS are demoted. This set only
# decides whose directory LAYOUT counts as a stack signal, so it can carry the long tail safely.
_VENDORED_DIRS = frozenset({
    "third_party", "third-party", "thirdparty", "vendor", "vendored", "external", "contrib",
    "testdata", "__fixtures__",
})
# The manifest/import blobs (#566) use a narrower set: `external` and `contrib` also commonly hold
# OWNED code (an `app/external/` of API clients, `django/contrib/`). For the layout arm the cost of
# that ambiguity is one Supabase signal; for the blobs it is every manifest and import detector, and
# the two errors are not symmetric. Treating an owned `app/external/llm.py` as vendored drops `llm`
# and its guard family with nothing disclosed, while counting a vendored one turns on guards whose
# findings are visible and can be excepted. So the blobs exclude only the names that unambiguously
# mean someone else's code (#566 review R1-M1).
_BLOB_VENDORED_DIRS = _VENDORED_DIRS - {"external", "contrib"}
_NONPRODUCT_SEGMENT = re.compile(rf"^(?:{NONPRODUCT_DIR_ALT})$", re.I)


def _owned_parts(dir_parts: tuple[str, ...], vendored: frozenset[str]) -> bool:
    """True if no repo-relative directory segment in `dir_parts` is a non-product segment or one
    of the `vendored` names. The one ownership test detect uses: `_owns_dir` (the directory-layout
    arms) passes `_VENDORED_DIRS`, and the manifest/import blob aggregation (#566) passes the
    narrower `_BLOB_VENDORED_DIRS`."""
    return not any(
        _NONPRODUCT_SEGMENT.match(seg) or seg.lower() in vendored for seg in dir_parts
    )


def _owns_dir(d: Path, root: Path) -> bool:
    """True if `d` looks like a directory THIS repo owns, rather than a vendored or sample copy
    of someone else's project.

    Tests only the segments ABOVE `d` and BELOW `root`, never `d` itself or anything under it:

    - below `d` cannot be tested because the shared `NONPRODUCT_DIR_ALT` list contains
      `migrations?`, so a full `supabase/migrations/` path would reject every legitimate one;
    - above `root` must not be tested because those segments belong to wherever the repo happens
      to be checked out. A clone living in `~/examples/` or a CI workspace under `/tmp/test-123/`
      is not a sample project, and judging it by its parent directory would make detection depend
      on the machine rather than the repo.

    `apps/backend/supabase/` (an ordinary monorepo) is owned; `examples/demo/supabase/` and
    `third_party/lib/supabase/` are not."""
    try:
        inside = d.relative_to(root).parent.parts
    except ValueError:      # not under root — cannot reason about ownership, so do not claim it
        return False
    return _owned_parts(inside, _VENDORED_DIRS)


@dataclass
class StackProfile:
    root: Path
    languages: set[str] = field(default_factory=set)
    backend_framework: str | None = None      # "fastapi"
    llm_framework: str | None = None           # "pydantic-ai" | "langchain"
    db: str | None = None                      # "supabase" | "postgres"
    frontend: str | None = None                # "vite-react"
    package_managers: set[str] = field(default_factory=set)
    python_dirs: list[str] = field(default_factory=list)  # repo-relative
    go_dirs: list[str] = field(default_factory=list)  # repo-relative, mirrors python_dirs
    php_dirs: list[str] = field(default_factory=list)  # repo-relative, mirrors python_dirs
    ruby_dirs: list[str] = field(default_factory=list)  # repo-relative, mirrors python_dirs/go_dirs
    java_dirs: list[str] = field(default_factory=list)  # repo-relative, mirrors python_dirs
    frontend_dir: str | None = None
    sql_dir: str | None = None
    has_docker: bool = False
    has_k8s_manifest: bool = False             # a Pod-shaped K8s workload manifest (see agentsec.k8s)
    has_cfn_template: bool = False             # an AWS CloudFormation template (see agentsec.cfn)
    has_arm_template: bool = False             # an Azure Resource Manager template (see agentsec.arm)
    has_rls_sql: bool = False
    has_payments: bool = False                 # Stripe / billing
    has_ansible: bool = False                  # Ansible playbook/role tree present
    features: set[str] = field(default_factory=set)
    # The audit's "today" (set by audit() before guards run) — the ONE allowed time
    # input, passed explicitly so guards stay pure functions of (file bytes + profile)
    # and never read the wall clock themselves. None = not provided (a guard must then
    # skip any expiry comparison rather than fall back to date.today()).
    today: date | None = None
    # Stacks we can name but have no guards for yet. Populated by the uncovered-stack
    # recogniser in detect(); never added to `features`. The CLI surfaces these so a
    # silent scan is never mistaken for a clean one.
    uncovered_stacks: set[str] = field(default_factory=set)
    # Languages present in real quantity (>= _FOREIGN_LANGUAGE_FLOOR files) that detect()'s
    # parser never opens at all — a different honesty gap than uncovered_stacks (a named
    # framework in a language we DO read) vs. this (a whole language we never read). Never
    # added to `features`; disclosure only, per design-stack-coverage-disclosure.md.
    foreign_languages: set[str] = field(default_factory=set)
    # Technologies the repo MENTIONS but that did not meet the anchored-evidence bar detection
    # requires, so their gated guards were skipped. A third honesty gap, distinct from both of the
    # above: `uncovered_stacks` is "we recognised it and have no guards", `foreign_languages` is
    # "a language we never read", and this is "we may have MISSED something we do have guards for".
    #
    # It exists because a narrowing is silent in the worst direction. When `db=supabase` stopped
    # accepting a bare substring (#481), a repo whose only Supabase signal was an unanchored
    # mention stopped matching — correct for the 8 false positives that motivated it, but every
    # supabase-gated guard then reports "Skipped (N/A for this stack)", which reads as "you do not
    # use Supabase" rather than "we could not confirm it". Never added to `features`; disclosure
    # only, so it can never re-open the false positives the narrowing closed.
    unconfirmed_stacks: set[str] = field(default_factory=set)
    # Docker base-image evidence of a language whose SOURCE we may never see — the artifact-layer
    # sibling to the three channels above, and a DIFFERENT honesty gap from all of them:
    # `foreign_languages` and `uncovered_stacks` both key off files `_walk()` returns from the
    # repo's own tree, so a repo that runs Go entirely as a prebuilt binary in a base image
    # (`FROM caddy:2`, zero `.go` files anywhere) reports "nothing to see" from BOTH — a TRUE
    # statement about the repo's tree that leads to a FALSE conclusion ("no Go here" when Go is
    # very much here, just not as source). Every real Go security incident on such a repo comes
    # from the artifact layer (a stale prebuilt binary, transitive deps in a builder's own go.mod
    # nobody re-reads, a wrong scan target between builder/final Docker stages) — none of which a
    # `.go`-file census could ever see. Populated by matching each Dockerfile `FROM` line against
    # the small curated `_GO_BASE_IMAGES` table; every stage's `FROM` is checked independently, so
    # a multi-stage build with only one Go-base final stage discloses exactly that one. Never added
    # to `features` — this is evidence a language runs here, not a stack agentsec can actually scan
    # (there is no source to run a guard against), so nothing is gated on it. Dean's
    # review (his own Caddy example); Dean's suggested smallest v0 — "a grep and a dict",
    # mirroring Mechanism B/`_UNGUARDED_DEPENDENCIES` — is exactly what this is.
    foreign_artifacts: set[str] = field(default_factory=set)
    # Every Dockerfile `FROM <image>:<tag>` pair that names an EXPLICIT tag, regardless of
    # language — (bare image name, tag, Dockerfile path relative to root). Unlike
    # `foreign_artifacts` above (curated to a short Go-only list, for a different purpose:
    # disclosing a language the source census can never see), this is unfiltered — every tagged
    # base image, so `guards/dependency_version_floor.py`'s `docker` ecosystem floors can catch
    # one pinned below a patched interpreter/runtime version (e.g. `FROM php:8.2.34-fpm` below a
    # CVE floor — the Contabo PHP-interpreter-RCE notice that surfaced this gap). A
    # floating tag (`latest`, a bare major/minor like `php:8.3`) or a `@digest`-only reference has
    # no comparable version and never reaches this set (see `_image_tag`); whether what's left is
    # an EXACT, floor-comparable version is the guard's own call to make, not detect()'s.
    docker_base_images: set[tuple[str, str, str]] = field(default_factory=set)
    # Per-repo OPT-IN archive/dead-code directory segments (e.g. {"old", "legacy"}).
    # Empty by default: detect() never fills this — `audit()` sets it from the repo's
    # `.agentsec/config.json` (see `config.load_repo_config`). When non-empty, guards
    # treat trees under these segments as non-product via `is_nonproduct_path`. Opt-in
    # by design, so a live directory merely named `old/` is never silently skipped.
    # (Distinct from the always-on `ARCHIVE_SEGMENTS` demotion in `prioritize`, which
    # only re-ranks and never drops a finding.)
    archive_segments: frozenset[str] = field(default_factory=frozenset)
    # Per-repo OPT-IN non-product directory segments (e.g. {"evals", "scripts"}) from
    # `.agentsec/config.json` `nonproduct_paths`. Like `archive_segments`, detect() never
    # fills this — `audit()` sets it from config. When non-empty, `audit()` DEMOTES (never
    # drops) findings under these trees via `prioritize` (stamps `Finding.nonproduct`), so a
    # real bug there stays visible but ranked low. The softer sibling of `archive_segments`.
    nonproduct_segments: frozenset[str] = field(default_factory=frozenset)
    # The active network-egress tier for this run (G5 / RFC #135). Run-scoped like
    # `archive_segments`: detect() never sets it — `audit()` stamps it from its
    # `network_tier` parameter before the runner loop. Default 0 = offline, so a
    # profile built directly (tests, a bare `invoke()`) is fail-closed to Tier 0.
    # A runner may read it to vary behavior by tier without being fully tier-gated
    # (semgrep runs its pinned local pack at Tier 0, adds the remote registry packs
    # at Tier >= 1 — the split that keeps Tier 0 genuinely offline, issue #421).
    network_tier: int = 0

    def python_paths(self) -> list[Path]:
        """The detected python source dirs as absolute paths (fallback: root)."""
        dirs = [self.root / d for d in self.python_dirs if d != "."]
        if "." in self.python_dirs or not dirs:
            dirs.append(self.root)
        dirs = [d for d in dirs if d.is_dir()]
        # `bandit`/`semgrep` (the two runners that consume this) are handed each returned path
        # as its own recursive scan target — if `python_dirs` resolves to both a directory and
        # one of its own subdirectories (e.g. root "." plus "guards"), every file under that
        # subdirectory gets handed to the scanner twice. Deduped the same way, and for the same
        # confirmed-live reason, as `guards/base.py::_dedupe_overlapping_scan_dirs` (#701) — drop
        # any directory that is itself, or a subdirectory of, another directory already kept.
        kept: list[Path] = []
        for d in sorted(dirs, key=lambda p: len(str(p))):
            if not any(d == k or d.is_relative_to(k) for k in kept):
                kept.append(d)
        return kept

    def summary(self) -> str:
        parts = [
            f"languages={sorted(self.languages) or '-'}",
            f"backend={self.backend_framework or '-'}",
            f"llm={self.llm_framework or '-'}",
            f"db={self.db or '-'}",
            f"frontend={self.frontend or '-'}",
            f"pkg={sorted(self.package_managers) or '-'}",
            f"docker={self.has_docker}",
            f"k8s={self.has_k8s_manifest}",
            f"cfn={self.has_cfn_template}",
            f"arm={self.has_arm_template}",
            f"rls={self.has_rls_sql}",
            f"payments={self.has_payments}",
        ]
        if self.uncovered_stacks:
            parts.append(f"uncovered={sorted(self.uncovered_stacks)}")
        if self.foreign_languages:
            parts.append(f"foreign_languages={sorted(self.foreign_languages)}")
        if self.unconfirmed_stacks:
            parts.append(f"unconfirmed={sorted(self.unconfirmed_stacks)}")
        if self.foreign_artifacts:
            parts.append(f"foreign_artifacts={sorted(self.foreign_artifacts)}")
        return " ".join(parts)


def _walk(root: Path) -> list[Path]:
    """File walk skipping vendored/build dirs, nested git worktrees, and
    `.gitignore`-matched paths (the shared policy in `agentsec.walk`)."""
    return walk_files(root)


_MAX_READ_CHARS = 2_000_000  # cap per-file reads during detection: a hostile target repo
                             # could ship a multi-GB manifest/source file and OOM the
                             # dependency-free walk (manifest text is also .lower()'d, doubling it).


def _read(p: Path) -> str:
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as fh:
            data = fh.read(_MAX_READ_CHARS)
            # The read above is deliberately capped (see _MAX_READ_CHARS). If anything remains,
            # detection saw only the file's head — so disclose it rather than silently under-detect
            # (a dependency past the cap would otherwise just vanish, reading as a detection bug).
            if fh.read(1):
                print(
                    f"detect: read-capped '{p.name}' at {_MAX_READ_CHARS:,} chars "
                    "(multi-GB-manifest OOM guard) — used the file head only; a dependency past the "
                    "cap may be missed. Not a bug; split or trim the file to detect it.",
                    file=sys.stderr,
                )
            return data
    except OSError:
        return ""


def detect(root: Path) -> StackProfile:
    root = root.resolve()
    prof = StackProfile(root=root)
    files = _walk(root)

    # Path facts every pass below needs, derived ONCE per file. `relative_to` builds a Path for
    # each ancestor of the file and `.parent` builds a new Path on every access, so re-deriving
    # them on each of detect()'s passes over `files` was the bulk of a walk-cached call.
    # `rel_parts[f]` is exactly `f.relative_to(root).parts`: walk output is root-prefixed and
    # `root` is resolved above, and slicing `parts` is separator-agnostic.
    _root_depth = len(root.parts)
    rel_parts = {f: f.parts[_root_depth:] for f in files}

    def _parent_name(f: Path) -> str:
        """`f.parent.name`, without building the parent Path."""
        rel = rel_parts[f]
        return rel[-2] if len(rel) > 1 else root.name

    # --- language presence by suffix ---
    suffixes = {f.suffix for f in files}
    if ".py" in suffixes:
        prof.languages.add("python")
    if suffixes & {".ts", ".tsx"}:
        prof.languages.add("typescript")
    if suffixes & {".js", ".jsx"}:
        prof.languages.add("javascript")
    if ".sql" in suffixes:
        prof.languages.add("sql")
    if ".go" in suffixes:
        prof.languages.add("go")
    if ".php" in suffixes:
        prof.languages.add("php")
    if ".rb" in suffixes:
        prof.languages.add("ruby")
    if ".java" in suffixes:
        prof.languages.add("java")
    if ".rs" in suffixes:
        prof.languages.add("rust")

    # --- foreign-language census (design-stack-coverage-disclosure.md, Mechanism A) ---
    # Reuses the same `files` list above — no second walk, so vendored/build dirs and
    # .gitignore-matched paths are already excluded (see `_walk`'s own docstring). Only
    # extensions in the curated table count; a `.md`/`.json`/`.yaml` file was never a
    # candidate, so it can never be miscounted as an unscanned language.
    _foreign_counts: dict[str, int] = {}
    for f in files:
        lang = _FOREIGN_LANGUAGE_EXTENSIONS.get(f.suffix)
        if lang:
            _foreign_counts[lang] = _foreign_counts.get(lang, 0) + 1
    prof.foreign_languages = {
        lang for lang, count in _foreign_counts.items() if count >= _FOREIGN_LANGUAGE_FLOOR
    }

    def _owned_file(f: Path) -> bool:
        """`f` sits in a directory this repo owns. Every directory segment between `root` and the
        file is judged, INCLUDING the immediate parent. `_owns_dir(f.parent, root)` would skip the
        parent, so `third_party/package.json` would count as owned. `external`/`contrib` count as
        owned here; see `_BLOB_VENDORED_DIRS`."""
        return _owned_parts(rel_parts[f][:-1], _BLOB_VENDORED_DIRS)

    # --- aggregate manifest + env text (cheap, high-signal) ---
    # Provenance (#566): only OWNED manifests feed the blob. Every manifest/import detector below
    # is anchored on content shape, and a vendored `third_party/lib/package.json` really does
    # declare `@supabase/supabase-js`, so without this test someone else's dependencies set this
    # repo's `db`, `payments`, `llm`, framework, … and the guard families they gate.
    manifest_text = ""
    for f in files:
        if f.name in _MANIFESTS and _owned_file(f):
            manifest_text += "\n" + _read(f).lower()

    # --- package managers (lockfiles / manifests) ---
    names = {f.name for f in files}
    if "requirements.txt" in names or "requirements-locked.txt" in names:
        prof.package_managers.add("pip")
    if "uv.lock" in names or "[tool.uv]" in manifest_text:
        prof.package_managers.add("uv")
    if "pnpm-lock.yaml" in names:
        prof.package_managers.add("pnpm")
    if "package-lock.json" in names:
        prof.package_managers.add("npm")
    # Both lockfile spellings: Bun < 1.2 wrote the binary `bun.lockb`, 1.2+ writes the text
    # `bun.lock`. Knowing only the old one meant a Bun 1.2+ backend (package.json + bun.lock,
    # no frontend) detected NO package manager, so `js-supply-chain.applies()` returned False
    # and the ENTIRE guard was skipped — including its HIGH lifecycle-scripts rule (#464
    # review). `js_supply_chain` already knew both names, so detect and the guard disagreed.
    if "bun.lockb" in names or "bun.lock" in names:
        prof.package_managers.add("bun")

    # --- docker ---
    prof.has_docker = any(
        f.name == "Dockerfile" or f.name.startswith("docker-compose") for f in files
    )

    # --- artifact-layer Go evidence (Dean's review; StackProfile.foreign_artifacts
    # doc comment above has the full "why"). Reuses the SAME `files` list already computed at the
    # top of detect() — no second walk — and matches Dockerfile names by hand the same way
    # `guards/base.py::iter_dockerfiles` does (`Dockerfile`, `Dockerfile.<x>`, `*.dockerfile`);
    # detect.py can't import that helper directly since guards/base.py imports StackProfile FROM
    # here, and importing it back would be circular.
    _artifacts: set[str] = set()
    _docker_images: set[tuple[str, str, str]] = set()
    for f in files:
        if not (
            f.name == "Dockerfile"
            or f.name.startswith("Dockerfile.")
            or f.name.lower().endswith(".dockerfile")
        ):
            continue
        _df_text = _read(f)
        if not _df_text.strip():
            continue
        # A later `FROM <stage-name>` references an earlier build stage, not a pullable registry
        # image — excluded the same way guards/docker_latest_base_tag.py's `_is_unpinned` does, so
        # a coincidentally Go-named build-stage alias is never mistaken for the real image.
        _stage_names = {
            m.group(2) for m in _FROM_INSTRUCTION.finditer(_df_text) if m.group(2)
        }
        for m in _FROM_INSTRUCTION.finditer(_df_text):
            _image_ref = m.group(1)
            if _image_ref in _stage_names:
                continue
            _bare = _bare_image_name(_image_ref)
            _lang = _GO_BASE_IMAGES.get(_bare)
            if _lang:
                _artifacts.add(f"{_lang} (Docker base image `{_image_ref}`)")
            _tag = _image_tag(_image_ref)
            if _tag:
                _docker_images.add((_bare, _tag, str(f.relative_to(root))))
    prof.foreign_artifacts = _artifacts
    prof.docker_base_images = _docker_images

    # --- k8s manifest (bounded content scan, mirrors the *.sh provisioning-script scan) ---
    _yaml_scanned = 0
    for f in files:
        if f.suffix not in (".yaml", ".yml"):
            continue
        if _yaml_scanned >= _MAX_YAML_SCAN:
            break
        _yaml_scanned += 1
        if is_k8s_manifest_text(_read(f)):
            prof.has_k8s_manifest = True
            break

    # --- CloudFormation template (bounded content scan, mirrors the k8s-manifest scan above —
    # also covers .json, since CFN ships in both formats; see agentsec.cfn) ---
    _cfn_scanned = 0
    for f in files:
        if f.suffix not in (".yaml", ".yml", ".json"):
            continue
        if _cfn_scanned >= _MAX_YAML_SCAN:
            break
        _cfn_scanned += 1
        if is_cfn_template_text(_read(f)):
            prof.has_cfn_template = True
            break

    # --- ARM template (bounded content scan, mirrors the k8s-manifest scan above — ARM is
    # JSON-only, no YAML variant; see agentsec.arm) ---
    _arm_scanned = 0
    for f in files:
        if f.suffix != ".json":
            continue
        if _arm_scanned >= _MAX_YAML_SCAN:
            break
        _arm_scanned += 1
        if is_arm_template_text(_read(f)):
            prof.has_arm_template = True
            break

    # --- per-language dirs (the top-level dirs containing a file of that language, + root as
    # "."), one pass for all five. python_dirs is the original; go/php/ruby/java mirror it exactly.
    # go_dirs is not consumed yet; Phase 3 (Go scanning infra in guards/base.py) is what reads it. ---
    lang_dirs: dict[str, set[str]] = {".py": set(), ".go": set(), ".php": set(), ".rb": set(), ".java": set()}
    for f in files:
        dirs = lang_dirs.get(f.suffix)
        if dirs is not None:
            rel = rel_parts[f]
            dirs.add(rel[0] if len(rel) > 1 else ".")
    prof.python_dirs = sorted(lang_dirs[".py"])
    prof.go_dirs = sorted(lang_dirs[".go"])
    prof.php_dirs = sorted(lang_dirs[".php"])
    prof.ruby_dirs = sorted(lang_dirs[".rb"])
    prof.java_dirs = sorted(lang_dirs[".java"])

    # --- frontend dir (package.json with react/vite) ---
    for f in files:
        if f.name == "package.json":
            txt = _read(f).lower()
            if '"react"' in txt or '"vite"' in txt:
                prof.frontend_dir = str(f.parent.relative_to(root))
                # Quoted, matching the test above: an unquoted "vite" substring-matches inside
                # "vitest"/"@vitejs/plugin-react" — common test-only devDependencies on any React
                # project, unrelated to the actual bundler — and mislabels e.g. a Next.js app that
                # merely uses vitest for unit tests as "vite-react" (#found scanning a real repo).
                prof.frontend = "vite-react" if '"vite"' in txt else "react"
                break

    # --- sql dir: prefer the LIVE top-level sql/ over an archived old/**/sql copy ---
    # Rank candidates by (non-archive, dir-named-"sql", shallowest, path) and take the
    # best — so a repo carrying both a live `sql/` and an `old/**/sql` resolves to the
    # live one (#111). A single sql/ tree is unaffected.
    sql_files = [f for f in files if f.suffix == ".sql"]
    if sql_files:

        def _sql_rank(f: Path) -> tuple[int, int, int, str]:
            rel = rel_parts[f]
            dir_parts = rel[:-1]
            in_archive = any(p.lower() in ARCHIVE_SEGMENTS for p in dir_parts)
            return (
                1 if in_archive else 0,            # live dirs before archived
                0 if _parent_name(f) == "sql" else 1,  # a dir named "sql" wins
                len(dir_parts),                    # shallowest wins
                str(Path(*rel)),                   # stable tiebreak: str(f.relative_to(root))
            )

        chosen = min(sql_files, key=_sql_rank)
        prof.sql_dir = str(chosen.parent.relative_to(root))
        prof.has_rls_sql = any("row level security" in _read(f).lower() for f in sql_files[:200])

    # --- bounded python import scan for frameworks/llm/db ---
    # Owned files only, same test as the manifest blob (#566), and only they count against the
    # cap: `examples/`, `docs_src/` and `alembic/` sort before `app/`/`src/`, so letting them in
    # spent the whole 200-file budget on samples and the owned imports were never read.
    import_blob = manifest_text
    scanned = 0
    for f in files:
        if scanned >= _MAX_PY_SCAN:
            break
        if f.suffix == ".py" and _owned_file(f):
            import_blob += "\n" + _read(f).lower()
            scanned += 1

    _has_express = _names_dep(manifest_text, "express")
    if "fastapi" in import_blob:
        prof.backend_framework = "fastapi"
    elif _has_express:
        prof.backend_framework = "express"
    if "pydantic_ai" in import_blob or "pydantic-ai" in import_blob:
        prof.llm_framework = "pydantic-ai"
    elif "langchain" in import_blob:
        prof.llm_framework = "langchain"
    # Python apps that import an LLM SDK directly (openai/anthropic/litellm/...). The `openai` SDK in
    # particular is the most common Python LLM client — and the way apps reach OpenRouter, vLLM,
    # Together, Groq, Azure, and local OpenAI-compatible endpoints — but was previously invisible to
    # detection (only pydantic-ai/langchain were matched for Python; `openai` was JS-only). An
    # openai-SDK RAG app therefore fingerprinted `llm=-` and every "llm"-gated guard (lethal-trifecta,
    # rag-*, prompt-injection, llm-output-*, tool-chaining-exfil, ...) was silently N/A-suppressed.
    # The manifest arm is gated on the project actually being PYTHON: `openai` is also a
    # package.json dependency name, and an unconditional check claimed a JS-only app as
    # `python-llm-sdk` before the JS branch below could classify it.
    elif _PY_LLM_IMPORT.search(import_blob) or (
        "python" in prof.languages and _py_llm_manifest_dep(manifest_text)
    ):
        prof.llm_framework = "python-llm-sdk"
    # JS/TS LLM SDKs (package.json dependency, not a Python import — a JS/TS-only app has no
    # import_blob signal at all otherwise, so the "llm" feature would never fire on its actual
    # target stack). Anchored to the dependency-declaration KEY shape via `_js_dep` (review #395
    # Major finding — a bare substring match false-positived on `"keywords": ["openai"]`). The
    # real openrouter JS SDK package is `@openrouter/sdk`; a bare `"openrouter"` string never
    # matched any real dependency (review #395 Minor finding — dead branch).
    elif (
        _js_dep(manifest_text, "openai")
        or _js_dep(manifest_text, "@anthropic-ai/sdk")
        or _js_dep(manifest_text, "@google/genai")
        or _js_dep(manifest_text, "@openrouter/sdk")
    ):
        prof.llm_framework = "js-llm-sdk"
    # Require REAL Supabase usage, not a bare "supabase" substring anywhere in the manifest blob. The
    # old `"supabase" in manifest_text` set db=supabase from a `.env.example` comment merely listing
    # Supabase as one optional Postgres provider ("point DATABASE_URL to Supabase, Neon, etc."), which
    # then made `public-table-rls` treat the app's `public` tables as anon-reachable on a repo that has
    # no PostgREST/anon surface (round-2 §D.4, 8 FPs). Mirrors the `_js_dep` anchored-match precedent
    # (review #395) used for LLM-SDK detection just above.
    # Every clause is ANCHORED to a real declaration/assignment, never a bare substring — a bare
    # substring is exactly what reopened this FP (a comment naming a `SUPABASE_*` var, or the string
    # `.supabase.com` from a docs/pooler hostname, both matched the earlier draft). PR #481 review.
    # The canonical Supabase CLI layout: `supabase/config.toml` next to `supabase/migrations/`.
    # A repo scaffolded by `supabase init` has no client dependency at all until the app code is
    # written, so every manifest/import clause below misses it (#481 review).
    #
    # `supabase/migrations/*.sql` counts on its own, not only alongside `config.toml`. A
    # database-only repo — migrations tracked in git, the app living in a different repo — is an
    # ordinary split, and `config.toml` is commonly gitignored because it carries local ports and
    # project refs. Without this arm such a repo detected as plain `postgres` and every
    # supabase-gated guard went N/A on a real Supabase project.
    #
    # Scoped to a supabase/ directory THIS repo owns. The first cut required only the path shape
    # plus the `.sql` suffix, which a vendored or sample copy of somebody else's Supabase project
    # satisfies: `third_party/some-lib/supabase/migrations/0001.sql` flipped the whole repo to
    # `db=supabase`, and the repo's OWN unprotected `public` tables then produced a real HIGH
    # `public-table-rls` finding — the FP-burst class this PR exists to close, reopened through a
    # second vector (#481 review round 3, reproduced end-to-end). `node_modules` was already safe
    # because `walk.DEFAULT_EXCLUDE_DIRS` drops it; `examples/` and `third_party/` are not dropped
    # anywhere, so the scoping has to live here.
    #
    # Only the segments ABOVE the `supabase/` dir are tested. The path below it cannot be: the
    # shared `NONPRODUCT_DIR_ALT` list contains `migrations?` itself, so matching the whole path
    # would reject every legitimate `supabase/migrations/` there is.
    _supabase_cli_layout = any(
        (f.name == "config.toml" and f.parent.name == "supabase" and _owns_dir(f.parent, root))
        or (
            f.suffix == ".sql"
            and f.parent.name == "migrations"
            and f.parent.parent.name == "supabase"
            and _owns_dir(f.parent.parent, root)
        )
        for f in files
    )
    # Manifest text with `#` line-comments removed — for the clauses where a mere MENTION is the
    # documented false positive (see the host checks below).
    # Drops a WHOLE-LINE comment and clips a TRAILING one. Whole-line-only was not enough: a
    # `.env.example` line `DATABASE_URL=...  # or use Supabase: https://xyz.supabase.co` kept its
    # comment, so the host clause matched and `db=supabase` came back — reopening the exact
    # 8-FP class this PR exists to close (#481 second-pass review). A `#` is treated as a comment
    # only at line start or after whitespace, so a `#` inside a value (`pass#word`, a URL fragment)
    # survives.
    #
    # Uses the shared `_strip_manifest_comments` rather than the local helper this branch first
    # carried. Main's is QUOTE-AWARE (#465 re-review) and that is not cosmetic here: the naive
    # regex strips from the first whitespace-preceded `#` to end of line even when that `#` sits
    # inside an earlier quoted value, so `dependencies = ["requests # legacy note", "supabase"]`
    # lost its `"supabase"` entry — defeating this PR's own single-line-TOML clause below on a
    # manifest where the dependency is real. Merge resolution, #481.
    _manifest_code = _strip_manifest_comments(manifest_text)
    _supabase_used = (
        "from supabase import" in import_blob
        or "from supabase." in import_blob        # `from supabase.client import create_client`
        or "import supabase" in import_blob
        # ANY `@supabase/*` package key, not just `supabase-js`: `@supabase/ssr` is the current
        # recommended Next.js package, and `auth-helpers-nextjs` / `postgrest-js` / `auth-ui-react`
        # are all real client surfaces (#481 review). Still the anchored KEY shape, so a
        # `"keywords": ["@supabase/ssr"]` tag does not count.
        or re.search(r'"@supabase/[\w.-]+"\s*:', _manifest_code) is not None
        or re.search(r'(?m)^[^\S\n]*"?supabase[\s"><=~\[]', manifest_text) is not None  # PyPI dep line
        # A single-line TOML dep list — `dependencies = ["fastapi", "supabase"]` — has no
        # line-start anchor for the entry, so the multiline form above misses it (#481 review).
        # Scoped to the inside of a `dependencies = [...]` array: a bare `"supabase"` anywhere in
        # the blob would match package.json's `"keywords": ["supabase"]`, the exact declared-vs-
        # mentioned FP `_js_dep` exists to prevent. Reads the comment-stripped blob: the regex
        # spans lines (`re.S`) and has no line-start anchor, so a commented-out example dep list
        # matched (#481 second-pass review). The line-ANCHORED clauses above and below can keep
        # reading the raw blob — a leading `#` already defeats their `^\s*` anchor.
        or re.search(
            r'dependencies\s*=\s*\[[^\]]*["\']supabase(?:\[[\w,-]+\])?["\']', _manifest_code, re.S
        ) is not None
        # A SUPABASE_* env ASSIGNMENT, with or without a framework prefix. Bare `^supabase_`
        # missed every bundler-exposed var — `NEXT_PUBLIC_SUPABASE_URL`, `VITE_`, `REACT_APP_`,
        # `EXPO_PUBLIC_` — which is how a frontend actually spells it (#481 review). Still
        # anchored to an assignment, so a comment merely NAMING the var does not count.
        or re.search(r'(?mi)^[^\S\n]*(?:\w+_)?supabase_\w*\s*=', manifest_text) is not None
        # A `*.supabase.co` project host, or the connection-pooler host, which lives on
        # `.supabase.com` — the one `.com` form that is a real deployment signal, so it is matched
        # explicitly rather than by reopening the bare `.supabase.com` substring the review of this
        # PR closed (a docs/marketing URL). Matched against the COMMENT-STRIPPED blob: a `.env.example`
        # that merely mentions a pooler host in a `#` comment is the documented FP-bait, and a host
        # is a real signal only when it is actually configured.
        or re.search(r'\.supabase\.co(?![a-z])', _manifest_code) is not None
        or re.search(r'\.pooler\.supabase\.com\b', _manifest_code) is not None
        or _supabase_cli_layout
    )
    if _supabase_used:
        prof.db = "supabase"
    elif "asyncpg" in import_blob or "psycopg" in import_blob:
        prof.db = "postgres"
    # The repo NAMES Supabase somewhere but nothing above met the anchored bar. Usually that is
    # exactly right — a `.env.example` comment listing it as one optional Postgres provider is the
    # false positive this narrowing exists to close — but it is also what a project shape detection
    # does not yet know looks like. Disclose rather than decide silently: without this the
    # supabase-gated guards report "Skipped (N/A for this stack)", which a reader takes as "this
    # repo does not use Supabase" when it may mean "we could not tell". Not a feature, so the
    # guards stay skipped and the 8 FPs stay closed; the report just stops implying certainty.
    if not _supabase_used and "supabase" in manifest_text:
        prof.unconfirmed_stacks.add("supabase")

    # --- payments / Stripe ---
    prof.has_payments = (
        "stripe" in manifest_text
        or "import stripe" in import_blob
        or any("stripe" in f.name.lower() for f in files)
        or "stripe_secret_key" in manifest_text
    )

    # --- GraphQL (Python server libraries only — gates graphql-mutation-idor, NS-2) ---
    _has_graphql = (
        "python" in prof.languages
        and (_PY_GRAPHQL_IMPORT.search(import_blob) is not None or _py_graphql_manifest_dep(manifest_text))
    )

    # --- MCP (Model Context Protocol) config files ---
    _MCP_CONFIG_NAMES = frozenset({
        "mcp.json", ".mcp.json", "mcp_config.yaml", "mcp_config.toml",
        "servers.json", "mcp-servers.json", "claude_desktop_config.json",
    })
    _has_mcp = any(
        f.name in _MCP_CONFIG_NAMES
        or (f.name.startswith("mcp-") and f.name.endswith(".json"))
        or (_parent_name(f) == ".mcp" and f.suffix in (".json", ".yaml", ".toml"))
        for f in files
    )
    # Also detect MCP via a real `import mcp` / `from mcp` statement, an `mcp` dependency, or a
    # `[tool.mcp]` pyproject section. Anchored (not a bare "mcp" substring) so it does not trip on
    # a package merely containing the letters "mcp" (fastmcp, …) or on source that quotes the
    # string "from mcp" / "[tool.mcp]" — e.g. agentsec's own guard source (PR #228 review).
    # A JS/TS MCP server or client announces itself by the official SDK in package.json, which
    # none of the Python arms can see (#981). Matched as a JSON object KEY via `_js_dep`, so a
    # `"keywords"` tag naming the SDK, or the SDK repo's own `"name"` value, does not count. The
    # key's section is not checked: an `overrides` pin counts too, as the tree still ships the SDK.
    if not _has_mcp:
        _has_mcp = bool(
            re.search(r"(?m)^[^\S\n]*(?:from\s+mcp[\s.]|import\s+mcp\b)", import_blob)
            or re.search(r"(?mi)\bmcp\b\s*(?:[><=~!]=?|\[|$)", manifest_text)
            or "[tool.mcp]" in manifest_text
            or _js_dep(manifest_text, "@modelcontextprotocol/sdk")
        )

    # --- host-hardening config files (sshd / ufw / fail2ban / unbound / auto-updates / cloud-init) ---
    # Turns on the `host-config` feature so the host-hardening guard family runs. Matched by name,
    # by the sshd_config.d/*.conf drop-in convention, by a fail2ban/cloud-init parent dir, OR by a
    # shell provisioning script that installs OS packages (`apt(-get) install` in a *.sh) — the bare
    # provisioning-script case, and the same anchor the `auto-updates-absent` guard uses in run().
    # (A *.sh invoked only from a Dockerfile also matches — a minor, pragma-suppressible over-fire;
    # only auto-updates-absent can act on it, since sshd/fail2ban self-anchor on a real sshd_config.)
    # The `.sh` content scan is capped like the import-scan so detection stays bounded on big repos.
    _HOST_CONFIG_NAMES = frozenset({
        "sshd_config", "jail.local", "jail.conf", "unbound.conf",
        "50unattended-upgrades", "20auto-upgrades", "setup-ufw.sh",
    })

    def _host_config_marker(f: Path) -> bool:
        parent = _parent_name(f)
        return (
            f.name in _HOST_CONFIG_NAMES
            or (parent == "sshd_config.d" and f.suffix == ".conf")
            or parent in {"fail2ban", "cloud-init"}
        )

    _has_host_config = False
    _sh_scanned = 0
    for f in files:
        if _host_config_marker(f):  # cheap name/dir check — always wins, no read
            _has_host_config = True
            break
        if f.suffix == ".sh" and _sh_scanned < _MAX_SH_SCAN:
            _sh_scanned += 1
            if APT_INSTALL.search(_read(f)):
                _has_host_config = True
                break

    # --- reverse-proxy config (Caddy / nginx) — gates the proxy-TLS-hardening guard ---
    _has_reverse_proxy = any(
        f.name.lower() == "caddyfile"  # case-insensitive: matches the guard's _is_caddy (review #252)
        or f.name.lower().endswith(".caddyfile")
        or f.suffix.lower() in {".caddy", ".nginx"}
        or f.name == "nginx.conf"
        or (f.suffix.lower() == ".conf"
            and f.parent.name in {"nginx", "sites-available", "sites-enabled", "conf.d"})
        for f in files
    )

    # --- Redis (gates the redis-glob-pattern-injection guard, NS-15) ---
    # Anchored to a real dependency declaration, not `_names_dep`'s looser substring match — a
    # bare "redis" mention is common enough in unrelated prose (a comment naming a caching
    # strategy, a doc link) that the electron-style loose check would over-trigger a whole new
    # guard family. `_declares_py_dep`/`_js_dep` are the same anchored helpers the LLM-SDK and
    # Supabase detection above already rely on for exactly this reason.
    _has_redis = (
        _declares_py_dep(_manifest_code, "redis")
        or _declares_py_dep(_manifest_code, "aioredis")
        or _js_dep(_manifest_code, "ioredis")
        or _js_dep(_manifest_code, "redis")
        or re.search(r"(?m)^[^\S\n]*(?:from\s+redis[\s.]|import\s+redis\b)", import_blob) is not None
    )

    # --- electron (desktop-app packaging) — gates the electron-security-misconfig guard ---
    _has_electron = _names_dep(manifest_text, "electron")
    # --- Ansible (playbook/role tree) ---
    # Cheap name/path checks first (no read needed): a real `ansible.cfg`, a conventionally-named
    # playbook entrypoint, or the `roles/<name>/tasks/main.yml` role-directory shape. Falls back to
    # a bounded content scan (capped like `_MAX_SH_SCAN`) for a play-shaped YAML file elsewhere in
    # the repo. The play-shape signal is a `hosts:` play key AND a `tasks:` play key AT PLAY-LEVEL
    # INDENT (<=4 spaces) IN THE SAME YAML DOCUMENT. Both constraints matter: an unrelated deeply
    # nested `tasks:` (an Argo Workflows DAG template) or a `hosts:` data key (a K8s ConfigMap)
    # would otherwise, when they co-occur in a multi-document YAML file, falsely trip detection —
    # so the two keys must be shallow AND share one `---`-delimited document, which docker-compose
    # (`services:`), K8s manifests (`kind:`/`spec:`), and GH Actions (`jobs:`/`steps:`) never are.
    _ANSIBLE_ENTRYPOINT_NAMES = frozenset({"ansible.cfg", "playbook.yml", "playbook.yaml", "site.yml", "site.yaml"})
    # `[^\S\n]`, not `\s`, in both leading classes: they express INDENT, and indent is never a
    # newline. Under `(?m)` a `\s`-based class also matches at a blank line and consumes newlines,
    # which made the unbounded `\s*` after `-?` rescan the whole blank run from every line start
    # of it — quadratic (#697). The `{0,4}` class alone was already bounded and so not the blow-up,
    # but it is the same "indent" idea and is converted with it rather than left as a puzzle.
    _ANSIBLE_PLAY_SHAPE = re.compile(r"(?m)^[^\S\n]{0,4}-?[^\S\n]*hosts\s*:")
    _ANSIBLE_TASKS_SHAPE = re.compile(r"(?m)^[^\S\n]{0,4}tasks\s*:")
    _YAML_DOC_SEP = re.compile(r"(?m)^---\s*$")

    def _is_ansible_role_task_path(f: Path) -> bool:
        if f.name not in ("main.yml", "main.yaml"):  # cheap check first: `f.parts` builds a tuple
            return False
        parts = f.parts
        return "roles" in parts and len(parts) >= 2 and parts[-2] == "tasks"

    prof.has_ansible = any(
        f.name in _ANSIBLE_ENTRYPOINT_NAMES or _is_ansible_role_task_path(f) for f in files
    )
    if not prof.has_ansible:
        _yaml_scanned = 0
        for f in files:
            if _yaml_scanned >= _MAX_YAML_SCAN:
                break
            if f.suffix not in (".yml", ".yaml"):
                continue
            _yaml_scanned += 1
            txt = _read(f)
            # Require both shape keys within one YAML document (split on `---`), so a `hosts:`
            # and a `tasks:` scattered across different docs of a multi-doc manifest don't combine.
            if any(
                _ANSIBLE_PLAY_SHAPE.search(doc) and _ANSIBLE_TASKS_SHAPE.search(doc)
                for doc in _YAML_DOC_SEP.split(txt)
            ):
                prof.has_ansible = True
                break

    # --- normalized feature flags (what the registry maps on) ---
    feats: set[str] = set(prof.languages)
    if prof.backend_framework:
        feats.add(prof.backend_framework)
    if _has_express:
        feats.add("express")
    _has_nextjs = any(f.name.startswith("next.config.") for f in files) or '"next"' in manifest_text
    if _has_nextjs:
        feats.add("nextjs")
    _has_react_native = _names_dep(manifest_text, "react-native") or _names_dep(manifest_text, "expo")
    if _has_react_native:
        feats.add("react-native")
    if prof.llm_framework:
        feats.add(prof.llm_framework)
        feats.add("llm")
    if prof.db:
        feats.add(prof.db)
    if prof.frontend:
        feats.add("frontend")
    if prof.has_docker:
        feats.add("docker")
    if prof.has_k8s_manifest:
        feats.add("k8s")
    if prof.has_cfn_template:
        feats.add("cloudformation")
    if prof.has_arm_template:
        feats.add("arm")
    if ".tf" in {f.suffix for f in files}:
        feats.add("terraform")
    if {".bicep", ".bicepparam"} & {f.suffix for f in files}:
        feats.add("bicep")
    if prof.has_rls_sql or prof.sql_dir:
        feats.add("sql")
    if prof.has_rls_sql:
        feats.add("rls")
    if prof.has_payments:
        feats.add("payments")
    if _has_graphql:
        feats.add("graphql")
    if _has_mcp:
        feats.add("mcp")
    if _has_redis:
        feats.add("redis")
    if _has_host_config:
        feats.add("host-config")
    if _has_reverse_proxy:
        feats.add("reverse-proxy")
    if _has_electron:
        feats.add("electron")
    if prof.has_ansible:
        feats.add("ansible")
    prof.features = feats

    # --- uncovered-stack recogniser ---
    # Detects frameworks/ORMs we can name but have no dedicated guard suite for yet — some
    # entries (django, flask) do get partial signal from other guards' framework-idiom checks
    # (#553 review, Dean, High 2), so the notice deliberately says "no dedicated guard suite
    # yet" rather than "no guards yet", which would overclaim silence. These go into
    # profile.uncovered_stacks (never into profile.features) so the CLI can surface that
    # honest notice instead of letting a silent scan read as clean.
    _uncovered: set[str] = set()
    for _dep_name, _stack_name in _UNGUARDED_DEPENDENCIES.items():
        if _names_dep(manifest_text, _dep_name):
            _uncovered.add(_stack_name)
    # "express" removed 2026-07-13 (njsscan research batch): now a real backend_framework/feature
    # with actual guard coverage, not just a named gap. "nextjs" removed 2026-09-19 (Splinter/
    # vibe-coder gap audit): now a real feature (see `_has_nextjs` above) with its own dedicated
    # guard suite (`next-public-client-secret`, and siblings), not just a named gap.
    # prisma detects via a file-name signal, not a plain dependency declaration, so it stays its
    # own check rather than joining _UNGUARDED_DEPENDENCIES's simple table.
    if '"@prisma/client"' in manifest_text or any(f.name == "schema.prisma" for f in files):
        _uncovered.add("prisma")
    # Go: detection is a language-presence signal (suffix/manifest file), not a plain
    # dependency declaration, so it stays its own check alongside prisma rather than
    # joining _UNGUARDED_DEPENDENCIES. Disclosed honestly here instead of a silent "clean"
    # scan: `dependency-version-floor`'s go.sum check is real coverage, but narrow (2 curated
    # SDK floors, not a dedicated code-pattern guard suite the way Java/PHP/Ruby each have).
    if "go" in prof.languages:
        _uncovered.add("go")
    # Rust: same shape as Go, added when Rust's dependency-version-floor Cargo.lock check
    # landed (PR #922). Dean's review: Rust's `.rs` extension was removed
    # from `_FOREIGN_LANGUAGE_EXTENSIONS` on the PHP/Ruby/Java graduation precedent, but unlike
    # those three (each with 7+ dedicated code-pattern guards), Rust has ZERO — only this one
    # narrow floor check, which fires solely on 2 curated crates. Removing the foreign-census
    # entry without adding this disclosure left a Rust repo reporting nothing at all about the
    # gap. Mirrors Go's own honest-disclosure shape above rather than Java/PHP/Ruby's silence,
    # since Rust's actual coverage depth matches Go's, not theirs.
    if "rust" in prof.languages:
        _uncovered.add("rust")
    prof.uncovered_stacks = _uncovered

    return prof
