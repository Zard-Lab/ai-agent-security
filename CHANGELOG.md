# agentsec Release History

_Issue and PR numbers below (`#NNN`) refer to the maintainers' development tracker, not to this repository's issues._

**Major releases** (`v0.MINOR.0`) get a structured entry under `## Major Releases`. **Patch releases**
(`v0.MINOR.Z`, Z > 0 — fixes, hygiene, and new non-breaking detections) get a one-line entry under
`## Patch Releases`, mirroring the GitHub Release title; the full per-patch notes live in the GitHub
Release and commit messages. (The inaugural `v0.19.2` baseline entry below is a one-time snapshot of the
state at the first tag, recorded so the history has a starting point, not a `v0.MINOR.0` release.)

Versioning follows the SemVer 2.0 pre-1.0 clause: `v0.MINOR.0` is the breaking-change signal (see
[`BREAKING_CHANGES.md`](BREAKING_CHANGES.md)), `v0.MINOR.Z` is non-breaking. The tool version is welded to the
checklist registry version (`agentsec/checklist/checklist.json`), so `agentsec --version` and every report's
"Checklist registry" stamp always agree.

Use `/changelog v0.MINOR.0` to generate a new major-release entry. A patch entry is appended
automatically by `scripts/cut-release.py <version> --summary "..."` when the release is cut.

---

## Major Releases

## v0.22.0 - The CI channel: a GitHub Action, pinned installs and the pre-commit manifest

**Date**: 2026-11-03
**Focus**: One supported way to run agentsec in CI, plus the stricter waiver and pragma matching queued since v0.21.0
**Stability**: Stable

### Overview
agentsec now ships a composite GitHub Action at the repository root. It runs agentsec straight from the
action's own checkout (no install step, no network, no token at run time), writes a job summary, capped
inline annotations, a SARIF artifact and an optional code-scanning upload from a single audit pass, and
fails closed: a scan that did not complete (no readable SARIF, a crash, or a guard killed over its time
budget) fails the job in every mode. The workflows `agentsec ci add` renders now install agentsec pinned
to the release tag, with a token-free private install, and the copier template is removed in favour of
the action, `ci add` and a `.pre-commit-hooks.yaml` manifest. This is a MINOR release because the copier
template is gone and because of five matching changes queued since v0.21.0 (waivers, triage identity and
suppress pragmas); every one is listed with its migration in `BREAKING_CHANGES.md`.

### Key Changes
#### ✨ Features
- **GitHub Action** (`action.yml`): `gate` or `advisory` mode, `fail-on`, `scanners`, `baseline`,
  `baseline-snapshot`, `exclude`, `annotations`, `upload-sarif` and a feedback link in the summary;
  every input reaches the shell through `env:`, and a CI self-test job runs it end to end (#1169).
- **Repo-relative SARIF and `--annotations N`**: a subdirectory scan emits repo-relative SARIF uris,
  and `audit --annotations N` prints GitHub workflow commands for the N most severe non-baselined
  findings (#1169).
- **Pinned, token-free CI installs**: `ci add` workflows install agentsec at `v<version>`, never
  `@main`; `--install-secret NAME` hands a private-repo token to git through `GIT_ASKPASS`, never a URL
  or argv; `ci doctor` flags an unpinned install (`install-unpinned`); `--advisory` and a single audit
  pass for `self-audit` (#1167).
- **Pre-commit manifest** (`.pre-commit-hooks.yaml`): hook `agentsec-guards`, `language: python`, so
  pre-commit installs agentsec itself; CI now runs the end-to-end `pre-commit try-repo` test (#1168).
#### 🔒 Security
- A waiver that carries a `fingerprint` matches on the fingerprint alone, with no `rule` + `location`
  fallback, and the report names any waiver that suppressed more than one finding (#507).
- A URL port is no longer stripped from a finding's triage identity, so a verdict on a finding at
  `:9200` no longer silently waives an unrelated one at `:6379` (#567, #700).
- An inline suppress pragma counts only when written as a comment, and the `npm-ignore-scripts` CI
  pragma covers one install rather than the whole workflow file (#424, #539).
#### 🧹 Removed
- The copier template (`templates/`) and the `copier` dev dependency (#1168).

### Schema / On-disk Changes
- `_TRIAGE_VERSION` 2 -> 3 (the URL-port identity fix): a `v2` triage file loads with a warning, and an
  affected verdict goes inert so its finding re-surfaces as untriaged (fail-closed).
- Waiver matching in `agentsec-exceptions.json` and `.agentsec/suppress.json` is stricter
  (fingerprint-only when a fingerprint is present).

### Impact
**User-Facing**:
- Replace a copier-rendered `agentsec-security.yml` with the action pinned by SHA (migration steps in
  `BREAKING_CHANGES.md`); re-render `ci add` workflows with `--force` to pick up the pinned install.
- A waiver or pragma that only worked through the old loose matching now lets its finding re-surface.
**Developer-Facing**:
- One audit workflow implementation remains (component library + action); the 71 patch releases since
  v0.21.0 are listed under `## Patch Releases`.

### GitHub Issues Closed
- #424, #507, #539, #567 (via #700); PRs #1167, #1168, #1169

---

## v0.21.0 - Machine-ledger relocation to `docs/ledger/`

**Date**: 2026-07-18
**Focus**: Separate machine-maintained state from human knowledge docs
**Stability**: Stable

### Overview
The seven machine-maintained ledger / staging files moved out of `docs/knowledge/` into a new
dedicated directory, `docs/ledger/`. Previously the append-only JSON ledgers and the two markdown
ledgers were interleaved with ~40 human knowledge docs, with no structural signal that they are
machine-written state consumed by scripts and workflows. `docs/knowledge/` is now human knowledge only.
This is an on-disk path change (a breaking change under the welded-version policy), so it ships as the
MINOR signal v0.21.0. Runtime behavior, report output, and the CI gate are unchanged.

### Key Changes
#### ✨ Features
- New `docs/ledger/` home for all machine state: `intake-ledger.json`, `guard-improvement-ledger.json`,
  `proposed-items.json`, `deps-monitor-exceptions.json`, `feeds.json`, `marconi-merge-ledger.md`, and
  `checklist-proposed-additions.md` (with a `docs/ledger/README.md` describing each).
#### 🔒 Security / Correctness
- Every reference moved with the files: the deps-monitor waiver loader (`_WAIVERS_PATH`), the
  promote-proposal staging constant, `scripts/branch-status.sh`, the `threat-intake.yml` commit list,
  the `/threat-intake` + `land-pr` skills/commands, and the `doc_counts.py` narrative-exclude entries
  (so the moved append-only markdown stays out of the drift net).

### Impact
**User-Facing**:
- Maintainers and forks that reference these files by path must update to `docs/ledger/<file>`
  (see `BREAKING_CHANGES.md`). In-flight threat-intake PRs must relocate their staged edits.
**Developer-Facing**:
- `docs/knowledge/` is now purely human knowledge; `docs/README.md` documents the new taxonomy.

### GitHub Issues Closed
- (none; maintainer-initiated refactor)

---

## v0.20.0 - Unified finding identity + fail-safe exception loading

**Date**: 2026-07-05
**Focus**: One canonical finding identity for triage + exceptions; stop silent suppression-disable
**Stability**: Stable

### Overview

The first MINOR (breaking) release under the new policy. Triage and exceptions now compute a finding's identity
the same way, on one canonical fingerprint (issue #325), so a verdict recorded once is honored consistently.
Landing that surfaced and fixed a latent data-loss bug in exception loading. This is a **breaking** release: the
triage fingerprint scheme moves from v1 to v2, so verdicts in an `agentsec-triage.json` written by an older
version re-surface as untriaged until re-triaged. See [`BREAKING_CHANGES.md`](BREAKING_CHANGES.md).

### Key Changes

#### 🔒 Security / Correctness
- **`merge_exceptions` no longer silently clobbers the registry.** On a malformed or unreadable
  `agentsec-exceptions.json` it now raises instead of degrading to an empty registry, which had silently
  disabled every suppression (a finding could re-surface, or a baselined one vanish, with no signal). Also now
  catches `UnicodeDecodeError` explicitly on the read path.

#### ✨ Features
- **Unified triage + exception fingerprints** on one canonical `Finding` identity (#325).
- **Triage load warns on a stale schema version** (`_TRIAGE_VERSION` 1 → 2) instead of silently mis-matching, so
  a user whose verdicts stopped applying gets an actionable message rather than confusion.

### Schema / On-disk Changes
- `_TRIAGE_VERSION` 1 → 2 (the triage fingerprint scheme). Existing `agentsec-triage.json` verdicts re-surface
  as untriaged until re-run; `agentsec triage <repo>` re-classifies them under the new scheme.

### Impact

**User-Facing**:
- Breaking: re-run `agentsec triage` after upgrading if you rely on recorded verdicts.
- A corrupt exceptions baseline now fails loud instead of silently turning off all suppressions.

**Developer-Facing**:
- One identity function backs both triage and exceptions: no more two-scheme drift.

### GitHub Issues Closed
- #325 (unify triage + exception finding identity)

---

## v0.19.2 - Release process baseline (first tagged release)

**Date**: 2026-07-05
**Focus**: Establish versioning + release process
**Stability**: Stable

### Overview

The first tagged release. agentsec had run for months with zero git tags, no changelog, and a version that only
moved when the checklist registry moved. This release does not change the tool's behavior; it establishes the
versioning scheme and release process (issue #331) so that from here on, every release is a tag with a signal:
`v0.MINOR.0` may break (documented in `BREAKING_CHANGES.md`), `v0.MINOR.Z` does not. `v0.19.2` is a baseline
marker of the current registry state, not a feature drop.

### Key Changes

#### 📚 Documentation
- **Versioning + release policy** (the maintainers' release-policy RFC): SemVer pre-1.0, version
  welded to the checklist, single `main` trunk with tags off it, manual tag + GitHub Release. (Issue #331)
- **`CHANGELOG.md`** (this file) and **`BREAKING_CHANGES.md`** seeded.

#### 🔧 Technical
- **`/changelog` command** ported from `ai-agent-mastery`, adapted to the welded-version model.
- **MINOR-means-breaking enforcement test** (`tests/test_versioning_policy.py`): MINOR cannot advance past the
  latest `BREAKING_CHANGES.md` entry.
- **The development-workflow doc**: the release-tagging open gap is closed; points at the new policy.

### Impact

**User-Facing**:
- There is now a version to pin against and a `BREAKING_CHANGES.md` to check before upgrading.

**Developer-Facing**:
- Every release is a checklist-version bump: MINOR when something breaks (with a `BREAKING_CHANGES.md` entry),
  PATCH otherwise. The enforcement test gates this in CI.

### GitHub Issues Closed
- #331 (Define a versioning scheme + release process)

---

## Patch Releases

One line per patch release (`v0.MINOR.Z`, Z > 0): non-breaking fixes, hygiene, and new detections.
Newest first; the full notes for each live in its GitHub Release.

- **v0.22.2** (2026-11-17): 3 new Dockerfile guards from the cr0hn/dockerfile-security research cycle: RUN --security=insecure and dangerous chmod/SUID, docker-login/HEALTHCHECK credential exposure, WORKDIR pointing to a system directory. First PyPI release: `pipx install ai-agent-security`, and the action, issues and releases move to the public `Zard-Lab/ai-agent-security`
- **v0.22.1** (2026-11-11): Widen hardcoded-llm-provider-key/client-side-secret-literal to 5 new LLM/RAG provider-key formats (Pinecone, Replicate, Groq, LangSmith, Supabase PAT).
- **v0.21.71** (2026-10-29): Terraform AWS checks from the sonar-iac catalog: S3 MFA-delete, insecure-transport policy and canned ACL; MSK, OpenSearch, ElastiCache, EFS, ECS-EFS and Kinesis encryption; ALB plaintext listeners; weak TLS policies; RDS/Aurora backup retention; Aurora-cluster storage encryption and Redshift public access
- **v0.21.70** (2026-10-27): Docker base-image CVE floors (PHP RCE pair, CPython ssl, Node zlib) with a Dockerfile allow-old pragma; harden-host security-updates-pending and restart-owed probes; suppress pragmas anchored to real comments across the Python, SQL, CloudFormation, JS, shell and commentless guards (#1040, #1055); SQL REVOKE role-set and TypeScript provider-key fixes; corpus outlier fix
- **v0.21.69** (2026-10-20): warden-supply-chain-security batch (PR #1093, fix pass per Dean's review): curl-pipe-to-shell Python extension + 5 new guards (browser credential theft, environ-dump exfil, ctypes downloaded-library loading, setup.py install-time network, cron/systemd/LaunchAgent persistence)
- **v0.21.68** (2026-10-19): 2 new guards: supabase-vault-exposure, Supabase Vault material reachable by anon/authenticated (body-proven vault-reading SECURITY DEFINER RPCs, decrypted views, DROP+CREATE ACL resets, privilege-aware grants and revokes incl. bulk ON ALL ... IN SCHEMA ordered against the first CREATE, writable search_path on vault definer functions; dual-mode, migration defaults vs pg_dump ACL), and supabase-vault-plaintext-leak, vault exposure a schema dump cannot vouch for (literal secrets passed to vault, statement logging in a vault repo, vault in pgrst.db_schemas / [api] schemas, grants on the vault schema itself)
- **v0.21.67** (2026-10-18): aisbom research-cycle: 5 new fail-closed ML model artifact guards (ml-artifact-committed, ml-pickle-dangerous-global, ml-keras-lambda-rce, ml-gguf-template-injection, ml-onnx-external-data) that parse untrusted pickle/Keras/GGUF/ONNX files without executing them
- **v0.21.66** (2026-10-18): Datadog GuardDog research-cycle: 6 new malware-pattern guards (reverse-shell-pattern, dns-exfiltration-pattern, destructive-filesystem-command, keylogging-pattern, download-execute-chain, autostart-persistence-mechanism) and obfuscated-payload-execution extended to JS/TS
- **v0.21.65** (2026-10-18): aws-agent-identity-guard research-cycle: 4 IAM guards widened to bare policy JSON (iam-notaction-with-allow, iam-escalation-action-no-condition + PassRole PassedToService, iam-wildcard escalation partial-wildcard, iam-role-public-assume delivery-service confused-deputy review signal + org-scoping rule) and 3 new agent-workload IAM guards (agent-iam-control-plane-exposure, agent-iam-tool-resource-unscoped, agent-iam-killchain-combination)
- **v0.21.64** (2026-10-18): mcp-raw-execution-tool-name: new MCP guard flagging a tool declared with a raw code/command-execution primitive as its own name
- **v0.21.63** (2026-10-12): sentrymcp research-cycle: 2 new MCP guards (mcp-hardcoded-credential as a non-gating review signal, mcp-overprivileged-scope), mcp-tool-path-traversal and mcp-transport-no-auth extended to JS/TS, js-code-injection MCP tool-argument taint
- **v0.21.62** (2026-10-12): MCPVul research-cycle: mcp-tool-description-injection widened (8 high-risk markers + confusable duplicate-name detection), upstream-response-unvalidated widened (5 tool raw-return sinks), 2 new guards (mcp-session-id-security, mcp-unsafe-auth-url-launch)
- **v0.21.61** (2026-09-30): Wave 5 re-land: injection/execution/RCE guards (argv-toctou, sandbox-denylist-bypass, crewai-rce-chain, claude-hook-rce, policy-truncation, mcp-transport-flip, claude-routines-security) + vscode-tasks-auto-exec/log-injection/llm-query-engine-execution extensions (from the agent-audit-kit deep-mine batch, PR #955 split)
- **v0.21.60** (2026-09-30): Wave 4 re-land: agentic supply-chain and trust-boundary guards (agent-headless-trust-surface, approval-parser-shell-desync, skill-untrusted-exec-path, skill-poisoning, shared-resource-authz, agentic-skills-ast, trust-boundary) split from PR #955, with a real-corpus CRITICAL FP fix for agent-headless-trust-surface's untrusted-trigger/PR-head-checkout correlation.
- **v0.21.59** (2026-09-30): Wave 3 re-land: MCP spec-conformance guards (server-card-integrity, tasks-lifecycle, stateless-migration, tunnel-config-security, apps-ui-isolation, oauth-flow-hardening) split from PR #955, with real-corpus FP fixes for oauth-flow-hardening (authorize() verb ambiguity, JSON-Schema/Mintlify docs-site configs, and doc-nav path-like-string fragments).
- **v0.21.58** (2026-09-30): Wave 2 re-land: MCP transport/auth/sandbox core + SSRF guards (8 new checklist items, from the agent-audit-kit deep-mine batch, PR #955 split)
- **v0.21.57** (2026-09-30): Wave 6 re-land: supply-chain hygiene (npm install-script network reach, mcp-config-security unpinned-fetcher/relative-path/loopback-pivot) + tool-description-injection encoded-payload extension (from the agent-audit-kit deep-mine batch, PR #955 split)
- **v0.21.56** (2026-09-30): Add env-file-not-gitignored guard; extend mcp-config-security (ws:// transport, URL-embedded secrets, remote no-auth entries, unconventional-filename discovery); 3 version floors (mcp-framework, @mcpjam/inspector, litellm)
- **v0.21.55** (2026-09-24): 7 new MCP protocol-layer guards from agent-audit-kit (env-placeholder exfil, unvalidated SSRF destination, sampling without consent, unbounded tools/list, routing desync, toolgate asymmetry, marketplace fetch-then-spawn) + code-injection-eval-exec and mcp-config-security extensions
- **v0.21.54** (2026-09-23): Batch C (MCP hardening): new mcp-oauth-scope-creep guard + ContextCrush trust-boundary widening (rag-trust-boundary, rag-no-instruction-filter now recognize MCP tool-call results)
- **v0.21.53** (2026-09-23): dependency-version-floor: Java/Maven + Rust/Cargo ecosystem support (pom.xml, build.gradle, Cargo.lock) + MCP Java/Rust SDK floors (CVE-2026-34237, CVE-2026-42559, CVE-2026-35577)
- **v0.21.52** (2026-09-23): Batch B (MCP hardening): mcp-tool-path-traversal guard + mcp-transport-dns-rebinding guard
- **v0.21.51** (2026-09-23): Batch A (MCP hardening): promisify(exec) command-injection coverage + new mcp-transport-no-auth guard + mcp version-floor bump (CVE-2026-59950, CVE-2026-52870)
- **v0.21.50** (2026-09-23): dependency-version-floor: Go ecosystem support (go.sum) + MCP Go SDK floor (CVE-2026-33252)
- **v0.21.49** (2026-09-22): vscode-tasks-auto-exec: detect VSCode tasks.json auto-exec on folder open
- **v0.21.48** (2026-09-22): graphql applies_when tagging (2b-idor-prevention, 7-pg-graphql-no-anon-authenticated-table-exposure) + corpus discovery queries widened (mcp-server + Next.js/TS) and `count` spread across every query
- **v0.21.47** (2026-09-22): Database Security: 19 new RLS/Postgres guards mined from the pgrls-postgres-rls catalog (PR #893)
- **v0.21.46** (2026-09-20): Land codeql-security-queries batch 6: Express/Node extensions (insecure-cookies, jwt-alg, secret-in-url-query, js-cors-wildcard) + 3 new guards (js-host-header-email-link, js-loop-bound-injection, js-http-to-file-access)
- **v0.21.45** (2026-09-20): Next.js Server Actions auth guard + middleware matcher fix, outside-in scan-live-url
- **v0.21.44** (2026-09-20): React Native/Expo mobile support: AsyncStorage insecure token storage guard
- **v0.21.43** (2026-09-19): CI image build/push pipelines flagged when missing an SBOM or provenance/signing step (Google/Wiz vibe-coding report gap G4)
- **v0.21.42** (2026-09-19): Next.js guard suite batch 1: NEXT_PUBLIC_ client secrets, Route Handler auth-missing surfacing check (nextjs promoted from uncovered_stacks to a real feature)
- **v0.21.41** (2026-09-19): Supabase Splinter lint catalog audit: pgmq queue exposure, fkey-to-auth non-primary, pg_graphql anon/authenticated table exposure (3 new guards)
- **v0.21.40** (2026-09-16): rate-limit-no-persistent-store: scope the storage_uri check per-Limiter, closing a cross-file false negative
- **v0.21.39** (2026-09-15): 7 AWS resource encryption-at-rest/KMS guards (checkov batch 3): dynamodb/ebs/sqs/sns/ecr/cloudwatch/secrets-manager Terraform encryption checks
- **v0.21.38** (2026-09-14): jwt-key-source-allowlist guard (unverified JWT signing-key source) + pydantic-model-construct precision fix; stripe-payments Rule 5 (`sk_live_` secret-key literal in backend source, #731); compounding-risk co-firing signal (#683); vitest-vs-Vite frontend detection fix (#727)
- **v0.21.37** (2026-09-13): CloudFormation stack support — template detection (JSON + YAML) + 18 cfripper/cfn-nag-derived guards (KMS key rotation, wildcard resource-policy principals, IAM privilege-escalation, IAM NotAction+Allow, IAM user direct-policy, S3 versioning, S3 public canned-ACL, RDS publicly-accessible, RDS hardcoded/unmasked MasterUserPassword, ECR scan-on-push, VPC flow logs, Cognito MFA-off, Cognito unauthenticated identities, WAF default-allow, Batch privileged container, EC2 subnet auto-assign-public-IP, NACL ineffective-deny, CloudFormation::Authentication literal password), plus guard-scope fixes and the `Resources:`/`Parameters:` header-comment silent-miss fixes (#856/#857)
- **v0.21.36** (2026-09-13): PHP stack detection + 9 graudit-derived guards (php-preg-replace-eval-modifier, php-code-injection, php-command-injection, php-unsafe-deserialization, php-file-inclusion, php-sql-injection, php-tls-verify-disabled, php-extract-superglobal-overwrite, php-reflected-xss)
- **v0.21.35** (2026-09-12): ARM template detection + 5 new Azure guard checks (azure-template-analyzer batch)
- **v0.21.34** (2026-09-12): Bicep detection + 7 new @secure()-decorator guard checks (azure-bicep-linter batch)
- **v0.21.33** (2026-09-12): agentsec's first Ruby-language coverage — 8 new guards (Brakeman research batch): weak hash (MD5/SHA-1), command injection (shell string vs. the safe argv-array form), unsafe deserialization (Marshal/YAML/Oj), TLS verification disabled, Rails mass-assignment (Strong Parameters defeated), ActiveRecord SQL injection, unsafe dynamic reflection (constantize/const_get), and dynamic method dispatch (send/public_send/try) — plus Ruby stack detection and shared scanning infrastructure (`ruby_scan_dirs`, `strip_ruby_comments`)
- **v0.21.32** (2026-09-12): Java stack detection + 10 find-sec-bugs-derived guards (java-weak-crypto, java-path-traversal, java-command-injection, java-sql-injection, java-ldap-injection, java-ssrf, java-xxe-unsafe-parsing, java-unsafe-deserialization, java-hardcoded-password-key, java-tls-verify-disabled)
- **v0.21.31** (2026-09-05): 5 K8s manifest security guard checks (KubeLinter batch)
- **v0.21.30** (2026-09-05): 5 docker-compose security guard checks (DockSec batch)
- **v0.21.29** (2026-09-05): K8s RBAC dangerous-verb grants guard (Kubescape batch)
- **v0.21.28** (2026-09-05): 5 new Terraform AWS IAM guard checks (Pike batch)
- **v0.21.27** (2026-09-05): 5 new KICS Azure/GCP Terraform public-access + TLS guards
- **v0.21.26** (2026-09-04): 12 llm-stack guard extensions (llm checklist coverage 33.3% -> 36.5%), plus round-5 fixes for a loop-guard false-positive/false-negative pair
- **v0.21.25** (2026-09-02): 5 new Python guards from the NotebookLM Tier 2 sweep: Supabase filter injection and anon-key RLS reachability, Redis glob-pattern injection, truthy ownership checks, agent-resume trigger verification
- **v0.21.24** (2026-08-30): GraphQL mutation IDOR detection (graphql-mutation-idor) + the graphql stack feature, closing the NotebookLM security-news sweep
- **v0.21.23** (2026-08-30): NotebookLM sweep Tier 2 JS/TS: nosql-injection-js (Mongoose type-confusion NoSQL injection, CVE-2026-30833) + unawaited-async-truthy (unawaited async call as truthy conditional, CVE-2026-28514)
- **v0.21.22** (2026-08-29): NotebookLM sweep Tier 0: langflow CVE-2026-9198 floor bump + 5 new dependency floors (starlette DoS, ormar, vite, mastra-docs-server, mlflow) + 1 new manual checklist item
- **v0.21.21** (2026-08-27): 5 new Database Security guards from a database-sentinel research audit (policy-no-role-scope, storage-no-rls, matview-exposed, sensitive-columns, rls-auth-uid-unwrapped), plus a piv-review-pr round disclosing + pinning a shared string-literal comment-blanking gap across all 3 SQL-comment-aware guards in the batch
- **v0.21.20** (2026-08-25): js-supply-chain: lockfile-manifest drift detection, with the pnpm+yarn coexistence skip and a mutation-proofed drift test
- **v0.21.19** (2026-08-24): batch2: 5 new guards, 2 FP fixes, and the scan-dir overlap dedupe
- **v0.21.18** (2026-08-24): 5 new guards from a careful re-mine of pasted FastAPI security articles + the pre-Tier-1 backlog: secret-str-serialized, request-body-size-unbounded, llm-output-secrets-unscanned, ansi-escape-llm-output, sql-race-check-then-insert. Plus 2 false-positive fixes (auto-updates-absent, jsx-href-scheme).
- **v0.21.18** (2026-08-24): iac-security-scanner batch: 5 new guards (Step Functions, ECR, AWS observability hygiene, K8s resource limits, K8s default-namespace) + terraform_hardcoded_secret_literal extensions (variable/locals/output blocks, embedded user_data secrets)
- **v0.21.17** (2026-08-21): Tag checklist items with HIPAA (164.308/164.312) and EU AI Act (Art 9/11/12/14/15) citations; add 14-ai-interaction-disclosure (Art 50)
- **v0.21.16** (2026-08-21): compose-lint: 9 Docker Compose guards + prompt-injection-safe report output
- **v0.21.15** (2026-08-19): agent-memory-user-scope: Mem0 client write-site + hollow-scope-binding (a scope kwarg bound to a constant), plus its review-fix round
- **v0.21.14** (2026-08-16): close the SKILL.md blind spot in claude-code-compromise + obfuscated-payload-execution (shell decode-exec chains in agent-skill bundles, connectedness over proximity, gitignored `.claude/` now scanned)
- **v0.21.13** (2026-08-15): PR #601 review-fix round: proxy case-encoding, OSV batch-truncation disclosure, comment-scoped detection, library webhook verification scoped to svix/standardwebhooks after the first attempt silently suppressed genuinely unverified handlers, Grafana secrets-file recognition, README runner count, checklist-section doc fixes
- **v0.21.12** (2026-08-14): mechanism C: go-osv-hygiene runner (OSV Go module CVE scan + module-path resolution hygiene), extended same day to also check `replace`-directive targets (a `require`-clean/`replace`-vulnerable go.mod was previously invisible)
- **v0.21.11** (2026-08-14): mechanism B: go-build-supply-chain-footgun guard (unpinned go install @latest/@master/@main, GOSUMDB=off/GONOSUMCHECK)
- **v0.21.10** (2026-08-14): New webhook-signature-not-verified guard, JadePuffer defense plan B3 (default-service-credential) + B4 (db-role-privilege-excessive), hostaudit egress/crontab probes, foreign_artifacts Go-artifact-layer disclosure
- **v0.21.9** (2026-08-14): PR #548 gate fixes, rounds 3 and 4: quote-aware split_call_args, security-headers evidence scoping, protocol-relative open-redirect gap closed for both `//host` and `/\host`, TS applies_when parity on 6 guards, and a rule-4 pragma regression test that could not fail
- **v0.21.8** (2026-08-12): CodeQL JS/TS research batches 7-11: 15 new guards + 6 Python guards widened to JS/TS, plus 4 checklist-parity applies_when fixes
- **v0.21.7** (2026-08-12): 7 new guards: the first Go-specific batch (go-ssh-host-key-trust, go-pprof-exposed, go-tls-verify-disabled, go-sql-injection, go-template-html-escaping), plus client-side-auth-decision and homoglyph-source-chars, with Go support extended to invisible-unicode and hardcoded-llm-provider-key
- **v0.21.6** (2026-08-08): new llm-tool-result-leak guard: an exception stringified into an LLM tool's return value, re-derived around a single tool-class discriminator
- **v0.21.5** (2026-08-06): Extend mcp-config-security + tool-callback-enforcement + credential-file-path-reference, add auth-disabled-by-default guard (agent-threat-rules research)
- **v0.21.4** (2026-08-06): Add hardcoded-llm-provider-key guard (OpenAI/Anthropic/Google AI/Hugging Face key literals in Python source)
- **v0.21.3** (2026-08-05): full 4-rule canary liveness coverage for agent-memory-security and acp-vulnerabilities, plus the 4 OWASP tags they emit now reflected on their mapped checklist items
- **v0.21.2** (2026-08-04): new client-side-secret-literal guard, a large false-positive precision sweep across the #423/#424 guard batches, per-guard non-product surface skips, and Python openai/anthropic SDK LLM detection
- **v0.21.1** (2026-07-31): checkov batch 3 — 6 KMS/Key-Vault key-hygiene guards (AWS KMS rotation/disabled, Azure Key Vault purge-protection/key-expiration, GCP KMS public-IAM/rotation-period), plus `s3-bucket-policy-wildcard-principal` extended to `aws_kms_key` policies.
- **v0.20.20** (2026-07-16): CodeQL security-queries batches 4/5/6 (Python + JS/TS guards)
- **v0.20.16** (2026-07-16): llmarmor batch: LLM tool-dispatch + agentic guard extensions
- **v0.20.15** (2026-07-15): checkov batch 2: IAM hygiene + CloudTrail audit logging
- **v0.20.14** (2026-07-15): drogonsec 5-guard batch
- **v0.20.13** (2026-07-14): njsscan: Node.js/Express/Electron guards
- **v0.20.12** (2026-07-14): ansible-security-scanner: first Ansible playbook coverage (7 guards)
- **v0.20.11** (2026-07-14): kubesec K8s manifest security: 10 new guards
- **v0.20.10** (2026-07-14): parallel research batch: 9 new guards
- **v0.20.9** (2026-07-14): checkov IaC: 5 new guards
- **v0.20.8** (2026-07-14): skillspector: 5 new guards
- **v0.20.7** (2026-07-14): Cisco skill-scanner: 5 new guards
- **v0.20.6** (2026-07-08): mcp-tool-env-inheritance guard
- **v0.20.5** (2026-07-08): datastore-auth-absent guard + ast lexing hardening
- **v0.20.4** (2026-07-06): langflow CVE version floor
- **v0.20.3** (2026-07-05): guard/checklist precision
- **v0.20.2** (2026-07-05): supabase-storage-public write-statement gate
- **v0.20.1** (2026-07-05): Guard mitigation-pattern recognition

---

## Pre-v0.19.2 history

Development before the first tag is not back-filled here. The full history is in the git log and the merge ledger
(the maintainers' development-workflow doc describes the Loop A/B/C process and the ledger). Notable prior milestones: the
zero-runtime-dependency guard/runner pipeline, the tiered network-egress policy, and the checklist-as-single-source-of-truth version model (PR #121).
