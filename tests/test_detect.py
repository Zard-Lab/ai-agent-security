"""Tests for stack detection — fingerprints a synthetic SaaS repo."""
from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.audit import audit
from agentsec.detect import _MAX_PY_SCAN, StackProfile, _strip_trailing_comment, detect
from tests._timing import assert_growth


def _build_saas_repo(root: Path) -> None:
    (root / "backend_agent_api").mkdir()
    (root / "sql").mkdir()
    (root / "frontend").mkdir()
    (root / "requirements.txt").write_text(
        # pydantic-ai pinned >= 1.99.0 (patched SSRF floor, CVE-2026-25580/46678) so this
        # "clean" fixture stays clean as the dependency-version-floor registry grows.
        "fastapi==0.115.12\npydantic-ai==1.99.0\nsupabase==2.15.1\nstripe==10.0.0\n", encoding="utf-8"
    )
    # a clean SaaS backend resolves to a hash-verified uv.lock + a 48h install
    # cooldown (so the python-supply-chain guard stays quiet, like the hardened base)
    (root / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "fastapi"\nversion = "0.115.12"\n'
        '[[package.wheels]]\nhash = "sha256:deadbeefcafe"\n', encoding="utf-8"
    )
    (root / "uv.toml").write_text('exclude-newer = "48 hours"\n', encoding="utf-8")
    (root / "backend_agent_api" / "agent.py").write_text(
        "from fastapi import FastAPI\nfrom pydantic_ai import Agent\nfrom supabase import create_client\n", encoding="utf-8"
    )
    (root / "backend_agent_api" / "stripe_utils.py").write_text(
        "import stripe\n\n"
        "def handle_webhook(request, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(request, sig, secret)\n"
        "    if _already_processed(event.id):\n"
        "        return {\"status\": \"duplicate\"}\n"
        "    return event\n"
        "\n"
        "def _already_processed(event_id: str) -> bool:\n"
        "    return False\n", encoding="utf-8"
    )
    (root / "sql" / "01-tables.sql").write_text(
        "CREATE TABLE public.profiles (id uuid primary key);\n"
        "ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY profile_owner ON public.profiles TO authenticated "
        "USING (id = (select auth.uid()));\n", encoding="utf-8"
    )
    # a clean SaaS frontend: pinned deps + pinned packageManager (pnpm)
    (root / "frontend" / "package.json").write_text(
        '{"packageManager": "pnpm@11.9.0", "dependencies": {"react": "19.0.0", "vite": "8.0.5"}}', encoding="utf-8"
    )
    # ...a committed lockfile + a 48h cooldown + trust policy (so js-supply-chain stays quiet).
    # pnpm blocks build scripts by default → no lifecycle-scripts finding.
    (root / "frontend" / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (root / "frontend" / "pnpm-workspace.yaml").write_text(
        "minimumReleaseAge: 2880\ntrustPolicy: no-downgrade\n", encoding="utf-8"
    )
    (root / ".env.example").write_text(
        "STRIPE_SECRET_KEY=sk_test_x\nSTRIPE_WEBHOOK_SECRET=whsec_x\nVITE_STRIPE_PUBLISHABLE_KEY=pk_test_x\n", encoding="utf-8"
    )
    (root / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")


def test_detect_saas_profile(tmp_path: Path) -> None:
    _build_saas_repo(tmp_path)
    prof = detect(tmp_path)
    assert prof.backend_framework == "fastapi"
    assert prof.llm_framework == "pydantic-ai"
    assert prof.db == "supabase"
    assert prof.frontend == "vite-react"
    assert prof.has_payments is True
    assert prof.has_docker is True
    assert prof.has_rls_sql is True
    assert prof.sql_dir == "sql"
    assert prof.frontend_dir == "frontend"
    assert {"python", "fastapi", "pydantic-ai", "llm", "supabase", "frontend", "sql", "rls", "payments", "docker"} <= prof.features


def test_detect_vitest_devdep_is_not_mislabeled_vite_react(tmp_path: Path) -> None:
    # FP-bait: a Next.js app that uses vitest for unit tests (no actual Vite bundler) must
    # report frontend="react", not "vite-react" — an unquoted "vite" substring match on the
    # lowercased manifest text matches inside "vitest"/"@vitejs/plugin-react" too, both common
    # test-only devDependencies unrelated to the build tool (found scanning a real Next.js repo).
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"next": "^16.0.0", "react": "^19.0.0"}, '
        '"devDependencies": {"vitest": "^3.0.0", "@vitejs/plugin-react": "^5.0.0"}}',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.frontend == "react"


def test_detect_real_vite_dep_is_still_vite_react(tmp_path: Path) -> None:
    # The direction traded against above: a genuine Vite dependency must still label vite-react.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "^19.0.0", "vite": "^5.0.0"}}',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.frontend == "vite-react"


def test_detect_supabase_comment_mention_is_not_supabase(tmp_path: Path) -> None:
    # FP-bait (§D.4): a repo whose only "supabase" is a doc/comment mention (listing it as one
    # optional Postgres provider) and that uses the `pg` driver directly must NOT be db=supabase —
    # otherwise public-table-rls treats its `public` tables as anon-reachable (8 FPs on remote-coding-agent).
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"pg": "^8.11.0"}}', encoding="utf-8"
    )
    (tmp_path / ".env.example").write_text(
        # every "supabase" here is a COMMENT/substring trap, never a real declaration/assignment:
        "# DATABASE_URL=postgresql://user:pass@host:5432/db  (point to Supabase, Neon, etc.)\n"
        "# see the docs at www.supabase.com — this app does NOT use SUPABASE_URL, remove it\n"
        "# (a managed provider such as aws-0-us-east.pooler.supabase.com also works)\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.db != "supabase"  # PR #481 review: .supabase.com / commented env-var names must NOT match
    assert "supabase" not in prof.features


def test_detect_supabase_js_dep_is_supabase(tmp_path: Path) -> None:
    # Real Supabase usage: the `@supabase/supabase-js` client dependency → db=supabase.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@supabase/supabase-js": "^2.45.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.db == "supabase"
    assert "supabase" in prof.features


def test_detect_js_llm_sdk_openai(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"openai": "^4.20.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.llm_framework == "js-llm-sdk"
    assert "llm" in prof.features


def test_detect_js_llm_sdk_anthropic(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@anthropic-ai/sdk": "^0.30.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.llm_framework == "js-llm-sdk"


def test_detect_no_js_llm_sdk_from_keywords_tag(tmp_path: Path) -> None:
    # FP-bait (review #395 Major finding): "openai" named as a keyword tag, not a real
    # dependency, must not set the js-llm-sdk framework or the llm feature.
    (tmp_path / "package.json").write_text(
        '{"name": "demo", "keywords": ["openai", "chatbot"], "dependencies": {"express": "^4.18.0"}}',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.llm_framework is None
    assert "llm" not in prof.features


def test_detect_js_llm_sdk_openrouter_real_dependency(tmp_path: Path) -> None:
    # Review #395 Minor finding: the real openrouter JS SDK package is `@openrouter/sdk`.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@openrouter/sdk": "^1.0.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.llm_framework == "js-llm-sdk"


def test_detect_no_js_llm_sdk_from_bare_openrouter_string(tmp_path: Path) -> None:
    # The old bare "openrouter" substring match was a dead branch — no real package is named
    # just "openrouter".
    (tmp_path / "package.json").write_text(
        '{"name": "openrouter-demo", "dependencies": {"express": "^4.18.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.llm_framework is None


def test_detect_no_js_llm_sdk_by_default(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "^4.18.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.llm_framework is None
    assert "llm" not in prof.features


def test_detect_python_llm_sdk_openai_import(tmp_path: Path) -> None:
    # The RAG-app case: a FastAPI app that reaches an LLM via the `openai` SDK (here pointed at
    # OpenRouter) must fingerprint `llm` so the whole LLM/agentic guard family runs. Previously only
    # pydantic-ai/langchain were matched for Python, so this app got `llm=-` and every LLM-gated
    # guard was silently N/A-suppressed.
    (tmp_path / "requirements.txt").write_text("fastapi==0.115.0\nopenai==1.40.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "from openai import OpenAI\n"
        "client = OpenAI(base_url='https://openrouter.ai/api/v1')\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.llm_framework == "python-llm-sdk"
    assert "llm" in prof.features


def test_detect_python_llm_sdk_anthropic_import(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("anthropic==0.40.0\n", encoding="utf-8")
    (tmp_path / "svc.py").write_text("import anthropic\nc = anthropic.Anthropic()\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.llm_framework == "python-llm-sdk"
    assert "llm" in prof.features


@pytest.mark.parametrize(
    "import_line",
    [
        "import openai as oai",              # aliased
        "from litellm import completion",
        "import cohere",
        "from groq import Groq",
        "import together",
        "from mistralai import Mistral",
        "import ollama",
        "import instructor",
        "import google.generativeai as genai",   # dotted form
        "from google.genai import types",        # dotted-from form
        "from google import genai",              # the SDK's documented headline form
        "from google import types, genai",       # genai not first in a single-line name list
        "from google import genai, types",       # genai first, with siblings
        "from google import (\n    types,\n    genai,\n)",  # parenthesized multi-line list
    ],
)
def test_detect_python_llm_sdk_each_provider(tmp_path: Path, import_line: str) -> None:
    # Every provider name in _PY_LLM_IMPORT sets the llm feature — including the google-genai SDK's
    # `from google import genai` headline form (which the dotted-only pattern missed; PR #465 review).
    (tmp_path / "app.py").write_text(f"from fastapi import FastAPI\n{import_line}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.llm_framework == "python-llm-sdk", import_line
    assert "llm" in prof.features


def test_detect_no_python_llm_sdk_from_other_google_import(tmp_path: Path) -> None:
    # FP-bait: `from google import auth` / `import google.cloud` (non-LLM google libs) must NOT match
    # — only the `genai`/`generativeai` google sub-packages count.
    (tmp_path / "app.py").write_text(
        "from google import auth\nimport google.cloud.storage\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.llm_framework is None
    assert "llm" not in prof.features


def test_detect_google_import_name_list_is_statement_bounded(tmp_path: Path) -> None:
    # FP-bait (PR #465 review, Medium): `from google import auth` must NOT be swept into a match by a
    # `genai` token on a LATER unrelated line — the `from google import <names>` scan is bounded to
    # the import statement (stops at the newline / closing paren), so this stays llm=None.
    (tmp_path / "app.py").write_text(
        "from google import auth\n"
        "genai_cache = {}  # unrelated variable that merely contains 'genai'\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.llm_framework is None
    assert "llm" not in prof.features


def test_detect_no_python_llm_sdk_from_model_name_string(tmp_path: Path) -> None:
    # FP-bait (mirrors the review #395 anchoring lesson): a bare "openai" in a model-name string or
    # comment, with no `import`, must NOT set the llm feature — otherwise every LLM-gated guard fires
    # on a non-LLM app.
    (tmp_path / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "# uses the openai/text-embedding-3-small naming convention elsewhere\n"
        "DEFAULT_MODEL = 'openai/text-embedding-3-small'\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.llm_framework is None
    assert "llm" not in prof.features


def test_detect_no_python_llm_sdk_from_unrelated_helper_import(tmp_path: Path) -> None:
    # Word-boundary guard: `import openai_helpers` (an unrelated third-party lib) must NOT match the
    # `openai` SDK pattern.
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\nimport openai_helpers\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.llm_framework is None
    assert "llm" not in prof.features


def test_clean_saas_repo_guards_have_no_high_findings(tmp_path: Path) -> None:
    # guards-only so the result is deterministic regardless of which external
    # scanners happen to be installed (they may flag real CVEs in the fixture deps).
    _build_saas_repo(tmp_path)
    result = audit(tmp_path, run_scanners=False)
    # payments guard is selected (Stripe detected) but the webhook verifies → no payment finding
    assert "stripe-payments" in result.ran
    assert "public-table-rls" in result.ran
    assert not [f for f in result.findings if f.severity in ("high", "critical")]


def test_gitignore_negation_keeps_env_example(tmp_path: Path) -> None:
    """A `.gitignore` of `.env.*` with `!.env.example` (the flagship pattern) must NOT
    hide `.env.example` from detection — else Stripe/payments detection regresses."""
    _build_saas_repo(tmp_path)
    (tmp_path / ".gitignore").write_text(
        ".env\n.env.*\n!.env.example\nnode_modules/\nfrontend/dist/\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.has_payments is True               # .env.example survived the gitignore
    assert prof.backend_framework == "fastapi"     # manifests still detected


def test_no_payments_suppresses_stripe_guard(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n", encoding="utf-8")
    result = audit(tmp_path, run_scanners=False)
    assert "stripe-payments" in result.skipped  # N/A: no payments detected
    assert "stripe-payments" not in result.ran


@pytest.mark.slow
def test_runner_selection_records_unavailable(tmp_path: Path) -> None:
    # A python repo selects scanners; ones whose binary is absent are recorded,
    # not fatal. (At least one of bandit/pip-audit/semgrep is typically absent in CI.)
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n", encoding="utf-8")
    result = audit(tmp_path, run_scanners=True)
    handled = set(result.ran) | set(result.tools_unavailable) | set(result.tools_errored)
    assert {"bandit", "pip-audit", "semgrep", "gitleaks"} & handled


def test_sql_dir_prefers_live_over_archived(tmp_path: Path) -> None:
    # A repo carrying BOTH a live top-level sql/ and an archived old/**/sql copy must
    # resolve sql_dir to the LIVE one — else the whole RLS guard family scans the dead
    # tree and silently misses the real schema (regression for #111).
    (tmp_path / "sql").mkdir()
    (tmp_path / "sql" / "0-all-tables.sql").write_text(
        "CREATE TABLE public.user_profiles (id uuid, is_admin boolean);\n"
        "ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    archived = tmp_path / "old" / "4_Pydantic_AI_Agent" / "sql"
    archived.mkdir(parents=True)
    (archived / "0-all-tables.sql").write_text(
        "CREATE TABLE public.legacy (id uuid);\n", encoding="utf-8"
    )

    prof = detect(tmp_path)
    assert prof.sql_dir == "sql", f"expected live 'sql', got {prof.sql_dir!r}"
    assert prof.has_rls_sql is True


def test_sql_dir_breaks_a_rank_tie_by_relative_path(tmp_path: Path) -> None:
    # Live, none named "sql", all one level deep: the last rank key decides, and it is the path
    # relative to the root, so the choice cannot depend on walk order or the checkout location.
    # `-` sorts before both `/` and `\`, and before `0`, so the answer is the same on Windows.
    for d in ("db0", "db", "db-a"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "a.sql").write_text("CREATE TABLE t (id int);\n", encoding="utf-8")
    assert detect(tmp_path).sql_dir == "db-a"


def test_detect_language_dirs_are_top_level_dirs_plus_root(tmp_path: Path) -> None:
    # All five lists come from one pass: each keeps only its own suffix, a nested file counts
    # under its TOP-level dir, and a root-level file counts as ".".
    for rel in ("app/api/deep/x.py", "main.py", "svc/cmd/m.go", "web/i.php", "lib/x.rb", "src/A.java",
                "docs/n.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.python_dirs == [".", "app"]
    assert (prof.go_dirs, prof.php_dirs, prof.ruby_dirs, prof.java_dirs) == (["svc"], ["web"], ["lib"], ["src"])


# --- uncovered-stack recogniser --------------------------------------------------


def test_detect_uncovered_django(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("django==4.2.0\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "django" in prof.uncovered_stacks
    assert "django" not in prof.features


def test_detect_uncovered_flask(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "flask" in prof.uncovered_stacks
    assert "flask" not in prof.features


def test_detect_express_is_a_real_feature_not_uncovered(tmp_path: Path) -> None:
    # 2026-07-13 (njsscan batch): express gained real guard coverage, so it's a proper
    # backend_framework/feature now, not a named-but-unguarded gap.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "^4.18.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.backend_framework == "express"
    assert "express" in prof.features
    assert "express" not in prof.uncovered_stacks


def test_detect_express_feature_present_alongside_fastapi(tmp_path: Path) -> None:
    # A polyglot repo (FastAPI backend + an Express gateway/BFF) must get BOTH features —
    # "express" is not just the fallback when fastapi is absent. backend_framework stays
    # single-valued (fastapi wins, first match), but the "express" feature must still gate
    # js-cors-wildcard and any other express-specific guard independent of that.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "^4.18.0"}}', encoding="utf-8"
    )
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.backend_framework == "fastapi"
    assert "fastapi" in prof.features
    assert "express" in prof.features


def test_detect_nextjs_config_file_is_a_real_feature(tmp_path: Path) -> None:
    # "nextjs" was promoted from uncovered_stacks to a real feature 2026-09-19 once a
    # dedicated Next.js guard suite existed (the same promotion "express" got 2026-07-13).
    (tmp_path / "next.config.ts").write_text("export default {};", encoding="utf-8")
    prof = detect(tmp_path)
    assert "nextjs" in prof.features
    assert "nextjs" not in prof.uncovered_stacks


def test_detect_nextjs_package_json_is_a_real_feature(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"next": "^14.0.0", "react": "^18.0.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert "nextjs" in prof.features
    assert "nextjs" not in prof.uncovered_stacks


def test_detect_uncovered_prisma_package(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@prisma/client": "^5.0.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert "prisma" in prof.uncovered_stacks


def test_detect_uncovered_prisma_schema_file(tmp_path: Path) -> None:
    prisma_dir = tmp_path / "prisma"
    prisma_dir.mkdir()
    (prisma_dir / "schema.prisma").write_text(
        'datasource db { provider = "postgresql" }', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert "prisma" in prof.uncovered_stacks


def test_detect_uncovered_empty_for_known_stack(tmp_path: Path) -> None:
    # fastapi is a guarded stack — must not appear in uncovered_stacks
    (tmp_path / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "fastapi" not in prof.uncovered_stacks


def test_detect_uncovered_empty_repo(tmp_path: Path) -> None:
    prof = detect(tmp_path)
    assert prof.uncovered_stacks == set()


def test_detect_uncovered_celery(tmp_path: Path) -> None:
    # The generalized table's actual net-new disclosure beyond django/flask (which existed
    # before the table-driven refactor) — celery has zero guard coverage, verified before
    # adding it (grepped agentsec/guards/*.py; its one hit was an unrelated docstring mention).
    (tmp_path / "requirements.txt").write_text("celery==5.3.0\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "celery" in prof.uncovered_stacks
    assert "celery" not in prof.features


# --------------------------------------------------------------------------- #
# Foreign-language census (design-stack-coverage-disclosure.md, Mechanism A)
# --------------------------------------------------------------------------- #


def test_foreign_language_below_floor_stays_silent(tmp_path: Path) -> None:
    # A single incidental script must not trigger a warning on every scan of an
    # otherwise pure-Python repo.
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "deploy.rb").write_text("puts 'deploying'\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_languages == set()


def test_foreign_language_below_floor_minus_one_stays_silent(tmp_path: Path) -> None:
    # Pins the exact boundary (#553 review, Dean, Low 6) — floor - 1 files stays silent, so a
    # future edit to _FOREIGN_LANGUAGE_FLOOR can't silently shift the off-by-one without a test
    # noticing. The existing below-floor test used 1 file; this uses floor - 1 (4) specifically.
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    for i in range(4):
        (tmp_path / f"service{i}.go").write_text("package main\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_languages == set()


def test_foreign_language_at_floor_discloses(tmp_path: Path) -> None:
    # Kotlin, not Go/Ruby/Java/PHP/Rust: all five graduated out of "foreign" once their own real
    # guard coverage landed (feat/go-stack-detection) — see the
    # coordination tests below for those boundaries specifically. Kotlin has no agentsec guard
    # coverage at all, so it stays a genuine "unscanned language" example for this floor-mechanic
    # test (Rust was this test's example before Rust detection gave it real Cargo.lock coverage).
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    for i in range(5):
        (tmp_path / f"service{i}.kt").write_text("fun main() {}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_languages == {"Kotlin"}


def test_foreign_language_ignores_non_code_extensions(tmp_path: Path) -> None:
    # .md/.json/.yaml are never candidates in the first place — the allowlist design means
    # a repo heavy on docs/config never misreads as an "unscanned language."
    for i in range(10):
        (tmp_path / f"doc{i}.md").write_text("# hi\n", encoding="utf-8")
        (tmp_path / f"config{i}.json").write_text("{}", encoding="utf-8")
        (tmp_path / f"workflow{i}.yaml").write_text("name: ci\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_languages == set()


def test_foreign_language_excludes_vendored_dirs(tmp_path: Path) -> None:
    # Reuses the same `_walk()` list the suffix-detection above already computes, so
    # anything `_walk` excludes (node_modules, .venv, etc.) is excluded here too. Uses PHP,
    # not Go or Ruby — both graduated out of foreign_languages entirely (feat/go-stack-detection,
    # then Ruby support), so an example in either would pass vacuously without exercising the exclusion.
    vendored = tmp_path / "node_modules" / "some-pkg"
    vendored.mkdir(parents=True)
    for i in range(10):
        (vendored / f"gen{i}.php").write_text("<?php echo 'hi';\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_languages == set()


def test_unguarded_dependency_table_matches_declaration_not_substring(tmp_path: Path) -> None:
    # A near-miss package name (a real plugin, not the thing itself) must not false-positive
    # — the exact protection _names_dep already provides for the pre-existing django/flask
    # checks, now exercised through the generalized table.
    (tmp_path / "requirements.txt").write_text("django-celery-results==2.5.1\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "celery" not in prof.uncovered_stacks
    assert "django" not in prof.uncovered_stacks

    (tmp_path / "requirements.txt").write_text("celery==5.3.0\n", encoding="utf-8")
    prof2 = detect(tmp_path)
    assert "celery" in prof2.uncovered_stacks


def test_unguarded_dependency_names_have_no_existing_guard() -> None:
    # Drift gate: if a guard is ever built for one of these, its entry must be removed from
    # _UNGUARDED_DEPENDENCIES in the same change — this test catches the table going stale.
    # Checks id AND title substring (#553 review, Dean, High 1) — an exact-id match alone
    # only catches a name that happens to equal a stack-feature tag or a full guard id; this
    # repo's guard ids are descriptive kebab-case (`stripe-payments`, not `stripe`), so a bare
    # technology name matching a guard id is close to the one shape that never occurs. The
    # title substring check catches the realistic case (planted: "stripe" against
    # `stripe-payments`'s title) without over-matching django/flask, which are intentionally
    # still in this table (partial coverage via other guards, not a guard *named* after them —
    # see the footer copy's "no dedicated guard suite yet" wording, not "no guards yet").
    from agentsec.checklist import load_checklist
    from agentsec.detect import _UNGUARDED_DEPENDENCIES
    from agentsec.registry import ALL_GUARDS

    guard_ids = {g.id for g in ALL_GUARDS}
    checklist_tags: set[str] = set()
    for item in load_checklist().items:
        checklist_tags.update(item.applies_when)

    for stack_name in _UNGUARDED_DEPENDENCIES.values():
        assert stack_name not in guard_ids, (
            f"{stack_name!r} now has a guard with a matching id — remove it from "
            "_UNGUARDED_DEPENDENCIES"
        )
        title_hits = [g.id for g in ALL_GUARDS if stack_name in g.title.lower()]
        assert not title_hits, (
            f"{stack_name!r} appears in the title of guard(s) {title_hits!r} — likely already "
            "covered under a different id; remove it from _UNGUARDED_DEPENDENCIES or confirm "
            "this is a false match before leaving it"
        )
        assert stack_name not in checklist_tags, (
            f"{stack_name!r} now appears in a checklist item's applies_when — remove it "
            "from _UNGUARDED_DEPENDENCIES"
        )


# --------------------------------------------------------------------------- #
# Go stack detection (feat/go-stack-detection, Phase 2 of the stack-coverage plan)
# --------------------------------------------------------------------------- #


def test_detect_go_language_and_feature(tmp_path: Path) -> None:
    # Widening: a real Go file must register as a detected language, and flow into
    # features automatically (feats starts as set(prof.languages) — no separate step).
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "go" in prof.languages
    assert "go" in prof.features


def test_detect_no_go_language_for_python_repo(tmp_path: Path) -> None:
    # Narrowing: an ordinary Python repo must not spuriously gain "go".
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "go" not in prof.languages
    assert "go" not in prof.features


def test_detect_go_uncovered_stack(tmp_path: Path) -> None:
    # No guards exist for Go yet (Phase 4 of the plan) — a Go repo must be honestly
    # disclosed via uncovered_stacks, the same mechanism django/flask/prisma use.
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "go" in prof.uncovered_stacks


def test_detect_go_not_uncovered_without_go_files(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "go" not in prof.uncovered_stacks


def test_detect_go_not_double_reported_as_foreign_language(tmp_path: Path) -> None:
    # Coordination test (the plan's own sequencing requirement): a Go repo well past the old
    # foreign-language floor must appear ONLY in uncovered_stacks, never in foreign_languages
    # too — Go graduated out of "foreign" the moment detect() gained real Go support.
    for i in range(10):
        (tmp_path / f"service{i}.go").write_text("package main\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "go" in prof.uncovered_stacks
    assert "Go" not in prof.foreign_languages
    assert prof.foreign_languages == set()


# --------------------------------------------------------------------------- #
# Rust language detection (Cargo.lock version-floor scanning) — minimal:
# no rust_dirs/rust_scan_dirs infrastructure was built (unlike Go/Java), since the only
# current consumer (dependency-version-floor's Cargo.lock scan) reads the repo root
# directly, mirroring how it already reads poetry.lock/package-lock.json.
# --------------------------------------------------------------------------- #


def test_detect_rust_language_and_feature(tmp_path: Path) -> None:
    (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "rust" in prof.languages
    assert "rust" in prof.features


def test_detect_no_rust_language_for_python_repo(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "rust" not in prof.languages
    assert "rust" not in prof.features


def test_detect_rust_not_double_reported_as_foreign_language(tmp_path: Path) -> None:
    # Coordination test (mirrors test_detect_go_not_double_reported_as_foreign_language): a Rust
    # repo well past the old foreign-language floor must appear ONLY in languages/features,
    # never in foreign_languages too -- Rust graduated out of "foreign" the moment
    # dependency-version-floor gained real Cargo.lock support.
    for i in range(10):
        (tmp_path / f"service{i}.rs").write_text("fn main() {}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "rust" in prof.languages
    assert "Rust" not in prof.foreign_languages
    assert prof.foreign_languages == set()


def test_detect_rust_uncovered_stack(tmp_path: Path) -> None:
    # (Dean's review): removing `.rs` from the foreign-language census graduated
    # Rust the same way PHP/Ruby/Java did, but unlike those three (each with 7+ dedicated
    # code-pattern guards), Rust has only the one narrow dependency-version-floor Cargo.lock
    # check -- so it needs Go's honest-disclosure treatment, not Java/PHP/Ruby's silence.
    (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "rust" in prof.uncovered_stacks


def test_detect_rust_not_uncovered_without_rust_files(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "rust" not in prof.uncovered_stacks


def test_detect_go_dirs_collected(tmp_path: Path) -> None:
    # Mirrors python_dirs exactly: top-level dirs containing .go, plus "." for root-level files.
    (tmp_path / "cmd").mkdir()
    (tmp_path / "cmd" / "main.go").write_text("package main\n", encoding="utf-8")
    (tmp_path / "internal").mkdir()
    (tmp_path / "internal" / "util.go").write_text("package internal\n", encoding="utf-8")
    (tmp_path / "root.go").write_text("package root\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.go_dirs == sorted(["cmd", "internal", "."])


def test_detect_go_dirs_empty_for_non_go_repo(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.go_dirs == []


# --------------------------------------------------------------------------- #
# PHP stack detection (graudit research batch) — mirrors the Ruby/Java sections
# (feat/prob328/feat/prob329) exactly: PHP never appears in uncovered_stacks, because real guard
# coverage (graudit-derived) lands in the SAME PR as detection.
# --------------------------------------------------------------------------- #



def test_detect_php_language_and_feature(tmp_path: Path) -> None:
    (tmp_path / "index.php").write_text("<?php echo 'hi'; ?>\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "php" in prof.languages
    assert "php" in prof.features


def test_detect_no_php_language_for_python_repo(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "php" not in prof.languages
    assert "php" not in prof.features


def test_detect_php_not_in_uncovered_stacks(tmp_path: Path) -> None:
    # Unlike Go's own history, PHP detection and real guard coverage land together — a PHP
    # repo must NOT be reported as an honest gap, because it isn't one.
    (tmp_path / "index.php").write_text("<?php echo 'hi'; ?>\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "php" not in prof.uncovered_stacks


def test_detect_php_not_double_reported_as_foreign_language(tmp_path: Path) -> None:
    # Coordination test: a PHP repo well past the old foreign-language floor must not appear
    # in foreign_languages either — PHP graduated out of "foreign" the moment detect() gained
    # real PHP support.
    for i in range(10):
        (tmp_path / f"page{i}.php").write_text("<?php echo 'hi'; ?>\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "PHP" not in prof.foreign_languages
    assert prof.foreign_languages == set()


def test_detect_php_dirs_collected(tmp_path: Path) -> None:
    # Mirrors python_dirs/go_dirs/java_dirs exactly: top-level dirs containing .php, plus "."
    # for root-level files.
    (tmp_path / "src" / "controllers").mkdir(parents=True)
    (tmp_path / "src" / "controllers" / "App.php").write_text("<?php\n", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "util.php").write_text("<?php\n", encoding="utf-8")
    (tmp_path / "index.php").write_text("<?php\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.php_dirs == sorted(["src", "lib", "."])


def test_detect_php_dirs_empty_for_non_php_repo(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.php_dirs == []


# --------------------------------------------------------------------------- #
# Java stack detection (find-sec-bugs research batch) — mirrors the Ruby section
# below (feat/prob328) exactly: Java never appears in uncovered_stacks, because real guard
# coverage (find-sec-bugs-derived) lands in the SAME PR as detection.
# --------------------------------------------------------------------------- #


def test_detect_java_language_and_feature(tmp_path: Path) -> None:
    (tmp_path / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "java" in prof.languages
    assert "java" in prof.features


def test_detect_no_java_language_for_python_repo(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "java" not in prof.languages
    assert "java" not in prof.features


def test_detect_java_not_in_uncovered_stacks(tmp_path: Path) -> None:
    # Unlike Go's own history, Java detection and real guard coverage land together — a Java
    # repo must NOT be reported as an honest gap, because it isn't one.
    (tmp_path / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "java" not in prof.uncovered_stacks


def test_detect_java_not_double_reported_as_foreign_language(tmp_path: Path) -> None:
    # Coordination test: a Java repo well past the old foreign-language floor must not appear
    # in foreign_languages either — Java graduated out of "foreign" the moment detect() gained
    # real Java support.
    for i in range(10):
        (tmp_path / f"Service{i}.java").write_text("class Service {}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "Java" not in prof.foreign_languages
    assert prof.foreign_languages == set()


def test_detect_java_dirs_collected(tmp_path: Path) -> None:
    # Mirrors python_dirs/go_dirs/ruby_dirs exactly: top-level dirs containing .java, plus "."
    # for root-level files.
    (tmp_path / "src" / "main").mkdir(parents=True)
    (tmp_path / "src" / "main" / "App.java").write_text("class App {}\n", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "Util.java").write_text("class Util {}\n", encoding="utf-8")
    (tmp_path / "Root.java").write_text("class Root {}\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.java_dirs == sorted(["src", "lib", "."])


def test_detect_java_dirs_empty_for_non_java_repo(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.java_dirs == []


def test_detect_go_detection_does_not_need_go_mod_in_manifests(tmp_path: Path) -> None:
    # go.mod is deliberately NOT in _MANIFESTS (#554 review, Dean, Major — see the comment at
    # its definition). Go detection must still work from the .go suffix signal alone, with or
    # without a go.mod present.
    (tmp_path / "go.mod").write_text("module example.com/svc\n\ngo 1.22\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "go" in prof.languages
    assert "go" in prof.uncovered_stacks


def test_detect_go_mod_does_not_contaminate_manifest_derived_features(tmp_path: Path) -> None:
    # Regression test for #554's Major review finding (Dean, verified end-to-end): a Go module
    # path is a full URL, so an ordinary Go dependency on the real Stripe/Supabase Go SDKs would
    # collide with the unanchored `"stripe" in manifest_text` / `"supabase" in manifest_text`
    # checks if go.mod were ever read into the shared manifest blob — flipping `payments`/`db`
    # on and sending 14 Python/SQL-only guards into "Checks run" with zero findings instead of
    # "Skipped (N/A)", on a stack none of them can actually read.
    (tmp_path / "go.mod").write_text(
        "module example.com/svc\n\ngo 1.22\n\nrequire (\n"
        "\tgithub.com/stripe/stripe-go/v76 v76.25.0\n"
        "\tgithub.com/supabase-community/supabase-go v0.0.4\n)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.has_payments is False
    assert prof.db is None
    assert "payments" not in prof.features
    assert "supabase" not in prof.features
    # Go detection itself is untouched by the fix.
    assert "go" in prof.languages
    assert "go" in prof.uncovered_stacks


# --------------------------------------------------------------------------- #
# Ruby stack detection (brakeman research batch) — mirrors the Go section above
# exactly, with one deliberate difference: Ruby never appears in uncovered_stacks, because
# real guard coverage (brakeman-derived) lands in the SAME PR as detection, unlike Go's own
# "detection first, guards later" sequencing.
# --------------------------------------------------------------------------- #


def test_detect_ruby_language_and_feature(tmp_path: Path) -> None:
    (tmp_path / "app.rb").write_text("puts 'hi'\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "ruby" in prof.languages
    assert "ruby" in prof.features


def test_detect_no_ruby_language_for_python_repo(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "ruby" not in prof.languages
    assert "ruby" not in prof.features


def test_detect_ruby_not_in_uncovered_stacks(tmp_path: Path) -> None:
    # Unlike Go's own history, Ruby detection and real guard coverage land together — a Ruby
    # repo must NOT be reported as an honest gap, because it isn't one.
    (tmp_path / "app.rb").write_text("puts 'hi'\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "ruby" not in prof.uncovered_stacks


def test_detect_ruby_not_double_reported_as_foreign_language(tmp_path: Path) -> None:
    # Coordination test: a Ruby repo well past the old foreign-language floor must not appear
    # in foreign_languages either — Ruby graduated out of "foreign" the moment detect() gained
    # real Ruby support.
    for i in range(10):
        (tmp_path / f"service{i}.rb").write_text("puts 'hi'\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "Ruby" not in prof.foreign_languages
    assert prof.foreign_languages == set()


def test_detect_ruby_dirs_collected(tmp_path: Path) -> None:
    # Mirrors python_dirs/go_dirs exactly: top-level dirs containing .rb, plus "." for root.
    (tmp_path / "app" / "models").mkdir(parents=True)
    (tmp_path / "app" / "models" / "user.rb").write_text("class User\nend\n", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "util.rb").write_text("module Util\nend\n", encoding="utf-8")
    (tmp_path / "root.rb").write_text("puts 1\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.ruby_dirs == sorted(["app", "lib", "."])


def test_detect_ruby_dirs_empty_for_non_ruby_repo(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.ruby_dirs == []


# --------------------------------------------------------------------------- #
# Per-file read cap (#180 review, Marconi): truncation must NOT be silent — a
# capped read could drop a dependency past the cap, which reads as a detect bug.
# --------------------------------------------------------------------------- #

def test_read_cap_discloses_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import agentsec.detect as d
    monkeypatch.setattr(d, "_MAX_READ_CHARS", 10)
    big = tmp_path / "huge.txt"
    big.write_text("x" * 100, encoding="utf-8")
    assert len(d._read(big)) == 10                       # used only the head
    err = capsys.readouterr().err
    assert "read-capped" in err and "huge.txt" in err    # disclosed, with the why


def test_read_under_cap_is_silent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import agentsec.detect as d
    small = tmp_path / "small.txt"
    small.write_text("hello", encoding="utf-8")
    assert d._read(small) == "hello"
    assert capsys.readouterr().err == ""                 # no note when not truncated


def test_detect_host_config_feature_sshd(tmp_path: Path) -> None:
    # A committed sshd_config turns on the host-config feature (gates the host-hardening guards).
    (tmp_path / "sshd_config").write_text("PermitRootLogin yes\n", encoding="utf-8")
    assert "host-config" in detect(tmp_path).features


def test_detect_host_config_feature_dropin(tmp_path: Path) -> None:
    # An sshd_config.d/*.conf drop-in also turns it on.
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "99-hardening.conf").write_text("X11Forwarding no\n", encoding="utf-8")
    assert "host-config" in detect(tmp_path).features


@pytest.mark.parametrize("rel", ["fail2ban/paths-overrides.local", "cloud-init/user-data"])
def test_detect_host_config_from_a_marker_parent_dir(tmp_path: Path, rel: str) -> None:
    # Any file directly inside a fail2ban/ or cloud-init/ dir is a host-config marker.
    (tmp_path / rel).parent.mkdir()
    (tmp_path / rel).write_text("x\n", encoding="utf-8")
    assert "host-config" in detect(tmp_path).features


@pytest.mark.parametrize("rel", ["fail2ban-notes/readme.txt", "docs/fail2ban", "cloud-init/sub/user-data"])
def test_detect_host_config_needs_the_marker_dir_as_the_direct_parent(tmp_path: Path, rel: str) -> None:
    # A near-miss dir name, a FILE named like the dir, or a file one level further down is not one.
    (tmp_path / rel).parent.mkdir(parents=True)
    (tmp_path / rel).write_text("x\n", encoding="utf-8")
    assert "host-config" not in detect(tmp_path).features


@pytest.mark.parametrize(("rel", "fires"), [  # `config.*` is not an MCP name by itself; the dir makes it one
    (".mcp/config.json", True), (".mcp/config.toml", True),
    (".mcp/readme.md", False),             # wrong suffix inside .mcp/
    ("mcpx/config.json", False),           # near-miss parent dir
    (".mcp/sub/config.json", False),       # .mcp/ is not the DIRECT parent
])
def test_detect_mcp_from_a_dot_mcp_dir(tmp_path: Path, rel: str, fires: bool) -> None:
    (tmp_path / rel).parent.mkdir(parents=True)
    (tmp_path / rel).write_text("{}\n", encoding="utf-8")
    assert ("mcp" in detect(tmp_path).features) is fires


_SDK = "@modelcontextprotocol/sdk"


@pytest.mark.parametrize(("files", "fires"), [
    # #981: a JS/TS MCP server's only MCP signal is the SDK as a package.json dependency KEY.
    ({"package.json": f'{{"dependencies": {{"{_SDK}": "1.13.1"}}}}'}, True),
    ({"package.json": f'{{"devDependencies": {{"{_SDK}": "^1.0.0"}}}}'}, True),
    ({"package.json": f'{{"peerDependencies": {{"{_SDK}": "^1.0.0"}}}}'}, True),
    ({"package.json": f'{{"dependencies": {{"{_SDK}"   :  "^1.0.0"}}}}'}, True),
    ({"package.json": '{"name": "mono", "private": true}',     # a workspace member declares it
      "packages/server/package.json": f'{{"dependencies": {{"{_SDK}": "^1.0.0"}}}}'}, True),
    # Any JSON key counts, not only a dependency section: an override pins an SDK the tree ships.
    ({"package.json": f'{{"overrides": {{"{_SDK}": "1.13.1"}}, "dependencies": {{"express": "4"}}}}'}, True),
    # FP-bait: the SDK as a string VALUE, a near-miss key, or only in a lockfile is not an MCP project.
    ({"package.json": f'{{"name": "demo", "keywords": ["{_SDK}"], "dependencies": {{"express": "4"}}}}'},
     False),
    ({"package.json": f'{{"name": "{_SDK}", "dependencies": {{"zod": "^3.23.8"}}}}'}, False),  # the SDK repo
    ({"package.json": f'{{"name": "demo", "description": "built on {_SDK}"}}'}, False),
    ({"package.json": f'{{"dependencies": {{"{_SDK}k": "1.0.0"}}}}'}, False),   # typosquat key
    ({"package.json": '{"name": "demo", "dependencies": {"fastmcp": "^1.0.0"}}',   # lockfiles feed no manifest
      "package-lock.json": f'{{"packages": {{"node_modules/fastmcp": {{"dependencies": {{"{_SDK}": "^1"}}}}}}}}'},
     False),
    # Regression pins for the pre-existing Python arms in the same expression.
    ({"app.py": "from mcp import ClientSession\n"}, True),
    ({"requirements.txt": "mcp>=1.0\n"}, True),
    ({"pyproject.toml": '[project]\nname = "demo"\n\n[tool.mcp]\nserver = "demo"\n'}, True),
])
def test_detect_mcp_from_a_dependency_or_import(tmp_path: Path, files: dict[str, str], fires: bool) -> None:
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    assert ("mcp" in detect(tmp_path).features) is fires


def test_detect_host_config_absent_by_default(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert "host-config" not in detect(tmp_path).features


def test_detect_host_config_from_apt_provisioning_script(tmp_path: Path) -> None:
    # A bare shell provisioning script that installs OS packages turns on host-config, even with
    # no sshd/fail2ban/unbound marker file (the §6d applies() gap Marconi flagged on #249).
    (tmp_path / "provision.sh").write_text(
        "#!/usr/bin/env bash\napt-get update && apt-get install -y nginx postgresql\n", encoding="utf-8"
    )
    assert "host-config" in detect(tmp_path).features


def test_detect_no_host_config_from_dockerfile_inline_run(tmp_path: Path) -> None:
    # An INLINE Dockerfile `RUN apt-get install` is not a *.sh, so it is not a host-config signal.
    # (A *.sh invoked from a Dockerfile IS matched by suffix — an accepted, pragma-suppressible
    # over-fire documented in detect's host-config comment; only auto-updates-absent can act on it.)
    (tmp_path / "Dockerfile").write_text("FROM debian\nRUN apt-get install -y gcc\n", encoding="utf-8")
    assert "host-config" not in detect(tmp_path).features


def test_detect_no_host_config_from_plain_script(tmp_path: Path) -> None:
    # A shell script with no package install is not a host-provisioning signal.
    (tmp_path / "run.sh").write_text("#!/usr/bin/env bash\necho hello\n", encoding="utf-8")
    assert "host-config" not in detect(tmp_path).features


def test_detect_reverse_proxy_feature_caddy(tmp_path: Path) -> None:
    (tmp_path / "Caddyfile").write_text("example.com {\n    reverse_proxy localhost:8001\n}\n", encoding="utf-8")
    assert "reverse-proxy" in detect(tmp_path).features


def test_detect_reverse_proxy_feature_nginx(tmp_path: Path) -> None:
    (tmp_path / "nginx.conf").write_text("http {\n    server { listen 80; }\n}\n", encoding="utf-8")
    assert "reverse-proxy" in detect(tmp_path).features


def test_detect_reverse_proxy_absent_by_default(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert "reverse-proxy" not in detect(tmp_path).features


def test_detect_reverse_proxy_caddyfile_lowercase(tmp_path: Path) -> None:
    # A lowercase `caddyfile` must gate the guard, matching its _is_caddy (review #252).
    (tmp_path / "caddyfile").write_text("example.com {\n    reverse_proxy localhost:8001\n}\n", encoding="utf-8")
    assert "reverse-proxy" in detect(tmp_path).features


def test_detect_reverse_proxy_nginx_conf_d(tmp_path: Path) -> None:
    # The Docker nginx `conf.d/*.conf` per-vhost layout must be detected (review #252).
    d = tmp_path / "conf.d"
    d.mkdir()
    (d / "default.conf").write_text("server { listen 80; }\n", encoding="utf-8")
    assert "reverse-proxy" in detect(tmp_path).features


def test_detect_electron_feature(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"devDependencies": {"electron": "^28.0.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert "electron" in prof.features


def test_detect_electron_absent_by_default(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.18.0"}}', encoding="utf-8")
    assert "electron" not in detect(tmp_path).features


def test_detect_redis_feature_from_py_dep(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("redis==5.0.1\n", encoding="utf-8")
    assert "redis" in detect(tmp_path).features


def test_detect_redis_feature_from_py_import(tmp_path: Path) -> None:
    (tmp_path / "cache.py").write_text("import redis\nr = redis.Redis()\n", encoding="utf-8")
    assert "redis" in detect(tmp_path).features


def test_detect_redis_feature_from_js_dep(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"ioredis": "^5.3.0"}}', encoding="utf-8")
    assert "redis" in detect(tmp_path).features


def test_detect_redis_absent_by_default(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.18.0"}}', encoding="utf-8")
    assert "redis" not in detect(tmp_path).features


def test_detect_redis_absent_on_bare_prose_mention(tmp_path: Path) -> None:
    # FP-bait: "redis" appearing in prose (not a real dependency declaration) must not count --
    # the anchored _declares_py_dep/_js_dep helpers, not the looser electron-style _names_dep.
    (tmp_path / "README.md").write_text("We considered redis for caching but chose in-memory.\n", encoding="utf-8")
    assert "redis" not in detect(tmp_path).features


def test_detect_ansible_feature_from_cfg(tmp_path: Path) -> None:
    (tmp_path / "ansible.cfg").write_text("[defaults]\ninventory = hosts\n", encoding="utf-8")
    assert "ansible" in detect(tmp_path).features


def test_detect_ansible_feature_from_playbook_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "site.yml").write_text(
        "- hosts: all\n  tasks:\n    - name: do a thing\n      debug: msg=hi\n", encoding="utf-8"
    )
    assert "ansible" in detect(tmp_path).features


def test_detect_ansible_feature_from_role_tasks_path(tmp_path: Path) -> None:
    d = tmp_path / "roles" / "myrole" / "tasks"
    d.mkdir(parents=True)
    (d / "main.yml").write_text("- name: task\n  debug: msg=hi\n", encoding="utf-8")
    assert "ansible" in detect(tmp_path).features


def test_detect_ansible_feature_from_playbook_shape_content(tmp_path: Path) -> None:
    # No conventional filename, but a top-level hosts: + tasks: play shape elsewhere in the repo.
    (tmp_path / "deploy" / "web.yml").parent.mkdir()
    (tmp_path / "deploy" / "web.yml").write_text(
        "- hosts: webservers\n  tasks:\n    - name: install nginx\n      apt: name=nginx\n", encoding="utf-8"
    )
    assert "ansible" in detect(tmp_path).features


def test_detect_ansible_absent_by_default(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert "ansible" not in detect(tmp_path).features


def test_detect_graphql_feature_from_strawberry_dep(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("strawberry-graphql==0.230.0\n", encoding="utf-8")
    assert "graphql" in detect(tmp_path).features


def test_detect_graphql_feature_from_ariadne_dep(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("ariadne==0.23.0\n", encoding="utf-8")
    assert "graphql" in detect(tmp_path).features


def test_detect_graphql_feature_from_graphene_import(tmp_path: Path) -> None:
    (tmp_path / "schema.py").write_text("import graphene\n\nclass Query(graphene.ObjectType):\n    pass\n", encoding="utf-8")
    assert "graphql" in detect(tmp_path).features


def test_detect_graphql_feature_from_graphql_core_import(tmp_path: Path) -> None:
    (tmp_path / "schema.py").write_text("from graphql import GraphQLSchema\n", encoding="utf-8")
    assert "graphql" in detect(tmp_path).features


def test_detect_graphql_absent_by_default(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert "graphql" not in detect(tmp_path).features


def test_detect_graphql_absent_on_bare_prose_mention(tmp_path: Path) -> None:
    # FP-bait: a prose mention (a comment, a description field) must not flip the feature —
    # mirrors the LLM-SDK import anchoring's own review #395 lesson.
    (tmp_path / "app.py").write_text(
        "# TODO: consider adding a graphql api with strawberry someday\nprint('hi')\n",
        encoding="utf-8",
    )
    assert "graphql" not in detect(tmp_path).features


def test_detect_graphql_absent_without_python(tmp_path: Path) -> None:
    # The feature is Python-scoped by design (the guard it gates resolves resolvers via Python
    # AST) — a JS-only repo naming a GraphQL package must not flip it.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"graphql": "^16.0.0"}}', encoding="utf-8"
    )
    (tmp_path / "index.js").write_text("console.log('hi');\n", encoding="utf-8")
    assert "graphql" not in detect(tmp_path).features


def test_detect_ansible_not_confused_with_docker_compose(tmp_path: Path) -> None:
    # docker-compose.yml has neither a top-level hosts: nor tasks: key — must not false-positive.
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports:\n      - '80:80'\n", encoding="utf-8"
    )
    assert "ansible" not in detect(tmp_path).features


def test_detect_ansible_not_confused_with_k8s_manifest(tmp_path: Path) -> None:
    # A Kubernetes manifest has kind:/spec:, not tasks: — must not false-positive.
    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: 1\n", encoding="utf-8"
    )
    assert "ansible" not in detect(tmp_path).features


def test_detect_ansible_not_confused_with_multidoc_configmap_and_argo(tmp_path: Path) -> None:
    # A K8s multi-document YAML: a `hosts:`-keyed ConfigMap AND an Argo Workflows DAG whose
    # `tasks:` is deeply nested. The two shape keys live in DIFFERENT docs and the Argo `tasks:`
    # is not at play-level indent, so this must NOT be detected as Ansible (regression: #408 #9).
    (tmp_path / "manifests.yaml").write_text(
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: inventory\n"
        "data:\n"
        "  hosts: |\n"
        "    web1.example.com\n"
        "    web2.example.com\n"
        "---\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "spec:\n"
        "  templates:\n"
        "    - name: build-dag\n"
        "      dag:\n"
        "        tasks:\n"
        "          - name: build\n"
        "            template: build\n",
        encoding="utf-8",
    )
    assert "ansible" not in detect(tmp_path).features


def test_detect_ansible_named_play_form_still_detected(tmp_path: Path) -> None:
    # The common `- name:` play form (hosts:/tasks: as indented play keys, not a bare `- hosts:`)
    # must still be detected after the same-document tightening.
    (tmp_path / "deploy.yaml").write_text(
        "---\n"
        "- name: Configure web servers\n"
        "  hosts: webservers\n"
        "  become: true\n"
        "  tasks:\n"
        "    - name: install nginx\n"
        "      ansible.builtin.apt:\n"
        "        name: nginx\n",
        encoding="utf-8",
    )
    assert "ansible" in detect(tmp_path).features
def test_detect_k8s_feature_from_deployment_manifest(tmp_path: Path) -> None:
    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n  name: app\n"
        "spec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: app:1.0\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_k8s_manifest is True
    assert "k8s" in prof.features


def test_detect_k8s_feature_absent_for_docker_compose(tmp_path: Path) -> None:
    # A docker-compose.yml's `services:`/`version:` shape must not false-positive as a K8s manifest.
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\nservices:\n  web:\n    image: nginx\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.has_k8s_manifest is False
    assert "k8s" not in prof.features


def test_detect_k8s_feature_absent_for_non_pod_resource(tmp_path: Path) -> None:
    # A Service/ConfigMap/Ingress etc. has no pod spec — not a workload manifest for these guards.
    (tmp_path / "service.yaml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\nspec:\n  selector:\n    app: x\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_k8s_manifest is False
    assert "k8s" not in prof.features


def test_detect_k8s_feature_from_rbac_binding_only(tmp_path: Path) -> None:
    # A repo shipping only an RBAC ClusterRoleBinding (e.g. a Helm chart's templates/rbac.yaml,
    # workloads defined elsewhere) must still turn on the "k8s" feature.
    (tmp_path / "rbac.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: app-binding\nsubjects:\n"
        "- kind: ServiceAccount\n  name: app-sa\n  namespace: default\n"
        "roleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_k8s_manifest is True
    assert "k8s" in prof.features


def test_detect_k8s_feature_from_rbac_role_only(tmp_path: Path) -> None:
    # A repo shipping only an RBAC ClusterRole (no binding, no pod-shaped workload) must still
    # turn on the "k8s" feature (Kubescape RBAC dangerous-verb batch).
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
        "metadata:\n  name: app-role\nrules:\n"
        '- apiGroups: [""]\n  resources: ["pods"]\n  verbs: ["get", "list"]\n',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_k8s_manifest is True
    assert "k8s" in prof.features



# --------------------------------------------------------------------------- #
# CloudFormation template detection (cfripper/cfn-nag research batch)
# --------------------------------------------------------------------------- #


def test_detect_cfn_feature_from_yaml_template(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: b\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_cfn_template is True
    assert "cloudformation" in prof.features


def test_detect_cfn_feature_from_json_template(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": '
        '{"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_cfn_template is True
    assert "cloudformation" in prof.features


def test_detect_cfn_feature_absent_for_ordinary_yaml(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("foo: bar\nbaz: qux\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.has_cfn_template is False
    assert "cloudformation" not in prof.features


def test_detect_cfn_feature_absent_for_k8s_manifest(tmp_path: Path) -> None:
    # A K8s manifest must not false-positive as CloudFormation -- distinct Resources:/Type: shape.
    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec: {}\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_cfn_template is False
    assert "cloudformation" not in prof.features


def test_detect_cfn_feature_not_confused_with_docker_compose(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\nservices:\n  web:\n    image: nginx\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.has_cfn_template is False
    assert "cloudformation" not in prof.features



# --------------------------------------------------------------------------- #
# ARM template detection (azure-template-analyzer research batch)
# --------------------------------------------------------------------------- #


def test_detect_arm_feature_from_schema_template(tmp_path: Path) -> None:
    (tmp_path / "azuredeploy.json").write_text(
        '{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", '
        '"contentVersion": "1.0.0.0", "resources": '
        '[{"type": "Microsoft.Storage/storageAccounts", "name": "s", "properties": {}}]}',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_arm_template is True
    assert "arm" in prof.features


def test_detect_arm_feature_from_resources_shape_without_schema(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Sql/servers", "name": "s", "properties": {}}]}',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_arm_template is True
    assert "arm" in prof.features


def test_detect_arm_feature_absent_for_ordinary_json(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text('{"foo": "bar"}', encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.has_arm_template is False
    assert "arm" not in prof.features


def test_detect_arm_feature_absent_for_cfn_json_template(tmp_path: Path) -> None:
    # A CFN JSON template must not false-positive as ARM -- distinct Resources/type shape
    # (CFN's "Type": "AWS::..." vs ARM's "type": "Microsoft.../...").
    (tmp_path / "template.json").write_text(
        '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": '
        '{"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.has_arm_template is False
    assert "arm" not in prof.features


def test_detect_arm_feature_not_confused_with_npm_package_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name": "app", "version": "1.0.0", "dependencies": {}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.has_arm_template is False
    assert "arm" not in prof.features
# Bicep detection (azure-bicep-linter research batch)
# --------------------------------------------------------------------------- #


def test_detect_bicep_feature_from_bicep_file(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param storageAccountName string\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert "bicep" in prof.features


def test_detect_bicep_feature_absent_without_bicep_file(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text('{"foo": "bar"}', encoding="utf-8")
    prof = detect(tmp_path)
    assert "bicep" not in prof.features


def test_detect_bicep_feature_from_bicepparam_file_only(tmp_path: Path) -> None:
    (tmp_path / "main.bicepparam").write_text(
        "using 'main.bicep'\n\nparam dbPassword = 'hardcoded'\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert "bicep" in prof.features



# --- #481 review: Supabase project shapes detection missed -------------------------------------

@pytest.mark.parametrize(
    ("label", "files"),
    [
        # `@supabase/ssr` is the CURRENT recommended Next.js package; the others are real
        # client surfaces. Only `@supabase/supabase-js` was recognized.
        ("ssr", {"package.json": '{"dependencies": {"@supabase/ssr": "^0.5.0"}}'}),
        ("auth-helpers", {"package.json": '{"dependencies": {"@supabase/auth-helpers-nextjs": "^0.10.0"}}'}),
        ("postgrest-js", {"package.json": '{"dependencies": {"@supabase/postgrest-js": "^1.15.0"}}'}),
        ("auth-ui-react", {"package.json": '{"dependencies": {"@supabase/auth-ui-react": "^0.4.0"}}'}),
        # Framework-prefixed env vars — how a frontend actually spells it.
        ("next-public-env", {".env.example": "NEXT_PUBLIC_SUPABASE_URL=https://abc.example\n"}),
        ("vite-env", {".env.example": "VITE_SUPABASE_ANON_KEY=ey.j.k\n"}),
        ("react-app-env", {".env.example": "REACT_APP_SUPABASE_URL=https://abc.example\n"}),
        ("expo-env", {".env.example": "EXPO_PUBLIC_SUPABASE_URL=https://abc.example\n"}),
        # The canonical `supabase init` CLI layout — no client dependency exists yet.
        ("cli-layout", {"supabase/config.toml": "[api]\nenabled = true\n",
                        "supabase/migrations/0001_init.sql": "create table t (id int);\n"}),
        # A single-line TOML dep list has no line-start anchor for the entry.
        ("single-line-deps", {"pyproject.toml": '[project]\ndependencies = ["fastapi", "supabase"]\n'}),
        # A submodule import.
        ("submodule-import", {"pyproject.toml": "[project]\nname = 'x'\n",
                              "app.py": "from supabase.client import create_client\n"}),
        # The connection-pooler host lives on `.supabase.com`, which the `.co`-only check excluded.
        ("pooler-host", {".env": "DATABASE_URL=postgres://u:p@aws-0-us-east-1.pooler.supabase.com:5432/postgres\n",
                         ".env.example": "DATABASE_URL=postgres://u:p@aws-0-us-east-1.pooler.supabase.com:5432/postgres\n"}),
    ],
)
def test_detect_supabase_project_shapes(tmp_path: Path, label: str, files: dict[str, str]) -> None:
    for rel_path, content in files.items():
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    assert detect(tmp_path).db == "supabase", label


def test_detect_supabase_keywords_tag_is_still_not_supabase(tmp_path: Path) -> None:
    # FP-bait for the widening: a package NAMED in `keywords` is not a dependency. This is the
    # declared-vs-mentioned distinction `_js_dep` exists to keep, and the single-line dep-list
    # clause must not reopen it.
    (tmp_path / "package.json").write_text(
        '{"keywords": ["@supabase/ssr", "supabase"], "dependencies": {"pg": "^8.11.0"}}',
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.db != "supabase"
    assert "supabase" not in prof.features


def test_detect_supabase_trailing_comment_does_not_count(tmp_path: Path) -> None:
    # #481 second-pass review: the comment filter dropped only WHOLE-LINE comments, so a trailing
    # one survived and the host clause matched — reopening the exact 8-FP class this PR closes.
    (tmp_path / "package.json").write_text('{"dependencies": {"pg": "^8.11.0"}}', encoding="utf-8")
    (tmp_path / ".env.example").write_text(
        "DATABASE_URL=postgres://u:p@host:5432/db  # or use Supabase: https://xyz.supabase.co\n"
        "OTHER_URL=postgres://h/db   # aws-0.pooler.supabase.com also works\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.db != "supabase"
    assert "supabase" not in prof.features


def test_detect_supabase_commented_out_dep_list_does_not_count(tmp_path: Path) -> None:
    # The single-line dep-list clause spans lines (`re.S`) with no line-start anchor, so it read a
    # commented-out example as a real dependency (#481 second-pass review).
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\n# dependencies = ["fastapi", "supabase"]\ndependencies = ["fastapi"]\n',
        encoding="utf-8",
    )
    assert detect(tmp_path).db != "supabase"


def test_detect_supabase_hash_inside_a_value_still_counts(tmp_path: Path) -> None:
    # The other direction: a `#` glued to a token (a URL fragment, a password) is not a comment, so
    # clipping must not truncate a real configured host.
    (tmp_path / ".env.example").write_text(
        "SUPABASE_URL=https://abcdef.supabase.co/#/ref\n", encoding="utf-8"
    )
    assert detect(tmp_path).db == "supabase"


def test_detect_supabase_migrations_only_repo_is_supabase(tmp_path: Path) -> None:
    # A database-only repo: migrations tracked in git, the app in a different repo, and
    # `supabase/config.toml` gitignored because it carries local ports and project refs. Every
    # manifest/import/host clause misses it and the CLI-layout clause used to require
    # `config.toml`, so it detected as plain `postgres` and every supabase-gated guard went N/A on
    # a real Supabase project (#481 review round 2).
    (tmp_path / "supabase" / "migrations").mkdir(parents=True)
    (tmp_path / "supabase" / "migrations" / "0001_init.sql").write_text(
        "CREATE TABLE public.notes (id int);\n", encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text("fastapi\npsycopg2\n", encoding="utf-8")
    assert detect(tmp_path).db == "supabase"


@pytest.mark.parametrize(
    ("label", "path"),
    [
        ("monorepo app dir", "apps/backend/supabase/migrations/0001.sql"),
        ("monorepo package dir", "packages/db/supabase/migrations/0001.sql"),
    ],
)
def test_detect_supabase_migrations_nested_in_a_monorepo_is_supabase(
    tmp_path: Path, label: str, path: str
) -> None:
    # The still-fires direction for the ownership scoping below. A supabase/ dir under an ordinary
    # workspace directory is this repo's own, and must keep detecting — the scoping exists to
    # exclude vendored/sample copies, not nesting per se.
    p = tmp_path / path
    p.parent.mkdir(parents=True)
    p.write_text("CREATE TABLE public.notes (id int);\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("fastapi\npsycopg2\n", encoding="utf-8")
    assert detect(tmp_path).db == "supabase"


@pytest.mark.parametrize(
    ("label", "path"),
    [
        ("hand-vendored tree", "third_party/some-lib/supabase/migrations/0001.sql"),
        ("vendor/ tree", "vendor/x/supabase/config.toml"),
        ("a sample project", "examples/demo/supabase/migrations/0001.sql"),
        ("a test fixture", "tests/fixtures/supabase/migrations/0001.sql"),
        ("go testdata convention", "pkg/testdata/supabase/migrations/0001.sql"),
        ("js __fixtures__ convention", "src/__fixtures__/supabase/migrations/0001.sql"),
        ("thirdparty, no separator", "THIRDPARTY/lib/supabase/migrations/0001.sql"),
        # The layout arm keeps the full vendored set; only the #566 blobs drop these two names.
        ("external/ tree", "external/proj/supabase/migrations/0001.sql"),
        ("contrib/ tree", "contrib/x/supabase/config.toml"),
    ],
)
def test_detect_a_vendored_supabase_project_is_not_this_repos_stack(
    tmp_path: Path, label: str, path: str
) -> None:
    # Regression (#481 review round 3, HIGH): the migrations arm keyed on the path shape alone, so
    # a vendored or sample copy of SOMEONE ELSE'S Supabase project flipped this repo to
    # db=supabase — and the repo's own unprotected `public` tables then produced a real HIGH
    # public-table-rls finding. The FP-burst class this PR exists to close, reopened through a
    # second vector. `node_modules` was already safe via walk.DEFAULT_EXCLUDE_DIRS; these trees
    # are not excluded anywhere.
    p = tmp_path / path
    p.parent.mkdir(parents=True)
    p.write_text("CREATE TABLE public.notes (id int);\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("fastapi\npsycopg2\n", encoding="utf-8")
    assert detect(tmp_path).db != "supabase"


def test_detect_supabase_ownership_ignores_the_checkout_path(tmp_path: Path) -> None:
    # The ownership test must read the repo-RELATIVE path. Judging absolute segments would make
    # detection depend on where the repo happens to live: a clone under `~/examples/` or a CI
    # workspace under `/tmp/test-123/` would stop being a Supabase project. Same class as the
    # `.env.example`-comment FP — a signal read from the wrong scope.
    root = tmp_path / "examples" / "my-app"
    (root / "supabase" / "migrations").mkdir(parents=True)
    (root / "supabase" / "migrations" / "0001.sql").write_text(
        "CREATE TABLE public.notes (id int);\n", encoding="utf-8"
    )
    (root / "requirements.txt").write_text("fastapi\npsycopg2\n", encoding="utf-8")
    assert detect(root).db == "supabase"


def test_detect_a_directory_merely_named_supabase_is_not_supabase(tmp_path: Path) -> None:
    # FP-bait for the arm above. The path shape AND the `.sql` suffix are both required, so a docs
    # folder or a vendored example that happens to sit under `supabase/` does not flip the stack.
    # Widening the CLI-layout clause is what makes this arm necessary: it is the direction traded
    # against, and without it "any file under supabase/" would have been the obvious shortcut.
    (tmp_path / "docs" / "supabase").mkdir(parents=True)
    (tmp_path / "docs" / "supabase" / "notes.md").write_text("we evaluated it once\n", encoding="utf-8")
    (tmp_path / "supabase" / "migrations").mkdir(parents=True)
    (tmp_path / "supabase" / "migrations" / "README.md").write_text("how to run\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("fastapi\npsycopg2\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.db != "supabase"


def test_detect_unconfirmed_supabase_is_disclosed_not_silently_dropped(tmp_path: Path) -> None:
    # The narrowing is silent in the worst direction: a repo whose only Supabase signal is an
    # unanchored mention correctly stops matching, but then every supabase-gated guard reports
    # "Skipped (N/A for this stack)", which reads as "does not use Supabase" rather than "could
    # not confirm". Disclosure, not detection — so `db` and `features` must NOT move (that is what
    # keeps the 8 FPs closed) while the profile still records that something was passed over.
    (tmp_path / ".env.example").write_text(
        "# point DATABASE_URL at Supabase, Neon, etc.\n"
        "DATABASE_URL=postgresql://u:p@localhost/db\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("fastapi\npsycopg2\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.db != "supabase"
    assert "supabase" not in prof.features
    assert "supabase" in prof.unconfirmed_stacks
    assert "unconfirmed=['supabase']" in prof.summary()


def test_detect_confirmed_supabase_is_not_also_disclosed_as_unconfirmed(tmp_path: Path) -> None:
    # FP-bait for the disclosure: a repo with REAL Supabase usage must not also carry the
    # "mentioned but not confirmed" notice. A disclosure that fires on confirmed stacks too is
    # noise, and noise is how a real one stops being read.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@supabase/supabase-js": "^2.39.0"}}', encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.db == "supabase"
    assert prof.unconfirmed_stacks == set()


def test_detect_llm_from_python_manifest_when_import_scan_is_capped(tmp_path: Path) -> None:
    # Regression (#465 review): the Python LLM check was import-only, and the import scan covers
    # the first `_MAX_PY_SCAN` .py files in sorted walk order — so `alembic/versions/*` wins the
    # alphabet and the `app/` module doing `from openai import OpenAI` is never read. The same
    # repo detected `llm` with 10 alembic files and did NOT with 250, dropping ~40 guards and
    # every checklist item gated on `llm`. `langchain`/`pydantic-ai` already matched on the
    # manifest, so the SDKs were the odd ones out.
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "llm.py").write_text("from openai import OpenAI\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("openai==1.2.0\nfastapi\n", encoding="utf-8")
    versions = tmp_path / "alembic" / "versions"
    versions.mkdir(parents=True)
    for i in range(250):
        (versions / f"{i:04d}_m.py").write_text("def upgrade(): pass\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "llm" in prof.features
    assert prof.llm_framework == "python-llm-sdk"


def test_detect_llm_manifest_ignores_a_keywords_array(tmp_path: Path) -> None:
    # FP-bait: a `keywords` array is prose, not a dependency list. `_names_dep` anchors to a
    # token shape that `["openai"]` satisfies, which is the exact false positive review #395 hit
    # on the import side.
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nkeywords = ["openai"]\ndependencies = ["fastapi"]\n', encoding="utf-8"
    )
    assert "llm" not in detect(tmp_path).features


# --- the manifest LLM-SDK arm: declaration vs mention -----------------------------
#
# `_declares_py_dep` narrows the manifest arm from "the name appears anywhere in the blob" to
# "the name is DECLARED as a dependency". Narrowing trades a false positive for the risk of a
# FALSE NEGATIVE, and a false negative here silently N/A-suppresses every `llm`-gated guard —
# so the real-dependency shapes are swept exhaustively first, then the non-declaration ones.

_REAL_PY_LLM_MANIFESTS = [
    # requirements.txt: every PEP 508 spelling that reaches production
    ("requirements.txt", "fastapi\nopenai\n"),                       # bare name
    ("requirements.txt", "fastapi\nopenai==1.2.3\n"),                # pinned
    ("requirements.txt", "openai>=1.0\n"),                           # lower bound
    ("requirements.txt", "openai >= 1.0\n"),                         # spaced operator
    ("requirements.txt", "openai~=1.2\n"),
    ("requirements.txt", "openai!=1.0\n"),
    ("requirements.txt", "openai[datalib]==1.2.3\n"),                # extras
    ("requirements.txt", "openai [datalib] == 1.2.3\n"),             # extras, spaced
    ("requirements.txt", 'openai ; python_version >= "3.9"\n'),      # environment marker
    ("requirements.txt", "openai @ https://example.invalid/o.whl\n"),  # direct URL
    ("requirements.txt", "fastapi\n  openai==1.2.3\n"),              # indented continuation-style
    ("requirements.txt", "openai==1.2.3  # the LLM client\n"),       # trailing comment on the dep
    ("requirements.txt", "# pinned deliberately\nopenai==1.2.3\n"),  # comment on a sibling line
    ("requirements.txt", "fastapi\r\nopenai==1.2.3\r\n"),            # CRLF (Windows checkout)
    # every other distribution in _PY_LLM_DISTS
    ("requirements.txt", "anthropic==0.30.0\n"),
    ("requirements.txt", "litellm\n"),
    ("requirements.txt", "cohere>=5\n"),
    ("requirements.txt", "groq\n"),
    ("requirements.txt", "together==1.2\n"),
    ("requirements.txt", "mistralai\n"),
    ("requirements.txt", "ollama\n"),
    ("requirements.txt", "instructor\n"),
    ("requirements.txt", "openai-agents==0.0.9\n"),
    ("requirements.txt", "llama-index==0.10.0\n"),
    ("requirements.txt", "llama-index-core==0.10.0\n"),
    ("requirements.txt", "dspy\n"),
    ("requirements.txt", "dspy-ai==2.4\n"),
    ("requirements.txt", "google-generativeai==0.5\n"),
    ("requirements.txt", "google-genai\n"),
    ("requirements.txt", "vertexai\n"),
    ("requirements.txt", "google-cloud-aiplatform==1.50\n"),
    ("requirements.txt", "transformers==4.40\n"),
    # pyproject.toml: PEP 621 arrays (single- and multi-line) + the poetry table
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["fastapi", "openai>=1.0"]\n'),
    ("pyproject.toml", '[project]\ndependencies = ["openai"]\n'),
    ("pyproject.toml", '[project]\ndependencies = [\n  "fastapi",\n  "openai>=1.0",\n]\n'),
    ("pyproject.toml", '[project]\ndependencies = [\n  "fastapi",  # web\n  "openai>=1.0",  # llm\n]\n'),
    ("pyproject.toml", '[project]\ndependencies = ["openai[datalib]>=1.0"]\n'),
    ("pyproject.toml", '[project.optional-dependencies]\nai = ["openai>=1.0"]\n'),
    ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.11"\nopenai = "^1.2.3"\n'),
    ("pyproject.toml", '[tool.poetry.dependencies]\nanthropic = "^0.30"\n'),
    ("pyproject.toml", "[project]\ndependencies = ['openai>=1.0']\n"),
    ("pyproject.toml", '[project]\ndependencies = ["openai>=1.0 ; python_version >= \'3.9\'"]\n'),
    # PEP 735 dependency groups + the poetry per-group table
    ("pyproject.toml", '[dependency-groups]\ndev = ["pytest", "openai>=1.0"]\n'),
    ("pyproject.toml", '[tool.poetry.group.dev.dependencies]\nopenai = "^1.2.3"\n'),
    # --- the comment stripper must be QUOTE-AWARE (#465 re-review MAJOR) ------------------
    # Each of these declares a real dependency AFTER a `#`/`//` that sits INSIDE an earlier
    # quoted value on the SAME physical line. `tomllib` parses both array entries, and an
    # installer installs both — so a stripper that cuts from the first whitespace-preceded
    # `#` to end of line silently deletes a real dependency and N/A-suppresses 41 guards.
    ("pyproject.toml", '[project]\ndependencies = ["requests # legacy note", "openai>=1.0"]\n'),
    ("pyproject.toml", "[project]\ndependencies = ['requests # legacy note', 'openai>=1.0']\n"),
    ("pyproject.toml", '[project]\ndependencies = [\n  "a # b", "openai>=1.0",\n]\n'),
    ("pyproject.toml", '[project]\ndependencies = ["a # b", "openai>=1.0"]  # the llm client\n'),
    ("pyproject.toml", '[project]\ndependencies = ["a # b", "openai[datalib] >= 1.0"]\n'),
    ("pyproject.toml", '[project]\ndependencies = ["a # b", "openai @ https://example.invalid/o.whl"]\n'),
    ("pyproject.toml", '[project]\ndependencies = ["a \\" # b", "openai>=1.0"]\n'),   # escaped quote
    ("pyproject.toml", '[project]\ndependencies = ["a // b", "openai>=1.0"]\n'),      # `//` in a value
    ("pyproject.toml", '[project]\ndependencies = ["httpx ; sys_platform == \'win32 # x\'", "openai"]\n'),
    ("pyproject.toml", '[project]\r\ndependencies = ["a # b", "openai>=1.0"]\r\n'),   # CRLF
    ("pyproject.toml", '[dependency-groups]\ndev = ["x # y", "openai"]\n'),
    ("pyproject.toml", '[project.optional-dependencies]\nai = ["x # y", "anthropic>=0.30"]\n'),
    # An apostrophe in prose is not a string delimiter: if it were treated as one, the rest of
    # the line would look "in string" and a `#` in a URL-ish tail could go unstripped — but more
    # importantly the SAME line's real value must survive.
    ("pyproject.toml", '[project]\nx = "don\'t"\ndependencies = ["openai>=1.0"]\n'),
    # A PEP 508 direct-URL fragment `#` is glued to the token, so it is never a comment.
    ("requirements.txt", "openai @ https://example.invalid/o.whl#sha256=deadbeef\n"),
]


@pytest.mark.parametrize("manifest,body", _REAL_PY_LLM_MANIFESTS)
def test_detect_llm_manifest_still_matches_every_real_dependency_shape(
    tmp_path: Path, manifest: str, body: str
) -> None:
    # The false-NEGATIVE sweep. The .py file carries no LLM import, so the manifest arm is the
    # only signal — if a real declaration stops matching here, ~40 llm-gated guards go silently
    # N/A on an app that really does ship an LLM SDK.
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n", encoding="utf-8")
    (tmp_path / manifest).write_text(body, encoding="utf-8", newline="")
    prof = detect(tmp_path)
    assert prof.llm_framework == "python-llm-sdk", (manifest, body)
    assert "llm" in prof.features, (manifest, body)


_NON_DECLARATION_MENTIONS = [
    # A `#` comment naming the SDK is a note about history, not a dependency (#465 review HIGH).
    ("requirements.txt",
     "# migrated off openai in 2024, keeping this note for history\n"
     "fastapi==0.110.0\nsqlalchemy==2.0.0\n"),
    ("requirements.txt", "fastapi==0.110.0  # replaced our openai calls with a local model\n"),
    ("pyproject.toml",
     '[project]\ndependencies = [\n  "fastapi",\n  # "openai>=1.0",  # dropped in 2024\n]\n'),
    # A prose field is prose: this one explicitly DISCLAIMS the SDK.
    ("pyproject.toml",
     '[project]\nname = "crud-app"\n'
     'description = "A FastAPI CRUD app, not an openai wrapper"\n'
     'dependencies = ["fastapi", "sqlalchemy"]\n'),
    ("pyproject.toml",
     '[project]\ndescription = "Ships without anthropic or any model provider"\n'
     'dependencies = ["fastapi"]\n'),
    ("pyproject.toml", '[project]\nname = "openai-cost-dashboard-ui"\ndependencies = ["fastapi"]\n'),
    ("pyproject.toml",
     '[project]\ndescription = """\nopenai is not used here at all.\n"""\n'
     'dependencies = ["fastapi"]\n'),
    # `together` is a real distribution name AND an everyday English word.
    ("pyproject.toml",
     '[project]\ndescription = "Stitches your services together"\ndependencies = ["fastapi"]\n'),
    # Already covered above, kept in the sweep so the whole class stays regression-tested.
    ("pyproject.toml", '[project]\nkeywords = ["openai", "llm"]\ndependencies = ["fastapi"]\n'),
    ("pyproject.toml",
     '[tool.myapp]\nembedding = "openai/text-embedding-3-small"\n'
     '[project]\ndependencies = ["fastapi"]\n'),
    # --- the other direction of the quote-aware stripper (#465 re-review MAJOR) -----------
    # Making the stripper quote-aware must not make it stop stripping: a comment may itself
    # contain quotes, an apostrophe, or a whole commented-out array entry.
    ("requirements.txt", 'fastapi\n# we don\'t use "openai>=1.0" anymore\n'),
    ("requirements.txt", 'fastapi  # don\'t add "openai>=1.0\n'),          # unterminated quote
    ("pyproject.toml",
     '[project]\ndependencies = [\n  "fastapi",\n  # it\'s gone: "openai>=1.0",\n]\n'),
    ("pyproject.toml",
     '[project]\nname = "crud"  # "openai>=1.0" was here\ndependencies = ["fastapi"]\n'),
    # An apostrophe inside a real double-quoted value must not "open" a string and swallow the
    # line's genuine trailing comment.
    ("pyproject.toml",
     '[project]\ndescription = "it\'s fine"  # "openai>=1.0"\ndependencies = ["fastapi"]\n'),
    ("pyproject.toml",
     '[project]\nauthors = ["Dean O\'Neil"]  # "openai>=1.0"\ndependencies = ["fastapi"]\n'),
    ("pyproject.toml", '[project]\nname = "x"  # she said \\"openai>=1.0\\"\ndependencies = ["fastapi"]\n'),
    ("pyproject.toml", '[project]\nkeywords = ["a # b", "openai"]\ndependencies = ["fastapi"]\n'),
    # `.env.example` is folded into the same blob and is the least TOML-ish of the manifests.
    (".env.example", 'NOTE=it\'s fine  # "openai>=1.0"\n'),
]


_STRIPPER_CASES = [
    # (line, expected) — the INVARIANT: a `#`/`//` begins a comment only when it is OUTSIDE a
    # string literal AND not glued to the token on its left.
    # -- outside a string: it IS a comment
    ("# whole line", ""),
    ("   # indented whole line", "   "),
    ("openai==1.0  # the llm client", "openai==1.0  "),
    ("x = 1 // 2", "x = 1 "),
    ("#", ""),
    ("//", ""),
    # -- glued to the token on its left: NOT a comment
    ("pass#word", "pass#word"),
    ("openai @ https://h/o.whl#sha256=x", "openai @ https://h/o.whl#sha256=x"),
    ('"url": "http://h/p"', '"url": "http://h/p"'),
    # -- inside a string literal: NOT a comment (the #465 re-review MAJOR)
    ('deps = ["requests # note", "openai>=1.0"]', 'deps = ["requests # note", "openai>=1.0"]'),
    ("deps = ['requests # note', 'openai>=1.0']", "deps = ['requests # note', 'openai>=1.0']"),
    ('"x": "see // notes"', '"x": "see // notes"'),
    ('deps = ["a \\" # b", "openai"]', 'deps = ["a \\" # b", "openai"]'),   # escaped quote
    ("x = \"it's # fine\"", "x = \"it's # fine\""),                        # other quote inside
    # -- a real comment AFTER a string that itself contained a `#`
    ('x = "a # b"  # real', 'x = "a # b"  '),
    ('x = """a # b"""  # real', 'x = """a # b"""  '),
    # -- an apostrophe glued to a word is prose, not a delimiter, so the comment still strips
    ("NOTE=it's fine  # openai", "NOTE=it's fine  "),
    ('authors = ["Dean O\'Neil"]  # openai', 'authors = ["Dean O\'Neil"]  '),
    # -- degenerate input must not raise or hang
    ("", ""),
    ('x = "unterminated', 'x = "unterminated'),
    ("x = \"trailing backslash \\", "x = \"trailing backslash \\"),
]


@pytest.mark.parametrize("line,expected", _STRIPPER_CASES)
def test_strip_trailing_comment_is_quote_aware(line: str, expected: str) -> None:
    # The first cut of this helper stripped from the first whitespace-preceded `#` to end of
    # PHYSICAL line with no notion of quote state, so a `#` inside an earlier quoted value ate
    # every real dependency after it on that line — a silent false negative that N/A-suppresses
    # the whole `llm`-gated guard family. Both halves of the invariant are pinned here.
    assert _strip_trailing_comment(line) == expected


@pytest.mark.parametrize("manifest,body", _NON_DECLARATION_MENTIONS)
def test_detect_llm_manifest_ignores_a_mention_that_is_not_a_declaration(
    tmp_path: Path, manifest: str, body: str
) -> None:
    # FP-bait (#465 review HIGH): the manifest arm reused `_names_dep`, which matches ANYWHERE in
    # the concatenated manifest blob and is neither comment- nor prose-aware — unlike the sibling
    # `_PY_LLM_IMPORT`, anchored to `from`/`import`. A `#` comment or a `description` naming an SDK
    # switched on the `llm` feature, and with it every `llm`-gated guard, on an app with no LLM
    # dependency at all.
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n", encoding="utf-8")
    (tmp_path / manifest).write_text(body, encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.llm_framework is None, (manifest, body)
    assert "llm" not in prof.features, (manifest, body)


def test_detect_llm_manifest_ignores_an_env_var_name(tmp_path: Path) -> None:
    # `.env.example` is one of the `_MANIFESTS` folded into the blob: an `OPENAI_API_KEY=` line
    # names a provider without declaring a dependency on its SDK.
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text(
        "OPENAI_API_KEY=sk-xxx\nANTHROPIC_API_KEY=\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.llm_framework is None
    assert "llm" not in prof.features


def test_detect_bun_lock_text_lockfile_is_a_package_manager(tmp_path: Path) -> None:
    # Regression (#464 review): detect knew only the pre-1.2 binary `bun.lockb`, while
    # `js_supply_chain` already knew both names. A Bun 1.2+ backend therefore detected NO package
    # manager, so that guard's `applies()` returned False and the whole guard was skipped —
    # including its HIGH lifecycle-scripts rule.
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4"}}', encoding="utf-8")
    (tmp_path / "bun.lock").write_text("# lockfile\n", encoding="utf-8")
    assert "bun" in detect(tmp_path).package_managers


# --------------------------------------------------------------------------- #
# Artifact-layer Go evidence (foreign_artifacts / Dean's review)
#
# design-stack-coverage-disclosure.md's "residual, not fixed by this phase" gap: a repo can run
# Go entirely as a prebuilt binary in a Docker base image with zero .go files anywhere in the
# tree, so neither foreign_languages nor uncovered_stacks can ever see it.
# --------------------------------------------------------------------------- #


def test_foreign_artifacts_fires_on_known_go_base_image(tmp_path: Path) -> None:
    # The Caddy example from Dean's review itself: a Dockerfile whose only FROM is a known
    # Go-shipping base image, no .go source anywhere in the repo.
    (tmp_path / "Dockerfile").write_text("FROM caddy:2\nCOPY site /srv\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert len(prof.foreign_artifacts) == 1
    artifact = next(iter(prof.foreign_artifacts))
    assert "Caddy" in artifact
    assert "caddy:2" in artifact
    assert "go" not in prof.languages
    assert "go" not in prof.uncovered_stacks
    assert "Go" not in prof.foreign_languages


def test_foreign_artifacts_stays_silent_on_an_ordinary_base_image(tmp_path: Path) -> None:
    # FP-bait / narrowing-direction check: an everyday base image must not fire.
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nCOPY . /app\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_artifacts == set()


def test_foreign_artifacts_multi_stage_only_matching_stage_fires(tmp_path: Path) -> None:
    # Per-stage independence: a multi-stage build where only ONE of several FROM lines names a
    # known Go base image must disclose exactly that one, not the builder stage too.
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "WORKDIR /src\n"
        "RUN go build -o /out/app .\n"
        "FROM caddy:2\n"
        "COPY --from=builder /out/app /usr/bin/app\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert len(prof.foreign_artifacts) == 1
    assert "Caddy" in next(iter(prof.foreign_artifacts))


def test_foreign_artifacts_multi_stage_none_matching_stays_silent(tmp_path: Path) -> None:
    # The other direction of the same multi-stage scenario: neither stage names a known
    # Go-shipping base image, so nothing fires.
    (tmp_path / "Dockerfile").write_text(
        "FROM node:20 AS builder\n"
        "RUN npm run build\n"
        "FROM nginx:1.27\n"
        "COPY --from=builder /dist /usr/share/nginx/html\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.foreign_artifacts == set()


def test_foreign_artifacts_stage_reference_not_mistaken_for_an_image(tmp_path: Path) -> None:
    # A later `FROM <stage-name>` (no `AS`) references an earlier build stage, not a pullable
    # registry image — must never be matched against the base-image table even if a stage happens
    # to be named after one (adversarial-adjacent: exercises the stage-name exclusion itself).
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim AS vault\n"
        "RUN pip install -r requirements.txt\n"
        "FROM vault\n"
        "COPY --from=vault /app /app\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.foreign_artifacts == set()


def test_foreign_artifacts_substring_lookalike_does_not_false_positive(tmp_path: Path) -> None:
    # Adversarial self-test: a base image whose BARE name (the part actually compared —
    # last path segment, tag stripped) merely CONTAINS a known Go image name as a substring must
    # not fire — matching is an exact dict-key lookup against the whole bare name, never a
    # substring search. "myvault-warden" contains "vault" but is not HashiCorp Vault.
    (tmp_path / "Dockerfile").write_text("FROM myvault-warden:latest\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_artifacts == set()

    # Same protection when the lookalike is namespaced too — "vault" only appears inside the
    # ORG/namespace segment, which is stripped before comparison, and the real final segment
    # ("unrelated-tool") doesn't match anything either.
    (tmp_path / "Dockerfile").write_text("FROM vault-org/unrelated-tool:1.0\n", encoding="utf-8")
    prof2 = detect(tmp_path)
    assert prof2.foreign_artifacts == set()


def test_foreign_artifacts_tag_stripped_before_matching(tmp_path: Path) -> None:
    # A `:latest` tag (or any tag) must be stripped before the bare-name lookup, not compared as
    # part of the image reference.
    (tmp_path / "Dockerfile").write_text("FROM traefik:latest\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert len(prof.foreign_artifacts) == 1
    assert "Traefik" in next(iter(prof.foreign_artifacts))


def test_foreign_artifacts_namespaced_image_matches_on_bare_name(tmp_path: Path) -> None:
    # A registry namespace (`hashicorp/`) must not block the match — only the final path segment
    # is compared, mirroring docker_latest_base_tag.py's own tag-extraction precedent.
    (tmp_path / "Dockerfile").write_text("FROM hashicorp/vault:1.15\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert len(prof.foreign_artifacts) == 1
    assert "HashiCorp Vault" in next(iter(prof.foreign_artifacts))


def test_foreign_artifacts_registry_host_with_port_not_mistaken_for_tag(tmp_path: Path) -> None:
    # A registry host:port (`registry:5000/caddy`) must not have its port digits mistaken for an
    # image tag — only the LAST path segment's colon is a tag separator.
    (tmp_path / "Dockerfile").write_text("FROM registry:5000/caddy:2\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert len(prof.foreign_artifacts) == 1
    assert "Caddy" in next(iter(prof.foreign_artifacts))


def test_foreign_artifacts_deduplicates_repeated_images(tmp_path: Path) -> None:
    # Two Dockerfiles pulling the same base image must not produce two disclosure entries — the
    # field is a set, and the evidence string is stable per (lang, image_ref) pair.
    (tmp_path / "Dockerfile").write_text("FROM caddy:2\n", encoding="utf-8")
    (tmp_path / "Dockerfile.dev").write_text("FROM caddy:2\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert len(prof.foreign_artifacts) == 1


def test_foreign_artifacts_no_dockerfile_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_artifacts == set()
    assert prof.has_docker is False


def test_foreign_artifacts_never_added_to_features(tmp_path: Path) -> None:
    # Disclosure only, per design-stack-coverage-disclosure.md's pattern for the other three
    # channels — never gates a guard, since there is no Go source here to actually scan.
    (tmp_path / "Dockerfile").write_text("FROM caddy:2\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.foreign_artifacts
    assert "go" not in prof.features
    assert "caddy" not in prof.features


# Docker base-image tags, ANY language (docker_base_images) -----------------------
#
# The Contabo PHP-interpreter-RCE notice (CVE-2026-109618/109619) surfaced that `foreign_artifacts`
# above is deliberately curated to a short Go-only list (a different purpose: disclosing source-
# invisible Go) — nothing recorded an ORDINARY PHP/Node/Python/Ruby base image's tag at all, so
# `dependency-version-floor`'s `docker` ecosystem floors had nothing to read.


def test_docker_base_images_records_any_tagged_image(tmp_path: Path) -> None:
    # Unlike foreign_artifacts, this is unfiltered — an ordinary, non-Go base image still records
    # its (bare name, tag, Dockerfile path) tuple.
    (tmp_path / "Dockerfile").write_text("FROM php:8.2.34-fpm\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert prof.docker_base_images == {("php", "8.2.34-fpm", "Dockerfile")}
    assert prof.foreign_artifacts == set()  # php is not in the Go-only table


def test_docker_base_images_untagged_reference_excluded(tmp_path: Path) -> None:
    # An implicit `:latest` (no `:` at all) and a `@digest`-pinned reference both carry no
    # comparable version — excluded at the source, same as `_bare_image_name`'s own digest
    # handling.
    (tmp_path / "Dockerfile").write_text(
        "FROM php\n"
        "FROM php@sha256:deadbeef00000000000000000000000000000000000000000000000000000000\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.docker_base_images == set()


def test_docker_base_images_stage_reference_excluded(tmp_path: Path) -> None:
    # Same stage-alias exclusion as foreign_artifacts: a later `FROM <stage-name>` is not a
    # pullable image and must not be recorded even if the alias happens to look tagged.
    (tmp_path / "Dockerfile").write_text(
        "FROM php:8.2.34-fpm AS base\nFROM base\nRUN echo hi\n", encoding="utf-8"
    )
    prof = detect(tmp_path)
    assert prof.docker_base_images == {("php", "8.2.34-fpm", "Dockerfile")}


def test_docker_base_images_multi_stage_each_tagged_stage_recorded(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM node:20.5.0 AS builder\nRUN npm run build\nFROM php:8.2.34-fpm\nCOPY --from=builder /dist /app\n",
        encoding="utf-8",
    )
    prof = detect(tmp_path)
    assert prof.docker_base_images == {
        ("node", "20.5.0", "Dockerfile"),
        ("php", "8.2.34-fpm", "Dockerfile"),
    }


def test_docker_base_images_path_is_relative_to_root(tmp_path: Path) -> None:
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / "worker.Dockerfile").write_text("FROM php:8.2.34-fpm\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert ("php", "8.2.34-fpm", str(Path("docker") / "worker.Dockerfile")) in prof.docker_base_images


def test_docker_base_images_no_dockerfile_stays_empty(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    assert detect(tmp_path).docker_base_images == set()


def test_bare_image_name_strips_tag_digest_and_registry_path() -> None:
    from agentsec.detect import _bare_image_name

    assert _bare_image_name("caddy:2") == "caddy"
    assert _bare_image_name("caddy") == "caddy"
    assert _bare_image_name("hashicorp/vault:1.15") == "vault"
    assert _bare_image_name("registry:5000/caddy:2") == "caddy"
    assert _bare_image_name("caddy@sha256:deadbeef") == "caddy"
    assert _bare_image_name("CADDY:2") == "caddy"


# ---------------------------------------------------------------------------
# #697: detection must not rescan a blank-line run quadratically
#
# `detect()` is the one path NO stack gate can skip — every command runs it before any guard's
# `applies()` is consulted, so a blow-up here is not avoidable with `--guards-only` or by having a
# different stack. Five of its patterns anchored with `^\s*` under `(?m)`, including a hand-copied
# duplicate of `docker_latest_base_tag`'s `_FROM_INSTRUCTION` that the #676/#696 hardening never
# reached. Measured before the conversion: 6.3s on a 32,000-blank-line Dockerfile.
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_detect_blank_line_run_stays_linear(tmp_path: Path) -> None:
    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). The fourth size extends the TOP, where this
    # workload is cheap enough that the extra step costs single-digit milliseconds.
    sizes = [2000, 8000, 32000, 128000]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        # `ARG` before `FROM` is legal Dockerfile, so this file is well-formed but offers the
        # FROM patterns no line to match. That matters: a matching line would swallow the blank
        # run into one match and hide the very blow-up being measured (#697).
        (root / "Dockerfile").write_text("ARG BASE=alpine\nRUN echo hi\n" + "\n" * n, encoding="utf-8")
        # A SECOND Dockerfile carries the only `FROM` in the tree, so the still-works assertion
        # below has something `_FROM_INSTRUCTION` actually drives while the blank-run file above
        # stays match-free. Putting the `FROM` in the padded file instead would let a match
        # swallow the run under the OLD anchor and quietly stop this test discriminating.
        (root / "Dockerfile.build").write_text("FROM caddy:2\nRUN echo build\n", encoding="utf-8")
        (root / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
        roots[n] = root

    seen: dict[int, set[str]] = {}

    def fingerprint(n: int) -> None:
        seen[n] = detect(roots[n]).foreign_artifacts

    assert_growth(fingerprint, sizes, expected="linear")
    # A detector that stopped READING Dockerfile content would also be fast. `foreign_artifacts` is
    # the field `_FROM_INSTRUCTION` actually feeds (detect.py:596-606); `has_docker` would NOT work
    # here — it is set from filename presence alone (detect.py:572-574), so it stays True even with
    # the pattern neutered, and asserting it proves nothing about the pattern being fixed.
    assert all(seen[n] == {"Caddy (Docker base image `caddy:2`)"} for n in sizes), seen


def test_detect_still_reads_a_from_after_a_blank_run(tmp_path: Path) -> None:
    """Rule 1: the conversion narrows what the anchor may cross, so the instruction it exists to
    find must still be found when a blank run precedes it.

    Asserts `foreign_artifacts`, the field `_FROM_INSTRUCTION` feeds, NOT `has_docker` — that one
    comes from filename presence alone and is True even when the pattern matches nothing, so it
    cannot tell a working conversion from a broken one."""
    (tmp_path / "Dockerfile").write_text(
        "# syntax=docker/dockerfile:1\n" + "\n" * 40 + "FROM caddy:2\nCMD ['x']\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    assert detect(tmp_path).foreign_artifacts == {"Caddy (Docker base image `caddy:2`)"}


def test_detect_from_after_a_blank_run_skips_a_build_stage_alias(tmp_path: Path) -> None:
    """The same pattern's OTHER job, also across a blank run: a later `FROM <alias>` naming an
    earlier stage is a build stage, not a pullable image, and must not be inventoried. This needs
    group(2) (the `AS` alias) to still be captured after the anchor change, which the single-FROM
    test above would not notice."""
    (tmp_path / "Dockerfile").write_text(
        "\n" * 20 + "FROM caddy:2 AS caddy\n" + "\n" * 20 + "FROM caddy\nCMD ['x']\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    # `caddy` the alias is skipped; only the real `caddy:2` image is inventoried.
    assert detect(tmp_path).foreign_artifacts == {"Caddy (Docker base image `caddy:2`)"}


def test_detect_still_recognizes_an_indented_ansible_play(tmp_path: Path) -> None:
    """`_ANSIBLE_PLAY_SHAPE`'s leading classes mean INDENT, and the conversion keeps the full
    whitespace vocabulary on the line (tab included) while refusing to cross one."""
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    play = tmp_path / "deploy.yml"
    play.write_text("---\n- hosts: all\n  tasks:\n    - name: ping\n", encoding="utf-8")
    assert detect(tmp_path).has_ansible is True
    # ...and a tab-indented play key is still play-shaped.
    play.write_text("---\n-\thosts: all\n\ttasks:\n", encoding="utf-8")
    assert detect(tmp_path).has_ansible is True


# --- StackProfile.python_paths() overlap dedup (#701) ------------------------------------------
# Same bug, same fix, as `guards/base.py::python_scan_dirs` (see that file's own test comment for
# the full story) -- this is the sibling copy the `bandit`/`semgrep` runners hand their scan
# targets from. Confirmed live: agentsec's own `python_dirs` resolves to both "." (root) and
# several of its own subdirectories at once, so without the dedup both runners would be handed
# root AND "guards" (etc.) as separate recursive targets, scanning every file under the overlap
# twice.

def test_python_paths_drops_root_when_subdir_also_present(tmp_path: Path) -> None:
    (tmp_path / "guards").mkdir()
    prof = StackProfile(root=tmp_path, python_dirs=[".", "guards"])
    assert prof.python_paths() == [tmp_path]


def test_python_paths_drops_subdir_when_root_also_present_regardless_of_order(
    tmp_path: Path,
) -> None:
    (tmp_path / "guards").mkdir()
    prof = StackProfile(root=tmp_path, python_dirs=["guards", "."])
    assert prof.python_paths() == [tmp_path]


def test_python_paths_keeps_sibling_dirs_unrelated_to_each_other(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "lib").mkdir()
    prof = StackProfile(root=tmp_path, python_dirs=["app", "lib"])
    assert sorted(prof.python_paths()) == sorted([tmp_path / "app", tmp_path / "lib"])


def test_detect_python_llm_from_crewai_requirements_only(tmp_path: Path) -> None:
    # A CrewAI app that declares only `crewai[tools]` (four of the crewAI-examples sub-projects) is an
    # LLM app: without this the `llm`-gated crewai-rce-chain guard never ran on it.
    (tmp_path / "requirements.txt").write_text("crewai[tools]==0.100.0\nfastapi\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text("print('hi')\n", encoding="utf-8")
    prof = detect(tmp_path)
    assert "llm" in prof.features


def test_detect_python_llm_from_crewai_tools_dependency_and_import(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("crewai-tools\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text("print('hi')\n", encoding="utf-8")
    assert "llm" in detect(tmp_path).features
    other = tmp_path / "imp"
    other.mkdir()
    (other / "app.py").write_text("from crewai_tools import CodeInterpreterTool\n", encoding="utf-8")
    assert "llm" in detect(other).features


def test_detect_no_python_llm_from_unrelated_crewai_lookalike(tmp_path: Path) -> None:
    """FP-bait: a lookalike package or module is not CrewAI."""
    (tmp_path / "requirements.txt").write_text("crewai-helpers-unrelated\nfastapi\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import crewai_helpers\n", encoding="utf-8")
    assert "llm" not in detect(tmp_path).features


# --------------------------------------------------------------------------- #
# Blob provenance (#566): only manifests and .py files this repo OWNS feed the shared
# `manifest_text` / `import_blob`. Before, a committed `third_party/` or `examples/` tree set
# `db=supabase`, `payments`, `llm`, the framework, … from someone else's dependencies. The
# vendored test and the owned test share one shape table, so neither direction can go vacuous: a
# shape that stopped firing at all fails the owned test.
# --------------------------------------------------------------------------- #

_BLOB_SHAPES = [
    # (file name, content, the feature it sets when the file is owned)
    pytest.param("package.json", '{"dependencies": {"@supabase/supabase-js": "^2.0.0"}}', "supabase",
                 id="supabase-js-key"),
    pytest.param(".env.example", "SUPABASE_URL=\n", "supabase", id="supabase-env-assignment"),
    pytest.param("client.py", "from supabase import create_client\n", "supabase", id="supabase-import"),
    pytest.param("requirements.txt", "stripe\n", "payments", id="stripe-requirement"),
    pytest.param("package.json", '{"dependencies": {"stripe": "^14.0.0"}}', "payments", id="stripe-js-dep"),
    pytest.param("llm.py", "import openai\n", "llm", id="openai-import"),
    pytest.param("requirements.txt", "langchain\n", "llm", id="langchain-requirement"),
    pytest.param("package.json", '{"dependencies": {"openai": "^4.0.0"}}', "llm", id="openai-js-dep"),
    pytest.param("srv.py", "from mcp.server import Server\n", "mcp", id="mcp-import"),
    pytest.param("package.json", '{"dependencies": {"express": "^4.0.0"}}', "express", id="express-dep"),
    pytest.param("package.json", '{"dependencies": {"next": "14.0.0"}}', "nextjs", id="next-dep"),
    pytest.param("cache.py", "import redis\n", "redis", id="redis-import"),
    pytest.param("server.py", "from fastapi import FastAPI\n", "fastapi", id="fastapi-import"),
    pytest.param("package.json", '{"devDependencies": {"electron": "^30.0.0"}}', "electron",
                 id="electron-dep"),
]


def _blob_base_repo(root: Path) -> None:
    """A repo whose only stack signals are python + postgres + sql, so each shape above is the one
    thing that can add its feature."""
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("import os\n", encoding="utf-8")
    (root / "app" / "db.py").write_text("import psycopg2\n", encoding="utf-8")
    (root / "sql").mkdir()
    (root / "sql" / "app.sql").write_text("CREATE TABLE public.orders (id int);\n", encoding="utf-8")


def _plant(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_detect_blob_base_repo_sets_none_of_the_shape_features(tmp_path: Path) -> None:
    # The control for both tests below: without a planted shape, none of their features is on.
    _blob_base_repo(tmp_path)
    prof = detect(tmp_path)
    assert prof.db == "postgres"
    assert not {p.values[2] for p in _BLOB_SHAPES} & prof.features


@pytest.mark.parametrize(
    "prefix",
    [
        "third_party/lib/",
        "vendor/x/",
        "examples/demo/",
        "testdata/r/",
        "samples/s/",
        "tests/fixtures/app/",
        "apps/web/vendor/",   # a vendored tree nested inside an owned workspace dir
        "THIRDPARTY/",        # case-insensitive
        "app/external/vendor/",   # owned `external/` does not launder a vendored tree inside it
        # Depth 1: the file's own parent is the vendored dir. `_owns_dir(f.parent, root)` skips
        # the parent by design, so reusing it for files would count these as owned.
        "third_party/",
    ],
)
@pytest.mark.parametrize(("name", "content", "feature"), _BLOB_SHAPES)
def test_detect_a_vendored_or_sample_tree_cannot_set_a_blob_feature(
    tmp_path: Path, prefix: str, name: str, content: str, feature: str
) -> None:
    # Regression (#566, HIGH): a vendored `third_party/lib/package.json` declaring
    # `@supabase/supabase-js` set db=supabase, and this repo's own `public.orders` then produced a
    # real HIGH public-table-rls finding that failed the CI gate.
    _blob_base_repo(tmp_path)
    _plant(tmp_path, prefix + name, content)
    prof = detect(tmp_path)
    assert feature not in prof.features
    assert prof.db == "postgres"


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "apps/backend/",
        "packages/db/",
        "services/api/",
        "src/",
        "src/example_app/",   # segments match whole: `example_app` is not `examples?`
    ],
)
@pytest.mark.parametrize(("name", "content", "feature"), _BLOB_SHAPES)
def test_detect_an_owned_manifest_or_import_still_sets_its_feature(
    tmp_path: Path, prefix: str, name: str, content: str, feature: str
) -> None:
    # The still-fires direction for the scoping above (Rule 1): the repo root and an ordinary
    # monorepo workspace dir are this repo's own and must keep detecting exactly as before.
    _blob_base_repo(tmp_path)
    _plant(tmp_path, prefix + name, content)
    assert feature in detect(tmp_path).features


@pytest.mark.parametrize("prefix", ["external/", "contrib/", "app/external/", "services/contrib/"])
@pytest.mark.parametrize(("name", "content", "feature"), _BLOB_SHAPES)
def test_detect_external_and_contrib_dirs_still_set_a_blob_feature(
    tmp_path: Path, prefix: str, name: str, content: str, feature: str
) -> None:
    # #566 review R1-M1: `external` and `contrib` are vendored names for the Supabase LAYOUT arm,
    # but they also commonly hold owned code (`app/external/` API clients, `django/contrib/`).
    # Scoping the blobs with them silently dropped `llm`, `payments` and `db=supabase` from that
    # code, so the blobs leave them owned.
    _blob_base_repo(tmp_path)
    _plant(tmp_path, prefix + name, content)
    assert feature in detect(tmp_path).features


@pytest.mark.parametrize(
    ("pyproject", "uv"),
    [("pyproject.toml", True), ("examples/a/pyproject.toml", False)],
)
def test_detect_tool_uv_table_counts_only_in_an_owned_pyproject(
    tmp_path: Path, pyproject: str, uv: bool
) -> None:
    # #566 review R1-L1: `[tool.uv]` is read from the manifest blob, so it is scoped like every
    # other blob consumer. A sample project's uv config does not make this repo a uv repo. No
    # `uv.lock` here: that arm matches the file name and is not part of the blob.
    _blob_base_repo(tmp_path)
    _plant(tmp_path, pyproject, '[project]\nname = "x"\n\n[tool.uv]\ndev-dependencies = []\n')
    assert ("uv" in detect(tmp_path).package_managers) is uv


@pytest.mark.parametrize(("name", "content", "feature"), _BLOB_SHAPES)
def test_detect_blob_ownership_ignores_the_checkout_path(
    tmp_path: Path, name: str, content: str, feature: str
) -> None:
    # Only the segments BELOW the scanned root are judged. A repo checked out under `third_party/`
    # or `examples/` is still its own repo, so its root manifests and imports still count.
    root = tmp_path / "third_party" / "examples" / "my-app"
    _blob_base_repo(root)
    _plant(root, name, content)
    assert feature in detect(root).features


@pytest.mark.parametrize(
    ("owned_line", "feature"),
    [("from fastapi import FastAPI\n", "fastapi"), ("from openai import OpenAI\n", "llm")],
)
def test_detect_sample_files_do_not_use_up_the_import_scan_cap(
    tmp_path: Path, owned_line: str, feature: str
) -> None:
    # The false-negative twin of #566. `examples/` sorts before `src/`, so on main the samples
    # filled all `_MAX_PY_SCAN` slots and the owned import was never read. Measured on the corpus:
    # semantic-kernel's import scan read 0 of its 556 owned .py files. No manifest declares the
    # dependency here, so the import scan is the only arm that can find it.
    for i in range(_MAX_PY_SCAN + 1):
        _plant(tmp_path, f"examples/e_{i:03d}.py", "x = 1\n")
    _plant(tmp_path, "src/app/main.py", owned_line)
    assert feature in detect(tmp_path).features


@pytest.mark.parametrize(
    ("manifest", "fires"),
    [("third_party/lib/package.json", False), ("package.json", True)],
)
def test_vendored_supabase_dep_does_not_raise_a_public_table_rls_high(
    tmp_path: Path, manifest: str, fires: bool
) -> None:
    # The #566 symptom end to end, through the report: the HIGH is real when the Supabase dep is
    # this repo's own, and absent when it belongs to a vendored tree.
    (tmp_path / "requirements.txt").write_text("fastapi\npsycopg2\n", encoding="utf-8")
    _plant(tmp_path, "app/main.py", "from fastapi import FastAPI\n")
    _plant(tmp_path, "sql/app.sql", "CREATE TABLE public.orders (id int);\n")
    _plant(tmp_path, manifest, '{"dependencies": {"@supabase/supabase-js": "^2.0.0"}}')
    result = audit(tmp_path, run_scanners=False)
    rules = {f.rule for f in result.findings}
    assert ("public-table-rls/rls-disabled-in-public" in rules) is fires
