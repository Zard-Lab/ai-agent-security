"""Guard: a declared dependency name is one typing slip away from a popular PyPI/npm package —
checklist §5, new item; mined from typomania's squat checks (omitted character, repeated
character, swapped adjacent characters, swapped delimiter-separated words).

`reqeusts` for `requests`, `expres` for `express`, `dateutil-python` for `python-dateutil`: a
typo'd dependency name resolves to whatever an attacker registered under it, and the install
runs their code. `requirements*.txt`, `pyproject.toml` (`[project]` dependencies, optional
dependencies, dependency groups, Poetry dependencies) and `package.json` (`dependencies`,
`devDependencies`, `optionalDependencies`) are read.

False positives are the whole risk of this idea, so the rule is deliberately narrow:

  * The declared name is length >= 6 (PEP 503-normalised for PyPI, lower-cased for npm).
  * It is NOT in the embedded corpus of popular names (either ecosystem) or the real-name
    allowlist, and it is NOT already within one edit of two different corpus names (ambiguous).
  * It is exactly ONE of: the corpus name with one character omitted, one character doubled, two
    adjacent characters swapped, or two hyphen-separated words swapped.
  * No substitution, insertion of arbitrary characters, or longer edit distances.

The corpus is a curated set of well-known names, not a registry mirror: silence means "not a
near-miss of a name this guard knows", never "this package is legitimate". Severity is MEDIUM: a
near-miss is a prompt to re-read the name, not proof of a squat.

Suppress an audited name with `# security: allow-dependency-typosquat-popular` as a comment on the
same line as that dependency (requirements, TOML). `package.json` has no comments, so the literal
is followed by the audited names (`security: allow-dependency-typosquat-popular expres other`, in
any string value such as a `"//"` key). The pragma covers only the names on its own line: a typo
added later still fires.

Residual false-positive risk: the check is static and has no download signal, so a real package
that happens to sit one edit from a corpus name is flagged until it is added to the real-name
allowlist or its entry carries the pragma.
"""
from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    CommentDialect,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files_named,
    pragma_line_set,
    read,
    rel,
)

_PRAGMA = "security: allow-dependency-typosquat-popular"

_MIN_LEN = 6


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())

# Popular PyPI distributions, PEP 503-normalised. Only names known to exist.
_PYPI_POPULAR = _words("""
requests urllib3 boto3 botocore s3transfer setuptools certifi idna charset-normalizer
typing-extensions python-dateutil packaging six pyyaml numpy pip cryptography cffi pycparser attrs
jmespath wheel pydantic pydantic-core pydantic-settings annotated-types click jinja2 markupsafe
pandas pytz tzdata rsa pyasn1 pyasn1-modules aiohttp aiosignal frozenlist multidict yarl
async-timeout protobuf grpcio google-api-core googleapis-common-protos google-auth
google-cloud-storage fsspec platformdirs filelock pluggy pytest iniconfig exceptiongroup tomli
colorama sqlalchemy greenlet flask werkzeug itsdangerous blinker django asgiref sqlparse fastapi
starlette uvicorn h11 anyio sniffio httpx httpcore httptools websockets uvloop watchfiles
python-dotenv python-multipart email-validator dnspython orjson ujson openai anthropic tiktoken
langchain langchain-core langchain-community langchain-openai langsmith langgraph llama-index
transformers tokenizers huggingface-hub safetensors torch torchvision tensorflow keras
scikit-learn scipy matplotlib seaborn pillow opencv-python psycopg2 psycopg2-binary psycopg
asyncpg pymysql mysqlclient redis celery kombu billiard amqp vine pymongo motor alembic mako
supabase gotrue postgrest storage3 gunicorn tqdm rich pygments markdown-it-py mdurl typer
shellingham tenacity jsonschema referencing rpds-py regex lxml beautifulsoup4 soupsieve html5lib
webencodings httplib2 oauthlib requests-oauthlib pyjwt python-jose passlib bcrypt argon2-cffi
pynacl paramiko fabric invoke ansible mypy mypy-extensions black flake8 pylint isort ruff pyright
coverage pytest-cov pytest-asyncio pytest-mock pytest-xdist pytest-django hypothesis tox
virtualenv poetry pipenv twine sphinx docutils babel nltk spacy gensim networkx sympy
statsmodels xgboost lightgbm joblib threadpoolctl numba llvmlite pyarrow polars duckdb sqlmodel
pytest-timeout structlog loguru sentry-sdk prometheus-client opentelemetry-api opentelemetry-sdk
stripe twilio sendgrid python-slugify markdown pypdf pymupdf pdfplumber python-docx openpyxl
xlrd xlsxwriter python-magic chardet cachetools wrapt decorator deprecated docker kubernetes
pexpect ptyprocess psutil ipython jupyter notebook jupyterlab ipykernel pyzmq tornado traitlets
nest-asyncio selenium playwright scrapy flask-cors flask-sqlalchemy flask-login flask-wtf
wtforms djangorestframework django-cors-headers django-environ whitenoise pyinstaller cython
pybind11 scikit-image imageio mcp fastmcp pydantic-ai instructor litellm chromadb
pinecone-client qdrant-client weaviate-client sentence-transformers faiss-cpu cohere groq
google-generativeai mistralai ollama gradio streamlit pytest-benchmark python-json-logger
""")

# Popular npm packages, lower-case, scoped names included in full. Only names known to exist.
_NPM_POPULAR = _words("""
react react-dom react-router react-router-dom react-native react-scripts react-redux redux
redux-thunk @reduxjs/toolkit next vue vuex vue-router nuxt svelte @sveltejs/kit @angular/core
@angular/common @angular/cli express body-parser cors cookie-parser morgan helmet dotenv lodash
underscore moment dayjs date-fns axios node-fetch got superagent request chalk commander yargs
minimist inquirer ora debug uuid nanoid async bluebird rxjs webpack webpack-cli
webpack-dev-server vite rollup esbuild parcel babel-loader @babel/core @babel/preset-env
@babel/preset-react typescript ts-node tsx tslib eslint prettier eslint-config-prettier
eslint-plugin-react eslint-plugin-import eslint-plugin-react-hooks @typescript-eslint/parser
@typescript-eslint/eslint-plugin jest ts-jest babel-jest mocha chai sinon vitest cypress
playwright @playwright/test puppeteer supertest nodemon concurrently cross-env rimraf husky
lint-staged tailwindcss postcss autoprefixer sass less styled-components @emotion/react
@emotion/styled @mui/material antd bootstrap jquery d3 chart.js three socket.io socket.io-client
ws mongoose mongodb mysql mysql2 pg sequelize typeorm prisma @prisma/client knex redis ioredis
graphql apollo-server @apollo/client jsonwebtoken bcrypt bcryptjs passport passport-local
express-session multer formidable sharp cheerio jsdom marked handlebars ejs pug glob fs-extra
semver zod yup joi ajv classnames prop-types immer zustand mobx swr @tanstack/react-query
react-hook-form formik framer-motion @supabase/supabase-js openai @anthropic-ai/sdk langchain
firebase aws-sdk @aws-sdk/client-s3 stripe @stripe/stripe-js @sentry/node @sentry/react winston
pino lru-cache core-js regenerator-runtime tslint @types/node @types/react @types/react-dom
@types/express @types/lodash @types/jest
""")

# Real packages that sit one edit from a corpus name; never flagged.
_REAL_NEIGHBOURS = _words("""
authlib psycopg-binary mongod prop-type deprecate
""")

_ALL_POPULAR = _PYPI_POPULAR | _NPM_POPULAR

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PEP503 = re.compile(r"[-_.]+")


def _norm_pypi(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def _near_miss(d: str, c: str) -> str | None:
    """The squat shape that turns corpus name `c` into `d`, or None."""
    if d == c:
        return None
    ld, lc = len(d), len(c)
    if ld == lc - 1:
        # Not the first character and not a digit: `authlib` is `oauthlib` minus its first letter and
        # `psycopg-binary` is `psycopg2-binary` minus a version digit, and both are real packages.
        if any(c[i].isalpha() and c[:i] + c[i + 1:] == d for i in range(1, lc)):
            return "one character omitted"
    elif ld == lc + 1:
        if any(c[i].isalpha() and c[: i + 1] + c[i:] == d for i in range(lc)):
            return "one character repeated"
    elif ld == lc:
        diff = [i for i in range(ld) if d[i] != c[i]]
        if (
            len(diff) == 2 and diff[1] == diff[0] + 1 and d[diff[0]] == c[diff[1]] and d[diff[1]] == c[diff[0]]
            and d[diff[0]].isalpha() and d[diff[1]].isalpha()
        ):
            return "two adjacent characters swapped"
        dw, cw = d.split("-"), c.split("-")
        if len(dw) >= 2 and sorted(dw) == sorted(cw) and dw != cw and all(len(w) >= 3 for w in dw):
            return "hyphen-separated words swapped"
    return None


def _squat_of(name: str, corpus: frozenset[str]) -> tuple[str, str] | None:
    if len(name) < _MIN_LEN or name in _ALL_POPULAR or name in _REAL_NEIGHBOURS:
        return None
    hits: dict[str, str] = {}
    for c in corpus:
        if abs(len(c) - len(name)) > 1:
            continue
        shape = _near_miss(name, c)
        if shape:
            hits[c] = shape
    if len(hits) != 1:  # none, or ambiguous between two popular names
        return None
    (c, shape), = hits.items()
    return c, shape


_TOKEN = re.compile(r"[A-Za-z0-9@][A-Za-z0-9@/._-]*")


def _pragma_names(text: str, dialect: CommentDialect | None, norm: Callable[[str], str]) -> frozenset[str]:
    """Names listed on the lines that carry the pragma: for a requirements or TOML entry, the
    dependency on that very line; for `package.json`, the names written after the literal."""
    names: set[str] = set()
    lines = text.splitlines()
    for n in pragma_line_set(_PRAGMA, text, dialect=dialect):
        names.update(norm(t) for t in _TOKEN.findall(lines[n - 1]))
    return frozenset(names)


def _py_spec_name(spec: str) -> str | None:
    s = spec.split("#", 1)[0].strip()
    if not s or s.startswith(("-", ".", "/")) or "://" in s:
        return None
    m = _REQ_NAME.match(s)
    return _norm_pypi(m.group(1)) if m else None


def _pyproject_names(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError):
        return []
    specs: list[str] = []
    proj = data.get("project")
    if isinstance(proj, dict):
        deps = proj.get("dependencies")
        if isinstance(deps, list):
            specs += [x for x in deps if isinstance(x, str)]
        opt = proj.get("optional-dependencies")
        if isinstance(opt, dict):
            for grp in opt.values():
                if isinstance(grp, list):
                    specs += [x for x in grp if isinstance(x, str)]
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for grp in groups.values():
            if isinstance(grp, list):
                specs += [x for x in grp if isinstance(x, str)]
    names = [n for s in specs if (n := _py_spec_name(s))]
    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        for key in ("dependencies", "dev-dependencies"):
            tbl = poetry.get(key)
            if isinstance(tbl, dict):
                names += [_norm_pypi(k) for k in tbl if isinstance(k, str) and k.lower() != "python"]
    return names


def _package_json_names(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []
    names: list[str] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            names += [k.lower() for k in deps if isinstance(k, str)]
    return names


class DependencyTyposquatPopularGuard(Guard):
    id = "dependency-typosquat-popular"
    title = "A declared dependency name is one typing slip away from a popular PyPI or npm package"
    area = "AI agent"

    # dependency-typosquat-popular-canary/requirements.txt: `reqeusts` is `requests` with two
    # adjacent characters swapped -> fires dependency-typosquat-popular/popular-name-near-miss.
    canary_plant = CanaryPlant(
        files={
            "dependency-typosquat-popular-canary/requirements.txt": (
                "fastapi==0.110.0\n"
                "reqeusts==2.31.0\n"
            ),
        },
        expects=frozenset({"dependency-typosquat-popular/popular-name-near-miss"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(root, "requirements*.txt", "pyproject.toml", "package.json"):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text:
                continue
            if f.name == "package.json":
                names, corpus, eco = _package_json_names(text), _NPM_POPULAR, "npm"
            elif f.name == "pyproject.toml":
                names, corpus, eco = _pyproject_names(text), _PYPI_POPULAR, "PyPI"
            else:
                names = [n for line in text.splitlines() if (n := _py_spec_name(line))]
                corpus, eco = _PYPI_POPULAR, "PyPI"
            allowed = _pragma_names(text, comment_dialect_for(f), str.lower if eco == "npm" else _norm_pypi)
            seen: set[str] = set()
            for name in names:
                if name in seen or name in allowed:
                    continue
                seen.add(name)
                hit = _squat_of(name, corpus)
                if hit is None:
                    continue
                popular, shape = hit
                out.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=r,
                    message=(
                        f"Dependency {name!r} ({eco}) is not a popular package name but is the "
                        f"popular {popular!r} with {shape}: the typo shape typosquatters register. "
                        "If an attacker owns this name, installing it runs their code."
                    ),
                    remediation=(
                        f"Check the spelling. If {popular!r} was intended, correct the name; if "
                        f"{name!r} is genuinely the package you want, verify its publisher and "
                        "add `# security: allow-dependency-typosquat-popular` on its line (in "
                        "`package.json`, the literal followed by the name, in a string value)."
                    ),
                    rule="dependency-typosquat-popular/popular-name-near-miss",
                    standards=["CWE-829", "OWASP-ASI:ASI04"],
                ))
        return out
