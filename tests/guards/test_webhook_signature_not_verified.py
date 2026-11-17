from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.detect import StackProfile
from agentsec.guards.webhook_signature_not_verified import WebhookSignatureNotVerifiedGuard
from tests.conftest import mkprofile


def _pyprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"python"}, python_dirs=["."])


def _jsprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"javascript", "typescript"})


def _run_py(tmp_path: Path, name: str, content: str) -> list:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return WebhookSignatureNotVerifiedGuard().run(tmp_path, _pyprof(tmp_path))


def _run_js(tmp_path: Path, name: str, content: str) -> list:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return WebhookSignatureNotVerifiedGuard().run(tmp_path, _jsprof(tmp_path))


# ---------------------------------------------------------------------------------------------
# Python — GitHub (HMAC)
# ---------------------------------------------------------------------------------------------

def test_python_github_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    payload = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/github-unverified"
    assert findings[0].severity == "high"
    assert "OWASP:A08" in findings[0].standards
    assert "CWE-345" in findings[0].standards


def test_python_github_verified_inline_stays_silent(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "import hashlib, hmac\n"
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    body = await request.body()\n"
        "    sig = request.headers.get('x-hub-signature-256')\n"
        "    mac = hmac.new(SECRET, body, hashlib.sha256).hexdigest()\n"
        "    if not hmac.compare_digest('sha256=' + mac, sig):\n"
        "        raise ValueError('bad signature')\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


def test_python_svix_library_verification_stays_silent(tmp_path: Path) -> None:
    # Review H4, reproduced live: a correctly-implemented svix/standardwebhooks handler was
    # flagged as unverified because the accepted set was HMAC/Ed25519-primitive-only.
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "from svix.webhooks import Webhook\n"
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_hook(request: Request) -> dict:\n"
        '    wh = Webhook("whsec_test")\n'
        "    payload = wh.verify(await request.body(), dict(request.headers))\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


def test_python_bare_dot_verify_without_webhook_ctor_still_fires(tmp_path: Path) -> None:
    # FP-bait, the counterweight to the library-verification widening: a bare `.verify(` call
    # with no `Webhook(...)` constructor anywhere in scope (e.g. an unrelated cert/schema
    # verification call) must NOT be treated as webhook signature verification.
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    payload = await request.json()\n"
        "    cert.verify(payload)  # unrelated -- not a webhook signature check\n"
        "    return {'ok': True}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/github-unverified"


def test_python_unrelated_webhook_ctor_and_verify_still_fires(tmp_path: Path) -> None:
    # Round-2 review R1, the co-occurrence counterweight. The pre-existing FP-bait above covers
    # `.verify(` with NO `Webhook(` anywhere; it does not cover the only shape the library check
    # can actually get wrong — an UNRELATED instance of EACH token in the same file. Both call
    # sites scan the whole file, so before the library-name gate this combination silently
    # suppressed a genuinely unverified handler (the false-negative direction).
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "from discord import Webhook  # outgoing notifier, unrelated\n"
        "import jwt\n"
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        "def notify(msg: str) -> None:\n"
        '    hook = Webhook(url="https://discord.com/api/webhooks/xxx")\n'
        "    hook.send(msg)\n\n"
        "def check(tok, pub):\n"
        "    return pub.verify(tok)  # unrelated -- not a webhook signature check\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    payload = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/github-unverified"


def test_js_unrelated_webhook_ctor_and_jwt_verify_still_fires(tmp_path: Path) -> None:
    # Same class on the JS path, which is the more exposed of the two: `jwt.verify(` is close to
    # universal in Express codebases and `Webhook(` ships in discord.js, so the unrelated-pair
    # combination is ordinary rather than contrived.
    findings = _run_js(
        tmp_path,
        "server.js",
        "const jwt = require('jsonwebtoken');\n"
        "const { WebhookClient, Webhook } = require('discord.js');\n"
        "const app = require('express')();\n\n"
        "function notify(msg) {\n"
        "  const hook = new Webhook({ url: process.env.DISCORD_URL });\n"
        "  hook.send(msg);\n"
        "}\n\n"
        "function auth(token) {\n"
        "  return jwt.verify(token, process.env.SECRET);  // unrelated\n"
        "}\n\n"
        "app.post('/webhooks/github', (req, res) => {\n"
        "  const payload = req.body;\n"
        "  res.json({ ok: true });\n"
        "});\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/github-unverified"


def test_python_github_archon_style_positive_control(tmp_path: Path) -> None:
    """Modeled on the real, correct shape confirmed by reading
    coleam00/Archon's packages/server/src/routes/webhooks.ts: a GitHub webhook route that reads
    the x-hub-signature-256 header and verifies it over the raw body via HMAC-SHA256 before
    trusting the payload. This is the positive-control case the guard must never fire on."""
    findings = _run_py(
        tmp_path,
        "github_webhooks.py",
        "import hashlib\n"
        "import hmac\n"
        "from fastapi import APIRouter, HTTPException, Request\n\n"
        "router = APIRouter()\n\n"
        '@router.post("/api/webhooks/github")\n'
        "async def handle_github_webhook(request: Request) -> dict:\n"
        "    \"\"\"Receive a GitHub webhook event and verify its signature.\"\"\"\n"
        "    raw_body = await request.body()\n"
        "    signature_header = request.headers.get('X-Hub-Signature-256', '')\n"
        "    expected = 'sha256=' + hmac.new(\n"
        "        WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256\n"
        "    ).hexdigest()\n"
        "    if not hmac.compare_digest(expected, signature_header):\n"
        "        raise HTTPException(status_code=401, detail='Invalid signature')\n"
        "    event = await request.json()\n"
        "    return {'status': 'accepted', 'event': event.get('action')}\n",
    )
    assert findings == []


def test_python_route_without_platform_or_webhook_word_stays_silent(tmp_path: Path) -> None:
    """An ordinary POST route — no platform name, no 'webhook' word — must never fire."""
    findings = _run_py(
        tmp_path,
        "routes.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        '@app.post("/orders")\n'
        "async def create_order(payload: dict) -> dict:\n"
        "    return {'id': 1}\n",
    )
    assert findings == []


def test_python_platform_name_without_route_decorator_stays_silent(tmp_path: Path) -> None:
    """A plain helper function that mentions 'github'/'webhook' but is not itself a route
    handler must never fire — the route-decorator gate is required."""
    findings = _run_py(
        tmp_path,
        "helpers.py",
        "def format_github_webhook_summary(event: dict) -> str:\n"
        "    return f\"github webhook: {event['action']}\"\n",
    )
    assert findings == []


def test_python_platform_name_without_webhook_word_stays_silent(tmp_path: Path) -> None:
    """A route that happens to mention 'github' (e.g. a GitHub API client call) but never says
    'webhook' and references no known signature header must stay silent — this is the
    FP-reduction co-occurrence gate: platform name alone is not enough."""
    findings = _run_py(
        tmp_path,
        "deploy.py",
        "from fastapi import FastAPI\n"
        "import github_client\n"
        "app = FastAPI()\n\n"
        '@app.post("/deploy")\n'
        "async def deploy(payload: dict) -> dict:\n"
        "    github_client.create_deployment_status(payload['sha'], 'success')\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


def test_python_outbound_github_notifier_is_not_a_receiver(tmp_path: Path) -> None:
    """Sending a notification TO a GitHub-style webhook URL (an outbound requests.post call) is
    not a route handler at all — must not be confused with a route RECEIVING a webhook. The
    literal '@app.post'/'@router.post' decorator gate is what keeps this silent even though both
    'github' and 'webhook' appear in the file."""
    findings = _run_py(
        tmp_path,
        "notify.py",
        "import requests\n\n"
        "def notify_github_webhook(status: str) -> None:\n"
        "    requests.post(GITHUB_WEBHOOK_URL, json={'state': status})\n",
    )
    assert findings == []


def test_python_github_fake_comment_verification_still_fires(tmp_path: Path) -> None:
    """Adversarial bypass attempt: a fake verification call sitting in a COMMENT must not
    silence the finding — the guard strips '#' comments before matching (see
    `_strip_py_comments`)."""
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    # hmac.compare_digest(expected, sig)  -- trust me, this is verified\n"
        "    payload = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/github-unverified"


def test_python_github_same_file_helper_delegation_stays_silent(tmp_path: Path) -> None:
    """Known-supported bypass-shaped pattern: verification is delegated to a helper function
    DEFINED IN THE SAME FILE rather than inlined in the handler. This is treated as verified
    (mirrors stripe_webhook.py's own file-wide leniency) — a deliberate, documented design
    choice, not an oversight."""
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "import hashlib, hmac\n"
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        "def verify_github_signature(body: bytes, sig: str) -> bool:\n"
        "    mac = hmac.new(SECRET, body, hashlib.sha256).hexdigest()\n"
        "    return hmac.compare_digest('sha256=' + mac, sig)\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    body = await request.body()\n"
        "    sig = request.headers.get('x-hub-signature-256')\n"
        "    if not verify_github_signature(body, sig):\n"
        "        raise ValueError('bad signature')\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


def test_python_github_cross_file_helper_delegation_still_fires(tmp_path: Path) -> None:
    """Known LIMITATION, exercised on purpose: verification delegated to a helper IMPORTED FROM
    A DIFFERENT FILE is invisible to this guard (it only reads the file being scanned) and still
    fires. This is the documented gap — use `# security: allow-unverified-webhook` for this
    shape."""
    (tmp_path / "verify_utils.py").write_text(
        "import hashlib, hmac\n\n"
        "def verify_github_signature(body: bytes, sig: str) -> bool:\n"
        "    mac = hmac.new(SECRET, body, hashlib.sha256).hexdigest()\n"
        "    return hmac.compare_digest('sha256=' + mac, sig)\n",
        encoding="utf-8",
    )
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "from fastapi import FastAPI, Request\n"
        "from verify_utils import verify_github_signature\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    body = await request.body()\n"
        "    sig = request.headers.get('x-hub-signature-256')\n"
        "    if not verify_github_signature(body, sig):\n"
        "        raise ValueError('bad signature')\n"
        "    return {'ok': True}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/github-unverified"


def test_python_pragma_suppresses(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "webhooks.py",
        "# security: allow-unverified-webhook\n"
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    payload = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


def test_python_nonproduct_path_skipped(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_webhooks.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/github")\n'
        "async def github_webhook(request: Request) -> dict:\n"
        "    payload = await request.json()\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    assert WebhookSignatureNotVerifiedGuard().run(tmp_path, _pyprof(tmp_path)) == []


# ---------------------------------------------------------------------------------------------
# Python — Slack (HMAC)
# ---------------------------------------------------------------------------------------------

def test_python_slack_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "slack_webhook.py",
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/slack")\n'
        "async def slack_webhook(request: Request) -> dict:\n"
        "    payload = await request.form()\n"
        "    return {'ok': True}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/slack-unverified"


def test_python_slack_verified_stays_silent(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "slack_webhook.py",
        "import hashlib, hmac, time\n"
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/slack")\n'
        "async def slack_webhook(request: Request) -> dict:\n"
        "    body = await request.body()\n"
        "    ts = request.headers.get('x-slack-request-timestamp')\n"
        "    sig = request.headers.get('x-slack-signature')\n"
        "    basestring = f'v0:{ts}:'.encode() + body\n"
        "    mac = hmac.new(SIGNING_SECRET, basestring, hashlib.sha256).hexdigest()\n"
        "    if not hmac.compare_digest('v0=' + mac, sig):\n"
        "        raise ValueError('bad signature')\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


# ---------------------------------------------------------------------------------------------
# Python — Discord (Ed25519)
# ---------------------------------------------------------------------------------------------

def test_python_discord_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "discord_webhook.py",
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/discord")\n'
        "async def discord_webhook(request: Request) -> dict:\n"
        "    payload = await request.json()\n"
        "    return {'type': 1}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/discord-unverified"


def test_python_discord_verified_stays_silent(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "discord_webhook.py",
        "from nacl.signing import VerifyKey\n"
        "from fastapi import FastAPI, Request, HTTPException\n"
        "app = FastAPI()\n"
        "verify_key = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY))\n\n"
        '@app.post("/webhooks/discord")\n'
        "async def discord_webhook(request: Request) -> dict:\n"
        "    sig = request.headers.get('x-signature-ed25519')\n"
        "    ts = request.headers.get('x-signature-timestamp')\n"
        "    body = await request.body()\n"
        "    try:\n"
        "        verify_key.verify(ts.encode() + body, bytes.fromhex(sig))\n"
        "    except Exception:\n"
        "        raise HTTPException(status_code=401)\n"
        "    return {'type': 1}\n",
    )
    assert findings == []


# ---------------------------------------------------------------------------------------------
# Python — Telegram (secret-token exact match)
# ---------------------------------------------------------------------------------------------

def test_python_telegram_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "telegram_webhook.py",
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/telegram")\n'
        "async def telegram_webhook(request: Request) -> dict:\n"
        "    update = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/telegram-unverified"


def test_python_telegram_verified_stays_silent(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "telegram_webhook.py",
        "import hmac\n"
        "from fastapi import FastAPI, Request, HTTPException\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/telegram")\n'
        "async def telegram_webhook(request: Request) -> dict:\n"
        "    token = request.headers.get('x-telegram-bot-api-secret-token')\n"
        "    if not hmac.compare_digest(token or '', SECRET_TOKEN):\n"
        "        raise HTTPException(status_code=401)\n"
        "    update = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


def test_python_telegram_verified_direct_compare_stays_silent(tmp_path: Path) -> None:
    """Telegram/GitLab verify by plain secret-token EXACT MATCH (no HMAC) per the platform's own
    spec — a direct comparison against the known header/token name is itself the correct
    pattern, not a red flag."""
    findings = _run_py(
        tmp_path,
        "telegram_webhook.py",
        "from fastapi import FastAPI, Request, HTTPException\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/telegram")\n'
        "async def telegram_webhook(request: Request) -> dict:\n"
        "    secret_token = request.headers.get('x-telegram-bot-api-secret-token')\n"
        "    if secret_token != EXPECTED_SECRET_TOKEN:\n"
        "        raise HTTPException(status_code=401)\n"
        "    update = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


# ---------------------------------------------------------------------------------------------
# Python — GitLab (secret-token exact match)
# ---------------------------------------------------------------------------------------------

def test_python_gitlab_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "gitlab_webhook.py",
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/gitlab")\n'
        "async def gitlab_webhook(request: Request) -> dict:\n"
        "    event = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/gitlab-unverified"


def test_python_gitlab_verified_stays_silent(tmp_path: Path) -> None:
    findings = _run_py(
        tmp_path,
        "gitlab_webhook.py",
        "import hmac\n"
        "from fastapi import FastAPI, Request, HTTPException\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhooks/gitlab")\n'
        "async def gitlab_webhook(request: Request) -> dict:\n"
        "    token = request.headers.get('x-gitlab-token')\n"
        "    if not hmac.compare_digest(token or '', GITLAB_SECRET):\n"
        "        raise HTTPException(status_code=401)\n"
        "    event = await request.json()\n"
        "    return {'ok': True}\n",
    )
    assert findings == []


# ---------------------------------------------------------------------------------------------
# JS/TS — GitHub (HMAC), including the Archon positive control and route-vs-sender FP-bait
# ---------------------------------------------------------------------------------------------

def test_js_github_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "webhooks.ts",
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/github', async (req, res) => {\n"
        "  const payload = req.body;\n"
        "  res.sendStatus(200);\n"
        "});\n"
        "export default router;\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/github-unverified"
    assert findings[0].severity == "high"


def test_js_github_archon_style_positive_control(tmp_path: Path) -> None:
    """Modeled on the real, correct shape confirmed by reading coleam00/Archon's
    packages/server/src/routes/webhooks.ts: it checks x-hub-signature-256 against the raw body
    with an HMAC-SHA256 digest before trusting the payload. Must NOT fire."""
    findings = _run_js(
        tmp_path,
        "webhooks.ts",
        "import express from 'express';\n"
        "import crypto from 'crypto';\n"
        "const router = express.Router();\n\n"
        "router.post('/api/webhooks/github', async (req, res) => {\n"
        "  const signature = req.headers['x-hub-signature-256'] as string;\n"
        "  const rawBody = req.rawBody;\n"
        "  const hmac = crypto.createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET!);\n"
        "  const digest = 'sha256=' + hmac.update(rawBody).digest('hex');\n"
        "  const expected = Buffer.from(digest);\n"
        "  const actual = Buffer.from(signature);\n"
        "  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {\n"
        "    return res.status(401).send('Invalid signature');\n"
        "  }\n"
        "  res.sendStatus(200);\n"
        "});\n"
        "export default router;\n",
    )
    assert findings == []


def test_js_route_without_platform_or_webhook_word_stays_silent(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "routes.ts",
        "import express from 'express';\n"
        "const app = express();\n\n"
        "app.post('/orders', (req, res) => {\n"
        "  res.json({ id: 1 });\n"
        "});\n",
    )
    assert findings == []


def test_js_outbound_slack_notifier_is_not_a_receiver(tmp_path: Path) -> None:
    """Posting a notification TO a Slack incoming-webhook URL (an outbound axios/fetch POST) is
    not a route handler — the guard's route-marker requires an `app.post(`/`router.post(`-style
    receiver, not any `.post(` call."""
    findings = _run_js(
        tmp_path,
        "notify.ts",
        "import axios from 'axios';\n\n"
        "export async function notifySlackWebhook(message: string) {\n"
        "  await axios.post(SLACK_WEBHOOK_URL, { text: message });\n"
        "}\n",
    )
    assert findings == []


def test_js_github_fake_comment_verification_still_fires(tmp_path: Path) -> None:
    """Adversarial bypass attempt: a fake verification call sitting in a `//` comment must not
    silence the finding — the guard matches against `strip_js_comments`-stripped code."""
    findings = _run_js(
        tmp_path,
        "webhooks.ts",
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/github', async (req, res) => {\n"
        "  // crypto.timingSafeEqual(expected, actual) -- verified upstream, trust me\n"
        "  const payload = req.body;\n"
        "  res.sendStatus(200);\n"
        "});\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/github-unverified"


def test_js_pragma_suppresses(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "webhooks.ts",
        "// security: allow-unverified-webhook\n"
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/github', async (req, res) => {\n"
        "  res.sendStatus(200);\n"
        "});\n",
    )
    assert findings == []


def test_js_nonproduct_path_skipped(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "webhooks.spec.ts").write_text(
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/github', async (req, res) => {\n"
        "  res.sendStatus(200);\n"
        "});\n",
        encoding="utf-8",
    )
    assert WebhookSignatureNotVerifiedGuard().run(tmp_path, _jsprof(tmp_path)) == []


# ---------------------------------------------------------------------------------------------
# JS/TS — Discord (Ed25519)
# ---------------------------------------------------------------------------------------------

def test_js_discord_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "discord_webhook.ts",
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/discord', async (req, res) => {\n"
        "  const interaction = req.body;\n"
        "  res.json({ type: 1 });\n"
        "});\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/discord-unverified"


def test_js_discord_verified_stays_silent(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "discord_webhook.ts",
        "import { verifyKey } from 'discord-interactions';\n"
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/discord', async (req, res) => {\n"
        "  const signature = req.headers['x-signature-ed25519'] as string;\n"
        "  const timestamp = req.headers['x-signature-timestamp'] as string;\n"
        "  const isValid = verifyKey(req.rawBody, signature, timestamp, DISCORD_PUBLIC_KEY);\n"
        "  if (!isValid) return res.status(401).send('bad signature');\n"
        "  res.json({ type: 1 });\n"
        "});\n",
    )
    assert findings == []


# ---------------------------------------------------------------------------------------------
# JS/TS — Telegram / GitLab (secret-token exact match)
# ---------------------------------------------------------------------------------------------

def test_js_telegram_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "telegram_webhook.ts",
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/telegram', async (req, res) => {\n"
        "  const update = req.body;\n"
        "  res.sendStatus(200);\n"
        "});\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/telegram-unverified"


def test_js_telegram_verified_stays_silent(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "telegram_webhook.ts",
        "import crypto from 'crypto';\n"
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/telegram', async (req, res) => {\n"
        "  const token = req.headers['x-telegram-bot-api-secret-token'] as string;\n"
        "  const expected = Buffer.from(SECRET_TOKEN);\n"
        "  const actual = Buffer.from(token || '');\n"
        "  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {\n"
        "    return res.sendStatus(401);\n"
        "  }\n"
        "  res.sendStatus(200);\n"
        "});\n",
    )
    assert findings == []


def test_js_gitlab_fires_no_verification(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "gitlab_webhook.ts",
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/gitlab', async (req, res) => {\n"
        "  const event = req.body;\n"
        "  res.sendStatus(200);\n"
        "});\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "webhook-signature-not-verified/gitlab-unverified"


def test_js_gitlab_verified_direct_compare_stays_silent(tmp_path: Path) -> None:
    findings = _run_js(
        tmp_path,
        "gitlab_webhook.ts",
        "import express from 'express';\n"
        "const router = express.Router();\n\n"
        "router.post('/webhooks/gitlab', async (req, res) => {\n"
        "  const token = req.headers['x-gitlab-token'];\n"
        "  if (token !== process.env.GITLAB_WEBHOOK_TOKEN) {\n"
        "    return res.sendStatus(401);\n"
        "  }\n"
        "  res.sendStatus(200);\n"
        "});\n",
    )
    assert findings == []


# --- #1055: a JS/TS verification credit or route marker counts only when it is live code ----------

_JS_GITHUB = (
    "import express from 'express';\n"
    "import crypto from 'crypto';\n"
    "const router = express.Router();\n"
    "router.post('/webhooks/github', async (req, res) => {\n"
    "  {EXTRA}\n"
    "  res.sendStatus(200);\n"
    "});\n"
)

_JS_GITLAB = (
    "import express from 'express';\n"
    "const router = express.Router();\n"
    "router.post('/webhooks/gitlab', async (req, res) => {\n"
    "  {EXTRA}\n"
    "  res.sendStatus(200);\n"
    "});\n"
)


@pytest.mark.parametrize(
    ("template", "extra", "rule"),
    [
        (_JS_GITHUB, "log.warn('TODO: crypto.timingSafeEqual(a, b) check');", "github"),
        (_JS_GITHUB, 'log.info("TODO: createHmac(sha256) the raw body");', "github"),
        (_JS_GITHUB, "throw new Error(`call createHmac( before trusting the body`);", "github"),
        (_JS_GITLAB, "log.debug('TODO: check x-gitlab-token == secret');", "gitlab"),
        (_JS_GITLAB, "log.debug(`x-gitlab-token != secret means reject`);", "gitlab"),
        (_JS_GITLAB, "log.warn('TODO: crypto.timingSafeEqual(token, secret)');", "gitlab"),
    ],
)
def test_js_quoted_verifier_no_longer_clears_the_finding(
    tmp_path: Path, template: str, extra: str, rule: str
) -> None:
    # The FN direction (#1055): a verifier named in a log or error string used to silence a HIGH.
    findings = _run_js(tmp_path, "hook.ts", template.replace("{EXTRA}", extra))
    assert [f.rule for f in findings] == [f"webhook-signature-not-verified/{rule}-unverified"]


@pytest.mark.parametrize(
    ("template", "extra"),
    [
        (_JS_GITHUB, "const h = crypto.createHmac('sha256', process.env.SECRET);"),
        # The real verifier nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        (_JS_GITHUB, "log(`sig ${crypto.createHmac('sha256', key).digest('hex')}`);"),
        # A quoted copy earlier on the line must not hide the real call after it (first-match shadowing).
        (_JS_GITHUB, "log('createHmac( pending'); const h = crypto.createHmac('sha256', key);"),
        (_JS_GITLAB, "if (req.headers['x-gitlab-token'] !== process.env.T) return res.sendStatus(401);"),
        # A quoted `==` after the real compare, inside the same 150-char window: the regex's greedy
        # window would end on the quoted one, so every operator in the window must be tried.
        (_JS_GITLAB, "const t = req.headers['x-gitlab-token']; if (t !== S) return res.sendStatus(401); "
                     "log('a == b');"),
        (_JS_GITLAB, "log(`ok ${req.headers['x-gitlab-token'] === process.env.T}`);"),
    ],
)
def test_js_real_verifier_still_clears_the_finding(tmp_path: Path, template: str, extra: str) -> None:
    assert _run_js(tmp_path, "hook.ts", template.replace("{EXTRA}", extra)) == []


def test_js_svix_verify_spelled_in_a_string_no_longer_clears(tmp_path: Path) -> None:
    # The library credit's ctor and `.verify(` calls are anchored too; the `svix` import specifier is
    # a string literal on purpose and stays readable.
    src = (
        "import { Webhook } from 'svix';\n"
        "const router = require('express').Router();\n"
        "router.post('/webhooks/github', (req, res) => {\n"
        "  const wh = new Webhook(secret);\n"
        "  {EXTRA}\n"
        "});\n"
    )
    findings = _run_js(tmp_path, "hook.ts", src.replace("{EXTRA}", "log('TODO: wh.verify(payload, headers)');"))
    assert [f.rule for f in findings] == ["webhook-signature-not-verified/github-unverified"]
    assert _run_js(tmp_path, "hook.ts", src.replace("{EXTRA}", "wh.verify(req.rawBody, req.headers);")) == []


def test_js_route_spelled_in_a_string_is_not_a_route(tmp_path: Path) -> None:
    # The sink side: only the route call's `(` must be code. The platform name, header and the word
    # "webhook" stay readable inside strings on purpose.
    findings = _run_js(
        tmp_path,
        "docs.ts",
        "const HELP = \"router.post('/webhooks/github', handler) receives the github webhook\";\n"
        "export default HELP;\n",
    )
    assert findings == []


@pytest.mark.parametrize(
    "route",
    [
        "const x = `${router.post('/webhooks/github', (req, res) => res.sendStatus(200))}`;",
        "log('router.post( docs'); router.post('/webhooks/github', (req, res) => res.sendStatus(200));",
    ],
)
def test_js_real_route_in_substitution_or_after_quoted_copy_still_fires(tmp_path: Path, route: str) -> None:
    findings = _run_js(
        tmp_path, "hook.ts", "const router = require('express').Router();\n" + route + "\n"
    )
    assert [f.rule for f in findings] == ["webhook-signature-not-verified/github-unverified"]
    assert findings[0].location.replace("\\", "/").endswith("hook.ts:2")


def test_js_pragma_still_suppresses_a_code_anchored_finding(tmp_path: Path) -> None:
    src = _JS_GITHUB.replace("{EXTRA}", "log.warn('TODO: crypto.timingSafeEqual(a, b) check');")
    assert len(_run_js(tmp_path, "hook.ts", src)) == 1
    assert _run_js(tmp_path, "hook.ts", "// security: allow-unverified-webhook\n" + src) == []
