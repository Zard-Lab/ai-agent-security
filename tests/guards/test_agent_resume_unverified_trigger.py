from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.agent_resume_unverified_trigger import AgentResumeUnverifiedTriggerGuard
from tests.guards._common import *  # noqa: F401,F403


def test_agent_resume_unverified_trigger_fires_on_inbound_email_webhook(tmp_path: Path) -> None:
    (tmp_path / "bridge_dispatch.py").write_text(
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n\n\n"
        '@router.post("/inbound/email-webhook")\n'
        "async def handle_inbound_email(request: Request):\n"
        "    payload = await request.json()\n"
        "    resume_session(\n"
        "        session_id=payload['thread_id'],\n"
        "        prompt=f\"New mail from {payload['from']}: {payload['subject']}\",\n"
        "        permissionMode='bypassPermissions',\n"
        "    )\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].rule == "agent-resume-unverified-trigger/unverified-trigger-elevated-permission"
    assert findings[0].severity == "critical"


def test_agent_resume_unverified_trigger_sender_verified_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "bridge_dispatch.py").write_text(
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n\n\n"
        '@router.post("/inbound/email-webhook")\n'
        "async def handle_inbound_email(request: Request):\n"
        "    payload = await request.json()\n"
        "    if not verify_sender(payload['from']):\n"
        "        return\n"
        "    resume_session(\n"
        "        session_id=payload['thread_id'],\n"
        "        permissionMode='bypassPermissions',\n"
        "    )\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof) == []


def test_agent_resume_unverified_trigger_hmac_verified_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "bridge_dispatch.py").write_text(
        "import hmac\n"
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n\n\n"
        '@router.post("/inbound/webhook")\n'
        "async def handle_inbound_email(request: Request):\n"
        "    sig = request.headers.get('x-signature')\n"
        "    body = await request.body()\n"
        "    expected = hmac.new(SECRET, body, 'sha256').hexdigest()\n"
        "    if not hmac.compare_digest(sig, expected):\n"
        "        return\n"
        "    resume_session(permissionMode='bypassPermissions')\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof) == []


def test_agent_resume_unverified_trigger_no_elevated_permission_stays_silent(tmp_path: Path) -> None:
    # FP-bait: an inbound email webhook that resumes a session in the DEFAULT (non-elevated)
    # permission mode is not this guard's target.
    (tmp_path / "bridge_dispatch.py").write_text(
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n\n\n"
        '@router.post("/inbound/email-webhook")\n'
        "async def handle_inbound_email(request: Request):\n"
        "    payload = await request.json()\n"
        "    resume_session(session_id=payload['thread_id'])\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof) == []


def test_agent_resume_unverified_trigger_no_inbound_trigger_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a route that elevates agent permissions but is NOT an inbound email/webhook
    # trigger -- e.g. an internal admin-only "run with bypass" debug endpoint.
    (tmp_path / "admin.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n\n\n"
        '@router.post("/admin/debug-run")\n'
        "async def debug_run(user=Depends(require_admin)):\n"
        "    resume_session(permissionMode='bypassPermissions')\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof) == []


def test_agent_resume_unverified_trigger_no_route_marker_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a plain helper function, not a route handler at all.
    (tmp_path / "helpers.py").write_text(
        "def build_prompt(payload):\n"
        "    return f\"webhook email from {payload['from']}\"\n"
        "\n"
        "def maybe_resume(payload):\n"
        "    return {'permissionMode': 'bypassPermissions', 'prompt': build_prompt(payload)}\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof) == []


def test_agent_resume_unverified_trigger_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "bridge_dispatch.py").write_text(
        "# security: allow-unverified-agent-resume\n"
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n\n\n"
        '@router.post("/inbound/email-webhook")\n'
        "async def handle_inbound_email(request: Request):\n"
        "    resume_session(permissionMode='bypassPermissions')\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof) == []


def test_agent_resume_unverified_trigger_js_fires(tmp_path: Path) -> None:
    (tmp_path / "bridge.ts").write_text(
        "router.post('/inbound/email-webhook', async (req, res) => {\n"
        "  const payload = req.body;\n"
        "  await resumeSession({\n"
        "    sessionId: payload.threadId,\n"
        "    permissionMode: 'bypassPermissions',\n"
        "  });\n"
        "});\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"typescript"})
    findings = AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof)
    assert any(
        f.rule == "agent-resume-unverified-trigger/unverified-trigger-elevated-permission"
        for f in findings
    )


def test_agent_resume_unverified_trigger_js_verified_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "bridge.ts").write_text(
        "router.post('/inbound/webhook', async (req, res) => {\n"
        "  const sig = req.headers['x-signature'];\n"
        "  const expected = crypto.createHmac('sha256', SECRET).update(req.rawBody).digest('hex');\n"
        "  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return;\n"
        "  await resumeSession({ permissionMode: 'bypassPermissions' });\n"
        "});\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"typescript"})
    assert AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof) == []


def test_agent_resume_unverified_trigger_not_applicable_without_relevant_language() -> None:
    prof = mkprofile(Path("/tmp"), features={"go"})
    assert AgentResumeUnverifiedTriggerGuard().applies(prof) is False


def test_agent_resume_unverified_trigger_dangerously_skip_flag_fires(tmp_path: Path) -> None:
    (tmp_path / "bridge_dispatch.py").write_text(
        "from fastapi import APIRouter, Request\n"
        "import subprocess\n"
        "router = APIRouter()\n\n\n"
        '@router.post("/inbound/email-webhook")\n'
        "async def handle_inbound_email(request: Request):\n"
        "    payload = await request.json()\n"
        "    subprocess.run(['claude', '--dangerously-skip-permissions', '-p', payload['subject']])\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof)
    assert len(findings) == 1


def test_agent_resume_unverified_trigger_checklist_applies_when_matches_the_guard(tmp_path: Path) -> None:
    # PR #742 review, Major 4: the checklist item declared applies_when=["llm"], but the guard's
    # own applies() gate has no `llm` check at all -- it gates on python/javascript/typescript.
    # That mismatch made `agentsec coverage` report the item "na" on a repo where the guard is
    # simultaneously live and can fire -- a coverage report actively contradicting the audit.
    import json
    from pathlib import Path as _Path

    checklist = json.loads(
        (_Path(__file__).resolve().parents[2] / "agentsec" / "checklist" / "checklist.json").read_text(
            encoding="utf-8"
        )
    )
    item = next(i for i in checklist["items"] if i["id"] == "4-agent-resume-trigger-verified")
    applies_when = set(item["applies_when"])
    for features, expected in [
        ({"python"}, True),
        ({"javascript"}, True),
        ({"typescript"}, True),
        ({"go"}, False),
    ]:
        prof = mkprofile(tmp_path, features=features)
        guard_applies = AgentResumeUnverifiedTriggerGuard().applies(prof)
        checklist_says_applies = bool(applies_when & features)
        assert guard_applies is expected, f"guard.applies() disagrees with itself for {features}"
        assert checklist_says_applies is guard_applies, (
            f"checklist applies_when={sorted(applies_when)} disagrees with the guard's own "
            f"applies() for features={features}"
        )


# --- #1055: a JS/TS credit or route marker counts only when it is live code ------------------------

_JS_HANDLER = (
    "const router = require('express').Router();\n"
    "router.post('/inbound/email-webhook', async (req, res) => {\n"
    "  {EXTRA}\n"
    "  await resume({ prompt: req.body.subject, permissionMode: 'bypassPermissions' });\n"
    "});\n"
)


def _run_js_handler(tmp_path: Path, extra: str) -> list[Finding]:
    (tmp_path / "bridge.js").write_text(_JS_HANDLER.replace("{EXTRA}", extra), encoding="utf-8")
    prof = mkprofile(tmp_path, features={"javascript"})
    return AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof)


@pytest.mark.parametrize(
    "extra",
    [
        "log.info('TODO: crypto.createHmac(sha256) check');",
        'log.warn("verify: sender in allowlist before resuming");',
        "throw new Error(`call crypto.timingSafeEqual(a, b) first`);",
    ],
)
def test_agent_resume_js_quoted_verifier_no_longer_clears_the_finding(tmp_path: Path, extra: str) -> None:
    # The FN direction (#1055): a verifier named in a log or error string used to silence a CRITICAL.
    findings = _run_js_handler(tmp_path, extra)
    assert [f.severity for f in findings] == ["critical"]


@pytest.mark.parametrize(
    "extra",
    [
        "const sig = crypto.createHmac('sha256', key).update(req.rawBody).digest('hex');",
        # The real verifier nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        "log(`sig ${crypto.createHmac('sha256', key).digest('hex')}`);",
        # A quoted copy earlier on the line must not hide the real call after it (first-match shadowing).
        "log('createHmac( pending'); const sig = crypto.createHmac('sha256', key);",
        # The allowlist branch of the credit (PR #1126 round-1 L2: only its quoted form was tested).
        "if (!verify_sender(req.body.from)) return res.sendStatus(403);",
    ],
)
def test_agent_resume_js_real_verifier_still_clears_the_finding(tmp_path: Path, extra: str) -> None:
    assert _run_js_handler(tmp_path, extra) == []


def test_agent_resume_js_route_spelled_in_a_string_is_not_a_route(tmp_path: Path) -> None:
    # The sink side: only the route call's `(` must be code. The inbound word and the
    # `'bypassPermissions'` value are string content on purpose, and stay readable.
    (tmp_path / "docs.js").write_text(
        "const HELP = \"wire router.post('/inbound/email-webhook', handler) to receive mail\";\n"
        "const opts = { permissionMode: 'bypassPermissions' };\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"javascript"})
    assert AgentResumeUnverifiedTriggerGuard().run(tmp_path, prof) == []


def test_agent_resume_js_pragma_still_suppresses(tmp_path: Path) -> None:
    findings = _run_js_handler(tmp_path, "// security: allow-unverified-agent-resume")
    assert findings == []
