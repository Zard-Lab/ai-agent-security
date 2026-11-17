#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "fastapi>=0.115",
#     "uvicorn>=0.30",
#     "httpx>=0.27",
# ]
# ///
"""Generic localhost adapter so garak / promptfoo can red-team a non-trivial target.

The red-team tools assume the target is a bare "prompt in, text out" HTTP endpoint.
Real agents are not: they need auth, a structured request body, dedup/session ids,
and often stream the answer. This shim is the translation layer. Point the tool at
the shim (e.g. http://127.0.0.1:8788/redteam) and configure the shim, via the env
vars below, to call YOUR endpoint. The actual agent responses never leave your host.

  garak / promptfoo  --(prompt -> text)-->  redteam-shim  --(your contract)-->  your agent

Configuration (all via env vars — no code edit needed for common cases):

  SHIM_TARGET_URL   (required)  the real endpoint to call, e.g. https://.../api/agent
  SHIM_PORT         (8788)      port this adapter listens on
  SHIM_METHOD       (POST)      HTTP method for the upstream call
  SHIM_TIMEOUT      (120)       upstream per-request timeout (seconds)

  SHIM_HEADERS      ('')        JSON object of upstream headers; values may reference
                               ${ENV_VAR}, e.g. '{"Authorization":"Bearer ${SHIM_TOKEN}"}'
                               (Content-Type defaults to application/json when SHIM_BODY is set)

  SHIM_BODY         ('')        JSON request-body TEMPLATE with placeholders:
                                 {{prompt}} -> the attack prompt (JSON-string-escaped)
                                 {{uuid}}   -> a fresh uuid4 (each occurrence is distinct;
                                               use for request_id / session_id / dedup keys)
                                 ${ENV_VAR} -> an env value (e.g. a fixed user id)
                               If empty, the raw prompt is sent as the request body
                               (garak's bare default).

  SHIM_RESPONSE     (raw)       how to extract the reply from the upstream response:
                                 raw                      -> the whole response body
                                 json:<dot.path>          -> a field of a JSON body,
                                                             e.g. json:choices.0.message.content
                                 ndjson:<field>           -> <field> of the last NDJSON line
                                 ndjson-complete:<field>  -> <field> of the last NDJSON line
                                                             whose "complete" is truthy
                                                             (streaming agents)

Examples
--------
OpenAI-style chat completion:
  SHIM_TARGET_URL=https://api.example.com/v1/chat/completions
  SHIM_HEADERS='{"Authorization":"Bearer ${SHIM_TOKEN}"}'
  SHIM_BODY='{"model":"x","messages":[{"role":"user","content":"{{prompt}}"}]}'
  SHIM_RESPONSE=json:choices.0.message.content

Streaming agent with auth + dedup id + session id:
  SHIM_TARGET_URL=http://127.0.0.1:8001/api/agent
  SHIM_HEADERS='{"Authorization":"Bearer ${SHIM_TOKEN}"}'
  SHIM_BODY='{"query":"{{prompt}}","user_id":"${SHIM_USER_ID}","request_id":"{{uuid}}","session_id":"{{uuid}}"}'
  SHIM_RESPONSE=ndjson-complete:text

For exotic id formats your template can't express (e.g. "{uuid}~{10}"), edit
`_gen_value` below — it's the single hook for placeholder generation.

DEV ONLY — relays real attack prompts. Point it at an owned, non-production target.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

TARGET_URL = os.environ.get("SHIM_TARGET_URL", "")
PORT = int(os.environ.get("SHIM_PORT", "8788"))
METHOD = os.environ.get("SHIM_METHOD", "POST").upper()
TIMEOUT = float(os.environ.get("SHIM_TIMEOUT", "120"))
HEADERS_TEMPLATE = os.environ.get("SHIM_HEADERS", "")
BODY_TEMPLATE = os.environ.get("SHIM_BODY", "")
RESPONSE_SPEC = os.environ.get("SHIM_RESPONSE", "raw")

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _interpolate_env(text: str) -> str:
    """Replace ${VAR} with os.environ[VAR] (missing -> empty string)."""
    return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), ""), text)


def _gen_value(placeholder: str) -> str:
    """Generate a value for a `{{...}}` placeholder. Edit here for custom formats."""
    if placeholder == "uuid":
        return str(uuid.uuid4())
    raise ValueError(f"unknown placeholder {{{{{placeholder}}}}}")


def build_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    if HEADERS_TEMPLATE:
        parsed = json.loads(_interpolate_env(HEADERS_TEMPLATE))
        headers = {str(k): str(v) for k, v in parsed.items()}
    if BODY_TEMPLATE and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"
    return headers


def build_body(prompt: str, template: str | None = None) -> tuple[Any | None, str | None]:
    """Render the body template for `prompt`. Returns (json_obj, raw_text):
    exactly one is non-None. Empty template -> raw prompt body (garak default)."""
    tmpl = BODY_TEMPLATE if template is None else template
    if not tmpl:
        return None, prompt
    rendered = _interpolate_env(tmpl)
    # Each {{placeholder}} occurrence gets a freshly generated value (distinct uuids).
    rendered = re.sub(r"\{\{(\w+)\}\}",
                      lambda m: "\x00PROMPT\x00" if m.group(1) == "prompt" else _gen_value(m.group(1)),
                      rendered)
    # Substitute the JSON-escaped prompt last so generated values can't collide with it.
    rendered = rendered.replace("\x00PROMPT\x00", json.dumps(prompt)[1:-1])
    return json.loads(rendered), None


def _dig(obj: Any, dotpath: str) -> str:
    cur = obj
    for part in dotpath.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return ""
    return "" if cur is None else str(cur)


def extract_reply(body: str, spec: str = RESPONSE_SPEC) -> str:
    """Pull the model's answer out of the upstream response per `spec`."""
    if spec == "raw":
        return body
    if spec.startswith("json:"):
        try:
            return _dig(json.loads(body), spec[len("json:"):])
        except (json.JSONDecodeError, IndexError, ValueError):
            return ""
    if spec.startswith("ndjson:") or spec.startswith("ndjson-complete:"):
        complete_only = spec.startswith("ndjson-complete:")
        field = spec.split(":", 1)[1]
        final = ""
        last = ""
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                chunk = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(chunk, dict):
                continue
            if isinstance(chunk.get(field), str):
                last = chunk[field]
            if complete_only and chunk.get("complete"):
                final = (chunk.get(field) if isinstance(chunk.get(field), str) else None) \
                    or (chunk.get("error") if isinstance(chunk.get("error"), str) else None) or last
        return (final or last) if complete_only else last
    return body  # unknown spec -> raw


app = FastAPI(title="redteam-shim", docs_url=None, redoc_url=None)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "target": TARGET_URL, "response": RESPONSE_SPEC}


async def _read_prompt(request: Request) -> str:
    """garak sends the raw prompt as the body; promptfoo sends JSON {"prompt": ...}."""
    raw = (await request.body()).decode("utf-8", "replace").strip()
    if raw and raw[0] in "{[":
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                for key in ("prompt", "text", "query", "input"):
                    if isinstance(obj.get(key), str):
                        return obj[key]
        except json.JSONDecodeError:
            pass
    return raw


@app.post("/redteam")
@app.post("/")
# security: allow-unauthenticated-route — this shim binds to localhost only (see
# SHIM_PORT above) and forwards to TARGET_URL for local red-team runs; it is never
# meant to be reachable from outside the host it runs on.
async def redteam(request: Request) -> PlainTextResponse:
    prompt = await _read_prompt(request)
    json_body, raw_body = build_body(prompt)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.request(
                METHOD, TARGET_URL, headers=build_headers(),
                json=json_body if json_body is not None else None,
                content=raw_body if raw_body is not None else None,
            )
    except httpx.HTTPError as exc:
        return PlainTextResponse(f"[shim-error] {exc}", status_code=502)
    return PlainTextResponse(extract_reply(resp.text))


if __name__ == "__main__":
    if not TARGET_URL:
        raise SystemExit("error: SHIM_TARGET_URL must be set")
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
