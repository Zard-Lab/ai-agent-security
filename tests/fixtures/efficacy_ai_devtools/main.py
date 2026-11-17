"""Tiny FastAPI + pydantic-ai agent shell.

Efficacy-corpus fixture only — never installed or run; agentsec parses this file as text.
"""
from fastapi import FastAPI
from pydantic_ai import Agent

app = FastAPI()
agent = Agent("openai:gpt-4o-mini", system_prompt="You are a helpful assistant.")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
