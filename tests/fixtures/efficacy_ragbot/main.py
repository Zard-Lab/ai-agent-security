"""RAG chatbot backend — PDF-chat assistant."""
import json
import os
import pickle

import langchain_core.load
from fastapi import FastAPI
from langchain_core.prompts import PromptTemplate
from pydantic_ai import Agent

app = FastAPI()
agent = Agent("openai:gpt-4o-mini", system_prompt="You are a document assistant.")
prompt_template = PromptTemplate.from_template("Answer based on: {context}")


async def summarize_document(prompt: str) -> str:
    # Mistake: the LLM's own output is used directly as a file path.
    result = await agent.run_sync(prompt)
    with open(result.content) as f:
        return f.read()


async def render_template() -> str:
    # Safe: a fixed, literal template path, never derived from the LLM.
    with open("templates/index.html") as f:
        return f.read()


def convert_upload(filename: str) -> None:
    # Mistake: the shell command is built from untrusted input.
    os.system(f"convert {filename} {filename}.png")


def list_uploads() -> None:
    # Safe: a static command with no interpolation.
    os.system("ls -la")


def restore_session(blob: bytes) -> object:
    # Mistake: arbitrary code execution as a side effect of deserializing.
    return pickle.loads(blob)


def restore_session_safe(blob: bytes) -> object:
    # Safe: JSON never executes code.
    return json.loads(blob)


def import_chain_config(raw_json: str) -> object:
    # Mistake: deserializes an attacker-reachable chain config.
    return langchain_core.load.loads(raw_json)


def render_prompt(context: str) -> str:
    # Safe: ordinary LangChain template use, no deserialization.
    return prompt_template.format(context=context)
