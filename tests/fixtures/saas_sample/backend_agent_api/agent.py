from fastapi import FastAPI
from pydantic_ai import Agent
from supabase import create_client
import httpx

# system prompt defined, but no output leak filter anywhere (§4 violation)
agent = Agent("openai:gpt-4o", system_prompt="You are a SaaS support agent. Follow the rules.")

def handle(user_message):
    # raw user input goes straight to the model, unwrapped and unfenced (§3b violation)
    return agent.run_sync(user_message)

def retrieve_documents(q):
    # untrusted content reaches the model; no sanitization/wrapping anywhere
    return get_document(q)

def call_out(url):
    return httpx.post(url)
