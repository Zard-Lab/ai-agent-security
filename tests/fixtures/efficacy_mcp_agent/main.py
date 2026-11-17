"""Agent that connects to external MCP tool servers."""
from mcp import ClientSession
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o-mini", system_prompt="You are a tool-using assistant.")


async def connect_to_tool_server(url: str):
    async with ClientSession(url) as session:
        tools = await session.list_tools()
        return tools
