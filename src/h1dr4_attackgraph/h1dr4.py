from __future__ import annotations

from typing import Any

from .mcp_client import JsonRpcMcpClient


class H1dr4Client:
    def __init__(self, endpoint: str = "https://h1dr4.dev/mcp") -> None:
        self.rpc = JsonRpcMcpClient(endpoint)

    def discover(self, query: str = "", limit: int = 20) -> list[dict[str, Any]]:
        words = {word.casefold() for word in query.split() if word}
        matches: list[dict[str, Any]] = []
        for tool in self.rpc.list_tools():
            haystack = f"{tool.get('name', '')} {tool.get('description', '')}".casefold()
            if words and not all(word in haystack for word in words):
                continue
            matches.append(
                {
                    "name": tool.get("name"),
                    "description": tool.get("description", ""),
                    "input_schema": tool.get("inputSchema", {}),
                }
            )
            if len(matches) >= max(1, min(limit, 50)):
                break
        return matches
