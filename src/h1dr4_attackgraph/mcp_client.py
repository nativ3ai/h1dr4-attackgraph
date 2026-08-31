from __future__ import annotations

import json
from typing import Any

import httpx


class McpRpcError(RuntimeError):
    pass


class JsonRpcMcpClient:
    def __init__(self, endpoint: str, *, timeout: float = 30.0) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params is not None:
            payload["params"] = params
        headers = {"Accept": "application/json, text/event-stream"}
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(self.endpoint, json=payload, headers=headers)
        response.raise_for_status()
        envelope = self._decode(response)
        if "error" in envelope:
            raise McpRpcError(str(envelope["error"]))
        return envelope.get("result")

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.request("tools/list") or {}
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        result = self.request("tools/call", {"name": name, "arguments": arguments}) or {}
        if result.get("isError"):
            raise McpRpcError(self._content_text(result.get("content", [])))
        text = self._content_text(result.get("content", []))
        if not text:
            return result.get("structuredContent", result)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"text": text}

    @staticmethod
    def _decode(response: httpx.Response) -> dict[str, Any]:
        if "text/event-stream" not in response.headers.get("content-type", ""):
            return response.json()
        for line in response.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line.removeprefix("data:").strip())
        raise McpRpcError("MCP endpoint returned an empty event stream")

    @staticmethod
    def _content_text(content: list[dict[str, Any]]) -> str:
        return "\n".join(item.get("text", "") for item in content if item.get("type") == "text")
