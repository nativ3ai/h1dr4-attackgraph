from __future__ import annotations

import time
from typing import Any

from .mcp_client import JsonRpcMcpClient


class H3retikClient:
    def __init__(self, endpoint: str = "https://h1dr4.dev/h3retik/api/mcp") -> None:
        self.rpc = JsonRpcMcpClient(endpoint, timeout=60.0)

    def capabilities(self) -> dict[str, Any]:
        tools = self.rpc.list_tools()
        wanted = {
            "h3retik_quote_compute_window",
            "h3retik_create_session_job",
            "h3retik_start_job",
            "h3retik_get_job",
            "h3retik_get_job_output",
        }
        return {
            "endpoint": self.rpc.endpoint,
            "available": sorted(tool["name"] for tool in tools if tool.get("name") in wanted),
            "tool_count": len(tools),
        }

    def quote(self, *, minutes: int, actions: int, location: str = "auto") -> Any:
        return self.rpc.call_tool(
            "h3retik_quote_compute_window",
            {"minutes": minutes, "actions": actions, "location": location},
        )

    def execute_existing_session(
        self,
        *,
        wallet: str,
        token: str,
        session_id: str,
        spec: dict[str, Any],
        poll_timeout: float = 120.0,
    ) -> dict[str, Any]:
        created = self.rpc.call_tool(
            "h3retik_create_session_job",
            {"wallet": wallet, "token": token, "session_id": session_id, "spec": spec},
        )
        job_id = self._find_value(created, "job_id")
        if not job_id:
            raise RuntimeError(f"H3RETIK did not return a job_id: {created!r}")
        started = self.rpc.call_tool(
            "h3retik_start_job",
            {"wallet": wallet, "token": token, "session_id": session_id, "job_id": job_id},
        )
        deadline = time.monotonic() + poll_timeout
        last_status: Any = started
        while time.monotonic() < deadline:
            last_status = self.rpc.call_tool(
                "h3retik_get_job",
                {"wallet": wallet, "token": token, "job_id": job_id},
            )
            status = str(self._find_value(last_status, "status") or "").casefold()
            if status in {"succeeded", "completed", "failed", "cancelled", "expired"}:
                break
            time.sleep(2)
        else:
            raise TimeoutError(f"H3RETIK job {job_id} did not finish in {poll_timeout}s")
        output = self.rpc.call_tool(
            "h3retik_get_job_output",
            {"wallet": wallet, "token": token, "job_id": job_id},
        )
        return {"job_id": job_id, "status": last_status, "output": output}

    @classmethod
    def _find_value(cls, value: Any, key: str) -> Any:
        if isinstance(value, dict):
            if key in value:
                return value[key]
            for child in value.values():
                found = cls._find_value(child, key)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = cls._find_value(child, key)
                if found is not None:
                    return found
        return None
