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
            "h3retik_create_extension_receipt",
            "h3retik_create_workspace",
            "h3retik_attach_session_to_workspace",
            "h3retik_get_workspace",
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

    def ensure_workspace(
        self,
        *,
        wallet: str,
        token: str,
        workspace_id: str,
        name: str = "",
    ) -> Any:
        return self.rpc.call_tool(
            "h3retik_create_workspace",
            {
                "wallet": wallet,
                "token": token,
                "workspace_id": workspace_id,
                "name": name,
            },
        )

    def attach_session(
        self,
        *,
        wallet: str,
        token: str,
        workspace_id: str,
        session_id: str,
        workspace_name: str = "",
        label: str = "",
        lane: str = "",
    ) -> Any:
        return self.rpc.call_tool(
            "h3retik_attach_session_to_workspace",
            {
                "wallet": wallet,
                "token": token,
                "workspace_id": workspace_id,
                "workspace_name": workspace_name,
                "session_id": session_id,
                "label": label,
                "lane": lane,
            },
        )

    def workspace(self, *, wallet: str, token: str, workspace_id: str) -> Any:
        return self.rpc.call_tool(
            "h3retik_get_workspace",
            {"wallet": wallet, "token": token, "workspace_id": workspace_id},
        )

    def create_extension_receipt(
        self,
        *,
        wallet: str,
        token: str,
        session_id: str,
        minutes: int,
        actions: int,
        asset: str = "USDC",
    ) -> Any:
        return self.rpc.call_tool(
            "h3retik_create_extension_receipt",
            {
                "wallet": wallet,
                "token": token,
                "session_id": session_id,
                "minutes": minutes,
                "actions": actions,
                "asset": asset,
            },
        )

    def sync_receipt(self, receipt_id: str) -> Any:
        return self.rpc.call_tool(
            "h3retik_sync_compute_receipt",
            {"receipt_id": receipt_id},
        )

    def execute_existing_session(
        self,
        *,
        wallet: str,
        token: str,
        session_id: str,
        spec: dict[str, Any],
        workspace_id: str = "",
        workspace_name: str = "",
        session_label: str = "",
        session_lane: str = "",
        poll_timeout: float | None = None,
    ) -> dict[str, Any]:
        if workspace_id:
            self.attach_session(
                wallet=wallet,
                token=token,
                workspace_id=workspace_id,
                workspace_name=workspace_name,
                session_id=session_id,
                label=session_label,
                lane=session_lane,
            )
        if poll_timeout is None:
            poll_timeout = self.default_poll_timeout(spec)
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

    @staticmethod
    def default_poll_timeout(spec: dict[str, Any]) -> float:
        """Include job runtime plus cold provisioning and leased-tool setup."""

        requested_minutes = max(0.0, float(spec.get("max_minutes") or 0))
        return max(300.0, requested_minutes * 60.0 + 300.0)

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
