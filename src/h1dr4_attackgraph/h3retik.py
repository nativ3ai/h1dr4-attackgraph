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
            "h3retik_quote_worker",
            "h3retik_create_worker_receipt",
            "h3retik_get_worker",
            "h3retik_create_worker_job",
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

    def quote_worker(
        self,
        *,
        goal: str,
        target: str,
        package: str = "micro",
        location: str = "auto",
        inference_budget_usdc: float = 1.0,
        model_mode: str = "manual",
        model: str = "",
        routing_profile: str = "premium",
        hermes_toolsets: list[str] | None = None,
    ) -> Any:
        arguments: dict[str, Any] = {
            "plugin_id": "h1dr4-worker-pack",
            "preset": "redteam",
            "package": package,
            "goal": goal,
            "target": target,
            "location": location,
            "inference_budget_usdc": inference_budget_usdc,
            "model_mode": model_mode,
            "routing_profile": routing_profile,
            "hermes_toolsets": hermes_toolsets or ["terminal", "file"],
        }
        if model:
            arguments["model"] = model
        return self.rpc.call_tool("h3retik_quote_worker", arguments)

    def create_worker_receipt(
        self,
        *,
        wallet: str,
        goal: str,
        target: str,
        package: str = "micro",
        location: str = "auto",
        asset: str = "USDC",
        inference_budget_usdc: float = 1.0,
        model_mode: str = "manual",
        model: str = "",
        routing_profile: str = "premium",
        hermes_toolsets: list[str] | None = None,
        lane: str = "",
        constraints: list[str] | None = None,
    ) -> Any:
        arguments: dict[str, Any] = {
            "wallet": wallet,
            "plugin_id": "h1dr4-worker-pack",
            "preset": "redteam",
            "package": package,
            "goal": goal,
            "target": target,
            "location": location,
            "asset": asset,
            "inference_budget_usdc": inference_budget_usdc,
            "model_mode": model_mode,
            "routing_profile": routing_profile,
            "hermes_toolsets": hermes_toolsets or ["terminal", "file"],
            "constraints": list(constraints or []),
        }
        if model:
            arguments["model"] = model
        if lane:
            arguments["lane"] = lane
        return self.rpc.call_tool("h3retik_create_worker_receipt", arguments)

    def get_worker(self, *, wallet: str, token: str, worker_id: str) -> Any:
        return self.rpc.call_tool(
            "h3retik_get_worker",
            {"wallet": wallet, "token": token, "worker_id": worker_id},
        )

    def execute_worker(
        self,
        *,
        wallet: str,
        token: str,
        worker_id: str,
        target: str,
        workspace_id: str,
        workspace_name: str = "",
        session_label: str = "Operation Red worker",
        session_lane: str = "",
        max_minutes: int = 30,
        job_id: str = "",
        command: str = "",
        poll_timeout: float | None = None,
    ) -> dict[str, Any]:
        worker = self.get_worker(wallet=wallet, token=token, worker_id=worker_id)
        session_id = str(self._find_value(worker, "session_id") or "")
        if not session_id:
            raise RuntimeError(f"H3RETIK worker did not return a session_id: {worker!r}")
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
        create_args: dict[str, Any] = {
            "wallet": wallet,
            "token": token,
            "worker_id": worker_id,
            "target": target,
            "max_minutes": max_minutes,
        }
        if job_id:
            create_args["job_id"] = job_id
        if command:
            create_args["cmd"] = command
        created = self.rpc.call_tool("h3retik_create_worker_job", create_args)
        created_job_id = str(self._find_value(created, "job_id") or "")
        if not created_job_id:
            raise RuntimeError(f"H3RETIK did not return a worker job_id: {created!r}")
        if poll_timeout is None:
            poll_timeout = self.default_poll_timeout({"max_minutes": max_minutes})
        status, output = self._start_and_poll(
            wallet=wallet,
            token=token,
            session_id=session_id,
            job_id=created_job_id,
            poll_timeout=poll_timeout,
        )
        return {
            "worker_id": worker_id,
            "session_id": session_id,
            "job_id": created_job_id,
            "status": status,
            "output": output,
        }

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
        last_status, output = self._start_and_poll(
            wallet=wallet,
            token=token,
            session_id=session_id,
            job_id=str(job_id),
            poll_timeout=poll_timeout,
        )
        return {"job_id": job_id, "status": last_status, "output": output}

    def _start_and_poll(
        self,
        *,
        wallet: str,
        token: str,
        session_id: str,
        job_id: str,
        poll_timeout: float,
    ) -> tuple[Any, Any]:
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
        return last_status, output

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
