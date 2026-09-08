from __future__ import annotations

from h1dr4_attackgraph.h3retik import H3retikClient


class FakeRpc:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, name: str, arguments: dict):
        self.calls.append((name, arguments))
        if name == "h3retik_create_session_job":
            return {"job_id": "job-1"}
        if name == "h3retik_get_worker":
            return {"worker": {"worker_id": "worker-1", "session_id": "session-worker"}}
        if name == "h3retik_create_worker_job":
            return {"job_id": "job-worker"}
        if name == "h3retik_attach_session_to_workspace":
            return {
                "workspace_id": arguments["workspace_id"],
                "session_id": arguments["session_id"],
            }
        if name == "h3retik_start_job":
            return {"status": "succeeded"}
        if name == "h3retik_get_job":
            return {"status": "succeeded"}
        if name == "h3retik_get_job_output":
            return {"output": "ok", "exit_code": 0}
        raise AssertionError(name)


def test_execution_timeout_includes_action_budget_and_provisioning_headroom():
    client = H3retikClient.__new__(H3retikClient)
    client.rpc = FakeRpc()

    result = client.execute_existing_session(
        wallet="0xabc",
        token="token",
        session_id="session-1",
        spec={"max_minutes": 3, "args": {"cmd": "true"}},
    )

    assert result["job_id"] == "job-1"
    assert [name for name, _ in client.rpc.calls] == [
        "h3retik_create_session_job",
        "h3retik_start_job",
        "h3retik_get_job",
        "h3retik_get_job_output",
    ]
    assert client.default_poll_timeout({"max_minutes": 3}) == 480.0
    assert client.default_poll_timeout({"max_minutes": 0}) == 300.0


def test_execution_attaches_session_to_durable_workspace_first():
    client = H3retikClient.__new__(H3retikClient)
    client.rpc = FakeRpc()

    client.execute_existing_session(
        wallet="0xabc",
        token="token",
        session_id="session-1",
        workspace_id="eng-1",
        workspace_name="Owned lab",
        session_label="Web worker",
        session_lane="web",
        spec={"max_minutes": 1, "args": {"cmd": "true"}},
    )

    name, arguments = client.rpc.calls[0]
    assert name == "h3retik_attach_session_to_workspace"
    assert arguments["workspace_id"] == "eng-1"
    assert arguments["session_id"] == "session-1"
    assert arguments["lane"] == "web"


def test_worker_execution_uses_paid_worker_session_and_durable_workspace():
    client = H3retikClient.__new__(H3retikClient)
    client.rpc = FakeRpc()

    result = client.execute_worker(
        wallet="0xabc",
        token="ephemeral-token",
        worker_id="worker-1",
        target="owned.example.test",
        workspace_id="eng-1",
        workspace_name="Operation Red",
        session_lane="web",
        max_minutes=2,
        poll_timeout=1,
    )

    assert result["job_id"] == "job-worker"
    assert result["session_id"] == "session-worker"
    assert [name for name, _ in client.rpc.calls] == [
        "h3retik_get_worker",
        "h3retik_attach_session_to_workspace",
        "h3retik_create_worker_job",
        "h3retik_start_job",
        "h3retik_get_job",
        "h3retik_get_job_output",
    ]
    create_call = client.rpc.calls[2][1]
    assert create_call["worker_id"] == "worker-1"
    assert create_call["max_minutes"] == 2
