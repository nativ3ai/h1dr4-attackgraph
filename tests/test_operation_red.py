from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from h1dr4_attackgraph.h3retik import H3retikClient
from h1dr4_attackgraph.operation_red import (
    AgentMailReportSender,
    OperationRedCampaignStore,
    OperationRedOrchestrator,
)
from h1dr4_attackgraph.products import OperationRedScope, OperationSchedule
from h1dr4_attackgraph.service import AttackGraphService

WALLET = "0x1111111111111111111111111111111111111111"


def schedule_window() -> OperationSchedule:
    current = datetime.now(UTC)
    return OperationSchedule(
        starts_at=(current - timedelta(hours=1)).isoformat(),
        ends_at=(current + timedelta(hours=1)).isoformat(),
    )


def create_scope(workspace_id: str = "workspace-fixture") -> OperationRedScope:
    return OperationRedScope(
        company_id="company-fixture",
        workspace_id=workspace_id,
        targets=["owned.example.test"],
        modules=["reporting", "web", "verification"],
        schedule=schedule_window(),
        budget_usdc_micros=21_000_000,
    )


class FakeWorkerRpc:
    def __init__(self, *, amount_delta: float = 0.0) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.receipts: dict[str, dict] = {}
        self.workers: dict[str, dict] = {}
        self.jobs: dict[str, str] = {}
        self.amount_delta = amount_delta

    @staticmethod
    def module(arguments: dict) -> str:
        goal = str(arguments.get("goal") or "")
        for module_id in ("web", "verification", "reporting"):
            if f"the {module_id} lane" in goal:
                return module_id
        worker_id = str(arguments.get("worker_id") or "")
        return worker_id.removeprefix("worker-")

    def call_tool(self, name: str, arguments: dict):
        self.calls.append((name, arguments))
        if name == "h3retik_quote_worker":
            inference = float(arguments["inference_budget_usdc"])
            return {
                "quote": {
                    "estimated_usdc": 6.0 + inference,
                    "platform_fee_usdc": 6.0,
                }
            }
        if name == "h3retik_create_worker_receipt":
            module_id = self.module(arguments)
            amount = 6.0 + float(arguments["inference_budget_usdc"])
            receipt = {
                "receipt_id": f"receipt-{module_id}",
                "wallet": arguments["wallet"].lower(),
                "status": "pending",
                "asset": "USDC",
                "chain": "base",
                "amount_usdc": amount,
                "profile": "worker",
                "profile_config": {
                    "plugin_id": "h1dr4-worker-pack",
                    "preset": "redteam",
                    "target": arguments["target"],
                },
            }
            self.receipts[receipt["receipt_id"]] = receipt
            return {"receipt": receipt}
        if name == "h3retik_sync_compute_receipt":
            pending = self.receipts[arguments["receipt_id"]]
            module_id = pending["receipt_id"].removeprefix("receipt-")
            paid = {
                **pending,
                "status": "paid",
                "amount_usdc": pending["amount_usdc"] + self.amount_delta,
                "session_id": f"session-{module_id}",
                "auth": {"wallet": WALLET, "token": f"secret-token-{module_id}"},
                "profile_config": {
                    **pending["profile_config"],
                    "worker_id": f"worker-{module_id}",
                },
            }
            return {"receipt": paid}
        if name == "h3retik_get_worker":
            module_id = self.module(arguments)
            return {
                "worker": {
                    "worker_id": arguments["worker_id"],
                    "session_id": f"session-{module_id}",
                }
            }
        if name == "h3retik_attach_session_to_workspace":
            return {"ok": True, "workspace_id": arguments["workspace_id"]}
        if name == "h3retik_create_worker_job":
            module_id = self.module(arguments)
            job_id = f"job-{module_id}"
            self.jobs[job_id] = module_id
            return {"job_id": job_id}
        if name == "h3retik_start_job":
            return {"status": "running"}
        if name == "h3retik_get_job":
            return {"status": "succeeded"}
        if name == "h3retik_get_job_output":
            module_id = self.jobs[arguments["job_id"]]
            completion = {
                "h3retik_completion": True,
                "status": "completed",
                "summary": f"{module_id} complete",
                "findings": (
                    [
                        {
                            "summary": "Version disclosure observed",
                            "severity": "low",
                            "confidence": 0.7,
                        }
                    ]
                    if module_id == "web"
                    else []
                ),
                "artifacts": (
                    [
                        {
                            "label": "HTTP response metadata",
                            "type": "response",
                            "sensitivity": "internal",
                        }
                    ]
                    if module_id == "web"
                    else []
                ),
                "errors": [],
            }
            worker_result = {
                "ok": True,
                "hermes_output": "worker transcript\n" + json.dumps(completion),
            }
            output = (
                "H3RETIK_WORKER_RESULT_BEGIN\n"
                + json.dumps(worker_result)
                + "\nH3RETIK_WORKER_RESULT_END"
            )
            return {"output": output, "exit_code": 0}
        raise AssertionError(name)


class FakeReportSender:
    def __init__(self) -> None:
        self.messages: list[dict[str, str]] = []

    def send(self, *, to: str, subject: str, text: str) -> str:
        self.messages.append({"to": to, "subject": subject, "text": text})
        return "agentmail:message-fixture"


def create_stack(tmp_path, *, amount_delta: float = 0.0):
    attackgraph = AttackGraphService(
        db_path=tmp_path / "attackgraph.db",
        operator_id="operator-fixture",
    )
    engagement = attackgraph.open_engagement(
        title="Owned target",
        target="owned.example.test",
        mode="autonomous_lab",
        scope="Operation Red fixture",
        target_allowlist=["owned.example.test"],
        allowed_lanes=["web", "verify", "report"],
    )
    store = OperationRedCampaignStore(tmp_path / "operation-red.db")
    rpc = FakeWorkerRpc(amount_delta=amount_delta)
    h3retik = H3retikClient.__new__(H3retikClient)
    h3retik.rpc = rpc
    orchestrator = OperationRedOrchestrator(
        store=store,
        h3retik=h3retik,
        attackgraph=attackgraph,
    )
    return attackgraph, engagement, store, rpc, orchestrator


def prepare_paid_campaign(tmp_path, *, amount_delta: float = 0.0):
    stack = create_stack(tmp_path, amount_delta=amount_delta)
    _, engagement, store, _, orchestrator = stack
    campaign_id = store.create(create_scope(engagement["engagement_id"]))["campaign_id"]
    store.approve(campaign_id, approved_by="owner-passkey")
    orchestrator.prepare_receipts(campaign_id, wallet=WALLET)
    return (*stack, campaign_id)


def test_unverified_funding_is_rejected(tmp_path):
    store = OperationRedCampaignStore(tmp_path / "operation-red.db")
    campaign_id = store.create(create_scope())["campaign_id"]
    store.approve(campaign_id, approved_by="owner-passkey")

    with pytest.raises(ValueError, match="operation_unverified_funding_not_allowed"):
        store.record_funding(
            campaign_id,
            receipt_ref="screenshot-or-user-claim",
            amount_usdc_micros=21_000_000,
        )


def test_campaign_detects_stored_dispatch_plan_tampering(tmp_path):
    database = tmp_path / "operation-red.db"
    store = OperationRedCampaignStore(database)
    campaign_id = store.create(create_scope())["campaign_id"]
    with store._connect() as connection:
        connection.execute(
            "UPDATE operation_red_campaigns SET plan_json='[]' WHERE campaign_id=?",
            (campaign_id,),
        )

    with pytest.raises(ValueError, match="operation_plan_integrity_failure"):
        store.get(campaign_id)


def test_campaign_rejects_mismatched_h3retik_receipt(tmp_path):
    *_, orchestrator, campaign_id = prepare_paid_campaign(tmp_path, amount_delta=0.01)

    with pytest.raises(ValueError, match="operation_receipt_amount_mismatch"):
        orchestrator.sync_funding(campaign_id)


def test_dispatch_rejects_time_outside_approved_window(tmp_path):
    _, _, store, _, orchestrator, campaign_id = prepare_paid_campaign(tmp_path)
    funded = orchestrator.sync_funding(campaign_id)
    assert funded["status"] == "funded"
    store.schedule(campaign_id)
    after_window = datetime.now(UTC) + timedelta(hours=2)

    with pytest.raises(ValueError, match="operation_outside_authorized_window"):
        orchestrator.dispatch(campaign_id, at=after_window, poll_timeout=1)


def test_operation_red_runs_end_to_end_into_sibyl_and_report(tmp_path):
    attackgraph, engagement, store, rpc, orchestrator, campaign_id = prepare_paid_campaign(
        tmp_path
    )
    prepared = store.get(campaign_id)
    assert [item["module_id"] for item in prepared["dispatch_plan"]] == [
        "web",
        "verification",
        "reporting",
    ]
    assert prepared["status"] == "approved"
    assert len(prepared["assignments"]) == 3

    funded = orchestrator.sync_funding(campaign_id)
    assert funded["status"] == "funded"
    assert funded["funded_usdc_micros"] == 21_000_000
    store.schedule(campaign_id)
    verifying = orchestrator.dispatch(campaign_id, poll_timeout=1)

    assert verifying["status"] == "verifying"
    assert {item["job_status"] for item in verifying["assignments"]} == {"succeeded"}
    assert all(item["worker_id"] and item["session_id"] for item in verifying["assignments"])
    graph = attackgraph.context(engagement["engagement_id"])["graph"]
    assert len(graph["actions"]) == 3
    assert all(item["policy"]["decision"] == "campaign_approved" for item in graph["actions"])
    assert any(item["event_type"] == "finding.observed" for item in graph["telemetry"])
    assert any(item["event_type"] == "loot.discovered" for item in graph["telemetry"])
    execution_events = [
        item for item in graph["telemetry"] if item["event_type"] == "execution.completed"
    ]
    assert len(execution_events) == 3
    assert all(item["verified"] for item in execution_events)
    findings = [item for item in graph["telemetry"] if item["event_type"] == "finding.observed"]
    assert all(item["assurance"] == "asserted" for item in findings)

    sender = FakeReportSender()
    reported = orchestrator.deliver_report(
        campaign_id,
        recipient="security@owned.example.test",
        sender=sender,
    )
    assert reported["status"] == "reported"
    assert reported["report_ref"] == "agentmail:message-fixture"
    assert reported["deliveries"][0]["status"] == "sent"
    assert "Scope hash:" in sender.messages[0]["text"]
    assert "secret-token" not in (tmp_path / "operation-red.db").read_bytes().decode(
        "utf-8", errors="ignore"
    )
    assert len([name for name, _ in rpc.calls if name == "h3retik_create_worker_job"]) == 3


def test_agentmail_adapter_uses_official_send_endpoint_without_persisting_key():
    def handler(request):
        assert request.headers["authorization"] == "Bearer agentmail-secret"
        assert json.loads(request.content)["to"] == "security@example.test"
        return __import__("httpx").Response(200, json={"message_id": "msg-1"})

    httpx = __import__("httpx")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        sender = AgentMailReportSender(
            api_key="agentmail-secret",
            inbox_id="inbox-1",
            client=client,
        )
        ref = sender.send(to="security@example.test", subject="Report", text="Evidence")

    assert ref == "agentmail:msg-1"
