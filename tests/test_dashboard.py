from __future__ import annotations

import httpx

from h1dr4_attackgraph.dashboard import build_dashboard_snapshot, create_dashboard_app
from h1dr4_attackgraph.service import AttackGraphService


class OfflineClient:
    def discover(self, **kwargs):
        return []

    def capabilities(self):
        return {}


def dashboard_service(tmp_path):
    client = OfflineClient()
    return AttackGraphService(
        db_path=tmp_path / "sibyl.db",
        operator_id="dashboard-test",
        h1dr4=client,
        h3retik=client,
    )


def populated_service(tmp_path):
    service = dashboard_service(tmp_path)
    engagement = service.open_engagement(
        title="Dashboard demo",
        target="demo.internal",
        mode="autonomous_lab",
        scope="Owned fixture only",
        target_allowlist=["demo.internal"],
        allowed_lanes=["web"],
    )
    engagement_id = engagement["engagement_id"]
    service.record_observation(
        engagement_id,
        statement="HTTPS surface reachable",
        source="fixture",
        confidence=0.95,
    )
    service.record_hypothesis(engagement_id, statement="Auth boundary exposes metadata")
    service.record_attempt(
        engagement_id,
        approach="Probe removed API",
        outcome="404",
        exhausted=True,
    )
    service.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="curl -I https://demo.internal",
        purpose="Compare security headers",
    )
    service.create_regression(
        engagement_id,
        name="Header baseline",
        check="curl -I https://demo.internal",
        expected="Security headers remain present",
    )
    return service, engagement_id


def test_dashboard_snapshot_maps_sibyl_state_to_operational_graph(tmp_path):
    service, engagement_id = populated_service(tmp_path)

    snapshot = build_dashboard_snapshot(service, engagement_id)

    assert snapshot["engagement"]["target"] == "demo.internal"
    assert snapshot["stats"] == {"nodes": 5, "evidence": 1, "pending": 1}
    assert {node["kind"] for node in snapshot["nodes"]} == {
        "target",
        "confirmed",
        "hypothesis",
        "action",
        "regression",
    }
    assert snapshot["primary_action"]["status"] == "human_required"
    assert snapshot["memory"]["online"] is True


async def test_dashboard_api_lists_and_reads_engagements(tmp_path):
    service, engagement_id = populated_service(tmp_path)
    transport = httpx.ASGITransport(app=create_dashboard_app(service))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        listed = await client.get("/api/engagements")
        detail = await client.get(f"/api/engagements/{engagement_id}")
        missing = await client.get("/api/engagements/eng-missing")

    assert listed.status_code == 200
    assert listed.json()["engagements"][0]["engagement_id"] == engagement_id
    assert detail.status_code == 200
    assert detail.json()["brief"]["exhausted_paths"][0]["approach"] == "Probe removed API"
    assert missing.status_code == 404
