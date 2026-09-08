from __future__ import annotations

import httpx

from h1dr4_attackgraph.dashboard import build_dashboard_snapshot, create_dashboard_app
from h1dr4_attackgraph.identity import IdentityStore
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
        evidence={"headers": {"server": "fixture"}, "credential_class": "none"},
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
    assert snapshot["stats"] == {
        "nodes": 2,
        "evidence": 1,
        "pending": 1,
        "loot": 0,
        "telemetry": 0,
        "relationships": 0,
    }
    assert {node["kind"] for node in snapshot["nodes"]} == {"target", "confirmed"}
    assert snapshot["primary_action"]["status"] == "human_required"
    assert snapshot["posture"]["state"] == "surface_mapped"
    assert snapshot["posture"]["derived"] is True
    assert snapshot["posture"]["evidence_ids"] == [snapshot["brief"]["confirmed"][0]["id"]]
    assert snapshot["memory"]["online"] is True
    assert snapshot["events"][0]["type"] == "regression_created"
    assert snapshot["memory"]["last_event"] == snapshot["events"][0]["time"]
    assert snapshot["loot"] == []
    assert "evidence" not in snapshot["brief"]["confirmed"][0]
    confirmed_node = next(node for node in snapshot["nodes"] if node["kind"] == "confirmed")
    assert confirmed_node["detail"]["record"]["telemetry_sealed"] is True


def test_posture_is_derived_from_loot_and_requires_verified_proof_for_high_states(tmp_path):
    service, engagement_id = populated_service(tmp_path)
    service.record_observation(
        engagement_id,
        statement="Scoped credential recovered",
        source="h3retik:job-loot",
        confidence=1.0,
        kind="execution_evidence",
        evidence={"credentials": {"username": "fixture", "password": "fixture-only"}},
    )
    service.record_observation(
        engagement_id,
        statement="Unverified foothold claim",
        source="agent-claim",
        confidence=1.0,
        evidence={"posture": {"signal": "foothold_active", "verified": False, "proof": "none"}},
    )

    loot_snapshot = build_dashboard_snapshot(service, engagement_id)

    assert loot_snapshot["posture"]["state"] == "access_material_acquired"
    assert loot_snapshot["posture"]["display_label"] == "LOOT SECURED"

    action = service.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="fixture-proof",
        purpose="Verify the owned target objective",
    )
    service.ingest_h3retik_telemetry(
        engagement_id,
        event_type="finding.confirmed",
        summary="Reproducible shell established",
        target="demo.internal",
        outcome="success",
        technique="fixture-proof",
        h3retik_session_id="session-fixture",
        job_id="job-shell",
        command_id="shell-check-42",
        status="completed",
        exit_code=0,
        action_id=action["id"],
        attributes={"posture_signal": "target_compromised"},
        trusted_internal=True,
    )

    compromised_snapshot = build_dashboard_snapshot(service, engagement_id)

    assert compromised_snapshot["posture"]["state"] == "target_compromised"
    assert compromised_snapshot["posture"]["display_label"] == "PWNED"
    assert (
        compromised_snapshot["posture"]["reasons"][0]["record_id"]
        in compromised_snapshot["posture"]["evidence_ids"]
    )


def test_dashboard_uses_typed_observation_kind_as_feed_title(tmp_path):
    service, engagement_id = populated_service(tmp_path)
    service.record_observation(
        engagement_id,
        statement="Telemetry audit passed",
        source="fixture",
        confidence=1.0,
        kind="telemetry_redaction_attestation",
    )

    snapshot = build_dashboard_snapshot(service, engagement_id)

    assert snapshot["events"][0]["title"] == "Telemetry Redaction Attestation"


def test_dashboard_hides_transport_records_from_loot_and_resolves_legacy_action_title(
    tmp_path,
):
    service, engagement_id = populated_service(tmp_path)
    action = service.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="fixture-check",
        purpose="Verify the administrative boundary",
    )
    service.record_observation(
        engagement_id,
        statement=f"Imported H3RETIK result for action {action['id']}",
        source="h3retik:job-fixture",
        confidence=1.0,
        kind="execution_evidence",
        evidence={"status": "completed"},
    )

    snapshot = build_dashboard_snapshot(service, engagement_id)

    assert snapshot["events"][0]["title"] == "Verify the administrative boundary"
    assert snapshot["events"][0]["detail"] == (
        "Execution completed · H3RETIK proof retained"
    )
    assert snapshot["loot"] == []


def test_dashboard_streams_normalized_telemetry_with_worker_session_and_room(tmp_path):
    service, engagement_id = populated_service(tmp_path)
    action = service.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="fixture-check",
        purpose="Verify fixture",
        h3retik_session_id="",
    )
    service.ingest_h3retik_telemetry(
        engagement_id,
        event_type="finding.confirmed",
        summary="Fixture vulnerability confirmed",
        target="demo.internal",
        outcome="success",
        technique="fixture-technique",
        h3retik_session_id="session-fixture",
        job_id="job-fixture",
        command_id="cli-fixture",
        status="completed",
        exit_code=0,
        action_id=action["id"],
        evidence={"status": 200, "authorization": "Bearer secret"},
        idempotency_key="finding:fixture",
        trusted_internal=True,
    )

    snapshot = build_dashboard_snapshot(service, engagement_id)

    event = snapshot["events"][0]
    node = next(node for node in snapshot["nodes"] if node["id"] == event["object_id"])
    assert event["title"] == "Fixture vulnerability confirmed"
    assert event["detail"] == "Finding confirmed · SUCCESS"
    assert event["h3retik_session_id"] == "session-fixture"
    assert event["job_id"] == "job-fixture"
    assert node["h3retik_session_id"] == "session-fixture"
    assert node["detail"]["findings"][0]["title"] == "Fixture vulnerability confirmed"
    assert snapshot["stats"]["telemetry"] == 1
    assert snapshot["stats"]["relationships"] >= 4


def test_dashboard_projects_entities_as_rooms_and_attaches_findings_loot_and_links(tmp_path):
    service, engagement_id = populated_service(tmp_path)
    action = service.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="fixture-map",
        purpose="Map application boundary",
    )
    finding = service.ingest_h3retik_telemetry(
        engagement_id,
        event_type="finding.confirmed",
        summary="Administrative endpoint bypass confirmed",
        outcome="success",
        technique="authorization-testing",
        h3retik_session_id="session-map",
        job_id="job-map",
        command_id="command-map",
        status="completed",
        exit_code=0,
        action_id=action["id"],
        entities=[
            {
                "id": "backend",
                "type": "asset",
                "label": "Backend service",
                "layer": "application",
            },
            {
                "id": "admin-api",
                "type": "endpoint",
                "label": "/api/admin",
                "layer": "application",
                "parent_id": "backend",
            },
        ],
        relationships=[
            {"from": "backend", "to": "admin-api", "type": "exposes"},
            {"from": "event", "to": "admin-api", "type": "observed_on"},
        ],
        evidence={"http_status": 200},
        idempotency_key="finding:admin-api",
        trusted_internal=True,
    )
    service.ingest_h3retik_telemetry(
        engagement_id,
        event_type="loot.discovered",
        summary="Administrator response captured",
        outcome="success",
        technique="response-capture",
        h3retik_session_id="session-map",
        job_id="job-loot",
        command_id="command-loot",
        status="completed",
        exit_code=0,
        action_id=action["id"],
        relationships=[
            {"from": "event", "to": "admin-api", "type": "observed_on"},
        ],
        artifact={
            "id": "artifact-admin-response",
            "type": "response",
            "label": "Administrator API response",
            "sensitivity": "sensitive",
            "entity_ids": ["admin-api"],
            "finding_ids": [finding["record"]["id"]],
        },
        evidence={"http_status": 200, "authorization": "Bearer secret"},
        idempotency_key="loot:admin-response",
        trusted_internal=True,
    )

    snapshot = build_dashboard_snapshot(service, engagement_id)

    assert {node["id"] for node in snapshot["nodes"]} >= {"target", "backend", "admin-api"}
    assert not any(node["id"] == finding["record"]["id"] for node in snapshot["nodes"])
    endpoint = next(node for node in snapshot["nodes"] if node["id"] == "admin-api")
    assert endpoint["kind"] == "entity"
    assert endpoint["layer"] == "application"
    assert endpoint["detail"]["findings"][0]["title"] == (
        "Administrative endpoint bypass confirmed"
    )
    assert endpoint["detail"]["loot"][0]["label"] == "Administrator API response"
    assert any(
        edge["from"] == "backend"
        and edge["to"] == "admin-api"
        and edge["type"] == "exposes"
        for edge in snapshot["edges"]
    )
    artifact = next(item for item in snapshot["loot"] if item["id"] == "artifact-admin-response")
    assert artifact["entity_labels"] == ["/api/admin"]
    semantic_event = next(
        event for event in snapshot["events"] if event["title"] == "Administrator response captured"
    )
    assert semantic_event["object_id"] == "admin-api"


async def test_dashboard_api_lists_and_reads_engagements(tmp_path):
    service, engagement_id = populated_service(tmp_path)
    artifact = service.record_observation(
        engagement_id,
        statement="Header capture",
        source="fixture",
        confidence=1.0,
        kind="loot",
        evidence={"headers": {"server": "fixture"}},
    )
    identity = IdentityStore(tmp_path / "control.db")
    transport = httpx.ASGITransport(app=create_dashboard_app(service, identity=identity))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        listed = await client.get("/api/engagements")
        detail = await client.get(f"/api/engagements/{engagement_id}")
        loot = await client.get(
            f"/api/engagements/{engagement_id}/loot/{detail.json()['loot'][0]['id']}"
        )
        missing = await client.get("/api/engagements/eng-missing")

    assert listed.status_code == 200
    assert listed.json()["engagements"][0]["engagement_id"] == engagement_id
    assert detail.status_code == 200
    assert detail.json()["brief"]["exhausted_paths"][0]["approach"] == "Probe removed API"
    assert loot.status_code == 200
    assert loot.json()["id"] == artifact["id"]
    assert loot.json()["telemetry"]["headers"]["server"] == "fixture"
    assert missing.status_code == 404


async def test_dashboard_creates_scoped_agent_invite_and_h3_binding(tmp_path):
    service, engagement_id = populated_service(tmp_path)
    identity = IdentityStore(tmp_path / "control.db")
    transport = httpx.ASGITransport(app=create_dashboard_app(service, identity=identity))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        status = await client.get("/api/auth/status")
        opened = await client.post(
            "/api/engagements",
            json={
                "title": "Dashboard-created",
                "target": "new.internal",
                "scope": "Owned fixture",
                "mode": "manual_only",
            },
        )
        agent = await client.post(
            "/api/agents", json={"engagement_id": engagement_id, "name": "Recon Worker"}
        )
        invite = await client.post(
            "/api/invites", json={"engagement_id": engagement_id, "hours": 24}
        )
        binding = await client.post(
            "/api/h3retik-sessions",
            json={
                "engagement_id": engagement_id,
                "session_id": "session-test",
                "label": "Kali pool",
            },
        )
        unbound_extension = await client.post(
            "/api/h3retik-sessions/session-other/extension-receipts",
            json={"engagement_id": engagement_id, "minutes": 15, "actions": 5},
        )
        snapshot = await client.get(f"/api/engagements/{engagement_id}/identity")

    assert status.json()["state"] == "setup"
    assert opened.status_code == 201
    assert opened.json()["target"] == "new.internal"
    assert agent.status_code == 201
    assert agent.json()["token"].startswith("atk_agent_")
    assert (
        agent.json()["mcp_config"]["mcpServers"]["h1dr4-attackgraph"]["env"][
            "ATTACKGRAPH_AGENT_TOKEN"
        ]
        == agent.json()["token"]
    )
    assert invite.status_code == 201
    assert invite.json()["token"].startswith("atk_invite_")
    assert binding.status_code == 201
    assert unbound_extension.status_code == 404
    assert unbound_extension.json()["error"] == "h3retik_session_not_bound"
    assert snapshot.json()["agents"][0]["name"] == "Recon Worker"
    assert snapshot.json()["h3retik_sessions"][0]["session_id"] == "session-test"
