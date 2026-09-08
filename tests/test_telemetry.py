from __future__ import annotations

import pytest

from h1dr4_attackgraph.posture import derive_engagement_posture
from h1dr4_attackgraph.service import AttackGraphService, ConfigurationError


class OfflineClient:
    def discover(self, **kwargs):
        return []

    def capabilities(self):
        return {}


def telemetry_service(tmp_path) -> tuple[AttackGraphService, str]:
    client = OfflineClient()
    service = AttackGraphService(
        db_path=tmp_path / "sibyl.db",
        operator_id="telemetry-test",
        h1dr4=client,
        h3retik=client,
    )
    engagement = service.open_engagement(
        title="Telemetry lab",
        target="demo.internal",
        mode="autonomous_lab",
        scope="Owned demo.internal fixture only",
        target_allowlist=["demo.internal"],
        allowed_lanes=["web"],
    )
    return service, engagement["engagement_id"]


def test_reporting_contract_is_model_agnostic_and_explicit_about_assurance(tmp_path):
    service, _ = telemetry_service(tmp_path)

    contract = service.reporting_contract()

    assert contract["schema"] == "h1dr4.telemetry.v1"
    assert "finding.confirmed" in contract["event_types"]
    assert "asserted" in contract["assurance"]
    assert "verified" in contract["assurance"]
    assert "application" in contract["entity_layers"]
    assert "response" in contract["artifact"]["types"]
    assert "transport/import" in contract["presentation"]["summary"]
    assert "model" not in str(contract).lower()


def test_h3retik_proof_promotes_the_same_agent_assertion_in_place(tmp_path):
    service, engagement_id = telemetry_service(tmp_path)
    action = service.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="fixture-auth-check",
        purpose="Verify the owned authentication boundary",
    )
    assertion = service.report_telemetry(
        engagement_id,
        event_type="finding.confirmed",
        summary="Administrator authentication bypass observed",
        outcome="success",
        technique="authentication_bypass",
        confidence=1.0,
        action_id=action["id"],
        entities=[{"id": "login", "type": "endpoint", "label": "/login"}],
        relationships=[{"from": "event", "to": "login", "type": "observed_on"}],
        attributes={
            "posture_signal": "target_compromised",
            "authorization": "Bearer do-not-store",
        },
        idempotency_key="finding:admin-auth-bypass",
    )

    graph = service.memory.get_graph(engagement_id)
    posture = derive_engagement_posture(
        service.memory.get_engagement(engagement_id).to_dict(), graph
    )
    assert assertion["event"]["assurance"] == "asserted"
    assert assertion["record"]["kind"] == "finding_assertion"
    assert assertion["record"]["confidence"] == 0.79
    assert assertion["event"]["attributes"]["authorization"] == "[REDACTED]"
    assert posture["state"] == "engagement_active"

    promoted = service.ingest_h3retik_telemetry(
        engagement_id,
        event_type="finding.confirmed",
        summary="Administrator authentication bypass observed",
        target="demo.internal",
        outcome="success",
        technique="authentication_bypass",
        confidence=1.0,
        h3retik_session_id="session-1",
        job_id="job-1",
        command_id="cli-1",
        status="completed",
        exit_code=0,
        action_id=action["id"],
        attributes={"posture_signal": "target_compromised"},
        evidence={"status": 200, "token": "do-not-store"},
        idempotency_key="finding:admin-auth-bypass",
        trusted_internal=True,
    )

    graph = service.memory.get_graph(engagement_id)
    posture = derive_engagement_posture(
        service.memory.get_engagement(engagement_id).to_dict(), graph
    )
    assert promoted["promoted"] is True
    assert promoted["event"]["id"] == assertion["event"]["id"]
    assert promoted["record"]["id"] == assertion["record"]["id"]
    assert promoted["event"]["assurance"] == "verified"
    assert promoted["event"]["entities"] == assertion["event"]["entities"]
    assert promoted["event"]["relationships"] == assertion["event"]["relationships"]
    assert promoted["event"]["attributes"]["authorization"] == "[REDACTED]"
    assert promoted["record"]["kind"] == "finding"
    assert promoted["record"]["evidence"]["proof"]["evidence"]["token"] == "[REDACTED]"
    assert len(graph["telemetry"]) == 1
    assert len(graph["observations"]) == 1
    assert posture["state"] == "target_compromised"
    assert posture["reasons"][0]["record_id"] == assertion["record"]["id"]
    assert service.memory.recent_events(engagement_id, 1)[0]["evaluated"]["type"] == (
        "telemetry_promoted"
    )


def test_h3retik_proof_without_action_is_attested_but_not_verified(tmp_path):
    service, engagement_id = telemetry_service(tmp_path)

    recorded = service.ingest_h3retik_telemetry(
        engagement_id,
        event_type="finding.confirmed",
        summary="Uncorrelated finding",
        outcome="success",
        h3retik_session_id="session-1",
        job_id="job-1",
        command_id="cli-1",
        status="completed",
        exit_code=0,
        attributes={"posture_signal": "target_compromised"},
        trusted_internal=True,
    )

    graph = service.memory.get_graph(engagement_id)
    posture = derive_engagement_posture(
        service.memory.get_engagement(engagement_id).to_dict(), graph
    )
    assert recorded["event"]["assurance"] == "attested"
    assert recorded["event"]["verified"] is False
    assert recorded["record"]["kind"] == "finding_assertion"
    assert posture["state"] == "recon_in_progress"


def test_exact_agent_reports_are_deduplicated(tmp_path):
    service, engagement_id = telemetry_service(tmp_path)
    kwargs = {
        "event_type": "checkpoint.written",
        "summary": "Phase complete",
        "outcome": "success",
        "idempotency_key": "checkpoint:phase-1",
    }

    first = service.report_telemetry(engagement_id, **kwargs)
    repeated = service.report_telemetry(engagement_id, **kwargs)

    assert first["event"]["id"] == repeated["event"]["id"]
    assert repeated["deduplicated"] is True
    assert len(service.memory.get_graph(engagement_id)["telemetry"]) == 1


def test_external_h3retik_ingest_requires_adapter_credential(tmp_path, monkeypatch):
    service, engagement_id = telemetry_service(tmp_path)
    payload = {
        "event_type": "execution.completed",
        "summary": "Authenticated adapter event",
        "h3retik_session_id": "session-1",
        "job_id": "job-1",
        "command_id": "command-1",
        "status": "completed",
        "exit_code": 0,
    }

    with pytest.raises(ConfigurationError, match="ATTESTATION_TOKEN is not configured"):
        service.ingest_h3retik_telemetry(engagement_id, **payload)

    monkeypatch.setenv("ATTACKGRAPH_H3RETIK_ATTESTATION_TOKEN", "adapter-secret")
    with pytest.raises(PermissionError, match="invalid H3RETIK attestation token"):
        service.ingest_h3retik_telemetry(
            engagement_id, **payload, attestation_token="wrong"
        )

    recorded = service.ingest_h3retik_telemetry(
        engagement_id, **payload, attestation_token="adapter-secret"
    )

    assert recorded["event"]["assurance"] == "attested"


def test_telemetry_rejects_out_of_scope_targets_and_unknown_relationships(tmp_path):
    service, engagement_id = telemetry_service(tmp_path)

    with pytest.raises(PermissionError, match="outside_engagement_scope"):
        service.report_telemetry(
            engagement_id,
            event_type="execution.completed",
            summary="Wrong target",
            target="outside.internal",
        )

    with pytest.raises(ValueError, match="relationship_reference_unknown"):
        service.report_telemetry(
            engagement_id,
            event_type="finding.observed",
            summary="Malformed relation",
            relationships=[{"from": "event", "to": "missing", "type": "observed_on"}],
        )


def test_entities_artifacts_and_cross_event_relationships_materialize_stably(tmp_path):
    service, engagement_id = telemetry_service(tmp_path)
    action = service.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="fixture-map",
        purpose="Map application boundary",
    )
    mapped = service.ingest_h3retik_telemetry(
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
    loot = service.ingest_h3retik_telemetry(
        engagement_id,
        event_type="loot.discovered",
        summary="Administrative response captured",
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
            "finding_ids": [mapped["record"]["id"]],
            "media_type": "application/json",
        },
        evidence={"http_status": 200, "authorization": "Bearer do-not-store"},
        idempotency_key="loot:admin-response",
        trusted_internal=True,
    )

    graph = service.memory.get_graph(engagement_id)

    assert {item["id"] for item in graph["entities"]} == {"backend", "admin-api"}
    endpoint = next(item for item in graph["entities"] if item["id"] == "admin-api")
    assert endpoint["parent_id"] == "backend"
    assert endpoint["assurance"] == "verified"
    assert mapped["record"]["entity_ids"] == ["admin-api"]
    assert loot["record"]["entity_ids"] == ["admin-api"]
    assert graph["artifacts"][0]["id"] == "artifact-admin-response"
    assert graph["artifacts"][0]["entity_ids"] == ["admin-api"]
    assert graph["artifacts"][0]["finding_ids"] == [mapped["record"]["id"]]
    assert graph["artifacts"][0]["sensitive"] is True
    assert "do-not-store" not in str(graph)
    relation = next(
        item
        for item in graph["relationships"]
        if item["from"] == "backend"
        and item["to"] == "admin-api"
        and item["type"] == "exposes"
    )
    assert relation["id"].startswith("rel-")
    assert len(relation["id"]) == 16


def test_entity_identity_cannot_change_type_across_events(tmp_path):
    service, engagement_id = telemetry_service(tmp_path)
    service.report_telemetry(
        engagement_id,
        event_type="finding.observed",
        summary="Endpoint observed",
        entities=[{"id": "stable-id", "type": "endpoint", "label": "/api"}],
    )

    with pytest.raises(ValueError, match="entity_type_conflict"):
        service.report_telemetry(
            engagement_id,
            event_type="finding.observed",
            summary="Identity drift",
            entities=[{"id": "stable-id", "type": "identity", "label": "admin"}],
        )
