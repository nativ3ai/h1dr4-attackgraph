from __future__ import annotations

import pytest

from h1dr4_attackgraph.service import AttackGraphService


class FakeH1dr4:
    def discover(self, query: str = "", limit: int = 20):
        return [{"name": "fake_tool", "query": query}][:limit]


class FakeH3retik:
    def __init__(self):
        self.spec = None

    def capabilities(self):
        return {"available": ["h3retik_create_session_job"]}

    def quote(self, *, minutes: int, actions: int, location: str):
        return {"minutes": minutes, "actions": actions, "location": location, "usdc": 0.19}

    def execute_existing_session(self, **kwargs):
        self.spec = kwargs["spec"]
        return {
            "job_id": "job-123",
            "status": {"status": "succeeded"},
            "output": {"stdout": "HTTP/2 200"},
        }


def service(tmp_path, h3retik=None):
    return AttackGraphService(
        db_path=tmp_path / "sibyl.db",
        operator_id="alice",
        h1dr4=FakeH1dr4(),
        h3retik=h3retik or FakeH3retik(),
    )


def open_lab(svc: AttackGraphService, mode: str = "autonomous_lab") -> str:
    opened = svc.open_engagement(
        title="Owned lab",
        target="demo.internal",
        mode=mode,
        scope="Owned demo.internal only",
        target_allowlist=["demo.internal"],
        allowed_lanes=["web", "local"],
    )
    return opened["engagement_id"]


def test_service_is_model_agnostic_and_builds_agent_brief(tmp_path, monkeypatch):
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_HOST", "MODEL"):
        monkeypatch.delenv(name, raising=False)
    svc = service(tmp_path)
    engagement_id = open_lab(svc, mode="manual_only")
    svc.record_hypothesis(engagement_id, statement="Admin route may be exposed")
    svc.record_attempt(
        engagement_id,
        approach="Try /old-admin",
        outcome="404",
        exhausted=True,
    )

    brief = svc.brief(engagement_id)

    assert brief["open_hypotheses"][0]["statement"] == "Admin route may be exposed"
    assert brief["exhausted_paths"][0]["approach"] == "Try /old-admin"
    assert "model" not in brief


def test_manual_mode_records_but_cannot_execute(tmp_path, monkeypatch):
    svc = service(tmp_path)
    engagement_id = open_lab(svc, mode="manual_only")
    action = svc.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="curl -I https://demo.internal",
        purpose="Check headers",
    )
    monkeypatch.setenv("ATTACKGRAPH_EXECUTION_APPROVAL_CODE", "human-ok")

    assert action["status"] == "recorded_only"
    with pytest.raises(PermissionError, match="only autonomous_lab"):
        svc.execute_approved_h3retik_job(
            engagement_id, action_id=action["id"], approval_code="human-ok"
        )


def test_approved_h3retik_result_becomes_sibyl_evidence(tmp_path, monkeypatch):
    fake = FakeH3retik()
    svc = service(tmp_path, h3retik=fake)
    engagement_id = open_lab(svc)
    action = svc.request_action(
        engagement_id,
        target="demo.internal",
        lane="web",
        command="curl -I https://demo.internal",
        purpose="Check headers",
        max_minutes=5,
        budget_usdc=0.5,
    )
    monkeypatch.setenv("ATTACKGRAPH_EXECUTION_APPROVAL_CODE", "human-ok")
    monkeypatch.setenv("H3RETIK_WALLET", "0xabc")
    monkeypatch.setenv("H3RETIK_TOKEN", "token-value")
    monkeypatch.setenv("H3RETIK_SESSION_ID", "session-1")

    result = svc.execute_approved_h3retik_job(
        engagement_id, action_id=action["id"], approval_code="human-ok"
    )

    assert fake.spec["args"]["cmd"] == "curl -I https://demo.internal"
    assert result["observation"]["source"] == "h3retik:job-123"
    assert svc.memory.get_action(engagement_id, action["id"])["status"] == "completed"
    assert svc.brief(engagement_id)["confirmed"]


def test_h3retik_quote_is_read_only_adapter(tmp_path):
    quote = service(tmp_path).h3retik_quote(minutes=5, actions=3, location="europe")

    assert quote == {"minutes": 5, "actions": 3, "location": "europe", "usdc": 0.19}
