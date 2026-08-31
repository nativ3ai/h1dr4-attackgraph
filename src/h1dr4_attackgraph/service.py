from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

from .h1dr4 import H1dr4Client
from .h3retik import H3retikClient
from .memory import SibylAttackMemory
from .models import ActionDecision, ActionRisk, EngagementMode
from .policy import evaluate_action
from .redaction import redact


class ConfigurationError(RuntimeError):
    pass


class AttackGraphService:
    def __init__(
        self,
        *,
        db_path: str | Path,
        operator_id: str,
        h1dr4: H1dr4Client | None = None,
        h3retik: H3retikClient | None = None,
    ) -> None:
        self.memory = SibylAttackMemory(db_path, operator_id)
        self.h1dr4 = h1dr4 or H1dr4Client()
        self.h3retik = h3retik or H3retikClient()

    def open_engagement(
        self,
        *,
        title: str,
        target: str,
        mode: str,
        scope: str,
        target_allowlist: list[str] | None = None,
        rules: list[str] | None = None,
        allowed_lanes: list[str] | None = None,
    ) -> dict[str, Any]:
        engagement = self.memory.open_engagement(
            title=title,
            target=target,
            mode=EngagementMode(mode),
            scope=scope,
            target_allowlist=target_allowlist,
            rules=rules,
            allowed_lanes=allowed_lanes,
        )
        return engagement.to_dict()

    def list_engagements(self) -> list[dict[str, Any]]:
        return self.memory.list_engagements()

    def context(self, engagement_id: str, *, event_limit: int = 25) -> dict[str, Any]:
        return {
            "engagement": self.memory.get_engagement(engagement_id).to_dict(),
            "graph": self.memory.get_graph(engagement_id),
            "recent_events": self.memory.recent_events(engagement_id, event_limit),
        }

    def brief(self, engagement_id: str) -> dict[str, Any]:
        engagement = self.memory.get_engagement(engagement_id)
        graph = self.memory.get_graph(engagement_id)
        return {
            "engagement": {
                "id": engagement.engagement_id,
                "title": engagement.title,
                "target": engagement.target,
                "mode": engagement.mode.value,
                "scope": engagement.scope,
                "target_allowlist": engagement.target_allowlist,
                "rules": engagement.rules,
                "allowed_lanes": engagement.allowed_lanes,
            },
            "confirmed": [item for item in graph["observations"] if item["confidence"] >= 0.8][
                -20:
            ],
            "open_hypotheses": [item for item in graph["hypotheses"] if item["status"] == "open"][
                -20:
            ],
            "exhausted_paths": [item for item in graph["attempts"] if item["exhausted"]][-20:],
            "recent_attempts": graph["attempts"][-20:],
            "pending_actions": [
                item
                for item in graph["actions"]
                if item.get("status") in {"recorded_only", "human_required"}
            ][-20:],
            "regressions": graph["regressions"][-20:],
            "agent_instruction": (
                "Reason from confirmed evidence and open hypotheses. Do not repeat exhausted "
                "paths without new evidence. Request policy evaluation before active testing."
            ),
        }

    def record_observation(self, engagement_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.memory.record_observation(engagement_id, **kwargs)

    def record_hypothesis(
        self, engagement_id: str, *, statement: str, status: str = "open"
    ) -> dict[str, Any]:
        return self.memory.record_hypothesis(engagement_id, statement=statement, status=status)

    def record_attempt(self, engagement_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.memory.record_attempt(engagement_id, **kwargs)

    def request_action(
        self,
        engagement_id: str,
        *,
        target: str,
        lane: str,
        command: str,
        purpose: str,
        risk: str = "active",
        max_minutes: int = 5,
        budget_usdc: float = 0.50,
    ) -> dict[str, Any]:
        engagement = self.memory.get_engagement(engagement_id)
        risk_value = ActionRisk(risk)
        decision = evaluate_action(
            engagement, target=target, lane=lane, command=command, risk=risk_value
        )
        action = self.memory.record_action(
            engagement_id,
            {
                "target": target,
                "lane": lane,
                "command": command,
                "purpose": purpose,
                "risk": risk_value.value,
                "max_minutes": max(1, min(max_minutes, 60)),
                "budget_usdc": max(0.10, budget_usdc),
                "status": decision.decision.value,
                "policy": decision.to_dict(),
            },
        )
        return action

    def h3retik_capabilities(self) -> dict[str, Any]:
        return self.h3retik.capabilities()

    def h3retik_quote(self, *, minutes: int = 5, actions: int = 1, location: str = "auto") -> Any:
        return self.h3retik.quote(minutes=minutes, actions=actions, location=location)

    def execute_approved_h3retik_job(
        self,
        engagement_id: str,
        *,
        action_id: str,
        approval_code: str,
    ) -> dict[str, Any]:
        engagement = self.memory.get_engagement(engagement_id)
        action = self.memory.get_action(engagement_id, action_id)
        expected_code = os.getenv("ATTACKGRAPH_EXECUTION_APPROVAL_CODE", "")
        if not expected_code:
            raise ConfigurationError("ATTACKGRAPH_EXECUTION_APPROVAL_CODE is not configured")
        if not hmac.compare_digest(approval_code, expected_code):
            raise PermissionError("invalid human approval code")
        if engagement.mode is not EngagementMode.AUTONOMOUS_LAB:
            raise PermissionError("only autonomous_lab engagements can dispatch")
        if action.get("status") != ActionDecision.HUMAN_REQUIRED.value:
            raise PermissionError("action is not awaiting human approval")
        decision = evaluate_action(
            engagement,
            target=action["target"],
            lane=action["lane"],
            command=action["command"],
            risk=ActionRisk(action["risk"]),
        )
        if decision.decision is not ActionDecision.HUMAN_REQUIRED:
            raise PermissionError(decision.reason)
        wallet = os.getenv("H3RETIK_WALLET", "")
        token = os.getenv("H3RETIK_TOKEN", "")
        session_id = os.getenv("H3RETIK_SESSION_ID", "")
        if not all((wallet, token, session_id)):
            raise ConfigurationError(
                "H3RETIK_WALLET, H3RETIK_TOKEN, and H3RETIK_SESSION_ID are required"
            )
        spec = {
            "target": action["target"],
            "lane": action["lane"],
            "module": "attackgraph-approved-command",
            "pipeline": "single-command",
            "args": {"cmd": action["command"]},
            "budget_usdc": action["budget_usdc"],
            "max_minutes": action["max_minutes"],
        }
        result = redact(
            self.h3retik.execute_existing_session(
                wallet=wallet,
                token=token,
                session_id=session_id,
                spec=spec,
            )
        )
        self.memory.complete_action(engagement_id, action_id, status="completed", result=result)
        observation = self.memory.record_observation(
            engagement_id,
            statement=f"H3RETIK action {action_id} completed",
            source=f"h3retik:{result.get('job_id', 'unknown')}",
            confidence=1.0,
            kind="execution_evidence",
            evidence=result,
        )
        return {"action_id": action_id, "observation": observation, "result": result}

    def ingest_h3retik_result(
        self,
        engagement_id: str,
        *,
        action_id: str,
        job_id: str,
        result: dict[str, Any],
        status: str = "completed",
    ) -> dict[str, Any]:
        self.memory.get_action(engagement_id, action_id)
        sanitized = redact({"job_id": job_id, "result": result})
        self.memory.complete_action(engagement_id, action_id, status=status, result=sanitized)
        return self.memory.record_observation(
            engagement_id,
            statement=f"Imported H3RETIK result for action {action_id}",
            source=f"h3retik:{job_id}",
            confidence=1.0,
            kind="execution_evidence",
            evidence=sanitized,
        )

    def create_regression(
        self, engagement_id: str, *, name: str, check: str, expected: str
    ) -> dict[str, Any]:
        return self.memory.create_regression(
            engagement_id, name=name, check=check, expected=expected
        )

    def discover_h1dr4(self, *, query: str = "", limit: int = 20) -> list[dict[str, Any]]:
        return self.h1dr4.discover(query=query, limit=limit)
