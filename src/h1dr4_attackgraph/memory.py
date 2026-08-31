from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sibyl_memory_client import MemoryClient
from sibyl_memory_client.exceptions import NotFoundError

from .models import Engagement, EngagementMode
from .redaction import redact


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _tenant_for(operator_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"h1dr4-attackgraph:{operator_id}"))


def _new_graph() -> dict[str, list[dict[str, Any]]]:
    return {
        "observations": [],
        "hypotheses": [],
        "attempts": [],
        "findings": [],
        "actions": [],
        "regressions": [],
    }


class EngagementNotFoundError(KeyError):
    pass


class SibylAttackMemory:
    """Sibyl-backed hot graph and append-only cold evidence for one operator."""

    def __init__(self, path: str | Path, operator_id: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.operator_id = operator_id
        self.client = MemoryClient.local(self.path, tenant_id=_tenant_for(operator_id))

    def open_engagement(
        self,
        *,
        title: str,
        target: str,
        mode: EngagementMode,
        scope: str,
        target_allowlist: list[str] | None = None,
        rules: list[str] | None = None,
        allowed_lanes: list[str] | None = None,
    ) -> Engagement:
        engagement_id = f"eng-{uuid.uuid4().hex[:12]}"
        allowlist = list(dict.fromkeys(target_allowlist or [target]))
        engagement = Engagement(
            engagement_id=engagement_id,
            operator_id=self.operator_id,
            title=title,
            target=target,
            mode=mode,
            scope=scope,
            target_allowlist=allowlist,
            rules=rules or [],
            allowed_lanes=allowed_lanes or ["local", "web", "osint"],
            created_at=_now(),
        )
        self.client.set_entity("engagement", engagement_id, engagement.to_dict(), status="active")
        self.client.set_state(self._graph_key(engagement_id), _new_graph())
        self._event(engagement_id, "engagement_opened", engagement.to_dict())
        return engagement

    def get_engagement(self, engagement_id: str) -> Engagement:
        try:
            body = self.client.get_entity("engagement", engagement_id)["body"]
        except NotFoundError as exc:
            raise EngagementNotFoundError(engagement_id) from exc
        return Engagement(
            engagement_id=body["engagement_id"],
            operator_id=body["operator_id"],
            title=body["title"],
            target=body["target"],
            mode=EngagementMode(body["mode"]),
            scope=body["scope"],
            target_allowlist=body["target_allowlist"],
            rules=body.get("rules", []),
            allowed_lanes=body.get("allowed_lanes", ["local", "web", "osint"]),
            created_at=body.get("created_at", ""),
        )

    def list_engagements(self) -> list[dict[str, Any]]:
        return [entity["body"] for entity in self.client.list_entities("engagement", limit=100)]

    def get_graph(self, engagement_id: str) -> dict[str, list[dict[str, Any]]]:
        self.get_engagement(engagement_id)
        state = self.client.get_state(self._graph_key(engagement_id))
        if not state:
            raise EngagementNotFoundError(engagement_id)
        return state["body"]

    def record_observation(
        self,
        engagement_id: str,
        *,
        statement: str,
        source: str,
        confidence: float,
        kind: str = "observation",
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        graph = self.get_graph(engagement_id)
        item = {
            "id": f"obs-{uuid.uuid4().hex[:10]}",
            "statement": statement,
            "source": source,
            "confidence": max(0.0, min(1.0, confidence)),
            "kind": kind,
            "evidence": redact(evidence or {}),
            "recorded_at": _now(),
        }
        graph["observations"].append(item)
        if kind == "finding":
            graph["findings"].append(item)
        self._save_graph(engagement_id, graph)
        self._event(engagement_id, "observation_recorded", item)
        return item

    def record_hypothesis(
        self, engagement_id: str, *, statement: str, status: str = "open"
    ) -> dict[str, Any]:
        if status not in {"open", "confirmed", "rejected"}:
            raise ValueError("hypothesis status must be open, confirmed, or rejected")
        graph = self.get_graph(engagement_id)
        item = {
            "id": f"hyp-{uuid.uuid4().hex[:10]}",
            "statement": statement,
            "status": status,
            "recorded_at": _now(),
        }
        graph["hypotheses"].append(item)
        self._save_graph(engagement_id, graph)
        self._event(engagement_id, "hypothesis_recorded", item)
        return item

    def record_attempt(
        self,
        engagement_id: str,
        *,
        approach: str,
        outcome: str,
        exhausted: bool,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        graph = self.get_graph(engagement_id)
        item = {
            "id": f"try-{uuid.uuid4().hex[:10]}",
            "approach": approach,
            "outcome": outcome,
            "exhausted": exhausted,
            "evidence": redact(evidence or {}),
            "recorded_at": _now(),
        }
        graph["attempts"].append(item)
        self._save_graph(engagement_id, graph)
        self._event(engagement_id, "attempt_recorded", item)
        return item

    def record_action(self, engagement_id: str, action: dict[str, Any]) -> dict[str, Any]:
        graph = self.get_graph(engagement_id)
        item = {
            "id": f"act-{uuid.uuid4().hex[:10]}",
            **redact(action),
            "recorded_at": _now(),
        }
        graph["actions"].append(item)
        self._save_graph(engagement_id, graph)
        self._event(engagement_id, "action_requested", item)
        return item

    def get_action(self, engagement_id: str, action_id: str) -> dict[str, Any]:
        graph = self.get_graph(engagement_id)
        try:
            return next(item for item in graph["actions"] if item["id"] == action_id)
        except StopIteration as exc:
            raise KeyError(action_id) from exc

    def complete_action(
        self,
        engagement_id: str,
        action_id: str,
        *,
        status: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        graph = self.get_graph(engagement_id)
        action = next((item for item in graph["actions"] if item["id"] == action_id), None)
        if action is None:
            raise KeyError(action_id)
        action["status"] = status
        action["result"] = redact(result)
        action["completed_at"] = _now()
        self._save_graph(engagement_id, graph)
        self._event(engagement_id, "action_completed", action)
        return action

    def create_regression(
        self, engagement_id: str, *, name: str, check: str, expected: str
    ) -> dict[str, Any]:
        graph = self.get_graph(engagement_id)
        item = {
            "id": f"reg-{uuid.uuid4().hex[:10]}",
            "name": name,
            "check": check,
            "expected": expected,
            "recorded_at": _now(),
        }
        graph["regressions"].append(item)
        self._save_graph(engagement_id, graph)
        self._event(engagement_id, "regression_created", item)
        return item

    def recent_events(self, engagement_id: str, limit: int = 25) -> list[dict[str, Any]]:
        self.get_engagement(engagement_id)
        events = self.client.read_events(limit=min(500, max(limit * 4, 50)))
        return [
            event
            for event in events
            if event.get("evaluated", {}).get("engagement_id") == engagement_id
        ][-limit:]

    @staticmethod
    def _graph_key(engagement_id: str) -> str:
        return f"attackgraph:{engagement_id}"

    def _save_graph(self, engagement_id: str, graph: dict[str, Any]) -> None:
        self.client.set_state(self._graph_key(engagement_id), redact(graph))

    def _event(self, engagement_id: str, event_type: str, payload: Any) -> None:
        self.client.write_event(
            evaluated={"engagement_id": engagement_id, "type": event_type},
            acted=redact(payload),
            forward=None,
            extra={"product": "h1dr4-attackgraph", "schema_version": 1},
        )
