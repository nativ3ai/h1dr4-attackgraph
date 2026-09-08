from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sibyl_memory_client import MemoryClient
from sibyl_memory_client.exceptions import NotFoundError

from .models import Engagement, EngagementMode
from .redaction import redact
from .telemetry import HIGH_IMPACT_POSTURES


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
        "telemetry": [],
        "entities": [],
        "artifacts": [],
        "relationships": [],
    }


class EngagementNotFoundError(KeyError):
    pass


class SibylAttackMemory:
    """Sibyl-backed hot graph and append-only cold evidence for one operator."""

    def __init__(
        self,
        path: str | Path,
        operator_id: str,
        *,
        actor_id: str = "",
        actor_name: str = "",
        actor_type: str = "human",
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.operator_id = operator_id
        self.actor_id = actor_id or operator_id
        self.actor_name = actor_name or operator_id
        self.actor_type = actor_type
        self.client = MemoryClient.local(self.path, tenant_id=_tenant_for(operator_id))

    def _actor(self) -> dict[str, str]:
        return {
            "id": self.actor_id,
            "name": self.actor_name,
            "type": self.actor_type,
        }

    def actor(self) -> dict[str, str]:
        return self._actor()

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
        graph = state["body"]
        for key in _new_graph():
            graph.setdefault(key, [])
        self._repair_telemetry_projection(graph)
        return graph

    def _repair_telemetry_projection(self, graph: dict[str, list[dict[str, Any]]]) -> None:
        """Project older telemetry into the current entity/artifact graph without a migration."""

        for event in graph.get("telemetry", []):
            self._upsert_telemetry_entities(graph, event)
            record = self._telemetry_record(graph, str(event.get("record_id") or ""))
            artifact = self._materialize_telemetry_artifact(graph, event, record)
            if artifact:
                event["artifact_id"] = str(artifact.get("id") or "")
            self._merge_telemetry_relationships(graph, event)

    def record_telemetry(
        self, engagement_id: str, event: dict[str, Any]
    ) -> dict[str, Any]:
        graph = self.get_graph(engagement_id)
        existing = next(
            (
                item
                for item in graph["telemetry"]
                if item.get("idempotency_key") == event.get("idempotency_key")
            ),
            None,
        )
        if existing is not None:
            assurance_rank = {"asserted": 0, "attested": 1, "verified": 2}
            old_rank = assurance_rank.get(str(existing.get("assurance") or "asserted"), 0)
            new_rank = assurance_rank.get(str(event.get("assurance") or "asserted"), 0)
            if new_rank <= old_rank:
                record = self._telemetry_record(graph, str(existing.get("record_id") or ""))
                return {
                    "event": existing,
                    "record": record,
                    "deduplicated": True,
                    "promoted": False,
                }

            original_id = str(existing["id"])
            original_time = str(existing.get("recorded_at") or "")
            record_id = str(existing.get("record_id") or "")
            previous_assurance = str(existing.get("assurance") or "asserted")
            original_entities = existing.get("entities") or []
            original_relationships = existing.get("relationships") or []
            original_artifact = existing.get("artifact") or {}
            original_presentation = existing.get("presentation") or {}
            original_attributes = existing.get("attributes") or {}
            existing.update(event)
            if not existing.get("entities"):
                existing["entities"] = original_entities
            if not existing.get("relationships"):
                existing["relationships"] = original_relationships
            if not existing.get("artifact"):
                existing["artifact"] = original_artifact
            if not existing.get("presentation"):
                existing["presentation"] = original_presentation
            existing["attributes"] = {
                **original_attributes,
                **(existing.get("attributes") or {}),
            }
            existing["id"] = original_id
            existing["recorded_at"] = original_time
            existing["promoted_at"] = _now()
            existing["previous_assurance"] = previous_assurance
            self._upsert_telemetry_entities(graph, existing)
            record = self._materialize_telemetry(graph, existing, record_id=record_id)
            existing["record_id"] = str(record.get("id") or "") if record else ""
            artifact = self._materialize_telemetry_artifact(graph, existing, record)
            existing["artifact_id"] = str(artifact.get("id") or "") if artifact else ""
            self._merge_telemetry_relationships(graph, existing)
            self._save_graph(engagement_id, graph)
            self._event(engagement_id, "telemetry_promoted", existing)
            return {
                "event": existing,
                "record": record,
                "deduplicated": False,
                "promoted": True,
            }

        event = redact(event)
        self._upsert_telemetry_entities(graph, event)
        record = self._materialize_telemetry(graph, event)
        event["record_id"] = str(record.get("id") or "") if record else ""
        artifact = self._materialize_telemetry_artifact(graph, event, record)
        event["artifact_id"] = str(artifact.get("id") or "") if artifact else ""
        graph["telemetry"].append(event)
        self._merge_telemetry_relationships(graph, event)
        self._save_graph(engagement_id, graph)
        self._event(engagement_id, "telemetry_recorded", event)
        return {
            "event": event,
            "record": record,
            "deduplicated": False,
            "promoted": False,
        }

    def _materialize_telemetry(
        self,
        graph: dict[str, list[dict[str, Any]]],
        event: dict[str, Any],
        *,
        record_id: str = "",
    ) -> dict[str, Any] | None:
        event_type = str(event.get("event_type") or "")
        if event_type == "execution.started":
            return None

        assurance = str(event.get("assurance") or "asserted")
        proof = event.get("proof") if isinstance(event.get("proof"), dict) else {}
        evidence: dict[str, Any] = {
            "telemetry": {
                "schema": event.get("schema"),
                "event_id": event.get("id"),
                "event_type": event_type,
                "outcome": event.get("outcome"),
                "technique": event.get("technique"),
                "assurance": assurance,
                "verified": event.get("verified") is True,
                "idempotency_key": event.get("idempotency_key"),
            },
            "proof": proof,
            "entities": event.get("entities") or [],
            "relationships": event.get("relationships") or [],
            "attributes": event.get("attributes") or {},
            "artifact": event.get("artifact") or {},
        }
        attributes = event.get("attributes") if isinstance(event.get("attributes"), dict) else {}
        posture_signal = str(attributes.get("posture_signal") or "")
        if (
            event_type == "finding.confirmed"
            and event.get("verified") is True
            and posture_signal in HIGH_IMPACT_POSTURES
            and proof.get("proof_ref")
        ):
            evidence["posture"] = {
                "signal": posture_signal,
                "verified": True,
                "proof": proof["proof_ref"],
            }

        source = str(proof.get("proof_ref") or f"agent:{self.actor_id}")
        confidence = float(event.get("confidence") or 0.0)
        if assurance == "asserted":
            confidence = min(confidence, 0.79)
        elif assurance == "verified":
            confidence = 1.0
        presentation = (
            event.get("presentation") if isinstance(event.get("presentation"), dict) else {}
        )
        statement = str(presentation.get("title") or event.get("summary") or "Telemetry event")
        entity_ids = list(
            dict.fromkeys(
                str(
                    relationship.get("to")
                    if relationship.get("from") == "event"
                    else relationship.get("from")
                )
                for relationship in event.get("relationships") or []
                if "event" in {relationship.get("from"), relationship.get("to")}
                and {relationship.get("from"), relationship.get("to")}
                != {"event", "target"}
            )
        )
        if not entity_ids:
            entity_ids = [
                str(item.get("id"))
                for item in event.get("entities") or []
                if item.get("id")
                and item.get("type") not in {"agent", "artifact", "finding", "job", "session"}
            ]

        if event_type == "attempt.completed":
            item = self._telemetry_record(graph, record_id) if record_id else None
            payload = {
                "id": record_id or f"try-{uuid.uuid4().hex[:10]}",
                "approach": statement,
                "outcome": event.get("outcome", "unknown"),
                "exhausted": event.get("outcome") in {"failed", "blocked", "no_finding"},
                "evidence": evidence,
                "actor": event.get("actor") or self._actor(),
                "h3retik_session_id": event.get("h3retik_session_id", ""),
                "job_id": proof.get("job_id", ""),
                "action_id": event.get("action_id", ""),
                "telemetry_event_id": event.get("id", ""),
                "entity_ids": entity_ids,
                "presentation": presentation,
                "recorded_at": (item or {}).get("recorded_at", event.get("recorded_at", _now())),
            }
            if item:
                item.update(payload)
                return item
            graph["attempts"].append(payload)
            return payload

        if event_type == "finding.confirmed" and event.get("verified") is True:
            kind = "finding"
        elif event_type.startswith("finding."):
            kind = "finding_assertion"
        elif event_type == "loot.discovered":
            kind = "loot"
        elif event_type == "checkpoint.written":
            kind = "checkpoint"
        else:
            kind = "execution_evidence" if assurance != "asserted" else "execution_assertion"

        item = self._telemetry_record(graph, record_id) if record_id else None
        payload = {
            "id": record_id or f"obs-{uuid.uuid4().hex[:10]}",
            "statement": statement,
            "source": source,
            "confidence": confidence,
            "kind": kind,
            "evidence": evidence,
            "actor": event.get("actor") or self._actor(),
            "h3retik_session_id": event.get("h3retik_session_id", ""),
            "job_id": proof.get("job_id", ""),
            "action_id": event.get("action_id", ""),
            "telemetry_event_id": event.get("id", ""),
            "entity_ids": entity_ids,
            "presentation": presentation,
            "recorded_at": (item or {}).get("recorded_at", event.get("recorded_at", _now())),
        }
        if item:
            item.update(payload)
        else:
            graph["observations"].append(payload)
            item = payload
        graph["findings"] = [
            observation
            for observation in graph["observations"]
            if observation.get("kind") == "finding"
        ]
        return item

    def _upsert_telemetry_entities(
        self, graph: dict[str, list[dict[str, Any]]], event: dict[str, Any]
    ) -> None:
        event_id = str(event.get("id") or "")
        proof = event.get("proof") if isinstance(event.get("proof"), dict) else {}
        actor = event.get("actor") or self._actor()
        recorded_at = str(event.get("recorded_at") or _now())
        for incoming in event.get("entities") or []:
            entity_id = str(incoming.get("id") or "")
            if not entity_id:
                continue
            existing = next(
                (item for item in graph["entities"] if item.get("id") == entity_id), None
            )
            event_ids = list(dict.fromkeys([*((existing or {}).get("event_ids") or []), event_id]))
            session_ids = list(
                dict.fromkeys(
                    [
                        *((existing or {}).get("h3retik_session_ids") or []),
                        *(
                            [str(event["h3retik_session_id"])]
                            if event.get("h3retik_session_id")
                            else []
                        ),
                    ]
                )
            )
            job_ids = list(
                dict.fromkeys(
                    [
                        *((existing or {}).get("job_ids") or []),
                        *([str(proof["job_id"])] if proof.get("job_id") else []),
                    ]
                )
            )
            metadata = {
                **((existing or {}).get("metadata") or {}),
                **(incoming.get("metadata") or {}),
            }
            assurance_rank = {"asserted": 0, "attested": 1, "verified": 2}
            previous_assurance = str((existing or {}).get("assurance") or "asserted")
            incoming_assurance = str(event.get("assurance") or "asserted")
            assurance = (
                incoming_assurance
                if assurance_rank.get(incoming_assurance, 0)
                >= assurance_rank.get(previous_assurance, 0)
                else previous_assurance
            )
            payload = {
                "id": entity_id,
                "type": incoming.get("type"),
                "label": incoming.get("label") or entity_id,
                "layer": incoming.get("layer") or (existing or {}).get("layer", ""),
                "parent_id": incoming.get("parent_id")
                or (existing or {}).get("parent_id", ""),
                "metadata": metadata,
                "assurance": assurance,
                "actor": actor,
                "first_seen_at": (existing or {}).get("first_seen_at", recorded_at),
                "last_seen_at": recorded_at,
                "event_ids": event_ids,
                "h3retik_session_ids": session_ids,
                "job_ids": job_ids,
            }
            if existing:
                existing.update(payload)
            else:
                graph["entities"].append(payload)

    def _materialize_telemetry_artifact(
        self,
        graph: dict[str, list[dict[str, Any]]],
        event: dict[str, Any],
        record: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if event.get("event_type") != "loot.discovered" or record is None:
            return None
        definition = event.get("artifact") if isinstance(event.get("artifact"), dict) else {}
        proof = event.get("proof") if isinstance(event.get("proof"), dict) else {}
        presentation = (
            event.get("presentation") if isinstance(event.get("presentation"), dict) else {}
        )
        evidence = proof.get("evidence") if isinstance(proof.get("evidence"), dict) else {}
        encoded = json.dumps(evidence, sort_keys=True, default=str).encode()
        artifact_id = str(definition.get("id") or f"artifact:{record['id']}")
        existing = next(
            (item for item in graph["artifacts"] if item.get("id") == artifact_id), None
        )
        entity_ids = list(
            dict.fromkeys(
                definition.get("entity_ids")
                or [
                    str(item.get("id"))
                    for item in event.get("entities") or []
                    if item.get("id") and item.get("type") not in {"artifact", "finding"}
                ]
            )
        )
        finding_ids = list(dict.fromkeys(definition.get("finding_ids") or []))
        sensitivity = str(definition.get("sensitivity") or "internal")
        payload = {
            "id": artifact_id,
            "record_id": record["id"],
            "label": definition.get("label")
            or presentation.get("title")
            or event.get("summary")
            or "Collected artifact",
            "type": definition.get("type") or "other",
            "sensitivity": sensitivity,
            "media_type": definition.get("media_type", ""),
            "locator": definition.get("locator", ""),
            "metadata": definition.get("metadata") or {},
            "entity_ids": entity_ids,
            "finding_ids": finding_ids,
            "source": proof.get("proof_ref") or f"agent:{self.actor_id}",
            "digest": definition.get("digest")
            or proof.get("digest")
            or f"sha256:{hashlib.sha256(encoded).hexdigest()}",
            "size_bytes": definition.get("size_bytes", len(encoded)),
            "assurance": event.get("assurance", "asserted"),
            "sensitive": sensitivity in {"sensitive", "restricted"},
            "actor": event.get("actor") or self._actor(),
            "h3retik_session_id": event.get("h3retik_session_id", ""),
            "job_id": proof.get("job_id", ""),
            "telemetry_event_id": event.get("id", ""),
            "recorded_at": (existing or {}).get(
                "recorded_at", event.get("recorded_at", _now())
            ),
        }
        if existing:
            existing.update(payload)
            return existing
        graph["artifacts"].append(payload)
        return payload

    @staticmethod
    def _telemetry_record(
        graph: dict[str, list[dict[str, Any]]], record_id: str
    ) -> dict[str, Any] | None:
        if not record_id:
            return None
        for collection in ("observations", "attempts"):
            match = next((item for item in graph[collection] if item.get("id") == record_id), None)
            if match:
                return match
        return None

    def _merge_telemetry_relationships(
        self, graph: dict[str, list[dict[str, Any]]], event: dict[str, Any]
    ) -> None:
        event_id = str(event.get("id") or "")
        record_id = str(event.get("record_id") or "")
        proof = event.get("proof") if isinstance(event.get("proof"), dict) else {}
        artifact_id = str(event.get("artifact_id") or "")
        artifact = next(
            (item for item in graph.get("artifacts", []) if item.get("id") == artifact_id),
            {},
        )
        relationships = [
            {
                "from": event_id,
                "to": "target",
                "type": "observed_on",
            },
            {
                "from": event_id,
                "to": f"agent:{(event.get('actor') or {}).get('id', self.actor_id)}",
                "type": "executed_by",
            },
        ]
        if record_id:
            relationships.extend(
                [
                    {"from": event_id, "to": record_id, "type": "supports"},
                    {"from": "target", "to": record_id, "type": "affects"},
                ]
            )
        if event.get("h3retik_session_id"):
            relationships.append(
                {
                    "from": event_id,
                    "to": f"session:{event['h3retik_session_id']}",
                    "type": "ran_in",
                }
            )
        if proof.get("job_id"):
            relationships.append(
                {
                    "from": f"job:{proof['job_id']}",
                    "to": event_id,
                    "type": "produced",
                }
            )
        for entity in event.get("entities") or []:
            entity_id = str(entity.get("id") or "")
            if not entity_id:
                continue
            parent_id = str(entity.get("parent_id") or "target")
            if entity.get("type") not in {"target", "agent", "session", "job", "technique"}:
                relationships.append(
                    {"from": parent_id, "to": entity_id, "type": "contains"}
                )
        record = self._telemetry_record(graph, record_id)
        for entity_id in (record or {}).get("entity_ids") or []:
            relationships.append(
                {"from": record_id, "to": entity_id, "type": "observed_on"}
            )
        if artifact_id:
            for entity_id in artifact.get("entity_ids") or []:
                relationships.append(
                    {"from": entity_id, "to": artifact_id, "type": "produced"}
                )
            for finding_id in artifact.get("finding_ids") or []:
                relationships.append(
                    {"from": artifact_id, "to": finding_id, "type": "supports"}
                )
        for relationship in event.get("relationships") or []:
            source = event_id if relationship.get("from") == "event" else relationship.get("from")
            destination = event_id if relationship.get("to") == "event" else relationship.get("to")
            relationships.append(
                {"from": source, "to": destination, "type": relationship.get("type")}
            )
            if record_id and (source == event_id or destination == event_id):
                relationships.append(
                    {
                        "from": record_id if source == event_id else source,
                        "to": record_id if destination == event_id else destination,
                        "type": relationship.get("type"),
                    }
                )

        for relationship in relationships:
            key = (
                relationship.get("from"),
                relationship.get("to"),
                relationship.get("type"),
            )
            if not all(key) or key[0] == key[1]:
                continue
            existing = next(
                (
                    item
                    for item in graph["relationships"]
                    if (item.get("from"), item.get("to"), item.get("type")) == key
                ),
                None,
            )
            if existing:
                existing["event_ids"] = list(
                    dict.fromkeys([*(existing.get("event_ids") or []), event_id])
                )
                existing["last_seen_at"] = event.get("recorded_at", _now())
                continue
            digest = hashlib.sha256("|".join(str(part) for part in key).encode()).hexdigest()
            graph["relationships"].append(
                {
                    "id": f"rel-{digest[:12]}",
                    **relationship,
                    "event_ids": [event_id] if event_id else [],
                    "first_seen_at": event.get("recorded_at", _now()),
                    "last_seen_at": event.get("recorded_at", _now()),
                }
            )

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
            "actor": self._actor(),
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
            "actor": self._actor(),
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
            "actor": self._actor(),
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
            "actor": self._actor(),
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
        action["completed_by"] = self._actor()
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
            "actor": self._actor(),
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
        ][:limit]

    @staticmethod
    def _graph_key(engagement_id: str) -> str:
        return f"attackgraph:{engagement_id}"

    def _save_graph(self, engagement_id: str, graph: dict[str, Any]) -> None:
        self.client.set_state(self._graph_key(engagement_id), redact(graph))

    def _event(self, engagement_id: str, event_type: str, payload: Any) -> None:
        self.client.write_event(
            evaluated={
                "engagement_id": engagement_id,
                "type": event_type,
                "actor_id": self.actor_id,
                "actor_type": self.actor_type,
            },
            acted=redact(payload),
            forward=None,
            extra={
                "product": "h1dr4-attackgraph",
                "schema_version": 2,
                "actor": self._actor(),
            },
        )
