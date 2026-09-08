from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .identity import IdentityError, IdentityStore
from .memory import EngagementNotFoundError
from .posture import derive_engagement_posture
from .service import AttackGraphService

_TRANSPORT_TITLE = re.compile(
    r"^(?:imported\s+)?h3retik\s+(?:action|result)(?:\s+for)?(?:\s+action)?\b",
    re.IGNORECASE,
)
_ACTION_REFERENCE = re.compile(r"\bact-[A-Za-z0-9]+\b")

_ROOM_ENTITY_TYPES = {"asset", "endpoint", "identity"}
_LEGACY_ROOM_KINDS = {
    "confirmed_vulnerability",
    "finding",
    "observation",
    "surface",
    "service",
    "host",
    "endpoint",
    "asset",
}

_ARTIFACT_LABELS = {
    "capture": "CAPTURE",
    "credential": "CREDENTIAL",
    "dataset": "DATASET",
    "document": "DOCUMENT",
    "log": "LOG",
    "request": "REQUEST",
    "response": "RESPONSE",
    "secret": "SECRET",
    "session": "SESSION MATERIAL",
    "source": "SOURCE MATERIAL",
    "other": "COLLECTED ARTIFACT",
}


def _short(value: str, limit: int = 28) -> str:
    return value if len(value) <= limit else f"{value[: limit - 1]}…"


def _job_id(item: dict[str, Any]) -> str:
    if item.get("job_id"):
        return str(item["job_id"])
    source = str(item.get("source") or "")
    if source.startswith("h3retik:"):
        return source.removeprefix("h3retik:")
    for container_name in ("result", "evidence", "proof"):
        container = item.get(container_name)
        if isinstance(container, dict) and container.get("job_id"):
            return str(container["job_id"])
    return ""


def _artifact_evidence(item: dict[str, Any]) -> dict[str, Any]:
    for key in ("evidence", "result"):
        value = item.get(key)
        if isinstance(value, dict) and value:
            return value
    return {}


def _contains_sensitive_telemetry(value: Any, key: str = "") -> bool:
    sensitive_keys = (
        "authorization",
        "cookie",
        "credential",
        "password",
        "private",
        "secret",
        "session",
        "token",
    )
    if any(term in key.lower() for term in sensitive_keys):
        return True
    if isinstance(value, dict):
        return any(
            _contains_sensitive_telemetry(item, str(item_key)) for item_key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_telemetry(item, key) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        return "bearer " in lowered or "authorization:" in lowered
    return False


def _artifact_type(item: dict[str, Any], evidence: dict[str, Any]) -> str:
    text = f"{item.get('kind', '')} {item.get('source', '')} {' '.join(evidence)}".lower()
    if _contains_sensitive_telemetry(evidence):
        return "SECRET TELEMETRY"
    if any(term in text for term in ("screenshot", "image", "capture")):
        return "CAPTURE"
    if any(term in text for term in ("endpoint", "route", "url", "host")):
        return "SURFACE INTEL"
    if str(item.get("source") or "").startswith("h3retik:"):
        return "JOB OUTPUT"
    if item.get("kind") == "finding":
        return "FINDING EVIDENCE"
    if item.get("kind") == "loot":
        return "LOOT"
    return "TELEMETRY"


def _artifact_summary(
    item: dict[str, Any], record: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    evidence_record = record or item
    evidence = _artifact_evidence(evidence_record)
    source = str(item.get("source") or "")
    is_materialized = bool(item.get("record_id"))
    if not is_materialized and item.get("kind") != "loot":
        return None
    if (
        not is_materialized
        and not evidence
        and not source.startswith("h3retik:")
        and item.get("kind") != "loot"
    ):
        return None
    encoded = json.dumps(evidence, sort_keys=True, default=str).encode()
    actor = item.get("actor") or {}
    sensitivity = str(item.get("sensitivity") or "")
    sensitive = bool(item.get("sensitive")) or sensitivity in {
        "sensitive",
        "restricted",
    } or _contains_sensitive_telemetry(evidence)
    artifact_type = (
        _ARTIFACT_LABELS.get(str(item.get("type") or "other"), "COLLECTED ARTIFACT")
        if is_materialized
        else _artifact_type(item, evidence)
    )
    integrity = str(item.get("digest") or "")
    if integrity.startswith("sha256:"):
        integrity = integrity.removeprefix("sha256:")
    return {
        "id": item.get("id", ""),
        "label": _short(
            str(item.get("label") or item.get("statement") or "Collected artifact"), 46
        ),
        "type": artifact_type,
        "source": source or "sibyl-memory",
        "sensitive": sensitive,
        "sealed_preview": "•••• •••• •••• ••••" if sensitive else "TELEMETRY SEALED",
        "has_reveal": bool(evidence),
        "size_bytes": int(item.get("size_bytes") or len(encoded)),
        "integrity": (integrity or hashlib.sha256(encoded).hexdigest())[:16],
        "recorded_at": item.get("recorded_at", ""),
        "actor_id": actor.get("id", ""),
        "actor_name": actor.get("name", ""),
        "job_id": _job_id(item),
        "assurance": item.get("assurance", "asserted"),
        "entity_ids": item.get("entity_ids") or [],
        "finding_ids": item.get("finding_ids") or [],
    }


def _finding_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id", ""),
        "title": item.get("statement", "Evidence"),
        "confidence": item.get("confidence", 0),
        "assurance": (item.get("evidence") or {}).get("telemetry", {}).get(
            "assurance", "asserted"
        ),
        "source": item.get("source", "sibyl-memory"),
        "recorded_at": item.get("recorded_at", ""),
    }


def _seal_snapshot_telemetry(value: Any) -> Any:
    if isinstance(value, list):
        return [_seal_snapshot_telemetry(item) for item in value]
    if not isinstance(value, dict):
        return value
    proof = value.get("proof") if isinstance(value.get("proof"), dict) else None
    sealed = any(key in value and bool(value[key]) for key in ("evidence", "result")) or bool(
        proof and proof.get("evidence")
    )
    result = {
        key: _seal_snapshot_telemetry(item)
        for key, item in value.items()
        if key not in {"evidence", "result", "proof"}
    }
    if proof:
        result["proof"] = {
            key: _seal_snapshot_telemetry(item)
            for key, item in proof.items()
            if key != "evidence"
        }
    if sealed:
        result["telemetry_sealed"] = True
    return result


def _positions(kind: str, index: int) -> tuple[int, int]:
    positions = {
        "confirmed": [(24, 22), (48, 17), (73, 23), (83, 41), (68, 57)],
        "hypothesis": [(22, 52), (28, 72), (45, 78), (13, 68)],
        "action": [(80, 67), (66, 78), (88, 82)],
        "regression": [(50, 88), (35, 88), (65, 88)],
    }
    choices = positions[kind]
    return choices[index % len(choices)]


def _entity_position(entity_id: str) -> tuple[int, int]:
    digest = hashlib.sha256(entity_id.encode()).digest()
    return 14 + digest[0] % 73, 12 + digest[1] % 72


def _semantic_event_copy(event: dict[str, Any]) -> tuple[str, str, str]:
    presentation = (
        event.get("presentation") if isinstance(event.get("presentation"), dict) else {}
    )
    event_type = str(event.get("event_type") or "telemetry_recorded")
    title = str(presentation.get("title") or event.get("summary") or "Telemetry recorded")
    if _TRANSPORT_TITLE.match(title):
        title = str(event.get("technique") or event_type.replace(".", " "))
    detail = str(
        presentation.get("detail")
        or " · ".join(
            part
            for part in (
                event_type.replace(".", " ").title(),
                str(event.get("outcome") or "").replace("_", " ").upper(),
            )
            if part and part != "UNKNOWN"
        )
    )
    subject_id = str(presentation.get("subject_id") or "")
    return title, detail, subject_id


def build_dashboard_snapshot(service: AttackGraphService, engagement_id: str) -> dict[str, Any]:
    context = service.context(engagement_id, event_limit=40)
    brief = service.brief(engagement_id)
    engagement = context["engagement"]
    graph = context["graph"]
    target_id = "target"
    nodes: list[dict[str, Any]] = [
        {
            "id": target_id,
            "label": engagement["target"],
            "meta": "PRIMARY TARGET",
            "kind": "target",
            "x": 50,
            "y": 43,
            "entity_type": "target",
            "layer": "surface",
            "detail": {
                "scope": engagement["scope"],
                "findings": [],
                "loot": [],
                "relationships": [],
                "activity": [],
            },
        }
    ]
    edges: list[dict[str, Any]] = []
    observations = {str(item.get("id")): item for item in graph.get("observations", [])}
    actions = {str(item.get("id")): item for item in graph.get("actions", [])}

    for entity in graph.get("entities", []):
        if entity.get("type") not in _ROOM_ENTITY_TYPES:
            continue
        x, y = _entity_position(str(entity["id"]))
        actor = entity.get("actor") or {}
        session_ids = entity.get("h3retik_session_ids") or []
        job_ids = entity.get("job_ids") or []
        nodes.append(
            {
                "id": entity["id"],
                "label": _short(str(entity.get("label") or entity["id"]), 36),
                "meta": (
                    f"{str(entity.get('type') or 'ENTITY').upper()} · "
                    f"{str(entity.get('assurance') or 'asserted').upper()}"
                ),
                "kind": "entity",
                "entity_type": entity.get("type", "asset"),
                "layer": entity.get("layer", ""),
                "x": x,
                "y": y,
                "detail": {
                    "entity": _seal_snapshot_telemetry(entity),
                    "findings": [],
                    "loot": [],
                    "relationships": [],
                    "activity": [],
                },
                "actor_id": actor.get("id", ""),
                "actor_name": actor.get("name", ""),
                "h3retik_session_id": session_ids[-1] if session_ids else "",
                "job_id": job_ids[-1] if job_ids else "",
            }
        )

    node_ids = {str(node["id"]) for node in nodes}
    findings = brief.get("findings", [])
    linked_finding_ids: set[str] = set()
    for item in findings:
        entity_ids = [
            str(value) for value in item.get("entity_ids") or [] if str(value) in node_ids
        ]
        if entity_ids:
            linked_finding_ids.add(str(item["id"]))

    # Legacy evidence remains navigable until integrations emit stable entities.
    legacy_candidates = list(
        {
            str(item.get("id")): item
            for item in [*findings, *brief["confirmed"]]
            if item.get("kind") in _LEGACY_ROOM_KINDS
        }.values()
    )
    legacy_findings = [
        item
        for item in legacy_candidates
        if str(item.get("id")) not in linked_finding_ids
        and not any(str(value) in node_ids for value in item.get("entity_ids") or [])
    ]
    for index, item in enumerate(legacy_findings[:8]):
        x, y = _positions("confirmed", index)
        actor = item.get("actor") or {}
        legacy_kind = (
            "FINDING"
            if item.get("kind") in {"finding", "confirmed_vulnerability"}
            else "EVIDENCE"
        )
        own_findings = [_finding_summary(item)] if legacy_kind == "FINDING" else []
        nodes.append(
            {
                "id": item["id"],
                "label": _short(str(item.get("statement") or "Evidence")),
                "meta": f"{legacy_kind} · {float(item.get('confidence') or 0):.2f}",
                "kind": "confirmed",
                "entity_type": "legacy_evidence",
                "layer": "",
                "x": x,
                "y": y,
                "detail": {
                    "record": _seal_snapshot_telemetry(item),
                    "findings": own_findings,
                    "loot": [],
                    "relationships": [],
                    "activity": [],
                },
                "actor_id": actor.get("id", ""),
                "actor_name": actor.get("name", ""),
                "h3retik_session_id": item.get("h3retik_session_id", ""),
                "job_id": _job_id(item),
            }
        )
    node_ids = {str(node["id"]) for node in nodes}

    for relationship in graph.get("relationships", []):
        source = str(relationship.get("from") or "")
        destination = str(relationship.get("to") or "")
        if source in node_ids and destination in node_ids:
            edges.append(
                {
                    "id": relationship.get("id")
                    or f"edge:{source}:{relationship.get('type')}:{destination}",
                    "from": source,
                    "to": destination,
                    "type": relationship.get("type", "related_to"),
                    "label": str(relationship.get("type") or "related to").replace("_", " "),
                }
            )

    edge_keys = {(str(edge["from"]), str(edge["to"])) for edge in edges}
    for node in nodes:
        node_id = str(node["id"])
        if node_id == target_id:
            continue
        connected = any(node_id in pair for pair in edge_keys)
        if not connected:
            edges.append(
                {
                    "id": f"edge:target:contains:{node_id}",
                    "from": target_id,
                    "to": node_id,
                    "type": "contains",
                    "label": "contains",
                }
            )

    artifact_records: list[dict[str, Any]] = []
    materialized_record_ids: set[str] = set()
    for artifact in graph.get("artifacts", []):
        record_id = str(artifact.get("record_id") or "")
        record = observations.get(record_id)
        summary = _artifact_summary(artifact, record)
        if summary:
            artifact_records.append(summary)
            materialized_record_ids.add(record_id)
    for item in graph.get("observations", []):
        if str(item.get("id") or "") in materialized_record_ids:
            continue
        summary = _artifact_summary(item)
        if summary:
            artifact_records.append(summary)

    node_by_id = {str(node["id"]): node for node in nodes}
    for finding in findings:
        summary = _finding_summary(finding)
        for entity_id in finding.get("entity_ids") or []:
            node = node_by_id.get(str(entity_id))
            if node:
                node["detail"]["findings"].append(summary)
    for artifact in artifact_records:
        artifact["entity_labels"] = [
            str(node_by_id[str(entity_id)]["label"])
            for entity_id in artifact.get("entity_ids") or []
            if str(entity_id) in node_by_id
        ]
        for entity_id in artifact.get("entity_ids") or []:
            node = node_by_id.get(str(entity_id))
            if node:
                node["detail"]["loot"].append(artifact)
    for edge in edges:
        source = str(edge["from"])
        destination = str(edge["to"])
        if source in node_by_id:
            node_by_id[source]["detail"]["relationships"].append(
                {
                    "edge_id": edge["id"],
                    "direction": "outbound",
                    "type": edge["type"],
                    "node_id": destination,
                    "label": node_by_id.get(destination, {}).get("label", destination),
                }
            )
        if destination in node_by_id:
            node_by_id[destination]["detail"]["relationships"].append(
                {
                    "edge_id": edge["id"],
                    "direction": "inbound",
                    "type": edge["type"],
                    "node_id": source,
                    "label": node_by_id.get(source, {}).get("label", source),
                }
            )

    events = []
    for event in context["recent_events"][:12]:
        evaluated = event.get("evaluated") or {}
        acted = event.get("acted") or {}
        event_type = evaluated.get("type", "memory_event")
        actor = (event.get("extra") or {}).get("actor") or acted.get("actor") or {}
        title_source = event_type
        subject_id = ""
        observation_kind = str(acted.get("kind") or "")
        if event_type == "observation_recorded" and observation_kind not in {"", "observation"}:
            title_source = observation_kind
        if event_type in {"telemetry_recorded", "telemetry_promoted"}:
            title_source, detail, subject_id = _semantic_event_copy(acted)
        else:
            detail = (
                acted.get("statement")
                or acted.get("approach")
                or acted.get("purpose")
                or acted.get("name")
                or acted.get("summary")
                or event_type.replace("_", " ")
            )
            if observation_kind in {"execution_assertion", "execution_evidence"} and (
                _TRANSPORT_TITLE.match(str(detail))
            ):
                referenced_action = _ACTION_REFERENCE.search(str(detail))
                action_id = str(
                    acted.get("action_id")
                    or (referenced_action.group(0) if referenced_action else "")
                )
                action = actions.get(action_id, {})
                title_source = str(action.get("purpose") or "Execution completed")
                detail = "Execution completed · H3RETIK proof retained"
            else:
                title_source = title_source.replace("_", " ").replace(".", " ").title()
        record_id = str(acted.get("record_id") or "")
        object_id = (
            subject_id
            if subject_id in node_ids and subject_id != target_id
            else record_id
            if record_id in node_ids
            else subject_id
            if subject_id in node_ids
            else ""
        )
        if object_id not in node_ids:
            object_id = str(acted.get("id") or "") if str(acted.get("id") or "") in node_ids else ""
        events.append(
            {
                "id": event["id"],
                "time": event["ts"],
                "type": str(acted.get("event_type") or event_type)
                if event_type in {"telemetry_recorded", "telemetry_promoted"}
                else event_type,
                "title": _short(str(title_source), 72),
                "detail": _short(str(detail), 72),
                "actor_id": actor.get("id", evaluated.get("actor_id", "")),
                "actor_name": actor.get("name", ""),
                "actor_type": actor.get("type", evaluated.get("actor_type", "")),
                "object_id": object_id,
                "h3retik_session_id": acted.get("h3retik_session_id", ""),
                "job_id": _job_id(acted),
            }
        )
        if subject_id in node_by_id:
            node_by_id[subject_id]["detail"]["activity"].append(
                {
                    "id": event["id"],
                    "time": event["ts"],
                    "title": _short(str(title_source), 72),
                    "detail": _short(str(detail), 72),
                }
            )

    pending_actions = brief["pending_actions"]
    loot = artifact_records
    posture = derive_engagement_posture(engagement, graph)
    last_event = events[0]["time"] if events else engagement.get("created_at", "")
    return {
        "engagement": engagement,
        "posture": posture,
        "brief": _seal_snapshot_telemetry(brief),
        "stats": {
            "nodes": len(nodes),
            "evidence": len(graph["observations"]),
            "pending": len(pending_actions),
            "loot": len(loot),
            "telemetry": len(graph.get("telemetry", [])),
            "relationships": len(graph.get("relationships", [])),
        },
        "nodes": nodes,
        "edges": edges,
        "events": events,
        "loot": loot,
        "primary_action": pending_actions[-1] if pending_actions else None,
        "memory": {"online": True, "last_event": last_event, "event_count": len(events)},
    }


def create_dashboard_app(
    service: AttackGraphService | None = None,
    static_dir: str | Path | None = None,
    identity: IdentityStore | None = None,
) -> Starlette:
    control_store = identity or IdentityStore(
        os.getenv("ATTACKGRAPH_CONTROL_DB_PATH", ".attackgraph/control.db")
    )
    graph_service = service or AttackGraphService(
        db_path=os.getenv("ATTACKGRAPH_DB_PATH", ".attackgraph/sibyl.db"),
        operator_id=os.getenv("ATTACKGRAPH_OPERATOR_ID", "local-operator"),
    )
    auth_mode = os.getenv("ATTACKGRAPH_AUTH_MODE", "optional").strip().lower()
    rp_id = os.getenv("ATTACKGRAPH_RP_ID", "localhost")
    origin = os.getenv("ATTACKGRAPH_ORIGIN", "http://localhost:3000").rstrip("/")
    session_cookie = "attackgraph_session"

    def current_user(request: Request) -> dict[str, Any] | None:
        return control_store.browser_user(request.cookies.get(session_cookie, ""))

    def auth_state(request: Request) -> tuple[str, dict[str, Any] | None]:
        user = current_user(request)
        if auth_mode == "disabled":
            return "open", user
        if user:
            return "authenticated", user
        if control_store.passkey_count() == 0:
            return "setup", None
        return "locked", None

    def require_dashboard_access(request: Request) -> dict[str, Any] | None:
        state, user = auth_state(request)
        if state == "locked":
            raise PermissionError("passkey_required")
        return user

    def require_engagement_access(
        request: Request, engagement_id: str, *, write: bool = False
    ) -> dict[str, Any] | None:
        user = require_dashboard_access(request)
        if user:
            role = control_store.membership_role(engagement_id, "human", str(user["user_id"]))
            if not role:
                raise PermissionError("engagement_access_denied")
            if write and role not in {"owner", "operator"}:
                raise PermissionError("operator_role_required")
        return user

    async def payload(request: Request) -> dict[str, Any]:
        value = await request.json()
        if not isinstance(value, dict):
            raise IdentityError("json_object_required")
        return value

    def session_response(body: dict[str, Any], token: str) -> JSONResponse:
        response = JSONResponse(body)
        response.set_cookie(
            session_cookie,
            token,
            max_age=12 * 60 * 60,
            httponly=True,
            secure=origin.startswith("https://"),
            samesite="strict",
            path="/",
        )
        return response

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "h1dr4-attackgraph-dashboard"})

    async def status(request: Request) -> JSONResponse:
        state, user = auth_state(request)
        return JSONResponse(
            {
                "mode": auth_mode,
                "state": state,
                "authenticated": user is not None,
                "user": user,
                "passkey_count": control_store.passkey_count(),
                "passkey_supported": True,
            }
        )

    async def register_options(request: Request) -> JSONResponse:
        body = await payload(request)
        user = current_user(request)
        result = control_store.begin_passkey_registration(
            display_name=str(body.get("display_name") or ""),
            invite_token=str(body.get("invite_token") or ""),
            current_user_id=str(user["user_id"]) if user else "",
            rp_id=rp_id,
            rp_name="H1DR4 ATTACKGRAPH",
        )
        return JSONResponse(result)

    async def register_verify(request: Request) -> JSONResponse:
        body = await payload(request)
        user, token = control_store.finish_passkey_registration(
            challenge_id=str(body.get("challenge_id") or ""),
            credential=body.get("credential") or {},
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        if control_store.passkey_count() == 1 and not control_store.engagement_ids_for(
            "human", str(user["user_id"])
        ):
            for item in graph_service.list_engagements():
                control_store.add_membership(
                    item["engagement_id"], "human", str(user["user_id"]), "owner"
                )
        return session_response({"ok": True, "user": user}, token)

    async def login_options(_: Request) -> JSONResponse:
        return JSONResponse(control_store.begin_passkey_authentication(rp_id=rp_id))

    async def login_verify(request: Request) -> JSONResponse:
        body = await payload(request)
        user, token = control_store.finish_passkey_authentication(
            challenge_id=str(body.get("challenge_id") or ""),
            credential=body.get("credential") or {},
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        return session_response({"ok": True, "user": user}, token)

    async def logout(request: Request) -> JSONResponse:
        control_store.revoke_browser_session(request.cookies.get(session_cookie, ""))
        response = JSONResponse({"ok": True})
        response.delete_cookie(session_cookie, path="/")
        return response

    async def engagements(request: Request) -> JSONResponse:
        user = require_dashboard_access(request)
        items = graph_service.list_engagements()
        if user:
            allowed = control_store.engagement_ids_for("human", str(user["user_id"]))
            items = [item for item in items if item["engagement_id"] in allowed]
        return JSONResponse({"engagements": items})

    async def create_engagement(request: Request) -> JSONResponse:
        body = await payload(request)
        user = require_dashboard_access(request)
        title = str(body.get("title") or "").strip()
        target = str(body.get("target") or "").strip()
        scope = str(body.get("scope") or "").strip()
        if not title or not target or not scope:
            raise IdentityError("title_target_and_scope_required")
        lanes = body.get("allowed_lanes") or ["web", "local", "osint"]
        if not isinstance(lanes, list) or not all(isinstance(item, str) for item in lanes):
            raise IdentityError("allowed_lanes_must_be_strings")
        created = graph_service.open_engagement(
            title=title[:120],
            target=target[:255],
            mode=str(body.get("mode") or "manual_only"),
            scope=scope[:500],
            target_allowlist=[target[:255]],
            rules=["Use only on explicitly authorized targets"],
            allowed_lanes=lanes,
        )
        if user:
            control_store.add_membership(
                created["engagement_id"], "human", str(user["user_id"]), "owner"
            )
        return JSONResponse(created, status_code=201)

    async def engagement(request: Request) -> JSONResponse:
        engagement_id = request.path_params["engagement_id"]
        try:
            require_engagement_access(request, engagement_id)
            return JSONResponse(build_dashboard_snapshot(graph_service, engagement_id))
        except EngagementNotFoundError:
            return JSONResponse({"error": "engagement_not_found"}, status_code=404)

    async def export_engagement(request: Request) -> JSONResponse:
        engagement_id = request.path_params["engagement_id"]
        try:
            require_engagement_access(request, engagement_id)
            payload = graph_service.context(engagement_id, event_limit=500)
        except EngagementNotFoundError:
            return JSONResponse({"error": "engagement_not_found"}, status_code=404)
        return JSONResponse(
            payload,
            headers={
                "Content-Disposition": f'attachment; filename="{engagement_id}-attackgraph.json"'
            },
        )

    async def loot_artifact(request: Request) -> JSONResponse:
        engagement_id = request.path_params["engagement_id"]
        artifact_id = request.path_params["artifact_id"]
        try:
            require_engagement_access(request, engagement_id)
            graph = graph_service.context(engagement_id, event_limit=1)["graph"]
        except EngagementNotFoundError:
            return JSONResponse({"error": "engagement_not_found"}, status_code=404)
        artifact = next(
            (
                candidate
                for candidate in graph.get("artifacts", [])
                if candidate.get("id") == artifact_id
            ),
            None,
        )
        item = None
        if artifact:
            item = next(
                (
                    candidate
                    for candidate in graph["observations"]
                    if candidate.get("id") == artifact.get("record_id")
                ),
                None,
            )
        if item is None:
            item = next(
                (
                    candidate
                    for candidate in graph["observations"]
                    if candidate.get("id") == artifact_id
                ),
                None,
            )
        if item is None:
            return JSONResponse({"error": "artifact_not_found"}, status_code=404)
        summary = _artifact_summary(artifact, item) if artifact else _artifact_summary(item)
        if summary is None:
            return JSONResponse({"error": "artifact_has_no_telemetry"}, status_code=404)
        return JSONResponse(
            {
                **summary,
                "telemetry": _artifact_evidence(item),
                "disclosure": "Fetched on demand; not embedded in the dashboard snapshot.",
            }
        )

    async def identity_snapshot(request: Request) -> JSONResponse:
        engagement_id = request.path_params["engagement_id"]
        require_engagement_access(request, engagement_id)
        sessions = control_store.list_h3retik_sessions(engagement_id)
        workspace_state: dict[str, Any] = {"configured": False, "available": False}
        if os.getenv("H3RETIK_WALLET") and os.getenv("H3RETIK_TOKEN"):
            workspace_state["configured"] = True
            try:
                remote = graph_service.h3retik_workspace(engagement_id)
                workspace = remote.get("workspace", remote) if isinstance(remote, dict) else {}
                workspace_state = {"configured": True, "available": True, **workspace}
                remote_sessions = {
                    str(item.get("session", {}).get("session_id")): item
                    for item in workspace.get("sessions", [])
                    if isinstance(item, dict) and isinstance(item.get("session"), dict)
                }
                sessions = [
                    {
                        **session,
                        **remote_sessions.get(str(session["session_id"]), {}).get("session", {}),
                        "lane": remote_sessions.get(str(session["session_id"]), {})
                        .get("attachment", {})
                        .get("lane", session.get("lane", "")),
                    }
                    for session in sessions
                ]
            except Exception as exc:
                workspace_state["error"] = type(exc).__name__
        return JSONResponse(
            {
                "members": control_store.list_members(engagement_id),
                "agents": control_store.list_agents(engagement_id),
                "h3retik_sessions": sessions,
                "h3retik_workspace": workspace_state,
            }
        )

    async def create_agent(request: Request) -> JSONResponse:
        body = await payload(request)
        engagement_id = str(body.get("engagement_id") or "")
        user = require_engagement_access(request, engagement_id, write=True)
        created = control_store.create_agent(
            owner_user_id=str(user["user_id"]) if user else "",
            name=str(body.get("name") or ""),
            engagement_id=engagement_id,
        )
        token = str(created["token"])
        project_root = str(Path(__file__).resolve().parents[2])
        created["mcp_config"] = {
            "mcpServers": {
                "h1dr4-attackgraph": {
                    "command": "uv",
                    "args": ["run", "--project", project_root, "h1dr4-attackgraph"],
                    "env": {
                        "ATTACKGRAPH_DB_PATH": str(graph_service.memory.path.resolve()),
                        "ATTACKGRAPH_CONTROL_DB_PATH": str(control_store.path.resolve()),
                        "ATTACKGRAPH_OPERATOR_ID": os.getenv(
                            "ATTACKGRAPH_OPERATOR_ID", "local-operator"
                        ),
                        "ATTACKGRAPH_AGENT_TOKEN": token,
                    },
                }
            }
        }
        return JSONResponse(created, status_code=201)

    async def revoke_agent(request: Request) -> JSONResponse:
        body = await payload(request)
        engagement_id = str(body.get("engagement_id") or "")
        require_engagement_access(request, engagement_id, write=True)
        agent_id = request.path_params["agent_id"]
        if not any(
            item["agent_id"] == agent_id for item in control_store.list_agents(engagement_id)
        ):
            return JSONResponse({"error": "agent_not_found"}, status_code=404)
        control_store.revoke_agent(agent_id)
        return JSONResponse({"ok": True, "agent_id": agent_id})

    async def create_invite(request: Request) -> JSONResponse:
        body = await payload(request)
        engagement_id = str(body.get("engagement_id") or "")
        user = require_engagement_access(request, engagement_id, write=True)
        invite = control_store.create_invite(
            created_by=str(user["user_id"]) if user else "local-operator",
            engagement_id=engagement_id,
            role=str(body.get("role") or "operator"),
            hours=int(body.get("hours") or 24),
        )
        invite["invite_url"] = f"{origin}/?invite={invite['token']}"
        return JSONResponse(invite, status_code=201)

    async def bind_h3retik_session(request: Request) -> JSONResponse:
        body = await payload(request)
        engagement_id = str(body.get("engagement_id") or "")
        user = require_engagement_access(request, engagement_id, write=True)
        session_id = str(body.get("session_id") or "").strip()
        if not session_id:
            raise IdentityError("session_id_required")
        lane = str(body.get("lane") or "").strip()[:64]
        remote_workspace = None
        if os.getenv("H3RETIK_WALLET") and os.getenv("H3RETIK_TOKEN"):
            remote_workspace = graph_service.sync_h3retik_session(
                engagement_id,
                session_id=session_id,
                label=str(body.get("label") or "H3RETIK session")[:80],
                lane=lane,
            )
        binding = control_store.bind_h3retik_session(
            engagement_id=engagement_id,
            session_id=session_id,
            label=str(body.get("label") or "H3RETIK session")[:80],
            lane=lane,
            attached_by=str(user["user_id"]) if user else "local-operator",
        )
        if remote_workspace is not None:
            binding["remote_workspace"] = remote_workspace
        return JSONResponse(binding, status_code=201)

    async def h3retik_workspace(request: Request) -> JSONResponse:
        engagement_id = str(request.path_params["engagement_id"])
        require_engagement_access(request, engagement_id)
        return JSONResponse(graph_service.h3retik_workspace(engagement_id))

    async def create_h3retik_extension_receipt(request: Request) -> JSONResponse:
        body = await payload(request)
        engagement_id = str(body.get("engagement_id") or "")
        require_engagement_access(request, engagement_id, write=True)
        session_id = str(request.path_params["session_id"])
        bound_session_ids = {
            str(item["session_id"])
            for item in control_store.list_h3retik_sessions(engagement_id)
        }
        if session_id not in bound_session_ids:
            return JSONResponse({"error": "h3retik_session_not_bound"}, status_code=404)
        return JSONResponse(
            graph_service.create_h3retik_extension_receipt(
                engagement_id,
                session_id=session_id,
                minutes=int(body.get("minutes") or 0),
                actions=int(body.get("actions") or 0),
                asset=str(body.get("asset") or "USDC"),
            ),
            status_code=201,
        )

    async def sync_h3retik_receipt(request: Request) -> JSONResponse:
        body = await payload(request)
        engagement_id = str(body.get("engagement_id") or "")
        require_engagement_access(request, engagement_id, write=True)
        return JSONResponse(
            graph_service.sync_h3retik_receipt(
                engagement_id,
                str(request.path_params["receipt_id"]),
            )
        )

    routes = [
        Route("/api/health", health),
        Route("/api/auth/status", status),
        Route("/api/auth/passkey/register/options", register_options, methods=["POST"]),
        Route("/api/auth/passkey/register/verify", register_verify, methods=["POST"]),
        Route("/api/auth/passkey/login/options", login_options, methods=["POST"]),
        Route("/api/auth/passkey/login/verify", login_verify, methods=["POST"]),
        Route("/api/auth/logout", logout, methods=["POST"]),
        Route("/api/engagements", engagements),
        Route("/api/engagements", create_engagement, methods=["POST"]),
        Route("/api/engagements/{engagement_id}", engagement),
        Route("/api/engagements/{engagement_id}/export", export_engagement),
        Route("/api/engagements/{engagement_id}/loot/{artifact_id}", loot_artifact),
        Route("/api/engagements/{engagement_id}/identity", identity_snapshot),
        Route("/api/agents", create_agent, methods=["POST"]),
        Route("/api/agents/{agent_id}/revoke", revoke_agent, methods=["POST"]),
        Route("/api/invites", create_invite, methods=["POST"]),
        Route("/api/h3retik-sessions", bind_h3retik_session, methods=["POST"]),
        Route(
            "/api/engagements/{engagement_id}/h3retik-workspace",
            h3retik_workspace,
        ),
        Route(
            "/api/h3retik-sessions/{session_id}/extension-receipts",
            create_h3retik_extension_receipt,
            methods=["POST"],
        ),
        Route(
            "/api/h3retik-receipts/{receipt_id}/sync",
            sync_h3retik_receipt,
            methods=["POST"],
        ),
    ]
    if static_dir and Path(static_dir).is_dir():
        index_path = Path(static_dir) / "index.html"

        async def index(_: Request) -> FileResponse:
            return FileResponse(index_path)

        routes.extend([Route("/", index), Mount("/", app=StaticFiles(directory=static_dir))])

    app = Starlette(debug=False, routes=routes)

    async def permission_error(_: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=401)

    async def identity_error(_: Request, exc: IdentityError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=400)

    async def value_error(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=400)

    app.add_exception_handler(PermissionError, permission_error)
    app.add_exception_handler(IdentityError, identity_error)
    app.add_exception_handler(ValueError, value_error)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        allow_credentials=True,
    )
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local H1DR4 ATTACKGRAPH dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7784)
    parser.add_argument("--static-dir", default=os.getenv("ATTACKGRAPH_DASHBOARD_STATIC", ""))
    args = parser.parse_args()
    app = create_dashboard_app(static_dir=args.static_dir or None)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
