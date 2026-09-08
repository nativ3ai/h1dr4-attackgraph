from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from .redaction import redact

SCHEMA_VERSION = "h1dr4.telemetry.v1"

EVENT_TYPES = {
    "execution.started",
    "execution.completed",
    "attempt.completed",
    "finding.observed",
    "finding.confirmed",
    "loot.discovered",
    "checkpoint.written",
}

OUTCOMES = {
    "in_progress",
    "success",
    "failed",
    "blocked",
    "no_finding",
    "unknown",
}

ENTITY_TYPES = {
    "target",
    "asset",
    "endpoint",
    "identity",
    "credential",
    "finding",
    "artifact",
    "agent",
    "session",
    "job",
    "technique",
}

ENTITY_LAYERS = {
    "surface",
    "perimeter",
    "application",
    "control",
    "trust",
    "identity",
    "privilege",
    "infrastructure",
    "data",
    "impact",
    "custom",
}

ARTIFACT_TYPES = {
    "capture",
    "credential",
    "dataset",
    "document",
    "log",
    "request",
    "response",
    "secret",
    "session",
    "source",
    "other",
}

ARTIFACT_SENSITIVITY = {"public", "internal", "sensitive", "restricted"}

RELATIONSHIP_TYPES = {
    "communicates_with",
    "contains",
    "controls",
    "depends_on",
    "exposes",
    "targets",
    "observed_on",
    "supports",
    "produced",
    "derived_from",
    "authenticated_as",
    "accesses",
    "affects",
    "executed_by",
    "ran_in",
    "stores",
    "uses",
}

HIGH_IMPACT_POSTURES = {
    "initial_access_established",
    "foothold_active",
    "privileged_access",
    "target_compromised",
    "objective_complete",
    "regression_detected",
}

TERMINAL_STATUSES = {"completed", "succeeded", "failed", "cancelled", "expired"}
SUCCESS_STATUSES = {"completed", "succeeded"}
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,159}$")
_TRANSPORT_SUMMARY = re.compile(
    r"^(?:imported\s+)?h3retik\s+(?:action|result)(?:\s+for)?(?:\s+action)?\b",
    re.IGNORECASE,
)

_EVENT_LABELS = {
    "execution.started": "Execution started",
    "execution.completed": "Execution completed",
    "attempt.completed": "Attack attempt completed",
    "finding.observed": "Potential finding observed",
    "finding.confirmed": "Finding confirmed",
    "loot.discovered": "Artifact collected",
    "checkpoint.written": "Checkpoint written",
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def reporting_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "purpose": (
            "Translate agent activity into typed Sibyl memory. Agent reports are assertions; "
            "only correlated executor attestations can become verified evidence."
        ),
        "grid": [
            {"when": "before execution", "tool": "attackgraph_request_action"},
            {"when": "command starts", "event_type": "execution.started"},
            {"when": "command finishes", "event_type": "execution.completed"},
            {"when": "a path is tested", "event_type": "attempt.completed"},
            {"when": "a possible vulnerability appears", "event_type": "finding.observed"},
            {"when": "proof establishes a vulnerability", "event_type": "finding.confirmed"},
            {"when": "an artifact is collected", "event_type": "loot.discovered"},
            {"when": "a phase or session ends", "event_type": "checkpoint.written"},
        ],
        "event_types": sorted(EVENT_TYPES),
        "outcomes": sorted(OUTCOMES),
        "entity_types": sorted(ENTITY_TYPES),
        "entity_layers": sorted(ENTITY_LAYERS),
        "relationship_types": sorted(RELATIONSHIP_TYPES),
        "artifact": {
            "types": sorted(ARTIFACT_TYPES),
            "sensitivity": sorted(ARTIFACT_SENSITIVITY),
            "rule": (
                "Use artifact only for loot.discovered. Store metadata and references here; "
                "put sanitized payload evidence behind the executor boundary."
            ),
        },
        "assurance": {
            "asserted": "Semantic report supplied by an agent; never promotes high-impact posture.",
            "attested": "Execution evidence is present but lacks a correlated scoped action.",
            "verified": "Executor proof is complete and correlated to a scoped AttackGraph action.",
        },
        "idempotency": (
            "Reuse one stable idempotency_key when an executor attestation promotes an earlier "
            "agent assertion. Exact repeats are deduplicated."
        ),
        "secret_policy": (
            "Send metadata, references, counts, status, and digests. Raw credentials, cookies, "
            "tokens, authorization values, private keys, and secret material are redacted."
        ),
        "presentation": {
            "summary": (
                "State what changed in operator language; never describe transport/import plumbing."
            ),
            "entity": "Reuse stable entity IDs across events so rooms and relationships persist.",
            "relationship": (
                "Connect the semantic record to the affected entity, not a session or job."
            ),
            "proof": (
                "Executor metadata establishes assurance but is never used as the display title."
            ),
        },
    }


def _clean_text(value: str, *, field: str, maximum: int, required: bool = False) -> str:
    cleaned = str(value or "").strip()
    if required and not cleaned:
        raise ValueError(f"{field}_required")
    if len(cleaned) > maximum:
        raise ValueError(f"{field}_too_long")
    return cleaned


def _clean_identifier(value: str, *, field: str, required: bool = False) -> str:
    cleaned = _clean_text(value, field=field, maximum=160, required=required)
    if cleaned and not _ID_PATTERN.fullmatch(cleaned):
        raise ValueError(f"{field}_invalid")
    return cleaned


def _normalise_entities(
    entities: list[dict[str, Any]] | None,
    *,
    known_references: set[str],
) -> list[dict[str, Any]]:
    if len(entities or []) > 25:
        raise ValueError("too_many_entities")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in entities or []:
        if not isinstance(raw, dict):
            raise ValueError("entity_must_be_an_object")
        entity_id = _clean_identifier(str(raw.get("id") or ""), field="entity_id", required=True)
        entity_type = _clean_identifier(
            str(raw.get("type") or ""), field="entity_type", required=True
        ).lower()
        if entity_type not in ENTITY_TYPES:
            raise ValueError("entity_type_invalid")
        if entity_id in seen:
            raise ValueError("duplicate_entity_id")
        seen.add(entity_id)
        entity: dict[str, Any] = {
            "id": entity_id,
            "type": entity_type,
            "label": _clean_text(
                str(raw.get("label") or entity_id), field="entity_label", maximum=160
            ),
        }
        layer = _clean_identifier(str(raw.get("layer") or ""), field="entity_layer").lower()
        if layer and layer not in ENTITY_LAYERS:
            raise ValueError("entity_layer_invalid")
        parent_id = _clean_identifier(str(raw.get("parent_id") or ""), field="entity_parent_id")
        if parent_id and parent_id not in known_references and parent_id not in {
            str(item.get("id") or "") for item in entities or [] if isinstance(item, dict)
        }:
            raise ValueError("entity_parent_unknown")
        metadata = redact(raw.get("metadata") or {})
        if not isinstance(metadata, dict):
            raise ValueError("entity_metadata_must_be_an_object")
        if layer:
            entity["layer"] = layer
        if parent_id:
            entity["parent_id"] = parent_id
        if metadata:
            entity["metadata"] = metadata
        output.append(entity)
    return output


def _normalise_relationships(
    relationships: list[dict[str, Any]] | None,
    entity_ids: set[str],
    known_references: set[str],
) -> list[dict[str, str]]:
    if len(relationships or []) > 50:
        raise ValueError("too_many_relationships")
    allowed_refs = {"event", "target", *entity_ids, *known_references}
    output: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in relationships or []:
        if not isinstance(raw, dict):
            raise ValueError("relationship_must_be_an_object")
        source = _clean_identifier(
            str(raw.get("from") or ""), field="relationship_from", required=True
        )
        destination = _clean_identifier(
            str(raw.get("to") or ""), field="relationship_to", required=True
        )
        relation_type = _clean_identifier(
            str(raw.get("type") or ""), field="relationship_type", required=True
        ).lower()
        if source not in allowed_refs or destination not in allowed_refs:
            raise ValueError("relationship_reference_unknown")
        if relation_type not in RELATIONSHIP_TYPES:
            raise ValueError("relationship_type_invalid")
        key = (source, destination, relation_type)
        if key not in seen:
            seen.add(key)
            output.append({"from": source, "to": destination, "type": relation_type})
    return output


def _normalise_artifact(
    artifact: dict[str, Any] | None,
    *,
    allowed_references: set[str],
) -> dict[str, Any]:
    if artifact is None:
        return {}
    if not isinstance(artifact, dict):
        raise ValueError("artifact_must_be_an_object")
    artifact_type = _clean_identifier(
        str(artifact.get("type") or "other"), field="artifact_type", required=True
    ).lower()
    if artifact_type not in ARTIFACT_TYPES:
        raise ValueError("artifact_type_invalid")
    sensitivity = _clean_identifier(
        str(artifact.get("sensitivity") or "internal"),
        field="artifact_sensitivity",
        required=True,
    ).lower()
    if sensitivity not in ARTIFACT_SENSITIVITY:
        raise ValueError("artifact_sensitivity_invalid")
    entity_ids = [
        _clean_identifier(str(value), field="artifact_entity_id", required=True)
        for value in artifact.get("entity_ids") or []
    ]
    finding_ids = [
        _clean_identifier(str(value), field="artifact_finding_id", required=True)
        for value in artifact.get("finding_ids") or []
    ]
    if len(entity_ids) > 25 or len(finding_ids) > 25:
        raise ValueError("too_many_artifact_references")
    if any(value not in allowed_references for value in [*entity_ids, *finding_ids]):
        raise ValueError("artifact_reference_unknown")
    metadata = redact(artifact.get("metadata") or {})
    if not isinstance(metadata, dict):
        raise ValueError("artifact_metadata_must_be_an_object")
    result: dict[str, Any] = {
        "type": artifact_type,
        "sensitivity": sensitivity,
        "entity_ids": list(dict.fromkeys(entity_ids)),
        "finding_ids": list(dict.fromkeys(finding_ids)),
    }
    for key, maximum in (
        ("id", 160),
        ("label", 160),
        ("media_type", 120),
        ("locator", 255),
        ("digest", 160),
    ):
        raw_value = str(artifact.get(key) or "")
        value = (
            _clean_identifier(raw_value, field=f"artifact_{key}")
            if key == "id"
            else _clean_text(raw_value, field=f"artifact_{key}", maximum=maximum)
        )
        if value:
            result[key] = value
    raw_size = artifact.get("size_bytes")
    if raw_size not in (None, ""):
        try:
            size_bytes = int(raw_size)
        except (TypeError, ValueError) as exc:
            raise ValueError("artifact_size_invalid") from exc
        if not 0 <= size_bytes <= 1_000_000_000_000:
            raise ValueError("artifact_size_invalid")
        result["size_bytes"] = size_bytes
    if metadata:
        result["metadata"] = metadata
    return result


def _semantic_presentation(
    *,
    event_type: str,
    summary: str,
    outcome: str,
    technique: str,
    entities: list[dict[str, Any]],
    relationships: list[dict[str, str]],
) -> dict[str, str]:
    primary = next(
        (item for item in entities if item.get("type") not in {"agent", "session", "job"}),
        None,
    )
    primary_label = str((primary or {}).get("label") or "")
    title = summary
    if _TRANSPORT_SUMMARY.match(title):
        title = technique or _EVENT_LABELS[event_type]
    parts = [_EVENT_LABELS[event_type]]
    if primary_label:
        parts.append(primary_label)
    if outcome not in {"unknown", "in_progress"}:
        parts.append(outcome.replace("_", " ").upper())
    subject_id = str((primary or {}).get("id") or "")
    if not subject_id:
        subject_id = next(
            (
                str(item["to"] if item.get("from") == "event" else item["from"])
                for item in relationships
                if "event" in {item.get("from"), item.get("to")}
                and {item.get("from"), item.get("to")} != {"event", "target"}
            ),
            "target",
        )
    return {
        "title": title,
        "detail": " · ".join(parts),
        "category": event_type.split(".", 1)[0],
        "subject_id": subject_id,
        "subject_type": str(
            (primary or {}).get("type")
            or ("target" if subject_id == "target" else "entity")
        ),
    }


def _fingerprint(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_event(
    *,
    event_type: str,
    summary: str,
    target: str,
    outcome: str,
    technique: str,
    confidence: float,
    actor: dict[str, str],
    h3retik_session_id: str = "",
    action_id: str = "",
    entities: list[dict[str, Any]] | None = None,
    relationships: list[dict[str, Any]] | None = None,
    artifact: dict[str, Any] | None = None,
    attributes: dict[str, Any] | None = None,
    idempotency_key: str = "",
    attestation: dict[str, Any] | None = None,
    action_correlated: bool = False,
    known_references: set[str] | None = None,
) -> dict[str, Any]:
    normalised_type = _clean_identifier(event_type, field="event_type", required=True).lower()
    if normalised_type not in EVENT_TYPES:
        raise ValueError("event_type_invalid")
    normalised_outcome = _clean_identifier(outcome or "unknown", field="outcome").lower()
    if normalised_outcome not in OUTCOMES:
        raise ValueError("outcome_invalid")
    if not 0 <= float(confidence) <= 1:
        raise ValueError("confidence_out_of_range")

    clean_known_references = set(known_references or set())
    clean_entities = _normalise_entities(
        entities, known_references=clean_known_references
    )
    clean_relationships = _normalise_relationships(
        relationships,
        {item["id"] for item in clean_entities},
        clean_known_references,
    )
    clean_attributes = redact(attributes or {})
    if not isinstance(clean_attributes, dict):
        raise ValueError("attributes_must_be_an_object")

    clean_target = _clean_text(target, field="target", maximum=255, required=True)
    clean_summary = _clean_text(summary, field="summary", maximum=500, required=True)
    clean_session = _clean_identifier(h3retik_session_id, field="h3retik_session_id")
    clean_action = _clean_identifier(action_id, field="action_id")
    clean_technique = _clean_text(technique, field="technique", maximum=120)
    clean_key = _clean_identifier(idempotency_key, field="idempotency_key")
    clean_artifact = _normalise_artifact(
        artifact,
        allowed_references={
            "target",
            *clean_known_references,
            *(item["id"] for item in clean_entities),
        },
    )
    if clean_artifact and normalised_type != "loot.discovered":
        raise ValueError("artifact_requires_loot_event")
    presentation = _semantic_presentation(
        event_type=normalised_type,
        summary=clean_summary,
        outcome=normalised_outcome,
        technique=clean_technique,
        entities=clean_entities,
        relationships=clean_relationships,
    )
    clean_summary = presentation["title"]

    proof = redact(attestation or {})
    if not isinstance(proof, dict):
        raise ValueError("attestation_must_be_an_object")
    proof_fields = ("provider", "job_id", "command_id", "status", "digest", "proof_ref")
    proof_complete = all(proof.get(key) not in (None, "") for key in proof_fields)
    terminal = str(proof.get("status") or "").lower() in TERMINAL_STATUSES
    assurance = "asserted"
    if proof_complete and terminal:
        assurance = "verified" if action_correlated else "attested"

    verified = assurance == "verified"
    if normalised_type == "finding.confirmed":
        verified = (
            verified
            and normalised_outcome == "success"
            and str(proof.get("status") or "").lower() in SUCCESS_STATUSES
            and proof.get("exit_code") == 0
        )
        assurance = "verified" if verified else ("attested" if proof_complete else "asserted")

    dedupe_basis = {
        "event_type": normalised_type,
        "summary": clean_summary,
        "target": clean_target,
        "outcome": normalised_outcome,
        "technique": clean_technique,
        "session": clean_session,
        "actor": actor.get("id", ""),
    }
    event_id = f"tel-{uuid.uuid4().hex[:12]}"
    return {
        "id": event_id,
        "schema": SCHEMA_VERSION,
        "event_type": normalised_type,
        "summary": clean_summary,
        "target": clean_target,
        "outcome": normalised_outcome,
        "technique": clean_technique,
        "confidence": float(confidence),
        "assurance": assurance,
        "verified": verified,
        "verification_reason": (
            "executor proof correlated to scoped action"
            if verified
            else "executor proof lacks scoped action correlation"
            if assurance == "attested"
            else "agent semantic assertion"
        ),
        "idempotency_key": clean_key or f"auto:{_fingerprint(dedupe_basis)}",
        "h3retik_session_id": clean_session,
        "action_id": clean_action,
        "actor": actor,
        "entities": clean_entities,
        "relationships": clean_relationships,
        "artifact": clean_artifact,
        "presentation": presentation,
        "attributes": clean_attributes,
        "proof": proof,
        "recorded_at": _now(),
    }


def h3retik_attestation(
    *,
    session_id: str,
    job_id: str,
    command_id: str,
    status: str,
    exit_code: int | None,
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    clean_session = _clean_identifier(session_id, field="h3retik_session_id", required=True)
    clean_job = _clean_identifier(job_id, field="job_id", required=True)
    clean_command = _clean_identifier(command_id, field="command_id", required=True)
    clean_status = _clean_identifier(status, field="status", required=True).lower()
    if clean_status not in TERMINAL_STATUSES | {"running", "queued"}:
        raise ValueError("status_invalid")
    clean_evidence = redact(evidence or {})
    digest = _fingerprint(
        {
            "session_id": clean_session,
            "job_id": clean_job,
            "command_id": clean_command,
            "status": clean_status,
            "exit_code": exit_code,
            "evidence": clean_evidence,
        }
    )
    return {
        "provider": "h3retik",
        "session_id": clean_session,
        "job_id": clean_job,
        "command_id": clean_command,
        "status": clean_status,
        "exit_code": exit_code,
        "digest": f"sha256:{digest}",
        "proof_ref": f"h3retik:{clean_session}:{clean_job}#{clean_command}",
        "evidence": clean_evidence,
    }
