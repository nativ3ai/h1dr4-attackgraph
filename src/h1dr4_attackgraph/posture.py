from __future__ import annotations

from typing import Any

_POSTURE_STATES: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "engagement_active",
        "ENGAGEMENT ACTIVE",
        "ENGAGEMENT ACTIVE",
        "No verified compromise state has been established.",
        "neutral",
    ),
    (
        "recon_in_progress",
        "RECON IN PROGRESS",
        "RECON IN PROGRESS",
        "Verified reconnaissance telemetry is entering Sibyl.",
        "recon",
    ),
    (
        "surface_mapped",
        "SURFACE MAPPED",
        "SURFACE MAPPED",
        "The target surface is backed by verified telemetry.",
        "mapped",
    ),
    (
        "finding_confirmed",
        "FINDING CONFIRMED",
        "FINDING CONFIRMED",
        "At least one finding is supported by high-confidence evidence.",
        "finding",
    ),
    (
        "access_material_acquired",
        "ACCESS MATERIAL ACQUIRED",
        "LOOT SECURED",
        "Usable access material is present in sealed Sibyl telemetry.",
        "loot",
    ),
    (
        "initial_access_established",
        "INITIAL ACCESS ESTABLISHED",
        "INITIAL ACCESS",
        "Validated evidence proves entry into the authorized target.",
        "access",
    ),
    (
        "foothold_active",
        "FOOTHOLD ACTIVE",
        "FOOTHOLD ACTIVE",
        "A reproducible execution foothold is supported by verified evidence.",
        "foothold",
    ),
    (
        "privileged_access",
        "PRIVILEGED ACCESS",
        "PRIVILEGED ACCESS",
        "Verified evidence establishes elevated control of the target.",
        "privileged",
    ),
    (
        "target_compromised",
        "TARGET COMPROMISED",
        "PWNED",
        "The engagement objective is proven by verified Sibyl records.",
        "compromised",
    ),
    (
        "objective_complete",
        "OBJECTIVE COMPLETE",
        "OBJECTIVE COMPLETE",
        "The declared engagement objective has been completed and evidenced.",
        "complete",
    ),
    (
        "regression_detected",
        "REGRESSION DETECTED",
        "REGRESSION DETECTED",
        "A previously verified security state no longer holds.",
        "regression",
    ),
)

_POSTURE_BY_STATE = {
    state: {
        "state": state,
        "label": label,
        "display_label": display_label,
        "description": description,
        "tone": tone,
        "rank": rank,
    }
    for rank, (state, label, display_label, description, tone) in enumerate(_POSTURE_STATES)
}

_POSTURE_ALIASES = {
    "initial_access": "initial_access_established",
    "foothold": "foothold_active",
    "admin": "privileged_access",
    "root": "privileged_access",
    "compromised": "target_compromised",
    "pwned": "target_compromised",
    "objective_reached": "objective_complete",
    "regression": "regression_detected",
}

_SURFACE_KEYS = {
    "attack_surface",
    "endpoint",
    "endpoints",
    "header",
    "headers",
    "host",
    "hosts",
    "port",
    "ports",
    "route",
    "routes",
    "service",
    "services",
    "technologies",
    "technology",
    "tools",
    "transport",
    "url",
    "urls",
}

_ACCESS_KEYS = {
    "access_key",
    "api_key",
    "authorization",
    "cookie",
    "credentials",
    "password",
    "private_key",
    "secret",
    "session_cookie",
    "session_token",
    "token",
}

_EMPTY_ACCESS_VALUES = {
    "",
    "false",
    "metadata only",
    "metadata-only",
    "n/a",
    "none",
    "not present",
    "not_present",
    "null",
    "unknown",
}


def _normalise_key(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _meaningful(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return _normalise_key(value) not in {_normalise_key(item) for item in _EMPTY_ACCESS_VALUES}
    if isinstance(value, (list, tuple, set)):
        return any(_meaningful(item) for item in value)
    if isinstance(value, dict):
        return any(_meaningful(item) for item in value.values())
    return bool(value)


def _contains_surface_telemetry(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _normalise_key(str(key)) in _SURFACE_KEYS and _meaningful(item):
                return True
            if _contains_surface_telemetry(item):
                return True
    elif isinstance(value, list):
        return any(_contains_surface_telemetry(item) for item in value)
    return False


def _contains_access_material(value: Any, key: str = "") -> bool:
    normalised_key = _normalise_key(key)
    if normalised_key in _ACCESS_KEYS and _meaningful(value):
        return True
    if isinstance(value, dict):
        return any(
            _contains_access_material(item, str(item_key)) for item_key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_access_material(item, key) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        return "authorization: bearer " in lowered or lowered.startswith("bearer [redacted]")
    return False


def _explicit_posture_claim(evidence: dict[str, Any]) -> tuple[str, str] | None:
    claim = evidence.get("posture")
    telemetry = evidence.get("telemetry")
    attestation = evidence.get("proof")
    if not isinstance(claim, dict):
        return None
    if not isinstance(telemetry, dict) or not isinstance(attestation, dict):
        return None
    proof_ref = str(attestation.get("proof_ref") or "")
    if (
        telemetry.get("verified") is not True
        or telemetry.get("assurance") != "verified"
        or not proof_ref
    ):
        return None
    raw_state = _normalise_key(str(claim.get("signal") or claim.get("state") or ""))
    state = _POSTURE_ALIASES.get(raw_state, raw_state)
    proof = claim.get("proof") or claim.get("validation") or claim.get("evidence_ref")
    if (
        state not in _POSTURE_BY_STATE
        or claim.get("verified") is not True
        or not _meaningful(proof)
        or str(proof) != proof_ref
    ):
        return None
    return state, str(proof)


def _reason(observation: dict[str, Any], state: str, summary: str) -> dict[str, Any]:
    actor = observation.get("actor") or {}
    return {
        "record_id": str(observation.get("id") or ""),
        "signal": state,
        "label": _POSTURE_BY_STATE[state]["label"],
        "summary": summary,
        "source": str(observation.get("source") or "sibyl-memory"),
        "actor_id": str(actor.get("id") or ""),
        "actor_name": str(actor.get("name") or ""),
        "recorded_at": str(observation.get("recorded_at") or ""),
        "rank": _POSTURE_BY_STATE[state]["rank"],
    }


def derive_engagement_posture(engagement: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    """Derive one explainable posture from verified Sibyl evidence.

    Low-level states are inferred from typed loot telemetry. High-impact states
    require an explicit, verified ``evidence.posture`` claim with a proof
    reference, so a display label can never be changed by a free-form title.
    """

    reasons: list[dict[str, Any]] = []
    for observation in graph.get("observations", []):
        if float(observation.get("confidence") or 0.0) < 0.8:
            continue
        evidence = observation.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        reasons.append(
            _reason(observation, "recon_in_progress", "High-confidence telemetry recorded")
        )
        if _contains_surface_telemetry(evidence):
            reasons.append(
                _reason(
                    observation,
                    "surface_mapped",
                    "Mapped surface telemetry retained as sealed loot",
                )
            )
        if observation.get("kind") == "finding":
            reasons.append(
                _reason(
                    observation, "finding_confirmed", "High-confidence finding recorded in Sibyl"
                )
            )
        if _contains_access_material(evidence):
            reasons.append(
                _reason(
                    observation,
                    "access_material_acquired",
                    "Access material retained in sealed telemetry",
                )
            )
        explicit = _explicit_posture_claim(evidence)
        if explicit:
            state, proof = explicit
            reasons.append(_reason(observation, state, f"Verified posture proof: {proof}"))

    if not reasons:
        current = dict(_POSTURE_BY_STATE["engagement_active"])
        return {
            **current,
            "derived": True,
            "verified": False,
            "evidence_count": 0,
            "evidence_ids": [],
            "reasons": [],
            "updated_at": str(engagement.get("created_at") or ""),
            "method": "sibyl-deterministic-evidence-v1",
        }

    reasons.sort(key=lambda item: (int(item["rank"]), str(item["recorded_at"])), reverse=True)
    current = dict(_POSTURE_BY_STATE[str(reasons[0]["signal"])])
    evidence_ids = list(
        dict.fromkeys(reason["record_id"] for reason in reasons if reason["record_id"])
    )
    return {
        **current,
        "derived": True,
        "verified": True,
        "evidence_count": len(evidence_ids),
        "evidence_ids": evidence_ids,
        "reasons": reasons[:8],
        "updated_at": max((reason["recorded_at"] for reason in reasons), default=""),
        "method": "sibyl-deterministic-evidence-v1",
    }
