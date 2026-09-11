from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

from .h1dr4 import H1dr4Client
from .h3retik import H3retikClient
from .identity import IdentityStore
from .memory import SibylAttackMemory
from .models import ActionDecision, ActionRisk, EngagementMode
from .policy import evaluate_action
from .redaction import redact
from .telemetry import build_event, h3retik_attestation, reporting_contract


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
        identity: IdentityStore | None = None,
        principal_type: str = "human",
        principal_id: str = "",
        actor_id: str = "",
        actor_name: str = "",
    ) -> None:
        self.identity = identity
        self.principal_type = principal_type
        self.principal_id = principal_id
        self.memory = SibylAttackMemory(
            db_path,
            operator_id,
            actor_id=actor_id or principal_id or operator_id,
            actor_name=actor_name or actor_id or principal_id or operator_id,
            actor_type=principal_type,
        )
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
        if self.identity and self.principal_type == "agent":
            raise PermissionError("agents_cannot_open_engagement")
        engagement = self.memory.open_engagement(
            title=title,
            target=target,
            mode=EngagementMode(mode),
            scope=scope,
            target_allowlist=target_allowlist,
            rules=rules,
            allowed_lanes=allowed_lanes,
        )
        if self.identity and self.principal_id:
            self.identity.add_membership(
                engagement.engagement_id,
                self.principal_type,
                self.principal_id,
                "owner",
            )
        return engagement.to_dict()

    def list_engagements(self) -> list[dict[str, Any]]:
        engagements = self.memory.list_engagements()
        if not self.identity or not self.principal_id:
            return engagements
        allowed = self.identity.engagement_ids_for(self.principal_type, self.principal_id)
        return [item for item in engagements if item["engagement_id"] in allowed]

    def context(self, engagement_id: str, *, event_limit: int = 25) -> dict[str, Any]:
        self._require_access(engagement_id)
        return {
            "engagement": self.memory.get_engagement(engagement_id).to_dict(),
            "graph": self.memory.get_graph(engagement_id),
            "recent_events": self.memory.recent_events(engagement_id, event_limit),
        }

    def brief(self, engagement_id: str) -> dict[str, Any]:
        self._require_access(engagement_id)
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
            "findings": [
                item
                for item in graph["observations"]
                if item.get("kind") in {"finding", "confirmed_vulnerability"}
            ][-20:],
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
            "telemetry": graph["telemetry"][-20:],
            "agent_instruction": (
                "Read attackgraph_get_reporting_contract once. Reason from confirmed evidence "
                "and open hypotheses; do not repeat exhausted paths without new evidence. "
                "Request policy evaluation before active testing, then report each meaningful "
                "execution, attempt, finding, loot item, and checkpoint through typed telemetry."
            ),
        }

    @staticmethod
    def reporting_contract() -> dict[str, Any]:
        return reporting_contract()

    def report_telemetry(
        self,
        engagement_id: str,
        *,
        event_type: str,
        summary: str,
        target: str = "",
        outcome: str = "unknown",
        technique: str = "",
        confidence: float = 0.5,
        h3retik_session_id: str = "",
        action_id: str = "",
        entities: list[dict[str, Any]] | None = None,
        relationships: list[dict[str, Any]] | None = None,
        artifact: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
        idempotency_key: str = "",
    ) -> dict[str, Any]:
        self._require_access(engagement_id)
        engagement = self.memory.get_engagement(engagement_id)
        event_target = target.strip() or engagement.target
        self._require_target(engagement, event_target)
        if h3retik_session_id:
            self._require_h3retik_session(engagement_id, h3retik_session_id)
        if action_id:
            action = self.memory.get_action(engagement_id, action_id)
            if action.get("target") != event_target:
                raise ValueError("telemetry_action_target_mismatch")
        known_references = self._telemetry_references(engagement_id, entities)
        event = build_event(
            event_type=event_type,
            summary=summary,
            target=event_target,
            outcome=outcome,
            technique=technique,
            confidence=confidence,
            actor=self.memory.actor(),
            h3retik_session_id=h3retik_session_id,
            action_id=action_id,
            entities=entities,
            relationships=relationships,
            artifact=artifact,
            attributes=attributes,
            idempotency_key=idempotency_key,
            known_references=known_references,
        )
        return self.memory.record_telemetry(engagement_id, event)

    def ingest_h3retik_telemetry(
        self,
        engagement_id: str,
        *,
        event_type: str,
        summary: str,
        h3retik_session_id: str,
        job_id: str,
        command_id: str,
        status: str,
        exit_code: int | None,
        target: str = "",
        outcome: str = "unknown",
        technique: str = "",
        confidence: float = 1.0,
        action_id: str = "",
        entities: list[dict[str, Any]] | None = None,
        relationships: list[dict[str, Any]] | None = None,
        artifact: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        idempotency_key: str = "",
        attestation_token: str = "",
        trusted_internal: bool = False,
    ) -> dict[str, Any]:
        self._require_access(engagement_id)
        if not trusted_internal:
            expected_token = os.getenv("ATTACKGRAPH_H3RETIK_ATTESTATION_TOKEN", "")
            if not expected_token:
                raise ConfigurationError(
                    "ATTACKGRAPH_H3RETIK_ATTESTATION_TOKEN is not configured"
                )
            if not hmac.compare_digest(attestation_token, expected_token):
                raise PermissionError("invalid H3RETIK attestation token")
        engagement = self.memory.get_engagement(engagement_id)
        event_target = target.strip() or engagement.target
        self._require_target(engagement, event_target)
        self._require_h3retik_session(engagement_id, h3retik_session_id)

        action_correlated = False
        if action_id:
            action = self.memory.get_action(engagement_id, action_id)
            if action.get("target") != event_target:
                raise ValueError("telemetry_action_target_mismatch")
            action_session = str(action.get("h3retik_session_id") or "")
            if action_session and action_session != h3retik_session_id:
                raise ValueError("telemetry_action_session_mismatch")
            action_correlated = True

        attestation = h3retik_attestation(
            session_id=h3retik_session_id,
            job_id=job_id,
            command_id=command_id,
            status=status,
            exit_code=exit_code,
            evidence=evidence,
        )
        known_references = self._telemetry_references(engagement_id, entities)
        event = build_event(
            event_type=event_type,
            summary=summary,
            target=event_target,
            outcome=outcome,
            technique=technique,
            confidence=confidence,
            actor=self.memory.actor(),
            h3retik_session_id=h3retik_session_id,
            action_id=action_id,
            entities=entities,
            relationships=relationships,
            artifact=artifact,
            attributes=attributes,
            idempotency_key=idempotency_key,
            attestation=attestation,
            action_correlated=action_correlated,
            known_references=known_references,
        )
        recorded = self.memory.record_telemetry(engagement_id, event)
        if event_type == "execution.completed" and action_id:
            current = self.memory.get_action(engagement_id, action_id)
            if current.get("status") not in {"completed", "succeeded", "failed", "cancelled"}:
                self.memory.complete_action(
                    engagement_id,
                    action_id,
                    status=status,
                    result={
                        "telemetry_event_id": recorded["event"]["id"],
                        "proof_ref": attestation["proof_ref"],
                        "digest": attestation["digest"],
                    },
                )
        return recorded

    def record_observation(self, engagement_id: str, **kwargs: Any) -> dict[str, Any]:
        self._require_access(engagement_id)
        evidence = kwargs.get("evidence")
        if isinstance(evidence, dict) and isinstance(evidence.get("posture"), dict):
            claim = dict(evidence["posture"])
            claim["verified"] = False
            claim["verification_reason"] = "legacy observation is an agent assertion"
            kwargs["evidence"] = {**evidence, "posture": claim}
        return self.memory.record_observation(engagement_id, **kwargs)

    def record_hypothesis(
        self, engagement_id: str, *, statement: str, status: str = "open"
    ) -> dict[str, Any]:
        self._require_access(engagement_id)
        return self.memory.record_hypothesis(engagement_id, statement=statement, status=status)

    def record_attempt(self, engagement_id: str, **kwargs: Any) -> dict[str, Any]:
        self._require_access(engagement_id)
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
        h3retik_session_id: str = "",
    ) -> dict[str, Any]:
        self._require_access(engagement_id)
        h3retik_session_id = h3retik_session_id.strip()
        if h3retik_session_id and self.identity:
            configured = {
                item["session_id"] for item in self.identity.list_h3retik_sessions(engagement_id)
            }
            if h3retik_session_id not in configured:
                raise PermissionError("h3retik_session_not_bound_to_engagement")
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
                "h3retik_session_id": h3retik_session_id,
                "status": decision.decision.value,
                "policy": decision.to_dict(),
            },
        )
        return action

    def authorize_operation_action(
        self,
        engagement_id: str,
        *,
        campaign_id: str,
        scope_hash: str,
        module_id: str,
        target: str,
        lane: str,
        h3retik_session_id: str,
        approved_by: str,
    ) -> dict[str, Any]:
        """Convert one immutable campaign approval into a scoped executor action."""

        self._require_access(engagement_id)
        engagement = self.memory.get_engagement(engagement_id)
        if engagement.mode is not EngagementMode.AUTONOMOUS_LAB:
            raise PermissionError("operation_red_requires_autonomous_lab")
        self._require_target(engagement, target)
        if lane not in engagement.allowed_lanes:
            raise PermissionError("operation_lane_outside_engagement_scope")
        if not all(
            value.strip()
            for value in (campaign_id, scope_hash, module_id, h3retik_session_id, approved_by)
        ):
            raise ValueError("operation_authorization_incomplete")
        if self.identity:
            self.identity.bind_h3retik_session(
                engagement_id=engagement_id,
                session_id=h3retik_session_id,
                label=f"Operation Red {module_id}",
                lane=lane,
                attached_by=approved_by,
            )
        return self.memory.record_action(
            engagement_id,
            {
                "target": target,
                "lane": lane,
                "command": f"operation-red:{campaign_id}:{module_id}",
                "purpose": f"Operation Red {module_id} worker",
                "risk": ActionRisk.ACTIVE.value,
                "max_minutes": 60,
                "budget_usdc": 0,
                "h3retik_session_id": h3retik_session_id,
                "status": "approved",
                "policy": {
                    "decision": "campaign_approved",
                    "may_dispatch": True,
                    "approved_by": approved_by,
                    "campaign_id": campaign_id,
                    "scope_hash": scope_hash,
                    "module_id": module_id,
                    "reason": "immutable Operation Red scope approved before funding",
                },
            },
        )

    def h3retik_capabilities(self) -> dict[str, Any]:
        return self.h3retik.capabilities()

    def h3retik_quote(self, *, minutes: int = 5, actions: int = 1, location: str = "auto") -> Any:
        return self.h3retik.quote(minutes=minutes, actions=actions, location=location)

    @staticmethod
    def _h3retik_credentials() -> tuple[str, str]:
        wallet = os.getenv("H3RETIK_WALLET", "").strip()
        token = os.getenv("H3RETIK_TOKEN", "").strip()
        if not wallet or not token:
            raise ConfigurationError("H3RETIK_WALLET and H3RETIK_TOKEN are required")
        return wallet, token

    def sync_h3retik_session(
        self,
        engagement_id: str,
        *,
        session_id: str,
        label: str = "H3RETIK session",
        lane: str = "",
    ) -> Any:
        self._require_access(engagement_id)
        engagement = self.memory.get_engagement(engagement_id)
        wallet, token = self._h3retik_credentials()
        return self.h3retik.attach_session(
            wallet=wallet,
            token=token,
            workspace_id=engagement_id,
            workspace_name=engagement.title,
            session_id=session_id,
            label=label,
            lane=lane,
        )

    def bind_h3retik_session(
        self,
        engagement_id: str,
        *,
        session_id: str,
        label: str = "H3RETIK session",
        lane: str = "",
    ) -> dict[str, Any]:
        remote = self.sync_h3retik_session(
            engagement_id,
            session_id=session_id,
            label=label,
            lane=lane,
        )
        local = None
        if self.identity:
            local = self.identity.bind_h3retik_session(
                engagement_id=engagement_id,
                session_id=session_id,
                label=label,
                lane=lane,
                attached_by=self.principal_id or self.memory.operator_id,
            )
        return {"workspace": remote, "binding": local}

    def h3retik_workspace(self, engagement_id: str) -> Any:
        self._require_access(engagement_id)
        wallet, token = self._h3retik_credentials()
        return self.h3retik.workspace(
            wallet=wallet,
            token=token,
            workspace_id=engagement_id,
        )

    def create_h3retik_extension_receipt(
        self,
        engagement_id: str,
        *,
        session_id: str,
        minutes: int,
        actions: int,
        asset: str = "USDC",
    ) -> Any:
        self._require_access(engagement_id)
        self._require_h3retik_session(engagement_id, session_id)
        wallet, token = self._h3retik_credentials()
        return self.h3retik.create_extension_receipt(
            wallet=wallet,
            token=token,
            session_id=session_id,
            minutes=minutes,
            actions=actions,
            asset=asset,
        )

    def sync_h3retik_receipt(self, engagement_id: str, receipt_id: str) -> Any:
        self._require_access(engagement_id)
        return self.h3retik.sync_receipt(receipt_id)

    def h3retik_sessions(self, engagement_id: str) -> list[dict[str, Any]]:
        self._require_access(engagement_id)
        if self.identity:
            return self.identity.list_h3retik_sessions(engagement_id)
        session_id = os.getenv("H3RETIK_SESSION_ID", "")
        return (
            [
                {
                    "session_id": session_id,
                    "label": "Environment session",
                    "status": "active",
                }
            ]
            if session_id
            else []
        )

    def execute_approved_h3retik_job(
        self,
        engagement_id: str,
        *,
        action_id: str,
        approval_code: str,
    ) -> dict[str, Any]:
        self._require_access(engagement_id)
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
        session_id = action.get("h3retik_session_id") or os.getenv("H3RETIK_SESSION_ID", "")
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
                workspace_id=engagement_id,
                workspace_name=engagement.title,
                session_label=str(action.get("lane") or "H3RETIK session"),
                session_lane=str(action.get("lane") or ""),
            )
        )
        job_id = str(result.get("job_id") or "unknown")
        remote_status = str(
            H3retikClient._find_value(result.get("status"), "status") or "failed"
        ).casefold()
        succeeded = remote_status in {"succeeded", "completed"}
        exit_code_value = H3retikClient._find_value(result.get("output"), "exit_code")
        try:
            exit_code = (
                int(exit_code_value) if exit_code_value is not None else (0 if succeeded else 1)
            )
        except (TypeError, ValueError):
            exit_code = 0 if succeeded else 1
        terminal_status = "completed" if succeeded else remote_status
        recorded = self.ingest_h3retik_telemetry(
            engagement_id,
            event_type="execution.completed",
            summary=str(action.get("purpose") or "Approved execution completed"),
            target=str(action["target"]),
            outcome="success" if succeeded else "failed",
            technique=str(action.get("purpose") or action.get("lane") or "execution"),
            confidence=1.0,
            h3retik_session_id=session_id,
            job_id=job_id,
            command_id=action_id,
            status=terminal_status,
            exit_code=exit_code,
            action_id=action_id,
            evidence=result,
            idempotency_key=f"h3retik:{job_id}:execution.completed",
            trusted_internal=True,
        )
        return {"action_id": action_id, "observation": recorded["record"], "result": result}

    def ingest_h3retik_result(
        self,
        engagement_id: str,
        *,
        action_id: str,
        job_id: str,
        result: dict[str, Any],
        status: str = "completed",
    ) -> dict[str, Any]:
        self._require_access(engagement_id)
        action = self.memory.get_action(engagement_id, action_id)
        sanitized = redact({"job_id": job_id, "result": result})
        h3retik_session_id = str(
            action.get("h3retik_session_id") or os.getenv("H3RETIK_SESSION_ID", "external")
        )
        recorded = self.ingest_h3retik_telemetry(
            engagement_id,
            event_type="execution.completed",
            summary=str(action.get("purpose") or "Approved execution completed"),
            target=str(action["target"]),
            outcome="success" if status in {"completed", "succeeded"} else "failed",
            technique=str(action.get("purpose") or action.get("lane") or "execution"),
            confidence=1.0,
            h3retik_session_id=h3retik_session_id,
            job_id=job_id,
            command_id=action_id,
            status=status,
            exit_code=0 if status in {"completed", "succeeded"} else 1,
            action_id=action_id,
            evidence=sanitized,
            idempotency_key=f"h3retik:{job_id}:execution.completed",
            trusted_internal=True,
        )
        return recorded["record"]

    def _telemetry_references(
        self,
        engagement_id: str,
        declared_entities: list[dict[str, Any]] | None,
    ) -> set[str]:
        """Return stable graph references and reject entity identity drift."""

        graph = self.memory.get_graph(engagement_id)
        existing_entities = {
            str(item.get("id") or ""): str(item.get("type") or "")
            for item in graph.get("entities", [])
            if item.get("id")
        }
        for entity in declared_entities or []:
            if not isinstance(entity, dict):
                continue
            entity_id = str(entity.get("id") or "")
            entity_type = str(entity.get("type") or "").lower()
            if (
                entity_id in existing_entities
                and entity_type
                and existing_entities[entity_id] != entity_type
            ):
                raise ValueError("entity_type_conflict")

        references = {"target"}
        for collection in (
            "entities",
            "artifacts",
            "observations",
            "attempts",
            "actions",
            "regressions",
            "telemetry",
        ):
            references.update(
                str(item.get("id"))
                for item in graph.get(collection, [])
                if item.get("id")
            )
        return references

    def create_regression(
        self, engagement_id: str, *, name: str, check: str, expected: str
    ) -> dict[str, Any]:
        self._require_access(engagement_id)
        return self.memory.create_regression(
            engagement_id, name=name, check=check, expected=expected
        )

    def discover_h1dr4(self, *, query: str = "", limit: int = 20) -> list[dict[str, Any]]:
        return self.h1dr4.discover(query=query, limit=limit)

    def _require_access(self, engagement_id: str) -> None:
        if not self.identity or not self.principal_id:
            return
        if not self.identity.can_access(
            engagement_id, self.principal_type, self.principal_id
        ):
            raise PermissionError("engagement_access_denied")

    @staticmethod
    def _require_target(engagement: Any, target: str) -> None:
        if target not in engagement.target_allowlist:
            raise PermissionError("telemetry_target_outside_engagement_scope")

    def _require_h3retik_session(self, engagement_id: str, session_id: str) -> None:
        if not session_id.strip():
            raise ValueError("h3retik_session_id_required")
        if not self.identity:
            return
        configured = {
            item["session_id"] for item in self.identity.list_h3retik_sessions(engagement_id)
        }
        if session_id not in configured:
            raise PermissionError("h3retik_session_not_bound_to_engagement")
