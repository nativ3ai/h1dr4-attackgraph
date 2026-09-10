from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from mcp.server.fastmcp import FastMCP

from .identity import IdentityStore
from .relay import DEFAULT_RELAY_URL, RelayCoordinator
from .service import AttackGraphService, ConfigurationError

mcp = FastMCP(
    "H1DR4 ATTACKGRAPH",
    instructions=(
        "Persistent, model-agnostic red-team context. Read the reporting contract once, open or "
        "select an engagement, request policy evaluation before active testing, and report each "
        "meaningful execution, attempt, finding, loot item, and checkpoint as typed telemetry. "
        "Agent reports are assertions; only correlated executor attestations become verified. "
        "Use only on explicitly authorized targets."
    ),
)


@lru_cache(maxsize=1)
def get_relay() -> RelayCoordinator:
    return RelayCoordinator.from_env()


@lru_cache(maxsize=1)
def get_service() -> AttackGraphService:
    identity = IdentityStore(os.getenv("ATTACKGRAPH_CONTROL_DB_PATH", ".attackgraph/control.db"))
    token = os.getenv("ATTACKGRAPH_AGENT_TOKEN", "")
    agent = identity.authenticate_agent(token) if token else None
    if token and not agent:
        raise ConfigurationError("ATTACKGRAPH_AGENT_TOKEN is invalid or revoked")
    relay_state = get_relay().client.state.load()
    return AttackGraphService(
        db_path=os.getenv("ATTACKGRAPH_DB_PATH", ".attackgraph/sibyl.db"),
        operator_id=os.getenv("ATTACKGRAPH_OPERATOR_ID", "local-operator"),
        identity=identity,
        principal_type="agent" if agent else "human",
        principal_id=str(agent["agent_id"]) if agent else "",
        actor_id=str(relay_state.get("actor_id") or ""),
        actor_name=str(
            relay_state.get("actor_name") or (agent["name"] if agent else "local-operator")
        ),
    )


def _read_service(engagement_id: str = "") -> AttackGraphService:
    service = get_service()
    get_relay().pull_best_effort(service, engagement_id)
    return service


def _after_write(service: AttackGraphService, engagement_id: str, result: Any) -> Any:
    get_relay().push_best_effort(service, engagement_id)
    return result


@mcp.tool()
def attackgraph_open_engagement(
    title: str,
    target: str,
    mode: str,
    scope: str,
    target_allowlist: list[str] | None = None,
    rules: list[str] | None = None,
    allowed_lanes: list[str] | None = None,
) -> dict[str, Any]:
    """Open an authorized engagement. Mode: manual_only, local_lab, or autonomous_lab."""
    return get_service().open_engagement(
        title=title,
        target=target,
        mode=mode,
        scope=scope,
        target_allowlist=target_allowlist,
        rules=rules,
        allowed_lanes=allowed_lanes,
    )


@mcp.tool()
def attackgraph_list_engagements() -> list[dict[str, Any]]:
    """List this operator's isolated Sibyl engagements."""
    return _read_service().list_engagements()


@mcp.tool()
def attackgraph_get_context(engagement_id: str, event_limit: int = 25) -> dict[str, Any]:
    """Return the complete hot graph plus recent append-only Sibyl events."""
    return _read_service(engagement_id).context(engagement_id, event_limit=event_limit)


@mcp.tool()
def attackgraph_get_brief(engagement_id: str) -> dict[str, Any]:
    """Return a compact handoff for the connected agent to reason over."""
    return _read_service(engagement_id).brief(engagement_id)


@mcp.tool()
def attackgraph_get_reporting_contract() -> dict[str, Any]:
    """Return the h1dr4.telemetry.v1 reporting grid, enums, and assurance rules."""
    return get_service().reporting_contract()


@mcp.tool()
def attackgraph_report_event(
    engagement_id: str,
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
    """Report one semantic telemetry event.

    This is an agent assertion and cannot self-declare verified. Reuse the same
    idempotency_key when a later executor attestation should promote it.
    """
    service = _read_service(engagement_id)
    result = service.report_telemetry(
        engagement_id,
        event_type=event_type,
        summary=summary,
        target=target,
        outcome=outcome,
        technique=technique,
        confidence=confidence,
        h3retik_session_id=h3retik_session_id,
        action_id=action_id,
        entities=entities,
        relationships=relationships,
        artifact=artifact,
        attributes=attributes,
        idempotency_key=idempotency_key,
    )
    return _after_write(service, engagement_id, result)


@mcp.tool()
def attackgraph_ingest_h3retik_event(
    engagement_id: str,
    event_type: str,
    summary: str,
    h3retik_session_id: str,
    job_id: str,
    command_id: str,
    status: str,
    attestation_token: str,
    exit_code: int | None = None,
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
) -> dict[str, Any]:
    """Ingest authenticated H3RETIK telemetry with a server-generated evidence digest.

    Complete proof becomes verified only when it correlates to an existing scoped
    AttackGraph action. Otherwise it remains tool-attested and cannot promote a
    high-impact posture. This adapter-only tool requires the server-configured
    H3RETIK attestation token; do not expose that credential to agent workers.
    """
    service = _read_service(engagement_id)
    result = service.ingest_h3retik_telemetry(
        engagement_id,
        event_type=event_type,
        summary=summary,
        h3retik_session_id=h3retik_session_id,
        job_id=job_id,
        command_id=command_id,
        status=status,
        exit_code=exit_code,
        target=target,
        outcome=outcome,
        technique=technique,
        confidence=confidence,
        action_id=action_id,
        entities=entities,
        relationships=relationships,
        artifact=artifact,
        attributes=attributes,
        evidence=evidence,
        idempotency_key=idempotency_key,
        attestation_token=attestation_token,
    )
    return _after_write(service, engagement_id, result)


@mcp.tool()
def attackgraph_record_observation(
    engagement_id: str,
    statement: str,
    source: str,
    confidence: float,
    kind: str = "observation",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a legacy sourced assertion in Sibyl.

    Use attackgraph_report_event for new integrations. Posture claims supplied
    here remain unverified; only correlated executor telemetry can promote a
    high-impact dashboard state.
    """
    service = _read_service(engagement_id)
    result = service.record_observation(
        engagement_id,
        statement=statement,
        source=source,
        confidence=confidence,
        kind=kind,
        evidence=evidence,
    )
    return _after_write(service, engagement_id, result)


@mcp.tool()
def attackgraph_record_hypothesis(
    engagement_id: str, statement: str, status: str = "open"
) -> dict[str, Any]:
    """Record an open, confirmed, or rejected attack hypothesis."""
    service = _read_service(engagement_id)
    result = service.record_hypothesis(engagement_id, statement=statement, status=status)
    return _after_write(service, engagement_id, result)


@mcp.tool()
def attackgraph_record_attempt(
    engagement_id: str,
    approach: str,
    outcome: str,
    exhausted: bool,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record an attempted path so future sessions do not blindly repeat it."""
    service = _read_service(engagement_id)
    result = service.record_attempt(
        engagement_id,
        approach=approach,
        outcome=outcome,
        exhausted=exhausted,
        evidence=evidence,
    )
    return _after_write(service, engagement_id, result)


@mcp.tool()
def attackgraph_request_action(
    engagement_id: str,
    target: str,
    lane: str,
    command: str,
    purpose: str,
    risk: str = "active",
    max_minutes: int = 5,
    budget_usdc: float = 0.50,
    h3retik_session_id: str = "",
) -> dict[str, Any]:
    """Policy-check and record an action plan. This does not execute the command."""
    service = _read_service(engagement_id)
    result = service.request_action(
        engagement_id,
        target=target,
        lane=lane,
        command=command,
        purpose=purpose,
        risk=risk,
        max_minutes=max_minutes,
        budget_usdc=budget_usdc,
        h3retik_session_id=h3retik_session_id,
    )
    return _after_write(service, engagement_id, result)


@mcp.tool()
def attackgraph_h3retik_capabilities() -> dict[str, Any]:
    """Inspect the live H3RETIK MCP execution capabilities without spending funds."""
    return get_service().h3retik_capabilities()


@mcp.tool()
def attackgraph_h3retik_quote(minutes: int = 5, actions: int = 1, location: str = "auto") -> Any:
    """Get a live H3RETIK compute-window quote. This does not accept terms or pay."""
    return get_service().h3retik_quote(minutes=minutes, actions=actions, location=location)


@mcp.tool()
def attackgraph_list_h3retik_sessions(engagement_id: str) -> list[dict[str, Any]]:
    """List the H3RETIK session pool bound to this shared engagement."""
    return get_service().h3retik_sessions(engagement_id)


@mcp.tool()
def attackgraph_bind_h3retik_session(
    engagement_id: str,
    session_id: str,
    label: str = "H3RETIK session",
    lane: str = "",
) -> dict[str, Any]:
    """Attach a paid H3RETIK session to this workspace locally and in H3RETIK Cloud."""
    return get_service().bind_h3retik_session(
        engagement_id,
        session_id=session_id,
        label=label,
        lane=lane,
    )


@mcp.tool()
def attackgraph_get_h3retik_workspace(engagement_id: str) -> Any:
    """Read live H3RETIK sessions and jobs attached to this AttackGraph workspace."""
    return get_service().h3retik_workspace(engagement_id)


@mcp.tool()
def attackgraph_create_h3retik_extension_receipt(
    engagement_id: str,
    session_id: str,
    minutes: int,
    actions: int,
    asset: str = "USDC",
) -> Any:
    """Create a payable receipt that adds time/actions to an attached session."""
    return get_service().create_h3retik_extension_receipt(
        engagement_id,
        session_id=session_id,
        minutes=minutes,
        actions=actions,
        asset=asset,
    )


@mcp.tool()
def attackgraph_sync_h3retik_receipt(engagement_id: str, receipt_id: str) -> Any:
    """Sync a previously created H3RETIK payment receipt and return its session state."""
    return get_service().sync_h3retik_receipt(engagement_id, receipt_id)


@mcp.tool()
def attackgraph_execute_approved_h3retik_job(
    engagement_id: str, action_id: str, approval_code: str
) -> dict[str, Any]:
    """Execute one already-scoped action in an existing session after human approval."""
    service = _read_service(engagement_id)
    result = service.execute_approved_h3retik_job(
        engagement_id, action_id=action_id, approval_code=approval_code
    )
    return _after_write(service, engagement_id, result)


@mcp.tool()
def attackgraph_ingest_h3retik_result(
    engagement_id: str,
    action_id: str,
    job_id: str,
    result: dict[str, Any],
    status: str = "completed",
) -> dict[str, Any]:
    """Import externally run H3RETIK output as sanitized Sibyl evidence."""
    service = _read_service(engagement_id)
    recorded = service.ingest_h3retik_result(
        engagement_id,
        action_id=action_id,
        job_id=job_id,
        result=result,
        status=status,
    )
    return _after_write(service, engagement_id, recorded)


@mcp.tool()
def attackgraph_create_regression(
    engagement_id: str, name: str, check: str, expected: str
) -> dict[str, Any]:
    """Turn a confirmed finding into a durable regression check."""
    service = _read_service(engagement_id)
    result = service.create_regression(engagement_id, name=name, check=check, expected=expected)
    return _after_write(service, engagement_id, result)


@mcp.tool()
def attackgraph_host_private_workspace(
    engagement_id: str,
    relay_url: str = DEFAULT_RELAY_URL,
    actor_name: str = "",
) -> dict[str, Any]:
    """Host an existing engagement through the H1DR4 ciphertext-only private relay."""
    return get_relay().client.host_workspace(
        get_service(),
        engagement_id,
        relay_url=relay_url,
        actor_name=actor_name,
        bootstrap_token=os.getenv("ATTACKGRAPH_RELAY_BOOTSTRAP_TOKEN", ""),
    )


@mcp.tool()
def attackgraph_create_private_invite(
    engagement_id: str,
    role: str = "operator",
    hours: int = 24,
) -> dict[str, Any]:
    """Create a one-use encrypted workspace invite. Treat the returned code as a secret."""
    return get_relay().client.create_invite(engagement_id, role=role, hours=hours)


@mcp.tool()
def attackgraph_join_private_workspace(
    invite_code: str,
    actor_name: str,
) -> dict[str, Any]:
    """Join a private workspace with a one-use secret invite and hydrate local Sibyl."""
    return get_relay().client.join_workspace(
        get_service(),
        invite_code,
        actor_name=actor_name,
    )


@mcp.tool()
def attackgraph_private_workspace_members(engagement_id: str) -> dict[str, Any]:
    """List the authorized members and revocation state for a private workspace."""
    return {
        "workspace_id": engagement_id,
        "members": get_relay().client.members(engagement_id),
    }


@mcp.tool()
def attackgraph_revoke_private_workspace_member(
    engagement_id: str,
    member_id: str,
) -> dict[str, Any]:
    """Revoke a private relay member. Only the workspace owner may do this."""
    return {
        "workspace_id": engagement_id,
        "member": get_relay().client.revoke_member(engagement_id, member_id),
    }


@mcp.tool()
def attackgraph_sync_private_workspace(engagement_id: str) -> dict[str, Any]:
    """Pull encrypted remote events into local Sibyl and publish the merged snapshot."""
    service = get_service()
    pulled = get_relay().pull(service, engagement_id)
    pushed = get_relay().push(service, engagement_id)
    return {
        "engagement_id": engagement_id,
        "pulled_events": pulled,
        "published": bool(pushed),
    }


@mcp.tool()
def attackgraph_private_workspace_status() -> dict[str, Any]:
    """List locally joined private workspaces without exposing relay credentials or keys."""
    coordinator = get_relay()
    return {
        **coordinator.client.status(),
        "last_sync_error": coordinator.last_error or None,
    }


@mcp.tool()
def attackgraph_discover_h1dr4_tools(query: str = "", limit: int = 20) -> list[dict[str, Any]]:
    """Discover live H1DR4 MCP tools by keyword instead of hard-coding the catalog."""
    return get_service().discover_h1dr4(query=query, limit=limit)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
