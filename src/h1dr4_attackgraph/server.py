from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from mcp.server.fastmcp import FastMCP

from .service import AttackGraphService

mcp = FastMCP(
    "H1DR4 ATTACKGRAPH",
    instructions=(
        "Persistent, model-agnostic red-team context. Open an engagement, record evidence and "
        "attempts, read the brief before reasoning, and request policy evaluation before active "
        "testing. Use only on explicitly authorized targets."
    ),
)


@lru_cache(maxsize=1)
def get_service() -> AttackGraphService:
    return AttackGraphService(
        db_path=os.getenv("ATTACKGRAPH_DB_PATH", ".attackgraph/sibyl.db"),
        operator_id=os.getenv("ATTACKGRAPH_OPERATOR_ID", "local-operator"),
    )


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
    return get_service().list_engagements()


@mcp.tool()
def attackgraph_get_context(engagement_id: str, event_limit: int = 25) -> dict[str, Any]:
    """Return the complete hot graph plus recent append-only Sibyl events."""
    return get_service().context(engagement_id, event_limit=event_limit)


@mcp.tool()
def attackgraph_get_brief(engagement_id: str) -> dict[str, Any]:
    """Return a compact handoff for the connected agent to reason over."""
    return get_service().brief(engagement_id)


@mcp.tool()
def attackgraph_record_observation(
    engagement_id: str,
    statement: str,
    source: str,
    confidence: float,
    kind: str = "observation",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a sourced fact, candidate fact, finding, or execution artifact in Sibyl."""
    return get_service().record_observation(
        engagement_id,
        statement=statement,
        source=source,
        confidence=confidence,
        kind=kind,
        evidence=evidence,
    )


@mcp.tool()
def attackgraph_record_hypothesis(
    engagement_id: str, statement: str, status: str = "open"
) -> dict[str, Any]:
    """Record an open, confirmed, or rejected attack hypothesis."""
    return get_service().record_hypothesis(engagement_id, statement=statement, status=status)


@mcp.tool()
def attackgraph_record_attempt(
    engagement_id: str,
    approach: str,
    outcome: str,
    exhausted: bool,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record an attempted path so future sessions do not blindly repeat it."""
    return get_service().record_attempt(
        engagement_id,
        approach=approach,
        outcome=outcome,
        exhausted=exhausted,
        evidence=evidence,
    )


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
) -> dict[str, Any]:
    """Policy-check and record an action plan. This does not execute the command."""
    return get_service().request_action(
        engagement_id,
        target=target,
        lane=lane,
        command=command,
        purpose=purpose,
        risk=risk,
        max_minutes=max_minutes,
        budget_usdc=budget_usdc,
    )


@mcp.tool()
def attackgraph_h3retik_capabilities() -> dict[str, Any]:
    """Inspect the live H3RETIK MCP execution capabilities without spending funds."""
    return get_service().h3retik_capabilities()


@mcp.tool()
def attackgraph_h3retik_quote(minutes: int = 5, actions: int = 1, location: str = "auto") -> Any:
    """Get a live H3RETIK compute-window quote. This does not accept terms or pay."""
    return get_service().h3retik_quote(minutes=minutes, actions=actions, location=location)


@mcp.tool()
def attackgraph_execute_approved_h3retik_job(
    engagement_id: str, action_id: str, approval_code: str
) -> dict[str, Any]:
    """Execute one already-scoped action in an existing session after human approval."""
    return get_service().execute_approved_h3retik_job(
        engagement_id, action_id=action_id, approval_code=approval_code
    )


@mcp.tool()
def attackgraph_ingest_h3retik_result(
    engagement_id: str,
    action_id: str,
    job_id: str,
    result: dict[str, Any],
    status: str = "completed",
) -> dict[str, Any]:
    """Import externally run H3RETIK output as sanitized Sibyl evidence."""
    return get_service().ingest_h3retik_result(
        engagement_id,
        action_id=action_id,
        job_id=job_id,
        result=result,
        status=status,
    )


@mcp.tool()
def attackgraph_create_regression(
    engagement_id: str, name: str, check: str, expected: str
) -> dict[str, Any]:
    """Turn a confirmed finding into a durable regression check."""
    return get_service().create_regression(engagement_id, name=name, check=check, expected=expected)


@mcp.tool()
def attackgraph_discover_h1dr4_tools(query: str = "", limit: int = 20) -> list[dict[str, Any]]:
    """Discover live H1DR4 MCP tools by keyword instead of hard-coding the catalog."""
    return get_service().discover_h1dr4(query=query, limit=limit)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
