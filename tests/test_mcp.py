from __future__ import annotations

from h1dr4_attackgraph.server import mcp


async def test_mcp_surface_is_model_agnostic_and_contains_execution_loop():
    names = {tool.name for tool in await mcp.list_tools()}

    assert "attackgraph_get_brief" in names
    assert "attackgraph_get_reporting_contract" in names
    assert "attackgraph_report_event" in names
    assert "attackgraph_ingest_h3retik_event" in names
    assert "attackgraph_execute_approved_h3retik_job" in names
    assert "attackgraph_bind_h3retik_session" in names
    assert "attackgraph_get_h3retik_workspace" in names
    assert "attackgraph_create_h3retik_extension_receipt" in names
    assert "attackgraph_sync_h3retik_receipt" in names
    assert "attackgraph_discover_h1dr4_tools" in names
    assert not any("qwen" in name or "recommend_next_move" in name for name in names)
    assert len(names) == 22
