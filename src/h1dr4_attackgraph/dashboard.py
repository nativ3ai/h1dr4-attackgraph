from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .memory import EngagementNotFoundError
from .service import AttackGraphService


def _short(value: str, limit: int = 28) -> str:
    return value if len(value) <= limit else f"{value[: limit - 1]}…"


def _positions(kind: str, index: int) -> tuple[int, int]:
    positions = {
        "confirmed": [(24, 22), (48, 17), (73, 23), (83, 41), (68, 57)],
        "hypothesis": [(22, 52), (28, 72), (45, 78), (13, 68)],
        "action": [(80, 67), (66, 78), (88, 82)],
        "regression": [(50, 88), (35, 88), (65, 88)],
    }
    choices = positions[kind]
    return choices[index % len(choices)]


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
            "detail": engagement["scope"],
        }
    ]
    edges: list[dict[str, str]] = []

    node_groups = (
        ("confirmed", brief["confirmed"]),
        ("hypothesis", brief["open_hypotheses"]),
        ("action", brief["pending_actions"]),
        ("regression", brief["regressions"]),
    )
    for kind, items in node_groups:
        for index, item in enumerate(items[:5]):
            x, y = _positions(kind, index)
            node_id = item["id"]
            if kind == "confirmed":
                label = item["statement"]
                meta = f"CONFIRMED · {item['confidence']:.2f}"
            elif kind == "hypothesis":
                label = item["statement"]
                meta = "OPEN HYPOTHESIS"
            elif kind == "action":
                label = item.get("purpose", item.get("command", "Pending action"))
                meta = item.get("status", "PENDING").replace("_", " ").upper()
            else:
                label = item["name"]
                meta = "REGRESSION"
            nodes.append(
                {
                    "id": node_id,
                    "label": _short(label),
                    "meta": meta,
                    "kind": kind,
                    "x": x,
                    "y": y,
                    "detail": item,
                }
            )
            edges.append({"from": target_id, "to": node_id})

    events = []
    for event in reversed(context["recent_events"][-12:]):
        evaluated = event.get("evaluated") or {}
        acted = event.get("acted") or {}
        event_type = evaluated.get("type", "memory_event")
        detail = (
            acted.get("statement")
            or acted.get("approach")
            or acted.get("purpose")
            or acted.get("name")
            or event_type.replace("_", " ")
        )
        events.append(
            {
                "id": event["id"],
                "time": event["ts"],
                "type": event_type,
                "title": event_type.replace("_", " ").title(),
                "detail": _short(str(detail), 72),
            }
        )

    pending_actions = brief["pending_actions"]
    last_event = events[0]["time"] if events else engagement.get("created_at", "")
    return {
        "engagement": engagement,
        "brief": brief,
        "stats": {
            "nodes": len(nodes),
            "evidence": len(graph["observations"]),
            "pending": len(pending_actions),
        },
        "nodes": nodes,
        "edges": edges,
        "events": events,
        "primary_action": pending_actions[-1] if pending_actions else None,
        "memory": {"online": True, "last_event": last_event, "event_count": len(events)},
    }


def create_dashboard_app(
    service: AttackGraphService | None = None, static_dir: str | Path | None = None
) -> Starlette:
    graph_service = service or AttackGraphService(
        db_path=os.getenv("ATTACKGRAPH_DB_PATH", ".attackgraph/sibyl.db"),
        operator_id=os.getenv("ATTACKGRAPH_OPERATOR_ID", "local-operator"),
    )

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "h1dr4-attackgraph-dashboard"})

    async def engagements(_: Request) -> JSONResponse:
        return JSONResponse({"engagements": graph_service.list_engagements()})

    async def engagement(request: Request) -> JSONResponse:
        engagement_id = request.path_params["engagement_id"]
        try:
            return JSONResponse(build_dashboard_snapshot(graph_service, engagement_id))
        except EngagementNotFoundError:
            return JSONResponse({"error": "engagement_not_found"}, status_code=404)

    async def export_engagement(request: Request) -> JSONResponse:
        engagement_id = request.path_params["engagement_id"]
        try:
            payload = graph_service.context(engagement_id, event_limit=500)
        except EngagementNotFoundError:
            return JSONResponse({"error": "engagement_not_found"}, status_code=404)
        return JSONResponse(
            payload,
            headers={
                "Content-Disposition": f'attachment; filename="{engagement_id}-attackgraph.json"'
            },
        )

    routes = [
        Route("/api/health", health),
        Route("/api/engagements", engagements),
        Route("/api/engagements/{engagement_id}", engagement),
        Route("/api/engagements/{engagement_id}/export", export_engagement),
    ]
    if static_dir and Path(static_dir).is_dir():
        index_path = Path(static_dir) / "index.html"

        async def index(_: Request) -> FileResponse:
            return FileResponse(index_path)

        routes.extend([Route("/", index), Mount("/", app=StaticFiles(directory=static_dir))])

    app = Starlette(debug=False, routes=routes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_methods=["GET"],
        allow_headers=["*"],
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
