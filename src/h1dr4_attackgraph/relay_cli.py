from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .relay import (
    DEFAULT_RELAY_URL,
    AttackGraphRelayClient,
    RelayError,
    RelayStateStore,
)
from .service import AttackGraphService


def _state() -> RelayStateStore:
    return RelayStateStore(
        Path(os.getenv("ATTACKGRAPH_RELAY_STATE_PATH", ".attackgraph/relay.json")).resolve()
    )


def _service(state: RelayStateStore) -> AttackGraphService:
    relay_state = state.load()
    return AttackGraphService(
        db_path=Path(os.getenv("ATTACKGRAPH_DB_PATH", ".attackgraph/sibyl.db")).resolve(),
        operator_id=os.getenv("ATTACKGRAPH_OPERATOR_ID", "local-operator"),
        identity=None,
        actor_id=str(relay_state.get("actor_id") or ""),
        actor_name=str(relay_state.get("actor_name") or "local-operator"),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attackgraph",
        description="Host, join, and synchronize H1DR4 AttackGraph private workspaces.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    host = commands.add_parser("host", help="Host an existing local engagement on the relay.")
    host.add_argument("engagement_id")
    host.add_argument("--relay", default=os.getenv("ATTACKGRAPH_RELAY_URL", DEFAULT_RELAY_URL))
    host.add_argument("--name", default=os.getenv("ATTACKGRAPH_RELAY_ACTOR_NAME", ""))

    invite = commands.add_parser("invite", help="Create a one-use encrypted join code.")
    invite.add_argument("engagement_id")
    invite.add_argument("--role", choices=("operator", "observer"), default="operator")
    invite.add_argument("--hours", type=int, default=24)

    join = commands.add_parser("join", help="Join a private workspace from another machine.")
    join.add_argument("invite_code")
    join.add_argument("--name", required=True)

    members = commands.add_parser("members", help="List members of a private workspace.")
    members.add_argument("engagement_id")

    revoke = commands.add_parser("revoke", help="Revoke one member as the workspace owner.")
    revoke.add_argument("engagement_id")
    revoke.add_argument("member_id")

    sync = commands.add_parser("sync", help="Synchronize one or all joined workspaces.")
    sync.add_argument("engagement_id", nargs="?")

    commands.add_parser("status", help="Show joined workspaces without revealing secrets.")
    return parser


def _run(args: argparse.Namespace) -> dict[str, Any]:
    state = _state()
    client = AttackGraphRelayClient(state)
    if args.command == "status":
        return client.status()
    service = _service(state)
    if args.command == "host":
        return client.host_workspace(
            service,
            args.engagement_id,
            relay_url=args.relay,
            actor_name=args.name,
            bootstrap_token=os.getenv("ATTACKGRAPH_RELAY_BOOTSTRAP_TOKEN", ""),
        )
    if args.command == "invite":
        return client.create_invite(args.engagement_id, role=args.role, hours=args.hours)
    if args.command == "join":
        return client.join_workspace(service, args.invite_code, actor_name=args.name)
    if args.command == "members":
        return {
            "workspace_id": args.engagement_id,
            "members": client.members(args.engagement_id),
        }
    if args.command == "revoke":
        return {
            "workspace_id": args.engagement_id,
            "member": client.revoke_member(args.engagement_id, args.member_id),
        }
    if args.command == "sync":
        if args.engagement_id:
            pulled = client.pull_workspace(service, args.engagement_id)
            pushed = client.push_workspace(service, args.engagement_id)
        else:
            pulled = client.pull_all(service)
            pushed = [client.push_workspace(service, item) for item in state.joined_ids()]
        return {"pulled_events": pulled, "published": bool(pushed)}
    raise RelayError("relay_command_unsupported")


def main() -> None:
    try:
        result = _run(_parser().parse_args())
    except (RelayError, ValueError) as exc:
        raise SystemExit(f"attackgraph: {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
