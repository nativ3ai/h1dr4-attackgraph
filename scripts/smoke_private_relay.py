from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

import httpx

from h1dr4_attackgraph.relay import AttackGraphRelayClient, RelayStateStore
from h1dr4_attackgraph.service import AttackGraphService


def main() -> None:
    parser = argparse.ArgumentParser(description="Exercise a real relay with two isolated Sibyls.")
    parser.add_argument("--relay", default="http://127.0.0.1:8790/v1/attackgraph")
    args = parser.parse_args()
    bootstrap = os.getenv("ATTACKGRAPH_RELAY_BOOTSTRAP_TOKEN", "local-development-only")

    with tempfile.TemporaryDirectory(prefix="attackgraph-relay-smoke-") as directory:
        root = Path(directory)
        owner_service = AttackGraphService(
            db_path=root / "owner.db", operator_id="smoke-owner", identity=None
        )
        engagement = owner_service.open_engagement(
            title="Private relay smoke",
            target="http://owned-fixture.internal",
            mode="local_lab",
            scope="Owned test fixture only",
            target_allowlist=["http://owned-fixture.internal"],
        )
        owner = AttackGraphRelayClient(RelayStateStore(root / "owner-relay.json"))
        owner.host_workspace(
            owner_service,
            engagement["engagement_id"],
            relay_url=args.relay,
            actor_name="WEB-01",
            bootstrap_token=bootstrap,
        )
        invite = owner.create_invite(engagement["engagement_id"])

        friend_service = AttackGraphService(
            db_path=root / "friend.db", operator_id="smoke-friend", identity=None
        )
        friend = AttackGraphRelayClient(RelayStateStore(root / "friend-relay.json"))
        joined = friend.join_workspace(
            friend_service,
            invite["invite_code"],
            actor_name="AUTH-02",
        )
        friend_service.record_attempt(
            engagement["engagement_id"],
            approach="Known failed path from remote operator",
            outcome="failed",
            exhausted=True,
            evidence={"status": 401},
        )
        friend.push_workspace(friend_service, engagement["engagement_id"])
        owner_pulled = owner.pull_workspace(owner_service, engagement["engagement_id"])
        brief = owner_service.brief(engagement["engagement_id"])

        owner_workspace = owner.state.workspace(engagement["engagement_id"])
        response = httpx.get(
            f"{args.relay}/workspaces/{engagement['engagement_id']}/events?after=0",
            headers={"authorization": f"Bearer {owner_workspace['access_token']}"},
            timeout=20,
        )
        response.raise_for_status()
        relay_view = response.text
        assert "Known failed path from remote operator" not in relay_view
        assert "owned-fixture.internal" not in relay_view
        assert brief["exhausted_paths"][-1]["approach"] == "Known failed path from remote operator"

        print(
            json.dumps(
                {
                    "ok": True,
                    "workspace_id": engagement["engagement_id"],
                    "friend_pulled_events": joined["pulled_events"],
                    "owner_pulled_events": owner_pulled,
                    "relay_plaintext_visible": False,
                    "exhausted_path_recalled": True,
                },
                indent=2,
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
