from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from h1dr4_attackgraph.relay import AttackGraphRelayClient, RelayError, RelayStateStore
from h1dr4_attackgraph.service import AttackGraphService


class RelayFixture:
    def __init__(self) -> None:
        self.invites: dict[str, dict] = {}
        self.events: list[dict] = []
        self.tokens = {"bootstrap": "bootstrap"}
        self.members: dict[str, dict] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/attackgraph")
        body = json.loads(request.content or b"{}")
        if request.method == "POST" and path == "/workspaces":
            self.tokens["owner-token"] = "owner"
            self.members["member-owner"] = {
                "member_id": "member-owner",
                "actor_id": body["actor_id"],
                "role": "owner",
                "status": "active",
            }
            return self.response(
                request,
                201,
                {
                    "workspace": {"workspace_id": body["workspace_id"]},
                    "member": {"role": "owner"},
                    "access_token": "owner-token",
                },
            )
        if request.method == "POST" and path.endswith("/invites"):
            invite_id = f"agi_{len(self.invites) + 1}"
            self.invites[invite_id] = {**body, "workspace_id": path.split("/")[2]}
            return self.response(
                request,
                201,
                {
                    "invite_id": invite_id,
                    "workspace_id": self.invites[invite_id]["workspace_id"],
                    "role": body["role"],
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            )
        if request.method == "GET" and path.startswith("/invites/"):
            invite_id = path.rsplit("/", 1)[-1]
            invite = self.invites[invite_id]
            return self.response(
                request,
                200,
                {
                    "invite_id": invite_id,
                    "workspace_id": invite["workspace_id"],
                    "role": invite["role"],
                    "expires_at": "2099-01-01T00:00:00Z",
                    "wrapped_workspace_key": invite["wrapped_workspace_key"],
                },
            )
        if request.method == "POST" and path.endswith("/redeem"):
            invite_id = path.split("/")[2]
            invite = self.invites[invite_id]
            proof_hash = hashlib.sha256(body["redeem_proof"].encode()).hexdigest()
            assert proof_hash == invite["redeem_proof_hash"]
            self.tokens["friend-token"] = "operator"
            self.members["member-friend"] = {
                "member_id": "member-friend",
                "actor_id": body["actor_id"],
                "role": invite["role"],
                "status": "active",
            }
            return self.response(
                request,
                201,
                {
                    "workspace_id": invite["workspace_id"],
                    "member": {"role": invite["role"]},
                    "access_token": "friend-token",
                    "wrapped_workspace_key": invite["wrapped_workspace_key"],
                },
            )
        if request.method == "POST" and path.endswith("/events"):
            row = {**body["envelope"], "cursor": len(self.events) + 1}
            self.events.append(row)
            return self.response(
                request,
                201,
                {"event_id": row["event_id"], "cursor": row["cursor"], "created": True},
            )
        if request.method == "GET" and path.endswith("/events"):
            after = int(parse_qs(request.url.query.decode()).get("after", ["0"])[0])
            rows = [event for event in self.events if event["cursor"] > after]
            return self.response(
                request,
                200,
                {
                    "workspace_id": path.split("/")[2],
                    "after": after,
                    "next_cursor": rows[-1]["cursor"] if rows else after,
                    "events": rows,
                },
            )
        if request.method == "GET" and path.endswith("/members"):
            return self.response(
                request,
                200,
                {
                    "workspace_id": path.split("/")[2],
                    "members": list(self.members.values()),
                },
            )
        if request.method == "DELETE" and "/members/" in path:
            member_id = path.rsplit("/", 1)[-1]
            self.members[member_id]["status"] = "revoked"
            return self.response(
                request,
                200,
                {"workspace_id": path.split("/")[2], "member": self.members[member_id]},
            )
        raise AssertionError(f"unexpected relay request: {request.method} {path}")

    @staticmethod
    def response(request: httpx.Request, status: int, body: dict) -> httpx.Response:
        return httpx.Response(status, json=body, request=request)


def service(path: Path, operator: str) -> AttackGraphService:
    return AttackGraphService(db_path=path, operator_id=operator, identity=None)


def test_two_local_sibyls_exchange_encrypted_workspace_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ATTACKGRAPH_RELAY_ALLOWED_HOSTS", "relay.test")
    relay = RelayFixture()
    transport = httpx.MockTransport(relay.handler)
    owner_service = service(tmp_path / "owner.db", "owner")
    engagement = owner_service.open_engagement(
        title="Owned Juice Shop",
        target="http://juice-shop.internal",
        mode="autonomous_lab",
        scope="Owned OWASP training fixture",
        target_allowlist=["http://juice-shop.internal"],
    )
    owner = AttackGraphRelayClient(
        RelayStateStore(tmp_path / "owner-relay.json"),
        client=httpx.Client(transport=transport),
    )
    hosted = owner.host_workspace(
        owner_service,
        engagement["engagement_id"],
        relay_url="https://relay.test/v1/attackgraph",
        actor_name="WEB-01",
        bootstrap_token="bootstrap",
    )
    assert hosted["workspaces"][0]["role"] == "owner"
    assert "snapshot" not in json.dumps(relay.events)

    invite = owner.create_invite(engagement["engagement_id"], role="operator")
    friend_service = service(tmp_path / "friend.db", "friend")
    friend = AttackGraphRelayClient(
        RelayStateStore(tmp_path / "friend-relay.json"),
        client=httpx.Client(transport=transport),
    )
    joined = friend.join_workspace(friend_service, invite["invite_code"], actor_name="AUTH-02")
    assert joined["pulled_events"] == 1
    brief = friend_service.brief(engagement["engagement_id"])
    assert brief["engagement"]["title"] == "Owned Juice Shop"

    friend_service.record_attempt(
        engagement["engagement_id"],
        approach="Default credentials",
        outcome="failed",
        exhausted=True,
        evidence={"status": 401},
    )
    friend.push_workspace(friend_service, engagement["engagement_id"])
    pulled = owner.pull_workspace(owner_service, engagement["engagement_id"])
    assert pulled == 2
    owner_brief = owner_service.brief(engagement["engagement_id"])
    assert owner_brief["exhausted_paths"][0]["approach"] == "Default credentials"

    members = owner.members(engagement["engagement_id"])
    friend_member = next(item for item in members if item["actor_id"] == joined["actor_id"])
    revoked = owner.revoke_member(engagement["engagement_id"], friend_member["member_id"])
    assert revoked["status"] == "revoked"

    relay_bytes = json.dumps(relay.events)
    assert "Default credentials" not in relay_bytes
    assert "juice-shop.internal" not in relay_bytes


def test_relay_state_is_created_private_and_untrusted_host_is_rejected(
    tmp_path: Path,
) -> None:
    state = RelayStateStore(tmp_path / "state" / "relay.json")
    state.identity("WEB-01")
    assert stat.S_IMODE(state.path.stat().st_mode) == 0o600

    service = AttackGraphService(db_path=tmp_path / "owner.db", operator_id="owner", identity=None)
    engagement = service.open_engagement(
        title="Confidential Target",
        target="https://example.test",
        mode="local_lab",
        scope="Owned fixture",
        target_allowlist=["https://example.test"],
    )
    client = AttackGraphRelayClient(
        state,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: pytest.fail(f"unexpected request: {request.url}")
            )
        ),
    )
    with pytest.raises(RelayError, match="relay_url_not_allowed"):
        client.host_workspace(
            service,
            engagement["engagement_id"],
            relay_url="https://attacker.example/v1/attackgraph",
            bootstrap_token="must-not-leak",
        )
