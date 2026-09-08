from __future__ import annotations

import sqlite3

import pytest

from h1dr4_attackgraph.identity import IdentityStore
from h1dr4_attackgraph.service import AttackGraphService


class OfflineClient:
    def discover(self, **kwargs):
        return []

    def capabilities(self):
        return {}


def test_agent_tokens_are_hashed_revocable_and_scoped(tmp_path):
    identity = IdentityStore(tmp_path / "control.db")
    created = identity.create_agent(
        owner_user_id="",
        name="Recon Worker",
        engagement_id="eng-allowed",
    )

    assert identity.authenticate_agent(created["token"])["agent_id"] == created["agent_id"]
    assert identity.can_access("eng-allowed", "agent", created["agent_id"])
    assert not identity.can_access("eng-other", "agent", created["agent_id"])
    with sqlite3.connect(identity.path) as connection:
        stored = connection.execute(
            "SELECT token_hash FROM agents WHERE agent_id=?", (created["agent_id"],)
        ).fetchone()[0]
    assert created["token"] not in stored

    identity.revoke_agent(created["agent_id"])
    assert identity.authenticate_agent(created["token"]) is None


def test_agent_service_enforces_membership_and_attributes_sibyl_records(tmp_path):
    db_path = tmp_path / "sibyl.db"
    identity = IdentityStore(tmp_path / "control.db")
    local = AttackGraphService(
        db_path=db_path,
        operator_id="team",
        h1dr4=OfflineClient(),
        h3retik=OfflineClient(),
    )
    allowed = local.open_engagement(
        title="Allowed",
        target="allowed.internal",
        mode="manual_only",
        scope="Owned fixture",
    )["engagement_id"]
    denied = local.open_engagement(
        title="Denied",
        target="denied.internal",
        mode="manual_only",
        scope="Owned fixture",
    )["engagement_id"]
    agent = identity.create_agent(
        owner_user_id="", name="Recon Worker", engagement_id=allowed
    )
    scoped = AttackGraphService(
        db_path=db_path,
        operator_id="team",
        h1dr4=OfflineClient(),
        h3retik=OfflineClient(),
        identity=identity,
        principal_type="agent",
        principal_id=agent["agent_id"],
        actor_name=agent["name"],
    )
    identity.bind_h3retik_session(
        engagement_id=allowed,
        session_id="shared-kali",
        label="Kali pool",
        attached_by="local-operator",
    )

    recorded = scoped.record_observation(
        allowed,
        statement="TLS reachable",
        source="fixture",
        confidence=1,
    )

    assert recorded["actor"] == {
        "id": agent["agent_id"],
        "name": "Recon Worker",
        "type": "agent",
    }
    assert [item["engagement_id"] for item in scoped.list_engagements()] == [allowed]
    assert scoped.h3retik_sessions(allowed)[0]["session_id"] == "shared-kali"
    action = scoped.request_action(
        allowed,
        target="allowed.internal",
        lane="web",
        command="curl -I https://allowed.internal",
        purpose="Inspect headers",
        h3retik_session_id="shared-kali",
    )
    assert action["h3retik_session_id"] == "shared-kali"
    with pytest.raises(PermissionError, match="h3retik_session_not_bound"):
        scoped.request_action(
            allowed,
            target="allowed.internal",
            lane="web",
            command="curl -I https://allowed.internal",
            purpose="Inspect headers",
            h3retik_session_id="another-session",
        )
    with pytest.raises(PermissionError, match="engagement_access_denied"):
        scoped.context(denied)
    with pytest.raises(PermissionError, match="agents_cannot_open_engagement"):
        scoped.open_engagement(
            title="Agent-created",
            target="nope.internal",
            mode="manual_only",
            scope="Denied",
        )
