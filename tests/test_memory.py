from __future__ import annotations

import pytest

from h1dr4_attackgraph.memory import EngagementNotFoundError, SibylAttackMemory
from h1dr4_attackgraph.models import EngagementMode


def open_demo(memory: SibylAttackMemory):
    return memory.open_engagement(
        title="Owned demo",
        target="demo.internal",
        mode=EngagementMode.MANUAL_ONLY,
        scope="Only demo.internal; no automated submission",
        target_allowlist=["demo.internal"],
        rules=["human submits findings"],
    )


def test_sibyl_recall_survives_a_fresh_client(tmp_path):
    path = tmp_path / "sibyl.db"
    first = SibylAttackMemory(path, "alice")
    engagement = open_demo(first)
    first.record_observation(
        engagement.engagement_id,
        statement="Server advertises nginx",
        source="curl headers",
        confidence=0.95,
    )
    first.record_attempt(
        engagement.engagement_id,
        approach="Probe removed endpoint",
        outcome="Consistent 404",
        exhausted=True,
    )

    fresh_process = SibylAttackMemory(path, "alice")
    graph = fresh_process.get_graph(engagement.engagement_id)

    assert graph["observations"][0]["statement"] == "Server advertises nginx"
    assert graph["attempts"][0]["exhausted"] is True
    recent = fresh_process.recent_events(engagement.engagement_id, limit=1)
    assert recent[0]["evaluated"]["type"] == "attempt_recorded"


def test_operator_tenants_are_isolated(tmp_path):
    path = tmp_path / "sibyl.db"
    alice = SibylAttackMemory(path, "alice")
    engagement = open_demo(alice)

    bob = SibylAttackMemory(path, "bob")

    assert bob.list_engagements() == []
    with pytest.raises(EngagementNotFoundError):
        bob.get_engagement(engagement.engagement_id)


def test_deletion_of_sibyl_database_removes_the_attack_brain(tmp_path):
    first_path = tmp_path / "with-memory.db"
    engagement = open_demo(SibylAttackMemory(first_path, "alice"))

    empty_path = tmp_path / "without-memory.db"
    memory_after_deletion = SibylAttackMemory(empty_path, "alice")

    with pytest.raises(EngagementNotFoundError):
        memory_after_deletion.get_graph(engagement.engagement_id)


def test_secrets_are_redacted_before_sibyl_persistence(tmp_path):
    memory = SibylAttackMemory(tmp_path / "sibyl.db", "alice")
    engagement = open_demo(memory)
    memory.record_observation(
        engagement.engagement_id,
        statement="Captured a test response",
        source="fixture",
        confidence=0.8,
        evidence={"headers": "Authorization: Bearer super-secret-token"},
    )

    stored = memory.get_graph(engagement.engagement_id)["observations"][0]

    assert "super-secret-token" not in str(stored)
    assert "[REDACTED]" in str(stored)


def test_structured_secret_fields_are_redacted_before_sibyl_persistence(tmp_path):
    memory = SibylAttackMemory(tmp_path / "sibyl.db", "alice")
    engagement = open_demo(memory)
    memory.record_observation(
        engagement.engagement_id,
        statement="Captured a scoped test credential",
        source="fixture",
        confidence=1.0,
        evidence={"credentials": {"username": "admin", "password": "do-not-store"}},
    )

    stored = memory.get_graph(engagement.engagement_id)["observations"][0]

    assert "do-not-store" not in str(stored)
    assert stored["evidence"]["credentials"] == "[REDACTED]"
