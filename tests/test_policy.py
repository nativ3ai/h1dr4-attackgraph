from __future__ import annotations

from h1dr4_attackgraph.models import (
    ActionDecision,
    ActionRisk,
    Engagement,
    EngagementMode,
)
from h1dr4_attackgraph.policy import evaluate_action


def engagement(mode: EngagementMode) -> Engagement:
    return Engagement(
        engagement_id="eng-1",
        operator_id="alice",
        title="test",
        target="demo.internal",
        mode=mode,
        scope="owned demo only",
        target_allowlist=["demo.internal"],
        allowed_lanes=["web", "local"],
    )


def test_manual_only_never_dispatches():
    decision = evaluate_action(
        engagement(EngagementMode.MANUAL_ONLY),
        target="demo.internal",
        lane="web",
        command="curl -I https://demo.internal",
        risk=ActionRisk.ACTIVE,
    )

    assert decision.decision is ActionDecision.RECORDED_ONLY
    assert decision.may_dispatch is False


def test_autonomous_lab_still_requires_a_human():
    decision = evaluate_action(
        engagement(EngagementMode.AUTONOMOUS_LAB),
        target="demo.internal",
        lane="web",
        command="curl -I https://demo.internal",
        risk=ActionRisk.ACTIVE,
    )

    assert decision.decision is ActionDecision.HUMAN_REQUIRED
    assert decision.may_dispatch is False


def test_scope_and_destructive_commands_are_denied():
    outside = evaluate_action(
        engagement(EngagementMode.AUTONOMOUS_LAB),
        target="outside.example",
        lane="web",
        command="curl -I https://outside.example",
        risk=ActionRisk.ACTIVE,
    )
    destructive = evaluate_action(
        engagement(EngagementMode.AUTONOMOUS_LAB),
        target="demo.internal",
        lane="local",
        command="rm -rf /",
        risk=ActionRisk.ACTIVE,
    )

    assert outside.decision is ActionDecision.DENIED
    assert destructive.decision is ActionDecision.DENIED
