from __future__ import annotations

import re

from .models import ActionDecision, ActionRisk, Engagement, EngagementMode, PolicyDecision

_DESTRUCTIVE_COMMANDS = (
    re.compile(r"\brm\s+-[^\n]*r[^\n]*f\s+/(?:\s|$)"),
    re.compile(r"\bmkfs(?:\.|\s)"),
    re.compile(r"\bdd\s+if="),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*;\s*\}\s*;:"),
    re.compile(r"\b(?:shutdown|reboot|poweroff)\b"),
)


def evaluate_action(
    engagement: Engagement,
    *,
    target: str,
    lane: str,
    command: str,
    risk: ActionRisk,
) -> PolicyDecision:
    if target not in engagement.target_allowlist:
        return PolicyDecision(ActionDecision.DENIED, "target is outside the exact allowlist", False)
    if lane not in engagement.allowed_lanes:
        return PolicyDecision(
            ActionDecision.DENIED, "execution lane is outside engagement scope", False
        )
    if risk is ActionRisk.DESTRUCTIVE or any(
        pattern.search(command) for pattern in _DESTRUCTIVE_COMMANDS
    ):
        return PolicyDecision(
            ActionDecision.DENIED, "destructive execution is not supported", False
        )
    if engagement.mode is EngagementMode.MANUAL_ONLY:
        return PolicyDecision(
            ActionDecision.RECORDED_ONLY,
            "manual-only engagements never dispatch commands",
            False,
        )
    if engagement.mode is EngagementMode.LOCAL_LAB:
        return PolicyDecision(
            ActionDecision.RECORDED_ONLY,
            "local-lab actions are recorded for the human-operated local runner",
            False,
        )
    return PolicyDecision(
        ActionDecision.HUMAN_REQUIRED,
        "scoped H3RETIK execution requires an explicit human approval code",
        False,
    )
