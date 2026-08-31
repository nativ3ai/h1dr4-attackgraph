from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class EngagementMode(StrEnum):
    MANUAL_ONLY = "manual_only"
    LOCAL_LAB = "local_lab"
    AUTONOMOUS_LAB = "autonomous_lab"


class ActionRisk(StrEnum):
    OBSERVE = "observe"
    ACTIVE = "active"
    DESTRUCTIVE = "destructive"


class ActionDecision(StrEnum):
    RECORDED_ONLY = "recorded_only"
    HUMAN_REQUIRED = "human_required"
    DENIED = "denied"


@dataclass(slots=True)
class Engagement:
    engagement_id: str
    operator_id: str
    title: str
    target: str
    mode: EngagementMode
    scope: str
    target_allowlist: list[str]
    rules: list[str] = field(default_factory=list)
    allowed_lanes: list[str] = field(default_factory=lambda: ["local", "web", "osint"])
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["mode"] = self.mode.value
        return value


@dataclass(slots=True)
class PolicyDecision:
    decision: ActionDecision
    reason: str
    may_dispatch: bool

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["decision"] = self.decision.value
        return value
